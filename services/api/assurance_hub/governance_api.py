from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .api import as_utc, commit_or_conflict, list_tenant_resources, page_response, tenant_get
from .assessment_review import (
    assessment_review_snapshot,
    finalize_assessment_review,
    save_control_review_decision,
)
from .auth import (
    AdminIdentity,
    AnalystIdentity,
    CurrentIdentity,
    ExceptionApproverIdentity,
    IntegrationIdentity,
    WriterIdentity,
)
from .dependencies import PaginationDep, SessionDep
from .errors import ConflictError, DomainError, LeaseConflictError
from .governance import (
    EVALUATOR_VERSION,
    canonical_sha256,
    enqueue_outbox,
    prepare_control_evaluation,
    results_for_control,
)
from .governance_schemas import (
    AssessmentFinalizeRequest,
    AssessmentReviewOut,
    AssessmentRunOut,
    AssessmentRunRequest,
    ControlDefinitionOut,
    ControlEvaluationRequest,
    ControlPackDetail,
    ControlPackPublish,
    ControlPackVersionOut,
    ControlResultOut,
    ControlReviewDecisionRequest,
    FindingExceptionDecision,
    FindingExceptionOut,
    FindingExceptionRequest,
    FindingExceptionRevoke,
    InboxAcceptRequest,
    IntegrationInboxOut,
    IntegrationOutboxOut,
    OutboxCompletionRequest,
    OutboxLeaseRenewRequest,
    OutboxLeaseRequest,
)
from .models import (
    Assessment,
    AssessmentStatus,
    Asset,
    Connector,
    ControlDefinition,
    ControlPackStatus,
    ControlPackVersion,
    ControlResult,
    DeliveryStatus,
    Evidence,
    Finding,
    FindingException,
    FindingExceptionStatus,
    FindingStatus,
    InboxStatus,
    IntegrationDestination,
    IntegrationInbox,
    IntegrationOutbox,
    ScanJob,
    WorkStatus,
)
from .observability import record_job_created
from .query_catalog import validate_probe_ids
from .schemas import AssessmentOut, JobResult, Page, ScanJobOut

router = APIRouter()


def enforce_worker_identity(identity: Any, worker_id: str) -> None:
    if "admin" not in identity.roles and identity.subject != worker_id:
        raise DomainError(
            "integration_worker_identity_mismatch",
            "Integration identity must match the requested worker ID",
            403,
        )


async def pack_detail(session: AsyncSession, pack: ControlPackVersion) -> ControlPackDetail:
    definitions = list(
        (
            await session.scalars(
                select(ControlDefinition)
                .where(
                    ControlDefinition.tenant_id == pack.tenant_id,
                    ControlDefinition.control_pack_version_id == pack.id,
                )
                .order_by(ControlDefinition.control_id.asc())
            )
        ).all()
    )
    data = ControlPackVersionOut.model_validate(pack).model_dump()
    return ControlPackDetail(
        **data,
        controls=[ControlDefinitionOut.model_validate(definition) for definition in definitions],
    )


@router.post(
    "/control-pack-versions",
    response_model=ControlPackDetail,
    status_code=201,
    tags=["control-packs"],
)
async def publish_control_pack(
    payload: ControlPackPublish,
    identity: AdminIdentity,
    session: SessionDep,
) -> ControlPackDetail:
    released_at = as_utc(payload.released_at)
    if payload.status == ControlPackStatus.ACTIVE and released_at > datetime.now(UTC):
        raise DomainError("future_active_release", "An active pack cannot be future dated", 422)
    if payload.supersedes:
        predecessor = await session.scalar(
            select(ControlPackVersion).where(
                ControlPackVersion.tenant_id == identity.tenant_id,
                ControlPackVersion.pack_id == payload.pack_id,
                ControlPackVersion.version == payload.supersedes,
            )
        )
        if predecessor is None:
            raise DomainError(
                "superseded_version_not_found",
                "The declared superseded version does not exist in this tenant",
                422,
            )
    for control in payload.controls:
        try:
            validate_probe_ids(payload.platform, control.probe_ids)
        except ValueError as exc:
            raise DomainError("probe_not_allowed", str(exc), 422) from exc

    canonical_payload = payload.model_dump(mode="json")
    pack = ControlPackVersion(
        tenant_id=identity.tenant_id,
        pack_id=payload.pack_id,
        version=payload.version,
        schema_version=payload.schema_version,
        platform=payload.platform,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        released_at=released_at,
        supersedes=payload.supersedes,
        immutable=True,
        content_sha256=canonical_sha256(canonical_payload),
        created_by=identity.subject,
    )
    session.add(pack)
    await session.flush()
    for control in payload.controls:
        definition_payload = control.model_dump(mode="json")
        session.add(
            ControlDefinition(
                tenant_id=identity.tenant_id,
                control_pack_version_id=pack.id,
                control_id=control.control_id,
                domain=control.domain,
                title=control.title,
                objective=control.objective,
                severity=control.severity,
                environments=[item.value for item in control.environments],
                version_scope=control.version_scope,
                applicability_notes=control.applicability_notes,
                assessment_mode=control.assessment_mode,
                probe_ids=control.probe_ids,
                decision_mode=control.decision_mode,
                manual_evidence_requirements=control.manual_evidence_requirements,
                allowed_fields=control.allowed_fields,
                limitations=control.limitations,
                remediation_guidance=control.remediation_guidance,
                definition_sha256=canonical_sha256(definition_payload),
            )
        )
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="control_pack_version",
        aggregate_id=pack.id,
        event_type="control_pack.published",
        payload={
            "pack_id": pack.pack_id,
            "version": pack.version,
            "platform": pack.platform.value,
            "content_sha256": pack.content_sha256,
        },
    )
    await commit_or_conflict(session, "This immutable control pack version already exists")
    return await pack_detail(session, pack)


@router.get(
    "/control-pack-versions",
    response_model=Page[ControlPackVersionOut],
    tags=["control-packs"],
)
async def list_control_packs(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[ControlPackVersionOut]:
    rows = await list_tenant_resources(session, ControlPackVersion, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, ControlPackVersionOut)


@router.get(
    "/control-pack-versions/{pack_id}",
    response_model=ControlPackDetail,
    tags=["control-packs"],
)
async def get_control_pack(
    pack_id: str, identity: CurrentIdentity, session: SessionDep
) -> ControlPackDetail:
    pack = await tenant_get(
        session, ControlPackVersion, pack_id, identity.tenant_id, "control pack version"
    )
    return await pack_detail(session, pack)


@router.post(
    "/assessment-runs",
    response_model=AssessmentRunOut,
    status_code=201,
    tags=["assessments"],
)
async def start_assessment_run(
    payload: AssessmentRunRequest,
    identity: WriterIdentity,
    session: SessionDep,
) -> AssessmentRunOut:
    """Atomically create an assessment, collector job, and integration event."""
    asset = await tenant_get(session, Asset, payload.asset_id, identity.tenant_id, "asset")
    connector = await tenant_get(
        session, Connector, payload.connector_id, identity.tenant_id, "connector"
    )
    pack = await tenant_get(
        session,
        ControlPackVersion,
        payload.control_pack_version_id,
        identity.tenant_id,
        "control pack version",
    )
    if connector.asset_id != asset.id or connector.platform != asset.platform:
        raise DomainError(
            "connector_asset_mismatch",
            "Connector and asset must identify the same database platform",
            422,
        )
    if pack.platform != asset.platform or pack.status != ControlPackStatus.ACTIVE:
        raise DomainError(
            "control_pack_not_applicable",
            "An active control pack for the asset platform is required",
            422,
        )
    definitions = list(
        (
            await session.scalars(
                select(ControlDefinition).where(
                    ControlDefinition.tenant_id == identity.tenant_id,
                    ControlDefinition.control_pack_version_id == pack.id,
                )
            )
        ).all()
    )
    probe_ids = sorted(
        {
            probe_id
            for definition in definitions
            if definition.assessment_mode == "automated_evidence"
            for probe_id in definition.probe_ids
        }
    )
    if not definitions or not probe_ids:
        raise DomainError(
            "control_pack_not_executable",
            "The immutable pack has no approved automated probes for an assessment run",
            422,
        )
    existing_job = await session.scalar(
        select(ScanJob).where(
            ScanJob.tenant_id == identity.tenant_id,
            ScanJob.deduplication_key == payload.run_key,
        )
    )
    if existing_job and existing_job.assessment_id:
        existing_assessment = await tenant_get(
            session,
            Assessment,
            existing_job.assessment_id,
            identity.tenant_id,
            "assessment",
        )
        if (
            existing_job.connector_id == connector.id
            and existing_assessment.asset_id == asset.id
            and existing_assessment.control_pack == pack.pack_id
            and existing_assessment.control_pack_version == pack.version
        ):
            return AssessmentRunOut(
                assessment=AssessmentOut.model_validate(existing_assessment),
                job=ScanJobOut.model_validate(existing_job),
            )
        raise ConflictError("The assessment run key is already bound to different inputs")

    active_assessment = await session.scalar(
        select(Assessment)
        .where(
            Assessment.tenant_id == identity.tenant_id,
            Assessment.asset_id == asset.id,
            Assessment.control_pack == pack.pack_id,
            Assessment.control_pack_version == pack.version,
            Assessment.status.in_(
                [
                    AssessmentStatus.QUEUED,
                    AssessmentStatus.RUNNING,
                    AssessmentStatus.REVIEW_REQUIRED,
                ]
            ),
        )
        .order_by(Assessment.created_at.desc(), Assessment.id.desc())
        .with_for_update()
        .limit(1)
    )
    if active_assessment is not None:
        raise ConflictError(
            "Complete the active assessment review before starting another run",
            {"assessment_id": active_assessment.id},
        )

    assessment = Assessment(
        tenant_id=identity.tenant_id,
        asset_id=asset.id,
        control_pack=pack.pack_id,
        control_pack_version=pack.version,
        status=AssessmentStatus.QUEUED,
        initiated_by=identity.subject,
        summary={"control_pack_version_id": pack.id, "control_count": len(definitions)},
    )
    session.add(assessment)
    await session.flush()
    job = ScanJob(
        tenant_id=identity.tenant_id,
        connector_id=connector.id,
        assessment_id=assessment.id,
        job_type="control_assessment",
        deduplication_key=payload.run_key,
        payload={
            "probe_ids": probe_ids,
            "schemas": [],
            "metadata": {
                "control_pack_id": pack.pack_id,
                "control_pack_version": pack.version,
            },
        },
        available_at=datetime.now(UTC),
        max_attempts=payload.max_attempts,
    )
    session.add(job)
    await session.flush()
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="assessment",
        aggregate_id=assessment.id,
        event_type="assessment.queued",
        payload={
            "asset_id": asset.id,
            "assessment_id": assessment.id,
            "job_id": job.id,
            "control_pack_version_id": pack.id,
        },
    )
    await commit_or_conflict(session, "This assessment run already exists")
    await session.refresh(assessment)
    await session.refresh(job)
    record_job_created(job.job_type)
    return AssessmentRunOut(
        assessment=AssessmentOut.model_validate(assessment),
        job=ScanJobOut.model_validate(job),
    )


@router.get(
    "/assessments/{assessment_id}/review",
    response_model=AssessmentReviewOut,
    tags=["assessments"],
)
async def get_assessment_review(
    assessment_id: str,
    identity: CurrentIdentity,
    session: SessionDep,
) -> AssessmentReviewOut:
    assessment = await tenant_get(
        session, Assessment, assessment_id, identity.tenant_id, "assessment"
    )
    return await assessment_review_snapshot(session, assessment=assessment)


@router.put(
    "/assessments/{assessment_id}/control-decisions/{control_definition_id}",
    response_model=AssessmentReviewOut,
    tags=["assessments"],
)
async def put_assessment_control_decision(
    assessment_id: str,
    control_definition_id: str,
    payload: ControlReviewDecisionRequest,
    identity: AnalystIdentity,
    session: SessionDep,
) -> AssessmentReviewOut:
    return await save_control_review_decision(
        session,
        tenant_id=identity.tenant_id,
        subject=identity.subject,
        assessment_id=assessment_id,
        control_definition_id=control_definition_id,
        payload=payload,
    )


@router.post(
    "/assessments/{assessment_id}/finalize",
    response_model=AssessmentReviewOut,
    tags=["assessments"],
)
async def finalize_assessment(
    assessment_id: str,
    payload: AssessmentFinalizeRequest,
    identity: AnalystIdentity,
    session: SessionDep,
) -> AssessmentReviewOut:
    del payload
    return await finalize_assessment_review(
        session,
        tenant_id=identity.tenant_id,
        subject=identity.subject,
        assessment_id=assessment_id,
    )


@router.post(
    "/control-results/evaluate",
    response_model=ControlResultOut,
    status_code=201,
    tags=["control-results"],
)
async def evaluate_control(
    payload: ControlEvaluationRequest,
    identity: WriterIdentity,
    session: SessionDep,
) -> ControlResult:
    assessment = await tenant_get(
        session, Assessment, payload.assessment_id, identity.tenant_id, "assessment"
    )
    definition = await tenant_get(
        session,
        ControlDefinition,
        payload.control_definition_id,
        identity.tenant_id,
        "control definition",
    )
    pack = await tenant_get(
        session,
        ControlPackVersion,
        definition.control_pack_version_id,
        identity.tenant_id,
        "control pack version",
    )
    if assessment.control_pack != pack.pack_id or assessment.control_pack_version != pack.version:
        raise DomainError(
            "control_pack_mismatch",
            "The control definition is not from the assessment's immutable pack version",
            422,
        )
    source_job: ScanJob | None = None
    if payload.source_job_id:
        source_job = await tenant_get(
            session, ScanJob, payload.source_job_id, identity.tenant_id, "scan job"
        )
        if source_job.assessment_id != assessment.id or source_job.status != WorkStatus.SUCCEEDED:
            raise DomainError(
                "source_job_mismatch",
                "A control result requires a succeeded job from the same assessment",
                422,
            )
    if definition.assessment_mode == "automated_evidence" and source_job is None:
        raise DomainError(
            "source_job_required",
            "Automated control evaluation requires its succeeded collector job",
            422,
        )
    if definition.assessment_mode == "manual_evidence" and source_job is not None:
        raise DomainError(
            "evidence_contract_violation",
            "Manual controls cannot be evaluated from a collector job",
            422,
        )
    effective_results = payload.probe_results
    if source_job is not None:
        stored_result = JobResult.model_validate(source_job.result)
        stored_control_results = results_for_control(definition, stored_result.probe_results)
        stored_probe_payload = sorted(
            [result.model_dump(mode="json") for result in stored_control_results],
            key=lambda item: str(item["probe_id"]),
        )
        supplied_probe_payload = sorted(
            [result.model_dump(mode="json") for result in payload.probe_results],
            key=lambda item: str(item["probe_id"]),
        )
        if payload.probe_results and canonical_sha256(supplied_probe_payload) != canonical_sha256(
            stored_probe_payload
        ):
            raise DomainError(
                "source_job_result_mismatch",
                "Caller-supplied probe results differ from the immutable succeeded job result",
                422,
            )
        effective_results = stored_control_results
    if definition.assessment_mode == "manual_evidence" and effective_results:
        raise DomainError(
            "evidence_contract_violation", "Manual controls cannot accept probe results", 422
        )

    evidence: list[Evidence] = []
    if payload.evidence_ids:
        evidence = list(
            (
                await session.scalars(
                    select(Evidence).where(
                        Evidence.tenant_id == identity.tenant_id,
                        Evidence.id.in_(payload.evidence_ids),
                    )
                )
            ).all()
        )
        if len(evidence) != len(payload.evidence_ids) or any(
            item.assessment_id != assessment.id or item.control_id != definition.control_id
            for item in evidence
        ):
            raise DomainError(
                "evidence_mismatch",
                "Every evidence record must belong to this assessment and control",
                422,
            )

    try:
        prepared = prepare_control_evaluation(
            tenant_id=identity.tenant_id,
            assessment_id=assessment.id,
            definition=definition,
            source_job_id=payload.source_job_id,
            probe_results=effective_results,
            evidence_ids=payload.evidence_ids,
            schema_version=payload.schema_version,
        )
    except ValueError as exc:
        raise DomainError("evidence_contract_violation", str(exc), 422) from exc
    existing = await session.scalar(
        select(ControlResult).where(
            ControlResult.tenant_id == identity.tenant_id,
            ControlResult.assessment_id == assessment.id,
            ControlResult.control_definition_id == definition.id,
        )
    )
    if existing:
        if existing.input_sha256 == prepared.input_sha256:
            return existing
        raise ConflictError("A different immutable result already exists for this control")
    result = ControlResult(
        tenant_id=identity.tenant_id,
        assessment_id=assessment.id,
        control_definition_id=definition.id,
        source_job_id=payload.source_job_id,
        control_id=definition.control_id,
        evaluation_key=prepared.evaluation_key,
        outcome=prepared.outcome,
        evaluator_version=EVALUATOR_VERSION,
        input_sha256=prepared.input_sha256,
        rationale=prepared.rationale,
        evidence_count=len(evidence),
        probe_outcomes=prepared.probe_outcomes,
        evaluated_at=datetime.now(UTC),
    )
    session.add(result)
    await session.flush()
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="control_result",
        aggregate_id=result.id,
        event_type="control_result.recorded",
        payload={
            "assessment_id": assessment.id,
            "control_id": definition.control_id,
            "outcome": prepared.outcome.value,
            "input_sha256": prepared.input_sha256,
        },
    )
    await commit_or_conflict(session, "This immutable control result already exists")
    await session.refresh(result)
    return result


@router.get(
    "/control-results",
    response_model=Page[ControlResultOut],
    tags=["control-results"],
)
async def list_control_results(
    identity: CurrentIdentity, session: SessionDep, pagination: PaginationDep
) -> Page[ControlResultOut]:
    rows = await list_tenant_resources(session, ControlResult, identity.tenant_id, pagination)
    return page_response(rows, pagination.limit, ControlResultOut)


@router.post(
    "/findings/{finding_id}/exceptions",
    response_model=FindingExceptionOut,
    status_code=201,
    tags=["finding-exceptions"],
)
async def request_finding_exception(
    finding_id: str,
    payload: FindingExceptionRequest,
    identity: WriterIdentity,
    session: SessionDep,
) -> FindingException:
    finding = await tenant_get(session, Finding, finding_id, identity.tenant_id, "finding")
    if finding.status not in {FindingStatus.OPEN, FindingStatus.IN_PROGRESS}:
        raise ConflictError("Only an open or in-progress finding can receive an exception request")
    now = datetime.now(UTC)
    expires_at = as_utc(payload.expires_at)
    if expires_at <= now or expires_at > now + timedelta(days=366 * 5):
        raise DomainError(
            "invalid_exception_expiry",
            "Exception expiry must be in the future and no more than five years away",
            422,
        )
    exception = FindingException(
        tenant_id=identity.tenant_id,
        finding_id=finding_id,
        request_key=payload.request_key,
        status=FindingExceptionStatus.REQUESTED,
        justification=payload.justification,
        requested_by=identity.subject,
        requested_at=now,
        expires_at=expires_at,
    )
    session.add(exception)
    await session.flush()
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="finding_exception",
        aggregate_id=exception.id,
        event_type="finding_exception.requested",
        payload={"finding_id": finding_id, "expires_at": expires_at.isoformat()},
    )
    await commit_or_conflict(session, "This finding exception request already exists")
    await session.refresh(exception)
    return exception


@router.get(
    "/findings/{finding_id}/exceptions",
    response_model=Page[FindingExceptionOut],
    tags=["finding-exceptions"],
)
async def list_finding_exceptions(
    finding_id: str,
    identity: CurrentIdentity,
    session: SessionDep,
    pagination: PaginationDep,
) -> Page[FindingExceptionOut]:
    await tenant_get(session, Finding, finding_id, identity.tenant_id, "finding")
    statement = (
        select(FindingException)
        .where(
            FindingException.tenant_id == identity.tenant_id,
            FindingException.finding_id == finding_id,
        )
        .order_by(FindingException.created_at.asc(), FindingException.id.asc())
        .limit(pagination.limit + 1)
    )
    rows = list((await session.scalars(statement)).all())
    return page_response(rows, pagination.limit, FindingExceptionOut)


@router.post(
    "/finding-exceptions/{exception_id}/decision",
    response_model=FindingExceptionOut,
    tags=["finding-exceptions"],
)
async def decide_finding_exception(
    exception_id: str,
    payload: FindingExceptionDecision,
    identity: ExceptionApproverIdentity,
    session: SessionDep,
) -> FindingException:
    exception = await tenant_get(
        session,
        FindingException,
        exception_id,
        identity.tenant_id,
        "finding exception",
        for_update=True,
    )
    if exception.status != FindingExceptionStatus.REQUESTED:
        raise ConflictError("Only a requested exception can be decided")
    if exception.requested_by == identity.subject:
        raise DomainError(
            "separation_of_duties_violation",
            "The requester cannot approve or reject their own exception",
            403,
        )
    now = datetime.now(UTC)
    if payload.decision == "approve" and as_utc(exception.expires_at) <= now:
        raise ConflictError("An expired exception request cannot be approved")
    exception.approved_by = identity.subject
    exception.approved_at = now
    exception.decision_reason = payload.reason
    finding = await tenant_get(
        session,
        Finding,
        exception.finding_id,
        identity.tenant_id,
        "finding",
        for_update=True,
    )
    if payload.decision == "approve":
        if finding.status not in {FindingStatus.OPEN, FindingStatus.IN_PROGRESS}:
            raise ConflictError("Only an open or in-progress finding can receive risk acceptance")
        existing_approved = await session.scalar(
            select(FindingException)
            .where(
                FindingException.tenant_id == identity.tenant_id,
                FindingException.finding_id == exception.finding_id,
                FindingException.status == FindingExceptionStatus.APPROVED,
                FindingException.id != exception.id,
            )
            .with_for_update()
        )
        if existing_approved:
            raise ConflictError("This finding already has an active approved exception")
        exception.status = FindingExceptionStatus.APPROVED
        finding.status = FindingStatus.RISK_ACCEPTED
    else:
        exception.status = FindingExceptionStatus.REJECTED
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="finding_exception",
        aggregate_id=exception.id,
        event_type=f"finding_exception.{exception.status.value}",
        payload={
            "finding_id": exception.finding_id,
            "status": exception.status.value,
            "expires_at": as_utc(exception.expires_at).isoformat(),
        },
    )
    await commit_or_conflict(session, "The finding exception decision conflicts with current state")
    await session.refresh(exception)
    return exception


@router.post(
    "/finding-exceptions/{exception_id}/revoke",
    response_model=FindingExceptionOut,
    tags=["finding-exceptions"],
)
async def revoke_finding_exception(
    exception_id: str,
    payload: FindingExceptionRevoke,
    identity: ExceptionApproverIdentity,
    session: SessionDep,
) -> FindingException:
    exception = await tenant_get(
        session,
        FindingException,
        exception_id,
        identity.tenant_id,
        "finding exception",
        for_update=True,
    )
    if exception.status != FindingExceptionStatus.APPROVED:
        raise ConflictError("Only an approved exception can be revoked")
    now = datetime.now(UTC)
    exception.status = FindingExceptionStatus.REVOKED
    exception.revoked_by = identity.subject
    exception.revoked_at = now
    exception.revocation_reason = payload.reason
    finding = await tenant_get(
        session,
        Finding,
        exception.finding_id,
        identity.tenant_id,
        "finding",
        for_update=True,
    )
    if finding.status == FindingStatus.RISK_ACCEPTED:
        finding.status = FindingStatus.OPEN
    enqueue_outbox(
        session,
        tenant_id=identity.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="finding_exception",
        aggregate_id=exception.id,
        event_type="finding_exception.revoked",
        payload={"finding_id": exception.finding_id, "status": exception.status.value},
    )
    await session.commit()
    await session.refresh(exception)
    return exception


@router.post(
    "/integrations/outbox/lease",
    response_model=IntegrationOutboxOut | None,
    tags=["integrations"],
)
async def lease_outbox_event(
    payload: OutboxLeaseRequest,
    identity: IntegrationIdentity,
    session: SessionDep,
    request: Request,
    response: Response,
) -> IntegrationOutbox | None:
    enforce_worker_identity(identity, payload.worker_id)
    now = datetime.now(UTC)
    event = await session.scalar(
        select(IntegrationOutbox)
        .where(
            IntegrationOutbox.tenant_id == identity.tenant_id,
            IntegrationOutbox.status == DeliveryStatus.PENDING,
            IntegrationOutbox.available_at <= now,
            IntegrationOutbox.destination.in_(payload.destinations),
        )
        .order_by(IntegrationOutbox.available_at.asc(), IntegrationOutbox.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if event is None:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    event.status = DeliveryStatus.LEASED
    event.leased_by = payload.worker_id
    event.lease_token = str(uuid.uuid4())
    event.lease_expires_at = now + timedelta(
        seconds=request.app.state.settings.outbox_lease_seconds
    )
    event.attempts += 1
    await session.commit()
    await session.refresh(event)
    return event


def validate_outbox_lease(
    event: IntegrationOutbox, worker_id: str, lease_token: str, operation: str
) -> None:
    if (
        event.leased_by != worker_id
        or event.lease_token != lease_token
        or event.status not in {DeliveryStatus.LEASED, DeliveryStatus.RUNNING}
    ):
        raise LeaseConflictError(f"The caller does not own the outbox lease for {operation}")
    if event.lease_expires_at and as_utc(event.lease_expires_at) < datetime.now(UTC):
        raise LeaseConflictError("The outbox lease has expired")


@router.post(
    "/integrations/outbox/{event_id}/renew",
    response_model=IntegrationOutboxOut,
    tags=["integrations"],
)
async def renew_outbox_lease(
    event_id: str,
    payload: OutboxLeaseRenewRequest,
    identity: IntegrationIdentity,
    session: SessionDep,
    request: Request,
) -> IntegrationOutbox:
    enforce_worker_identity(identity, payload.worker_id)
    event = await tenant_get(
        session, IntegrationOutbox, event_id, identity.tenant_id, "outbox event"
    )
    validate_outbox_lease(event, payload.worker_id, payload.lease_token, "renewal")
    event.status = DeliveryStatus.RUNNING
    event.lease_expires_at = datetime.now(UTC) + timedelta(
        seconds=request.app.state.settings.outbox_lease_seconds
    )
    await session.commit()
    await session.refresh(event)
    return event


@router.post(
    "/integrations/outbox/{event_id}/complete",
    response_model=IntegrationOutboxOut,
    tags=["integrations"],
)
async def complete_outbox_event(
    event_id: str,
    payload: OutboxCompletionRequest,
    identity: IntegrationIdentity,
    session: SessionDep,
) -> IntegrationOutbox:
    enforce_worker_identity(identity, payload.worker_id)
    event = await tenant_get(
        session, IntegrationOutbox, event_id, identity.tenant_id, "outbox event"
    )
    validate_outbox_lease(event, payload.worker_id, payload.lease_token, "completion")
    now = datetime.now(UTC)
    event.leased_by = None
    event.lease_token = None
    event.lease_expires_at = None
    if payload.success:
        event.status = DeliveryStatus.DELIVERED
        event.external_reference = payload.external_reference
        event.last_error = None
        event.completed_at = now
    elif event.attempts < event.max_attempts:
        event.status = DeliveryStatus.PENDING
        event.last_error = payload.error
        event.available_at = now + timedelta(seconds=min(900, 2**event.attempts))
    else:
        event.status = DeliveryStatus.DEAD_LETTER
        event.last_error = payload.error
        event.completed_at = now
    await session.commit()
    await session.refresh(event)
    return event


@router.post(
    "/integrations/inbox",
    response_model=IntegrationInboxOut,
    status_code=201,
    tags=["integrations"],
)
async def accept_inbox_message(
    payload: InboxAcceptRequest,
    identity: IntegrationIdentity,
    session: SessionDep,
) -> IntegrationInbox:
    enforce_worker_identity(identity, payload.worker_id)
    payload_sha256 = canonical_sha256(payload.payload)
    existing = await session.scalar(
        select(IntegrationInbox).where(
            IntegrationInbox.tenant_id == identity.tenant_id,
            IntegrationInbox.source == payload.source,
            IntegrationInbox.message_id == payload.message_id,
        )
    )
    if existing:
        if existing.payload_sha256 == payload_sha256 and existing.event_type == payload.event_type:
            return existing
        raise ConflictError("The inbox message ID was reused with different content")
    now = datetime.now(UTC)
    message = IntegrationInbox(
        tenant_id=identity.tenant_id,
        source=payload.source,
        message_id=payload.message_id,
        event_type=payload.event_type,
        payload_sha256=payload_sha256,
        status=InboxStatus.PROCESSED,
        received_by=identity.subject,
        received_at=now,
        processed_at=now,
    )
    session.add(message)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError("The inbox message was accepted concurrently; retry safely") from exc
    await session.refresh(message)
    return message
