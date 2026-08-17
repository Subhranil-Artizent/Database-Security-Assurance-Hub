from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import ConflictError, DomainError
from .governance import canonical_sha256, enqueue_outbox_once, results_for_control
from .governance_schemas import (
    AssessmentReviewControlOut,
    AssessmentReviewOut,
    ControlDefinitionOut,
    ControlResultOut,
    ControlReviewDecisionOut,
    ControlReviewDecisionRequest,
)
from .models import (
    Assessment,
    AssessmentStatus,
    Asset,
    ControlDecisionOutcome,
    ControlDefinition,
    ControlPackVersion,
    ControlResult,
    ControlResultOutcome,
    ControlReviewDecision,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    IntegrationDestination,
    ScanJob,
)
from .schemas import AssessmentOut, JobResult

REVIEWABLE_COLLECTION_OUTCOMES = {
    ControlResultOutcome.REVIEW_REQUIRED,
    ControlResultOutcome.NOT_APPLICABLE,
}
REVIEWABLE_ASSESSMENT_STATUSES = {
    AssessmentStatus.RUNNING,
    AssessmentStatus.REVIEW_REQUIRED,
}


async def assessment_review_snapshot(
    session: AsyncSession,
    *,
    assessment: Assessment,
) -> AssessmentReviewOut:
    pack = await session.scalar(
        select(ControlPackVersion).where(
            ControlPackVersion.tenant_id == assessment.tenant_id,
            ControlPackVersion.pack_id == assessment.control_pack,
            ControlPackVersion.version == assessment.control_pack_version,
        )
    )
    if pack is None:
        raise RuntimeError("assessment immutable control pack is missing")

    definitions = list(
        (
            await session.scalars(
                select(ControlDefinition)
                .where(
                    ControlDefinition.tenant_id == assessment.tenant_id,
                    ControlDefinition.control_pack_version_id == pack.id,
                )
                .order_by(ControlDefinition.control_id.asc())
            )
        ).all()
    )
    results = list(
        (
            await session.scalars(
                select(ControlResult).where(
                    ControlResult.tenant_id == assessment.tenant_id,
                    ControlResult.assessment_id == assessment.id,
                )
            )
        ).all()
    )
    decisions = list(
        (
            await session.scalars(
                select(ControlReviewDecision).where(
                    ControlReviewDecision.tenant_id == assessment.tenant_id,
                    ControlReviewDecision.assessment_id == assessment.id,
                )
            )
        ).all()
    )
    evidence = list(
        (
            await session.scalars(
                select(Evidence).where(
                    Evidence.tenant_id == assessment.tenant_id,
                    Evidence.assessment_id == assessment.id,
                )
            )
        ).all()
    )

    result_by_definition = {item.control_definition_id: item for item in results}
    decision_by_definition = {item.control_definition_id: item for item in decisions}
    evidence_by_control: dict[str, list[Evidence]] = {}
    for item in evidence:
        evidence_by_control.setdefault(item.control_id, []).append(item)

    job_ids = {item.source_job_id for item in results if item.source_job_id}
    jobs = (
        list(
            (
                await session.scalars(
                    select(ScanJob).where(
                        ScanJob.tenant_id == assessment.tenant_id,
                        ScanJob.id.in_(job_ids),
                    )
                )
            ).all()
        )
        if job_ids
        else []
    )
    job_by_id = {item.id: item for item in jobs}

    collection_ready = assessment.summary.get("collection_status") == "review_required"
    reviewable = assessment.status in REVIEWABLE_ASSESSMENT_STATUSES and collection_ready
    controls: list[AssessmentReviewControlOut] = []
    blockers: list[str] = []
    for definition in definitions:
        result = result_by_definition.get(definition.id)
        decision = decision_by_definition.get(definition.id)
        control_evidence = sorted(
            evidence_by_control.get(definition.control_id, []),
            key=lambda item: (item.collected_at, item.id),
        )
        observations: list[dict[str, str | int | float | bool | None]] = []
        if result is not None and result.source_job_id:
            source_job = job_by_id.get(result.source_job_id)
            if source_job is not None:
                stored = JobResult.model_validate(source_job.result)
                for probe_result in results_for_control(definition, stored.probe_results):
                    observations.extend(probe_result.observations)

        allowed: list[ControlDecisionOutcome] = []
        if reviewable:
            if definition.assessment_mode == "automated_evidence":
                if result is not None and result.outcome in REVIEWABLE_COLLECTION_OUTCOMES:
                    allowed = [
                        ControlDecisionOutcome.FAILED,
                        ControlDecisionOutcome.NOT_APPLICABLE,
                    ]
                    if result.outcome == ControlResultOutcome.REVIEW_REQUIRED and control_evidence:
                        allowed.insert(0, ControlDecisionOutcome.PASSED)
            else:
                allowed = [
                    ControlDecisionOutcome.FAILED,
                    ControlDecisionOutcome.NOT_APPLICABLE,
                ]
                if control_evidence:
                    allowed.insert(0, ControlDecisionOutcome.PASSED)

        controls.append(
            AssessmentReviewControlOut(
                definition=ControlDefinitionOut.model_validate(definition),
                collection_result=(
                    ControlResultOut.model_validate(result) if result is not None else None
                ),
                evidence_ids=[item.id for item in control_evidence],
                observations=observations,
                decision=(
                    ControlReviewDecisionOut.model_validate(decision)
                    if decision is not None
                    else None
                ),
                allowed_outcomes=allowed,
            )
        )

        if definition.assessment_mode == "automated_evidence" and (
            result is None or result.outcome not in REVIEWABLE_COLLECTION_OUTCOMES
        ):
            blockers.append(f"{definition.title}: collection evidence is not reviewable.")
        if decision is None:
            blockers.append(f"{definition.title}: analyst decision is required.")
        elif decision.outcome not in allowed and assessment.status != AssessmentStatus.COMPLETED:
            blockers.append(f"{definition.title}: the saved decision is no longer valid.")

    if not collection_ready and assessment.status != AssessmentStatus.COMPLETED:
        blockers.insert(0, "Read-only evidence collection has not reached analyst review.")
    if assessment.status == AssessmentStatus.FAILED:
        blockers.insert(0, "Evidence collection failed; this assessment cannot be finalized.")
    elif assessment.status == AssessmentStatus.SUPERSEDED:
        blockers.insert(0, "A newer assessment replaced this review.")

    all_not_applicable = bool(decisions) and len(decisions) == len(definitions) and all(
        item.outcome == ControlDecisionOutcome.NOT_APPLICABLE for item in decisions
    )
    if all_not_applicable:
        blockers.append("At least one control must be applicable to calculate an assurance score.")

    ready = (
        reviewable
        and bool(definitions)
        and len(decisions) == len(definitions)
        and not blockers
    )
    return AssessmentReviewOut(
        assessment=AssessmentOut.model_validate(assessment),
        controls=controls,
        decided_count=len(decisions),
        total_controls=len(definitions),
        ready_to_finalize=ready,
        blocking_reasons=blockers,
    )


async def save_control_review_decision(
    session: AsyncSession,
    *,
    tenant_id: str,
    subject: str,
    assessment_id: str,
    control_definition_id: str,
    payload: ControlReviewDecisionRequest,
) -> AssessmentReviewOut:
    assessment = await session.scalar(
        select(Assessment)
        .where(Assessment.tenant_id == tenant_id, Assessment.id == assessment_id)
        .with_for_update()
    )
    if assessment is None:
        raise DomainError("resource_not_found", "Assessment was not found", 404)
    if assessment.status not in REVIEWABLE_ASSESSMENT_STATUSES:
        raise ConflictError("Only an assessment awaiting analyst review can accept decisions")

    review = await assessment_review_snapshot(session, assessment=assessment)
    control = next(
        (
            item
            for item in review.controls
            if item.definition.id == control_definition_id
        ),
        None,
    )
    if control is None:
        raise DomainError(
            "control_pack_mismatch",
            "The control definition is not part of this assessment's immutable pack",
            422,
        )
    if payload.outcome not in control.allowed_outcomes:
        if (
            control.definition.assessment_mode == "manual_evidence"
            and payload.outcome == ControlDecisionOutcome.PASSED
        ):
            raise DomainError(
                "manual_evidence_required",
                (
                    "A manual control cannot pass until linked execution and "
                    "validation evidence exists"
                ),
                422,
            )
        raise DomainError(
            "decision_not_allowed",
            "The selected decision is not allowed for the collected evidence",
            422,
        )

    now = datetime.now(UTC)
    decision = await session.scalar(
        select(ControlReviewDecision)
        .where(
            ControlReviewDecision.tenant_id == tenant_id,
            ControlReviewDecision.assessment_id == assessment.id,
            ControlReviewDecision.control_definition_id == control_definition_id,
        )
        .with_for_update()
    )
    if decision is None:
        decision = ControlReviewDecision(
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            control_definition_id=control_definition_id,
            control_id=control.definition.control_id,
            outcome=payload.outcome,
            rationale=payload.rationale,
            decided_by=subject,
            decided_at=now,
        )
        session.add(decision)
    else:
        decision.outcome = payload.outcome
        decision.rationale = payload.rationale
        decision.decided_by = subject
        decision.decided_at = now
    assessment.status = AssessmentStatus.REVIEW_REQUIRED
    await session.flush()
    decision_count = len(
        list(
            (
                await session.scalars(
                    select(ControlReviewDecision).where(
                        ControlReviewDecision.tenant_id == tenant_id,
                        ControlReviewDecision.assessment_id == assessment.id,
                    )
                )
            ).all()
        )
    )
    assessment.summary = {
        **assessment.summary,
        "decided_controls": decision_count,
        "reviewed_by": subject,
        "review_status": "in_progress",
    }
    await session.commit()
    return await assessment_review_snapshot(session, assessment=assessment)


async def finalize_assessment_review(
    session: AsyncSession,
    *,
    tenant_id: str,
    subject: str,
    assessment_id: str,
) -> AssessmentReviewOut:
    assessment = await session.scalar(
        select(Assessment)
        .where(Assessment.tenant_id == tenant_id, Assessment.id == assessment_id)
        .with_for_update()
    )
    if assessment is None:
        raise DomainError("resource_not_found", "Assessment was not found", 404)
    if (
        assessment.status == AssessmentStatus.COMPLETED
        and assessment.summary.get("review_status") == "completed"
    ):
        return await assessment_review_snapshot(session, assessment=assessment)

    review = await assessment_review_snapshot(session, assessment=assessment)
    if not review.ready_to_finalize:
        raise DomainError(
            "assessment_not_ready",
            "Every applicable control needs a valid analyst decision before finalization",
            409,
            review.blocking_reasons,
        )

    decisions = [item.decision for item in review.controls if item.decision is not None]
    passed = sum(item.outcome == ControlDecisionOutcome.PASSED for item in decisions)
    failed = sum(item.outcome == ControlDecisionOutcome.FAILED for item in decisions)
    not_applicable = sum(
        item.outcome == ControlDecisionOutcome.NOT_APPLICABLE for item in decisions
    )
    applicable = passed + failed
    if not applicable:
        raise DomainError(
            "assessment_has_no_applicable_controls",
            "At least one control must be applicable to calculate a score",
            409,
        )
    score = round(100 * passed / applicable)
    domain_summary: dict[str, int] = {}
    for domain in {control.definition.domain.value for control in review.controls}:
        domain_decisions = [
            control.decision
            for control in review.controls
            if control.definition.domain.value == domain and control.decision is not None
        ]
        domain_passed = sum(
            item.outcome == ControlDecisionOutcome.PASSED for item in domain_decisions
        )
        domain_failed = sum(
            item.outcome == ControlDecisionOutcome.FAILED for item in domain_decisions
        )
        domain_applicable = domain_passed + domain_failed
        domain_summary[f"domain_{domain}_passed"] = domain_passed
        domain_summary[f"domain_{domain}_failed"] = domain_failed
        domain_summary[f"domain_{domain}_applicable"] = domain_applicable
        if domain_applicable:
            domain_summary[f"domain_{domain}_score"] = round(
                100 * domain_passed / domain_applicable
            )
    now = datetime.now(UTC)
    assessment.status = AssessmentStatus.COMPLETED
    assessment.score = float(score)
    assessment.completed_at = now
    assessment.summary = {
        **assessment.summary,
        "passed": passed,
        "failed": failed,
        "not_applicable": not_applicable,
        "warnings": 0,
        "applicable_controls": applicable,
        "decided_controls": len(decisions),
        "manual_controls_pending": 0,
        "evidence": sum(len(control.evidence_ids) for control in review.controls),
        "reviewed_by": subject,
        "review_status": "completed",
        "score_basis": "analyst_decisions_equal_weight",
        "score_formula": f"{passed} passed / {applicable} applicable controls",
        "collection_status": "review_completed",
        **domain_summary,
    }

    asset = await session.scalar(
        select(Asset).where(Asset.tenant_id == tenant_id, Asset.id == assessment.asset_id)
    )
    if asset is None:
        raise RuntimeError("assessment asset is missing")
    definitions = {
        item.id: item
        for item in (
            await session.scalars(
                select(ControlDefinition).where(
                    ControlDefinition.tenant_id == tenant_id,
                    ControlDefinition.id.in_(
                        [control.definition.id for control in review.controls]
                    ),
                )
            )
        ).all()
    }
    for control in review.controls:
        decision = control.decision
        if decision is None:
            raise RuntimeError("assessment review changed while finalizing")
        definition = definitions[control.definition.id]
        if decision.outcome == ControlDecisionOutcome.FAILED:
            fingerprint = canonical_sha256(
                {
                    "assessment_id": assessment.id,
                    "control_id": definition.control_id,
                    "decision": decision.outcome.value,
                }
            )
            finding = await session.scalar(
                select(Finding).where(
                    Finding.tenant_id == tenant_id,
                    Finding.assessment_id == assessment.id,
                    Finding.control_id == definition.control_id,
                    Finding.fingerprint == fingerprint,
                )
            )
            if finding is None:
                finding = Finding(
                    tenant_id=tenant_id,
                    assessment_id=assessment.id,
                    asset_id=assessment.asset_id,
                    control_id=definition.control_id,
                    fingerprint=fingerprint,
                    domain=definition.domain,
                    title=f"{definition.title}: analyst decision failed",
                    description=decision.rationale,
                    severity=definition.severity,
                    owner=asset.owner,
                    due_at=now + timedelta(days=_remediation_days(definition.severity)),
                    remediation=definition.remediation_guidance,
                    risk_context={
                        "generated_by": "assessment_review",
                        "decision_id": decision.id,
                        "evidence_count": len(control.evidence_ids),
                        "decision": decision.outcome.value,
                    },
                )
                session.add(finding)
        elif decision.outcome == ControlDecisionOutcome.PASSED:
            older_findings = list(
                (
                    await session.scalars(
                        select(Finding).where(
                            Finding.tenant_id == tenant_id,
                            Finding.asset_id == assessment.asset_id,
                            Finding.control_id == definition.control_id,
                            Finding.assessment_id != assessment.id,
                            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
                        )
                    )
                ).all()
            )
            for finding in older_findings:
                if finding.risk_context.get("generated_by") != "assessment_review":
                    continue
                finding.status = FindingStatus.RESOLVED
                finding.risk_context = {
                    **finding.risk_context,
                    "resolved_by_assessment_id": assessment.id,
                }

    await session.flush()
    await enqueue_outbox_once(
        session,
        tenant_id=tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="assessment",
        aggregate_id=assessment.id,
        event_type="assessment.review_completed",
        payload={
            "assessment_id": assessment.id,
            "score": score,
            "passed": passed,
            "failed": failed,
            "not_applicable": not_applicable,
        },
    )
    await session.commit()
    return await assessment_review_snapshot(session, assessment=assessment)


def _remediation_days(severity: FindingSeverity) -> int:
    return {
        FindingSeverity.CRITICAL: 7,
        FindingSeverity.HIGH: 14,
        FindingSeverity.MEDIUM: 30,
        FindingSeverity.LOW: 60,
        FindingSeverity.INFO: 90,
    }[severity]
