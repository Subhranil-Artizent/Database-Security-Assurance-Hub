from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    Assessment,
    AssessmentStatus,
    ControlDefinition,
    ControlPackVersion,
    ControlResult,
    ControlResultOutcome,
    Evidence,
    Finding,
    IntegrationDestination,
    IntegrationOutbox,
    ScanJob,
    WorkStatus,
)
from .schemas import JobResult, JsonScalar, ProbeExecutionResult, ScanJobPayload

EVALUATOR_VERSION = "rules-1.0"


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class EvaluationDecision:
    outcome: ControlResultOutcome
    rationale: str


@dataclass(frozen=True, slots=True)
class PreparedControlEvaluation:
    outcome: ControlResultOutcome
    rationale: str
    input_sha256: str
    evaluation_key: str
    probe_outcomes: list[str]


def evaluate_analyst_review_control(
    *, assessment_mode: str, probe_outcomes: Sequence[str], evidence_count: int
) -> EvaluationDecision:
    """Classify collection state without inventing assurance conclusions."""
    outcomes = set(probe_outcomes)
    if "error" in outcomes:
        return EvaluationDecision(
            ControlResultOutcome.COLLECTION_ERROR,
            "At least one approved probe reported a collection error; no pass was inferred.",
        )
    if "insufficient_privilege" in outcomes:
        return EvaluationDecision(
            ControlResultOutcome.INSUFFICIENT_PRIVILEGE,
            "The collector lacked an approved read privilege; no pass was inferred.",
        )
    if "unsupported" in outcomes:
        return EvaluationDecision(
            ControlResultOutcome.UNSUPPORTED,
            "The source environment reported an unsupported probe; no pass was inferred.",
        )
    if outcomes and outcomes == {"not_applicable"}:
        return EvaluationDecision(
            ControlResultOutcome.NOT_APPLICABLE,
            "All approved probes reported not applicable; reviewer confirmation is retained.",
        )
    if assessment_mode == "manual_evidence" and evidence_count < 1:
        return EvaluationDecision(
            ControlResultOutcome.COLLECTION_ERROR,
            "Required manual evidence was not supplied; no pass was inferred.",
        )
    if assessment_mode == "automated_evidence" and not probe_outcomes:
        return EvaluationDecision(
            ControlResultOutcome.COLLECTION_ERROR,
            "No approved probe result was supplied; no pass was inferred.",
        )
    return EvaluationDecision(
        ControlResultOutcome.REVIEW_REQUIRED,
        "Evidence was collected and requires analyst review; collection is not a control pass.",
    )


def validate_probe_evidence(
    definition: ControlDefinition, results: list[ProbeExecutionResult]
) -> None:
    expected = set(definition.probe_ids)
    supplied = [result.probe_id for result in results]
    if len(supplied) != len(set(supplied)):
        raise ValueError("probe results must be unique")
    if not set(supplied).issubset(expected):
        raise ValueError("probe result is not approved by this immutable control definition")
    allowed_fields = set(definition.allowed_fields)
    for result in results:
        for observation in result.observations:
            unexpected = set(observation) - allowed_fields
            if unexpected:
                raise ValueError(
                    "observation contains fields not approved by the control definition"
                )


def results_for_control(
    definition: ControlDefinition,
    results: Sequence[ProbeExecutionResult],
) -> list[ProbeExecutionResult]:
    """Select only the immutable probe evidence owned by one control definition."""
    expected = set(definition.probe_ids)
    return sorted(
        (result for result in results if result.probe_id in expected),
        key=lambda result: result.probe_id,
    )


def prepare_control_evaluation(
    *,
    tenant_id: str,
    assessment_id: str,
    definition: ControlDefinition,
    source_job_id: str | None,
    probe_results: list[ProbeExecutionResult],
    evidence_ids: Sequence[str] = (),
    schema_version: str = "1.0",
) -> PreparedControlEvaluation:
    """Create the deterministic immutable evaluation envelope used by every workflow."""
    validate_probe_evidence(definition, probe_results)
    normalized_results = sorted(
        [result.model_dump(mode="json") for result in probe_results],
        key=lambda item: str(item["probe_id"]),
    )
    evaluation_input = {
        "schema_version": schema_version,
        "assessment_id": assessment_id,
        "control_definition_id": definition.id,
        "source_job_id": source_job_id,
        "probe_results": normalized_results,
        "evidence_ids": sorted(evidence_ids),
        "evaluator_version": EVALUATOR_VERSION,
    }
    input_sha256 = canonical_sha256(evaluation_input)
    probe_outcomes = [str(result.outcome) for result in probe_results]
    expected_probes = set(definition.probe_ids)
    supplied_probes = {result.probe_id for result in probe_results}
    if definition.assessment_mode == "automated_evidence" and supplied_probes != expected_probes:
        decision = EvaluationDecision(
            ControlResultOutcome.COLLECTION_ERROR,
            "The approved probe set was incomplete; no pass was inferred.",
        )
    else:
        decision = evaluate_analyst_review_control(
            assessment_mode=definition.assessment_mode,
            probe_outcomes=probe_outcomes,
            evidence_count=len(evidence_ids),
        )
    evaluation_key = canonical_sha256(
        {
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "control_definition_id": definition.id,
            "input_sha256": input_sha256,
            "evaluator_version": EVALUATOR_VERSION,
        }
    )
    return PreparedControlEvaluation(
        outcome=decision.outcome,
        rationale=decision.rationale,
        input_sha256=input_sha256,
        evaluation_key=evaluation_key,
        probe_outcomes=probe_outcomes,
    )


async def orchestrate_assessment_after_job(
    session: AsyncSession,
    *,
    job: ScanJob,
    job_result: JobResult,
    now: datetime,
) -> None:
    """Progress an assessment in the same transaction as its fenced job completion.

    Collected metadata never becomes an inferred control pass. Automated controls
    receive immutable collection/review results; manual controls remain explicit
    in the summary for a later human-evidence workflow.
    """
    if job.assessment_id is None or job.job_type != "control_assessment":
        return
    assessment = await session.scalar(
        select(Assessment)
        .where(
            Assessment.tenant_id == job.tenant_id,
            Assessment.id == job.assessment_id,
        )
        .with_for_update()
    )
    if assessment is None:
        raise RuntimeError("assessment orchestration target is missing")
    assessment.started_at = assessment.started_at or now

    if job.status != WorkStatus.SUCCEEDED:
        assessment.score = None
        if job.status == WorkStatus.FAILED:
            assessment.status = AssessmentStatus.FAILED
            assessment.completed_at = now
            assessment.summary = {
                **assessment.summary,
                "source_job_id": job.id,
                "collection_status": "failed",
                "score_basis": "no_assurance_score_when_collection_fails",
            }
            await enqueue_outbox_once(
                session,
                tenant_id=job.tenant_id,
                destination=IntegrationDestination.GRC,
                aggregate_type="assessment",
                aggregate_id=assessment.id,
                event_type="assessment.collection_failed",
                payload={"assessment_id": assessment.id, "job_id": job.id},
            )
        else:
            assessment.status = AssessmentStatus.RUNNING
            assessment.completed_at = None
            assessment.summary = {
                **assessment.summary,
                "source_job_id": job.id,
                "collection_status": "retry_scheduled",
                "score_basis": "pending_bounded_collection_retry",
            }
        return

    pack = await session.scalar(
        select(ControlPackVersion).where(
            ControlPackVersion.tenant_id == job.tenant_id,
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
                    ControlDefinition.tenant_id == job.tenant_id,
                    ControlDefinition.control_pack_version_id == pack.id,
                )
                .order_by(ControlDefinition.control_id.asc())
            )
        ).all()
    )
    automated = [item for item in definitions if item.assessment_mode == "automated_evidence"]
    manual_count = len(definitions) - len(automated)
    requested = ScanJobPayload.model_validate(job.payload)
    expected_probe_ids = sorted(
        {probe_id for definition in automated for probe_id in definition.probe_ids}
    )
    if sorted(requested.probe_ids) != expected_probe_ids:
        raise RuntimeError("assessment job probes differ from its immutable control pack")
    if (
        requested.metadata.get("control_pack_id") != pack.pack_id
        or requested.metadata.get("control_pack_version") != pack.version
    ):
        raise RuntimeError("assessment job metadata differs from its immutable control pack")
    prepared_results: list[PreparedControlEvaluation] = []
    materialized_evidence_count = 0
    for definition in automated:
        control_probe_results = results_for_control(definition, job_result.probe_results)
        evidence_count = 0
        for probe_result in control_probe_results:
            evidence = await ensure_collected_evidence(
                session,
                assessment=assessment,
                definition=definition,
                job=job,
                probe_result=probe_result,
                job_result=job_result,
                now=now,
            )
            evidence_count += evidence is not None
        materialized_evidence_count += evidence_count
        prepared = prepare_control_evaluation(
            tenant_id=job.tenant_id,
            assessment_id=assessment.id,
            definition=definition,
            source_job_id=job.id,
            probe_results=control_probe_results,
        )
        prepared_results.append(prepared)
        existing = await session.scalar(
            select(ControlResult).where(
                ControlResult.tenant_id == job.tenant_id,
                ControlResult.assessment_id == assessment.id,
                ControlResult.control_definition_id == definition.id,
            )
        )
        if existing is not None:
            if (
                existing.input_sha256 != prepared.input_sha256
                or existing.evidence_count != evidence_count
            ):
                raise RuntimeError("immutable control result conflicts with collector evidence")
            result = existing
        else:
            result = ControlResult(
                tenant_id=job.tenant_id,
                assessment_id=assessment.id,
                control_definition_id=definition.id,
                source_job_id=job.id,
                control_id=definition.control_id,
                evaluation_key=prepared.evaluation_key,
                outcome=prepared.outcome,
                evaluator_version=EVALUATOR_VERSION,
                input_sha256=prepared.input_sha256,
                rationale=prepared.rationale,
                evidence_count=evidence_count,
                probe_outcomes=prepared.probe_outcomes,
                evaluated_at=now,
            )
            session.add(result)
            await session.flush()
            await enqueue_outbox_once(
                session,
                tenant_id=job.tenant_id,
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
        if prepared.outcome in {
            ControlResultOutcome.COLLECTION_ERROR,
            ControlResultOutcome.INSUFFICIENT_PRIVILEGE,
            ControlResultOutcome.UNSUPPORTED,
        }:
            await ensure_collection_finding(
                session,
                assessment=assessment,
                definition=definition,
                result=result,
                source_job_id=job.id,
                prepared=prepared,
            )

    outcome_counts = {
        outcome.value: sum(item.outcome == outcome for item in prepared_results)
        for outcome in ControlResultOutcome
    }
    collection_defects = sum(
        outcome_counts[outcome.value]
        for outcome in (
            ControlResultOutcome.COLLECTION_ERROR,
            ControlResultOutcome.INSUFFICIENT_PRIVILEGE,
            ControlResultOutcome.UNSUPPORTED,
        )
    )
    collected_count = sum(
        item.outcome in {ControlResultOutcome.REVIEW_REQUIRED, ControlResultOutcome.NOT_APPLICABLE}
        for item in prepared_results
    )
    collection_coverage = round(100 * collected_count / len(automated)) if automated else 0
    pending_review = outcome_counts[ControlResultOutcome.REVIEW_REQUIRED.value]
    pending_review += outcome_counts[ControlResultOutcome.NOT_APPLICABLE.value]
    assessment.score = None
    assessment.summary = {
        **assessment.summary,
        "source_job_id": job.id,
        "automated_controls": len(automated),
        "manual_controls_pending": manual_count,
        "control_results": len(prepared_results),
        "collection_coverage": collection_coverage,
        "review_required": outcome_counts[ControlResultOutcome.REVIEW_REQUIRED.value],
        "not_applicable": outcome_counts[ControlResultOutcome.NOT_APPLICABLE.value],
        "collection_errors": outcome_counts[ControlResultOutcome.COLLECTION_ERROR.value],
        "unsupported": outcome_counts[ControlResultOutcome.UNSUPPORTED.value],
        "insufficient_privilege": outcome_counts[ControlResultOutcome.INSUFFICIENT_PRIVILEGE.value],
        "passed": outcome_counts[ControlResultOutcome.PASSED.value],
        "failed": outcome_counts[ControlResultOutcome.FAILED.value],
        "warnings": pending_review + collection_defects + manual_count,
        "evidence": materialized_evidence_count,
        "score_basis": "human_control_decision_required",
    }
    if collection_defects:
        assessment.status = AssessmentStatus.FAILED
        assessment.completed_at = now
        collection_status = "failed"
        event_type = "assessment.collection_failed"
    elif manual_count or pending_review:
        assessment.status = AssessmentStatus.REVIEW_REQUIRED
        assessment.completed_at = None
        collection_status = "review_required"
        event_type = "assessment.collection_review_required"
    else:
        assessment.status = AssessmentStatus.COMPLETED
        assessment.completed_at = now
        collection_status = "completed"
        event_type = "assessment.completed"
    assessment.summary = {**assessment.summary, "collection_status": collection_status}
    await enqueue_outbox_once(
        session,
        tenant_id=job.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="assessment",
        aggregate_id=assessment.id,
        event_type=event_type,
        payload={
            "assessment_id": assessment.id,
            "job_id": job.id,
            "collection_status": collection_status,
        },
    )


async def ensure_collected_evidence(
    session: AsyncSession,
    *,
    assessment: Assessment,
    definition: ControlDefinition,
    job: ScanJob,
    probe_result: ProbeExecutionResult,
    job_result: JobResult,
    now: datetime,
) -> Evidence | None:
    """Persist digest-only lineage for collected metadata without duplicating observations."""
    if probe_result.outcome != "collected" or probe_result.evidence_sha256 is None:
        return None
    uri = f"evidence://scan-jobs/{job.id}/controls/{definition.id}/probes/{probe_result.probe_id}"
    existing = await session.scalar(
        select(Evidence).where(
            Evidence.tenant_id == assessment.tenant_id,
            Evidence.assessment_id == assessment.id,
            Evidence.control_id == definition.control_id,
            Evidence.uri == uri,
        )
    )
    if existing is not None:
        if existing.sha256 != probe_result.evidence_sha256:
            raise RuntimeError("persisted evidence lineage conflicts with collector evidence")
        return existing
    reported_version = job_result.summary.get("collector_version")
    collector_version = (
        reported_version
        if isinstance(reported_version, str) and 1 <= len(reported_version) <= 40
        else "unknown"
    )
    evidence = Evidence(
        tenant_id=assessment.tenant_id,
        assessment_id=assessment.id,
        finding_id=None,
        control_id=definition.control_id,
        evidence_type="query_result",
        uri=uri,
        sha256=probe_result.evidence_sha256,
        collected_at=now,
        collector_version=collector_version,
        attributes={
            "source_job_id": job.id,
            "probe_id": probe_result.probe_id,
            "row_count": probe_result.row_count,
            "outcome": probe_result.outcome,
        },
    )
    session.add(evidence)
    await session.flush()
    await enqueue_outbox_once(
        session,
        tenant_id=assessment.tenant_id,
        destination=IntegrationDestination.GRC,
        aggregate_type="evidence",
        aggregate_id=evidence.id,
        event_type="evidence.collected",
        payload={
            "assessment_id": assessment.id,
            "control_id": definition.control_id,
            "evidence_id": evidence.id,
            "probe_id": probe_result.probe_id,
            "sha256": probe_result.evidence_sha256,
        },
    )
    return evidence


async def ensure_collection_finding(
    session: AsyncSession,
    *,
    assessment: Assessment,
    definition: ControlDefinition,
    result: ControlResult,
    source_job_id: str,
    prepared: PreparedControlEvaluation,
) -> Finding:
    fingerprint = canonical_sha256(
        {
            "assessment_id": assessment.id,
            "control_id": definition.control_id,
            "source_job_id": source_job_id,
            "outcome": prepared.outcome.value,
        }
    )
    existing = await session.scalar(
        select(Finding).where(
            Finding.tenant_id == assessment.tenant_id,
            Finding.assessment_id == assessment.id,
            Finding.control_id == definition.control_id,
            Finding.fingerprint == fingerprint,
        )
    )
    if existing is not None:
        return existing
    finding = Finding(
        tenant_id=assessment.tenant_id,
        assessment_id=assessment.id,
        asset_id=assessment.asset_id,
        control_id=definition.control_id,
        fingerprint=fingerprint,
        domain=definition.domain,
        title=f"{definition.title}: evidence collection gap",
        description=prepared.rationale,
        severity=definition.severity,
        remediation=definition.remediation_guidance,
        risk_context={
            "assurance_gap": True,
            "control_result_id": result.id,
            "outcome": prepared.outcome.value,
            "source_job_id": source_job_id,
        },
    )
    session.add(finding)
    return finding


async def enqueue_outbox_once(
    session: AsyncSession,
    *,
    tenant_id: str,
    destination: IntegrationDestination,
    aggregate_type: str,
    aggregate_id: str,
    event_type: str,
    payload: dict[str, JsonScalar],
    event_version: int = 1,
) -> IntegrationOutbox:
    deduplication_key = canonical_sha256(
        {
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "event_type": event_type,
            "event_version": event_version,
        }
    )
    existing = await session.scalar(
        select(IntegrationOutbox).where(
            IntegrationOutbox.tenant_id == tenant_id,
            IntegrationOutbox.destination == destination,
            IntegrationOutbox.deduplication_key == deduplication_key,
        )
    )
    if existing is not None:
        return existing
    event = enqueue_outbox(
        session,
        tenant_id=tenant_id,
        destination=destination,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        event_type=event_type,
        payload=payload,
        event_version=event_version,
    )
    # The session disables autoflush. Persist the deduplication key now so a
    # second call in this transaction observes the first event.
    await session.flush()
    return event


def enqueue_outbox(
    session: AsyncSession,
    *,
    tenant_id: str,
    destination: IntegrationDestination,
    aggregate_type: str,
    aggregate_id: str,
    event_type: str,
    payload: dict[str, JsonScalar],
    event_version: int = 1,
) -> IntegrationOutbox:
    deduplication_key = canonical_sha256(
        {
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "event_type": event_type,
            "event_version": event_version,
        }
    )
    event = IntegrationOutbox(
        tenant_id=tenant_id,
        destination=destination,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        event_type=event_type,
        event_version=event_version,
        deduplication_key=deduplication_key,
        payload=payload,
    )
    session.add(event)
    return event
