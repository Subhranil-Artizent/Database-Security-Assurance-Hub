from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .db import Database
from .governance import enqueue_outbox, orchestrate_assessment_after_job
from .models import (
    AssetEnvironment,
    DeliveryStatus,
    Finding,
    FindingException,
    FindingExceptionStatus,
    FindingStatus,
    IdempotencyRecord,
    IntegrationDestination,
    IntegrationOutbox,
    MaskingPolicy,
    ScanJob,
    WorkStatus,
)
from .observability import (
    JOBS_RECONCILED,
    record_exceptions_expired,
    record_idempotency_recovery,
    record_outbox_reconciliation,
)
from .schemas import JobResult, MaskingCopyJobPayload

logger = logging.getLogger(__name__)


RECONCILER_ADVISORY_LOCK_ID = 4_437_626_318_371_887_441
IDEMPOTENCY_RECONCILER_ADVISORY_LOCK_ID = 4_437_626_318_371_887_442
OUTBOX_RECONCILER_ADVISORY_LOCK_ID = 4_437_626_318_371_887_443
EXCEPTION_RECONCILER_ADVISORY_LOCK_ID = 4_437_626_318_371_887_444


async def reconcile_masking_policy_after_stale_job(
    session: AsyncSession, job: ScanJob
) -> None:
    """Keep the built-in policy aligned with a fenced masking job retry or failure."""
    if job.job_type != "masking_copy":
        return
    try:
        payload = MaskingCopyJobPayload.model_validate(job.payload)
    except ValueError:
        logger.error(
            "stale masking-copy job has an invalid stored payload",
            extra={"event": "masking_copy.reconcile_invalid_payload", "job_id": job.id},
        )
        return
    policy = await session.scalar(
        select(MaskingPolicy)
        .where(
            MaskingPolicy.tenant_id == job.tenant_id,
            MaskingPolicy.id == payload.policy_id,
        )
        .with_for_update()
    )
    if policy is None or not (
        policy.version == 1
        and policy.classification == "Restricted and confidential"
        and policy.strategy == "substitute"
        and policy.target_environment == AssetEnvironment.DEVELOPMENT
        and policy.parameters.get("source_asset") == "insurance_sample"
        and policy.parameters.get("target_database") == payload.target_database
        and (
            payload.target_database
            == f"insurance_sample_masked_{uuid.UUID(policy.id).hex[:12]}"
            or (
                payload.target_database == "insurance_sample_masked"
                and policy.name == "insurance_sample local masking plan"
            )
        )
        and (
            policy.parameters.get("local_copy_plan") is True
            or policy.name == "insurance_sample local masking plan"
        )
    ):
        logger.error(
            "stale masking-copy job is not bound to the built-in policy",
            extra={"event": "masking_copy.reconcile_invalid_policy", "job_id": job.id},
        )
        return
    policy.parameters = {
        **policy.parameters,
        "copy_status": (
            "retry_pending" if job.status == WorkStatus.PENDING else "failed"
        ),
        "copy_job_id": job.id,
    }


async def reconcile_stale_jobs(database: Database, batch_size: int = 100) -> tuple[int, int]:
    """Return expired leases to the queue or terminally fail exhausted jobs."""
    requeued = failed = 0
    now = datetime.now(UTC)
    async with database.maintenance_session_factory() as session:
        if database.engine.dialect.name == "postgresql":
            acquired = await session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": RECONCILER_ADVISORY_LOCK_ID},
            )
            if not acquired:
                logger.debug(
                    "another replica owns the reconciliation lock",
                    extra={"event": "jobs.reconcile_skipped"},
                )
                return 0, 0
        jobs = list(
            (
                await session.scalars(
                    select(ScanJob)
                    .where(
                        ScanJob.status.in_([WorkStatus.LEASED, WorkStatus.RUNNING]),
                        ScanJob.lease_expires_at.is_not(None),
                        ScanJob.lease_expires_at < now,
                    )
                    .order_by(ScanJob.lease_expires_at.asc(), ScanJob.id.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for job in jobs:
            job.leased_by = None
            job.lease_token = None
            job.lease_expires_at = None
            if job.attempts >= job.max_attempts:
                job.status = WorkStatus.FAILED
                job.last_error = "collector lease expired and retry budget was exhausted"
                job.completed_at = now
                failed += 1
            else:
                job.status = WorkStatus.PENDING
                job.last_error = "collector lease expired; job automatically requeued"
                requeued += 1
            await reconcile_masking_policy_after_stale_job(session, job)
            await orchestrate_assessment_after_job(
                session,
                job=job,
                job_result=JobResult.model_validate(job.result),
                now=now,
            )
        await session.commit()
    if jobs:
        logger.warning(
            "reconciled stale scan jobs",
            extra={"event": "jobs.reconciled", "requeued": requeued, "failed": failed},
        )
    if JOBS_RECONCILED is not None:
        JOBS_RECONCILED.labels("requeued").inc(requeued)
        JOBS_RECONCILED.labels("failed").inc(failed)
    return requeued, failed


async def reconcile_uncertain_idempotency(database: Database, batch_size: int = 100) -> int:
    """Escalate expired, uncertain mutations without permitting an unsafe replay."""
    now = datetime.now(UTC)
    async with database.maintenance_session_factory() as session:
        if database.engine.dialect.name == "postgresql":
            acquired = await session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": IDEMPOTENCY_RECONCILER_ADVISORY_LOCK_ID},
            )
            if not acquired:
                return 0
        records = list(
            (
                await session.scalars(
                    select(IdempotencyRecord)
                    .where(
                        IdempotencyRecord.state == "pending",
                        IdempotencyRecord.expires_at < now,
                    )
                    .order_by(IdempotencyRecord.expires_at.asc(), IdempotencyRecord.id.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for record in records:
            record.state = "review_required"
            record.resolution_reason = (
                "reservation expired before a durable response was recorded; "
                "operator review required"
            )
        await session.commit()
    if records:
        logger.error(
            "idempotency reservations require operator review",
            extra={"event": "idempotency.recovery_required", "count": len(records)},
        )
        record_idempotency_recovery("review_required", len(records))
    return len(records)


async def reconcile_stale_outbox(database: Database, batch_size: int = 100) -> tuple[int, int]:
    requeued = dead_lettered = 0
    now = datetime.now(UTC)
    async with database.maintenance_session_factory() as session:
        if database.engine.dialect.name == "postgresql":
            acquired = await session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": OUTBOX_RECONCILER_ADVISORY_LOCK_ID},
            )
            if not acquired:
                return 0, 0
        events = list(
            (
                await session.scalars(
                    select(IntegrationOutbox)
                    .where(
                        IntegrationOutbox.status.in_(
                            [DeliveryStatus.LEASED, DeliveryStatus.RUNNING]
                        ),
                        IntegrationOutbox.lease_expires_at.is_not(None),
                        IntegrationOutbox.lease_expires_at < now,
                    )
                    .order_by(
                        IntegrationOutbox.lease_expires_at.asc(),
                        IntegrationOutbox.id.asc(),
                    )
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for event in events:
            event.leased_by = None
            event.lease_token = None
            event.lease_expires_at = None
            if event.attempts >= event.max_attempts:
                event.status = DeliveryStatus.DEAD_LETTER
                event.last_error = "delivery lease expired and retry budget was exhausted"
                event.completed_at = now
                dead_lettered += 1
            else:
                event.status = DeliveryStatus.PENDING
                event.last_error = "delivery lease expired; event automatically requeued"
                event.available_at = now + timedelta(seconds=min(900, 2**event.attempts))
                requeued += 1
        await session.commit()
    if events:
        logger.warning(
            "reconciled stale integration outbox leases",
            extra={
                "event": "outbox.reconciled",
                "requeued": requeued,
                "dead_lettered": dead_lettered,
            },
        )
        record_outbox_reconciliation("requeued", requeued)
        record_outbox_reconciliation("dead_lettered", dead_lettered)
    return requeued, dead_lettered


async def expire_finding_exceptions(database: Database, batch_size: int = 100) -> int:
    now = datetime.now(UTC)
    async with database.maintenance_session_factory() as session:
        if database.engine.dialect.name == "postgresql":
            acquired = await session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": EXCEPTION_RECONCILER_ADVISORY_LOCK_ID},
            )
            if not acquired:
                return 0
        exceptions = list(
            (
                await session.scalars(
                    select(FindingException)
                    .where(
                        FindingException.status == FindingExceptionStatus.APPROVED,
                        FindingException.expires_at <= now,
                    )
                    .order_by(FindingException.expires_at.asc(), FindingException.id.asc())
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        for exception in exceptions:
            exception.status = FindingExceptionStatus.EXPIRED
            finding = await session.scalar(
                select(Finding).where(
                    Finding.tenant_id == exception.tenant_id,
                    Finding.id == exception.finding_id,
                )
            )
            if finding is not None and finding.status == FindingStatus.RISK_ACCEPTED:
                finding.status = FindingStatus.OPEN
            enqueue_outbox(
                session,
                tenant_id=exception.tenant_id,
                destination=IntegrationDestination.GRC,
                aggregate_type="finding_exception",
                aggregate_id=exception.id,
                event_type="finding_exception.expired",
                payload={
                    "finding_id": exception.finding_id,
                    "status": FindingExceptionStatus.EXPIRED.value,
                },
            )
        await session.commit()
    if exceptions:
        logger.warning(
            "expired approved finding exceptions",
            extra={"event": "finding_exceptions.expired", "count": len(exceptions)},
        )
        record_exceptions_expired(len(exceptions))
    return len(exceptions)


async def reconciliation_loop(
    database: Database, interval_seconds: int, batch_size: int = 100
) -> None:
    while True:
        # Stagger startup work so replicas do not contend with migrations, seeding,
        # readiness checks, or SQLite's single test connection during boot.
        await asyncio.sleep(interval_seconds)
        try:
            await reconcile_stale_jobs(database, batch_size)
            await reconcile_uncertain_idempotency(database, batch_size)
            await reconcile_stale_outbox(database, batch_size)
            await expire_finding_exceptions(database, batch_size)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "stale job reconciliation failed", extra={"event": "jobs.reconcile_failed"}
            )
