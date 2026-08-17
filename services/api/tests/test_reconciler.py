from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from assurance_hub.config import Settings
from assurance_hub.db import Database
from assurance_hub.models import (
    Assessment,
    AssessmentStatus,
    Asset,
    AssetEnvironment,
    Connector,
    ControlDomain,
    DatabasePlatform,
    DeliveryStatus,
    Finding,
    FindingException,
    FindingExceptionStatus,
    FindingSeverity,
    FindingStatus,
    IdempotencyRecord,
    IntegrationDestination,
    IntegrationOutbox,
    MaskingPolicy,
    ScanJob,
    WorkStatus,
)
from assurance_hub.reconciler import (
    expire_finding_exceptions,
    reconcile_stale_jobs,
    reconcile_stale_outbox,
    reconcile_uncertain_idempotency,
)


@pytest.mark.asyncio
async def test_distinct_maintenance_url_creates_a_dedicated_reconciler_factory():
    database = Database(
        Settings(
            environment="test",
            database_url="sqlite+aiosqlite:///:memory:",
            database_maintenance_url="sqlite+aiosqlite:///maintenance-test.db",
        )
    )
    try:
        assert database.maintenance_engine is not None
        assert database.maintenance_session_factory is not database.session_factory
        assert database.maintenance_session_factory.kw["bind"] is database.maintenance_engine
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_reconciler_uses_a_deterministic_bounded_batch():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    expired = datetime.now(UTC) - timedelta(minutes=5)
    async with database.session_factory() as session:
        asset = Asset(
            tenant_id="tenant-alpha",
            external_id="reconciler-asset",
            name="Reconciler Test Asset",
            platform=DatabasePlatform.ORACLE,
            version="23ai",
            environment=AssetEnvironment.TEST,
            owner="test",
        )
        session.add(asset)
        await session.flush()
        connector = Connector(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            name="reconciler-connector",
            platform=DatabasePlatform.ORACLE,
            endpoint_ref="dns://reconciler.internal:1521/testdb",
            secret_ref="vault://test/reconciler#readonly",  # noqa: S106
            collector_id="collector-test",
        )
        session.add(connector)
        await session.flush()
        for index in range(3):
            session.add(
                ScanJob(
                    tenant_id="tenant-alpha",
                    connector_id=connector.id,
                    job_type="inventory",
                    deduplication_key=f"reconcile-test-{index}",
                    status=WorkStatus.LEASED,
                    payload={"probe_ids": ["oracle.version"]},
                    leased_by="collector-test",
                    lease_expires_at=expired,
                    attempts=1,
                    max_attempts=3,
                )
            )
        await session.commit()

    assert await reconcile_stale_jobs(database, batch_size=2) == (2, 0)
    async with database.session_factory() as session:
        pending = await session.scalar(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == WorkStatus.PENDING)
        )
        leased = await session.scalar(
            select(func.count()).select_from(ScanJob).where(ScanJob.status == WorkStatus.LEASED)
        )
        assert (pending, leased) == (2, 1)

    assert await reconcile_stale_jobs(database, batch_size=2) == (1, 0)
    await database.dispose()


@pytest.mark.asyncio
async def test_sqlite_stale_masking_job_reconciles_policy_without_scoring_assessment():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    expired = datetime.now(UTC) - timedelta(minutes=5)
    async with database.session_factory() as session:
        asset = Asset(
            tenant_id="tenant-alpha",
            external_id="local-mysql-insurance-sample",
            name="insurance_sample",
            platform=DatabasePlatform.MYSQL,
            version="8.4",
            environment=AssetEnvironment.DEVELOPMENT,
            owner="test",
        )
        session.add(asset)
        await session.flush()
        connector = Connector(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            name="local-mysql-insurance-sample-masking-copy",
            platform=DatabasePlatform.MYSQL,
            endpoint_ref="dns://localhost:3306/insurance_sample",
            secret_ref="vault://local/database/mysql-insurance-sample-masked#writer",  # noqa: S106
            collector_id="local-mysql-masker",
            capabilities=["masking_copy"],
        )
        assessment = Assessment(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            control_pack="aegisdb.database-security.mysql",
            control_pack_version="1.0.0",
            status=AssessmentStatus.REVIEW_REQUIRED,
            score=None,
            initiated_by="analyst@example.com",
            summary={"collection_status": "review_required"},
        )
        policy = MaskingPolicy(
            tenant_id="tenant-alpha",
            name="insurance_sample local masking plan",
            version=1,
            classification="Restricted and confidential",
            strategy="substitute",
            target_environment=AssetEnvironment.DEVELOPMENT,
            enabled=True,
            approved_by="analyst@example.com",
            parameters={
                "source_asset": "insurance_sample",
                "target_database": "insurance_sample_masked",
                "workflow_status": "approved",
                "copy_status": "running",
            },
        )
        session.add_all([connector, assessment, policy])
        await session.flush()
        job = ScanJob(
            tenant_id="tenant-alpha",
            connector_id=connector.id,
            assessment_id=assessment.id,
            job_type="masking_copy",
            deduplication_key=(
                f"masking-copy:{policy.id}:insurance_sample_masked"
            ),
            status=WorkStatus.LEASED,
            payload={
                "policy_id": policy.id,
                "asset_id": asset.id,
                "source_database": "insurance_sample",
                "target_database": "insurance_sample_masked",
                "row_cap": 500,
            },
            leased_by="local-mysql-masker",
            lease_token="11111111-1111-4111-8111-111111111111",  # noqa: S106
            lease_expires_at=expired,
            attempts=1,
            max_attempts=2,
        )
        session.add(job)
        await session.commit()
        job_id = job.id
        policy_id = policy.id
        assessment_id = assessment.id

    assert await reconcile_stale_jobs(database) == (1, 0)
    async with database.session_factory() as session:
        job = await session.get(ScanJob, job_id)
        policy = await session.get(MaskingPolicy, policy_id)
        assessment = await session.get(Assessment, assessment_id)
        assert job is not None and job.status == WorkStatus.PENDING
        assert policy is not None and policy.parameters["copy_status"] == "retry_pending"
        assert policy.parameters["copy_job_id"] == job_id
        assert assessment is not None
        assert assessment.status == AssessmentStatus.REVIEW_REQUIRED
        assert assessment.score is None

        job.status = WorkStatus.RUNNING
        job.leased_by = "local-mysql-masker"
        job.lease_token = "22222222-2222-4222-8222-222222222222"  # noqa: S105
        job.lease_expires_at = expired
        job.attempts = job.max_attempts
        policy.parameters = {**policy.parameters, "copy_status": "running"}
        await session.commit()

    assert await reconcile_stale_jobs(database) == (0, 1)
    async with database.session_factory() as session:
        job = await session.get(ScanJob, job_id)
        policy = await session.get(MaskingPolicy, policy_id)
        assessment = await session.get(Assessment, assessment_id)
        assert job is not None and job.status == WorkStatus.FAILED
        assert policy is not None and policy.parameters["copy_status"] == "failed"
        assert assessment is not None
        assert assessment.status == AssessmentStatus.REVIEW_REQUIRED
        assert assessment.score is None
    await database.dispose()


@pytest.mark.asyncio
async def test_exhausted_stale_job_fails_its_assessment_in_the_same_reconciliation():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    async with database.session_factory() as session:
        asset = Asset(
            tenant_id="tenant-alpha",
            external_id="terminal-reconciler-asset",
            name="Terminal Reconciler Test Asset",
            platform=DatabasePlatform.ORACLE,
            version="23ai",
            environment=AssetEnvironment.TEST,
            owner="test",
        )
        session.add(asset)
        await session.flush()
        connector = Connector(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            name="terminal-reconciler-connector",
            platform=DatabasePlatform.ORACLE,
            endpoint_ref="dns://terminal-reconciler.internal:1521/testdb",
            secret_ref="vault://test/terminal-reconciler#readonly",  # noqa: S106
            collector_id="collector-test",
        )
        assessment = Assessment(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            control_pack="aegisdb.database-security.oracle",
            control_pack_version="1.0.0",
            initiated_by="analyst@example.com",
        )
        session.add_all([connector, assessment])
        await session.flush()
        job = ScanJob(
            tenant_id="tenant-alpha",
            connector_id=connector.id,
            assessment_id=assessment.id,
            job_type="control_assessment",
            deduplication_key="terminal-reconciler-job-01",
            status=WorkStatus.LEASED,
            payload={"probe_ids": ["oracle.tablespace_encryption"]},
            leased_by="collector-test",
            lease_expires_at=datetime.now(UTC) - timedelta(minutes=5),
            attempts=1,
            max_attempts=1,
        )
        session.add(job)
        await session.commit()
        assessment_id = assessment.id

    assert await reconcile_stale_jobs(database) == (0, 1)
    async with database.session_factory() as session:
        reconciled = await session.get(Assessment, assessment_id)
        assert reconciled is not None
        assert reconciled.status == AssessmentStatus.FAILED
        assert reconciled.completed_at is not None
        assert reconciled.score is None
        assert reconciled.summary["collection_status"] == "failed"
        assert reconciled.summary["score_basis"] == ("no_assurance_score_when_collection_fails")
    await database.dispose()


@pytest.mark.asyncio
async def test_outbox_and_exception_reconciliation_are_fenced_and_auditable():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    now = datetime.now(UTC)
    async with database.session_factory() as session:
        asset = Asset(
            tenant_id="tenant-alpha",
            external_id="governance-reconciler-asset",
            name="Governance Reconciler Asset",
            platform=DatabasePlatform.ORACLE,
            version="23ai",
            environment=AssetEnvironment.TEST,
            owner="test",
        )
        session.add(asset)
        await session.flush()
        assessment = Assessment(
            tenant_id="tenant-alpha",
            asset_id=asset.id,
            control_pack="aegisdb.database-security.oracle",
            control_pack_version="1.0.0",
            initiated_by="analyst@example.com",
        )
        session.add(assessment)
        await session.flush()
        finding = Finding(
            tenant_id="tenant-alpha",
            assessment_id=assessment.id,
            asset_id=asset.id,
            control_id="oracle.encryption.tablespace-metadata",
            fingerprint="expiry-reconciler-fingerprint",
            domain=ControlDomain.ENCRYPTION,
            title="Temporary exception",
            description="Temporary exception awaiting automatic expiry.",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.RISK_ACCEPTED,
            remediation="Return the finding to normal remediation workflow.",
        )
        session.add(finding)
        await session.flush()
        exception = FindingException(
            tenant_id="tenant-alpha",
            finding_id=finding.id,
            request_key="expired-exception-request-01",
            status=FindingExceptionStatus.APPROVED,
            justification="A bounded test exception that has already expired.",
            requested_by="requester@example.com",
            requested_at=now - timedelta(days=2),
            expires_at=now - timedelta(days=1),
            approved_by="approver@example.com",
            approved_at=now - timedelta(days=2),
            decision_reason="Approved only for the original bounded period.",
        )
        stale_event = IntegrationOutbox(
            tenant_id="tenant-alpha",
            destination=IntegrationDestination.GRC,
            aggregate_type="finding",
            aggregate_id=finding.id,
            event_type="finding.created",
            deduplication_key="reconciler-outbox-event-01",
            payload={"finding_id": finding.id},
            status=DeliveryStatus.LEASED,
            leased_by="worker-old",
            lease_token="00000000-0000-4000-8000-000000000000",  # noqa: S106
            lease_expires_at=now - timedelta(minutes=1),
            attempts=1,
            max_attempts=3,
        )
        session.add_all([exception, stale_event])
        await session.commit()
        exception_id = exception.id
        finding_id = finding.id
        stale_event_id = stale_event.id

    assert await reconcile_stale_outbox(database) == (1, 0)
    assert await expire_finding_exceptions(database) == 1
    async with database.session_factory() as session:
        reconciled_event = await session.get(IntegrationOutbox, stale_event_id)
        expired_exception = await session.get(FindingException, exception_id)
        reopened_finding = await session.get(Finding, finding_id)
        expiry_event = await session.scalar(
            select(IntegrationOutbox).where(
                IntegrationOutbox.event_type == "finding_exception.expired"
            )
        )
        assert reconciled_event is not None
        assert reconciled_event.status == DeliveryStatus.PENDING
        assert reconciled_event.lease_token is None
        assert expired_exception is not None
        assert expired_exception.status == FindingExceptionStatus.EXPIRED
        assert reopened_finding is not None
        assert reopened_finding.status == FindingStatus.OPEN
        assert expiry_event is not None
    await database.dispose()


@pytest.mark.asyncio
async def test_uncertain_idempotency_is_escalated_without_reopening_replay():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    async with database.session_factory() as session:
        reservation = IdempotencyRecord(
            tenant_id="tenant-alpha",
            actor_subject="analyst@example.com",
            authorization_hash="a" * 64,
            method="POST",
            path="/api/v1/assets",
            idempotency_key="uncertain-reservation-01",
            request_hash="b" * 64,
            state="pending",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
        session.add(reservation)
        await session.commit()
        reservation_id = reservation.id

    assert await reconcile_uncertain_idempotency(database) == 1
    async with database.session_factory() as session:
        reconciled = await session.get(IdempotencyRecord, reservation_id)
        assert reconciled is not None
        assert reconciled.state == "review_required"
        assert reconciled.response_status is None
    await database.dispose()
