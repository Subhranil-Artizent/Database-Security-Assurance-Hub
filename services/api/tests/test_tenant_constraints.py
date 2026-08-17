from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError, StatementError

from assurance_hub.config import Settings
from assurance_hub.db import Database
from assurance_hub.models import (
    Asset,
    AssetEnvironment,
    Connector,
    ControlDefinition,
    ControlDomain,
    ControlPackStatus,
    ControlPackVersion,
    DatabasePlatform,
    FindingSeverity,
)


@pytest.mark.asyncio
async def test_composite_foreign_key_rejects_cross_tenant_parent_reference():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    async with database.session_factory() as session:
        asset = Asset(
            tenant_id="tenant-alpha",
            external_id="tenant-parent",
            name="Tenant A database",
            platform=DatabasePlatform.POSTGRESQL,
            version="17",
            environment=AssetEnvironment.TEST,
            owner="database-team",
        )
        session.add(asset)
        await session.commit()

        session.add(
            Connector(
                tenant_id="tenant-beta",
                asset_id=asset.id,
                name="cross-tenant-connector",
                platform=DatabasePlatform.POSTGRESQL,
                endpoint_ref="dns://tenant-a-database.internal:5432/testdb",
                secret_ref="vault://database/tenant-a#readonly",  # noqa: S106
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()
    await database.dispose()


def make_pack() -> ControlPackVersion:
    return ControlPackVersion(
        tenant_id="tenant-alpha",
        pack_id="aegisdb.database-security.postgresql",
        version="1.0.0",
        schema_version="1.0",
        platform=DatabasePlatform.POSTGRESQL,
        title="PostgreSQL immutable baseline",
        description="A sufficiently descriptive immutable test control pack version.",
        status=ControlPackStatus.ACTIVE,
        released_at=datetime.now(UTC),
        immutable=True,
        content_sha256="a" * 64,
        created_by="admin@example.com",
    )


@pytest.mark.asyncio
async def test_governance_foreign_keys_and_immutability_are_enforced():
    database = Database(Settings(environment="test", database_url="sqlite+aiosqlite:///:memory:"))
    await database.create_all_for_test_or_dev()
    async with database.session_factory() as session:
        pack = make_pack()
        session.add(pack)
        await session.commit()
        session.add(
            ControlDefinition(
                tenant_id="tenant-beta",
                control_pack_version_id=pack.id,
                control_id="postgresql.encryption.tls-metadata",
                domain=ControlDomain.ENCRYPTION,
                title="Review PostgreSQL TLS metadata",
                objective="Collect PostgreSQL TLS session metadata for authorized review.",
                severity=FindingSeverity.HIGH,
                environments=["test"],
                version_scope="customer_validated",
                applicability_notes="Validate the exact PostgreSQL deployment.",
                assessment_mode="automated_evidence",
                probe_ids=["postgresql.tls_sessions"],
                decision_mode="analyst_review_required",
                manual_evidence_requirements=[],
                allowed_fields=["ssl"],
                limitations=["TLS session metadata alone cannot establish complete encryption."],
                remediation_guidance="Review policy and architecture before making changes.",
                definition_sha256="b" * 64,
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()

        pack.title = "Attempted mutation"
        with pytest.raises((StatementError, ValueError)):
            await session.commit()
        await session.rollback()
    await database.dispose()
