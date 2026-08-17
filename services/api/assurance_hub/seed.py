from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from .db import Database
from .models import (
    Assessment,
    AssessmentStatus,
    Asset,
    AssetEnvironment,
    Connector,
    ControlDomain,
    DatabasePlatform,
    Finding,
    FindingSeverity,
)

DEMO_TENANT = "demo-enterprise"


async def seed_demo(database: Database) -> None:
    """Idempotently seed a non-production tenant for product demonstrations."""
    async with database.session_factory() as session:
        if await session.scalar(
            select(Asset.id).where(
                Asset.tenant_id == DEMO_TENANT, Asset.external_id == "demo-oracle-finance"
            )
        ):
            return
        asset = Asset(
            tenant_id=DEMO_TENANT,
            external_id="demo-oracle-finance",
            name="Finance Oracle Demo",
            platform=DatabasePlatform.ORACLE,
            version="23ai",
            edition="Enterprise",
            environment=AssetEnvironment.TEST,
            owner="Database Engineering",
            criticality="high",
            tags={"data_domain": "finance", "synthetic": "true"},
        )
        session.add(asset)
        await session.flush()
        session.add(
            Connector(
                tenant_id=DEMO_TENANT,
                asset_id=asset.id,
                name="finance-oracle-demo",
                platform=DatabasePlatform.ORACLE,
                endpoint_ref="dns://oracle-demo.internal:1521/finance",
                secret_ref="vault://demo/database/oracle#read-only",  # noqa: S106
                collector_id="demo-collector",
                capabilities=["inventory", "control_assessment"],
                config={"network_zone": "demo"},
            )
        )
        assessment = Assessment(
            tenant_id=DEMO_TENANT,
            asset_id=asset.id,
            control_pack="enterprise-database-baseline",
            control_pack_version="1.0.0",
            status=AssessmentStatus.COMPLETED,
            score=82.5,
            initiated_by="seed",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            summary={"passed": 33, "failed": 7},
        )
        session.add(assessment)
        await session.flush()
        session.add(
            Finding(
                tenant_id=DEMO_TENANT,
                assessment_id=assessment.id,
                asset_id=asset.id,
                control_id="ORACLE-TDE-001",
                fingerprint="demo-tde-unencrypted-tablespace",
                domain=ControlDomain.ENCRYPTION,
                title="Tablespace encryption coverage is incomplete",
                description="A synthetic non-production tablespace is reported as unencrypted.",
                severity=FindingSeverity.HIGH,
                remediation="Evaluate TDE rollout and key lifecycle controls in the test estate.",
                risk_context={"synthetic": True},
            )
        )
        await session.commit()
