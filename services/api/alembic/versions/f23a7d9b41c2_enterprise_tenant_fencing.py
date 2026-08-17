"""enterprise tenant fencing

Revision ID: 20260812_0002
Revises: 20260812_0001
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260812_0002"
down_revision: str | None = "20260812_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "assets",
    "connectors",
    "assessments",
    "findings",
    "scan_jobs",
    "evidence",
    "masking_policies",
    "access_reviews",
    "audit_events",
    "idempotency_records",
)

OLD_FOREIGN_KEYS = (
    ("access_reviews", "fk_access_reviews_asset_id_assets"),
    ("assessments", "fk_assessments_asset_id_assets"),
    ("connectors", "fk_connectors_asset_id_assets"),
    ("findings", "fk_findings_assessment_id_assessments"),
    ("findings", "fk_findings_asset_id_assets"),
    ("scan_jobs", "fk_scan_jobs_assessment_id_assessments"),
    ("scan_jobs", "fk_scan_jobs_connector_id_connectors"),
    ("evidence", "fk_evidence_assessment_id_assessments"),
    ("evidence", "fk_evidence_finding_id_findings"),
)


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("lease_token", sa.String(length=36), nullable=True))
    op.add_column(
        "idempotency_records",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column(
        "idempotency_records", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "idempotency_records", sa.Column("resolved_by", sa.String(length=160), nullable=True)
    )
    op.add_column("idempotency_records", sa.Column("resolution_reason", sa.Text(), nullable=True))
    op.create_index(
        "ix_idempotency_recovery",
        "idempotency_records",
        ["state", "expires_at"],
        unique=False,
    )

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite remains supported for deterministic local tests. Fresh SQLite
        # databases created from ORM metadata still receive the composite FKs.
        return

    op.create_unique_constraint("uq_assets_tenant_id", "assets", ["tenant_id", "id"])
    op.create_unique_constraint("uq_connectors_tenant_id", "connectors", ["tenant_id", "id"])
    op.create_unique_constraint("uq_assessments_tenant_id", "assessments", ["tenant_id", "id"])
    op.create_unique_constraint("uq_findings_tenant_id", "findings", ["tenant_id", "id"])
    for table, constraint in OLD_FOREIGN_KEYS:
        op.drop_constraint(constraint, table, type_="foreignkey")

    op.create_foreign_key(
        "fk_access_reviews_tenant_asset",
        "access_reviews",
        "assets",
        ["tenant_id", "asset_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_assessments_tenant_asset",
        "assessments",
        "assets",
        ["tenant_id", "asset_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_connectors_tenant_asset",
        "connectors",
        "assets",
        ["tenant_id", "asset_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_findings_tenant_assessment",
        "findings",
        "assessments",
        ["tenant_id", "assessment_id"],
        ["tenant_id", "id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_findings_tenant_asset",
        "findings",
        "assets",
        ["tenant_id", "asset_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_scan_jobs_tenant_assessment",
        "scan_jobs",
        "assessments",
        ["tenant_id", "assessment_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_scan_jobs_tenant_connector",
        "scan_jobs",
        "connectors",
        ["tenant_id", "connector_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_evidence_tenant_assessment",
        "evidence",
        "assessments",
        ["tenant_id", "assessment_id"],
        ["tenant_id", "id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_evidence_tenant_finding",
        "evidence",
        "findings",
        ["tenant_id", "finding_id"],
        ["tenant_id", "id"],
        ondelete="RESTRICT",
    )

    tenant_expression = "tenant_id = nullif(current_setting('app.tenant_id', true), '')"
    for table in TENANT_TABLES:
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                f"USING ({tenant_expression}) WITH CHECK ({tenant_expression})"
            )
        )

    op.execute(
        sa.text(
            """
            CREATE FUNCTION reject_audit_event_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'audit_events are append-only' USING ERRCODE = '55000';
            END;
            $$
            """
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events "
            "FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation()"
        )
    )

    # Roles are intentionally provisioned by the platform/IAM team. If the fixed
    # runtime role exists, this migration applies least-privilege table grants.
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'assurance_runtime') THEN
                    GRANT USAGE ON SCHEMA public TO assurance_runtime;
                    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
                        TO assurance_runtime;
                    REVOKE UPDATE, DELETE ON audit_events FROM assurance_runtime;
                END IF;
            END
            $$
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events"))
        op.execute(sa.text("DROP FUNCTION IF EXISTS reject_audit_event_mutation()"))
        for table in reversed(TENANT_TABLES):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))

        for table, constraint in (
            ("access_reviews", "fk_access_reviews_tenant_asset"),
            ("assessments", "fk_assessments_tenant_asset"),
            ("connectors", "fk_connectors_tenant_asset"),
            ("findings", "fk_findings_tenant_assessment"),
            ("findings", "fk_findings_tenant_asset"),
            ("scan_jobs", "fk_scan_jobs_tenant_assessment"),
            ("scan_jobs", "fk_scan_jobs_tenant_connector"),
            ("evidence", "fk_evidence_tenant_assessment"),
            ("evidence", "fk_evidence_tenant_finding"),
        ):
            op.drop_constraint(constraint, table, type_="foreignkey")

        op.create_foreign_key(
            "fk_access_reviews_asset_id_assets",
            "access_reviews",
            "assets",
            ["asset_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_assessments_asset_id_assets",
            "assessments",
            "assets",
            ["asset_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_connectors_asset_id_assets",
            "connectors",
            "assets",
            ["asset_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_findings_assessment_id_assessments",
            "findings",
            "assessments",
            ["assessment_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.create_foreign_key(
            "fk_findings_asset_id_assets",
            "findings",
            "assets",
            ["asset_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_scan_jobs_assessment_id_assessments",
            "scan_jobs",
            "assessments",
            ["assessment_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_foreign_key(
            "fk_scan_jobs_connector_id_connectors",
            "scan_jobs",
            "connectors",
            ["connector_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_evidence_assessment_id_assessments",
            "evidence",
            "assessments",
            ["assessment_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.create_foreign_key(
            "fk_evidence_finding_id_findings",
            "evidence",
            "findings",
            ["finding_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.drop_constraint("uq_findings_tenant_id", "findings", type_="unique")
        op.drop_constraint("uq_assessments_tenant_id", "assessments", type_="unique")
        op.drop_constraint("uq_connectors_tenant_id", "connectors", type_="unique")
        op.drop_constraint("uq_assets_tenant_id", "assets", type_="unique")

    op.drop_index("ix_idempotency_recovery", table_name="idempotency_records")
    op.drop_column("idempotency_records", "resolution_reason")
    op.drop_column("idempotency_records", "resolved_by")
    op.drop_column("idempotency_records", "resolved_at")
    op.drop_column("idempotency_records", "updated_at")
    op.drop_column("scan_jobs", "lease_token")
