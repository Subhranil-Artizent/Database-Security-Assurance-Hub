"""governance and durable delivery

Revision ID: 20260812_0003
Revises: 20260812_0002
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260812_0003"
down_revision: str | None = "20260812_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TENANT_TABLES = (
    "control_pack_versions",
    "control_definitions",
    "control_results",
    "finding_exceptions",
    "integration_outbox",
    "integration_inbox",
)


def upgrade() -> None:
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.create_unique_constraint("uq_scan_jobs_tenant_id", ["tenant_id", "id"])

    op.create_table(
        "control_pack_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("pack_id", sa.String(length=120), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column(
            "platform",
            sa.Enum(
                "ORACLE",
                "POSTGRESQL",
                "SYBASE",
                name="databaseplatform",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "DEPRECATED",
                name="controlpackstatus",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("supersedes", sa.String(length=40), nullable=True),
        sa.Column("immutable", sa.Boolean(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_control_pack_versions")),
        sa.UniqueConstraint(
            "tenant_id", "pack_id", "version", name="uq_control_pack_tenant_version"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_control_pack_versions_tenant_id"),
    )
    op.create_index(
        op.f("ix_control_pack_versions_created_at"),
        "control_pack_versions",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_control_pack_versions_tenant_id"),
        "control_pack_versions",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_control_pack_tenant_status",
        "control_pack_versions",
        ["tenant_id", "status"],
        unique=False,
    )

    op.create_table(
        "control_definitions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("control_pack_version_id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=100), nullable=False),
        sa.Column(
            "domain",
            sa.Enum(
                "ENCRYPTION",
                "DATA_PROTECTION",
                "ACCESS_SECURITY",
                "DATA_MASKING",
                name="controldomain",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.String(length=140), nullable=False),
        sa.Column("objective", sa.String(length=600), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO",
                name="findingseverity",
                native_enum=False,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("environments", sa.JSON(), nullable=False),
        sa.Column("version_scope", sa.String(length=32), nullable=False),
        sa.Column("applicability_notes", sa.String(length=400), nullable=False),
        sa.Column("assessment_mode", sa.String(length=32), nullable=False),
        sa.Column("probe_ids", sa.JSON(), nullable=False),
        sa.Column("decision_mode", sa.String(length=40), nullable=False),
        sa.Column("manual_evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("allowed_fields", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("remediation_guidance", sa.String(length=600), nullable=False),
        sa.Column("definition_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "control_pack_version_id"],
            ["control_pack_versions.tenant_id", "control_pack_versions.id"],
            name="fk_control_definitions_tenant_pack",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_control_definitions")),
        sa.UniqueConstraint(
            "tenant_id",
            "control_pack_version_id",
            "control_id",
            name="uq_control_definition_pack_control",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_control_definitions_tenant_id"),
    )
    op.create_index(
        op.f("ix_control_definitions_control_pack_version_id"),
        "control_definitions",
        ["control_pack_version_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_control_definitions_created_at"),
        "control_definitions",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_control_definitions_tenant_id"),
        "control_definitions",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_control_definition_tenant_domain",
        "control_definitions",
        ["tenant_id", "domain"],
        unique=False,
    )

    op.create_table(
        "control_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("control_definition_id", sa.String(length=36), nullable=False),
        sa.Column("source_job_id", sa.String(length=36), nullable=True),
        sa.Column("control_id", sa.String(length=100), nullable=False),
        sa.Column("evaluation_key", sa.String(length=64), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "PASSED",
                "FAILED",
                "REVIEW_REQUIRED",
                "NOT_APPLICABLE",
                "UNSUPPORTED",
                "INSUFFICIENT_PRIVILEGE",
                "COLLECTION_ERROR",
                name="controlresultoutcome",
                native_enum=False,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("evaluator_version", sa.String(length=40), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("rationale", sa.String(length=1000), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("probe_outcomes", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_control_results_tenant_assessment",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "control_definition_id"],
            ["control_definitions.tenant_id", "control_definitions.id"],
            name="fk_control_results_tenant_definition",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "source_job_id"],
            ["scan_jobs.tenant_id", "scan_jobs.id"],
            name="fk_control_results_tenant_job",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_control_results")),
        sa.UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_definition_id",
            name="uq_control_result_assessment_control",
        ),
        sa.UniqueConstraint("tenant_id", "evaluation_key", name="uq_control_result_evaluation_key"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_control_results_tenant_id"),
    )
    for column in ("assessment_id", "control_definition_id", "source_job_id", "created_at"):
        op.create_index(
            op.f(f"ix_control_results_{column}"),
            "control_results",
            [column],
            unique=False,
        )
    op.create_index(
        op.f("ix_control_results_tenant_id"),
        "control_results",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_control_result_tenant_outcome",
        "control_results",
        ["tenant_id", "outcome"],
        unique=False,
    )

    op.create_table(
        "finding_exceptions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("request_key", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "REQUESTED",
                "APPROVED",
                "REJECTED",
                "EXPIRED",
                "REVOKED",
                name="findingexceptionstatus",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("justification", sa.String(length=4000), nullable=False),
        sa.Column("requested_by", sa.String(length=160), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(length=160), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(length=2000), nullable=True),
        sa.Column("revoked_by", sa.String(length=160), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name=op.f("ck_finding_exceptions_finding_exception_separation_of_duties"),
        ),
        sa.CheckConstraint(
            "expires_at > requested_at",
            name=op.f("ck_finding_exceptions_finding_exception_positive_validity"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["findings.tenant_id", "findings.id"],
            name="fk_finding_exceptions_tenant_finding",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_exceptions")),
        sa.UniqueConstraint(
            "tenant_id", "finding_id", "request_key", name="uq_finding_exception_request"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_finding_exceptions_tenant_id"),
    )
    for column in ("finding_id", "created_at", "tenant_id"):
        op.create_index(
            op.f(f"ix_finding_exceptions_{column}"),
            "finding_exceptions",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_finding_exception_expiry",
        "finding_exceptions",
        ["status", "expires_at"],
        unique=False,
    )
    op.create_index(
        "uq_finding_exception_active",
        "finding_exceptions",
        ["tenant_id", "finding_id"],
        unique=True,
        postgresql_where=sa.text("status = 'APPROVED'"),
        sqlite_where=sa.text("status = 'APPROVED'"),
    )

    op.create_table(
        "integration_outbox",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "destination",
            sa.Enum(
                "SIEM",
                "TICKETING",
                "GRC",
                name="integrationdestination",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("aggregate_type", sa.String(length=80), nullable=False),
        sa.Column("aggregate_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("event_version", sa.Integer(), nullable=False),
        sa.Column("deduplication_key", sa.String(length=160), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PENDING",
                "LEASED",
                "RUNNING",
                "DELIVERED",
                "DEAD_LETTER",
                name="deliverystatus",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("leased_by", sa.String(length=128), nullable=True),
        sa.Column("lease_token", sa.String(length=36), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=4000), nullable=True),
        sa.Column("external_reference", sa.String(length=512), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_outbox")),
        sa.UniqueConstraint(
            "tenant_id", "destination", "deduplication_key", name="uq_outbox_delivery"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_integration_outbox_tenant_id"),
    )
    for column in ("created_at", "tenant_id"):
        op.create_index(
            op.f(f"ix_integration_outbox_{column}"),
            "integration_outbox",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_outbox_lease_queue",
        "integration_outbox",
        ["status", "available_at"],
        unique=False,
    )

    op.create_table(
        "integration_inbox",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "source",
            sa.Enum(
                "SIEM",
                "TICKETING",
                "GRC",
                name="integrationdestination",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("message_id", sa.String(length=160), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "PROCESSED",
                "REJECTED",
                name="inboxstatus",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("received_by", sa.String(length=160), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_inbox")),
        sa.UniqueConstraint("tenant_id", "source", "message_id", name="uq_inbox_message"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_integration_inbox_tenant_id"),
    )
    op.create_index(
        op.f("ix_integration_inbox_tenant_id"),
        "integration_inbox",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_inbox_tenant_received",
        "integration_inbox",
        ["tenant_id", "received_at"],
        unique=False,
    )

    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
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
            CREATE FUNCTION reject_governance_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'immutable governance records cannot be changed or deleted'
                    USING ERRCODE = '55000';
            END;
            $$
            """
        )
    )
    for table in (
        "control_pack_versions",
        "control_definitions",
        "control_results",
        "integration_inbox",
    ):
        op.execute(
            sa.text(
                f'CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON "{table}" '
                "FOR EACH ROW EXECUTE FUNCTION reject_governance_mutation()"
            )
        )

    op.execute(
        sa.text(
            """
            CREATE FUNCTION protect_succeeded_scan_job_result() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
                IF OLD.status = 'SUCCEEDED' AND
                   (NEW.result IS DISTINCT FROM OLD.result OR
                    NEW.status IS DISTINCT FROM OLD.status)
                THEN
                    RAISE EXCEPTION 'succeeded scan job results are immutable'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NEW;
            END;
            $$
            """
        )
    )
    op.execute(
        sa.text(
            "CREATE TRIGGER scan_jobs_succeeded_result_immutable "
            "BEFORE UPDATE ON scan_jobs FOR EACH ROW "
            "EXECUTE FUNCTION protect_succeeded_scan_job_result()"
        )
    )

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'assurance_runtime') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON
                        control_pack_versions, control_definitions, control_results,
                        finding_exceptions, integration_outbox, integration_inbox
                        TO assurance_runtime;
                    REVOKE UPDATE, DELETE ON
                        control_pack_versions, control_definitions, control_results,
                        integration_inbox FROM assurance_runtime;
                END IF;
            END
            $$
            """
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text("DROP TRIGGER IF EXISTS scan_jobs_succeeded_result_immutable ON scan_jobs")
        )
        op.execute(sa.text("DROP FUNCTION IF EXISTS protect_succeeded_scan_job_result()"))
        for table in (
            "control_pack_versions",
            "control_definitions",
            "control_results",
            "integration_inbox",
        ):
            op.execute(sa.text(f'DROP TRIGGER IF EXISTS {table}_immutable ON "{table}"'))
        op.execute(sa.text("DROP FUNCTION IF EXISTS reject_governance_mutation()"))
        for table in reversed(TENANT_TABLES):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))

    op.drop_index("ix_inbox_tenant_received", table_name="integration_inbox")
    op.drop_index(op.f("ix_integration_inbox_tenant_id"), table_name="integration_inbox")
    op.drop_table("integration_inbox")
    op.drop_index("ix_outbox_lease_queue", table_name="integration_outbox")
    op.drop_index(op.f("ix_integration_outbox_tenant_id"), table_name="integration_outbox")
    op.drop_index(op.f("ix_integration_outbox_created_at"), table_name="integration_outbox")
    op.drop_table("integration_outbox")
    op.drop_index("uq_finding_exception_active", table_name="finding_exceptions")
    op.drop_index("ix_finding_exception_expiry", table_name="finding_exceptions")
    op.drop_index(op.f("ix_finding_exceptions_tenant_id"), table_name="finding_exceptions")
    op.drop_index(op.f("ix_finding_exceptions_created_at"), table_name="finding_exceptions")
    op.drop_index(op.f("ix_finding_exceptions_finding_id"), table_name="finding_exceptions")
    op.drop_table("finding_exceptions")
    op.drop_index("ix_control_result_tenant_outcome", table_name="control_results")
    op.drop_index(op.f("ix_control_results_tenant_id"), table_name="control_results")
    for column in ("created_at", "source_job_id", "control_definition_id", "assessment_id"):
        op.drop_index(op.f(f"ix_control_results_{column}"), table_name="control_results")
    op.drop_table("control_results")
    op.drop_index("ix_control_definition_tenant_domain", table_name="control_definitions")
    op.drop_index(op.f("ix_control_definitions_tenant_id"), table_name="control_definitions")
    op.drop_index(op.f("ix_control_definitions_created_at"), table_name="control_definitions")
    op.drop_index(
        op.f("ix_control_definitions_control_pack_version_id"),
        table_name="control_definitions",
    )
    op.drop_table("control_definitions")
    op.drop_index("ix_control_pack_tenant_status", table_name="control_pack_versions")
    op.drop_index(op.f("ix_control_pack_versions_tenant_id"), table_name="control_pack_versions")
    op.drop_index(op.f("ix_control_pack_versions_created_at"), table_name="control_pack_versions")
    op.drop_table("control_pack_versions")
    with op.batch_alter_table("scan_jobs") as batch_op:
        batch_op.drop_constraint("uq_scan_jobs_tenant_id", type_="unique")
