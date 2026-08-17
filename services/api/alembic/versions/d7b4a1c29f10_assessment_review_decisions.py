"""add assessment review decisions

Revision ID: 20260815_0005
Revises: 20260812_0004
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260815_0005"
down_revision: str | None = "20260812_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "control_review_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("control_definition_id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=100), nullable=False),
        sa.Column(
            "outcome",
            sa.Enum(
                "PASSED",
                "FAILED",
                "NOT_APPLICABLE",
                name="controldecisionoutcome",
                native_enum=False,
                length=24,
            ),
            nullable=False,
        ),
        sa.Column("rationale", sa.String(length=2000), nullable=False),
        sa.Column("decided_by", sa.String(length=160), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["assessments.tenant_id", "assessments.id"],
            name="fk_control_review_decisions_tenant_assessment",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "control_definition_id"],
            ["control_definitions.tenant_id", "control_definitions.id"],
            name="fk_control_review_decisions_tenant_definition",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_control_review_decisions")),
        sa.UniqueConstraint(
            "tenant_id",
            "assessment_id",
            "control_definition_id",
            name="uq_control_review_decision_assessment_control",
        ),
        sa.UniqueConstraint(
            "tenant_id", "id", name="uq_control_review_decisions_tenant_id"
        ),
    )
    for column in ("assessment_id", "control_definition_id", "created_at", "tenant_id"):
        op.create_index(
            op.f(f"ix_control_review_decisions_{column}"),
            "control_review_decisions",
            [column],
            unique=False,
        )
    op.create_index(
        "ix_control_review_decisions_tenant_assessment",
        "control_review_decisions",
        ["tenant_id", "assessment_id"],
        unique=False,
    )

    # Older local launchers could queue more than one baseline before the first
    # review was completed. Preserve every record, but keep only the newest
    # successful collection reviewable.
    op.execute(
        sa.text(
            """
            UPDATE assessments
               SET status = 'SUPERSEDED',
                   completed_at = COALESCE(completed_at, updated_at)
             WHERE id IN (
                SELECT id FROM (
                    SELECT a.id,
                           ROW_NUMBER() OVER (
                               PARTITION BY a.tenant_id, a.asset_id,
                                            a.control_pack, a.control_pack_version
                               ORDER BY a.created_at DESC, a.id DESC
                           ) AS position
                      FROM assessments AS a
                     WHERE a.status = 'RUNNING'
                       AND EXISTS (
                           SELECT 1
                             FROM scan_jobs AS j
                            WHERE j.tenant_id = a.tenant_id
                              AND j.assessment_id = a.id
                              AND j.status = 'SUCCEEDED'
                       )
                ) AS ranked
               WHERE position > 1
             )
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE assessments
               SET status = 'REVIEW_REQUIRED'
             WHERE status = 'RUNNING'
               AND EXISTS (
                   SELECT 1
                     FROM scan_jobs AS j
                    WHERE j.tenant_id = assessments.tenant_id
                      AND j.assessment_id = assessments.id
                      AND j.status = 'SUCCEEDED'
               )
            """
        )
    )
    op.create_index(
        "uq_assessments_active_run",
        "assessments",
        ["tenant_id", "asset_id", "control_pack", "control_pack_version"],
        unique=True,
        postgresql_where=sa.text("status IN ('QUEUED', 'RUNNING', 'REVIEW_REQUIRED')"),
        sqlite_where=sa.text("status IN ('QUEUED', 'RUNNING', 'REVIEW_REQUIRED')"),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('ALTER TABLE "control_review_decisions" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "control_review_decisions" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                'CREATE POLICY tenant_isolation ON "control_review_decisions" '
                "USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')) "
                "WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''))"
            )
        )
        op.execute(
            sa.text(
                """
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_roles WHERE rolname = 'assurance_runtime'
                    ) THEN
                        GRANT SELECT, INSERT, UPDATE ON control_review_decisions
                            TO assurance_runtime;
                        REVOKE DELETE ON control_review_decisions FROM assurance_runtime;
                    END IF;
                END
                $$
                """
            )
        )


def downgrade() -> None:
    op.drop_index("uq_assessments_active_run", table_name="assessments")
    op.execute(
        sa.text(
            "UPDATE assessments SET status = 'RUNNING', completed_at = NULL "
            "WHERE status IN ('REVIEW_REQUIRED', 'SUPERSEDED')"
        )
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "control_review_decisions"'))
    op.drop_index(
        "ix_control_review_decisions_tenant_assessment",
        table_name="control_review_decisions",
    )
    for column in reversed(("assessment_id", "control_definition_id", "created_at", "tenant_id")):
        op.drop_index(
            op.f(f"ix_control_review_decisions_{column}"),
            table_name="control_review_decisions",
        )
    op.drop_table("control_review_decisions")
