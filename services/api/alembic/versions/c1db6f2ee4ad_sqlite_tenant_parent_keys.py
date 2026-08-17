"""add SQLite tenant-scoped parent keys

Revision ID: 20260812_0004
Revises: 20260812_0003

SQLite requires a parent key referenced by a composite foreign key to be backed
by a unique constraint or unique index with the same columns. Revision 0002
creates these keys as constraints on PostgreSQL, but intentionally avoids
SQLite batch table rebuilds. Add equivalent SQLite-only unique indexes so a
database upgraded through Alembic has the same usable tenant fences as one
created directly from ORM metadata.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260812_0004"
down_revision: str | None = "20260812_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

SQLITE_TENANT_PARENT_KEYS = (
    ("assets", "uq_assets_tenant_id"),
    ("connectors", "uq_connectors_tenant_id"),
    ("assessments", "uq_assessments_tenant_id"),
    ("findings", "uq_findings_tenant_id"),
)


def upgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        return
    for table, name in SQLITE_TENANT_PARENT_KEYS:
        op.create_index(name, table, ["tenant_id", "id"], unique=True)


def downgrade() -> None:
    if op.get_bind().dialect.name != "sqlite":
        return
    for table, name in reversed(SQLITE_TENANT_PARENT_KEYS):
        op.drop_index(name, table_name=table)
