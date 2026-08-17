from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic.config import Config

from alembic import command
from assurance_hub.config import get_settings

API_ROOT = Path(__file__).resolve().parents[1]
SQLITE_TENANT_PARENT_KEYS = {
    "assets": ("tenant_id", "id"),
    "connectors": ("tenant_id", "id"),
    "assessments": ("tenant_id", "id"),
    "findings": ("tenant_id", "id"),
}


def test_alembic_sqlite_upgrade_has_usable_tenant_parent_keys(tmp_path: Path, monkeypatch) -> None:
    database_path = tmp_path / "migration-smoke.db"
    database_url = f"sqlite+aiosqlite:///{database_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("DATABASE_MAINTENANCE_URL", "")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    get_settings.cache_clear()

    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(API_ROOT / "alembic"))
    try:
        command.upgrade(config, "head")
    finally:
        get_settings.cache_clear()

    with sqlite3.connect(database_path) as connection:
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert revision == ("20260815_0005",)

        decision_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(control_review_decisions)"
            ).fetchall()
        }
        assert {
            "assessment_id",
            "control_definition_id",
            "outcome",
            "rationale",
            "decided_by",
            "decided_at",
            "tenant_id",
        }.issubset(decision_columns)

        for table, expected_columns in SQLITE_TENANT_PARENT_KEYS.items():
            indexes = connection.execute(
                'SELECT name FROM pragma_index_list(?) WHERE "unique" = 1', (table,)
            ).fetchall()
            indexed_columns = {
                tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM pragma_index_info(?) ORDER BY seqno", (index_name,)
                    )
                )
                for (index_name,) in indexes
            }
            assert expected_columns in indexed_columns

        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
