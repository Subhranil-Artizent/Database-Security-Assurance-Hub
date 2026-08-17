from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.bootstrap_local_mysql import (
    FINAL_GRANT_DATABASE_PATTERN,
    SOURCE_DATABASE,
    STAGING_DATABASE,
    STAGING_GRANT_DATABASE_PATTERN,
    STAGING_WRITER_PRIVILEGES,
    TARGET_DATABASE,
    TARGET_READER_PRIVILEGES,
    TARGET_READER_USERNAME,
    TARGET_WRITER_PRIVILEGES,
    bootstrap,
    grants_match_scopes,
    load_local_mysql_values,
)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.query = ""
        self.parameters: tuple[Any, ...] = ()

    def execute(self, query: str, parameters: tuple[Any, ...] = ()) -> None:
        self.query = " ".join(query.split())
        self.parameters = parameters
        self.connection.commands.append((self.query, parameters))

    def fetchone(self) -> tuple[Any, ...]:
        if self.query == "SELECT VERSION()":
            return ("8.0.36",)
        if self.query == "SELECT DATABASE()":
            return (self.connection.database,)
        if "COUNT(*)" in self.query:
            if "table_schema = DATABASE()" in self.query:
                return (8,)
            return (0,)
        raise AssertionError(f"unexpected fetchone query: {self.query}")

    def fetchall(self) -> list[tuple[Any, ...]]:
        if self.query == "SHOW GRANTS FOR CURRENT_USER()":
            if self.connection.username == TARGET_READER_USERNAME:
                target_reader = ", ".join(sorted(TARGET_READER_PRIVILEGES))
                return [
                    (
                        "GRANT USAGE ON *.* TO "
                        "`insurance_masked_test_ro`@`localhost`",
                    ),
                    (
                        f"GRANT {target_reader} ON `{FINAL_GRANT_DATABASE_PATTERN}`.* TO "
                        "`insurance_masked_test_ro`@`localhost`",
                    ),
                ]
            final = ", ".join(sorted(TARGET_WRITER_PRIVILEGES))
            staging = ", ".join(sorted(STAGING_WRITER_PRIVILEGES))
            return [
                (
                    "GRANT USAGE ON *.* TO "
                    "`assurance_hub_mask_writer`@`localhost`",
                ),
                (
                    f"GRANT {final} ON `{FINAL_GRANT_DATABASE_PATTERN}`.* TO "
                    "`assurance_hub_mask_writer`@`localhost`",
                ),
                (
                    f"GRANT {staging} ON `{STAGING_GRANT_DATABASE_PATTERN}`.* TO "
                    "`assurance_hub_mask_writer`@`localhost`",
                ),
            ]
        if "schema_privileges" not in self.query:
            raise AssertionError(f"unexpected fetchall query: {self.query}")
        if self.connection.database == SOURCE_DATABASE:
            return [("SELECT",), ("SHOW VIEW",)]
        requested_database = str(self.parameters[0]) if self.parameters else ""
        if self.connection.username == TARGET_READER_USERNAME:
            if requested_database == TARGET_DATABASE:
                return [
                    (privilege,) for privilege in sorted(TARGET_READER_PRIVILEGES)
                ]
            if requested_database in {SOURCE_DATABASE, STAGING_DATABASE}:
                return []
            raise AssertionError(
                f"unexpected target reader privilege database: {requested_database}"
            )
        if requested_database == TARGET_DATABASE:
            return [(privilege,) for privilege in sorted(TARGET_WRITER_PRIVILEGES)]
        if requested_database == STAGING_DATABASE:
            return [(privilege,) for privilege in sorted(STAGING_WRITER_PRIVILEGES)]
        if requested_database == SOURCE_DATABASE:
            return []
        raise AssertionError(f"unexpected privilege database: {requested_database}")

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(self, database: str, username: str) -> None:
        self.database = database
        self.username = username
        self.commands: list[tuple[str, tuple[Any, ...]]] = []
        self.closed = False
        self.rolled_back = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def start_transaction(self, *, readonly: bool) -> None:
        assert readonly is True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def write_settings(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "MYSQL_TARGET_HOST=127.0.0.1",
                "MYSQL_TARGET_PORT=3306",
                f"MYSQL_TARGET_DATABASE={SOURCE_DATABASE}",
                "MYSQL_TARGET_USERNAME=local_admin",
                "MYSQL_TARGET_PASSWORD=fake-only",
                "MYSQL_TARGET_CHARSET=utf8mb4",
            ]
        ),
        encoding="utf-8",
    )


def test_environment_loader_keeps_only_approved_local_mysql_keys(tmp_path: Path) -> None:
    settings = tmp_path / "local-mysql.env"
    write_settings(settings)
    with settings.open("a", encoding="utf-8") as handle:
        handle.write("\nUNRELATED_REMOTE_PASSWORD=must-not-be-retained\n")

    values = load_local_mysql_values(settings)

    assert set(values) == {
        "MYSQL_TARGET_HOST",
        "MYSQL_TARGET_PORT",
        "MYSQL_TARGET_DATABASE",
        "MYSQL_TARGET_USERNAME",
        "MYSQL_TARGET_PASSWORD",
        "MYSQL_TARGET_CHARSET",
    }
    assert "must-not-be-retained" not in repr(values)


def test_bootstrap_projects_distinct_accounts_and_reuses_masking_key(
    tmp_path: Path, monkeypatch
) -> None:
    settings = tmp_path / "local-mysql.env"
    credentials = tmp_path / "projected"
    write_settings(settings)
    connections: list[FakeConnection] = []

    def fake_connect(**options: Any) -> FakeConnection:
        connection = FakeConnection(str(options["database"]), str(options["user"]))
        connections.append(connection)
        return connection

    monkeypatch.setattr("tools.bootstrap_local_mysql.mysql.connector.connect", fake_connect)
    first = bootstrap(settings, credentials)
    first_key = Path(str(first["masking_key_file"])).read_bytes()
    second = bootstrap(settings, credentials)
    second_key = Path(str(second["masking_key_file"])).read_bytes()

    assert first["database"] == SOURCE_DATABASE
    assert first["target_database"] == TARGET_DATABASE
    assert first["staging_database"] == STAGING_DATABASE
    assert first["privileges"] == ["SELECT", "SHOW VIEW"]
    assert first["target_writer_privileges"] == sorted(TARGET_WRITER_PRIVILEGES)
    assert first["staging_writer_privileges"] == sorted(STAGING_WRITER_PRIVILEGES)
    assert first["target_reader_account"] == TARGET_READER_USERNAME
    assert first["target_reader_privileges"] == sorted(TARGET_READER_PRIVILEGES)
    assert not {"ALTER", "DELETE", "DROP", "UPDATE"} & TARGET_WRITER_PRIVILEGES
    assert "DROP" in STAGING_WRITER_PRIVILEGES
    assert first["target_table_count"] == 0
    assert first["secret_ref"] != first["target_writer_secret_ref"]
    assert first["target_reader_secret_ref"] not in {
        first["secret_ref"],
        first["target_writer_secret_ref"],
    }
    assert first["secret_file"] != first["target_secret_file"]
    assert first["target_reader_secret_file"] not in {
        first["secret_file"],
        first["target_secret_file"],
    }
    assert first_key == second_key
    assert first["masking_key_fingerprint"] == second["masking_key_fingerprint"]

    admin_commands = [command for connection in connections for command, _ in connection.commands]
    source_grants = [
        command
        for command in admin_commands
        if "GRANT SELECT, SHOW VIEW" in command and "assurance_hub_ro" in command
    ]
    target_grants = [
        command
        for command in admin_commands
        if command.startswith("GRANT ") and "assurance_hub_mask_writer" in command
    ]
    target_reader_grants = [
        command
        for command in admin_commands
        if command.startswith("GRANT ") and TARGET_READER_USERNAME in command
    ]
    assert source_grants and all(f"`{SOURCE_DATABASE}`.*" in command for command in source_grants)
    assert target_grants
    final_grants = [
        command
        for command in target_grants
        if f"`{FINAL_GRANT_DATABASE_PATTERN}`.*" in command
    ]
    staging_grants = [
        command
        for command in target_grants
        if f"`{STAGING_GRANT_DATABASE_PATTERN}`.*" in command
    ]
    assert final_grants and staging_grants
    assert all("DROP" not in command for command in final_grants)
    assert all("DROP" in command for command in staging_grants)
    assert all(f"`{SOURCE_DATABASE}`.*" not in command for command in target_grants)
    assert target_reader_grants
    assert all(
        f"`{FINAL_GRANT_DATABASE_PATTERN}`.*" in command
        for command in target_reader_grants
    )
    assert all("SELECT, SHOW VIEW" in command for command in target_reader_grants)
    assert all(f"`{SOURCE_DATABASE}`.*" not in command for command in target_reader_grants)
    assert all(f"`{STAGING_DATABASE}`.*" not in command for command in target_reader_grants)
    assert any("information_schema.routines" in command for command in admin_commands)
    assert any("information_schema.events" in command for command in admin_commands)
    assert all(connection.closed for connection in connections)


def test_exact_writer_grants_reject_extra_global_or_schema_privileges() -> None:
    final = ", ".join(sorted(TARGET_WRITER_PRIVILEGES))
    staging = ", ".join(sorted(STAGING_WRITER_PRIVILEGES))
    rows = [
        ("GRANT USAGE ON *.* TO `writer`@`localhost`",),
        (f"GRANT {final} ON `{FINAL_GRANT_DATABASE_PATTERN}`.* TO `writer`@`localhost`",),
        (f"GRANT {staging} ON `{STAGING_GRANT_DATABASE_PATTERN}`.* TO `writer`@`localhost`",),
    ]
    expected = {
        FINAL_GRANT_DATABASE_PATTERN: TARGET_WRITER_PRIVILEGES,
        STAGING_GRANT_DATABASE_PATTERN: STAGING_WRITER_PRIVILEGES,
    }
    assert grants_match_scopes(rows, expected)
    assert not grants_match_scopes(
        rows + [("GRANT PROCESS ON *.* TO `writer`@`localhost`",)], expected
    )
    assert not grants_match_scopes(
        rows + [("GRANT DELETE ON `other`.* TO `writer`@`localhost`",)], expected
    )


def test_masked_test_reader_is_confined_to_the_final_target() -> None:
    privileges = ", ".join(sorted(TARGET_READER_PRIVILEGES))
    rows = [
        (f"GRANT USAGE ON *.* TO `{TARGET_READER_USERNAME}`@`localhost`",),
        (
            f"GRANT {privileges} ON `{TARGET_DATABASE}`.* TO "
            f"`{TARGET_READER_USERNAME}`@`localhost`",
        ),
    ]
    expected = {TARGET_DATABASE: TARGET_READER_PRIVILEGES}

    assert grants_match_scopes(rows, expected)
    assert not grants_match_scopes(
        rows
        + [
            (
                f"GRANT SELECT ON `{SOURCE_DATABASE}`.* TO "
                f"`{TARGET_READER_USERNAME}`@`localhost`",
            )
        ],
        expected,
    )
    assert not grants_match_scopes(
        rows
        + [
            (
                f"GRANT SELECT ON `{STAGING_DATABASE}`.* TO "
                f"`{TARGET_READER_USERNAME}`@`localhost`",
            )
        ],
        expected,
    )
