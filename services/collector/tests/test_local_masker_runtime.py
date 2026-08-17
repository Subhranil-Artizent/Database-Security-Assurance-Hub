from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

import assurance_collector.local_masker as local_masker_module
from assurance_collector.local_masker import (
    FINAL_GRANT_DATABASE_PATTERN,
    MASKER_COLLECTOR_ID,
    SENSITIVE_MARKERS,
    SOURCE_READER_PRIVILEGES,
    SOURCE_USERNAME,
    STAGING_GRANT_DATABASE_PATTERN,
    STAGING_WRITER_PRIVILEGES,
    TARGET_USERNAME,
    TARGET_WRITER_PRIVILEGES,
    LeasedMaskingJob,
    LocalCredential,
    LocalMaskingApiClient,
    LocalMaskingWorker,
    MaskerSettings,
    MaskingCopyResult,
    MySqlSourceReader,
    MySqlTargetWriter,
    _grants_match,
    _grants_match_scopes,
    _is_sensitive_name,
    _validate_create_statement,
    load_local_credential,
    load_masking_key,
)
from assurance_collector.masking_engine import (
    MASKING_ALGORITHM,
    ROW_CAP,
    SOURCE_DATABASE,
    STAGING_DATABASE,
    STAGING_DATABASE_PREFIX,
    TARGET_DATABASE,
    TARGET_DATABASE_PREFIX,
    ColumnSpec,
    DatabaseSnapshot,
    MaskingBoundaryError,
    TableSnapshot,
    mask_snapshot,
    staging_database_for_target,
)


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.statement = ""
        self.parameters: tuple[object, ...] = ()

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> None:
        self.statement = " ".join(statement.split())
        self.parameters = parameters
        self.connection.commands.append((self.statement, parameters))
        self.connection.mutate(self.statement)

    def executemany(self, statement: str, rows: tuple[tuple[object, ...], ...]) -> None:
        self.statement = " ".join(statement.split())
        self.connection.commands.append((self.statement, rows))

    def fetchall(self) -> list[tuple[object, ...]]:
        return self.connection.respond(self.statement, self.parameters)

    def fetchone(self) -> tuple[object, ...] | None:
        rows = self.connection.respond(self.statement, self.parameters)
        return rows[0] if rows else None

    def close(self) -> None:
        return None


class FakeConnection:
    def __init__(
        self, database: str, username: str, *, version: str = "8.0.36"
    ) -> None:
        self.database = database
        self.username = username
        self.version = version
        self.commands: list[tuple[str, object]] = []
        self.transaction_options: dict[str, object] | None = None
        self.rolled_back = False
        self.committed = False
        self.closed = False
        self.schema_tables: dict[str, set[str]] = {
            TARGET_DATABASE: set(),
            STAGING_DATABASE: set(),
        }

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def start_transaction(self, **options: object) -> None:
        self.transaction_options = options

    def rollback(self) -> None:
        self.rolled_back = True

    def commit(self) -> None:
        self.committed = True

    def close(self) -> None:
        self.closed = True

    def mutate(self, statement: str) -> None:
        create = re.match(r"CREATE TABLE `([^`]+)`\.`([^`]+)`", statement)
        if create:
            self.schema_tables.setdefault(create.group(1), set()).add(create.group(2))
            return
        if statement.startswith("DROP TABLE "):
            for database, table in re.findall(r"`([^`]+)`\.`([^`]+)`", statement):
                self.schema_tables.setdefault(database, set()).discard(table)
            return
        if statement.startswith("RENAME TABLE "):
            for source_db, table, target_db, target_table in re.findall(
                r"`([^`]+)`\.`([^`]+)` TO `([^`]+)`\.`([^`]+)`", statement
            ):
                self.schema_tables.setdefault(source_db, set()).discard(table)
                self.schema_tables.setdefault(target_db, set()).add(target_table)

    def respond(self, statement: str, _parameters: tuple[object, ...]) -> list[tuple[object, ...]]:
        if statement == "SELECT DATABASE()":
            return [(self.database,)]
        if statement == "SELECT CURRENT_USER()":
            return [(f"{self.username}@localhost",)]
        if statement == "SELECT VERSION()":
            return [(self.version,)]
        if statement == "SHOW GRANTS FOR CURRENT_USER()":
            grants = [(f"GRANT USAGE ON *.* TO `{self.username}`@`localhost`",)]
            if self.username == SOURCE_USERNAME:
                grants.append(
                    (
                        f"GRANT SELECT, SHOW VIEW ON `{SOURCE_DATABASE}`.* "
                        f"TO `{self.username}`@`localhost`",
                    )
                )
            else:
                final = ", ".join(sorted(TARGET_WRITER_PRIVILEGES))
                staging = ", ".join(sorted(STAGING_WRITER_PRIVILEGES))
                grants.extend(
                    [
                        (
                            f"GRANT {final} ON `{FINAL_GRANT_DATABASE_PATTERN}`.* "
                            f"TO `{self.username}`@`localhost`",
                        ),
                        (
                            f"GRANT {staging} ON `{STAGING_GRANT_DATABASE_PATTERN}`.* "
                            f"TO `{self.username}`@`localhost`",
                        ),
                    ]
                )
            return grants
        if statement.startswith("SELECT GET_LOCK(") or statement.startswith(
            "SELECT RELEASE_LOCK("
        ):
            return [(1,)]
        if "FROM information_schema.tables" in statement:
            if statement.startswith("SELECT COUNT(*)") and self.username == SOURCE_USERNAME:
                return [(0,)]
            database = str(_parameters[0])
            if self.username == SOURCE_USERNAME and database == SOURCE_DATABASE:
                return [("customers", "BASE TABLE")]
            return [
                (name, "BASE TABLE")
                for name in sorted(self.schema_tables.get(database, set()))
            ]
        if "FROM information_schema.triggers" in statement:
            return [(0,)] if statement.startswith("SELECT COUNT(*)") else []
        if "FROM information_schema.routines" in statement:
            return []
        if "FROM information_schema.events" in statement:
            return []
        if "FROM information_schema.columns" in statement:
            return [
                ("customers", "customer_id", "int", "int", "NO", None, 10, 0, "", ""),
                (
                    "customers",
                    "email",
                    "varchar",
                    "varchar(80)",
                    "YES",
                    80,
                    None,
                    None,
                    "",
                    "",
                ),
            ]
        if "constraint_name = 'PRIMARY'" in statement:
            return [("customers", "customer_id")]
        if "referenced_table_name IS NOT NULL" in statement:
            return []
        if statement == f"SELECT COUNT(*) FROM `{SOURCE_DATABASE}`.`customers`":  # noqa: S608
            return [(1,)]
        if statement.startswith("SELECT `customer_id`, `email` FROM"):
            return [(7, "person@example.test")]
        if statement.startswith("SHOW CREATE TABLE"):
            return [
                (
                    "customers",
                    "CREATE TABLE `customers` ("
                    "`customer_id` int NOT NULL,"
                    "`email` varchar(80) DEFAULT NULL,"
                    "PRIMARY KEY (`customer_id`)"
                    ") ENGINE=InnoDB",
                )
            ]
        raise AssertionError(f"unexpected fake query: {statement}")


def projected_environment(root: Path) -> dict[str, str]:
    files = [root / name for name in ("source.json", "target.json", "key.json")]
    for file in files:
        file.write_text("{}", encoding="utf-8")
    return {
        "LOCAL_MASKER_API_URL": "http://127.0.0.1:8000",
        "LOCAL_MASKER_COLLECTOR_ID": MASKER_COLLECTOR_ID,
        "LOCAL_MASKER_TENANT_ID": "local-development",
        "LOCAL_MASKER_HOST": "127.0.0.1",
        "LOCAL_MASKER_PORT": "3306",
        "LOCAL_MASKER_SOURCE_DATABASE": SOURCE_DATABASE,
        "LOCAL_MASKER_TARGET_PREFIX": TARGET_DATABASE_PREFIX,
        "LOCAL_MASKER_STAGING_PREFIX": STAGING_DATABASE_PREFIX,
        "LOCAL_MASKER_CREDENTIAL_ROOT": str(root),
        "LOCAL_MASKER_SOURCE_SECRET_FILE": str(files[0]),
        "LOCAL_MASKER_TARGET_SECRET_FILE": str(files[1]),
        "LOCAL_MASKER_KEY_FILE": str(files[2]),
        "UNRELATED_REMOTE_PASSWORD": "must-not-be-consumed",
    }


def aggregate_result() -> MaskingCopyResult:
    return MaskingCopyResult(
        source_database=SOURCE_DATABASE,
        target_database=TARGET_DATABASE,
        tables_copied=1,
        rows_copied=1,
        columns_masked=2,
        values_masked=2,
        row_cap=ROW_CAP,
        source_before_hmac="a" * 64,
        source_after_hmac="a" * 64,
        target_manifest_hmac="b" * 64,
        manifest_sha256="c" * 64,
        key_fingerprint="d" * 16,
        source_digest_match=True,
        target_counts_match=True,
        foreign_keys_valid=True,
        raw_values_exported=False,
        algorithm=MASKING_ALGORITHM,
    )


def test_settings_accept_only_fixed_loopback_and_projected_files(tmp_path: Path) -> None:
    settings = MaskerSettings.from_environment(projected_environment(tmp_path))
    assert settings.host == "127.0.0.1"
    assert settings.source_database == SOURCE_DATABASE
    assert settings.target_prefix == TARGET_DATABASE_PREFIX
    assert settings.staging_prefix == STAGING_DATABASE_PREFIX

    remote = {**projected_environment(tmp_path), "LOCAL_MASKER_HOST": "db.example"}
    with pytest.raises(MaskingBoundaryError, match="literal loopback"):
        MaskerSettings.from_environment(remote)

    unexpected = {**projected_environment(tmp_path), "LOCAL_MASKER_EXTRA": "unsafe"}
    with pytest.raises(MaskingBoundaryError, match="unapproved setting"):
        MaskerSettings.from_environment(unexpected)

    outside = tmp_path.parent / "outside-masker-key.json"
    outside.write_text("{}", encoding="utf-8")
    escaped = {**projected_environment(tmp_path), "LOCAL_MASKER_KEY_FILE": str(outside)}
    with pytest.raises(MaskingBoundaryError, match="escaped"):
        MaskerSettings.from_environment(escaped)


def test_projection_loaders_are_strict_and_do_not_expose_values(tmp_path: Path) -> None:
    credential_path = tmp_path / "credential.json"
    credential_path.write_text(
        json.dumps({"username": SOURCE_USERNAME, "password": "fake-only", "ca_file": None}),
        encoding="utf-8",
    )
    credential = load_local_credential(credential_path, expected_username=SOURCE_USERNAME)
    assert credential.username == SOURCE_USERNAME
    assert credential.password == "fake-only"  # noqa: S105

    key = bytes(range(32))
    key_path = tmp_path / "key.json"
    key_path.write_text(
        json.dumps({"version": 1, "key_b64": base64.urlsafe_b64encode(key).decode("ascii")}),
        encoding="utf-8",
    )
    assert load_masking_key(key_path) == key


def test_exact_grants_reject_any_extra_or_wrong_schema() -> None:
    source_grants = [
        (f"GRANT USAGE ON *.* TO `{SOURCE_USERNAME}`@`localhost`",),
        (f"GRANT SELECT, SHOW VIEW ON `{SOURCE_DATABASE}`.* TO `{SOURCE_USERNAME}`@`localhost`",),
    ]
    assert _grants_match(source_grants, SOURCE_DATABASE, SOURCE_READER_PRIVILEGES)
    assert not _grants_match(
        source_grants + [("GRANT INSERT ON `other`.* TO `reader`@`localhost`",)],
        SOURCE_DATABASE,
        SOURCE_READER_PRIVILEGES,
    )
    assert not _grants_match(source_grants, TARGET_DATABASE, TARGET_WRITER_PRIVILEGES)
    writer_grants = [
        (f"GRANT USAGE ON *.* TO `{TARGET_USERNAME}`@`localhost`",),
        (
            f"GRANT {', '.join(sorted(TARGET_WRITER_PRIVILEGES))} "
            f"ON `{FINAL_GRANT_DATABASE_PATTERN}`.* TO `{TARGET_USERNAME}`@`localhost`",
        ),
        (
            f"GRANT {', '.join(sorted(STAGING_WRITER_PRIVILEGES))} "
            f"ON `{STAGING_GRANT_DATABASE_PATTERN}`.* TO `{TARGET_USERNAME}`@`localhost`",
        ),
    ]
    scopes = {
        FINAL_GRANT_DATABASE_PATTERN: TARGET_WRITER_PRIVILEGES,
        STAGING_GRANT_DATABASE_PATTERN: STAGING_WRITER_PRIVILEGES,
    }
    assert _grants_match_scopes(writer_grants, scopes)
    assert not _grants_match_scopes(
        writer_grants + [("GRANT DELETE ON `other`.* TO `writer`@`localhost`",)],
        scopes,
    )


@pytest.mark.parametrize("version", ["8.0.12", "10.11.6-MariaDB"])
def test_target_writer_rejects_unsupported_mysql_implementations(version: str) -> None:
    connection = FakeConnection(TARGET_DATABASE, TARGET_USERNAME, version=version)
    writer = MySqlTargetWriter(
        host="127.0.0.1",
        port=3306,
        credential=LocalCredential(TARGET_USERNAME, "fake-only"),
        connect=lambda **_options: connection,
    )

    assert not writer.verify_target_only(
        SOURCE_DATABASE, TARGET_DATABASE, STAGING_DATABASE
    )


def test_target_writer_accepts_a_separate_server_derived_workflow_target() -> None:
    target_database = f"{TARGET_DATABASE_PREFIX}0123456789ab"
    staging_database = staging_database_for_target(target_database)
    connection = FakeConnection(target_database, TARGET_USERNAME)
    writer = MySqlTargetWriter(
        host="127.0.0.1",
        port=3306,
        credential=LocalCredential(TARGET_USERNAME, "fake-only"),
        target_database=target_database,
        connect=lambda **_options: connection,
    )

    assert writer.verify_target_only(
        SOURCE_DATABASE, target_database, staging_database
    )
    statements = [statement for statement, _parameters in connection.commands]
    assert any(target_database in statement for statement in statements)
    assert any(staging_database in statement for statement in statements)


def test_real_source_adapter_uses_read_only_consistent_snapshot_with_fake_driver() -> None:
    connections: list[FakeConnection] = []

    def connect(**options: object) -> FakeConnection:
        connection = FakeConnection(str(options["database"]), str(options["user"]))
        connections.append(connection)
        return connection

    reader = MySqlSourceReader(
        host="127.0.0.1",
        port=3306,
        credential=LocalCredential(SOURCE_USERNAME, "fake-only"),
        connect=connect,
    )
    assert reader.verify_read_only(SOURCE_DATABASE)
    snapshot = reader.read_snapshot(SOURCE_DATABASE, ROW_CAP)

    assert snapshot.database == SOURCE_DATABASE
    assert snapshot.tables[0].rows == ((7, "person@example.test"),)
    assert snapshot.tables[0].columns[0].sensitive is False
    assert snapshot.tables[0].columns[1].sensitive is False
    assert snapshot.tables[0].create_statement is not None
    assert all(
        connection.transaction_options
        == {
            "consistent_snapshot": True,
            "isolation_level": "REPEATABLE READ",
            "readonly": True,
        }
        for connection in connections
    )
    statements = [statement for connection in connections for statement, _ in connection.commands]
    assert all(statement.startswith(("SELECT ", "SHOW ")) for statement in statements)
    assert all(connection.rolled_back and connection.closed for connection in connections)


def test_real_target_adapter_writes_only_new_target_with_fake_driver() -> None:
    connection = FakeConnection(TARGET_DATABASE, TARGET_USERNAME)
    opened_databases: list[object] = []

    def connect(**options: object) -> FakeConnection:
        opened_databases.append(options.get("database"))
        connection.database = str(options.get("database") or "")
        return connection

    writer = MySqlTargetWriter(
        host="127.0.0.1",
        port=3306,
        credential=LocalCredential(TARGET_USERNAME, "fake-only"),
        connect=connect,
    )
    snapshot = DatabaseSnapshot(
        database=TARGET_DATABASE,
        tables=(
            TableSnapshot(
                name="customers",
                columns=(
                        ColumnSpec(
                            "customer_id",
                            "int",
                            nullable=False,
                            sensitive=True,
                            precision=10,
                            scale=0,
                        ),
                    ColumnSpec("email", "varchar(80)", sensitive=True, max_length=80),
                ),
                rows=((99, "masked@example.test"),),
                primary_key=("customer_id",),
                create_statement=(
                    "CREATE TABLE `customers` ("
                    "`customer_id` int NOT NULL,"
                    "`email` varchar(80) DEFAULT NULL,"
                    "PRIMARY KEY (`customer_id`)"
                    ") ENGINE=InnoDB"
                ),
            ),
        ),
    )

    assert writer.read_existing_final(snapshot, ROW_CAP) is None
    assert opened_databases == [TARGET_DATABASE]
    writer.stage(snapshot)
    writer.publish()
    statements = [statement for statement, _ in connection.commands]
    assert any(
        statement.startswith(f"CREATE TABLE `{STAGING_DATABASE}`.`customers`")
        for statement in statements
    )
    assert any(
        statement.startswith(f"INSERT INTO `{STAGING_DATABASE}`.`customers`")
        for statement in statements
    )
    renames = [statement for statement in statements if statement.startswith("RENAME TABLE")]
    assert renames == [
        f"RENAME TABLE `{STAGING_DATABASE}`.`customers` "
        f"TO `{TARGET_DATABASE}`.`customers`"
    ]
    destructive = [
        statement
        for statement in statements
        if statement.startswith(("DROP TABLE", "TRUNCATE", "DELETE", "UPDATE"))
    ]
    assert all(f"`{STAGING_DATABASE}`." in statement for statement in destructive)
    assert not any(
        statement.startswith(("DROP", "TRUNCATE", "DELETE", "UPDATE"))
        and f"`{TARGET_DATABASE}`." in statement
        for statement in statements
    )
    assert not any(f"`{SOURCE_DATABASE}`." in statement for statement in statements)
    writer.rollback()
    assert connection.rolled_back and connection.closed


@pytest.mark.parametrize(
    "unsafe_suffix",
    [
        "ENGINE=MyISAM",
        "ENGINE=FEDERATED",
        "ENGINE=InnoDB CONNECTION='remote'",
        "ENGINE=InnoDB DATA DIRECTORY='/tmp'",
        "ENGINE=InnoDB INDEX DIRECTORY='/tmp'",
        "ENGINE=InnoDB TABLESPACE external_space",
        "ENGINE=InnoDB UNION=(`other`)",
        "ENGINE=InnoDB PARTITION BY HASH (`id`) PARTITIONS 2",
        "ENGINE=InnoDB EXTERNAL",
        "ENGINE=InnoDB COMMENT='unsafe'",
        "ENGINE=InnoDB DEFINER='root'@'localhost'",
        "ENGINE=InnoDB SQL SECURITY DEFINER",
        "ENGINE=InnoDB ALGORITHM=1",
    ],
)
def test_show_create_replay_rejects_unsafe_table_options(unsafe_suffix: str) -> None:
    statement = f"CREATE TABLE `safe_table` (`id` int NOT NULL) {unsafe_suffix}"
    with pytest.raises(MaskingBoundaryError, match="approved subset"):
        _validate_create_statement("safe_table", statement)


def test_show_create_replay_accepts_only_safe_innodb_and_quoted_comment_name() -> None:
    statement = (
        "CREATE TABLE `safe_table` (`id` int NOT NULL, `comment` varchar(20)) "
        "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
    )
    assert _validate_create_statement("safe_table", statement) == statement


def test_every_discovery_marker_and_camel_case_variant_is_masked() -> None:
    names = tuple(dict.fromkeys(SENSITIVE_MARKERS))
    columns = tuple(
        ColumnSpec(name, "varchar(64)", sensitive=_is_sensitive_name(name), max_length=64)
        for name in names
    )
    raw_row = tuple(f"raw-{index}" for index, _name in enumerate(names))
    snapshot = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(TableSnapshot(name="classified", columns=columns, rows=(raw_row,)),),
    )

    masked = mask_snapshot(snapshot, b"m" * 32).target.tables[0].rows[0]

    assert all(column.sensitive for column in columns)
    assert all(after != before for before, after in zip(raw_row, masked, strict=True))
    for camel_case in (
        "clientFullName",
        "paidAmount",
        "grossEstimate",
        "paymentMode",
        "issuedDate",
    ):
        assert _is_sensitive_name(camel_case)


def test_financial_decimal_markers_are_type_safe_and_never_remain_raw() -> None:
    names = ("paid_amount", "premium", "commission", "expenses")
    columns = tuple(
        ColumnSpec(
            name,
            "decimal(12,2)",
            sensitive=_is_sensitive_name(name),
            precision=12,
            scale=2,
        )
        for name in names
    )
    raw_row = tuple(Decimal(f"{index + 1}.25") for index in range(len(names)))
    snapshot = DatabaseSnapshot(
        database=SOURCE_DATABASE,
        tables=(TableSnapshot(name="financials", columns=columns, rows=(raw_row,)),),
    )

    masked = mask_snapshot(snapshot, b"m" * 32).target.tables[0].rows[0]

    assert all(isinstance(value, Decimal) for value in masked)
    assert all(after != before for before, after in zip(raw_row, masked, strict=True))


@pytest.mark.asyncio
async def test_dedicated_api_client_leases_only_masking_and_submits_aggregate_summary() -> None:
    job_id = "11111111-1111-1111-1111-111111111111"
    connector_id = "22222222-2222-2222-2222-222222222222"
    policy_id = "33333333-3333-3333-3333-333333333333"
    asset_id = "44444444-4444-4444-4444-444444444444"
    lease_token = "55555555-5555-5555-5555-555555555555"  # noqa: S105
    assessment_id = "66666666-6666-6666-6666-666666666666"
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        requests.append({"path": request.url.path, "body": body})
        if request.url.path.endswith("/lease"):
            return httpx.Response(
                200,
                json={
                    "id": job_id,
                    "connector_id": connector_id,
                    "assessment_id": assessment_id,
                    "job_type": "masking_copy",
                    "status": "leased",
                    "payload": {
                        "policy_id": policy_id,
                        "asset_id": asset_id,
                        "source_database": SOURCE_DATABASE,
                        "target_database": TARGET_DATABASE,
                        "row_cap": ROW_CAP,
                    },
                    "lease_token": lease_token,
                    "lease_expires_at": datetime.now(UTC).isoformat(),
                    "attempts": 1,
                    "max_attempts": 3,
                },
            )
        return httpx.Response(200, json={})

    result = aggregate_result()
    async with LocalMaskingApiClient(
        api_url="http://127.0.0.1:8000",
        collector_id=MASKER_COLLECTOR_ID,
        tenant_id="local-development",
        transport=httpx.MockTransport(handler),
    ) as client:
        await client.heartbeat(15)
        job = await client.lease()
        assert job is not None
        await client.complete(job, result=result, error=None)

    lease_body = next(item["body"] for item in requests if item["path"].endswith("/lease"))
    assert lease_body == {
        "collector_id": MASKER_COLLECTOR_ID,
        "supported_job_types": ["masking_copy"],
    }
    completion = next(item["body"] for item in requests if item["path"].endswith("/complete"))
    assert completion["result"]["probe_results"] == []
    assert completion["result"]["summary"] == result.as_summary()
    encoded = json.dumps(completion)
    assert "person@example.test" not in encoded


@pytest.mark.asyncio
async def test_worker_completes_with_only_safe_summary_and_sanitizes_failures(
    tmp_path: Path, monkeypatch
) -> None:
    settings = MaskerSettings.from_environment(projected_environment(tmp_path))
    job = LeasedMaskingJob.model_validate(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "connector_id": "22222222-2222-2222-2222-222222222222",
            "assessment_id": "66666666-6666-6666-6666-666666666666",
            "job_type": "masking_copy",
            "status": "leased",
            "payload": {
                "policy_id": "33333333-3333-3333-3333-333333333333",
                "asset_id": "44444444-4444-4444-4444-444444444444",
                "source_database": SOURCE_DATABASE,
                "target_database": TARGET_DATABASE,
                "row_cap": ROW_CAP,
            },
            "lease_token": "55555555-5555-5555-5555-555555555555",
            "lease_expires_at": datetime.now(UTC),
            "attempts": 1,
            "max_attempts": 3,
        }
    )

    class FakeApi:
        def __init__(self) -> None:
            self.completions: list[tuple[MaskingCopyResult | None, str | None]] = []
            self.raise_on_complete = False

        async def renew(self, _job: LeasedMaskingJob) -> None:
            return None

        async def complete(
            self,
            _job: LeasedMaskingJob,
            *,
            result: MaskingCopyResult | None,
            error: str | None,
        ) -> None:
            self.completions.append((result, error))
            if self.raise_on_complete:
                raise httpx.ConnectError("fake completion transport outage")

    api = FakeApi()
    expected = aggregate_result()

    def succeed(**options: object) -> MaskingCopyResult:
        assert options["source_database"] == SOURCE_DATABASE
        assert options["target_database"] == TARGET_DATABASE
        lease_check = options["lease_check"]
        assert callable(lease_check)
        lease_check()
        return expected

    monkeypatch.setattr(local_masker_module, "execute_local_masking_copy", succeed)
    worker = LocalMaskingWorker(
        settings=settings,
        api=api,  # type: ignore[arg-type]
        source=object(),  # type: ignore[arg-type]
        target=object(),  # type: ignore[arg-type]
        master_key=b"m" * 32,
    )
    await worker.run_job(job)
    assert api.completions == [(expected, None)]

    api.raise_on_complete = True
    await worker.run_job(job)
    assert api.completions[-1] == (expected, None)
    api.raise_on_complete = False

    def fail_closed(**_options: object) -> MaskingCopyResult:
        raise RuntimeError("raw customer value must never escape")

    monkeypatch.setattr(local_masker_module, "execute_local_masking_copy", fail_closed)
    await worker.run_job(job)
    assert api.completions[-1] == (None, "local masking copy failed closed")
    assert "customer" not in str(api.completions[-1]).lower()
