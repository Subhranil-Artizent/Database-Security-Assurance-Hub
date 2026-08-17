from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import importlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from datetime import time as datetime_time
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StringConstraints

from .masking_engine import (
    LOOPBACK_HOSTS,
    MASKING_ALGORITHM,
    ROW_CAP,
    SOURCE_DATABASE,
    STAGING_DATABASE_PREFIX,
    TARGET_DATABASE,
    TARGET_DATABASE_PREFIX,
    ColumnSpec,
    DatabaseSnapshot,
    ForeignKeySpec,
    MaskingBoundaryError,
    MaskValue,
    TableSnapshot,
    derive_key,
    is_approved_staging_database,
    is_approved_target_database,
    mask_snapshot,
    snapshot_hmac,
    staging_database_for_target,
    validate_local_boundary,
    validate_snapshot,
)

LOGGER = logging.getLogger("assurance.local_masker")

SOURCE_USERNAME = "assurance_hub_ro"
TARGET_USERNAME = "assurance_hub_mask_writer"
MASKER_COLLECTOR_ID = "local-mysql-masker"
TARGET_WRITER_PRIVILEGES = frozenset({"CREATE", "INSERT", "SELECT"})
STAGING_WRITER_PRIVILEGES = frozenset(
    {"ALTER", "CREATE", "DROP", "INSERT", "REFERENCES", "SELECT"}
)
SOURCE_READER_PRIVILEGES = frozenset({"SELECT", "SHOW VIEW"})
MAX_TABLES = 500
MAX_COLUMNS = 10_000
MAX_AGGREGATE_VALUES = 250_000

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_RESOURCE_ID = Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]
_LEASE_TOKEN = Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]
_SAFE_TENANT = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
FINAL_GRANT_DATABASE_PATTERN = r"insurance\_sample\_masked%"
STAGING_GRANT_DATABASE_PATTERN = r"aegisdb\_mask\_stage\_%"
_ALLOWED_SETTINGS = frozenset(
    {
        "LOCAL_MASKER_API_URL",
        "LOCAL_MASKER_COLLECTOR_ID",
        "LOCAL_MASKER_TENANT_ID",
        "LOCAL_MASKER_HOST",
        "LOCAL_MASKER_PORT",
        "LOCAL_MASKER_SOURCE_DATABASE",
        "LOCAL_MASKER_TARGET_PREFIX",
        "LOCAL_MASKER_STAGING_PREFIX",
        "LOCAL_MASKER_CREDENTIAL_ROOT",
        "LOCAL_MASKER_SOURCE_SECRET_FILE",
        "LOCAL_MASKER_TARGET_SECRET_FILE",
        "LOCAL_MASKER_KEY_FILE",
    }
)
SENSITIVE_MARKERS = (
    "aadhaar",
    "pan_attached",
    "national_id",
    "passport",
    "tax_identifier",
    "client_full_name",
    "account_number",
    "card_number",
    "cvv",
    "iban",
    "payee",
    "service_provider",
    "garage_name",
    "hospital_name",
    "court_name",
    "agent_name",
    "policy_id",
    "policy_trans",
    "claim_id",
    "claimid",
    "case_id",
    "caseid",
    "paid_amount",
    "paidamount",
    "premium",
    "commission",
    "expenses",
    "gross_estimate",
    "service_tax",
    "insured",
    "employee",
    "lives",
    "payment_mode",
    "settlement_mode",
    "survey_type",
    "city",
    "state",
    "loss_date",
    "paid_date",
    "close_date",
    "issued_date",
)


class LocalSourceReader(Protocol):
    def verify_read_only(self, database: str) -> bool: ...

    def read_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot: ...


class LocalTargetWriter(Protocol):
    def verify_target_only(
        self, source_database: str, target_database: str, staging_database: str
    ) -> bool: ...

    def read_existing_final(
        self, expected: DatabaseSnapshot, row_cap: int
    ) -> DatabaseSnapshot | None: ...

    def stage(self, snapshot: DatabaseSnapshot) -> None: ...

    def read_staged_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot: ...

    def foreign_keys_valid(self, database: str) -> bool: ...

    def publish(self) -> None: ...

    def read_final_snapshot(self, row_cap: int) -> DatabaseSnapshot: ...

    def finish(self) -> None: ...

    def rollback(self) -> None: ...


class MaskingPublishUncertain(MaskingBoundaryError):
    """The final publish may have committed and must be recovered by replay."""


class ConnectionFactory(Protocol):
    def __call__(self, **kwargs: object) -> Any: ...


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class MaskingJobPayload(_StrictModel):
    policy_id: _RESOURCE_ID
    asset_id: _RESOURCE_ID
    source_database: Literal["insurance_sample"]
    target_database: Annotated[
        str,
        StringConstraints(pattern=r"^insurance_sample_masked(?:_[a-f0-9]{12})?$"),
    ]
    row_cap: Literal[500]


class LeasedMaskingJob(_StrictModel):
    id: _RESOURCE_ID
    connector_id: _RESOURCE_ID
    assessment_id: _RESOURCE_ID | None = None
    job_type: Literal["masking_copy"]
    status: Literal["leased", "running"]
    payload: MaskingJobPayload
    lease_token: _LEASE_TOKEN
    lease_expires_at: datetime
    attempts: StrictInt = Field(ge=1, le=20)
    max_attempts: StrictInt = Field(ge=1, le=20)


@dataclass(frozen=True, slots=True)
class LocalCredential:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class MaskerSettings:
    api_url: str
    collector_id: str
    tenant_id: str
    host: str
    port: int
    source_database: str
    target_prefix: str
    staging_prefix: str
    credential_root: Path
    source_secret_file: Path
    target_secret_file: Path
    key_file: Path
    poll_seconds: float = 2.0
    heartbeat_seconds: int = 15
    lease_renew_seconds: int = 10

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> MaskerSettings:
        provided = os.environ if environment is None else environment
        values = {key: provided[key] for key in _ALLOWED_SETTINGS if key in provided}
        unexpected = sorted(
            key
            for key in provided
            if key.startswith("LOCAL_MASKER_") and key not in _ALLOWED_SETTINGS
        )
        if unexpected:
            raise MaskingBoundaryError("local masker received an unapproved setting")

        def required(name: str) -> str:
            value = values.get(name, "").strip()
            if not value:
                raise MaskingBoundaryError("local masker configuration is incomplete")
            return value

        api_url = required("LOCAL_MASKER_API_URL")
        parsed = urlsplit(api_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in LOOPBACK_HOSTS
            or parsed.port is None
            or parsed.path not in {"", "/"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise MaskingBoundaryError("local masker API must use a literal loopback HTTP URL")
        collector_id = required("LOCAL_MASKER_COLLECTOR_ID")
        if collector_id != MASKER_COLLECTOR_ID:
            raise MaskingBoundaryError("local masker collector identity is fixed")
        tenant_id = required("LOCAL_MASKER_TENANT_ID")
        if not _SAFE_TENANT.fullmatch(tenant_id):
            raise MaskingBoundaryError("local masker tenant identity is invalid")
        host = required("LOCAL_MASKER_HOST").lower()
        source_database = required("LOCAL_MASKER_SOURCE_DATABASE")
        target_prefix = required("LOCAL_MASKER_TARGET_PREFIX")
        staging_prefix = required("LOCAL_MASKER_STAGING_PREFIX")
        if target_prefix != TARGET_DATABASE_PREFIX or staging_prefix != STAGING_DATABASE_PREFIX:
            raise MaskingBoundaryError("local masker database prefixes are fixed")
        validate_local_boundary(host, source_database, f"{target_prefix}{'0' * 12}")
        try:
            port = int(required("LOCAL_MASKER_PORT"))
        except ValueError as exc:
            raise MaskingBoundaryError("local masker port is invalid") from exc
        if port < 1 or port > 65535:
            raise MaskingBoundaryError("local masker port is invalid")

        root = Path(required("LOCAL_MASKER_CREDENTIAL_ROOT")).resolve(strict=True)
        if not root.is_dir():
            raise MaskingBoundaryError("local credential root is unavailable")

        def local_file(name: str) -> Path:
            path = Path(required(name)).resolve(strict=True)
            if path.parent != root or not path.is_file():
                raise MaskingBoundaryError("local credential path escaped its approved root")
            return path

        source_secret_file = local_file("LOCAL_MASKER_SOURCE_SECRET_FILE")
        target_secret_file = local_file("LOCAL_MASKER_TARGET_SECRET_FILE")
        key_file = local_file("LOCAL_MASKER_KEY_FILE")
        if len({source_secret_file, target_secret_file, key_file}) != 3:
            raise MaskingBoundaryError("local credential projections must be distinct")
        return cls(
            api_url=api_url.rstrip("/"),
            collector_id=collector_id,
            tenant_id=tenant_id,
            host=host,
            port=port,
            source_database=source_database,
            target_prefix=target_prefix,
            staging_prefix=staging_prefix,
            credential_root=root,
            source_secret_file=source_secret_file,
            target_secret_file=target_secret_file,
            key_file=key_file,
        )


@dataclass(frozen=True, slots=True)
class MaskingCopyResult:
    source_database: str
    target_database: str
    tables_copied: int
    rows_copied: int
    columns_masked: int
    values_masked: int
    row_cap: int
    source_before_hmac: str
    source_after_hmac: str
    target_manifest_hmac: str
    manifest_sha256: str
    key_fingerprint: str
    source_digest_match: bool
    target_counts_match: bool
    foreign_keys_valid: bool
    raw_values_exported: bool
    algorithm: str

    def as_summary(self) -> dict[str, str | int | bool]:
        return {
            "source_database": self.source_database,
            "target_database": self.target_database,
            "tables_copied": self.tables_copied,
            "rows_copied": self.rows_copied,
            "columns_masked": self.columns_masked,
            "values_masked": self.values_masked,
            "row_cap": self.row_cap,
            "source_before_hmac": self.source_before_hmac,
            "source_after_hmac": self.source_after_hmac,
            "target_manifest_hmac": self.target_manifest_hmac,
            "manifest_sha256": self.manifest_sha256,
            "key_fingerprint": self.key_fingerprint,
            "source_digest_match": self.source_digest_match,
            "target_counts_match": self.target_counts_match,
            "foreign_keys_valid": self.foreign_keys_valid,
            "raw_values_exported": self.raw_values_exported,
            "algorithm": self.algorithm,
        }


@dataclass(frozen=True, slots=True)
class _RawColumn:
    name: str
    data_type: str
    column_type: str
    nullable: bool
    max_length: int | None
    precision: int | None
    scale: int | None
    unsigned: bool
    generated: bool


@dataclass(frozen=True, slots=True)
class _SchemaInventory:
    base_tables: tuple[str, ...]
    views: tuple[str, ...]
    triggers: tuple[str, ...]
    routines: tuple[str, ...]
    events: tuple[str, ...]

    @property
    def completely_empty(self) -> bool:
        return not (
            self.base_tables
            or self.views
            or self.triggers
            or self.routines
            or self.events
        )


class MySqlSourceReader:
    """Read one internally consistent snapshot using the fixed local reader."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        credential: LocalCredential,
        connect: ConnectionFactory | None = None,
    ) -> None:
        validate_local_boundary(host, SOURCE_DATABASE, TARGET_DATABASE)
        if credential.username != SOURCE_USERNAME:
            raise MaskingBoundaryError("source credential uses an unapproved account")
        self._host = host
        self._port = port
        self._credential = credential
        self._connect = connect or _default_mysql_connect

    def verify_read_only(self, database: str) -> bool:
        if database != SOURCE_DATABASE:
            return False
        connection = self._open(database)
        try:
            _start_source_transaction(connection)
            return _connection_identity_matches(
                connection, database, SOURCE_USERNAME
            ) and _grants_match(
                _query_all(connection, "SHOW GRANTS FOR CURRENT_USER()"),
                database,
                SOURCE_READER_PRIVILEGES,
            )
        finally:
            _rollback_and_close(connection)

    def read_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot:
        if database != SOURCE_DATABASE or row_cap != ROW_CAP:
            raise MaskingBoundaryError("source snapshot boundary is invalid")
        connection = self._open(database)
        try:
            _start_source_transaction(connection)
            if not _connection_identity_matches(
                connection, database, SOURCE_USERNAME
            ) or not _grants_match(
                _query_all(connection, "SHOW GRANTS FOR CURRENT_USER()"),
                database,
                SOURCE_READER_PRIVILEGES,
            ):
                raise MaskingBoundaryError("source account is not strictly read-only")
            snapshot = _read_source_snapshot(connection, database, row_cap)
            validate_snapshot(snapshot, expected_database=SOURCE_DATABASE)
            return snapshot
        finally:
            _rollback_and_close(connection)

    def _open(self, database: str) -> Any:
        return self._connect(
            host=self._host,
            port=self._port,
            database=database,
            user=self._credential.username,
            password=self._credential.password,
            charset="utf8mb4",
            connection_timeout=10,
            autocommit=False,
        )


class MySqlTargetWriter:
    """Publish one server-derived workflow target through its paired staging schema."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        credential: LocalCredential,
        target_database: str = TARGET_DATABASE,
        connect: ConnectionFactory | None = None,
    ) -> None:
        validate_local_boundary(host, SOURCE_DATABASE, target_database)
        if credential.username != TARGET_USERNAME:
            raise MaskingBoundaryError("target credential uses an unapproved account")
        self._host = host
        self._port = port
        self._credential = credential
        self._target_database = target_database
        self._staging_database = staging_database_for_target(target_database)
        self._publish_lock = f"aegisdb:{target_database}:publish-v2"
        self._connect = connect or _default_mysql_connect
        self._active: Any | None = None
        self._expected: DatabaseSnapshot | None = None
        self._published = False

    def verify_target_only(
        self, source_database: str, target_database: str, staging_database: str
    ) -> bool:
        validate_local_boundary(self._host, source_database, target_database)
        if (
            target_database != self._target_database
            or staging_database != self._staging_database
        ):
            return False
        connection = self._open(None)
        try:
            self._ensure_databases(connection)
            return self._connection_is_scoped(connection)
        finally:
            _rollback_and_close(connection)

    def read_existing_final(
        self, expected: DatabaseSnapshot, row_cap: int
    ) -> DatabaseSnapshot | None:
        validate_snapshot(expected, expected_database=self._target_database)
        if row_cap != ROW_CAP:
            raise MaskingBoundaryError("final target snapshot boundary is invalid")
        if self._active is not None:
            raise MaskingBoundaryError("target writer already has an active copy")
        connection = self._open(self._target_database)
        self._active = connection
        self._expected = expected
        self._published = False
        try:
            if not self._connection_is_scoped(connection):
                raise MaskingBoundaryError("target writer privileges changed")
            self._ensure_databases(connection)
            _acquire_publish_lock(connection, self._publish_lock)
            final_inventory = _schema_inventory(connection, self._target_database)
            staging_inventory = _schema_inventory(connection, self._staging_database)
            if final_inventory.completely_empty:
                _require_staging_cleanup_safe(
                    connection, self._staging_database, staging_inventory, expected
                )
                return None
            if not staging_inventory.completely_empty:
                raise MaskingBoundaryError(
                    "staging must be empty when recovering a published target"
                )
            observed = _read_expected_snapshot(
                connection, self._target_database, expected, row_cap
            )
            if not _foreign_keys_valid(connection, self._target_database, expected):
                raise MaskingBoundaryError("published target failed foreign-key validation")
            self.finish()
            return observed
        except Exception:
            self.rollback()
            raise

    def stage(self, snapshot: DatabaseSnapshot) -> None:
        validate_snapshot(snapshot, expected_database=self._target_database)
        connection, expected = self._require_active()
        if expected != snapshot or self._published:
            raise MaskingBoundaryError("staged copy differs from its recovered manifest")
        foreign_key_checks_disabled = False
        try:
            if not self._connection_is_scoped(connection):
                raise MaskingBoundaryError("target writer privileges changed")
            if not _schema_inventory(connection, self._target_database).completely_empty:
                raise MaskingBoundaryError(
                    "masked target is not empty; no overwrite was attempted"
                )
            _execute(connection, "SET SESSION FOREIGN_KEY_CHECKS = 0")
            foreign_key_checks_disabled = True
            _clean_staging_base_tables(connection, self._staging_database, expected)
            for table in snapshot.tables:
                _execute(
                    connection,
                    _target_create_statement(table, self._staging_database),
                )
            for table in snapshot.tables:
                if not table.rows:
                    continue
                columns = ", ".join(
                    _quote_identifier(column.name) for column in table.columns
                )
                placeholders = ", ".join("%s" for _column in table.columns)
                statement = (
                    f"INSERT INTO {_qualified(self._staging_database, table.name)} ({columns}) "  # noqa: S608
                    f"VALUES ({placeholders})"
                )
                _execute_many(connection, statement, table.rows)
            _execute(connection, "SET SESSION FOREIGN_KEY_CHECKS = 1")
            foreign_key_checks_disabled = False
        except Exception:
            if foreign_key_checks_disabled:
                _best_effort_enable_foreign_keys(connection)
            self.rollback()
            raise

    def read_staged_snapshot(self, database: str, row_cap: int) -> DatabaseSnapshot:
        if database != self._staging_database or row_cap != ROW_CAP:
            raise MaskingBoundaryError("staging snapshot boundary is invalid")
        connection, expected = self._require_active()
        return _read_expected_snapshot(connection, self._staging_database, expected, row_cap)

    def foreign_keys_valid(self, database: str) -> bool:
        if database not in {self._staging_database, self._target_database}:
            return False
        connection, expected = self._require_active()
        return _foreign_keys_valid(connection, database, expected)

    def publish(self) -> None:
        connection, expected = self._require_active()
        if self._published:
            raise MaskingBoundaryError("masked target was already published")
        connection.commit()
        if not _schema_inventory(connection, self._target_database).completely_empty:
            raise MaskingBoundaryError("masked target became nonempty before publish")
        _verify_target_manifest(connection, self._staging_database, expected)
        renames = ", ".join(
            f"{_qualified(self._staging_database, table.name)} TO "
            f"{_qualified(self._target_database, table.name)}"
            for table in sorted(expected.tables, key=lambda item: item.name)
        )
        if not renames:
            raise MaskingBoundaryError("there are no staging tables to publish")
        _execute(connection, "SET SESSION lock_wait_timeout = 5")
        try:
            _execute(connection, f"RENAME TABLE {renames}")  # noqa: S608
        except Exception as exc:
            if self._recover_publish_after_error(expected, renames):
                return
            raise MaskingPublishUncertain(
                "masked target publish outcome requires replay recovery"
            ) from exc
        self._published = True
        try:
            if not _schema_inventory(connection, self._staging_database).completely_empty:
                raise MaskingBoundaryError("staging was not empty after atomic publish")
        except Exception as exc:
            raise MaskingPublishUncertain(
                "masked target publish requires replay verification"
            ) from exc

    def read_final_snapshot(self, row_cap: int) -> DatabaseSnapshot:
        if row_cap != ROW_CAP or not self._published:
            raise MaskingBoundaryError("final target snapshot boundary is invalid")
        connection, expected = self._require_active()
        return _read_expected_snapshot(connection, self._target_database, expected, row_cap)

    def finish(self) -> None:
        connection, _expected = self._require_active()
        try:
            _release_publish_lock(connection, self._publish_lock)
            connection.close()
        finally:
            self._active = None
            self._expected = None
            self._published = False

    def rollback(self) -> None:
        if self._active is None:
            self._expected = None
            self._published = False
            return
        connection = self._active
        self._active = None
        self._expected = None
        self._published = False
        try:
            connection.rollback()
        finally:
            _release_publish_lock(connection, self._publish_lock)
            connection.close()

    def _connection_is_scoped(self, connection: Any) -> bool:
        return _mysql_version_supported(connection) and _connection_identity_matches(
            connection, self._target_database, TARGET_USERNAME
        ) and _grants_match_scopes(
            _query_all(connection, "SHOW GRANTS FOR CURRENT_USER()"),
            {
                FINAL_GRANT_DATABASE_PATTERN: TARGET_WRITER_PRIVILEGES,
                STAGING_GRANT_DATABASE_PATTERN: STAGING_WRITER_PRIVILEGES,
            },
        )

    def _open(self, database: str | None) -> Any:
        options: dict[str, object] = dict(
            host=self._host,
            port=self._port,
            user=self._credential.username,
            password=self._credential.password,
            charset="utf8mb4",
            connection_timeout=10,
            autocommit=False,
        )
        if database is not None:
            options["database"] = database
        return self._connect(**options)

    def _ensure_databases(self, connection: Any) -> None:
        _execute(
            connection,
            f"CREATE DATABASE IF NOT EXISTS {_quote_identifier(self._target_database)} "
            "CHARACTER SET utf8mb4",
        )
        _execute(
            connection,
            f"CREATE DATABASE IF NOT EXISTS {_quote_identifier(self._staging_database)} "
            "CHARACTER SET utf8mb4",
        )
        _execute(connection, f"USE {_quote_identifier(self._target_database)}")

    def _require_active(self) -> tuple[Any, DatabaseSnapshot]:
        if self._active is None or self._expected is None:
            raise MaskingBoundaryError("target writer has no staged copy")
        return self._active, self._expected

    def _recover_publish_after_error(
        self, expected: DatabaseSnapshot, renames: str
    ) -> bool:
        previous = self._active
        self._active = None
        if previous is not None:
            try:
                previous.close()
            except Exception:
                LOGGER.debug("discarded an unavailable local masking connection")
        try:
            connection = self._open(self._target_database)
            self._active = connection
            self._expected = expected
            if not self._connection_is_scoped(connection):
                return False
            self._ensure_databases(connection)
            _acquire_publish_lock(connection, self._publish_lock)
            final_inventory = _schema_inventory(connection, self._target_database)
            staging_inventory = _schema_inventory(connection, self._staging_database)
            if staging_inventory.completely_empty and not final_inventory.completely_empty:
                _read_expected_snapshot(
                    connection, self._target_database, expected, ROW_CAP
                )
                if not _foreign_keys_valid(connection, self._target_database, expected):
                    return False
                self._published = True
                return True
            if final_inventory.completely_empty:
                _verify_target_manifest(connection, self._staging_database, expected)
                _execute(connection, "SET SESSION lock_wait_timeout = 5")
                _execute(connection, f"RENAME TABLE {renames}")  # noqa: S608
                self._published = True
                return _schema_inventory(
                    connection, self._staging_database
                ).completely_empty
            return False
        except Exception:
            return False


def execute_local_masking_copy(
    *,
    host: str,
    port: int,
    source_database: str,
    target_database: str,
    master_key: bytes,
    source: LocalSourceReader,
    target: LocalTargetWriter,
    lease_check: Callable[[], None] | None = None,
) -> MaskingCopyResult:
    """Copy and mask locally while keeping raw values inside this process."""
    validate_local_boundary(host, source_database, target_database)
    staging_database = staging_database_for_target(target_database)
    if port < 1 or port > 65535:
        raise MaskingBoundaryError("local masking port is invalid")
    check = lease_check or (lambda: None)
    check()
    if not source.verify_read_only(source_database):
        raise MaskingBoundaryError("source account is not strictly read-only")
    if not target.verify_target_only(
        source_database, target_database, staging_database
    ):
        raise MaskingBoundaryError("target account is not restricted to the masked database")

    evidence_key = derive_key(master_key, b"evidence")
    check()
    before = source.read_snapshot(source_database, ROW_CAP)
    validate_snapshot(before, expected_database=SOURCE_DATABASE)
    source_before_hmac = snapshot_hmac(before, evidence_key)
    transformation = mask_snapshot(
        before, master_key, target_database=target_database
    )
    if transformation.values_masked < 1:
        raise MaskingBoundaryError("no nonempty sensitive values were selected for masking")
    if (
        transformation.tables_copied > MAX_TABLES
        or transformation.rows_copied > MAX_AGGREGATE_VALUES
        or transformation.columns_masked > MAX_COLUMNS
        or transformation.values_masked > MAX_AGGREGATE_VALUES
    ):
        raise MaskingBoundaryError("masking copy exceeds its aggregate evidence boundary")

    def source_after_hmac() -> str:
        after = source.read_snapshot(source_database, ROW_CAP)
        validate_snapshot(after, expected_database=SOURCE_DATABASE)
        digest = snapshot_hmac(after, evidence_key)
        if not hmac.compare_digest(source_before_hmac, digest):
            raise MaskingBoundaryError("source changed during the local copy window")
        return digest

    def validated_target_hmac(
        observed: DatabaseSnapshot, expected: DatabaseSnapshot
    ) -> str:
        validate_snapshot(observed, expected_database=expected.database)
        expected_hmac = snapshot_hmac(expected, evidence_key)
        observed_hmac = snapshot_hmac(observed, evidence_key)
        counts_match = _row_counts(observed) == _row_counts(expected)
        if not counts_match or not hmac.compare_digest(expected_hmac, observed_hmac):
            raise MaskingBoundaryError("observed target differs from the deterministic copy")
        return observed_hmac

    def result_for(source_after: str, target_hmac: str) -> MaskingCopyResult:
        key_fingerprint = hashlib.sha256(master_key).hexdigest()[:16]
        manifest = {
            "algorithm": MASKING_ALGORITHM,
            "columns_masked": transformation.columns_masked,
            "foreign_keys_valid": True,
            "key_fingerprint": key_fingerprint,
            "raw_values_exported": False,
            "row_cap": ROW_CAP,
            "rows_copied": transformation.rows_copied,
            "source_after_hmac": source_after,
            "source_before_hmac": source_before_hmac,
            "source_database": source_database,
            "tables_copied": transformation.tables_copied,
            "target_counts_match": True,
            "target_database": target_database,
            "target_manifest_hmac": target_hmac,
            "values_masked": transformation.values_masked,
        }
        manifest_sha256 = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return MaskingCopyResult(
            source_database=source_database,
            target_database=target_database,
            tables_copied=transformation.tables_copied,
            rows_copied=transformation.rows_copied,
            columns_masked=transformation.columns_masked,
            values_masked=transformation.values_masked,
            row_cap=ROW_CAP,
            source_before_hmac=source_before_hmac,
            source_after_hmac=source_after,
            target_manifest_hmac=target_hmac,
            manifest_sha256=manifest_sha256,
            key_fingerprint=key_fingerprint,
            source_digest_match=True,
            target_counts_match=True,
            foreign_keys_valid=True,
            raw_values_exported=False,
            algorithm=MASKING_ALGORITHM,
        )

    existing = target.read_existing_final(transformation.target, ROW_CAP)
    if existing is not None:
        existing_hmac = validated_target_hmac(existing, transformation.target)
        check()
        return result_for(source_after_hmac(), existing_hmac)

    staged = False
    try:
        check()
        staged = True
        target.stage(transformation.target)
        expected_staging = DatabaseSnapshot(
            database=staging_database,
            tables=transformation.target.tables,
        )
        staged_snapshot = target.read_staged_snapshot(staging_database, ROW_CAP)
        validated_target_hmac(staged_snapshot, expected_staging)
        if not target.foreign_keys_valid(staging_database):
            raise MaskingBoundaryError("staged target failed foreign-key validation")

        check()
        source_after_hmac()
        check()
        target.publish()
        published = target.read_final_snapshot(ROW_CAP)
        published_hmac = validated_target_hmac(published, transformation.target)
        if not target.foreign_keys_valid(target_database):
            raise MaskingBoundaryError("published target failed foreign-key validation")
        check()
        after_hmac = source_after_hmac()
        result = result_for(after_hmac, published_hmac)
        target.finish()
        staged = False
        return result
    except Exception:
        if staged:
            target.rollback()
        raise


class LocalMaskingApiClient:
    def __init__(
        self,
        *,
        api_url: str,
        collector_id: str,
        tenant_id: str,
        timeout_seconds: float = 15,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._collector_id = collector_id
        self._tenant_id = tenant_id
        self._client = httpx.AsyncClient(
            base_url=api_url,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=transport,
        )

    async def __aenter__(self) -> LocalMaskingApiClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self._client.aclose()

    async def ready(self) -> bool:
        try:
            response = await self._request("GET", "/api/v1/collectors/ready")
            response.raise_for_status()
            body: object = response.json()
            return body == {"status": "ok", "collector_id": self._collector_id}
        except (httpx.HTTPError, TypeError, ValueError):
            return False

    async def heartbeat(self, heartbeat_seconds: int) -> None:
        response = await self._request(
            "POST",
            "/api/v1/collectors/heartbeat",
            _operation_key(
                "heartbeat",
                self._collector_id,
                str(int(time.time() / heartbeat_seconds)),
            ),
            json_body={
                "collector_id": self._collector_id,
                "version": "0.1.0",
                "capabilities": ["masking_copy"],
            },
        )
        response.raise_for_status()

    async def lease(self) -> LeasedMaskingJob | None:
        response = await self._exact_mutation(
            "/api/v1/scan-jobs/lease",
            _operation_key("lease", self._collector_id, str(uuid.uuid4())),
            {
                "collector_id": self._collector_id,
                "supported_job_types": ["masking_copy"],
            },
        )
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return LeasedMaskingJob.model_validate(response.json())

    async def renew(self, job: LeasedMaskingJob) -> None:
        response = await self._request(
            "POST",
            f"/api/v1/scan-jobs/{job.id}/renew",
            _operation_key("renew", job.id, job.lease_token, str(int(time.time() / 5))),
            json_body={"collector_id": self._collector_id, "lease_token": job.lease_token},
        )
        response.raise_for_status()
        renewed = LeasedMaskingJob.model_validate(response.json())
        if renewed.id != job.id or renewed.lease_token != job.lease_token:
            raise MaskingBoundaryError("lease renewal did not preserve the active fence")

    async def complete(
        self,
        job: LeasedMaskingJob,
        *,
        result: MaskingCopyResult | None,
        error: str | None,
    ) -> None:
        success = result is not None
        body = {
            "collector_id": self._collector_id,
            "lease_token": job.lease_token,
            "success": success,
            "result": {
                "probe_results": [],
                "summary": result.as_summary() if result is not None else {},
            },
            "error": error,
        }
        response = await self._exact_mutation(
            f"/api/v1/scan-jobs/{job.id}/complete",
            _operation_key("complete", job.id, job.lease_token),
            body,
        )
        response.raise_for_status()

    async def _exact_mutation(
        self,
        path: str,
        idempotency_key: str,
        body: object,
        attempts: int = 3,
    ) -> httpx.Response:
        for attempt in range(1, attempts + 1):
            try:
                response = await self._request("POST", path, idempotency_key, json_body=body)
            except httpx.TransportError:
                if attempt == attempts:
                    raise
                await asyncio.sleep(0.1 * (2 ** (attempt - 1)))
                continue
            if response.status_code >= 500 and attempt < attempts:
                await asyncio.sleep(0.1 * (2 ** (attempt - 1)))
                continue
            return response
        raise AssertionError("bounded request loop must return or raise")

    async def _request(
        self,
        method: str,
        path: str,
        idempotency_key: str | None = None,
        json_body: object | None = None,
    ) -> httpx.Response:
        headers = {
            "X-Tenant-ID": self._tenant_id,
            "X-Subject": self._collector_id,
            "X-Roles": "collector",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        return await self._client.request(method, path, headers=headers, json=json_body)


class LocalMaskingWorker:
    def __init__(
        self,
        *,
        settings: MaskerSettings,
        api: LocalMaskingApiClient,
        source: LocalSourceReader,
        target: LocalTargetWriter | None,
        master_key: bytes,
        target_factory: Callable[[str], LocalTargetWriter] | None = None,
    ) -> None:
        self._settings = settings
        self._api = api
        self._source = source
        self._target = target
        self._target_factory = target_factory
        if target is None and target_factory is None:
            raise MaskingBoundaryError("local masker has no approved target writer")
        self._master_key = master_key

    async def run_forever(self) -> None:
        next_heartbeat = 0.0
        while True:
            now = time.monotonic()
            if now >= next_heartbeat:
                await self._api.heartbeat(self._settings.heartbeat_seconds)
                next_heartbeat = now + self._settings.heartbeat_seconds
            job = await self._api.lease()
            if job is None:
                await asyncio.sleep(self._settings.poll_seconds)
                continue
            await self.run_job(job)

    async def run_job(self, job: LeasedMaskingJob) -> None:
        payload = job.payload
        validate_local_boundary(
            self._settings.host,
            payload.source_database,
            payload.target_database,
        )
        if payload.row_cap != ROW_CAP:
            raise MaskingBoundaryError("masking job row cap is not fixed")
        target = (
            self._target_factory(payload.target_database)
            if self._target_factory is not None
            else self._target
        )
        if target is None:
            raise MaskingBoundaryError("local masker target writer is unavailable")
        lease_lost = threading.Event()
        finished = asyncio.Event()
        renewal = asyncio.create_task(self._renew_until_finished(job, lease_lost, finished))

        def check_lease() -> None:
            if lease_lost.is_set():
                raise MaskingBoundaryError("masking job lease was lost")

        try:
            try:
                result = await asyncio.to_thread(
                    execute_local_masking_copy,
                    host=self._settings.host,
                    port=self._settings.port,
                    source_database=payload.source_database,
                    target_database=payload.target_database,
                    master_key=self._master_key,
                    source=self._source,
                    target=target,
                    lease_check=check_lease,
                )
            except MaskingPublishUncertain:
                LOGGER.warning(
                    "masking_copy publish verification deferred for job %s", job.id
                )
                return
            except Exception as exc:
                if lease_lost.is_set():
                    LOGGER.warning("masking_copy lease lost for job %s", job.id)
                    return
                try:
                    await self._api.complete(job, result=None, error=_safe_error(exc))
                except Exception:
                    LOGGER.warning(
                        "masking_copy failure acknowledgement deferred for job %s", job.id
                    )
                    return
                LOGGER.warning("masking_copy failed closed for job %s", job.id)
                return
            if lease_lost.is_set():
                LOGGER.warning("masking_copy lease lost for job %s", job.id)
                return
            try:
                await self._api.complete(job, result=result, error=None)
            except Exception:
                LOGGER.warning(
                    "masking_copy completion acknowledgement deferred for job %s", job.id
                )
                return
            LOGGER.info("masking_copy completed for job %s", job.id)
        finally:
            finished.set()
            await renewal

    async def _renew_until_finished(
        self,
        job: LeasedMaskingJob,
        lease_lost: threading.Event,
        finished: asyncio.Event,
    ) -> None:
        while True:
            try:
                await asyncio.wait_for(finished.wait(), timeout=self._settings.lease_renew_seconds)
                return
            except TimeoutError:
                pass
            try:
                await self._api.renew(job)
            except Exception:
                lease_lost.set()
                return


def load_local_credential(path: Path, *, expected_username: str) -> LocalCredential:
    payload = _read_small_json(path)
    if set(payload) != {"username", "password", "ca_file"}:
        raise MaskingBoundaryError("local credential projection has an invalid shape")
    username = payload.get("username")
    password = payload.get("password")
    if username != expected_username or not isinstance(password, str) or not password:
        raise MaskingBoundaryError("local credential projection is invalid")
    if payload.get("ca_file") is not None:
        raise MaskingBoundaryError("local loopback credential cannot configure remote TLS material")
    return LocalCredential(username=username, password=password)


def load_masking_key(path: Path) -> bytes:
    payload = _read_small_json(path)
    if set(payload) != {"version", "key_b64"} or payload.get("version") != 1:
        raise MaskingBoundaryError("local masking key projection is invalid")
    encoded = payload.get("key_b64")
    if not isinstance(encoded, str):
        raise MaskingBoundaryError("local masking key projection is invalid")
    try:
        key = base64.b64decode(encoded.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise MaskingBoundaryError("local masking key projection is invalid") from exc
    if len(key) != 32:
        raise MaskingBoundaryError("local masking key projection is invalid")
    return key


def _read_small_json(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > 16_384:
            raise MaskingBoundaryError("local projection exceeds 16 KiB")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaskingBoundaryError("local projection is unavailable") from exc
    if not isinstance(value, dict):
        raise MaskingBoundaryError("local projection must be a JSON object")
    return value


def _read_source_snapshot(connection: Any, database: str, row_cap: int) -> DatabaseSnapshot:
    object_rows = _query_all(
        connection,
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = %s ORDER BY table_name",
        (database,),
    )
    if any(str(row[1]).upper() != "BASE TABLE" for row in object_rows):
        raise MaskingBoundaryError("views are outside the approved masking copy")
    table_names = tuple(str(row[0]) for row in object_rows)
    if len(table_names) > MAX_TABLES:
        raise MaskingBoundaryError("source exceeds the fixed table boundary")
    if any(not _IDENTIFIER.fullmatch(name) for name in table_names):
        raise MaskingBoundaryError("source contains an unsupported table identifier")
    if _database_int(
        _query_scalar(
            connection,
            "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = %s",
            (database,),
        )
    ):
        raise MaskingBoundaryError("triggers are outside the approved masking copy")

    raw_columns = _load_raw_columns(connection, database)
    if set(raw_columns) != set(table_names):
        raise MaskingBoundaryError("source table metadata is incomplete")
    if sum(len(columns) for columns in raw_columns.values()) > MAX_COLUMNS:
        raise MaskingBoundaryError("source exceeds the fixed column boundary")
    primary_keys = _load_primary_keys(connection, database)
    foreign_keys = _load_foreign_keys(connection, database)
    relation_groups, relationship_sensitive = _relationship_metadata(raw_columns, foreign_keys)

    tables: list[TableSnapshot] = []
    for table_name in table_names:
        columns = tuple(
            _column_spec(
                item,
                sensitive=(table_name, item.name) in relationship_sensitive
                or _is_sensitive_name(item.name),
                relation_group=relation_groups.get((table_name, item.name)),
            )
            for item in raw_columns[table_name]
        )
        count = _database_int(
            _query_scalar(
                connection,
                f"SELECT COUNT(*) FROM {_qualified(database, table_name)}",  # noqa: S608
            )
        )
        if count > row_cap:
            raise MaskingBoundaryError(f"table {table_name} exceeds the {row_cap}-row cap")
        projection = ", ".join(_quote_identifier(column.name) for column in columns)
        rows = _query_all(
            connection,
            f"SELECT {projection} FROM {_qualified(database, table_name)}",  # noqa: S608
        )
        if len(rows) != count or len(rows) > row_cap:
            raise MaskingBoundaryError("source table count changed inside its snapshot")
        normalized = tuple(tuple(_normalize_driver_value(value) for value in row) for row in rows)
        create_row = _query_one(
            connection,
            f"SHOW CREATE TABLE {_qualified(database, table_name)}",
        )
        if len(create_row) < 2 or not isinstance(create_row[1], str):
            raise MaskingBoundaryError("source table DDL is unavailable")
        create_statement = _validate_create_statement(table_name, create_row[1])
        tables.append(
            TableSnapshot(
                name=table_name,
                columns=columns,
                rows=normalized,
                primary_key=primary_keys.get(table_name, ()),
                foreign_keys=foreign_keys.get(table_name, ()),
                create_statement=create_statement,
            )
        )
    return DatabaseSnapshot(database=database, tables=tuple(tables))


def _load_raw_columns(connection: Any, database: str) -> dict[str, tuple[_RawColumn, ...]]:
    rows = _query_all(
        connection,
        "SELECT table_name, column_name, data_type, column_type, is_nullable, "
        "character_maximum_length, numeric_precision, numeric_scale, extra, generation_expression "
        "FROM information_schema.columns WHERE table_schema = %s "
        "ORDER BY table_name, ordinal_position",
        (database,),
    )
    grouped: dict[str, list[_RawColumn]] = {}
    for row in rows:
        name = str(row[1])
        if not _IDENTIFIER.fullmatch(name):
            raise MaskingBoundaryError("source contains an unsupported column identifier")
        extra = str(row[8] or "")
        expression = str(row[9] or "")
        item = _RawColumn(
            name=name,
            data_type=str(row[2]).lower(),
            column_type=str(row[3]),
            nullable=str(row[4]).upper() == "YES",
            max_length=_database_int(row[5]) if row[5] is not None else None,
            precision=_database_int(row[6]) if row[6] is not None else None,
            scale=_database_int(row[7]) if row[7] is not None else None,
            unsigned="unsigned" in str(row[3]).lower().split(),
            generated="generated" in extra.lower() or bool(expression),
        )
        grouped.setdefault(str(row[0]), []).append(item)
    return {name: tuple(items) for name, items in grouped.items()}


def _load_primary_keys(connection: Any, database: str) -> dict[str, tuple[str, ...]]:
    rows = _query_all(
        connection,
        "SELECT table_name, column_name FROM information_schema.key_column_usage "
        "WHERE table_schema = %s AND constraint_name = 'PRIMARY' "
        "ORDER BY table_name, ordinal_position",
        (database,),
    )
    grouped: dict[str, list[str]] = {}
    for row in rows:
        grouped.setdefault(str(row[0]), []).append(str(row[1]))
    return {name: tuple(items) for name, items in grouped.items()}


def _load_foreign_keys(connection: Any, database: str) -> dict[str, tuple[ForeignKeySpec, ...]]:
    rows = _query_all(
        connection,
        "SELECT table_name, constraint_name, column_name, referenced_table_schema, "
        "referenced_table_name, referenced_column_name FROM information_schema.key_column_usage "
        "WHERE table_schema = %s AND referenced_table_name IS NOT NULL "
        "ORDER BY table_name, constraint_name, ordinal_position",
        (database,),
    )
    grouped: dict[tuple[str, str, str], list[tuple[str, str]]] = {}
    for row in rows:
        if str(row[3]) != database:
            raise MaskingBoundaryError("foreign key crosses the approved database boundary")
        key = (str(row[0]), str(row[1]), str(row[4]))
        grouped.setdefault(key, []).append((str(row[2]), str(row[5])))
    by_table: dict[str, list[ForeignKeySpec]] = {}
    for (table_name, _constraint, parent_table), pairs in grouped.items():
        by_table.setdefault(table_name, []).append(
            ForeignKeySpec(
                child_columns=tuple(pair[0] for pair in pairs),
                parent_table=parent_table,
                parent_columns=tuple(pair[1] for pair in pairs),
            )
        )
    return {
        name: tuple(sorted(items, key=lambda item: (item.parent_table, item.child_columns)))
        for name, items in by_table.items()
    }


def _relationship_metadata(
    columns: dict[str, tuple[_RawColumn, ...]],
    foreign_keys: dict[str, tuple[ForeignKeySpec, ...]],
) -> tuple[dict[tuple[str, str], str], set[tuple[str, str]]]:
    nodes = {(table, column.name) for table, items in columns.items() for column in items}
    parent = {node: node for node in nodes}

    def root(node: tuple[str, str]) -> tuple[str, str]:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root = root(left)
        right_root = root(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for child_table, items in foreign_keys.items():
        for item in items:
            for child, referenced in zip(item.child_columns, item.parent_columns, strict=True):
                child_node = (child_table, child)
                parent_node = (item.parent_table, referenced)
                if child_node not in nodes or parent_node not in nodes:
                    raise MaskingBoundaryError("foreign key metadata references an unknown column")
                union(child_node, parent_node)

    groups: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for node in nodes:
        groups.setdefault(root(node), set()).add(node)
    relation_groups: dict[tuple[str, str], str] = {}
    sensitive_nodes: set[tuple[str, str]] = set()
    for members in groups.values():
        if len(members) < 2:
            continue
        if not any(_is_sensitive_name(column) for _table, column in members):
            continue
        serialized = "|".join(f"{table}.{column}" for table, column in sorted(members))
        group_name = "rel_" + hashlib.sha256(serialized.encode()).hexdigest()[:24]
        for member in members:
            relation_groups[member] = group_name
            sensitive_nodes.add(member)
    return relation_groups, sensitive_nodes


def _column_spec(
    item: _RawColumn,
    *,
    sensitive: bool,
    relation_group: str | None,
) -> ColumnSpec:
    return ColumnSpec(
        name=item.name,
        mysql_type=item.column_type,
        nullable=item.nullable,
        sensitive=sensitive,
        max_length=item.max_length,
        precision=item.precision,
        scale=item.scale,
        unsigned=item.unsigned,
        relation_group=relation_group,
        generated=item.generated,
    )


def _is_sensitive_name(name: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    normalized = re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")
    return any(marker in normalized for marker in SENSITIVE_MARKERS)


def _target_create_statement(table: TableSnapshot, database: str) -> str:
    if not is_approved_staging_database(database):
        raise MaskingBoundaryError("table creation is restricted to the staging database")
    if table.create_statement is None:
        raise MaskingBoundaryError("source table DDL is missing")
    source_prefix = f"CREATE TABLE {_quote_identifier(table.name)}"
    if not table.create_statement.startswith(source_prefix):
        raise MaskingBoundaryError("source table DDL prefix is invalid")
    return (
        f"CREATE TABLE {_qualified(database, table.name)}"
        + table.create_statement[len(source_prefix) :]
    )


def _validate_create_statement(table_name: str, statement: str) -> str:
    prefix = f"CREATE TABLE {_quote_identifier(table_name)}"
    reviewed = _ddl_without_literals_or_identifiers(statement)
    upper = reviewed.upper()
    unsafe = (
        r"\bFEDERATED\b",
        r"\bCONNECTION\b",
        r"\bDATA\s+DIRECTORY\b",
        r"\bINDEX\s+DIRECTORY\b",
        r"\bTABLESPACE\b",
        r"\bUNION\s*=",
        r"\bPARTITION(?:ED|ING)?\b",
        r"\bEXTERNAL\b",
        r"\bCOMMENT\b",
        r"\bDEFINER\b",
        r"\bSQL\s+SECURITY\b",
        r"\bALGORITHM\b",
    )
    engines = re.findall(r"\bENGINE\s*=\s*([A-Z0-9_]+)", upper)
    if (
        not statement.startswith(prefix)
        or not statement[len(prefix) :].lstrip().startswith("(")
        or ";" in statement
        or len(engines) != 1
        or engines[0] != "INNODB"
        or any(re.search(pattern, upper) for pattern in unsafe)
        or "/*" in reviewed
        or "--" in reviewed
        or re.search(r"(^|\s)#", reviewed)
        or re.search(r"\bCREATE\s+(?:OR\s+REPLACE\s+)?VIEW\b", upper)
        or re.search(r"\bCREATE\s+TRIGGER\b", upper)
        or re.search(r"`[^`]+`\s*\.\s*`", statement)
    ):
        raise MaskingBoundaryError("source table DDL is outside the approved subset")
    return statement


def _ddl_without_literals_or_identifiers(statement: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(statement):
        character = statement[index]
        if character not in {"`", "'", '"'}:
            output.append(character)
            index += 1
            continue
        quote = character
        output.append(quote)
        index += 1
        while index < len(statement):
            current = statement[index]
            if current == "\\" and quote != "`" and index + 1 < len(statement):
                index += 2
                continue
            if current == quote:
                if index + 1 < len(statement) and statement[index + 1] == quote:
                    index += 2
                    continue
                output.append(quote)
                index += 1
                break
            index += 1
        else:
            raise MaskingBoundaryError("source table DDL contains an unterminated quote")
    return "".join(output)


def _verify_target_manifest(
    connection: Any, database: str, expected: DatabaseSnapshot
) -> None:
    if not (
        is_approved_staging_database(database)
        or is_approved_target_database(database)
    ):
        raise MaskingBoundaryError("target manifest database is outside the approved boundary")
    inventory = _schema_inventory(connection, database)
    expected_names = tuple(sorted(table.name for table in expected.tables))
    if inventory.base_tables != expected_names or any(
        (inventory.views, inventory.triggers, inventory.routines, inventory.events)
    ):
        raise MaskingBoundaryError("target objects differ from the staged manifest")
    actual_columns = _load_raw_columns(connection, database)
    actual_primary = _load_primary_keys(connection, database)
    actual_foreign = _load_foreign_keys(connection, database)
    for table in expected.tables:
        create_row = _query_one(
            connection,
            f"SHOW CREATE TABLE {_qualified(database, table.name)}",
        )
        if len(create_row) < 2 or not isinstance(create_row[1], str):
            raise MaskingBoundaryError("target table DDL is unavailable")
        actual_create = _validate_create_statement(table.name, create_row[1])
        if table.create_statement is None or _stable_create_statement(
            actual_create
        ) != _stable_create_statement(table.create_statement):
            raise MaskingBoundaryError("target table DDL differs from the staged manifest")
        expected_contracts = tuple(_column_contract(column) for column in table.columns)
        actual_contracts = tuple(
            _raw_column_contract(column) for column in actual_columns[table.name]
        )
        if expected_contracts != actual_contracts:
            raise MaskingBoundaryError("target columns differ from the staged manifest")
        if actual_primary.get(table.name, ()) != table.primary_key:
            raise MaskingBoundaryError("target primary key differs from the staged manifest")
        if actual_foreign.get(table.name, ()) != table.foreign_keys:
            raise MaskingBoundaryError("target foreign keys differ from the staged manifest")


def _read_expected_snapshot(
    connection: Any,
    database: str,
    expected: DatabaseSnapshot,
    row_cap: int,
) -> DatabaseSnapshot:
    if row_cap != ROW_CAP:
        raise MaskingBoundaryError("target row cap is not fixed")
    _verify_target_manifest(connection, database, expected)
    tables: list[TableSnapshot] = []
    for table in expected.tables:
        count = _database_int(
            _query_scalar(
                connection,
                f"SELECT COUNT(*) FROM {_qualified(database, table.name)}",  # noqa: S608
            )
        )
        if count != len(table.rows) or count > row_cap:
            raise MaskingBoundaryError("target table row count differs from the manifest")
        projection = ", ".join(_quote_identifier(column.name) for column in table.columns)
        rows = _query_all(
            connection,
            f"SELECT {projection} FROM {_qualified(database, table.name)}",  # noqa: S608
        )
        if len(rows) != count:
            raise MaskingBoundaryError("target table changed while it was verified")
        normalized = tuple(
            tuple(_normalize_driver_value(value) for value in row) for row in rows
        )
        create_row = _query_one(
            connection,
            f"SHOW CREATE TABLE {_qualified(database, table.name)}",
        )
        if len(create_row) < 2 or not isinstance(create_row[1], str):
            raise MaskingBoundaryError("target table DDL is unavailable")
        tables.append(
            replace(
                table,
                rows=normalized,
                create_statement=_validate_create_statement(table.name, create_row[1]),
            )
        )
    return DatabaseSnapshot(database=database, tables=tuple(tables))


def _foreign_keys_valid(
    connection: Any, database: str, expected: DatabaseSnapshot
) -> bool:
    if not (
        is_approved_staging_database(database)
        or is_approved_target_database(database)
    ):
        return False
    for table in expected.tables:
        for foreign_key in table.foreign_keys:
            child_alias = "child_row"
            parent_alias = "parent_row"
            child_present = " AND ".join(
                f"{child_alias}.{_quote_identifier(column)} IS NOT NULL"
                for column in foreign_key.child_columns
            )
            relation = " AND ".join(
                f"{parent_alias}.{_quote_identifier(parent)} <=> "
                f"{child_alias}.{_quote_identifier(child)}"
                for child, parent in zip(
                    foreign_key.child_columns,
                    foreign_key.parent_columns,
                    strict=True,
                )
            )
            statement = (
                "SELECT COUNT(*) FROM "  # noqa: S608
                f"{_qualified(database, table.name)} AS {child_alias} "
                f"WHERE {child_present} AND NOT EXISTS (SELECT 1 FROM "
                f"{_qualified(database, foreign_key.parent_table)} AS {parent_alias} "
                f"WHERE {relation})"
            )
            if _database_int(_query_scalar(connection, statement)) != 0:
                return False
    return True


def _column_contract(column: ColumnSpec) -> tuple[object, ...]:
    return (
        column.name,
        column.mysql_type.casefold(),
        column.nullable,
        column.max_length,
        column.precision,
        column.scale,
        column.unsigned,
        column.generated,
    )


def _raw_column_contract(column: _RawColumn) -> tuple[object, ...]:
    return (
        column.name,
        column.column_type.casefold(),
        column.nullable,
        column.max_length,
        column.precision,
        column.scale,
        column.unsigned,
        column.generated,
    )


def _stable_create_statement(statement: str) -> str:
    return re.sub(r"\bAUTO_INCREMENT=\d+\b", "AUTO_INCREMENT=<value>", statement)


def _schema_inventory(connection: Any, database: str) -> _SchemaInventory:
    if not (
        is_approved_staging_database(database)
        or is_approved_target_database(database)
    ):
        raise MaskingBoundaryError("inventory database is outside the target boundary")
    table_rows = _query_all(
        connection,
        "SELECT table_name, table_type FROM information_schema.tables "
        "WHERE table_schema = %s ORDER BY table_name",
        (database,),
    )
    base_tables: list[str] = []
    views: list[str] = []
    for row in table_rows:
        name = str(row[0])
        if not _IDENTIFIER.fullmatch(name):
            raise MaskingBoundaryError("target contains an unsupported object identifier")
        kind = str(row[1]).upper()
        if kind == "BASE TABLE":
            base_tables.append(name)
        elif kind == "VIEW":
            views.append(name)
        else:
            raise MaskingBoundaryError("target contains an unsupported table object")
    triggers = tuple(
        str(row[0])
        for row in _query_all(
            connection,
            "SELECT trigger_name FROM information_schema.triggers "
            "WHERE trigger_schema = %s ORDER BY trigger_name",
            (database,),
        )
    )
    routines = tuple(
        f"{row[1]}:{row[0]}"
        for row in _query_all(
            connection,
            "SELECT routine_name, routine_type FROM information_schema.routines "
            "WHERE routine_schema = %s ORDER BY routine_type, routine_name",
            (database,),
        )
    )
    events = tuple(
        str(row[0])
        for row in _query_all(
            connection,
            "SELECT event_name FROM information_schema.events "
            "WHERE event_schema = %s ORDER BY event_name",
            (database,),
        )
    )
    if any(
        not _IDENTIFIER.fullmatch(name)
        for name in (*triggers, *events, *(item.partition(":")[2] for item in routines))
    ):
        raise MaskingBoundaryError("target contains an unsupported object identifier")
    return _SchemaInventory(
        base_tables=tuple(sorted(base_tables)),
        views=tuple(sorted(views)),
        triggers=triggers,
        routines=routines,
        events=events,
    )


def _require_staging_cleanup_safe(
    connection: Any,
    database: str,
    inventory: _SchemaInventory,
    expected: DatabaseSnapshot,
) -> None:
    if not is_approved_staging_database(database):
        raise MaskingBoundaryError("staging database is outside the approved boundary")
    if any((inventory.views, inventory.triggers, inventory.routines, inventory.events)):
        raise MaskingBoundaryError("staging contains an object that cannot be cleaned safely")
    expected_by_name = {table.name: table for table in expected.tables}
    if not set(inventory.base_tables).issubset(expected_by_name):
        raise MaskingBoundaryError("staging contains a table outside the expected manifest")
    for table_name in inventory.base_tables:
        create_row = _query_one(
            connection,
            f"SHOW CREATE TABLE {_qualified(database, table_name)}",
        )
        if len(create_row) < 2 or not isinstance(create_row[1], str):
            raise MaskingBoundaryError("staging table DDL is unavailable")
        expected_create = expected_by_name[table_name].create_statement
        if expected_create is None or _stable_create_statement(
            _validate_create_statement(table_name, create_row[1])
        ) != _stable_create_statement(expected_create):
            raise MaskingBoundaryError("staging table differs from the expected manifest")


def _clean_staging_base_tables(
    connection: Any, database: str, expected: DatabaseSnapshot
) -> None:
    inventory = _schema_inventory(connection, database)
    _require_staging_cleanup_safe(connection, database, inventory, expected)
    if not inventory.base_tables:
        return
    tables = ", ".join(
        _qualified(database, table_name)
        for table_name in inventory.base_tables
    )
    _execute(connection, f"DROP TABLE {tables}")  # noqa: S608


def _acquire_publish_lock(connection: Any, lock_name: str) -> None:
    acquired = _query_scalar(connection, "SELECT GET_LOCK(%s, 0)", (lock_name,))
    if _database_int(acquired) != 1:
        raise MaskingBoundaryError("another local masking publish is active")


def _release_publish_lock(connection: Any, lock_name: str) -> None:
    try:
        _query_scalar(connection, "SELECT RELEASE_LOCK(%s)", (lock_name,))
    except Exception:
        LOGGER.debug("local masking publish lock released with its connection")


def _connection_identity_matches(connection: Any, database: str, username: str) -> bool:
    selected = str(_query_scalar(connection, "SELECT DATABASE()"))
    current_user = str(_query_scalar(connection, "SELECT CURRENT_USER()"))
    if selected != database or "@" not in current_user:
        return False
    actual_username, actual_host = current_user.rsplit("@", 1)
    return actual_username == username and actual_host in LOOPBACK_HOSTS


def _mysql_version_supported(connection: Any) -> bool:
    version = str(_query_scalar(connection, "SELECT VERSION()"))
    if "mariadb" in version.casefold():
        return False
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    return match is not None and tuple(int(part) for part in match.groups()) >= (8, 0, 13)


def _grants_match(
    grant_rows: list[tuple[object, ...]],
    database: str,
    expected_privileges: frozenset[str],
) -> bool:
    saw_usage = False
    saw_schema = False
    expected_scope = f"{_quote_identifier(database)}.*"
    for row in grant_rows:
        if len(row) != 1:
            return False
        statement = str(row[0]).strip()
        match = re.fullmatch(r"GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+.+", statement, re.I)
        if match is None or "WITH GRANT OPTION" in statement.upper():
            return False
        privileges = frozenset(item.strip().upper() for item in match.group(1).split(","))
        scope = match.group(2).strip()
        if scope == "*.*" and privileges == {"USAGE"} and not saw_usage:
            saw_usage = True
        elif scope == expected_scope and privileges == expected_privileges and not saw_schema:
            saw_schema = True
        else:
            return False
    return saw_usage and saw_schema


def _grants_match_scopes(
    grant_rows: list[tuple[object, ...]],
    expected: Mapping[str, frozenset[str]],
) -> bool:
    saw_usage = False
    remaining = dict(expected)
    for row in grant_rows:
        if len(row) != 1:
            return False
        statement = str(row[0]).strip()
        match = re.fullmatch(r"GRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+.+", statement, re.I)
        if match is None or "WITH GRANT OPTION" in statement.upper():
            return False
        privileges = frozenset(item.strip().upper() for item in match.group(1).split(","))
        scope = match.group(2).strip()
        if scope == "*.*" and privileges == {"USAGE"} and not saw_usage:
            saw_usage = True
            continue
        matching_database = next(
            (
                database
                for database in remaining
                if scope == f"`{database}`.*"
            ),
            None,
        )
        if matching_database is None or privileges != remaining[matching_database]:
            return False
        del remaining[matching_database]
    return saw_usage and not remaining


def _normalize_driver_value(value: object) -> MaskValue:
    if value is None or isinstance(
        value, (bool, int, float, Decimal, str, bytes, date, datetime, datetime_time)
    ):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, timedelta):
        seconds = value.total_seconds()
        if value.days < 0 or seconds >= 86_400 or not seconds.is_integer():
            raise MaskingBoundaryError("source time value is outside the reviewed subset")
        whole_seconds = int(seconds)
        return datetime_time(
            whole_seconds // 3600,
            (whole_seconds % 3600) // 60,
            whole_seconds % 60,
        )
    raise MaskingBoundaryError("source returned an unsupported value type")


def _database_int(value: object) -> int:
    if isinstance(value, bool):
        raise MaskingBoundaryError("database metadata integer is invalid")
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal) and value == value.to_integral_value():
        return int(value)
    raise MaskingBoundaryError("database metadata integer is invalid")


def _quote_identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise MaskingBoundaryError("database identifier is outside the approved subset")
    return f"`{value}`"


def _qualified(database: str, table: str) -> str:
    return f"{_quote_identifier(database)}.{_quote_identifier(table)}"


def _query_all(
    connection: Any,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> list[tuple[object, ...]]:
    cursor = connection.cursor()
    try:
        if parameters:
            cursor.execute(statement, parameters)
        else:
            cursor.execute(statement)
        return [tuple(row) for row in cursor.fetchall()]
    finally:
        cursor.close()


def _query_one(
    connection: Any,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> tuple[object, ...]:
    cursor = connection.cursor()
    try:
        if parameters:
            cursor.execute(statement, parameters)
        else:
            cursor.execute(statement)
        row = cursor.fetchone()
        if row is None:
            raise MaskingBoundaryError("database metadata query returned no row")
        return tuple(row)
    finally:
        cursor.close()


def _query_scalar(
    connection: Any,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> object:
    row = _query_one(connection, statement, parameters)
    if len(row) != 1:
        raise MaskingBoundaryError("database metadata query returned an invalid shape")
    return row[0]


def _execute(
    connection: Any,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    cursor = connection.cursor()
    try:
        if parameters:
            cursor.execute(statement, parameters)
        else:
            cursor.execute(statement)
    finally:
        cursor.close()


def _execute_many(
    connection: Any,
    statement: str,
    rows: tuple[tuple[MaskValue, ...], ...],
) -> None:
    cursor = connection.cursor()
    try:
        cursor.executemany(statement, rows)
    finally:
        cursor.close()


def _start_source_transaction(connection: Any) -> None:
    connection.start_transaction(
        consistent_snapshot=True,
        isolation_level="REPEATABLE READ",
        readonly=True,
    )


def _rollback_and_close(connection: Any) -> None:
    try:
        connection.rollback()
    finally:
        connection.close()


def _best_effort_enable_foreign_keys(connection: Any) -> None:
    try:
        _execute(connection, "SET SESSION FOREIGN_KEY_CHECKS = 1")
    except Exception:
        LOGGER.warning("failed to restore session foreign-key checks during rollback")


def _default_mysql_connect(**kwargs: object) -> Any:
    try:
        connector = importlib.import_module("mysql.connector")
    except ImportError as exc:
        raise MaskingBoundaryError("local MySQL driver is unavailable") from exc
    return connector.connect(**kwargs)


def _row_counts(snapshot: DatabaseSnapshot) -> tuple[tuple[str, int], ...]:
    return tuple(sorted((table.name, len(table.rows)) for table in snapshot.tables))


def _safe_error(error: Exception) -> str:
    if isinstance(error, MaskingBoundaryError):
        return "local masking safety validation failed"
    return "local masking copy failed closed"


def _operation_key(operation: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((operation, *parts)).encode()).hexdigest()
    return f"local-masker-{operation}-{digest[:32]}"


async def _run(settings: MaskerSettings) -> None:
    source_credential = load_local_credential(
        settings.source_secret_file, expected_username=SOURCE_USERNAME
    )
    target_credential = load_local_credential(
        settings.target_secret_file, expected_username=TARGET_USERNAME
    )
    master_key = load_masking_key(settings.key_file)
    source = MySqlSourceReader(
        host=settings.host,
        port=settings.port,
        credential=source_credential,
    )
    async with LocalMaskingApiClient(
        api_url=settings.api_url,
        collector_id=settings.collector_id,
        tenant_id=settings.tenant_id,
    ) as api:
        ready_event = asyncio.Event()
        while not await api.ready():
            try:
                await asyncio.wait_for(ready_event.wait(), timeout=settings.poll_seconds)
            except TimeoutError:
                continue
        worker = LocalMaskingWorker(
            settings=settings,
            api=api,
            source=source,
            target=None,
            master_key=master_key,
            target_factory=lambda database: MySqlTargetWriter(
                host=settings.host,
                port=settings.port,
                credential=target_credential,
                target_database=database,
            ),
        )
        await worker.run_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dedicated bounded worker for one approved local MySQL masked copy."
    )
    parser.add_argument("command", choices=("run", "self-check"), nargs="?", default="run")
    args = parser.parse_args()
    if args.command == "self-check":
        validate_local_boundary("127.0.0.1", SOURCE_DATABASE, TARGET_DATABASE)
        print(
            json.dumps(
                {
                    "source_database": SOURCE_DATABASE,
                    "target_database": TARGET_DATABASE,
                    "row_cap": ROW_CAP,
                    "status": "boundary-ok",
                },
                separators=(",", ":"),
            )
        )
        return
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    settings = MaskerSettings.from_environment()
    try:
        asyncio.run(_run(settings))
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
