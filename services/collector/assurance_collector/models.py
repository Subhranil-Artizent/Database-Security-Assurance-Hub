from __future__ import annotations

import re
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

SafeIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
    ),
]
ProbeIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9_.-]{3,100}$"),
]
JsonScalar = str | int | float | bool | None


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Platform(StrEnum):
    ORACLE = "oracle"
    POSTGRESQL = "postgresql"
    SYBASE = "sybase"
    MYSQL = "mysql"


class CollectorSettings(BaseSettings):
    """Strict, bounded collector configuration loaded from COLLECTOR_* values."""

    model_config = SettingsConfigDict(
        env_prefix="COLLECTOR_",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "test", "staging", "production"] = "production"
    api_url: str = "https://assurance-api.example.invalid"
    collector_id: SafeIdentifier
    tenant_id: SafeIdentifier
    token_file: Path | None = None
    credential_root: Path = Path("/var/run/secrets/assurance-sources")
    liveness_file: Path = Path("/tmp/assurance-collector-live")  # noqa: S108
    enable_leasing: bool = False
    poll_seconds: float = Field(default=5.0, ge=0.25, le=300)
    heartbeat_seconds: int = Field(default=30, ge=10, le=3600)
    lease_renew_seconds: int = Field(default=30, ge=5, le=600)
    connect_timeout_seconds: int = Field(default=10, ge=1, le=60)
    statement_timeout_seconds: int = Field(default=15, ge=1, le=300)
    max_rows: int = Field(default=100, ge=1, le=100)
    max_payload_bytes: int = Field(default=131_072, ge=1024, le=131_072)
    max_parallel_jobs: int = Field(default=2, ge=1, le=32)
    source_retry_attempts: int = Field(default=3, ge=1, le=5)
    source_retry_base_seconds: float = Field(default=0.25, ge=0.01, le=10)
    source_retry_max_seconds: float = Field(default=2.0, ge=0.05, le=30)
    circuit_failure_threshold: int = Field(default=3, ge=2, le=20)
    circuit_recovery_seconds: float = Field(default=60, ge=5, le=3600)
    metrics_host: Literal["127.0.0.1", "0.0.0.0"] = "127.0.0.1"  # noqa: S104
    metrics_port: int = Field(default=9464, ge=1024, le=65535)
    sybase_odbc_driver: str = Field(default="SAP ASE ODBC Driver", min_length=1, max_length=120)

    @model_validator(mode="after")
    def validate_runtime(self) -> CollectorSettings:
        parsed = urlsplit(self.api_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("api_url must be an absolute HTTP(S) URL without credentials")
        if self.environment in {"staging", "production"}:
            if parsed.scheme != "https":
                raise ValueError("staging and production API transport must use HTTPS")
            if self.token_file is None:
                raise ValueError("a projected short-lived token_file is required")
            if parsed.hostname.endswith(".invalid"):
                raise ValueError("staging and production require a real API hostname")
        if self.lease_renew_seconds >= self.heartbeat_seconds * 4:
            raise ValueError("lease renewal cadence is too slow for the heartbeat policy")
        if self.source_retry_base_seconds > self.source_retry_max_seconds:
            raise ValueError("source retry base delay cannot exceed its maximum delay")
        return self


class SourceCredential(StrictModel):
    username: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    password: SecretStr
    ca_file: Path | None
    client_certificate_file: Path | None = None
    client_key_file: Path | None = None
    wallet_directory: Path | None = None


class DatabaseEndpoint(StrictModel):
    host: Annotated[str, StringConstraints(min_length=1, max_length=253)]
    port: int = Field(ge=1, le=65535)
    database: Annotated[str, StringConstraints(min_length=1, max_length=128)]

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value):
            raise ValueError("endpoint host is not a valid DNS name or address alias")
        return value.lower()

    @classmethod
    def from_reference(cls, reference: str) -> DatabaseEndpoint:
        parsed = urlsplit(reference)
        if (
            parsed.scheme != "dns"
            or not parsed.hostname
            or parsed.port is None
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "runtime endpoint must be dns://host:port/database without credentials"
            )
        database = unquote(parsed.path.lstrip("/"))
        if any(character in database for character in ";{}\0\r\n"):
            raise ValueError("endpoint database contains forbidden connection-string characters")
        return cls(host=parsed.hostname, port=parsed.port, database=database)


class RuntimeConnector(StrictModel):
    connector_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]
    platform: Platform
    endpoint_ref: Annotated[str, StringConstraints(min_length=8, max_length=512)]
    secret_ref: Annotated[str, StringConstraints(min_length=8, max_length=1024)]
    enabled: StrictBool = True

    @field_validator("secret_ref")
    @classmethod
    def validate_secret_reference(cls, value: str) -> str:
        allowed = (
            "vault://",
            "azure-key-vault://",
            "aws-secrets-manager://",
            "gcp-secret-manager://",
            "cyberark://",
        )
        if not value.startswith(allowed) or any(char in value for char in "\r\n\0"):
            raise ValueError("secret_ref must use an approved enterprise secret provider")
        return value

    def endpoint(self) -> DatabaseEndpoint:
        return DatabaseEndpoint.from_reference(self.endpoint_ref)


class ProbeSpec(StrictModel):
    probe_id: ProbeIdentifier
    platform: Platform
    domain: Literal["inventory", "encryption", "data_protection", "access_security"]
    sql: Annotated[str, StringConstraints(min_length=6, max_length=4000)]
    allowed_fields: frozenset[Annotated[str, StringConstraints(min_length=1, max_length=128)]]

    @field_validator("sql")
    @classmethod
    def enforce_read_only_statement(cls, value: str) -> str:
        normalized = value.strip()
        lowered = normalized.lower()
        forbidden = (
            ";",
            "--",
            "/*",
            " insert ",
            " update ",
            " delete ",
            " merge ",
            " alter ",
            " create ",
            " drop ",
            " grant ",
            " revoke ",
            " execute ",
            " call ",
        )
        padded = f" {lowered} "
        if not lowered.startswith(("select ", "with ")) or any(
            token in padded for token in forbidden
        ):
            raise ValueError("probe catalogue permits one read-only SELECT statement")
        return normalized


class ExecutionLimits(StrictModel):
    connect_timeout_seconds: int = Field(ge=1, le=60)
    statement_timeout_seconds: int = Field(ge=1, le=300)
    max_rows: int = Field(ge=1, le=100)
    max_payload_bytes: int = Field(ge=1024, le=131_072)


class ResiliencePolicy(StrictModel):
    retry_attempts: int = Field(ge=1, le=5)
    retry_base_seconds: float = Field(ge=0.01, le=10)
    retry_max_seconds: float = Field(ge=0.05, le=30)
    circuit_failure_threshold: int = Field(ge=2, le=20)
    circuit_recovery_seconds: float = Field(ge=5, le=3600)


class CollectedEvidence(StrictModel):
    probe_id: ProbeIdentifier
    row_count: int = Field(ge=0, le=100)
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
    observations: list[dict[str, JsonScalar]] = Field(max_length=100)
    duration_ms: int = Field(ge=0, le=600_000)


def normalize_scalar(value: object) -> JsonScalar:
    """Convert driver values to a bounded, deterministic evidence scalar."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("non-finite numbers are forbidden in evidence")
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        aware = value if value.tzinfo else value.replace(tzinfo=UTC)
        return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, str):
        if len(value) > 512 or any(character in value for character in "\0"):
            raise ValueError("evidence string is invalid or exceeds 512 characters")
        return value
    if isinstance(value, bytes):
        raise ValueError("binary source values are not permitted as evidence")
    text = str(value)
    if len(text) > 512:
        raise ValueError("evidence value exceeds 512 characters")
    return text
