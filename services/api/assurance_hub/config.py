from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import parse_qs, unquote, urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    service_name: str = "database-security-assurance-api"
    service_version: str = "0.1.0"
    environment: Literal["development", "test", "staging", "production"] = "production"
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    database_url: str = "postgresql+asyncpg://assurance:change-me@localhost:5432/assurance"
    # Use a separately credentialed role for bounded reconciliation. The request
    # path never receives this engine, limiting the blast radius of BYPASSRLS.
    database_maintenance_url: str | None = None
    database_pool_size: int = Field(default=10, ge=1, le=100)
    database_max_overflow: int = Field(default=20, ge=0, le=200)
    cors_origins: list[str] = Field(default_factory=list)

    auth_mode: Literal["oidc", "development"] = "oidc"
    allow_insecure_dev_auth: bool = False
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "roles"

    idempotency_ttl_hours: int = Field(default=24, ge=1, le=168)
    job_reconcile_interval_seconds: int = Field(default=30, ge=5, le=3600)
    job_reconcile_batch_size: int = Field(default=100, ge=1, le=1000)
    job_lease_seconds: int = Field(default=120, ge=15, le=3600)
    outbox_lease_seconds: int = Field(default=120, ge=15, le=3600)
    collector_max_attempts: int = Field(default=5, ge=1, le=20)
    otel_exporter_otlp_endpoint: str | None = None
    enable_metrics: bool = True
    seed_demo_data: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def dev_auth_enabled(self) -> bool:
        return (
            self.auth_mode == "development"
            and self.allow_insecure_dev_auth
            and self.environment in {"development", "test"}
        )

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_url)

    def validate_runtime(self) -> None:
        """Fail closed when a deployed environment has insecure or incomplete settings."""
        if self.environment not in {"staging", "production"}:
            return
        errors: list[str] = []
        if self.auth_mode != "oidc" or not self.oidc_configured:
            errors.append("complete OIDC issuer, audience, and JWKS configuration is required")
        for name, value in {
            "OIDC issuer": self.oidc_issuer,
            "OIDC JWKS URL": self.oidc_jwks_url,
        }.items():
            if value:
                parsed = urlparse(value)
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.fragment
                ):
                    errors.append(f"{name} must be an HTTPS URL without credentials or fragments")
        if self.allow_insecure_dev_auth:
            errors.append("development authentication must be disabled")
        if self.database_url.startswith("sqlite"):
            errors.append("PostgreSQL persistence is required")
        if "change-me" in self.database_url:
            errors.append("default database credentials are forbidden")
        request_database_identity = _postgresql_connection_identity(self.database_url)
        if request_database_identity is None:
            errors.append(
                "the request database must be a PostgreSQL URL with a host, database, and username"
            )
        if not _requires_postgresql_tls(self.database_url):
            errors.append("PostgreSQL transport encryption must be required")
        if not self.database_maintenance_url:
            errors.append("a distinct maintenance PostgreSQL URL is required")
        else:
            if self.database_maintenance_url == self.database_url:
                errors.append(
                    "the maintenance PostgreSQL URL must be distinct from the request URL"
                )
            if self.database_maintenance_url.startswith("sqlite"):
                errors.append("the maintenance database must use PostgreSQL")
            maintenance_database_identity = _postgresql_connection_identity(
                self.database_maintenance_url
            )
            if maintenance_database_identity is None:
                errors.append(
                    "the maintenance database must be a PostgreSQL URL with a host, "
                    "database, and username"
                )
            elif (
                request_database_identity is not None
                and maintenance_database_identity == request_database_identity
            ):
                errors.append(
                    "the maintenance PostgreSQL username must differ from the request username"
                )
            if not _requires_postgresql_tls(self.database_maintenance_url):
                errors.append("maintenance PostgreSQL transport encryption must be required")
        if errors:
            raise RuntimeError("invalid production configuration: " + "; ".join(errors))


@lru_cache
def get_settings() -> Settings:
    return Settings()


def _requires_postgresql_tls(value: str) -> bool:
    """Accept only PostgreSQL TLS modes that cannot silently downgrade."""
    parsed = urlparse(value)
    query = parse_qs(parsed.query, keep_blank_values=True)
    accepted_modes = {"require", "verify-ca", "verify-full"}
    modes = [mode for key in ("ssl", "sslmode") for mode in query.get(key, [])]
    return len(modes) == 1 and modes[0].lower() in accepted_modes


def _postgresql_connection_identity(value: str) -> str | None:
    """Return the decoded role name only for a structurally valid PostgreSQL URL."""
    try:
        parsed = urlparse(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"postgresql", "postgresql+asyncpg"}
        or not parsed.hostname
        or not parsed.username
        or parsed.path in {"", "/"}
        or parsed.fragment
    ):
        return None
    username = unquote(parsed.username).strip()
    return username or None
