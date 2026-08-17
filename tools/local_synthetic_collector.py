from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Self
from urllib.parse import unquote, urlsplit

import httpx
from pydantic import Field, ValidationError, model_validator

from assurance_hub.models import WorkStatus
from assurance_hub.schemas import (
    CollectorLeaseOut,
    HeartbeatRequest,
    HeartbeatResponse,
    JobCompletionRequest,
    JobLeaseRequest,
    JobResult,
    JsonScalar,
    ProbeExecutionResult,
    ScanJobOut,
    StrictModel,
)

logger = logging.getLogger("assurance.local_synthetic_collection")

LAUNCH_SOURCE = "npm-dev-integrated-v1"
DEMO_TENANT_ID = "demo-enterprise"
DEMO_COLLECTOR_ID = "demo-collector"
SQLITE_PREFIX = "sqlite+aiosqlite:///"
MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024
SYNTHETIC_COLLECTOR_VERSION = "local-synthetic-1.0"


class LocalSyntheticSettings(StrictModel):
    """Fail-closed configuration for the disposable local collection helper."""

    launch_source: Literal["npm-dev-integrated-v1"]
    api_base_url: str
    api_directory: Path
    database_url: str
    environment: Literal["development"]
    auth_mode: Literal["development"]
    allow_insecure_dev_auth: Literal[True]
    tenant_id: Literal["demo-enterprise"]
    collector_id: Literal["demo-collector"]
    poll_seconds: float = Field(default=2.0, ge=1.0, le=5.0)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> LocalSyntheticSettings:
        def required(name: str) -> str:
            value = environment.get(name, "").strip()
            if not value:
                raise ValueError(f"{name} is required by the integrated launcher")
            return value

        insecure_auth = required("ALLOW_INSECURE_DEV_AUTH")
        if insecure_auth != "true":
            raise ValueError("ALLOW_INSECURE_DEV_AUTH must be exactly 'true'")
        return cls(
            launch_source=required("LOCAL_SYNTHETIC_LAUNCH_SOURCE"),
            api_base_url=required("LOCAL_SYNTHETIC_API_BASE_URL"),
            api_directory=Path(required("LOCAL_SYNTHETIC_API_DIRECTORY")),
            database_url=required("LOCAL_SYNTHETIC_DATABASE_URL"),
            environment=required("ENVIRONMENT"),
            auth_mode=required("AUTH_MODE"),
            allow_insecure_dev_auth=True,
            tenant_id=required("LOCAL_SYNTHETIC_TENANT_ID"),
            collector_id=required("LOCAL_SYNTHETIC_COLLECTOR_ID"),
        )

    @model_validator(mode="after")
    def validate_local_boundary(self) -> Self:
        parsed = urlsplit(self.api_base_url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("synthetic API port is invalid") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or port is None
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("synthetic collection requires an uncredentialed loopback API")

        expected_api_directory = (
            Path(__file__).resolve().parents[1] / "services" / "api"
        ).resolve()
        api_directory = self.api_directory.resolve()
        if api_directory != expected_api_directory:
            raise ValueError("synthetic collection API directory must be this repository")
        database_path = resolve_local_sqlite_path(self.database_url, api_directory)
        if not database_path.is_relative_to(api_directory):
            raise ValueError("synthetic collection database escaped services/api")
        return self


def resolve_local_sqlite_path(database_url: str, api_directory: Path) -> Path:
    if not database_url.startswith(SQLITE_PREFIX) or "?" in database_url or "#" in database_url:
        raise ValueError("synthetic collection requires sqlite+aiosqlite")
    reference = unquote(database_url.removeprefix(SQLITE_PREFIX))
    if not reference or reference == ":memory:" or any(char in reference for char in "\0\r\n"):
        raise ValueError("synthetic collection requires a file-backed SQLite database")
    candidate = Path(reference)
    database_path = (
        candidate.resolve() if candidate.is_absolute() else (api_directory / candidate).resolve()
    )
    if database_path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise ValueError("synthetic collection requires a SQLite database file")
    if not database_path.is_relative_to(api_directory):
        raise ValueError("synthetic collection SQLite data must remain inside services/api")
    return database_path


_SYNTHETIC_OBSERVATIONS: Mapping[str, tuple[dict[str, JsonScalar], ...]] = MappingProxyType(
    {
        "oracle.version": ({"banner": "Oracle Database synthetic development fixture"},),
        "oracle.tablespace_encryption": ({"tablespace_name": "AEGISDB_DEMO", "encrypted": "YES"},),
        "oracle.account_posture": (
            {
                "username": "AEGISDB_DEMO_READER",
                "account_status": "OPEN",
                "authentication_type": "PASSWORD",
                "profile": "DEFAULT",
            },
        ),
        "oracle.unified_auditing": ({"parameter": "Unified Auditing", "value": "TRUE"},),
        "postgresql.version": ({"version": "PostgreSQL synthetic development fixture"},),
        "postgresql.tls_sessions": (
            {
                "ssl": True,
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "bits": 256,
            },
        ),
        "postgresql.role_posture": (
            {
                "rolname": "aegisdb_demo_reader",
                "rolsuper": False,
                "rolcreaterole": False,
                "rolcreatedb": False,
                "rolcanlogin": True,
            },
        ),
        "postgresql.row_security": (
            {
                "nspname": "aegisdb_demo",
                "relname": "protected_records",
                "relrowsecurity": True,
                "relforcerowsecurity": True,
            },
        ),
        "sybase.version": ({"version": "SAP ASE synthetic development fixture"},),
        "sybase.login_posture": (
            {
                "name": "aegisdb_demo_reader",
                "suid": 1001,
                "status": 0,
                "fullname": "Synthetic read-only principal",
            },
        ),
        "sybase.audit_configuration": ({"name": "auditing", "value": 1},),
    }
)


def synthetic_probe_result(probe_id: str) -> ProbeExecutionResult:
    """Create deterministic, bounded metadata evidence without a database query."""
    try:
        source = _SYNTHETIC_OBSERVATIONS[probe_id]
    except KeyError as exc:
        raise ValueError(
            f"no approved local synthetic evidence exists for probe '{probe_id}'"
        ) from exc
    observations = [dict(item) for item in source]
    canonical = json.dumps(
        observations,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return ProbeExecutionResult(
        probe_id=probe_id,
        outcome="collected",
        duration_ms=0,
        row_count=len(observations),
        evidence_sha256=hashlib.sha256(canonical).hexdigest(),
        observations=observations,
        message="Development-only synthetic metadata; no customer database was queried.",
    )


def completion_for(job: CollectorLeaseOut) -> JobCompletionRequest:
    results = [synthetic_probe_result(probe_id) for probe_id in job.payload.probe_ids]
    return JobCompletionRequest(
        collector_id=DEMO_COLLECTOR_ID,
        lease_token=job.lease_token,
        success=True,
        result=JobResult(
            probe_results=results,
            summary={
                "collector_version": SYNTHETIC_COLLECTOR_VERSION,
                "evidence_origin": "development_synthetic",
                "customer_database_queried": False,
            },
        ),
        error=None,
    )


class LocalSyntheticApiClient:
    def __init__(
        self,
        settings: LocalSyntheticSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.api_base_url,
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            transport=transport,
        )

    async def __aenter__(self) -> LocalSyntheticApiClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._client.aclose()

    async def heartbeat(self) -> int:
        payload = HeartbeatRequest(
            collector_id=self._settings.collector_id,
            version=SYNTHETIC_COLLECTOR_VERSION,
            capabilities=["control_assessment", "development_synthetic_metadata"],
        )
        response = await self._exact_mutation(
            "/api/v1/collectors/heartbeat",
            operation_key("heartbeat", str(int(time.time() / 10))),
            payload.model_dump(mode="json"),
        )
        response.raise_for_status()
        accepted = HeartbeatResponse.model_validate(response.json())
        if not accepted.accepted:
            raise RuntimeError("synthetic collector heartbeat was not accepted")
        return accepted.next_heartbeat_seconds

    async def lease(self) -> CollectorLeaseOut | None:
        payload = JobLeaseRequest(
            collector_id=self._settings.collector_id,
            supported_job_types=["control_assessment"],
        )
        response = await self._exact_mutation(
            "/api/v1/scan-jobs/lease",
            operation_key("lease", str(uuid.uuid4())),
            payload.model_dump(mode="json"),
        )
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return CollectorLeaseOut.model_validate(response.json())

    async def complete(self, job: CollectorLeaseOut) -> None:
        payload = completion_for(job)
        response = await self._exact_mutation(
            f"/api/v1/scan-jobs/{job.id}/complete",
            operation_key("complete", job.id, job.lease_token),
            payload.model_dump(mode="json"),
        )
        response.raise_for_status()
        completed = ScanJobOut.model_validate(response.json())
        if completed.id != job.id or completed.status != WorkStatus.SUCCEEDED:
            raise RuntimeError("synthetic completion acknowledgement did not match the leased job")

    async def _exact_mutation(
        self,
        path: str,
        idempotency_key: str,
        body: object,
        attempts: int = 3,
    ) -> httpx.Response:
        for attempt in range(1, attempts + 1):
            try:
                response = await self._request(path, idempotency_key, body)
            except httpx.TransportError:
                if attempt == attempts:
                    raise
                await asyncio.sleep(0.1 * 2 ** (attempt - 1))
                continue
            if response.status_code >= 500 and attempt < attempts:
                await asyncio.sleep(0.1 * 2 ** (attempt - 1))
                continue
            return response
        raise AssertionError("exact mutation retry loop must return or raise")

    async def _request(self, path: str, idempotency_key: str, body: object) -> httpx.Response:
        response = await self._client.post(
            path,
            headers={
                "X-Tenant-ID": self._settings.tenant_id,
                "X-Subject": self._settings.collector_id,
                "X-Roles": "collector",
                "Idempotency-Key": idempotency_key,
            },
            json=body,
        )
        if 300 <= response.status_code < 400:
            raise RuntimeError("synthetic collector API returned an unsafe redirect")
        if len(response.content) > MAX_API_RESPONSE_BYTES:
            raise RuntimeError("synthetic collector API response exceeded 2 MiB")
        return response


def operation_key(operation: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((operation, *parts)).encode()).hexdigest()
    return f"local-synthetic-{operation}-{digest[:32]}"


async def run(settings: LocalSyntheticSettings) -> None:
    logger.warning(
        "Synthetic local collection active — no customer database queried",
        extra={
            "event": "local_synthetic_collection.started",
            "tenant_id": settings.tenant_id,
            "collector_id": settings.collector_id,
        },
    )
    async with LocalSyntheticApiClient(settings) as api:
        next_heartbeat_at = 0.0
        while True:
            try:
                now = time.monotonic()
                if now >= next_heartbeat_at:
                    heartbeat_seconds = await api.heartbeat()
                    next_heartbeat_at = now + max(10, heartbeat_seconds)
                job = await api.lease()
                if job is None:
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                await api.complete(job)
                logger.info(
                    "synthetic metadata collection completed for analyst review",
                    extra={
                        "event": "local_synthetic_collection.completed",
                        "job_id": job.id,
                        "assessment_id": job.assessment_id,
                        "probe_count": len(job.payload.probe_ids),
                    },
                )
            except httpx.TransportError as exc:
                logger.warning(
                    "local API temporarily unavailable",
                    extra={
                        "event": "local_synthetic_collection.api_unavailable",
                        "error_type": type(exc).__name__,
                    },
                )
                await asyncio.sleep(1.0)
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                if status_code >= 500:
                    logger.warning(
                        "local API temporarily rejected synthetic collection",
                        extra={
                            "event": "local_synthetic_collection.api_unavailable",
                            "status_code": status_code,
                        },
                    )
                    await asyncio.sleep(1.0)
                    continue
                raise RuntimeError(
                    f"local synthetic collection contract was rejected with HTTP {status_code}"
                ) from exc


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        settings = LocalSyntheticSettings.from_environment(os.environ)
        asyncio.run(run(settings))
    except (ValidationError, ValueError, RuntimeError) as exc:
        logger.error(
            "local synthetic collection stopped safely",
            extra={
                "event": "local_synthetic_collection.startup_failed",
                "error_type": type(exc).__name__,
            },
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
