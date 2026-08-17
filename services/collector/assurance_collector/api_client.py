from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import Field, StrictInt, StringConstraints, field_validator, model_validator

from .models import JsonScalar, Platform, ProbeIdentifier, RuntimeConnector, StrictModel

ResourceId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]
LeaseToken = Annotated[str, StringConstraints(pattern=r"^[a-f0-9-]{36}$")]


class ScanJobPayload(StrictModel):
    probe_ids: list[ProbeIdentifier] = Field(min_length=1, max_length=100)
    schemas: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, JsonScalar] = Field(default_factory=dict)

    @field_validator("probe_ids")
    @classmethod
    def unique_probes(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("probe IDs must be unique")
        return value


class LeasedJob(StrictModel):
    id: ResourceId
    connector_id: ResourceId
    assessment_id: ResourceId | None = None
    job_type: Literal["inventory", "control_assessment", "access_review", "classification"]
    status: Literal["leased", "running"]
    payload: ScanJobPayload
    lease_token: LeaseToken
    lease_expires_at: datetime
    attempts: StrictInt = Field(ge=1, le=20)
    max_attempts: StrictInt = Field(ge=1, le=20)


class ProbeResultSubmission(StrictModel):
    probe_id: ProbeIdentifier
    outcome: Literal[
        "collected",
        "error",
        "not_applicable",
        "unsupported",
        "insufficient_privilege",
    ]
    duration_ms: StrictInt = Field(ge=0, le=600_000)
    row_count: StrictInt = Field(ge=0, le=100)
    evidence_sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")] | None = None
    message: Annotated[str, StringConstraints(max_length=1000)] | None = None
    observations: list[dict[str, JsonScalar]] = Field(default_factory=list, max_length=100)

    @field_validator("observations")
    @classmethod
    def bounded_observations(
        cls, value: list[dict[str, JsonScalar]]
    ) -> list[dict[str, JsonScalar]]:
        for observation in value:
            if len(observation) > 25:
                raise ValueError("an observation cannot contain more than 25 scalar fields")
            for key, item in observation.items():
                if len(key) > 100 or (isinstance(item, str) and len(item) > 512):
                    raise ValueError("observation fields exceed the approved evidence boundary")
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(encoded) > 128 * 1024:
            raise ValueError("observations cannot exceed 128 KiB")
        return value

    @model_validator(mode="after")
    def structurally_consistent(self) -> ProbeResultSubmission:
        if self.row_count != len(self.observations):
            raise ValueError("row_count must equal the number of observations")
        if self.outcome == "collected":
            if self.evidence_sha256 is None:
                raise ValueError("collected evidence requires evidence_sha256")
        elif self.row_count or self.observations or self.evidence_sha256 is not None:
            raise ValueError("non-collected outcomes cannot include collected evidence")
        return self


class RuntimeConnectorEnvelope(StrictModel):
    schema_version: Literal["1.0"]
    connector_id: ResourceId = Field(validation_alias="connector_id")
    platform: Literal["oracle", "postgresql", "sybase", "mysql"]
    endpoint_ref: str
    secret_ref: str
    config: dict[str, JsonScalar] = Field(default_factory=dict)
    updated_at: datetime

    @field_validator("config")
    @classmethod
    def strict_kill_switch(cls, value: dict[str, JsonScalar]) -> dict[str, JsonScalar]:
        if "enabled" in value and not isinstance(value["enabled"], bool):
            raise ValueError("connector enabled must be a JSON boolean")
        return value

    def to_runtime_connector(self) -> RuntimeConnector:
        return RuntimeConnector(
            connector_id=self.connector_id,
            platform=Platform(self.platform),
            endpoint_ref=self.endpoint_ref,
            secret_ref=self.secret_ref,
            enabled=self.config.get("enabled", True) is not False,
        )

    @classmethod
    def model_validate_api(cls, value: object) -> RuntimeConnectorEnvelope:
        if isinstance(value, dict) and "connector_id" not in value and "id" in value:
            value = {**value, "connector_id": value["id"]}
        return cls.model_validate(value)


class CollectorReadyEnvelope(StrictModel):
    status: Literal["ok"]
    collector_id: Annotated[str, StringConstraints(min_length=1, max_length=160)]


class AssuranceApiClient:
    def __init__(
        self,
        *,
        api_url: str,
        collector_id: str,
        tenant_id: str,
        token_file: Path | None,
        environment: str,
        timeout_seconds: float = 15,
    ) -> None:
        self._collector_id = collector_id
        self._tenant_id = tenant_id
        self._token_file = token_file
        self._environment = environment
        self._client = httpx.AsyncClient(
            base_url=api_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )

    async def __aenter__(self) -> AssuranceApiClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._client.aclose()

    async def ready(self) -> bool:
        try:
            response = await self._request("GET", "/api/v1/collectors/ready")
            response.raise_for_status()
            ready = CollectorReadyEnvelope.model_validate(response.json())
            return ready.collector_id == self._collector_id
        except (httpx.HTTPError, ValueError):
            return False

    async def heartbeat(self, heartbeat_seconds: int) -> None:
        response = await self._request(
            "POST",
            "/api/v1/collectors/heartbeat",
            operation_key(
                "heartbeat",
                self._collector_id,
                str(int(time.time() / heartbeat_seconds)),
            ),
            json={
                "collector_id": self._collector_id,
                "version": "0.1.0",
                "capabilities": [
                    "inventory",
                    "control_assessment",
                    "access_review",
                    "classification",
                ],
            },
        )
        response.raise_for_status()

    async def lease(self, poll_seconds: float) -> LeasedJob | None:
        _ = poll_seconds
        response = await self._exact_mutation(
            "/api/v1/scan-jobs/lease",
            operation_key("lease", self._collector_id, str(uuid.uuid4())),
            {
                "collector_id": self._collector_id,
                "supported_job_types": [
                    "inventory",
                    "control_assessment",
                    "access_review",
                    "classification",
                ],
            },
        )
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return LeasedJob.model_validate(response.json())

    async def runtime_connector(self, connector_id: str) -> RuntimeConnector:
        response = await self._request(
            "GET",
            f"/api/v1/collectors/connectors/{connector_id}/runtime-config",
        )
        response.raise_for_status()
        return RuntimeConnectorEnvelope.model_validate_api(response.json()).to_runtime_connector()

    async def renew(self, job: LeasedJob) -> datetime:
        response = await self._request(
            "POST",
            f"/api/v1/scan-jobs/{job.id}/renew",
            operation_key("renew", job.id, job.lease_token, str(int(time.time() / 5))),
            json={"collector_id": self._collector_id, "lease_token": job.lease_token},
        )
        response.raise_for_status()
        renewed = LeasedJob.model_validate(response.json())
        if renewed.id != job.id or renewed.lease_token != job.lease_token:
            raise RuntimeError("lease renewal response does not match the active fence")
        return renewed.lease_expires_at

    async def complete(
        self,
        job: LeasedJob,
        *,
        success: bool,
        results: list[ProbeResultSubmission] | None = None,
        error: str | None = None,
    ) -> None:
        body = {
            "collector_id": self._collector_id,
            "lease_token": job.lease_token,
            "success": success,
            "result": {
                "probe_results": [item.model_dump(mode="json") for item in results or []],
                "summary": {"collector_version": "0.1.0"},
            },
            "error": error,
        }
        response = await self._exact_mutation(
            f"/api/v1/scan-jobs/{job.id}/complete",
            operation_key("complete", job.id, job.lease_token),
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
                response = await self._request(
                    "POST",
                    path,
                    idempotency_key,
                    json=body,
                )
            except httpx.TransportError:
                if attempt == attempts:
                    raise
                await asyncio.sleep(0.1 * 2 ** (attempt - 1))
                continue
            if response.status_code >= 500 and attempt < attempts:
                await asyncio.sleep(0.1 * 2 ** (attempt - 1))
                continue
            return response
        raise AssertionError("completion retry loop must return or raise")

    async def _request(
        self,
        method: str,
        path: str,
        idempotency_key: str | None = None,
        json: object | None = None,
    ) -> httpx.Response:
        headers = await self._headers()
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return await self._client.request(method, path, headers=headers, json=json)

    async def _headers(self) -> dict[str, str]:
        if self._token_file is not None:
            token = await asyncio.to_thread(read_projected_token, self._token_file)
            return {"Authorization": f"Bearer {token}"}
        if self._environment in {"development", "test"}:
            return {
                "X-Tenant-ID": self._tenant_id,
                "X-Subject": self._collector_id,
                "X-Roles": "collector",
            }
        raise RuntimeError("collector token is not configured")


def read_projected_token(path: Path) -> str:
    try:
        if path.stat().st_size > 16_384:
            raise RuntimeError("projected collector token exceeds 16 KiB")
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError("projected collector token is unavailable") from exc
    if not token or any(character.isspace() for character in token):
        raise RuntimeError("projected collector token is invalid")
    return token


def operation_key(operation: str, *parts: str) -> str:
    digest = hashlib.sha256("\0".join((operation, *parts)).encode()).hexdigest()
    return f"collector-{operation}-{digest[:32]}"
