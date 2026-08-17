from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from assurance_collector.adapters import QueryBoundaryError
from assurance_collector.api_client import (
    AssuranceApiClient,
    LeasedJob,
    ProbeResultSubmission,
    RuntimeConnectorEnvelope,
    operation_key,
    read_projected_token,
)
from assurance_collector.secrets import SecretResolutionError
from assurance_collector.worker import local_liveness, safe_error_message


def test_operation_keys_are_stable_and_do_not_expose_inputs() -> None:
    first = operation_key("complete", "job-one", "lease-one")
    second = operation_key("complete", "job-one", "lease-one")
    assert first == second
    assert len(first) < 128
    assert "job-one" not in first
    assert operation_key("complete", "job-one", "lease-two") != first


def test_projected_token_validation(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("header.payload.signature\n", encoding="utf-8")
    assert read_projected_token(token_file) == "header.payload.signature"
    token_file.write_text("not a token", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid"):
        read_projected_token(token_file)


def test_error_messages_do_not_echo_exception_details() -> None:
    secret = SecretResolutionError("vault path failed with sensitive password material")
    boundary = QueryBoundaryError("query returned sensitive user value")
    assert "sensitive" not in safe_error_message(secret)
    assert "sensitive" not in safe_error_message(boundary)


def test_local_liveness_uses_marker_freshness(tmp_path: Path) -> None:
    marker = tmp_path / "live"
    assert not local_liveness(marker, 30)
    marker.write_text("1", encoding="ascii")
    assert local_liveness(marker, 30)


def leased_job() -> LeasedJob:
    return LeasedJob(
        id="00000000-0000-4000-8000-000000000010",
        connector_id="00000000-0000-4000-8000-000000000011",
        assessment_id="00000000-0000-4000-8000-000000000012",
        job_type="control_assessment",
        status="leased",
        payload={"probe_ids": ["postgresql.tls_sessions"]},
        lease_token="00000000-0000-4000-8000-000000000013",  # noqa: S106 - lease fence fixture
        lease_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        attempts=1,
        max_attempts=3,
    )


def test_collector_wire_models_reject_coercion_and_extra_capabilities() -> None:
    raw_job = leased_job().model_dump(mode="json")
    with pytest.raises(ValidationError):
        LeasedJob.model_validate({**raw_job, "attempts": "1"})
    with pytest.raises(ValidationError):
        LeasedJob.model_validate({**raw_job, "secret_ref": "vault://should-not-leak"})
    with pytest.raises(ValidationError, match="JSON boolean"):
        RuntimeConnectorEnvelope.model_validate(
            {
                "schema_version": "1.0",
                "connector_id": raw_job["connector_id"],
                "platform": "postgresql",
                "endpoint_ref": "dns://db.internal:5432/app",
                "secret_ref": "vault://database/app#reader",
                "config": {"enabled": "false"},
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )


@pytest.mark.asyncio
async def test_readiness_proves_collector_authentication_and_identity() -> None:
    seen_authorization: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers.get("x-subject"))
        return httpx.Response(200, json={"status": "ok", "collector_id": "collector-one"})

    client = AssuranceApiClient(
        api_url="http://api.test",
        collector_id="collector-one",
        tenant_id="tenant-one",
        token_file=None,
        environment="test",
    )
    await client._client.aclose()  # noqa: SLF001 - inject an isolated transport at the boundary
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://api.test", transport=httpx.MockTransport(handler)
    )
    async with client:
        assert await client.ready()
    assert seen_authorization == ["collector-one"]


@pytest.mark.asyncio
async def test_each_logical_lease_call_has_a_distinct_idempotency_key() -> None:
    keys: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        keys.append(request.headers.get("idempotency-key"))
        return httpx.Response(204)

    client = AssuranceApiClient(
        api_url="http://api.test",
        collector_id="collector-one",
        tenant_id="tenant-one",
        token_file=None,
        environment="test",
    )
    await client._client.aclose()  # noqa: SLF001 - inject an isolated transport at the boundary
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://api.test", transport=httpx.MockTransport(handler)
    )
    async with client:
        assert await client.lease(1) is None
        assert await client.lease(1) is None

    assert len(keys) == 2
    assert all(keys)
    assert keys[0] != keys[1]


@pytest.mark.asyncio
async def test_completion_uncertainty_retries_the_exact_envelope() -> None:
    requests: list[tuple[str | None, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.headers.get("idempotency-key"), request.content))
        if len(requests) == 1:
            raise httpx.ReadTimeout("uncertain completion", request=request)
        return httpx.Response(200, json={})

    client = AssuranceApiClient(
        api_url="http://api.test",
        collector_id="collector-one",
        tenant_id="tenant-one",
        token_file=None,
        environment="test",
    )
    await client._client.aclose()  # noqa: SLF001 - inject an isolated transport at the boundary
    client._client = httpx.AsyncClient(  # noqa: SLF001
        base_url="http://api.test", transport=httpx.MockTransport(handler)
    )
    result = ProbeResultSubmission(
        probe_id="postgresql.tls_sessions",
        outcome="unsupported",
        duration_ms=1,
        row_count=0,
    )
    async with client:
        await client.complete(leased_job(), success=True, results=[result])

    assert len(requests) == 2
    assert requests[0] == requests[1]
    assert json.loads(requests[0][1])["success"] is True
