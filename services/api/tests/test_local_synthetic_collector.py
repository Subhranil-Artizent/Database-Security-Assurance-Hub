from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from assurance_hub.schemas import CollectorLeaseOut

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.local_synthetic_collector import (  # noqa: E402
    DEMO_COLLECTOR_ID,
    DEMO_TENANT_ID,
    LAUNCH_SOURCE,
    LocalSyntheticApiClient,
    LocalSyntheticSettings,
    completion_for,
    synthetic_probe_result,
)

API_DIRECTORY = Path(__file__).resolve().parents[1]


def safe_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "LOCAL_SYNTHETIC_LAUNCH_SOURCE": LAUNCH_SOURCE,
        "LOCAL_SYNTHETIC_API_BASE_URL": "http://127.0.0.1:8000",
        "LOCAL_SYNTHETIC_API_DIRECTORY": str(API_DIRECTORY),
        "LOCAL_SYNTHETIC_DATABASE_URL": "sqlite+aiosqlite:///./assurance-local.db",
        "LOCAL_SYNTHETIC_TENANT_ID": DEMO_TENANT_ID,
        "LOCAL_SYNTHETIC_COLLECTOR_ID": DEMO_COLLECTOR_ID,
        "ENVIRONMENT": "development",
        "AUTH_MODE": "development",
        "ALLOW_INSECURE_DEV_AUTH": "true",
    }
    environment.update(overrides)
    return environment


def leased_job() -> CollectorLeaseOut:
    return CollectorLeaseOut.model_validate(
        {
            "id": "10000000-0000-4000-8000-000000000001",
            "connector_id": "10000000-0000-4000-8000-000000000002",
            "assessment_id": "10000000-0000-4000-8000-000000000003",
            "job_type": "control_assessment",
            "status": "leased",
            "payload": {
                "probe_ids": [
                    "oracle.account_posture",
                    "oracle.tablespace_encryption",
                    "oracle.unified_auditing",
                ],
                "schemas": [],
                "metadata": {
                    "control_pack_id": "oracle-database-security",
                    "control_pack_version": "1.0.0",
                },
            },
            "lease_token": "20000000-0000-4000-8000-000000000001",
            "lease_expires_at": datetime.now(UTC) + timedelta(seconds=120),
            "attempts": 1,
            "max_attempts": 5,
        }
    )


def test_synthetic_settings_fail_closed_outside_integrated_local_sqlite() -> None:
    settings = LocalSyntheticSettings.from_environment(safe_environment())
    assert settings.tenant_id == DEMO_TENANT_ID
    assert settings.poll_seconds == 2.0

    unsafe_overrides = [
        {"LOCAL_SYNTHETIC_LAUNCH_SOURCE": "direct"},
        {"LOCAL_SYNTHETIC_API_BASE_URL": "https://api.example.com"},
        {"LOCAL_SYNTHETIC_DATABASE_URL": "postgresql+asyncpg://localhost/assurance"},
        {"LOCAL_SYNTHETIC_DATABASE_URL": "sqlite+aiosqlite:///../../outside.db"},
        {"LOCAL_SYNTHETIC_TENANT_ID": "customer-tenant"},
        {"LOCAL_SYNTHETIC_COLLECTOR_ID": "customer-collector"},
        {"ENVIRONMENT": "production"},
        {"AUTH_MODE": "oidc"},
        {"ALLOW_INSECURE_DEV_AUTH": "false"},
    ]
    for override in unsafe_overrides:
        with pytest.raises((ValidationError, ValueError)):
            LocalSyntheticSettings.from_environment(safe_environment(**override))

    missing_marker = safe_environment()
    del missing_marker["LOCAL_SYNTHETIC_LAUNCH_SOURCE"]
    with pytest.raises(ValueError, match="integrated launcher"):
        LocalSyntheticSettings.from_environment(missing_marker)


def test_synthetic_evidence_is_deterministic_bounded_and_collection_only() -> None:
    first = synthetic_probe_result("oracle.tablespace_encryption")
    second = synthetic_probe_result("oracle.tablespace_encryption")
    assert first == second
    canonical = json.dumps(
        first.observations,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert first.evidence_sha256 == hashlib.sha256(canonical).hexdigest()
    assert first.outcome == "collected"
    assert first.row_count == 1
    assert len(canonical) < 1024

    completion = completion_for(leased_job())
    assert completion.success is True
    assert {result.outcome for result in completion.result.probe_results} == {"collected"}
    assert completion.result.summary == {
        "collector_version": "local-synthetic-1.0",
        "evidence_origin": "development_synthetic",
        "customer_database_queried": False,
    }
    payload = completion.model_dump(mode="json")
    assert not {"score", "passed", "failed"}.intersection(payload)
    assert not {"score", "passed", "failed"}.intersection(payload["result"]["summary"])

    with pytest.raises(ValueError, match="no approved local synthetic evidence"):
        synthetic_probe_result("oracle.unreviewed_future_probe")


@pytest.mark.asyncio
async def test_synthetic_client_uses_real_heartbeat_lease_and_completion_contracts() -> None:
    job = leased_job()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/collectors/heartbeat"):
            return httpx.Response(
                200,
                json={
                    "accepted": True,
                    "server_time": datetime.now(UTC).isoformat(),
                    "next_heartbeat_seconds": 10,
                },
            )
        if request.url.path.endswith("/scan-jobs/lease"):
            return httpx.Response(200, json=job.model_dump(mode="json"))
        if request.url.path.endswith(f"/scan-jobs/{job.id}/complete"):
            submitted = json.loads(request.content)
            now = datetime.now(UTC).isoformat()
            return httpx.Response(
                200,
                json={
                    "id": job.id,
                    "connector_id": job.connector_id,
                    "assessment_id": job.assessment_id,
                    "job_type": job.job_type,
                    "deduplication_key": "local-synthetic-contract-test",
                    "status": "succeeded",
                    "payload": job.payload.model_dump(mode="json"),
                    "available_at": now,
                    "leased_by": None,
                    "lease_token": None,
                    "lease_expires_at": None,
                    "attempts": 1,
                    "max_attempts": 5,
                    "last_error": None,
                    "result": submitted["result"],
                    "completed_at": now,
                    "created_at": now,
                    "updated_at": now,
                },
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    settings = LocalSyntheticSettings.from_environment(safe_environment())
    async with LocalSyntheticApiClient(settings, transport=httpx.MockTransport(handler)) as client:
        assert await client.heartbeat() == 10
        leased = await client.lease()
        assert leased == job
        assert leased is not None
        await client.complete(leased)

    assert [request.url.path for request in requests] == [
        "/api/v1/collectors/heartbeat",
        "/api/v1/scan-jobs/lease",
        f"/api/v1/scan-jobs/{job.id}/complete",
    ]
    assert all(request.headers["x-tenant-id"] == DEMO_TENANT_ID for request in requests)
    assert all(request.headers["x-subject"] == DEMO_COLLECTOR_ID for request in requests)
    assert all(request.headers["x-roles"] == "collector" for request in requests)
    assert all(request.headers.get("idempotency-key") for request in requests)
    completion_payload = json.loads(requests[-1].content)
    assert completion_payload["result"]["summary"]["customer_database_queried"] is False
    assert {item["outcome"] for item in completion_payload["result"]["probe_results"]} == {
        "collected"
    }
