from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

import pytest

from assurance_collector.adapters import DatabaseAdapter, Row
from assurance_collector.executor import EvidenceBoundaryError, ProbeExecutor
from assurance_collector.models import (
    DatabaseEndpoint,
    ExecutionLimits,
    Platform,
    ProbeSpec,
    ResiliencePolicy,
    RuntimeConnector,
    SourceCredential,
)


class FakeSecretResolver:
    async def resolve(self, secret_ref: str) -> SourceCredential:
        assert secret_ref.startswith("vault://")
        return SourceCredential(
            username="reader",
            password="not-returned",  # noqa: S106 - isolated fake credential
            ca_file="ca.pem",
        )


class FakeAdapter(DatabaseAdapter):
    platform = Platform.POSTGRESQL

    def __init__(self, rows: Sequence[Row]) -> None:
        self.rows = rows
        self.calls = 0

    async def execute(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        probe: ProbeSpec,
        limits: ExecutionLimits,
    ) -> Sequence[Row]:
        self.calls += 1
        assert endpoint.host == "db.internal"
        assert credential.password.get_secret_value() == "not-returned"
        assert probe.probe_id == "postgresql.tls_sessions"
        return self.rows

    async def verify_read_only(
        self,
        endpoint: DatabaseEndpoint,
        credential: SourceCredential,
        limits: ExecutionLimits,
    ) -> bool:
        _ = (endpoint, credential, limits)
        return True


def connector() -> RuntimeConnector:
    return RuntimeConnector(
        connector_id="00000000-0000-4000-8000-000000000001",
        platform="postgresql",
        endpoint_ref="dns://db.internal:5432/app",
        secret_ref="vault://database/app#reader",  # noqa: S106 - opaque reference, not a secret
    )


def limits() -> ExecutionLimits:
    return ExecutionLimits(
        connect_timeout_seconds=5,
        statement_timeout_seconds=10,
        max_rows=10,
        max_payload_bytes=4096,
    )


def resilience() -> ResiliencePolicy:
    return ResiliencePolicy(
        retry_attempts=1,
        retry_base_seconds=0.01,
        retry_max_seconds=0.05,
        circuit_failure_threshold=2,
        circuit_recovery_seconds=5,
    )


@pytest.mark.asyncio
async def test_executor_filters_and_hashes_approved_security_metadata() -> None:
    adapter = FakeAdapter([{"ssl": True, "version": "TLSv1.3", "cipher": "AES", "bits": 256}])
    executor = ProbeExecutor(
        adapters={Platform.POSTGRESQL: adapter},
        secret_resolver=FakeSecretResolver(),
        limits=limits(),
        resilience=resilience(),
    )
    evidence = await executor.execute(connector(), "postgresql.tls_sessions")
    canonical = json.dumps(
        [{"bits": 256, "cipher": "AES", "ssl": True, "version": "TLSv1.3"}],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert evidence.row_count == 1
    assert evidence.sha256 == hashlib.sha256(canonical).hexdigest()
    assert adapter.calls == 1
    assert "not-returned" not in evidence.model_dump_json()


@pytest.mark.asyncio
async def test_executor_rejects_driver_fields_outside_contract() -> None:
    adapter = FakeAdapter(
        [{"ssl": True, "version": "TLSv1.3", "cipher": "AES", "bits": 256, "password": "x"}]
    )
    executor = ProbeExecutor(
        adapters={Platform.POSTGRESQL: adapter},
        secret_resolver=FakeSecretResolver(),
        limits=limits(),
        resilience=resilience(),
    )
    with pytest.raises(EvidenceBoundaryError, match="differ"):
        await executor.execute(connector(), "postgresql.tls_sessions")


@pytest.mark.asyncio
async def test_executor_rejects_missing_driver_fields() -> None:
    adapter = FakeAdapter([{"ssl": True, "version": "TLSv1.3", "cipher": "AES"}])
    executor = ProbeExecutor(
        adapters={Platform.POSTGRESQL: adapter},
        secret_resolver=FakeSecretResolver(),
        limits=limits(),
        resilience=resilience(),
    )
    with pytest.raises(EvidenceBoundaryError, match="differ"):
        await executor.execute(connector(), "postgresql.tls_sessions")


@pytest.mark.asyncio
async def test_disabled_connector_is_an_operator_kill_switch() -> None:
    adapter = FakeAdapter([])
    executor = ProbeExecutor(
        adapters={Platform.POSTGRESQL: adapter},
        secret_resolver=FakeSecretResolver(),
        limits=limits(),
        resilience=resilience(),
    )
    disabled = connector().model_copy(update={"enabled": False})
    with pytest.raises(RuntimeError, match="kill switch"):
        await executor.execute(disabled, "postgresql.tls_sessions")
    assert adapter.calls == 0


@pytest.mark.asyncio
async def test_executor_exposes_read_only_promotion_check() -> None:
    adapter = FakeAdapter([])
    executor = ProbeExecutor(
        adapters={Platform.POSTGRESQL: adapter},
        secret_resolver=FakeSecretResolver(),
        limits=limits(),
        resilience=resilience(),
    )
    assert await executor.verify_read_only(connector())
