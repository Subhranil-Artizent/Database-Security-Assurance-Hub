from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Mapping, Sequence

from .adapters import DatabaseAdapter, QueryBoundaryError, Row, TransientSourceError
from .catalog import get_probe
from .models import (
    CollectedEvidence,
    ExecutionLimits,
    JsonScalar,
    Platform,
    ResiliencePolicy,
    RuntimeConnector,
    normalize_scalar,
)
from .observability import CIRCUIT_REJECTIONS, RETRIES, increment
from .resilience import AsyncCircuitBreaker, CircuitOpenError, retry_async
from .secrets import SecretResolver


class EvidenceBoundaryError(RuntimeError):
    pass


class ProbeExecutor:
    def __init__(
        self,
        *,
        adapters: Mapping[Platform, DatabaseAdapter],
        secret_resolver: SecretResolver,
        limits: ExecutionLimits,
        resilience: ResiliencePolicy,
    ) -> None:
        self._adapters = adapters
        self._secret_resolver = secret_resolver
        self._limits = limits
        self._resilience = resilience
        self._circuits: OrderedDict[str, AsyncCircuitBreaker] = OrderedDict()

    async def verify_read_only(self, connector: RuntimeConnector) -> bool:
        credential = await self._secret_resolver.resolve(connector.secret_ref)
        adapter = self._adapters[connector.platform]
        return await adapter.verify_read_only(connector.endpoint(), credential, self._limits)

    async def execute(self, connector: RuntimeConnector, probe_id: str) -> CollectedEvidence:
        if not connector.enabled:
            raise RuntimeError("connector is disabled by its operator kill switch")
        probe = get_probe(connector.platform, probe_id)
        adapter = self._adapters[connector.platform]
        credential = await self._secret_resolver.resolve(connector.secret_ref)
        started = time.perf_counter()
        circuit = self._circuit_for(connector.connector_id)

        def on_retry(_attempt: int, _error: Exception) -> None:
            increment(RETRIES, connector.platform.value)

        async def execute_with_retry() -> Sequence[Row]:
            return await retry_async(
                lambda: adapter.execute(connector.endpoint(), credential, probe, self._limits),
                attempts=self._resilience.retry_attempts,
                base_delay_seconds=self._resilience.retry_base_seconds,
                maximum_delay_seconds=self._resilience.retry_max_seconds,
                retryable=lambda error: isinstance(error, TransientSourceError),
                on_retry=on_retry,
            )

        try:
            rows = await circuit.call(
                execute_with_retry,
                retryable=lambda error: isinstance(error, TransientSourceError),
            )
        except CircuitOpenError:
            increment(CIRCUIT_REJECTIONS, connector.platform.value)
            raise
        observations = sanitize_rows(rows, probe.allowed_fields, self._limits)
        canonical = json.dumps(
            observations,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(canonical) > self._limits.max_payload_bytes:
            raise EvidenceBoundaryError(
                f"normalized evidence exceeded {self._limits.max_payload_bytes} bytes"
            )
        return CollectedEvidence(
            probe_id=probe.probe_id,
            row_count=len(observations),
            sha256=hashlib.sha256(canonical).hexdigest(),
            observations=observations,
            duration_ms=round((time.perf_counter() - started) * 1000),
        )

    def _circuit_for(self, connector_id: str) -> AsyncCircuitBreaker:
        existing = self._circuits.pop(connector_id, None)
        if existing is not None:
            self._circuits[connector_id] = existing
            return existing
        # Bound local state so a reassigned fleet cannot grow this process forever.
        while len(self._circuits) >= 2048:
            self._circuits.popitem(last=False)
        created = AsyncCircuitBreaker(
            failure_threshold=self._resilience.circuit_failure_threshold,
            recovery_seconds=self._resilience.circuit_recovery_seconds,
        )
        self._circuits[connector_id] = created
        return created

    @property
    def maximum_operation_seconds(self) -> float:
        """Conservative bound used before starting work under a fenced lease."""
        per_attempt = self._limits.connect_timeout_seconds + self._limits.statement_timeout_seconds
        retry_delay = sum(
            min(
                self._resilience.retry_max_seconds,
                self._resilience.retry_base_seconds * (2**attempt),
            )
            for attempt in range(max(0, self._resilience.retry_attempts - 1))
        )
        return float(self._resilience.retry_attempts * per_attempt + retry_delay)


def sanitize_rows(
    rows: Sequence[Row],
    allowed_fields: frozenset[str],
    limits: ExecutionLimits,
) -> list[dict[str, JsonScalar]]:
    if len(rows) > limits.max_rows:
        raise QueryBoundaryError(f"probe exceeded the {limits.max_rows}-row safety limit")
    normalized: list[dict[str, JsonScalar]] = []
    for row in rows:
        lowered = {str(key).lower(): value for key, value in row.items()}
        returned = set(lowered)
        if returned != allowed_fields:
            raise EvidenceBoundaryError(
                "database driver returned fields that differ from the approved evidence contract"
            )
        normalized.append(
            {key: normalize_scalar(lowered.get(key)) for key in sorted(allowed_fields)}
        )
    return normalized
