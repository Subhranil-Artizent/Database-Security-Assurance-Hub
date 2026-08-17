from __future__ import annotations

import pytest

from assurance_hub.resilience import CircuitBreaker, CircuitState, retry_async


@pytest.mark.asyncio
async def test_retry_eventually_succeeds():
    calls = 0

    async def transient_operation():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise TimeoutError("temporary")
        return "ok"

    assert await retry_async(transient_operation, attempts=3, base_delay=0) == "ok"
    assert calls == 3


@pytest.mark.asyncio
async def test_circuit_breaker_opens():
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=60)

    async def failing_operation():
        raise ConnectionError("downstream unavailable")

    with pytest.raises(ConnectionError):
        await breaker.call(failing_operation)
    with pytest.raises(ConnectionError):
        await breaker.call(failing_operation)
    assert breaker.state == CircuitState.OPEN
    with pytest.raises(RuntimeError, match="open"):
        await breaker.call(failing_operation)
