from __future__ import annotations

import asyncio

import pytest

from assurance_collector.resilience import AsyncCircuitBreaker, CircuitOpenError, retry_async


class TemporaryFailure(RuntimeError):
    pass


@pytest.mark.asyncio
async def test_retry_is_bounded_and_only_retries_classified_failures() -> None:
    calls = 0
    delays: list[float] = []

    async def operation() -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise TemporaryFailure
        return "ok"

    async def no_sleep(delay: float) -> None:
        delays.append(delay)

    result = await retry_async(
        operation,
        attempts=3,
        base_delay_seconds=1,
        maximum_delay_seconds=4,
        retryable=lambda error: isinstance(error, TemporaryFailure),
        sleep=no_sleep,
        random_value=lambda: 0.5,
    )
    assert result == "ok"
    assert calls == 3
    assert delays == [0.5, 1.0]


@pytest.mark.asyncio
async def test_circuit_opens_and_recovers_after_timeout() -> None:
    now = 0.0
    breaker = AsyncCircuitBreaker(
        failure_threshold=2,
        recovery_seconds=10,
        clock=lambda: now,
    )

    async def fail() -> None:
        raise TemporaryFailure

    for _ in range(2):
        with pytest.raises(TemporaryFailure):
            await breaker.call(fail, retryable=lambda error: isinstance(error, TemporaryFailure))
    with pytest.raises(CircuitOpenError):
        await breaker.call(fail, retryable=lambda error: isinstance(error, TemporaryFailure))
    now = 11

    async def recover() -> str:
        return "healthy"

    assert (
        await breaker.call(
            recover,
            retryable=lambda error: isinstance(error, TemporaryFailure),
        )
        == "healthy"
    )


@pytest.mark.asyncio
async def test_half_open_allows_only_one_probe_and_recovers_after_cancellation() -> None:
    now = 0.0
    breaker = AsyncCircuitBreaker(
        failure_threshold=2,
        recovery_seconds=10,
        clock=lambda: now,
    )

    async def fail() -> None:
        raise TemporaryFailure

    for _ in range(2):
        with pytest.raises(TemporaryFailure):
            await breaker.call(fail, retryable=lambda error: isinstance(error, TemporaryFailure))
    now = 11
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_recovery() -> None:
        entered.set()
        await release.wait()

    task = asyncio.create_task(
        breaker.call(
            blocking_recovery,
            retryable=lambda error: isinstance(error, TemporaryFailure),
        )
    )
    await entered.wait()
    with pytest.raises(CircuitOpenError):
        await breaker.call(
            blocking_recovery,
            retryable=lambda error: isinstance(error, TemporaryFailure),
        )
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    now = 22
    release.set()
    await breaker.call(
        blocking_recovery,
        retryable=lambda error: isinstance(error, TemporaryFailure),
    )
