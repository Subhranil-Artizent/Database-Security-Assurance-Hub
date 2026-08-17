from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum


class CircuitOpenError(RuntimeError):
    """Raised when a failing source is temporarily isolated."""


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class AsyncCircuitBreaker:
    failure_threshold: int
    recovery_seconds: float
    clock: Callable[[], float] = time.monotonic
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _consecutive_failures: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)
    _half_open_in_flight: bool = field(default=False, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    @property
    def state(self) -> CircuitState:
        return self._state

    async def call[T](
        self,
        operation: Callable[[], Awaitable[T]],
        *,
        retryable: Callable[[Exception], bool],
    ) -> T:
        await self._before_call()
        try:
            result = await operation()
        except asyncio.CancelledError:
            await self._record_abandoned()
            raise
        except Exception as exc:
            if retryable(exc):
                await self._record_failure()
            else:
                # A permanent validation or authorization failure proves that
                # the transport is reachable; it must not keep a circuit open.
                await self._record_success()
            raise
        await self._record_success()
        return result

    async def _before_call(self) -> None:
        async with self._lock:
            if self._state is CircuitState.CLOSED:
                return
            if self._state is CircuitState.HALF_OPEN:
                raise CircuitOpenError("source circuit recovery probe is already running")
            opened_at = self._opened_at if self._opened_at is not None else self.clock()
            if self.clock() - opened_at < self.recovery_seconds:
                raise CircuitOpenError("source circuit is temporarily open")
            if self._half_open_in_flight:
                raise CircuitOpenError("source circuit recovery probe is already running")
            self._state = CircuitState.HALF_OPEN
            self._half_open_in_flight = True

    async def _record_abandoned(self) -> None:
        async with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = self.clock()
                self._half_open_in_flight = False

    async def _record_failure(self) -> None:
        async with self._lock:
            self._consecutive_failures += 1
            if (
                self._state is CircuitState.HALF_OPEN
                or self._consecutive_failures >= self.failure_threshold
            ):
                self._state = CircuitState.OPEN
                self._opened_at = self.clock()
            self._half_open_in_flight = False

    async def _record_success(self) -> None:
        async with self._lock:
            self._state = CircuitState.CLOSED
            self._consecutive_failures = 0
            self._opened_at = None
            self._half_open_in_flight = False


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int,
    base_delay_seconds: float,
    maximum_delay_seconds: float,
    retryable: Callable[[Exception], bool],
    on_retry: Callable[[int, Exception], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    random_value: Callable[[], float] = random.random,
) -> T:
    """Retry an explicitly classified transient operation with full jitter."""
    if attempts < 1:
        raise ValueError("attempts must be at least one")
    for attempt in range(1, attempts + 1):
        try:
            return await operation()
        except Exception as exc:
            if attempt >= attempts or not retryable(exc):
                raise
            if on_retry is not None:
                on_retry(attempt, exc)
            ceiling = min(maximum_delay_seconds, base_delay_seconds * (2 ** (attempt - 1)))
            await sleep(max(0.0, ceiling * random_value()))
    raise AssertionError("retry loop must always return or raise")
