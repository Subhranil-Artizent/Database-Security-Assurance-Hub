from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 0.2,
    max_delay: float = 5.0,
    retryable: tuple[type[Exception], ...] = (TimeoutError, ConnectionError),
) -> T:
    """Bounded exponential backoff with full jitter."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return await operation()
        except retryable as exc:
            last_error = exc
            if attempt == attempts - 1:
                break
            cap = min(max_delay, base_delay * (2**attempt))
            await asyncio.sleep(random.uniform(0, cap))  # noqa: S311 - jitter is not cryptographic
    assert last_error is not None
    raise last_error


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(slots=True)
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    state: CircuitState = CircuitState.CLOSED
    failures: int = 0
    opened_at: float | None = None

    async def call[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        now = time.monotonic()
        if self.state == CircuitState.OPEN:
            if self.opened_at is None or now - self.opened_at < self.recovery_timeout:
                raise RuntimeError("circuit breaker is open")
            self.state = CircuitState.HALF_OPEN
        try:
            value = await operation()
        except Exception:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.opened_at = time.monotonic()
            raise
        self.state = CircuitState.CLOSED
        self.failures = 0
        self.opened_at = None
        return value
