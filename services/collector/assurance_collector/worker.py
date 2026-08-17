from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import httpx

from .adapters import (
    DriverUnavailableError,
    InsufficientPrivilegeError,
    QueryBoundaryError,
    TransientSourceError,
    UnsupportedSourceError,
)
from .api_client import AssuranceApiClient, LeasedJob, ProbeResultSubmission
from .executor import EvidenceBoundaryError, ProbeExecutor
from .observability import (
    ACTIVE_JOBS,
    HEARTBEATS,
    JOBS,
    LAST_HEARTBEAT,
    PROBE_SECONDS,
    PROBES,
    increment,
    observe,
    set_value,
)
from .resilience import CircuitOpenError, retry_async
from .secrets import SecretResolutionError

logger = logging.getLogger(__name__)
TRANSIENT_ERRORS = (httpx.TransportError, TimeoutError, ConnectionError)
MAX_JOB_RESULT_BYTES = 1024 * 1024
LEASE_SAFETY_SECONDS = 5


class LeaseLostError(RuntimeError):
    pass


class CollectorWorker:
    def __init__(
        self,
        *,
        api: AssuranceApiClient,
        executor: ProbeExecutor,
        enable_leasing: bool,
        heartbeat_seconds: int,
        poll_seconds: float,
        lease_renew_seconds: int,
        max_parallel_jobs: int,
        liveness_file: Path,
    ) -> None:
        self._api = api
        self._executor = executor
        self._enable_leasing = enable_leasing
        self._heartbeat_seconds = heartbeat_seconds
        self._poll_seconds = poll_seconds
        self._lease_renew_seconds = lease_renew_seconds
        self._max_parallel_jobs = max_parallel_jobs
        self._liveness_file = liveness_file
        self._active_jobs = 0

    async def run(self) -> None:
        stop = asyncio.Event()
        heartbeat_task = asyncio.create_task(self._heartbeat_loop(stop))
        jobs: set[asyncio.Task[None]] = set()
        try:
            while True:
                self._touch_liveness()
                completed = {task for task in jobs if task.done()}
                jobs.difference_update(completed)
                if completed:
                    await asyncio.gather(*completed, return_exceptions=True)
                if not self._enable_leasing:
                    await asyncio.sleep(self._poll_seconds)
                    continue
                if len(jobs) >= self._max_parallel_jobs:
                    await asyncio.wait(
                        jobs,
                        timeout=self._poll_seconds,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    continue
                try:
                    job = await self._api.lease(self._poll_seconds)
                    if job is None:
                        await asyncio.sleep(self._poll_seconds)
                        continue
                    jobs.add(asyncio.create_task(self._execute_job(job)))
                except TRANSIENT_ERRORS as exc:
                    logger.warning(
                        "collector API temporarily unavailable",
                        extra={
                            "event": "collector.api_transient",
                            "error_type": type(exc).__name__,
                        },
                    )
                    await asyncio.sleep(self._poll_seconds)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "collector loop failed safely",
                        extra={"event": "collector.loop_failed"},
                    )
                    await asyncio.sleep(self._poll_seconds)
        finally:
            stop.set()
            heartbeat_task.cancel()
            for job_task in jobs:
                job_task.cancel()
            await asyncio.gather(heartbeat_task, *jobs, return_exceptions=True)

    async def _heartbeat_loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self._api.heartbeat(self._heartbeat_seconds)
                increment(HEARTBEATS, "accepted")
                set_value(LAST_HEARTBEAT, time.time())
                self._touch_liveness()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                increment(HEARTBEATS, "failed")
                logger.warning(
                    "collector heartbeat failed",
                    extra={"event": "collector.heartbeat_failed", "error_type": type(exc).__name__},
                )
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._heartbeat_seconds)
            except TimeoutError:
                pass

    async def _execute_job(self, job: LeasedJob) -> None:
        self._active_jobs += 1
        set_value(ACTIVE_JOBS, self._active_jobs)
        platform = "unknown"
        renewal_stop = asyncio.Event()
        lease_lost = asyncio.Event()
        renewal_task = asyncio.create_task(self._renew_loop(job, renewal_stop, lease_lost))
        completion_started = False
        try:
            self._assert_lease_budget(job)
            connector = await self._api.runtime_connector(job.connector_id)
            platform = connector.platform.value
            results: list[ProbeResultSubmission] = []
            for probe_id in job.payload.probe_ids:
                if lease_lost.is_set():
                    raise LeaseLostError("job lease could not be safely renewed")
                self._assert_lease_budget(job)
                started = time.perf_counter()
                try:
                    evidence = await self._executor.execute(connector, probe_id)
                except (DriverUnavailableError, UnsupportedSourceError):
                    results.append(terminal_probe_result(probe_id, "unsupported", started))
                    increment(PROBES, platform, "unsupported")
                    continue
                except InsufficientPrivilegeError:
                    results.append(
                        terminal_probe_result(probe_id, "insufficient_privilege", started)
                    )
                    increment(PROBES, platform, "insufficient_privilege")
                    continue
                except (TransientSourceError, CircuitOpenError):
                    results.append(
                        terminal_probe_result(
                            probe_id,
                            "error",
                            started,
                            "Source remained unavailable after the bounded retry policy.",
                        )
                    )
                    increment(PROBES, platform, "error")
                    continue
                except (QueryBoundaryError, EvidenceBoundaryError):
                    results.append(
                        terminal_probe_result(
                            probe_id,
                            "error",
                            started,
                            "Source evidence exceeded an approved safety boundary.",
                        )
                    )
                    increment(PROBES, platform, "error")
                    continue
                except SecretResolutionError:
                    results.append(
                        terminal_probe_result(
                            probe_id,
                            "error",
                            started,
                            "The approved source credential could not be resolved.",
                        )
                    )
                    increment(PROBES, platform, "error")
                    continue
                results.append(
                    ProbeResultSubmission(
                        probe_id=evidence.probe_id,
                        outcome="collected",
                        duration_ms=evidence.duration_ms,
                        row_count=evidence.row_count,
                        evidence_sha256=evidence.sha256,
                        observations=evidence.observations,
                    )
                )
                increment(PROBES, platform, "collected")
                observe(PROBE_SECONDS, time.perf_counter() - started, platform)
            if lease_lost.is_set():
                raise LeaseLostError("job lease could not be safely renewed")
            encoded_results = json.dumps(
                [result.model_dump(mode="json") for result in results],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            if len(encoded_results) > MAX_JOB_RESULT_BYTES:
                raise EvidenceBoundaryError("aggregate job result exceeds 1 MiB")
            completion_started = True
            await self._api.complete(job, success=True, results=results)
            increment(JOBS, platform, "succeeded")
            logger.info(
                "collector job completed",
                extra={"event": "collector.job_completed", "job_id": job.id, "platform": platform},
            )
        except asyncio.CancelledError:
            raise
        except LeaseLostError:
            increment(JOBS, platform, "lease_lost")
            logger.warning(
                "collector abandoned a job after losing its fenced lease",
                extra={"event": "collector.lease_lost", "job_id": job.id, "platform": platform},
            )
        except Exception as exc:
            increment(JOBS, platform, "failed")
            if completion_started:
                logger.warning(
                    "collector did not submit a contradictory result after completion uncertainty",
                    extra={
                        "event": "collector.job_completion_uncertain",
                        "job_id": job.id,
                        "platform": platform,
                        "error_type": type(exc).__name__,
                    },
                )
                return
            try:
                await self._api.complete(job, success=False, error=safe_error_message(exc))
            except httpx.HTTPStatusError as completion_error:
                if completion_error.response.status_code in {409, 422}:
                    logger.warning(
                        "collector did not contradict an uncertain or fenced completion",
                        extra={"event": "collector.job_completion_uncertain", "job_id": job.id},
                    )
                    return
                logger.exception(
                    "collector job failure could not be reported",
                    extra={"event": "collector.job_report_failed", "job_id": job.id},
                )
            except Exception:
                logger.exception(
                    "collector job failure could not be reported",
                    extra={"event": "collector.job_report_failed", "job_id": job.id},
                )
            logger.warning(
                "collector job failed",
                extra={
                    "event": "collector.job_failed",
                    "job_id": job.id,
                    "platform": platform,
                    "error_type": type(exc).__name__,
                },
            )
        finally:
            renewal_stop.set()
            renewal_task.cancel()
            await asyncio.gather(renewal_task, return_exceptions=True)
            self._active_jobs = max(0, self._active_jobs - 1)
            set_value(ACTIVE_JOBS, self._active_jobs)

    async def _renew_loop(
        self,
        job: LeasedJob,
        stop: asyncio.Event,
        lease_lost: asyncio.Event,
    ) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self._lease_renew_seconds)
                return
            except TimeoutError:
                try:
                    renewed_expiry = await retry_async(
                        lambda: self._api.renew(job),
                        attempts=3,
                        base_delay_seconds=0.1,
                        maximum_delay_seconds=1.0,
                        retryable=lambda error: isinstance(error, TRANSIENT_ERRORS),
                    )
                    job.lease_expires_at = renewed_expiry
                except Exception as exc:
                    lease_lost.set()
                    logger.warning(
                        "collector job lease renewal failed closed",
                        extra={
                            "event": "collector.lease_renew_failed",
                            "job_id": job.id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    return

    def _assert_lease_budget(self, job: LeasedJob) -> None:
        expires_at = job.lease_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        remaining = (expires_at.astimezone(UTC) - datetime.now(UTC)).total_seconds()
        required = self._executor.maximum_operation_seconds + LEASE_SAFETY_SECONDS
        if remaining <= required or self._lease_renew_seconds >= remaining / 2:
            raise LeaseLostError("active lease has insufficient safe execution budget")

    def _touch_liveness(self) -> None:
        self._liveness_file.parent.mkdir(parents=True, exist_ok=True)
        self._liveness_file.write_text(str(time.time()), encoding="ascii")


def local_liveness(path: Path, maximum_age_seconds: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime <= maximum_age_seconds
    except OSError:
        return False


def safe_error_message(error: Exception) -> str:
    if isinstance(error, DriverUnavailableError):
        return "approved database driver is unavailable"
    if isinstance(error, SecretResolutionError):
        return "source credential could not be resolved"
    if isinstance(error, QueryBoundaryError):
        return "source query exceeded an approved safety boundary"
    if isinstance(error, EvidenceBoundaryError):
        return "source evidence exceeded an approved safety boundary"
    if isinstance(error, (TransientSourceError, CircuitOpenError)):
        return "source is temporarily unavailable"
    if isinstance(error, TRANSIENT_ERRORS):
        return "transient source or network failure"
    return "collector execution failed"


def terminal_probe_result(
    probe_id: str,
    outcome: Literal["unsupported", "insufficient_privilege", "error"],
    started: float,
    message: str | None = None,
) -> ProbeResultSubmission:
    messages = {
        "unsupported": "Approved probe is unsupported by this database version or driver.",
        "insufficient_privilege": "Approved metadata privilege is unavailable.",
        "error": "Source remained unavailable after the bounded retry policy.",
    }
    return ProbeResultSubmission(
        probe_id=probe_id,
        outcome=outcome,
        duration_ms=round((time.perf_counter() - started) * 1000),
        row_count=0,
        message=message or messages[outcome],
    )
