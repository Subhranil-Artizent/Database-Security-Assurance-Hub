from __future__ import annotations

import asyncio
import logging
import sys

from pydantic import ValidationError

from .adapters import default_adapters
from .api_client import AssuranceApiClient
from .executor import ProbeExecutor
from .models import CollectorSettings, ExecutionLimits, ResiliencePolicy
from .observability import configure_logging, start_metrics_server
from .secrets import MountedJsonSecretResolver
from .worker import CollectorWorker, local_liveness

logger = logging.getLogger(__name__)


async def run(settings: CollectorSettings) -> None:
    resolver = MountedJsonSecretResolver(
        settings.credential_root,
        require_private_mode=settings.environment in {"staging", "production"},
    )
    executor = ProbeExecutor(
        adapters=default_adapters(
            settings.sybase_odbc_driver,
            allow_insecure_loopback=settings.environment == "development",
        ),
        secret_resolver=resolver,
        limits=ExecutionLimits(
            connect_timeout_seconds=settings.connect_timeout_seconds,
            statement_timeout_seconds=settings.statement_timeout_seconds,
            max_rows=settings.max_rows,
            max_payload_bytes=settings.max_payload_bytes,
        ),
        resilience=ResiliencePolicy(
            retry_attempts=settings.source_retry_attempts,
            retry_base_seconds=settings.source_retry_base_seconds,
            retry_max_seconds=settings.source_retry_max_seconds,
            circuit_failure_threshold=settings.circuit_failure_threshold,
            circuit_recovery_seconds=settings.circuit_recovery_seconds,
        ),
    )
    async with AssuranceApiClient(
        api_url=settings.api_url,
        collector_id=settings.collector_id,
        tenant_id=settings.tenant_id,
        token_file=settings.token_file,
        environment=settings.environment,
    ) as api:
        worker = CollectorWorker(
            api=api,
            executor=executor,
            enable_leasing=settings.enable_leasing,
            heartbeat_seconds=settings.heartbeat_seconds,
            poll_seconds=settings.poll_seconds,
            lease_renew_seconds=settings.lease_renew_seconds,
            max_parallel_jobs=settings.max_parallel_jobs,
            liveness_file=settings.liveness_file,
        )
        await worker.run()


async def readiness(settings: CollectorSettings) -> bool:
    async with AssuranceApiClient(
        api_url=settings.api_url,
        collector_id=settings.collector_id,
        tenant_id=settings.tenant_id,
        token_file=settings.token_file,
        environment=settings.environment,
    ) as api:
        return await api.ready()


def main() -> None:
    configure_logging()
    try:
        # BaseSettings obtains the runtime identities from COLLECTOR_*.
        settings = CollectorSettings()  # type: ignore[call-arg]
        command = sys.argv[1] if len(sys.argv) > 1 else "run"
        if command == "validate-config":
            return
        if command == "live":
            maximum_age = max(30, settings.heartbeat_seconds * 3)
            raise SystemExit(0 if local_liveness(settings.liveness_file, maximum_age) else 1)
        if command == "ready":
            raise SystemExit(0 if asyncio.run(readiness(settings)) else 1)
        if command != "run":
            raise ValueError("command must be run, live, ready, or validate-config")
        start_metrics_server(settings.metrics_port, settings.metrics_host)
        asyncio.run(run(settings))
    except (ValidationError, ValueError, RuntimeError) as exc:
        logger.error(
            "collector startup failed",
            extra={"event": "collector.startup_failed", "error_type": type(exc).__name__},
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
