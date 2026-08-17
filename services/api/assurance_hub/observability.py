from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)
REQUESTS: Any = None
LATENCY: Any = None
JOBS_RECONCILED: Any = None
JOBS_CREATED: Any = None
JOBS_LEASED: Any = None
JOBS_COMPLETED: Any = None
EVIDENCE_INGESTED: Any = None
GOVERNANCE_WRITE_FAILURES: Any = None
LEASE_FENCING_REJECTIONS: Any = None
IDEMPOTENCY_RECOVERY: Any = None
OUTBOX_RECONCILED: Any = None
EXCEPTIONS_EXPIRED: Any = None
READY: Any = None

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

    REQUESTS = Counter(
        "assurance_http_requests_total", "HTTP requests", ["method", "route", "status"]
    )
    LATENCY = Histogram(
        "assurance_http_request_duration_seconds", "HTTP request duration", ["method", "route"]
    )
    JOBS_RECONCILED = Counter(
        "assurance_jobs_reconciled_total", "Expired job leases reconciled", ["outcome"]
    )
    JOBS_CREATED = Counter("assurance_scan_jobs_created_total", "Scan jobs accepted", ["job_type"])
    JOBS_LEASED = Counter("assurance_scan_jobs_leased_total", "Scan jobs leased", ["job_type"])
    JOBS_COMPLETED = Counter(
        "assurance_scan_jobs_completed_total", "Scan job outcomes", ["outcome"]
    )
    EVIDENCE_INGESTED = Counter(
        "assurance_evidence_ingested_total", "Evidence records accepted", ["evidence_type"]
    )
    GOVERNANCE_WRITE_FAILURES = Counter(
        "assurance_governance_write_failures_total",
        "Durable idempotency or audit outcome write failures",
    )
    LEASE_FENCING_REJECTIONS = Counter(
        "assurance_lease_fencing_rejections_total",
        "Stale or invalid collector lease capabilities rejected",
        ["operation"],
    )
    IDEMPOTENCY_RECOVERY = Counter(
        "assurance_idempotency_recovery_total",
        "Uncertain idempotency reservation recovery transitions",
        ["outcome"],
    )
    OUTBOX_RECONCILED = Counter(
        "assurance_outbox_reconciled_total",
        "Expired integration delivery leases reconciled",
        ["outcome"],
    )
    EXCEPTIONS_EXPIRED = Counter(
        "assurance_finding_exceptions_expired_total",
        "Approved finding exceptions expired by governance reconciliation",
    )
    READY = Gauge("assurance_ready", "Service readiness")
except ImportError:  # pragma: no cover - verified in minimal installations
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"


def record_request(method: str, route: str, status: int, duration: float) -> None:
    if REQUESTS is not None and LATENCY is not None:
        REQUESTS.labels(method, route, str(status)).inc()
        LATENCY.labels(method, route).observe(duration)


def record_job_created(job_type: str) -> None:
    if JOBS_CREATED is not None:
        JOBS_CREATED.labels(job_type).inc()


def record_job_leased(job_type: str) -> None:
    if JOBS_LEASED is not None:
        JOBS_LEASED.labels(job_type).inc()


def record_job_completed(outcome: str) -> None:
    if JOBS_COMPLETED is not None:
        JOBS_COMPLETED.labels(outcome).inc()


def record_evidence_ingested(evidence_type: str) -> None:
    if EVIDENCE_INGESTED is not None:
        EVIDENCE_INGESTED.labels(evidence_type).inc()


def record_governance_write_failure() -> None:
    if GOVERNANCE_WRITE_FAILURES is not None:
        GOVERNANCE_WRITE_FAILURES.inc()


def record_lease_fencing_rejection(operation: str) -> None:
    if LEASE_FENCING_REJECTIONS is not None:
        LEASE_FENCING_REJECTIONS.labels(operation).inc()


def record_idempotency_recovery(outcome: str, count: int = 1) -> None:
    if IDEMPOTENCY_RECOVERY is not None:
        IDEMPOTENCY_RECOVERY.labels(outcome).inc(count)


def record_outbox_reconciliation(outcome: str, count: int) -> None:
    if OUTBOX_RECONCILED is not None:
        OUTBOX_RECONCILED.labels(outcome).inc(count)


def record_exceptions_expired(count: int) -> None:
    if EXCEPTIONS_EXPIRED is not None:
        EXCEPTIONS_EXPIRED.inc(count)


def metric_payload() -> tuple[bytes, str]:
    if REQUESTS is None:
        return b"# Prometheus client is not installed\n", CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST


def configure_telemetry(app: Any, engine: Any, endpoint: str | None) -> None:
    if not endpoint:
        logger.info("OpenTelemetry export disabled", extra={"event": "otel.disabled"})
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": app.title}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app)
        SQLAlchemyInstrumentor().instrument(engine=engine.sync_engine)
        logger.info("OpenTelemetry export enabled", extra={"event": "otel.enabled"})
    except ImportError:
        logger.warning("OpenTelemetry extras unavailable", extra={"event": "otel.unavailable"})
