from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

try:
    import prometheus_client
except ImportError:  # pragma: no cover - intentionally optional integration
    prometheus_client = None  # type: ignore[assignment]


class JsonFormatter(logging.Formatter):
    _standard = {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._standard and isinstance(value, (str, int, float, bool)):
                payload[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


if prometheus_client is not None:
    HEARTBEATS: Any = prometheus_client.Counter(
        "assurance_collector_heartbeats_total",
        "Collector heartbeat attempts",
        ("outcome",),
    )
    JOBS: Any = prometheus_client.Counter(
        "assurance_collector_jobs_total",
        "Collector jobs by terminal outcome and platform",
        ("platform", "outcome"),
    )
    PROBES: Any = prometheus_client.Counter(
        "assurance_collector_probes_total",
        "Collector probes by platform and outcome",
        ("platform", "outcome"),
    )
    PROBE_SECONDS: Any = prometheus_client.Histogram(
        "assurance_collector_probe_duration_seconds",
        "Bounded source probe duration",
        ("platform",),
        buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
    )
    LAST_HEARTBEAT: Any = prometheus_client.Gauge(
        "assurance_collector_last_heartbeat_timestamp_seconds",
        "Unix timestamp of the last accepted API heartbeat",
    )
    ACTIVE_JOBS: Any = prometheus_client.Gauge(
        "assurance_collector_active_jobs",
        "Number of locally active jobs",
    )
    RETRIES: Any = prometheus_client.Counter(
        "assurance_collector_source_retries_total",
        "Explicitly classified transient source retries",
        ("platform",),
    )
    CIRCUIT_REJECTIONS: Any = prometheus_client.Counter(
        "assurance_collector_source_circuit_rejections_total",
        "Source operations rejected by an open circuit",
        ("platform",),
    )
else:  # pragma: no cover
    HEARTBEATS = JOBS = PROBES = PROBE_SECONDS = LAST_HEARTBEAT = ACTIVE_JOBS = None
    RETRIES = CIRCUIT_REJECTIONS = None


def start_metrics_server(port: int, host: str = "127.0.0.1") -> None:
    if prometheus_client is not None:
        prometheus_client.start_http_server(port, addr=host)


def increment(metric: Any, *labels: str) -> None:
    if metric is not None:
        metric.labels(*labels).inc()


def observe(metric: Any, value: float, *labels: str) -> None:
    if metric is not None:
        metric.labels(*labels).observe(value)


def set_value(metric: Any, value: float) -> None:
    if metric is not None:
        metric.set(value)
