# SLO, observability, and reliability contract

These are initial engineering targets, not evidence of achieved production
reliability. Product, platform, security, database, and operations owners must
approve them, then validate measurement and recovery under representative load
and failure before production promotion.

## Initial service objectives

| Capability | Service-level indicator | Initial objective | Current implementation |
|---|---|---:|---|
| API availability | Non-5xx API responses divided by all API responses | 99.9% per rolling 30 days | Request counter plus 5m/1h fast-burn and 30m/6h slow-burn rules |
| Read latency | p95 GET request duration | Below 500 ms over 10 minutes | Request histogram plus traffic-gated warning rule |
| Scheduling | Runnable jobs first leased inside the approved window | 99% start within 15 minutes monthly | Lease counters exist; queue depth/age and schedule timestamps still required |
| Evidence freshness | In-scope assets with accepted evidence inside their schedule | 99% monthly | Evidence counters exist; freshness gauge and estate denominator still required |
| Durable governance | Accepted mutations with durable audit/idempotency outcome | 100% | Transactional code/tests and write-failure counter; production database proof remains required |
| Collector availability | Approved collectors heartbeating and able to authenticate readiness | Environment-defined | Collector heartbeat timestamp exists; Kubernetes base does not expose its loopback metrics for scraping |
| Integration delivery | Outbox events delivered or explicitly dead-lettered inside policy | Environment-defined | Durable state/reconciliation metrics exist; queue-age, destination latency, and dead-letter alerts remain required |

Cross-tenant disclosure, unauthorized source writes, stale-fence acceptance,
forged evidence, and duplicate logical results are zero-tolerance correctness
invariants. They are not error-budget events.

A 99.9% 30-day API availability objective provides approximately 43 minutes
and 50 seconds of error budget. The checked-in rules page on a 14.4x fast burn
and warn on a 6x slow burn. When the budget is exhausted, non-remediation
releases stop until service health and the recovery plan are approved.

## Implemented telemetry

The API exposes:

- request count and duration by method, route, and status;
- readiness;
- jobs created, leased, completed, and reconciled;
- accepted evidence;
- governance-write and lease-fencing failures;
- idempotency recovery, stale outbox reconciliation, and exception expiry;
- structured logs with request and tenant correlation context;
- optional FastAPI and SQLAlchemy OpenTelemetry instrumentation.

The collector exposes:

- heartbeat attempts and last accepted heartbeat time;
- active and terminal jobs;
- probe outcomes and duration by bounded platform;
- classified source retries and circuit rejections;
- structured logs without resolved credentials or source rows.

Metric labels use route templates and bounded enums. Tenant, database, asset,
connector, user, and source-field values are prohibited labels. Logs, traces,
and alerts must never contain credentials, connection strings, source rows,
arbitrary SQL, or customer database names.

## Checked-in recording and alert rules

`infra/prometheus/rules/availability.yml` contains five recording rules and
nine alerts for:

- missing or down API metrics targets;
- API fast and slow availability-budget burn;
- high p95 API read latency;
- governance-write failure;
- elevated scan-job failures;
- leased work with no completion;
- exhausted scan lease retry budget.

The repository validator enforces the exact rule set, bounded aggregations,
severity, delay, summary, and runbook anchor. An alert definition is not
operational evidence. Each production alert must be routed, injected,
acknowledged, recovered, and retained with timestamps.

## Required environment signals

Before live collector and production promotion, add and validate:

- runnable queue depth and oldest job age;
- lease age, expiry, renewal, stale completion, retry, and terminal counts;
- collector heartbeat age and authenticated readiness from the supported
  environment telemetry path;
- source connection duration, statement timeout, circuit state, and source
  workload saturation;
- assessment completion, control outcomes, evidence freshness, and estate
  coverage gaps;
- outbox depth/age, destination duration/errors/rate limits, inbox conflicts,
  and dead-letter state;
- API and maintenance database pool saturation, locks, replica lag, storage,
  failover, and backup status;
- IdP/JWKS, token broker, vault, certificates, private DNS, and key/credential
  rotation health.

The collector metrics server binds loopback and the Kubernetes base permits no
collector ingress. A reviewed sidecar/export path or narrowly scoped
metrics-only Service/ServiceMonitor and NetworkPolicy is required before those
metrics count as production measurement.

## Self-healing behavior

Implemented recovery is bounded and fail-closed:

- Kubernetes restarts failed processes and performs rolling replacement with
  disruption and topology constraints;
- HPA can scale stateless API and collector pods within configured bounds;
- expired scan leases are requeued until the attempt budget is exhausted;
- expired outbox leases are requeued or dead-lettered;
- approved finding exceptions expire automatically;
- uncertain idempotency reservations require audited operator resolution;
- source retry uses bounded backoff/circuit breaking and never bypasses the
  lease, payload, or read-only boundary.

This is not automatic database remediation. It does not change source data,
grants, schema, encryption, or masking policy.

## Recovery objectives

Starting proposals, subject to customer approval:

- managed multi-zone PostgreSQL failover: RPO 0 and RTO no more than 15 minutes;
- regional disaster: RPO no more than 15 minutes and RTO no more than 4 hours;
- immutable retained evidence: versioned cross-region copy with digest checks;
- quarterly restore exercise and semiannual regional recovery exercise.

A backup job is not recovery proof. A drill passes only when the restored schema
is at the expected migration, tenant policies and restricted roles are active,
row counts and sampled digests reconcile, audit history is readable, the API
passes authenticated tenant-isolation smoke tests, and measured RPO/RTO meet the
approved targets.

## Known measurement gaps

- Queue age, estate coverage, evidence freshness, database pool, outbox age,
  destination delivery, and dead-letter measurements are not complete.
- Collector metrics are not scraped by the base because the listener is
  intentionally loopback-only.
- `RequestMetricsMiddleware` falls back to the raw URL path if routing metadata
  is unavailable. That fallback must become one bounded `unmatched` label before
  an untrusted path can reach production metrics.
- Local Prometheus does not cover managed PostgreSQL, IdP/broker, vault,
  certificates, backup, or failover.

These gaps block a claim of complete observability or demonstrated
self-healing, even though the application instrumentation and recovery
mechanisms are implemented.
