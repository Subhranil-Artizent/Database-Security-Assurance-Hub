# Implementation status

Date: 15 August 2026

## Executive status

The repository now contains the cross-phase application foundation: a live
API-backed console, tenant-fenced control plane, executable outbound collector,
immutable control packs and results, governed exceptions, durable integration
delivery state, and production-oriented SRE contracts. It is suitable for local
demonstration and for controlled customer-environment integration work.

It is not yet a customer-accepted production deployment. Production acceptance
depends on identity, vault, network, database, driver, masking-pilot, operations,
and security evidence that cannot be created truthfully in this local workspace.

## Locally validated capabilities

### Web and identity boundary

- The existing landing page is preserved and links to a protected console.
- Console loaders use the API repository in normal builds. Fixture data is
  available only through the explicit local development server and mutations
  fail read-only in that mode.
- API-backed asset registration, atomic assessment start, per-control review,
  assessment finalization, finding updates, masking governance, and per-workflow
  local copy requests use same-origin action handlers, request-size/content-type
  checks, CSRF protections, idempotency keys, and bounded retries.
- `npm run dev:integrated` includes a fail-closed synthetic metadata collector
  confined to the seeded demo tenant, demo collector, loopback API, and a local
  SQLite file. It exercises the production heartbeat/lease/completion contracts
  and creates digest-linked evidence, but never queries a customer database or
  assigns pass/fail/score; assessments stop at analyst review required.
- Loading, error, empty, stale, and pagination states are present across the
  console routes. Data discovery reports an explicit unavailable state because
  no discovery API is claimed.
- The console includes next-action guidance, explicit masking workflow stages,
  plain-language score interpretation, friendly recovery messages, and a
  printable management report. Completed masking workflows can be archived in
  the Hub without deleting their evidence or local target databases.
- Production console authentication requires an HTTPS per-user token broker.
  Shared bearer-token configuration is not supported. Missing identity or
  broker configuration fails closed.

### API, governance, and tenancy

- FastAPI boundaries use Pydantic models that forbid unknown fields and bound
  identifiers, collections, evidence, URLs, and mutation payloads.
- Production OIDC validates issuer, audience, signature, expiry, tenant, and
  role claims. Development headers require three explicit development gates.
- Idempotency is scoped by tenant, actor, authorization context, route, key,
  method, and request digest. Uncertain commits move to review rather than
  being silently replayed.
- PostgreSQL migrations define composite tenant foreign keys, forced RLS with
  transaction-local tenant context, restricted runtime grants, append-only
  audit events, and immutable governance/result triggers.
- Four immutable control packs provide 16 controls across Oracle,
  PostgreSQL, Sybase, MySQL, and the four requested domains.
- Atomic assessment-run creation binds asset, connector, immutable control-pack
  version, scan job, and outbox event in one transaction.
- Fenced scan completion atomically advances the assessment, evaluates each
  automated control from only its approved probe subset, stores digest-only
  evidence lineage, creates deterministic immutable results and collection-gap
  findings, and publishes deduplicated outbox state. Collection alone never
  becomes a pass or an assurance score.
- Finding exceptions implement request, separate approval, rejection,
  revocation, automatic expiry, and one-active-exception constraints.
- Transactional outbox/inbox state implements deduplication, lease fencing,
  bounded retries, stale-lease reconciliation, and dead-letter handling. No
  external SIEM, ticketing, or GRC endpoint is activated by the repository.

### Collector and source safety

- The collector is outbound-only and consumes exact, minimal lease contracts.
- An enabled connector must be assigned to the authenticated collector and
  heartbeat online before work is leasable.
- Probe SQL is an immutable code catalog; caller-authored SQL is rejected by
  design. Connection, statement, row, field, value, probe, total-job,
  concurrency, retry, and circuit-breaker limits are bounded.
- Oracle, PostgreSQL, SAP Sybase, and MySQL adapters classify unsupported features,
  insufficient privilege, and transient failures. They enforce encrypted
  connection contracts and read-only/session timeouts where the platform
  supports them.
- Lease-budget checks, UUID fencing, exact terminal probe coverage, evidence
  digest revalidation, and exact-body completion retries prevent stale or
  ambiguous completion from being treated as success.
- The checked-in collector container intentionally installs no database
  drivers. Unit tests use driver-independent fakes and do not claim a customer
  database certification.

### Development-only local MySQL masking proof

- `npm run dev:mysql` is the only launcher for the dedicated local masker. It
  fixes the network boundary to loopback, the source to read-only
  `insurance_sample`, derives one `insurance_sample_masked_<workflow>` target
  per policy, and fixes the maximum to 500 rows per table. Azure SQL settings
  are not loaded and Azure SQL is never connected.
- The source and target use separate least-privilege local identities. The
  final writer has no update, delete, or drop authority. Additional create and
  cleanup privileges apply only to paired internal
  `aegisdb_mask_stage_<workflow>` databases.
- Selected sensitive values are transformed before any target insert;
  non-sensitive keys and structural fields may be retained in the local masked
  copy. Raw rows and values never enter the Hub API, evidence, logs, or browser.
- Stale staging tables can be dropped only when they match the exact
  worker-owned manifest and normalized definitions. The worker validates the
  staged copy and publishes it to the final database with one atomic
  multi-table rename. It never issues `DROP`, `UPDATE`, `DELETE`, or overwrite
  operations against the source or final database.
- Each new workflow publishes to a separate empty final database. A
  publish/completion gap accepts only that workflow's existing final after an
  exact manifest, row-set, digest, and foreign-key match. A changed source,
  mismatch, or ambiguous final/staging state fails closed.
- Automated source-unchanged, masking, row-count, manifest, and foreign-key
  checks can complete the copy evidence. They do not pass the masking control
  or create a score; an analyst decision and assessment finalization remain
  mandatory.
- The local proof is excluded from the standard collector, production images,
  Compose, and Kubernetes. It is demonstration evidence, not customer or
  production acceptance.

### Reliability and delivery contracts

- JSON logs, request/run correlation, liveness, dependency readiness,
  Prometheus metrics, bounded labels, optional OpenTelemetry, and background
  reconciliation are implemented.
- The Kubernetes base contains exactly 17 API/collector resources, including
  separate identities, deny-by-default networking, hardened pod settings,
  rolling updates, topology spread, disruption budgets, and autoscaling.
- The production overlay template is structurally validated but deliberately
  non-deployable. Collector leasing defaults to false and no source credential
  mount is present in the base.
- SLO recording and alert rules are machine validated. They are engineering
  targets until an environment proves measurement, routing, response, and
  recovery.

## Verification record

The following checks have passed in the current workspace:

| Area | Local result |
|---|---|
| Web lint, TypeScript compilation, production build, rendered-route, accessibility, security, and architecture tests | Pass |
| API Ruff formatting/lint, strict mypy, and pytest | Pass |
| Collector Ruff formatting/lint, strict mypy, and pytest | Pass |
| Alembic empty-database upgrade through `20260812_0004` | Pass on local SQLite; PostgreSQL SQL also renders offline |
| Control-pack validation and unit tests | Pass; 4 packs and 16 controls use approved probes |
| Kubernetes source-policy validation | Pass; exactly 17 intended resources |
| Infrastructure policy unit tests | Pass |
| Observability contract validation | Pass; 5 recording rules and 9 alerts |

These local results do not substitute for a successful protected CI run or a
customer acceptance environment.

## CI-only gates

The quality workflow defines the following additional gates, but they count as
evidence only after the workflow succeeds for the promoted revision and retains
its artifacts:

- reproducible package and container builds;
- dependency, filesystem, configuration, and container vulnerability scans;
- Kustomize rendering and strict Kubernetes schema checks;
- Prometheus configuration and rule validation in the pinned tool image;
- CycloneDX SBOM generation and rendered-manifest retention.

Docker, Kubernetes, kubeconform, Prometheus tooling, Trivy, Syft, artifact
signing, and admission enforcement were not all available for local execution.
No successful CI run is claimed here.

## Customer and environment promotion gates

The following remain open and block a production claim:

- representative Oracle, PostgreSQL, and Sybase instances, approved versions,
  drivers, license terms, read-only grants, TLS trust, and negative-write tests;
- enterprise IdP claims, Sites token broker, vault/KMS, private DNS and routing,
  source CIDR allowlists, credential rotation, and workload identity;
- managed PostgreSQL testing for forced RLS, runtime-role restrictions,
  concurrent leasing, failover, backup/restore, and N-1 compatibility;
- golden evidence datasets, control decision calibration, false-positive review,
  source workload budgets, and load/soak testing;
- protected immutable image publication, signatures, provenance, admission
  verification, penetration testing, and exception review;
- production telemetry retention, queue/freshness/database metrics, alert
  routing, alert injection, on-call acknowledgement, and recovery drills;
- customer-approved non-production masking execution that proves referential integrity,
  application behavior, approval, rollback, and absence of raw values in hub
  storage and telemetry; the fixed local proof does not close this gate;
- live SIEM/ticketing/GRC adapters with customer authentication, authorization,
  rate limits, replay tests, and reconciliation;
- private Sites publication. Publication remains blocked while Sites is not
  enabled for this workspace.

## Deliberate exclusions

- Informatica migration is paused and not implemented.
- Automatic production remediation and user-authored SQL are prohibited.
- Source credentials, private keys, vault tokens, and source row samples are
  prohibited from hub storage. The development masker may hold the bounded raw
  rows in memory only for the duration of its local worker operation; it must
  not export them to the API, evidence, logs, or browser.
- Generative AI is not in the authoritative control, exception, remediation,
  or execution path. Any future AI assistance requires a separate governed,
  evidence-grounded design and human review.

The authoritative remaining gates are in
[the phased acceptance checklist](phased-acceptance-checklist.md).
