# Database Security Assurance Hub architecture

## Purpose and scope

The hub centralizes evidence about encryption, data protection, access security,
and masking posture for Oracle, PostgreSQL, SAP Sybase ASE, and MySQL. It is an
assurance plane. It is not a database proxy, PAM replacement, SIEM, backup
platform, production data-masking engine, or Informatica migration engine.

The initial source interaction is read-only. The collector does not accept
caller-authored SQL, the hub does not store source credentials or sampled
business rows, and the product does not issue automatic remediation statements.
Any future source write requires a separate threat review, approval workflow,
least-privilege identity, rollback design, and customer acceptance.

## Target production topology

The following is the intended production topology, not a claim that these
customer-managed dependencies or the private Sites release are currently
deployed.

```text
Browser
  -> private Sites dispatch and authenticated web console
       -> HTTPS per-user token broker
            -> enterprise TLS ingress
                 -> stateless FastAPI control plane
                      -> managed PostgreSQL metadata/evidence store
                      -> durable integration outbox/inbox

Customer network
  -> outbound-only collector
       -> enterprise vault or secret manager
       -> approved Oracle/PostgreSQL/Sybase endpoint
       -> FastAPI collector endpoints over HTTPS

API and collector
  -> structured logs, Prometheus metrics, optional OpenTelemetry
```

| Component | Responsibility | Scaling unit |
|---|---|---|
| Web | Landing page, authenticated operations UI, API-backed reads and approved mutations; no database credentials | Private Sites worker |
| Token broker | Exchanges the trusted Sites user for a short-lived, tenant- and role-bound API token | Enterprise identity service |
| API | Validation, authorization, inventory, scheduling, governance, evidence, findings, exceptions, audit, and integration delivery state | Stateless pod |
| Collector | Claims fenced work, resolves an approved secret reference, executes allowlisted read-only probes, and normalizes bounded evidence | Stateless worker |
| PostgreSQL | Tenant-scoped metadata, immutable governance records, execution state, evidence, audit, idempotency, outbox, and inbox | Managed HA service |
| Vault/KMS | Source credentials, trust material, and keys | Enterprise managed service |
| Telemetry stack | Logs, traces, metrics, alerts, retention, and on-call routing | Enterprise managed service |

## Identity and trust boundaries

1. In the target deployment, Sites authenticates the user. Server-only console
   code reads the trusted identity and exchanges it through the configured HTTPS broker. The broker,
   not the browser, derives tenant and roles from enterprise policy.
2. The API validates OIDC issuer, audience, signature, expiry, tenant, and role
   claims on every request. Development headers work only behind explicit
   development and insecure-auth gates.
3. Connector registration is administrator-only. Endpoints use a
   credential-free `dns://host:port/database` reference and secrets use an
   approved vault-style reference.
4. Each collector has a stable tenant-scoped identity. It can retrieve only its
   assigned runtime connector configuration, and the API never returns resolved
   credentials.
5. Network policy and the customer firewall remain independent enforcement
   points. An API reference is not authorization to reach an arbitrary host or
   secret path.

## Assessment flow

1. An administrator publishes a complete immutable control-pack version. Probe
   identifiers are checked against the code-reviewed catalog and canonical
   digests are stored with the pack and definitions.
2. A user starts an assessment with one mutation. The API validates the asset,
   connector, platform, control-pack version, and run key, then atomically
   creates the assessment, scan job, and outbox event.
3. An enabled, online, assigned collector claims the job through an expiring
   lease with a random UUID fencing token. Renewal and completion require the
   same token; a stale worker cannot overwrite a later attempt.
4. Before each probe, the collector verifies that enough lease time remains.
   It resolves the approved credential reference, establishes an encrypted
   connection, applies read-only and timeout controls, and executes only the
   immutable platform query catalog.
5. Evidence is normalized to approved scalar fields and bounded by row, field,
   string, probe-payload, and total-job limits. The collector reports an exact
   terminal result for every requested probe.
6. The API revalidates platform and probe coverage, observation structure, row
   count, and canonical evidence digests before accepting completion.
7. In the same fenced transaction, the API selects each control's exact probe
   subset, stores digest-only evidence lineage, creates immutable control
   results, materializes deterministic collection-gap findings, and advances
   assessment collection state. Unsupported sources, insufficient privilege,
   and collection errors cannot become a pass. Current pack definitions require
   analyst review for control conclusions, so collection alone never creates an
   assurance score.
8. Findings and exceptions retain history. Exception approval requires a
   different principal, expires automatically, and produces a transactional
   outbox event.

## Data ownership and database enforcement

The schema owns:

- inventory: `assets` and `connectors`;
- execution: `assessments`, `scan_jobs`, and `evidence`;
- workflow: `findings`, `masking_policies`, and `access_reviews`;
- immutable governance: `control_pack_versions`, `control_definitions`, and
  `control_results`;
- exception lifecycle: `finding_exceptions`;
- delivery: `integration_outbox` and `integration_inbox`;
- security history: `audit_events` and `idempotency_records`.

Tenant-owned relationships use composite `(tenant_id, id)` foreign keys.
PostgreSQL migrations enable and force row-level security, and each request sets
the tenant context transaction-locally. PostgreSQL triggers make audit events,
published control definitions/results, processed inbox records, and successful
scan results append-only or immutable as appropriate. A restricted runtime role
is provisioned outside the repository.

SQLite is supported for deterministic development and migration smoke tests. It
does not prove PostgreSQL RLS, role grants, lock behavior, or concurrent leasing;
those require a real PostgreSQL acceptance environment.

## Idempotency and self-healing

- Mutation idempotency is scoped by tenant, actor, authorization context, route,
  key, and request digest. Completed responses replay exactly. An uncertain
  reservation is retained for audited operator reconciliation and is never
  silently executed again.
- Assessment run keys and deterministic control-result keys prevent duplicate
  logical runs and evaluations.
- Scan and outbox leases use compare-and-set state transitions, UUID fences,
  bounded attempts, backoff, and expiry reconciliation. Exhausted work becomes
  terminal or dead-lettered instead of retrying forever.
- API and collector processes expose separate liveness and readiness checks.
  Kubernetes restart, HPA, disruption-budget, topology-spread, and rolling-update
  policies provide bounded recovery and horizontal scale.
- Self-healing does not mean automatic source remediation. It means safe process
  restart, lease recovery, retry-budget enforcement, and fail-closed dependency
  behavior.

## Observability contract

The API and collector emit structured logs, correlation identifiers, health and
readiness, bounded-label counters/histograms, reconciliation outcomes, fencing
rejections, and optional OpenTelemetry. Metrics use route templates and bounded
enums; tenant, asset, database, connector, and user names are prohibited labels.

The checked-in SLO rules cover API availability and latency, governance-write
failures, elevated scan failures, stalled leased work, and exhausted lease retry
budgets. Production promotion still requires environment telemetry and alerts
for collector heartbeat, source timeouts, outbox delivery, queue age, evidence
freshness, database pools, managed PostgreSQL, vault, certificates, backup, and
failover, plus alert-injection evidence.

## AI and masking boundaries

The authoritative decision path is deterministic and versioned. Generative AI
is not used to mark a control passed or failed, approve an exception, change a
database, or deliver privileged instructions. A future AI assistant may only
summarize already-authorized evidence with citations, redaction, provider/data
residency approval, prompt/version audit, evaluation, and human review; it must
remain outside the control-decision transaction.

The hub records and reviews masking policy metadata. A single local proof path
also exists, but it is not part of the target production topology.

### Development-only local MySQL masking proof

`npm run dev:mysql` may start a dedicated local masker only when every boundary
check succeeds:

- network and source are fixed to the loopback MySQL server and read-only
  `insurance_sample`. Each policy receives a server-derived separate target
  `insurance_sample_masked_<workflow>`; Azure SQL configuration is neither
  loaded nor connected;
- the source identity has read-only access. The target identity can create,
  insert, and select in the final database, while its additional cleanup
  authority is restricted to paired internal
  `aegisdb_mask_stage_<workflow>` databases;
- each source table must contain no more than 500 rows, and the copy stays
  inside one bounded worker operation;
- selected sensitive values are transformed before any target insert;
  non-sensitive keys and structural fields may be retained in the local masked
  copy. Raw rows and values never enter the Hub API, evidence, logs, or browser;
- the worker builds only in the workflow's `aegisdb_mask_stage_<workflow>`. It may `DROP`
  stale staging tables only after their names and normalized definitions match
  the exact worker-owned manifest. Any unexpected staging object fails closed;
- after staged manifest, row, digest, masking, and foreign-key validation, one
  atomic multi-table rename publishes the complete copy to that workflow's
  final target. The worker never issues `DROP`, `UPDATE`,
  `DELETE`, or overwrite operations against the source or final database;
- every new workflow publishes into its own empty final database and never
  overwrites or reuses a prior workflow target. Interrupted API completion may
  recover only that workflow's target when its complete manifest, rows,
  digests, and foreign keys exactly match the deterministic expected result.
  A changed source, mismatched final, or ambiguous final/staging state fails closed;
- automated unchanged-source, row-count, manifest, masking, and foreign-key
  checks create evidence only. They never pass a control and never calculate an
  assurance score. A human must record the control decision and finalize the
  assessment.

This proof is a repeatable local workflow, but does not constitute a general
customer masking engine or
acceptance. A separately approved non-production pilot must still prove
classification accuracy, referential integrity, application behavior,
approval, rollback, and safe data handling before any production execution
capability is introduced.

## Deployment boundary

- Private Sites is the supported production web-console runtime.
- `infra/kubernetes/base` contains the API and driver-free collector only. The
  base has an exact, machine-validated 17-resource contract.
- The dedicated local MySQL masker is excluded from Kubernetes, Compose, and
  production collector images; it is started only by the loopback development
  launcher.
- The base intentionally sets collector leasing to false and omits a source
  credential mount. A protected overlay may enable both only after the customer
  collector gates pass.
- `infra/kubernetes/overlays/production-template` is non-deployable. It contains
  placeholder image digests, hostnames, and documentation networks.
- Managed PostgreSQL, identity, token broker, vault/KMS, PKI, private DNS,
  certificate issuance, backup, telemetry, signed-artifact admission, and real
  environment overlays are external platform responsibilities.
