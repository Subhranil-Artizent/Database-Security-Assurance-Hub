# Phased delivery and acceptance checklist

Each phase separates repository delivery from environment acceptance. A checked
item means the stated code or local contract exists. It does not imply that a
customer environment has accepted the phase. Production requires every open
customer, security, operational, and release gate to close with retained
evidence and owner sign-off.

## Implementation snapshot - 15 August 2026

- Cross-phase application code is delivered for the live console, tenant-aware
  API, collector orchestration, immutable controls/results, exception lifecycle,
  durable integration delivery, and SRE deployment contracts.
- Local tests and validators are green. Protected CI, real PostgreSQL, database
  drivers, customer databases, identity, vault, network, load, and recovery
  evidence remain separate gates.
- The Kubernetes base intentionally keeps collector leasing disabled. Enabling
  it without the Phase 2 customer gates is an unsupported configuration.
- Masking policy governance and repeatable per-workflow development-only local
  MySQL masking exist. No production masking executor exists. Generative AI is
  deliberately outside authoritative decisions and privileged actions.
- Sites publication is blocked because Sites is not enabled for this workspace.

## Phase 0 - discovery and guardrails

- [x] Record Informatica migration and automatic remediation as out of scope.
- [x] Define repository architecture, threat model, data-handling boundary,
  environment contract, initial SLOs, and promotion sequence.
- [ ] Inventory customer database versions, editions, environments, owners,
  criticality, data residency, and network paths.
- [ ] Confirm pilot assets and approved read-only privilege matrices for Oracle,
  PostgreSQL, and Sybase.
- [ ] Approve the architecture, threat model, DPIA, retention policy, recovery
  objectives, maintenance windows, and non-functional requirements.
- [ ] Confirm ownership for IdP/token broker, vault/KMS, managed PostgreSQL,
  private networking, SIEM, ticketing, telemetry, and on-call response.

## Phase 1 - platform foundation

### Repository delivery

- [x] Strict Pydantic request, response, configuration, evidence, and collector
  models reject unknown or out-of-bound data.
- [x] Production configuration fails closed without distinct TLS request and
  maintenance PostgreSQL URLs and complete OIDC issuer, audience, and HTTPS
  JWKS settings.
- [x] Composite tenant foreign keys, forced PostgreSQL RLS, transaction-local
  tenant context, restricted runtime grants, and append-only audit triggers are
  defined in migrations.
- [x] Idempotency is tenant-, actor-, authorization-, route-, key-, method-, and
  payload-scoped; uncertain state requires audited reconciliation.
- [x] Health/readiness, structured logs, metrics, optional traces, security
  headers, and bounded error envelopes are implemented.
- [x] The 17-resource API/collector Kubernetes base passes local source policy
  validation and includes hardened workload, scaling, disruption, and network
  controls.

### Acceptance gates

- [ ] Protected CI passes web, API, collector, package, rendered manifest,
  schema, scan, and SBOM jobs for the promoted revision.
- [ ] Real PostgreSQL negative tenant-isolation tests prove RLS and runtime-role
  behavior under concurrent connections.
- [ ] Enterprise SSO/RBAC tests cover every role, tenant boundary, token failure,
  and privileged action.
- [ ] Restore, rollback, certificate rotation, and secret rotation are exercised
  in a representative non-production environment.

## Phase 2 - collectors and inventory

### Repository delivery

- [x] Outbound collector supports strict runtime configuration, projected API
  tokens, vault-style secret references, credential-free endpoints, and
  authenticated runtime-config retrieval.
- [x] Server-owned Oracle, PostgreSQL, Sybase, and MySQL probe catalogs prohibit
  caller-authored SQL and bound connection, statement, rows, fields, values,
  payload, concurrency, retries, and circuit state.
- [x] UUID lease fencing, renewal, exact terminal probe coverage, lease-budget
  checks, completion retry, stale-lease reconciliation, and retry exhaustion are
  implemented.
- [x] Unsupported sources, missing drivers, insufficient privileges, collection
  errors, and transient failures are explicit outcomes and never false passes.
- [x] Collector leasing defaults to false in settings and Kubernetes.

### Acceptance gates

- [ ] Approved drivers and license terms are captured in environment-specific,
  signed collector images.
- [ ] One representative Oracle, PostgreSQL, and Sybase version connects through
  the approved vault and PKI using a least-privilege read-only identity.
- [ ] Negative-write tests prove that collector identities cannot modify data,
  schema, configuration, grants, or audit state.
- [ ] Customer firewalls and workload identity independently restrict each
  collector to approved database endpoints and secret paths.
- [ ] Failure, partition, duplicate delivery, and source-load tests prove safe
  recovery without orphaned work or material production impact.

## Phase 3 - assessment controls

### Repository delivery

- [x] Four versioned immutable packs contain 16 controls covering encryption,
  data protection, access security, and masking posture on all four platforms.
- [x] Publishing validates platform probe IDs, allowed evidence fields, canonical
  digests, and immutability; no update or delete route exists.
- [x] Atomic assessment start binds the asset, connector, pack version, run key,
  scan job, and outbox event.
- [x] Evaluation binds to a stored successful job, generates a deterministic
  result key, preserves evidence provenance, and requires analyst review for the
  current definitions.
- [x] Fenced completion atomically materializes digest-only evidence lineage,
  per-control collection results, deterministic collection-gap findings, and
  assessment collection state without inferring an assurance score.
- [x] Findings, evidence, pack versions, control results, and collector outcomes
  are tenant scoped and historically traceable.

### Acceptance gates

- [ ] Golden datasets and supported database-version matrices validate every
  expected outcome and false-positive/false-negative tolerance.
- [ ] Security, DBA, risk, and audit owners review severity, applicability,
  evidence requirements, guidance, and control-pack release procedure.
- [ ] Production pack disable/rollback and stale-evidence handling are exercised.

## Phase 4 - live console and workflow

### Repository delivery

- [x] Normal builds load overview, assets, assessments, findings, evidence,
  access, masking, connectors, and control packs from the API.
- [x] Asset registration, atomic assessment start, finding updates,
  control-by-control analyst decisions, assessment finalization, and governed
  masking actions make bounded idempotent API mutations.
- [x] Console routes include loading, failure, empty, stale, pagination,
  responsive, keyboard, and accessible states without regressing the landing
  page.
- [x] Production authentication exchanges the trusted Sites user through an
  HTTPS token broker and rejects shared or missing credentials.
- [x] Fixture mode is restricted to local development and is clearly read-only.

### Acceptance gates

- [ ] Customer Sites, IdP, broker, API ingress, CORS, tenant claims, and role
  policy pass end-to-end positive and negative tests.
- [ ] Data-discovery API and UX are implemented only after its evidence and
  privacy design is approved; the current live route reports unavailable.
- [ ] Filters, exports, and accessibility are validated at target estate volume
  with tenant-leakage tests.
- [ ] Product, security, DBA, and audit users complete workflow acceptance.

## Phase 5 - exceptions, masking, and integrations

### Repository delivery

- [x] Finding exceptions support request, separate approval, rejection,
  revocation, one active approval, expiry, and transactional audit/outbox state.
- [x] Integration outbox/inbox supports canonical deduplication, fenced leases,
  bounded retry, stale recovery, and dead-letter state.
- [x] Masking policy metadata can be recorded and reviewed without storing source
  row values.
- [x] A dedicated development-only local worker can repeatedly create bounded
  copies from read-only `insurance_sample`, using a paired internal
  `aegisdb_mask_stage_<workflow>` and separate
  `insurance_sample_masked_<workflow>` final for every policy on the same
  loopback MySQL server. It accepts no browser-selected database, endpoint, row
  cap, SQL, or credentials; enforces at most 500 rows per table; transforms
  selected sensitive values before target insert; may retain non-sensitive keys
  and structural fields unchanged; and sends no raw rows or values to
  the Hub API, evidence, logs, or browser. Staging cleanup can drop only exact
  worker-owned manifest tables, publish is one atomic rename, and the worker
  never drops, updates, deletes, or overwrites the source or final database. An
  existing final is accepted only to recover the same interrupted workflow
  after an exact deterministic verification and is never rewritten;
  changed-source, mismatched, or ambiguous state fails closed. Automated
  evidence still requires mandatory human review and cannot pass or score a
  control.
- [x] AI is excluded from control decisions, exception approvals, remediation,
  masking execution, and privileged integration actions.

### Acceptance gates

- [ ] A non-production masking pilot proves classification accuracy, referential
  integrity, application behavior, approval, rollback, and safe data handling.
- [ ] A production masking executor is implemented only after the pilot design
  is approved. The fixed local proof is never promoted and does not satisfy this
  gate.
- [ ] SIEM, ticketing, and GRC adapters are implemented and tested with customer
  authentication, authorization, idempotency, rate limits, replay, and
  reconciliation. The repository currently provides delivery state only.
- [ ] Any future AI assistant passes privacy, residency, security, redaction,
  grounding, evaluation, prompt/version audit, and human-review gates while
  remaining outside the authoritative decision transaction.

## Phase 6 - production readiness and rollout

### Repository delivery

- [x] Production-template validation rejects placeholder/mutable images,
  example hosts, documentation CIDRs, broad egress, embedded secrets, unsafe
  pods, and Kubernetes web workloads.
- [x] SLO recording rules and alerts cover baseline API availability/latency,
  governance writes, scan failures, stalled leases, and exhausted retry budgets.
- [x] CI definitions include package/container builds, scans, Kubernetes schema
  validation, Prometheus validation, and SBOM retention.
- [x] Runbook procedures cover containment, lease recovery, uncertain
  idempotency, outbox delivery, rollback, restore, regional recovery, and the
  collector kill switch.

### Acceptance gates

- [ ] Independent penetration, architecture, dependency, container, and threat
  reviews have no unaccepted critical/high findings.
- [ ] Images are signed, SBOMs and provenance retained, digests pinned, and
  admission enforcement validated in the protected release path.
- [ ] Capacity, load, and soak tests prove SLOs and source workload budgets at
  forecast peak plus approved headroom.
- [ ] Multi-zone failure, collector loss, queue replay, token/secret rotation,
  backup restore, regional recovery, and application rollback are exercised.
- [ ] Critical alerts are injected, delivered, acknowledged, and recovered by
  the named 24x7 owner within the approved response objective.
- [ ] A protected production overlay passes policy and schema validation with no
  placeholders, unsigned images, world-open egress, or Kubernetes web workload.
- [ ] Private Sites publication succeeds and the production console-to-API
  identity path passes end-to-end smoke and tenant-isolation tests.
- [ ] Operational, security, DBA, audit, product, and data-protection owners sign
  off a limited pilot before any additional critical database is onboarded.
