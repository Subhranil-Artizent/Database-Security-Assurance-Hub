# Operations runbook

## Supported operating modes

- `npm run dev` is a local visual preview. It uses explicitly labelled,
  read-only fixtures and does not prove API behavior.
- `npm run dev:integrated` is the supported local functional path. It applies
  migrations, starts the API on loopback, seeds the demonstration tenant and
  control packs idempotently, runs a development-only synthetic metadata
  collector, and runs the console against the API. The helper never queries a
  customer database and leaves collected assessments at analyst review required
  with no score.
- `npm run dev:mysql` is the development-only local MySQL path. It connects only
  to loopback `insurance_sample` with a read-only source identity. Its separate
  local masker transforms selected sensitive values before target insert and
  may retain non-sensitive structural fields in a copy of at most 500 rows per
  table. Each workflow builds in a paired `aegisdb_mask_stage_<workflow>`,
  validates the staged copy, and publishes once to its server-derived
  `insurance_sample_masked_<workflow>` target with an atomic rename. Raw rows
  and values never enter the Hub API, evidence, logs, or
  browser. Automated checks still require human review before any pass/fail
  decision or score. Azure SQL configuration is ignored and Azure SQL is never
  connected.
  The launcher also rotates a loopback-only `insurance_masked_test_ro`
  credential with exactly `SELECT` and `SHOW VIEW` on generated final masked
  databases and no source or staging privileges. Use it only for read-only application
  utility testing; privacy acceptance still requires an authorized reviewer.
- Private Sites plus the enterprise token broker is the supported production
  web boundary. Kubernetes hosts the API and collectors, not the web console.
- The Kubernetes collector is a safe standby by default:
  `COLLECTOR_ENABLE_LEASING=false`. Do not enable it until the customer source,
  driver, vault, PKI, network, privilege, and workload gates are approved.

The local modes are for engineering validation. They are not substitutes for
the production identity, PostgreSQL, database-driver, network, or recovery
acceptance evidence.

## Service-level indicators

Measure availability using successful non-maintenance API requests, latency at p50/p95/p99, fresh collector heartbeats, successful assessment completion, queue age and evidence-write durability. Initial targets must be confirmed with stakeholders; recommended starting objectives are 99.9% monthly API availability, p95 read latency below 500 ms, and 99% of scheduled assessments starting within 15 minutes.

Error budgets govern release pace. A breached budget pauses non-remediation releases until reliability recovers.

The calculation, burn windows, recovery proposals and known missing telemetry
are authoritative in [the SLO contract](slo-and-reliability.md). Do not infer
collector or evidence-freshness health from API availability alone.

## Triage sequence

1. Confirm scope: tenant, region, environment, API/web/collector, and first observed time in UTC.
2. Check deployment changes, health/readiness, replica availability, HPA saturation, queue age and dependency status.
3. Correlate using request or run ID; do not search logs using credentials or sensitive values.
4. Contain impact. Pause the affected connector or control pack before scaling collectors if source load is involved.
5. Recover through rollback or dependency failover. Replay a completed request
   with its original idempotency key; escalate a stale `pending` reservation for
   reconciliation instead of inventing a new key.
6. Validate user-visible behavior and evidence consistency, then document timeline and follow-up actions.

## Common incidents

### API is unavailable

- Confirm ingress, certificate and API readiness separately.
- If pods are unhealthy, inspect structured error counts and dependency probes. Never relax readiness to restore traffic.
- Roll back the latest deployment if errors correlate with the release.
- If PostgreSQL is unavailable, engage the managed-database runbook; keep API unready until consistency is assured.

### API error budget burn

- Confirm the alert has request volume and is not caused by a missing target.
- Compare the 5-minute, 30-minute, 1-hour and 6-hour 5xx ratios with the latest
  deployment, database failover, certificate and IdP events.
- Freeze non-remediation releases. Roll back the application digest when the
  burn began with a release and its database migration is backward compatible.
- Close the incident only after both burn windows recover and a synthetic API
  transaction succeeds from the supported private path.

### API latency is high

- Check pod CPU/memory, database pool saturation, PostgreSQL locks and ingress latency.
- Separate read latency from queued assessment duration; never increase source
  database concurrency to repair control-plane latency.
- Scale only within the tested connection budget. Roll back a regressing release
  before increasing limits.

### Collector heartbeat is stale

- Check process health, API reachability, token expiry, vault reachability and network policy.
- Expired leases are safe to reclaim. Do not manually submit a second scan with a new idempotency key.
- Restart the collector through the deployment controller. Rotate the collector credential if compromise is suspected.

### Collector job failures are elevated

- Group failures by bounded platform, control-pack version and outcome using run
  IDs; never add asset/database names as metric labels.
- Disable the affected control pack or asset schedule before retrying if source
  workload, privileges or query compatibility may be involved.
- Do not reset attempt counts or create a new idempotency key. Requeue only
  through the audited recovery operation after the cause is corrected.

### Collector work is stalled

- Compare leased/completed counters, lease expiry and collector process state.
- Verify API, token, Vault and network reachability, then inspect the current
  lease owner. Do not allow a stale worker to complete a re-leased job.
- The entrypoint, fencing, renewal, and exact completion contracts are
  implemented. If customer Phase 2 gates are incomplete, keep leasing disabled.
  If they are complete, pause leasing first, allow active statements to reach
  their bounded timeout, reconcile leases, and resume one collector cohort.

### Source database impact

- Disable scheduling for the affected asset and allow in-flight statement timeout/cancellation to complete.
- Notify the database owner and capture run/control-pack identifiers.
- Do not retry until query plan, limits and maintenance window are reviewed on a production-like system.

### Development local masking copy fails

- Confirm the process was started by `npm run dev:mysql`, the API and MySQL
  endpoints are loopback, the source is exactly `insurance_sample`, and the
  requested target/staging pair matches `insurance_sample_masked_<workflow>`
  and `aegisdb_mask_stage_<workflow>`. Stop the local launcher if any boundary differs;
  do not substitute an Azure SQL or remote endpoint.
- Do not bypass a final-state check, truncate a final database, or add an
  overwrite flag. Each new workflow must receive a new empty final database.
  A publish/API-completion gap may accept only that workflow's existing final
  when its complete manifest, rows, digests, and foreign keys exactly match the
  deterministic expected result.
- Staging cleanup is automatic only for stale tables whose names and normalized
  definitions match the exact worker-owned manifest. Do not manually clean an
  unexpected object to force the job forward. A mismatched final or ambiguous
  final/staging state is a deliberate fail-closed result; preserve it for
  investigation.
- Confirm the read-only source digest is unchanged and no raw row or value
  appeared in API evidence, logs, or the browser. Rotate local secrets and stop
  the local masking path if that boundary was violated.
- Confirm that selected sensitive values were transformed before staging
  insert. Non-sensitive keys and structural fields may remain in the local
  masked copy. The worker must never issue `DROP`, `UPDATE`, `DELETE`, or
  overwrite operations against the source or final database; only exact
  staging cleanup may use `DROP`.
- Automated check success is not a control pass. Complete the analyst decision
  and finalization workflow; never patch a score or mark the assessment passed
  from worker output.

### Evidence or audit write failure

- Treat audit failure as a security incident. Stop administrative mutations if durable audit cannot be guaranteed.
- Preserve application and database logs according to evidence-handling procedure.
- Reconcile assessment run and control-result identifiers after recovery; do not fabricate missing evidence.

### Idempotency reservation requires review

- A reservation in `review_required` means the API could not prove whether the
  domain mutation committed. Never retry it with a new key and never delete the
  reservation to force replay.
- Correlate the reservation with audit, domain, database, and request records.
  Determine whether the intended resource already exists and whether its body
  matches the original request digest.
- Use the administrator recovery endpoint only after incident review. The
  supported resolution durably rejects replay and appends an audit event; there
  is deliberately no automatic reopen operation.

### Integration delivery is stalled

- Inspect outbox status, lease owner, lease expiry, attempts, destination, and
  deduplication key. Do not edit an event payload or generate a second event for
  the same logical delivery.
- Restart the integration worker only after its destination credentials,
  allowlist, rate limit, and idempotency behavior are healthy. Expired leases
  are reconciled automatically; exhausted events remain dead-lettered for
  operator review.
- A completed inbox message is immutable. Reuse of a source/message identifier
  with different content is a security and integration incident.

### Suspected credential exposure

- Revoke/rotate first, then investigate. Disable the connector until the read-only grant is revalidated.
- Search audit and source authentication logs using identity and time, never the secret.
- Rebuild affected images if a secret may have entered a layer; deleting the visible file is insufficient.

## Deployment and rollback

- Deploy immutable image digests after CI, security scans and migration review pass.
- Apply backward-compatible database migrations before new code. Destructive migrations require expand/migrate/contract across releases.
- Observe readiness, errors, latency, saturation and scan success during a staged rollout.
- Roll back application images when thresholds are exceeded. Do not roll back a database migration unless its tested recovery procedure explicitly supports it.

Before a production apply, retain the `--profile production` infrastructure
validation result, strict schema result, rendered-manifest digest, signed image
digest, SBOM, vulnerability result, migration plan and approver identities. The
private Sites web deployment is independent; never add a web Deployment to the
Kubernetes rollback plan.

During progressive rollout, stop when readiness falls, either availability burn
alert fires, p95 read latency breaches for 15 minutes, governance writes fail or
source workload exceeds the approved budget. Roll back to the last signed digest
and record the exact UTC decision time.

### Collector enablement and kill switch

Before changing `COLLECTOR_ENABLE_LEASING` to `true`, retain approval for the
exact collector image digest, driver versions, database/version matrix, secret
path, target DNS names and ports, TLS trust, read-only grants, negative-write
test, statement/row/payload limits, maintenance window, and database owner.

Enable one collector cohort and one non-critical pilot asset first. Observe API
readiness, heartbeat age, leases, statement timeouts, source load, collection
outcomes, evidence size, and fencing rejections through at least one complete
assessment window.

The kill switch is to set leasing false in the protected overlay and roll out
that configuration. It stops new claims; it does not cancel an in-flight driver
call. Allow the bounded statement timeout and pod termination grace period to
complete, then reconcile expired leases before resuming. Disable the connector
or assessment schedule as an additional source-specific containment step.

## Backup and recovery

Production PostgreSQL requires encrypted continuous backup, cross-zone copies, point-in-time recovery and quarterly restore exercises. Define recovery point and recovery time objectives with data owners before go-live. A successful backup job is not proof of recoverability; record restore duration and integrity checks.

Evidence exports with regulatory retention should use immutable object storage. Deletion follows the approved retention policy and is audited.

### Restore exercise

1. Record the selected recovery timestamp, expected RPO/RTO and backup identity.
2. Restore into an isolated account/network with production egress disabled.
3. Apply no ad-hoc schema changes. Confirm the Alembic revision and application
   compatibility using the signed recovery release.
4. Re-enable the restricted runtime role and PostgreSQL tenant policies before
   running any application smoke test.
5. Reconcile tenant row counts, audit sequence/time bounds, idempotency states
   and sampled evidence digests against the source backup inventory.
6. Run authenticated health, tenant-isolation and read-only dashboard tests.
7. Record achieved RPO/RTO, integrity exceptions, owners and due dates. Destroy
   the isolated restore according to the approved handling procedure.

### Regional recovery gate

Promote the recovery region only after DNS/certificates, IdP, Vault, managed
PostgreSQL, immutable evidence storage and telemetry are healthy. Collectors must
remain paused until the recovered queue and leases are reconciled. Resume one
approved collector cohort first, then expand only while source budgets and the
error budget remain healthy.

## Safe maintenance

- Drain collectors before changing query packs.
- Rotate database and collector credentials without downtime using overlap, validate the new identity, then revoke the old one.
- Use PodDisruptionBudgets and one workload at a time for voluntary maintenance.
- Test certificate renewal at least 30 days before expiry and alert before that window.

## Post-incident requirements

For severity 1/2 incidents, record impact, exact UTC timeline, detection gap, technical and organizational causes, recovery, evidence references, accountable actions and due dates. Focus on systemic improvement; never place secrets or sensitive database contents in the report.
