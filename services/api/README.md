# Database Security Assurance API

An async, multi-tenant control plane for inventory, security assessments, evidence,
findings, masking governance, access reviews, and private collector job orchestration.
It never stores database passwords or sampled customer values.

## Local development

```powershell
py -3.12 -m venv .venv
.venv\Scripts\pip install -e ".[dev,sqlite,observability]"
$env:ENVIRONMENT="development"
$env:AUTH_MODE="development"
$env:ALLOW_INSECURE_DEV_AUTH="true"
$env:DATABASE_URL="sqlite+aiosqlite:///./assurance.db"
.venv\Scripts\uvicorn assurance_hub.main:app --reload
```

Development requests must include `X-Tenant-ID`, `X-Subject`, and `X-Roles`. In
production the API accepts only a validated OIDC bearer token. All mutation requests
must include a unique `Idempotency-Key` header.

Run tests with `python -m pytest`. Apply PostgreSQL migrations with
`alembic upgrade head`. API documentation is available at `/docs` outside production.

## Security boundaries

- Connector payloads accept vault-style secret references only.
- Connector registration is administrator-only and accepts only credential-free
  `dns://host:port/database` endpoint references. Assigned collectors must heartbeat an enabled
  connector online before its jobs become leasable.
- Product tables include `tenant_id`; queries and foreign-key lookups are tenant scoped.
- PostgreSQL migrations add composite `(tenant_id, id)` foreign keys, forced row-level
  security, transaction-local tenant context, and database-enforced append-only audit events.
- Collector probes come from an immutable allowlist. Arbitrary SQL is not accepted.
- Audit events are append-only and record mutation outcomes.
- The collector plane uses leases, bounded retries, and stale-lease reconciliation.
- Database remediation and production writes are deliberately outside this release.

## Production database roles

Provision `assurance_runtime` as a `NOLOGIN` role before applying migrations, and grant it to
the API login. The migration detects that fixed role and applies least-privilege table grants;
it does not create identities or credentials. Configure `DATABASE_MAINTENANCE_URL` with a
separate, narrowly held PostgreSQL role for the bounded lease/idempotency reconciler. The
maintenance engine is never exposed to request handlers. Both URLs must require TLS in staging
and production, where the maintenance URL is required and its PostgreSQL username must differ
from the request-path username.

Every request transaction sets `app.tenant_id` locally. Forced PostgreSQL RLS then rejects rows
outside that tenant even if an application query omits its tenant predicate. SQLite remains a
test/development target and enables foreign-key enforcement, including the same composite
tenant constraints for databases created from ORM metadata.

## Collector fencing contract

`POST /api/v1/scan-jobs/lease` returns a random UUID `lease_token`. The assigned collector must
send that token to both `/{job_id}/renew` and `/{job_id}/complete`. Reassignment, retry, or stale
lease reconciliation clears/rotates the token, so delayed workers receive `409` and cannot
overwrite a newer attempt.

Only the assigned collector can read
`GET /api/v1/collectors/connectors/{connector_id}/runtime-config`. This endpoint returns an
enterprise secret-manager reference, never resolved credentials. General connector responses
continue to omit `secret_ref`.

Production deployment must give each collector identity access only to its assigned connector's
secret-manager path. Network policy/firewall egress must independently allowlist only the DNS
host and port approved during connector registration. Deployment is not production-ready until
both controls are verified; an API reference is not authority to access another secret or host.

`GET /api/v1/collectors/ready` validates collector authentication and returns only the caller's
collector ID. Both lease and renew use the minimal `CollectorLeaseOut` contract rather than
exposing internal scheduling, deduplication, result, or error fields.

Successful query transport should be reported as `outcome: "collected"`; pass/fail remains the
responsibility of a deterministic versioned evaluator. Probe observations are limited to 100
rows, 25 safe scalar fields per row, and 128 KiB total.

Collector completion cannot claim `passed`, `failed`, or `review_required`. A successful job
must provide exactly one terminal result for every requested allowlisted probe. The API checks
the connector platform, unique probe set, row count, observation structure, and independently
recomputes each canonical evidence digest. A failed job cannot attach probe results.

## Uncertain mutation recovery

Idempotency reservations whose response was not durably recorded are never automatically
deleted or replayed. The reconciler changes expired reservations to `review_required`. Tenant
administrators can list recovery candidates and, after incident review, use the resolve endpoint
to durably reject replay with an append-only audit event. The API intentionally offers no
"reopen" operation because it could duplicate an already committed domain side effect.

## Immutable controls and deterministic evaluation

Administrators publish complete immutable versions through `POST /control-pack-versions`.
The API validates platform probe IDs against the code-reviewed allowlist, calculates canonical
pack/control digests, stores definitions and a GRC outbox event in one transaction, and exposes
no update or delete route. PostgreSQL triggers also reject direct mutation of published packs,
definitions, results, and processed inbox records.

Automated evaluation requires a succeeded `source_job_id`. The evaluator reads the stored job
result; omitted probe data is derived from it and caller-supplied probe data must match it
exactly. Observation fields must be approved by the immutable definition. All currently
publishable definitions require analyst review, so `collected` becomes `review_required`.
Collection errors, unsupported probes, and insufficient privileges can never become passes.

## Atomic assessment runs

Use `POST /assessment-runs` instead of creating an assessment and scan job separately. The
request contains `asset_id`, `connector_id`, `control_pack_version_id`, `run_key`, and optional
`max_attempts`. The API validates every reference and platform before atomically writing the
assessment, allowlisted collector job, and `assessment.queued` outbox event.

The same idempotency key and body replays the stored response. A reused `run_key` returns the
existing run only when all bound inputs match and otherwise fails with `409`.

## Governed exceptions and durable integrations

Finding exceptions require a future expiry and a separate `exception_approver`; a database
constraint also prevents the requester from being recorded as approver. Only one approved
exception may be active for a finding. Approval, revocation, automatic expiry, finding status,
and their GRC outbox records are committed atomically.

The outbox offers lease, renew, and complete operations using rotating UUID fencing tokens,
bounded retry, dead-letter state, and stale-lease reconciliation. The inbox stores only the
canonical payload digest and rejects reuse of a source/message ID with different content. These
are delivery contracts only—no external SIEM, ticketing, or GRC connector is activated here.
