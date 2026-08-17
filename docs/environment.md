# Environment and secret contract

This document defines configuration ownership and safe defaults. It contains no
deployable credentials. Populate secrets only through the approved local secret
file or enterprise secret provider, and never place them in source control,
shell history, tickets, chat, screenshots, build arguments, or telemetry.

## Local development modes

### Visual preview

```powershell
npm ci
npm run dev
```

This starts the site on loopback with an explicitly gated development identity
and labelled, read-only fixture data. It is useful for design and route review;
it does not exercise API persistence.

### Integrated functional mode

Create the API environment once:

```powershell
py -3.12 -m venv services/api/.venv
services/api/.venv/Scripts/python.exe -m pip install -e "services/api[dev,sqlite,observability]"
```

Then run:

```powershell
npm run dev:integrated
```

The launcher performs the following bounded development actions:

1. upgrades the local database through the current Alembic revision;
2. starts the API on `127.0.0.1` with explicitly enabled development auth;
3. seeds the demonstration tenant and immutable control packs idempotently;
4. starts a bounded synthetic metadata collector for only `demo-enterprise` and
   `demo-collector`;
5. starts the console in API mode with a local tenant and role identity.

The synthetic helper uses the real heartbeat, fenced lease, Pydantic completion,
evidence, and governance contracts. It never connects to a source database and
never submits a pass, fail, or score. Successful collection therefore leaves
the assessment in `running` / `review_required` with digest-linked evidence and
a null score for later human review. Idle work polling is limited to once every
two seconds. The launcher explicitly clears `DATABASE_MAINTENANCE_URL` and
`OTEL_EXPORTER_OTLP_ENDPOINT` so inherited shell settings cannot route this
local workflow to an external maintenance database or telemetry service.

Supported overrides are `ASSURANCE_API_PYTHON`,
`ASSURANCE_LOCAL_DATABASE_URL`, and `ASSURANCE_LOCAL_API_PORT`. The defaults use
the repository API virtual environment, a local SQLite file, and API port 8000.
For this workflow, a database override must still be a file-backed
`sqlite+aiosqlite` URL resolving inside `services/api`; PostgreSQL, in-memory,
and out-of-workspace paths fail before migration. The API host is fixed to
`127.0.0.1`, and the helper independently validates the same boundary before it
starts. Do not copy its auth or synthetic-collection flags into another
environment.

### Local MySQL functional and masking mode

```powershell
npm run dev:mysql
```

This development-only launcher reads the local MySQL values from
`../Database/.env`, registers the migrated `insurance_sample` asset, and starts
the real read-only MySQL assessment collector. It deliberately ignores every
Azure SQL setting and never opens an Azure SQL connection.

The launcher may also start one dedicated local masking worker. Its authority
is fixed in code and cannot be broadened by a console form:

| Boundary | Fixed development value |
|---|---|
| Network | `127.0.0.1` / `localhost` only |
| Source | `insurance_sample`, read-only identity and read-only consistent snapshot |
| Target | One server-derived `insurance_sample_masked_<workflow>` per policy, using a separate target-only writer identity |
| Internal staging | Paired `aegisdb_mask_stage_<workflow>`; cleanup can drop only exact worker-owned manifest tables |
| Test reader | `insurance_masked_test_ro`; exactly `SELECT` and `SHOW VIEW` on generated final targets only |
| Size | No more than 500 rows per table |
| Publish | Validate staging, then publish all tables to the final database with one atomic rename |
| Existing final | A new workflow receives a new empty target; interrupted completion may recover only that workflow's exact deterministic target and never rewrites it |
| Mismatch | A mismatched final or ambiguous final/staging state fails closed |
| Evidence | Bounded counts, booleans, and keyed digests only |

Selected sensitive values are transformed before any target insert;
non-sensitive keys and structural fields may be retained in the local masked
copy. Raw rows and values never enter the Hub API, evidence, logs, or browser.
The worker never issues `DROP`, `UPDATE`, `DELETE`, or overwrite operations
against the source or final database. `DROP` is available only for staging
cleanup, and only when each stale table belongs to the exact expected manifest
and has the expected normalized definition. Automated checks prove the source
remained unchanged and verify row counts, the target manifest, masking, and
foreign keys. Those checks create evidence only: they never mark the control
passed and never calculate a score. A human analyst must review the evidence,
choose the control outcome, and finalize the assessment.

Generated source, target-writer, API-token, and evidence-key files remain under
the ignored local secret root and are not printed. This mode is excluded from
Compose, Kubernetes, production collector images, and production promotion.

The generated masked-target test-reader credential is stored under that same
ignored root. Use it only from a loopback development/test application to
verify screens, reports, formats, and relationships. It has no privilege on
`insurance_sample` or any `aegisdb_mask_stage_<workflow>` and cannot write to a
final masked database.

### Compose integration harness

`infra/compose.yaml` is a local image and infrastructure harness for the API,
PostgreSQL, and Prometheus services. Supply `POSTGRES_PASSWORD` and the
matching URL-encoded `DATABASE_URL` from a secure, ignored environment file.

```powershell
docker compose --env-file <secure-env-path> -f infra/compose.yaml config --quiet
docker compose --env-file <secure-env-path> -f infra/compose.yaml up --build --wait
docker compose --env-file <secure-env-path> -f infra/compose.yaml ps
```

Loopback ports are API 8000 and Prometheus 9090. PostgreSQL has no host port.
Compose networking, local passwords, and synthetic identities are not
production authentication, TLS, database, secrets, or isolation controls. Use
`npm run dev:integrated` for the supported local end-to-end console workflow.

The protected web console is deliberately absent from Compose. A production
web build cannot enable the synthetic development identity, and a standalone
container does not provide the private Sites sign-in routes or trusted identity
headers. Adding a web service here would therefore be either unusable or an
authentication bypass.

## Web build and runtime contract

| Variable | Scope | Purpose |
|---|---|---|
| `CONSOLE_DATA_MODE` | Build | `api` for normal builds; `fixture` is accepted only by the explicit local development server |
| `ASSURANCE_API_BASE_URL` | Build | Exact API origin; production requires HTTPS without credentials, query, or fragment |
| `DEPLOYMENT_ENVIRONMENT` | Local build only | Must be `development` for synthetic console identity |
| `CONSOLE_AUTH_MODE` | Local build only | Must be `development` for synthetic console identity |
| `ALLOW_INSECURE_CONSOLE_AUTH` | Local build only | Must be exactly `true`, together with the two preceding gates |
| `CONSOLE_DEVELOPMENT_EMAIL` | Local build only | Display identity for the loopback development console |
| `AEGISDB_DEVELOPMENT_TENANT_ID` | Local API mode only | Synthetic tenant header; ignored unless compile-time local auth is enabled |
| `AEGISDB_DEVELOPMENT_ROLES` | Local API mode only | Synthetic roles; ignored unless compile-time local auth is enabled |
| `AEGISDB_TOKEN_BROKER_URL` | Sites runtime | Exact HTTPS endpoint for per-user API token exchange |
| `AEGISDB_TOKEN_BROKER_CLIENT_ID` | Sites secret | Broker client identity; runtime only |
| `AEGISDB_TOKEN_BROKER_CLIENT_SECRET` | Sites secret | Rotated broker client credential; runtime only |

The web console never accepts a shared production API bearer token. Server-only
code exchanges the trusted Sites identity for a short-lived, user-attributed
bearer token. The broker must derive tenant and roles from enterprise policy and
must not trust browser-supplied email, tenant, or role values. Missing identity,
broker configuration, invalid token shape, or insecure URLs fail closed.

`ASSURANCE_API_BASE_URL` is not a secret, but it is compiled into the web build;
use the correct environment-specific API origin during the Sites build. Broker
credentials are runtime secrets and must never enter the client bundle.

## API runtime contract

| Variable | Required | Purpose |
|---|---:|---|
| `ENVIRONMENT` | Yes | `development`, `test`, `staging`, or `production` |
| `DATABASE_URL` | Yes | Request-path PostgreSQL URI; staging/production must require TLS |
| `DATABASE_MAINTENANCE_URL` | Staging/production | Required TLS PostgreSQL URL for a narrowly held reconciliation role; its username must differ from the request-path username |
| `DATABASE_POOL_SIZE` / `DATABASE_MAX_OVERFLOW` | No | Bounded connection-pool sizing, tuned from load evidence |
| `AUTH_MODE` | Yes | `oidc` in staging/production |
| `ALLOW_INSECURE_DEV_AUTH` | Local only | Must be false outside development/test |
| `OIDC_ISSUER` | Staging/production | Exact HTTPS issuer |
| `OIDC_AUDIENCE` | Staging/production | API audience |
| `OIDC_JWKS_URL` | Staging/production | Exact HTTPS signing-key endpoint |
| `OIDC_TENANT_CLAIM` / `OIDC_ROLES_CLAIM` | No | Enterprise claim names |
| `CORS_ORIGINS` | Yes | Comma-separated exact HTTPS Sites origins; no wildcard with credentials |
| `IDEMPOTENCY_TTL_HOURS` | No | Retention before an unresolved reservation requires review |
| `JOB_LEASE_SECONDS` / `OUTBOX_LEASE_SECONDS` | No | Fenced lease periods; coordinate with collector operation bounds |
| `JOB_RECONCILE_INTERVAL_SECONDS` / `JOB_RECONCILE_BATCH_SIZE` | No | Bounded reconciliation cadence and batch size |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Production | Approved OpenTelemetry collector endpoint |
| `ENABLE_METRICS` | No | Prometheus endpoint switch; enabled by default |
| `SEED_DEMO_DATA` | Local only | Must be false in staging/production |

The request API and maintenance reconciler use separate engines. Staging and
production fail closed unless both distinct TLS URLs are present. The request
path must never receive the maintenance role. Platform/IAM owners provision the
fixed `assurance_runtime` database role; migrations apply least-privilege grants
when that role exists but do not create logins or credentials.

## Collector runtime contract

Collector settings use the `COLLECTOR_` prefix.

| Variable | Required | Purpose |
|---|---:|---|
| `COLLECTOR_ENVIRONMENT` | Yes | Runtime environment; production activates strict transport checks |
| `COLLECTOR_API_URL` | Yes | Exact HTTPS API origin in staging/production |
| `COLLECTOR_COLLECTOR_ID` | Yes | Stable tenant-scoped collector identity |
| `COLLECTOR_TENANT_ID` | Yes | Tenant assigned to that identity |
| `COLLECTOR_TOKEN_FILE` | Staging/production | Projected short-lived API token; not an environment token value |
| `COLLECTOR_CREDENTIAL_ROOT` | Before leasing | Private root populated by the approved secrets integration |
| `COLLECTOR_ENABLE_LEASING` | Yes | Safe default `false`; change only after customer promotion gates |
| `COLLECTOR_POLL_SECONDS` / `COLLECTOR_HEARTBEAT_SECONDS` / `COLLECTOR_LEASE_RENEW_SECONDS` | No | Bounded scheduling and renewal cadence |
| `COLLECTOR_CONNECT_TIMEOUT_SECONDS` / `COLLECTOR_STATEMENT_TIMEOUT_SECONDS` | No | Bounded source operation time |
| `COLLECTOR_MAX_ROWS` / `COLLECTOR_MAX_PAYLOAD_BYTES` | No | Evidence caps; code-enforced maximums are 100 rows and 128 KiB per probe |
| `COLLECTOR_MAX_PARALLEL_JOBS` | No | Per-process source concurrency ceiling |
| `COLLECTOR_SOURCE_RETRY_*` / `COLLECTOR_CIRCUIT_*` | No | Bounded retry and circuit-breaker policy |
| `COLLECTOR_METRICS_HOST` / `COLLECTOR_METRICS_PORT` | No | Local collector metrics listener; base binds loopback |
| `COLLECTOR_SYBASE_ODBC_DRIVER` | Environment-specific | Exact approved SAP ASE ODBC driver name |

The base does not mount source credentials because leasing is disabled. A
protected overlay that enables leasing must also provide an approved
secret-manager mount, environment-specific driver image, target network
allowlist, and retained approval evidence. Secret references identify files by
canonical reference digest; plaintext credentials do not belong in environment
variables.

## Kubernetes and external dependencies

The authenticated web console is hosted privately on Sites and is not a
Kubernetes workload. The base references, but deliberately does not create,
these runtime secrets:

- `assurance-hub-runtime/database-url`;
- `assurance-hub-runtime/database-maintenance-url`;
- `assurance-hub-runtime/collector-token`;
- `assurance-hub-runtime/collector-tenant-id`;
- `assurance-hub-runtime/collector-id`;
- `assurance-hub-runtime/oidc-issuer`;
- `assurance-hub-runtime/oidc-audience`;
- `assurance-hub-runtime/oidc-jwks-url`;
- `assurance-hub-tls` certificate and key.

Provision them through the organization's approved External Secrets, Secrets
Store CSI, Sealed Secrets, or equivalent system. Prefer workload identity and
automatic rotation. Do not enable the default Kubernetes API token.

Before applying an environment overlay:

1. replace all example images with immutable, signed digests;
2. replace every `.example.invalid` host and documentation CIDR;
3. restrict API and collector egress to the minimum approved DNS names, ports,
   and source networks;
4. configure private Sites CORS, ingress, certificate, IdP, broker, vault,
   telemetry, and managed PostgreSQL dependencies;
5. tune replicas, requests, limits, pool sizes, and timeouts from load evidence;
6. keep collector leasing false until the source-specific checklist is signed;
7. render and validate the protected overlay before apply.

```powershell
kubectl kustomize <protected-production-overlay> > rendered-production.yaml
python tools/validate_infrastructure.py --rendered rendered-production.yaml --profile production
```

`infra/kubernetes/overlays/production-template` is structural guidance only. Its
all-zero digest, example hostnames, documentation networks, and template marker
make it intentionally non-deployable.
