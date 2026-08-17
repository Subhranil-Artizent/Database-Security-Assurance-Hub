# Threat model

## Scope and protected assets

This model covers the Sites web application, token-broker boundary, API,
private collectors, the development-only local MySQL masker, metadata database,
control packs, evidence, integration delivery, telemetry, build artifacts, and
their trust relationships. Protected assets are source credentials, source-row
confidentiality during local masking, TLS trust, security evidence, tenant
boundaries, identity and authorization state, audit history, control integrity,
exception decisions, delivery state, and production database availability.

The model assumes an enterprise IdP/token broker, secrets manager/KMS, private
networking, TLS ingress, managed PostgreSQL, container platform, artifact
registry, and observability service. Those dependencies require their own
threat models and acceptance evidence.

## Principal threats and controls

| Threat | Impact | Implemented controls | Remaining treatment |
|---|---|---|---|
| Stolen or forged user token | Unauthorized evidence or mutation access | OIDC issuer/audience/signature/expiry checks; role dependencies; short-lived per-user broker contract; fail-closed production config; audit | Customer MFA/session policy, broker implementation, revocation and replay drills |
| Browser identity spoofing | Cross-tenant or privileged API access | Server-only trusted Sites identity; browser input is not used to derive tenant/roles; no shared production token | End-to-end Sites/broker negative tests and trusted-header boundary review |
| Tenant-scope bypass | Cross-customer disclosure or corruption | Tenant-scoped API queries; composite tenant FKs; transaction-local context; forced PostgreSQL RLS; tenant-scoped idempotency; negative unit tests | Real PostgreSQL restricted-role and concurrency tests plus independent penetration testing |
| Collector confused deputy | Access to an unassigned host or secret | Admin-only credential-free connector registration; assigned runtime config; enabled/online lease gate; approved vault-reference schemes; stable collector identity | Customer secret-path policy, target CIDR/DNS allowlists, workload identity, and egress tests |
| Collector credential theft | Source database compromise | Projected API token file; secret references only; mounted secret resolver; no resolved credentials in API responses/logs; non-root/read-only pod | Short-lived source credentials where possible, automatic rotation/revocation, source-login monitoring |
| Arbitrary or malicious query | Source write, exfiltration, or denial of service | Server-owned immutable probe catalog; one read-only SELECT/CTE; no caller SQL; parameterized hub persistence; read-only sessions and timeouts | Approved driver/version negative-write and adversarial query tests on each platform |
| Source workload denial of service | Production latency or outage | Bounded connections, statements, rows, payloads, concurrency, retry, circuit breaker, leases, and disabled-by-default leasing | Customer workload budgets, maintenance windows, source monitoring, pilot cohort, DBA kill switch |
| Duplicate or replayed mutation | Conflicting runs, evidence, or source load | Actor/authz/tenant/route/payload idempotency; atomic run keys; UUID lease fences; deterministic results; uncertain-state review | Network-partition and crash tests with production PostgreSQL and real integration workers |
| Forged or partial evidence | False control conclusion | Exact requested probe set; bounded typed observations; server recomputes row counts/digests; evaluation binds to stored successful job | Golden datasets, platform/version certification, analyst calibration, independent control review |
| Altered control pack or result | Unsafe query or false assurance | Admin-only immutable pack publication; code-catalog probe validation; canonical digests; database immutability triggers; deterministic results | Protected pack approval/signing and emergency disable/rollback procedure |
| Exception self-approval or permanence | Unreviewed risk acceptance | Separate approver role; database separation-of-duties constraint; future expiry; one active approval; revoke/expiry audit and outbox | Customer approval policy, maximum durations, alerting, periodic risk-owner review |
| Evidence or audit tampering | Invalid audit conclusion | Append-oriented API; PostgreSQL append-only audit trigger; immutable successful jobs and governance records; canonical digests | Restricted DBA access, managed audit, immutable export/WORM, reconciliation and restore proof |
| Integration replay or message substitution | Duplicate ticket/GRC state or false acknowledgement | Transactional outbox/inbox; canonical payload digest; deduplication; fenced delivery leases; bounded attempts; immutable processed inbox | Authenticated destination adapters, rate limits, destination idempotency, reconciliation and dead-letter alerting |
| Data leakage in UI/logs/metrics/traces | Credential, customer, or topology disclosure | Bounded evidence fields; raw rows and values never enter the Hub API, evidence, logs, or browser; response models omit secret references; structured allowlist logging; bounded metric labels | Realistic telemetry sampling review, retention/access policy, DLP and redaction testing |
| Local masking boundary escape or execution error | Source modification, target overwrite, broken referential integrity, or raw-value exposure | Development-only loopback launcher; fixed read-only `insurance_sample` source; one server-derived `insurance_sample_masked_<workflow>` final and paired `aegisdb_mask_stage_<workflow>` per policy; distinct least-privilege identities; 500-row table cap; selected sensitive values transformed before target insert while non-sensitive structural fields may be retained; staging-only `DROP` after exact worker-manifest and DDL checks; staged validation and one atomic rename publish; no `DROP`, `UPDATE`, `DELETE`, or overwrite against source/final; every new workflow gets an empty final; interrupted completion may recover only its own exact deterministic final; changed-source, mismatched, or ambiguous state fails closed; bounded digest/count/boolean evidence; automated checks cannot pass or score a control; excluded from production images and deployment paths | Separately approved customer non-production pilot, SoD, rollback, application tests, safe-data proof, and independent verification that the local proof cannot be promoted |
| Unsafe AI recommendation | Incorrect pass/fail, disclosure, or privileged action | No generative AI in control decisions, exception approval, remediation, masking, or execution | Any future assistant needs provider/residency review, redaction, grounding/citations, evaluations, prompt/version audit, human review, and no privileges |
| Compromised image or CI dependency | Platform or source-network code execution | Lockfiles; restricted containers; CI scans; SBOM generation; digest-only production policy | Pin actions/tools by immutable SHA/digest, sign and attest artifacts, enforce admission, exercise image revocation |
| Network interception | Credential/evidence disclosure | HTTPS requirements; certificate verification; source TLS settings; deny-by-default network policy | Customer PKI, optional mTLS, private routing, downgrade tests, certificate-expiry monitoring |
| Secret committed to source | Long-lived compromise | Secret/misconfiguration scan; runtime references; documented secret boundary; no manifest secrets | Protected CI environments, history scan, immediate rotation and incident response |

## Required validation before production

- Complete architecture risk review, DPIA, data classification, retention, and
  residency approval.
- Test tenant isolation, object authorization, role escalation, token replay,
  broker spoofing, collector assignment, lease fencing, and audit coverage.
- Prove that each source identity cannot write data, schema, configuration,
  grants, or audit state on every supported database/version/driver combination.
- Load-test scans against production-like databases and prove the configured
  source workload ceilings and kill switch.
- Exercise token and secret rotation, collector loss, duplicate delivery,
  database failover, restore, regional recovery, and application rollback.
- Review every UI field, log, metric, trace, alert, evidence payload, and outbox
  event using realistic sensitive names.
- Resolve all critical/high findings or approve a time-bounded exception with a
  separate accountable approver.

## Explicitly prohibited

- User-authored SQL, arbitrary scripts, shared DBA credentials, or automatic
  production remediation.
- Storage of source row samples, passwords, private keys, wallet material, or
  vault/API tokens in the hub, repository, image, logs, or telemetry.
- Disabling TLS verification, bypassing source change management, or enabling
  collector leasing without the customer promotion record.
- Treating a generative response as control evidence, an approval, or authority
  to execute a privileged action.
