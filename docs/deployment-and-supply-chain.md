# Deployment and supply-chain contract

## Supported production boundary

Private Sites is the only supported production runtime for the web console.
Kubernetes contains the FastAPI control plane and outbound-only collectors. The
infrastructure validator rejects a Kubernetes web workload.

The checked-in production overlay is a template, not a deployable environment.
It contains example hosts, documentation networks, an all-zero image digest,
and a template-only marker. Real environment values belong in the protected
configuration repository. Runtime secrets arrive through the approved external
secret provider and must not be represented as Kubernetes `Secret` resources in
this repository.

The collector base is intentionally driver-free, omits the source credential
mount, and sets `COLLECTOR_ENABLE_LEASING=false`. A protected environment may
enable leasing only with an approved driver image digest, vault mount, target
network allowlist, TLS trust, read-only privilege evidence, negative-write test,
and source workload approval for the exact database/version cohort.

## Current quality workflow

The checked-in workflow defines:

- web lint, build, rendered-route, accessibility, security, architecture, and
  full dependency-tree audit checks;
- API and collector Ruff, strict mypy, pytest, package-build, dependency-audit,
  migration, configuration, and entrypoint checks;
- immutable control-pack validation and unit tests;
- exact 17-resource source and rendered infrastructure policy checks;
- base and production-template Kustomize rendering and strict Kubernetes schema
  validation;
- Prometheus configuration, recording-rule, and alert validation;
- Compose interpolation, API/driver-free collector image builds, and a
  non-deployable web artifact build for supply-chain inspection;
- repository secret, vulnerability, and misconfiguration scanning;
- web, API, and collector container scans;
- CycloneDX SBOM and rendered-manifest retention.

This list describes workflow definitions, not successful release evidence. The
protected release owner must retain the successful run, source revision,
artifacts, findings, exceptions, and approvals for the promoted revision.

Vinext currently depends on an upstream image metadata parser with no patched
release for its ICNS/HEIF/JXL infinite-loop advisories. This repository replaces
that build-time dependency with the private `vendor/safe-image-size` package,
which supports only bounded PNG, GIF, JPEG, WebP, and SVG metadata and rejects
those unsafe formats. Its regression tests and the full npm audit are release
gates; remove the fork only after an upstream patched release is reviewed.

The workflow currently references GitHub actions and several CI tool images by
version tag rather than reviewed immutable digest/SHA. Pinning those dependencies
is an open protected-release gate. Repository CI also stops before registry
publication, signing, provenance attestation, and cluster admission verification.

## Database migration evidence

The local and CI smoke path upgrades an empty SQLite database through Alembic
revision `20260812_0004`. PostgreSQL migration SQL can be rendered offline.
Neither action proves PostgreSQL locking, forced RLS, runtime-role grants,
concurrent leasing, online migration behavior, or N-1 compatibility.

Before promotion, test the exact migration chain against a production-like
PostgreSQL version with realistic volume. Prove tenant isolation using the
restricted runtime role, validate background reconcilers during rollout, and
exercise forward compatibility with both the old and new application versions.
Use expand/migrate/contract for any incompatible change.

## Build and promotion sequence

1. Select a protected, reviewed source revision and assign a release identity.
2. Run the complete quality workflow; resolve or formally accept findings with
   an owner and expiry.
3. Build each artifact once. Generate SBOM and provenance, scan it, and sign its
   immutable digest.
4. Publish the web through private Sites using the approved build-time API
   origin and runtime token-broker configuration.
5. Promote the same API digest through integration, staging, and production.
   Promote only a customer-approved collector driver digest for the exact source
   cohort; keep leasing false until its source gates pass.
6. Validate database migration compatibility, IdP/broker, vault, certificates,
   private networking, managed PostgreSQL, telemetry, backup, and on-call
   dependencies.
7. Render the protected overlay and pass both strict schema and production
   policy validation. Retain its digest and approval.
8. Verify signatures and provenance through cluster admission, then roll out
   progressively while observing readiness, availability burn, latency,
   saturation, governance-write failures, leases, source timeouts, and workload
   impact.
9. Stop and roll back the application digest when a threshold breaches. Do not
   roll back a database migration unless its tested procedure explicitly allows
   it.
10. Enable one approved collector cohort and non-critical pilot asset. Expand
    only after a complete assessment window remains inside the error and source
    workload budgets.

Required release evidence includes source revision, dependency lockfiles,
workflow run, scan and exception records, image/site release identifiers,
immutable digests, signatures, provenance, SBOMs, migration plan and results,
rendered-manifest digest, approvals, smoke results, alert state, rollout
timeline, and rollback decision.

## Production manifest gate

```powershell
kubectl kustomize <protected-production-overlay> > rendered-production.yaml
python tools/validate_infrastructure.py `
  --rendered rendered-production.yaml `
  --profile production
```

The gate rejects missing resources, duplicate YAML keys, mutable or placeholder
images, example hosts, documentation networks, world-open egress, embedded
secrets, unsafe pod settings, template markers, and Kubernetes web workloads.
Cluster admission must independently repeat the critical digest, signature,
provenance, restricted-pod, and network rules; CI validation is not an
authorization boundary.

## Rollback boundary

Sites, API, collector, and database changes have separate rollback decisions:

- roll back the Sites release when console behavior or the identity exchange
  regresses;
- roll back API/collector images to the last signed digest when application
  thresholds breach and the database remains compatible;
- set collector leasing false before source containment or collector rollback;
- reconcile expired leases and outbox deliveries before resuming;
- treat database rollback as an exceptional, pre-tested recovery operation, not
  an automatic deployment step.
