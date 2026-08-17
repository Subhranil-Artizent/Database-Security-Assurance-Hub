# Operations assets

This directory adds deployment and monitoring assets without changing application source.

- `compose.yaml`: development-only infrastructure harness for the API, PostgreSQL and Prometheus.
- `docker/`: multi-stage API and driver-free collector images, plus a scan-ready web build artifact.
- `prometheus/`: scrape, SLO recording rules and bounded alert configuration.
- `kubernetes/base/`: Kustomize production base for the API and private collectors.
- `kubernetes/overlays/production-template/`: deliberately non-deployable,
  secret-free environment overlay example.

Read `docs/environment.md` before using these assets. The Kubernetes base is intentionally incomplete until an environment overlay supplies immutable images, approved hostnames/CIDRs, external secrets and platform integrations. It does not deploy production PostgreSQL or a secret manager.

The authenticated console is deployed only through a private Sites deployment, whose dispatch layer owns sign-in and injects trusted identity headers. It is intentionally excluded from the Kubernetes base: exposing the web image directly would neither provide the Sites sign-in routes nor a trustworthy identity-header boundary.
For the same reason, the web artifact is not a Compose service. Use
`npm run dev:integrated` for the supported local API-backed console.

The collector workload accepts no ingress. Its egress is deny-by-default and restricted to the hub API, HTTPS vault access, and standard Oracle/PostgreSQL/Sybase ports. Production overlays must narrow the database destination CIDRs and ports further.
The base uses the dedicated `assurance-collector` image and consumes its API
token from a projected file. Leasing is explicitly disabled; the checked-in
image contains observability support but no optional database drivers.
Collector metrics remain loopback-only because collectors accept no ingress.
Do not set `COLLECTOR_METRICS_HOST=0.0.0.0` without adding and approving a
metrics-only scrape path and NetworkPolicy.

Validate the source and rendered contracts before any environment work:

```powershell
python tools/validate_infrastructure.py --source-dir infra/kubernetes/base --profile base
kubectl kustomize infra/kubernetes/base > rendered-base.yaml
python tools/validate_infrastructure.py --rendered rendered-base.yaml --profile base
python tools/validate_observability.py
```

The base renders exactly 17 resources: namespace, configuration, two service
accounts, API service, two deployments, two HPAs, two disruption budgets, five
network policies and one API-only ingress. Missing documents are a hard failure.
See `docs/deployment-and-supply-chain.md` and `docs/slo-and-reliability.md` for
production promotion and reliability gates.
