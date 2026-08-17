# Production overlay template

This is an intentionally non-deployable example for the API and outbound-only
collector. The web console is excluded because private Sites is its only
supported production runtime.

Before deployment, copy this directory into the protected environment
configuration repository and replace:

- the all-zero image digest with the signed digest promoted by CI;
- every `.example.invalid` hostname;
- all RFC 5737 documentation CIDRs (`192.0.2.0/24`, `198.51.100.0/24`, and
  `203.0.113.0/24`) with minimum approved routes;
- ingress class, certificate reference, resource sizing, replica bounds and
  telemetry routing as required by the environment.

Do not add `Secret` resources. Provision the referenced keys through the
approved external secret provider. In particular, `database-url` must identify
the forced-RLS request role and `database-maintenance-url` must identify a
distinct, narrowly held reconciliation role; both URLs must require TLS. Remove the
`assurance-hub.openai.com/template-only` annotation only in the protected copy.
The template keeps `COLLECTOR_ENABLE_LEASING=false`. Enabling it requires a
collector image containing only approved drivers plus a signed driver/version,
negative-write and workload-impact evidence digest recorded through the
environment's admission process.

Render and validate both policies before apply:

```powershell
kubectl kustomize infra/kubernetes/overlays/production-template > rendered.yaml
python tools/validate_infrastructure.py --rendered rendered.yaml --profile production-template

# In the protected environment repository after all replacements:
python tools/validate_infrastructure.py --rendered rendered.yaml --profile production
```

The production profile rejects template annotations, example hostnames,
documentation CIDRs, mutable images, world-open egress, embedded secrets and any
Kubernetes web workload.
