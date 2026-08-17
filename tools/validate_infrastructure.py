#!/usr/bin/env python3
"""Validate the assurance-hub Kubernetes contract without contacting a cluster.

The source mode catches malformed multi-document files before Kustomize can
silently drop resources. Rendered mode validates the complete Kustomize output
and applies stricter production-template or production policies.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

EXPECTED_RESOURCES = {
    ("Namespace", "assurance-hub"),
    ("ConfigMap", "assurance-hub-config"),
    ("ServiceAccount", "assurance-hub-api"),
    ("ServiceAccount", "assurance-hub-collector"),
    ("Deployment", "assurance-hub-api"),
    ("Deployment", "assurance-hub-collector"),
    ("Service", "assurance-hub-api"),
    ("HorizontalPodAutoscaler", "assurance-hub-api"),
    ("HorizontalPodAutoscaler", "assurance-hub-collector"),
    ("PodDisruptionBudget", "assurance-hub-api"),
    ("PodDisruptionBudget", "assurance-hub-collector"),
    ("NetworkPolicy", "default-deny-all"),
    ("NetworkPolicy", "allow-dns"),
    ("NetworkPolicy", "api-ingress"),
    ("NetworkPolicy", "api-egress"),
    ("NetworkPolicy", "collector-outbound-only"),
    ("Ingress", "assurance-hub"),
}

API_VERSIONS = {
    "Namespace": "v1",
    "ConfigMap": "v1",
    "ServiceAccount": "v1",
    "Service": "v1",
    "Deployment": "apps/v1",
    "HorizontalPodAutoscaler": "autoscaling/v2",
    "PodDisruptionBudget": "policy/v1",
    "NetworkPolicy": "networking.k8s.io/v1",
    "Ingress": "networking.k8s.io/v1",
}

SENSITIVE_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|token|secret|private_key|client_secret)(?:$|_)",
    re.IGNORECASE,
)
IMAGE_DIGEST = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$")
DOCUMENTATION_CIDRS = {"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"}
TEMPLATE_ANNOTATION = "assurance-hub.openai.com/template-only"
DRIVER_EVIDENCE_ANNOTATION = "assurance-hub.openai.com/driver-validation-evidence"
EVIDENCE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that treats duplicate mapping keys as an error."""


def _construct_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_documents(path: Path) -> list[dict[str, Any]]:
    try:
        loaded = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
        )
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: invalid YAML: {exc}") from exc
    documents: list[dict[str, Any]] = []
    for index, document in enumerate(loaded, start=1):
        if document is None:
            continue
        if not isinstance(document, dict):
            raise TypeError(f"{path}: document {index} must be a mapping")
        documents.append(document)
    return documents


def load_source(directory: Path) -> list[dict[str, Any]]:
    kustomization_path = directory / "kustomization.yaml"
    documents = load_documents(kustomization_path)
    if len(documents) != 1 or documents[0].get("kind") != "Kustomization":
        raise ValueError(f"{kustomization_path}: expected one Kustomization document")
    resources = documents[0].get("resources")
    if not isinstance(resources, list) or not resources:
        raise ValueError(f"{kustomization_path}: resources must be a non-empty list")

    result: list[dict[str, Any]] = []
    root = directory.resolve()
    for resource in resources:
        if not isinstance(resource, str):
            raise TypeError(f"{kustomization_path}: resource paths must be strings")
        candidate = (directory / resource).resolve()
        if candidate.parent != root or candidate.suffix not in {".yaml", ".yml"}:
            raise ValueError(
                f"{kustomization_path}: source validation accepts only direct YAML files"
            )
        if not candidate.is_file():
            raise ValueError(f"{kustomization_path}: missing resource {resource!r}")
        result.extend(load_documents(candidate))
    return result


class Validator:
    def __init__(
        self, resources: list[dict[str, Any]], *, profile: str, rendered: bool
    ):
        self.resources = resources
        self.profile = profile
        self.rendered = rendered
        self.errors: list[str] = []

    def fail(self, resource: str, message: str) -> None:
        self.errors.append(f"{resource}: {message}")

    def validate(self) -> None:
        identities: list[tuple[str, str]] = []
        for index, item in enumerate(self.resources, start=1):
            kind = item.get("kind")
            metadata = item.get("metadata")
            name = metadata.get("name") if isinstance(metadata, dict) else None
            label = f"document {index}"
            if not isinstance(kind, str) or not isinstance(name, str) or not name:
                self.fail(label, "apiVersion, kind, and metadata.name are required")
                continue
            label = f"{kind}/{name}"
            identities.append((kind, name))
            if item.get("apiVersion") != API_VERSIONS.get(kind):
                self.fail(label, f"unexpected apiVersion {item.get('apiVersion')!r}")
            if kind == "Secret":
                self.fail(
                    label,
                    "Secret resources are prohibited; use the external secret provider",
                )
            if "web" in name.lower():
                self.fail(
                    label, "the web console must be deployed only through private Sites"
                )
            if (
                self.rendered
                and kind != "Namespace"
                and metadata.get("namespace") != "assurance-hub"
            ):
                self.fail(
                    label,
                    "rendered namespaced resources must use namespace assurance-hub",
                )
            self._validate_template_marker(label, metadata)

        duplicate_identities = [
            identity for identity, count in Counter(identities).items() if count > 1
        ]
        for kind, name in duplicate_identities:
            self.fail(f"{kind}/{name}", "duplicate rendered resource")

        actual = set(identities)
        for kind, name in sorted(EXPECTED_RESOURCES - actual):
            self.fail(f"{kind}/{name}", "required resource is missing")
        for kind, name in sorted(actual - EXPECTED_RESOURCES):
            self.fail(
                f"{kind}/{name}", "unexpected resource in API/collector-only deployment"
            )
        if len(self.resources) != len(EXPECTED_RESOURCES):
            self.fail(
                "resource-set",
                f"expected exactly {len(EXPECTED_RESOURCES)} resources, found {len(self.resources)}",
            )

        for resource in self.resources:
            kind = resource.get("kind")
            metadata = resource.get("metadata", {})
            name = (
                metadata.get("name", "unknown")
                if isinstance(metadata, dict)
                else "unknown"
            )
            label = f"{kind}/{name}"
            if kind == "ConfigMap":
                self._validate_config_map(label, resource)
            elif kind == "ServiceAccount":
                self._validate_service_account(label, resource)
            elif kind == "Deployment":
                self._validate_deployment(label, resource)
            elif kind == "Service":
                self._validate_service(label, resource)
            elif kind == "HorizontalPodAutoscaler":
                self._validate_hpa(label, resource)
            elif kind == "PodDisruptionBudget":
                self._validate_pdb(label, resource)
            elif kind == "NetworkPolicy":
                self._validate_network_policy(label, resource)
            elif kind == "Ingress":
                self._validate_ingress(label, resource)

    def _validate_template_marker(
        self, label: str, metadata: Mapping[str, Any]
    ) -> None:
        annotations = metadata.get("annotations", {})
        marker = (
            annotations.get(TEMPLATE_ANNOTATION)
            if isinstance(annotations, dict)
            else None
        )
        if self.rendered and self.profile == "production-template" and marker != "true":
            self.fail(
                label, f"production template must carry {TEMPLATE_ANNOTATION}=true"
            )
        if self.profile == "production" and marker is not None:
            self.fail(
                label, "template-only annotation must be removed before production"
            )

    def _validate_config_map(self, label: str, resource: Mapping[str, Any]) -> None:
        data = resource.get("data")
        if not isinstance(data, dict):
            self.fail(label, "data must be a mapping")
            return
        for key, value in data.items():
            if SENSITIVE_KEY.search(str(key)):
                self.fail(label, f"sensitive configuration key {key!r} is prohibited")
            if not isinstance(value, str):
                self.fail(label, f"configuration value {key!r} must be a string")
            elif self.profile == "production" and (
                ".example.invalid" in value.lower() or "replace" in value.lower()
            ):
                self.fail(
                    label, f"placeholder configuration value {key!r} must be replaced"
                )
        if data.get("ENVIRONMENT") != "production" or data.get("AUTH_MODE") != "oidc":
            self.fail(label, "production and OIDC modes must be fail-closed defaults")

    def _validate_service_account(
        self, label: str, resource: Mapping[str, Any]
    ) -> None:
        if resource.get("automountServiceAccountToken") is not False:
            self.fail(label, "default Kubernetes API token must not be mounted")

    def _validate_deployment(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec")
        if not isinstance(spec, dict):
            self.fail(label, "spec is required")
            return
        if not isinstance(spec.get("replicas"), int) or spec["replicas"] < 2:
            self.fail(label, "at least two replicas are required")
        if spec.get("minReadySeconds", 0) < 10:
            self.fail(label, "minReadySeconds must be at least 10")
        deadline = spec.get("progressDeadlineSeconds")
        if not isinstance(deadline, int) or not 60 <= deadline <= 900:
            self.fail(label, "progressDeadlineSeconds must be between 60 and 900")
        strategy = spec.get("strategy", {})
        rolling = (
            strategy.get("rollingUpdate", {}) if isinstance(strategy, dict) else {}
        )
        if (
            strategy.get("type") != "RollingUpdate"
            or rolling.get("maxUnavailable") != 0
        ):
            self.fail(label, "rolling updates must use maxUnavailable: 0")

        template = spec.get("template", {})
        pod = template.get("spec", {}) if isinstance(template, dict) else {}
        expected_sa = label.split("/", maxsplit=1)[1]
        if pod.get("serviceAccountName") != expected_sa:
            self.fail(label, f"must use dedicated service account {expected_sa}")
        if pod.get("automountServiceAccountToken") is not False:
            self.fail(label, "pod must disable the default service-account token")
        if pod.get("hostNetwork") or pod.get("hostPID") or pod.get("hostIPC"):
            self.fail(label, "host namespaces are prohibited")
        pod_security = pod.get("securityContext", {})
        if pod_security.get("runAsNonRoot") is not True:
            self.fail(label, "pod must run as non-root")
        if pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
            self.fail(label, "RuntimeDefault seccomp is required")

        constraints = pod.get("topologySpreadConstraints", [])
        spread = {
            constraint.get("topologyKey"): constraint.get("whenUnsatisfiable")
            for constraint in constraints
            if isinstance(constraint, dict)
        }
        if spread.get("topology.kubernetes.io/zone") != "DoNotSchedule":
            self.fail(label, "hard zone topology spreading is required")
        if "kubernetes.io/hostname" not in spread:
            self.fail(label, "host topology spreading is required")

        containers = pod.get("containers")
        if not isinstance(containers, list) or len(containers) != 1:
            self.fail(label, "exactly one application container is required")
            return
        container = containers[0]
        image = container.get("image", "")
        if "web" in str(image).lower():
            self.fail(label, "web images are prohibited from Kubernetes")
        if self.profile in {"production-template", "production"}:
            if not isinstance(image, str) or not IMAGE_DIGEST.fullmatch(image):
                self.fail(label, "production images must be pinned by sha256 digest")
            elif self.profile == "production" and image.endswith("0" * 64):
                self.fail(label, "placeholder image digest must be replaced")
            elif self.profile == "production" and ".example.invalid/" in image:
                self.fail(label, "placeholder image registry must be replaced")
        security = container.get("securityContext", {})
        if security.get("allowPrivilegeEscalation") is not False:
            self.fail(label, "privilege escalation must be disabled")
        if security.get("readOnlyRootFilesystem") is not True:
            self.fail(label, "read-only root filesystem is required")
        if security.get("capabilities", {}).get("drop") != ["ALL"]:
            self.fail(label, "all Linux capabilities must be dropped")
        resources = container.get("resources", {})
        for boundary in ("requests", "limits"):
            values = resources.get(boundary, {})
            if not values.get("cpu") or not values.get("memory"):
                self.fail(label, f"CPU and memory {boundary} are required")
        for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
            if not isinstance(container.get(probe), dict):
                self.fail(label, f"{probe} is required")
        for env in container.get("env", []):
            if not isinstance(env, dict):
                continue
            name = str(env.get("name", ""))
            if (
                SENSITIVE_KEY.search(name)
                and "value" in env
                and not name.endswith("_FILE")
            ):
                self.fail(label, f"{name} must use secretKeyRef, not a literal value")
        for source in container.get("envFrom", []):
            if isinstance(source, dict) and "secretRef" in source:
                self.fail(
                    label,
                    "whole-secret envFrom imports are prohibited; reference explicit keys",
                )
        for volume in pod.get("volumes", []):
            if isinstance(volume, dict) and "hostPath" in volume:
                self.fail(label, "hostPath volumes are prohibited")
        if label == "Deployment/assurance-hub-collector":
            self._validate_collector_deployment(label, resource, container)
        elif label == "Deployment/assurance-hub-api":
            self._validate_api_deployment(label, container)

    def _validate_api_deployment(
        self, label: str, container: Mapping[str, Any]
    ) -> None:
        env = {
            entry.get("name"): entry
            for entry in container.get("env", [])
            if isinstance(entry, dict) and isinstance(entry.get("name"), str)
        }
        required_database_secrets = {
            "DATABASE_URL": "database-url",
            "DATABASE_MAINTENANCE_URL": "database-maintenance-url",
        }
        for variable, key in required_database_secrets.items():
            reference = (
                env.get(variable, {}).get("valueFrom", {}).get("secretKeyRef", {})
            )
            if (
                reference.get("name") != "assurance-hub-runtime"
                or reference.get("key") != key
            ):
                self.fail(
                    label,
                    f"{variable} must use assurance-hub-runtime/{key} secretKeyRef",
                )

    def _validate_collector_deployment(
        self,
        label: str,
        resource: Mapping[str, Any],
        container: Mapping[str, Any],
    ) -> None:
        if container.get("command") != ["assurance-collector", "run"]:
            self.fail(
                label, "collector must use the dedicated assurance-collector runtime"
            )
        env = {
            entry.get("name"): entry
            for entry in container.get("env", [])
            if isinstance(entry, dict) and isinstance(entry.get("name"), str)
        }
        leasing = env.get("COLLECTOR_ENABLE_LEASING", {}).get("value")
        if leasing != "false":
            metadata = resource.get("metadata", {})
            annotations = (
                metadata.get("annotations", {}) if isinstance(metadata, dict) else {}
            )
            evidence = (
                annotations.get(DRIVER_EVIDENCE_ANNOTATION)
                if isinstance(annotations, dict)
                else None
            )
            if not (
                self.profile == "production"
                and leasing == "true"
                and isinstance(evidence, str)
                and EVIDENCE_DIGEST.fullmatch(evidence)
            ):
                self.fail(
                    label,
                    "leasing must remain false unless production carries signed driver-validation evidence",
                )
            pod = resource.get("spec", {}).get("template", {}).get("spec", {})
            credential_mounts = [
                mount
                for mount in container.get("volumeMounts", [])
                if isinstance(mount, dict)
                and mount.get("mountPath") == "/var/run/secrets/assurance-sources"
                and mount.get("readOnly") is True
            ]
            volume_names = {
                volume.get("name")
                for volume in pod.get("volumes", [])
                if isinstance(volume, dict)
                and any(key in volume for key in ("csi", "projected", "secret"))
            }
            if (
                not credential_mounts
                or credential_mounts[0].get("name") not in volume_names
            ):
                self.fail(
                    label,
                    "enabled leasing requires a read-only approved source-credential volume",
                )
        token_file = env.get("COLLECTOR_TOKEN_FILE", {}).get("value")
        if token_file != "/var/run/secrets/assurance-api/token":
            self.fail(
                label, "collector token must be consumed from the projected token file"
            )
        expected_probes = {
            "startupProbe": ["assurance-collector", "live"],
            "readinessProbe": ["assurance-collector", "ready"],
            "livenessProbe": ["assurance-collector", "live"],
        }
        for probe, command in expected_probes.items():
            actual = container.get(probe, {}).get("exec", {}).get("command")
            if actual != command:
                self.fail(label, f"{probe} must execute {' '.join(command)}")

    def _validate_service(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec", {})
        if spec.get("type", "ClusterIP") != "ClusterIP":
            self.fail(label, "only ClusterIP services are allowed")
        if (
            spec.get("selector", {}).get("app.kubernetes.io/name")
            != "assurance-hub-api"
        ):
            self.fail(label, "service must select only the API")

    def _validate_hpa(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec", {})
        name = label.split("/", maxsplit=1)[1]
        target = spec.get("scaleTargetRef", {})
        if target.get("kind") != "Deployment" or target.get("name") != name:
            self.fail(label, "HPA must target its same-named Deployment")
        minimum = spec.get("minReplicas")
        maximum = spec.get("maxReplicas")
        if not isinstance(minimum, int) or minimum < 2:
            self.fail(label, "minReplicas must be at least two")
        if (
            not isinstance(maximum, int)
            or not isinstance(minimum, int)
            or maximum <= minimum
        ):
            self.fail(label, "maxReplicas must be greater than minReplicas")
        if not spec.get("metrics"):
            self.fail(label, "at least one autoscaling metric is required")
        if not isinstance(spec.get("behavior"), dict):
            self.fail(label, "bounded scale-up and scale-down behavior is required")

    def _validate_pdb(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec", {})
        if spec.get("minAvailable") != 1:
            self.fail(label, "minAvailable must be one")
        name = label.split("/", maxsplit=1)[1]
        selected = (
            spec.get("selector", {})
            .get("matchLabels", {})
            .get("app.kubernetes.io/name")
        )
        if selected != name:
            self.fail(label, "PDB selector must match its same-named workload")

    def _validate_network_policy(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec", {})
        name = label.split("/", maxsplit=1)[1]
        if name == "default-deny-all":
            if set(spec.get("policyTypes", [])) != {"Ingress", "Egress"}:
                self.fail(label, "default deny must cover ingress and egress")
            if spec.get("podSelector") != {}:
                self.fail(label, "default deny must select every pod")
        elif name == "allow-dns":
            ports = {
                (entry.get("protocol"), entry.get("port"))
                for rule in spec.get("egress", [])
                for entry in rule.get("ports", [])
                if isinstance(entry, dict)
            }
            if not {("UDP", 53), ("TCP", 53)}.issubset(ports):
                self.fail(label, "DNS policy must allow TCP and UDP port 53")
        elif name == "collector-outbound-only" and spec.get("ingress") != []:
            self.fail(label, "collectors must not accept inbound connections")

        if self.profile in {"production-template", "production"}:
            for rule in spec.get("egress", []):
                for destination in rule.get("to", []):
                    cidr = destination.get("ipBlock", {}).get("cidr")
                    if cidr in {"0.0.0.0/0", "::/0"}:
                        self.fail(label, "world-open production egress is prohibited")
                    if self.profile == "production" and cidr in DOCUMENTATION_CIDRS:
                        self.fail(label, f"documentation CIDR {cidr} must be replaced")

    def _validate_ingress(self, label: str, resource: Mapping[str, Any]) -> None:
        spec = resource.get("spec", {})
        tls = spec.get("tls")
        if not isinstance(tls, list) or not tls:
            self.fail(label, "TLS configuration is required")
        paths: list[Mapping[str, Any]] = []
        hosts: list[str] = []
        for rule in spec.get("rules", []):
            if not isinstance(rule, dict):
                continue
            hosts.append(str(rule.get("host", "")))
            paths.extend(rule.get("http", {}).get("paths", []))
        tls_hosts = {
            host
            for entry in tls or []
            if isinstance(entry, dict)
            for host in entry.get("hosts", [])
            if isinstance(host, str)
        }
        if set(hosts) != tls_hosts:
            self.fail(label, "TLS hosts must exactly match ingress rule hosts")
        if not paths or any(path.get("path") != "/api/v1" for path in paths):
            self.fail(label, "ingress may expose only /api/v1")
        for path in paths:
            service = path.get("backend", {}).get("service", {}).get("name")
            if service != "assurance-hub-api":
                self.fail(label, "ingress backend must be the API service")
        if self.profile == "production" and any(
            host.endswith(".example.invalid") for host in hosts
        ):
            self.fail(label, "placeholder ingress hostname must be replaced")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--source-dir", type=Path, help="Kustomize base source directory"
    )
    source.add_argument("--rendered", type=Path, help="Rendered multi-document YAML")
    parser.add_argument(
        "--profile",
        choices=("base", "production-template", "production"),
        default="base",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] = sys.argv[1:]) -> int:
    args = parse_args(argv)
    try:
        resources = (
            load_source(args.source_dir)
            if args.source_dir is not None
            else load_documents(args.rendered)
        )
        validator = Validator(
            resources, profile=args.profile, rendered=args.rendered is not None
        )
        validator.validate()
    except (TypeError, ValueError) as exc:
        print(f"infrastructure validation failed: {exc}", file=sys.stderr)
        return 1
    if validator.errors:
        print("infrastructure validation failed:", file=sys.stderr)
        for error in validator.errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        f"validated {len(resources)} Kubernetes resources for profile {args.profile!r}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
