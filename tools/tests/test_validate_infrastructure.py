from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

from tools.validate_infrastructure import (
    EXPECTED_RESOURCES,
    TEMPLATE_ANNOTATION,
    UniqueKeyLoader,
    Validator,
    load_source,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "infra" / "kubernetes" / "base"


class InfrastructureValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resources = load_source(BASE)

    def test_base_has_the_exact_approved_resource_set(self) -> None:
        validator = Validator(self.resources, profile="base", rendered=False)
        validator.validate()
        self.assertEqual(validator.errors, [])
        self.assertEqual(
            {(item["kind"], item["metadata"]["name"]) for item in self.resources},
            EXPECTED_RESOURCES,
        )

    def test_missing_document_is_a_hard_failure(self) -> None:
        resources = [
            item
            for item in self.resources
            if (item["kind"], item["metadata"]["name"])
            != ("ServiceAccount", "assurance-hub-collector")
        ]
        validator = Validator(resources, profile="base", rendered=False)
        validator.validate()
        self.assertTrue(
            any(
                "ServiceAccount/assurance-hub-collector" in error
                for error in validator.errors
            )
        )

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        with self.assertRaises(yaml.YAMLError):
            yaml.load(
                "apiVersion: v1\nkind: ConfigMap\nkind: Secret\n",
                Loader=UniqueKeyLoader,
            )

    def test_template_profile_rejects_world_open_egress(self) -> None:
        resources = self._as_rendered_template()
        policy = next(
            item
            for item in resources
            if item["kind"] == "NetworkPolicy"
            and item["metadata"]["name"] == "api-egress"
        )
        policy["spec"]["egress"] = [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]
        validator = Validator(resources, profile="production-template", rendered=True)
        validator.validate()
        self.assertTrue(any("world-open" in error for error in validator.errors))

    def test_safe_rendered_template_passes_policy(self) -> None:
        validator = Validator(
            self._as_rendered_template(), profile="production-template", rendered=True
        )
        validator.validate()
        self.assertEqual(validator.errors, [])

    def test_leasing_requires_explicit_driver_evidence_gate(self) -> None:
        resources = copy.deepcopy(self.resources)
        deployment = next(
            item
            for item in resources
            if item["kind"] == "Deployment"
            and item["metadata"]["name"] == "assurance-hub-collector"
        )
        env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in env if item["name"] == "COLLECTOR_ENABLE_LEASING")[
            "value"
        ] = "true"
        validator = Validator(resources, profile="base", rendered=False)
        validator.validate()
        self.assertTrue(
            any("leasing must remain false" in error for error in validator.errors)
        )

    def test_api_requires_distinct_request_and_maintenance_database_secret_refs(
        self,
    ) -> None:
        resources = copy.deepcopy(self.resources)
        deployment = next(
            item
            for item in resources
            if item["kind"] == "Deployment"
            and item["metadata"]["name"] == "assurance-hub-api"
        )
        env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        maintenance = next(
            item for item in env if item["name"] == "DATABASE_MAINTENANCE_URL"
        )
        maintenance["valueFrom"]["secretKeyRef"]["key"] = "database-url"

        validator = Validator(resources, profile="base", rendered=False)
        validator.validate()
        self.assertTrue(
            any(
                "DATABASE_MAINTENANCE_URL must use"
                " assurance-hub-runtime/database-maintenance-url" in error
                for error in validator.errors
            )
        )

    def _as_rendered_template(self) -> list[dict[str, object]]:
        resources = copy.deepcopy(self.resources)
        for item in resources:
            metadata = item.setdefault("metadata", {})
            metadata.setdefault("annotations", {})[TEMPLATE_ANNOTATION] = "true"
            if item["kind"] != "Namespace":
                metadata["namespace"] = "assurance-hub"
            if item["kind"] == "Deployment":
                suffix = (
                    "assurance-hub-api"
                    if metadata["name"] == "assurance-hub-api"
                    else "assurance-hub-collector"
                )
                item["spec"]["template"]["spec"]["containers"][0]["image"] = (
                    f"registry.example.invalid/platform/{suffix}@sha256:" + "0" * 64
                )
            if item["kind"] == "NetworkPolicy" and metadata["name"] in {
                "api-egress",
                "collector-outbound-only",
            }:
                item["spec"]["egress"] = [
                    {
                        "to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}],
                        "ports": [{"protocol": "TCP", "port": 443}],
                    }
                ]
        return resources


if __name__ == "__main__":
    unittest.main()
