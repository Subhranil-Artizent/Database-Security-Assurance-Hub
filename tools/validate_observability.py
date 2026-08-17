#!/usr/bin/env python3
"""Validate the bounded Prometheus alert and SLO contract."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from validate_infrastructure import UniqueKeyLoader

EXPECTED_RECORDINGS = {
    "assurance:http_5xx_ratio:rate5m",
    "assurance:http_5xx_ratio:rate30m",
    "assurance:http_5xx_ratio:rate1h",
    "assurance:http_5xx_ratio:rate6h",
    "assurance:http_latency_seconds:p95_rate10m",
}

EXPECTED_ALERTS = {
    "AssuranceHubApiDown",
    "AssuranceHubApiMetricsMissing",
    "AssuranceHubApiErrorBudgetFastBurn",
    "AssuranceHubApiErrorBudgetSlowBurn",
    "AssuranceHubApiReadLatencyHigh",
    "AssuranceHubGovernanceWriteFailed",
    "AssuranceHubScanFailuresElevated",
    "AssuranceHubLeasedWorkStalled",
    "AssuranceHubLeaseRetryBudgetExhausted",
}

REQUIRED_EXPRESSION_FRAGMENTS = {
    "AssuranceHubApiErrorBudgetFastBurn": ("rate5m", "rate1h", "0.0144"),
    "AssuranceHubApiErrorBudgetSlowBurn": ("rate30m", "rate6h", "0.006"),
    "AssuranceHubApiReadLatencyHigh": ("p95_rate10m", "> 0.5"),
    "AssuranceHubGovernanceWriteFailed": ("assurance_governance_write_failures_total",),
}

FORBIDDEN_GROUP_LABELS = re.compile(
    r"\b(?:by|without)\s*\([^)]*\b(?:tenant|database|asset|user|subject|connector_id)\b",
    re.IGNORECASE,
)


def load(path: Path) -> dict[str, Any]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("groups"), list):
        raise TypeError("top-level groups list is required")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "rules",
        nargs="?",
        type=Path,
        default=Path("infra/prometheus/rules/availability.yml"),
    )
    args = parser.parse_args()
    try:
        document = load(args.rules)
    except (TypeError, ValueError) as exc:
        print(f"observability validation failed: {exc}", file=sys.stderr)
        return 1

    errors: list[str] = []
    recordings: set[str] = set()
    alerts: set[str] = set()
    group_names: set[str] = set()
    runbook_path = Path("docs/runbook.md")
    try:
        headings = {
            re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
            for heading in re.findall(
                r"^#{1,6}\s+(.+?)\s*$",
                runbook_path.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        }
    except (OSError, UnicodeError) as exc:
        print(
            f"observability validation failed: cannot read {runbook_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    for group in document["groups"]:
        if not isinstance(group, dict) or not isinstance(group.get("rules"), list):
            errors.append("each rule group must be a mapping with a rules list")
            continue
        group_name = group.get("name")
        if not isinstance(group_name, str) or group_name in group_names:
            errors.append(f"duplicate or invalid rule group {group_name!r}")
        else:
            group_names.add(group_name)
        for rule in group["rules"]:
            if not isinstance(rule, dict):
                errors.append("each rule must be a mapping")
                continue
            expression = rule.get("expr")
            if not isinstance(expression, str) or not expression.strip():
                errors.append("every rule must have a non-empty expression")
                continue
            if FORBIDDEN_GROUP_LABELS.search(expression):
                errors.append(
                    "metric aggregation contains a sensitive or high-cardinality label"
                )
            if "record" in rule:
                name = rule.get("record")
                if not isinstance(name, str) or name in recordings:
                    errors.append(f"duplicate or invalid recording rule {name!r}")
                else:
                    recordings.add(name)
                continue
            name = rule.get("alert")
            if not isinstance(name, str) or name in alerts:
                errors.append(f"duplicate or invalid alert {name!r}")
                continue
            alerts.add(name)
            for fragment in REQUIRED_EXPRESSION_FRAGMENTS.get(name, ()):
                if fragment not in expression:
                    errors.append(f"{name}: expression must contain {fragment!r}")
            if not isinstance(rule.get("for"), str):
                errors.append(f"{name}: a non-zero `for` duration is required")
            labels = rule.get("labels", {})
            if labels.get("severity") not in {"warning", "critical"}:
                errors.append(f"{name}: severity must be warning or critical")
            annotations = rule.get("annotations", {})
            if not isinstance(annotations.get("summary"), str):
                errors.append(f"{name}: summary annotation is required")
            runbook = annotations.get("runbook")
            if not isinstance(runbook, str) or not runbook.startswith(
                "docs/runbook.md#"
            ):
                errors.append(f"{name}: repository runbook anchor is required")
            elif runbook.partition("#")[2] not in headings:
                errors.append(f"{name}: runbook anchor {runbook!r} does not exist")

    missing_recordings = EXPECTED_RECORDINGS - recordings
    missing_alerts = EXPECTED_ALERTS - alerts
    unexpected_recordings = recordings - EXPECTED_RECORDINGS
    unexpected_alerts = alerts - EXPECTED_ALERTS
    for name in sorted(missing_recordings):
        errors.append(f"missing recording rule {name}")
    for name in sorted(missing_alerts):
        errors.append(f"missing alert {name}")
    for name in sorted(unexpected_recordings):
        errors.append(f"unexpected recording rule {name}")
    for name in sorted(unexpected_alerts):
        errors.append(f"unexpected alert {name}")

    if errors:
        print("observability validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"validated {len(recordings)} recording rules and {len(alerts)} alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
