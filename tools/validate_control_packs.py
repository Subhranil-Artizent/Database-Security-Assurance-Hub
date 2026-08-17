#!/usr/bin/env python3
"""Validate immutable AegisDB control packs using only the Python standard library.

The validator enforces the checked-in JSON Schemas, manifest digests, immutable
version paths, domain coverage, and probe references extracted from the API's
approved query catalog. It never imports or executes API application code.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTROL_PACK_ROOT = REPOSITORY_ROOT / "control-packs"
DEFAULT_QUERY_CATALOG = (
    REPOSITORY_ROOT / "services" / "api" / "assurance_hub" / "query_catalog.py"
)
EXPECTED_DOMAINS = {
    "encryption",
    "data_protection",
    "access_security",
    "data_masking",
}
PLATFORM_ENUM_NAMES = {
    "ORACLE": "oracle",
    "POSTGRESQL": "postgresql",
    "SYBASE": "sybase",
    "MYSQL": "mysql",
}
FORBIDDEN_FIELD_NAMES = {
    "sql",
    "query",
    "statement",
    "credential",
    "credentials",
    "password",
    "secret",
    "connection_string",
    "raw_data",
    "raw_values",
    "sample_values",
}


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.location}: {self.message}"


class DuplicateKeyError(ValueError):
    """Raised when JSON contains a duplicate object member."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key '{key}'")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=_unique_object)


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _resolve_ref(root_schema: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(
            f"only local JSON Schema references are supported: {reference}"
        )
    node: Any = root_schema
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        node = node[token]
    if not isinstance(node, dict):
        raise TypeError(f"JSON Schema reference is not an object: {reference}")
    return node


def _is_datetime(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def validate_schema(
    value: Any,
    schema: Mapping[str, Any],
    *,
    root_schema: Mapping[str, Any] | None = None,
    location: str = "$",
) -> list[ValidationIssue]:
    """Validate the JSON Schema subset used by this repository.

    Supported Draft 2020-12 keywords are deliberately explicit so validation
    never becomes permissive when a schema grows unexpectedly.
    """

    root = root_schema or schema
    issues: list[ValidationIssue] = []

    reference = schema.get("$ref")
    if reference is not None:
        try:
            target = _resolve_ref(root, reference)
        except (KeyError, TypeError, ValueError) as exc:
            return [ValidationIssue(location, f"invalid schema reference: {exc}")]
        return validate_schema(value, target, root_schema=root, location=location)

    if "oneOf" in schema:
        branches = schema["oneOf"]
        branch_results = [
            validate_schema(value, branch, root_schema=root, location=location)
            for branch in branches
        ]
        matches = sum(not result for result in branch_results)
        if matches != 1:
            issues.append(
                ValidationIssue(
                    location, f"must match exactly one oneOf branch; matched {matches}"
                )
            )
            return issues

    for subschema in schema.get("allOf", []):
        issues.extend(
            validate_schema(value, subschema, root_schema=root, location=location)
        )

    if "if" in schema:
        condition_issues = validate_schema(
            value, schema["if"], root_schema=root, location=location
        )
        branch = schema.get("then") if not condition_issues else schema.get("else")
        if branch is not None:
            issues.extend(
                validate_schema(value, branch, root_schema=root, location=location)
            )

    expected_type = schema.get("type")
    if expected_type is not None:
        allowed_types = (
            [expected_type] if isinstance(expected_type, str) else expected_type
        )
        if not any(_type_matches(value, item) for item in allowed_types):
            issues.append(
                ValidationIssue(
                    location,
                    f"expected type {allowed_types}, got {type(value).__name__}",
                )
            )
            return issues

    if "const" in schema and value != schema["const"]:
        issues.append(ValidationIssue(location, f"must equal {schema['const']!r}"))
    if "enum" in schema and value not in schema["enum"]:
        issues.append(ValidationIssue(location, f"must be one of {schema['enum']!r}"))

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                issues.append(
                    ValidationIssue(location, f"missing required property '{key}'")
                )

        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    issues.append(
                        ValidationIssue(
                            f"{location}.{key}", "additional property is not allowed"
                        )
                    )
        for key, property_schema in properties.items():
            if key in value:
                issues.extend(
                    validate_schema(
                        value[key],
                        property_schema,
                        root_schema=root,
                        location=f"{location}.{key}",
                    )
                )

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            issues.append(
                ValidationIssue(
                    location, f"must contain at least {schema['minItems']} items"
                )
            )
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            issues.append(
                ValidationIssue(
                    location, f"must contain at most {schema['maxItems']} items"
                )
            )
        if schema.get("uniqueItems"):
            encoded = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                issues.append(ValidationIssue(location, "array items must be unique"))
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                issues.extend(
                    validate_schema(
                        item,
                        item_schema,
                        root_schema=root,
                        location=f"{location}[{index}]",
                    )
                )

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            issues.append(
                ValidationIssue(
                    location, f"must be at least {schema['minLength']} characters"
                )
            )
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            issues.append(
                ValidationIssue(
                    location, f"must be at most {schema['maxLength']} characters"
                )
            )
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            issues.append(
                ValidationIssue(
                    location, f"does not match required pattern {schema['pattern']!r}"
                )
            )
        if schema.get("format") == "date-time" and not _is_datetime(value):
            issues.append(
                ValidationIssue(location, "must be an offset-aware ISO 8601 date-time")
            )

    return issues


def extract_approved_probes(catalog_path: Path) -> dict[str, dict[str, str]]:
    """Parse approved probe IDs and domains without importing application code."""

    source = catalog_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(catalog_path))
    probes_node: ast.Dict | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "PROBES"
            for target in node.targets
        ):
            if isinstance(node.value, ast.Dict):
                probes_node = node.value
            break
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "PROBES"
            and isinstance(node.value, ast.Dict)
        ):
            probes_node = node.value
            break

    if probes_node is None:
        raise ValueError("could not find a literal PROBES dictionary")

    approved: dict[str, dict[str, str]] = {}
    for platform_key, platform_value in zip(
        probes_node.keys, probes_node.values, strict=True
    ):
        if not (
            isinstance(platform_key, ast.Attribute)
            and isinstance(platform_key.value, ast.Name)
            and platform_key.value.id == "DatabasePlatform"
        ):
            raise ValueError("PROBES contains an unsupported platform key")
        platform = PLATFORM_ENUM_NAMES.get(platform_key.attr)
        if platform is None or not isinstance(platform_value, ast.Dict):
            raise ValueError(
                f"PROBES contains unsupported platform '{platform_key.attr}'"
            )

        platform_probes: dict[str, str] = {}
        for declared_key, probe_call in zip(
            platform_value.keys, platform_value.values, strict=True
        ):
            if not (
                isinstance(declared_key, ast.Constant)
                and isinstance(declared_key.value, str)
                and isinstance(probe_call, ast.Call)
                and isinstance(probe_call.func, ast.Name)
                and probe_call.func.id == "Probe"
                and len(probe_call.args) >= 2
            ):
                raise ValueError(f"unsupported Probe declaration for {platform}")
            probe_id = ast.literal_eval(probe_call.args[0])
            domain = ast.literal_eval(probe_call.args[1])
            if declared_key.value != probe_id:
                raise ValueError(
                    f"probe dictionary key '{declared_key.value}' differs from Probe.id '{probe_id}'"
                )
            if not isinstance(domain, str):
                raise TypeError(f"probe domain for '{probe_id}' is not a string")
            platform_probes[probe_id] = domain
        approved[platform] = platform_probes
    return approved


def _find_forbidden_fields(
    value: Any, location: str = "$"
) -> Iterable[ValidationIssue]:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.lower().replace("-", "_")
            if normalized in FORBIDDEN_FIELD_NAMES:
                yield ValidationIssue(
                    f"{location}.{key}",
                    "forbidden field name; packs may contain only probe references and metadata",
                )
            yield from _find_forbidden_fields(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _find_forbidden_fields(child, f"{location}[{index}]")


def _schema_is_closed(
    schema: Any, location: str = "$", root: Mapping[str, Any] | None = None
) -> list[ValidationIssue]:
    """Require every object declared by a schema to reject unknown fields."""

    issues: list[ValidationIssue] = []
    if not isinstance(schema, dict):
        return issues
    root = root or schema
    if (
        schema.get("type") == "object"
        and schema.get("additionalProperties") is not False
    ):
        issues.append(
            ValidationIssue(
                location, "object schema must set additionalProperties to false"
            )
        )
    for key, child in schema.items():
        if key == "$ref":
            continue
        if isinstance(child, dict):
            issues.extend(_schema_is_closed(child, f"{location}.{key}", root))
        elif isinstance(child, list):
            for index, item in enumerate(child):
                issues.extend(
                    _schema_is_closed(item, f"{location}.{key}[{index}]", root)
                )
    return issues


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _semver(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def validate_repository(
    control_pack_root: Path = DEFAULT_CONTROL_PACK_ROOT,
    query_catalog: Path = DEFAULT_QUERY_CATALOG,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    manifest_path = control_pack_root / "manifest.json"
    pack_schema_path = control_pack_root / "schema" / "control-pack.schema.json"
    manifest_schema_path = control_pack_root / "schema" / "manifest.schema.json"

    required_files = [
        manifest_path,
        pack_schema_path,
        manifest_schema_path,
        query_catalog,
    ]
    for required_file in required_files:
        if not required_file.is_file():
            issues.append(
                ValidationIssue(str(required_file), "required file is missing")
            )
    if issues:
        return issues

    try:
        manifest = load_json(manifest_path)
        pack_schema = load_json(pack_schema_path)
        manifest_schema = load_json(manifest_schema_path)
    except (OSError, json.JSONDecodeError, DuplicateKeyError) as exc:
        return [ValidationIssue("control-packs", f"failed to load JSON: {exc}")]

    issues.extend(_schema_is_closed(pack_schema, str(pack_schema_path)))
    issues.extend(_schema_is_closed(manifest_schema, str(manifest_schema_path)))
    issues.extend(
        validate_schema(
            manifest,
            manifest_schema,
            location=str(manifest_path),
        )
    )
    if not isinstance(manifest, dict) or not isinstance(manifest.get("packs"), list):
        return issues

    try:
        approved_probes = extract_approved_probes(query_catalog)
    except (OSError, SyntaxError, ValueError) as exc:
        issues.append(
            ValidationIssue(str(query_catalog), f"cannot load approved probes: {exc}")
        )
        return issues

    seen_versions: set[tuple[str, str]] = set()
    manifest_paths: set[str] = set()
    entries_by_version: dict[tuple[str, str], Mapping[str, Any]] = {}
    parsed_packs: list[tuple[Mapping[str, Any], Mapping[str, Any], Path]] = []

    for index, entry in enumerate(manifest["packs"]):
        entry_location = f"{manifest_path}.packs[{index}]"
        if not isinstance(entry, dict):
            continue
        pack_id = entry.get("pack_id")
        version = entry.get("version")
        platform = entry.get("platform")
        relative_path = entry.get("path")
        if not all(
            isinstance(item, str)
            for item in (pack_id, version, platform, relative_path)
        ):
            continue

        identity = (pack_id, version)
        if identity in seen_versions:
            issues.append(
                ValidationIssue(
                    entry_location, f"duplicate immutable version {identity}"
                )
            )
        seen_versions.add(identity)
        entries_by_version[identity] = entry

        posix_path = PurePosixPath(relative_path)
        if (
            posix_path.is_absolute()
            or ".." in posix_path.parts
            or "\\" in relative_path
        ):
            issues.append(
                ValidationIssue(
                    entry_location, "path must be a normalized relative POSIX path"
                )
            )
            continue
        expected_path = f"packs/{platform}/database-security/{version}.json"
        if relative_path != expected_path:
            issues.append(
                ValidationIssue(
                    entry_location, f"immutable version path must be '{expected_path}'"
                )
            )
        if relative_path in manifest_paths:
            issues.append(
                ValidationIssue(
                    entry_location, f"duplicate manifest path '{relative_path}'"
                )
            )
        manifest_paths.add(relative_path)

        pack_path = control_pack_root.joinpath(*posix_path.parts)
        try:
            if not pack_path.resolve().is_relative_to(control_pack_root.resolve()):
                issues.append(
                    ValidationIssue(
                        entry_location, "path escapes the control-pack root"
                    )
                )
                continue
        except OSError as exc:
            issues.append(
                ValidationIssue(entry_location, f"cannot resolve pack path: {exc}")
            )
            continue
        if not pack_path.is_file():
            issues.append(
                ValidationIssue(str(pack_path), "manifest references a missing pack")
            )
            continue

        actual_digest = _sha256(pack_path)
        if entry.get("sha256") != actual_digest:
            issues.append(
                ValidationIssue(
                    str(pack_path),
                    f"sha256 mismatch; expected {entry.get('sha256')}, calculated {actual_digest}",
                )
            )
        try:
            pack = load_json(pack_path)
        except (OSError, json.JSONDecodeError, DuplicateKeyError) as exc:
            issues.append(
                ValidationIssue(str(pack_path), f"failed to load JSON: {exc}")
            )
            continue

        issues.extend(validate_schema(pack, pack_schema, location=str(pack_path)))
        issues.extend(_find_forbidden_fields(pack, str(pack_path)))
        if not isinstance(pack, dict):
            continue
        parsed_packs.append((entry, pack, pack_path))

        expected_pack_id = f"aegisdb.database-security.{platform}"
        if pack.get("pack_id") != pack_id or pack_id != expected_pack_id:
            issues.append(
                ValidationIssue(
                    str(pack_path),
                    "pack_id must match the platform and manifest identity",
                )
            )
        if pack.get("version") != version:
            issues.append(
                ValidationIssue(
                    str(pack_path), "pack version differs from manifest version"
                )
            )
        if pack.get("platform") != platform:
            issues.append(
                ValidationIssue(
                    str(pack_path), "pack platform differs from manifest platform"
                )
            )
        release = pack.get("release")
        if isinstance(release, dict) and release.get("status") != entry.get("status"):
            issues.append(
                ValidationIssue(
                    str(pack_path), "release status differs from manifest status"
                )
            )

        controls = pack.get("controls")
        if not isinstance(controls, list):
            continue
        control_ids: set[str] = set()
        domains: set[str] = set()
        for control_index, control in enumerate(controls):
            control_location = f"{pack_path}.controls[{control_index}]"
            if not isinstance(control, dict):
                continue
            control_id = control.get("id")
            domain = control.get("domain")
            if isinstance(control_id, str):
                if control_id in control_ids:
                    issues.append(
                        ValidationIssue(
                            control_location, f"duplicate control id '{control_id}'"
                        )
                    )
                control_ids.add(control_id)
            if isinstance(domain, str):
                domains.add(domain)

            assessment = control.get("assessment")
            evidence = control.get("evidence")
            if not isinstance(assessment, dict):
                continue
            probe_ids = assessment.get("probe_ids")
            if not isinstance(probe_ids, list):
                continue
            for probe_id in probe_ids:
                if not isinstance(probe_id, str):
                    continue
                approved_domain = approved_probes.get(platform, {}).get(probe_id)
                if approved_domain is None:
                    issues.append(
                        ValidationIssue(
                            control_location,
                            f"probe '{probe_id}' is not approved for platform '{platform}'",
                        )
                    )
                elif approved_domain != domain:
                    issues.append(
                        ValidationIssue(
                            control_location,
                            f"probe '{probe_id}' belongs to domain '{approved_domain}', not '{domain}'",
                        )
                    )

            allowed_fields = (
                evidence.get("allowed_fields") if isinstance(evidence, dict) else None
            )
            if assessment.get("mode") == "automated_evidence" and not allowed_fields:
                issues.append(
                    ValidationIssue(
                        control_location,
                        "automated evidence must declare allowed metadata fields",
                    )
                )
            if assessment.get("mode") == "manual_evidence" and allowed_fields:
                issues.append(
                    ValidationIssue(
                        control_location,
                        "manual evidence cannot declare collector output fields",
                    )
                )

        missing_domains = EXPECTED_DOMAINS - domains
        extra_domains = domains - EXPECTED_DOMAINS
        if missing_domains:
            issues.append(
                ValidationIssue(
                    str(pack_path),
                    f"missing required control domains: {sorted(missing_domains)}",
                )
            )
        if extra_domains:
            issues.append(
                ValidationIssue(
                    str(pack_path),
                    f"unsupported control domains: {sorted(extra_domains)}",
                )
            )

    discovered_paths = {
        path.relative_to(control_pack_root).as_posix()
        for path in (control_pack_root / "packs").glob("**/*.json")
        if path.is_file()
    }
    for unregistered in sorted(discovered_paths - manifest_paths):
        issues.append(
            ValidationIssue(
                unregistered,
                "versioned pack is not registered in the immutable manifest",
            )
        )
    for missing in sorted(manifest_paths - discovered_paths):
        issues.append(ValidationIssue(missing, "manifest pack is not present on disk"))

    active_by_pack: dict[str, list[str]] = {}
    for entry, pack, pack_path in parsed_packs:
        pack_id = pack.get("pack_id")
        version = pack.get("version")
        release = pack.get("release")
        if (
            not isinstance(pack_id, str)
            or not isinstance(version, str)
            or not isinstance(release, dict)
        ):
            continue
        if release.get("status") == "active":
            active_by_pack.setdefault(pack_id, []).append(version)
        supersedes = release.get("supersedes")
        if isinstance(supersedes, str):
            prior = entries_by_version.get((pack_id, supersedes))
            if prior is None:
                issues.append(
                    ValidationIssue(
                        str(pack_path),
                        f"supersedes unregistered version '{supersedes}'",
                    )
                )
            elif _semver(supersedes) >= _semver(version):
                issues.append(
                    ValidationIssue(
                        str(pack_path),
                        "superseded version must be lower than the new version",
                    )
                )
    for pack_id, active_versions in active_by_pack.items():
        if len(active_versions) > 1:
            issues.append(
                ValidationIssue(
                    str(manifest_path),
                    f"pack '{pack_id}' has multiple active versions: {sorted(active_versions)}",
                )
            )

    return issues


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_CONTROL_PACK_ROOT,
        help="control-packs directory (default: repository control-packs)",
    )
    parser.add_argument(
        "--query-catalog",
        type=Path,
        default=DEFAULT_QUERY_CATALOG,
        help="approved API query_catalog.py source",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    issues = validate_repository(args.root.resolve(), args.query_catalog.resolve())
    if issues:
        print(
            f"Control-pack validation failed with {len(issues)} issue(s):",
            file=sys.stderr,
        )
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1

    manifest = load_json(args.root / "manifest.json")
    pack_count = len(manifest["packs"])
    control_count = 0
    for entry in manifest["packs"]:
        pack = load_json(args.root / entry["path"])
        control_count += len(pack["controls"])
    print(
        f"Validated {pack_count} immutable control pack(s), {control_count} control(s), "
        "and all approved probe references."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
