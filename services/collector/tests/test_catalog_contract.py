from __future__ import annotations

import ast
from pathlib import Path

from assurance_collector.catalog import PROBES

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
API_CATALOG = REPOSITORY_ROOT / "services" / "api" / "assurance_hub" / "query_catalog.py"


def _api_contract() -> dict[str, tuple[str, str]]:
    tree = ast.parse(API_CATALOG.read_text(encoding="utf-8"), filename=str(API_CATALOG))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.AnnAssign)
        and isinstance(node.target, ast.Name)
        and node.target.id == "PROBES"
    )
    assert isinstance(assignment.value, ast.Dict)
    contract: dict[str, tuple[str, str]] = {}
    for platform_node, probes_node in zip(
        assignment.value.keys,
        assignment.value.values,
        strict=True,
    ):
        assert isinstance(platform_node, ast.Attribute)
        platform = platform_node.attr.lower()
        assert isinstance(probes_node, ast.Dict)
        for probe_node in probes_node.values:
            assert isinstance(probe_node, ast.Call)
            probe_id = ast.literal_eval(probe_node.args[0])
            domain = ast.literal_eval(probe_node.args[1])
            sql = ast.literal_eval(probe_node.args[2])
            contract[probe_id] = (platform, domain, sql)
    return contract


def test_api_and_collector_probe_catalogues_are_exactly_aligned() -> None:
    collector_contract = {
        probe_id: (probe.platform.value, probe.domain, probe.sql)
        for probe_id, probe in PROBES.items()
    }
    assert collector_contract == _api_contract()
