#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_CONTRACT = ROOT / "config" / "runtime-entrypoint.json"
CAPABILITY_CATALOG = ROOT / "contracts" / "capability-catalog.v1.json"
OUTPUT = ROOT / "contracts" / "publication-profiles.v1.json"
CORE_RISK_CLASSES = {"low", "medium"}
CORE_ALLOWED_EFFECTS = {"remote-read"}
CORE_TOOLS = {
    "grabowski_verify_audit",
    "grabowski_runtime_health",
    "grabowski_deployment_identity",
    "grabowski_contract_drift",
    "grabowski_checkout_summary",
    "grabowski_git_status",
    "grabowski_git_diff",
    "grabowski_git_log",
    "grabowski_git_show",
    "grabowski_github_pr_view",
    "grabowski_github_checks",
    "grabowski_service_status",
    "grabowski_service_logs",
    "grabowski_ports",
    "grabowski_fleet_list",
    "grabowski_privileged_broker_status",
    "grabowski_recovery_status",
    "repoground_bundle_discover",
    "repoground_bundle_status",
    "repoground_freshness_check",
    "repoground_context_pack",
    "repoground_context_compose",
}
OPERATOR_ORIENTATION_TOOLS = {
    "grabowski_runtime_health",
    "grabowski_contract_drift",
    "repoground_bundle_discover",
    "repoground_bundle_status",
    "repoground_freshness_check",
    "repoground_context_pack",
    "repoground_context_compose",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _effects_are_observational(record: dict[str, Any]) -> bool:
    effects = record.get("effects")
    if not isinstance(effects, list) or not all(isinstance(item, str) for item in effects):
        raise ValueError(f"invalid effects for capability record: {record.get('tool')}")
    return set(effects).issubset(CORE_ALLOWED_EFFECTS)


def build() -> dict[str, Any]:
    contract = load_json(RUNTIME_CONTRACT)
    catalog = load_json(CAPABILITY_CATALOG)
    expected = contract.get("expected_tools")
    records = catalog.get("tools")
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        raise ValueError("runtime expected_tools must be a string list")
    if not isinstance(records, list):
        raise ValueError("capability catalog tools must be a list")

    by_tool: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("tool"), str):
            raise ValueError("invalid capability record")
        tool = record["tool"]
        if tool in by_tool:
            raise ValueError(f"duplicate capability record: {tool}")
        by_tool[tool] = record

    if set(expected) != set(by_tool):
        missing = sorted(set(expected) - set(by_tool))
        extra = sorted(set(by_tool) - set(expected))
        raise ValueError(f"contract/catalog mismatch: missing={missing}, extra={extra}")

    missing_core = sorted(CORE_TOOLS - set(expected))
    if missing_core:
        raise ValueError(f"core tools missing from runtime contract: {missing_core}")

    core = [
        tool
        for tool in expected
        if tool in CORE_TOOLS
        and by_tool[tool].get("read_only") is True
        and by_tool[tool].get("risk_class") in CORE_RISK_CLASSES
        and _effects_are_observational(by_tool[tool])
    ]
    if set(core) != CORE_TOOLS:
        rejected = sorted(CORE_TOOLS - set(core))
        raise ValueError(f"core tools violate publication constraints: {rejected}")

    core_set = set(core)
    operator = [
        tool
        for tool in expected
        if tool not in core_set or tool in OPERATOR_ORIENTATION_TOOLS
    ]
    return {
        "schema_version": 1,
        "status": "design-and-canary-only",
        "canonical_contract": {
            "path": "config/runtime-entrypoint.json",
            "sha256": sha256(RUNTIME_CONTRACT),
        },
        "capability_catalog": {
            "path": "contracts/capability-catalog.v1.json",
            "sha256": sha256(CAPABILITY_CATALOG),
        },
        "rules": {
            "full": {"selection": "all expected_tools"},
            "core": {
                "read_only": True,
                "risk_classes": sorted(CORE_RISK_CLASSES),
                "allowed_effects": sorted(CORE_ALLOWED_EFFECTS),
                "explicit_tools": sorted(CORE_TOOLS),
            },
            "operator": {
                "selection": "all tools not in core plus orientation tools",
                "orientation_tools": sorted(OPERATOR_ORIENTATION_TOOLS),
            },
        },
        "profiles": {
            "core": core,
            "operator": operator,
            "full": list(expected),
        },
        "counts": {
            "core": len(core),
            "operator": len(operator),
            "full": len(expected),
        },
        "registration": {
            "second_connector_created": False,
            "requires_canary_evidence": True,
        },
    }


def render(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    content = render(build())
    if args.write:
        OUTPUT.write_text(content, encoding="utf-8")
        print(OUTPUT.relative_to(ROOT))
        return 0
    try:
        current = OUTPUT.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"missing generated profile contract: {OUTPUT.relative_to(ROOT)}")
        return 1
    if current != content:
        print(f"stale generated profile contract: {OUTPUT.relative_to(ROOT)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
