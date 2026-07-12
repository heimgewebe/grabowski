#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "runtime-entrypoint.json"
POLICY_PATH = ROOT / "config" / "access.example.json"
CAPABILITIES_PATH = ROOT / "src" / "grabowski_capabilities.py"
CATALOG_PATH = ROOT / "contracts" / "capability-catalog.v1.json"
CONTEXT_JSON_PATH = ROOT / "docs" / "generated" / "operator-context.v1.json"
CONTEXT_MD_PATH = ROOT / "docs" / "generated" / "operator-context.md"
PROTOCOL_PATH = ROOT / "docs" / "blocked-action-protocol-v0.md"
READ_ANNOTATION_NAMES = {"READ_ANNOTATIONS", "READ_ONLY", "LOCAL_READ", "REMOTE_READ"}
WRITE_ANNOTATION_NAMES = {
    "CREATE_ANNOTATIONS",
    "REPLACE_ANNOTATIONS",
    "REMOVE_ANNOTATIONS",
    "SECRET_REVEAL_ANNOTATIONS",
    "MUTATING",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_capabilities_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "grabowski_capabilities_build",
        CAPABILITIES_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load capability definitions")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tool_declaration(node: ast.AST) -> tuple[str, bool | None] | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        function = decorator.func
        if not (
            isinstance(function, ast.Attribute)
            and function.attr == "tool"
        ):
            continue
        tool_name: str | None = None
        read_only: bool | None = None
        for keyword in decorator.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                tool_name = keyword.value.value
            if keyword.arg == "annotations" and isinstance(keyword.value, ast.Name):
                if keyword.value.id in READ_ANNOTATION_NAMES:
                    read_only = True
                elif keyword.value.id in WRITE_ANNOTATION_NAMES:
                    read_only = False
        if tool_name is not None:
            return tool_name, read_only
    return None


def _source_records(contract: dict[str, Any]) -> list[dict[str, str]]:
    records = [
        {
            "module": str(contract["module"]),
            "source": str(contract["source"]),
        }
    ]
    records.extend(contract.get("supporting_sources", []))
    return records


def _discover_tools(
    contract: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    tools: dict[str, dict[str, Any]] = {}
    source_hashes: dict[str, str] = {}
    for record in _source_records(contract):
        relative = str(record["source"])
        source_path = ROOT / relative
        source_hashes[relative] = _sha256(source_path)
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=relative)
        for node in tree.body:
            declaration = _tool_declaration(node)
            if declaration is None:
                continue
            name, read_only = declaration
            if name in tools:
                raise ValueError(f"Duplicate MCP tool declaration: {name}")
            assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            tools[name] = {
                "tool": name,
                "function": node.name,
                "source": relative,
                "description": ast.get_docstring(node) or "",
                "read_only": read_only,
            }
    return tools, dict(sorted(source_hashes.items()))


def build_documents() -> tuple[dict[str, Any], dict[str, Any], str]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    capabilities = _load_capabilities_module()
    profiles = policy.get("profiles", {})
    active_profile_name = policy.get("active_profile", policy.get("mode"))
    active_profile = (
        profiles.get(active_profile_name, {})
        if isinstance(profiles, dict) and isinstance(active_profile_name, str)
        else {}
    )
    if not isinstance(active_profile, dict):
        active_profile = {}

    def policy_values(key: str, default: Any = None) -> Any:
        if key in active_profile:
            return active_profile[key]
        return policy.get(key, default)

    def format_policy_values(key: str) -> str:
        values = policy_values(key, [])
        if not values:
            return "`none`"
        return ", ".join(f"`{item}`" for item in values)

    discovered, source_hashes = _discover_tools(contract)
    expected_tools = list(contract["expected_tools"])
    descriptions = {
        name: record["description"]
        for name, record in discovered.items()
    }
    read_only = {
        name: record["read_only"]
        for name, record in discovered.items()
    }
    records = capabilities.capability_records(
        expected_tools,
        descriptions=descriptions,
        read_only=read_only,
    )
    classification = capabilities.classify_contract(expected_tools)
    expected_set = set(expected_tools)
    discovered_set = set(discovered)
    integrity = {
        **classification,
        "missing_declarations": sorted(expected_set - discovered_set),
        "undeclared_tools": sorted(discovered_set - expected_set),
    }

    catalog = {
        "schema_version": capabilities.CATALOG_SCHEMA_VERSION,
        "contract": "config/runtime-entrypoint.json",
        "contract_sha256": _sha256(CONTRACT_PATH),
        "capability_source": "src/grabowski_capabilities.py",
        "capability_source_sha256": _sha256(CAPABILITIES_PATH),
        "tools": records,
        "integrity": integrity,
    }
    context = {
        "schema_version": capabilities.CONTEXT_SCHEMA_VERSION,
        "kind": "repository-operator-context",
        "purpose": (
            "Deterministic repository contract for the Grabowski operator. "
            "Live state is returned by the grabowski_context MCP tool."
        ),
        "sources": {
            "runtime_contract": {
                "path": "config/runtime-entrypoint.json",
                "sha256": _sha256(CONTRACT_PATH),
            },
            "policy_example": {
                "path": "config/access.example.json",
                "sha256": _sha256(POLICY_PATH),
            },
            "capability_definitions": {
                "path": "src/grabowski_capabilities.py",
                "sha256": _sha256(CAPABILITIES_PATH),
            },
            "runtime_sources": source_hashes,
            "blocked_action_protocol": {
                "path": "docs/blocked-action-protocol-v0.md",
                "sha256": _sha256(PROTOCOL_PATH),
            },
        },
        "operating_protocol": {
            "name": "Operator Relay v0",
            "doc_path": "docs/blocked-action-protocol-v0.md",
            "rule": (
                "Keep ChatGPT as operator and execute bounded work first. "
                "Delegate only when a helper adds useful scale or independent contrast."
            ),
            "control_loop": [
                "typed_grabowski_tool",
                "grabowski_micro_task",
                "receipt_before_next_step",
            ],
            "execution_priority": [
                "chatgpt_operator",
                "claude",
                "codex",
                "agy",
                "cline",
            ],
            "coding_agent_priority": [
                "claude",
                "codex",
                "agy",
                "cline",
            ],
            "workspace_execution_model": {
                "default": "adaptive_operator_routing",
                "lane_owner": "chatgpt_operator",
                "operator_self_serves_lanes": ["captain", "writer", "tests", "review"],
                "role_evidence_isolated": True,
                "workspace_not_universal": True,
                "direct_operator_for": [
                    "small_low_risk_fix",
                    "simple_document_change",
                    "bounded_deterministic_edit",
                ],
                "full_workspace_for": [
                    "runtime_or_security_change",
                    "long_or_multi_file_implementation",
                    "parallel_or_foreign_state",
                    "connector_or_execution_state_uncertainty",
                ],
                "external_agent_delegation": "adaptive_opt_in",
                "delegation_triggers": [
                    "high_novelty_design_space",
                    "independent_contrast",
                    "multiple_plausible_implementations",
                    "security_schema_or_concurrency_risk",
                    "capacity_fallback",
                ],
                "external_programming_modes": ["competitor", "contrast"],
                "max_external_candidates": 2,
                "external_candidate_authority": "advisory_only",
                "automatic_patch_apply": False,
                "automatic_winner_selection": False,
            },
            "operator_first_for": [
                "task_decomposition",
                "bounded_code_change",
                "integration",
                "critical_self_review",
                "recovery",
            ],
            "routing_roles": {
                "complex_code_task": "chatgpt_operator_adaptive_workspace_external_competition_when_high_value",
                "quick_light_reasoning": "chatgpt_operator_external_opt_in_agy_print",
                "local_micro_reasoning": "ollama_api_qwen_coder",
                "shell_or_git_grip": "grabowski_task",
                "security_or_architecture_review": "chatgpt_operator_external_opt_in_claude",
                "session_resume": "tmux_first_agy_when_useful",
                "memory_prioritization": "bureau",
                "patch_file_relay": "operator_patch_relay",
                "patch_fallback": "aider_no_auto_commit",
                "audit": "grabowski_git",
                "repo_state_context": "steuerboard_operator_report",
            },
            "does_not_establish": [
                "new_privileges",
                "automatic_merge",
                "automatic_push",
                "automatic_deploy",
                "free_shell_as_default_path",
                "durable_agent_autonomy",
                "steuerboard_report_action_approval",
            ],
        },
        "runtime_contract": {
            "module": contract["module"],
            "source": contract["source"],
            "supporting_sources": contract.get("supporting_sources", []),
            "expected_tools": expected_tools,
        },
        "policy_contract": {
            "mode": policy.get("mode"),
            "active_profile": active_profile_name,
            "access_profiles": sorted(profiles) if isinstance(profiles, dict) else [],
            "capabilities": policy_values("capabilities", []),
            "read_roots": policy_values("read_roots", []),
            "write_roots": policy_values("write_roots", []),
            "write_excluded_roots": policy_values("write_excluded_roots", []),
            "secret_roots": policy_values("secret_roots", []),
            "browser_profile_roots": policy_values("browser_profile_roots", []),
            "secret_export_roots": policy_values("secret_export_roots", []),
            "forbidden_capabilities": policy.get("forbidden_capabilities", []),
        },
        "capabilities": records,
        "integrity": integrity,
    }

    lines = [
        "# Generated Grabowski Operator Context",
        "",
        "> Generated by `tools/build_operator_context.py`. Do not edit manually.",
        "",
        "This document describes the repository contract. Current runtime state must be read through `grabowski_context`.",
        "",
        "## Operator relay protocol",
        "",
        "- Name: `Operator Relay v0`",
        "- Source: `docs/blocked-action-protocol-v0.md`",
        "- Control loop: typed Grabowski tool first; if blocked, one bounded Grabowski Micro-Task; then read a receipt before deciding the next step.",
        "- Execution priority: ChatGPT operator first; delegated coding agents follow Claude, Codex, agy, then Cline.",
        "- Workspace routing: use direct operator execution for small low-risk edits; use isolated role evidence for long, risky, parallel or state-uncertain work.",
        "- External programming: at most two opt-in competitor/contrast candidates may challenge the primary approach; their patches remain advisory and are never applied or selected automatically.",
        "- Operator-first work: task decomposition, bounded code changes, integration, critical self-review and recovery.",
        "- Complex code task: the operator remains integrator; high-value design spaces may add bounded Claude/agy competition or contrast before the normal Writer, Tests and Review path.",
        "- Quick light reasoning: operator first, then agy `--print` when delegation adds value.",
        "- Local micro reasoning: Ollama API with qwen coder.",
        "- Patch file relay: local patch files use `tools/operator_patch_relay.py` for check/apply receipts before user manual execution.",
        "- Review: operator first; Claude provides independent architecture and safety contrast.",
        "- Session: tmux first; agy only when available and better for resume.",
        "- Steuerboard: `operator report` is a lightweight read-only repo-state context signal; no separate trial/noise logging; never an approval gate.",
        "",
        "## Contract integrity",
        "",
    ]
    finding_count = sum(len(value) for value in integrity.values())
    if finding_count == 0:
        lines.append("All expected tools are declared and classified; no orphan declarations or profiles exist.")
    else:
        for key, values in integrity.items():
            lines.append(f"- `{key}`: {', '.join(values) if values else 'none'}")
    lines.extend(
        [
            "",
            "## Capabilities",
            "",
            "| Tool | Category | Read only | Risk | Purpose |",
            "|---|---|---:|---|---|",
        ]
    )
    for item in records:
        read_label = "yes" if item["read_only"] is True else "no" if item["read_only"] is False else "unknown"
        purpose = str(item["purpose"]).replace("|", "\\|")
        lines.append(
            f"| `{item['tool']}` | {item['category']} | {read_label} | {item['risk_class']} | {purpose} |"
        )
    lines.extend(
        [
            "",
            "## Policy contract",
            "",
            f"- Mode: `{policy.get('mode', 'unknown')}`",
            f"- Active profile: `{active_profile_name or 'unknown'}`",
            f"- Capabilities: {format_policy_values('capabilities')}",
            f"- Read roots: {format_policy_values('read_roots')}",
            f"- Write roots: {format_policy_values('write_roots')}",
            f"- Read-only exclusions: {format_policy_values('write_excluded_roots')}",
            f"- Secret roots: {format_policy_values('secret_roots')}",
            f"- Browser profile roots: {format_policy_values('browser_profile_roots')}",
            f"- Secret export roots: {format_policy_values('secret_export_roots')}",
            f"- Forbidden capabilities: {format_policy_values('forbidden_capabilities')}",
            "",
            "## Update contract",
            "",
            "`make context-refresh` regenerates this document and the JSON catalog. `make validate` fails when generated artifacts are stale or a tool is missing a declaration or capability profile.",
            "",
        ]
    )
    return catalog, context, "\n".join(lines)


def _json_text(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _expected_outputs() -> dict[Path, str]:
    catalog, context, markdown = build_documents()
    return {
        CATALOG_PATH: _json_text(catalog),
        CONTEXT_JSON_PATH: _json_text(context),
        CONTEXT_MD_PATH: markdown,
    }


def _integrity_errors(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key, values in payload["integrity"].items():
        if values:
            errors.append(f"{key}: {', '.join(values)}")
    return errors


def write_outputs() -> int:
    outputs = _expected_outputs()
    catalog = json.loads(outputs[CATALOG_PATH])
    errors = _integrity_errors(catalog)
    if errors:
        print("Capability contract is incomplete:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(path.relative_to(ROOT))
    return 0


def check_outputs() -> int:
    outputs = _expected_outputs()
    catalog = json.loads(outputs[CATALOG_PATH])
    errors = _integrity_errors(catalog)
    stale: list[str] = []
    for path, expected in outputs.items():
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            stale.append(str(path.relative_to(ROOT)))
    if errors or stale:
        if errors:
            print("Capability contract is incomplete:", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
        if stale:
            print(
                "Generated operator context is stale; run make context-refresh:",
                file=sys.stderr,
            )
            for path in stale:
                print(f"- {path}", file=sys.stderr)
        return 1
    print("operator context: current")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    return write_outputs() if arguments.write else check_outputs()


if __name__ == "__main__":
    raise SystemExit(main())
