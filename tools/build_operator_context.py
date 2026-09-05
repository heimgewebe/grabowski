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
OPERATOR_RELAY_PATH = ROOT / "src" / "grabowski_operator_relay.py"
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
    "SECRET_USE_ANNOTATIONS",
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


def _load_operator_relay_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "grabowski_operator_relay_build",
        OPERATOR_RELAY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load operator relay contract")
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


SEMANTIC_SOURCE_DIGEST_CONTRACT = "mcp-tool-surface-v1"


def _canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ast_contract(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    dumped = ast.dump(node, annotate_fields=True, include_attributes=False)
    # Python 3.12 added ``type_params`` to FunctionDef/AsyncFunctionDef/ClassDef.
    # An empty field is parser-version metadata, not a source-contract change.
    # Non-empty type parameters remain in the dump and therefore stay digest-bound.
    return dumped.replace(", type_params=[]", "")


def _bound_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def _qualified_references(node: ast.AST | None) -> set[tuple[str, str]]:
    if node is None:
        return set()
    references: set[tuple[str, str]] = set()
    for item in ast.walk(node):
        if not isinstance(item, ast.Attribute):
            continue
        root: ast.AST = item
        attributes: list[str] = []
        while isinstance(root, ast.Attribute):
            attributes.append(root.attr)
            root = root.value
        if isinstance(root, ast.Name) and attributes:
            references.add((root.id, attributes[-1]))
    return references


def _string_annotation_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    names: set[str] = set()
    for item in ast.walk(node):
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            continue
        try:
            parsed = ast.parse(item.value, mode="eval")
        except SyntaxError:
            continue
        names.update(_bound_names(parsed))
    return names


def _function_annotation_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    arguments = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    if node.args.vararg is not None:
        arguments.append(node.args.vararg)
    if node.args.kwarg is not None:
        arguments.append(node.args.kwarg)
    annotations = [
        arg.annotation for arg in arguments if arg.annotation is not None
    ]
    if node.returns is not None:
        annotations.append(node.returns)
    annotations.extend(getattr(node, "type_params", []))
    return annotations


def _function_contract_reference_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    references: list[ast.AST] = []
    for decorator in node.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "tool"
        ):
            references.extend(decorator.args)
            references.extend(keyword.value for keyword in decorator.keywords)
        else:
            references.append(decorator)
    references.extend(node.args.defaults)
    references.extend(value for value in node.args.kw_defaults if value is not None)
    references.extend(_function_annotation_nodes(node))
    return references


def _definition_names(node: ast.AST) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        names: set[str] = set()
        for target in targets:
            for item in ast.walk(target):
                if isinstance(item, ast.Name):
                    names.add(item.id)
        return names
    type_alias = getattr(ast, "TypeAlias", None)
    if type_alias is not None and isinstance(node, type_alias):
        name = getattr(node, "name", None)
        return {name.id} if isinstance(name, ast.Name) else set()
    return set()


def _source_contract_index(source_text: str, *, filename: str) -> dict[str, Any]:
    tree = ast.parse(source_text, filename=filename)
    definitions: dict[str, dict[str, Any]] = {}
    imports: dict[str, dict[str, Any]] = {}
    tools: list[dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            contract_sha256 = _canonical_json_sha256(
                {"kind": "import", "ast": _ast_contract(node)}
            )
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                imports[local_name] = {
                    "contract_sha256": contract_sha256,
                    "module": alias.name,
                    "symbol": None,
                }
        elif isinstance(node, ast.ImportFrom):
            contract_sha256 = _canonical_json_sha256(
                {"kind": "import", "ast": _ast_contract(node)}
            )
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname or alias.name
                imports[local_name] = {
                    "contract_sha256": contract_sha256,
                    "module": module,
                    "symbol": alias.name,
                }
        else:
            names = _definition_names(node)
            if names:
                contract_sha256 = _canonical_json_sha256(
                    {"kind": "definition", "ast": _ast_contract(node)}
                )
                references = _bound_names(node)
                qualified = _qualified_references(node)
                for name in names:
                    definitions[name] = {
                        "contract_sha256": contract_sha256,
                        "references": references - {name},
                        "qualified": qualified,
                    }

        declaration = _tool_declaration(node)
        if declaration is None:
            continue
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        tool_name, read_only = declaration
        referenced_names: set[str] = set()
        qualified: set[tuple[str, str]] = set()
        for reference in _function_contract_reference_nodes(node):
            referenced_names.update(_bound_names(reference))
            qualified.update(_qualified_references(reference))
        for annotation in _function_annotation_nodes(node):
            referenced_names.update(_string_annotation_names(annotation))
        tools.append(
            {
                "tool": tool_name,
                "async": isinstance(node, ast.AsyncFunctionDef),
                "decorators": [_ast_contract(item) for item in node.decorator_list],
                "arguments": _ast_contract(node.args),
                "returns": _ast_contract(node.returns),
                "type_params": [
                    _ast_contract(item) for item in getattr(node, "type_params", [])
                ],
                "description": ast.get_docstring(node) or "",
                "read_only": read_only,
                "references": referenced_names,
                "qualified": qualified,
            }
        )
    return {
        "definitions": definitions,
        "imports": imports,
        "tools": tools,
    }


def _semantic_source_hashes(
    source_texts: dict[str, str],
    module_to_source: dict[str, str],
) -> dict[str, str]:
    indexes = {
        relative: _source_contract_index(text, filename=relative)
        for relative, text in source_texts.items()
    }
    source_by_module = dict(module_to_source)
    for relative in source_texts:
        source_by_module.setdefault(Path(relative).stem, relative)

    def dependency_node(
        relative: str,
        name: str,
    ) -> tuple[dict[str, Any], set[tuple[str, str]]] | None:
        index = indexes.get(relative)
        if index is None:
            return None
        definitions: dict[str, dict[str, Any]] = index["definitions"]
        imports: dict[str, dict[str, Any]] = index["imports"]
        definition = definitions.get(name)
        edges: set[tuple[str, str]] = set()
        if definition is not None:
            material = {
                "source": relative,
                "name": name,
                "contract_sha256": definition["contract_sha256"],
            }
            for child_name in definition["references"]:
                if child_name in definitions or child_name in imports:
                    edges.add((relative, child_name))
            for root_name, attribute in definition["qualified"]:
                imported = imports.get(root_name)
                if not imported or imported["symbol"] is not None:
                    continue
                imported_source = source_by_module.get(imported["module"])
                if imported_source is not None:
                    edges.add((imported_source, attribute))
        else:
            imported = imports.get(name)
            if imported is None:
                return None
            material = {
                "source": relative,
                "name": name,
                "contract_sha256": imported["contract_sha256"],
            }
            imported_source = source_by_module.get(imported["module"])
            target_symbol = imported["symbol"]
            if imported_source is not None and target_symbol not in {None, "*"}:
                edges.add((imported_source, str(target_symbol)))
        return material, edges

    def dependency_closure(relative: str, tool: dict[str, Any]) -> list[dict[str, Any]]:
        index = indexes[relative]
        definitions: dict[str, dict[str, Any]] = index["definitions"]
        imports: dict[str, dict[str, Any]] = index["imports"]
        initial = {
            (relative, name)
            for name in tool["references"]
            if name in definitions or name in imports
        }
        for root_name, attribute in tool["qualified"]:
            imported = imports.get(root_name)
            if not imported or imported["symbol"] is not None:
                continue
            imported_source = source_by_module.get(imported["module"])
            if imported_source is not None:
                initial.add((imported_source, attribute))

        visited: set[tuple[str, str]] = set()
        pending = sorted(initial, reverse=True)
        material: list[dict[str, Any]] = []
        while pending:
            key = pending.pop()
            if key in visited:
                continue
            visited.add(key)
            resolved = dependency_node(*key)
            if resolved is None:
                continue
            record, edges = resolved
            material.append(record)
            for edge in sorted(edges, reverse=True):
                if edge not in visited:
                    pending.append(edge)
        return sorted(
            material,
            key=lambda item: (str(item["source"]), str(item["name"])),
        )

    hashes: dict[str, str] = {}
    for relative, index in indexes.items():
        tools: list[dict[str, Any]] = []
        for tool in index["tools"]:
            tools.append(
                {
                    key: value
                    for key, value in tool.items()
                    if key not in {"references", "qualified"}
                }
                | {"dependencies": dependency_closure(relative, tool)}
            )
        material = {
            "schema_version": 1,
            "contract": SEMANTIC_SOURCE_DIGEST_CONTRACT,
            "source": relative,
            "tools": sorted(tools, key=lambda item: item["tool"]),
        }
        hashes[relative] = _canonical_json_sha256(material)
    return dict(sorted(hashes.items()))


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
    records = _source_records(contract)
    source_texts = {
        str(record["source"]): (ROOT / str(record["source"])).read_text(encoding="utf-8")
        for record in records
    }
    module_to_source = {
        str(record["module"]): str(record["source"])
        for record in records
    }
    source_hashes = _semantic_source_hashes(source_texts, module_to_source)
    for record in records:
        relative = str(record["source"])
        tree = ast.parse(source_texts[relative], filename=relative)
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
    browser_operator_contract = contract.get("browser_operator_default")
    if not isinstance(browser_operator_contract, dict):
        raise ValueError("runtime contract browser_operator_default is missing or invalid")
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    capabilities = _load_capabilities_module()
    operating_protocol = _load_operator_relay_module().operator_relay_protocol()
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
    staged_unpublished = set(capabilities.STAGED_UNPUBLISHED_TOOL_NAMES)
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
    staged_discovered = sorted(staged_unpublished & discovered_set)
    integrity = {
        **classification,
        "missing_declarations": sorted(expected_set - discovered_set),
        "undeclared_tools": sorted(
            (discovered_set - expected_set) - staged_unpublished
        ),
        "missing_staged_declarations": sorted(
            staged_unpublished - discovered_set
        ),
    }

    publication_staging = {
        "implemented_unpublished_tools": staged_discovered,
    }

    catalog = {
        "schema_version": capabilities.CATALOG_SCHEMA_VERSION,
        "contract": "config/runtime-entrypoint.json",
        "contract_sha256": _sha256(CONTRACT_PATH),
        "capability_source": "src/grabowski_capabilities.py",
        "capability_source_sha256": _sha256(CAPABILITIES_PATH),
        "tools": records,
        "publication_staging": publication_staging,
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
            "runtime_source_digest_contract": SEMANTIC_SOURCE_DIGEST_CONTRACT,
            "runtime_sources": source_hashes,
            "blocked_action_protocol": {
                "path": "docs/blocked-action-protocol-v0.md",
                "sha256": _sha256(PROTOCOL_PATH),
            },
        },
        "operating_protocol": operating_protocol,
        "browser_operator_contract": browser_operator_contract,
        "runtime_contract": {
            "module": contract["module"],
            "source": contract["source"],
            "supporting_sources": contract.get("supporting_sources", []),
            "spawn_dependencies": contract.get("spawn_dependencies", []),
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
        "publication_staging": publication_staging,
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
        "- Execution priority: ChatGPT/Grabowski performs authoritative work; external review or contrast selection follows Claude, Codex, Antigravity, OpenCode, OpenHands, then Cline.",
        "- Workspace routing: authoritative implementation stays with the direct ChatGPT/Grabowski operator for every task size.",
        "- External programming: agents are limited to explicit advisory contrast or competition; their patches are never applied or selected automatically.",
        "- Operator-first work: state inspection, planning, all code changes, tests, integration, merge, deployment and closeout.",
        "- Complex code task: the operator remains the only authoritative writer; independent agents may review or compare an alternative after the operator plan or candidate exists.",
        "- Quick light reasoning: ChatGPT operator directly.",
        "- Local micro reasoning: ChatGPT operator directly.",
        "- Patch file relay: local patch files use `tools/operator_patch_relay.py` for check/apply receipts before user manual execution.",
        "- Review: operator verifies directly; Claude may provide independent architecture and safety findings.",
        "- Session: direct operator context first; tmux or Antigravity may preserve a bounded advisory session when useful.",
        "- Repository state: use target-bound native typed Git, checkout and GitHub reads; these observations never authorize mutation.",
        "",
        "## Browser operator default",
        "",
        f"- Authority: `{browser_operator_contract['authority']}`",
        f"- Canonical browser: `{browser_operator_contract['canonical_browser']['family']}` via `{browser_operator_contract['canonical_browser']['adapter']}` / `{browser_operator_contract['canonical_browser']['protocol']}`.",
        f"- Primary transport: `{browser_operator_contract['transport']['primary']}` on `{browser_operator_contract['transport']['endpoint_address']}`; loopback-only is `{str(browser_operator_contract['transport']['loopback_only']).lower()}`.",
        f"- Profile default: `{browser_operator_contract['profile']['default']}`; persistent profiles are `{browser_operator_contract['profile']['persistent_profile_policy']}`.",
        f"- Human default: preserve `{browser_operator_contract['human_browser_default']['browser']}`; it is not agent-primary.",
        "- Lifecycle: `" + "` → `".join(browser_operator_contract['lifecycle']) + "`.",
        "- Vendor MCPs remain optional diagnostics/adapters and never own browser lifecycle authority.",
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
