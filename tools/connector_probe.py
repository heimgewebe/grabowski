#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import deploy_runtime

DEFAULT_RUNTIME = Path.home() / ".local" / "share" / "grabowski-mcp"
REQUIRED_SCHEMA_SENTINELS = {"grabowski_secret_reveal"}
SCHEMA_METADATA_KEYS = {"title", "description"}


def fingerprint(names: list[str]) -> str:
    raw = json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _normalize_schema(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize_schema(item)
            for key, item in sorted(value.items())
            if key not in SCHEMA_METADATA_KEYS
        }
    if isinstance(value, list):
        return [_normalize_schema(item) for item in value]
    return value


def schema_fingerprint(schema: dict[str, Any]) -> str:
    raw = json.dumps(
        _normalize_schema(schema),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _runtime_tools(runtime: Path) -> list[dict[str, Any]]:
    contract = deploy_runtime.load_contract(
        ROOT / "config" / "runtime-entrypoint.json"
    )
    python_exe = runtime / ".venv" / "bin" / "python"
    if not python_exe.is_file():
        raise RuntimeError(f"runtime Python missing: {python_exe}")
    last_error: Exception | None = None
    for version in deploy_runtime.MCP_PROTOCOL_VERSIONS:
        with tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                contract.command_argv(runtime, python_exe),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr_file,
                cwd=runtime,
                bufsize=0,
                env={**os.environ, "PYTHONNOUSERSITE": "1"},
            )
            try:
                deploy_runtime.send_json(process, {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": {
                            "name": "grabowski-connector-contract-probe",
                            "version": "2.0",
                        },
                    },
                })
                initialized = deploy_runtime.wait_for_id(
                    process, 1, deploy_runtime.TIMEOUTS["mcp_probe"]
                )
                if "error" in initialized:
                    raise RuntimeError(str(initialized["error"]))
                deploy_runtime.send_json(process, {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                })
                deploy_runtime.send_json(process, {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                })
                listed = deploy_runtime.wait_for_id(
                    process, 2, deploy_runtime.TIMEOUTS["mcp_probe"]
                )
                if "error" in listed:
                    raise RuntimeError(str(listed["error"]))
                tools = listed.get("result", {}).get("tools")
                if not isinstance(tools, list) or not all(
                    isinstance(item, dict) for item in tools
                ):
                    raise RuntimeError("runtime tools/list did not return tool objects")
                deploy_runtime.stop_process(process)
                return tools
            except Exception as exc:
                last_error = exc
                deploy_runtime.stop_process(process)
    raise RuntimeError(f"runtime tools/list failed: {last_error}")


def _observed(path: Path | None, positional: list[str]) -> tuple[list[str], dict[str, dict[str, Any]]]:
    if path is None:
        if not positional:
            raise ValueError("observed tools are required")
        return positional, {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value, {}
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("observed file must use schema_version 1")
    tools = value.get("tools")
    if not isinstance(tools, list) or not tools:
        raise ValueError("observed file must contain a non-empty tools list")
    names: list[str] = []
    schemas: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(tools):
        if isinstance(item, str):
            name = item
            schema = None
        elif isinstance(item, dict):
            if set(item) - {"name", "inputSchema"}:
                raise ValueError(f"observed tools[{index}] has unknown keys")
            name = item.get("name")
            schema = item.get("inputSchema")
        else:
            raise ValueError(f"observed tools[{index}] is invalid")
        if not isinstance(name, str) or not name:
            raise ValueError(f"observed tools[{index}] has invalid name")
        if name in names:
            raise ValueError(f"duplicate observed tool: {name}")
        names.append(name)
        if schema is not None:
            if not isinstance(schema, dict):
                raise ValueError(f"observed schema for {name} must be an object")
            schemas[name] = schema
    return names, schemas


def probe(
    observed_names: list[str],
    observed_schemas: dict[str, dict[str, Any]],
    runtime_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    runtime_by_name = {
        item["name"]: item
        for item in runtime_tools
        if isinstance(item.get("name"), str)
    }
    runtime_names = sorted(runtime_by_name)
    contract_names = json.loads(
        (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
    )["expected_tools"]
    schema_mismatches = []
    for name, observed_schema in sorted(observed_schemas.items()):
        runtime_schema = runtime_by_name.get(name, {}).get("inputSchema")
        if not isinstance(runtime_schema, dict):
            schema_mismatches.append({
                "tool": name,
                "reason": "runtime schema missing",
            })
            continue
        observed_hash = schema_fingerprint(observed_schema)
        runtime_hash = schema_fingerprint(runtime_schema)
        if observed_hash != runtime_hash:
            schema_mismatches.append({
                "tool": name,
                "observed_sha256": observed_hash,
                "runtime_sha256": runtime_hash,
            })
    missing_schema_sentinels = sorted(
        REQUIRED_SCHEMA_SENTINELS - set(observed_schemas)
    )
    missing_from_connector = sorted(set(runtime_names) - set(observed_names))
    unexpected_in_connector = sorted(set(observed_names) - set(runtime_names))
    contract_missing_from_runtime = sorted(set(contract_names) - set(runtime_names))
    runtime_unexpected_from_contract = sorted(set(runtime_names) - set(contract_names))
    matches = not any((
        missing_from_connector,
        unexpected_in_connector,
        contract_missing_from_runtime,
        runtime_unexpected_from_contract,
        schema_mismatches,
        missing_schema_sentinels,
    ))
    return {
        "matches": matches,
        "name_contract_matches": not missing_from_connector and not unexpected_in_connector,
        "runtime_contract_matches": not contract_missing_from_runtime and not runtime_unexpected_from_contract,
        "schema_contract_matches": not schema_mismatches and not missing_schema_sentinels,
        "runtime_count": len(runtime_names),
        "observed_count": len(observed_names),
        "runtime_names_sha256": fingerprint(runtime_names),
        "observed_names_sha256": fingerprint(observed_names),
        "schema_coverage_count": len(observed_schemas),
        "required_schema_sentinels": sorted(REQUIRED_SCHEMA_SENTINELS),
        "missing_schema_sentinels": missing_schema_sentinels,
        "schema_mismatches": schema_mismatches,
        "missing_from_connector": missing_from_connector,
        "unexpected_in_connector": unexpected_in_connector,
        "contract_missing_from_runtime": contract_missing_from_runtime,
        "runtime_unexpected_from_contract": runtime_unexpected_from_contract,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare connector names and input schemas with live MCP tools/list"
    )
    parser.add_argument("tools", nargs="*")
    parser.add_argument("--observed-file", type=Path)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    args = parser.parse_args()
    try:
        names, schemas = _observed(args.observed_file, args.tools)
        result = probe(names, schemas, _runtime_tools(args.runtime))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["matches"] else 1
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
