#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
import deploy_runtime
from grabowski_connector_contract import (
    MAX_OBSERVED_ARTIFACT_BYTES,
    fingerprint,
    parse_observed_artifact,
    probe_contract,
)

DEFAULT_RUNTIME = Path.home() / ".local" / "share" / "grabowski-mcp"


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
                deploy_runtime.send_json(
                    process,
                    {
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
                    },
                )
                initialized = deploy_runtime.wait_for_id(
                    process, 1, deploy_runtime.TIMEOUTS["mcp_probe"]
                )
                if "error" in initialized:
                    raise RuntimeError(str(initialized["error"]))
                deploy_runtime.send_json(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                        "params": {},
                    },
                )
                deploy_runtime.send_json(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/list",
                        "params": {},
                    },
                )
                listed = deploy_runtime.wait_for_id(
                    process, 2, deploy_runtime.TIMEOUTS["mcp_probe"]
                )
                if "error" in listed:
                    raise RuntimeError(str(listed["error"]))
                tools = listed.get("result", {}).get("tools")
                if not isinstance(tools, list) or not all(
                    isinstance(item, dict) for item in tools
                ):
                    raise RuntimeError(
                        "runtime tools/list did not return tool objects"
                    )
                deploy_runtime.stop_process(process)
                return tools
            except Exception as exc:
                last_error = exc
                deploy_runtime.stop_process(process)
    raise RuntimeError(f"runtime tools/list failed: {last_error}")


def _observed(
    path: Path | None,
    positional: list[str],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    if path is None:
        if not positional:
            raise ValueError("observed tools are required")
        return positional, {}
    if path.stat().st_size > MAX_OBSERVED_ARTIFACT_BYTES:
        raise ValueError("observed file exceeds the 32-KiB size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value, {}
    names, schemas, _metadata = parse_observed_artifact(value)
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
    contract_names = json.loads(
        (ROOT / "config" / "runtime-entrypoint.json").read_text(
            encoding="utf-8"
        )
    )["expected_tools"]
    return probe_contract(
        observed_names,
        observed_schemas,
        sorted(runtime_by_name),
        {
            name: item["inputSchema"]
            for name, item in runtime_by_name.items()
            if isinstance(item.get("inputSchema"), dict)
        },
        contract_names,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare connector names and selected input schemas with live MCP tools/list"
        )
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
