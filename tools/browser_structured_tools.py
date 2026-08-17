#!/usr/bin/env python3
"""Offline CLI for the non-executing StructuredToolProvider contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grabowski_browser_structured_tools import (
    StructuredToolProviderRegistry,
)

MAX_JSON_BYTES = 262_144


def _read_json(path: str) -> dict[str, Any]:
    target = Path(path).expanduser()
    metadata = target.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("input must be a regular non-symlink file")
    if metadata.st_size > MAX_JSON_BYTES:
        raise ValueError("input JSON exceeds size limit")
    value = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and inspect the non-executing StructuredToolProvider contract. "
            "This tool never invokes a provider or chooses a route."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate one provider contract")
    validate.add_argument("spec")

    assess = sub.add_parser("assess", help="assess one explicitly named provider")
    assess.add_argument("spec")
    assess.add_argument("provider_id")
    assess.add_argument("operation")
    assess.add_argument("target")

    normalize = sub.add_parser("normalize", help="normalize one caller-supplied provider receipt")
    normalize.add_argument("spec")
    normalize.add_argument("provider_id")
    normalize.add_argument("operation")
    normalize.add_argument("target")
    normalize.add_argument("receipt")
    return parser


def _failure(exc: Exception) -> dict[str, Any]:
    code = getattr(exc, "code", "invalid")
    return {
        "schema_version": 1,
        "kind": "structured_tool_provider_cli_failure",
        "state": "failed_closed",
        "result_code": str(code)[:80],
        "provider_execution_performed": False,
        "automatic_route_selected": False,
        "retry_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        registry = StructuredToolProviderRegistry()
        contract = registry.register(_read_json(args.spec))
        if args.command == "validate":
            result = contract
        elif args.command == "assess":
            result = registry.assess(args.provider_id, args.operation, args.target)
        else:
            result = registry.normalize_receipt(
                args.provider_id,
                args.operation,
                args.target,
                _read_json(args.receipt),
            )
    except Exception as exc:
        result = _failure(exc)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("state") != "failed_closed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
