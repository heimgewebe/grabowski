#!/usr/bin/env python3
"""CLI for the one explicit anonymous GitHub StructuredToolProvider backend."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grabowski_browser_structured_provider_github import (
    assess_repository_read,
    execute_repository_read,
    provider_contract,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or execute the explicit anonymous github.public-rest repository.read "
            "provider. This tool has no provider selection, routing, fallback or credentials."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("contract", help="show the normalized fixed provider contract")
    assess = sub.add_parser("assess", help="assess one canonical repository target without I/O")
    assess.add_argument("target")
    read = sub.add_parser("read", help="perform one bounded anonymous repository metadata read")
    read.add_argument("target")
    return parser


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "github_structured_tool_provider_cli_failure",
        "state": "failed_closed",
        "result_code": str(getattr(exc, "code", "invalid"))[:80],
        "provider_execution_performed": False,
        "automatic_route_selected": False,
        "retry_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "contract":
            result = provider_contract()
        elif args.command == "assess":
            result = assess_repository_read(args.target)
        else:
            result = execute_repository_read(args.target)
    except Exception as exc:
        result = _failure(exc)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("state") != "failed_closed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
