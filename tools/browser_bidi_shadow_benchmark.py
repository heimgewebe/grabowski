#!/usr/bin/env python3
"""Run one fail-closed Firefox/WebDriver BiDi shadow benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import browser_bidi_shadow_benchmark_core as shadow


def _reference(value: str) -> dict[str, object]:
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("reference JSON is invalid") from exc
    if not isinstance(document, dict):
        raise argparse.ArgumentTypeError("reference JSON must be an object")
    return document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure one isolated Firefox/WebDriver BiDi path against a semantic "
            "reference without changing Grabowski's production Chrome/CDP adapter."
        )
    )
    parser.add_argument("--geckodriver", type=Path, required=True)
    parser.add_argument("--firefox", type=Path, default=Path("/usr/bin/firefox"))
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--websocket-port", type=int, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument(
        "--reference-json",
        type=_reference,
        default=None,
        help="Canonical semantic observation to compare against as JSON.",
    )
    parser.add_argument(
        "--html",
        default=shadow.DEFAULT_HTML,
        help="Deterministic data: page body for the isolated shadow probe.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if len(args.html.encode("utf-8")) > 64 * 1024:
        print(
            json.dumps(
                shadow.failure_report(
                    shadow.BidiShadowError("benchmark HTML exceeds 64 KiB")
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    try:
        report = shadow.run_shadow_benchmark(
            geckodriver=args.geckodriver,
            firefox=args.firefox,
            http_port=args.http_port,
            websocket_port=args.websocket_port,
            work_root=args.work_root,
            reference=args.reference_json,
            html=args.html,
        )
    except Exception as exc:
        report = shadow.failure_report(exc)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("state") == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
