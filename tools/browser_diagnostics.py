#!/usr/bin/env python3
"""Tooling-only CLI for bounded Grabowski browser diagnostics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from grabowski_browser_diagnostics import (
    DEFAULT_CAPTURE_MS,
    DEFAULT_MAX_EVENTS,
    failure_report,
    observe_browser_diagnostics,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passively collect bounded diagnostics from one live Grabowski browser worker."
    )
    parser.add_argument("worker_id")
    parser.add_argument("--capture-ms", type=int, default=DEFAULT_CAPTURE_MS)
    parser.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = observe_browser_diagnostics(
            args.worker_id,
            capture_ms=args.capture_ms,
            max_events=args.max_events,
        )
    except Exception as exc:
        report = failure_report(exc)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report.get("state") == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
