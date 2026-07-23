#!/usr/bin/env python3
"""Seal prospective routing-shadow cohort cases without operational effects."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operator_routing_shadow_capture as capture  # noqa: E402


def _default_root() -> Path:
    return Path(
        os.environ.get(
            "GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT",
            str(Path.home() / ".local/state/grabowski/operator-routing-shadow-cohort"),
        )
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind and seal one already-prospective routing-shadow cohort case."
    )
    parser.add_argument("--prospective-eligibility", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--outcome", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=_default_root())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    prospective = capture._read_regular_json(
        args.prospective_eligibility, label="prospective eligibility"
    )
    manifest = capture._read_regular_json(args.manifest, label="manifest")
    outcome_input = capture._read_regular_json(args.outcome, label="outcome")
    if set(outcome_input) != {"outcome", "primary_evidence_refs"}:
        raise capture.ShadowCaptureError(
            "outcome input must contain exactly outcome and primary_evidence_refs"
        )
    result = capture.seal_prospective_case(
        prospective,
        manifest,
        eligible_task_id=args.task_id,
        outcome=outcome_input["outcome"],
        primary_evidence_refs=outcome_input["primary_evidence_refs"],
        root=args.root,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except capture.ShadowCaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
