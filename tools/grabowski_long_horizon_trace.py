#!/usr/bin/env python3
"""Record explicit long-horizon evaluation events for one real Grabowski task."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import grabowski_long_horizon_trace as producer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Opt-in recorder for explicit monitoring and commitment events. "
            "It never infers events from prompts, tool frequency, stdout or task prose."
        )
    )
    parser.add_argument(
        "--state-root",
        type=Path,
        required=True,
        help="Explicit private directory that owns trace retention.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    open_parser = subparsers.add_parser("open", help="Bind a new trace to one task snapshot.")
    open_parser.add_argument("--task-id", required=True)
    open_parser.add_argument(
        "--retention-mode",
        choices=sorted(producer.RETENTION_MODES),
        required=True,
    )

    record_parser = subparsers.add_parser("record", help="Append one explicit typed event.")
    record_parser.add_argument("--task-id", required=True)
    record_parser.add_argument("--attempt", type=int, required=True)
    record_parser.add_argument("--step", type=int, required=True)
    record_parser.add_argument("--kind", choices=sorted(producer.RECORD_KINDS), required=True)
    record_parser.add_argument("--monitor-id")
    record_parser.add_argument("--cadence-steps", type=int)
    record_parser.add_argument("--grace-steps", type=int, default=0)
    record_parser.add_argument("--commitment-id")
    record_parser.add_argument("--horizon-steps", type=int, default=10)
    record_parser.add_argument("--reason", choices=sorted(producer.ABANDONMENT_REASONS))
    record_parser.add_argument("--evidence-ref", action="append", default=[])

    close_parser = subparsers.add_parser("close", help="Append run.terminal and freeze closeout.")
    close_parser.add_argument("--task-id", required=True)
    close_parser.add_argument("--attempt", type=int, required=True)
    close_parser.add_argument("--step", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "open":
            result = producer.open_trace(
                args.state_root,
                args.task_id,
                retention_mode=args.retention_mode,
            )
        elif args.command == "record":
            result = producer.record_event(
                args.state_root,
                args.task_id,
                args.attempt,
                step=args.step,
                kind=args.kind,
                monitor_id=args.monitor_id,
                cadence_steps=args.cadence_steps,
                grace_steps=args.grace_steps,
                commitment_id=args.commitment_id,
                horizon_steps=args.horizon_steps,
                reason=args.reason,
                evidence_refs=args.evidence_ref,
            )
        else:
            result = producer.close_trace(
                args.state_root,
                args.task_id,
                args.attempt,
                step=args.step,
            )
    except (OSError, producer.TraceProducerError) as exc:
        print(f"long-horizon-trace: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
