#!/usr/bin/env python3
"""Evaluate long-horizon monitoring and commitment discipline from explicit traces.

This module deliberately does not infer plans or required observations from free text.
A producer must emit the small typed trace contract documented in
``docs/long-horizon-evaluation-v1.md``. That keeps absence-of-retrieval distinct
from absence-of-information and keeps deliberate abandonment distinct from a
silently dropped commitment.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

TRACE_SCHEMA_VERSION = "grabowski.long-horizon-trace.v1"
EVAL_SCHEMA_VERSION = "grabowski.long-horizon-eval.v1"
DEFAULT_COMMITMENT_HORIZON_STEPS = 10
DEFAULT_TERMINAL_WINDOW_STEPS = 20

_ALLOWED_KINDS = frozenset(
    {
        "run.started",
        "run.terminal",
        "monitor.requirement",
        "monitor.check",
        "commitment.declared",
        "commitment.completed",
        "commitment.abandoned",
    }
)


class TraceError(ValueError):
    """Raised when a trace cannot support deterministic evaluation."""


def _nonempty_string(record: dict[str, Any], key: str, *, line: int) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise TraceError(f"line {line}: {key} must be a non-empty string")
    return value.strip()


def _integer(
    record: dict[str, Any],
    key: str,
    *,
    line: int,
    minimum: int = 0,
    default: int | None = None,
) -> int:
    if key not in record and default is not None:
        return default
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TraceError(f"line {line}: {key} must be an integer >= {minimum}")
    return value


def _validate_record(record: Any, *, line: int, ordinal: int) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise TraceError(f"line {line}: trace record must be a JSON object")
    if record.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise TraceError(
            f"line {line}: schema_version must be {TRACE_SCHEMA_VERSION!r}"
        )

    normalized = dict(record)
    normalized["run_id"] = _nonempty_string(record, "run_id", line=line)
    normalized["step"] = _integer(record, "step", line=line)
    kind = _nonempty_string(record, "kind", line=line)
    if kind not in _ALLOWED_KINDS:
        raise TraceError(f"line {line}: unsupported kind {kind!r}")
    normalized["kind"] = kind
    normalized["_line"] = line
    normalized["_ordinal"] = ordinal

    if kind == "monitor.requirement":
        normalized["monitor_id"] = _nonempty_string(record, "monitor_id", line=line)
        normalized["cadence_steps"] = _integer(
            record, "cadence_steps", line=line, minimum=1
        )
        normalized["grace_steps"] = _integer(
            record, "grace_steps", line=line, minimum=0, default=0
        )
    elif kind == "monitor.check":
        normalized["monitor_id"] = _nonempty_string(record, "monitor_id", line=line)
    elif kind == "commitment.declared":
        normalized["commitment_id"] = _nonempty_string(
            record, "commitment_id", line=line
        )
        normalized["horizon_steps"] = _integer(
            record,
            "horizon_steps",
            line=line,
            minimum=1,
            default=DEFAULT_COMMITMENT_HORIZON_STEPS,
        )
    elif kind in {"commitment.completed", "commitment.abandoned"}:
        normalized["commitment_id"] = _nonempty_string(
            record, "commitment_id", line=line
        )
        if kind == "commitment.abandoned":
            normalized["reason"] = _nonempty_string(record, "reason", line=line)
            evidence_refs = record.get("evidence_refs", [])
            if not isinstance(evidence_refs, list) or any(
                not isinstance(item, str) or not item.strip() for item in evidence_refs
            ):
                raise TraceError(
                    f"line {line}: evidence_refs must be a list of non-empty strings"
                )
            normalized["evidence_refs"] = [item.strip() for item in evidence_refs]

    return normalized


def parse_jsonl(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TraceError(f"line {line_no}: invalid JSON: {exc.msg}") from exc
        records.append(_validate_record(payload, line=line_no, ordinal=len(records)))
    if not records:
        raise TraceError("trace contains no records")
    return records


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _mean(values: list[int]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 6)


def _evaluate_monitoring(
    events: list[dict[str, Any]],
    *,
    observation_end_step: int,
    terminal_step: int | None,
    terminal_window_steps: int,
) -> list[dict[str, Any]]:
    requirements: dict[str, dict[str, Any]] = {}
    checks: dict[str, list[int]] = defaultdict(list)

    for event in events:
        kind = event["kind"]
        if kind == "monitor.requirement":
            monitor_id = event["monitor_id"]
            if monitor_id in requirements:
                raise TraceError(
                    f"run {event['run_id']}: duplicate monitor requirement {monitor_id!r}"
                )
            requirements[monitor_id] = event
        elif kind == "monitor.check":
            checks[event["monitor_id"]].append(event["step"])

    unknown = sorted(set(checks) - set(requirements))
    if unknown:
        raise TraceError(
            f"run {events[0]['run_id']}: monitor checks without requirement: {unknown}"
        )

    results: list[dict[str, Any]] = []
    for monitor_id in sorted(requirements):
        requirement = requirements[monitor_id]
        start_step = requirement["step"]
        cadence = requirement["cadence_steps"]
        grace = requirement["grace_steps"]
        threshold = cadence + grace
        monitor_checks = sorted(checks.get(monitor_id, []))
        if any(step < start_step for step in monitor_checks):
            raise TraceError(
                f"run {events[0]['run_id']}: monitor {monitor_id!r} checked before requirement"
            )

        anchor = start_step
        deadline_segments = 0
        deadline_breaches = 0
        overdue_steps_total = 0
        for step in monitor_checks:
            gap = step - anchor
            deadline_segments += 1
            if gap > threshold:
                deadline_breaches += 1
                overdue_steps_total += gap - threshold
            anchor = step

        tail_steps = observation_end_step - anchor
        tail_deadline_missed = tail_steps >= threshold
        if tail_deadline_missed:
            deadline_segments += 1
            deadline_breaches += 1
            overdue_steps_total += max(0, tail_steps - threshold)

        consecutive_intervals = [
            current - previous
            for previous, current in zip(monitor_checks, monitor_checks[1:])
        ]
        last_check = monitor_checks[-1] if monitor_checks else None
        checked_in_terminal_window: bool | None = None
        if terminal_step is not None:
            checked_in_terminal_window = bool(
                last_check is not None
                and last_check >= max(start_step, terminal_step - terminal_window_steps)
                and last_check <= terminal_step
            )

        results.append(
            {
                "monitor_id": monitor_id,
                "start_step": start_step,
                "cadence_steps": cadence,
                "grace_steps": grace,
                "check_count": len(monitor_checks),
                "initial_check_delay_steps": (
                    monitor_checks[0] - start_step if monitor_checks else None
                ),
                "mean_check_interval_steps": _mean(consecutive_intervals),
                "max_check_interval_steps": (
                    max(consecutive_intervals) if consecutive_intervals else None
                ),
                "deadline_segment_count": deadline_segments,
                "deadline_breach_count": deadline_breaches,
                "deadline_segment_compliance_rate": _rate(
                    deadline_segments - deadline_breaches, deadline_segments
                ),
                "overdue_steps_total": overdue_steps_total,
                "tail_steps_since_last_check": tail_steps,
                "tail_deadline_missed": tail_deadline_missed,
                "terminal_window_steps": terminal_window_steps,
                "checked_in_terminal_window": checked_in_terminal_window,
            }
        )

    return results


def _evaluate_commitments(
    events: list[dict[str, Any]], *, observation_end_step: int
) -> list[dict[str, Any]]:
    declarations: dict[str, dict[str, Any]] = {}
    resolutions: dict[str, dict[str, Any]] = {}

    for event in events:
        kind = event["kind"]
        if kind == "commitment.declared":
            commitment_id = event["commitment_id"]
            if commitment_id in declarations:
                raise TraceError(
                    f"run {event['run_id']}: duplicate commitment {commitment_id!r}"
                )
            declarations[commitment_id] = event
        elif kind in {"commitment.completed", "commitment.abandoned"}:
            commitment_id = event["commitment_id"]
            if commitment_id in resolutions:
                raise TraceError(
                    f"run {event['run_id']}: commitment {commitment_id!r} resolved more than once"
                )
            resolutions[commitment_id] = event

    unknown = sorted(set(resolutions) - set(declarations))
    if unknown:
        raise TraceError(
            f"run {events[0]['run_id']}: commitment resolutions without declaration: {unknown}"
        )

    results: list[dict[str, Any]] = []
    for commitment_id in sorted(declarations):
        declaration = declarations[commitment_id]
        declared_step = declaration["step"]
        horizon = declaration["horizon_steps"]
        due_step = declared_step + horizon
        resolution = resolutions.get(commitment_id)
        if resolution is not None and resolution["step"] < declared_step:
            raise TraceError(
                f"run {events[0]['run_id']}: commitment {commitment_id!r} resolved before declaration"
            )

        resolution_kind = resolution["kind"] if resolution else None
        resolution_step = resolution["step"] if resolution else None
        within_horizon = bool(resolution and resolution_step <= due_step)
        fully_observed = observation_end_step >= due_step

        if within_horizon and resolution_kind == "commitment.completed":
            status = "completed"
        elif within_horizon and resolution_kind == "commitment.abandoned":
            status = "abandoned"
        elif not fully_observed:
            status = "censored"
        else:
            status = "missed"

        results.append(
            {
                "commitment_id": commitment_id,
                "declared_step": declared_step,
                "horizon_steps": horizon,
                "due_step": due_step,
                "status_at_horizon": status,
                "resolution_kind": resolution_kind,
                "resolution_step": resolution_step,
                "resolution_latency_steps": (
                    resolution_step - declared_step if resolution is not None else None
                ),
                "explicit_abandonment": bool(
                    resolution_kind == "commitment.abandoned"
                ),
                "abandonment_evidence_ref_count": (
                    len(resolution.get("evidence_refs", []))
                    if resolution_kind == "commitment.abandoned"
                    else 0
                ),
            }
        )

    return results


def evaluate_records(
    records: Iterable[dict[str, Any]],
    *,
    terminal_window_steps: int = DEFAULT_TERMINAL_WINDOW_STEPS,
) -> dict[str, Any]:
    if terminal_window_steps < 1:
        raise TraceError("terminal_window_steps must be >= 1")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["run_id"]].append(record)

    run_results: list[dict[str, Any]] = []
    for run_id in sorted(grouped):
        events = sorted(grouped[run_id], key=lambda item: (item["step"], item["_ordinal"]))
        terminal_events = [event for event in events if event["kind"] == "run.terminal"]
        if len(terminal_events) > 1:
            raise TraceError(f"run {run_id}: more than one run.terminal event")
        terminal_step = terminal_events[0]["step"] if terminal_events else None
        max_step = max(event["step"] for event in events)
        if terminal_step is not None and max_step > terminal_step:
            raise TraceError(f"run {run_id}: events occur after run.terminal")
        observation_end_step = terminal_step if terminal_step is not None else max_step

        monitoring = _evaluate_monitoring(
            events,
            observation_end_step=observation_end_step,
            terminal_step=terminal_step,
            terminal_window_steps=terminal_window_steps,
        )
        commitments = _evaluate_commitments(
            events, observation_end_step=observation_end_step
        )

        eligible = [item for item in commitments if item["status_at_horizon"] != "censored"]
        completed = sum(item["status_at_horizon"] == "completed" for item in eligible)
        abandoned = sum(item["status_at_horizon"] == "abandoned" for item in eligible)
        missed = sum(item["status_at_horizon"] == "missed" for item in eligible)
        deadline_segments = sum(item["deadline_segment_count"] for item in monitoring)
        deadline_breaches = sum(item["deadline_breach_count"] for item in monitoring)

        run_results.append(
            {
                "run_id": run_id,
                "terminal_observed": terminal_step is not None,
                "terminal_step": terminal_step,
                "observation_end_step": observation_end_step,
                "monitoring": monitoring,
                "commitments": commitments,
                "summary": {
                    "monitoring_channel_count": len(monitoring),
                    "monitoring_deadline_segment_count": deadline_segments,
                    "monitoring_deadline_breach_count": deadline_breaches,
                    "monitoring_segment_compliance_rate": _rate(
                        deadline_segments - deadline_breaches, deadline_segments
                    ),
                    "commitments_declared": len(commitments),
                    "commitments_eligible_at_horizon": len(eligible),
                    "commitments_completed_within_horizon": completed,
                    "commitments_abandoned_within_horizon": abandoned,
                    "commitments_silently_missed_at_horizon": missed,
                    "commitment_completion_at_horizon_rate": _rate(
                        completed, len(eligible)
                    ),
                    "commitment_accounted_for_at_horizon_rate": _rate(
                        completed + abandoned, len(eligible)
                    ),
                    "commitment_silent_drop_rate": _rate(missed, len(eligible)),
                },
            }
        )

    aggregate_deadline_segments = sum(
        run["summary"]["monitoring_deadline_segment_count"] for run in run_results
    )
    aggregate_deadline_breaches = sum(
        run["summary"]["monitoring_deadline_breach_count"] for run in run_results
    )
    aggregate_eligible = sum(
        run["summary"]["commitments_eligible_at_horizon"] for run in run_results
    )
    aggregate_completed = sum(
        run["summary"]["commitments_completed_within_horizon"] for run in run_results
    )
    aggregate_abandoned = sum(
        run["summary"]["commitments_abandoned_within_horizon"] for run in run_results
    )
    aggregate_missed = sum(
        run["summary"]["commitments_silently_missed_at_horizon"] for run in run_results
    )

    return {
        "schema_version": EVAL_SCHEMA_VERSION,
        "trace_schema_version": TRACE_SCHEMA_VERSION,
        "runs": run_results,
        "aggregate": {
            "run_count": len(run_results),
            "terminal_run_count": sum(run["terminal_observed"] for run in run_results),
            "monitoring_channel_count": sum(
                run["summary"]["monitoring_channel_count"] for run in run_results
            ),
            "monitoring_deadline_segment_count": aggregate_deadline_segments,
            "monitoring_deadline_breach_count": aggregate_deadline_breaches,
            "monitoring_segment_compliance_rate": _rate(
                aggregate_deadline_segments - aggregate_deadline_breaches,
                aggregate_deadline_segments,
            ),
            "commitments_declared": sum(
                run["summary"]["commitments_declared"] for run in run_results
            ),
            "commitments_eligible_at_horizon": aggregate_eligible,
            "commitments_completed_within_horizon": aggregate_completed,
            "commitments_abandoned_within_horizon": aggregate_abandoned,
            "commitments_silently_missed_at_horizon": aggregate_missed,
            "commitment_completion_at_horizon_rate": _rate(
                aggregate_completed, aggregate_eligible
            ),
            "commitment_accounted_for_at_horizon_rate": _rate(
                aggregate_completed + aggregate_abandoned, aggregate_eligible
            ),
            "commitment_silent_drop_rate": _rate(
                aggregate_missed, aggregate_eligible
            ),
        },
        "does_not_establish": [
            "that an omitted monitor requirement was unimportant",
            "that an explicit abandonment was strategically correct",
            "that a completed commitment improved the external outcome",
            "CivBench score equivalence without a separately validated adapter",
            "model-family ranking from a single run or scenario",
        ],
    }


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate explicit long-horizon monitoring and commitment traces."
    )
    parser.add_argument("trace", help="JSONL trace path, or '-' for stdin")
    parser.add_argument(
        "--terminal-window-steps",
        type=int,
        default=DEFAULT_TERMINAL_WINDOW_STEPS,
        help="Window used only for the terminal recent-check diagnostic (default: 20)",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    try:
        records = parse_jsonl(_read_input(args.trace))
        result = evaluate_records(
            records, terminal_window_steps=args.terminal_window_steps
        )
    except (OSError, TraceError) as exc:
        print(f"long-horizon-eval: {exc}", file=sys.stderr)
        return 2

    if args.pretty:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
