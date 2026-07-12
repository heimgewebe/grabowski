#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import statistics
import time
from typing import Any, Callable

import grabowski_friction
import grabowski_mcp
import grabowski_read_surface
import grabowski_runtime_extensions
import grabowski_tasks

PRE_CHANGE_BYTES = {
    "status": 7579,
    "context_concise": 37597,
    "checkout_summary": 11458,
    "task_list_20": 113239,
    "friction_summary_50": 60842,
}


def _bytes(value: Any) -> int:
    return len(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))


def _p90(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, min(len(ordered) - 1, int((len(ordered) - 1) * 0.9)))]


def measure(call: Callable[[], Any], samples: int) -> dict[str, Any]:
    elapsed_ms: list[float] = []
    sizes: list[int] = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        value = call()
        elapsed_ms.append((time.perf_counter_ns() - started) / 1_000_000)
        sizes.append(_bytes(value))
    return {
        "samples": samples,
        "bytes_median": int(statistics.median(sizes)),
        "bytes_p90": int(_p90([float(item) for item in sizes])),
        "elapsed_ms_median": round(statistics.median(elapsed_ms), 3),
        "elapsed_ms_p90": round(_p90(elapsed_ms), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.samples <= 20:
        raise SystemExit("samples must be between 1 and 20")
    cases: dict[str, Callable[[], Any]] = {
        "status_minimal": lambda: grabowski_mcp.grabowski_status(view="minimal"),
        "status_standard": lambda: grabowski_mcp.grabowski_status(view="standard"),
        "status_evidence": lambda: grabowski_mcp.grabowski_status(view="evidence"),
        "context_minimal": lambda: grabowski_runtime_extensions.grabowski_context(
            profile="concise", view="minimal"
        ),
        "context_standard": lambda: grabowski_runtime_extensions.grabowski_context(
            profile="concise", view="standard"
        ),
        "context_evidence": lambda: grabowski_runtime_extensions.grabowski_context(
            profile="concise", view="evidence"
        ),
        "checkout_minimal": lambda: grabowski_read_surface.grabowski_checkout_summary(
            view="minimal", limit=20
        ),
        "checkout_standard": lambda: grabowski_read_surface.grabowski_checkout_summary(
            view="standard", limit=20
        ),
        "checkout_evidence": lambda: grabowski_read_surface.grabowski_checkout_summary(
            view="evidence", limit=100
        ),
        "tasks_minimal": lambda: grabowski_tasks.grabowski_task_list(
            view="minimal", limit=20
        ),
        "tasks_standard": lambda: grabowski_tasks.grabowski_task_list(
            view="standard", limit=20
        ),
        "tasks_evidence": lambda: grabowski_tasks.grabowski_task_list(
            view="evidence", limit=20
        ),
        "friction_minimal": lambda: grabowski_friction.friction_summary(
            view="minimal", limit=20
        ),
        "friction_standard": lambda: grabowski_friction.friction_summary(
            view="standard", limit=50
        ),
        "friction_evidence": lambda: grabowski_friction.friction_summary(
            view="evidence", limit=50
        ),
    }
    results = {name: measure(call, args.samples) for name, call in cases.items()}
    comparisons: dict[str, dict[str, dict[str, Any]]] = {}
    baseline_cases = {
        "status": ("status", "status"),
        "context": ("context_concise", "context"),
        "checkout": ("checkout_summary", "checkout"),
        "tasks": ("task_list_20", "tasks"),
        "friction": ("friction_summary_50", "friction"),
    }
    for view in ("minimal", "standard"):
        view_comparisons: dict[str, dict[str, Any]] = {}
        for surface, (baseline_name, result_prefix) in baseline_cases.items():
            before = PRE_CHANGE_BYTES[baseline_name]
            after = results[f"{result_prefix}_{view}"]["bytes_median"]
            view_comparisons[surface] = {
                "before_bytes": before,
                "after_bytes": after,
                "reduction_percent": round((before - after) * 100 / before, 2),
            }
        comparisons[view] = view_comparisons
    print(json.dumps({
        "schema_version": 1,
        "pre_change_bytes": PRE_CHANGE_BYTES,
        "results": results,
        "comparisons": comparisons,
        "does_not_establish": [
            "model_token_count",
            "connector_transport_reliability",
            "workflow_correctness",
        ],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
