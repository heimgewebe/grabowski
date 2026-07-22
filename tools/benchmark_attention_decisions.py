#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sqlite3
import tempfile
import time
from typing import Iterable

DECISION_FILE_RE = re.compile(r"(?P<task_id>[0-9a-f]{24})\.a(?P<attempt>[1-9][0-9]*)\.json\Z")
DEFAULT_SIZES = (100, 1_000, 10_000, 50_000)
DEFAULT_ITERATIONS = 7
PROMOTE_P95_MS_AT_10K = 250.0
PROMOTE_P95_MS_AT_50K = 1_000.0


def _percentile(values: list[float], q: float) -> float:
    if not values:
        raise ValueError("values must not be empty")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def scan_decision_candidates(root: Path, current_attempts: dict[str, int]) -> int:
    if not root.exists():
        return 0
    count = 0
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        match = DECISION_FILE_RE.fullmatch(path.name)
        if match is None:
            continue
        task_id = match.group("task_id")
        attempt = int(match.group("attempt"))
        if current_attempts.get(task_id) == attempt:
            count += 1
    return count


def load_current_attempts(task_db: Path) -> dict[str, int]:
    uri = f"file:{task_db}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        rows = connection.execute("SELECT task_id, attempt FROM tasks").fetchall()
    return {str(task_id): int(attempt) for task_id, attempt in rows}

def benchmark_root(
    root: Path,
    current_attempts: dict[str, int],
    iterations: int,
) -> dict[str, object]:
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    timings_ms: list[float] = []
    candidate_count = 0
    for _ in range(iterations):
        started = time.perf_counter_ns()
        candidate_count = scan_decision_candidates(root, current_attempts)
        timings_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "entry_count": sum(1 for _ in root.iterdir()) if root.exists() else 0,
        "decision_candidate_count": candidate_count,
        "iterations": iterations,
        "median_ms": round(statistics.median(timings_ms), 3),
        "p95_ms": round(_percentile(timings_ms, 0.95), 3),
        "max_ms": round(max(timings_ms), 3),
    }


def _synthetic_case(size: int, iterations: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="grabowski-attention-benchmark-") as tmp:
        root = Path(tmp)
        current_attempts: dict[str, int] = {}
        for index in range(size):
            task_id = f"{index:024x}"
            current_attempts[task_id] = 1
            (root / f"{task_id}.a1.json").touch()
        result = benchmark_root(root, current_attempts, iterations)
        result["synthetic_size"] = size
        return result


def index_promotion_recommended(
    results: Iterable[dict[str, object]],
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    by_size = {
        int(result["synthetic_size"]): float(result["p95_ms"])
        for result in results
    }
    if by_size.get(10_000, 0.0) > PROMOTE_P95_MS_AT_10K:
        reasons.append(f"p95_at_10000_exceeds_{PROMOTE_P95_MS_AT_10K:g}ms")
    if by_size.get(50_000, 0.0) > PROMOTE_P95_MS_AT_50K:
        reasons.append(f"p95_at_50000_exceeds_{PROMOTE_P95_MS_AT_50K:g}ms")
    return bool(reasons), reasons


def _parse_sizes(value: str) -> tuple[int, ...]:
    sizes = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    if not sizes or any(size < 0 for size in sizes):
        raise argparse.ArgumentTypeError("sizes must be comma-separated non-negative integers")
    return sizes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark Grabowski attention decision directory lookup."
    )
    parser.add_argument("--sizes", type=_parse_sizes, default=DEFAULT_SIZES)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--live-task-db", type=Path)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    if (args.live_root is None) != (args.live_task_db is None):
        parser.error("--live-root and --live-task-db must be provided together")

    synthetic = [_synthetic_case(size, args.iterations) for size in args.sizes]
    promote, reasons = index_promotion_recommended(synthetic)
    payload: dict[str, object] = {
        "schema_version": 1,
        "benchmark": "grabowski_attention_decision_directory_lookup",
        "iterations": args.iterations,
        "synthetic": synthetic,
        "index_promotion": {
            "recommended": promote,
            "reasons": reasons,
            "thresholds_ms": {
                "p95_at_10000": PROMOTE_P95_MS_AT_10K,
                "p95_at_50000": PROMOTE_P95_MS_AT_50K,
            },
        },
    }
    if args.live_root is not None and args.live_task_db is not None:
        live_attempts = load_current_attempts(args.live_task_db)
        payload["live"] = {
            "root": str(args.live_root),
            "task_db": str(args.live_task_db),
            "attempt_source": "tasks_sqlite_read_only",
            **benchmark_root(args.live_root, live_attempts, args.iterations),
        }
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
