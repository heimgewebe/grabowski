from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "benchmark_attention_decisions", ROOT / "tools" / "benchmark_attention_decisions.py"
)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class AttentionDecisionBenchmarkTests(unittest.TestCase):
    def test_scan_counts_only_current_attempt_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ("a" * 24 + ".a1.json")).touch()
            (root / ("b" * 24 + ".a2.json")).touch()
            (root / "not-a-decision.txt").touch()
            count = benchmark.scan_decision_candidates(
                root, {"a" * 24: 1, "b" * 24: 1}
            )
            self.assertEqual(1, count)

    def test_missing_root_is_empty_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing"
            self.assertEqual(0, benchmark.scan_decision_candidates(root, {}))
            self.assertFalse(root.exists())

    def test_load_current_attempts_reads_task_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task_db = Path(tmp) / "tasks.sqlite3"
            with sqlite3.connect(task_db) as connection:
                connection.execute("CREATE TABLE tasks (task_id TEXT, attempt INTEGER)")
                connection.execute("INSERT INTO tasks VALUES (?, ?)", ("a" * 24, 3))
            self.assertEqual({"a" * 24: 3}, benchmark.load_current_attempts(task_db))

    def test_decision_filename_regex_matches_runtime_contract(self) -> None:
        tree = ast.parse((ROOT / "src" / "grabowski_task_attention.py").read_text())
        runtime_pattern = None
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not any(
                isinstance(target, ast.Name) and target.id == "DECISION_FILE_RE"
                for target in node.targets
            ):
                continue
            call = node.value
            if (
                isinstance(call, ast.Call)
                and call.args
                and isinstance(call.args[0], ast.Constant)
            ):
                runtime_pattern = call.args[0].value
                break
        self.assertEqual(benchmark.DECISION_FILE_RE.pattern, runtime_pattern)

    def test_promotion_thresholds_are_explicit(self) -> None:
        promote, reasons = benchmark.index_promotion_recommended(
            [
                {"synthetic_size": 10_000, "p95_ms": 251.0},
                {"synthetic_size": 50_000, "p95_ms": 900.0},
            ]
        )
        self.assertTrue(promote)
        self.assertEqual(["p95_at_10000_exceeds_250ms"], reasons)

    def test_below_threshold_does_not_recommend_index(self) -> None:
        promote, reasons = benchmark.index_promotion_recommended(
            [
                {"synthetic_size": 10_000, "p95_ms": 250.0},
                {"synthetic_size": 50_000, "p95_ms": 1000.0},
            ]
        )
        self.assertFalse(promote)
        self.assertEqual([], reasons)


if __name__ == "__main__":
    unittest.main()
