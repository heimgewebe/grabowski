"""Focused regressions for source- and loader-bound synthetic audit probe."""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "operator_read_cost_probe.py"
SPEC = importlib.util.spec_from_file_location("operator_read_cost_probe", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class BenchmarkInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="probe-input-binding-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for folder, names in (
            ("src", probe.SOURCE_BINDING_FILES),
            ("tests", probe.TEST_LOADER_BINDING_FILES),
        ):
            (self.root / folder).mkdir()
            for name in names:
                (self.root / folder / name).write_text(name, encoding="utf-8")
        self.loader_path = self.root / "tests" / probe.TEST_LOADER_BINDING_FILES[0]
        self.transitive_paths = [
            self.root / "src" / "grabowski_audit_signal.py",
            self.root / "src" / "grabowski_consumer_surface.py",
        ]
        for path in self.transitive_paths:
            path.write_text(path.name, encoding="utf-8")

    def _worker_args(self, hashes):
        return [
            "probe", "--worker-state", str(self.root),
            "--worker-case", "verify",
            "--expected-input-hashes", json.dumps(hashes),
        ]

    def test_all_three_loader_files_are_bound_and_mutation_detected(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            self.assertEqual(set(pinned["test_loader_sha256"]), set(probe.TEST_LOADER_BINDING_FILES))
            self.assertEqual(set(pinned["source_sha256"]), set(probe.SOURCE_BINDING_FILES))
            probe.require_benchmark_inputs(pinned)
            self.loader_path.write_text("unexpected-new-loader", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                probe.require_benchmark_inputs(pinned)

    def test_transitive_projection_modules_are_bound(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            direct_hashes = pinned["source_sha256"].copy()
            self.assertEqual(
                set(pinned["python_tree_sha256"]), {"src", "tests"}
            )
            for path in self.transitive_paths:
                original = path.read_text(encoding="utf-8")
                path.write_text("transitive-change", encoding="utf-8")
                self.assertEqual(
                    probe.benchmark_input_hashes()["source_sha256"], direct_hashes
                )
                with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                    probe.require_benchmark_inputs(pinned)
                path.write_text(original, encoding="utf-8")

    def test_new_python_module_is_bound_before_worker_execution(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            (self.root / "tests" / "new_dependency.py").write_text(
                "dynamic-import", encoding="utf-8"
            )
            with mock.patch.object(sys, "argv", self._worker_args(pinned)), mock.patch.object(
                probe, "run_case"
            ) as measure:
                with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                    probe.main()
                measure.assert_not_called()

    def test_transitive_change_during_worker_blocks_result(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()

            def changed_projection(*_args):
                self.transitive_paths[0].write_text(
                    "changed-during-measurement", encoding="utf-8"
                )
                return {"case": "projection", "valid": True}

            output = StringIO()
            with mock.patch.object(sys, "argv", self._worker_args(pinned)), mock.patch.object(
                probe, "run_case", side_effect=changed_projection
            ), redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                    probe.main()
            self.assertEqual(output.getvalue(), "")

    def test_worker_denies_stale_input_before_measurement(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            self.loader_path.write_text("changed-before-import", encoding="utf-8")
            with mock.patch.object(sys, "argv", self._worker_args(pinned)), mock.patch.object(
                probe, "run_case"
            ) as measure:
                with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                    probe.main()
                measure.assert_not_called()

    def test_worker_denies_changed_input_after_measurement_without_emitting(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()

            def changed_during_measurement(*_args):
                self.loader_path.write_text("changed-during-import", encoding="utf-8")
                return {"case": "verify", "valid": True}

            output = StringIO()
            with mock.patch.object(sys, "argv", self._worker_args(pinned)), mock.patch.object(
                probe, "run_case", side_effect=changed_during_measurement
            ), redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                    probe.main()
            self.assertEqual(output.getvalue(), "")

    def test_worker_emits_valid_result_only_with_matching_binding(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            output = StringIO()
            with mock.patch.object(sys, "argv", self._worker_args(pinned)), mock.patch.object(
                probe, "run_case", return_value={"case": "verify", "valid": True}
            ), redirect_stdout(output):
                probe.main()
            self.assertEqual(json.loads(output.getvalue()), {"case": "verify", "valid": True})


if __name__ == "__main__":
    unittest.main()
