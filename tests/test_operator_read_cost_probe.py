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

    def test_sweep_budget_rejects_repeated_and_aggregate_sizes(self):
        self.assertEqual(probe.validate_sweep("1000,100000,1000000", "verify,snapshot", 768)[0], [1000, 100000, 1000000])
        for numbers in ("10,10", "1,2,3,4,5,6", "1500000,1", "0", "10000000"):
            with self.subTest(numbers=numbers), self.assertRaises(ValueError):
                probe.validate_sweep(numbers, "verify", 64)
        with self.assertRaises(ValueError):
            probe.validate_sweep("1000000", "verify", 4096)
        with self.assertRaises(ValueError):
            probe.validate_sweep("1000", "verify,verify", 64)

    def test_modules_deny_unowned_parent_bytecode_cache_before_import(self):
        with mock.patch.object(probe.sys, "pycache_prefix", None):
            with self.assertRaisesRegex(RuntimeError, "private owned bytecode cache"):
                probe.modules()
        wrong = self.root / "unowned-cache"
        wrong.mkdir(mode=0o700)
        with mock.patch.object(probe.sys, "pycache_prefix", str(wrong)):
            with self.assertRaisesRegex(RuntimeError, "private owned bytecode cache"):
                probe.modules()

    def test_parent_private_cache_never_loads_unchecked_hash_bytecode(self):
        import py_compile
        source = self.root / "src" / "parent_fixture_sentinel.py"
        source.write_text("VALUE = 'poison'\n", encoding="utf-8")
        cached = self.root / "src" / "__pycache__"
        cached.mkdir()
        compiled = cached / f"parent_fixture_sentinel.{sys.implementation.cache_tag}.pyc"
        py_compile.compile(
            str(source), cfile=str(compiled), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH
        )
        source.write_text("VALUE = 'safe'\n", encoding="utf-8")
        private = self.root / "private-bytecode"
        private.mkdir(mode=0o700)
        with mock.patch.object(sys, "pycache_prefix", str(private)):
            spec = importlib.util.spec_from_file_location("parent_fixture_sentinel", source)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        self.assertEqual(module.VALUE, "safe")

    def test_disk_budget_preflight(self):
        from types import SimpleNamespace
        with mock.patch.object(probe.shutil, "disk_usage", return_value=SimpleNamespace(free=10)):
            with self.assertRaisesRegex(RuntimeError, "insufficient temporary disk"):
                probe.require_fixture_space(self.root, 1000, 768)

    def test_root_symlink_and_transitive_symlink_directory_rejected(self):
        with mock.patch.object(probe, "ROOT", self.root):
            (self.root / "src" / "unsafe-package").symlink_to(self.root / "tests", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "source directory is unsafe"):
                probe.python_tree_sha256("src")
            (self.root / "src" / "unsafe-package").unlink()
            (self.root / "src").rename(self.root / "src-actual")
            (self.root / "src").symlink_to(self.root / "src-actual", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "source tree is unsafe"):
                probe.python_tree_sha256("src")

    def test_unreadable_source_tree_walk_fails_closed(self):
        def unreadable(_root, **kwargs):
            kwargs["onerror"](PermissionError("inaccessible subdirectory"))
            return iter(())
        with mock.patch.object(probe, "ROOT", self.root), mock.patch.object(
            probe.os, "walk", side_effect=unreadable
        ):
            with self.assertRaisesRegex(RuntimeError, "enumeration failed"):
                probe.python_tree_sha256("src")

    def test_native_extension_and_new_non_python_file_change_hash(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            (self.root / "src" / "grabowski_audit_signal.cpython-310-x86_64-linux-gnu.so").write_bytes(b"shadowing-extension")
            with self.assertRaisesRegex(RuntimeError, "input hashes changed"):
                probe.require_benchmark_inputs(pinned)

    def test_cache_directory_ignored_but_symlink_cache_rejected(self):
        with mock.patch.object(probe, "ROOT", self.root):
            pinned = probe.benchmark_input_hashes()
            cache = self.root / "src" / "__pycache__"
            cache.mkdir()
            (cache / "old.pyc").write_bytes(b"stale-bytecode-not-executable-in-isolated-worker")
            probe.require_benchmark_inputs(pinned)
            import shutil
            shutil.rmtree(cache)
            cache.symlink_to(self.root / "tests", target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "source directory is unsafe"):
                probe.require_benchmark_inputs(pinned)

    def test_counter_excludes_contender_lock_wait(self):
        from contextlib import contextmanager
        class FakeAudit:
            def _read_audit_descriptor(self, descriptor, path):
                return b"x"
            def _acquire_flock(self, descriptor, *, exclusive):
                return None
            @contextmanager
            def _audit_coordination_lock(self, path, *, exclusive):
                self._acquire_flock(None, exclusive=exclusive)
                yield
        base = FakeAudit()
        with probe.instrument(base, None, None, False, contend=True) as counts:
            with base._audit_coordination_lock("synthetic-lock", exclusive=False):
                base._read_audit_descriptor(None, "synthetic")
        self.assertEqual(counts["flock_acquire_count"], 1)
        self.assertEqual(counts["coordination_hold_count"], 1)
        self.assertEqual(counts["audit_descriptor_reads"], 1)
        self.assertEqual(counts["exclusive_contender"]["outcome"], "acquired")

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
