from __future__ import annotations

from pathlib import Path
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "watchdog_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location("watchdog_runtime", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("watchdog_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["watchdog_runtime"] = module
    spec.loader.exec_module(module)
    return module


watchdog = load_module()


class WatchdogRuntimeTests(unittest.TestCase):
    def _probe(
        self,
        *,
        operators: list[int],
        age: float = 120.0,
        integrity: "watchdog.IntegrityResult | None" = None,
    ):
        if integrity is None:
            integrity = watchdog.IntegrityResult(True, None, "release-001")
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "101",
                },
            ),
            patch.object(watchdog, "main_identity_ok", return_value=True),
            patch.object(watchdog, "process_age_seconds", return_value=age),
            patch.object(watchdog, "operator_candidates", return_value=operators),
            patch.object(watchdog, "http_probe", return_value=True),
            patch.object(watchdog, "probe_integrity", return_value=integrity),
        ):
            return watchdog.probe_runtime(
                service="tunnel-client-grabowski.service",
                profile="grabowski",
                expected_module="grabowski_operator",
                runtime_root=Path("/runtime"),
                health_url="http://127.0.0.1:18080/healthz",
                ready_url="http://127.0.0.1:18080/readyz",
                startup_grace=20,
                http_timeout=1,
            )

    def test_green_http_without_operator_is_unhealthy(self) -> None:
        result = self._probe(operators=[])

        self.assertEqual(result.status, "unhealthy")
        self.assertEqual(result.reasons, ("operator-count-0",))
        self.assertIsNone(result.operator_pid)

    def test_exactly_one_operator_and_green_http_is_healthy(self) -> None:
        result = self._probe(operators=[202])

        self.assertEqual(result.status, "healthy")
        self.assertEqual(result.main_pid, 101)
        self.assertEqual(result.operator_pid, 202)

    def test_live_runtime_with_invalid_integrity_is_not_healthy(self) -> None:
        """A runtime that answers /healthz but cannot act is degraded, not healthy."""
        result = self._probe(
            operators=[202],
            integrity=watchdog.IntegrityResult(
                False, "entrypoint-contract-invalid", "release-001"
            ),
        )

        self.assertEqual(result.status, "integrity_invalid")
        self.assertEqual(result.reasons, ("integrity-entrypoint-contract-invalid",))
        self.assertEqual(result.operator_pid, 202)
        self.assertIsNotNone(result.integrity)
        self.assertFalse(result.integrity.valid)
        self.assertEqual(result.integrity.reason, "entrypoint-contract-invalid")

    def test_process_failure_outranks_integrity(self) -> None:
        """Transport/process faults keep their own status and restart path."""
        result = self._probe(
            operators=[],
            integrity=watchdog.IntegrityResult(False, "contract-hash-drift"),
        )

        self.assertEqual(result.status, "unhealthy")

    def test_startup_grace_suppresses_early_restart(self) -> None:
        result = self._probe(operators=[], age=4.0)

        self.assertEqual(result.status, "startup_grace")
        self.assertEqual(result.reasons, ("operator-count-0",))

    def test_failure_threshold_requires_three_consecutive_failures(self) -> None:
        state = watchdog.WatchdogState()
        first = watchdog.decide_failure(
            state,
            now=100,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )
        second = watchdog.decide_failure(
            first.state,
            now=130,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )
        third = watchdog.decide_failure(
            second.state,
            now=160,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(first.action, "observe")
        self.assertEqual(second.action, "observe")
        self.assertEqual(third.action, "restart")
        self.assertEqual(third.state.consecutive_failures, 0)
        self.assertEqual(third.state.restart_timestamps, [160])

    def test_restart_budget_blocks_fourth_restart_in_window(self) -> None:
        state = watchdog.WatchdogState(
            consecutive_failures=2,
            restart_timestamps=[100, 200, 300],
        )
        decision = watchdog.decide_failure(
            state,
            now=400,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(decision.action, "budget-exhausted")
        self.assertEqual(decision.state.restart_timestamps, [100, 200, 300])

    def test_restart_budget_prunes_old_entries(self) -> None:
        state = watchdog.WatchdogState(
            consecutive_failures=2,
            restart_timestamps=[1, 200, 300],
        )
        decision = watchdog.decide_failure(
            state,
            now=1000,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(decision.action, "restart")
        self.assertEqual(decision.state.restart_timestamps, [200, 300, 1000])

    def test_main_identity_requires_exact_profile_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            pid_dir = proc / "42"
            pid_dir.mkdir()
            (pid_dir / "cmdline").write_bytes(
                b"/home/alex/.local/bin/tunnel-client\0run\0--profile\0grabowski\0"
            )
            self.assertTrue(watchdog.main_identity_ok(proc, 42, "grabowski"))

            (pid_dir / "cmdline").write_bytes(
                b"/home/alex/.local/bin/tunnel-client\0run\0--profile\0grabowski-old\0"
            )
            self.assertFalse(watchdog.main_identity_ok(proc, 42, "grabowski"))

    def test_state_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            state = root / "watchdog-state.json"
            state.symlink_to(target)

            with self.assertRaisesRegex(watchdog.WatchdogError, "state-file-is-symlink"):
                watchdog.load_state(state)

    def test_operator_identity_requires_stable_runtime_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            runtime = root / "runtime"
            python = runtime / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")

            (proc / "1").mkdir(parents=True)
            (proc / "1/status").write_text("PPid:\t0\n", encoding="utf-8")
            (proc / "2").mkdir()
            (proc / "2/status").write_text("PPid:\t1\n", encoding="utf-8")
            (proc / "2/cmdline").write_bytes(
                f"{python}\0-m\0grabowski_operator\0".encode()
            )
            (proc / "2/exe").symlink_to(python)

            self.assertEqual(
                watchdog.operator_candidates(proc, 1, runtime, "grabowski_operator"),
                [2],
            )

            (proc / "2/cmdline").write_bytes(
                f"{python}\0-m\0other_module\0".encode()
            )
            self.assertEqual(
                watchdog.operator_candidates(proc, 1, runtime, "grabowski_operator"),
                [],
            )


class WatchdogIntegrityProbeTests(unittest.TestCase):
    """probe_integrity must fail closed and name a machine-readable reason."""

    def _runtime(self, root: Path) -> Path:
        """Stage a deployed runtime with a schema-complete manifest.

        The manifest must satisfy the full canonical schema, not just the
        contract: a fixture that omitted the other required fields would let the
        probe claim validity for a manifest the runtime itself rejects.
        """
        runtime = root / "grabowski-mcp"
        site_packages = runtime / ".venv/lib/python3.12/site-packages"
        site_packages.mkdir(parents=True)
        shutil.copy(
            ROOT / "src" / "grabowski_runtime_contract.py",
            site_packages / "grabowski_runtime_contract.py",
        )
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        inputs = runtime / "inputs"
        inputs.mkdir()
        contract_path = inputs / "runtime-entrypoint.json"
        contract_bytes = (json.dumps(contract, indent=2) + "\n").encode("utf-8")
        contract_path.write_bytes(contract_bytes)

        modules = [contract["module"]] + [
            item["module"] for item in contract["supporting_sources"]
        ]
        destinations = [item["destination"] for item in contract["runtime_assets"]]
        digest = "0" * 64
        entrypoint_path = str(site_packages / f"{contract['module']}.py")
        manifest = {
            "schema_version": 6,
            "release_id": "release-001",
            "repo_head": "a" * 40,
            "entrypoint_contract": contract,
            "entrypoint_contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
            "agent_instructions": {
                "schema_version": 1,
                "version": "grabowski-agent-facing-contract-v1",
                "sha256": digest,
                "bytes": 2530,
                "max_bytes": 4096,
            },
            "source_sha256": digest,
            "source_sha256s": {module: digest for module in modules},
            "runtime_asset_sha256s": {name: digest for name in destinations},
            "runtime_asset_paths": {
                name: str(runtime / name) for name in destinations
            },
            "runtime_input_sha256": digest,
            "runtime_lock_sha256": digest,
            "snapshot_paths": {
                "runtime_entrypoint": str(contract_path),
                "runtime_input": str(inputs / "runtime.in"),
                "runtime_lock": str(inputs / "runtime.lock.txt"),
                "source": str(inputs / contract["source"]),
                "supporting_sources": {
                    item["module"]: str(inputs / item["source"])
                    for item in contract["supporting_sources"]
                },
                "runtime_assets": {
                    item["destination"]: str(inputs / item["source"])
                    for item in contract["runtime_assets"]
                },
            },
            "immutable_release_path": str(runtime),
            "expected_stable_runtime_path": str(runtime),
            "release_python_path": str(runtime / ".venv/bin/python"),
            "entrypoint_path": entrypoint_path,
            "module_paths": {
                module: str(site_packages / f"{module}.py") for module in modules
            },
            "platform": "Linux-test",
            "python_version": "3.12.0",
            "python_implementation": "CPython",
            "mcp_protocol_version": "2025-06-18",
            "created_at_unix": 1,
            "completion_status": "complete",
            "executable": str(runtime / ".venv/bin/python"),
            "pip_version": "pip 23.0.1",
        }
        (runtime / "deployment-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        return runtime

    def test_consistent_release_is_integrity_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            result = watchdog.probe_integrity(runtime)

        self.assertTrue(result.valid)
        self.assertIsNone(result.reason)
        self.assertEqual(result.release_id, "release-001")
        self.assertEqual(result.scope, "deployment-manifest")

    def test_non_contract_manifest_corruption_fails_closed(self) -> None:
        """A manifest field the runtime rejects must not read as healthy here."""
        for field in ("source_sha256s", "module_paths", "repo_head", "schema_version"):
            with self.subTest(field):
                with tempfile.TemporaryDirectory() as directory:
                    runtime = self._runtime(Path(directory))
                    manifest_path = runtime / "deployment-manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    del manifest[field]
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    result = watchdog.probe_integrity(runtime)

                self.assertFalse(result.valid)
                self.assertTrue(result.reason.startswith("manifest-schema-invalid:"))
                self.assertIn(field, result.reason)

    def test_missing_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = watchdog.probe_integrity(Path(directory))

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "manifest-missing")

    def test_unknown_contract_field_fails_closed(self) -> None:
        """The exact drift that deadlocked the runtime, seen by the watchdog."""
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            manifest_path = runtime / "deployment-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["entrypoint_contract"]["unreviewed_capability"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "entrypoint-contract-invalid")

    def test_contract_hash_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            manifest_path = runtime / "deployment-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["entrypoint_contract_sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "contract-hash-drift")

    def test_incomplete_deployment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            (runtime / "deployment-incomplete.json").write_text("{}", encoding="utf-8")
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "deployment-incomplete")

    def test_broken_canonical_schema_fails_closed_without_crashing(self) -> None:
        """A schema that raises at import must degrade the verdict, not the watchdog."""
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            for path in runtime.glob(
                ".venv/lib/*/site-packages/grabowski_runtime_contract.py"
            ):
                path.write_text(
                    "raise RuntimeError('schema exploded')\n", encoding="utf-8"
                )
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "canonical-contract-schema-unavailable")

    def test_relocated_release_reports_stale_path_not_corruption(self) -> None:
        """A moved release is stale, not content-corrupt; the reason must say so."""
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            manifest_path = runtime / "deployment-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["snapshot_paths"]["runtime_entrypoint"] = str(
                Path(directory) / "moved-away" / "runtime-entrypoint.json"
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "contract-snapshot-path-stale")

    def test_missing_canonical_schema_fails_closed(self) -> None:
        """Without the schema the watchdog must not guess that a release is fine."""
        with tempfile.TemporaryDirectory() as directory:
            runtime = self._runtime(Path(directory))
            for path in runtime.glob(
                ".venv/lib/*/site-packages/grabowski_runtime_contract.py"
            ):
                path.unlink()
            result = watchdog.probe_integrity(runtime)

        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "canonical-contract-schema-unavailable")


if __name__ == "__main__":
    unittest.main()
