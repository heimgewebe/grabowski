from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_fleet as fleet
import grabowski_operations as operations
import grabowski_privileged as privileged


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class FleetTests(unittest.TestCase):
    def test_registry_and_local_execution_are_typed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.json"
            _write(config, {
                "schema_version": 1,
                "hosts": {
                    "local": {
                        "transport": "local",
                        "target": "local",
                        "enabled": True,
                        "roles": ["test"],
                        "command_allowlist": ["hostname"],
                    }
                },
            })
            completed = {
                "returncode": 0,
                "stdout": "local\n",
                "stderr": "",
                "timed_out": False,
            }
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                fleet.operator, "_run", return_value=completed
            ) as run:
                parsed = fleet.load_fleet()
                self.assertEqual(parsed["hosts"]["local"]["transport"], "local")
                result = fleet.run_fleet_host(
                    "local", ["hostname"], timeout_seconds=10, max_output_bytes=1000
                )
            self.assertEqual(result["result"]["returncode"], 0)
            run.assert_called_once()

    def test_registry_rejects_unknown_fields_and_unsafe_ssh_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.json"
            _write(config, {
                "schema_version": 1,
                "hosts": {
                    "remote": {
                        "transport": "ssh",
                        "target": "host;uname",
                        "enabled": True,
                        "roles": ["test"],
                        "command_allowlist": ["*"],
                        "unexpected": True,
                    }
                },
            })
            with patch.object(fleet, "FLEET_CONFIG", config):
                with self.assertRaisesRegex(ValueError, "key mismatch"):
                    fleet.load_fleet()
            value = json.loads(config.read_text(encoding="utf-8"))
            del value["hosts"]["remote"]["unexpected"]
            _write(config, value)
            with patch.object(fleet, "FLEET_CONFIG", config):
                with self.assertRaisesRegex(ValueError, "unsafe SSH target"):
                    fleet.load_fleet()


class OperationTests(unittest.TestCase):
    def _config(self, path: Path) -> None:
        _write(path, {
            "schema_version": 1,
            "operations": {
                "rollback-test": {
                    "description": "Exercise phase ordering and rollback.",
                    "parameters": {"unit": "[a-z-]+"},
                    "steps": [
                        {"phase": "preflight", "target": "local", "argv": ["pre", "${unit}"]},
                        {"phase": "action", "target": "local", "argv": ["act", "${unit}"]},
                        {"phase": "postflight", "target": "local", "argv": ["post", "${unit}"]},
                        {"phase": "rollback", "target": "local", "argv": ["undo", "${unit}"]},
                    ],
                }
            },
        })

    def test_plan_uses_only_exact_parameter_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "operations.json"
            self._config(config)
            with patch.object(operations, "OPERATIONS_CONFIG", config):
                plan = operations._render("rollback-test", {"unit": "demo-unit"})
            self.assertEqual(plan["steps"][1]["argv"], ["act", "demo-unit"])
            self.assertEqual(len(plan["parameters_sha256"]), 64)

    def test_postflight_failure_runs_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "operations.json"
            self._config(config)

            def execute(step):
                code = 1 if step["phase"] == "postflight" else 0
                return {"target": "local", "result": {"returncode": code}}

            with patch.object(operations, "OPERATIONS_CONFIG", config), patch.object(
                operations, "_run_step", side_effect=execute
            ), patch.object(
                operations.operator, "_require_operator_mutation"
            ), patch.object(
                operations.base, "_append_audit"
            ):
                result = operations.grabowski_operation_run(
                    "rollback-test", {"unit": "demo-unit"}
                )
            self.assertFalse(result["success"])
            self.assertEqual(result["failed_phase"], "postflight")
            self.assertTrue(result["rollback"]["attempted"])
            self.assertTrue(result["rollback"]["success"])


class PrivilegedAndConnectorTests(unittest.TestCase):
    def test_privileged_status_is_fail_closed_without_root_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(privileged, "BROKER", root / "missing-broker"), patch.object(
                privileged, "BROKER_CONFIG", root / "missing-config"
            ), patch.object(
                privileged.operator, "_require_operator_capability"
            ), patch.object(
                privileged.shutil, "which", return_value=None
            ):
                result = privileged.grabowski_privileged_broker_status()
            self.assertFalse(result["ready"])
            self.assertTrue(result["fail_closed"])

    def test_connector_probe_detects_snapshot_drift(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "connector_probe_test", ROOT / "tools" / "connector_probe.py"
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        expected = contract["expected_tools"]
        self.assertEqual(module.fingerprint(expected), module.fingerprint(list(reversed(expected))))
        self.assertNotEqual(module.fingerprint(expected), module.fingerprint(expected[:-1]))


if __name__ == "__main__":
    unittest.main()
