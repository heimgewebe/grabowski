from __future__ import annotations

import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SOURCE = SRC / "grabowski_fleet.py"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeMcp:
    def tool(self, *args, **kwargs):
        return lambda function: function


def _load_fleet_module(root: Path):
    config = root / "fleet.json"
    config.write_text(
        json.dumps({
            "schema_version": 1,
            "hosts": {
                "local": {
                    "transport": "local",
                    "target": "localhost",
                    "enabled": True,
                    "roles": ["development"],
                    "command_allowlist": ["*"],
                }
            },
        }),
        encoding="utf-8",
    )
    fake = types.ModuleType("grabowski_operator_core")
    fake.mcp = _FakeMcp()
    fake.HOME = root
    fake.READ_ONLY = object()
    fake.MUTATING = object()
    fake.DEFAULT_TIMEOUT = 60
    fake.DEFAULT_OUTPUT_BYTES = 250_000
    fake.SYNCHRONOUS_TRANSPORT_TIMEOUT_SECONDS = 30
    fake.SYNCHRONOUS_TRANSPORT_OUTPUT_BYTES = 64 * 1024
    fake._validate_argv = lambda argv, cwd=None: list(argv)
    fake._redact_argv = lambda argv: list(argv)
    fake._timeout = lambda value: value
    fake._output_limit = lambda value: value
    fake._require_operator_mutation = lambda capability: None
    fake._require_operator_capability = lambda capability: None
    fake._enforce_synchronous_call_shape = Mock()
    fake._synchronous_public_contract = lambda *, surface: {
        "surface": surface,
        "server_owned_limits": True,
        "client_selected_timeout_supported": False,
        "client_selected_output_limit_supported": False,
    }
    fake._run = Mock(return_value={
        "returncode": 0,
        "stdout": "ok",
        "stderr": "",
        "timed_out": False,
    })

    module_name = f"_fleet_transport_{id(root)}"
    spec = importlib.util.spec_from_file_location(module_name, SOURCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"grabowski_operator_core": fake, module_name: module}), patch.dict(
        os.environ, {"GRABOWSKI_FLEET_CONFIG": str(config)}
    ):
        spec.loader.exec_module(module)
    return module, fake


class FleetTransportGateTests(unittest.TestCase):
    def test_operator_core_exports_server_owned_sync_contract(self) -> None:
        import grabowski_operator_core as core

        self.assertEqual(core.SYNCHRONOUS_TRANSPORT_TIMEOUT_SECONDS, 30)
        self.assertEqual(core.SYNCHRONOUS_TRANSPORT_OUTPUT_BYTES, 64 * 1024)
        contract = core._synchronous_public_contract(surface="test")
        self.assertTrue(contract["server_owned_limits"])
        self.assertFalse(contract["client_selected_timeout_supported"])

    def test_public_fleet_run_enforces_server_owned_limits_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            parameters = inspect.signature(module.grabowski_fleet_run).parameters
            self.assertEqual(list(parameters), ["host", "argv"])
            result = module.grabowski_fleet_run("local", ["printf", "ok"])
        fake._enforce_synchronous_call_shape.assert_called_once_with(
            ["printf", "ok"],
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
            surface="grabowski_fleet_run",
        )
        fake._run.assert_called_once()
        self.assertEqual(result["result"]["returncode"], 0)
        self.assertTrue(result["synchronous_contract"]["server_owned_limits"])
        self.assertFalse(
            result["synchronous_contract"]["client_selected_timeout_supported"]
        )

    def test_public_fleet_run_denial_prevents_host_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            fake._enforce_synchronous_call_shape.side_effect = PermissionError("denied")
            with self.assertRaisesRegex(PermissionError, "denied"):
                module.grabowski_fleet_run("local", ["bash", "-lc", "printf ok"])
        fake._run.assert_not_called()

    def test_fleet_cli_uses_same_gate_and_bounded_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            with patch.object(
                sys,
                "argv",
                ["grabowski-fleet", "run", "local", "printf", "ok"],
            ):
                self.assertEqual(module.main(), 0)
        fake._enforce_synchronous_call_shape.assert_called_once_with(
            ["printf", "ok"],
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
            surface="grabowski_fleet_cli",
        )
        fake._run.assert_called_once()

    def test_fleet_cli_denial_prevents_host_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            fake._enforce_synchronous_call_shape.side_effect = PermissionError("denied")
            with patch.object(
                sys,
                "argv",
                ["grabowski-fleet", "run", "local", "bash", "-lc", "printf ok"],
            ):
                self.assertEqual(module.main(), 2)
        fake._run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
