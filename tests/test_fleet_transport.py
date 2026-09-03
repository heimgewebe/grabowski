from __future__ import annotations

import base64
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
    fake._require_operator_mutation = Mock()
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

    def test_fleet_list_is_registry_read_without_terminal_capability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            fake._require_operator_capability = Mock(side_effect=AssertionError("must not gate pure read"))
            result = module.grabowski_fleet_list()
        fake._require_operator_capability.assert_not_called()
        fake._run.assert_not_called()
        encoded = json.dumps(result, sort_keys=True)
        for forbidden in (
            "target",
            "command_allowlist",
            "connect_timeout_seconds",
            "roles",
            "remote_command_mode",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn("path", result)
        self.assertEqual(result["count"], 1)
        self.assertEqual(
            result["hosts"]["local"],
            {"kind": "local", "ready": True},
        )

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

    def test_windows_powershell_remote_mode_uses_encoded_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            config = json.loads(module.FLEET_CONFIG.read_text(encoding="utf-8"))
            config["hosts"]["windows"] = {
                "transport": "ssh",
                "target": "windows-host",
                "enabled": True,
                "roles": ["windows"],
                "command_allowlist": ["*"],
                "remote_command_mode": "windows-powershell",
            }
            module.FLEET_CONFIG.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(module.shutil, "which", return_value="/usr/bin/ssh"):
                module.run_fleet_host(
                    "windows",
                    ["tool.exe", "space value", "a&b"],
                    timeout_seconds=30,
                    max_output_bytes=64 * 1024,
                )
        remote = fake._run.call_args.args[0][-1]
        self.assertTrue(remote.startswith(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
        ))
        self.assertNotIn("exec ", remote)
        self.assertNotIn("space value", remote)
        self.assertNotIn("a&b", remote)
        encoded_script = remote.rsplit(" ", 1)[1]
        script = base64.b64decode(encoded_script).decode("utf-16le")
        marker = "FromBase64String('"
        payload_start = script.index(marker) + len(marker)
        payload_end = script.index("')", payload_start)
        payload = json.loads(
            base64.b64decode(script[payload_start:payload_end]).decode("utf-8")
        )
        self.assertEqual(
            payload,
            {"command": "tool.exe", "args": ["space value", "a&b"]},
        )
        self.assertIn("$o.command", script)
        self.assertIn("$o.args", script)

    def test_ssh_remote_mode_defaults_to_posix_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, fake = _load_fleet_module(Path(tmp))
            config = json.loads(module.FLEET_CONFIG.read_text(encoding="utf-8"))
            config["hosts"]["ssh"] = {
                "transport": "ssh",
                "target": "ssh-host",
                "enabled": True,
                "roles": ["development"],
                "command_allowlist": ["*"],
            }
            module.FLEET_CONFIG.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(module.shutil, "which", return_value="/usr/bin/ssh"):
                module.run_fleet_host(
                    "ssh",
                    ["printf", "ok"],
                    timeout_seconds=30,
                    max_output_bytes=64 * 1024,
                )
        remote = fake._run.call_args.args[0][-1]
        self.assertEqual(remote, "exec printf ok")

    def test_windows_remote_mode_requires_ssh_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module, _ = _load_fleet_module(Path(tmp))
            config = json.loads(module.FLEET_CONFIG.read_text(encoding="utf-8"))
            config["hosts"]["local"]["remote_command_mode"] = "windows-powershell"
            module.FLEET_CONFIG.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires SSH transport"):
                module.load_fleet()


if __name__ == "__main__":
    unittest.main()
