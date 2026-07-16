from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import time
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
import grabowski_privileged_broker as privileged_broker


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

    def test_production_host_rejects_wildcard_allowlist_at_run_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.json"
            _write(config, {
                "schema_version": 1,
                "hosts": {
                    "prod": {
                        "transport": "ssh",
                        "target": "prod.example",
                        "enabled": True,
                        "roles": ["vps", "production"],
                        "command_allowlist": ["*"],
                    }
                },
            })
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                fleet.operator, "_run"
            ) as run:
                with self.assertRaisesRegex(PermissionError, "wildcard command_allowlist"):
                    fleet.run_fleet_host(
                        "prod",
                        ["hostname"],
                        timeout_seconds=10,
                        max_output_bytes=1000,
                    )
            run.assert_not_called()

    def test_production_host_can_use_explicit_ssh_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.json"
            _write(config, {
                "schema_version": 1,
                "hosts": {
                    "prod": {
                        "transport": "ssh",
                        "target": "prod.example",
                        "enabled": True,
                        "roles": ["vps", "production"],
                        "command_allowlist": ["hostname"],
                        "connect_timeout_seconds": 7,
                    }
                },
            })
            completed = {
                "returncode": 0,
                "stdout": "prod\n",
                "stderr": "",
                "timed_out": False,
            }
            with (
                patch.object(fleet, "FLEET_CONFIG", config),
                patch.object(fleet.shutil, "which", return_value="/usr/bin/ssh"),
                patch.object(fleet.operator, "_run", return_value=completed) as run,
            ):
                result = fleet.run_fleet_host(
                    "prod",
                    ["hostname"],
                    timeout_seconds=10,
                    max_output_bytes=1000,
                )

            self.assertEqual(result["transport"], "ssh")
            self.assertEqual(result["roles"], ["vps", "production"])
            call_argv = run.call_args.args[0]
            self.assertEqual(call_argv[-2:], ["prod.example", "exec hostname"])


    def test_task_unit_observer_does_not_open_generic_systemctl_on_production(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "fleet.json"
            _write(config, {
                "schema_version": 1,
                "hosts": {
                    "prod": {
                        "transport": "ssh",
                        "target": "prod.example",
                        "enabled": True,
                        "roles": ["vps", "production"],
                        "command_allowlist": ["hostname"],
                        "connect_timeout_seconds": 7,
                    }
                },
            })
            completed = {
                "returncode": 0,
                "stdout": "LoadState=not-found\nActiveState=inactive\nResult=success\n",
                "stderr": "",
                "timed_out": False,
            }
            with (
                patch.object(fleet, "FLEET_CONFIG", config),
                patch.object(fleet.shutil, "which", return_value="/usr/bin/ssh"),
                patch.object(fleet.operator, "_run", return_value=completed) as run,
            ):
                with self.assertRaisesRegex(fleet.FleetCommandDenied, "Executable is not allowed"):
                    fleet.run_fleet_host(
                        "prod",
                        ["systemctl", "--user", "show", "demo.service"],
                        timeout_seconds=10,
                        max_output_bytes=1000,
                    )
                result = fleet.run_fleet_task_unit_show(
                    "prod",
                    "grabowski-task-0123456789abcdef01234567-a1.service",
                    ("LoadState", "ActiveState", "Result"),
                    timeout_seconds=10,
                    max_output_bytes=1000,
                )

            self.assertEqual(result["observer"], fleet.TASK_UNIT_SHOW_OBSERVER)
            self.assertEqual(result["transport"], "ssh")
            call_argv = run.call_args.args[0]
            self.assertEqual(call_argv[-2], "prod.example")
            self.assertEqual(
                call_argv[-1],
                "exec systemctl --user show grabowski-task-0123456789abcdef01234567-a1.service --no-pager --property=LoadState --property=ActiveState --property=Result",
            )

    def test_task_unit_observer_rejects_unbounded_shapes(self) -> None:
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
            with patch.object(fleet, "FLEET_CONFIG", config), patch.object(
                fleet.operator, "_run"
            ) as run:
                with self.assertRaisesRegex(ValueError, "task unit"):
                    fleet.run_fleet_task_unit_show(
                        "local", "demo.service", ["LoadState"],
                        timeout_seconds=10, max_output_bytes=1000,
                    )
                with self.assertRaisesRegex(ValueError, "property"):
                    fleet.run_fleet_task_unit_show(
                        "local",
                        "grabowski-task-0123456789abcdef01234567-a1.service",
                        ["LoadState;reboot"],
                        timeout_seconds=10,
                        max_output_bytes=1000,
                    )
            run.assert_not_called()


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


class PrivilegedBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _reference(self, now: int = 1000) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "execution": "unprivileged-reference-only",
            "may_execute": False,
            "requires_external_privileged_agent": True,
            "replay_policy": "single-use-external-broker",
            "action": "edit_system_service",
            "target": "grabowski-mcp.service",
            "justification": "Restart the explicitly named managed service",
            "request_id": "a" * 32,
            "created_at_unix": now,
            "expires_at_unix": now + 900,
        }
        value["reference_sha256"] = privileged_broker.canonical_sha256(value)
        return value

    def test_reference_and_fixed_template_are_validated(self) -> None:
        reference = self._reference()
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 1,
            "actions": {
                "edit_system_service": {
                    "enabled": True,
                    "target_pattern": "[A-Za-z0-9_.@:-]{1,200}",
                    "argv": ["/usr/bin/systemctl", "restart", "{target}"],
                    "timeout_seconds": 120,
                }
            },
        }
        argv, timeout = privileged_broker.resolve_action(config, parsed)
        self.assertEqual(
            argv,
            ["/usr/bin/systemctl", "restart", "grabowski-mcp.service"],
        )
        self.assertEqual(timeout, 120)

    def test_reset_failed_systemd_unit_uses_fixed_template(self) -> None:
        reference = self._reference()
        reference["action"] = "reset_failed_systemd_unit"
        reference["target"] = "user@111.service"
        reference["justification"] = "Clear stale failed state for a checked GDM user manager"
        reference.pop("reference_sha256")
        reference["reference_sha256"] = privileged_broker.canonical_sha256(reference)
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 1,
            "actions": {
                "reset_failed_systemd_unit": {
                    "enabled": True,
                    "target_pattern": r"(?:user@[0-9]{1,10}|[A-Za-z0-9_@][A-Za-z0-9_.@:-]{0,119})\.service",
                    "argv": ["/usr/bin/systemctl", "reset-failed", "{target}"],
                    "timeout_seconds": 30,
                }
            },
        }
        argv, timeout = privileged_broker.resolve_action(config, parsed)
        self.assertEqual(
            argv,
            ["/usr/bin/systemctl", "reset-failed", "user@111.service"],
        )
        self.assertEqual(timeout, 30)

    def test_reset_failed_systemd_unit_rejects_non_service_target(self) -> None:
        config = {
            "schema_version": 1,
            "actions": {
                "reset_failed_systemd_unit": {
                    "enabled": True,
                    "target_pattern": r"(?:user@[0-9]{1,10}|[A-Za-z0-9_@][A-Za-z0-9_.@:-]{0,119})\.service",
                    "argv": ["/usr/bin/systemctl", "reset-failed", "{target}"],
                    "timeout_seconds": 30,
                }
            },
        }
        for target in ("../../etc/shadow", "--system.service", "-.service"):
            with self.subTest(target=target):
                reference = self._reference()
                reference["action"] = "reset_failed_systemd_unit"
                reference["target"] = target
                reference.pop("reference_sha256")
                reference["reference_sha256"] = privileged_broker.canonical_sha256(reference)
                parsed = privileged_broker.parse_reference(
                    json.dumps(reference).encode("utf-8"), now=1000
                )
                with self.assertRaisesRegex(PermissionError, "target"):
                    privileged_broker.resolve_action(config, parsed)

    def _root_task_reference(self, payload: dict[str, object], now: int = 1000) -> dict[str, object]:
        value = self._reference(now=now)
        value["action"] = "operator_root_task_systemd_unit"
        value["target"] = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        value["justification"] = "Operate one Grabowski root-owned systemd task unit"
        value.pop("reference_sha256")
        value["reference_sha256"] = privileged_broker.canonical_sha256(value)
        return value

    def _root_task_config(self) -> dict[str, object]:
        return {
            "schema_version": 2,
            "actions": {
                "operator_root_task_systemd_unit": {
                    "enabled": True,
                    "mode": "root-task-systemd",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 60,
                    "max_argv": 16,
                    "allow_shell": False,
                    "allowed_argv_prefixes": [
                        ["/usr/local/bin/sleep-heimserver"],
                    ],
                    "start_gate": self._power_gate(self.tmp.name),
                    "policy_intent": "recovery-gated-root-task-catalog",
                }
            },
        }

    def test_root_task_start_resolves_to_root_owned_systemd_unit(self) -> None:
        unit = "grabowski-task-0123456789abcdef01234567-a1.service"
        reference = self._root_task_reference({
            "operation": "start",
            "unit": unit,
            "argv": ["/usr/local/bin/sleep-heimserver"],
            "cwd": "/",
            "runtime_seconds": 300,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "description": "Grabowski task root",
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        execution = privileged_broker.resolve_execution(self._root_task_config(), parsed)

        self.assertEqual(execution["mode"], "root-task-systemd")
        self.assertEqual(execution["internal_action"], "root-task-start")
        argv = execution["argv"]
        self.assertEqual(argv[:2], ["/usr/bin/systemd-run", "--system"])
        self.assertIn("--slice=grabowski-root-tasks.slice", argv)
        self.assertIn("--property=LogRateLimitIntervalSec=30s", argv)
        self.assertIn("--property=LogRateLimitBurst=1000", argv)
        self.assertNotIn("--user", argv)
        self.assertEqual(argv[-2:], ["--", "/usr/local/bin/sleep-heimserver"])

    def test_root_task_start_rejects_runtime_without_lease_grace(self) -> None:
        reference = self._root_task_reference({
            "operation": "start",
            "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            "argv": ["/usr/local/bin/sleep-heimserver"],
            "cwd": "/",
            "runtime_seconds": privileged_broker.ROOT_TASK_MAX_RUNTIME_SECONDS + 1,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "description": "Grabowski task root",
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        with self.assertRaisesRegex(ValueError, "runtime_seconds"):
            privileged_broker.resolve_execution(self._root_task_config(), parsed)

    def test_root_task_start_rejects_control_character_description(self) -> None:
        reference = self._root_task_reference({
            "operation": "start",
            "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            "argv": ["/usr/local/bin/sleep-heimserver"],
            "cwd": "/",
            "runtime_seconds": 300,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "description": "Grabowski task\nforged",
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        with self.assertRaisesRegex(ValueError, "description"):
            privileged_broker.resolve_execution(self._root_task_config(), parsed)

    def test_root_task_start_rejects_command_outside_catalog(self) -> None:
        reference = self._root_task_reference({
            "operation": "start",
            "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            "argv": ["/usr/bin/id", "-u"],
            "cwd": "/",
            "runtime_seconds": 300,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "description": "Grabowski task root",
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        with self.assertRaisesRegex(PermissionError, "configured catalog"):
            privileged_broker.resolve_execution(self._root_task_config(), parsed)

    def test_root_task_start_requires_fresh_gate_but_show_remains_available(self) -> None:
        config = self._root_task_config()
        config["actions"]["operator_root_task_systemd_unit"]["start_gate"] = self._power_gate(
            self.tmp.name,
            generated_at_unix=1,
        )
        start = self._root_task_reference({
            "operation": "start",
            "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            "argv": ["/usr/local/bin/sleep-heimserver"],
            "cwd": "/",
            "runtime_seconds": 300,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "description": "Grabowski task root",
        })
        parsed_start = privileged_broker.parse_reference(
            json.dumps(start).encode("utf-8"), now=1000
        )
        with self.assertRaisesRegex(PermissionError, "stale"):
            privileged_broker.resolve_execution(config, parsed_start)

        show = self._root_task_reference({
            "operation": "show",
            "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            "properties": ["LoadState", "ActiveState", "Result"],
        })
        parsed_show = privileged_broker.parse_reference(
            json.dumps(show).encode("utf-8"), now=1000
        )
        execution = privileged_broker.resolve_execution(config, parsed_show)
        self.assertEqual(execution["operation"], "show")
        self.assertNotIn("gate", execution)

    def test_root_task_show_resolves_to_system_scope_only(self) -> None:
        unit = "grabowski-task-0123456789abcdef01234567-a1.service"
        reference = self._root_task_reference({
            "operation": "show",
            "unit": unit,
            "properties": ["LoadState", "ActiveState", "Result"],
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        argv, timeout = privileged_broker.resolve_action(self._root_task_config(), parsed)

        self.assertEqual(timeout, 15)
        self.assertEqual(
            argv,
            [
                "/usr/bin/systemctl", "--system", "show", unit, "--no-pager",
                "--property=LoadState", "--property=ActiveState", "--property=Result",
            ],
        )
        self.assertNotIn("--user", argv)

    def test_root_task_journal_uses_bounded_read_timeout(self) -> None:
        unit = "grabowski-task-0123456789abcdef01234567-a1.service"
        reference = self._root_task_reference({
            "operation": "journal",
            "unit": unit,
            "max_lines": 200,
        })
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        execution = privileged_broker.resolve_execution(
            self._root_task_config(), parsed
        )

        self.assertEqual(execution["timeout_seconds"], 30)
        self.assertEqual(execution["configured_timeout_seconds"], 60)
        self.assertEqual(execution["operation_timeout_cap_seconds"], 30)
        self.assertEqual(
            execution["argv"],
            [
                "/usr/bin/journalctl", "--system", "--unit", unit,
                "--no-pager", "--output=cat", "--lines", "200",
            ],
        )

    def _power_gate(
        self,
        directory: str | Path,
        *,
        generated_at_unix: int | None = None,
        max_age_seconds: int = 86400,
        target: str = "heimberry:rest-server/grabowski-recovery-probe",
    ) -> dict[str, object]:
        root = Path(directory)
        marker = root / "recovery-gate.json"
        marker.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "kind": "grabowski_recovery_freshness",
                    "generated_at_unix": int(time.time()) if generated_at_unix is None else generated_at_unix,
                    "max_age_seconds": max_age_seconds,
                    "snapshot_id": "abc12345",
                    "restore_probe_valid": True,
                    "repository_check_valid": True,
                    "target": target,
                    "configured_target": target,
                    "configured_target_valid": True,
                    "target_matches_configured": True,
                    "source_record_sha256": "a" * 64,
                    "source_owner_uid": os.getuid(),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        marker.chmod(0o600)
        return {
            "kill_switch_path": str(root / "operator-kill-switch"),
            "recovery_marker_path": str(marker),
            "max_recovery_age_seconds": max_age_seconds,
            "require_root_owned_gate_files": False,
            "configured_target": target,
        }

    def _power_reference(self, payload: dict[str, object], now: int = 1000) -> dict[str, object]:
        value = self._reference(now=now)
        value["action"] = "operator_power_argv"
        value["target"] = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        value["justification"] = "Run one recovery-gated operator power command"
        value.pop("reference_sha256")
        value["reference_sha256"] = privileged_broker.canonical_sha256(value)
        return value

    def test_power_argv_json_action_resolves_without_shell(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/id", "-u"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        execution = privileged_broker.resolve_execution(config, parsed)
        self.assertEqual(execution["mode"], "argv-json")
        self.assertEqual(execution["argv"], ["/usr/bin/id", "-u"])
        self.assertEqual(execution["cwd"], "/")
        argv, timeout = privileged_broker.resolve_action(config, parsed)
        self.assertEqual(argv, ["/usr/bin/id", "-u"])
        self.assertEqual(timeout, 30)

    def test_power_gate_opens_marker_with_file_descriptor_checks(self) -> None:
        source = (ROOT / "src" / "grabowski_privileged_broker.py").read_text(encoding="utf-8")
        self.assertIn("os.open(path, flags)", source)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', source)
        self.assertIn("before = os.fstat(descriptor)", source)
        self.assertIn("chunk = os.read(descriptor", source)
        self.assertNotIn("raw = path.read_bytes()", source)

    def test_power_argv_json_missing_recovery_marker_is_handled_denial(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/id", "-u"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        gate = self._power_gate(self.tmp.name)
        Path(gate["recovery_marker_path"]).unlink()
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "gate": gate,
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "recovery marker does not exist"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_argv_json_requires_fresh_root_side_gate(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/id", "-u"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        gate = self._power_gate(self.tmp.name)
        Path(gate["kill_switch_path"]).write_text("stop", encoding="utf-8")
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "gate": gate,
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "kill-switch"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_argv_json_rejects_shell_when_disabled(self) -> None:
        reference = self._power_reference({"argv": ["/bin/bash", "-lc", "id"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "shell"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_argv_json_allows_cataloged_admin_prefix(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/systemctl", "is-active", "grabowski-privileged-broker.socket"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "policy_intent": "trusted-owner-high-power-admin-catalog",
                    "allowed_argv_prefixes": [
                        ["/usr/bin/systemctl", "is-active"],
                        ["/usr/bin/systemctl", "status"],
                    ],
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        execution = privileged_broker.resolve_execution(config, parsed)

        self.assertEqual(execution["argv"], ["/usr/bin/systemctl", "is-active", "grabowski-privileged-broker.socket"])
        self.assertEqual(execution["policy_intent"], "trusted-owner-high-power-admin-catalog")
        self.assertEqual(
            execution["argv_catalog_sha256"],
            privileged_broker.canonical_sha256([
                ["/usr/bin/systemctl", "is-active"],
                ["/usr/bin/systemctl", "status"],
            ]),
        )
        self.assertEqual(
            execution["matched_argv_prefix_sha256"],
            privileged_broker.canonical_sha256(["/usr/bin/systemctl", "is-active"]),
        )

    def test_power_argv_json_rejects_prefix_longer_than_max_argv(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/systemctl", "is-active"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 1,
                    "allow_shell": False,
                    "allowed_argv_prefixes": [["/usr/bin/systemctl", "is-active"]],
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        with self.assertRaisesRegex(ValueError, "power argv exceeds item limit"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_argv_json_rejects_uncataloged_admin_command(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/systemctl", "restart", "grabowski-mcp.service"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "allowed_argv_prefixes": [["/usr/bin/systemctl", "is-active"]],
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "configured catalog"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_argv_json_rejects_shell_prefix_in_catalog_when_shell_disabled(self) -> None:
        reference = self._power_reference({"argv": ["/usr/bin/id", "-u"], "cwd": "/", "timeout_seconds": 30})
        parsed = privileged_broker.parse_reference(
            json.dumps(reference).encode("utf-8"), now=1000
        )
        config = {
            "schema_version": 2,
            "actions": {
                "operator_power_argv": {
                    "enabled": True,
                    "mode": "argv-json",
                    "target_pattern": r"\{.{1,49152}\}",
                    "cwd_pattern": r"/[A-Za-z0-9._/@:+-]{0,999}",
                    "timeout_seconds": 600,
                    "max_argv": 128,
                    "allow_shell": False,
                    "allowed_argv_prefixes": [["/bin/bash", "-lc"]],
                    "gate": self._power_gate(self.tmp.name),
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "shell"):
            privileged_broker.resolve_execution(config, parsed)

    def test_power_run_tool_builds_reference_and_requires_recovery(self) -> None:
        class Completed:
            returncode = 0
            stdout = json.dumps({
                "returncode": 0,
                "stdout": "uid=0(root)\n",
                "stderr": "",
                "audit": {"request_id": "x" * 32},
            }).encode("utf-8")
            stderr = b""

        with tempfile.TemporaryDirectory() as directory:
            reference_dir = Path(directory)
            captured: dict[str, object] = {}

            def fake_run(argv: list[str], **kwargs: object) -> Completed:
                captured["argv"] = argv
                reference_path = Path(argv[1])
                captured["reference"] = json.loads(reference_path.read_text(encoding="utf-8"))
                return Completed()

            with patch.object(privileged, "POWER_REFERENCE_DIR", reference_dir), patch.object(
                privileged.operator, "_require_operator_mutation"
            ), patch.object(
                privileged, "grabowski_privileged_broker_status",
                return_value={"ready": True, "request_client": "/usr/local/bin/grabowski-privileged-request"},
            ), patch.object(
                privileged, "_power_recovery_status",
                return_value={
                    "ready_for_user_power_worker": True,
                    "ready_for_privileged_actions": True,
                    "checked_at_unix": 1000,
                },
            ), patch.object(privileged.subprocess, "run", side_effect=fake_run), patch.object(
                privileged.operator.base, "_append_audit"
            ) as append_audit:
                result = privileged.grabowski_power_run(
                    ["/usr/bin/id", "-u"],
                    cwd="/",
                    timeout_seconds=30,
                    justification="Check root identity for operator maintenance",
                )

            self.assertTrue(result["success"])
            self.assertEqual(captured["argv"][0], "/usr/local/bin/grabowski-privileged-request")
            reference = captured["reference"]
            self.assertEqual(reference["action"], "operator_power_argv")
            self.assertEqual(reference["execution"], "unprivileged-reference-only")
            target = json.loads(reference["target"])
            self.assertEqual(target, {"argv": ["/usr/bin/id", "-u"], "cwd": "/", "timeout_seconds": 30})
            append_audit.assert_called_once()
            self.assertEqual(list(reference_dir.glob("*.json")), [])

    def test_tamper_expiry_disable_and_replay_fail_closed(self) -> None:
        reference = self._reference()
        reference["target"] = "other.service"
        with self.assertRaisesRegex(ValueError, "hash"):
            privileged_broker.parse_reference(
                json.dumps(reference).encode("utf-8"), now=1000
            )
        expired = self._reference()
        with self.assertRaisesRegex(PermissionError, "currently valid"):
            privileged_broker.parse_reference(
                json.dumps(expired).encode("utf-8"), now=2000
            )
        valid = self._reference()
        parsed = privileged_broker.parse_reference(
            json.dumps(valid).encode("utf-8"), now=1000
        )
        disabled = {
            "schema_version": 1,
            "actions": {
                "edit_system_service": {
                    "enabled": False,
                    "target_pattern": ".*",
                    "argv": ["/usr/bin/false", "{target}"],
                    "timeout_seconds": 1,
                }
            },
        }
        with self.assertRaisesRegex(PermissionError, "disabled"):
            privileged_broker.resolve_action(disabled, parsed)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            privileged_broker.claim_once(state, "b" * 32)
            with self.assertRaises(FileExistsError):
                privileged_broker.claim_once(state, "b" * 32)


class PrivilegedAndConnectorTests(unittest.TestCase):
    def test_systemd_socket_contract_is_rooted_and_group_bounded(self) -> None:
        socket_unit = (ROOT / "systemd" / "grabowski-privileged-broker.socket").read_text(encoding="utf-8")
        service_unit = (ROOT / "systemd" / "grabowski-privileged-broker@.service").read_text(encoding="utf-8")
        tmpfiles = (ROOT / "tmpfiles" / "grabowski.conf").read_text(encoding="utf-8")
        self.assertIn("Accept=yes", socket_unit)
        self.assertIn("SocketGroup=grabowski", socket_unit)
        self.assertIn("SocketMode=0660", socket_unit)
        self.assertEqual(tmpfiles, "d /run/grabowski 0750 root grabowski -\n")
        self.assertIn("User=root", service_unit)
        self.assertIn("StandardInput=socket", service_unit)
        self.assertIn("NoNewPrivileges=yes", service_unit)
        self.assertIn("ProtectHome=tmpfs", service_unit)
        self.assertIn(
            "BindReadOnlyPaths=-/home/alex/.local/state/grabowski/recovery/last-server-recovery.json",
            service_unit,
        )
        self.assertIn(
            "BindReadOnlyPaths=-/home/alex/.local/state/grabowski/operator-kill-switch",
            service_unit,
        )
        self.assertNotIn("ProtectHome=yes", service_unit)
        self.assertIn("ExecStart=/usr/local/libexec/grabowski-privileged-broker", service_unit)
        self.assertNotIn("SuccessExitStatus=", service_unit)

    def test_broker_script_uses_utf8_audit_hash_and_process_group_timeout(self) -> None:
        broker = (ROOT / "tools" / "grabowski_privileged_broker.py").read_text(encoding="utf-8")
        self.assertIn('json.dumps(argv, ensure_ascii=False, separators=(",", ":"))', broker)
        self.assertIn("start_new_session=True", broker)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", broker)

    def test_broker_audit_records_power_catalog_metadata(self) -> None:
        broker = (ROOT / "tools" / "grabowski_privileged_broker.py").read_text(encoding="utf-8")
        self.assertIn('"policy_intent"', broker)
        self.assertIn('"argv_catalog_sha256"', broker)
        self.assertIn('"matched_argv_prefix_sha256"', broker)

    def test_broker_script_keeps_structured_denials_out_of_systemd_failed_state(self) -> None:
        broker = (ROOT / "tools" / "grabowski_privileged_broker.py").read_text(encoding="utf-8")
        self.assertIn("return 0\n\n\nif __name__ ==", broker)
        self.assertIn("except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:", broker)
        self.assertIn("raise SystemExit(0)", broker)
        self.assertIn("except Exception as exc:", broker)
        self.assertIn("raise SystemExit(2)", broker)

    def test_recovery_publication_timeout_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(privileged, "POWER_REFERENCE_DIR", root), patch.object(
                privileged,
                "grabowski_privileged_broker_status",
                return_value={"ready": True, "request_client": "/usr/local/bin/grabowski-privileged-request"},
            ), patch.object(
                privileged.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(
                    cmd=["grabowski-privileged-request"],
                    timeout=45,
                    stderr=b"broker stalled",
                ),
            ), patch.object(privileged, "_append_operator_audit") as append_audit:
                result = privileged.publish_recovery_marker_reference(
                    source_record_sha256="a" * 64,
                    generated_at_unix=123,
                )

            self.assertFalse(result["success"])
            self.assertTrue(result["broker_client_timed_out"])
            self.assertIsNone(result["broker_client_returncode"])
            self.assertEqual(result["failure_reason"], "privileged broker client timed out")
            self.assertEqual(list(root.iterdir()), [])
            append_audit.assert_called_once()
            self.assertTrue(append_audit.call_args.args[0]["broker_client_timed_out"])

    def test_root_task_garbage_broker_response_is_outcome_unknown(self) -> None:
        invoked = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "broker_client_returncode": 0,
            "broker_client_timed_out": False,
            "broker_response": None,
            "stdout": "not-json",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        with patch.object(
            privileged, "_invoke_privileged_reference", return_value=invoked
        ):
            result = privileged.root_task_systemd_request({
                "operation": "show",
                "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
                "properties": ["LoadState"],
            })

        self.assertTrue(result["outcome_unknown"])
        self.assertFalse(result["root_truth_observable"])
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["stdout"], "not-json")

    def test_missing_operator_audit_backend_fails_explicitly(self) -> None:
        with patch.object(privileged.operator, "base", None):
            with self.assertRaisesRegex(RuntimeError, "audit backend"):
                privileged._append_operator_audit({"operation": "test"})

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

        runtime_schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string", "title": "Path"},
                "expected_sha256": {"type": "string"},
                "max_bytes": {
                    "anyOf": [{"type": "integer"}, {"type": "null"}],
                    "default": None,
                },
                "justification": {"type": "string", "default": ""},
                "acknowledge_context_exposure": {
                    "type": "boolean",
                    "default": False,
                },
            },
            "required": ["path", "expected_sha256"],
        }
        runtime_tools = [
            {
                "name": name,
                **(
                    {"inputSchema": runtime_schema}
                    if name == "grabowski_secret_reveal"
                    else {}
                ),
            }
            for name in expected
        ]
        current = module.probe(
            expected,
            {"grabowski_secret_reveal": runtime_schema},
            runtime_tools,
        )
        self.assertTrue(current["matches"])
        self.assertTrue(current["schema_contract_matches"])

        stale_schema = json.loads(json.dumps(runtime_schema))
        del stale_schema["properties"]["justification"]
        del stale_schema["properties"]["acknowledge_context_exposure"]
        stale = module.probe(
            expected,
            {"grabowski_secret_reveal": stale_schema},
            runtime_tools,
        )
        self.assertFalse(stale["matches"])
        self.assertFalse(stale["schema_contract_matches"])
        self.assertEqual(
            stale["schema_mismatches"][0]["tool"],
            "grabowski_secret_reveal",
        )

        names_only = module.probe(expected, {}, runtime_tools)
        self.assertFalse(names_only["matches"])
        self.assertEqual(
            names_only["missing_schema_sentinels"],
            ["grabowski_secret_reveal"],
        )


if __name__ == "__main__":
    unittest.main()
