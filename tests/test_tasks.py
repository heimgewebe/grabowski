from __future__ import annotations

import json
import sqlite3
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


import grabowski_tasks as tasks


LOCAL_HOST = {
    "transport": "local",
    "target": "local",
    "enabled": True,
    "roles": ["test"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}
REMOTE_HOST = {
    "transport": "ssh",
    "target": "remote",
    "enabled": True,
    "roles": ["worker"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}


def _launcher(returncode: int = 0) -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }


class TaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "tasks.sqlite3"
        self.db_patch = patch.object(tasks, "TASK_DB", self.database)
        self.resource_database = self.root / "state" / "resources.sqlite3"
        self.resource_patch = patch.object(
            tasks.resources, "RESOURCE_DB", self.resource_database
        )
        self.db_patch.start()
        self.resource_patch.start()

    def tearDown(self) -> None:
        self.resource_patch.stop()
        self.db_patch.stop()
        self.temporary.cleanup()

    def _start(self, *, host: str = "local") -> dict[str, object]:
        selected = LOCAL_HOST if host == "local" else REMOTE_HOST
        with patch.object(tasks.fleet, "fleet_host", return_value=selected), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ) as dispatch, patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
        ):
            result = tasks.grabowski_task_start(
                host,
                ["/bin/echo", "ok"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="verify-then-retry",
                cpu_weight=50,
                io_weight=25,
                memory_max_bytes=64 * 1024 * 1024,
            )
        launch = dispatch.call_args.args[1]
        self.assertIn("--slice=grabowski-tasks.slice", launch)
        self.assertIn("--property=CPUWeight=50", launch)
        self.assertIn("--property=IOWeight=25", launch)
        self.assertIn("--property=MemoryMax=67108864", launch)
        self.assertIn("--property=NoNewPrivileges=no", launch)
        self.assertIn("--property=ProtectHome=no", launch)
        self.assertIn("--property=MemoryDenyWriteExecute=no", launch)
        self.assertIn("--property=UMask=0077", launch)
        self.assertEqual(launch[-3:], ["--", "/bin/echo", "ok"])
        return result

    def test_start_persists_auditable_record(self) -> None:
        result = self._start()
        task = result["task"]
        self.assertEqual(task["state"], "running")
        self.assertEqual(task["attempt"], 1)
        self.assertEqual(task["host"], "local")
        self.assertEqual(task["argv"], ["/bin/echo", "ok"])
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])

    def test_status_maps_successful_inactive_unit_to_completed(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=1\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=probe):
            status = tasks.grabowski_task_status(task_id)
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["last_observation"]["properties"]["Result"], "success")

    def test_missing_unit_is_interrupted_and_can_resume(self) -> None:
        started = self._start(host="remote")
        task_id = started["task"]["task_id"]
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", side_effect=[missing, _launcher()]), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            resumed = tasks.grabowski_task_resume(task_id)
        task = resumed["task"]
        self.assertEqual(task["attempt"], 2)
        self.assertEqual(task["state"], "running")
        self.assertTrue(task["unit"].endswith("-a2.service"))
        self.assertEqual(task["last_observation"]["state"], "interrupted")

    def test_manual_resume_policy_fails_closed(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="manual",
            )
        with self.assertRaisesRegex(PermissionError, "does not permit"):
            tasks.grabowski_task_resume(started["task"]["task_id"])

    def test_ordinary_task_does_not_depend_on_recovery_evidence(self) -> None:
        with patch.object(tasks.recovery, "recovery_status", side_effect=AssertionError("unexpected recovery probe")), patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ):
            result = tasks.grabowski_task_start(
                "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["state"], "running")
        self.assertFalse(result["audit"]["recovery_required"])
        self.assertIsNone(result["audit"]["recovery_checked_at_unix"])

    def test_power_worker_fails_closed_when_recovery_is_not_ready(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": False,
                "required_actions": ["produce recovery evidence"],
            },
        ):
            with self.assertRaisesRegex(PermissionError, "recovery gate"):
                tasks.grabowski_task_start(
                    "local", ["/usr/local/bin/sleep-heimserver"], cwd=str(self.root)
                )


    def test_task_resource_lease_is_released_after_completion(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 130}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=["port:9222"],
            )
        task = started["task"]
        lease = tasks.resources.inspect_resource("port:9222")
        self.assertEqual(lease["owner_id"], task["lease_owner_id"])
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=completed):
            status = tasks.grabowski_task_status(task["task_id"])
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(tasks.resources.inspect_resource("port:9222"))

    def test_launch_failure_releases_task_resource_lease(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher(returncode=1)
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 131}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/false"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=["service:example.service"],
            )
        self.assertEqual(result["task"]["state"], "failed")
        self.assertIsNone(
            tasks.resources.inspect_resource("service:example.service")
        )

    def test_reconcile_auto_resumes_only_retry_safe(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 132}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["display:12"],
            )
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(
            tasks, "_dispatch", side_effect=[missing, missing, _launcher()]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 133}
        ):
            result = tasks.reconcile_tasks(auto_resume=True)
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(len(result["resumed"]), 1)
        self.assertEqual(result["resumed"][0]["attempt"], 2)
        self.assertEqual(result["resumed"][0]["state"], "running")
        self.assertEqual(
            tasks.resources.inspect_resource("display:12")["owner_id"],
            started["task"]["lease_owner_id"],
        )

    def test_reconcile_blocks_unverified_policy(self) -> None:
        started = self._start()
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing):
            result = tasks.reconcile_tasks(auto_resume=True)
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertEqual(
            result["blocked"][0]["resume_policy"], "verify-then-retry"
        )

    def test_schema_v1_database_migrates_without_losing_records(self) -> None:
        self.database.parent.mkdir(parents=True)
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO metadata(key, value) VALUES('schema_version', '1');
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY, host TEXT NOT NULL, unit TEXT NOT NULL,
                attempt INTEGER NOT NULL, state TEXT NOT NULL, resume_policy TEXT NOT NULL,
                argv_json TEXT NOT NULL, argv_sha256 TEXT NOT NULL, cwd TEXT NOT NULL,
                runtime_seconds INTEGER NOT NULL, cpu_weight INTEGER NOT NULL,
                io_weight INTEGER NOT NULL, memory_max_bytes INTEGER,
                created_at_unix INTEGER NOT NULL, updated_at_unix INTEGER NOT NULL,
                launcher_json TEXT NOT NULL, last_observation_json TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO tasks VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "a" * 24, "local", f"grabowski-task-{'a' * 24}-a1.service",
                1, "interrupted", "manual", '["/bin/true"]', "b" * 64,
                str(self.root), 60, 100, 100, None, 1, 1, '{}', None,
            ),
        )
        connection.commit()
        connection.close()
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["resource_keys"], [])
        with sqlite3.connect(self.database) as migrated:
            version = migrated.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(tasks)")}
        self.assertEqual(version, "2")
        self.assertIn("resource_keys_json", columns)
        self.assertIn("lease_owner_id", columns)

    def test_database_rejects_symlink(self) -> None:
        target = self.root / "real.sqlite3"
        target.write_bytes(b"")
        self.database.parent.mkdir(parents=True)
        self.database.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            tasks.grabowski_task_list()


class RuntimeContractTests(unittest.TestCase):
    def test_runtime_registers_control_plane_and_tasks(self) -> None:
        source = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        for module in (
            "grabowski_fleet",
            "grabowski_operations",
            "grabowski_privileged",
            "grabowski_tasks",
            "grabowski_resources",
            "grabowski_artifacts",
            "grabowski_workers",
        ):
            self.assertIn(f"import {module}", source)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        expected = set(contract["expected_tools"])
        for tool in (
            "grabowski_fleet_list",
            "grabowski_fleet_run",
            "grabowski_operation_list",
            "grabowski_operation_plan",
            "grabowski_operation_run",
            "grabowski_privileged_broker_status",
            "grabowski_task_start",
            "grabowski_task_status",
            "grabowski_task_logs",
            "grabowski_task_cancel",
            "grabowski_task_resume",
            "grabowski_task_list",
            "grabowski_task_reconcile",
            "grabowski_resource_acquire",
            "grabowski_resource_renew",
            "grabowski_resource_release",
            "grabowski_resource_inspect",
            "grabowski_resource_list",
        ):
            self.assertIn(tool, expected)


if __name__ == "__main__":
    unittest.main()
