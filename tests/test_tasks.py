from __future__ import annotations

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
        self.db_patch.start()

    def tearDown(self) -> None:
        self.db_patch.stop()
        self.temporary.cleanup()

    def _start(self, *, host: str = "local") -> dict[str, object]:
        selected = LOCAL_HOST if host == "local" else REMOTE_HOST
        with patch.object(tasks.fleet, "fleet_host", return_value=selected), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ) as dispatch, patch.object(tasks.base, "_append_audit"):
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
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="manual",
            )
        with self.assertRaisesRegex(PermissionError, "does not permit"):
            tasks.grabowski_task_resume(started["task"]["task_id"])

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
        ):
            self.assertIn(tool, expected)


if __name__ == "__main__":
    unittest.main()
