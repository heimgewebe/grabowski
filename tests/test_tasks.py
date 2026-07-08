from __future__ import annotations

import io
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
import grabowski_task_reconcile as task_reconcile_cli


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
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski task grabowski-task-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
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
        self.assertFalse(task["chronik_outbox_enabled"])
        self.assertIsNone(task["chronik_outbox_state_root"])
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])

    def test_start_chronik_outbox_opt_in_writes_without_global_env(self) -> None:
        outbox_root = self.root / "chronik-state"
        with patch.dict(
            "os.environ",
            {
                tasks.chronik.ENABLED_ENV: "",
                tasks.chronik.STATE_ROOT_ENV: "",
            },
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 140}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                chronik_outbox=True,
                chronik_outbox_state_root=str(outbox_root),
            )
        task = result["task"]
        self.assertTrue(task["chronik_outbox_enabled"])
        self.assertEqual(task["chronik_outbox_state_root"], str(outbox_root))
        files = sorted(outbox_root.rglob("*.jsonl"))
        self.assertEqual(len(files), 1)
        event = json.loads(files[0].read_text().splitlines()[0])
        self.assertEqual(event["kind"], "agent.run.started")

    def test_start_rejects_chronik_state_root_without_opt_in(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "requires chronik_outbox"):
                tasks.grabowski_task_start(
                    "local",
                    ["/bin/true"],
                    cwd=str(self.root),
                    runtime_seconds=60,
                    chronik_outbox_state_root=str(self.root / "chronik-state"),
                )

    def test_collected_success_unit_maps_to_completed_not_unknown(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=probe):
            status = tasks.grabowski_task_status(task_id)
        self.assertEqual(status["state"], "completed")
        receipt = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        self.assertTrue(receipt.is_file())
        payload = json.loads(receipt.read_text())
        self.assertEqual(payload["state"], "completed")
        self.assertIn("receipt_sha256", payload)

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

    def test_missing_unit_is_outcome_unknown_and_can_resume_manually(self) -> None:
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
        self.assertEqual(task["last_observation"]["state"], "outcome_unknown")

    def test_reconcile_observer_falls_back_to_narrow_production_probe(self) -> None:
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        observed = {
            "host": "wg-prod-1",
            "transport": "ssh",
            "roles": ["vps", "production"],
            "observer": "task-systemd-user-show-v1",
            "result": probe,
        }
        with patch.object(
            tasks,
            "_dispatch",
            side_effect=tasks.fleet.FleetCommandDenied("Executable is not allowed for fleet host wg-prod-1: systemctl"),
        ), patch.object(
            tasks.fleet, "run_fleet_task_unit_show", return_value=observed
        ) as show:
            result = tasks._observe({
                "host": "wg-prod-1",
                "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            })
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["observer"]["kind"], "task-systemd-user-show-v1")
        self.assertEqual(
            result["observer"]["fallback_from"],
            "fleet-dispatch-permission-denied",
        )
        show.assert_called_once()

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

    def test_legacy_reconcile_auto_resume_is_disabled_compatibility_path(self) -> None:
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
        self.assertTrue(result["legacy_auto_resume_disabled"])
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertIn("outcome_unknown", result["blocked"][0]["reason"])
        self.assertTrue(
            all(
                "legacy auto_resume reconcile is disabled" in item["reason"]
                for item in result["blocked"][1:]
            )
        )
        self.assertIsNone(tasks.resources.inspect_resource("display:12"))

    def test_reconcile_resume_blocks_unverified_policy(self) -> None:
        started = self._start()
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing):
            result = tasks.reconcile_tasks_resume(
                reason="test unsafe policy block", max_resumes=1
            )
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertEqual(
            result["blocked"][0]["resume_policy"], "verify-then-retry"
        )

    def test_reconcile_check_is_read_only_preview(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 140}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["service:preview.service"],
            )
        task = started["task"]
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing):
            result = tasks.reconcile_tasks_check()
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["would_release"], [task["task_id"]])
        self.assertEqual(result["would_resume"], [])
        self.assertIn("outcome_unknown", result["blocked"][0]["reason"])
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["tasks"][0]["state"], "running")
        self.assertIsNotNone(tasks.resources.inspect_resource("service:preview.service"))

    def test_reconcile_refresh_does_not_resume_processes(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["service:refresh.service"],
            )
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing) as dispatch:
            result = tasks.reconcile_tasks_refresh()
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["released"], [started["task"]["task_id"]])
        self.assertEqual(result["refreshed"][0]["state"], "outcome_unknown")
        self.assertIsNone(tasks.resources.inspect_resource("service:refresh.service"))

    def test_reconcile_resume_requires_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "reason is required"):
            tasks.reconcile_tasks_resume()

    def test_reconcile_cli_check_mode_is_read_only(self) -> None:
        preview = {"mode": "check", "scanned": 0}
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_check",
                return_value=preview,
            ) as check,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_refresh"
            ) as refresh,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_resume"
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print") as output,
        ):
            self.assertEqual(task_reconcile_cli.main(["--mode", "check"]), 0)
        check.assert_called_once_with(task_id="")
        refresh.assert_not_called()
        resume.assert_not_called()
        audit.assert_not_called()
        self.assertIn('"mode": "check"', output.call_args.args[0])

    def test_reconcile_cli_refresh_does_not_resume_processes(self) -> None:
        task_id = "a" * 24
        refreshed = {"mode": "refresh", "scanned": 0}
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_refresh",
                return_value=refreshed,
            ) as refresh,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_resume"
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print"),
        ):
            self.assertEqual(
                task_reconcile_cli.main(["--mode", "refresh", "--task-id", task_id]),
                0,
            )
        refresh.assert_called_once_with(task_id=task_id)
        resume.assert_not_called()
        audit.assert_not_called()

    def test_reconcile_cli_resume_requires_reason(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main(["--mode", "resume"])
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_resume_bounds_max_resumes(self) -> None:
        for value in ("0", "51"):
            with self.subTest(value=value):
                with patch("sys.stderr", new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as raised:
                        task_reconcile_cli.main(
                            [
                                "--mode",
                                "resume",
                                "--reason",
                                "bounded test",
                                "--max-resumes",
                                value,
                            ]
                        )
                self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_rejects_legacy_auto_resume(self) -> None:
        legacy = "--auto-" + "resume"
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main([legacy])
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_rejects_unsupported_expected_state_hash(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main(
                    [
                        "--mode",
                        "resume",
                        "--reason",
                        "precondition test",
                        "--expected-state-hash",
                        "a" * 64,
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_resume_is_explicit_bounded_and_audited(self) -> None:
        result = {
            "mode": "resume",
            "task_id": "",
            "max_resumes": 2,
            "reason": "operator proof",
            "scanned": 2,
            "refreshed": [],
            "released": [],
            "resumed": [{"task_id": "a" * 24}],
            "blocked": [{"task_id": "b" * 24}],
            "checked_at_unix": 1234,
        }
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_resume",
                return_value=result,
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print"),
        ):
            self.assertEqual(
                task_reconcile_cli.main(
                    [
                        "--mode",
                        "resume",
                        "--reason",
                        "operator proof",
                        "--max-resumes",
                        "2",
                    ]
                ),
                0,
            )
        resume.assert_called_once_with(
            task_id="", max_resumes=2, reason="operator proof"
        )
        audit.assert_called_once()
        audit_record = audit.call_args.args[0]
        self.assertEqual(audit_record["mode"], "resume")
        self.assertEqual(audit_record["reason"], "operator proof")
        self.assertEqual(audit_record["max_resumes"], 2)
        self.assertEqual(audit_record["resumed_count"], 1)
        self.assertEqual(audit_record["blocked_count"], 1)

    def test_reconcile_does_not_resume_completed_tasks(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 142}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
            )
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=completed):
            result = tasks.reconcile_tasks_resume(
                reason="test completed no-resume", max_resumes=1
            )
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertIn("completed", result["blocked"][0]["reason"])

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
        self.assertIn("chronik_outbox_enabled", columns)
        self.assertIn("chronik_outbox_state_root", columns)

    def test_database_rejects_symlink(self) -> None:
        target = self.root / "real.sqlite3"
        target.write_bytes(b"")
        self.database.parent.mkdir(parents=True)
        self.database.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            tasks.grabowski_task_list()


class RuntimeContractTests(unittest.TestCase):
    def test_reconcile_service_example_uses_refresh_not_resume(self) -> None:
        source = (
            ROOT / "systemd" / "grabowski-reconcile-tasks.service.example"
        ).read_text(encoding="utf-8")
        legacy = "--auto-" + "resume"
        self.assertNotIn(legacy, source)
        self.assertIn("--mode refresh", source)
        self.assertNotIn("--mode resume", source)

    def test_runtime_registers_control_plane_and_tasks(self) -> None:
        source = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        for module in (
            "grabowski_fleet",
            "grabowski_operations",
            "grabowski_privileged",
            "grabowski_tasks",
            "grabowski_resources",
            "grabowski_checkouts",
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
            "grabowski_task_reconcile_check",
            "grabowski_task_reconcile_refresh",
            "grabowski_task_reconcile_resume",
            "grabowski_task_reconcile",
            "grabowski_resource_acquire",
            "grabowski_resource_renew",
            "grabowski_resource_release",
            "grabowski_resource_inspect",
            "grabowski_resource_list",
            "grabowski_checkout_inventory",
            "grabowski_checkout_retain",
            "grabowski_checkout_archive",
            "grabowski_checkout_cleanup",
        ):
            self.assertIn(tool, expected)


if __name__ == "__main__":
    unittest.main()
