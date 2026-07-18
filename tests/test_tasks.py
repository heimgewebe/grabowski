from __future__ import annotations

from contextlib import contextmanager
import io
import json
import os
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


import grabowski_command_identity as command_identity
import grabowski_resources as resources
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
        (self.root / ".git").write_text("gitdir: /tmp/test-worktree\n")
        self.database = self.root / "state" / "tasks.sqlite3"
        self.db_patch = patch.object(tasks, "TASK_DB", self.database)
        self.outcomes_patch = patch.object(
            tasks,
            "TASK_OUTCOMES_DIR",
            self.database.with_suffix(".outcomes"),
        )
        self.resource_database = self.root / "state" / "resources.sqlite3"
        self.resource_patch = patch.object(
            tasks.resources, "RESOURCE_DB", self.resource_database
        )
        self.db_patch.start()
        self.outcomes_patch.start()
        self.resource_patch.start()

    def tearDown(self) -> None:
        self.resource_patch.stop()
        self.outcomes_patch.stop()
        self.db_patch.stop()
        self.temporary.cleanup()

    def _start(
        self,
        *,
        host: str = "local",
        resource_keys: list[str] | None = None,
    ) -> dict[str, object]:
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
                resource_keys=resource_keys,
            )
        launch = dispatch.call_args.args[1]
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski task grabowski-task-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
        self.assertIn("--slice=grabowski-tasks.slice", launch)
        self.assertEqual(launch.count("--property=LimitCORE=0"), 1)
        self.assertIn("--property=CPUWeight=50", launch)
        self.assertIn("--property=IOWeight=25", launch)
        self.assertIn("--property=MemoryMax=67108864", launch)
        self.assertIn("--property=NoNewPrivileges=no", launch)
        self.assertIn("--property=ProtectHome=no", launch)
        self.assertIn("--property=MemoryDenyWriteExecute=no", launch)
        self.assertIn("--property=UMask=0077", launch)
        self.assertEqual(launch[-3:], ["--", "/bin/echo", "ok"])
        return result

    def test_server_task_lease_delegation_requires_running_task_and_live_leases(self) -> None:
        result = self._start(resource_keys=["component:test-task-delegation"])
        task = result["task"]
        owner = task["lease_owner_id"]

        evidence = tasks.server_task_lease_delegation_evidence(owner)

        self.assertEqual(task["task_id"], evidence["task_id"])
        self.assertEqual(owner, evidence["lease_owner_id"])
        self.assertEqual("running", evidence["state"])
        self.assertEqual(task["resource_keys"], evidence["resource_keys"])
        self.assertRegex(evidence["task_record_sha256"], r"[0-9a-f]{64}\Z")

        tasks._set_state(task["task_id"], "completed")
        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(owner)

    def test_terminalization_atomically_revokes_owner_leases_and_binds_lifecycle_receipt(self) -> None:
        result = self._start(
            resource_keys=[
                "component:test-terminalization-a",
                "service:test-terminalization-b",
            ]
        )
        task = result["task"]
        task_id = task["task_id"]
        owner = task["lease_owner_id"]
        resources.acquire_resources(
            owner,
            ["component:test-terminalization-late"],
            purpose="late owner-bound task lease",
            ttl_seconds=120,
            metadata={"task_id": task_id, "attempt": 1},
        )
        observation = {"state": "completed", "source": "unit-test"}

        stored = tasks._set_state(
            task_id,
            "completed",
            observation=observation,
        )

        self.assertEqual("completed", stored["state"])
        transition = resources.task_terminalization_record(task_id)
        self.assertIsNotNone(transition)
        self.assertEqual("projected", transition["phase"])
        self.assertEqual(
            sorted(
                [
                    "component:test-terminalization-a",
                    "component:test-terminalization-late",
                    "service:test-terminalization-b",
                ]
            ),
            transition["revoked_resource_keys"],
        )
        self.assertEqual([], resources.list_resources(owner_id=owner))
        self.assertEqual(
            transition["transition_sha256"], stored["terminalization_sha256"]
        )
        receipt_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(2, payload["schema_version"])
        self.assertEqual("grabowski_task_lifecycle_receipt", payload["kind"])
        self.assertEqual(
            transition["transition_sha256"],
            payload["terminalization"]["transition_sha256"],
        )
        self.assertEqual(payload["receipt_sha256"], stored["lifecycle_receipt_sha256"])
        self.assertEqual(payload["receipt_sha256"], transition["lifecycle_receipt_sha256"])
        with self.assertRaisesRegex(ValueError, "terminalized task owner"):
            resources.acquire_resources(
                owner,
                ["component:test-terminalization-revival"],
                purpose="forbidden terminal task revival",
                ttl_seconds=120,
                metadata={"task_id": task_id, "attempt": 1},
            )

    def test_lifecycle_receipt_link_race_with_legacy_primary_uses_lifecycle_path(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-receipt-race"]
        )
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        observation = {"state": "failed", "source": "legacy-link-race"}
        legacy_digest = tasks._write_outcome_receipt(
            record,
            "failed",
            observation,
        )
        self.assertIsNotNone(legacy_digest)
        primary_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        lifecycle_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.lifecycle.json"
        legacy_bytes = primary_path.read_bytes()
        primary_path.unlink()
        original_link = os.link
        raced = False

        def race_link(source: str, destination: str) -> None:
            nonlocal raced
            if not raced and Path(destination) == primary_path:
                raced = True
                primary_path.write_bytes(legacy_bytes)
                os.chmod(primary_path, 0o600)
                raise FileExistsError(destination)
            original_link(source, destination)

        with patch.object(tasks.os, "link", side_effect=race_link):
            stored = tasks._set_state(
                task_id,
                "failed",
                observation=observation,
            )

        self.assertTrue(raced)
        self.assertEqual(legacy_digest, json.loads(primary_path.read_text())["receipt_sha256"])
        self.assertTrue(lifecycle_path.exists())
        lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
        self.assertEqual(2, lifecycle["schema_version"])
        self.assertEqual("grabowski_task_lifecycle_receipt", lifecycle["kind"])
        self.assertEqual(
            lifecycle["receipt_sha256"],
            tasks._sha256_json(
                {key: value for key, value in lifecycle.items() if key != "receipt_sha256"}
            ),
        )
        self.assertEqual(lifecycle["receipt_sha256"], stored["lifecycle_receipt_sha256"])
        self.assertNotEqual(legacy_digest, stored["lifecycle_receipt_sha256"])

    def test_pending_resource_terminalization_recovers_task_projection_and_blocks_delegation(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-crash"]
        )
        task_id = result["task"]["task_id"]
        record = tasks._row_raw(task_id)
        observation = {"state": "failed", "source": "crash-fixture"}
        projection = tasks._terminal_projection(
            record,
            "failed",
            observation=observation,
        )
        transition = resources.begin_task_terminalization(
            task_id,
            int(record["attempt"]),
            record["lease_owner_id"],
            "failed",
            tasks._record_resource_keys(record),
            task_projection=projection,
            observation_sha256=tasks._sha256_json(observation),
        )
        self.assertEqual("leases_revoked", transition["phase"])
        self.assertEqual("running", tasks._row_raw(task_id)["state"])
        self.assertEqual([], resources.list_resources(owner_id=record["lease_owner_id"]))

        listed = tasks.grabowski_task_list(limit=100, view="evidence")
        listed_task = next(item for item in listed["tasks"] if item["task_id"] == task_id)
        self.assertEqual("failed", listed_task["state"])
        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(record["lease_owner_id"])

        recovered = tasks._row_raw(task_id)
        self.assertEqual("failed", recovered["state"])
        final = resources.task_terminalization_record(task_id)
        self.assertEqual("projected", final["phase"])
        self.assertEqual("recovered_after_revocation", final["recovery_status"])
        self.assertEqual(final["transition_sha256"], recovered["terminalization_sha256"])

    def test_legacy_row_first_terminal_state_is_recovered_before_delegation(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-legacy-row-first"]
        )
        task_id = result["task"]["task_id"]
        owner = result["task"]["lease_owner_id"]
        observation = {"state": "completed", "source": "legacy-row-first"}
        with tasks._database_connection() as connection:
            connection.execute(
                "UPDATE tasks SET state='completed', last_observation_json=? "
                "WHERE task_id=?",
                (tasks._canonical_json(observation), task_id),
            )
            connection.commit()
        self.assertIsNotNone(
            resources.inspect_resource("component:test-terminalization-legacy-row-first")
        )

        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(owner)

        recovered = tasks._row_raw(task_id)
        transition = resources.task_terminalization_record(task_id)
        self.assertEqual("completed", recovered["state"])
        self.assertEqual([], resources.list_resources(owner_id=owner))
        self.assertEqual("projected", transition["phase"])
        self.assertEqual("recovered_legacy_row_first", transition["recovery_status"])
        self.assertEqual(transition["transition_sha256"], recovered["terminalization_sha256"])

    def test_server_task_lease_delegation_rejects_missing_live_lease(self) -> None:
        result = self._start(resource_keys=["component:test-task-delegation-missing"])
        task = result["task"]
        owner = task["lease_owner_id"]
        tasks.resources.release_resources(owner, task["resource_keys"])

        with self.assertRaisesRegex(ValueError, "not live"):
            tasks.server_task_lease_delegation_evidence(owner)

    def test_start_persists_auditable_record(self) -> None:
        result = self._start()
        task = result["task"]
        self.assertEqual(task["state"], "running")
        self.assertEqual(task["attempt"], 1)
        self.assertEqual(task["host"], "local")
        self.assertEqual(task["execution_backend"], "systemd-user")
        self.assertEqual(task["systemd_scope"], "user")
        self.assertEqual(task["authoritative_unit"], task["unit"])
        self.assertEqual(task["argv"], ["/bin/echo", "ok"])
        self.assertFalse(task["chronik_outbox_enabled"])
        self.assertIsNone(task["chronik_outbox_state_root"])
        self.assertIsNone(task["chronik_context"])
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])
        self.assertEqual(listed["state_filter_kind"], "all")
        self.assertEqual(listed["projection_counts"]["active"], 1)

    def test_task_list_supports_compact_state_projections(self) -> None:
        task = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='failed' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()

        attention = tasks.grabowski_task_list(state="attention")

        self.assertEqual(attention["state_filter_kind"], "projection")
        self.assertEqual(
            attention["state_filter_states"],
            ["interrupted", "outcome_unknown", "failed", "timed_out", "signalled"],
        )
        self.assertEqual(attention["total_matching"], 1)
        self.assertEqual(attention["tasks"][0]["state"], "failed")
        self.assertEqual(attention["state_counts"]["failed"], 1)
        self.assertEqual(attention["state_counts_scope"], "all_tasks")
        self.assertEqual(attention["projection_counts"]["attention"], 1)
        self.assertEqual(attention["projection_counts_scope"], "all_tasks")
        self.assertEqual(attention["projection_counts"]["terminal"], 1)
        self.assertEqual(attention["projection_counts"]["active"], 0)
        self.assertTrue(attention["projection_counts_overlap"])
        self.assertTrue(attention["state_counts_complete"])
        self.assertEqual(attention["unknown_state_count"], 0)
        self.assertEqual(tasks.grabowski_task_list(state="active")["count"], 0)

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='interrupted' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()
        interrupted = tasks.grabowski_task_list(state="attention")
        self.assertEqual(interrupted["count"], 1)
        self.assertEqual(interrupted["tasks"][0]["state"], "interrupted")
        self.assertEqual(interrupted["projection_counts"]["active"], 0)
        self.assertEqual(interrupted["projection_counts"]["attention"], 1)
        self.assertEqual(interrupted["projection_counts"]["terminal"], 0)
        self.assertEqual(tasks.grabowski_task_list(state="active")["count"], 0)
        self.assertIn("reconcile_check", interrupted["tasks"][0]["recommended_next_action"])

        self.assertEqual(
            tasks.grabowski_task_list(state="failed")["state_filter_kind"],
            "exact",
        )
        with self.assertRaisesRegex(ValueError, "state must be one of"):
            tasks.grabowski_task_list(state="stale")

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='legacy_unknown' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()
        unknown = tasks.grabowski_task_list()
        self.assertFalse(unknown["state_counts_complete"])
        self.assertEqual(unknown["unknown_state_count"], 1)
        self.assertEqual(unknown["warnings"][0]["code"], "unknown_task_states")
        self.assertEqual(
            unknown["recommended_next_action"],
            "inspect unknown task states before relying on projections",
        )

    def test_database_connection_closes_after_success_and_failure(self) -> None:
        with tasks._database_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

        with self.assertRaisesRegex(RuntimeError, "connection failure"):
            with tasks._database_connection() as failed_connection:
                raise RuntimeError("connection failure")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")

    def test_task_read_snapshot_closes_after_success_and_failure(self) -> None:
        with tasks._task_read_snapshot() as connection:
            self.assertTrue(connection.in_transaction)
            connection.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

        with self.assertRaisesRegex(RuntimeError, "snapshot failure"):
            with tasks._task_read_snapshot() as failed_connection:
                self.assertTrue(failed_connection.in_transaction)
                raise RuntimeError("snapshot failure")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")

    def test_task_list_derives_total_from_single_grouped_count_query(self) -> None:
        task = self._start()["task"]
        statements: list[str] = []
        original_snapshot = tasks._task_read_snapshot

        @contextmanager
        def traced_snapshot():
            with original_snapshot() as connection:
                connection.set_trace_callback(statements.append)
                try:
                    yield connection
                finally:
                    connection.set_trace_callback(None)

        with patch.object(tasks, "_task_read_snapshot", traced_snapshot):
            listed = tasks.grabowski_task_list(state="running")

        normalized = [" ".join(statement.upper().split()) for statement in statements]
        grouped_counts = [
            statement
            for statement in normalized
            if statement.startswith("SELECT STATE, COUNT(*) AS COUNT FROM TASKS GROUP BY STATE")
        ]
        standalone_counts = [
            statement
            for statement in normalized
            if statement.startswith("SELECT COUNT(*) FROM TASKS")
        ]
        self.assertEqual(len(grouped_counts), 1)
        self.assertEqual(standalone_counts, [])
        self.assertEqual(listed["total_matching"], 1)
        self.assertEqual(listed["state_counts"]["running"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])

    def test_task_list_reads_rows_and_counts_from_one_snapshot(self) -> None:
        task = self._start()["task"]
        original_state_counts = tasks._task_state_counts

        def mutate_then_count(
            connection: sqlite3.Connection,
        ) -> tuple[dict[str, int], dict[str, int], int]:
            with sqlite3.connect(self.database) as writer:
                writer.execute(
                    "UPDATE tasks SET state='failed' WHERE task_id=?",
                    (task["task_id"],),
                )
                writer.commit()
            return original_state_counts(connection)

        with patch.object(
            tasks,
            "_task_state_counts",
            side_effect=mutate_then_count,
        ):
            listed = tasks.grabowski_task_list(state="running")

        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["total_matching"], 1)
        self.assertEqual(listed["tasks"][0]["state"], "running")
        self.assertEqual(listed["state_counts"]["running"], 1)
        self.assertEqual(listed["state_counts"]["failed"], 0)
        with sqlite3.connect(self.database) as connection:
            stored_state = connection.execute(
                "SELECT state FROM tasks WHERE task_id=?",
                (task["task_id"],),
            ).fetchone()[0]
        self.assertEqual(stored_state, "failed")

    def test_start_uses_shared_unicode_argv_identity(self) -> None:
        argv = ["/bin/echo", "Grüße"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 139}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["argv_sha256"], command_identity.argv_sha256(argv))

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
                chronik_operation="review",
            )
        task = result["task"]
        self.assertTrue(task["chronik_outbox_enabled"])
        self.assertEqual(task["chronik_outbox_state_root"], str(outbox_root))
        files = sorted(outbox_root.rglob("*.jsonl"))
        self.assertEqual(len(files), 1)
        event = json.loads(files[0].read_text().splitlines()[0])
        self.assertEqual(event["kind"], "agent.run.started")
        self.assertEqual(event["data"]["operation"], "review")
        self.assertEqual(event["data"]["task_class"], "review")

    def test_chronik_context_derives_repository_from_canonical_repo_claim(self) -> None:
        result = {"returncode": 0, "stdout": "git@github.com:heimgewebe/chronik.git\n", "stderr": "", "timed_out": False}
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(tasks.operator, "_run", return_value=result) as run:
            context = json.loads(tasks._chronik_context("local", ["repo:/work/chronik"], "implement"))
        self.assertEqual(context, {
            "subject_scope": "repository", "repo": "heimgewebe/chronik",
            "operation": "implement", "task_class": "coding",
        })
        self.assertEqual(run.call_args.args[0], ["git", "-C", "/work/chronik", "config", "--get", "remote.origin.url"])

    def test_chronik_context_falls_back_to_host_for_ambiguous_or_foreign_claims(self) -> None:
        remote = {"returncode": 0, "stdout": "git@github.com:other/private.git\n", "stderr": "", "timed_out": False}
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(tasks.operator, "_run", return_value=remote):
            foreign = json.loads(tasks._chronik_context("heim-pc", ["repo:/work/private"], "recovery"))
            ambiguous = json.loads(tasks._chronik_context("heim-pc", ["repo:/a", "repo:/b"], "recovery"))
        expected = {"subject_scope": "host", "host": "heim-pc", "operation": "recovery", "task_class": "recovery"}
        self.assertEqual(foreign, expected)
        self.assertEqual(ambiguous, expected)

    def test_start_rejects_chronik_operation_without_outbox(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "chronik_operation requires chronik_outbox"):
                tasks.grabowski_task_start(
                    "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60,
                    chronik_operation="implement",
                )

    def test_start_rejects_unknown_chronik_operation(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "chronik_operation must be one of"):
                tasks.grabowski_task_start(
                    "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60,
                    chronik_outbox=True, chronik_operation="shell-text",
                )

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

    def test_completed_observation_blocks_direct_resume_before_launch(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_observe", return_value={
            "state": "completed",
            "properties": {"Result": "success"},
            "probe": completed,
            "observer": {"kind": "test"},
            "observed_at_unix": 123,
        }), patch.object(tasks, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "already completed"):
                tasks.grabowski_task_resume(task_id)
        launch.assert_not_called()
        stored = tasks._row(task_id)
        self.assertEqual(stored["state"], "completed")

    def test_terminal_record_blocks_direct_resume_before_observation(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        tasks._set_state(task_id, "failed", observation={"state": "failed"})
        with patch.object(tasks, "_observe") as observe, patch.object(tasks, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "Terminal task"):
                tasks.grabowski_task_resume(task_id)
        observe.assert_not_called()
        launch.assert_not_called()

    def test_missing_unit_outcome_unknown_blocks_manual_resume(self) -> None:
        started = self._start(host="remote")
        task_id = started["task"]["task_id"]
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            with self.assertRaisesRegex(RuntimeError, "outcome is unknown"):
                tasks.grabowski_task_resume(task_id)
        task = tasks.grabowski_task_list(view="evidence")["tasks"][0]
        self.assertEqual(task["attempt"], 1)
        self.assertEqual(task["state"], "outcome_unknown")
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
            "observer": tasks.fleet.TASK_UNIT_SHOW_OBSERVER,
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
        self.assertEqual(result["observer"]["kind"], tasks.fleet.TASK_UNIT_SHOW_OBSERVER)
        self.assertEqual(
            result["observer"]["fallback_from"],
            "fleet-dispatch-permission-denied",
        )
        show.assert_called_once_with(
            "wg-prod-1",
            "grabowski-task-0123456789abcdef01234567-a1.service",
            tasks.fleet.TASK_UNIT_SHOW_PROPERTIES,
            timeout_seconds=30,
            max_output_bytes=8192,
        )

    def test_reconcile_observer_propagates_narrow_probe_failure(self) -> None:
        with patch.object(
            tasks,
            "_dispatch",
            side_effect=tasks.fleet.FleetCommandDenied("Executable is not allowed for fleet host wg-prod-1: systemctl"),
        ), patch.object(
            tasks.fleet, "run_fleet_task_unit_show", side_effect=RuntimeError("ssh failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "ssh failed"):
                tasks._observe({
                    "host": "wg-prod-1",
                    "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
                })

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

    def test_root_task_runtime_preserves_lease_grace(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 199,
            },
        ), patch.object(
            tasks.operator, "_job_runtime", side_effect=lambda value: value
        ), patch.object(tasks.operator, "_require_operator_mutation") as mutation:
            with self.assertRaisesRegex(ValueError, "300 seconds"):
                tasks.grabowski_task_start(
                    "local",
                    ["/usr/local/bin/sleep-heimserver"],
                    cwd=str(self.root),
                    runtime_seconds=tasks.resources.MAX_TTL_SECONDS - 299,
                )
        mutation.assert_not_called()

    def test_local_power_worker_task_starts_through_root_broker_backend(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 200,
            },
        ), patch.object(
            tasks.privileged, "root_task_systemd_request", return_value=_launcher()
        ) as broker, patch.object(tasks, "_dispatch") as dispatch, patch.object(
            tasks.base, "_append_audit"
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )

        task = result["task"]
        self.assertEqual(task["state"], "running")
        self.assertEqual(task["execution_backend"], "systemd-root-broker")
        self.assertEqual(task["systemd_scope"], "system")
        self.assertEqual(task["authoritative_unit"], task["unit"])
        dispatch.assert_not_called()
        broker.assert_called_once()
        payload = broker.call_args.args[0]
        self.assertEqual(payload["operation"], "start")
        self.assertEqual(payload["unit"], task["authoritative_unit"])
        self.assertEqual(payload["argv"], ["/usr/local/bin/sleep-heimserver"])
        self.assertEqual(payload["runtime_seconds"], 300)
        self.assertEqual(result["audit"]["execution_backend"], "systemd-root-broker")

    def test_root_task_status_logs_and_cancel_route_by_stored_scope(self) -> None:
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        logs = _launcher()
        logs["stdout"] = "root log\n"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 201,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[_launcher(), running, logs, _launcher()],
        ) as broker, patch.object(tasks, "_dispatch") as dispatch, patch.object(
            tasks.base, "_append_audit"
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )
            task_id = started["task"]["task_id"]
            status = tasks.grabowski_task_status(task_id)
            output = tasks.grabowski_task_logs(task_id, max_lines=50)
            cancelled = tasks.grabowski_task_cancel(task_id)

        self.assertEqual(status["state"], "running")
        self.assertEqual(status["last_observation"]["observer"]["kind"], "root-systemd-broker-show-v1")
        self.assertEqual(output["result"]["stdout"], "root log\n")
        self.assertEqual(cancelled["task"]["state"], "cancelled")
        self.assertEqual(
            [call.args[0]["operation"] for call in broker.call_args_list],
            ["start", "show", "journal", "stop"],
        )
        self.assertEqual(broker.call_args_list[2].args[0]["max_lines"], 50)
        dispatch.assert_not_called()

    def test_root_scope_observation_denial_does_not_fallback_to_user_scope(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 202,
            },
        ), patch.object(
            tasks.privileged, "root_task_systemd_request", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )

        with patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=PermissionError("privileged broker is not ready"),
        ) as broker, patch.object(tasks, "_dispatch") as dispatch:
            result = tasks.reconcile_tasks_check(task_id=started["task"]["task_id"])

        self.assertEqual(result["blocked"][0]["execution_backend"], "systemd-root-broker")
        self.assertIn("observation denied", result["blocked"][0]["reason"])
        broker.assert_called_once()
        dispatch.assert_not_called()


    def test_root_broker_pre_dispatch_failure_is_terminal_and_releases_lease(self) -> None:
        resource_key = "service:root-task-pre-dispatch-failure"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 205,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=PermissionError("privileged broker is not ready"),
        ), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )

        self.assertEqual(result["task"]["state"], "failed")
        self.assertTrue(result["task"]["launcher"]["launch_not_dispatched"])
        self.assertFalse(result["task"]["launcher"]["outcome_unknown"])
        self.assertIsNone(tasks.resources.inspect_resource(resource_key))
        receipt = tasks.TASK_OUTCOMES_DIR / f"{result['task']['task_id']}.json"
        self.assertTrue(receipt.is_file())
        self.assertEqual(json.loads(receipt.read_text())["state"], "failed")

    def test_root_unknown_start_retains_lease_and_later_reattaches(self) -> None:
        unknown = _launcher(returncode=1)
        unknown["outcome_unknown"] = True
        unknown["root_truth_observable"] = False
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        resource_key = "service:root-task-lifetime-test"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 203,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[unknown, running, completed, unknown],
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )
            task_id = started["task"]["task_id"]
            self.assertEqual(started["task"]["state"], "outcome_unknown")
            lease = tasks.resources.inspect_resource(resource_key)
            self.assertIsNotNone(lease)
            self.assertGreaterEqual(
                lease["expires_at_unix"],
                tasks._now() + tasks.resources.MAX_TTL_SECONDS - 5,
            )
            self.assertEqual(
                started["audit"]["resource_lease_maintenance"]["mode"],
                "renewed",
            )
            self.assertFalse((tasks.TASK_OUTCOMES_DIR / f"{task_id}.json").exists())

            reattached = tasks.grabowski_task_status(task_id)
            self.assertEqual(reattached["state"], "running")
            self.assertIsNotNone(tasks.resources.inspect_resource(resource_key))

            terminal = tasks.grabowski_task_status(task_id)
            self.assertEqual(terminal["state"], "completed")
            self.assertIsNone(tasks.resources.inspect_resource(resource_key))
            receipt = json.loads(
                (tasks.TASK_OUTCOMES_DIR / f"{task_id}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["state"], "completed")
            self.assertEqual(receipt["systemd_scope"], "system")

            terminal_readback = tasks.grabowski_task_status(task_id)
            self.assertEqual(terminal_readback["state"], "completed")
            self.assertIsNone(terminal_readback["lease_maintenance"])
            self.assertIsNone(tasks.resources.inspect_resource(resource_key))

    def test_unknown_root_task_reacquires_expired_free_lease(self) -> None:
        unknown = _launcher(returncode=1)
        unknown["outcome_unknown"] = True
        unknown["root_truth_observable"] = False
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        resource_key = "service:root-task-expired-lease-test"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 204,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[unknown, running],
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?",
                    (resource_key,),
                )
                connection.commit()

            with patch.object(tasks, "_set_state", wraps=tasks._set_state) as set_state:
                status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(1, set_state.call_count)
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["lease_maintenance"]["mode"], "reacquired")
        lease = tasks.resources.inspect_resource(resource_key)
        self.assertIsNotNone(lease)
        self.assertEqual(lease["owner_id"], started["task"]["lease_owner_id"])

    def test_mutating_codex_task_implicitly_leases_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 150}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        key = f"repo:{self.root}"
        self.assertEqual(result["task"]["resource_keys"], [key])
        self.assertEqual(result["audit"]["requested_resource_keys"], [])
        self.assertEqual(result["audit"]["implicit_workspace_resource_key"], key)
        lease = tasks.resources.inspect_resource(key)
        self.assertEqual(lease["owner_id"], result["task"]["lease_owner_id"])
        with sqlite3.connect(self.resource_database) as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        metadata = json.loads(row[0])
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])
        self.assertEqual(
            metadata["scope_manifest"]["task_id"], result["task"]["task_id"]
        )
        self.assertEqual(metadata["scope_manifest"]["head"], "0" * 40)
        self.assertEqual(metadata["scope_manifest"]["branch"], "unversioned")
        self.assertRegex(
            result["audit"]["repository_scope_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_expired_implicit_repository_lease_reacquires_complete_scope(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", side_effect=[_launcher(), running]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 161}
        ):
            started = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            key = f"repo:{self.root}"
            empty_json, empty_sha256 = tasks.resources._metadata({})
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE leases SET expires_at_unix=0, metadata_json=?, "
                    "metadata_sha256=? WHERE resource_key=?",
                    (empty_json, empty_sha256, key),
                )
                connection.commit()
            status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(status["lease_maintenance"]["mode"], "reacquired")
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertIs(metadata["recovered_after_expiry"], True)
        self.assertEqual(metadata["implicit_workspace_resource_key"], key)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])

    def test_explicit_repository_task_scope_is_attested(self) -> None:
        key = f"repo:{self.root}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 160}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[key],
            )
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])
        self.assertRegex(
            result["audit"]["repository_scope_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_scoped_repository_task_key_binds_underlying_repository(self) -> None:
        key = f"repo:{self.root}:branch:feat/scoped-task"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 162}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[key],
            )
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertNotIn("scope_manifest", metadata)
        self.assertNotIn("scope_manifest_complete", metadata)
        self.assertIsNone(result["audit"]["repository_scope_manifest_sha256"])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_mutating_agents_cannot_share_one_implicit_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 151}
        ):
            tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            with self.assertRaises(tasks.resources.ResourceConflict):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60
                )
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(tasks.grabowski_task_list()["count"], 1)

    def test_explicit_path_scopes_allow_disjoint_agent_tasks(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        left = f"path:{self.root / 'left.py'}"
        right = f"path:{self.root / 'right.py'}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 152}
        ):
            first = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60,
                resource_keys=[left],
            )
            second = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60,
                resource_keys=[right],
            )
        self.assertEqual(first["task"]["resource_keys"], [left])
        self.assertEqual(second["task"]["resource_keys"], [right])
        self.assertIsNone(first["audit"]["implicit_workspace_resource_key"])
        self.assertIsNone(second["audit"]["implicit_workspace_resource_key"])

    def test_nested_agent_working_directories_share_git_root_guard(self) -> None:
        repository = self.root / "repository"
        nested = repository / "src" / "feature"
        nested.mkdir(parents=True)
        (repository / ".git").write_text("gitdir: /tmp/example\n")
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 159}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(nested), runtime_seconds=60
            )
        self.assertEqual(
            result["audit"]["implicit_workspace_resource_key"],
            f"repo:{repository}",
        )

    def test_codex_explicit_working_directory_is_the_guarded_workspace(self) -> None:
        workspace = self.root / "writer-worktree"
        workspace.mkdir()
        argv = [
            "/opt/codex", "exec", "-C", str(workspace),
            "--sandbox", "workspace-write",
        ]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 155}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(
            result["audit"]["implicit_workspace_resource_key"],
            f"repo:{self.root}",
        )

    def test_framework_writer_wrapper_keeps_workspace_owned_lease_contract(self) -> None:
        argv = [
            "/usr/bin/python3", "-m", "grabowski_agent_writer",
            "--repository", str(self.root),
        ]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["resource_keys"], [])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_non_path_resource_does_not_disable_workspace_guard(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 157}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60,
                resource_keys=["port:4567"],
            )
        self.assertEqual(
            result["task"]["resource_keys"],
            ["port:4567", f"repo:{self.root}"],
        )

    def test_read_only_codex_task_does_not_lease_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "read-only"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 153}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["resource_keys"], [])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_launch_failure_releases_implicit_workspace_lease(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher(returncode=1)), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 154}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["state"], "failed")
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))

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
        self.assertIsNotNone(tasks.resources.inspect_resource("display:12"))

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
        self.assertEqual(result["would_release"], [])
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
        self.assertEqual(result["released"], [])
        self.assertEqual(result["refreshed"][0]["state"], "outcome_unknown")
        self.assertIsNotNone(tasks.resources.inspect_resource("service:refresh.service"))

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
        self.assertEqual(listed["tasks"][0]["execution_backend"], "systemd-user")
        self.assertEqual(listed["tasks"][0]["systemd_scope"], "user")
        self.assertEqual(
            listed["tasks"][0]["authoritative_unit"],
            f"grabowski-task-{'a' * 24}-a1.service",
        )
        with sqlite3.connect(self.database) as migrated:
            version = migrated.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(tasks)")}
            indexes = {row[1] for row in migrated.execute("PRAGMA index_list(tasks)")}
            journal_mode = migrated.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(version, "4")
        self.assertIn("resource_keys_json", columns)
        self.assertIn("lease_owner_id", columns)
        self.assertIn("request_id", columns)
        self.assertIn("origin_ref", columns)
        self.assertIn("external_run_id", columns)
        self.assertIn("execution_envelope_sha256", columns)
        self.assertIn("acceptance_json", columns)
        self.assertIn("request_sha256", columns)
        self.assertIn("chronik_outbox_enabled", columns)
        self.assertIn("chronik_outbox_state_root", columns)
        self.assertIn("execution_backend", columns)
        self.assertIn("systemd_scope", columns)
        self.assertIn("authoritative_unit", columns)
        self.assertIn("tasks_state_created_task_idx", indexes)
        self.assertIn("tasks_created_task_idx", indexes)
        self.assertEqual(journal_mode, "wal")
        with tasks._database() as reopened:
            self.assertEqual(
                reopened.total_changes,
                0,
                "schema-4 fast path must not repeat migration writes",
            )

    def _promote_to_additive_schema_v4(self, *, incomplete: bool = False) -> str:
        task_id = "d" * 24
        with tasks._database():
            pass
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE tasks DROP COLUMN lifecycle_receipt_sha256")
            connection.execute("ALTER TABLE tasks DROP COLUMN terminalized_at_unix")
            connection.execute("ALTER TABLE tasks DROP COLUMN terminalization_sha256")
            connection.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, host, unit, attempt, state, resume_policy,
                    argv_json, argv_sha256, cwd, runtime_seconds,
                    cpu_weight, io_weight, memory_max_bytes,
                    created_at_unix, updated_at_unix, launcher_json,
                    last_observation_json, resource_keys_json,
                    execution_backend, systemd_scope, authoritative_unit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (task_id, "local", f"grabowski-task-{task_id}-a1.service", 1,
                 "completed", "manual", '["/bin/true"]', "b" * 64,
                 str(self.root), 60, 100, 100, None, 1, 1, '{}', None, '[]',
                 "systemd-user", "user", f"grabowski-task-{task_id}-a1.service"),
            )
            connection.execute("ALTER TABLE tasks ADD COLUMN terminalization_sha256 TEXT")
            connection.execute("ALTER TABLE tasks ADD COLUMN terminalized_at_unix INTEGER")
            if not incomplete:
                connection.execute("ALTER TABLE tasks ADD COLUMN lifecycle_receipt_sha256 TEXT")
            connection.execute("UPDATE metadata SET value='4' WHERE key='schema_version'")
            connection.execute(
                "UPDATE tasks SET terminalization_sha256=?, terminalized_at_unix=? WHERE task_id=?",
                ("c" * 64, 42, task_id),
            )
            if not incomplete:
                connection.execute(
                    "UPDATE tasks SET lifecycle_receipt_sha256=? WHERE task_id=?",
                    ("e" * 64, task_id),
                )
            connection.commit()
        return task_id

    def test_additive_schema_v4_preserves_terminalization_state(self) -> None:
        task_id = self._promote_to_additive_schema_v4()
        listed = tasks.grabowski_task_list(limit=10)
        self.assertTrue(any(item["task_id"] == task_id for item in listed["tasks"]))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual("4", connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0])
            self.assertEqual(
                ("c" * 64, 42, "e" * 64),
                connection.execute(
                    "SELECT terminalization_sha256, terminalized_at_unix, lifecycle_receipt_sha256 FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone(),
            )

    def test_incomplete_additive_schema_v4_fails_closed(self) -> None:
        self._promote_to_additive_schema_v4(incomplete=True)
        with self.assertRaisesRegex(RuntimeError, "schema 4 is incomplete"):
            tasks.grabowski_task_list()

    def test_unknown_task_schema_still_fails_closed(self) -> None:
        with tasks._database() as connection:
            connection.execute("UPDATE metadata SET value='5' WHERE key='schema_version'")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "Unsupported task database schema"):
            tasks.grabowski_task_list()

    def test_schema_v3_missing_root_contract_column_fails_closed(self) -> None:
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '3');
                CREATE TABLE tasks (task_id TEXT PRIMARY KEY);
                """
            )
        with self.assertRaisesRegex(RuntimeError, "schema 3 is incomplete"):
            tasks.grabowski_task_list()

    def test_schema_v4_missing_index_fails_closed_without_repair_write(self) -> None:
        with tasks._database() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "4",
            )
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP INDEX tasks_created_task_idx")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "indexes are incomplete"):
            tasks.grabowski_task_list()

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

    def test_shared_command_identity_is_in_runtime_contract(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        modules = {
            item["module"]: item["source"]
            for item in contract["supporting_sources"]
        }
        self.assertEqual(
            modules.get("grabowski_command_identity"),
            "src/grabowski_command_identity.py",
        )

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
            "grabowski_agent_workspace",
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
            "grabowski_agent_workspace_create",
            "grabowski_agent_workspace_status",
            "grabowski_agent_workspace_attach",
            "grabowski_agent_workspace_collect",
            "grabowski_agent_workspace_close",
        ):
            self.assertIn(tool, expected)


if __name__ == "__main__":
    unittest.main()
