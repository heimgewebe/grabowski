"""Fail-closed Codex command selection at the task-owned workspace lease boundary.

Tests are isolated from the separately owned tests/test_tasks.py used by PR #1409.
No test invokes Codex or writes anything outside unittest temporary fixtures.
"""

from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

import test_tasks as fixture


tasks = fixture.tasks


class CodexTaskCommandSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixture.TaskTests(
            "test_native_task_effect_classification_covers_local_and_remote_agents"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root

    def test_administrative_and_unknown_commands_fail_before_workspace_admission(self) -> None:
        # These commands may write to user-level configuration, authentication,
        # global plugins, or historical sessions rather than the leased root.
        unsupported = (
            ("mcp", "add", "candidate"),
            ("plugin", "marketplace", "add", "candidate"),
            ("login",),
            ("logout",),
            ("apply",),
            ("update",),
            ("resume", "--last"),
            ("fork", "--last"),
            ("exec", "resume", "--last"),
            ("exec", "fork", "--last"),
            ("features", "list"),
            ("cloud", "list"),
            ("unrecognized-future-subcommand",),
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST):
            for tail in unsupported:
                command = ["/opt/codex", "-C", str(self.root), *tail]
                with self.subTest(command=tail):
                    with self.assertRaisesRegex(RuntimeError, "Codex"):
                        tasks._mutating_agent_workspace(
                            "local", command, cwd=str(self.root)
                        )

    def test_codex_admin_command_denied_before_task_lease_dispatch_or_insert(self) -> None:
        command = [
            "/opt/codex", "-C", str(self.root),
            "mcp", "add", "fixture", "--url", "https://example.invalid",
        ]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=command),
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Codex"):
                tasks.grabowski_task_start(
                    "local", command, cwd=str(self.root), runtime_seconds=60
                )
        dispatch.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))
        if self.database_exists():
            with sqlite3.connect(self.fixture.database) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM tasks").fetchone()[0], 0)

    def database_exists(self) -> bool:
        return self.fixture.database.exists()

    def test_unrecognized_options_and_unbound_prompt_delimiter_fail_closed(self) -> None:
        # Unknown current/future flags must not silently change CLI semantics.
        # A payload delimiter alone does not establish an execution subcommand.
        invalid = (
            ("--",),
            ("--future-write-control", "exec", "prompt"),
            ("exec", "--future-write-control", "prompt"),
            ("exec", "--future-write-control=some-value", "prompt"),
            ("exec", "-x", "prompt"),
            ("exec", "--config", "sandbox_workspace_write.writable_roots=['/tmp']", "prompt"),
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST):
            for tail in invalid:
                with self.subTest(tail=tail), self.assertRaisesRegex(RuntimeError, "Codex"):
                    tasks._mutating_agent_workspace(
                        "local", ["/opt/codex", "-C", str(self.root), *tail],
                        cwd=str(self.root),
                    )

    def test_conflicting_or_duplicate_sandbox_declarations_fail_closed(self) -> None:
        duplicate = (
            ("--sandbox", "read-only", "--sandbox", "workspace-write"),
            ("--sandbox=workspace-write", "-s", "read-only"),
            ("-sread-only", "--sandbox=workspace-write"),
            ("-s=workspace-write", "-sread-only"),
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST):
            for flags in duplicate:
                with self.subTest(flags=flags), self.assertRaisesRegex(RuntimeError, "Codex"):
                    tasks._mutating_agent_workspace(
                        "local",
                        ["/opt/codex", "-C", str(self.root), "exec", *flags, "prompt"],
                        cwd=str(self.root),
                    )

    def test_direct_codex_without_attested_filesystem_sandbox_is_denied(self) -> None:
        # A workspace lease coordinates a writer but does not sandbox the process.
        # systemd-run's current ProtectSystem=off/ProtectHome=no is not proof
        # that the effective Codex permissions are confined to that workspace.
        command = ["/opt/codex", "-C", str(self.root), "exec", "--sandbox", "workspace-write", "prompt"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=command),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                tasks.grabowski_task_start(
                    "local", command, cwd=str(self.root), runtime_seconds=60
                )
        dispatch.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))
        if self.database_exists():
            with sqlite3.connect(self.fixture.database) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM tasks").fetchone()[0], 0)

    def test_preexisting_codex_task_cannot_resume_without_os_sandbox(self) -> None:
        command = ["/opt/codex", "-C", str(self.root), "exec", "prompt"]
        admitted = {
            "schema_version": 1, "kind": "coding_agent_pre_dispatch_admission",
            "applicable": True, "admitted": True, "reason_code": "admitted",
            "argv_sha256": "1" * 64, "admission_sha256": "2" * 64,
            "reservation": {"status": "not_reserved", "atomic": False},
        }
        # Only synthesize a historical pre-fix record in the private fixture DB.
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=command),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 130}),
            patch.object(tasks, "_require_direct_codex_filesystem_sandbox"),
            patch.object(fixture.coding_agent_router, "coding_agent_pre_dispatch_admission", return_value=admitted),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()),
            patch.object(tasks.base, "_append_audit"),
        ):
            created = tasks.grabowski_task_start(
                "local", command, cwd=str(self.root),
                runtime_seconds=60, resume_policy="verify-then-retry",
            )
        task_id = created["task"]["task_id"]
        attempt_before = tasks._row_raw(task_id)["attempt"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST),
            patch.object(tasks, "_dispatch") as dispatch,
            patch.object(tasks, "_launch") as launch,
            patch.object(tasks.resources, "renew_resources") as renew,
            patch.object(tasks.resources, "acquire_resources") as acquire,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                tasks.grabowski_task_resume(task_id)
        dispatch.assert_not_called()
        launch.assert_not_called()
        renew.assert_not_called()
        acquire.assert_not_called()
        self.assertEqual(tasks._row_raw(task_id)["attempt"], attempt_before)

    def test_existing_scoped_writer_wrapper_is_still_admissible(self) -> None:
        command = [
            "/usr/bin/python3", "-m", "grabowski_agent_writer",
            "--repository", str(self.root),
        ]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=command),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
        ):
            accepted = tasks.grabowski_task_start(
                "local", command, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(accepted["task"]["resource_keys"], [])
        dispatch.assert_called()

    def test_known_execution_and_explicit_payload_remain_accepted(self) -> None:
        permitted = (
            ["/opt/codex", "exec", "--sandbox", "workspace-write", "prompt"],
            ["/opt/codex", "-C", str(self.root), "exec", "--", "mcp", "add"],
            ["/opt/codex", "-C", str(self.root), "review", "code"],
            ["/opt/codex", "-C", str(self.root), "--", "login"],
            ["/opt/codex", "--model", "mcp", "-C", str(self.root), "exec", "prompt"],
            ["/opt/codex", "exec", "-C" + str(self.root), "prompt"],
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=fixture.LOCAL_HOST):
            for argv in permitted:
                with self.subTest(argv=argv):
                    self.assertEqual(
                        tasks._mutating_agent_workspace(
                            "local", argv, cwd=str(self.root)
                        ),
                        str(self.root),
                    )


if __name__ == "__main__":
    unittest.main()