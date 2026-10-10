"""Head-bound P1/P2 security regressions independent of PR1409's leased test file.

The original dirty RED checkout remains untouched. Test infrastructure is
reused from test_tasks rather than duplicating the persistent-task fixtures.
"""

from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch

import test_tasks as fixture


tasks = fixture.tasks
router = fixture.coding_agent_router
LOCAL_HOST = fixture.LOCAL_HOST


class TaskSecurityRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = fixture.TaskTests(
            "test_native_task_effect_classification_covers_local_and_remote_agents"
        )
        self.fixtures.setUp()
        self.addCleanup(self.fixtures.tearDown)
        self.root = self.fixtures.root

    @staticmethod
    def _admission() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "coding_agent_pre_dispatch_admission",
            "applicable": True,
            "admitted": True,
            "reason_code": "admitted",
            "argv_sha256": "1" * 64,
            "admission_sha256": "2" * 64,
            "reservation": {"status": "not_reserved", "atomic": False},
        }

    def _start_claude(self) -> str:
        argv = ["/opt/claude", "--permission-mode", "plan", "-p", "prompt"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()),
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 147},
            ),
            patch.object(
                router, "coding_agent_pre_dispatch_admission",
                return_value=self._admission(),
            ),
            patch.object(tasks.base, "_append_audit"),
        ):
            result = tasks.grabowski_task_start(
                "local",
                argv,
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="verify-then-retry",
            )
        return str(result["task"]["task_id"])

    def _assert_denied_before_resume_effects(
        self, task_id: str, *, message: str
    ) -> None:
        failed = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": fixture._launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        attempt_before = int(tasks._row_raw(task_id)["attempt"])
        with (
            patch.object(tasks, "_observe", return_value=failed),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 148},
            ),
            patch.object(
                router, "coding_agent_pre_dispatch_admission",
                return_value=self._admission(),
            ) as admission,
            patch.object(tasks, "_launch") as launch,
            patch.object(tasks.resources, "renew_resources") as renew,
            patch.object(tasks.resources, "acquire_resources") as acquire,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, message):
                tasks.grabowski_task_resume(task_id)
        admission.assert_not_called()
        launch.assert_not_called()
        renew.assert_not_called()
        acquire.assert_not_called()
        self.assertEqual(attempt_before, tasks._row_raw(task_id)["attempt"])

    def test_codex_ambiguous_workspace_flags_fail_before_launch(self) -> None:
        other = str(self.root.parent)
        invalid = (
            ["-C", str(self.root), "--cd", other],
            ["--cd", str(self.root), "-C", other],
            ["--cd=" + str(self.root), "--cd=" + other],
            ["-C", str(self.root), "-C", other],
            ["-C" + str(self.root), "-C", other],
            ["--add-dir", other],
            ["--add-dir=" + other],
            ["--worktree"],
            ["-p", "unchecked-profile"],
            ["--output-last-message", other],
            ["-c", 'sandbox_workspace_write.writable_roots=["/tmp/extra"]'],
            ["--config=default_permissions=\":danger-full-access\""],
            ["-s", "danger-full-access"],
            ["--dangerously-bypass-approvals-and-sandbox"],
        )
        for flags in invalid:
            argv = ["/opt/codex", *flags, "exec", "prompt"]
            with (
                self.subTest(argv=argv),
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            ):
                with self.assertRaisesRegex(RuntimeError, "Codex"):
                    tasks._mutating_agent_workspace(
                        "local", argv, cwd=str(self.root)
                    )

        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            for valid in (
                ["-C", str(self.root)],
                ["-C" + str(self.root)],
                ["--cd", str(self.root)],
                ["--cd=" + str(self.root)],
                ["-C=" + str(self.root)],
            ):
                with self.subTest(valid=valid):
                    self.assertEqual(
                        tasks._mutating_agent_workspace(
                            "local", ["/opt/codex", *valid, "exec", "prompt"],
                            cwd=str(self.root),
                        ),
                        str(self.root),
                    )
            self.assertEqual(
                tasks._mutating_agent_workspace(
                    "local",
                    ["/opt/codex", "-C", str(self.root), "--", "--cd", other],
                    cwd=str(self.root),
                ),
                str(self.root),
            )

        argv = ["/opt/codex", "-C", str(self.root), "--cd", other, "exec", "x"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 151},
            ),
            patch.object(tasks, "_dispatch") as dispatch,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Codex"):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60
                )
        dispatch.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))

    def test_coding_agent_resume_rejects_spoofed_effect_profiles(self) -> None:
        task_id = self._start_claude()
        baseline = json.loads(tasks._row_raw(task_id)["launcher_json"])
        for profile in (
            "unknown", "remote_write", "read_only", "repository_write", None
        ):
            with self.subTest(effect_profile=profile):
                launcher = json.loads(json.dumps(baseline))
                if profile is None:
                    launcher["task_effect_classification"].pop("effect_profile")
                else:
                    launcher["task_effect_classification"]["effect_profile"] = profile
                with tasks._database_connection() as db:
                    db.execute(
                        "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                        (tasks._canonical_json(launcher), task_id),
                    )
                self._assert_denied_before_resume_effects(
                    task_id, message="effect profile"
                )

    def test_original_agent_anchor_rejects_disguised_nonagent_resume(self) -> None:
        task_id = self._start_claude()
        fake_argv = ["/bin/echo", "hello"]
        with tasks._database_connection() as db:
            db.execute(
                """UPDATE tasks
                   SET argv_json=?, argv_sha256=?, launcher_json=?
                   WHERE task_id=?""",
                (
                    tasks._canonical_json(fake_argv),
                    tasks.command_identity.argv_sha256(fake_argv),
                    tasks._canonical_json({}),
                    task_id,
                ),
            )
        self._assert_denied_before_resume_effects(
            task_id, message="agent identity"
        )

    def test_missing_start_anchor_blocks_resume(self) -> None:
        task_id = self._start_claude()
        with tasks._database_connection() as db:
            db.execute(
                "DELETE FROM metadata WHERE key=?",
                (f"{tasks.TASK_EFFECT_START_KEY_PREFIX}{task_id}",),
            )
        self._assert_denied_before_resume_effects(
            task_id, message="original start decision is missing"
        )

    def test_task_and_start_anchor_roll_back_in_same_transaction(self) -> None:
        argv = ["/opt/claude", "--permission-mode", "plan", "-p", "prompt"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(tasks, "_dispatch") as dispatch,
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 147},
            ),
            patch.object(
                router, "coding_agent_pre_dispatch_admission",
                return_value=self._admission(),
            ),
            patch.object(
                tasks, "_register_task_reconcile_sequence",
                side_effect=RuntimeError("injected before transaction commit"),
            ),
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected before transaction commit"):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60,
                    resume_policy="verify-then-retry",
                )
        dispatch.assert_not_called()
        with tasks._database_connection() as db:
            task_count = db.execute("SELECT count(*) FROM tasks").fetchone()[0]
            anchor_count = db.execute(
                "SELECT count(*) FROM metadata WHERE key LIKE 'task_effect_start:%'"
            ).fetchone()[0]
        self.assertEqual((task_count, anchor_count), (0, 0))


if __name__ == "__main__":
    unittest.main()
