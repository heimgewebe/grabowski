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
            patch.object(tasks, "_launch", return_value=fixture._launcher()),
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

    def test_missing_anchor_with_disguised_agent_cannot_be_legacy_nonagent(self) -> None:
        task_id = self._start_claude()
        fake_argv = [
            "/bin/bash", "-c",
            "/opt/claude --permission-mode plan -p prompt",
        ]
        with tasks._database_connection() as db:
            db.execute(
                "DELETE FROM metadata WHERE key=?",
                (f"{tasks.TASK_EFFECT_START_KEY_PREFIX}{task_id}",),
            )
            db.execute(
                "UPDATE tasks SET argv_json=?, argv_sha256=?, launcher_json=? "
                "WHERE task_id=?",
                (
                    tasks._canonical_json(fake_argv),
                    tasks.command_identity.argv_sha256(fake_argv),
                    tasks._canonical_json({}),
                    task_id,
                ),
            )
        # Missing original identity cannot become a legacy exemption merely
        # because mutable argv/launcher fields were rewritten.
        with self.assertRaisesRegex(RuntimeError, "original start decision"):
            tasks._verified_task_effect_start(
                tasks._row_raw(task_id), command=fake_argv
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


    def test_operation_identity_active_bound_lease_requires_fresh_maintenance(self) -> None:
        # A fresh unit observation does not attest an unchanged resource lease.
        # A deduplicated task must not be returned when its lease check fails.
        task_id = "f" * 24
        stored = {
            "task_id": task_id,
            "state": "running",
            "resume_policy": "verify-then-retry",
            "resource_keys_json": json.dumps([f"repo:{self.root}"]),
        }
        operation_identity = {"operation_identity_sha256": "a" * 64}
        with (
            patch.object(
                tasks, "_latest_task_for_operation_identity", return_value=stored
            ),
            patch.object(
                tasks, "_task_has_fresh_active_observation", return_value=True
            ),
            patch.object(
                tasks, "grabowski_task_status",
                side_effect=RuntimeError("lease maintenance failed"),
            ) as status,
        ):
            with self.assertRaisesRegex(RuntimeError, "lease maintenance failed"):
                tasks._resolve_task_operation_identity(
                    operation_identity,
                    supersedes_task_id="",
                    supersedes_receipt_sha256="",
                    force_new_reason="",
                )
        status.assert_called_once_with(task_id)



    def test_env_split_short_clusters_do_not_bypass_codex_guard(self) -> None:
        commands = (
            ["/usr/bin/env", "-iS", "codex exec prompt"],
            ["/usr/bin/env", "-Scodex", "exec", "prompt"],
            ["/usr/bin/env", "-vS", "codex exec prompt"],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_codex_indirect_prefixers_do_not_bypass_guard(self) -> None:
        commands = (
            ["/usr/bin/time", "-p", "codex", "exec", "prompt"],
            ["sudo", "-n", "codex", "exec", "prompt"],
            ["doas", "codex", "exec", "prompt"],
            ["/usr/bin/busybox", "sh", "-c", "codex exec prompt"],
            ["/usr/bin/busybox", "env", "codex", "exec", "prompt"],
            ["/lib64/ld-linux-x86-64.so.2", "/opt/codex", "exec", "prompt"],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_symlinked_prefix_launcher_aliases_must_not_hide_codex(self) -> None:
        for name, target, args in (
            ("alias-env", "/usr/bin/env", ["-iS", "codex exec prompt"]),
            ("alias-time", "/usr/bin/time", ["-p", "codex", "exec", "prompt"]),
        ):
            alias = self.root / name
            alias.symlink_to(target)
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        [str(alias), *args]
                    )
        alias = self.root / "alias-env-good"
        alias.symlink_to("/usr/bin/env")
        tasks._require_direct_codex_filesystem_sandbox([
            str(alias), "CARGO_TARGET_DIR=/tmp/project-codex/target",
            "cargo", "test"
        ])

    def test_shell_builtin_prefixes_do_not_hide_codex(self) -> None:
        commands = (
            "exec -a harmless codex exec prompt",
            "command -p codex exec prompt",
            "eval 'codex exec prompt'",
            "builtin eval 'codex exec prompt'",
            "bash -c 'exec -a harmless codex exec prompt'",
        )
        for source in commands:
            with self.subTest(source=source):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", source]
                    )

    def test_shell_builtin_cargo_and_printed_text_remain_allowed(self) -> None:
        for source in (
            "exec -a label cargo test",
            "command -p cargo test",
            "eval 'printf codex'",
            "printf 'codex exec prompt'",
        ):
            with self.subTest(source=source):
                tasks._require_direct_codex_filesystem_sandbox(
                    ["/bin/bash", "-c", source]
                )

    def test_sudo_assignment_prefix_cannot_hide_indirect_codex(self) -> None:
        # Prefixed environment assignments are not the executable. Both
        # wrappers must still inspect the child command before any task effect.
        for argv in (
            ["sudo", "-n", "HOME=/tmp", "codex", "exec", "prompt"],
            ["sudo", "-u", "tester", "X=1", "codex", "exec", "prompt"],
            ["doas", "-n", "HOME=/tmp", "codex", "exec", "prompt"],
            ["/usr/bin/env", "HOME=/tmp", "sudo", "-n",
             "X=1", "/usr/bin/env", "-S", "codex exec prompt"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_sudo_assignment_preserves_non_agent_cargo(self) -> None:
        for wrapper in ("sudo", "doas"):
            with self.subTest(wrapper=wrapper):
                tasks._require_direct_codex_filesystem_sandbox([
                    wrapper, "-n", "HOME=/tmp/project-codex",
                    "cargo", "build", "--manifest-path",
                    str(self.root / "project-codex" / "Cargo.toml"),
                ])

    def test_prefix_launchers_preserve_non_agent_cargo_and_build_paths(self) -> None:
        commands = (
            ["timeout", "30", "cargo", "build", "--manifest-path",
             str(self.root / "project-codex" / "Cargo.toml")],
            ["nice", "-n", "10", "cargo", "build", "--manifest-path",
             str(self.root / "project-codex" / "Cargo.toml")],
            ["stdbuf", "-oL", "cargo", "build", "--manifest-path",
             str(self.root / "project-codex" / "Cargo.toml")],
            ["nohup", "/bin/bash", str(self.root / "project-codex" / "build.sh")],
            ["setsid", "/bin/bash", str(self.root / "project-codex" / "build.sh")],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_prefixed_codex_remains_denied(self) -> None:
        for argv in (
            ["timeout", "30", "codex", "exec", "prompt"],
            ["nice", "-n", "10", "codex", "exec", "prompt"],
            ["stdbuf", "-oL", "codex", "exec", "prompt"],
            ["nohup", "codex", "exec", "prompt"],
            ["setsid", "codex", "exec", "prompt"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_shell_control_flow_still_detects_literal_codex(self) -> None:
        for command in (
            "while true; do codex exec prompt; done",
            "if true; then codex exec prompt; fi",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", command]
                    )

    def test_reviewer_p1_grouped_shell_codex_launches_are_denied(self) -> None:
        for source in (
            "{ codex exec prompt; }",
            "function run(){ codex exec prompt; }; run",
            "echo ok; { codex exec prompt; }",
            "if true; then { codex exec prompt; }; fi",
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", source]
                    )

    def test_reviewer_p1_shell_command_substitution_is_not_argv_data(self) -> None:
        for source in (
            'printf "$(codex exec prompt)"',
            "echo " + chr(96) + "codex exec prompt" + chr(96),
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", source]
                    )

        for source in (
            'printf "$(printf codex)"',
            "printf 'codex exec prompt'",
        ):
            with self.subTest(source=source):
                tasks._require_direct_codex_filesystem_sandbox(
                    ["/bin/bash", "-c", source]
                )

    def test_reviewer_p1_bash_coprocess_and_ansi_quote_exec_cannot_hide_codex(self) -> None:
        for source in (
            "coproc codex exec prompt",
            "$'codex' exec prompt",
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", source]
                    )
        for source in (
            "printf $'codex'",
            "printf 'coproc codex exec'",
        ):
            with self.subTest(source=source):
                tasks._require_direct_codex_filesystem_sandbox(
                    ["/bin/bash", "-c", source]
                )

    def test_reviewer_p1_env_optional_signal_flags_cannot_hide_codex(self) -> None:
        # GNU env --block-signal takes an OPTIONAL attached argument.
        # The separated form "--block-signal SIGTERM codex" attempts to exec
        # SIGTERM (exit 127), not codex, so is not an executable bypass.
        executable = (
            ["/usr/bin/env", "--block-signal=SIGTERM", "codex", "exec", "prompt"],
            ["/usr/bin/env", "--default-signal=TERM", "codex", "exec", "prompt"],
            ["/usr/bin/env", "--ignore-signal=PIPE", "codex", "exec", "prompt"],
            ["/usr/bin/env", "-S",
             "--block-signal=TERM codex exec prompt"],
        )
        for argv in executable:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        # Signal option values do not by themselves make cargo a Codex launch.
        for argv in (
            ["/usr/bin/env", "--block-signal=TERM", "cargo", "build"],
            ["/usr/bin/env", "--default-signal=TERM", "cargo", "test"],
        ):
            with self.subTest(non_agent=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_reviewer_p1_busybox_shell_applets_cannot_hide_codex(self) -> None:
        for shell in ("ash", "hush"):
            with self.subTest(shell=shell):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/usr/bin/busybox", shell, "-c", "codex exec prompt"]
                    )

    def test_reviewer_p1_perl_ruby_option_clusters_cannot_hide_codex(self) -> None:
        for argv in (
            ["perl", "-p", "-e", "system('codex exec')"],
            ["perl", "-pe", "system('codex exec')"],
            ["ruby", "-p", "-e", "system('codex exec')"],
            ["ruby", "-pe", "system('codex exec')"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_reviewer_p1_renamed_python_and_loader_are_detected(self) -> None:
        for name, target, args in (
            ("alias-python-guard", "/usr/bin/python3.12",
             ["-c", "import os; os.execvp('codex', ['codex', 'exec'])"]),
            ("alias-loader-guard", "/lib64/ld-linux-x86-64.so.2",
             ["/opt/codex", "exec", "prompt"]),
        ):
            alias = self.root / name
            alias.symlink_to(target)
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox([str(alias), *args])

    def test_grouping_non_agent_literal_arguments_are_preserved(self) -> None:
        for argv in (
            ["/bin/bash", "-c", "{ printf 'codex exec prompt'; }"],
            ["/bin/bash", "-c", "function f(){ printf codex; }; f"],
            ["/usr/bin/busybox", "ash", "-c", "printf 'codex exec prompt'"],
        ):
            with self.subTest(argv=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_legitimate_codex_named_paths_are_not_entrypoints(self) -> None:
        commands = (
            ["/usr/bin/python3", "-m", "grabowski_agent_writer", "--repository",
             str(self.root / "project-codex")],
            ["/bin/bash", str(self.root / "project-codex" / "build.sh")],
            ["/bin/bash", "-c", "printf hello", "--", str(self.root / "project-codex")],
            ["sudo", "-n", "/bin/bash", str(self.root / "project-codex" / "build.sh")],
            ["/usr/bin/time", "-p", "cargo", "build", "--manifest-path",
             str(self.root / "project-codex" / "Cargo.toml")],
            ["/usr/bin/env", "-iS", "python -m grabowski_agent_writer"
             " --repository /tmp/project-codex"],
            ["/usr/bin/busybox", "sh", "-c", "printf project-codex"],
            ["/bin/bash", "-c", "printf codex"],
            ["/bin/bash", "-c", "echo codex"],
            ["/usr/bin/node", str(self.root / "project-codex" / "build.js"),
             "--label", "codex"],
            ["ruby", str(self.root / "project-codex" / "build.rb")],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_env_split_codex_fails_before_dispatch_or_persistence(self) -> None:
        argv = ["/usr/bin/env", "-iS", "codex exec prompt"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=argv),
            patch.object(tasks, "_require_recovery_gate",
                         return_value={"checked_at_unix": 150}),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60
                )
        dispatch.assert_not_called()
        with tasks._database_connection() as db:
            count = db.execute("SELECT count(*) FROM tasks").fetchone()[0]
        self.assertEqual(count, 0)

    def test_computed_shell_agent_entrypoints_require_isolation(self) -> None:
        # A literal argv scan does not see the actual exec target created
        # through variables, substitutions, or dynamic Python invocation.
        for source in (
            'agent=codex; "$agent" exec prompt',
            'eval "$(printf co)$(printf dex) exec prompt"',
            'python -c \'import os; os.execvp("co"+"dex", ["co"+"dex", "exec"])\'',
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(
                        ["/bin/bash", "-c", source]
                    )

    def test_computed_interpreter_agent_entrypoints_require_isolation(self) -> None:
        # These are inert source strings. No agent or interpreter is executed.
        for argv in (
            ["python3", "-c",
             "import os; os.execvp('co'+'dex', ['co'+'dex','exec'])"],
            ["node", "-e",
             "require('child_process').spawnSync('co'+'dex',['exec'])"],
            ["ruby", "-e", "system('co'+'dex', 'exec')"],
            ["perl", "-e", "system('co' . 'dex', 'exec')"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_print_only_interpreter_code_can_mention_codex(self) -> None:
        # A command name appearing only as printable text is not an exec.
        for argv in (
            ["python3", "-c", "print('codex')"],
            ["node", "-e", "console.log('codex')"],
            ["ruby", "-e", "puts 'codex'"],
            ["perl", "-e", "print 'codex'"],
        ):
            with self.subTest(argv=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_interpolated_print_strings_cannot_hide_computed_codex(self) -> None:
        # Ruby and Perl evaluate interpolations inside double-quoted strings.
        # These payloads are only passed as strings to the admission guard.
        for argv in (
            ["ruby", "-e", "puts \"#{system('co' + 'dex', 'exec')}\""],
            ["perl", "-e", "print \"@{[system('co' . 'dex', 'exec')]}\""],
        ):
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        for argv in (
            ["ruby", "-e", "puts 'codex'"],
            ["perl", "-e", "print 'codex'"],
        ):
            with self.subTest(harmless=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_preload_environment_must_not_bypass_coding_agent_isolation(self) -> None:
        # All commands here are inert strings inspected only by the admission
        # guard. None of the preload files exists in the fixture or is run.
        # Each variable can load executable code before a harmless argv body.
        commands = (
            ["env", "BASH_ENV=/tmp/preload.sh",
             "bash", "-c", "printf safe"],
            ["env", "PYTHONPATH=/tmp/preload",
             "python3", "-c", "print('safe')"],
            ["env", "NODE_OPTIONS=--require=/tmp/preload.js",
             "node", "-e", "console.log('safe')"],
            ["env", "RUBYOPT=-r/tmp/preload.rb",
             "ruby", "-e", "puts 'safe'"],
            ["env", "PERL5OPT=-MInjected",
             "perl", "-e", "print 'safe'"],
        )
        for argv in commands:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(
                    RuntimeError, "Codex.*filesystem sandbox"
                ):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        for argv in (
            ["env", "CARGO_TARGET_DIR=/tmp/project-codex", "cargo", "test"],
            ["env", "FOO=bar", "bash", "-c", "printf safe"],
        ):
            with self.subTest(allowed=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_nested_preload_environment_bypasses_are_rejected(self) -> None:
        # Test *admission* only; no shell, sudo or interpreter is executed.
        dangerous = (
            ["env", "-S", "NODE_OPTIONS=--require=/tmp/preload.js node -e 'console.log(1)'"],
            ["env", "--", "PYTHONPATH=/tmp/preload", "python3", "-c", "print('safe')"],
            ["env", "LD_PRELOAD=/tmp/preload.so", "cargo", "test"],
            ["sudo", "-n", "BASH_ENV=/tmp/preload.sh", "bash", "-c", "printf safe"],
            ["doas", "RUBYOPT=-r/tmp/preload.rb", "ruby", "-e", "puts 'safe'"],
            ["bash", "-c", "BASH_ENV=/tmp/preload.sh bash -c 'printf safe'"],
            ["bash", "-c", "export BASH_ENV=/tmp/preload.sh; bash -c 'printf safe'"],
            ["bash", "-c", "declare -x NODE_OPTIONS=--require=/tmp/preload.js; node -e 'console.log(1)'"],
        )
        for argv in dangerous:
            with self.subTest(dangerous=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        for argv in (
            ["sudo", "-n", "FOO=bar", "bash", "-c", "printf safe"],
            ["bash", "-c", "export FOO=bar; printf safe"],
        ):
            with self.subTest(allowed=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_interpreter_preload_flags_cannot_run_unverified_code(self) -> None:
        # Preload modules run *before* a harmless inline body. Inspect only;
        # never run or create the named payload files in this fixture.
        dangerous = (
            ["node", "--require", "/tmp/unsafe.js", "-e", "console.log('safe')"],
            ["node", "--require=/tmp/unsafe.js", "-e", "console.log('safe')"],
            ["node", "--import", "/tmp/unsafe.mjs", "-e", "console.log('safe')"],
            ["node", "--loader=/tmp/unsafe.mjs", "-e", "console.log('safe')"],
            ["ruby", "-r", "/tmp/unsafe.rb", "-e", "puts 'safe'"],
            ["perl", "-r", "/tmp/unsafe.pl", "-e", "print 'safe'"],
        )
        for argv in dangerous:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        for argv in (
            ["node", "-e", "console.log('safe')"],
            ["ruby", "-e", "puts 'safe'"],
            ["perl", "-e", "print 'safe'"],
        ):
            with self.subTest(allowed=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_elf_loader_preload_and_library_override_rejected(self) -> None:
        # Admission-only fixtures: no ELF loader or shared object is executed.
        # Library search overrides can load arbitrary constructors just like
        # explicit --preload/--audit, even if the target binary is harmless.
        dangerous = (
            ["ld-linux-x86-64.so.2", "--preload", "/tmp/inject.so", "/bin/true"],
            ["ld-linux-x86-64.so.2", "--preload=/tmp/inject.so", "/bin/true"],
            ["ld-linux-x86-64.so.2", "--audit", "/tmp/inject.so", "/bin/true"],
            ["ld-linux-x86-64.so.2", "--audit=/tmp/inject.so", "/bin/true"],
            ["ld.so", "--library-path", "/tmp/untrusted", "/bin/true"],
            ["ld.so", "--library-path=/tmp/untrusted", "/bin/true"],
            ["env", "-i", "ld.so", "--preload", "/tmp/inject.so", "/bin/true"],
            ["bash", "-c", "ld.so --preload /tmp/inject.so /bin/true"],
        )
        for argv in dangerous:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        for argv in (
            ["ld.so", "--verify", "/bin/true"],
            ["ld.so", "--list", "/bin/true"],
            ["env", "FOO=bar", "ld.so", "--verify", "/bin/true"],
        ):
            with self.subTest(allowed=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_unverified_command_carrier_and_attached_python_source(self) -> None:
        # Admission-only. No CLI, script, dynamic loader or coding agent starts.
        dangerous = (
            ["python3", "-cimport os;os.execvp('co'+'dex', ['co'+'dex','exec'])"],
            ["python3", "-I", "-cimport os;os.execvp('co'+'dex', ['co'+'dex','exec'])"],
            ["bash", "--rcfile", "/tmp/user-config.sh", "-ic", "printf safe"],
            ["bash", "--init-file", "/tmp/user-config.sh", "-ic", "printf safe"],
            ["systemd-run", "--user", "codex", "exec", "prompt"],
            ["xargs", "codex", "exec", "prompt"],
            ["script", "-c", "codex exec prompt", "/dev/null"],
            ["flock", "/tmp/lock", "codex", "exec", "prompt"],
            ["watch", "-n", "1", "codex", "exec", "prompt"],
            ["unshare", "codex", "exec", "prompt"],
            ["nsenter", "--target", "1", "codex", "exec", "prompt"],
            ["setpriv", "codex", "exec", "prompt"],
            ["runuser", "-u", "test", "--", "codex", "exec", "prompt"],
            ["su", "-c", "codex exec prompt"],
            ["ionice", "-c", "3", "bash", "-c", "codex exec prompt"],
            ["taskset", "-c", "0", "codex", "exec", "prompt"],
            ["chrt", "--fifo", "1", "codex", "exec", "prompt"],
            ["sudo", "-E", "bash", "-c", "printf safe"],
            ["doas", "-E", "bash", "-c", "printf safe"],
        )
        for argv in dangerous:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks._require_direct_codex_filesystem_sandbox(argv)

        # Normal literal interpreter output and non-agent command data stay
        # permissible through this narrow name-based admission guard.
        for argv in (
            ["python3", "-cprint('safe')"],
            ["python3", "-I", "-cprint('safe')"],
            ["env", "FOO=bar", "cargo", "test"],
            ["bash", "-c", "printf safe"],
        ):
            with self.subTest(allowed=argv):
                tasks._require_direct_codex_filesystem_sandbox(argv)


    def test_busybox_applet_alias_is_checked_at_actual_command_position(self) -> None:
        # A symlinked BusyBox applet uses argv[0] as the applet selector.
        # It does NOT expect an explicit argv[1] applet name.
        alias = self.root / "env"
        alias.symlink_to("/usr/bin/busybox")
        argv = [str(alias), "FOO=bar", "codex", "exec", "prompt"]
        with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
            tasks._require_direct_codex_filesystem_sandbox(argv)

    def test_opaque_launcher_rejected_before_dispatch_or_task_insert(self) -> None:
        # Synthetic task start only. No command is launched.
        for argv in (
            ["systemd-run", "--user", "codex", "exec", "prompt"],
            ["python3", "-cimport os;os.execvp('co'+'dex',['co'+'dex','exec'])"],
        ):
            with (
                self.subTest(argv=argv),
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(tasks, "_validate_command", return_value=argv),
                patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 166}),
                patch.object(tasks, "_dispatch") as dispatch,
                patch.object(tasks, "_launch") as launch,
                patch.object(tasks.resources, "acquire_resources") as acquire,
                patch.object(tasks.base, "_append_audit"),
            ):
                with self.assertRaisesRegex(RuntimeError, "Codex.*filesystem sandbox"):
                    tasks.grabowski_task_start(
                        "local", argv, cwd=str(self.root), runtime_seconds=60
                    )
                dispatch.assert_not_called()
                launch.assert_not_called()
                acquire.assert_not_called()
                with tasks._database_connection() as connection:
                    count = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
                self.assertEqual(count, 0)



    def test_unknown_or_renamed_executable_must_run_below_os_write_boundary(self) -> None:
        # Only build argv: never run a renamed executable, interpreter or agent.
        # Read-only-by-default local tasks may not inherit the host filesystem.
        for executable in ("/usr/bin/true", "/tmp/renamed-codex", "/tmp/opaque-script"):
            with (
                self.subTest(executable=executable),
                patch.object(
                    tasks, "_task_output_paths",
                    return_value={"directory": self.root / "captured"},
                ),
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(
                    tasks, "_verified_task_effect_start",
                    return_value={"effect_profile": "unknown", "agent_executable": None},
                ),
            ):
                captured = tasks._task_output_capture_argv(
                    {
                        "task_id": "opaque-test",
                        "argv_json": json.dumps([executable, "--data"]),
                        "cwd": str(self.root),
                        "host": "local",
                    }
                )
                self.assertIn("/usr/bin/bwrap", captured)
                self.assertIn("--ro-bind", captured)
                self.assertIn(str(self.root), captured)

    def test_nonagent_resume_identity_is_not_mutable_classification(self) -> None:
        original = ["/bin/echo", "original"]
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_validate_command", return_value=original),
            patch.object(tasks, "_dispatch", return_value=fixture._launcher()),
            patch.object(
                tasks, "_require_recovery_gate",
                return_value={"checked_at_unix": 151},
            ),
            patch.object(tasks.base, "_append_audit"),
        ):
            result = tasks.grabowski_task_start(
                "local", original, cwd=str(self.root), runtime_seconds=60,
                effect_profile="read_only",
            )
        task_id = str(result["task"]["task_id"])
        injected = ["/bin/echo", "changed"]
        with tasks._database_connection() as db:
            db.execute(
                "UPDATE tasks SET argv_json=?, argv_sha256=? WHERE task_id=?",
                (
                    tasks._canonical_json(injected),
                    tasks.command_identity.argv_sha256(injected),
                    task_id,
                ),
            )
        with self.assertRaisesRegex(RuntimeError, "original|identity|effect"):
            tasks._verified_task_effect_start(tasks._row_raw(task_id), command=injected)


    def test_write_mount_requires_live_exact_owned_path_lease(self) -> None:
        # A benign binary may write only where the lease grants a mount.
        allowed = self.root / "build"
        allowed.mkdir()
        command = ["/usr/bin/true"]
        record = {
            "task_id": "bounded-write-test",
            "host": "local",
            "cwd": str(self.root),
            "lease_owner_id": "task:bounded-write-test",
            "argv_json": json.dumps(command),
        }
        lease = f"path:{allowed}"
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "workspace_write"},
            ),
            patch.object(tasks, "_record_resource_keys", return_value=[lease]),
            patch.object(
                tasks.resources, "inspect_resources",
                return_value={lease: {"owner_id": "task:bounded-write-test"}},
            ),
        ):
            sandbox = tasks._task_sandboxed_command_argv(record, command)
        position = sandbox.index("--bind")
        self.assertEqual(sandbox[position + 1: position + 3], [str(allowed)] * 2)
        self.assertIn("--ro-bind", sandbox)
        self.assertNotIn("--bind", sandbox[position + 3:])

        for live_owner in (None, "foreign:task"):
            with (
                self.subTest(owner=live_owner),
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(
                    tasks, "_verified_task_effect_start",
                    return_value={"effect_profile": "workspace_write"},
                ),
                patch.object(tasks, "_record_resource_keys", return_value=[lease]),
                patch.object(
                    tasks.resources, "inspect_resources",
                    return_value={lease: {"owner_id": live_owner}},
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "foreign path leases"):
                    tasks._task_sandboxed_command_argv(record, command)

    def test_actual_readonly_bwrap_denies_write_open_without_modifying_contents(self) -> None:
        # Controlled kernel exercise. The test never writes through the opened FD.
        import errno
        import subprocess
        from pathlib import Path

        sandbox = tasks.agent_sandbox
        try:
            sandbox.require_bwrap()
        except sandbox.AgentSandboxError:
            self.skipTest("bubblewrap not installed on this test host")
        target = Path(self.root) / "readonly-probe.txt"
        target.write_text("unchanged", encoding="utf-8")
        code = (
            "import errno,os,sys\n"
            "try:\n"
            " fd=os.open(sys.argv[1],os.O_WRONLY);os.close(fd);sys.exit(27)\n"
            "except OSError as exc:\n"
            " print(exc.errno);sys.exit(0 if exc.errno==errno.EROFS else 26)\n"
        )
        argv = sandbox.runtime_sandbox_argv(
            sandbox.minimal_sandbox_argv(
                workspace=Path(self.root),
                command=["/usr/bin/python3", "-c", code, str(target)],
                workspace_writable=False,
            )
        )
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=20, check=False,
        )
        if completed.returncode != 0 and "No permissions to create" in completed.stderr:
            self.skipTest("kernel does not permit namespaces in this runner")
        self.assertEqual(
            completed.returncode, 0,
            f"missing EROFS: rc={completed.returncode} stdout={completed.stdout} stderr={completed.stderr}",
        )
        self.assertEqual(completed.stdout.strip(), str(errno.EROFS))
        self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")


    def test_local_runtime_executable_gets_exact_read_only_venv_mount(self) -> None:
        venv_root = self.root / "private-runtime"
        runtime = venv_root / "bin" / "python"
        runtime.parent.mkdir(parents=True)
        runtime.write_text("test interpreter placeholder", encoding="utf-8")
        command = [str(runtime), "-I", "-c", "pass"]
        record = {"task_id": "venv-check", "host": "local", "cwd": str(self.root)}
        with (
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", runtime),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            sandbox = tasks._task_sandboxed_command_argv(record, command)
        mounts = [sandbox[i:i + 3] for i in range(len(sandbox) - 2)]
        self.assertIn(["--ro-bind", str(venv_root), str(venv_root)], mounts)
        self.assertNotIn(["--bind", str(venv_root), str(venv_root)], mounts)
        self.assertIn("--clearenv", sandbox)

    def test_linked_git_common_dir_requires_two_way_bounded_backlinks(self) -> None:
        home = self.root / "test-home"
        common = home / "repos" / "owned" / ".git"
        gitdir = common / "worktrees" / "fixture"
        gitdir.mkdir(parents=True)
        workspace = self.root / "workspace"
        workspace.mkdir()
        marker = workspace / ".git"
        marker.write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        (gitdir / "gitdir").write_text(f"{marker}\n", encoding="utf-8")
        (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
        command = ["/usr/bin/true"]
        record = {"task_id": "linked-check", "host": "local", "cwd": str(workspace)}
        with (
            patch.object(tasks.operator, "HOME", home),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "read_only"},
            ),
        ):
            self.assertEqual(tasks._task_linked_git_common_dir(workspace), common)
            argv = tasks._task_sandboxed_command_argv(record, command)
            mounts = [argv[i:i + 3] for i in range(len(argv) - 2)]
            self.assertIn(["--ro-bind", str(common), str(common)], mounts)
            self.assertNotIn(["--bind", str(common), str(common)], mounts)
            (gitdir / "gitdir").write_text(
                str(self.root / "foreign" / ".git") + "\n", encoding="utf-8",
            )
            self.assertIsNone(tasks._task_linked_git_common_dir(workspace))
            rejected = tasks._task_sandboxed_command_argv(record, command)
            denied_mounts = [rejected[i:i + 3] for i in range(len(rejected) - 2)]
            self.assertNotIn(["--ro-bind", str(common), str(common)], denied_mounts)
            (gitdir / "gitdir").write_text(f"{marker}\n", encoding="utf-8")
            honest_marker = workspace / "real-git-marker"
            honest_marker.write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
            marker.unlink()
            marker.symlink_to(honest_marker)
            self.assertIsNone(tasks._task_linked_git_common_dir(workspace))
            marker.unlink()
            marker.write_text("gitdir: " + "x" * 4097, encoding="utf-8")
            self.assertIsNone(tasks._task_linked_git_common_dir(workspace))


    def test_nested_framework_writer_needs_a_scoped_outer_writable_mount(self) -> None:
        """Exercise a real writer process, not only its assembled bwrap argv.

        This fixture synthesizes task lease truth only for command construction.
        It does not establish admission authority for a production task.
        """
        import subprocess
        from pathlib import Path

        try:
            tasks.agent_sandbox.require_bwrap()
        except tasks.agent_sandbox.AgentSandboxError:
            self.skipTest("target-host bubblewrap is unavailable")
        runtime = Path(tasks.GRABOWSKI_RUNTIME_PYTHON)
        if not runtime.is_file():
            self.skipTest("Grabowski runtime Python is unavailable on this host")

        repo = self.root / "writer-kernel-e2e"
        repo.mkdir()
        allowed = repo / "allowed"
        allowed.mkdir()

        def git(*arguments: str) -> str:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), *arguments],
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        git("init", "-b", "topic")
        git(
            "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=Sandbox Test",
            "-c", "user.email=sandbox-test@localhost",
            "commit", "--allow-empty", "-m", "scratch",
        )
        head = git("rev-parse", "HEAD")
        output = allowed / "writer-receipt.json"
        writer = [
            str(runtime), "-m", "grabowski_agent_writer",
            "--repository", str(repo),
            "--expected-base-head", head,
            "--expected-branch", "topic",
            "--allowed-path", "allowed",
            "--output", str(output),
            "--", "/usr/bin/true",
        ]
        record = {
            "task_id": "sandbox-writer-test",
            "host": "local",
            "cwd": str(repo),
            "lease_owner_id": "task:sandbox-writer-test",
        }
        local = {"transport": "local", "target": "local"}

        # Unknown effects never gain write rights from a module name.
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=local),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            read_only = tasks._task_sandboxed_command_argv(record, writer)
        blocked = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(read_only),
            capture_output=True, text=True, timeout=40, check=False,
        )
        if "No permissions to create" in blocked.stderr:
            self.skipTest("target-host kernel disallows user namespaces")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("Read-only file system", blocked.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(git("status", "--porcelain"), "")

        # A synthetic exact live path lease permits the real nested writer
        # and its create-only receipt, without exposing sibling paths.
        lease = f"path:{allowed}"
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=local),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "workspace_write"},
            ),
            patch.object(tasks, "_record_resource_keys", return_value=[lease]),
            patch.object(
                tasks.resources, "inspect_resources",
                return_value={lease: {"owner_id": "task:sandbox-writer-test"}},
            ),
        ):
            confined_writer = tasks._task_sandboxed_command_argv(record, writer)
        completed = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(confined_writer),
            capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(output.is_file())
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("role"), "writer")
        self.assertEqual(payload.get("returncode"), 0)
        self.assertEqual(payload.get("head_before"), payload.get("head_after"))
        self.assertEqual(payload.get("head_before"), head)


    def test_framework_role_receipt_requires_exact_outer_output_mount(self) -> None:
        """A read-only role still needs an independently authorized receipt sink.

        The narrow output lease below is synthetic and does not stand in for
        production task admission or the workspace lifecycle authority.
        """
        import subprocess
        from pathlib import Path
        import grabowski_agent_role as agent_role

        try:
            tasks.agent_sandbox.require_bwrap()
        except tasks.agent_sandbox.AgentSandboxError:
            self.skipTest("target-host bubblewrap is unavailable")
        runtime = Path(tasks.GRABOWSKI_RUNTIME_PYTHON)
        if not runtime.is_file():
            self.skipTest("Grabowski runtime Python is unavailable on this host")

        repo = self.root / "role-kernel-e2e"
        repo.mkdir()
        output_root = repo / "output"
        output_root.mkdir(mode=0o700)

        def git(*arguments: str) -> str:
            result = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), *arguments],
                capture_output=True, text=True, timeout=20, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        git("init", "-b", "topic")
        git(
            "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=Sandbox Test",
            "-c", "user.email=sandbox-test@localhost",
            "commit", "--allow-empty", "-m", "scratch",
        )
        head = git("rev-parse", "HEAD")
        bound_head, diff_digest, dirty = agent_role.current_binding(repo, head)
        self.assertEqual(bound_head, head)
        self.assertFalse(dirty)

        output = output_root / "role-receipt.json"
        command = [
            str(runtime), "-m", "grabowski_agent_role",
            "--role", "tests",
            "--repository", str(repo),
            "--expected-head", head,
            "--expected-base-head", head,
            "--expected-diff-sha256", diff_digest,
            "--expected-dirty", "false",
            "--output", str(output),
            "--", "/usr/bin/true",
        ]
        record = {
            "task_id": "sandbox-role-test",
            "host": "local",
            "cwd": str(repo),
            "lease_owner_id": "task:sandbox-role-test",
        }
        local = {"transport": "local", "target": "local"}

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=local),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            read_only = tasks._task_sandboxed_command_argv(record, command)
        blocked = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(read_only),
            capture_output=True, text=True, timeout=40, check=False,
        )
        if "No permissions to create" in blocked.stderr:
            self.skipTest("target-host kernel disallows user namespaces")
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("Read-only file system", blocked.stderr)
        self.assertFalse(output.exists())

        receipt_lease = f"path:{output_root}"
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=local),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "workspace_write"},
            ),
            patch.object(
                tasks, "_record_resource_keys", return_value=[receipt_lease],
            ),
            patch.object(
                tasks.resources, "inspect_resources",
                return_value={
                    receipt_lease: {"owner_id": "task:sandbox-role-test"}
                },
            ),
        ):
            allowed = tasks._task_sandboxed_command_argv(record, command)
        result = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(allowed),
            capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload.get("role"), "tests")
        self.assertEqual(payload.get("returncode"), 0)
        self.assertEqual(payload.get("head_before"), head)
        self.assertEqual(payload.get("head_after"), head)


    def test_opaque_executor_module_needs_verified_origin(self) -> None:
        """A Python module name cannot itself exempt a local child from bwrap.

        The synthetic classification models an unrecognized task. This test
        does not pretend to establish the reserved executor's server authority.
        """
        command = [
            "/usr/bin/python3",
            "-m",
            "grabowski_bureau_runtime_refresh_executor",
            "--not-an-authorized-intent",
        ]
        record = {
            "task_id": "untrusted-executor-module",
            "host": "local",
            "cwd": str(self.root),
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            try:
                result = tasks._task_sandboxed_command_argv(record, command)
            except (RuntimeError, PermissionError):
                return  # Fail-closed denial is also safe.
        self.assertNotEqual(result, command, "module name alone bypassed bwrap")
        self.assertIn("--ro-bind", result)

    def test_opaque_default_operator_home_is_not_mounted_as_readable_workspace(
        self,
    ) -> None:
        """Default cwd may not disclose an entire operator home to a child."""
        from pathlib import Path

        home = self.root / "operator-home"
        home.mkdir(mode=0o700)
        (home / ".private-fixture").write_text("never expose", encoding="utf-8")
        record = {"task_id": "opaque-home", "host": "local", "cwd": str(home)}
        with (
            patch.object(tasks.operator, "HOME", home),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            sandbox = tasks._task_sandboxed_command_argv(record, ["/usr/bin/true"])
        mounted = [sandbox[i : i + 3] for i in range(len(sandbox) - 2)]
        self.assertFalse(
            ["--ro-bind", str(home), str(home)] in mounted,
            "read-only is not confidential: operator home was disclosed",
        )


    def test_external_role_receipt_is_an_isolated_kernel_mount(self) -> None:
        """A real read-only role can atomically publish only into a fresh
        private output sink outside its read-only Git checkout.

        This proves the kernel boundary, not server task-admission authority.
        """
        import subprocess
        from pathlib import Path
        import grabowski_agent_role as agent_role

        tasks.agent_sandbox.require_bwrap()
        runtime = Path(tasks.GRABOWSKI_RUNTIME_PYTHON)
        self.assertTrue(runtime.is_file(), "runtime venv missing from target host")

        repo = self.root / "isolated-role-source"
        repo.mkdir()
        protected_repo_file = repo / "protected.txt"
        protected_repo_file.write_text("repository is immutable", encoding="utf-8")

        def git(*args: str) -> str:
            completed = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), *args],
                capture_output=True, text=True, timeout=15, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return completed.stdout.strip()

        git("init", "-b", "role-fixture")
        git("add", "--", "protected.txt")
        git(
            "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=Fixture",
            "-c", "user.email=fixture@localhost",
            "commit", "-m", "baseline",
        )
        head = git("rev-parse", "HEAD")
        bound_head, diff_sha256, dirty = agent_role.current_binding(repo, head)
        self.assertEqual(bound_head, head)
        self.assertFalse(dirty)

        state_root = self.root / "private-role-state"
        state_root.mkdir(mode=0o700)
        protected_state_file = state_root / "manifest.json"
        protected_state_file.write_text("controller only", encoding="utf-8")
        receipt_dir = state_root / "one-attempt"
        receipt_dir.mkdir(mode=0o700)
        external_receipt = receipt_dir / "receipt.json"
        sandbox_receipt = Path("/tmp/grabowski-scoped-role-receipt/receipt.json")
        command = [
            str(runtime), "-m", "grabowski_agent_role",
            "--role", "tests", "--repository", str(repo),
            "--expected-head", head,
            "--expected-base-head", head,
            "--expected-diff-sha256", diff_sha256,
            "--expected-dirty", "false",
            "--output", str(sandbox_receipt),
            "--", "/usr/bin/true",
        ]
        runtime_root = runtime.parent.parent
        parents = sorted(
            (parent for parent in runtime_root.parents if parent != Path("/")),
            key=lambda item: (len(item.parts), str(item)),
        )
        kwargs = {
            "workspace": repo,
            "command": command,
            "workspace_writable": False,
            "extra_read_only": ((runtime_root, runtime_root),),
            "extra_directories": tuple(parents),
        }
        # A role may write into its private /tmp, but without a host bind the
        # result disappears with the namespace: this is not a valid receipt.
        no_host_receipt = tasks.agent_sandbox.minimal_sandbox_argv(**kwargs)
        ephemeral = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(no_host_receipt),
            capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertEqual(ephemeral.returncode, 0, ephemeral.stderr)
        self.assertFalse(external_receipt.exists())

        bounded = tasks.agent_sandbox.minimal_sandbox_argv(
            **kwargs,
            extra_read_write_directories=((
                receipt_dir, sandbox_receipt.parent,
            ),),
        )
        self.assertIn(
            ["--bind", str(receipt_dir), str(sandbox_receipt.parent)],
            [bounded[index:index + 3] for index in range(len(bounded) - 2)],
        )
        completed = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(bounded),
            capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(external_receipt.is_file())
        payload = json.loads(external_receipt.read_text(encoding="utf-8"))
        self.assertEqual(payload["role"], "tests")
        self.assertEqual(payload["returncode"], 0)
        self.assertEqual(payload["head_before"], head)
        self.assertEqual(payload["head_after"], head)
        self.assertEqual(git("status", "--porcelain"), "")
        self.assertEqual(
            protected_repo_file.read_text(encoding="utf-8"),
            "repository is immutable",
        )
        self.assertEqual(
            protected_state_file.read_text(encoding="utf-8"),
            "controller only",
        )
        # A reused attempt directory must never silently be bound for another
        # role after its receipt has been written.
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "empty|fresh",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    receipt_dir, sandbox_receipt.parent,
                ),),
            )


    def test_external_receipt_bind_rejects_unsafe_source_or_target(self) -> None:
        """Fail closed on forged external RW sinks and overlapping mounts."""
        from pathlib import Path

        source_workspace = self.root / "read-only-source"
        source_workspace.mkdir()
        state = self.root / "operator-private"
        state.mkdir(mode=0o700)
        fresh = state / "fresh-attempt"
        fresh.mkdir(mode=0o700)
        kwargs = {
            "workspace": source_workspace,
            "command": ["/usr/bin/true"],
            "workspace_writable": False,
        }

        second = state / "second-attempt"
        second.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "one|too many",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=(
                    (fresh, Path("/tmp/grabowski-first-receipt")),
                    (second, Path("/tmp/grabowski-second-receipt")),
                ),
            )

        for unsafe in (
            Path("/etc/receipt"),
            Path("/tmp"),
            Path("/tmp/ordinary-dir"),
            Path("/tmp/grabowski-a/../b"),
        ):
            with self.subTest(target=str(unsafe)):
                with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        **kwargs, extra_read_write_directories=((fresh, unsafe),),
                    )

        nested = source_workspace / "do-not-expose"
        nested.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "overlaps",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    nested, Path("/tmp/grabowski-nested"),
                ),),
            )

        # A writable alias into an independently RO-mounted Git common-dir
        # or runtime tree would defeat the read-only kernel promise.
        git_common = self.root / "git-common"
        git_common.mkdir(mode=0o700)
        git_shadow = git_common / "private-shadow"
        git_shadow.mkdir(mode=0o700)
        with self.assertRaisesRegex(tasks.agent_sandbox.AgentSandboxError, "read-only|overlap"):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                git_common_dir=git_common,
                extra_read_write_directories=((
                    git_shadow, Path("/tmp/grabowski-git-shadow"),
                ),),
            )
        runtime_root = self.root / "readonly-runtime"
        runtime_root.mkdir(mode=0o700)
        runtime_shadow = runtime_root / "private-shadow"
        runtime_shadow.mkdir(mode=0o700)
        with self.assertRaisesRegex(tasks.agent_sandbox.AgentSandboxError, "read-only|overlap"):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_only=((runtime_root, runtime_root),),
                extra_read_write_directories=((
                    runtime_shadow, Path("/tmp/grabowski-runtime-shadow"),
                ),),
            )

        misplaced = state / "not-private"
        misplaced.mkdir(mode=0o755)
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    misplaced, Path("/tmp/grabowski-untrusted"),
                ),),
            )

        link = state / "linked"
        link.symlink_to(fresh, target_is_directory=True)
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    link, Path("/tmp/grabowski-linked"),
                ),),
            )
        missing = state / "missing"
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    missing, Path("/tmp/grabowski-missing"),
                ),),
            )
        parent_link = self.root / "redirected-parent"
        parent_link.symlink_to(state, target_is_directory=True)
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write_directories=((
                    parent_link / "fresh-attempt", Path("/tmp/grabowski-parent-link"),
                ),),
            )

        private_file = state / "protected-credential"
        private_file.write_text("no sibling RW", encoding="utf-8")
        private_file.chmod(0o600)
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "overlaps",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                **kwargs,
                extra_read_write=((
                    private_file, Path("/tmp/grabowski-output/credential"),
                ),),
                extra_read_write_directories=((
                    fresh, Path("/tmp/grabowski-output"),
                ),),
            )


    def test_opaque_home_can_be_invisible_to_real_kernel_child(self) -> None:
        """A default operator-home cwd must be hidden, not merely read-only.

        This exercises an opt-in primitive on the real Linux kernel.
        Separate trusted task admission must later select it for opaque cwd=None.
        """
        from pathlib import Path
        import subprocess

        home = self.root / "opaque-home"
        home.mkdir(mode=0o700)
        private_file = home / "private-token.txt"
        private_file.write_text("operator-only", encoding="utf-8")
        child_code = (
            "import os,sys\n"
            "print(os.getcwd())\n"
            "sys.exit(0 if os.getcwd()=='/tmp' and "
            "not os.path.lexists(sys.argv[1]) else 33)\n"
        )
        sandbox = tasks.agent_sandbox.minimal_sandbox_argv(
            workspace=home,
            command=["/usr/bin/python3", "-I", "-c", child_code, str(private_file)],
            workspace_writable=False,
            mount_workspace=False,
        )
        self.assertNotIn(
            ["--ro-bind", str(home), str(home)],
            [sandbox[i:i + 3] for i in range(len(sandbox) - 2)],
        )
        completed = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(sandbox),
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "/tmp")
        self.assertEqual(private_file.read_text(encoding="utf-8"), "operator-only")

        writable = home / "write"
        writable.mkdir(mode=0o700)
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=home, command=["/usr/bin/true"],
                workspace_writable=True, writable_paths=(writable,),
                mount_workspace=False,
            )
        with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=home, command=["/usr/bin/true"],
                workspace_writable=False, git_common_dir=home,
                mount_workspace=False,
            )


if __name__ == "__main__":
    unittest.main()