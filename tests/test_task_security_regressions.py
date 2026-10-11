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


if __name__ == "__main__":
    unittest.main()
