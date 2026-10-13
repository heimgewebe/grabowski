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



    def test_kernel_sandbox_denies_host_abstract_unix_but_allows_inet(self) -> None:
        """Actual AF_UNIX abstract host-write attempt under an opaque bwrap child.

        AF_INET socket creation must still work for legitimate remote APIs.
        Only a newly created synthetic listener inside this test is contacted.
        """
        import os
        import socket
        import subprocess

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "abstract-namespace-probe"
        workspace.mkdir()
        name = "pr1386-synthetic-abstract-" + str(os.getpid())
        code = (
            "import errno,sys,socket,json\n"
            "tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.close()\n"
            "try:\n"
            " local=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
            " local.connect('\\0'+sys.argv[1])\n"
            " local.sendall(b'SYNTHETIC-ONLY')\n"
            " print(json.dumps({'tcp':'ALLOWED','host_unix':'CONNECTED'}))\n"
            "except OSError as exc:\n"
            " print(json.dumps({'tcp':'ALLOWED','host_unix':'BLOCKED','errno':exc.errno}))\n"
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind("\0" + name)
            listener.listen(1)
            record = {
                "task_id": "opaque-abstract-ipc",
                "host": "local", "cwd": str(workspace),
            }
            with (
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(
                    tasks, "_verified_task_effect_start",
                    return_value={"effect_profile": "unknown"},
                ),
            ):
                argv = tasks._task_sandboxed_command_argv(
                    record, ["/usr/bin/python3", "-I", "-c", code, name],
                )
            result = subprocess.run(
                tasks.agent_sandbox.runtime_sandbox_argv(argv),
                capture_output=True, text=True, check=False, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout.strip())
            if output.get("host_unix") == "CONNECTED":
                listener.settimeout(2)
                with listener.accept()[0] as connection:
                    self.assertEqual(connection.recv(64), b"SYNTHETIC-ONLY")
            self.assertEqual(output["tcp"], "ALLOWED")
            self.assertEqual(output["host_unix"], "BLOCKED")
            self.assertEqual(output.get("errno"), 1)


    def test_untrusted_task_unit_must_restrict_host_abstract_unix_sockets(self) -> None:
        """The real systemd child argv must carry the already E2E-tested gate.

        Bubblewrap shares the host network namespace: --unshare-ipc alone does
        not block abstract AF_UNIX. Unlike a synthetic systemd property check,
        this verifies that output capture launches the *filtered* bwrap child.
        The independent kernel test proves that its filter actually denies
        AF_UNIX; this assertion binds that binary path to the task unit.
        """
        identifier = "a" * 24
        argv = ["/usr/bin/true"]
        record = {
            "task_id": identifier,
            "host": "local",
            "unit": tasks._task_unit(identifier, 1),
            "authoritative_unit": tasks._task_unit(identifier, 1),
            "argv_json": tasks._canonical_json(argv),
            "argv_sha256": tasks.command_identity.argv_sha256(argv),
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
            patch.object(
                tasks, "_task_output_paths",
                return_value={"directory": self.root / "captured"},
            ),
        ):
            captured = tasks._task_output_capture_argv(record)
        sandbox = tasks.agent_sandbox
        expected_prefix = [
            sandbox.SANDBOX_LAUNCH_PYTHON, "-I", "-S",
            str(sandbox._host_seccomp_launcher_path()),
            str(sandbox.require_bwrap()),
        ]
        self.assertEqual(captured[5:10], expected_prefix)
        self.assertNotIn("-c", captured)
        self.assertLess(len(captured[8].encode("utf-8")), 4096)
        self.assertEqual(
            sandbox._host_seccomp_launcher_path().read_text(),
            sandbox._HOST_UNIX_DENY_LAUNCH_SOURCE,
        )
        with patch.object(tasks, "_task_output_capture_argv", return_value=captured):
            command = tasks._launch_argv(record, include_managed_runtime=False)
        self.assertEqual(
            command[command.index("--") + 1:],
            tasks.command_identity.systemd_escape_argv(captured),
        )
        self.assertNotIn("--property=RestrictAddressFamilies=AF_UNIX", command)

    def test_runtime_sandbox_rewraps_bare_bwrap_and_rejects_forged_launcher(self) -> None:
        """Legacy bare bwrap callers cannot drop the kernel filter by mistake."""
        sandbox = tasks.agent_sandbox
        resolved = str(sandbox.require_bwrap())
        argv = sandbox.runtime_sandbox_argv(["/untrusted/bwrap", "--version"])
        self.assertEqual(
            argv[:5],
            [sandbox.SANDBOX_LAUNCH_PYTHON, "-I", "-S",
             str(sandbox._host_seccomp_launcher_path()), resolved],
        )
        self.assertEqual(argv[5:], ["--version"])
        with self.assertRaisesRegex(sandbox.AgentSandboxError, "unrecognized"):
            sandbox.runtime_sandbox_argv(
                [sandbox.SANDBOX_LAUNCH_PYTHON, "-c", "print('bypass')"]
            )

    def test_seccomp_script_is_private_content_addressed_and_tamper_fails_closed(self) -> None:
        """The host launcher is staged privately and never trusts a changed file."""
        import hashlib
        import os
        import stat

        sandbox = tasks.agent_sandbox
        with patch.object(sandbox.Path, "home", return_value=self.root):
            script = sandbox._host_seccomp_launcher_path()
            self.assertEqual(
                script.name,
                "seccomp-" + hashlib.sha256(
                    sandbox._HOST_UNIX_DENY_LAUNCH_SOURCE.encode("utf-8")
                ).hexdigest() + ".py",
            )
            self.assertEqual(script.read_text(), sandbox._HOST_UNIX_DENY_LAUNCH_SOURCE)
            self.assertEqual(stat.S_IMODE(script.lstat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(script.parent.lstat().st_mode), 0o700)
            self.assertEqual(sandbox._host_seccomp_launcher_path(), script)
            script.write_text("raise SystemExit(0)\n")
            with self.assertRaisesRegex(sandbox.AgentSandboxError, "identity drifted"):
                sandbox.runtime_sandbox_argv(["/untrusted/bwrap", "--version"])
            script.unlink()
            os.symlink(self.root / "foreign.py", script)
            with self.assertRaisesRegex(sandbox.AgentSandboxError, "cannot be staged"):
                sandbox.runtime_sandbox_argv(["/untrusted/bwrap", "--version"])


    def test_kernel_seccomp_inherits_into_exec_and_blocks_raw_socket_bypass(self) -> None:
        """A second exec and high-domain-bit raw syscalls keep the kernel ban."""
        import os
        import subprocess

        if os.uname().machine not in {"x86_64", "aarch64"}:
            self.skipTest("raw socket syscall numbers need a known Linux ABI")
        workspace = self.root / "seccomp-inherited"
        workspace.mkdir()
        code = (
            "import ctypes,json,os,socket,subprocess\n"
            "nr={'x86_64':41,'aarch64':198}[os.uname().machine]\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "ret=libc.syscall(ctypes.c_long(nr),ctypes.c_ulong((1<<32)|1),"
            "ctypes.c_long(socket.SOCK_STREAM),ctypes.c_long(0))\n"
            "failure=ctypes.get_errno()\n"
            "sub=subprocess.run(['/bin/sh','-c',"
            "\"/usr/bin/python3 -I -c 'import socket; socket.socket(socket.AF_UNIX)'\""
            "],capture_output=True,text=True)\n"
            "print(json.dumps({'ret':ret,'errno':failure,"
            "'child_denied':sub.returncode!=0 and '[Errno 1]' in sub.stderr}))\n"
        )
        record = {"task_id": "opaque-raw-syscall", "host": "local", "cwd": str(workspace)}
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_verified_task_effect_start",
                         return_value={"effect_profile": "unknown"}),
        ):
            command = tasks._task_sandboxed_command_argv(
                record, ["/usr/bin/python3", "-I", "-c", code],
            )
        result = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(command),
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        outcome = json.loads(result.stdout.strip())
        self.assertEqual(outcome["ret"], -1)
        self.assertEqual(outcome["errno"], 1)
        self.assertTrue(outcome["child_denied"], outcome)

    def test_kernel_sandbox_blocks_io_uring_async_socket_escape(self) -> None:
        """AF_UNIX socket() filtering must also deny io_uring async socket IO.

        Linux 5.19+ can create sockets via IORING_OP_SOCKET without making a
        socket syscall. Forbid a new ring so the syscall filter is not bypassed.
        This probes the actual kernel rather than a mocked wrapper string.
        """
        import os
        import subprocess

        if os.uname().machine not in {"x86_64", "aarch64"}:
            self.skipTest("io_uring_setup syscall 425 requires a known Linux ABI")
        directory = self.root / "seccomp-io-uring"
        directory.mkdir()
        payload = (
            "import ctypes,json,os\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "params=ctypes.create_string_buffer(256)\n"
            "ret=libc.syscall(ctypes.c_long(425),ctypes.c_uint(2),ctypes.byref(params))\n"
            "errno=ctypes.get_errno()\n"
            "if ret>=0: os.close(ret)\n"
            "print(json.dumps({'ret':ret,'errno':errno}))\n"
        )
        record = {"task_id": "opaque-io-uring", "host": "local", "cwd": str(directory)}
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_verified_task_effect_start",
                         return_value={"effect_profile": "unknown"}),
        ):
            child = tasks._task_sandboxed_command_argv(
                record, ["/usr/bin/python3", "-I", "-c", payload],
            )
        result = subprocess.run(
            tasks.agent_sandbox.runtime_sandbox_argv(child),
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout.strip())
        self.assertEqual(data["ret"], -1, data)
        self.assertEqual(data["errno"], 1, data)


    def test_unavailable_seccomp_library_fails_closed_before_exec(self) -> None:
        """Fault-injected libseccomp absence may not reach bubblewrap or child."""
        import subprocess

        sandbox = tasks.agent_sandbox
        sandbox.require_bwrap()
        candidate = sandbox.minimal_sandbox_argv(
            workspace=self.root,
            command=["/usr/bin/true"],
            workspace_writable=False,
        )
        argv = sandbox.runtime_sandbox_argv(candidate)
        # A separate, explicitly test-only Python script proves the fail-closed
        # behavior without weakening the production digest-bound path.
        fake = self.root / "absent-libseccomp-probe.py"
        fake.write_text(
            sandbox._HOST_UNIX_DENY_LAUNCH_SOURCE.replace(
                "libseccomp.so.2", "pr1386-deliberately-missing-seccomp.so.2"
            )
        )
        argv[3] = str(fake)
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 125, result.stderr)
        self.assertIn("AF_UNIX sandbox enforcement unavailable", result.stderr)
        # Untrusted replacement of the trusted script argument is rejected
        # before the real launcher is dispatched.
        with self.assertRaisesRegex(sandbox.AgentSandboxError, "unrecognized"):
            sandbox.runtime_sandbox_argv(argv)


    def test_kernel_untrusted_child_denies_io_uring_setup(self) -> None:
        """io_uring can submit socket operations outside syscall seccomp gates.

        This synthetic kernel-level regression tests setup denial while keeping
        AF_INET socket creation usable for remote model APIs. No outside host
        sockets or filesystem state are touched.
        """
        import subprocess

        sandbox = tasks.agent_sandbox
        sandbox.require_bwrap()
        directory = self.root / "untrusted-io-uring"
        directory.mkdir()
        code = (
            "import ctypes,os,socket,json\n"
            "tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM);tcp.close()\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "fd=libc.syscall(ctypes.c_long(425),ctypes.c_uint(2),"
            "ctypes.create_string_buffer(256))\n"
            "err=ctypes.get_errno()\n"
            "print(json.dumps({'fd':fd,'errno':err,'inet':'ALLOWED'}))\n"
            "fd>=0 and os.close(fd)\n"
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_verified_task_effect_start",
                         return_value={"effect_profile": "unknown"}),
        ):
            sandbox_argv = tasks._task_sandboxed_command_argv(
                {"task_id": "untrusted-ring", "host": "local", "cwd": str(directory)},
                ["/usr/bin/python3", "-I", "-c", code],
            )
        result = subprocess.run(
            sandbox.runtime_sandbox_argv(sandbox_argv),
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        outcome = json.loads(result.stdout.strip())
        self.assertEqual(outcome["inet"], "ALLOWED")
        self.assertEqual(outcome["fd"], -1, outcome)
        self.assertEqual(outcome["errno"], 1, outcome)


    def test_real_systemd_revoked_lease_stops_live_cgroup(self) -> None:
        """An actual, still-running user-systemd task must stop on lease loss.

        This starts only a bounded synthetic sleep process. Verify the unit
        was active before losing authority, then inactive/dead after stop.
        No mock, production unit, or shared filesystem marker is involved.
        """
        import subprocess
        import uuid

        available = subprocess.run(
            ["systemctl", "--user", "show-environment"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if available.returncode != 0:
            self.skipTest("user systemd bus unavailable; run E2E on Heim-PC")
        identifier = uuid.uuid4().hex[:24]
        unit = tasks._task_unit(identifier, 1)
        launched = subprocess.run(
            ["systemd-run", "--user", "--unit=" + unit,
             "--property=Type=exec",
             "--property=KillMode=control-group",
             "--property=RuntimeMaxSec=12s",
             "--", "/usr/bin/sleep", "12"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(launched.returncode, 0, launched.stderr)
        try:
            deadline = time.monotonic() + 4
            pre_active = False
            while time.monotonic() < deadline:
                observed = subprocess.run(
                    ["systemctl", "--user", "show", unit,
                     "--property=ActiveState", "--property=SubState"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if "ActiveState=active\n" in observed.stdout:
                    pre_active = True
                    break
                time.sleep(0.05)
            self.assertTrue(pre_active, "synthetic unit was never running")
            key = f"path:{self.root / 'revoked-writer-scope'}"
            record = {
                "task_id": identifier, "unit": unit,
                "authoritative_unit": unit, "host": "local",
                "execution_backend": "systemd-user",
                "systemd_scope": "user", "runtime_seconds": 12,
                "lease_owner_id": f"task:{identifier}",
                "resource_keys_json": tasks._canonical_json([key]),
            }
            # The synthetic task is explicitly local, but make test gives
            # this process an isolated HOME without a fleet registry.
            with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
                maintenance = tasks._maintain_record_resources(record, "running")
            self.assertIsNotNone(maintenance)
            self.assertIs(maintenance["maintained"], False)
            self.assertIs(maintenance["stop_verified"], True, maintenance)
            self.assertEqual(maintenance["state_override"], "cancelled")
            after = subprocess.run(
                ["systemctl", "--user", "show", unit,
                 "--property=ActiveState", "--property=SubState",
                 "--property=MainPID"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertIn("ActiveState=inactive\n", after.stdout)
            self.assertIn("SubState=dead\n", after.stdout)
            self.assertIn("MainPID=0\n", after.stdout)
            self.assertIsNone(tasks.resources.inspect_resource(key))
        finally:
            subprocess.run(
                ["systemctl", "--user", "stop", unit],
                capture_output=True, text=True, timeout=15, check=False,
            )


    def test_revoked_running_task_lease_cannot_be_silently_reacquired(self) -> None:
        """A current unit observation is not authority to restore a lost lease.

        This uses a synthetic still-running unit and a real private resource
        database. Revocation must be followed by a verified stop/reconcile,
        never an implicit writable regrant during task_status().
        """
        import sqlite3

        task_id = self._start_claude()
        record = tasks._row_raw(task_id)
        keys = tasks._record_resource_keys(record)
        self.assertTrue(keys)
        with sqlite3.connect(self.fixtures.resource_database) as database:
            database.execute(
                "DELETE FROM leases WHERE resource_key IN ("
                + ",".join("?" for _ in keys) + ")",
                keys,
            )
        self.assertFalse(tasks.resources.inspect_resources(keys))
        observed_running = {
            "state": "running",
            "properties": {
                "LoadState": "loaded",
                "ActiveState": "active",
                "SubState": "running",
                "Result": "success",
            },
            "observer": {"kind": "test", "execution_backend": "systemd-user"},
            "observed_at_unix": tasks._now(),
        }
        with (
            patch.object(tasks, "_observe", return_value=observed_running),
            patch.object(
                tasks.resources, "acquire_resources",
                wraps=tasks.resources.acquire_resources,
            ) as regrant,
            patch.object(tasks.base, "_append_audit"),
        ):
            status = tasks.grabowski_task_status(task_id)
        # Stopping a revoked task may itself acquire a narrow service-unit
        # lease. Only reacquisition of the *revoked writable task keys* is
        # forbidden; a stop-control lease is not a renewed writer grant.
        for call in regrant.call_args_list:
            acquired_keys = call.args[1] if len(call.args) > 1 else []
            self.assertTrue(set(acquired_keys).isdisjoint(keys), acquired_keys)
        maintenance = status["lease_maintenance"]
        self.assertIsInstance(maintenance, dict)
        self.assertIs(maintenance["maintained"], False)
        # A visible, still-running unit with no grant remains a live writer.
        # A failed renewal alone is not a cgroup-stop or reconciliation proof.
        self.assertNotEqual(status["state"], "running")
        self.assertIsNone(tasks.resources.inspect_resource(keys[0]))


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
            "runtime_seconds": 60,
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
                return_value={
                    lease: {
                        "owner_id": "task:bounded-write-test",
                        "expires_at_unix": tasks._now() + 600,
                    }
                },
            ),
        ):
            sandbox = tasks._task_sandboxed_command_argv(record, command)
        position = sandbox.index("--bind")
        self.assertEqual(sandbox[position + 1: position + 3], [str(allowed)] * 2)
        self.assertIn("--ro-bind", sandbox)
        self.assertNotIn("--bind", sandbox[position + 3:])

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_verified_task_effect_start",
                         return_value={"effect_profile": "workspace_write"}),
            patch.object(tasks, "_record_resource_keys", return_value=[lease]),
            patch.object(tasks.resources, "inspect_resources", return_value={
                lease: {
                    "owner_id": "task:bounded-write-test",
                    "expires_at_unix": tasks._now() + 30,
                }
            }),
        ):
            with self.assertRaisesRegex(RuntimeError, "lease lifetime"):
                tasks._task_sandboxed_command_argv(record, command)

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
            # Git backlink inspection must never block when .git is swapped for a FIFO.
            import os
            import subprocess
            import sys
            from pathlib import Path

            marker.unlink()
            os.mkfifo(marker)
            helper_probe = (
                "import sys\n"
                "from pathlib import Path\n"
                "sys.dont_write_bytecode = True\n"
                f"sys.path.insert(0, {str(Path(tasks.__file__).resolve().parent)!r})\n"
                "import grabowski_tasks as tasks\n"
                "print(tasks._task_linked_git_common_dir(Path(sys.argv[1])))\n"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-c", helper_probe, str(workspace)],
                capture_output=True, text=True, check=False, timeout=3,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "None")


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
        protected = repo / "protected.txt"
        protected.write_text("immutable baseline", encoding="utf-8")
        git("add", "--", "protected.txt")
        git(
            "-c", "core.hooksPath=/dev/null",
            "-c", "user.name=Sandbox Test",
            "-c", "user.email=sandbox-test@localhost",
            "commit", "-m", "scratch",
        )
        head = git("rev-parse", "HEAD")
        output = allowed / "writer-receipt.json"
        created = allowed / "created.txt"
        inner_code = (
            "import errno,os,sys\n"
            "try:\n"
            " fd=os.open(sys.argv[1],os.O_WRONLY);os.close(fd);raise RuntimeError('outside writable')\n"
            "except OSError as exc:\n"
            " assert exc.errno==errno.EROFS,exc\n"
            "with open(sys.argv[2],'w',encoding='utf-8') as f:f.write('bounded effect')\n"
        )
        writer = [
            str(runtime), "-m", "grabowski_agent_writer",
            "--repository", str(repo),
            "--expected-base-head", head,
            "--expected-branch", "topic",
            "--allowed-path", "allowed",
            "--output", str(output),
            "--", "/usr/bin/python3", "-I", "-c", inner_code,
            str(protected), str(created),
        ]
        record = {
            "task_id": "sandbox-writer-test",
            "host": "local",
            "cwd": str(repo),
            "lease_owner_id": "task:sandbox-writer-test",
            "runtime_seconds": 60,
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
                return_value={
                    lease: {
                        "owner_id": "task:sandbox-writer-test",
                        "expires_at_unix": tasks._now() + 600,
                    },
                },
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
        self.assertEqual(protected.read_text(encoding="utf-8"), "immutable baseline")
        self.assertEqual(created.read_text(encoding="utf-8"), "bounded effect")
        after = git("status", "--porcelain", "--untracked-files=all")
        self.assertIn("allowed/created.txt", after)
        self.assertNotIn("protected.txt", after)


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
            "runtime_seconds": 60,
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
                    receipt_lease: {
                        "owner_id": "task:sandbox-role-test",
                        "expires_at_unix": tasks._now() + 600,
                    },
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


    def test_opaque_parent_cwd_cannot_expose_entire_operator_home(self) -> None:
        """Actual kernel probe for workspace ancestor mounts, including root.

        A caller-selected parent directory must not be able to expose HOME as
        part of a larger read-only workspace. Synthetic secrets only.
        """
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        home = self.root / "private-operator-home-below-cwd"
        home.mkdir(mode=0o700)
        secret = home / "private.txt"
        secret.write_text("owned-test-secret", encoding="utf-8")
        code = (
            "from pathlib import Path\n"
            "import sys\n"
            "secret=Path(sys.argv[1])\n"
            "print('LEAKED' if secret.is_file() and "
            "secret.read_text(encoding='utf-8')=='owned-test-secret' else 'HIDDEN')\n"
        )
        record = {
            "task_id": "opaque-home-parent",
            "host": "local", "cwd": str(self.root),
        }
        with (
            patch.object(tasks.operator, "HOME", home),
            patch.object(Path, "home", return_value=home),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            try:
                candidate = tasks._task_sandboxed_command_argv(
                    record, ["/usr/bin/python3", "-I", "-c", code, str(secret)],
                )
            except tasks.agent_sandbox.AgentSandboxError as exc:
                self.assertIn("private operator home", str(exc))
            else:
                observed = subprocess.run(
                    tasks.agent_sandbox.runtime_sandbox_argv(candidate),
                    capture_output=True, text=True, check=False, timeout=20,
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertEqual(observed.stdout.strip(), "HIDDEN")

        # Do not bind the real host root in a test. Its policy denial must be
        # verified before kernel execution, using only a synthetic home.
        with patch.object(Path, "home", return_value=home):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "private operator home",
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=Path("/"),
                    command=["/usr/bin/true"], workspace_writable=False,
                )


    def test_opaque_task_cwd_must_not_reveal_private_home_subdirectory(self) -> None:
        """Kernel check: a different cwd is not authority to read operator secrets.

        The fixture changes only self-owned temporary files. Fail-closed
        rejection and an isolated mount with no private source are both safe.
        """
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        home = self.root / "operator-home-private"
        home.mkdir(mode=0o700)
        private_dirs = (
            home / ".ssh",
            home / ".config" / "grabowski",
            home / ".local" / "state" / "grabowski",
        )
        command_code = (
            "from pathlib import Path\n"
            "import sys\n"
            "private=Path(sys.argv[1])\n"
            "print('LEAKED' if private.is_file() and "
            "private.read_text(encoding='utf-8')=='fixture-only' else 'HIDDEN')\n"
        )
        for private in private_dirs:
            private.mkdir(parents=True, mode=0o700)
            secret = private / "secret.txt"
            secret.write_text("fixture-only", encoding="utf-8")
            record = {
                "task_id": "opaque-private-cwd",
                "host": "local", "cwd": str(private),
            }
            with (
                self.subTest(private=str(private)),
                patch.object(tasks.operator, "HOME", home),
                patch.object(Path, "home", return_value=home),
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(
                    tasks, "_verified_task_effect_start",
                    return_value={"effect_profile": "unknown"},
                ),
            ):
                try:
                    candidate = tasks._task_sandboxed_command_argv(
                        record, ["/usr/bin/python3", "-I", "-c", command_code, str(secret)],
                    )
                except tasks.agent_sandbox.AgentSandboxError as exc:
                    self.assertIn("private operator home", str(exc))
                else:
                    observed = subprocess.run(
                        tasks.agent_sandbox.runtime_sandbox_argv(candidate),
                        capture_output=True, text=True, check=False, timeout=20,
                    )
                    self.assertEqual(observed.returncode, 0, observed.stderr)
                    self.assertEqual(observed.stdout.strip(), "HIDDEN")

        # The repository collection root is not itself a bounded checkout;
        # an exact checkout below it remains visible and read-only.
        repositories = home / "repos"
        checkout = repositories / "scoped-checkout"
        checkout.mkdir(parents=True, mode=0o700)
        with (
            patch.object(tasks.operator, "HOME", home),
            patch.object(Path, "home", return_value=home),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks, "_verified_task_effect_start",
                return_value={"effect_profile": "unknown"},
            ),
        ):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "private operator home",
            ):
                tasks._task_sandboxed_command_argv(
                    {"task_id": "opaque-repos-root", "host": "local", "cwd": str(repositories)},
                    ["/usr/bin/true"],
                )
            bounded = tasks._task_sandboxed_command_argv(
                {"task_id": "opaque-checkout", "host": "local", "cwd": str(checkout)},
                ["/usr/bin/true"],
            )
        mounts = [bounded[i:i + 3] for i in range(len(bounded) - 2)]
        self.assertIn(["--ro-bind", str(checkout), str(checkout)], mounts)


    def test_external_role_receipt_is_an_isolated_kernel_mount(self) -> None:
        """A real read-only role can atomically publish only into a fresh
        private output sink outside its read-only Git checkout.

        This proves the kernel boundary, not server task-admission authority.
        """
        import subprocess
        import sys
        from pathlib import Path
        import grabowski_agent_role as agent_role

        tasks.agent_sandbox.require_bwrap()
        # make test isolates HOME; the real selected Python runtime is not below it.
        runtime = Path(sys.executable)
        self.assertTrue(runtime.is_file(), "selected test runtime missing from target host")

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


    def test_external_receipt_directory_rejects_kernel_mount_alias(self) -> None:
        """A private-looking receipt dir may be a bind alias to other host state.

        The mount-root and nested-mount probes are synthetic; the following
        Linux test checks the actual kernel mountinfo representation.
        """
        from pathlib import Path

        workspace = self.root / "receipt-mount-alias-source"
        workspace.mkdir()
        receipt = self.root / "receipt-mount-alias-sink"
        receipt.mkdir(mode=0o700)
        args = {
            "workspace": workspace,
            "command": ["/usr/bin/true"],
            "workspace_writable": False,
            "extra_read_write_directories": (
                (receipt, Path("/tmp/grabowski-scoped-receipt")),
            ),
        }
        for mounted in (receipt, receipt / "nested-mount"):
            with self.subTest(mounted=str(mounted)), patch.object(
                tasks.agent_sandbox, "_kernel_mount_points",
                return_value=frozenset({mounted}),
            ):
                with self.assertRaisesRegex(
                    tasks.agent_sandbox.AgentSandboxError, "mount boundary",
                ):
                    tasks.agent_sandbox.minimal_sandbox_argv(**args)

        # Even read-only host sources may conceal a foreign mount alias;
        # missing mountinfo must now deny all visible host source mounts.
        with patch.object(
            tasks.agent_sandbox, "_kernel_mount_points",
            side_effect=tasks.agent_sandbox.AgentSandboxError("mountinfo unavailable"),
        ):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mountinfo unavailable",
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=workspace, command=["/usr/bin/true"],
                    workspace_writable=False,
                )
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mountinfo unavailable",
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(**args)

    def test_read_only_workspace_must_not_expose_live_host_unix_socket(self) -> None:
        """A ro-bind does not itself grant safe read-only IPC semantics."""
        import socket
        import subprocess

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "synthetic-local-socket-workspace"
        workspace.mkdir()
        endpoint = workspace / "private-control.sock"
        program = (
            "import socket,sys\n"
            "sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
            "try:\n"
            " sock.connect(sys.argv[1])\n"
            " sock.sendall(b'SYNTHETIC-ONLY')\n"
            " print('CONNECTED')\n"
            "except OSError:\n"
            " print('BLOCKED')\n"
            "finally:\n"
            " sock.close()\n"
        )
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint))
            listener.listen(1)
            try:
                argv = tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=workspace,
                    command=["/usr/bin/python3", "-I", "-c", program, str(endpoint)],
                    workspace_writable=False,
                )
            except tasks.agent_sandbox.AgentSandboxError as exc:
                self.assertIn("IPC", str(exc))
                return
            result = subprocess.run(
                tasks.agent_sandbox.runtime_sandbox_argv(argv),
                capture_output=True, text=True, check=False, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            if result.stdout.strip() == "CONNECTED":
                listener.settimeout(2)
                with listener.accept()[0] as client:
                    self.assertEqual(client.recv(64), b"SYNTHETIC-ONLY")
            self.assertEqual(result.stdout.strip(), "BLOCKED")


    def test_read_only_dependencies_must_not_expose_host_ipc(self) -> None:
        """Git metadata and extra read-only directories are also host mounts."""
        import os
        from pathlib import Path

        workspace = self.root / "ipc-dependency-workspace"
        workspace.mkdir()
        common = self.root / "synthetic-git-common"
        common.mkdir()
        auxiliary = self.root / "synthetic-readonly-runtime"
        auxiliary.mkdir()
        for directory, option in (
            (common, {"git_common_dir": common}),
            (auxiliary, {"extra_read_only": ((auxiliary, auxiliary),)}),
        ):
            with self.subTest(source=str(directory)):
                endpoint = directory / "hidden-control.fifo"
                os.mkfifo(endpoint, mode=0o600)
                with self.assertRaisesRegex(
                    tasks.agent_sandbox.AgentSandboxError, "IPC",
                ):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        workspace=workspace,
                        command=["/usr/bin/true"], workspace_writable=False,
                        **option,
                    )
                endpoint.unlink()

        nested = workspace / "nested"
        nested.mkdir()
        os.mkfifo(nested / "hidden-control.fifo", mode=0o600)
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "IPC",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=workspace,
                command=["/usr/bin/true"], workspace_writable=False,
            )


    def test_read_only_mount_sources_reject_same_device_kernel_aliases(self) -> None:
        """Read-only does not mean confidential when a host bind replaces a source."""
        from pathlib import Path

        workspace = self.root / "ro-alias-workspace"
        workspace.mkdir()
        nested = workspace / "foreign-mount"
        nested.mkdir()
        common = self.root / "ro-git-common"
        common.mkdir()
        auxiliary = self.root / "ro-external-library"
        auxiliary.mkdir()
        for source_root, mounted, options in (
            (workspace, workspace, {}),
            (workspace, nested, {}),
            (common, common, {"git_common_dir": common}),
            (
                auxiliary, auxiliary,
                {"extra_read_only": ((auxiliary, auxiliary),)},
            ),
        ):
            with self.subTest(mounted=str(mounted)), patch.object(
                tasks.agent_sandbox, "_kernel_mount_points",
                return_value=frozenset({mounted}),
            ):
                with self.assertRaisesRegex(
                    tasks.agent_sandbox.AgentSandboxError, "mount boundary",
                ):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        workspace=workspace,
                        command=["/usr/bin/true"],
                        workspace_writable=False,
                        **options,
                    )

    def test_real_kernel_read_only_nested_bind_alias_is_rejected(self) -> None:
        """Reject a nested same-device foreign mount in a ro-bound cwd."""
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "ro-nested-alias"
        workspace.mkdir()
        nested = workspace / "foreign-state"
        nested.mkdir()
        outside = self.root / "foreign-secret-state"
        outside.mkdir()
        (outside / "private.txt").write_text(
            "read-only is not confidential", encoding="utf-8"
        )
        self.assertEqual(workspace.stat().st_dev, outside.stat().st_dev)
        module = Path(tasks.agent_sandbox.__file__).resolve(strict=True)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.dont_write_bytecode = True\n"
            "sys.path.insert(0, '/opt')\n"
            "import grabowski_agent_sandbox as sandbox\n"
            "try:\n"
            " sandbox.minimal_sandbox_argv(\n"
            "  workspace=Path('/mnt/ro-nested-alias'),\n"
            "  command=['/usr/bin/true'], workspace_writable=False,\n"
            " )\n"
            "except sandbox.AgentSandboxError as exc:\n"
            " print('REJECTED:' + str(exc))\n"
            "else:\n"
            " print('ACCEPTED')\n"
        )
        outer = [
            str(tasks.agent_sandbox.require_bwrap()),
            "--die-with-parent", "--new-session", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", str(self.root), "/mnt",
            "--bind", str(outside), "/mnt/ro-nested-alias/foreign-state",
            "--ro-bind", str(module), "/opt/grabowski_agent_sandbox.py",
            "--", "/usr/bin/python3", "-I", "-c", script,
        ]
        checked = subprocess.run(
            outer, capture_output=True, text=True, check=False, timeout=40,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("mount boundary", checked.stdout)
        self.assertNotIn("ACCEPTED", checked.stdout)


    def test_read_only_ipc_scan_budget_fails_closed(self) -> None:
        """A huge caller-selected tree cannot bypass bounded prelaunch checks."""
        workspace = self.root / "readonly-budget"
        workspace.mkdir()
        (workspace / "regular.txt").write_text("safe", encoding="utf-8")
        with patch.object(tasks.agent_sandbox, "MAX_READ_ONLY_SCOPE_ENTRIES", 0):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "entry budget",
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=workspace,
                    command=["/usr/bin/true"], workspace_writable=False,
                )


    def test_real_kernel_same_device_receipt_mount_alias_denied(self) -> None:
        """Reject a host receipt sink that is a same-device bind-mount alias."""
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "receipt-kernel-source"
        workspace.mkdir()
        receipt = self.root / "receipt-kernel-sink"
        receipt.mkdir(mode=0o700)
        outside = self.root / "other-private-empty"
        outside.mkdir(mode=0o700)
        self.assertEqual(receipt.stat().st_dev, outside.stat().st_dev)
        sandbox_file = Path(tasks.agent_sandbox.__file__).resolve(strict=True)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.dont_write_bytecode = True\n"
            "sys.path.insert(0, '/opt')\n"
            "import grabowski_agent_sandbox as sandbox\n"
            "try:\n"
            " sandbox.minimal_sandbox_argv(\n"
            "  workspace=Path('/mnt/receipt-kernel-source'),\n"
            "  command=['/usr/bin/true'], workspace_writable=False,\n"
            "  extra_read_write_directories=[(\n"
            "   Path('/mnt/receipt-kernel-sink'),\n"
            "   Path('/tmp/grabowski-scoped-receipt'))],\n"
            " )\n"
            "except sandbox.AgentSandboxError as exc:\n"
            " print('REJECTED:' + str(exc))\n"
            "else:\n"
            " print('ACCEPTED')\n"
        )
        outer = [
            str(tasks.agent_sandbox.require_bwrap()),
            "--die-with-parent", "--new-session",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", str(self.root), "/mnt",
            "--bind", str(outside), "/mnt/receipt-kernel-sink",
            "--ro-bind", str(sandbox_file), "/opt/grabowski_agent_sandbox.py",
            "--", "/usr/bin/python3", "-I", "-c", script,
        ]
        checked = subprocess.run(
            outer, capture_output=True, text=True, check=False, timeout=40,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("mount boundary", checked.stdout)


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
        misplaced.chmod(0o755)  # umask=0077 must not turn this negative fixture private.
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


    def test_extra_mount_targets_reject_parent_traversal(self) -> None:
        """An apparent /tmp path must not remount a protected /etc target."""
        from pathlib import Path

        worktree = self.root / "mount-target-traversal"
        worktree.mkdir()
        private_file = self.root / "mount-private-file"
        private_file.write_text("private", encoding="utf-8")
        private_file.chmod(0o600)
        forged_target = Path("/tmp/../etc/passwd")
        cases = (
            ("read_only", {"extra_read_only": ((private_file, forged_target),)}),
            ("fd_data", {"extra_read_only_data_fds": ((0, forged_target),)}),
            ("read_write", {"extra_read_write": ((private_file, forged_target),)}),
        )
        for kind, extra in cases:
            with self.subTest(kind=kind):
                with self.assertRaises(tasks.agent_sandbox.AgentSandboxError):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        workspace=worktree,
                        command=["/usr/bin/true"],
                        workspace_writable=False,
                        **extra,
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
        # A hidden home must not reappear through another sandbox target.
        private_file.chmod(0o600)
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "hidden workspace",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=home, command=["/usr/bin/true"],
                workspace_writable=False, mount_workspace=False,
                extra_read_only=((private_file, Path("/tmp/grabowski-secret-read")),),
            )
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "hidden workspace",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=home, command=["/usr/bin/true"],
                workspace_writable=False, mount_workspace=False,
                extra_read_write=((private_file, Path("/tmp/grabowski-secret-write")),),
            )


    def test_writable_file_mount_cannot_alias_read_only_sources(self) -> None:
        """Even a private individual file cannot be RW-aliased into a read-only tree."""
        from pathlib import Path

        workspace = self.root / "readonly-source"
        workspace.mkdir()
        git_common = self.root / "readonly-git-common"
        git_common.mkdir()
        runtime_root = self.root / "readonly-runtime"
        runtime_root.mkdir()
        for name, protected_root, options in (
            ("workspace", workspace, {}),
            ("git", git_common, {"git_common_dir": git_common}),
            ("runtime", runtime_root, {
                "extra_read_only": ((runtime_root, runtime_root),),
            }),
        ):
            with self.subTest(source=name):
                private = protected_root / "private.txt"
                private.write_text("unchanged", encoding="utf-8")
                private.chmod(0o600)
                with self.assertRaisesRegex(
                    tasks.agent_sandbox.AgentSandboxError, "read-only|overlap",
                ):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        workspace=workspace,
                        command=["/usr/bin/true"],
                        workspace_writable=False,
                        extra_read_write=((
                            private, Path("/tmp/grabowski-private-file-alias"),
                        ),),
                        **options,
                    )
                self.assertEqual(private.read_text(encoding="utf-8"), "unchanged")


    def test_writable_scope_rejects_cross_device_root_alias(self) -> None:
        """A bounded lease does not attest a mounted alias beneath its workspace."""
        import os
        from pathlib import Path

        workspace = self.root / "device-boundary-workspace"
        workspace.mkdir()
        allowed = workspace / "allowed"
        allowed.mkdir()
        original_stat = Path.stat

        def mounted_root_stat(path: Path, *args: object, **kwargs: object) -> os.stat_result:
            observed = original_stat(path, *args, **kwargs)
            if path != allowed:
                return observed
            fields = list(observed)
            fields[2] = int(observed.st_dev) + 1
            return os.stat_result(fields)

        kwargs = {
            "workspace": workspace,
            "command": ["/usr/bin/true"],
            "workspace_writable": True,
            "writable_paths": (allowed,),
        }
        normal = tasks.agent_sandbox.minimal_sandbox_argv(**kwargs)
        self.assertIn(
            ["--bind", str(allowed), str(allowed)],
            [normal[i:i + 3] for i in range(len(normal) - 2)],
        )
        with patch.object(Path, "stat", mounted_root_stat):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "filesystem boundary"
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(**kwargs)




    def test_nonhome_workspace_does_not_require_a_mounted_operator_home(self) -> None:
        """A nested kernel namespace has no host HOME, but can still attest mounts."""
        from pathlib import Path

        workspace = self.root / "isolated-nonhome-workspace"
        workspace.mkdir()
        absent_home = self.root / "unmounted-operator-home"
        self.assertFalse(absent_home.exists())
        with patch.object(Path, "home", return_value=absent_home):
            argv = tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=workspace, command=["/usr/bin/true"],
                workspace_writable=False,
            )
        self.assertIn(
            ["--ro-bind", str(workspace), str(workspace)],
            [argv[index:index + 3] for index in range(len(argv) - 2)],
        )

    def test_writable_scope_rejects_mount_alias_at_workspace_root(self) -> None:
        """A same-device bind at workspace root is not identity evidence."""
        from pathlib import Path

        workspace = self.root / "alias-worktree-root"
        workspace.mkdir()
        allowed = workspace / "allowed"
        allowed.mkdir()
        with patch.object(
            tasks.agent_sandbox, "_kernel_mount_points",
            return_value=frozenset({workspace}),
        ):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mount boundary",
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=workspace,
                    command=["/usr/bin/true"], workspace_writable=True,
                    writable_paths=(allowed,),
                )

    def test_real_kernel_same_device_workspace_root_alias_denied(self) -> None:
        """Check the actual mountinfo reason, not merely any preflight denial."""
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "real-alias-workspace"
        workspace.mkdir()
        allowed = workspace / "allowed"
        allowed.mkdir()
        unrelated = self.root / "unrelated-same-device"
        unrelated.mkdir()
        (unrelated / "allowed").mkdir()
        self.assertEqual(workspace.stat().st_dev, unrelated.stat().st_dev)
        sandbox_file = Path(tasks.agent_sandbox.__file__).resolve(strict=True)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.dont_write_bytecode = True\n"
            "sys.path.insert(0, '/opt')\n"
            "import grabowski_agent_sandbox as sandbox\n"
            "try:\n"
            " sandbox.minimal_sandbox_argv(\n"
            "  workspace=Path('/mnt/real-alias-workspace'),\n"
            "  command=['/usr/bin/true'], workspace_writable=True,\n"
            "  writable_paths=[Path('/mnt/real-alias-workspace/allowed')],\n"
            " )\n"
            "except sandbox.AgentSandboxError as exc:\n"
            " print('REJECTED:' + str(exc))\n"
            "else:\n"
            " print('ACCEPTED')\n"
        )
        outer = [
            str(tasks.agent_sandbox.require_bwrap()),
            "--die-with-parent", "--new-session", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", str(self.root), "/mnt",
            "--bind", str(unrelated), "/mnt/real-alias-workspace",
            "--ro-bind", str(sandbox_file), "/opt/grabowski_agent_sandbox.py",
            "--", "/usr/bin/python3", "-I", "-c", script,
        ]
        checked = subprocess.run(
            outer, capture_output=True, text=True, check=False, timeout=40,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("mount boundary", checked.stdout)
        self.assertNotIn("ACCEPTED", checked.stdout)


    def test_writable_mountinfo_missing_or_unbounded_fails_closed(self) -> None:
        """Unobservable kernel mount identity denies all visible host mounts."""
        from pathlib import Path

        workspace = self.root / "mountinfo-workspace"
        workspace.mkdir()
        allowed = workspace / "allowed"
        allowed.mkdir()
        kwargs = {
            "workspace": workspace,
            "command": ["/usr/bin/true"],
            "workspace_writable": True,
            "writable_paths": (allowed,),
        }
        with patch("builtins.open", side_effect=OSError("mountinfo missing")):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mount identity is unavailable"
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(**kwargs)
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mount identity is unavailable"
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(
                    workspace=workspace,
                    command=["/usr/bin/true"],
                    workspace_writable=False,
                )
        with patch.object(tasks.agent_sandbox, "MAX_MOUNTINFO_BYTES", 1):
            with self.assertRaisesRegex(
                tasks.agent_sandbox.AgentSandboxError, "mount identity.*budget"
            ):
                tasks.agent_sandbox.minimal_sandbox_argv(**kwargs)


    def test_real_kernel_same_device_bind_mount_is_not_a_writer_scope(self) -> None:
        """An alternate same-device mount root cannot inherit one path lease."""
        import subprocess
        from pathlib import Path

        tasks.agent_sandbox.require_bwrap()
        workspace = self.root / "same device workspace"
        workspace.mkdir()
        allowed = workspace / "allowed"
        allowed.mkdir()
        outside = self.root / "outside-bind-root"
        outside.mkdir()
        (outside / "private.txt").write_text("protected", encoding="utf-8")
        self.assertEqual(workspace.stat().st_dev, outside.stat().st_dev)
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "sys.dont_write_bytecode = True\n"
            "sys.path.insert(0, '/opt')\n"
            "import grabowski_agent_sandbox as sandbox\n"
            "try:\n"
            "    sandbox.minimal_sandbox_argv(\n"
            "        workspace=Path('/mnt/same device workspace'),\n"
            "        command=['/usr/bin/true'], workspace_writable=True,\n"
            "        writable_paths=[Path('/mnt/same device workspace/allowed')],\n"
            "    )\n"
            "except sandbox.AgentSandboxError as exc:\n"
            "    print('REJECTED:' + str(exc))\n"
            "else:\n"
            "    print('ACCEPTED')\n"
        )
        sandbox_module = Path(tasks.agent_sandbox.__file__).resolve(strict=True)
        outer = [
            str(tasks.agent_sandbox.require_bwrap()),
            "--die-with-parent", "--new-session",
            "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--cap-drop", "ALL",
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64",
            "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", str(self.root), "/mnt",
            "--bind", str(outside), "/mnt/same device workspace/allowed",
            "--ro-bind", str(sandbox_module), "/opt/grabowski_agent_sandbox.py",
            "--", "/usr/bin/python3", "-I", "-c", script,
        ]
        run = subprocess.run(
            outer, capture_output=True, text=True, check=False, timeout=40
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("mount boundary", run.stdout)


    def test_git_metadata_must_not_be_a_bounded_writable_path(self) -> None:
        """An owned path lease must not make repository bookkeeping writable."""
        workspace = self.root / "git-metadata-scope"
        workspace.mkdir()
        gitdir = workspace / ".git"
        gitdir.mkdir()
        config = gitdir / "config"
        config.write_text("[core]\\n", encoding="utf-8")
        for target in (gitdir, config):
            with self.subTest(target=str(target)):
                with self.assertRaisesRegex(
                    tasks.agent_sandbox.AgentSandboxError, "Git|git|metadata",
                ):
                    tasks.agent_sandbox.minimal_sandbox_argv(
                        workspace=workspace,
                        command=["/usr/bin/true"],
                        workspace_writable=True,
                        writable_paths=(target,),
                    )
        parent = workspace / "allowed-parent"
        parent.mkdir()
        nested_git = parent / ".git"
        nested_git.mkdir()
        (nested_git / "config").write_text("[core]\\n", encoding="utf-8")
        with self.assertRaisesRegex(
            tasks.agent_sandbox.AgentSandboxError, "Git|git|metadata",
        ):
            tasks.agent_sandbox.minimal_sandbox_argv(
                workspace=workspace,
                command=["/usr/bin/true"],
                workspace_writable=True,
                writable_paths=(parent,),
            )


if __name__ == "__main__":
    unittest.main()
