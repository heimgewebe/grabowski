from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
MODULE_PATH = ROOT / "tools" / "grabowski_privileged_broker.py"
SPEC = importlib.util.spec_from_file_location(
    "grabowski_privileged_broker_peer_test", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("privileged broker tool could not be loaded")
broker_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker_tool)

import grabowski_privileged as privileged_client  # noqa: E402


REAL_SYSTEM_CGROUP_VALIDATOR = broker_tool._validate_system_cgroup_authority


class PrivilegedBrokerPeerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._system_cgroup_patch = mock.patch.object(
            broker_tool, "_validate_system_cgroup_authority", return_value=None
        )
        self._system_cgroup_patch.start()
        self._output_evidence_patch = mock.patch.object(
            broker_tool, "_write_output_evidence",
            return_value={"path": "/run/grabowski/privileged-broker-evidence/test.json", "sha256": "f" * 64},
        )
        self._output_evidence = self._output_evidence_patch.start()
        self._package_stage_lock_patch = mock.patch.object(
            broker_tool, "_package_stage_lock", side_effect=lambda: nullcontext()
        )
        self._package_stage_lock_patch.start()

    def tearDown(self) -> None:
        self._package_stage_lock_patch.stop()
        self._output_evidence_patch.stop()
        self._system_cgroup_patch.stop()

    @staticmethod
    def peer() -> dict[str, object]:
        return {
            "pid": 1234,
            "uid": 1000,
            "gid": 1000,
            "cgroup": "/system.slice/grabowski-operator.service",
            "unit": "grabowski-operator.service",
            "starttime_ticks": 100,
            "cgroup_process_count": 1,
            "systemd_main_pid": 1234,
            "systemd_control_group": "/system.slice/grabowski-operator.service",
        }

    @staticmethod
    def execution() -> dict[str, object]:
        return {
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }

    SERVICE_CGROUP = "/system.slice/grabowski-operator.service"

    OPERATOR_ARGV = (
        "/home/alex/.local/share/grabowski-mcp/.venv/bin/python",
        "-m",
        "grabowski_operator",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    )

    @classmethod
    def unit_identity(
        cls, *, main_pid: int = 1234, control_group: str | None = None
    ) -> dict[str, object]:
        return {
            "main_pid": main_pid,
            "control_group": control_group or cls.SERVICE_CGROUP,
            "active_state": "active",
            "sub_state": "running",
            "username": "alex",
            "home": "/home/alex",
            "fragment_path": "/etc/systemd/system/grabowski-operator.service",
        }

    @staticmethod
    def _write_process(
        proc_root: Path,
        pid: int,
        *,
        parent_pid: int,
        starttime_ticks: int,
        cgroup: str,
    ) -> None:
        process = proc_root / str(pid)
        process.mkdir(parents=True, exist_ok=True)
        (process / "cgroup").write_text(f"0::{cgroup}\n", encoding="utf-8")
        fields = ["S", str(parent_pid), *(["0"] * 17), str(starttime_ticks)]
        (process / "stat").write_text(
            f"{pid} (python worker) " + " ".join(fields) + "\n",
            encoding="utf-8",
        )
        (process / "cmdline").write_bytes(
            b"\x00".join(
                item.encode("utf-8")
                for item in PrivilegedBrokerPeerTests.OPERATOR_ARGV
            )
            + b"\x00"
        )

    @staticmethod
    def _write_cgroup_members(
        cgroup_root: Path, cgroup: str, members: list[int]
    ) -> None:
        target = cgroup_root / cgroup.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        (target / "cgroup.procs").write_text(
            "".join(f"{pid}\n" for pid in members), encoding="utf-8"
        )

    def test_exact_operator_service_main_peer_is_accepted(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(1234, 1000, 1000)
            ):
                result = broker_tool._validate_blockade_lifecycle_peer(
                    self.execution(),
                    proc_root=proc_root,
                    cgroup_root=cgroup_root,
                    unit_identity=self.unit_identity(),
                    expected_argv=self.OPERATOR_ARGV,
                )
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["uid"], 1000)
        self.assertEqual(result["unit"], "grabowski-operator.service")
        self.assertEqual(result["starttime_ticks"], 100)
        self.assertEqual(result["cgroup_process_count"], 1)

    def test_operator_main_peer_remains_valid_with_later_child_present(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 2345, parent_pid=1234, starttime_ticks=200, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234, 2345])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(1234, 1000, 1000)
            ):
                result = broker_tool._validate_blockade_lifecycle_peer(
                    self.execution(),
                    proc_root=proc_root,
                    cgroup_root=cgroup_root,
                    unit_identity=self.unit_identity(),
                    expected_argv=self.OPERATOR_ARGV,
                )
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["cgroup_process_count"], 2)

    def test_equal_oldest_start_ticks_fail_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root,
                1234,
                parent_pid=50,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                2345,
                parent_pid=1234,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                50,
                parent_pid=1,
                starttime_ticks=10,
                cgroup=(
                    "/user.slice/user-1000.slice/user@1000.service/"
                    "init.scope"
                ),
            )
            self._write_cgroup_members(
                cgroup_root, self.SERVICE_CGROUP, [1234, 2345]
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(PermissionError, "ambiguous"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        cgroup_root=cgroup_root,
                        unit_identity=self.unit_identity(),
                        expected_argv=self.OPERATOR_ARGV,
                    )

    def test_same_service_child_peer_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root, 1234, parent_pid=50, starttime_ticks=100, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 2345, parent_pid=1234, starttime_ticks=200, cgroup=self.SERVICE_CGROUP
            )
            self._write_process(
                proc_root, 50, parent_pid=1, starttime_ticks=10, cgroup="/init.scope"
            )
            self._write_cgroup_members(cgroup_root, self.SERVICE_CGROUP, [1234, 2345])
            with mock.patch.object(
                broker_tool, "_socket_peer_credentials", return_value=(2345, 1000, 1000)
            ):
                with self.assertRaisesRegex(PermissionError, "systemd MainPID"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        cgroup_root=cgroup_root,
                        unit_identity=self.unit_identity(main_pid=1234),
                        expected_argv=self.OPERATOR_ARGV,
                    )

    def test_moved_older_same_uid_process_cannot_replace_systemd_main_pid(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root,
                1234,
                parent_pid=50,
                starttime_ticks=200,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                2222,
                parent_pid=60,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_cgroup_members(
                cgroup_root, self.SERVICE_CGROUP, [1234, 2222]
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(2222, 1000, 1000),
            ):
                with self.assertRaisesRegex(PermissionError, "systemd MainPID"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        cgroup_root=cgroup_root,
                        unit_identity=self.unit_identity(main_pid=1234),
                        expected_argv=self.OPERATOR_ARGV,
                    )

    def test_service_membership_drift_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_proc,
            tempfile.TemporaryDirectory() as raw_cgroup,
        ):
            proc_root = Path(raw_proc)
            cgroup_root = Path(raw_cgroup)
            self._write_process(
                proc_root,
                1234,
                parent_pid=50,
                starttime_ticks=100,
                cgroup=self.SERVICE_CGROUP,
            )
            self._write_process(
                proc_root,
                50,
                parent_pid=1,
                starttime_ticks=10,
                cgroup=(
                    "/user.slice/user-1000.slice/user@1000.service/"
                    "init.scope"
                ),
            )
            with (
                mock.patch.object(
                    broker_tool,
                    "_socket_peer_credentials",
                    return_value=(1234, 1000, 1000),
                ),
                mock.patch.object(
                    broker_tool,
                    "_cgroup_processes",
                    side_effect=[(1234,), (1234, 2345)],
                ),
            ):
                with self.assertRaisesRegex(
                    PermissionError, "changed during validation"
                ):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        cgroup_root=cgroup_root,
                        unit_identity=self.unit_identity(),
                        expected_argv=self.OPERATOR_ARGV,
                    )

    def test_same_uid_tmux_peer_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc_root = Path(raw)
            peer = proc_root / "1234"
            peer.mkdir()
            (peer / "cgroup").write_text(
                "0::/user.slice/user-1000.slice/session-9.scope\n",
                encoding="utf-8",
            )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(
                    PermissionError, "outside the operator service"
                ):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        unit_identity=self.unit_identity(),
                        expected_argv=self.OPERATOR_ARGV,
                    )

    def test_root_broker_reads_authoritative_systemd_main_pid(self) -> None:
        account = mock.Mock(pw_name="alex", pw_dir="/home/alex", pw_gid=1000)
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                b"MainPID=1234\n"
                b"ControlGroup=/system.slice/grabowski-operator.service\n"
                b"ActiveState=active\nSubState=running\n"
                b"User=alex\n"
                b"FragmentPath=/etc/systemd/system/grabowski-operator.service\n"
            ),
            stderr=b"",
        )
        fake_stat = mock.Mock(
            st_mode=broker_tool.stat.S_IFREG | 0o644,
            st_uid=0,
            st_gid=0,
        )
        with (
            mock.patch.object(broker_tool.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                broker_tool.subprocess, "run", return_value=completed
            ) as run,
            mock.patch.object(broker_tool.Path, "lstat", return_value=fake_stat),
        ):
            identity = broker_tool._operator_system_unit_identity(
                1000, "grabowski-operator.service"
            )
        self.assertEqual(identity["main_pid"], 1234)
        self.assertEqual(identity["control_group"], self.SERVICE_CGROUP)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["/usr/bin/systemctl", "show"])
        self.assertNotIn("--user", argv)
        self.assertNotIn("--machine=alex@.host", argv)
        self.assertIn("--property=MainPID", argv)
        self.assertIn("--property=FragmentPath", argv)
        self.assertEqual(run.call_args.kwargs["env"], broker_tool.SAFE_ENV)

    def test_user_owned_cgroup_is_never_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "system.slice" / "grabowski-operator.service"
            target.mkdir(parents=True)
            (target / "cgroup.procs").write_text("1234\n", encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "not root-controlled"):
                REAL_SYSTEM_CGROUP_VALIDATOR(
                    self.SERVICE_CGROUP, cgroup_root=root
                )

    def test_blockade_lifecycle_client_preserves_operator_socket_peer(self) -> None:
        response = json.dumps(
            {
                "returncode": 0,
                "timed_out": False,
                "lifecycle": {"operation": "observe", "state": "absent_unproven"},
            },
            sort_keys=True,
        ).encode("utf-8")

        class FakeSocket:
            def __init__(self) -> None:
                self.connected: str | None = None
                self.sent = b""
                self.responses = [response, b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: int) -> None:
                pass

            def connect(self, path: str) -> None:
                self.connected = path

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def shutdown(self, _how: int) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return self.responses.pop(0)

        fake = FakeSocket()
        payload = {
            "operation": "observe",
            "transaction_id": "direct-peer-test",
            "expected_record_sha256": "0" * 64,
            "expected_marker_file_sha256": "0" * 64,
        }
        with (
            mock.patch.object(
                privileged_client,
                "grabowski_privileged_broker_status",
                return_value={"ready": True},
            ),
            mock.patch.object(privileged_client.socket, "socket", return_value=fake),
            mock.patch.object(privileged_client.subprocess, "run") as subprocess_run,
            mock.patch.object(privileged_client, "_write_power_reference") as write_reference,
            mock.patch.object(privileged_client, "_append_operator_audit"),
        ):
            result = privileged_client.run_blockade_lifecycle_reference(
                payload, justification="direct socket identity test"
            )
        subprocess_run.assert_not_called()
        write_reference.assert_not_called()
        self.assertEqual(fake.connected, str(privileged_client.BROKER_SOCKET))
        sent = json.loads(fake.sent.decode("utf-8"))
        self.assertEqual(sent["action"], privileged_client.BLOCKADE_LIFECYCLE_ACTION)
        self.assertEqual(
            sent["target"],
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["broker_client_returncode"], 0)

    def test_power_client_preserves_operator_socket_peer(self) -> None:
        response = json.dumps(
            {
                "returncode": 0,
                "timed_out": False,
                "stdout": "ok",
                "stderr": "",
            },
            sort_keys=True,
        ).encode("utf-8")

        class FakeSocket:
            def __init__(self) -> None:
                self.connected: str | None = None
                self.sent = b""
                self.responses = [response, b""]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: int) -> None:
                pass

            def connect(self, path: str) -> None:
                self.connected = path

            def sendall(self, payload: bytes) -> None:
                self.sent += payload

            def shutdown(self, _how: int) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return self.responses.pop(0)

        fake = FakeSocket()
        with (
            mock.patch.object(
                privileged_client,
                "grabowski_privileged_broker_status",
                return_value={"ready": True},
            ),
            mock.patch.object(
                privileged_client, "_power_recovery_status",
                return_value={
                    "ready_for_user_power_worker": True,
                    "ready_for_privileged_actions": True,
                    "checked_at_unix": 1,
                },
            ),
            mock.patch.object(privileged_client.socket, "socket", return_value=fake),
            mock.patch.object(privileged_client.subprocess, "run") as subprocess_run,
            mock.patch.object(privileged_client, "_write_power_reference") as write_reference,
            mock.patch.object(privileged_client, "_append_operator_audit"),
            mock.patch.object(privileged_client.operator, "_require_operator_mutation"),
        ):
            result = privileged_client.grabowski_power_run(
                ["/usr/bin/true"], justification="direct socket identity test"
            )
        subprocess_run.assert_not_called()
        write_reference.assert_not_called()
        self.assertTrue(result["success"])
        self.assertEqual(fake.connected, str(privileged_client.BROKER_SOCKET))
        sent = json.loads(fake.sent.decode("utf-8"))
        self.assertEqual(sent["action"], privileged_client.POWER_ACTION)

    def test_power_run_rejects_direct_github_merge_before_broker_use(self) -> None:
        with self.assertRaisesRegex(PermissionError, "Captain pr-merge"):
            privileged_client._normalize_power_argv(
                ["/usr/bin/gh", "pr", "merge", "350"]
            )

    def test_blockade_lifecycle_oversize_response_is_outcome_unknown(self) -> None:
        class OversizeSocket:
            def __init__(self) -> None:
                self.responses = [b"x" * 250_001]

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout: int) -> None:
                pass

            def connect(self, _path: str) -> None:
                pass

            def sendall(self, _payload: bytes) -> None:
                pass

            def shutdown(self, _how: int) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return self.responses.pop(0) if self.responses else b""

        with (
            mock.patch.object(
                privileged_client,
                "grabowski_privileged_broker_status",
                return_value={"ready": True},
            ),
            mock.patch.object(
                privileged_client.socket,
                "socket",
                return_value=OversizeSocket(),
            ),
            mock.patch.object(privileged_client, "_append_operator_audit") as audit,
        ):
            result = privileged_client.run_blockade_lifecycle_reference(
                {
                    "operation": "observe",
                    "transaction_id": "oversize-response-test",
                    "expected_record_sha256": "0" * 64,
                    "expected_marker_file_sha256": "0" * 64,
                },
                justification="oversize broker response ambiguity test",
            )
        self.assertFalse(result["success"])
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("response exceeds output limit", result["failure_reason"])
        audit.assert_called_once()
        self.assertEqual(audit.call_args.args[0]["outcome"], "unknown")

    def test_rootbroker_timeout_allows_rollback_grace_before_kill(self) -> None:
        process = mock.Mock()
        process.pid = 4321
        process.communicate.return_value = (b"rolled-back", b"")
        with mock.patch.object(broker_tool.os, "killpg") as killpg:
            observed = broker_tool._communicate_after_timeout(
                action=broker_tool.ROOTBROKER_CUTOVER_ACTION,
                process=process,
            )
        self.assertEqual(observed, (b"rolled-back", b""))
        killpg.assert_called_once_with(4321, signal.SIGTERM)
        process.communicate.assert_called_once_with(
            timeout=broker_tool.ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS
        )

    def test_non_cutover_timeout_remains_immediate_kill(self) -> None:
        process = mock.Mock()
        process.pid = 4321
        process.communicate.return_value = (b"", b"")
        with mock.patch.object(broker_tool.os, "killpg") as killpg:
            broker_tool._communicate_after_timeout(
                action="edit_system_service",
                process=process,
            )
        killpg.assert_called_once_with(4321, signal.SIGKILL)
        process.communicate.assert_called_once_with()

    def test_power_action_missing_peer_uid_fails_closed_before_spawn(self) -> None:
        reference = {
            "request_id": "c" * 32,
            "reference_sha256": "d" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                side_effect=PermissionError("blockade lifecycle peer uid is not configured"),
            ) as validate_peer,
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "peer uid"):
                broker_tool.main()
        validate_peer.assert_called_once_with(execution)
        popen.assert_not_called()

    def test_power_action_without_peer_fields_still_fails_closed_before_spawn(self) -> None:
        reference = {
            "request_id": "c" * 32,
            "reference_sha256": "d" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                side_effect=PermissionError("operator peer identity contract is incomplete"),
            ) as validate_peer,
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "peer identity"):
                broker_tool.main()
        validate_peer.assert_called_once_with(execution)
        popen.assert_not_called()

    def test_power_child_peer_is_rejected_before_process_spawn(self) -> None:
        reference = {
            "request_id": "d" * 32,
            "reference_sha256": "e" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                side_effect=PermissionError("blockade lifecycle peer is not systemd MainPID"),
            ),
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "systemd MainPID"):
                broker_tool.main()
        popen.assert_not_called()

    def test_rootbroker_cutover_timeout_allows_bounded_rollback_before_sigkill(self) -> None:
        reference = {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": broker_tool.ROOTBROKER_CUTOVER_ACTION,
            "target": "c" * 40,
        }
        execution = {
            "mode": "template",
            "argv": [
                "/usr/local/libexec/grabowski-rootbroker-cutover",
                "--expected-head",
                "c" * 40,
            ],
            "cwd": None,
            "timeout_seconds": 2700,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        process = mock.Mock(pid=4242, returncode=2)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(execution["argv"], 2700),
            (b"", b"rolled back"),
        ]
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool, "_validate_blockade_lifecycle_peer", return_value=self.peer()
            ),
            mock.patch.object(broker_tool, "claim_once"),
            mock.patch.object(broker_tool, "append_audit"),
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            mock.patch.object(broker_tool.os, "killpg") as killpg,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(broker_tool.main(), 0)
        self.assertEqual(
            process.communicate.call_args_list,
            [
                mock.call(timeout=2700),
                mock.call(timeout=broker_tool.ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS),
            ],
        )
        killpg.assert_called_once_with(4242, signal.SIGTERM)
        self.assertEqual(broker_tool.ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS, 900)

    def test_power_audit_keeps_raw_digest_root_only_for_unclassified_output(self) -> None:
        reference = {
            "request_id": "9" * 32,
            "reference_sha256": "8" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/printf", "payload"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        raw_stdout = b"secret-candidate\n"
        raw_stderr = b"warn\x00bytes"
        process = mock.Mock(pid=4242, returncode=0)
        process.communicate.return_value = (raw_stdout, raw_stderr)
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        audits: list[dict[str, object]] = []
        self._output_evidence.reset_mock()
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool, "_validate_blockade_lifecycle_peer", return_value=self.peer()
            ),
            mock.patch.object(broker_tool, "claim_once"),
            mock.patch.object(broker_tool, "append_audit", side_effect=lambda record: audits.append(dict(record))),
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            redirect_stdout(io.StringIO()) as captured,
        ):
            self.assertEqual(broker_tool.main(), 0)
        self.assertEqual(len(audits), 1)
        record = audits[0]
        self.assertEqual(record["stdout_sha256"], hashlib.sha256(raw_stdout).hexdigest())
        self.assertEqual(record["stdout_bytes"], len(raw_stdout))
        self.assertEqual(record["stderr_sha256"], hashlib.sha256(raw_stderr).hexdigest())
        self.assertEqual(record["stderr_bytes"], len(raw_stderr))
        self._output_evidence.assert_not_called()
        response = json.loads(captured.getvalue())
        self.assertIsNone(response["output_evidence"])
        for key in ("stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes"):
            self.assertNotIn(key, response["audit"])

    def test_package_output_evidence_classifier_is_narrow(self) -> None:
        root = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT)
        plan = "20260827T010203Z-123456abcdef"
        self.assertTrue(broker_tool._package_output_evidence_allowed([
            "/usr/bin/stat", "-f", "-c", "%a:%S", root
        ]))
        self.assertTrue(broker_tool._package_output_evidence_allowed([
            "/usr/bin/sha256sum",
            f"{root}/{plan}/debs/cursor.deb",
            f"{root}/{plan}/snaps/core.snap",
        ]))
        self.assertFalse(broker_tool._package_output_evidence_allowed(["/usr/bin/printf", "secret"]))
        self.assertFalse(broker_tool._package_output_evidence_allowed(["/usr/bin/sha256sum", "/etc/shadow"]))
        self.assertFalse(broker_tool._package_output_evidence_allowed([
            "/usr/bin/sha256sum", f"{root}/{plan}/debs/nested/file.deb"
        ]))
        self.assertFalse(broker_tool._package_output_evidence_allowed([
            "/usr/bin/sha256sum",
            f"{root}/{plan}/debs/a.deb",
            f"{root}/20260827T010204Z-fedcba654321/debs/b.deb",
        ]))

    def test_package_output_identity_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            home = Path(raw) / "heim-pc"
            stage_root = home / "package-update-stages"
            plan = stage_root / "20260827T010203Z-123456abcdef"
            debs = plan / "debs"
            debs.mkdir(parents=True)
            for directory in (home, stage_root, plan, debs):
                directory.chmod(0o700)
            artifact = debs / "cursor.deb"
            artifact.write_bytes(b"package")
            artifact.chmod(0o600)
            argv = ["/usr/bin/sha256sum", str(artifact)]
            with mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root):
                snapshot = broker_tool._package_output_identity_snapshot(argv)
                self.assertIn(str(artifact), snapshot)
                artifact.unlink()
                artifact.symlink_to("/etc/hosts")
                with self.assertRaisesRegex(PermissionError, "symlink"):
                    broker_tool._package_output_identity_snapshot(argv)
                artifact.unlink()
                source = debs / "source.deb"
                source.write_bytes(b"package")
                source.chmod(0o600)
                os.link(source, artifact)
                with self.assertRaisesRegex(PermissionError, "single-link"):
                    broker_tool._package_output_identity_snapshot(argv)

    def test_power_gate_is_revalidated_after_request_claim_before_spawn(self) -> None:
        reference = {
            "request_id": "4" * 32,
            "reference_sha256": "3" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(
                broker_tool, "resolve_execution",
                side_effect=[execution, PermissionError("power kill-switch is engaged")],
            ) as resolve,
            mock.patch.object(
                broker_tool, "_validate_blockade_lifecycle_peer", return_value=self.peer()
            ),
            mock.patch.object(broker_tool, "claim_once") as claim,
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "kill-switch"):
                broker_tool.main()
        self.assertEqual(resolve.call_count, 2)
        claim.assert_called_once()
        popen.assert_not_called()

    def test_safe_package_readback_publishes_output_evidence(self) -> None:
        reference = {
            "request_id": "6" * 32,
            "reference_sha256": "5" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": [
                "/usr/bin/stat", "-f", "-c", "%a:%S",
                str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT),
            ],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        process = mock.Mock(pid=4242, returncode=0)
        process.communicate.return_value = (b"123:4096\n", b"")
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        self._output_evidence.reset_mock()
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool, "_validate_blockade_lifecycle_peer", return_value=self.peer()
            ),
            mock.patch.object(broker_tool, "claim_once"),
            mock.patch.object(broker_tool, "append_audit"),
            mock.patch.object(
                broker_tool, "_package_output_identity_snapshot",
                return_value={"stage": (1, 2, 3)},
            ) as identity_snapshot,
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            redirect_stdout(io.StringIO()) as captured,
        ):
            self.assertEqual(broker_tool.main(), 0)
        self.assertEqual(identity_snapshot.call_count, 2)
        self._output_evidence.assert_called_once()
        response = json.loads(captured.getvalue())
        self.assertEqual(response["output_evidence"]["sha256"], "f" * 64)
        self.assertNotIn("stdout_sha256", response["audit"])

    def test_output_evidence_is_content_hashed_and_group_read_only(self) -> None:
        self._output_evidence_patch.stop()
        try:
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw) / "evidence"
                record: dict[str, object] = {
                    "schema_version": 1,
                    "timestamp_unix": 123,
                    "request_id": "7" * 32,
                    "reference_sha256": "6" * 64,
                    "action": broker_tool.POWER_ACTION,
                    "mode": "argv-json",
                    "argv_sha256": "5" * 64,
                    "cwd_sha256": "4" * 64,
                    "peer_uid": 1000,
                    "peer_unit": "grabowski-operator.service",
                    "returncode": 0,
                    "timed_out": False,
                    "stdout_sha256": hashlib.sha256(b"abc\n").hexdigest(),
                    "stdout_bytes": 4,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
                with (
                    mock.patch.object(broker_tool, "OUTPUT_EVIDENCE_ROOT", root),
                    mock.patch.object(
                        broker_tool.grp, "getgrnam",
                        return_value=mock.Mock(gr_gid=root.parent.stat().st_gid),
                    ),
                ):
                    published = broker_tool._write_output_evidence(record)
                destination = Path(published["path"])
                value = json.loads(destination.read_text(encoding="utf-8"))
                digest = value.pop("evidence_sha256")
                self.assertEqual(digest, broker_tool.canonical_sha256(value))
                self.assertEqual(published["sha256"], digest)
                self.assertEqual(value["stdout_sha256"], record["stdout_sha256"])
                self.assertEqual(value["stdout_bytes"], 4)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o640)
                self.assertEqual(root.stat().st_mode & 0o777, 0o750)
                self.assertEqual(destination.stat().st_gid, root.parent.stat().st_gid)
                self.assertEqual(root.stat().st_gid, root.parent.stat().st_gid)
        finally:
            self._output_evidence_patch = mock.patch.object(
                broker_tool, "_write_output_evidence",
                return_value={"path": "/run/grabowski/privileged-broker-evidence/test.json", "sha256": "f" * 64},
            )
            self._output_evidence = self._output_evidence_patch.start()

    def test_rootbroker_action_name_requires_peer_validation_even_if_execution_fields_missing(self) -> None:
        reference = {
            "request_id": "1" * 32,
            "reference_sha256": "2" * 64,
            "action": broker_tool.ROOTBROKER_CUTOVER_ACTION,
            "target": "a" * 40,
        }
        execution = {
            "mode": "template",
            "argv": ["/usr/bin/true"],
            "cwd": None,
            "timeout_seconds": 5,
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                side_effect=PermissionError("operator peer identity contract is incomplete"),
            ) as validate_peer,
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "peer identity"):
                broker_tool.main()
        validate_peer.assert_called_once_with(execution)
        popen.assert_not_called()

    def test_peer_bound_template_rejects_non_main_peer_before_spawn(self) -> None:
        reference = {
            "request_id": "f" * 32,
            "reference_sha256": "0" * 64,
            "action": "operator_rootbroker_cutover",
            "target": "a" * 40,
        }
        execution = {
            "mode": "template",
            "argv": [
                "/usr/local/libexec/grabowski-rootbroker-cutover",
                "--expected-head",
                "a" * 40,
            ],
            "cwd": None,
            "timeout_seconds": 600,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        fake_stdin = mock.Mock()
        fake_stdin.buffer = io.BytesIO(b"{}")
        with (
            mock.patch.object(broker_tool.os, "geteuid", return_value=0),
            mock.patch.object(broker_tool.sys, "stdin", fake_stdin),
            mock.patch.object(broker_tool, "parse_reference", return_value=reference),
            mock.patch.object(broker_tool, "load_root_config", return_value={}),
            mock.patch.object(broker_tool, "resolve_execution", return_value=execution),
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                side_effect=PermissionError("blockade lifecycle peer is not systemd MainPID"),
            ),
            mock.patch.object(broker_tool.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(PermissionError, "systemd MainPID"):
                broker_tool.main()
        popen.assert_not_called()

    @staticmethod
    def reference() -> dict[str, object]:
        return {
            "request_id": "a" * 32,
            "reference_sha256": "b" * 64,
            "action": "operator_blockade_lifecycle",
            "target": "{}",
        }

    @staticmethod
    def lifecycle_execution() -> dict[str, object]:
        return {
            "mode": "blockade-marker-lifecycle",
            "internal_action": "blockade-marker-migrate",
            "operation": "migrate",
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }

    def test_lifecycle_audit_intent_precedes_mutation_and_completion(self) -> None:
        events: list[str] = []
        records: list[dict[str, object]] = []

        def append(record: dict[str, object]) -> None:
            records.append(dict(record))
            events.append("audit:" + str(record["phase"]))

        def execute(_execution: dict[str, object]) -> dict[str, object]:
            events.append("mutation")
            return {"operation": "migrate", "receipt_sha256": "c" * 64}

        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(broker_tool, "append_audit", side_effect=append),
            mock.patch.object(broker_tool, "execute_lifecycle", side_effect=execute),
            redirect_stdout(io.StringIO()),
        ):
            result = broker_tool._run_blockade_lifecycle(
                self.reference(), self.lifecycle_execution(), peer=self.peer()
            )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["audit:intent", "mutation", "audit:complete"])
        self.assertEqual(records[1]["intent_record_sha256"], records[0]["record_sha256"])

    def test_lifecycle_failure_is_audited_after_durable_intent(self) -> None:
        events: list[str] = []
        records: list[dict[str, object]] = []

        def append(record: dict[str, object]) -> None:
            records.append(dict(record))
            events.append("audit:" + str(record["phase"]))

        def execute(_execution: dict[str, object]) -> dict[str, object]:
            events.append("mutation")
            raise PermissionError("injected lifecycle failure")

        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(broker_tool, "append_audit", side_effect=append),
            mock.patch.object(broker_tool, "execute_lifecycle", side_effect=execute),
        ):
            with self.assertRaisesRegex(PermissionError, "injected"):
                broker_tool._run_blockade_lifecycle(
                    self.reference(), self.lifecycle_execution(), peer=self.peer()
                )

        self.assertEqual(events, ["audit:intent", "mutation", "audit:failure"])
        self.assertEqual(records[1]["intent_record_sha256"], records[0]["record_sha256"])
        self.assertEqual(records[1]["error_type"], "PermissionError")

    def test_lifecycle_intent_failure_prevents_mutation(self) -> None:
        execute = mock.Mock()
        with (
            mock.patch.object(
                broker_tool,
                "_validate_blockade_lifecycle_peer",
                return_value={
                    "pid": 1,
                    "uid": 1000,
                    "gid": 1000,
                    "cgroup": "/grabowski-operator.service",
                    "unit": "grabowski-operator.service",
                },
            ),
            mock.patch.object(broker_tool, "claim_once", return_value=None),
            mock.patch.object(
                broker_tool,
                "append_audit",
                side_effect=OSError("audit unavailable"),
            ),
            mock.patch.object(broker_tool, "execute_lifecycle", execute),
        ):
            with self.assertRaisesRegex(OSError, "audit unavailable"):
                broker_tool._run_blockade_lifecycle(
                    self.reference(), self.lifecycle_execution(), peer=self.peer()
                )
        execute.assert_not_called()

    def test_wrong_uid_and_unobservable_cgroup_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            proc_root = Path(raw)
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1001, 1001),
            ):
                with self.assertRaisesRegex(PermissionError, "UID"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        unit_identity=self.unit_identity(),
                        expected_argv=self.OPERATOR_ARGV,
                    )
            with mock.patch.object(
                broker_tool,
                "_socket_peer_credentials",
                return_value=(1234, 1000, 1000),
            ):
                with self.assertRaisesRegex(PermissionError, "not observable"):
                    broker_tool._validate_blockade_lifecycle_peer(
                        self.execution(),
                        proc_root=proc_root,
                        unit_identity=self.unit_identity(),
                        expected_argv=self.OPERATOR_ARGV,
                    )


    def test_package_stage_operation_requires_exact_dpkg_files(self) -> None:
        plan_id = "20260827T010203Z-123456abcdef"
        deb = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "a.deb")

        preflight_argv = broker_tool._expected_package_dpkg_preflight_argv([deb])
        preflight = broker_tool._package_stage_operation(preflight_argv)
        self.assertEqual(preflight["kind"], "preflight")
        self.assertEqual(preflight["operation"], "apt_preflight")
        self.assertEqual(preflight["plan_id"], plan_id)
        self.assertEqual(preflight["package_paths"], [deb])
        self.assertIs(preflight["exact_evidence"], True)

        apply_argv = broker_tool._expected_package_apt_systemd_argv(plan_id, [deb])
        self.assertIn("--property=PrivateNetwork=yes", apply_argv)
        self.assertIn("--property=ProtectProc=invisible", apply_argv)
        self.assertNotIn("--property=ProcSubset=pid", apply_argv)
        self.assertNotIn("--property=PrivateDevices=yes", apply_argv)
        self.assertIn("--property=DevicePolicy=closed", apply_argv)
        self.assertNotIn("--property=DeviceAllow=block-* r", apply_argv)
        self.assertIn("--property=DeviceAllow=/dev/nvme0n1p3 r", apply_argv)
        self.assertIn("--property=DeviceAllow=/dev/nvme0n1p1 r", apply_argv)
        self.assertIn("--property=ProtectKernelTunables=yes", apply_argv)
        self.assertNotIn("--property=ProtectKernelModules=yes", apply_argv)
        self.assertTrue(
            any(
                value.startswith("--property=CapabilityBoundingSet=")
                and "CAP_SYS_MODULE" in value
                for value in apply_argv
            )
        )
        self.assertIn("--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK", apply_argv)
        self.assertIn("--property=IPAddressDeny=any", apply_argv)
        operation = broker_tool._package_stage_operation(apply_argv)
        self.assertEqual(operation["kind"], "apply")
        self.assertEqual(operation["operation"], "apt_apply")
        self.assertEqual(operation["plan_id"], plan_id)
        self.assertEqual(operation["package_paths"], [deb])
        self.assertIs(operation["exact_evidence"], True)

        with self.assertRaisesRegex(PermissionError, "exact released simulation"):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--log", "--dry-run", "--install", deb,
            ])

        missing_wait = list(apply_argv)
        missing_wait.remove("--wait")
        with self.assertRaisesRegex(PermissionError, "exact synchronous local APT apply"):
            broker_tool._package_stage_operation(missing_wait)

        remote_wrapper = list(apply_argv)
        remote_wrapper.insert(2, "--host=example.invalid")
        with self.assertRaisesRegex(PermissionError, "exact synchronous local APT apply"):
            broker_tool._package_stage_operation(remote_wrapper)

        noncanonical = (
            str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT)
            + "//"
            + plan_id
            + "/debs/a.deb"
        )
        self.assertTrue(broker_tool._argv_mentions_package_stage([noncanonical]))
        with self.assertRaises(PermissionError):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--simulate", "--refuse-downgrade",
                "--force-confold", "--install", noncanonical,
            ])

        lexical_escape = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT) + "/../outside.deb"
        self.assertTrue(broker_tool._argv_mentions_package_stage([lexical_escape]))
        with self.assertRaises(PermissionError):
            broker_tool._package_stage_operation([
                "/usr/bin/dpkg", "--simulate", "--refuse-downgrade",
                "--force-confold", "--install", lexical_escape,
            ])

    def test_package_sha256_output_is_exact_path_bound(self) -> None:
        plan_id = "20260827T010203Z-123456abcdef"
        first = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "a.deb")
        second = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "b.deb")
        argv = ["/usr/bin/sha256sum", first, second]
        stdout = ("a" * 64 + "  " + first + "\n" + "b" * 64 + "  " + second + "\n").encode()
        self.assertEqual(
            broker_tool._parse_package_sha256_output(argv, stdout),
            {first: "a" * 64, second: "b" * 64},
        )
        with self.assertRaisesRegex(ValueError, "requested argv order"):
            broker_tool._parse_package_sha256_output(
                argv,
                ("b" * 64 + "  " + second + "\n" + "a" * 64 + "  " + first + "\n").encode(),
            )

    def test_package_apply_evidence_rehash_rejects_changed_stage_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            stage_root = root / "stages"
            evidence_root = root / "evidence"
            stage_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            plan_id = "20260827T010203Z-123456abcdef"
            deb_dir = stage_root / plan_id / "debs"
            deb_dir.mkdir(parents=True, mode=0o700)
            deb = deb_dir / "a.deb"
            deb.write_bytes(b"trusted-bytes")
            deb.chmod(0o600)
            digest = hashlib.sha256(deb.read_bytes()).hexdigest()
            evidence = {
                "schema_version": 1,
                "kind": broker_tool.OUTPUT_EVIDENCE_KIND,
                "request_id": "a" * 32,
                "peer_uid": os.geteuid(),
                "peer_unit": "grabowski-operator.service",
                "timestamp_unix": int(broker_tool.time.time()),
                "package_plan_id": plan_id,
                "package_paths": [str(deb)],
                "package_sha256": {str(deb): digest},
            }
            evidence["evidence_sha256"] = broker_tool.canonical_sha256(evidence)
            evidence_path = evidence_root / "proof.json"
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            evidence_path.chmod(0o640)
            operation = {
                "kind": "apply", "plan_id": plan_id,
                "package_paths": [str(deb)], "exact_evidence": True,
            }
            with (
                mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root),
                mock.patch.object(broker_tool, "OUTPUT_EVIDENCE_ROOT", evidence_root),
            ):
                selected = broker_tool._find_package_apply_evidence(
                    operation, peer_uid=os.geteuid(), peer_unit="grabowski-operator.service"
                )
                self.assertEqual(selected["evidence_sha256"], evidence["evidence_sha256"])
                deb.write_bytes(b"replayed-different-bytes")
                with self.assertRaisesRegex(PermissionError, "changed after authenticated hash readback"):
                    broker_tool._find_package_apply_evidence(
                        operation, peer_uid=os.geteuid(), peer_unit="grabowski-operator.service"
                    )

    def test_package_apply_plan_wide_evidence_accepts_operation_subset(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            stage_root = root / "stages"
            evidence_root = root / "evidence"
            stage_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            plan_id = "20260827T010203Z-123456abcdef"
            deb_dir = stage_root / plan_id / "debs"
            snap_dir = stage_root / plan_id / "snaps"
            deb_dir.mkdir(parents=True, mode=0o700)
            snap_dir.mkdir(parents=True, mode=0o700)
            deb = deb_dir / "a.deb"
            snap = snap_dir / "a.snap"
            deb.write_bytes(b"deb")
            snap.write_bytes(b"snap")
            deb.chmod(0o600)
            snap.chmod(0o600)
            paths = [str(deb), str(snap)]
            hashes = {
                path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for path in paths
            }
            evidence = {
                "schema_version": 1,
                "kind": broker_tool.OUTPUT_EVIDENCE_KIND,
                "request_id": "b" * 32,
                "peer_uid": os.geteuid(),
                "peer_unit": "grabowski-operator.service",
                "timestamp_unix": int(broker_tool.time.time()),
                "package_plan_id": plan_id,
                "package_paths": paths,
                "package_sha256": hashes,
            }
            evidence["evidence_sha256"] = broker_tool.canonical_sha256(evidence)
            proof = evidence_root / "proof.json"
            proof.write_text(json.dumps(evidence), encoding="utf-8")
            proof.chmod(0o640)
            operation = {
                "kind": "apply",
                "operation": "apt_apply",
                "plan_id": plan_id,
                "package_paths": [str(deb)],
                "exact_evidence": True,
            }
            with (
                mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root),
                mock.patch.object(broker_tool, "OUTPUT_EVIDENCE_ROOT", evidence_root),
            ):
                selected = broker_tool._find_package_apply_evidence(
                    operation,
                    peer_uid=os.geteuid(),
                    peer_unit="grabowski-operator.service",
                )
            self.assertEqual(selected["evidence_sha256"], evidence["evidence_sha256"])

    def test_package_apply_revalidates_evidence_under_lock_before_spawn(self) -> None:
        events: list[str] = []
        operation = {
            "kind": "apply",
            "operation": "snap_install",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/snaps/a.snap"
            ],
            "exact_evidence": True,
        }

        class Lock:
            def __enter__(self):
                events.append("lock-enter")
            def __exit__(self, exc_type, exc, tb):
                events.append("lock-exit")

        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"", b"")

        def evidence(*args, **kwargs):
            events.append("evidence")
            return {
                "evidence_sha256": "c" * 64,
                "request_id": "d" * 32,
                "timestamp_unix": int(broker_tool.time.time()),
            }

        def replay_check(*args, **kwargs):
            events.append("replay-check")
            return {"binding": "ok"}

        def consume(*args, **kwargs):
            events.append("consume")
            return {"path": "/state/consumed.json", "sha256": "a" * 64}

        def popen(*args, **kwargs):
            events.append("popen")
            return process

        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", side_effect=lambda: Lock()),
            mock.patch.object(broker_tool, "_find_package_apply_evidence", side_effect=evidence),
            mock.patch.object(broker_tool, "_assert_package_apply_not_consumed", side_effect=replay_check),
            mock.patch.object(broker_tool, "_consume_package_apply", side_effect=consume),
            mock.patch.object(broker_tool.subprocess, "Popen", side_effect=popen),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(
            events,
            ["lock-enter", "evidence", "replay-check", "popen", "consume", "lock-exit"],
        )
        self.assertEqual(result["record"]["package_apply_evidence_sha256"], "c" * 64)
        self.assertEqual(result["record"]["package_apply_consumed_sha256"], "a" * 64)
        self.assertEqual(result["output_evidence_status"], "published")
        self._output_evidence.assert_called_once()

    def test_package_apply_consumption_blocks_exact_replay_only_after_success_marker(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "state"
            stage_root = root / "stages"
            consumed_root = state / "package-update-apply-consumed"
            stage_root.mkdir(mode=0o700)
            plan_id = "20260827T010203Z-123456abcdef"
            snap = stage_root / plan_id / "snaps" / "a.snap"
            snap.parent.mkdir(parents=True, mode=0o700)
            snap.write_bytes(b"snap")
            snap.chmod(0o600)
            operation = {
                "kind": "apply",
                "operation": "snap_install",
                "plan_id": plan_id,
                "package_paths": [str(snap)],
                "exact_evidence": True,
            }
            guard = {"evidence_sha256": "a" * 64}
            install_argv = ["/usr/bin/snap", "install", str(snap)]
            ack_argv = ["/usr/bin/snap", "ack", str(snap)]
            with (
                mock.patch.object(broker_tool, "STATE", state),
                mock.patch.object(broker_tool, "PACKAGE_UPDATE_STAGE_ROOT", stage_root),
                mock.patch.object(
                    broker_tool,
                    "PACKAGE_UPDATE_APPLY_CONSUMED_ROOT",
                    consumed_root,
                ),
            ):
                binding = broker_tool._assert_package_apply_not_consumed(
                    operation,
                    guard_evidence=guard,
                    argv=install_argv,
                )
                broker_tool._consume_package_apply(binding)
                with self.assertRaisesRegex(PermissionError, "already consumed"):
                    broker_tool._assert_package_apply_not_consumed(
                        operation,
                        guard_evidence=guard,
                        argv=install_argv,
                    )
                distinct = broker_tool._assert_package_apply_not_consumed(
                    operation,
                    guard_evidence=guard,
                    argv=ack_argv,
                )
                self.assertNotEqual(
                    broker_tool._package_apply_consumption_path(binding),
                    broker_tool._package_apply_consumption_path(distinct),
                )

    def test_apt_apply_requires_exact_guard_bound_preflight_evidence(self) -> None:
        plan_id = "20260827T010203Z-123456abcdef"
        deb = str(broker_tool.PACKAGE_UPDATE_STAGE_ROOT / plan_id / "debs" / "a.deb")
        operation = {
            "kind": "apply",
            "operation": "apt_apply",
            "plan_id": plan_id,
            "package_paths": [deb],
            "exact_evidence": True,
        }
        guard = {
            "evidence_sha256": "a" * 64,
            "timestamp_unix": 100,
        }
        preflight = {
            "evidence_sha256": "b" * 64,
            "request_id": "c" * 32,
            "package_preflight_completed": True,
            "package_operation": "apt_preflight",
            "package_exact_evidence": True,
            "package_plan_id": plan_id,
            "package_paths": [deb],
            "package_preflight_guard_evidence_sha256": "a" * 64,
            "argv_sha256": broker_tool._argv_sha256(
                broker_tool._expected_package_dpkg_preflight_argv([deb])
            ),
            "peer_uid": 1000,
            "peer_unit": "grabowski-operator.service",
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "timestamp_unix": 101,
        }
        with (
            mock.patch.object(
                broker_tool,
                "_package_evidence_candidates",
                return_value=[Path("/evidence/preflight.json")],
            ),
            mock.patch.object(
                broker_tool,
                "_read_package_output_evidence",
                return_value=preflight,
            ),
            mock.patch.object(broker_tool.time, "time", return_value=102),
        ):
            selected = broker_tool._find_package_preflight_evidence(
                operation,
                guard_evidence=guard,
                peer_uid=1000,
                peer_unit="grabowski-operator.service",
            )
            self.assertEqual(selected["evidence_sha256"], "b" * 64)
            bad = dict(preflight)
            bad["package_operation"] = "snap_install"
            with mock.patch.object(
                broker_tool,
                "_read_package_output_evidence",
                return_value=bad,
            ):
                with self.assertRaisesRegex(PermissionError, "no fresh authenticated"):
                    broker_tool._find_package_preflight_evidence(
                        operation,
                        guard_evidence=guard,
                        peer_uid=1000,
                        peer_unit="grabowski-operator.service",
                    )

    def test_failed_package_apply_does_not_consume_guard_operation(self) -> None:
        operation = {
            "kind": "apply",
            "operation": "snap_install",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/snaps/a.snap"
            ],
            "exact_evidence": True,
        }
        process = mock.Mock(returncode=1)
        process.communicate.return_value = (b"", b"failed")
        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", return_value=nullcontext()),
            mock.patch.object(
                broker_tool,
                "_find_package_apply_evidence",
                return_value={
                    "evidence_sha256": "a" * 64,
                    "request_id": "b" * 32,
                    "timestamp_unix": int(broker_tool.time.time()),
                },
            ),
            mock.patch.object(
                broker_tool,
                "_assert_package_apply_not_consumed",
                return_value={"binding": "ok"},
            ),
            mock.patch.object(broker_tool, "_consume_package_apply") as consume,
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertEqual(result["returncode"], 1)
        consume.assert_not_called()
        self.assertEqual(result["output_evidence_status"], "unavailable")

    def test_truncated_stderr_blocks_public_output_evidence(self) -> None:
        operation = {
            "kind": "preflight",
            "operation": "apt_preflight",
            "plan_id": "20260827T010203Z-123456abcdef",
            "package_paths": [
                "/var/lib/heim-pc/package-update-stages/20260827T010203Z-123456abcdef/debs/a.deb"
            ],
            "exact_evidence": True,
        }
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (
            b"",
            b"x" * (broker_tool.MAX_OUTPUT_BYTES + 1),
        )
        reference = {
            "request_id": "e" * 32,
            "reference_sha256": "f" * 64,
            "action": broker_tool.POWER_ACTION,
            "target": "{}",
        }
        execution = {
            "mode": "argv-json",
            "argv": ["/usr/bin/true"],
            "cwd": "/",
            "timeout_seconds": 5,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
        }
        with (
            mock.patch.object(broker_tool, "_package_stage_operation", return_value=operation),
            mock.patch.object(broker_tool, "_package_stage_lock", return_value=nullcontext()),
            mock.patch.object(
                broker_tool,
                "_find_package_apply_evidence",
                return_value={
                    "evidence_sha256": "a" * 64,
                    "request_id": "b" * 32,
                    "timestamp_unix": int(broker_tool.time.time()),
                },
            ),
            mock.patch.object(broker_tool.subprocess, "Popen", return_value=process),
            mock.patch.object(broker_tool, "append_audit"),
        ):
            result = broker_tool._execute_broker_command(
                reference=reference,
                execution=execution,
                operator_peer=self.peer(),
            )
        self.assertIs(result["record"]["stderr_truncated"], True)
        self.assertEqual(result["output_evidence_status"], "unavailable")
        self._output_evidence.assert_not_called()


if __name__ == "__main__":
    unittest.main()
