"""Provider-free regression tests for root-only RAB one-shot primitive.

These exercise the CAS state machine, NOT root-owned installation, socket
broker integration, or permission to execute a model.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


_MODULE = (
    Path(__file__).resolve().parents[1] / "tools" / "grabowski_rab_provider_one_shot.py"
)
_spec = importlib.util.spec_from_file_location("rab_once", _MODULE)
assert _spec is not None and _spec.loader is not None
once = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(once)


def _policy() -> dict:
    return {
        "schema_version": 1,
        "epoch_sha256": "a" * 64,
        "pair_id": "rab-sixcase:finalizer:r1",
        "service_unit": "grabowski-rab-rabpilot.service",
        "invocation_id": "b" * 32,
        "main_cmdline_sha256": "c" * 64,
        "source_manifest_sha256": "d" * 64,
        "runtime_code_sha256": "e" * 64,
        "codex_binary_sha256": "f" * 64,
        "mode": "chatgpt_subscription",
        "provider": "openai-codex-cli",
        "model": "gpt-6-astra",
        "reasoning": "medium",
        "max_exec": 2,
        "positions": [
            {
                "arm": "treatment",
                "index": 0,
                "request_sha256": "1" * 64,
                "slot_id": "2" * 64,
            },
            {
                "arm": "baseline",
                "index": 1,
                "request_sha256": "3" * 64,
                "slot_id": "4" * 64,
            },
        ],
    }


def _request(policy: dict, index: int) -> dict:
    return {
        "epoch_sha256": policy["epoch_sha256"],
        "pair_id": policy["pair_id"],
        **policy["positions"][index],
    }


class FrozenGrantPolicyTests(unittest.TestCase):
    def test_lone_surrogate_pair_is_typed_denial(self) -> None:
        p = _policy()
        p["pair_id"] = "\ud800"
        with self.assertRaisesRegex(once.ProviderGrantDenied, "pair identity invalid"):
            once._validate_policy(p)

    def test_exact_epoch_and_pair_contract(self) -> None:
        p = _policy()
        self.assertIs(once._validate_policy(p), p)
        self.assertEqual(once._position(p, _request(p, 0))["arm"], "treatment")
        self.assertEqual(once._position(p, _request(p, 1))["arm"], "baseline")

    def test_reject_adversarial_fields(self) -> None:
        import copy

        modifications = (
            lambda p: p.update(model="gpt-6.1-sol"),
            lambda p: p.update(provider="openai-api-payg"),
            lambda p: p.update(mode="api"),
            lambda p: p.update(reasoning="high"),
            lambda p: p.update(max_exec=True),
            lambda p: p.update(max_exec=3),
            lambda p: p.update(service_unit="grabowski-operator.service"),
            lambda p: p.update(invocation_id="0" * 64),
            lambda p: p.update(codex_binary_sha256="invalid"),
            lambda p: p.update(schema_version=True),
            lambda p: p.update(extra_auth=True),
            lambda p: p["positions"].pop(),
            lambda p: p["positions"][1].update(arm="treatment"),
            lambda p: p["positions"][1].update(arm=[]),
            lambda p: p["positions"][1].update(index=0),
            lambda p: p["positions"][0].update(slot_id="4" * 64),
            lambda p: p["positions"][1].update(request_sha256="not-sha"),
            lambda p: p["positions"][1].update(request_sha256="1" * 64),
        )
        for mutate in modifications:
            p = copy.deepcopy(_policy())
            mutate(p)
            with self.subTest(p=p), self.assertRaises(once.ProviderGrantDenied):
                once._validate_policy(p)

    def test_request_cannot_change_identity_or_position(self) -> None:
        p = _policy()
        for key, value in (
            ("epoch_sha256", "0" * 64),
            ("pair_id", "different"),
            ("arm", "baseline"),
            ("index", 1),
            ("index", True),
            ("request_sha256", "0" * 64),
            ("slot_id", "0" * 64),
        ):
            request = _request(p, 0)
            request[key] = value
            with self.subTest(key=key), self.assertRaises(once.ProviderGrantDenied):
                once._position(p, request)
        request = _request(p, 0)
        request["extra"] = "allow"
        with self.assertRaises(once.ProviderGrantDenied):
            once._position(p, request)


class TrustedKernelPeerTests(unittest.TestCase):
    def test_wrong_pid_invocation_cgroup_or_runtime_rejected(self) -> None:
        p = _policy()
        peer = 12114
        g = "/system.slice/" + p["service_unit"]
        observed = {
            "MainPID": str(peer),
            "ActiveState": "active",
            "ControlGroup": g,
            "InvocationID": p["invocation_id"],
            "DynamicUser": "yes",
            "UID": "1999",
            "Type": "exec",
            "NotifyAccess": "none",
            "PIDFile": "",
        }
        cmdline = b"python3\0-I\0-B\0"
        p["main_cmdline_sha256"] = once._sha(cmdline)
        once._attest_service(
            p, peer, 1999, observed, ("0::" + g + "\n").encode(), cmdline
        )
        for change in (
            "MainPID",
            "ActiveState",
            "ControlGroup",
            "InvocationID",
            "DynamicUser",
            "UID",
            "Type",
            "NotifyAccess",
            "PIDFile",
        ):
            different = dict(observed)
            different[change] = "wrong"
            with (
                self.subTest(change=change),
                self.assertRaises(once.ProviderGrantDenied),
            ):
                once._attest_service(
                    p, peer, 1999, different, ("0::" + g + "\n").encode(), cmdline
                )
        with self.assertRaises(once.ProviderGrantDenied):
            once._attest_service(p, peer, 1999, observed, b"0::/user.slice\n", cmdline)
        with self.assertRaises(once.ProviderGrantDenied):
            once._attest_service(
                p, peer, 1999, observed, ("0::" + g + "\n").encode(), b"other"
            )
        with self.assertRaises(once.ProviderGrantDenied):
            once._attest_service(
                p, peer, 0, observed, ("0::" + g + "\n").encode(), cmdline
            )

    def test_systemd_mainpid_cannot_be_reassigned_by_notify_or_pidfile(self) -> None:
        policy = _policy()
        peer = 12114
        group = "/system.slice/" + policy["service_unit"]
        cmdline = b"python3\0-I\0-B\0"
        policy["main_cmdline_sha256"] = once._sha(cmdline)
        trusted = {
            "MainPID": str(peer),
            "ActiveState": "active",
            "ControlGroup": group,
            "InvocationID": policy["invocation_id"],
            "DynamicUser": "yes",
            "UID": "1999",
            "Type": "exec",
            "NotifyAccess": "none",
            "PIDFile": "",
        }
        cgroup = ("0::" + group + "\n").encode()
        for key, value in (
            ("Type", "forking"),
            ("Type", "notify"),
            ("Type", "oneshot"),
            ("NotifyAccess", "all"),
            ("NotifyAccess", "exec"),
            ("NotifyAccess", "main"),
            ("PIDFile", "/run/fake-main.pid"),
            ("PIDFile", "/run/user/1000/writable.pid"),
            ("Type", ""),
            ("NotifyAccess", ""),
        ):
            changed = dict(trusted)
            changed[key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaisesRegex(
                    once.ProviderGrantDenied, "trusted Systemd MainPID"
                ):
                    once._attest_service(policy, peer, 1999, changed, cgroup, cmdline)
        for key in ("Type", "NotifyAccess", "PIDFile"):
            changed = dict(trusted)
            del changed[key]
            with self.subTest(missing=key):
                with self.assertRaises(once.ProviderGrantDenied):
                    once._attest_service(policy, peer, 1999, changed, cgroup, cmdline)

    def test_pid1_service_observation_includes_immutable_notify_contract(self) -> None:
        metadata = {
            "MainPID": "12114",
            "ActiveState": "active",
            "ControlGroup": "/system.slice/grabowski-rab-rabpilot.service",
            "InvocationID": "b" * 32,
            "DynamicUser": "yes",
            "UID": "1999",
            "Type": "exec",
            "NotifyAccess": "none",
            "PIDFile": "",
        }
        output = "".join(f"{key}={value}\n" for key, value in metadata.items())
        with mock.patch.object(
            once.subprocess, "run", return_value=mock.Mock(stdout=output)
        ) as proc:
            self.assertEqual(
                once._service_observation("grabowski-rab-rabpilot.service"), metadata
            )
            argv = proc.call_args.args[0]
            self.assertIn("Type", argv[-2])
            self.assertIn("NotifyAccess", argv[-2])
            self.assertIn("PIDFile", argv[-2])
        missing_pidfile_line = output.replace("PIDFile=\n", "")
        with (
            mock.patch.object(
                once.subprocess,
                "run",
                return_value=mock.Mock(stdout=missing_pidfile_line),
            ),
            self.assertRaisesRegex(once.ProviderGrantDenied, "metadata incomplete"),
        ):
            once._service_observation("grabowski-rab-rabpilot.service")

    def test_procfs_file_reader_bounds_bytes_before_allocating_all(self) -> None:
        current_pid = os.getpid()
        with self.assertRaisesRegex(once.ProviderGrantDenied, "exceeds bound"):
            once._read_proc_bounded(current_pid, "cmdline", 1)
        original = Path("/proc/self/cmdline").read_bytes()
        self.assertEqual(
            once._read_proc_bounded(current_pid, "cmdline", 16384), original
        )
        with self.assertRaises(once.ProviderGrantDenied):
            once._read_proc_bounded(current_pid, "environ", 1)

    def test_procfs_short_read_never_becomes_a_trusted_prefix(self) -> None:
        current_pid = os.getpid()
        with mock.patch.object(
            once.os, "read", side_effect=[b"allow", b"ed", b""]
        ) as read:
            self.assertEqual(
                once._read_proc_bounded(current_pid, "cmdline", 16384), b"allowed"
            )
            self.assertEqual(read.call_count, 3)
        with mock.patch.object(once.os, "read", side_effect=[b"a", b"b", b"c"]):
            with self.assertRaisesRegex(once.ProviderGrantDenied, "exceeds bound"):
                once._read_proc_bounded(current_pid, "cmdline", 1)

    def test_peer_credentials_come_from_kernel_not_payload(self) -> None:
        if os.getuid() == 0:
            self.skipTest("only rootless test of kernel peer UID")
        s1, s2 = socket.socketpair()
        try:
            self.assertEqual(once._peer_credentials(s1)[:2], (os.getpid(), os.getuid()))
            with self.assertRaises(once.ProviderGrantDenied):
                once._peer_credentials("user-supplied-PID")
        finally:
            s1.close()
            s2.close()


class BoundedJsonTests(unittest.TestCase):
    def test_deeply_nested_near_full_packet_is_rejected_before_parser(self) -> None:
        levels = once._MAX_BYTES // 2 - 2
        payload = b"[" * levels + b"0" + b"]" * levels
        self.assertLessEqual(len(payload), once._MAX_BYTES)
        with self.assertRaisesRegex(once.ProviderGrantDenied, "nesting budget"):
            once._bounded_json_object(payload)

    def test_quoted_brackets_and_escaped_quotes_do_not_increase_depth(self) -> None:
        request = {
            "pair_id": '[[]]{\\\\\\" nested not brackets',
            "nested": {"value": ["ok", "brackets } ] { ["]},
        }
        self.assertEqual(
            once._bounded_json_object(json.dumps(request).encode()),
            request,
        )

    def test_utf16_utf32_bom_and_malformed_utf8_are_denied(self) -> None:
        for raw in (
            json.dumps({"a": 1}).encode("utf-16"),
            json.dumps({"a": 1}).encode("utf-32"),
            b'{"k":"\xff"}',
        ):
            with self.subTest(raw=raw[:12]):
                with self.assertRaisesRegex(once.ProviderGrantDenied, "UTF-8"):
                    once._bounded_json_object(raw)

    def test_duplicate_keys_and_nonfinite_json_are_denied(self) -> None:
        for raw in (
            b'{"outcome":"failed","outcome":"provider_completed"}',
            b'{"nested":{"a":1,"a":2}}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":-Infinity}',
            b'{"value":1e999}',
            b'{"value":-1e999}',
            b'{"nested":{"value":1e999}}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(once.ProviderGrantDenied):
                    once._bounded_json_object(raw)

    def test_root_json_parser_rejects_scalar_or_truncated_object(self) -> None:
        for raw in (b"true", b"{}", b'{"open": [1,2}', b'"scalar"'):
            if raw == b"{}":
                self.assertEqual(once._bounded_json_object(raw), {})
            else:
                with self.assertRaises(once.ProviderGrantDenied):
                    once._bounded_json_object(raw)


class KernelMessageSenderTests(unittest.TestCase):
    """Real kernel packets: SO_PEERCRED alone must never establish sender PID."""

    def setUp(self) -> None:
        self.receiver, self.sender = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        self.addCleanup(self.receiver.close)
        self.addCleanup(self.sender.close)
        # Install PASSCRED before a child sends so the kernel always emits
        # per-message evidence, even when the packet is queued before recvmsg.
        self.receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

    def test_matching_original_peer_and_packet_sender(self) -> None:
        p = _policy()
        req = _request(p, 0)
        self.sender.sendall(json.dumps(req).encode())
        received, identity = once._receive_authenticated_request(self.receiver)
        self.assertEqual(req, received)
        self.assertEqual(identity, (os.getpid(), os.getuid(), os.getgid()))

    def test_inherited_fd_child_sender_is_denied(self) -> None:
        """A child really sends, but SO_PEERCRED still reports its parent."""
        original_peer = once._peer_credentials(self.receiver)
        sent = json.dumps(_request(_policy(), 0))
        child = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "import socket,sys; s=socket.socket(fileno=int(sys.argv[1]));"
                "s.sendall(sys.argv[2].encode()); s.close()",
                str(self.sender.fileno()),
                sent,
            ],
            check=True,
            capture_output=True,
            timeout=5,
            pass_fds=(self.sender.fileno(),),
        )
        self.assertEqual(child.returncode, 0)
        self.assertEqual(original_peer[0], os.getpid())
        with self.assertRaisesRegex(
            once.ProviderGrantDenied,
            "inherited/forwarded socket sender",
        ):
            once._receive_authenticated_request(self.receiver)

    def test_stream_without_packet_boundaries_is_denied(self) -> None:
        a, b = socket.socketpair()
        try:
            with self.assertRaisesRegex(once.ProviderGrantDenied, "SOCK_SEQPACKET"):
                once._receive_authenticated_request(a)
        finally:
            a.close()
            b.close()

    def test_invalid_json_and_non_object_rejected(self) -> None:
        for data in (b"not-json", b"[]"):
            with self.subTest(data=data):
                self.sender.sendall(data)
                with self.assertRaisesRegex(
                    once.ProviderGrantDenied, "not JSON|not an object"
                ):
                    once._receive_authenticated_request(self.receiver)

    def test_deeply_nested_json_is_typed_denial_not_recursion_crash(self) -> None:
        payload = b"[" * 1400 + b"0" + b"]" * 1400
        self.sender.sendall(payload)
        with self.assertRaisesRegex(once.ProviderGrantDenied, "not JSON"):
            once._receive_authenticated_request(self.receiver)

    def test_oversized_single_packet_denied(self) -> None:
        self.sender.sendall(b"x" * (once._MAX_BYTES + 1))
        with self.assertRaisesRegex(once.ProviderGrantDenied, "oversized"):
            once._receive_authenticated_request(self.receiver)

    def test_rights_attachment_denied_without_consuming_request(self) -> None:
        fd = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            self.sender.sendmsg(
                [json.dumps(_request(_policy(), 0)).encode()],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))],
            )
        finally:
            os.close(fd)
        with self.assertRaises(once.ProviderGrantDenied):
            once._receive_authenticated_request(self.receiver)


class StablePeerPidfdTests(unittest.TestCase):
    def test_live_peer_pidfd_matches_exact_kernel_process(self) -> None:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            try:
                pinned = once._open_peer_pidfd(a, os.getpid())
            except once.ProviderGrantDenied as exc:
                self.skipTest(f"host lacks stable kernel PIDFD identity: {exc}")
            else:
                os.close(pinned)
            with self.assertRaises(once.ProviderGrantDenied):
                once._open_peer_pidfd(a, 1)
        finally:
            a.close()
            b.close()

    def test_legacy_shared_anon_inode_must_fail_closed(self) -> None:
        from types import SimpleNamespace

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            fake = SimpleNamespace(st_dev=1, st_ino=1)
            with (
                mock.patch.object(once.os, "fstat", return_value=fake),
                self.assertRaisesRegex(
                    once.ProviderGrantDenied, "does not match the live MainPID"
                ),
            ):
                once._open_peer_pidfd(a, os.getpid())
        finally:
            a.close()
            b.close()

    def test_other_live_pid_does_not_match_original_socket_peer(self) -> None:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        other = subprocess.Popen(
            [sys.executable, "-B", "-c", "import time;time.sleep(3)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with self.assertRaises(once.ProviderGrantDenied):
                once._open_peer_pidfd(a, other.pid)
        finally:
            other.terminate()
            other.wait(timeout=5)
            a.close()
            b.close()

    def test_unverified_architecture_denied_before_kernel_option(self) -> None:
        from types import SimpleNamespace

        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with (
                mock.patch.object(
                    once.os,
                    "uname",
                    return_value=SimpleNamespace(sysname="Linux", machine="sparc64"),
                ),
                self.assertRaisesRegex(
                    once.ProviderGrantDenied, "stable kernel PID identity unavailable"
                ),
            ):
                once._open_peer_pidfd(a, os.getpid())
        finally:
            a.close()
            b.close()

    def test_reaped_peer_cannot_be_reidentified_by_reused_number(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rab-pidfd-listen-") as root:
            sockpath = str(Path(root) / "c.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                listener.bind(sockpath)
                listener.listen(1)
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        "import socket,sys; s=socket.socket(socket.AF_UNIX,"
                        "socket.SOCK_SEQPACKET);s.connect(sys.argv[1]);"
                        "s.sendall(b'queued');s.close()",
                        sockpath,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                _, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0, stderr)
                accepted, _ = listener.accept()
                try:
                    self.assertEqual(once._peer_credentials(accepted)[0], child.pid)
                    with self.assertRaises(once.ProviderGrantDenied):
                        once._open_peer_pidfd(accepted, child.pid)
                finally:
                    accepted.close()
            finally:
                listener.close()


class AtomicRootStateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rab-provider-free-")
        self.addCleanup(self.tmp.cleanup)
        self.fd = os.open(self.tmp.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.fd)
        self.policy = _policy()
        self.peer = (2255, 1999, 1999)

    def _consume(self, index: int) -> dict:
        return once._consume_position(
            self.fd, self.policy, _request(self.policy, index), self.peer
        )

    def _first_spent_sha(self) -> str:
        return once._digest(
            {
                "epoch": self.policy["epoch_sha256"],
                "pair": self.policy["pair_id"],
                "position": self.policy["positions"][0],
            }
        )

    def _first_receipt(self) -> dict:
        first = self.policy["positions"][0]
        return {
            "kind": "rab.root_first_arm_outcome_receipt",
            "schema_version": 1,
            "epoch_sha256": self.policy["epoch_sha256"],
            "policy_sha256": once._digest(self.policy),
            "pair_id": self.policy["pair_id"],
            "first_token_sha256": self._first_spent_sha(),
            "arm": first["arm"],
            "slot_id": first["slot_id"],
            "request_sha256": first["request_sha256"],
            "service_unit": self.policy["service_unit"],
            "invocation_id": self.policy["invocation_id"],
            "provider": self.policy["provider"],
            "model": self.policy["model"],
            "outcome": "provider_completed",
            "codex_exec_process_count": 1,
            "provider_output_sha256": "5" * 64,
            "usage_receipt_sha256": "6" * 64,
        }

    def _release(self, *, valid: bool = True, receipt: dict | None = None) -> dict:
        return {
            "kind": "rab.second_position_release",
            "schema_version": 1,
            "pair_id": self.policy["pair_id"],
            "slot_id": self.policy["positions"][1]["slot_id"],
            "first_token_sha256": self._first_spent_sha(),
            "first_receipt_sha256": (
                once._digest(self._first_receipt() if receipt is None else receipt)
                if valid
                else "corrupt"
            ),
        }

    def test_first_consumed_at_most_once_and_persisted(self) -> None:
        result = self._consume(0)
        self.assertEqual(result["status"], "consumed")
        self.assertEqual(result["arm"], "treatment")
        record = Path(self.tmp.name, "spent-" + result["token_sha256"] + ".json")
        self.assertTrue(record.is_file())
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(record.read_text())["request_sha256"], "1" * 64)
        with self.assertRaisesRegex(once.ProviderGrantDenied, "already consumed"):
            self._consume(0)
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 1)

    def test_fifo_input_is_immediately_denied_without_writer(self) -> None:
        target = Path(self.tmp.name, "fifo.json")
        os.mkfifo(target, mode=0o600)
        with self.assertRaises(once.ProviderGrantDenied):
            once._read_root_file(self.fd, target.name)

    def test_second_without_root_release_is_denied(self) -> None:
        self._consume(0)
        with self.assertRaisesRegex(
            once.ProviderGrantDenied, "independent root release"
        ):
            self._consume(1)
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 1)

    def _root_file_simulator(
        self,
        release: dict,
        first_receipt: dict | None = None,
        *,
        missing_receipt: bool = False,
    ):
        # Synthetic root-owned read: public broker path is still not installed.
        def read(_state_fd: int, filename: str) -> dict:
            if filename.startswith("release-"):
                return release
            if filename.startswith("receipt-"):
                if missing_receipt:
                    raise FileNotFoundError("no independent first outcome")
                return self._first_receipt() if first_receipt is None else first_receipt
            return json.loads(Path(self.tmp.name, filename).read_text())

        return read

    def test_second_release_cannot_grant_first_or_duplicate(self) -> None:
        with mock.patch.object(
            once,
            "_read_root_file",
            side_effect=self._root_file_simulator(self._release()),
        ):
            with self.assertRaisesRegex(
                once.ProviderGrantDenied, "not previously consumed"
            ):
                self._consume(1)
            self._consume(0)
            second = self._consume(1)
            self.assertEqual(second["arm"], "baseline")
            with self.assertRaisesRegex(once.ProviderGrantDenied, "already consumed"):
                self._consume(1)
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 2)

    def test_second_position_must_be_consumed_by_first_kernel_peer(self) -> None:
        self._consume(0)
        with mock.patch.object(
            once,
            "_read_root_file",
            side_effect=self._root_file_simulator(self._release()),
        ):
            for other in (
                (2256, 1999, 1999),
                (2255, 2000, 1999),
                (2255, 1999, 2000),
            ):
                with self.subTest(other=other):
                    with self.assertRaisesRegex(
                        once.ProviderGrantDenied, "marker changed"
                    ):
                        once._consume_position(
                            self.fd, self.policy, _request(self.policy, 1), other
                        )
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 1)

    def test_first_spent_marker_bad_peer_types_fail_typed(self) -> None:
        first = self._consume(0)
        spent = Path(self.tmp.name, "spent-" + first["token_sha256"] + ".json")
        original = json.loads(spent.read_text())
        for field, value in (
            ("peer_pid", "2255"),
            ("peer_uid", None),
            ("peer_gid", []),
            ("peer_pid", True),
        ):
            mutated = dict(original)
            mutated[field] = value
            spent.write_text(json.dumps(mutated))
            with (
                self.subTest(field=field, value=value),
                mock.patch.object(
                    once,
                    "_read_root_file",
                    side_effect=self._root_file_simulator(self._release()),
                ),
                self.assertRaisesRegex(once.ProviderGrantDenied, "marker changed"),
            ):
                self._consume(1)
        spent.write_text(json.dumps(original))

    def test_second_release_strict_schema_does_not_accept_boolean(self) -> None:
        self._consume(0)
        release = self._release()
        release["schema_version"] = True
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(release),
            ),
            self.assertRaisesRegex(once.ProviderGrantDenied, "release is not bound"),
        ):
            self._consume(1)

    def test_root_first_outcome_cannot_cross_policy_code_digest(self) -> None:
        receipt = self._first_receipt()
        changed_policy = {**self.policy, "runtime_code_sha256": "0" * 64}
        with self.assertRaisesRegex(
            once.ProviderGrantDenied, "outcome receipt identity invalid"
        ):
            once._first_outcome_digest(
                changed_policy,
                changed_policy["positions"][0],
                self._first_spent_sha(),
                receipt,
            )

    def test_strict_spent_marker_rejects_boolean_schema(self) -> None:
        first = self._consume(0)
        spent = Path(self.tmp.name, "spent-" + first["token_sha256"] + ".json")
        changed = json.loads(spent.read_text())
        changed["schema_version"] = True
        spent.write_text(json.dumps(changed))
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(self._release()),
            ),
            self.assertRaisesRegex(once.ProviderGrantDenied, "marker changed"),
        ):
            self._consume(1)

    def test_corrupt_first_marker_blocks_second_even_with_root_release(self) -> None:
        first = self._consume(0)
        spent = Path(self.tmp.name, "spent-" + first["token_sha256"] + ".json")
        data = json.loads(spent.read_text())
        data["request_sha256"] = "0" * 64
        spent.write_text(json.dumps(data))
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(self._release()),
            ),
            self.assertRaisesRegex(once.ProviderGrantDenied, "marker changed"),
        ):
            self._consume(1)

    def test_second_release_requires_existing_first_outcome_receipt(self) -> None:
        self._consume(0)
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(
                    self._release(), missing_receipt=True
                ),
            ),
            self.assertRaisesRegex(
                once.ProviderGrantDenied, "lacks trusted root outcome receipt"
            ),
        ):
            self._consume(1)
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 1)

    def test_second_release_rejects_first_receipt_sha_mismatch(self) -> None:
        self._consume(0)
        forged = self._first_receipt()
        forged["provider_output_sha256"] = "0" * 64
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(
                    self._release(), first_receipt=forged
                ),
            ),
            self.assertRaisesRegex(
                once.ProviderGrantDenied, "does not bind first outcome"
            ),
        ):
            self._consume(1)

    def test_second_release_rejects_noncompleted_outcome_even_with_sha(self) -> None:
        self._consume(0)
        failed = self._first_receipt()
        failed["outcome"] = "failed"
        with (
            mock.patch.object(
                once,
                "_read_root_file",
                side_effect=self._root_file_simulator(
                    self._release(receipt=failed), first_receipt=failed
                ),
            ),
            self.assertRaisesRegex(
                once.ProviderGrantDenied, "outcome receipt identity invalid"
            ),
        ):
            self._consume(1)

    def test_first_outcome_rejects_bool_process_count(self) -> None:
        receipt = self._first_receipt()
        receipt["codex_exec_process_count"] = True
        with self.assertRaisesRegex(
            once.ProviderGrantDenied, "outcome receipt identity invalid"
        ):
            once._first_outcome_digest(
                self.policy,
                self.policy["positions"][0],
                self._first_spent_sha(),
                receipt,
            )

    def test_corrupted_second_release_never_consumes(self) -> None:
        self._consume(0)
        with mock.patch.object(
            once, "_read_root_file", return_value=self._release(valid=False)
        ):
            with self.assertRaisesRegex(once.ProviderGrantDenied, "not bound"):
                self._consume(1)
        self.assertEqual(len(list(Path(self.tmp.name).glob("spent-*"))), 1)

    def test_empty_partial_or_symlink_marker_is_terminal_no_retry(self) -> None:
        token = self._first_spent_sha()
        filename = Path(self.tmp.name, "spent-" + token + ".json")
        filename.write_bytes(b"")
        with self.assertRaisesRegex(once.ProviderGrantDenied, "already consumed"):
            self._consume(0)
        filename.unlink()
        filename.symlink_to(Path(self.tmp.name, "not-authority"))
        with self.assertRaisesRegex(once.ProviderGrantDenied, "already consumed"):
            self._consume(0)

    def test_parallel_provider_intents_have_single_winner(self) -> None:
        def run() -> str:
            try:
                self._consume(0)
            except once.ProviderGrantDenied:
                return "rejected"
            return "consumed"

        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(lambda _: run(), range(12)))
        self.assertEqual(outcomes.count("consumed"), 1)
        self.assertEqual(outcomes.count("rejected"), 11)

    def test_changed_request_does_not_create_any_marker(self) -> None:
        req = _request(self.policy, 0)
        req["request_sha256"] = "9" * 64
        with self.assertRaisesRegex(once.ProviderGrantDenied, "mismatch"):
            once._consume_position(self.fd, self.policy, req, self.peer)
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_state_directory_error_closes_prior_root_policy_fd(self) -> None:
        fd = os.open(self.tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        connection, other = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(connection.close)
        self.addCleanup(other.close)
        with connection:
            with (
                mock.patch.object(once.os, "geteuid", return_value=0),
                mock.patch.object(
                    once,
                    "_secure_directory",
                    side_effect=[fd, once.ProviderGrantDenied("state root denied")],
                ),
                self.assertRaisesRegex(once.ProviderGrantDenied, "state root denied"),
            ):
                once.authorize_once(
                    connection,
                    policy_path=once._TRUSTED_POLICY_ROOT
                    / ("epoch-" + "a" * 64 + ".json"),
                    state_dir=once._TRUSTED_STATE_ROOT,
                )
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_root_entrypoint_rejects_arbitrary_policy_paths(self) -> None:
        a, b = socket.socketpair()
        try:
            with (
                mock.patch.object(once.os, "geteuid", return_value=0),
                self.assertRaisesRegex(once.ProviderGrantDenied, "not canonical"),
            ):
                once.authorize_once(
                    a,
                    policy_path=Path(self.tmp.name) / "policy.json",
                    state_dir=Path(self.tmp.name),
                )
        finally:
            a.close()
            b.close()

    def test_public_root_seam_fail_closed_for_unprivileged_caller(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("requires rootless environment")
        a, b = socket.socketpair()
        try:
            with self.assertRaisesRegex(
                once.ProviderGrantDenied, "independent root-owned broker"
            ):
                once.authorize_once(
                    a,
                    policy_path=Path(self.tmp.name) / "policy.json",
                    state_dir=Path(self.tmp.name),
                )
        finally:
            a.close()
            b.close()


if __name__ == "__main__":
    unittest.main()
