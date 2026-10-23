"""Provider-free socket seam regressions; no root daemon/model is started."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


_SOURCE = (
    Path(__file__).resolve().parents[1] / "tools" / "grabowski_rab_root_service.py"
)
_SPEC = importlib.util.spec_from_file_location("rab_root_socket_seam", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
service = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(service)


class _SocketSeamFixture:
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="rab-socket-seam-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "once.sock"

    def listen(self, *, passcred: bool) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(s.close)
        if passcred:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        s.bind(str(self.path))
        os.chmod(self.path, 0o660)
        s.listen(2)
        return s


class ListenerAdmissionTests(_SocketSeamFixture, unittest.TestCase):
    def test_unprivileged_process_cannot_claim_root_listener(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("rootless denial case")
        s = self.listen(passcred=True)
        with self.assertRaisesRegex(
            service.RootOneShotServiceDenied, "root-owned socket"
        ):
            service._checked_listener(s)

    def test_missing_early_passcred_denied(self) -> None:
        s = self.listen(passcred=False)
        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            self.assertRaisesRegex(service.RootOneShotServiceDenied, "early PASSCRED"),
        ):
            service._checked_listener(s)

    def test_wrong_listener_name_denied(self) -> None:
        s = self.listen(passcred=True)
        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            self.assertRaisesRegex(
                service.RootOneShotServiceDenied, "incorrect kernel pathname"
            ),
        ):
            service._checked_listener(s)

    def test_reject_nonroot_socket_filesystem_even_if_euid_mocked(self) -> None:
        s = self.listen(passcred=True)
        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            mock.patch.object(service, "_LISTENER_PATH", self.path),
            self.assertRaisesRegex(service.RootOneShotServiceDenied, "untrusted"),
        ):
            service._checked_listener(s)

    def test_root_only_identity_accepts_exact_mode_and_real_listener(self) -> None:
        s = self.listen(passcred=True)
        original = Path.lstat

        def root_projection(p: Path):
            result = original(p)
            if p == self.path or p == self.path.parent:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_uid=0,
                    st_gid=996 if p == self.path else 0,
                    st_nlink=result.st_nlink,
                )
            return result

        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            mock.patch.object(service, "_LISTENER_PATH", self.path),
            mock.patch.object(Path, "lstat", root_projection),
        ):
            service._checked_listener(s)

    def test_root_group_socket_is_not_a_dynamic_user_client_capability(self) -> None:
        s = self.listen(passcred=True)
        original = Path.lstat

        def root_group_projection(p: Path):
            result = original(p)
            if p == self.path or p == self.path.parent:
                return SimpleNamespace(
                    st_mode=result.st_mode,
                    st_uid=0,
                    st_gid=0,
                    st_nlink=result.st_nlink,
                )
            return result

        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            mock.patch.object(service, "_LISTENER_PATH", self.path),
            mock.patch.object(Path, "lstat", root_group_projection),
            self.assertRaisesRegex(
                service.RootOneShotServiceDenied, "filesystem is untrusted"
            ),
        ):
            service._checked_listener(s)

    def test_wrong_activation_credentials_denied_without_fd3_access(self) -> None:
        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            mock.patch.dict(
                os.environ,
                {
                    "LISTEN_PID": "0",
                    "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "rab-provider-once",
                },
            ),
            self.assertRaisesRegex(
                service.RootOneShotServiceDenied, "activation missing"
            ),
        ):
            service._checked_activated_listener()

    def test_service_main_refuses_without_verified_installed_import_closure(
        self,
    ) -> None:
        listener = self.listen(passcred=True)
        with (
            mock.patch.object(service.os, "geteuid", return_value=0),
            mock.patch.object(
                service, "_checked_activated_listener", return_value=listener
            ),
            self.assertRaisesRegex(
                service.RootOneShotServiceDenied, "verified grant-core import closure"
            ),
        ):
            service.main(["--epoch-sha256", "a" * 64])
        self.assertEqual(listener.fileno(), -1)


class BoundedSeamTests(_SocketSeamFixture, unittest.TestCase):
    def test_exact_two_accepted_connections_with_mocked_providerfree_core(self) -> None:
        listener = self.listen(passcred=True)

        class FakeCore:
            def __init__(self):
                self.called = 0

            def authorize_once(self, connection, *, policy_path, state_dir):
                assert connection.recv(1024) == b'{"test":"provider-free"}'
                self.called += 1
                return {
                    "status": "consumed",
                    "token_sha256": "a" * 64,
                    "arm": "baseline" if self.called == 1 else "treatment",
                }

        core = FakeCore()
        with (
            mock.patch.object(service, "_checked_listener"),
            mock.patch.object(service, "_POLICY_ROOT", self.path.parent),
            mock.patch.object(service, "_STATE_ROOT", self.path.parent),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            job = pool.submit(
                service._serve_two,
                listener,
                policy_path=self.path.parent / ("epoch-" + "a" * 64 + ".json"),
                state_dir=self.path.parent,
                grant_core=core,
            )
            for arm in ("baseline", "treatment"):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    client.connect(str(self.path))
                    client.sendall(b'{"test":"provider-free"}')
                    answer = json.loads(client.recv(1024))
                    self.assertEqual(answer["status"], "consumed")
                    self.assertEqual(answer["arm"], arm)
                finally:
                    client.close()
            result = job.result(timeout=5)
        self.assertEqual(result, {"attempts": 2, "consumed": 2})
        self.assertEqual(core.called, 2)

    def test_synthetic_core_exception_returns_only_generic_denial(self) -> None:
        listener = self.listen(passcred=True)

        class RejectCore:
            def authorize_once(self, connection, *, policy_path, state_dir):
                # This case must not rely on an unread packet.
                raise RuntimeError("secret internal diagnostic")

        with (
            mock.patch.object(service, "_checked_listener"),
            mock.patch.object(service, "_POLICY_ROOT", self.path.parent),
            mock.patch.object(service, "_STATE_ROOT", self.path.parent),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            job = pool.submit(
                service._serve_two,
                listener,
                policy_path=self.path.parent / ("epoch-" + "a" * 64 + ".json"),
                state_dir=self.path.parent,
                grant_core=RejectCore(),
            )
            for _ in range(2):
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
                    client.connect(str(self.path))
                    self.assertEqual(
                        json.loads(client.recv(1024)), {"status": "denied"}
                    )
            self.assertEqual(job.result(timeout=5)["consumed"], 0)

    def test_policy_path_cannot_be_client_chosen(self) -> None:
        listener = self.listen(passcred=True)
        with (
            mock.patch.object(service, "_checked_listener"),
            self.assertRaisesRegex(
                service.RootOneShotServiceDenied, "root policy or state path"
            ),
        ):
            service._serve_two(
                listener,
                policy_path=Path(self.tmp.name) / "wrong.json",
                state_dir=Path(self.tmp.name),
                grant_core=object(),
            )


if __name__ == "__main__":
    unittest.main()
