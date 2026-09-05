from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_blockade_store as store  # noqa: E402
from grabowski_blockades import BlockadeRecord, Provenance, Scope  # noqa: E402


class BlockadeStorePermissionTests(unittest.TestCase):
    def test_read_succeeds_through_execute_only_parent_without_read_permission(self) -> None:
        if not hasattr(os, "O_PATH"):
            self.skipTest("Linux O_PATH is required by the production contract")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            parent = temporary_root / "operator-blockade"
            parent.mkdir(mode=0o700)
            marker = parent / "operator-kill-switch"
            record = BlockadeRecord(
                blockade_id="execute-only-read-proof",
                posture="mutation_freeze",
                scope=Scope("task", "TASK-EXECUTE-ONLY"),
                reason="Prove exact marker reads without directory read permission.",
                trigger_class="permission_regression_test",
                engaged_at=datetime(2026, 9, 4, 11, 0, tzinfo=timezone.utc),
                evidence_refs=("test:execute-only-parent",),
                provenance=Provenance(
                    tool="test_blockade_store_permissions",
                    request_id="request-execute-only",
                    session_id="session-execute-only",
                    task_id="TASK-EXECUTE-ONLY",
                    owner_id="test-owner",
                ),
            )
            receipt = store.engage_blockade_marker(
                record,
                marker,
                expected_marker_path=marker,
                transaction_id="execute-only-engage",
            )

            original_uid = os.geteuid()
            original_gid = os.getegid()
            probe_uid = original_uid
            probe_gid = original_gid
            use_child = original_uid == 0
            if use_child and not hasattr(os, "fork"):
                self.skipTest("root permission probe requires fork")

            def assert_probe() -> None:
                try:
                    descriptor = os.open(parent, store._directory_flags())
                except PermissionError:
                    pass
                else:
                    os.close(descriptor)
                    self.fail("O_RDONLY unexpectedly opened an execute-only directory")

                snapshot = store.read_blockade_marker(
                    marker,
                    expected_marker_path=marker,
                    expected_uid=probe_uid,
                )
                self.assertEqual(snapshot.record, record)
                self.assertEqual(snapshot.record_sha256, receipt.record_sha256)
                self.assertEqual(snapshot.file_sha256, receipt.marker_file_sha256)

            try:
                if use_child:
                    try:
                        import pwd

                        nobody = pwd.getpwnam("nobody")
                        probe_uid = nobody.pw_uid
                        probe_gid = nobody.pw_gid
                        temporary_root.chmod(0o711)
                        os.chown(parent, probe_uid, probe_gid)
                        os.chown(marker, probe_uid, probe_gid)
                    except (ImportError, KeyError, OSError) as exc:
                        self.skipTest(
                            "cannot establish an unprivileged permission probe: "
                            f"{type(exc).__name__}: {exc}"
                        )

                parent.chmod(0o100)
                if not use_child:
                    assert_probe()
                else:
                    read_fd, write_fd = os.pipe()
                    try:
                        pid = os.fork()
                    except BaseException:
                        os.close(read_fd)
                        os.close(write_fd)
                        raise
                    if pid == 0:
                        os.close(read_fd)
                        code = 91

                        def report(message: str) -> None:
                            try:
                                os.write(write_fd, message.encode("utf-8", errors="replace")[:4096])
                            except OSError:
                                pass

                        try:
                            try:
                                os.setgroups([])
                                os.setgid(probe_gid)
                                os.setuid(probe_uid)
                            except OSError as exc:
                                code = 90
                                report(f"privilege-drop failed: {type(exc).__name__}: {exc}")
                            else:
                                try:
                                    assert_probe()
                                except Exception as exc:
                                    code = 92
                                    report(f"probe failed: {type(exc).__name__}: {exc}")
                                else:
                                    code = 0
                        finally:
                            try:
                                os.close(write_fd)
                            finally:
                                os._exit(code)

                    os.close(write_fd)
                    diagnostic = bytearray()
                    try:
                        while len(diagnostic) < 4096:
                            chunk = os.read(read_fd, 4096 - len(diagnostic))
                            if not chunk:
                                break
                            diagnostic.extend(chunk)
                    finally:
                        os.close(read_fd)
                    _, status = os.waitpid(pid, 0)
                    self.assertTrue(os.WIFEXITED(status), "permission probe child did not exit normally")
                    exit_code = os.WEXITSTATUS(status)
                    detail = diagnostic.decode("utf-8", errors="replace")
                    if exit_code == 90:
                        self.skipTest(detail or "cannot drop root privileges for permission probe")
                    self.assertNotEqual(exit_code, 91, detail or "permission probe child escaped its assertion body")
                    self.assertEqual(exit_code, 0, detail or f"permission probe failed with code {exit_code}")

                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o100)
            finally:
                if use_child:
                    try:
                        if os.path.lexists(marker):
                            os.chown(
                                marker, original_uid, original_gid, follow_symlinks=False
                            )
                    finally:
                        try:
                            if os.path.lexists(parent):
                                os.chown(
                                    parent, original_uid, original_gid, follow_symlinks=False
                                )
                        finally:
                            if parent.exists():
                                parent.chmod(0o700)
                            temporary_root.chmod(0o700)
                elif parent.exists():
                    parent.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
