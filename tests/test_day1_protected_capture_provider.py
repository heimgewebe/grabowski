"""Fail-closed tests for the uninstalled, root-only capture parent.

The positive integration fixture explicitly mocks root ownership and UID
separation on a disposable local directory. It NEVER proves a real root/UID
boundary, deployed key custody, an authenticated Grabowski unit, or admission.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

from tools import day1_protected_capture_provider as cap

OBSERVED_STDOUT = b"CAPTURED_FROM_FD\n"
OBSERVED_STDERR = b"STDERR_FD\n"

# Independent Linux x86-64 syscall UAPI reference: cannot inherit a wrong
# number from the production module this integration test must check.
_LANDLOCK_CREATE_RULESET_X86_64 = 444


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _probe_landlock_abi_version() -> tuple[int | None, int]:
    """Read only the kernel Landlock ABI version; never install restrictions.

    Unlike a failed collector launch, this query preserves ENOSYS (absent)
    and EOPNOTSUPP (disabled at boot) without masking unrelated runtime bugs.
    """
    libc = cap.ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = cap.ctypes.c_long
    cap.ctypes.set_errno(0)
    version = libc.syscall(_LANDLOCK_CREATE_RULESET_X86_64, None, 0, 1)
    if version < 0:
        return None, cap.ctypes.get_errno()
    return version, 0


def example_policy(binary: bytes, *, host: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "kind": cap.POLICY_KIND,
        "host": host or socket.gethostname(),
        "source_revision": "a" * 40,
        "collector_sha256": sha(binary),
        "signer_sha256": sha(Path("/usr/bin/ssh-keygen").read_bytes()),
        "runtime_seconds": 5,
        "max_stdout_bytes": 65536,
        "max_stderr_bytes": 65536,
    }


class StrictContractTests(unittest.TestCase):
    def test_entrypoint_refuses_caller_commands_or_paths(self) -> None:
        self.assertEqual(2, cap.main(["/bin/sh"]))
        self.assertEqual(2, cap.main(["--collector=/tmp/attacker"]))
        self.assertEqual(2, cap.main(["--policy=/tmp/attacker"]))

    def test_nonroot_cannot_invoke_protected_capture(self) -> None:
        with patch.object(cap.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(cap.CaptureDenied, "requires root"):
                cap.run()

    def test_policy_is_exact_canonical_host_and_bounded(self) -> None:
        binary = b"not-a-binary"
        valid = example_policy(binary, host="heim-pc")
        self.assertEqual(
            valid, cap._policy(cap._json_bytes(valid), hostname="heim-pc")
        )
        with self.assertRaisesRegex(cap.CaptureDenied, "canonical"):
            cap._policy(json.dumps(valid, indent=2).encode(), hostname="heim-pc")
        with self.assertRaisesRegex(cap.CaptureDenied, "host mismatch"):
            cap._policy(cap._json_bytes(valid), hostname="wrong-host")
        for field, replacement in (
            ("runtime_seconds", True),
            ("runtime_seconds", 0),
            ("runtime_seconds", 301),
            ("max_stderr_bytes", -1),
            ("max_stdout_bytes", cap.MAX_CAPTURE_BYTES + 1),
            ("collector_sha256", "not a digest"),
            ("signer_sha256", "wrong signer digest"),
        ):
            with self.subTest(field=field, replacement=replacement):
                copy = {**valid, field: replacement}
                with self.assertRaises(cap.CaptureDenied):
                    cap._policy(cap._json_bytes(copy), hostname="heim-pc")
        with self.assertRaisesRegex(cap.CaptureDenied, "exact bounded"):
            cap._policy(
                cap._json_bytes({**valid, "argv": ["/bin/sh"]}),
                hostname="heim-pc",
            )

    def test_root_path_ancestors_and_leaf_cannot_be_user_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            own = root / "untrusted"
            own.write_text("payload", encoding="utf-8")
            with self.assertRaises((cap.CaptureDenied, PermissionError)):
                fd, _ = cap._open_root_file(own, max_bytes=4096)
                os.close(fd)
            with self.assertRaises((cap.CaptureDenied, PermissionError)):
                fd = cap._open_root_directory(root, private=True)
                os.close(fd)
            link = root / "alias"
            link.symlink_to(own)
            with self.assertRaises((cap.CaptureDenied, PermissionError)):
                fd, _ = cap._open_root_file(link, max_bytes=4096)
                os.close(fd)

    def test_refuse_unapproved_child_user(self) -> None:
        for row in (
            types.SimpleNamespace(pw_name=cap.CHILD_USER, pw_uid=0, pw_gid=0, pw_shell="/sbin/nologin"),
            types.SimpleNamespace(pw_name=cap.CHILD_USER, pw_uid=1001, pw_gid=1002, pw_shell="/bin/bash"),
            types.SimpleNamespace(pw_name="alex", pw_uid=1001, pw_gid=1002, pw_shell="/sbin/nologin"),
        ):
            with self.subTest(row=row):
                with patch.object(cap.pwd, "getpwnam", return_value=row):
                    with self.assertRaises(cap.CaptureDenied):
                        cap._separate_child_identity()
        with patch.object(cap.pwd, "getpwnam", side_effect=KeyError):
            with self.assertRaisesRegex(cap.CaptureDenied, "not installed"):
                cap._separate_child_identity()

    def test_dedicated_account_cannot_alias_operator_uid(self) -> None:
        dedicated = types.SimpleNamespace(
            pw_name=cap.CHILD_USER, pw_uid=1000, pw_gid=998,
            pw_shell="/usr/sbin/nologin",
        )
        controller = types.SimpleNamespace(pw_name="alex", pw_uid=1000, pw_gid=1000)
        group = types.SimpleNamespace(gr_name=cap.CHILD_USER)
        def lookup(name):
            return dedicated if name == cap.CHILD_USER else controller
        with patch.object(cap.pwd, "getpwnam", side_effect=lookup), \
             patch.object(cap.pwd, "getpwuid", return_value=dedicated), \
             patch.object(cap.grp, "getgrgid", return_value=group), \
             patch.object(cap.os, "getgrouplist", return_value=[1000, 27]):
            with self.assertRaisesRegex(cap.CaptureDenied, "not isolated"):
                cap._separate_child_identity()

    def test_dedicated_account_resolution_requires_distinct_uid(self) -> None:
        dedicated = types.SimpleNamespace(
            pw_name=cap.CHILD_USER, pw_uid=963, pw_gid=963,
            pw_shell="/usr/sbin/nologin",
        )
        controller = types.SimpleNamespace(pw_name="alex", pw_uid=1000, pw_gid=1000)
        group = types.SimpleNamespace(gr_name=cap.CHILD_USER)
        def lookup(name):
            return dedicated if name == cap.CHILD_USER else controller
        with patch.object(cap.pwd, "getpwnam", side_effect=lookup), \
             patch.object(cap.pwd, "getpwuid", return_value=dedicated), \
             patch.object(cap.grp, "getgrgid", return_value=group), \
             patch.object(cap.os, "getgrouplist", return_value=[1000, 27]):
            self.assertEqual((963, 963), cap._separate_child_identity())

    def test_rejects_shared_controller_primary_or_supplementary_gid(self) -> None:
        dedicated = types.SimpleNamespace(
            pw_name=cap.CHILD_USER, pw_uid=963, pw_gid=1000,
            pw_shell="/usr/sbin/nologin",
        )
        controller = types.SimpleNamespace(
            pw_name="alex", pw_uid=1000, pw_gid=1000,
        )
        def lookup(name):
            return dedicated if name == cap.CHILD_USER else controller
        for denied_gid in (1000, 27):
            with self.subTest(denied_gid=denied_gid):
                dedicated.pw_gid = denied_gid
                group = types.SimpleNamespace(gr_name=cap.CHILD_USER)
                with patch.object(cap.pwd, "getpwnam", side_effect=lookup), \
                     patch.object(cap.pwd, "getpwuid", return_value=dedicated), \
                     patch.object(cap.grp, "getgrgid", return_value=group), \
                     patch.object(cap.os, "getgrouplist", return_value=[1000, 27]):
                    with self.assertRaisesRegex(cap.CaptureDenied, "not isolated"):
                        cap._separate_child_identity()

    def test_rejects_canonical_group_mismatch(self) -> None:
        dedicated = types.SimpleNamespace(
            pw_name=cap.CHILD_USER, pw_uid=963, pw_gid=963,
            pw_shell="/usr/sbin/nologin",
        )
        controller = types.SimpleNamespace(
            pw_name="alex", pw_uid=1000, pw_gid=1000,
        )
        with patch.object(cap.pwd, "getpwnam", side_effect=lambda name: (
            dedicated if name == cap.CHILD_USER else controller
        )), patch.object(cap.pwd, "getpwuid", return_value=dedicated), \
             patch.object(cap.grp, "getgrgid", return_value=types.SimpleNamespace(
                 gr_name="shared-other-group"
             )), patch.object(cap.os, "getgrouplist", return_value=[1000, 27]):
            with self.assertRaisesRegex(cap.CaptureDenied, "not isolated"):
                cap._separate_child_identity()

    def test_receipt_schema_explicitly_denies_admission(self) -> None:
        policy = example_policy(b"x", host="heim-pc")
        proof = json.loads(cap._canonical_receipt(
            policy, hostname="heim-pc", code_hash="a"*64,
            task_id="b"*24, nonce="c"*64, argv=["/proc/self/fd/5"],
            stdout=b"", stderr=b"error", started_at=100, terminal_at=100,
        ))
        fields = {
            "schema_version", "kind", "issuer", "capture_boundary",
            "host", "capture_id", "capture_attempt",
            "provider_unit_template", "initial_exec_command_sha256",
            "initial_executable_sha256", "source_revision_policy_claim",
            "execution_closure_verified", "actual_task_binding_verified",
            "collector_process_tree_verified", "day1_admission_authorized",
            "nonce", "captured_stdout_sha256", "captured_stdout_bytes",
            "captured_stdout_complete", "stdout_truncated",
            "captured_stderr_sha256", "captured_stderr_bytes",
            "captured_stderr_complete", "stderr_truncated",
            "parent_capture_started_at_unix", "primary_exit_observed_at_unix",
            "state", "primary_exit_code",
        }
        self.assertEqual(fields, set(proof))
        self.assertEqual(sha(b""), proof["captured_stdout_sha256"])
        self.assertEqual(len(b"error"), proof["captured_stderr_bytes"])
        self.assertEqual("b"*24, proof["capture_id"])
        self.assertEqual(cap.PROOF_KIND, proof["kind"])
        self.assertNotEqual("grabowski.protected_day1_task_proof", proof["kind"])
        self.assertNotIn("task_id", proof)
        self.assertNotIn("unit", proof)
        self.assertNotIn("execution_closure_sha256", proof)
        for field in (
            "day1_admission_authorized", "execution_closure_verified",
            "actual_task_binding_verified", "collector_process_tree_verified",
        ):
            self.assertIs(proof[field], False)
        self.assertEqual(
            "primary_exited_zero_pipes_closed_tree_unverified", proof["state"]
        )

    def test_cgroup_kernel_gate_denies_missing_or_surviving_process_tree(self) -> None:
        # Mocked root-owned cgroup values: not a deployed host attestation.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected = f"0::{cap.UNIT_CGROUP}\n".encode("ascii")
            baseline = {
                "pids.max": b"2\n",
                "pids.current": b"1\n",
                "cgroup.procs": f"{os.getpid()}\n".encode("ascii"),
            }
            values = dict(baseline)
            def open_fixture(_path):
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            def read_fixture(_fd, name):
                return values[name]
            with (
                patch.object(cap, "_open_root_directory", side_effect=open_fixture),
                patch.object(cap, "_read_cgroup_leaf", side_effect=read_fixture),
                patch.object(cap, "_read_proc_cgroup", return_value=expected),
            ):
                cap._assert_cgroup_drained()
                for name, wrong in (
                    ("pids.max", b"max\n"),
                    ("pids.max", b"3\n"),
                    ("pids.current", b"2\n"),  # Escaped child/nested cgroup.
                    ("pids.current", b"0\n"),
                    ("cgroup.procs", f"{os.getpid()}\n999999\n".encode()),
                    ("cgroup.procs", b"999999\n"),
                ):
                    with self.subTest(name=name, value=wrong):
                        values[name] = wrong
                        with self.assertRaisesRegex(
                            cap.CaptureDenied, "cgroup limit or process tree"
                        ):
                            cap._assert_cgroup_drained()
                        values[name] = baseline[name]
            with patch.object(cap, "_read_proc_cgroup", return_value=(
                b"0::/user.slice/user-1000.slice/attacker.service\n"
            )):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "outside its fixed systemd cgroup"
                ):
                    cap._assert_cgroup_drained()

    def test_cgroup_kernel_readback_drift_blocks_signing(self) -> None:
        expected = f"0::{cap.UNIT_CGROUP}\n".encode("ascii")
        with tempfile.TemporaryDirectory() as temp:
            values = {
                "pids.max": b"2\n",
                "pids.current": b"1\n",
                "cgroup.procs": f"{os.getpid()}\n".encode("ascii"),
            }
            reads = [0]
            def race(_fd, name):
                if name == "pids.current":
                    reads[0] += 1
                    if reads[0] == 2:
                        return b"2\n"
                return values[name]
            with (
                patch.object(cap, "_read_proc_cgroup", return_value=expected),
                patch.object(cap, "_open_root_directory",
                             side_effect=lambda _path: os.open(
                                 temp, os.O_RDONLY | os.O_DIRECTORY)),
                patch.object(cap, "_read_cgroup_leaf", side_effect=race),
            ):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "cgroup limit or process tree"
                ):
                    cap._assert_cgroup_drained()
            self.assertEqual(2, reads[0])
            with (
                patch.object(cap, "_read_proc_cgroup", side_effect=[
                    expected, b"0::/system.slice/other.service\n"
                ]),
                patch.object(cap, "_open_root_directory",
                             side_effect=lambda _path: os.open(
                                 temp, os.O_RDONLY | os.O_DIRECTORY)),
                patch.object(cap, "_read_cgroup_leaf",
                             side_effect=lambda _fd, name: values[name]),
            ):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "changed cgroup"
                ):
                    cap._assert_cgroup_drained()

    def test_cgroup_leaf_rejects_symlink_and_untrusted_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pids.max").symlink_to("/etc/hosts")
            (root / "pids.current").write_bytes(b"1\n")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "unapproved cgroup control"
                ):
                    cap._read_cgroup_leaf(fd, "arbitrary")
                with self.assertRaises(cap.CaptureDenied):
                    cap._read_cgroup_leaf(fd, "pids.max")
                # Only test-doubles grant root metadata to a user-owned temp file.
                for mode, uid, passes in (
                    (0o100644, 0, True),
                    (0o100666, 0, False),
                    (0o100644, os.getuid() or 1000, False),
                ):
                    with self.subTest(mode=mode, uid=uid):
                        with patch.object(
                            cap.os, "fstat", return_value=types.SimpleNamespace(
                                st_mode=mode, st_uid=uid,
                            ),
                        ):
                            if passes:
                                self.assertEqual(
                                    b"1\n", cap._read_cgroup_leaf(fd, "pids.current")
                                )
                            else:
                                with self.assertRaisesRegex(
                                    cap.CaptureDenied, "not root-controlled"
                                ):
                                    cap._read_cgroup_leaf(fd, "pids.current")
            finally:
                os.close(fd)

    def test_unit_example_is_inert_and_keeps_root_broker_unchanged(self) -> None:
        root = Path(__file__).resolve().parents[1]
        unit = (root / "systemd" /
                "grabowski-day1-protected-capture.service.example").read_text()
        self.assertIn("RefuseManualStart=yes", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("User=root", unit)
        self.assertIn("CAP_SETUID CAP_SETGID", unit)
        self.assertNotIn("[Install]", unit)
        self.assertNotIn("systemd-run", unit)
        self.assertNotIn("EnvironmentFile", unit)
        self.assertNotIn("ExecStartPre=", unit)
        self.assertIn("ProtectSystem=strict", unit)
        # Kernel pids controller permits the root parent + one collector,
        # not a detached forked process (source-only unit template).
        self.assertRegex(unit, r"(?m)^TasksMax=2$")
        self.assertIn("Slice=system.slice", unit)
        self.assertIn("TasksAccounting=yes", unit)
        self.assertIn("ProtectControlGroups=yes", unit)


@unittest.skipUnless(shutil.which("gcc") and Path("/usr/lib/x86_64-linux-gnu/libc.a").exists(),
                     "static C compiler with libc.a needed for subprocess fixture")
class StaticELFRealPipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.working = tempfile.TemporaryDirectory(prefix="root-parent-synthetic-")
        cls.tmp = Path(cls.working.name)
        cls.programs = {}
        sources = {
            "success": r'''
#include <unistd.h>
int main(void) {
 const char a[]="CAPTURED_FROM_FD\n";
 const char b[]="STDERR_FD\n";
 (void)write(1,a,sizeof(a)-1);
 (void)write(2,b,sizeof(b)-1);
 return 0;
}
''',
            "empty": r'''int main(void) {return 0;}''',
            "exit": r'''int main(void) {return 9;}''',
            "overflow": r'''
#include <unistd.h>
int main(void) {char data[65536]={0}; (void)write(1,data,sizeof(data)); return 0;}
''',
            "timeout": r'''
#include <unistd.h>
int main(void) {sleep(3);return 0;}
''',
        }
        sources["second_stage"] = r'''
#include <unistd.h>
int main(void) {
 const char msg[]="SECOND_EXEC_NOT_PINNED\n";
 (void)write(1,msg,sizeof(msg)-1);
 return 0;
}
'''
        # Compile second_stage before second_exec. Neither may run outside
        # the disposable fixture; the second exec does not allocate a PID.
        sources["second_exec"] = (
            '#include <unistd.h>\n'
            'int main(void) {\n'
            f' const char *path = {json.dumps(str(cls.tmp / "second_stage"))};\n'
            ' char *const args[] = {(char *)path, 0};\n'
            ' execv(path, args);\n'
            ' return 9;\n'
            '}\n'
        )
        # Landlock restricts filesystem exec, not anonymous executable memfd.
        # This alternate route must remain explicitly NON-ADMITTING.
        sources["memfd_exec"] = (
            '#define _GNU_SOURCE\n'
            '#include <unistd.h>\n#include <sys/mman.h>\n'
            '#include <fcntl.h>\n#include <stdio.h>\n#include <errno.h>\n'
            '#ifndef MFD_EXEC\n#define MFD_EXEC 0x0010U\n#endif\n'
            'int main(void) {\n'
            f' const char *path = {json.dumps(str(cls.tmp / "second_stage"))};\n'
            ' int input = open(path, O_RDONLY);\n'
            ' int output = memfd_create("nonadmitted-stage", MFD_EXEC);\n'
            ' if (output < 0 && errno == EINVAL)\n'
            '   output = memfd_create("nonadmitted-stage", 0);\n'
            ' if (input < 0 || output < 0) return 80;\n'
            ' char buf[8192]; ssize_t count;\n'
            ' while ((count = read(input, buf, sizeof(buf))) > 0) {\n'
            '   ssize_t offset = 0;\n'
            '   while (offset < count) {\n'
            '     ssize_t wrote = write(output, buf + offset, count - offset);\n'
            '     if (wrote < 1) return 81;\n'
            '     offset += wrote;\n'
            '   }\n'
            ' }\n'
            ' if (count < 0) return 82;\n'
            ' char name[80];\n'
            ' if (snprintf(name, sizeof(name), "/proc/self/fd/%d", output) < 0) return 83;\n'
            ' char *const args[] = {name, 0};\n'
            ' execv(name, args);\n'
            ' return 84;\n'
            '}\n'
        )
        for name, source in sources.items():
            sourcepath = cls.tmp / f"{name}.c"
            binary = cls.tmp / name
            sourcepath.write_text(source, encoding="utf-8")
            subprocess.run(
                ["/usr/bin/gcc", "-static", "-no-pie", "-O2",
                 str(sourcepath), "-o", str(binary)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=45,
            )
            cap._validate_native_static_elf(binary.read_bytes())
            cls.programs[name] = binary

    @classmethod
    def tearDownClass(cls) -> None:
        cls.working.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="protected-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.dest = Path(self.temp.name) / "out"
        self.dest.mkdir(0o700)
        self.key = Path(self.temp.name) / "fixture-signing-key"
        subprocess.run(
            ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-f", str(self.key)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        pub = (Path(str(self.key)+".pub")).read_text().strip()
        self.signers = Path(self.temp.name) / "signers"
        self.signers.write_text(cap.PROOF_ISSUER+" "+pub+"\n")

        # Unrelated collector/receipt unit fixtures do not depend on the
        # CI runner's Landlock syscall exposure. Real-kernel tests opt in.
        # This is NEVER a production runtime fallback.
        self._landlock_unit_patch = patch.object(
            cap, "_confine_child_filesystem_exec", return_value=None,
        )
        self._landlock_unit_patch.start()
        self.addCleanup(self._landlock_unit_patch.stop)

    def require_kernel_landlock(self) -> None:
        # A read-only ABI query does not launch a child or restrict this test
        # process. Only exact documented kernel unavailability may skip an
        # integration case; *any* subsequent child-start failure is a bug.
        abi, unavailable_errno = _probe_landlock_abi_version()
        if abi is None:
            if unavailable_errno in (errno.ENOSYS, errno.EOPNOTSUPP):
                self.skipTest(f"Landlock ABI unavailable (errno={unavailable_errno})")
            self.fail(f"Landlock ABI query unexpectedly failed (errno={unavailable_errno})")
        self.assertGreaterEqual(abi, 1)
        self._landlock_unit_patch.stop()
        stdout, *_ = self.capture("success")
        self.assertEqual(OBSERVED_STDOUT, stdout)

    def test_kernel_abi_probe_preserves_syscall_errno(self) -> None:
        class FakeSyscall:
            restype = None

            def __init__(self, result: int, error: int) -> None:
                self.result = result
                self.error = error
                self.args = None

            def __call__(self, *args) -> int:
                self.args = args
                cap.ctypes.set_errno(self.error)
                return self.result

        for result, error in ((9, 0), (-1, errno.ENOSYS),
                              (-1, errno.EOPNOTSUPP), (-1, errno.EPERM)):
            with self.subTest(result=result, errno=error):
                syscall = FakeSyscall(result, error)
                with (
                    patch.object(cap, "_LANDLOCK_CREATE_RULESET", 9999),
                    patch.object(cap.ctypes, "CDLL",
                                 return_value=types.SimpleNamespace(syscall=syscall)),
                ):
                    self.assertEqual(
                        (result if result >= 0 else None,
                         0 if result >= 0 else error),
                        _probe_landlock_abi_version(),
                    )
                self.assertEqual(
                    (_LANDLOCK_CREATE_RULESET_X86_64, None, 0, 1), syscall.args
                )

    def test_kernel_abi_skip_never_hides_child_launch_error(self) -> None:
        for unsupported in (errno.ENOSYS, errno.EOPNOTSUPP):
            with self.subTest(unsupported=unsupported), patch(
                __name__ + "._probe_landlock_abi_version",
                return_value=(None, unsupported),
            ):
                with self.assertRaises(unittest.SkipTest):
                    self.require_kernel_landlock()
        for unexpected in (errno.EPERM, errno.EINVAL):
            with self.subTest(unexpected=unexpected), patch(
                __name__ + "._probe_landlock_abi_version",
                return_value=(None, unexpected),
            ):
                with self.assertRaisesRegex(AssertionError, "unexpectedly failed"):
                    self.require_kernel_landlock()
        with patch(
            __name__ + "._probe_landlock_abi_version", return_value=(9, 0)
        ), patch.object(
            self, "capture",
            side_effect=cap.CaptureDenied("protected collector child could not start"),
        ):
            with self.assertRaisesRegex(
                cap.CaptureDenied, "collector child could not start"
            ):
                self.require_kernel_landlock()

    def fake_root_file(self, path: Path, **_kwargs):
        # EXPLICIT test-only substitute for absent UID0/root installed files.
        files = {
            cap.POLICY_PATH: self.policy_file,
            cap.COLLECTOR_PATH: self.active_binary,
            cap.SIGNING_KEY_PATH: self.key,
            cap.SIGN_TOOL: Path("/usr/bin/ssh-keygen"),
        }
        chosen = files[path]
        return os.open(chosen, os.O_RDONLY | os.O_CLOEXEC), chosen.read_bytes()

    def capture(self, name: str, *, runtime: int = 5,
                stdout_cap: int = 65536, stderr_cap: int = 65536):
        fd = os.open(self.programs[name], os.O_RDONLY | os.O_CLOEXEC)
        try:
            with patch.object(cap, "_drop_to_child", return_value=None):
                return cap._capture_from_pipes(
                    fd, uid=os.getuid(), gid=os.getgid(), seconds=runtime,
                    stdout_cap=stdout_cap, stderr_cap=stderr_cap,
                )
        finally:
            os.close(fd)

    def test_real_executable_open_fd_and_direct_pipe_streams(self) -> None:
        stdout, stderr, code, begin, end, argv = self.capture("success")
        self.assertEqual(0, code)
        self.assertEqual(OBSERVED_STDOUT, stdout)
        self.assertEqual(OBSERVED_STDERR, stderr)
        self.assertEqual(1, len(argv))
        self.assertRegex(argv[0], r"^/proc/self/fd/\d+$")
        self.assertGreaterEqual(end, begin)

    def test_second_execve_to_different_file_denied_before_publication(self) -> None:
        # The kernel must block filesystem-backed secondary exec without
        # trusting the primary PID, stdout digest, or prototype SSH signature.
        initial = self.programs["second_exec"]
        second = self.programs["second_stage"]
        self.assertNotEqual(sha(initial.read_bytes()), sha(second.read_bytes()))
        # Unconfined control must prove that this particular second ELF
        # succeeds and produces the exact bytes before relying on denial.
        unconfined_stdout, *_ = self.capture("second_exec")
        self.assertEqual(b"SECOND_EXEC_NOT_PINNED\n", unconfined_stdout)
        self.require_kernel_landlock()
        self.active_binary = initial
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(initial.read_bytes())
        ))
        def fake_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with (
            patch.object(cap.os, "geteuid", return_value=0),
            patch.object(cap, "SIGNING_KEY_PATH", self.key),
            patch.object(cap, "_open_root_file", side_effect=self.fake_root_file),
            patch.object(cap, "_open_root_directory", side_effect=fake_dir),
            patch.object(cap, "_check_staging_root_owned", return_value=None),
            patch.object(cap, "_validate_signer_static", return_value=None),
            patch.object(cap, "_separate_child_identity",
                         return_value=(os.getuid(), os.getgid())),
            patch.object(cap, "_drop_to_child", return_value=None),
            patch.object(cap, "_assert_cgroup_drained", return_value=None),
        ):
            with self.assertRaisesRegex(
                cap.CaptureDenied, "collector did not exit successfully"
            ):
                cap.run()
        # An attempt reservation may persist, but no proof or output bundle
        # may be signed or published for the executed second-stage code.
        self.assertTrue((self.dest / cap.ATTEMPT_MARKER).exists())
        self.assertEqual([], list(self.dest.glob("prototype-*")))
        self.assertEqual([], list(self.dest.glob(".incomplete-*")))

    def test_memfd_exec_bypass_is_signed_but_never_admitted(self) -> None:
        # Explicitly demonstrate a residual same-PID code-closure gap where
        # the host permits executable anonymous memfd objects. The signature
        # authenticates the *nonadmitting prototype claim*, not the code tree.
        setting = Path("/proc/sys/vm/memfd_noexec")
        # Scope 1 only changes the default: explicit MFD_EXEC still works.
        # Missing sysctl may mean a legacy executable-memfd kernel.
        if setting.is_file() and setting.read_text().strip() == "2":
            self.skipTest("kernel enforces no executable memfds (scope 2)")
        initial = self.programs["memfd_exec"]
        second = self.programs["second_stage"]
        self.assertNotEqual(sha(initial.read_bytes()), sha(second.read_bytes()))
        # The unconfined control must execute the copied second ELF.
        # Do not treat a nonzero or unavailable sysctl as safety evidence.
        unconfined_stdout, *_ = self.capture("memfd_exec")
        self.assertEqual(b"SECOND_EXEC_NOT_PINNED\n", unconfined_stdout)
        self.require_kernel_landlock()
        self.active_binary = initial
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(initial.read_bytes())
        ))
        def fake_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with (
            patch.object(cap.os, "geteuid", return_value=0),
            patch.object(cap, "SIGNING_KEY_PATH", self.key),
            patch.object(cap, "_open_root_file", side_effect=self.fake_root_file),
            patch.object(cap, "_open_root_directory", side_effect=fake_dir),
            patch.object(cap, "_check_staging_root_owned", return_value=None),
            patch.object(cap, "_validate_signer_static", return_value=None),
            patch.object(cap, "_separate_child_identity",
                         return_value=(os.getuid(), os.getgid())),
            patch.object(cap, "_drop_to_child", return_value=None),
            patch.object(cap, "_assert_cgroup_drained", return_value=None),
        ):
            outcome = cap.run()
        bundle = self.dest / outcome["bundle_name"]
        self.assertEqual(b"SECOND_EXEC_NOT_PINNED\n", (bundle / "stdout.bin").read_bytes())
        proofbytes = (bundle / "proof.json").read_bytes()
        proof = json.loads(proofbytes)
        self.assertEqual(sha(initial.read_bytes()), proof["initial_executable_sha256"])
        self.assertNotEqual(sha(second.read_bytes()), proof["initial_executable_sha256"])
        for field in (
            "execution_closure_verified", "collector_process_tree_verified",
            "actual_task_binding_verified", "day1_admission_authorized",
        ):
            self.assertIs(proof[field], False)
        self.assertFalse(outcome["day1_admission_authorized"])
        self.assertNotIn("execution_closure_sha256", proof)
        checked = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s",
             str(bundle / "proof.sshsig")],
            input=proofbytes, capture_output=True, timeout=15,
        )
        self.assertEqual(0, checked.returncode, checked.stderr.decode(errors="replace"))

    def test_missing_landlock_fails_before_any_capture(self) -> None:
        # The read-only fixture mocks UID drop, never Landlock success.
        with patch.object(
            cap, "_confine_child_filesystem_exec",
            side_effect=cap.CaptureDenied("kernel restriction unavailable"),
        ):
            with self.assertRaisesRegex(
                cap.CaptureDenied, "collector child could not start"
            ):
                self.capture("success")

    def test_landlock_abi_marshalling_and_prebound_libc_symbols(self) -> None:
        # Synthetic boundary: no kernel Landlock calls or no_new_privs here.
        # Real-kernel behavior is exercised by the two opt-in integration tests.
        self._landlock_unit_patch.stop()
        self.assertEqual(8, cap.ctypes.sizeof(cap._LandlockRulesetAttr))
        self.assertEqual(12, cap.ctypes.sizeof(cap._LandlockPathBeneathAttr))
        self.assertEqual(8, cap._LandlockPathBeneathAttr.parent_fd.offset)
        fd = os.open(self.programs["success"], os.O_RDONLY | os.O_CLOEXEC)
        calls = []

        def fake_syscall(*args):
            calls.append(args)
            if len(calls) == 1:
                return os.dup(fd)  # Fake, valid ruleset FD, closed by child helper.
            return 0

        try:
            with (
                patch.object(cap.ctypes, "CDLL", side_effect=AssertionError(
                    "child must not resolve a new libc handle"
                )),
                patch.object(cap, "_LANDLOCK_SYSCALL", side_effect=fake_syscall),
                patch.object(cap, "_LANDLOCK_PRCTL", return_value=0) as prctl,
            ):
                cap._confine_child_filesystem_exec(fd)
            self.assertEqual(3, len(calls))
            self.assertEqual(
                [cap._LANDLOCK_CREATE_RULESET, cap._LANDLOCK_ADD_RULE,
                 cap._LANDLOCK_RESTRICT_SELF],
                [args[0].value for args in calls],
            )
            self.assertIsInstance(calls[0][2], cap.ctypes.c_size_t)
            self.assertEqual(8, calls[0][2].value)
            self.assertIsInstance(calls[1][1], cap.ctypes.c_int)
            self.assertEqual(cap._LANDLOCK_RULE_PATH_BENEATH, calls[1][2].value)
            self.assertEqual(1, prctl.call_count)
            self.assertEqual(cap._PR_SET_NO_NEW_PRIVS, prctl.call_args.args[0].value)
        finally:
            os.close(fd)

    def test_execute_allowlist_requires_a_regular_verified_fd(self) -> None:
        # Validation occurs before the Landlock syscall and must remain
        # testable without kernel privileges.
        self._landlock_unit_patch.stop()
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "not a regular FD"
                ):
                    cap._confine_child_filesystem_exec(fd)
            finally:
                os.close(fd)

    def test_genuinely_empty_stdout_can_be_captured(self) -> None:
        stdout, stderr, code, *_ = self.capture("empty")
        self.assertEqual((b"", b"", 0), (stdout, stderr, code))

    def test_nonzero_child_never_becomes_trusted_proof(self) -> None:
        with self.assertRaisesRegex(cap.CaptureDenied, "successfully"):
            self.capture("exit")

    def test_stdout_excess_and_timeout_fail_closed(self) -> None:
        with self.assertRaisesRegex(cap.CaptureDenied, "stream exceeded limit"):
            self.capture("overflow", stdout_cap=256)
        with self.assertRaisesRegex(cap.CaptureDenied, "timed out"):
            self.capture("timeout", runtime=1)

    def test_signer_refuses_any_elf_dynamic_loader(self) -> None:
        # Even a pinned static collector SHA is not enough to justify
        # exposing a private key to a dynamically loaded signer.
        data = bytearray(self.programs["success"].read_bytes())
        program_header_offset = int.from_bytes(data[32:40], "little")
        data[program_header_offset:program_header_offset + 4] = (
            3
        ).to_bytes(4, "little")  # PT_INTERP
        with self.assertRaisesRegex(
            cap.CaptureDenied, "signer requires pinned reviewed static ELF"
        ):
            cap._validate_signer_static(bytes(data))
        self.assertEqual(
            "/usr/local/libexec/grabowski/day1-ssh-keygen-static",
            str(cap.SIGN_TOOL),
        )

    def test_dynamic_signer_cannot_reach_signature_subprocess(self) -> None:
        # A synthetically altered, sha-pinned ELF cannot consume the private
        # signing key merely because its main file SHA matches root policy.
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        data = bytearray(self.active_binary.read_bytes())
        phoff = int.from_bytes(data[32:40], "little")
        data[phoff:phoff + 4] = (3).to_bytes(4, "little")
        unsafe_signer = Path(self.temp.name) / "unsafe-dynamic-signer"
        unsafe_signer.write_bytes(data)
        unsafe_signer.chmod(0o755)

        def fixture_open(path, **kwargs):
            if path == cap.SIGN_TOOL:
                return (
                    os.open(unsafe_signer, os.O_RDONLY | os.O_CLOEXEC),
                    bytes(data),
                )
            return self.fake_root_file(path, **kwargs)

        with patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=fixture_open), \
             patch.object(
                 cap.subprocess, "run",
                 side_effect=AssertionError("MUST NOT LAUNCH SIGNER"),
             ):
            with self.assertRaisesRegex(
                cap.CaptureDenied,
                "signer requires pinned reviewed static ELF",
            ):
                cap._sign_receipt(
                    b"synthetic reject unreviewed code\n",
                    expected_signer_sha256=sha(bytes(data)),
                )

    def test_elf_loader_or_arbitrary_script_is_rejected(self) -> None:
        with self.assertRaisesRegex(cap.CaptureDenied, "ELF"):
            cap._validate_native_static_elf(b"#!/bin/sh\necho forged\n")
        dynamic = Path("/usr/bin/true").read_bytes()
        with self.assertRaises(cap.CaptureDenied):
            cap._validate_native_static_elf(dynamic)
        data = bytearray(self.programs["success"].read_bytes())
        data[18:20] = (183).to_bytes(2, "little")  # AArch64 not this host
        with self.assertRaisesRegex(cap.CaptureDenied, "header"):
            cap._validate_native_static_elf(bytes(data))

    def test_create_only_bundle_requires_root_owned_directory(self) -> None:
        root_fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Deterministic on root and non-root CI: real mode validation,
            # plus a separate injected wrong-owner denial at publication.
            os.fchmod(root_fd, 0o750)
            with self.assertRaisesRegex(
                cap.CaptureDenied, "directory mode/owner"
            ):
                cap._check_staging_root_owned(root_fd)
            os.fchmod(root_fd, 0o700)
            with patch.object(
                cap, "_check_staging_root_owned",
                side_effect=cap.CaptureDenied(
                    "staged protected directory mode/owner mismatch"
                ),
            ):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "directory mode/owner"
                ):
                    cap._publish_bundle(
                        root_fd, task_id="a"*24, nonce="b"*64,
                        stdout=b"", stderr=b"",
                        receipt=b"{}", signature=b"sig",
                    )
        finally:
            os.close(root_fd)
        self.assertEqual([], list(self.dest.glob("prototype-*")))

    def test_simulated_root_bundle_atomic_write_readback_and_collision(self) -> None:
        # Only validates atomic publication and readback, not root ownership.
        with patch.object(cap, "_check_staging_root_owned", return_value=None):
            root_fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
            try:
                params = dict(
                    task_id="a"*24, nonce="b"*64,
                    stdout=OBSERVED_STDOUT, stderr=OBSERVED_STDERR,
                    receipt=b"receipt\n", signature=b"signature\n",
                )
                name = cap._publish_bundle(root_fd, **params)
                self.assertTrue(name.startswith("prototype-"))
                for leaf, data in (("stdout.bin", OBSERVED_STDOUT),
                                   ("stderr.bin", OBSERVED_STDERR),
                                   ("proof.json", b"receipt\n"),
                                   ("proof.sshsig", b"signature\n")):
                    stored = self.dest / name / leaf
                    self.assertEqual(data, stored.read_bytes())
                    self.assertEqual(0o600, stored.stat().st_mode & 0o777)
                with self.assertRaisesRegex(cap.CaptureDenied, "already"):
                    cap._publish_bundle(root_fd, **params)
                self.assertEqual(1, len(list(self.dest.glob("prototype-*"))))
            finally:
                os.close(root_fd)

    def test_interrupted_stage_is_not_published(self) -> None:
        original = cap._write_new
        calls = [0]
        def fail_second(fd, name, blob):
            calls[0] += 1
            if calls[0] == 2:
                raise OSError("simulated crash before atomic rename")
            return original(fd, name, blob)
        root_fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_write_new", side_effect=fail_second):
                with self.assertRaises(OSError):
                    cap._publish_bundle(
                        root_fd, task_id="a"*24, nonce="c"*64,
                        stdout=b"out", stderr=b"err",
                        receipt=b"{}",
                        signature=b"sig",
                    )
        finally:
            os.close(root_fd)
        self.assertEqual([], list(self.dest.glob("prototype-*")))
        self.assertEqual(1, len(list(self.dest.glob(".incomplete-*"))))

    def test_post_rename_parent_fsync_failure_is_uncertain_not_success(self) -> None:
        # Simulated power-loss boundary, not an authenticated restore protocol:
        # the prototype directory may already be visible after rename.
        params = dict(
            task_id="a" * 24, nonce="d" * 64,
            stdout=OBSERVED_STDOUT, stderr=OBSERVED_STDERR,
            receipt=b"not-production-proof\n", signature=b"test-only\n",
        )
        expected_dir = self.dest / (
            "prototype-" + params["task_id"] + "-" + params["nonce"]
        )
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        actual_fsync = cap.os.fsync
        failed_after_rename = [False]

        def fail_parent_fsync(target_fd):
            if target_fd == fd:
                self.assertTrue(expected_dir.is_dir())
                failed_after_rename[0] = True
                raise OSError("injected failure after atomic directory rename")
            return actual_fsync(target_fd)

        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap.os, "fsync", side_effect=fail_parent_fsync):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "publication durability uncertain"
                ):
                    cap._publish_bundle(fd, **params)
            self.assertTrue(failed_after_rename[0])
            # The residual folder is explicitly a non-admitting prototype.
            self.assertEqual(
                b"not-production-proof\n",
                (expected_dir / "proof.json").read_bytes(),
            )
            self.assertFalse(any(self.dest.glob("proof-*")))
        finally:
            os.close(fd)


    def test_capture_reservation_is_durable_and_never_silently_reissued(self) -> None:
        # Synthetic user-owned temp root: only root mode is mocked. No host proof.
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_check_attempt_leaf", return_value=None):
                capture_id, nonce = cap._reserve_prototype_capture(
                    fd, host="heim-pc",
                    policy_sha256="a" * 64,
                    initial_executable_sha256="b" * 64,
                )
                marker = self.dest / cap.ATTEMPT_MARKER
                raw = marker.read_bytes()
                value = json.loads(raw)
                self.assertEqual(raw, cap._json_bytes(value))
                self.assertEqual((capture_id, nonce),
                                 (value["capture_id"], value["nonce"]))
                self.assertEqual(0o600, marker.stat().st_mode & 0o777)
                with patch.object(cap.secrets, "token_hex",
                                  side_effect=AssertionError("MUST NOT RESAMPLE")):
                    with self.assertRaisesRegex(
                        cap.CaptureDenied, "requires protected recovery"
                    ):
                        cap._reserve_prototype_capture(
                            fd, host="heim-pc", policy_sha256="a"*64,
                            initial_executable_sha256="b"*64,
                        )
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "binding changed"
                ):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="c"*64,
                        initial_executable_sha256="b"*64,
                    )
        finally:
            os.close(fd)

    def test_orphaned_prototype_or_staging_prevents_new_capture_identity(self) -> None:
        for name in ("prototype-unknown", ".incomplete-unknown"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / name).mkdir()
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with patch.object(cap, "_check_staging_root_owned",
                                      return_value=None), \
                         patch.object(cap.secrets, "token_hex",
                                      side_effect=AssertionError("MUST NOT ISSUE")):
                        with self.assertRaisesRegex(
                            cap.CaptureDenied, "unreconciled protected capture root"
                        ):
                            cap._reserve_prototype_capture(
                                fd, host="heim-pc", policy_sha256="a"*64,
                                initial_executable_sha256="b"*64,
                            )
                finally:
                    os.close(fd)

    def test_capture_reservation_post_fsync_failure_stays_blocked(self) -> None:
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        actual = cap.os.fsync
        def fail_root(target: int) -> None:
            if target == fd:
                self.assertTrue((self.dest / cap.ATTEMPT_MARKER).exists())
                raise OSError("simulated reservation root fsync failure")
            return actual(target)
        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap.os, "fsync", side_effect=fail_root):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "reservation durability uncertain"
                ):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="a"*64,
                        initial_executable_sha256="b"*64,
                    )
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_check_attempt_leaf", return_value=None), \
                 patch.object(cap.secrets, "token_hex",
                              side_effect=AssertionError("MUST NOT REISSUE")):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "requires protected recovery"
                ):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="a"*64,
                        initial_executable_sha256="b"*64,
                    )
        finally:
            os.close(fd)

    def test_competing_reservation_cannot_replace_first_root_identity(self) -> None:
        # Simulate two privileged callers after both observed an empty root.
        # Only one O_EXCL create may win; no second nonce can be committed.
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        actual_write = cap._write_new
        winner = [None]
        def interleaving(target_fd, name, data):
            original = json.loads(data)
            rival = {**original, "capture_id": "f"*24, "nonce": "e"*64}
            winner[0] = cap._json_bytes(rival)
            actual_write(target_fd, name, winner[0])
            return actual_write(target_fd, name, data)
        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_write_new", side_effect=interleaving):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "reservation already exists"
                ):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="a"*64,
                        initial_executable_sha256="b"*64,
                    )
            self.assertIsNotNone(winner[0])
            self.assertEqual(
                winner[0], (self.dest / cap.ATTEMPT_MARKER).read_bytes()
            )
            self.assertFalse(any(self.dest.glob("prototype-*")))
        finally:
            os.close(fd)

    def test_capture_reservation_enforces_root_owned_inodes(self) -> None:
        good = types.SimpleNamespace(
            st_mode=0o100600, st_uid=0, st_nlink=1, st_size=200,
        )
        cap._check_attempt_leaf(good)
        for kwargs in (
            {"st_uid": 1000}, {"st_mode": 0o100660},
            {"st_mode": 0o120600}, {"st_nlink": 2},
            {"st_size": 0}, {"st_size": cap.MAX_ATTEMPT_MARKER_BYTES+1},
        ):
            with self.subTest(kwargs=kwargs):
                bad = types.SimpleNamespace(**{**vars(good), **kwargs})
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "not root-owned 0600"
                ):
                    cap._check_attempt_leaf(bad)

    def test_reservation_symlink_or_malformed_identity_denied(self) -> None:
        marker = self.dest / cap.ATTEMPT_MARKER
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            marker.symlink_to("/etc/hosts")
            with patch.object(cap, "_check_staging_root_owned", return_value=None):
                with self.assertRaises(cap.CaptureDenied):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="a"*64,
                        initial_executable_sha256="b"*64,
                    )
            marker.unlink()
            marker.write_text('{"schema_version":1}\n', encoding="utf-8")
            marker.chmod(0o600)
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_check_attempt_leaf", return_value=None):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "invalid binding"
                ):
                    cap._reserve_prototype_capture(
                        fd, host="heim-pc", policy_sha256="a"*64,
                        initial_executable_sha256="b"*64,
                    )
        finally:
            os.close(fd)

    def test_post_rename_crash_does_not_issue_another_identity(self) -> None:
        fd = os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with patch.object(cap, "_check_staging_root_owned", return_value=None), \
                 patch.object(cap, "_check_attempt_leaf", return_value=None):
                capture_id, nonce = cap._reserve_prototype_capture(
                    fd, host="heim-pc", policy_sha256="a"*64,
                    initial_executable_sha256="b"*64,
                )
                actual = cap.os.fsync
                def fail_publish_sync(target: int) -> None:
                    if target == fd:
                        raise OSError("simulated crash after rename")
                    return actual(target)
                with patch.object(cap.os, "fsync", side_effect=fail_publish_sync):
                    with self.assertRaisesRegex(
                        cap.CaptureDenied, "publication durability uncertain"
                    ):
                        cap._publish_bundle(
                            fd, task_id=capture_id, nonce=nonce,
                            stdout=b"bytes", stderr=b"",
                            receipt=b"not-admitted\n", signature=b"fixture",
                        )
                self.assertEqual(1, len(list(self.dest.glob("prototype-*"))))
                with patch.object(cap.secrets, "token_hex",
                                  side_effect=AssertionError("MUST NOT REISSUE")):
                    with self.assertRaisesRegex(
                        cap.CaptureDenied, "requires protected recovery"
                    ):
                        cap._reserve_prototype_capture(
                            fd, host="heim-pc", policy_sha256="a"*64,
                            initial_executable_sha256="b"*64,
                        )
        finally:
            os.close(fd)

    def test_disposable_real_ssh_signature_over_exact_proof_bytes(self) -> None:
        receipt = cap._json_bytes({"kind":"disposable_fixture", "data_sha256":sha(OBSERVED_STDOUT)})
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(example_policy(
            self.programs["success"].read_bytes()
        )))
        self.active_binary = self.programs["success"]
        with patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_validate_signer_static", return_value=None):
            # This disposable fixture uses distro's dynamic ssh-keygen to
            # exercise SSHSIG wire semantics ONLY; production must reject it.
            signed = cap._sign_receipt(
                receipt, expected_signer_sha256=sha(
                    Path("/usr/bin/ssh-keygen").read_bytes()
                ),
            )
        self.assertIn(b"-----BEGIN SSH SIGNATURE-----", signed)
        sig_path = Path(self.temp.name) / "sig"
        sig_path.write_bytes(signed)
        verified = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s", str(sig_path)],
            input=receipt, capture_output=True, timeout=15,
        )
        self.assertEqual(0, verified.returncode, verified.stderr.decode(errors="replace"))

    def test_signer_executable_sha_is_exactly_root_policy_pinned(self) -> None:
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        with patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file):
            with self.assertRaisesRegex(
                cap.CaptureDenied, "signer executable differs"
            ):
                cap._sign_receipt(
                    b"synthetic fixture\n",
                    expected_signer_sha256="f" * 64,
                )

    def test_key_path_rotation_does_not_swap_verified_signer_fd(self) -> None:
        # This simulates a trusted root path rotation after descriptor-open,
        # not a proof of deployed key custody or actual UID0 permissions.
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        receipt = b"pinned key fd during rotation\n"
        rotated = [False]
        original_key = Path(self.temp.name) / "original-key-inode"

        def switch_path_after_open(path, **kwargs):
            descriptor, data = self.fake_root_file(path, **kwargs)
            if path == cap.SIGNING_KEY_PATH and not rotated[0]:
                rotated[0] = True
                self.key.rename(original_key)
                self.key.write_bytes(b"attacker-supplied-incorrect-key")
                self.key.chmod(0o600)
            return descriptor, data

        with patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=switch_path_after_open), \
             patch.object(cap, "_validate_signer_static", return_value=None):
            signature = cap._sign_receipt(
                receipt,
                expected_signer_sha256=sha(
                    Path("/usr/bin/ssh-keygen").read_bytes()
                ),
            )
        self.assertTrue(rotated[0])
        sig_path = Path(self.temp.name) / "rotated-fd.sshsig"
        sig_path.write_bytes(signature)
        checked = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE,
             "-s", str(sig_path)],
            input=receipt, capture_output=True, timeout=15,
        )
        self.assertEqual(
            0, checked.returncode,
            checked.stderr.decode(errors="replace"),
        )

    def test_wrong_pinned_binary_digest_fails_before_child_execution(self) -> None:
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        policy = example_policy(self.active_binary.read_bytes())
        policy["collector_sha256"] = "f" * 64
        self.policy_file.write_bytes(cap._json_bytes(policy))
        with patch.object(cap.os, "geteuid", return_value=0), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_capture_from_pipes", side_effect=AssertionError("MUST NOT EXEC")):
            with self.assertRaisesRegex(cap.CaptureDenied, "differs"):
                cap.run()
        self.assertEqual([], list(self.dest.glob("prototype-*")))

    def test_signer_failure_leaves_no_authoritative_output(self) -> None:
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        def fake_open_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with patch.object(cap.os, "geteuid", return_value=0), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_open_root_directory", side_effect=fake_open_dir), \
             patch.object(cap, "_separate_child_identity", return_value=(os.getuid(), os.getgid())), \
             patch.object(cap, "_drop_to_child", return_value=None), \
             patch.object(cap, "_assert_cgroup_drained", return_value=None), \
             patch.object(cap, "_check_staging_root_owned", return_value=None), \
             patch.object(cap, "_sign_receipt", side_effect=cap.CaptureDenied("missing signer")):
            with self.assertRaisesRegex(cap.CaptureDenied, "missing signer"):
                cap.run()
        self.assertEqual([], list(self.dest.glob("prototype-*")))

    def test_cgroup_denial_before_launch_or_after_exit_never_signs(self) -> None:
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        def fake_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        for failed_gate in (1, 2, 3):
            with self.subTest(failed_gate=failed_gate):
                calls = [0]
                def gate():
                    calls[0] += 1
                    if calls[0] == failed_gate:
                        raise cap.CaptureDenied("simulated cgroup gate failure")
                def fake_sign(_payload, *, expected_signer_sha256):
                    if failed_gate < 3:
                        raise AssertionError("MUST NOT SIGN")
                    return b"synthetic-signature-not-for-admission"
                with (
                    patch.object(cap.os, "geteuid", return_value=0),
                    patch.object(cap, "_open_root_file", side_effect=self.fake_root_file),
                    patch.object(cap, "_open_root_directory", side_effect=fake_dir),
                    patch.object(cap, "_separate_child_identity",
                                 return_value=(os.getuid(), os.getgid())),
                    patch.object(cap, "_drop_to_child", return_value=None),
                    patch.object(cap, "_assert_cgroup_drained", side_effect=gate),
                    patch.object(cap, "_reserve_prototype_capture",
                                 return_value=("a"*24, "b"*64)),
                    patch.object(cap, "_sign_receipt", side_effect=fake_sign),
                    patch.object(cap, "_publish_bundle",
                                 side_effect=AssertionError("MUST NOT PUBLISH")),
                ):
                    with self.assertRaisesRegex(
                        cap.CaptureDenied, "simulated cgroup gate failure"
                    ):
                        cap.run()
                self.assertEqual(failed_gate, calls[0])
                self.assertEqual([], list(self.dest.glob("prototype-*")))

    def test_end_to_end_simulated_static_capture_is_signed_but_not_admitted(self) -> None:
        # The root/uid/path checks are replaced in this user-UID fixture ONLY.
        self.active_binary = self.programs["success"]
        self.policy_file = Path(self.temp.name) / "policy"
        payload = example_policy(self.active_binary.read_bytes())
        self.policy_file.write_bytes(cap._json_bytes(payload))
        def fake_open_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with patch.object(cap.os, "geteuid", return_value=0), \
             patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_open_root_directory", side_effect=fake_open_dir), \
             patch.object(cap, "_check_staging_root_owned", return_value=None), \
             patch.object(cap, "_validate_signer_static", return_value=None), \
             patch.object(cap, "_separate_child_identity", return_value=(os.getuid(), os.getgid())), \
             patch.object(cap, "_drop_to_child", return_value=None), \
             patch.object(cap, "_assert_cgroup_drained", return_value=None):
            outcome = cap.run()
        self.assertEqual("root_owned_prototype_bundle_published_not_admitted", outcome["status"])
        self.assertFalse(outcome["day1_admission_authorized"])
        self.assertFalse(outcome["ledger_binding_verified"])
        self.assertFalse(outcome["real_deployment_verified"])
        bundle = self.dest / outcome["bundle_name"]
        stdout = (bundle / "stdout.bin").read_bytes()
        stderr = (bundle / "stderr.bin").read_bytes()
        proofbytes = (bundle / "proof.json").read_bytes()
        sig = bundle / "proof.sshsig"
        proof = json.loads(proofbytes)
        self.assertEqual(OBSERVED_STDOUT, stdout)
        self.assertEqual(OBSERVED_STDERR, stderr)
        self.assertEqual(sha(stdout), proof["captured_stdout_sha256"])
        self.assertEqual(len(stdout), proof["captured_stdout_bytes"])
        self.assertEqual(sha(stderr), proof["captured_stderr_sha256"])
        self.assertEqual(sha(self.active_binary.read_bytes()), proof["initial_executable_sha256"])
        self.assertEqual(cap.PROOF_KIND, proof["kind"])
        self.assertIs(proof["day1_admission_authorized"], False)
        genuine = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s", str(sig)],
            input=proofbytes, capture_output=True, timeout=15,
        )
        self.assertEqual(0, genuine.returncode, genuine.stderr.decode(errors="replace"))
        # Control: the allowed-signers file authorizes BOTH principals
        # for exactly the same key. Prove prototype SSHSIG namespace works
        # with the production principal, then change ONLY the namespace.
        # This detects regressions hidden by an unauthorized principal.
        public = Path(str(self.key) + ".pub").read_text().strip()
        both_principals = Path(self.temp.name) / "dual-principals"
        production_principal = "grabowski-day1-capture@heimgewebe"
        production_namespace = "grabowski-day1-task-proof-v1@heimgewebe"
        both_principals.write_text(
            cap.PROOF_ISSUER + " " + public + "\n"
            + production_principal + " " + public + "\n",
            encoding="utf-8",
        )
        self.assertNotEqual(cap.PROOF_NAMESPACE, production_namespace)
        accepted_same_namespace = subprocess.run(
            [
                "/usr/bin/ssh-keygen", "-Y", "verify",
                "-f", str(both_principals),
                "-I", production_principal,
                "-n", cap.PROOF_NAMESPACE,
                "-s", str(sig),
            ],
            input=proofbytes, capture_output=True, timeout=15,
        )
        self.assertEqual(
            0, accepted_same_namespace.returncode,
            accepted_same_namespace.stderr.decode(errors="replace"),
        )
        production_verification = subprocess.run(
            [
                "/usr/bin/ssh-keygen", "-Y", "verify",
                "-f", str(both_principals),
                "-I", production_principal,
                "-n", production_namespace,
                "-s", str(sig),
            ],
            input=proofbytes, capture_output=True, timeout=15,
        )
        self.assertNotEqual(0, production_verification.returncode)
        self.assertNotEqual(
            "grabowski.protected_day1_task_proof", proof["kind"]
        )
        # A *canonical* reissued proof with forged stdout hash still has
        # valid JSON/schema; the original root-owned signature must reject it.
        forged_claim = {**proof, "captured_stdout_sha256": "f" * 64}
        forged = cap._json_bytes(forged_claim)
        self.assertNotEqual(proofbytes, forged)
        invalid = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s", str(sig)],
            input=forged, capture_output=True, timeout=15,
        )
        self.assertNotEqual(0, invalid.returncode)

    def test_postexec_binary_bytes_changed_blocks_signature(self) -> None:
        # Only in the synthetic user-owned binary fixture. The production
        # executable must also be root-owned and impossible for child to edit.
        source = self.programs["success"]
        private_copy = Path(self.temp.name) / "editable_fixture_binary"
        shutil.copyfile(source, private_copy)
        private_copy.chmod(0o755)
        self.active_binary = private_copy
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(private_copy.read_bytes())
        ))
        original_capture = cap._capture_from_pipes
        def flip_source_after_execution(program_fd, **kwargs):
            result = original_capture(program_fd, **kwargs)
            with private_copy.open("r+b") as handle:
                handle.seek(128)
                original = handle.read(1)
                handle.seek(128)
                handle.write(b"X" if original != b"X" else b"Y")
            return result
        def fake_open_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with patch.object(cap.os, "geteuid", return_value=0), \
             patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_open_root_directory", side_effect=fake_open_dir), \
             patch.object(cap, "_separate_child_identity", return_value=(os.getuid(), os.getgid())), \
             patch.object(cap, "_drop_to_child", return_value=None), \
             patch.object(cap, "_assert_cgroup_drained", return_value=None), \
             patch.object(cap, "_check_staging_root_owned", return_value=None), \
             patch.object(cap, "_capture_from_pipes", side_effect=flip_source_after_execution), \
             patch.object(cap, "_sign_receipt", side_effect=AssertionError("MUST NOT SIGN")):
            with self.assertRaisesRegex(cap.CaptureDenied, "executable FD changed"):
                cap.run()
        self.assertEqual([], list(self.dest.glob("prototype-*")))

    def test_error_exits_without_authoritative_bundle_or_root_key(self) -> None:
        self.active_binary = self.programs["exit"]
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(
            example_policy(self.active_binary.read_bytes())
        ))
        def fake_open_dir(_path, *, private=False):
            return os.open(self.dest, os.O_RDONLY | os.O_DIRECTORY)
        with patch.object(cap.os, "geteuid", return_value=0), \
             patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file), \
             patch.object(cap, "_open_root_directory", side_effect=fake_open_dir), \
             patch.object(cap, "_separate_child_identity", return_value=(os.getuid(), os.getgid())), \
             patch.object(cap, "_drop_to_child", return_value=None), \
             patch.object(cap, "_assert_cgroup_drained", return_value=None), \
             patch.object(cap, "_sign_receipt", side_effect=AssertionError("MUST NOT SIGN")):
            with self.assertRaises(cap.CaptureDenied):
                cap.run()
        self.assertEqual([], list(self.dest.glob("prototype-*")))