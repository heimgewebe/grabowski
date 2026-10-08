"""Fail-closed tests for the uninstalled, root-only capture parent.

The positive integration fixture explicitly mocks root ownership and UID
separation on a disposable local directory. It NEVER proves a real root/UID
boundary, deployed key custody, an authenticated Grabowski unit, or admission.
"""
from __future__ import annotations

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


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def example_policy(binary: bytes, *, host: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "kind": cap.POLICY_KIND,
        "host": host or socket.gethostname(),
        "source_revision": "a" * 40,
        "collector_sha256": sha(binary),
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
        controller = types.SimpleNamespace(pw_name="alex", pw_uid=1000)
        def lookup(name):
            return dedicated if name == cap.CHILD_USER else controller
        with patch.object(cap.pwd, "getpwnam", side_effect=lookup), \
             patch.object(cap.pwd, "getpwuid", return_value=dedicated):
            with self.assertRaisesRegex(cap.CaptureDenied, "not isolated"):
                cap._separate_child_identity()

    def test_dedicated_account_resolution_requires_distinct_uid(self) -> None:
        dedicated = types.SimpleNamespace(
            pw_name=cap.CHILD_USER, pw_uid=963, pw_gid=963,
            pw_shell="/usr/sbin/nologin",
        )
        controller = types.SimpleNamespace(pw_name="alex", pw_uid=1000)
        def lookup(name):
            return dedicated if name == cap.CHILD_USER else controller
        with patch.object(cap.pwd, "getpwnam", side_effect=lookup), \
             patch.object(cap.pwd, "getpwuid", return_value=dedicated):
            self.assertEqual((963, 963), cap._separate_child_identity())

    def test_receipt_schema_explicitly_denies_admission(self) -> None:
        policy = example_policy(b"x", host="heim-pc")
        proof = json.loads(cap._canonical_receipt(
            policy, hostname="heim-pc", code_hash="a"*64,
            task_id="b"*24, nonce="c"*64, argv=["/proc/self/fd/5"],
            stdout=b"", stderr=b"error", started_at=100, terminal_at=100,
        ))
        fields = {
            "schema_version", "kind", "issuer", "capture_boundary",
            "host", "task_id", "attempt", "unit", "argv_sha256",
            "executed_source_sha256", "execution_closure_sha256", "nonce",
            "captured_stdout_sha256", "captured_stdout_bytes",
            "captured_stdout_complete", "stdout_truncated",
            "captured_stderr_sha256", "captured_stderr_bytes",
            "captured_stderr_complete", "stderr_truncated",
            "started_at_unix", "terminalized_at_unix", "state", "exit_code",
        }
        self.assertEqual(fields, set(proof))
        self.assertEqual(sha(b""), proof["captured_stdout_sha256"])
        self.assertEqual(len(b"error"), proof["captured_stderr_bytes"])
        self.assertNotIn("day1_admission_authorized", proof)
        self.assertEqual("grabowski-task-"+("b"*24)+"-a1.service", proof["unit"])

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
            with self.assertRaisesRegex(cap.CaptureDenied, "directory mode/owner"):
                cap._publish_bundle(
                    root_fd, task_id="a"*24, nonce="b"*64, stdout=b"",
                    stderr=b"", receipt=b"{}", signature=b"sig",
                )
        finally:
            os.close(root_fd)
        self.assertEqual([], list(self.dest.glob("proof-*")))

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
                self.assertTrue(name.startswith("proof-"))
                for leaf, data in (("stdout.bin", OBSERVED_STDOUT),
                                   ("stderr.bin", OBSERVED_STDERR),
                                   ("proof.json", b"receipt\n"),
                                   ("proof.sshsig", b"signature\n")):
                    stored = self.dest / name / leaf
                    self.assertEqual(data, stored.read_bytes())
                    self.assertEqual(0o600, stored.stat().st_mode & 0o777)
                with self.assertRaisesRegex(cap.CaptureDenied, "already"):
                    cap._publish_bundle(root_fd, **params)
                self.assertEqual(1, len(list(self.dest.glob("proof-*"))))
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
        self.assertEqual([], list(self.dest.glob("proof-*")))
        self.assertEqual(1, len(list(self.dest.glob(".incomplete-*"))))

    def test_disposable_real_ssh_signature_over_exact_proof_bytes(self) -> None:
        receipt = cap._json_bytes({"kind":"disposable_fixture", "data_sha256":sha(OBSERVED_STDOUT)})
        self.policy_file = Path(self.temp.name) / "policy"
        self.policy_file.write_bytes(cap._json_bytes(example_policy(
            self.programs["success"].read_bytes()
        )))
        self.active_binary = self.programs["success"]
        with patch.object(cap, "SIGNING_KEY_PATH", self.key), \
             patch.object(cap, "_open_root_file", side_effect=self.fake_root_file):
            signed = cap._sign_receipt(receipt)
        self.assertIn(b"-----BEGIN SSH SIGNATURE-----", signed)
        sig_path = Path(self.temp.name) / "sig"
        sig_path.write_bytes(signed)
        verified = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s", str(sig_path)],
            input=receipt, capture_output=True, timeout=15,
        )
        self.assertEqual(0, verified.returncode, verified.stderr.decode(errors="replace"))

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
        self.assertEqual([], list(self.dest.glob("proof-*")))

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
             patch.object(cap, "_sign_receipt", side_effect=cap.CaptureDenied("missing signer")):
            with self.assertRaisesRegex(cap.CaptureDenied, "missing signer"):
                cap.run()
        self.assertEqual([], list(self.dest.glob("proof-*")))

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
             patch.object(cap, "_separate_child_identity", return_value=(os.getuid(), os.getgid())), \
             patch.object(cap, "_drop_to_child", return_value=None):
            outcome = cap.run()
        self.assertEqual("root_owned_proof_published_not_admitted", outcome["status"])
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
        self.assertEqual(sha(self.active_binary.read_bytes()), proof["executed_source_sha256"])
        self.assertEqual(cap.PROOF_KIND, proof["kind"])
        self.assertNotIn("day1_admission_authorized", proof)
        genuine = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(self.signers),
             "-I", cap.PROOF_ISSUER, "-n", cap.PROOF_NAMESPACE, "-s", str(sig)],
            input=proofbytes, capture_output=True, timeout=15,
        )
        self.assertEqual(0, genuine.returncode, genuine.stderr.decode(errors="replace"))
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
             patch.object(cap, "_capture_from_pipes", side_effect=flip_source_after_execution), \
             patch.object(cap, "_sign_receipt", side_effect=AssertionError("MUST NOT SIGN")):
            with self.assertRaisesRegex(cap.CaptureDenied, "executable FD changed"):
                cap.run()
        self.assertEqual([], list(self.dest.glob("proof-*")))

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
             patch.object(cap, "_sign_receipt", side_effect=AssertionError("MUST NOT SIGN")):
            with self.assertRaises(cap.CaptureDenied):
                cap.run()
        self.assertEqual([], list(self.dest.glob("proof-*")))