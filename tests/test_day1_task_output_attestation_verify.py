"""Adversarial tests for a proposed signed Day-1 task proof verifier.

All signatures and keys are disposable test fixtures. None is a deployed
protected capture signer. Even an authentic test signature MUST deny admission.
"""

from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from tools import day1_task_output_attestation_verify as verifier


TASK_ID = "a" * 24
NONCE = "b" * 64
NOW = 2_000_000_100
STDOUT = b'{"kind":"fixture","verified":false}\n'
STDERR = b""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def proof_fixture() -> dict:
    return {
        "schema_version": 1,
        "kind": verifier.PROOF_KIND,
        "issuer": verifier.SIGNER_PRINCIPAL,
        "capture_boundary": verifier.CAPTURE_BOUNDARY,
        "host": "heim-pc",
        "task_id": TASK_ID,
        "attempt": 1,
        "unit": f"grabowski-task-{TASK_ID}-a1.service",
        "argv_sha256": "c" * 64,
        "executed_source_sha256": "d" * 64,
        "execution_closure_sha256": "e" * 64,
        "nonce": NONCE,
        "captured_stdout_sha256": sha(STDOUT),
        "captured_stdout_bytes": len(STDOUT),
        "captured_stdout_complete": True,
        "stdout_truncated": False,
        "captured_stderr_sha256": sha(STDERR),
        "captured_stderr_bytes": len(STDERR),
        "captured_stderr_complete": True,
        "stderr_truncated": False,
        "started_at_unix": NOW - 20,
        "terminalized_at_unix": NOW - 2,
        "state": "completed",
        "exit_code": 0,
    }


def expectation(receipt: dict) -> dict:
    return {name: receipt[name] for name in verifier.EXPECTED_KEYS}


class SignedTaskProofTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="day1-signed-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / "test-issuer"
        cmd = [verifier.SSH_KEYGEN, "-q", "-t", "ed25519",
               "-N", "", "-f", str(self.key)]
        subprocess.run(cmd, capture_output=True, check=True, timeout=15)
        pub = (self.root / "test-issuer.pub").read_text(encoding="utf-8").strip()
        self.allowed_signers = (
            verifier.SIGNER_PRINCIPAL + " " + pub + "\n"
        ).encode("utf-8")
        self.receipt = proof_fixture()
        self.expected = expectation(self.receipt)
        self.now_patch = patch.object(verifier.time, "time", return_value=NOW)
        self.now_patch.start()
        self.addCleanup(self.now_patch.stop)

    def sign(self, payload: bytes, *, key: Path | None = None,
             namespace: str | None = None) -> bytes:
        proc = subprocess.run(
            [verifier.SSH_KEYGEN, "-Y", "sign", "-f", str(key or self.key),
             "-n", namespace or verifier.SIGNATURE_NAMESPACE],
            input=payload, capture_output=True, check=True, timeout=15,
        )
        return proc.stdout

    def check(self, receipt: dict | None = None, *, payload: bytes | None = None,
              signature: bytes | None = None, expected: dict | None = None,
              stdout: bytes = STDOUT, stderr: bytes = STDERR) -> dict:
        if payload is None:
            payload = verifier._canonical_json(
                self.receipt if receipt is None else receipt
            )
        if signature is None:
            signature = self.sign(payload)
        with patch.object(
            verifier, "_read_root_owned_signers",
            return_value=self.allowed_signers,
        ):
            return verifier.verify_signed_task_proof(
                payload, signature, stdout, stderr,
                expected=self.expected if expected is None else expected,
            )

    def test_genuine_fixture_signature_stays_deny_only(self) -> None:
        result = self.check()
        self.assertEqual("signed_fields_consistent", result["status"])
        self.assertTrue(result["cryptographic_binding_checked"])
        self.assertEqual(sha(STDOUT), result["captured_stdout_sha256"])
        self.assertFalse(result["protected_capture_verified"])
        self.assertFalse(result["executed_source_verified"])
        self.assertFalse(result["day1_admission_authorized"])
        self.assertIn("real_uid_separated_capture_parent", result["does_not_establish"])

    def test_rejects_changed_stdout_after_original_signature(self) -> None:
        with self.assertRaisesRegex(verifier.ValidationError, "stdout capture byte count differs"):
            self.check(stdout=STDOUT + b"forged")

    def test_rejects_changed_stderr_after_original_signature(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["captured_stderr_sha256"] = sha(b"warning")
        receipt["captured_stderr_bytes"] = len(b"warning")
        with self.assertRaisesRegex(verifier.ValidationError, "stderr capture byte count differs"):
            self.check(receipt=receipt)

    def test_rejects_untrusted_self_signed_key(self) -> None:
        wrong = self.root / "attacker"
        subprocess.run([verifier.SSH_KEYGEN, "-q", "-t", "ed25519",
                        "-N", "", "-f", str(wrong)],
                       capture_output=True, check=True, timeout=15)
        payload = verifier._canonical_json(self.receipt)
        with self.assertRaisesRegex(verifier.ValidationError, "signature is untrusted"):
            self.check(payload=payload, signature=self.sign(payload, key=wrong))

    def test_rejects_wrong_signature_namespace(self) -> None:
        payload = verifier._canonical_json(self.receipt)
        with self.assertRaisesRegex(verifier.ValidationError, "signature is untrusted"):
            self.check(payload=payload, signature=self.sign(
                payload, namespace="some-other-protocol"
            ))

    def test_rejects_signature_from_prior_proof(self) -> None:
        old = verifier._canonical_json(self.receipt)
        # The plaintext and digests are valid; only the signature rejects.
        changed = {**self.receipt, "terminalized_at_unix": NOW - 1}
        with self.assertRaisesRegex(verifier.ValidationError, "signature is untrusted"):
            self.check(payload=verifier._canonical_json(changed),
                       signature=self.sign(old))

    def test_rejects_wrong_nonce_even_when_correctly_signed(self) -> None:
        replay = {**self.receipt, "nonce": "e" * 64}
        with self.assertRaisesRegex(verifier.ValidationError, "expected nonce"):
            self.check(receipt=replay)

    def test_rejects_other_task_unit_and_attempt(self) -> None:
        for field, value, pattern in (
            ("task_id", "f" * 24, "unit does not bind task"),
            ("attempt", 2, "unit does not bind task"),
            ("unit", f"grabowski-task-{TASK_ID}-a4.service", "unit does not bind task"),
        ):
            with self.subTest(field=field):
                receipt = {**self.receipt, field: value}
                with self.assertRaisesRegex(verifier.ValidationError, pattern):
                    self.check(receipt=receipt)

    def test_rejects_forged_source_or_closure(self) -> None:
        for field in ("executed_source_sha256", "execution_closure_sha256",
                      "argv_sha256", "host"):
            with self.subTest(field=field):
                receipt = {**self.receipt, field: (
                    "f" * 64 if field != "host" else "attacker"
                )}
                with self.assertRaisesRegex(verifier.ValidationError, "expected " + field):
                    self.check(receipt=receipt)

    def test_rejects_noncanonical_signed_json_and_unknown_fields(self) -> None:
        canonical = verifier._canonical_json(self.receipt)
        with self.assertRaisesRegex(verifier.ValidationError, "not canonical"):
            self.check(payload=canonical.replace(b':', b': ', 1))
        receipt = {**self.receipt, "trust_me": True}
        with self.assertRaisesRegex(verifier.ValidationError, "field set"):
            self.check(receipt=receipt)

    def test_rejects_legacy_receipt_selfhash_without_signature(self) -> None:
        legacy = {"schema_version": 2, "task_id": TASK_ID, "receipt_sha256": "f" * 64}
        with self.assertRaisesRegex(verifier.ValidationError, "field set"):
            self.check(receipt=legacy)

    def test_rejects_undeclared_truncation_and_incomplete_stream(self) -> None:
        for field, value in (
            ("stdout_truncated", True),
            ("captured_stdout_complete", False),
            ("stderr_truncated", True),
            ("captured_stderr_complete", None),
        ):
            with self.subTest(field=field):
                receipt = {**self.receipt, field: value}
                with self.assertRaises(verifier.ValidationError):
                    self.check(receipt=receipt)

    def test_rejects_bools_as_counts_and_proof_timestamp(self) -> None:
        for field in ("captured_stdout_bytes", "started_at_unix",
                      "terminalized_at_unix", "attempt", "exit_code"):
            with self.subTest(field=field):
                receipt = {**self.receipt, field: True}
                with self.assertRaises(verifier.ValidationError):
                    self.check(receipt=receipt)

    def test_rejects_expired_future_or_overlong_task(self) -> None:
        fixtures = [
            {"terminalized_at_unix": NOW - verifier.MAX_PROOF_AGE_SECONDS - 1,
             "started_at_unix": NOW - verifier.MAX_PROOF_AGE_SECONDS - 2},
            {"terminalized_at_unix": NOW + 6},
            {"started_at_unix": NOW - verifier.MAX_RUN_SECONDS - 25},
        ]
        for row in fixtures:
            with self.subTest(changes=row):
                with self.assertRaisesRegex(verifier.ValidationError, "time bounds"):
                    self.check(receipt={**self.receipt, **row})

    def test_rejects_excess_stream_bytes_even_if_signed(self) -> None:
        with patch.object(verifier, "MAX_STREAM_BYTES", 4):
            with self.assertRaisesRegex(verifier.ValidationError, "oversized"):
                self.check()

    def test_unsigned_or_missing_root_trust_store_fails_closed(self) -> None:
        payload = verifier._canonical_json(self.receipt)
        signature = self.sign(payload)
        with patch.object(verifier, "ROOT_SIGNERS_PATH",
                          self.root / "not-root-owned"):
            with self.assertRaises(verifier.ValidationError):
                verifier.verify_signed_task_proof(
                    payload, signature, STDOUT, STDERR, expected=self.expected,
                )

    def test_symlinked_trusted_policy_path_is_never_accepted(self) -> None:
        actual = self.root / "allowed"
        actual.write_bytes(self.allowed_signers)
        link = self.root / "policy"
        link.symlink_to(actual)
        with patch.object(verifier, "ROOT_SIGNERS_PATH", link):
            with self.assertRaises(verifier.ValidationError):
                verifier._read_root_owned_signers()

    def test_rejects_signer_policy_modified_just_before_kernel_seal(self) -> None:
        # A same-UID attacker changes the trusted key data through the open
        # memfd before F_ADD_SEALS. A successful seal alone would preserve
        # those forged bytes. The post-seal content readback must reject it.
        actual_fcntl = verifier.fcntl.fcntl
        modified = [False]
        add_seals_command = getattr(verifier.fcntl, "F_ADD_SEALS", 1033)

        def attack_before_seal(fd, command, *args):
            if command == add_seals_command and not modified[0]:
                modified[0] = True
                os.lseek(fd, 0, os.SEEK_SET)
                os.write(fd, b"X")
            return actual_fcntl(fd, command, *args)

        with patch.object(verifier.fcntl, "fcntl", side_effect=attack_before_seal):
            with self.assertRaisesRegex(
                verifier.ValidationError, "sealed verifier input bytes differ"
            ):
                self.check()
        self.assertTrue(modified[0])

    def test_linux_libc_memfd_fallback_verifies_real_signature(self) -> None:
        # CPython distributions may omit os.memfd_create despite a working
        # Linux kernel; the fallback is still sealed, never a pathname.
        with patch.object(verifier.os, "memfd_create", None, create=True):
            result = self.check()
        self.assertTrue(result["cryptographic_binding_checked"])
        self.assertFalse(result["day1_admission_authorized"])

    def test_signature_requires_strictly_sealed_kernel_descriptors(self) -> None:
        with patch.object(verifier.os, "memfd_create",
                          side_effect=OSError("unavailable"), create=True):
            with self.assertRaises(verifier.ValidationError):
                self.check()