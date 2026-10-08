"""Adversarial read-only checks for non-admitting Day-1 prototype reconciliation.

The temporary test paths are user-owned. Root-only checks are mocked here,
not presented as privileged physical-host attestation or SSHSIG verification.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import day1_protected_capture_provider as cap
from tools import day1_protected_capture_attempts as rec

DUMMY_SIGNATURE = (
    b"-----BEGIN SSH SIGNATURE-----\n"
    b"not-verified-disposable-signature\n"
    b"-----END SSH SIGNATURE-----\n"
)


class ProtectedAttemptReadbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="prototype-reconcile-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "protected"
        self.root.mkdir(mode=0o700)

    @contextmanager
    def fixture(self):
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with (
                patch.object(cap, "_check_staging_root_owned", return_value=None),
                patch.object(cap, "_check_attempt_leaf", return_value=None),
                patch.object(rec, "_check_prototype_leaf", return_value=None),
            ):
                yield root_fd
        finally:
            os.close(root_fd)

    def reserve(self, root_fd: int) -> tuple[str, str]:
        return cap._reserve_prototype_capture(
            root_fd, host="heim-pc", policy_sha256="a" * 64,
            initial_executable_sha256="b" * 64,
        )

    def publish(self, root_fd: int, capture_id: str, nonce: str,
                stdout: bytes = b"stdout bytes",
                stderr: bytes = b"stderr bytes") -> Path:
        policy = {"source_revision": "c" * 40}
        receipt = cap._canonical_receipt(
            policy, hostname="heim-pc", code_hash="b" * 64,
            task_id=capture_id, nonce=nonce, argv=["/proc/self/fd/17"],
            stdout=stdout, stderr=stderr, started_at=100, terminal_at=101,
        )
        name = cap._publish_bundle(
            root_fd, task_id=capture_id, nonce=nonce,
            stdout=stdout, stderr=stderr, receipt=receipt,
            signature=DUMMY_SIGNATURE,
        )
        return self.root / name

    def test_missing_reservation_cannot_be_reconciled(self) -> None:
        with self.fixture() as fd:
            with self.assertRaisesRegex(cap.CaptureDenied, "no authenticated"):
                rec.inspect_reserved_prototype(fd)

    def test_reserved_only_never_authorizes_retry_or_admission(self) -> None:
        with self.fixture() as fd:
            capture_id, _ = self.reserve(fd)
            view = rec.inspect_reserved_prototype(fd)
            self.assertEqual("reserved_without_publication", view["status"])
            self.assertEqual(capture_id, view["capture_id"])
            self.assertFalse(view["retry_authorized"])
            self.assertFalse(view["recovery_complete"])
            self.assertFalse(view["signature_verified"])
            self.assertFalse(view["day1_admission_authorized"])
            self.assertFalse(view["task_binding_verified"])

    def test_staging_is_incomplete_even_with_all_files(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            staging = self.root / f".incomplete-{capture_id}-{nonce}"
            staging.mkdir(mode=0o700)
            (staging / "stdout.bin").write_bytes(b"data")
            result = rec.inspect_reserved_prototype(fd)
            self.assertEqual("incomplete_staging_unverified", result["status"])
            self.assertFalse(result["retry_authorized"])
            self.assertFalse(result["day1_admission_authorized"])

    def test_complete_published_bytes_are_not_cryptographic_attestation(self) -> None:
        # The signature merely resembles SSHSIG framing and has never been
        # cryptographically checked; that MUST NOT create successful admission.
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            self.publish(fd, capture_id, nonce, stdout=b"true source bytes")
            view = rec.inspect_reserved_prototype(fd)
            self.assertEqual(
                "published_prototype_bytes_consistent_signature_unverified",
                view["status"],
            )
            self.assertEqual(capture_id, view["capture_id"])
            self.assertEqual(64, len(view["proof_sha256"]))
            self.assertFalse(view["signature_verified"])
            self.assertFalse(view["day1_admission_authorized"])
            self.assertFalse(view["recovery_complete"])
            self.assertFalse(view["retry_authorized"])

    def test_mismatched_stdout_and_forged_admission_are_rejected(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            target = path / "stdout.bin"
            target.write_bytes(b"forged stdout")
            with self.assertRaisesRegex(cap.CaptureDenied, "digest mismatch"):
                rec.inspect_reserved_prototype(fd)
            target.write_bytes(b"stdout bytes")
            proof_path = path / "proof.json"
            proof = json.loads(proof_path.read_bytes())
            proof["day1_admission_authorized"] = True
            proof_path.write_bytes(cap._json_bytes(proof))
            with self.assertRaisesRegex(cap.CaptureDenied, "deny admission"):
                rec.inspect_reserved_prototype(fd)

    def test_mismatched_identity_or_malformed_signature_are_rejected(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            proof_path = path / "proof.json"
            original = proof_path.read_bytes()
            proof = json.loads(original)
            proof["capture_id"] = "0" * 24
            proof_path.write_bytes(cap._json_bytes(proof))
            with self.assertRaisesRegex(cap.CaptureDenied, "identity and schema mismatch"):
                rec.inspect_reserved_prototype(fd)
            proof_path.write_bytes(original)
            (path / "proof.sshsig").write_bytes(b"not a signature")
            with self.assertRaisesRegex(cap.CaptureDenied, "envelope"):
                rec.inspect_reserved_prototype(fd)

    def test_link_swap_and_unexpected_files_block_readback(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            (path / "stdout.bin").unlink()
            (path / "stdout.bin").symlink_to("/etc/hosts")
            with self.assertRaises(cap.CaptureDenied):
                rec.inspect_reserved_prototype(fd)
            (path / "stdout.bin").unlink()
            (path / "stdout.bin").write_bytes(b"stdout bytes")
            (path / "unexpected.txt").write_bytes(b"extra")
            with self.assertRaisesRegex(cap.CaptureDenied, "unexpected prototype files"):
                rec.inspect_reserved_prototype(fd)

    def test_unknown_attempt_or_double_publication_blocks_readback(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            self.publish(fd, capture_id, nonce)
            (self.root / "prototype-foreign").mkdir()
            with self.assertRaisesRegex(cap.CaptureDenied, "foreign"):
                rec.inspect_reserved_prototype(fd)
            (self.root / "prototype-foreign").rmdir()
            (self.root / f".incomplete-{capture_id}-{nonce}").mkdir()
            with self.assertRaisesRegex(cap.CaptureDenied, "simultaneous"):
                rec.inspect_reserved_prototype(fd)

    def test_boolean_numbers_cannot_change_signed_schema_meaning(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            proof_path = path / "proof.json"
            original_proof = json.loads(proof_path.read_bytes())
            for key, bool_value in (
                ("schema_version", True),
                ("capture_attempt", True),
                ("primary_exit_code", False),
            ):
                with self.subTest(key=key):
                    proof_path.write_bytes(cap._json_bytes({
                        **original_proof, key: bool_value,
                    }))
                    with self.assertRaisesRegex(
                        cap.CaptureDenied, "identity and schema mismatch"
                    ):
                        rec.inspect_reserved_prototype(fd)
            proof_path.write_bytes(cap._json_bytes(original_proof))
            marker_path = self.root / cap.ATTEMPT_MARKER
            reservation = json.loads(marker_path.read_bytes())
            marker_path.write_bytes(cap._json_bytes({
                **reservation, "schema_version": True,
            }))
            with self.assertRaisesRegex(
                cap.CaptureDenied, "invalid binding"
            ):
                rec.inspect_reserved_prototype(fd)

    def test_path_swap_during_readback_is_detected(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            dirname = f"prototype-{capture_id}-{nonce}"
            self.publish(fd, capture_id, nonce)
            original_read = rec._read_leaf
            renamed = [False]
            def shift_after_last_read(directory_fd, name, maximum):
                data = original_read(directory_fd, name, maximum)
                if name == "proof.sshsig":
                    (self.root / dirname).rename(self.root / "moved-away")
                    renamed[0] = True
                return data
            with patch.object(rec, "_read_leaf", side_effect=shift_after_last_read):
                with self.assertRaisesRegex(
                    cap.CaptureDenied, "directory changed during inspection"
                ):
                    rec.inspect_reserved_prototype(fd)
            self.assertTrue(renamed[0])
            self.assertFalse((self.root / dirname).exists())

    def test_leaf_swapped_after_read_before_final_report_is_denied(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            original_read = rec._read_leaf
            injected = [False]

            def swap_after_later_leaf(directory_fd, name, maximum):
                data = original_read(directory_fd, name, maximum)
                if name == "proof.sshsig" and not injected[0]:
                    # Replaces the already-read stdout after its first
                    # identity/digest check but before readback completes.
                    (path / "stdout.bin").unlink()
                    (path / "stdout.bin").write_bytes(b"forged-after-first-read")
                    injected[0] = True
                return data

            with patch.object(rec, "_read_leaf", side_effect=swap_after_later_leaf):
                with self.assertRaisesRegex(
                    cap.CaptureDenied,
                    "prototype snapshot (changed|identity changed) during inspection",
                ):
                    rec.inspect_reserved_prototype(fd)
            self.assertTrue(injected[0])

    def test_same_bytes_leaf_replacement_during_read_is_denied(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            original_read = rec._read_leaf
            injected = [False]
            stdout = (path / "stdout.bin").read_bytes()

            def same_bytes_different_inode(directory_fd, name, maximum):
                data = original_read(directory_fd, name, maximum)
                if name == "proof.sshsig" and not injected[0]:
                    (path / "stdout.bin").unlink()
                    (path / "stdout.bin").write_bytes(stdout)
                    injected[0] = True
                return data

            with patch.object(rec, "_read_leaf", side_effect=same_bytes_different_inode):
                with self.assertRaisesRegex(
                    cap.CaptureDenied,
                    "prototype snapshot (leaf )?identity changed during inspection",
                ):
                    rec.inspect_reserved_prototype(fd)
            self.assertTrue(injected[0])

    def test_inplace_change_after_stdout_read_is_denied(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            path = self.publish(fd, capture_id, nonce)
            original_read = rec._read_leaf
            injected = [False]

            def mutate_after_read(directory_fd, name, maximum):
                data = original_read(directory_fd, name, maximum)
                if name == "proof.sshsig" and not injected[0]:
                    with (path / "stdout.bin").open("r+b") as target:
                        target.seek(0)
                        target.write(b"x")
                    injected[0] = True
                return data

            with patch.object(rec, "_read_leaf", side_effect=mutate_after_read):
                with self.assertRaisesRegex(
                    cap.CaptureDenied,
                    "prototype snapshot changed during inspection",
                ):
                    rec.inspect_reserved_prototype(fd)
            self.assertTrue(injected[0])

    def test_reservation_swap_after_read_is_denied(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            self.publish(fd, capture_id, nonce)
            original_read = rec._read_leaf
            injected = [False]

            def replace_reservation_late(directory_fd, name, maximum):
                data = original_read(directory_fd, name, maximum)
                if name == "proof.sshsig" and not injected[0]:
                    marker = self.root / cap.ATTEMPT_MARKER
                    raw = marker.read_bytes()
                    marker.unlink()
                    marker.write_bytes(raw)
                    marker.chmod(0o600)
                    injected[0] = True
                return data

            with patch.object(rec, "_read_leaf", side_effect=replace_reservation_late):
                with self.assertRaisesRegex(
                    cap.CaptureDenied,
                    "prototype snapshot identity changed during inspection",
                ):
                    rec.inspect_reserved_prototype(fd)
            self.assertTrue(injected[0])

    def test_published_absence_or_symlinked_directory_blocks(self) -> None:
        with self.fixture() as fd:
            capture_id, nonce = self.reserve(fd)
            dirname = f"prototype-{capture_id}-{nonce}"
            (self.root / dirname).symlink_to("/etc")
            with self.assertRaises(cap.CaptureDenied):
                rec.inspect_reserved_prototype(fd)
            (self.root / dirname).unlink()
            path = self.publish(fd, capture_id, nonce)
            (path / "proof.json").unlink()
            with self.assertRaisesRegex(cap.CaptureDenied, "lacks required files"):
                rec.inspect_reserved_prototype(fd)


if __name__ == "__main__":
    unittest.main()