from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import grabowski_merge_delivery as delivery


BASE = "a" * 40
HEAD = "b" * 40
DIFF = hashlib.sha256(b"diff --git a/a b/a\n").hexdigest()
ARTIFACT_ID = "c" * 32


class MergeDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.artifact_root = root / "artifacts"
        self.delivery_root = root / "deliveries"
        self.artifact_root.mkdir(mode=0o700)
        artifact_dir = self.artifact_root / ARTIFACT_ID
        artifact_dir.mkdir(mode=0o700)
        payload = b"diff --git a/a b/a\n"
        filename = "grabowski-pr-96-a-b-diff.txt"
        payload_path = artifact_dir / filename
        payload_path.write_bytes(payload)
        os.chmod(payload_path, 0o600)
        receipt = {
            "schema": delivery.TEXT_ARTIFACT_SCHEMA,
            "profile": delivery.TEXT_ARTIFACT_PROFILE,
            "artifact_id": ARTIFACT_ID,
            "repository": "heimgewebe/grabowski",
            "repository_path_sha256": "d" * 64,
            "base_commit": BASE,
            "head_commit": HEAD,
            "pull_request_number": 96,
            "filename": filename,
            "diff_sha256": DIFF,
            "byte_size": len(payload),
            "generated_at_unix": int(time.time()) - 1,
            "encoding": "utf-8",
            "format": "unified-diff",
        }
        receipt_raw = delivery.canonical_json_bytes(receipt)
        receipt_path = artifact_dir / "receipt.json"
        receipt_path.write_bytes(receipt_raw)
        os.chmod(receipt_path, 0o600)
        self.artifact_receipt_sha256 = hashlib.sha256(receipt_raw).hexdigest()
        self.now_ns = time.time_ns()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def clone_artifact(self, artifact_id: str, *, generated_at_unix: int) -> str:
        source = self.artifact_root / ARTIFACT_ID
        destination = self.artifact_root / artifact_id
        destination.mkdir(mode=0o700)
        payload_name = "grabowski-pr-96-a-b-diff.txt"
        payload = (source / payload_name).read_bytes()
        payload_path = destination / payload_name
        payload_path.write_bytes(payload)
        os.chmod(payload_path, 0o600)
        receipt = {
            "schema": delivery.TEXT_ARTIFACT_SCHEMA,
            "profile": delivery.TEXT_ARTIFACT_PROFILE,
            "artifact_id": artifact_id,
            "repository": "heimgewebe/grabowski",
            "repository_path_sha256": "d" * 64,
            "base_commit": BASE,
            "head_commit": HEAD,
            "pull_request_number": 96,
            "filename": payload_name,
            "diff_sha256": DIFF,
            "byte_size": len(payload),
            "generated_at_unix": generated_at_unix,
            "encoding": "utf-8",
            "format": "unified-diff",
        }
        raw = delivery.canonical_json_bytes(receipt)
        receipt_path = destination / "receipt.json"
        receipt_path.write_bytes(raw)
        os.chmod(receipt_path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def record(self, **overrides):
        parameters = {
            "repository": "heimgewebe/grabowski",
            "pull_request": 96,
            "base_sha": BASE,
            "head_sha": HEAD,
            "diff_sha256": DIFF,
            "artifact_id": ARTIFACT_ID,
            "artifact_sha256": DIFF,
            "artifact_receipt_sha256": self.artifact_receipt_sha256,
            "delivery_channel": "chat-download",
            "delivery_reference": "sandbox:/mnt/data/grabowski-pr-96-diff.txt",
            "root": self.delivery_root,
            "artifact_root": self.artifact_root,
            "now_ns": self.now_ns,
        }
        parameters.update(overrides)
        return delivery.record_merge_delivery(**parameters)

    def tamper_stored_receipt(
        self, result: dict[str, object], *, field: str, value: object
    ) -> dict[str, object]:
        receipt = dict(result["receipt"])
        receipt[field] = value
        raw = delivery.canonical_json_bytes(receipt)
        receipt_path = Path(result["receipt_path"])
        receipt_path.write_bytes(raw)
        os.chmod(receipt_path, 0o600)
        return {
            **result,
            "receipt": receipt,
            "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def verify(self, result, **overrides):
        parameters = {
            "receipt": result["receipt"],
            "expected_repository": "heimgewebe/grabowski",
            "expected_pull_request": 96,
            "expected_base_sha": BASE,
            "expected_head_sha": HEAD,
            "expected_diff_sha256": DIFF,
            "expected_receipt_sha256": result["receipt_sha256"],
            "root": self.delivery_root,
            "artifact_root": self.artifact_root,
            "now_ns": self.now_ns,
        }
        parameters.update(overrides)
        return delivery.verify_merge_delivery(**parameters)

    def test_legacy_repository_name_cannot_authorize_merge_delivery(self) -> None:
        receipt_path = self.artifact_root / ARTIFACT_ID / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["repository"] = "grabowski"
        raw = delivery.canonical_json_bytes(receipt)
        receipt_path.write_bytes(raw)
        os.chmod(receipt_path, 0o600)
        legacy_receipt_sha256 = hashlib.sha256(raw).hexdigest()

        with self.assertRaisesRegex(
            delivery.MergeDeliveryError,
            "text artifact receipt does not match the merge binding",
        ):
            self.record(artifact_receipt_sha256=legacy_receipt_sha256)
        self.assertFalse(self.delivery_root.exists())

    def test_record_and_verify_exact_delivery(self) -> None:
        result = self.record()
        verified = self.verify(result)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["durable"])
        self.assertEqual(DIFF, result["receipt"]["artifact_sha256"])
        self.assertEqual(
            "d" * 64,
            result["receipt"]["artifact_repository_path_sha256"],
        )
        self.assertEqual("unix-realtime", verified["clock_domain"])
        self.assertIn("merge_authority", verified["does_not_establish"])
        receipt_path = Path(result["receipt_path"])
        self.assertEqual(0o600, receipt_path.stat().st_mode & 0o777)
        self.assertEqual(
            result["receipt"],
            json.loads(receipt_path.read_text(encoding="utf-8")),
        )

    def test_same_delivery_is_idempotent(self) -> None:
        first = self.record()
        second = self.record(now_ns=self.now_ns + 1_000_000)
        self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])
        self.assertEqual(
            first["receipt"]["delivery_confirmed_at_unix_ns"],
            second["receipt"]["delivery_confirmed_at_unix_ns"],
        )

    def test_conflicting_reference_for_same_binding_is_rejected(self) -> None:
        self.record()
        with self.assertRaises(delivery.MergeDeliveryError):
            self.record(delivery_reference="sandbox:/mnt/data/different.txt")

    def test_head_drift_is_rejected(self) -> None:
        result = self.record()
        with self.assertRaises(delivery.MergeDeliveryError):
            self.verify(result, expected_head_sha="e" * 40)

    def test_stale_delivery_is_rejected(self) -> None:
        result = self.record()
        stale_now = (
            result["receipt"]["expires_at_unix_ns"]
            + delivery.CLOCK_SKEW_TOLERANCE_SECONDS * 1_000_000_000
            + 1
        )
        with self.assertRaises(delivery.MergeDeliveryError):
            self.verify(result, now_ns=stale_now)

    def test_fresh_artifact_can_replace_expired_delivery_for_same_binding(self) -> None:
        first = self.record()
        second_artifact_id = "e" * 32
        second_now_ns = first["receipt"]["expires_at_unix_ns"] + 1_000_000_000
        second_receipt_sha256 = self.clone_artifact(
            second_artifact_id,
            generated_at_unix=second_now_ns // 1_000_000_000,
        )

        second = self.record(
            artifact_id=second_artifact_id,
            artifact_receipt_sha256=second_receipt_sha256,
            delivery_reference="sandbox:/mnt/data/grabowski-pr-96-redelivery-diff.txt",
            now_ns=second_now_ns,
        )

        self.assertNotEqual(first["receipt_path"], second["receipt_path"])
        self.assertNotEqual(first["receipt_sha256"], second["receipt_sha256"])
        verified = self.verify(
            second,
            now_ns=second_now_ns,
            artifact_root=self.artifact_root,
        )
        self.assertTrue(verified["durable"])
        self.assertEqual(second_artifact_id, verified["artifact_id"])

    def test_receipt_filename_must_match_text_artifact(self) -> None:
        result = self.record()
        tampered = self.tamper_stored_receipt(
            result,
            field="artifact_filename",
            value="different-valid-name.txt",
        )
        with self.assertRaisesRegex(
            delivery.MergeDeliveryError, "artifact_filename drifted"
        ):
            self.verify(tampered)

    def test_receipt_byte_size_must_match_text_artifact(self) -> None:
        result = self.record()
        tampered = self.tamper_stored_receipt(
            result,
            field="artifact_byte_size",
            value=result["receipt"]["artifact_byte_size"] + 1,
        )
        with self.assertRaisesRegex(
            delivery.MergeDeliveryError, "artifact_byte_size drifted"
        ):
            self.verify(tampered)

    def test_receipt_creation_time_must_match_text_artifact(self) -> None:
        result = self.record()
        tampered = self.tamper_stored_receipt(
            result,
            field="artifact_created_at_unix_ns",
            value=result["receipt"]["artifact_created_at_unix_ns"] - 1_000_000_000,
        )
        with self.assertRaisesRegex(
            delivery.MergeDeliveryError, "artifact_created_at_unix_ns drifted"
        ):
            self.verify(tampered)

    def test_artifact_mutation_after_delivery_is_rejected(self) -> None:
        result = self.record()
        artifact = self.artifact_root / ARTIFACT_ID / result["receipt"]["artifact_filename"]
        artifact.write_bytes(b"tampered\n")
        os.chmod(artifact, 0o600)
        with self.assertRaises(delivery.MergeDeliveryError):
            self.verify(result)

    def test_symlink_receipt_is_rejected(self) -> None:
        result = self.record()
        receipt_path = Path(result["receipt_path"])
        target = receipt_path.with_suffix(".target")
        receipt_path.rename(target)
        receipt_path.symlink_to(target.name)
        with self.assertRaises(delivery.MergeDeliveryError):
            self.verify(result)

    def test_delivery_failure_does_not_create_receipt(self) -> None:
        with self.assertRaises(delivery.MergeDeliveryError):
            self.record(artifact_receipt_sha256="f" * 64)
        self.assertFalse(self.delivery_root.exists())

    def test_merge_ordering_distinguishes_before_after_and_uncertain(self) -> None:
        result = self.record()
        info = self.verify(result)
        delivered = info["delivery_confirmed_at_unix_ns"]
        uncertainty = info["ordering_uncertainty_ns"]
        before = delivery.github_merge_ordering(
            info, delivered + uncertainty + 1
        )
        after = delivery.github_merge_ordering(
            info, delivered - uncertainty - 1
        )
        uncertain = delivery.github_merge_ordering(info, delivered)
        self.assertEqual("delivery_before_merge", before["ordering"])
        self.assertTrue(before["pre_merge_delivery_contract_satisfied"])
        self.assertEqual("delivery_after_merge", after["ordering"])
        self.assertFalse(after["pre_merge_delivery_contract_satisfied"])
        self.assertEqual("ordering_uncertain", uncertain["ordering"])
        self.assertTrue(uncertain["post_merge_exposure_is_not_equivalent"])



if __name__ == "__main__":
    unittest.main()
