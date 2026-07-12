from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tests.test_operator_contract import _load_operator_module


class JobNotificationOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.operator = _load_operator_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.jobs = self.state / "jobs"
        self.jobs.mkdir(parents=True, mode=0o700)
        self.job_id = "123456789abc"
        self.unit = f"grabowski-job-{self.job_id}"
        self.directory = self.jobs / self.unit
        self.directory.mkdir(mode=0o700)
        self.receipt = self._receipt()
        self._write_json(self.directory / "notification.json", self.receipt)
        self.patchers = [
            mock.patch.object(self.operator, "STATE_DIR", self.state),
            mock.patch.object(self.operator, "JOBS_DIR", self.jobs),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def _receipt(self) -> dict:
        value = {
            "schema_version": 1,
            "kind": "grabowski_job_notification",
            "notification_id": "f" * 32,
            "job_id": self.job_id,
            "unit": self.unit,
            "owner": "uid:1000",
            "scope": {"cwd": "/tmp"},
            "argv_sha256": "a" * 64,
            "terminal_status": "succeeded",
            "terminalization": {
                "service_result": "success",
                "exit_code": "exited",
                "exit_status": "0",
            },
            "requested_channels": ["operator_outbox"],
            "note": "done",
            "delivery_mode": "operator_outbox",
            "delivery_state": "queued",
            "does_not_establish": [
                "external_push_delivery",
                "user_has_seen_notification",
                "job_success_beyond_terminalization_evidence",
            ],
        }
        value["receipt_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(value)
        ).hexdigest()
        return value

    def _write_json(self, path: Path, value: dict, *, mode: int = 0o600) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        path.chmod(mode)

    def _ack(self, *, receipt: dict | None = None, timestamp: int = 100) -> dict:
        source = self.receipt if receipt is None else receipt
        value = {
            "schema_version": 1,
            "kind": "grabowski_job_notification_ack",
            "unit": self.unit,
            "job_id": source.get("job_id"),
            "notification_id": source.get("notification_id"),
            "receipt_sha256": source.get("receipt_sha256"),
            "acknowledged_at": "1970-01-01T00:01:40Z",
            "acknowledged_at_unix": timestamp,
            "does_not_establish": ["external_push_delivery", "job_success"],
        }
        value["ack_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(value)
        ).hexdigest()
        return value

    def test_list_exposes_queued_receipt_without_external_delivery_claim(self) -> None:
        result = self.operator.grabowski_job_notification_list(state="queued")
        self.assertEqual(result["returned"], 1)
        self.assertEqual(result["notifications"][0]["delivery_state"], "queued")
        self.assertEqual(
            result["notifications"][0]["receipt_sha256"],
            self.receipt["receipt_sha256"],
        )
        self.assertIn("external_push_delivery", result["does_not_establish"])
        self.assertNotIn("delivered", json.dumps(result).lower())

    def test_ack_is_private_audited_and_idempotent(self) -> None:
        audit = mock.Mock()
        self.operator.base._append_audit = audit
        with mock.patch.object(
            self.operator,
            "_job_timestamp",
            return_value=(100, "1970-01-01T00:01:40Z"),
        ):
            first = self.operator.grabowski_job_notification_ack(
                self.unit,
                self.receipt["receipt_sha256"],
            )
        with mock.patch.object(
            self.operator,
            "_job_timestamp",
            return_value=(200, "1970-01-01T00:03:20Z"),
        ) as timestamp:
            second = self.operator.grabowski_job_notification_ack(
                self.unit,
                self.receipt["receipt_sha256"],
            )

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["acknowledgement"], second["acknowledgement"])
        timestamp.assert_not_called()
        audit.assert_called_once()
        audit_record = audit.call_args.args[0]
        self.assertEqual(audit_record["operation"], "job-notification-ack")
        self.assertEqual(audit_record["receipt_sha256"], self.receipt["receipt_sha256"])
        path = self.directory / "notification-ack.json"
        metadata = path.lstat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(list(self.directory.glob(".notification-ack.json.*.tmp")), [])
        listed = self.operator.grabowski_job_notification_list(state="acknowledged")
        self.assertEqual(listed["returned"], 1)
        self.assertEqual(
            listed["notifications"][0]["ack_sha256"],
            first["acknowledgement"]["ack_sha256"],
        )

    def test_expected_receipt_hash_is_a_precondition(self) -> None:
        with self.assertRaisesRegex(ValueError, "changed"):
            self.operator.grabowski_job_notification_ack(self.unit, "0" * 64)
        self.assertFalse((self.directory / "notification-ack.json").exists())

    def test_tampered_receipt_is_reported_invalid(self) -> None:
        self.receipt["terminal_status"] = "failed"
        self._write_json(self.directory / "notification.json", self.receipt)
        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(result["returned"], 0)
        self.assertEqual(len(result["invalid_receipts"]), 1)
        self.assertIn("hash mismatch", result["invalid_receipts"][0]["error"])

    def test_symlink_and_hardlink_receipts_are_rejected(self) -> None:
        path = self.directory / "notification.json"
        payload = path.read_bytes()
        path.unlink()
        target = self.directory / "target.json"
        target.write_bytes(payload)
        target.chmod(0o600)
        path.symlink_to(target.name)
        symlink_result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(symlink_result["returned"], 0)
        self.assertEqual(len(symlink_result["invalid_receipts"]), 1)

        path.unlink()
        os.link(target, path)
        hardlink_result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(hardlink_result["returned"], 0)
        self.assertEqual(len(hardlink_result["invalid_receipts"]), 1)

    def test_invalid_ack_binding_and_hash_are_not_treated_as_acknowledged(self) -> None:
        ack = self._ack()
        ack["notification_id"] = "0" * 32
        ack["ack_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(
                {key: value for key, value in ack.items() if key != "ack_sha256"}
            )
        ).hexdigest()
        self._write_json(self.directory / "notification-ack.json", ack)
        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(result["returned"], 0)
        self.assertIn("binding mismatch", result["invalid_receipts"][0]["error"])

        evidence = self.operator._job_notification_evidence_for_unit(
            self.unit,
            {"requested": True},
            {"final_status": "succeeded"},
        )
        self.assertEqual(evidence["delivery_state"], "invalid_acknowledgement")
        self.assertEqual(evidence["final_status_preserved"], "succeeded")

        ack = self._ack()
        ack["acknowledged_at_unix"] = 999
        self._write_json(self.directory / "notification-ack.json", ack)
        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(result["returned"], 0)
        self.assertIn("hash mismatch", result["invalid_receipts"][0]["error"])

    def test_publish_race_accepts_valid_winner_without_duplicate_audit(self) -> None:
        audit = mock.Mock()
        self.operator.base._append_audit = audit

        def publish_winner(directory: Path, target: Path, payload: dict) -> bool:
            self._write_json(target, payload)
            return False

        with mock.patch.object(
            self.operator,
            "_job_timestamp",
            return_value=(100, "1970-01-01T00:01:40Z"),
        ), mock.patch.object(
            self.operator,
            "_publish_private_create_only_json",
            side_effect=publish_winner,
        ):
            result = self.operator.grabowski_job_notification_ack(
                self.unit,
                self.receipt["receipt_sha256"],
            )
        self.assertFalse(result["created"])
        audit.assert_not_called()
        self.assertEqual(
            result["acknowledgement"]["receipt_sha256"],
            self.receipt["receipt_sha256"],
        )

    def test_publish_race_rejects_different_winner(self) -> None:
        audit = mock.Mock()
        self.operator.base._append_audit = audit

        def publish_bad_winner(directory: Path, target: Path, payload: dict) -> bool:
            bad = dict(payload)
            bad["receipt_sha256"] = "0" * 64
            bad["ack_sha256"] = hashlib.sha256(
                self.operator._canonical_json_bytes(
                    {key: value for key, value in bad.items() if key != "ack_sha256"}
                )
            ).hexdigest()
            self._write_json(target, bad)
            return False

        with mock.patch.object(
            self.operator,
            "_publish_private_create_only_json",
            side_effect=publish_bad_winner,
        ):
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                self.operator.grabowski_job_notification_ack(
                    self.unit,
                    self.receipt["receipt_sha256"],
                )
        audit.assert_not_called()

    def test_ack_input_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.operator.grabowski_job_notification_ack(self.unit, "bad")
        with self.assertRaises(ValueError):
            self.operator.grabowski_job_notification_list(limit=0)
        with self.assertRaises(ValueError):
            self.operator.grabowski_job_notification_list(state="delivered")


if __name__ == "__main__":
    unittest.main()
