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

    def test_list_preserves_valid_legacy_nonhex_job_names_after_prefilter(self) -> None:
        legacy_job_id = "legacy000001"
        legacy_unit = f"grabowski-job-{legacy_job_id}"
        legacy_directory = self.jobs / legacy_unit
        legacy_directory.mkdir(mode=0o700)
        legacy_receipt = {
            **self.receipt,
            "job_id": legacy_job_id,
            "unit": legacy_unit,
            "notification_id": "e" * 32,
        }
        legacy_receipt.pop("receipt_sha256", None)
        legacy_receipt["receipt_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(legacy_receipt)
        ).hexdigest()
        self._write_json(legacy_directory / "notification.json", legacy_receipt)

        invalid = self.jobs / "not-a-grabowski-job"
        invalid.mkdir(mode=0o700)
        (self.jobs / "grabowski-job-file000000").write_text("not a directory")

        result = self.operator.grabowski_job_notification_list(state="queued")
        self.assertEqual(result["returned"], 2)
        self.assertEqual(
            {row["unit"] for row in result["notifications"]},
            {self.unit, legacy_unit},
        )

    def test_schema_two_receipt_rejects_noncanonical_legacy_unit_name(self) -> None:
        legacy_job_id = "legacy000001"
        legacy_unit = f"grabowski-job-{legacy_job_id}"
        legacy_directory = self.jobs / legacy_unit
        legacy_directory.mkdir(mode=0o700)
        receipt = {
            **self.receipt,
            "schema_version": 2,
            "job_id": legacy_job_id,
            "unit": legacy_unit,
            "origin_sha256": "b" * 64,
            "invoker_tool": "grabowski_job_start",
            "origin_binding": self.operator.JOB_NOTIFICATION_ORIGIN_BINDING,
            "trust_boundary": self.operator.JOB_NOTIFICATION_TRUST_BOUNDARY,
        }
        receipt.pop("receipt_sha256", None)
        receipt["receipt_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(receipt)
        ).hexdigest()
        self._write_json(legacy_directory / "notification.json", receipt)

        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertTrue(any(
            "canonical job unit" in row["error"]
            for row in result["invalid_receipts"]
        ))

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

    def _install_origin_bound_receipt(self) -> tuple[dict, dict]:
        metadata = {
            "schema_version": 2,
            "unit": self.unit,
            "job_id": self.job_id,
            "owner": "uid:1000",
            "scope": {"cwd": "/tmp"},
            "argv_sha256": "a" * 64,
            "notify_on_done": {
                "requested": True,
                "channels": ["operator_outbox"],
                "note": "done",
            },
            "created_at_unix": 100,
            "started_at": "1970-01-01T00:01:40Z",
        }
        origin, origin_sha256 = self.operator.job_origin.build_origin(
            unit=self.unit,
            owner=metadata["owner"],
            argv_sha256=metadata["argv_sha256"],
            scope=metadata["scope"],
            notify_on_done=metadata["notify_on_done"],
            created_at_unix=metadata["created_at_unix"],
            started_at=metadata["started_at"],
            invoker_tool="grabowski_job_start",
        )
        metadata["origin"] = origin
        metadata["origin_sha256"] = origin_sha256
        receipt = {
            **self._receipt(),
            "schema_version": 2,
            "origin_sha256": origin_sha256,
            "invoker_tool": "grabowski_job_start",
            "origin_binding": self.operator.JOB_NOTIFICATION_ORIGIN_BINDING,
            "trust_boundary": self.operator.JOB_NOTIFICATION_TRUST_BOUNDARY,
            "does_not_establish": [
                "external_push_delivery",
                "user_has_seen_notification",
                "job_success_beyond_terminalization_evidence",
                "untrusted_same_uid_job_authenticity",
            ],
        }
        receipt.pop("receipt_sha256", None)
        receipt["receipt_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(receipt)
        ).hexdigest()
        self._write_json(self.directory / "metadata.json", metadata)
        self._write_json(self.directory / "notification.json", receipt)
        self.receipt = receipt
        return metadata, receipt

    def test_schema_two_receipt_and_ack_preserve_origin_binding(self) -> None:
        _metadata, receipt = self._install_origin_bound_receipt()
        listed = self.operator.grabowski_job_notification_list(state="queued")
        self.assertEqual(listed["schema_version"], 2)
        row = listed["notifications"][0]
        self.assertEqual(row["receipt_schema_version"], 2)
        self.assertEqual(row["origin_sha256"], receipt["origin_sha256"])
        self.assertEqual(row["invoker_tool"], "grabowski_job_start")
        self.assertEqual(row["trust_boundary"], "same_uid_authorized_job")

        self.operator.base._append_audit = mock.Mock()
        with mock.patch.object(
            self.operator,
            "_job_timestamp",
            return_value=(100, "1970-01-01T00:01:40Z"),
        ):
            result = self.operator.grabowski_job_notification_ack(
                self.unit,
                receipt["receipt_sha256"],
            )
        acknowledgement = result["acknowledgement"]
        self.assertEqual(acknowledgement["schema_version"], 2)
        self.assertEqual(acknowledgement["origin_sha256"], receipt["origin_sha256"])
        self.assertEqual(acknowledgement["invoker_tool"], "grabowski_job_start")

    def test_schema_two_receipt_fails_closed_on_metadata_origin_drift(self) -> None:
        metadata, _receipt = self._install_origin_bound_receipt()
        metadata["scope"] = {"cwd": "/attacker"}
        self._write_json(self.directory / "metadata.json", metadata)
        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(result["returned"], 0)
        self.assertIn("scope binding mismatch", result["invalid_receipts"][0]["error"])

    def test_schema_two_ack_rejects_unknown_rehashed_claims(self) -> None:
        _metadata, receipt = self._install_origin_bound_receipt()
        acknowledgement = {
            "schema_version": 2,
            "kind": "grabowski_job_notification_ack",
            "unit": self.unit,
            "job_id": self.job_id,
            "notification_id": receipt["notification_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "origin_sha256": receipt["origin_sha256"],
            "invoker_tool": receipt["invoker_tool"],
            "acknowledged_at": "1970-01-01T00:01:40Z",
            "acknowledged_at_unix": 100,
            "does_not_establish": [
                "external_push_delivery",
                "job_success",
                "untrusted_same_uid_job_authenticity",
            ],
            "fabricated_delivery_claim": True,
        }
        acknowledgement["ack_sha256"] = hashlib.sha256(
            self.operator._canonical_json_bytes(acknowledgement)
        ).hexdigest()
        self._write_json(self.directory / "notification-ack.json", acknowledgement)
        result = self.operator.grabowski_job_notification_list(state="all")
        self.assertEqual(result["returned"], 0)
        self.assertIn("schema is invalid", result["invalid_receipts"][0]["error"])

    def test_ack_input_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.operator.grabowski_job_notification_ack(self.unit, "bad")
        with self.assertRaises(ValueError):
            self.operator.grabowski_job_notification_list(limit=0)
        with self.assertRaises(ValueError):
            self.operator.grabowski_job_notification_list(state="delivered")


if __name__ == "__main__":
    unittest.main()
