from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


import grabowski_alert_outbox as outbox
import grabowski_ntfy_dispatch as ntfy


class AlertOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "alert-outbox"
        self.environment = patch.dict(
            os.environ,
            {"GRABOWSKI_ALERT_OUTBOX_ROOT": str(self.root)},
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def _enqueue(self, **overrides: object) -> dict[str, object]:
        parameters: dict[str, object] = {
            "event_class": "blocked_operation",
            "producer": "operator_obligation",
            "correlation_key": "goo-example-alert",
            "deduplication_key": "receipt:" + "a" * 64,
            "subject": "operator_obligation",
            "fields": {"outcome": "blocked"},
        }
        parameters.update(overrides)
        return outbox.enqueue_alert(**parameters)

    def test_receipt_is_private_create_only_and_identity_is_deterministic(self) -> None:
        first = self._enqueue()
        second = self._enqueue()

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertTrue(second["replayed"])
        first_alert = first["alert"]
        second_alert = second["alert"]
        self.assertEqual(first_alert["alert_id"], second_alert["alert_id"])
        self.assertEqual(first_alert["correlation_id"], second_alert["correlation_id"])
        self.assertEqual(first_alert["receipt_sha256"], second_alert["receipt_sha256"])
        path = self.root / f"{first_alert['alert_id']}.json"
        self.assertEqual(0o700, self.root.stat().st_mode & 0o777)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual(
            [
                "external_push_delivery",
                "user_has_seen_alert",
                "primary_operation_success",
                "authorization_to_retry_or_mutate",
                "root_cause",
            ],
            first_alert["does_not_establish"],
        )

    def test_deterministic_identity_conflicts_with_different_material(self) -> None:
        self._enqueue(fields={"outcome": "blocked"})

        with self.assertRaises(outbox.AlertOutboxConflictError):
            self._enqueue(fields={"outcome": "completed"})

    def test_fields_are_bounded_redacted_and_do_not_store_identity_keys(self) -> None:
        queued = self._enqueue(
            correlation_key="private-correlation-source",
            deduplication_key="private-deduplication-source",
            fields={"detail": "token=supersecret"},
        )

        alert = queued["alert"]
        self.assertEqual("token=[redacted]", alert["fields"]["detail"])
        encoded = json.dumps(alert, sort_keys=True)
        self.assertNotIn("supersecret", encoded)
        self.assertNotIn("private-correlation-source", encoded)
        self.assertNotIn("private-deduplication-source", encoded)
        with self.assertRaises(outbox.AlertOutboxInputError):
            self._enqueue(fields={"detail": "x" * (outbox.MAX_FIELD_BYTES + 1)})
        with self.assertRaises(outbox.AlertOutboxInputError):
            self._enqueue(fields={"detail": "unsafe\ncontrol"})

    def test_all_event_classes_are_supported(self) -> None:
        seen = set()
        for event_class in sorted(outbox.EVENT_CLASSES):
            queued = self._enqueue(
                event_class=event_class,
                deduplication_key=event_class,
            )
            seen.add(queued["alert"]["event_class"])

        self.assertEqual(outbox.EVENT_CLASSES, seen)

    def test_acknowledgement_requires_2xx_and_is_append_only(self) -> None:
        queued = self._enqueue()
        alert = queued["alert"]

        with self.assertRaises(outbox.AlertOutboxInputError):
            outbox.acknowledge_alert(
                alert["alert_id"],
                alert["receipt_sha256"],
                503,
            )
        self.assertFalse((self.root / f"{alert['alert_id']}.ack.json").exists())

        first = outbox.acknowledge_alert(
            alert["alert_id"],
            alert["receipt_sha256"],
            204,
        )
        second = outbox.acknowledge_alert(
            alert["alert_id"],
            alert["receipt_sha256"],
            204,
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(
            first["acknowledgement"]["ack_sha256"],
            second["acknowledgement"]["ack_sha256"],
        )
        self.assertEqual([], outbox.list_alerts(state="queued")["alerts"])
        self.assertEqual(1, len(outbox.list_alerts(state="acknowledged")["alerts"]))

    def test_invalid_receipt_is_reported_fail_closed(self) -> None:
        queued = self._enqueue()
        alert = queued["alert"]
        path = self.root / f"{alert['alert_id']}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["event_class"] = "forged"
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)

        listed = outbox.list_alerts(state="queued")

        self.assertEqual([], listed["alerts"])
        self.assertEqual(
            "AlertOutboxIntegrityError", listed["invalid_receipts"][0]["error"]
        )

    def test_limit_does_not_hide_invalid_or_orphan_receipts(self) -> None:
        self._enqueue(deduplication_key="first")
        corrupted = self._enqueue(deduplication_key="second")["alert"]
        corrupted_path = self.root / f"{corrupted['alert_id']}.json"
        corrupted_path.write_text("{}", encoding="utf-8")
        os.chmod(corrupted_path, 0o600)
        orphan = self.root / f"{'f' * 32}.ack.json"
        orphan.write_text("{}\n", encoding="utf-8")
        os.chmod(orphan, 0o600)

        listed = outbox.list_alerts(state="queued", limit=1)

        self.assertLessEqual(len(listed["alerts"]), 1)
        self.assertEqual(
            {"AlertOutboxIntegrityError", "orphan_acknowledgement"},
            {item["error"] for item in listed["invalid_receipts"]},
        )

    def test_private_io_temporary_entry_does_not_block_queue_scan(self) -> None:
        queued = self._enqueue()
        alert = queued["alert"]
        temporary = self.root / (
            f".{alert['alert_id']}.json.{os.getpid()}.{'a' * 32}.tmp"
        )
        temporary.write_text("partial", encoding="utf-8")
        os.chmod(temporary, 0o600)

        listed = outbox.list_alerts(state="queued")

        self.assertEqual([], listed["invalid_receipts"])
        self.assertEqual(
            [alert["alert_id"]], [row["alert_id"] for row in listed["alerts"]]
        )

    def test_dispatch_scheduling_uses_existing_entrypoint_and_is_fail_soft(
        self,
    ) -> None:
        completed = Mock(returncode=0)
        with patch.object(outbox.subprocess, "run", return_value=completed) as run:
            self.assertTrue(outbox.schedule_dispatch("a" * 32))

        argv = run.call_args.args[0]
        self.assertIn("--unit=grabowski-ntfy-alert-" + "a" * 32 + ".service", argv)
        self.assertEqual(["-I", "-m", "grabowski_ntfy_dispatch"], argv[-3:])
        with patch.object(outbox.subprocess, "run", side_effect=OSError("offline")):
            self.assertFalse(outbox.schedule_dispatch("a" * 32))


class AlertDispatchTests(unittest.TestCase):
    def test_missing_optional_source_set_makes_no_empty_outbox_claim(self) -> None:
        with patch.object(ntfy, "alert_outbox", None):
            result = ntfy.dispatch_alerts(topic="x" * 32)

        self.assertEqual("ok", result["status"])
        self.assertEqual("alert_outbox_unavailable", result["reason"])
        self.assertEqual(["alert_outbox_empty"], result["does_not_establish"])

    def test_dispatch_acknowledges_alert_only_after_http_2xx(self) -> None:
        row = {
            "alert_id": "a" * 32,
            "receipt_sha256": "b" * 64,
        }
        with (
            patch.object(
                ntfy.alert_outbox,
                "list_alerts",
                return_value={"alerts": [row], "invalid_receipts": []},
            ),
            patch.object(ntfy.alert_outbox, "acknowledge_alert") as acknowledge,
        ):
            failed = ntfy.dispatch_alerts(
                topic="x" * 32,
                publisher=lambda _topic, _row: 503,
            )
            acknowledge.assert_not_called()
            delivered = ntfy.dispatch_alerts(
                topic="x" * 32,
                publisher=lambda _topic, _row: 201,
            )

        self.assertEqual("delivery_failed", failed["status"])
        self.assertEqual("ok", delivered["status"])
        acknowledge.assert_called_once_with("a" * 32, "b" * 64, 201)

    def test_acknowledgement_failure_is_structured_and_retryable(self) -> None:
        row = {
            "alert_id": "a" * 32,
            "receipt_sha256": "b" * 64,
        }
        with (
            patch.object(
                ntfy.alert_outbox,
                "list_alerts",
                return_value={"alerts": [row], "invalid_receipts": []},
            ),
            patch.object(
                ntfy.alert_outbox,
                "acknowledge_alert",
                side_effect=RuntimeError("ack write failed"),
            ),
        ):
            result = ntfy.dispatch_alerts(
                topic="x" * 32,
                publisher=lambda _topic, _row: 201,
            )

        self.assertEqual("delivery_failed", result["status"])
        self.assertEqual(0, result["delivered"])
        self.assertEqual(1, result["failed"])
        self.assertEqual("acknowledgement", result["phase"])
        self.assertEqual("RuntimeError", result["error_type"])

    def test_invalid_alert_receipt_blocks_dispatch(self) -> None:
        with (
            patch.object(
                ntfy.alert_outbox,
                "list_alerts",
                return_value={
                    "alerts": [],
                    "invalid_receipts": [{"name": "bad", "error": "invalid"}],
                },
            ),
            patch.object(ntfy.alert_outbox, "acknowledge_alert") as acknowledge,
        ):
            result = ntfy.dispatch_alerts(
                topic="x" * 32,
                publisher=Mock(return_value=200),
            )

        self.assertEqual(
            {"status": "blocked", "reason": "invalid_alert_outbox_receipts"},
            result,
        )
        acknowledge.assert_not_called()
