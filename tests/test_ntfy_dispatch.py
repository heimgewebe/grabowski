from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

MODULE_PATH = ROOT / "src" / "grabowski_ntfy_dispatch.py"
SPEC = importlib.util.spec_from_file_location("grabowski_ntfy_dispatch", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ntfy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ntfy)


class NtfyDispatchTests(TestCase):
    def test_acks_only_after_successful_ntfy_delivery(self) -> None:
        row = {
            "unit": "grabowski-job-abc.service",
            "job_id": "1234567890abcdef",
            "terminal_status": "succeeded",
            "requested_channels": ["ntfy"],
            "receipt_sha256": "a" * 64,
            "note": "must-not-be-sent",
            "argv": ["secret-command"],
            "origin_sha256": "b" * 64,
        }
        publisher = mock.Mock(return_value=200)
        with mock.patch.object(
            ntfy.operator,
            "grabowski_job_notification_list",
            return_value={"invalid_receipts": [], "notifications": [row]},
        ), mock.patch.object(
            ntfy.operator, "grabowski_job_notification_ack"
        ) as ack:
            result = ntfy.dispatch(topic="x" * 32, publisher=publisher)

        self.assertEqual(result, {"status": "ok", "delivered": 1, "skipped": 0})
        ack.assert_called_once_with(row["unit"], row["receipt_sha256"])
        publisher.assert_called_once_with("x" * 32, row)

    def test_non_2xx_delivery_is_not_acknowledged(self) -> None:
        row = {
            "unit": "grabowski-job-abc.service",
            "job_id": "1234567890abcdef",
            "terminal_status": "failed",
            "requested_channels": ["ntfy"],
            "receipt_sha256": "a" * 64,
        }
        with mock.patch.object(
            ntfy.operator,
            "grabowski_job_notification_list",
            return_value={"invalid_receipts": [], "notifications": [row]},
        ), mock.patch.object(
            ntfy.operator, "grabowski_job_notification_ack"
        ) as ack:
            result = ntfy.dispatch(topic="x" * 32, publisher=lambda _topic, _row: 503)

        self.assertEqual(result["status"], "delivery_failed")
        self.assertEqual(result["http_status"], 503)
        ack.assert_not_called()

    def test_transport_exception_is_not_acknowledged(self) -> None:
        row = {
            "unit": "grabowski-job-abc.service",
            "job_id": "1234567890abcdef",
            "terminal_status": "failed",
            "requested_channels": ["ntfy"],
            "receipt_sha256": "a" * 64,
        }

        def fail(_topic: str, _row: dict[str, object]) -> int:
            raise OSError("offline")

        with mock.patch.object(
            ntfy.operator,
            "grabowski_job_notification_list",
            return_value={"invalid_receipts": [], "notifications": [row]},
        ), mock.patch.object(
            ntfy.operator, "grabowski_job_notification_ack"
        ) as ack:
            result = ntfy.dispatch(topic="x" * 32, publisher=fail)

        self.assertEqual(result["status"], "delivery_failed")
        ack.assert_not_called()

    def test_non_ntfy_channels_are_skipped(self) -> None:
        row = {
            "unit": "grabowski-job-chat.service",
            "job_id": "1234567890abcdef",
            "terminal_status": "succeeded",
            "requested_channels": ["chat"],
            "receipt_sha256": "a" * 64,
        }
        publisher = mock.Mock(return_value=200)
        with mock.patch.object(
            ntfy.operator,
            "grabowski_job_notification_list",
            return_value={"invalid_receipts": [], "notifications": [row]},
        ), mock.patch.object(
            ntfy.operator, "grabowski_job_notification_ack"
        ) as ack:
            result = ntfy.dispatch(topic="x" * 32, publisher=publisher)

        self.assertEqual(result, {"status": "ok", "delivered": 0, "skipped": 1})
        publisher.assert_not_called()
        ack.assert_not_called()

    def test_invalid_outbox_receipts_block_fail_closed(self) -> None:
        with mock.patch.object(
            ntfy.operator,
            "grabowski_job_notification_list",
            return_value={"invalid_receipts": [{"unit": "bad"}], "notifications": []},
        ), mock.patch.object(
            ntfy.operator, "grabowski_job_notification_ack"
        ) as ack:
            result = ntfy.dispatch(topic="x" * 32, publisher=mock.Mock(return_value=200))

        self.assertEqual(result, {"status": "blocked", "reason": "invalid_outbox_receipts"})
        ack.assert_not_called()

    def test_publish_payload_excludes_sensitive_fields(self) -> None:
        row = {
            "job_id": "1234567890abcdef",
            "terminal_status": "succeeded",
            "note": "sensitive note",
            "argv": ["secret-command"],
            "origin_sha256": "b" * 64,
            "receipt_sha256": "c" * 64,
        }

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        captured = {}

        def fake_urlopen(request, timeout):
            captured["data"] = request.data
            captured["timeout"] = timeout
            captured["headers"] = dict(request.header_items())
            return Response()

        with mock.patch.object(ntfy.urllib.request, "urlopen", side_effect=fake_urlopen):
            status = ntfy.publish("x" * 32, row)

        self.assertEqual(status, 200)
        payload = captured["data"].decode("utf-8")
        self.assertIn("90abcdef", payload)
        self.assertIn("succeeded", payload)
        self.assertNotIn("sensitive note", payload)
        self.assertNotIn("secret-command", payload)
        self.assertNotIn("bbbb", payload)
        self.assertNotIn("cccc", payload)


class NtfyFinalizerTriggerTests(TestCase):
    def test_ntfy_channel_schedules_one_transient_dispatcher(self) -> None:
        import grabowski_job_finalizer as finalizer

        completed = mock.Mock(returncode=0)
        with mock.patch.object(finalizer.subprocess, "run", return_value=completed) as run:
            scheduled = finalizer._schedule_ntfy_dispatch("a" * 32, ["ntfy"])

        self.assertTrue(scheduled)
        argv = run.call_args.args[0]
        self.assertIn("--unit=grabowski-ntfy-dispatch-" + "a" * 32 + ".service", argv)
        self.assertEqual(argv[-3:], ["-I", "-m", "grabowski_ntfy_dispatch"])
        self.assertTrue(run.call_args.kwargs["check"] is False)

    def test_non_ntfy_channel_does_not_schedule_dispatcher(self) -> None:
        import grabowski_job_finalizer as finalizer

        with mock.patch.object(finalizer.subprocess, "run") as run:
            scheduled = finalizer._schedule_ntfy_dispatch("a" * 32, ["chat"])

        self.assertFalse(scheduled)
        run.assert_not_called()

    def test_dispatcher_launch_failure_is_fail_soft(self) -> None:
        import grabowski_job_finalizer as finalizer

        with mock.patch.object(finalizer.subprocess, "run", side_effect=OSError("systemd unavailable")):
            scheduled = finalizer._schedule_ntfy_dispatch("a" * 32, ["ntfy"])

        self.assertFalse(scheduled)
