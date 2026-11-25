from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_alert_outbox as outbox
import grabowski_ntfy_dispatch as ntfy


class NetdataNtfyRendererTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        environment = patch.dict(os.environ, {
            "GRABOWSKI_ALERT_OUTBOX_ROOT": str(Path(temporary.name) / "outbox"),
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.serial = 0

    def alert(self, fields, *, kind="owner_decision", producer="netdata_watch",
              subject="heim-pc-netdata"):
        self.serial += 1
        return outbox.enqueue_alert(
            event_class=kind, producer=producer, subject=subject,
            correlation_key=f"probe-{self.serial}", deduplication_key=f"test-{self.serial}",
            fields=fields,
        )["alert"]

    def test_cpu_warning_uses_actual_threshold_and_preserves_metadata(self):
        row = self.alert({"condition": "cpu_temperature_sustained",
                          "threshold": "89C for most of 5min",
                          "detail": "token=secret-value"})
        rendered = ntfy.render_alert_notification(row)
        self.assertIn("CPU-Temperatur", rendered["title"])
        self.assertIn("89 °C", rendered["body"])
        self.assertIn("5 Minuten", rendered["body"])
        self.assertNotIn("secret-value", rendered["body"])
        baseline = ntfy.render_notification(ntfy._alert_render_row(row))
        for key in ("event_class", "correlation_id", "priority", "tags"):
            self.assertEqual(rendered[key], baseline[key])

    def test_btrfs_counter_is_total_not_delta(self):
        row = self.alert({"condition": "new_btrfs_device_errors",
                          "counter": "corruption_errs", "count": "335"})
        result = ntfy.render_alert_notification(row)
        self.assertIn("Btrfs", result["title"])
        self.assertIn("Korruptionsfehler", result["body"])
        self.assertIn("335", result["body"])
        self.assertIn("Gesamtzähler", result["body"])

    def test_native_critical_alarm_names_the_alarm(self):
        row = self.alert({"condition": "native_critical", "alarm": "system.cpu"})
        result = ntfy.render_alert_notification(row)
        self.assertIn("kritischer", result["title"])
        self.assertIn("system.cpu", result["body"])

    def test_monitoring_read_failure_does_not_invent_collector(self):
        row = self.alert({"error_type": "two_failed_reads"}, kind="service_failure")
        result = ntfy.render_alert_notification(row)
        self.assertIn("Messdaten fehlen", result["title"])
        self.assertIn("Zwei aufeinanderfolgende", result["body"])
        self.assertEqual(result["priority"], "5")

    def test_invalid_optional_values_keep_warning_and_do_not_echo_raw_fields(self):
        for fields in (
            {"condition": "cpu_temperature_sustained", "threshold": "unexpected-value"},
            {"condition": "new_btrfs_device_errors", "counter": "unexpected-value", "count": "123"},
            {"condition": "native_critical", "alarm": "unexpected value"},
            {"condition": "unknown", "detail": "unexpected-value"},
        ):
            with self.subTest(fields=fields):
                result = ntfy.render_alert_notification(self.alert(fields))
                self.assertIn("Heim-PC:", result["title"])
                self.assertNotIn("unexpected", result["body"])

    def test_other_producers_and_subjects_keep_original_rendering(self):
        for producer, subject in (
            ("other", "heim-pc-netdata"), ("netdata_watch", "other"),
        ):
            with self.subTest(producer=producer, subject=subject):
                row = self.alert({"condition": "cpu_temperature_sustained"},
                                 producer=producer, subject=subject)
                self.assertEqual(ntfy.render_alert_notification(row),
                                 ntfy.render_notification(ntfy._alert_render_row(row)))

    def test_publish_uses_renderer_and_acknowledges_only_success(self):
        row = self.alert({"condition": "new_btrfs_device_errors",
                          "counter": "read_errs", "count": "4"})
        with patch.object(ntfy, "_publish_rendered", return_value=200) as transport:
            result = ntfy.dispatch_alerts(topic="x" * 32)
        self.assertEqual(result, {"status": "ok", "delivered": 1})
        rendered = transport.call_args.args[1]
        self.assertIn("Lesefehler", rendered["body"])
        self.assertEqual(outbox.list_alerts(state="queued")["queued_count"], 0)
        self.assertEqual(outbox.list_alerts(state="acknowledged")["acknowledged_count"], 1)
        self.assertEqual(outbox.list_alerts(state="acknowledged")["alerts"][0]["alert_id"],
                         row["alert_id"])

    def test_invalid_receipt_cannot_render_or_publish(self):
        row = self.alert({"condition": "cpu_temperature_sustained"})
        row["fields"]["threshold"] = "88C for most of 7min"
        with patch.object(ntfy, "_publish_rendered") as transport:
            with self.assertRaises(outbox.AlertOutboxError):
                ntfy.publish_alert("x" * 32, row)
        transport.assert_not_called()
