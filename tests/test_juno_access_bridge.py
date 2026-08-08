from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools" / "juno" / "juno_access_bridge.py"


def load_bridge():
    spec = importlib.util.spec_from_file_location("test_juno_access_bridge_module", PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load bridge")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class JunoAccessBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = load_bridge()

    def request(self, operation: str, **values):
        return {"schema_version": 1, "operation": operation, **values}

    def test_import_does_not_require_juno(self) -> None:
        self.assertNotIn("juno.objc", sys.modules)
        result = self.bridge.dispatch(self.request("capabilities"))
        self.assertEqual("capabilities", result["operation"])
        self.assertIn("contacts_search", result["operations"])

    def test_unknown_operation_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported operation"):
            self.bridge.dispatch(self.request("root_shell"))

    def test_schema_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "schema_version"):
            self.bridge.dispatch({"operation": "capabilities"})

    def test_private_operations_require_ack_before_native_import(self) -> None:
        for operation, values in (
            ("clipboard_get_text", {}),
            ("motion_sample", {}),
            ("bluetooth_scan", {}),
            ("contacts_search", {"query": "Alex"}),
            ("reminders_list", {}),
            ("location_one_shot", {}),
            ("photos_latest_metadata", {}),
            ("mic_record_short", {"relative_path": "capture.caf"}),
        ):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, "private_content_ack"):
                    self.bridge.dispatch(self.request(operation, **values))

    def test_url_validation_rejects_non_allowlisted_scheme_before_native_import(self) -> None:
        with patch.object(self.bridge, "_require_foreground", return_value=None):
            with self.assertRaisesRegex(ValueError, "scheme"):
                self.bridge.dispatch(self.request("open_url", url="file:///etc/passwd"))

    def test_url_size_bound(self) -> None:
        with patch.object(self.bridge, "_require_foreground", return_value=None):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                self.bridge.dispatch(
                    self.request("open_url", url="https://example.invalid/" + "x" * 5000)
                )

    def test_identifier_validation(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid characters"):
            self.bridge._identifier(self.request("notification_remove", identifier="../../bad"))

    def test_numeric_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "out of range"):
            self.bridge._number(
                self.request("capabilities", duration=999),
                "duration",
                minimum=1,
                maximum=10,
            )
        with self.assertRaisesRegex(ValueError, "integer"):
            self.bridge._integer(
                self.request("capabilities", max_results=True),
                "max_results",
                minimum=1,
                maximum=25,
            )

    def test_workspace_path_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = self.bridge._safe_workspace_path(root, "recordings/test.caf")
            self.assertEqual(root / "recordings" / "test.caf", valid)
            for value in ("../escape.caf", "/tmp/escape.caf", "a/../../escape.caf"):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ValueError, "workspace|escapes"):
                        self.bridge._safe_workspace_path(root, value)

    def test_capability_contract_marks_privacy_and_foreground(self) -> None:
        result = self.bridge.dispatch(self.request("capabilities"))
        self.assertTrue(result["operations"]["contacts_search"]["private_content_ack_required"])
        self.assertTrue(result["operations"]["location_one_shot"]["foreground_required"])
        self.assertFalse(result["operations"]["notification_schedule"]["private_content_ack_required"])
        self.assertFalse(result["operations"]["replaykit_status"]["foreground_required"])


    def test_native_bool_property_accepts_objc_is_accessor(self) -> None:
        class FakeRecorder:
            def isAvailable(self):
                return True

        self.assertTrue(
            self.bridge._native_bool_property(FakeRecorder(), "available", "isAvailable")
        )

    def test_output_is_json_serializable(self) -> None:
        result = self.bridge.dispatch(self.request("capabilities"))
        json.dumps(result)

    def test_clipboard_set_is_size_bounded_before_native_import(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte bound"):
            self.bridge.dispatch(self.request("clipboard_set_text", text="x" * 20000))

    def test_contacts_query_and_result_bounds_are_validated_before_native_import(self) -> None:
        with self.assertRaisesRegex(ValueError, "byte bound"):
            self.bridge.dispatch(
                self.request(
                    "contacts_search",
                    query="x" * 600,
                    max_results=10,
                    private_content_ack=True,
                )
            )
        with self.assertRaisesRegex(ValueError, "out of range"):
            self.bridge.dispatch(
                self.request(
                    "contacts_search",
                    query="Alex",
                    max_results=26,
                    private_content_ack=True,
                )
            )

    def test_mic_path_suffix_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(self.bridge, "_require_foreground", return_value=None):
                with self.assertRaisesRegex(ValueError, r"\.caf"):
                    self.bridge.dispatch(
                        self.request(
                            "mic_record_short",
                            relative_path="recordings/bad.txt",
                            duration_seconds=1,
                            private_content_ack=True,
                        ),
                        workspace=Path(directory),
                    )


if __name__ == "__main__":
    unittest.main()
