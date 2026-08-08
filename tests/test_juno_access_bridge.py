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

    def test_array_items_supports_python_sequences(self) -> None:
        self.assertEqual([1, 2], self.bridge._array_items([1, 2, 3], 2))

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


    def test_camera_and_vision_operations_require_private_ack(self) -> None:
        for operation in (
            "camera_photo_workspace",
            "vision_ocr_workspace_image",
            "vision_barcodes_workspace_image",
        ):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, "private_content_ack"):
                    self.bridge.dispatch(
                        self.request(operation, relative_path="test.jpg"),
                        workspace=Path("/tmp"),
                    )

    def test_workspace_image_path_rejects_non_image_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "note.txt").write_text("x")
            with self.assertRaisesRegex(ValueError, "image type"):
                self.bridge._workspace_image_path(
                    self.request("vision_ocr_workspace_image", relative_path="note.txt"),
                    root,
                )
            with self.assertRaisesRegex(ValueError, "workspace|escapes"):
                self.bridge._workspace_image_path(
                    self.request("vision_ocr_workspace_image", relative_path="../image.jpg"),
                    root,
                )

    def test_camera_target_suffix_is_validated_before_native_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(self.bridge, "_require_foreground", return_value=None):
                with self.assertRaisesRegex(ValueError, "jpg"):
                    self.bridge.dispatch(
                        self.request(
                            "camera_photo_workspace",
                            relative_path="capture.png",
                            private_content_ack=True,
                        ),
                        workspace=Path(directory),
                    )

    def test_shortcut_name_bound_is_validated_before_native_open(self) -> None:
        with patch.object(self.bridge, "_require_foreground", return_value=None):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                self.bridge.dispatch(
                    self.request("shortcut_run", name="x" * 300),
                )

    def test_share_workspace_file_requires_private_ack(self) -> None:
        with self.assertRaisesRegex(ValueError, "private_content_ack"):
            self.bridge.dispatch(
                self.request("share_workspace_file", relative_path="file.txt"),
                workspace=Path("/tmp"),
            )

    def test_share_workspace_file_path_is_bounded_before_native_ui(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(self.bridge, "_require_foreground", return_value=None):
                with self.assertRaisesRegex(ValueError, "workspace|escapes"):
                    self.bridge.dispatch(
                        self.request(
                            "share_workspace_file",
                            relative_path="../secret.txt",
                            private_content_ack=True,
                        ),
                        workspace=root,
                    )

    def test_share_text_size_is_bounded_before_native_ui(self) -> None:
        with patch.object(self.bridge, "_require_foreground", return_value=None):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                self.bridge.dispatch(
                    self.request("share_text", text="x" * 20000),
                )

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


    def test_retention_mutations_are_lock_guarded(self) -> None:
        class TrackingLock:
            def __init__(self) -> None:
                self.entries = 0

            def __enter__(self):
                self.entries += 1
                return self

            def __exit__(self, exc_type, exc, traceback) -> None:
                return None

        lock = TrackingLock()
        value = object()
        self.bridge._RETAINED.clear()
        try:
            with patch.object(self.bridge, "_RETAINED_LOCK", lock):
                self.bridge._retain(value)
                self.bridge._release(value)
        finally:
            self.bridge._RETAINED.clear()
        self.assertEqual(2, lock.entries)

    def test_bluetooth_and_location_cleanup_have_bounded_completion_paths(self) -> None:
        import inspect

        bluetooth_source = inspect.getsource(self.bridge._bluetooth_scan)
        location_source = inspect.getsource(self.bridge._location_one_shot)
        self.assertIn("done.set()", bluetooth_source)
        self.assertIn("done.wait(duration)", bluetooth_source)
        self.assertNotIn("time.sleep(duration)", bluetooth_source)
        self.assertIn("manager.stopUpdatingLocation", location_source)

    def test_syntactic_validation_precedes_foreground_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = (
                (self.request("open_url", url="file:///etc/passwd"), None, "scheme"),
                (
                    self.request("motion_sample", timeout_seconds=99, private_content_ack=True),
                    None,
                    "out of range",
                ),
                (
                    self.request("location_one_shot", timeout_seconds=99, private_content_ack=True),
                    None,
                    "out of range",
                ),
                (
                    self.request("mic_record_short", relative_path="capture.txt", private_content_ack=True),
                    root,
                    r"\.caf",
                ),
                (
                    self.request("camera_photo_workspace", relative_path="capture.png", private_content_ack=True),
                    root,
                    "jpg",
                ),
                (self.request("shortcut_run", name="x" * 300), None, "byte bound"),
                (
                    self.request("share_workspace_file", relative_path="../escape.txt", private_content_ack=True),
                    root,
                    "workspace|escapes",
                ),
                (self.request("share_text", text="x" * 20000), None, "byte bound"),
            )
            for request, workspace, message in cases:
                with self.subTest(operation=request["operation"]):
                    with patch.object(
                        self.bridge,
                        "_require_foreground",
                        side_effect=AssertionError("foreground checked too early"),
                    ):
                        with self.assertRaisesRegex(ValueError, message):
                            self.bridge.dispatch(request, workspace=workspace)

    def test_photos_fetch_is_sorted_and_limited_at_framework_level(self) -> None:
        class FakeAsset:
            def __init__(self, identifier: str) -> None:
                self.localIdentifier = identifier
                self.mediaType = 1
                self.pixelWidth = 10
                self.pixelHeight = 20
                self.duration = 0.0
                self.favorite = False
                self.hidden = False
                self.creationDate = identifier

        class FakeAssets:
            def __init__(self) -> None:
                self.items = [FakeAsset("newest"), FakeAsset("older"), FakeAsset("old")]
                self.count = len(self.items)

            def objectAtIndex_(self, index: int):
                return self.items[index]

        class FakeOptions:
            latest = None

            @classmethod
            def alloc(cls):
                cls.latest = cls()
                return cls.latest

            def init(self):
                return self

            def setSortDescriptors_(self, value) -> None:
                self.sort_descriptors = value

            def setFetchLimit_(self, value) -> None:
                self.fetch_limit = value

        class FakePhotoLibrary:
            @staticmethod
            def authorizationStatusForAccessLevel_(level: int) -> int:
                return 3

        class FakePHAsset:
            last_options = None

            @classmethod
            def fetchAssetsWithOptions_(cls, options):
                cls.last_options = options
                return FakeAssets()

        class FakeSortDescriptor:
            @staticmethod
            def sortDescriptorWithKey_ascending_(key: str, ascending: bool):
                return (key, ascending)

        class FakeObjC:
            classes = {
                "PHPhotoLibrary": FakePhotoLibrary,
                "PHFetchOptions": FakeOptions,
                "PHAsset": FakePHAsset,
                "NSSortDescriptor": FakeSortDescriptor,
            }

            def ObjCClass(self, name: str):
                return self.classes[name]

            @staticmethod
            def ns(value):
                return value

        with patch.object(self.bridge, "_objc", return_value=FakeObjC()):
            result = self.bridge.dispatch(
                self.request("photos_latest_metadata", max_results=2, private_content_ack=True)
            )
        self.assertEqual(2, FakeOptions.latest.fetch_limit)
        self.assertEqual([("creationDate", False)], FakeOptions.latest.sort_descriptors)
        self.assertIs(FakePHAsset.last_options, FakeOptions.latest)
        self.assertEqual(
            ["newest", "older"],
            [item["local_identifier"] for item in result["assets"]],
        )

if __name__ == "__main__":
    unittest.main()
