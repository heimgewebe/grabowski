from __future__ import annotations

import base64
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_juno_storage as storage  # noqa: E402


GRANT_ID = "grant-" + "a" * 32
EVIDENCE_HASH = "b" * 64
PROVIDER = "document_provider_test"


class FakeURL:
    def __init__(self, path: Path) -> None:
        self.path = str(path)
        self.started = False
        self.stopped = False

    def startAccessingSecurityScopedResource(self) -> bool:
        self.started = True
        return True

    def stopAccessingSecurityScopedResource(self) -> None:
        self.stopped = True


class JunoStorageDeviceRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.external = self.root / "provider"
        self.external.mkdir(parents=True)
        self.home.mkdir(parents=True)
        bookmark = b"test-security-scoped-bookmark"
        evidence_material = {
            "schema_version": 1,
            "grant_id": GRANT_ID,
            "selected_path": str(self.external.resolve()),
            "selected_name": "provider",
            "provider_hint": PROVIDER,
            "bookmark_sha256": hashlib.sha256(bookmark).hexdigest(),
            "bookmark_creation_options": 1 << 11,
            "bookmark_resolution_options": 1 << 10,
            "created_at": "2026-07-16T00:00:00+00:00",
            "exists": True,
            "readable": True,
            "writable": True,
            "externally_granted": True,
        }
        self.evidence_hash = hashlib.sha256(
            json.dumps(
                evidence_material,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        record = {
            **evidence_material,
            "kind": "grabowski_juno_storage_grant",
            "bookmark_b64": base64.b64encode(bookmark).decode("ascii"),
            "evidence_hash": self.evidence_hash,
            "limitations": [],
        }
        grants = (
            self.home
            / "Library"
            / "Application Support"
            / "GrabowskiJunoAgent"
            / "storage-grants"
        )
        grants.mkdir(parents=True, mode=0o700)
        path = grants / f"{GRANT_ID}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_device(self, request: dict[str, object]) -> dict[str, object]:
        external = self.external

        class FakeNSURLClass:
            @staticmethod
            def URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                _data: object,
                _options: int,
                _relative: object,
                _stale: object,
                _error: object,
            ) -> FakeURL:
                return FakeURL(external)

        objc = ModuleType("juno.objc")
        objc.ObjCClass = lambda name: FakeNSURLClass if name == "NSURL" else None
        objc.ns = lambda value: value
        objc.nsdata_to_bytes = lambda value: bytes(value)
        objc.py_from_ns = lambda value: value
        juno = ModuleType("juno")
        juno.objc = objc
        code, digest = storage._storage_code(request)
        self.assertEqual(hashlib.sha256(code.encode("utf-8")).hexdigest(), digest)
        namespace: dict[str, object] = {}
        with (
            patch.dict(sys.modules, {"juno": juno, "juno.objc": objc}),
            patch.dict(os.environ, {"HOME": str(self.home)}),
        ):
            exec(compile(code, "<juno-storage-job>", "exec"), namespace)
        result = namespace["GRABOWSKI_RESULT"]
        self.assertIsInstance(result, dict)
        return result

    def base_request(self, operation: str, relative_path: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "operation": operation,
            "grant_id": GRANT_ID,
            "expected_grant_evidence_hash": self.evidence_hash,
            "expected_provider": PROVIDER,
            "relative_path": relative_path,
        }

    def test_create_read_and_hash_bound_replace(self) -> None:
        first = b"first sentinel"
        create = {
            **self.base_request("file_create", "sentinel.txt"),
            "payload_b64": base64.b64encode(first).decode("ascii"),
            "payload_sha256": hashlib.sha256(first).hexdigest(),
            "max_write_bytes": 1024,
        }
        created = self.run_device(create)
        self.assertEqual(created["kind"], "ipad_file_create")
        self.assertEqual(created["expected_prestate"], "absent")
        self.assertEqual(created["readback"]["sha256"], hashlib.sha256(first).hexdigest())
        self.assertEqual((self.external / "sentinel.txt").read_bytes(), first)

        read = {
            **self.base_request("file_read", "sentinel.txt"),
            "max_bytes": 1024,
        }
        observed = self.run_device(read)
        self.assertEqual(base64.b64decode(observed["payload_b64"]), first)
        self.assertEqual(observed["sha256"], hashlib.sha256(first).hexdigest())

        second = b"second sentinel"
        replace = {
            **self.base_request("file_replace", "sentinel.txt"),
            "expected_sha256": hashlib.sha256(first).hexdigest(),
            "payload_b64": base64.b64encode(second).decode("ascii"),
            "payload_sha256": hashlib.sha256(second).hexdigest(),
            "max_write_bytes": 1024,
        }
        replaced = self.run_device(replace)
        self.assertEqual(replaced["readback"]["before"]["sha256"], hashlib.sha256(first).hexdigest())
        self.assertEqual(replaced["readback"]["after"]["sha256"], hashlib.sha256(second).hexdigest())
        self.assertEqual((self.external / "sentinel.txt").read_bytes(), second)

        with self.assertRaisesRegex(RuntimeError, "does not match"):
            self.run_device({**replace, "expected_sha256": "0" * 64})
        self.assertEqual((self.external / "sentinel.txt").read_bytes(), second)

    def test_create_is_create_only_and_path_traversal_is_rejected(self) -> None:
        payload = b"bounded"
        request = {
            **self.base_request("file_create", "bounded.txt"),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "max_write_bytes": 1024,
        }
        self.run_device(request)
        with self.assertRaises(FileExistsError):
            self.run_device(request)
        code, _digest = storage._storage_code(
            {**request, "relative_path": "../outside.txt"}
        )
        namespace: dict[str, object] = {}
        external = self.external

        class FakeNSURLClass:
            @staticmethod
            def URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                *_args: object,
            ) -> FakeURL:
                return FakeURL(external)

        objc = ModuleType("juno.objc")
        objc.ObjCClass = lambda _name: FakeNSURLClass
        objc.ns = lambda value: value
        objc.nsdata_to_bytes = lambda value: bytes(value)
        objc.py_from_ns = lambda value: value
        juno = ModuleType("juno")
        juno.objc = objc
        with (
            patch.dict(sys.modules, {"juno": juno, "juno.objc": objc}),
            patch.dict(os.environ, {"HOME": str(self.home)}),
        ):
            with self.assertRaisesRegex(ValueError, "unsafe segment"):
                exec(compile(code, "<juno-storage-job>", "exec"), namespace)
        self.assertFalse((self.root / "outside.txt").exists())

    def test_directory_list_is_immediate_and_bounded(self) -> None:
        (self.external / "a.txt").write_text("a", encoding="utf-8")
        (self.external / "folder").mkdir()
        (self.external / "folder" / "nested.txt").write_text("nested", encoding="utf-8")
        request = {
            **self.base_request("directory_list", ""),
            "limit": 10,
            "max_scan_entries": 10,
        }
        result = self.run_device(request)
        self.assertEqual([entry["name"] for entry in result["entries"]], ["a.txt", "folder"])
        self.assertFalse(result["truncated"])
        self.assertFalse(result["scan_truncated"])
        self.assertEqual(result["scan_limit"], 10)
        self.assertEqual(result["scanned_count"], 2)
        self.assertNotIn("nested.txt", json.dumps(result))

        limited = self.run_device({**request, "limit": 1})
        self.assertEqual([entry["name"] for entry in limited["entries"]], ["a.txt"])
        self.assertTrue(limited["truncated"])
        self.assertFalse(limited["scan_truncated"])

        with patch.object(os, "listdir", side_effect=AssertionError("unbounded listdir")):
            scan_limited = self.run_device(
                {**request, "limit": 1, "max_scan_entries": 1}
            )
        self.assertEqual(len(scan_limited["entries"]), 1)
        self.assertTrue(scan_limited["truncated"])
        self.assertTrue(scan_limited["scan_truncated"])
        self.assertEqual(scan_limited["scanned_count"], 1)
        self.assertIn("directory_view_is_partial", scan_limited["limitations"][0])

    def test_broken_symlink_target_and_grant_evidence_tampering_are_rejected(self) -> None:
        broken = self.external / "broken.txt"
        broken.symlink_to(self.external / "missing.txt")
        request = {
            **self.base_request("file_create", "broken.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        with self.assertRaisesRegex(PermissionError, "symlink"):
            self.run_device(request)

        grant_path = (
            self.home
            / "Library"
            / "Application Support"
            / "GrabowskiJunoAgent"
            / "storage-grants"
            / f"{GRANT_ID}.json"
        )
        record = json.loads(grant_path.read_text(encoding="utf-8"))
        record["selected_name"] = "tampered"
        grant_path.write_text(json.dumps(record), encoding="utf-8")
        grant_path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "evidence hash mismatch"):
            self.run_device({**self.base_request("grant_status", "")})

    def test_create_write_failure_preserves_partial_file_safely(self) -> None:
        request = {
            **self.base_request("file_create", "partial.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        with (
            patch.object(
                os,
                "write",
                side_effect=OSError(errno.ENOSPC, "simulated full provider"),
            ),
            patch.object(
                os,
                "unlink",
                side_effect=AssertionError("failure cleanup must not unlink by name"),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "atomic identity-conditional unlink.*residue preserved",
            ):
                self.run_device(request)
        partial = self.external / "partial.txt"
        self.assertTrue(partial.exists())
        partial.unlink()

    def test_create_close_failure_is_reported_and_preserves_file(self) -> None:
        request = {
            **self.base_request("file_create", "close-failure.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        target = self.external / "close-failure.txt"
        real_close = os.close
        failed = False

        def failing_close(descriptor: int) -> None:
            nonlocal failed
            metadata = os.fstat(descriptor)
            should_fail = (
                not failed
                and target.exists()
                and metadata.st_dev == target.stat().st_dev
                and metadata.st_ino == target.stat().st_ino
            )
            real_close(descriptor)
            if should_fail:
                failed = True
                raise OSError(errno.EIO, "simulated delayed close failure")

        with patch.object(os, "close", side_effect=failing_close):
            with self.assertRaisesRegex(
                RuntimeError,
                "atomic identity-conditional unlink.*residue preserved",
            ):
                self.run_device(request)
        self.assertTrue(failed)
        self.assertEqual(target.read_bytes(), b"payload")
        target.unlink()

    def test_create_readback_failure_preserves_created_file(self) -> None:
        request = {
            **self.base_request("file_create", "readback.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        real_read = os.read

        def failing_read(descriptor: int, size: int) -> bytes:
            if not (self.external / "readback.txt").exists():
                return real_read(descriptor, size)
            raise OSError(errno.EIO, "simulated provider readback failure")

        with patch.object(os, "read", side_effect=failing_read):
            with self.assertRaisesRegex(RuntimeError, "residue preserved"):
                self.run_device(request)
        target = self.external / "readback.txt"
        self.assertEqual(target.read_bytes(), b"payload")
        target.unlink()

    def test_create_readback_failure_does_not_touch_a_replacement(self) -> None:
        request = {
            **self.base_request("file_create", "readback.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        replaced = False
        real_read = os.read

        def failing_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            target = self.external / "readback.txt"
            if not target.exists():
                return real_read(descriptor, size)
            if not replaced:
                displaced = self.external / "readback-displaced.txt"
                target.rename(displaced)
                target.write_bytes(b"replacement")
                replaced = True
            raise OSError(errno.EIO, "simulated provider readback failure")

        with patch.object(os, "read", side_effect=failing_read):
            with self.assertRaisesRegex(
                RuntimeError,
                "cleanup target changed.*cleanup was skipped",
            ):
                self.run_device(request)
        self.assertTrue(replaced)
        self.assertEqual((self.external / "readback.txt").read_bytes(), b"replacement")
        (self.external / "readback.txt").unlink()
        (self.external / "readback-displaced.txt").unlink()

    def test_create_write_failure_does_not_touch_a_replacement(self) -> None:
        request = {
            **self.base_request("file_create", "partial.txt"),
            "payload_b64": base64.b64encode(b"payload").decode("ascii"),
            "payload_sha256": hashlib.sha256(b"payload").hexdigest(),
            "max_write_bytes": 1024,
        }
        replaced = False

        def failing_write(descriptor: int, payload: bytes) -> int:
            nonlocal replaced
            if not replaced:
                partial = self.external / "partial.txt"
                displaced = self.external / "partial-displaced.txt"
                partial.rename(displaced)
                partial.write_bytes(b"replacement")
                replaced = True
            raise OSError(errno.ENOSPC, "simulated full provider")

        with patch.object(os, "write", side_effect=failing_write):
            with self.assertRaisesRegex(
                RuntimeError,
                "cleanup target changed.*cleanup was skipped",
            ):
                self.run_device(request)
        self.assertTrue(replaced)
        self.assertEqual((self.external / "partial.txt").read_bytes(), b"replacement")
        (self.external / "partial.txt").unlink()
        (self.external / "partial-displaced.txt").unlink()

    def test_directory_list_on_file_has_stable_validation_error(self) -> None:
        (self.external / "plain.txt").write_text("plain", encoding="utf-8")
        request = {
            **self.base_request("directory_list", "plain.txt"),
            "limit": 10,
            "max_scan_entries": 10,
        }
        with self.assertRaisesRegex(ValueError, "target is not a directory"):
            self.run_device(request)

    def test_replace_write_failure_preserves_temporary_safely(self) -> None:
        target = self.external / "target.txt"
        target.write_bytes(b"before")
        payload = b"after"
        request = {
            **self.base_request("file_replace", "target.txt"),
            "expected_sha256": hashlib.sha256(b"before").hexdigest(),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "max_write_bytes": 1024,
        }
        with (
            patch.object(
                os,
                "write",
                side_effect=OSError(errno.ENOSPC, "simulated full provider"),
            ),
            patch.object(
                os,
                "unlink",
                side_effect=AssertionError("failure cleanup must not unlink by name"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "residue preserved"):
                self.run_device(request)
        self.assertEqual(target.read_bytes(), b"before")
        leftovers = list(self.external.glob(".grabowski-replace-*.tmp"))
        self.assertEqual(len(leftovers), 1)
        leftovers[0].unlink()

    def test_replace_failure_does_not_touch_a_swapped_temporary(self) -> None:
        target = self.external / "target.txt"
        target.write_bytes(b"before")
        payload = b"after"
        request = {
            **self.base_request("file_replace", "target.txt"),
            "expected_sha256": hashlib.sha256(b"before").hexdigest(),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "max_write_bytes": 1024,
        }
        swapped_paths: list[Path] = []

        def failing_replace(
            source_name: str,
            destination_name: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            temporary = self.external / source_name
            displaced = self.external / f"{source_name}.displaced"
            temporary.rename(displaced)
            temporary.write_bytes(b"replacement temporary")
            swapped_paths.extend([temporary, displaced])
            raise OSError(errno.EIO, "simulated provider replace failure")

        with patch.object(os, "replace", side_effect=failing_replace):
            with self.assertRaisesRegex(
                RuntimeError,
                "cleanup target changed.*cleanup was skipped",
            ):
                self.run_device(request)
        self.assertEqual(target.read_bytes(), b"before")
        self.assertEqual(swapped_paths[0].read_bytes(), b"replacement temporary")
        for path in swapped_paths:
            path.unlink()

    def test_unsupported_descriptor_replace_preserves_temporary(self) -> None:
        target = self.external / "target.txt"
        target.write_bytes(b"before")
        payload = b"after"
        request = {
            **self.base_request("file_replace", "target.txt"),
            "expected_sha256": hashlib.sha256(b"before").hexdigest(),
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "max_write_bytes": 1024,
        }
        with patch.object(os, "replace", side_effect=TypeError("no dir_fd")):
            with self.assertRaisesRegex(RuntimeError, "residue preserved"):
                self.run_device(request)
        self.assertEqual(target.read_bytes(), b"before")
        leftovers = list(self.external.glob(".grabowski-replace-*.tmp"))
        self.assertEqual(len(leftovers), 1)
        leftovers[0].unlink()

    def test_hardlinked_file_read_and_replace_are_rejected(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_bytes(b"outside")
        linked = self.external / "linked.txt"
        os.link(outside, linked)

        read = {
            **self.base_request("file_read", "linked.txt"),
            "max_bytes": 1024,
        }
        with self.assertRaisesRegex(PermissionError, "multiple hard links"):
            self.run_device(read)

        replacement = b"replacement"
        replace = {
            **self.base_request("file_replace", "linked.txt"),
            "expected_sha256": hashlib.sha256(b"outside").hexdigest(),
            "payload_b64": base64.b64encode(replacement).decode("ascii"),
            "payload_sha256": hashlib.sha256(replacement).hexdigest(),
            "max_write_bytes": 1024,
        }
        with self.assertRaisesRegex(PermissionError, "multiple hard links"):
            self.run_device(replace)

        self.assertEqual(outside.read_bytes(), b"outside")
        self.assertEqual(linked.read_bytes(), b"outside")

    def test_descriptor_pinned_parent_does_not_follow_later_symlink_swap(self) -> None:
        original_parent = self.external / "nested"
        original_parent.mkdir()
        (original_parent / "inside.txt").write_bytes(b"inside")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "inside.txt").write_bytes(b"outside")

        request = {
            "schema_version": 1,
            "operation": "grant_status",
            "grant_id": GRANT_ID,
        }
        external = self.external

        class FakeNSURLClass:
            @staticmethod
            def URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                *_args: object,
            ) -> FakeURL:
                return FakeURL(external)

        objc = ModuleType("juno.objc")
        objc.ObjCClass = lambda _name: FakeNSURLClass
        objc.ns = lambda value: value
        objc.nsdata_to_bytes = lambda value: bytes(value)
        objc.py_from_ns = lambda value: value
        juno = ModuleType("juno")
        juno.objc = objc
        namespace: dict[str, object] = {}
        code, _digest = storage._storage_code(request)
        with (
            patch.dict(sys.modules, {"juno": juno, "juno.objc": objc}),
            patch.dict(os.environ, {"HOME": str(self.home)}),
        ):
            exec(compile(code, "<juno-storage-job>", "exec"), namespace)

        open_parent = namespace["_open_parent_directory"]
        read_at = namespace["_read_file_at"]
        create_at = namespace["_create_file_at"]
        descriptor, name = open_parent(self.external, "nested/inside.txt")
        try:
            pinned_parent = self.external / "nested-pinned"
            original_parent.rename(pinned_parent)
            (self.external / "nested").symlink_to(outside, target_is_directory=True)

            payload, _metadata = read_at(descriptor, name, 1024)
            self.assertEqual(payload, b"inside")
            create_at(descriptor, "created.txt", b"pinned")
        finally:
            os.close(descriptor)

        self.assertEqual((pinned_parent / "created.txt").read_bytes(), b"pinned")
        self.assertFalse((outside / "created.txt").exists())
        self.assertEqual((outside / "inside.txt").read_bytes(), b"outside")

    def test_root_swap_between_stat_and_open_fails_closed(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "grant_status",
            "grant_id": GRANT_ID,
        }
        external = self.external

        class FakeNSURLClass:
            @staticmethod
            def URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                *_args: object,
            ) -> FakeURL:
                return FakeURL(external)

        objc = ModuleType("juno.objc")
        objc.ObjCClass = lambda _name: FakeNSURLClass
        objc.ns = lambda value: value
        objc.nsdata_to_bytes = lambda value: bytes(value)
        objc.py_from_ns = lambda value: value
        juno = ModuleType("juno")
        juno.objc = objc
        namespace: dict[str, object] = {}
        code, _digest = storage._storage_code(request)
        with (
            patch.dict(sys.modules, {"juno": juno, "juno.objc": objc}),
            patch.dict(os.environ, {"HOME": str(self.home)}),
        ):
            exec(compile(code, "<juno-storage-job>", "exec"), namespace)

        open_root = namespace["_open_root_directory"]
        displaced = self.root / "provider-original"
        replacement = self.root / "provider-replacement"
        replacement.mkdir()
        real_open = os.open
        swapped = False

        def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal swapped
            if not swapped and Path(path) == self.external:
                self.external.rename(displaced)
                replacement.rename(self.external)
                swapped = True
            return real_open(path, flags, *args, **kwargs)

        with patch.object(os, "open", side_effect=racing_open):
            with self.assertRaisesRegex(RuntimeError, "changed while it was opened"):
                open_root(self.external)
        self.assertTrue(swapped)

    def test_missing_no_follow_flag_fails_closed(self) -> None:
        request = {
            "schema_version": 1,
            "operation": "grant_status",
            "grant_id": GRANT_ID,
        }
        external = self.external

        class FakeNSURLClass:
            @staticmethod
            def URLByResolvingBookmarkData_options_relativeToURL_bookmarkDataIsStale_error_(
                *_args: object,
            ) -> FakeURL:
                return FakeURL(external)

        objc = ModuleType("juno.objc")
        objc.ObjCClass = lambda _name: FakeNSURLClass
        objc.ns = lambda value: value
        objc.nsdata_to_bytes = lambda value: bytes(value)
        objc.py_from_ns = lambda value: value
        juno = ModuleType("juno")
        juno.objc = objc
        namespace: dict[str, object] = {}
        code, _digest = storage._storage_code(request)
        with (
            patch.dict(sys.modules, {"juno": juno, "juno.objc": objc}),
            patch.dict(os.environ, {"HOME": str(self.home)}),
        ):
            exec(compile(code, "<juno-storage-job>", "exec"), namespace)

        directory_flags = namespace["_directory_open_flags"]
        open_regular_file_at = namespace["_open_regular_file_at"]
        parent_descriptor = os.open(self.external, os.O_RDONLY)
        try:
            with patch.object(os, "O_NOFOLLOW", 0):
                with self.assertRaisesRegex(RuntimeError, "O_NOFOLLOW"):
                    directory_flags()
                with self.assertRaisesRegex(RuntimeError, "O_NOFOLLOW"):
                    open_regular_file_at(parent_descriptor, "missing.txt")
        finally:
            os.close(parent_descriptor)
        with patch.object(os, "O_DIRECTORY", 0):
            with self.assertRaisesRegex(RuntimeError, "O_DIRECTORY"):
                directory_flags()

    def test_capability_manifest_is_uniform_private_and_restart_bound(self) -> None:
        required = {
            "logical_name",
            "path",
            "provider",
            "exists",
            "readable",
            "writable",
            "persistent",
            "externally_granted",
            "verification_time",
            "evidence_hash",
            "limitations",
        }
        before = self.run_device(
            {
                "schema_version": 1,
                "operation": "capability_manifest",
                "agent_instance_started_at": "2026-07-15T23:59:00+00:00",
            }
        )
        self.assertTrue(before["capabilities"])
        for row in before["capabilities"]:
            self.assertTrue(required.issubset(row), row)
            self.assertEqual(len(row["evidence_hash"]), 64)
        before_grant = next(
            row for row in before["capabilities"] if row["logical_name"] == GRANT_ID
        )
        self.assertFalse(before_grant["persistent"])
        self.assertFalse(before_grant["juno_restart_persistent"])

        after = self.run_device(
            {
                "schema_version": 1,
                "operation": "capability_manifest",
                "agent_instance_started_at": "2026-07-16T01:00:00+00:00",
            }
        )
        after_grant = next(
            row for row in after["capabilities"] if row["logical_name"] == GRANT_ID
        )
        self.assertTrue(after_grant["persistent"])
        self.assertTrue(after_grant["juno_restart_persistent"])
        self.assertFalse(after_grant["device_restart_persistent"])
        self.assertNotIn("bookmark_b64", json.dumps(after, sort_keys=True))


class JunoStorageHostValidationTests(unittest.TestCase):
    def test_relative_paths_are_canonical_and_escape_is_rejected(self) -> None:
        self.assertEqual(storage._normalize_relative_path("a/b.txt", allow_root=False), "a/b.txt")
        self.assertEqual(storage._normalize_relative_path("", allow_root=True), "")
        for value in ("/absolute", "../escape", "a/../escape", "a/./b", ""):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    storage._normalize_relative_path(value, allow_root=False)

    def test_transport_bounds_fit_generated_code_and_result_envelopes(self) -> None:
        payload = b"x" * storage.MAX_WRITE_BYTES
        request = {
            "schema_version": 1,
            "operation": "file_replace",
            "agent_instance_started_at": "2" * storage.MAX_EXPECTED_STARTED_AT_BYTES,
            "grant_id": GRANT_ID,
            "expected_grant_evidence_hash": EVIDENCE_HASH,
            "expected_provider": "p" * storage.MAX_PROVIDER_BYTES,
            "relative_path": "x" * storage.MAX_RELATIVE_PATH_BYTES,
            "expected_sha256": "c" * 64,
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "max_write_bytes": storage.MAX_WRITE_BYTES,
        }
        code, _digest = storage._storage_code(request)
        self.assertLessEqual(len(code.encode("utf-8")), storage.bridge.MAX_CODE_BYTES)

        too_large = b"x" * (storage.MAX_WRITE_BYTES + 1)
        with patch.object(storage.bridge, "grabowski_juno_run") as run:
            with self.assertRaisesRegex(ValueError, "write bound"):
                storage.ipad_file_create(
                    grant_id=GRANT_ID,
                    expected_grant_evidence_hash=EVIDENCE_HASH,
                    expected_provider=PROVIDER,
                    relative_path="oversized.bin",
                    payload_b64=base64.b64encode(too_large).decode("ascii"),
                    payload_sha256=hashlib.sha256(too_large).hexdigest(),
                    expected_started_at="agent-start",
                    session_escalation={"target": {"device": "ipad"}},
                )
        run.assert_not_called()

        transport_oversized = b"x" * (256 * 1024)
        oversized_request = {
            **request,
            "payload_b64": base64.b64encode(transport_oversized).decode("ascii"),
            "payload_sha256": hashlib.sha256(transport_oversized).hexdigest(),
            "max_write_bytes": len(transport_oversized),
        }
        with self.assertRaisesRegex(ValueError, "code transport bound"):
            storage._storage_code(oversized_request)

        read_payload = b"x" * storage.MAX_READ_BYTES
        result = {
            "schema_version": 1,
            "kind": "ipad_file_read",
            "verification_time": "2" * 64,
            "grant_id": GRANT_ID,
            "provider": "p" * storage.MAX_PROVIDER_BYTES,
            "grant_evidence_hash": EVIDENCE_HASH,
            "relative_path": "x" * storage.MAX_RELATIVE_PATH_BYTES,
            "payload_b64": base64.b64encode(read_payload).decode("ascii"),
            "size": len(read_payload),
            "sha256": hashlib.sha256(read_payload).hexdigest(),
            "mode": 0o600,
            "mtime_ns": 9223372036854775807,
            "bookmark_stale": None,
            "bookmark_stale_observed": False,
        }
        encoded = storage._canonical_json_bytes(result)
        self.assertLessEqual(len(encoded), storage.MAX_DEVICE_RESULT_BYTES)
        self.assertGreaterEqual(
            storage.MAX_DEVICE_RESULT_BYTES - len(encoded),
            storage.MIN_DEVICE_RESULT_HEADROOM_BYTES,
        )
        storage._validate_device_result(
            {
                "operation": "file_read",
                "grant_id": GRANT_ID,
                "expected_grant_evidence_hash": EVIDENCE_HASH,
                "expected_provider": result["provider"],
                "relative_path": result["relative_path"],
                "max_bytes": storage.MAX_READ_BYTES,
            },
            result,
        )

        oversized_result = dict(result)
        oversized_result["padding"] = "x" * storage.MAX_DEVICE_RESULT_BYTES
        with self.assertRaisesRegex(RuntimeError, "result transport bound"):
            storage._validate_device_result(
                {
                    "operation": "file_read",
                    "grant_id": GRANT_ID,
                    "expected_grant_evidence_hash": EVIDENCE_HASH,
                    "expected_provider": result["provider"],
                    "relative_path": result["relative_path"],
                    "max_bytes": storage.MAX_READ_BYTES,
                },
                oversized_result,
            )

        with self.assertRaisesRegex(ValueError, "bounded non-empty"):
            storage._validate_expected_started_at(
                "x" * (storage.MAX_EXPECTED_STARTED_AT_BYTES + 1)
            )

    def test_file_read_default_matches_transport_safe_maximum(self) -> None:
        with patch.object(storage, "_read_request", return_value={"ok": True}) as request:
            result = storage.ipad_file_read(
                grant_id=GRANT_ID,
                expected_grant_evidence_hash=EVIDENCE_HASH,
                expected_provider=PROVIDER,
                relative_path="file.bin",
                expected_started_at="agent-start",
                session_escalation={"target": {"device": "ipad"}},
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(request.call_args.kwargs["max_bytes"], storage.MAX_READ_BYTES)

    def test_payload_hash_is_checked_before_device_submission(self) -> None:
        with patch.object(storage.bridge, "grabowski_juno_run") as run:
            with self.assertRaisesRegex(ValueError, "does not match"):
                storage.ipad_file_create(
                    grant_id=GRANT_ID,
                    expected_grant_evidence_hash=EVIDENCE_HASH,
                    expected_provider=PROVIDER,
                    relative_path="sentinel.txt",
                    payload_b64=base64.b64encode(b"payload").decode("ascii"),
                    payload_sha256="0" * 64,
                    expected_started_at="agent-start",
                    session_escalation={"target": {"device": "ipad"}},
                )
        run.assert_not_called()

    def test_write_receipt_binds_scope_path_prestate_and_payload(self) -> None:
        payload = b"payload"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        execution = {
            "job_id": "job-mcp-test0001",
            "status": {
                "state": "succeeded",
                "result": {
                    "schema_version": 1,
                    "kind": "ipad_file_create",
                    "grant_id": GRANT_ID,
                    "grant_evidence_hash": EVIDENCE_HASH,
                    "provider": PROVIDER,
                    "relative_path": "sentinel.txt",
                    "expected_prestate": "absent",
                    "payload_sha256": payload_sha256,
                    "readback": {
                        "size": len(payload),
                        "sha256": payload_sha256,
                        "mode": 0o600,
                        "mtime_ns": 1,
                    },
                },
            },
        }
        with (
            patch.object(storage.bridge, "grabowski_juno_run", return_value=execution) as run,
            patch.object(storage.bridge, "_write_receipt", return_value={"path": "receipt", "sha256": "c" * 64}) as receipt,
        ):
            result = storage.ipad_file_create(
                grant_id=GRANT_ID,
                expected_grant_evidence_hash=EVIDENCE_HASH,
                expected_provider=PROVIDER,
                relative_path="sentinel.txt",
                payload_b64=base64.b64encode(payload).decode("ascii"),
                payload_sha256=payload_sha256,
                expected_started_at="agent-start",
                session_escalation={"target": {"device": "ipad"}},
            )
        self.assertEqual(result["operation"], "file_create")
        run.assert_called_once()
        fields = receipt.call_args.args[1]
        self.assertEqual(fields["started_at"], "agent-start")
        self.assertEqual(fields["operation"], "file_create")
        self.assertEqual(fields["grant_id"], GRANT_ID)
        self.assertEqual(fields["grant_evidence_hash"], EVIDENCE_HASH)
        self.assertEqual(fields["provider"], PROVIDER)
        self.assertEqual(fields["relative_path"], "sentinel.txt")
        self.assertEqual(fields["payload_sha256"], payload_sha256)
        self.assertIsNone(fields["expected_sha256"])
        self.assertEqual(fields["expected_prestate"], "absent")
        self.assertEqual(fields["agent_id"], storage.bridge.AGENT_ID)
        self.assertTrue(fields["semantic_validation"]["valid"])

    def test_invalid_device_result_is_receipted_then_rejected(self) -> None:
        payload = b"payload"
        payload_sha256 = hashlib.sha256(payload).hexdigest()
        execution = {
            "job_id": "job-mcp-test0002",
            "status": {
                "state": "succeeded",
                "result": {
                    "schema_version": 1,
                    "kind": "ipad_file_create",
                    "bookmark_b64": "forbidden",
                },
            },
        }
        with (
            patch.object(storage.bridge, "grabowski_juno_run", return_value=execution),
            patch.object(
                storage.bridge,
                "_write_receipt",
                return_value={"path": "receipt", "sha256": "d" * 64},
            ) as receipt,
        ):
            with self.assertRaisesRegex(RuntimeError, "semantic validation"):
                storage.ipad_file_create(
                    grant_id=GRANT_ID,
                    expected_grant_evidence_hash=EVIDENCE_HASH,
                    expected_provider=PROVIDER,
                    relative_path="sentinel.txt",
                    payload_b64=base64.b64encode(payload).decode("ascii"),
                    payload_sha256=payload_sha256,
                    expected_started_at="agent-start",
                    session_escalation={"target": {"device": "ipad"}},
                )
        fields = receipt.call_args.args[1]
        self.assertFalse(fields["semantic_validation"]["valid"])
        self.assertEqual(fields["semantic_validation"]["error_type"], "RuntimeError")
        self.assertEqual(len(fields["semantic_validation"]["error_sha256"]), 64)


class JunoStorageGrantScriptTests(unittest.TestCase):
    @staticmethod
    def load_script() -> ModuleType:
        juno_module = ModuleType("juno")
        dialogs_module = ModuleType("juno.dialogs")
        objc_module = ModuleType("juno.objc")
        juno_module.dialogs = dialogs_module
        objc_module.ObjCClass = object
        objc_module.ObjCInstance = object
        objc_module.ObjCProtocol = lambda name: name
        objc_module.create_objc_class = lambda *args, **kwargs: object
        objc_module.ns = lambda value: value
        objc_module.nsdata_to_bytes = bytes
        objc_module.py_from_ns = lambda value: value
        objc_module.on_main_thread = lambda function: function
        module_name = "test_juno_storage_grant_script"
        script_path = ROOT / "tools" / "juno" / "juno_storage_grant.py"
        spec = importlib.util.spec_from_file_location(module_name, script_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load Juno storage grant script")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(
            sys.modules,
            {
                "juno": juno_module,
                "juno.dialogs": dialogs_module,
                "juno.objc": objc_module,
                module_name: module,
            },
        ):
            spec.loader.exec_module(module)
        return module

    def test_picker_uses_open_in_place_mode(self) -> None:
        module = self.load_script()
        self.assertEqual(module.PICKER_MODE_OPEN, 1)

    def test_atomic_create_is_private_single_link_and_create_only(self) -> None:
        module = self.load_script()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "grant.json"
            module._atomic_create(target, b"grant")

            metadata = target.lstat()
            self.assertTrue(target.is_file())
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(target.read_bytes(), b"grant")

            with self.assertRaises(FileExistsError):
                module._atomic_create(target, b"replacement")

    def test_main_returns_after_presenting_picker_without_waiting(self) -> None:
        module = self.load_script()
        source = (ROOT / "tools" / "juno" / "juno_storage_grant.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("threading.Event", source)
        self.assertNotIn(".wait(", source)
        module._RETAINED.clear()
        with (
            patch.object(module, "_present_picker", return_value="a" * 32),
            patch.object(module, "_dismiss_retained_pickers") as dismiss,
        ):
            self.assertEqual(module.main(), 0)
        dismiss.assert_not_called()

    def test_presented_picker_remains_retained_until_callback(self) -> None:
        module = self.load_script()
        new_picker = object()

        def present() -> str:
            module._RETAINED["new"] = {
                "picker": new_picker,
                "delegate": object(),
                "created_at": "new",
            }
            return "a" * 32

        module._RETAINED.clear()
        with patch.object(module, "_present_picker", side_effect=present):
            self.assertEqual(module.main(), 0)

        self.assertIs(module._RETAINED["new"]["picker"], new_picker)

    def test_delayed_old_picker_callback_releases_only_old_picker(self) -> None:
        module = self.load_script()
        old_picker = object()
        new_picker = object()
        module._RETAINED.clear()
        module._RETAINED.update(
            {
                "old": {
                    "picker": old_picker,
                    "delegate": object(),
                    "created_at": "old",
                },
                "new": {
                    "picker": new_picker,
                    "delegate": object(),
                    "created_at": "new",
                },
            }
        )

        module.documentPickerWasCancelled_(object(), old_picker)

        self.assertNotIn("old", module._RETAINED)
        self.assertIs(module._RETAINED["new"]["picker"], new_picker)

    def test_repeated_main_dismisses_retained_picker_before_new_picker(self) -> None:
        module = self.load_script()

        class OldPicker:
            dismiss_calls = 0

            def dismissViewControllerAnimated_completion_(self, animated, completion) -> None:
                self.dismiss_calls += 1

        old_picker = OldPicker()
        module._RETAINED["old"] = {
            "picker": old_picker,
            "delegate": object(),
            "created_at": "old",
        }
        observed = {}

        def present() -> str:
            observed["retained"] = dict(module._RETAINED)
            return "b" * 32

        with patch.object(module, "_present_picker", side_effect=present):
            result = module.main()

        self.assertEqual(result, 0)
        self.assertEqual(old_picker.dismiss_calls, 1)
        self.assertEqual(observed["retained"], {})


if __name__ == "__main__":
    unittest.main()
