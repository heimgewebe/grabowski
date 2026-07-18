from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "grabowski_process_reference_observer",
    ROOT / "tools" / "grabowski_process_reference_observer.py",
)
assert SPEC and SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


class ProcessReferenceObserverTests(unittest.TestCase):
    def make_root(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory(prefix="observer-root-", dir="/home/alex/repos")

    def allowed(self, root: Path):
        return patch.object(observer, "ALLOWED_ROOTS", (root,))

    def request(self, root: str, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "target_uid": os.getuid(),
            "roots": [root],
            "max_processes": 128,
            "max_file_descriptors": 128,
        }
        value.update(overrides)
        return value

    def fake_process(
        self,
        proc: Path,
        pid: int,
        *,
        cwd: Path,
        exe: Path,
        root: Path,
        descriptors: list[Path],
    ) -> None:
        process = proc / str(pid)
        (process / "fd").mkdir(parents=True)
        (process / "cwd").symlink_to(cwd)
        (process / "exe").symlink_to(exe)
        (process / "root").symlink_to(root)
        for index, target in enumerate(descriptors):
            (process / "fd" / str(index)).symlink_to(target)

    def test_rejects_unconfigured_target_uid(self) -> None:
        with self.make_root() as root_raw, self.allowed(Path(root_raw)):
            with self.assertRaisesRegex(observer.ObservationError, "target_uid"):
                observer.normalize_request(self.request(root_raw, target_uid=os.getuid() + 1))

    def test_rejects_root_outside_allowed_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as outside, self.make_root() as allowed:
            with self.allowed(Path(allowed)), self.assertRaises(observer.ObservationError):
                observer.normalize_request(self.request(outside))

    def test_rejects_symlink_root(self) -> None:
        with self.make_root() as parent:
            real = Path(parent) / "real"
            real.mkdir()
            link = Path(parent) / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.allowed(Path(parent)), self.assertRaises(observer.ObservationError):
                observer.normalize_request(self.request(str(link)))

    def test_reports_only_references_inside_requested_root(self) -> None:
        with self.make_root() as root_raw, tempfile.TemporaryDirectory() as proc_raw:
            root = Path(root_raw)
            target_file = root / "target" / "debug" / "artifact"
            target_file.parent.mkdir(parents=True)
            target_file.write_text("x", encoding="utf-8")
            foreign = Path(proc_raw) / "foreign"
            foreign.write_text("y", encoding="utf-8")
            proc = Path(proc_raw) / "proc"
            proc.mkdir()
            self.fake_process(
                proc,
                42,
                cwd=target_file.parent,
                exe=foreign,
                root=Path("/"),
                descriptors=[target_file, foreign],
            )
            with self.allowed(root):
                result = observer.observe_process_references(self.request(str(root)), proc_root=proc)
            self.assertTrue(result["complete"])
            self.assertEqual(
                [(item["kind"], item["path"]) for item in result["path_references"]],
                [("cwd", str(target_file.parent)), ("fd", str(target_file))],
            )
            self.assertNotIn(str(foreign), json.dumps(result, sort_keys=True))
            material = dict(result)
            digest = material.pop("observation_sha256")
            self.assertEqual(digest, observer._canonical_sha256(material))

    def test_descriptor_limit_fails_closed(self) -> None:
        with self.make_root() as root_raw, tempfile.TemporaryDirectory() as proc_raw:
            root = Path(root_raw)
            files = []
            for index in range(2):
                path = root / f"file-{index}"
                path.write_text("x", encoding="utf-8")
                files.append(path)
            proc = Path(proc_raw) / "proc"
            proc.mkdir()
            self.fake_process(
                proc,
                7,
                cwd=root,
                exe=files[0],
                root=Path("/"),
                descriptors=files,
            )
            with self.allowed(root):
                result = observer.observe_process_references(
                    self.request(str(root), max_file_descriptors=1), proc_root=proc
                )
            self.assertFalse(result["complete"])
            self.assertIn("file-descriptor-limit-exceeded", result["errors"])
            self.assertEqual(result["open_file_descriptors_checked"], 1)

    def test_reference_limit_fails_closed(self) -> None:
        with self.make_root() as root_raw, tempfile.TemporaryDirectory() as proc_raw:
            root = Path(root_raw)
            proc = Path(proc_raw) / "proc"
            proc.mkdir()
            descriptors = []
            for index in range(observer.MAX_REFERENCES + 1):
                item = root / f"artifact-{index}"
                item.write_text("x", encoding="utf-8")
                descriptors.append(item)
            self.fake_process(proc, 9, cwd=Path("/"), exe=Path("/bin/sh"), root=Path("/"), descriptors=descriptors)
            with self.allowed(root):
                result = observer.observe_process_references(self.request(str(root), max_file_descriptors=1000), proc_root=proc)
            self.assertFalse(result["complete"])
            self.assertIn("reference-limit-exceeded", result["errors"])
            self.assertEqual(len(result["path_references"]), observer.MAX_REFERENCES)

    def test_process_limit_fails_closed(self) -> None:
        with self.make_root() as root_raw, tempfile.TemporaryDirectory() as proc_raw:
            root = Path(root_raw)
            proc = Path(proc_raw) / "proc"
            proc.mkdir()
            for pid in (1, 2):
                self.fake_process(
                    proc,
                    pid,
                    cwd=root,
                    exe=root,
                    root=Path("/"),
                    descriptors=[],
                )
            with self.allowed(root):
                result = observer.observe_process_references(
                    self.request(str(root), max_processes=1), proc_root=proc
                )
            self.assertFalse(result["complete"])
            self.assertIn("process-limit-exceeded", result["errors"])
            self.assertEqual(result["process_count"], 1)


if __name__ == "__main__":
    unittest.main()
