"""PR #1662: durable job writer/reader bounds must not deadlock the deploy index.

A real ordinary job in production contains 68,321 bytes of valid metadata.
The pre-fix writer accepts it but the 64-KiB reader rejects it, even when the
historical job cannot possibly be a runtime deploy or resume runner.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_operator as operator  # noqa: E402
import grabowski_self_deploy as deploy  # noqa: E402


class DurableJobMetadataBoundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="jobmetadata-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        patcher = mock.patch.object(operator, "_jobs_root", return_value=self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def new_job(self, name: str) -> Path:
        directory = self.root / name
        directory.mkdir(mode=0o700)
        return directory

    def payload(self, name: str, *, size: int = 68_000, runner: bool = False):
        command = (
            str(deploy.CANONICAL_REPOSITORY / deploy.RUNNER_RELATIVE_PATH)
            if runner else "/tmp/non-runtime-job.py"
        )
        return {
            "unit": name, "schema_version": 2, "final_status": "running",
            "argv": ["/usr/bin/python3", command, "a" * size],
        }

    def test_valid_68kb_ordinary_job_is_read_without_metadata_loss(self) -> None:
        name = "grabowski-job-aaaaaaaaaaaa"
        directory = self.new_job(name)
        original = self.payload(name)
        location = operator._write_job_metadata(directory, original)
        self.assertGreater(location.stat().st_size, 64 * 1024)
        self.assertEqual(operator._read_job_metadata(name), original)

    def test_oversized_ordinary_job_cannot_hide_a_runtime_job_in_census(self) -> None:
        ordinary = "grabowski-job-aaaaaaaaaaaa"
        runtime = "grabowski-job-ffffffffffff"
        operator._write_job_metadata(self.new_job(ordinary), self.payload(ordinary))
        operator._write_job_metadata(
            self.new_job(runtime), self.payload(runtime, size=12, runner=True)
        )
        with mock.patch.object(deploy, "_write_deploy_index") as write:
            index = deploy._deploy_index(self.root, read_only=True)
        self.assertIn(runtime, index["units"])
        self.assertNotIn(ordinary, index["units"])
        write.assert_not_called()
        self.assertFalse(deploy._deploy_index_path(self.root).exists())

    def test_writer_rejects_overlimit_before_creating_metadata_file(self) -> None:
        name = "grabowski-job-bbbbbbbbbbbb"
        directory = self.new_job(name)
        with self.assertRaisesRegex(ValueError, "metadata.*(large|limit|bounded)"):
            operator._write_job_metadata(
                directory, self.payload(name, size=300_000)
            )
        self.assertFalse((directory / "metadata.json").exists())

    def test_reader_rejects_larger_than_bound_even_with_valid_json(self) -> None:
        name = "grabowski-job-cccccccccccc"
        directory = self.new_job(name)
        payload = self.payload(name, size=300_000)
        (directory / "metadata.json").write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError, "metadata is too large"):
            operator._read_job_metadata(name)

    def test_wrong_unit_and_symlink_still_fail_closed(self) -> None:
        name = "grabowski-job-dddddddddddd"
        directory = self.new_job(name)
        operator._write_job_metadata(
            directory, self.payload("grabowski-job-eeeeeeeeeeee", size=100)
        )
        with self.assertRaisesRegex(ValueError, "metadata is invalid"):
            operator._read_job_metadata(name)
        link = "grabowski-job-111111111111"
        link_dir = self.new_job(link)
        (link_dir / "metadata.json").symlink_to(directory / "metadata.json")
        with self.assertRaisesRegex(ValueError, "metadata is missing"):
            operator._read_job_metadata(link)


    def test_post_dispatch_growth_cannot_replace_readable_metadata_with_oversize(self) -> None:
        name = "grabowski-job-222222222222"
        directory = self.new_job(name)
        original = self.payload(name, size=100)
        raw_size = len((json.dumps(original, indent=2, sort_keys=True) + "\n").encode())
        original["argv"][-1] += "x" * (operator.MAX_JOB_METADATA_BYTES - 64 - raw_size)
        location = operator._write_job_metadata(directory, original)
        before = location.read_bytes()
        self.assertEqual(len(before), operator.MAX_JOB_METADATA_BYTES - 64)
        after_dispatch = {
            **original,
            "launcher_evidence": operator._job_launcher_evidence(
                {"stdout": "", "stderr": "", "returncode": 0}
            ),
            "dispatch_outcome": "started",
        }
        self.assertGreater(
            len((json.dumps(after_dispatch, indent=2, sort_keys=True) + "\n").encode()),
            operator.MAX_JOB_METADATA_BYTES,
        )
        with self.assertRaisesRegex(ValueError, "metadata.*(large|limit|bounded)"):
            operator._replace_job_metadata(directory, after_dispatch)
        self.assertEqual(location.read_bytes(), before)
        self.assertEqual(operator._read_job_metadata(name), original)
        self.assertEqual(list(directory.iterdir()), [location])

    def test_pre_dispatch_capacity_reserves_space_for_launcher_evidence(self) -> None:
        name = "grabowski-job-333333333333"
        prepared = self.payload(name, size=operator.MAX_JOB_METADATA_BYTES - 1500)
        self.assertLess(
            len((json.dumps(prepared, indent=2, sort_keys=True) + "\n").encode()),
            operator.MAX_JOB_METADATA_BYTES,
        )
        with self.assertRaisesRegex(ValueError, "metadata.*(headroom|reserve|capacity)"):
            operator._require_job_metadata_pre_dispatch_headroom(prepared)
        self.assertFalse((self.root / name).exists())


if __name__ == "__main__":
    unittest.main()
