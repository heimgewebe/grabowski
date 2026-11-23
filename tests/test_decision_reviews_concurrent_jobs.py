"""Captain scans must not be blocked by ordinary jobs progressing mid-scan.

Issue #1797: a full archive scan for ONE PR failed with
``decision_review_job_file_changed`` / ``..._directory_changed`` whenever any
unrelated job published metadata, a finalization receipt or log output while
the scan ran. Those jobs are re-checked individually now; material evidence
for the target PR/head and identity swaps still hard-block.
"""
from pathlib import Path
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import grabowski_decision_reviews as reviews
import grabowski_job_origin as job_origin
from test_decision_reviews import (
    BASE, DIFF, HEAD, PR, REPO, make_job, result, write_private,
)


def make_ordinary_job(jobs: Path, suffix: str, *, argv_digest: str = "e" * 64) -> Path:
    directory = jobs / f"grabowski-job-{suffix}"
    directory.mkdir(mode=0o700)
    write_ordinary_metadata(directory, argv_digest=argv_digest)
    write_private(directory / "stdout.log", "starting\n")
    write_private(directory / "stderr.log", "warming up\n")
    return directory


def ordinary_metadata(directory: Path, *, argv_digest: str, **extra) -> dict:
    scope = {"cwd": "/tmp", "argv_sha256": argv_digest, "runtime_seconds": 60}
    origin, digest = job_origin.build_origin(
        unit=directory.name, owner=f"uid:{os.getuid()}",
        argv_sha256=argv_digest, scope=scope,
        notify_on_done={"requested": False, "channels": []},
        created_at_unix=1_787_000_000,
        started_at="2026-08-18T12:00:00Z",
        invoker_tool="grabowski_job_start",
    )
    return {
        "unit": directory.name, "job_id": origin["job_id"],
        "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
        "scope": scope, "origin": origin, "origin_sha256": digest, **extra,
    }


def write_ordinary_metadata(directory: Path, *, argv_digest: str, **extra) -> None:
    payload = json.dumps(ordinary_metadata(directory, argv_digest=argv_digest, **extra))
    temporary = directory / "metadata.json.tmp"
    write_private(temporary, payload)
    os.replace(temporary, directory / "metadata.json")  # new inode, like the operator


def finish_ordinary_job(directory: Path) -> None:
    """What a real job does when it ends: log, finalize, rewrite metadata."""
    with (directory / "stdout.log").open("ab") as stream:
        stream.write(b"done\n")
    with (directory / "stderr.log").open("ab") as stream:
        stream.write(b"exit 0\n")
    write_private(directory / "finalization.json", json.dumps({"final_status": "succeeded"}))
    write_ordinary_metadata(directory, argv_digest="e" * 64, final_status="succeeded")


class ConcurrentOrdinaryJobTests(unittest.TestCase):
    def reconcile(self, jobs: Path) -> dict:
        return reviews.reconcile(
            repo=REPO, pr=PR, head_sha=HEAD, base_sha=BASE,
            diff_sha256=DIFF, jobs_root=jobs,
        )

    def run_with_mutation(self, mutate, *, during: str) -> tuple[dict, Path, Path]:
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp, True)
        jobs = Path(temp) / "jobs"
        jobs.mkdir(mode=0o700)
        ordinary = make_ordinary_job(jobs, "aaaaaaaaa501")
        reviewer = make_job(
            jobs, suffix="bbbbbbbbb502", slot="A",
            terminal_status="succeeded",
            review_result=result("A", "PASS_THIS_REVISION", 0),
        )
        trigger = ordinary if during == "own" else reviewer
        original = reviews._validated_origin_binding
        fired = []

        def hook(directory, *args, **kwargs):
            outcome = original(directory, *args, **kwargs)
            if directory == trigger and not fired:
                fired.append(True)
                mutate(ordinary)
            return outcome

        with mock.patch.object(reviews, "_validated_origin_binding", side_effect=hook):
            checked = self.reconcile(jobs)
        self.assertTrue(fired)
        return checked, ordinary, jobs

    def test_ordinary_job_finishing_mid_scan_does_not_block(self) -> None:
        for during in ("own", "later"):
            with self.subTest(during=during):
                checked, _ordinary, _jobs = self.run_with_mutation(
                    finish_ordinary_job, during=during,
                )
                self.assertEqual(checked["errors"], [])
                self.assertEqual(checked["status"], "settled")

    def test_prelaunch_stub_becoming_ordinary_job_mid_scan_does_not_block(self) -> None:
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp, True)
        jobs = Path(temp) / "jobs"
        jobs.mkdir(mode=0o700)
        stub = jobs / "grabowski-job-aaaaaaaaa501"
        stub.mkdir(mode=0o700)
        write_private(stub / "stdout.log", "")
        write_private(stub / "stderr.log", "")
        reviewer = make_job(
            jobs, suffix="bbbbbbbbb502", slot="A",
            terminal_status="succeeded",
            review_result=result("A", "PASS_THIS_REVISION", 0),
        )
        original = reviews._validated_origin_binding
        fired = []

        def hook(directory, *args, **kwargs):
            if directory == reviewer and not fired:
                fired.append(True)
                write_ordinary_metadata(stub, argv_digest="e" * 64)
                with (stub / "stdout.log").open("ab") as stream:
                    stream.write(b"started\n")
            return original(directory, *args, **kwargs)

        with mock.patch.object(reviews, "_validated_origin_binding", side_effect=hook):
            checked = self.reconcile(jobs)
        self.assertTrue(fired)
        self.assertEqual(checked["errors"], [])
        self.assertEqual(checked["status"], "settled")

    def test_material_or_contradictory_progress_still_blocks(self) -> None:
        def late_reject(directory: Path) -> None:
            finish_ordinary_job(directory)
            marker = reviews.RESULT_PREFIX + json.dumps(
                result("A", "REJECT_THIS_REVISION", 1)
            ) + "\n"
            with (directory / "stderr.log").open("ab") as stream:
                stream.write(marker.encode("utf-8"))

        def rebound_origin(directory: Path) -> None:
            write_ordinary_metadata(directory, argv_digest="f" * 64)

        def prefix_rewrite(directory: Path) -> None:
            write_private(directory / "finalization.json", "{}")
            with (directory / "stdout.log").open("r+b") as stream:
                stream.write(b"X")
                stream.seek(0, os.SEEK_END)
                stream.write(b"more\n")

        def role_receipt(directory: Path) -> None:
            write_private(directory / "finalization.json", "{}")
            write_private(
                directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME,
                json.dumps({"expected_head": "9" * 40, "expected_base_head": BASE}),
            )

        def directory_swap(directory: Path) -> None:
            parked = directory.with_name("parked-copy")
            shutil.copytree(directory, parked)
            shutil.rmtree(directory)
            os.replace(parked, directory)
            finish_ordinary_job(directory)

        def truncated_log(directory: Path) -> None:
            write_private(directory / "finalization.json", "{}")
            os.truncate(directory / "stdout.log", 0)

        cases = {
            "late_reject": late_reject,
            "rebound_origin": rebound_origin,
            "prefix_rewrite": prefix_rewrite,
            "role_receipt": role_receipt,
            "directory_swap": directory_swap,
            "truncated_log": truncated_log,
        }
        for name, mutate in cases.items():
            for during in ("own", "later"):
                if name == "prefix_rewrite" and during == "own":
                    # Rewritten before its first read: the scan already saw
                    # and fully inspected the rewritten bytes, as if the
                    # write had happened before the scan started.
                    continue
                with self.subTest(case=name, during=during):
                    checked, ordinary, _jobs = self.run_with_mutation(mutate, during=during)
                    self.assertEqual(checked["status"], "blocked", checked["errors"])
                    if name == "late_reject":
                        self.assertIn(
                            f"decision_review_unbound_result:{ordinary.name}",
                            checked["errors"],
                        )
                    else:
                        self.assertTrue(any(
                            code in checked["errors"] for code in (
                                "decision_review_job_file_changed",
                                "decision_review_job_directory_changed",
                            )
                        ), checked["errors"])

    def test_target_review_job_progress_still_blocks(self) -> None:
        # Drift inside a review bound to THIS PR/head is never deferred.
        temp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, temp, True)
        jobs = Path(temp) / "jobs"
        jobs.mkdir(mode=0o700)
        earlier = make_job(
            jobs, suffix="aaaaaaaaa501", slot="A",
            terminal_status="succeeded",
            review_result=result("A", "PASS_THIS_REVISION", 0),
        )
        later = make_job(
            jobs, suffix="bbbbbbbbb502", slot="B",
            terminal_status="succeeded",
            review_result=result("B", "PASS_THIS_REVISION", 0),
        )
        original = reviews._validated_origin_binding
        fired = []

        def hook(directory, *args, **kwargs):
            if directory == later and not fired:
                fired.append(True)
                with (earlier / "stderr.log").open("ab") as stream:
                    stream.write(b"late\n")
                write_private(earlier / "extra.json", "{}")
            return original(directory, *args, **kwargs)

        with mock.patch.object(reviews, "_validated_origin_binding", side_effect=hook):
            checked = self.reconcile(jobs)
        self.assertTrue(fired)
        self.assertEqual(checked["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
