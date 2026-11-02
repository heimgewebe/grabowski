"""Retained decision markers use the same UTF-8 line boundaries as admission."""
from __future__ import annotations

from contextlib import nullcontext
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_decision_reviews as fixture


reviews = fixture.reviews
LINE_SEPARATORS = {
    "LF": "\n", "CR": "\r", "CRLF": "\r\n", "VT": "\v", "FF": "\f",
    "FS": "\x1c", "GS": "\x1d", "RS": "\x1e", "NEL": "\x85",
    "LS": "\u2028", "PS": "\u2029",
}


class DecisionReviewLineBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sequence = 0
        self.expected = reviews.normalize_binding(fixture.binding("A"))
        self.reject = fixture.result("A", "REJECT_THIS_REVISION", 1)
        self.marker = self._marker(self.reject)

    def _marker(self, result: dict) -> bytes:
        return (
            reviews.RESULT_PREFIX + json.dumps(result, separators=(",", ":"))
        ).encode("utf-8")

    def _directory(self, label: str) -> Path:
        self.sequence += 1
        directory = self.root / f"{label}-{self.sequence}"
        directory.mkdir(mode=0o700)
        return directory

    def _write_stdout(self, directory: Path, payload: bytes, *, mode: int = 0o600) -> None:
        path = directory / "stdout.log"
        path.write_bytes(payload)
        path.chmod(mode)

    def _jobs(self) -> Path:
        parent = self._directory("case")
        jobs = parent / "jobs"
        jobs.mkdir(mode=0o700)
        fixture.make_job(
            jobs, suffix="a00000000001", slot="A", terminal_status="succeeded",
            review_result=fixture.result("A", "PASS_THIS_REVISION", 0),
        )
        return jobs

    def _ordinary(self, jobs: Path, payload: bytes) -> Path:
        directory = jobs / "grabowski-job-b00000000002"
        directory.mkdir(mode=0o700)
        scope = {"cwd": "/tmp", "argv_sha256": "e" * 64, "runtime_seconds": 60}
        origin, digest = fixture.job_origin.build_origin(
            unit=directory.name, owner=f"uid:{os.getuid()}",
            argv_sha256=scope["argv_sha256"], scope=scope,
            notify_on_done={"requested": False, "channels": []},
            created_at_unix=1_787_000_000, started_at="2026-08-18T12:00:00Z",
            invoker_tool="grabowski_job_start",
            order_root=jobs.parent / "decision-review-order", jobs_root=jobs,
        )
        fixture.job_origin.validate_origin(origin, digest, expected_unit=directory.name)
        fixture.write_private(directory / "metadata.json", json.dumps({
            "unit": directory.name, "job_id": origin["job_id"],
            "owner": origin["owner"], "argv_sha256": origin["argv_sha256"],
            "scope": scope, "origin": origin, "origin_sha256": digest,
        }))
        self._write_stdout(directory, payload)
        return directory

    def _rebind(self, directory: Path, drift: dict | None) -> None:
        path = directory / "metadata.json"
        metadata = json.loads(path.read_bytes())
        scope = copy.deepcopy(metadata["scope"])
        if drift is None:
            for field in (
                "decision_bound_review", "decision_review_provenance",
                "decision_review_attempt_epoch",
            ):
                scope.pop(field, None)
        else:
            scope["decision_bound_review"].update(drift)
        previous = metadata["origin"]
        origin, digest = fixture.job_origin.build_origin(
            unit=directory.name, owner=previous["owner"],
            argv_sha256=previous["argv_sha256"], scope=scope,
            notify_on_done=previous["notify_on_done"],
            created_at_unix=previous["created_at_unix"], started_at=previous["started_at"],
            invoker_tool=previous["invoker_tool"],
            order_root=directory.parent.parent / "decision-review-order",
            jobs_root=directory.parent,
        )
        fixture.job_origin.validate_origin(origin, digest, expected_unit=directory.name)
        metadata.update({
            "scope": scope, "origin": origin, "origin_sha256": digest,
            "created_at_unix": origin["created_at_unix"],
        })
        fixture.write_private(path, json.dumps(metadata))

    def _reconcile(self, jobs: Path) -> dict:
        return reviews.reconcile(
            repo=fixture.REPO, pr=fixture.PR, head_sha=fixture.HEAD,
            base_sha=fixture.BASE, diff_sha256=fixture.DIFF, jobs_root=jobs,
        )

    def _scan(
        self, payload: bytes, *, read_size: int | None = None,
        aggregate: list[int] | None = None, mode: int = 0o600,
        allow_legacy_readable: bool = False,
    ) -> bool:
        directory = self._directory("scan")
        self._write_stdout(directory, payload, mode=mode)
        budget = [0] if aggregate is None else aggregate
        original_budget = budget[0]
        original_hash = hashlib.sha256(payload).hexdigest()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        real_read = reviews.os.read
        reads = (
            mock.patch.object(
                reviews.os, "read",
                side_effect=lambda fd, size: real_read(fd, min(size, read_size)),
            )
            if read_size is not None else nullcontext()
        )
        try:
            with reads:
                found = reviews._unbound_stdout_has_target_result(
                    directory, parent_fd=descriptor, aggregate_bytes=budget,
                    expected=self.expected, allow_legacy_readable=allow_legacy_readable,
                )
        finally:
            os.close(descriptor)
        self.assertEqual(original_budget + len(payload), budget[0])
        self.assertEqual(original_hash, hashlib.sha256((directory / "stdout.log").read_bytes()).hexdigest())
        return found

    def test_ordinary_origin_retains_reject_for_every_parser_line_separator(self) -> None:
        for name, separator in LINE_SEPARATORS.items():
            with self.subTest(separator=name):
                encoded = separator.encode("utf-8")
                payload = b"progress" + encoded + self.marker + encoded
                parsed = reviews._parse_result_marker(payload.decode("utf-8"), self.expected)
                self.assertEqual("REJECT_THIS_REVISION", parsed["verdict"])
                jobs = self._jobs()
                ordinary = self._ordinary(jobs, payload)
                checked = self._reconcile(jobs)
                self.assertEqual("blocked", checked["status"])
                self.assertIn(f"decision_review_unbound_result:{ordinary.name}", checked["errors"])
                self.assertEqual(payload, (ordinary / "stdout.log").read_bytes())

    def test_rebound_review_retains_reject_and_original_stdout_hash(self) -> None:
        for name, separator in LINE_SEPARATORS.items():
            for drift in (None, {"pr": fixture.PR + 1}, {"head_sha": "d" * 40}):
                with self.subTest(separator=name, new_binding=drift):
                    encoded = separator.encode("utf-8")
                    payload = b"progress" + encoded + self.marker + encoded
                    jobs = self._jobs()
                    rejected = fixture.make_job(
                        jobs, suffix="b00000000002", slot="A", terminal_status="succeeded",
                        review_result=self.reject,
                    )
                    self._write_stdout(rejected, payload)
                    before = self._reconcile(jobs)
                    self.assertEqual("blocked", before["status"])
                    attempt = next(item for item in before["attempts"] if item["unit"] == rejected.name)
                    self.assertEqual("REJECT_THIS_REVISION", attempt["verdict"])
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), attempt["stdout_tail_sha256"])
                    self._rebind(rejected, drift)
                    checked = self._reconcile(jobs)
                    self.assertEqual("blocked", checked["status"])
                    self.assertIn(f"decision_review_unbound_result:{rejected.name}", checked["errors"])
                    self.assertEqual(payload, (rejected / "stdout.log").read_bytes())

    def test_separators_survive_short_reads_and_multibyte_chunk_boundaries(self) -> None:
        for name, separator in LINE_SEPARATORS.items():
            encoded = separator.encode("utf-8")
            payload = b"progress" + encoded + self.marker + encoded
            for size in (1, 2, 3, 17, 65536):
                with self.subTest(separator=name, read_size=size):
                    self.assertTrue(self._scan(payload, read_size=size))
            # Put every internal separator byte and every marker-prefix byte
            # on opposite sides of the scanner's real 64-KiB read boundary.
            for marker_offset in range(-len(encoded), len(reviews.RESULT_PREFIX)):
                with self.subTest(separator=name, marker_offset=marker_offset):
                    noise = b"x" * (65536 - len(encoded) - marker_offset)
                    self.assertTrue(self._scan(noise + encoded + self.marker + encoded))

    def test_unterminated_final_marker_is_retained_after_every_separator(self) -> None:
        for name, separator in LINE_SEPARATORS.items():
            with self.subTest(separator=name):
                payload = b"progress" + separator.encode("utf-8") + self.marker
                self.assertIsNotNone(reviews._parse_result_marker(payload.decode(), self.expected))
                self.assertTrue(self._scan(payload, read_size=3))

    def test_invalid_utf8_and_non_line_controls_do_not_create_marker_boundaries(self) -> None:
        non_boundaries = (
            b"\x1f", b"\x85", b"\xc4\x85", b"\xe2\xa8", b"\xe2\x80",
            b"\xe2\x80\xaa", b"\xc2", b"\xe2", b" ", b"\t",
        )
        for boundary in non_boundaries:
            for size in (1, 2, 65536):
                with self.subTest(boundary=boundary, read_size=size):
                    payload = b"progress" + boundary + self.marker + b"\n"
                    self.assertIsNone(reviews._parse_result_marker(payload.decode("utf-8", errors="replace"), self.expected))
                    self.assertFalse(self._scan(payload, read_size=size))

    def test_incomplete_utf8_at_eof_remains_part_of_the_candidate(self) -> None:
        for suffix in (b"\xc2", b"\xe2", b"\xe2\x80"):
            for size in (1, 2, 3, 65536):
                with self.subTest(suffix=suffix, read_size=size):
                    payload = self.marker + suffix
                    with self.assertRaisesRegex(ValueError, "invalid JSON"):
                        reviews._parse_result_marker(payload.decode("utf-8", errors="replace"), self.expected)
                    self.assertFalse(self._scan(payload, read_size=size))
        # A complete CR at EOF remains a real separator, including after
        # another separator carried across an earlier read boundary.
        self.assertTrue(self._scan(b"progress\r" + self.marker + b"\r", read_size=1))

    def test_oversized_noise_line_does_not_hide_a_later_marker(self) -> None:
        noise = b"x" * (reviews.MAX_UNBOUND_MARKER_BYTES + 65536)
        for name, separator in LINE_SEPARATORS.items():
            with self.subTest(separator=name):
                encoded = separator.encode("utf-8")
                self.assertFalse(self._scan(noise + encoded + b"ordinary output"))
                self.assertTrue(self._scan(noise + encoded + self.marker))

    def test_foreign_revision_and_malformed_markers_remain_nonblocking(self) -> None:
        for name, separator in LINE_SEPARATORS.items():
            for drift in ({"repo": "heimgewebe/other"}, {"pr": fixture.PR + 1}, {"head_sha": "d" * 40}):
                with self.subTest(separator=name, marker_binding=drift):
                    result = {**self.reject, **drift}
                    encoded = separator.encode("utf-8")
                    jobs = self._jobs()
                    self._ordinary(jobs, b"progress" + encoded + self._marker(result) + encoded)
                    checked = self._reconcile(jobs)
                    self.assertEqual("settled", checked["status"])
                    self.assertEqual([], checked["errors"])
            with self.subTest(separator=name, malformed=True):
                payload = separator.encode("utf-8") + reviews.RESULT_PREFIX.encode() + b"invalid-json"
                self.assertFalse(self._scan(payload))

    def test_marker_and_aggregate_byte_budgets_still_fail_closed(self) -> None:
        oversized = reviews.RESULT_PREFIX.encode() + b" " * reviews.MAX_UNBOUND_MARKER_BYTES
        for name, separator in LINE_SEPARATORS.items():
            with self.subTest(separator=name):
                with self.assertRaisesRegex(ValueError, "marker exceeds bounded size"):
                    self._scan(oversized + separator.encode("utf-8"))
        budget = [reviews.MAX_TOTAL_METADATA_BYTES - len(self.marker) + 1]
        with self.assertRaises(reviews.ReviewMetadataBudgetExceeded):
            self._scan(self.marker, aggregate=budget)

    def test_stdout_authority_checks_remain_strict(self) -> None:
        payload = b"progress\r" + self.marker + b"\r"
        with self.assertRaisesRegex(ValueError, "owner-private"):
            self._scan(payload, mode=0o644)
        self.assertTrue(self._scan(payload, mode=0o644, allow_legacy_readable=True))
        with self.assertRaisesRegex(ValueError, "owner-private"):
            self._scan(payload, mode=0o666, allow_legacy_readable=True)


if __name__ == "__main__":
    unittest.main()
