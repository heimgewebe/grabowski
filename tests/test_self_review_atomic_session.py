"""Interrupted writes must never publish unauthenticated review history."""
import json
import unittest
from unittest import mock

import test_self_review_first_party as fixture

review = fixture.review


class AtomicSessionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.FirstPartySemanticReviewTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def _failure_then_retry(self, partial):
        f = self.f
        plan = f._first_party_plan()

        def fail(path, record, **kwargs):
            if partial:
                review._create_private_bytes(path, review._canonical(record))
            raise OSError("injected signing/write failure")

        with mock.patch.object(review, "_write_signed_record", side_effect=fail):
            with self.assertRaisesRegex(OSError, "injected"):
                f._start_plan(plan)
        self.assertEqual([], list((f.state / "sessions").iterdir()))
        self.assertEqual([], list((f.state / "batches").iterdir()))
        self.assertEqual({"sessions", "batches", ".lock"},
                         {p.name for p in f.state.iterdir()})
        retry_arguments = {
            "review_batch_id": plan["binding"]["review_batch_id"],
            "reason": "Retry after confirming no session or batch was published.",
            "user_intent": "Verify atomic session retry.",
        }
        started = review.start_first_party_review_session(
            plan, f._issuer(review.FIRST_PARTY_TOOL_START, retry_arguments),
            root=f.state, key=f.key, signers=f.signers,
            root_owned_signers=False, now_unix=f.now,
        )
        path = f.state / "sessions" / started["review_session_id"] / "session.json"
        record = review._read_signed_record(
            path, signers=f.signers, root_owned_signers=False,
        )
        self.assertEqual(plan["binding"], record["binding"])
        f._read(started, review.REQUIRED_AXES[0], "source", f.source_path, "head", 1, 5)
        other = f._start_plan(f._first_party_plan())
        self.assertNotEqual(started["review_session_id"], other["review_session_id"])

    def test_signer_failure_is_retryable(self):
        self._failure_then_retry(False)

    def test_partial_json_write_is_retryable(self):
        self._failure_then_retry(True)

    def test_crash_staging_outside_history_is_ignored(self):
        f = self.f
        f._start_plan(f._first_party_plan())
        leftover = f.state / ".session-stage-crashed"
        leftover.mkdir(mode=0o700)
        (leftover / "session.json").write_text("{")
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(started, axis, number)
        f._seal_direct(plan)

    def _axis_report(self, started):
        f = self.f
        axis = review.REQUIRED_AXES[0]
        lines = review._first_party_diff(
            f.repo, {"base_sha": f.base, "head_sha": f.head},
        ).decode().splitlines()
        f._read(started, axis, "diff", "", "head", 1, len(lines))
        first = f._read(started, axis, "source", f.source_path, "head", 1, 8)
        second = f._read(started, axis, "source", f.source_path, "head", 9, 16)
        return f._report(axis, 1, [first["source_ref"], second["source_ref"]])

    def test_failed_axis_publication_is_retryable_in_same_session(self):
        f = self.f
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        report = self._axis_report(started)
        axes = f.state / "sessions" / started["review_session_id"] / "axes"
        with mock.patch.object(review, "_rename_private_record", side_effect=OSError("injected publish failure")):
            with self.assertRaisesRegex(OSError, "injected"):
                f._submit(started, report)
        self.assertEqual([], list(axes.iterdir()))
        self.assertEqual("axis_accepted", f._submit(
            started, report, reason="Retry after observing no published axis.",
        )["status"])
        for number, axis in enumerate(review.REQUIRED_AXES[1:], 2):
            f._submit_axis(started, axis, number)
        f._seal_direct(plan)

    def test_partial_stage_file_cannot_poison_later_session(self):
        f = self.f
        started = f._start_plan(f._first_party_plan())
        report = self._axis_report(started)

        def crash_before_publish(path, data):
            review._create_private_bytes(path.parent / ".signed-record-stage-crashed", data[:20])
            raise OSError("injected process interruption")

        with mock.patch.object(review, "_publish_private_record", side_effect=crash_before_publish):
            with self.assertRaisesRegex(OSError, "injected"):
                f._submit(started, report)
        later = f._first_party_plan()
        fresh = f._start_plan(later)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(fresh, axis, number)
        f._seal_direct(later)

    def test_failed_source_read_publication_does_not_poison_session(self):
        f = self.f
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        with mock.patch.object(review, "_rename_private_record", side_effect=OSError("injected publish failure")):
            with self.assertRaisesRegex(OSError, "injected"):
                f._read(started, review.REQUIRED_AXES[0], "source", f.source_path, "head", 1, 4)
        reads = f.state / "sessions" / started["review_session_id"] / "reads"
        self.assertEqual([], list(reads.glob("*.json")))
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(started, axis, number)
        f._seal_direct(plan)

    def test_failed_finalization_publication_is_retryable(self):
        f = self.f
        plan = f._candidate_plan()
        started = f._start_plan(plan)
        f._complete_candidate(plan, started)
        with mock.patch.object(review, "_rename_private_record", side_effect=OSError("injected publish failure")):
            with self.assertRaisesRegex(OSError, "injected"):
                f._finalize_candidate(plan, started)
        session = f.state / "sessions" / started["review_session_id"]
        self.assertFalse((session / "finalized.json").exists())
        f._finalize_candidate(plan, started, reason="Retry after observing no finalized record.")
        self.assertEqual("PASS", f._verify_candidate(plan)["verdict"])

    def test_interruption_after_publish_leaves_a_verifiable_immutable_axis(self):
        f = self.f
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        report = self._axis_report(started)
        publish = review._publish_private_record

        def lost_response(path, data):
            publish(path, data)
            raise OSError("injected response loss")

        with mock.patch.object(review, "_publish_private_record", side_effect=lost_response):
            with self.assertRaisesRegex(OSError, "injected"):
                f._submit(started, report)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "duplicated"):
            f._submit(started, report, reason="Confirm an already published axis cannot be replaced.")
        for number, axis in enumerate(review.REQUIRED_AXES[1:], 2):
            f._submit_axis(started, axis, number)
        f._seal_direct(plan)

    def test_atomic_record_is_create_only_and_checks_inner_budget(self):
        f = self.f
        path = f.root / "atomic.json"
        record = {"payload": "x" * 100}
        limit = len(review._canonical(record))
        review._write_signed_record(path, record, key=f.key, signers=f.signers, max_bytes=limit, atomic=True)
        before = path.read_bytes()
        self.assertGreater(len(before), limit)
        self.assertEqual(record, review._read_signed_record(
            path, signers=f.signers, root_owned_signers=False, max_bytes=limit,
        ))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "publication"):
            review._write_signed_record(path, {"different": True}, key=f.key, signers=f.signers, atomic=True)
        self.assertEqual(before, path.read_bytes())
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "over budget"):
            review._read_signed_record(path, signers=f.signers, root_owned_signers=False, max_bytes=limit - 1)

    def test_atomic_record_file_sync_failure_publishes_nothing(self):
        f = self.f
        path = f.root / "interrupted.json"
        with mock.patch.object(review.os, "fsync", side_effect=OSError("injected file sync failure")):
            with self.assertRaisesRegex(OSError, "injected"):
                review._write_signed_record(path, {"record": True}, key=f.key, signers=f.signers, atomic=True)
        self.assertFalse(path.exists())
        self.assertEqual([], list(f.root.glob(".signed-record-stage-*")))

    def _legacy_axis(self, started):
        f = self.f
        path = f.state / "sessions" / started["review_session_id"] / "axes" / (review.REQUIRED_AXES[0] + ".json")
        envelope = json.loads(path.read_bytes())
        path.write_bytes(review._canonical(envelope["record"]))
        review._create_private_bytes(path.with_suffix(".sig"), envelope["signature"].encode("ascii"))
        return path

    def test_legacy_pair_remains_valid_and_missing_signature_stays_blocking(self):
        f = self.f
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(started, axis, number)
        path = self._legacy_axis(started)
        f._seal_direct(plan)
        path.with_suffix(".sig").unlink()
        with self.assertRaises((review.ReviewExecutionRejected, FileNotFoundError)):
            f._seal_direct(plan)

    def test_legacy_material_reject_survives_atomic_records_in_new_batch(self):
        f = self.f
        started = f._start_plan(f._first_party_plan())
        f._submit_axis(started, review.REQUIRED_AXES[0], 1, reject=True)
        self._legacy_axis(started)
        later = f._first_party_plan()
        fresh = f._start_plan(later)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            f._submit_axis(fresh, axis, number)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            f._seal_direct(later)


if __name__ == "__main__":
    unittest.main()
