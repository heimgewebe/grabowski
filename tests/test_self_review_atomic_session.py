"""Failed starts must never publish unauthenticated review history."""
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


if __name__ == "__main__":
    unittest.main()
