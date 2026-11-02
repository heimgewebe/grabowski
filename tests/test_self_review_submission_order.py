"""Real signed fixtures for publication ordering; no production review evidence."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
import unittest

import test_self_review_first_party as fixture


review = fixture.review


class SubmissionOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        # Compose the signing fixture without inheriting or rediscovering its tests.
        self.f = fixture.FirstPartySemanticReviewTests(
            "test_first_party_direct_audit_passes_public_receipt_verifier"
        )
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def _prepare_reject(self):
        f = self.f
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        axis = review.REQUIRED_AXES[0]
        count = len(review._first_party_diff(f.repo, plan["binding"]).splitlines())
        f._read(started, axis, "diff", "", "head", 1, count)
        refs = [
            f._read(started, axis, "source", f.source_path, "head", first, last)["source_ref"]
            for first, last in ((1, 8), (9, 16))
        ]
        report = f._report(axis, 1, refs, reject=True)
        issuer = f._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"],
            "report": report,
        })
        return started, report, issuer

    def _paused_loader(self, started, entered, resume):
        actual_load = review._load_first_party_session

        def load(session_id, *args, **kwargs):
            session = actual_load(session_id, *args, **kwargs)
            if session_id == started["review_session_id"]:
                # The request has captured its initial time and passed the
                # initial session checks, but has not acquired the signer lock.
                entered.set()
                if not resume.wait(timeout=15):
                    raise AssertionError("delayed submission was not resumed")
            return session

        return load

    def _launch(self, pool, started, report, issuer):
        f = self.f
        # Deliberately omit now_unix: exercise the production clock path.
        return pool.submit(
            review.submit_first_party_axis_review,
            started["review_session_id"], started["session_nonce"], report, issuer,
            root=f.state, key=f.key, signers=f.signers, root_owned_signers=False,
        )

    def test_delayed_reject_cannot_backdate_past_an_earlier_sealed_resolution(self):
        f = self.f
        initial = f.now
        delayed, report, issuer = self._prepare_reject()
        entered, resume = threading.Event(), threading.Event()
        clock = {"value": initial}
        with (
            mock.patch.object(review.time, "time", side_effect=lambda: clock["value"]),
            mock.patch.object(review, "_load_first_party_session",
                              side_effect=self._paused_loader(delayed, entered, resume)),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            future = self._launch(pool, delayed, report, issuer)
            try:
                self.assertTrue(entered.wait(timeout=5), "submission did not reach the barrier")
                clock["value"] = initial + 1
                f.now = initial + 1
                plan = f._first_party_plan()
                earlier = f._start_plan(plan)
                for number, axis in enumerate(review.REQUIRED_AXES, 1):
                    f._submit_axis(
                        earlier, axis, number,
                        resolve_ids=("material-1",) if number == 1 else (),
                    )
                audit, receipts = f._seal_direct(plan)
                self.assertEqual([], f._receipt_errors(audit, receipts))
                clock["value"] = initial + 2
                f.now = initial + 2
            finally:
                resume.set()
            self.assertEqual("axis_rejected", future.result(timeout=10)["status"])
            self.assertTrue(
                f._receipt_errors(audit, receipts),
                "a later published REJECT must invalidate the earlier sealed resolution",
            )
        path = (
            f.state / "sessions" / delayed["review_session_id"]
            / "axes" / (review.REQUIRED_AXES[0] + ".json")
        )
        signed = review._read_signed_record(
            path, signers=f.signers, root_owned_signers=False,
        )
        self.assertEqual(initial + 2, signed["submitted_at_unix"])

    def test_submission_delayed_past_session_expiry_publishes_no_axis(self):
        f = self.f
        initial = f.now
        delayed, report, issuer = self._prepare_reject()
        entered, resume = threading.Event(), threading.Event()
        clock = {"value": initial}
        with (
            mock.patch.object(review.time, "time", side_effect=lambda: clock["value"]),
            mock.patch.object(review, "_load_first_party_session",
                              side_effect=self._paused_loader(delayed, entered, resume)),
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            future = self._launch(pool, delayed, report, issuer)
            try:
                self.assertTrue(entered.wait(timeout=5), "submission did not reach the barrier")
                clock["value"] = initial + review.FIRST_PARTY_SESSION_TTL_SECONDS + 1
            finally:
                resume.set()
            with self.assertRaisesRegex(
                review.ReviewExecutionRejected,
                "session expired before axis publication",
            ):
                future.result(timeout=10)
        axes = f.state / "sessions" / delayed["review_session_id"] / "axes"
        self.assertEqual([], list(axes.iterdir()))


if __name__ == "__main__":
    unittest.main()
