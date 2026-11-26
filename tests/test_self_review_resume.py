"""Authenticated continuation must preserve the original signed PR review."""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

import test_self_review_first_party as fixture

review = fixture.review


class FirstPartyResumeTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.FirstPartySemanticReviewTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()

    def _start(self):
        plan = self.f._first_party_plan()
        return plan, self.f._start_plan(plan)

    def _resume(self, plan):
        f = self.f
        arguments = {
            "review_batch_id": plan["binding"]["review_batch_id"],
            "reason": f"Resume exact session with retained evidence, attempt {f._request_counter + 1}.",
            "user_intent": "Continue authenticated first-party review after handoff.",
        }
        return review.start_first_party_review_session(
            plan, f._issuer(review.FIRST_PARTY_TOOL_START, arguments),
            root=f.state, key=f.key, signers=f.signers,
            root_owned_signers=False, now_unix=f.now,
        )

    def _session(self, started):
        return self.f.state / "sessions" / started["review_session_id"]

    def test_same_pr_batch_resumes_original_session_and_reads(self):
        f = self.f
        plan, started = self._start()
        session = self._session(started)
        axis = review.REQUIRED_AXES[0]
        f._submit_axis(started, axis, 1)
        original = {
            str(p.relative_to(session)): p.read_bytes()
            for p in session.rglob("*") if p.is_file()
        }
        f.now += 1
        resumed = self._resume(plan)
        self.assertEqual("review_session_resumed", resumed["status"])
        self.assertEqual(started["review_session_id"], resumed["review_session_id"])
        self.assertNotEqual(started["session_nonce"], resumed["session_nonce"])
        self.assertEqual(started["expires_at_unix"], resumed["expires_at_unix"])
        self.assertEqual(list(review.REQUIRED_AXES[1:]), resumed["pending_axes"])
        for name, data in original.items():
            self.assertEqual(data, (session / name).read_bytes(), name)
        self.assertEqual(1, len(list((f.state / "sessions").iterdir())))
        for number, axis in enumerate(review.REQUIRED_AXES[1:], 2):
            f._submit_axis(resumed, axis, number)
        audit, receipts = f._seal_direct(plan)
        self.assertEqual("PASS", audit["gate_verdict"])
        self.assertEqual([], f._receipt_errors(audit, receipts))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "already complete"):
            self._resume(plan)

    def test_cross_principal_resume_is_rejected(self):
        f = self.f
        plan, started = self._start()
        with mock.patch.object(fixture, "SCOPE_SHA256", hashlib.sha256(b"another scope").hexdigest()):
            with self.assertRaisesRegex(review.ReviewExecutionRejected, "crossed controller"):
                self._resume(plan)
        self.assertFalse((self._session(started) / "resume-credentials").exists())

    def test_resume_does_not_extend_deadline(self):
        f = self.f
        plan, started = self._start()
        f.now = started["expires_at_unix"] + 1
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "expired"):
            self._resume(plan)
        self.assertFalse((self._session(started) / "resume-credentials").exists())

    def test_bad_resume_credential_cannot_authorize_read(self):
        f = self.f
        plan, started = self._start()
        f.now += 1
        resumed = self._resume(plan)
        axis = review.REQUIRED_AXES[0]
        credential = next((self._session(started) / "resume-credentials").glob("*.json"))
        envelope = json.loads(credential.read_bytes())
        envelope["record"]["binding_sha256"] = "0" * 64
        credential.write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaises(review.ReviewExecutionRejected):
            f._read(resumed, axis, "diff", "", "head", 1, 1)
        f._read(started, axis, "diff", "", "head", 1, 1)

    def test_resume_rejects_drift(self):
        f = self.f
        plan, started = self._start()
        (f.repo / f.source_path).write_text("DRIFT = True\n", encoding="utf-8")
        with self.assertRaises(review.ReviewExecutionRejected):
            self._resume(plan)
        self.assertFalse((self._session(started) / "resume-credentials").exists())


if __name__ == "__main__":
    unittest.main()
