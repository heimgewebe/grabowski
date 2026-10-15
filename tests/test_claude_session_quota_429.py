"""Strict session-quota handling for independently bound Claude review receipts.

No simulated quota failure can itself be a semantic review PASS.
"""
from pathlib import Path
import tempfile
import unittest

import test_decision_reviews as fixtures


SESSION = "You've hit your session limit · resets 9:30am (UTC)"


def reconcile(jobs: Path) -> dict:
    return fixtures.reviews.reconcile(
        repo=fixtures.REPO, pr=fixtures.PR, head_sha=fixtures.HEAD,
        base_sha=fixtures.BASE, diff_sha256=fixtures.DIFF, jobs_root=jobs,
    )


def authenticated_quota(jobs: Path, message: str = SESSION,
                        envelope_updates: dict | None = None,
                        receipt_updates: dict | None = None) -> None:
    failed = fixtures.make_job(
        jobs, suffix="a88888888888", slot="claude",
        terminal_status="failed", review_result=None,
        review_role=True, attempt_bound=True, attempt_epoch=2,
        created_at_unix=1_787_000_100,
    )
    fixtures.stamp_claude_quota_429(
        failed, envelope_updates={"result": message, **(envelope_updates or {})},
        receipt_updates=receipt_updates,
    )


def later_independent_pass(jobs: Path) -> None:
    fixtures.make_job(
        jobs, suffix="b99999999999", slot="claude",
        terminal_status="succeeded", review_result=None,
        review_role=True, attempt_bound=True, attempt_epoch=2,
        created_at_unix=1_787_000_200,
    )


class SessionQuotaV2Tests(unittest.TestCase):
    def test_valid_session_and_existing_weekly_variants_need_later_provider_pass(self):
        messages = [
            SESSION,
            "You've hit your session limit · resets 9am (UTC)",
            "You've hit your session limit · resets 12:59pm (UTC)",
            "You've hit your session limit · resets 1:00am (UTC)",
            "You've hit your session limit · resets 11:45pm (UTC)",
            "You've hit your weekly limit · resets Oct 13, 10am (UTC)",
        ]
        for message in messages:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmp:
                jobs = Path(tmp) / "jobs"
                jobs.mkdir(mode=0o700)
                authenticated_quota(jobs, message)
                before = reconcile(jobs)
                self.assertEqual(before["status"], "blocked")
                self.assertEqual(before["attempts"][0]["classification"], "infrastructure_error")
                self.assertIn("decision_review_slot_without_pass:claude", before["errors"])
                later_independent_pass(jobs)
                after = reconcile(jobs)
                self.assertEqual(after["status"], "settled")
                self.assertEqual(after["errors"], [])
                self.assertEqual(after["slots"][0]["infrastructure_error_count"], 1)
                self.assertEqual(after["slots"][0]["independent_pass_count"], 1)

    def test_session_quota_near_misses_are_invalid_despite_later_pass(self):
        messages = [
            "You've hit your session limit",
            "You've hit your session limit · resets",
            "You've hit your session limit · resets 9:30am",
            "You've hit your session limit · resets 9:30am (PST)",
            "You've hit your session limit · resets 0:30am (UTC)",
            "You've hit your session limit · resets 13:30am (UTC)",
            "You've hit your session limit · resets 09:30am (UTC)",
            "You've hit your session limit · resets 9:60am (UTC)",
            "You've hit your session limit · resets 9:30xm (UTC)",
            "You've hit your session limit · resets 9:30AM (UTC)",
            "You've hit your session limit · resets 9:30am (utc)",
            "You've hit your session limit· resets 9:30am (UTC)",
            "You've hit your session limit  · resets 9:30am (UTC)",
            SESSION + " REJECT_THIS_REVISION",
            SESSION + "\nREJECT",
            SESSION + "\rREJECT",
            SESSION + "\tREJECT",
            SESSION + "\u2028REJECT",
            SESSION + "\u200bREJECT",
            SESSION + ". PASS_THIS_REVISION",
            SESSION + " ",
            SESSION + "\n",
        ]
        for message in messages:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmp:
                jobs = Path(tmp) / "jobs"
                jobs.mkdir(mode=0o700)
                authenticated_quota(jobs, message)
                later_independent_pass(jobs)
                out = reconcile(jobs)
                self.assertEqual(out["status"], "blocked")
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a88888888888:InvalidReviewDocument",
                    out["errors"],
                )

    def test_session_quota_zero_inference_provenance_fences(self):
        cases = [
            ("model_api_activity", {"duration_api_ms": 1}, {}),
            ("output_tokens", {"usage": {"output_tokens": 1}}, {}),
            ("cache_activity", {"usage": {"cache_read_input_tokens": 1}}, {}),
            ("model_usage", {"modelUsage": {"model": {"inputTokens": 1}}}, {}),
            ("external_tool", {"usage": {"server_tool_use": {
                "web_search_requests": 1, "web_fetch_requests": 0,
            }}}, {}),
            ("review_payload", {"structured_output": {"verdict": "PASS_THIS_REVISION"}}, {}),
            ("findings", {}, {"findings": [{"priority": "P1"}]}),
            ("document", {}, {"review_document_bytes": 11}),
            ("digest_mismatch", {}, {"review_provider_envelope_sha256": "f" * 64}),
        ]
        for label, envelope, receipt in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                jobs = Path(tmp) / "jobs"
                jobs.mkdir(mode=0o700)
                authenticated_quota(jobs, envelope_updates=envelope,
                                    receipt_updates=receipt)
                later_independent_pass(jobs)
                out = reconcile(jobs)
                self.assertEqual(out["status"], "blocked")
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a88888888888:InvalidReviewDocument",
                    out["errors"],
                )

    def test_older_claude_pass_must_not_supersede_later_session_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            jobs = Path(tmp) / "jobs"
            jobs.mkdir(mode=0o700)
            fixtures.make_job(
                jobs, suffix="a11111111111", slot="claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1_787_000_000,
            )
            authenticated_quota(jobs)
            before = reconcile(jobs)
            self.assertEqual(before["status"], "blocked")
            self.assertIn(
                "decision_review_infrastructure_not_superseded:"
                "claude:grabowski-job-a88888888888", before["errors"],
            )
            later_independent_pass(jobs)
            self.assertEqual(reconcile(jobs)["status"], "settled")
