"""Captain handles optional-check GitHub BLOCKED without weakening required gates.

The provider remains the final authority: merge calls never use --admin.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_grips import (
    CAPTAIN_HEAD,
    FakeGh,
    FakeGit,
    captain_execution_intent,
    captain_independent_review_reconciliation,
    captain_parameters,
    grips,
    merge_guard,
    resources,
)


class CaptainNonrequiredBlockTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reuse the same isolated first-party signer and resource fixtures
        # as CaptainAuthorityPathTests; the real signer guard is tested elsewhere.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        for fixture in (
            patch.object(resources, "RESOURCE_DB", Path(temp.name) / "resources.sqlite3"),
            patch.object(
                merge_guard.decision_reviews,
                "reconcile",
                return_value=captain_independent_review_reconciliation(),
            ),
            patch("grabowski_self_review_execution.review_receipt_errors", return_value=[]),
            # Material REJECT/ledger authenticity is covered in its own signer
            # suite. These tests must isolate only GitHub required-check
            # semantics, regardless of the operator machine's live history.
            patch.object(
                merge_guard, "_signed_first_party_material_history_errors",
                return_value=[],
            ),
        ):
            fixture.start()
            self.addCleanup(fixture.stop)

    def _run(self, *, checks=None, checks_returncode=0, merge_returncode=0, mergeable="MERGEABLE"):
        params = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        params.pop("human_authorization")
        params.pop("execution_authority")
        # This test isolates merge-state/required-check behavior; the
        # high-critical signed provenance tier has its own full test suite.
        review = params["review_evidence"]
        review["review_tier"] = "standard"
        review["minimum_review_iterations"] = 2
        review["actual_review_iterations"] = 2
        for field in ("review_pass_axes", "review_iterations", "review_pass_evidence_sha256"):
            review.pop(field, None)
        params.pop("codex_review_evidence", None)
        params["execution_intent"] = captain_execution_intent(params)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": mergeable,
                "mergeStateStatus": "BLOCKED",
            },
            required_checks=checks,
            required_checks_returncode=checks_returncode,
            merge_returncode=merge_returncode,
            merge_stderr="GitHub refused the merge" if merge_returncode else "",
        )
        outcome = grips.grip_run(
            "captain-run",
            params,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )
        merge_calls = [x for x in gh.calls if x[:2] == ("pr", "merge")]
        return outcome, gh, merge_calls

    def test_blocked_with_required_green_allows_provider_decision(self) -> None:
        result, gh, calls = self._run(checks=[
            {"bucket": "pass", "name": "Required merge gate", "state": "SUCCESS"},
            {"bucket": "pass", "name": "Review evidence gate", "state": "SUCCESS"},
        ])
        self.assertEqual("passed", result["receipt"]["status"], (result["output"].get("blocked_reasons"), result["output"].get("executions")))
        self.assertEqual(1, len(calls), (result["output"].get("blocked_reasons"), result["output"].get("executions")))
        self.assertNotIn("--admin", calls[0])
        execution = result["output"]["executions"][0]
        self.assertTrue(execution["execution_attempted"])
        self.assertTrue(execution["verification_passed"])
        # Head/base are checked before dispatch; nonrequired checks cannot
        # silently replace the two real current-head required status probes.
        probe = execution["preflight_view_summary"]["required_checks_probe"]
        self.assertEqual("green", probe["status"])
        self.assertEqual(2, probe["required_check_count"])
        self.assertGreaterEqual(
            len([x for x in gh.calls if x[:2] == ("pr", "checks")]), 3
        )

    def test_blocked_with_failed_or_unavailable_required_checks_stops_before_provider(self) -> None:
        cases = (
            ({"bucket": "fail", "name": "Review evidence gate", "state": "FAILURE"}, 0),
            ({"bucket": "pending", "name": "Review evidence gate", "state": "PENDING"}, 0),
            ({"bucket": "pass", "name": "Review evidence gate", "state": "SUCCESS"}, 1),
        )
        for check, code in cases:
            with self.subTest(check=check, code=code):
                result, _, calls = self._run(checks=[check], checks_returncode=code)
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertEqual([], calls)

    def test_blocked_with_no_required_checks_is_not_a_green_proof(self) -> None:
        result, _, calls = self._run(checks=[])
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual([], calls)

    def test_blocked_nonmergeable_conflict_never_calls_provider(self) -> None:
        result, _, calls = self._run(mergeable="CONFLICTING")
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual([], calls)

    def test_provider_refusal_remains_terminal_and_cannot_be_forced(self) -> None:
        result, _, calls = self._run(
            checks=[{"bucket": "pass", "name": "Required merge gate", "state": "SUCCESS"}],
            merge_returncode=1,
        )
        self.assertNotEqual("passed", result["receipt"]["status"])
        self.assertEqual(1, len(calls), (result["output"].get("blocked_reasons"), result["output"].get("executions")))
        self.assertNotIn("--admin", calls[0])
        self.assertFalse(result["output"]["executions"][0]["verification_passed"])


if __name__ == "__main__":
    unittest.main()