from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "0" * 64
OTHER_DIFF_SHA = "1" * 64


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_self_diff_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state(*, diff_sha: str | None = DIFF_SHA, diff_error: str | None = None) -> dict[str, object]:
    state: dict[str, object] = {
        "repoName": "heimgewebe/grabowski",
        "pr_diff_required": True,
        "pr": {
            "number": 88,
            "title": "docs: example",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "files": [{"path": "docs/example.md"}],
            "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "state": "APPROVED", "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }
    if diff_sha is not None:
        state["pr_diff_sha256"] = diff_sha
    if diff_error is not None:
        state["pr_diff_error"] = diff_error
    return state


def _self_review(*, diff_sha: str | None = DIFF_SHA) -> dict[str, object]:
    review: dict[str, object] = {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 88,
        "head_sha": HEAD,
        "base_sha": BASE,
        "reviewed_files": ["docs/example.md"],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "current diff reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "small non-risk diff"},
    }
    if diff_sha is not None:
        review["diff_sha256"] = diff_sha
    return review


def _has_failure(result: dict[str, object], needle: str) -> bool:
    return any(needle in str(item) for item in result.get("failures", []))


class SelfReviewDiffBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        # Synthetic legacy examples cannot depend on signed production sessions.
        # Real signature and REJECT verification is exercised separately.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        history = patch.object(
            gate.review_provenance, "FIRST_PARTY_REVIEW_ROOT",
            Path(tmp.name) / "no-first-party-sessions",
        )
        history.start()
        self.addCleanup(history.stop)

    def test_matching_self_review_diff_hash_passes(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bound"])

    def test_foreign_repo_ignores_unrelated_signed_heimgewebe_history(self) -> None:
        state = _state()
        state["repoName"] = "alexdermohr/machtverflechtungen"
        review = _self_review()
        review["repo"] = state["repoName"]
        # A real global signed history root may exist, but this repository
        # cannot have a first-party Heimgewebe binding to validate.
        with patch.object(
            gate.review_provenance, "_assert_no_first_party_reject_for_legacy_review",
            side_effect=ValueError("foreign owner cannot be a first-party subject"),
        ) as history:
            result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS", result["failures"])
        history.assert_not_called()

    def test_mixed_case_foreign_owner_still_ignores_heimgewebe_history(self) -> None:
        state = _state()
        state["repoName"] = "AlexDerMohr/Machtverflechtungen"
        review = _self_review()
        review["repo"] = state["repoName"]
        with patch.object(
            gate.review_provenance, "_assert_no_first_party_reject_for_legacy_review",
            side_effect=ValueError("unrelated signed Heimgewebe history"),
        ) as history:
            result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS", result["failures"])
        history.assert_not_called()

    def test_mixed_case_managed_owner_still_enforces_signed_reject(self) -> None:
        state = _state()
        state["repoName"] = "HeiMGeWeBe/Grabowski"
        review = _self_review()
        review["repo"] = state["repoName"]
        with patch.object(
            gate.review_provenance, "_assert_no_first_party_reject_for_legacy_review",
            side_effect=gate.review_provenance.ReviewExecutionRejected("signed material REJECT"),
        ) as history:
            result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK", result["failures"])
        self.assertTrue(_has_failure(result, "signed first-party material review history unresolved or invalid"))
        history.assert_called_once()

    def test_unicode_repository_alias_is_rejected_before_history_scope(self) -> None:
        state = _state()
        state["repoName"] = "heiMGewebe/Grabowſki"
        review = _self_review()
        review["repo"] = state["repoName"]
        with patch.object(
            gate.review_provenance, "_assert_no_first_party_reject_for_legacy_review",
            side_effect=AssertionError("invalid Unicode must not bind history"),
        ) as history:
            result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK", result["failures"])
        history.assert_not_called()
        self.assertTrue(_has_failure(result, "repository identity could not be canonicalized"))

    def test_managed_repo_signed_reject_still_blocks_standard_review(self) -> None:
        with patch.object(
            gate.review_provenance, "_assert_no_first_party_reject_for_legacy_review",
            side_effect=gate.review_provenance.ReviewExecutionRejected("material REJECT"),
        ) as history:
            result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "signed first-party material review history unresolved or invalid"),
            result["failures"],
        )
        history.assert_called_once()

    def test_self_review_base_sha_mismatch_blocks(self) -> None:
        review = _self_review()
        review["base_sha"] = "d" * 40
        result = gate.evaluate_review_gate(_state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review base_sha mismatch"), result["failures"])

    def test_missing_self_review_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 is missing or invalid"), result["failures"])

    def test_mismatching_self_review_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review(diff_sha=OTHER_DIFF_SHA))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 mismatch"), result["failures"])

    def test_unavailable_current_diff_hash_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state(diff_sha=None, diff_error="gh pr diff failed"),
            self_review=_self_review(),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "current PR diff hash is unavailable: gh pr diff failed"), result["failures"])

    def test_state_without_required_flag_still_enforces_diff_binding(self) -> None:
        state = _state()
        state.pop("pr_diff_required")
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "self-review diff_sha256 is missing or invalid"), result["failures"])

    def test_explicit_bypass_requires_reason(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "self-review diff binding bypass requires pr_diff_bypass_reason='legacy unit seam without live PR diff'"),
            result["failures"],
        )

    def test_explicit_bypass_with_reason_passes_legacy_unit_seam(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["self_review_diff_bound"])

    def test_self_review_diff_hash_accepts_uppercase_and_whitespace(self) -> None:
        result = gate.evaluate_review_gate(
            _state(diff_sha=DIFF_SHA),
            self_review=_self_review(diff_sha=f"  {DIFF_SHA.upper()}\n"),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bound"])

    def test_explicit_bypass_is_reported(self) -> None:
        state = _state(diff_sha=None)
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        result = gate.evaluate_review_gate(state, self_review=_self_review(diff_sha=None))
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_diff_bypass_used"])
        self.assertIn("Self-review diff binding bypass was requested", result["warnings"])


if __name__ == "__main__":
    unittest.main()
