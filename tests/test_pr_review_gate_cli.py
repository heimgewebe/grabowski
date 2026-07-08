from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_cli_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


class PrReviewGateCliTests(unittest.TestCase):
    def test_missing_external_review_cannot_be_disabled(self) -> None:
        source = (ROOT / "tools" / "pr_review_gate.py").read_text(encoding="utf-8")
        marker = "cod" + "ex"
        self.assertNotIn("--allow-missing-" + marker, source)
        self.assertNotIn("require_" + marker, source)
        self.assertIn("--claude-evidence", source)

    def test_unavailable_review_reason_warns_but_no_cli_bypass_exists(self) -> None:
        marker = "cod" + "ex"
        state = {
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": "legacy unit seam without live PR diff",
            "pr": {
                "number": 58,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": "a" * 40,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/low_risk_note.md"}],
                "reviews": [],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": [],
        }
        review = {
            "head_sha": "a" * 40,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "claude_review": {"required": False, "reason": "small low-risk diff"},
            marker + "_review": {"unavailable_reason": "service unavailable"},
        }
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn("Codex review unavailable but explained", result["warnings"])

    def test_core_grabowski_paths_require_independent_review(self) -> None:
        head = "a" * 40
        state = {
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": "legacy unit seam without live PR diff",
            "pr": {
                "number": 58,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": head,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "src/grabowski_mcp.py"}],
                "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": head}],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": [],
        }
        review = {
            "head_sha": head,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "claude_review": {"required": False, "reason": "claimed small"},
        }
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(result["complexity"]["high_critical"])
        self.assertIn("high-critical Grabowski operator path touched: src/grabowski_mcp.py", result["complexity"]["reasons"])
        self.assertIn("External review evidence invalid: external review is required but evidence is missing", result["failures"])

class PrReviewGateEvidenceHardeningTests(unittest.TestCase):
    def _state(self, *, reviews=None, review_comments=None) -> dict:
        head = "a" * 40
        return {
            "repoName": "heimgewebe/grabowski",
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": "legacy unit seam without live PR diff",
            "pr": {
                "number": 58,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": head,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/low_risk_note.md"}],
                "reviews": reviews if reviews is not None else [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": head}],
                "latestReviews": [],
                "comments": [],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": review_comments or [],
        }

    def _review(self, **overrides) -> dict:
        head = "a" * 40
        payload = {
            "head_sha": head,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "claude_review": {"required": False, "reason": "small low-risk diff"},
        }
        payload.update(overrides)
        return payload

    def _claude_evidence(self, **overrides) -> dict:
        head = "a" * 40
        payload = {
            "schema_version": 1,
            "kind": "claude_ultrareview",
            "repo": "heimgewebe/grabowski",
            "pr": 58,
            "head_sha": head,
            "expected_head_sha": head,
            "tool": "claude-code",
            "tool_version": "2.1.197",
            "command": ["claude", "ultrareview", "58", "--json", "--timeout", "30"],
            "exit_code": 0,
            "json_ok": True,
            "verdict": "PASS",
            "finding_count": 0,
            "findings_triaged": True,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "1" * 64,
        }
        payload.update(overrides)
        return payload

    def test_inline_review_comment_does_not_satisfy_codex_evidence(self) -> None:
        head = "a" * 40
        result = pr_review_gate.evaluate_review_gate(
            self._state(reviews=[], review_comments=[{"user": {"login": "chatgpt-codex-connector"}, "commit_id": head}]),
            self_review=self._review(codex_review={"required": True, "reason": "explicit check"}),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["codex_seen"])
        self.assertIn("Codex review is explicitly required but not observed on current head", result["failures"])

    def test_rest_pr_review_still_satisfies_codex_evidence(self) -> None:
        head = "a" * 40
        state = self._state(reviews=[])
        state["prReviews"] = [{"user": {"login": "chatgpt-codex-connector"}, "commit_id": head}]
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["codex_seen"])

    def test_blocking_materiality_is_case_insensitive(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(findings=[{"severity": "p3", "materiality": "BLOCKING", "status": "accepted", "reason": "known"}]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("finding 0 is not terminally triaged", result["failures"])

    def test_claude_evidence_repo_mismatch_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(reviews=[{"author": {"login": "chatgpt-codex-connector"}, "commit_id": "a" * 40}]),
            self_review=self._review(claude_review={"required": True, "reason": "risk"}),
            claude_evidence=self._claude_evidence(repo="heimgewebe/other"),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Claude CLI evidence invalid: repo mismatch", result["failures"])

    def test_claude_command_accepts_equals_timeout(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(claude_review={"required": True, "reason": "risk"}),
            claude_evidence=self._claude_evidence(command=["claude", "ultrareview", "58", "--json", "--timeout=30"]),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["claude_cli_seen"])

    def test_claude_command_rejects_unknown_extra_flag(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(claude_review={"required": True, "reason": "risk"}),
            claude_evidence=self._claude_evidence(command=["claude", "ultrareview", "58", "--json", "--timeout", "30", "--extra"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Claude CLI evidence invalid: command is not claude ultrareview for this PR", result["failures"])

    def test_claude_command_rejects_wrong_pr_number(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(claude_review={"required": True, "reason": "risk"}),
            claude_evidence=self._claude_evidence(command=["claude", "ultrareview", "59", "--json", "--timeout", "30"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Claude CLI evidence invalid: command is not claude ultrareview for this PR", result["failures"])
