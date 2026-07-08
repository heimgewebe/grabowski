from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


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
REVIEW_FOCUS = ["correctness", "regression_risk", "tests", "security", "integration"]


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
            "repoName": "heimgewebe/grabowski",
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
            "schema_version": 1,
            "kind": "grabowski_self_review",
            "review_mode": "critical_diff_review",
            "verdict": "PASS",
            "repo": "heimgewebe/grabowski",
            "pr": 58,
            "head_sha": "a" * 40,
            "reviewed_files": ["docs/low_risk_note.md"],
            "review_focus": REVIEW_FOCUS,
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

    def test_pr_comment_self_review_text_does_not_satisfy_self_review_evidence(self) -> None:
        head = "a" * 40
        state = {
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
                "reviews": [],
                "latestReviews": [],
                "comments": [
                    {
                        "author": {"login": "grabowski"},
                        "body": "Self-review: PASS. I critically reviewed the diff.",
                    }
                ],
            },
            "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
            "reviewComments": [],
        }
        result = pr_review_gate.evaluate_review_gate(state, self_review=None)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Grabowski self-review evidence is missing", result["failures"])

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
            "schema_version": 1,
            "kind": "grabowski_self_review",
            "review_mode": "critical_diff_review",
            "verdict": "PASS",
            "repo": "heimgewebe/grabowski",
            "pr": 58,
            "head_sha": head,
            "reviewed_files": ["src/grabowski_mcp.py"],
            "review_focus": REVIEW_FOCUS,
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
            "schema_version": 1,
            "kind": "grabowski_self_review",
            "review_mode": "critical_diff_review",
            "verdict": "PASS",
            "repo": "heimgewebe/grabowski",
            "pr": 58,
            "head_sha": head,
            "reviewed_files": ["docs/low_risk_note.md"],
            "review_focus": REVIEW_FOCUS,
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


    def test_self_review_workflow_metadata_is_required(self) -> None:
        review = self._review()
        review.pop("kind")
        result = pr_review_gate.evaluate_review_gate(self._state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review kind must be grabowski_self_review", result["failures"])
        self.assertFalse(result["review_sources"]["self_review_workflow_valid"])

    def test_self_review_current_pr_number_is_required(self) -> None:
        state = self._state()
        state["pr"].pop("number")
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("current PR state is missing integer PR number", result["failures"])

    def test_self_review_current_pr_number_rejects_bool(self) -> None:
        state = self._state()
        state["pr"]["number"] = True
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("current PR state is missing integer PR number", result["failures"])

    def test_self_review_current_repo_name_is_required(self) -> None:
        state = self._state()
        state.pop("repoName")
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("current gate state is missing repoName", result["failures"])

    def test_self_review_file_coverage_requires_complete_pr_file_list(self) -> None:
        state = self._state()
        state["pr"]["changedFiles"] = 2
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("current PR file list is incomplete", result["failures"])

    def test_self_review_schema_version_is_required(self) -> None:
        review = self._review()
        review.pop("schema_version")
        result = pr_review_gate.evaluate_review_gate(self._state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review schema_version is not integer 1", result["failures"])

    def test_self_review_repo_mismatch_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(repo="heimgewebe/other"),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review repo mismatch", result["failures"])

    def test_self_review_pr_mismatch_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(pr=59),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review pr number mismatch", result["failures"])

    def test_self_review_file_coverage_accepts_repeated_dot_slash_prefix(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["././docs/low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_self_review_file_coverage_accepts_dot_slash_prefix(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["./docs/low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["self_review_workflow_valid"])

    def test_self_review_file_coverage_is_case_sensitive(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["DOCS/LOW_RISK_NOTE.MD"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "self-review reviewed_files does not cover PR file(s): docs/low_risk_note.md",
            result["failures"],
        )

    def test_self_review_file_coverage_rejects_backslashes(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=[r"docs\low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_rejects_double_slashes(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["docs//low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_rejects_control_characters(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["docs/low\t_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_rejects_dot_segments(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["docs/./low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_rejects_parent_segments(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["../../docs/low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_rejects_absolute_paths(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["/docs/low_risk_note.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review reviewed_files contains invalid path at index 0", result["failures"])

    def test_self_review_file_coverage_requires_current_pr_file_list(self) -> None:
        state = self._state()
        state["pr"]["files"] = []
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("current PR file list is missing or empty", result["failures"])

    def test_self_review_file_coverage_accepts_filename_field(self) -> None:
        state = self._state()
        state["pr"]["files"] = [{"filename": "docs/low_risk_note.md"}]
        result = pr_review_gate.evaluate_review_gate(state, self_review=self._review())
        self.assertEqual(result["verdict"], "PASS")

    def test_self_review_non_pass_verdict_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(verdict="NEEDS_CHANGE"),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review verdict is NEEDS_CHANGE, not PASS", result["failures"])

    def test_self_review_must_cover_current_pr_files(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(reviewed_files=["README.md"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "self-review reviewed_files does not cover PR file(s): docs/low_risk_note.md",
            result["failures"],
        )

    def test_self_review_focus_must_cover_required_axes(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(review_focus=["correctness", "tests"]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "self-review review_focus missing required item(s): regression_risk, security, integration",
            result["failures"],
        )

    def test_self_review_gate_valid_includes_full_self_review_requirements(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            self._state(),
            self_review=self._review(diff_reviewed=False),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(result["review_sources"]["self_review_workflow_valid"])
        self.assertTrue(result["review_sources"]["self_review_metadata_valid"])
        self.assertFalse(result["review_sources"]["self_review_gate_valid"])

    def test_write_self_review_template_cli_emits_template_metadata(self) -> None:
        state = self._state()
        state["pr_diff_sha256"] = "0" * 64
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as tmpdir:
            template_path = Path(tmpdir) / "self-review-template.json"
            stdout = io.StringIO()
            with mock.patch.object(pr_review_gate, "load_pr_state", return_value=state), contextlib.redirect_stdout(stdout):
                rc = pr_review_gate.main(["--pr", "58", "--write-self-review-template", str(template_path), "--json"])
            self.assertEqual(rc, 2)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["self_review_template"]["path"], str(template_path))
            self.assertEqual(result["self_review_template"]["diff_sha256"], "0" * 64)
            self.assertTrue(template_path.is_file())

    def test_write_self_review_template_cli_blocks_existing_file(self) -> None:
        state = self._state()
        state["pr_diff_sha256"] = "0" * 64
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as tmpdir:
            template_path = Path(tmpdir) / "self-review-template.json"
            template_path.write_text("existing", encoding="utf-8")
            stdout = io.StringIO()
            with mock.patch.object(pr_review_gate, "load_pr_state", return_value=state), contextlib.redirect_stdout(stdout):
                rc = pr_review_gate.main(["--pr", "58", "--write-self-review-template", str(template_path), "--json"])
            self.assertEqual(rc, 2)
            result = json.loads(stdout.getvalue())
            self.assertIn("self-review template already exists", result["failures"][0])
            self.assertEqual(template_path.read_text(encoding="utf-8"), "existing")

    def test_write_self_review_template_cli_blocks_missing_diff_hash(self) -> None:
        state = self._state()
        state["pr_diff_error"] = "gh pr diff failed"
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build) as tmpdir:
            template_path = Path(tmpdir) / "self-review-template.json"
            stdout = io.StringIO()
            with mock.patch.object(pr_review_gate, "load_pr_state", return_value=state), contextlib.redirect_stdout(stdout):
                rc = pr_review_gate.main(["--pr", "58", "--write-self-review-template", str(template_path), "--json"])
            self.assertEqual(rc, 2)
            result = json.loads(stdout.getvalue())
            self.assertIn("cannot write self-review template without current PR diff SHA-256", result["failures"][0])
            self.assertFalse(template_path.exists())

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
