from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
DIFF_SHA = "0" * 64
PROMPT_SHA = "1" * 64
REVIEW_SHA = "2" * 64
PACKET_PROMPT_SHA = "3" * 64


def _load_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _state(path: str = "README.md", *, diff_sha: str | None = DIFF_SHA) -> dict[str, object]:
    state: dict[str, object] = {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 7,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": "b" * 40,
            "changedFiles": 1,
            "additions": 3,
            "deletions": 1,
            "files": [{"path": path}],
            "reviews": [
                {"author": {"login": "chatgpt-codex-connector"}, "state": "APPROVED", "commit_id": HEAD},
                {"author": {"login": "claude[bot]"}, "state": "APPROVED", "commit_id": HEAD},
            ],
        },
        "checks": [
            {"name": "validate (3.10)", "bucket": "pass"},
            {"name": "validate (3.12)", "bucket": "pass"},
        ],
    }
    if diff_sha is not None:
        state["pr_diff_sha256"] = diff_sha
    return state


def _self_review(*, diff_sha: str = DIFF_SHA, path: str = "README.md") -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "reviewed_files": [path],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "diff_sha256": diff_sha,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "diff reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "material_findings_after_first_review": 0,
        "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "small non-risk diff"},
    }


def _packet_command() -> list[str]:
    schema = json.dumps(gate.CLAUDE_PACKET_REVIEW_SCHEMA, separators=(",", ":"), sort_keys=True)
    return [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--json-schema",
        schema,
        "--tools=",
        "--permission-mode",
        "plan",
        "--no-session-persistence",
        "--safe-mode",
        "--model",
        "opus",
        "--effort",
        "high",
        "--max-budget-usd",
        "2",
    ]


def _claude_review(**overrides: object) -> dict[str, object]:
    review: dict[str, object] = {
        "source": gate.CLAUDE_CLI_REVIEW_SOURCE,
        "tool": "claude-code",
        "tool_version": "2.1.206",
        "command": _packet_command(),
        "stdin_sha256": PROMPT_SHA,
        "model": "opus",
        "effort": "high",
        "exit_code": 0,
        "json_ok": True,
        "review_sha256": REVIEW_SHA,
        "verdict": "PASS",
        "finding_count": 0,
    }
    review.update(overrides)
    return review


def _external(**overrides: object) -> dict[str, object]:
    repo = overrides.get("repo", "heimgewebe/grabowski")
    pr = overrides.get("pr", 7)
    head_sha = overrides.get("head_sha", HEAD)
    diff_sha256 = overrides.get("diff_sha256", DIFF_SHA)
    prompt_sha256 = overrides.get("prompt_sha256", PROMPT_SHA)
    packet_prompt = gate.build_external_review_prompt(
        {
            "repoName": repo,
            "pr": {"number": pr, "headRefOid": head_sha, "title": ""},
        },
        f"pr-{pr}-{str(head_sha)[:12]}.diff",
        str(diff_sha256).strip().lower(),
    )
    packet_prompt_sha256 = gate._sha256_text(packet_prompt)
    data: dict[str, object] = {
        "schema_version": 1,
        "kind": "external_review",
        "repo": repo,
        "pr": pr,
        "head_sha": head_sha,
        "diff_sha256": diff_sha256,
        "prompt_sha256": prompt_sha256,
        "prompt_includes_diff": True,
        "prompt_transmitted": True,
        "review_input": {
            "mode": gate.CLAUDE_CLI_REVIEW_INPUT_MODE,
            "repo": repo,
            "pr": pr,
            "head_sha": head_sha,
            "diff_sha256": diff_sha256,
            "packet_prompt_sha256": packet_prompt_sha256,
            "prompt_sha256": prompt_sha256,
            "transport": "stdin",
        },
        "reviews": [_claude_review(stdin_sha256=prompt_sha256)],
        "external_reviews_triaged": True,
        "findings": [],
    }
    data.update(overrides)
    return data


def _policy_waiver(**overrides: object) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    waiver: dict[str, object] = {
        "schema_version": 1,
        "kind": gate.CLAUDE_POLICY_WAIVER_KIND,
        "scope": gate.CLAUDE_POLICY_WAIVER_SCOPE,
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "head_sha": HEAD,
        "diff_sha256": DIFF_SHA,
        "authority": gate.CLAUDE_POLICY_WAIVER_AUTHORITY,
        "approver": "trusted-owner:test",
        "reason": "Claude CLI provider unavailable during a bounded recovery window.",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "audit_reference": "test://waiver/7",
    }
    waiver.update(overrides)
    return waiver


def _generic_external(**overrides: object) -> dict[str, object]:
    evidence = _external()
    evidence.pop("review_input", None)
    evidence["reviews"] = [
        {
            "source": "chatgpt",
            "review_sha256": REVIEW_SHA,
            "verdict": "PASS",
            "finding_count": 0,
        }
    ]
    evidence.update(overrides)
    return evidence


def _terminal_external_finding() -> dict[str, object]:
    return {
        "status": "fixed",
        "severity": "p2",
        "materiality": "material",
        "reason": "addressed in follow-up patch",
    }


def _has_failure(result: dict[str, object], needle: str) -> bool:
    return any(needle in str(item) for item in result.get("failures", []))


class ExternalReviewGateTests(unittest.TestCase):
    def test_complex_risk_path_without_external_evidence_blocks(self) -> None:
        result = gate.evaluate_review_gate(_state("tools/pr_review_gate.py"), self_review=_self_review(path="tools/pr_review_gate.py"))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_complex_risk_path_with_valid_external_evidence_passes(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["external_review_required"])
        self.assertEqual(result["review_sources"]["external_reviews_received"], 1)


    def test_complex_risk_path_block_verdict_without_terminal_finding_coverage_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "BLOCK", "finding_count": 0}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review 0 verdict is BLOCK without terminal finding coverage"), result["failures"])

    def test_complex_risk_path_needs_change_without_terminal_finding_coverage_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 0}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review 0 verdict is NEEDS_CHANGE without terminal finding coverage"), result["failures"])

    def test_complex_risk_path_pass_with_reported_finding_without_terminal_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1}],
                external_reviews_triaged=True,
                findings=[],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 1 finding(s) but only 0 terminal finding(s) are recorded"), result["failures"])

    def test_complex_risk_path_reported_finding_with_matching_terminal_finding_passes(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[
                    {"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1},
                    _claude_review(),
                ],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()]
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_complex_risk_path_two_reported_findings_with_one_terminal_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 2}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"), result["failures"])

    def test_complex_risk_path_needs_change_requires_matching_terminal_finding_count(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 2}],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"), result["failures"])

        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[
                    {"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "NEEDS_CHANGE", "finding_count": 2},
                    _claude_review(),
                ],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding(), _terminal_external_finding()]
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_complex_risk_path_block_zero_count_passes_with_one_terminal_finding(self) -> None:
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=[
                    {"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "BLOCK", "finding_count": 0},
                    _claude_review(),
                ],
                external_reviews_triaged=True,
                findings=[_terminal_external_finding()]
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_sha256_normalization_accepts_uppercase_and_whitespace(self) -> None:
        diff_sha = "ab" * 32
        prompt_sha = "cd" * 32
        review_sha = "ef" * 32
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py", diff_sha=diff_sha),
            self_review=_self_review(diff_sha=diff_sha, path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                diff_sha256=f"  {diff_sha.upper()}\n",
                prompt_sha256=f"\t{prompt_sha.upper()}  ",
                reviews=[
                    _claude_review(review_sha256=f"  {review_sha.upper()}\t", stdin_sha256=f"\t{prompt_sha.upper()}  "),
                ],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_mixed_review_counts_require_two_terminal_findings(self) -> None:
        reviews = [
            {"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 1},
            {"source": "claude", "review_sha256": "3" * 64, "verdict": "BLOCK", "finding_count": 0},
            _claude_review(review_sha256="4" * 64),
        ]
        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(),
            external_review_evidence=_external(reviews=reviews, findings=[_terminal_external_finding()]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "external reviews report 2 finding(s) but only 1 terminal finding(s) are recorded"),
            result["failures"],
        )

        result = gate.evaluate_review_gate(
            _state("tools/pr_review_gate.py"),
            self_review=_self_review(path="tools/pr_review_gate.py"),
            external_review_evidence=_external(
                reviews=reviews,
                findings=[_terminal_external_finding(), _terminal_external_finding()],
            ),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_deprecated_embedded_external_review_does_not_satisfy_complex_path(self) -> None:
        self_review = _self_review()
        self_review["external_review"] = _external()
        result = gate.evaluate_review_gate(_state("tools/pr_review_gate.py"), self_review=self_review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])
        self.assertIn(
            "Deprecated self_review.external_review ignored; pass --external-review-evidence instead",
            result["warnings"],
        )
        self.assertIsNone(result["review_sources"]["external_reviews_received"])

    def test_trivial_embedded_external_review_is_ignored_with_warning(self) -> None:
        self_review = _self_review()
        self_review["external_review"] = _external()
        result = gate.evaluate_review_gate(_state(), self_review=self_review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertIn(
            "Deprecated self_review.external_review ignored; pass --external-review-evidence instead",
            result["warnings"],
        )
        self.assertIsNone(result["review_sources"]["external_reviews_received"])

    def test_json_evidence_file_size_limit_blocks_all_loaders(self) -> None:
        loaders = [
            ("self-review", gate.load_self_review, "self-review.json"),
            ("Claude evidence", gate.load_claude_evidence, "claude.json"),
            ("external review evidence", gate.load_external_review_evidence, "external-review.json"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            for label, loader, filename in loaders:
                with self.subTest(label=label):
                    path = Path(tmpdir) / filename
                    path.write_text("{" + (" " * gate.MAX_JSON_EVIDENCE_BYTES) + "}", encoding="utf-8")
                    with self.assertRaisesRegex(gate.GateInputError, f"{label} file exceeds"):
                        loader(path)

    def test_missing_current_diff_hash_reports_error_detail(self) -> None:
        state = _state("tools/pr_review_gate.py", diff_sha=None)
        state["pr_diff_error"] = "gh pr diff failed"
        result = gate.evaluate_review_gate(state, self_review=_self_review(), external_review_evidence=_external())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(
            _has_failure(result, "current PR diff hash is unavailable: gh pr diff failed"),
            result["failures"],
        )

    def test_invalid_external_evidence_cases_block(self) -> None:
        cases = [
            ("required false", _state("tools/pr_review_gate.py"), _external(required=False), "required=false cannot disable"),
            ("required string false", _state("tools/pr_review_gate.py"), _external(required="false"), "external_review.required must be a bool"),
            ("required zero", _state("tools/pr_review_gate.py"), _external(required=0), "external_review.required must be a bool"),
            ("bool schema version", _state("tools/pr_review_gate.py"), _external(schema_version=True), "schema_version is not integer 1"),
            ("bool pr number", _state("tools/pr_review_gate.py"), _external(pr=True), "pr number mismatch"),
            ("string pr number", _state("tools/pr_review_gate.py"), _external(pr="7"), "pr number mismatch"),
            ("wrong head", _state("tools/pr_review_gate.py"), _external(head_sha="b" * 40), "head_sha mismatch"),
            ("wrong diff", _state("tools/pr_review_gate.py"), _external(diff_sha256="3" * 64), "diff_sha256 mismatch"),
            ("missing diff", _state("tools/pr_review_gate.py", diff_sha=None), _external(), "current PR diff hash is unavailable"),
            ("invalid prompt", _state("tools/pr_review_gate.py"), _external(prompt_sha256="not-a-sha"), "prompt_sha256 is missing or invalid"),
            ("empty reviews", _state("tools/pr_review_gate.py"), _external(reviews=[]), "reviews must be non-empty"),
            ("reviews not list", _state("tools/pr_review_gate.py"), _external(reviews={"source": "chatgpt"}), "reviews is not a list"),
            ("bool finding count", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": True}]), "finding_count must be an integer"),
            ("non-string source", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": 123, "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}]), "source is missing"),
            ("non-string verdict", _state("tools/pr_review_gate.py"), _external(reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": 123, "finding_count": 0}]), "verdict is invalid"),
            ("not triaged", _state("tools/pr_review_gate.py"), _external(external_reviews_triaged=False), "external_reviews_triaged is not true"),
            ("findings not list", _state("tools/pr_review_gate.py"), _external(findings={"status": "fixed"}), "findings is not a list"),
            ("untriaged finding", _state("tools/pr_review_gate.py"), _external(findings=[{"status": "open", "severity": "low"}]), "external_review finding 0 is not terminally triaged"),
        ]
        for name, state, evidence, needle in cases:
            with self.subTest(name=name):
                result = gate.evaluate_review_gate(state, self_review=_self_review(), external_review_evidence=evidence)
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertTrue(_has_failure(result, needle), result["failures"])

    def test_trivial_change_without_external_evidence_passes(self) -> None:
        result = gate.evaluate_review_gate(_state(), self_review=_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["external_review_required"])

    def test_trivial_change_with_voluntary_untriaged_external_finding_blocks(self) -> None:
        result = gate.evaluate_review_gate(
            _state(),
            self_review=_self_review(),
            external_review_evidence=_external(findings=[{"status": "open", "severity": "low"}]),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external_review finding 0 is not terminally triaged"), result["failures"])


class ExternalReviewDefaultPolicyTests(unittest.TestCase):
    def test_non_trivial_code_change_requires_external_llm_evidence(self) -> None:
        state = _state("src/feature.py")
        state["pr"]["additions"] = 45
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["high_critical"])
        self.assertFalse(result["complexity"]["complex"])
        self.assertEqual(result["complexity"]["review_tier"], "external_llm")
        self.assertTrue(result["review_sources"]["external_review_required"])
        self.assertFalse(result["review_sources"]["platform_review_required"])
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_docs_only_change_is_exempt_from_external_llm_evidence(self) -> None:
        state = _state("docs/architecture.md")
        state["pr"]["additions"] = 1200
        state["pr"]["deletions"] = 200
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review(path="docs/architecture.md"))
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "exempt_documentation")
        self.assertFalse(result["review_sources"]["external_review_required"])
        self.assertFalse(result["review_sources"]["platform_review_required"])

    def test_grabowski_md_is_policy_critical_not_documentation_exempt(self) -> None:
        state = _state("GRABOWSKI.md")
        state["pr"]["additions"] = 200
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["docs_only"])
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertFalse(result["review_sources"]["platform_review_required"])
        self.assertIn("high-critical policy path touched: GRABOWSKI.md", result["complexity"]["reasons"])

    def test_agents_md_is_policy_critical_not_documentation_exempt(self) -> None:
        state = _state("AGENTS.md")
        state["pr"]["additions"] = 80
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["docs_only"])
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertFalse(result["review_sources"]["platform_review_required"])
        self.assertIn("high-critical policy path touched: AGENTS.md", result["complexity"]["reasons"])

    def test_external_review_loop_doc_is_policy_critical(self) -> None:
        state = _state("docs/external-review-loop.md")
        state["pr"]["additions"] = 20
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["docs_only"])
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertFalse(result["review_sources"]["platform_review_required"])

    def test_generated_json_under_docs_is_not_documentation_exempt(self) -> None:
        state = _state("docs/generated/operator-context.v1.json")
        state["pr"]["additions"] = 120
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["docs_only"])
        self.assertEqual(result["complexity"]["review_tier"], "external_llm")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_requirements_txt_is_not_documentation_exempt(self) -> None:
        state = _state("requirements/deploy-tooling.lock.txt")
        state["pr"]["additions"] = 60
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["docs_only"])
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertTrue(result["complexity"]["high_critical"])
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_small_pyproject_change_is_not_trivial_exempt(self) -> None:
        state = _state("pyproject.toml")
        state["pr"]["additions"] = 2
        state["pr"]["deletions"] = 1
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["very_small_uncomplicated"])
        self.assertEqual(result["complexity"]["review_tier"], "external_llm")
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])

    def test_small_makefile_change_is_not_trivial_exempt(self) -> None:
        state = _state("Makefile")
        state["pr"]["additions"] = 1
        state["pr"]["deletions"] = 1
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["very_small_uncomplicated"])
        self.assertEqual(result["complexity"]["review_tier"], "external_llm")

    def test_zero_line_asset_change_is_not_trivial_exempt(self) -> None:
        state = _state("assets/logo.png")
        state["pr"]["additions"] = 0
        state["pr"]["deletions"] = 0
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["complexity"]["very_small_uncomplicated"])
        self.assertEqual(result["complexity"]["review_tier"], "external_llm")

    def test_very_small_uncomplicated_code_change_is_exempt(self) -> None:
        state = _state("src/tiny_feature.py")
        state["pr"]["additions"] = 4
        state["pr"]["deletions"] = 1
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review(path="src/tiny_feature.py"))
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "exempt_very_small")
        self.assertFalse(result["review_sources"]["external_review_required"])
        self.assertFalse(result["review_sources"]["platform_review_required"])

    def test_weltgewebe_tiny_code_change_requires_claude_cli_review(self) -> None:
        state = _state("src/tiny_feature.py")
        state["repoName"] = "heimgewebe/weltgewebe"
        state["pr"]["additions"] = 4
        state["pr"]["deletions"] = 1
        state["pr"]["reviews"] = []
        self_review = _self_review(path="src/tiny_feature.py")
        self_review["repo"] = "heimgewebe/weltgewebe"
        result = gate.evaluate_review_gate(state, self_review=self_review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["complexity"]["review_tier"], "important_repo")
        self.assertEqual(result["complexity"]["repo_policy"], "important")
        self.assertTrue(result["review_sources"]["claude_cli_required"])
        self.assertTrue(_has_failure(result, "external review is required"), result["failures"])

    def test_weltgewebe_tiny_code_change_passes_with_claude_cli_review(self) -> None:
        state = _state("src/tiny_feature.py")
        state["repoName"] = "heimgewebe/weltgewebe"
        state["pr"]["additions"] = 4
        state["pr"]["deletions"] = 1
        state["pr"]["reviews"] = []
        self_review = _self_review(path="src/tiny_feature.py")
        self_review["repo"] = "heimgewebe/weltgewebe"
        result = gate.evaluate_review_gate(
            state,
            self_review=self_review,
            external_review_evidence=_external(repo="heimgewebe/weltgewebe"),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["complexity"]["review_tier"], "important_repo")

    def test_weltgewebe_ordinary_docs_only_change_remains_exempt(self) -> None:
        state = _state("docs/note.md")
        state["repoName"] = "heimgewebe/weltgewebe"
        state["pr"]["reviews"] = []
        self_review = _self_review(path="docs/note.md")
        self_review["repo"] = "heimgewebe/weltgewebe"
        result = gate.evaluate_review_gate(state, self_review=self_review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["complexity"]["important_repo"])
        self.assertFalse(result["review_sources"]["claude_cli_required"])

    def test_high_critical_change_requires_external_evidence_without_coding_agent_requirement(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(state, self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(result["complexity"]["high_critical"])
        self.assertTrue(result["complexity"]["complex"])
        self.assertEqual(result["complexity"]["review_tier"], "high_critical")
        self.assertTrue(result["review_sources"]["external_review_required"])
        self.assertFalse(result["review_sources"]["platform_review_required"])
        self.assertTrue(_has_failure(result, "external review is required but evidence is missing"), result["failures"])
        self.assertFalse(
            _has_failure(result, "High-critical platform review is required"),
            result["failures"],
        )

    def test_high_critical_change_requires_claude_cli_review_entry(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_external(
                reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}]
            ),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(result["review_sources"]["claude_cli_required"])
        self.assertTrue(_has_failure(result, "Claude CLI packet review is required"), result["failures"])

    def test_high_critical_claude_review_without_pr_bound_input_blocks(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["pr"]["reviews"] = []
        evidence = _external(prompt_includes_diff=True, prompt_transmitted=True)
        evidence.pop("review_input")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review_input is missing"), result["failures"])

    def test_high_critical_claude_review_with_wrong_bound_diff_blocks(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["pr"]["reviews"] = []
        evidence = _external()
        evidence["review_input"] = {
            "mode": gate.CLAUDE_CLI_REVIEW_INPUT_MODE,
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "diff_sha256": "f" * 64,
        }
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review_input.diff_sha256 mismatch"), result["failures"])

    def test_high_critical_change_with_claude_cli_review_passes(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["pr"]["reviews"] = []
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_external(),
        )
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["claude_cli_required"])
        self.assertEqual(result["review_sources"]["external_reviews_received"], 1)

    def test_claude_packet_command_with_unknown_flag_blocks(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external()
        review = dict(evidence["reviews"][0])
        review["command"] = [*_packet_command(), "--extra"]
        evidence["reviews"] = [review]
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "allowed Claude packet-review command"), result["failures"])

    def test_claude_packet_command_requires_exact_schema(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external()
        review = dict(evidence["reviews"][0])
        command = _packet_command()
        command[5] = json.dumps({"type": "object"})
        review["command"] = command
        evidence["reviews"] = [review]
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "allowed Claude packet-review command"), result["failures"])

    def test_claude_packet_review_requires_opus_and_high_effort(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external(reviews=[_claude_review(model="sonnet", effort="medium")])
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "model is not opus"), result["failures"])
        self.assertTrue(_has_failure(result, "effort is not high"), result["failures"])

    def test_claude_packet_review_requires_tools_disabled_and_safe_mode(self) -> None:
        state = _state("src/runtime_boundary.py")
        unsafe_command = _packet_command()
        unsafe_command[6] = "--tools=Bash"
        unsafe_command.remove("--safe-mode")
        evidence = _external(reviews=[_claude_review(command=unsafe_command)])
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "allowed Claude packet-review command"), result["failures"])

    def test_claude_packet_review_requires_stdin_hash_binding(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external(reviews=[_claude_review(stdin_sha256="f" * 64)])
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "stdin_sha256 does not match"), result["failures"])

    def test_claude_packet_review_requires_prompt_and_transport_binding(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external()
        evidence["review_input"] = {
            **evidence["review_input"],
            "packet_prompt_sha256": "not-a-sha",
            "prompt_sha256": "f" * 64,
            "transport": "argv",
        }
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "packet_prompt_sha256"), result["failures"])
        self.assertTrue(_has_failure(result, "review_input.prompt_sha256 mismatch"), result["failures"])
        self.assertTrue(_has_failure(result, "transport is not stdin"), result["failures"])

    def test_claude_packet_review_requires_transmitted_diff_prompt(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external(prompt_transmitted=False, prompt_includes_diff=False)
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "prompt_transmitted must be true"), result["failures"])
        self.assertTrue(_has_failure(result, "prompt_includes_diff must be true"), result["failures"])

    def test_claude_pass_with_findings_blocks_forged_evidence(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external(reviews=[_claude_review(verdict="PASS", finding_count=1)])
        evidence["findings"] = [_terminal_external_finding()]
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "PASS Claude review must have finding_count 0"), result["failures"])

    def test_chatgpt_alone_does_not_satisfy_weltgewebe_lane(self) -> None:
        state = _state("src/tiny_feature.py")
        state["repoName"] = "heimgewebe/weltgewebe"
        self_review = _self_review(path="src/tiny_feature.py")
        self_review["repo"] = "heimgewebe/weltgewebe"
        evidence = _external(
            repo="heimgewebe/weltgewebe",
            reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}],
        )
        result = gate.evaluate_review_gate(state, self_review=self_review, external_review_evidence=evidence)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "Claude CLI packet review is required"), result["failures"])

    def test_legacy_claude_evidence_cannot_bypass_packet_requirement(self) -> None:
        state = _state("src/runtime_boundary.py")
        legacy = {
            "schema_version": 1,
            "kind": "claude_ultrareview",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "expected_head_sha": HEAD,
            "tool": "claude-code",
            "tool_version": "2.1.206",
            "command": ["claude", "ultrareview", "7", "--json", "--timeout", "30"],
            "exit_code": 0,
            "json_ok": True,
            "verdict": "PASS",
            "finding_count": 0,
            "findings_triaged": True,
            "stdout_sha256": REVIEW_SHA,
            "stderr_sha256": REVIEW_SHA,
        }
        evidence = _external(
            reviews=[{"source": "chatgpt", "review_sha256": REVIEW_SHA, "verdict": "PASS", "finding_count": 0}]
        )
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            claude_evidence=legacy,
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "Claude CLI packet review is required"), result["failures"])

    def test_weltgewebe_policy_survives_canonical_repo_forms(self) -> None:
        state = _state("src/tiny_feature.py")
        state["repoName"] = "HTTPS://GITHUB.COM/Heimgewebe/Weltgewebe.git"
        self_review = _self_review(path="src/tiny_feature.py")
        self_review["repo"] = "heimgewebe/weltgewebe"
        result = gate.evaluate_review_gate(state, self_review=self_review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(result["complexity"]["important_repo"])
        self.assertTrue(result["review_sources"]["claude_cli_required"])

    def test_valid_policy_waiver_replaces_only_claude_provider_requirement(self) -> None:
        state = _state("src/runtime_boundary.py")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_generic_external(),
            policy_waiver=_policy_waiver(),
        )
        self.assertEqual(result["verdict"], "PASS", result["failures"])
        self.assertTrue(result["review_sources"]["claude_cli_required"])
        self.assertTrue(result["review_sources"]["claude_cli_waived"])
        self.assertTrue(result["policy_waiver"]["valid"])
        self.assertTrue(result["policy_waiver"]["applied"])
        self.assertEqual(result["policy_waiver"]["evidence"]["audit_reference"], "test://waiver/7")

    def test_policy_waiver_does_not_remove_external_review_requirement(self) -> None:
        state = _state("src/runtime_boundary.py")
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            policy_waiver=_policy_waiver(),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "external review is required"), result["failures"])

    def test_expired_policy_waiver_blocks(self) -> None:
        state = _state("src/runtime_boundary.py")
        now = datetime.now(timezone.utc)
        waiver = _policy_waiver(
            issued_at=(now - timedelta(hours=2)).isoformat(),
            expires_at=(now - timedelta(hours=1)).isoformat(),
        )
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_generic_external(),
            policy_waiver=waiver,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "waiver is expired"), result["failures"])
        self.assertFalse(result["review_sources"]["claude_cli_waived"])

    def test_policy_waiver_is_head_and_diff_bound(self) -> None:
        state = _state("src/runtime_boundary.py")
        waiver = _policy_waiver(head_sha="b" * 40, diff_sha256="f" * 64)
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_generic_external(),
            policy_waiver=waiver,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "head_sha mismatch"), result["failures"])
        self.assertTrue(_has_failure(result, "diff_sha256 mismatch"), result["failures"])

    def test_policy_waiver_rejects_unknown_fields_and_long_lifetime(self) -> None:
        state = _state("src/runtime_boundary.py")
        now = datetime.now(timezone.utc)
        waiver = _policy_waiver(
            expires_at=(now + timedelta(hours=25)).isoformat(),
            hidden_fallback=True,
        )
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_generic_external(),
            policy_waiver=waiver,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "unknown field(s): hidden_fallback"), result["failures"])
        self.assertTrue(_has_failure(result, "lifetime exceeds 24 hours"), result["failures"])

    def test_invalid_repo_identity_blocks_gate_explicitly(self) -> None:
        state = _state("src/runtime_boundary.py")
        state["repoName"] = "not a repository"
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=_external(),
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "repository identity could not be canonicalized"), result["failures"])

    def test_write_external_review_packet_rejects_invalid_repo_identity(self) -> None:
        state = _state("README.md")
        state["repoName"] = "not a repository"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(gate.GateInputError, "valid repo name"):
                gate.write_external_review_packet(Path(directory) / "packet", state, b"diff")

    def test_write_external_review_packet_absolutizes_relative_output_dir(self) -> None:
        state = _state("README.md")
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            try:
                packet = gate.write_external_review_packet(Path("packet"), state, b"diff bytes")
            finally:
                os.chdir(previous)
            manifest = json.loads(Path(packet["manifest_path"]).read_text(encoding="utf-8"))
            self.assertTrue(Path(manifest["diff_path"]).is_absolute())
            self.assertTrue(Path(manifest["prompt_path"]).is_absolute())
            self.assertTrue(Path(manifest["diff_path"]).is_file())
            self.assertTrue(Path(manifest["prompt_path"]).is_file())

    def test_packet_prompt_hash_is_recomputed_by_gate(self) -> None:
        state = _state("src/runtime_boundary.py")
        evidence = _external()
        evidence["review_input"] = {**evidence["review_input"], "packet_prompt_sha256": "f" * 64}
        result = gate.evaluate_review_gate(
            state,
            self_review=_self_review(path="src/runtime_boundary.py"),
            external_review_evidence=evidence,
        )
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertTrue(_has_failure(result, "review_input.packet_prompt_sha256 mismatch"), result["failures"])

    def test_write_external_review_packet_creates_downloadable_diff_and_template(self) -> None:
        state = _state("src/feature.py")
        state["pr"]["title"] = "feat: example"
        patch_text = "diff header\n+example\n".encode("utf-8")
        with tempfile.TemporaryDirectory() as tmpdir:
            packet = gate.write_external_review_packet(Path(tmpdir), state, patch_text)
            diff_path = Path(packet["diff_path"])
            prompt_path = Path(packet["prompt_path"])
            evidence_path = Path(packet["evidence_template_path"])
            manifest_path = Path(packet["manifest_path"])
            self.assertEqual(diff_path.read_bytes(), patch_text)
            self.assertTrue(prompt_path.read_text(encoding="utf-8").startswith("You are an external LLM reviewer."))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["diff_sha256"], gate._sha256_bytes(patch_text))
            self.assertEqual(evidence["prompt_sha256"], packet["prompt_sha256"])
            self.assertTrue(manifest_path.is_file())

    def test_write_self_review_template_creates_non_passing_scaffold(self) -> None:
        state = _state("src/feature.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            result = gate.write_self_review_template(path, state)
            template = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(result["kind"], "self_review_template")
            self.assertEqual(template["schema_version"], 1)
            self.assertEqual(template["kind"], "grabowski_self_review")
            self.assertEqual(template["repo"], "heimgewebe/grabowski")
            self.assertEqual(template["pr"], 7)
            self.assertEqual(template["head_sha"], HEAD)
            self.assertEqual(template["diff_sha256"], DIFF_SHA)
            self.assertEqual(template["reviewed_files"], ["src/feature.py"])
            self.assertEqual(template["review_focus"], ["correctness", "regression_risk", "tests", "security", "integration"])
            self.assertFalse(template["diff_reviewed"])
            self.assertEqual(template["verdict"], "PASS|NEEDS_CHANGE|BLOCK")
            self.assertEqual(template["review_iterations"], [])
            self.assertFalse(template["all_findings_triaged"])

    def test_write_self_review_template_requires_repo_name(self) -> None:
        state = _state("src/feature.py")
        state.pop("repoName")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            with self.assertRaisesRegex(gate.GateInputError, "cannot write self-review template without repo name"):
                gate.write_self_review_template(path, state)

    def test_write_self_review_template_requires_complete_file_list(self) -> None:
        state = _state("src/feature.py")
        state["pr"]["files"] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            with self.assertRaisesRegex(gate.GateInputError, "complete current PR file list"):
                gate.write_self_review_template(path, state)

    def test_write_self_review_template_rejects_incomplete_file_list(self) -> None:
        state = _state("src/feature.py")
        state["pr"]["changedFiles"] = 2
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            with self.assertRaisesRegex(gate.GateInputError, "current PR file list is incomplete"):
                gate.write_self_review_template(path, state)

    def test_write_self_review_template_refuses_to_overwrite_existing_file(self) -> None:
        state = _state("src/feature.py")
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            path.write_text("existing", encoding="utf-8")
            with self.assertRaisesRegex(gate.GateInputError, "self-review template already exists"):
                gate.write_self_review_template(path, state)
            self.assertEqual(path.read_text(encoding="utf-8"), "existing")

    def test_write_self_review_template_requires_current_diff_hash(self) -> None:
        state = _state("src/feature.py", diff_sha=None)
        state["pr_diff_error"] = "gh pr diff failed"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "self-review-template.json"
            with self.assertRaisesRegex(gate.GateInputError, "cannot write self-review template without current PR diff SHA-256: gh pr diff failed"):
                gate.write_self_review_template(path, state)


if __name__ == "__main__":
    unittest.main()
