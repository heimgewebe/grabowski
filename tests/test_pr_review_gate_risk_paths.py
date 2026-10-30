from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_risk_paths_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


def _state(path: str) -> dict:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 58,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": "CLEAN",
            "mergeable": "MERGEABLE",
            "headRefOid": HEAD,
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 3,
            "deletions": 1,
            "files": [{"path": path, "changeType": "MODIFIED"}],
            "reviews": [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
        "reviewComments": [],
    }


def _self_review(path: str) -> dict:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 58,
        "head_sha": HEAD,
        "base_sha": BASE,
        "reviewed_files": [path],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
            "material_findings_after_first_review": 0,
            "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "claimed small diff"},
    }


class PrReviewGateRiskPathExpansionTests(unittest.TestCase):
    def test_mutating_runtime_support_modules_require_deep_self_review(self) -> None:
        for path in (
            "src/grabowski_tasks.py",
            "src/grabowski_checkouts.py",
            "src/grabowski_physical_checkout.py",
            "src/grabowski_agent_role.py",
            "src/grabowski_operations.py",
            "src/grabowski_artifacts.py",
            "src/grabowski_merge_guard.py",
            "src/grabowski_decision_reviews.py",
            "src/grabowski_release_admission.py",
        ):
            with self.subTest(path=path):
                result = pr_review_gate.evaluate_review_gate(_state(path), self_review=_self_review(path))
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertTrue(result["complexity"]["high_critical"])
                self.assertTrue(
                    any("high-critical Grabowski operator path touched" in reason for reason in result["complexity"]["reasons"]),
                    result["complexity"]["reasons"],
                )
                self.assertEqual(result["complexity"]["minimum_self_review_iterations"], 5)
                self.assertTrue(
                    any("minimum 5" in failure for failure in result["failures"]),
                    result["failures"],
                )
                self.assertFalse(result["review_sources"]["external_review_required"])
                self.assertFalse(result["review_sources"]["independent_review_required"])
                self.assertFalse(result["complexity"]["independent_review_required"])

    def test_dot_github_workflows_and_actions_require_high_critical_review(self) -> None:
        # The real heim-pc #225 GitHub changed-file path begins with a dot.
        # str.lstrip("./") must not strip that dot or downgrade CI authority.
        for path in (
            ".github/workflows/heim-pc-nix-cache-publish.yml",
            "./.github/workflows/ci.yml",
            ".github/actions/identity/action.yml",
        ):
            with self.subTest(path=path):
                state = _state(path)
                complexity = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name="heimgewebe/heim-pc"
                )
                self.assertEqual("high_critical", complexity["review_tier"])
                self.assertFalse(complexity["independent_review_required"])
                self.assertGreaterEqual(complexity["minimum_self_review_iterations"], 5)
                self.assertTrue(
                    any("high-critical path touched" in reason
                        for reason in complexity["high_critical_reasons"]),
                    complexity["high_critical_reasons"],
                )
                self.assertEqual(
                    "BLOCK",
                    pr_review_gate.evaluate_review_gate(
                        state, self_review=_self_review(path)
                    )["verdict"],
                    "a one-pass standard self-review cannot satisfy this gate",
                )

    def test_dot_github_lookalikes_are_not_silently_rewritten(self) -> None:
        for path in (
            "github/workflows/ci.yml",
            ".githubish/workflows/ci.yml",
            "/.github/workflows/ci.yml",
            "../../.github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                complexity = pr_review_gate.classify_complexity(
                    _state(path)["pr"], None, repo_name="heimgewebe/heim-pc"
                )
                self.assertFalse(complexity["high_critical"], complexity)

    def test_renamed_critical_source_paths_remain_high_critical(self) -> None:
        # GitHub supplies both path (destination) and previousPath (source).
        # A rename out of .github must not look like documentation-only work.
        for previous in (
            ".github/workflows/ci.yml",
            ".github/actions/identity/action.yml",
        ):
            with self.subTest(previous=previous):
                state = _state("docs/ci.md")
                state["repoName"] = "heimgewebe/heim-pc"
                state["pr"]["files"] = [
                    {"path": "docs/ci.md", "status": "renamed", "previousPath": previous}
                ]
                complexity = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertEqual("high_critical", complexity["review_tier"])
                self.assertFalse(complexity["independent_review_required"])
                self.assertTrue(any(previous in reason for reason in
                                    complexity["high_critical_reasons"]))
                paths, failures = pr_review_gate._current_pr_paths_failures(state["pr"])
                self.assertEqual(["docs/ci.md"], paths)
                self.assertEqual([], failures)
                self.assertEqual("BLOCK", pr_review_gate.evaluate_review_gate(
                    state, self_review=_self_review("docs/ci.md")
                )["verdict"])

    def test_renamed_previous_filename_fallback_is_security_relevant(self) -> None:
        state = _state("docs/ci.md")
        state["repoName"] = "heimgewebe/heim-pc"
        state["pr"]["files"] = [{
            "path": "docs/ci.md", "status": "renamed",
            "previous_filename": ".github/workflows/ci.yml",
        }]
        result = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertEqual("high_critical", result["review_tier"])
        self.assertFalse(result["independent_review_required"])

    def test_renamed_missing_or_invalid_source_fails_closed(self) -> None:
        for previous in (None, "", 42, "/.github/workflows/ci.yml",
                         "../.github/workflows/ci.yml"):
            with self.subTest(previous=previous):
                state = _state("docs/ci.md")
                state["repoName"] = "heimgewebe/heim-pc"
                item = {"path": "docs/ci.md", "status": "renamed"}
                if previous is not None:
                    item["previousPath"] = previous
                state["pr"]["files"] = [item]
                _, failures = pr_review_gate._current_pr_paths_failures(state["pr"])
                self.assertTrue(any("renamed source path" in failure
                                    for failure in failures), failures)
                complexity = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertFalse(complexity["independent_review_required"])
                result = pr_review_gate.evaluate_review_gate(
                    state, self_review=_self_review("docs/ci.md")
                )
                self.assertEqual("BLOCK", result["verdict"])
                self.assertTrue(any("renamed source path" in failure
                                    for failure in result["failures"]), result["failures"])

    def test_benign_documentation_rename_keeps_documentation_tier(self) -> None:
        state = _state("docs/new.md")
        state["repoName"] = "heimgewebe/example"
        state["pr"]["files"] = [{
            "path": "docs/new.md", "status": "renamed",
            "previousPath": "docs/old.md",
        }]
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertEqual("documentation", complexity["review_tier"])
        self.assertFalse(complexity["independent_review_required"])
        self.assertEqual([], pr_review_gate._current_pr_paths_failures(state["pr"])[1])

    def test_unrelated_plain_python_module_keeps_standard_review_floor(self) -> None:
        state = _state("src/grabowski_plain_helper.py")
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertFalse(complexity["high_critical"])
        self.assertFalse(complexity["independent_review_required"])

    def test_documentation_does_not_gain_independent_review_floor(self) -> None:
        state = _state("docs/usage.md")
        state["repoName"] = "heimgewebe/example"
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )

        self.assertEqual("documentation", complexity["review_tier"])
        self.assertFalse(complexity["independent_review_required"])
        self.assertFalse(complexity["external_review_required"])

    def test_self_review_audit_transports_independent_review_policy(self) -> None:
        state = _state("src/grabowski_physical_checkout.py")
        state["pr_diff_sha256"] = "0" * 64
        complexity = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        review = _self_review("src/grabowski_physical_checkout.py")
        review["review_iterations"] = [
            {"n": index, "summary": "reviewed", "material_findings": 0}
            for index in range(1, complexity["minimum_self_review_iterations"] + 1)
        ]
        result = {
            "complexity": complexity,
            "review_sources": {"self_review_gate_valid": True},
        }

        audit = pr_review_gate.build_self_review_audit(state, result, review)

        self.assertEqual("high_critical", audit["review_tier"])
        self.assertFalse(audit["independent_review_required"])
        self.assertEqual(HEAD, audit["head_sha"])
        self.assertEqual(BASE, audit["base_sha"])
        self.assertEqual("0" * 64, audit["diff_sha256"])


    def test_heim_pc_nixos_production_input_paths_require_high_critical_review(self) -> None:
        for path in (
            "flake.lock",
            "flake.nix",
            "nixos/system/flake.nix",
            "nixos/production/trust-contract-v1.json",
            "./nixos/production/trust-contract-v1.json",
        ):
            with self.subTest(path=path):
                state = _state(path)
                state["repoName"] = "heimgewebe/heim-pc"
                complexity = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertTrue(complexity["high_critical"], complexity)
                self.assertEqual("high_critical", complexity["review_tier"])
                self.assertFalse(complexity["independent_review_required"])
                self.assertFalse(complexity["very_small_uncomplicated"])
                self.assertGreaterEqual(complexity["minimum_self_review_iterations"], 5)
                self.assertTrue(
                    any("NixOS supply-chain source" in reason for reason in complexity["reasons"]),
                    complexity["reasons"],
                )

    def test_exact_heim_pc_pr228_production_trust_transition_is_high_critical(self) -> None:
        state = _state("flake.lock")
        state["repoName"] = "heimgewebe/heim-pc"
        paths = [
            "flake.lock",
            "flake.nix",
            "nixos/production/trust-contract-v1.json",
            "nixos/system/flake.nix",
            "tests/test_nixos_system_source.py",
        ]
        state["pr"]["files"] = [{"path": path, "changeType": "MODIFIED"} for path in paths]
        state["pr"]["changedFiles"] = len(paths)
        state["pr"]["additions"] = 20
        state["pr"]["deletions"] = 5
        classified = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertEqual("high_critical", classified["review_tier"])
        self.assertFalse(classified["independent_review_required"])
        self.assertTrue(any(
            "NixOS supply-chain source" in reason for reason in classified["high_critical_reasons"]
        ))

    def test_nix_trust_path_rules_are_repo_scoped_and_do_not_match_lookalikes(self) -> None:
        for path in (
            "docs/flake.lock",
            "flake.lock.example",
            "flake.nix.bak",
            "nixos/production/trust-contract-v1.json.bak",
            "docs/nixos/production/trust-contract-v1.json",
            "../nixos/production/trust-contract-v1.json",
            "tests/test_nixos_system_source.py",
        ):
            with self.subTest(path=path):
                state = _state(path)
                state["repoName"] = "heimgewebe/heim-pc"
                classified = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertFalse(classified["high_critical"], classified)
        for path in ("flake.lock", "nixos/production/trust-contract-v1.json"):
            with self.subTest(other_repo_path=path):
                state = _state(path)
                state["repoName"] = "heimgewebe/example-repo"
                classified = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertFalse(classified["high_critical"], classified)


    def test_nix_trust_rename_out_of_source_requires_deep_self_review(self) -> None:
        protected = (
            "flake.lock",
            "flake.nix",
            "nixos/system/flake.nix",
            "nixos/production/trust-contract-v1.json",
        )
        for old_path in protected:
            for old_field in ("previous_filename", "previousFilename", "previousPath"):
                with self.subTest(source=old_path, field=old_field):
                    state = _state("docs/benign.md")
                    state["repoName"] = "heimgewebe/heim-pc"
                    state["pr"]["files"] = [
                        {"path": "docs/benign.md", "changeType": "RENAMED", old_field: old_path}
                    ]
                    result = pr_review_gate.classify_complexity(
                        state["pr"], None, repo_name=state["repoName"]
                    )
                    self.assertTrue(result["high_critical"], result)
                    self.assertFalse(result["independent_review_required"])
                    self.assertFalse(result["docs_only"])
                    self.assertTrue(any(
                        "NixOS supply-chain source" in reason for reason in result["reasons"]
                    ), result["reasons"])

    def test_nix_trust_rename_without_source_or_unknown_type_blocks(self) -> None:
        for entry in (
            {"path": "docs/innocent.md", "changeType": "RENAMED"},
            {"path": "docs/innocent.md", "status": "renamed", "previous_filename": ""},
            {"path": "docs/innocent.md"},
            {"path": "docs/innocent.md", "changeType": "UNKNOWN"},
        ):
            with self.subTest(entry=entry):
                state = _state("docs/innocent.md")
                state["repoName"] = "heimgewebe/heim-pc"
                state["pr"]["files"] = [entry]
                result = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertEqual("high_critical", result["review_tier"], result)
                self.assertFalse(result["independent_review_required"])

    def test_nix_trust_rename_metadata_incomplete_list_is_fail_closed(self) -> None:
        state = _state("docs/benign.md")
        state["repoName"] = "heimgewebe/heim-pc"
        state["pr"]["files"] = [{"path": "docs/benign.md", "changeType": "MODIFIED"}]
        state["pr"]["changedFiles"] = 2
        result = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertTrue(result["high_critical"])
        self.assertFalse(result["independent_review_required"])

    def test_nix_trust_conflicting_change_file_aliases_fail_closed(self) -> None:
        # A protected source must not be hidden behind a benign first alias.
        examples = (
            {"path": "docs/new.md", "filename": "flake.lock", "changeType": "MODIFIED"},
            {"path": "docs/new.md", "filename": "", "changeType": "MODIFIED"},
            {"path": "docs/new.md", "changeType": "RENAMED",
             "previous_filename": "docs/old.md", "previousPath": "flake.lock"},
            {"path": "docs/new.md", "changeType": "RENAMED",
             "previous_filename": "docs/old.md", "previousFilename": "flake.lock"},
            {"path": "docs/new.md", "changeType": "RENAMED",
             "previous_filename": "docs/old.md", "previousPath": "docs/other.md"},
            {"path": "docs/new.md", "changeType": "RENAMED",
             "previous_filename": "docs/old.md", "previousPath": ""},
            {"path": "docs/new.md", "changeType": "RENAMED",
             "previous_filename": "docs/old.md", "previousPath": 123},
            {"path": "docs/new.md", "changeType": "MODIFIED", "status": "RENAMED"},
            {"path": "docs/new.md", "changeType": "RENAMED", "status": "MODIFIED",
             "previous_filename": "docs/old.md"},
            {"path": "docs/new.md", "changeType": "MODIFIED", "previousPath": ""},
            {"filename": "docs/new.md", "changeType": "RENAMED", "previousPath": "flake.lock"},
        )
        for entry in examples:
            with self.subTest(entry=entry):
                state = _state("docs/new.md")
                state["repoName"] = "heimgewebe/heim-pc"
                state["pr"]["files"] = [entry]
                result = pr_review_gate.classify_complexity(
                    state["pr"], None, repo_name=state["repoName"]
                )
                self.assertEqual("high_critical", result["review_tier"], result)
                self.assertFalse(result["independent_review_required"])

    def test_nix_trust_consistent_duplicate_aliases_remain_documentation(self) -> None:
        state = _state("docs/new.md")
        state["repoName"] = "heimgewebe/heim-pc"
        state["pr"]["files"] = [{
            "path": "docs/new.md", "filename": "docs/new.md",
            "changeType": "RENAMED", "status": "renamed",
            "previous_filename": "docs/old.md",
            "previousFilename": "docs/old.md", "previousPath": "docs/old.md",
        }]
        result = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertEqual("documentation", result["review_tier"], result)

    def test_unrelated_documentation_rename_remains_documentation_tier(self) -> None:
        state = _state("docs/new.md")
        state["repoName"] = "heimgewebe/heim-pc"
        state["pr"]["files"] = [
            {"path": "docs/new.md", "changeType": "RENAMED", "previousPath": "docs/old.md"}
        ]
        result = pr_review_gate.classify_complexity(
            state["pr"], None, repo_name=state["repoName"]
        )
        self.assertEqual("documentation", result["review_tier"], result)
        self.assertFalse(result["independent_review_required"])


if __name__ == "__main__":
    unittest.main()
