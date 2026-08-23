from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40
BASE = "b" * 40
DIFF_SHA = "c" * 64
FRESHNESS = "registry-registration-preflight/freshness"


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "grabowski_pr_review_gate_trusted_actors_test",
        ROOT / "tools" / "pr_review_gate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pr_review_gate = _load_gate()


def _self_review(*, reviewed_files: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review",
        "review_mode": "critical_diff_review",
        "verdict": "PASS",
        "repo": "heimgewebe/grabowski",
        "pr": 58,
        "head_sha": HEAD,
        "base_sha": BASE,
        "reviewed_files": reviewed_files or ["docs/low_risk_note.md"],
        "review_focus": ["correctness", "regression_risk", "tests", "security", "integration"],
        "diff_sha256": DIFF_SHA,
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [
            {"n": 1, "summary": "reviewed correctness", "material_findings": 0},
            {"n": 2, "summary": "reviewed integration", "material_findings": 0},
        ],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
            "material_findings_after_first_review": 0,
            "uncertainty": 0.1,
        "claude_review": {"required": False, "reason": "small low-risk diff"},
    }


def _state(*, actor: str = "chatgpt-codex-connector", merge_state: str = "CLEAN", mergeable: str = "MERGEABLE") -> dict:
    return {
        "repoName": "heimgewebe/grabowski",
        "pr": {
            "number": 58,
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": merge_state,
            "mergeable": mergeable,
            "headRefName": "feature/test",
            "headRefOid": HEAD,
            "baseRefName": "main",
            "baseRefOid": BASE,
            "changedFiles": 1,
            "additions": 1,
            "deletions": 0,
            "pullFilesEvidenceComplete": True,
            "files": [{"path": "docs/low_risk_note.md", "status": "modified"}],
            "reviews": [{"author": {"login": actor}, "commit_id": HEAD}],
            "latestReviews": [],
            "comments": [],
        },
        "checks": [{"bucket": "pass", "name": "validate (3.10)"}, {"bucket": "pass", "name": "validate (3.12)"}],
        "reviewComments": [],
        "pr_diff_sha256": DIFF_SHA,
    }


def _registry_state(*, include_non_registry: bool = False) -> tuple[dict, list[str]]:
    state = _state()
    paths = ["registry/tasks/TEST-BASE-BOUND.json"]
    if include_non_registry:
        paths.insert(0, "docs/low_risk_note.md")
    state["pr"]["files"] = [{"path": path, "status": "modified"} for path in paths]
    state["pr"]["changedFiles"] = len(paths)
    return state, paths


class PrReviewGateTrustedActorsTests(unittest.TestCase):
    def test_expected_checks_support_test_job_python_matrix(self) -> None:
        workflow = """jobs:
  test:
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
"""
        with mock.patch.object(
            pr_review_gate, "_required_check_catalog_text_at_revision", return_value=None
        ), mock.patch.object(
            pr_review_gate, "_workflow_text_at_revision", return_value=workflow
        ):
            result = pr_review_gate.expected_check_names_for_repo(
                Path("/tmp"),
                repo_name="heimgewebe/reposkop",
                head_sha=HEAD,
                base_sha=BASE,
            )

        self.assertEqual(
            result,
            ("test (3.10)", "test (3.11)", "test (3.12)", "test (3.13)"),
        )

    def test_unparsed_validate_job_blocks_before_test_fallback(self) -> None:
        workflow = """jobs:
  validate:
    strategy: {matrix: {python-version: ["3.11"]}}
  test:
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]
"""
        with mock.patch.object(
            pr_review_gate, "_required_check_catalog_text_at_revision", return_value=None
        ), mock.patch.object(
            pr_review_gate, "_workflow_text_at_revision", return_value=workflow
        ):
            with self.assertRaisesRegex(
                pr_review_gate.GateInputError, "not unambiguously parseable"
            ):
                pr_review_gate.expected_check_names_for_repo(
                    Path("/tmp"),
                    repo_name="heimgewebe/example",
                    head_sha=HEAD,
                    base_sha=BASE,
                )

    def test_validate_matrix_alias_blocks_before_test_fallback(self) -> None:
        workflow = """x-python-matrix: &python-matrix
  python-version: ["3.11"]
jobs:
  validate:
    strategy:
      matrix: *python-matrix
  test:
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]
"""
        with mock.patch.object(
            pr_review_gate, "_required_check_catalog_text_at_revision", return_value=None
        ), mock.patch.object(
            pr_review_gate, "_workflow_text_at_revision", return_value=workflow
        ):
            with self.assertRaisesRegex(
                pr_review_gate.GateInputError, "not unambiguously parseable"
            ):
                pr_review_gate.expected_check_names_for_repo(
                    Path("/tmp"),
                    repo_name="heimgewebe/example",
                    head_sha=HEAD,
                    base_sha=BASE,
                )

    def test_validate_job_remains_preferred_over_test_job(self) -> None:
        workflow = """jobs:
  test:
    strategy:
      matrix:
        python-version: ["3.9"]
  validate:
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]
"""
        with mock.patch.object(
            pr_review_gate, "_required_check_catalog_text_at_revision", return_value=None
        ), mock.patch.object(
            pr_review_gate, "_workflow_text_at_revision", return_value=workflow
        ):
            result = pr_review_gate.expected_check_names_for_repo(
                Path("/tmp"),
                repo_name="heimgewebe/example",
                head_sha=HEAD,
                base_sha=BASE,
            )

        self.assertEqual(result, ("validate (3.10)", "validate (3.12)"))

    def test_merge_state_status_must_be_clean(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_state(merge_state="BLOCKED"), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeStateStatus is BLOCKED, not CLEAN", result["failures"])


    def test_mergeable_must_be_mergeable(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_state(mergeable="UNKNOWN"), self_review=_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeable is UNKNOWN, not MERGEABLE", result["failures"])

    def test_unstable_merge_state_passes_when_only_codex_diagnostic_is_non_green(self) -> None:
        state = _state(merge_state="UNSTABLE")
        state["checks"].extend(
            [
                {"bucket": "cancel", "name": "Codex review settled"},
                {"bucket": "pending", "name": "Codex review settled"},
            ]
        )

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "PASS")
        self.assertNotIn("2 non-green check(s)", result["failures"])
        self.assertIn(
            "GitHub mergeStateStatus UNSTABLE is attributable only to non-blocking diagnostic review status checks",
            result["warnings"],
        )

    def test_unstable_merge_state_without_non_green_diagnostic_still_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(
            _state(merge_state="UNSTABLE"),
            self_review=_self_review(),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeStateStatus is UNSTABLE, not CLEAN", result["failures"])

    def test_unstable_merge_state_with_other_non_green_check_still_blocks(self) -> None:
        state = _state(merge_state="UNSTABLE")
        state["checks"].extend(
            [
                {"bucket": "pending", "name": "Codex review settled"},
                {"bucket": "fail", "name": "claude"},
            ]
        )

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])
        self.assertIn("GitHub mergeStateStatus is UNSTABLE, not CLEAN", result["failures"])

    def test_optional_skipped_check_does_not_block_when_expected_checks_pass(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "claude"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "PASS")

    def test_skipped_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"] = [
            {"bucket": "skipping", "name": "validate (3.10)"},
            {"bucket": "pass", "name": "validate (3.12)"},
        ]

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.10)",
            result["failures"],
        )

    def test_non_registry_freshness_check_does_not_require_base_sha_link(self) -> None:
        state = _state()
        state["checks"].append(
            {
                "bucket": "pass",
                "name": FRESHNESS,
                "link": "https://github.com/heimgewebe/bureau/actions/runs/1",
            }
        )

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [])

    def test_registry_freshness_check_accepts_exact_current_base_link(self) -> None:
        state, paths = _registry_state()
        state["checks"].append(
            {
                "bucket": "pass",
                "name": FRESHNESS,
                "link": f"https://github.com/heimgewebe/bureau/actions/runs/1?base_sha={BASE}",
            }
        )

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])

    def test_registry_freshness_accepts_exact_external_id_when_github_strips_query(self) -> None:
        state, paths = _registry_state()
        state["checks"].append(
            {
                "bucket": "pass",
                "name": FRESHNESS,
                "link": "https://github.com/heimgewebe/bureau/runs/123",
                "baseBindingEvidence": {
                    "name": FRESHNESS,
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": HEAD,
                    "external_id": f"registry-freshness:58:{HEAD}:{BASE}",
                    "app_slug": "github-actions",
                },
            }
        )

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])

    def test_registry_freshness_external_id_fails_closed_on_wrong_identity_or_app(self) -> None:
        cases = (
            (f"registry-freshness:59:{HEAD}:{BASE}", HEAD, "github-actions"),
            (f"registry-freshness:58:{HEAD}:{BASE}", "d" * 40, "github-actions"),
            (f"registry-freshness:58:{HEAD}:{'e' * 40}", HEAD, "github-actions"),
            (f"registry-freshness:58:{HEAD}:{BASE}", HEAD, "other-app"),
        )
        for external_id, observed_head, app_slug in cases:
            with self.subTest(external_id=external_id, observed_head=observed_head, app_slug=app_slug):
                state, paths = _registry_state()
                state["checks"].append(
                    {
                        "bucket": "pass",
                        "name": FRESHNESS,
                        "link": "https://github.com/heimgewebe/bureau/runs/123",
                        "baseBindingEvidence": {
                            "name": FRESHNESS,
                            "status": "completed",
                            "conclusion": "success",
                            "head_sha": observed_head,
                            "external_id": external_id,
                            "app_slug": app_slug,
                        },
                    }
                )
                result = pr_review_gate.evaluate_review_gate(
                    state,
                    self_review=_self_review(reviewed_files=paths),
                    expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
                )
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn(
                    f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
                    result["failures"],
                )

    def test_registry_freshness_accepts_exact_pull_request_target_workflow_run(self) -> None:
        state, paths = _registry_state()
        state["checks"].append(
            {
                "bucket": "pass",
                "name": FRESHNESS,
                "link": "https://github.com/heimgewebe/grabowski/actions/runs/32619059187/job/97144293316",
                "workflowRunBindingEvidence": {
                    "source": "github-actions-workflow-run",
                    "repository": "heimgewebe/grabowski",
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": HEAD,
                    "path": pr_review_gate.REGISTRY_FRESHNESS_WORKFLOW_PATH,
                    "pull_requests": [
                        {"number": 58, "head_ref": "feature/test", "head_sha": HEAD, "base_ref": "main", "base_sha": BASE}
                    ],
                },
            }
        )

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])

        state["checks"][-1]["workflowRunBindingEvidence"]["head_sha"] = BASE
        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )
        self.assertEqual(result["verdict"], "PASS")

    def test_registry_freshness_workflow_run_fails_closed_on_wrong_identity(self) -> None:
        good = {
            "source": "github-actions-workflow-run",
            "repository": "heimgewebe/grabowski",
            "event": "pull_request_target",
            "status": "completed",
            "conclusion": "success",
            "head_sha": HEAD,
            "path": pr_review_gate.REGISTRY_FRESHNESS_WORKFLOW_PATH,
            "pull_requests": [{"number": 58, "head_ref": "feature/test", "head_sha": HEAD, "base_ref": "main", "base_sha": BASE}],
        }
        cases = (
            {**good, "repository": "other/repo"},
            {**good, "event": "push"},
            {**good, "status": "in_progress"},
            {**good, "conclusion": "failure"},
            {**good, "head_sha": "d" * 40},
            {**good, "path": ".github/workflows/other.yml"},
            {**good, "pull_requests": [{"number": 59, "head_ref": "feature/test", "head_sha": HEAD, "base_ref": "main", "base_sha": BASE}]},
            {**good, "pull_requests": [{"number": 58, "head_ref": "other", "head_sha": HEAD, "base_ref": "main", "base_sha": BASE}]},
            {**good, "pull_requests": [{"number": 58, "head_ref": "feature/test", "head_sha": "d" * 40, "base_ref": "main", "base_sha": BASE}]},
            {**good, "pull_requests": [{"number": 58, "head_ref": "feature/test", "head_sha": HEAD, "base_ref": "dev", "base_sha": BASE}]},
            {**good, "pull_requests": [{"number": 58, "head_ref": "feature/test", "head_sha": HEAD, "base_ref": "main", "base_sha": "e" * 40}]},
        )
        for workflow_evidence in cases:
            with self.subTest(workflow_evidence=workflow_evidence):
                state, paths = _registry_state()
                state["checks"].append(
                    {
                        "bucket": "pass",
                        "name": FRESHNESS,
                        "link": "https://github.com/heimgewebe/grabowski/actions/runs/32619059187/job/97144293316",
                        "workflowRunBindingEvidence": workflow_evidence,
                    }
                )
                result = pr_review_gate.evaluate_review_gate(
                    state,
                    self_review=_self_review(reviewed_files=paths),
                    expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
                )
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn(
                    f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
                    result["failures"],
                )

    def test_github_actions_run_id_is_repo_bound(self) -> None:
        for link in (
            "https://github.com/heimgewebe/bureau/actions/runs/32619059187",
            "https://github.com/heimgewebe/bureau/actions/runs/32619059187/job/97144293316",
        ):
            self.assertEqual(
                pr_review_gate._github_actions_run_id(link, repo_slug="heimgewebe/bureau"),
                32619059187,
            )
        for link in (
            "https://github.com/other/bureau/actions/runs/32619059187/job/97144293316",
            "https://example.com/heimgewebe/bureau/actions/runs/32619059187/job/97144293316",
            "https://github.com/heimgewebe/bureau/runs/97144293316",
            "https://github.com/heimgewebe/bureau/actions/workflows/32619059187",
        ):
            self.assertIsNone(
                pr_review_gate._github_actions_run_id(link, repo_slug="heimgewebe/bureau")
            )

    def test_github_check_run_id_is_repo_bound(self) -> None:
        self.assertEqual(
            pr_review_gate._github_check_run_id(
                "https://github.com/heimgewebe/bureau/runs/97025223152",
                repo_slug="heimgewebe/bureau",
            ),
            97025223152,
        )
        for link in (
            "https://github.com/other/bureau/runs/97025223152",
            "https://example.com/heimgewebe/bureau/runs/97025223152",
            "https://github.com/heimgewebe/bureau/actions/runs/97025223152",
        ):
            self.assertIsNone(
                pr_review_gate._github_check_run_id(link, repo_slug="heimgewebe/bureau")
            )

    def test_any_registry_task_path_keeps_freshness_base_binding_strict(self) -> None:
        state, paths = _registry_state(include_non_registry=True)
        state["checks"].append(
            {
                "bucket": "pass",
                "name": FRESHNESS,
                "link": f"https://github.com/heimgewebe/bureau/actions/runs/1?base_sha={HEAD}",
            }
        )

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_registry_freshness_check_blocks_missing_link(self) -> None:
        state, paths = _registry_state()
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_normalized_registry_task_paths_keep_base_binding_strict(self) -> None:
        for raw_path in (
            "./registry/tasks/X.json",
            " registry/tasks/X.json ",
            "./registry/tasks",
        ):
            with self.subTest(raw_path=raw_path):
                state = _state()
                state["pr"]["files"] = [{"path": raw_path}]
                state["checks"].append({"bucket": "pass", "name": FRESHNESS})

                result = pr_review_gate.evaluate_review_gate(
                    state,
                    self_review=_self_review(reviewed_files=[raw_path]),
                    expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
                )

                self.assertEqual(result["verdict"], "BLOCK")
                self.assertEqual(
                    result["check_policy"]["base_bound_check_names"], [FRESHNESS]
                )
                self.assertIn(
                    f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
                    result["failures"],
                )

    def test_malformed_individual_path_cannot_relax_base_binding(self) -> None:
        state = _state()
        state["pr"]["files"] = [{"path": "docs/../x.md"}]
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=["docs/../x.md"]),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_invalid_or_mismatched_changed_files_count_cannot_relax_binding(self) -> None:
        for changed_files in (True, "1", 2):
            with self.subTest(changed_files=changed_files):
                state = _state()
                state["pr"]["changedFiles"] = changed_files
                state["checks"].append({"bucket": "pass", "name": FRESHNESS})

                result = pr_review_gate.evaluate_review_gate(
                    state,
                    self_review=_self_review(),
                    expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
                )

                self.assertEqual(result["verdict"], "BLOCK")
                self.assertEqual(
                    result["check_policy"]["base_bound_check_names"], [FRESHNESS]
                )
                self.assertIn(
                    f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
                    result["failures"],
                )

    def test_registry_task_rename_out_keeps_base_binding_strict(self) -> None:
        state = _state()
        state["pr"]["files"] = [
            {
                "path": "docs/TEST-BASE-BOUND.json",
                "status": "renamed",
                "previousPath": "registry/tasks/TEST-BASE-BOUND.json",
            }
        ]
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=["docs/TEST-BASE-BOUND.json"]),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_non_registry_rename_can_relax_base_binding(self) -> None:
        state = _state()
        state["pr"]["files"] = [
            {
                "path": "docs/new-name.md",
                "status": "renamed",
                "previousPath": "docs/old-name.md",
            }
        ]
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=["docs/new-name.md"]),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [])

    def test_rename_without_previous_path_cannot_relax_base_binding(self) -> None:
        state = _state()
        state["pr"]["files"] = [{"path": "docs/new-name.md", "status": "renamed"}]
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=["docs/new-name.md"]),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_pull_file_evidence_preserves_rename_preimage_and_rejects_missing_one(self) -> None:
        payload = [
            [
                {
                    "filename": "docs/new-name.md",
                    "status": "renamed",
                    "previous_filename": "registry/tasks/old-name.json",
                },
                {"filename": "docs/other.md", "status": "modified"},
            ]
        ]
        self.assertEqual(
            pr_review_gate._pull_file_evidence(payload),
            [
                {
                    "path": "docs/new-name.md",
                    "status": "renamed",
                    "previousPath": "registry/tasks/old-name.json",
                },
                {"path": "docs/other.md", "status": "modified"},
            ],
        )
        self.assertIsNone(
            pr_review_gate._pull_file_evidence(
                [[{"filename": "docs/new-name.md", "status": "renamed"}]]
            )
        )

    def test_missing_changed_files_count_cannot_relax_base_binding(self) -> None:
        state = _state()
        state["pr"].pop("changedFiles")
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_exact_registry_tasks_path_keeps_base_binding_strict(self) -> None:
        state = _state()
        paths = ["registry/tasks"]
        state["pr"]["files"] = [{"path": paths[0]}]
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(reviewed_files=paths),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_missing_changed_file_evidence_cannot_relax_base_binding(self) -> None:
        state = _state()
        state["pr"]["files"] = []
        state["checks"].append({"bucket": "pass", "name": FRESHNESS})

        result = pr_review_gate.evaluate_review_gate(
            state,
            self_review=_self_review(),
            expected_check_names=("validate (3.10)", "validate (3.12)", FRESHNESS),
        )

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertEqual(result["check_policy"]["base_bound_check_names"], [FRESHNESS])
        self.assertIn(
            f"base-bound expected check(s) stale or unbound for current base: {FRESHNESS}",
            result["failures"],
        )

    def test_optional_failed_check_still_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "fail", "name": "claude"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_non_expected_skipped_check_is_neutral(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "on-demand proof"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "PASS")

    def test_non_green_duplicate_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "fail", "name": "validate (3.10)"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.10)",
            result["failures"],
        )
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_skipped_duplicate_expected_check_blocks(self) -> None:
        state = _state()
        state["checks"].append({"bucket": "skipping", "name": "validate (3.12)"})

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn(
            "expected check(s) missing or non-green: validate (3.12)",
            result["failures"],
        )
        self.assertIn("1 non-green check(s)", result["failures"])

    def test_coding_agent_review_state_is_advisory_but_github_merge_state_still_blocks(self) -> None:
        state = _state(merge_state="BLOCKED")
        state["pr"]["reviews"] = [{"author": {"login": "chatgpt-codex-connector"}, "commit_id": HEAD, "state": "CHANGES_REQUESTED"}]

        result = pr_review_gate.evaluate_review_gate(state, self_review=_self_review())

        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeStateStatus is BLOCKED, not CLEAN", result["failures"])
        self.assertIn("Codex review has advisory blocking state(s): CHANGES_REQUESTED", result["warnings"])
        self.assertFalse(any("Codex review has blocking state" in failure for failure in result["failures"]))

    def test_untrusted_codex_substring_actor_does_not_satisfy_codex_seen_diagnostic(self) -> None:
        state = _state(actor="friendly-codex-bot")
        state["pr_diff_bypass"] = True
        state["pr_diff_bypass_reason"] = "legacy unit seam without live PR diff"
        review = _self_review()
        review["codex_review"] = {"required": True, "reason": "legacy explicit check"}
        result = pr_review_gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(result["review_sources"]["codex_seen"])
        self.assertIn(
            "Deprecated self_review.codex_review.required ignored; external reviews are optional diagnostics",
            result["warnings"],
        )


if __name__ == "__main__":
    unittest.main()
