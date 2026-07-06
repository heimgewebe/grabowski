from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_grips as grips


class FakeGit:
    def __init__(
        self,
        *,
        branch: str = "feat/work",
        dirty: bool = False,
        upstream: str | None = "origin/feat/work",
        head: str = "a" * 40,
        remote_head: str | None = None,
    ):
        self.branch = branch
        self.dirty = dirty
        self.upstream = upstream
        self.head = head
        self.remote_head = remote_head or head
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv == ["rev-parse", "--show-toplevel"]:
            return {"returncode": 0, "stdout": str(repo), "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return {"returncode": 0, "stdout": self.branch, "stderr": ""}
        if argv == ["rev-parse", "HEAD"]:
            return {"returncode": 0, "stdout": self.head, "stderr": ""}
        if argv == ["status", "--short", "--branch"]:
            body = "\n M src/example.py" if self.dirty else ""
            upstream = self.upstream or ""
            return {"returncode": 0, "stdout": f"## {self.branch}...{upstream}{body}", "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
            if self.upstream is None:
                return {"returncode": 128, "stdout": "", "stderr": "no upstream"}
            return {"returncode": 0, "stdout": self.upstream, "stderr": ""}
        if argv == ["push", "origin", f"HEAD:{self.branch}"]:
            return {"returncode": 0, "stdout": "", "stderr": "pushed"}
        if argv == ["ls-remote", "origin", f"refs/heads/{self.branch}"]:
            return {"returncode": 0, "stdout": f"{self.remote_head}\trefs/heads/{self.branch}", "stderr": ""}
        return {"returncode": 1, "stdout": "", "stderr": f"unexpected command: {argv}"}


class FakeGh:
    def __init__(self, *, existing: dict[str, object] | None = None, view: dict[str, object] | None = None):
        self.existing = existing
        self.view = view or {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": False,
            "mergeable": "MERGEABLE",
        }
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv[:2] == ["pr", "list"]:
            return {"returncode": 0, "stdout": json.dumps(self.existing), "stderr": ""}
        if argv[:2] == ["pr", "create"]:
            return {"returncode": 0, "stdout": str(self.view["url"]), "stderr": ""}
        if argv[:2] == ["pr", "edit"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if argv[:2] == ["pr", "view"]:
            return {"returncode": 0, "stdout": json.dumps(self.view), "stderr": ""}
        return {"returncode": 1, "stdout": "", "stderr": f"unexpected gh command: {argv}"}


class GripParserTests(unittest.TestCase):
    def test_parse_worktree_porcelain(self) -> None:
        parsed = grips._parse_worktree_porcelain(
            "worktree /repo/main\n"
            "HEAD aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "branch refs/heads/main\n"
            "worktree /repo/feat path\n"
            "branch refs/heads/feat/x\n"
        )

        self.assertEqual(["/repo/main", "/repo/feat path"], [item["path"] for item in parsed])
        self.assertEqual("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", parsed[0]["head"])
        self.assertEqual("main", parsed[0]["branch"])
        self.assertEqual("feat/x", parsed[1]["branch"])

    def test_parse_worktree_porcelain_preserves_flags_reasons_and_unknowns(self) -> None:
        parsed = grips._parse_worktree_porcelain(
            "worktree /repo/prunable\n"
            "prunable\n"
            "locked needs review\n"
            "bare\n"
            "unknown value\n"
            "worktree /repo/detached\n"
            "detached\n"
            "locked\n"
            "prunable stale reason  \n"
            "unknown value  \n"
        )

        self.assertTrue(parsed[0]["prunable"])
        self.assertEqual("", parsed[0]["prunable_reason"])
        self.assertTrue(parsed[0]["locked"])
        self.assertEqual("needs review", parsed[0]["locked_reason"])
        self.assertTrue(parsed[0]["bare"])
        self.assertEqual(["unknown value"], parsed[0]["unknown_fields"])
        self.assertTrue(parsed[1]["detached"])
        self.assertEqual("", parsed[1]["locked_reason"])
        self.assertEqual("stale reason  ", parsed[1]["prunable_reason"])
        self.assertEqual(["unknown value  "], parsed[1]["unknown_fields"])


class WorktreeOrientReceiptTests(unittest.TestCase):
    def test_worktree_orient_receipt_shape_main_only_has_no_next_pr_grip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {"returncode": 0, "stdout": f"worktree {repo}\nbranch refs/heads/main", "stderr": ""}
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## main", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("worktree-orient", result["receipt"]["grip"]["name"])
        self.assertIn("receipt_sha256", result["receipt"])
        self.assertIn("worktrees", result["output"])
        self.assertNotIn("runtime_matching_worktree", result["output"])
        self.assertEqual(str(repo), result["output"]["canonical_checkout"])
        self.assertEqual("matches requested repo path", result["output"]["canonical_checkout_reason"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])
        self.assertEqual([], result["output"]["cleanup_candidates"])
        self.assertEqual("pass", checks["protected_branches_valid"])
        self.assertEqual("pass", checks["worktree_status_read"])
        self.assertEqual("pass", checks["status_unavailable_count"])
        self.assertEqual("pass", checks["classification_degraded"])

    def test_worktree_orient_does_not_mark_unobservable_clean_or_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            feature = repo / "feature"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {feature}\nbranch refs/heads/feat/x\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"] and _repo == repo:
                    return {"returncode": 0, "stdout": "## main", "stderr": ""}
                if argv == ["status", "--short", "--branch"] and _repo == feature:
                    return {"returncode": 128, "stdout": None, "stderr": "missing worktree"}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([str(feature)], result["output"]["active_feature_worktrees"])
        self.assertEqual([], result["output"]["clean_feature_worktrees"])
        self.assertEqual([str(feature)], result["output"]["unobservable_worktrees"])
        self.assertEqual([], result["output"]["stale_candidates"])
        self.assertEqual([], result["output"]["cleanup_candidates"])
        self.assertIsNone(result["output"]["worktrees"][1]["dirty"])
        self.assertFalse(result["output"]["worktrees"][1]["status_available"])
        self.assertEqual("missing worktree", result["output"]["worktrees"][1]["status_error"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])
        self.assertEqual("warn", checks["worktree_status_read"])
        self.assertEqual("warn", checks["status_unavailable_count"])
        self.assertEqual("warn", checks["classification_degraded"])

    def test_worktree_orient_prunable_unobservable_is_not_cleanup_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            stale = repo / "stale"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {stale}\nbranch refs/heads/feat/stale\nprunable gone\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"] and _repo == repo:
                    return {"returncode": 0, "stdout": "## main", "stderr": ""}
                if argv == ["status", "--short", "--branch"] and _repo == stale:
                    return {"returncode": 128, "stdout": None, "stderr": "missing worktree"}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual([str(stale)], result["output"]["unobservable_worktrees"])
        self.assertEqual([str(stale)], result["output"]["prunable_worktrees"])
        self.assertEqual([], result["output"]["stale_candidates"])
        self.assertEqual([], result["output"]["cleanup_candidates"])
        self.assertIsNone(result["output"]["worktrees"][1]["dirty"])
        self.assertEqual(
            "prunable marker present but status unavailable",
            result["output"]["worktrees"][1]["classification_degraded_reason"],
        )
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])
        self.assertEqual("warn", checks["classification_degraded"])

    def test_worktree_orient_clean_feature_is_readiness_target_not_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            feature = repo / "feature"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {feature}\nbranch refs/heads/feat/x\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual([str(feature)], result["output"]["active_feature_worktrees"])
        self.assertEqual([str(feature)], result["output"]["clean_feature_worktrees"])
        self.assertEqual([], result["output"]["stale_candidates"])
        self.assertEqual([], result["output"]["cleanup_candidates"])
        self.assertEqual(0, result["output"]["cleanup_candidate_count"])
        self.assertEqual("pr-check-readiness", result["output"]["next_safe_grip"]["name"])
        self.assertEqual({"repo": str(feature)}, result["output"]["next_safe_grip"]["parameters"])

    def test_worktree_orient_one_clean_one_dirty_feature_has_no_automatic_next_grip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            clean = repo / "clean"
            dirty = repo / "dirty"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {clean}\nbranch refs/heads/feat/clean\n"
                            f"worktree {dirty}\nbranch refs/heads/feat/dirty\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"] and _repo == dirty:
                    return {"returncode": 0, "stdout": "## feat/dirty\n M src/example.py", "stderr": ""}
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual([str(clean), str(dirty)], result["output"]["active_feature_worktrees"])
        self.assertEqual([str(clean)], result["output"]["clean_feature_worktrees"])
        self.assertEqual([str(dirty)], result["output"]["dirty_worktrees"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])

    def test_worktree_orient_canonical_checkout_prefers_requested_repo_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            other = repo / "other"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {other}\nbranch refs/heads/main\n"
                            f"worktree {repo}\nbranch refs/heads/feat/x\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual(str(repo), result["output"]["canonical_checkout"])
        self.assertEqual("matches requested repo path", result["output"]["canonical_checkout_reason"])

    def test_worktree_orient_canonical_checkout_falls_back_to_first_protected_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            main = repo / "main-checkout"
            feature = repo / "feature"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {feature}\nbranch refs/heads/feat/x\n"
                            f"worktree {main}\nbranch refs/heads/main\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual(str(main), result["output"]["canonical_checkout"])
        self.assertEqual("first protected branch worktree", result["output"]["canonical_checkout_reason"])

    def test_worktree_orient_canonical_checkout_falls_back_to_first_listed_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            other = repo / "other"
            feature = repo / "feature"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {other}\nbranch refs/heads/dev\n"
                            f"worktree {feature}\nbranch refs/heads/feat/x\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip(
                "worktree-orient",
                {"repo": str(repo), "protected_branches": ["main", "master"]},
                command_runner=runner,
            )

        self.assertEqual(str(other), result["output"]["canonical_checkout"])
        self.assertEqual("fallback to first listed worktree", result["output"]["canonical_checkout_reason"])

    def test_worktree_orient_multiple_clean_features_have_no_automatic_next_grip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            first = repo / "first"
            second = repo / "second"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {first}\nbranch refs/heads/feat/a\n"
                            f"worktree {second}\nbranch refs/heads/feat/b\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual([str(first), str(second)], result["output"]["clean_feature_worktrees"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])

    def test_worktree_orient_invalid_protected_branches_block_before_git_worktree_list(self) -> None:
        invalid_values = [
            [],
            [""],
            [" main"],
            ["main "],
            ["main", "main"],
        ]
        for protected in invalid_values:
            with self.subTest(protected=protected):
                with tempfile.TemporaryDirectory() as tmp:
                    repo = Path(tmp)
                    calls: list[list[str]] = []

                    def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                        calls.append(argv)
                        return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

                    result = grips.run_grip(
                        "worktree-orient",
                        {"repo": str(repo), "protected_branches": protected},
                        command_runner=runner,
                    )

                checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertEqual("fail", checks["protected_branches_valid"])
                self.assertEqual([], calls)


class WorktreeOrientCleanupTests(unittest.TestCase):
    def test_prunable_worktrees_are_cleanup_candidates_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            feature = repo / "feature"
            detached = repo / "detached"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\nbranch refs/heads/main\n"
                            f"worktree {feature}\nbranch refs/heads/feat/x\nprunable\n"
                            f"worktree {detached}\ndetached\nprunable old\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip("worktree-orient", {"repo": str(repo)}, command_runner=runner)

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([str(detached)], result["output"]["detached_worktrees"])
        self.assertEqual([str(feature), str(detached)], result["output"]["prunable_worktrees"])
        self.assertEqual([str(feature), str(detached)], result["output"]["stale_candidates"])
        self.assertEqual(
            [str(feature), str(detached)],
            [item["path"] for item in result["output"]["cleanup_candidates"]],
        )
        self.assertEqual(2, result["output"]["cleanup_candidate_count"])
        self.assertTrue(all(item["cleanup_allowed"] is False for item in result["output"]["cleanup_candidates"]))
        self.assertIn("git marks worktree prunable", result["output"]["cleanup_candidates"][0]["reason"])
        self.assertEqual("old", result["output"]["cleanup_candidates"][1]["reason"])
        self.assertNotIn("detached worktree", result["output"]["cleanup_candidates"][1]["reason"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])


class GripFoundationTests(unittest.TestCase):
    def test_list_grips_exposes_core_foundation_specs(self) -> None:
        listed = grips.list_grips()
        specs = {item["name"]: item for item in listed}
        self.assertEqual({"branch-publish", "post-merge-sync", "pr-check-readiness", "pr-create-or-update", "repo-orient", "worktree-orient"}, set(specs))
        for item in listed:
            self.assertIn("acceptance_ids", item)
        self.assertEqual("mutating", specs["branch-publish"]["effect"])
        self.assertEqual("read_only", specs["repo-orient"]["effect"])

    def test_repo_orient_emits_pass_receipt_and_git_facts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="feat/operator-grip-foundation-v1", dirty=False)
            result = grips.run_grip(
                "repo-orient",
                {"repo": tmp, "expected_branch": "feat/operator-grip-foundation-v1"},
                command_runner=fake,
            )

        receipt = result["receipt"]
        output = result["output"]
        self.assertEqual("grabowski.operator_grip_receipt", receipt["kind"])
        self.assertEqual(1, receipt["schema_version"])
        self.assertEqual("passed", receipt["status"])
        self.assertEqual("action", receipt["phase"])
        self.assertEqual("repo-orient", receipt["grip"]["name"])
        self.assertEqual("feat/operator-grip-foundation-v1", output["branch"])
        self.assertFalse(output["dirty"])
        self.assertTrue(output["expected_branch_match"])
        self.assertEqual(64, len(receipt["receipt_sha256"]))
        self.assertEqual(64, len(receipt["output_sha256"]))

    def test_pr_check_readiness_summarizes_work_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "require_clean": True},
                command_runner=FakeGit(branch="feat/operator-grip-foundation-v1", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["work_branch"])
        self.assertEqual("pass", checks["upstream"])
        self.assertEqual("pass", checks["cleanliness"])

    def test_pr_check_readiness_blocks_failed_required_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "require_clean": True,
                    "required_checks": ["validate"],
                    "check_results": {"validate": "failure"},
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertEqual("blocked", result["output"]["verdict"])
        self.assertIn("required checks failing", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["required_checks"])

    def test_pr_check_readiness_blocks_external_review_requirement_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "external_review_required": True},
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertIn("external review evidence missing", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["external_review_evidence"])

    def test_pr_check_readiness_reports_ready_with_checks_and_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "require_clean": True,
                    "expected_head": "a" * 40,
                    "required_checks": ["validate"],
                    "check_results": {"validate": "success"},
                    "review_decision": "APPROVED",
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head="a" * 40),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        self.assertEqual("ready", result["output"]["verdict"])
        self.assertEqual([], result["output"]["blocking_reasons"])

    def test_pr_check_readiness_blocks_review_required_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "review_decision": "REVIEW_REQUIRED"},
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertEqual("blocked", result["output"]["verdict"])
        self.assertIn("review approval required", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["review_decision"])

    def test_pr_check_readiness_blocks_unstructured_external_review_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "external_review_required": True, "external_review_evidence": "todo"},
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertIn("external review evidence invalid", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["external_review_evidence"])

    def test_pr_check_readiness_accepts_structured_external_review_evidence(self) -> None:
        head = "a" * 40
        evidence = {
            "head_sha": head,
            "diff_sha256": "0" * 64,
            "reviews": [{"source": "external-llm", "verdict": "PASS", "review_sha256": "1" * 64}],
            "external_reviews_triaged": True,
            "findings": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "expected_head": head,
                    "external_review_required": True,
                    "external_review_evidence": evidence,
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["external_review_evidence"])

    def test_preflight_blocks_missing_required_parameter_with_receipt(self) -> None:
        result = grips.run_grip("repo-orient", {}, command_runner=FakeGit())

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("missing required parameters", result["output"]["error"])
        self.assertEqual(64, len(result["receipt"]["receipt_sha256"]))

    def test_preflight_blocks_non_json_parameter_with_receipt(self) -> None:
        result = grips.run_grip("repo-orient", {"repo": Path(".")}, command_runner=FakeGit())

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("repo parameter must be a non-empty string", result["output"]["error"])
        self.assertEqual(64, len(result["receipt"]["receipt_sha256"]))

    def test_repo_orient_blocks_expected_branch_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "repo-orient",
                {"repo": tmp, "expected_branch": "feat/operator-grip-foundation-v1"},
                command_runner=FakeGit(branch="main", dirty=False),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("expected_branch mismatch", result["output"]["error"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["expected_branch"])
        self.assertEqual(64, len(result["receipt"]["receipt_sha256"]))

    def test_post_merge_sync_validates_target_branch_before_orienting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit()
            result = grips.run_grip(
                "post-merge-sync",
                {"repo": tmp, "target_branch": ""},
                command_runner=fake,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("target_branch parameter must be a non-empty string", result["output"]["error"])
        self.assertEqual([], fake.calls)
        self.assertEqual(64, len(result["receipt"]["receipt_sha256"]))

    def test_branch_publish_requires_allow_mutation(self) -> None:
        result = grips.run_grip(
            "branch-publish",
            {"repo": ".", "branch": "feat/work", "expected_head": "a" * 40},
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("allow_mutation", result["output"]["error"])

    def test_branch_publish_pushes_and_verifies_remote_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("action", result["receipt"]["phase"])
        self.assertEqual("a" * 40, result["output"]["remote_head"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["remote_head"])

    def test_branch_publish_rejects_fully_qualified_branch_ref_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="refs/heads/main")
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "refs/heads/main", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("short branch name", result["output"]["error"])
        self.assertEqual([], fake.calls)

    def test_branch_publish_rejects_malformed_expected_head_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="feat/work")
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "not-a-sha"},
                allow_mutation=True,
                command_runner=fake,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("hex SHA", result["output"]["error"])
        self.assertEqual([], fake.calls)

    def test_branch_publish_blocks_protected_branch_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="main")
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "main", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("protected branches", result["output"]["error"])
        self.assertEqual([], fake.calls)

    def test_branch_publish_blocks_expected_head_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "b" * 40},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("expected_head mismatch", result["output"]["error"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["expected_head"])

    def test_pr_create_or_update_requires_allow_mutation(self) -> None:
        result = grips.run_grip(
            "pr-create-or-update",
            {"repo": ".", "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Test"},
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("allow_mutation", result["output"]["error"])

    def test_pr_create_or_update_creates_and_verifies_pr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_git = FakeGit(branch="feat/work", head="a" * 40)
            fake_gh = FakeGh()
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Test", "body": "Body"},
                allow_mutation=True,
                command_runner=fake_git,
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("created", result["output"]["action"])
        self.assertIn(("pr", "create", "--base", "main", "--head", "feat/work", "--title", "Test", "--body", "Body"), fake_gh.calls)
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["remote_head"])
        self.assertEqual("pass", checks["pr_verify"])

    def test_pr_create_or_update_updates_existing_matching_pr(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40}
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(existing=existing)
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Updated"},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("updated", result["output"]["action"])
        self.assertIn(("pr", "edit", "77", "--title", "Updated"), fake_gh.calls)

    def test_pr_create_or_update_blocks_existing_base_mismatch(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "develop", "headRefName": "feat/work", "headRefOid": "a" * 40}
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Test"},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=FakeGh(existing=existing),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("existing PR base", result["output"]["error"])

    def test_post_merge_sync_is_dry_run_only_in_foundation_slice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "post-merge-sync",
                {"repo": tmp, "target_branch": "main", "dry_run": False},
                command_runner=FakeGit(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("dry-run only", result["output"]["error"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["dry_run_only"])

    def test_action_failure_is_recorded_as_failed_action_receipt(self) -> None:
        def failing_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            return {"returncode": 2, "stdout": "", "stderr": "git command failed for test"}

        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip("repo-orient", {"repo": tmp}, command_runner=failing_runner)

        self.assertEqual("failed", result["receipt"]["status"])
        self.assertEqual("action", result["receipt"]["phase"])
        self.assertIn("git command failed", result["output"]["error"])

    def test_default_runner_disables_prompt_pager_fsmonitor_and_bounds_runtime(self) -> None:
        calls: dict[str, object] = {}

        class Completed:
            returncode = 0
            stdout = "ok\n"
            stderr = ""

        def fake_run(argv: list[str], **kwargs: object) -> Completed:
            calls["argv"] = argv
            calls.update(kwargs)
            return Completed()

        original = grips.subprocess.run
        try:
            grips.subprocess.run = fake_run  # type: ignore[assignment]
            result = grips._default_command_runner(Path("/tmp/repo"), ["status", "--short"])
        finally:
            grips.subprocess.run = original  # type: ignore[assignment]

        env = calls["env"]
        self.assertIsInstance(env, dict)
        self.assertEqual(0, result["returncode"])
        self.assertEqual(30, calls["timeout"])
        self.assertEqual("0", env["GIT_TERMINAL_PROMPT"])
        self.assertEqual("0", env["GIT_OPTIONAL_LOCKS"])
        self.assertEqual("1", env["GIT_CONFIG_COUNT"])
        self.assertEqual("core.fsmonitor", env["GIT_CONFIG_KEY_0"])
        self.assertEqual("false", env["GIT_CONFIG_VALUE_0"])
        self.assertEqual("cat", env["GIT_PAGER"])
        self.assertEqual("cat", env["PAGER"])

if __name__ == "__main__":
    unittest.main()
