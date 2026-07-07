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
    def __init__(
        self,
        *,
        existing: dict[str, object] | list[dict[str, object]] | None = None,
        view: dict[str, object] | None = None,
        failure: bool = False,
        invalid_json: bool = False,
    ):
        self.existing = existing
        self.failure = failure
        self.invalid_json = invalid_json
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
            if self.failure:
                return {"returncode": 2, "stdout": "", "stderr": "gh failed"}
            if self.invalid_json:
                return {"returncode": 0, "stdout": "{", "stderr": ""}
            uses_jq = "--jq" in argv
            if uses_jq:
                value: object
                if isinstance(self.existing, list):
                    value = self.existing[0] if self.existing else None
                else:
                    value = self.existing
            elif self.existing is None:
                value = []
            elif isinstance(self.existing, list):
                value = self.existing
            else:
                value = [self.existing]
            return {"returncode": 0, "stdout": json.dumps(value), "stderr": ""}
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
        self.assertEqual(
            "first protected branch worktree by protected_branches order",
            result["output"]["canonical_checkout_reason"],
        )

    def test_worktree_orient_canonical_checkout_respects_protected_branches_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release = repo / "release-checkout"
            main = repo / "main-checkout"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {release}\nbranch refs/heads/release\n"
                            f"worktree {main}\nbranch refs/heads/main\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["status", "--short", "--branch"]:
                    return {"returncode": 0, "stdout": "## clean", "stderr": ""}
                return {"returncode": 1, "stdout": "", "stderr": "unexpected"}

            result = grips.run_grip(
                "worktree-orient",
                {"repo": str(repo), "protected_branches": ["main", "release"]},
                command_runner=runner,
            )

        self.assertEqual(str(main), result["output"]["canonical_checkout"])
        self.assertEqual(
            "first protected branch worktree by protected_branches order",
            result["output"]["canonical_checkout_reason"],
        )

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
            ["refs/heads/main"],
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
        self.assertEqual({"branch-publish", "captain-preflight", "mechanic-loop", "post-merge-sync", "pr-check-readiness", "pr-create-or-update", "repo-orient", "scout", "situation", "worktree-orient"}, set(specs))
        for item in listed:
            self.assertIn("acceptance_ids", item)
        self.assertEqual("mutating", specs["branch-publish"]["effect"])
        self.assertEqual("read_only", specs["repo-orient"]["effect"])
        for field in (
            "purpose",
            "target",
            "scope",
            "effect_class",
            "risk",
            "recovery_path",
            "preconditions",
            "expected_receipt_shape",
            "availability",
        ):
            self.assertIn(field, specs["repo-orient"])
        self.assertEqual("operator", specs["repo-orient"]["profile"])

    def test_grip_list_profile_visibility(self) -> None:
        surface = grips.grip_list(profile="observer")
        by_name = {item["name"]: item for item in surface["grips"]}

        self.assertEqual("observer", surface["profile"])
        self.assertFalse(by_name["branch-publish"]["availability"]["available"])
        self.assertFalse(by_name["captain-preflight"]["availability"]["available"])
        self.assertTrue(by_name["repo-orient"]["availability"]["available"])
        self.assertIn("does not expose generic shell execution", surface["non_claims"])

    def test_grip_run_rejects_unknown_surface_grip(self) -> None:
        result = grips.grip_run("do-everything", {"repo": "."})

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("surface allowlist", result["output"]["error"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["surface_allowlist"])

    def test_grip_run_dispatches_read_only_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.grip_run(
                "repo-orient",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/surface", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("repo-orient", result["receipt"]["grip"]["name"])
        self.assertEqual("read_only", result["receipt"]["grip"]["effect"])

    def test_grip_run_keeps_mutating_grips_receipt_gated(self) -> None:
        result = grips.grip_run(
            "branch-publish",
            {"repo": ".", "branch": "feat/test", "expected_head": "a" * 40},
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("branch-publish", result["receipt"]["grip"]["name"])
        self.assertIn("allow_mutation=true", result["output"]["error"])

    def test_grip_run_observer_profile_rejects_mutating_grip(self) -> None:
        result = grips.grip_run(
            "branch-publish",
            {"repo": ".", "branch": "feat/test", "expected_head": "a" * 40},
            profile="observer",
            allow_mutation=True,
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("profile observer cannot run mutating grips", result["output"]["error"])

    def test_mechanic_loop_runs_normal_actions_with_visible_scope_and_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "repo-orient",
                            "parameters": {"repo": tmp},
                            "target": {"repo": "heimgewebe/grabowski", "checkout": tmp},
                            "scope": {"operation": "read repository orientation", "forbidden_effects": ["pr-merge", "runtime-deploy"]},
                            "receipt_path": "receipts/mechanic/repo-orient.json",
                        },
                        {
                            "action": "pr-check-readiness",
                            "parameters": {"repo": tmp},
                            "target": {"repo": "heimgewebe/grabowski", "branch": "feat/work"},
                            "scope": {"operation": "evaluate PR readiness", "forbidden_effects": ["pr-merge", "runtime-deploy"]},
                            "receipt_path": "receipts/mechanic/pr-check-readiness.json",
                        },
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=FakeGh(),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("mechanic-loop", result["receipt"]["grip"]["name"])
        self.assertTrue(result["output"]["complete"])
        self.assertEqual(2, result["output"]["executed_action_count"])
        self.assertEqual(["repo-orient", "pr-check-readiness"], [item["grip"] for item in result["output"]["actions"]])
        for action in result["output"]["actions"]:
            self.assertIsInstance(action["target"], dict)
            self.assertIsInstance(action["scope"], dict)
            self.assertTrue(action["receipt_path"].startswith("receipts/"))
            self.assertEqual("mechanic", action["envelope"]["role"])
            self.assertFalse(action["envelope"]["requires_captain"])
            self.assertEqual(64, len(action["receipt_sha256"]))
            self.assertEqual("passed", action["receipt_status"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["normal-grips-only"])
        self.assertEqual("pass", checks["scope-visible"])
        self.assertEqual("pass", checks["receipt-per-grip"])

    def test_mechanic_loop_rejects_non_normal_or_recursive_grip(self) -> None:
        result = grips.run_grip(
            "mechanic-loop",
            {"actions": [{"action": "mechanic-loop", "parameters": {"actions": []}}]},
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("not dispatchable by mechanic-loop", result["output"]["error"])

    def test_mechanic_loop_runs_mutating_normal_grip_with_child_allow_mutation(self) -> None:
        head = "a" * 40
        fake_git = FakeGit(branch="feat/work", dirty=False, head=head)
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "branch-publish",
                            "parameters": {"repo": tmp, "branch": "feat/work", "expected_head": head},
                            "allow_mutation": True,
                            "target": {"remote": "origin", "branch": "feat/work"},
                            "scope": {"operation": "publish expected HEAD", "forbidden_effects": ["pr-merge", "runtime-deploy"]},
                            "receipt_path": "receipts/mechanic/branch-publish.json",
                        }
                    ]
                },
                allow_mutation=True,
                command_runner=fake_git,
                github_runner=FakeGh(),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["complete"])
        self.assertEqual("branch-publish", result["output"]["actions"][0]["grip"])
        self.assertEqual("mutating", result["output"]["actions"][0]["effect"])
        self.assertIn(("push", "origin", "HEAD:feat/work"), fake_git.calls)

    def test_mechanic_loop_stops_on_blocked_child_but_keeps_child_receipt(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "branch-publish",
                            "parameters": {"repo": tmp, "branch": "feat/work", "expected_head": head},
                            "target": {"remote": "origin", "branch": "feat/work"},
                            "scope": {"operation": "publish expected HEAD", "forbidden_effects": ["pr-merge", "runtime-deploy"]},
                            "receipt_path": "receipts/mechanic/branch-publish-blocked.json",
                        },
                        {
                            "action": "repo-orient",
                            "parameters": {"repo": tmp},
                            "target": {"repo": "heimgewebe/grabowski", "checkout": tmp},
                            "scope": {"operation": "read repository orientation", "forbidden_effects": ["pr-merge"]},
                            "receipt_path": "receipts/mechanic/repo-after-block.json",
                        },
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
                github_runner=FakeGh(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertFalse(result["output"]["complete"])
        self.assertEqual("blocked", result["output"]["status"])
        self.assertEqual(0, result["output"]["stopped_at_index"])
        self.assertEqual("branch-publish", result["output"]["stopped_at_action"])
        self.assertEqual(1, result["output"]["executed_action_count"])
        self.assertEqual("blocked", result["output"]["actions"][0]["receipt_status"])
        self.assertEqual(64, len(result["output"]["actions"][0]["receipt_sha256"]))

    def test_mechanic_loop_rejects_high_impact_action(self) -> None:
        result = grips.run_grip(
            "mechanic-loop",
            {
                "actions": [
                    {
                        "action": "runtime-deploy",
                        "target": {"repo": "heimgewebe/grabowski"},
                        "scope": {"operation": "deploy"},
                        "receipt_path": "receipts/mechanic/runtime-deploy.json",
                    }
                ]
            },
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("requires Captain", result["output"]["error"])

    def test_mechanic_loop_rejects_missing_target_scope_or_receipt_path(self) -> None:
        invalid_actions = [
            {"action": "repo-orient", "parameters": {"repo": "."}, "scope": {"operation": "read"}, "receipt_path": "r.json"},
            {"action": "repo-orient", "parameters": {"repo": "."}, "target": {"repo": "x"}, "receipt_path": "r.json"},
            {"action": "repo-orient", "parameters": {"repo": "."}, "target": {"repo": "x"}, "scope": {"operation": "read"}},
        ]
        for action in invalid_actions:
            with self.subTest(action=action):
                result = grips.run_grip(
                    "mechanic-loop",
                    {"actions": [action]},
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=FakeGh(),
                )
                self.assertEqual("blocked", result["receipt"]["status"])

    def test_captain_preflight_blocks_without_fresh_projection(self) -> None:
        result = grips.grip_run(
            "captain-preflight",
            {
                "actions": [
                    {
                        "action": "service-restart",
                        "high_impact": True,
                        "target": {"host": "heim-pc", "unit": "grabowski-mcp.service"},
                        "scope": {"operation": "preflight only"},
                        "risk": {"risk_level": "high", "irreversibility": "reversible", "recovery_path": "restart previous unit"},
                        "target_change": None,
                        "receipt_path": "receipts/captain/service-restart.json",
                    }
                ]
            },
            profile="captain",
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn("fresh_status_projection_unavailable", result["output"]["blocked_reasons"])
        self.assertIn("service-restart", result["output"]["high_impact_action_allowlist"])

    def test_captain_preflight_requires_target_change_record_when_declared(self) -> None:
        result = grips.grip_run(
            "captain-preflight",
            {
                "actions": [
                    {
                        "action": "pr-merge",
                        "high_impact": True,
                        "target": {"repo": "heimgewebe/grabowski", "pr": 1},
                        "scope": {"operation": "preflight only"},
                        "risk": {"risk_level": "high", "irreversibility": "reversible", "recovery_path": "revert merge commit"},
                        "target_change_required": True,
                        "receipt_path": "receipts/captain/pr-merge.json",
                    }
                ]
            },
            profile="captain",
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("target_change record is required", result["output"]["error"])

    def test_captain_preflight_is_captain_only_surface(self) -> None:
        result = grips.grip_run(
            "captain-preflight",
            {"actions": []},
            profile="operator",
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("captain-only", result["output"]["error"])

    def test_mechanic_loop_rejects_captain_only_child_grip(self) -> None:
        result = grips.run_grip(
            "mechanic-loop",
            {
                "actions": [
                    {
                        "action": "captain-preflight",
                        "target": {"repo": "heimgewebe/grabowski"},
                        "scope": {"operation": "preflight"},
                        "receipt_path": "receipts/mechanic/captain-preflight.json",
                    }
                ]
            },
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("not dispatchable by mechanic-loop", result["output"]["error"])

    def test_mechanic_loop_rejects_target_parameter_mismatch(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "branch-publish",
                            "parameters": {"repo": tmp, "branch": "feat/actual", "expected_head": head},
                            "allow_mutation": True,
                            "target": {"remote": "origin", "branch": "feat/claimed"},
                            "scope": {"operation": "publish expected HEAD"},
                            "receipt_path": "receipts/mechanic/branch-publish.json",
                        }
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/actual", dirty=False, head=head),
                github_runner=FakeGh(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("target.branch must match parameters.branch", result["output"]["error"])

    def test_mechanic_loop_blocks_child_without_valid_receipt(self) -> None:
        original = grips.run_grip

        def fake_child(*args, **kwargs):
            if args and args[0] == "repo-orient":
                return {"receipt": None, "output": {}}
            return original(*args, **kwargs)

        try:
            grips.run_grip = fake_child
            result = original(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "repo-orient",
                            "parameters": {"repo": "."},
                            "target": {"repo": "heimgewebe/grabowski"},
                            "scope": {"operation": "read"},
                            "receipt_path": "receipts/mechanic/repo-orient.json",
                        }
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
        finally:
            grips.run_grip = original

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("action", result["receipt"]["phase"])
        self.assertEqual("blocked", result["output"]["status"])
        self.assertEqual(1, result["output"]["executed_action_count"])
        self.assertIn("child receipt is missing or invalid", result["output"]["actions"][0]["receipt_error"])
        self.assertEqual(64, len(result["output"]["actions"][0]["receipt_sha256"]))

    def test_mechanic_loop_blocks_child_without_sha256_hex_receipt(self) -> None:
        original = grips.run_grip

        def fake_child(*args, **kwargs):
            if args and args[0] == "repo-orient":
                return {"receipt": {"status": "passed", "phase": "action", "receipt_sha256": "z" * 64}, "output": {}}
            return original(*args, **kwargs)

        try:
            grips.run_grip = fake_child
            result = original(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": "repo-orient",
                            "parameters": {"repo": "."},
                            "target": {"repo": "heimgewebe/grabowski"},
                            "scope": {"operation": "read"},
                            "receipt_path": "receipts/mechanic/repo-orient.json",
                        }
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
        finally:
            grips.run_grip = original

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("action", result["receipt"]["phase"])
        self.assertIn("child receipt hash is missing or invalid", result["output"]["actions"][0]["receipt_error"])
        self.assertIsNone(result["output"]["actions"][0]["child_receipt_sha256"])

    def test_mechanic_loop_rejects_grip_alias_mismatch(self) -> None:
        result = grips.run_grip(
            "mechanic-loop",
            {
                "actions": [
                    {
                        "action": "repo-orient",
                        "grip": "pr-check-readiness",
                        "parameters": {"repo": "."},
                        "target": {"repo": "heimgewebe/grabowski"},
                        "scope": {"operation": "read"},
                        "receipt_path": "receipts/mechanic/repo-orient.json",
                    }
                ]
            },
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("grip alias must match action", result["output"]["error"])

    def test_mechanic_loop_rejects_receipt_path_outside_receipts(self) -> None:
        invalid_paths = ["mechanic/repo-orient.json", ".git/receipts/repo-orient.json"]
        for receipt_path in invalid_paths:
            with self.subTest(receipt_path=receipt_path):
                result = grips.run_grip(
                    "mechanic-loop",
                    {
                        "actions": [
                            {
                                "action": "repo-orient",
                                "parameters": {"repo": "."},
                                "target": {"repo": "heimgewebe/grabowski"},
                                "scope": {"operation": "read"},
                                "receipt_path": receipt_path,
                            }
                        ]
                    },
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=FakeGh(),
                )

                self.assertEqual("blocked", result["receipt"]["status"])

    def test_captain_preflight_rejects_unknown_irreversibility(self) -> None:
        result = grips.grip_run(
            "captain-preflight",
            {
                "actions": [
                    {
                        "action": "pr-merge",
                        "high_impact": True,
                        "target": {"repo": "heimgewebe/grabowski", "pr": 1},
                        "scope": {"operation": "preflight only"},
                        "risk": {"risk_level": "high", "irreversibility": "maybe"},
                        "target_change": None,
                        "receipt_path": "receipts/captain/pr-merge.json",
                    }
                ]
            },
            profile="captain",
            command_runner=FakeGit(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("irreversibility must be reversible or irreversible", result["output"]["error"])

    def test_mechanic_allowlists_do_not_overlap_captain_surfaces(self) -> None:
        self.assertLessEqual(grips.MECHANIC_NORMAL_GRIPS, grips.GRIP_SPECS.keys())
        self.assertTrue(grips.MECHANIC_NORMAL_GRIPS.isdisjoint(grips.GRIP_SURFACE_CAPTAIN_ONLY))
        self.assertTrue(grips.MECHANIC_NORMAL_GRIPS.isdisjoint(grips.CAPTAIN_HIGH_IMPACT_ACTIONS))

    def test_mechanic_loop_continue_on_blocked_runs_remaining_but_parent_blocks(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "continue_on_blocked": True,
                    "actions": [
                        {
                            "action": "branch-publish",
                            "parameters": {"repo": tmp, "branch": "feat/work", "expected_head": head},
                            "target": {"remote": "origin", "branch": "feat/work"},
                            "scope": {"operation": "publish expected HEAD"},
                            "receipt_path": "receipts/mechanic/branch-publish-blocked.json",
                        },
                        {
                            "action": "repo-orient",
                            "parameters": {"repo": tmp},
                            "target": {"repo": "heimgewebe/grabowski", "checkout": tmp},
                            "scope": {"operation": "read repository orientation"},
                            "receipt_path": "receipts/mechanic/repo-after-block.json",
                        },
                    ],
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
                github_runner=FakeGh(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("blocked", result["output"]["status"])
        self.assertFalse(result["output"]["complete"])
        self.assertEqual(2, result["output"]["executed_action_count"])
        self.assertEqual(["blocked", "passed"], [item["receipt_status"] for item in result["output"]["actions"]])


    def test_situation_grip_reports_core_state_and_next_safe_grip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(existing=None)
            result = grips.run_grip(
                "situation",
                {
                    "repo": tmp,
                    "include_pr": True,
                    "bureau_task": {"id": "GRABOWSKI-OPERATOR-SURFACE-V1-T001", "state": "planned"},
                    "blockers": [],
                    "jobs": [],
                },
                command_runner=FakeGit(branch="feat/situation-grip-v1", dirty=False),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("situation", result["receipt"]["grip"]["name"])
        self.assertEqual("feat/situation-grip-v1", result["output"]["repo"]["branch"])
        self.assertFalse(result["output"]["repo"]["dirty"])
        self.assertFalse(result["output"]["pr"]["available"])
        self.assertEqual("worktree-orient", result["output"]["next_safe_grip"]["name"])
        self.assertIn("does not mutate repositories", result["output"]["non_claims"])
        self.assertEqual(64, len(result["output"]["snapshot_digest"]["grip_catalog_sha256"]))
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["snapshot_digest"])
        self.assertEqual("pass", checks["next_safe_grip"])

    def test_situation_grip_warns_on_stale_digest_and_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp, "include_pr": False, "expected_grip_catalog_sha256": "0" * 64},
                command_runner=FakeGit(branch="feat/work", dirty=True),
                github_runner=FakeGh(),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("repo-orient", result["output"]["next_safe_grip"]["name"])
        self.assertIsNotNone(result["output"]["snapshot_digest"]["stale_warning"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("warn", checks["repo_state"])
        self.assertEqual("warn", checks["snapshot_digest"])

    def test_situation_grip_uses_open_pr_when_available(self) -> None:
        existing = {
            "number": 132,
            "url": "https://github.com/heimgewebe/grabowski/pull/132",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "reviewDecision": "APPROVED",
            "statusCheckRollup": [{"name": "validate", "conclusion": "SUCCESS"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/work", dirty=False, head="a" * 40),
                github_runner=FakeGh(existing=existing),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["pr"]["available"])
        self.assertEqual(132, result["output"]["pr"]["number"])
        self.assertEqual({"SUCCESS": 1}, result["output"]["pr"]["check_state_counts"])
        self.assertEqual({"validate": "SUCCESS"}, result["output"]["pr"]["check_results"])
        self.assertEqual("pr-check-readiness", result["output"]["next_safe_grip"]["name"])
        self.assertEqual(
            {"validate": "SUCCESS"},
            result["output"]["next_safe_grip"]["parameters"]["check_results"],
        )

    def test_situation_grip_skips_github_when_include_pr_is_false(self) -> None:
        fake_gh = FakeGh()
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp, "include_pr": False},
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([], fake_gh.calls)
        self.assertEqual("PR lookup skipped", result["output"]["pr"]["reason"])

    def test_situation_grip_blocks_invalid_include_pr_type(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp, "include_pr": "false"},
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("include_pr must be a boolean", result["output"]["error"])

    def test_situation_grip_blocks_invalid_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp, "expected_grip_catalog_sha256": "z" * 64},
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("hex SHA", result["output"]["error"])

    def test_situation_grip_blocks_missing_repo(self) -> None:
        missing = "/tmp/grabowski-missing-situation-repo"
        result = grips.run_grip(
            "situation",
            {"repo": missing},
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("repo does not exist", result["output"]["error"])

    def test_situation_grip_reports_github_failure_as_unavailable_pr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=FakeGh(failure=True),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["pr"]["available"])
        self.assertEqual("gh failed", result["output"]["pr"]["reason"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("warn", checks["pr_state"])

    def test_situation_grip_reports_invalid_pr_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=FakeGh(invalid_json=True),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["pr"]["available"])
        self.assertEqual("PR lookup returned invalid JSON", result["output"]["pr"]["reason"])

    def test_situation_grip_rejects_incomplete_pr_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=FakeGh(existing={}),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["pr"]["available"])
        self.assertEqual("PR lookup returned incomplete PR object", result["output"]["pr"]["reason"])

    def test_situation_grip_marks_multiple_prs_ambiguous(self) -> None:
        first = {
            "number": 1,
            "url": "https://github.com/heimgewebe/grabowski/pull/1",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
        }
        second = {
            "number": 2,
            "url": "https://github.com/heimgewebe/grabowski/pull/2",
            "headRefName": "feat/work",
            "headRefOid": "b" * 40,
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="feat/work", dirty=False),
                github_runner=FakeGh(existing=[first, second]),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["pr"]["ambiguous"])
        self.assertEqual(2, result["output"]["pr"]["count"])
        self.assertIsNone(result["output"]["next_safe_grip"]["name"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("warn", checks["pr_state"])

    def test_situation_grip_skips_pr_lookup_for_detached_head(self) -> None:
        fake_gh = FakeGh()
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "situation",
                {"repo": tmp},
                command_runner=FakeGit(branch="HEAD", dirty=False),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([], fake_gh.calls)
        self.assertEqual(
            "detached HEAD; PR lookup by branch skipped",
            result["output"]["pr"]["reason"],
        )

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


class ScoutGripTests(unittest.TestCase):
    class FakeScoutGit:
        def __init__(self, repo: Path):
            self.repo = repo
            self.calls: list[tuple[str, ...]] = []
            self.head = "b" * 40
            self.origin_main = "c" * 40

        def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
            self.calls.append(tuple(argv))
            if argv == ["rev-parse", "--show-toplevel"]:
                return {"returncode": 0, "stdout": str(self.repo), "stderr": ""}
            if argv == ["rev-parse", "--abbrev-ref", "HEAD"]:
                return {"returncode": 0, "stdout": "feat/scout", "stderr": ""}
            if argv == ["rev-parse", "HEAD"]:
                return {"returncode": 0, "stdout": self.head, "stderr": ""}
            if argv == ["rev-parse", "origin/main"]:
                return {"returncode": 0, "stdout": self.origin_main, "stderr": ""}
            if argv == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
                return {"returncode": 0, "stdout": "origin/feat/scout", "stderr": ""}
            if argv == ["rev-list", "--left-right", "--count", "origin/feat/scout...HEAD"]:
                return {"returncode": 0, "stdout": "0\t2", "stderr": ""}
            if argv == ["remote", "get-url", "origin"]:
                return {"returncode": 0, "stdout": "git@github.com:heimgewebe/grabowski.git", "stderr": ""}
            return {"returncode": 1, "stdout": "", "stderr": f"unexpected command: {argv}"}

    class FakeScoutGh:
        def __init__(self, head: str):
            self.head = head
            self.calls: list[tuple[str, ...]] = []

        def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
            self.calls.append(tuple(argv))
            if argv[:2] == ["pr", "list"]:
                return {
                    "returncode": 0,
                    "stdout": json.dumps([
                        {
                            "number": 92,
                            "title": "Scout branch",
                            "headRefName": "feat/scout",
                            "headRefOid": "d" * 40,
                            "isDraft": False,
                            "mergeStateStatus": "CLEAN",
                            "reviewDecision": "CHANGES_REQUESTED",
                            "updatedAt": "2026-07-07T08:00:00Z",
                        },
                    ]),
                    "stderr": "",
                }
            return {"returncode": 1, "stdout": "", "stderr": f"unexpected gh command: {argv}"}

    def test_scout_reports_only_changes_across_signals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            fake_git = self.FakeScoutGit(repo)
            fake_gh = self.FakeScoutGh(fake_git.head)
            result = grips.run_grip(
                "scout",
                {
                    "repo": str(repo),
                    "runtime_head": "e" * 40,
                    "receipt_paths": ["receipts/missing.json"],
                },
                command_runner=fake_git,
                github_runner=fake_gh,
            )
        self.assertEqual(result["receipt"]["status"], "passed")
        output = result["output"]
        self.assertEqual(set(output), {"enabled", "change_count", "changes", "non_claims"})
        categories = {item["category"] for item in output["changes"]}
        self.assertIn("runtime_main_drift", categories)
        self.assertIn("unpushed_branch", categories)
        self.assertIn("pr_drift", categories)
        self.assertIn("stale_review", categories)
        self.assertIn("missing_receipt", categories)
        self.assertEqual(output["change_count"], len(output["changes"]))
        mutating_terms = {"push", "merge", "commit", "checkout", "switch"}
        self.assertFalse(any(call and call[0] in mutating_terms for call in fake_git.calls))

    def test_scout_can_be_disabled_without_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            fake_git = self.FakeScoutGit(repo)
            fake_gh = self.FakeScoutGh(fake_git.head)
            result = grips.run_grip(
                "scout",
                {"repo": str(repo), "disabled": True},
                command_runner=fake_git,
                github_runner=fake_gh,
            )
        self.assertEqual(result["receipt"]["status"], "passed")
        self.assertFalse(result["output"]["enabled"])
        self.assertEqual(result["output"]["changes"], [])
        self.assertEqual(fake_git.calls, [])
        self.assertEqual(fake_gh.calls, [])

    def test_scout_is_exposed_on_surface_as_read_only(self) -> None:
        listed = {item["name"]: item for item in grips.list_grips("observer")}
        self.assertIn("scout", listed)
        self.assertEqual(listed["scout"]["effect"], grips.READ_ONLY)
        self.assertTrue(listed["scout"]["availability"]["available"])


CAPTAIN_HEAD = "b" * 40
CAPTAIN_DIFF = "c" * 64


def captain_action(**overrides) -> dict[str, object]:
    action: dict[str, object] = {
        "action": "pr-merge",
        "high_impact": True,
        "role": "captain",
        "target": {"repo": "heimgewebe/grabowski", "pr": 96},
        "scope": {
            "allowed_effects": ["merge pull request 96 into main"],
            "forbidden_effects": ["force-push", "branch-deletion"],
            "boundaries": "single pull request in heimgewebe/grabowski",
            "max_targets": 1,
        },
        "risk": {
            "risk_level": "high",
            "irreversibility": "reversible",
            "recovery_path": "revert the merge commit on main",
        },
        "target_change": None,
        "receipt_path": "receipts/captain/pr-merge.json",
    }
    action.update(overrides)
    return action


def captain_parameters(actions: list[dict[str, object]] | None = None, **overrides) -> dict[str, object]:
    projection = {"schema_version": 1, "healthy": True, "generated_at": "2026-07-07T12:00:00Z"}
    parameters: dict[str, object] = {
        "actions": actions if actions is not None else [captain_action()],
        "status_projection": projection,
        "status_projection_fresh": True,
        "status_projection_source": "bureau status-projection",
        "status_projection_sha256": grips.sha256_json(projection),
        "expected_head": CAPTAIN_HEAD,
        "diff_sha256": CAPTAIN_DIFF,
        "execution_authority": {"granted_by": "alex", "reference": "captain decision record 2026-07-07"},
        "review_evidence": {
            "head_sha": CAPTAIN_HEAD,
            "diff_sha256": CAPTAIN_DIFF,
            "reviews": [{"reviewer": "external-review", "verdict": "PASS"}],
            "external_reviews_triaged": True,
            "findings": [],
        },
        "ci_evidence": {"state": "passed", "head_sha": CAPTAIN_HEAD, "source": "github-actions"},
        "human_authorization": {"authorized_by": "alex", "statement": "manual captain decision still pending"},
    }
    parameters.update(overrides)
    return parameters


class CaptainAuthorityPathTests(unittest.TestCase):
    def run_captain(self, parameters: dict[str, object]) -> dict[str, object]:
        return grips.grip_run("captain-preflight", parameters, profile="captain", command_runner=FakeGit())

    def gate(self, result: dict[str, object], gate_id: str) -> dict[str, object]:
        return next(item for item in result["output"]["gates"] if item["id"] == gate_id)

    def test_all_gates_pass_yields_only_manual_decision_and_no_execution(self) -> None:
        result = self.run_captain(captain_parameters())

        output = result["output"]
        self.assertEqual([gate["id"] for gate in output["gates"]], list(grips.CAPTAIN_GATE_IDS))
        self.assertTrue(all(gate["status"] == "pass" for gate in output["gates"]))
        self.assertEqual("ready_for_manual_captain_decision", output["decision"])
        self.assertEqual("blocked", output["status"])
        self.assertEqual("blocked", output["receipt_status"])
        self.assertEqual(["captain_execution_not_implemented_in_this_slice"], output["blocked_reasons"])
        self.assertEqual("blocked", result["receipt"]["status"])
        action = output["actions"][0]
        self.assertEqual("not-performed", action["execution"])
        self.assertEqual("blocked", action["captain_receipt"]["status"])
        self.assertTrue(grips._is_sha256_hex(action["receipt_sha256"]))
        self.assertEqual(action["captain_receipt"]["recovery_path"], "revert the merge commit on main")
        self.assertIn("privileged execution is not implemented", output["why_no_mutation"])

    def test_top_level_receipt_follows_receipt_status_when_blocked(self) -> None:
        result = self.run_captain(captain_parameters(review_evidence=None))

        self.assertEqual("blocked", result["output"]["receipt_status"])
        self.assertEqual("blocked", result["output"]["status"])
        self.assertEqual(result["output"]["receipt_status"], result["receipt"]["status"])
        self.assertEqual("blocked", result["output"]["decision"])

    def test_blocks_without_status_projection_object(self) -> None:
        parameters = captain_parameters()
        for key in ("status_projection", "status_projection_fresh", "status_projection_source", "status_projection_sha256"):
            parameters.pop(key)
        result = self.run_captain(parameters)

        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn("fresh_status_projection_unavailable", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", self.gate(result, "status-projection-fresh")["status"])

    def test_blocks_stale_status_projection(self) -> None:
        result = self.run_captain(captain_parameters(status_projection_fresh=False))

        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn("fresh_status_projection_unavailable", result["output"]["blocked_reasons"])
        self.assertTrue(result["output"]["status_projection"]["used"])

    def test_blocks_invalid_status_projection_sha256(self) -> None:
        result = self.run_captain(captain_parameters(status_projection_sha256="zz" * 32))

        self.assertIn("status_projection_sha256_invalid", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", result["output"]["decision"])

    def test_blocks_status_projection_hash_drift(self) -> None:
        result = self.run_captain(captain_parameters(status_projection_sha256="d" * 64))

        self.assertIn("status_projection_sha256_mismatch", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", result["output"]["decision"])

    def test_blocks_missing_status_projection_source(self) -> None:
        result = self.run_captain(captain_parameters(status_projection_source="  "))

        self.assertIn("status_projection_source_missing", result["output"]["blocked_reasons"])

    def test_allow_execution_alone_never_grants_authority(self) -> None:
        parameters = captain_parameters(allow_execution=True)
        parameters.pop("execution_authority")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn("execution_authority_missing", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", self.gate(result, "execution-authority-present")["status"])

    def test_blocks_incomplete_execution_authority(self) -> None:
        result = self.run_captain(captain_parameters(execution_authority={"granted_by": "alex"}))

        self.assertEqual("blocked", self.gate(result, "execution-authority-present")["status"])

    def test_blocks_missing_review_evidence(self) -> None:
        parameters = captain_parameters()
        parameters.pop("review_evidence")
        result = self.run_captain(parameters)

        self.assertIn("review_evidence_missing", result["output"]["blocked_reasons"])

    def test_blocks_review_evidence_for_other_head(self) -> None:
        parameters = captain_parameters()
        parameters["review_evidence"]["head_sha"] = "e" * 40
        result = self.run_captain(parameters)

        self.assertEqual("blocked", self.gate(result, "review-evidence-present")["status"])

    def test_blocks_missing_diff_binding(self) -> None:
        parameters = captain_parameters()
        parameters.pop("diff_sha256")
        result = self.run_captain(parameters)

        self.assertIn("diff_binding_missing_or_invalid", result["output"]["blocked_reasons"])

    def test_blocks_diff_hash_mismatch_with_review_evidence(self) -> None:
        result = self.run_captain(captain_parameters(diff_sha256="f" * 64))

        blocked = result["output"]["blocked_reasons"]
        self.assertTrue("diff_sha256_mismatch" in blocked or any("diff_sha256" in reason for reason in blocked))
        self.assertEqual("blocked", result["output"]["decision"])

    def test_blocks_missing_or_failed_ci_evidence(self) -> None:
        parameters = captain_parameters()
        parameters.pop("ci_evidence")
        result = self.run_captain(parameters)
        self.assertIn("ci_evidence_missing", result["output"]["blocked_reasons"])

        failed = self.run_captain(
            captain_parameters(ci_evidence={"state": "failed", "head_sha": CAPTAIN_HEAD, "source": "github-actions"})
        )
        self.assertEqual("blocked", self.gate(failed, "ci-green")["status"])

    def test_blocks_missing_human_authorization(self) -> None:
        parameters = captain_parameters()
        parameters.pop("human_authorization")
        result = self.run_captain(parameters)

        self.assertIn("human_authorization_missing", result["output"]["blocked_reasons"])

    def test_blocks_missing_recovery_and_irreversibility(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(risk={"risk_level": "high"})]))

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("risk requires recovery_path or irreversibility", result["output"]["error"])

    def test_irreversible_requires_irreversibility_record(self) -> None:
        action = captain_action(risk={"risk_level": "high", "irreversibility": "irreversible"})
        result = self.run_captain(captain_parameters([action]))
        self.assertIn("irreversibility_record is required", result["output"]["error"])

        action["irreversibility_record"] = {"reason": "merge rewrites main history context", "accepted_by": "alex"}
        recorded = self.run_captain(captain_parameters([action]))
        self.assertEqual("ready_for_manual_captain_decision", recorded["output"]["decision"])

    def test_rejects_unknown_high_impact_like_action(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(action="database-drop")]))

        self.assertIn("must be an explicit high-impact Captain action", result["output"]["error"])

    def test_rejects_normal_mechanic_action(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(action="branch-publish")]))

        self.assertIn("is a normal mechanic action", result["output"]["error"])

    def test_rejects_nested_orchestration_grips(self) -> None:
        for name in ("mechanic-loop", "captain-preflight"):
            result = self.run_captain(captain_parameters([captain_action(action=name)]))
            self.assertIn("must not nest orchestration grips", result["output"]["error"])

    def test_rejects_non_captain_role(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(role="mechanic")]))

        self.assertIn("role must be captain", result["output"]["error"])

    def test_pr_merge_requires_repo_and_positive_integer_pr(self) -> None:
        for target in (
            {"pr": 96},
            {"repo": "heimgewebe/grabowski"},
            {"repo": "grabowski", "pr": 96},
            {"repo": "heimgewebe/grabowski", "pr": 0},
            {"repo": "heimgewebe/grabowski", "pr": -3},
            {"repo": "heimgewebe/grabowski", "pr": "96"},
            {"repo": "heimgewebe/grabowski", "pr": True},
        ):
            result = self.run_captain(captain_parameters([captain_action(target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assertIn("target", result["output"]["error"])

    def test_runtime_deploy_requires_runtime_target(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={"service": "grabowski-mcp"},
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        result = self.run_captain(captain_parameters([action]))
        self.assertIn("environment or runtime_target", result["output"]["error"])

        action["target"] = {"service": "grabowski-mcp", "environment": "heim-pc"}
        parameters = captain_parameters([action])
        for key in ("status_projection", "status_projection_fresh", "status_projection_source", "status_projection_sha256"):
            parameters.pop(key)
        blocked = self.run_captain(parameters)
        self.assertIn("fresh_status_projection_unavailable", blocked["output"]["blocked_reasons"])
        self.assertTrue(blocked["output"]["actions"][0]["requires_status_projection"])

    def test_service_restart_requires_host_and_concrete_unit(self) -> None:
        base = {"action": "service-restart", "receipt_path": "receipts/captain/service-restart.json"}
        for target in ({"unit": "grabowski-mcp.service"}, {"host": "heim-pc"}, {"host": "heim-pc", "unit": "*"}, {"host": "heim-pc", "unit": "all"}):
            result = self.run_captain(captain_parameters([captain_action(**base, target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assertIn("target", result["output"]["error"])

    def test_fleet_mutation_requires_concrete_target_and_explicit_operation(self) -> None:
        base = {"action": "fleet-mutation", "receipt_path": "receipts/captain/fleet-mutation.json"}
        for target in (
            {"operation": "rotate-worker-tokens"},
            {"fleet_target": "*", "operation": "rotate-worker-tokens"},
            {"fleet_target": "browser-workers", "operation": "update"},
            {"fleet_target": "browser-workers", "operation": "any"},
        ):
            result = self.run_captain(captain_parameters([captain_action(**base, target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assertIn("target", result["output"]["error"])

    def test_cleanup_apply_requires_cleanup_target_and_location(self) -> None:
        base = {"action": "cleanup-apply", "receipt_path": "receipts/captain/cleanup-apply.json"}
        for target in ({"repo": "heimgewebe/grabowski"}, {"cleanup_target": "stale worktrees"}):
            result = self.run_captain(captain_parameters([captain_action(**base, target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assertIn("target", result["output"]["error"])

    def test_target_change_required_needs_non_empty_record(self) -> None:
        result = self.run_captain(
            captain_parameters([captain_action(target_change_required=True, target_change={})])
        )

        self.assertIn("target_change record must be a non-empty object", result["output"]["error"])

    def test_scope_without_effect_boundaries_blocks(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(scope={"operation": "preflight only"})]))

        self.assertEqual("blocked", self.gate(result, "scope-bound")["status"])
        self.assertEqual("blocked", result["output"]["decision"])

    def test_does_not_establish_lists_safety_non_claims(self) -> None:
        result = self.run_captain(captain_parameters())

        claims = set(result["output"]["does_not_establish"])
        self.assertLessEqual(
            {
                "automatic_merge_authority",
                "automatic_deploy_authority",
                "service_restart_safety",
                "fleet_mutation_safety",
                "cleanup_safety",
                "runtime_correctness",
                "semantic_correctness",
                "review_completeness",
                "production_safety",
                "privileged_execution",
            },
            claims,
        )
        self.assertTrue(any("allow_execution" in claim for claim in result["output"]["non_claims"]))

    def test_mechanic_loop_still_cannot_dispatch_captain_actions(self) -> None:
        for name in sorted(grips.CAPTAIN_HIGH_IMPACT_ACTIONS) + ["captain-preflight"]:
            result = grips.run_grip(
                "mechanic-loop",
                {
                    "actions": [
                        {
                            "action": name,
                            "target": {"repo": "heimgewebe/grabowski"},
                            "scope": {"operation": "attempt"},
                            "receipt_path": "receipts/mechanic/forbidden.json",
                        }
                    ]
                },
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
            self.assertEqual("blocked", result["receipt"]["status"])
