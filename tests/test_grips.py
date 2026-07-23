from __future__ import annotations
from datetime import datetime, timedelta, timezone

from pathlib import Path
import hashlib
import inspect
import json
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_grips as grips
import grabowski_grip_orchestration as grip_orchestration
import grabowski_merge_guard as merge_guard
import grabowski_resources as resources
import grabowski_task_attention as task_attention

def _self_review_audit(
    *,
    head: str = "a" * 40,
    diff_sha256: str = "0" * 64,
    tier: str = "standard",
    minimum: int = 2,
    actual: int = 2,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "repo": "heimgewebe/grabowski",
        "pr": 7,
        "generated_at": "2026-07-10T12:00:00+00:00",
        "head_sha": head,
        "diff_sha256": diff_sha256,
        "review_tier": tier,
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "minimum_review_iterations": minimum,
        "actual_review_iterations": actual,
        "all_findings_triaged": True,
        "material_findings_remaining": 0,
        "residual_risk_accepted": False,
        "residual_risk_reason": "",
        "tuning_signal": "observe",
    }


class FakeGit:
    def __init__(
        self,
        *,
        branch: str = "feat/work",
        dirty: bool = False,
        upstream: str | None = "origin/feat/work",
        head: str = "a" * 40,
        remote_head: str | None = None,
        push_config_entries: list[tuple[str, str]] | None = None,
        configured_urls: list[str] | None = None,
        effective_push_urls: list[str] | None = None,
    ):
        self.branch = branch
        self.dirty = dirty
        self.upstream = upstream
        self.head = head
        self.remote_head = remote_head or head
        self.push_config_entries = list(push_config_entries or [])
        self.configured_urls = list(
            configured_urls or ["git@github.com:heimgewebe/grabowski.git"]
        )
        self.effective_push_urls = list(effective_push_urls or self.configured_urls)
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv == ["rev-parse", "--show-toplevel"]:
            return {"returncode": 0, "stdout": str(repo), "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return {"returncode": 0, "stdout": self.branch, "stderr": ""}
        if argv == ["rev-parse", "HEAD"]:
            return {"returncode": 0, "stdout": self.head, "stderr": ""}
        if len(argv) == 3 and argv[:2] == ["config", "--get-regexp"]:
            if not self.push_config_entries:
                return {"returncode": 1, "stdout": "", "stderr": ""}
            stdout = "\n".join(f"{key} {value}" for key, value in self.push_config_entries)
            return {"returncode": 0, "stdout": stdout, "stderr": ""}
        if argv == ["config", "--get-all", "remote.origin.url"]:
            if not self.configured_urls:
                return {"returncode": 1, "stdout": "", "stderr": ""}
            return {"returncode": 0, "stdout": "\n".join(self.configured_urls), "stderr": ""}
        if argv == ["remote", "get-url", "--push", "--all", "origin"]:
            if not self.effective_push_urls:
                return {"returncode": 2, "stdout": "", "stderr": "no such remote"}
            return {"returncode": 0, "stdout": "\n".join(self.effective_push_urls), "stderr": ""}
        if argv == ["status", "--short", "--branch"]:
            body = "\n M src/example.py" if self.dirty else ""
            upstream = self.upstream or ""
            return {"returncode": 0, "stdout": f"## {self.branch}...{upstream}{body}", "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
            if self.upstream is None:
                return {"returncode": 128, "stdout": "", "stderr": "no upstream"}
            return {"returncode": 0, "stdout": self.upstream, "stderr": ""}
        push_argv = list(argv)
        while len(push_argv) >= 2 and push_argv[0] == "-c":
            push_argv = push_argv[2:]
        if push_argv == [
            "push",
            "origin",
            f"HEAD:refs/heads/{self.branch}",
        ]:
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
        view_failure_after_merge: bool = False,
        post_merge_view: dict[str, object] | None = None,
        post_merge_view_failures: int = 0,
        merge_returncode: int = 0,
        merge_stdout: str = "merged",
        merge_stderr: str = "",
        merge_updates_view: bool = True,
        view_invalid_json: bool = False,
        view_non_mapping: bool = False,
        merge_exception: bool = False,
        view_sequence: list[dict[str, object]] | None = None,
        view_results: list[object] | None = None,
        repo_settings: dict[str, object] | None = None,
        repo_settings_returncode: int = 0,
        repo_settings_invalid_json: bool = False,
        diff_text: str = "captain-diff\n",
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
            "mergeStateStatus": "CLEAN",
        }
        self.view.setdefault("baseRefOid", "e" * 40)
        self.view.setdefault("headRefName", "feat/captain")
        self.view.setdefault("changedFiles", 1)
        self.view.setdefault(
            "files", [{"path": "src/changed.py", "changeType": "MODIFIED"}]
        )
        self.diff_text = diff_text
        self.view_failure_after_merge = view_failure_after_merge
        self.post_merge_view = post_merge_view or {}
        self.post_merge_view_failures = post_merge_view_failures
        self.merge_returncode = merge_returncode
        self.merge_stdout = merge_stdout
        self.merge_stderr = merge_stderr
        self.merge_updates_view = merge_updates_view
        self.view_invalid_json = view_invalid_json
        self.view_non_mapping = view_non_mapping
        self.merge_exception = merge_exception
        self.view_sequence = list(view_sequence or [])
        self.view_results = list(view_results or [])
        self.repo_settings = repo_settings if repo_settings is not None else {
            "allow_merge_commit": True,
            "allow_squash_merge": True,
            "allow_rebase_merge": True,
        }
        self.repo_settings_returncode = repo_settings_returncode
        self.repo_settings_invalid_json = repo_settings_invalid_json
        self.merged = False
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
        if argv[:1] == ["api"]:
            if self.repo_settings_returncode != 0:
                return {"returncode": self.repo_settings_returncode, "stdout": "", "stderr": "repo policy failed"}
            if self.repo_settings_invalid_json:
                return {"returncode": 0, "stdout": "{", "stderr": ""}
            return {"returncode": 0, "stdout": json.dumps(self.repo_settings), "stderr": ""}
        if argv[:2] == ["pr", "create"]:
            return {"returncode": 0, "stdout": str(self.view["url"]), "stderr": ""}
        if argv[:2] == ["pr", "edit"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if argv[:2] == ["pr", "ready"]:
            self.view["isDraft"] = "--undo" in argv
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if argv[:2] == ["pr", "diff"]:
            return {"returncode": 0, "stdout": self.diff_text, "stderr": ""}
        if argv[:2] == ["pr", "merge"]:
            if self.merge_exception:
                raise RuntimeError("merge runner exploded")
            if self.merge_updates_view:
                self.merged = True
                merged_view = dict(self.view)
                merged_view.update({"state": "MERGED", "mergedAt": "2026-07-08T03:00:00Z", "mergeCommit": {"oid": "d" * 40}})
                merged_view.update(self.post_merge_view)
                self.view = merged_view
            return {"returncode": self.merge_returncode, "stdout": self.merge_stdout, "stderr": self.merge_stderr}
        if argv[:2] == ["pr", "view"]:
            if self.view_results:
                result = self.view_results.pop(0)
                return result  # type: ignore[return-value]
            if self.view_non_mapping:
                return None  # type: ignore[return-value]
            if self.view_invalid_json:
                return {"returncode": 0, "stdout": "{", "stderr": ""}
            if self.view_sequence:
                self.view = dict(self.view_sequence.pop(0))
                self.view.setdefault("baseRefOid", "e" * 40)
                self.view.setdefault("changedFiles", 1)
                self.view.setdefault(
                    "files", [{"path": "src/changed.py", "changeType": "MODIFIED"}]
                )
                return {"returncode": 0, "stdout": json.dumps(self.view), "stderr": ""}
            if self.view_failure_after_merge and self.merged:
                return {"returncode": 1, "stdout": "", "stderr": "transient PR view failure"}
            if self.merged and self.post_merge_view_failures > 0:
                self.post_merge_view_failures -= 1
                return {"returncode": 1, "stdout": "", "stderr": "transient PR view failure"}
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
    def test_orchestration_runners_live_outside_core_grip_surface(self) -> None:
        core_source = inspect.getsource(grips)
        orchestration_source = inspect.getsource(grip_orchestration)

        for name in ("run_mechanic_loop", "run_captain_preflight", "run_captain_run"):
            self.assertIn(f"def {name}", orchestration_source)
        for name in ("_run_mechanic_loop", "_run_captain_preflight", "_run_captain_run"):
            wrapper_source = inspect.getsource(getattr(grips, name))
            self.assertIn("grabowski_grip_orchestration.", wrapper_source)
            self.assertNotIn("for action in actions", wrapper_source)
            self.assertNotIn("executions: list", wrapper_source)
        self.assertIn("for action in actions", orchestration_source)
        self.assertIn("core.run_grip", orchestration_source)
        self.assertIn("core._run_captain_pr_merge", orchestration_source)
        self.assertIn("grabowski_grip_orchestration", core_source)

    def test_list_grips_exposes_core_foundation_specs(self) -> None:
        listed = grips.list_grips()
        specs = {item["name"]: item for item in listed}
        self.assertEqual(
            {
                "branch-publish",
                "captain-preflight",
                "captain-run",
                "connector-snapshot-bind",
                "convergence-assess",
                "convergence-state-classify",
                "gate-evidence-preflight",
                "mechanic-loop",
                "operator-obligation-close",
                "operator-obligation-list",
                "operator-obligation-open",
                "operator-obligation-status",
                "post-merge-sync",
                "pr-check-readiness",
                "pr-create-or-update",
                "repo-orient",
                "runtime-deploy-check",
                "task-attention-decision",
                "task-attention-reconciliation",
                "task-closeout-archive",
                "scout",
                "situation",
                "worktree-ensure",
                "worktree-hygiene-reconcile",
                "worktree-orient",
            },
            set(specs),
        )
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

    def test_task_closeout_archive_grip_runs_typed_archive_surface(self) -> None:
        parameters = {
            "task_id": "a" * 24,
            "expected_attempt": 1,
            "expected_unit": "grabowski-task-test-a1.service",
            "expected_authoritative_unit": "grabowski-task-test-a1.service",
            "expected_argv_sha256": "b" * 64,
            "expected_execution_envelope_sha256": None,
            "expected_lifecycle_receipt_sha256": "c" * 64,
            "minimum_age_seconds": 86400,
            "execution_id": "operator-closeout-1",
        }
        output = {
            "closeout": {"closeout_state": "ready_to_archive"},
            "retention_boundary_unix": 123,
            "archive_segment": {"manifest_sha256": "d" * 64},
            "projection": {"projection_sha256": "e" * 64},
            "resource_release": {"status": "released", "released": []},
        }

        with patch.object(
            task_attention,
            "execute_closeout_archive",
            return_value=output,
        ) as execute:
            result = grips.grip_run(
                "task-closeout-archive",
                parameters,
                profile="operator",
                allow_mutation=True,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("passed", result["output"]["receipt_status"])
        self.assertEqual(parameters, execute.call_args.args[0])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["projection-readback"])
        self.assertEqual("pass", checks["exact-resource-leases-released"])
        self.assertEqual("high", grips.grip_risk_level("task-closeout-archive"))

    def test_task_closeout_archive_grip_reports_conflict_as_blocked(self) -> None:
        parameters = {
            "task_id": "a" * 24,
            "expected_attempt": 1,
            "expected_unit": "grabowski-task-test-a1.service",
            "expected_authoritative_unit": "grabowski-task-test-a1.service",
            "expected_argv_sha256": "b" * 64,
            "expected_execution_envelope_sha256": None,
            "expected_lifecycle_receipt_sha256": "c" * 64,
            "minimum_age_seconds": 86400,
            "execution_id": "operator-closeout-1",
        }

        with patch.object(
            task_attention,
            "execute_closeout_archive",
            side_effect=task_attention.TaskAttentionConflictError(
                "minimum retention is not yet satisfied"
            ),
        ):
            result = grips.grip_run(
                "task-closeout-archive",
                parameters,
                profile="operator",
                allow_mutation=True,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("blocked", result["output"]["receipt_status"])
        self.assertEqual(
            ["task_closeout_archive_conflict"],
            result["output"]["blocked_reasons"],
        )

    def test_grip_list_profile_visibility(self) -> None:
        surface = grips.grip_list(profile="observer")
        by_name = {item["name"]: item for item in surface["grips"]}

        self.assertEqual("observer", surface["profile"])
        self.assertFalse(by_name["branch-publish"]["availability"]["available"])
        self.assertFalse(by_name["captain-preflight"]["availability"]["available"])
        self.assertFalse(by_name["captain-run"]["availability"]["available"])
        self.assertTrue(by_name["repo-orient"]["availability"]["available"])
        self.assertTrue(by_name["operator-obligation-list"]["availability"]["available"])
        self.assertTrue(by_name["operator-obligation-status"]["availability"]["available"])
        self.assertFalse(by_name["operator-obligation-open"]["availability"]["available"])
        self.assertFalse(by_name["operator-obligation-close"]["availability"]["available"])
        self.assertIn("does not expose generic shell execution", surface["non_claims"])

    def test_operator_obligation_grips_enforce_response_end_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(Path(tmp) / "obligations")},
        ):
            open_result = grips.grip_run(
                "operator-obligation-open",
                {
                    "obligation_id": "goo-grip-contract-0001",
                    "objective": "Complete an operator change.",
                    "acceptance": [
                        {"id": "implemented", "description": "The change exists."},
                        {"id": "verified", "description": "Tests passed."},
                    ],
                    "origin": {"thread_id": "thread-17"},
                },
                allow_mutation=True,
            )
            list_open = grips.grip_run(
                "operator-obligation-list",
                {"thread_id": "thread-17"},
            )
            status_open = grips.grip_run(
                "operator-obligation-status",
                {"obligation_id": "goo-grip-contract-0001"},
            )
            invalid_close = grips.grip_run(
                "operator-obligation-close",
                {
                    "obligation_id": "goo-grip-contract-0001",
                    "outcome": "completed",
                    "evidence": [
                        {
                            "acceptance_id": "implemented",
                            "status": "passed",
                            "source": "git",
                            "reference": "commit:a",
                        }
                    ],
                },
                allow_mutation=True,
            )
            close_result = grips.grip_run(
                "operator-obligation-close",
                {
                    "obligation_id": "goo-grip-contract-0001",
                    "outcome": "completed",
                    "evidence": [
                        {
                            "acceptance_id": "implemented",
                            "status": "passed",
                            "source": "git",
                            "reference": "commit:a",
                            "sha256": "a" * 64,
                        },
                        {
                            "acceptance_id": "verified",
                            "status": "passed",
                            "source": "test",
                            "reference": "unit:test",
                            "sha256": "b" * 64,
                        },
                    ],
                },
                allow_mutation=True,
            )

        self.assertEqual("passed", open_result["receipt"]["status"])
        self.assertFalse(open_result["output"]["response_may_end"])
        self.assertEqual("passed", list_open["receipt"]["status"])
        self.assertEqual(1, list_open["output"]["record_count"])
        self.assertTrue(list_open["output"]["attention_required"])
        self.assertEqual("passed", status_open["receipt"]["status"])
        self.assertTrue(status_open["output"]["continuation_required"])
        self.assertEqual("blocked", invalid_close["receipt"]["status"])
        self.assertEqual("passed", close_result["receipt"]["status"])
        self.assertTrue(close_result["output"]["response_may_end"])
        self.assertTrue(close_result["output"]["work_complete"])

    def test_operator_delegation_observer_uses_live_job_status(self) -> None:
        live = {
            "unit": "grabowski-job-live01",
            "final_status": "running",
            "metadata": {
                "job_id": "live01",
                "origin_sha256": "a" * 64,
                "argv_sha256": "b" * 64,
            },
        }
        with patch.object(grips, "_observe_operator_systemd_job", return_value=live):
            result = grips._operator_delegation_observation(
                {"kind": "systemd_job", "id": "grabowski-job-live01"}
            )

        material = {key: value for key, value in result.items() if key != "observation_receipt_sha256"}
        self.assertEqual("grabowski_job_status", result["observation_tool"])
        self.assertEqual("running", result["status"])
        self.assertEqual(grips.sha256_json(material), result["observation_receipt_sha256"])

        terminal = {**live, "final_status": "succeeded"}
        with patch.object(grips, "_observe_operator_systemd_job", return_value=terminal):
            with self.assertRaises(grips.GripPreflightError):
                grips._operator_delegation_observation(
                    {"kind": "systemd_job", "id": "grabowski-job-live01"}
                )

    def test_operator_delegation_observer_validates_task_and_workspace(self) -> None:
        task = {
            "task_id": "task-live01",
            "unit": "grabowski-task-live01",
            "attempt": 1,
            "state": "running",
            "argv_sha256": "c" * 64,
            "updated_at_unix": 1784126804,
        }
        with patch.object(grips, "_observe_operator_task", return_value=task):
            task_result = grips._operator_delegation_observation(
                {"kind": "grabowski_task", "id": "task-live01"}
            )
        self.assertEqual("grabowski_task_status", task_result["observation_tool"])

        workspace = {
            "workspace_id": "gaw-live-workspace-01",
            "creation_state": "ready",
            "expected_base_head": "d" * 40,
            "closed": False,
            "writer_terminal_failure": False,
            "tasks": {
                "writer": {"task_id": "writer-1", "state": "running", "terminal": False},
                "tests": {"task_id": None, "state": "not_started", "terminal": False},
                "review": {"task_id": None, "state": "not_started", "terminal": False},
            },
        }
        with patch.object(
            grips,
            "_observe_operator_workspace",
            return_value=workspace,
        ):
            workspace_result = grips._operator_delegation_observation(
                {"kind": "agent_workspace", "id": "gaw-live-workspace-01"}
            )
        self.assertEqual("grabowski_agent_workspace_status", workspace_result["observation_tool"])
        self.assertEqual("running", workspace_result["status"])

        workspace["tasks"]["writer"]["state"] = "failed"
        workspace["tasks"]["writer"]["terminal"] = True
        workspace["writer_terminal_failure"] = True
        with patch.object(
            grips,
            "_observe_operator_workspace",
            return_value=workspace,
        ):
            with self.assertRaises(grips.GripPreflightError):
                grips._operator_delegation_observation(
                    {"kind": "agent_workspace", "id": "gaw-live-workspace-01"}
                )

    def test_delegated_close_is_live_observed_or_remains_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            "os.environ",
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(Path(tmp) / "obligations")},
        ):
            for obligation_id in ("goo-delegated-live-0001", "goo-delegated-dead-0002"):
                grips.grip_run(
                    "operator-obligation-open",
                    {
                        "obligation_id": obligation_id,
                        "objective": "Continue work durably.",
                        "acceptance": [{"id": "done", "description": "Work is complete."}],
                    },
                    allow_mutation=True,
                )
            observation = {
                "kind": "systemd_job",
                "id": "grabowski-job-live01",
                "observation_tool": "grabowski_job_status",
                "status": "running",
                "observed_at": "2026-07-15T14:00:00Z",
                "identity_sha256": "e" * 64,
            }
            observed = {
                **observation,
                "observation_receipt_sha256": grips.sha256_json(observation),
            }
            with patch.object(grips, "_operator_delegation_observation", return_value=observed):
                delegated = grips.grip_run(
                    "operator-obligation-close",
                    {
                        "obligation_id": "goo-delegated-live-0001",
                        "outcome": "delegated",
                        "evidence": [],
                        "delegation": {"kind": "systemd_job", "id": "grabowski-job-live01"},
                        "next_action": "Observe the durable job.",
                    },
                    allow_mutation=True,
                )
            with patch.object(
                grips,
                "_operator_delegation_observation",
                side_effect=grips.GripPreflightError("job is terminal"),
            ):
                blocked = grips.grip_run(
                    "operator-obligation-close",
                    {
                        "obligation_id": "goo-delegated-dead-0002",
                        "outcome": "delegated",
                        "evidence": [],
                        "delegation": {"kind": "systemd_job", "id": "grabowski-job-dead02"},
                        "next_action": "Observe the durable job.",
                    },
                    allow_mutation=True,
                )
            remaining = grips.grip_run(
                "operator-obligation-status",
                {"obligation_id": "goo-delegated-dead-0002"},
            )

        self.assertEqual("passed", delegated["receipt"]["status"])
        self.assertEqual("delegated", delegated["output"]["state"])
        self.assertFalse(delegated["output"]["work_complete"])
        self.assertEqual("blocked", blocked["receipt"]["status"])
        self.assertFalse(blocked["output"]["response_may_end"])
        self.assertEqual("open", remaining["output"]["state"])

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
        self.assertIn(
            (
                "-c",
                "remote.origin.mirror=false",
                "-c",
                "remote.origin.receivepack=git-receive-pack",
                "-c",
                "push.followTags=false",
                "-c",
                "push.pushOption=",
                "-c",
                "push.gpgSign=false",
                "-c",
                "push.recurseSubmodules=no",
                "push",
                "origin",
                "HEAD:refs/heads/feat/work",
            ),
            fake_git.calls,
        )

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
                        "target": {"repo": "heimgewebe/grabowski", "pr": 1, "base": "main"},
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
        target_change_gate = next(gate for gate in result["output"]["gates"] if gate["id"] == "target-change-record")
        self.assertEqual("blocked", target_change_gate["status"])
        self.assertTrue(any("target_change record is required" in reason for reason in result["output"]["blocked_reasons"]))

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

    def test_mechanic_runtime_deploy_check_binds_target_to_parameters_and_adapter(self) -> None:
        head = "a" * 40
        base_action = {
            "action": "runtime-deploy-check",
            "parameters": {"adapter": "grabowski-self", "expected_head": head},
            "target": {
                "adapter": "grabowski-self",
                "expected_head": head,
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
            },
            "scope": {"operation": "read deployment readiness"},
            "receipt_path": "receipts/mechanic/runtime-deploy-check.json",
        }
        invalid_targets = [
            dict(base_action["target"], adapter="other"),
            dict(base_action["target"], expected_head="b" * 40),
            dict(base_action["target"], service="other-service"),
            dict(base_action["target"], runtime_target="other-host"),
            dict(base_action["target"], repo=None, service="grabowski-mcp", environment=None, runtime_target="heim-pc"),
        ]
        invalid_targets[-1]["service"] = None
        for target in invalid_targets:
            with self.subTest(target=target):
                action = dict(base_action, target=target)
                result = grips.run_grip(
                    "mechanic-loop",
                    {"actions": [action]},
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=FakeGh(),
                )
                self.assertEqual("blocked", result["receipt"]["status"])

    def test_mechanic_runtime_deploy_check_accepts_null_aliases_without_selecting_them(self) -> None:
        head = "a" * 40
        preflight = {
            "adapter": "grabowski-self",
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": head,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        action = {
            "action": "runtime-deploy-check",
            "parameters": {"adapter": "grabowski-self", "expected_head": head},
            "target": {
                "adapter": "grabowski-self",
                "expected_head": head,
                "repo": None,
                "service": "grabowski-mcp",
                "environment": None,
                "runtime_target": "heim-pc",
            },
            "scope": {"operation": "read deployment readiness"},
            "receipt_path": "receipts/mechanic/runtime-deploy-check.json",
        }
        with patch.object(grips, "_runtime_deploy_self_preflight", return_value=preflight):
            result = grips.run_grip(
                "mechanic-loop",
                {"actions": [action]},
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
        self.assertEqual("passed", result["receipt"]["status"])

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
                        "target": {"repo": "heimgewebe/grabowski", "pr": 1, "base": "main"},
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
        recovery_gate = next(gate for gate in result["output"]["gates"] if gate["id"] == "recovery-or-irreversibility")
        self.assertEqual("blocked", recovery_gate["status"])
        self.assertTrue(any("irreversibility must be reversible or irreversible" in reason for reason in result["output"]["blocked_reasons"]))

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
        self.assertTrue(
            result["output"]["next_safe_grip"]["parameters"]["self_review_required"]
        )
        self.assertNotIn("review_decision", result["output"]["next_safe_grip"]["parameters"])

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

    def test_pr_check_readiness_summarizes_work_branch_and_blocks_without_self_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "require_clean": True},
                command_runner=FakeGit(branch="feat/operator-grip-foundation-v1", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review diff binding missing", result["output"]["blocking_reasons"])
        self.assertIn("self-review audit missing", result["output"]["blocking_reasons"])
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
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(),
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertEqual("blocked", result["output"]["verdict"])
        self.assertIn("required checks failing", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["required_checks"])

    def test_pr_check_readiness_blocks_required_self_review_without_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "self_review_required": True,
                    "expected_diff_sha256": "0" * 64,
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit missing", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["self_review_audit"])

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
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(),
                    "review_decision": "APPROVED",
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head="a" * 40),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        self.assertEqual("ready", result["output"]["verdict"])
        self.assertEqual([], result["output"]["blocking_reasons"])

    def test_pr_check_readiness_treats_review_required_decision_as_advisory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "review_decision": "REVIEW_REQUIRED",
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(),
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        self.assertEqual("ready", result["output"]["verdict"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("warn", checks["review_decision"])
        self.assertIn(
            "review_decision is deprecated advisory metadata and never satisfies or blocks self-review",
            result["output"]["warnings"],
        )

    def test_pr_check_readiness_blocks_invalid_self_review_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "self_review_required": True,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": {"kind": "todo"},
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit invalid", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["self_review_audit"])

    def test_pr_check_readiness_blocks_unknown_self_review_tier(self) -> None:
        head = "a" * 40
        audit = {
            "schema_version": 1,
            "kind": "grabowski_self_review_audit",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "generated_at": "2026-07-10T12:00:00+00:00",
            "head_sha": head,
            "diff_sha256": "0" * 64,
            "review_tier": "extreme",
            "gate_verdict": "PASS",
            "self_review_gate_valid": True,
            "minimum_review_iterations": 2,
            "actual_review_iterations": 2,
            "all_findings_triaged": True,
            "material_findings_remaining": 0,
            "residual_risk_accepted": False,
            "residual_risk_reason": "",
            "tuning_signal": "observe",
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "expected_head": head,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_required": True,
                    "self_review_audit": audit,
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
            )

        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit invalid", result["output"]["blocking_reasons"])

    def test_pr_check_readiness_accepts_self_review_audit(self) -> None:
        head = "a" * 40
        audit = {
            "schema_version": 1,
            "kind": "grabowski_self_review_audit",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "generated_at": "2026-07-10T12:00:00+00:00",
            "head_sha": head,
            "diff_sha256": "0" * 64,
            "review_tier": "standard",
            "gate_verdict": "PASS",
            "self_review_gate_valid": True,
            "minimum_review_iterations": 2,
            "actual_review_iterations": 2,
            "all_findings_triaged": True,
            "material_findings_remaining": 0,
            "residual_risk_accepted": False,
            "residual_risk_reason": "",
            "tuning_signal": "observe",
        }
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "expected_head": head,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_required": True,
                    "self_review_audit": audit,
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
            )

        self.assertTrue(result["output"]["ready"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["self_review_audit"])

    def test_pr_check_readiness_binds_audit_to_live_head_without_expected_head_parameter(self) -> None:
        live_head = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(head="b" * 40),
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head=live_head),
            )

        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit invalid", result["output"]["blocking_reasons"])

    def test_pr_check_readiness_ignores_false_self_review_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "self_review_required": False,
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit missing", result["output"]["blocking_reasons"])
        self.assertIn(
            "self_review_required=false is deprecated and ignored; PR readiness always requires self-review",
            result["output"]["warnings"],
        )

    def test_pr_check_readiness_rejects_non_boolean_self_review_switch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {"repo": tmp, "self_review_required": "false"},
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("self_review_required must be a boolean", result["output"]["error"])

    def test_pr_check_readiness_blocks_self_review_for_other_diff(self) -> None:
        head = "a" * 40
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "expected_head": head,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(
                        head=head, diff_sha256="1" * 64
                    ),
                },
                command_runner=FakeGit(branch="feat/work", dirty=False, head=head),
            )

        self.assertFalse(result["output"]["ready"])
        self.assertIn("self-review audit invalid", result["output"]["blocking_reasons"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["self_review_audit"])

    def test_pr_check_readiness_ignores_legacy_external_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-check-readiness",
                {
                    "repo": tmp,
                    "external_review_required": True,
                    "expected_diff_sha256": "0" * 64,
                    "self_review_audit": _self_review_audit(),
                },
                command_runner=FakeGit(branch="feat/work", dirty=False),
            )

        self.assertTrue(result["output"]["ready"])
        self.assertFalse(result["output"]["external_review_required"])
        self.assertIn(
            "external_review_required is deprecated and ignored; use self_review_required",
            result["output"]["warnings"],
        )

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

    def test_branch_publish_rejects_remote_option_injection_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="feat/work")
            for remote in ("--mirror", "-f", ".", "../remote", "https://example.invalid/repo.git"):
                with self.subTest(remote=remote):
                    result = grips.run_grip(
                        "branch-publish",
                        {
                            "repo": tmp,
                            "branch": "feat/work",
                            "expected_head": "a" * 40,
                            "remote": remote,
                        },
                        allow_mutation=True,
                        command_runner=fake,
                    )
                    self.assertEqual("blocked", result["receipt"]["status"])
                    self.assertEqual("preflight", result["receipt"]["phase"])
            self.assertEqual([], fake.calls)

    def test_branch_publish_intrinsically_protects_main_and_master(self) -> None:
        for branch in ("main", "master"):
            with self.subTest(branch=branch), tempfile.TemporaryDirectory() as tmp:
                fake = FakeGit(branch=branch)
                result = grips.run_grip(
                    "branch-publish",
                    {
                        "repo": tmp,
                        "branch": branch,
                        "expected_head": "a" * 40,
                        "protected_branches": ["release"],
                    },
                    allow_mutation=True,
                    command_runner=fake,
                )
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertEqual([], fake.calls)

    def test_branch_publish_overrides_semantic_push_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(branch="feat/work", head="a" * 40)
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )
        self.assertEqual("passed", result["receipt"]["status"])
        push = next(call for call in fake.calls if "push" in call)
        self.assertIn("remote.origin.mirror=false", push)
        self.assertIn("remote.origin.receivepack=git-receive-pack", push)
        self.assertNotIn("remote.origin.push=", push)
        self.assertIn("push.followTags=false", push)
        self.assertIn("push.pushOption=", push)
        self.assertIn("push.gpgSign=false", push)
        self.assertIn("push.recurseSubmodules=no", push)

    def test_branch_publish_rejects_semantic_push_configuration_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(
                branch="feat/work",
                push_config_entries=[("remote.origin.push", "HEAD:refs/heads/other")],
            )
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertFalse(any("push" in call for call in fake.calls))
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["push_configuration"])

    def test_branch_publish_allows_identity_preserving_https_to_ssh_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = FakeGit(
                branch="feat/work",
                configured_urls=["https://github.com/heimgewebe/grabowski.git"],
                effective_push_urls=["git@github.com:heimgewebe/grabowski.git"],
            )
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )
        self.assertEqual("passed", result["receipt"]["status"])
        target_check = next(
            item for item in result["receipt"]["checks"] if item["id"] == "push_remote_target"
        )
        self.assertEqual("pass", target_check["status"])
        self.assertEqual("identity_preserving_ssh_rewrite", target_check["detail"])

    def test_branch_publish_config_query_failure_is_redacted_and_fail_closed(self) -> None:
        secret = "transport-secret-value"

        class FailingConfigGit(FakeGit):
            def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
                if len(argv) == 3 and argv[:2] == ["config", "--get-regexp"]:
                    self.calls.append(tuple(argv))
                    return {"returncode": 2, "stdout": "", "stderr": secret}
                return super().__call__(repo, argv)

        with tempfile.TemporaryDirectory() as tmp:
            fake = FailingConfigGit(branch="feat/work")
            result = grips.run_grip(
                "branch-publish",
                {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                allow_mutation=True,
                command_runner=fake,
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertFalse(any("push" in call for call in fake.calls))
        self.assertNotIn(secret, json.dumps(result, sort_keys=True))
        checks = {item["id"]: item for item in result["receipt"]["checks"]}
        self.assertEqual("fail", checks["push_configuration"]["status"])
        self.assertEqual("git config query failed", checks["push_configuration"]["detail"])

    def test_branch_publish_rejects_multiple_or_rewritten_push_targets(self) -> None:
        cases = (
            {
                "configured_urls": ["git@github.com:heimgewebe/grabowski.git", "git@evil.invalid:other/repo.git"],
                "effective_push_urls": ["git@github.com:heimgewebe/grabowski.git", "git@evil.invalid:other/repo.git"],
                "detail": "configured_url_count_not_one",
            },
            {
                "configured_urls": ["git@github.com:heimgewebe/grabowski.git"],
                "effective_push_urls": ["git@evil.invalid:other/repo.git"],
                "detail": "url_rewrite_changed_identity",
            },
            {
                "configured_urls": ["git@github.com:heimgewebe/grabowski.git"],
                "effective_push_urls": ["root@github.com:heimgewebe/grabowski.git"],
                "detail": "url_rewrite_changed_identity",
            },
        )
        for case in cases:
            with self.subTest(detail=case["detail"]), tempfile.TemporaryDirectory() as tmp:
                fake = FakeGit(
                    branch="feat/work",
                    configured_urls=case["configured_urls"],
                    effective_push_urls=case["effective_push_urls"],
                )
                result = grips.run_grip(
                    "branch-publish",
                    {"repo": tmp, "branch": "feat/work", "expected_head": "a" * 40},
                    allow_mutation=True,
                    command_runner=fake,
                )
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assertFalse(any("push" in call for call in fake.calls))
            target_check = next(
                item for item in result["receipt"]["checks"] if item["id"] == "push_remote_target"
            )
            self.assertEqual("fail", target_check["status"])
            self.assertEqual(case["detail"], target_check["detail"])

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
        list_call = next(call for call in fake_gh.calls if call[:2] == ("pr", "list"))
        self.assertNotIn("--jq", list_call)
        self.assertIn(("pr", "create", "--base", "main", "--head", "feat/work", "--title", "Test", "--body", "Body"), fake_gh.calls)
        self.assertFalse(result["output"]["draft"])
        self.assertIsNone(result["output"]["draft_requested"])
        self.assertFalse(result["output"]["pr"]["isDraft"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["remote_head"])
        self.assertEqual("pass", checks["pr_verify"])
        self.assertEqual("pass", checks["pr_draft_state"])

    def test_pr_create_or_update_creates_ready_when_draft_is_explicitly_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh()
            result = grips.run_grip(
                "pr-create-or-update",
                {
                    "repo": tmp,
                    "branch": "feat/work",
                    "base": "main",
                    "expected_head": "a" * 40,
                    "title": "Ready",
                    "draft": False,
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        create_call = next(call for call in fake_gh.calls if call[:2] == ("pr", "create"))
        self.assertNotIn("--draft", create_call)
        self.assertFalse(result["output"]["draft"])
        self.assertFalse(result["output"]["draft_requested"])
        self.assertFalse(result["output"]["pr"]["isDraft"])

    def test_pr_create_or_update_creates_draft_and_verifies_exact_state(self) -> None:
        view = {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": True,
            "mergeable": "MERGEABLE",
        }
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(view=view)
            result = grips.run_grip(
                "pr-create-or-update",
                {
                    "repo": tmp,
                    "branch": "feat/work",
                    "base": "main",
                    "expected_head": "a" * 40,
                    "title": "Draft",
                    "draft": True,
                },
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["draft"])
        self.assertTrue(result["output"]["draft_requested"])
        self.assertTrue(result["output"]["pr"]["isDraft"])
        self.assertIn(
            (
                "pr",
                "create",
                "--base",
                "main",
                "--head",
                "feat/work",
                "--title",
                "Draft",
                "--body",
                "",
                "--draft",
            ),
            fake_gh.calls,
        )

    def test_pr_create_or_update_updates_existing_matching_pr(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40, "isDraft": False}
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
        self.assertIsNone(result["output"]["draft_requested"])
        self.assertFalse(any(call[:2] == ("pr", "ready") for call in fake_gh.calls))

    def test_pr_create_or_update_preserves_existing_draft_when_parameter_is_omitted(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40, "isDraft": True}
        view = {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": True,
            "mergeable": "MERGEABLE",
        }
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(existing=existing, view=view)
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Preserve"},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["draft"])
        self.assertIsNone(result["output"]["draft_requested"])
        self.assertFalse(any(call[:2] == ("pr", "ready") for call in fake_gh.calls))

    def test_pr_create_or_update_converts_existing_ready_pr_to_draft(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40, "isDraft": False}
        view = {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": False,
            "mergeable": "MERGEABLE",
        }
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(existing=existing, view=view)
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Draft", "draft": True},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertIn(("pr", "ready", "77", "--undo"), fake_gh.calls)
        self.assertTrue(result["output"]["pr"]["isDraft"])

    def test_pr_create_or_update_converts_existing_draft_pr_to_ready(self) -> None:
        existing = {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40, "isDraft": True}
        view = {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "isDraft": True,
            "mergeable": "MERGEABLE",
        }
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh(existing=existing, view=view)
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Ready", "draft": False},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertIn(("pr", "ready", "77"), fake_gh.calls)
        self.assertFalse(result["output"]["pr"]["isDraft"])

    def test_pr_create_or_update_rejects_non_boolean_draft_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_git = FakeGit(branch="feat/work", head="a" * 40)
            fake_gh = FakeGh()
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Invalid", "draft": "true"},
                allow_mutation=True,
                command_runner=fake_git,
                github_runner=fake_gh,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("draft must be a boolean", result["output"]["error"])
        self.assertEqual([], fake_git.calls)
        self.assertEqual([], fake_gh.calls)

    def test_pr_create_or_update_fails_closed_on_draft_readback_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_gh = FakeGh()
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Draft", "draft": True},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=fake_gh,
            )

        self.assertEqual("failed", result["receipt"]["status"])
        self.assertIn("draft verification", result["output"]["error"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["pr_verify"])
        self.assertEqual("fail", checks["pr_draft_state"])
        check_ids = [item["id"] for item in result["receipt"]["checks"]]
        self.assertLess(check_ids.index("pr_verify"), check_ids.index("pr_draft_state"))

    def test_pr_create_or_update_fails_closed_when_draft_readback_is_not_boolean(self) -> None:
        base_view = {
            "number": 77,
            "url": "https://github.com/heimgewebe/grabowski/pull/77",
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/work",
            "headRefOid": "a" * 40,
            "mergeable": "MERGEABLE",
        }
        for label, actual in (("missing", None), ("string", "false")):
            with self.subTest(label=label):
                view = dict(base_view)
                if label != "missing":
                    view["isDraft"] = actual
                with tempfile.TemporaryDirectory() as tmp:
                    result = grips.run_grip(
                        "pr-create-or-update",
                        {
                            "repo": tmp,
                            "branch": "feat/work",
                            "base": "main",
                            "expected_head": "a" * 40,
                            "title": "Ready",
                            "draft": False,
                        },
                        allow_mutation=True,
                        command_runner=FakeGit(branch="feat/work", head="a" * 40),
                        github_runner=FakeGh(view=view),
                    )

                self.assertEqual("failed", result["receipt"]["status"])
                self.assertIn("draft state is unavailable", result["output"]["error"])
                checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
                self.assertEqual("pass", checks["pr_verify"])
                self.assertEqual("fail", checks["pr_draft_state"])

    def test_pr_create_or_update_blocks_ambiguous_open_pr_list(self) -> None:
        existing = [
            {"number": 77, "url": "https://github.com/heimgewebe/grabowski/pull/77", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40},
            {"number": 78, "url": "https://github.com/heimgewebe/grabowski/pull/78", "baseRefName": "main", "headRefName": "feat/work", "headRefOid": "a" * 40},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            result = grips.run_grip(
                "pr-create-or-update",
                {"repo": tmp, "branch": "feat/work", "base": "main", "expected_head": "a" * 40, "title": "Test"},
                allow_mutation=True,
                command_runner=FakeGit(branch="feat/work", head="a" * 40),
                github_runner=FakeGh(existing=existing),
            )

        self.assertEqual("failed", result["receipt"]["status"])
        self.assertIn("multiple open PRs", result["output"]["error"])

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
        self.assertEqual("3", env["GIT_CONFIG_COUNT"])
        self.assertEqual("core.fsmonitor", env["GIT_CONFIG_KEY_0"])
        self.assertEqual("false", env["GIT_CONFIG_VALUE_0"])
        self.assertEqual("core.hooksPath", env["GIT_CONFIG_KEY_1"])
        self.assertEqual("/dev/null", env["GIT_CONFIG_VALUE_1"])
        self.assertEqual("protocol.ext.allow", env["GIT_CONFIG_KEY_2"])
        self.assertEqual("never", env["GIT_CONFIG_VALUE_2"])
        self.assertEqual("ssh", env["GIT_ALLOW_PROTOCOL"])
        self.assertEqual("/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no -oClearAllForwardings=yes", env["GIT_SSH_COMMAND"])
        self.assertEqual("/bin/false", env["GIT_ASKPASS"])
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
        self.assertNotIn("stale_review", categories)
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


class RuntimeDeployGripTests(unittest.TestCase):
    def test_runtime_deploy_check_is_read_only_and_exposed(self) -> None:
        listed = {item["name"]: item for item in grips.list_grips("observer")}
        self.assertIn("runtime-deploy-check", listed)
        self.assertEqual(grips.READ_ONLY, listed["runtime-deploy-check"]["effect"])
        self.assertTrue(listed["runtime-deploy-check"]["availability"]["available"])

    def test_runtime_deploy_check_runs_registered_adapter_preflight_without_mutation(self) -> None:
        expected = "d" * 40
        preflight = {
            "adapter": grips.RUNTIME_DEPLOY_ADAPTER_GRABOWSKI_SELF,
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": expected,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        with patch.object(grips, "_runtime_deploy_self_preflight", return_value=preflight) as check:
            result = grips.run_grip(
                "runtime-deploy-check",
                {"adapter": "grabowski-self", "expected_head": expected},
                command_runner=FakeGit(),
            )
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["ready"])
        self.assertFalse(result["output"]["mutation_attempted"])
        check.assert_called_once_with(expected)

    def test_runtime_deploy_check_blocks_unknown_adapter_and_failed_preflight(self) -> None:
        unknown = grips.run_grip(
            "runtime-deploy-check",
            {"adapter": "shell", "expected_head": "e" * 40},
            command_runner=FakeGit(),
        )
        self.assertEqual("blocked", unknown["receipt"]["status"])
        self.assertIn("not registered", unknown["output"]["error"])

        with patch.object(grips, "_runtime_deploy_self_preflight", side_effect=RuntimeError("canonical checkout is dirty")):
            blocked = grips.run_grip(
                "runtime-deploy-check",
                {"adapter": "grabowski-self", "expected_head": "f" * 40},
                command_runner=FakeGit(),
            )
        self.assertEqual("blocked", blocked["receipt"]["status"])
        self.assertIn("canonical checkout is dirty", blocked["output"]["blocking_reasons"])
        self.assertFalse(blocked["output"]["mutation_attempted"])


class ConnectorSnapshotGripTests(unittest.TestCase):
    def parameters(self) -> dict[str, object]:
        return {
            "client_id": "chatgpt-api-tool",
            "session_id": "session-1",
            "observed_tool_count": 140,
            "observed_names_sha256": "a" * 64,
            "observed_release_id": "release-test",
            "observed_agent_instructions_sha256": "b" * 64,
            "_server_tool_contract": {
                "registered_tool_count": 140,
                "registered_names_sha256": "a" * 64,
                "runtime_matches_deployment_contract": True,
            },
            "_server_runtime": {
                "release_id": "release-test",
                "repo_head": "c" * 40,
            },
            "_server_agent_instructions_sha256": "b" * 64,
        }

    def test_connector_snapshot_bind_is_mutating_and_profile_bound(self) -> None:
        observer = {
            item["name"]: item for item in grips.list_grips("observer")
        }
        operator = {
            item["name"]: item for item in grips.list_grips("operator")
        }
        self.assertEqual(
            grips.MUTATING,
            operator["connector-snapshot-bind"]["effect"],
        )
        self.assertFalse(
            observer["connector-snapshot-bind"]["availability"]["available"]
        )
        self.assertTrue(
            operator["connector-snapshot-bind"]["availability"]["available"]
        )

    def test_connector_snapshot_bind_requires_explicit_mutation(self) -> None:
        result = grips.run_grip(
            "connector-snapshot-bind",
            self.parameters(),
            allow_mutation=False,
        )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual(
            ["mutation_permission_missing"],
            result["output"]["blocked_reasons"],
        )

    def test_connector_snapshot_bind_returns_receipt_bound_match(self) -> None:
        output = {
            "state": "matched",
            "verified": True,
            "mismatches": [],
            "client_declaration_sha256": "d" * 64,
            "receipt_sha256": "e" * 64,
        }
        with patch.object(
            grips.grabowski_client_snapshot,
            "bind_snapshot",
            return_value=output,
        ) as bind:
            result = grips.run_grip(
                "connector-snapshot-bind",
                self.parameters(),
                allow_mutation=True,
            )
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertTrue(result["output"]["verified"])
        bind.assert_called_once()
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["server-tool-contract-bound"])
        self.assertEqual("pass", checks["private-receipt-persisted"])

    def test_connector_snapshot_persistence_failure_is_bounded(self) -> None:
        with patch.object(
            grips.grabowski_client_snapshot,
            "bind_snapshot",
            side_effect=OSError("disk unavailable"),
        ):
            result = grips.run_grip(
                "connector-snapshot-bind",
                self.parameters(),
                allow_mutation=True,
            )
        self.assertEqual("failed", result["receipt"]["status"])
        self.assertIn("persistence failed", result["output"]["error"])
        self.assertNotIn("disk unavailable", result["output"]["error"])

    def test_connector_snapshot_mismatch_blocks_completion(self) -> None:
        output = {
            "state": "mismatch",
            "verified": False,
            "mismatches": ["tool_count"],
            "client_declaration_sha256": "d" * 64,
            "receipt_sha256": "e" * 64,
        }
        with patch.object(
            grips.grabowski_client_snapshot,
            "bind_snapshot",
            return_value=output,
        ):
            result = grips.run_grip(
                "connector-snapshot-bind",
                self.parameters(),
                allow_mutation=True,
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual(
            ["connector_snapshot_mismatch"],
            result["output"]["blocked_reasons"],
        )


CAPTAIN_HEAD = "b" * 40
CAPTAIN_BASE_SHA = "e" * 40
CAPTAIN_DIFF_TEXT = "captain-diff\n"
CAPTAIN_DIFF = hashlib.sha256(CAPTAIN_DIFF_TEXT.encode("utf-8")).hexdigest()


def captain_action(**overrides) -> dict[str, object]:
    action: dict[str, object] = {
        "action": "pr-merge",
        "high_impact": True,
        "role": "captain",
        "target": {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main"},
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
    source = str(overrides.get("status_projection_source", "bureau status-projection"))
    projection = {
        "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
        "source": source,
        "healthy": True,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "run_id": "captain-status-projection-test-run",
    }
    parameters: dict[str, object] = {
        "actions": actions if actions is not None else [captain_action()],
        "status_projection": projection,
        "status_projection_fresh": True,
        "status_projection_source": "bureau status-projection",
        "status_projection_sha256": grips.sha256_json(projection),
        "expected_head": CAPTAIN_HEAD,
        "expected_base_sha": CAPTAIN_BASE_SHA,
        "diff_sha256": CAPTAIN_DIFF,
        "execution_authority": {"granted_by": "alex", "reference": "captain decision record 2026-07-07"},
        "review_evidence": {
            "schema_version": 1,
            "kind": "grabowski_self_review_audit",
            "repo": "heimgewebe/grabowski",
            "pr": 96,
            "generated_at": "2026-07-10T12:00:00+00:00",
            "head_sha": CAPTAIN_HEAD,
            "base_sha": CAPTAIN_BASE_SHA,
            "diff_sha256": CAPTAIN_DIFF,
            "review_tier": "high_critical",
            "minimum_review_iterations": 4,
            "actual_review_iterations": 4,
            "all_findings_triaged": True,
            "finding_count": 0,
            "material_findings_remaining": 0,
            "residual_risk_accepted": False,
            "residual_risk_reason": "",
            "gate_verdict": "PASS",
            "self_review_gate_valid": True,
            "tuning_signal": "observe",
        },
        "ci_evidence": {"state": "passed", "head_sha": CAPTAIN_HEAD, "source": "github-actions"},
        "human_authorization": {"authorized_by": "alex", "statement": "manual captain decision still pending"},
    }
    parameters.update(overrides)
    return parameters


def captain_execution_intent(parameters: dict[str, object], **overrides) -> dict[str, object]:
    actions = grips._captain_actions({"actions": parameters["actions"]}, gate_native_validation=True)
    action = actions[0]
    target = action["target"]
    if action["action"] == "pr-merge":
        expected_base = target.get("base")
    elif action["action"] == "runtime-deploy":
        expected_base = next(
            (
                target.get(key)
                for key in ("environment", "runtime_target")
                if isinstance(target.get(key), str) and target.get(key).strip()
            ),
            None,
        )
    else:
        expected_base = None
    intent: dict[str, object] = {
        "schema_version": grips.CAPTAIN_EXECUTION_INTENT_SCHEMA_VERSION,
        "kind": grips.CAPTAIN_EXECUTION_INTENT_KIND,
        "action": action["action"],
        "target_sha256": action["target_sha256"],
        "expected_head": parameters.get("expected_head"),
        "expected_base": expected_base,
        "evidence_sha256": {
            "actions_sha256": action["actions_sha256"],
            "status_projection_sha256": grips.sha256_json(parameters["status_projection"]),
            "diff_sha256": parameters.get("diff_sha256"),
            "review_evidence_sha256": grips.sha256_json(parameters["review_evidence"]),
            "ci_evidence_sha256": grips.sha256_json(parameters["ci_evidence"]),
            "authorization_sha256": grips._captain_execution_intent_authorization_sha256(parameters),
        },
        "actor": {"id": "alex", "kind": "trusted-owner"},
        "context": {
            "surface": "captain-run",
            "workspace": "bureau-task",
            "lease_owner_id": "captain-test-owner",
        },
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if action["action"] == "pr-merge":
        intent["expected_base_sha"] = parameters.get("expected_base_sha")
    intent.update(overrides)
    return intent


def authorized_captain_run_parameters(**overrides) -> dict[str, object]:
    parameters = captain_parameters(
        trusted_owner_mode=True,
        autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        allow_execution=True,
        **overrides,
    )
    parameters.pop("human_authorization")
    parameters.pop("execution_authority")
    parameters["execution_intent"] = captain_execution_intent(parameters)
    return parameters


class CaptainAuthorityPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self._resource_tempdir = tempfile.TemporaryDirectory()
        self._resource_db_patch = patch.object(
            resources,
            "RESOURCE_DB",
            Path(self._resource_tempdir.name) / "resources.sqlite3",
        )
        self._resource_db_patch.start()

    def tearDown(self) -> None:
        self._resource_db_patch.stop()
        self._resource_tempdir.cleanup()

    def run_captain(self, parameters: dict[str, object]) -> dict[str, object]:
        return grips.grip_run("captain-preflight", parameters, profile="captain", command_runner=FakeGit())

    def gate(self, result: dict[str, object], gate_id: str) -> dict[str, object]:
        return next(item for item in result["output"]["gates"] if item["id"] == gate_id)

    def assert_blocked_gate_reason(self, result: dict[str, object], gate_id: str, fragment: str) -> None:
        gate = self.gate(result, gate_id)
        self.assertEqual("blocked", gate["status"])
        self.assertTrue(
            any(fragment in str(reason) for reason in result["output"]["blocked_reasons"]),
            result["output"]["blocked_reasons"],
        )

    def test_all_gates_pass_yields_only_manual_decision_and_no_execution(self) -> None:
        result = self.run_captain(captain_parameters())

        output = result["output"]
        self.assertEqual([gate["id"] for gate in output["gates"]], list(grips.CAPTAIN_GATE_IDS))
        self.assertTrue(all(gate["status"] == "pass" for gate in output["gates"]))
        self.assertEqual("blocked", output["decision"])
        self.assertEqual("ready_for_manual_captain_decision", output["gate_decision"])
        self.assertTrue(output["manual_decision_candidate"])
        self.assertEqual("blocked", output["status"])
        self.assertEqual("blocked", output["receipt_status"])
        self.assertEqual(["captain_preflight_does_not_execute; use captain-run for execution"], output["blocked_reasons"])
        self.assertEqual("blocked", result["receipt"]["status"])
        action = output["actions"][0]
        self.assertEqual("not-performed", action["execution"])
        self.assertEqual("blocked", action["captain_receipt"]["status"])
        self.assertEqual("blocked", action["captain_receipt"]["decision"])
        self.assertEqual("ready_for_manual_captain_decision", action["captain_receipt"]["gate_decision"])
        self.assertTrue(grips._is_sha256_hex(action["receipt_sha256"]))
        self.assertEqual(action["captain_receipt"]["recovery_path"], "revert the merge commit on main")
        self.assertIn("captain-preflight is read-only", output["why_no_mutation"])

    def test_captain_preflight_exposes_authority_contract(self) -> None:
        result = self.run_captain(captain_parameters())
        contract = result["output"]["authority_contract"]
        self.assertEqual(grips.CAPTAIN_AUTHORITY_CONTRACT_VERSION, contract["schema_version"])
        self.assertEqual("captain-preflight", contract["surface"])
        self.assertIn("evaluation_authority", contract["terms"])
        self.assertIn("execution_authority", contract["terms"])
        execution = contract["terms"]["execution_authority"]
        self.assertEqual("execution_authority", execution["evidence_field"])
        self.assertEqual("execution-authority-present", execution["gate"])
        self.assertIn("allow_execution=true", execution["required_with"])
        self.assertEqual(list(grips.CAPTAIN_GATE_IDS), contract["required_gates"])
        self.assertEqual(sorted(grips.CAPTAIN_EXECUTABLE_ACTIONS), contract["executable_action_allowlist"])
        self.assertIn("allow_execution alone is never sufficient", contract["non_claims"])

    def test_captain_authority_contract_rejects_unknown_surface(self) -> None:
        with self.assertRaises(ValueError):
            grips._captain_authority_contract("captain-rnu")

    def test_captain_preflight_exposes_action_and_target_digests(self) -> None:
        result = self.run_captain(captain_parameters())

        output = result["output"]
        self.assertTrue(grips._is_sha256_hex(output["actions_sha256"]))
        binding_gate = self.gate(result, "evidence-digest-bound")
        self.assertEqual("pass", binding_gate["status"])
        self.assertEqual(output["actions_sha256"], binding_gate["details"]["actions_sha256"])
        action = output["actions"][0]
        self.assertTrue(grips._is_sha256_hex(action["target_sha256"]))
        self.assertTrue(grips._is_sha256_hex(action["action_sha256"]))
        self.assertEqual(output["actions_sha256"], action["actions_sha256"])
        self.assertEqual(0, action["index"])
        self.assertEqual(action["index"], action["envelope"]["index"])
        self.assertEqual(action["target_sha256"], action["envelope"]["target_sha256"])
        self.assertEqual(action["action_sha256"], action["envelope"]["action_sha256"])
        self.assertEqual(output["actions_sha256"], action["envelope"]["actions_sha256"])
        self.assertEqual(action["target_sha256"], action["captain_receipt"]["target_sha256"])
        self.assertEqual(action["action_sha256"], action["captain_receipt"]["action_sha256"])
        self.assertEqual(output["actions_sha256"], action["captain_receipt"]["actions_sha256"])

    def test_captain_evidence_digest_mismatches_fail_closed(self) -> None:
        cases = (
            ("status_projection", "actions_sha256", "status_projection.actions_sha256 mismatch", "status-projection-fresh"),
            ("execution_authority", "target_sha256", "execution_authority.target_sha256 mismatch", "execution-authority-present"),
            ("review_evidence", "actions_sha256", "review_evidence.actions_sha256 mismatch", "review-evidence-present"),
            ("ci_evidence", "action_sha256", "ci_evidence.action_sha256 mismatch", "ci-green"),
            ("human_authorization", "target_sha256", "human_authorization.target_sha256 mismatch", "human-authorization-present"),
        )
        for evidence_name, digest_field, expected_reason, specific_gate in cases:
            with self.subTest(evidence_name=evidence_name, digest_field=digest_field):
                parameters = captain_parameters()
                assert isinstance(parameters[evidence_name], dict)
                parameters[evidence_name][digest_field] = "f" * 64
                if evidence_name == "status_projection":
                    parameters["status_projection_sha256"] = grips.sha256_json(parameters["status_projection"])
                result = self.run_captain(parameters)

                self.assertEqual("blocked", result["output"]["decision"])
                self.assertIn(expected_reason, result["output"]["blocked_reasons"])
                self.assertEqual("blocked", self.gate(result, "evidence-digest-bound")["status"])
                self.assertEqual("blocked", self.gate(result, specific_gate)["status"])

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

    def test_blocks_untrusted_status_projection_source(self) -> None:
        result = self.run_captain(captain_parameters(status_projection_source="caller supplied flag"))

        self.assertIn("status_projection_source_untrusted", result["output"]["blocked_reasons"])
        self.assertFalse(result["output"]["status_projection"]["source_allowlisted"])
        self.assertFalse(result["output"]["status_projection"]["source_trusted"])
        self.assertIn("bureau status-projection", result["output"]["status_projection"]["allowlisted_sources"])

    def test_reports_allowlisted_status_projection_source(self) -> None:
        result = self.run_captain(captain_parameters())

        status_projection = result["output"]["status_projection"]
        self.assertTrue(status_projection["source_allowlisted"])
        self.assertTrue(status_projection["source_trusted"])
        self.assertEqual("bureau status-projection", status_projection["source"])
        self.assertIn("bureau status-projection", status_projection["allowlisted_sources"])

    def test_reports_run_id_status_projection_replay_reference_kind(self) -> None:
        result = self.run_captain(captain_parameters())

        status_projection = result["output"]["status_projection"]
        self.assertEqual("captain-status-projection-test-run", status_projection["replay_reference"])
        self.assertEqual("run_id", status_projection["replay_reference_kind"])

    def test_blocks_status_projection_source_swap_after_hash(self) -> None:
        parameters = captain_parameters(status_projection_source="caller supplied flag")
        parameters["status_projection_source"] = "bureau status-projection"

        result = self.run_captain(parameters)

        self.assertIn("status_projection_source_mismatch", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", self.gate(result, "status-projection-fresh")["status"])

    def test_accepts_small_status_projection_clock_skew(self) -> None:
        generated_at = datetime.now(timezone.utc) + timedelta(seconds=60)
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": generated_at.isoformat(),
            "run_id": "clock-skew-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertNotIn("status_projection_generated_at_in_future", result["output"]["blocked_reasons"])
        self.assertEqual("pass", self.gate(result, "status-projection-fresh")["status"])

    def test_blocks_invalid_status_projection_schema_and_required_fields(self) -> None:
        projection = {"schema_version": 999, "source": "bureau status-projection", "generated_at": datetime.now(timezone.utc).isoformat(), "run_id": "run"}
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_schema_version_invalid", result["output"]["blocked_reasons"])
        self.assertIn("status_projection_healthy_missing", result["output"]["blocked_reasons"])

    def test_blocks_invalid_status_projection_healthy_type(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": "yes",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": "run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_healthy_invalid", result["output"]["blocked_reasons"])

    def test_blocks_unhealthy_status_projection(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": False,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": "unhealthy-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_unhealthy", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", self.gate(result, "status-projection-fresh")["status"])

    def test_blocks_naive_generated_at_status_projection(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "run_id": "naive-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_generated_at_invalid", result["output"]["blocked_reasons"])

    def test_blocks_status_projection_generated_too_far_in_future(self) -> None:
        generated_at = datetime.now(timezone.utc) + timedelta(
            seconds=grips.CAPTAIN_STATUS_PROJECTION_CLOCK_SKEW_TOLERANCE_SECONDS + 30
        )
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": generated_at.isoformat(),
            "run_id": "future-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_generated_at_in_future", result["output"]["blocked_reasons"])

    def test_accepts_numeric_unix_timestamp_status_projection_generated_at(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).timestamp(),
            "run_id": "numeric-generated-at-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertNotIn("status_projection_generated_at_invalid", result["output"]["blocked_reasons"])
        self.assertTrue(result["output"]["status_projection"]["generated_at"].endswith("Z"))
        self.assertEqual("pass", self.gate(result, "status-projection-fresh")["status"])

    def test_blocks_boolean_status_projection_generated_at(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": True,
            "run_id": "boolean-generated-at-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_generated_at_invalid", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", self.gate(result, "status-projection-fresh")["status"])

    def test_blocks_stale_generated_at_status_projection(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": "2026-07-07T12:00:00Z",
            "run_id": "old-run",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_stale_by_generated_at", result["output"]["blocked_reasons"])

    def test_blocks_status_projection_without_replay_reference(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertIn("status_projection_replay_reference_missing", result["output"]["blocked_reasons"])

    def test_accepts_nonce_when_status_projection_run_id_is_blank(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": "   ",
            "nonce": "nonce-ok",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertNotIn("status_projection_replay_reference_missing", result["output"]["blocked_reasons"])
        self.assertEqual("nonce-ok", result["output"]["status_projection"]["replay_reference"])
        self.assertEqual("nonce", result["output"]["status_projection"]["replay_reference_kind"])
        self.assertEqual("pass", self.gate(result, "status-projection-fresh")["status"])

    def test_accepts_receipt_ref_when_status_projection_run_id_and_nonce_are_blank(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": "   ",
            "nonce": "   ",
            "receipt_ref": "receipt-ok",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertNotIn("status_projection_replay_reference_missing", result["output"]["blocked_reasons"])
        self.assertEqual("receipt-ok", result["output"]["status_projection"]["replay_reference"])
        self.assertEqual("receipt_ref", result["output"]["status_projection"]["replay_reference_kind"])
        self.assertEqual("pass", self.gate(result, "status-projection-fresh")["status"])

    def test_prefers_receipt_ref_status_projection_replay_reference(self) -> None:
        projection = {
            "schema_version": grips.CAPTAIN_STATUS_PROJECTION_SCHEMA_VERSION,
            "source": "bureau status-projection",
            "healthy": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": "run-ok",
            "nonce": "nonce-ok",
            "receipt_ref": "receipt-ok",
        }
        result = self.run_captain(captain_parameters(status_projection=projection, status_projection_sha256=grips.sha256_json(projection)))

        self.assertNotIn("status_projection_replay_reference_missing", result["output"]["blocked_reasons"])
        self.assertEqual("receipt-ok", result["output"]["status_projection"]["replay_reference"])
        self.assertEqual("receipt_ref", result["output"]["status_projection"]["replay_reference_kind"])
        self.assertEqual("pass", self.gate(result, "status-projection-fresh")["status"])

    def test_captain_run_without_allow_mutation_exposes_authority_contract(self) -> None:
        result = grips.grip_run(
            "captain-run",
            captain_parameters(),
            profile="captain",
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("mutating grip requires allow_mutation=true", result["output"]["error"])
        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn("mutation_permission_missing", result["output"]["blocked_reasons"])
        self.assertTrue(result["output"]["requires_allow_mutation"])
        contract = result["output"]["authority_contract"]
        self.assertEqual("captain-run", contract["surface"])
        self.assertIn("execution_authority evidence alone is never sufficient", contract["non_claims"])

    def test_captain_run_exposes_execution_authority_contract_when_blocked(self) -> None:
        parameters = captain_parameters()
        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )
        contract = result["output"]["authority_contract"]
        self.assertEqual("captain-run", contract["surface"])
        self.assertIn("allow_execution must be true", contract["release_conditions"]["captain_run"])
        self.assertIn("execution_authority evidence alone is never sufficient", contract["non_claims"])
        self.assertIn("allow_execution_required", result["output"]["blocked_reasons"])

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

    def test_blocks_review_evidence_for_other_base_sha(self) -> None:
        parameters = captain_parameters()
        parameters["review_evidence"]["base_sha"] = "a" * 40
        result = self.run_captain(parameters)

        gate = self.gate(result, "review-evidence-present")
        self.assertEqual("blocked", gate["status"])
        self.assertIn("base_sha does not match expected_base_sha", result["output"]["blocked_reasons"])

    def test_expected_base_sha_is_required_for_captain_review_binding(self) -> None:
        parameters = captain_parameters()
        parameters.pop("expected_base_sha")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", self.gate(result, "review-evidence-present")["status"])
        self.assertIn("expected_base_sha_missing_or_invalid", result["output"]["blocked_reasons"])

    def test_blocks_review_evidence_for_other_repository(self) -> None:
        parameters = captain_parameters()
        parameters["review_evidence"]["repo"] = "heimgewebe/weltgewebe"
        result = self.run_captain(parameters)

        gate = self.gate(result, "review-evidence-present")
        self.assertEqual("blocked", gate["status"])
        self.assertIn("repo does not match PR target", result["output"]["blocked_reasons"])

    def test_blocks_review_evidence_for_other_pr(self) -> None:
        parameters = captain_parameters()
        parameters["review_evidence"]["pr"] = 97
        result = self.run_captain(parameters)

        gate = self.gate(result, "review-evidence-present")
        self.assertEqual("blocked", gate["status"])
        self.assertIn("pr does not match PR target", result["output"]["blocked_reasons"])

    def test_expected_head_is_required_for_captain_evidence_binding(self) -> None:
        parameters = captain_parameters()
        parameters.pop("expected_head")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", self.gate(result, "review-evidence-present")["status"])
        self.assertIn("expected_head_missing_or_invalid", result["output"]["blocked_reasons"])
        self.assertEqual("blocked", result["output"]["decision"])

    def test_ci_head_must_match_expected_head(self) -> None:
        result = self.run_captain(
            captain_parameters(ci_evidence={"state": "passed", "head_sha": "e" * 40, "source": "github-actions"})
        )

        self.assertEqual("blocked", self.gate(result, "ci-green")["status"])
        self.assertIn("ci_evidence.head_sha does not match expected_head", result["output"]["blocked_reasons"])

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

    def test_trusted_owner_autonomy_replaces_per_action_human_authorization_for_reversible_actions(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        result = self.run_captain(parameters)

        self.assertEqual("ready_for_autonomous_captain_execution", result["output"]["gate_decision"])
        self.assertTrue(result["output"]["autonomous_execution_candidate"])
        self.assertFalse(result["output"]["manual_decision_candidate"])
        self.assertNotIn("human_authorization_missing", result["output"]["blocked_reasons"])
        self.assertEqual("pass", self.gate(result, "autonomy-policy")["status"])
        self.assertEqual("pass", self.gate(result, "human-authorization-present")["status"])

    def test_trusted_owner_autonomy_does_not_cover_irreversible_actions(self) -> None:
        action = captain_action(
            risk={"risk_level": "high", "irreversibility": "irreversible"},
            irreversibility_record={"reason": "no automatic rollback"},
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", result["output"]["gate_decision"])
        self.assertIn("irreversible_action_requires_human_authorization", result["output"]["blocked_reasons"])
        self.assertIn("human_authorization_missing", result["output"]["blocked_reasons"])

    def test_trusted_owner_autonomy_requires_explicit_reversible_record(self) -> None:
        action = captain_action(risk={"risk_level": "high", "recovery_path": "revert the merge commit on main"})
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", result["output"]["gate_decision"])
        self.assertIn("ambiguous_reversibility_requires_human_authorization", result["output"]["blocked_reasons"])
        self.assertIn("human_authorization_missing", result["output"]["blocked_reasons"])

    def test_trusted_owner_autonomy_does_not_signal_autonomous_execution_without_executor(self) -> None:
        action = captain_action(
            action="service-restart",
            target={"host": "heim-pc", "unit": "grabowski-mcp.service"},
            receipt_path="receipts/captain/service-restart.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        result = self.run_captain(parameters)

        self.assertEqual("blocked", result["output"]["gate_decision"])
        self.assertFalse(result["output"]["autonomous_execution_candidate"])
        self.assertIn("captain_executor_unavailable:service-restart", result["output"]["blocked_reasons"])

    def test_captain_run_merges_pr_when_trusted_owner_gates_pass(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(view={
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        })

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("passed", result["status"])
        self.assertEqual(result["receipt"]["receipt_sha256"], result["receipt_sha256"])
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("executed", result["output"]["decision"])
        self.assertEqual("passed", result["output"]["actions"][0]["captain_receipt"]["status"])
        self.assertEqual("performed", result["output"]["actions"][0]["execution"])
        self.assertNotIn(
            "automatic_merge_authority",
            result["output"]["actions"][0]["captain_receipt"]["does_not_establish"],
        )
        merge_calls = [call for call in gh.calls if call[:2] == ("pr", "merge")]
        self.assertEqual(1, len(merge_calls))
        self.assertIn("--match-head-commit", merge_calls[0])
        self.assertIn(CAPTAIN_HEAD, merge_calls[0])
        self.assertIn("--merge", merge_calls[0])
        execution = result["output"]["executions"][0]
        self.assertEqual("merge", execution["merge_policy"]["selected_method"])
        self.assertEqual(["merge", "squash", "rebase"], execution["merge_policy"]["allowed_methods"])

    def test_captain_run_uses_allowed_repository_merge_method(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            repo_settings={
                "allow_merge_commit": False,
                "allow_squash_merge": True,
                "allow_rebase_merge": True,
            },
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("passed", result["receipt"]["status"])
        execution = result["output"]["executions"][0]
        self.assertEqual("squash", execution["merge_policy"]["selected_method"])
        self.assertEqual(["squash", "rebase"], execution["merge_policy"]["allowed_methods"])
        merge_call = next(call for call in gh.calls if call[:2] == ("pr", "merge"))
        self.assertIn("--squash", merge_call)
        self.assertNotIn("--merge", merge_call)

    def test_captain_run_blocks_when_repository_merge_policy_is_unusable(self) -> None:
        matching_view = {
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        }
        for gh, expected in (
            (FakeGh(view=matching_view, repo_settings_returncode=1), "repository_merge_policy_query_failed"),
            (FakeGh(view=matching_view, repo_settings_invalid_json=True), "repository_merge_policy_invalid_json"),
            (
                FakeGh(view=matching_view, repo_settings={
                    "allow_merge_commit": True,
                    "allow_squash_merge": False,
                }),
                "repository_merge_policy_invalid_fields:allow_rebase_merge",
            ),
            (
                FakeGh(view=matching_view, repo_settings={
                    "allow_merge_commit": False,
                    "allow_squash_merge": False,
                    "allow_rebase_merge": False,
                }),
                "repository_all_merge_methods_disabled",
            ),
        ):
            with self.subTest(expected=expected):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertEqual("blocked", result["output"]["decision"])
                execution = result["output"]["executions"][0]
                self.assertFalse(execution["execution_invoked"])
                self.assertFalse(execution["execution_attempted"])
                self.assertIn(expected, execution["verification_error"])
                self.assertFalse(any(call[:2] == ("pr", "merge") for call in gh.calls))

    def test_captain_run_schedules_registered_grabowski_self_deploy_without_claiming_completion(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
            },
            scope={
                "allowed_effects": ["schedule one verified Grabowski self-deployment"],
                "forbidden_effects": ["arbitrary shell", "other services", "other hosts"],
                "boundaries": "single local Grabowski runtime",
                "max_targets": 1,
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "inspect the scheduled job and roll back to the previous release",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        preflight = {
            "adapter": "grabowski-self",
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "canonical-main",
            "source_identity_sha256": "e" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        unit = "grabowski-job-abcdef012345"
        job_dir = Path(preflight["job_root"]) / unit
        expected_argv_sha256 = "d" * 64
        command = [
            "/usr/bin/python3",
            preflight["runner"],
            "--repo",
            preflight["repository"],
            "--expected-head",
            CAPTAIN_HEAD,
            "--delay-seconds",
            "8",
        ]
        schedule = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": CAPTAIN_HEAD,
            "requested_delay_seconds": 8,
            "delay_seconds": 8,
            "unit": unit,
            "argv_sha256": expected_argv_sha256,
            "source_identity_sha256": "e" * 64,
            "source_identity": {"identity_sha256": "e" * 64},
            "metadata_path": str(job_dir / "metadata.json"),
            "stdout_path": str(job_dir / "stdout.log"),
            "stderr_path": str(job_dir / "stderr.log"),
            "expected_connector_disconnect": True,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }

        with patch.object(grips, "_runtime_deploy_self_preflight", return_value=preflight) as check, patch.object(
            grips, "_runtime_deploy_self_schedule", return_value=schedule
        ) as scheduler, patch.object(
            grips, "_runtime_deploy_self_expected_argv_sha256", return_value=expected_argv_sha256
        ) as hash_check:
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("scheduled", result["output"]["decision"])
        self.assertEqual("scheduled", result["output"]["actions"][0]["execution"])
        self.assertTrue(result["output"]["execution_intent"]["valid"])
        self.assertEqual("heim-pc", result["output"]["execution_intent"]["expected_base"])
        execution = result["output"]["executions"][0]
        self.assertTrue(execution["deployment_scheduled"])
        self.assertTrue(execution["new_job_registered"])
        self.assertTrue(execution["local_mutation_observed"])
        self.assertFalse(execution["remote_mutation_observed"])
        self.assertFalse(execution["deployment_completion_verified"])
        self.assertEqual("schedule-registration", execution["verification_scope"])
        self.assertEqual("grabowski-job-abcdef012345", execution["next_verification"]["unit"])
        check.assert_called_once_with(CAPTAIN_HEAD)
        scheduler.assert_called_once_with(CAPTAIN_HEAD, 8)
        hash_check.assert_called_once_with(preflight, CAPTAIN_HEAD, 8)

    def test_captain_run_marks_local_mutation_unknown_when_scheduler_receipt_is_invalid(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "inspect durable job records before retrying",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        preflight = {
            "adapter": "grabowski-self",
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "canonical-main",
            "source_identity_sha256": "e" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        invalid_schedule = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": CAPTAIN_HEAD,
            "requested_delay_seconds": 8,
            "delay_seconds": 8,
            "unit": "grabowski-job-abcdef012345",
            "argv_sha256": "d" * 64,
            "source_identity_sha256": "e" * 64,
            "source_identity": {"identity_sha256": "e" * 64},
            "metadata_path": "/wrong/metadata.json",
            "stdout_path": "/wrong/stdout.log",
            "stderr_path": "/wrong/stderr.log",
            "expected_connector_disconnect": True,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        with patch.object(grips, "_runtime_deploy_self_preflight", return_value=preflight), patch.object(
            grips, "_runtime_deploy_self_schedule", return_value=invalid_schedule
        ), patch.object(
            grips, "_runtime_deploy_self_expected_argv_sha256", return_value="d" * 64
        ):
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
        execution = result["output"]["executions"][0]
        self.assertEqual("failed", result["receipt"]["status"])
        self.assertTrue(execution["mutation_outcome_unknown"])
        self.assertTrue(execution["local_mutation_outcome_unknown"])
        self.assertFalse(execution["local_mutation_observed"])

    def test_captain_run_preserves_unknown_mutation_outcome_when_scheduler_raises(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "inspect durable job records before retrying",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        preflight = {
            "adapter": "grabowski-self",
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "canonical-main",
            "source_identity_sha256": "e" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        with patch.object(grips, "_runtime_deploy_self_preflight", return_value=preflight), patch.object(
            grips, "_runtime_deploy_self_schedule", side_effect=RuntimeError("audit append failed after job start")
        ):
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )

        self.assertEqual("failed", result["receipt"]["status"])
        self.assertEqual("verification_failed_after_execution", result["output"]["decision"])
        execution = result["output"]["executions"][0]
        self.assertTrue(execution["execution_invoked"])
        self.assertTrue(execution["execution_attempted"])
        self.assertFalse(execution["command_returned"])
        self.assertTrue(execution["mutation_outcome_unknown"])
        self.assertTrue(execution["local_mutation_outcome_unknown"])
        self.assertIn("may already have been registered", execution["verification_error"])

    def test_runtime_deploy_schedule_validation_binds_delay_and_unit_namespace(self) -> None:
        unit = "grabowski-job-abcdef012345"
        job_root = Path.home() / ".local/state/grabowski/jobs"
        job_prefix = "grabowski-job-"
        job_dir = job_root / unit
        runner = "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py"
        repository = "/home/alex/repos/grabowski"
        preflight = {
            "repository": repository,
            "runner": runner,
            "job_root": str(job_root),
            "job_prefix": job_prefix,
        }
        expected_argv_sha256 = "d" * 64
        base = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": CAPTAIN_HEAD,
            "requested_delay_seconds": 8,
            "delay_seconds": 8,
            "unit": unit,
            "argv_sha256": expected_argv_sha256,
            "source_identity_sha256": "e" * 64,
            "source_identity": {"identity_sha256": "e" * 64},
            "metadata_path": str(job_dir / "metadata.json"),
            "stdout_path": str(job_dir / "stdout.log"),
            "stderr_path": str(job_dir / "stderr.log"),
            "expected_connector_disconnect": True,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        self.assertEqual(
            [],
            grips._runtime_deploy_schedule_errors(
                base,
                expected_head=CAPTAIN_HEAD,
                expected_delay_seconds=8,
                expected_argv_sha256=expected_argv_sha256,
                expected_job_root=str(job_root),
                expected_job_prefix=job_prefix,
                expected_source_identity_sha256="e" * 64,
            ),
        )
        drifted = dict(
            base,
            requested_delay_seconds=5,
            delay_seconds=5,
            unit="foreign.service",
            argv_sha256="invalid",
            metadata_path="/state/meta",
        )
        errors = grips._runtime_deploy_schedule_errors(
            drifted,
            expected_head=CAPTAIN_HEAD,
            expected_delay_seconds=8,
            expected_argv_sha256=expected_argv_sha256,
            expected_job_root=str(job_root),
            expected_job_prefix=job_prefix,
            expected_source_identity_sha256="e" * 64,
        )
        self.assertIn("runtime_deploy_schedule_requested_delay_mismatch", errors)
        self.assertIn("runtime_deploy_schedule_unit_missing_or_unbound", errors)
        self.assertIn("runtime_deploy_schedule_argv_hash_missing_or_invalid", errors)
        self.assertIn("runtime_deploy_schedule_paths_not_bound_to_unit", errors)
        wrong_hash = dict(base, argv_sha256="0" * 64)
        hash_errors = grips._runtime_deploy_schedule_errors(
            wrong_hash,
            expected_head=CAPTAIN_HEAD,
            expected_delay_seconds=8,
            expected_argv_sha256=expected_argv_sha256,
            expected_job_root=str(job_root),
            expected_job_prefix=job_prefix,
            expected_source_identity_sha256="e" * 64,
        )
        self.assertIn("runtime_deploy_schedule_argv_hash_mismatch", hash_errors)


    def test_captain_run_blocks_runtime_deploy_target_without_registered_adapter(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        result = self.run_captain(captain_parameters([action]))
        self.assert_blocked_gate_reason(result, "target-bound", "target.adapter")


    def test_captain_run_preserves_execution_receipt_when_post_merge_verification_fails(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            view_failure_after_merge=True,
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("failed", result["receipt"]["status"])
        self.assertEqual("verification_failed_after_execution", result["output"]["decision"])
        self.assertEqual("performed", result["output"]["actions"][0]["execution"])
        self.assertEqual("failed", result["output"]["actions"][0]["captain_receipt"]["status"])
        self.assertFalse(result["output"]["executions"][0]["verification_passed"])
        self.assertEqual("transient PR view failure", result["output"]["executions"][0]["verification_error"])
        self.assertEqual("merged", result["output"]["executions"][0]["merge_stdout"])
        verification_checks = [check for check in result["receipt"]["checks"] if check["id"] == "post-execution-verification"]
        self.assertEqual("fail", verification_checks[-1]["status"])
        self.assertTrue(grips._is_sha256_hex(result["output"]["actions"][0]["receipt_sha256"]))

    def test_captain_run_blocks_multiple_actions_before_execution(self) -> None:
        parameters = captain_parameters(
            [captain_action(), captain_action(target={"repo": "heimgewebe/grabowski", "pr": 97, "base": "main"})],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        gh = FakeGh()

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("captain_run_supports_exactly_one_action_in_v1", result["output"]["blocked_reasons"])
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_blocks_pr_merge_preflight_drift_before_execution(self) -> None:
        cases = (
            ({"baseRefName": "develop"}, "pr_base_does_not_match_expected_base_before_execution"),
            ({"isDraft": True}, "pr_draft_state_not_confirmed_before_execution"),
            ({"state": "CLOSED"}, "pr_not_open_before_execution"),
            ({"state": "MERGED"}, "pr_already_merged_before_execution"),
            ({"headRefOid": "a" * 40}, "pr_head_does_not_match_expected_head_before_execution"),
            ({"mergeStateStatus": "DIRTY"}, "pr_merge_state_not_clean_before_execution"),
            ({"mergeable": "CONFLICTING"}, "pr_mergeable_not_confirmed_before_execution"),
        )
        for view_patch, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                view = {
                    "number": 96,
                    "state": "OPEN",
                    "baseRefName": "main",
                    "headRefName": "feat/captain",
                    "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                }
                view.update(view_patch)
                gh = FakeGh(view=view)

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertIn(expected_reason, result["output"]["blocked_reasons"])
                self.assertFalse(result["output"]["executions"][0]["execution_attempted"])
                self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_blocks_unknown_and_missing_pr_view_fields_before_execution(self) -> None:
        cases = (
            ({"mergeable": "UNKNOWN"}, "pr_mergeable_not_confirmed_before_execution"),
            ({"mergeStateStatus": "UNKNOWN"}, "pr_merge_state_not_clean_before_execution"),
            ({"isDraft": None}, "pr_draft_state_not_confirmed_before_execution"),
        )
        for view_patch, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                view = {
                    "number": 96,
                    "state": "OPEN",
                    "baseRefName": "main",
                    "headRefName": "feat/captain",
                    "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                }
                view.update(view_patch)
                gh = FakeGh(view=view)

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertIn(expected_reason, result["output"]["blocked_reasons"])
                self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

        for missing_key in ("isDraft", "mergeable", "mergeStateStatus"):
            with self.subTest(missing_key=missing_key):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                view = {
                    "number": 96,
                    "state": "OPEN",
                    "baseRefName": "main",
                    "headRefName": "feat/captain",
                    "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                }
                view.pop(missing_key)
                gh = FakeGh(view=view)

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertIn(f"pr_view_missing_{missing_key}", result["output"]["blocked_reasons"])
                self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_settles_unknown_preflight_state_before_execution(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        unknown_view = {
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "UNKNOWN",
            "mergeStateStatus": "UNKNOWN",
        }
        clean_view = dict(unknown_view, mergeable="MERGEABLE", mergeStateStatus="CLEAN")
        gh = FakeGh(view_sequence=[unknown_view, clean_view])
        sleeps: list[float] = []

        original_sleep = grips._captain_sleep
        try:
            grips._captain_sleep = sleeps.append
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=gh,
            )
        finally:
            grips._captain_sleep = original_sleep

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([0.5], sleeps)
        self.assertEqual(2, result["output"]["executions"][0]["preflight_view_summary"]["attempt_count"])

    def test_captain_run_blocks_persistent_unknown_preflight_state(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        unknown_view = {
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "UNKNOWN",
            "mergeStateStatus": "UNKNOWN",
        }
        gh = FakeGh(view=unknown_view)
        sleeps: list[float] = []

        original_sleep = grips._captain_sleep
        try:
            grips._captain_sleep = sleeps.append
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=gh,
            )
        finally:
            grips._captain_sleep = original_sleep

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("pr_mergeable_not_confirmed_before_execution", result["output"]["blocked_reasons"])
        self.assertEqual([0.5, 1.0], sleeps)
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_handles_malformed_and_non_mapping_pr_view(self) -> None:
        cases = (
            (FakeGh(view_invalid_json=True), "invalid JSON"),
            (FakeGh(view_non_mapping=True), "command runner returned non-object result"),
        )
        for gh, expected in cases:
            with self.subTest(expected=expected):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertIn(expected, result["output"]["executions"][0]["verification_error"])

    def test_bounded_command_output_keeps_prefix_for_tiny_limit_and_hashes_bytes(self) -> None:
        self.assertEqual("abcdefghij", grips._bounded_command_output("abcdefghijklmnop", limit=10))
        raw_stdout = ("prefix-".encode() + b"\xff" * (grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT + 20))
        info = grips._command_result_info({"returncode": 1, "stdout": raw_stdout, "stderr": b""})

        self.assertTrue(info["stdout_truncated"])
        self.assertLessEqual(len(info["stdout"]), grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT)
        self.assertEqual(hashlib.sha256(raw_stdout).hexdigest(), info["stdout_sha256"])

    def test_captain_run_retries_transient_preflight_view_failure_before_execution(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        clean_view = {
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        }
        gh = FakeGh(view=clean_view, view_results=[{"returncode": 0, "stdout": "{", "stderr": ""}])
        sleeps: list[float] = []

        original_sleep = grips._captain_sleep
        try:
            grips._captain_sleep = sleeps.append
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=gh,
            )
        finally:
            grips._captain_sleep = original_sleep

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([0.5], sleeps)
        self.assertEqual(2, result["output"]["executions"][0]["preflight_view_summary"]["attempt_count"])
        self.assertTrue([call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_does_not_retry_unknown_state_with_hard_preflight_blocker(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        hard_blocked_view = {
            "number": 96,
            "state": "OPEN",
            "baseRefName": "release/other",
            "headRefName": "feat/captain",
            "headRefOid": "a" * 40,
            "isDraft": False,
            "mergeable": "UNKNOWN",
            "mergeStateStatus": "UNKNOWN",
        }
        gh = FakeGh(view=hard_blocked_view)
        sleeps: list[float] = []

        original_sleep = grips._captain_sleep
        try:
            grips._captain_sleep = sleeps.append
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=gh,
            )
        finally:
            grips._captain_sleep = original_sleep

        self.assertEqual("blocked", result["receipt"]["status"])
        execution = result["output"]["executions"][0]
        self.assertEqual(1, execution["preflight_view_summary"]["attempt_count"])
        self.assertIn("pr_head_does_not_match_expected_head_before_execution", execution["preflight_errors"])
        self.assertIn("pr_base_does_not_match_expected_base_before_execution", execution["preflight_errors"])
        self.assertEqual([], sleeps)
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_requires_post_merge_head_confirmation(self) -> None:
        for post_merge_view in ({"headRefOid": None}, {"headRefOid": "a" * 40}):
            with self.subTest(post_merge_view=post_merge_view):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                gh = FakeGh(
                    view={
                        "number": 96,
                        "state": "OPEN",
                        "baseRefName": "main",
                        "headRefName": "feat/captain",
                        "headRefOid": CAPTAIN_HEAD,
                        "isDraft": False,
                        "mergeable": "MERGEABLE",
                        "mergeStateStatus": "CLEAN",
                    },
                    post_merge_view=post_merge_view,
                )

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("failed", result["receipt"]["status"])
                self.assertEqual("verification_failed_after_execution", result["output"]["decision"])
                self.assertEqual("merged_pr_head_does_not_match_expected_head", result["output"]["executions"][0]["verification_error"])
                verification_checks = [check for check in result["receipt"]["checks"] if check["id"] == "post-execution-verification"]
                self.assertEqual("fail", verification_checks[-1]["status"])

    def test_captain_run_retries_transient_post_merge_view(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            post_merge_view_failures=1,
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual(2, len(result["output"]["executions"][0]["verify_view_attempts"]))
        verification_checks = [check for check in result["receipt"]["checks"] if check["id"] == "post-execution-verification"]
        self.assertEqual("pass", verification_checks[-1]["status"])

    def test_captain_run_records_merge_command_failure_without_losing_receipt(self) -> None:
        for merge_updates_view, expected_reason in (
            (False, "pr_not_merged_after_execution"),
            (True, "merge_command_failed_but_pr_observed_merged"),
        ):
            with self.subTest(merge_updates_view=merge_updates_view):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                gh = FakeGh(
                    view={
                        "number": 96,
                        "state": "OPEN",
                        "baseRefName": "main",
                        "headRefName": "feat/captain",
                        "headRefOid": CAPTAIN_HEAD,
                        "isDraft": False,
                        "mergeable": "MERGEABLE",
                        "mergeStateStatus": "CLEAN",
                    },
                    merge_returncode=1,
                    merge_stderr="merge failed",
                    merge_updates_view=merge_updates_view,
                )

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("failed", result["receipt"]["status"])
                self.assertEqual("performed", result["output"]["actions"][0]["execution"])
                execution = result["output"]["executions"][0]
                self.assertTrue(execution["execution_attempted"])
                self.assertEqual(1, execution["merge_returncode"])
                self.assertIn(expected_reason, execution["verification_error"])
                verification_checks = [check for check in result["receipt"]["checks"] if check["id"] == "post-execution-verification"]
                self.assertEqual("fail", verification_checks[-1]["status"])

    def test_captain_run_bounds_command_output_in_execution_result(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        long_stdout = "y" * (grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT + 50)
        long_stderr = "x" * (grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT + 100)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            merge_returncode=1,
            merge_stdout=long_stdout,
            merge_stderr=long_stderr,
            merge_updates_view=False,
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        execution = result["output"]["executions"][0]
        self.assertTrue(execution["merge_result"]["stdout_truncated"])
        self.assertTrue(execution["merge_result"]["stderr_truncated"])
        self.assertLessEqual(len(execution["merge_stdout"]), grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT)
        self.assertLessEqual(len(execution["merge_stderr"]), grips.CAPTAIN_COMMAND_OUTPUT_PREVIEW_LIMIT)
        self.assertTrue(grips._is_sha256_hex(execution["merge_result"]["stdout_sha256"]))
        self.assertTrue(grips._is_sha256_hex(execution["merge_result"]["stderr_sha256"]))

    def test_captain_run_fails_after_all_post_merge_view_retries(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            post_merge_view_failures=3,
        )
        sleeps: list[float] = []

        original_sleep = grips._captain_sleep
        try:
            grips._captain_sleep = sleeps.append
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=gh,
            )
        finally:
            grips._captain_sleep = original_sleep

        self.assertEqual("failed", result["receipt"]["status"])
        execution = result["output"]["executions"][0]
        self.assertEqual(3, execution["verify_view_summary"]["attempt_count"])
        self.assertIn("transient PR view failure", execution["verify_view_summary"]["last_error"])
        self.assertEqual([0.5, 1.0], sleeps)

    def test_captain_run_records_merge_runner_exception_without_performed_claim(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            },
            merge_exception=True,
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        self.assertEqual("failed", result["receipt"]["status"])
        action = result["output"]["actions"][0]
        execution = result["output"]["executions"][0]
        self.assertEqual("attempt-failed", action["execution"])
        self.assertTrue(execution["execution_invoked"])
        self.assertFalse(execution["execution_attempted"])
        self.assertFalse(execution["command_returned"])
        self.assertIn("runner_exception", execution)
        self.assertEqual(
            {
                "invoked_count": 1,
                "command_returned_count": 0,
                "attempted_count": 0,
                "verified_count": 0,
                "cleanup_failed_count": 0,
            },
            result["output"]["execution_counts"],
        )

    def test_captain_run_requires_merge_commit_oid_after_merge(self) -> None:
        for merge_commit in (None, {"oid": "not-a-sha"}):
            with self.subTest(merge_commit=merge_commit):
                parameters = captain_parameters(
                    trusted_owner_mode=True,
                    autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
                    allow_execution=True,
                )
                parameters.pop("human_authorization")
                parameters.pop("execution_authority")
                parameters["execution_intent"] = captain_execution_intent(parameters)
                gh = FakeGh(
                    view={
                        "number": 96,
                        "state": "OPEN",
                        "baseRefName": "main",
                        "headRefName": "feat/captain",
                        "headRefOid": CAPTAIN_HEAD,
                        "isDraft": False,
                        "mergeable": "MERGEABLE",
                        "mergeStateStatus": "CLEAN",
                    },
                    post_merge_view={"mergeCommit": merge_commit},
                )

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=gh,
                )

                self.assertEqual("failed", result["receipt"]["status"])
                self.assertIn("merged_pr_merge_commit_oid_missing_or_invalid", result["output"]["executions"][0]["verification_error"])

    def test_captain_run_blocks_unimplemented_high_impact_executor(self) -> None:
        action = captain_action(
            action="service-restart",
            target={"host": "heim-pc", "unit": "grabowski-mcp.service"},
            receipt_path="receipts/captain/service-restart.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("captain_action_execution_not_implemented:service-restart", result["output"]["blocked_reasons"])

    def test_captain_run_requires_allow_execution_parameter(self) -> None:
        parameters = captain_parameters(
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(),
        )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("allow_execution_required", result["output"]["blocked_reasons"])

    def test_blocks_missing_recovery_and_irreversibility(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(risk={"risk_level": "high"})]))

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assert_blocked_gate_reason(result, "recovery-or-irreversibility", "risk requires recovery_path or irreversible risk record")

    def test_irreversible_requires_irreversibility_record(self) -> None:
        action = captain_action(risk={"risk_level": "high", "irreversibility": "irreversible"})
        result = self.run_captain(captain_parameters([action]))
        self.assert_blocked_gate_reason(result, "recovery-or-irreversibility", "irreversibility_record is required")

        action["irreversibility_record"] = {}
        empty_record = self.run_captain(captain_parameters([action]))
        self.assert_blocked_gate_reason(empty_record, "recovery-or-irreversibility", "irreversibility_record is required")

        action["irreversibility_record"] = {"reason": "merge rewrites main history context", "accepted_by": "alex"}
        recorded = self.run_captain(captain_parameters([action]))
        self.assertEqual("blocked", recorded["output"]["decision"])
        self.assertEqual("ready_for_manual_captain_decision", recorded["output"]["gate_decision"])

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
            {"pr": 96, "base": "main"},
            {"repo": "heimgewebe/grabowski", "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": 96},
            {"repo": "grabowski", "pr": 96, "base": "main"},
            {"repo": "owner/repo/extra", "pr": 96, "base": "main"},
            {"repo": "owner/", "pr": 96, "base": "main"},
            {"repo": "/repo", "pr": 96, "base": "main"},
            {"repo": "owner//repo", "pr": 96, "base": "main"},
            {"repo": "./repo", "pr": 96, "base": "main"},
            {"repo": "owner/.", "pr": 96, "base": "main"},
            {"repo": "../repo", "pr": 96, "base": "main"},
            {"repo": "owner/..", "pr": 96, "base": "main"},
            {"repo": "a" * 101 + "/repo", "pr": 96, "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": 0, "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": -3, "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": "96", "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": True, "base": "main"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "*"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "refs/heads/main"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main branch"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "-main"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main:evil"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main\nx"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main//x"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main@{evil"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main^1"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main~1"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main\\evil"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main[abc]"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main."},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main/.evil"},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main/foo."},
            {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main/foo.lock"},
        ):
            result = self.run_captain(captain_parameters([captain_action(target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assert_blocked_gate_reason(result, "target-bound", "target")

    def test_runtime_deploy_requires_runtime_target(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={"service": "grabowski-mcp"},
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        result = self.run_captain(captain_parameters([action]))
        self.assert_blocked_gate_reason(result, "target-bound", "environment or runtime_target")

        for target in (
            {"repo": "heimgewebe/grabowski", "service": "grabowski-mcp", "environment": "heim-pc"},
            {"service": "grabowski-mcp", "environment": "heim-pc", "runtime_target": "heim-pc"},
            {"repo": 123, "environment": "heim-pc"},
        ):
            bad = captain_action(action="runtime-deploy", target=target, receipt_path="receipts/captain/runtime-deploy.json")
            blocked = self.run_captain(captain_parameters([bad]))
            self.assert_blocked_gate_reason(blocked, "target-bound", "target")

        for target, expected_reason in (
            (
                {"service": "other-service", "runtime_target": "heim-pc", "adapter": "grabowski-self"},
                "runtime_deploy_service_does_not_match_grabowski_self_adapter",
            ),
            (
                {"repo": "heimgewebe/other", "runtime_target": "heim-pc", "adapter": "grabowski-self"},
                "runtime_deploy_repo_does_not_match_grabowski_self_adapter",
            ),
            (
                {"service": "grabowski-mcp", "runtime_target": "other-host", "adapter": "grabowski-self"},
                "runtime_deploy_target_does_not_match_local_grabowski_runtime",
            ),
            (
                {"repo": "heimgewebe/grabowski", "environment": "production", "adapter": "grabowski-self"},
                "runtime_deploy_target_does_not_match_local_grabowski_runtime",
            ),
        ):
            with self.subTest(target=target):
                bad = captain_action(
                    action="runtime-deploy",
                    target=target,
                    receipt_path="receipts/captain/runtime-deploy.json",
                )
                blocked = self.run_captain(captain_parameters([bad]))
                self.assert_blocked_gate_reason(blocked, "target-bound", expected_reason)

        action["target"] = {"service": "grabowski-mcp", "environment": "heim-pc", "adapter": "grabowski-self"}
        parameters = captain_parameters([action])
        for key in ("status_projection", "status_projection_fresh", "status_projection_source", "status_projection_sha256"):
            parameters.pop(key)
        blocked = self.run_captain(parameters)
        self.assertIn("fresh_status_projection_unavailable", blocked["output"]["blocked_reasons"])
        self.assertTrue(blocked["output"]["actions"][0]["requires_status_projection"])

    def test_service_restart_requires_host_and_concrete_unit(self) -> None:
        base = {"action": "service-restart", "receipt_path": "receipts/captain/service-restart.json"}
        for target in (
            {"unit": "grabowski-mcp.service"},
            {"host": "heim-pc"},
            {"host": "*", "unit": "grabowski-mcp.service"},
            {"host": "all", "unit": "grabowski-mcp.service"},
            {"host": "heim-pc", "unit": "*"},
            {"host": "heim-pc", "unit": "all"},
        ):
            result = self.run_captain(captain_parameters([captain_action(**base, target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assert_blocked_gate_reason(result, "target-bound", "target")

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
            self.assert_blocked_gate_reason(result, "target-bound", "target")

    def test_cleanup_apply_requires_cleanup_target_and_location(self) -> None:
        base = {"action": "cleanup-apply", "receipt_path": "receipts/captain/cleanup-apply.json"}
        for target in (
            {"repo": "heimgewebe/grabowski"},
            {"cleanup_target": "stale worktrees"},
            {"cleanup_target": "*", "repo": "heimgewebe/grabowski"},
            {"cleanup_target": "stale worktrees", "repo": "owner/repo/extra"},
            {"cleanup_target": "stale worktrees", "repo": "heimgewebe/grabowski", "checkout_path": 123},
            {"cleanup_target": "stale worktrees", "checkout_path": "*"},
        ):
            result = self.run_captain(captain_parameters([captain_action(**base, target=target)]))
            self.assertEqual("blocked", result["receipt"]["status"])
            self.assert_blocked_gate_reason(result, "target-bound", "target")

    def test_target_change_must_be_non_empty_when_required_or_provided(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(target_change_required=True, target_change={})]))
        self.assert_blocked_gate_reason(result, "target-change-record", "target_change must be a non-empty object")

        provided = self.run_captain(captain_parameters([captain_action(target_change={})]))
        self.assert_blocked_gate_reason(provided, "target-change-record", "target_change must be a non-empty object")

        valid = self.run_captain(captain_parameters([captain_action(target_change={"from": "head-a", "to": "head-b"})]))
        self.assertEqual("ready_for_manual_captain_decision", valid["output"]["gate_decision"])

    def test_scope_without_effect_boundaries_blocks(self) -> None:
        for scope in (
            {"operation": "preflight only"},
            {"max_targets": 1},
            {"max_targets": "unbounded"},
            {"max_targets": 0},
            {"boundaries": "  "},
            {"boundaries": []},
            {"allowed_effects": []},
            {"forbidden_effects": [""]},
        ):
            result = self.run_captain(captain_parameters([captain_action(scope=scope)]))
            self.assertEqual("blocked", self.gate(result, "scope-bound")["status"])
            self.assertEqual("blocked", result["output"]["decision"])

    def test_scope_accepts_effect_or_boundary_with_max_targets(self) -> None:
        for scope in (
            {"boundaries": "single target", "max_targets": 1},
            {"allowed_effects": ["preflight only"], "max_targets": 1},
        ):
            result = self.run_captain(captain_parameters([captain_action(scope=scope)]))
            self.assertEqual("pass", self.gate(result, "scope-bound")["status"])
            self.assertEqual("ready_for_manual_captain_decision", result["output"]["gate_decision"])

    def test_reversible_action_requires_recovery_path(self) -> None:
        result = self.run_captain(captain_parameters([captain_action(risk={"risk_level": "high", "irreversibility": "reversible"})]))
        self.assert_blocked_gate_reason(result, "recovery-or-irreversibility", "recovery_path is required for reversible actions")

    def test_pr_merge_action_evidence_schema_binds_head_diff_ci_review_and_authorization(self) -> None:
        result = self.run_captain(captain_parameters())
        schema = result["output"]["actions"][0]["evidence_schema"]
        evidence_names = {item["name"] for item in schema["required_evidence"]}

        self.assertEqual(schema["schema_version"], grips.CAPTAIN_ACTION_EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(schema["action"], "pr-merge")
        self.assertEqual(schema["target_binding"], {"repo": "heimgewebe/grabowski", "pr": 96, "base": "main"})
        self.assertEqual(schema["head_binding"], {"parameter": "expected_head", "required": True})
        self.assertEqual(schema["base_sha_binding"], {"parameter": "expected_base_sha", "required": True})
        self.assertEqual(schema["diff_binding"], {"parameter": "diff_sha256", "required": True})
        self.assertLessEqual({"status_projection", "review_evidence", "ci_evidence", "human_authorization"}, evidence_names)
        review_evidence = next(item for item in schema["required_evidence"] if item["name"] == "review_evidence")
        ci_evidence = next(item for item in schema["required_evidence"] if item["name"] == "ci_evidence")
        self.assertIn("diff_sha256", review_evidence["required_fields"])
        self.assertIn("repo", review_evidence["required_fields"])
        self.assertIn("pr", review_evidence["required_fields"])
        self.assertIn("generated_at", review_evidence["required_fields"])
        self.assertIn("review_tier", review_evidence["required_fields"])
        self.assertIn("expected_head", review_evidence["binds"])
        self.assertIn("state", ci_evidence["required_fields"])
        self.assertEqual(ci_evidence["required_values"], {"state": "passed"})
        self.assertIn("expected_head", ci_evidence["binds"])
        status_projection = next(
            item for item in schema["required_evidence"] if item["name"] == "status_projection"
        )
        authorization = next(
            item for item in schema["required_evidence"] if item["name"] == "human_authorization"
        )
        self.assertIn("healthy", status_projection["required_fields"])
        self.assertNotIn("replay_reference", status_projection["required_fields"])
        self.assertNotIn("sha256", status_projection["required_fields"])
        self.assertEqual(status_projection["required_values"], {"healthy": True})
        self.assertEqual(
            status_projection["required_one_of"],
            [["receipt_ref"], ["run_id"], ["nonce"]],
        )
        self.assertEqual(status_projection["required_parameters"], ["status_projection_sha256"])
        self.assertEqual(
            status_projection["parameter_bindings"],
            {"status_projection_sha256": {"algorithm": "sha256", "covers": "status_projection"}},
        )
        self.assertIn("status_projection_sha256", status_projection["binds"])
        self.assertEqual(authorization["required_fields"], ["authorized_by"])
        self.assertEqual(authorization["required_one_of"], [["statement"], ["reference"]])
        self.assertEqual(authorization["required_when"], "trusted_owner_autonomy_does_not_apply")

    def test_captain_receipt_carries_action_evidence_schema(self) -> None:
        result = self.run_captain(captain_parameters())
        action_record = result["output"]["actions"][0]
        self.assertEqual(action_record["captain_receipt"]["evidence_schema"], action_record["evidence_schema"])

    def test_action_evidence_schema_uses_concrete_alternate_keys_when_json_nulls_are_present(self) -> None:
        runtime_action = captain_action(
            action="runtime-deploy",
            target={
                "repo": None,
                "service": "grabowski-mcp",
                "environment": None,
                "runtime_target": "heim-pc",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        runtime_result = self.run_captain(captain_parameters([runtime_action]))
        runtime_schema = runtime_result["output"]["actions"][0]["evidence_schema"]
        deployment_boundary = next(
            item for item in runtime_schema["required_evidence"] if item["name"] == "deployment_boundary"
        )
        self.assertEqual(runtime_schema["target_binding"], {"service": "grabowski-mcp", "runtime_target": "heim-pc"})
        self.assertIn("service", deployment_boundary["required_fields"])
        self.assertIn("runtime_target", deployment_boundary["required_fields"])
        self.assertNotIn("repo", deployment_boundary["required_fields"])
        self.assertNotIn("environment", deployment_boundary["required_fields"])

        cleanup_action = captain_action(
            action="cleanup-apply",
            target={
                "cleanup_target": "stale-worktrees",
                "repo": None,
                "checkout_path": "worktrees/grabowski-stale",
            },
            receipt_path="receipts/captain/cleanup-apply.json",
        )
        cleanup_result = self.run_captain(captain_parameters([cleanup_action]))
        cleanup_schema = cleanup_result["output"]["actions"][0]["evidence_schema"]
        dry_run = next(item for item in cleanup_schema["required_evidence"] if item["name"] == "dry_run_or_projection")
        self.assertEqual(
            cleanup_schema["target_binding"],
            {"cleanup_target": "stale-worktrees", "checkout_path": "worktrees/grabowski-stale"},
        )
        self.assertIn("checkout_path", dry_run["required_fields"])
        self.assertNotIn("repo", dry_run["required_fields"])

    def test_cleanup_evidence_schema_binds_all_supplied_concrete_locations(self) -> None:
        action = captain_action(
            action="cleanup-apply",
            target={
                "cleanup_target": "stale-worktrees",
                "repo": "heimgewebe/grabowski",
                "checkout_path": "worktrees/grabowski-stale",
            },
            receipt_path="receipts/captain/cleanup-apply.json",
        )
        result = self.run_captain(captain_parameters([action]))
        schema = result["output"]["actions"][0]["evidence_schema"]
        dry_run = next(item for item in schema["required_evidence"] if item["name"] == "dry_run_or_projection")
        recovery = next(
            item for item in schema["required_evidence"] if item["name"] == "recovery_or_irreversibility"
        )
        self.assertEqual(
            schema["target_binding"],
            {
                "cleanup_target": "stale-worktrees",
                "repo": "heimgewebe/grabowski",
                "checkout_path": "worktrees/grabowski-stale",
            },
        )
        self.assertIn("repo", dry_run["required_fields"])
        self.assertIn("checkout_path", dry_run["required_fields"])
        self.assertEqual(
            recovery["required_one_of"],
            [["recovery_path"], ["irreversibility_record"]],
        )
        self.assertEqual(recovery["required_fields"], [])

    def test_non_pr_captain_action_evidence_schemas_bind_specific_evidence(self) -> None:
        actions = [
            (
                captain_action(
                    action="runtime-deploy",
                    target={"service": "grabowski-mcp", "environment": "heim-pc"},
                    receipt_path="receipts/captain/runtime-deploy.json",
                ),
                {"deployment_boundary", "rollback_plan"},
                {"service": "grabowski-mcp", "environment": "heim-pc"},
            ),
            (
                captain_action(
                    action="service-restart",
                    target={"host": "heim-pc", "unit": "grabowski-mcp.service"},
                    receipt_path="receipts/captain/service-restart.json",
                ),
                {"restart_budget", "recovery_path"},
                {"host": "heim-pc", "unit": "grabowski-mcp.service"},
            ),
            (
                captain_action(
                    action="fleet-mutation",
                    target={"fleet_target": "browser-workers", "operation": "rotate-worker-tokens"},
                    receipt_path="receipts/captain/fleet-mutation.json",
                ),
                {"dry_run_or_projection", "recovery_or_irreversibility"},
                {"fleet_target": "browser-workers", "operation": "rotate-worker-tokens"},
            ),
            (
                captain_action(
                    action="cleanup-apply",
                    target={"cleanup_target": "stale-worktrees", "repo": "heimgewebe/grabowski"},
                    receipt_path="receipts/captain/cleanup-apply.json",
                ),
                {"dry_run_or_projection", "recovery_or_irreversibility"},
                {"cleanup_target": "stale-worktrees", "repo": "heimgewebe/grabowski"},
            ),
        ]
        for action, expected_evidence, expected_target_binding in actions:
            result = self.run_captain(captain_parameters([action]))
            schema = result["output"]["actions"][0]["evidence_schema"]
            evidence_names = {item["name"] for item in schema["required_evidence"]}
            self.assertLessEqual({"status_projection", *expected_evidence}, evidence_names)
            self.assertEqual(schema["target_binding"], expected_target_binding)
            self.assertIn("target_sha256", schema["digest_bindings"])

    def test_valid_non_pr_merge_action_envelopes_reach_gate_evaluation(self) -> None:
        actions = [
            captain_action(
                action="runtime-deploy",
                target={"service": "grabowski-mcp", "environment": "heim-pc", "adapter": "grabowski-self"},
                receipt_path="receipts/captain/runtime-deploy.json",
            ),
            captain_action(
                action="service-restart",
                target={"host": "heim-pc", "unit": "grabowski-mcp.service"},
                receipt_path="receipts/captain/service-restart.json",
            ),
            captain_action(
                action="fleet-mutation",
                target={"fleet_target": "browser-workers", "operation": "rotate-worker-tokens"},
                receipt_path="receipts/captain/fleet-mutation.json",
            ),
            captain_action(
                action="cleanup-apply",
                target={"cleanup_target": "stale-worktrees", "repo": "heimgewebe/grabowski"},
                receipt_path="receipts/captain/cleanup-apply.json",
            ),
        ]

        for action in actions:
            result = self.run_captain(captain_parameters([action]))
            self.assertEqual("pass", self.gate(result, "target-bound")["status"])
            self.assertEqual("ready_for_manual_captain_decision", result["output"]["gate_decision"])
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


    def test_atomic_merge_guard_receipt_binds_live_base_diff_resources_and_timestamps(self) -> None:
        parameters = authorized_captain_run_parameters()
        gh = FakeGh(view={
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "baseRefOid": "e" * 40,
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        }, diff_text=CAPTAIN_DIFF_TEXT)
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=gh,
        )
        self.assertEqual("passed", result["receipt"]["status"])
        guard = result["output"]["executions"][0]["merge_lease_guard"]
        self.assertEqual("completed", guard["status"])
        self.assertTrue(guard["contract_satisfied"])
        self.assertTrue(guard["dispatch_called"])
        self.assertEqual(CAPTAIN_HEAD, guard["bindings"]["head_sha"])
        self.assertEqual("feat/captain", guard["bindings"]["head_branch"])
        self.assertEqual("e" * 40, guard["bindings"]["base_sha"])
        self.assertEqual("main", guard["bindings"]["base_branch"])
        self.assertEqual(CAPTAIN_DIFF, guard["bindings"]["diff_sha256"])
        self.assertEqual(["src/changed.py"], guard["bindings"]["changed_paths"])
        self.assertEqual(
            guard["bindings"]["changed_paths_sha256"],
            guard["changed_paths_sha256"],
        )
        self.assertEqual(7, len(guard["resource_keys"]))
        self.assertLessEqual(
            guard["observed_at_unix_ns"],
            guard["lease_snapshot_observed_at_unix_ns"],
        )
        self.assertLessEqual(
            guard["lease_snapshot_observed_at_unix_ns"],
            guard["dispatch_at_unix_ns"],
        )
        self.assertLessEqual(guard["dispatch_at_unix_ns"], guard["completed_at_unix_ns"])
        self.assertRegex(guard["lease_snapshot_sha256"], r"[0-9a-f]{64}\Z")
        self.assertRegex(guard["receipt_sha256"], r"[0-9a-f]{64}\Z")
        self.assertEqual([], resources.list_resources())

    def test_default_github_runner_preserves_partial_stderr_on_timeout(self) -> None:
        timeout = grips.subprocess.TimeoutExpired(
            cmd=["gh", "pr", "view", "96"],
            timeout=30,
            output=b"partial output\n",
            stderr=b"network warning\xff\n",
        )
        with patch.object(grips.subprocess, "run", side_effect=timeout):
            result = grips._default_github_runner(Path.cwd(), ["pr", "view", "96"])

        self.assertEqual(124, result["returncode"])
        self.assertEqual(b"partial output\n", result["stdout_bytes"])
        self.assertEqual(b"network warning\xff\n", result["stderr_bytes"])
        self.assertIn("gh command timed out after 30 seconds", result["stderr"])
        self.assertIn("network warning", result["stderr"])
        self.assertIn("\ufffd", result["stderr"])

    def test_atomic_merge_guard_blocks_lease_acquired_after_review_before_dispatch(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        parameters = authorized_captain_run_parameters()
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })
        inserted = False
        def late_lease_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            nonlocal inserted
            result = gh(repo, argv)
            if argv[:2] == ["pr", "diff"] and not inserted:
                resources.acquire_resources(
                    "foreign-writer",
                    [f"path:{local_repo / 'src' / 'changed.py'}"],
                    purpose="late writer lease",
                    ttl_seconds=60,
                )
                inserted = True
            return result
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=late_lease_runner,
        )
        self.assertEqual("blocked", result["receipt"]["status"])
        execution = result["output"]["executions"][0]
        self.assertTrue(execution["merge_dispatch_blocked_by_lease_guard"])
        self.assertEqual("blocked_by_live_lease", execution["merge_lease_guard"]["status"])
        self.assertFalse(execution["merge_lease_guard"]["contract_satisfied"])
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_atomic_merge_guard_blocks_late_base_or_head_branch_lease(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        for branch in ("main", "feat/captain"):
            with self.subTest(branch=branch):
                resources.RESOURCE_DB.unlink(missing_ok=True)
                parameters = authorized_captain_run_parameters()
                gh = FakeGh(view={
                    "number": 96,
                    "state": "OPEN",
                    "baseRefName": "main",
                    "baseRefOid": "e" * 40,
                    "headRefName": "feat/captain",
                    "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False,
                    "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                })
                inserted = False

                def late_branch_runner(repo: Path, argv: list[str]) -> dict[str, object]:
                    nonlocal inserted
                    result = gh(repo, argv)
                    if argv[:2] == ["pr", "diff"] and not inserted:
                        resources.acquire_resources(
                            "foreign-branch-writer",
                            [f"repo:{local_repo}:branch:{branch}"],
                            purpose="late branch writer",
                            ttl_seconds=60,
                        )
                        inserted = True
                    return result

                result = grips.grip_run(
                    "captain-run",
                    parameters,
                    profile="captain",
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=late_branch_runner,
                )
                execution = result["output"]["executions"][0]
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertEqual(
                    "blocked_by_live_lease", execution["merge_lease_guard"]["status"]
                )
                self.assertEqual(
                    [], [call for call in gh.calls if call[:2] == ("pr", "merge")]
                )

    def test_atomic_merge_guard_requires_hash_bound_lease_owner(self) -> None:
        parameters = authorized_captain_run_parameters()
        parameters["execution_intent"]["context"].pop("lease_owner_id")
        parameters["execution_intent"] = captain_execution_intent(
            parameters, context=parameters["execution_intent"]["context"]
        )
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=gh,
        )
        execution = result["output"]["executions"][0]
        self.assertEqual("blocked_before_guard", execution["merge_lease_guard"]["status"])
        self.assertIn(
            "merge_guard_lease_owner_invalid", execution["merge_lease_guard"]["errors"]
        )
        self.assertEqual([], gh.calls)

    def test_server_runtime_actor_identity_is_session_bound_and_tamper_evident(self) -> None:
        class Session:
            pass

        first_session = Session()
        second_session = Session()
        first = merge_guard.issue_server_runtime_actor_identity(
            first_session, profile="trusted-owner", now_unix=100
        )
        repeated = merge_guard.issue_server_runtime_actor_identity(
            first_session, profile="trusted-owner", now_unix=101
        )
        second = merge_guard.issue_server_runtime_actor_identity(
            second_session, profile="trusted-owner", now_unix=100
        )

        self.assertEqual(first["owner_id"], repeated["owner_id"])
        self.assertNotEqual(first["owner_id"], second["owner_id"])
        verified = merge_guard.verify_server_runtime_actor_identity(first, now_unix=100)
        self.assertEqual(first["owner_id"], verified["owner_id"])

        tampered = dict(first)
        tampered["owner_id"] = "runtime-actor:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "proof"):
            merge_guard.verify_server_runtime_actor_identity(tampered, now_unix=100)

    def test_server_task_lease_delegation_is_request_bound_and_short_lived(self) -> None:
        class Session:
            pass

        task_id = "a" * 24
        owner = f"task:{task_id}"
        resource_keys = ["component:test-task-delegation"]
        task_binding = {
            "task_id": task_id,
            "lease_owner_id": owner,
            "state": "running",
            "attempt": 1,
            "updated_at_unix": 100,
            "resource_keys_sha256": merge_guard._sha256_json(resource_keys),
            "lease_bindings_sha256": "b" * 64,
        }
        evidence = {
            "schema_version": 1,
            "kind": "grabowski_live_task_lease_delegation_evidence",
            **task_binding,
            "task_record_sha256": merge_guard._sha256_json(task_binding),
            "resource_keys": resource_keys,
            "minimum_expires_at_unix": 150,
            "observed_at_unix": 100,
        }
        actor = merge_guard.issue_server_runtime_actor_identity(
            Session(), profile="trusted-owner", now_unix=100
        )
        delegation = merge_guard.issue_server_task_lease_delegation(
            actor,
            evidence,
            captain_request_sha256_value="c" * 64,
            now_unix=100,
        )

        verified = merge_guard.verify_server_task_lease_delegation(
            delegation,
            actor_identity=actor,
            captain_request_sha256_value="c" * 64,
            now_unix=100,
        )
        self.assertEqual(owner, verified["lease_owner_id"])
        self.assertEqual(150, verified["expires_at_unix"])
        with self.assertRaisesRegex(ValueError, "captain request mismatch"):
            merge_guard.verify_server_task_lease_delegation(
                delegation,
                actor_identity=actor,
                captain_request_sha256_value="d" * 64,
                now_unix=100,
            )
        with self.assertRaisesRegex(ValueError, "not current"):
            merge_guard.verify_server_task_lease_delegation(
                delegation,
                actor_identity=actor,
                captain_request_sha256_value="c" * 64,
                now_unix=151,
            )

    def test_atomic_merge_guard_accepts_live_server_delegated_task_lease(self) -> None:
        class Session:
            pass

        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        guard_keys = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="heimgewebe/grabowski",
            pr_number=96,
            base="main",
            head="feat/captain",
        )
        task_key = next(
            key for key in guard_keys if key.startswith("component:github-branch:")
            and key.endswith(":" + merge_guard._merge_guard_identifier("branch", "feat/captain"))
        )
        task_id = "a" * 24
        task_owner = f"task:{task_id}"
        resources.acquire_resources(
            task_owner,
            [task_key],
            purpose="live task branch lease",
            ttl_seconds=600,
            metadata={"task_id": task_id, "attempt": 1},
        )
        lease_evidence = resources.task_lease_delegation_evidence(
            task_owner, task_id, [task_key]
        )
        task_binding = {
            "task_id": task_id,
            "lease_owner_id": task_owner,
            "state": "running",
            "attempt": 1,
            "updated_at_unix": int(time.time()),
            "resource_keys_sha256": lease_evidence["resource_keys_sha256"],
            "lease_bindings_sha256": lease_evidence["lease_bindings_sha256"],
        }
        task_evidence = {
            "schema_version": 1,
            "kind": "grabowski_live_task_lease_delegation_evidence",
            **task_binding,
            "task_record_sha256": merge_guard._sha256_json(task_binding),
            "resource_keys": lease_evidence["resource_keys"],
            "minimum_expires_at_unix": lease_evidence["minimum_expires_at_unix"],
            "observed_at_unix": lease_evidence["observed_at_unix"],
        }
        parameters = authorized_captain_run_parameters()
        parameters["execution_intent"]["context"]["lease_owner_id"] = task_owner
        parameters["execution_intent"] = captain_execution_intent(
            parameters, context=parameters["execution_intent"]["context"]
        )
        actor = merge_guard.issue_server_runtime_actor_identity(
            Session(), profile="trusted-owner"
        )
        parameters["_server_runtime_actor_identity"] = actor
        delegation = merge_guard.issue_server_task_lease_delegation(
            actor,
            task_evidence,
            captain_request_sha256_value=merge_guard.captain_request_sha256(parameters),
        )
        parameters["_server_task_lease_delegation"] = delegation
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": CAPTAIN_BASE_SHA, "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD, "isDraft": False,
            "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })

        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=gh,
        )

        self.assertEqual("passed", result["receipt"]["status"])
        guard = result["output"]["executions"][0]["merge_lease_guard"]
        self.assertEqual("server-runtime-task-delegation-v1", guard["lease_owner_source"])
        self.assertEqual(task_id, guard["delegated_task_id"])
        self.assertNotIn(delegation["proof_sha256"], json.dumps(guard, sort_keys=True))
        remaining = resources.inspect_resource(task_key)
        self.assertIsNotNone(remaining)
        self.assertEqual(task_owner, remaining["owner_id"])

    def test_atomic_merge_guard_rejects_delegation_after_task_lease_release(self) -> None:
        class Session:
            pass

        task_id = "a" * 24
        task_owner = f"task:{task_id}"
        task_key = "component:delegated-task-release"
        resources.acquire_resources(
            task_owner, [task_key], purpose="task lease", ttl_seconds=600,
            metadata={"task_id": task_id},
        )
        lease_evidence = resources.task_lease_delegation_evidence(
            task_owner, task_id, [task_key]
        )
        task_binding = {
            "task_id": task_id, "lease_owner_id": task_owner,
            "state": "running", "attempt": 1,
            "updated_at_unix": int(time.time()),
            "resource_keys_sha256": lease_evidence["resource_keys_sha256"],
            "lease_bindings_sha256": lease_evidence["lease_bindings_sha256"],
        }
        task_evidence = {
            "schema_version": 1,
            "kind": "grabowski_live_task_lease_delegation_evidence",
            **task_binding, "task_record_sha256": merge_guard._sha256_json(task_binding),
            "resource_keys": [task_key],
            "minimum_expires_at_unix": lease_evidence["minimum_expires_at_unix"],
            "observed_at_unix": lease_evidence["observed_at_unix"],
        }
        parameters = authorized_captain_run_parameters()
        parameters["execution_intent"]["context"]["lease_owner_id"] = task_owner
        parameters["execution_intent"] = captain_execution_intent(
            parameters, context=parameters["execution_intent"]["context"]
        )
        actor = merge_guard.issue_server_runtime_actor_identity(Session(), profile="trusted-owner")
        parameters["_server_runtime_actor_identity"] = actor
        parameters["_server_task_lease_delegation"] = merge_guard.issue_server_task_lease_delegation(
            actor, task_evidence,
            captain_request_sha256_value=merge_guard.captain_request_sha256(parameters),
        )
        resources.release_resources(task_owner, [task_key])
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=FakeGh(view={
                "number": 96, "state": "OPEN", "baseRefName": "main",
                "baseRefOid": CAPTAIN_BASE_SHA, "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD, "isDraft": False,
                "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
            }),
        )
        guard = result["output"]["executions"][0]["merge_lease_guard"]
        self.assertEqual("blocked_by_live_lease", guard["status"])
        self.assertIn("delegated task lease is not live", guard["errors"][0])

    def test_atomic_merge_guard_prefers_server_actor_to_caller_lease_owner(self) -> None:
        class Session:
            pass

        parameters = authorized_captain_run_parameters()
        identity = merge_guard.issue_server_runtime_actor_identity(
            Session(), profile="trusted-owner"
        )
        runner = merge_guard.CaptainMergeGuardRunner(
            repo_path=Path.cwd(),
            action=parameters["actions"][0],
            parameters=parameters,
            github_runner=FakeGh(),
            execution_intent_sha256="f" * 64,
            lease_owner_id="visible-foreign-owner",
            server_actor_identity=identity,
        )

        self.assertEqual(identity["owner_id"], runner.lease_owner_id)
        self.assertEqual("server-runtime-session-v1", runner.lease_owner_source)
        self.assertTrue(runner.receipt["lease_owner_binding"]["server_authenticated"])
        self.assertNotIn(
            "server_authenticated_lease_owner_identity",
            runner.receipt["does_not_establish"],
        )
        self.assertNotIn(identity["proof_sha256"], json.dumps(runner.receipt, sort_keys=True))

    def test_atomic_merge_guard_server_actor_blocks_spoofed_visible_owner_lease(self) -> None:
        class Session:
            pass

        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        resource_keys = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="heimgewebe/grabowski",
            pr_number=96,
            base="main",
            head="feat/captain",
        )
        head_component = next(
            key
            for key in resource_keys
            if key.startswith("component:github-branch:")
            and key.endswith(
                ":" + merge_guard._merge_guard_identifier("branch", "feat/captain")
            )
        )
        resources.acquire_resources(
            "visible-foreign-owner",
            [head_component],
            purpose="foreign visible lease",
            ttl_seconds=60,
        )
        parameters = authorized_captain_run_parameters()
        parameters["execution_intent"]["context"]["lease_owner_id"] = (
            "visible-foreign-owner"
        )
        parameters["execution_intent"] = captain_execution_intent(
            parameters,
            context=parameters["execution_intent"]["context"],
        )
        parameters["_server_runtime_actor_identity"] = (
            merge_guard.issue_server_runtime_actor_identity(
                Session(), profile="trusted-owner"
            )
        )
        gh = FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "baseRefOid": CAPTAIN_BASE_SHA,
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            }
        )

        result = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

        execution = result["output"]["executions"][0]
        self.assertEqual(
            "server-runtime-session-v1",
            execution["merge_lease_guard"]["lease_owner_binding"]["source"],
        )
        self.assertEqual(
            "blocked_by_live_lease", execution["merge_lease_guard"]["status"]
        )
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_atomic_merge_guard_hashes_raw_diff_bytes_without_newline_translation(self) -> None:
        raw_diff = b"captain-diff\r\n"
        parameters = authorized_captain_run_parameters()
        parameters["diff_sha256"] = hashlib.sha256(raw_diff).hexdigest()
        parameters["review_evidence"]["diff_sha256"] = parameters["diff_sha256"]
        parameters["execution_intent"] = captain_execution_intent(parameters)
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": CAPTAIN_BASE_SHA, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })

        def raw_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            result = gh(repo, argv)
            if argv[:2] == ["pr", "diff"]:
                result = dict(result)
                result["stdout"] = raw_diff.decode("utf-8")
                result["stdout_bytes"] = raw_diff
            return result

        runner = merge_guard.CaptainMergeGuardRunner(
            repo_path=Path.cwd(), action=parameters["actions"][0],
            parameters=parameters, github_runner=raw_runner,
            execution_intent_sha256="f" * 64, lease_owner_id="captain-test-owner",
        )
        bindings, errors = runner._live_bindings()
        self.assertEqual([], errors)
        self.assertIsNotNone(bindings)
        self.assertEqual(hashlib.sha256(raw_diff).hexdigest(), bindings["diff_sha256"])
        self.assertEqual("raw-command-bytes", runner.receipt["live_diff"]["canonicalization"])

    def test_atomic_merge_guard_rejects_cached_snapshot_and_live_diff_drift(self) -> None:
        for parameters, gh, expected in (
            (
                authorized_captain_run_parameters(merge_lease_snapshot={"sha256": "0" * 64}),
                FakeGh(),
                "merge_guard_cached_snapshot_input_forbidden",
            ),
            (
                authorized_captain_run_parameters(),
                FakeGh(diff_text="different-diff\n"),
                "merge_guard_diff_drift",
            ),
        ):
            with self.subTest(expected=expected):
                gh.view.update({
                    "number": 96, "state": "OPEN", "baseRefName": "main",
                    "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
                })
                result = grips.grip_run(
                    "captain-run", parameters, profile="captain", allow_mutation=True,
                    command_runner=FakeGit(), github_runner=gh,
                )
                execution = result["output"]["executions"][0]
                self.assertEqual("blocked_before_guard", execution["merge_lease_guard"]["status"])
                self.assertTrue(any(expected in item for item in execution["merge_lease_guard"]["errors"]))
                self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_atomic_merge_guard_rejects_empty_live_diff(self) -> None:
        parameters = authorized_captain_run_parameters()
        parameters["diff_sha256"] = hashlib.sha256(b"").hexdigest()
        gh = FakeGh(diff_text="")
        gh.view.update({
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "baseRefOid": "e" * 40,
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        })
        runner = merge_guard.CaptainMergeGuardRunner(
            repo_path=Path.cwd(),
            action=parameters["actions"][0],
            parameters=parameters,
            github_runner=gh,
            execution_intent_sha256="f" * 64,
            lease_owner_id="captain-test-owner",
        )
        bindings, errors = runner._live_bindings()
        self.assertIsNotNone(bindings)
        self.assertIn("merge_guard_live_diff_empty", errors)
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_atomic_merge_guard_releases_after_unexpected_executor_exception(self) -> None:
        parameters = authorized_captain_run_parameters()
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": CAPTAIN_BASE_SHA, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })

        def exploding_executor(repo, action, supplied_parameters, guarded_runner):
            guarded_runner(repo, ["pr", "merge", "96"])
            raise RuntimeError("executor exploded after guarded dispatch")

        with patch.object(
            grips,
            "_run_captain_pr_merge",
            side_effect=exploding_executor,
        ):
            result = grips.grip_run(
                "captain-run", parameters, profile="captain", allow_mutation=True,
                command_runner=FakeGit(), github_runner=gh,
            )

        execution = result["output"]["executions"][0]
        self.assertFalse(execution["verification_passed"])
        self.assertTrue(execution["merge_guard_cleanup_passed"])
        self.assertEqual("completed", execution["merge_lease_guard"]["status"])
        with resources._database() as connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0])

    def test_atomic_merge_guard_preserves_merge_verification_when_release_fails(self) -> None:
        parameters = authorized_captain_run_parameters()
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": CAPTAIN_BASE_SHA, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        })
        with patch.object(resources, "release_resources", side_effect=RuntimeError("release unavailable")):
            result = grips.grip_run(
                "captain-run", parameters, profile="captain", allow_mutation=True,
                command_runner=FakeGit(), github_runner=gh,
            )
        execution = result["output"]["executions"][0]
        self.assertTrue(execution["verification_passed"])
        self.assertFalse(execution["merge_guard_cleanup_passed"])
        self.assertEqual("guard_release_failed", execution["merge_lease_guard"]["status"])
        self.assertEqual("executed_with_guard_cleanup_failure", result["output"]["decision"])
        self.assertEqual("failed", result["receipt"]["status"])

    def test_atomic_merge_guard_blocks_base_sha_drift_after_acquisition_and_releases(self) -> None:
        parameters = authorized_captain_run_parameters()
        good = {
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": CAPTAIN_BASE_SHA, "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD, "isDraft": False,
            "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        }
        drifted = dict(good, baseRefOid="a" * 40)
        gh = FakeGh(view_sequence=[good, good, drifted])
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=gh,
        )
        execution = result["output"]["executions"][0]
        self.assertFalse(execution["verification_passed"])
        self.assertTrue(execution["merge_guard_cleanup_passed"])
        self.assertTrue(
            any(
                "merge_guard_dispatch_revalidation_drift:baseRefOid" in item
                for item in execution["merge_lease_guard"]["errors"]
            )
        )
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])
        self.assertEqual(
            "blocked_after_guard_revalidation_released",
            execution["merge_lease_guard"]["status"],
        )
        with resources._database() as connection:
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0])

    def test_atomic_merge_guard_blocks_legacy_repo_lease_and_same_owner_concurrent_gate(self) -> None:
        for mode in ("legacy-repo", "same-owner-gate"):
            with self.subTest(mode=mode):
                resources.RESOURCE_DB.unlink(missing_ok=True)
                local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
                parameters = authorized_captain_run_parameters()
                keys = merge_guard.merge_guard_resource_keys(
                    local_repo,
                    repo_slug="heimgewebe/grabowski",
                    pr_number=96,
                    base="main",
                    head="feat/captain",
                )
                if mode == "legacy-repo":
                    resources.acquire_resources(
                        "foreign-legacy", [f"repo:{local_repo}"],
                        purpose="legacy unscoped repository lease", ttl_seconds=60,
                    )
                else:
                    gate = next(key for key in keys if key.startswith("gate:github-merge:"))
                    resources.acquire_resources(
                        "alex", [gate], purpose="first concurrent merge", ttl_seconds=60,
                    )
                gh = FakeGh(view={
                    "number": 96, "state": "OPEN", "baseRefName": "main",
                    "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
                })
                result = grips.grip_run(
                    "captain-run", parameters, profile="captain", allow_mutation=True,
                    command_runner=FakeGit(), github_runner=gh,
                )
                execution = result["output"]["executions"][0]
                self.assertEqual("blocked_by_live_lease", execution["merge_lease_guard"]["status"])
                self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_atomic_merge_guard_serializes_head_branch_component(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        resource_keys = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="heimgewebe/grabowski",
            pr_number=96,
            base="main",
            head="feat/captain",
        )
        head_branch_id = merge_guard._merge_guard_identifier("branch", "feat/captain")
        head_component = next(
            key
            for key in resource_keys
            if key.startswith("component:github-branch:")
            and key.endswith(f":{head_branch_id}")
        )
        parameters = authorized_captain_run_parameters()

        resources.acquire_resources(
            "foreign-head-component",
            [head_component],
            purpose="foreign pull request head branch mutation",
            ttl_seconds=60,
        )
        blocked = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=FakeGh(view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "baseRefOid": "e" * 40,
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            }),
        )
        blocked_execution = blocked["output"]["executions"][0]
        self.assertEqual(
            "blocked_by_live_lease", blocked_execution["merge_lease_guard"]["status"]
        )

        resources.RESOURCE_DB.unlink(missing_ok=True)
        resources.acquire_resources(
            "captain-test-owner",
            [head_component],
            purpose="authorized task owns pull request head branch",
            ttl_seconds=60,
        )
        gh = FakeGh(view={
            "number": 96,
            "state": "OPEN",
            "baseRefName": "main",
            "baseRefOid": "e" * 40,
            "headRefName": "feat/captain",
            "headRefOid": CAPTAIN_HEAD,
            "isDraft": False,
            "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN",
        })
        late_component_blocked = False

        def assert_guard_held(repo: Path, argv: list[str]) -> dict[str, object]:
            nonlocal late_component_blocked
            if argv[:2] == ["pr", "merge"]:
                released = resources.release_resources(
                    "captain-test-owner", [head_component], force=False
                )
                self.assertEqual(
                    [head_component],
                    [item["resource_key"] for item in released["released"]],
                )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_resources(
                        "late-head-component",
                        [head_component],
                        purpose="late pull request head branch mutation",
                        ttl_seconds=60,
                    )
                late_component_blocked = True
            return gh(repo, argv)

        passed = grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=assert_guard_held,
        )
        execution = passed["output"]["executions"][0]
        self.assertEqual("passed", passed["receipt"]["status"])
        self.assertTrue(late_component_blocked)
        self.assertIn(head_component, execution["merge_lease_guard"]["resource_keys"])

    def test_merge_guard_resource_ids_are_collision_free_and_slash_safe(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        first = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="a-b/c",
            pr_number=96,
            base="release/2026",
            head="feat/captain",
        )
        second = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="a/b-c",
            pr_number=96,
            base="release/2026",
            head="feat/captain",
        )
        self.assertTrue(set(first).isdisjoint(second))
        self.assertEqual(7, len(first))
        self.assertEqual(first, resources.normalize_resource_keys(first))
        release_branch_id = merge_guard._merge_guard_identifier(
            "branch", "release/2026"
        )
        self.assertTrue(
            any(
                key.startswith("gate:github-merge:")
                and key.endswith(f":{release_branch_id}")
                for key in first
            )
        )
        self.assertTrue(
            any(
                key.startswith("deployment:github:")
                and key.endswith(f":{release_branch_id}")
                for key in first
            )
        )

        canonical_case = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="heimgewebe/grabowski",
            pr_number=96,
            base="main",
            head="feat/captain",
        )
        display_case = merge_guard.merge_guard_resource_keys(
            local_repo,
            repo_slug="Heimgewebe/Grabowski",
            pr_number=96,
            base="main",
            head="feat/captain",
        )
        self.assertEqual(canonical_case, display_case)

    def test_atomic_merge_guard_allows_exact_nonoverlap(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        local_disjoint = f"path:{local_repo / 'docs' / 'foreign.md'}"
        resources.acquire_resources(
            "foreign-same-repo",
            [local_disjoint],
            purpose="same repository but disjoint file",
            ttl_seconds=60,
        )
        resources.acquire_resources(
            "foreign-other-repo",
            ["gate:github-merge:heimgewebe-other:main"],
            purpose="unrelated repository merge", ttl_seconds=60,
        )
        parameters = authorized_captain_run_parameters()
        gh = FakeGh(view={
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
            "changedFiles": 1,
            "files": [{"path": "src/changed.py", "changeType": "MODIFIED"}],
        })
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=gh,
        )
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual(
            "foreign-same-repo", resources.inspect_resource(local_disjoint)["owner_id"]
        )
        self.assertEqual("foreign-other-repo", resources.inspect_resource(
            "gate:github-merge:heimgewebe-other:main"
        )["owner_id"])

    def test_atomic_merge_guard_rejects_incomplete_or_rename_path_evidence(self) -> None:
        cases = (
            (
                {
                    "changedFiles": 2,
                    "files": [{"path": "src/changed.py", "changeType": "MODIFIED"}],
                },
                "merge_guard_changed_file_list_incomplete",
            ),
            (
                {
                    "changedFiles": True,
                    "files": [{"path": "src/changed.py", "changeType": "MODIFIED"}],
                },
                "merge_guard_changed_file_count_invalid",
            ),
            (
                {
                    "changedFiles": 101,
                    "files": [
                        {"path": f"src/file-{index}.py", "changeType": "MODIFIED"}
                        for index in range(100)
                    ],
                },
                "merge_guard_changed_file_count_exceeds_supported_limit",
            ),
            (
                {
                    "changedFiles": 129,
                    "files": [
                        {"path": f"src/file-{index}.py", "changeType": "MODIFIED"}
                        for index in range(129)
                    ],
                },
                "merge_guard_changed_path_count_exceeds_limit",
            ),
            (
                {
                    "changedFiles": 1,
                    "files": [
                        {
                            "path": "src/" + ("x" * 8200),
                            "changeType": "MODIFIED",
                        }
                    ],
                },
                "merge_guard_changed_paths_exceed_byte_limit",
            ),
            (
                {
                    "changedFiles": 1,
                    "files": [{"path": "src/new.py", "changeType": "RENAMED"}],
                },
                "merge_guard_changed_path_requires_previous_name",
            ),
        )
        for file_evidence, expected in cases:
            with self.subTest(expected=expected):
                parameters = authorized_captain_run_parameters()
                view = {
                    "number": 96, "state": "OPEN", "baseRefName": "main",
                    "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
                    "isDraft": False, "mergeable": "MERGEABLE",
                    "mergeStateStatus": "CLEAN",
                    **file_evidence,
                }
                gh = FakeGh(view=view)
                result = grips.grip_run(
                    "captain-run", parameters, profile="captain", allow_mutation=True,
                    command_runner=FakeGit(), github_runner=gh,
                )
                execution = result["output"]["executions"][0]
                self.assertEqual("blocked_before_guard", execution["merge_lease_guard"]["status"])
                self.assertTrue(any(
                    expected in item for item in execution["merge_lease_guard"]["errors"]
                ))
                self.assertEqual(
                    [], [call for call in gh.calls if call[:2] == ("pr", "merge")]
                )

    def test_atomic_merge_guard_external_merge_does_not_manufacture_compliance(self) -> None:
        local_repo = merge_guard.merge_guard_repository_root(Path.cwd())
        parameters = authorized_captain_run_parameters()
        open_view = {
            "number": 96, "state": "OPEN", "baseRefName": "main",
            "baseRefOid": "e" * 40, "headRefOid": CAPTAIN_HEAD,
            "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
        }
        merged_view = dict(
            open_view,
            state="MERGED",
            mergedAt="2026-07-14T08:00:00Z",
            mergeCommit={"oid": "d" * 40},
        )
        gh = FakeGh(view_sequence=[open_view, open_view, merged_view], merge_updates_view=False)
        inserted = False
        def external_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            nonlocal inserted
            result = gh(repo, argv)
            if argv[:2] == ["pr", "diff"] and not inserted:
                resources.acquire_resources(
                    "foreign-writer",
                    [f"path:{local_repo / 'src' / 'changed.py'}"],
                    purpose="late external lease", ttl_seconds=60,
                )
                inserted = True
            return result
        result = grips.grip_run(
            "captain-run", parameters, profile="captain", allow_mutation=True,
            command_runner=FakeGit(), github_runner=external_runner,
        )
        execution = result["output"]["executions"][0]
        guard = execution["merge_lease_guard"]
        self.assertTrue(execution["remote_mutation_observed"])
        self.assertTrue(guard["external_merge_observed"])
        self.assertFalse(guard["contract_satisfied"])
        self.assertFalse(guard["dispatch_called"])
        self.assertEqual(
            "external_merge_observed_after_merge_guard_block",
            execution["verification_error"],
        )
        self.assertEqual([], [call for call in gh.calls if call[:2] == ("pr", "merge")])

class CaptainExecutionIntentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._resource_tempdir = tempfile.TemporaryDirectory()
        self._resource_db_patch = patch.object(
            resources,
            "RESOURCE_DB",
            Path(self._resource_tempdir.name) / "resources.sqlite3",
        )
        self._resource_db_patch.start()

    def tearDown(self) -> None:
        self._resource_db_patch.stop()
        self._resource_tempdir.cleanup()

    def executable_parameters(self, actions: list[dict[str, object]] | None = None) -> dict[str, object]:
        parameters = captain_parameters(
            actions,
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        return parameters

    def mergeable_gh(self) -> FakeGh:
        return FakeGh(
            view={
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "headRefName": "feat/captain",
                "headRefOid": CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            }
        )

    def run_captain_run(self, parameters: dict[str, object], gh: FakeGh) -> dict[str, object]:
        return grips.grip_run(
            "captain-run",
            parameters,
            profile="captain",
            allow_mutation=True,
            command_runner=FakeGit(),
            github_runner=gh,
        )

    def assert_blocked_without_executor_calls(
        self,
        result: dict[str, object],
        gh: FakeGh,
        expected_reason: str,
    ) -> None:
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("blocked", result["output"]["decision"])
        self.assertIn(expected_reason, result["output"]["blocked_reasons"])
        self.assertEqual([], result["output"]["executions"])
        info = result["output"]["execution_intent"]
        self.assertTrue(info["required"])
        self.assertFalse(info["valid"])
        self.assertIn(expected_reason, info["errors"])
        self.assertEqual([], gh.calls)
        intent_checks = [check for check in result["receipt"]["checks"] if check["id"] == "execution-intent-bound"]
        self.assertEqual("fail", intent_checks[-1]["status"])

    def test_captain_run_blocks_missing_execution_intent_before_any_executor(self) -> None:
        parameters = self.executable_parameters()
        gh = self.mergeable_gh()

        result = self.run_captain_run(parameters, gh)

        self.assert_blocked_without_executor_calls(result, gh, "execution_intent_missing")
        self.assertFalse(result["output"]["execution_intent"]["present"])
        self.assertIsNone(result["output"]["execution_intent"]["intent_sha256"])

    def test_captain_run_blocks_malformed_execution_intent(self) -> None:
        cases = (
            ("execution_intent_malformed", lambda intent: "merge it"),
            ("execution_intent_malformed", lambda intent: {}),
            ("execution_intent_field_missing:actor", lambda intent: {k: v for k, v in intent.items() if k != "actor"}),
            ("execution_intent_field_missing:issued_at", lambda intent: {k: v for k, v in intent.items() if k != "issued_at"}),
            ("execution_intent_schema_version_invalid", lambda intent: dict(intent, schema_version=2)),
            ("execution_intent_schema_version_invalid", lambda intent: dict(intent, schema_version=True)),
            ("execution_intent_kind_invalid", lambda intent: dict(intent, kind="grabowski_generic_intent")),
            ("execution_intent_unknown_fields_present", lambda intent: dict(intent, note="extra")),
            ("execution_intent_field_invalid:evidence_sha256", lambda intent: dict(intent, evidence_sha256=[])),
            (
                "execution_intent_evidence_missing:ci_evidence_sha256",
                lambda intent: dict(
                    intent,
                    evidence_sha256={k: v for k, v in intent["evidence_sha256"].items() if k != "ci_evidence_sha256"},
                ),
            ),
            (
                "execution_intent_evidence_unknown_keys_present",
                lambda intent: dict(intent, evidence_sha256=dict(intent["evidence_sha256"], extra_sha256="0" * 64)),
            ),
            (
                "execution_intent_evidence_invalid:diff_sha256",
                lambda intent: dict(intent, evidence_sha256=dict(intent["evidence_sha256"], diff_sha256="short")),
            ),
            ("execution_intent_actor_invalid", lambda intent: dict(intent, actor="alex")),
            ("execution_intent_actor_invalid", lambda intent: dict(intent, actor={"id": "   "})),
            ("execution_intent_context_invalid", lambda intent: dict(intent, context={})),
            ("execution_intent_field_invalid:action", lambda intent: dict(intent, action="  ")),
            ("execution_intent_field_invalid:expected_base", lambda intent: dict(intent, expected_base=None)),
            (
                "execution_intent_field_missing:expected_base_sha",
                lambda intent: {k: v for k, v in intent.items() if k != "expected_base_sha"},
            ),
            (
                "execution_intent_field_invalid:expected_base_sha",
                lambda intent: dict(intent, expected_base_sha="e" * 39),
            ),
            ("execution_intent_field_invalid:expected_head", lambda intent: dict(intent, expected_head="b" * 39)),
            ("execution_intent_issued_at_invalid", lambda intent: dict(intent, issued_at="soon")),
            (
                "execution_intent_issued_at_invalid",
                lambda intent: dict(intent, issued_at=datetime.now(timezone.utc).replace(tzinfo=None).isoformat()),
            ),
        )
        for expected_reason, mutate in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = self.executable_parameters()
                parameters["execution_intent"] = mutate(captain_execution_intent(parameters))
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                self.assert_blocked_without_executor_calls(result, gh, expected_reason)

    def test_captain_run_blocks_non_canonical_execution_intent_digests(self) -> None:
        cases = (
            (
                "execution_intent_field_not_canonical:expected_head",
                lambda intent: dict(intent, expected_head=str(intent["expected_head"]).upper()),
            ),
            (
                "execution_intent_field_not_canonical:expected_base_sha",
                lambda intent: dict(
                    intent, expected_base_sha=str(intent["expected_base_sha"]).upper()
                ),
            ),
            (
                "execution_intent_field_not_canonical:target_sha256",
                lambda intent: dict(intent, target_sha256=str(intent["target_sha256"]).upper()),
            ),
            (
                "execution_intent_evidence_not_canonical:diff_sha256",
                lambda intent: dict(
                    intent,
                    evidence_sha256=dict(
                        intent["evidence_sha256"],
                        diff_sha256=str(intent["evidence_sha256"]["diff_sha256"]).upper(),
                    ),
                ),
            ),
        )
        for expected_reason, mutate in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = self.executable_parameters()
                parameters["execution_intent"] = mutate(captain_execution_intent(parameters))
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                self.assert_blocked_without_executor_calls(result, gh, expected_reason)

    def test_captain_run_blocks_execution_intent_action_target_head_and_base_drift(self) -> None:
        cases = (
            ("execution_intent_action_drift", lambda intent: dict(intent, action="runtime-deploy")),
            ("execution_intent_target_drift", lambda intent: dict(intent, target_sha256="f" * 64)),
            ("execution_intent_head_drift", lambda intent: dict(intent, expected_head="a" * 40)),
            (
                "execution_intent_base_sha_drift",
                lambda intent: dict(intent, expected_base_sha="a" * 40),
            ),
            ("execution_intent_base_drift", lambda intent: dict(intent, expected_base="develop")),
        )
        for expected_reason, mutate in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = self.executable_parameters()
                parameters["execution_intent"] = mutate(captain_execution_intent(parameters))
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                self.assert_blocked_without_executor_calls(result, gh, expected_reason)

    def test_captain_run_blocks_execution_intent_evidence_drift_for_every_decisive_digest(self) -> None:
        for key in grips.CAPTAIN_EXECUTION_INTENT_EVIDENCE_KEYS:
            with self.subTest(key=key):
                parameters = self.executable_parameters()
                intent = captain_execution_intent(parameters)
                intent["evidence_sha256"] = dict(intent["evidence_sha256"], **{key: "f" * 64})
                parameters["execution_intent"] = intent
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                self.assert_blocked_without_executor_calls(result, gh, f"execution_intent_evidence_drift:{key}")

    def test_captain_run_blocks_execution_intent_authorization_drift(self) -> None:
        mutations = (
            lambda parameters: parameters.__setitem__(
                "execution_authority",
                {"granted_by": "mallory", "reference": "replacement authority"},
            ),
            lambda parameters: parameters.__setitem__(
                "human_authorization",
                {"authorized_by": "mallory", "statement": "replacement authorization"},
            ),
            lambda parameters: parameters.__setitem__("trusted_owner_mode", True),
            lambda parameters: parameters.__setitem__(
                "autonomy_policy",
                grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                parameters = captain_parameters()
                parameters["execution_intent"] = captain_execution_intent(parameters)
                mutate(parameters)
                gh = self.mergeable_gh()
                result = self.run_captain_run(parameters, gh)
                self.assert_blocked_without_executor_calls(
                    result,
                    gh,
                    "execution_intent_evidence_drift:authorization_sha256",
                )

    def test_captain_run_blocks_stale_and_future_dated_execution_intent(self) -> None:
        stale_issued_at = (
            datetime.now(timezone.utc) - timedelta(seconds=grips.CAPTAIN_EXECUTION_INTENT_MAX_AGE_SECONDS + 60)
        ).isoformat()
        future_issued_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=grips.CAPTAIN_EXECUTION_INTENT_CLOCK_SKEW_TOLERANCE_SECONDS + 60)
        ).isoformat()
        cases = (
            ("execution_intent_issued_at_stale", stale_issued_at),
            ("execution_intent_issued_at_in_future", future_issued_at),
        )
        for expected_reason, issued_at in cases:
            with self.subTest(expected_reason=expected_reason):
                parameters = self.executable_parameters()
                parameters["execution_intent"] = captain_execution_intent(parameters, issued_at=issued_at)
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                self.assert_blocked_without_executor_calls(result, gh, expected_reason)

    def test_captain_run_accepts_small_execution_intent_clock_skew(self) -> None:
        parameters = self.executable_parameters()
        parameters["execution_intent"] = captain_execution_intent(
            parameters,
            issued_at=(datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat(),
        )
        gh = self.mergeable_gh()

        result = self.run_captain_run(parameters, gh)

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertNotIn("execution_intent_issued_at_in_future", result["output"]["execution_intent"]["errors"])

    def test_captain_run_executes_with_valid_execution_intent_and_binds_receipt(self) -> None:
        parameters = self.executable_parameters()
        intent = captain_execution_intent(parameters)
        parameters["execution_intent"] = intent
        gh = self.mergeable_gh()

        result = self.run_captain_run(parameters, gh)

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("executed", result["output"]["decision"])
        info = result["output"]["execution_intent"]
        self.assertTrue(info["present"])
        self.assertTrue(info["valid"])
        self.assertEqual([], info["errors"])
        self.assertEqual(grips.sha256_json(intent), info["intent_sha256"])
        self.assertEqual("pr-merge", info["action"])
        self.assertEqual(CAPTAIN_HEAD, info["expected_head"])
        self.assertEqual("main", info["expected_base"])
        self.assertEqual(CAPTAIN_BASE_SHA, info["expected_base_sha"])
        self.assertEqual(intent["target_sha256"], info["target_sha256"])
        self.assertEqual(intent["evidence_sha256"], info["evidence_sha256"])
        self.assertEqual(grips.sha256_json(intent["actor"]), info["actor_sha256"])
        self.assertEqual(grips.sha256_json(intent["context"]), info["context_sha256"])
        self.assertEqual(
            info["intent_sha256"],
            result["output"]["actions"][0]["captain_receipt"]["execution_intent_sha256"],
        )
        intent_checks = [check for check in result["receipt"]["checks"] if check["id"] == "execution-intent-bound"]
        self.assertEqual("pass", intent_checks[-1]["status"])
        self.assertTrue([call for call in gh.calls if call[:2] == ("pr", "merge")])

    def test_captain_run_blocks_runtime_deploy_without_intent_before_scheduler(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "inspect the scheduled job and roll back to the previous release",
            },
            receipt_path="receipts/captain/runtime-deploy.json",
        )
        parameters = self.executable_parameters([action])
        gh = FakeGh()

        with patch.object(grips, "_runtime_deploy_self_preflight") as preflight, patch.object(
            grips, "_runtime_deploy_self_schedule"
        ) as scheduler:
            result = self.run_captain_run(parameters, gh)

        self.assert_blocked_without_executor_calls(result, gh, "execution_intent_missing")
        preflight.assert_not_called()
        scheduler.assert_not_called()

    def test_captain_run_receipts_do_not_echo_execution_intent_secrets(self) -> None:
        actor_secret = "SECRET-ACTOR-TOKEN-b2f0"
        context_secret = "SECRET-CONTEXT-KEY-91cd"
        for drift in (False, True):
            with self.subTest(drift=drift):
                parameters = self.executable_parameters()
                overrides: dict[str, object] = {
                    "actor": {"id": "alex", "session_token": actor_secret},
                    "context": {
                        "surface": "captain-run",
                        "lease_owner_id": "captain-test-owner",
                        "api_key": context_secret,
                    },
                }
                if drift:
                    overrides["expected_head"] = "a" * 40
                    overrides["smuggled_credential"] = context_secret
                intent = captain_execution_intent(parameters, **overrides)
                parameters["execution_intent"] = intent
                gh = self.mergeable_gh()

                result = self.run_captain_run(parameters, gh)

                serialized = grips.canonical_json(result)
                self.assertNotIn(actor_secret, serialized)
                self.assertNotIn(context_secret, serialized)
                self.assertNotIn("session_token", serialized)
                self.assertNotIn("api_key", serialized)
                self.assertNotIn("smuggled_credential", serialized)
                info = result["output"]["execution_intent"]
                self.assertEqual(grips.sha256_json(intent["actor"]), info["actor_sha256"])
                self.assertEqual(grips.sha256_json(intent["context"]), info["context_sha256"])
                if drift:
                    self.assertEqual("blocked", result["receipt"]["status"])
                    self.assertIn("execution_intent_head_drift", result["output"]["blocked_reasons"])
                    self.assertEqual([], gh.calls)
                else:
                    self.assertEqual("passed", result["receipt"]["status"])


class GateEvidenceConvergenceGripTests(unittest.TestCase):
    @staticmethod
    def complete_gate_parameters() -> dict[str, object]:
        return {
            "gate_owner": "merge-guard",
            "policy_boundary": "fresh leases and exact target identity are mandatory",
            "target": {"kind": "pull_request", "identifier": "heimgewebe/grabowski#257"},
            "scope": {"operation": "merge", "resource": "repo:heimgewebe/grabowski"},
            "expected_identity": {"head": "a" * 40, "base": "b" * 40},
            "evidence": {
                category: {"status": "satisfied", "reference": f"SECRET-REF-{category}"}
                for category in (
                    "leases",
                    "dirty_state",
                    "running_work",
                    "receipt",
                    "acceptance",
                    "post_state_readback",
                )
            },
            "attempt": {
                "prior_attempt": False,
                "evidence_changed": False,
                "change_reference": "",
            },
        }

    def test_gate_evidence_preflight_prepares_without_granting_authority(self) -> None:
        parameters = self.complete_gate_parameters()
        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("passed", result["receipt"]["status"])
        output = result["output"]
        self.assertTrue(output["ready_for_gate_evaluation"])
        self.assertEqual("evidence_prepared", output["decision"])
        self.assertIn("execution_authority", output["does_not_establish"])
        serialized = grips.canonical_json(result)
        self.assertNotIn("SECRET-REF", serialized)
        self.assertTrue(all(len(item["reference_sha256"]) == 64 for item in output["evidence"]))

    def test_gate_evidence_preflight_preserves_numeric_and_boolean_identity_types(self) -> None:
        parameters = self.complete_gate_parameters()
        parameters["target"] = {
            "repo": "heimgewebe/grabowski",
            "pr": 258,
            "draft": False,
        }
        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual(
            grips.sha256_json(parameters["target"]),
            result["output"]["target_sha256"],
        )
        self.assertNotEqual(
            grips.sha256_json({"repo": "heimgewebe/grabowski", "pr": "258", "draft": "False"}),
            result["output"]["target_sha256"],
        )

    def test_gate_evidence_preflight_rejects_change_flag_on_first_attempt(self) -> None:
        parameters = self.complete_gate_parameters()
        parameters["attempt"] = {
            "prior_attempt": False,
            "evidence_changed": True,
            "change_reference": "not-a-retry",
        }

        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("prior_attempt is false", result["output"]["error"])

    def test_gate_evidence_preflight_blocks_missing_and_unchanged_retry(self) -> None:
        parameters = self.complete_gate_parameters()
        parameters["evidence"]["receipt"] = {"status": "missing", "reference": "receipt absent"}
        parameters["attempt"] = {
            "prior_attempt": True,
            "evidence_changed": False,
            "change_reference": None,
        }

        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual(
            ["missing_evidence:receipt", "unchanged_retry_rejected"],
            result["output"]["blocked_reasons"],
        )
        self.assertFalse(result["output"]["ready_for_gate_evaluation"])

    def test_gate_evidence_preflight_rejects_nonempty_nonscalar_unchanged_reference(self) -> None:
        parameters = self.complete_gate_parameters()
        parameters["attempt"] = {
            "prior_attempt": True,
            "evidence_changed": False,
            "change_reference": {"unexpected": "object"},
        }

        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("attempt.change_reference", result["output"]["error"])
        self.assertNotIn("unhashable", result["output"]["error"])

    def test_gate_evidence_preflight_requires_named_change_reference(self) -> None:
        parameters = self.complete_gate_parameters()
        parameters["attempt"] = {
            "prior_attempt": True,
            "evidence_changed": True,
            "change_reference": "",
        }

        result = grips.grip_run("gate-evidence-preflight", parameters)

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("attempt.change_reference", result["output"]["error"])

    def test_convergence_state_classify_preserves_meaning_and_conflicts(self) -> None:
        def record(record_id: str, **evidence: object) -> dict[str, object]:
            value = {
                "record_id": record_id,
                "observed_state": "failed",
                "failure_evidence": None,
                "expected_evidence": None,
                "blocking_evidence": None,
                "superseding_evidence": None,
                "resolution_evidence": None,
            }
            value.update(evidence)
            return value

        result = grips.grip_run(
            "convergence-state-classify",
            {
                "records": [
                    record("defect", failure_evidence="SECRET-defect"),
                    record("expected", failure_evidence="failure", expected_evidence="expected-red"),
                    record("blocked", failure_evidence="failure", blocking_evidence="policy-gate"),
                    record("superseded", failure_evidence="failure", superseding_evidence="pr-243"),
                    record("resolved", failure_evidence="failure", resolution_evidence="receipt-17"),
                    record("unknown"),
                    record("conflicted", expected_evidence="red", blocking_evidence="gate"),
                ]
            },
        )

        self.assertEqual("passed", result["receipt"]["status"])
        by_id = {item["record_id"]: item for item in result["output"]["records"]}
        for record_id in ("defect", "expected", "blocked", "superseded", "resolved", "unknown", "conflicted"):
            self.assertEqual(record_id, by_id[record_id]["classification"])
        self.assertEqual(1, result["output"]["counts"]["conflicted"])
        self.assertNotIn("SECRET-defect", grips.canonical_json(result))
        self.assertIn("automatic_closeout", result["output"]["does_not_establish"])

    def test_convergence_state_classify_documents_terminal_priority_combinations(self) -> None:
        def record(record_id: str, **evidence: object) -> dict[str, object]:
            value = {
                "record_id": record_id,
                "observed_state": "failed",
                "failure_evidence": "failure",
                "expected_evidence": None,
                "blocking_evidence": None,
                "superseding_evidence": None,
                "resolution_evidence": None,
            }
            value.update(evidence)
            return value

        result = grips.grip_run(
            "convergence-state-classify",
            {
                "records": [
                    record("resolved-blocked", resolution_evidence="receipt", blocking_evidence="old-gate"),
                    record("superseded-blocked", superseding_evidence="replacement", blocking_evidence="old-gate"),
                    record("terminal-conflict", resolution_evidence="receipt", superseding_evidence="replacement"),
                ]
            },
        )

        by_id = {item["record_id"]: item for item in result["output"]["records"]}
        self.assertEqual("resolved", by_id["resolved-blocked"]["classification"])
        self.assertEqual("superseded", by_id["superseded-blocked"]["classification"])
        self.assertEqual("conflicted", by_id["terminal-conflict"]["classification"])

    def test_convergence_state_classify_accepts_empty_bounded_snapshot(self) -> None:
        result = grips.grip_run(
            "convergence-state-classify",
            {"records": []},
        )
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual([], result["output"]["records"])
        self.assertEqual(0, result["output"]["decision_required_count"])
        self.assertTrue(all(value == 0 for value in result["output"]["counts"].values()))

    def test_convergence_state_classify_rejects_duplicate_ids(self) -> None:
        duplicate = {
            "record_id": "same",
            "observed_state": "failed",
            "failure_evidence": "failure",
            "expected_evidence": None,
            "blocking_evidence": None,
            "superseding_evidence": None,
            "resolution_evidence": None,
        }
        result = grips.grip_run(
            "convergence-state-classify",
            {"records": [duplicate, dict(duplicate)]},
        )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("duplicate record_id", result["output"]["error"])


class WorktreeHygieneReconcileTests(unittest.TestCase):
    OWNER = "operator:test-worktree-hygiene"
    HEAD = "a" * 40
    BRANCH = "feat/terminal-work"

    def _owned_item(
        self,
        path: str,
        *,
        state: str = "retained",
        dirty: bool | None = False,
        blocking: bool = False,
        archive: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "path": path,
            "is_main": False,
            "head": self.HEAD,
            "branch": self.BRANCH,
            "status": {"dirty": dirty},
            "coordination": {"blocking": blocking},
            "lifecycle_state": state,
            "lifecycle": {
                "retention": {
                    "owner_id": self.OWNER,
                    "retention_until_unix": int(time.time()) + 3600,
                }
                if archive is None
                else None,
                "binding": None,
                "latest_archive": archive,
            },
        }

    def _parameters(self, repo: str, *, apply_cleanup: bool = False) -> dict[str, object]:
        return {
            "repo": repo,
            "owner_id": self.OWNER,
            "apply_cleanup": apply_cleanup,
            "confirmation": grips.WORKTREE_HYGIENE_CONFIRMATION,
        }

    def test_exact_merged_pr_archives_owned_clean_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "1" * 64,
                "worktrees": [self._owned_item(checkout)],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv[:2] == ["repo", "view"]:
                    return {
                        "returncode": 0,
                        "stdout": json.dumps({"defaultBranchRef": {"name": "main"}}),
                        "stderr": "",
                    }
                self.assertIn("merged", argv)
                return {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 77,
                                "url": "https://github.com/heimgewebe/grabowski/pull/77",
                                "state": "MERGED",
                                "baseRefName": "main",
                                "headRefName": self.BRANCH,
                                "headRefOid": self.HEAD,
                                "mergedAt": "2026-07-22T01:00:00Z",
                            }
                        ]
                    ),
                    "stderr": "",
                }

            archive_result = {
                "archive": {
                    "archive_id": "20260722T010000Z-aaaaaaaaaaaa",
                    "created_at_unix": 1000,
                }
            }
            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch(
                    "grabowski_checkouts.grabowski_checkout_archive",
                    return_value=archive_result,
                ) as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        self.assertEqual("passed", result["receipt"]["status"] )
        self.assertEqual(1, result["output"]["actions"])
        self.assertEqual(1, len(result["output"]["archived"]))
        self.assertEqual(77, result["output"]["archived"][0]["merged_pr"]["number"])
        archive.assert_called_once()
        self.assertEqual(self.HEAD, archive.call_args.kwargs["expected_head"])
        self.assertEqual(self.BRANCH, archive.call_args.kwargs["expected_branch"])

    def test_head_mismatch_does_not_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "2" * 64,
                "worktrees": [self._owned_item(checkout)],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv[:2] == ["repo", "view"]:
                    return {
                        "returncode": 0,
                        "stdout": json.dumps({"defaultBranchRef": {"name": "main"}}),
                        "stderr": "",
                    }
                return {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 78,
                                "url": "https://github.com/heimgewebe/grabowski/pull/78",
                                "state": "MERGED",
                                "baseRefName": "main",
                                "headRefName": self.BRANCH,
                                "headRefOid": "b" * 40,
                                "mergedAt": "2026-07-22T01:00:00Z",
                            }
                        ]
                    ),
                    "stderr": "",
                }

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_archive") as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        archive.assert_not_called()
        self.assertEqual(0, result["output"]["actions"])
        self.assertEqual("terminality_not_proven", result["output"]["skipped"][0]["reason"])

    def test_dirty_or_coordinated_checkout_fails_closed_before_github(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            inventory = {
                "inventory_sha256": "3" * 64,
                "worktrees": [
                    self._owned_item(str(Path(tmp) / "dirty"), dirty=True),
                    self._owned_item(str(Path(tmp) / "blocked"), blocking=True),
                ],
            }

            def github_runner(_repo: Path, _argv: list[str]) -> dict[str, object]:
                raise AssertionError("GitHub must not be queried for unsafe checkouts")

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_archive") as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        archive.assert_not_called()
        self.assertEqual(0, result["output"]["github_queries"])
        self.assertEqual(
            ["active_coordination", "dirty_or_unobservable"],
            sorted(item["reason"] for item in result["output"]["skipped"]),
        )

    def test_cleanup_candidate_uses_dry_run_hash_before_apply(self) -> None:
        archive_record = {
            "owner_id": self.OWNER,
            "archive_id": "20260721T010000Z-bbbbbbbbbbbb",
        }
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "4" * 64,
                "worktrees": [
                    self._owned_item(
                        checkout,
                        state="cleanup_candidate",
                        archive=archive_record,
                    )
                ],
            }
            dry = {
                "plan": {
                    "plan_sha256": "c" * 64,
                    "safe_to_apply": True,
                    "archive_id": archive_record["archive_id"],
                },
                "dry_run_record": {"plan_id": "cleanup-plan-1"},
            }
            applied = {"applied_at_unix": 2000}
            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch(
                    "grabowski_checkouts.grabowski_checkout_cleanup",
                    side_effect=[dry, applied],
                ) as cleanup,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp, apply_cleanup=True),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=lambda _repo, _argv: {
                        "returncode": 1, "stdout": "", "stderr": "not expected"
                    },
                )

        self.assertEqual(2, cleanup.call_count)
        self.assertTrue(cleanup.call_args_list[0].kwargs["dry_run"])
        self.assertFalse(cleanup.call_args_list[1].kwargs["dry_run"])
        self.assertEqual("cleanup-plan-1", cleanup.call_args_list[1].kwargs["plan_id"])
        self.assertEqual("c" * 64, cleanup.call_args_list[1].kwargs["expected_plan_sha256"])
        self.assertEqual(1, len(result["output"]["cleaned"]))
        self.assertEqual(2, result["output"]["actions"])

    def test_cleanup_action_bound_can_stop_after_persisted_dry_run(self) -> None:
        archive_record = {
            "owner_id": self.OWNER,
            "archive_id": "20260721T010000Z-dddddddddddd",
        }
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "6" * 64,
                "worktrees": [
                    self._owned_item(
                        checkout,
                        state="cleanup_candidate",
                        archive=archive_record,
                    )
                ],
            }
            dry = {
                "plan": {
                    "plan_sha256": "d" * 64,
                    "safe_to_apply": True,
                    "archive_id": archive_record["archive_id"],
                },
                "dry_run_record": {"plan_id": "cleanup-plan-bound"},
            }
            parameters = self._parameters(tmp, apply_cleanup=True)
            parameters["max_actions"] = 1
            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch(
                    "grabowski_checkouts.grabowski_checkout_cleanup",
                    return_value=dry,
                ) as cleanup,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    parameters,
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=lambda _repo, _argv: {
                        "returncode": 1, "stdout": "", "stderr": "not expected"
                    },
                )

        self.assertEqual(1, cleanup.call_count)
        self.assertEqual(1, result["output"]["actions"])
        self.assertEqual([], result["output"]["cleaned"])
        self.assertEqual(
            "cleanup_apply_deferred_by_action_bound",
            result["output"]["skipped"][0]["reason"],
        )

    def test_ownerless_clean_checkout_is_adopted_only_after_exact_merge_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "legacy-worktree")
            item = self._owned_item(checkout, state="unclassified_clean")
            item["lifecycle"]["retention"] = None
            inventory = {
                "inventory_sha256": "5" * 64,
                "worktrees": [item],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv[:2] == ["repo", "view"]:
                    return {
                        "returncode": 0,
                        "stdout": json.dumps({"defaultBranchRef": {"name": "main"}}),
                        "stderr": "",
                    }
                return {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 79,
                                "url": "https://github.com/heimgewebe/grabowski/pull/79",
                                "state": "MERGED",
                                "baseRefName": "main",
                                "headRefName": self.BRANCH,
                                "headRefOid": self.HEAD,
                                "mergedAt": "2026-07-22T01:00:00Z",
                            }
                        ]
                    ),
                    "stderr": "",
                }

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch(
                    "grabowski_checkouts.grabowski_checkout_archive",
                    return_value={
                        "archive": {
                            "archive_id": "20260722T010000Z-cccccccccccc",
                            "created_at_unix": 1000,
                        }
                    },
                ) as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        self.assertEqual(1, result["output"]["adopted_unowned_count"])
        self.assertEqual(
            "adopt_unowned_after_terminal_proof",
            result["output"]["archived"][0]["ownership_mode"],
        )
        self.assertEqual(self.OWNER, archive.call_args.kwargs["owner_id"])

    def test_default_branch_lookup_failure_blocks_archival(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "9" * 64,
                "worktrees": [self._owned_item(checkout)],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                self.assertEqual(["repo", "view"], argv[:2])
                return {"returncode": 1, "stdout": "", "stderr": "offline"}

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_archive") as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        archive.assert_not_called()
        self.assertEqual(0, result["output"]["actions"])
        self.assertIsNone(result["output"]["default_branch"])
        self.assertEqual(
            "default_branch_not_proven",
            result["output"]["skipped"][0]["reason"],
        )

    def test_non_default_branch_merge_does_not_prove_terminality(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            inventory = {
                "inventory_sha256": "7" * 64,
                "worktrees": [self._owned_item(checkout)],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv[:2] == ["repo", "view"]:
                    return {
                        "returncode": 0,
                        "stdout": json.dumps({"defaultBranchRef": {"name": "main"}}),
                        "stderr": "",
                    }
                return {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 80,
                                "url": "https://github.com/heimgewebe/grabowski/pull/80",
                                "state": "MERGED",
                                "baseRefName": "integration",
                                "headRefName": self.BRANCH,
                                "headRefOid": self.HEAD,
                                "mergedAt": "2026-07-22T01:00:00Z",
                            }
                        ]
                    ),
                    "stderr": "",
                }

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_archive") as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        archive.assert_not_called()
        self.assertEqual(0, result["output"]["actions"])
        self.assertEqual("main", result["output"]["default_branch"])
        self.assertEqual(
            "terminality_not_proven", result["output"]["skipped"][0]["reason"]
        )

    def test_active_retention_blocks_cleanup_even_for_same_owner(self) -> None:
        archive_record = {
            "owner_id": self.OWNER,
            "archive_id": "20260721T010000Z-eeeeeeeeeeee",
        }
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "worktree")
            item = self._owned_item(
                checkout,
                state="cleanup_candidate",
                archive=archive_record,
            )
            item["lifecycle"]["retention"] = {
                "owner_id": self.OWNER,
                "retention_until_unix": int(time.time()) + 3600,
            }
            inventory = {
                "inventory_sha256": "8" * 64,
                "worktrees": [item],
            }
            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_cleanup") as cleanup,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp, apply_cleanup=True),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=lambda _repo, _argv: {
                        "returncode": 1, "stdout": "", "stderr": "not expected"
                    },
                )

        cleanup.assert_not_called()
        self.assertEqual(0, result["output"]["actions"])
        self.assertEqual(
            "active_retention_not_elapsed",
            result["output"]["skipped"][0]["reason"],
        )

    def test_expired_retention_can_be_adopted_after_exact_terminal_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "expired-retention-worktree")
            item = self._owned_item(checkout, state="unclassified_clean")
            item["lifecycle"]["retention"] = {
                "owner_id": "operator:expired-owner",
                "retention_until_unix": int(time.time()) - 60,
            }
            inventory = {
                "inventory_sha256": "a" * 64,
                "worktrees": [item],
            }

            def github_runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv[:2] == ["repo", "view"]:
                    return {
                        "returncode": 0,
                        "stdout": json.dumps({"defaultBranchRef": {"name": "main"}}),
                        "stderr": "",
                    }
                return {
                    "returncode": 0,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 81,
                                "url": "https://github.com/heimgewebe/grabowski/pull/81",
                                "state": "MERGED",
                                "baseRefName": "main",
                                "headRefName": self.BRANCH,
                                "headRefOid": self.HEAD,
                                "mergedAt": "2026-07-22T01:00:00Z",
                            }
                        ]
                    ),
                    "stderr": "",
                }

            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch(
                    "grabowski_checkouts.grabowski_checkout_archive",
                    return_value={
                        "archive": {
                            "archive_id": "20260722T010000Z-ffffffffffff",
                            "created_at_unix": 1000,
                        }
                    },
                ) as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=github_runner,
                )

        self.assertEqual(1, result["output"]["adopted_unowned_count"])
        self.assertEqual(0, result["output"]["foreign_owned_count"])
        archive.assert_called_once()
        self.assertEqual(self.OWNER, archive.call_args.kwargs["owner_id"])

    def test_expired_retention_does_not_override_foreign_lifecycle_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checkout = str(Path(tmp) / "bound-worktree")
            item = self._owned_item(checkout, state="unclassified_clean")
            item["lifecycle"]["retention"] = {
                "owner_id": "operator:expired-owner",
                "retention_until_unix": int(time.time()) - 60,
            }
            item["lifecycle"]["binding"] = {"owner_id": "operator:binding-owner"}
            inventory = {
                "inventory_sha256": "b" * 64,
                "worktrees": [item],
            }
            with (
                patch("grabowski_checkouts.checkout_inventory", return_value=inventory),
                patch("grabowski_checkouts.grabowski_checkout_archive") as archive,
            ):
                result = grips.run_grip(
                    "worktree-hygiene-reconcile",
                    self._parameters(tmp),
                    allow_mutation=True,
                    command_runner=FakeGit(),
                    github_runner=lambda _repo, _argv: {
                        "returncode": 1, "stdout": "", "stderr": "must not run"
                    },
                )

        archive.assert_not_called()
        self.assertEqual(0, result["output"]["actions"])
        self.assertEqual(1, result["output"]["foreign_owned_count"])
        self.assertEqual(0, result["output"]["adopted_unowned_count"])

    def test_surface_marks_worktree_hygiene_as_high_risk_and_not_mechanic_normal(self) -> None:
        spec = next(
            item for item in grips.list_grips()
            if item["name"] == "worktree-hygiene-reconcile"
        )
        self.assertEqual("high", spec["risk"])
        self.assertEqual("mutating", spec["effect"])
        self.assertNotIn("worktree-hygiene-reconcile", grips.MECHANIC_NORMAL_GRIPS)
