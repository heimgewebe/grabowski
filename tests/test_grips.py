from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_grips as grips


class FakeGit:
    def __init__(self, *, branch: str = "feat/work", dirty: bool = False, upstream: str | None = "origin/feat/work"):
        self.branch = branch
        self.dirty = dirty
        self.upstream = upstream
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv == ["rev-parse", "--show-toplevel"]:
            return {"returncode": 0, "stdout": str(repo), "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return {"returncode": 0, "stdout": self.branch, "stderr": ""}
        if argv == ["rev-parse", "HEAD"]:
            return {"returncode": 0, "stdout": "a" * 40, "stderr": ""}
        if argv == ["status", "--short", "--branch"]:
            body = "\n M src/example.py" if self.dirty else ""
            upstream = self.upstream or ""
            return {"returncode": 0, "stdout": f"## {self.branch}...{upstream}{body}", "stderr": ""}
        if argv == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
            if self.upstream is None:
                return {"returncode": 128, "stdout": "", "stderr": "no upstream"}
            return {"returncode": 0, "stdout": self.upstream, "stderr": ""}
        return {"returncode": 1, "stdout": "", "stderr": f"unexpected command: {argv}"}


class GripFoundationTests(unittest.TestCase):
    def test_list_grips_exposes_core_foundation_specs(self) -> None:
        listed = grips.list_grips()
        names = {item["name"] for item in listed}
        self.assertEqual({"post-merge-sync", "pr-check-readiness", "repo-orient"}, names)
        for item in listed:
            self.assertIn("acceptance_ids", item)
            self.assertEqual("read_only", item["effect"])

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

    def test_preflight_blocks_missing_required_parameter_with_receipt(self) -> None:
        result = grips.run_grip("repo-orient", {}, command_runner=FakeGit())

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual("preflight", result["receipt"]["phase"])
        self.assertIn("missing required parameters", result["output"]["error"])
        self.assertEqual(64, len(result["receipt"]["receipt_sha256"]))

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
