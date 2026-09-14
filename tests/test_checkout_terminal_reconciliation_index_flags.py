from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_checkouts as checkouts
import grabowski_checkout_terminal_reconciliation as reconciliation


class CheckoutTerminalReconciliationIndexFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Grabowski Test")
        self._git("config", "user.email", "grabowski@example.invalid")
        (self.repo / "tracked.txt").write_text("initial\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text(".review-audits/\n", encoding="utf-8")
        self._git("add", "tracked.txt", ".gitignore")
        self._git("commit", "-m", "initial")
        evidence_root = self.repo / ".review-audits"
        evidence_root.mkdir()
        (evidence_root / "review.json").write_text("{}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @staticmethod
    def _git_read(
        repo: Path, arguments: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _review_evidence_blockers(self) -> tuple[list[str], list[str]]:
        with patch.object(checkouts, "_git_read", side_effect=self._git_read):
            return reconciliation._thread_focus_review_evidence_paths(
                self.repo,
                {"entry_count": 0, "untracked_count": 0},
            )

    def test_assume_unchanged_tracked_change_blocks_evidence_only_admission(self) -> None:
        self._git("update-index", "--assume-unchanged", "tracked.txt")
        (self.repo / "tracked.txt").write_text("hidden change\n", encoding="utf-8")

        diff = subprocess.run(
            ["git", "-C", str(self.repo), "diff", "--quiet", "--no-ext-diff", "--"],
            check=False,
        )
        status = self._git("status", "--short")
        self.assertEqual(0, diff.returncode)
        self.assertEqual("", status.stdout)

        paths, blockers = self._review_evidence_blockers()
        self.assertIn(".review-audits/review.json", paths)
        self.assertIn("review-evidence-assume-unchanged-present", blockers)

    def test_skip_worktree_tracked_change_blocks_evidence_only_admission(self) -> None:
        self._git("update-index", "--skip-worktree", "tracked.txt")
        (self.repo / "tracked.txt").write_text("hidden change\n", encoding="utf-8")

        diff = subprocess.run(
            ["git", "-C", str(self.repo), "diff", "--quiet", "--no-ext-diff", "--"],
            check=False,
        )
        status = self._git("status", "--short")
        self.assertEqual(0, diff.returncode)
        self.assertEqual("", status.stdout)

        paths, blockers = self._review_evidence_blockers()
        self.assertIn(".review-audits/review.json", paths)
        self.assertIn("review-evidence-skip-worktree-present", blockers)


if __name__ == "__main__":
    unittest.main()
