from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from grabowski_pr_diff import (  # noqa: E402
    BoundLocalDiffError,
    _bounded_git_capture,
    bound_local_pr_git_diff,
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


class BoundLocalPrDiffTests(unittest.TestCase):
    def test_head_attributes_override_dirty_worktree_without_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr-diff-attrs-") as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "config", "user.email", "diff@example.invalid")
            _git(repo, "config", "user.name", "Diff Test")
            (repo / "data.dat").write_text("before\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD")
            (repo / ".gitattributes").write_text("*.dat -diff\n")
            (repo / "data.dat").write_text("after\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "head")
            head = _git(repo, "rev-parse", "HEAD")
            expected = subprocess.run(
                ["git", "-C", str(repo), "diff", "--no-renames", base, head],
                check=True, capture_output=True,
            ).stdout
            self.assertIn(b"Binary files", expected)
            (repo / ".gitattributes").write_text("*.dat diff\n")
            corrupted = subprocess.run(
                ["git", "-C", str(repo), "diff", "--no-renames", base, head],
                check=True, capture_output=True,
            ).stdout
            self.assertNotEqual(corrupted, expected)
            bounded = bound_local_pr_git_diff(repo, merge_base=base, head=head)
            self.assertEqual(bounded, expected)
            self.assertEqual((repo / ".gitattributes").read_text(), "*.dat diff\n")
            self.assertIn(" .gitattributes", _git(repo, "status", "--short"))

            info = repo / ".git" / "info" / "attributes"
            info.parent.mkdir(parents=True, exist_ok=True)
            info.write_text("*.dat diff\n")
            with self.assertRaisesRegex(BoundLocalDiffError, "info/attributes"):
                bound_local_pr_git_diff(repo, merge_base=base, head=head)

    def test_stdout_oversize_kills_early_and_never_returns_partial_diff(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(BoundLocalDiffError, "byte budget"):
                _bounded_git_capture(
                    [sys.executable, "-c", "import os; os.write(1,b'x'*131072)"],
                    cwd=d, env=os.environ.copy(), stdout_limit=4096, timeout=10,
                )

    def test_single_line_and_stderr_cannot_exceed_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(BoundLocalDiffError, "byte budget"):
                _bounded_git_capture(
                    [sys.executable, "-c", "import os; os.write(1,b'a'*1000000)"],
                    cwd=d, env=os.environ.copy(), stdout_limit=1024, timeout=10,
                )
            with self.assertRaisesRegex(BoundLocalDiffError, "byte budget"):
                _bounded_git_capture(
                    [sys.executable, "-c", "import os; os.write(2,b'x'*200000)"],
                    cwd=d, env=os.environ.copy(), stdout_limit=4096, timeout=10,
                )

    def test_both_pipes_are_drained_without_deadlock(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            result = _bounded_git_capture(
                [sys.executable, "-c",
                 "import os; os.write(2,b'e'*70000); os.write(1,b'o'*70000)"],
                cwd=d, env=os.environ.copy(), stdout_limit=75000, timeout=10,
            )
            self.assertEqual(result, b"o" * 70000)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux process group test")
    def test_timeout_kills_pipe_holder_after_parent_exits(self) -> None:
        import time
        with tempfile.TemporaryDirectory() as d:
            pid_file = Path(d) / "child.pid"
            script = (
                "import pathlib,subprocess,sys; "
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import time;time.sleep(8)']); "
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid))"
            )
            with self.assertRaisesRegex(BoundLocalDiffError, "timed out"):
                _bounded_git_capture(
                    [sys.executable, "-c", script, str(pid_file)],
                    cwd=d, env=os.environ.copy(), stdout_limit=4096, timeout=1,
                )
            pid = int(pid_file.read_text())
            # A briefly surviving zombie is permitted; a live child is not.
            for _ in range(20):
                stat = Path(f"/proc/{pid}/stat")
                if not stat.exists() or stat.read_text().split()[2] == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("pipe-inheriting child survived timeout cleanup")

    def test_subprocess_timeout_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(BoundLocalDiffError, "timed out"):
                _bounded_git_capture(
                    [sys.executable, "-c", "import time; time.sleep(2)"],
                    cwd=d, env=os.environ.copy(), stdout_limit=4096, timeout=1,
                )

    def test_invalid_bound_revision_and_unbounded_budget_rejected(self) -> None:
        with self.assertRaises(BoundLocalDiffError):
            bound_local_pr_git_diff(Path("/tmp"), merge_base="x" * 40, head="a" * 40)
        with self.assertRaises(BoundLocalDiffError):
            bound_local_pr_git_diff(Path("/tmp"), merge_base="a" * 40,
                                    head="b" * 40, max_diff_bytes=1 << 40)


if __name__ == "__main__":
    unittest.main()