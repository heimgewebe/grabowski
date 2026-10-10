"""Real Git regressions for revision-bound local PR diff config/tree independence."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_pr_diff as pr_diff
from grabowski_pr_diff import bound_local_pr_git_diff, local_pr_git_environment


class BoundLocalPrDiffHardeningTests(unittest.TestCase):
    @staticmethod
    def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> str:
        result = subprocess.run(
            ["git", *args], cwd=repo, input=input_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        return result.stdout.decode("ascii").strip()

    def test_host_system_attributes_are_disabled_independently_of_inherited_env(self) -> None:
        # GIT_CONFIG_NOSYSTEM disables config, not $(prefix)/etc/gitattributes.
        with mock.patch.dict(os.environ, {"GIT_ATTR_NOSYSTEM": "0"}):
            env = local_pr_git_environment()
        self.assertEqual(env["GIT_ATTR_NOSYSTEM"], "1")

    def test_completed_git_command_does_not_kill_reaped_process_group(self) -> None:
        # Reaped PGIDs can be reused; a clean command must not signal its old group.
        with mock.patch("os.killpg") as kill_group:
            result = pr_diff._bounded_git_capture(
                ["git", "--version"], cwd=str(Path.cwd()),
                env=local_pr_git_environment(), timeout=5, stdout_limit=2048,
            )
        self.assertIn(b"git version", result)
        kill_group.assert_not_called()

    def test_local_diff_subcommands_share_one_aggregate_deadline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr-diff-deadline-") as d:
            repo = Path(d)
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.email", "test@example.invalid")
            self.git(repo, "config", "user.name", "PR Diff Test")
            (repo / "a.txt").write_text("before\\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "base")
            base = self.git(repo, "rev-parse", "HEAD")
            (repo / "a.txt").write_text("after\\n")
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "head")
            head = self.git(repo, "rev-parse", "HEAD")
            original = pr_diff._bounded_git_capture
            budgets: list[float] = []

            def track(*args: object, **kwargs: object) -> bytes:
                budgets.append(float(kwargs["timeout"]))
                time.sleep(0.035)
                return original(*args, **kwargs)

            with mock.patch.object(pr_diff, "_bounded_git_capture", side_effect=track):
                result = bound_local_pr_git_diff(
                    repo, merge_base=base, head=head, timeout=8,
                )
            self.assertIn(b"a.txt", result)
            self.assertGreaterEqual(len(budgets), 5)
            self.assertGreater(budgets[0] - budgets[-1], 0.10)

    def test_checkout_diff_config_cannot_change_canonical_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr-diff-config-") as d:
            root = Path(d)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.email", "test@example.invalid")
            self.git(repo, "config", "user.name", "PR Diff Test")
            (repo / "a.txt").write_text("".join(f"line {x}\n" for x in range(15)))
            (repo / "b.txt").write_text("".join(f"second {x}\n" for x in range(15)))
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "base")
            base = self.git(repo, "rev-parse", "HEAD")
            (repo / "a.txt").write_text("".join(f"MOD {x}\n" if x in (2, 11) else f"line {x}\n" for x in range(15)))
            (repo / "b.txt").write_text("".join(f"CHG {x}\n" if x == 7 else f"second {x}\n" for x in range(15)))
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-qm", "head")
            head = self.git(repo, "rev-parse", "HEAD")
            clean = bound_local_pr_git_diff(repo, merge_base=base, head=head)
            (root / "reverse-order.txt").write_text("b.txt\na.txt\n")
            for name, value in (
                ("diff.context", "0"),
                ("diff.algorithm", "patience"),
                ("diff.indentHeuristic", "false"),
                ("diff.noprefix", "true"),
                ("diff.orderFile", str(root / "reverse-order.txt")),
            ):
                self.git(repo, "config", name, value)
            altered = bound_local_pr_git_diff(repo, merge_base=base, head=head)
            self.assertEqual(clean, altered, "checkout-local diff config must not affect pinned bytes")
            self.assertIn(b"diff --git a/a.txt b/a.txt", altered)

    def test_large_nonattribute_tree_does_not_exhaust_attribute_listing_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pr-diff-big-tree-") as d:
            repo = Path(d)
            self.git(repo, "init", "-q")
            # Full make test clears HOME: commit-tree requires local identity.
            self.git(repo, "config", "user.email", "pr-diff@example.invalid")
            self.git(repo, "config", "user.name", "PR Diff Test")
            dummy = self.git(repo, "hash-object", "-w", "--stdin", input_bytes=b"unchanged\n")
            previous = self.git(repo, "hash-object", "-w", "--stdin", input_bytes=b"before\n")
            updated = self.git(repo, "hash-object", "-w", "--stdin", input_bytes=b"after\n")
            attribute = self.git(repo, "hash-object", "-w", "--stdin", input_bytes=b"*.txt text\n")
            common = [
                (f"item_{index:05d}_{'z' * 160}", dummy)
                for index in range(48000)
            ]
            self.assertGreater(48000 * (160 + 70), 8 * 1024 * 1024)

            def commit_tree(target_oid: str, *, parent: str | None = None) -> str:
                entries = [(".gitattributes", attribute), *common, ("target.txt", target_oid)]
                tree_material = b"".join(
                    ("100644 blob " + oid + "\t" + name).encode("ascii") + b"\0"
                    for name, oid in entries
                )
                tree = self.git(repo, "mktree", "-z", input_bytes=tree_material)
                args = ["commit-tree", tree]
                if parent:
                    args += ["-p", parent]
                args += ["-m", "synthetic big tree"]
                return self.git(repo, *args)

            base = commit_tree(previous)
            head = commit_tree(updated, parent=base)
            payload = bound_local_pr_git_diff(repo, merge_base=base, head=head, timeout=70)
            self.assertIn(b"target.txt", payload)
            self.assertNotIn(b"item_00001_", payload)


if __name__ == "__main__":
    unittest.main()
