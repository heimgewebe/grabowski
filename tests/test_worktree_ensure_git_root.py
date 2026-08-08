from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


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

import grabowski_worktree_ensure as worktree_ensure  # noqa: E402


class WorktreeGitRootRegressionTests(unittest.TestCase):
    def test_git_toplevel_newline_is_normalized_before_resolve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            target = Path(temporary) / "worktree"
            head = "a" * 40
            branch = "feat/git-root-newline"

            def runner(_repo: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["rev-parse", "--show-toplevel"]:
                    return {"returncode": 0, "stdout": str(repo) + "\n", "stderr": ""}
                if argv == ["check-ref-format", "--branch", branch]:
                    return {"returncode": 0, "stdout": branch + "\n", "stderr": ""}
                if argv == ["rev-parse", "--verify", f"{head}^{{commit}}"]:
                    return {"returncode": 0, "stdout": head + "\n", "stderr": ""}
                if argv == ["worktree", "list", "--porcelain"]:
                    return {
                        "returncode": 0,
                        "stdout": (
                            f"worktree {repo}\n"
                            f"HEAD {head}\n"
                            "branch refs/heads/main\n\n"
                        ),
                        "stderr": "",
                    }
                if argv == ["show-ref", "--verify", "--hash", f"refs/heads/{branch}"]:
                    return {"returncode": 1, "stdout": "", "stderr": ""}
                raise AssertionError(f"unexpected argv: {argv}")

            observed = worktree_ensure._observe(
                {
                    "repo": str(repo),
                    "target_path": str(target),
                    "branch": branch,
                    "base_head": head,
                },
                runner,
            )

        self.assertEqual(observed["classification"], "ABSENT")
        self.assertFalse(observed["target_path_exists"])
        self.assertIsNone(observed["branch_ref_head"])


if __name__ == "__main__":
    unittest.main()
