from __future__ import annotations

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


class CheckoutTerminalReconciliationToctouTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Grabowski Test")
        self._git("config", "user.email", "grabowski@example.invalid")
        (self.repo / "tracked.txt").write_text("initial\n", encoding="utf-8")
        (self.repo / ".gitignore").write_text(
            ".review-audits/\nignored-local/\n", encoding="utf-8"
        )
        self._git("add", "tracked.txt", ".gitignore")
        self._git("commit", "-m", "initial")
        self.evidence_root = self.repo / ".review-audits"
        self.evidence_root.mkdir()
        self.audit = self.evidence_root / "review.json"
        self.audit.write_text('{"verdict":"PASS"}\n', encoding="utf-8")

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

    @staticmethod
    def _status() -> dict[str, object]:
        return {"entry_count": 0, "untracked_count": 0}

    def test_rejects_audit_content_changed_after_initial_hash(self) -> None:
        real_hash = reconciliation._hash_review_evidence_file
        hash_calls = 0

        def hash_with_late_content_change(
            root_descriptor: int, raw_path: str, remaining_bytes: int
        ) -> tuple[dict[str, object] | None, list[str]]:
            nonlocal hash_calls
            result = real_hash(root_descriptor, raw_path, remaining_bytes)
            hash_calls += 1
            if hash_calls == 1:
                self.audit.write_text('{"verdict":"BLOCK"}\n', encoding="utf-8")
            return result

        with (
            patch.object(checkouts, "_git_read", side_effect=self._git_read),
            patch.object(
                reconciliation,
                "_hash_review_evidence_file",
                side_effect=hash_with_late_content_change,
            ),
        ):
            observation = reconciliation._thread_focus_review_evidence_observation(
                {"path": str(self.repo)}, self._status()
            )

        self.assertFalse(observation["eligible"])
        self.assertIn(
            "review-evidence-file-changed-after-read", observation["blockers"]
        )

    def test_rejects_ignored_content_added_after_initial_inventory(self) -> None:
        real_ignored_roots = reconciliation._review_evidence_ignored_roots
        inventory_calls = 0

        def roots_with_late_ignored_content(
            checkout: Path,
        ) -> tuple[list[str], list[str]]:
            nonlocal inventory_calls
            result = real_ignored_roots(checkout)
            inventory_calls += 1
            if inventory_calls == 2:
                ignored = self.repo / "ignored-local"
                ignored.mkdir()
                (ignored / "cache.bin").write_bytes(b"late ignored content")
            return result

        with (
            patch.object(checkouts, "_git_read", side_effect=self._git_read),
            patch.object(
                reconciliation,
                "_review_evidence_ignored_roots",
                side_effect=roots_with_late_ignored_content,
            ),
        ):
            observation = reconciliation._thread_focus_review_evidence_observation(
                {"path": str(self.repo)}, self._status()
            )

        self.assertFalse(observation["eligible"])
        self.assertIn(
            "review-evidence-ignored-inventory-drift", observation["blockers"]
        )
        self.assertIn(
            "review-evidence-ignored-content-outside-allowlist",
            observation["blockers"],
        )


if __name__ == "__main__":
    unittest.main()
