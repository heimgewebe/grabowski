"""Provider-boundary regression for Git-OID-P2 on the exact #1487 tail.

Native Git object IDs may be SHA-1 or SHA-256, but the current GitHub
pr-base-converge and Captain pr-merge review contract is explicitly SHA-1
only. An unsupported SHA-256 OID must fail *before* contacting GitHub or
performing any protected merge/publication operation. These tests document a
provider-specific limitation; they do not assert end-to-end SHA-256 support.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock

# Same local FastMCP substitute as tests/test_grips.py; it never starts a
# server or changes production provider, controller or Reviewer identity.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeFastMCP:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def tool(self, *args: object, **kwargs: object):
        del args, kwargs
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs: object) -> None:
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

import grabowski_grips as grips


def _native_commit(directory: Path, object_format: str) -> str:
    """Return a real native commit OID from an isolated disposable repository."""
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "init",
         "--quiet", f"--object-format={object_format}", str(directory)],
        check=True, capture_output=True, timeout=15,
    )
    subprocess.run(
        ["git", "-C", str(directory),
         "-c", "user.name=OID Boundary Fixture",
         "-c", "user.email=oid-boundary@invalid.example",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
         "commit", "--quiet", "--allow-empty", "-m", "native OID fixture"],
        check=True, capture_output=True, timeout=15,
    )
    return subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "--verify", "HEAD^{commit}"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()


class GitHubOidProviderBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="grabowski-gh-oid-boundary-")
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.sha1 = _native_commit(folder / "sha1", "sha1")
        self.sha256 = _native_commit(folder / "sha256", "sha256")
        self.assertEqual(40, len(self.sha1))
        self.assertEqual(64, len(self.sha256))

    def test_native_full_widths_are_recognized_without_promoting_provider_scope(self) -> None:
        for oid in (self.sha1, self.sha256):
            with self.subTest(width=len(oid)):
                self.assertEqual(oid, grips._normalize_git_object_id(oid))
        self.assertEqual(self.sha1, grips._normalize_40_sha(self.sha1))
        self.assertIsNone(grips._normalize_40_sha(self.sha256))
        for length in (1, 39, 41, 48, 63, 65):
            with self.subTest(invalid_length=length):
                self.assertIsNone(grips._normalize_git_object_id("a" * length))
                self.assertIsNone(grips._normalize_40_sha("a" * length))
        self.assertIsNone(grips._normalize_git_object_id("z" * 64))

    def test_github_pr_base_converge_rejects_sha256_and_mixed_width_before_effect(self) -> None:
        for head, base in (
            (self.sha256, self.sha256),
            (self.sha256, self.sha1),
            (self.sha1, self.sha256),
        ):
            with self.subTest(head_width=len(head), base_width=len(base)):
                gh = Mock(side_effect=AssertionError("GitHub must not be contacted"))
                git = Mock(side_effect=AssertionError("Git must not be mutated"))
                result = grips.run_grip(
                    "pr-base-converge",
                    {
                        "repo": self.temp.name,
                        "pr_number": 1448,
                        "base": "main",
                        "expected_head": head,
                        "expected_base_sha": base,
                    },
                    allow_mutation=True,
                    command_runner=git,
                    github_runner=gh,
                )
                self.assertEqual("blocked", result["receipt"]["status"])
                self.assertIn("40 character", result["output"]["error"])
                gh.assert_not_called()
                git.assert_not_called()

    def test_captain_pr_merge_review_does_not_infer_sha256_provider_support(self) -> None:
        action = {
            "action": "pr-merge",
            "target": {"repo": "heimgewebe/grabowski", "pr": 1448},
        }
        for head, base in (
            (self.sha256, self.sha1),
            (self.sha1, self.sha256),
            (self.sha256, self.sha256),
        ):
            with self.subTest(head_width=len(head), base_width=len(base)):
                gate = grips._captain_review_evidence_gate(
                    {
                        "expected_head": head,
                        "expected_base_sha": base,
                        "review_evidence": {},
                    },
                    [action],
                )
                self.assertEqual("blocked", gate["status"])
                expected_problem = (
                    "expected_head_missing_or_invalid"
                    if len(head) != 40 else "expected_base_sha_missing_or_invalid"
                )
                self.assertIn(expected_problem, gate["evidence"] if isinstance(gate.get("evidence"), list) else str(gate))


if __name__ == "__main__":
    unittest.main()
