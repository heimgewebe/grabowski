"""Provider-boundary regression for Git-OID-P2 on the exact #1487 tail.

Native Git object IDs may be SHA-1 or SHA-256, but the current GitHub
pr-base-converge and Captain pr-merge review contract is explicitly SHA-1
only. An unsupported SHA-256 OID must fail *before* contacting GitHub or
performing any protected merge/publication operation. These tests document a
provider-specific limitation; they do not assert end-to-end SHA-256 support.
"""

from __future__ import annotations

from pathlib import Path
import importlib
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

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
    # Restore ONLY the four fake module entries. patch.dict(sys.modules)
    # rolls back transitive imports too, leaving duplicate module/class
    # identities when another test imports grabowski_grips afterwards.
    substitutes = {
        "mcp": fake_mcp,
        "mcp.server": fake_server,
        "mcp.server.fastmcp": fake_fastmcp,
        "mcp.types": fake_types,
    }
    absent = object()
    originals = {key: sys.modules.get(key, absent) for key in substitutes}
    try:
        sys.modules.update(substitutes)
        grips = importlib.import_module("grabowski_grips")
    finally:
        for key, prior in originals.items():
            if prior is absent:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = prior
else:
    grips = importlib.import_module("grabowski_grips")


def _native_commit(directory: Path, object_format: str) -> str:
    """Return a real native OID; never inherit the invoking repository's Git context."""
    # These tests can run from a Git hook, managed CI or a nested Git worktree.
    # Inherited GIT_DIR/INDEX_FILE/OBJECT_DIRECTORY and GIT_CONFIG_* can direct
    # even git -C commands at the caller's actual index/object database.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update({
        "HOME": str(directory.parent),
        "XDG_CONFIG_HOME": str(directory.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    })
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
         "init", "--quiet", f"--object-format={object_format}", str(directory)],
        check=True, capture_output=True, timeout=15, env=env,
    )
    subprocess.run(
        ["git", "-C", str(directory),
         "-c", "user.name=OID Boundary Fixture",
         "-c", "user.email=oid-boundary@invalid.example",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
         "-c", "core.fsmonitor=false",
         "commit", "--quiet", "--allow-empty", "-m", "native OID fixture"],
        check=True, capture_output=True, timeout=15, env=env,
    )
    return subprocess.run(
        ["git", "-C", str(directory), "-c", "core.fsmonitor=false",
         "rev-parse", "--verify", "HEAD^{commit}"],
        check=True, capture_output=True, text=True, timeout=15, env=env,
    ).stdout.strip()


def _poisoned_git_environment(root: Path) -> dict[str, str]:
    return {
        "GIT_DIR": str(root / "foreign.git"),
        "GIT_WORK_TREE": str(root / "foreign-worktree"),
        "GIT_INDEX_FILE": str(root / "foreign-index"),
        "GIT_OBJECT_DIRECTORY": str(root / "foreign-objects"),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": str(root / "untrusted-hooks"),
        "GIT_CONFIG_GLOBAL": str(root / "untrusted-global-config"),
    }


def _supports_native_sha256(root: Path) -> bool:
    # Probe only inside an isolated, disposable directory. Native SHA-1 and
    # the synthetic SHA-256 provider-width checks must remain runnable even
    # when the installed Git has no experimental SHA-256 repository support.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "HOME": str(root), "XDG_CONFIG_HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        # Git diagnostics are parsed below: translated stderr must not turn
        # unsupported native SHA-256 support into an unexpected test failure.
        "LC_ALL": "C",
    })
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "init", "--quiet",
         "--object-format=sha256", str(root / "sha256-capability")],
        capture_output=True, timeout=15, env=env, check=False,
    )
    if result.returncode == 0:
        return True
    error = result.stderr.decode("utf-8", errors="replace").lower()
    unsupported = (
        "unknown option", "unrecognized option", "unknown hash algorithm",
        "invalid object format", "unsupported object format",
        "unsupported hash algorithm",
    )
    if any(marker in error for marker in unsupported):
        return False
    raise RuntimeError(f"SHA-256 Git capability probe failed unexpectedly: {error[:512]}")


class GitHubOidProviderBoundaryTests(unittest.TestCase):
    def test_grips_import_keeps_canonical_module_registered(self) -> None:
        self.assertIs(sys.modules.get("grabowski_grips"), grips)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="grabowski-gh-oid-boundary-")
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.sha1 = _native_commit(folder / "sha1", "sha1")
        # The boundary tests validate object-ID width, not repository format.
        self.sha256 = "a" * 64
        self.assertEqual(40, len(self.sha1))
        self.assertEqual(64, len(self.sha256))

    def test_sha256_capability_probe_uses_c_locale_for_git_errors(self) -> None:
        root = Path(self.temp.name)
        unsupported = subprocess.CompletedProcess(
            args=["git", "init"], returncode=129, stdout=b"",
            stderr=b"error: unknown option object-format=sha256\\n",
        )
        with patch.dict(os.environ, {"LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8"}):
            with patch("subprocess.run", return_value=unsupported) as runner:
                self.assertFalse(_supports_native_sha256(root))
        self.assertEqual("C", runner.call_args.kwargs["env"]["LC_ALL"])
        self.assertEqual(15, runner.call_args.kwargs["timeout"])

    def test_native_sha1_commit_ignores_inherited_git_environment(self) -> None:
        root = Path(self.temp.name)
        poisoned = _poisoned_git_environment(root)
        with patch.dict(os.environ, poisoned):
            sha1 = _native_commit(root / "env-sha1", "sha1")
        self.assertEqual(40, len(sha1))
        for key in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
            self.assertFalse(Path(poisoned[key]).exists())

    def test_native_sha256_commit_ignores_inherited_git_environment(self) -> None:
        root = Path(self.temp.name)
        if not _supports_native_sha256(root):
            self.skipTest("installed Git does not support native SHA-256 repositories")
        poisoned = _poisoned_git_environment(root)
        with patch.dict(os.environ, poisoned):
            sha256 = _native_commit(root / "env-sha256", "sha256")
        self.assertEqual(64, len(sha256))
        for key in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
            self.assertFalse(Path(poisoned[key]).exists())

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

    def test_github_pr_base_converge_sha1_reaches_provider_preflight(self) -> None:
        # A native SHA-1 pair must not fail at the provider-width boundary.
        # Stop safely at a mocked PR read; never make a real GitHub/Git change.
        gh = Mock(return_value={"returncode": 0, "stdout": "{}", "stderr": ""})
        git = Mock(side_effect=AssertionError("Git must not be mutated"))
        result = grips.run_grip(
            "pr-base-converge",
            {
                "repo": self.temp.name, "pr_number": 1448, "base": "main",
                "expected_head": self.sha1, "expected_base_sha": self.sha1,
            },
            allow_mutation=True, command_runner=git, github_runner=gh,
        )
        self.assertNotIn("40 character", str(result.get("output", {}).get("error", "")))
        gh.assert_called()
        git.assert_not_called()

    def test_captain_pr_merge_sha1_does_not_hit_provider_width_gate(self) -> None:
        action = {"index": 0, "action": "pr-merge",
                  "target": {"repo": "heimgewebe/grabowski", "pr": 1448}}
        # The cryptographic action digest is outside this width-control test.
        # Keep its refusal explicit without requiring a real Captain receipt.
        with patch.object(
            grips, "_captain_evidence_digest_binding_errors",
            return_value=["fixture_self_review_not_authenticated"],
        ) as digest:
            gate = grips._captain_review_evidence_gate(
                {"expected_head": self.sha1, "expected_base_sha": self.sha1,
                 "review_evidence": {}},
                [action],
            )
        self.assertEqual("blocked", gate["status"])
        details = gate.get("details")
        self.assertIsInstance(details, list)
        self.assertIn("fixture_self_review_not_authenticated", details)
        self.assertNotIn("expected_head_missing_or_invalid", details)
        self.assertNotIn("expected_base_sha_missing_or_invalid", details)
        digest.assert_called_once()

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
                details = gate.get("details")
                self.assertIsInstance(details, list)
                expected_problem = (
                    "expected_head_missing_or_invalid"
                    if len(head) != 40 else "expected_base_sha_missing_or_invalid"
                )
                self.assertIn(expected_problem, details)
                if len(head) != 40 and len(base) != 40:
                    # Captain deliberately short-circuits on the invalid head.
                    # Check the independently-invalid base via a valid SHA-1
                    # head so both malformed inputs are explicitly exercised.
                    base_gate = grips._captain_review_evidence_gate(
                        {"expected_head": self.sha1, "expected_base_sha": base,
                         "review_evidence": {}},
                        [action],
                    )
                    self.assertIsInstance(base_gate.get("details"), list)
                    self.assertIn(
                        "expected_base_sha_missing_or_invalid",
                        base_gate["details"],
                    )


if __name__ == "__main__":
    unittest.main()