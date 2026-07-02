from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorator(func):
            self.tools[kwargs.get("name", func.__name__)] = func
            return func
        return decorator

    def run(self, *args, **kwargs):
        return None

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

mcp_pkg = types.ModuleType("mcp")
mcp_server_pkg = types.ModuleType("mcp.server")
mcp_fastmcp_pkg = types.ModuleType("mcp.server.fastmcp")
mcp_fastmcp_pkg.FastMCP = _FakeFastMCP
mcp_types_pkg = types.ModuleType("mcp.types")
mcp_types_pkg.ToolAnnotations = _FakeToolAnnotations
sys.modules.setdefault("mcp", mcp_pkg)
sys.modules.setdefault("mcp.server", mcp_server_pkg)
sys.modules.setdefault("mcp.server.fastmcp", mcp_fastmcp_pkg)
sys.modules.setdefault("mcp.types", mcp_types_pkg)

import grabowski_mcp as mcp


class RlensBundleToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.merges = self.home / "repos" / "merges"
        self.merges.mkdir(parents=True)
        self.state = self.home / ".local" / "state" / "grabowski"
        self.state.mkdir(parents=True)
        self.patches = [
            patch.object(mcp, "HOME", self.home),
            patch.object(mcp, "MERGES_ROOT", self.merges),
            patch.object(mcp, "BUNDLE_REGISTRY", self.state / "rlens-latest-complete-bundles.tsv"),
            patch.object(mcp, "_require_capability", lambda _capability: None),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def _write_bundle(self, stem: str, commit: str = "a" * 40) -> Path:
        manifest = self.merges / f"{stem}_merge.bundle.manifest.json"
        manifest.write_text(json.dumps({
            "kind": "repolens.bundle.manifest",
            "run_id": f"{stem}-run",
            "created_at": "2026-07-01T00:00:00Z",
            "generator": {"runtime": {"git_commit": commit, "git_dirty": False}},
            "artifacts": [
                {"role": "canonical_md"},
                {"role": "output_health"},
            ],
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(json.dumps({
            "status": "pass",
            "evidence_level": "range_strict",
            "range_ref_resolution_status": "ok",
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.output_health.json").write_text(json.dumps({
            "verdict": "pass",
            "run_id": f"{stem}-run",
        }), encoding="utf-8")
        return manifest

    def _git_repo(self, name: str) -> tuple[Path, str]:
        repo = self.home / "repos" / name
        repo.mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Grabowski Test"], cwd=repo, check=True)
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        return repo, head

    def test_discover_reads_latest_bundle_metadata(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.rlens_bundle_discover(repo="demo-repo")

        self.assertEqual(result["kind"], "grabowski.rlens_bundle_discovery")
        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["repo"], "demo-repo")
        self.assertEqual(candidate["post_emit_health"]["status"], "pass")
        self.assertIn("canonical_md", candidate["artifact_roles"])
        self.assertIn("bundle_freshness_against_live_repo", result["does_not_establish"])

    def test_bundle_status_reads_sidecars_without_content_dump(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.rlens_bundle_status("demo-repo-max-260701-1200")

        self.assertTrue(result["exists"])
        self.assertEqual(result["post_emit_health"]["evidence_level"], "range_strict")
        self.assertEqual(result["output_health"]["verdict"], "pass")
        self.assertEqual(result["authority"], "artifact_metadata_only")
        self.assertIn("claims_true", result["does_not_establish"])

    def test_freshness_check_reports_fresh_exact_for_matching_clean_head(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)

        result = mcp.rlens_freshness_check("demo-repo", "demo-repo-max-260701-1200")

        self.assertEqual(result["freshness"], "fresh_exact")
        self.assertEqual(result["bundle"]["git_commit"], head)
        self.assertEqual(result["live_repo"]["head"], head)
        self.assertFalse(result["live_repo"]["dirty"])

    def test_freshness_check_reports_stale_head_for_mismatched_commit(self) -> None:
        _repo, _head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit="b" * 40)

        result = mcp.rlens_freshness_check("demo-repo", "demo-repo-max-260701-1200")

        self.assertEqual(result["freshness"], "stale_head")
        self.assertEqual(result["reason"], "bundle_commit_differs_from_live_head")

    def test_invalid_repo_name_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mcp.rlens_bundle_discover(repo="../demo")

    def test_context_pack_builds_context_ref(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle("demo-repo-max-260701-1200", commit=head)
        manifest_sha = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()
        preflight = {"status": "pass", "answer_compliance_template": {"task_profile": "basic_repo_question"}}

        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight):
            result = mcp.rlens_context_pack("demo-repo", "basic_repo_question")

        self.assertTrue(result["available"])
        self.assertEqual(result["preflight"]["status"], "pass")
        self.assertEqual(result["freshness"]["freshness"], "fresh_exact")
        ref = result["context_ref"]
        self.assertEqual(ref["repo"], "demo-repo")
        self.assertEqual(ref["stem"], "demo-repo-max-260701-1200")
        self.assertEqual(ref["manifest_sha256"], manifest_sha)
        self.assertEqual(ref["bundle_commit"], head)
        self.assertEqual(ref["live_commit_at_claim"], head)
        self.assertEqual(ref["preflight_status"], "pass")
    def test_context_pack_rejects_cross_repo_stem(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("other-repo-max-260701-1200", commit=head)

        result = mcp.rlens_context_pack(
            "demo-repo",
            "basic_repo_question",
            "other-repo-max-260701-1200",
        )

        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "bundle_repo_mismatch")
        self.assertEqual(result["bundle_repo"], "other-repo")


    def test_full_max_stem_maps_to_base_repo(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-full-max-260701-1200", commit=head)

        discovery = mcp.rlens_bundle_discover(repo="demo-repo")

        self.assertEqual(discovery["candidate_count"], 1)
        self.assertEqual(discovery["candidates"][0]["repo"], "demo-repo")

        preflight = {"status": "pass"}
        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight):
            result = mcp.rlens_context_pack(
                "demo-repo",
                "basic_repo_question",
                "demo-repo-full-max-260701-1200",
            )

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["repo"], "demo-repo")

    def test_context_pack_reports_missing_bundle(self) -> None:
        result = mcp.rlens_context_pack("missing-repo", "basic_repo_question")
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "no_bundle_available")


if __name__ == "__main__":
    unittest.main()
