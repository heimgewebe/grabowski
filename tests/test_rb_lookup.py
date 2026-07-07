from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
rb = __import__("grabowski_repobrief")

def runner(repo: Path, argv: list[str]) -> dict[str, object]:
    return {"returncode": 1, "stdout": "", "stderr": "missing"}

def manifest(root: Path, *, bundle_path: str = "bundle/bundle.json", artifact_path: str = "agent.md") -> None:
    base = root / "pub" / "external" / "repobrief" / "demo" / "main"
    base.mkdir(parents=True)
    bundle = base / "bundle"
    bundle.mkdir()
    (bundle / "bundle.json").write_text("{}")
    (bundle / "agent.md").write_text("agent")
    data = {"generatedAt": "2026-07-07T08:00:00Z", "bundleManifest": {"path": bundle_path}, "snapshotProvenance": {"repositories": [{"git_commit": "a" * 40}]}, "artifacts": [{"role": "agent_reading_pack", "path": artifact_path}]}
    (base / "manifest.json").write_text(json.dumps(data))

class RBLookupTests(unittest.TestCase):
    def test_safe_segment_rejects_pathlike_values(self) -> None:
        self.assertEqual("grabowski", rb.safe_segment("grabowski"))
        for value in ["", ".", "..", ".hidden", "repo/", "repo\\evil", "repo."]:
            self.assertIsNone(rb.safe_segment(value))

    def test_missing_publication_root(self) -> None:
        got = rb.context(Path("/tmp/demo"), runner, {"root": "/tmp/demo", "branch": "main", "head": "a" * 40}, {"repobrief_publication_root": "/tmp/no-such-grabowski-rb-root"})
        self.assertFalse(got["available"])
        self.assertEqual("missing_publication_root", got["status"])

    def test_finds_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo = root / "demo"; repo.mkdir(); manifest(root)
            got = rb.context(repo, runner, {"root": str(repo), "branch": "main", "head": "a" * 40}, {"repobrief_publication_root": str(root / "pub")})
        self.assertTrue(got["available"])
        self.assertEqual("exact", got["freshness_status"])
        self.assertTrue(str(got["agent_reading_pack_path"]).endswith("agent.md"))

    def test_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo = root / "demo"; repo.mkdir()
            base = root / "pub" / "external" / "repobrief" / "demo" / "main"
            base.mkdir(parents=True); (base / "manifest.json").write_text("{")
            got = rb.context(repo, runner, {"root": str(repo), "branch": "main", "head": "a" * 40}, {"repobrief_publication_root": str(root / "pub")})
        self.assertFalse(got["available"])
        self.assertEqual("invalid_manifest", got["status"])

    def test_manifest_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo = root / "demo"; repo.mkdir(); manifest(root, bundle_path="../evil.json")
            got = rb.context(repo, runner, {"root": str(repo), "branch": "main", "head": "a" * 40}, {"repobrief_publication_root": str(root / "pub")})
        self.assertFalse(got["available"])
        self.assertEqual("invalid_manifest_path", got["status"])

    def test_pyproject_packages_module(self) -> None:
        self.assertIn("grabowski_repobrief", Path("pyproject.toml").read_text())

if __name__ == "__main__":
    unittest.main()
