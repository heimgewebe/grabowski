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
        self.assertEqual("fresh", got["freshness_status"])
        self.assertTrue(str(got["agent_reading_pack_path"]).endswith("bundle/agent.md"))
        self.assertEqual("legacy_repobrief_fallback", got["publication_authority"])

    def test_canonical_manifest_precedes_legacy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_path = root / "demo"
            repo_path.mkdir()
            publication_root = root / "pub"
            manifest(root)
            canonical_dir = (
                publication_root
                / "heimgewebe__demo"
                / "main"
                / "20260718T120000Z-test"
            )
            canonical_dir.mkdir(parents=True)
            stem = "heimgewebe__demo__main-max-260718-1200"
            (canonical_dir / f"{stem}_merge.agent_reading_pack.md").write_text(
                "canonical", encoding="utf-8"
            )
            (canonical_dir / f"{stem}_merge.md").write_text(
                "canonical", encoding="utf-8"
            )
            canonical_manifest = canonical_dir / f"{stem}_merge.bundle.manifest.json"
            canonical_manifest.write_text(
                json.dumps(
                    {
                        "created_at": "2026-07-18T12:00:00Z",
                        "snapshot_provenance": {
                            "repositories": [{"git_commit": "a" * 40}]
                        },
                        "artifacts": [
                            {
                                "role": "agent_reading_pack",
                                "path": f"{stem}_merge.agent_reading_pack.md",
                            },
                            {
                                "role": "canonical_md",
                                "path": f"{stem}_merge.md",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            got = rb.context(
                repo_path,
                runner,
                {"root": str(repo_path), "branch": "main", "head": "a" * 40},
                {"repobrief_publication_root": str(publication_root)},
            )

        self.assertTrue(got["available"])
        self.assertEqual("canonical_publication", got["publication_authority"])
        self.assertEqual(str(canonical_manifest), got["manifest_path"])
        self.assertEqual("fresh", got["freshness_status"])
        self.assertTrue(
            str(got["agent_reading_pack_path"]).endswith(
                f"{stem}_merge.agent_reading_pack.md"
            )
        )

    def test_missing_manifest_reports_publication_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_path = root / "demo"
            repo_path.mkdir()
            publication_root = root / "pub"
            publication_root.mkdir()
            got = rb.context(
                repo_path,
                runner,
                {"root": str(repo_path), "branch": "main", "head": "a" * 40},
                {"repobrief_publication_root": str(publication_root)},
            )
        self.assertFalse(got["available"])
        self.assertEqual("publication_unavailable", got["freshness_status"])

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
