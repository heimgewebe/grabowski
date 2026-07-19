from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
rb = __import__("grabowski_repobrief")


def runner(repo: Path, argv: list[str]) -> dict[str, object]:
    return {"returncode": 1, "stdout": "", "stderr": "missing"}


def manifest(
    root: Path,
    *,
    bundle_path: str = "bundle/bundle.json",
    artifact_path: str = "agent.md",
) -> None:
    base = root / "pub" / "external" / "repobrief" / "demo" / "main"
    base.mkdir(parents=True)
    bundle = base / "bundle"
    bundle.mkdir()
    (bundle / "bundle.json").write_text("{}")
    (bundle / "agent.md").write_text("agent")
    data = {
        "generatedAt": "2026-07-07T08:00:00Z",
        "bundleManifest": {"path": bundle_path},
        "snapshotProvenance": {"repositories": [{"git_commit": "a" * 40}]},
        "artifacts": [{"role": "agent_reading_pack", "path": artifact_path}],
    }
    (base / "manifest.json").write_text(json.dumps(data))


def canonical_manifest(
    publication_root: Path,
    *,
    ref: str,
    run_dir: str,
    created_at: str,
) -> Path:
    repo_id = "heimgewebe__demo"
    stem = f"{repo_id}__{ref}-max-{run_dir[:8]}-{run_dir[9:13]}"
    base = publication_root / repo_id / ref / run_dir
    base.mkdir(parents=True)
    (base / f"{stem}_merge.agent_reading_pack.md").write_text(ref, encoding="utf-8")
    (base / f"{stem}_merge.md").write_text(ref, encoding="utf-8")
    path = base / f"{stem}_merge.bundle.manifest.json"
    path.write_text(
        json.dumps(
            {
                "kind": "repoground.bundle.manifest",
                "run_id": f"{stem}-run",
                "created_at": created_at,
                "snapshot_provenance": {
                    "repositories": [
                        {
                            "name": f"{repo_id}__{ref}",
                            "git_commit": "a" * 40,
                            "git_dirty": False,
                        }
                    ]
                },
                "artifacts": [
                    {
                        "role": "agent_reading_pack",
                        "path": f"{stem}_merge.agent_reading_pack.md",
                    },
                    {"role": "canonical_md", "path": f"{stem}_merge.md"},
                    {"role": "output_health"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (base / f"{stem}_merge.bundle_health.post.json").write_text(
        json.dumps({"status": "pass"}), encoding="utf-8"
    )
    (base / f"{stem}_merge.output_health.json").write_text(
        json.dumps({"verdict": "pass", "run_id": f"{stem}-run"}),
        encoding="utf-8",
    )
    return path


class RBLookupTests(unittest.TestCase):
    def test_safe_segment_rejects_pathlike_values(self) -> None:
        self.assertEqual("grabowski", rb.safe_segment("grabowski"))
        for value in ["", ".", "..", ".hidden", "repo/", "repo\\evil", "repo."]:
            self.assertIsNone(rb.safe_segment(value))

    def test_missing_publication_root(self) -> None:
        got = rb.context(
            Path("/tmp/demo"),
            runner,
            {"root": "/tmp/demo", "branch": "main", "head": "a" * 40},
            {"repobrief_publication_root": "/tmp/no-such-grabowski-rb-root"},
        )
        self.assertFalse(got["available"])
        self.assertEqual("missing_publication_root", got["status"])

    def test_finds_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "demo"
            repo.mkdir()
            manifest(root)
            got = rb.context(
                repo,
                runner,
                {"root": str(repo), "branch": "main", "head": "a" * 40},
                {"repobrief_publication_root": str(root / "pub")},
            )
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
                publication_root / "heimgewebe__demo" / "main" / "20260718T120000Z-test"
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
                        "kind": "repoground.bundle.manifest",
                        "run_id": f"{stem}-run",
                        "created_at": "2026-07-18T12:00:00Z",
                        "snapshot_provenance": {
                            "repositories": [
                                {
                                    "name": "heimgewebe__demo__main",
                                    "git_commit": "a" * 40,
                                    "git_dirty": False,
                                }
                            ]
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
                            {"role": "output_health"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (canonical_dir / f"{stem}_merge.bundle_health.post.json").write_text(
                json.dumps({"status": "pass"}), encoding="utf-8"
            )
            (canonical_dir / f"{stem}_merge.output_health.json").write_text(
                json.dumps({"verdict": "pass", "run_id": f"{stem}-run"}),
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

    def test_requested_ref_is_selected_before_newer_unrequested_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_path = root / "demo"
            repo_path.mkdir()
            publication_root = root / "pub"
            main = canonical_manifest(
                publication_root,
                ref="main",
                run_dir="20260718T120000Z-main",
                created_at="2026-07-18T12:00:00Z",
            )
            canonical_manifest(
                publication_root,
                ref="feature",
                run_dir="20260718T130000Z-feature",
                created_at="2026-07-18T13:00:00Z",
            )
            with patch.object(
                rb.repoground_catalog,
                "scan_catalog",
                wraps=rb.repoground_catalog.scan_catalog,
            ) as scan:
                got = rb.context(
                    repo_path,
                    runner,
                    {"root": str(repo_path), "branch": "main", "head": "a" * 40},
                    {"repobrief_publication_root": str(publication_root)},
                )

        self.assertTrue(got["available"])
        self.assertEqual(str(main), got["manifest_path"])
        self.assertEqual("main", got["ref"])
        self.assertEqual(1, scan.call_count)

    def test_legacy_manifest_reader_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            for kind in ("symlink", "hardlink"):
                with self.subTest(kind=kind):
                    candidate = root / f"{kind}.json"
                    if kind == "symlink":
                        candidate.symlink_to(target)
                    else:
                        os.link(target, candidate)
                    parsed, error = rb.read_manifest(candidate)
                    self.assertIsNone(parsed)
                    self.assertEqual("manifest_read_error", error["status"])
                    self.assertEqual(
                        "symlink" if kind == "symlink" else "hardlinked",
                        error["reason"],
                    )

    def test_default_bundles_root_still_finds_legacy_repobrief_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_path = root / "demo"
            repo_path.mkdir()
            publication_root = root / "pub"
            (publication_root / "bundles").mkdir(parents=True)
            manifest(root)
            with patch.object(
                rb, "DEFAULT_PUBLICATION_ROOT", publication_root / "bundles"
            ):
                got = rb.context(
                    repo_path,
                    runner,
                    {"root": str(repo_path), "branch": "main", "head": "a" * 40},
                    {},
                )
        self.assertTrue(got["available"])
        self.assertEqual("legacy_repobrief_fallback", got["publication_authority"])
        self.assertIn(
            "/external/repobrief/demo/main/manifest.json", got["manifest_path"]
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
            root = Path(tmp)
            repo = root / "demo"
            repo.mkdir()
            base = root / "pub" / "external" / "repobrief" / "demo" / "main"
            base.mkdir(parents=True)
            (base / "manifest.json").write_text("{")
            got = rb.context(
                repo,
                runner,
                {"root": str(repo), "branch": "main", "head": "a" * 40},
                {"repobrief_publication_root": str(root / "pub")},
            )
        self.assertFalse(got["available"])
        self.assertEqual("invalid_manifest", got["status"])

    def test_manifest_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "demo"
            repo.mkdir()
            manifest(root, bundle_path="../evil.json")
            got = rb.context(
                repo,
                runner,
                {"root": str(repo), "branch": "main", "head": "a" * 40},
                {"repobrief_publication_root": str(root / "pub")},
            )
        self.assertFalse(got["available"])
        self.assertEqual("invalid_manifest_path", got["status"])

    def test_pyproject_packages_module(self) -> None:
        self.assertIn("grabowski_repobrief", Path("pyproject.toml").read_text())


if __name__ == "__main__":
    unittest.main()
