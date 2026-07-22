from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_repoground_catalog as catalog


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

import grabowski_mcp as mcp  # noqa: E402


class CatalogFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.canonical = self.root / "bundles"
        self.legacy = self.root / "merges"
        self.canonical.mkdir()
        self.legacy.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_canonical(
        self,
        *,
        owner: str = "heimgewebe",
        repo: str = "demo",
        ref: str = "main",
        run_dir: str,
        stem: str | None = None,
        created_at: str,
        commit: str = "a" * 40,
        dirty: bool = False,
        output_verdict: str = "pass",
        bundle_status: str = "pass",
        malformed: bool = False,
        provenance_name: str | None = None,
        include_output_run_id: bool = True,
    ) -> tuple[Path, str]:
        repo_id = f"{owner}__{repo}"
        stem = stem or f"{repo_id}__{ref}-max-{run_dir[:8]}-{run_dir[9:13]}"
        directory = self.canonical / repo_id / ref / run_dir
        directory.mkdir(parents=True)
        manifest = directory / f"{stem}{catalog.MANIFEST_SUFFIX}"
        if malformed:
            manifest.write_text("{", encoding="utf-8")
        else:
            manifest.write_text(
                json.dumps(
                    {
                        "kind": "repoground.bundle.manifest",
                        "run_id": f"{stem}-run",
                        "created_at": created_at,
                        "snapshot_provenance": {
                            "repositories": [
                                {
                                    "name": provenance_name or f"{repo_id}__{ref}",
                                    "git_commit": commit,
                                    "git_dirty": dirty,
                                }
                            ]
                        },
                        "artifacts": [
                            {"role": "canonical_md"},
                            {"role": "output_health"},
                            {"role": "sqlite_index"},
                            {"role": "python_symbol_index"},
                            {"role": "python_call_graph"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
        (directory / f"{stem}{catalog.BUNDLE_HEALTH_SUFFIX}").write_text(
            json.dumps({"status": bundle_status}), encoding="utf-8"
        )
        output_health = {"verdict": output_verdict}
        if include_output_run_id:
            output_health["run_id"] = f"{stem}-run"
        (directory / f"{stem}{catalog.OUTPUT_HEALTH_SUFFIX}").write_text(
            json.dumps(output_health),
            encoding="utf-8",
        )
        return manifest, stem

    def write_legacy(
        self,
        *,
        repo: str = "legacy-demo",
        root: Path | None = None,
        stem: str | None = None,
        created_at: str = "2026-07-18T12:00:00Z",
    ) -> tuple[Path, str]:
        target = root or self.legacy
        target.mkdir(parents=True, exist_ok=True)
        stem = stem or f"{repo}-max-260718-1200"
        manifest = target / f"{stem}{catalog.MANIFEST_SUFFIX}"
        manifest.write_text(
            json.dumps(
                {
                    "kind": "repoground.bundle.manifest",
                    "run_id": f"{stem}-run",
                    "created_at": created_at,
                    "snapshot_provenance": {
                        "repositories": [
                            {
                                "name": repo,
                                "git_commit": "a" * 40,
                                "git_dirty": False,
                            }
                        ]
                    },
                    "artifacts": [{"role": "canonical_md"}],
                }
            ),
            encoding="utf-8",
        )
        (target / f"{stem}{catalog.BUNDLE_HEALTH_SUFFIX}").write_text(
            json.dumps({"status": "pass"}), encoding="utf-8"
        )
        (target / f"{stem}{catalog.OUTPUT_HEALTH_SUFFIX}").write_text(
            json.dumps({"verdict": "pass", "run_id": f"{stem}-run"}),
            encoding="utf-8",
        )
        return manifest, stem


class RepoGroundCatalogResolverTests(CatalogFixture):
    def test_manifest_created_at_wins_over_filesystem_mtime(self) -> None:
        older, _older_stem = self.write_canonical(
            run_dir="20260718T120000Z-old",
            created_at="2026-07-18T12:00:00Z",
        )
        newer, newer_stem = self.write_canonical(
            run_dir="20260718T130000Z-new",
            created_at="2026-07-18T13:00:00Z",
        )
        os.utime(older, (2_000_000_000, 2_000_000_000))
        os.utime(newer, (1_000_000_000, 1_000_000_000))

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertTrue(resolved["available"])
        self.assertEqual(newer_stem, resolved["selected"][0]["stem"])

    def test_unhealthy_newer_candidate_falls_back_to_healthy_older(self) -> None:
        older, older_stem = self.write_canonical(
            run_dir="20260718T120000Z-old",
            created_at="2026-07-18T12:00:00Z",
        )
        self.write_canonical(
            run_dir="20260718T130000Z-new",
            created_at="2026-07-18T13:00:00Z",
            output_verdict="warn",
        )

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertEqual(str(older), resolved["selected"][0]["manifest_path"])
        self.assertEqual(older_stem, resolved["selected"][0]["stem"])
        self.assertIn(
            "output_health_not_pass",
            {item["reason"] for item in resolved["rejected"]},
        )

    def test_malformed_newer_candidate_does_not_crash_or_win(self) -> None:
        older, _stem = self.write_canonical(
            run_dir="20260718T120000Z-old",
            created_at="2026-07-18T12:00:00Z",
        )
        self.write_canonical(
            run_dir="20260718T130000Z-new",
            created_at="2026-07-18T13:00:00Z",
            malformed=True,
        )

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertEqual(str(older), resolved["selected"][0]["manifest_path"])
        self.assertIn(
            "manifest_invalid_json",
            {item["reason"] for item in resolved["rejected"]},
        )

    def test_canonical_provenance_must_bind_owner_repo_and_ref(self) -> None:
        self.write_canonical(
            run_dir="20260718T120000Z-weak-provenance",
            created_at="2026-07-18T12:00:00Z",
            provenance_name="demo",
        )

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertFalse(resolved["available"])
        self.assertIn(
            "snapshot_repository_entry_absent",
            {item["reason"] for item in resolved["rejected"]},
        )

    def test_canonical_output_health_requires_matching_run_id(self) -> None:
        self.write_canonical(
            run_dir="20260718T120000Z-no-output-run",
            created_at="2026-07-18T12:00:00Z",
            include_output_run_id=False,
        )

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertFalse(resolved["available"])
        self.assertIn(
            "output_health_run_id_mismatch",
            {item["reason"] for item in resolved["rejected"]},
        )

    def test_simple_repo_alias_fails_closed_across_owners(self) -> None:
        self.write_canonical(
            owner="alice",
            run_dir="20260718T120000Z-a",
            created_at="2026-07-18T12:00:00Z",
        )
        self.write_canonical(
            owner="bob",
            run_dir="20260718T130000Z-b",
            created_at="2026-07-18T13:00:00Z",
        )

        ambiguous = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")
        qualified = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="alice__demo"
        )

        self.assertFalse(ambiguous["available"])
        self.assertEqual("ambiguous_repository_alias", ambiguous["reason"])
        self.assertEqual(["alice__demo", "bob__demo"], ambiguous["repo_ids"])
        self.assertTrue(qualified["available"])
        self.assertEqual("alice__demo", qualified["selected"][0]["repo_id"])

    def test_owner_slash_repo_identity_matches_owner_underscore_identity(self) -> None:
        self.write_canonical(
            owner="alice",
            run_dir="20260718T120000Z-a",
            created_at="2026-07-18T12:00:00Z",
        )

        underscored = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="alice__demo"
        )
        slashed = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="alice/demo"
        )

        self.assertTrue(underscored["available"])
        self.assertTrue(slashed["available"])
        self.assertEqual(
            underscored["selected"][0]["manifest_sha256"],
            slashed["selected"][0]["manifest_sha256"],
        )
        self.assertEqual("alice__demo", slashed["selected"][0]["repo_id"])

    def test_malformed_owner_slash_repo_identity_fails_before_scanning(self) -> None:
        for repo in ("/demo", "alice/", "alice/demo/extra", "alice__demo/extra"):
            with self.subTest(repo=repo), patch.object(
                catalog, "scan_catalog", wraps=catalog.scan_catalog
            ) as scan:
                with self.assertRaisesRegex(ValueError, "owner/repository"):
                    catalog.resolve_catalog(self.canonical, self.legacy, repo=repo)
                self.assertEqual(0, scan.call_count)

    def test_duplicate_canonical_stem_fails_closed(self) -> None:
        duplicate_stem = "heimgewebe__demo__main-max-260718-1200"
        self.write_canonical(
            run_dir="20260718T120000Z-a",
            stem=duplicate_stem,
            created_at="2026-07-18T12:00:00Z",
        )
        self.write_canonical(
            run_dir="20260718T130000Z-b",
            stem=duplicate_stem,
            created_at="2026-07-18T13:00:00Z",
        )

        resolved = catalog.resolve_catalog(
            self.canonical, self.legacy, stem=duplicate_stem
        )

        self.assertFalse(resolved["available"])
        self.assertEqual("ambiguous_stem", resolved["reason"])
        self.assertEqual(2, len(resolved["ambiguous_candidates"]))

    def test_symlinked_manifest_is_rejected_without_following_target(self) -> None:
        manifest, _stem = self.write_canonical(
            run_dir="20260718T120000Z-symlink",
            created_at="2026-07-18T12:00:00Z",
        )
        target = self.root / "external-manifest.json"
        target.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(target)

        scanned = catalog.scan_catalog(self.canonical, self.legacy)

        self.assertFalse(scanned["healthy"])
        self.assertIn(
            "manifest_symlink",
            {item["reason"] for item in scanned["rejected"]},
        )

    def test_hardlinked_manifest_is_rejected(self) -> None:
        manifest, _stem = self.write_canonical(
            run_dir="20260718T120000Z-hardlink",
            created_at="2026-07-18T12:00:00Z",
        )
        target = self.root / "hardlink-target.json"
        target.write_bytes(manifest.read_bytes())
        manifest.unlink()
        os.link(target, manifest)

        resolved = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")

        self.assertFalse(resolved["available"])
        self.assertIn(
            "manifest_hardlinked",
            {item["reason"] for item in resolved["rejected"]},
        )

    def test_overlapping_roots_allow_only_flat_legacy_contract(self) -> None:
        shared = self.root / "shared"
        manifest, _stem = self.write_legacy(root=shared)

        resolved = catalog.resolve_catalog(shared, shared, repo="legacy-demo")

        self.assertTrue(resolved["available"])
        self.assertEqual(str(manifest), resolved["selected"][0]["manifest_path"])
        self.assertEqual("legacy_merges_fallback", resolved["selected"][0]["authority"])

        malformed = (
            shared
            / "invalid-repo-id"
            / "main"
            / "20260718T120000Z-run"
            / f"invalid-main-max-260718-1200{catalog.MANIFEST_SUFFIX}"
        )
        malformed.parent.mkdir(parents=True)
        malformed.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(catalog.CatalogError, "canonical_repo_id_invalid"):
            catalog.catalog_info(malformed, shared, shared)

    def test_refs_filter_selects_requested_branch_before_newest(self) -> None:
        _main, main_stem = self.write_canonical(
            ref="main",
            run_dir="20260718T120000Z-main",
            created_at="2026-07-18T12:00:00Z",
        )
        _feature, feature_stem = self.write_canonical(
            ref="feature",
            run_dir="20260718T130000Z-feature",
            created_at="2026-07-18T13:00:00Z",
        )

        newest = catalog.resolve_catalog(self.canonical, self.legacy, repo="demo")
        main = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="demo", refs=["main"]
        )

        self.assertEqual(feature_stem, newest["selected"][0]["stem"])
        self.assertEqual(main_stem, main["selected"][0]["stem"])
        self.assertEqual("main", main["selected"][0]["ref"])

    def test_legacy_symlink_and_hardlink_manifests_are_rejected(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                root = self.root / kind
                root.mkdir()
                manifest, _stem = self.write_legacy(root=root)
                target = self.root / f"{kind}-target.json"
                target.write_bytes(manifest.read_bytes())
                manifest.unlink()
                if kind == "symlink":
                    manifest.symlink_to(target)
                else:
                    try:
                        os.link(target, manifest)
                    except OSError as exc:
                        self.skipTest(f"hardlinks unavailable: {exc}")

                scanned = catalog.scan_catalog(self.canonical, root)

                self.assertFalse(scanned["healthy"])
                self.assertIn(
                    f"manifest_{'symlink' if kind == 'symlink' else 'hardlinked'}",
                    {item["reason"] for item in scanned["rejected"]},
                )

    def test_rejection_limit_reports_truncation_without_unbounded_records(self) -> None:
        for index in range(catalog.MAX_REJECTIONS + 5):
            self.write_canonical(
                run_dir=f"20260718T120000Z-bad-{index}",
                stem=f"heimgewebe__demo__main-max-260718-{index:04d}",
                created_at="2026-07-18T12:00:00Z",
                malformed=True,
            )

        scanned = catalog.scan_catalog(self.canonical, self.legacy)

        self.assertEqual(catalog.MAX_REJECTIONS, len(scanned["rejected"]))
        self.assertEqual(catalog.MAX_REJECTIONS + 5, scanned["rejected_total_count"])
        self.assertTrue(scanned["rejected_truncated"])

    def test_repo_scoped_rejections_are_not_hidden_by_global_truncation(self) -> None:
        for index in range(catalog.MAX_REJECTIONS + 5):
            self.write_canonical(
                repo="alpha",
                run_dir=f"20260718T120000Z-alpha-{index}",
                stem=f"heimgewebe__alpha__main-max-260718-{index:04d}",
                created_at="2026-07-18T12:00:00Z",
                malformed=True,
            )
        _manifest, target_stem = self.write_canonical(
            repo="target",
            run_dir="20260718T130000Z-target",
            created_at="2026-07-18T13:00:00Z",
            malformed=True,
        )

        resolved = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="target"
        )

        self.assertFalse(resolved["available"])
        self.assertEqual(1, resolved["rejected_total_count"])
        self.assertFalse(resolved["rejected_truncated"])
        self.assertEqual([target_stem], [item["stem"] for item in resolved["rejected"]])

    def test_repo_scoped_scan_does_not_parse_unrelated_manifests(self) -> None:
        self.write_canonical(
            repo="target",
            run_dir="20260718T120000Z-target",
            created_at="2026-07-18T12:00:00Z",
        )
        for index in range(10):
            self.write_canonical(
                repo=f"other-{index}",
                run_dir=f"20260718T120000Z-other-{index}",
                created_at="2026-07-18T12:00:00Z",
            )

        with patch.object(
            catalog, "inspect_candidate", wraps=catalog.inspect_candidate
        ) as inspect:
            resolved = catalog.resolve_catalog(
                self.canonical, self.legacy, repo="target"
            )

        self.assertTrue(resolved["available"])
        self.assertEqual(1, inspect.call_count)

    def test_short_repo_query_does_not_suffix_match_nested_name(self) -> None:
        self.write_canonical(
            repo="foo__bar",
            run_dir="20260718T120000Z-nested",
            created_at="2026-07-18T12:00:00Z",
        )
        self.write_canonical(
            repo="bar",
            run_dir="20260718T130000Z-exact",
            created_at="2026-07-18T13:00:00Z",
        )

        with patch.object(
            catalog, "inspect_candidate", wraps=catalog.inspect_candidate
        ) as inspect:
            resolved = catalog.resolve_catalog(
                self.canonical, self.legacy, repo="bar"
            )

        self.assertTrue(resolved["available"])
        self.assertEqual("bar", resolved["selected"][0]["repo"])
        self.assertEqual("heimgewebe__bar", resolved["selected"][0]["repo_id"])
        self.assertEqual(1, inspect.call_count)

    def test_invalid_ref_names_fail_before_scanning(self) -> None:
        with patch.object(
            catalog, "scan_catalog", wraps=catalog.scan_catalog
        ) as scan:
            with self.assertRaisesRegex(ValueError, "safe ref names"):
                catalog.resolve_catalog(
                    self.canonical, self.legacy, repo="demo", refs=["../main"]
                )
        self.assertEqual(0, scan.call_count)

    def test_legacy_fallback_remains_eligible_with_ref_filter(self) -> None:
        _manifest, stem = self.write_legacy(repo="demo")

        resolved = catalog.resolve_catalog(
            self.canonical, self.legacy, repo="demo", refs=["main"]
        )

        self.assertTrue(resolved["available"])
        self.assertEqual(stem, resolved["selected"][0]["stem"])
        self.assertEqual(
            "legacy_merges_fallback", resolved["selected"][0]["authority"]
        )

    def test_selected_manifest_paths_rejects_malformed_resolution(self) -> None:
        with self.assertRaisesRegex(
            catalog.CatalogError, "resolution_candidate_identity_invalid"
        ):
            catalog.selected_manifest_paths({"selected": [{"ref": "main"}]})

    def test_read_only_resolution_does_not_create_catalog_roots(self) -> None:
        missing_canonical = self.root / "missing-bundles"
        missing_legacy = self.root / "missing-merges"

        resolved = catalog.resolve_catalog(
            missing_canonical, missing_legacy, repo="demo"
        )

        self.assertFalse(resolved["available"])
        self.assertFalse(missing_canonical.exists())
        self.assertFalse(missing_legacy.exists())


class RepoGroundConsumerBindingTests(CatalogFixture):
    def setUp(self) -> None:
        super().setUp()
        self.home = self.root / "home"
        (self.home / "repos").mkdir(parents=True)
        self.state = self.home / ".local" / "state" / "grabowski"
        self.state.mkdir(parents=True)
        self.patches = [
            patch.object(mcp, "HOME", self.home),
            patch.object(mcp, "REPOGROUND_PUBLICATION_ROOT", self.canonical),
            patch.object(mcp, "MERGES_ROOT", self.legacy),
            patch.object(
                mcp,
                "BUNDLE_REGISTRY",
                self.state / "repoground-latest-complete-bundles.tsv",
            ),
            patch.object(mcp, "_require_capability", lambda _capability: None),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        super().tearDown()

    @staticmethod
    def manifest_sha(result: dict[str, object]) -> str | None:
        freshness = result.get("freshness")
        if isinstance(freshness, dict):
            bundle = freshness.get("bundle")
            if isinstance(bundle, dict):
                value = bundle.get("manifest_sha256")
                return value if isinstance(value, str) else None
        return None

    def test_dirty_publication_is_reported_as_dirty_overlay(self) -> None:
        _manifest, stem = self.write_canonical(
            run_dir="20260718T120000Z-dirty",
            created_at="2026-07-18T12:00:00Z",
            dirty=True,
        )

        result = mcp.repoground_freshness_check("demo", stem)

        self.assertEqual("dirty_overlay", result["freshness_status"])
        self.assertEqual("publication_source_dirty", result["reason"])

    def test_agent_surfaces_bind_the_same_manifest_sha(self) -> None:
        manifest, stem = self.write_canonical(
            run_dir="20260718T120000Z-bind",
            created_at="2026-07-18T12:00:00Z",
        )
        expected_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        available = {
            "status": "available",
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
        }
        preflight_payload = {
            "status": "pass",
            "available": True,
            "required_reading": {},
            "answer_compliance_template": {},
        }

        with (
            patch.object(
                mcp, "_repoground_agent_preflight", return_value=preflight_payload
            ),
            patch.object(
                mcp, "_repoground_query_existing_index", return_value=available
            ),
            patch.object(mcp, "_repoground_find_symbol", return_value=available),
            patch.object(mcp, "_repoground_get_callers", return_value=available),
            patch.object(mcp, "_repoground_get_callees", return_value=available),
        ):
            discovery = mcp.repoground_bundle_discover("demo")
            latest = mcp.latest_complete_bundles()
            status = mcp.repoground_bundle_status(stem)
            freshness = mcp.repoground_freshness_check("demo", stem)
            preflight = mcp.repoground_preflight("demo", stem=stem)
            query = mcp.repoground_query("demo", "target", stem=stem)
            context = mcp.repoground_context_pack("demo", stem=stem)
            symbol = mcp.repoground_find_symbol("demo", "target", stem=stem)
            callers = mcp.repoground_get_callers("demo", "target", stem=stem)
            callees = mcp.repoground_get_callees("demo", "target", stem=stem)

        observed = {
            discovery["candidates"][0]["manifest_sha256"],
            latest["selected_manifests"][0]["manifest_sha256"],
            status["manifest_sha256"],
            freshness["bundle"]["manifest_sha256"],
            self.manifest_sha(preflight),
            self.manifest_sha(query),
            context["context_ref"]["manifest_sha256"],
            self.manifest_sha(symbol),
            self.manifest_sha(callers),
            self.manifest_sha(callees),
        }
        self.assertEqual({expected_sha}, observed)


if __name__ == "__main__":
    unittest.main()
