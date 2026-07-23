from __future__ import annotations

import json
import re
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


class RepoGroundBundleToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.merges = self.home / "repos" / "merges"
        self.merges.mkdir(parents=True)
        self.publications = (
            self.home / "repos" / "manifest-publications" / "bundles"
        )
        self.state = self.home / ".local" / "state" / "grabowski"
        self.state.mkdir(parents=True)
        self.patches = [
            patch.object(mcp, "HOME", self.home),
            patch.object(mcp, "MERGES_ROOT", self.merges),
            patch.object(mcp, "REPOGROUND_PUBLICATION_ROOT", self.publications),
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
        self.tmp.cleanup()

    def _write_bundle(
        self,
        stem: str,
        commit: str = "a" * 40,
        *,
        include_snapshot_provenance: bool = True,
        generator_commit: str | None = None,
    ) -> Path:
        manifest = self.merges / f"{stem}_merge.bundle.manifest.json"
        repo = stem.rsplit("-max-", 1)[0]
        doc = {
            "kind": "repolens.bundle.manifest",
            "run_id": f"{stem}-run",
            "created_at": "2026-07-01T00:00:00Z",
            "generator": {
                "runtime": {
                    "git_commit": generator_commit or "f" * 40,
                    "git_dirty": False,
                }
            },
            "artifacts": [
                {"role": "canonical_md"},
                {"role": "output_health"},
            ],
        }
        if include_snapshot_provenance:
            doc["snapshotProvenance"] = {
                "repositories": [
                    {"repo": repo, "git_commit": commit, "git_dirty": False}
                ]
            }
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "evidence_level": "range_strict",
                    "range_ref_resolution_status": "ok",
                }
            ),
            encoding="utf-8",
        )
        (self.merges / f"{stem}_merge.output_health.json").write_text(
            json.dumps(
                {
                    "verdict": "pass",
                    "run_id": f"{stem}-run",
                    "created_at": "2026-07-01T00:00:00Z",
                    "warnings": [],
                    "dependencies": {
                        "jsonschema": {
                            "available": True,
                            "effect": "full_validation_available",
                        }
                    },
                    "checks": {
                        "range_ref_resolution_status": "ok",
                        "range_ref_resolution": {
                            "status": "ok",
                            "validation": {"mode": "jsonschema", "reason": "available"},
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def _write_canonical_bundle(
        self,
        repo: str,
        commit: str = "a" * 40,
        *,
        include_snapshot_provenance: bool = True,
        run_id: str = "20260718T120000Z-test",
    ) -> Path:
        stem = f"heimgewebe__{repo}__main-max-260718-1200"
        directory = self.publications / f"heimgewebe__{repo}" / "main" / run_id
        directory.mkdir(parents=True, exist_ok=True)
        manifest = directory / f"{stem}_merge.bundle.manifest.json"
        doc = {
            "kind": "repoground.bundle.manifest",
            "run_id": f"{stem}-run",
            "created_at": "2026-07-18T12:00:00Z",
            "generator": {
                "runtime": {"git_commit": "f" * 40, "git_dirty": False}
            },
            "artifacts": [
                {"role": "canonical_md"},
                {"role": "output_health"},
                {"role": "python_symbol_index_json"},
                {"role": "python_call_graph_json"},
            ],
        }
        if include_snapshot_provenance:
            doc["snapshot_provenance"] = {
                "repositories": [
                    {
                        "name": f"heimgewebe__{repo}__main",
                        "git_commit": commit,
                        "git_dirty": False,
                    }
                ]
            }
        manifest.write_text(json.dumps(doc), encoding="utf-8")
        (directory / f"{stem}_merge.bundle_health.post.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "evidence_level": "range_strict",
                    "range_ref_resolution_status": "ok",
                }
            ),
            encoding="utf-8",
        )
        (directory / f"{stem}_merge.output_health.json").write_text(
            json.dumps(
                {
                    "verdict": "pass",
                    "run_id": f"{stem}-run",
                    "checks": {"range_ref_resolution_status": "ok"},
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def _git_repo(self, name: str) -> tuple[Path, str]:
        repo = self.home / "repos" / name
        repo.mkdir(parents=True)
        subprocess.run(
            ["git", "init"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Grabowski Test"], cwd=repo, check=True
        )
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        return repo, head

    def test_full_max_stem_maps_to_base_repository(self) -> None:
        stem = "demo-repo-full-max-260701-1200"
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle(stem, commit=head)
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["snapshotProvenance"]["repositories"][0]["repo"] = "demo-repo"
        manifest.write_text(json.dumps(document), encoding="utf-8")

        discovery = mcp.repoground_bundle_discover(repo="demo-repo")

        self.assertEqual(discovery["candidate_count"], 1)
        self.assertEqual(discovery["candidates"][0]["repo"], "demo-repo")

        with patch.object(
            mcp,
            "_repoground_agent_preflight",
            return_value={"status": "pass"},
        ):
            result = mcp.repoground_context_pack(
                "demo-repo",
                "basic_repo_question",
                stem,
            )

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["repo"], "demo-repo")

    def test_discover_reads_latest_bundle_metadata(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.repoground_bundle_discover(repo="demo-repo")

        self.assertEqual(result["kind"], "grabowski.repoground_bundle_discovery")
        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["repo"], "demo-repo")
        self.assertEqual(candidate["post_emit_health"]["status"], "pass")
        self.assertEqual(candidate["git_commit"], "a" * 40)
        self.assertEqual(candidate["source_provenance"]["git_commit"], "a" * 40)
        self.assertEqual(candidate["generator_runtime"]["git_commit"], "f" * 40)
        self.assertEqual(
            candidate["output_health"]["range_ref_resolution_status"], "ok"
        )
        self.assertTrue(
            candidate["output_health"]["dependencies"]["jsonschema"]["available"]
        )
        self.assertIn("canonical_md", candidate["artifact_roles"])
        self.assertIn(
            "bundle_freshness_against_live_repo", result["does_not_establish"]
        )

    def test_canonical_publications_for_repoground_and_weltgewebe_are_discovered(self) -> None:
        for repo in ("repoground", "weltgewebe"):
            manifest = self._write_canonical_bundle(repo)
            with self.subTest(repo=repo):
                result = mcp.repoground_bundle_discover(repo=repo)
                self.assertEqual(result["candidate_count"], 1)
                candidate = result["candidates"][0]
                self.assertEqual(candidate["repo"], repo)
                self.assertEqual(
                    candidate["publication_authority"], "canonical_publication"
                )
                self.assertEqual(candidate["manifest_path"], str(manifest))
                self.assertEqual(
                    result["catalog"]["authority"], "canonical_publication_catalog"
                )

    def test_owner_slash_repo_identity_matches_canonical_aliases(self) -> None:
        manifest = self._write_canonical_bundle("demo")

        short = mcp.repoground_bundle_discover(repo="demo")
        underscored = mcp.repoground_bundle_discover(repo="heimgewebe__demo")
        slashed = mcp.repoground_bundle_discover(repo="heimgewebe/demo")

        for result in (short, underscored, slashed):
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(result["candidates"][0]["manifest_path"], str(manifest))
            self.assertEqual(result["candidates"][0]["repo_id"], "heimgewebe__demo")

        stem = slashed["candidates"][0]["stem"]
        with patch.object(
            mcp,
            "_repoground_agent_preflight",
            return_value={"available": True, "status": "pass"},
        ):
            preflight = mcp.repoground_preflight("heimgewebe/demo", stem=stem)
        self.assertTrue(preflight["available"])
        self.assertEqual(preflight["stem"], stem)

    def test_canonical_publication_precedes_legacy_for_all_consumers(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        legacy = self._write_bundle(
            "demo-repo-max-260718-1300", commit="b" * 40
        )
        canonical = self._write_canonical_bundle("demo-repo", commit=head)
        legacy.touch()

        discovery = mcp.repoground_bundle_discover(repo="demo-repo")
        self.assertEqual(discovery["candidate_count"], 1)
        self.assertEqual(discovery["candidates"][0]["manifest_path"], str(canonical))

        query_payload = {"status": "available", "query_result": {"results": []}}
        with patch.object(
            mcp, "_repoground_query_existing_index", return_value=query_payload
        ) as query_helper:
            result = mcp.repoground_query_existing_index("demo-repo", "target")
        self.assertTrue(result["available"])
        self.assertEqual(query_helper.call_args.args[0], canonical)

        symbol_payload = {"status": "available", "result": {"hits": []}}
        with patch.object(
            mcp, "_repoground_find_symbol", return_value=symbol_payload
        ) as symbol_helper:
            symbol = mcp.repoground_find_symbol("demo-repo", "target")
        self.assertTrue(symbol["available"])
        self.assertEqual(symbol_helper.call_args.args[0], canonical)

    def test_canonical_catalog_overrides_valid_legacy_registry_cache(self) -> None:
        self._write_bundle("demo-repo-max-260718-1300")
        canonical = self._write_canonical_bundle("demo-repo")
        self.state.joinpath("repoground-latest-complete-bundles.tsv").write_text(
            "repo\tstem\tlatest_mtime\thas_agent_reading_pack\tcanonical_md\tbundle_manifest\toutput_health\tagent_reading_pack\n"
            "demo-repo\tdemo-repo-max-260718-1300\t2026-07-18T13:00:00Z\tno\t./merges/demo-repo-max-260718-1300_merge.md\t./merges/demo-repo-max-260718-1300_merge.bundle.manifest.json\t./merges/demo-repo-max-260718-1300_merge.output_health.json\t./merges/demo-repo-max-260718-1300_merge.agent_reading_pack.md\n",
            encoding="utf-8",
        )

        result = mcp.latest_complete_bundles()

        self.assertEqual(result["authority"], "canonical_live_discovery")
        self.assertEqual(result["canonical_publication_row_count"], 1)
        self.assertEqual(result["rows"][0][0], "demo-repo")
        self.assertTrue(
            result["rows"][0][5].endswith(
                canonical.relative_to(self.home / "repos").as_posix()
            )
        )
        self.assertNotIn("demo-repo-max-260718-1300", result["rows"][0][1])

    def test_bundle_status_reads_sidecars_without_content_dump(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.repoground_bundle_status("demo-repo-max-260701-1200")

        self.assertTrue(result["exists"])
        self.assertEqual(result["post_emit_health"]["evidence_level"], "range_strict")
        self.assertEqual(result["output_health"]["verdict"], "pass")
        self.assertEqual(result["output_health"]["range_ref_resolution_status"], "ok")
        self.assertEqual(
            result["output_health"]["range_ref_resolution"]["validation"]["mode"],
            "jsonschema",
        )
        self.assertEqual(
            result["output_health"]["dependencies"]["jsonschema"]["effect"],
            "full_validation_available",
        )
        self.assertEqual(result["authority"], "artifact_metadata_only")
        self.assertIn("claims_true", result["does_not_establish"])

    def test_latest_complete_bundles_merges_valid_registry_rows_with_discovery_when_cache_is_stale(
        self,
    ) -> None:
        self._write_bundle("valid-repo-max-260701-1200")
        self._write_bundle("live-repo-max-260701-1200")
        (self.state / "repoground-latest-complete-bundles.tsv").write_text(
            "repo\tstem\tlatest_mtime\thas_agent_reading_pack\tcanonical_md\tbundle_manifest\toutput_health\tagent_reading_pack\n"
            "valid-repo\tvalid-repo-max-260701-1200\t2026-07-01T00:00:00Z\tno\t./merges/valid-repo-max-260701-1200_merge.md\t./merges/valid-repo-max-260701-1200_merge.bundle.manifest.json\t./merges/valid-repo-max-260701-1200_merge.output_health.json\t./merges/valid-repo-max-260701-1200_merge.agent_reading_pack.md\n"
            "stale-repo\tstale-repo-max-260101-0000\t2026-01-01T00:00:00Z\tno\t./merges/stale.md\t./merges/stale.json\t./merges/stale-health.json\t./merges/stale-pack.md\n",
            encoding="utf-8",
        )

        result = mcp.latest_complete_bundles()

        self.assertEqual(result["authority"], "merged_registry_live_discovery")
        self.assertEqual(result["stale_registry_row_count"], 1)
        self.assertEqual(result["live_discovery_row_count"], 2)
        self.assertEqual(
            [row[0] for row in result["rows"]], ["valid-repo", "live-repo"]
        )
        self.assertNotIn("stale-repo", [row[0] for row in result["rows"]])
        self.assertIn(
            "bundle_freshness_against_live_repo", result["does_not_establish"]
        )

    def test_latest_complete_bundles_uses_valid_cache_without_live_discovery(
        self,
    ) -> None:
        self._write_bundle("valid-repo-max-260701-1200")
        (self.state / "repoground-latest-complete-bundles.tsv").write_text(
            "repo\tstem\tlatest_mtime\thas_agent_reading_pack\tcanonical_md\tbundle_manifest\toutput_health\tagent_reading_pack\n"
            "valid-repo\tvalid-repo-max-260701-1200\t2026-07-01T00:00:00Z\tno\t./merges/valid-repo-max-260701-1200_merge.md\t./merges/valid-repo-max-260701-1200_merge.bundle.manifest.json\t./merges/valid-repo-max-260701-1200_merge.output_health.json\t./merges/valid-repo-max-260701-1200_merge.agent_reading_pack.md\n",
            encoding="utf-8",
        )

        with patch.object(
            mcp,
            "_repoground_latest_manifest_by_repo",
            side_effect=AssertionError("unexpected discovery"),
        ):
            result = mcp.latest_complete_bundles()

        self.assertEqual(result["authority"], "registry_cache")
        self.assertEqual(result["stale_registry_row_count"], 0)
        self.assertEqual(result["live_discovery_row_count"], 0)
        self.assertEqual(result["rows"][1][0], "valid-repo")

    def test_registry_header_status_requires_full_header_shape(self) -> None:
        self.assertTrue(
            mcp._repoground_registry_row_status(list(mcp.BUNDLE_REGISTRY_HEADER))[
                "is_header"
            ]
        )
        malformed = ["repo", "wrong", *list(mcp.BUNDLE_REGISTRY_HEADER[2:])]
        status = mcp._repoground_registry_row_status(malformed)
        self.assertFalse(status["is_header"])
        self.assertFalse(status["valid"])
        extended_header = [*list(mcp.BUNDLE_REGISTRY_HEADER), "extra"]
        status = mcp._repoground_registry_row_status(extended_header)
        self.assertFalse(status["is_header"])
        self.assertFalse(status["valid"])

    def test_bundle_status_surfaces_output_health_dependency_degradation(self) -> None:
        stem = "demo-repo-max-260701-1200"
        self._write_bundle(stem)
        degraded = {
            "verdict": "warn",
            "run_id": f"{stem}-run",
            "warnings": ["range_ref schema validation skipped"],
            "dependencies": {
                "jsonschema": {
                    "available": False,
                    "required_for": ["range_ref_schema"],
                    "effect": "validation_degraded",
                }
            },
            "checks": {
                "range_ref_resolution_status": "environment_error",
                "range_ref_resolution": {
                    "status": "environment_error",
                    "reason": "range_ref schema validation skipped",
                    "validation": {
                        "mode": "skipped_unavailable",
                        "engine": "range_resolver",
                        "reason": "dependency_unavailable",
                    },
                },
            },
        }
        (self.merges / f"{stem}_merge.output_health.json").write_text(
            json.dumps(degraded), encoding="utf-8"
        )

        result = mcp.repoground_bundle_status(stem)

        self.assertEqual(result["output_health"]["verdict"], "warn")
        self.assertEqual(
            result["output_health"]["range_ref_resolution_status"], "environment_error"
        )
        self.assertFalse(
            result["output_health"]["dependencies"]["jsonschema"]["available"]
        )
        self.assertEqual(
            result["output_health"]["dependencies"]["jsonschema"]["effect"],
            "validation_degraded",
        )
        self.assertEqual(
            result["output_health"]["range_ref_resolution"]["validation"]["reason"],
            "dependency_unavailable",
        )

    def test_freshness_check_reports_fresh_exact_for_matching_clean_head(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)

        result = mcp.repoground_freshness_check(
            "demo-repo", "demo-repo-max-260701-1200"
        )

        self.assertEqual(result["freshness"], "fresh_exact")
        self.assertEqual(result["freshness_status"], "fresh")
        self.assertEqual(result["bundle"]["git_commit"], head)
        self.assertEqual(result["live_repo"]["head"], head)
        self.assertFalse(result["live_repo"]["dirty"])

    def test_canonical_freshness_prefers_clean_publication_source_checkout(self) -> None:
        conventional, _head = self._git_repo("demo-repo")
        conventional.joinpath("dirty.txt").write_text("foreign", encoding="utf-8")
        source = (
            self.home
            / "repos"
            / ".repoground-sources"
            / "heimgewebe__demo-repo__main"
        )
        source.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=source,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"], cwd=source, check=True
        )
        source.joinpath("README.md").write_text("source", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=source, check=True)
        subprocess.run(["git", "commit", "-qm", "source"], cwd=source, check=True)
        source_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/main", source_head],
            cwd=source,
            check=True,
        )
        self._write_canonical_bundle("demo-repo", commit=source_head)

        result = mcp.repoground_freshness_check("demo-repo")

        self.assertEqual(result["freshness_status"], "fresh")
        self.assertEqual(
            result["live_repo"]["source_kind"], "publication_source_checkout"
        )
        self.assertEqual(result["live_repo"]["comparison_ref"], "origin/main")
        self.assertEqual(result["live_repo"]["head"], source_head)
        self.assertTrue(conventional.joinpath("dirty.txt").exists())

    def test_freshness_check_reports_stale_head_for_mismatched_commit(self) -> None:
        _repo, _head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit="b" * 40)

        result = mcp.repoground_freshness_check(
            "demo-repo", "demo-repo-max-260701-1200"
        )

        self.assertEqual(result["freshness"], "stale_head")
        self.assertEqual(result["freshness_status"], "stale")
        self.assertEqual(result["reason"], "bundle_commit_differs_from_live_head")

    def test_freshness_check_does_not_compare_generator_commit_to_live_head(
        self,
    ) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle(
            "demo-repo-max-260701-1200",
            commit=head,
            include_snapshot_provenance=False,
            generator_commit="b" * 40,
        )

        result = mcp.repoground_freshness_check(
            "demo-repo", "demo-repo-max-260701-1200"
        )

        self.assertEqual(result["freshness"], "unknown")
        self.assertEqual(result["freshness_status"], "provenance_missing")
        self.assertEqual(result["reason"], "bundle_source_commit_unavailable")
        self.assertIsNone(result["bundle"]["git_commit"])
        self.assertEqual(
            result["bundle"]["source_provenance"]["reason"],
            "snapshot_provenance_absent",
        )
        self.assertEqual(result["bundle"]["generator_runtime"]["git_commit"], "b" * 40)

    def test_freshness_statuses_fail_closed_when_source_or_publication_is_missing(self) -> None:
        self._write_bundle("source-missing-max-260701-1200")

        source_missing = mcp.repoground_freshness_check("source-missing")
        publication_missing = mcp.repoground_freshness_check("publication-missing")

        self.assertEqual(source_missing["freshness_status"], "source_unavailable")
        self.assertEqual(source_missing["reason"], "repo_missing_or_invalid")
        self.assertEqual(
            publication_missing["freshness_status"], "publication_unavailable"
        )
        self.assertEqual(publication_missing["reason"], "no_bundle_found")

    def test_invalid_repo_name_is_rejected(self) -> None:
        for repo in ("../demo", "/demo", "heimgewebe/", "heimgewebe/demo/extra"):
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                mcp.repoground_bundle_discover(repo=repo)

    def test_context_pack_builds_context_ref(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle("demo-repo-max-260701-1200", commit=head)
        manifest_sha = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()
        preflight = {
            "status": "pass",
            "answer_compliance_template": {"task_profile": "basic_repo_question"},
        }

        with patch.object(mcp, "_repoground_agent_preflight", return_value=preflight):
            result = mcp.repoground_context_pack("demo-repo", "basic_repo_question")

        self.assertTrue(result["available"])
        self.assertEqual(result["preflight"]["status"], "pass")
        self.assertEqual(result["freshness"]["freshness"], "fresh_exact")
        ref = result["context_ref"]
        self.assertEqual(ref["repo"], "demo-repo")
        self.assertEqual(ref["stem"], "demo-repo-max-260701-1200")
        self.assertEqual(ref["manifest_sha256"], manifest_sha)
        self.assertEqual(ref["bundle_commit"], head)
        self.assertEqual(ref["live_commit_at_claim"], head)
        self.assertEqual(ref["freshness_status"], "fresh")
        self.assertEqual(ref["preflight_status"], "pass")

    def test_context_pack_declares_timestamp_volatility_and_stable_content_hash(self) -> None:
        dt = __import__("datetime")
        first_time = dt.datetime(2026, 7, 23, 10, 0, 0, tzinfo=dt.timezone.utc)
        second_time = dt.datetime(2026, 7, 23, 10, 5, 0, tzinfo=dt.timezone.utc)
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        preflight = {"status": "pass", "answer_compliance_template": {}}
        with patch.object(mcp, "_repoground_agent_preflight", return_value=preflight):
            with patch.object(mcp, "datetime") as mocked_datetime:
                mocked_datetime.now.return_value = first_time
                first = mcp.repoground_context_pack("demo-repo", "basic_repo_question")
                mocked_datetime.now.return_value = second_time
                second = mcp.repoground_context_pack("demo-repo", "basic_repo_question")

        self.assertNotEqual(
            first["context_ref"]["generated_at"], second["context_ref"]["generated_at"]
        )
        self.assertEqual(
            first["determinism"]["content_sha256"],
            second["determinism"]["content_sha256"],
        )
        self.assertEqual(
            first["determinism"]["volatile_fields"], ["context_ref.generated_at"]
        )

    def test_context_pack_determinism_contract_holds_for_two_repository_bundles(self) -> None:
        hashes = []
        preflight = {"status": "pass", "answer_compliance_template": {}}
        for repo_name, stem in (
            ("first-repo", "first-repo-max-260701-1200"),
            ("second-repo", "second-repo-max-260701-1200"),
        ):
            _repo, head = self._git_repo(repo_name)
            self._write_bundle(stem, commit=head)
            with patch.object(mcp, "_repoground_agent_preflight", return_value=preflight):
                cold = mcp.repoground_context_pack(repo_name, "basic_repo_question")
                warm = mcp.repoground_context_pack(repo_name, "basic_repo_question")
            self.assertEqual(
                cold["determinism"]["content_sha256"],
                warm["determinism"]["content_sha256"],
            )
            hashes.append(cold["determinism"]["content_sha256"])
        self.assertNotEqual(hashes[0], hashes[1])

    def test_context_pack_rejects_cross_repo_stem(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("other-repo-max-260701-1200", commit=head)

        result = mcp.repoground_context_pack(
            "demo-repo",
            "basic_repo_question",
            "other-repo-max-260701-1200",
        )

        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "bundle_repo_mismatch")
        self.assertEqual(result["bundle_repo"], "other-repo")

    def test_context_pack_reports_missing_bundle(self) -> None:
        result = mcp.repoground_context_pack("missing-repo", "basic_repo_question")
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "no_bundle_available")

    def test_query_existing_index_normalizes_nested_query_result_shape(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        repoground_result = {
            "status": "available",
            "query_result": {
                "results": [
                    {
                        "path": "README.md",
                        "chunk_id": "chunk-1",
                        "text": "hello world from bounded evidence",
                        "score": 0.5,
                        "range_ref": {
                            "artifact_role": "canonical_md",
                            "file_path": "demo-repo.md",
                            "start_byte": 0,
                            "end_byte": 11,
                        },
                    }
                ]
            },
        }

        with patch.object(
            mcp, "_repoground_query_existing_index", return_value=repoground_result
        ):
            result = mcp.repoground_query_existing_index("demo-repo", "hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["normalized_query_shape"], "query_result.results")
        self.assertEqual(result["hit_count"], 1)
        self.assertEqual(
            result["snippets"][0]["text_excerpt"], "hello world from bounded evidence"
        )
        self.assertEqual(result["ranges"][0]["artifact_role"], "canonical_md")
        self.assertIn("runtime_correctness", result["does_not_establish"])

    def test_query_existing_index_accepts_top_level_results_shape(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        repoground_result = {
            "status": "available",
            "results": [
                {
                    "path": "README.md",
                    "snippet": "top level shape",
                    "derived_range_ref": {
                        "artifact_role": "canonical_md",
                        "file_path": "demo-repo.md",
                        "start_byte": 20,
                        "end_byte": 35,
                    },
                }
            ],
        }

        with patch.object(
            mcp, "_repoground_query_existing_index", return_value=repoground_result
        ):
            result = mcp.repoground_query_existing_index("demo-repo", "shape", k=1)

        self.assertEqual(result["normalized_query_shape"], "top_level_results")
        self.assertEqual(result["snippets"][0]["text_excerpt"], "top level shape")
        self.assertEqual(result["ranges"][0]["start_byte"], 20)

    def test_range_get_wraps_repoground_result(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = {
            "artifact_role": "canonical_md",
            "file_path": "demo-repo.md",
            "start_byte": 0,
            "end_byte": 5,
        }
        repoground_result = {
            "status": "available",
            "available": True,
            "range": {"text": "hello", "lines": [1, 1]},
        }

        with patch.object(mcp, "_repoground_range_get", return_value=repoground_result):
            result = mcp.repoground_range_get("demo-repo", range_ref)

        self.assertTrue(result["available"])
        self.assertEqual(result["kind"], "grabowski.repoground_range_get")
        self.assertEqual(result["range"]["text"], "hello")
        self.assertEqual(result["mutation_boundary"]["writes"], [])

    def test_context_pack_exposes_wrappers_and_empty_snippet_axes(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle("demo-repo-max-260701-1200", commit=head)
        manifest_sha = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()
        preflight = {
            "status": "pass",
            "answer_compliance_template": {"task_profile": "basic_repo_question"},
        }

        with patch.object(mcp, "_repoground_agent_preflight", return_value=preflight):
            result = mcp.repoground_context_pack("demo-repo", "basic_repo_question")

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["manifest_sha256"], manifest_sha)
        self.assertEqual(result["access_wrappers"]["preflight"], "repoground_preflight")
        self.assertEqual(
            result["access_wrappers"]["query"], "repoground_query_existing_index"
        )
        self.assertEqual(result["access_wrappers"]["range"], "repoground_range_get")
        self.assertEqual(
            result["bounded_evidence"]["normalized_query_shape"], "query_not_requested"
        )
        self.assertEqual(result["bounded_evidence"]["snippets"], [])
        self.assertEqual(result["bounded_evidence"]["ranges"], [])
        self.assertEqual(
            result["preflight"]["answer_compliance_template"]["task_profile"],
            "basic_repo_question",
        )

    def test_only_canonical_repoground_tools_register_before_server_run(self) -> None:
        canonical = {
            "repoground_bundle_discover",
            "repoground_bundle_status",
            "repoground_freshness_check",
            "repoground_preflight",
            "repoground_query",
            "repoground_query_existing_index",
            "repoground_range_get",
            "repoground_context_pack",
            "repoground_find_symbol",
            "repoground_get_callers",
            "repoground_get_callees",
        }
        removed = {
            "rlens_bundle_discover",
            "rlens_bundle_status",
            "rlens_freshness_check",
            "rlens_preflight",
            "rlens_query",
            "rlens_query_existing_index",
            "rlens_range_get",
            "rlens_context_pack",
        }
        source = (ROOT / "src" / "grabowski_mcp.py").read_text(encoding="utf-8")
        registered = set(re.findall(r'@mcp\.tool\(name="([^"]+)"', source))
        self.assertTrue(canonical <= registered)
        self.assertTrue(removed.isdisjoint(registered))
        run_offset = source.index('if __name__ == "__main__":')
        for tool_name in canonical:
            self.assertLess(source.index(f'@mcp.tool(name="{tool_name}"'), run_offset)
        for tool_name in removed:
            self.assertNotIn(f'@mcp.tool(name="{tool_name}"', source)

    def test_call_graph_tools_preserve_s1_and_s0_axes(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        callers_payload = {
            "kind": "repobrief.mcp.readonly",
            "status": "available",
            "result": {
                "callers": [{"caller_scope": "module.fn", "call_sites": []}],
                "unresolved_references": [
                    {"relation_to_selected_target": "textual_name_only"}
                ],
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "does_not_establish": ["runtime_reachability"],
        }
        callees_payload = {
            "kind": "repobrief.mcp.readonly",
            "status": "available",
            "result": {
                "callees": [{"resolution": "S1", "target_symbol": {"id": "s1"}}],
                "unresolved_call_sites": [{"resolution": "S0"}],
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "does_not_establish": ["runtime_reachability"],
        }

        with patch.object(mcp, "_repoground_get_callers", return_value=callers_payload):
            callers = mcp.repoground_get_callers("demo-repo", "target")
        with patch.object(mcp, "_repoground_get_callees", return_value=callees_payload):
            callees = mcp.repoground_get_callees("demo-repo", "caller")

        self.assertIs(callers["result"], callers_payload)
        self.assertEqual(
            callers["result"]["result"]["callers"][0]["caller_scope"], "module.fn"
        )
        self.assertEqual(
            callers["result"]["result"]["unresolved_references"][0][
                "relation_to_selected_target"
            ],
            "textual_name_only",
        )
        self.assertEqual(callees["result"]["result"]["callees"][0]["resolution"], "S1")
        self.assertEqual(
            callees["result"]["result"]["unresolved_call_sites"][0]["resolution"],
            "S0",
        )

    def test_find_symbol_uses_bounded_repo_selection_and_passes_result_through(
        self,
    ) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        payload = {
            "kind": "repobrief.mcp.readonly",
            "status": "available",
            "result": {"hits": [{"name": "target", "path": "src/mod.py"}]},
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
        }
        with patch.object(
            mcp, "_repoground_find_symbol", return_value=payload
        ) as helper:
            result = mcp.repoground_find_symbol(
                "demo-repo",
                "target",
                kind="function",
                path="src/mod.py",
                k=5,
            )

        self.assertTrue(result["available"])
        self.assertEqual(result["result"], payload)
        helper.assert_called_once()
        self.assertEqual(helper.call_args.kwargs["name"], "target")
        self.assertEqual(helper.call_args.kwargs["path"], "src/mod.py")

    def test_navigation_rejects_path_and_name_injection_before_helper(self) -> None:
        for path in ("/etc/passwd", "../secret", "src\\secret.py", "src//mod.py"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                mcp.repoground_get_callers("demo-repo", "target", path=path)
        with self.assertRaises(ValueError):
            mcp.repoground_find_symbol("demo-repo", "bad\x00name")
        with self.assertRaises(ValueError):
            mcp.repoground_get_callees("demo-repo", "target", k=201)

    def test_navigation_missing_bundle_does_not_invoke_core_helper(self) -> None:
        with patch.object(
            mcp,
            "_repoground_get_callers",
            side_effect=AssertionError("core helper must not run"),
        ):
            result = mcp.repoground_get_callers("missing-repo", "target")
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "no_bundle_available")
        self.assertEqual(result["mutation_boundary"]["writes"], [])

    def test_core_subprocess_is_repo_grounded_and_bytecode_read_only(self) -> None:
        repo = self.home / "repos" / "repoground"
        repo.mkdir(parents=True)
        manifest = self.merges / "demo_merge.bundle.manifest.json"
        manifest.write_text("{}\n", encoding="utf-8")
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "status": "available",
                    "mutation_boundary": {
                        "writes": [],
                        "read_paths_do_not_refresh": True,
                    },
                }
            ),
            stderr="",
        )

        with (
            patch.object(mcp, "_repoground_repo", return_value=(repo, None)),
            patch.object(mcp.subprocess, "run", return_value=completed) as run,
        ):
            result = mcp._repoground_core_json(
                "find_symbol",
                manifest,
                {"name": "target", "kind": None, "path": None, "k": 5},
            )

        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["python3", "-B", "-c"])
        self.assertEqual(run.call_args.kwargs["cwd"], repo)
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertIn("from merger.repoground.core", command[3])
        self.assertNotIn("merger.lenskit", command[3])
        self.assertTrue(result["available"])


class RepoGroundContextBridgeToolTests(unittest.TestCase):
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
        self.tmp.cleanup()

    def _write_bundle(self, stem: str, commit: str = "a" * 40) -> Path:
        manifest = self.merges / f"{stem}_merge.bundle.manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "kind": "repolens.bundle.manifest",
                    "run_id": f"{stem}-run",
                    "created_at": "2026-07-01T00:00:00Z",
                    "generator": {
                        "runtime": {"git_commit": commit, "git_dirty": False}
                    },
                    "artifacts": [
                        {"role": "canonical_md"},
                        {"role": "sqlite_index"},
                        {"role": "citation_map_jsonl"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "evidence_level": "range_strict",
                    "range_ref_resolution_status": "ok",
                }
            ),
            encoding="utf-8",
        )
        (self.merges / f"{stem}_merge.output_health.json").write_text(
            json.dumps(
                {
                    "verdict": "pass",
                    "checks": {"range_ref_resolution_status": "ok"},
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def _git_repo(self, name: str) -> tuple[Path, str]:
        repo = self.home / "repos" / name
        repo.mkdir(parents=True)
        subprocess.run(
            ["git", "init"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Grabowski Test"], cwd=repo, check=True
        )
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        return repo, head

    def _range_ref(self) -> dict[str, object]:
        return {
            "artifact_role": "canonical_md",
            "repo_id": "demo-repo",
            "file_path": "README.md",
            "start_byte": 0,
            "end_byte": 5,
            "start_line": 1,
            "end_line": 1,
            "content_sha256": "b" * 64,
        }

    def test_query_wrapper_normalizes_nested_repoground_query_result(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = self._range_ref()
        payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "query_result": {
                "count": 1,
                "results": [
                    {
                        "chunk_id": "c1",
                        "path": "README.md",
                        "content": "hello from nested result",
                        "range_ref": range_ref,
                    }
                ],
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }

        with patch.object(
            mcp, "_repoground_query_existing_index", return_value=payload
        ):
            result = mcp.repoground_query("demo-repo", "hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["query_shape"], "query_result.results")
        self.assertEqual(result["hit_count"], 1)
        self.assertEqual(
            result["snippets"][0]["text_excerpt"], "hello from nested result"
        )
        self.assertEqual(result["ranges"][0], range_ref)
        self.assertFalse(result["raw_results_included"])

    def test_context_pack_includes_snippets_ranges_and_compliance_template(
        self,
    ) -> None:
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle("demo-repo-max-260701-1200", commit=head)
        manifest_sha = __import__("hashlib").sha256(manifest.read_bytes()).hexdigest()
        range_ref = self._range_ref()
        preflight = {
            "status": "pass",
            "available": True,
            "required_reading": {"required": ["canonical_md"]},
            "answer_compliance_template": {"task_profile": "basic_repo_question"},
            "does_not_establish": ["actual_agent_reading"],
        }
        query_payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "query_result": {"count": 1, "results": []},
            "source_citation_projection": {
                "items": [
                    {
                        "ordinal": 0,
                        "path": "README.md",
                        "chunk_id": "c1",
                        "text_excerpt": "bounded citation text",
                        "range_status": "resolved",
                        "citation_status": "resolved",
                        "citation_id": "cit_0123456789abcdef",
                        "source_range": range_ref,
                    }
                ]
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }

        with (
            patch.object(mcp, "_repoground_agent_preflight", return_value=preflight),
            patch.object(
                mcp, "_repoground_query_existing_index", return_value=query_payload
            ),
        ):
            result = mcp.repoground_context_pack("demo-repo", query="hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["manifest_sha256"], manifest_sha)
        self.assertEqual(result["context_ref"]["snippet_count"], 1)
        self.assertEqual(result["context_ref"]["range_count"], 1)
        self.assertEqual(
            result["preflight"]["answer_compliance_template"]["task_profile"],
            "basic_repo_question",
        )
        self.assertEqual(result["snippets"][0]["text_excerpt"], "bounded citation text")
        self.assertEqual(result["ranges"][0], range_ref)
        self.assertIn("actual_agent_reading", result["does_not_establish"])

    def test_query_existing_index_honors_evidence_and_projection_flags(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        captured = {}

        def fake_query(
            _manifest, _query, *, k, filters, resolve_evidence, project_sources
        ):
            captured.update(
                {
                    "k": k,
                    "filters": filters,
                    "resolve_evidence": resolve_evidence,
                    "project_sources": project_sources,
                }
            )
            return {"status": "available", "query_result": {"results": []}}

        with patch.object(
            mcp, "_repoground_query_existing_index", side_effect=fake_query
        ):
            result = mcp.repoground_query_existing_index(
                "demo-repo",
                "hello",
                k=2,
                filters={"path": "README.md"},
                resolve_evidence=False,
                project_sources=False,
            )

        self.assertTrue(result["available"])
        self.assertFalse(result["resolve_evidence"])
        self.assertFalse(result["project_sources"])
        self.assertEqual(captured["k"], 2)
        self.assertEqual(captured["filters"], {"path": "README.md"})
        self.assertFalse(captured["resolve_evidence"])
        self.assertFalse(captured["project_sources"])

    def test_range_wrapper_returns_bounded_repoground_range(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = self._range_ref()
        payload = {
            "kind": "repobrief.range_get",
            "status": "available",
            "range": {"text": "hello", "lines": [1, 1]},
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
        }

        with patch.object(mcp, "_repoground_range_get", return_value=payload):
            result = mcp.repoground_range_get("demo-repo", range_ref)

        self.assertTrue(result["available"])
        self.assertEqual(result["range"]["text"], "hello")
        self.assertEqual(result["mutation_boundary"]["writes"], [])


class RepoGroundContextPackResolvedEvidenceTests(unittest.TestCase):
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
        self.tmp.cleanup()

    def _write_bundle_and_repo(self, name: str = "demo-repo") -> tuple[Path, str]:
        repo = self.home / "repos" / name
        repo.mkdir(parents=True)
        subprocess.run(
            ["git", "init"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Grabowski Test"], cwd=repo, check=True
        )
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        stem = f"{name}-max-260701-1200"
        manifest = self.merges / f"{stem}_merge.bundle.manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "kind": "repolens.bundle.manifest",
                    "run_id": f"{stem}-run",
                    "created_at": "2026-07-01T00:00:00Z",
                    "generator": {"runtime": {"git_commit": head, "git_dirty": False}},
                    "artifacts": [
                        {"role": "canonical_md"},
                        {"role": "sqlite_index"},
                        {"role": "citation_map_jsonl"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(
            json.dumps({"status": "pass"}), encoding="utf-8"
        )
        (self.merges / f"{stem}_merge.output_health.json").write_text(
            json.dumps({"verdict": "pass"}), encoding="utf-8"
        )
        return manifest, head

    def test_context_pack_consumes_resolved_evidence_hits_with_citation_and_live_address(
        self,
    ) -> None:
        self._write_bundle_and_repo()
        preflight = {
            "status": "pass",
            "available": True,
            "answer_compliance_template": {"task_profile": "basic_repo_question"},
            "does_not_establish": ["actual_agent_reading"],
        }
        payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "resolved_evidence": {
                "hits": [
                    {
                        "chunk_id": "c1",
                        "source_path": "src/app.py",
                        "text_excerpt": "resolved evidence text",
                        "source_range": {
                            "file_path": "src/app.py",
                            "start_line": 4,
                            "end_line": 5,
                        },
                        "line_range": {
                            "start_line": 4,
                            "end_line": 5,
                            "display": "4-5",
                        },
                        "citation_id": "cit_0123456789abcdef",
                        "citation_status": "resolved",
                        "citation_verified": True,
                        "canonical_authority": {"authority": "canonical_brief_source"},
                        "live_repo_address": {
                            "status": "available",
                            "path": "src/app.py",
                            "git_commit": "a" * 40,
                        },
                        "live_repo_address_status": "available",
                    }
                ]
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }
        with (
            patch.object(mcp, "_repoground_agent_preflight", return_value=preflight),
            patch.object(mcp, "_repoground_query_existing_index", return_value=payload),
        ):
            result = mcp.repoground_context_pack("demo-repo", query="hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(
            result["bounded_evidence"]["normalized_query_shape"],
            "resolved_evidence.hits",
        )
        self.assertEqual(
            result["bounded_evidence"]["resolved_evidence_status"], "available"
        )
        self.assertEqual(
            result["bounded_evidence"]["citation_ids"], ["cit_0123456789abcdef"]
        )
        self.assertEqual(result["context_ref"]["citation_count"], 1)
        snippet = result["snippets"][0]
        self.assertEqual(snippet["text_excerpt"], "resolved evidence text")
        self.assertEqual(snippet["source_range"]["file_path"], "src/app.py")
        self.assertEqual(snippet["live_repo_address_status"], "available")
        self.assertEqual(
            snippet["canonical_authority"]["authority"], "canonical_brief_source"
        )

    def test_context_pack_degrades_when_resolved_evidence_unavailable(self) -> None:
        self._write_bundle_and_repo()
        preflight = {
            "status": "warn",
            "available": True,
            "answer_compliance_template": {"task_profile": "basic_repo_question"},
        }
        payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "query_result": {"count": 0, "results": []},
            "evidence_resolution_used": False,
        }
        with (
            patch.object(mcp, "_repoground_agent_preflight", return_value=preflight),
            patch.object(mcp, "_repoground_query_existing_index", return_value=payload),
        ):
            result = mcp.repoground_context_pack("demo-repo", query="missing", k=1)

        self.assertEqual(
            result["bounded_evidence"]["resolved_evidence_status"], "degraded"
        )
        self.assertEqual(
            result["bounded_evidence"]["degradation_reason"],
            "resolved_evidence_missing_snippets_ranges_or_citations",
        )
        self.assertEqual(result["bounded_evidence"]["snippets"], [])
        self.assertEqual(result["bounded_evidence"]["ranges"], [])
        self.assertEqual(result["context_ref"]["resolved_evidence_status"], "degraded")


    def _composer_fixture(self) -> tuple[str, str]:
        _manifest, base = self._write_bundle_and_repo()
        repo = self.home / "repos" / "demo-repo"
        (repo / "src").mkdir()
        (repo / "tests").mkdir()
        (repo / "src" / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
        (repo / "tests" / "test_app.py").write_text("def test_run():\n    assert True\n", encoding="utf-8")
        subprocess.run(["git", "add", "src/app.py", "tests/test_app.py"], cwd=repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "change app"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        target = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip()
        return base, target

    @staticmethod
    def _composer_context_pack() -> dict:
        return {
            "kind": "grabowski.repoground_context_pack",
            "schema_version": 1,
            "available": True,
            "preflight": {
                "available": True,
                "status": "pass",
                "required_reading": {
                    "required": ["canonical_md", "bundle_manifest"],
                    "recommended": ["agent_entry_manifest"],
                    "missing_required": [],
                    "missing_recommended": ["pr_delta_cards_jsonl"],
                },
            },
            "bounded_evidence": {
                "citation_ids": ["cit_0123456789abcdef"],
                "snippets": [
                    {
                        "path": "src/app.py",
                        "text_excerpt": "x" * 700,
                        "citation_id": "cit_0123456789abcdef",
                    }
                ],
                "ranges": [
                    {"file_path": "src/app.py", "start_line": 1, "end_line": 2}
                ],
            },
            "snippets": [
                {
                    "path": "src/app.py",
                    "text_excerpt": "x" * 700,
                    "citation_id": "cit_0123456789abcdef",
                }
            ],
            "ranges": [
                {"file_path": "src/app.py", "start_line": 1, "end_line": 2}
            ],
            "does_not_establish": ["claims_true"],
        }

    @staticmethod
    def _composer_impact() -> dict:
        return {
            "status": "available",
            "relations": [
                {
                    "direction": "incoming",
                    "peer": {"path": "tests/test_app.py"},
                    "edge_type": "import",
                    "evidence_level": "S1",
                }
            ],
            "supporting_context": [
                {
                    "path": "config/app.json",
                    "path_class": "config",
                    "evidence_type": "graph_edge",
                }
            ],
            "related_tests": [
                {"path": "tests/test_app.py", "evidence_type": "graph_edge"}
            ],
            "entrypoints": [{"path": "src/app.py"}],
            "edit_context": {
                "recommended_first_reads": [
                    {"path": "src/app.py", "reason": "changed_path"}
                ]
            },
            "gaps": [],
            "source_statuses": [
                {"source": "python_symbol_index_json", "status": "available"}
            ],
            "does_not_establish": ["test_sufficiency", "runtime_behavior"],
        }

    def test_context_lane_policy_rejects_missing_or_unknown_configuration(self) -> None:
        lane_values = {name: [] for name in mcp._REPOGROUND_CONTEXT_LANE_CONFIG}
        lane_values["unconfigured_lane"] = []
        with self.assertRaisesRegex(RuntimeError, "configuration mismatch"):
            mcp._repoground_context_lane_policy(lane_values)

        lane_values = {name: [] for name in mcp._REPOGROUND_CONTEXT_LANE_CONFIG}
        lane_values.pop("target_symbols")
        with self.assertRaisesRegex(RuntimeError, "configuration mismatch"):
            mcp._repoground_context_lane_policy(lane_values)

    def test_budget_context_distinguishes_policy_caps_from_byte_budget(self) -> None:
        items = [{"id": index} for index in range(5)]
        context, counts, used_bytes = mcp._repoground_budget_context(
            [("query_snippets", items)],
            10_000,
            lane_item_limits={"query_snippets": 2},
        )

        self.assertEqual(context["query_snippets"], items[:2])
        self.assertEqual(counts["query_snippets"]["available"], 5)
        self.assertEqual(counts["query_snippets"]["considered"], 2)
        self.assertEqual(counts["query_snippets"]["included"], 2)
        self.assertEqual(counts["query_snippets"]["policy_omitted"], 3)
        self.assertEqual(counts["query_snippets"]["budget_omitted"], 0)
        self.assertEqual(used_bytes, mcp._repoground_json_bytes(context))

    def test_budget_context_preserves_cross_lane_coverage_before_priority_fill(self) -> None:
        direct_changes = [
            {"payload": "d" * 120},
            {"payload": "d" * 60},
        ]
        target_symbols = [{"payload": "s" * 20}]
        causal_relations = [{"payload": "c" * 20}]
        coverage_context = {
            "direct_changes": direct_changes[:1],
            "target_symbols": target_symbols,
            "causal_relations": causal_relations,
        }
        limit = mcp._repoground_json_bytes(coverage_context)
        self.assertLessEqual(
            mcp._repoground_json_bytes({"direct_changes": direct_changes}),
            limit,
        )

        context, counts, used_bytes = mcp._repoground_budget_context(
            [
                ("direct_changes", direct_changes),
                ("target_symbols", target_symbols),
                ("causal_relations", causal_relations),
            ],
            limit,
            lane_item_limits={
                "direct_changes": 2,
                "target_symbols": 1,
                "causal_relations": 1,
            },
            lane_min_items={
                "direct_changes": 1,
                "target_symbols": 1,
                "causal_relations": 1,
            },
        )

        self.assertEqual(len(context["direct_changes"]), 1)
        self.assertEqual(len(context["target_symbols"]), 1)
        self.assertEqual(len(context["causal_relations"]), 1)
        self.assertEqual(counts["direct_changes"]["budget_omitted"], 1)
        self.assertEqual(used_bytes, mcp._repoground_json_bytes(context))

    def test_context_compose_is_deterministic_diff_bound_and_budgeted(self) -> None:
        base, target = self._composer_fixture()
        with (
            patch.object(mcp, "repoground_context_pack", return_value=self._composer_context_pack()),
            patch.object(mcp, "_repoground_agent_impact_context", return_value=self._composer_impact()),
        ):
            unbound = mcp.repoground_context_compose(
                "demo-repo",
                base,
                target,
                task_profile="change_impact",
                context_budget_bytes=1200,
            )
            expected_diff = unbound["change_identity"]["diff_sha256"]
            first = mcp.repoground_context_compose(
                "demo-repo",
                base,
                target,
                task_profile="change_impact",
                context_budget_bytes=1200,
                expected_diff_sha256=expected_diff,
            )
            second = mcp.repoground_context_compose(
                "demo-repo",
                base,
                target,
                task_profile="change_impact",
                context_budget_bytes=1200,
                expected_diff_sha256=expected_diff,
            )

        self.assertEqual(first, second)
        self.assertTrue(first["available"])
        self.assertEqual(first["change_identity"]["base_commit"], base)
        self.assertEqual(first["change_identity"]["target_commit"], target)
        self.assertTrue(first["change_identity"]["diff_binding_verified"])
        self.assertLessEqual(
            first["context_budget"]["used_bytes"],
            first["context_budget"]["effective_limit_bytes"],
        )
        self.assertLessEqual(
            first["context_budget"]["effective_limit_bytes"], 1200
        )
        self.assertTrue(first["compactness"]["smaller_than_general_context_pack"])
        self.assertLessEqual(
            first["compactness"]["ratio"], first["compactness"]["target_max_ratio"]
        )
        self.assertEqual(first["sampling_policy"]["kind"], "deterministic_priority_lane_caps_v2")
        self.assertIn("direct_changes", first["context"])
        self.assertIn("related_tests", first["context"])
        self.assertIn("authority_ordered_rules", first["context"])
        self.assertIn("gate_evidence", first["context"])
        self.assertEqual(
            first["context"]["authority_ordered_rules"][0]["authority"],
            "required_reading_protocol",
        )
        self.assertIn("agent_impact", first["retrieval_lanes"]["used"])
        self.assertIn("query_context", first["retrieval_lanes"]["used"])
        self.assertFalse(first["dirty_overlay"]["included_in_revision_diff"])
        self.assertNotIn("raw_diff", first)
        self.assertEqual(
            first["sampling_policy"]["allocation_strategy"],
            "minimum_coverage_then_priority_fill_v1",
        )
        self.assertLess(
            first["sampling_policy"]["lane_order_used"].index("target_symbols"),
            first["sampling_policy"]["lane_order_used"].index("query_snippets"),
        )
        self.assertIn("patch_correctness", first["does_not_establish"])
        self.assertIn("merge_readiness", first["does_not_establish"])

    def test_context_compose_does_not_claim_call_graph_lane_for_architecture_relations(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["relations"] = [
            {
                "direction": "incoming",
                "peer": {"path": "tests/test_app.py"},
                "edge_type": "import",
                "evidence_level": "S1",
                "freshness": {
                    "source": "architecture_graph_json",
                    "status": "coherent",
                },
            }
        ]
        impact["source_statuses"].append(
            {
                "source": "python_call_graph_json",
                "status": "blocked",
                "error_code": "artifact_too_large",
            }
        )
        impact["gaps"].append(
            {
                "kind": "call_graph_coverage_gap",
                "source": "python_call_graph_json",
                "reason": "artifact_too_large",
            }
        )
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=4000
            )

        self.assertIn("causal_relations", result["context"])
        self.assertNotIn("call_graph", result["retrieval_lanes"]["used"])
        self.assertIn("call_graph", result["retrieval_lanes"]["skipped"])
        self.assertEqual(
            result["context_budget"]["lane_counts"]["gaps"]["available"], 1
        )
        self.assertEqual(
            result["context_budget"]["lane_counts"]["gaps"]["included"], 1
        )
        self.assertEqual(result["context"]["gaps"], impact["gaps"])

    def test_context_compose_does_not_claim_call_graph_lane_for_untrusted_call_graph_evidence(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["relations"] = [
            {
                "relation_kind": "direct_caller",
                "direction": "incoming",
                "path": "src/caller.py",
                "relation_type": "calls",
                "evidence_level": "S1",
                "resolution_status": "resolved",
                "source_ranges": {"call_site": "file:src/caller.py#L10-L10"},
                "freshness": {
                    "source": "python_call_graph_json",
                    "status": "stale_or_mismatched",
                },
                "provenance": {
                    "relation": {
                        "source": "python_call_graph_json",
                        "status": "stale_or_mismatched",
                    }
                },
            }
        ]
        impact["source_statuses"].append(
            {"source": "python_call_graph_json", "status": "available"}
        )
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=4000
            )

        self.assertNotIn("call_graph", result["retrieval_lanes"]["used"])
        self.assertIn("call_graph", result["retrieval_lanes"]["skipped"])

    def test_context_compose_claims_call_graph_lane_only_for_consumed_call_graph_evidence(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["relations"] = [
            {
                "relation_kind": "direct_caller",
                "direction": "incoming",
                "path": "src/caller.py",
                "relation_type": "calls",
                "evidence_level": "S1",
                "resolution_status": "resolved",
                "source_ranges": {"call_site": "file:src/caller.py#L10-L10"},
                "freshness": {
                    "source": "python_call_graph_json",
                    "status": "coherent",
                },
                "provenance": {
                    "relation": {
                        "source": "python_call_graph_json",
                        "status": "coherent",
                    }
                },
            }
        ]
        impact["source_statuses"].append(
            {"source": "python_call_graph_json", "status": "available"}
        )
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=4000
            )

        self.assertIn("call_graph", result["retrieval_lanes"]["used"])
        self.assertNotIn("call_graph", result["retrieval_lanes"]["skipped"])

    def test_context_compose_ignores_coherent_source_markers_outside_relation_provenance(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["relations"] = [
            {
                "direction": "incoming",
                "peer": {"path": "src/caller.py"},
                "edge_type": "import",
                "metadata": {
                    "diagnostic": {
                        "source": "python_call_graph_json",
                        "status": "coherent",
                    }
                },
            }
        ]
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=4000
            )

        self.assertNotIn("call_graph", result["retrieval_lanes"]["used"])
        self.assertIn("call_graph", result["retrieval_lanes"]["skipped"])

    def test_context_compose_does_not_claim_call_graph_when_evidence_is_budget_omitted(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["relations"] = [
            {
                "relation_kind": "direct_caller",
                "direction": "incoming",
                "path": "src/caller.py",
                "relation_type": "calls",
                "evidence_level": "S1",
                "resolution_status": "resolved",
                "payload": "x" * 4000,
                "freshness": {
                    "source": "python_call_graph_json",
                    "status": "coherent",
                },
            }
        ]
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=512
            )

        relation_counts = result["context_budget"]["lane_counts"]["causal_relations"]
        self.assertEqual(relation_counts["available"], 1)
        self.assertEqual(relation_counts["included"], 0)
        self.assertEqual(relation_counts["budget_omitted"], 1)
        self.assertNotIn("call_graph", result["retrieval_lanes"]["used"])
        self.assertIn("call_graph", result["retrieval_lanes"]["skipped"])

    def test_context_compose_reports_content_lanes_used_only_when_post_budget_content_survives(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["target_symbols"] = [
            {"name": "oversized_symbol", "payload": "s" * 4000}
        ]
        with (
            patch.object(
                mcp,
                "repoground_context_pack",
                return_value=self._composer_context_pack(),
            ),
            patch.object(
                mcp, "_repoground_agent_impact_context", return_value=impact
            ),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=512
            )

        used = set(result["retrieval_lanes"]["used"])
        lane_projection = {
            "symbol_navigation": "target_symbols",
            "citation": "citations",
            "live_evidence": "live_ranges",
            "entry_manifest": "entry_manifest",
            "pr_delta_cards": "pr_delta_cards",
        }
        for retrieval_lane, context_lane in lane_projection.items():
            self.assertEqual(
                retrieval_lane in used,
                bool(result["context"].get(context_lane)),
                retrieval_lane,
            )
        self.assertEqual(
            result["context_budget"]["lane_counts"]["target_symbols"]["included"],
            0,
        )
        self.assertNotIn("symbol_navigation", used)

    def test_context_compose_prioritizes_tests_and_gates_before_large_impact_lanes(self) -> None:
        base, target = self._composer_fixture()
        impact = self._composer_impact()
        impact["target_symbols"] = [
            {"name": f"symbol_{index}", "path": f"src/module_{index}.py"}
            for index in range(40)
        ]
        impact["relations"] = [
            {
                "direction": "incoming",
                "peer": {"path": f"src/peer_{index}.py"},
                "edge_type": "import",
                "evidence_level": "S1",
            }
            for index in range(40)
        ]
        impact["related_tests"] = [
            {"path": f"tests/test_{index}.py", "evidence_type": "graph_edge"}
            for index in range(12)
        ]
        with (
            patch.object(mcp, "repoground_context_pack", return_value=self._composer_context_pack()),
            patch.object(mcp, "_repoground_agent_impact_context", return_value=impact),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=1200
            )

        self.assertGreater(len(result["context"]["related_tests"]), 0)
        self.assertGreater(len(result["context"]["gate_evidence"]), 0)
        self.assertEqual(
            result["context_budget"]["lane_counts"]["target_symbols"]["available"], 40
        )
        self.assertEqual(
            result["context_budget"]["lane_counts"]["target_symbols"]["considered"], 8
        )
        self.assertEqual(
            result["sampling_policy"]["effective_priorities"]["target_symbols"], 80
        )
        self.assertIn("target_symbols", result["sampling_policy"]["policy_limited_lanes"])
        self.assertLessEqual(
            result["compactness"]["ratio"], result["compactness"]["target_max_ratio"]
        )

    def test_context_compose_blocks_mismatched_diff_binding(self) -> None:
        base, target = self._composer_fixture()
        result = mcp.repoground_context_compose(
            "demo-repo",
            base,
            target,
            context_budget_bytes=1200,
            expected_diff_sha256="0" * 64,
        )

        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "diff_sha256_mismatch")
        self.assertIn("diff_sha256_mismatch", result["stop_criteria"]["triggered"])
        self.assertEqual(result["retrieval_lanes"]["used"], ["direct_changes"])

    def test_context_compose_keeps_dirty_overlay_separate_from_revision_diff(self) -> None:
        base, target = self._composer_fixture()
        repo = self.home / "repos" / "demo-repo"
        (repo / "src" / "app.py").write_text("dirty overlay\n", encoding="utf-8")
        with (
            patch.object(mcp, "repoground_context_pack", return_value=self._composer_context_pack()),
            patch.object(mcp, "_repoground_agent_impact_context", return_value=self._composer_impact()),
        ):
            result = mcp.repoground_context_compose(
                "demo-repo", base, target, context_budget_bytes=1200
            )

        self.assertTrue(result["dirty_overlay"]["dirty"])
        self.assertFalse(result["dirty_overlay"]["included_in_revision_diff"])
        self.assertEqual(result["change_identity"]["changed_path_count"], 2)
        paths = [item["path"] for item in result["context"]["direct_changes"]]
        self.assertEqual(paths, ["src/app.py", "tests/test_app.py"])


class RepoGroundAgentHandoffTests(unittest.TestCase):
    def test_agent_handoff_exposes_exact_operations_and_modes(self) -> None:
        self.assertEqual(
            mcp._REPOGROUND_AGENT_HANDOFF_OPERATIONS,
            {"change_impact", "find_relevant_tests", "ground_claim"},
        )
        self.assertEqual(
            mcp._REPOGROUND_AGENT_HANDOFF_RETRIEVAL_MODES,
            {
                "native_live_tools",
                "repoground_context",
                "combined",
                "no_additional_retrieval",
            },
        )

    def test_agent_handoff_rejects_invalid_operation_and_mode(self) -> None:
        with patch.object(mcp, "_require_capability", return_value=None):
            with self.assertRaisesRegex(ValueError, "operation must be one of"):
                mcp.repoground_agent_handoff(
                    "demo-repo", "search_everything", "no_additional_retrieval"
                )
            with self.assertRaisesRegex(ValueError, "retrieval_mode must be one of"):
                mcp.repoground_agent_handoff(
                    "demo-repo", "change_impact", "automatic"
                )

    def test_agent_handoff_requires_operation_inputs(self) -> None:
        with patch.object(mcp, "_require_capability", return_value=None):
            with self.assertRaisesRegex(ValueError, "base_revision is required"):
                mcp.repoground_agent_handoff(
                    "demo-repo", "change_impact", "native_live_tools"
                )
            with self.assertRaisesRegex(ValueError, "target_revision is required"):
                mcp.repoground_agent_handoff(
                    "demo-repo",
                    "find_relevant_tests",
                    "native_live_tools",
                    base_revision="base",
                )
            with self.assertRaisesRegex(ValueError, "claim must be"):
                mcp.repoground_agent_handoff(
                    "demo-repo", "ground_claim", "native_live_tools"
                )
            with self.assertRaisesRegex(ValueError, "claim is only valid"):
                mcp.repoground_agent_handoff(
                    "demo-repo",
                    "change_impact",
                    "native_live_tools",
                    base_revision="base",
                    target_revision="target",
                    claim="irrelevant",
                )
            with self.assertRaisesRegex(ValueError, "not valid for ground_claim"):
                mcp.repoground_agent_handoff(
                    "demo-repo",
                    "ground_claim",
                    "native_live_tools",
                    base_revision="base",
                    claim="claim",
                )
            with self.assertRaisesRegex(ValueError, "use claim"):
                mcp.repoground_agent_handoff(
                    "demo-repo",
                    "ground_claim",
                    "native_live_tools",
                    claim="claim",
                    query="ignored",
                )

    def test_agent_handoff_no_additional_retrieval_calls_nothing_and_has_no_default(self) -> None:
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(mcp, "repoground_context_compose") as compose,
            patch.object(mcp, "repoground_context_pack") as pack,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "change_impact",
                "no_additional_retrieval",
                base_revision="base",
                target_revision="target",
            )
        self.assertEqual(result["routes"], [])
        self.assertEqual(
            result["routing_contract"],
            {
                "selection": "caller_explicit",
                "automatic_selection": False,
                "default_route": None,
                "global_repoground_promotion": False,
            },
        )
        self.assertEqual(result["mutation_boundary"]["writes"], [])
        compose.assert_not_called()
        pack.assert_not_called()

    def test_agent_handoff_native_mode_is_declarative_only(self) -> None:
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(mcp, "repoground_context_compose") as compose,
            patch.object(mcp, "repoground_context_pack") as pack,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "change_impact",
                "native_live_tools",
                base_revision="base",
                target_revision="target",
            )
        self.assertEqual(result["routes"][0]["kind"], "native_live_tools")
        self.assertFalse(result["routes"][0]["executed"])
        self.assertEqual(result["routes"][0]["authority"], "live_repository_readback")
        compose.assert_not_called()
        pack.assert_not_called()

    def test_agent_handoff_change_impact_delegates_to_compose(self) -> None:
        evidence = {"status": "available", "context": {"direct_changes": []}}
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(
                mcp, "repoground_context_compose", return_value=evidence
            ) as compose,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "change_impact",
                "repoground_context",
                base_revision=" base ",
                target_revision=" target ",
                expected_diff_sha256="0" * 64,
                query="changed files",
            )
        compose.assert_called_once_with(
            "demo-repo",
            "base",
            "target",
            task_profile="change_impact",
            context_budget_bytes=12000,
            expected_diff_sha256="0" * 64,
            stem=None,
            query="changed files",
        )
        self.assertIs(result["routes"][0]["repoground_evidence"], evidence)
        self.assertTrue(result["routes"][0]["executed"])

    def test_agent_handoff_find_relevant_tests_reuses_compose(self) -> None:
        evidence = {
            "status": "available",
            "context": {"related_tests": [{"path": "tests/test_app.py"}]},
        }
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(
                mcp, "repoground_context_compose", return_value=evidence
            ) as compose,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "find_relevant_tests",
                "repoground_context",
                base_revision="base",
                target_revision="target",
            )
        compose.assert_called_once_with(
            "demo-repo",
            "base",
            "target",
            task_profile="change_impact",
            context_budget_bytes=12000,
            expected_diff_sha256=None,
            stem=None,
            query=None,
        )
        self.assertEqual(result["routes"][0]["tool"], "repoground_context_compose")
        self.assertIs(result["routes"][0]["repoground_evidence"], evidence)

    def test_agent_handoff_ground_claim_reuses_basic_context_pack(self) -> None:
        evidence = {"available": True, "bounded_evidence": {"snippets": []}}
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(mcp, "repoground_context_pack", return_value=evidence) as pack,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "ground_claim",
                "repoground_context",
                claim=" The claim ",
            )
        pack.assert_called_once_with(
            "demo-repo",
            task_profile="basic_repo_question",
            stem=None,
            query="The claim",
        )
        self.assertIs(result["routes"][0]["repoground_evidence"], evidence)

    def test_agent_handoff_combined_keeps_authorities_separate(self) -> None:
        evidence = {"status": "available"}
        with (
            patch.object(mcp, "_require_capability", return_value=None),
            patch.object(
                mcp, "repoground_context_compose", return_value=evidence
            ) as compose,
        ):
            result = mcp.repoground_agent_handoff(
                "demo-repo",
                "change_impact",
                "combined",
                base_revision="base",
                target_revision="target",
            )
        compose.assert_called_once()
        self.assertEqual(
            [route["kind"] for route in result["routes"]],
            ["repoground_context", "native_live_tools"],
        )
        self.assertEqual(
            [route["authority"] for route in result["routes"]],
            ["bounded_published_repository_evidence", "live_repository_readback"],
        )
        self.assertFalse(result["routes"][1]["executed"])
        self.assertIn("truth", result["does_not_establish"])
        self.assertIn("global_repoground_routing_authority", result["does_not_establish"])

    def test_agent_handoff_paired_baseline_preserves_evidence_for_two_repositories(self) -> None:
        for repo in ("lenskit", "bureau"):
            with self.subTest(repo=repo):
                evidence = {
                    "kind": "grabowski.repoground_context_compose",
                    "repo": repo,
                    "status": "available",
                    "context": {"direct_changes": [{"path": "example.py"}]},
                }
                with (
                    patch.object(mcp, "_require_capability", return_value=None),
                    patch.object(
                        mcp, "repoground_context_compose", return_value=evidence
                    ) as compose,
                ):
                    result = mcp.repoground_agent_handoff(
                        repo,
                        "change_impact",
                        "repoground_context",
                        base_revision="base",
                        target_revision="target",
                    )
                compose.assert_called_once()
                self.assertIs(result["routes"][0]["repoground_evidence"], evidence)
                self.assertFalse(result["routing_contract"]["global_repoground_promotion"])

    def test_agent_handoff_is_registered_in_runtime_and_capabilities(self) -> None:
        runtime = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text()
        )
        self.assertIn("repoground_agent_handoff", runtime["expected_tools"])
        import grabowski_capabilities

        self.assertIn(
            "repoground_agent_handoff", grabowski_capabilities.TOOL_PROFILES
        )
        self.assertEqual(
            mcp.TOOL_CAPABILITY_REQUIREMENTS["repoground_agent_handoff"],
            ("bundle_registry",),
        )


if __name__ == "__main__":
    unittest.main()
