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
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(json.dumps({
            "status": "pass",
            "evidence_level": "range_strict",
            "range_ref_resolution_status": "ok",
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.output_health.json").write_text(json.dumps({
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

    def test_full_max_stem_maps_to_base_repository(self) -> None:
        stem = "demo-repo-full-max-260701-1200"
        _repo, head = self._git_repo("demo-repo")
        manifest = self._write_bundle(stem, commit=head)
        document = json.loads(manifest.read_text(encoding="utf-8"))
        document["snapshotProvenance"]["repositories"][0]["repo"] = "demo-repo"
        manifest.write_text(json.dumps(document), encoding="utf-8")

        discovery = mcp.rlens_bundle_discover(repo="demo-repo")

        self.assertEqual(discovery["candidate_count"], 1)
        self.assertEqual(discovery["candidates"][0]["repo"], "demo-repo")

        with patch.object(
            mcp,
            "_rlens_agent_preflight",
            return_value={"status": "pass"},
        ):
            result = mcp.rlens_context_pack(
                "demo-repo",
                "basic_repo_question",
                stem,
            )

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["repo"], "demo-repo")

    def test_discover_reads_latest_bundle_metadata(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.rlens_bundle_discover(repo="demo-repo")

        self.assertEqual(result["kind"], "grabowski.rlens_bundle_discovery")
        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["repo"], "demo-repo")
        self.assertEqual(candidate["post_emit_health"]["status"], "pass")
        self.assertEqual(candidate["git_commit"], "a" * 40)
        self.assertEqual(candidate["source_provenance"]["git_commit"], "a" * 40)
        self.assertEqual(candidate["generator_runtime"]["git_commit"], "f" * 40)
        self.assertEqual(candidate["output_health"]["range_ref_resolution_status"], "ok")
        self.assertTrue(candidate["output_health"]["dependencies"]["jsonschema"]["available"])
        self.assertIn("canonical_md", candidate["artifact_roles"])
        self.assertIn("bundle_freshness_against_live_repo", result["does_not_establish"])

    def test_bundle_status_reads_sidecars_without_content_dump(self) -> None:
        self._write_bundle("demo-repo-max-260701-1200")

        result = mcp.rlens_bundle_status("demo-repo-max-260701-1200")

        self.assertTrue(result["exists"])
        self.assertEqual(result["post_emit_health"]["evidence_level"], "range_strict")
        self.assertEqual(result["output_health"]["verdict"], "pass")
        self.assertEqual(result["output_health"]["range_ref_resolution_status"], "ok")
        self.assertEqual(result["output_health"]["range_ref_resolution"]["validation"]["mode"], "jsonschema")
        self.assertEqual(result["output_health"]["dependencies"]["jsonschema"]["effect"], "full_validation_available")
        self.assertEqual(result["authority"], "artifact_metadata_only")
        self.assertIn("claims_true", result["does_not_establish"])

    def test_latest_complete_bundles_merges_valid_legacy_with_discovery_when_cache_is_stale(self) -> None:
        self._write_bundle("valid-repo-max-260701-1200")
        self._write_bundle("live-repo-max-260701-1200")
        (self.state / "rlens-latest-complete-bundles.tsv").write_text(
            "repo\tstem\tlatest_mtime\thas_agent_reading_pack\tcanonical_md\tbundle_manifest\toutput_health\tagent_reading_pack\n"
            "valid-repo\tvalid-repo-max-260701-1200\t2026-07-01T00:00:00Z\tno\t./merges/valid-repo-max-260701-1200_merge.md\t./merges/valid-repo-max-260701-1200_merge.bundle.manifest.json\t./merges/valid-repo-max-260701-1200_merge.output_health.json\t./merges/valid-repo-max-260701-1200_merge.agent_reading_pack.md\n"
            "stale-repo\tstale-repo-max-260101-0000\t2026-01-01T00:00:00Z\tno\t./merges/stale.md\t./merges/stale.json\t./merges/stale-health.json\t./merges/stale-pack.md\n",
            encoding="utf-8",
        )

        result = mcp.latest_complete_bundles()

        self.assertEqual(result["authority"], "merged_legacy_live_discovery")
        self.assertEqual(result["stale_legacy_row_count"], 1)
        self.assertEqual(result["live_discovery_row_count"], 2)
        self.assertEqual([row[0] for row in result["rows"]], ["valid-repo", "live-repo"])
        self.assertNotIn("stale-repo", [row[0] for row in result["rows"]])
        self.assertIn("bundle_freshness_against_live_repo", result["does_not_establish"])

    def test_latest_complete_bundles_uses_valid_cache_without_live_discovery(self) -> None:
        self._write_bundle("valid-repo-max-260701-1200")
        (self.state / "rlens-latest-complete-bundles.tsv").write_text(
            "repo\tstem\tlatest_mtime\thas_agent_reading_pack\tcanonical_md\tbundle_manifest\toutput_health\tagent_reading_pack\n"
            "valid-repo\tvalid-repo-max-260701-1200\t2026-07-01T00:00:00Z\tno\t./merges/valid-repo-max-260701-1200_merge.md\t./merges/valid-repo-max-260701-1200_merge.bundle.manifest.json\t./merges/valid-repo-max-260701-1200_merge.output_health.json\t./merges/valid-repo-max-260701-1200_merge.agent_reading_pack.md\n",
            encoding="utf-8",
        )

        with patch.object(mcp, "_rlens_latest_manifest_by_repo", side_effect=AssertionError("unexpected discovery")):
            result = mcp.latest_complete_bundles()

        self.assertEqual(result["authority"], "legacy_cache")
        self.assertEqual(result["stale_legacy_row_count"], 0)
        self.assertEqual(result["live_discovery_row_count"], 0)
        self.assertEqual(result["rows"][1][0], "valid-repo")

    def test_registry_header_status_requires_full_header_shape(self) -> None:
        self.assertTrue(mcp._rlens_registry_row_status(list(mcp.BUNDLE_REGISTRY_HEADER))["is_header"])
        malformed = ["repo", "wrong", *list(mcp.BUNDLE_REGISTRY_HEADER[2:])]
        status = mcp._rlens_registry_row_status(malformed)
        self.assertFalse(status["is_header"])
        self.assertFalse(status["valid"])
        extended_header = [*list(mcp.BUNDLE_REGISTRY_HEADER), "extra"]
        status = mcp._rlens_registry_row_status(extended_header)
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

        result = mcp.rlens_bundle_status(stem)

        self.assertEqual(result["output_health"]["verdict"], "warn")
        self.assertEqual(result["output_health"]["range_ref_resolution_status"], "environment_error")
        self.assertFalse(result["output_health"]["dependencies"]["jsonschema"]["available"])
        self.assertEqual(result["output_health"]["dependencies"]["jsonschema"]["effect"], "validation_degraded")
        self.assertEqual(
            result["output_health"]["range_ref_resolution"]["validation"]["reason"],
            "dependency_unavailable",
        )

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

    def test_freshness_check_does_not_compare_generator_commit_to_live_head(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle(
            "demo-repo-max-260701-1200",
            commit=head,
            include_snapshot_provenance=False,
            generator_commit="b" * 40,
        )

        result = mcp.rlens_freshness_check("demo-repo", "demo-repo-max-260701-1200")

        self.assertEqual(result["freshness"], "unknown")
        self.assertEqual(result["reason"], "bundle_source_commit_unavailable")
        self.assertIsNone(result["bundle"]["git_commit"])
        self.assertEqual(
            result["bundle"]["source_provenance"]["reason"],
            "snapshot_provenance_absent",
        )
        self.assertEqual(result["bundle"]["generator_runtime"]["git_commit"], "b" * 40)

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


    def test_context_pack_reports_missing_bundle(self) -> None:
        result = mcp.rlens_context_pack("missing-repo", "basic_repo_question")
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "no_bundle_available")


    def test_query_existing_index_normalizes_nested_query_result_shape(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        lenskit_result = {
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

        with patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=lenskit_result):
            result = mcp.rlens_query_existing_index("demo-repo", "hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["normalized_query_shape"], "query_result.results")
        self.assertEqual(result["hit_count"], 1)
        self.assertEqual(result["snippets"][0]["text_excerpt"], "hello world from bounded evidence")
        self.assertEqual(result["ranges"][0]["artifact_role"], "canonical_md")
        self.assertIn("runtime_correctness", result["does_not_establish"])

    def test_query_existing_index_accepts_top_level_results_shape(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        lenskit_result = {
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

        with patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=lenskit_result):
            result = mcp.rlens_query_existing_index("demo-repo", "shape", k=1)

        self.assertEqual(result["normalized_query_shape"], "top_level_results")
        self.assertEqual(result["snippets"][0]["text_excerpt"], "top level shape")
        self.assertEqual(result["ranges"][0]["start_byte"], 20)

    def test_range_get_wraps_lenskit_result(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = {
            "artifact_role": "canonical_md",
            "file_path": "demo-repo.md",
            "start_byte": 0,
            "end_byte": 5,
        }
        lenskit_result = {
            "status": "available",
            "available": True,
            "range": {"text": "hello", "lines": [1, 1]},
        }

        with patch.object(mcp, "_rlens_lenskit_range_get", return_value=lenskit_result):
            result = mcp.rlens_range_get("demo-repo", range_ref)

        self.assertTrue(result["available"])
        self.assertEqual(result["kind"], "grabowski.rlens_range_get")
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

        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight):
            result = mcp.rlens_context_pack("demo-repo", "basic_repo_question")

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["manifest_sha256"], manifest_sha)
        self.assertEqual(result["access_wrappers"]["preflight"], "rlens_preflight")
        self.assertEqual(result["access_wrappers"]["query"], "rlens_query_existing_index")
        self.assertEqual(result["access_wrappers"]["range"], "rlens_range_get")
        self.assertEqual(result["bounded_evidence"]["normalized_query_shape"], "query_not_requested")
        self.assertEqual(result["bounded_evidence"]["snippets"], [])
        self.assertEqual(result["bounded_evidence"]["ranges"], [])
        self.assertEqual(
            result["preflight"]["answer_compliance_template"]["task_profile"],
            "basic_repo_question",
        )



class RlensContextBridgeToolTests(unittest.TestCase):
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
                {"role": "sqlite_index"},
                {"role": "citation_map_jsonl"},
            ],
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(json.dumps({
            "status": "pass",
            "evidence_level": "range_strict",
            "range_ref_resolution_status": "ok",
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.output_health.json").write_text(json.dumps({
            "verdict": "pass",
            "checks": {"range_ref_resolution_status": "ok"},
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

    def test_query_wrapper_normalizes_nested_lenskit_query_result(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = self._range_ref()
        payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "query_result": {
                "count": 1,
                "results": [{
                    "chunk_id": "c1",
                    "path": "README.md",
                    "content": "hello from nested result",
                    "range_ref": range_ref,
                }],
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }

        with patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=payload):
            result = mcp.rlens_query("demo-repo", "hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["query_shape"], "query_result.results")
        self.assertEqual(result["hit_count"], 1)
        self.assertEqual(result["snippets"][0]["text_excerpt"], "hello from nested result")
        self.assertEqual(result["ranges"][0], range_ref)
        self.assertFalse(result["raw_results_included"])

    def test_context_pack_includes_snippets_ranges_and_compliance_template(self) -> None:
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
                "items": [{
                    "ordinal": 0,
                    "path": "README.md",
                    "chunk_id": "c1",
                    "text_excerpt": "bounded citation text",
                    "range_status": "resolved",
                    "citation_status": "resolved",
                    "citation_id": "cit_0123456789abcdef",
                    "source_range": range_ref,
                }]
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }

        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight), \
             patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=query_payload):
            result = mcp.rlens_context_pack("demo-repo", query="hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["context_ref"]["manifest_sha256"], manifest_sha)
        self.assertEqual(result["context_ref"]["snippet_count"], 1)
        self.assertEqual(result["context_ref"]["range_count"], 1)
        self.assertEqual(result["preflight"]["answer_compliance_template"]["task_profile"], "basic_repo_question")
        self.assertEqual(result["snippets"][0]["text_excerpt"], "bounded citation text")
        self.assertEqual(result["ranges"][0], range_ref)
        self.assertIn("actual_agent_reading", result["does_not_establish"])


    def test_query_existing_index_honors_evidence_and_projection_flags(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        captured = {}

        def fake_query(_manifest, _query, *, k, filters, resolve_evidence, project_sources):
            captured.update({
                "k": k,
                "filters": filters,
                "resolve_evidence": resolve_evidence,
                "project_sources": project_sources,
            })
            return {"status": "available", "query_result": {"results": []}}

        with patch.object(mcp, "_rlens_lenskit_query_existing_index", side_effect=fake_query):
            result = mcp.rlens_query_existing_index(
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

    def test_range_wrapper_returns_bounded_lenskit_range(self) -> None:
        _repo, head = self._git_repo("demo-repo")
        self._write_bundle("demo-repo-max-260701-1200", commit=head)
        range_ref = self._range_ref()
        payload = {
            "kind": "repobrief.range_get",
            "status": "available",
            "range": {"text": "hello", "lines": [1, 1]},
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
        }

        with patch.object(mcp, "_rlens_lenskit_range_get", return_value=payload):
            result = mcp.rlens_range_get("demo-repo", range_ref)

        self.assertTrue(result["available"])
        self.assertEqual(result["range"]["text"], "hello")
        self.assertEqual(result["mutation_boundary"]["writes"], [])


class RlensContextPackResolvedEvidenceTests(unittest.TestCase):
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

    def _write_bundle_and_repo(self, name: str = "demo-repo") -> tuple[Path, str]:
        repo = self.home / "repos" / name
        repo.mkdir(parents=True)
        subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Grabowski Test"], cwd=repo, check=True)
        (repo / "README.md").write_text("demo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        stem = f"{name}-max-260701-1200"
        manifest = self.merges / f"{stem}_merge.bundle.manifest.json"
        manifest.write_text(json.dumps({
            "kind": "repolens.bundle.manifest",
            "run_id": f"{stem}-run",
            "created_at": "2026-07-01T00:00:00Z",
            "generator": {"runtime": {"git_commit": head, "git_dirty": False}},
            "artifacts": [
                {"role": "canonical_md"},
                {"role": "sqlite_index"},
                {"role": "citation_map_jsonl"},
            ],
        }), encoding="utf-8")
        (self.merges / f"{stem}_merge.bundle_health.post.json").write_text(json.dumps({"status": "pass"}), encoding="utf-8")
        (self.merges / f"{stem}_merge.output_health.json").write_text(json.dumps({"verdict": "pass"}), encoding="utf-8")
        return manifest, head

    def test_context_pack_consumes_resolved_evidence_hits_with_citation_and_live_address(self) -> None:
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
                "hits": [{
                    "chunk_id": "c1",
                    "source_path": "src/app.py",
                    "text_excerpt": "resolved evidence text",
                    "source_range": {"file_path": "src/app.py", "start_line": 4, "end_line": 5},
                    "line_range": {"start_line": 4, "end_line": 5, "display": "4-5"},
                    "citation_id": "cit_0123456789abcdef",
                    "citation_status": "resolved",
                    "citation_verified": True,
                    "canonical_authority": {"authority": "canonical_brief_source"},
                    "live_repo_address": {"status": "available", "path": "src/app.py", "git_commit": "a" * 40},
                    "live_repo_address_status": "available",
                }]
            },
            "mutation_boundary": {"writes": [], "read_paths_do_not_refresh": True},
            "evidence_resolution_used": True,
        }
        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight), \
             patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=payload):
            result = mcp.rlens_context_pack("demo-repo", query="hello", k=1)

        self.assertTrue(result["available"])
        self.assertEqual(result["bounded_evidence"]["normalized_query_shape"], "resolved_evidence.hits")
        self.assertEqual(result["bounded_evidence"]["resolved_evidence_status"], "available")
        self.assertEqual(result["bounded_evidence"]["citation_ids"], ["cit_0123456789abcdef"])
        self.assertEqual(result["context_ref"]["citation_count"], 1)
        snippet = result["snippets"][0]
        self.assertEqual(snippet["text_excerpt"], "resolved evidence text")
        self.assertEqual(snippet["source_range"]["file_path"], "src/app.py")
        self.assertEqual(snippet["live_repo_address_status"], "available")
        self.assertEqual(snippet["canonical_authority"]["authority"], "canonical_brief_source")

    def test_context_pack_degrades_when_resolved_evidence_unavailable(self) -> None:
        self._write_bundle_and_repo()
        preflight = {"status": "warn", "available": True, "answer_compliance_template": {"task_profile": "basic_repo_question"}}
        payload = {
            "kind": "repobrief.query_existing_index",
            "status": "available",
            "query_result": {"count": 0, "results": []},
            "evidence_resolution_used": False,
        }
        with patch.object(mcp, "_rlens_agent_preflight", return_value=preflight), \
             patch.object(mcp, "_rlens_lenskit_query_existing_index", return_value=payload):
            result = mcp.rlens_context_pack("demo-repo", query="missing", k=1)

        self.assertEqual(result["bounded_evidence"]["resolved_evidence_status"], "degraded")
        self.assertEqual(
            result["bounded_evidence"]["degradation_reason"],
            "resolved_evidence_missing_snippets_ranges_or_citations",
        )
        self.assertEqual(result["bounded_evidence"]["snippets"], [])
        self.assertEqual(result["bounded_evidence"]["ranges"], [])
        self.assertEqual(result["context_ref"]["resolved_evidence_status"], "degraded")


if __name__ == "__main__":
    unittest.main()
