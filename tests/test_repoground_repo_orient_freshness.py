from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import types
from unittest.mock import patch

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
import grabowski_repobrief as repobrief


TARGET = "a" * 40
OTHER = "b" * 40


def _orientation(*, dirty: bool = False) -> dict[str, object]:
    return {
        "repo": "/tmp/repo",
        "root": "/tmp/repo",
        "branch": "main",
        "head": TARGET,
        "dirty": dirty,
        "status_header": "## main...origin/main",
        "status_entries": [" M tracked.py"] if dirty else [],
        "upstream": "origin/main",
        "upstream_source": "resolved-ref",
        "upstream_ref_materialized": True,
        "upstream_remote": None,
        "upstream_merge_ref": None,
        "expected_branch_match": None,
    }


def _context(
    *,
    snapshot_commit: str = TARGET,
    snapshot_dirty: object = False,
    freshness_status: str = "fresh",
    available: bool = True,
    status: str = "available",
) -> dict[str, object]:
    return {
        "available": available,
        "status": status,
        "repository": "grabowski",
        "ref": "main",
        "snapshot_commit": snapshot_commit,
        "snapshot_dirty": snapshot_dirty,
        "current_head_matches_snapshot": snapshot_commit == TARGET,
        "freshness_status": freshness_status,
        "manifest_path": "/published/manifest.json",
        "bundle_manifest_path": "/published/bundle.json",
        "agent_reading_pack_path": "/published/agent.md",
        "canonical_md_path": "/published/canonical.md",
    }


def test_repo_orient_admits_exact_clean_context() -> None:
    result = grips._repo_orient_admit_repoground_context(
        _orientation(),
        _context(),
    )

    assert result["available"] is True
    assert result["admission"] == "exact"
    assert result["target_revision"] == TARGET
    assert result["context_revision"] == TARGET
    assert result["canonical_md_path"] == "/published/canonical.md"


def test_repo_orient_withholds_dirty_or_unproven_snapshot() -> None:
    dirty = grips._repo_orient_admit_repoground_context(
        _orientation(),
        _context(snapshot_dirty=True),
    )
    unknown = grips._repo_orient_admit_repoground_context(
        _orientation(),
        _context(snapshot_dirty=None),
    )

    assert dirty["available"] is False
    assert dirty["status"] == "dirty_overlay"
    assert dirty["reason"] == "repoground_snapshot_is_dirty"
    assert dirty["snapshot_dirty"] is True
    assert unknown["available"] is False
    assert unknown["status"] == "unknown"
    assert unknown["reason"] == "repoground_snapshot_cleanliness_unproven"
    assert unknown["snapshot_dirty"] is None


def test_repo_orient_admits_exact_clean_sha256_context() -> None:
    target = "c" * 64
    result = grips._repo_orient_admit_repoground_context(
        {**_orientation(), "head": target},
        _context(snapshot_commit=target),
    )

    assert result["available"] is True
    assert result["admission"] == "exact"
    assert result["target_revision"] == target
    assert result["context_revision"] == target


def test_repobrief_context_selects_target_repository_provenance() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {"repo": "other", "git_commit": TARGET},
                {
                    "name": "heimgewebe__grabowski__main",
                    "git_commit": OTHER,
                },
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        {**_orientation(), "head": OTHER},
    )

    assert result["snapshot_commit"] == OTHER
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_matches_repo_name_containing_double_underscores() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {
                    "name": f"owner__foo__bar__main--{TARGET}",
                    "git_commit": TARGET,
                    "git_dirty": False,
                }
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/foo__bar.bundle.manifest.json"),
        "foo__bar",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] == TARGET
    assert result["snapshot_dirty"] is False
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_preserves_internal_revision_separators() -> None:
    repo = "foo--bar"
    ref = "release--candidate"
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {
                    "name": f"owner__{repo}__{ref}--{TARGET}",
                    "git_commit": TARGET,
                    "git_dirty": False,
                }
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path(f"/tmp/published/{repo}.bundle.manifest.json"),
        repo,
        ref,
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] == TARGET
    assert result["snapshot_dirty"] is False
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_matches_catalog_recovery_revision_name() -> None:
    recovery = "c0ffee123456"
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {
                    "name": f"owner__grabowski__main--{TARGET}--recovery-{recovery}",
                    "git_commit": TARGET,
                    "git_dirty": False,
                }
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] == TARGET
    assert result["snapshot_dirty"] is False
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_normalizes_commit_alias() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {
                    "repo": "grabowski",
                    "commit": TARGET.upper(),
                    "git_dirty": False,
                }
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] == TARGET
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_accepts_head_alias() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {
                    "repository": "heimgewebe/grabowski",
                    "head": TARGET,
                    "git_dirty": False,
                }
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] == TARGET
    assert result["freshness_status"] == "fresh"


def test_repobrief_context_refuses_unmatched_repository_provenance() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [{"repo": "other", "git_commit": TARGET}]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] is None
    assert result["freshness_status"] == "provenance_missing"


def test_repobrief_context_refuses_ambiguous_target_repository_provenance() -> None:
    manifest = {
        "snapshotProvenance": {
            "repositories": [
                {"repo": "grabowski", "git_commit": TARGET},
                {"repository": "heimgewebe/grabowski", "git_commit": OTHER},
            ]
        }
    }
    result = repobrief._process_manifest_candidate(
        manifest,
        Path("/tmp/published/grabowski.bundle.manifest.json"),
        "grabowski",
        "main",
        "canonical_publication",
        Path("/tmp/published"),
        _orientation(),
    )

    assert result["snapshot_commit"] is None
    assert result["freshness_status"] == "provenance_missing"


def test_repo_orient_withholds_stale_context_and_paths() -> None:
    result = grips._repo_orient_admit_repoground_context(
        _orientation(),
        _context(snapshot_commit=OTHER, freshness_status="stale"),
    )

    assert result["available"] is False
    assert result["status"] == "stale"
    assert result["admission"] == "withheld"
    assert result["target_revision"] == TARGET
    assert result["snapshot_commit"] == OTHER
    assert result["fallback"]["targeted_build_recommended"] is True
    assert result["fallback"]["live_fallback_allowed"] is True
    for forbidden in (
        "manifest_path",
        "bundle_manifest_path",
        "agent_reading_pack_path",
        "canonical_md_path",
    ):
        assert forbidden not in result


def test_repo_orient_withholds_exact_base_for_dirty_worktree() -> None:
    result = grips._repo_orient_admit_repoground_context(
        _orientation(dirty=True),
        _context(),
    )

    assert result["available"] is False
    assert result["status"] == "dirty_unbound"
    assert result["reason"] == "dirty_worktree_is_not_bound_to_repoground_snapshot"
    assert result["fallback"] == {
        "mode": "live_fallback",
        "targeted_build_recommended": False,
        "live_fallback_allowed": True,
        "live_fallback_required": True,
    }


def test_repo_orient_preserves_excluded_as_skip_with_live_fallback() -> None:
    result = grips._repo_orient_admit_repoground_context(
        _orientation(),
        {
            "available": False,
            "status": "excluded",
            "freshness_status": "publication_unavailable",
            "reason": "repository is intentionally excluded from RepoGround fleet publication",
            "repository": "grabowski",
            "ref": "main",
            "canonical_md_path": "/must/not/leak.md",
        },
    )

    assert result["available"] is False
    assert result["status"] == "excluded"
    assert result["admission"] == "withheld"
    assert result["fallback"] == {
        "mode": "live_fallback",
        "targeted_build_recommended": False,
        "live_fallback_allowed": True,
        "live_fallback_required": True,
    }
    assert "canonical_md_path" not in result


def test_repo_orient_marks_missing_publication_unavailable() -> None:
    result = grips._repo_orient_admit_repoground_context(
        _orientation(),
        {
            "available": False,
            "status": "missing",
            "freshness_status": "publication_unavailable",
            "reason": "no published bundle",
            "repository": "grabowski",
            "ref": "main",
        },
    )

    assert result["available"] is False
    assert result["status"] == "unavailable"
    assert result["target_revision"] == TARGET
    assert result["fallback"]["mode"] == "targeted_build_or_live_fallback"
    assert result["fallback"]["targeted_build_recommended"] is True


def test_repo_orient_grip_passes_but_withholds_stale_repoground_context() -> None:
    stale = _context(snapshot_commit=OTHER, freshness_status="stale")
    with tempfile.TemporaryDirectory() as tmp, patch.object(
        grips,
        "_orient",
        return_value={**_orientation(), "repo": tmp, "root": tmp},
    ), patch.object(
        grips.grabowski_repobrief,
        "context",
        return_value=stale,
    ):
        result = grips.run_grip(
            "repo-orient",
            {"repo": tmp},
            command_runner=lambda _repo, _argv: {
                "returncode": 1,
                "stdout": "",
                "stderr": "unexpected command",
            },
        )

    assert result["receipt"]["status"] == "passed"
    context = result["output"]["repobrief_context"]
    assert context["available"] is False
    assert context["status"] == "stale"
    assert "canonical_md_path" not in context
    checks = {
        check["id"]: check["status"]
        for check in result["receipt"]["checks"]
    }
    assert checks["repobrief_context"] == "warn"
