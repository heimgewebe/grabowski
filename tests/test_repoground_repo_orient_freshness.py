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
