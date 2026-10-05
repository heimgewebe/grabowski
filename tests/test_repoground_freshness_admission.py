from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        del args, kwargs
        self.tools = {}

    def tool(self, *args, **kwargs):
        del args

        def decorator(func):
            self.tools[kwargs.get("name", func.__name__)] = func
            return func

        return decorator

    def run(self, *args, **kwargs):
        del args, kwargs
        return None


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


if "mcp" not in sys.modules:
    mcp_pkg = types.ModuleType("mcp")
    mcp_server_pkg = types.ModuleType("mcp.server")
    mcp_fastmcp_pkg = types.ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_pkg.FastMCP = _FakeFastMCP
    mcp_types_pkg = types.ModuleType("mcp.types")
    mcp_types_pkg.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = mcp_pkg
    sys.modules["mcp.server"] = mcp_server_pkg
    sys.modules["mcp.server.fastmcp"] = mcp_fastmcp_pkg
    sys.modules["mcp.types"] = mcp_types_pkg

import grabowski_mcp as mcp


TARGET = "a" * 40
OTHER = "b" * 40


def _freshness(
    status: str,
    identity: str,
    *,
    reason: str = "synthetic",
) -> dict[str, object]:
    return {
        "kind": "grabowski.repoground_freshness_check",
        "schema_version": 3,
        "repo": "heimgewebe/demo",
        "stem": "demo-stem",
        "freshness_status": status,
        "freshness": identity,
        "reason": reason,
    }


def test_conventional_checkout_freshness_requires_fresh_remote_main() -> None:
    status = {"stem": "demo-stem", "repo": "heimgewebe/demo", "git_commit": TARGET, "git_dirty": False}
    git_results = {
        ("rev-parse", "HEAD"): (0, TARGET, ""),
        ("status", "--porcelain"): (0, "", ""),
        ("ls-remote", "--exit-code", "--refs", "--", "origin", "refs/heads/main"): (0, f"{TARGET}\trefs/heads/main\n", ""),
    }
    def fake_git(_repo_path: Path, args: list[str]) -> tuple[int, str, str]:
        return git_results[tuple(args)]
    with (
        patch.object(mcp, "_repoground_freshness_source", return_value=(Path("/tmp/repo"), "conventional_checkout", None)),
        patch.object(Path, "is_dir", return_value=True),
        patch.object(Path, "is_symlink", return_value=False),
        patch.object(mcp, "_repoground_git", side_effect=fake_git),
    ):
        result = mcp._repoground_freshness_from_status("heimgewebe/demo", status)
    assert result["freshness"] == "fresh_exact"
    assert result["live_repo"]["head"] == TARGET
    assert result["live_repo"]["comparison_ref"] == "origin/main"
    assert result["live_repo"]["branch_head_observation"]["head"] == TARGET


def test_conventional_checkout_remote_drift_is_stale() -> None:
    status = {"stem": "demo-stem", "repo": "heimgewebe/demo", "git_commit": TARGET, "git_dirty": False}
    git_results = {
        ("rev-parse", "HEAD"): (0, TARGET, ""),
        ("status", "--porcelain"): (0, "", ""),
        ("ls-remote", "--exit-code", "--refs", "--", "origin", "refs/heads/main"): (0, f"{OTHER}\trefs/heads/main\n", ""),
    }
    def fake_git(_repo_path: Path, args: list[str]) -> tuple[int, str, str]:
        return git_results[tuple(args)]
    with (
        patch.object(mcp, "_repoground_freshness_source", return_value=(Path("/tmp/repo"), "conventional_checkout", None)),
        patch.object(Path, "is_dir", return_value=True),
        patch.object(Path, "is_symlink", return_value=False),
        patch.object(mcp, "_repoground_git", side_effect=fake_git),
    ):
        result = mcp._repoground_freshness_from_status("heimgewebe/demo", status)
    assert result["freshness"] == "stale_head"
    assert result["live_repo"]["checkout_head"] == TARGET
    assert result["live_repo"]["head"] == OTHER
    assert result["live_repo"]["branch_head_observation"]["head"] == OTHER


def test_agent_freshness_admission_accepts_only_exact() -> None:
    exact = _freshness("fresh", "fresh_exact")
    exact["bundle"] = {"git_dirty": False}
    assert (
        mcp._repoground_agent_freshness_admission_error(
            "heimgewebe/demo",
            "demo-stem",
            exact,
        )
        is None
    )

    unknown_cleanliness = _freshness("fresh", "fresh_exact")
    refused_unknown = mcp._repoground_agent_freshness_admission_error(
        "heimgewebe/demo",
        "demo-stem",
        unknown_cleanliness,
    )
    assert refused_unknown is not None
    assert refused_unknown["reason"] == "freshness_unverified"

    nonexact = [
        (_freshness("stale", "stale_head"), "stale_context_refused"),
        (
            _freshness("dirty_overlay", "fresh_dirty_unverified"),
            "dirty_context_refused",
        ),
        (
            _freshness("source_unavailable", "unknown"),
            "freshness_unverified",
        ),
        (
            _freshness("fresh", "unknown"),
            "freshness_unverified",
        ),
    ]
    for freshness, expected_reason in nonexact:
        result = mcp._repoground_agent_freshness_admission_error(
            "heimgewebe/demo",
            "demo-stem",
            freshness,
        )
        assert result is not None
        assert result["available"] is False
        assert result["reason"] == expected_reason
        assert result["route"] == "targeted_build_or_live_fallback"
        assert result["mutation_boundary"] == {
            "writes": [],
            "read_paths_do_not_refresh": True,
        }


def test_manifest_snapshot_provenance_accepts_sha256_git_object_id() -> None:
    commit = "a" * 64
    result = mcp._repoground_manifest_snapshot_provenance(
        {
            "snapshotProvenance": {
                "repositories": [
                    {
                        "repo": "heimgewebe/demo",
                        "git_commit": commit,
                        "git_dirty": False,
                    }
                ]
            }
        },
        "heimgewebe/demo",
    )

    assert result["available"] is True
    assert result["git_commit"] == commit
    assert result["git_dirty"] is False


def test_manifest_snapshot_provenance_rejects_invalid_git_object_id_lengths() -> None:
    for length in (39, 41, 63, 65):
        result = mcp._repoground_manifest_snapshot_provenance(
            {
                "snapshotProvenance": {
                    "repositories": [
                        {
                            "repo": "heimgewebe/demo",
                            "git_commit": "a" * length,
                            "git_dirty": False,
                        }
                    ]
                }
            },
            "heimgewebe/demo",
        )
        assert result["available"] is False
        assert result["reason"] == "snapshot_repository_commit_absent"


def test_repoground_commit_and_manifest_parsers_accept_sha256_ids() -> None:
    target = "c" * 64
    with patch.object(mcp, "_repoground_git", return_value=(0, target, "")):
        assert mcp._repoground_resolve_commit(Path("/tmp/repo"), "HEAD") == target

    provenance = mcp._repoground_manifest_snapshot_provenance(
        {
            "snapshot_provenance": {
                "repositories": [
                    {
                        "repo": "heimgewebe/demo",
                        "git_commit": target,
                        "git_dirty": False,
                    }
                ]
            }
        },
        "heimgewebe/demo",
    )
    assert provenance["available"] is True
    assert provenance["git_commit"] == target
    assert provenance["git_dirty"] is False


def test_explicit_expected_commit_allows_only_that_exact_bundle_commit() -> None:
    bound = _freshness("stale", "stale_head")
    bound["bundle"] = {
        "git_commit": TARGET,
        "git_dirty": False,
    }

    assert (
        mcp._repoground_agent_freshness_admission_error(
            "heimgewebe/demo",
            "demo-stem",
            bound,
            expected_commits=TARGET,
        )
        is None
    )

    refused = mcp._repoground_agent_freshness_admission_error(
        "heimgewebe/demo",
        "demo-stem",
        bound,
        expected_commits=OTHER,
    )
    assert refused is not None
    assert refused["available"] is False
    assert refused["expected_commits"] == [OTHER]
    assert refused["bundle_commit"] == TARGET


def test_selected_manifest_refuses_stale_pinned_publication() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "bundle.manifest.json"
        pinned = mcp._RepoGroundPinnedPublication(
            manifest_path=manifest,
            manifest_sha256="a" * 64,
            stem="demo-stem",
            publication_run_id="run-a",
        )
        status = {
            "stem": "demo-stem",
            "manifest_sha256": "a" * 64,
            "publication_run_id": "run-a",
        }
        stale = _freshness(
            "stale",
            "stale_head",
            reason="bundle_commit_differs_from_live_head",
        )
        with (
            patch.object(mcp, "_repoground_manifest_summary", return_value=status),
            patch.object(mcp, "_repoground_freshness_from_status", return_value=stale),
        ):
            freshness, stem, selected_path, error = (
                mcp._repoground_selected_manifest_for_repo(
                    "heimgewebe/demo",
                    pinned,
                )
            )

    assert freshness == stale
    assert stem == "demo-stem"
    assert selected_path is None
    assert error is not None
    assert error["reason"] == "stale_context_refused"
    assert error["freshness_reason"] == "bundle_commit_differs_from_live_head"


def test_selected_manifest_keeps_exact_pinned_publication_available() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "bundle.manifest.json"
        pinned = mcp._RepoGroundPinnedPublication(
            manifest_path=manifest,
            manifest_sha256="a" * 64,
            stem="demo-stem",
            publication_run_id="run-a",
        )
        status = {
            "stem": "demo-stem",
            "manifest_sha256": "a" * 64,
            "publication_run_id": "run-a",
        }
        exact = _freshness("fresh", "fresh_exact")
        exact["bundle"] = {"git_dirty": False}
        with (
            patch.object(mcp, "_repoground_manifest_summary", return_value=status),
            patch.object(mcp, "_repoground_freshness_from_status", return_value=exact),
        ):
            freshness, stem, selected_path, error = (
                mcp._repoground_selected_manifest_for_repo(
                    "heimgewebe/demo",
                    pinned,
                )
            )

    assert freshness == exact
    assert stem == "demo-stem"
    assert selected_path == manifest
    assert error is None


def test_query_stale_selection_emits_no_evidence_or_retrieval() -> None:
    stale = _freshness("stale", "stale_head")
    error = mcp._repoground_agent_freshness_admission_error(
        "heimgewebe/demo",
        "demo-stem",
        stale,
    )
    assert error is not None

    with (
        patch.object(mcp, "_require_capability", return_value=None),
        patch.object(
            mcp,
            "_repoground_selected_manifest_for_repo",
            return_value=(stale, "demo-stem", None, error),
        ),
        patch.object(mcp, "_repoground_agent_query") as retrieval,
        patch.object(mcp, "_repoground_query_existing_index") as indexed_retrieval,
    ):
        result = mcp.repoground_query("heimgewebe/demo", "target")

    assert result["available"] is False
    assert result["reason"] == "stale_context_refused"
    assert result["snippets"] == []
    assert result["ranges"] == []
    assert result["hit_count"] == 0
    retrieval.assert_not_called()
    indexed_retrieval.assert_not_called()


def test_context_pack_stale_selection_emits_no_context_or_preflight() -> None:
    stale = _freshness("stale", "stale_head")
    error = mcp._repoground_agent_freshness_admission_error(
        "heimgewebe/demo",
        "demo-stem",
        stale,
    )
    assert error is not None

    with (
        patch.object(mcp, "_require_capability", return_value=None),
        patch.object(
            mcp,
            "_repoground_selected_manifest_for_repo",
            return_value=(stale, "demo-stem", None, error),
        ),
        patch.object(mcp, "_repoground_agent_preflight") as preflight,
        patch.object(mcp, "repoground_query") as query,
    ):
        result = mcp.repoground_context_pack(
            "heimgewebe/demo",
            query="target",
        )

    assert result["available"] is False
    assert result["reason"] == "stale_context_refused"
    assert result["bounded_evidence"]["snippets"] == []
    assert result["bounded_evidence"]["ranges"] == []
    assert "context_ref" not in result
    preflight.assert_not_called()
    query.assert_not_called()
