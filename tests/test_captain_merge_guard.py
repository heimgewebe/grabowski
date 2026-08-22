from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

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

import grabowski_merge_guard as merge_guard  # noqa: E402
import grabowski_resources as resources  # noqa: E402


class _PagedFilesGh:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        return {"returncode": 0, "stdout": self.stdout, "stderr": ""}


class _LargePrGh:
    def __init__(
        self,
        *,
        base_sha: str,
        head_sha: str,
        paths: list[str],
    ) -> None:
        self.base_sha = base_sha
        self.head_sha = head_sha
        self.paths = paths
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv[:2] == ["pr", "view"]:
            payload = {
                "number": 212,
                "state": "OPEN",
                "headRefName": "feature/large-release",
                "headRefOid": self.head_sha,
                "baseRefName": "main",
                "baseRefOid": self.base_sha,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
                "changedFiles": len(self.paths),
                "files": [
                    {"path": path, "changeType": "ADDED"} for path in self.paths[:100]
                ],
            }
            return {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""}
        if argv[:2] == ["api", "--paginate"]:
            lines = [json.dumps([path, "added", None]) for path in self.paths]
            return {"returncode": 0, "stdout": "\n".join(lines) + "\n", "stderr": ""}
        if argv[:2] == ["pr", "diff"]:
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": "HTTP 406: diff exceeded the maximum number of files (300) (PullRequest.diff too_large)",
            }
        raise AssertionError(f"unexpected GitHub call: {argv!r}")


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _large_git_repo(
    file_count: int = 301,
) -> tuple[tempfile.TemporaryDirectory[str], Path, str, str, list[str]]:
    temporary = tempfile.TemporaryDirectory()
    repo = Path(temporary.name)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "captain-test@example.invalid")
    _git(repo, "config", "user.name", "Captain Test")
    (repo / "seed.txt").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "seed.txt")
    _git(repo, "commit", "-q", "-m", "base")
    base_sha = _git(repo, "rev-parse", "HEAD")
    paths = [f"release/generated-{index:04d}.txt" for index in range(file_count)]
    (repo / "release").mkdir()
    for index, path in enumerate(paths):
        (repo / path).write_text(f"generated {index}\n", encoding="utf-8")
    _git(repo, "add", "release")
    _git(repo, "commit", "-q", "-m", "large release")
    head_sha = _git(repo, "rev-parse", "HEAD")
    return temporary, repo, base_sha, head_sha, paths


class CaptainLargePrMergeGuardTests(unittest.TestCase):
    def test_github_diff_too_large_is_narrowly_detected(self) -> None:
        info = {
            "returncode": 1,
            "stdout": "",
            "stderr": "HTTP 406: diff exceeded the maximum number of files (300) (PullRequest.diff too_large)",
        }
        self.assertTrue(
            merge_guard._merge_guard_github_diff_too_large(info, changed_files=301)
        )
        self.assertFalse(
            merge_guard._merge_guard_github_diff_too_large(info, changed_files=300)
        )
        self.assertFalse(
            merge_guard._merge_guard_github_diff_too_large(
                {"returncode": 1, "stdout": "", "stderr": "HTTP 503"},
                changed_files=301,
            )
        )

    def test_paged_file_projection_maps_only_supported_metadata(self) -> None:
        gh = _PagedFilesGh(
            "\n".join(
                [
                    json.dumps(["a.txt", "modified", None]),
                    json.dumps(["b.txt", "added", None]),
                    json.dumps(["c.txt", "removed", None]),
                    json.dumps(["d.txt", "renamed", "old-d.txt"]),
                ]
            )
            + "\n"
        )
        records, receipt, errors = merge_guard._merge_guard_github_file_records(
            Path.cwd(), gh, repo_slug="heimgewebe/commonworld", pr_number=212
        )
        self.assertEqual(errors, [])
        self.assertEqual(receipt["record_count"], 4)
        self.assertEqual(
            [record["changeType"] for record in records],
            ["MODIFIED", "ADDED", "DELETED", "RENAMED"],
        )
        self.assertEqual(records[-1]["previousPath"], "old-d.txt")

    def test_missing_pr_object_fetches_bounded_refs_and_reprobes_exact_shas(self) -> None:
        base_sha = "a" * 40
        head_sha = "b" * 40
        results = [
            {"returncode": 0, "stdout_bytes": b"", "stderr_bytes": b""},
            {"returncode": 1, "stdout_bytes": b"", "stderr_bytes": b"missing"},
            {"returncode": 0, "stdout_bytes": b"", "stderr_bytes": b""},
            {"returncode": 0, "stdout_bytes": b"", "stderr_bytes": b""},
            {"returncode": 0, "stdout_bytes": b"", "stderr_bytes": b""},
        ]
        with mock.patch.object(
            merge_guard, "_merge_guard_local_git_bytes", side_effect=results
        ) as local_git:
            receipt, errors = merge_guard._merge_guard_ensure_pr_objects(
                Path("/repo"),
                base_branch="main",
                pr_number=212,
                base_sha=base_sha,
                head_sha=head_sha,
            )

        self.assertEqual(errors, [])
        self.assertTrue(receipt["fetch_attempted"])
        self.assertTrue(receipt["available"])
        self.assertEqual(
            receipt["fetch_refs"], ["refs/heads/main", "refs/pull/212/head"]
        )
        fetch_args = local_git.call_args_list[2].args[1]
        self.assertEqual(
            fetch_args,
            [
                "-c",
                "remote.origin.uploadpack=git-upload-pack",
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "protocol.file.allow=never",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                "--",
                "origin",
                "refs/heads/main",
                "refs/pull/212/head",
            ],
        )
        self.assertEqual(
            local_git.call_args_list[3].args[1],
            ["cat-file", "-e", f"{base_sha}^{{commit}}"],
        )
        self.assertEqual(
            local_git.call_args_list[4].args[1],
            ["cat-file", "-e", f"{head_sha}^{{commit}}"],
        )

    def test_binary_detection_is_anchored_to_diff_metadata(self) -> None:
        text_diff = (
            b"diff --git a/note.txt b/note.txt\n"
            b"--- a/note.txt\n+++ b/note.txt\n@@ -0,0 +1 @@\n"
            b"+Binary files alpha and beta differ\n"
        )
        binary_diff = (
            b"diff --git a/blob.bin b/blob.bin\n"
            b"Binary files a/blob.bin and b/blob.bin differ\n"
        )
        patch_binary_diff = b"diff --git a/blob.bin b/blob.bin\nGIT binary patch\n"
        self.assertFalse(merge_guard._merge_guard_diff_contains_binary_metadata(text_diff))
        self.assertTrue(merge_guard._merge_guard_diff_contains_binary_metadata(binary_diff))
        self.assertTrue(
            merge_guard._merge_guard_diff_contains_binary_metadata(patch_binary_diff)
        )

    def test_local_bound_diff_supports_large_text_release(self) -> None:
        temporary, repo, base_sha, head_sha, expected_paths = _large_git_repo()
        self.addCleanup(temporary.cleanup)
        _git(repo, "replace", head_sha, base_sha)
        paths, path_info, path_errors = merge_guard._merge_guard_local_changed_paths(
            repo, base_sha=base_sha, head_sha=head_sha
        )
        diff, diff_info, diff_errors = merge_guard._merge_guard_local_diff_bytes(
            repo, base_sha=base_sha, head_sha=head_sha
        )
        self.assertEqual(path_errors, [])
        self.assertEqual(diff_errors, [])
        self.assertEqual(paths, expected_paths)
        self.assertEqual(path_info["source"], "local-bound-git-name-only")
        self.assertGreater(len(diff), 0)
        self.assertEqual(
            diff_info["sha256"], merge_guard.github_pr_diff_identity_sha256(diff)
        )

    def test_live_bindings_falls_back_only_after_provider_too_large(self) -> None:
        temporary, repo, base_sha, head_sha, expected_paths = _large_git_repo()
        self.addCleanup(temporary.cleanup)
        diff, diff_info, diff_errors = merge_guard._merge_guard_local_diff_bytes(
            repo, base_sha=base_sha, head_sha=head_sha
        )
        self.assertEqual(diff_errors, [])
        self.assertTrue(diff)
        gh = _LargePrGh(base_sha=base_sha, head_sha=head_sha, paths=expected_paths)
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.action = {
            "target": {"repo": "heimgewebe/commonworld", "pr": 212, "base": "main"}
        }
        runner.parameters = {
            "expected_head": head_sha,
            "expected_base_sha": base_sha,
            "diff_sha256": diff_info["sha256"],
        }
        runner.static_errors = []
        runner.repo_path = repo
        runner.github_runner = gh
        runner.receipt = {}
        runner.execution_intent_sha256 = "1" * 64
        runner._revalidate_codex_review = lambda _bindings, phase: []

        bindings, errors = runner._live_bindings()

        self.assertEqual(errors, [])
        self.assertIsNotNone(bindings)
        assert bindings is not None
        self.assertEqual(bindings["changed_paths"], expected_paths)
        self.assertEqual(bindings["diff_sha256"], diff_info["sha256"])
        self.assertEqual(
            runner.receipt["live_diff"]["source"],
            "local-bound-git-diff-after-github-too-large",
        )
        self.assertEqual(
            runner.receipt["live_diff"]["provider_attempt"]["returncode"], 1
        )
        self.assertEqual(
            runner.receipt["live_files"]["record_count"], len(expected_paths)
        )

    def test_resource_normalization_supports_bounded_generated_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            paths = [str(root / f"generated-{index:04d}.txt") for index in range(1058)]
            normalized = resources._normalize_merge_guard_changed_paths(
                paths, repository=str(root)
            )
            self.assertEqual(len(normalized), 1058)
            too_many = [
                str(root / f"overflow-{index:04d}.txt")
                for index in range(resources._MERGE_GUARD_MAX_CHANGED_PATHS + 1)
            ]
            with self.assertRaisesRegex(ValueError, "entry limit"):
                resources._normalize_merge_guard_changed_paths(
                    too_many, repository=str(root)
                )

    def test_merge_guard_rejects_declared_changed_path_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as state:
            repo = Path(directory).resolve()
            paths = [str(repo / "one.txt"), str(repo / "two.txt")]
            resource_keys = merge_guard.merge_guard_resource_keys(
                repo,
                repo_slug="heimgewebe/commonworld",
                pr_number=212,
                base="main",
                head="feature/large-release",
            )
            metadata = {
                "merge_guard": {
                    "repository": "heimgewebe/commonworld",
                    "pull_request": 212,
                    "base_branch": "main",
                    "head_branch": "feature/large-release",
                    "changed_paths_sha256": "0" * 64,
                }
            }
            original_db = resources.RESOURCE_DB
            resources.RESOURCE_DB = Path(state) / "resources.sqlite3"
            try:
                with self.assertRaisesRegex(ValueError, "digest does not match"):
                    resources.acquire_merge_guard_resources(
                        "captain-merge:test-digest",
                        "lane:test-digest",
                        resource_keys,
                        repository=str(repo),
                        changed_paths=paths,
                        purpose="digest binding test",
                        ttl_seconds=60,
                        metadata=metadata,
                    )
            finally:
                resources.RESOURCE_DB = original_db

    def test_large_guard_compacts_persisted_scope_and_blocks_late_disjoint_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as state:
            repo = Path(directory).resolve()
            paths = [str(repo / f"generated-{index:04d}.txt") for index in range(1058)]
            resource_keys = merge_guard.merge_guard_resource_keys(
                repo,
                repo_slug="heimgewebe/commonworld",
                pr_number=212,
                base="main",
                head="feature/large-release",
            )
            metadata = {
                "merge_guard": {
                    "repository": "heimgewebe/commonworld",
                    "pull_request": 212,
                    "base_branch": "main",
                    "head_branch": "feature/large-release",
                    "base_sha": "a" * 40,
                    "expected_base_sha": "a" * 40,
                    "head_sha": "b" * 40,
                    "diff_sha256": "c" * 64,
                    "execution_intent_sha256": "d" * 64,
                    "changed_paths_sha256": hashlib.sha256(
                        resources._canonical_json(
                            [str(Path(path).relative_to(repo)) for path in paths]
                        ).encode("utf-8")
                    ).hexdigest(),
                }
            }
            original_db = resources.RESOURCE_DB
            resources.RESOURCE_DB = Path(state) / "resources.sqlite3"
            try:
                acquisition = resources.acquire_merge_guard_resources(
                    "captain-merge:test-large",
                    "lane:test-large",
                    resource_keys,
                    repository=str(repo),
                    changed_paths=paths,
                    purpose="large merge guard compaction test",
                    ttl_seconds=60,
                    metadata=metadata,
                )
                gate_key = next(
                    key for key in acquisition["held_resource_keys"]
                    if key.startswith("gate:github-merge:")
                )
                with resources._database() as connection:
                    row = connection.execute(
                        "SELECT * FROM leases WHERE resource_key=?", (gate_key,)
                    ).fetchone()
                    self.assertIsNotNone(row)
                    assert row is not None
                    persisted = resources._row_metadata(row)
                    encoded, _digest = resources._metadata(persisted)
                    guard = persisted["merge_guard"]
                    self.assertLessEqual(len(encoded.encode("utf-8")), 16 * 1024)
                    self.assertEqual(guard["local_changed_paths_mode"], "repository_wide")
                    self.assertEqual(guard["local_changed_path_count"], 1058)
                    self.assertNotIn("local_changed_paths", guard)
                    self.assertEqual(
                        resources._merge_guard_changed_paths_from_row(
                            row, repository=str(repo)
                        ),
                        [str(repo)],
                    )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_resources(
                        "foreign-late-writer",
                        [f"path:{repo / 'otherwise-disjoint.txt'}"],
                        purpose="prove repository-wide late conflict",
                        ttl_seconds=60,
                    )
            finally:
                resources.RESOURCE_DB = original_db


if __name__ == "__main__":
    unittest.main()
