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


class _RenamePrGh:
    def __init__(
        self,
        *,
        change_status: str = "renamed",
        previous_path: str | None = "old-name.txt",
    ) -> None:
        self.base_sha = "a" * 40
        self.head_sha = "b" * 40
        self.change_status = change_status
        self.change_type = change_status.upper()
        self.previous_path = previous_path
        self.new_path = "new-name.txt"
        self.diff_text = "captain-rename-diff\n"
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, argv: list[str]) -> dict[str, object]:
        self.calls.append(tuple(argv))
        if argv[:2] == ["pr", "view"]:
            payload = {
                "number": 212,
                "state": "OPEN",
                "headRefName": "feature/rename",
                "headRefOid": self.head_sha,
                "baseRefName": "main",
                "baseRefOid": self.base_sha,
                "isCrossRepository": False,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
                "changedFiles": 1,
                "files": [
                    {"path": self.new_path, "changeType": self.change_type}
                ],
            }
            return {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""}
        if argv[:2] == ["api", "--paginate"]:
            record = [self.new_path, self.change_status, self.previous_path]
            return {
                "returncode": 0,
                "stdout": json.dumps(record) + "\n",
                "stderr": "",
            }
        if argv[:2] == ["pr", "diff"]:
            return {"returncode": 0, "stdout": self.diff_text, "stderr": ""}
        raise AssertionError(f"unexpected GitHub call: {argv!r}")


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
    # Keep the temporary repository synchronous. Detached auto-maintenance can
    # race TemporaryDirectory cleanup on fast CI runners after the test ends.
    _git(repo, "config", "gc.auto", "0")
    _git(repo, "config", "maintenance.auto", "false")
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

    def test_live_bindings_refreshes_rename_and_copy_previous_paths(self) -> None:
        for change_status in ("renamed", "copied"):
            with self.subTest(change_status=change_status):
                gh = _RenamePrGh(change_status=change_status)
                runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
                runner.action = {
                    "target": {
                        "repo": "heimgewebe/commonworld",
                        "pr": 212,
                        "base": "main",
                    }
                }
                runner.parameters = {
                    "expected_head": gh.head_sha,
                    "expected_base_sha": gh.base_sha,
                    "diff_sha256": merge_guard.github_pr_diff_identity_sha256(
                        gh.diff_text.encode("utf-8")
                    ),
                }
                runner.static_errors = []
                runner.repo_path = Path.cwd()
                runner.github_runner = gh
                runner.receipt = {}
                runner.execution_intent_sha256 = "1" * 64
                runner._revalidate_codex_review = lambda _bindings, phase: []

                bindings, errors = runner._live_bindings()

                self.assertEqual(errors, [])
                self.assertIsNotNone(bindings)
                assert bindings is not None
                expected_paths = (
                    [gh.new_path, gh.previous_path]
                    if change_status == "renamed"
                    else [gh.new_path]
                )
                self.assertEqual(bindings["changed_paths"], expected_paths)
                self.assertEqual(runner.receipt["live_files"]["record_count"], 1)
                self.assertTrue(
                    any(call[:2] == ("api", "--paginate") for call in gh.calls)
                )

    def test_live_bindings_accepts_exact_current_raw_provider_diff_identity(self) -> None:
        gh = _RenamePrGh()
        gh.diff_text = (
            "diff --git a/new-name.txt b/new-name.txt\n"
            "index 123456789abcdef..abcdef0123456789 100644\n"
            "--- a/new-name.txt\n"
            "+++ b/new-name.txt\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        raw_diff_sha256 = hashlib.sha256(gh.diff_text.encode("utf-8")).hexdigest()
        canonical_diff_sha256 = merge_guard.github_pr_diff_identity_sha256(
            gh.diff_text.encode("utf-8")
        )
        self.assertNotEqual(raw_diff_sha256, canonical_diff_sha256)
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.action = {
            "target": {
                "repo": "heimgewebe/commonworld",
                "pr": 212,
                "base": "main",
            }
        }
        runner.parameters = {
            "expected_head": gh.head_sha,
            "expected_base_sha": gh.base_sha,
            "diff_sha256": raw_diff_sha256,
        }
        runner.static_errors = []
        runner.repo_path = Path.cwd()
        runner.github_runner = gh
        runner.receipt = {}
        runner.execution_intent_sha256 = "1" * 64
        runner._revalidate_codex_review = lambda _bindings, phase: []

        bindings, errors = runner._live_bindings()

        self.assertEqual(errors, [])
        self.assertIsNotNone(bindings)
        assert bindings is not None
        self.assertEqual(bindings["diff_sha256"], raw_diff_sha256)
        self.assertEqual(bindings["raw_diff_sha256"], raw_diff_sha256)
        self.assertEqual(bindings["canonical_diff_sha256"], canonical_diff_sha256)
        self.assertEqual(bindings["diff_identity_mode"], "raw-current-provider-compat")
        self.assertEqual(runner.receipt["live_diff"]["raw_sha256"], raw_diff_sha256)
        self.assertEqual(runner.receipt["live_diff"]["sha256"], canonical_diff_sha256)
        self.assertEqual(runner.receipt["live_diff"]["binding_sha256"], raw_diff_sha256)
        self.assertEqual(
            runner.receipt["live_diff"]["identity_mode"],
            "raw-current-provider-compat",
        )

    def test_live_bindings_prefers_canonical_provider_diff_identity(self) -> None:
        gh = _RenamePrGh()
        gh.diff_text = (
            "diff --git a/new-name.txt b/new-name.txt\n"
            "index 123456789abcdef..abcdef0123456789 100644\n"
            "--- a/new-name.txt\n"
            "+++ b/new-name.txt\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        raw_diff_sha256 = hashlib.sha256(gh.diff_text.encode("utf-8")).hexdigest()
        canonical_diff_sha256 = merge_guard.github_pr_diff_identity_sha256(
            gh.diff_text.encode("utf-8")
        )
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.action = {
            "target": {
                "repo": "heimgewebe/commonworld",
                "pr": 212,
                "base": "main",
            }
        }
        runner.parameters = {
            "expected_head": gh.head_sha,
            "expected_base_sha": gh.base_sha,
            "diff_sha256": canonical_diff_sha256,
        }
        runner.static_errors = []
        runner.repo_path = Path.cwd()
        runner.github_runner = gh
        runner.receipt = {}
        runner.execution_intent_sha256 = "1" * 64
        runner._revalidate_codex_review = lambda _bindings, phase: []

        bindings, errors = runner._live_bindings()

        self.assertEqual(errors, [])
        self.assertIsNotNone(bindings)
        assert bindings is not None
        self.assertEqual(bindings["diff_sha256"], canonical_diff_sha256)
        self.assertEqual(bindings["raw_diff_sha256"], raw_diff_sha256)
        self.assertEqual(bindings["canonical_diff_sha256"], canonical_diff_sha256)
        self.assertEqual(bindings["diff_identity_mode"], "canonical")
        self.assertEqual(
            runner.receipt["live_diff"]["binding_sha256"],
            canonical_diff_sha256,
        )
        self.assertEqual(runner.receipt["live_diff"]["identity_mode"], "canonical")

    def test_live_bindings_rejects_unrelated_diff_identity(self) -> None:
        gh = _RenamePrGh()
        gh.diff_text = (
            "diff --git a/new-name.txt b/new-name.txt\n"
            "index 123456789abcdef..abcdef0123456789 100644\n"
            "--- a/new-name.txt\n"
            "+++ b/new-name.txt\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.action = {
            "target": {
                "repo": "heimgewebe/commonworld",
                "pr": 212,
                "base": "main",
            }
        }
        runner.parameters = {
            "expected_head": gh.head_sha,
            "expected_base_sha": gh.base_sha,
            "diff_sha256": "f" * 64,
        }
        runner.static_errors = []
        runner.repo_path = Path.cwd()
        runner.github_runner = gh
        runner.receipt = {}
        runner.execution_intent_sha256 = "1" * 64
        runner._revalidate_codex_review = lambda _bindings, phase: []

        bindings, errors = runner._live_bindings()

        self.assertIn("merge_guard_diff_drift", errors)
        self.assertIsNotNone(bindings)
        assert bindings is not None
        self.assertNotEqual(bindings["diff_sha256"], "f" * 64)
        self.assertEqual(bindings["diff_identity_mode"], "unmatched")
        self.assertEqual(runner.receipt["live_diff"]["identity_mode"], "unmatched")

    def test_live_bindings_rejects_missing_or_invalid_previous_path(self) -> None:
        for previous_path in (None, "../old-name.txt", "new-name.txt"):
            with self.subTest(previous_path=previous_path):
                gh = _RenamePrGh(previous_path=previous_path)
                runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
                runner.action = {
                    "target": {
                        "repo": "heimgewebe/commonworld",
                        "pr": 212,
                        "base": "main",
                    }
                }
                runner.parameters = {
                    "expected_head": gh.head_sha,
                    "expected_base_sha": gh.base_sha,
                    "diff_sha256": merge_guard.github_pr_diff_identity_sha256(
                        gh.diff_text.encode("utf-8")
                    ),
                }
                runner.static_errors = []
                runner.repo_path = Path.cwd()
                runner.github_runner = gh
                runner.receipt = {}
                runner.execution_intent_sha256 = "1" * 64
                runner._revalidate_codex_review = lambda _bindings, phase: []

                _bindings, errors = runner._live_bindings()

                self.assertIn(
                    "merge_guard_changed_path_requires_previous_name:0", errors
                )
                self.assertFalse(
                    any(call[:2] == ("pr", "merge") for call in gh.calls)
                )

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


_PLAN_LIMIT_403 = (
    "gh: Upgrade to GitHub Pro or make this repository public to enable this feature. "
    "(HTTP 403)"
)
_CAS_BASE = "a" * 40
_CAS_HEAD = "b" * 40
_CAS_MERGE = "c" * 40
_CAS_TREE = "e" * 40
_CAS_OTHER = "d" * 40
_CAS_REF = "refs/heads/main"
_CAS_HEAD_BRANCH = "feature/cas"
_CAS_HEAD_REF = f"refs/heads/{_CAS_HEAD_BRANCH}"
_CAS_PULL_REF = "refs/pull/153/head"


class _PlanLimitedRulesGh:
    def __init__(
        self,
        *,
        private: bool = True,
        allow_merge_commit: bool = True,
        stderr: str = _PLAN_LIMIT_403,
    ) -> None:
        self.private = private
        self.allow_merge_commit = allow_merge_commit
        self.stderr = stderr
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, args: list[str]) -> dict[str, object]:
        self.calls.append(tuple(args))
        if any("/rules/branches/" in item for item in args):
            return {"returncode": 1, "stdout": "", "stderr": self.stderr}
        if args[:2] == ["api", "repos/heimgewebe/infra"]:
            return {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "private": self.private,
                        "allow_merge_commit": self.allow_merge_commit,
                    }
                ),
                "stderr": "",
            }
        return {"returncode": 1, "stdout": "", "stderr": "unexpected call"}


class _AuthenticatedUserGh:
    def __init__(
        self,
        *,
        login: str = "captain-owner",
        account_id: int = 123456,
        account_type: str = "User",
        created_at: str = "2024-01-02T03:04:05Z",
        returncode: int = 0,
    ) -> None:
        self.login = login
        self.account_id = account_id
        self.account_type = account_type
        self.created_at = created_at
        self.returncode = returncode
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, _repo: Path, args: list[str]) -> dict[str, object]:
        self.calls.append(tuple(args))
        if args != ["api", "user"]:
            raise AssertionError(f"unexpected GitHub call: {args!r}")
        if self.returncode != 0:
            return {"returncode": self.returncode, "stdout": "", "stderr": "auth failed"}
        return {
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "login": self.login,
                    "id": self.account_id,
                    "type": self.account_type,
                    "created_at": self.created_at,
                }
            ),
            "stderr": "",
        }


class _ScriptedCasGit:
    def __init__(
        self,
        *,
        remote_before: str = _CAS_BASE,
        remote_head_before: str = _CAS_HEAD,
        remote_pr_head_before: str = _CAS_HEAD,
        push_returncode: int = 0,
        remote_url: str = "git@github.com:heimgewebe/infra.git",
    ) -> None:
        self.remote_before = remote_before
        self.remote_head_before = remote_head_before
        self.remote_pr_head_before = remote_pr_head_before
        self.push_returncode = push_returncode
        self.remote_url = remote_url
        self.calls: list[tuple[str, ...]] = []
        self.base_ls_remote_count = 0
        self.pushed = False

    def __call__(
        self, _repo: Path, args: list[str], *, timeout: int = 60
    ) -> dict[str, object]:
        del timeout
        self.calls.append(tuple(args))
        if args[:1] == ["check-ref-format"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args == ["remote", "get-url", "origin"]:
            return {"returncode": 0, "stdout": self.remote_url + "\n", "stderr": ""}
        if args[:2] == ["init", "--quiet"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args == ["config", "core.hooksPath", "/dev/null"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args[:3] == ["remote", "add", "origin"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args[:1] == ["fetch"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args == ["rev-parse", "refs/captain/base^{commit}"]:
            return {"returncode": 0, "stdout": _CAS_BASE + "\n", "stderr": ""}
        if args == ["rev-parse", "refs/captain/head-branch^{commit}"]:
            return {"returncode": 0, "stdout": _CAS_HEAD + "\n", "stderr": ""}
        if args == ["rev-parse", "refs/captain/pr-head^{commit}"]:
            return {"returncode": 0, "stdout": _CAS_HEAD + "\n", "stderr": ""}
        if args[:3] == ["checkout", "--quiet", "--detach"]:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if "merge" in args:
            return {"returncode": 0, "stdout": "", "stderr": ""}
        if args == ["rev-list", "--parents", "-n", "1", "HEAD"]:
            return {
                "returncode": 0,
                "stdout": f"{_CAS_MERGE} {_CAS_BASE} {_CAS_HEAD}\n",
                "stderr": "",
            }
        if args == ["rev-parse", "HEAD^{tree}"]:
            return {"returncode": 0, "stdout": _CAS_TREE + "\n", "stderr": ""}
        if args == ["ls-remote", "origin", _CAS_HEAD_REF]:
            if self.pushed:
                return {"returncode": 0, "stdout": "", "stderr": ""}
            return {
                "returncode": 0,
                "stdout": f"{self.remote_head_before}\t{_CAS_HEAD_REF}\n",
                "stderr": "",
            }
        if args == ["ls-remote", "origin", _CAS_PULL_REF]:
            return {
                "returncode": 0,
                "stdout": f"{self.remote_pr_head_before}\t{_CAS_PULL_REF}\n",
                "stderr": "",
            }
        if args == ["ls-remote", "origin", _CAS_REF]:
            self.base_ls_remote_count += 1
            sha = self.remote_before if self.base_ls_remote_count == 1 else _CAS_MERGE
            return {
                "returncode": 0,
                "stdout": f"{sha}\t{_CAS_REF}\n",
                "stderr": "",
            }
        if args[:2] == ["push", "--porcelain"]:
            if self.push_returncode == 0:
                self.pushed = True
            return {
                "returncode": self.push_returncode,
                "stdout": "ok\n" if self.push_returncode == 0 else "",
                "stderr": "" if self.push_returncode == 0 else "rejected",
            }
        return {"returncode": 1, "stdout": "", "stderr": "unexpected git call"}


class CaptainPrivatePlanCasFallbackTests(unittest.TestCase):
    def test_plan_fallback_requires_explicit_same_repository_binding(self) -> None:
        self.assertIsNone(
            merge_guard._exact_base_git_cas_pr_scope_error(
                {"is_cross_repository": False}
            )
        )
        for value in (True, None):
            with self.subTest(is_cross_repository=value):
                self.assertEqual(
                    "merge_guard_plan_fallback_requires_same_repository_pr",
                    merge_guard._exact_base_git_cas_pr_scope_error(
                        {"is_cross_repository": value}
                    ),
                )

    def test_plan_fallback_requires_explicit_branch_deletion_scope(self) -> None:
        self.assertEqual(
            [],
            merge_guard._exact_base_git_cas_effect_scope_errors(
                {"scope": {"allowed_effects": ["pr-merge", "branch-deletion"]}}
            ),
        )
        self.assertEqual(
            ["merge_guard_plan_fallback_branch_deletion_scope_missing"],
            merge_guard._exact_base_git_cas_effect_scope_errors(
                {"scope": {"allowed_effects": ["pr-merge"]}}
            ),
        )
        self.assertEqual(
            ["merge_guard_plan_fallback_branch_deletion_forbidden"],
            merge_guard._exact_base_git_cas_effect_scope_errors(
                {
                    "scope": {
                        "allowed_effects": ["pr-merge", "branch-deletion"],
                        "forbidden_effects": ["branch-deletion"],
                    }
                }
            ),
        )

    def test_exact_plan_limit_private_repo_enables_cas_guard(self) -> None:
        policy, evidence, errors = merge_guard.verify_github_base_update_guard(
            Path.cwd(),
            _PlanLimitedRulesGh(),
            repo_slug="heimgewebe/infra",
            base_branch="main",
        )
        self.assertEqual([], errors)
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual("exact_base_git_cas", policy["mode"])
        self.assertTrue(policy["private_repository"])
        self.assertTrue(policy["merge_commit_allowed"])
        self.assertTrue(evidence["active_rules"]["github_plan_limit"])
        self.assertEqual([], evidence["errors"])

    def test_generic_403_never_enables_cas_guard(self) -> None:
        policy, _evidence, errors = merge_guard.verify_github_base_update_guard(
            Path.cwd(),
            _PlanLimitedRulesGh(stderr="gh: forbidden (HTTP 403)"),
            repo_slug="heimgewebe/infra",
            base_branch="main",
        )
        self.assertIsNone(policy)
        self.assertIn("base_update_guard_active_rules_query_failed", errors)

    def test_public_or_merge_commit_disabled_repo_is_ineligible(self) -> None:
        for private, allow_merge_commit in ((False, True), (True, False)):
            with self.subTest(private=private, allow_merge_commit=allow_merge_commit):
                policy, _evidence, errors = merge_guard.verify_github_base_update_guard(
                    Path.cwd(),
                    _PlanLimitedRulesGh(
                        private=private, allow_merge_commit=allow_merge_commit
                    ),
                    repo_slug="heimgewebe/infra",
                    base_branch="main",
                )
                self.assertIsNone(policy)
                self.assertIn("base_update_guard_plan_fallback_not_eligible", errors)

    def test_exact_base_cas_builds_two_parent_merge_and_exact_old_value_lease(self) -> None:
        git = _ScriptedCasGit()
        dispatched: list[bool] = []
        result, evidence = merge_guard._exact_base_git_cas_merge(
            Path.cwd(),
            repo_slug="heimgewebe/infra",
            base_branch="main",
            base_sha=_CAS_BASE,
            head_sha=_CAS_HEAD,
            head_branch=_CAS_HEAD_BRANCH,
            pr_number=153,
            github_runner=_AuthenticatedUserGh(),
            git_runner=git,
            on_dispatch=lambda: dispatched.append(True),
        )
        self.assertEqual(0, result["returncode"])
        self.assertEqual([True], dispatched)
        self.assertEqual("pushed_and_read_back", evidence["status"])
        self.assertFalse(evidence["protected_base_force_push"])
        self.assertTrue(evidence["head_branch_delete_with_expected_old_lease"])
        self.assertTrue(evidence["atomic_base_update_and_head_delete"])
        push = next(call for call in git.calls if call[:2] == ("push", "--porcelain"))
        self.assertIn("--atomic", push)
        self.assertIn(f"--force-with-lease={_CAS_HEAD_REF}:{_CAS_HEAD}", push)
        self.assertNotIn(f"--force-with-lease={_CAS_REF}:{_CAS_BASE}", push)
        self.assertIn(f"HEAD:{_CAS_REF}", push)
        self.assertEqual(f":{_CAS_HEAD_REF}", push[-1])
        merge_call = next(call for call in git.calls if "merge" in call)
        self.assertIn("user.name=captain-owner", merge_call)
        self.assertIn(
            "user.email=123456+captain-owner@users.noreply.github.com", merge_call
        )
        self.assertNotIn("grabowski@localhost", " ".join(merge_call))
        self.assertEqual(_CAS_TREE, evidence["merge_tree_sha"])
        self.assertEqual("resolved", evidence["commit_identity"]["status"])
        self.assertEqual(
            "github_authenticated_user_api", evidence["commit_identity"]["source"]
        )
        self.assertEqual("id_plus_login", evidence["commit_identity"]["noreply_format"])
        self.assertNotIn(
            "@users.noreply.github.com", json.dumps(evidence["commit_identity"], sort_keys=True)
        )

    def test_exact_base_cas_commit_identity_does_not_change_observed_merge_tree(self) -> None:
        observed_trees: list[str] = []
        merge_calls: list[tuple[str, ...]] = []
        for login, account_id in (("captain-one", 1001), ("captain-two", 1002)):
            git = _ScriptedCasGit()
            result, evidence = merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(login=login, account_id=account_id),
                git_runner=git,
            )
            self.assertEqual(0, result["returncode"])
            observed_trees.append(str(evidence["merge_tree_sha"]))
            merge_calls.append(next(call for call in git.calls if "merge" in call))

        self.assertEqual([_CAS_TREE, _CAS_TREE], observed_trees)
        self.assertNotEqual(merge_calls[0], merge_calls[1])

    def test_exact_base_cas_fails_closed_without_proven_github_noreply_identity(self) -> None:
        git = _ScriptedCasGit()
        github = _AuthenticatedUserGh(created_at="2016-01-02T03:04:05Z")
        with self.assertRaisesRegex(
            RuntimeError, "cannot resolve provider-compatible GitHub commit identity"
        ):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=github,
                git_runner=git,
            )
        self.assertEqual([("api", "user")], github.calls)
        self.assertFalse(any(call[:1] == ("fetch",) for call in git.calls))
        self.assertFalse(any(call[:1] == ("push",) for call in git.calls))

    def test_exact_base_cas_blocks_authenticated_user_query_failure(self) -> None:
        git = _ScriptedCasGit()
        with self.assertRaisesRegex(
            RuntimeError, "cannot resolve provider-compatible GitHub commit identity"
        ):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(returncode=1),
                git_runner=git,
            )
        self.assertFalse(any(call[:1] == ("fetch",) for call in git.calls))
        self.assertFalse(any(call[:1] == ("push",) for call in git.calls))

    def test_exact_base_cas_blocks_head_drift_before_dispatch(self) -> None:
        git = _ScriptedCasGit(remote_head_before=_CAS_OTHER)
        dispatched: list[bool] = []
        with self.assertRaisesRegex(RuntimeError, "head branch changed before dispatch"):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(),
                git_runner=git,
                on_dispatch=lambda: dispatched.append(True),
            )
        self.assertEqual([], dispatched)
        self.assertFalse(any(call[:1] == ("push",) for call in git.calls))

    def test_exact_base_cas_atomic_head_lease_rejection_fails_without_success(self) -> None:
        git = _ScriptedCasGit(push_returncode=1)
        dispatched: list[bool] = []
        result, evidence = merge_guard._exact_base_git_cas_merge(
            Path.cwd(),
            repo_slug="heimgewebe/infra",
            base_branch="main",
            base_sha=_CAS_BASE,
            head_sha=_CAS_HEAD,
            head_branch=_CAS_HEAD_BRANCH,
            pr_number=153,
            github_runner=_AuthenticatedUserGh(),
            git_runner=git,
            on_dispatch=lambda: dispatched.append(True),
        )
        self.assertEqual([True], dispatched)
        self.assertEqual(1, result["returncode"])
        self.assertEqual("push_rejected_or_failed", evidence["status"])

    def test_exact_base_cas_blocks_base_drift_before_dispatch(self) -> None:
        git = _ScriptedCasGit(remote_before=_CAS_OTHER)
        dispatched: list[bool] = []
        with self.assertRaisesRegex(RuntimeError, "base changed before dispatch"):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(),
                git_runner=git,
                on_dispatch=lambda: dispatched.append(True),
            )
        self.assertEqual([], dispatched)
        self.assertFalse(any(call[:1] == ("push",) for call in git.calls))

    def test_exact_base_cas_blocks_origin_repository_drift(self) -> None:
        git = _ScriptedCasGit(remote_url="git@github.com:heimgewebe/other.git")
        with self.assertRaisesRegex(RuntimeError, "origin repository drift"):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(),
                git_runner=git,
            )
        self.assertFalse(any(call[:1] == ("fetch",) for call in git.calls))

    def test_exact_base_cas_rejects_https_origin_without_bounded_git_auth(self) -> None:
        git = _ScriptedCasGit(remote_url="https://github.com/heimgewebe/infra.git")
        with self.assertRaisesRegex(RuntimeError, "requires canonical SSH GitHub origin"):
            merge_guard._exact_base_git_cas_merge(
                Path.cwd(),
                repo_slug="heimgewebe/infra",
                base_branch="main",
                base_sha=_CAS_BASE,
                head_sha=_CAS_HEAD,
                head_branch=_CAS_HEAD_BRANCH,
                pr_number=153,
                github_runner=_AuthenticatedUserGh(),
                git_runner=git,
            )
        self.assertFalse(any(call[:1] == ("fetch",) for call in git.calls))

    def test_exact_base_cas_surfaces_lease_rejection(self) -> None:
        git = _ScriptedCasGit(push_returncode=1)
        dispatched: list[bool] = []
        result, evidence = merge_guard._exact_base_git_cas_merge(
            Path.cwd(),
            repo_slug="heimgewebe/infra",
            base_branch="main",
            base_sha=_CAS_BASE,
            head_sha=_CAS_HEAD,
            head_branch=_CAS_HEAD_BRANCH,
            pr_number=153,
            github_runner=_AuthenticatedUserGh(),
            git_runner=git,
            on_dispatch=lambda: dispatched.append(True),
        )
        self.assertEqual([True], dispatched)
        self.assertEqual(1, result["returncode"])
        self.assertEqual("push_rejected_or_failed", evidence["status"])


class CaptainRequiredChecksProbeTests(unittest.TestCase):
    def test_no_required_checks_cli_rc1_is_green_empty_set(self) -> None:
        github_runner = mock.Mock(
            return_value={
                "returncode": 1,
                "stdout": "",
                "stderr": "no required checks reported on the 'feature/no-required' branch\n",
            }
        )

        probe = merge_guard.required_pr_checks_probe(
            Path.cwd(),
            github_runner,
            repo_slug="heimgewebe/infra",
            pr_number=153,
        )

        self.assertEqual("green", probe["status"])
        self.assertEqual(0, probe["required_check_count"])
        self.assertEqual(0, probe["non_passing_required_check_count"])
        self.assertEqual([], probe["required_check_names"])
        self.assertEqual([], probe["errors"])
        self.assertEqual(
            "no_required_checks_reported",
            probe["query"]["nonzero_empty_result"],
        )

    def test_other_required_checks_rc1_remains_unavailable(self) -> None:
        github_runner = mock.Mock(
            return_value={
                "returncode": 1,
                "stdout": "",
                "stderr": "HTTP 401: Bad credentials\n",
            }
        )

        probe = merge_guard.required_pr_checks_probe(
            Path.cwd(),
            github_runner,
            repo_slug="heimgewebe/infra",
            pr_number=153,
        )

        self.assertEqual("unavailable", probe["status"])
        self.assertIsNone(probe["required_check_count"])
        self.assertEqual(["required_pr_checks_query_failed"], probe["errors"])
        self.assertNotIn("nonzero_empty_result", probe["query"])




if __name__ == "__main__":
    unittest.main()
