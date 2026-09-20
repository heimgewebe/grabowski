from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
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


import grabowski_post_merge_sync_apply as sync_apply  # noqa: E402


def git(repo: Path, argv: list[str]) -> dict[str, object]:
    completed = subprocess.run(
        ["git", "-C", str(repo), *argv],
        text=True,
        capture_output=True,
        check=False,
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout.rstrip("\n"),
        "stderr": completed.stderr.rstrip("\n"),
    }


def git_stdout(repo: Path, *argv: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *argv],
        text=True,
        capture_output=True,
        check=True,
    )
    return completed.stdout.strip()


class LeaseHarness:
    def __init__(self, *, acquire_effect=None) -> None:
        self.acquire_effect = acquire_effect
        self.live: dict[str, dict[str, object]] = {}
        self.acquire_calls = 0
        self.release_calls = 0
        self.release_expected_leases: list[dict[str, object]] | None = None

    def acquire(
        self,
        owner_id: str,
        resource_keys: list[str],
        *,
        purpose: str,
        ttl_seconds: int,
    ) -> dict[str, object]:
        self.acquire_calls += 1
        if self.acquire_effect is not None:
            self.acquire_effect()
        leases = []
        for key in resource_keys:
            lease = {
                "resource_key": key,
                "owner_id": owner_id,
                "purpose": purpose,
                "acquired_at_unix": 1,
                "updated_at_unix": 1,
                "expires_at_unix": 1 + ttl_seconds,
                "metadata_sha256": "a" * 64,
                "reclaimed_from_owner": None,
            }
            self.live[key] = lease
            leases.append(lease)
        return {"leases": leases}

    def inspect(self, resource_keys: list[str]) -> dict[str, dict[str, object]]:
        return {key: dict(self.live[key]) for key in resource_keys if key in self.live}

    def release(
        self,
        owner_id: str,
        resource_keys: list[str],
        *,
        expected_leases: list[dict[str, object]] | None = None,
        force: bool = False,
    ) -> dict[str, object]:
        self.release_expected_leases = expected_leases
        del force
        self.release_calls += 1
        released = []
        for key in resource_keys:
            lease = self.live.get(key)
            if lease is not None and lease["owner_id"] == owner_id:
                released.append(lease)
                self.live.pop(key, None)
        return {"released": released}



class ConcurrentLeaseHarness(LeaseHarness):
    def __init__(self) -> None:
        super().__init__()
        self.owner_ids: list[str] = []
        self.on_first_acquire = None
        self.nested_result: dict[str, object] | None = None

    def acquire(
        self,
        owner_id: str,
        resource_keys: list[str],
        *,
        purpose: str,
        ttl_seconds: int,
    ) -> dict[str, object]:
        self.acquire_calls += 1
        self.owner_ids.append(owner_id)
        if self.live:
            live_owners = {
                str(item["owner_id"])
                for item in self.live.values()
            }
            if live_owners != {owner_id}:
                raise RuntimeError("resource conflict")
            return {
                "leases": [
                    dict(self.live[key])
                    for key in resource_keys
                ]
            }

        leases = []
        for key in resource_keys:
            lease = {
                "resource_key": key,
                "owner_id": owner_id,
                "purpose": purpose,
                "acquired_at_unix": 1,
                "updated_at_unix": 1,
                "expires_at_unix": 1 + ttl_seconds,
                "metadata_sha256": "a" * 64,
                "reclaimed_from_owner": None,
            }
            self.live[key] = lease
            leases.append(lease)

        callback = self.on_first_acquire
        self.on_first_acquire = None
        if callback is not None:
            self.nested_result = callback()
        return {"leases": leases}



@contextmanager
def patched_leases(harness: LeaseHarness):
    with (
        patch.object(sync_apply.resources, "acquire_resources", harness.acquire),
        patch.object(sync_apply.resources, "inspect_resources", harness.inspect),
        patch.object(sync_apply.resources, "release_resources", harness.release),
    ):
        yield


class PostMergeSyncApplyTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, str, str]:
        remote = root / "remote.git"
        repo = root / "repo"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "core.hooksPath", "/dev/null"],
            check=True,
        )
        (repo / "state.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True
        )
        base = git_stdout(repo, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", str(remote)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "push", "-q", "-u", "origin", "main"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "switch", "-q", "-c", "publisher"],
            check=True,
        )
        (repo / "state.txt").write_text("remote\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-am", "remote update"],
            check=True,
        )
        remote_head = git_stdout(repo, "rev-parse", "HEAD")
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "push",
                "-q",
                "origin",
                f"{remote_head}:refs/heads/main",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "switch", "-q", "main"], check=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "update-ref",
                "refs/remotes/origin/main",
                base,
            ],
            check=True,
        )
        self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
        self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
        return repo, remote, base, remote_head

    def fixture_remote_object_absent(
        self, root: Path
    ) -> tuple[Path, Path, str, str]:
        remote = root / "remote.git"
        repo = root / "repo"
        publisher = root / "publisher"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "user.email",
                "grabowski@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "core.hooksPath", "/dev/null"],
            check=True,
        )
        (repo / "state.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True
        )
        base = git_stdout(repo, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin", str(remote)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "push", "-q", "-u", "origin", "main"],
            check=True,
        )
        subprocess.run(
            ["git", "clone", "-q", "-b", "main", str(remote), str(publisher)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(publisher), "config", "user.name", "Publisher"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(publisher),
                "config",
                "user.email",
                "publisher@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(publisher), "config", "core.hooksPath", "/dev/null"],
            check=True,
        )
        (publisher / "state.txt").write_text("remote\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(publisher), "commit", "-q", "-am", "remote update"],
            check=True,
        )
        remote_head = git_stdout(publisher, "rev-parse", "HEAD")
        subprocess.run(
            ["git", "-C", str(publisher), "push", "-q", "origin", "main"],
            check=True,
        )
        self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
        self.assertEqual(base, git_stdout(repo, "rev-parse", "refs/remotes/origin/main"))
        missing = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "cat-file",
                "-e",
                f"{remote_head}^{{commit}}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(0, missing.returncode)
        self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
        return repo, remote, base, remote_head

    def remote_reader(self, remote: Path):
        def read(_stage: str, _effect_started: bool) -> str:
            output = subprocess.check_output(
                [
                    "git",
                    "ls-remote",
                    "--heads",
                    str(remote),
                    "refs/heads/main",
                ],
                text=True,
            ).strip()
            return output.split()[0]

        return read

    @staticmethod
    def pinned(remote: Path):
        def factory(_remote_target: str) -> tuple[str, str]:
            return str(remote), "advice.detachedHead=false"

        return factory

    def apply(
        self,
        repo: Path,
        remote: Path,
        local_head: str,
        remote_head: str,
        *,
        runner=git,
        remote_reader=None,
    ) -> dict[str, object]:
        return sync_apply.apply(
            repo=repo,
            target_branch="main",
            expected_local_head=local_head,
            expected_remote_head=remote_head,
            remote="origin",
            remote_target=str(remote),
            confirmation=sync_apply.CONFIRMATION,
            runner=runner,
            remote_head_reader=remote_reader or self.remote_reader(remote),
            pinned_target_factory=self.pinned(remote),
        )

    def test_successful_clean_fast_forward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("passed", result["receipt_status"])
            self.assertEqual("synced", result["state"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("main", git_stdout(repo, "branch", "--show-current"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual("remote\n", (repo / "state.txt").read_text(encoding="utf-8"))
            self.assertEqual(1, leases.acquire_calls)
            self.assertEqual(1, leases.release_calls)
            self.assertEqual({}, leases.live)
            self.assertIsNotNone(leases.release_expected_leases)
            self.assertEqual(
                set(result["resource_keys"]),
                {
                    str(item["resource_key"])
                    for item in (leases.release_expected_leases or [])
                },
            )
            self.assertIn(f"repo:{repo}", result["resource_keys"])
            self.assertIn(f"path:{repo}", result["resource_keys"])
            self.assertIn(f"path:{repo / '.git'}", result["resource_keys"])
            self.assertFalse(
                any(":branch:" in key for key in result["resource_keys"])
            )

    def test_materializes_absent_remote_commit_before_ancestry_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture_remote_object_absent(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("passed", result["receipt_status"])
            self.assertEqual("synced", result["state"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            subprocess.run(
                ["git", "-C", str(repo), "cat-file", "-e", f"{target}^{{commit}}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(1, leases.acquire_calls)
            self.assertEqual(1, leases.release_calls)

    def test_dirty_checkout_is_blocked_before_leases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            (repo / "dirty.txt").write_text("dirty\n", encoding="utf-8")
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("dirty_checkout", result["state"])
            self.assertEqual(0, leases.acquire_calls)
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))

    def test_wrong_local_head_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            wrong = "1" * len(base)
            with patched_leases(leases):
                result = self.apply(repo, remote, wrong, target)

            self.assertEqual("local_head_mismatch", result["state"])
            self.assertEqual(0, leases.acquire_calls)

    def test_wrong_remote_head_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, base)

            self.assertEqual("remote_head_mismatch", result["state"])
            self.assertEqual(target, result["actual_remote_head"])
            self.assertEqual(0, leases.acquire_calls)

    def test_non_fast_forward_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            (repo / "local.txt").write_text("local\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "local.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "local diverges"],
                check=True,
            )
            local = git_stdout(repo, "rev-parse", "HEAD")
            self.assertNotEqual(base, local)
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, local, target)

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual("non_fast_forward", result["state"])
            self.assertTrue(result["effect_started"])
            self.assertFalse(result["worktree_effect_started"])
            self.assertFalse(result["branch_cas_started"])
            self.assertEqual(1, leases.acquire_calls)
            self.assertEqual(1, leases.release_calls)
            self.assertEqual(local, git_stdout(repo, "rev-parse", "HEAD"))

    def test_wrong_current_branch_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            subprocess.run(
                ["git", "-C", str(repo), "switch", "-q", "publisher"], check=True
            )
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("canonical_checkout_mismatch", result["state"])
            self.assertEqual("publisher", git_stdout(repo, "branch", "--show-current"))
            self.assertEqual(0, leases.acquire_calls)

    def test_success_keeps_target_branch_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("synced", result["state"])
            self.assertEqual("main", git_stdout(repo, "branch", "--show-current"))
            self.assertEqual(target, git_stdout(repo, "rev-parse", "refs/heads/main"))

    def test_success_creates_no_merge_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            target_parents_before = git_stdout(repo, "rev-list", "--parents", "-n", "1", target)
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)
            target_parents_after = git_stdout(repo, "rev-list", "--parents", "-n", "1", "HEAD")

            self.assertFalse(result["merge_commit_created"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(target_parents_before, target_parents_after)

    def test_replay_is_idempotent_without_new_leases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                first = self.apply(repo, remote, base, target)
            self.assertEqual("synced", first["state"])

            second_leases = LeaseHarness()
            with patched_leases(second_leases):
                second = self.apply(repo, remote, base, target)

            self.assertEqual("passed", second["receipt_status"])
            self.assertEqual("already_synced", second["state"])
            self.assertTrue(second["idempotent"])
            self.assertEqual(0, second_leases.acquire_calls)

    def test_branch_cas_failure_after_worktree_update_is_outcome_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def failing_runner(path: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["update-ref", "refs/heads/main", target, base]:
                    return {
                        "returncode": 1,
                        "stdout": "",
                        "stderr": "injected CAS failure",
                    }
                return git(path, argv)

            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=failing_runner,
                )

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("outcome_unknown", result["state"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(base, git_stdout(repo, "rev-parse", "refs/heads/main"))
            self.assertEqual("M  state.txt", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(
                git_stdout(repo, "rev-parse", f"{target}^{{tree}}"),
                git_stdout(repo, "write-tree"),
            )
            self.assertNotEqual(
                git_stdout(repo, "rev-parse", f"{base}^{{tree}}"),
                git_stdout(repo, "write-tree"),
            )
            self.assertEqual(
                "state.txt",
                git_stdout(repo, "diff", "--cached", "--name-only"),
            )
            self.assertEqual(1, leases.release_calls)

    def test_cas_failure_with_release_failure_preserves_git_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def failing_runner(path: Path, argv: list[str]) -> dict[str, object]:
                if argv == ["update-ref", "refs/heads/main", target, base]:
                    return {
                        "returncode": 1,
                        "stdout": "",
                        "stderr": "injected CAS failure",
                    }
                return git(path, argv)

            def failing_release(
                owner_id: str,
                resource_keys: list[str],
                *,
                expected_leases: list[dict[str, object]] | None = None,
                force: bool = False,
            ) -> dict[str, object]:
                del owner_id, resource_keys, expected_leases, force
                raise RuntimeError("cleanup state unknown")

            with (
                patch.object(sync_apply.resources, "acquire_resources", leases.acquire),
                patch.object(sync_apply.resources, "inspect_resources", leases.inspect),
                patch.object(sync_apply.resources, "release_resources", failing_release),
            ):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=failing_runner,
                )

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("outcome_unknown", result["state"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertFalse(result["post_state_verified"])
            self.assertTrue(result["lease_cleanup_required"])
            self.assertEqual("failed", result["lease_release"]["status"])
            self.assertIn(
                "authoritative local and remote readback",
                result["next_action"],
            )
            self.assertIn("inspect and clean", result["next_action"])
            self.assertEqual(
                "authoritative local and remote readback before any new intent",
                result["effect_next_action"],
            )
            self.assertIn(
                "inspect and clean",
                result["lease_cleanup_next_action"],
            )
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(base, git_stdout(repo, "rev-parse", "refs/heads/main"))
            self.assertEqual("M  state.txt", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(
                git_stdout(repo, "rev-parse", f"{target}^{{tree}}"),
                git_stdout(repo, "write-tree"),
            )

    def test_preimage_drift_after_lease_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))

            def drift() -> None:
                (repo / "drift.txt").write_text("external drift\n", encoding="utf-8")

            leases = LeaseHarness(acquire_effect=drift)
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("preimage_drift_after_lease", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(1, leases.release_calls)
            self.assertEqual({}, leases.live)
            self.assertIsNotNone(leases.release_expected_leases)

    def test_remote_drift_after_lease_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            calls = 0

            def drifting_remote(_stage: str, _effect_started: bool) -> str:
                nonlocal calls
                calls += 1
                return target if calls == 1 else base

            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    remote_reader=drifting_remote,
                )

            self.assertEqual("remote_head_drift_after_lease", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(1, leases.release_calls)

    def test_final_remote_drift_blocks_even_when_local_effect_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))

            def drifting_remote(stage: str, _effect_started: bool) -> str:
                if stage in {"final", "error_readback"}:
                    return base
                return target

            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    remote_reader=drifting_remote,
                )

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual("effect_confirmed_remote_drift", result["state"])
            self.assertTrue(result["local_post_state_verified"])
            self.assertFalse(result["post_state_verified"])
            self.assertTrue(result["readback_required"])
            self.assertFalse(result["retry_authorized"])
            self.assertEqual(base, result["remote_readback"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(1, leases.release_calls)

    def test_lease_drift_is_blocked_before_git_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def missing_inspect(_keys: list[str]) -> dict[str, dict[str, object]]:
                return {}

            with (
                patch.object(sync_apply.resources, "acquire_resources", leases.acquire),
                patch.object(sync_apply.resources, "inspect_resources", missing_inspect),
                patch.object(sync_apply.resources, "release_resources", leases.release),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("lease_preimage_drift", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(1, leases.release_calls)


    def test_identical_concurrent_apply_blocks_second_before_git_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = ConcurrentLeaseHarness()
            leases.on_first_acquire = lambda: self.apply(
                repo,
                remote,
                base,
                target,
            )

            with (
                patch.object(
                    sync_apply.secrets,
                    "token_hex",
                    side_effect=["a" * 24, "b" * 24],
                ),
                patched_leases(leases),
            ):
                first = self.apply(repo, remote, base, target)

            self.assertEqual("synced", first["state"])
            self.assertIsNotNone(leases.nested_result)
            second = leases.nested_result or {}
            self.assertEqual("lease_acquisition_blocked", second["state"])
            self.assertFalse(second["effect_started"])
            self.assertFalse(second["retry_authorized"])
            self.assertEqual(2, leases.acquire_calls)
            self.assertEqual(2, len(leases.owner_ids))
            self.assertNotEqual(leases.owner_ids[0], leases.owner_ids[1])
            self.assertEqual(first["lease_owner_id"], leases.owner_ids[0])
            self.assertEqual(second["lease_owner_id"], leases.owner_ids[1])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))


    def test_foreign_repository_guard_conflict_blocks_before_git_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            attempted_keys: list[str] = []

            def blocked_acquire(
                owner_id: str,
                resource_keys: list[str],
                *,
                purpose: str,
                ttl_seconds: int,
            ) -> dict[str, object]:
                del owner_id, purpose, ttl_seconds
                attempted_keys.extend(resource_keys)
                raise RuntimeError("foreign broad repository lease")

            with patch.object(
                sync_apply.resources,
                "acquire_resources",
                blocked_acquire,
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("lease_acquisition_blocked", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertFalse(result["retry_authorized"])
            self.assertIn(f"repo:{repo}", attempted_keys)
            self.assertIn(f"path:{repo}", attempted_keys)
            self.assertIn(f"path:{repo / '.git'}", attempted_keys)
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))

    def test_lease_cleanup_uncertainty_never_authorizes_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def failing_release(
                owner_id: str,
                resource_keys: list[str],
                *,
                expected_leases: list[dict[str, object]] | None = None,
                force: bool = False,
            ) -> dict[str, object]:
                del owner_id, resource_keys, expected_leases, force
                raise RuntimeError("cleanup state unknown")

            with (
                patch.object(sync_apply.resources, "acquire_resources", leases.acquire),
                patch.object(sync_apply.resources, "inspect_resources", leases.inspect),
                patch.object(sync_apply.resources, "release_resources", failing_release),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual("synced", result["state"])
            self.assertTrue(result["lease_cleanup_required"])
            self.assertRegex(
                str(result["lease_owner_id"]),
                r"^operator:post-merge-sync-[0-9a-f]{16}-[0-9a-f]{24}$",
            )
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["effect_started"])
            self.assertTrue(result["post_state_verified"])
            self.assertEqual("failed", result["lease_release"]["status"])
            self.assertIn("inspect and clean", result["next_action"])
            self.assertIn(
                "inspect and clean",
                result["lease_cleanup_next_action"],
            )
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()