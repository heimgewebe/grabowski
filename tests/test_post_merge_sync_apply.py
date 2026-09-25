from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
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
import grabowski_physical_checkout as physical_checkout  # noqa: E402


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
        self.work_admission_modes: list[str] = []
        self.release_calls = 0
        self.release_expected_leases: list[dict[str, object]] | None = None

    def acquire(
        self,
        owner_id: str,
        resource_keys: list[str],
        *,
        purpose: str,
        ttl_seconds: int,
        _work_admission_mode: str = "normal",
    ) -> dict[str, object]:
        self.acquire_calls += 1
        self.work_admission_modes.append(_work_admission_mode)
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
        _work_admission_mode: str = "normal",
    ) -> dict[str, object]:
        self.acquire_calls += 1
        self.work_admission_modes.append(_work_admission_mode)
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




class ExactConflictLeaseHarness(LeaseHarness):
    """Conflict only when two owners request at least one identical resource key."""

    def acquire(
        self,
        owner_id: str,
        resource_keys: list[str],
        *,
        purpose: str,
        ttl_seconds: int,
        _work_admission_mode: str = "normal",
    ) -> dict[str, object]:
        self.acquire_calls += 1
        self.work_admission_modes.append(_work_admission_mode)
        for key in resource_keys:
            existing = self.live.get(key)
            if existing is not None and existing["owner_id"] != owner_id:
                raise RuntimeError(f"resource conflict: {key}")
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
        physical = physical_checkout.capture_physical_checkout_identity(repo)
        return sync_apply.apply(
            repo=repo,
            target_branch="main",
            expected_local_head=local_head,
            expected_remote_head=remote_head,
            expected_physical_identity_sha256=physical["physical_identity_sha256"],
            remote="origin",
            remote_target=str(remote),
            confirmation=sync_apply.CONFIRMATION,
            runner=runner,
            remote_head_reader=remote_reader or self.remote_reader(remote),
            pinned_target_factory=self.pinned(remote),
        )

    def test_physical_identity_mismatch_blocks_before_leases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            expected = physical_checkout.capture_physical_checkout_identity(repo)
            leases = LeaseHarness()
            changed = {**expected, "physical_identity_sha256": "0" * 64}
            with (
                patched_leases(leases),
                patch.object(
                    sync_apply.physical_checkout,
                    "capture_physical_checkout_identity",
                    return_value=changed,
                ),
            ):
                result = sync_apply.apply(
                    repo=repo,
                    target_branch="main",
                    expected_local_head=base,
                    expected_remote_head=target,
                    expected_physical_identity_sha256=expected[
                        "physical_identity_sha256"
                    ],
                    remote="origin",
                    remote_target=str(remote),
                    confirmation=sync_apply.CONFIRMATION,
                    runner=git,
                    remote_head_reader=self.remote_reader(remote),
                    pinned_target_factory=self.pinned(remote),
                )

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual("physical_checkout_identity_mismatch", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertEqual(0, leases.acquire_calls)

    def test_physical_identity_drift_after_lease_blocks_before_git_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            expected = physical_checkout.capture_physical_checkout_identity(repo)
            changed = {**expected, "physical_identity_sha256": "0" * 64}
            leases = LeaseHarness()
            with (
                patched_leases(leases),
                patch.object(
                    sync_apply.physical_checkout,
                    "capture_physical_checkout_identity",
                    side_effect=[expected, changed],
                ),
            ):
                result = sync_apply.apply(
                    repo=repo,
                    target_branch="main",
                    expected_local_head=base,
                    expected_remote_head=target,
                    expected_physical_identity_sha256=expected[
                        "physical_identity_sha256"
                    ],
                    remote="origin",
                    remote_target=str(remote),
                    confirmation=sync_apply.CONFIRMATION,
                    runner=git,
                    remote_head_reader=self.remote_reader(remote),
                    pinned_target_factory=self.pinned(remote),
                )

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual(
                "physical_checkout_identity_drift_after_lease",
                result["state"],
            )
            self.assertFalse(result["effect_started"])
            self.assertEqual(1, leases.acquire_calls)
            self.assertEqual(1, leases.release_calls)

    def test_physical_identity_drift_at_final_readback_never_reports_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            expected = physical_checkout.capture_physical_checkout_identity(repo)
            changed = {**expected, "physical_identity_sha256": "0" * 64}
            leases = LeaseHarness()
            with (
                patched_leases(leases),
                patch.object(
                    sync_apply.physical_checkout,
                    "capture_physical_checkout_identity",
                    side_effect=[expected, expected, expected, changed],
                ),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("physical_checkout_identity_drift_final", result["state"])
            self.assertFalse(result["physical_identity_verified"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertEqual(
                "authoritative physical, local and remote readback before any new intent",
                result["next_action"],
            )
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(1, leases.release_calls)

    def test_git_effects_are_routed_through_fd_bound_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            calls: list[tuple[Path, list[str]]] = []

            def recording_runner(run_repo: Path, argv: list[str]) -> dict[str, object]:
                calls.append((run_repo, list(argv)))
                return git(run_repo, argv)

            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=recording_runner,
                )

            self.assertEqual("passed", result["receipt_status"])
            effect_calls = [
                (run_repo, argv)
                for run_repo, argv in calls
                if any(token in argv for token in {"fetch", "read-tree", "update-ref"})
            ]
            self.assertGreaterEqual(len(effect_calls), 3)
            for run_repo, argv in effect_calls:
                self.assertTrue(
                    str(run_repo).startswith("/proc/"),
                    (run_repo, argv),
                )
                self.assertTrue(
                    any(arg.startswith("--git-dir=/proc/") for arg in argv),
                    argv,
                )
                self.assertTrue(
                    any(arg.startswith("--work-tree=/proc/") for arg in argv),
                    argv,
                )

    def test_renamed_checkout_cannot_reenter_with_disjoint_path_leases(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, remote, base, target = self.fixture(root)
            retired = root / "retired"
            leases = ExactConflictLeaseHarness()
            nested_result: dict[str, object] | None = None
            swapped = False

            def outer_runner(
                run_repo: Path,
                argv: list[str],
            ) -> dict[str, object]:
                nonlocal nested_result, swapped
                if (
                    not swapped
                    and str(run_repo).startswith("/proc/")
                    and "fetch" in argv
                ):
                    repo.rename(retired)
                    renamed_physical = (
                        physical_checkout.capture_physical_checkout_identity(retired)
                    )
                    nested_result = sync_apply.apply(
                        repo=retired,
                        target_branch="main",
                        expected_local_head=base,
                        expected_remote_head=target,
                        expected_physical_identity_sha256=renamed_physical[
                            "physical_identity_sha256"
                        ],
                        remote="origin",
                        remote_target=str(remote),
                        confirmation=sync_apply.CONFIRMATION,
                        runner=git,
                        remote_head_reader=self.remote_reader(remote),
                        pinned_target_factory=self.pinned(remote),
                    )
                    swapped = True
                return git(run_repo, argv)

            with patched_leases(leases):
                outer_result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=outer_runner,
                )

            self.assertTrue(swapped)
            self.assertIsNotNone(nested_result)
            assert nested_result is not None
            self.assertEqual("blocked", nested_result["receipt_status"])
            self.assertEqual("lease_acquisition_blocked", nested_result["state"])
            self.assertEqual(
                "physical-checkout-root:"
                + str(os.stat(retired).st_dev)
                + ":"
                + str(os.stat(retired).st_ino),
                next(
                    key.removeprefix("component:")
                    for key in outer_result["resource_keys"]
                    if key.startswith("component:physical-checkout-root:")
                ),
            )
            self.assertEqual(target, git_stdout(retired, "rev-parse", "HEAD"))

    def test_same_path_replacement_during_effect_cannot_receive_git_effects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, remote, base, target = self.fixture(root)
            retired = root / "retired"
            leases = LeaseHarness()
            swapped = False

            def swapping_runner(
                run_repo: Path,
                argv: list[str],
            ) -> dict[str, object]:
                nonlocal swapped
                if (
                    not swapped
                    and str(run_repo).startswith("/proc/")
                    and "fetch" in argv
                ):
                    repo.rename(retired)
                    subprocess.run(
                        [
                            "git",
                            "clone",
                            "-q",
                            "-b",
                            "main",
                            str(remote),
                            str(repo),
                        ],
                        check=True,
                    )
                    subprocess.run(
                        ["git", "-C", str(repo), "reset", "-q", "--hard", base],
                        check=True,
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
                    swapped = True
                return git(run_repo, argv)

            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=swapping_runner,
                )

            self.assertTrue(swapped)
            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual(
                "physical_checkout_identity_drift_final",
                result["state"],
            )
            self.assertTrue(result["readback_required"])
            self.assertEqual(target, result["readback"]["head"])
            self.assertEqual(target, git_stdout(retired, "rev-parse", "HEAD"))
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))

    def test_successful_clean_fast_forward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("passed", result["receipt_status"])
            self.assertEqual("synced", result["state"])
            self.assertTrue(result["serialization_verified"])
            self.assertTrue(result["remote_head_verified"])
            self.assertTrue(result["fast_forward_verified"])
            self.assertTrue(result["preimage_verified"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("main", git_stdout(repo, "branch", "--show-current"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual("remote\n", (repo / "state.txt").read_text(encoding="utf-8"))
            self.assertEqual(1, leases.acquire_calls)
            self.assertEqual(["convergence"], leases.work_admission_modes)
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
            self.assertTrue(result["serialization_verified"])
            self.assertTrue(result["remote_head_verified"])
            self.assertFalse(result["fast_forward_verified"])
            self.assertTrue(result["preimage_verified"])
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
            self.assertTrue(second["remote_head_verified"])
            self.assertTrue(second["idempotent"])
            self.assertEqual(0, second_leases.acquire_calls)

    def test_branch_cas_failure_after_worktree_update_is_outcome_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def failing_runner(path: Path, argv: list[str]) -> dict[str, object]:
                if argv[-4:] == ["update-ref", "refs/heads/main", target, base]:
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
                if argv[-4:] == ["update-ref", "refs/heads/main", target, base]:
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

    def test_invalid_lease_snapshot_release_failure_surfaces_cleanup_required(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def malformed_acquire(
                owner_id: str,
                resource_keys: list[str],
                *,
                purpose: str,
                ttl_seconds: int,
                _work_admission_mode: str = "normal",
            ) -> dict[str, object]:
                acquired = leases.acquire(
                    owner_id,
                    resource_keys,
                    purpose=purpose,
                    ttl_seconds=ttl_seconds,
                    _work_admission_mode=_work_admission_mode,
                )
                snapshots = list(acquired["leases"])
                return {"leases": snapshots[:-1]}

            def failing_release(
                owner_id: str,
                resource_keys: list[str],
                *,
                expected_leases: list[dict[str, object]] | None = None,
                force: bool = False,
            ) -> dict[str, object]:
                del owner_id, resource_keys, expected_leases, force
                leases.release_calls += 1
                raise RuntimeError("cleanup state unknown")

            with (
                patch.object(
                    sync_apply.resources,
                    "acquire_resources",
                    malformed_acquire,
                ),
                patch.object(
                    sync_apply.resources,
                    "release_resources",
                    failing_release,
                ),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("lease_snapshot_invalid", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertTrue(result["lease_cleanup_required"])
            self.assertEqual("failed", result["lease_release"]["status"])
            self.assertEqual("RuntimeError", result["lease_release"]["error_class"])
            self.assertIn(
                "authoritative local and remote readback",
                result["next_action"],
            )
            self.assertIn("inspect and clean", result["next_action"])
            self.assertIn(
                "inspect and clean",
                result["lease_cleanup_next_action"],
            )
            self.assertEqual(1, leases.release_calls)
            self.assertEqual(4, len(leases.live))
            self.assertEqual(
                1,
                sum(
                    key.startswith("component:physical-checkout-root:")
                    for key in leases.live
                ),
            )
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))

    def test_post_lease_inspect_exception_with_release_failure_is_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def failing_inspect(
                _keys: list[str],
            ) -> dict[str, dict[str, object]]:
                raise RuntimeError("lease inspection unavailable")

            def failing_release(
                owner_id: str,
                resource_keys: list[str],
                *,
                expected_leases: list[dict[str, object]] | None = None,
                force: bool = False,
            ) -> dict[str, object]:
                del owner_id, resource_keys, expected_leases, force
                leases.release_calls += 1
                raise RuntimeError("cleanup state unknown")

            with (
                patch.object(sync_apply.resources, "acquire_resources", leases.acquire),
                patch.object(sync_apply.resources, "inspect_resources", failing_inspect),
                patch.object(sync_apply.resources, "release_resources", failing_release),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("outcome_unknown", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertFalse(result["serialization_verified"])
            self.assertFalse(result["remote_head_verified"])
            self.assertFalse(result["fast_forward_verified"])
            self.assertFalse(result["preimage_verified"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertTrue(result["lease_cleanup_required"])
            self.assertEqual("failed", result["lease_release"]["status"])
            self.assertEqual("RuntimeError", result["error_class"])
            self.assertEqual(1, leases.release_calls)
            self.assertIn(
                "authoritative local and remote readback",
                result["next_action"],
            )
            self.assertIn("inspect and clean", result["next_action"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))

    def test_post_lease_snapshot_exception_with_release_failure_is_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()
            real_snapshot = sync_apply._snapshot
            snapshot_calls = 0

            def failing_locked_snapshot(*args: object, **kwargs: object) -> dict[str, object]:
                nonlocal snapshot_calls
                snapshot_calls += 1
                if snapshot_calls >= 2:
                    raise sync_apply.PostMergeSyncApplyError(
                        "locked checkout readback unavailable"
                    )
                return real_snapshot(*args, **kwargs)

            def failing_release(
                owner_id: str,
                resource_keys: list[str],
                *,
                expected_leases: list[dict[str, object]] | None = None,
                force: bool = False,
            ) -> dict[str, object]:
                del owner_id, resource_keys, expected_leases, force
                leases.release_calls += 1
                raise RuntimeError("cleanup state unknown")

            with (
                patch.object(sync_apply.resources, "acquire_resources", leases.acquire),
                patch.object(sync_apply.resources, "inspect_resources", leases.inspect),
                patch.object(sync_apply.resources, "release_resources", failing_release),
                patch.object(sync_apply, "_snapshot", failing_locked_snapshot),
            ):
                result = self.apply(repo, remote, base, target)

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("outcome_unknown", result["state"])
            self.assertFalse(result["effect_started"])
            self.assertTrue(result["serialization_verified"])
            self.assertFalse(result["remote_head_verified"])
            self.assertFalse(result["fast_forward_verified"])
            self.assertFalse(result["preimage_verified"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertTrue(result["lease_cleanup_required"])
            self.assertEqual(
                "PostMergeSyncApplyError",
                result["readback"]["readback_error_type"],
            )
            self.assertEqual(1, leases.release_calls)
            self.assertIn(
                "authoritative local and remote readback",
                result["next_action"],
            )
            self.assertIn("inspect and clean", result["next_action"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))

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
            self.assertFalse(result["remote_head_verified"])
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
            self.assertFalse(result["remote_head_verified"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(1, leases.release_calls)

    def test_remote_drift_after_fetch_invalidates_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))

            def drifting_remote(stage: str, _effect_started: bool) -> str:
                return base if stage == "after_fetch" else target

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
            self.assertEqual("effect_failed_before_branch_cas", result["state"])
            self.assertTrue(result["effect_started"])
            self.assertFalse(result["branch_cas_started"])
            self.assertFalse(result["remote_head_verified"])
            self.assertFalse(result["retry_authorized"])
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(1, leases.release_calls)

    def test_tracking_ref_advance_before_branch_check_requires_readback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))
            leases = LeaseHarness()

            def branch_ref_missing_after_tracking_update(
                path: Path,
                argv: list[str],
            ) -> dict[str, object]:
                if argv[-4:] == [
                    "show-ref",
                    "--verify",
                    "--hash",
                    "refs/heads/main",
                ]:
                    return {
                        "returncode": 1,
                        "stdout": "",
                        "stderr": "",
                    }
                return git(path, argv)

            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    runner=branch_ref_missing_after_tracking_update,
                )

            self.assertEqual("failed", result["receipt_status"])
            self.assertEqual("outcome_unknown", result["state"])
            self.assertTrue(result["effect_started"])
            self.assertFalse(result["worktree_effect_started"])
            self.assertFalse(result["branch_cas_started"])
            self.assertTrue(result["remote_head_verified"])
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["readback_required"])
            self.assertFalse(result["post_state_verified"])
            self.assertEqual(
                target,
                git_stdout(repo, "rev-parse", "refs/remotes/origin/main"),
            )
            self.assertEqual(base, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual(base, git_stdout(repo, "rev-parse", "refs/heads/main"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(target, result["readback"]["tracking_head"])
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
            self.assertFalse(result["remote_head_verified"])
            self.assertEqual(base, result["remote_readback"])
            self.assertEqual(target, git_stdout(repo, "rev-parse", "HEAD"))
            self.assertEqual("", git_stdout(repo, "status", "--porcelain"))
            self.assertEqual(1, leases.release_calls)

    def test_final_remote_unreadable_invalidates_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo, remote, base, target = self.fixture(Path(tmp))

            def unreadable_remote(stage: str, _effect_started: bool) -> str:
                if stage in {"final", "error_readback"}:
                    raise RuntimeError("remote head unavailable")
                return target

            leases = LeaseHarness()
            with patched_leases(leases):
                result = self.apply(
                    repo,
                    remote,
                    base,
                    target,
                    remote_reader=unreadable_remote,
                )

            self.assertEqual("blocked", result["receipt_status"])
            self.assertEqual("effect_confirmed_remote_unreadable", result["state"])
            self.assertTrue(result["local_post_state_verified"])
            self.assertFalse(result["post_state_verified"])
            self.assertFalse(result["remote_head_verified"])
            self.assertTrue(result["readback_required"])
            self.assertFalse(result["retry_authorized"])
            self.assertEqual("RuntimeError", result["remote_readback_error_type"])
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
                _work_admission_mode: str = "normal",
            ) -> dict[str, object]:
                self.assertEqual("convergence", _work_admission_mode)
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