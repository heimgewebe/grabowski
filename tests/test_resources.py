from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
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

import grabowski_resources as resources

class ResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "resources.sqlite3"
        self.patch = patch.object(resources, "RESOURCE_DB", self.database)
        self.patch.start()

    def tearDown(self) -> None:
        self.patch.stop()
        self.temporary.cleanup()

    def scope_manifest(
        self, repository: Path, *, name: str, path: Path, effects: list[str] | None = None
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "repository": str(repository),
            "task_id": f"TASK-{name.upper()}",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": f"feat/{name}",
            "worktree": str(repository.parent / "worktrees" / name),
            "effects": effects or ["write"],
            "paths": [str(path)],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }

    def test_normalizes_typed_resource_keys(self) -> None:
        self.assertEqual(resources.normalize_resource_key("port:09222"), "port:9222")
        self.assertEqual(resources.normalize_resource_key("display::17"), "display:17")
        self.assertEqual(
            resources.normalize_resource_key(
                "component:github-branch:heimgewebe-grabowski:feat/captain"
            ),
            "component:github-branch:heimgewebe-grabowski:feat/captain",
        )
        with self.assertRaises(ValueError):
            resources.normalize_resource_key("service:github-branch:feat/captain")
        self.assertEqual(
            resources.normalize_resource_key(f"path:{self.root}/a/../b"),
            f"path:{self.root}/b",
        )
        with self.assertRaises(ValueError):
            resources.normalize_resource_key("path:relative")
        with self.assertRaises(ValueError):
            resources.normalize_resource_key("port:70000")

    def test_atomic_conflict_does_not_partially_acquire(self) -> None:
        resources.acquire_resources(
            "owner-a", ["port:9222"], purpose="browser", ttl_seconds=60
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b", ["port:9223", "port:9222"],
                purpose="conflict", ttl_seconds=60,
            )
        self.assertIsNone(resources.inspect_resource("port:9223"))
        self.assertEqual(resources.inspect_resource("port:9222")["owner_id"], "owner-a")

    def test_github_merge_gate_is_nonrenewable_even_for_same_owner(self) -> None:
        key = "gate:github-merge:heimgewebe-grabowski:main"
        first = resources.acquire_resources(
            "owner-a", [key], purpose="first merge dispatch", ttl_seconds=60
        )
        self.assertEqual("owner-a", first["leases"][0]["owner_id"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-a", [key], purpose="concurrent duplicate merge", ttl_seconds=60
            )
        self.assertEqual("owner-a", resources.inspect_resource(key)["owner_id"])

    def test_merge_guard_snapshots_existing_owner_leases_and_releases_only_guard_keys(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "owned.py"
        existing_path = f"path:{changed_path}"
        existing_main = "service:github-main:heimgewebe-grabowski"
        resources.acquire_resources(
            "task-owner",
            [existing_path, existing_main],
            purpose="active task resources",
            ttl_seconds=120,
        )
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        result = resources.acquire_merge_guard_resources(
            "captain-merge:guard-1",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        self.assertEqual([existing_path, existing_main], [
            item["resource_key"] for item in result["observed_leases"]
        ])
        self.assertEqual(
            sorted(set(keys) - {existing_main}), result["held_resource_keys"]
        )
        self.assertEqual([str(changed_path)], result["changed_paths"])
        resources.release_resources(
            "captain-merge:guard-1", result["held_resource_keys"]
        )
        self.assertEqual("task-owner", resources.inspect_resource(existing_path)["owner_id"])
        self.assertEqual("task-owner", resources.inspect_resource(existing_main)["owner_id"])
        self.assertEqual([existing_path, existing_main], [
            item["resource_key"] for item in resources.list_resources()
        ])

    def test_merge_guard_preserves_owner_repo_lease_and_blocks_only_changed_paths(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        repo_key = f"repo:{repository}"
        changed_path = repository / "src" / "target.py"
        resources.acquire_resources(
            "task-owner", [repo_key], purpose="active task repo", ttl_seconds=120
        )
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        result = resources.acquire_merge_guard_resources(
            "captain-merge:guard-2",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        self.assertEqual([repo_key], [
            item["resource_key"] for item in result["observed_leases"]
        ])
        self.assertEqual(sorted(keys), result["held_resource_keys"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "task-owner",
                [f"path:{changed_path}"],
                purpose="late overlapping same-owner write",
                ttl_seconds=60,
            )
        disjoint_key = f"path:{repository / 'src' / 'disjoint.py'}"
        disjoint = resources.acquire_resources(
            "task-owner",
            [disjoint_key],
            purpose="late disjoint same-owner write",
            ttl_seconds=60,
        )
        self.assertEqual(disjoint_key, disjoint["leases"][0]["resource_key"])
        resources.release_resources(
            "captain-merge:guard-2", result["held_resource_keys"]
        )
        self.assertEqual("task-owner", resources.inspect_resource(repo_key)["owner_id"])

    def test_merge_guard_allows_foreign_disjoint_paths_but_blocks_late_overlap(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        foreign_path = f"path:{repository / 'src' / 'foreign.py'}"
        resources.acquire_resources(
            "foreign-owner", [foreign_path], purpose="disjoint task", ttl_seconds=120
        )
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        result = resources.acquire_merge_guard_resources(
            "captain-merge:guard-3",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        self.assertEqual([], result["observed_leases"])
        self.assertEqual("foreign-owner", resources.inspect_resource(foreign_path)["owner_id"])
        second_disjoint = f"path:{repository / 'docs' / 'other.md'}"
        acquired = resources.acquire_resources(
            "another-owner",
            [second_disjoint],
            purpose="another disjoint task",
            ttl_seconds=60,
        )
        self.assertEqual(second_disjoint, acquired["leases"][0]["resource_key"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "another-owner",
                [f"path:{repository / 'src'}"],
                purpose="late directory overlap",
                ttl_seconds=60,
            )
        resources.release_resources(
            "captain-merge:guard-3", result["held_resource_keys"]
        )

    def test_active_merge_guard_requires_complete_mutating_scope_for_disjoint_work(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        disjoint_path = repository / "docs" / "other.md"
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:scope-guard",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
        )
        scope = self.scope_manifest(
            repository, name="disjoint", path=disjoint_path
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "foreign-scope",
                [f"path:{disjoint_path}"],
                purpose="unattested disjoint scope",
                ttl_seconds=60,
                metadata={"scope_manifest": scope},
            )
        accepted = resources.acquire_resources(
            "foreign-scope",
            [f"path:{disjoint_path}"],
            purpose="attested disjoint scope",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        self.assertEqual(
            f"path:{disjoint_path}", accepted["leases"][0]["resource_key"]
        )
        resources.release_resources(
            "captain-merge:scope-guard", guard["held_resource_keys"]
        )

    def test_merge_guard_blocks_preexisting_unattested_foreign_scope(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        disjoint_path = repository / "docs" / "other.md"
        scope = self.scope_manifest(
            repository, name="preexisting", path=disjoint_path
        )
        resources.acquire_resources(
            "foreign-scope",
            [f"path:{disjoint_path}"],
            purpose="preexisting unattested scope",
            ttl_seconds=60,
            metadata={"scope_manifest": scope},
        )
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:scope-guard-2",
                "task-owner",
                keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="atomic merge guard",
                ttl_seconds=60,
                metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
            )

    def test_merge_guard_rejects_foreign_repo_or_changed_path_lease(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        resources.acquire_resources(
            "foreign-owner",
            [f"path:{changed_path}"],
            purpose="overlapping task",
            ttl_seconds=120,
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:guard-4",
                "task-owner",
                keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="atomic merge guard",
                ttl_seconds=60,
                metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
            )
        resources.release_resources(
            "foreign-owner", [f"path:{changed_path}"]
        )
        resources.acquire_resources(
            "foreign-owner",
            [f"repo:{repository}"],
            purpose="broad repository task",
            ttl_seconds=120,
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:guard-5",
                "task-owner",
                keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="atomic merge guard",
                ttl_seconds=60,
                metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
            )

    def test_merge_guard_binds_base_and_head_branch_leases(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }
        for branch in ("main", "feat/work"):
            with self.subTest(branch=branch):
                self.database.unlink(missing_ok=True)
                branch_key = f"repo:{repository}:branch:{branch}"
                resources.acquire_resources(
                    "foreign-owner",
                    [branch_key],
                    purpose="foreign branch writer",
                    ttl_seconds=60,
                )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_merge_guard_resources(
                        "captain-merge:branch-guard",
                        "task-owner",
                        keys,
                        repository=str(repository),
                        changed_paths=[str(changed_path)],
                        purpose="atomic merge guard",
                        ttl_seconds=60,
                        metadata=metadata,
                    )

        self.database.unlink(missing_ok=True)
        unrelated_key = f"repo:{repository}:branch:feat/unrelated"
        resources.acquire_resources(
            "foreign-owner",
            [unrelated_key],
            purpose="unrelated branch writer",
            ttl_seconds=60,
        )
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:branch-guard-disjoint",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata=metadata,
        )
        self.assertEqual([], guard["observed_leases"])
        resources.release_resources(
            "captain-merge:branch-guard-disjoint", guard["held_resource_keys"]
        )
        self.assertEqual(
            "foreign-owner", resources.inspect_resource(unrelated_key)["owner_id"]
        )

    def test_active_merge_guard_blocks_relevant_branch_and_repo_operation_leases(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:active-branch-guard",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        for resource_key in (
            f"repo:{repository}:branch:main",
            f"repo:{repository}:branch:feat/work",
            f"repo:{repository}:operation:worktree-add:test",
        ):
            with self.subTest(resource_key=resource_key):
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_resources(
                        "late-owner",
                        [resource_key],
                        purpose="late relevant repository mutation",
                        ttl_seconds=60,
                    )
        unrelated_key = f"repo:{repository}:branch:feat/unrelated"
        accepted = resources.acquire_resources(
            "late-owner",
            [unrelated_key],
            purpose="late unrelated branch mutation",
            ttl_seconds=60,
        )
        self.assertEqual(unrelated_key, accepted["leases"][0]["resource_key"])
        resources.release_resources(
            "captain-merge:active-branch-guard", guard["held_resource_keys"]
        )

    def test_active_merge_guard_with_tampered_effect_key_binding_fails_closed(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            "component:github-repository:heimgewebe-grabowski",
            "component:github-branch:heimgewebe-grabowski:main",
            "component:github-branch:heimgewebe-grabowski:feat/work",
            "service:github-main:heimgewebe-grabowski",
            "service:github-pr:heimgewebe-grabowski-57",
            "gate:github-merge:heimgewebe-grabowski:main",
            "deployment:github:heimgewebe-grabowski:main",
        ]
        resources.acquire_merge_guard_resources(
            "captain-merge:tamper-guard",
            "task-owner",
            keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        gate = "gate:github-merge:heimgewebe-grabowski:main"
        with resources._database() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (gate,)
            ).fetchone()
            self.assertIsNotNone(row)
            metadata = json.loads(row["metadata_json"])
            metadata["merge_guard"]["effect_resource_keys_sha256"] = "0" * 64
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (resources._canonical_json(metadata), gate),
            )
            connection.commit()
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "late-owner",
                ["component:unrelated-but-cooperating"],
                purpose="must not proceed past malformed active merge guard",
                ttl_seconds=60,
            )

    def test_expired_lease_is_reclaimed(self) -> None:
        resources.acquire_resources(
            "owner-a", ["service:test.service"], purpose="first", ttl_seconds=60
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=? WHERE resource_key=?",
                (int(time.time()) - 1, "service:test.service"),
            )
            connection.commit()
        result = resources.acquire_resources(
            "owner-b", ["service:test.service"], purpose="second", ttl_seconds=60
        )
        self.assertEqual(result["leases"][0]["owner_id"], "owner-b")
        self.assertEqual(result["reclaimed"][0]["previous_owner_id"], "owner-a")

    def test_release_is_owner_bound_and_force_is_explicit(self) -> None:
        resources.acquire_resources("owner-a", ["display:9"], purpose="gui", ttl_seconds=60)
        with self.assertRaises(PermissionError):
            resources.release_resources("owner-b", ["display:9"])
        forced = resources.release_resources("owner-b", ["display:9"], force=True)
        self.assertEqual(len(forced["released"]), 1)
        self.assertIsNone(resources.inspect_resource("display:9"))

    def test_renew_requires_live_owned_lease(self) -> None:
        resources.acquire_resources(
            "owner-a", ["repo:/tmp/repo"], purpose="git", ttl_seconds=60
        )
        renewed = resources.renew_resources(
            "owner-a", ["repo:/tmp/repo"], ttl_seconds=120
        )
        self.assertGreater(renewed["leases"][0]["expires_at_unix"], int(time.time()) + 60)
        with self.assertRaises(PermissionError):
            resources.renew_resources("owner-b", ["repo:/tmp/repo"])

    def test_database_rejects_symlink(self) -> None:
        target = self.root / "real.sqlite3"
        target.write_bytes(b"")
        self.database.parent.mkdir(parents=True)
        self.database.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            resources.list_resources()

    def test_tool_audits_hash_only_metadata(self) -> None:
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as audit:
            result = resources.grabowski_resource_acquire(
                "owner-a", ["port:9222"], "browser", 60,
                {"private": "not returned"},
            )
        self.assertNotIn("metadata", result["leases"][0])
        self.assertIn("metadata_sha256", result["leases"][0])
        self.assertNotIn("private", str(audit.call_args.args[0]))

if __name__ == "__main__":
    unittest.main()
