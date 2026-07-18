from __future__ import annotations

from pathlib import Path
import json
import sqlite3
import sys
import tempfile
import threading
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

import grabowski_merge_guard as merge_guard
import grabowski_resources as resources

REPOSITORY_ID = merge_guard._merge_guard_identifier("repository", "heimgewebe/grabowski")
MAIN_BRANCH_ID = merge_guard._merge_guard_identifier("branch", "main")
WORK_BRANCH_ID = merge_guard._merge_guard_identifier("branch", "feat/work")

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

    def _promote_to_additive_schema_v2(self, *, incomplete: bool = False) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '1');
                CREATE TABLE leases (
                    resource_key TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    acquired_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    metadata_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    reclaimed_from_owner TEXT
                );
                """
            )
            connection.execute(
                """
                CREATE TABLE task_authority_adoptions (
                    task_id TEXT PRIMARY KEY,
                    guard_owner_id TEXT NOT NULL,
                    lease_owner_id TEXT NOT NULL,
                    acquired_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    binding_sha256 TEXT NOT NULL
                )
                """
            )
            if not incomplete:
                connection.execute(
                    """
                    CREATE TABLE task_terminalizations (
                        task_id TEXT PRIMARY KEY,
                        attempt INTEGER NOT NULL,
                        lease_owner_id TEXT NOT NULL,
                        terminal_state TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        task_projection_json TEXT NOT NULL,
                        task_projection_sha256 TEXT NOT NULL,
                        requested_resource_keys_json TEXT NOT NULL,
                        requested_resource_keys_sha256 TEXT NOT NULL,
                        prior_leases_json TEXT NOT NULL,
                        prior_leases_sha256 TEXT NOT NULL,
                        revoked_resource_keys_json TEXT NOT NULL,
                        missing_resource_keys_json TEXT NOT NULL,
                        observation_sha256 TEXT NOT NULL,
                        prepared_at_unix INTEGER NOT NULL,
                        leases_revoked_at_unix INTEGER NOT NULL,
                        projected_at_unix INTEGER,
                        lifecycle_receipt_sha256 TEXT,
                        recovery_status TEXT NOT NULL,
                        transition_sha256 TEXT NOT NULL
                    )
                    """
                )
            connection.execute(
                "UPDATE metadata SET value='2' WHERE key='schema_version'"
            )
            connection.execute(
                """
                INSERT INTO task_authority_adoptions(
                    task_id, guard_owner_id, lease_owner_id,
                    acquired_at_unix, expires_at_unix, binding_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("task-v2", "guard-v2", "lease-v2", 1, 2, "a" * 64),
            )
            connection.commit()

    def test_additive_schema_v2_preserves_task_lifetime_state(self) -> None:
        self._promote_to_additive_schema_v2()

        resources.acquire_resources(
            "owner-v2", ["port:9222"], purpose="schema v2 compatibility", ttl_seconds=60
        )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "2",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                ("task-v2", "guard-v2", "lease-v2", 1, 2, "a" * 64),
                connection.execute(
                    """
                    SELECT task_id, guard_owner_id, lease_owner_id,
                           acquired_at_unix, expires_at_unix, binding_sha256
                    FROM task_authority_adoptions
                    """
                ).fetchone(),
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM leases WHERE owner_id='owner-v2'"
                ).fetchone()[0],
            )

    def test_incomplete_additive_schema_v2_fails_closed(self) -> None:
        self._promote_to_additive_schema_v2(incomplete=True)

        with self.assertRaisesRegex(RuntimeError, "Unsupported resource database schema"):
            resources.count_resources()

    def test_raced_away_current_resource_store_is_not_recreated(self) -> None:
        with resources._database():
            pass
        self.database.unlink()
        with patch.object(resources, "_preflight_resource_store", return_value="2"):
            with self.assertRaises(sqlite3.OperationalError):
                resources._database()
        self.assertFalse(self.database.exists())

    def test_corrupt_resource_store_fails_without_side_effects(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        payload = b"not-a-sqlite-resource-store\x00corrupt"
        self.database.write_bytes(payload)
        before_stat = self.database.stat()
        with self.assertRaisesRegex(RuntimeError, "corrupt"):
            resources.count_resources()
        self.assertEqual(payload, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            [], list(self.database.parent.glob(self.database.name + "-*"))
        )
        self.assertEqual([], self._resource_migration_backups())

    def test_malformed_resource_metadata_fails_without_side_effects(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT, value TEXT NOT NULL);
                INSERT INTO metadata VALUES('schema_version', '1');
                INSERT INTO metadata VALUES('schema_version', '2');
                CREATE TABLE leases (resource_key TEXT PRIMARY KEY);
                """
            )
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        with self.assertRaisesRegex(RuntimeError, "metadata table is malformed"):
            resources.count_resources()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            [], list(self.database.parent.glob(self.database.name + "-*"))
        )
        self.assertEqual([], self._resource_migration_backups())

    def test_unknown_resource_schema_still_fails_closed(self) -> None:
        resources.count_resources()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE metadata SET value='3' WHERE key='schema_version'"
            )
            connection.commit()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_sidecars = {
            item.name for item in self.database.parent.glob(self.database.name + "-*")
        }
        with self.assertRaisesRegex(RuntimeError, "Unsupported resource database schema"):
            resources.count_resources()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            before_sidecars,
            {item.name for item in self.database.parent.glob(self.database.name + "-*")},
        )
        self.assertEqual([], self._resource_migration_backups())

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

    def test_count_resources_uses_complete_aggregate_and_owner_filter(self) -> None:
        resources.acquire_resources(
            "owner-a", ["port:9222"], purpose="first", ttl_seconds=60
        )
        resources.acquire_resources(
            "owner-b", ["port:9223"], purpose="second", ttl_seconds=60
        )

        self.assertEqual(2, resources.count_resources())
        self.assertEqual(1, resources.count_resources(owner_id="owner-a"))
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=0 WHERE owner_id=?",
                ("owner-b",),
            )
            connection.commit()
        self.assertEqual(1, resources.count_resources())
        self.assertEqual(2, resources.count_resources(include_expired=True))

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
        key = f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}"
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
        existing_main = f"service:github-main:{REPOSITORY_ID}"
        resources.acquire_resources(
            "task-owner",
            [existing_path, existing_main],
            purpose="active task resources",
            ttl_seconds=120,
        )
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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

    def test_delegated_merge_guard_rejects_same_owner_lease_added_after_signing(self) -> None:
        repository = self.root / "repo-delegated-growth"
        repository.mkdir()
        task_id = "a" * 24
        task_owner = f"task:{task_id}"
        existing_main = f"service:github-main:{REPOSITORY_ID}"
        resources.acquire_resources(
            task_owner,
            [existing_main],
            purpose="signed task lease",
            ttl_seconds=120,
            metadata={"task_id": task_id},
        )
        delegated_task = resources.task_lease_delegation_evidence(
            task_owner, task_id, [existing_main]
        )
        extra_repo = f"repo:{repository}"
        resources.acquire_resources(
            task_owner,
            [extra_repo],
            purpose="late task lease",
            ttl_seconds=120,
            metadata={"task_id": task_id},
        )
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            existing_main,
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
        ]

        with self.assertRaises(resources.ResourceConflict) as raised:
            resources.acquire_merge_guard_resources(
                "captain-merge:delegated-growth",
                task_owner,
                keys,
                repository=str(repository),
                changed_paths=[str(repository / "src" / "target.py")],
                purpose="atomic delegated merge guard",
                ttl_seconds=60,
                metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "diff_sha256": "b" * 64,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
                delegated_task=delegated_task,
            )

        self.assertEqual(extra_repo, raised.exception.resource_key)

    def test_task_terminalization_and_merge_adoption_are_serialized(self) -> None:
        repository = self.root / "repo-task-authority-race"
        repository.mkdir()
        task_id = "c" * 24
        task_owner = f"task:{task_id}"
        task_key = f"service:github-main:{REPOSITORY_ID}"
        resources.acquire_resources(
            task_owner,
            [task_key],
            purpose="task merge authority",
            ttl_seconds=120,
            metadata={"task_id": task_id, "attempt": 1},
        )
        delegated = resources.task_lease_delegation_evidence(
            task_owner, task_id, [task_key]
        )
        guard_keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            task_key,
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
        ]
        guard_owner = "captain-merge:task-authority-race"
        guard = resources.acquire_merge_guard_resources(
            guard_owner,
            task_owner,
            guard_keys,
            repository=str(repository),
            changed_paths=[str(repository / "src" / "target.py")],
            purpose="task authority race guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
            delegated_task=delegated,
        )
        self.assertEqual(
            task_id, guard["task_authority_adoption"]["task_id"]
        )
        self.assertLessEqual(
            guard["task_authority_adoption"]["expires_at_unix"],
            delegated["minimum_expires_at_unix"],
        )
        projection = {
            "task_id": task_id,
            "state": "completed",
            "updated_at_unix": int(time.time()),
            "launcher_json": "{}",
            "last_observation_json": "{}",
            "unit": f"grabowski-task-{task_id}-a1.service",
            "authoritative_unit": f"grabowski-task-{task_id}-a1.service",
            "attempt": 1,
        }
        with self.assertRaises(resources.ResourceConflict):
            resources.begin_task_terminalization(
                task_id,
                1,
                task_owner,
                "completed",
                [task_key],
                task_projection=projection,
                observation_sha256="d" * 64,
            )
        resources.release_resources(
            guard_owner, guard["held_resource_keys"]
        )
        resources.release_task_authority_adoption(guard_owner, task_id)

        transition = resources.begin_task_terminalization(
            task_id,
            1,
            task_owner,
            "completed",
            [task_key],
            task_projection=projection,
            observation_sha256="d" * 64,
        )
        self.assertEqual("leases_revoked", transition["phase"])
        with self.assertRaisesRegex(ValueError, "terminalized"):
            resources.acquire_merge_guard_resources(
                "captain-merge:task-authority-race-late",
                task_owner,
                guard_keys,
                repository=str(repository),
                changed_paths=[str(repository / "src" / "target.py")],
                purpose="late task authority race guard",
                ttl_seconds=60,
                metadata={
                    "merge_guard": {
                        "head_sha": "a" * 40,
                        "diff_sha256": "b" * 64,
                        "base_branch": "main",
                        "head_branch": "feat/work",
                    }
                },
                delegated_task=delegated,
            )

    def test_merge_guard_preserves_owner_repo_lease_and_blocks_only_changed_paths(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        repo_key = f"repo:{repository}"
        changed_path = repository / "src" / "target.py"
        resources.acquire_resources(
            "task-owner", [repo_key], purpose="active task repo", ttl_seconds=120
        )
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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

    def test_merge_guard_rejects_tampered_preexisting_foreign_scope_metadata(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        scope = {
            "schema_version": 1,
            "repository": str(repository),
            "task_id": "TASK-FOREIGN-TAMPER",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": "feat/foreign-tamper",
            "worktree": str(self.root / "worktrees" / "foreign-tamper"),
            "effects": ["write"],
            "paths": [],
            "components": ["preexisting-foreign-scope"],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        resource_key = "component:preexisting-foreign-scope"
        resources.acquire_resources(
            "foreign-owner",
            [resource_key],
            purpose="preexisting foreign scoped writer",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        with resources._database() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            self.assertIsNotNone(row)
            metadata = json.loads(row["metadata_json"])
            metadata["scope_manifest"]["repository"] = str(self.root / "other-repo")
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (resources._canonical_json(metadata), resource_key),
            )
            connection.commit()
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
        ]
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:tampered-foreign-scope",
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
        self.assertIsNone(
            resources.inspect_resource(
                f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}"
            )
        )

    def test_merge_guard_rejects_tampered_preexisting_owner_scope_metadata(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        scope = {
            "schema_version": 1,
            "repository": str(repository),
            "task_id": "TASK-OWNER-TAMPER",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": "feat/owner-tamper",
            "worktree": str(self.root / "worktrees" / "owner-tamper"),
            "effects": ["write"],
            "paths": [],
            "components": ["preexisting-owner-scope"],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        resource_key = "component:preexisting-owner-scope"
        resources.acquire_resources(
            "task-owner",
            [resource_key],
            purpose="preexisting owner scoped writer",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        with resources._database() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            self.assertIsNotNone(row)
            metadata = json.loads(row["metadata_json"])
            metadata["scope_manifest"]["repository"] = str(self.root / "other-repo")
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                (resources._canonical_json(metadata), resource_key),
            )
            connection.commit()
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
        ]
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:tampered-owner-scope",
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
        self.assertIsNone(
            resources.inspect_resource(
                f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}"
            )
        )

    def test_merge_guard_rejects_foreign_repo_or_changed_path_lease(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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

    def test_merge_guard_binds_repository_paths_containing_scope_markers(self) -> None:
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
        ]
        metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }
        for marker_name in ("branch", "operation"):
            with self.subTest(marker=marker_name, direction="existing-lease"):
                self.database.unlink(missing_ok=True)
                repository = self.root / f"repo:{marker_name}:literal"
                repository.mkdir(exist_ok=True)
                changed_path = repository / "src" / "target.py"
                repo_key = f"repo:{repository}"
                resources.acquire_resources(
                    "foreign-owner",
                    [repo_key],
                    purpose="broad repository task",
                    ttl_seconds=120,
                )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_merge_guard_resources(
                        f"captain-merge:{marker_name}-path-existing",
                        "task-owner",
                        keys,
                        repository=str(repository),
                        changed_paths=[str(changed_path)],
                        purpose="atomic merge guard",
                        ttl_seconds=60,
                        metadata=metadata,
                    )

            with self.subTest(marker=marker_name, direction="late-lease"):
                self.database.unlink(missing_ok=True)
                repository = self.root / f"repo:{marker_name}:literal"
                changed_path = repository / "src" / "target.py"
                repo_key = f"repo:{repository}"
                guard = resources.acquire_merge_guard_resources(
                    f"captain-merge:{marker_name}-path-active",
                    "task-owner",
                    keys,
                    repository=str(repository),
                    changed_paths=[str(changed_path)],
                    purpose="atomic merge guard",
                    ttl_seconds=60,
                    metadata=metadata,
                )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_resources(
                        "late-owner",
                        [repo_key],
                        purpose="late broad repository task",
                        ttl_seconds=60,
                    )
                resources.release_resources(
                    f"captain-merge:{marker_name}-path-active",
                    guard["held_resource_keys"],
                )

    def test_merge_guard_binds_base_and_head_branch_leases(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        keys = [
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
            f"component:github-repository:{REPOSITORY_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"component:github-branch:{REPOSITORY_ID}:{WORK_BRANCH_ID}",
            f"service:github-main:{REPOSITORY_ID}",
            f"service:github-pr:{REPOSITORY_ID}:57",
            f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
            f"deployment:github:{REPOSITORY_ID}:{MAIN_BRANCH_ID}",
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
        gate = f"gate:github-merge:{REPOSITORY_ID}:{MAIN_BRANCH_ID}"
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
                purpose="must not proceed past tampered outer metadata",
                ttl_seconds=60,
            )
        _, tampered_metadata_sha256 = resources._metadata(metadata)
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_sha256=? WHERE resource_key=?",
                (tampered_metadata_sha256, gate),
            )
            connection.commit()
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "late-owner",
                ["component:still-unrelated-but-cooperating"],
                purpose="must not proceed past invalid inner effect binding",
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

    def _resource_migration_backups(self) -> list[Path]:
        return sorted(
            self.database.parent.glob(
                f"{self.database.name}.schema-*.backup"
            )
        )

    def _create_resource_schema_v1(
        self,
    ) -> tuple[str, dict[str, object]]:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        metadata_json, metadata_sha256 = resources._metadata(
            {"task_id": "f" * 24, "purpose": "schema-migration"}
        )
        resource_key = "component:migration-semantic-preservation"
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '1');
                CREATE TABLE leases (
                    resource_key TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    acquired_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    metadata_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    reclaimed_from_owner TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO leases VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    resource_key,
                    "task:" + "f" * 24,
                    "semantic preservation fixture",
                    101,
                    102,
                    103,
                    metadata_sha256,
                    metadata_json,
                    "previous-owner",
                ),
            )
            connection.row_factory = sqlite3.Row
            original = dict(
                connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()
            )
            connection.commit()
        return resource_key, original

    def test_schema_v1_database_migrates_to_v2_without_losing_leases(self) -> None:
        self.database.parent.mkdir(parents=True)
        metadata_json, metadata_sha256 = resources._metadata({"task_id": "a" * 24})
        now = int(time.time())
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '1');
                CREATE TABLE leases (
                    resource_key TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    acquired_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    metadata_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    reclaimed_from_owner TEXT
                );
                """
            )
            connection.execute(
                "INSERT INTO leases VALUES(?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    "component:migration-preserved",
                    "task:" + "a" * 24,
                    "migration fixture",
                    now,
                    now,
                    now + 120,
                    metadata_sha256,
                    metadata_json,
                ),
            )
            connection.commit()

        listed = resources.list_resources(owner_id="task:" + "a" * 24)

        self.assertEqual(
            ["component:migration-preserved"],
            [item["resource_key"] for item in listed],
        )
        with sqlite3.connect(self.database) as migrated:
            version = migrated.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in migrated.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual("2", version)
        self.assertTrue(
            {"leases", "task_terminalizations", "task_authority_adoptions"}.issubset(
                tables
            )
        )
        backups = self._resource_migration_backups()
        self.assertEqual(1, len(backups))
        self.assertEqual(0o400, backups[0].stat().st_mode & 0o777)
        with sqlite3.connect(backups[0]) as backup:
            self.assertEqual(
                "1",
                backup.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                "ok", backup.execute("PRAGMA integrity_check").fetchone()[0]
            )
            self.assertEqual(
                "component:migration-preserved",
                backup.execute("SELECT resource_key FROM leases").fetchone()[0],
            )
        with resources._database() as reopened:
            self.assertEqual(0, reopened.total_changes)
        self.assertEqual(backups, self._resource_migration_backups())

    def test_resource_integrity_check_reports_busy_separately_from_corruption(self) -> None:
        class BusyConnection:
            def execute(self, statement: str) -> object:
                raise sqlite3.OperationalError("database is busy")

        with self.assertRaisesRegex(RuntimeError, "busy; retry"):
            resources._resource_sqlite_integrity(
                BusyConnection(),
                "Resource database",
            )

    def test_current_resource_store_opens_without_backup_or_writes(self) -> None:
        connection = resources._database()
        connection.close()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        self.assertEqual([], self._resource_migration_backups())
        reopened = resources._database()
        self.assertEqual(0, reopened.total_changes)
        reopened.close()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            before_names,
            sorted(item.name for item in self.database.parent.iterdir()),
        )
        self.assertEqual([], self._resource_migration_backups())

    def test_resource_schema_only_inventory_reports_migration_without_mutation(self) -> None:
        self._create_resource_schema_v1()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        inventory = resources.grabowski_resource_list(schema_only=True)
        self.assertEqual("resources", inventory["store"])
        self.assertEqual("1", inventory["observed_version"])
        self.assertEqual("2", inventory["current_version"])
        self.assertEqual(["1", "2"], inventory["supported_versions"])
        self.assertEqual("migration_required", inventory["status"])
        self.assertTrue(inventory["migration_required"])
        self.assertFalse(inventory["write_compatible"])
        self.assertFalse(inventory["mutation_performed"])
        self.assertEqual(
            [{
                "from": "1",
                "to": "2",
                "lock": "exclusive_store_directory",
                "transaction": "immediate",
                "verified_backup_required": True,
            }],
            inventory["migration_path"],
        )
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(before_names, sorted(item.name for item in self.database.parent.iterdir()))
        self.assertEqual([], self._resource_migration_backups())
        with self.assertRaisesRegex(ValueError, "schema_only must be boolean"):
            resources.grabowski_resource_list(schema_only=1)

    def test_current_resource_schema_inventory_is_byte_stable(self) -> None:
        connection = resources._database()
        connection.close()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        inventory = resources.grabowski_resource_list(schema_only=True)
        self.assertEqual("2", inventory["observed_version"])
        self.assertEqual("current", inventory["status"])
        self.assertTrue(inventory["write_compatible"])
        self.assertFalse(inventory["migration_required"])
        self.assertEqual("none", inventory["required_action"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(before_names, sorted(item.name for item in self.database.parent.iterdir()))

    def test_resource_schema_inventory_reads_uncheckpointed_future_wal(self) -> None:
        connection = resources._database()
        connection.close()
        keeper = sqlite3.connect(self.database)
        try:
            self.assertEqual("wal", keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            keeper.execute(
                "UPDATE metadata SET value='3' WHERE key='schema_version'"
            )
            keeper.commit()
            wal = Path(str(self.database) + "-wal")
            self.assertTrue(wal.exists())
            before_database = self.database.read_bytes()
            before_wal = wal.read_bytes()
            before_names = sorted(item.name for item in self.database.parent.iterdir())
            inventory = resources.grabowski_resource_list(schema_only=True)
            self.assertEqual("3", inventory["observed_version"])
            self.assertEqual("unsupported_future", inventory["status"])
            self.assertFalse(inventory["write_compatible"])
            self.assertFalse(inventory["mutation_performed"])
            self.assertIsNotNone(inventory["recovery_instruction"])
            self.assertEqual(before_database, self.database.read_bytes())
            self.assertEqual(before_wal, wal.read_bytes())
            self.assertEqual(
                before_names,
                sorted(item.name for item in self.database.parent.iterdir()),
            )
            self.assertEqual([], self._resource_migration_backups())
        finally:
            keeper.close()

    def test_resource_backup_includes_committed_uncheckpointed_wal_data(self) -> None:
        resource_key, _ = self._create_resource_schema_v1()
        keeper = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                "wal",
                keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0],
            )
            keeper.execute(
                "UPDATE leases SET updated_at_unix=999 WHERE resource_key=?",
                (resource_key,),
            )
            keeper.commit()
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            resources.list_resources()
            backup = self._resource_migration_backups()[0]
            with sqlite3.connect(backup) as connection:
                self.assertEqual(
                    999,
                    connection.execute(
                        "SELECT updated_at_unix FROM leases WHERE resource_key=?",
                        (resource_key,),
                    ).fetchone()[0],
                )
        finally:
            keeper.close()

    def test_resource_backup_failure_rolls_back_without_partial_schema(self) -> None:
        resource_key, original = self._create_resource_schema_v1()
        with patch.object(
            resources.os,
            "link",
            side_effect=OSError("simulated resource backup publish failure"),
        ):
            with self.assertRaisesRegex(OSError, "backup publish failure"):
                resources.list_resources()
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            self.assertEqual(
                "1",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                original,
                dict(connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()),
            )
            self.assertEqual(
                {"metadata", "leases"},
                {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                },
            )
        self.assertEqual([], self._resource_migration_backups())
        self.assertEqual(
            [], list(self.database.parent.glob(".*.backup.tmp"))
        )
        resources.list_resources()
        self.assertEqual(1, len(self._resource_migration_backups()))

    def test_interrupted_resource_migration_rolls_back_and_reuses_backup(self) -> None:
        resource_key, original = self._create_resource_schema_v1()
        with patch.object(
            resources,
            "_validate_resource_schema_current",
            side_effect=RuntimeError("simulated resource validation failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "validation failure"):
                resources.list_resources()
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            self.assertEqual(
                "1",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                original,
                dict(connection.execute(
                    "SELECT * FROM leases WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()),
            )
        backups = self._resource_migration_backups()
        self.assertEqual(1, len(backups))
        resources.list_resources()
        self.assertEqual(backups, self._resource_migration_backups())
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "2",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_tampered_resource_backup_blocks_retry(self) -> None:
        self._create_resource_schema_v1()
        with patch.object(
            resources,
            "_validate_resource_schema_current",
            side_effect=RuntimeError("stop after resource backup"),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after resource backup"):
                resources.list_resources()
        backup = self._resource_migration_backups()[0]
        backup.chmod(0o600)
        backup.write_bytes(b"not a sqlite database")
        with self.assertRaisesRegex(RuntimeError, "corrupt"):
            resources.list_resources()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "1",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_concurrent_resource_openers_create_one_verified_backup(self) -> None:
        self._create_resource_schema_v1()
        barrier = threading.Barrier(3)
        errors: list[BaseException] = []

        def open_store() -> None:
            try:
                barrier.wait(timeout=2)
                with resources._database():
                    pass
            except BaseException as exc:
                errors.append(exc)

        workers = [threading.Thread(target=open_store) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=2)
        for worker in workers:
            worker.join(timeout=5)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual([], errors)
        self.assertEqual(1, len(self._resource_migration_backups()))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "2",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_schema_v2_missing_terminalization_table_fails_closed(self) -> None:
        self.database.parent.mkdir(parents=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '2');
                CREATE TABLE leases (
                    resource_key TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    acquired_at_unix INTEGER NOT NULL,
                    updated_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    metadata_sha256 TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    reclaimed_from_owner TEXT
                );
                """
            )
        with self.assertRaisesRegex(RuntimeError, "Unsupported resource database schema"):
            resources.list_resources()

    def test_database_rejects_symlink(self) -> None:
        target = self.root / "real.sqlite3"
        target.write_bytes(b"")
        self.database.parent.mkdir(parents=True)
        self.database.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            resources.list_resources()

    def test_repository_scope_manifest_for_owner_reads_expired_owned_lease(self) -> None:
        key = f"repo:{self.root}"
        scope = self.scope_manifest(self.root, name="expired", path=self.root)
        resources.acquire_resources(
            "owner-a",
            [key],
            purpose="expired broad repository lease",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?", (key,)
            )
            connection.commit()
        recovered = resources.repository_scope_manifest_for_owner("owner-a", key)
        self.assertEqual(recovered, resources.nonconflict.normalize_scope_manifest(scope))

    def test_repository_scope_manifest_for_owner_rejects_owner_and_hash_drift(self) -> None:
        key = f"repo:{self.root}"
        scope = self.scope_manifest(self.root, name="integrity", path=self.root)
        resources.acquire_resources(
            "owner-a",
            [key],
            purpose="integrity-bound broad repository lease",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
        )
        with self.assertRaisesRegex(PermissionError, "another owner"):
            resources.repository_scope_manifest_for_owner("owner-b", key)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE leases SET metadata_json='{}' WHERE resource_key=?", (key,)
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "metadata hash"):
            resources.repository_scope_manifest_for_owner("owner-a", key)

    def test_public_tool_rejects_unscoped_repository_lease(self) -> None:
        with patch.object(resources.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(
                ValueError, "scope_manifest_complete=true"
            ):
                resources.grabowski_resource_acquire(
                    "owner-a",
                    [f"repo:{self.root}"],
                    "repository work",
                    60,
                )
        self.assertIsNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_public_tool_preserves_self_scoped_repository_lease(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/public-scoped-repo\n")
        key = f"repo:{self.root}:branch:feat/scoped"
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ):
            result = resources.grabowski_resource_acquire(
                "owner-a",
                [key],
                "scoped branch work",
                60,
            )
        self.assertEqual(result["leases"][0]["resource_key"], key)

    def test_scoped_repository_resource_root_scans_multiple_markers(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/multi-marker-repo\n")
        key = f"repo:{self.root}:branch:feat/work:operation:deploy"
        self.assertEqual(resources.scoped_repository_resource_root(key), str(self.root))

    def test_public_tool_rejects_manifest_on_self_scoped_repository_lease(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/public-scoped-repo\n")
        key = f"repo:{self.root}:branch:feat/scoped"
        scope = self.scope_manifest(self.root, name="scoped", path=self.root)
        with patch.object(resources.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(
                ValueError, "scoped repository leases must not include"
            ):
                resources.grabowski_resource_acquire(
                    "owner-a",
                    [key],
                    "scoped branch work",
                    60,
                    {
                        "scope_manifest": scope,
                        "scope_manifest_complete": True,
                    },
                )

    def test_public_tool_treats_existing_marker_paths_as_broad(self) -> None:
        for marker in ("branch", "operation"):
            with self.subTest(marker=marker):
                repository = self.root / f"repo:{marker}:literal"
                repository.mkdir()
                (repository / ".git").write_text("gitdir: /tmp/marker-repo\n")
                with patch.object(resources.operator, "_require_operator_mutation"):
                    with self.assertRaisesRegex(
                        ValueError, "scope_manifest_complete=true"
                    ):
                        resources.grabowski_resource_acquire(
                            "owner-a",
                            [f"repo:{repository}"],
                            "broad marker repository work",
                            60,
                        )
                self.database.unlink(missing_ok=True)

    def test_public_tool_rejects_manifest_for_other_scoped_repository(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/manifest-repo\n")
        other = self.root / "other-scoped-repository"
        other.mkdir()
        (other / ".git").write_text("gitdir: /tmp/other-scoped-repo\n")
        key = f"repo:{other}:branch:feat/scoped"
        scope = self.scope_manifest(self.root, name="mismatch", path=self.root)
        with patch.object(resources.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(ValueError, "scoped repository leases must not include"):
                resources.grabowski_resource_acquire(
                    "owner-a", [key], "mismatched scoped branch work", 60,
                    {"scope_manifest": scope, "scope_manifest_complete": True},
                )

    def test_public_tool_accepts_complete_repository_scope(self) -> None:
        scope = self.scope_manifest(
            self.root,
            name="public",
            path=self.root,
        )
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ):
            result = resources.grabowski_resource_acquire(
                "owner-a",
                [f"repo:{self.root}"],
                "repository work",
                60,
                {
                    "scope_manifest": scope,
                    "scope_manifest_complete": True,
                },
            )
        self.assertEqual(result["leases"][0]["resource_key"], f"repo:{self.root}")

    def test_public_tool_rejects_repository_scope_identity_mismatch(self) -> None:
        scope = self.scope_manifest(
            self.root,
            name="public",
            path=self.root,
        )
        other = self.root.parent / "other-repository"
        with patch.object(resources.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(
                ValueError, "must match metadata.scope_manifest repository"
            ):
                resources.grabowski_resource_acquire(
                    "owner-a",
                    [f"repo:{other}"],
                    "repository work",
                    60,
                    {
                        "scope_manifest": scope,
                        "scope_manifest_complete": True,
                    },
                )

    def test_public_tool_preserves_explicit_emergency_repository_exclusion(self) -> None:
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ):
            result = resources.grabowski_resource_acquire(
                "owner-a",
                [f"repo:{self.root}"],
                "emergency recovery",
                60,
                {"lease_mode": "emergency-recovery"},
            )
        self.assertEqual(result["leases"][0]["resource_key"], f"repo:{self.root}")

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
