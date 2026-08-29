from __future__ import annotations

from pathlib import Path
import hashlib
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
import grabowski_work_admission as work_admission

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

    def work_lane_metadata(
        self, repository: Path, *, target: Path, lane_id: str
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "grabowski.work_lane",
            "lane_id": lane_id,
            "repo": str(repository),
            "target_path": str(target),
        }

    def operation_scope(
        self,
        repository: Path,
        resource_key: str,
        *,
        effect_class: str = "publication",
        operation_class: str = "push",
        branches: list[str] | None = None,
        pull_requests: list[int] | None = None,
        scope_complete: bool = True,
    ) -> dict[str, object]:
        return resources.operation_scope_contract(
            resource_key,
            repository=str(repository),
            effect_class=effect_class,
            operation_class=operation_class,
            branches=branches or [],
            pull_requests=pull_requests or [],
            scope_complete=scope_complete,
        )

    def _pending_terminalization(
        self,
        task_id: str,
        *,
        prepared_at_unix: int,
    ) -> dict[str, object]:
        owner = f"task:{task_id}"
        key = f"component:pending-{task_id}"
        resources.acquire_resources(
            owner,
            [key],
            purpose="pending terminalization fixture",
            ttl_seconds=120,
            metadata={"task_id": task_id, "attempt": 1},
        )
        projection = {
            "task_id": task_id,
            "state": "failed",
            "updated_at_unix": prepared_at_unix,
            "launcher_json": "{}",
            "last_observation_json": "{}",
            "unit": f"grabowski-task-{task_id}-a1.service",
            "authoritative_unit": f"grabowski-task-{task_id}-a1.service",
            "attempt": 1,
        }
        with patch.object(resources, "_now", return_value=prepared_at_unix):
            return resources.begin_task_terminalization(
                task_id,
                1,
                owner,
                "failed",
                [key],
                task_projection=projection,
                observation_sha256="d" * 64,
            )

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

    def test_additive_schema_v2_migrates_and_preserves_task_lifetime_state(self) -> None:
        self._promote_to_additive_schema_v2()

        resources.acquire_resources(
            "owner-v2", ["port:9222"], purpose="schema v2 compatibility", ttl_seconds=60
        )

        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "3",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                "1",
                connection.execute(
                    "SELECT value FROM metadata "
                    "WHERE key='resource_lease_contract_version'"
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
            indexes = {
                row[1]
                for row in connection.execute(
                    "PRAGMA index_list(task_terminalizations)"
                )
            }
            self.assertIn("task_terminalizations_pending_idx", indexes)

    def test_incomplete_additive_schema_v2_fails_closed(self) -> None:
        self._promote_to_additive_schema_v2(incomplete=True)

        with self.assertRaisesRegex(RuntimeError, "Unsupported resource database schema"):
            resources.count_resources()

    def test_schema_v3_missing_lease_contract_is_promoted_without_schema_bump(self) -> None:
        resources.acquire_resources(
            "owner-before-contract",
            ["component:lease-contract-fixture"],
            purpose="preserve lease across contract metadata promotion",
            ttl_seconds=120,
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM metadata WHERE key='resource_lease_contract_version'"
            )
            connection.commit()
        before = self.database.read_bytes()
        before_stat = self.database.stat()

        inventory = resources.grabowski_resource_list(schema_only=True)

        self.assertEqual("3", inventory["observed_version"])
        self.assertIsNone(inventory["lease_contract_observed_version"])
        self.assertEqual("1", inventory["lease_contract_current_version"])
        self.assertEqual("missing", inventory["lease_contract_status"])
        self.assertEqual("lease_contract_metadata_required", inventory["status"])
        self.assertTrue(inventory["migration_required"])
        self.assertFalse(inventory["write_compatible"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)

        self.assertEqual(1, resources.count_resources())

        with sqlite3.connect(self.database) as connection:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            self.assertEqual("3", metadata["schema_version"])
            self.assertEqual("1", metadata["resource_lease_contract_version"])
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM leases "
                    "WHERE owner_id='owner-before-contract'"
                ).fetchone()[0],
            )
        backups = self._resource_migration_backups()
        self.assertEqual(1, len(backups))
        with sqlite3.connect(backups[0]) as backup:
            self.assertEqual(
                "3",
                backup.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertIsNone(
                backup.execute(
                    "SELECT value FROM metadata "
                    "WHERE key='resource_lease_contract_version'"
                ).fetchone()
            )

    def test_lease_projection_read_guard_pins_contract_and_rows_to_one_snapshot(self) -> None:
        key = "component:lease-snapshot-proof"
        resources.acquire_resources(
            "snapshot-owner",
            [key],
            purpose="prove contract and lease rows share one read snapshot",
            ttl_seconds=120,
        )
        with sqlite3.connect(self.database) as connection:
            mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        self.assertEqual("wal", str(mode).lower())

        with resources._resource_readonly_sqlite(self.database) as reader:
            self.assertEqual(
                "1",
                resources._begin_resource_lease_projection_read(
                    reader, quick_integrity=True
                ),
            )
            self.assertEqual(
                "snapshot-owner",
                reader.execute(
                    "SELECT owner_id FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0],
            )
            with sqlite3.connect(self.database) as writer:
                writer.execute(
                    "UPDATE metadata SET value='2' "
                    "WHERE key='resource_lease_contract_version'"
                )
                writer.execute(
                    "UPDATE leases SET owner_id='future-owner' WHERE resource_key=?",
                    (key,),
                )
                writer.commit()
            self.assertEqual(
                "1",
                reader.execute(
                    "SELECT value FROM metadata "
                    "WHERE key='resource_lease_contract_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                "snapshot-owner",
                reader.execute(
                    "SELECT owner_id FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0],
            )

        with sqlite3.connect(self.database) as current:
            self.assertEqual(
                "2",
                current.execute(
                    "SELECT value FROM metadata "
                    "WHERE key='resource_lease_contract_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                "future-owner",
                current.execute(
                    "SELECT owner_id FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0],
            )

    def test_future_lease_contract_fails_closed_without_side_effects(self) -> None:
        resources.count_resources()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE metadata SET value='2' "
                "WHERE key='resource_lease_contract_version'"
            )
            connection.commit()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_sidecars = sorted(
            item.name for item in self.database.parent.glob(self.database.name + "-*")
        )

        with self.assertRaisesRegex(RuntimeError, "lease contract version"):
            resources.count_resources()

        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            before_sidecars,
            sorted(
                item.name for item in self.database.parent.glob(self.database.name + "-*")
            ),
        )
        inventory = resources.grabowski_resource_list(schema_only=True)
        self.assertEqual("unsupported_future_lease_contract", inventory["status"])
        self.assertEqual("unsupported", inventory["lease_contract_status"])

    def test_malformed_lease_contract_fails_closed_without_side_effects(self) -> None:
        resources.count_resources()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE metadata SET value='not-a-version' "
                "WHERE key='resource_lease_contract_version'"
            )
            connection.commit()
        before = self.database.read_bytes()
        before_stat = self.database.stat()

        with self.assertRaisesRegex(RuntimeError, "lease contract version is malformed"):
            resources.count_resources()

        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)

    def test_raced_away_current_resource_store_is_not_recreated(self) -> None:
        with resources._database():
            pass
        self.database.unlink()
        with patch.object(resources, "_preflight_resource_store", return_value="3"):
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
                "UPDATE metadata SET value='4' WHERE key='schema_version'"
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
        self.assertEqual(resources.normalize_resource_key("host:heim-pc"), "host:heim-pc")
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

    def test_host_resource_lease_is_exclusive(self) -> None:
        key = "host:heim-pc"
        acquired = resources.acquire_resources(
            "owner-a", [key], purpose="exclusive host work", ttl_seconds=60
        )
        self.assertEqual(key, acquired["leases"][0]["resource_key"])
        self.assertEqual("owner-a", resources.inspect_resource(key)["owner_id"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b", [key], purpose="conflicting host work", ttl_seconds=60
            )

    def test_exact_path_resource_leases_remain_exact_identities(self) -> None:
        parent = f"path:{self.root / 'repo' / 'src'}"
        child = f"path:{self.root / 'repo' / 'src' / 'module.py'}"

        resources.acquire_resources(
            "owner-parent", [parent], purpose="exact parent", ttl_seconds=60
        )
        result = resources.acquire_resources(
            "owner-child", [child], purpose="exact child", ttl_seconds=60
        )

        self.assertEqual(child, result["leases"][0]["resource_key"])

    def test_public_resource_acquire_rejects_spoofed_work_lane_metadata(self) -> None:
        repository = self.root / "repo"
        lane_id = "f" * 32
        metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-spoof", lane_id=lane_id
        )

        with self.assertRaisesRegex(ValueError, "server-owned authority surface"):
            resources.grabowski_resource_acquire(
                f"lane:{lane_id}",
                [f"path:{repository / 'src'}"],
                "spoofed lane scope",
                60,
                metadata,
            )
        self.assertEqual(0, resources.count_resources())

    def test_work_lane_write_scopes_conflict_on_parent_child_overlap(self) -> None:
        repository = self.root / "repo"
        parent = f"path:{repository / 'src'}"
        child = f"path:{repository / 'src' / 'module.py'}"
        sibling = f"path:{repository / 'tests' / 'test_module.py'}"
        parent_metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-parent", lane_id="a" * 32
        )
        child_metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-child", lane_id="b" * 32
        )
        sibling_metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-sibling", lane_id="c" * 32
        )

        resources.acquire_resources(
            f"lane:{'a' * 32}",
            [parent],
            purpose="lane parent scope",
            ttl_seconds=60,
            metadata=parent_metadata,
        )
        resources.acquire_resources(
            f"lane:{'c' * 32}",
            [sibling],
            purpose="disjoint lane scope",
            ttl_seconds=60,
            metadata=sibling_metadata,
        )
        with self.assertRaises(resources.ResourceConflict) as raised:
            resources.acquire_resources(
                f"lane:{'b' * 32}",
                [child],
                purpose="nested lane scope",
                ttl_seconds=60,
                metadata=child_metadata,
            )
        self.assertEqual(parent, raised.exception.resource_key)

        resources.release_resources(f"lane:{'a' * 32}", [parent])
        resources.acquire_resources(
            f"lane:{'b' * 32}",
            [child],
            purpose="lane child scope",
            ttl_seconds=60,
            metadata=child_metadata,
        )
        with self.assertRaises(resources.ResourceConflict) as raised:
            resources.acquire_resources(
                f"lane:{'a' * 32}",
                [parent],
                purpose="lane parent scope",
                ttl_seconds=60,
                metadata=parent_metadata,
            )
        self.assertEqual(child, raised.exception.resource_key)

    def test_work_lane_scopes_conflict_across_nested_repository_boundaries(self) -> None:
        outer = self.root / "outer"
        nested = outer / "nested"
        parent = f"path:{nested}"
        child = f"path:{nested / 'module.py'}"
        outer_metadata = self.work_lane_metadata(
            outer, target=self.root / "lane-outer", lane_id="1" * 32
        )
        nested_metadata = self.work_lane_metadata(
            nested, target=self.root / "lane-nested", lane_id="2" * 32
        )

        resources.acquire_resources(
            f"lane:{'1' * 32}",
            [parent],
            purpose="outer repository subtree",
            ttl_seconds=60,
            metadata=outer_metadata,
        )

        with self.assertRaises(resources.ResourceConflict) as raised:
            resources.acquire_resources(
                f"lane:{'2' * 32}",
                [child],
                purpose="nested repository child",
                ttl_seconds=60,
                metadata=nested_metadata,
            )
        self.assertEqual(parent, raised.exception.resource_key)

    def test_work_lane_conflict_check_rejects_metadata_digest_drift(self) -> None:
        repository = self.root / "repo"
        parent = f"path:{repository / 'src'}"
        child = f"path:{repository / 'src' / 'module.py'}"
        lane_id = "3" * 32
        metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-drift", lane_id=lane_id
        )
        resources.acquire_resources(
            f"lane:{lane_id}",
            [parent],
            purpose="lane metadata drift fixture",
            ttl_seconds=60,
            metadata=metadata,
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_sha256=? WHERE resource_key=?",
                ("0" * 64, parent),
            )
            connection.commit()

        with self.assertRaises(resources.ResourceConflict) as raised:
            resources.acquire_resources(
                "owner-exact", [child], purpose="descendant", ttl_seconds=60
            )
        self.assertEqual(parent, raised.exception.resource_key)

    def test_work_lane_conflict_check_rejects_malformed_metadata(self) -> None:
        repository = self.root / "repo"
        parent = f"path:{repository / 'src'}"
        child = f"path:{repository / 'src' / 'module.py'}"
        lane_id = "4" * 32
        metadata = self.work_lane_metadata(
            repository, target=self.root / "lane-invalid", lane_id=lane_id
        )
        resources.acquire_resources(
            f"lane:{lane_id}",
            [parent],
            purpose="lane malformed metadata fixture",
            ttl_seconds=60,
            metadata=metadata,
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET metadata_json=? WHERE resource_key=?",
                ("{", parent),
            )
            connection.commit()

        with self.assertRaisesRegex(RuntimeError, "resource lease metadata is invalid"):
            resources.acquire_resources(
                "owner-exact", [child], purpose="descendant", ttl_seconds=60
            )

    def test_work_lane_scope_conflicts_with_exact_descendant_path(self) -> None:
        repository = self.root / "repo"
        parent = f"path:{repository / 'src'}"
        child = f"path:{repository / 'src' / 'module.py'}"
        lane_metadata = self.work_lane_metadata(
            repository, target=self.root / "lane", lane_id="d" * 32
        )

        resources.acquire_resources(
            f"lane:{'d' * 32}",
            [parent],
            purpose="lane subtree",
            ttl_seconds=60,
            metadata=lane_metadata,
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-exact", [child], purpose="exact child", ttl_seconds=60
            )

        resources.release_resources(f"lane:{'d' * 32}", [parent])
        resources.acquire_resources(
            "owner-exact", [child], purpose="exact child", ttl_seconds=60
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                f"lane:{'d' * 32}",
                [parent],
                purpose="lane subtree",
                ttl_seconds=60,
                metadata=lane_metadata,
            )

    def test_same_owner_may_hold_nested_work_lane_paths(self) -> None:
        repository = self.root / "repo"
        parent = f"path:{repository / 'src'}"
        child = f"path:{repository / 'src' / 'module.py'}"
        lane_metadata = self.work_lane_metadata(
            repository, target=self.root / "lane", lane_id="e" * 32
        )

        result = resources.acquire_resources(
            f"lane:{'e' * 32}",
            [parent, child],
            purpose="one lane owner",
            ttl_seconds=60,
            metadata=lane_metadata,
        )

        self.assertEqual(
            [parent, child], [item["resource_key"] for item in result["leases"]]
        )

    def test_normalizes_top_level_operation_resource_keys(self) -> None:
        key = (
            "operation:bug-fix:"
            "lane-6a6ba53c457c8191b71efd721ebf8df6:"
            "repo-heimgewebe-grabowski:pr-560:"
            f"head-{'a' * 40}:diff-{'b' * 64}:stage-review"
        )

        self.assertEqual(key, resources.normalize_resource_key(key))
        embedded = (
            f"repo:{self.root}/grabowski:operation:bug-fix:"
            "lane-6a6ba53c457c8191b71efd721ebf8df6"
        )
        self.assertEqual(embedded, resources.normalize_resource_key(embedded))
        self.assertNotEqual(key, resources.normalize_resource_key(embedded))

        invalid = (
            "operation:bug-fix",
            "operation:bug-fix:",
            "operation:bug-fix::lane-example",
            "operation:bug fix:lane-example",
            "operation:-bug-fix:lane-example",
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    resources.normalize_resource_key(candidate)

        with self.assertRaisesRegex(ValueError, "too large"):
            resources.normalize_resource_key(
                "operation:bug-fix:" + "a" * 4090
            )

    def test_operation_resource_leases_conflict_only_on_exact_identity(self) -> None:
        first = (
            "operation:bug-fix:lane-a:repo-grabowski:"
            "head-aaaaaaaa:stage-review"
        )
        second = (
            "operation:bug-fix:lane-b:repo-grabowski:"
            "head-aaaaaaaa:stage-review"
        )

        resources.acquire_resources(
            "owner-a", [first], purpose="first operation", ttl_seconds=60
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b", [first], purpose="duplicate operation", ttl_seconds=60
            )
        resources.acquire_resources(
            "owner-b", [second], purpose="disjoint operation", ttl_seconds=60
        )

        scoped = "operation:bug-fix:lane-c:repo-grabowski:stage-review"
        with self.assertRaisesRegex(
            ValueError, "do not accept repository scope manifests"
        ):
            resources.acquire_resources(
                "owner-c",
                [scoped],
                purpose="operation may not inherit repository authority",
                ttl_seconds=60,
                metadata={
                    "scope_manifest": self.scope_manifest(
                        self.root / "grabowski",
                        name="operation-scope",
                        path=self.root / "grabowski" / "src" / "example.py",
                    ),
                    "scope_manifest_complete": True,
                },
            )

        with sqlite3.connect(self.database) as connection:
            rows = connection.execute(
                "SELECT resource_key, owner_id FROM leases "
                "WHERE resource_key LIKE 'operation:%' ORDER BY resource_key"
            ).fetchall()
        self.assertEqual([(first, "owner-a"), (second, "owner-b")], rows)

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

    def test_exact_batch_inspection_uses_one_store_snapshot(self) -> None:
        first_key = "component:batch-inspection-first"
        second_key = "component:batch-inspection-second"
        resources.acquire_resources(
            "owner-a", [first_key], purpose="batch first", ttl_seconds=60
        )
        resources.acquire_resources(
            "owner-b", [second_key], purpose="batch second", ttl_seconds=60
        )

        with patch.object(resources, "_database", wraps=resources._database) as database:
            observed = resources.inspect_resources(
                [second_key, first_key, first_key]
            )
        self.assertEqual(database.call_count, 1)
        self.assertEqual(sorted(observed), [first_key, second_key])
        self.assertEqual(observed[first_key]["owner_id"], "owner-a")
        self.assertEqual(observed[second_key]["owner_id"], "owner-b")
        self.assertEqual(resources.inspect_resources([]), {})
        with self.assertRaisesRegex(ValueError, "sequence"):
            resources.inspect_resources(first_key)
        with self.assertRaisesRegex(ValueError, "128"):
            resources.inspect_resources(
                [f"component:batch-overflow-{index}" for index in range(129)]
            )

    def test_exact_batch_inspection_uses_current_lease_boundary(self) -> None:
        key = "component:batch-liveness-boundary"
        with patch.object(resources, "_now", return_value=100):
            acquired = resources.acquire_resources(
                "owner-a", [key], purpose="batch boundary", ttl_seconds=30
            )
        with patch.object(resources, "_now", return_value=129):
            self.assertEqual(resources.inspect_resources([key])[key], acquired["leases"][0])
        with patch.object(resources, "_now", return_value=130):
            self.assertEqual(resources.inspect_resources([key]), {})

    def test_current_readers_share_expiry_boundary_and_preserve_history(self) -> None:
        key = "component:lease-liveness-boundary"
        with patch.object(resources, "_now", return_value=100):
            acquired = resources.acquire_resources(
                "owner-a", [key], purpose="boundary", ttl_seconds=30
            )
        lease = acquired["leases"][0]
        self.assertEqual(lease["expires_at_unix"], 130)

        with patch.object(resources, "_now", return_value=129):
            self.assertEqual(resources.inspect_resource(key), lease)
            self.assertEqual(resources.list_resources(), [lease])
            self.assertEqual(resources.count_resources(), 1)

        with patch.object(resources, "_now", return_value=130):
            self.assertIsNone(resources.inspect_resource(key))
            self.assertEqual(resources.list_resources(), [])
            self.assertEqual(resources.count_resources(), 0)
            self.assertEqual(resources.list_resources(include_expired=True), [lease])
            self.assertEqual(resources.count_resources(include_expired=True), 1)
            with patch.object(resources.operator, "_require_operator_capability"):
                public = resources.grabowski_resource_inspect(key)
            self.assertEqual(public, {"resource_key": key, "lease": None})

    def test_malformed_expiry_never_grants_current_authority(self) -> None:
        key = "component:lease-liveness-malformed"
        with patch.object(resources, "_now", return_value=100):
            resources.acquire_resources(
                "owner-a", [key], purpose="malformed fixture", ttl_seconds=30
            )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=? WHERE resource_key=?",
                ("not-a-timestamp", key),
            )
            connection.commit()

        with patch.object(resources, "_now", return_value=110):
            self.assertIsNone(resources.inspect_resource(key))
            self.assertEqual(resources.list_resources(), [])
            self.assertEqual(resources.count_resources(), 0)
        self.assertEqual(resources.count_resources(include_expired=True), 1)

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

    def test_pending_terminalization_keyset_page_is_indexed_and_high_water_bound(self) -> None:
        initial = [
            self._pending_terminalization(
                format(index + 1, "024x"),
                prepared_at_unix=100 + index,
            )
            for index in range(6)
        ]
        first = resources.pending_task_terminalizations(limit=2)
        self.assertEqual(2, first["examined"])
        self.assertFalse(first["cycle_completed"])
        self.assertEqual(
            [item["task_id"] for item in initial[:2]],
            [item["task_id"] for item in first["terminalizations"]],
        )

        self._pending_terminalization("a" * 24, prepared_at_unix=99)
        self._pending_terminalization("b" * 24, prepared_at_unix=200)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM task_terminalizations WHERE task_id=?",
                (initial[2]["task_id"],),
            )
            connection.commit()

        pages = [first]
        while not pages[-1]["cycle_completed"]:
            pages.append(
                resources.pending_task_terminalizations(
                    limit=2,
                    cursor=pages[-1]["cursor_after"],
                    high_water=pages[-1]["high_water"],
                )
            )
        scanned = {
            item["task_id"]
            for page in pages
            for item in page["terminalizations"]
        }
        self.assertNotIn("a" * 24, scanned)
        self.assertNotIn("b" * 24, scanned)
        self.assertNotIn(initial[2]["task_id"], scanned)
        self.assertEqual(
            {initial[0]["task_id"], initial[1]["task_id"]}
            | {item["task_id"] for item in initial[3:]},
            scanned,
        )
        self.assertTrue(all(page["examined"] <= 2 for page in pages))
        self.assertEqual(
            {tuple(first["high_water"])},
            {tuple(page["high_water"]) for page in pages},
        )

        with sqlite3.connect(self.database) as connection:
            plan = list(
                connection.execute(
                    "EXPLAIN QUERY PLAN "
                    "SELECT * FROM task_terminalizations "
                    "WHERE phase='leases_revoked' "
                    "AND (prepared_at_unix > ? OR "
                    "(prepared_at_unix = ? AND task_id > ?)) "
                    "ORDER BY prepared_at_unix, task_id LIMIT ?",
                    (0, 0, "0" * 24, 3),
                )
            )
        self.assertIn(
            "task_terminalizations_pending_idx",
            " ".join(str(row) for row in plan),
        )

    def test_pending_terminalization_rejects_cursor_after_high_water(self) -> None:
        with self.subTest("later timestamp"):
            with self.assertRaisesRegex(
                ValueError,
                "cursor cannot be greater than high_water",
            ):
                resources.pending_task_terminalizations(
                    limit=1,
                    cursor=(101, "0" * 24),
                    high_water=(100, "f" * 24),
                )
        with self.subTest("same timestamp later task id"):
            with self.assertRaisesRegex(
                ValueError,
                "cursor cannot be greater than high_water",
            ):
                resources.pending_task_terminalizations(
                    limit=1,
                    cursor=(100, "b" * 24),
                    high_water=(100, "a" * 24),
                )

    def test_pending_terminalization_cursor_equal_to_high_water_completes(self) -> None:
        boundary = (100, "a" * 24)
        page = resources.pending_task_terminalizations(
            limit=1,
            cursor=boundary,
            high_water=boundary,
        )
        self.assertEqual(0, page["examined"])
        self.assertTrue(page["cycle_completed"])
        self.assertEqual(boundary, page["high_water"])
        self.assertIsNone(page["cursor_after"])

    def test_pending_terminalization_deleted_high_water_completes_truthfully(self) -> None:
        first = self._pending_terminalization(
            "1" * 24,
            prepared_at_unix=100,
        )
        high_water = self._pending_terminalization(
            "2" * 24,
            prepared_at_unix=101,
        )
        page = resources.pending_task_terminalizations(limit=1)
        self.assertFalse(page["cycle_completed"])
        self.assertEqual(first["task_id"], page["terminalizations"][0]["task_id"])
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM task_terminalizations WHERE task_id=?",
                (high_water["task_id"],),
            )
            connection.commit()
        completed = resources.pending_task_terminalizations(
            limit=1,
            cursor=page["cursor_after"],
            high_water=page["high_water"],
        )
        self.assertEqual(0, completed["examined"])
        self.assertTrue(completed["cycle_completed"])
        self.assertEqual(page["high_water"], completed["high_water"])

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

    def test_operation_scope_contract_is_fail_closed_and_publication_identity_bound(self) -> None:
        repository = self.root / "operation-contract-repo"
        repository.mkdir()
        push_key = f"repo:{repository}:operation:branch-publish:lane-a"
        contract = self.operation_scope(
            repository,
            push_key,
            branches=["feat/publish", "feat/publish"],
        )
        self.assertEqual("publication", contract["effect_class"])
        self.assertEqual("push", contract["operation_class"])
        self.assertEqual(["feat/publish"], contract["branches"])
        self.assertTrue(contract["scope_complete"])

        spoofed_key = f"repo:{repository}:operation:worktree-add:lane-a"
        with self.assertRaisesRegex(
            ValueError, "does not match the operation resource class"
        ):
            self.operation_scope(
                repository,
                spoofed_key,
                branches=["feat/publish"],
            )
        with self.assertRaisesRegex(ValueError, "must be complete"):
            self.operation_scope(
                repository,
                push_key,
                branches=["feat/publish"],
                scope_complete=False,
            )

        for effect_class, operation_class, suffix in (
            ("merge", "merge", "pr-merge:lane-a"),
            ("deploy", "deploy", "runtime-deploy:lane-a"),
            ("worktree_admin", "worktree-admin", "worktree-add:lane-a"),
            ("unknown", "unknown", "legacy:lane-a"),
        ):
            with self.subTest(effect_class=effect_class):
                key = f"repo:{repository}:operation:{suffix}"
                classified = self.operation_scope(
                    repository,
                    key,
                    effect_class=effect_class,
                    operation_class=operation_class,
                )
                self.assertEqual(effect_class, classified["effect_class"])
                self.assertEqual(operation_class, classified["operation_class"])
                self.assertEqual([], classified["branches"])
                self.assertEqual([], classified["pull_requests"])

    def test_merge_guard_allows_existing_disjoint_pr_publication_operation(self) -> None:
        repository = self.root / "existing-publication-repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        operation_key = (
            f"repo:{repository}:operation:pr-create-or-update:lane-a"
        )
        resources.acquire_resources(
            "foreign-publication-owner",
            [operation_key],
            purpose="disjoint PR publication",
            ttl_seconds=120,
            metadata={
                "operation_scope": self.operation_scope(
                    repository,
                    operation_key,
                    operation_class="pr-publication",
                    branches=["feat/unrelated"],
                    pull_requests=[99],
                )
            },
        )
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:existing-publication",
            "task-owner",
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="merge with disjoint publication",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "pull_request": 57,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        self.assertEqual([], guard["observed_leases"])
        self.assertEqual(1, len(guard["operation_nonconflicts"]))
        proof = guard["operation_nonconflicts"][0]
        self.assertEqual("existing-operation-to-merge", proof["direction"])
        self.assertEqual("pr-publication", proof["operation_class"])
        self.assertEqual([], proof["branch_overlap"])
        self.assertEqual([], proof["pull_request_overlap"])
        self.assertRegex(guard["operation_nonconflicts_sha256"], r"[0-9a-f]{64}\Z")
        self.assertEqual(
            "foreign-publication-owner",
            resources.inspect_resource(operation_key)["owner_id"],
        )
        resources.release_resources(
            "captain-merge:existing-publication", guard["held_resource_keys"]
        )

    def test_active_merge_guard_allows_late_disjoint_push_operation(self) -> None:
        repository = self.root / "late-publication-repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:late-publication",
            "task-owner",
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="active merge",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "pull_request": 57,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        operation_key = f"repo:{repository}:operation:branch-publish:lane-a"
        acquired = resources.acquire_resources(
            "late-publication-owner",
            [operation_key],
            purpose="late disjoint push",
            ttl_seconds=60,
            metadata={
                "operation_scope": self.operation_scope(
                    repository,
                    operation_key,
                    branches=["feat/unrelated"],
                )
            },
        )
        self.assertEqual(1, len(acquired["merge_guard_nonconflicts"]))
        proof = acquired["merge_guard_nonconflicts"][0]
        self.assertEqual("late-operation-to-active-merge", proof["direction"])
        self.assertEqual("push", proof["operation_class"])
        self.assertEqual([], proof["branch_overlap"])
        self.assertEqual([], proof["pull_request_overlap"])
        resources.release_resources("late-publication-owner", [operation_key])
        resources.release_resources(
            "captain-merge:late-publication", guard["held_resource_keys"]
        )

    def test_late_disjoint_publication_persists_nonconflict_audit(self) -> None:
        repository = self.root / "late-publication-audit-repo"
        repository.mkdir()
        (repository / ".git").write_text(
            "gitdir: /tmp/late-publication-audit-repo\n", encoding="utf-8"
        )
        changed_path = repository / "src" / "target.py"
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        guard = resources.acquire_merge_guard_resources(
            "captain-merge:late-publication-audit",
            "task-owner",
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="active merge",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                    "pull_request": 57,
                    "base_branch": "main",
                    "head_branch": "feat/work",
                }
            },
        )
        operation_key = f"repo:{repository}:operation:branch-publish:lane-a"
        audit_log = self.root / "audit" / "write-audit.jsonl"
        audit_log.parent.mkdir(mode=0o700)
        with patch.object(
            resources.operator, "_require_operator_mutation"
        ), patch.object(resources.base, "AUDIT_LOG", audit_log):
            acquired = resources.grabowski_resource_acquire(
                "late-publication-audit-owner",
                [operation_key],
                "late disjoint push",
                60,
                {
                    "operation_scope": self.operation_scope(
                        repository,
                        operation_key,
                        branches=["feat/unrelated"],
                    )
                },
            )
        resources.release_resources(
            "late-publication-audit-owner", [operation_key]
        )

        self.assertIsNone(resources.inspect_resource(operation_key))
        audit_records = [
            json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()
        ]
        acquire_audit = next(
            record
            for record in audit_records
            if record["operation"] == "resource-acquire"
        )
        proofs = acquired["merge_guard_nonconflicts"]
        self.assertEqual(1, len(proofs))
        self.assertEqual(proofs, acquire_audit["merge_guard_nonconflicts"])
        self.assertEqual(
            hashlib.sha256(resources._canonical_json(proofs).encode("utf-8")).hexdigest(),
            acquire_audit["merge_guard_nonconflicts_sha256"],
        )
        resources.release_resources(
            "captain-merge:late-publication-audit", guard["held_resource_keys"]
        )

    def test_merge_guard_keeps_overlapping_and_nonpublication_operations_serialized(self) -> None:
        repository = self.root / "serialized-operation-repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        guard_metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "diff_sha256": "b" * 64,
                "pull_request": 57,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }

        overlapping_key = f"repo:{repository}:operation:branch-publish:overlap"
        resources.acquire_resources(
            "overlap-owner",
            [overlapping_key],
            purpose="overlapping publication",
            ttl_seconds=60,
            metadata={
                "operation_scope": self.operation_scope(
                    repository,
                    overlapping_key,
                    branches=["feat/work"],
                )
            },
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:overlap-existing",
                "task-owner",
                guard_keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="must serialize overlapping publication",
                ttl_seconds=60,
                metadata=guard_metadata,
            )

        cases = (
            ("merge", "merge", "pr-merge:lane"),
            ("deploy", "deploy", "runtime-deploy:lane"),
            ("worktree_admin", "worktree-admin", "worktree-add:lane"),
            ("unknown", "unknown", "legacy:lane"),
        )
        for effect_class, operation_class, suffix in cases:
            with self.subTest(direction="existing", effect_class=effect_class):
                self.database.unlink(missing_ok=True)
                operation_key = f"repo:{repository}:operation:{suffix}"
                resources.acquire_resources(
                    "unsafe-owner",
                    [operation_key],
                    purpose="explicit unsafe operation",
                    ttl_seconds=60,
                    metadata={
                        "operation_scope": self.operation_scope(
                            repository,
                            operation_key,
                            effect_class=effect_class,
                            operation_class=operation_class,
                        )
                    },
                )
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_merge_guard_resources(
                        f"captain-merge:unsafe-{effect_class}",
                        "task-owner",
                        guard_keys,
                        repository=str(repository),
                        changed_paths=[str(changed_path)],
                        purpose="unsafe operation remains serialized",
                        ttl_seconds=60,
                        metadata=guard_metadata,
                    )

        self.database.unlink(missing_ok=True)
        active = resources.acquire_merge_guard_resources(
            "captain-merge:late-overlap",
            "task-owner",
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="active merge for overlap",
            ttl_seconds=60,
            metadata=guard_metadata,
        )
        late_overlap = f"repo:{repository}:operation:pr-create-or-update:late-overlap"
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "late-overlap-owner",
                [late_overlap],
                purpose="late overlapping PR publication",
                ttl_seconds=60,
                metadata={
                    "operation_scope": self.operation_scope(
                        repository,
                        late_overlap,
                        operation_class="pr-publication",
                        pull_requests=[57],
                    )
                },
            )
        for effect_class, operation_class, suffix in cases:
            with self.subTest(direction="late", effect_class=effect_class):
                late_key = f"repo:{repository}:operation:{suffix}:late"
                with self.assertRaises(resources.ResourceConflict):
                    resources.acquire_resources(
                        f"late-{effect_class}-owner",
                        [late_key],
                        purpose="late unsafe operation remains serialized",
                        ttl_seconds=60,
                        metadata={
                            "operation_scope": self.operation_scope(
                                repository,
                                late_key,
                                effect_class=effect_class,
                                operation_class=operation_class,
                            )
                        },
                    )

        legacy_publication = f"repo:{repository}:operation:branch-publish:legacy"
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "legacy-owner",
                [legacy_publication],
                purpose="legacy publication without scope metadata",
                ttl_seconds=60,
            )
        resources.release_resources(
            "captain-merge:late-overlap", active["held_resource_keys"]
        )

        self.database.unlink(missing_ok=True)
        legacy_guard_metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "diff_sha256": "b" * 64,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }
        legacy_guard = resources.acquire_merge_guard_resources(
            "captain-merge:legacy-no-pr",
            "task-owner",
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="legacy merge without PR binding",
            ttl_seconds=60,
            metadata=legacy_guard_metadata,
        )
        late_pr = f"repo:{repository}:operation:pr-create-or-update:legacy-guard"
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "late-pr-owner",
                [late_pr],
                purpose="PR publication requires exact merge PR identity",
                ttl_seconds=60,
                metadata={
                    "operation_scope": self.operation_scope(
                        repository,
                        late_pr,
                        operation_class="pr-publication",
                        branches=["feat/unrelated"],
                        pull_requests=[99],
                    )
                },
            )
        resources.release_resources(
            "captain-merge:legacy-no-pr", legacy_guard["held_resource_keys"]
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

    def test_public_acquire_audits_compact_reclamation_evidence(self) -> None:
        key = "service:reclamation-audit.service"
        audit_log = self.root / "audit" / "write-audit.jsonl"
        audit_log.parent.mkdir(mode=0o700)
        with patch.object(
            resources.operator, "_require_operator_mutation"
        ), patch.object(resources.base, "AUDIT_LOG", audit_log):
            resources.grabowski_resource_acquire(
                "owner-a", [key], "first", 60
            )
        expired_at = int(time.time()) - 1
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=? WHERE resource_key=?",
                (expired_at, key),
            )
            connection.commit()
        with patch.object(
            resources.operator, "_require_operator_mutation"
        ), patch.object(resources.base, "AUDIT_LOG", audit_log):
            result = resources.grabowski_resource_acquire(
                "owner-b", [key], "second", 60
            )

        audit_records = [
            json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()
        ]
        acquire_records = [
            record for record in audit_records if record["operation"] == "resource-acquire"
        ]
        self.assertNotIn("reclamation_evidence", acquire_records[0])
        acquire_audit = acquire_records[-1]
        self.assertEqual(result["reclaimed"][0]["resource_key"], key)
        self.assertEqual(acquire_audit["resource_keys"], [key])
        self.assertEqual(acquire_audit["reclaimed_count"], 1)
        self.assertEqual(
            acquire_audit["reclamation_evidence"],
            [
                {
                    "resource_index": 0,
                    "previous_owner_id": "owner-a",
                    "previous_expires_at_unix": expired_at,
                }
            ],
        )
        self.assertNotIn("resource_key", acquire_audit["reclamation_evidence"][0])

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

    def test_missing_renew_uses_typed_reacquisition_signal(self) -> None:
        with self.assertRaisesRegex(
            resources.ResourceLeaseMissing, "Unknown resource lease"
        ):
            resources.renew_resources(
                "owner-a", ["component:typed-missing"], ttl_seconds=60
            )

    def test_expired_renew_uses_typed_reacquisition_signal(self) -> None:
        key = "component:typed-expiry"
        with patch.object(resources, "_now", return_value=100):
            resources.acquire_resources(
                "owner-a", [key], purpose="typed expiry", ttl_seconds=30
            )
        with patch.object(resources, "_now", return_value=130):
            with self.assertRaisesRegex(
                resources.ResourceLeaseExpired, "Resource lease has expired"
            ):
                resources.renew_resources("owner-a", [key], ttl_seconds=60)

    def test_live_same_owner_reentry_is_identity_bound_and_never_shortens(self) -> None:
        key = "component:same-owner-reentry"
        with patch.object(resources, "_now", return_value=100):
            first = resources.acquire_resources(
                "owner-a",
                [key],
                purpose="stable purpose",
                ttl_seconds=120,
                metadata={"scope": "stable"},
            )
        with patch.object(resources, "_now", return_value=110):
            second = resources.acquire_resources(
                "owner-a",
                [key],
                purpose="stable purpose",
                ttl_seconds=30,
                metadata={"scope": "stable"},
            )
        self.assertEqual(first["leases"][0]["acquired_at_unix"], 100)
        self.assertEqual(second["leases"][0]["acquired_at_unix"], 100)
        self.assertEqual(second["leases"][0]["updated_at_unix"], 100)
        self.assertEqual(second["leases"][0]["expires_at_unix"], 220)
        self.assertEqual(second["reclaimed"], [])

        with patch.object(resources, "_now", return_value=120):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                resources.acquire_resources(
                    "owner-a",
                    [key],
                    purpose="different purpose",
                    ttl_seconds=60,
                    metadata={"scope": "stable"},
                )
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                resources.acquire_resources(
                    "owner-a",
                    [key],
                    purpose="stable purpose",
                    ttl_seconds=60,
                    metadata={"scope": "different"},
                )
        with patch.object(resources, "_now", return_value=120):
            self.assertEqual(resources.inspect_resource(key), second["leases"][0])

    def test_same_owner_rebind_restores_journaled_identity_after_expiry(self) -> None:
        key = "component:bureau-resume-rebind"
        owner = "bureau-run:BUR-RUN-20260803T112652Z-594b4414fc"
        original_metadata = {
            "task_id": "WELTGEWEBE-OS-V1-T065",
            "run_id": "BUR-RUN-20260803T112652Z-594b4414fc",
            "claim_intent_sha256": "d" * 64,
            "pickup_schema_version": 1,
            "pickup_group": "other",
        }
        with patch.object(resources, "_now", return_value=100):
            original = resources.acquire_resources(
                owner,
                [key],
                purpose="Bureau coordinated pickup original group other",
                ttl_seconds=30,
                metadata=original_metadata,
            )
        with patch.object(resources, "_now", return_value=140):
            drifted = resources.acquire_resources(
                owner,
                [key],
                purpose="Resume existing Bureau task without claim binding",
                ttl_seconds=120,
                metadata={"task_id": "WELTGEWEBE-OS-V1-T065"},
            )
        with patch.object(resources, "_now", return_value=150):
            rebound = resources.rebind_same_owner_resources(
                owner,
                [key],
                purpose="Bureau coordinated pickup original group other",
                ttl_seconds=180,
                metadata=original_metadata,
                expected_current_leases=[
                    resources._release_lease_snapshot(drifted["leases"][0])
                ],
                expected_original_leases=[
                    resources._release_lease_snapshot(original["leases"][0])
                ],
            )
        self.assertEqual(
            original["leases"][0]["metadata_sha256"],
            rebound["leases"][0]["metadata_sha256"],
        )
        self.assertEqual(
            "Bureau coordinated pickup original group other",
            rebound["leases"][0]["purpose"],
        )
        self.assertEqual(140, rebound["leases"][0]["acquired_at_unix"])
        self.assertEqual(330, rebound["leases"][0]["expires_at_unix"])

    def test_same_owner_rebind_preserves_server_work_admission_after_expiry(self) -> None:
        (self.root / ".git").mkdir()
        key = f"repo:{self.root}"
        scope = self.scope_manifest(
            self.root, name="server-admission-rebind", path=self.root
        )
        metadata = {
            "scope_manifest": scope,
            "scope_manifest_complete": True,
        }

        def assessor(**_kwargs: object) -> dict[str, object]:
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "blocker_codes": [],
                "blockers": [],
                "read_only": True,
            }

        with patch.object(resources, "_now", return_value=100):
            original = resources.acquire_resources(
                "owner-a",
                [key],
                purpose="stable server admission rebind",
                ttl_seconds=30,
                metadata=metadata,
                admission_assessor=assessor,
            )
        with resources._database() as connection:
            original_row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(original_row)
        original_persisted_metadata = json.loads(original_row["metadata_json"])
        self.assertIn("work_admission", original_persisted_metadata)

        original_snapshot = resources._release_lease_snapshot(original["leases"][0])
        with patch.object(resources, "_now", return_value=140):
            rebound = resources.rebind_same_owner_resources(
                "owner-a",
                [key],
                purpose="stable server admission rebind",
                ttl_seconds=60,
                metadata=metadata,
                expected_current_leases=[original_snapshot],
                expected_original_leases=[original_snapshot],
            )

        self.assertEqual(
            original["leases"][0]["metadata_sha256"],
            rebound["leases"][0]["metadata_sha256"],
        )
        with resources._database() as connection:
            rebound_row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(rebound_row)
        self.assertEqual(
            original_persisted_metadata, json.loads(rebound_row["metadata_json"])
        )

    def test_same_owner_rebind_rejects_drifted_server_work_admission(self) -> None:
        (self.root / ".git").mkdir()
        key = f"repo:{self.root}"
        scope = self.scope_manifest(
            self.root, name="drifted-server-admission-rebind", path=self.root
        )
        metadata = {
            "scope_manifest": scope,
            "scope_manifest_complete": True,
        }

        def assessor(**_kwargs: object) -> dict[str, object]:
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "blocker_codes": [],
                "blockers": [],
                "read_only": True,
            }

        with patch.object(resources, "_now", return_value=100):
            original = resources.acquire_resources(
                "owner-a",
                [key],
                purpose="stable drifted server admission rebind",
                ttl_seconds=30,
                metadata=metadata,
                admission_assessor=assessor,
            )
        original_snapshot = resources._release_lease_snapshot(original["leases"][0])
        with resources._database() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
            self.assertIsNotNone(row)
            drifted_metadata = json.loads(row["metadata_json"])
            drifted_metadata["work_admission"] = dict(
                drifted_metadata["work_admission"]
            )
            drifted_metadata["work_admission"]["assessment_sha256"] = "b" * 64
            metadata_json, metadata_sha256 = resources._metadata(drifted_metadata)
            connection.execute(
                "UPDATE leases SET metadata_json=?, metadata_sha256=? WHERE resource_key=?",
                (metadata_json, metadata_sha256, key),
            )
            current_row = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(current_row)
        current_snapshot = resources._release_lease_snapshot(current_row)

        with patch.object(resources, "_now", return_value=140):
            with self.assertRaisesRegex(
                RuntimeError, "Journaled lease metadata does not match requested rebind"
            ):
                resources.rebind_same_owner_resources(
                    "owner-a",
                    [key],
                    purpose="stable drifted server admission rebind",
                    ttl_seconds=60,
                    metadata=metadata,
                    expected_current_leases=[current_snapshot],
                    expected_original_leases=[original_snapshot],
                )

    def test_same_owner_rebind_rejects_public_work_admission_metadata(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a public authority surface"):
            resources.rebind_same_owner_resources(
                "owner-a",
                ["component:forbidden-rebind-work-admission"],
                purpose="attempt caller admission evidence during rebind",
                ttl_seconds=60,
                metadata={"work_admission": {"decision": "allow"}},
                expected_current_leases=[],
                expected_original_leases=[],
            )

    def test_task_reconciliation_preserves_live_generation_and_recreates_missing(self) -> None:
        task_id = "a" * 24
        owner = f"task:{task_id}"
        live_key = "component:task-reconcile-live"
        missing_key = "component:task-reconcile-missing"
        keys = [live_key, missing_key]
        initial_metadata = {
            "task_id": task_id,
            "host": "heim-pc",
            "attempt": 1,
            "implicit_workspace_resource_key": None,
        }
        with patch.object(resources, "_now", return_value=100):
            initial = resources.acquire_resources(
                owner,
                keys,
                purpose=f"persistent task {task_id}",
                ttl_seconds=120,
                metadata=initial_metadata,
            )
        before = {item["resource_key"]: item for item in initial["leases"]}
        resources.release_resources(owner, [missing_key])

        recovery_metadata = {
            **initial_metadata,
            "attempt": 2,
            "recovered_after_expiry": True,
        }
        with patch.object(resources, "_now", return_value=110):
            reconciled = resources.acquire_resources(
                owner,
                keys,
                purpose=f"persistent task {task_id}",
                ttl_seconds=120,
                metadata=recovery_metadata,
                _preserve_live_same_owner=True,
            )

        self.assertEqual(reconciled["preserved"], [live_key])
        after = {item["resource_key"]: item for item in reconciled["leases"]}
        self.assertEqual(
            after[live_key]["acquired_at_unix"], before[live_key]["acquired_at_unix"]
        )
        self.assertEqual(
            after[live_key]["metadata_sha256"], before[live_key]["metadata_sha256"]
        )
        self.assertEqual(after[missing_key]["acquired_at_unix"], 110)
        self.assertNotEqual(
            after[missing_key]["metadata_sha256"], before[missing_key]["metadata_sha256"]
        )
        with resources._database() as connection:
            rows = {
                row["resource_key"]: row
                for row in connection.execute(
                    "SELECT * FROM leases WHERE resource_key IN (?, ?)",
                    (live_key, missing_key),
                ).fetchall()
            }
        live_metadata = json.loads(rows[live_key]["metadata_json"])
        missing_metadata = json.loads(rows[missing_key]["metadata_json"])
        self.assertEqual(live_metadata["attempt"], 1)
        self.assertNotIn("recovered_after_expiry", live_metadata)
        self.assertEqual(missing_metadata["attempt"], 2)
        self.assertIs(missing_metadata["recovered_after_expiry"], True)

    def test_live_preservation_is_restricted_to_task_owners(self) -> None:
        with self.assertRaisesRegex(PermissionError, "requires a task owner"):
            resources.acquire_resources(
                "owner-a",
                ["component:forbidden-preservation"],
                purpose="forbidden internal mode",
                ttl_seconds=60,
                _preserve_live_same_owner=True,
            )

    def test_snapshot_guarded_renew_is_atomic_and_never_shortens(self) -> None:
        keys = ["component:renew-a", "component:renew-b"]
        with patch.object(resources, "_now", return_value=100):
            acquired = resources.acquire_resources(
                "owner-a", keys, purpose="guarded renew", ttl_seconds=120
            )
        snapshots = [
            {field: lease[field] for field in resources.LEASE_SNAPSHOT_KEYS}
            for lease in acquired["leases"]
        ]
        with patch.object(resources, "_now", return_value=110):
            renewed = resources.renew_resources(
                "owner-a",
                keys,
                ttl_seconds=30,
                expected_leases=snapshots,
            )
        self.assertTrue(renewed["snapshot_guarded"])
        self.assertEqual(
            [lease["expires_at_unix"] for lease in renewed["leases"]], [220, 220]
        )

        with patch.object(resources, "_now", return_value=120):
            with self.assertRaisesRegex(RuntimeError, "changed before renew"):
                resources.renew_resources(
                    "owner-a",
                    keys,
                    ttl_seconds=200,
                    expected_leases=snapshots,
                )
        with patch.object(resources, "_now", return_value=120):
            self.assertEqual(
                resources.list_resources(owner_id="owner-a"), renewed["leases"]
            )

    def test_live_same_owner_reentry_preserves_reclaim_provenance(self) -> None:
        key = "component:reclaim-provenance"
        with patch.object(resources, "_now", return_value=100):
            resources.acquire_resources(
                "owner-a", [key], purpose="first", ttl_seconds=30
            )
        with patch.object(resources, "_now", return_value=200):
            reclaimed = resources.acquire_resources(
                "owner-b",
                [key],
                purpose="stable",
                ttl_seconds=120,
                metadata={"scope": "stable"},
            )
        self.assertEqual(
            reclaimed["leases"][0]["reclaimed_from_owner"], "owner-a"
        )
        with patch.object(resources, "_now", return_value=210):
            renewed = resources.acquire_resources(
                "owner-b",
                [key],
                purpose="stable",
                ttl_seconds=30,
                metadata={"scope": "stable"},
            )
        self.assertEqual(renewed["leases"][0]["reclaimed_from_owner"], "owner-a")

    def test_snapshot_guarded_force_release_binds_foreign_snapshot(self) -> None:
        key = "component:force-snapshot"
        acquired = resources.acquire_resources(
            "owner-a", [key], purpose="foreign owner", ttl_seconds=60
        )
        snapshot = [
            {field: acquired["leases"][0][field] for field in resources.LEASE_SNAPSHOT_KEYS}
        ]
        released = resources.release_resources(
            "operator", [key], force=True, expected_leases=snapshot
        )
        self.assertTrue(released["snapshot_guarded"])
        self.assertEqual(released["released"][0]["owner_id"], "owner-a")
        self.assertIsNone(resources.inspect_resource(key))

    def test_snapshot_guarded_release_rejects_same_owner_aba(self) -> None:
        key = "component:release-aba"
        with patch.object(resources, "_now", return_value=100):
            first = resources.acquire_resources(
                "owner-a", [key], purpose="first identity", ttl_seconds=30
            )
        stale_snapshot = [
            {field: first["leases"][0][field] for field in resources.LEASE_SNAPSHOT_KEYS}
        ]
        with patch.object(resources, "_now", return_value=200):
            second = resources.acquire_resources(
                "owner-a", [key], purpose="second identity", ttl_seconds=60
            )
        self.assertEqual(second["leases"][0]["acquired_at_unix"], 200)
        self.assertEqual(second["reclaimed"][0]["previous_owner_id"], "owner-a")

        with self.assertRaisesRegex(RuntimeError, "changed before release"):
            resources.release_resources(
                "owner-a", [key], expected_leases=stale_snapshot
            )
        with patch.object(resources, "_now", return_value=210):
            self.assertEqual(resources.inspect_resource(key), second["leases"][0])
        current_snapshot = [
            {field: second["leases"][0][field] for field in resources.LEASE_SNAPSHOT_KEYS}
        ]
        released = resources.release_resources(
            "owner-a", [key], expected_leases=current_snapshot
        )
        self.assertTrue(released["snapshot_guarded"])
        self.assertIsNone(resources.inspect_resource(key))

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

    def test_schema_v1_database_migrates_to_v3_without_losing_leases(self) -> None:
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
        self.assertEqual("3", version)
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
        self.assertEqual("3", inventory["current_version"])
        self.assertEqual(["1", "2", "3"], inventory["supported_versions"])
        self.assertIsNone(inventory["lease_contract_observed_version"])
        self.assertEqual("1", inventory["lease_contract_current_version"])
        self.assertEqual(["1"], inventory["lease_contract_supported_versions"])
        self.assertEqual("missing", inventory["lease_contract_status"])
        self.assertEqual("migration_required", inventory["status"])
        self.assertTrue(inventory["migration_required"])
        self.assertFalse(inventory["write_compatible"])
        self.assertFalse(inventory["mutation_performed"])
        self.assertEqual(
            "supported_with_exclusive_migration",
            inventory["rolling_upgrade"][
                "current_runtime_supported_older_store"
            ],
        )
        self.assertEqual(
            "unsupported_require_full_runtime_drain",
            inventory["rolling_upgrade"][
                "pre_t062_runtime_overlap_with_future_schema"
            ],
        )
        self.assertEqual(
            [{
                "from": "1",
                "to": "3",
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
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            resources.grabowski_resource_list(schema_only=True, owner_id="task:test")

    def test_current_resource_schema_inventory_is_byte_stable(self) -> None:
        connection = resources._database()
        connection.close()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        original_integrity = resources._resource_sqlite_integrity
        with patch.object(
            resources,
            "_resource_sqlite_integrity",
            wraps=original_integrity,
        ) as integrity:
            connection = resources._database()
            connection.close()
        self.assertEqual(1, integrity.call_count)
        inventory = resources.grabowski_resource_list(schema_only=True)
        self.assertEqual("3", inventory["observed_version"])
        self.assertEqual("1", inventory["lease_contract_observed_version"])
        self.assertEqual("current", inventory["lease_contract_status"])
        self.assertEqual("current", inventory["status"])
        self.assertTrue(inventory["write_compatible"])
        self.assertFalse(inventory["migration_required"])
        self.assertEqual("none", inventory["required_action"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(before_names, sorted(item.name for item in self.database.parent.iterdir()))

    def test_resource_schema_inventory_blocks_if_wal_appears_during_immutable_read(self) -> None:
        connection = resources._database()
        connection.close()
        wal = Path(str(self.database) + "-wal")
        self.assertFalse(wal.exists())
        original = resources._resource_schema_version

        def create_wal_during_read(connection: sqlite3.Connection) -> str | None:
            version = original(connection)
            wal.write_bytes(b"concurrent-writer-marker")
            return version

        try:
            with patch.object(
                resources,
                "_resource_schema_version",
                side_effect=create_wal_during_read,
            ):
                inventory = resources.grabowski_resource_list(schema_only=True)
            self.assertEqual("blocked", inventory["status"])
            self.assertEqual("retry_schema_inventory", inventory["required_action"])
            self.assertFalse(inventory["write_compatible"])
            self.assertFalse(inventory["mutation_performed"])
            self.assertIn("changed while schema inventory", inventory["error"])
        finally:
            wal.unlink(missing_ok=True)

    def test_resource_schema_inventory_reads_uncheckpointed_future_wal(self) -> None:
        connection = resources._database()
        connection.close()
        keeper = sqlite3.connect(self.database)
        try:
            self.assertEqual("wal", keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            self.assertEqual(
                0, keeper.execute("PRAGMA wal_autocheckpoint=0").fetchone()[0]
            )
            keeper.execute(
                "UPDATE metadata SET value='4' WHERE key='schema_version'"
            )
            keeper.commit()
            wal = Path(str(self.database) + "-wal")
            self.assertTrue(wal.exists())
            before_database = self.database.read_bytes()
            before_wal = wal.read_bytes()
            before_names = sorted(item.name for item in self.database.parent.iterdir())
            original_connect = sqlite3.connect
            source_uri = self.database.absolute().as_uri()

            def reject_source_sqlite_open(
                database: object,
                *args: object,
                **kwargs: object,
            ) -> sqlite3.Connection:
                database_text = str(database)
                if (
                    database_text == str(self.database)
                    or database_text.startswith(source_uri)
                ):
                    raise AssertionError(
                        "Resource schema inventory must not open the source database when WAL is present"
                    )
                return original_connect(database, *args, **kwargs)

            with patch.object(
                resources.sqlite3,
                "connect",
                side_effect=reject_source_sqlite_open,
            ):
                inventory = resources.grabowski_resource_list(schema_only=True)
            self.assertEqual("4", inventory["observed_version"])
            self.assertEqual("unsupported_future", inventory["status"])
            self.assertFalse(inventory["write_compatible"])
            self.assertFalse(inventory["mutation_performed"])
            self.assertEqual(
                "fail_closed_without_mutation",
                inventory["rolling_upgrade"][
                    "current_runtime_newer_store"
                ],
            )
            self.assertEqual(
                "unsupported_require_full_runtime_drain",
                inventory["rolling_upgrade"][
                    "pre_t062_runtime_overlap_with_future_schema"
                ],
            )
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
                "3",
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
                "3",
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

    def test_schema_v3_missing_pending_index_fails_closed_without_repair(self) -> None:
        with resources._database():
            pass
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP INDEX task_terminalizations_pending_idx")
            connection.commit()
        before = self.database.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "indexes are incomplete"):
            resources.list_resources()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual([], self._resource_migration_backups())

    def test_resource_store_file_ready_rejects_symlink(self) -> None:
        target = self.root / "resource-store-target.sqlite3"
        target.write_bytes(b"sqlite")
        self.database.parent.mkdir(parents=True)
        self.database.symlink_to(target)

        with self.assertRaisesRegex(PermissionError, "regular file"):
            resources._resource_store_file_ready()

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
        for index, suffix in enumerate(("branch:feat/scoped", "operation:deploy", "tag:release-v1")):
            with self.subTest(suffix=suffix):
                key = f"repo:{self.root}:{suffix}"
                with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
                    resources.base, "_append_audit"
                ):
                    result = resources.grabowski_resource_acquire(
                        f"owner-{index}",
                        [key],
                        "self-scoped repository work",
                        60,
                    )
                self.assertEqual(result["leases"][0]["resource_key"], key)

    def test_scoped_repository_resource_root_scans_multiple_markers(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/multi-marker-repo\n")
        key = f"repo:{self.root}:branch:feat/work:operation:deploy:tag:release-v1"
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

    def test_scoped_repository_resource_root_rejects_ambiguous_marker_roots(self) -> None:
        (self.root / ".git").write_text("gitdir: /tmp/outer-marker-repo\n")
        nested = Path(f"{self.root}:branch:child")
        nested.mkdir()
        (nested / ".git").write_text("gitdir: /tmp/nested-marker-repo\n")
        key = f"repo:{nested}:tag:release-v1"
        self.assertIsNone(resources.scoped_repository_resource_root(key))

    def test_public_tool_treats_existing_marker_paths_as_broad(self) -> None:
        for marker in ("branch", "operation", "tag"):
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

    def test_public_tool_rejects_caller_selected_emergency_repository_mode(self) -> None:
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ):
            with self.assertRaisesRegex(
                ValueError, "metadata.lease_mode is not a public authority surface"
            ):
                resources.grabowski_resource_acquire(
                    "owner-a",
                    [f"repo:{self.root}"],
                    "emergency recovery",
                    60,
                    {"lease_mode": "emergency-recovery"},
                )

    def test_core_rejects_non_bureau_emergency_repository_mode(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "metadata.lease_mode is not an authority surface"
        ):
            resources.acquire_resources(
                "owner-a",
                [f"repo:{self.root}"],
                purpose="emergency recovery",
                ttl_seconds=60,
                metadata={"lease_mode": "emergency-recovery"},
            )
        self.assertFalse(self.database.exists())

    def test_public_tool_does_not_accept_bureau_phase_for_other_repository(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "metadata.scope_manifest_complete=true"
        ):
            resources.grabowski_resource_acquire(
                "owner-a",
                [f"repo:{self.root}"],
                "claimed recovery",
                60,
                {
                    "bureau_phase": "emergency-recovery",
                    "bureau_justification": "not the Bureau repository",
                    "bureau_expected_head": "a" * 40,
                },
            )

    def test_public_bureau_emergency_pass_through_rejects_mixed_repositories(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "metadata.scope_manifest_complete=true"
        ):
            resources._public_repository_scope_keys(
                [
                    resources.bureau_leases.BROAD_BUREAU_REPOSITORY_KEY,
                    f"repo:{self.root}",
                ],
                {"bureau_phase": "emergency-recovery"},
            )

    def test_public_broad_bureau_work_still_requires_complete_scope(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "metadata.scope_manifest_complete=true"
        ):
            resources._public_repository_scope_keys(
                [resources.bureau_leases.BROAD_BUREAU_REPOSITORY_KEY],
                {"bureau_phase": "work"},
            )

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

    def test_public_nonconflict_live_path_deny_is_structured_and_fail_closed(self) -> None:
        path = self.root / "owned.py"
        key = f"path:{path}"
        resources.acquire_resources(
            "owner-a", [key], purpose="live exact path", ttl_seconds=120
        )
        before = resources.inspect_resource(key)
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as append_audit:
            result = resources.grabowski_resource_nonconflict_assess(
                key, "owner-b", [key], "request path", {}, False
            )
        after = resources.inspect_resource(key)
        self.assertEqual("deny", result["decision"])
        self.assertEqual("exact-path-owner-release-required", result["code"])
        self.assertEqual("exact_path_lease", result["blocker_type"])
        self.assertNotIn("proof", result)
        self.assertEqual("owner-a", result["blocked_lease"]["owner_id"])
        self.assertEqual(before, after)
        self.assertIn("permission_to_release_other_owner", result["does_not_establish"])
        self.assertIn("retry_authority", result["does_not_establish"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "owner-b", [key], purpose="must remain blocked", ttl_seconds=60
            )
        audit = append_audit.call_args.args[0]
        self.assertEqual("deny", audit["decision"])
        self.assertEqual("exact-path-owner-release-required", audit["code"])
        self.assertNotIn("proof_sha256", audit)

    def test_public_nonconflict_absent_path_keeps_stable_code(self) -> None:
        key = f"path:{self.root / 'absent.py'}"
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as append_audit:
            result = resources.grabowski_resource_nonconflict_assess(
                key, "owner-b", [key], "request absent path", {}, False
            )
        self.assertEqual("deny", result["decision"])
        self.assertEqual("blocked-path-lease-absent-or-expired", result["code"])
        self.assertEqual("exact_path_lease", result["blocker_type"])
        self.assertNotIn("proof", result)
        self.assertEqual(result["code"], append_audit.call_args.args[0]["code"])

    def test_public_nonconflict_unsupported_blocker_keeps_stable_code(self) -> None:
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as append_audit:
            result = resources.grabowski_resource_nonconflict_assess(
                "port:9222", "owner-b", ["port:9223"], "unsupported blocker", {}, False
            )
        self.assertEqual("deny", result["decision"])
        self.assertEqual("unsupported-blocker-type", result["code"])
        self.assertEqual("port", result["blocker_type"])
        self.assertNotIn("proof", result)
        self.assertEqual("unsupported-blocker-type", append_audit.call_args.args[0]["code"])

    def test_public_nonconflict_repository_allow_preserves_proof_path(self) -> None:
        blocked_key = f"repo:{self.root}"
        existing_path = self.root / "existing.py"
        requested_path = self.root / "requested.py"
        existing_scope = self.scope_manifest(
            self.root, name="existing", path=existing_path
        )
        requested_scope = self.scope_manifest(
            self.root, name="requested", path=requested_path
        )
        resources.acquire_resources(
            "owner-a",
            [blocked_key],
            purpose="broad repository blocker",
            ttl_seconds=120,
            metadata={
                "scope_manifest": existing_scope,
                "scope_manifest_complete": True,
            },
        )
        requested_key = f"path:{requested_path.resolve()}"
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as append_audit:
            result = resources.grabowski_resource_nonconflict_assess(
                blocked_key,
                "owner-b",
                [requested_key],
                "disjoint repository work",
                requested_scope,
                True,
            )
        self.assertEqual("allow", result["decision"])
        self.assertIn("proof", result)
        self.assertEqual("allow", result["proof"]["decision"])
        audit = append_audit.call_args.args[0]
        self.assertEqual(result["proof"]["proof_sha256"], audit["proof_sha256"])
        self.assertNotIn("code", audit)

    def test_public_nonconflict_repository_deny_remains_typed(self) -> None:
        blocked_key = f"repo:{self.root}"
        shared_path = self.root / "shared.py"
        existing_scope = self.scope_manifest(
            self.root, name="existing", path=shared_path
        )
        requested_scope = self.scope_manifest(
            self.root, name="requested", path=shared_path
        )
        resources.acquire_resources(
            "owner-a",
            [blocked_key],
            purpose="broad repository blocker",
            ttl_seconds=120,
            metadata={
                "scope_manifest": existing_scope,
                "scope_manifest_complete": True,
            },
        )
        requested_key = f"path:{shared_path.resolve()}"
        with patch.object(resources.operator, "_require_operator_mutation"), patch.object(
            resources.base, "_append_audit"
        ) as append_audit:
            with self.assertRaises(resources.nonconflict.NonConflictDenied) as raised:
                resources.grabowski_resource_nonconflict_assess(
                    blocked_key,
                    "owner-b",
                    [requested_key],
                    "overlapping repository work",
                    requested_scope,
                    True,
                )
        self.assertEqual("scope-conflict", raised.exception.code)
        append_audit.assert_not_called()

    def test_public_nonconflict_rejects_malformed_assessor_shapes(self) -> None:
        common = {
            "blocked_resource_key": "path:/tmp/example",
            "requesting_owner": "owner-b",
        }
        variants = [
            ({**common, "decision": "allow"}, "missing its proof"),
            (
                {
                    **common,
                    "decision": "deny",
                    "code": "exact-path-owner-release-required",
                    "blocker_type": "exact_path_lease",
                    "proof": {},
                },
                "must not include a proof",
            ),
            ({**common, "decision": "deny"}, "stable classification"),
        ]
        for result, message in variants:
            with self.subTest(result=result), patch.object(
                resources.operator, "_require_operator_mutation"
            ), patch.object(
                resources, "assess_nonconflict", return_value=result
            ), patch.object(resources.base, "_append_audit") as append_audit:
                with self.assertRaisesRegex(RuntimeError, message):
                    resources.grabowski_resource_nonconflict_assess(
                        "path:/tmp/example", "owner-b", [], "shape", {}, False
                    )
                append_audit.assert_not_called()

    def _operator_terminal_evidence(
        self, *, status: str = "success"
    ) -> dict[str, object]:
        material: dict[str, object] = {
            "schema_version": 1,
            "kind": "grabowski_captain_operator_lease_terminal_evidence",
            "status": status,
            "guard_owner_id": "captain-merge:test-operator",
            "dispatch_called": status == "success",
            "execution_invoked": status == "success",
            "verification_passed": status == "success",
            "observed_at_unix_ns": time.time_ns(),
        }
        return {
            **material,
            "terminal_evidence_sha256": merge_guard._sha256_json(material),
        }

    def _operator_delegation(
        self, evidence: dict[str, object], *, digest: str = "d" * 64
    ) -> dict[str, object]:
        return {**evidence, "delegation_sha256": digest}

    def _operator_authority_resource_key(self, owner: str) -> str:
        return (
            "gate:operator-lease-authority:"
            + hashlib.sha256(owner.encode("utf-8")).hexdigest()
        )

    def _operator_authority_gate(
        self,
        owner: str,
        evidence: dict[str, object],
        *,
        guard_owner: str = "captain-merge:test-operator",
        delegation_sha256: str = "d" * 64,
    ) -> str:
        resource_keys = evidence["resource_keys"]
        authority_key = self._operator_authority_resource_key(owner)
        resources.acquire_resources(
            guard_owner,
            [authority_key],
            purpose="test direct Operator authority",
            ttl_seconds=120,
            metadata={
                "operator_lease_delegation": {
                    "lease_owner_id_sha256": hashlib.sha256(
                        owner.encode("utf-8")
                    ).hexdigest(),
                    "resource_keys_sha256": merge_guard._sha256_json(
                        resource_keys
                    ),
                    "lease_bindings_sha256": evidence[
                        "lease_bindings_sha256"
                    ],
                    "delegation_sha256": delegation_sha256,
                }
            },
        )
        return authority_key

    def test_operator_lease_delegation_evidence_binds_complete_live_set(self) -> None:
        owner = "operator:test-direct-owner"
        keys = ["component:operator-a", "component:operator-b"]
        resources.acquire_resources(
            owner, keys, purpose="direct Operator work", ttl_seconds=120
        )

        evidence = resources.operator_lease_delegation_evidence(owner)

        self.assertEqual(owner, evidence["lease_owner_id"])
        self.assertEqual(keys, evidence["resource_keys"])
        self.assertEqual(2, len(evidence["lease_snapshots"]))
        self.assertEqual(
            evidence["lease_bindings_sha256"],
            merge_guard._sha256_json(evidence["lease_snapshots"]),
        )
        with self.assertRaisesRegex(ValueError, "complete current owner lease set"):
            resources.operator_lease_delegation_evidence(owner, [keys[0]])
        with self.assertRaisesRegex(ValueError, "direct Operator lease owner"):
            resources.operator_lease_delegation_evidence("captain-test-owner")

    def test_operator_lease_terminal_convergence_releases_exact_and_replays(self) -> None:
        owner = "operator:test-terminal-owner"
        keys = ["component:operator-terminal-a", "component:operator-terminal-b"]
        resources.acquire_resources(
            owner, keys, purpose="direct Operator work", ttl_seconds=120
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        terminal = self._operator_terminal_evidence()
        delegation_sha256 = "d" * 64
        authority_key = self._operator_authority_gate(
            owner, evidence, delegation_sha256=delegation_sha256
        )

        result = resources.reconcile_delegated_operator_leases(
            owner,
            evidence["lease_snapshots"],
            expected_lease_bindings_sha256=evidence["lease_bindings_sha256"],
            delegation_sha256=delegation_sha256,
            authority_resource_key=authority_key,
            terminal_source=terminal,
        )

        self.assertTrue(result["converged"])
        self.assertEqual(keys, [item["resource_key"] for item in result["released"]])
        self.assertEqual([], resources.list_resources(owner_id=owner))

        resources.release_resources(
            "captain-merge:test-operator", [authority_key]
        )
        replay = resources.reconcile_delegated_operator_leases(
            owner,
            evidence["lease_snapshots"],
            expected_lease_bindings_sha256=evidence["lease_bindings_sha256"],
            delegation_sha256=delegation_sha256,
            authority_resource_key=authority_key,
            terminal_source=terminal,
        )
        self.assertTrue(replay["converged"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(keys, replay["already_absent"])

    def test_operator_lease_terminal_convergence_requires_bound_authority_gate(self) -> None:
        owner = "operator:test-missing-authority"
        key = "component:operator-missing-authority"
        resources.acquire_resources(
            owner, [key], purpose="direct Operator work", ttl_seconds=120
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        authority_key = self._operator_authority_resource_key(owner)

        with self.assertRaisesRegex(ValueError, "authority gate is not live"):
            resources.reconcile_delegated_operator_leases(
                owner,
                evidence["lease_snapshots"],
                expected_lease_bindings_sha256=evidence[
                    "lease_bindings_sha256"
                ],
                delegation_sha256="d" * 64,
                authority_resource_key=authority_key,
                terminal_source=self._operator_terminal_evidence(),
            )
        self.assertIsNotNone(resources.inspect_resource(key))

        self._operator_authority_gate(
            owner, evidence, delegation_sha256="e" * 64
        )
        with self.assertRaisesRegex(ValueError, "authority gate binding mismatch"):
            resources.reconcile_delegated_operator_leases(
                owner,
                evidence["lease_snapshots"],
                expected_lease_bindings_sha256=evidence[
                    "lease_bindings_sha256"
                ],
                delegation_sha256="d" * 64,
                authority_resource_key=authority_key,
                terminal_source=self._operator_terminal_evidence(),
            )
        self.assertIsNotNone(resources.inspect_resource(key))

    def test_operator_lease_terminal_convergence_retains_drift_and_growth(self) -> None:
        owner = "operator:test-drift-owner"
        key = "component:operator-drift"
        resources.acquire_resources(
            owner, [key], purpose="direct Operator work", ttl_seconds=120
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        resources.renew_resources(owner, [key], ttl_seconds=180)

        drift = resources.reconcile_delegated_operator_leases(
            owner,
            evidence["lease_snapshots"],
            expected_lease_bindings_sha256=evidence["lease_bindings_sha256"],
            delegation_sha256="d" * 64,
            authority_resource_key=self._operator_authority_resource_key(owner),
            terminal_source=self._operator_terminal_evidence(),
        )
        self.assertFalse(drift["converged"])
        self.assertEqual("lease_changed", drift["retained"][0]["reason"])
        self.assertIsNotNone(resources.inspect_resource(key))

        fresh = resources.operator_lease_delegation_evidence(owner)
        extra = "component:operator-growth"
        resources.acquire_resources(
            owner, [extra], purpose="late direct Operator work", ttl_seconds=120
        )
        growth = resources.reconcile_delegated_operator_leases(
            owner,
            fresh["lease_snapshots"],
            expected_lease_bindings_sha256=fresh["lease_bindings_sha256"],
            delegation_sha256="d" * 64,
            authority_resource_key=self._operator_authority_resource_key(owner),
            terminal_source=self._operator_terminal_evidence(),
        )
        self.assertFalse(growth["converged"])
        self.assertEqual("owner_lease_set_changed", growth["retained"][0]["reason"])
        self.assertIsNotNone(growth["unexpected_owner_resource_keys_sha256"])
        self.assertIsNotNone(resources.inspect_resource(key))
        self.assertIsNotNone(resources.inspect_resource(extra))

    def test_operator_lease_delegation_rejects_owner_held_authority_gate(self) -> None:
        owner = "operator:test-reserved-authority"
        authority_key = (
            "gate:operator-lease-authority:"
            + hashlib.sha256(owner.encode("utf-8")).hexdigest()
        )
        resources.acquire_resources(
            owner,
            [authority_key],
            purpose="invalid preheld authority",
            ttl_seconds=120,
        )

        with self.assertRaisesRegex(ValueError, "reserved delegation authority gate"):
            resources.operator_lease_delegation_evidence(owner)
        self.assertIsNotNone(resources.inspect_resource(authority_key))

    def test_operator_merge_delegation_requires_target_bound_lease(self) -> None:
        repository = self.root / "operator-target-repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        changed_path.parent.mkdir()
        changed_path.write_text("x", encoding="utf-8")
        owner = "operator:test-unrelated-owner"
        resources.acquire_resources(
            owner,
            ["component:unrelated-direct-operator-work"],
            purpose="unrelated direct Operator work",
            ttl_seconds=120,
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "diff_sha256": "b" * 64,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }

        with self.assertRaisesRegex(ValueError, "do not bind the merge target"):
            resources.acquire_merge_guard_resources(
                "captain-merge:operator-target",
                owner,
                guard_keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="target-bound direct Operator guard",
                ttl_seconds=60,
                metadata=metadata,
                delegated_operator=self._operator_delegation(evidence),
            )
        self.assertIsNotNone(
            resources.inspect_resource("component:unrelated-direct-operator-work")
        )

    def test_operator_merge_authority_gate_serializes_parallel_adoption(self) -> None:
        repository = self.root / "operator-authority-repo"
        repository.mkdir()
        changed_path = repository / "src" / "target.py"
        changed_path.parent.mkdir()
        changed_path.write_text("x", encoding="utf-8")
        owner = "operator:test-authority-owner"
        guard_keys = merge_guard.merge_guard_resource_keys(
            repository,
            repo_slug="heimgewebe/grabowski",
            pr_number=57,
            base="main",
            head="feat/work",
        )
        head_key = next(
            key
            for key in guard_keys
            if key.startswith("component:github-branch:")
            and key.endswith(":" + WORK_BRANCH_ID)
        )
        resources.acquire_resources(
            owner, [head_key], purpose="direct Operator work", ttl_seconds=120
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        metadata = {
            "merge_guard": {
                "head_sha": "a" * 40,
                "diff_sha256": "b" * 64,
                "base_branch": "main",
                "head_branch": "feat/work",
            }
        }

        first = resources.acquire_merge_guard_resources(
            "captain-merge:operator-authority-first",
            owner,
            guard_keys,
            repository=str(repository),
            changed_paths=[str(changed_path)],
            purpose="direct Operator authority guard",
            ttl_seconds=60,
            metadata=metadata,
            delegated_operator=self._operator_delegation(evidence),
        )

        authority_key = first["delegated_operator_authority_key"]
        self.assertIsNotNone(authority_key)
        authority_lease = resources.inspect_resource(authority_key)
        self.assertIsNotNone(authority_lease)
        self.assertEqual(
            "captain-merge:operator-authority-first",
            authority_lease["owner_id"],
        )
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_merge_guard_resources(
                "captain-merge:operator-authority-second",
                owner,
                guard_keys,
                repository=str(repository),
                changed_paths=[str(changed_path)],
                purpose="parallel direct Operator authority guard",
                ttl_seconds=60,
                metadata=metadata,
                delegated_operator=self._operator_delegation(evidence),
            )
        resources.release_resources(
            "captain-merge:operator-authority-first",
            first["held_resource_keys"],
        )
        self.assertIsNone(resources.inspect_resource(authority_key))
        self.assertIsNotNone(resources.inspect_resource(head_key))

    def test_operator_lease_terminal_convergence_rejects_missing_terminal_evidence(self) -> None:
        owner = "operator:test-terminal-evidence"
        key = "component:operator-terminal-evidence"
        resources.acquire_resources(
            owner, [key], purpose="direct Operator work", ttl_seconds=120
        )
        evidence = resources.operator_lease_delegation_evidence(owner)
        terminal = self._operator_terminal_evidence()
        terminal["terminal_evidence_sha256"] = "0" * 64

        with self.assertRaisesRegex(ValueError, "terminal evidence digest"):
            resources.reconcile_delegated_operator_leases(
                owner,
                evidence["lease_snapshots"],
                expected_lease_bindings_sha256=evidence["lease_bindings_sha256"],
                delegation_sha256="d" * 64,
                authority_resource_key=self._operator_authority_resource_key(owner),
                terminal_source=terminal,
            )
        self.assertIsNotNone(resources.inspect_resource(key))

    def test_broad_repository_lease_runs_read_only_admission_before_write(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(self.root, name="admission", path=self.root)
        calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            calls.append(dict(kwargs))
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            }

        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}"],
            purpose="admission-bound repository work",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=assessor,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["operation"], "broad_repository_lease")
        self.assertEqual(calls[0]["repo"], str(self.root.resolve()))
        self.assertEqual(result["work_admission"][0]["decision"], "allow")
        stored = resources.inspect_resource(f"repo:{self.root}")
        self.assertIsNotNone(stored)

    def test_broad_repository_read_only_scope_skips_work_admission(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(
            self.root,
            name="read-only-admission",
            path=self.root,
            effects=["read"],
        )
        scope["worktree"] = str(self.root)
        scope["paths"] = []

        def assessor(**_kwargs: object) -> dict[str, object]:
            self.fail("read-only repository observation must not require work admission")

        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}"],
            purpose="read-only repository observation",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=assessor,
        )

        self.assertEqual(
            result["work_admission"],
            [
                {
                    "repository": str(self.root.resolve()),
                    "decision": "allow",
                    "reason": "attested-read-only-scope",
                    "read_only": True,
                }
            ],
        )
        self.assertIsNotNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_broad_repository_full_scope_reaches_exact_checkout_admission(self) -> None:
        (self.root / ".git").mkdir()
        scoped_path = self.root / "src" / "example.py"
        scope = self.scope_manifest(
            self.root, name="full-scope-admission", path=scoped_path
        )
        calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            call = dict(kwargs)
            calls.append(call)
            call.pop("mode")
            return work_admission.assess_repository_admission(
                **call,
                inventory_loader=lambda _repo: {
                    "worktrees": [
                        {
                            "path": str(self.root),
                            "is_main": True,
                            "status": {"dirty": True},
                            "coordination": {
                                "blocking": False,
                                "resource_leases": [],
                                "tasks": [],
                                "processes": [],
                            },
                        }
                    ],
                    "inventory_sha256": "a" * 64,
                },
                reconciliation_loader=lambda _repo: {
                    "bindings": [],
                    "pagination": {"has_more": False},
                    "source_snapshot": {"repository_errors": []},
                    "snapshot_sha256": "b" * 64,
                },
            )

        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}"],
            purpose="full scope admission integration",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=assessor,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["requested_scope"],
            resources.nonconflict.normalize_scope_manifest(scope),
        )
        self.assertEqual(result["work_admission"][0]["decision"], "allow")
        self.assertIsNotNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_broad_repository_same_owner_reentry_preserves_admission_generation(self) -> None:
        (self.root / ".git").mkdir()
        key = f"repo:{self.root}"
        scope = self.scope_manifest(self.root, name="admission-reentry", path=self.root)
        calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            calls.append(dict(kwargs))
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            }

        first = resources.acquire_resources(
            "owner-a",
            [key],
            purpose="stable admitted repository work",
            ttl_seconds=120,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=assessor,
        )
        with resources._database() as connection:
            original = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(original)

        def unexpected_assessor(**_kwargs: object) -> dict[str, object]:
            raise AssertionError("same-owner live reentry must not rerun admission")

        second = resources.acquire_resources(
            "owner-a",
            [key],
            purpose="stable admitted repository work",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=unexpected_assessor,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(second["preserved"], [key])
        self.assertEqual(
            second["leases"][0]["metadata_sha256"], first["leases"][0]["metadata_sha256"]
        )
        self.assertEqual(
            second["leases"][0]["acquired_at_unix"], first["leases"][0]["acquired_at_unix"]
        )
        with resources._database() as connection:
            current = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertEqual(current["metadata_json"], original["metadata_json"])
        self.assertEqual(current["metadata_sha256"], original["metadata_sha256"])

    def test_branch_attempt_same_owner_cas_blocks_live_duplicate_and_preserves_sequential_continuation(self) -> None:
        (self.root / ".git").mkdir()
        owner = "operator:same-owner"
        branch = "feat/same-owner-cas"
        preimage = "a" * 64

        first = resources.acquire_branch_mutation_attempt(
            owner,
            str(self.root),
            branch,
            operation_id="operation-a",
            attempt_id="attempt-1",
            expected_preimage_sha256=preimage,
            ttl_seconds=120,
        )
        with self.assertRaises(resources.SameOwnerBranchAttemptConflict) as duplicate:
            resources.acquire_branch_mutation_attempt(
                owner,
                str(self.root),
                branch,
                operation_id="operation-a",
                attempt_id="attempt-1",
                expected_preimage_sha256=preimage,
                ttl_seconds=120,
            )
        self.assertTrue(duplicate.exception.already_running)
        self.assertEqual(
            duplicate.exception.existing_binding_sha256,
            duplicate.exception.requested_binding_sha256,
        )

        resources.complete_branch_mutation_attempt(first)
        continued = resources.acquire_branch_mutation_attempt(
            owner,
            str(self.root),
            branch,
            operation_id="operation-a",
            attempt_id="attempt-1",
            expected_preimage_sha256=preimage,
            ttl_seconds=120,
        )
        self.assertEqual(
            first["attempt_binding_sha256"], continued["attempt_binding_sha256"]
        )

        with self.assertRaises(resources.SameOwnerBranchAttemptConflict) as blocked:
            resources.acquire_branch_mutation_attempt(
                owner,
                str(self.root),
                branch,
                operation_id="operation-b",
                attempt_id="attempt-2",
                expected_preimage_sha256=preimage,
                ttl_seconds=120,
            )
        self.assertEqual(first["resource_key"], blocked.exception.resource_key)
        self.assertFalse(blocked.exception.already_running)
        self.assertNotEqual(
            blocked.exception.existing_binding_sha256,
            blocked.exception.requested_binding_sha256,
        )

        disjoint = resources.acquire_branch_mutation_attempt(
            owner,
            str(self.root),
            "feat/disjoint",
            operation_id="operation-b",
            attempt_id="attempt-2",
            expected_preimage_sha256=preimage,
            ttl_seconds=120,
        )
        self.assertNotEqual(first["resource_key"], disjoint["resource_key"])
        self.assertEqual(owner, disjoint["lease"]["owner_id"])

    def test_branch_attempt_concurrent_exact_duplicate_admits_only_one(self) -> None:
        (self.root / ".git").mkdir()
        with resources._database():
            pass
        start_barrier = threading.Barrier(3)
        overlay_barrier = threading.Barrier(2)
        admitted: list[dict[str, object]] = []
        conflicts: list[resources.SameOwnerBranchAttemptConflict] = []
        errors: list[BaseException] = []
        original_overlay = resources._overlay_live_same_owner_branch_attempt

        def synchronize_empty_overlay(**kwargs: object) -> None:
            result = original_overlay(**kwargs)
            if result is not None:
                raise AssertionError("both callers must observe the empty overlay path")
            overlay_barrier.wait(timeout=2)

        def acquire() -> None:
            try:
                start_barrier.wait(timeout=2)
                admitted.append(
                    resources.acquire_branch_mutation_attempt(
                        "operator:concurrent-duplicate",
                        str(self.root),
                        "feat/concurrent-duplicate",
                        operation_id="operation-a",
                        attempt_id="attempt-1",
                        expected_preimage_sha256="e" * 64,
                        ttl_seconds=120,
                    )
                )
            except resources.SameOwnerBranchAttemptConflict as exc:
                conflicts.append(exc)
            except BaseException as exc:  # pragma: no cover - surfaced below
                errors.append(exc)

        threads = [threading.Thread(target=acquire) for _ in range(2)]
        with patch.object(
            resources,
            "_overlay_live_same_owner_branch_attempt",
            side_effect=synchronize_empty_overlay,
        ):
            for thread in threads:
                thread.start()
            start_barrier.wait(timeout=2)
            for thread in threads:
                thread.join(timeout=2)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(1, len(admitted))
        self.assertEqual(1, len(conflicts))
        self.assertTrue(conflicts[0].already_running)
        self.assertEqual(
            admitted[0]["attempt_binding_sha256"],
            conflicts[0].existing_binding_sha256,
        )
        self.assertEqual(
            conflicts[0].existing_binding_sha256,
            conflicts[0].requested_binding_sha256,
        )
        resources.complete_branch_mutation_attempt(admitted[0])

    def test_branch_attempt_preserves_and_restores_existing_work_lane_branch_lease(self) -> None:
        (self.root / ".git").mkdir()
        lane_id = "a" * 32
        owner = f"lane:{lane_id}"
        branch = "feat/work-lane-attempt"
        key = f"repo:{self.root}:branch:{branch}"
        metadata = self.work_lane_metadata(
            self.root, target=self.root / "writer", lane_id=lane_id
        )
        resources.acquire_resources(
            owner,
            [key],
            purpose="work lane writer authority",
            ttl_seconds=120,
            metadata=metadata,
        )
        with resources._database() as connection:
            original = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(original)
        original_record = dict(original)

        attempt = resources.acquire_branch_mutation_attempt(
            owner,
            str(self.root),
            branch,
            operation_id="operation-a",
            attempt_id="attempt-1",
            expected_preimage_sha256="b" * 64,
            ttl_seconds=60,
        )
        self.assertEqual("preexisting", attempt["lease_origin"])
        self.assertTrue(attempt["preserved"])
        self.assertEqual(
            original_record["purpose"], attempt["lease"]["purpose"]
        )
        with resources._database() as connection:
            active = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(active)
        active_metadata = resources._row_metadata(active)
        self.assertEqual(original_record["purpose"], active["purpose"])
        self.assertEqual(
            original_record["acquired_at_unix"], active["acquired_at_unix"]
        )
        self.assertEqual(
            original_record["updated_at_unix"], active["updated_at_unix"]
        )
        self.assertEqual(
            original_record["expires_at_unix"], active["expires_at_unix"]
        )
        self.assertEqual(
            original_record["metadata_sha256"],
            active_metadata[resources.BRANCH_MUTATION_ATTEMPT_METADATA_KEY][
                "previous_metadata_sha256"
            ],
        )

        with self.assertRaises(resources.SameOwnerBranchAttemptConflict):
            resources.acquire_branch_mutation_attempt(
                owner,
                str(self.root),
                branch,
                operation_id="operation-b",
                attempt_id="attempt-2",
                expected_preimage_sha256="b" * 64,
                ttl_seconds=60,
            )

        cleanup = resources.complete_branch_mutation_attempt(attempt)
        self.assertEqual("restored", cleanup["action"])
        with resources._database() as connection:
            restored = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(restored)
        self.assertEqual(original_record["purpose"], restored["purpose"])
        self.assertEqual(
            original_record["acquired_at_unix"], restored["acquired_at_unix"]
        )
        self.assertEqual(
            original_record["updated_at_unix"], restored["updated_at_unix"]
        )
        self.assertEqual(
            original_record["expires_at_unix"], restored["expires_at_unix"]
        )
        self.assertEqual(
            original_record["metadata_sha256"], restored["metadata_sha256"]
        )
        self.assertEqual(original_record["metadata_json"], restored["metadata_json"])

    def test_branch_attempt_temporarily_extends_short_work_lane_lease_and_restores_expiry(self) -> None:
        (self.root / ".git").mkdir()
        lane_id = "b" * 32
        owner = f"lane:{lane_id}"
        branch = "feat/work-lane-short-expiry"
        key = f"repo:{self.root}:branch:{branch}"
        metadata = self.work_lane_metadata(
            self.root, target=self.root / "writer", lane_id=lane_id
        )
        resources.acquire_resources(
            owner,
            [key],
            purpose="work lane writer authority",
            ttl_seconds=30,
            metadata=metadata,
        )
        with resources._database() as connection:
            original = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(original)
        original_record = dict(original)

        attempt = resources.acquire_branch_mutation_attempt(
            owner,
            str(self.root),
            branch,
            operation_id="operation-a",
            attempt_id="attempt-1",
            expected_preimage_sha256="c" * 64,
            ttl_seconds=120,
        )
        with resources._database() as connection:
            active = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(active)
        active_metadata = resources._row_metadata(active)
        marker = active_metadata[resources.BRANCH_MUTATION_ATTEMPT_METADATA_KEY]
        self.assertEqual(
            original_record["expires_at_unix"], marker["previous_expires_at_unix"]
        )
        self.assertEqual(active["expires_at_unix"], marker["attempt_expires_at_unix"])
        self.assertGreater(active["expires_at_unix"], original_record["expires_at_unix"])
        self.assertEqual(
            original_record["expires_at_unix"], attempt["previous_expires_at_unix"]
        )

        cleanup = resources.complete_branch_mutation_attempt(attempt)
        self.assertEqual("restored", cleanup["action"])
        with resources._database() as connection:
            restored = connection.execute(
                "SELECT * FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(restored)
        self.assertEqual(
            original_record["expires_at_unix"], restored["expires_at_unix"]
        )
        self.assertEqual(original_record["metadata_json"], restored["metadata_json"])
        self.assertEqual(
            original_record["metadata_sha256"], restored["metadata_sha256"]
        )

    def test_branch_attempt_only_lease_is_snapshot_released_after_terminal_readback(self) -> None:
        (self.root / ".git").mkdir()
        branch = "feat/attempt-only-cleanup"
        attempt = resources.acquire_branch_mutation_attempt(
            "operator:attempt-only",
            str(self.root),
            branch,
            operation_id="operation-a",
            attempt_id="attempt-1",
            expected_preimage_sha256="d" * 64,
            ttl_seconds=60,
        )
        self.assertEqual("attempt_only", attempt["lease_origin"])
        cleanup = resources.complete_branch_mutation_attempt(attempt)
        self.assertEqual("released", cleanup["action"])
        self.assertTrue(cleanup["snapshot_guarded"])
        self.assertIsNone(resources.inspect_resource(attempt["resource_key"]))

    def test_expired_same_owner_repository_reentry_binds_exact_target(self) -> None:
        (self.root / ".git").mkdir()
        key = f"repo:{self.root}"
        scope = self.scope_manifest(
            self.root, name="expired-admission-reentry", path=self.root
        )
        metadata = {
            "scope_manifest": scope,
            "scope_manifest_complete": True,
        }

        first = resources.acquire_resources(
            "owner-a",
            [key],
            purpose="stable expired repository work",
            ttl_seconds=60,
            metadata=metadata,
            admission_assessor=lambda **_kwargs: {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            },
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?",
                (key,),
            )

        calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            calls.append(dict(kwargs))
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "b" * 64,
                "read_only": True,
            }

        second = resources.acquire_resources(
            "owner-a",
            [key],
            purpose="stable expired repository work",
            ttl_seconds=60,
            metadata=metadata,
            admission_assessor=assessor,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["target_path"], scope["worktree"])
        self.assertEqual(calls[0]["branch"], scope["branch"])
        self.assertEqual(
            calls[0]["source_kind"], "expired_same_owner_lease"
        )
        self.assertEqual(calls[0]["source_id"], first["leases"][0]["metadata_sha256"])
        self.assertEqual(second["reclaimed"][0]["previous_owner_id"], "owner-a")

    def test_expired_same_owner_reentry_rejects_snapshot_drift(self) -> None:
        (self.root / ".git").mkdir()
        key = f"repo:{self.root}"
        scope = self.scope_manifest(
            self.root, name="expired-admission-race", path=self.root
        )
        metadata = {
            "scope_manifest": scope,
            "scope_manifest_complete": True,
        }
        resources.acquire_resources(
            "owner-a",
            [key],
            purpose="stable expired repository race",
            ttl_seconds=60,
            metadata=metadata,
            admission_assessor=lambda **_kwargs: {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            },
        )
        with resources._database() as connection:
            connection.execute(
                "UPDATE leases SET updated_at_unix=1, expires_at_unix=0 WHERE resource_key=?",
                (key,),
            )

        def assessor(**_kwargs: object) -> dict[str, object]:
            with resources._database() as connection:
                connection.execute(
                    "UPDATE leases SET metadata_sha256=? WHERE resource_key=?",
                    ("f" * 64, key),
                )
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "b" * 64,
                "read_only": True,
            }

        with self.assertRaisesRegex(
            RuntimeError, "changed before reacquisition"
        ):
            resources.acquire_resources(
                "owner-a",
                [key],
                purpose="stable expired repository race",
                ttl_seconds=60,
                metadata=metadata,
                admission_assessor=assessor,
            )

    def test_work_admission_metadata_counts_isolated_decision(self) -> None:
        evidence = resources._work_admission_metadata(
            [
                {
                    "decision": "isolate_and_execute",
                    "blockers": [],
                    "blocker_codes": [],
                }
            ]
        )
        self.assertEqual(evidence["assessment_count"], 1)
        self.assertEqual(evidence["decision_counts"]["isolate_and_execute"], 1)
        self.assertEqual(evidence["decision_counts"]["allow"], 0)
        self.assertEqual(evidence["blocker_count"], 0)

    def test_work_admission_metadata_is_not_caller_controlled(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a public authority surface"):
            resources.acquire_resources(
                "owner-a",
                ["component:forbidden-work-admission"],
                purpose="attempt caller admission evidence",
                ttl_seconds=60,
                metadata={"work_admission": {"decision": "allow"}},
            )

    def test_broad_repository_lease_rejects_public_convergence_mode_override(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(
            self.root, name="convergence-override", path=self.root
        )
        assessor_calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            assessor_calls.append(dict(kwargs))
            raise AssertionError("rejected convergence metadata must not reach admission")

        with self.assertRaisesRegex(
            ValueError, "not a public authority surface"
        ):
            resources.acquire_resources(
                "owner-a",
                [f"repo:{self.root}"],
                purpose="attempt public convergence override",
                ttl_seconds=60,
                metadata={
                    "scope_manifest": scope,
                    "scope_manifest_complete": True,
                    "work_admission_mode": "convergence",
                },
                admission_assessor=assessor,
            )

        self.assertEqual(assessor_calls, [])
        self.assertIsNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_broad_repository_lease_without_scope_still_runs_admission(self) -> None:
        (self.root / ".git").mkdir()
        calls: list[dict[str, object]] = []

        def assessor(**kwargs: object) -> dict[str, object]:
            calls.append(dict(kwargs))
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "blocker_codes": [],
                "blockers": [],
                "read_only": True,
            }

        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}"],
            purpose="internal broad lease without scope",
            ttl_seconds=60,
            admission_assessor=assessor,
        )

        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0]["requested_scope"])
        self.assertEqual(result["work_admission"][0]["decision"], "allow")

    def test_persisted_admission_evidence_is_bounded_for_large_inputs(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(
            self.root, name="large-admission", path=self.root
        )
        scope["paths"] = [
            str(self.root / f"bounded-admission-path-{index:03d}" / ("x" * 32))
            for index in range(128)
        ]
        blockers = [
            {
                "code": f"bounded-code-{index:03d}",
                "path": str(self.root / f"worktree-{index:03d}" / ("y" * 64)),
            }
            for index in range(512)
        ]

        def assessor(**_kwargs: object) -> dict[str, object]:
            return {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "c" * 64,
                "requested_scope": scope,
                "blocker_codes": [item["code"] for item in blockers],
                "blockers": blockers,
                "read_only": True,
            }

        resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}"],
            purpose="large bounded admission evidence",
            ttl_seconds=60,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=assessor,
        )

        with resources._database() as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?",
                (f"repo:{self.root}",),
            ).fetchone()
        self.assertIsNotNone(row)
        metadata_json = row["metadata_json"]
        self.assertLessEqual(len(metadata_json.encode("utf-8")), 16 * 1024)
        metadata = json.loads(metadata_json)
        evidence = metadata["work_admission"]
        self.assertNotIn("assessments", evidence)
        self.assertEqual(evidence["assessment_count"], 1)
        self.assertRegex(evidence["assessment_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(evidence["blocker_count"], len(blockers))
        self.assertEqual(len(evidence["blocker_codes"]), 8)
        self.assertTrue(evidence["blocker_codes_truncated"])
        self.assertNotIn("requested_scope", evidence)
        self.assertNotIn("blockers", evidence)
        self.assertEqual(metadata["scope_manifest"]["paths"], scope["paths"])

    def test_broad_repository_lease_rejects_any_public_admission_mode_metadata(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(
            self.root, name="normal-mode-override", path=self.root
        )
        with self.assertRaisesRegex(
            ValueError, "not a public authority surface"
        ):
            resources.acquire_resources(
                "owner-a",
                [f"repo:{self.root}"],
                purpose="attempt public normal mode metadata",
                ttl_seconds=60,
                metadata={
                    "scope_manifest": scope,
                    "scope_manifest_complete": True,
                    "work_admission_mode": "normal",
                },
            )
        self.assertIsNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_broad_repository_admission_blocks_before_lease_creation(self) -> None:
        (self.root / ".git").mkdir()
        scope = self.scope_manifest(self.root, name="blocked-admission", path=self.root)
        assessment = {
            "schema_version": 1,
            "decision": "blocked",
            "blocker_codes": ["dirty-worktree"],
            "assessment_sha256": "b" * 64,
            "read_only": True,
        }

        def assessor(**_kwargs: object) -> dict[str, object]:
            raise work_admission.WorkAdmissionBlocked(assessment)

        with self.assertRaises(work_admission.WorkAdmissionBlocked):
            resources.acquire_resources(
                "owner-a",
                [f"repo:{self.root}"],
                purpose="blocked repository work",
                ttl_seconds=60,
                metadata={
                    "scope_manifest": scope,
                    "scope_manifest_complete": True,
                },
                admission_assessor=assessor,
            )
        self.assertIsNone(resources.inspect_resource(f"repo:{self.root}"))

    def test_exact_repository_scope_does_not_trigger_global_admission(self) -> None:
        (self.root / ".git").mkdir()
        called = False

        def assessor(**_kwargs: object) -> dict[str, object]:
            nonlocal called
            called = True
            raise AssertionError("exact branch work must stay on the non-conflict path")

        result = resources.acquire_resources(
            "owner-a",
            [f"repo:{self.root}:branch:feat/disjoint"],
            purpose="exact disjoint branch work",
            ttl_seconds=60,
            admission_assessor=assessor,
        )
        self.assertFalse(called)
        self.assertEqual(result["work_admission"], [])


    def _runtime_refresh_fixture(
        self,
        *,
        status: str = "deployed",
        effect_started: bool | None = None,
        resource_contract: str = "historical-five",
        persist_observation: bool = True,
        source_precondition: bool = False,
        source_precondition_drift: bool = False,
    ) -> dict[str, object]:
        state_root = self.root / "runtime-refresh"
        attempts_root = state_root / "attempts"
        intents_root = state_root / "intents"
        observations_root = state_root / "observations"
        workspaces_root = state_root / "workspaces"
        for directory in (
            state_root,
            attempts_root,
            intents_root,
            observations_root,
            workspaces_root,
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        main_commit = "a" * 40
        bin_dir = self.root / "bin"
        prefix = self.root / "prefix"
        workspace = workspaces_root / main_commit
        bin_dir.mkdir(mode=0o700)
        prefix.mkdir(mode=0o700)
        resource_sets = {
            "current-three": [
                f"path:{prefix}",
                f"path:{state_root}",
                f"path:{workspace}",
            ],
            "current-mixed": [
                f"path:{prefix}",
                f"path:{state_root}",
                f"path:{workspace}",
                "service:bureau-runtime-refresh.service",
                "service:bureau-runtime-refresh.timer",
            ],
            "unsupported-mixed": [
                f"path:{prefix}",
                f"path:{state_root}",
                f"path:{workspace}",
                "component:bureau.runtime",
            ],
            "historical-five": [
                f"path:{bin_dir / 'bureau'}",
                f"path:{bin_dir / 'bureau-runtime-refresh'}",
                f"path:{prefix}",
                f"path:{state_root}",
                f"path:{workspace}",
            ],
        }
        if resource_contract not in resource_sets:
            raise ValueError(
                f"unknown runtime-refresh resource contract: {resource_contract}"
            )
        resource_keys = sorted(resource_sets[resource_contract])
        owner = "operator:test-runtime-refresh"
        task_id = "BUREAU-RUNTIME-REFRESH-TEST"
        acquired_at = int(time.time()) - 60
        with patch.object(resources, "_now", return_value=acquired_at):
            resources.acquire_resources(
                owner,
                resource_keys,
                purpose="runtime refresh fixture",
                ttl_seconds=360,
            )
        snapshots = [
            {
                field: resources.inspect_resource(key)[field]
                for field in resources.LEASE_SNAPSHOT_KEYS
            }
            for key in resource_keys
        ]
        with sqlite3.connect(self.database) as connection:
            metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        lease_binding = {
            "owner_id": owner,
            "task_id": task_id,
            "resource_db": str(self.database),
            "resource_db_schema_version": metadata["schema_version"],
            "resource_lease_contract_version": metadata[
                "resource_lease_contract_version"
            ],
            "resource_keys": resource_keys,
            "min_expires_at_unix": min(item["expires_at_unix"] for item in snapshots),
            "lease_snapshots": snapshots,
            "observed_at_unix": acquired_at,
            "minimum_remaining_seconds": 30,
            "required_metadata_sha256": None,
        }
        lease_binding["lease_binding_sha256"] = (
            resources._runtime_refresh_payload_digest(
                lease_binding, "lease_binding_sha256"
            )
        )
        pull_request = {
            "number": 1,
            "url": "https://github.com/heimgewebe/bureau/pull/1",
            "head_commit": "c" * 40,
            "merge_commit": main_commit,
        }
        observation = {
            "schema_version": 1,
            "kind": "bureau_runtime_refresh_observation",
            "repository": "heimgewebe/bureau",
            "main_commit": main_commit,
            "pull_request": pull_request,
            "merged_at": "2026-08-03T08:59:00Z",
            "required_checks": ["validate (3.10)", "validate (3.12)"],
            "check_summary": {
                "validate (3.10)": {"state": "success", "observed_states": ["success"]},
                "validate (3.12)": {"state": "success", "observed_states": ["success"]},
            },
            "deployed_source_commit": "d" * 40,
            "deployed_manifest_sha256": "e" * 64,
            "lag_commits": 1,
            "status": "candidate",
            "reason_codes": [],
            "observed_at": "2026-08-03T09:00:00Z",
        }
        target_payload = {
            key: observation.get(key)
            for key in (
                "repository",
                "main_commit",
                "pull_request",
                "merged_at",
                "required_checks",
                "check_summary",
                "deployed_source_commit",
                "deployed_manifest_sha256",
                "lag_commits",
            )
        }
        target_sha256 = hashlib.sha256(
            (
                json.dumps(
                    target_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest()
        observation["target_sha256"] = target_sha256
        observation["observation_sha256"] = (
            resources._runtime_refresh_payload_digest(
                observation, "observation_sha256"
            )
        )
        intent = {
            "schema_version": 1,
            "kind": resources.BUREAU_RUNTIME_REFRESH_INTENT_KIND,
            "repository": "heimgewebe/bureau",
            "remote_url": "git@github.com:heimgewebe/bureau.git",
            "state_root": str(state_root),
            "workspace": str(workspace),
            "prefix": str(prefix),
            "bin_dir": str(bin_dir),
            "main_commit": main_commit,
            "target_sha256": target_sha256,
            "required_resource_keys": resource_keys,
            "pull_request": pull_request,
            "merged_at": observation["merged_at"],
            "observation_sha256": observation["observation_sha256"],
            "created_at": "2026-08-03T09:00:00Z",
            "expires_at": "2026-08-03T12:00:00Z",
            "expected_deployed_source_commit": "d" * 40,
            "expected_manifest_sha256": "e" * 64,
            "required_checks": ["validate (3.10)", "validate (3.12)"],
            "does_not_establish": ["deployment_outcome"],
        }
        if source_precondition:
            registered_manifest_sha256 = (
                "f" * 64 if source_precondition_drift else "e" * 64
            )
            intent["source_precondition"] = {
                "schema_version": 1,
                "policy": "registered-source-or-verified-target-ancestor",
                "identity_sources": [
                    "deployment-manifest.source_commit",
                    "canonical-registry.source_commit",
                ],
                "require_deployment_registry_identity_match": True,
                "registered_deployed_source_commit": "d" * 40,
                "registered_manifest_sha256": registered_manifest_sha256,
                "registered_registry_source_commit": "d" * 40,
                "ancestry_verification": "git-merge-base-is-ancestor",
                "require_target_freshness": True,
                "required_before": ["prepare-intent", "apply"],
                "fail_closed": True,
                "does_not_establish": ["future_runtime_health"],
            }
            intent["approval_task_id"] = task_id
            intent["runtime_approval"] = {
                "schema_version": 1,
                "required": True,
                "required_level": "break_glass",
                "action_class": "runtime_mutation",
                "action_classes": ["runtime_mutation"],
                "allowed": True,
                "reason": "approved",
                "expected_reference": target_sha256,
                "expected_task_id": task_id,
                "evidence": {
                    "schema_version": 1,
                    "approved": True,
                    "level": "break_glass",
                    "scope": ["runtime_mutation"],
                    "source": "test-authority",
                    "reviewer": "operator:test-runtime-refresh",
                    "reference": target_sha256,
                    "task_id": task_id,
                    "note": "test runtime refresh",
                },
            }
        intent["intent_sha256"] = resources._runtime_refresh_payload_digest(
            intent, "intent_sha256"
        )
        attempt_dir = attempts_root / target_sha256
        attempt_dir.mkdir(mode=0o700)
        started = {
            "schema_version": 1,
            "kind": resources.BUREAU_RUNTIME_REFRESH_START_KIND,
            "intent_sha256": intent["intent_sha256"],
            "lease_binding": lease_binding,
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(acquired_at + 10)
            ),
            "effect_started": False,
        }
        if status != "already_current":
            started["target_sha256"] = target_sha256
            started["main_commit"] = main_commit
        started["start_sha256"] = resources._runtime_refresh_payload_digest(
            started, "start_sha256"
        )
        finished_at_unix = acquired_at + 30
        result = {
            "schema_version": 1,
            "kind": resources.BUREAU_RUNTIME_REFRESH_RESULT_KIND,
            "status": status,
            "intent_sha256": intent["intent_sha256"],
            "main_commit": main_commit,
            "lease_binding": lease_binding,
            "finished_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished_at_unix)
            ),
            "effect_started": (
                status == "deployed" if effect_started is None else effect_started
            ),
        }
        if status != "already_current":
            result["target_sha256"] = target_sha256
        if status == "deployed":
            result.update(
                {
                    "source_identity": {
                        "root": str(workspace),
                        "head": main_commit,
                        "origin_main": main_commit,
                        "dirty": False,
                        "detached": True,
                        "remote_url": intent["remote_url"],
                    },
                    "install_receipt": {
                        "schema_version": 1,
                        "kind": "bureau_runtime_install_receipt",
                    },
                    "readback": {
                        "source_commit": main_commit,
                        "check_valid": True,
                        "runtime_identity_valid": True,
                    },
                    "does_not_establish": [
                        "future_runtime_health",
                        "future_main_stability",
                    ],
                }
            )
        elif status == "failed":
            result.update(
                {
                    "error": {
                        "code": "runtime-approval-missing",
                        "message": "pre-effect abort",
                        "details": {},
                    },
                    "workspace_preserved": False,
                    "does_not_establish": ["future_success"],
                }
            )
        elif status == "unclear":
            result.update(
                {
                    "error": {
                        "code": "effect-timeout",
                        "message": "ambiguous",
                        "details": {},
                    },
                    "workspace_preserved": True,
                    "does_not_establish": ["safe_retry", "deployment_outcome"],
                }
            )
        result["result_sha256"] = resources._runtime_refresh_payload_digest(
            result, "result_sha256"
        )
        payloads = [
            (intents_root / f"{intent['intent_sha256']}.json", intent),
            (attempt_dir / "started.json", started),
            (attempt_dir / "result.json", result),
        ]
        if persist_observation:
            payloads.insert(
                0,
                (
                    observations_root
                    / (
                        "20260803T090000.000000Z-"
                        f"{main_commit[:12]}-{observation['observation_sha256'][:12]}.json"
                    ),
                    observation,
                ),
            )
        for path, payload in payloads:
            path.write_text(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
        return {
            "state_root": state_root,
            "target_sha256": target_sha256,
            "result_sha256": result["result_sha256"],
            "result_path": attempt_dir / "result.json",
            "owner": owner,
            "resource_keys": resource_keys,
            "snapshots": snapshots,
        }

    def test_runtime_refresh_terminal_release_deployed_and_reacquires(self) -> None:
        fixture = self._runtime_refresh_fixture()
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertEqual("complete", result["state"])
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in result["released"]],
        )
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            replay = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertEqual("no_change", replay["state"])
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in replay["retained"]],
        )
        self.assertTrue(
            all(item["reason"] == "already_absent" for item in replay["retained"])
        )
        self.assertEqual([], replay["released"])
        started = time.monotonic()
        reacquired = resources.acquire_resources(
            fixture["owner"],
            fixture["resource_keys"],
            purpose="next runtime refresh",
            ttl_seconds=120,
        )
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in reacquired["leases"]],
        )

    def test_runtime_refresh_terminal_release_accepts_current_three_resource_contract(self) -> None:
        fixture = self._runtime_refresh_fixture(resource_contract="current-three")
        self.assertEqual(3, len(fixture["resource_keys"]))
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertEqual("complete", result["state"])
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in result["released"]],
        )
        reacquired = resources.acquire_resources(
            fixture["owner"],
            fixture["resource_keys"],
            purpose="next current-contract runtime refresh",
            ttl_seconds=120,
        )
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in reacquired["leases"]],
        )

    def test_runtime_refresh_terminal_release_accepts_current_mixed_contract_without_observation_receipt(self) -> None:
        fixture = self._runtime_refresh_fixture(
            resource_contract="current-mixed",
            persist_observation=False,
            source_precondition=True,
        )
        self.assertTrue(
            any(key.startswith("service:") for key in fixture["resource_keys"])
        )
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertEqual("complete", result["state"])
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in result["released"]],
        )
        reacquired = resources.acquire_resources(
            fixture["owner"],
            fixture["resource_keys"],
            purpose="next mixed-contract runtime refresh",
            ttl_seconds=120,
        )
        self.assertEqual(
            fixture["resource_keys"],
            [item["resource_key"] for item in reacquired["leases"]],
        )

    def test_runtime_refresh_terminal_release_without_observation_requires_source_precondition(self) -> None:
        fixture = self._runtime_refresh_fixture(persist_observation=False)
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ), self.assertRaisesRegex(
            resources.nonconflict.NonConflictDenied, "source precondition is invalid"
        ):
            resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )

    def test_runtime_refresh_terminal_release_rejects_source_precondition_drift(self) -> None:
        fixture = self._runtime_refresh_fixture(
            persist_observation=False,
            source_precondition=True,
            source_precondition_drift=True,
        )
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ), self.assertRaisesRegex(
            resources.nonconflict.NonConflictDenied, "source precondition differs"
        ):
            resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )

    def test_runtime_refresh_terminal_release_rejects_unknown_resource_kind(self) -> None:
        fixture = self._runtime_refresh_fixture(resource_contract="unsupported-mixed")
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ), self.assertRaisesRegex(
            resources.nonconflict.NonConflictDenied, "unsupported resource kind"
        ):
            resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )

    def test_runtime_refresh_terminal_source_rejects_caller_subset_and_superset(self) -> None:
        fixture = self._runtime_refresh_fixture(resource_contract="current-three")
        source = {
            "kind": resources.BUREAU_RUNTIME_REFRESH_RESULT_KIND,
            "target_sha256": fixture["target_sha256"],
            "result_sha256": fixture["result_sha256"],
        }
        extra_key = f"path:{self.root / 'extra-runtime-refresh-resource'}"
        resources.acquire_resources(
            fixture["owner"],
            [extra_key],
            purpose="unbound runtime refresh resource",
            ttl_seconds=360,
        )
        extra_snapshot = {
            field: resources.inspect_resource(extra_key)[field]
            for field in resources.LEASE_SNAPSHOT_KEYS
        }
        cases = [
            (
                "subset",
                list(fixture["resource_keys"][:-1]),
                list(fixture["snapshots"][:-1]),
            ),
            (
                "superset",
                sorted([*fixture["resource_keys"], extra_key]),
                sorted(
                    [*fixture["snapshots"], extra_snapshot],
                    key=lambda item: item["resource_key"],
                ),
            ),
        ]
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            for label, resource_keys, snapshots in cases:
                with self.subTest(label=label):
                    with self.assertRaisesRegex(PermissionError, "names other resources"):
                        resources.reconcile_obsolete_path_leases(
                            owner_id=fixture["owner"],
                            resource_keys=resource_keys,
                            expected_leases=snapshots,
                            terminal_source=source,
                        )
        self.assertTrue(
            all(
                resources.inspect_resource(key) is not None
                for key in [*fixture["resource_keys"], extra_key]
            )
        )

    def test_runtime_refresh_mcp_tool_requires_operator_and_audits(self) -> None:
        target_sha256 = "a" * 64
        result_sha256 = "b" * 64
        output = {
            "state": "complete",
            "owner_id": "operator:test-runtime-refresh",
            "resource_keys": ["path:/tmp/runtime-refresh"],
            "released": [{"resource_key": "path:/tmp/runtime-refresh"}],
            "retained": [],
            "receipt_sha256": "c" * 64,
        }
        with patch.object(
            resources.operator, "_require_operator_mutation"
        ) as require_operator, patch.object(
            resources,
            "release_runtime_refresh_terminal_leases",
            return_value=output,
        ) as release, patch.object(resources.base, "_append_audit") as append_audit:
            result = resources.grabowski_runtime_refresh_lease_release(
                target_sha256=target_sha256,
                result_sha256=result_sha256,
            )
        self.assertEqual(output, result)
        require_operator.assert_called_once_with("resource_lease")
        release.assert_called_once_with(
            target_sha256=target_sha256,
            result_sha256=result_sha256,
        )
        audit = append_audit.call_args.args[0]
        self.assertEqual("runtime-refresh-lease-release", audit["operation"])
        self.assertEqual(target_sha256, audit["target_sha256"])
        self.assertEqual(result_sha256, audit["result_sha256"])
        self.assertEqual(output["receipt_sha256"], audit["receipt_sha256"])

    def test_runtime_refresh_terminal_release_accepts_already_current(self) -> None:
        fixture = self._runtime_refresh_fixture(
            status="already_current", effect_started=False
        )
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertEqual("complete", result["state"])
        self.assertEqual(
            "already_current", result["terminal_evidence"]["status"]
        )

    def test_runtime_refresh_terminal_release_accepts_pre_effect_failure(self) -> None:
        fixture = self._runtime_refresh_fixture(status="failed", effect_started=False)
        source = {
            "kind": resources.BUREAU_RUNTIME_REFRESH_RESULT_KIND,
            "target_sha256": fixture["target_sha256"],
            "result_sha256": fixture["result_sha256"],
        }
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=fixture["owner"],
                resource_keys=fixture["resource_keys"],
                expected_leases=fixture["snapshots"],
                terminal_source=source,
            )
        self.assertEqual("complete", result["state"])
        self.assertEqual("failed", result["terminal_evidence"]["status"])

    def test_runtime_refresh_terminal_release_rejects_unclear_and_missing_result(self) -> None:
        fixture = self._runtime_refresh_fixture(status="unclear", effect_started=True)
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            with self.assertRaisesRegex(
                resources.nonconflict.NonConflictDenied,
                "unclear or not explicitly terminal",
            ):
                resources.release_runtime_refresh_terminal_leases(
                    target_sha256=fixture["target_sha256"],
                    result_sha256=fixture["result_sha256"],
                )
            Path(fixture["result_path"]).unlink()
            with self.assertRaisesRegex(
                resources.nonconflict.NonConflictDenied,
                "result or start receipt is absent",
            ):
                resources.release_runtime_refresh_terminal_leases(
                    target_sha256=fixture["target_sha256"],
                    result_sha256=fixture["result_sha256"],
                )
        self.assertTrue(
            all(
                resources.inspect_resource(key) is not None
                for key in fixture["resource_keys"]
            )
        )

    def test_runtime_refresh_terminal_release_rejects_tamper(self) -> None:
        fixture = self._runtime_refresh_fixture()
        result_path = Path(fixture["result_path"])
        payload = json.loads(result_path.read_text())
        payload["main_commit"] = "f" * 40
        result_path.write_text(json.dumps(payload) + "\n")
        result_path.chmod(0o600)
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ), self.assertRaisesRegex(
            resources.nonconflict.NonConflictDenied, "result digest is invalid"
        ):
            resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertTrue(
            all(
                resources.inspect_resource(key) is not None
                for key in fixture["resource_keys"]
            )
        )

    def test_runtime_refresh_terminal_release_rejects_target_tamper(self) -> None:
        fixture = self._runtime_refresh_fixture()
        observations = list(
            (Path(fixture["state_root"]) / "observations").glob("*.json")
        )
        self.assertEqual(1, len(observations))
        payload = json.loads(observations[0].read_text())
        payload["lag_commits"] = 2
        payload["observation_sha256"] = (
            resources._runtime_refresh_payload_digest(
                payload, "observation_sha256"
            )
        )
        observations[0].write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        )
        observations[0].chmod(0o600)
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ), self.assertRaisesRegex(
            resources.nonconflict.NonConflictDenied,
            "observation identity changed|observation receipt is absent or ambiguous|target digest is invalid",
        ):
            resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        self.assertTrue(
            all(
                resources.inspect_resource(key) is not None
                for key in fixture["resource_keys"]
            )
        )

    def test_runtime_refresh_terminal_release_retains_changed_and_foreign_leases(self) -> None:
        fixture = self._runtime_refresh_fixture()
        changed_key, foreign_key = fixture["resource_keys"][:2]
        resources.renew_resources(fixture["owner"], [changed_key], ttl_seconds=600)
        resources.release_resources(fixture["owner"], [foreign_key])
        resources.acquire_resources(
            "operator:foreign-runtime-refresh",
            [foreign_key],
            purpose="foreign replacement",
            ttl_seconds=600,
        )
        with patch.object(
            resources,
            "BUREAU_RUNTIME_REFRESH_STATE_ROOT",
            fixture["state_root"],
        ):
            result = resources.release_runtime_refresh_terminal_leases(
                target_sha256=fixture["target_sha256"],
                result_sha256=fixture["result_sha256"],
            )
        retained = {item["resource_key"]: item["reason"] for item in result["retained"]}
        self.assertEqual("lease_snapshot_changed", retained[changed_key])
        self.assertEqual("owner_changed", retained[foreign_key])
        self.assertEqual(
            "operator:foreign-runtime-refresh",
            resources.inspect_resource(foreign_key)["owner_id"],
        )

if __name__ == "__main__":
    unittest.main()
