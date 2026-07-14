from __future__ import annotations

from pathlib import Path
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

    def test_normalizes_typed_resource_keys(self) -> None:
        self.assertEqual(resources.normalize_resource_key("port:09222"), "port:9222")
        self.assertEqual(resources.normalize_resource_key("display::17"), "display:17")
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
        existing_path = f"path:{repository / 'src' / 'owned.py'}"
        existing_main = "service:github-main:heimgewebe-grabowski"
        resources.acquire_resources(
            "task-owner",
            [existing_path, existing_main],
            purpose="active task resources",
            ttl_seconds=120,
        )
        keys = [
            f"repo:{repository}",
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
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "local_resource_repository": str(repository),
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                }
            },
        )
        self.assertEqual([existing_path, existing_main], [
            item["resource_key"] for item in result["observed_leases"]
        ])
        self.assertEqual(
            sorted(set(keys) - {existing_main}), result["held_resource_keys"]
        )
        resources.release_resources(
            "captain-merge:guard-1", result["held_resource_keys"]
        )
        self.assertEqual("task-owner", resources.inspect_resource(existing_path)["owner_id"])
        self.assertEqual("task-owner", resources.inspect_resource(existing_main)["owner_id"])
        self.assertEqual([existing_path, existing_main], [
            item["resource_key"] for item in resources.list_resources()
        ])

    def test_merge_guard_preserves_existing_owner_repo_lease_and_blocks_new_overlap(self) -> None:
        repository = self.root / "repo"
        repository.mkdir()
        repo_key = f"repo:{repository}"
        resources.acquire_resources(
            "task-owner", [repo_key], purpose="active task repo", ttl_seconds=120
        )
        keys = [
            repo_key,
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
            purpose="atomic merge guard",
            ttl_seconds=60,
            metadata={
                "merge_guard": {
                    "local_resource_repository": str(repository),
                    "head_sha": "a" * 40,
                    "diff_sha256": "b" * 64,
                }
            },
        )
        self.assertEqual([repo_key], [
            item["resource_key"] for item in result["observed_leases"]
        ])
        self.assertNotIn(repo_key, result["held_resource_keys"])
        with self.assertRaises(resources.ResourceConflict):
            resources.acquire_resources(
                "task-owner",
                [f"path:{repository / 'late.py'}"],
                purpose="late same-owner write",
                ttl_seconds=60,
            )
        resources.release_resources(
            "captain-merge:guard-2", result["held_resource_keys"]
        )
        self.assertEqual("task-owner", resources.inspect_resource(repo_key)["owner_id"])

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
