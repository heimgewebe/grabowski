from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
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


import grabowski_checkouts as checkouts


class CheckoutLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.checkout = self.root / "worktrees" / "topic"
        self.checkout_db = self.root / "state" / "checkouts.sqlite3"
        self.archive_root = self.root / "state" / "archives"
        self.resource_db = self.root / "state" / "resources.sqlite3"
        self.task_db = self.root / "state" / "tasks.sqlite3"
        self.repo.mkdir()
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Grabowski Test")
        self._git("config", "user.email", "grabowski@example.invalid")
        (self.repo / "README.md").write_text("initial\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("commit", "-m", "initial")
        self.head = self._git("rev-parse", "HEAD").stdout.strip()
        self._git("worktree", "add", "-b", "topic", str(self.checkout), "HEAD")

        self.patches = [
            patch.object(checkouts, "CHECKOUT_DB", self.checkout_db),
            patch.object(checkouts, "ARCHIVE_ROOT", self.archive_root),
            patch.object(checkouts, "CHECKOUT_LOCK", self.root / "state" / "checkouts.lock"),
            patch.object(checkouts.resources, "RESOURCE_DB", self.resource_db),
            patch.object(checkouts.tasks, "TASK_DB", self.task_db),
            patch.object(checkouts.operator, "_safe_environment", return_value=os.environ.copy()),
            patch.object(checkouts.operator, "_require_operator_mutation"),
            patch.object(checkouts.operator, "_require_operator_capability"),
            patch.object(checkouts.base, "_append_audit"),
            patch.object(checkouts, "_processes_under", return_value=[]),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _git(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(cwd or self.repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _archive(self) -> dict[str, object]:
        return checkouts.grabowski_checkout_archive(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            "temporary review checkout",
            int(time.time()) + 3600,
            self.head,
            "topic",
        )

    def test_parent_directory_is_not_a_checkout_process_scope(self) -> None:
        parent = self.root
        self.assertFalse(
            checkouts._path_inside_any(parent, [self.checkout, self.repo])
        )
        self.assertTrue(
            checkouts._path_inside_any(self.checkout, [self.checkout, self.repo])
        )
        self.assertTrue(
            checkouts._path_inside_any(self.checkout / "nested", [self.checkout])
        )

    def test_task_in_parent_directory_does_not_block_child_checkout(self) -> None:
        with checkouts.tasks._database() as connection:
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, host, unit, attempt, state, resume_policy,
                    argv_json, argv_sha256, cwd, runtime_seconds,
                    cpu_weight, io_weight, memory_max_bytes,
                    created_at_unix, updated_at_unix, launcher_json,
                    last_observation_json, resource_keys_json, lease_owner_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "c" * 24,
                    "local",
                    "grabowski-task-" + "c" * 24 + "-a1.service",
                    1,
                    "running",
                    "manual",
                    '["/bin/true"]',
                    "d" * 64,
                    str(self.root),
                    60,
                    100,
                    100,
                    None,
                    int(time.time()),
                    int(time.time()),
                    "{}",
                    None,
                    "[]",
                    "task:" + "c" * 24,
                ),
            )
            connection.commit()
        self.assertEqual(
            checkouts._task_records([self.checkout, self.repo]),
            [],
        )


    def test_archive_ignores_processes_in_main_checkout(self) -> None:
        def fake_processes(paths: list[Path]) -> list[dict[str, object]]:
            if any(path == self.repo for path in paths):
                return [{"pid": 123, "cwd": str(self.repo), "command": "shell"}]
            return []

        with patch.object(checkouts, "_processes_under", side_effect=fake_processes):
            archive = self._archive()

        self.assertEqual(archive["audit"]["coordination_checked"]["processes"], 0)


    def test_archive_preserves_repo_scoped_task_blocker(self) -> None:
        with checkouts.tasks._database() as connection:
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, host, unit, attempt, state, resume_policy,
                    argv_json, argv_sha256, cwd, runtime_seconds,
                    cpu_weight, io_weight, memory_max_bytes,
                    created_at_unix, updated_at_unix, launcher_json,
                    last_observation_json, resource_keys_json, lease_owner_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "e" * 24,
                    "local",
                    "grabowski-task-" + "e" * 24 + "-a1.service",
                    1,
                    "running",
                    "manual",
                    '["/bin/true"]',
                    "f" * 64,
                    str(self.repo),
                    60,
                    100,
                    100,
                    None,
                    int(time.time()),
                    int(time.time()),
                    "{}",
                    None,
                    json.dumps([f"repo:{self.repo}"]),
                    "task:" + "e" * 24,
                ),
            )
            connection.commit()

        with self.assertRaisesRegex(RuntimeError, "tasks=1"):
            self._archive()

    def test_inventory_is_deterministic_and_shows_linked_checkout(self) -> None:
        first = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        second = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        self.assertEqual(first["inventory_sha256"], second["inventory_sha256"])
        paths = [item["path"] for item in first["worktrees"]]
        self.assertEqual(paths, sorted(paths))
        linked = next(item for item in first["worktrees"] if item["path"] == str(self.checkout))
        self.assertTrue(linked["is_linked"])
        self.assertEqual(linked["head"], self.head)
        self.assertEqual(linked["branch"], "topic")
        self.assertFalse(linked["status"]["dirty"])
        self.assertEqual(linked["lifecycle_state"], "unclassified_clean")
        self.assertEqual(linked["hygiene_mark"], "unknown")
        self.assertFalse(linked["cleanup_candidate"])
        self.assertFalse(linked["lifecycle_decision"]["requires_cleanup_dry_run"])
        self.assertIn("permission_to_cleanup", linked["lifecycle_decision"]["does_not_establish"])

    def test_archive_creates_recovery_refs_and_preserves_branch(self) -> None:
        result = self._archive()
        archive = result["archive"]
        refs = archive["recovery_refs"]
        self.assertEqual(archive["head"], self.head)
        self.assertEqual(archive["branch"], "topic")
        self.assertEqual(
            self._git("rev-parse", "--verify", "refs/heads/topic").stdout.strip(),
            self.head,
        )
        for item in refs:
            self.assertEqual(
                self._git("rev-parse", "--verify", f"{item['ref']}^{{commit}}").stdout.strip(),
                item["target"],
            )
        manifest = json.loads(Path(archive["manifest_path"]).read_text(encoding="utf-8"))
        self.assertTrue(manifest["rollback"]["branch_preserved"])
        self.assertEqual(manifest["cleanup"]["tool"], "grabowski_checkout_cleanup")

    def test_inventory_marks_retained_clean_checkout(self) -> None:
        retained_until = int(time.time()) + 3600
        checkouts.grabowski_checkout_retain(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            "keep for review",
            retained_until,
            self.head,
            "topic",
        )
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertEqual(linked["lifecycle_state"], "retained")
        self.assertEqual(linked["hygiene_mark"], "retained")
        self.assertTrue(linked["lifecycle_decision"]["retention_active"])
        self.assertFalse(linked["cleanup_candidate"])

    def test_inventory_marks_archived_checkout_as_cleanup_candidate(self) -> None:
        self._archive()
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertEqual(linked["lifecycle_state"], "cleanup_candidate")
        self.assertEqual(linked["hygiene_mark"], "obsolete")
        self.assertTrue(linked["cleanup_candidate"])
        self.assertTrue(linked["lifecycle_decision"]["requires_cleanup_dry_run"])

    def test_cleanup_requires_prior_dry_run_and_uses_plain_worktree_remove(self) -> None:
        archive = self._archive()["archive"]
        with self.assertRaisesRegex(ValueError, "plan_id"):
            checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=False,
                archive_id=archive["archive_id"],
                confirmation="remove-linked-checkout",
            )

        dry_run = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=True,
            archive_id=archive["archive_id"],
            expected_head=self.head,
            expected_branch="topic",
        )
        self.assertTrue(dry_run["plan"]["safe_to_apply"])
        applied = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=False,
            plan_id=dry_run["dry_run_record"]["plan_id"],
            expected_plan_sha256=dry_run["plan"]["plan_sha256"],
            confirmation="remove-linked-checkout",
        )
        self.assertFalse(self.checkout.exists())
        self.assertEqual(
            self._git("rev-parse", "--verify", "refs/heads/topic").stdout.strip(),
            self.head,
        )
        self.assertNotIn("--force", applied["result"]["argv"])

    def test_running_task_blocks_cleanup_apply(self) -> None:
        archive = self._archive()["archive"]
        with checkouts.tasks._database() as connection:
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, host, unit, attempt, state, resume_policy,
                    argv_json, argv_sha256, cwd, runtime_seconds,
                    cpu_weight, io_weight, memory_max_bytes,
                    created_at_unix, updated_at_unix, launcher_json,
                    last_observation_json, resource_keys_json, lease_owner_id
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "a" * 24,
                    "local",
                    "grabowski-task-" + "a" * 24 + "-a1.service",
                    1,
                    "running",
                    "manual",
                    '["/bin/true"]',
                    "b" * 64,
                    str(self.checkout),
                    60,
                    100,
                    100,
                    None,
                    int(time.time()),
                    int(time.time()),
                    "{}",
                    None,
                    "[]",
                    "task:" + "a" * 24,
                ),
            )
            connection.commit()
        dry_run = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=True,
            archive_id=archive["archive_id"],
        )
        self.assertFalse(dry_run["plan"]["safe_to_apply"])
        self.assertEqual(dry_run["plan"]["coordination"]["blocking_counts"]["tasks"], 1)
        with self.assertRaisesRegex(RuntimeError, "active work"):
            checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=False,
                plan_id=dry_run["dry_run_record"]["plan_id"],
                expected_plan_sha256=dry_run["plan"]["plan_sha256"],
                confirmation="remove-linked-checkout",
            )

    def test_retention_can_protect_dirty_checkout_and_rejects_foreign_owner(self) -> None:
        (self.checkout / "untracked.txt").write_text("preserve me\n", encoding="utf-8")
        retained_until = int(time.time()) + 3600
        first = checkouts.grabowski_checkout_retain(
            str(self.repo), str(self.checkout), "owner-a", "unfinished work",
            retained_until, self.head, "topic",
        )
        self.assertEqual(first["retention"]["owner_id"], "owner-a")
        lease_expiry = max(item["expires_at_unix"] for item in first["lease"]["leases"])
        self.assertLessEqual(
            lease_expiry - int(time.time()), checkouts.OPERATION_LEASE_TTL_SECONDS
        )
        with self.assertRaisesRegex(PermissionError, "another owner"):
            checkouts.grabowski_checkout_retain(
                str(self.repo), str(self.checkout), "owner-b", "foreign retention",
                retained_until + 60, self.head, "topic",
            )

    def test_archive_rejects_symlinked_git_metadata(self) -> None:
        git_file = self.checkout / ".git"
        target = self.root / "gitfile-target"
        target.write_text(git_file.read_text(encoding="utf-8"), encoding="utf-8")
        git_file.unlink()
        git_file.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "Symlinked"):
            self._archive()

    def test_lifecycle_source_has_no_forced_filesystem_deletion(self) -> None:
        source = (SRC / "grabowski_checkouts.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn('"worktree", "remove", "--force"', source)
        self.assertNotIn('"worktree", "remove", "-f"', source)


if __name__ == "__main__":
    unittest.main()
