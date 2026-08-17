from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import sqlite3
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
import grabowski_work_admission as work_admission


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

    def _publish_remote(self) -> None:
        """Make the current heads visible on local origin remote-tracking refs.

        The test environment blocks direct pushes to main, so remote-tracking
        refs are written with update-ref after a bare origin is available.
        """
        origin = self.root / "origin.git"
        if not origin.exists():
            subprocess.run(
                ["git", "init", "--bare", str(origin)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._git("remote", "add", "origin", str(origin))
        head = self._git("rev-parse", "HEAD").stdout.strip()
        topic = self._git("rev-parse", "topic").stdout.strip()
        self._git("update-ref", "refs/remotes/origin/main", head)
        self._git("update-ref", "refs/remotes/origin/topic", topic)

    def _archive(self, *, aged: bool = True) -> dict[str, object]:
        result = checkouts.grabowski_checkout_archive(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            "temporary review checkout",
            int(time.time()) + 3600,
            self.head,
            "topic",
        )
        if aged:
            archive = result["archive"]
            assert isinstance(archive, dict)
            created_at = (
                int(time.time()) - checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS - 1
            )
            with checkouts._database() as connection:
                connection.execute(
                    "UPDATE archives SET created_at_unix=? WHERE archive_id=?",
                    (created_at, archive["archive_id"]),
                )
                connection.execute(
                    "UPDATE retention SET retention_until_unix=? WHERE checkout_key=?",
                    (created_at, archive["checkout_key"]),
                )
                connection.execute(
                    "UPDATE lifecycle_bindings SET retention_until_unix=? WHERE checkout_key=?",
                    (created_at, archive["checkout_key"]),
                )
                connection.commit()
            archive["created_at_unix"] = created_at
            archive["retention_until_unix"] = created_at
        return result

    def _common_dir(self) -> Path:
        raw = Path(self._git("rev-parse", "--git-common-dir").stdout.strip())
        return (self.repo / raw).resolve() if not raw.is_absolute() else raw.resolve()

    def _managed_binding(
        self,
        *,
        owner: str = "owner-a",
        retention_seconds: int = 3600,
    ) -> dict[str, object]:
        common_dir = self._common_dir()
        retained_until = int(time.time()) + retention_seconds
        binding = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=self.checkout,
            owner_id=owner,
            purpose="managed lifecycle fixture",
            source_kind="bureau_task",
            source_id="GRABOWSKI-OPERATOR-SURFACE-V1-T095",
            artifact_class="implementation_worktree",
            retention_until_unix=retained_until,
            expected_head=self.head,
            expected_branch="topic",
        )
        checkouts._upsert_retention(
            checkout_key=str(binding["checkout_key"]),
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=self.checkout,
            owner_id=owner,
            purpose="managed lifecycle fixture",
            retention_until_unix=retained_until,
            expected_head=self.head,
            expected_branch="topic",
        )
        return binding

    def _completed_owner_drift(self) -> dict[str, object]:
        binding = self._managed_binding(owner="owner-a")
        checkouts._mark_checkout_completed_retained(
            checkout_key=str(binding["checkout_key"]),
            owner_id="owner-a",
            expected_head=self.head,
            expected_branch="topic",
        )
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET owner_id='owner-b' WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        return binding

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

    def test_task_inventory_schema_drift_is_unobservable(self) -> None:
        self.task_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.task_db) as connection:
            connection.execute("CREATE TABLE tasks(task_id TEXT PRIMARY KEY)")
            connection.commit()

        with self.assertRaisesRegex(
            RuntimeError, "Task inventory projection is unavailable"
        ):
            checkouts._task_records([self.checkout, self.repo])

        assessment = work_admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=lambda repo: checkouts.checkout_inventory(
                repo,
                include_processes=False,
                include_tasks=True,
                include_resources=False,
            ),
            reconciliation_loader=lambda _repo: {
                "bindings": [],
                "pagination": {"has_more": False},
                "source_snapshot": {"repository_errors": []},
                "snapshot_sha256": "a" * 64,
            },
        )
        self.assertEqual(assessment["decision"], "blocked")
        self.assertIn("inventory-unobservable", assessment["blocker_codes"])
        self.assertTrue(
            any(
                "Task inventory projection is unavailable"
                in str(blocker.get("detail", ""))
                for blocker in assessment["blockers"]
            )
        )

    def test_process_cgroup_reports_exact_systemd_task_unit(self) -> None:
        proc_entry = self.root / "proc" / "43210"
        proc_entry.mkdir(parents=True)
        unit = "grabowski-task-" + "a" * 24 + "-a2.service"
        (proc_entry / "cgroup").write_text(
            f"0::/user.slice/app.slice/{unit}\n",
            encoding="utf-8",
        )

        self.assertEqual(checkouts._process_systemd_units(proc_entry), [unit])


    def test_archive_ignores_processes_in_main_checkout(self) -> None:
        def fake_processes(paths: list[Path]) -> list[dict[str, object]]:
            if any(path == self.repo for path in paths):
                return [{"pid": 123, "cwd": str(self.repo), "command": "shell"}]
            return []

        with patch.object(checkouts, "_processes_under", side_effect=fake_processes):
            archive = self._archive()

        self.assertEqual(archive["audit"]["coordination_checked"]["processes"], 0)


    def test_archive_converges_managed_binding_to_terminal_identity(self) -> None:
        self._managed_binding()
        (self.checkout / "README.md").write_text("terminal head\n", encoding="utf-8")
        self._git("add", "README.md", cwd=self.checkout)
        self._git("commit", "-m", "terminal head", cwd=self.checkout)
        terminal_head = self._git(
            "rev-parse", "HEAD", cwd=self.checkout
        ).stdout.strip()

        result = checkouts.grabowski_checkout_archive(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            "archive exact terminal identity",
            int(time.time()) + 3600,
            terminal_head,
            "topic",
        )

        binding = result["lifecycle_binding"]
        self.assertEqual(binding["phase"], "archived")
        self.assertEqual(binding["expected_head"], terminal_head)
        self.assertEqual(binding["expected_branch"], "topic")
        self.assertIsNotNone(binding["terminal_at_unix"])
        inventory = checkouts.checkout_inventory(
            str(self.repo),
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        record = next(
            item for item in inventory["worktrees"]
            if item["path"] == str(self.checkout.resolve())
        )
        self.assertTrue(record["lifecycle_decision"]["binding_consistent"])
        self.assertEqual(record["lifecycle_decision"]["binding_drift_reasons"], [])

    def test_archive_rejects_managed_binding_branch_drift_before_effects(self) -> None:
        binding = self._managed_binding()
        checkout_key = str(binding["checkout_key"])
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET expected_branch=? WHERE checkout_key=?",
                ("other", checkout_key),
            )
            connection.commit()
        retention_before = checkouts._retention_records([checkout_key])[checkout_key]

        with self.assertRaisesRegex(
            RuntimeError, "lifecycle branch changed before archive"
        ):
            self._archive()

        retention_after = checkouts._retention_records([checkout_key])[checkout_key]
        self.assertEqual(retention_after, retention_before)
        with checkouts._database() as connection:
            count = connection.execute("SELECT count(*) FROM archives").fetchone()[0]
        self.assertEqual(count, 0)

    def test_archive_uses_exact_checkout_common_dir_and_branch_operation_leases(self) -> None:
        result = self._archive()
        keys = {item["resource_key"] for item in result["lease"]["leases"]}
        self.assertEqual(
            keys,
            {
                f"path:{self.checkout.resolve()}",
                f"path:{self._common_dir()}",
                f"repo:{self.repo.resolve()}:branch:topic",
            },
        )
        self.assertNotIn(f"repo:{self.repo.resolve()}", keys)

    def _bureau_resource_partition(self, keys):
        return sorted(
            key
            for key in keys
            if key in {
                f"path:{self.checkout.resolve()}",
                f"path:{self._common_dir()}",
            }
        )

    def _bureau_contract_for_test(self, keys, **kwargs):
        return {"phase": "work"} if self._bureau_resource_partition(keys) else None

    def test_bureau_checkout_cleanup_sequences_resource_classes_and_succeeds(self) -> None:
        with (
            patch.object(
                checkouts.resources.bureau_leases,
                "bureau_resource_keys",
                side_effect=self._bureau_resource_partition,
            ),
            patch.object(
                checkouts.resources.bureau_leases,
                "enforce_bureau_lease_contract",
                side_effect=self._bureau_contract_for_test,
            ),
        ):
            archived = self._archive()
            classes = archived["lease"]["resource_classes"]
            self.assertEqual(
                set(classes["bureau"]),
                {
                    f"path:{self.checkout.resolve()}",
                    f"path:{self._common_dir()}",
                },
            )
            self.assertEqual(
                classes["non_bureau"],
                [f"repo:{self.repo.resolve()}:branch:topic"],
            )
            archive = archived["archive"]
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )
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
        self.assertNotIn("--force", applied["result"]["argv"])
        self.assertEqual(checkouts._read_resource_leases(), [])

    def test_resource_lease_reader_fails_before_query_when_contract_is_invalid(self) -> None:
        lease_queries: list[str] = []

        class Connection:
            def execute(self, query, _parameters):
                lease_queries.append(query)
                raise AssertionError("lease rows must not be read without a valid contract")

            def close(self):
                pass

        with (
            patch.object(checkouts, "_readonly_connection", return_value=Connection()),
            patch.object(
                checkouts.resources,
                "_begin_resource_lease_projection_read",
                side_effect=RuntimeError("Resource lease contract metadata is missing"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "contract metadata is missing"):
                checkouts._read_resource_leases()

        self.assertEqual(lease_queries, [])

    def test_resource_lease_reader_does_not_hide_sqlite_failure(self) -> None:
        class Connection:
            def execute(self, query, _parameters=()):
                if query.startswith("SELECT * FROM leases"):
                    raise sqlite3.OperationalError("database is locked")
                raise AssertionError(f"unexpected query: {query}")

            def close(self):
                pass

        with (
            patch.object(checkouts, "_readonly_connection", return_value=Connection()),
            patch.object(
                checkouts.resources,
                "_begin_resource_lease_projection_read",
                return_value="1",
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "Resource lease projection is unavailable"
            ):
                checkouts._read_resource_leases()

    def test_resource_lease_reader_accepts_future_aggregate_schema_with_contract_v1(self) -> None:
        checkouts.resources.acquire_resources(
            "future-schema-owner",
            [f"path:{self.checkout.resolve()}"],
            purpose="future aggregate schema lease projection proof",
            ttl_seconds=3600,
        )
        with sqlite3.connect(self.resource_db) as connection:
            connection.execute(
                "UPDATE metadata SET value='4' WHERE key='schema_version'"
            )
            connection.commit()

        leases = checkouts._read_resource_leases()

        self.assertEqual(1, len(leases))
        self.assertEqual("future-schema-owner", leases[0]["owner_id"])
        self.assertEqual(f"path:{self.checkout.resolve()}", leases[0]["resource_key"])

    def test_mixed_bureau_and_non_bureau_acquire_remains_forbidden(self) -> None:
        bureau_key = f"path:{self.checkout.resolve()}"
        branch_key = f"repo:{self.repo.resolve()}:branch:topic"

        def classify(keys):
            return [bureau_key] if bureau_key in keys else []

        def contract(keys, **kwargs):
            return {"phase": "work"} if classify(keys) else None

        with (
            patch.object(
                checkouts.resources.bureau_leases,
                "bureau_resource_keys",
                side_effect=classify,
            ),
            patch.object(
                checkouts.resources.bureau_leases,
                "enforce_bureau_lease_contract",
                side_effect=contract,
            ),
        ):
            with self.assertRaisesRegex(
                ValueError, "Bureau and non-Bureau resources must be acquired separately"
            ):
                checkouts.resources.acquire_resources(
                    "mixed-owner",
                    [bureau_key, branch_key],
                    purpose="forbidden mixed checkout acquire",
                    ttl_seconds=60,
                )

    def test_checkout_resource_sequence_rolls_back_first_group_on_later_failure(self) -> None:
        bureau_keys = [
            f"path:{self.checkout.resolve()}",
            f"path:{self._common_dir()}",
        ]
        branch_key = f"repo:{self.repo.resolve()}:branch:topic"
        calls = []

        def acquire(owner, keys, **kwargs):
            group = list(keys)
            calls.append(group)
            if branch_key in group:
                raise RuntimeError("simulated branch acquire failure")
            return {
                "owner_id": owner,
                "leases": [
                    {"resource_key": key, "owner_id": owner}
                    for key in group
                ],
            }

        with (
            patch.object(
                checkouts.resources.bureau_leases,
                "bureau_resource_keys",
                return_value=bureau_keys,
            ),
            patch.object(checkouts.resources, "acquire_resources", side_effect=acquire),
            patch.object(checkouts.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(RuntimeError, "branch acquire failure"):
                checkouts._acquire_checkout_resources(
                    owner_id="owner-a",
                    repo_common_dir=self._common_dir(),
                    checkout_path=self.checkout.resolve(),
                    purpose="rollback sequence test",
                    retention_until_unix=int(time.time()) + 3600,
                    repo_path=self.repo.resolve(),
                    branch="topic",
                    metadata={},
                )
        self.assertEqual(calls, [bureau_keys, [branch_key]])
        release.assert_called_once()
        self.assertEqual(release.call_args.args[1], bureau_keys)

    def test_archive_transaction_rolls_back_on_lifecycle_transition_failure(self) -> None:
        common_dir = self._common_dir()
        binding = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=self.checkout,
            owner_id="owner-a",
            purpose="transaction rollback fixture",
            source_kind="bureau_task",
            source_id="STORAGE-LIFECYCLE-V1-T003",
            artifact_class="operator_worktree",
            retention_until_unix=int(time.time()) + 3600,
            expected_head=self.head,
            expected_branch="topic",
        )
        with patch.object(
            checkouts,
            "_mark_checkout_archived_in_connection",
            side_effect=RuntimeError("simulated lifecycle transition failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated lifecycle"):
                self._archive(aged=False)

        self.assertIsNone(
            checkouts._latest_archive_for_key(binding["checkout_key"])
        )
        stored = checkouts._lifecycle_bindings([binding["checkout_key"]])
        self.assertEqual(stored[binding["checkout_key"]]["phase"], "active")
        self.assertEqual(checkouts._read_resource_leases(), [])

    def test_archive_releases_operation_lease_when_manifest_write_fails(self) -> None:
        with patch.object(
            checkouts,
            "_write_json_evidence",
            side_effect=OSError("simulated manifest failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated manifest failure"):
                self._archive(aged=False)

        self.assertEqual(checkouts._read_resource_leases(), [])

    def test_archive_preserves_committed_state_when_audit_append_fails(self) -> None:
        common_dir = self._common_dir()
        binding = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=self.checkout,
            owner_id="owner-a",
            purpose="audit failure recovery fixture",
            source_kind="bureau_task",
            source_id="STORAGE-LIFECYCLE-V1-T003",
            artifact_class="operator_worktree",
            retention_until_unix=int(time.time()) + 3600,
            expected_head=self.head,
            expected_branch="topic",
        )
        with patch.object(
            checkouts.base,
            "_append_audit",
            side_effect=OSError("simulated audit failure"),
        ):
            with self.assertRaisesRegex(OSError, "simulated audit failure"):
                self._archive(aged=False)

        archive = checkouts._latest_archive_for_key(binding["checkout_key"])
        self.assertIsNotNone(archive)
        assert archive is not None
        self.assertTrue(Path(archive["manifest_path"]).is_file())
        self.assertTrue(all(item["ref"] for item in archive["recovery_refs"]))
        stored = checkouts._lifecycle_bindings([binding["checkout_key"]])
        self.assertEqual(stored[binding["checkout_key"]]["phase"], "archived")
        self.assertEqual(checkouts._read_resource_leases(), [])

    def test_disjoint_source_file_lease_does_not_block_archive(self) -> None:
        checkouts.resources.acquire_resources(
            "foreign-source-owner",
            [f"path:{self.repo / 'README.md'}"],
            purpose="edit disjoint source file",
            ttl_seconds=3600,
        )
        result = self._archive()
        self.assertEqual(
            result["audit"]["coordination_checked"]["resource_leases"], 0
        )

    def test_relevant_same_owner_lease_still_blocks_archive(self) -> None:
        checkouts.resources.acquire_resources(
            "owner-a",
            [f"path:{self.checkout.resolve()}"],
            purpose="active work still owns checkout path",
            ttl_seconds=3600,
        )
        with self.assertRaisesRegex(RuntimeError, "resources=1"):
            self._archive()

    def test_common_dir_lease_serializes_archive(self) -> None:
        checkouts.resources.acquire_resources(
            "foreign-git-owner",
            [f"path:{self._common_dir()}"],
            purpose="mutate shared Git metadata",
            ttl_seconds=3600,
        )
        with self.assertRaisesRegex(RuntimeError, "resources=1"):
            self._archive()

    def test_persisted_emergency_recovery_broad_repo_lease_still_blocks_archive(self) -> None:
        resource_key = f"repo:{self.repo}"
        scope = {
            "schema_version": 1,
            "repository": str(self.repo),
            "task_id": "CHECKOUT-EMERGENCY-RECOVERY",
            "base_head": self.head,
            "head": self.head,
            "branch": "topic",
            "worktree": str(self.checkout),
            "effects": ["write"],
            "paths": [str(self.repo / "README.md")],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        checkouts.resources.acquire_resources(
            "foreign-broad-owner",
            [resource_key],
            purpose="validated recovery placeholder",
            ttl_seconds=3600,
            metadata={
                "scope_manifest": scope,
                "scope_manifest_complete": True,
            },
            admission_assessor=lambda **kwargs: {
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            },
        )
        with sqlite3.connect(self.resource_db) as connection:
            stored = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?",
                    (resource_key,),
                ).fetchone()[0]
            )
            stored["lease_mode"] = "emergency-recovery"
            metadata_json, metadata_sha256 = checkouts.resources._metadata(stored)
            connection.execute(
                "UPDATE leases SET metadata_json=?, metadata_sha256=? "
                "WHERE resource_key=?",
                (metadata_json, metadata_sha256, resource_key),
            )
        with self.assertRaisesRegex(RuntimeError, "resources=1"):
            self._archive()

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
        self.assertTrue(
            work_admission._complete_repository_inventory(
                first,
                repository=str(self.repo.resolve()),
                worktrees=first["worktrees"],
            )
        )
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

    def test_admission_binds_canonical_inventory_for_requested_subdirectory(
        self,
    ) -> None:
        requested_repo = self.repo / "nested" / "source"
        requested_repo.mkdir(parents=True)
        inventory = checkouts.checkout_inventory(
            requested_repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        common_dir = checkouts._git_common_dir(requested_repo)
        self.assertEqual(inventory["repository"], str(self.repo.resolve()))
        self.assertEqual(inventory["requested_repo"], str(requested_repo.resolve()))
        self.assertEqual(inventory["git_common_dir"], str(common_dir))

        target_path = self.root / "worktrees" / "future-target"
        branch = "feat/future-target"
        scope = {
            "schema_version": 1,
            "repository": str(self.repo.resolve()),
            "task_id": "GRABOWSKI-ADMISSION-SUBDIR-TEST",
            "base_head": "0" * 40,
            "head": "a" * 40,
            "branch": branch,
            "worktree": str(target_path),
            "effects": ["write"],
            "paths": [str(self.repo / "README.md")],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        reconciliation = {
            "bindings": [],
            "pagination": {"has_more": False},
            "source_snapshot": {"repository_errors": []},
            "snapshot_sha256": "a" * 64,
        }
        inventory_requests: list[str] = []
        reconciliation_requests: list[str] = []

        def load_inventory(repository: str) -> dict[str, object]:
            inventory_requests.append(repository)
            return inventory

        def load_reconciliation(repository: str) -> dict[str, object]:
            reconciliation_requests.append(repository)
            return reconciliation

        result = work_admission.assess_repository_admission(
            repo=str(requested_repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            requested_scope=scope,
            inventory_loader=load_inventory,
            reconciliation_loader=load_reconciliation,
        )

        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["scope_mode"], "exact_checkout")
        self.assertEqual(result["repository"], str(self.repo.resolve()))
        self.assertEqual(inventory_requests, [str(requested_repo.resolve())])
        self.assertEqual(reconciliation_requests, [str(self.repo.resolve())])

        def rebound_inventory(**updates: object) -> dict[str, object]:
            body = {
                key: value
                for key, value in inventory.items()
                if key not in {"generated_at_unix", "inventory_sha256"}
            }
            body.update(updates)
            return {
                **body,
                "generated_at_unix": inventory["generated_at_unix"],
                "inventory_sha256": work_admission._digest(body),
            }

        equivalent_common_dir = common_dir / ".." / common_dir.name
        normalized = work_admission.assess_repository_admission(
            repo=str(requested_repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            requested_scope=scope,
            inventory_loader=lambda _repo: rebound_inventory(
                git_common_dir=str(equivalent_common_dir)
            ),
            reconciliation_loader=lambda _repo: reconciliation,
        )
        self.assertEqual(normalized["decision"], "allow")

        mismatches = {
            "top-level": rebound_inventory(repository=str(self.checkout)),
            "requested-path": rebound_inventory(requested_repo=str(self.repo)),
            "common-dir": rebound_inventory(
                git_common_dir=str(self.checkout / ".git")
            ),
        }
        for label, mismatched_inventory in mismatches.items():
            with self.subTest(label=label):
                blocked = work_admission.assess_repository_admission(
                    repo=str(requested_repo),
                    owner_id="owner-a",
                    operation="broad_repository_lease",
                    requested_scope=scope,
                    inventory_loader=lambda _repo, value=mismatched_inventory: value,
                    reconciliation_loader=lambda _repo: reconciliation,
                )
                self.assertEqual(blocked["decision"], "blocked")
                self.assertIn(
                    "inventory-unobservable", blocked["blocker_codes"]
                )

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

    def test_inventory_marks_fresh_archive_as_cleanup_candidate(self) -> None:
        archive_result = self._archive(aged=False)
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertEqual(linked["lifecycle_state"], "archived_retained")
        self.assertEqual(linked["hygiene_mark"], "archived")
        self.assertFalse(linked["cleanup_candidate"])
        decision = linked["lifecycle_decision"]
        self.assertEqual(decision["archive_grace_seconds"], 24 * 60 * 60)
        self.assertFalse(decision["archive_grace_elapsed"])
        self.assertFalse(decision["requires_cleanup_dry_run"])
        self.assertEqual(
            linked["lifecycle"]["latest_archive"]["archive_id"],
            archive_result["archive"]["archive_id"],
        )

    def test_cleanup_dry_run_accepts_fresh_archive(self) -> None:
        archive = self._archive(aged=False)["archive"]
        assert isinstance(archive, dict)
        dry_run = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=True,
            archive_id=str(archive["archive_id"]),
            expected_head=self.head,
            expected_branch="topic",
        )
        self.assertFalse(dry_run["plan"]["safe_to_apply"])
        self.assertEqual(
            dry_run["plan"]["archive_grace_seconds"],
            24 * 60 * 60,
        )
        self.assertFalse(dry_run["plan"]["archive_grace_elapsed"])
        self.assertIn("active_retention_not_elapsed", dry_run["plan"]["cleanup_blockers"])
        self.assertIn("archive_grace_not_elapsed", dry_run["plan"]["cleanup_blockers"])

    def test_cleanup_accepts_exact_merged_github_pull_head_ref(self) -> None:
        self._git(
            "remote",
            "add",
            "origin",
            "git@github.com:heimgewebe/reposkop.git",
        )
        archive = self._archive()["archive"]
        calls: list[list[str]] = []

        def github_run(argv, **_kwargs):
            calls.append(list(argv))
            if argv[:3] == ["gh", "pr", "list"]:
                self.assertIn("github.com/heimgewebe/reposkop", argv)
                payload = [
                    {
                        "number": 101,
                        "state": "MERGED",
                        "headRefName": "topic",
                        "headRefOid": self.head,
                    }
                ]
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": json.dumps(payload),
                    "stderr": "",
                    "stdout_truncated": False,
                }
            if argv[:2] == ["gh", "api"]:
                self.assertEqual(argv[2:4], ["--hostname", "github.com"])
                self.assertEqual(
                    argv[4],
                    "repos/heimgewebe/reposkop/git/ref/pull/101/head",
                )
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": self.head + "\n",
                    "stderr": "",
                    "stdout_truncated": False,
                }
            raise AssertionError(f"unexpected GitHub command: {argv!r}")

        with patch.object(checkouts.operator, "_run", side_effect=github_run):
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )

        self.assertTrue(dry_run["plan"]["remote_secured"])
        self.assertEqual(
            dry_run["plan"]["remote_secured_refs"],
            ["github:heimgewebe/reposkop:refs/pull/101/head"],
        )
        self.assertTrue(dry_run["plan"]["safe_to_apply"])
        self.assertEqual(len(calls), 2)

    def test_cleanup_rejects_mismatched_github_pull_head_ref(self) -> None:
        self._git(
            "remote",
            "add",
            "origin",
            "https://github.com/heimgewebe/reposkop.git",
        )
        archive = self._archive()["archive"]

        def github_run(argv, **_kwargs):
            if argv[:3] == ["gh", "pr", "list"]:
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": json.dumps(
                        [
                            {
                                "number": 101,
                                "state": "MERGED",
                                "headRefName": "topic",
                                "headRefOid": self.head,
                            }
                        ]
                    ),
                    "stderr": "",
                    "stdout_truncated": False,
                }
            if argv[:2] == ["gh", "api"]:
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "0" * 40 + "\n",
                    "stderr": "",
                    "stdout_truncated": False,
                }
            raise AssertionError(f"unexpected GitHub command: {argv!r}")

        with patch.object(checkouts.operator, "_run", side_effect=github_run):
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )

        self.assertFalse(dry_run["plan"]["remote_secured"])
        self.assertIn(
            "head_not_remote_secured",
            dry_run["plan"]["cleanup_blockers"],
        )
        self.assertFalse(dry_run["plan"]["safe_to_apply"])

    def test_cleanup_fails_closed_when_github_result_has_no_returncode(self) -> None:
        self._git(
            "remote",
            "add",
            "origin",
            "https://github.com/heimgewebe/reposkop.git",
        )
        archive = self._archive()["archive"]

        with patch.object(
            checkouts.operator,
            "_run",
            return_value={
                "returncode": None,
                "timed_out": False,
                "stdout": "[]",
                "stderr": "",
                "stdout_truncated": False,
            },
        ):
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )

        self.assertFalse(dry_run["plan"]["remote_secured"])
        self.assertIn(
            "head_not_remote_secured",
            dry_run["plan"]["cleanup_blockers"],
        )
        self.assertFalse(dry_run["plan"]["safe_to_apply"])

    def test_remote_security_local_ref_fast_path_skips_github(self) -> None:
        self._publish_remote()
        _top, _common, records = checkouts._worktree_records(self.repo)
        record = next(item for item in records if item["path"] == str(self.checkout))
        with patch.object(
            checkouts.operator,
            "_run",
            side_effect=AssertionError("GitHub fallback must not run"),
        ):
            observed = checkouts._remote_secured_observation(
                record,
                verify_github_pull_ref=True,
            )
        self.assertTrue(observed["remote_secured"])
        self.assertIn("refs/remotes/origin/topic", observed["remote_secured_refs"])

    def test_github_remote_identity_parser_fails_closed(self) -> None:
        self.assertEqual(
            checkouts._github_repository_slug_from_remote_url(
                "git@github.com:heimgewebe/reposkop.git"
            ),
            "heimgewebe/reposkop",
        )
        self.assertEqual(
            checkouts._github_repository_slug_from_remote_url(
                "ssh://git@github.com/heimgewebe/reposkop.git"
            ),
            "heimgewebe/reposkop",
        )
        self.assertEqual(
            checkouts._github_repository_slug_from_remote_url(
                "https://github.com/heimgewebe/reposkop.git"
            ),
            "heimgewebe/reposkop",
        )
        rejected = [
            "http://github.com/heimgewebe/reposkop.git",
            "https://user@github.com/heimgewebe/reposkop.git",
            "https://github.com.evil.invalid/heimgewebe/reposkop.git",
            "ssh://root@github.com/heimgewebe/reposkop.git",
            "https://github.com/heimgewebe/reposkop/extra.git",
            "https://github.com/heimgewebe/%72eposkop.git",
        ]
        for remote in rejected:
            with self.subTest(remote=remote):
                self.assertIsNone(
                    checkouts._github_repository_slug_from_remote_url(remote)
                )

    def test_cleanup_requires_prior_dry_run_and_uses_plain_worktree_remove(self) -> None:
        self._publish_remote()
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
        self.assertTrue(dry_run["plan"]["remote_secured"])
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

    def test_cleanup_plan_remains_valid_when_only_archive_age_advances(self) -> None:
        archive = self._archive()["archive"]
        assert isinstance(archive, dict)
        base = (
            int(archive["created_at_unix"])
            + checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS
            + 100
        )
        current_time = [base]

        with patch.object(checkouts, "_now", side_effect=lambda: current_time[0]):
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )
            current_time[0] = base + 1
            applied = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=False,
                plan_id=dry_run["dry_run_record"]["plan_id"],
                expected_plan_sha256=dry_run["plan"]["plan_sha256"],
                confirmation="remove-linked-checkout",
            )

        self.assertEqual(dry_run["plan"]["schema_version"], 2)
        self.assertEqual(
            dry_run["plan"]["archive_created_at_unix"],
            archive["created_at_unix"],
        )
        self.assertEqual(
            dry_run["plan"]["plan_hash_excludes"],
            ["archive_age_seconds"],
        )
        self.assertEqual(
            dry_run["plan"]["archive_age_seconds"],
            checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS + 100,
        )
        self.assertEqual(
            applied["plan"]["archive_age_seconds"],
            checkouts.CHECKOUT_CLEANUP_GRACE_SECONDS + 101,
        )
        self.assertEqual(
            dry_run["plan"]["plan_sha256"],
            applied["plan"]["plan_sha256"],
        )
        self.assertFalse(self.checkout.exists())

    def test_schema_one_cleanup_dry_run_is_intentionally_stale(self) -> None:
        archive = self._archive()["archive"]
        assert isinstance(archive, dict)
        dry_run = checkouts.grabowski_checkout_cleanup(
            str(self.repo),
            str(self.checkout),
            "owner-a",
            dry_run=True,
            archive_id=archive["archive_id"],
            expected_head=self.head,
            expected_branch="topic",
        )
        legacy_plan = dict(dry_run["plan"])
        legacy_plan.pop("plan_sha256")
        legacy_plan.pop("archive_created_at_unix")
        legacy_plan.pop("plan_hash_excludes")
        legacy_plan["schema_version"] = 1
        legacy_hash = checkouts._sha256_json(legacy_plan)
        plan_id = dry_run["dry_run_record"]["plan_id"]
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE dry_runs SET plan_sha256=?, plan_json=? WHERE plan_id=?",
                (legacy_hash, checkouts._canonical_json(legacy_plan), plan_id),
            )
            connection.commit()

        with self.assertRaisesRegex(RuntimeError, "dry-run is stale"):
            checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=False,
                plan_id=plan_id,
                expected_plan_sha256=legacy_hash,
                confirmation="remove-linked-checkout",
            )

        self.assertTrue(self.checkout.exists())

    def test_cleanup_plan_still_rejects_new_coordination_blocker(self) -> None:
        archive = self._archive()["archive"]
        assert isinstance(archive, dict)
        clear = checkouts._coordination_result([], [], [])
        blocked = checkouts._coordination_result(
            [
                {
                    "resource_key": f"path:{self.checkout}",
                    "owner_id": "foreign-owner",
                    "blocking": True,
                }
            ],
            [],
            [],
        )
        with patch.object(
            checkouts,
            "_linked_checkout_coordination",
            side_effect=[clear, blocked],
        ):
            dry_run = checkouts.grabowski_checkout_cleanup(
                str(self.repo),
                str(self.checkout),
                "owner-a",
                dry_run=True,
                archive_id=archive["archive_id"],
                expected_head=self.head,
                expected_branch="topic",
            )
            with self.assertRaisesRegex(RuntimeError, "dry-run is stale"):
                checkouts.grabowski_checkout_cleanup(
                    str(self.repo),
                    str(self.checkout),
                    "owner-a",
                    dry_run=False,
                    plan_id=dry_run["dry_run_record"]["plan_id"],
                    expected_plan_sha256=dry_run["plan"]["plan_sha256"],
                    confirmation="remove-linked-checkout",
                )

        self.assertTrue(self.checkout.exists())

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

    def test_completed_retained_limit_blocks_transition_without_deleting_checkout(self) -> None:
        common_dir = self._common_dir()
        first_path = self.root / "worktrees" / "first-managed"
        second_path = self.root / "worktrees" / "second-managed"
        with patch.object(checkouts, "MAX_COMPLETED_RETAINED_CHECKOUTS_PER_REPO", 1):
            first = checkouts._reserve_checkout_lifecycle(
                repo_common_dir=common_dir,
                repo_path=self.repo,
                checkout_path=first_path,
                owner_id="owner-a",
                purpose="first",
                source_kind="bureau_task",
                source_id="T1",
                artifact_class="operator_worktree",
                retention_until_unix=int(time.time()) + 3600,
                expected_head=self.head,
                expected_branch="topic-one",
            )
            second = checkouts._reserve_checkout_lifecycle(
                repo_common_dir=common_dir,
                repo_path=self.repo,
                checkout_path=second_path,
                owner_id="owner-a",
                purpose="second",
                source_kind="bureau_task",
                source_id="T2",
                artifact_class="operator_worktree",
                retention_until_unix=int(time.time()) + 3600,
                expected_head=self.head,
                expected_branch="topic-two",
            )
            for binding, purpose, branch in (
                (first, "first", "topic-one"),
                (second, "second", "topic-two"),
            ):
                checkouts._upsert_retention(
                    checkout_key=binding["checkout_key"],
                    repo_common_dir=common_dir,
                    repo_path=self.repo,
                    checkout_path=Path(binding["checkout_path"]),
                    owner_id="owner-a",
                    purpose=purpose,
                    retention_until_unix=int(time.time()) + 3600,
                    expected_head=self.head,
                    expected_branch=branch,
                )
            checkouts._mark_checkout_completed_retained(
                checkout_key=first["checkout_key"],
                owner_id="owner-a",
                expected_head=self.head,
                expected_branch="topic-one",
            )
            with self.assertRaisesRegex(RuntimeError, "completed-retained checkout limit"):
                checkouts._mark_checkout_completed_retained(
                    checkout_key=second["checkout_key"],
                    owner_id="owner-a",
                    expected_head=self.head,
                    expected_branch="topic-two",
                )
        bindings = checkouts._lifecycle_bindings(
            [first["checkout_key"], second["checkout_key"]]
        )
        self.assertEqual(bindings[first["checkout_key"]]["phase"], "completed_retained")
        self.assertEqual(bindings[second["checkout_key"]]["phase"], "active")
        self.assertTrue(self.checkout.is_dir())

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

    def test_branch_lease_is_checkout_coordination_blocker(self) -> None:
        top_level, common_dir, record = checkouts._worktree_for_path(
            self.repo, self.checkout
        )
        branch_key = f"repo:{top_level}:branch:{record['branch']}"
        lease = {
            "resource_key": branch_key,
            "owner_id": "active-branch-owner",
            "purpose": "active branch work",
            "acquired_at_unix": int(time.time()) - 10,
            "updated_at_unix": int(time.time()) - 10,
            "expires_at_unix": int(time.time()) + 600,
            "metadata_sha256": "a" * 64,
            "reclaimed_from_owner": None,
        }
        with patch.object(checkouts, "_read_resource_leases", return_value=[lease]):
            coordination = checkouts._linked_checkout_coordination(
                self.checkout,
                top_level,
                common_dir,
                branch=record["branch"],
                include_processes=False,
                include_tasks=False,
                include_resources=True,
            )

        self.assertTrue(coordination["blocking"])
        self.assertEqual(1, coordination["blocking_counts"]["resource_leases"])
        self.assertEqual(branch_key, coordination["resource_leases"][0]["resource_key"])

    def test_unrelated_branch_lease_does_not_block_checkout(self) -> None:
        top_level, common_dir, record = checkouts._worktree_for_path(
            self.repo, self.checkout
        )
        lease = {
            "resource_key": f"repo:{top_level}:branch:other-topic",
            "owner_id": "other-owner",
            "purpose": "unrelated branch work",
            "acquired_at_unix": int(time.time()) - 10,
            "updated_at_unix": int(time.time()) - 10,
            "expires_at_unix": int(time.time()) + 600,
            "metadata_sha256": "b" * 64,
            "reclaimed_from_owner": None,
        }
        with patch.object(checkouts, "_read_resource_leases", return_value=[lease]):
            coordination = checkouts._linked_checkout_coordination(
                self.checkout,
                top_level,
                common_dir,
                branch=record["branch"],
                include_processes=False,
                include_tasks=False,
                include_resources=True,
            )

        self.assertFalse(coordination["blocking"])
        self.assertEqual(0, coordination["blocking_counts"]["resource_leases"])

    def test_archive_atomically_conflicts_with_branch_lease_after_clear_readback(self) -> None:
        top_level, _common_dir, record = checkouts._worktree_for_path(
            self.repo, self.checkout
        )
        branch_key = f"repo:{top_level}:branch:{record['branch']}"
        lease = checkouts.resources.acquire_resources(
            "foreign-branch-owner",
            [branch_key],
            purpose="concurrent branch work",
            ttl_seconds=600,
        )
        try:
            clear = checkouts._coordination_result([], [], [])
            with (
                patch.object(
                    checkouts, "_linked_checkout_coordination", return_value=clear
                ),
                self.assertRaisesRegex(RuntimeError, "Resource is leased"),
            ):
                self._archive()

            self.assertTrue(self.checkout.exists())
        finally:
            checkouts.resources.release_resources(
                lease["owner_id"],
                [branch_key],
            )

    def test_archive_rejects_symlinked_git_metadata(self) -> None:
        git_file = self.checkout / ".git"
        target = self.root / "gitfile-target"
        target.write_text(git_file.read_text(encoding="utf-8"), encoding="utf-8")
        git_file.unlink()
        git_file.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "Symlinked"):
            self._archive()

    def test_inventory_called_from_linked_checkout_uses_canonical_repo_identity(self) -> None:
        _top_level, _common_dir, records = checkouts._worktree_records(self.checkout)
        linked = next(item for item in records if item["path"] == str(self.checkout))
        self.assertEqual(linked["repo_path"], str(self.repo.resolve()))

    def test_managed_active_binding_with_effective_retention_is_consistent(self) -> None:
        self._managed_binding()
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        decision = linked["lifecycle_decision"]
        self.assertEqual(linked["lifecycle_state"], "retained")
        self.assertTrue(decision["binding_present"])
        self.assertEqual(decision["binding_phase"], "active")
        self.assertTrue(decision["binding_consistent"])
        self.assertEqual(decision["binding_drift_reasons"], [])

    def test_managed_active_binding_with_expired_retention_requires_attention(self) -> None:
        binding = self._managed_binding()
        expired = int(time.time()) - 1
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET retention_until_unix=? WHERE checkout_key=?",
                (expired, binding["checkout_key"]),
            )
            connection.execute(
                "UPDATE retention SET retention_until_unix=? WHERE checkout_key=?",
                (expired, binding["checkout_key"]),
            )
            connection.commit()
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        decision = linked["lifecycle_decision"]
        self.assertEqual(linked["lifecycle_state"], "managed_active_attention")
        self.assertTrue(decision["binding_consistent"])
        self.assertFalse(decision["retention_active"])
        self.assertFalse(linked["cleanup_candidate"])

    def test_inventory_projects_active_creation_capacity_separately_from_preservation(self) -> None:
        self._managed_binding()
        common_dir = self._common_dir()
        now = int(time.time())
        expired_present = self.root / "worktrees" / "expired-present"
        expired_present.mkdir(parents=True, exist_ok=True)
        expired_missing = self.root / "worktrees" / "expired-missing"
        present_binding = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=expired_present,
            owner_id="owner-a",
            purpose="expired present capacity fixture",
            source_kind="bureau_task",
            source_id="GRABOWSKI-OPERATOR-SURFACE-V1-T095",
            artifact_class="implementation_worktree",
            retention_until_unix=now + 3600,
            expected_head=self.head,
            expected_branch="expired-present",
        )
        missing_binding = checkouts._reserve_checkout_lifecycle(
            repo_common_dir=common_dir,
            repo_path=self.repo,
            checkout_path=expired_missing,
            owner_id="owner-a",
            purpose="expired missing capacity fixture",
            source_kind="bureau_task",
            source_id="GRABOWSKI-OPERATOR-SURFACE-V1-T095",
            artifact_class="implementation_worktree",
            retention_until_unix=now + 3600,
            expected_head=self.head,
            expected_branch="expired-missing",
        )
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET retention_until_unix=? WHERE checkout_key IN (?, ?)",
                (now - 1, present_binding["checkout_key"], missing_binding["checkout_key"]),
            )
            connection.commit()

        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        capacity = inventory["active_capacity"]
        self.assertTrue(capacity["available"])
        self.assertEqual(capacity["configured_limit"], checkouts.MAX_ACTIVE_CHECKOUTS_PER_REPO)
        self.assertEqual(capacity["raw_active_rows"], 3)
        self.assertEqual(capacity["unexpired_active_rows"], 1)
        self.assertEqual(capacity["expired_active_rows"], 2)
        self.assertEqual(capacity["expired_present_active_rows"], 1)
        self.assertEqual(capacity["expired_missing_active_rows"], 1)
        self.assertEqual(capacity["expired_unobservable_active_rows"], 0)
        self.assertEqual(capacity["expired_unclassified_active_rows"], 0)
        self.assertTrue(capacity["path_classification_complete"])
        self.assertEqual(capacity["path_observations_attempted"], 2)
        self.assertEqual(capacity["used"], 1)
        self.assertEqual(capacity["free"], checkouts.MAX_ACTIVE_CHECKOUTS_PER_REPO - 1)
        self.assertFalse(capacity["saturated"])
        self.assertIn("checkout_path_reuse_authority", capacity["does_not_establish"])

    def test_completed_retained_binding_is_terminal_and_not_cleanup_candidate(self) -> None:
        binding = self._managed_binding()
        checkouts._mark_checkout_completed_retained(
            checkout_key=str(binding["checkout_key"]),
            owner_id="owner-a",
            expected_head=self.head,
            expected_branch="topic",
        )
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertEqual(linked["lifecycle_state"], "completed_retained")
        self.assertEqual(linked["lifecycle_decision"]["binding_phase"], "completed_retained")
        self.assertTrue(linked["lifecycle_decision"]["binding_consistent"])
        self.assertFalse(linked["cleanup_candidate"])

    def test_archived_binding_without_matching_archive_is_fail_closed(self) -> None:
        binding = self._managed_binding()
        checkouts._mark_checkout_archived(
            str(binding["checkout_key"]),
            "owner-a",
            int(time.time()),
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
        decision = linked["lifecycle_decision"]
        self.assertEqual(linked["lifecycle_state"], "managed_lifecycle_drift")
        self.assertFalse(decision["binding_consistent"])
        self.assertIn(
            "archived-binding-without-matching-open-archive",
            decision["binding_drift_reasons"],
        )
        self.assertFalse(linked["cleanup_candidate"])

    def test_matching_archived_binding_is_immediately_cleanup_candidate(self) -> None:
        self._managed_binding()
        self._archive(aged=False)
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        decision = linked["lifecycle_decision"]
        self.assertEqual(linked["lifecycle_state"], "archived_retained")
        self.assertEqual(decision["binding_phase"], "archived")
        self.assertTrue(decision["binding_consistent"])
        self.assertFalse(decision["archive_grace_elapsed"])
        self.assertEqual(decision["archive_grace_seconds"], 24 * 60 * 60)
        self.assertFalse(linked["cleanup_candidate"])

    def test_unknown_managed_phase_is_lifecycle_drift(self) -> None:
        binding = self._managed_binding()
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET phase='future_phase' WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertEqual(linked["lifecycle_state"], "managed_lifecycle_drift")
        self.assertIn(
            "binding-phase-unsupported",
            linked["lifecycle_decision"]["binding_drift_reasons"],
        )

    def test_managed_branch_owner_and_terminal_head_drift_are_explicit(self) -> None:
        binding = self._managed_binding()
        checkouts._mark_checkout_completed_retained(
            checkout_key=str(binding["checkout_key"]),
            owner_id="owner-a",
            expected_head="b" * 40,
            expected_branch="topic",
        )
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET owner_id='owner-b' WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.execute(
                "UPDATE lifecycle_bindings SET expected_branch='other-topic' WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        reasons = linked["lifecycle_decision"]["binding_drift_reasons"]
        self.assertEqual(linked["lifecycle_state"], "managed_lifecycle_drift")
        self.assertIn("binding-expected-branch-mismatch", reasons)
        self.assertIn("binding-retention-owner-mismatch", reasons)
        self.assertIn("terminal-binding-head-mismatch", reasons)
        self.assertFalse(linked["cleanup_candidate"])

    def test_worktree_status_timeout_is_unobservable_not_clean(self) -> None:
        record = {
            "path": str(self.checkout),
            "prunable": False,
        }
        with patch.object(
            checkouts,
            "_git_read",
            side_effect=subprocess.TimeoutExpired(cmd="git status", timeout=0.1),
        ):
            status = checkouts._worktree_status(
                record,
                timeout_seconds=0.1,
            )
        self.assertIsNone(status["dirty"])
        self.assertIsNone(status["returncode"])
        self.assertEqual(status["error"], "git status timed out")

    def test_bounded_inventory_does_not_probe_expired_capacity_paths(self) -> None:
        binding = self._managed_binding()
        expired = int(time.time()) - 1
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE lifecycle_bindings SET retention_until_unix=? WHERE checkout_key=?",
                (expired, binding["checkout_key"]),
            )
            connection.commit()

        original_projection = checkouts._active_capacity_projection_from_connection

        def guarded_projection(connection, **kwargs):
            self.assertEqual(kwargs["max_path_observations"], 0)
            with patch.object(Path, "lstat", side_effect=AssertionError("capacity path probe escaped budget")):
                return original_projection(connection, **kwargs)

        with patch.object(
            checkouts,
            "_active_capacity_projection_from_connection",
            side_effect=guarded_projection,
        ):
            inventory = checkouts.checkout_inventory(
                self.repo,
                include_processes=False,
                include_tasks=False,
                include_resources=False,
                git_timeout_seconds=1.0,
                observation_budget_seconds=5.0,
                max_worktrees=1,
            )
        capacity = inventory["active_capacity"]
        self.assertTrue(capacity["available"])
        self.assertEqual(capacity["used"], 0)
        self.assertEqual(capacity["expired_active_rows"], 1)
        self.assertEqual(capacity["expired_unclassified_active_rows"], 1)
        self.assertFalse(capacity["path_classification_complete"])
        self.assertEqual(capacity["path_observations_attempted"], 0)
        self.assertIn("complete_expired_path_presence", capacity["does_not_establish"])

    def test_bounded_inventory_prioritizes_main_and_reports_omissions(self) -> None:
        inventory = checkouts.checkout_inventory(
            self.repo,
            include_processes=False,
            include_tasks=False,
            include_resources=False,
            git_timeout_seconds=1.0,
            observation_budget_seconds=5.0,
            max_worktrees=1,
        )
        self.assertTrue(inventory["truncated"])
        self.assertEqual(inventory["total_worktree_count"], 2)
        self.assertEqual(inventory["observed_worktree_count"], 1)
        self.assertEqual(inventory["omitted_worktree_count"], 1)
        self.assertTrue(inventory["worktrees"][0]["is_main"])
        contract = inventory["observation_contract"]
        self.assertTrue(contract["bounded"])
        self.assertEqual(contract["max_worktrees"], 1)
        self.assertTrue(contract["unobserved_worktrees_are_not_reported_clean"])

    def test_bounded_inventory_omits_unobservable_status(self) -> None:
        clean = {
            "returncode": 0,
            "dirty": False,
            "entry_count": 0,
            "untracked_count": 0,
            "error": None,
        }
        unknown = {
            "returncode": None,
            "dirty": None,
            "entry_count": None,
            "untracked_count": None,
            "error": "git status timed out",
        }
        with (
            patch.object(
                checkouts,
                "_worktree_status",
                side_effect=[clean, unknown],
            ),
            patch.object(
                checkouts,
                "_remote_secured_observation",
                return_value={
                    "remote_secured": False,
                    "remote_secured_refs": [],
                },
            ),
        ):
            inventory = checkouts.checkout_inventory(
                self.repo,
                include_processes=False,
                include_tasks=False,
                include_resources=False,
                git_timeout_seconds=1.0,
                observation_budget_seconds=5.0,
                max_worktrees=2,
            )
        self.assertTrue(inventory["truncated"])
        self.assertEqual(inventory["observed_worktree_count"], 1)
        self.assertEqual(inventory["omitted_worktree_count"], 1)
        self.assertTrue(all(
            item["status"]["dirty"] in {True, False}
            for item in inventory["worktrees"]
        ))
        self.assertEqual(inventory["probe_errors"][0]["stage"], "status")
        self.assertEqual(
            inventory["probe_errors"][0]["error"],
            "git status timed out",
        )

    def test_owner_handoff_preview_and_apply_converges_only_owner_drift(self) -> None:
        binding = self._completed_owner_drift()
        preview = checkouts.checkout_owner_handoff_preview(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic",
        )
        self.assertEqual(["binding-retention-owner-mismatch"], preview["allowed_drift_reasons"])
        applied = checkouts.checkout_owner_handoff_apply(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic", preview["snapshot_sha256"], preview["observed_at_unix"],
            preview["confirmation"],
        )
        self.assertEqual("applied", applied["status"])
        self.assertEqual("owner-b", applied["after"]["lifecycle"]["owner_id"])
        self.assertEqual("owner-b", applied["after"]["retention"]["owner_id"])
        inventory = checkouts.checkout_inventory(
            self.repo, include_processes=False, include_tasks=False, include_resources=False
        )
        linked = next(item for item in inventory["worktrees"] if item["path"] == str(self.checkout))
        self.assertNotIn(
            "binding-retention-owner-mismatch",
            linked["lifecycle_decision"]["binding_drift_reasons"],
        )
        self.assertTrue(self.checkout.is_dir())

    def test_owner_handoff_preserves_deliberately_extended_retention(self) -> None:
        binding = self._completed_owner_drift()
        extended_until = int(time.time()) + 30 * 24 * 60 * 60
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET retention_until_unix=? WHERE checkout_key=?",
                (extended_until, binding["checkout_key"]),
            )
            connection.commit()
        preview = checkouts.checkout_owner_handoff_preview(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic",
        )
        applied = checkouts.checkout_owner_handoff_apply(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic", preview["snapshot_sha256"], preview["observed_at_unix"],
            preview["confirmation"],
        )
        self.assertEqual(extended_until, applied["after"]["retention"]["retention_until_unix"])
        self.assertNotEqual(
            applied["after"]["lifecycle"]["retention_until_unix"],
            applied["after"]["retention"]["retention_until_unix"],
        )
        self.assertEqual(["lifecycle_owner_update"], applied["audit"]["effects"])

    def test_owner_handoff_rejects_active_binding(self) -> None:
        binding = self._managed_binding(owner="owner-a")
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET owner_id='owner-b' WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "completed-retained"):
            checkouts.checkout_owner_handoff_preview(
                str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
                self.head, "topic",
            )

    def test_owner_handoff_audit_failure_requires_readback_after_database_effect(self) -> None:
        self._completed_owner_drift()
        preview = checkouts.checkout_owner_handoff_preview(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic",
        )
        with patch.object(checkouts.base, "_append_audit", side_effect=OSError("audit down")):
            with self.assertRaisesRegex(RuntimeError, "readback required"):
                checkouts.checkout_owner_handoff_apply(
                    str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
                    self.head, "topic", preview["snapshot_sha256"], preview["observed_at_unix"],
                    preview["confirmation"],
                )
        current = checkouts._lifecycle_bindings([preview["checkout"]["checkout_key"]])[
            preview["checkout"]["checkout_key"]
        ]
        retention = checkouts._retention_records([preview["checkout"]["checkout_key"]])[
            preview["checkout"]["checkout_key"]
        ]
        self.assertEqual("owner-b", current["owner_id"])
        self.assertEqual("owner-b", retention["owner_id"])

    def test_owner_handoff_rejects_arbitrary_third_owner(self) -> None:
        self._completed_owner_drift()
        with self.assertRaisesRegex(PermissionError, "current retention owner"):
            checkouts.checkout_owner_handoff_preview(
                str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-c",
                self.head, "topic",
            )

    def test_owner_handoff_rejects_reversing_to_legacy_lifecycle_owner(self) -> None:
        self._completed_owner_drift()
        with self.assertRaisesRegex(PermissionError, "current retention owner"):
            checkouts.checkout_owner_handoff_preview(
                str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-a",
                self.head, "topic",
            )

    def test_owner_handoff_rejects_dirty_checkout(self) -> None:
        self._completed_owner_drift()
        (self.checkout / "foreign.txt").write_text("foreign\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "must be clean"):
            checkouts.checkout_owner_handoff_preview(
                str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
                self.head, "topic",
            )

    def test_owner_handoff_rejects_snapshot_toctou(self) -> None:
        binding = self._completed_owner_drift()
        preview = checkouts.checkout_owner_handoff_preview(
            str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
            self.head, "topic",
        )
        with checkouts._database() as connection:
            connection.execute(
                "UPDATE retention SET purpose='changed', updated_at_unix=updated_at_unix+1 WHERE checkout_key=?",
                (binding["checkout_key"],),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "snapshot changed"):
            checkouts.checkout_owner_handoff_apply(
                str(self.repo), str(self.checkout), "owner-a", "owner-b", "owner-b",
                self.head, "topic", preview["snapshot_sha256"], preview["observed_at_unix"],
                preview["confirmation"],
            )

    def test_lifecycle_source_has_no_forced_filesystem_deletion(self) -> None:
        source = (SRC / "grabowski_checkouts.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.rmtree", source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn('"worktree", "remove", "--force"', source)
        self.assertNotIn('"worktree", "remove", "-f"', source)


if __name__ == "__main__":
    unittest.main()
