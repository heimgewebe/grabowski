from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import threading
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

import grabowski_nonconflict as nonconflict  # noqa: E402
import grabowski_resources as resources  # noqa: E402


class ObsoletePathLeaseReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "state" / "resources.sqlite3"
        self.database_patch = patch.object(resources, "RESOURCE_DB", self.database)
        self.database_patch.start()
        self.owner = "owner-terminal"
        self.path_a = f"path:{self.root / 'repo' / 'a.py'}"
        self.path_b = f"path:{self.root / 'repo' / 'b.py'}"

    def tearDown(self) -> None:
        self.database_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def _snapshot(lease: dict[str, object]) -> dict[str, object]:
        return {key: lease[key] for key in resources.LEASE_SNAPSHOT_KEYS}

    @staticmethod
    def _terminal_evidence(owner: str, keys: list[str]) -> dict[str, object]:
        return {
            "kind": "durable_task_outcome",
            "task_id": "a" * 24,
            "outcome_receipt_sha256": "b" * 64,
            "state": "completed",
            "attempt": 1,
            "owner_id": owner,
            "resource_keys": keys,
        }

    def _acquire(self, keys: list[str]) -> list[dict[str, object]]:
        result = resources.acquire_resources(
            self.owner,
            keys,
            purpose="terminal owner work",
            ttl_seconds=300,
        )
        return [self._snapshot(item) for item in result["leases"]]

    def _task_source_fixture(
        self,
        *,
        receipt_state: str,
        record_state: str | None = None,
        receipt_attempt: int = 1,
        record_attempt: int | None = None,
    ) -> tuple[types.SimpleNamespace, dict[str, str], str, str, list[dict[str, object]]]:
        task_id = "c" * 24
        owner = f"task:{task_id}"
        key = self.path_a
        task_root = self.root / "task-outcomes"
        task_root.mkdir(exist_ok=True, mode=0o700)
        task_root.chmod(0o700)
        unit = f"grabowski-task-{task_id}-a{receipt_attempt}.service"
        argv_sha256 = "d" * 64
        host = "local"
        core = {
            "schema_version": 1,
            "task_id": task_id,
            "unit": unit,
            "attempt": receipt_attempt,
            "state": receipt_state,
            "argv_sha256": argv_sha256,
            "execution_envelope_sha256": None,
            "resource_keys": [key],
            "observed_at_unix": resources._now() + 60,
            "observation_sha256": "e" * 64,
            "observation": {},
        }
        receipt_sha = hashlib.sha256(
            json.dumps(
                core,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        receipt_path = task_root / f"{task_id}.json"
        receipt_path.write_text(
            json.dumps({**core, "receipt_sha256": receipt_sha}),
            encoding="utf-8",
        )
        receipt_path.chmod(0o600)
        current_attempt = receipt_attempt if record_attempt is None else record_attempt
        current_state = receipt_state if record_state is None else record_state
        fake_tasks = types.SimpleNamespace(
            TASK_ID=re.compile(r"[0-9a-f]{24}\Z"),
            TASK_OUTCOMES_DIR=task_root,
            _row=lambda _task_id: {
                "task_id": task_id,
                "host": host,
                "lease_owner_id": owner,
                "resource_keys_json": json.dumps([key]),
                "state": current_state,
                "attempt": current_attempt,
                "unit": f"grabowski-task-{task_id}-a{current_attempt}.service",
                "argv_sha256": argv_sha256,
            },
            _lease_owner=lambda _task_id: owner,
            _record_resource_keys=lambda _record: [key],
        )
        terminal_source = {
            "kind": "durable_task_outcome",
            "task_id": task_id,
            "outcome_receipt_sha256": receipt_sha,
        }
        snapshot = {
            "resource_key": key,
            "owner_id": owner,
            "acquired_at_unix": 0,
            "updated_at_unix": 0,
            "expires_at_unix": 300,
            "metadata_sha256": resources._metadata(
                {"task_id": task_id, "host": host, "attempt": current_attempt}
            )[1],
        }
        return fake_tasks, terminal_source, owner, key, [snapshot]

    def test_path_blocker_returns_stable_owner_release_navigation(self) -> None:
        snapshots = self._acquire([self.path_a])
        result = resources.assess_nonconflict(
            blocked_resource_key=self.path_a,
            requesting_owner="owner-requester",
            resource_keys=[self.path_b],
            purpose="disjoint successor",
            requested_scope={},
            requested_scope_complete=True,
        )
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["code"], "exact-path-owner-release-required")
        self.assertEqual(result["blocker_type"], "exact_path_lease")
        self.assertEqual(result["blocked_lease"], snapshots[0])
        self.assertIn("reconcile_obsolete_path_leases", result["recommended_next_action"])

    def test_unchanged_owner_snapshot_is_released_atomically(self) -> None:
        snapshots = self._acquire([self.path_a])
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a]),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertEqual(result["state"], "complete")
        self.assertEqual([item["resource_key"] for item in result["released"]], [self.path_a])
        self.assertIsNone(resources.inspect_resource(self.path_a))
        core = {key: value for key, value in result.items() if key != "receipt_sha256"}
        self.assertEqual(
            result["receipt_sha256"],
            hashlib.sha256(resources._canonical_json(core).encode("utf-8")).hexdigest(),
        )

    def test_task_resume_like_lease_change_after_verification_is_retained(self) -> None:
        snapshots = self._acquire([self.path_a])

        def verify(*_args, **_kwargs):
            resources.acquire_resources(
                self.owner,
                [self.path_a],
                purpose="resumed terminal owner work",
                ttl_seconds=600,
                metadata={"attempt": 2},
            )
            return self._terminal_evidence(self.owner, [self.path_a])

        with patch.object(resources, "_verify_terminal_source", side_effect=verify):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "durable_task_outcome"},
            )
        self.assertEqual(result["state"], "no_change")
        self.assertEqual(result["retained"][0]["reason"], "lease_snapshot_changed")
        self.assertIsNotNone(resources.inspect_resource(self.path_a))

    def test_workspace_source_holds_workspace_lock_before_resource_reconcile(self) -> None:
        snapshots = self._acquire([self.path_a])
        held = {"value": False}

        class Lock:
            def __enter__(self):
                held["value"] = True
                return self

            def __exit__(self, exc_type, exc, traceback):
                held["value"] = False
                return False

        fake_workspace = types.SimpleNamespace(_lock=lambda _workspace_id: Lock())

        def verify(*_args, **_kwargs):
            self.assertTrue(held["value"])
            return self._terminal_evidence(self.owner, [self.path_a])

        def reconcile(**_kwargs):
            self.assertTrue(held["value"])
            return {"state": "complete"}

        with (
            patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}),
            patch.object(resources, "_verify_terminal_source", side_effect=verify),
            patch.object(
                resources,
                "_reconcile_verified_path_leases",
                side_effect=reconcile,
            ),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={
                    "kind": "agent_workspace_close",
                    "workspace_id": "gaw-lock-order",
                    "close_receipt_sha256": "a" * 64,
                },
            )
        self.assertEqual(result["state"], "complete")
        self.assertFalse(held["value"])

    def test_changed_snapshot_is_retained(self) -> None:
        snapshots = self._acquire([self.path_a])
        resources.renew_resources(self.owner, [self.path_a], ttl_seconds=600)
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a]),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertEqual(result["state"], "no_change")
        self.assertEqual(result["retained"][0]["reason"], "lease_snapshot_changed")
        self.assertIsNotNone(resources.inspect_resource(self.path_a))

    def test_partial_release_only_removes_unchanged_snapshot(self) -> None:
        snapshots = self._acquire([self.path_a, self.path_b])
        resources.renew_resources(self.owner, [self.path_b], ttl_seconds=600)
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a, self.path_b]),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a, self.path_b],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertEqual(result["state"], "partial")
        self.assertIsNone(resources.inspect_resource(self.path_a))
        self.assertIsNotNone(resources.inspect_resource(self.path_b))
        self.assertEqual(result["retained"], [{"resource_key": self.path_b, "reason": "lease_snapshot_changed"}])

    def test_concurrent_reconciliation_releases_snapshot_once(self) -> None:
        snapshots = self._acquire([self.path_a])
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def verify(*_args, **_kwargs):
            return self._terminal_evidence(self.owner, [self.path_a])

        def run() -> None:
            try:
                results.append(
                    resources.reconcile_obsolete_path_leases(
                        owner_id=self.owner,
                        resource_keys=[self.path_a],
                        expected_leases=snapshots,
                        terminal_source={"kind": "test"},
                    )
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with patch.object(resources, "_verify_terminal_source", side_effect=verify):
            threads = [threading.Thread(target=run) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=3)
        self.assertEqual(errors, [])
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertCountEqual([result["state"] for result in results], ["complete", "no_change"])
        self.assertIsNone(resources.inspect_resource(self.path_a))

    def test_second_reconciliation_is_idempotent_no_change(self) -> None:
        snapshots = self._acquire([self.path_a])
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a]),
        ):
            first = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
            second = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertEqual(first["state"], "complete")
        self.assertEqual(second["state"], "no_change")
        self.assertEqual(second["retained"][0]["reason"], "already_absent")

    def test_wrong_owner_snapshot_is_rejected_before_database_change(self) -> None:
        snapshots = self._acquire([self.path_a])
        snapshots[0]["owner_id"] = "owner-other"
        with self.assertRaises(PermissionError):
            resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertIsNotNone(resources.inspect_resource(self.path_a))

    def test_unsupported_terminal_source_cannot_use_expiry_or_process_absence(self) -> None:
        snapshots = self._acquire([self.path_a])
        with self.assertRaises(nonconflict.NonConflictDenied) as raised:
            resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "process_absent", "expired": True},
            )
        self.assertEqual(raised.exception.code, "unsupported-terminal-source")
        self.assertIsNotNone(resources.inspect_resource(self.path_a))

    def test_task_receipt_symlink_is_rejected(self) -> None:
        receipt_dir = self.root / "private-receipts"
        receipt_dir.mkdir(mode=0o700)
        target = self.root / "target.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        link = receipt_dir / "receipt.json"
        link.symlink_to(target)
        with self.assertRaises(PermissionError):
            resources._load_private_receipt_json(link)

    def test_current_completed_task_receipt_is_authoritative(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            evidence = resources._verify_task_terminal_source(
                terminal_source,
                owner_id=owner,
                resource_keys=[key],
                expected_leases=snapshots,
            )
        self.assertEqual(evidence["state"], "completed")
        self.assertEqual(evidence["attempt"], 1)


    def test_task_lease_metadata_must_bind_current_attempt(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        snapshots[0]["metadata_sha256"] = "0" * 64
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-mismatch")

    def test_task_lease_update_after_terminal_observation_is_rejected(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        snapshots[0]["updated_at_unix"] = resources._now() + 120
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-drift")

    def test_task_lease_updated_in_terminal_second_is_rejected(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        receipt = json.loads(
            (fake_tasks.TASK_OUTCOMES_DIR / f"{terminal_source['task_id']}.json").read_text(
                encoding="utf-8"
            )
        )
        snapshots[0]["updated_at_unix"] = receipt["observed_at_unix"]
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-drift")

    def test_task_lease_acquired_in_terminal_second_is_rejected(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        receipt = json.loads(
            (fake_tasks.TASK_OUTCOMES_DIR / f"{terminal_source['task_id']}.json").read_text(
                encoding="utf-8"
            )
        )
        snapshots[0]["acquired_at_unix"] = receipt["observed_at_unix"]
        snapshots[0]["updated_at_unix"] = receipt["observed_at_unix"]
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-drift")

    def test_stale_task_attempt_receipt_remains_blocked(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed",
            receipt_attempt=1,
            record_attempt=2,
            record_state="running",
        )
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "owner-work-nonterminal")

    def test_failed_task_receipt_remains_blocked(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="failed"
        )
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(raised.exception.code, "owner-work-nonterminal")

    def test_task_outcome_unknown_receipt_remains_blocked(self) -> None:
        task_id = "c" * 24
        key = self.path_a
        task_root = self.root / "task-outcomes"
        task_root.mkdir(mode=0o700)
        core = {
            "schema_version": 1,
            "task_id": task_id,
            "unit": f"grabowski-task-{task_id}-a1.service",
            "attempt": 1,
            "state": "outcome_unknown",
            "argv_sha256": "d" * 64,
            "execution_envelope_sha256": None,
            "resource_keys": [key],
            "observed_at_unix": 1,
            "observation_sha256": "e" * 64,
            "observation": {},
        }
        receipt_sha = hashlib.sha256(
            json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        receipt_path = task_root / f"{task_id}.json"
        receipt_path.write_text(
            json.dumps({**core, "receipt_sha256": receipt_sha}), encoding="utf-8"
        )
        receipt_path.chmod(0o600)
        fake_tasks = types.SimpleNamespace(
            TASK_ID=re.compile(r"[0-9a-f]{24}\Z"),
            TASK_OUTCOMES_DIR=task_root,
            _row=lambda _task_id: {
                "task_id": task_id,
                "host": "local",
                "lease_owner_id": f"task:{task_id}",
                "resource_keys_json": json.dumps([key]),
            },
            _lease_owner=lambda _task_id: f"task:{task_id}",
            _record_resource_keys=lambda _record: [key],
        )
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_task_terminal_source(
                    {
                        "kind": "durable_task_outcome",
                        "task_id": task_id,
                        "outcome_receipt_sha256": receipt_sha,
                    },
                    owner_id=f"task:{task_id}",
                    resource_keys=[key],
                    expected_leases=[
                        {
                            "resource_key": key,
                            "owner_id": f"task:{task_id}",
                            "acquired_at_unix": 0,
                            "updated_at_unix": 0,
                            "expires_at_unix": 300,
                            "metadata_sha256": resources._metadata(
                                {"task_id": task_id, "host": "local", "attempt": None}
                            )[1],
                        }
                    ],
                )
        self.assertEqual(raised.exception.code, "owner-work-nonterminal")


    def test_workspace_incomplete_release_receipt_is_authoritative(self) -> None:
        workspace_id = "gaw-test-terminal"
        key = self.path_a
        workspace_root = self.root / "workspaces" / workspace_id
        workspace_root.mkdir(parents=True)
        task_states = {
            role: {
                "task_id": f"task-{role}",
                "attempt": 1,
                "state": "completed",
                "terminal": True,
            }
            for role in ("writer", "tests", "review")
        }
        collection = {
            "state": "complete",
            "writer_head": "a" * 40,
            "diff_sha256": "b" * 64,
            "result_sha256": "c" * 64,
        }
        core = {
            "schema_version": 1,
            "state": "resource_release_incomplete",
            "workspace_id": workspace_id,
            "expected_head": collection["writer_head"],
            "expected_diff_sha256": collection["diff_sha256"],
            "expected_result_sha256": collection["result_sha256"],
            "task_states": task_states,
            "closed_at": "1970-01-01T00:00:01+00:00",
            "closure_outcome": "successful",
            "failed_roles": [],
            "abandon_failed_roles": False,
            "remaining_resource_keys": [key],
        }
        receipt_sha = hashlib.sha256(
            resources._canonical_json(core).encode("utf-8")
        ).hexdigest()
        receipt = {**core, "receipt_sha256": receipt_sha}
        (workspace_root / "close-receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        binding = {"kind": "test", "id": "terminal"}
        base_head = "f" * 40
        plan_sha256 = "1" * 64
        manifest = {
            "resources": {"owner_id": self.owner, "lease_keys": [key]},
            "collection": collection,
            "tasks": {role: f"task-{role}" for role in task_states},
            "binding": binding,
            "expected_base_head": base_head,
            "plan_sha256": plan_sha256,
        }
        expected_leases = [
            {
                "resource_key": key,
                "owner_id": self.owner,
                "acquired_at_unix": 0,
                "updated_at_unix": 0,
                "expires_at_unix": 300,
                "metadata_sha256": resources._metadata(
                    {
                        "workspace_id": workspace_id,
                        "binding": binding,
                        "base_head": base_head,
                        "plan_sha256": plan_sha256,
                    }
                )[1],
            }
        ]
        fake_workspace = types.SimpleNamespace(
            _manifest=lambda _workspace_id: manifest,
            _workspace_dir=lambda _workspace_id: workspace_root,
            _load_json=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _receipt_integrity=lambda value: value.get("receipt_sha256")
            == hashlib.sha256(
                resources._canonical_json(
                    {name: item for name, item in value.items() if name != "receipt_sha256"}
                ).encode("utf-8")
            ).hexdigest(),
            _collection_integrity_status=lambda _manifest, _collection: {"valid": True},
            _collection_failed_roles=lambda _collection: [],
            _close_integrity_status=lambda _manifest, _receipt: {"valid": False},
            _task_public=lambda task_id: next(
                item for item in task_states.values() if item["task_id"] == task_id
            ),
        )
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            evidence = resources._verify_workspace_terminal_source(
                {
                    "kind": "agent_workspace_close",
                    "workspace_id": workspace_id,
                    "close_receipt_sha256": receipt_sha,
                },
                owner_id=self.owner,
                resource_keys=[key],
                expected_leases=expected_leases,
            )
        self.assertEqual(evidence["state"], "resource_release_incomplete")
        self.assertEqual(evidence["resource_keys"], [key])

        same_second_leases = [dict(expected_leases[0])]
        same_second_leases[0]["acquired_at_unix"] = 1
        same_second_leases[0]["updated_at_unix"] = 1
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": receipt_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=same_second_leases,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-drift")

        same_update_leases = [dict(expected_leases[0])]
        same_update_leases[0]["updated_at_unix"] = 1
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": receipt_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=same_update_leases,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-drift")

        naive_core = {**core, "closed_at": "1970-01-01T00:00:01"}
        naive_sha = hashlib.sha256(
            resources._canonical_json(naive_core).encode("utf-8")
        ).hexdigest()
        (workspace_root / "close-receipt.json").write_text(
            json.dumps({**naive_core, "receipt_sha256": naive_sha}), encoding="utf-8"
        )
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": naive_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=expected_leases,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-invalid")

    def test_workspace_explicit_abandoned_failed_roles_is_authoritative(self) -> None:
        workspace_id = "gaw-test-abandoned"
        key = self.path_a
        workspace_root = self.root / "workspaces" / workspace_id
        workspace_root.mkdir(parents=True)
        task_states = {
            "writer": {
                "task_id": "task-writer",
                "attempt": 1,
                "state": "completed",
                "terminal": True,
            },
            "tests": {
                "task_id": "task-tests",
                "attempt": 1,
                "state": "failed",
                "terminal": True,
            },
            "review": {
                "task_id": "task-review",
                "attempt": 1,
                "state": "completed",
                "terminal": True,
            },
        }
        collection = {
            "state": "complete",
            "writer_head": "a" * 40,
            "diff_sha256": "b" * 64,
            "result_sha256": "c" * 64,
        }
        core = {
            "schema_version": 1,
            "state": "resource_release_incomplete",
            "workspace_id": workspace_id,
            "expected_head": collection["writer_head"],
            "expected_diff_sha256": collection["diff_sha256"],
            "expected_result_sha256": collection["result_sha256"],
            "task_states": task_states,
            "closed_at": "1970-01-01T00:00:01+00:00",
            "closure_outcome": "abandoned_failed_roles",
            "failed_roles": ["tests"],
            "abandon_failed_roles": True,
            "remaining_resource_keys": [key],
        }
        receipt_sha = hashlib.sha256(
            resources._canonical_json(core).encode("utf-8")
        ).hexdigest()
        receipt = {**core, "receipt_sha256": receipt_sha}
        (workspace_root / "close-receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        binding = {"kind": "test", "id": "abandoned"}
        base_head = "f" * 40
        plan_sha256 = "1" * 64
        manifest = {
            "resources": {"owner_id": self.owner, "lease_keys": [key]},
            "collection": collection,
            "tasks": {role: value["task_id"] for role, value in task_states.items()},
            "binding": binding,
            "expected_base_head": base_head,
            "plan_sha256": plan_sha256,
        }
        expected_leases = [
            {
                "resource_key": key,
                "owner_id": self.owner,
                "acquired_at_unix": 0,
                "updated_at_unix": 0,
                "expires_at_unix": 300,
                "metadata_sha256": resources._metadata(
                    {
                        "workspace_id": workspace_id,
                        "binding": binding,
                        "base_head": base_head,
                        "plan_sha256": plan_sha256,
                    }
                )[1],
            }
        ]
        fake_workspace = types.SimpleNamespace(
            _manifest=lambda _workspace_id: manifest,
            _workspace_dir=lambda _workspace_id: workspace_root,
            _load_json=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _receipt_integrity=lambda value: value.get("receipt_sha256")
            == hashlib.sha256(
                resources._canonical_json(
                    {
                        name: item
                        for name, item in value.items()
                        if name != "receipt_sha256"
                    }
                ).encode("utf-8")
            ).hexdigest(),
            _collection_integrity_status=lambda _manifest, _collection: {
                "valid": True
            },
            _collection_failed_roles=lambda _collection: ["tests"],
            _close_integrity_status=lambda _manifest, _receipt: {"valid": False},
            _task_public=lambda task_id: next(
                item for item in task_states.values() if item["task_id"] == task_id
            ),
        )
        mismatched_workspace = types.SimpleNamespace(**vars(fake_workspace))
        mismatched_workspace._collection_failed_roles = lambda _collection: ["review"]
        with patch.dict(
            sys.modules, {"grabowski_agent_workspace": mismatched_workspace}
        ):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": receipt_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=expected_leases,
                )
        self.assertEqual(raised.exception.code, "terminal-evidence-invalid")

        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            evidence = resources._verify_workspace_terminal_source(
                {
                    "kind": "agent_workspace_close",
                    "workspace_id": workspace_id,
                    "close_receipt_sha256": receipt_sha,
                },
                owner_id=self.owner,
                resource_keys=[key],
                expected_leases=expected_leases,
            )
        self.assertEqual(evidence["closure_outcome"], "abandoned_failed_roles")
        self.assertEqual(evidence["state"], "resource_release_incomplete")

    def test_workspace_unknown_closure_outcome_remains_blocked(self) -> None:
        workspace_id = "gaw-test-unknown-outcome"
        key = self.path_a
        workspace_root = self.root / "workspaces" / workspace_id
        workspace_root.mkdir(parents=True)
        core = {
            "schema_version": 1,
            "state": "resource_release_incomplete",
            "workspace_id": workspace_id,
            "closure_outcome": "outcome_unknown",
        }
        receipt_sha = hashlib.sha256(
            resources._canonical_json(core).encode("utf-8")
        ).hexdigest()
        receipt = {**core, "receipt_sha256": receipt_sha}
        (workspace_root / "close-receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        fake_workspace = types.SimpleNamespace(
            _manifest=lambda _workspace_id: {},
            _workspace_dir=lambda _workspace_id: workspace_root,
            _load_json=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _receipt_integrity=lambda value: True,
        )
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": receipt_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=[],
                )
        self.assertEqual(raised.exception.code, "owner-work-nonterminal")

    def test_nonterminal_workspace_closeout_remains_blocked(self) -> None:
        workspace_id = "gaw-test-active"
        key = self.path_a
        workspace_root = self.root / "workspaces" / workspace_id
        workspace_root.mkdir(parents=True)
        core = {
            "schema_version": 1,
            "state": "closing",
            "workspace_id": workspace_id,
            "task_states": {"writer": {"terminal": False}},
            "closure_outcome": "successful",
            "remaining_resource_keys": [key],
        }
        receipt_sha = hashlib.sha256(
            resources._canonical_json(core).encode("utf-8")
        ).hexdigest()
        receipt = {**core, "receipt_sha256": receipt_sha}
        (workspace_root / "close-receipt.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        fake_workspace = types.SimpleNamespace(
            _manifest=lambda _workspace_id: {
                "resources": {"owner_id": self.owner, "lease_keys": [key]}
            },
            _workspace_dir=lambda _workspace_id: workspace_root,
            _load_json=lambda path: json.loads(path.read_text(encoding="utf-8")),
            _receipt_integrity=lambda value: True,
        )
        with patch.dict(sys.modules, {"grabowski_agent_workspace": fake_workspace}):
            with self.assertRaises(nonconflict.NonConflictDenied) as raised:
                resources._verify_workspace_terminal_source(
                    {
                        "kind": "agent_workspace_close",
                        "workspace_id": workspace_id,
                        "close_receipt_sha256": receipt_sha,
                    },
                    owner_id=self.owner,
                    resource_keys=[key],
                    expected_leases=[],
                )
        self.assertEqual(raised.exception.code, "owner-work-nonterminal")


    def test_completed_task_source_releases_matching_live_snapshot(self) -> None:
        fake_tasks, terminal_source, owner, key, _ = self._task_source_fixture(
            receipt_state="completed"
        )
        task_id = terminal_source["task_id"]
        acquired = resources.acquire_resources(
            owner,
            [key],
            purpose="completed task lease",
            ttl_seconds=300,
            metadata={"task_id": task_id, "host": "local", "attempt": 1},
        )
        snapshots = [self._snapshot(acquired["leases"][0])]
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=owner,
                resource_keys=[key],
                expected_leases=snapshots,
                terminal_source=terminal_source,
            )
        self.assertEqual(result["state"], "complete")
        self.assertIsNone(resources.inspect_resource(key))

    def test_only_explicitly_named_path_is_released(self) -> None:
        snapshots = self._acquire([self.path_a, self.path_b])
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a]),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=[snapshots[0]],
                terminal_source={"kind": "test"},
            )
        self.assertEqual(result["state"], "complete")
        self.assertIsNone(resources.inspect_resource(self.path_a))
        self.assertIsNotNone(resources.inspect_resource(self.path_b))

    def test_each_changed_snapshot_field_is_retained(self) -> None:
        mutations = {
            "updated_at_unix": lambda value: int(value) + 1,
            "expires_at_unix": lambda value: int(value) + 1,
            "metadata_sha256": lambda _value: "0" * 64,
        }
        for field, mutate in mutations.items():
            with self.subTest(field=field):
                key = f"path:{self.root / 'repo' / (field + '.py')}"
                acquired = self._acquire([key])
                expected = [dict(acquired[0])]
                expected[0][field] = mutate(expected[0][field])
                with patch.object(
                    resources,
                    "_verify_terminal_source",
                    return_value=self._terminal_evidence(self.owner, [key]),
                ):
                    result = resources.reconcile_obsolete_path_leases(
                        owner_id=self.owner,
                        resource_keys=[key],
                        expected_leases=expected,
                        terminal_source={"kind": "test"},
                    )
                self.assertEqual(result["state"], "no_change")
                self.assertEqual(result["retained"][0]["reason"], "lease_snapshot_changed")
                self.assertIsNotNone(resources.inspect_resource(key))
                resources.release_resources(self.owner, [key])

    def test_live_owner_change_is_retained(self) -> None:
        snapshots = self._acquire([self.path_a])
        resources.release_resources(self.owner, [self.path_a])
        resources.acquire_resources(
            "owner-other",
            [self.path_a],
            purpose="replacement owner",
            ttl_seconds=300,
        )
        with patch.object(
            resources,
            "_verify_terminal_source",
            return_value=self._terminal_evidence(self.owner, [self.path_a]),
        ):
            result = resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={"kind": "test"},
            )
        self.assertEqual(result["state"], "no_change")
        self.assertEqual(result["retained"][0]["reason"], "owner_changed")
        self.assertEqual(resources.inspect_resource(self.path_a)["owner_id"], "owner-other")

    def test_non_path_resource_is_never_reconciled(self) -> None:
        with self.assertRaisesRegex(ValueError, "exact path leases only"):
            resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=["service:example.service"],
                expected_leases=[],
                terminal_source={"kind": "durable_task_outcome"},
            )

    def test_absent_and_expired_path_navigation_is_stable(self) -> None:
        absent = resources.assess_nonconflict(
            blocked_resource_key=self.path_a,
            requesting_owner="owner-requester",
            resource_keys=[self.path_b],
            purpose="successor",
            requested_scope={},
            requested_scope_complete=True,
        )
        self.assertEqual(absent["code"], "blocked-path-lease-absent-or-expired")
        lease = resources.acquire_resources(
            self.owner,
            [self.path_a],
            purpose="expiring blocker",
            ttl_seconds=30,
        )["leases"][0]
        with patch.object(resources, "_now", return_value=lease["expires_at_unix"]):
            expired = resources.assess_nonconflict(
                blocked_resource_key=self.path_a,
                requesting_owner="owner-requester",
                resource_keys=[self.path_b],
                purpose="successor",
                requested_scope={},
                requested_scope_complete=True,
            )
        self.assertEqual(expired["code"], "blocked-path-lease-absent-or-expired")

    def test_unsupported_blocker_navigation_is_stable(self) -> None:
        result = resources.assess_nonconflict(
            blocked_resource_key="service:example.service",
            requesting_owner="owner-requester",
            resource_keys=[self.path_b],
            purpose="successor",
            requested_scope={},
            requested_scope_complete=True,
        )
        self.assertEqual(result["code"], "unsupported-blocker-type")
        self.assertEqual(result["blocker_type"], "service")

    def test_missing_or_hash_drifted_task_receipt_is_blocked(self) -> None:
        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        receipt_path = fake_tasks.TASK_OUTCOMES_DIR / f"{terminal_source['task_id']}.json"
        receipt_path.unlink()
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as missing:
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(missing.exception.code, "terminal-evidence-missing")

        fake_tasks, terminal_source, owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        drifted = {**terminal_source, "outcome_receipt_sha256": "0" * 64}
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(nonconflict.NonConflictDenied) as invalid:
                resources._verify_task_terminal_source(
                    drifted,
                    owner_id=owner,
                    resource_keys=[key],
                    expected_leases=snapshots,
                )
        self.assertEqual(invalid.exception.code, "terminal-evidence-invalid")

    def test_task_receipt_for_other_owner_is_blocked(self) -> None:
        fake_tasks, terminal_source, _owner, key, snapshots = self._task_source_fixture(
            receipt_state="completed"
        )
        snapshots[0]["owner_id"] = "owner-other"
        with patch.dict(sys.modules, {"grabowski_tasks": fake_tasks}):
            with self.assertRaises(PermissionError):
                resources._verify_task_terminal_source(
                    terminal_source,
                    owner_id="owner-other",
                    resource_keys=[key],
                    expected_leases=snapshots,
                )

    def test_caller_constructed_hash_has_no_terminal_authority(self) -> None:
        snapshots = self._acquire([self.path_a])
        with self.assertRaises(nonconflict.NonConflictDenied) as raised:
            resources.reconcile_obsolete_path_leases(
                owner_id=self.owner,
                resource_keys=[self.path_a],
                expected_leases=snapshots,
                terminal_source={
                    "kind": "caller_receipt",
                    "receipt_sha256": hashlib.sha256(b"self").hexdigest(),
                    "task_title": "completed",
                    "process_present": False,
                    "nonconflict_proof": True,
                },
            )
        self.assertEqual(raised.exception.code, "unsupported-terminal-source")
        self.assertIsNotNone(resources.inspect_resource(self.path_a))


if __name__ == "__main__":
    unittest.main()
