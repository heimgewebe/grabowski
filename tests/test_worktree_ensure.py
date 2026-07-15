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

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


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
import grabowski_grips as grips
import grabowski_worktree_ensure as worktree_ensure


class WorktreeEnsureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self._git(self.repo, "init", "-b", "main")
        self._git(self.repo, "config", "user.email", "tests@example.invalid")
        self._git(self.repo, "config", "user.name", "Grabowski Tests")
        (self.repo / "README.md").write_text("fixture\n", encoding="utf-8")
        self._git(self.repo, "add", "README.md")
        self._git(self.repo, "commit", "-m", "fixture")
        self.head = self._git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.worktree_root = self.root / "worktrees"
        self.worktree_root.mkdir()
        self.receipt_root = self.root / "receipts"
        self.checkout_state = self.root / "checkout-state"
        self.checkout_patches = [
            patch.object(checkouts, "CHECKOUT_DB", self.checkout_state / "checkouts.sqlite3"),
            patch.object(checkouts, "CHECKOUT_LOCK", self.checkout_state / "checkouts.lock"),
            patch.object(checkouts, "ARCHIVE_ROOT", self.checkout_state / "archives"),
        ]
        for checkout_patch in self.checkout_patches:
            checkout_patch.start()
            self.addCleanup(checkout_patch.stop)
        self.owner = "test-owner"
        self.retention_until = int(time.time()) + 2 * 24 * 60 * 60
        self.friction_events: list[dict[str, object]] = []
        self.friction_closeouts: list[dict[str, object]] = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _git(cwd: Path, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(cwd), *argv],
            check=True,
            text=True,
            capture_output=True,
        )

    def _parameters(
        self,
        *,
        key: str = "worktree-case-1",
        branch: str = "feat/worktree-case",
        target: Path | None = None,
        owner: str | None = None,
    ) -> dict[str, object]:
        return {
            "repo": str(self.repo),
            "base_head": self.head,
            "branch": branch,
            "target_path": str(target or (self.worktree_root / "case")),
            "lease_owner_id": owner or self.owner,
            "purpose": "implement the bound checkout test",
            "retention_until_unix": self.retention_until,
            "source_kind": "bureau_task",
            "source_id": "STORAGE-LIFECYCLE-V1-T003",
            "artifact_class": "operator_worktree",
            "idempotency_key": key,
        }

    def _lease(self, resource_key: str) -> dict[str, object]:
        return {
            "resource_key": resource_key,
            "owner_id": self.owner,
            "expires_at_unix": int(time.time()) + 3600,
        }

    def _record_friction(self, **kwargs: object) -> dict[str, object]:
        event_id = f"event-{len(self.friction_events) + 1}"
        event = {"event_id": event_id, "recorded": True, **kwargs}
        self.friction_events.append(event)
        return event

    def _resolve_friction(self, **kwargs: object) -> dict[str, object]:
        closeout = {"resolved": True, **kwargs}
        self.friction_closeouts.append(closeout)
        return closeout

    def _ensure(
        self,
        parameters: dict[str, object],
        *,
        runner=grips._default_command_runner,
        inspect_lease=None,
    ) -> dict[str, object]:
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ):
            return worktree_ensure.ensure_worktree(
                parameters,
                runner,
                inspect_lease or self._lease,
                record_friction=self._record_friction,
                resolve_friction=self._resolve_friction,
            )

    def test_creation_contract_rejects_missing_explicit_lifecycle_fields(self) -> None:
        for missing in (
            "purpose",
            "retention_until_unix",
            "source_kind",
            "source_id",
            "artifact_class",
        ):
            parameters = self._parameters(key=f"missing-{missing}")
            parameters.pop(missing)
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(
                    worktree_ensure.WorktreeEnsurePreflight, missing
                ):
                    self._ensure(parameters)
                self.assertFalse(Path(str(parameters["target_path"])).exists())

    def test_active_limit_blocks_new_growth_without_deleting_existing_checkout(self) -> None:
        first = self._parameters(
            key="limit-first",
            branch="feat/limit-first",
            target=self.worktree_root / "limit-first",
        )
        second = self._parameters(
            key="limit-second",
            branch="feat/limit-second",
            target=self.worktree_root / "limit-second",
        )
        with patch.object(checkouts, "MAX_ACTIVE_CHECKOUTS_PER_REPO", 1):
            created = self._ensure(first)
            blocked = self._ensure(second)

        self.assertEqual(created["result_state"], "CREATED")
        self.assertEqual(blocked["result_state"], "NOT_ACCEPTED")
        self.assertEqual(blocked["error_class"], "CHECKOUT_LIFECYCLE_REJECTED")
        self.assertIn("active checkout limit", blocked["error"])
        self.assertTrue(Path(str(first["target_path"])).is_dir())
        self.assertFalse(Path(str(second["target_path"])).exists())

    def test_creates_and_replays_same_durable_result(self) -> None:
        parameters = self._parameters()
        created = self._ensure(parameters)
        replayed = self._ensure(parameters)

        self.assertEqual(created["result_state"], "CREATED")
        self.assertFalse(created["replayed"])
        self.assertEqual(replayed["result_state"], "CREATED")
        self.assertTrue(replayed["replayed"])
        self.assertEqual(
            created["durable_receipt_sha256"], replayed["durable_receipt_sha256"]
        )
        self.assertEqual(self._git(Path(parameters["target_path"]), "rev-parse", "HEAD").stdout.strip(), self.head)
        self.assertEqual(self.friction_events, [])
        lifecycle = created["lifecycle"]
        self.assertEqual(lifecycle["owner_id"], self.owner)
        self.assertEqual(
            lifecycle["task"],
            {"kind": "worktree_ensure", "id": "worktree-ensure:worktree-case-1"},
        )
        self.assertEqual(lifecycle["purpose"], "implement the bound checkout test")
        self.assertEqual(
            lifecycle["source"],
            {"kind": "bureau_task", "id": "STORAGE-LIFECYCLE-V1-T003"},
        )
        self.assertEqual(lifecycle["artifact_class"], "operator_worktree")
        self.assertEqual(lifecycle["limit"]["maximum"], 8)
        self.assertEqual(lifecycle["expected_head"], self.head)
        self.assertEqual(lifecycle["expected_branch"], "feat/worktree-case")
        self.assertEqual(lifecycle["terminal_decision"], "retain")
        self.assertFalse(lifecycle["automatic_cleanup_authorized"])
        self.assertEqual(replayed["lifecycle"]["checkout_key"], lifecycle["checkout_key"])
        self.assertEqual(created["lifecycle_integrity"]["source"], "durable_receipt")
        self.assertTrue(created["lifecycle_integrity"]["bound_to_durable_receipt"])
        self.assertEqual(
            created["lifecycle_integrity"]["sha256"],
            worktree_ensure._sha256_json(lifecycle),
        )
        stored = checkouts._retention_records([lifecycle["checkout_key"]])
        self.assertEqual(stored[lifecycle["checkout_key"]]["owner_id"], self.owner)

    def test_legacy_success_replay_marks_lifecycle_as_unbound_projection(self) -> None:
        parameters = self._parameters(key="legacy-success")
        created = self._ensure(parameters)
        receipt_path = Path(created["durable_receipt_path"])
        record = json.loads(receipt_path.read_text(encoding="utf-8"))
        record.pop("lifecycle")
        worktree_ensure._write_receipt(receipt_path, record)
        legacy_record = json.loads(receipt_path.read_text(encoding="utf-8"))
        legacy_receipt_sha256 = legacy_record["receipt_sha256"]

        replayed = self._ensure(parameters)

        self.assertEqual(replayed["result_state"], "CREATED")
        self.assertEqual(replayed["durable_receipt_sha256"], legacy_receipt_sha256)
        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="utf-8"))["receipt_sha256"],
            legacy_receipt_sha256,
        )
        self.assertEqual(
            replayed["lifecycle_integrity"]["source"],
            "checkout_retention_db",
        )
        self.assertFalse(
            replayed["lifecycle_integrity"]["bound_to_durable_receipt"]
        )
        self.assertEqual(
            replayed["lifecycle_integrity"]["sha256"],
            worktree_ensure._sha256_json(replayed["lifecycle"]),
        )

    def test_existing_exact_worktree_is_already_correct(self) -> None:
        first = self._parameters(key="create-first")
        self.assertEqual(self._ensure(first)["result_state"], "CREATED")
        second = self._parameters(key="observe-existing")

        result = self._ensure(second)

        self.assertEqual(result["result_state"], "ALREADY_CORRECT")
        self.assertFalse(result["replayed"])
        self.assertEqual(result["lifecycle"]["terminal_decision"], "retain")
        self.assertFalse(result["lifecycle"]["automatic_cleanup_authorized"])

    def test_conflicting_target_fails_closed_and_records_friction(self) -> None:
        target = self.worktree_root / "occupied"
        target.mkdir()
        result = self._ensure(self._parameters(key="conflict", target=target))

        self.assertEqual(result["result_state"], "CONFLICT")
        self.assertEqual(result["error_class"], "WORKTREE_CONFLICT")
        self.assertEqual(len(self.friction_events), 1)
        self.assertEqual(self.friction_events[0]["kind"], "fail_closed_gate")

    def test_foreign_lease_is_rejected_without_mutation(self) -> None:
        def foreign_lease(resource_key: str) -> dict[str, object]:
            return {
                "resource_key": resource_key,
                "owner_id": "foreign-owner",
                "expires_at_unix": int(time.time()) + 3600,
            }

        parameters = self._parameters(key="foreign-lease")
        result = self._ensure(parameters, inspect_lease=foreign_lease)

        self.assertEqual(result["result_state"], "REJECTED_BY_LEASE")
        self.assertEqual(result["error_class"], "LEASE_REJECTED")
        self.assertFalse(Path(parameters["target_path"]).exists())

    def test_same_idempotency_key_cannot_be_rebound_without_new_git_reads(self) -> None:
        original = self._parameters(key="stable-key")
        self.assertEqual(self._ensure(original)["result_state"], "CREATED")
        changed = self._parameters(key="stable-key", branch="invalid..branch")

        def unexpected_runner(_repo: Path, _argv: list[str]) -> dict[str, object]:
            self.fail("idempotency-key reuse must block before new Git observation")

        result = self._ensure(changed, runner=unexpected_runner)

        self.assertEqual(result["result_state"], "CONFLICT")
        self.assertEqual(result["error_class"], "IDEMPOTENCY_KEY_REUSE")

    def test_replay_recovers_crash_after_git_mutation_and_closes_friction(self) -> None:
        parameters = self._parameters(key="crash-window", target=self.worktree_root / "crash")
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ), patch.object(
            worktree_ensure,
            "_after_worktree_mutation",
            side_effect=SystemExit("simulated process loss"),
        ):
            with self.assertRaises(SystemExit):
                worktree_ensure.ensure_worktree(
                    parameters,
                    grips._default_command_runner,
                    self._lease,
                    record_friction=self._record_friction,
                    resolve_friction=self._resolve_friction,
                )

        receipt_files = list(self.receipt_root.glob("*.json"))
        self.assertEqual(len(receipt_files), 1)
        self.assertEqual(json.loads(receipt_files[0].read_text())["state"], "intent")

        recovered = self._ensure(parameters)

        self.assertEqual(recovered["result_state"], "CREATED")
        self.assertTrue(recovered["replayed"])
        self.assertTrue(recovered["recovered_after_interruption"])
        self.assertEqual(len(self.friction_events), 1)
        self.assertEqual(len(self.friction_closeouts), 1)
        self.assertEqual(
            self.friction_closeouts[0]["event_id"], self.friction_events[0]["event_id"]
        )

    def test_lease_is_rechecked_immediately_before_mutation(self) -> None:
        parameters = self._parameters(key="lease-race", target=self.worktree_root / "lease-race")
        calls = 0

        def changing_lease(resource_key: str) -> dict[str, object]:
            nonlocal calls
            calls += 1
            first_check = calls <= 2
            return {
                "resource_key": resource_key,
                "owner_id": self.owner if first_check else "foreign-owner",
                "expires_at_unix": int(time.time()) + 3600,
            }

        result = self._ensure(parameters, inspect_lease=changing_lease)

        self.assertEqual(result["result_state"], "REJECTED_BY_LEASE")
        self.assertEqual(result["error_class"], "LEASE_REJECTED_BEFORE_MUTATION")
        self.assertEqual(calls, 4)
        self.assertFalse(Path(parameters["target_path"]).exists())

    def test_replay_finalizes_verified_state_after_lease_expiry_without_mutation(self) -> None:
        parameters = self._parameters(key="crash-expired-lease", target=self.worktree_root / "expired")
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ), patch.object(
            worktree_ensure,
            "_after_worktree_mutation",
            side_effect=SystemExit("simulated process loss"),
        ):
            with self.assertRaises(SystemExit):
                worktree_ensure.ensure_worktree(
                    parameters,
                    grips._default_command_runner,
                    self._lease,
                    record_friction=self._record_friction,
                    resolve_friction=self._resolve_friction,
                )

        def expired_lease(resource_key: str) -> dict[str, object]:
            return {
                "resource_key": resource_key,
                "owner_id": self.owner,
                "expires_at_unix": int(time.time()) - 1,
            }

        def readback_only_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            if argv[:3] == ["worktree", "add", "-b"]:
                self.fail("recovery attempted a second mutation after the exact state already existed")
            return grips._default_command_runner(repo, argv)

        recovered = self._ensure(
            parameters,
            runner=readback_only_runner,
            inspect_lease=expired_lease,
        )

        self.assertEqual(recovered["result_state"], "CREATED")
        self.assertTrue(recovered["replayed"])
        self.assertTrue(recovered["recovered_after_interruption"])
        receipt = json.loads(Path(recovered["durable_receipt_path"]).read_text())
        self.assertTrue(receipt["recovery_without_live_lease"])
        self.assertFalse(receipt["lease"]["valid"])
        self.assertEqual(recovered["lifecycle"]["terminal_decision"], "retain")
        self.assertGreater(recovered["lifecycle"]["expires_at_unix"], int(time.time()))

    def test_replay_detects_post_state_drift(self) -> None:
        parameters = self._parameters(key="drift")
        created = self._ensure(parameters)
        self.assertEqual(created["result_state"], "CREATED")
        (Path(parameters["target_path"]) / "drift.txt").write_text("changed\n", encoding="utf-8")

        replayed = self._ensure(parameters)

        self.assertEqual(replayed["result_state"], "CONFLICT")
        self.assertEqual(replayed["error_class"], "POST_STATE_DRIFT")
        self.assertTrue(replayed["replayed"])

    def test_schema_foreign_but_integrity_valid_receipt_is_rejected(self) -> None:
        parameters = self._parameters(key="foreign-schema")
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ):
            self.receipt_root.mkdir(mode=0o700)
            receipt_path, _lock_path = worktree_ensure._receipt_paths(parameters["idempotency_key"])
            worktree_ensure._write_receipt(
                receipt_path,
                {
                    "kind": "foreign.receipt",
                    "schema_version": 1,
                    "state": "complete",
                    "result_state": "CREATED",
                    "parameters_sha256": "a" * 64,
                    "idempotency_key_sha256": "b" * 64,
                    "inputs": {},
                    "post_state": {},
                    "lease": {},
                    "error_class": None,
                    "error": "",
                    "friction": None,
                    "friction_closeout": None,
                    "created_at_unix": 1,
                    "updated_at_unix": 1,
                },
            )

        with self.assertRaises(worktree_ensure.WorktreeEnsureAction):
            self._ensure(parameters)
        self.assertFalse(Path(parameters["target_path"]).exists())

    def test_receipt_rejects_lifecycle_cleanup_authority(self) -> None:
        parameters = self._parameters(key="unsafe-lifecycle")
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ):
            self.receipt_root.mkdir(mode=0o700)
            receipt_path, _lock_path = worktree_ensure._receipt_paths(
                parameters["idempotency_key"]
            )
            inputs = worktree_ensure._normalize_inputs(parameters)
            worktree_ensure._write_receipt(
                receipt_path,
                {
                    "kind": worktree_ensure.RECEIPT_KIND,
                    "schema_version": 1,
                    "state": "complete",
                    "result_state": "CREATED",
                    "parameters_sha256": worktree_ensure._sha256_json(inputs),
                    "idempotency_key_sha256": "b" * 64,
                    "inputs": {k: v for k, v in inputs.items() if k != "idempotency_key"},
                    "post_state": {},
                    "lease": {},
                    "lifecycle": {
                        "automatic_cleanup_authorized": True,
                        "terminal_decision": "retain",
                    },
                    "error_class": None,
                    "error": "",
                    "friction": None,
                    "friction_closeout": None,
                    "created_at_unix": 1,
                    "updated_at_unix": 1,
                },
            )

        with self.assertRaisesRegex(
            worktree_ensure.WorktreeEnsureAction,
            "cleanup authority",
        ):
            self._ensure(parameters)

    def test_receipt_lock_symlink_is_rejected_without_touching_target(self) -> None:
        parameters = self._parameters(key="symlink-lock")
        victim = self.root / "victim.txt"
        victim.write_text("unchanged\n", encoding="utf-8")
        with patch.dict(
            os.environ,
            {"GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT": str(self.receipt_root)},
        ):
            self.receipt_root.mkdir(mode=0o700)
            _receipt_path, lock_path = worktree_ensure._receipt_paths(parameters["idempotency_key"])
            lock_path.symlink_to(victim)
            with self.assertRaises(worktree_ensure.WorktreeEnsureAction):
                worktree_ensure.ensure_worktree(
                    parameters,
                    grips._default_command_runner,
                    self._lease,
                )

        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")
        self.assertFalse(Path(parameters["target_path"]).exists())

    def test_known_git_rejection_returns_not_accepted(self) -> None:
        parameters = self._parameters(key="rejected", target=self.worktree_root / "rejected")

        def rejecting_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            if argv[:3] == ["worktree", "add", "-b"]:
                return {"returncode": 128, "stdout": "", "stderr": "simulated rejection"}
            return grips._default_command_runner(repo, argv)

        result = self._ensure(parameters, runner=rejecting_runner)

        self.assertEqual(result["result_state"], "NOT_ACCEPTED")
        self.assertEqual(result["error_class"], "GIT_WORKTREE_ADD_REJECTED")
        self.assertFalse(Path(parameters["target_path"]).exists())
        common_dir = checkouts._git_common_dir(self.repo)
        checkout_key = checkouts._checkout_key(
            common_dir, Path(str(parameters["target_path"]))
        )
        self.assertEqual(checkouts._lifecycle_bindings([checkout_key]), {})
        self.assertEqual(len(self.friction_events), 1)

    def test_partial_conflict_preserves_lifecycle_binding(self) -> None:
        parameters = self._parameters(
            key="partial-conflict",
            branch="feat/partial-conflict",
            target=self.worktree_root / "partial-conflict",
        )

        def dirtying_runner(repo: Path, argv: list[str]) -> dict[str, object]:
            result = grips._default_command_runner(repo, argv)
            if argv[:3] == ["worktree", "add", "-b"] and result["returncode"] == 0:
                target = Path(str(parameters["target_path"]))
                (target / "untracked.txt").write_text("partial\n", encoding="utf-8")
            return result

        result = self._ensure(parameters, runner=dirtying_runner)

        self.assertEqual(result["result_state"], "CONFLICT")
        self.assertEqual(result["error_class"], "POST_MUTATION_CONFLICT")
        self.assertTrue(Path(str(parameters["target_path"])).is_dir())
        reservation = result["lifecycle_reservation"]
        self.assertTrue(reservation["preserved"])
        self.assertFalse(reservation["released"])
        binding = reservation["binding"]
        self.assertEqual(binding["phase"], "active")
        self.assertEqual(binding["source"]["id"], "STORAGE-LIFECYCLE-V1-T003")
        self.assertIn(
            binding["checkout_key"],
            checkouts._lifecycle_bindings([binding["checkout_key"]]),
        )

    def test_surface_dispatches_successful_worktree_ensure_receipt(self) -> None:
        parameters = self._parameters(key="surface-success")
        output = {
            "receipt_status": "passed",
            "result_state": "CREATED",
            "durable_receipt_path": str(self.receipt_root / "surface.json"),
            "durable_receipt_sha256": "a" * 64,
            "post_state": {"matches_requested_state": True},
        }
        friction_module = types.ModuleType("grabowski_friction")
        friction_module.record_friction_event = lambda **_kwargs: {}
        friction_module.resolve_friction = lambda **_kwargs: {}
        resources_module = types.ModuleType("grabowski_resources")
        resources_module.inspect_resource = lambda _resource_key: {}
        with patch.dict(
            sys.modules,
            {
                "grabowski_friction": friction_module,
                "grabowski_resources": resources_module,
            },
        ), patch.object(worktree_ensure, "ensure_worktree", return_value=output) as ensure_mock:
            result = grips.grip_run(
                "worktree-ensure",
                parameters,
                profile="operator",
                allow_mutation=True,
            )

        self.assertEqual(result["receipt"]["status"], "passed")
        self.assertEqual(result["output"]["result_state"], "CREATED")
        self.assertEqual(ensure_mock.call_count, 1)
        check_ids = {item["id"] for item in result["receipt"]["checks"]}
        self.assertIn("worktree_ensure_result", check_ids)
        self.assertIn("durable_receipt", check_ids)

    def test_surface_requires_mutation_permission(self) -> None:
        result = grips.grip_run(
            "worktree-ensure",
            self._parameters(key="permission"),
            profile="operator",
            allow_mutation=False,
        )

        self.assertEqual(result["receipt"]["status"], "blocked")
        self.assertEqual(result["output"]["blocked_reasons"], ["mutation_permission_missing"])
        contract = next(
            item for item in grips.grip_list("operator")["grips"]
            if item["name"] == "worktree-ensure"
        )
        self.assertTrue(contract["availability"]["available"])
        self.assertTrue(contract["availability"]["requires_allow_mutation"])


if __name__ == "__main__":
    unittest.main()
