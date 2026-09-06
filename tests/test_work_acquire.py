from __future__ import annotations

import inspect
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_execution_plan as execution_plan
import grabowski_lane_closeout as closeout
import grabowski_work_acquire as work_acquire

SHA = "a" * 40


class WorkAcquireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.target = self.root / "lane-worktree"
        self.state = self.root / "state"
        self.retention = int(time.time()) + 3600
        self.previous = os.environ.get("GRABOWSKI_WORK_LANE_ROOT")
        os.environ["GRABOWSKI_WORK_LANE_ROOT"] = str(self.state)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self.previous is None:
            os.environ.pop("GRABOWSKI_WORK_LANE_ROOT", None)
        else:
            os.environ["GRABOWSKI_WORK_LANE_ROOT"] = self.previous

    def parameters(self) -> dict[str, object]:
        return {
            "source_kind": "direct",
            "source_id": "chat:authority-p0",
            "controller_actor": "chatgpt:controller",
            "scoped_writer_actor": "agent:writer",
            "repo": str(self.repo),
            "base_head": SHA,
            "branch": "feat/authority-p0",
            "target_path": str(self.target),
            "purpose": "direct user implementation lane",
            "retention_until_unix": self.retention,
            "idempotency_key": "authority-p0",
            "resource_keys": [],
            "ttl_seconds": 1200,
        }

    def execution_plan(self, *, source_id: str = "chat:authority-p0", write_scope: list[str] | None = None) -> dict[str, object]:
        scope = ["src/app.py"] if write_scope is None else list(write_scope)
        route_body = {
            "schema_version": 2,
            "routing_contract_version": execution_plan.ROUTING_CONTRACT_VERSION,
            "executor": "scoped_writer",
            "writer_route": "codex-sol-high",
            "effect_profile": "candidate",
            "verification_policy": "deterministic",
            "task_class": "complex-patch",
            "risk": {"flags": [], "novelty": "medium", "critical_task_class": False},
        }
        route = {
            **route_body,
            "recommendation_sha256": execution_plan.sha256_json(route_body),
        }
        nodes = [
            {
                "node_id": "writer",
                "kind": "scoped_writer",
                "critical": True,
                "mutates": True,
                "write_scope": scope,
            }
        ]
        return execution_plan.build_execution_plan(
            source_binding={"kind": "direct", "id": source_id},
            route_decision=route,
            topology="direct",
            nodes=nodes,
            edges=[],
            write_scope=scope,
            verification_policy="deterministic",
            failure_policy={
                "on_indeterminate": "block",
                "on_unknown_effect": "reconcile",
                "revision": "bounded",
            },
            budgets={
                "max_revisions": 1,
                "max_duration_seconds": 1200,
                "max_tool_calls": 50,
            },
            completion_policy={
                "required_nodes": ["writer"],
                "require_all_critical": True,
                "verifier_quorum": 0,
            },
        )

    def store_lane(self, params: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        lane_id = str(inputs["lane_id"])
        work_acquire._private_directory(self.state)
        receipt = work_acquire._write_state(
            self.state / f"{lane_id}.json",
            {
                "kind": work_acquire.LANE_KIND,
                "schema_version": work_acquire.SCHEMA_VERSION,
                "lane_id": lane_id,
                "inputs_sha256": work_acquire._sha(inputs),
                "inputs": inputs,
                "state": "ready",
            },
        )
        return inputs, receipt

    def isolation_admission(self) -> dict[str, object]:
        scope = {
            "target_path": str(self.target),
            "branch": "feat/authority-p0",
        }
        signal = {
            "code": "unrelated-dirty-worktree",
            "path": str(self.root / "foreign-worktree"),
        }
        evidence_material = {
            "schema_version": 1,
            "kind": "grabowski.repository_work_isolation_evidence",
            "scope_identity": scope,
            "signals": [signal],
            "signal_codes": ["unrelated-dirty-worktree"],
            "nonconflict_verified": True,
            "does_not_establish": [
                "mutation authority",
                "cleanup authority over unrelated work",
                "absence of later semantic or merge conflicts",
            ],
        }
        evidence = {
            **evidence_material,
            "evidence_sha256": work_acquire.work_admission._digest(
                evidence_material
            ),
        }
        material = {
            "decision": "isolate_and_execute",
            "scope_mode": "exact_checkout",
            "scope_identity": scope,
            "blockers": [],
            "blocker_codes": [],
            "isolation_signals": [signal],
            "isolation_evidence": evidence,
        }
        return {
            **material,
            "assessment_sha256": work_acquire.work_admission._digest(material),
        }

    @staticmethod
    def acquired(
        owner: str,
        keys: list[str],
        *,
        preserved: list[str] | None = None,
        bureau_contract: dict[str, object] | None = None,
    ) -> dict[str, object]:
        now = int(time.time())
        leases = [
            {
                "resource_key": key,
                "owner_id": owner,
                "purpose": "direct user implementation lane",
                "acquired_at_unix": now,
                "updated_at_unix": now,
                "expires_at_unix": now + 1200,
                "metadata_sha256": "d" * 64,
                "reclaimed_from_owner": None,
            }
            for key in keys
        ]
        return {
            "owner_id": owner,
            "leases": leases,
            "preserved": list(preserved or []),
            "reclaimed": [],
            "bureau_contract": bureau_contract,
        }

    @staticmethod
    def released(
        owner: str, expected_leases: list[dict[str, object]]
    ) -> dict[str, object]:
        return {
            "owner_id": owner,
            "force": False,
            "snapshot_guarded": True,
            "released": [
                {
                    **snapshot,
                    "purpose": "direct user implementation lane",
                    "reclaimed_from_owner": None,
                }
                for snapshot in expected_leases
            ],
        }

    def release(
        self,
        owner: str,
        keys: list[str],
        *,
        expected_leases: list[dict[str, object]],
    ) -> dict[str, object]:
        self.assertEqual(
            keys, [str(snapshot["resource_key"]) for snapshot in expected_leases]
        )
        return self.released(owner, expected_leases)

    @staticmethod
    def bureau_path_resources(keys: list[str]) -> list[str]:
        return sorted(key for key in keys if key.startswith("path:"))

    def acquire(self, owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
        return self.acquired(owner, keys)

    def test_public_work_acquire_signature_does_not_change_in_p4(self) -> None:
        parameters = inspect.signature(work_acquire.grabowski_work_acquire).parameters
        self.assertIsNone(parameters["scoped_writer_runtime_seconds"].default)
        self.assertEqual(
            list(parameters),
            [
                "source_kind",
                "source_id",
                "controller_actor",
                "repo",
                "base_head",
                "branch",
                "target_path",
                "purpose",
                "retention_until_unix",
                "idempotency_key",
                "resource_keys",
                "write_paths",
                "scoped_writer_actor",
                "scoped_writer_argv",
                "scoped_writer_runtime_seconds",
                "system_convergence",
                "artifact_class",
                "ttl_seconds",
                "terminal_closeout",
            ],
        )

    def test_execution_plan_is_validated_source_scope_and_lane_identity_bound(self) -> None:
        legacy = work_acquire._normalize(self.parameters())
        params = self.parameters()
        params["write_paths"] = [str(self.repo / "src/app.py")]
        params["execution_plan"] = self.execution_plan()
        planned = work_acquire._normalize(params)
        self.assertEqual(planned["execution_plan"], params["execution_plan"])
        self.assertNotEqual(planned["lane_id"], legacy["lane_id"])
        self.assertIn(f"path:{self.repo / 'src/app.py'}", planned["resource_keys"])

    def test_execution_plan_none_preserves_legacy_lane_identity(self) -> None:
        first = work_acquire._normalize(self.parameters())
        params = self.parameters()
        params["execution_plan"] = None
        second = work_acquire._normalize(params)
        self.assertEqual(first["lane_id"], second["lane_id"])
        self.assertNotIn("execution_plan", first)
        self.assertNotIn("execution_plan", second)

    def test_execution_plan_rejects_source_or_write_scope_drift(self) -> None:
        params = self.parameters()
        params["write_paths"] = ["src/app.py"]
        params["execution_plan"] = self.execution_plan(source_id="other-source")
        with self.assertRaisesRegex(ValueError, "source binding"):
            work_acquire._normalize(params)

        params["execution_plan"] = self.execution_plan(write_scope=["src/other.py"] )
        with self.assertRaisesRegex(ValueError, "write scope"):
            work_acquire._normalize(params)

    def test_execution_plan_rejects_route_decision_tamper_before_lane_identity(self) -> None:
        params = self.parameters()
        params["write_paths"] = ["src/app.py"]
        plan = self.execution_plan()
        plan["route_binding"]["decision"]["writer_route"] = "forged-route"
        params["execution_plan"] = plan
        with self.assertRaisesRegex(ValueError, "execution_plan is invalid"):
            work_acquire._normalize(params)

    def test_invalid_execution_plan_blocks_before_resource_or_worktree_effect(self) -> None:
        params = self.parameters()
        params["write_paths"] = ["src/app.py"]
        params["execution_plan"] = self.execution_plan(source_id="wrong-source")
        acquire = Mock()
        ensure = Mock()
        with self.assertRaisesRegex(ValueError, "source binding"):
            work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_acquires_narrow_resources_and_returns_ready_lane(self) -> None:
        seen: dict[str, object] = {}
        acquire_calls = 0

        def acquire(owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
            nonlocal acquire_calls
            acquire_calls += 1
            seen.update(owner=owner, keys=keys, kwargs=kwargs)
            return self.acquired(owner, keys)
        ensure = Mock(return_value={
            "result_state": "CREATED",
            "durable_receipt_sha256": "b" * 64,
            "post_state": {"target_registered": True, "target_path_exists": True},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=acquire,
            release_resources_fn=Mock(), inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["decision"], "AUTO_PREPARE_AND_EXECUTE")
        self.assertEqual(result["authority"]["scoped_writer"]["role"], "scoped_writer")
        self.assertEqual(acquire_calls, 1)
        self.assertIn(f"path:{self.target}", seen["keys"])
        self.assertIn(f"repo:{self.repo}:branch:feat/authority-p0", seen["keys"])
        self.assertNotIn(f"repo:{self.repo}", seen["keys"])
        self.assertEqual(
            result["inputs"]["system_convergence_plan"]["status"], "unclassified"
        )
        ensure.assert_called_once()
        ensure_parameters = ensure.call_args.args[0]
        self.assertNotIn("reposkop_required", ensure_parameters)
        self.assertIsNone(ensure_parameters["system_convergence"])
        self.assertEqual(ensure_parameters["source_kind"], "work_lane")
        self.assertEqual(ensure_parameters["source_id"], result["lane_id"])
        self.assertEqual(result["inputs"]["source"], {"kind": "direct", "id": "chat:authority-p0"})
        self.assertEqual(result["lifecycle_source"], {"kind": "work_lane", "id": result["lane_id"]})
        self.assertEqual(result["authority"]["lifecycle_source"], result["lifecycle_source"])
        self.assertEqual(
            ensure_parameters["system_convergence_plan_sha256"],
            result["inputs"]["system_convergence_plan"]["plan_sha256"],
        )

    def test_declared_write_path_uses_narrow_path_and_branch_leases(self) -> None:
        seen: dict[str, object] = {}

        def acquire(owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
            seen["keys"] = list(keys)
            return self.acquired(owner, keys)

        params = self.parameters()
        params["write_paths"] = ["src/app.py"]
        ensure = Mock(return_value={
            "result_state": "CREATED",
            "durable_receipt_sha256": "b" * 64,
            "post_state": {"target_registered": True, "target_path_exists": True},
        })

        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )

        self.assertEqual("ready", result["state"])
        keys = seen["keys"]
        self.assertIn(f"path:{self.repo / 'src' / 'app.py'}", keys)
        self.assertIn(f"repo:{self.repo}:branch:feat/authority-p0", keys)
        self.assertNotIn(f"repo:{self.repo}", keys)

    def test_verified_isolation_promotes_lane_decision(self) -> None:
        admission = self.isolation_admission()
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
                "work_admission": admission,
            }
        )
        result = work_acquire.acquire_work(
            self.parameters(),
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["decision"], "ISOLATE_AND_EXECUTE")
        self.assertEqual(result["worktree_receipt"]["work_admission"], admission)

    def test_tampered_isolation_never_promotes_lane_decision(self) -> None:
        admission = self.isolation_admission()
        admission["isolation_evidence"] = {
            **admission["isolation_evidence"],
            "nonconflict_verified": False,
        }
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
                "work_admission": admission,
            }
        )
        result = work_acquire.acquire_work(
            self.parameters(),
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        self.assertEqual(result["decision"], "AUTO_PREPARE_AND_EXECUTE")

    def test_bureau_path_and_branch_use_same_owner_separate_contract_groups(self) -> None:
        calls: list[dict[str, object]] = []
        events: list[str] = []

        def acquire(
            owner: str, keys: list[str], **kwargs: object
        ) -> dict[str, object]:
            contract_group = "bureau" if self.bureau_path_resources(keys) else "standard"
            events.append(f"acquire:{contract_group}")
            calls.append(
                {
                    "owner": owner,
                    "keys": list(keys),
                    "kwargs": dict(kwargs),
                    "contract_group": contract_group,
                }
            )
            return self.acquired(
                owner,
                keys,
                bureau_contract=(
                    {"phase": "work", "resource_keys": list(keys)}
                    if contract_group == "bureau"
                    else None
                ),
            )

        def ensure(*_args: object) -> dict[str, object]:
            events.append("ensure")
            return {
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
            }

        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            result = work_acquire.acquire_work(
                self.parameters(),
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )

        self.assertEqual(events, ["acquire:bureau", "acquire:standard", "ensure"])
        self.assertEqual(result["state"], "ready")
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            {str(call["owner"]) for call in calls},
            {result["inputs"]["lease_owner_id"]},
        )
        self.assertTrue(all(str(key).startswith("path:") for key in calls[0]["keys"]))
        self.assertEqual(
            calls[1]["keys"],
            [f"repo:{self.repo}:branch:feat/authority-p0"],
        )
        first_kwargs = calls[0]["kwargs"]
        second_kwargs = calls[1]["kwargs"]
        self.assertEqual(first_kwargs, second_kwargs)
        self.assertEqual(first_kwargs["purpose"], self.parameters()["purpose"])
        self.assertEqual(first_kwargs["ttl_seconds"], 1200)
        metadata = first_kwargs["metadata"]
        self.assertEqual(metadata["lane_id"], result["lane_id"])
        self.assertEqual(metadata["branch"], "feat/authority-p0")
        groups = result["lease_acquisition_groups"]
        self.assertEqual(
            [group["contract_group"] for group in groups],
            ["bureau", "standard"],
        )
        self.assertEqual(groups[0]["receipt"]["bureau_contract"]["phase"], "work")
        self.assertIsNone(groups[1]["receipt"]["bureau_contract"])
        self.assertEqual(
            result["lease_receipt"]["kind"],
            "grabowski.work_lane.lease_bundle",
        )

    def test_second_contract_group_failure_compensates_first_exactly(self) -> None:
        first_receipt: dict[str, object] = {}
        release = Mock(side_effect=self.release)
        ensure = Mock()

        def acquire(
            owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            nonlocal first_receipt
            if self.bureau_path_resources(keys):
                first_receipt = self.acquired(
                    owner,
                    keys,
                    bureau_contract={"phase": "work", "resource_keys": list(keys)},
                )
                return first_receipt
            raise work_acquire.resources.ResourceConflict(
                keys[0], "foreign-owner", int(time.time()) + 1200
            )

        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            result = work_acquire.acquire_work(
                self.parameters(),
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["acquisition"]["contract_group"], "standard")
        ensure.assert_not_called()
        release.assert_called_once()
        expected = release.call_args.kwargs["expected_leases"]
        self.assertEqual(
            expected,
            [
                {
                    key: lease[key]
                    for key in sorted(work_acquire.resources.LEASE_SNAPSHOT_KEYS)
                }
                for lease in first_receipt["leases"]
            ],
        )
        self.assertEqual(
            release.call_args.args[0], result["inputs"]["lease_owner_id"]
        )
        self.assertEqual(result["compensation"]["state"], "complete")

    def test_worktree_rejection_compensates_split_groups_in_reverse_order(self) -> None:
        acquired_receipts: dict[str, dict[str, object]] = {}
        release_calls: list[tuple[str, list[str], list[dict[str, object]]]] = []

        def acquire(
            owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            contract_group = "bureau" if self.bureau_path_resources(keys) else "standard"
            receipt = self.acquired(
                owner,
                keys,
                bureau_contract=(
                    {"phase": "work", "resource_keys": list(keys)}
                    if contract_group == "bureau"
                    else None
                ),
            )
            acquired_receipts[contract_group] = receipt
            return receipt

        def release(
            owner: str,
            keys: list[str],
            *,
            expected_leases: list[dict[str, object]],
        ) -> dict[str, object]:
            release_calls.append((owner, list(keys), expected_leases))
            return self.release(owner, keys, expected_leases=expected_leases)

        ensure = Mock(
            return_value={
                "result_state": "NOT_ACCEPTED",
                "post_state": {
                    "target_registered": False,
                    "target_path_exists": False,
                    "branch_ref_head": None,
                },
            }
        )
        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            result = work_acquire.acquire_work(
                self.parameters(),
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(
            [keys for _owner, keys, _expected in release_calls],
            [
                [
                    lease["resource_key"]
                    for lease in acquired_receipts["standard"]["leases"]
                ],
                [
                    lease["resource_key"]
                    for lease in acquired_receipts["bureau"]["leases"]
                ],
            ],
        )
        self.assertEqual(
            [group["contract_group"] for group in result["compensation"]["released_groups"]],
            ["standard", "bureau"],
        )

    def test_compensation_unknown_hard_blocks_and_replay_has_no_effects(self) -> None:
        acquire = Mock()
        ensure = Mock()
        release = Mock(side_effect=RuntimeError("Resource lease changed before release"))

        def acquire_group(
            owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            if self.bureau_path_resources(keys):
                return self.acquired(
                    owner,
                    keys,
                    bureau_contract={"phase": "work", "resource_keys": list(keys)},
                )
            raise work_acquire.resources.ResourceConflict(
                keys[0], "foreign-owner", int(time.time()) + 1200
            )

        acquire.side_effect = acquire_group
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": release,
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
        }
        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            first = work_acquire.acquire_work(self.parameters(), **kwargs)
            second = work_acquire.acquire_work(self.parameters(), **kwargs)

        self.assertEqual(first["state"], "outcome_unknown")
        self.assertEqual(first["decision"], "HARD_BLOCK")
        self.assertEqual(first["compensation"]["state"], "outcome_unknown")
        self.assertEqual(
            first["next_action"], "reconcile_lease_compensation_before_retry"
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(acquire.call_count, 2)
        self.assertEqual(release.call_count, 1)
        ensure.assert_not_called()

    def test_ambiguous_later_acquisition_compensates_known_group_then_blocks(self) -> None:
        acquire = Mock()
        release = Mock(side_effect=self.release)
        ensure = Mock()

        def acquire_group(
            owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            if self.bureau_path_resources(keys):
                return self.acquired(
                    owner,
                    keys,
                    bureau_contract={"phase": "work", "resource_keys": list(keys)},
                )
            raise RuntimeError("acquisition response lost")

        acquire.side_effect = acquire_group
        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            result = work_acquire.acquire_work(
                self.parameters(),
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )

        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["acquisition"]["state"], "outcome_unknown")
        self.assertEqual(result["compensation"]["state"], "complete")
        release.assert_called_once()
        ensure.assert_not_called()

    def test_preserved_same_owner_group_is_not_released_on_later_failure(self) -> None:
        release = Mock()
        ensure = Mock()

        def acquire(
            owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            if self.bureau_path_resources(keys):
                return self.acquired(
                    owner,
                    keys,
                    preserved=list(keys),
                    bureau_contract={"phase": "work", "resource_keys": list(keys)},
                )
            raise work_acquire.resources.ResourceConflict(
                keys[0], "foreign-owner", int(time.time()) + 1200
            )

        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            result = work_acquire.acquire_work(
                self.parameters(),
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )

        self.assertEqual(result["state"], "blocked")
        release.assert_not_called()
        ensure.assert_not_called()
        self.assertEqual(
            result["compensation"]["preserved_resource_keys"],
            result["acquisition_plan"][0]["resource_keys"],
        )

    def test_foreign_acquisition_snapshot_is_not_released_or_retried(self) -> None:
        acquire = Mock()
        release = Mock()
        ensure = Mock()

        def acquire_group(
            _owner: str, keys: list[str], **_kwargs: object
        ) -> dict[str, object]:
            return self.acquired(
                "foreign-owner",
                keys,
                bureau_contract={"phase": "work", "resource_keys": list(keys)},
            )

        acquire.side_effect = acquire_group
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": release,
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
        }
        with patch.object(
            work_acquire.resources.bureau_leases,
            "bureau_resource_keys",
            side_effect=self.bureau_path_resources,
        ):
            first = work_acquire.acquire_work(self.parameters(), **kwargs)
            second = work_acquire.acquire_work(self.parameters(), **kwargs)

        self.assertEqual(first["state"], "outcome_unknown")
        self.assertEqual(first["error_class"], "LeaseAcquisitionOutcomeUnknown")
        self.assertTrue(second["replayed"])
        self.assertEqual(acquire.call_count, 1)
        release.assert_not_called()
        ensure.assert_not_called()

    def test_incomplete_resource_effect_receipt_does_not_retry_effect(self) -> None:
        for incomplete_state in ("acquiring", "compensating"):
            with self.subTest(incomplete_state=incomplete_state):
                params = self.parameters()
                params["idempotency_key"] = f"incomplete-{incomplete_state}"
                inputs = work_acquire._normalize(params)
                inputs.pop("_scoped_writer_argv")
                work_acquire._private_directory(self.state)
                work_acquire._write_state(
                    self.state / f"{inputs['lane_id']}.json",
                    {
                        "kind": work_acquire.LANE_KIND,
                        "schema_version": work_acquire.SCHEMA_VERSION,
                        "lane_id": inputs["lane_id"],
                        "inputs_sha256": work_acquire._sha(inputs),
                        "inputs": inputs,
                        "attempt_count": 1,
                        "created_at_unix": int(time.time()),
                        "updated_at_unix": int(time.time()),
                        "state": incomplete_state,
                    },
                )
                acquire = Mock()
                release = Mock()
                ensure = Mock()
                result = work_acquire.acquire_work(
                    params,
                    acquire_resources_fn=acquire,
                    release_resources_fn=release,
                    inspect_resource_fn=Mock(),
                    ensure_worktree_fn=ensure,
                    runner=Mock(),
                )
                self.assertEqual(result["state"], "outcome_unknown")
                self.assertEqual(result["decision"], "HARD_BLOCK")
                self.assertTrue(result["replayed"])
                acquire.assert_not_called()
                release.assert_not_called()
                ensure.assert_not_called()


    def test_legacy_direct_user_source_uses_lane_lifecycle_evidence(self) -> None:
        params = self.parameters()
        params["source_kind"] = "direct-user"
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {"target_registered": True, "target_path_exists": True},
            }
        )
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        ensure_parameters = ensure.call_args.args[0]
        self.assertEqual(result["inputs"]["source"]["kind"], "direct-user")
        self.assertEqual(ensure_parameters["source_kind"], "work_lane")
        self.assertEqual(ensure_parameters["source_id"], result["lane_id"])

    def test_invalid_operator_obligation_source_is_rejected_before_effects(self) -> None:
        params = self.parameters()
        params["source_kind"] = "operator_obligation"
        params["source_id"] = "metarepo-local-mcp-single-lockfile-v1-20260822"
        acquire = Mock()
        ensure = Mock()
        with self.assertRaisesRegex(
            ValueError, "source_id for operator_obligation must match goo-"
        ):
            work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_historical_invalid_operator_obligation_outcome_unknown_still_replays(self) -> None:
        params = self.parameters()
        params["source_kind"] = "operator_obligation"
        params["source_id"] = "metarepo-local-mcp-single-lockfile-v1-20260822"
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        lane_id = str(inputs["lane_id"])
        with work_acquire._lane_lock(lane_id) as receipt_path:
            work_acquire._write_state(
                receipt_path,
                {
                    "kind": work_acquire.LANE_KIND,
                    "schema_version": work_acquire.SCHEMA_VERSION,
                    "lane_id": lane_id,
                    "inputs_sha256": work_acquire._sha(inputs),
                    "inputs": inputs,
                    "state": "outcome_unknown",
                    "decision": "HARD_BLOCK",
                    "attempt_count": 1,
                    "created_at_unix": int(time.time()),
                    "updated_at_unix": int(time.time()),
                },
            )
        acquire = Mock()
        ensure = Mock()
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        self.assertTrue(result["replayed"])
        self.assertEqual(result["state"], "outcome_unknown")
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_historical_invalid_operator_obligation_ready_lane_cannot_resume_effects(self) -> None:
        params = self.parameters()
        params["source_kind"] = "operator_obligation"
        params["source_id"] = "metarepo-local-mcp-single-lockfile-v1-20260822"
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        lane_id = str(inputs["lane_id"])
        with work_acquire._lane_lock(lane_id) as receipt_path:
            work_acquire._write_state(
                receipt_path,
                {
                    "kind": work_acquire.LANE_KIND,
                    "schema_version": work_acquire.SCHEMA_VERSION,
                    "lane_id": lane_id,
                    "inputs_sha256": work_acquire._sha(inputs),
                    "inputs": inputs,
                    "state": "ready",
                    "decision": "ISOLATE_AND_EXECUTE",
                    "attempt_count": 1,
                    "created_at_unix": int(time.time()),
                    "updated_at_unix": int(time.time()),
                },
            )
        acquire = Mock()
        ensure = Mock()
        with self.assertRaisesRegex(RuntimeError, "cannot resume effectful execution"):
            work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_existing_evidence_source_remains_checkout_lifecycle_source(self) -> None:
        params = self.parameters()
        params["source_kind"] = "operator_obligation"
        params["source_id"] = "goo-agent-fabric-existing"
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {"target_registered": True, "target_path_exists": True},
            }
        )
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        ensure_parameters = ensure.call_args.args[0]
        self.assertEqual(
            result["lifecycle_source"],
            {"kind": "operator_obligation", "id": "goo-agent-fabric-existing"},
        )
        self.assertEqual(ensure_parameters["source_kind"], "operator_obligation")
        self.assertEqual(ensure_parameters["source_id"], "goo-agent-fabric-existing")

    def test_supplied_system_convergence_plan_is_bound_into_lane_identity(self) -> None:
        planned = {
            "schema_version": 1,
            "kind": "grabowski.system_convergence_plan",
            "status": "planned",
            "systemic_closure_gate": "hard",
            "hard_gate_required": True,
            "admission_blocking": False,
            "plan_sha256": "f" * 64,
        }
        params = self.parameters()
        context = {
            "change_risk": "R2",
            "target_criticality": "essential",
            "expected_protocol_head": "d" * 40,
        }
        params["system_convergence"] = context
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
            }
        )
        with patch.object(
            work_acquire.work_admission,
            "plan_system_convergence",
            return_value=planned,
        ) as planner:
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=self.acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
            )
        planner.assert_called_once_with(context)
        self.assertEqual(result["inputs"]["system_convergence"], context)
        self.assertEqual(result["inputs"]["system_convergence_plan"], planned)
        ensure_parameters = ensure.call_args.args[0]
        self.assertEqual(ensure_parameters["system_convergence"], context)
        self.assertEqual(
            ensure_parameters["system_convergence_plan_sha256"], "f" * 64
        )
        self.assertEqual(result["decision"], "AUTO_PREPARE_AND_EXECUTE")

    def test_write_paths_become_exact_repo_path_resources(self) -> None:
        seen: dict[str, object] = {}

        def acquire(owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
            seen.update(owner=owner, keys=keys, kwargs=kwargs)
            return self.acquired(owner, keys)

        params = self.parameters()
        params["write_paths"] = [
            "src/feature.py",
            str(self.repo / "tests" / "test_feature.py"),
        ]
        work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
        )
        self.assertIn(f"path:{self.repo / 'src' / 'feature.py'}", seen["keys"])
        self.assertIn(
            f"path:{self.repo / 'tests' / 'test_feature.py'}", seen["keys"]
        )
        self.assertNotIn(f"repo:{self.repo}", seen["keys"])

    @staticmethod
    def writer_result(target: Path) -> dict[str, object]:
        return {
            "job_id": "job-123",
            "unit": "grabowski-job-123456789abc",
            "owner": "job:grabowski-job-123456789abc",
            "argv_sha256": "e" * 64,
            "cwd": str(target),
            "runtime_seconds": 600,
            "metadata_path": "/tmp/job/metadata.json",
            "expected_receipt": {
                "finalization_path": "/tmp/job/finalization.json"
            },
            "final_status": "launch_submitted",
        }

    def test_optional_scoped_writer_starts_and_binds_durable_job(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=start,
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["next_action"], "writer_started")
        self.assertEqual(
            result["writer_job"]["unit"], "grabowski-job-123456789abc"
        )
        self.assertEqual(result["writer_start"]["state"], "started")
        self.assertNotIn("scoped_writer_argv", result["inputs"])
        start.assert_called_once_with(
            ["writer", "--once"], cwd=str(self.target), runtime_seconds=600
        )

    def test_identical_writer_replay_renews_lane_without_second_job(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        acquire = Mock(side_effect=self.acquire)
        ensure = Mock(
            side_effect=[
                {
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                },
                {
                    "result_state": "ALREADY_CORRECT",
                    "durable_receipt_sha256": "c" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                },
            ]
        )
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": Mock(),
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
            "start_writer_fn": start,
        }
        first = work_acquire.acquire_work(params, **kwargs)
        second = work_acquire.acquire_work(params, **kwargs)
        self.assertEqual(first["writer_job"], second["writer_job"])
        self.assertEqual(second["writer_start"]["state"], "reused")
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)
        self.assertEqual(acquire.call_count, 2)
        self.assertEqual(ensure.call_count, 2)

    def test_writer_binding_survives_reacquire_block(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        first = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=start,
        )
        second = work_acquire.acquire_work(
            params,
            acquire_resources_fn=Mock(
                side_effect=work_acquire.resources.ResourceConflict(
                    f"path:{self.target}",
                    "foreign-owner",
                    int(time.time()) + 1200,
                )
            ),
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(),
            runner=Mock(),
            start_writer_fn=Mock(),
        )
        self.assertEqual(second["state"], "blocked")
        self.assertEqual(second["writer_job"], first["writer_job"])
        self.assertEqual(second["writer_start"]["state"], "started")
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)

    def test_writer_preflight_failure_falls_back_to_controller(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        release = Mock()
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=release,
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=Mock(
                side_effect=work_acquire.ScopedWriterStartPreflight("bad command")
            ),
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["next_action"], "controller_execute")
        self.assertEqual(result["writer_start"]["state"], "preflight_failed")
        release.assert_not_called()

    def test_unknown_writer_start_is_preserved_and_not_blindly_retried(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        release = Mock()
        acquire = Mock(side_effect=self.acquire)
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
            }
        )
        start = Mock(side_effect=RuntimeError("lost writer launch response"))
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": release,
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
            "start_writer_fn": start,
        }
        first = work_acquire.acquire_work(params, **kwargs)
        second = work_acquire.acquire_work(params, **kwargs)
        self.assertEqual(first["state"], "outcome_unknown")
        self.assertEqual(
            first["next_action"], "readback_scoped_writer_before_retry"
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)
        self.assertEqual(acquire.call_count, 1)
        self.assertEqual(ensure.call_count, 1)
        release.assert_not_called()

    def test_writer_starting_crash_window_fails_closed_without_second_launch(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        self.state.mkdir(mode=0o700)
        receipt_path = self.state / f"{inputs['lane_id']}.json"
        work_acquire._write_state(
            receipt_path,
            {
                "kind": work_acquire.LANE_KIND,
                "schema_version": work_acquire.SCHEMA_VERSION,
                "lane_id": inputs["lane_id"],
                "inputs_sha256": work_acquire._sha(inputs),
                "inputs": inputs,
                "attempt_count": 1,
                "created_at_unix": int(time.time()),
                "updated_at_unix": int(time.time()),
                "state": "writer_starting",
                "decision": "EXECUTE",
                "writer_start": {"state": "starting"},
                "next_action": "start_scoped_writer",
            },
        )
        acquire = Mock()
        ensure = Mock()
        start = Mock()
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
            start_writer_fn=start,
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["decision"], "HARD_BLOCK")
        self.assertEqual(
            result["next_action"], "readback_scoped_writer_before_retry"
        )
        self.assertEqual(result["writer_start"]["state"], "outcome_unknown")
        self.assertTrue(result["replayed"])
        acquire.assert_not_called()
        ensure.assert_not_called()
        start.assert_not_called()

    def test_scoped_writer_argv_requires_scoped_writer_actor(self) -> None:
        params = self.parameters()
        params["scoped_writer_actor"] = None
        params["scoped_writer_argv"] = ["writer"]
        with self.assertRaisesRegex(ValueError, "requires scoped_writer_actor"):
            work_acquire.acquire_work(params)

    def test_identical_retry_reuses_lane_identity(self) -> None:
        ensure = Mock(return_value={
            "result_state": "ALREADY_CORRECT",
            "durable_receipt_sha256": "c" * 64,
            "post_state": {"target_registered": True, "target_path_exists": True},
        })
        params = self.parameters()
        first = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=ensure, runner=Mock(),
        )
        second = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(first["lane_id"], second["lane_id"])
        self.assertTrue(second["replayed"])
        self.assertEqual(second["attempt_count"], 2)

    def test_pre_effect_failure_releases_exact_acquired_leases(self) -> None:
        release = Mock(side_effect=self.release)
        ensure = Mock(return_value={
            "result_state": "NOT_ACCEPTED",
            "post_state": {"target_registered": False, "target_path_exists": False, "branch_ref_head": None},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["decision"], "AUTO_PREPARE_FAILED")
        release.assert_called_once()
        self.assertIsInstance(release.call_args.kwargs["expected_leases"], list)

    def test_preexisting_conflict_is_compensated(self) -> None:
        release = Mock(side_effect=self.release)
        ensure = Mock(return_value={
            "result_state": "CONFLICT",
            "post_state": {"target_registered": True, "target_path_exists": True, "branch_ref_head": SHA},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertFalse(result["mutation_attempted"])
        release.assert_called_once()

    def test_post_mutation_conflict_preserves_leases_for_reconciliation(self) -> None:
        release = Mock()
        ensure = Mock(return_value={
            "result_state": "CONFLICT",
            "mutation": {"returncode": 1},
            "post_state": {"target_registered": True, "target_path_exists": True, "branch_ref_head": SHA},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["decision"], "HARD_BLOCK")
        release.assert_not_called()

    def test_exception_after_lease_acquisition_preserves_for_reconciliation(self) -> None:
        acquire = Mock(side_effect=self.acquire)
        release = Mock()
        ensure = Mock(side_effect=RuntimeError("lost response"))
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": release,
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
        }
        first = work_acquire.acquire_work(self.parameters(), **kwargs)
        second = work_acquire.acquire_work(self.parameters(), **kwargs)
        self.assertEqual(first["state"], "outcome_unknown")
        self.assertIsNone(first["effect_observed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(acquire.call_count, 1)
        self.assertEqual(ensure.call_count, 1)
        release.assert_not_called()

    def test_preflight_exception_after_lease_acquisition_is_compensated(self) -> None:
        release = Mock(side_effect=self.release)
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                side_effect=work_acquire.worktree_ensure.WorktreeEnsurePreflight(
                    "invalid branch"
                )
            ),
            runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["decision"], "AUTO_PREPARE_FAILED")
        self.assertFalse(result["effect_observed"])
        release.assert_called_once()
        expected_leases = release.call_args.kwargs["expected_leases"]
        self.assertIsInstance(expected_leases, list)
        self.assertTrue(expected_leases)
        self.assertEqual(
            set(expected_leases[0]),
            work_acquire.resources.LEASE_SNAPSHOT_KEYS,
        )

    def test_non_object_result_is_durable_outcome_unknown(self) -> None:
        release = Mock()
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(return_value=None), runner=Mock(),
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["error_class"], "InvalidWorktreeEnsureResult")
        release.assert_not_called()


    def terminal_assessment(
        self,
        lane_id: str,
        observed_at: int,
        *,
        lease_active: bool = True,
    ) -> dict[str, object]:
        return closeout.assess(closeout.LaneCloseoutObservation(
            lane_id=lane_id, repository=str(self.repo), workspace=str(self.target),
            branch="feat/authority-p0", base_revision=SHA, writer_state="completed",
            task_active=False, process_active=False, lease_active=lease_active, git_dirty=False,
            head_sha=SHA, remote_head_sha=SHA, ahead_commits=0, behind_commits=0,
            no_change_proven=True,
        ), observed_at_unix=observed_at)

    def test_terminal_assessment_replay_hash_preserves_legacy_equivalence(self) -> None:
        assessment = self.terminal_assessment("a" * 32, 200)
        legacy = dict(assessment)
        legacy.pop("terminal_head_sha")
        material = {
            key: value
            for key, value in legacy.items()
            if key not in {"assessment_sha256", "audit_record_sha256", "does_not_establish"}
        }
        legacy["assessment_sha256"] = closeout.sha256_json(material)
        self.assertEqual(
            work_acquire._terminal_assessment_replay_sha256(assessment),
            work_acquire._terminal_assessment_replay_sha256(legacy),
        )

    def test_terminal_checkout_lifecycle_convergence_preserves_blocked_followup_capacity(self) -> None:
        inspect = Mock()
        with patch.object(work_acquire.checkouts, "_worktree_for_path", inspect):
            result = work_acquire._converge_terminal_checkout_lifecycle(
                {},
                assessment={
                    "phase": "terminal",
                    "lease_release_ready": False,
                    "terminal_head_sha": SHA,
                },
            )
        self.assertIsNone(result)
        inspect.assert_not_called()

    def test_terminal_checkout_lifecycle_convergence_releases_active_capacity_only(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        checkout_key = "c" * 64
        lifecycle = {
            "checkout_key": checkout_key,
            "checkout_path": str(self.target),
            "owner_id": inputs["lease_owner_id"],
            "expected_branch": "feat/authority-p0",
        }
        record = {
            "inputs": inputs,
            "worktree_receipt": {"lifecycle": lifecycle},
        }
        observed = {
            "checkout_key": checkout_key,
            "head": SHA,
            "branch": "feat/authority-p0",
        }
        completed = {
            **lifecycle,
            "phase": "completed_retained",
            "expected_head": SHA,
        }
        with (
            patch.object(
                work_acquire.checkouts,
                "_worktree_for_path",
                return_value=(self.repo, self.repo / ".git", observed),
            ),
            patch.object(
                work_acquire.checkouts,
                "_require_clean_linked",
                return_value={"dirty": False},
            ) as clean,
            patch.object(
                work_acquire.checkouts,
                "_mark_checkout_completed_retained",
                return_value=completed,
            ) as mark,
        ):
            result = work_acquire._converge_terminal_checkout_lifecycle(
                record,
                assessment={
                    "phase": "terminal",
                    "lease_release_ready": True,
                    "terminal_head_sha": SHA,
                },
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["state"], "completed_retained")
        self.assertTrue(result["active_capacity_released"])
        self.assertTrue(result["retention_preserved"])
        clean.assert_called_once_with(observed)
        mark.assert_called_once_with(
            checkout_key=checkout_key,
            owner_id=inputs["lease_owner_id"],
            expected_head=SHA,
            expected_branch="feat/authority-p0",
        )

    def test_terminal_checkout_lifecycle_convergence_rejects_new_dirty_state(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        checkout_key = "e" * 64
        record = {
            "inputs": inputs,
            "worktree_receipt": {
                "lifecycle": {
                    "checkout_key": checkout_key,
                    "checkout_path": str(self.target),
                    "owner_id": inputs["lease_owner_id"],
                    "expected_branch": "feat/authority-p0",
                }
            },
        }
        observed = {
            "checkout_key": checkout_key,
            "head": SHA,
            "branch": "feat/authority-p0",
        }
        with (
            patch.object(
                work_acquire.checkouts,
                "_worktree_for_path",
                return_value=(self.repo, self.repo / ".git", observed),
            ),
            patch.object(
                work_acquire.checkouts,
                "_require_clean_linked",
                side_effect=RuntimeError("Checkout must be clean before archival or cleanup"),
            ),
            patch.object(
                work_acquire.checkouts, "_mark_checkout_completed_retained"
            ) as mark,
        ):
            with self.assertRaisesRegex(RuntimeError, "Checkout must be clean"):
                work_acquire._converge_terminal_checkout_lifecycle(
                    record,
                    assessment={
                        "phase": "terminal",
                        "lease_release_ready": True,
                        "terminal_head_sha": SHA,
                    },
                )
        mark.assert_not_called()

    def test_terminal_checkout_lifecycle_convergence_rejects_head_drift(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        checkout_key = "d" * 64
        record = {
            "inputs": inputs,
            "worktree_receipt": {
                "lifecycle": {
                    "checkout_key": checkout_key,
                    "checkout_path": str(self.target),
                    "owner_id": inputs["lease_owner_id"],
                    "expected_branch": "feat/authority-p0",
                }
            },
        }
        observed = {
            "checkout_key": checkout_key,
            "head": "b" * 40,
            "branch": "feat/authority-p0",
        }
        with (
            patch.object(
                work_acquire.checkouts,
                "_worktree_for_path",
                return_value=(self.repo, self.repo / ".git", observed),
            ),
            patch.object(
                work_acquire.checkouts,
                "_require_clean_linked",
                return_value={"dirty": False},
            ) as clean,
            patch.object(
                work_acquire.checkouts, "_mark_checkout_completed_retained"
            ) as mark,
        ):
            with self.assertRaisesRegex(RuntimeError, "HEAD precondition failed"):
                work_acquire._converge_terminal_checkout_lifecycle(
                    record,
                    assessment={
                        "phase": "terminal",
                        "lease_release_ready": True,
                        "terminal_head_sha": SHA,
                    },
                )
        clean.assert_called_once_with(observed)
        mark.assert_not_called()

    def test_terminal_closeout_lifecycle_failure_keeps_receipt_retryable(self) -> None:
        params = self.parameters()
        _, receipt = self.store_lane(params)
        lane_id = str(receipt["lane_id"])
        assessment = self.terminal_assessment(lane_id, 200)
        before = work_acquire._read_state(
            self.state / f"{lane_id}.json"
        )
        self.assertIsNotNone(before)
        with patch.object(
            work_acquire,
            "_converge_terminal_checkout_lifecycle",
            side_effect=RuntimeError("lifecycle temporarily unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "lifecycle temporarily unavailable"):
                work_acquire.persist_terminal_closeout(
                    lane_id,
                    assessment,
                    expected_receipt_sha256=str(receipt["receipt_sha256"]),
                )
        after = work_acquire._read_state(self.state / f"{lane_id}.json")
        self.assertIsNotNone(after)
        assert after is not None
        self.assertNotIn("terminal_closeout", after)
        self.assertIn("terminal_closeout_pending", after)
        self.assertEqual(
            after["terminal_closeout_pending"]["expected_receipt_sha256"],
            receipt["receipt_sha256"],
        )
        self.assertNotEqual(after["receipt_sha256"], receipt["receipt_sha256"])

        acquire = Mock()
        ensure = Mock()
        replay = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        self.assertTrue(replay["replayed"])
        self.assertTrue(replay["closeout_pending"])
        self.assertEqual(replay["decision"], "TERMINAL_CLOSEOUT_PENDING")
        self.assertEqual(replay["next_action"], "retry_terminal_closeout")
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_candidate_adopted_defers_resource_release_until_publication_closeout(self) -> None:
        params = self.parameters()
        inputs, receipt = self.store_lane(params)
        lane_id = str(inputs["lane_id"])
        owner_id = str(inputs["lease_owner_id"])
        assessment = closeout.assess(
            closeout.LaneCloseoutObservation(
                lane_id=lane_id,
                repository=str(self.repo),
                workspace=str(self.target),
                branch="feat/authority-p0",
                base_revision=SHA,
                writer_state="completed",
                task_active=False,
                process_active=False,
                lease_active=True,
                git_dirty=False,
                head_sha=SHA,
                candidate_id="c" * 64,
                adoption_receipt_sha256="d" * 64,
                adoption_commit_sha=SHA,
            ),
            observed_at_unix=200,
        )
        self.assertEqual("candidate_adopted", assessment["closeout_state"])
        self.assertTrue(assessment["lease_release_ready"])

        with (
            patch.object(work_acquire.resources, "list_resources") as listing,
            patch.object(work_acquire.resources, "count_resources") as counting,
            patch.object(work_acquire.resources, "grabowski_resource_release") as release,
        ):
            stored = work_acquire.persist_terminal_closeout(
                lane_id,
                assessment,
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
            )
        self.assertIn("terminal_closeout", stored)
        self.assertNotIn("resource_lease_closeout", stored)
        listing.assert_not_called()
        counting.assert_not_called()
        release.assert_not_called()

        late_key = "operation:publication-after-adoption"
        late_lease = self.acquired(owner_id, [late_key])["leases"][0]
        snapshot = work_acquire._lease_snapshot(late_lease, owner_id=owner_id)
        with (
            patch.object(
                work_acquire.resources,
                "list_resources",
                side_effect=[[late_lease], []],
            ),
            patch.object(
                work_acquire.resources,
                "count_resources",
                side_effect=[1, 0],
            ),
            patch.object(
                work_acquire.resources,
                "grabowski_resource_release",
                return_value=self.released(owner_id, [snapshot]),
            ) as release,
        ):
            converged = work_acquire.converge_terminal_resource_closeout(
                lane_id, expected_closeout_states={"candidate_adopted"}
            )
        self.assertEqual("released", converged["state"])
        self.assertEqual(0, converged["live_owner_lease_count"])
        self.assertEqual([late_key], converged["released_resource_keys"])
        release.assert_called_once_with(
            owner_id, [late_key], force=False, expected_leases=[snapshot]
        )

    def test_terminal_resource_convergence_releases_all_current_owner_generations(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        owner_id = str(inputs["lease_owner_id"])
        registered_keys = list(inputs["resource_keys"])
        own_key = registered_keys[0]
        late_key = "operation:terminal-late-deploy"
        own_lease = self.acquired(owner_id, [own_key])["leases"][0]
        late_lease = self.acquired(owner_id, [late_key])["leases"][0]
        own_snapshot = work_acquire._lease_snapshot(own_lease, owner_id=owner_id)
        late_snapshot = work_acquire._lease_snapshot(late_lease, owner_id=owner_id)
        expected_snapshots = sorted(
            [own_snapshot, late_snapshot], key=lambda item: item["resource_key"]
        )
        release = Mock(
            return_value=self.released(owner_id, expected_snapshots)
        )
        record = {"lane_id": inputs["lane_id"], "inputs": inputs}

        with (
            patch.object(
                work_acquire.resources,
                "list_resources",
                side_effect=[[own_lease, late_lease], []],
            ) as listing,
            patch.object(
                work_acquire.resources,
                "count_resources",
                side_effect=[2, 0],
            ) as counting,
            patch.object(work_acquire.resources, "grabowski_resource_release", release),
        ):
            result = work_acquire._converge_terminal_resource_leases(
                record,
                assessment={"phase": "terminal", "lease_release_ready": True},
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["state"], "released")
        self.assertEqual(
            result["released_resource_keys"],
            [snapshot["resource_key"] for snapshot in expected_snapshots],
        )
        self.assertEqual(
            result["registered_resource_key_count"], len(registered_keys)
        )
        self.assertEqual(result["live_owner_lease_count"], 0)
        self.assertEqual(listing.call_count, 2)
        self.assertEqual(counting.call_count, 2)
        for call in listing.call_args_list:
            self.assertEqual(call.kwargs["owner_id"], owner_id)
            self.assertFalse(call.kwargs["include_expired"])
        release.assert_called_once_with(
            owner_id,
            [snapshot["resource_key"] for snapshot in expected_snapshots],
            force=False,
            expected_leases=expected_snapshots,
        )

    def test_terminal_resource_convergence_batches_more_than_64_owner_leases(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        owner_id = str(inputs["lease_owner_id"])
        leases = self.acquired(
            owner_id, [f"operation:batch-{index:02d}" for index in range(65)]
        )["leases"]
        snapshots = sorted(
            [work_acquire._lease_snapshot(lease, owner_id=owner_id) for lease in leases],
            key=lambda item: item["resource_key"],
        )
        first, second = snapshots[:64], snapshots[64:]
        release = Mock(
            side_effect=[
                self.released(owner_id, first),
                self.released(owner_id, second),
            ]
        )
        record = {"lane_id": inputs["lane_id"], "inputs": inputs}
        remaining_lease = next(
            lease
            for lease in leases
            if lease["resource_key"] == second[0]["resource_key"]
        )

        with (
            patch.object(
                work_acquire.resources,
                "list_resources",
                side_effect=[leases, [remaining_lease], []],
            ),
            patch.object(
                work_acquire.resources,
                "count_resources",
                side_effect=[65, 1, 0],
            ),
            patch.object(work_acquire.resources, "grabowski_resource_release", release),
        ):
            result = work_acquire._converge_terminal_resource_leases(
                record,
                assessment={"phase": "terminal", "lease_release_ready": True},
            )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual("released", result["state"])
        self.assertEqual(2, result["release_batch_count"])
        self.assertEqual(65, len(result["released_resource_keys"]))
        self.assertEqual(2, release.call_count)
        self.assertEqual(64, len(release.call_args_list[0].args[1]))
        self.assertEqual(1, len(release.call_args_list[1].args[1]))
        self.assertFalse(release.call_args_list[0].kwargs["force"])
        self.assertFalse(release.call_args_list[1].kwargs["force"])
        self.assertEqual(first, release.call_args_list[0].kwargs["expected_leases"])
        self.assertEqual(second, release.call_args_list[1].kwargs["expected_leases"])

    def test_terminal_resource_convergence_stops_between_batches_on_owner_drift(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        owner_id = str(inputs["lease_owner_id"])
        leases = self.acquired(
            owner_id, [f"operation:drift-{index:02d}" for index in range(65)]
        )["leases"]
        snapshots = sorted(
            [work_acquire._lease_snapshot(lease, owner_id=owner_id) for lease in leases],
            key=lambda item: item["resource_key"],
        )
        first = snapshots[:64]
        late = self.acquired(owner_id, ["operation:drift-late"])["leases"][0]
        remaining_lease = next(
            lease
            for lease in leases
            if lease["resource_key"] == snapshots[64]["resource_key"]
        )
        events: list[str] = []

        def release_batch(*args: object, **kwargs: object) -> dict[str, object]:
            events.append("audited-release")
            return self.released(owner_id, first)

        def list_owner_leases(*_args: object, **_kwargs: object) -> list[dict[str, object]]:
            events.append("observe")
            return leases if events.count("observe") == 1 else [remaining_lease, late]

        release = Mock(side_effect=release_batch)
        record = {"lane_id": inputs["lane_id"], "inputs": inputs}

        with (
            patch.object(
                work_acquire.resources,
                "list_resources",
                side_effect=list_owner_leases,
            ),
            patch.object(
                work_acquire.resources,
                "count_resources",
                side_effect=[65, 2],
            ),
            patch.object(work_acquire.resources, "grabowski_resource_release", release),
            self.assertRaisesRegex(
                work_acquire.TerminalLeaseConvergenceError,
                "inventory drifted during batched release",
            ),
        ):
            work_acquire._converge_terminal_resource_leases(
                record,
                assessment={"phase": "terminal", "lease_release_ready": True},
            )

        self.assertEqual(1, release.call_count)
        self.assertEqual(64, len(release.call_args.args[1]))
        self.assertFalse(release.call_args.kwargs["force"])
        self.assertEqual(["observe", "audited-release", "observe"], events)

    def test_terminal_owner_lease_observation_fails_closed_when_bounded_view_is_incomplete(self) -> None:
        params = self.parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        owner_id = str(inputs["lease_owner_id"])
        lease = self.acquired(owner_id, [inputs["resource_keys"][0]])["leases"][0]
        record = {"lane_id": inputs["lane_id"], "inputs": inputs}
        with (
            patch.object(
                work_acquire.resources, "list_resources", return_value=[lease]
            ),
            patch.object(
                work_acquire.resources, "count_resources", return_value=2
            ),
            self.assertRaisesRegex(
                work_acquire.TerminalLeaseConvergenceError,
                "changed or exceeds bounded view",
            ),
        ):
            work_acquire._terminal_lane_resource_observation(record)

    def test_terminal_resource_generation_drift_keeps_pending_and_blocks_reacquire(self) -> None:
        params = self.parameters()
        inputs, receipt = self.store_lane(params)
        lane_id = str(inputs["lane_id"])
        owner_id = str(inputs["lease_owner_id"])
        leases = self.acquired(owner_id, list(inputs["resource_keys"]))["leases"]
        assessment = self.terminal_assessment(lane_id, 200)

        with (
            patch.object(
                work_acquire.resources,
                "list_resources",
                return_value=leases,
            ),
            patch.object(
                work_acquire.resources,
                "count_resources",
                return_value=len(leases),
            ),
            patch.object(
                work_acquire.resources,
                "grabowski_resource_release",
                side_effect=RuntimeError("Resource lease changed before release"),
            ),
            self.assertRaisesRegex(RuntimeError, "changed before release"),
        ):
            work_acquire.persist_terminal_closeout(
                lane_id,
                assessment,
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
            )

        pending = work_acquire._read_state(self.state / f"{lane_id}.json")
        self.assertIsNotNone(pending)
        assert pending is not None
        self.assertIn("terminal_closeout_pending", pending)
        self.assertNotIn("terminal_closeout", pending)

        acquire = Mock()
        ensure = Mock()
        replay = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
        )
        self.assertTrue(replay["closeout_pending"])
        acquire.assert_not_called()
        ensure.assert_not_called()

        with self.assertRaisesRegex(RuntimeError, "current durable pending receipt"):
            work_acquire.persist_terminal_closeout(
                lane_id,
                self.terminal_assessment(lane_id, 201),
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
            )

        with (
            patch.object(work_acquire.resources, "list_resources", return_value=[]),
            patch.object(work_acquire.resources, "count_resources", return_value=0),
        ):
            recovered = work_acquire.persist_terminal_closeout(
                lane_id,
                self.terminal_assessment(
                    lane_id, 201, lease_active=False
                ),
                expected_receipt_sha256=str(pending["receipt_sha256"]),
            )
        self.assertTrue(recovered["replayed"])
        self.assertNotEqual(
            pending["terminal_closeout_pending"]["assessment"]["observation_sha256"],
            recovered["terminal_closeout"]["assessment"]["observation_sha256"],
        )
        self.assertNotIn("terminal_closeout_pending", recovered)
        self.assertIn("terminal_closeout", recovered)
        self.assertEqual(
            recovered["resource_lease_closeout"]["state"], "already_absent"
        )
        self.assertEqual(
            201, recovered["terminal_closeout"]["assessment"]["observed_at_unix"]
        )

    def test_terminal_closeout_replay_retries_checkout_lifecycle_convergence(self) -> None:
        params = self.parameters()
        _, receipt = self.store_lane(params)
        lane_id = str(receipt["lane_id"])
        assessment = self.terminal_assessment(lane_id, 200)
        lifecycle = {
            "state": "completed_retained",
            "active_capacity_released": True,
            "retention_preserved": True,
        }
        with patch.object(
            work_acquire,
            "_converge_terminal_checkout_lifecycle",
            return_value=lifecycle,
        ) as converge:
            first = work_acquire.persist_terminal_closeout(
                lane_id,
                assessment,
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
            )
            replay = work_acquire.persist_terminal_closeout(
                lane_id,
                self.terminal_assessment(lane_id, 201),
                expected_receipt_sha256=str(receipt["receipt_sha256"]),
            )
        self.assertEqual(first["checkout_lifecycle_closeout"], lifecycle)
        self.assertEqual(replay["checkout_lifecycle_closeout"], lifecycle)
        self.assertTrue(replay["replayed"])
        self.assertEqual(converge.call_count, 2)
        self.assertEqual(
            converge.call_args_list[0].kwargs["assessment"]["terminal_head_sha"], SHA
        )
        self.assertEqual(
            converge.call_args_list[1].kwargs["assessment"]["terminal_head_sha"], SHA
        )

    def test_terminal_closeout_is_durable_idempotent_and_stops_reacquire(self) -> None:
        params = self.parameters()
        first = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=Mock(return_value={
                "result_state": "CREATED", "durable_receipt_sha256": "b" * 64,
                "post_state": {"target_registered": True, "target_path_exists": True},
            }), runner=Mock(),
        )
        assessment = self.terminal_assessment(first["lane_id"], 200)
        audit_records: dict[str, str] = {}

        def append_audit(event: dict[str, object]) -> str:
            digest = "a" * 64
            audit_records[str(event["terminal_transition_sha256"])] = digest
            return digest

        def lookup_audit(event: dict[str, object]) -> str | None:
            return audit_records.get(str(event["terminal_transition_sha256"]))

        audit = Mock(side_effect=append_audit)
        lookup = Mock(side_effect=lookup_audit)
        stored = work_acquire.persist_terminal_closeout(
            first["lane_id"], assessment,
            expected_receipt_sha256=first["receipt_sha256"],
            audit_fn=audit, audit_lookup_fn=lookup,
        )
        self.assertFalse(stored["replayed"])
        self.assertEqual(stored["terminal_closeout"]["assessment_sha256"], assessment["assessment_sha256"])
        audit.assert_called_once()
        audit_record = audit.call_args.args[0]
        self.assertEqual(audit_record["operation"], "work-lane-terminal-closeout")
        self.assertEqual(audit_record["lane_id"], first["lane_id"])
        self.assertEqual(audit_record["assessment_sha256"], assessment["assessment_sha256"])
        self.assertEqual(audit_record["receipt_sha256"], stored["receipt_sha256"])
        self.assertEqual(audit_record["expected_receipt_sha256"], first["receipt_sha256"])
        self.assertRegex(audit_record["terminal_transition_sha256"], r"[0-9a-f]{64}\Z")
        self.assertEqual(stored["terminal_closeout_audit_record_sha256"], "a" * 64)
        self.assertTrue(work_acquire.persist_terminal_closeout(
            first["lane_id"], assessment,
            expected_receipt_sha256=first["receipt_sha256"],
            audit_fn=audit, audit_lookup_fn=lookup,
        )["replayed"])
        audit.assert_called_once()
        later_same_observation = self.terminal_assessment(first["lane_id"], 201)
        self.assertNotEqual(
            assessment["assessment_sha256"], later_same_observation["assessment_sha256"]
        )
        self.assertTrue(work_acquire.persist_terminal_closeout(
            first["lane_id"], later_same_observation,
            expected_receipt_sha256=first["receipt_sha256"],
            audit_fn=audit, audit_lookup_fn=lookup,
        )["replayed"])
        audit.assert_called_once()
        competing = closeout.assess(closeout.LaneCloseoutObservation(
            lane_id=first["lane_id"], repository=str(self.repo), workspace=str(self.target),
            branch="feat/authority-p0", base_revision=SHA, writer_state="completed",
            task_active=False, process_active=False, lease_active=True, git_dirty=False,
            head_sha=SHA, remote_head_sha=SHA, ahead_commits=0, behind_commits=0,
            durable_followup_id="followup-1",
        ), observed_at_unix=202)
        self.assertEqual(competing["closeout_state"], "blocked_with_durable_followup")
        with self.assertRaisesRegex(RuntimeError, "another terminal assessment"):
            work_acquire.persist_terminal_closeout(
                first["lane_id"], competing, expected_receipt_sha256=stored["receipt_sha256"]
            )
        acquire = Mock()
        ensure = Mock()
        replay = work_acquire.acquire_work(
            params, acquire_resources_fn=acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertTrue(replay["replayed"])
        acquire.assert_not_called()
        ensure.assert_not_called()

    def test_terminal_closeout_retry_recovers_missing_audit_after_receipt_write(self) -> None:
        params = self.parameters()
        first = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=Mock(return_value={
                "result_state": "CREATED", "durable_receipt_sha256": "b" * 64,
                "post_state": {"target_registered": True, "target_path_exists": True},
            }), runner=Mock(),
        )
        assessment = self.terminal_assessment(first["lane_id"], 200)
        audit_records: dict[str, str] = {}
        attempts = 0

        def append_audit(event: dict[str, object]) -> str:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("audit unavailable")
            digest = "b" * 64
            audit_records[str(event["terminal_transition_sha256"])] = digest
            return digest

        def lookup_audit(event: dict[str, object]) -> str | None:
            return audit_records.get(str(event["terminal_transition_sha256"]))

        with self.assertRaisesRegex(OSError, "audit unavailable"):
            work_acquire.persist_terminal_closeout(
                first["lane_id"], assessment,
                expected_receipt_sha256=first["receipt_sha256"],
                audit_fn=append_audit, audit_lookup_fn=lookup_audit,
            )
        durable = work_acquire._read_state(self.state / f"{first['lane_id']}.json")
        self.assertIsNotNone(durable)
        assert durable is not None
        self.assertEqual(
            durable["terminal_closeout"]["expected_receipt_sha256"],
            first["receipt_sha256"],
        )
        recovered = work_acquire.persist_terminal_closeout(
            first["lane_id"], self.terminal_assessment(first["lane_id"], 201),
            expected_receipt_sha256=first["receipt_sha256"],
            audit_fn=append_audit, audit_lookup_fn=lookup_audit,
        )
        self.assertTrue(recovered["replayed"])
        self.assertEqual(recovered["terminal_closeout_audit_record_sha256"], "b" * 64)
        replayed = work_acquire.persist_terminal_closeout(
            first["lane_id"], self.terminal_assessment(first["lane_id"], 202),
            expected_receipt_sha256=first["receipt_sha256"],
            audit_fn=append_audit, audit_lookup_fn=lookup_audit,
        )
        self.assertTrue(replayed["replayed"])
        self.assertEqual(replayed["terminal_closeout_audit_record_sha256"], "b" * 64)
        self.assertEqual(attempts, 2)

    def test_terminal_closeout_rejects_stale_receipt_preimage(self) -> None:
        lane_id = "d" * 32
        self.state.mkdir(mode=0o700)
        work_acquire._write_state(self.state / f"{lane_id}.json", {
            "kind": work_acquire.LANE_KIND, "schema_version": work_acquire.SCHEMA_VERSION,
            "lane_id": lane_id, "state": "ready",
        })
        with self.assertRaisesRegex(RuntimeError, "CAS preimage changed"):
            work_acquire.persist_terminal_closeout(
                lane_id, self.terminal_assessment(lane_id, 202), expected_receipt_sha256="e" * 64
            )

    def test_mcp_entry_routes_terminal_closeout_after_original_retention_expires(self) -> None:
        params = self.parameters()
        params["retention_until_unix"] = 100
        with patch.object(work_acquire.checkouts, "_now", return_value=50):
            stored_inputs, receipt = self.store_lane(params)
        lane_id = str(stored_inputs["lane_id"])
        expected = {"lane_id": lane_id, "replayed": False}
        terminal = self.terminal_assessment(lane_id, 200)
        with (
            patch.object(work_acquire.operator, "_require_operator_mutation"),
            patch.object(work_acquire.checkouts, "_now", return_value=200),
            patch.object(work_acquire.lane_closeout, "assess", return_value=terminal),
            patch.object(work_acquire, "persist_terminal_closeout", return_value=expected) as persist,
            patch.object(work_acquire, "acquire_work") as acquire,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                scoped_writer_actor=str(params["scoped_writer_actor"]),
                ttl_seconds=int(params["ttl_seconds"]),
                terminal_closeout={
                    "expected_receipt_sha256": str(receipt["receipt_sha256"]),
                    "observation": {
                        "lane_id": lane_id, "repository": str(self.repo),
                        "workspace": str(self.target), "branch": "feat/authority-p0",
                        "base_revision": SHA, "writer_state": "completed",
                        "task_active": False, "process_active": False, "lease_active": True,
                        "git_dirty": False, "head_sha": SHA, "remote_head_sha": SHA,
                        "ahead_commits": 0, "behind_commits": 0, "no_change_proven": True,
                    },
                },
            )
        self.assertEqual(expected, result)
        self.assertEqual(persist.call_args.args[0], lane_id)
        self.assertEqual(persist.call_args.args[1]["terminal_head_sha"], SHA)
        self.assertNotIn("terminal_head_sha", persist.call_args.kwargs)
        acquire.assert_not_called()

    def test_mcp_entry_reuses_stored_system_convergence_plan_on_closeout(self) -> None:
        params = self.parameters()
        params["system_convergence"] = {"system_id": "example"}
        stored_plan = {"status": "unavailable", "plan_sha256": "1" * 64}
        with patch.object(
            work_acquire.work_admission,
            "plan_system_convergence",
            return_value=stored_plan,
        ):
            stored_inputs = work_acquire._normalize(params)
        stored_inputs.pop("_scoped_writer_argv")
        lane_id = str(stored_inputs["lane_id"])
        work_acquire._private_directory(self.state)
        receipt = work_acquire._write_state(
            self.state / f"{lane_id}.json",
            {
                "kind": work_acquire.LANE_KIND,
                "schema_version": work_acquire.SCHEMA_VERSION,
                "lane_id": lane_id,
                "inputs_sha256": work_acquire._sha(stored_inputs),
                "inputs": stored_inputs,
                "state": "ready",
            },
        )
        expected = {"lane_id": lane_id, "replayed": False}
        terminal = {"lane_id": lane_id, "phase": "terminal"}
        with (
            patch.object(work_acquire.operator, "_require_operator_mutation"),
            patch.object(
                work_acquire.work_admission,
                "plan_system_convergence",
                side_effect=AssertionError("terminal closeout must not re-plan convergence"),
            ) as planner,
            patch.object(work_acquire.lane_closeout, "assess", return_value=terminal),
            patch.object(
                work_acquire, "persist_terminal_closeout", return_value=expected
            ) as persist,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                scoped_writer_actor=str(params["scoped_writer_actor"]),
                system_convergence=dict(params["system_convergence"]),
                ttl_seconds=int(params["ttl_seconds"]),
                terminal_closeout={
                    "expected_receipt_sha256": receipt["receipt_sha256"],
                    "observation": {
                        "lane_id": lane_id,
                        "repository": str(self.repo),
                        "workspace": str(self.target),
                        "branch": "feat/authority-p0",
                        "base_revision": SHA,
                        "writer_state": "completed",
                        "task_active": False,
                        "process_active": False,
                        "lease_active": True,
                        "git_dirty": False,
                        "head_sha": SHA,
                        "remote_head_sha": SHA,
                        "ahead_commits": 0,
                        "behind_commits": 0,
                        "no_change_proven": True,
                    },
                },
            )
        self.assertEqual(expected, result)
        planner.assert_not_called()
        self.assertEqual(persist.call_args.args[0], lane_id)

    def test_mcp_entry_reuses_stored_path_identity_after_symlink_drift(self) -> None:
        params = self.parameters()
        first = self.repo / "first.py"
        second = self.repo / "second.py"
        first.write_text("first\n")
        second.write_text("second\n")
        link = self.repo / "current.py"
        link.symlink_to(first.name)
        params["write_paths"] = [link.name]
        stored_inputs, receipt = self.store_lane(params)
        lane_id = str(stored_inputs["lane_id"])
        self.assertIn(f"path:{first}", stored_inputs["resource_keys"])
        link.unlink()
        link.symlink_to(second.name)
        expected = {"lane_id": lane_id, "replayed": False}
        terminal = {"lane_id": lane_id, "phase": "terminal"}
        with (
            patch.object(work_acquire.operator, "_require_operator_mutation"),
            patch.object(
                work_acquire.work_admission,
                "plan_system_convergence",
                side_effect=AssertionError("terminal closeout must not normalize live identity"),
            ) as planner,
            patch.object(work_acquire.lane_closeout, "assess", return_value=terminal),
            patch.object(
                work_acquire, "persist_terminal_closeout", return_value=expected
            ) as persist,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                scoped_writer_actor=str(params["scoped_writer_actor"]),
                write_paths=list(params["write_paths"]),
                ttl_seconds=int(params["ttl_seconds"]),
                terminal_closeout={
                    "expected_receipt_sha256": str(receipt["receipt_sha256"]),
                    "observation": {
                        "lane_id": lane_id,
                        "repository": str(self.repo),
                        "workspace": str(self.target),
                        "branch": "feat/authority-p0",
                        "base_revision": SHA,
                        "writer_state": "completed",
                        "task_active": False,
                        "process_active": False,
                        "lease_active": True,
                        "git_dirty": False,
                        "head_sha": SHA,
                        "remote_head_sha": SHA,
                        "ahead_commits": 0,
                        "behind_commits": 0,
                        "no_change_proven": True,
                    },
                },
            )
        self.assertEqual(expected, result)
        planner.assert_not_called()
        self.assertEqual(persist.call_args.args[0], lane_id)
        self.assertNotIn(f"path:{second}", stored_inputs["resource_keys"])

    def test_mcp_entry_rejects_terminal_closeout_identity_mismatch(self) -> None:
        params = self.parameters()
        stored_inputs, _receipt = self.store_lane(params)
        lane_id = str(stored_inputs["lane_id"])
        observation = {
            "lane_id": lane_id,
            "repository": str(self.repo),
            "workspace": str(self.target),
            "branch": "feat/authority-p0",
            "base_revision": SHA,
            "writer_state": "completed",
            "task_active": False,
            "process_active": False,
            "lease_active": True,
            "git_dirty": False,
            "head_sha": SHA,
            "remote_head_sha": SHA,
            "ahead_commits": 0,
            "behind_commits": 0,
            "no_change_proven": True,
        }
        mismatches = {
            "repository": str(self.repo.parent / "other-repo"),
            "workspace": str(self.target.parent / "other-workspace"),
            "branch": "feat/other-lane",
            "base_revision": "b" * 40,
        }
        for field, value in mismatches.items():
            with self.subTest(field=field):
                assess = Mock()
                persist = Mock()
                with (
                    patch.object(work_acquire.operator, "_require_operator_mutation"),
                    patch.object(work_acquire.lane_closeout, "assess", assess),
                    patch.object(work_acquire, "persist_terminal_closeout", persist),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "terminal closeout observation identity does not match work lane inputs",
                    ),
                ):
                    work_acquire.grabowski_work_acquire(
                        source_kind=str(params["source_kind"]),
                        source_id=str(params["source_id"]),
                        controller_actor=str(params["controller_actor"]),
                        repo=str(params["repo"]),
                        base_head=str(params["base_head"]),
                        branch=str(params["branch"]),
                        target_path=str(params["target_path"]),
                        purpose=str(params["purpose"]),
                        retention_until_unix=int(params["retention_until_unix"]),
                        idempotency_key=str(params["idempotency_key"]),
                        scoped_writer_actor=str(params["scoped_writer_actor"]),
                        ttl_seconds=int(params["ttl_seconds"]),
                        terminal_closeout={
                            "expected_receipt_sha256": "e" * 64,
                            "observation": {**observation, field: value},
                        },
                    )
                assess.assert_not_called()
                persist.assert_not_called()

    def test_mcp_entry_routes_terminal_closeout_without_reacquiring(self) -> None:
        params = self.parameters()
        stored_inputs, receipt = self.store_lane(params)
        lane_id = str(stored_inputs["lane_id"])
        expected = {"lane_id": lane_id, "replayed": False}
        with (
            patch.object(
                work_acquire.operator, "_require_operator_mutation"
            ) as require_mutation,
            patch.object(work_acquire.operator, "_require_operator_capability") as capability,
            patch.object(work_acquire.lane_closeout, "assess", return_value={
                "lane_id": lane_id, "phase": "terminal"
            }),
            patch.object(work_acquire, "persist_terminal_closeout", return_value=expected) as persist,
            patch.object(work_acquire, "acquire_work") as acquire,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                scoped_writer_actor=str(params["scoped_writer_actor"]),
                ttl_seconds=int(params["ttl_seconds"]),
                terminal_closeout={
                    "expected_receipt_sha256": str(receipt["receipt_sha256"]),
                    "observation": {
                        "lane_id": lane_id, "repository": str(self.repo),
                        "workspace": str(self.target), "branch": "feat/authority-p0",
                        "base_revision": SHA, "writer_state": "completed",
                        "task_active": False, "process_active": False, "lease_active": True,
                        "git_dirty": False, "head_sha": SHA, "remote_head_sha": SHA,
                        "ahead_commits": 0, "behind_commits": 0, "no_change_proven": True,
                    },
                },
            )
        self.assertEqual(expected, result)
        acquire.assert_not_called()
        capability.assert_not_called()
        require_mutation.assert_called_once_with(
            "resource_lease", path=str(self.target), repo=str(self.repo)
        )
        self.assertEqual(persist.call_args.args[0], lane_id)
        self.assertEqual(
            persist.call_args.kwargs["expected_receipt_sha256"],
            receipt["receipt_sha256"],
        )
        self.assertIs(
            persist.call_args.kwargs["audit_fn"],
            work_acquire.operator.base._append_audit_with_digest,
        )
        self.assertIs(
            persist.call_args.kwargs["audit_lookup_fn"],
            work_acquire._find_terminal_closeout_audit,
        )

    def test_mcp_entry_binds_audit_to_runtime_base(self) -> None:
        params = self.parameters()
        expected = {"state": "ready", "decision": "EXECUTE"}
        with (
            patch.object(work_acquire.operator, "_require_operator_mutation"),
            patch.object(work_acquire.operator, "_require_operator_capability"),
            patch.object(work_acquire, "acquire_work", return_value=expected) as acquire,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                resource_keys=[],
                system_convergence={
                    "change_risk": "R2",
                    "target_criticality": "essential",
                    "expected_protocol_head": "d" * 40,
                },
            )

        self.assertEqual(expected, result)
        self.assertEqual(
            acquire.call_args.args[0]["system_convergence"],
            {
                "change_risk": "R2",
                "target_criticality": "essential",
                "expected_protocol_head": "d" * 40,
            },
        )
        self.assertIs(
            acquire.call_args.kwargs["audit_fn"],
            work_acquire.operator.base._append_audit,
        )


    def bureau_run_parameters(self) -> dict[str, object]:
        params = self.parameters()
        params.update(
            {
                "source_kind": "bureau_run",
                "source_id": "BUR-RUN-20260817T204720Z-8972ca454d",
                "branch": "bureau/test-parent-run",
                "write_paths": ["src/app.py"],
                "scoped_writer_argv": ["writer", "--once"],
                "scoped_writer_runtime_seconds": 600,
            }
        )
        return params

    def test_scoped_writer_runtime_defaults_are_source_aware(self) -> None:
        direct = self.parameters()
        direct["scoped_writer_argv"] = ["writer", "--once"]
        normalized_direct = work_acquire._normalize(direct)
        self.assertEqual(
            work_acquire.DEFAULT_SCOPED_WRITER_RUNTIME_SECONDS,
            normalized_direct["scoped_writer_command"]["runtime_seconds"],
        )

        bureau = self.bureau_run_parameters()
        bureau.pop("scoped_writer_runtime_seconds")
        normalized_bureau = work_acquire._normalize(bureau)
        self.assertEqual(
            work_acquire.BUREAU_RUN_DEFAULT_SCOPED_WRITER_RUNTIME_SECONDS,
            normalized_bureau["scoped_writer_command"]["runtime_seconds"],
        )

        explicit = self.bureau_run_parameters()
        explicit["scoped_writer_runtime_seconds"] = 1800
        normalized_explicit = work_acquire._normalize(explicit)
        self.assertEqual(
            1800, normalized_explicit["scoped_writer_command"]["runtime_seconds"]
        )

    @staticmethod
    def delegated_parent_receipt() -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "grabowski.bureau_scoped_writer_delegation",
            "receipt_sha256": "1" * 64,
            "artifact_sha256": "2" * 64,
            "parent_owner_id": "bureau-run:BUR-RUN-20260817T204720Z-8972ca454d",
            "claim_intent_sha256": "3" * 64,
            "delegation_expires_at_unix": 10_000_000_000,
        }

    @staticmethod
    def writer_start_receipt() -> dict[str, object]:
        return {
            "job_id": "job-delegated-1",
            "unit": "grabowski-job-delegated-1",
            "argv_sha256": "4" * 64,
            "metadata_path": "/tmp/grabowski-job-delegated-1.json",
            "owner": "grabowski",
            "cwd": "/tmp/parent-workspace",
            "runtime_seconds": 600,
        }

    def test_bureau_run_requires_writer_exact_write_scope_and_allows_disjoint_independent_resources(
        self,
    ) -> None:
        params = self.bureau_run_parameters()
        params.pop("scoped_writer_argv")
        with self.assertRaisesRegex(
            ValueError, "require scoped_writer_actor and scoped_writer_argv"
        ):
            work_acquire._normalize(params)

        params = self.bureau_run_parameters()
        params["write_paths"] = []
        with self.assertRaisesRegex(ValueError, "require non-empty write_paths"):
            work_acquire._normalize(params)

        params = self.bureau_run_parameters()
        independent_key = f"path:{self.repo / 'other'}"
        params["resource_keys"] = [independent_key]
        normalized = work_acquire._normalize(params)
        self.assertEqual([independent_key], normalized["resource_keys"])
        self.assertEqual(
            [f"path:{self.repo / 'src/app.py'}"],
            normalized["delegated_write_resource_keys"],
        )

        forged = self.bureau_run_parameters()
        forged["parent_delegation"] = {"receipt_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "server-derived"):
            work_acquire._normalize(forged)

    def test_bureau_run_delegation_skips_child_leases_and_second_worktree(self) -> None:
        params = self.bureau_run_parameters()
        acquire = Mock(
            side_effect=AssertionError("child resource acquisition forbidden")
        )
        ensure = Mock(side_effect=AssertionError("second worktree forbidden"))
        start = Mock(return_value=self.writer_start_receipt())
        delegate = Mock(return_value=self.delegated_parent_receipt())
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", delegate),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", return_value={"status": "validated"}),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
                start_writer_fn=start,
            )

        self.assertEqual("ready", result["state"])
        self.assertEqual("DELEGATED_EXECUTE", result["decision"])
        acquire.assert_not_called()
        ensure.assert_not_called()
        start.assert_called_once_with(
            ["writer", "--once"], cwd=str(self.target), runtime_seconds=600
        )
        delegation_call = delegate.call_args
        self.assertEqual("BUR-RUN-20260817T204720Z-8972ca454d", delegation_call.args[0])
        self.assertEqual(
            [str(self.repo / "src/app.py")], delegation_call.kwargs["write_paths"]
        )
        self.assertEqual(
            ["implement", "test", "commit"], result["authority"]["writer_effects"]
        )
        self.assertIn("push", result["authority"]["controller_only_effects"])
        self.assertEqual(
            "parent-bureau-run-derived-exact-write-paths",
            result["authority"]["single_writer_scope"],
        )

    def test_bureau_run_parent_authority_failure_stops_before_writer_or_other_effect(
        self,
    ) -> None:
        params = self.bureau_run_parameters()
        acquire = Mock()
        ensure = Mock()
        start = Mock()
        with patch.object(
            work_acquire,
            "_authorize_bureau_run_delegation",
            side_effect=RuntimeError("parent authority drift"),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=ensure,
                runner=Mock(),
                start_writer_fn=start,
            )

        self.assertEqual("blocked", result["state"])
        self.assertEqual("HARD_BLOCK", result["decision"])
        self.assertFalse(result["effect_observed"])
        self.assertEqual(
            "repair_parent_bureau_delegation_authority", result["next_action"]
        )
        acquire.assert_not_called()
        ensure.assert_not_called()
        start.assert_not_called()

    def test_bureau_run_writer_preflight_failure_has_no_controller_fallback(
        self,
    ) -> None:
        params = self.bureau_run_parameters()
        with (
            patch.object(
                work_acquire,
                "_authorize_bureau_run_delegation",
                return_value=self.delegated_parent_receipt(),
            ),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", return_value={"status": "validated"}),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=Mock(),
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(),
                runner=Mock(),
                start_writer_fn=Mock(
                    side_effect=work_acquire.ScopedWriterStartPreflight("bad writer")
                ),
            )

        self.assertEqual("blocked", result["state"])
        self.assertEqual("HARD_BLOCK", result["decision"])
        self.assertEqual("fix_scoped_writer_start_preflight", result["next_action"])
        self.assertNotEqual("controller_execute", result["next_action"])

    def test_bureau_run_terminal_convergence_observes_only_child_owner_and_never_parent(
        self,
    ) -> None:
        params = self.bureau_run_parameters()
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        record = {
            "lane_id": inputs["lane_id"],
            "inputs": inputs,
            "worktree_receipt": {
                "kind": "grabowski.work_lane.delegated_parent_workspace"
            },
        }
        assessment = {
            "phase": "terminal",
            "lease_release_ready": True,
            "closeout_state": "no_change_verified",
            "terminal_head_sha": SHA,
        }
        with (
            patch.object(
                work_acquire.resources, "list_resources", return_value=[]
            ) as listing,
            patch.object(
                work_acquire.resources, "count_resources", return_value=0
            ) as counting,
            patch.object(
                work_acquire.resources, "grabowski_resource_release"
            ) as release,
            patch.object(
                work_acquire.checkouts, "_worktree_for_path"
            ) as checkout_probe,
        ):
            lifecycle = work_acquire._converge_terminal_checkout_lifecycle(
                record, assessment=assessment
            )
            resources_result = work_acquire._converge_terminal_resource_leases(
                record, assessment=assessment
            )

        self.assertIsNone(lifecycle)
        self.assertIsNotNone(resources_result)
        assert resources_result is not None
        self.assertEqual("already_absent", resources_result["state"])
        self.assertEqual(f"lane:{inputs['lane_id']}", resources_result["owner_id"])
        self.assertEqual([], resources_result["released_resource_keys"])
        listing.assert_called_with(
            owner_id=f"lane:{inputs['lane_id']}",
            include_expired=False,
            limit=work_acquire.MAX_TERMINAL_OWNER_LEASES,
        )
        counting.assert_called_with(
            owner_id=f"lane:{inputs['lane_id']}", include_expired=False
        )
        release.assert_not_called()
        checkout_probe.assert_not_called()

    def test_bureau_run_ready_replay_does_not_start_second_writer_or_redelegate(
        self,
    ) -> None:
        params = self.bureau_run_parameters()
        delegate = Mock(return_value=self.delegated_parent_receipt())
        start = Mock(return_value=self.writer_start_receipt())
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", delegate),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", return_value={"status": "validated"}),
        ):
            first = work_acquire.acquire_work(
                params,
                acquire_resources_fn=Mock(),
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(),
                runner=Mock(),
                start_writer_fn=start,
            )
        self.assertEqual("ready", first["state"])
        self.assertEqual(1, delegate.call_count)
        self.assertEqual(1, start.call_count)

        delegate.reset_mock()
        start.reset_mock()
        with patch.object(work_acquire, "_authorize_bureau_run_delegation", delegate):
            second = work_acquire.acquire_work(
                params,
                acquire_resources_fn=Mock(),
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(),
                runner=Mock(),
                start_writer_fn=start,
            )
        self.assertTrue(second["replayed"])
        self.assertEqual("ready", second["state"])
        delegate.assert_not_called()
        start.assert_not_called()

    def test_bureau_run_disjoint_independent_resource_is_lane_owned_only(self) -> None:
        params = self.bureau_run_parameters()
        independent_key = f"path:{self.repo / 'independent-child-resource'}"
        params["resource_keys"] = [independent_key]
        inputs = work_acquire._normalize(params)
        owner = inputs["lease_owner_id"]
        acquire = Mock(return_value=self.acquired(owner, [independent_key]))
        start = Mock(return_value=self.writer_start_receipt())
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", return_value=self.delegated_parent_receipt()),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", return_value={"status": "validated"}),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(side_effect=AssertionError("second worktree forbidden")),
                runner=Mock(),
                start_writer_fn=start,
            )
        self.assertEqual("ready", result["state"])
        self.assertEqual([independent_key], result["authority"]["lane_owned_resource_keys"])
        self.assertEqual(owner, acquire.call_args.args[0])
        self.assertEqual([independent_key], acquire.call_args.args[1])
        self.assertNotEqual(result["parent_delegation"]["parent_owner_id"], owner)
        start.assert_called_once()

    def test_bureau_run_prelaunch_drift_compensates_only_lane_owned_resource(self) -> None:
        params = self.bureau_run_parameters()
        independent_key = f"path:{self.repo / 'independent-child-resource'}"
        params["resource_keys"] = [independent_key]
        inputs = work_acquire._normalize(params)
        owner = inputs["lease_owner_id"]
        acquire = Mock(return_value=self.acquired(owner, [independent_key]))
        release = Mock(side_effect=self.release)
        start = Mock()
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", return_value=self.delegated_parent_receipt()),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", side_effect=RuntimeError("parent drift")),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(),
                runner=Mock(),
                start_writer_fn=start,
            )
        self.assertEqual("blocked", result["state"])
        self.assertEqual("complete", result["compensation"]["state"])
        self.assertEqual(owner, release.call_args.args[0])
        self.assertEqual([independent_key], release.call_args.args[1])
        self.assertNotEqual(result["parent_delegation"]["parent_owner_id"], owner)
        start.assert_not_called()

    def test_bureau_run_compensation_unknown_stays_outcome_unknown(self) -> None:
        params = self.bureau_run_parameters()
        independent_key = f"path:{self.repo / 'independent-child-resource'}"
        params["resource_keys"] = [independent_key]
        inputs = work_acquire._normalize(params)
        owner = inputs["lease_owner_id"]
        acquire = Mock(return_value=self.acquired(owner, [independent_key]))
        release = Mock(side_effect=RuntimeError("release outcome lost"))
        start = Mock()
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", return_value=self.delegated_parent_receipt()),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", side_effect=RuntimeError("parent drift")),
        ):
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=acquire,
                release_resources_fn=release,
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(),
                runner=Mock(),
                start_writer_fn=start,
            )
        self.assertEqual("outcome_unknown", result["state"])
        self.assertEqual("outcome_unknown", result["compensation"]["state"])
        self.assertEqual("reconcile_lease_compensation_before_retry", result["next_action"])
        self.assertEqual(owner, release.call_args.args[0])
        start.assert_not_called()

    def test_bureau_run_unknown_writer_start_is_not_blindly_retried(self) -> None:
        params = self.bureau_run_parameters()
        start = Mock(side_effect=RuntimeError("writer launch response lost"))
        with (
            patch.object(work_acquire, "_authorize_bureau_run_delegation", return_value=self.delegated_parent_receipt()),
            patch.object(work_acquire, "_revalidate_bureau_run_delegation", return_value={"status": "validated"}),
        ):
            first = work_acquire.acquire_work(
                params,
                acquire_resources_fn=Mock(), release_resources_fn=Mock(),
                inspect_resource_fn=Mock(), ensure_worktree_fn=Mock(), runner=Mock(),
                start_writer_fn=start,
            )
            second = work_acquire.acquire_work(
                params,
                acquire_resources_fn=Mock(), release_resources_fn=Mock(),
                inspect_resource_fn=Mock(), ensure_worktree_fn=Mock(), runner=Mock(),
                start_writer_fn=start,
            )
        self.assertEqual("outcome_unknown", first["state"])
        self.assertTrue(second["replayed"])
        self.assertEqual("outcome_unknown", second["state"])
        self.assertEqual(1, start.call_count)


if __name__ == "__main__":
    unittest.main()
