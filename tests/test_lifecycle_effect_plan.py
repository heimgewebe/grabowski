from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import grabowski_lifecycle_effect_plan as effect_plan
import grabowski_lifecycle_evidence as evidence


ALL_SOURCES = frozenset(evidence.REQUIRED_SOURCES)
SOURCE_SHA256S = {
    source: (format(index + 1, "x") * 64)
    for index, source in enumerate(sorted(ALL_SOURCES))
}
OWNER = "operator:t071-effect-test"
RESOURCE_KEYS = [
    "component:/tmp/grabowski:task-archive",
    "path:/tmp/grabowski/archive-segment",
]


class LifecycleEffectPlanTests(unittest.TestCase):
    def classification(self, identity: str = "task-a", **overrides):
        values = {
            "identity": identity,
            "kind": "task",
            "observed_sources": ALL_SOURCES,
            "source_sha256s": SOURCE_SHA256S,
            "source_applicability": {source: "observed" for source in ALL_SOURCES},
            "state": "completed",
            "closed": None,
            "receipt_integrity_valid": True,
        }
        values.update(overrides)
        return evidence.classify_observation_bundle(
            evidence.LifecycleObservationBundle(**values)
        )

    def build_plan(self, classifications=None, **overrides):
        values = {
            "classifications": classifications or [self.classification()],
            "effect_kind": "task_archive",
            "lease_owner_id": OWNER,
            "required_resource_keys": RESOURCE_KEYS,
            "created_at_unix": 1000,
        }
        values.update(overrides)
        return effect_plan.build_effect_plan(**values)

    def lease(self, resource_key: str, **overrides):
        values = {
            "resource_key": resource_key,
            "owner_id": OWNER,
            "expires_at_unix": 2000,
            "metadata_sha256": "a" * 64,
        }
        values.update(overrides)
        return effect_plan.LeaseObservation(**values)

    def valid_leases(self):
        return [self.lease(key) for key in RESOURCE_KEYS]

    def ready_revalidation(self, plan=None, classification=None):
        current = classification or self.classification()
        value = plan or self.build_plan([current])
        return effect_plan.revalidate_effect_plan(
            value,
            {current["identity"]: current},
            self.valid_leases(),
            now_unix=1500,
        )

    def build_receipt(self, plan=None, revalidation=None, **overrides):
        value = plan or self.build_plan()
        current_revalidation = revalidation or self.ready_revalidation(plan=value)
        arguments = {
            "execution_id": "exec-task-a-001",
            "started_at_unix": 1501,
            "completed_at_unix": 1502,
            "transport_outcome": "confirmed_success",
            "mutation_state": "performed",
            "post_state_status": "verified",
            "post_state_sha256s": {"task_store": "b" * 64},
        }
        arguments.update(overrides)
        return effect_plan.build_effect_execution_receipt(
            value,
            current_revalidation,
            **arguments,
        )

    def test_build_plan_binds_evidence_sources_and_resources(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        self.assertEqual(plan["effect_kind"], "task_archive")
        self.assertEqual(plan["lease_owner_id"], OWNER)
        self.assertEqual(plan["required_resource_keys"], sorted(RESOURCE_KEYS))
        self.assertEqual(plan["entries"][0]["evidence_sha256"], classification["evidence_sha256"])
        self.assertEqual(
            plan["entries"][0]["source_applicability"],
            classification["evidence"]["source_applicability"],
        )
        self.assertEqual(
            plan["entries"][0]["source_sha256s"],
            classification["evidence"]["source_sha256s"],
        )
        self.assertFalse(plan["mutation_performed"])
        self.assertTrue(plan["requires_immediate_revalidation"])

    def test_archive_plan_rejects_ambiguous_classification(self) -> None:
        classification = self.classification(active_process=None)
        self.assertEqual(classification["classification"], "ambiguous")
        with self.assertRaises(effect_plan.LifecycleEffectPlanError):
            self.build_plan([classification])

    def test_archive_plan_rejects_untouchable_classification(self) -> None:
        classification = self.classification(
            kind="checkout", state=None, closed=True, dirty=True
        )
        with self.assertRaises(effect_plan.LifecycleEffectPlanError):
            self.build_plan(
                [classification],
                effect_kind="retention_converge",
            )

    def test_projection_switch_requires_archived_classification(self) -> None:
        with self.assertRaises(effect_plan.LifecycleEffectPlanError):
            self.build_plan(effect_kind="current_projection_switch")
        archived = self.classification(archived=True)
        plan = self.build_plan(
            [archived], effect_kind="current_projection_switch"
        )
        self.assertEqual(plan["entries"][0]["classification"], "archived")

    def test_forged_classification_verdict_is_rejected(self) -> None:
        classification = self.classification()
        forged = {**classification, "classification": "terminal_archivable"}
        forged["safe_to_archive"] = False
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            self.build_plan([forged])

    def test_tampered_evidence_snapshot_is_rejected_even_with_outer_digest(self) -> None:
        classification = self.classification()
        evidence_snapshot = dict(classification["evidence"])
        evidence_snapshot["active_process"] = True
        forged = {**classification, "evidence": evidence_snapshot}
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            self.build_plan([forged])

    def test_plan_rejects_broad_repository_resource(self) -> None:
        with self.assertRaises(ValueError):
            self.build_plan(required_resource_keys=["repo:/tmp/grabowski"])

    def test_digest_valid_plan_cannot_claim_mutation(self) -> None:
        plan = self.build_plan()
        forged = {**plan, "mutation_performed": True}
        body = {key: value for key, value in forged.items() if key != "plan_sha256"}
        forged["plan_sha256"] = effect_plan.sha256_json(body)
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            effect_plan.revalidate_effect_plan(
                forged,
                {"task-a": self.classification()},
                self.valid_leases(),
                now_unix=1500,
            )

    def test_plan_digest_changes_when_evidence_changes(self) -> None:
        first = self.build_plan()
        bindings = dict(SOURCE_SHA256S)
        bindings["process"] = "f" * 64
        second = self.build_plan(
            [self.classification(source_sha256s=bindings)]
        )
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])

    def test_plan_rejects_duplicate_resource_keys(self) -> None:
        with self.assertRaises(ValueError):
            self.build_plan(required_resource_keys=[RESOURCE_KEYS[0], RESOURCE_KEYS[0]])

    def test_write_verify_and_idempotent_replay(self) -> None:
        plan = self.build_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-plans"
            first = effect_plan.write_effect_plan(plan, plan_root=root)
            self.assertEqual(first["status"], "verified")
            self.assertFalse(first["idempotent_replay"])
            second = effect_plan.write_effect_plan(plan, plan_root=root)
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(first["plan"], second["plan"])

    def test_tampered_plan_fails_verification(self) -> None:
        plan = self.build_plan()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-plans"
            result = effect_plan.write_effect_plan(plan, plan_root=root)
            path = Path(result["plan_path"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["lease_owner_id"] = "operator:other"
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.verify_effect_plan(path)

    def test_revalidation_passes_only_with_unchanged_evidence_and_live_leases(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        result = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": classification},
            self.valid_leases(),
            now_unix=1500,
        )
        self.assertTrue(result["ready_for_effect"])
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(len(result["revalidation_sha256"]), 64)

    def test_write_verify_revalidation_and_idempotent_replay(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-revalidations"
            first = effect_plan.write_effect_revalidation(
                revalidation, revalidation_root=root, plan=plan
            )
            self.assertEqual(first["status"], "verified")
            self.assertFalse(first["idempotent_replay"])
            second = effect_plan.write_effect_revalidation(
                revalidation, revalidation_root=root, plan=plan
            )
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(first["revalidation"], second["revalidation"])
            verified = effect_plan.verify_effect_revalidation(
                Path(first["revalidation_path"]), plan=plan
            )
            self.assertEqual(
                verified["revalidation"]["revalidation_sha256"],
                revalidation["revalidation_sha256"],
            )

    def test_tampered_persisted_revalidation_fails_verification(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-revalidations"
            result = effect_plan.write_effect_revalidation(
                revalidation, revalidation_root=root, plan=plan
            )
            path = Path(result["revalidation_path"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["ready_for_effect"] = False
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.verify_effect_revalidation(path, plan=plan)

    def test_revalidation_fails_when_current_classification_missing(self) -> None:
        plan = self.build_plan()
        result = effect_plan.revalidate_effect_plan(
            plan, {}, self.valid_leases(), now_unix=1500
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn("current_classification_missing:task-a", result["errors"])

    def test_revalidation_fails_on_evidence_drift(self) -> None:
        original = self.classification()
        plan = self.build_plan([original])
        bindings = dict(SOURCE_SHA256S)
        bindings["process"] = "f" * 64
        changed = self.classification(source_sha256s=bindings)
        result = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": changed},
            self.valid_leases(),
            now_unix=1500,
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn("evidence_drift:task-a", result["errors"])
        self.assertIn("source_digest_drift:task-a", result["errors"])

    def test_revalidation_fails_on_source_applicability_drift(self) -> None:
        original = self.classification()
        plan = self.build_plan([original])
        applicability = {source: "observed" for source in ALL_SOURCES}
        applicability["checkout"] = "explicit_absence"
        changed = self.classification(source_applicability=applicability)
        result = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": changed},
            self.valid_leases(),
            now_unix=1500,
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn("evidence_drift:task-a", result["errors"])
        self.assertIn("source_applicability_drift:task-a", result["errors"])

    def test_effect_plan_rejects_evidence_without_applicability(self) -> None:
        classification = self.classification()
        snapshot = dict(classification["evidence"])
        snapshot.pop("source_applicability")
        forged = {**classification, "evidence": snapshot}
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            self.build_plan([forged])

    def test_revalidation_fails_when_object_becomes_active(self) -> None:
        original = self.classification()
        plan = self.build_plan([original])
        active = self.classification(state="running", active_task=True)
        result = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": active},
            self.valid_leases(),
            now_unix=1500,
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn(
            "current_classification_invalid:task-a:LifecycleEffectPlanError",
            result["errors"],
        )

    def test_revalidation_fails_when_required_lease_missing(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        result = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": classification},
            [self.lease(RESOURCE_KEYS[0])],
            now_unix=1500,
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn(
            f"required_lease_missing:{RESOURCE_KEYS[1]}", result["errors"]
        )

    def test_revalidation_fails_on_foreign_lease_owner(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        leases = [
            self.lease(RESOURCE_KEYS[0], owner_id="operator:foreign"),
            self.lease(RESOURCE_KEYS[1]),
        ]
        result = effect_plan.revalidate_effect_plan(
            plan, {"task-a": classification}, leases, now_unix=1500
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn(
            f"required_lease_foreign_owner:{RESOURCE_KEYS[0]}", result["errors"]
        )

    def test_revalidation_fails_on_expired_lease(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        leases = [
            self.lease(RESOURCE_KEYS[0], expires_at_unix=1500),
            self.lease(RESOURCE_KEYS[1]),
        ]
        result = effect_plan.revalidate_effect_plan(
            plan, {"task-a": classification}, leases, now_unix=1500
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn(
            f"required_lease_expired:{RESOURCE_KEYS[0]}", result["errors"]
        )

    def test_revalidation_fails_on_duplicate_lease_observation(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        leases = [
            self.lease(RESOURCE_KEYS[0]),
            self.lease(RESOURCE_KEYS[0]),
            self.lease(RESOURCE_KEYS[1]),
        ]
        result = effect_plan.revalidate_effect_plan(
            plan, {"task-a": classification}, leases, now_unix=1500
        )
        self.assertFalse(result["ready_for_effect"])
        self.assertIn(
            f"duplicate_lease_observation:{RESOURCE_KEYS[0]}", result["errors"]
        )

    def test_effect_receipt_binds_plan_revalidation_sources_leases_and_post_state(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        self.assertEqual(receipt["effect_kind"], plan["effect_kind"])
        self.assertEqual(receipt["plan_sha256"], plan["plan_sha256"])
        self.assertEqual(
            receipt["revalidation_sha256"],
            revalidation["revalidation_sha256"],
        )
        self.assertEqual(
            receipt["source_bindings_sha256"],
            effect_plan._source_bindings_sha256(plan),
        )
        self.assertEqual(
            receipt["lease_bindings_sha256"],
            effect_plan.sha256_json(revalidation["lease_bindings"]),
        )
        self.assertEqual(receipt["post_state_status"], "verified")
        self.assertEqual(receipt["status"], "succeeded")
        self.assertFalse(receipt["blind_retry_allowed"])

    def test_effect_receipt_rejects_not_ready_revalidation(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        revalidation = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": classification},
            [self.lease(RESOURCE_KEYS[0])],
            now_unix=1500,
        )
        self.assertFalse(revalidation["ready_for_effect"])
        with self.assertRaises(effect_plan.LifecycleEffectPlanError):
            self.build_receipt(plan=plan, revalidation=revalidation)

    def test_unknown_transport_forces_recovery_and_forbids_blind_retry(self) -> None:
        receipt = self.build_receipt(
            transport_outcome="unknown",
            mutation_state="unknown",
            post_state_status="unavailable",
            post_state_sha256s=None,
            recovery_refs=["recovery:effect:exec-task-a-001"],
        )
        self.assertEqual(receipt["status"], "recovery_required")
        self.assertFalse(receipt["blind_retry_allowed"])
        self.assertEqual(receipt["post_state_sha256s"], {})

    def test_confirmed_failure_after_mutation_requires_recovery(self) -> None:
        receipt = self.build_receipt(
            transport_outcome="confirmed_failure",
            mutation_state="performed",
            recovery_refs=["recovery:effect:exec-task-a-001"],
        )
        self.assertEqual(receipt["status"], "recovery_required")

    def test_recovery_required_receipt_requires_recovery_reference(self) -> None:
        with self.assertRaises(ValueError):
            self.build_receipt(
                transport_outcome="unknown",
                mutation_state="unknown",
                post_state_status="unavailable",
                post_state_sha256s=None,
            )

    def test_confirmed_failure_without_mutation_is_failed(self) -> None:
        receipt = self.build_receipt(
            transport_outcome="confirmed_failure",
            mutation_state="not_performed",
        )
        self.assertEqual(receipt["status"], "failed")

    def test_effect_receipt_must_start_before_earliest_lease_expiry(self) -> None:
        with self.assertRaises(ValueError):
            self.build_receipt(started_at_unix=2000, completed_at_unix=2001)

    def test_self_consistent_receipt_start_after_lease_expiry_fails_binding(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        forged = {**receipt, "started_at_unix": 2000, "completed_at_unix": 2001}
        body = {key: value for key, value in forged.items() if key != "receipt_sha256"}
        forged["receipt_sha256"] = effect_plan.sha256_json(body)
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            effect_plan._validate_effect_execution_receipt_binding(
                forged, plan=plan, revalidation=revalidation
            )

    def test_recovery_receipt_may_complete_after_lease_expiry_if_started_in_time(self) -> None:
        receipt = self.build_receipt(
            started_at_unix=1999,
            completed_at_unix=2001,
            transport_outcome="unknown",
            mutation_state="unknown",
            post_state_status="unavailable",
            post_state_sha256s=None,
            recovery_refs=["recovery:effect:exec-task-a-001"],
        )
        self.assertEqual(receipt["status"], "recovery_required")

    def test_confirmed_outcome_requires_verified_post_state(self) -> None:
        with self.assertRaises(ValueError):
            self.build_receipt(
                post_state_status="unavailable",
                post_state_sha256s=None,
            )

    def test_effect_receipt_write_verify_and_idempotent_replay(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-receipts"
            first = effect_plan.write_effect_execution_receipt(
                receipt, receipt_root=root, plan=plan, revalidation=revalidation
            )
            self.assertFalse(first["idempotent_replay"])
            second = effect_plan.write_effect_execution_receipt(
                receipt, receipt_root=root, plan=plan, revalidation=revalidation
            )
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(first["receipt"], second["receipt"])

    def test_effect_receipt_execution_identity_conflict_fails_closed(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        first_receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        second_receipt = self.build_receipt(
            plan=plan, revalidation=revalidation, completed_at_unix=1503
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-receipts"
            effect_plan.write_effect_execution_receipt(
                first_receipt, receipt_root=root, plan=plan, revalidation=revalidation
            )
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.write_effect_execution_receipt(
                    second_receipt,
                    receipt_root=root,
                    plan=plan,
                    revalidation=revalidation,
                )

    def test_tampered_effect_receipt_fails_verification(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-receipts"
            result = effect_plan.write_effect_execution_receipt(
                receipt, receipt_root=root, plan=plan, revalidation=revalidation
            )
            path = Path(result["receipt_path"])
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["status"] = "failed"
            path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.verify_effect_execution_receipt(
                    path, plan=plan, revalidation=revalidation
                )

    def test_effect_receipt_symlink_fails_closed(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        receipt = self.build_receipt(plan=plan, revalidation=revalidation)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "effect-receipts"
            result = effect_plan.write_effect_execution_receipt(
                receipt, receipt_root=root, plan=plan, revalidation=revalidation
            )
            path = Path(result["receipt_path"])
            outside = Path(directory) / "outside-receipt.json"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.verify_effect_execution_receipt(
                    path, plan=plan, revalidation=revalidation
                )

    def test_effect_receipt_writer_rejects_different_plan_binding(self) -> None:
        first_plan = self.build_plan()
        first_revalidation = self.ready_revalidation(plan=first_plan)
        receipt = self.build_receipt(
            plan=first_plan, revalidation=first_revalidation
        )
        bindings = dict(SOURCE_SHA256S)
        bindings["process"] = "f" * 64
        classification = self.classification(source_sha256s=bindings)
        second_plan = self.build_plan([classification])
        second_revalidation = self.ready_revalidation(
            plan=second_plan, classification=classification
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
                effect_plan.write_effect_execution_receipt(
                    receipt,
                    receipt_root=Path(directory) / "effect-receipts",
                    plan=second_plan,
                    revalidation=second_revalidation,
                )

    def test_ready_revalidation_cannot_forge_source_binding(self) -> None:
        plan = self.build_plan()
        revalidation = self.ready_revalidation(plan=plan)
        forged = dict(revalidation)
        forged_bindings = [dict(item) for item in revalidation["current_bindings"]]
        forged_bindings[0]["evidence_sha256"] = "f" * 64
        forged["current_bindings"] = forged_bindings
        body = {
            key: value
            for key, value in forged.items()
            if key != "revalidation_sha256"
        }
        forged["revalidation_sha256"] = effect_plan.sha256_json(body)
        with self.assertRaises(effect_plan.LifecycleEffectPlanIntegrityError):
            self.build_receipt(plan=plan, revalidation=forged)

    def test_effect_receipt_source_binding_changes_with_plan_sources(self) -> None:
        first = self.build_receipt()
        bindings = dict(SOURCE_SHA256S)
        bindings["process"] = "f" * 64
        classification = self.classification(source_sha256s=bindings)
        plan = self.build_plan([classification])
        revalidation = self.ready_revalidation(
            plan=plan,
            classification=classification,
        )
        second = self.build_receipt(
            plan=plan,
            revalidation=revalidation,
            execution_id="exec-task-a-002",
        )
        self.assertNotEqual(
            first["source_bindings_sha256"],
            second["source_bindings_sha256"],
        )

    def test_plan_and_revalidation_never_claim_effect_or_deletion(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        revalidation = effect_plan.revalidate_effect_plan(
            plan,
            {"task-a": classification},
            self.valid_leases(),
            now_unix=1500,
        )
        self.assertIn("effect_execution", plan["does_not_establish"])
        self.assertIn("physical_deletion_authority", plan["does_not_establish"])
        self.assertIn("effect_execution", revalidation["does_not_establish"])
        self.assertIn(
            "physical_deletion_authority", revalidation["does_not_establish"]
        )


if __name__ == "__main__":
    unittest.main()
