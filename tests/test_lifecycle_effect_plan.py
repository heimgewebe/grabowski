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

    def test_build_plan_binds_evidence_sources_and_resources(self) -> None:
        classification = self.classification()
        plan = self.build_plan([classification])
        self.assertEqual(plan["effect_kind"], "task_archive")
        self.assertEqual(plan["lease_owner_id"], OWNER)
        self.assertEqual(plan["required_resource_keys"], sorted(RESOURCE_KEYS))
        self.assertEqual(plan["entries"][0]["evidence_sha256"], classification["evidence_sha256"])
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
