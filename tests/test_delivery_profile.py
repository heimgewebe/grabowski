from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_candidate_adoption as delivery
import grabowski_candidate_verification as verification
import grabowski_execution_plan as execution_plan


class CandidateDeliveryManifestTests(unittest.TestCase):
    BASE = "a" * 40
    HEAD = "b" * 40
    TREE = "c" * 40
    LANE = "d" * 32
    LANE_RECEIPT = "e" * 64
    WORKSPACE = "gaw-p6-delivery-test"

    def test_delivery_manifest_api_is_in_packaged_candidate_adoption_module(self) -> None:
        self.assertEqual("grabowski_candidate_adoption", delivery.__name__)
        self.assertTrue(callable(delivery.build_candidate_delivery_manifest))
        self.assertTrue(callable(delivery.persist_candidate_delivery_manifest))
        self.assertFalse((SRC / "grabowski_delivery_profile.py").exists())

    def candidate(self) -> dict:
        patch = "1" * 64
        untracked = "2" * 64
        return verification.build_candidate_manifest(
            workspace_id=self.WORKSPACE,
            round_number=1,
            base_head=self.BASE,
            patch_sha256=patch,
            untracked_manifest_sha256=untracked,
            scope_evidence_sha256="3" * 64,
            resulting_tree_sha256=verification.derive_resulting_tree_sha256(
                base_head=self.BASE,
                patch_sha256=patch,
                untracked_manifest_sha256=untracked,
            ),
            writer_evidence_sha256="4" * 64,
            lane_id=self.LANE,
        )

    def source_receipt(self, role: str) -> dict:
        body = {
            "schema_version": 1,
            "role": role,
            "expected_head": self.BASE,
            "expected_base_head": self.BASE,
            "expected_diff_sha256": "5" * 64,
            "expected_dirty": True,
            "head_before": self.BASE,
            "head_after": self.BASE,
            "diff_after": "5" * 64,
            "worktree_dirty_after": True,
            "argv_sha256": "6" * 64,
            "returncode": 0,
            "stdout_sha256": "7" * 64,
            "stderr_sha256": "8" * 64,
            "sandbox": "bubblewrap-minimal-root-read-only-v1",
            "failure_classification": "passed",
        }
        if role == "review":
            body.update(
                {
                    "review_document_contract": "grabowski-review-document-v1",
                    "verdict": "PASS",
                    "findings": [],
                }
            )
        return {**body, "receipt_sha256": verification.sha256_json(body)}

    def evidence(self) -> tuple[dict, list[dict], dict, dict]:
        candidate = self.candidate()
        receipts = [
            verification.derive_verification_receipt(
                candidate_manifest=candidate,
                verifier_kind="tests",
                source_role_receipt=self.source_receipt("tests"),
                runtime_identity={"identity_sha256": "9" * 64},
            ),
            verification.derive_verification_receipt(
                candidate_manifest=candidate,
                verifier_kind="review",
                source_role_receipt=self.source_receipt("review"),
                runtime_identity={"identity_sha256": "0" * 64},
            ),
        ]
        summary = verification.reduce_verifications(
            candidate_manifest=candidate,
            verification_receipts=receipts,
        )
        collection = {
            "state": "complete",
            "candidate_id": candidate["candidate_id"],
            "candidate_manifest": candidate,
            "verification_receipts": receipts,
            "verification_summary": summary,
            "tests": {"status": "passed"},
            "review": {"status": "passed", "verdict": "PASS", "findings": []},
        }
        collection["result_sha256"] = delivery.sha256_json(collection)
        return candidate, receipts, summary, collection

    def plan(self, *, effect_profile: str = "delivery") -> dict:
        route_body = {
            "schema_version": 2,
            "routing_contract_version": execution_plan.ROUTING_CONTRACT_VERSION,
            "executor": "scoped_writer",
            "writer_route": "codex-sol-high",
            "effect_profile": effect_profile,
            "verification_policy": "independent_review",
            "task_class": "complex-patch",
        }
        route = {
            **route_body,
            "recommendation_sha256": execution_plan.sha256_json(route_body),
        }
        return execution_plan.build_execution_plan(
            source_binding={"kind": "direct-user", "id": "p6-test"},
            route_decision=route,
            topology="writer_verify_reduce",
            nodes=[
                {
                    "node_id": "writer",
                    "kind": "scoped_writer",
                    "critical": True,
                    "mutates": True,
                    "write_scope": ["src/app.py"],
                },
                {
                    "node_id": "tests",
                    "kind": "verifier",
                    "critical": True,
                    "mutates": False,
                    "write_scope": [],
                },
                {
                    "node_id": "reduce",
                    "kind": "reducer",
                    "critical": True,
                    "mutates": False,
                    "write_scope": [],
                },
            ],
            edges=[
                {"from": "writer", "to": "tests", "artifact": "CandidateManifest.v1"},
                {"from": "tests", "to": "reduce", "artifact": "VerificationReceipt.v1"},
            ],
            write_scope=["src/app.py"],
            verification_policy="independent_review",
            failure_policy={
                "on_indeterminate": "block",
                "on_unknown_effect": "reconcile",
                "revision": "bounded",
            },
            budgets={
                "max_revisions": 1,
                "max_duration_seconds": 3600,
                "max_tool_calls": 100,
            },
            completion_policy={
                "required_nodes": ["writer", "tests", "reduce"],
                "require_all_critical": True,
                "verifier_quorum": 1,
            },
        )

    def manifest(self) -> tuple[dict, dict, list[dict], dict, dict, dict]:
        candidate, receipts, summary, collection = self.evidence()
        plan = self.plan()
        manifest = delivery.build_candidate_delivery_manifest(
            candidate_manifest=candidate,
            verification_receipts=receipts,
            verification_summary=summary,
            collection_result=collection,
            execution_plan_value=plan,
            lane_receipt_sha256=self.LANE_RECEIPT,
            base_commit=self.BASE,
            head_commit=self.HEAD,
            candidate_git_tree_sha=self.TREE,
            commit_git_tree_sha=self.TREE,
            writer_branch="feat/p6-delivery",
            base_branch="main",
            title="P6 exact delivery",
            body="Candidate-bound commit range",
            draft=False,
        )
        return manifest, candidate, receipts, summary, collection, plan

    def test_manifest_binds_candidate_collection_tree_scope_and_actions(self) -> None:
        manifest, candidate, receipts, summary, collection, plan = self.manifest()
        self.assertEqual(candidate["candidate_id"], manifest["candidate"]["candidate_id"])
        self.assertEqual(collection["result_sha256"], manifest["candidate"]["collection_result_sha256"])
        self.assertEqual(self.TREE, manifest["commit_range"]["commit_git_tree_sha"])
        self.assertEqual("refs/heads/feat/p6-delivery", manifest["branch"]["remote_ref"])
        self.assertEqual(
            manifest,
            delivery.validate_candidate_delivery_manifest(
                manifest,
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                collection_result=collection,
                execution_plan_value=plan,
            ),
        )

    def test_candidate_and_commit_tree_mismatch_is_rejected(self) -> None:
        candidate, receipts, summary, collection = self.evidence()
        with self.assertRaisesRegex(delivery.CandidateDeliveryError, "commit tree differs"):
            delivery.build_candidate_delivery_manifest(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                collection_result=collection,
                execution_plan_value=self.plan(),
                lane_receipt_sha256=self.LANE_RECEIPT,
                base_commit=self.BASE,
                head_commit=self.HEAD,
                candidate_git_tree_sha=self.TREE,
                commit_git_tree_sha="f" * 40,
                writer_branch="feat/p6-delivery",
                base_branch="main",
                title="P6 exact delivery",
            )

    def test_stale_route_scope_branch_or_action_identity_is_rejected(self) -> None:
        manifest, candidate, receipts, summary, collection, plan = self.manifest()
        for mutate in (
            lambda value: value["identity"].__setitem__("execution_plan_id", "f" * 64),
            lambda value: value["scope"]["write_paths"].append("src/drift.py"),
            lambda value: value["branch"].__setitem__("base_branch", "release"),
            lambda value: value["actions"]["pr"].__setitem__("title", "stale"),
        ):
            drifted = copy.deepcopy(manifest)
            mutate(drifted)
            with self.assertRaises(delivery.CandidateDeliveryError):
                delivery.validate_candidate_delivery_manifest(
                    drifted,
                    candidate_manifest=candidate,
                    verification_receipts=receipts,
                    verification_summary=summary,
                    collection_result=collection,
                    execution_plan_value=plan,
                )

    def test_exact_create_only_replay_is_reused_and_conflict_is_rejected(self) -> None:
        manifest, candidate, receipts, summary, collection, plan = self.manifest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "delivery.json"
            kwargs = {
                "candidate_manifest": candidate,
                "verification_receipts": receipts,
                "verification_summary": summary,
                "collection_result": collection,
                "execution_plan_value": plan,
            }
            self.assertTrue(delivery.persist_candidate_delivery_manifest(path, manifest, **kwargs))
            self.assertFalse(delivery.persist_candidate_delivery_manifest(path, manifest, **kwargs))
            self.assertEqual(manifest, delivery.read_candidate_delivery_manifest(path, **kwargs))
            conflict = copy.deepcopy(manifest)
            conflict["manifest_id"] = "f" * 64
            with self.assertRaises(delivery.CandidateDeliveryError):
                delivery.persist_candidate_delivery_manifest(path, conflict, **kwargs)

    def test_candidate_profile_plan_cannot_be_relabelled_as_delivery(self) -> None:
        candidate, receipts, summary, collection = self.evidence()
        with self.assertRaisesRegex(delivery.CandidateDeliveryError, "delivery-bound"):
            delivery.build_candidate_delivery_manifest(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                collection_result=collection,
                execution_plan_value=self.plan(effect_profile="candidate"),
                lane_receipt_sha256=self.LANE_RECEIPT,
                base_commit=self.BASE,
                head_commit=self.HEAD,
                candidate_git_tree_sha=self.TREE,
                commit_git_tree_sha=self.TREE,
                writer_branch="feat/p6-delivery",
                base_branch="main",
                title="P6 exact delivery",
            )


if __name__ == "__main__":
    unittest.main()
