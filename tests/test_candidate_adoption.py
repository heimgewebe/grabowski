from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_candidate_adoption as adoption
import grabowski_candidate_verification as verification


class CandidateAdoptionTests(unittest.TestCase):
    BASE = "a" * 40
    PATCH = "b" * 64
    UNTRACKED = "c" * 64
    SCOPE = "d" * 64
    WRITER = "e" * 64
    LANE = "f" * 32
    WORKSPACE = "gaw-candidate-adoption-test"
    GIT_TREE = "1" * 40
    COMMIT = "2" * 40

    def candidate(self, *, lane_id: str | None = LANE, patch: str | None = None) -> dict:
        patch_sha = patch or self.PATCH
        return verification.build_candidate_manifest(
            workspace_id=self.WORKSPACE,
            round_number=1,
            base_head=self.BASE,
            patch_sha256=patch_sha,
            untracked_manifest_sha256=self.UNTRACKED,
            scope_evidence_sha256=self.SCOPE,
            resulting_tree_sha256=verification.derive_resulting_tree_sha256(
                base_head=self.BASE,
                patch_sha256=patch_sha,
                untracked_manifest_sha256=self.UNTRACKED,
            ),
            writer_evidence_sha256=self.WRITER,
            lane_id=lane_id,
        )

    def source_receipt(self, role: str, *, returncode: int = 0, verdict: str = "PASS") -> dict:
        body = {
            "schema_version": 1,
            "role": role,
            "expected_head": self.BASE,
            "expected_base_head": self.BASE,
            "expected_diff_sha256": "3" * 64,
            "expected_dirty": True,
            "head_before": self.BASE,
            "head_after": self.BASE,
            "diff_after": "3" * 64,
            "worktree_dirty_after": True,
            "argv_sha256": "4" * 64,
            "returncode": returncode,
            "stdout_sha256": "5" * 64,
            "stderr_sha256": "6" * 64,
            "sandbox": "bubblewrap-minimal-root-read-only-v1",
            "failure_classification": "passed" if returncode == 0 else "semantic_test_failure",
        }
        if role == "review":
            body["review_document_contract"] = "grabowski-review-document-v1"
            body["verdict"] = verdict
            body["findings"] = []
        return {**body, "receipt_sha256": verification.sha256_json(body)}

    def evidence(
        self,
        *,
        candidate: dict | None = None,
        tests_returncode: int = 0,
        review_verdict: str = "PASS",
    ) -> tuple[dict, list[dict], dict]:
        item = candidate or self.candidate()
        receipts = [
            verification.derive_verification_receipt(
                candidate_manifest=item,
                verifier_kind="tests",
                source_role_receipt=self.source_receipt("tests", returncode=tests_returncode),
                runtime_identity={"identity_sha256": "7" * 64},
            ),
            verification.derive_verification_receipt(
                candidate_manifest=item,
                verifier_kind="review",
                source_role_receipt=self.source_receipt("review", verdict=review_verdict),
                runtime_identity={"identity_sha256": "8" * 64},
            ),
        ]
        summary = verification.reduce_verifications(
            candidate_manifest=item,
            verification_receipts=receipts,
        )
        return item, receipts, summary

    def intent(self, *, candidate: dict | None = None, summary_override: dict | None = None) -> tuple[dict, list[dict], dict, dict]:
        item, receipts, summary = self.evidence(candidate=candidate)
        effective_summary = summary if summary_override is None else summary_override
        intent = adoption.build_adoption_intent(
            candidate_manifest=item,
            verification_receipts=receipts,
            verification_summary=effective_summary,
            controller_actor="controller:chatgpt",
            integration_target="feat/adopt",
            expected_git_tree_sha=self.GIT_TREE,
            expected_commit_sha=self.COMMIT,
        )
        return item, receipts, effective_summary, intent

    def readback(self, *, parent: str | None = None, head: str | None = None, tree: str | None = None, clean: bool = True) -> dict:
        return {
            "branch": "feat/adopt",
            "head_sha": head or self.COMMIT,
            "parent_sha": parent or self.BASE,
            "git_tree_sha": tree or self.GIT_TREE,
            "clean": clean,
            "staged_changes": False,
            "untracked_changes": False,
        }

    def receipt(self) -> tuple[dict, dict, list[dict], dict, dict]:
        candidate, receipts, summary, intent = self.intent()
        value = adoption.build_adoption_receipt(
            candidate_manifest=candidate,
            verification_receipts=receipts,
            verification_summary=summary,
            adoption_intent=intent,
            resulting_commit_sha=self.COMMIT,
            resulting_git_tree_sha=self.GIT_TREE,
            integration_readback=self.readback(),
            adopted_at_unix=123,
        )
        return value, candidate, receipts, summary, intent

    def test_intent_binds_exact_candidate_verification_lane_and_tree(self) -> None:
        candidate, receipts, summary, intent = self.intent()
        self.assertEqual(intent["candidate_id"], candidate["candidate_id"])
        self.assertEqual(intent["source_lane_id"], self.LANE)
        self.assertEqual(intent["expected_git_tree_sha"], self.GIT_TREE)
        self.assertEqual(
            adoption.validate_adoption_intent(
                intent,
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
            ),
            intent,
        )

    def test_legacy_candidate_without_lane_cannot_be_adopted(self) -> None:
        candidate, receipts, summary = self.evidence(candidate=self.candidate(lane_id=None))
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "lane-backed"):
            adoption.build_adoption_intent(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                controller_actor="controller:chatgpt",
                integration_target="/tmp/integration",
                expected_git_tree_sha=self.GIT_TREE,
                expected_commit_sha=self.COMMIT,
            )

    def test_non_pass_verification_cannot_be_adopted(self) -> None:
        candidate, receipts, summary = self.evidence(tests_returncode=1)
        self.assertEqual(summary["outcome"], "NEEDS_CHANGE")
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "must be PASS"):
            adoption.build_adoption_intent(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                controller_actor="controller:chatgpt",
                integration_target="/tmp/integration",
                expected_git_tree_sha=self.GIT_TREE,
                expected_commit_sha=self.COMMIT,
            )

    def test_verification_for_another_candidate_is_rejected(self) -> None:
        candidate, receipts, summary = self.evidence()
        other = self.candidate(patch="0" * 64)
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "candidate_id mismatch"):
            adoption.build_adoption_intent(
                candidate_manifest=other,
                verification_receipts=receipts,
                verification_summary=summary,
                controller_actor="controller:chatgpt",
                integration_target="/tmp/integration",
                expected_git_tree_sha=self.GIT_TREE,
                expected_commit_sha=self.COMMIT,
            )

    def test_receipt_binds_commit_tree_parent_and_readback(self) -> None:
        value, candidate, receipts, summary, intent = self.receipt()
        self.assertEqual(value["candidate_id"], candidate["candidate_id"])
        self.assertEqual(value["resulting_commit_sha"], self.COMMIT)
        self.assertEqual(value["integration_base_head"], self.BASE)
        self.assertEqual(
            adoption.validate_adoption_receipt(
                value,
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
            ),
            value,
        )

    def test_base_drift_in_readback_is_rejected(self) -> None:
        candidate, receipts, summary, intent = self.intent()
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "parent"):
            adoption.build_adoption_receipt(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
                resulting_commit_sha=self.COMMIT,
                resulting_git_tree_sha=self.GIT_TREE,
                integration_readback=self.readback(parent="9" * 40),
            )

    def test_wrong_resulting_tree_is_rejected(self) -> None:
        candidate, receipts, summary, intent = self.intent()
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "prepared candidate tree"):
            adoption.build_adoption_receipt(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
                resulting_commit_sha=self.COMMIT,
                resulting_git_tree_sha="9" * 40,
                integration_readback=self.readback(tree="9" * 40),
            )

    def test_dirty_readback_is_rejected(self) -> None:
        candidate, receipts, summary, intent = self.intent()
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "clean adopted checkout"):
            adoption.build_adoption_receipt(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
                resulting_commit_sha=self.COMMIT,
                resulting_git_tree_sha=self.GIT_TREE,
                integration_readback=self.readback(clean=False),
            )

    def test_receipt_tamper_is_rejected(self) -> None:
        value, candidate, receipts, summary, intent = self.receipt()
        value["controller_actor"] = "controller:other"
        with self.assertRaisesRegex(adoption.CandidateAdoptionError, "binding mismatch"):
            adoption.validate_adoption_receipt(
                value,
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
            )

    def test_immutable_receipt_is_idempotent_but_conflicting_adoption_is_rejected(self) -> None:
        value, candidate, receipts, summary, intent = self.receipt()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.chmod(0o700)
            path = root / "adoption.json"
            self.assertTrue(
                adoption.persist_adoption_receipt(
                    path,
                    value,
                    candidate_manifest=candidate,
                    verification_receipts=receipts,
                    verification_summary=summary,
                    adoption_intent=intent,
                )
            )
            self.assertFalse(
                adoption.persist_adoption_receipt(
                    path,
                    value,
                    candidate_manifest=candidate,
                    verification_receipts=receipts,
                    verification_summary=summary,
                    adoption_intent=intent,
                )
            )
            conflicting = adoption.build_adoption_receipt(
                candidate_manifest=candidate,
                verification_receipts=receipts,
                verification_summary=summary,
                adoption_intent=intent,
                resulting_commit_sha=self.COMMIT,
                resulting_git_tree_sha=self.GIT_TREE,
                integration_readback=self.readback(),
                adopted_at_unix=124,
            )
            with self.assertRaisesRegex(adoption.CandidateAdoptionError, "same-round receipt changed"):
                adoption.persist_adoption_receipt(
                    path,
                    conflicting,
                    candidate_manifest=candidate,
                    verification_receipts=receipts,
                    verification_summary=summary,
                    adoption_intent=intent,
                )
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
