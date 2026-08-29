from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

import grabowski_candidate_verification as candidate_verification


class CandidateVerificationTests(unittest.TestCase):
    BASE = "a" * 40
    PATCH = "b" * 64
    UNTRACKED = "c" * 64
    SCOPE = "d" * 64
    WRITER = "e" * 64
    LANE = "f" * 32
    WORKSPACE = "gaw-candidate-verification-test"

    def candidate(
        self,
        *,
        patch_sha256: str | None = None,
        untracked_manifest_sha256: str | None = None,
        lane_id: str | None = LANE,
    ) -> dict:
        patch = patch_sha256 or self.PATCH
        untracked = untracked_manifest_sha256 or self.UNTRACKED
        resulting = candidate_verification.derive_resulting_tree_sha256(
            base_head=self.BASE,
            patch_sha256=patch,
            untracked_manifest_sha256=untracked,
        )
        return candidate_verification.build_candidate_manifest(
            workspace_id=self.WORKSPACE,
            round_number=1,
            base_head=self.BASE,
            patch_sha256=patch,
            untracked_manifest_sha256=untracked,
            scope_evidence_sha256=self.SCOPE,
            resulting_tree_sha256=resulting,
            writer_evidence_sha256=self.WRITER,
            lane_id=lane_id,
        )

    def source_receipt(
        self,
        role: str,
        *,
        returncode: int = 0,
        failure_classification: str = "passed",
        verdict: str = "PASS",
        findings: list[dict] | None = None,
    ) -> dict:
        body = {
            "schema_version": 1,
            "role": role,
            "expected_head": self.BASE,
            "expected_base_head": self.BASE,
            "expected_diff_sha256": "1" * 64,
            "expected_dirty": True,
            "head_before": self.BASE,
            "head_after": self.BASE,
            "diff_after": "1" * 64,
            "worktree_dirty_after": True,
            "argv_sha256": "2" * 64,
            "returncode": returncode,
            "stdout_sha256": "3" * 64,
            "stderr_sha256": "4" * 64,
            "sandbox": "bubblewrap-minimal-root-read-only-v1",
            "failure_classification": failure_classification,
        }
        if role == "review":
            body["review_document_contract"] = "grabowski-review-document-v1"
            body["verdict"] = verdict
            body["findings"] = [] if findings is None else findings
        return {
            **body,
            "receipt_sha256": candidate_verification.sha256_json(body),
        }

    def verification(
        self,
        role: str,
        *,
        candidate: dict | None = None,
        returncode: int = 0,
        failure_classification: str = "passed",
        verdict: str = "PASS",
        findings: list[dict] | None = None,
        verifier_attempt: int = 1,
    ) -> dict:
        source = self.source_receipt(
            role,
            returncode=returncode,
            failure_classification=failure_classification,
            verdict=verdict,
            findings=findings,
        )
        return candidate_verification.derive_verification_receipt(
            candidate_manifest=candidate or self.candidate(),
            verifier_kind=role,
            source_role_receipt=source,
            runtime_identity={"identity_sha256": "5" * 64},
            toolchain_identity={
                "command_sha256": source["argv_sha256"],
                "sandbox": source["sandbox"],
                "environment": {"environment_sha256": "6" * 64},
                "resolved_executable": "/usr/bin/python3",
                "declared_python_module": None,
                "external_agent_profile": None,
                "passed": returncode == 0,
                "failure_classification": failure_classification,
            },
            verifier_attempt=verifier_attempt,
        )

    def test_candidate_id_is_canonical_and_lane_bound(self) -> None:
        first = self.candidate()
        second = self.candidate()
        self.assertEqual(first, second)
        self.assertEqual(len(first["candidate_id"]), 64)
        self.assertEqual(first["lane_id"], self.LANE)
        self.assertEqual(
            candidate_verification.validate_candidate_manifest(first), first
        )

    def test_legacy_candidate_can_omit_lane_id(self) -> None:
        candidate = self.candidate(lane_id=None)
        self.assertNotIn("lane_id", candidate)
        self.assertEqual(
            candidate_verification.validate_candidate_manifest(candidate), candidate
        )

    def test_candidate_tamper_is_rejected(self) -> None:
        candidate = self.candidate()
        candidate["patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            candidate_verification.CandidateVerificationError,
            "candidate_id",
        ):
            candidate_verification.validate_candidate_manifest(candidate)

    def test_logical_resulting_tree_changes_with_patch_or_untracked_manifest(self) -> None:
        baseline = candidate_verification.derive_resulting_tree_sha256(
            base_head=self.BASE,
            patch_sha256=self.PATCH,
            untracked_manifest_sha256=self.UNTRACKED,
        )
        patch_changed = candidate_verification.derive_resulting_tree_sha256(
            base_head=self.BASE,
            patch_sha256="0" * 64,
            untracked_manifest_sha256=self.UNTRACKED,
        )
        untracked_changed = candidate_verification.derive_resulting_tree_sha256(
            base_head=self.BASE,
            patch_sha256=self.PATCH,
            untracked_manifest_sha256="1" * 64,
        )
        self.assertNotEqual(baseline, patch_changed)
        self.assertNotEqual(baseline, untracked_changed)

    def test_verification_receipt_binds_exact_candidate_and_identities(self) -> None:
        candidate = self.candidate()
        receipt = self.verification("tests", candidate=candidate)
        self.assertEqual(receipt["candidate_id"], candidate["candidate_id"])
        self.assertEqual(receipt["verifier_attempt"], 1)
        self.assertEqual(receipt["outcome"], "PASS")
        self.assertIn("tool_or_command_identity", receipt)
        self.assertIn("toolchain_identity", receipt)
        self.assertIn("environment_identity", receipt)
        self.assertEqual(
            candidate_verification.validate_verification_receipt(
                receipt,
                expected_candidate_id=candidate["candidate_id"],
            ),
            receipt,
        )

    def test_verifier_attempt_is_immutable_evidence_not_candidate_revision(self) -> None:
        candidate = self.candidate()
        first = self.verification("tests", candidate=candidate, verifier_attempt=1)
        second = self.verification("tests", candidate=candidate, verifier_attempt=2)
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertEqual(first["round"], second["round"])
        self.assertEqual(first["verifier_attempt"], 1)
        self.assertEqual(second["verifier_attempt"], 2)
        self.assertNotEqual(first["receipt_sha256"], second["receipt_sha256"])

    def test_verification_for_another_candidate_is_rejected(self) -> None:
        candidate = self.candidate()
        receipt = self.verification("tests", candidate=candidate)
        other = self.candidate(patch_sha256="0" * 64)
        with self.assertRaisesRegex(
            candidate_verification.CandidateVerificationError,
            "candidate_id mismatch",
        ):
            candidate_verification.validate_verification_receipt(
                receipt,
                expected_candidate_id=other["candidate_id"],
            )

    def test_verification_receipt_tamper_is_rejected(self) -> None:
        candidate = self.candidate()
        receipt = self.verification("tests", candidate=candidate)
        receipt["outcome"] = "NEEDS_CHANGE"
        with self.assertRaisesRegex(
            candidate_verification.CandidateVerificationError,
            "integrity mismatch",
        ):
            candidate_verification.validate_verification_receipt(
                receipt,
                expected_candidate_id=candidate["candidate_id"],
            )

    def test_review_needs_change_is_preserved(self) -> None:
        receipt = self.verification(
            "review",
            verdict="NEEDS_CHANGE",
            findings=[{"severity": "high", "code": "bug", "message": "fix me"}],
        )
        self.assertEqual(receipt["outcome"], "NEEDS_CHANGE")
        self.assertEqual(len(receipt["findings"]), 1)

    def test_semantic_test_failure_needs_change(self) -> None:
        receipt = self.verification(
            "tests",
            returncode=1,
            failure_classification="semantic_test_failure",
        )
        self.assertEqual(receipt["outcome"], "NEEDS_CHANGE")

    def test_environment_failure_is_indeterminate(self) -> None:
        receipt = self.verification(
            "tests",
            returncode=1,
            failure_classification="environment_toolchain_failure",
        )
        self.assertEqual(receipt["outcome"], "INDETERMINATE")

    def test_missing_required_verifier_is_indeterminate(self) -> None:
        candidate = self.candidate()
        summary = candidate_verification.reduce_verifications(
            candidate_manifest=candidate,
            verification_receipts=[self.verification("tests", candidate=candidate)],
        )
        self.assertEqual(summary["outcome"], "INDETERMINATE")
        self.assertEqual(summary["missing_required_verifiers"], ["review"])
        self.assertIn(
            {"code": "missing_required_verifier", "verifier_kind": "review"},
            summary["findings"],
        )

    def test_required_needs_change_dominates_indeterminate(self) -> None:
        candidate = self.candidate()
        summary = candidate_verification.reduce_verifications(
            candidate_manifest=candidate,
            verification_receipts=[
                self.verification(
                    "review",
                    candidate=candidate,
                    verdict="NEEDS_CHANGE",
                    findings=[{"code": "real_defect"}],
                ),
                self.verification(
                    "tests",
                    candidate=candidate,
                    returncode=1,
                    failure_classification="environment_toolchain_failure",
                ),
            ],
        )
        self.assertEqual(summary["outcome"], "NEEDS_CHANGE")

    def test_all_required_pass_yields_pass(self) -> None:
        candidate = self.candidate()
        receipts = [
            self.verification("review", candidate=candidate),
            self.verification("tests", candidate=candidate),
        ]
        summary = candidate_verification.reduce_verifications(
            candidate_manifest=candidate,
            verification_receipts=receipts,
        )
        self.assertEqual(summary["outcome"], "PASS")
        self.assertEqual(summary["missing_required_verifiers"], [])
        self.assertEqual(summary["verifier_attempts"], {"review": 1, "tests": 1})
        self.assertEqual(
            summary["verifier_provenance"],
            {
                receipt["verifier_kind"]: {
                    "verification_receipt_sha256": receipt["receipt_sha256"],
                    "source_role_receipt_sha256": receipt["source_role_receipt_sha256"],
                }
                for receipt in sorted(receipts, key=lambda item: item["verifier_kind"])
            },
        )
        self.assertEqual(
            candidate_verification.validate_verification_summary(
                summary,
                candidate_manifest=candidate,
                verification_receipts=receipts,
            ),
            summary,
        )

    def test_legacy_summary_without_verifier_provenance_is_rejected(self) -> None:
        candidate = self.candidate()
        receipts = [
            self.verification("review", candidate=candidate),
            self.verification("tests", candidate=candidate),
        ]
        current = candidate_verification.reduce_verifications(
            candidate_manifest=candidate,
            verification_receipts=receipts,
        )
        legacy_body = {
            key: value
            for key, value in current.items()
            if key not in {"summary_sha256", "verifier_provenance"}
        }
        legacy = {
            **legacy_body,
            "summary_sha256": candidate_verification.sha256_json(legacy_body),
        }
        with self.assertRaisesRegex(
            candidate_verification.CandidateVerificationError,
            "differs from deterministic reduction",
        ):
            candidate_verification.validate_verification_summary(
                legacy,
                candidate_manifest=candidate,
                verification_receipts=receipts,
            )

    def test_duplicate_verifier_receipt_is_rejected(self) -> None:
        candidate = self.candidate()
        receipt = self.verification("tests", candidate=candidate)
        with self.assertRaisesRegex(
            candidate_verification.CandidateVerificationError,
            "duplicate verifier",
        ):
            candidate_verification.reduce_verifications(
                candidate_manifest=candidate,
                verification_receipts=[receipt, receipt],
            )

    def test_findings_are_deduplicated_and_deterministically_sorted(self) -> None:
        findings = candidate_verification.normalize_findings(
            [
                {"code": "z", "message": " second \r\n"},
                {"message": "first", "code": "a"},
                {"code": "z", "message": "second"},
            ]
        )
        self.assertEqual(
            findings,
            [
                {"code": "a", "message": "first"},
                {"code": "z", "message": "second"},
            ],
        )

    def test_same_round_immutable_receipt_is_idempotent_but_cannot_change(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            path = root / "candidate-round-0001.json"
            self.assertTrue(
                candidate_verification.persist_immutable_receipt(
                    path,
                    candidate,
                    validator=candidate_verification.validate_candidate_manifest,
                )
            )
            self.assertFalse(
                candidate_verification.persist_immutable_receipt(
                    path,
                    candidate,
                    validator=candidate_verification.validate_candidate_manifest,
                )
            )
            changed = self.candidate(patch_sha256="0" * 64)
            with self.assertRaisesRegex(
                candidate_verification.CandidateVerificationError,
                "same-round receipt changed",
            ):
                candidate_verification.persist_immutable_receipt(
                    path,
                    changed,
                    validator=candidate_verification.validate_candidate_manifest,
                )

    def test_immutable_receipt_requires_private_owner_controlled_parent(self) -> None:
        candidate = self.candidate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o755)
            with self.assertRaisesRegex(
                candidate_verification.CandidateVerificationError,
                "private owner-controlled",
            ):
                candidate_verification.persist_immutable_receipt(
                    root / "candidate-round-0001.json",
                    candidate,
                    validator=candidate_verification.validate_candidate_manifest,
                )


if __name__ == "__main__":
    unittest.main()
