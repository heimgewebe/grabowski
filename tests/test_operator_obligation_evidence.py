from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligations
import grabowski_operator_obligation_evidence as evidence


class OperatorObligationEvidenceTests(unittest.TestCase):
    @staticmethod
    def _stored_evidence(
        *,
        acceptance_id: str = "runtime",
        source: str = "runtime",
        reference: str = "runtime:revision-a",
        sha256: str = "a" * 64,
        status: str = "passed",
    ) -> dict[str, str]:
        return {
            "acceptance_id": acceptance_id,
            "status": status,
            "source": source,
            "reference": reference,
            "sha256": sha256,
        }

    @staticmethod
    def _status(
        *,
        state: str = "completed",
        close_schema_version: int | None = obligations.CLOSE_SCHEMA_VERSION,
        acceptance_ids: list[str] | None = None,
        stored_evidence: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        acceptance = acceptance_ids or ["runtime"]
        items = stored_evidence if stored_evidence is not None else [
            OperatorObligationEvidenceTests._stored_evidence()
        ]
        evidenced = {item["acceptance_id"] for item in items}
        return {
            "obligation_id": "goo-shadow-evidence-test-0001",
            "state": state,
            "close_schema_version": close_schema_version,
            "open_file_sha256": "e" * 64,
            "close_file_sha256": None if state == "open" else "f" * 64,
            "acceptance_ids": acceptance,
            "evidence": items,
            "missing_acceptance_ids": [
                acceptance_id
                for acceptance_id in acceptance
                if acceptance_id not in evidenced
            ],
        }

    @staticmethod
    def _observation(
        *,
        acceptance_id: str = "runtime",
        source: str = "runtime",
        reference: str = "runtime:revision-a",
        sha256: str = "a" * 64,
        status: str = "verified",
    ) -> dict[str, object]:
        return {
            "schema_version": evidence.SCHEMA_VERSION,
            "kind": evidence.OBSERVATION_KIND,
            "acceptance_id": acceptance_id,
            "source": source,
            "reference": reference,
            "sha256": sha256,
            "status": status,
        }

    def test_fake_hash_is_not_verified(self) -> None:
        result = evidence.assess_status(self._status())

        self.assertEqual("unverified", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])
        self.assertTrue(result["declared_hash_bound_completion"])
        self.assertTrue(result["false_confidence_risk"])

    def test_assessment_digest_binds_exact_obligation_records(self) -> None:
        status = self._status()
        first = evidence.assess_status(status)
        rebound = dict(status)
        rebound["open_file_sha256"] = "d" * 64
        second = evidence.assess_status(rebound)

        self.assertEqual(
            {
                "open_file_sha256": "e" * 64,
                "close_file_sha256": "f" * 64,
            },
            first["record_binding"],
        )
        self.assertNotEqual(first["assessment_sha256"], second["assessment_sha256"])

    def test_missing_evidence_is_classified_per_acceptance(self) -> None:
        result = evidence.assess_status(
            self._status(
                state="open",
                close_schema_version=None,
                stored_evidence=[],
            )
        )

        self.assertEqual(["runtime"], result["missing_acceptance_ids"])
        self.assertEqual("missing", result["acceptance"][0]["classification"])
        self.assertEqual(1, result["classifications"]["missing"])

    def test_wrong_revision_reference_is_mismatch(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={
                "runtime": self._observation(reference="runtime:revision-b")
            },
        )

        self.assertEqual("mismatch", result["acceptance"][0]["classification"])
        self.assertEqual(
            "observation_identity_mismatch", result["acceptance"][0]["reason"]
        )

    def test_stale_trusted_observation_is_stale(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={"runtime": self._observation(status="stale")},
        )

        self.assertEqual("stale", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])

    def test_only_typed_matching_observation_can_verify(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={"runtime": self._observation()},
        )

        self.assertEqual("verified", result["acceptance"][0]["classification"])
        self.assertTrue(result["fully_verified"])
        self.assertFalse(result["false_confidence_risk"])

        malformed = self._observation()
        malformed["kind"] = "caller.assertion"
        with self.assertRaisesRegex(evidence.EvidenceAssessmentError, "kind is invalid"):
            evidence.assess_status(
                self._status(), observations={"runtime": malformed}
            )

    def test_legacy_hash_bound_close_is_not_retroactively_verified(self) -> None:
        result = evidence.assess_status(
            self._status(close_schema_version=obligations.LEGACY_CLOSE_SCHEMA_VERSION)
        )

        self.assertTrue(result["legacy_close"])
        self.assertEqual(
            "legacy_unverifiable", result["acceptance"][0]["classification"]
        )
        self.assertFalse(result["fully_verified"])
        self.assertTrue(result["false_confidence_risk"])

    def test_human_assertion_is_unsupported_for_machine_verification(self) -> None:
        result = evidence.assess_status(
            self._status(
                stored_evidence=[self._stored_evidence(source="user")]
            )
        )

        self.assertEqual("unsupported", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])

    def test_sample_is_exactly_bounded_deterministic_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(Path(tmp) / "obligations")},
        ), patch.object(obligations.alert_outbox, "enqueue_and_schedule"):
            for index in range(evidence.MIN_ROLLOUT_SAMPLE):
                obligation_id = f"goo-shadow-sample-{index:04d}"
                obligations.open_obligation(
                    {
                        "obligation_id": obligation_id,
                        "objective": "Provide one deterministic completed sample record.",
                        "acceptance": [
                            {"id": "runtime", "description": "Runtime is correct."}
                        ],
                        "origin": {"source": "unit-test"},
                        "references": [],
                    }
                )
                obligations.close_obligation(
                    {
                        "obligation_id": obligation_id,
                        "outcome": "completed",
                        "closure_classification": {
                            "convergence_required": False,
                            "reason": "process_only",
                        },
                        "evidence": [
                            self._stored_evidence(
                                reference=f"runtime:sample-{index:04d}",
                                sha256=f"{index + 1:064x}",
                            )
                        ],
                    }
                )

            root = Path(os.environ["GRABOWSKI_OPERATOR_OBLIGATION_ROOT"])
            before = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }
            first = evidence.sample_completed()
            second = evidence.sample_completed()
            after = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }

        self.assertEqual(30, first["sample_size"])
        self.assertEqual(30, first["summary"]["total"])
        self.assertEqual(30, first["summary"]["acceptance_total"])
        self.assertEqual(0, first["summary"]["acceptance_verified"])
        self.assertEqual(30, first["summary"]["unverified"])
        self.assertEqual(0, first["summary"]["obligations_fully_verified"])
        self.assertEqual(
            30, first["summary"]["obligations_with_false_confidence_risk"]
        )
        self.assertEqual("verifiability_gap_observed", first["shadow_signal"])
        self.assertEqual(
            {"runtime": 30}, first["missing_adapter_source_counts"]
        )
        self.assertEqual(first["sample_sha256"], second["sample_sha256"])
        self.assertEqual(before, after)

    def test_sample_rejects_more_than_thirty(self) -> None:
        with self.assertRaisesRegex(evidence.EvidenceAssessmentError, "1 to 30"):
            evidence.sample_completed(31)


if __name__ == "__main__":
    unittest.main()
