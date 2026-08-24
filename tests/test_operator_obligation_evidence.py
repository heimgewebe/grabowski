from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
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

    def test_free_form_reference_never_self_attests(self) -> None:
        status = self._status(
            stored_evidence=[
                self._stored_evidence(
                    source="github",
                    reference="PR #1 looked green when I checked it",
                )
            ]
        )
        observations = evidence.collect_trusted_observations(status)

        self.assertEqual({}, observations)
        result = evidence.assess_status(status, observations=observations)
        self.assertEqual("unverified", result["acceptance"][0]["classification"])

    def test_github_adapter_binds_exact_merged_pr_and_check_count(self) -> None:
        parsed = {
            "repo": "heimgewebe/grabowski",
            "pr": 919,
            "head": "1" * 40,
            "base": "2" * 40,
            "merge": "3" * 40,
            "passed": 2,
            "total": 2,
        }
        reference = (
            "github-pr:heimgewebe/grabowski#919@"
            + parsed["head"]
            + ":base="
            + parsed["base"]
            + ":merge="
            + parsed["merge"]
            + ":checks=2/2-success"
        )
        digest = evidence._sha256(evidence._github_observation_material(parsed))
        payload = {
            "state": "MERGED",
            "isDraft": False,
            "baseRefOid": parsed["base"],
            "headRefOid": parsed["head"],
            "mergeCommit": {"oid": parsed["merge"]},
            "statusCheckRollup": [
                {
                    "__typename": "CheckRun",
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                },
                {"__typename": "StatusContext", "state": "SUCCESS"},
            ],
        }
        stored = self._stored_evidence(
            source="github", reference=reference, sha256=digest
        )
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            observation = evidence._github_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(digest, observation["sha256"])

        payload["headRefOid"] = "4" * 40
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            mismatch = evidence._github_observation(stored)
        assert mismatch is not None
        self.assertEqual("mismatch", mismatch["status"])

    def test_git_adapter_hashes_exact_commit_payload(self) -> None:
        commit_payload = b"tree " + b"a" * 40 + b"\n\nmessage\n"
        digest = hashlib.sha256(commit_payload).hexdigest()
        stored = self._stored_evidence(
            source="git",
            reference="git-commit:heimgewebe/grabowski@" + "b" * 40,
            sha256=digest,
        )
        with patch.object(evidence, "_local_git_repo", return_value=Path("/tmp/repo")), patch.object(
            evidence, "_run_command", return_value=(0, commit_payload, b"")
        ):
            observation = evidence._git_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(digest, observation["sha256"])

    def test_receipt_adapter_hashes_only_bound_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GRABOWSKI_EVIDENCE_RECEIPT_ROOT": tmp}
        ):
            root = Path(tmp)
            path = root / "grip-receipts" / "sample.json"
            path.parent.mkdir(mode=0o700)
            payload = b'{"status":"passed"}\n'
            path.write_bytes(payload)
            path.chmod(0o600)
            digest = hashlib.sha256(payload).hexdigest()
            stored = self._stored_evidence(
                source="receipt",
                reference="grabowski-receipt:grip-receipts/sample.json",
                sha256=digest,
            )
            observation = evidence._receipt_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(digest, observation["sha256"])

    def test_runtime_adapter_binds_exact_active_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_EVIDENCE_DEPLOYMENT_MANIFEST": str(Path(tmp) / "manifest.json")},
        ):
            runtime_input = "7" * 64
            repo_head = "8" * 40
            release_id = "release-verified-1234567890"
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "completion_status": "complete",
                        "repo_head": repo_head,
                        "release_id": release_id,
                        "runtime_input_sha256": runtime_input,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            stored = self._stored_evidence(
                source="runtime",
                reference=(
                    f"grabowski-runtime-manifest:repo_head={repo_head};"
                    f"release_id={release_id};runtime_input_sha256={runtime_input}"
                ),
                sha256=runtime_input,
            )
            observation = evidence._runtime_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(runtime_input, observation["sha256"])

    def test_test_adapter_binds_terminal_task_receipt_and_exact_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "GRABOWSKI_EVIDENCE_TASK_DATABASE": str(Path(tmp) / "tasks.sqlite3"),
                "GRABOWSKI_EVIDENCE_TASK_OUTPUT_ROOT": str(Path(tmp) / "task-output"),
            },
        ):
            task_id = "a" * 24
            lifecycle_receipt = "9" * 64
            connection = sqlite3.connect(Path(tmp) / "tasks.sqlite3")
            try:
                connection.execute(
                    "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, attempt INTEGER, state TEXT, lifecycle_receipt_sha256 TEXT)"
                )
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?, ?)",
                    (task_id, 1, "completed", lifecycle_receipt),
                )
                connection.commit()
            finally:
                connection.close()
            output = (
                Path(tmp)
                / "task-output"
                / f".grabowski-task-output-{task_id}-a1"
            )
            output.mkdir(parents=True, mode=0o700)
            (output / "stdout.log").write_text(
                "..................................................... [100%]\n"
                "53 passed, 19 subtests passed in 0.20s\n",
                encoding="utf-8",
            )
            (output / "stdout.log").chmod(0o600)
            stored = self._stored_evidence(
                source="test",
                reference=f"grabowski-task:{task_id}:53-passed+19-subtests",
                sha256=lifecycle_receipt,
            )
            observation = evidence._test_observation(stored)

            self.assertIsNotNone(observation)
            assert observation is not None
            self.assertEqual("verified", observation["status"])
            self.assertEqual(lifecycle_receipt, observation["sha256"])

            stored["reference"] = f"grabowski-task:{task_id}:54-passed+19-subtests"
            mismatch = evidence._test_observation(stored)
            assert mismatch is not None
            self.assertEqual("mismatch", mismatch["status"])

    def test_matching_adapter_observation_flows_through_public_assessment(self) -> None:
        stored = self._stored_evidence(
            source="receipt",
            reference="grabowski-receipt:sample.json",
            sha256="a" * 64,
        )
        status = self._status(stored_evidence=[stored])
        trusted = self._observation(
            source="receipt",
            reference="grabowski-receipt:sample.json",
        )
        with patch.object(
            evidence,
            "collect_trusted_observations",
            return_value={"runtime": trusted},
        ), patch.object(obligations, "status_obligation", return_value=status):
            result = evidence.assess_obligation("goo-shadow-evidence-test-0001")

        self.assertTrue(result["fully_verified"])
        self.assertEqual("verified", result["acceptance"][0]["classification"])

    def test_sample_selection_is_schema_stratified_and_input_order_independent(self) -> None:
        legacy = [
            {
                "obligation_id": f"goo-legacy-sample-{index:04d}",
                "close_schema_version": obligations.LEGACY_CLOSE_SCHEMA_VERSION,
            }
            for index in range(40)
        ]
        current = [
            {
                "obligation_id": f"goo-current-sample-{index:04d}",
                "close_schema_version": obligations.CLOSE_SCHEMA_VERSION,
            }
            for index in range(5)
        ]
        population = legacy + current

        first = evidence._select_sample_population(population, 30)
        second = evidence._select_sample_population(list(reversed(population)), 30)

        first_ids = [item["obligation_id"] for item in first]
        self.assertEqual(first_ids, [item["obligation_id"] for item in second])
        self.assertEqual(30, len(first_ids))
        self.assertTrue(
            {item["obligation_id"] for item in current}.issubset(set(first_ids))
        )
        self.assertEqual(
            25,
            sum(
                item["close_schema_version"]
                == obligations.LEGACY_CLOSE_SCHEMA_VERSION
                for item in first
            ),
        )

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
        self.assertEqual(30, first["population_completed_total"])
        self.assertEqual({"2": 30}, first["population_close_schema_counts"])
        self.assertEqual({"2": 30}, first["sample_close_schema_counts"])
        self.assertEqual("schema_stratified_sha256_rank_v1", first["selection_order"])
        self.assertFalse(first["selection_scan_truncated"])
        self.assertEqual([], first["selection_integrity_errors"])
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
            ["github", "git", "receipt", "runtime", "test"],
            first["trusted_observation_adapter_sources"],
        )
        self.assertEqual({}, first["trusted_observation_counts"])
        self.assertEqual(
            {"runtime": 30}, first["missing_adapter_source_counts"]
        )
        self.assertFalse(first["rollout_eligible"])
        self.assertEqual(
            "stop_verifiability_threshold_not_met", first["rollout_decision"]
        )
        self.assertFalse(first["verified_completion_enforcement_enabled"])
        self.assertTrue(first["rollout_threshold"]["enforcement_change_separate"])
        self.assertEqual(first["sample_sha256"], second["sample_sha256"])
        self.assertEqual(before, after)

    def test_sample_rejects_more_than_thirty(self) -> None:
        with self.assertRaisesRegex(evidence.EvidenceAssessmentError, "1 to 30"):
            evidence.sample_completed(31)


if __name__ == "__main__":
    unittest.main()
