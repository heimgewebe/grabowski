from __future__ import annotations

from pathlib import Path
import hashlib
import json
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligation
import grabowski_task_attention as attention
import grabowski_tasks as tasks
import grabowski_terminal_convergence as convergence


class TerminalConvergenceTests(unittest.TestCase):
    def test_failure_taxonomy_is_stable_and_fail_closed(self) -> None:
        base = {
            "current_state": "running",
            "resume_policy": "retry-safe",
            "terminal_evidence_valid": True,
            "lease_evidence_valid": True,
        }
        cases = [
            ({**base, "observed_state": "outcome_unknown"}, "outcome_unknown", False, True),
            ({**base, "observed_state": "failed", "terminal_evidence_valid": False}, "stale_process", False, True),
            ({**base, "observed_state": "failed", "lease_evidence_valid": False}, "evidence_drift", False, True),
            ({**base, "observed_state": "failed", "resume_policy": "manual"}, "non_retryable_failure", False, True),
            ({**base, "observed_state": "failed", "retry_count": 1, "retry_limit": 1}, "retry_exhausted", False, True),
            ({**base, "observed_state": "failed", "retry_count": 0, "retry_limit": 1}, "retry_safe_failure", True, False),
        ]
        for arguments, reason_class, automatic, owner_decision in cases:
            with self.subTest(reason_class=reason_class):
                result = convergence.classify_terminal_failure(**arguments)
                self.assertEqual(reason_class, result["reason_class"])
                self.assertIs(automatic, result["automatic_resume_allowed"])
                self.assertIs(owner_decision, result["owner_decision_required"])

    def test_terminal_lifecycle_truth_overrides_missing_unit_observation(self) -> None:
        record = {
            "task_id": "e" * 24,
            "state": "failed",
            "resume_policy": "retry-safe",
            "attempt": 1,
        }
        with patch.object(tasks, "_terminal_convergence_evidence", return_value=(True, True)):
            result = tasks._terminal_convergence_classification(
                record,
                {"state": "outcome_unknown"},
            )
        self.assertEqual("retry_safe_failure", result["reason_class"])
        self.assertTrue(result["automatic_resume_allowed"])

    def test_attention_convergence_is_idempotent_and_history_preserving(self) -> None:
        records = [
            {"task_id": "a" * 24, "attempt": 1, "updated_at_unix": 10, "lifecycle_receipt_sha256": "1" * 64},
            {"task_id": "a" * 24, "attempt": 1, "updated_at_unix": 10, "lifecycle_receipt_sha256": "1" * 64},
            {"task_id": "a" * 24, "attempt": 2, "updated_at_unix": 20, "lifecycle_receipt_sha256": "2" * 64},
            {"task_id": "b" * 24, "attempt": 1, "updated_at_unix": 30, "lifecycle_receipt_sha256": "3" * 64},
        ]
        first = convergence.converge_attention_records(records)
        second = convergence.converge_attention_records(records)
        self.assertEqual(first, second)
        self.assertEqual(4, first["raw_count"])
        self.assertEqual(2, first["current_count"])
        self.assertEqual(2, first["converged_count"])
        self.assertEqual(1, first["classification_counts"]["duplicate"])
        self.assertEqual(1, first["classification_counts"]["superseded"])
        self.assertEqual(4, len(first["current"]) + len(first["historical"]))

    @staticmethod
    def _failed_attention_record(
        task_id: str,
        created: int,
        receipt: str,
        terminalization: str,
    ) -> dict[str, object]:
        return {
            "task_id": task_id,
            "attempt": 1,
            "unit": f"grabowski-task-{task_id}-a1.service",
            "authoritative_unit": f"grabowski-task-{task_id}-a1.service",
            "execution_envelope_sha256": None,
            "host": "local",
            "argv_sha256": "9" * 64,
            "cwd": "/repo",
            "resource_keys_json": '["path:/repo/out"]',
            "runtime_seconds": 60,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "resume_policy": "never",
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": None,
            "chronik_context_json": '{"bureau_task_id":"T001"}',
            "execution_backend": "systemd-user",
            "systemd_scope": "user",
            "state": "failed",
            "created_at_unix": created,
            "updated_at_unix": created,
            "terminalized_at_unix": created,
            "terminalization_sha256": terminalization * 64,
            "lifecycle_receipt_sha256": receipt * 64,
            "launcher_json": "{}",
        }

    def test_attention_convergence_keeps_independent_identical_failures(self) -> None:
        older = self._failed_attention_record("1" * 24, 10, "a", "c")
        newer = self._failed_attention_record("2" * 24, 20, "b", "d")
        result = convergence.converge_attention_records([older, newer])
        self.assertEqual(2, result["current_count"])
        self.assertEqual(
            0,
            result["classification_counts"]["superseded_by_verified_retry"],
        )
        projection = attention.current_attention_projection([older, newer])
        self.assertEqual(2, projection["raw_attention_count"])
        self.assertEqual(2, projection["deduplicated_attention_count"])
        self.assertEqual(2, projection["current_attention_count"])
        self.assertEqual(0, projection["convergence_excluded_attention_count"])

    def test_attention_convergence_excludes_only_persisted_verified_retry_source(self) -> None:
        older = self._failed_attention_record("1" * 24, 10, "a", "c")
        newer = self._failed_attention_record("2" * 24, 20, "b", "d")
        identity = convergence.attention_execution_identity(older)
        assert identity is not None
        material = {
            "schema_version": 1,
            "kind": "grabowski_named_terminal_retry",
            "source_task_id": older["task_id"],
            "source_attempt": older["attempt"],
            "source_state": older["state"],
            "source_resume_policy": older["resume_policy"],
            "source_lifecycle_receipt_sha256": older[
                "lifecycle_receipt_sha256"
            ],
            "source_terminalization_sha256": older[
                "terminalization_sha256"
            ],
            "source_execution_identity_sha256": identity,
            "named_state_change": "repository head advanced",
            "observed_at_unix": 15,
            "does_not_establish": [
                "that_the_named_change_is_sufficient",
                "that_the_retry_will_succeed",
                "automatic_retry_authority",
            ],
        }
        binding = {
            **material,
            "context_sha256": hashlib.sha256(
                json.dumps(
                    material,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        }
        newer["launcher_json"] = json.dumps(
            {"retry_binding": binding},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        result = convergence.converge_attention_records([older, newer])
        self.assertEqual(["2" * 24], [item["task_id"] for item in result["current"]])
        self.assertEqual(1, result["classification_counts"]["superseded_by_verified_retry"])
        self.assertEqual(1, result["verified_retry_edge_count"])
        historical = result["historical"][0]
        self.assertEqual("1" * 24, historical["task_id"])
        self.assertEqual("2" * 24, historical["successor_task_id"])
        self.assertEqual(binding["context_sha256"], historical["retry_context_sha256"])
        self.assertIs(True, historical["retry_binding_verified"])
        self.assertIs(False, historical["success_claimed"])

        projection = attention.current_attention_projection([older, newer])
        self.assertEqual(2, projection["raw_attention_count"])
        self.assertEqual(1, projection["deduplicated_attention_count"])
        self.assertEqual(1, projection["current_attention_count"])
        self.assertEqual(1, projection["convergence_excluded_attention_count"])
        self.assertIn("1" * 24, projection["excluded_task_ids"])

    def test_attention_convergence_uses_non_attention_retry_successor_as_support(self) -> None:
        source = self._failed_attention_record("1" * 24, 10, "a", "c")
        successor = self._failed_attention_record("2" * 24, 20, "b", "d")
        identity = convergence.attention_execution_identity(source)
        assert identity is not None
        material = {
            "schema_version": 1,
            "kind": "grabowski_named_terminal_retry",
            "source_task_id": source["task_id"],
            "source_attempt": source["attempt"],
            "source_state": source["state"],
            "source_resume_policy": source["resume_policy"],
            "source_lifecycle_receipt_sha256": source["lifecycle_receipt_sha256"],
            "source_terminalization_sha256": source["terminalization_sha256"],
            "source_execution_identity_sha256": identity,
            "named_state_change": "repository head advanced",
            "observed_at_unix": 15,
            "does_not_establish": [
                "that_the_named_change_is_sufficient",
                "that_the_retry_will_succeed",
                "automatic_retry_authority",
            ],
        }
        successor["state"] = "running"
        successor["terminalized_at_unix"] = None
        successor["terminalization_sha256"] = None
        successor["lifecycle_receipt_sha256"] = None
        successor["launcher_json"] = json.dumps(
            {
                "retry_binding": {
                    **material,
                    "context_sha256": hashlib.sha256(
                        json.dumps(
                            material,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest(),
                }
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        result = convergence.converge_attention_records(
            [source, successor],
            attention_task_ids={str(source["task_id"])},
        )
        self.assertEqual([], result["current"])
        self.assertEqual(1, result["raw_count"])
        self.assertEqual(1, result["support_record_count"])
        self.assertEqual(1, result["verified_retry_edge_count"])

        projection = attention.current_attention_projection(
            [source],
            retry_successor_records=[successor],
        )
        self.assertEqual(1, projection["raw_attention_count"])
        self.assertEqual(0, projection["current_attention_count"])
        self.assertEqual(1, projection["retry_successor_record_count"])
        self.assertIn(source["task_id"], projection["excluded_task_ids"])

        successor["state"] = "completed"
        with self.assertRaisesRegex(
            convergence.TerminalConvergenceError,
            "completed retry successor terminal evidence is invalid",
        ):
            convergence.converge_attention_records(
                [source, successor],
                attention_task_ids={str(source["task_id"])},
            )
        successor["terminalized_at_unix"] = 25
        successor["terminalization_sha256"] = "d" * 64
        successor["lifecycle_receipt_sha256"] = "b" * 64
        completed = convergence.converge_attention_records(
            [source, successor],
            attention_task_ids={str(source["task_id"])},
        )
        self.assertEqual([], completed["current"])
        self.assertEqual(1, completed["verified_retry_edge_count"])

    def test_attention_convergence_rejects_tampered_persisted_retry_binding(self) -> None:
        older = self._failed_attention_record("1" * 24, 10, "a", "c")
        newer = self._failed_attention_record("2" * 24, 20, "b", "d")
        newer["launcher_json"] = json.dumps(
            {
                "retry_binding": {
                    "schema_version": 1,
                    "kind": "grabowski_named_terminal_retry",
                    "source_task_id": older["task_id"],
                    "source_attempt": 1,
                    "source_state": "failed",
                    "source_resume_policy": "never",
                    "source_lifecycle_receipt_sha256": "a" * 64,
                    "source_terminalization_sha256": "c" * 64,
                    "source_execution_identity_sha256": "9" * 64,
                    "named_state_change": "repository head advanced",
                    "observed_at_unix": 15,
                    "does_not_establish": [],
                    "context_sha256": "0" * 64,
                }
            }
        )
        with self.assertRaisesRegex(
            convergence.TerminalConvergenceError,
            "integrity",
        ):
            convergence.converge_attention_records([older, newer])

    def test_attention_execution_identity_keeps_distinct_work_contexts(self) -> None:
        base = {
            "task_id": "5" * 24,
            "attempt": 1,
            "unit": f"grabowski-task-{'5' * 24}-a1.service",
            "authoritative_unit": f"grabowski-task-{'5' * 24}-a1.service",
            "execution_envelope_sha256": None,
            "host": "local",
            "argv_sha256": "7" * 64,
            "cwd": "/repo",
            "resource_keys_json": "[]",
            "runtime_seconds": 60,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "resume_policy": "never",
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": None,
            "chronik_context_json": '{"bureau_task_id":"T001"}',
            "execution_backend": "systemd-user",
            "systemd_scope": "user",
            "state": "failed",
            "created_at_unix": 10,
            "updated_at_unix": 10,
            "lifecycle_receipt_sha256": "e" * 64,
        }
        changed = {
            **base,
            "task_id": "6" * 24,
            "unit": f"grabowski-task-{'6' * 24}-a1.service",
            "authoritative_unit": f"grabowski-task-{'6' * 24}-a1.service",
            "created_at_unix": 20,
            "updated_at_unix": 20,
            "chronik_context_json": '{"bureau_task_id":"T002"}',
            "lifecycle_receipt_sha256": "f" * 64,
        }
        result = convergence.converge_attention_records([base, changed])
        self.assertEqual(2, result["current_count"])
        self.assertEqual(
            0,
            result["classification_counts"]["superseded_by_verified_retry"],
        )

    def test_attention_execution_identity_does_not_collapse_changed_limits(self) -> None:
        base = {
            "task_id": "3" * 24,
            "attempt": 1,
            "host": "local",
            "argv_sha256": "8" * 64,
            "cwd": "/repo",
            "resource_keys_json": "[]",
            "runtime_seconds": 60,
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "resume_policy": "never",
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": None,
            "chronik_context_json": '{"bureau_task_id":"T001"}',
            "execution_backend": "systemd-user",
            "systemd_scope": "user",
            "state": "failed",
            "created_at_unix": 10,
            "updated_at_unix": 10,
            "lifecycle_receipt_sha256": "c" * 64,
        }
        changed = {
            **base,
            "task_id": "4" * 24,
            "created_at_unix": 20,
            "updated_at_unix": 20,
            "runtime_seconds": 120,
            "lifecycle_receipt_sha256": "d" * 64,
        }
        result = convergence.converge_attention_records([base, changed])
        self.assertEqual(2, result["current_count"])
        self.assertEqual(0, result["classification_counts"]["superseded_by_verified_retry"])

    def test_task_attention_projection_converges_duplicate_rows(self) -> None:
        base = {
            "task_id": "c" * 24,
            "attempt": 1,
            "unit": f"grabowski-task-{'c' * 24}-a1.service",
            "authoritative_unit": f"grabowski-task-{'c' * 24}-a1.service",
            "argv_sha256": "4" * 64,
            "execution_envelope_sha256": None,
            "state": "failed",
            "lifecycle_receipt_sha256": "5" * 64,
            "updated_at_unix": 10,
        }
        projection = attention.current_attention_projection([base, dict(base)])
        self.assertEqual(2, projection["raw_attention_count"])
        self.assertEqual(1, projection["deduplicated_attention_count"])
        self.assertEqual(1, projection["converged_attention_count"])
        self.assertEqual(1, projection["attention_convergence_counts"]["duplicate"])

    def test_completed_task_obligation_requires_current_receipt(self) -> None:
        task_id = "d" * 24
        open_record = {
            "references": [
                {
                    "kind": "grabowski_task",
                    "id": task_id,
                    "observation_tool": "grabowski_task_status",
                }
            ]
        }
        record = {
            "task_id": task_id,
            "attempt": 2,
            "state": "completed",
            "lifecycle_receipt_sha256": "6" * 64,
        }
        closeout = {
            "terminal": True,
            "lifecycle_evidence_valid": True,
            "outcome_receipt_sha256": "6" * 64,
            "task_binding": {"task_id": task_id, "attempt": 2},
            "closeout_state": "ready_to_archive",
        }
        evidence = [
            {
                "acceptance_id": "verification",
                "status": "passed",
                "source": "receipt",
                "reference": f"task:{task_id}",
                "sha256": "6" * 64,
            }
        ]
        with (
            patch.object(tasks, "_row", return_value=record),
            patch.object(attention, "terminal_closeout_plan", return_value=closeout),
        ):
            binding = obligation._validate_completed_task_closeout(open_record, evidence)
        self.assertEqual(task_id, binding["task_id"])
        self.assertEqual("6" * 64, binding["lifecycle_receipt_sha256"])

        drifted = [{**evidence[0], "sha256": "7" * 64}]
        with (
            patch.object(tasks, "_row", return_value=record),
            patch.object(attention, "terminal_closeout_plan", return_value=closeout),
        ):
            with self.assertRaisesRegex(obligation.OperatorObligationInputError, "current lifecycle receipt"):
                obligation._validate_completed_task_closeout(open_record, drifted)


if __name__ == "__main__":
    unittest.main()
