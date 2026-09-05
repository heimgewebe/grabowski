from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligation


class OperatorObligationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "operator-obligations"
        self.environment = patch.dict(
            os.environ,
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(self.root)},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.alerts = patch.object(
            obligation.alert_outbox,
            "enqueue_and_schedule",
        )
        self.alerts.start()
        self.addCleanup(self.alerts.stop)

    @staticmethod
    def _open_parameters(obligation_id: str = "goo-example-work-0001") -> dict[str, object]:
        return {
            "obligation_id": obligation_id,
            "objective": "Complete the requested operator work with evidence.",
            "acceptance": [
                {"id": "implementation", "description": "Implementation exists."},
                {"id": "verification", "description": "Verification passed."},
            ],
            "origin": {
                "thread_id": "thread-17",
                "source": "chatgpt-via-grabowski",
                "repo": "/home/alex/repos/grabowski",
            },
            "references": [],
        }

    @staticmethod
    def _delegation(status: str) -> dict[str, str]:
        material = {
            "kind": "systemd_job",
            "id": "grabowski-job-17",
            "observation_tool": "grabowski_job_status",
            "status": status,
            "observed_at": "2026-07-15T14:00:00Z",
            "identity_sha256": "c" * 64,
        }
        return {
            **material,
            "observation_receipt_sha256": obligation._sha256(material),
        }

    @staticmethod
    def _passed_evidence() -> list[dict[str, str]]:
        return [
            {
                "acceptance_id": "implementation",
                "status": "passed",
                "source": "git",
                "reference": "commit:0123456789abcdef",
                "sha256": "1" * 64,
            },
            {
                "acceptance_id": "verification",
                "status": "passed",
                "source": "test",
                "reference": "python -m unittest tests.test_operator_obligation",
                "sha256": "2" * 64,
            },
        ]

    @staticmethod
    def _process_only() -> dict[str, object]:
        return {"convergence_required": False, "reason": "process_only"}

    @staticmethod
    def _system_convergence_plan(
        *,
        gate: str = "hard",
        change_risk: str = "R2",
        target_criticality: str = "essential",
        protocol_head: str = "a" * 40,
    ) -> dict[str, object]:
        material: dict[str, object] = {
            "schema_version": 1,
            "kind": "grabowski.system_convergence_plan",
            "status": "planned",
            "change_risk": change_risk,
            "target_criticality": target_criticality,
            "protocol_head": protocol_head,
            "profile_id": "profile-test",
            "profile_cell_id": "cell-test",
            "profile_sha256": "e" * 64,
            "protocol_source": "immutable_bundle",
            "bundle_identity_sha256": "f" * 64,
            "wheel_sha256": "0" * 64,
            "required_effects": [],
            "required_verifications": [],
            "required_closure_fields": [],
            "requires_resilience_evidence": gate == "hard",
            "requires_independent_recovery": gate == "hard",
            "systemic_closure_gate": gate,
            "hard_gate_required": True if gate == "hard" else False,
            "criticality_resolution_required": gate == "classification_required",
            "admission_blocking": False,
            "next_action": "test convergence plan",
            "does_not_establish": ["systemic convergence"],
        }
        return {**material, "plan_sha256": obligation._sha256(material)}

    def _convergence_receipt(
        self,
        obligation_id: str,
        *,
        target_obligation_id: str | None = None,
        assessment_status: str = "terminally_closed",
        assessment_schema_version: int = 2,
    ) -> dict[str, object]:
        target_id = target_obligation_id or obligation_id
        assessment_id = f"assessment-{obligation_id}"
        request = {
            "assessment_id": assessment_id,
            "closure": {
                "schema_version": 1,
                "closure_id": f"operator-obligation:{target_id}",
                "status": "closed",
                "residual_risks": [],
            },
        }
        raw = json.dumps(
            request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request_path = (Path(self.temporary.name) / f"{obligation_id}-convergence.json").resolve()
        request_path.write_bytes(raw)
        request_sha256 = hashlib.sha256(raw).hexdigest()
        protocol_head = "a" * 40
        allowed = assessment_status == "terminally_closed"
        output = {
            "schema_version": 1,
            "kind": "grabowski.convergence_assessment",
            "request_path": str(request_path),
            "request_sha256": request_sha256,
            "protocol_repo": None,
            "protocol_head": protocol_head,
            "protocol_source": "immutable_bundle",
            "bundle_manifest_path": "/tmp/bundle.json",
            "bundle_identity_sha256": "b" * 64,
            "contracts_sha256": "c" * 64,
            "executable_sha256": "d" * 64,
            "assessment": {
                "schema_version": assessment_schema_version,
                "assessment_id": assessment_id,
                "status": assessment_status,
                "change_risk": "R2",
                "target_criticality": "essential",
                "profile_id": "profile-test",
                "profile_cell_id": "cell-test",
                "profile_sha256": "e" * 64,
            },
            "closure_allowed": allowed,
            "decision": "allow_closure" if allowed else "block_closure",
            "does_not_establish": [],
            "receipt_status": "passed" if allowed else "blocked",
        }
        parameters = {
            "request_path": str(request_path),
            "expected_request_sha256": request_sha256,
            "expected_protocol_head": protocol_head,
        }
        check_status = "pass" if allowed else "fail"
        receipt = {
            "kind": "grabowski.operator_grip_receipt",
            "schema_version": 1,
            "grip": {"name": "convergence-assess", "version": "1.0", "effect": "read_only"},
            "status": "passed" if allowed else "blocked",
            "phase": "action",
            "started_at": "2026-08-22T05:00:00Z",
            "ended_at": "2026-08-22T05:00:01Z",
            "parameters_sha256": obligation._sha256(parameters),
            "acceptance_ids": [
                "protocol-identity-bound",
                "request-hash-bound",
                "deterministic-assessment",
                "terminal-closure-gate",
            ],
            "checks": [
                {"id": "protocol-identity-bound", "status": "pass", "detail": protocol_head},
                {"id": "request-hash-bound", "status": "pass", "detail": request_sha256},
                {"id": "deterministic-assessment", "status": "pass", "detail": assessment_id},
                {"id": "terminal-closure-gate", "status": check_status, "detail": assessment_status},
            ],
            "output_sha256": obligation._sha256(output),
        }
        receipt["receipt_sha256"] = obligation._sha256(receipt)
        return {
            "status": receipt["status"],
            "receipt_sha256": receipt["receipt_sha256"],
            "receipt": receipt,
            "output": output,
        }

    @staticmethod
    def _rehash_grip_result(result: dict[str, object]) -> None:
        receipt = result["receipt"]
        output = result["output"]
        assert isinstance(receipt, dict)
        assert isinstance(output, dict)
        receipt["output_sha256"] = obligation._sha256(output)
        receipt.pop("receipt_sha256", None)
        receipt["receipt_sha256"] = obligation._sha256(receipt)
        result["receipt_sha256"] = receipt["receipt_sha256"]

    def test_open_is_private_idempotent_and_requires_continuation(self) -> None:
        first = obligation.open_obligation(self._open_parameters())
        second = obligation.open_obligation(self._open_parameters())
        status_value = obligation.status_obligation("goo-example-work-0001")

        self.assertTrue(first["created"])
        self.assertFalse(first["response_may_end"])
        self.assertTrue(first["continuation_required"])
        self.assertTrue(first["follow_up_required"])
        self.assertFalse(first["work_complete"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["open_file_sha256"], second["open_file_sha256"])
        self.assertEqual(status_value["state"], "open")
        self.assertEqual(
            status_value["missing_acceptance_ids"],
            ["implementation", "verification"],
        )
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        directory = self.root / "goo-example-work-0001"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "open.json").stat().st_mode), 0o600)

    def test_projection_rejects_gate_outcome_drift_from_classification(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan(gate="hard")
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            status = obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": False,
                        "reason": "process_only",
                        "system_convergence_plan": plan,
                    },
                    "evidence": self._passed_evidence(),
                }
            )
        status["convergence_gate_outcome"] = "explicit_non_systemic"
        with self.assertRaisesRegex(
            obligation.OperatorObligationIntegrityError,
            "disagrees with classification",
        ):
            obligation._status_projection_requires_attention(status)

    def test_list_finds_open_work_by_origin_without_claiming_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        other = self._open_parameters("goo-other-thread-0002")
        other["origin"] = {"thread_id": "thread-99", "repo": "/other"}
        obligation.open_obligation(other)

        result = obligation.list_obligations(
            {
                "state": "open",
                "repo": "/home/alex/repos/grabowski",
                "thread_id": "thread-17",
                "limit": 10,
            }
        )

        self.assertEqual(1, result["record_count"])
        self.assertEqual("goo-example-work-0001", result["records"][0]["obligation_id"])
        self.assertTrue(result["records"][0]["continuation_required"])
        self.assertFalse(result["records"][0]["response_may_end"])
        self.assertTrue(result["attention_required"])

    def test_default_list_keeps_all_unfinished_work_visible(self) -> None:
        blocked = self._open_parameters("goo-blocked-work-0002")
        delegated = self._open_parameters("goo-delegated-work-0003")
        completed = self._open_parameters("goo-completed-work-0004")
        open_work = self._open_parameters("goo-open-work-0005")
        for parameters in (blocked, delegated, completed, open_work):
            obligation.open_obligation(parameters)
        obligation.close_obligation(
            {
                "obligation_id": "goo-blocked-work-0002",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "foreign-lease",
                        "detail": "Exact overlap remains active.",
                        "reference": "lease:owner-17",
                        "sha256": "3" * 64,
                    }
                ],
                "next_action": "Recheck the lease and open a successor obligation.",
            }
        )
        obligation.close_obligation(
            {
                "obligation_id": "goo-delegated-work-0003",
                "outcome": "delegated",
                "evidence": [],
                "delegation": self._delegation("running"),
                "next_action": "Observe the durable job and open a successor obligation.",
            }
        )
        obligation.close_obligation(
            {
                "obligation_id": "goo-completed-work-0004",
                "outcome": "completed",
                    "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )

        result = obligation.list_obligations()
        explicit_attention = obligation.list_obligations({"state": "attention"})
        open_only = obligation.list_obligations({"state": "open"})
        states = {item["obligation_id"]: item["state"] for item in result["records"]}

        self.assertEqual("attention", result["state_filter"])
        self.assertEqual(result["records"], explicit_attention["records"])
        self.assertEqual(
            {
                "goo-blocked-work-0002": "blocked",
                "goo-delegated-work-0003": "delegated",
                "goo-open-work-0005": "open",
            },
            states,
        )
        self.assertEqual(
            ["goo-open-work-0005"],
            [item["obligation_id"] for item in open_only["records"]],
        )
        self.assertTrue(result["attention_required"])
        self.assertTrue(all(item["continuation_required"] for item in result["records"]))

        summary = obligation.list_obligations(
            {"state": "attention", "summary_only": True}
        )
        self.assertEqual(3, summary["record_count"])
        self.assertEqual([], summary["records"])
        self.assertTrue(summary["attention_required"])

    def test_attention_resurfacing_orders_due_work_before_recent_work(self) -> None:
        with patch.object(
            obligation, "_utc_now", return_value="2026-09-01T00:00:00Z"
        ):
            obligation.open_obligation(
                self._open_parameters("goo-zzz-overdue-0002")
            )
        with patch.object(
            obligation, "_utc_now", return_value="2026-09-02T18:00:00Z"
        ):
            obligation.open_obligation(
                self._open_parameters("goo-aaa-recent-0001")
            )

        result = obligation.list_obligations(
            {
                "state": "attention",
                "as_of": "2026-09-03T00:00:00Z",
                "attention_due_after_seconds": 86_400,
                "limit": 2,
            }
        )

        self.assertEqual(
            ["goo-zzz-overdue-0002", "goo-aaa-recent-0001"],
            [item["obligation_id"] for item in result["records"]],
        )
        overdue, recent = result["records"]
        self.assertTrue(overdue["attention_due"])
        self.assertEqual("due", overdue["attention_priority"])
        self.assertEqual(172_800, overdue["attention_age_seconds"])
        self.assertEqual("2026-09-02T00:00:00Z", overdue["attention_due_at"])
        self.assertFalse(recent["attention_due"])
        self.assertEqual("recent", recent["attention_priority"])
        self.assertEqual(21_600, recent["attention_age_seconds"])
        self.assertEqual(1, result["attention_resurfacing"]["due_count"])
        self.assertEqual(1, result["attention_resurfacing"]["recent_count"])
        self.assertEqual(
            "due_then_oldest_first",
            result["attention_resurfacing"]["ordering"],
        )
        self.assertIn(
            "oldest due", result["recommended_next_action"]
        )

    def test_attention_resurfacing_inputs_are_bounded_and_canonical(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaisesRegex(
            obligation.OperatorObligationInputError,
            "attention_due_after_seconds",
        ):
            obligation.list_obligations(
                {"attention_due_after_seconds": 59}
            )
        with self.assertRaisesRegex(
            obligation.OperatorObligationInputError, "as_of"
        ):
            obligation.list_obligations({"as_of": "2026-09-03 00:00:00"})

    def test_list_reports_projection_drift_as_attention_integrity_error(self) -> None:
        obligation.open_obligation(self._open_parameters())
        original_status = obligation.status_obligation

        def incomplete_status(obligation_id: str) -> dict[str, object]:
            status = original_status(obligation_id)
            status.pop("work_complete")
            return status

        with patch.object(obligation, "status_obligation", side_effect=incomplete_status):
            result = obligation.list_obligations()

        self.assertEqual([], result["records"])
        self.assertEqual(
            [
                {
                    "obligation_id": "goo-example-work-0001",
                    "error": "OperatorObligationIntegrityError",
                }
            ],
            result["integrity_errors"],
        )
        self.assertTrue(result["attention_required"])
        self.assertEqual(
            "inspect integrity errors before relying on the affected obligations",
            result["recommended_next_action"],
        )

    def test_same_id_cannot_be_rebound_to_different_work(self) -> None:
        obligation.open_obligation(self._open_parameters())
        changed = self._open_parameters()
        changed["objective"] = "Different work"
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.open_obligation(changed)

    def test_completed_close_requires_explicit_classification(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaisesRegex(
            obligation.OperatorObligationCompletionClassificationError,
            "requires closure_classification",
        ):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "evidence": self._passed_evidence(),
                }
            )
        self.assertEqual("open", obligation.status_obligation("goo-example-work-0001")["state"])

    def test_process_only_completion_is_explicitly_non_systemic(self) -> None:
        obligation.open_obligation(self._open_parameters())
        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )
        self.assertEqual(obligation.CLOSE_SCHEMA_VERSION, result["close_schema_version"])
        self.assertEqual("process_only", result["completion_scope"])
        self.assertFalse(result["systemic_convergence_claim"])
        self.assertIn("does not establish systemic convergence", result["non_claims"][0])

    def test_systemic_completion_requires_exact_terminal_convergence_receipt(self) -> None:
        obligation.open_obligation(self._open_parameters())
        convergence_receipt = self._convergence_receipt("goo-example-work-0001")
        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "closure_classification": {
                    "convergence_required": True,
                    "reason": "systemic",
                    "convergence_receipt": convergence_receipt,
                },
                "evidence": self._passed_evidence(),
            }
        )
        self.assertEqual("systemic", result["completion_scope"])
        self.assertTrue(result["systemic_convergence_claim"])
        self.assertEqual(
            convergence_receipt["receipt_sha256"],
            result["completion_classification"]["convergence_receipt_sha256"],
        )
        self.assertEqual([], result["non_claims"])

    def test_process_only_hard_plan_is_explicit_non_systemic_bypass(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan(gate="hard")
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            result = obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": False,
                        "reason": "process_only",
                        "system_convergence_plan": plan,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

        self.assertEqual("process_only", result["completion_scope"])
        self.assertFalse(result["systemic_convergence_claim"])
        self.assertEqual(
            "explicit_non_systemic_bypass", result["convergence_gate_outcome"]
        )
        self.assertEqual(
            plan["plan_sha256"],
            result["completion_classification"]["system_convergence_plan"][
                "plan_sha256"
            ],
        )
        self.assertIn(
            "explicitly bypassed a bound systemic convergence gate",
            " ".join(result["non_claims"]),
        )

    def test_systemic_plan_must_match_assessment_profile_cell(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan()
        receipt = self._convergence_receipt("goo-example-work-0001")
        receipt["output"]["assessment"]["change_risk"] = "R1"
        self._rehash_grip_result(receipt)
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            with self.assertRaisesRegex(
                obligation.OperatorObligationCompletionClassificationError,
                "change_risk",
            ):
                obligation.close_obligation(
                    {
                        "obligation_id": "goo-example-work-0001",
                        "outcome": "completed",
                        "closure_classification": {
                            "convergence_required": True,
                            "reason": "systemic",
                            "convergence_receipt": receipt,
                            "system_convergence_plan": plan,
                        },
                        "evidence": self._passed_evidence(),
                    }
                )

    def test_passed_convergence_receipt_rejects_auxiliary_failed_check(self) -> None:
        obligation.open_obligation(self._open_parameters())
        receipt = self._convergence_receipt("goo-example-work-0001")
        receipt["receipt"]["checks"].append(
            {"id": "resilience-evidence", "status": "fail", "detail": "missing"}
        )
        receipt["receipt"].pop("receipt_sha256")
        receipt["receipt"]["receipt_sha256"] = obligation._sha256(receipt["receipt"])
        receipt["receipt_sha256"] = receipt["receipt"]["receipt_sha256"]
        with self.assertRaisesRegex(
            obligation.OperatorObligationCompletionClassificationError,
            "explicitly failing check",
        ):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": True,
                        "reason": "systemic",
                        "convergence_receipt": receipt,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

    def test_system_convergence_plan_rejects_integer_hard_gate_flag(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan()
        plan["hard_gate_required"] = 1
        material = {key: value for key, value in plan.items() if key != "plan_sha256"}
        plan["plan_sha256"] = obligation._sha256(material)
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            with self.assertRaisesRegex(
                obligation.OperatorObligationCompletionClassificationError,
                "hard_gate_required",
            ):
                obligation.close_obligation(
                    {
                        "obligation_id": "goo-example-work-0001",
                        "outcome": "completed",
                        "closure_classification": {
                            "convergence_required": False,
                            "reason": "process_only",
                            "system_convergence_plan": plan,
                        },
                        "evidence": self._passed_evidence(),
                    }
                )

    def test_process_only_not_required_plan_is_not_applicable(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan(
            gate="not_required", change_risk="R1", target_criticality="ordinary"
        )
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            result = obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": False,
                        "reason": "process_only",
                        "system_convergence_plan": plan,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

        self.assertEqual("not_applicable", result["convergence_gate_outcome"])

    def test_systemic_plan_and_receipt_must_share_protocol_head(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan(protocol_head="b" * 40)
        receipt = self._convergence_receipt("goo-example-work-0001")
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            with self.assertRaises(
                obligation.OperatorObligationCompletionClassificationError
            ):
                obligation.close_obligation(
                    {
                        "obligation_id": "goo-example-work-0001",
                        "outcome": "completed",
                        "closure_classification": {
                            "convergence_required": True,
                            "reason": "systemic",
                            "convergence_receipt": receipt,
                            "system_convergence_plan": plan,
                        },
                        "evidence": self._passed_evidence(),
                    }
                )

    def test_process_only_plan_replay_does_not_rebuild_canonical_policy(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan(gate="assessment_required")
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
            "closure_classification": {
                "convergence_required": False,
                "reason": "process_only",
                "system_convergence_plan": plan,
            },
            "evidence": self._passed_evidence(),
        }
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            first = obligation.close_obligation(parameters)
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            side_effect=AssertionError("replay must not rebuild convergence policy"),
        ):
            replay = obligation.close_obligation(parameters)

        self.assertTrue(first["created"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            "explicit_non_systemic_bypass", replay["convergence_gate_outcome"]
        )

    def test_systemic_plan_and_receipt_replay_without_volatile_sources(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan()
        receipt = self._convergence_receipt("goo-example-work-0001")
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
            "closure_classification": {
                "convergence_required": True,
                "reason": "systemic",
                "convergence_receipt": receipt,
                "system_convergence_plan": plan,
            },
            "evidence": self._passed_evidence(),
        }
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            first = obligation.close_obligation(parameters)
        Path(receipt["output"]["request_path"]).unlink()
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            side_effect=AssertionError("exact replay must not rebuild convergence policy"),
        ):
            replay = obligation.close_obligation(parameters)
        self.assertTrue(first["created"])
        self.assertTrue(replay["replayed"])
        self.assertEqual("pass", replay["convergence_gate_outcome"])
        self.assertEqual(
            plan["profile_cell_id"],
            replay["completion_classification"]["system_convergence_plan"][
                "profile_cell_id"
            ],
        )

    def test_systemic_completion_replays_after_request_file_is_removed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        convergence_receipt = self._convergence_receipt("goo-example-work-0001")
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
            "closure_classification": {
                "convergence_required": True,
                "reason": "systemic",
                "convergence_receipt": convergence_receipt,
            },
            "evidence": self._passed_evidence(),
        }
        first = obligation.close_obligation(parameters)
        Path(convergence_receipt["output"]["request_path"]).unlink()

        replay = obligation.close_obligation(parameters)

        self.assertTrue(first["created"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["close_file_sha256"], replay["close_file_sha256"])
        self.assertEqual("systemic", replay["completion_scope"])
        self.assertTrue(replay["systemic_convergence_claim"])

    def test_systemic_replay_shortcut_requires_exact_bound_receipt(self) -> None:
        obligation.open_obligation(self._open_parameters())
        original_receipt = self._convergence_receipt("goo-example-work-0001")
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "closure_classification": {
                    "convergence_required": True,
                    "reason": "systemic",
                    "convergence_receipt": original_receipt,
                },
                "evidence": self._passed_evidence(),
            }
        )

        different_receipt = self._convergence_receipt("goo-example-work-0001")
        different_receipt["output"]["assessment"]["assessment_id"] = "assessment-different"
        self._rehash_grip_result(different_receipt)
        Path(different_receipt["output"]["request_path"]).unlink()

        with self.assertRaises(
            obligation.OperatorObligationCompletionClassificationError
        ):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": True,
                        "reason": "systemic",
                        "convergence_receipt": different_receipt,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

    def test_legacy_v1_convergence_assessment_blocks_systemic_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        convergence_receipt = self._convergence_receipt(
            "goo-example-work-0001", assessment_schema_version=1
        )
        with self.assertRaises(obligation.OperatorObligationCompletionClassificationError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": True,
                        "reason": "systemic",
                        "convergence_receipt": convergence_receipt,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

    def test_nonterminal_convergence_assessment_blocks_systemic_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        convergence_receipt = self._convergence_receipt(
            "goo-example-work-0001", assessment_status="evidence_missing"
        )
        with self.assertRaises(obligation.OperatorObligationCompletionClassificationError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": True,
                        "reason": "systemic",
                        "convergence_receipt": convergence_receipt,
                    },
                    "evidence": self._passed_evidence(),
                }
            )

    def test_systemic_completion_blocks_request_target_protocol_and_receipt_drift(self) -> None:
        for label in ("request", "target", "protocol", "receipt"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as isolated:
                if label == "target":
                    convergence_receipt = self._convergence_receipt(
                        "goo-example-work-0001",
                        target_obligation_id="goo-other-work-0002",
                    )
                else:
                    convergence_receipt = self._convergence_receipt("goo-example-work-0001")

                if label == "request":
                    request_path = Path(convergence_receipt["output"]["request_path"])
                    request_path.write_text("{}", encoding="utf-8")
                elif label == "protocol":
                    convergence_receipt["output"]["protocol_head"] = "f" * 40
                    self._rehash_grip_result(convergence_receipt)
                elif label == "receipt":
                    convergence_receipt["output"]["decision"] = "block_closure"

                with patch.dict(
                    os.environ,
                    {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(Path(isolated) / "obligations")},
                ):
                    obligation.open_obligation(self._open_parameters())
                    with self.assertRaises(
                        obligation.OperatorObligationCompletionClassificationError
                    ):
                        obligation.close_obligation(
                            {
                                "obligation_id": "goo-example-work-0001",
                                "outcome": "completed",
                                "closure_classification": {
                                    "convergence_required": True,
                                    "reason": "systemic",
                                    "convergence_receipt": convergence_receipt,
                                },
                                "evidence": self._passed_evidence(),
                            }
                        )

    def test_persisted_systemic_plan_assessment_drift_fails_closed_on_read(self) -> None:
        obligation.open_obligation(self._open_parameters())
        plan = self._system_convergence_plan()
        receipt = self._convergence_receipt("goo-example-work-0001")
        with patch.object(
            obligation.grabowski_convergence,
            "build_system_convergence_plan",
            return_value=plan,
        ):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": {
                        "convergence_required": True,
                        "reason": "systemic",
                        "convergence_receipt": receipt,
                        "system_convergence_plan": plan,
                    },
                    "evidence": self._passed_evidence(),
                }
            )
        target = self.root / "goo-example-work-0001" / "close.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["completion_classification"]["system_convergence_plan"][
            "change_risk"
        ] = "R1"
        material = {
            key: value
            for key, value in payload.items()
            if key not in {"closed_at", "material_sha256", "record_sha256"}
        }
        payload["material_sha256"] = obligation._sha256(material)
        payload.pop("record_sha256")
        payload["record_sha256"] = obligation._sha256(payload)
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaisesRegex(
            obligation.OperatorObligationIntegrityError,
            "close record semantics are invalid",
        ):
            obligation.status_obligation("goo-example-work-0001")

    def test_persisted_systemic_classification_cannot_rebind_to_another_obligation(self) -> None:
        obligation.open_obligation(self._open_parameters())
        convergence_receipt = self._convergence_receipt("goo-example-work-0001")
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "closure_classification": {
                    "convergence_required": True,
                    "reason": "systemic",
                    "convergence_receipt": convergence_receipt,
                },
                "evidence": self._passed_evidence(),
            }
        )
        target = self.root / "goo-example-work-0001" / "close.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["completion_classification"]["closure_id"] = (
            "operator-obligation:goo-other-work-0002"
        )
        material = {
            key: value
            for key, value in payload.items()
            if key not in {"closed_at", "material_sha256", "record_sha256"}
        }
        payload["material_sha256"] = obligation._sha256(material)
        payload.pop("record_sha256")
        payload["record_sha256"] = obligation._sha256(payload)
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")

    def test_legacy_v1_completed_close_remains_readable_but_not_systemic(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )
        target = self.root / "goo-example-work-0001" / "close.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["schema_version"] = obligation.LEGACY_CLOSE_SCHEMA_VERSION
        payload.pop("completion_classification")
        material = {
            key: value
            for key, value in payload.items()
            if key not in {"closed_at", "material_sha256", "record_sha256"}
        }
        payload["material_sha256"] = obligation._sha256(material)
        payload.pop("record_sha256")
        payload["record_sha256"] = obligation._sha256(payload)
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        status = obligation.status_obligation("goo-example-work-0001")
        self.assertEqual("legacy_unclassified", status["completion_scope"])
        self.assertIsNone(status["systemic_convergence_claim"])
        self.assertIn("does not establish systemic convergence", status["non_claims"][0])

    def test_task_backed_exact_completed_replay_does_not_require_live_task_truth(self) -> None:
        task_id = "task-replay-0001"
        params = self._open_parameters()
        params["references"] = [
            {
                "kind": "grabowski_task",
                "id": task_id,
                "observation_tool": "grabowski_task_status",
            }
        ]
        obligation.open_obligation(params)
        lifecycle_sha = "9" * 64
        task_record = {
            "task_id": task_id,
            "attempt": 1,
            "state": "completed",
            "lifecycle_receipt_sha256": lifecycle_sha,
        }
        closeout = {
            "terminal": True,
            "lifecycle_evidence_valid": True,
            "outcome_receipt_sha256": lifecycle_sha,
            "task_binding": {"task_id": task_id, "attempt": 1},
            "closeout_state": "ready_to_archive",
        }
        evidence = self._passed_evidence()
        evidence[0] = {
            "acceptance_id": "implementation",
            "status": "passed",
            "source": "receipt",
            "reference": f"task:{task_id}",
            "sha256": lifecycle_sha,
        }
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
            "closure_classification": self._process_only(),
            "evidence": evidence,
        }
        task_rows: list[dict[str, object]] = []

        def row_first(_task_id: str) -> dict[str, object]:
            task_rows.append(task_record)
            return task_record

        tasks_module = SimpleNamespace(_row=row_first)
        attention_module = SimpleNamespace(
            terminal_closeout_plan=lambda _record: closeout
        )
        with patch.dict(
            sys.modules,
            {
                "grabowski_tasks": tasks_module,
                "grabowski_task_attention": attention_module,
            },
        ):
            first = obligation.close_obligation(parameters)
            task_rows.clear()

            def unavailable(_task_id: str) -> dict[str, object]:
                task_rows.append(task_record)
                raise OSError("task store unavailable")

            tasks_module._row = unavailable
            replay = obligation.close_obligation(parameters)
        self.assertTrue(first["created"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["close_file_sha256"], replay["close_file_sha256"])
        self.assertEqual([], task_rows)

    def test_completed_close_requires_passed_evidence_for_every_acceptance(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": self._process_only(),
                    "evidence": self._passed_evidence()[:1],
                }
            )
        self.assertEqual(
            obligation.status_obligation("goo-example-work-0001")["state"],
            "open",
        )

    def test_completed_close_rejects_unhashed_evidence(self) -> None:
        obligation.open_obligation(self._open_parameters())
        evidence = self._passed_evidence()
        evidence[0].pop("sha256")
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "completed",
                    "closure_classification": self._process_only(),
                    "evidence": evidence,
                }
            )
        self.assertEqual(
            obligation.status_obligation("goo-example-work-0001")["state"],
            "open",
        )

    def test_completed_close_is_create_only_and_reports_real_completion(self) -> None:
        obligation.open_obligation(self._open_parameters())
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "outcome": "completed",
                    "closure_classification": self._process_only(),
            "evidence": self._passed_evidence(),
        }
        first = obligation.close_obligation(parameters)
        second = obligation.close_obligation(parameters)

        self.assertTrue(first["created"])
        self.assertFalse(first["continuation_required"])
        self.assertTrue(first["response_may_end"])
        self.assertTrue(first["work_complete"])
        self.assertEqual(first["state"], "completed")
        self.assertTrue(second["replayed"])
        self.assertEqual(first["close_file_sha256"], second["close_file_sha256"])
        close_path = self.root / "goo-example-work-0001" / "close.json"
        self.assertEqual(stat.S_IMODE(close_path.stat().st_mode), 0o600)

    def test_terminal_close_alerts_are_narrow_and_dispatch_failure_is_advisory(
        self,
    ) -> None:
        completed_id = "goo-completed-alert-0002"
        blocked_id = "goo-blocked-alert-0003"
        obligation.open_obligation(self._open_parameters(completed_id))
        obligation.open_obligation(self._open_parameters(blocked_id))
        with patch.object(
            obligation.alert_outbox,
            "enqueue_and_schedule",
            side_effect=RuntimeError("dispatcher unavailable"),
        ) as enqueue:
            completed = obligation.close_obligation(
                {
                    "obligation_id": completed_id,
                    "outcome": "completed",
                    "closure_classification": self._process_only(),
                    "evidence": self._passed_evidence(),
                }
            )
            blocked = obligation.close_obligation(
                {
                    "obligation_id": blocked_id,
                    "outcome": "blocked",
                    "evidence": [],
                    "blockers": [
                        {
                            "code": "foreign-lease",
                            "detail": "Exact overlap remains active.",
                            "reference": "lease:owner-17",
                            "sha256": "3" * 64,
                        }
                    ],
                    "next_action": "Recheck the lease.",
                }
            )

        self.assertEqual("completed", completed["state"])
        self.assertEqual("blocked", blocked["state"])
        self.assertEqual(2, enqueue.call_count)
        self.assertEqual(
            ["long_run_completed", "blocked_operation"],
            [call.kwargs["event_class"] for call in enqueue.call_args_list],
        )
        self.assertEqual(
            [completed_id, blocked_id],
            [call.kwargs["correlation_key"] for call in enqueue.call_args_list],
        )

    def test_reopening_same_obligation_preserves_terminal_state(self) -> None:
        parameters = self._open_parameters()
        obligation.open_obligation(parameters)
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                    "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )

        replay = obligation.open_obligation(parameters)

        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["state"], "completed")
        self.assertTrue(replay["response_may_end"])
        self.assertTrue(replay["work_complete"])

    def test_blocked_close_requires_hashed_blocker_evidence(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "blocked",
                    "evidence": [],
                    "blockers": [
                        {
                            "code": "foreign-lease",
                            "detail": "An exact overlapping lease is active.",
                            "reference": "lease:owner-17",
                        }
                    ],
                    "next_action": "Wait for the exact lease to be released, then reorient.",
                }
            )

    def test_blocked_close_ends_chat_without_claiming_work_complete(self) -> None:
        obligation.open_obligation(self._open_parameters())
        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [
                    {
                        "acceptance_id": "implementation",
                        "status": "partial",
                        "source": "git",
                        "reference": "worktree:dirty",
                    }
                ],
                "blockers": [
                    {
                        "code": "foreign-lease",
                        "detail": "An exact overlapping lease is active.",
                        "reference": "lease:owner-17",
                        "sha256": "3" * 64,
                    }
                ],
                "next_action": "Wait for the exact lease to be released, then reorient.",
            }
        )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(obligation.LEGACY_CLOSE_SCHEMA_VERSION, result["close_schema_version"])
        self.assertTrue(result["response_may_end"])
        self.assertTrue(result["continuation_required"])
        self.assertTrue(result["follow_up_required"])
        self.assertFalse(result["work_complete"])
        self.assertIn("does not establish", result["non_claims"][0])

    def test_delegated_close_requires_a_live_durable_reference(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "delegated",
                    "evidence": [],
                    "delegation": self._delegation("failed"),
                    "next_action": "Observe the job.",
                }
            )

        result = obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "delegated",
                "evidence": [],
                "delegation": self._delegation("running"),
                "next_action": "Observe the durable job and verify its final receipt.",
            }
        )
        self.assertEqual(result["state"], "delegated")
        self.assertEqual(obligation.LEGACY_CLOSE_SCHEMA_VERSION, result["close_schema_version"])
        self.assertTrue(result["continuation_required"])
        self.assertTrue(result["follow_up_required"])
        self.assertFalse(result["work_complete"])
        self.assertEqual(result["delegation"]["status"], "running")

    def test_delegation_receipt_hash_cannot_be_forged(self) -> None:
        obligation.open_obligation(self._open_parameters())
        forged = self._delegation("running")
        forged["identity_sha256"] = "d" * 64
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "delegated",
                    "evidence": [],
                    "delegation": forged,
                    "next_action": "Observe the durable job.",
                }
            )

    def test_conflicting_terminal_close_is_rejected(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                    "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.close_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "outcome": "blocked",
                    "evidence": [],
                    "blockers": [
                        {
                            "code": "late-blocker",
                            "detail": "A conflicting terminal claim appeared.",
                            "reference": "test",
                            "sha256": "4" * 64,
                        }
                    ],
                    "next_action": "Review manually.",
                }
            )

    def test_hardlinked_lock_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        os.link(self.root / ".lock", self.root / ".lock-copy")
        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.open_obligation(self._open_parameters("goo-second-work-0002"))

    def test_list_scan_is_bounded(self) -> None:
        obligation.open_obligation(self._open_parameters())
        for name in ("goo-extra-work-0002", "goo-extra-work-0003"):
            (self.root / name).mkdir(mode=0o700)
        with patch.object(obligation, "MAX_LIST_SCAN", 2):
            result = obligation.list_obligations({"state": "all", "limit": 10})
        self.assertTrue(result["scan_truncated"])
        self.assertTrue(result["attention_required"])

    def test_list_rejects_non_string_state(self) -> None:
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.list_obligations({"state": ["open"]})

    def test_tampered_unhashed_close_timestamp_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                    "closure_classification": self._process_only(),
                "evidence": self._passed_evidence(),
            }
        )
        target = self.root / "goo-example-work-0001" / "close.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["closed_at"] = "2026-07-15T00:00:00Z"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")

    def test_tampered_timestamp_fails_closed_via_record_hash(self) -> None:
        obligation.open_obligation(self._open_parameters())
        target = self.root / "goo-example-work-0001" / "open.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["created_at"] = "2026-07-15T00:00:00Z"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")

    def test_tampered_open_record_fails_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        target = self.root / "goo-example-work-0001" / "open.json"
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["objective"] = "Tampered"
        target.write_text(json.dumps(payload), encoding="utf-8")
        target.chmod(0o600)

        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")


    def test_blocked_resolution_moves_obligation_out_of_current_attention(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "lease",
                        "detail": "Foreign lease.",
                        "reference": "lease:foreign",
                        "sha256": "d" * 64,
                    }
                ],
                "next_action": "Recheck later.",
            }
        )
        before = obligation.status_obligation("goo-example-work-0001")
        self.assertTrue(before["continuation_required"])
        result = obligation.resolve_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "disposition": "superseded",
                "evidence": [
                    {"source": "bureau", "reference": "task:NEW", "sha256": "a" * 64}
                ],
            }
        )
        self.assertFalse(result["continuation_required"])
        self.assertEqual("historical", result["attention_class"])
        self.assertEqual("superseded", result["resolution_disposition"])
        self.assertEqual(
            0, obligation.list_obligations({"state": "attention"})["record_count"]
        )
        self.assertEqual(
            1, obligation.list_obligations({"state": "blocked"})["record_count"]
        )


    def test_deferred_resolution_parks_attention_and_requires_new_obligation_for_resume(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Old next action.",
            }
        )
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "fresh-probe",
                    "sha256": "b" * 64,
                }
            ],
            "next_action": "Probe again when the target is reachable.",
        }
        first = obligation.resolve_obligation(parameters)
        replay = obligation.resolve_obligation(parameters)

        self.assertFalse(first["continuation_required"])
        self.assertEqual("historical", first["attention_class"])
        self.assertEqual("deferred", first["resolution_disposition"])
        self.assertEqual(2, first["resolution_schema_version"])
        self.assertEqual(2, replay["resolution_schema_version"])
        self.assertEqual(
            "Probe again when the target is reachable.",
            first["recommended_next_action"],
        )
        self.assertEqual(1, first["resolution_sequence"])
        self.assertEqual(1, first["resolution_revision_count"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            0, obligation.list_obligations({"state": "attention"})["record_count"]
        )
        self.assertEqual(
            1, obligation.list_obligations({"state": "blocked"})["record_count"]
        )

        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.resolve_obligation(
                {
                    **parameters,
                    "evidence": [
                        {
                            "source": "runtime",
                            "reference": "second-probe",
                            "sha256": "c" * 64,
                        }
                    ],
                    "next_action": "Retry after a later checkpoint.",
                }
            )
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "resolved",
                    "evidence": [
                        {
                            "source": "runtime",
                            "reference": "final-probe",
                            "sha256": "d" * 64,
                        }
                    ],
                }
            )

        obligation.open_obligation(self._open_parameters("goo-example-work-resume-0002"))
        resumed = obligation.status_obligation("goo-example-work-resume-0002")
        attention = obligation.list_obligations({"state": "attention"})
        self.assertTrue(resumed["continuation_required"])
        self.assertEqual(1, attention["record_count"])
        self.assertEqual("goo-example-work-resume-0002", attention["records"][0]["obligation_id"])

        directory = self.root / "goo-example-work-0001"
        self.assertTrue((directory / "resolution.json").is_file())
        self.assertFalse((directory / "resolution-000002.json").exists())

    def test_legacy_deferred_resolution_stays_current_until_explicit_v2_successor(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Old next action.",
            }
        )
        legacy_parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "legacy-probe",
                    "sha256": "a" * 64,
                }
            ],
            "next_action": "Keep checking under the legacy contract.",
        }
        obligation.resolve_obligation(legacy_parameters)

        directory = self.root / "goo-example-work-0001"
        legacy_path = directory / "resolution.json"
        legacy_record = json.loads(legacy_path.read_text(encoding="utf-8"))
        legacy_record["schema_version"] = obligation.LEGACY_RESOLUTION_SCHEMA_VERSION
        material = {
            key: value
            for key, value in legacy_record.items()
            if key not in {"resolved_at", "material_sha256", "record_sha256"}
        }
        legacy_record["material_sha256"] = obligation._sha256(material)
        record_material = {
            key: value
            for key, value in legacy_record.items()
            if key != "record_sha256"
        }
        legacy_record["record_sha256"] = obligation._sha256(record_material)
        legacy_path.write_text(
            json.dumps(legacy_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        grandfathered = obligation.status_obligation("goo-example-work-0001")
        self.assertEqual(1, grandfathered["resolution_schema_version"])
        self.assertTrue(grandfathered["continuation_required"])
        self.assertEqual("current", grandfathered["attention_class"])
        self.assertFalse(grandfathered["work_complete"])
        self.assertEqual(
            1, obligation.list_obligations({"state": "attention"})["record_count"]
        )

        replay = obligation.resolve_obligation(legacy_parameters)
        self.assertTrue(replay["replayed"])
        self.assertTrue(replay["continuation_required"])
        self.assertEqual(1, replay["resolution_sequence"])
        self.assertEqual(1, replay["resolution_revision_count"])
        self.assertEqual(1, replay["resolution_schema_version"])

        with self.assertRaisesRegex(
            obligation.OperatorObligationConflictError,
            "legacy deferred migration requires new evidence",
        ):
            obligation.resolve_obligation(
                {
                    **legacy_parameters,
                    "next_action": "Changing only the next action must not park legacy work.",
                }
            )
        with self.assertRaisesRegex(
            obligation.OperatorObligationConflictError,
            "legacy deferred migration requires new evidence",
        ):
            obligation.resolve_obligation(
                {
                    **legacy_parameters,
                    "evidence": [
                        {
                            "source": "different-source",
                            "reference": "different-reference",
                            "sha256": "a" * 64,
                        }
                    ],
                    "next_action": "Metadata changes must not manufacture fresh evidence.",
                }
            )

        migrated_parameters = {
            **legacy_parameters,
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "explicit-parking-decision",
                    "sha256": "b" * 64,
                }
            ],
            "next_action": "Open a new obligation if this work becomes current again.",
        }
        migrated = obligation.resolve_obligation(migrated_parameters)
        self.assertTrue(migrated["created"])
        self.assertFalse(migrated["continuation_required"])
        self.assertFalse(migrated["work_complete"])
        self.assertEqual("historical", migrated["attention_class"])
        self.assertEqual(2, migrated["resolution_schema_version"])
        self.assertEqual(2, migrated["resolution_sequence"])
        self.assertEqual(2, migrated["resolution_revision_count"])
        self.assertEqual(
            0, obligation.list_obligations({"state": "attention"})["record_count"]
        )
        self.assertEqual(
            1, json.loads(legacy_path.read_text(encoding="utf-8"))["schema_version"]
        )
        self.assertEqual(
            2,
            json.loads(
                (directory / "resolution-000002.json").read_text(encoding="utf-8")
            )["schema_version"],
        )

        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.resolve_obligation(
                {
                    **migrated_parameters,
                    "evidence": [
                        {
                            "source": "runtime",
                            "reference": "third-decision",
                            "sha256": "c" * 64,
                        }
                    ],
                }
            )

        v2_path = directory / "resolution-000002.json"
        _, v2_file_sha256 = obligation._read_private_json(v2_path)
        malicious_material = {
            "kind": obligation.RESOLUTION_KIND,
            "schema_version": obligation.LEGACY_RESOLUTION_SCHEMA_VERSION,
            "obligation_id": "goo-example-work-0001",
            "open_file_sha256": migrated["open_file_sha256"],
            "close_file_sha256": migrated["close_file_sha256"],
            "sequence": 3,
            "predecessor_file_sha256": v2_file_sha256,
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "restored-legacy-after-v2",
                    "sha256": "d" * 64,
                }
            ],
            "delegation_observation": {},
            "next_action": "This legacy record must never reactivate attention.",
        }
        malicious_payload = {
            **malicious_material,
            "resolved_at": obligation._utc_now(),
            "material_sha256": obligation._sha256(malicious_material),
        }
        malicious_payload["record_sha256"] = obligation._sha256(malicious_payload)
        obligation.private_io.publish_private_create_only_json(
            directory,
            directory / "resolution-000003.json",
            malicious_payload,
            max_bytes=obligation.MAX_RECORD_BYTES,
            label="test invalid legacy resolution after schema v2",
        )
        with self.assertRaisesRegex(
            obligation.OperatorObligationIntegrityError,
            "resolution schema chain continues after schema v2",
        ):
            obligation.status_obligation("goo-example-work-0001")


    def test_legacy_deferred_migration_requires_evidence_new_to_entire_v1_prefix(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Old next action.",
            }
        )
        first_parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "legacy-first",
                    "sha256": "a" * 64,
                }
            ],
            "next_action": "First legacy action.",
        }
        obligation.resolve_obligation(first_parameters)
        directory = self.root / "goo-example-work-0001"
        first_path = directory / "resolution.json"
        first_record = json.loads(first_path.read_text(encoding="utf-8"))
        first_record["schema_version"] = obligation.LEGACY_RESOLUTION_SCHEMA_VERSION
        first_material = {
            key: value
            for key, value in first_record.items()
            if key not in {"resolved_at", "material_sha256", "record_sha256"}
        }
        first_record["material_sha256"] = obligation._sha256(first_material)
        first_record["record_sha256"] = obligation._sha256(
            {key: value for key, value in first_record.items() if key != "record_sha256"}
        )
        first_path.write_text(
            json.dumps(first_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _, first_file_sha256 = obligation._read_private_json(first_path)

        second_material = {
            "kind": obligation.RESOLUTION_KIND,
            "schema_version": obligation.LEGACY_RESOLUTION_SCHEMA_VERSION,
            "obligation_id": "goo-example-work-0001",
            "open_file_sha256": first_record["open_file_sha256"],
            "close_file_sha256": first_record["close_file_sha256"],
            "sequence": 2,
            "predecessor_file_sha256": first_file_sha256,
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "legacy-second",
                    "sha256": "b" * 64,
                }
            ],
            "delegation_observation": {},
            "next_action": "Second legacy action.",
        }
        second_payload = {
            **second_material,
            "resolved_at": obligation._utc_now(),
            "material_sha256": obligation._sha256(second_material),
        }
        second_payload["record_sha256"] = obligation._sha256(second_payload)
        obligation.private_io.publish_private_create_only_json(
            directory,
            directory / "resolution-000002.json",
            second_payload,
            max_bytes=obligation.MAX_RECORD_BYTES,
            label="test second legacy deferred resolution",
        )
        current = obligation.status_obligation("goo-example-work-0001")
        self.assertTrue(current["continuation_required"])
        self.assertEqual("current", current["attention_class"])
        self.assertEqual(2, current["resolution_revision_count"])

        with self.assertRaisesRegex(
            obligation.OperatorObligationConflictError,
            "legacy deferred migration requires new evidence",
        ):
            obligation.resolve_obligation(
                {
                    **first_parameters,
                    "next_action": "Delayed retry of the first legacy decision.",
                }
            )

        migrated = obligation.resolve_obligation(
            {
                **first_parameters,
                "evidence": [
                    {
                        "source": "runtime",
                        "reference": "post-upgrade-migration",
                        "sha256": "c" * 64,
                    }
                ],
                "next_action": "Open a new obligation if work resumes.",
            }
        )
        self.assertEqual(2, migrated["resolution_schema_version"])
        self.assertEqual(3, migrated["resolution_sequence"])
        self.assertEqual(3, migrated["resolution_revision_count"])
        self.assertFalse(migrated["continuation_required"])
        self.assertEqual("historical", migrated["attention_class"])

    def test_reader_rejects_v2_migration_reusing_legacy_prefix_evidence(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Old next action.",
            }
        )
        legacy_parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "legacy-evidence",
                    "sha256": "a" * 64,
                }
            ],
            "next_action": "Legacy next action.",
        }
        obligation.resolve_obligation(legacy_parameters)
        directory = self.root / "goo-example-work-0001"
        legacy_path = directory / "resolution.json"
        legacy_record = json.loads(legacy_path.read_text(encoding="utf-8"))
        legacy_record["schema_version"] = obligation.LEGACY_RESOLUTION_SCHEMA_VERSION
        legacy_material = {
            key: value
            for key, value in legacy_record.items()
            if key not in {"resolved_at", "material_sha256", "record_sha256"}
        }
        legacy_record["material_sha256"] = obligation._sha256(legacy_material)
        legacy_record["record_sha256"] = obligation._sha256(
            {key: value for key, value in legacy_record.items() if key != "record_sha256"}
        )
        legacy_path.write_text(
            json.dumps(legacy_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _, legacy_file_sha256 = obligation._read_private_json(legacy_path)

        v2_material = {
            "kind": obligation.RESOLUTION_KIND,
            "schema_version": obligation.RESOLUTION_SCHEMA_VERSION,
            "obligation_id": "goo-example-work-0001",
            "open_file_sha256": legacy_record["open_file_sha256"],
            "close_file_sha256": legacy_record["close_file_sha256"],
            "sequence": 2,
            "predecessor_file_sha256": legacy_file_sha256,
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "different-source",
                    "reference": "different-reference",
                    "sha256": "a" * 64,
                }
            ],
            "delegation_observation": {},
            "next_action": "This restored migration must fail closed.",
        }
        v2_payload = {
            **v2_material,
            "resolved_at": obligation._utc_now(),
            "material_sha256": obligation._sha256(v2_material),
        }
        v2_payload["record_sha256"] = obligation._sha256(v2_payload)
        obligation.private_io.publish_private_create_only_json(
            directory,
            directory / "resolution-000002.json",
            v2_payload,
            max_bytes=obligation.MAX_RECORD_BYTES,
            label="test stale schema-v2 migration record",
        )

        with self.assertRaisesRegex(
            obligation.OperatorObligationIntegrityError,
            "schema-v2 migration requires evidence new to legacy prefix",
        ):
            obligation.status_obligation("goo-example-work-0001")

    def test_reader_rejects_successor_after_terminal_legacy_disposition(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Old next action.",
            }
        )
        obligation.resolve_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "disposition": "resolved",
                "evidence": [
                    {
                        "source": "runtime",
                        "reference": "legacy-terminal",
                        "sha256": "a" * 64,
                    }
                ],
            }
        )
        directory = self.root / "goo-example-work-0001"
        legacy_path = directory / "resolution.json"
        legacy_record = json.loads(legacy_path.read_text(encoding="utf-8"))
        legacy_record["schema_version"] = obligation.LEGACY_RESOLUTION_SCHEMA_VERSION
        legacy_material = {
            key: value
            for key, value in legacy_record.items()
            if key not in {"resolved_at", "material_sha256", "record_sha256"}
        }
        legacy_record["material_sha256"] = obligation._sha256(legacy_material)
        legacy_record["record_sha256"] = obligation._sha256(
            {key: value for key, value in legacy_record.items() if key != "record_sha256"}
        )
        legacy_path.write_text(
            json.dumps(legacy_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _, legacy_file_sha256 = obligation._read_private_json(legacy_path)

        v2_material = {
            "kind": obligation.RESOLUTION_KIND,
            "schema_version": obligation.RESOLUTION_SCHEMA_VERSION,
            "obligation_id": "goo-example-work-0001",
            "open_file_sha256": legacy_record["open_file_sha256"],
            "close_file_sha256": legacy_record["close_file_sha256"],
            "sequence": 2,
            "predecessor_file_sha256": legacy_file_sha256,
            "disposition": "deferred",
            "evidence": [
                {
                    "source": "runtime",
                    "reference": "new-but-illegal-after-terminal",
                    "sha256": "b" * 64,
                }
            ],
            "delegation_observation": {},
            "next_action": "This successor must fail closed.",
        }
        v2_payload = {
            **v2_material,
            "resolved_at": obligation._utc_now(),
            "material_sha256": obligation._sha256(v2_material),
        }
        v2_payload["record_sha256"] = obligation._sha256(v2_payload)
        obligation.private_io.publish_private_create_only_json(
            directory,
            directory / "resolution-000002.json",
            v2_payload,
            max_bytes=obligation.MAX_RECORD_BYTES,
            label="test successor after terminal legacy resolution",
        )

        with self.assertRaisesRegex(
            obligation.OperatorObligationIntegrityError,
            "resolution chain continues after terminal legacy disposition",
        ):
            obligation.status_obligation("goo-example-work-0001")


    def test_resolution_status_readback_remains_under_writer_lock(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "probe:external",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Recheck later.",
            }
        )
        original_lock = obligation._state_lock
        original_status = obligation.status_obligation
        lock_held = False

        @contextmanager
        def tracked_lock():
            nonlocal lock_held
            with original_lock():
                lock_held = True
                try:
                    yield
                finally:
                    lock_held = False

        def checked_status(obligation_id: str) -> dict[str, object]:
            self.assertTrue(lock_held)
            return original_status(obligation_id)

        with patch.object(obligation, "_state_lock", tracked_lock), patch.object(
            obligation, "status_obligation", side_effect=checked_status
        ):
            result = obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "deferred",
                    "evidence": [
                        {
                            "source": "runtime",
                            "reference": "probe:locked-readback",
                            "sha256": "f" * 64,
                        }
                    ],
                    "next_action": "Retry after the external checkpoint.",
                }
            )

        self.assertEqual(1, result["resolution_sequence"])
        self.assertEqual(1, result["resolution_revision_count"])
        self.assertEqual(result["resolution_file_sha256"], (
            obligation.status_obligation("goo-example-work-0001")["resolution_file_sha256"]
        ))


    def test_resolution_is_create_only_and_conflict_bound(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "lease",
                        "detail": "Foreign lease.",
                        "reference": "lease:foreign",
                        "sha256": "d" * 64,
                    }
                ],
                "next_action": "Recheck later.",
            }
        )
        parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "resolved",
            "evidence": [{"source": "github", "reference": "pr:1", "sha256": "c" * 64}],
        }
        self.assertTrue(obligation.resolve_obligation(parameters)["created"])
        self.assertTrue(obligation.resolve_obligation(parameters)["replayed"])
        changed = {**parameters, "disposition": "superseded"}
        with self.assertRaises(obligation.OperatorObligationConflictError):
            obligation.resolve_obligation(changed)


    def test_open_and_completed_obligations_cannot_be_resolved(self) -> None:
        obligation.open_obligation(self._open_parameters())
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "superseded",
                    "evidence": [
                        {"source": "test", "reference": "open", "sha256": "a" * 64}
                    ],
                }
            )
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "completed",
                    "closure_classification": self._process_only(),
                "evidence": [
                    {
                        "acceptance_id": "implementation",
                        "status": "passed",
                        "source": "git",
                        "reference": "commit:a",
                        "sha256": "b" * 64,
                    },
                    {
                        "acceptance_id": "verification",
                        "status": "passed",
                        "source": "test",
                        "reference": "test:a",
                        "sha256": "c" * 64,
                    },
                ],
            }
        )
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "resolved",
                    "evidence": [
                        {"source": "test", "reference": "done", "sha256": "d" * 64}
                    ],
                }
            )

    def test_resolution_next_action_contract_is_fail_closed(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "external",
                        "detail": "External blocker.",
                        "reference": "external:a",
                        "sha256": "e" * 64,
                    }
                ],
                "next_action": "Recheck later.",
            }
        )
        evidence = [
            {"source": "runtime", "reference": "probe:a", "sha256": "f" * 64}
        ]
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "deferred",
                    "evidence": evidence,
                }
            )
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(
                {
                    "obligation_id": "goo-example-work-0001",
                    "disposition": "resolved",
                    "evidence": evidence,
                    "next_action": "This must be empty.",
                }
            )

    def test_tampered_resolution_record_is_rejected(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "blocked",
                "evidence": [],
                "blockers": [
                    {
                        "code": "old",
                        "detail": "Old blocker.",
                        "reference": "old:a",
                        "sha256": "1" * 64,
                    }
                ],
                "next_action": "Recheck later.",
            }
        )
        obligation.resolve_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "disposition": "superseded",
                "evidence": [
                    {"source": "bureau", "reference": "task:new", "sha256": "2" * 64}
                ],
            }
        )
        path = self.root / "goo-example-work-0001" / "resolution.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["disposition"] = "resolved"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaises(obligation.OperatorObligationIntegrityError):
            obligation.status_obligation("goo-example-work-0001")


    def test_delegated_resolution_requires_bound_terminal_observation(self) -> None:
        obligation.open_obligation(self._open_parameters())
        obligation.close_obligation(
            {
                "obligation_id": "goo-example-work-0001",
                "outcome": "delegated",
                "evidence": [],
                "delegation": self._delegation("running"),
                "next_action": "Observe the delegated job.",
            }
        )
        base_parameters = {
            "obligation_id": "goo-example-work-0001",
            "disposition": "superseded",
            "evidence": [
                {"source": "github", "reference": "pr:new", "sha256": "4" * 64}
            ],
        }
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(base_parameters)

        terminal = self._delegation("succeeded")
        with self.assertRaises(obligation.OperatorObligationInputError):
            obligation.resolve_obligation(
                {
                    **base_parameters,
                    "delegation_observation": terminal,
                }
            )
        receipt_evidence = {
            "source": "receipt",
            "reference": "delegation:systemd_job:grabowski-job-17",
            "sha256": terminal["observation_receipt_sha256"],
        }
        final_parameters = {
            **base_parameters,
            "evidence": [*base_parameters["evidence"], receipt_evidence],
            "delegation_observation": terminal,
        }
        result = obligation.resolve_obligation(final_parameters)
        replay = obligation.resolve_obligation(final_parameters)
        self.assertEqual("historical", result["attention_class"])
        self.assertFalse(result["continuation_required"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(1, replay["resolution_revision_count"])
        self.assertEqual(
            terminal,
            result["resolution_delegation_observation"],
        )



if __name__ == "__main__":
    unittest.main()
