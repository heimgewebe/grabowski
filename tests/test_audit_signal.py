from __future__ import annotations

import ast
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_audit_signal as signal  # noqa: E402


class AuditSignalTests(unittest.TestCase):
    def test_emits_five_evidence_bound_signals(self) -> None:
        now = 1_800_000_000
        records = [
            (
                {
                    "operation": "runtime-state-retention-intent",
                    "record_sha256": "a" * 64,
                },
                now - 1_000,
            ),
            (
                {
                    "operation": "task-start",
                    "record_sha256": "b" * 64,
                    "launcher_outcome_unknown": True,
                },
                now - 900,
            ),
            (
                {
                    "operation": "task-start",
                    "record_sha256": "c" * 64,
                    "recovery_required": True,
                },
                now - 800,
            ),
        ]
        events = [
            *[
                {
                    "event_id": f"gate{index}",
                    "recorded_at_unix": now - 700 + index,
                    "kind": "fail_closed_gate",
                    "operation": "repo.worktree.ensure",
                    "symptom": "gate evidence missing",
                    "resolved": False,
                    "resolution_status": "unresolved",
                }
                for index in range(3)
            ],
            {
                "event_id": "contract1",
                "recorded_at_unix": now - 600,
                "kind": "ci_contract",
                "operation": "generated_context_contract",
                "symptom": "producer and consumer contract mismatch",
                "resolved": False,
                "resolution_status": "unresolved",
            },
            {
                "event_id": "snapshot1",
                "recorded_at_unix": now - 500,
                "kind": "connector_snapshot",
                "operation": "tool_contract_snapshot",
                "symptom": "client snapshot stale",
                "resolved": False,
                "resolution_status": "unresolved",
            },
        ]
        friction = types.ModuleType("grabowski_friction")
        friction.friction_summary = lambda **kwargs: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "events": events,
            "pagination": {"snapshot_sha256": "d" * 64, "has_more": False},
        }
        friction.classify_friction_event = lambda event: {
            "fail_closed_gate": "policy_gate",
            "ci_contract": "contract_error",
            "connector_snapshot": "environment_tooling",
        }.get(event.get("kind"), "unknown")
        runtime_status = {
            "healthy": True,
            "tool_contract": {
                "runtime_matches_deployment_contract": True,
                "client_snapshot_observable": True,
                "client_snapshot": {
                    "fresh": True,
                    "matched": True,
                    "created_at_unix": now - 100,
                    "receipt_sha256": "e" * 64,
                },
            },
        }
        with patch.dict(sys.modules, {"grabowski_friction": friction}, clear=False):
            result = signal.build_projection(
                records,
                as_of_unix=now,
                audit_source_binding={
                    "snapshot_sha256": "f" * 64,
                    "last_record_sha256": "c" * 64,
                },
                runtime_status_provider=lambda **kwargs: runtime_status,
            )
        self.assertEqual(
            [item["id"] for item in result["signals"]], list(signal.AUDIT_SIGNAL_IDS)
        )
        by_id = {item["id"]: item for item in result["signals"]}
        self.assertEqual(by_id["uncertain_outcome"]["count"], 2)
        self.assertEqual(by_id["transition_gap"]["count"], 1)
        self.assertEqual(by_id["repeated_blockade"]["count"], 3)
        self.assertEqual(by_id["contract_contradiction"]["count"], 1)
        self.assertEqual(by_id["stale_attention"]["count"], 1)
        self.assertEqual(
            by_id["uncertain_outcome"]["evidence_refs"][0],
            "audit-record-sha256:" + "b" * 64,
        )
        self.assertRegex(result["findings_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["projection_sha256"], r"^[0-9a-f]{64}$")
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("producer and consumer contract mismatch", encoded)
        self.assertNotIn("gate evidence missing", encoded)

    def test_contract_contradiction_requires_conflict_language(self) -> None:
        normal = {
            "failure_class": "contract_error",
            "kind": "ci_contract",
            "operation": "contract_validation",
            "symptom": "validator reported a missing generated file",
        }
        dual = {
            **normal,
            "symptom": "receipt reported released while envelope simultaneously reported retained",
        }
        self.assertIsNone(signal._audit_contract_contradiction_kind(normal))
        self.assertEqual(
            signal._audit_contract_contradiction_kind(dual),
            "structured_contract_mismatch",
        )

    def test_transition_completion_closes_gap(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "a" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "b" * 64,
                    },
                    now - 999,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["count"]), ("clear", 0))

    def test_retention_completion_matches_identity_before_legacy_fifo(self) -> None:
        now = 1_800_000_000
        plan_sha256 = "1" * 64
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "a" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "b" * 64,
                        "plan_sha256": plan_sha256,
                        "attempt": 2,
                    },
                    now - 900,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "c" * 64,
                        "plan_sha256": plan_sha256,
                        "attempt": 2,
                    },
                    now - 899,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"], result["count"]),
            ("observed", "high", 1),
        )
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "a" * 64]
        )
        self.assertEqual(
            result["details"]["completed_pairs_by_transition"],
            {"runtime-state-retention-intent": 1},
        )

    def test_retention_completion_does_not_consume_different_identity(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "d" * 64,
                        "plan_sha256": "1" * 64,
                        "attempt": 1,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "e" * 64,
                        "plan_sha256": "2" * 64,
                        "attempt": 1,
                    },
                    now - 999,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"], result["count"]),
            ("observed", "high", 1),
        )
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "d" * 64]
        )

    def test_identity_completion_does_not_consume_legacy_intent(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-state-retention-intent",
                        "record_sha256": "f" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-state-retention-complete",
                        "record_sha256": "0" * 64,
                        "plan_sha256": "2" * 64,
                        "attempt": 1,
                    },
                    now - 999,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual(
            (result["status"], result["severity"], result["count"]),
            ("observed", "high", 1),
        )
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "f" * 64]
        )
        self.assertEqual(result["details"]["completed_pairs_by_transition"], {})

    def test_deployment_transition_keeps_fifo_pairing(self) -> None:
        now = 1_800_000_000
        result = signal._audit_transition_gap_signal(
            [
                (
                    {
                        "operation": "runtime-deploy-schedule-intent",
                        "record_sha256": "a" * 64,
                    },
                    now - 1_000,
                ),
                (
                    {
                        "operation": "runtime-deploy-schedule-intent",
                        "record_sha256": "b" * 64,
                    },
                    now - 900,
                ),
                (
                    {
                        "operation": "runtime-deploy-scheduled",
                        "record_sha256": "c" * 64,
                    },
                    now - 800,
                ),
            ],
            start_unix=now - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=now,
        )
        self.assertEqual((result["status"], result["count"]), ("observed", 1))
        self.assertEqual(
            result["evidence_refs"], ["audit-record-sha256:" + "b" * 64]
        )

    def test_incomplete_friction_window_is_not_false_clear(self) -> None:
        source = {
            "available": True,
            "integrity_valid": True,
            "has_more": True,
            "events": [{"recorded_at_unix": 1_800_000_000 - 60, "resolved": True}],
        }
        results = signal._audit_friction_signals(
            source,
            {"available": True},
            start_unix=1_800_000_000 - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=1_800_000_000,
        )
        self.assertEqual([item["status"] for item in results], ["indeterminate"] * 3)
        self.assertEqual(results[0]["details"]["count_semantics"], "lower_bound")

    def test_findings_ignore_runtime_receipt_rotation(self) -> None:
        item = {
            "id": "stale_attention",
            "status": "clear",
            "severity": "none",
            "count": 0,
            "observed_count": 0,
            "evidence_refs": [],
            "evidence_refs_truncated": False,
            "evidence_quality": "test",
            "recommended_action": "none",
            "details": {
                "live_runtime_clean": True,
                "client_snapshot_created_at_unix": 10,
                "client_snapshot_receipt_sha256": "a" * 64,
            },
            "does_not_establish": [],
        }
        first = {
            "signals": [item],
            "source_health": {
                "runtime_healthy": True,
                "friction_snapshot_sha256": "b" * 64,
            },
        }
        rotated = dict(item)
        rotated["details"] = {
            **item["details"],
            "client_snapshot_created_at_unix": 20,
            "client_snapshot_receipt_sha256": "c" * 64,
        }
        second = {
            "signals": [rotated],
            "source_health": {
                "runtime_healthy": True,
                "friction_snapshot_sha256": "d" * 64,
            },
        }
        self.assertEqual(
            signal.findings_payload(first), signal.findings_payload(second)
        )

    def test_stale_attention_requires_clean_runtime(self) -> None:
        _, _, stale = signal._audit_friction_signals(
            {
                "available": True,
                "integrity_valid": True,
                "has_more": False,
                "events": [],
            },
            {
                "available": True,
                "healthy": False,
                "runtime_matches_contract": True,
                "client_snapshot_observable": True,
                "client_snapshot_fresh": True,
                "client_snapshot_matched": True,
            },
            start_unix=1_800_000_000 - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=1_800_000_000,
        )
        self.assertEqual(stale["status"], "indeterminate")
        self.assertEqual(stale["evidence_quality"], "live_runtime_not_clean")

    def test_stale_attention_requires_valid_snapshot_timestamp(self) -> None:
        _, _, stale = signal._audit_friction_signals(
            {
                "available": True,
                "integrity_valid": True,
                "has_more": False,
                "events": [],
            },
            {
                "available": True,
                "healthy": True,
                "runtime_matches_contract": True,
                "client_snapshot_observable": True,
                "client_snapshot_fresh": True,
                "client_snapshot_matched": True,
                "client_snapshot_created_at_unix": None,
            },
            start_unix=1_800_000_000 - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=1_800_000_000,
        )
        self.assertEqual(stale["status"], "indeterminate")
        self.assertEqual(
            stale["evidence_quality"], "runtime_snapshot_timestamp_unavailable"
        )
        self.assertIsNone(stale["count"])

    def test_stale_attention_requires_snapshot_receipt(self) -> None:
        _, _, stale = signal._audit_friction_signals(
            {
                "available": True,
                "integrity_valid": True,
                "has_more": False,
                "events": [],
            },
            {
                "available": True,
                "healthy": True,
                "runtime_matches_contract": True,
                "client_snapshot_observable": True,
                "client_snapshot_fresh": True,
                "client_snapshot_matched": True,
                "client_snapshot_created_at_unix": 1_800_000_000,
                "client_snapshot_receipt_sha256": None,
            },
            start_unix=1_800_000_000 - signal.AUDIT_SIGNAL_WINDOW_SECONDS,
            end_unix=1_800_000_000,
        )
        self.assertEqual(stale["status"], "indeterminate")
        self.assertEqual(
            stale["evidence_quality"], "runtime_snapshot_receipt_unavailable"
        )
        self.assertIsNone(stale["count"])

    def test_unavailable_friction_source_does_not_claim_complete_window(self) -> None:
        with patch.dict(sys.modules, {"grabowski_friction": None}, clear=False):
            result = signal.build_projection(
                [],
                as_of_unix=1_800_000_000,
                audit_source_binding={
                    "snapshot_sha256": "a" * 64,
                    "last_record_sha256": None,
                },
                runtime_status_provider=None,
            )
        self.assertFalse(result["source_health"]["friction_available"])
        self.assertFalse(result["source_health"]["friction_integrity_valid"])
        self.assertFalse(result["source_health"]["friction_recent_window_complete"])
        self.assertNotEqual(result["recommended_next_action"], "none")

    def test_client_snapshot_health_requires_observable_snapshot(self) -> None:
        runtime_status = {
            "healthy": True,
            "tool_contract": {
                "runtime_matches_deployment_contract": True,
                "client_snapshot_observable": False,
                "client_snapshot": {"fresh": True, "matched": True},
            },
        }
        result = signal.build_projection(
            [],
            as_of_unix=1_800_000_000,
            audit_source_binding={},
            runtime_status_provider=lambda **kwargs: runtime_status,
        )
        self.assertFalse(result["source_health"]["client_snapshot_fresh_and_matched"])

    def test_schema_fixes_signal_order(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/audit-signal.v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertFalse(schema["properties"]["source_binding"]["additionalProperties"])
        self.assertEqual(
            set(schema["properties"]["source_binding"]["required"]),
            set(schema["properties"]["source_binding"]["properties"]),
        )
        self.assertFalse(schema["properties"]["source_health"]["additionalProperties"])
        self.assertEqual(
            set(schema["properties"]["source_health"]["required"]),
            set(schema["properties"]["source_health"]["properties"]),
        )
        refs = [item["$ref"] for item in schema["properties"]["signals"]["prefixItems"]]
        self.assertEqual(
            refs,
            [
                "#/$defs/uncertainOutcome",
                "#/$defs/contractContradiction",
                "#/$defs/transitionGap",
                "#/$defs/repeatedBlockade",
                "#/$defs/staleAttention",
            ],
        )


    def test_retention_transition_identity_is_safe_and_traceable(self) -> None:
        source = (ROOT / "src" / "grabowski_audit_query.py").read_text(encoding="utf-8")
        scalar_block = source.split("_SCALAR_RECORD_FIELDS = (", 1)[1].split(")", 1)[0]
        trace_block = source.split("_TRACE_SCALAR_FIELDS = (", 1)[1].split(")", 1)[0]
        anchor_block = source.split("_TRACE_ANCHOR_KINDS = {", 1)[1].split("}", 1)[0]
        for field in (
            "plan_sha256",
            "receipt_sha256",
            "intent_record_sha256",
            "attempt",
            "reconciliation_kind",
            "completed",
            "retention_effect_retried",
        ):
            self.assertIn(f'"{field}"', scalar_block)
        for field in ("plan_sha256", "receipt_sha256"):
            self.assertIn(f'"{field}"', trace_block)
            self.assertIn(f'"{field}"', anchor_block)

        tree = ast.parse(source)
        boolean_fields = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "_BOOLEAN_RECORD_FIELDS"
                for target in node.targets
            )
        )
        boolean_namespace: dict[str, object] = {}
        exec(
            compile(
                ast.Module(body=[boolean_fields], type_ignores=[]),
                "<audit-query-boolean-fields>",
                "exec",
            ),
            boolean_namespace,
        )
        self.assertEqual(
            boolean_namespace["_BOOLEAN_RECORD_FIELDS"],
            frozenset({"completed", "retention_effect_retried"}),
        )

        sha_fields = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "_SHA256_RECORD_FIELDS"
                for target in node.targets
            )
        )
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_trace_scalar_value"
        )
        namespace = {"Any": object}
        exec(compile(ast.Module(body=[sha_fields, helper], type_ignores=[]), "<audit-query-trace-helper>", "exec"), namespace)
        trace_scalar = namespace["_trace_scalar_value"]
        self.assertEqual(trace_scalar({"plan_sha256": "a" * 64}, "plan_sha256"), "a" * 64)
        self.assertIsNone(trace_scalar({"plan_sha256": "not-a-digest"}, "plan_sha256"))
        self.assertIsNone(trace_scalar({"receipt_sha256": "secret-value"}, "receipt_sha256"))

        project_record = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_project_record"
        )
        project_namespace = {
            "Any": object,
            "_SCALAR_RECORD_FIELDS": ("completed", "retention_effect_retried"),
            "_STRING_LIST_RECORD_FIELDS": (),
            "_SHA256_RECORD_FIELDS": frozenset(),
            "_BOOLEAN_RECORD_FIELDS": frozenset(
                {"completed", "retention_effect_retried"}
            ),
        }
        exec(
            compile(
                ast.Module(body=[project_record], type_ignores=[]),
                "<audit-query-project-record>",
                "exec",
            ),
            project_namespace,
        )
        project = project_namespace["_project_record"]
        projected, omitted = project(
            {"completed": True, "retention_effect_retried": False}
        )
        self.assertEqual(
            projected, {"completed": True, "retention_effect_retried": False}
        )
        self.assertEqual(omitted, [])
        projected, omitted = project(
            {"completed": 1, "retention_effect_retried": "false"}
        )
        self.assertEqual(projected, {})
        self.assertEqual(omitted, ["completed", "retention_effect_retried"])



if __name__ == "__main__":
    unittest.main()
