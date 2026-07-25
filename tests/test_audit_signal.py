from __future__ import annotations

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

    def test_schema_fixes_signal_order(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/audit-signal.v1.schema.json").read_text(encoding="utf-8")
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


if __name__ == "__main__":
    unittest.main()
