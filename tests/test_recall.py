from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class RecallTests(unittest.TestCase):
    def _load_module(self):
        import types

        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator._redact = lambda value: value

        old_core = sys.modules.get("grabowski_operator_core")
        sys.modules["grabowski_operator_core"] = fake_operator
        name = f"grabowski_recall_under_test_{id(self)}"
        spec = importlib.util.spec_from_file_location(name, ROOT / "src/grabowski_recall.py")
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        sys.modules[name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        def restore_modules() -> None:
            if old_core is None:
                sys.modules.pop("grabowski_operator_core", None)
            else:
                sys.modules["grabowski_operator_core"] = old_core
            sys.modules.pop(name, None)

        self.addCleanup(restore_modules)
        return module

    def test_source_registers_read_only_recall_tool(self) -> None:
        source = (ROOT / "src/grabowski_recall.py").read_text(encoding="utf-8")
        self.assertIn('name="grabowski_operator_recall_export"', source)
        self.assertIn('annotations=READ_ONLY', source)
        self.assertNotIn("_require_mutations_enabled", source)
        self.assertNotIn("_require_operator_mutation", source)

    def test_valid_recall_export_from_all_sources_is_evidence_bound(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall(
            {
                "receipts": [
                    {"receipt_id": "receipt-1", "phase": "merge", "operation": "pr merge", "status": "complete", "receipt_sha256": "a" * 64}
                ],
                "prs": [
                    {"repo": "heimgewebe/grabowski", "number": 114, "title": "Add recall", "state": "MERGED", "head_sha": "b" * 40}
                ],
                "bureau_tasks": [
                    {"id": "GRABOWSKI-OPERATOR-SURFACE-V1-T004", "title": "Add evidence-bound operator recall", "state": "planned", "goal": "derive recall"}
                ],
                "friction_records": [
                    {"event_id": "friction-1", "kind": "fail_closed_gate", "operation": "review gate", "symptom": "blocked", "resolved": False}
                ],
            }
        )

        self.assertEqual(export["kind"], "grabowski_operator_recall_export")
        self.assertEqual(export["authority"], "derived_evidence_records")
        self.assertEqual(export["source_trust"], "caller_supplied_unverified")
        self.assertEqual(export["evidence_binding"], "requires_concrete_ref_but_does_not_verify_source")
        self.assertIn("evidence_authenticity", export["does_not_establish"])
        self.assertIn("current_truth", export["does_not_establish"])
        self.assertEqual(export["returned"], 4)
        self.assertEqual(export["rejected_source_count"], 0)
        self.assertEqual({item["source"] for item in export["items"]}, {"receipt", "pr", "bureau_task", "friction_record"})
        for item in export["items"]:
            self.assertEqual(item["kind"], "grabowski_operator_recall_item")
            self.assertTrue(item["evidence_refs"])
            self.assertIn("free_form_chat_memory", item["does_not_establish"])
            self.assertIn("policy_oracle", item["does_not_establish"])
            self.assertEqual(item["learned_rule_trust"], "caller_supplied_unverified")
            self.assertIn("learned_rule_authority", item["does_not_establish"])

    def test_free_form_memory_without_evidence_is_rejected(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "at least one evidence reference"):
            module.build_recall_item(
                topic="free memory",
                situation="remember this",
                attempt="store it",
                result="stored",
                learned_rule="always do this",
                evidence_refs=[],
                source="receipt",
            )

    def test_missing_source_evidence_is_reported_not_exported(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"friction_records": [{"kind": "operator_bug", "symptom": "missing event id"}]})

        self.assertEqual(export["returned"], 0)
        self.assertEqual(export["rejected_source_count"], 1)
        self.assertEqual(export["rejected_sources"][0]["reason"], "missing_concrete_evidence_ref")

    def test_caller_supplied_refs_do_not_establish_authenticity_or_current_truth(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"prs": [{"repo": "heimgewebe/grabowski", "number": 999999, "state": "MERGED"}]})

        self.assertEqual(export["returned"], 1)
        self.assertEqual(export["source_trust"], "caller_supplied_unverified")
        self.assertEqual(export["evidence_binding"], "requires_concrete_ref_but_does_not_verify_source")
        self.assertIn("evidence_authenticity", export["does_not_establish"])
        self.assertIn("source_record_authenticity", export["does_not_establish"])
        self.assertIn("current_truth", export["does_not_establish"])

    def test_invalid_pr_numbers_are_rejected_per_record(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({
            "prs": [
                {"repo": "heimgewebe/grabowski", "number": True},
                {"repo": "heimgewebe/grabowski", "number": 0},
                {"repo": "heimgewebe/grabowski", "number": -1},
                {"repo": "heimgewebe/grabowski", "number": "114"},
            ]
        })

        self.assertEqual(export["returned"], 0)
        self.assertEqual(export["rejected_source_count"], 4)
        self.assertEqual({item["reason"] for item in export["rejected_sources"]}, {"invalid_source_record"})

    def test_non_scalar_evidence_id_is_rejected_per_record(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"receipts": [{"receipt_id": {"bad": "object"}, "phase": "x"}]})

        self.assertEqual(export["returned"], 0)
        self.assertEqual(export["rejected_source_count"], 1)
        self.assertEqual(export["rejected_sources"][0]["reason"], "invalid_source_record")

    def test_unknown_item_source_is_rejected_even_with_valid_evidence(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "source is unsupported"):
            module.build_recall_item(
                topic="topic",
                situation="situation",
                attempt="attempt",
                result="result",
                learned_rule="rule",
                evidence_refs=[{"type": "receipt", "id": "r1"}],
                source="chat",
            )

    def test_item_source_requires_matching_evidence_type(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "matching evidence reference"):
            module.build_recall_item(
                topic="topic",
                situation="situation",
                attempt="attempt",
                result="result",
                learned_rule="rule",
                evidence_refs=[{"type": "receipt", "id": "r1"}],
                source="pr",
            )

    def test_invalid_required_pr_repo_is_rejected_per_record(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"prs": [{"repo": "bad\nrepo", "number": 1}]})

        self.assertEqual(export["returned"], 0)
        self.assertEqual(export["rejected_source_count"], 1)
        self.assertEqual(export["rejected_sources"][0]["reason"], "invalid_source_record")

    def test_runtime_imports_recall_module(self) -> None:
        runtime = (ROOT / "src/grabowski_runtime.py").read_text(encoding="utf-8")

        self.assertIn("import grabowski_recall", runtime)


    def test_required_control_char_text_is_rejected(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "control characters"):
            module.build_recall_item(
                topic="bad\nline",
                situation="situation",
                attempt="attempt",
                result="result",
                learned_rule="rule",
                evidence_refs=[{"type": "receipt", "id": "r1"}],
                source="receipt",
            )

    def test_unsupported_source_keys_are_reported(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"memories": [{"text": "remember this"}]})

        self.assertEqual(export["unsupported_source_keys"], ["memories"])
        self.assertEqual(export["unsupported_source_key_count"], 1)
        self.assertEqual(export["returned"], 0)

    def test_rejected_sources_are_bounded_and_marked_truncated(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"prs": [{"repo": "heimgewebe/grabowski", "number": 0} for _ in range(module.MAX_REJECTED_SOURCES + 100)]})

        self.assertEqual(export["rejected_source_count"], module.MAX_REJECTED_SOURCES + 100)
        self.assertTrue(export["rejected_sources_truncated"])
        self.assertEqual(len(export["rejected_sources"]), module.MAX_REJECTED_SOURCES)

    def test_limit_preserves_full_source_counts(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall(
            {
                "receipts": [{"receipt_id": "r1"}, {"receipt_id": "r2"}],
                "prs": [{"repo": "heimgewebe/grabowski", "number": 1}, {"repo": "heimgewebe/grabowski", "number": 2}],
                "bureau_tasks": [{"id": "T1"}, {"id": "T2"}],
                "friction_records": [{"event_id": "f1"}, {"event_id": "f2"}],
            },
            limit=1,
        )

        self.assertEqual(export["returned"], 1)
        self.assertTrue(export["stopped_on_limit"])
        self.assertEqual(export["source_counts"], {"receipts": 2, "prs": 2, "bureau_tasks": 2, "friction_records": 2})

    def test_too_many_evidence_refs_are_rejected(self) -> None:
        module = self._load_module()
        with self.assertRaisesRegex(ValueError, "too many evidence references"):
            module.build_recall_item(
                topic="topic",
                situation="situation",
                attempt="attempt",
                result="result",
                learned_rule="rule",
                evidence_refs=[{"type": "receipt", "id": f"r{i}"} for i in range(module.MAX_EVIDENCE_REFS + 1)],
                source="receipt",
            )

    def test_required_long_strings_are_bounded(self) -> None:
        module = self._load_module()
        long_text = "x" * (module.MAX_RECALL_TEXT_CHARS + 25)
        item = module.build_recall_item(
            topic="topic",
            situation=long_text,
            attempt="attempt",
            result="result",
            learned_rule="rule",
            evidence_refs=[{"type": "receipt", "id": "r1"}],
            source="receipt",
        )

        self.assertLessEqual(len(item["situation"]), module.MAX_RECALL_TEXT_CHARS)
        self.assertTrue(item["situation"].endswith("…"))

    def test_operator_recall_doc_states_boundary(self) -> None:
        doc = (ROOT / "docs/operator-recall.md").read_text(encoding="utf-8")

        self.assertIn("caller_supplied_unverified", doc)
        self.assertIn("free_form_chat_memory", doc)
        self.assertIn("policy_oracle", doc)
        self.assertIn("offline_proposal_only", doc)
        self.assertIn("does not verify", doc)
        self.assertIn("Multiline source text must be normalized", doc)

    def test_heimlern_boundary_is_offline_proposal_only(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"bureau_tasks": [{"id": "T1", "title": "Task", "state": "verified"}]})

        boundary = export["heimlern_offline_learning"]
        self.assertTrue(boundary["allowed"])
        self.assertEqual(boundary["mode"], "offline_proposal_only")
        self.assertIn("live_routing_change", boundary["does_not_establish"])
        self.assertIn("heimlern_live_update", export["does_not_establish"])


    def _chronik_history_result(self, module, *, available: bool = True):
        event = {
            "schema_version": "agent-run-event.v0",
            "kind": "agent.run.completed",
            "ts": "2026-07-23T12:00:00Z",
            "source": {
                "repo": "heimgewebe/grabowski",
                "component": "grabowski",
                "run_id": "task-0123456789abcdef01234567-a1",
            },
            "subject": {
                "scope": "repository",
                "repo": "heimgewebe/grabowski",
                "component": "chronik",
            },
            "trust_tier": "observed",
            "status": "active",
            "caused_by": [],
            "evidence_refs": [
                "grabowski-task:0123456789abcdef01234567",
                "grabowski-unit:grabowski-task-0123456789abcdef01234567-a1.service",
            ],
            "data": {
                "result": "completed",
                "operation": "implement",
                "task_class": "coding",
            },
        }
        event["event_id"] = module._chronik_event_id(event)
        query = {"repo": "heimgewebe/grabowski", "subject_component": "chronik", "limit": 20}
        payload = {
            "schema_version": 1,
            "kind": "grabowski_chronik_history",
            "query": query,
            "cli_present": True,
            "available": available,
            "historical_only": True,
            "events": [event] if available else [],
            "does_not_establish": list(module.CHRONIK_HISTORY_DOES_NOT_ESTABLISH),
        }
        if available:
            payload["history"] = {
                "schema_version": "chronik-coding-history.v1",
                "query": query,
                "target": {"scope": "repository", "repo": "heimgewebe/grabowski"},
                "event_ids": [event["event_id"]],
                "historical_only": True,
                "does_not_establish": list(module.CHRONIK_HISTORY_DOES_NOT_ESTABLISH),
                "ledger_snapshot": {"sha256": "b" * 64},
            }
        else:
            payload["failure"] = {"code": "chronik_repository_unavailable"}
        payload["result_sha256"] = module._sha256_json(payload)
        return payload

    def test_chronik_history_recall_is_hash_bound_and_historical_only(self) -> None:
        module = self._load_module()
        result = module.export_chronik_history_recall(self._chronik_history_result(module))

        self.assertEqual(result["kind"], "grabowski_operator_historical_recall")
        self.assertEqual(result["source_trust"], "grabowski_validated_chronik_history")
        self.assertEqual(result["evidence_binding"], "hash_bound_chronik_event")
        self.assertTrue(result["historical_only"])
        self.assertTrue(result["available"])
        self.assertEqual(result["returned"], 1)
        item = result["items"][0]
        self.assertEqual(item["source"], "chronik_event")
        self.assertEqual(module.SOURCE_TO_EVIDENCE_TYPE["chronik_event"], "chronik_event")
        self.assertEqual(item["learned_rule_trust"], "historical_observation_not_rule")
        self.assertEqual(
            item["evidence_refs"][0]["id"],
            self._chronik_history_result(module)["events"][0]["event_id"],
        )
        self.assertEqual(
            result["result_reference"]["kind"],
            "chronik_history_receipt",
        )
        self.assertEqual(
            result["result_reference"]["result_sha256"],
            result["history_result_sha256"],
        )
        self.assertEqual(
            result["result_reference"]["ledger_snapshot_sha256"],
            "b" * 64,
        )
        self.assertEqual(
            len(result["result_reference"]["event_ids_sha256"]),
            64,
        )
        self.assertIn("current_git_state", result["does_not_establish"])
        self.assertIn("safe_retry", result["does_not_establish"])
        self.assertIn("policy_change", item["does_not_establish"])

    def test_chronik_history_recall_exposes_structured_hash_bound_context(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["subject"]["pr_number"] = 200
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]

        self.assertEqual(item["historical_context"]["observed_at"], "2026-07-23T12:00:00Z")
        self.assertEqual(
            item["historical_context"]["run_id"],
            "task-0123456789abcdef01234567-a1",
        )
        self.assertEqual(item["historical_context"]["operation"], "implement")
        self.assertEqual(item["historical_context"]["task_class"], "coding")
        self.assertEqual(item["historical_context"]["subject"]["component"], "chronik")
        self.assertEqual(item["historical_context"]["subject"]["pr_number"], 200)
        self.assertEqual(len(item["historical_context"]["support_refs"]), 2)
        self.assertTrue(item["pattern_fingerprint"].startswith("sha256:"))
        self.assertEqual(item["pattern_occurrence_count"], 1)
        self.assertEqual(item["pattern_scope"], "bounded_query_result")
        self.assertTrue(item["reuse_condition"]["requires_live_recheck"])
        self.assertNotIn("pr_number", item["reuse_condition"]["match"])
        self.assertIn("root_cause", item["does_not_establish"])

    def test_chronik_history_started_event_has_no_terminal_signature(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["kind"] = "agent.run.started"
        event["data"]["result"] = "started"
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]

        self.assertEqual(item["historical_context"]["outcome"], "started")
        self.assertNotIn("terminal_signature", item["reuse_condition"])
        self.assertTrue(item["reuse_condition"]["requires_live_recheck"])
        self.assertIn("not outcome evidence", item["learned_rule"])

    def test_chronik_history_recall_counts_repeated_semantic_patterns_only_within_result(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        first = history["events"][0]
        first["kind"] = "agent.run.blocked"
        first["data"]["result"] = "blocked"
        first["data"]["blocker_code"] = "task-failed"
        first["event_id"] = module._chronik_event_id(first)

        second = {
            **first,
            "source": {**first["source"], "run_id": "task-fedcba9876543210fedcba98-a1"},
            "ts": "2026-07-23T13:00:00Z",
        }
        second["event_id"] = module._chronik_event_id(second)
        history["events"] = [first, second]
        history["history"]["event_ids"] = [first["event_id"], second["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)

        self.assertEqual(result["returned"], 2)
        self.assertEqual(result["pattern_count"], 1)
        self.assertEqual(result["pattern_summary"][0]["occurrences"], 2)
        self.assertEqual(result["pattern_scope"], "bounded_query_result")
        self.assertEqual(result["items"][0]["pattern_fingerprint"], result["items"][1]["pattern_fingerprint"])
        self.assertEqual(result["items"][0]["pattern_occurrence_count"], 2)
        self.assertEqual(result["items"][1]["pattern_occurrence_count"], 2)
        self.assertIn("task-failed", result["items"][0]["learned_rule"])


    def test_legacy_v0_task_failed_is_execution_failure_not_true_block(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["kind"] = "agent.run.blocked"
        event["data"]["result"] = "blocked"
        event["data"]["blocker_code"] = "task-failed"
        event["subject"]["bureau_task_id"] = "BUREAU-GOAL-T001"
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]
        self.assertEqual(item["historical_context"]["outcome"], "blocked")
        self.assertEqual(item["historical_context"]["effective_outcome"], "failed")
        self.assertEqual(item["historical_context"]["outcome_class"], "execution_failure")
        self.assertTrue(item["historical_context"]["legacy_blocked_execution_failure"])
        self.assertIn("not evidence of a coordination or policy block", item["learned_rule"])
        self.assertEqual(result["goal_count"], 1)
        goal = result["goal_summary"][0]
        self.assertEqual(goal["goal_key"], "bureau_task:BUREAU-GOAL-T001")
        self.assertEqual(goal["subrun_count"], 1)
        self.assertEqual(goal["execution_failure_subruns"], 1)
        self.assertEqual(goal["true_block_subruns"], 0)
        self.assertEqual(goal["legacy_blocked_failure_subruns"], 1)

    def test_legacy_outcome_unknown_remains_a_true_safety_block(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["kind"] = "agent.run.blocked"
        event["data"]["result"] = "blocked"
        event["data"]["blocker_code"] = "task-outcome-unknown"
        event["subject"]["repo"] = "heimgewebe/grabowski"
        event["subject"]["pr_number"] = 1008
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]
        self.assertEqual(item["historical_context"]["effective_outcome"], "outcome_unknown")
        self.assertEqual(item["historical_context"]["outcome_class"], "safety_block")
        self.assertEqual(result["goal_summary"][0]["goal_key"], "pr:heimgewebe/grabowski#1008")
        self.assertEqual(result["goal_summary"][0]["true_block_subruns"], 1)
        self.assertEqual(result["goal_summary"][0]["outcome_unknown_subruns"], 1)

    def test_v1_outcome_unknown_counts_as_true_safety_block(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["schema_version"] = "agent-run-event.v1"
        event["kind"] = "agent.run.blocked"
        event["data"]["result"] = "blocked"
        event["data"]["blocker_code"] = "task-outcome-unknown"
        event["subject"]["pr_number"] = 1009
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]
        self.assertEqual(item["historical_context"]["effective_outcome"], "outcome_unknown")
        self.assertEqual(item["historical_context"]["outcome_class"], "safety_block")
        goal = result["goal_summary"][0]
        self.assertEqual(goal["true_block_subruns"], 1)
        self.assertEqual(goal["outcome_unknown_subruns"], 1)
        self.assertEqual(
            item["reuse_condition"]["terminal_signature"]["blocker_code"],
            "task-outcome-unknown",
        )

    def test_pr_number_without_repository_identity_is_not_aggregated(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["subject"] = {
            "scope": "host",
            "host": "heim-pc",
            "component": "chronik",
            "pr_number": 1008,
        }
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        self.assertEqual(result["goal_count"], 0)
        self.assertEqual(result["unbound_goal_subrun_count"], 1)

    def test_v1_execution_failure_is_accepted_without_blocker_code(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["schema_version"] = "agent-run-event.v1"
        event["kind"] = "agent.run.timed_out"
        event["data"]["result"] = "timed_out"
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        item = result["items"][0]
        self.assertEqual(item["historical_context"]["schema_version"], "agent-run-event.v1")
        self.assertEqual(item["historical_context"]["outcome_class"], "execution_failure")
        self.assertEqual(item["historical_context"]["effective_outcome"], "timed_out")

    def test_goal_summary_counts_unique_subruns_not_events(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        first = history["events"][0]
        first["subject"]["bureau_task_id"] = "BUREAU-GOAL-T002"
        first["event_id"] = module._chronik_event_id(first)
        started = {
            **first,
            "kind": "agent.run.started",
            "data": {**first["data"], "result": "started"},
        }
        started["event_id"] = module._chronik_event_id(started)
        second = {
            **first,
            "source": {**first["source"], "run_id": "task-fedcba9876543210fedcba98-a1"},
            "ts": "2026-07-23T13:00:00Z",
        }
        second["event_id"] = module._chronik_event_id(second)
        history["events"] = [started, first, second]
        history["history"]["event_ids"] = [event["event_id"] for event in history["events"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        goal = result["goal_summary"][0]
        self.assertEqual(goal["event_count"], 3)
        self.assertEqual(goal["subrun_count"], 2)
        self.assertEqual(goal["completed_subruns"], 2)
        self.assertEqual(result["unbound_goal_subrun_count"], 0)
        self.assertTrue(any("self_block_minutes" in item for item in result["measurement_limitations"]))

    def test_chronik_history_recall_bounds_support_refs(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["evidence_refs"] = [f"grabowski-task:ref-{index}" for index in range(10)]
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)
        context = result["items"][0]["historical_context"]

        self.assertEqual(len(context["support_refs"]), module.MAX_HISTORICAL_SUPPORT_REFS)
        self.assertTrue(context["support_refs_truncated"])

    def test_chronik_history_pattern_summary_is_bounded(self) -> None:
        module = self._load_module()
        items = [
            {
                "pattern_fingerprint": f"sha256:{index:064x}",
                "historical_pattern": {"operation": f"operation-{index}"},
            }
            for index in range(module.MAX_HISTORICAL_PATTERN_SUMMARY + 3)
        ]

        summary, total = module._historical_pattern_summary(items)

        self.assertEqual(total, module.MAX_HISTORICAL_PATTERN_SUMMARY + 3)
        self.assertEqual(len(summary), module.MAX_HISTORICAL_PATTERN_SUMMARY)
        self.assertEqual(items[0]["pattern_occurrence_count"], 1)
        self.assertEqual(items[0]["pattern_scope"], "bounded_query_result")

    def test_chronik_history_recall_bounds_long_valid_subject_without_rejecting_event(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        event = history["events"][0]
        event["subject"]["repo"] = "r" * 500
        event["event_id"] = module._chronik_event_id(event)
        history["history"]["event_ids"] = [event["event_id"]]
        unsigned = dict(history)
        unsigned.pop("result_sha256", None)
        history["result_sha256"] = module._sha256_json(unsigned)

        result = module.export_chronik_history_recall(history)

        self.assertEqual(result["returned"], 1)
        self.assertLessEqual(len(result["items"][0]["topic"]), 120)
        self.assertEqual(result["items"][0]["source"], "chronik_event")
        self.assertNotIn("repo", result["items"][0]["evidence_refs"][0])

    def test_chronik_history_recall_rejects_tampered_receipt_digest(self) -> None:
        module = self._load_module()
        history = self._chronik_history_result(module)
        history["events"][0]["data"]["operation"] = "merge"

        with self.assertRaisesRegex(ValueError, "result digest"):
            module.export_chronik_history_recall(history)

    def test_unavailable_chronik_history_becomes_empty_non_authoritative_recall(self) -> None:
        module = self._load_module()
        result = module.export_chronik_history_recall(
            self._chronik_history_result(module, available=False)
        )

        self.assertFalse(result["available"])
        self.assertTrue(result["historical_only"])
        self.assertEqual(result["returned"], 0)
        self.assertEqual(result["items"], [])
        self.assertEqual(result["failure_code"], "chronik_repository_unavailable")
        self.assertEqual(
            result["result_reference"]["result_sha256"],
            result["history_result_sha256"],
        )
        self.assertNotIn(
            "ledger_snapshot_sha256",
            result["result_reference"],
        )
        self.assertIn("current_runtime_state", result["does_not_establish"])

    def test_chronik_history_recall_rejects_invalid_ledger_snapshot(self) -> None:
        module = self._load_module()
        for snapshot in (None, {}, {"sha256": "not-a-digest"}):
            with self.subTest(snapshot=snapshot):
                history = self._chronik_history_result(module)
                if snapshot is None:
                    history["history"].pop("ledger_snapshot")
                else:
                    history["history"]["ledger_snapshot"] = snapshot
                unsigned = dict(history)
                unsigned.pop("result_sha256", None)
                history["result_sha256"] = module._sha256_json(unsigned)

                with self.assertRaisesRegex(ValueError, "ledger snapshot"):
                    module.export_chronik_history_recall(history)

    def test_runtime_publishes_canonical_chronik_backed_operator_recall_tool(self) -> None:
        tasks = (ROOT / "src/grabowski_tasks.py").read_text(encoding="utf-8")
        capabilities = (ROOT / "src/grabowski_capabilities.py").read_text(encoding="utf-8")
        mcp = (ROOT / "src/grabowski_mcp.py").read_text(encoding="utf-8")

        self.assertIn(
            'OPERATOR_HISTORICAL_RECALL_TOOL = "grabowski_operator_historical_recall"',
            tasks,
        )
        self.assertIn(
            '@mcp.tool(name="grabowski_operator_historical_recall"',
            tasks,
        )
        self.assertIn("recall.export_chronik_history_recall", tasks)
        self.assertIn('"grabowski_operator_historical_recall": {', capabilities)
        self.assertIn('"grabowski_operator_historical_recall": ("durable_job",)', mcp)


if __name__ == "__main__":
    unittest.main()
