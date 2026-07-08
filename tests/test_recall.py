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
                source="chat",
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
        export = module.export_operator_recall({"prs": [{"repo": "heimgewebe/grabowski", "number": 0} for _ in range(module.MAX_REJECTED_SOURCES + 3)]})

        self.assertEqual(export["rejected_source_count"], module.MAX_REJECTED_SOURCES + 3)
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


    def test_heimlern_boundary_is_offline_proposal_only(self) -> None:
        module = self._load_module()
        export = module.export_operator_recall({"bureau_tasks": [{"id": "T1", "title": "Task", "state": "verified"}]})

        boundary = export["heimlern_offline_learning"]
        self.assertTrue(boundary["allowed"])
        self.assertEqual(boundary["mode"], "offline_proposal_only")
        self.assertIn("live_routing_change", boundary["does_not_establish"])
        self.assertIn("heimlern_live_update", export["does_not_establish"])


if __name__ == "__main__":
    unittest.main()
