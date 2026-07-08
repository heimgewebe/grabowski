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
