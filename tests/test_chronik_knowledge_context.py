"""Chronik knowledge.ledger in the read-only search adapter and the agent bootstrap."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import grabowski_chronik_full_search as search  # noqa: E402


def knowledge_event(n: int, **subject):
    return {
        "event_id": "sha256:" + format(n, "x") * 64,
        "kind": "knowledge.insight.published.v1",
        "ts": f"2026-11-0{n}T10:00:00Z",
        "knowledge_type": "root_cause", "epistemic_status": "confirmed",
        "statement": f"Cause number {n}.",
        "evidence_refs": [f"github:heimgewebe/grabowski#{n}"],
        "subject": {"repo": "heimgewebe/grabowski", **subject},
        "source": {"system": "claude-code", "component": "test"},
        "relations": [],
        "private_payload": "MUST_NOT_LEAK",
    }


def knowledge_payload(items):
    return {
        "schema_version": "chronik-knowledge-search.v1",
        "historical_only": True, "matching_count": len(items),
        "returned": len(items), "has_more": False,
        "events": items,
        "ledger_snapshot": {
            "domain": "knowledge.ledger", "integrity_valid": True,
            "record_count": 100, "sha256": "e" * 64, "complete_bytes": 1,
        },
    }


class KnowledgeQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "tools").mkdir()
        (root / "tools/knowledge_ledger.py").write_text("# fixture\n", encoding="utf-8")
        (root / "data").mkdir()
        self.config = {
            "available": True, "repository": str(root),
            "python": sys.executable, "data_dir": str(root / "data"),
        }
        self.payload = knowledge_payload(
            [{"event": knowledge_event(1), "superseded_by": []}])
        self.calls = []

    def execute(self, argv, cwd):
        self.calls.append(argv)
        return {"returncode": 0, "stdout": json.dumps(self.payload)}

    def run_query(self, **selectors):
        return search.knowledge_query(
            selectors=selectors or {"repo": "heimgewebe/grabowski"},
            limit=5, configuration=self.config, executor=self.execute)

    def test_valid_result_is_bound_to_knowledge_snapshot(self):
        result = self.run_query()
        self.assertTrue(result["available"])
        self.assertEqual(result["ledger_snapshot"]["domain"], "knowledge.ledger")
        self.assertEqual(len(result["result_sha256"]), 64)
        argv = self.calls[0]
        self.assertTrue(argv[1].endswith("tools/knowledge_ledger.py"))
        self.assertEqual(argv[argv.index("--repo") + 1], "heimgewebe/grabowski")
        self.assertEqual(argv[argv.index("--limit") + 1], "5")

    def test_wrong_domain_or_invalid_integrity_is_a_gap(self):
        self.payload["ledger_snapshot"]["domain"] = "agent.ledger"
        self.assertEqual(self.run_query()["failure_code"],
                         "chronik_knowledge_contract_failed")
        self.payload["ledger_snapshot"]["domain"] = "knowledge.ledger"
        self.payload["ledger_snapshot"]["integrity_valid"] = False
        self.assertFalse(self.run_query()["available"])

    def test_cli_failure_and_bad_selectors(self):
        self.execute = lambda argv, cwd: {"returncode": 2, "stdout": ""}
        self.assertEqual(self.run_query()["failure_code"], "chronik_knowledge_cli_failed")
        with self.assertRaises(ValueError):
            search.knowledge_query(selectors={"task_id": "x"}, configuration=self.config,
                                   executor=self.execute)
        with self.assertRaises(ValueError):
            search.knowledge_query(selectors={"repo": ""}, configuration=self.config,
                                   executor=self.execute)

    def test_sandbox_admits_only_the_two_read_only_clis(self):
        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        with self.assertRaisesRegex(ValueError, "identity"):
            search.read_only_search_argv(
                [sys.executable, str(repo / "tools/coding_memory.py")], repo, data)
        self.assertIn("knowledge_ledger.py", search.READ_ONLY_CLIS)
        self.assertIn("chronik_search.py", search.READ_ONLY_CLIS)


class BootstrapKnowledgeContextTests(unittest.TestCase):
    def load_module(self):
        spec = importlib.util.spec_from_file_location(
            f"_agent_bootstrap_knowledge_{id(self)}", ROOT / "src/grabowski_agent_bootstrap.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def run_events(**kwargs):
        return {
            "available": True, "historical_only": True, "search_exhaustive": True,
            "matching_count": 0, "has_more": False, "events": [],
            "ledger_snapshot": {"integrity_valid": True, "invalid_record_count": 0,
                                "sha256": "c" * 64},
        }

    def test_knowledge_section_orders_current_first_and_hides_private_fields(self):
        module = self.load_module()
        calls = []
        old, new = knowledge_event(1), knowledge_event(2)

        def knowledge(**kwargs):
            calls.append(kwargs)
            return {
                "available": True, "historical_only": True, "matching_count": 2,
                "has_more": False, "result_sha256": "f" * 64,
                "ledger_snapshot": {"integrity_valid": True, "sha256": "e" * 64},
                "events": [
                    {"event": old, "superseded_by": [new["event_id"]]},
                    {"event": new, "superseded_by": []},
                ],
            }

        context = module._chronik_first_context(
            repo="heimgewebe/grabowski", search_fn=self.run_events,
            knowledge_search_fn=knowledge)
        self.assertEqual(calls, [{"repo": "heimgewebe/grabowski", "limit": 20}])
        section = context["knowledge"]
        self.assertEqual(section["status"], "available")
        self.assertEqual([e["event_id"] for e in section["events"]],
                         [new["event_id"], old["event_id"]])
        self.assertEqual(section["snapshot_sha256"], "e" * 64)
        self.assertNotIn("MUST_NOT_LEAK", json.dumps(context))
        self.assertEqual(context["status"], "available")

    def test_target_constraints_and_statement_bound(self):
        module = self.load_module()
        long_event = knowledge_event(3, component="rustdesk", pr_number=7)
        long_event["statement"] = "x" * 2000
        other = knowledge_event(4, component="other", pr_number=7)

        def knowledge(**kwargs):
            return {
                "available": True, "historical_only": True, "matching_count": 2,
                "has_more": False,
                "ledger_snapshot": {"integrity_valid": True, "sha256": "e" * 64},
                "events": [{"event": long_event, "superseded_by": []},
                           {"event": other, "superseded_by": []}],
            }

        section = module._chronik_first_context(
            repo="heimgewebe/grabowski", subject_component="rustdesk", pr_number=7,
            search_fn=self.run_events, knowledge_search_fn=knowledge)["knowledge"]
        self.assertEqual(section["selected_event_count"], 1)
        self.assertEqual(section["discarded_by_target_constraints"], 1)
        self.assertLessEqual(len(section["events"][0]["statement"]),
                             module.KNOWLEDGE_STATEMENT_CHARS)

    def test_knowledge_outage_never_changes_run_event_status(self):
        module = self.load_module()

        def broken(**kwargs):
            raise OSError("ledger offline")

        context = module._chronik_first_context(
            host="heim-pc", search_fn=self.run_events, knowledge_search_fn=broken)
        self.assertEqual(context["status"], "available")
        self.assertEqual(context["knowledge"]["status"], "knowledge_context_unavailable")
        self.assertEqual(context["knowledge"]["failure_code"], "OSError")

    def test_injected_run_search_alone_does_not_touch_live_knowledge(self):
        module = self.load_module()
        context = module._chronik_first_context(
            repo="heimgewebe/grabowski", search_fn=self.run_events)
        self.assertEqual(context["knowledge"]["status"], "not_requested")

    def test_unbound_target_stays_skipped(self):
        module = self.load_module()
        context = module._chronik_first_context(
            search_fn=self.run_events, knowledge_search_fn=lambda **kw: 1 / 0)
        self.assertEqual(context["status"], "skipped_unbound_target")
        self.assertNotIn("knowledge", context)


if __name__ == "__main__":
    unittest.main()
