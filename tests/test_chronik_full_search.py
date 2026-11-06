"""Contract tests for complete, read-only Chronik historical search via Grabowski."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import grabowski_chronik_full_search as search  # noqa: E402


class ChronikFullSearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / "tools").mkdir()
        (root / "tools/chronik_search.py").write_text("# fixture\n", encoding="utf-8")
        data = root / "data"
        data.mkdir()
        self.config = {
            "available": True, "repository": str(root),
            "python": sys.executable, "data_dir": str(data),
        }
        self.filters = {name: None for name in search.FILTER_NAMES}
        self.filters["pr_number"] = 1717
        self.event = {"event_id": "sha256:" + "a" * 64, "kind": "agent.run.failed"}
        self.payload = {
            "schema_version": "chronik-agent-search.v1",
            "query": dict(self.filters),
            "query_sha256": search._sha(self.filters),
            "historical_only": True,
            "result_scope": "complete_committed_agent_ledger_snapshot",
            "search_exhaustive": True,
            "does_not_establish": ["live deployment"],
            "returned": 1, "matching_count": 4,
            "remaining_from_cursor": 4, "has_more": True,
            "next_cursor": "cursor-for-snapshot",
            "events": [{
                "event": self.event,
                "event_id": self.event["event_id"],
                "event_ref": "chronik:agent.ledger:" + self.event["event_id"],
                "canonical_event_sha256": search._sha(self.event),
            }],
            "ledger_snapshot": {
                "domain": "agent.ledger", "sha256": "b" * 64,
                "integrity_valid": True, "total_record_count": 54863,
                "valid_record_count": 54863, "invalid_record_count": 0,
            },
        }
        self.calls = []

    def execute(self, argv, cwd):
        self.calls.append((argv, cwd))
        return {
            "returncode": 0, "timed_out": False,
            "stdout": json.dumps(self.payload),
        }

    def query(self, *, cursor=None):
        return search.query(
            selectors=self.filters, configuration=self.config,
            executor=self.execute, limit=2, cursor=cursor,
        )

    def test_exact_pr_search_preserves_complete_snapshot_and_forward_cursor(self):
        result = self.query(cursor="old-page-cursor")
        self.assertTrue(result["available"])
        self.assertTrue(result["search_exhaustive"])
        self.assertEqual(result["matching_count"], 4)
        self.assertEqual(result["ledger_snapshot"]["sha256"], "b" * 64)
        self.assertEqual(result["next_cursor"], "cursor-for-snapshot")
        argv, cwd = self.calls[0]
        self.assertEqual(cwd, Path(self.config["repository"]))
        self.assertIn("--pr-number", argv)
        self.assertEqual(argv[argv.index("--pr-number") + 1], "1717")
        self.assertEqual(argv[argv.index("--cursor") + 1], "old-page-cursor")
        self.assertTrue(argv[1].endswith("tools/chronik_search.py"))
        self.assertNotIn("query", argv)
        self.assertEqual(len(result["events"]), 1)

    def test_hash_tampering_must_not_be_reported_as_available_history(self):
        self.payload["events"][0]["canonical_event_sha256"] = "0" * 64
        result = self.query()
        self.assertFalse(result["available"])
        self.assertEqual(result["failure_code"], "chronik_full_search_contract_failed")
        self.assertEqual(result["events"], [])

    def test_unbound_query_is_rejected(self):
        self.payload["query"]["pr_number"] = 999
        self.assertEqual(self.query()["failure_code"], "chronik_full_search_contract_failed")

    def test_invalid_ledger_is_rejected(self):
        self.payload["ledger_snapshot"]["invalid_record_count"] = 1
        self.assertEqual(self.query()["failure_code"], "chronik_full_search_contract_failed")

    def test_truncated_provider_response_is_not_a_complete_search(self):
        def truncated(argv, cwd):
            return {"returncode": 0, "stdout": "{}", "stdout_truncated": True}
        self.assertEqual(
            search.query(selectors=self.filters, configuration=self.config, executor=truncated)["failure_code"],
            "chronik_full_search_cli_failed",
        )

    def test_stale_cursor_is_explicitly_retriable_from_first_page(self):
        def stale(argv, cwd):
            return {
                "returncode": 2, "stdout": "",
                "stderr": "chronik-search: stale search cursor: ledger changed; restart search",
            }
        result = search.query(
            selectors=self.filters, configuration=self.config, executor=stale,
            cursor="expired-snapshot",
        )
        self.assertFalse(result["available"])
        self.assertEqual(
            result["failure_code"], "chronik_cursor_stale_restart_from_first_page",
        )

    def test_missing_provider_is_unavailable_not_an_empty_result(self):
        config = dict(self.config, available=False, reason="chronik_repository_unavailable")
        result = search.query(selectors=self.filters, configuration=config, executor=self.execute)
        self.assertFalse(result["available"])
        self.assertEqual(result["failure_code"], "chronik_repository_unavailable")
        self.assertEqual(self.calls, [])

    def test_unusable_provider_continuation_cannot_claim_available(self):
        for token in ("", "x" * 4097):
            with self.subTest(length=len(token)):
                self.payload["next_cursor"] = token
                result = self.query()
                self.assertFalse(result["available"])
                self.assertEqual(
                    result["failure_code"], "chronik_full_search_contract_failed"
                )

    def test_read_only_command_mounts_only_source_and_ledger(self):
        from unittest.mock import patch

        import grabowski_agent_sandbox as sandbox

        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        argv = [sys.executable, str(repo / "tools/chronik_search.py"),
                "--data-dir", str(data), "search", "--pr-number", "1717"]
        with patch.object(sandbox, "require_bwrap", return_value=Path("/usr/bin/bwrap")):
            prepared = search.read_only_search_argv(argv, repo, data)
        self.assertEqual(prepared[0], "/usr/bin/bwrap")
        self.assertIn("--ro-bind", prepared)
        self.assertNotIn("--bind", prepared)
        self.assertIn(["--ro-bind", str(repo), str(repo)],
                      [prepared[i:i + 3] for i in range(len(prepared) - 2)])
        self.assertIn(["--ro-bind", str(data), str(data)],
                      [prepared[i:i + 3] for i in range(len(prepared) - 2)])
        self.assertEqual(prepared[-len(argv):], argv)

    def test_live_read_only_sandbox_blocks_chronik_script_writes(self):
        import os
        import subprocess

        # The immutable Nix deployment provides the verified bwrap executable.
        # CI machines without that runtime still check the complete argv above.
        if not os.environ.get("GRABOWSKI_BWRAP_BIN"):
            self.skipTest("Nix bubblewrap runtime unavailable")
        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        sentinel = data / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        (repo / "tools/chronik_search.py").write_text(
            "from pathlib import Path\\n"
            f"Path({str(sentinel)!r}).write_text('modified')\\n",
            encoding="utf-8",
        )
        argv = [sys.executable, str(repo / "tools/chronik_search.py"),
                "--data-dir", str(data), "search"]
        command = search.read_only_search_argv(argv, repo, data)
        completed = subprocess.run(command, capture_output=True, timeout=20, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

    def test_bad_filters_and_limits_fail_before_execution(self):
        with self.assertRaisesRegex(ValueError, "selector"):
            search.query(selectors={}, configuration=self.config, executor=self.execute)
        with self.assertRaisesRegex(ValueError, "at least one"):
            search.query(selectors={name: None for name in search.FILTER_NAMES},
                         configuration=self.config, executor=self.execute)
        with self.assertRaisesRegex(ValueError, "pr_number"):
            search.query(selectors={**self.filters, "pr_number": True},
                         configuration=self.config, executor=self.execute)
        with self.assertRaisesRegex(ValueError, "limit"):
            search.query(selectors=self.filters, configuration=self.config,
                         executor=self.execute, limit=100)
        with self.assertRaisesRegex(ValueError, "cursor"):
            search.query(selectors=self.filters, configuration=self.config,
                         executor=self.execute, cursor="x" * 4097)


if __name__ == "__main__":
    unittest.main()
