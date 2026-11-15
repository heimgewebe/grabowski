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

    def test_invalid_datetime_filters_fail_before_provider_invocation(self):
        cases = (
            ("since", "2026-11-05"),
            ("since", "2026-11-05T00:00:00"),
            ("since", "not-a-date"),
            ("until", "2026-11-06"),
            ("until", "2026-11-06T23:59:59"),
            ("until", "2026-13-06T00:00:00+01:00"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                self.filters[field] = value
                with self.assertRaisesRegex(ValueError, field + " must be an ISO 8601 timestamp with timezone"):
                    self.query()
                self.filters[field] = None
        self.assertEqual(self.calls, [])

    def test_timezone_aware_datetime_filters_reach_provider_unchanged(self):
        self.filters["since"] = "2026-11-05T00:00:00+01:00"
        self.filters["until"] = "2026-11-06T23:59:59Z"
        self.payload["query"] = dict(self.filters)
        self.payload["query_sha256"] = search._sha(self.filters)
        result = self.query()
        self.assertTrue(result["available"])
        argv, _ = self.calls[0]
        for field in ("since", "until"):
            self.assertEqual(
                argv[argv.index("--" + field) + 1], self.filters[field]
            )

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

    def test_unsupported_operation_is_input_error_not_provider_outage(self):
        def unsupported(argv, cwd):
            self.calls.append((argv, cwd))
            return {
                "returncode": 2, "stdout": "",
                "stderr": "chronik-search: unsupported operation\n",
            }
        self.filters["operation"] = "never-existing-operation"
        result = search.query(
            selectors=self.filters, configuration=self.config,
            executor=unsupported, limit=2,
        )
        self.assertFalse(result["available"])
        self.assertEqual(
            result["failure_code"], "chronik_full_search_unsupported_operation"
        )
        self.assertEqual(len(self.calls), 1)

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
        # CI may use /opt/hostedtoolcache Python rather than /usr or Nix.
        # Construct a declared release-style venv instead of relaxing the
        # production executor's trusted-interpreter boundary for a unit test.
        venv = Path(self.tmp.name) / "static-review-runtime" / ".venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin/python").symlink_to(sys.executable)
        (venv / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).resolve().parent}\n", encoding="utf-8",
        )
        argv = [str(venv / "bin/python"), str(repo / "tools/chronik_search.py"),
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

    def test_virtualenv_python_is_bound_read_only(self):
        from unittest.mock import patch

        import grabowski_agent_sandbox as sandbox

        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        venv = Path(self.tmp.name) / "grabowski-release" / ".venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin" / "python").symlink_to(sys.executable)
        (venv / "pyvenv.cfg").write_text("home = /nix/store\n", encoding="utf-8")
        argv = [str(venv / "bin/python"), str(repo / "tools/chronik_search.py"),
                "--data-dir", str(data), "search"]
        with patch.object(sandbox, "require_bwrap", return_value=Path("/usr/bin/bwrap")):
            prepared = search.read_only_search_argv(argv, repo, data)
        self.assertIn(["--ro-bind", str(venv), str(venv)],
                      [prepared[i:i + 3] for i in range(len(prepared) - 2)])
        self.assertNotIn("--bind", prepared)

    def test_live_virtualenv_python_runs_inside_read_only_sandbox(self):
        import os
        import subprocess

        if not os.environ.get("GRABOWSKI_BWRAP_BIN"):
            self.skipTest("Nix bubblewrap runtime unavailable")
        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        venv = repo / "grabowski-operator-release" / ".venv"
        (venv / "bin").mkdir(parents=True)
        (venv / "bin/python").symlink_to(sys.executable)
        (venv / "pyvenv.cfg").write_text(
            f"home = {Path(sys.executable).resolve().parent}\n",
            encoding="utf-8",
        )
        (repo / "tools/chronik_search.py").write_text(
            "import sys\nprint('sandbox-venv-ok')\n", encoding="utf-8",
        )
        argv = [str(venv / "bin/python"), str(repo / "tools/chronik_search.py"),
                "--data-dir", str(data), "search"]
        completed = subprocess.run(
            search.read_only_search_argv(argv, repo, data),
            capture_output=True, timeout=20, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), b"sandbox-venv-ok")

    def test_live_read_only_sandbox_blocks_chronik_script_writes(self):
        import os
        import subprocess

        if not os.environ.get("GRABOWSKI_BWRAP_BIN"):
            self.skipTest("Nix bubblewrap runtime unavailable")
        repo = Path(self.config["repository"])
        data = Path(self.config["data_dir"])
        sentinel = data / "sentinel.txt"
        sentinel.write_text("unchanged", encoding="utf-8")
        cli = repo / "tools/chronik_search.py"
        script = (
            "from pathlib import Path\n"
            f"Path({str(sentinel)!r}).write_text('modified')\n"
        )
        compile(script, str(cli), "exec")
        cli.write_text(script, encoding="utf-8")
        argv = [sys.executable, str(cli), "--data-dir", str(data), "search"]
        # A real positive control proves the payload is executable and would
        # mutate the host sentinel if not mounted read-only.
        control = subprocess.run(argv, capture_output=True, timeout=20, check=False)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "modified")
        sentinel.write_text("unchanged", encoding="utf-8")
        command = search.read_only_search_argv(argv, repo, data)
        completed = subprocess.run(command, capture_output=True, timeout=20, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(
            b"Read-only file system" in completed.stderr
            or b"PermissionError" in completed.stderr,
            completed.stderr,
        )
        self.assertNotIn(b"SyntaxError", completed.stderr)
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
