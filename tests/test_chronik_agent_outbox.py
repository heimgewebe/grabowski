import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_chronik as chronik


def record(**overrides):
    value = {
        "task_id": "a" * 24,
        "unit": "grabowski-task-" + "a" * 24 + "-a1.service",
        "attempt": 1,
    }
    value.update(overrides)
    return value


class ChronikAgentOutboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_enabled = os.environ.get(chronik.ENABLED_ENV)
        self.old_root = os.environ.get(chronik.STATE_ROOT_ENV)

    def tearDown(self):
        if self.old_enabled is None:
            os.environ.pop(chronik.ENABLED_ENV, None)
        else:
            os.environ[chronik.ENABLED_ENV] = self.old_enabled
        if self.old_root is None:
            os.environ.pop(chronik.STATE_ROOT_ENV, None)
        else:
            os.environ[chronik.STATE_ROOT_ENV] = self.old_root
        self.tmp.cleanup()

    def enable(self):
        os.environ[chronik.ENABLED_ENV] = "1"
        os.environ[chronik.STATE_ROOT_ENV] = str(self.root)

    def lines(self):
        files = sorted(self.root.glob("grabowski/chronik-outbox/*.jsonl"))
        self.assertTrue(files)
        return files[0].read_text(encoding="utf-8").splitlines()

    def test_disabled_by_default(self):
        os.environ.pop(chronik.ENABLED_ENV, None)
        os.environ[chronik.STATE_ROOT_ENV] = str(self.root)
        self.assertEqual(chronik.record_task_state(record(), "running"), {"enabled": False, "written": False})
        self.assertEqual(list(self.root.rglob("*.jsonl")), [])

    def test_task_opt_in_writes_without_global_environment(self):
        os.environ.pop(chronik.ENABLED_ENV, None)
        os.environ.pop(chronik.STATE_ROOT_ENV, None)
        result = chronik.record_task_state(
            record(
                chronik_outbox_enabled=1,
                chronik_outbox_state_root=str(self.root),
            ),
            "running",
        )
        self.assertTrue(result["written"])
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.started")

    def test_started_event_when_enabled(self):
        self.enable()
        result = chronik.record_task_state(record(), "running")
        self.assertTrue(result["written"])
        event = json.loads(self.lines()[0])
        self.assertEqual(event["schema_version"], "agent-run-event.v0")
        self.assertEqual(event["kind"], "agent.run.started")
        self.assertEqual(event["source"]["repo"], "heimgewebe/grabowski")
        self.assertEqual(event["data"], {"result": "started"})
        self.assertLessEqual(len(event["caused_by"]), 3)
        self.assertLessEqual(len(event["evidence_refs"]), 5)

    def test_completed_and_blocked_events(self):
        self.enable()
        chronik.record_task_state(record(), "completed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.completed")
        self.assertEqual(event["data"], {"result": "completed"})
        self.tmp.cleanup(); self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); os.environ[chronik.STATE_ROOT_ENV] = str(self.root)
        chronik.record_task_state(record(), "failed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.blocked")
        self.assertEqual(event["data"], {"result": "blocked", "blocker_code": "task-failed"})

    def test_deduplicates_same_event(self):
        self.enable()
        chronik.record_task_state(record(), "running")
        chronik.record_task_state(record(), "running")
        self.assertEqual(len(self.lines()), 1)

    def test_failure_is_non_blocking(self):
        bad_root = self.root / "occupied"
        bad_root.write_text("x", encoding="utf-8")
        os.environ[chronik.ENABLED_ENV] = "1"
        os.environ[chronik.STATE_ROOT_ENV] = str(bad_root)
        result = chronik.record_task_state_safely(record(), "running")
        self.assertFalse(result["written"])
        self.assertIn("error", result)


class PlexerFlushTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_url = os.environ.get(chronik.PLEXER_EVENTS_URL_ENV)

    def tearDown(self):
        if self.old_url is None:
            os.environ.pop(chronik.PLEXER_EVENTS_URL_ENV, None)
        else:
            os.environ[chronik.PLEXER_EVENTS_URL_ENV] = self.old_url
        self.tmp.cleanup()

    def test_plexer_url_normalization(self):
        self.assertEqual(
            chronik.plexer_events_url("http://plexer.local"),
            "http://plexer.local/v1/events",
        )
        self.assertEqual(
            chronik.plexer_events_url("http://plexer.local/v1/events/"),
            "http://plexer.local/v1/events",
        )

    def test_missing_plexer_url_is_non_blocking(self):
        os.environ.pop(chronik.PLEXER_EVENTS_URL_ENV, None)
        result = chronik.send_event_to_plexer_safely({"kind": "agent.run.completed"})
        self.assertFalse(result["configured"])
        self.assertFalse(result["sent"])

    def test_send_event_posts_json_to_plexer(self):
        class Response:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getcode(self):
                return self.status

        seen = {}

        def fake_urlopen(request, timeout):
            seen["url"] = request.full_url
            seen["body"] = request.data.decode("utf-8")
            seen["timeout"] = timeout
            return Response()

        event = {"schema_version": "agent-run-event.v0", "kind": "agent.run.completed", "data": {"result": "completed"}}
        with patch.object(chronik, "urlopen", fake_urlopen):
            result = chronik.send_event_to_plexer(event, url="http://plexer.local", timeout_seconds=2.5)

        self.assertTrue(result["sent"])
        self.assertEqual(result["status_code"], 202)
        self.assertEqual(seen["url"], "http://plexer.local/v1/events")
        self.assertEqual(json.loads(seen["body"]), event)
        self.assertEqual(seen["timeout"], 2.5)

    def test_flush_outbox_file_is_non_destructive(self):
        event = chronik.build_event(record(), "completed")
        self.assertIsNotNone(event)
        path = self.root / "event.jsonl"
        path.write_text(chronik.canonical_json(event) + "\n", encoding="utf-8")

        with patch.object(chronik, "send_event_to_plexer_safely", return_value={"sent": True}):
            result = chronik.flush_outbox_file_to_plexer(path, url="http://plexer.local")

        self.assertEqual(result["events"], 1)
        self.assertEqual(result["sent"], 1)
        self.assertTrue(path.exists())
        self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
