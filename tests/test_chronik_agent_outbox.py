import json
import os
import tempfile
import unittest
from pathlib import Path

import grabowski_chronik as chronik


def record():
    return {
        "task_id": "a" * 24,
        "unit": "grabowski-task-" + "a" * 24 + "-a1.service",
        "attempt": 1,
    }


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


if __name__ == "__main__":
    unittest.main()
