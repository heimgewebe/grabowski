from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_long_horizon_trace as producer


TASK_ID = "a" * 24
TASK_UNIT = f"grabowski-task-{TASK_ID}-a1.service"


def task_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "task_id": TASK_ID,
        "attempt": 1,
        "created_at_unix": 1234,
        "authoritative_unit": TASK_UNIT,
        "state": "running",
        "argv": ["secret", "command"],
        "argv_sha256": "b" * 64,
        "prompt": "private reasoning must not be captured",
        "stdout": "private output",
    }
    record.update(overrides)
    return record


def evaluator_module():
    path = ROOT / "tools" / "grabowski_long_horizon_eval.py"
    spec = importlib.util.spec_from_file_location("grabowski_long_horizon_eval_for_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LongHorizonTraceProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "trace-state"
        self.lookup = lambda _task_id: task_record()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def open(self, *, retention_mode: str = "ephemeral") -> dict[str, object]:
        return producer.open_trace(
            self.root,
            TASK_ID,
            retention_mode=retention_mode,
            task_lookup=self.lookup,
        )

    def test_open_is_explicit_idempotent_and_privacy_bounded(self) -> None:
        first = self.open()
        second = self.open()

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        self.assertTrue(second["idempotent_replay"])

        session = self.root / f"task-{TASK_ID}-attempt-1"
        manifest = json.loads((session / "manifest.json").read_text())
        self.assertEqual(
            "grabowski-persistent-task-store-snapshot",
            manifest["source_authority"],
        )
        self.assertEqual(
            {
                "task_id": TASK_ID,
                "attempt": 1,
                "created_at_unix": 1234,
                "authoritative_unit": TASK_UNIT,
            },
            manifest["source_snapshot"],
        )
        source_text = json.dumps(manifest["source_snapshot"], sort_keys=True)
        self.assertNotIn("argv", source_text)
        self.assertNotIn("secret", source_text)
        self.assertNotIn("prompt", source_text)
        self.assertNotIn("stdout", source_text)
        self.assertFalse(manifest["privacy"]["free_text_capture"])
        self.assertIn(
            "argv_digest", manifest["privacy"]["forbidden_capture_categories"]
        )
        self.assertFalse(manifest["routing_effect"])
        self.assertFalse(manifest["policy_effect"])
        self.assertTrue(manifest["historical_evidence_only"])
        self.assertEqual("ephemeral", manifest["retention"]["mode"])

        trace = (session / "trace.jsonl").read_text().splitlines()
        self.assertEqual(1, len(trace))
        self.assertEqual("run.started", json.loads(trace[0])["kind"])

    def test_no_trace_exists_without_explicit_open(self) -> None:
        self.assertFalse(self.root.exists())

    def test_records_monotone_typed_monitoring_and_exact_replay(self) -> None:
        opened = self.open()
        attempt = int(opened["attempt"])
        requirement = producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=0,
            kind="monitor.requirement",
            monitor_id="pr-ci-mergeability",
            cadence_steps=2,
        )
        first_check = producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=1,
            kind="monitor.check",
            monitor_id="pr-ci-mergeability",
        )
        replay = producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=1,
            kind="monitor.check",
            monitor_id="pr-ci-mergeability",
        )

        self.assertTrue(requirement["appended"])
        self.assertTrue(first_check["appended"])
        self.assertFalse(replay["appended"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(first_check["event_sha256"], replay["event_sha256"])

        with self.assertRaisesRegex(producer.TraceProducerError, "monotone"):
            producer.record_event(
                self.root,
                TASK_ID,
                attempt,
                step=0,
                kind="monitor.check",
                monitor_id="pr-ci-mergeability",
            )

    def test_monitor_check_requires_explicit_requirement(self) -> None:
        opened = self.open()
        with self.assertRaisesRegex(producer.TraceProducerError, "earlier requirement"):
            producer.record_event(
                self.root,
                TASK_ID,
                int(opened["attempt"]),
                step=1,
                kind="monitor.check",
                monitor_id="undeclared-monitor",
            )

    def test_commitment_abandonment_accepts_only_reason_codes(self) -> None:
        opened = self.open()
        attempt = int(opened["attempt"])
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=1,
            kind="commitment.declared",
            commitment_id="rerun-focused-tests",
            horizon_steps=3,
        )
        result = producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=2,
            kind="commitment.abandoned",
            commitment_id="rerun-focused-tests",
            reason="target_changed",
            evidence_refs=["pr-head:abc123"],
        )
        self.assertTrue(result["appended"])

        other_root = Path(self.temporary.name) / "other-state"
        opened_other = producer.open_trace(
            other_root,
            TASK_ID,
            retention_mode="ephemeral",
            task_lookup=self.lookup,
        )
        producer.record_event(
            other_root,
            TASK_ID,
            int(opened_other["attempt"]),
            step=1,
            kind="commitment.declared",
            commitment_id="commitment-two",
        )
        with self.assertRaisesRegex(producer.TraceProducerError, "reason must be one of"):
            producer.record_event(
                other_root,
                TASK_ID,
                int(opened_other["attempt"]),
                step=2,
                kind="commitment.abandoned",
                commitment_id="commitment-two",
                reason="free form private explanation",
            )

    def test_close_is_idempotent_and_blocks_later_events(self) -> None:
        opened = self.open()
        attempt = int(opened["attempt"])
        first = producer.close_trace(self.root, TASK_ID, attempt, step=1)
        second = producer.close_trace(self.root, TASK_ID, attempt, step=1)

        self.assertTrue(first["closeout_created"])
        self.assertFalse(second["closeout_created"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(first["trace_sha256"], second["trace_sha256"])
        with self.assertRaisesRegex(producer.TraceProducerError, "already closed"):
            producer.record_event(
                self.root,
                TASK_ID,
                attempt,
                step=2,
                kind="commitment.declared",
                commitment_id="too-late",
            )

    def test_source_snapshot_rejects_unbound_or_malformed_task_identity(self) -> None:
        with self.assertRaisesRegex(producer.TraceProducerError, "authoritative_unit"):
            producer.open_trace(
                self.root,
                TASK_ID,
                retention_mode="ephemeral",
                task_lookup=lambda _task_id: task_record(authoritative_unit="bad unit"),
            )

    def test_tampered_noncanonical_trace_fails_closed(self) -> None:
        opened = self.open()
        trace_path = Path(str(opened["trace_path"]))
        with trace_path.open("a", encoding="utf-8") as handle:
            handle.write(
                '{"schema_version":"grabowski.long-horizon-trace.v1", "run_id":"x"}\n'
            )
        with self.assertRaisesRegex(producer.TraceProducerError, "non-canonical"):
            producer.close_trace(self.root, TASK_ID, int(opened["attempt"]), step=1)

    def test_generated_trace_is_deterministically_evaluable(self) -> None:
        opened = self.open(retention_mode="operator-managed-local")
        attempt = int(opened["attempt"])
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=0,
            kind="monitor.requirement",
            monitor_id="pr-ci-mergeability",
            cadence_steps=2,
        )
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=1,
            kind="monitor.check",
            monitor_id="pr-ci-mergeability",
        )
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=1,
            kind="commitment.declared",
            commitment_id="rerun-focused-tests",
            horizon_steps=2,
        )
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=2,
            kind="commitment.completed",
            commitment_id="rerun-focused-tests",
        )
        producer.record_event(
            self.root,
            TASK_ID,
            attempt,
            step=3,
            kind="monitor.check",
            monitor_id="pr-ci-mergeability",
        )
        closed = producer.close_trace(self.root, TASK_ID, attempt, step=3)

        evaluator = evaluator_module()
        text = Path(str(closed["trace_path"])).read_text()
        first = evaluator.evaluate_records(evaluator.parse_jsonl(text))
        second = evaluator.evaluate_records(evaluator.parse_jsonl(text))
        self.assertEqual(first, second)
        self.assertEqual(
            1.0, first["aggregate"]["monitoring_segment_compliance_rate"]
        )
        self.assertEqual(
            1.0, first["aggregate"]["commitment_completion_at_horizon_rate"]
        )
        self.assertEqual(0.0, first["aggregate"]["commitment_silent_drop_rate"])


if __name__ == "__main__":
    unittest.main()
