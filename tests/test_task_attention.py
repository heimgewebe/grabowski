from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_current_work_surface as current_work_surface
import grabowski_lifecycle_archive as lifecycle_archive
import grabowski_task_attention as attention
import grabowski_tasks as tasks


LOCAL_HOST = {
    "transport": "local",
    "target": "local",
    "enabled": True,
    "roles": ["test"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}


def _launcher(returncode: int = 0) -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }


class TaskAttentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / ".git").write_text("gitdir: /tmp/test-worktree\n", encoding="utf-8")
        self.database = self.root / "state" / "tasks.sqlite3"
        self.outcomes = self.database.with_suffix(".outcomes")
        self.decisions = self.database.with_suffix(".attention-decisions")
        self.resource_database = self.root / "state" / "resources.sqlite3"
        (self.root / "state").mkdir(parents=True, exist_ok=True)
        os.chmod(self.root / "state", 0o700)
        self.audit_log = self.root / "state" / "write-audit.jsonl"
        self.archive_root = self.root / "state" / "task-archives"
        self.archive_effect_root = self.root / "state" / "task-archive-effects"
        self.projection_root = self.root / "state" / "task-projection"
        self.patches = [
            patch.object(tasks, "TASK_DB", self.database),
            patch.object(tasks, "TASK_OUTCOMES_DIR", self.outcomes),
            patch.object(tasks.resources, "RESOURCE_DB", self.resource_database),
            patch.object(tasks.base, "AUDIT_LOG", self.audit_log),
            patch.object(attention.alert_outbox, "enqueue_and_schedule"),
            patch.object(
                tasks,
                "_task_output_cleanup_run",
                return_value={
                    "status": "missing",
                    "mode": "inspect",
                    "observer": "task-output-cleanup-v1",
                },
            ),
            patch.dict(
                os.environ,
                {
                    "GRABOWSKI_TASK_ATTENTION_ROOT": str(self.decisions),
                    "GRABOWSKI_TASK_ARCHIVE_ROOT": str(self.archive_root),
                    "GRABOWSKI_TASK_ARCHIVE_EFFECT_ROOT": str(self.archive_effect_root),
                    "GRABOWSKI_TASK_PROJECTION_ROOT": str(self.projection_root),
                },
            ),
        ]
        for item in self.patches:
            item.start()
        self.start_counter = 0

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _start(
        self, resource_keys: list[str] | None = None
    ) -> dict[str, object]:
        self.start_counter += 1
        command_argument = "ok" if self.start_counter == 1 else f"ok-{self.start_counter}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
        ):
            return tasks.grabowski_task_start(
                "local",
                ["/bin/echo", command_argument],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="verify-then-retry",
                resource_keys=resource_keys,
            )

    def _failed_task(self) -> dict[str, object]:
        started = self._start()
        task_id = started["task"]["task_id"]
        tasks._set_state(task_id, "failed", observation={"state": "failed"})
        return tasks._row(task_id)


    def _verified_retry_pair(
        self,
        *,
        successor_state: str = "failed",
    ) -> tuple[dict[str, object], dict[str, object]]:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "verified-retry"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
            source = tasks._set_state(
                str(first["task_id"]),
                "failed",
                observation={"state": "failed", "source": "test"},
            )
            resumed = tasks.reconcile_tasks_resume(
                task_id=str(first["task_id"]),
                max_resumes=1,
                reason="repository head advanced after the failed validation",
            )
            successor_id = str(resumed["resumed"][0]["task_id"])
            successor = tasks._row(successor_id)
            if successor_state != str(successor["state"]):
                successor = tasks._set_state(
                    successor_id,
                    successor_state,
                    observation={
                        "state": successor_state,
                        "source": "test-successor",
                    },
                )
        return source, successor

    def _completed_task(
        self, resource_keys: list[str] | None = None
    ) -> dict[str, object]:
        started = self._start(resource_keys=resource_keys)
        task_id = str(started["task"]["task_id"])
        tasks._set_state(task_id, "completed", observation={"state": "completed"})
        return tasks._row(task_id)

    def _archive_parameters(
        self, record: dict[str, object], **overrides: object
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "task_id": record["task_id"],
            "expected_attempt": record["attempt"],
            "expected_unit": record["unit"],
            "expected_authoritative_unit": record["authoritative_unit"],
            "expected_argv_sha256": record["argv_sha256"],
            "expected_execution_envelope_sha256": record[
                "execution_envelope_sha256"
            ],
            "expected_lifecycle_receipt_sha256": record[
                "lifecycle_receipt_sha256"
            ],
            "minimum_age_seconds": 0,
            "execution_id": f"test-task-closeout-archive:{record['task_id']}",
        }
        value.update(overrides)
        return value

    @staticmethod
    def _inactive_process_observation() -> dict[str, object]:
        return {
            "properties": {
                "LoadState": "not-found",
                "ActiveState": "inactive",
                "SubState": "dead",
            },
            "probe": {"returncode": 0, "outcome_unknown": False},
        }

    def _parameters(self, record: dict[str, object], **overrides: object) -> dict[str, object]:
        outcome = json.loads(
            (self.outcomes / f"{record['task_id']}.json").read_text(encoding="utf-8")
        )
        value: dict[str, object] = {
            "task_id": record["task_id"],
            "decision": "closed",
            "expected_attempt": record["attempt"],
            "expected_unit": record["unit"],
            "expected_authoritative_unit": record["authoritative_unit"],
            "expected_argv_sha256": record["argv_sha256"],
            "expected_execution_envelope_sha256": record["execution_envelope_sha256"],
            "outcome_receipt_sha256": outcome["receipt_sha256"],
            "authority": "operator:alex",
            "evidence_ref": "bureau:event:597",
        }
        value.update(overrides)
        return value

    @staticmethod
    def _to_legacy_unbound_outcome(
        lifecycle: dict[str, object],
    ) -> dict[str, object]:
        legacy = {
            key: value
            for key, value in lifecycle.items()
            if key
            not in {
                "kind",
                "terminalization",
                "receipt_sha256",
                "authoritative_unit",
                "execution_backend",
                "systemd_scope",
            }
        }
        legacy["schema_version"] = 1
        legacy["receipt_sha256"] = attention._sha256_json(legacy)
        return legacy

    def test_decision_is_private_create_only_and_idempotent(self) -> None:
        record = self._failed_task()
        parameters = self._parameters(record)

        first = attention.record_decision(parameters)
        second = attention.record_decision(parameters)

        self.assertTrue(first["created"])
        self.assertFalse(first["replayed"])
        self.assertFalse(second["created"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])
        decision_path = self.decisions / f"{record['task_id']}.a1.json"
        self.assertEqual(0o600, decision_path.stat().st_mode & 0o777)
        self.assertEqual(0o700, self.decisions.stat().st_mode & 0o777)
        stored = tasks._row(str(record["task_id"]))
        self.assertEqual("failed", stored["state"])
        self.assertEqual(1, stored["attempt"])

    def test_authoritative_decision_schedules_deduplicated_owner_alert(self) -> None:
        record = self._failed_task()
        with patch.object(
            attention.alert_outbox,
            "enqueue_and_schedule",
            side_effect=RuntimeError("dispatcher unavailable"),
        ) as enqueue:
            result = attention.record_decision(
                self._parameters(record, decision="deferred")
            )

        self.assertTrue(result["created"])
        enqueue.assert_called_once()
        parameters = enqueue.call_args.kwargs
        self.assertEqual("owner_decision", parameters["event_class"])
        self.assertEqual("task_attention", parameters["producer"])
        self.assertEqual(result["receipt_sha256"], parameters["deduplication_key"])
        self.assertEqual(
            f"{record['task_id']}:a{record['attempt']}",
            parameters["correlation_key"],
        )

    def test_different_material_conflicts_without_replacement(self) -> None:
        record = self._failed_task()
        first = attention.record_decision(self._parameters(record))
        with self.assertRaises(attention.TaskAttentionConflictError):
            attention.record_decision(
                self._parameters(record, evidence_ref="bureau:event:598")
            )
        decision_path = self.decisions / f"{record['task_id']}.a1.json"
        payload = json.loads(decision_path.read_text(encoding="utf-8"))
        self.assertEqual(first["receipt_sha256"], payload["receipt_sha256"])

    def test_expected_task_binding_drift_blocks_before_publication(self) -> None:
        record = self._failed_task()
        with self.assertRaises(attention.TaskAttentionConflictError):
            attention.record_decision(self._parameters(record, expected_attempt=2))
        self.assertEqual([], list(self.decisions.glob("*.json")))

    def test_missing_outcome_receipt_blocks_decision(self) -> None:
        record = self._failed_task()
        parameters = self._parameters(record)
        outcome_path = self.outcomes / f"{record['task_id']}.json"
        outcome_path.unlink()
        with self.assertRaises(FileNotFoundError):
            attention.record_decision(parameters)

    def test_wrong_expected_outcome_receipt_blocks_decision(self) -> None:
        record = self._failed_task()
        with self.assertRaises(attention.TaskAttentionConflictError):
            attention.record_decision(
                self._parameters(record, outcome_receipt_sha256="a" * 64)
            )

    def test_manipulated_outcome_self_hash_is_rejected(self) -> None:
        record = self._failed_task()
        parameters = self._parameters(record)
        outcome_path = self.outcomes / f"{record['task_id']}.json"
        payload = json.loads(outcome_path.read_text(encoding="utf-8"))
        payload["state"] = "timed_out"
        outcome_path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(outcome_path, 0o600)
        with self.assertRaises(attention.TaskAttentionIntegrityError):
            attention.record_decision(parameters)

    def test_legacy_primary_receipt_does_not_hide_authoritative_lifecycle_receipt(self) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        primary_path = self.outcomes / f"{task_id}.json"
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        lifecycle = json.loads(primary_path.read_text(encoding="utf-8"))
        primary_path.replace(lifecycle_path)

        legacy = self._to_legacy_unbound_outcome(lifecycle)
        primary_path.write_text(
            json.dumps(legacy, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(primary_path, 0o600)

        expected = lifecycle["receipt_sha256"]
        result = attention.record_decision(
            self._parameters(record, outcome_receipt_sha256=expected)
        )

        self.assertEqual(expected, result["outcome_receipt_sha256"])
        classified = attention._classify_record(tasks._row(task_id))
        self.assertEqual("decision_closed", classified["classification"])
        self.assertEqual(expected, classified["outcome_receipt_sha256"])

    def test_authoritative_primary_survives_unrelated_lifecycle_path(self) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        primary_path = self.outcomes / f"{task_id}.json"
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        authoritative = json.loads(primary_path.read_text(encoding="utf-8"))
        unrelated = self._to_legacy_unbound_outcome(authoritative)
        lifecycle_path.write_text(
            json.dumps(unrelated, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(lifecycle_path, 0o600)

        expected = authoritative["receipt_sha256"]
        result = attention.record_decision(
            self._parameters(record, outcome_receipt_sha256=expected)
        )

        self.assertEqual(expected, result["outcome_receipt_sha256"])

    def test_missing_authoritative_lifecycle_does_not_fall_back_to_legacy_primary(self) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        primary_path = self.outcomes / f"{task_id}.json"
        lifecycle = json.loads(primary_path.read_text(encoding="utf-8"))

        legacy = self._to_legacy_unbound_outcome(lifecycle)
        primary_path.write_text(
            json.dumps(legacy, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(primary_path, 0o600)

        with self.assertRaises(FileNotFoundError):
            attention.record_decision(
                self._parameters(
                    record,
                    outcome_receipt_sha256=lifecycle["receipt_sha256"],
                )
            )

    def test_all_unrelated_outcome_paths_raise_file_not_found(self) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        primary_path = self.outcomes / f"{task_id}.json"
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        authoritative = json.loads(primary_path.read_text(encoding="utf-8"))
        unrelated = self._to_legacy_unbound_outcome(authoritative)
        encoded = (
            json.dumps(unrelated, ensure_ascii=False, sort_keys=True, indent=2)
            + "\n"
        )
        primary_path.write_text(encoded, encoding="utf-8")
        lifecycle_path.write_text(encoded, encoding="utf-8")
        os.chmod(primary_path, 0o600)
        os.chmod(lifecycle_path, 0o600)

        with self.assertRaisesRegex(
            FileNotFoundError,
            "No task outcome receipt",
        ):
            attention._read_valid_outcome(
                record,
                expected_receipt_sha256=authoritative["receipt_sha256"],
            )

    def test_corrupt_preferred_lifecycle_fails_closed_before_primary_fallback(
        self,
    ) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        lifecycle_path.write_text("{", encoding="utf-8")
        os.chmod(lifecycle_path, 0o600)

        with self.assertRaisesRegex(
            attention.TaskAttentionIntegrityError,
            "invalid task outcome receipt JSON",
        ):
            attention.record_decision(self._parameters(record))
        self.assertEqual([], list(self.decisions.glob("*.json")))

    def test_unreadable_preferred_lifecycle_fails_closed_before_primary_fallback(
        self,
    ) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        original_read = attention._read_private_json
        attempted_paths: list[Path] = []

        def read_with_denied_lifecycle(path: Path, *, label: str):
            attempted_paths.append(path)
            if path == lifecycle_path:
                raise PermissionError("lifecycle receipt is unreadable")
            return original_read(path, label=label)

        with patch.object(
            attention,
            "_read_private_json",
            side_effect=read_with_denied_lifecycle,
        ):
            with self.assertRaisesRegex(PermissionError, "unreadable"):
                attention.record_decision(self._parameters(record))

        self.assertEqual([lifecycle_path], attempted_paths)
        self.assertEqual([], list(self.decisions.glob("*.json")))

    def test_incomplete_lifecycle_binding_fails_closed(self) -> None:
        record = self._failed_task()
        incomplete = dict(record)
        incomplete["lifecycle_receipt_sha256"] = None

        with self.assertRaisesRegex(
            attention.TaskAttentionConflictError,
            "task lifecycle binding is incomplete",
        ):
            attention._read_valid_outcome(
                incomplete,
                expected_receipt_sha256=None,
            )
        classified = attention._classify_record(incomplete)
        self.assertEqual("invalid_evidence", classified["classification"])
        self.assertEqual(
            "TaskAttentionConflictError",
            classified["evidence_error"],
        )

    def test_lifecycle_binding_drift_before_publication_blocks_decision(self) -> None:
        record = self._failed_task()
        parameters = self._parameters(record)
        outcome = attention._read_valid_outcome(
            record,
            expected_receipt_sha256=parameters["outcome_receipt_sha256"],
        )
        drifted = dict(record)
        drifted["lifecycle_receipt_sha256"] = "a" * 64

        with patch.object(tasks, "_row", side_effect=[record, drifted]), patch.object(
            attention,
            "_read_valid_outcome",
            return_value=outcome,
        ):
            with self.assertRaisesRegex(
                attention.TaskAttentionConflictError,
                "binding changed before decision publication",
            ):
                attention.record_decision(parameters)
        self.assertEqual([], list(self.decisions.glob("*.json")))

    def test_tampered_authoritative_lifecycle_is_not_masked_by_legacy_primary(self) -> None:
        record = self._failed_task()
        task_id = str(record["task_id"])
        primary_path = self.outcomes / f"{task_id}.json"
        lifecycle_path = self.outcomes / f"{task_id}.lifecycle.json"
        lifecycle = json.loads(primary_path.read_text(encoding="utf-8"))

        legacy = self._to_legacy_unbound_outcome(lifecycle)
        primary_path.write_text(
            json.dumps(legacy, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(primary_path, 0o600)

        lifecycle["terminalization"]["recovery_status"] = "recovered_after_revocation"
        lifecycle["receipt_sha256"] = attention._sha256_json(
            {key: value for key, value in lifecycle.items() if key != "receipt_sha256"}
        )
        lifecycle_path.write_text(
            json.dumps(lifecycle, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(lifecycle_path, 0o600)
        tampered_record = dict(record)
        tampered_record["lifecycle_receipt_sha256"] = lifecycle["receipt_sha256"]

        with self.assertRaisesRegex(attention.TaskAttentionIntegrityError, "transition hash"):
            attention._read_valid_outcome(
                tampered_record,
                expected_receipt_sha256=lifecycle["receipt_sha256"],
            )

    def test_lifecycle_transition_tampering_is_rejected_after_outer_rehash(self) -> None:
        record = self._failed_task()
        outcome_path = self.outcomes / f"{record['task_id']}.json"
        payload = json.loads(outcome_path.read_text(encoding="utf-8"))
        self.assertEqual(2, payload["schema_version"])
        payload["terminalization"]["recovery_status"] = "recovered_after_revocation"
        payload["receipt_sha256"] = attention._sha256_json(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        tampered_record = dict(record)
        tampered_record["lifecycle_receipt_sha256"] = payload["receipt_sha256"]
        with self.assertRaisesRegex(
            attention.TaskAttentionIntegrityError,
            "transition hash",
        ):
            attention._validate_outcome_receipt(
                payload,
                record=tampered_record,
                binding=attention._task_binding(tampered_record),
                expected_receipt_sha256=payload["receipt_sha256"],
            )

    def test_unsafe_outcome_mode_owner_symlink_and_oversize_fail_closed(self) -> None:
        scenarios = ("mode", "owner", "symlink", "oversize")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.tearDown()
                self.setUp()
                record = self._failed_task()
                parameters = self._parameters(record)
                outcome_path = self.outcomes / f"{record['task_id']}.json"
                if scenario == "mode":
                    os.chmod(outcome_path, 0o644)
                    context = self.assertRaises(attention.TaskAttentionIntegrityError)
                    with context:
                        attention.record_decision(parameters)
                elif scenario == "owner":
                    with patch.object(attention.os, "getuid", return_value=os.getuid() + 1):
                        with self.assertRaises(attention.TaskAttentionIntegrityError):
                            attention.record_decision(parameters)
                elif scenario == "symlink":
                    target = self.root / "outcome-target.json"
                    target.write_bytes(outcome_path.read_bytes())
                    outcome_path.unlink()
                    outcome_path.symlink_to(target)
                    with self.assertRaises(OSError):
                        attention.record_decision(parameters)
                else:
                    outcome_path.write_bytes(b"{" + b" " * attention.MAX_RECORD_BYTES + b"}")
                    os.chmod(outcome_path, 0o600)
                    with self.assertRaises(attention.TaskAttentionIntegrityError):
                        attention.record_decision(parameters)

    def test_history_reconciliation_uses_no_observation_probe_and_classifies_decisions(self) -> None:
        failed = self._failed_task()
        attention.record_decision(self._parameters(failed))
        unknown = self._start()["task"]
        tasks._set_state(str(unknown["task_id"]), "outcome_unknown", observation={"state": "outcome_unknown"})

        with patch.object(tasks, "_observe", side_effect=AssertionError("probe called")), patch.object(
            tasks, "_dispatch", side_effect=AssertionError("dispatch called")
        ):
            result = attention.reconcile_attention({"limit": 20, "view": "history"})

        by_id = {item["task_id"]: item for item in result["records"]}
        self.assertEqual("history", result["view"])
        self.assertEqual("decision_closed", by_id[failed["task_id"]]["classification"])
        self.assertEqual("outcome_unknown", by_id[unknown["task_id"]]["classification"])
        self.assertEqual(1, result["classification_counts"]["decision_closed"])
        self.assertEqual(1, result["classification_counts"]["outcome_unknown"])

    def test_terminal_closeout_plan_requires_attention_before_failed_task_archive(self) -> None:
        record = self._failed_task()

        plan = attention.terminal_closeout_plan(record)

        self.assertEqual("attention_required", plan["closeout_state"])
        self.assertFalse(plan["archive_ready"])
        self.assertEqual("actionable", plan["attention_classification"])
        self.assertEqual("decide_task_attention", plan["operator_obligation"]["kind"])

    def test_terminal_closeout_plan_accepts_evidence_bound_closed_decision(self) -> None:
        record = self._failed_task()
        attention.record_decision(self._parameters(record, decision="closed"))

        plan = attention.terminal_closeout_plan(tasks._row(str(record["task_id"])))

        self.assertEqual("ready_to_archive", plan["closeout_state"])
        self.assertTrue(plan["archive_ready"])
        self.assertEqual("decision_closed", plan["attention_classification"])
        self.assertIsNone(plan["operator_obligation"])

    def test_terminal_closeout_plan_keeps_deferred_attention_visible(self) -> None:
        record = self._failed_task()
        attention.record_decision(self._parameters(record, decision="deferred"))

        plan = attention.terminal_closeout_plan(tasks._row(str(record["task_id"])))

        self.assertEqual("attention_deferred", plan["closeout_state"])
        self.assertFalse(plan["archive_ready"])
        self.assertEqual("resolve_deferred_attention", plan["operator_obligation"]["kind"])

    def test_terminal_closeout_plan_completed_task_needs_no_attention_decision(self) -> None:
        started = self._start()["task"]
        task_id = str(started["task_id"])
        tasks._set_state(task_id, "completed", observation={"state": "completed"})

        plan = attention.terminal_closeout_plan(tasks._row(task_id))

        self.assertEqual("ready_to_archive", plan["closeout_state"])
        self.assertTrue(plan["archive_ready"])
        self.assertFalse(plan["attention_required"])
        self.assertEqual("not_required", plan["attention_classification"])
        self.assertIsNone(plan["operator_obligation"])

    def test_task_archive_classification_uses_typed_not_applicable_sources(self) -> None:
        record = self._completed_task()
        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            classified = attention._task_archive_classification(
                record,
                expected_lifecycle_receipt_sha256=str(
                    record["lifecycle_receipt_sha256"]
                ),
                archived=False,
            )

        evidence_snapshot = classified["evidence"]
        self.assertEqual(
            {"task", "lease", "process", "receipt"},
            set(evidence_snapshot["observed_sources"]),
        )
        for source in ("workspace", "checkout", "tmux"):
            self.assertEqual(
                "not_applicable",
                evidence_snapshot["source_applicability"][source],
            )
            self.assertNotIn(source, evidence_snapshot["observed_sources"])
            self.assertIn(source, evidence_snapshot["source_sha256s"])
        self.assertEqual(
            "task_archive.v1",
            evidence_snapshot["source_applicability_profile"],
        )
        for source in ("task", "receipt"):
            self.assertEqual(
                "observed",
                evidence_snapshot["source_applicability"][source],
            )
        for source in ("lease", "process"):
            self.assertEqual(
                "explicit_absence",
                evidence_snapshot["source_applicability"][source],
            )

    @staticmethod
    def _cleanup_inventory(record: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_inventory",
            "task_id": record["task_id"],
            "attempt": record["attempt"],
            "directory": str(tasks._task_output_paths(record)["directory"]),
            "streams": {
                "stdout": {
                    "sha256": "1" * 64,
                    "bytes": 12,
                    "mode": 0o600,
                    "nlink": 1,
                },
                "stderr": {
                    "sha256": "2" * 64,
                    "bytes": 3,
                    "mode": 0o600,
                    "nlink": 1,
                },
            },
        }

    @staticmethod
    def _cleanup_archive_binding(record_sha256: str) -> dict[str, str]:
        return {
            "segment_id": "segment-" + "a" * 24,
            "segment_identity_sha256": "b" * 64,
            "manifest_sha256": "c" * 64,
            "segment_sha256": "d" * 64,
            "plan_sha256": "e" * 64,
            "record_sha256": record_sha256,
        }

    @staticmethod
    def _cleanup_projection(record: dict[str, object], record_sha256: str) -> dict[str, str]:
        return {
            "task_id": str(record["task_id"]),
            "record_sha256": record_sha256,
            "segment_id": "segment-" + "a" * 24,
            "switch_sha256": "f" * 64,
            "projection_sha256": "0" * 64,
        }

    @staticmethod
    def _cleanup_ready_record(record: dict[str, object]) -> dict[str, object]:
        return {**record, "terminalized_at_unix": 0, "updated_at_unix": 0}

    def test_task_output_cleanup_writes_intent_completion_and_replays(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        inventory = self._cleanup_inventory(record)
        deleted = {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_delete_result",
            "task_id": record["task_id"],
            "attempt": record["attempt"],
            "directory": inventory["directory"],
            "token": "unused",
            "resumed_from_staging": False,
            "removed": ["stdout.log", "stderr.log"],
            "streams": inventory["streams"],
            "post_state": "absent",
        }

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if mode == "inspect":
                return {"status": "present", "inventory": self._cleanup_inventory(current)}
            result = dict(deleted)
            result["token"] = token
            return {"status": "deleted", "delete_result": result}

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ) as runner, patch.object(
            attention, "_existing_task_projection_binding", return_value=projection
        ):
            first = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )
            second = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(first["status"], "deleted")
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(2, runner.call_count)
        intent_path, completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        self.assertTrue(intent_path.is_file())
        self.assertTrue(completion_path.is_file())
        self.assertEqual(
            first["intent_receipt_sha256"], second["intent_receipt_sha256"]
        )
        self.assertEqual(
            first["completion_receipt_sha256"],
            second["completion_receipt_sha256"],
        )

    def test_task_output_cleanup_recovers_after_intent_before_completion(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        inventory = self._cleanup_inventory(record)
        calls = 0

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if mode == "inspect":
                return {"status": "present", "inventory": self._cleanup_inventory(current)}
            if calls == 2:
                raise RuntimeError("simulated interruption after durable intent")
            result = {
                "schema_version": 1,
                "kind": "grabowski_task_output_cleanup_delete_result",
                "task_id": current["task_id"],
                "attempt": current["attempt"],
                "directory": self._cleanup_inventory(current)["directory"],
                "token": token,
                "resumed_from_staging": True,
                "removed": ["stderr.log"],
                "streams": self._cleanup_inventory(current)["streams"],
                "post_state": "absent",
            }
            return {"status": "deleted", "delete_result": result}

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ), patch.object(
            attention, "_existing_task_projection_binding", return_value=projection
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                attention._task_output_cleanup_after_archive(
                    record,
                    archive_binding=archive_binding,
                    projection=projection,
                    retention_boundary_unix=123,
                )
            recovered = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(recovered["status"], "deleted")
        self.assertFalse(recovered["idempotent_replay"])
        self.assertEqual(calls, 3)
        intent_path, completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        self.assertTrue(intent_path.is_file())
        self.assertTrue(completion_path.is_file())

    def test_task_output_cleanup_replay_uses_persisted_higher_retention_boundary(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        persisted_boundary_unix = attention.TASK_OUTPUT_MINIMUM_RETENTION_SECONDS + 456
        calls = 0

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if mode == "inspect":
                return {
                    "status": "present",
                    "inventory": self._cleanup_inventory(current),
                }
            if calls == 2:
                raise RuntimeError("simulated interruption after durable intent")
            result = {
                "schema_version": 1,
                "kind": "grabowski_task_output_cleanup_delete_result",
                "task_id": current["task_id"],
                "attempt": current["attempt"],
                "directory": self._cleanup_inventory(current)["directory"],
                "token": token,
                "resumed_from_staging": True,
                "removed": ["stdout.log", "stderr.log"],
                "streams": self._cleanup_inventory(current)["streams"],
                "post_state": "absent",
            }
            return {"status": "deleted", "delete_result": result}

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ), patch.object(
            attention, "_existing_task_projection_binding", return_value=projection
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                attention._task_output_cleanup_after_archive(
                    record,
                    archive_binding=archive_binding,
                    projection=projection,
                    retention_boundary_unix=persisted_boundary_unix,
                )
            recovered = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(recovered["status"], "deleted")
        self.assertEqual(recovered["mutation_state"], "performed")
        intent_path, _completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        intent, _file_sha256 = attention._task_output_cleanup_read_receipt(
            intent_path, kind=attention.TASK_OUTPUT_CLEANUP_INTENT_KIND
        )
        self.assertEqual(
            intent["material"]["retention_boundary_unix"],
            persisted_boundary_unix,
        )

    def test_task_output_cleanup_intent_survives_global_projection_digest_change(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        first_projection = self._cleanup_projection(record, record_sha256)
        second_projection = dict(first_projection)
        second_projection["projection_sha256"] = "9" * 64
        calls = 0

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if mode == "inspect":
                return {
                    "status": "present",
                    "inventory": self._cleanup_inventory(current),
                }
            if calls == 2:
                raise RuntimeError("simulated interruption after intent")
            result = {
                "schema_version": 1,
                "kind": "grabowski_task_output_cleanup_delete_result",
                "task_id": current["task_id"],
                "attempt": current["attempt"],
                "directory": self._cleanup_inventory(current)["directory"],
                "token": token,
                "resumed_from_staging": False,
                "removed": ["stdout.log", "stderr.log"],
                "streams": self._cleanup_inventory(current)["streams"],
                "post_state": "absent",
            }
            return {"status": "deleted", "delete_result": result}

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ), patch.object(
            attention,
            "_existing_task_projection_binding",
            return_value=second_projection,
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                attention._task_output_cleanup_after_archive(
                    record,
                    archive_binding=archive_binding,
                    projection=first_projection,
                    retention_boundary_unix=123,
                )
            recovered = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=second_projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(recovered["status"], "deleted")
        self.assertEqual(recovered["mutation_state"], "performed")
        intent_path, _completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        intent, _file_sha = attention._task_output_cleanup_read_receipt(
            intent_path, kind=attention.TASK_OUTPUT_CLEANUP_INTENT_KIND
        )
        stable_projection = intent["material"]["projection"]
        self.assertEqual(
            set(stable_projection),
            {"task_id", "record_sha256", "segment_id", "switch_sha256"},
        )
        self.assertNotIn("projection_sha256", stable_projection)

    def test_task_output_cleanup_defers_before_fixed_retention_without_effect(self) -> None:
        record = self._completed_task()
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        boundary = int(record["terminalized_at_unix"]) + (24 * 60 * 60)
        with patch.object(tasks, "_task_output_cleanup_run") as cleanup_run, patch.object(
            tasks.resources, "acquire_resources"
        ) as acquire:
            result = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=boundary,
            )
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["eligible_at_unix"], boundary)
        self.assertEqual(
            result["minimum_retention_seconds"],
            attention.TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
        )
        cleanup_run.assert_not_called()
        acquire.assert_not_called()
        intent_path, completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        self.assertFalse(intent_path.exists())
        self.assertFalse(completion_path.exists())

    def test_task_output_cleanup_canonical_boundary_enforces_fixed_minimum(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)

        boundary = attention._canonical_task_output_cleanup_retention_boundary(
            record,
            archive_binding=archive_binding,
            projection=projection,
            proposed_boundary_unix=123,
        )

        self.assertEqual(
            boundary,
            attention.TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
        )

    def test_task_output_cleanup_rejects_intent_below_fixed_minimum(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        binding = attention._task_binding(record)
        projection_binding = attention._task_output_cleanup_projection_binding(
            projection
        )
        material = {
            "schema_version": 1,
            "task_binding": binding,
            "lifecycle_receipt_sha256": record["lifecycle_receipt_sha256"],
            "retention_boundary_unix": 123,
            "archive": archive_binding,
            "projection": projection_binding,
            "inventory": self._cleanup_inventory(record),
        }
        intent_payload = {
            "schema_version": 1,
            "kind": attention.TASK_OUTPUT_CLEANUP_INTENT_KIND,
            "material": material,
            "material_sha256": attention._sha256_json(material),
            "created_at_unix": 123,
        }
        intent_path, _completion_path = attention._task_output_cleanup_paths(binding)
        attention._task_output_cleanup_publish(intent_path, intent_payload)

        with self.assertRaisesRegex(
            attention.TaskAttentionIntegrityError,
            "fixed minimum retention",
        ):
            attention._canonical_task_output_cleanup_retention_boundary(
                record,
                archive_binding=archive_binding,
                projection=projection,
                proposed_boundary_unix=attention.TASK_OUTPUT_MINIMUM_RETENTION_SECONDS,
            )

    def test_task_output_cleanup_empty_attempt_selection_is_bounded(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)

        with patch.object(
            attention,
            "_load_task_output_cleanup_attempt_cursor",
            return_value=int(record["attempt"]),
        ), patch.object(
            attention,
            "_save_task_output_cleanup_attempt_cursor",
        ) as save_cursor:
            result = attention._task_output_cleanup_all_attempts_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(result["status"], "not_present")
        self.assertEqual(result["attempts_scanned"], 0)
        self.assertEqual(result["retention_boundary_unix"], 123)
        self.assertEqual(result["retention_boundaries_unix"], [])
        save_cursor.assert_called_once()

    def test_task_output_cleanup_blocks_parallel_owner(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        binding = attention._task_binding(record)
        resource_key = (
            "component:grabowski-task-output-cleanup:"
            + str(binding["task_id"])
            + ":a"
            + str(binding["attempt"])
        )
        foreign_owner = "operator:test-parallel-output-cleanup"
        tasks.resources.acquire_resources(
            foreign_owner,
            [resource_key],
            purpose="simulate concurrent task output cleanup",
            ttl_seconds=60,
        )
        try:
            with patch.object(tasks, "_task_output_cleanup_run") as cleanup_run:
                with self.assertRaises(attention.TaskAttentionConflictError):
                    attention._task_output_cleanup_after_archive(
                        record,
                        archive_binding=archive_binding,
                        projection=projection,
                        retention_boundary_unix=123,
                    )
            cleanup_run.assert_not_called()
        finally:
            tasks.resources.release_resources(foreign_owner, [resource_key])

    def test_task_output_cleanup_uses_distinct_owner_per_invocation(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        calls = 0

        def cleanup_unlocked(
            current: dict[str, object],
            *,
            archive_binding: dict[str, object],
            projection: dict[str, object],
            retention_boundary_unix: int,
            archived_record: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls != 1:
                self.fail("parallel cleanup reached the unlocked effect body")
            with self.assertRaises(attention.TaskAttentionConflictError):
                attention._task_output_cleanup_after_archive(
                    current,
                    archive_binding=archive_binding,
                    projection=projection,
                    retention_boundary_unix=retention_boundary_unix,
                )
            return {"status": "deleted", "task_binding": attention._task_binding(current)}

        invocation_ids = [
            types.SimpleNamespace(hex="1" * 32),
            types.SimpleNamespace(hex="2" * 32),
        ]
        with patch.object(
            attention.uuid, "uuid4", side_effect=invocation_ids
        ) as uuid4, patch.object(
            attention,
            "_task_output_cleanup_after_archive_unlocked",
            side_effect=cleanup_unlocked,
        ):
            result = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(result["status"], "deleted")
        self.assertEqual(calls, 1)
        self.assertEqual(uuid4.call_count, 2)

    def test_task_output_cleanup_reconciles_absent_after_effect_interruption(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        calls = 0

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if mode == "inspect":
                return {"status": "present", "inventory": self._cleanup_inventory(current)}
            if calls == 2:
                raise RuntimeError("simulated crash after absent post-state")
            return {
                "status": "missing",
                "mode": "delete",
                "observer": "task-output-cleanup-v1",
            }

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ), patch.object(
            attention, "_existing_task_projection_binding", return_value=projection
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                attention._task_output_cleanup_after_archive(
                    record,
                    archive_binding=archive_binding,
                    projection=projection,
                    retention_boundary_unix=123,
                )
            recovered = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )
            replay = attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(calls, 3)
        self.assertEqual(recovered["status"], "deleted")
        self.assertEqual(recovered["mutation_state"], "reconciled_absent")
        self.assertFalse(recovered["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["mutation_state"], "reconciled_absent")
        self.assertEqual(
            recovered["completion_receipt_sha256"],
            replay["completion_receipt_sha256"],
        )

    def test_task_output_cleanup_rejects_completion_without_intent(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        intent_path, completion_path = attention._task_output_cleanup_paths(
            attention._task_binding(record)
        )
        completion_payload = {
            "schema_version": 1,
            "kind": attention.TASK_OUTPUT_CLEANUP_COMPLETION_KIND,
            "task_binding": attention._task_binding(record),
            "intent_receipt_sha256": "1" * 64,
            "intent_file_sha256": "2" * 64,
            "material_sha256": "3" * 64,
            "delete_result_sha256": "4" * 64,
            "post_state": "absent",
            "completed_at_unix": 123,
        }
        attention._task_output_cleanup_publish(
            completion_path, completion_payload
        )
        self.assertFalse(intent_path.exists())

        with self.assertRaisesRegex(
            attention.TaskAttentionIntegrityError, "without its intent"
        ):
            attention._task_output_cleanup_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

    def test_task_output_cleanup_covers_every_resumed_attempt(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        task_id = str(record["task_id"])
        final_attempt = 3
        final_unit = tasks._task_unit(task_id, final_attempt)
        record = {
            **record,
            "attempt": final_attempt,
            "unit": final_unit,
            "authoritative_unit": final_unit,
        }
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)
        inspected_attempts: list[int] = []

        def cleanup_run(
            current: dict[str, object],
            *,
            mode: str,
            token: str,
            inventory: dict[str, object] | None = None,
        ) -> dict[str, object]:
            self.assertEqual(mode, "inspect")
            inspected_attempts.append(int(current["attempt"]))
            return {
                "status": "missing",
                "mode": mode,
                "observer": "task-output-cleanup-v1",
            }

        with patch.object(
            tasks, "_task_output_cleanup_run", side_effect=cleanup_run
        ), patch.object(
            attention, "_assert_no_live_task_resource_leases",
            return_value={"active_lease": False},
        ) as leases, patch.object(
            attention, "_assert_no_live_task_process",
            return_value={"active_process": False},
        ) as processes:
            result = attention._task_output_cleanup_all_attempts_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=123,
            )

        self.assertEqual(inspected_attempts, [1, 2, 3])
        self.assertEqual(result["status"], "not_present")
        self.assertEqual(result["attempt_cursor_before"], 0)
        self.assertEqual(result["attempt_cursor_after"], 0)
        self.assertTrue(result["attempt_cycle_completed"])
        self.assertEqual(result["attempt_count"], 3)
        self.assertEqual(result["attempts_scanned"], 3)
        self.assertEqual(result["not_present_attempts"], [1, 2, 3])
        self.assertEqual(leases.call_count, 3)
        self.assertEqual(
            [int(call.args[0]["attempt"]) for call in processes.call_args_list],
            [1, 2, 3],
        )

    def test_task_output_cleanup_refreshes_live_guard_time_per_attempt(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        task_id = str(record["task_id"])
        final_attempt = 2
        final_unit = tasks._task_unit(task_id, final_attempt)
        record = {
            **record,
            "attempt": final_attempt,
            "unit": final_unit,
            "authoritative_unit": final_unit,
        }
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)

        def cleanup_attempt(
            current: dict[str, object], **_kwargs: object
        ) -> dict[str, object]:
            return {
                "status": "not_present",
                "task_binding": attention._task_binding(current),
            }

        with patch.object(
            attention,
            "_task_output_cleanup_now_unix",
            side_effect=[101, 202],
        ), patch.object(
            attention,
            "_canonical_task_output_cleanup_retention_boundary",
            return_value=100,
        ), patch.object(
            attention, "_assert_no_live_task_resource_leases",
            return_value={"active_lease": False},
        ) as leases, patch.object(
            attention, "_assert_no_live_task_process",
            return_value={"active_process": False},
        ), patch.object(
            attention, "_task_output_cleanup_after_archive",
            side_effect=cleanup_attempt,
        ) as cleanup:
            result = attention._task_output_cleanup_all_attempts_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=100,
            )

        self.assertEqual(result["status"], "not_present")
        self.assertEqual(
            [call.kwargs["now_unix"] for call in leases.call_args_list],
            [101, 202],
        )
        self.assertEqual(
            [int(call.args[0]["attempt"]) for call in cleanup.call_args_list],
            [1, 2],
        )

    def test_task_output_cleanup_canonicalizes_retention_per_attempt(self) -> None:
        record = self._cleanup_ready_record(self._completed_task())
        task_id = str(record["task_id"])
        final_attempt = 2
        final_unit = tasks._task_unit(task_id, final_attempt)
        record = {
            **record,
            "attempt": final_attempt,
            "unit": final_unit,
            "authoritative_unit": final_unit,
        }
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection = self._cleanup_projection(record, record_sha256)

        def cleanup_attempt(
            current: dict[str, object], **kwargs: object
        ) -> dict[str, object]:
            return {
                "status": "not_present",
                "task_binding": attention._task_binding(current),
                "retention_boundary_unix": kwargs["retention_boundary_unix"],
            }

        with patch.object(
            attention,
            "_canonical_task_output_cleanup_retention_boundary",
            side_effect=[24, 48],
        ) as canonical, patch.object(
            attention, "_task_output_cleanup_now_unix", side_effect=[100, 100],
        ), patch.object(
            attention, "_assert_no_live_task_resource_leases",
            return_value={"active_lease": False},
        ), patch.object(
            attention, "_assert_no_live_task_process",
            return_value={"active_process": False},
        ), patch.object(
            attention, "_task_output_cleanup_after_archive",
            side_effect=cleanup_attempt,
        ) as cleanup:
            result = attention._task_output_cleanup_all_attempts_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection,
                retention_boundary_unix=48,
            )

        self.assertEqual([24, 48], [
            call.kwargs["retention_boundary_unix"]
            for call in cleanup.call_args_list
        ])
        self.assertEqual([1, 2], [
            int(call.args[0]["attempt"]) for call in canonical.call_args_list
        ])
        self.assertEqual("not_present", result["status"])
        self.assertEqual([24, 48], result["retention_boundaries_unix"])
        self.assertEqual(24, result["retention_boundary_unix"])

    def _automatic_cleanup_fixture(
        self, count: int, *, projection_sha256: str = "9" * 64
    ) -> tuple[list[dict[str, object]], dict[str, object], object]:
        records = [self._completed_task() for _ in range(count)]
        hashes: dict[str, str] = {}
        bindings: dict[str, dict[str, str]] = {}
        for record in records:
            _archive, record_sha256, _source = (
                attention._task_archive_source_binding(record)
            )
            task_id = str(record["task_id"])
            hashes[task_id] = record_sha256
            bindings[task_id] = {
                "record_sha256": record_sha256,
                "segment_id": "segment-" + "a" * 24,
                "switch_sha256": "b" * 64,
            }
        manifest = {
            "segment_id": "segment-" + "a" * 24,
            "segment_identity_sha256": "c" * 64,
            "manifest_sha256": "d" * 64,
            "segment_sha256": "e" * 64,
            "plan_sha256": "f" * 64,
            "record_sha256s": [hashes[key] for key in sorted(hashes)],
        }
        projection: dict[str, object] = {
            "schema_version": 1,
            "projection_sha256": projection_sha256,
            "archived_task_bindings": bindings,
            "switches": [],
        }
        return records, projection, manifest

    def test_archived_output_reconcile_component_lease_blocks_parallel_run(self) -> None:
        foreign_owner = "operator:test-parallel-output-reconcile"
        tasks.resources.acquire_resources(
            foreign_owner,
            [attention.TASK_OUTPUT_CLEANUP_RECONCILE_RESOURCE],
            purpose="simulate parallel archived output reconcile",
            ttl_seconds=60,
        )
        try:
            with patch.object(tasks, "_task_current_projection") as projection:
                with self.assertRaises(attention.TaskAttentionConflictError):
                    attention.reconcile_archived_task_outputs(limit=1)
            projection.assert_not_called()
        finally:
            tasks.resources.release_resources(
                foreign_owner,
                [attention.TASK_OUTPUT_CLEANUP_RECONCILE_RESOURCE],
            )

    def test_archived_output_reconcile_renews_component_lease_per_task(self) -> None:
        records, projection, manifest = self._automatic_cleanup_fixture(2)

        with patch.object(
            tasks, "_task_current_projection", return_value=projection
        ), patch.object(
            lifecycle_archive,
            "verify_task_archive_segment",
            return_value={"manifest": manifest},
        ), patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
            return_value={"status": "not_present"},
        ), patch.object(
            attention,
            "_renew_task_output_cleanup_reconcile_lease",
            return_value={"status": "renewed"},
        ) as renew:
            result = attention.reconcile_archived_task_outputs(limit=2)

        self.assertEqual(result["scanned"], 2)
        self.assertEqual(renew.call_count, 2)
        owners = {str(call.args[0]) for call in renew.call_args_list}
        self.assertEqual(len(owners), 1)

    def test_archived_output_reconcile_stops_after_component_lease_loss(self) -> None:
        _records, projection, manifest = self._automatic_cleanup_fixture(2)

        with patch.object(
            tasks, "_task_current_projection", return_value=projection
        ), patch.object(
            lifecycle_archive,
            "verify_task_archive_segment",
            return_value={"manifest": manifest},
        ), patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
            return_value={"status": "not_present"},
        ) as cleanup, patch.object(
            attention,
            "_renew_task_output_cleanup_reconcile_lease",
            side_effect=[
                {"status": "renewed"},
                attention.TaskAttentionConflictError("lost component lease"),
            ],
        ):
            with self.assertRaisesRegex(
                attention.TaskAttentionConflictError, "lost component lease"
            ):
                attention.reconcile_archived_task_outputs(limit=2)

        self.assertEqual(cleanup.call_count, 1)

    def test_archived_output_reconcile_canonicalizes_boundary_before_live_checks(self) -> None:
        records, projection, manifest = self._automatic_cleanup_fixture(1)
        record = records[0]
        _archive, record_sha256, _store = attention._task_archive_source_binding(record)
        archive_binding = self._cleanup_archive_binding(record_sha256)
        projection_binding = {
            "task_id": str(record["task_id"]),
            **projection["archived_task_bindings"][str(record["task_id"])],
            "projection_sha256": str(projection["projection_sha256"]),
        }
        future_boundary_unix = int(attention.time.time()) + 3600

        with patch.object(
            attention,
            "_canonical_task_output_cleanup_retention_boundary",
            return_value=future_boundary_unix,
        ) as canonicalize, patch.object(
            attention, "_assert_no_live_task_resource_leases"
        ) as leases, patch.object(
            attention, "_assert_no_live_task_process"
        ) as process, patch.object(
            attention, "_task_output_cleanup_after_archive"
        ) as cleanup:
            result = attention._task_output_cleanup_all_attempts_after_archive(
                record,
                archive_binding=archive_binding,
                projection=projection_binding,
                retention_boundary_unix=123,
            )

        canonicalize.assert_called_once()
        leases.assert_not_called()
        process.assert_not_called()
        cleanup.assert_not_called()
        self.assertEqual(result["status"], "deferred")
        self.assertEqual(result["retention_boundary_unix"], future_boundary_unix)

    def test_archived_output_reconcile_cursor_is_fair_and_bounded(self) -> None:
        records, projection, manifest = self._automatic_cleanup_fixture(3)
        ordered = sorted(str(record["task_id"]) for record in records)
        observed: list[str] = []

        def cleanup(record: dict[str, object], **_kwargs: object) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {"status": "not_present"}

        with patch.object(
            tasks, "_task_current_projection", return_value=projection
        ), patch.object(
            lifecycle_archive,
            "verify_task_archive_segment",
            return_value={"manifest": manifest},
        ), patch.object(
            attention, "_task_output_cleanup_all_attempts_after_archive", side_effect=cleanup
        ):
            first = attention.reconcile_archived_task_outputs(limit=2)
            second = attention.reconcile_archived_task_outputs(limit=2)

        self.assertEqual(observed, ordered)
        self.assertEqual(first["scanned"], 2)
        self.assertFalse(first["cycle_completed"])
        self.assertEqual(first["cursor_after"], ordered[1])
        self.assertEqual(second["scanned"], 1)
        self.assertTrue(second["cycle_completed"])
        self.assertIsNone(second["cursor_after"])
        self.assertEqual(first["counts"]["not_present"], 2)
        self.assertEqual(second["counts"]["not_present"], 1)

    def test_archived_output_reconcile_additive_projection_drift_preserves_cursor(self) -> None:
        records, full_projection, manifest = self._automatic_cleanup_fixture(4)
        ordered = sorted(str(record["task_id"]) for record in records)
        first_projection = dict(full_projection)
        first_projection["archived_task_bindings"] = {
            task_id: full_projection["archived_task_bindings"][task_id]
            for task_id in ordered[:3]
        }
        attention._save_task_output_cleanup_cursor(
            projection_sha256=str(first_projection["projection_sha256"]),
            cursor=ordered[1],
        )
        second_projection = dict(full_projection)
        second_projection["projection_sha256"] = "8" * 64
        observed: list[str] = []

        def cleanup(record: dict[str, object], **_kwargs: object) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {"status": "not_present"}

        with patch.object(
            tasks, "_task_current_projection", return_value=second_projection
        ), patch.object(
            lifecycle_archive,
            "verify_task_archive_segment",
            return_value={"manifest": manifest},
        ), patch.object(
            attention, "_task_output_cleanup_all_attempts_after_archive", side_effect=cleanup
        ):
            result = attention.reconcile_archived_task_outputs(limit=1)

        self.assertEqual(result["cursor_before"], ordered[1])
        self.assertEqual(observed, [ordered[2]])
        self.assertEqual(result["cursor_after"], ordered[2])
        self.assertFalse(result["cycle_completed"])

    def test_archived_output_reconcile_isolates_errors_and_advances(self) -> None:
        records, projection, manifest = self._automatic_cleanup_fixture(2)
        ordered = sorted(str(record["task_id"]) for record in records)
        calls = 0

        def cleanup(record: dict[str, object], **_kwargs: object) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("poison cleanup")
            return {"status": "not_present"}

        with patch.object(
            tasks, "_task_current_projection", return_value=projection
        ), patch.object(
            lifecycle_archive,
            "verify_task_archive_segment",
            return_value={"manifest": manifest},
        ), patch.object(
            attention, "_task_output_cleanup_all_attempts_after_archive", side_effect=cleanup
        ):
            result = attention.reconcile_archived_task_outputs(limit=2)

        self.assertEqual([item["task_id"] for item in result["results"]], ordered)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["counts"]["errors"], 1)
        self.assertEqual(result["counts"]["not_present"], 1)
        self.assertTrue(result["cycle_completed"])
        self.assertIsNone(result["cursor_after"])

    def test_closeout_archive_completed_task_writes_segment_and_projection_idempotently(self) -> None:
        record = self._completed_task()
        parameters = self._archive_parameters(record)

        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            first = attention.execute_closeout_archive(parameters)
            second = attention.execute_closeout_archive(parameters)

        self.assertFalse(first["already_archived"])
        self.assertEqual("released", first["resource_release"]["status"])
        self.assertEqual(3, len(first["resource_release"]["released"]))
        self.assertRegex(first["archive_effect_receipt_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(first["projection"]["projection_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(second["already_archived"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual("not_required", second["resource_release"]["status"])
        self.assertEqual(
            first["projection"]["projection_sha256"],
            second["projection"]["projection_sha256"],
        )

    def test_closeout_archive_releases_archive_resources_before_output_cleanup(self) -> None:
        import grabowski_lifecycle_archive as lifecycle
        import grabowski_lifecycle_projection as lifecycle_projection

        record = self._completed_task()
        parameters = self._archive_parameters(record)
        resource_keys = sorted(
            {
                lifecycle._task_archive_effect_resource_key(self.archive_root),
                lifecycle._task_archive_effect_resource_key(self.archive_effect_root),
                lifecycle_projection._projection_resource_key(self.projection_root),
            }
        )
        original_cleanup = attention._task_output_cleanup_all_attempts_after_archive
        observed: list[object] = []

        def cleanup(*args: object, **kwargs: object) -> dict[str, object]:
            observed.extend(
                tasks.resources.inspect_resource(resource_key)
                for resource_key in resource_keys
            )
            return original_cleanup(*args, **kwargs)

        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ), patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
            side_effect=cleanup,
        ):
            result = attention.execute_closeout_archive(parameters)

        self.assertEqual("released", result["resource_release"]["status"])
        self.assertEqual([None, None, None], observed)

    def test_closeout_archive_blocks_output_cleanup_when_archive_release_fails(self) -> None:
        record = self._completed_task()
        parameters = self._archive_parameters(record)

        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ), patch.object(
            attention,
            "_release_owned_archive_resources",
            return_value={
                "status": "release_failed",
                "released": [],
                "foreign_preserved": [],
                "error_type": "OSError",
            },
        ), patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
        ) as cleanup:
            with self.assertRaisesRegex(
                attention.TaskAttentionConflictError,
                "could not be released before output cleanup",
            ):
                attention.execute_closeout_archive(parameters)

        cleanup.assert_not_called()

    def test_closeout_archive_namespaces_same_caller_execution_id_per_task(self) -> None:
        first_record = self._completed_task()
        second_record = self._completed_task()
        shared_execution_id = "shared-caller-retry-key"

        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            first = attention.execute_closeout_archive(
                self._archive_parameters(
                    first_record, execution_id=shared_execution_id
                )
            )
            second = attention.execute_closeout_archive(
                self._archive_parameters(
                    second_record, execution_id=shared_execution_id
                )
            )

        self.assertEqual(
            first["caller_execution_id_sha256"],
            second["caller_execution_id_sha256"],
        )
        self.assertNotEqual(
            first["execution_id_sha256"],
            second["execution_id_sha256"],
        )
        self.assertNotEqual(
            first["archive_effect_receipt_sha256"],
            second["archive_effect_receipt_sha256"],
        )

    def test_closeout_archive_replay_releases_leftover_owned_effect_leases(self) -> None:
        import grabowski_lifecycle_archive as lifecycle
        import grabowski_lifecycle_projection as lifecycle_projection

        record = self._completed_task()
        parameters = self._archive_parameters(record)
        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            first = attention.execute_closeout_archive(parameters)

        owner = (
            "operator:task-closeout-archive:"
            + first["execution_id_sha256"][:24]
        )
        resource_keys = sorted(
            {
                lifecycle._task_archive_effect_resource_key(self.archive_root),
                lifecycle._task_archive_effect_resource_key(self.archive_effect_root),
                lifecycle_projection._projection_resource_key(self.projection_root),
            }
        )
        tasks.resources.acquire_resources(
            owner,
            resource_keys,
            purpose="simulate ambiguous release after successful projection",
            ttl_seconds=60,
        )

        replay = attention.execute_closeout_archive(parameters)

        self.assertTrue(replay["already_archived"])
        self.assertEqual("released", replay["resource_release"]["status"])
        self.assertEqual(resource_keys, replay["resource_release"]["released"])
        for resource_key in resource_keys:
            self.assertIsNone(tasks.resources.inspect_resource(resource_key))

    def test_closeout_archive_replay_releases_archive_resources_before_output_cleanup(self) -> None:
        import grabowski_lifecycle_archive as lifecycle
        import grabowski_lifecycle_projection as lifecycle_projection

        record = self._completed_task()
        parameters = self._archive_parameters(record)
        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            first = attention.execute_closeout_archive(parameters)

        owner = (
            "operator:task-closeout-archive:"
            + first["execution_id_sha256"][:24]
        )
        resource_keys = sorted(
            {
                lifecycle._task_archive_effect_resource_key(self.archive_root),
                lifecycle._task_archive_effect_resource_key(self.archive_effect_root),
                lifecycle_projection._projection_resource_key(self.projection_root),
            }
        )
        tasks.resources.acquire_resources(
            owner,
            resource_keys,
            purpose="simulate ambiguous release after successful projection",
            ttl_seconds=60,
        )
        original_cleanup = attention._task_output_cleanup_all_attempts_after_archive
        observed: list[object] = []

        def cleanup(*args: object, **kwargs: object) -> dict[str, object]:
            observed.extend(
                tasks.resources.inspect_resource(resource_key)
                for resource_key in resource_keys
            )
            return original_cleanup(*args, **kwargs)

        with patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
            side_effect=cleanup,
        ):
            replay = attention.execute_closeout_archive(parameters)

        self.assertTrue(replay["already_archived"])
        self.assertEqual("released", replay["resource_release"]["status"])
        self.assertEqual([None, None, None], observed)

    def test_closeout_archive_replay_blocks_cleanup_when_archive_release_fails(self) -> None:
        record = self._completed_task()
        parameters = self._archive_parameters(record)
        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            attention.execute_closeout_archive(parameters)

        with patch.object(
            attention,
            "_release_owned_archive_resources",
            return_value={
                "status": "release_failed",
                "released": [],
                "foreign_preserved": [],
                "error_type": "OSError",
            },
        ), patch.object(
            attention,
            "_task_output_cleanup_all_attempts_after_archive",
        ) as cleanup:
            with self.assertRaisesRegex(
                attention.TaskAttentionConflictError,
                "could not be released before output cleanup",
            ):
                attention.execute_closeout_archive(parameters)

        cleanup.assert_not_called()

    def test_closeout_archive_failed_task_requires_attention_decision(self) -> None:
        record = self._failed_task()

        with self.assertRaisesRegex(
            attention.TaskAttentionConflictError,
            "not ready for archival",
        ):
            attention.execute_closeout_archive(self._archive_parameters(record))

    def test_closeout_archive_failed_task_accepts_closed_decision(self) -> None:
        record = self._failed_task()
        attention.record_decision(self._parameters(record, decision="closed"))

        with patch.object(
            tasks,
            "_observe",
            return_value=self._inactive_process_observation(),
        ):
            result = attention.execute_closeout_archive(
                self._archive_parameters(record)
            )

        self.assertFalse(result["already_archived"])
        self.assertEqual("decision_closed", result["closeout"]["attention_classification"])
        self.assertEqual("released", result["resource_release"]["status"])

    def test_closeout_archive_blocks_until_minimum_retention_is_satisfied(self) -> None:
        record = self._completed_task()

        with self.assertRaisesRegex(
            attention.TaskAttentionConflictError,
            "minimum retention",
        ):
            attention.execute_closeout_archive(
                self._archive_parameters(record, minimum_age_seconds=10**9)
            )

        self.assertFalse(self.archive_root.exists())
        self.assertFalse(self.projection_root.exists())

    def test_closeout_archive_blocks_live_authoritative_unit(self) -> None:
        record = self._completed_task()
        live = {
            "properties": {
                "LoadState": "loaded",
                "ActiveState": "active",
                "SubState": "running",
            },
            "probe": {"returncode": 0, "outcome_unknown": False},
        }

        with patch.object(tasks, "_observe", return_value=live), self.assertRaisesRegex(
            attention.TaskAttentionConflictError,
            "still live",
        ):
            attention.execute_closeout_archive(self._archive_parameters(record))

    def test_closeout_archive_blocks_reacquired_task_resource_lease(self) -> None:
        resource_key = "component:test-task-closeout-archive"
        record = self._completed_task(resource_keys=[resource_key])
        foreign_owner = "operator:test-foreign-retention"
        tasks.resources.acquire_resources(
            foreign_owner,
            [resource_key],
            purpose="test active lease after terminalization",
            ttl_seconds=60,
        )
        try:
            with patch.object(
                tasks,
                "_observe",
                return_value=self._inactive_process_observation(),
            ), self.assertRaisesRegex(
                attention.TaskAttentionConflictError,
                "active task resource leases",
            ):
                attention.execute_closeout_archive(self._archive_parameters(record))
        finally:
            tasks.resources.release_resources(foreign_owner, [resource_key])

    def test_current_reconciliation_excludes_closed_and_superseded_but_keeps_deferred(self) -> None:
        closed = self._failed_task()
        attention.record_decision(self._parameters(closed, decision="closed"))
        superseded = self._failed_task()
        attention.record_decision(self._parameters(superseded, decision="superseded"))
        deferred = self._failed_task()
        attention.record_decision(self._parameters(deferred, decision="deferred"))
        unknown = self._start()["task"]
        tasks._set_state(str(unknown["task_id"]), "outcome_unknown", observation={"state": "outcome_unknown"})

        with patch.object(tasks, "_observe", side_effect=AssertionError("probe called")), patch.object(
            tasks, "_dispatch", side_effect=AssertionError("dispatch called")
        ):
            result = attention.reconcile_attention({"limit": 20})

        by_id = {item["task_id"]: item for item in result["records"]}
        self.assertEqual("current", result["view"])
        self.assertNotIn(closed["task_id"], by_id)
        self.assertNotIn(superseded["task_id"], by_id)
        self.assertEqual("decision_deferred", by_id[deferred["task_id"]]["classification"])
        self.assertEqual("outcome_unknown", by_id[unknown["task_id"]]["classification"])
        self.assertEqual(1, result["classification_counts"]["decision_deferred"])
        self.assertEqual(1, result["classification_counts"]["outcome_unknown"])
        self.assertEqual(1, result["filtered_classification_counts"]["decision_closed"])
        self.assertEqual(1, result["filtered_classification_counts"]["decision_superseded"])
        self.assertEqual(4, result["total_attention"])
        self.assertEqual("raw_task_state_projection_before_decisions", result["total_attention_scope"])

    def test_current_user_surfaces_apply_verified_retry_convergence_without_decision_store(self) -> None:
        source, successor = self._verified_retry_pair()
        self.assertFalse(self.decisions.exists())

        reconciled = attention.reconcile_attention({"limit": 20})
        reconciled_ids = {item["task_id"] for item in reconciled["records"]}
        self.assertNotIn(source["task_id"], reconciled_ids)
        self.assertIn(successor["task_id"], reconciled_ids)
        self.assertEqual("verified", reconciled["attention_convergence_status"])
        self.assertEqual(
            1,
            reconciled["filtered_classification_counts"][
                "superseded_by_verified_retry"
            ],
        )
        self.assertEqual(1, reconciled["convergence_excluded_attention_count"])
        self.assertEqual("absent", reconciled["decision_snapshot_status"])

        listed = tasks.grabowski_task_list(
            state="attention",
            view="evidence",
            limit=20,
        )
        listed_ids = {item["task_id"] for item in listed["tasks"]}
        self.assertNotIn(source["task_id"], listed_ids)
        self.assertIn(successor["task_id"], listed_ids)
        self.assertEqual(2, listed["raw_projection_counts"]["attention"])
        self.assertEqual(1, listed["projection_counts"]["attention"])
        self.assertEqual(
            1,
            listed["attention_projection"][
                "convergence_excluded_attention_count"
            ],
        )

        surface = current_work_surface._attention_payload("current")
        surface_ids = {item["task_id"] for item in surface["records"]}
        self.assertNotIn(source["task_id"], surface_ids)
        self.assertIn(successor["task_id"], surface_ids)

    def test_current_user_surfaces_exclude_source_for_running_retry_successor(self) -> None:
        source, successor = self._verified_retry_pair(successor_state="running")
        self.assertEqual("running", successor["state"])

        reconciled = attention.reconcile_attention({"limit": 20})
        reconciled_ids = {item["task_id"] for item in reconciled["records"]}
        self.assertNotIn(source["task_id"], reconciled_ids)
        self.assertNotIn(successor["task_id"], reconciled_ids)
        self.assertEqual(1, reconciled["retry_successor_record_count"])

        listed = tasks.grabowski_task_list(
            state="attention",
            view="evidence",
            limit=20,
        )
        listed_ids = {item["task_id"] for item in listed["tasks"]}
        self.assertNotIn(source["task_id"], listed_ids)
        self.assertNotIn(successor["task_id"], listed_ids)
        self.assertEqual(0, listed["projection_counts"]["attention"])
        self.assertEqual(1, listed["attention_projection"]["retry_successor_record_count"])

    def test_current_user_surfaces_exclude_source_for_completed_retry_successor(self) -> None:
        source, successor = self._verified_retry_pair(successor_state="completed")
        self.assertEqual("completed", successor["state"])

        reconciled = attention.reconcile_attention({"limit": 20})
        reconciled_ids = {item["task_id"] for item in reconciled["records"]}
        self.assertNotIn(source["task_id"], reconciled_ids)
        self.assertNotIn(successor["task_id"], reconciled_ids)
        self.assertEqual(1, reconciled["retry_successor_record_count"])

        listed = tasks.grabowski_task_list(
            state="attention",
            view="evidence",
            limit=20,
        )
        self.assertEqual([], listed["tasks"])
        self.assertEqual(0, listed["projection_counts"]["attention"])

    def test_cancelled_retry_successor_does_not_hide_source_failure(self) -> None:
        source, successor = self._verified_retry_pair(successor_state="cancelled")
        self.assertEqual("cancelled", successor["state"])

        reconciled = attention.reconcile_attention({"limit": 20})
        reconciled_ids = {item["task_id"] for item in reconciled["records"]}
        self.assertIn(source["task_id"], reconciled_ids)
        self.assertNotIn(successor["task_id"], reconciled_ids)
        self.assertEqual(0, reconciled["retry_successor_record_count"])
        self.assertEqual(0, reconciled["convergence_excluded_attention_count"])

        listed = tasks.grabowski_task_list(
            state="attention",
            view="evidence",
            limit=20,
        )
        listed_ids = {item["task_id"] for item in listed["tasks"]}
        self.assertIn(source["task_id"], listed_ids)
        self.assertNotIn(successor["task_id"], listed_ids)
        self.assertEqual(1, listed["projection_counts"]["attention"])

    def test_current_reconciliation_keeps_retry_source_visible_when_binding_is_invalid(self) -> None:
        source, successor = self._verified_retry_pair(successor_state="running")
        successor_row = tasks._row_raw(str(successor["task_id"]))
        launcher = json.loads(str(successor_row["launcher_json"]))
        launcher["retry_binding"]["context_sha256"] = "0" * 64
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                (
                    json.dumps(
                        launcher,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    successor["task_id"],
                ),
            )

        reconciled = attention.reconcile_attention({"limit": 20})
        reconciled_ids = {item["task_id"] for item in reconciled["records"]}
        self.assertIn(source["task_id"], reconciled_ids)
        self.assertNotIn(successor["task_id"], reconciled_ids)
        self.assertEqual("degraded", reconciled["attention_convergence_status"])
        self.assertEqual(
            "TaskAttentionIntegrityError",
            reconciled["attention_convergence_error"],
        )
        self.assertEqual(0, reconciled["convergence_excluded_attention_count"])

    def test_current_attention_projection_separates_operational_signal_from_raw_history(self) -> None:
        closed = self._failed_task()
        attention.record_decision(self._parameters(closed, decision="closed"))
        superseded = self._failed_task()
        attention.record_decision(
            self._parameters(superseded, decision="superseded")
        )
        deferred = self._failed_task()
        attention.record_decision(self._parameters(deferred, decision="deferred"))

        projection = attention.current_attention_projection(
            [closed, superseded, deferred]
        )

        self.assertEqual(3, projection["raw_attention_count"])
        self.assertEqual(1, projection["current_attention_count"])
        self.assertEqual(2, projection["excluded_attention_count"])
        self.assertEqual(
            {"decision_closed": 1, "decision_superseded": 1},
            projection["excluded_classification_counts"],
        )
        self.assertEqual(
            1, projection["decision_classification_counts"]["decision_deferred"]
        )
        self.assertEqual(
            {closed["task_id"], superseded["task_id"]},
            projection["excluded_task_ids"],
        )
        self.assertRegex(projection["projection_sha256"], r"^[0-9a-f]{64}$")

    def test_exact_failed_filter_does_not_claim_attention_without_evaluation(self) -> None:
        closed = self._failed_task()
        attention.record_decision(self._parameters(closed, decision="closed"))

        listed = tasks.grabowski_task_list(state="failed")

        self.assertEqual(1, listed["count"])
        self.assertEqual(closed["task_id"], listed["tasks"][0]["task_id"])
        self.assertEqual("not_evaluated", listed["attention_projection"]["status"])
        self.assertNotIn(
            "task_requires_attention",
            {warning["code"] for warning in listed["warnings"]},
        )

    def test_task_current_records_for_states_batches_lifecycle_projection(self) -> None:
        records = [self._failed_task() for _ in range(3)]
        projection = tasks._task_current_projection()
        original = tasks.lifecycle_projection.bounded_current_task_projection

        with tasks._task_read_snapshot() as connection, patch.object(
            tasks.lifecycle_projection,
            "bounded_current_task_projection",
            wraps=original,
        ) as bounded:
            current = tasks._task_current_records_for_states(
                connection,
                states=tasks.TASK_STATE_PROJECTIONS["attention"],
                projection=projection,
            )

        self.assertEqual(1, bounded.call_count)
        self.assertEqual(3, len(bounded.call_args.args[0]))
        self.assertEqual(
            {str(record["task_id"]) for record in records},
            {str(record["task_id"]) for record in current},
        )

    def test_attention_list_holds_decision_snapshot_through_row_materialization(self) -> None:
        deferred = self._failed_task()
        attention.record_decision(self._parameters(deferred, decision="deferred"))
        record = self._failed_task()
        parameters = self._parameters(record, decision="closed")
        original_rows = tasks._task_list_current_rows
        original_publish = attention.private_io.publish_private_create_only_json
        writer_started = threading.Event()
        publish_reached = threading.Event()
        writer_finished = threading.Event()
        writer_errors: list[BaseException] = []
        writer_threads: list[threading.Thread] = []

        def observed_publish(*args, **kwargs):
            publish_reached.set()
            return original_publish(*args, **kwargs)

        def writer() -> None:
            writer_started.set()
            try:
                attention.record_decision(parameters)
            except BaseException as exc:  # pragma: no cover - surfaced below
                writer_errors.append(exc)
            finally:
                writer_finished.set()

        def rows_while_writer_waits(*args, **kwargs):
            thread = threading.Thread(target=writer, daemon=True)
            writer_threads.append(thread)
            thread.start()
            self.assertTrue(writer_started.wait(1.0))
            self.assertFalse(
                publish_reached.wait(0.1),
                "decision writer reached publication while attention rows were materializing",
            )
            return original_rows(*args, **kwargs)

        with patch.object(
            attention.private_io,
            "publish_private_create_only_json",
            side_effect=observed_publish,
        ), patch.object(
            tasks,
            "_task_list_current_rows",
            side_effect=rows_while_writer_waits,
        ):
            listed = tasks.grabowski_task_list(state="attention")
            self.assertEqual(1, len(writer_threads))
            writer_threads[0].join(timeout=2.0)

        self.assertTrue(writer_finished.is_set())
        self.assertEqual([], writer_errors)
        self.assertTrue(publish_reached.is_set())
        self.assertEqual(2, listed["count"])
        self.assertIn(record["task_id"], {item["task_id"] for item in listed["tasks"]})

        after = tasks.grabowski_task_list(state="attention")
        self.assertEqual(1, after["count"])
        self.assertEqual(1, after["total_matching"])
        self.assertEqual(deferred["task_id"], after["tasks"][0]["task_id"])

    def test_task_list_attention_uses_decision_aware_current_projection(self) -> None:
        closed = self._failed_task()
        attention.record_decision(self._parameters(closed, decision="closed"))
        superseded = self._failed_task()
        attention.record_decision(
            self._parameters(superseded, decision="superseded")
        )
        deferred = self._failed_task()
        attention.record_decision(self._parameters(deferred, decision="deferred"))

        listed = tasks.grabowski_task_list(state="attention")
        general = tasks.grabowski_task_list()

        self.assertEqual(1, listed["count"])
        self.assertEqual(1, listed["total_matching"])
        self.assertEqual(deferred["task_id"], listed["tasks"][0]["task_id"])
        self.assertEqual(3, listed["state_counts"]["failed"])
        self.assertEqual(3, listed["raw_projection_counts"]["attention"])
        self.assertEqual(1, listed["projection_counts"]["attention"])
        self.assertEqual(
            "current_task_projection_after_valid_attention_decisions",
            listed["projection_counts_semantics"]["attention"],
        )
        self.assertEqual(2, listed["attention_projection"]["excluded_attention_count"])
        self.assertEqual(
            "inspect current attention tasks before retry",
            listed["recommended_next_action"],
        )
        self.assertEqual(1, len(general["warnings"]))
        self.assertEqual(deferred["task_id"], general["warnings"][0]["task_id"])
        self.assertEqual(3, general["raw_projection_counts"]["attention"])
        self.assertEqual(1, general["projection_counts"]["attention"])

    def test_task_list_attention_degrades_to_raw_visibility_on_evidence_error(self) -> None:
        failed = self._failed_task()
        self.decisions.mkdir(parents=True, mode=0o700)
        lock_path = self.decisions / ".lock"
        lock_path.write_bytes(b"")
        os.chmod(lock_path, 0o600)

        with patch.object(
            attention,
            "current_attention_projection",
            side_effect=attention.TaskAttentionIntegrityError("broken evidence"),
        ):
            listed = tasks.grabowski_task_list(state="attention")

        self.assertEqual(1, listed["count"])
        self.assertEqual(1, listed["total_matching"])
        self.assertEqual(failed["task_id"], listed["tasks"][0]["task_id"])
        self.assertEqual(1, listed["raw_projection_counts"]["attention"])
        self.assertEqual(1, listed["projection_counts"]["attention"])
        self.assertEqual("degraded", listed["attention_projection"]["status"])
        self.assertEqual(
            "TaskAttentionIntegrityError",
            listed["attention_projection"]["evidence_error"],
        )
        self.assertEqual(0, listed["attention_projection"]["excluded_attention_count"])
        self.assertEqual("attention_projection_degraded", listed["warnings"][0]["code"])
        self.assertEqual(
            "repair attention projection evidence before relying on closeout filtering",
            listed["recommended_next_action"],
        )

    def test_task_list_attention_does_not_create_absent_decision_store(self) -> None:
        failed = self._failed_task()
        self.assertFalse(self.decisions.exists())

        listed = tasks.grabowski_task_list(state="attention")

        self.assertFalse(self.decisions.exists())
        self.assertEqual(1, listed["count"])
        self.assertEqual(failed["task_id"], listed["tasks"][0]["task_id"])
        self.assertEqual("verified", listed["attention_projection"]["status"])
        self.assertEqual(0, listed["attention_projection"]["decision_candidate_count"])
        self.assertEqual(0, listed["attention_projection"]["excluded_attention_count"])

    def test_task_list_attention_degrades_to_raw_visibility_on_decision_lock_error(self) -> None:
        failed = self._failed_task()
        self.decisions.mkdir(parents=True, mode=0o700)

        class BrokenLock:
            def __enter__(self):
                raise attention.TaskAttentionIntegrityError("unsafe decision lock")

            def __exit__(self, exc_type, exc, traceback):
                return False

        with patch.object(
            attention,
            "decision_snapshot_lock",
            return_value=BrokenLock(),
        ):
            listed = tasks.grabowski_task_list(state="attention")

        self.assertEqual(1, listed["count"])
        self.assertEqual(failed["task_id"], listed["tasks"][0]["task_id"])
        self.assertEqual("degraded", listed["attention_projection"]["status"])
        self.assertEqual(
            "TaskAttentionIntegrityError",
            listed["attention_projection"]["evidence_error"],
        )
        self.assertEqual(0, listed["attention_projection"]["excluded_attention_count"])
        self.assertIsNone(listed["attention_projection"]["decision_candidate_count"])

    def test_attention_cursor_is_invalidated_by_new_closeout_decision(self) -> None:
        first = self._failed_task()
        second = self._failed_task()
        page = tasks.grabowski_task_list(state="attention", limit=1)
        self.assertTrue(page["pagination"]["has_more"])
        closed_task_id = page["tasks"][0]["task_id"]
        closed = tasks._row(closed_task_id)
        attention.record_decision(self._parameters(closed, decision="closed"))

        with self.assertRaisesRegex(ValueError, "cursor_snapshot_changed"):
            tasks.grabowski_task_list(
                state="attention",
                limit=1,
                cursor=page["pagination"]["next_cursor"],
            )
        self.assertIn(closed_task_id, {first["task_id"], second["task_id"]})

    def test_current_reconciliation_scans_past_filtered_rows_to_fill_page(self) -> None:
        closed = self._failed_task()
        attention.record_decision(self._parameters(closed, decision="closed"))
        superseded = self._failed_task()
        attention.record_decision(self._parameters(superseded, decision="superseded"))
        actionable = self._failed_task()

        page = attention.reconcile_attention({"limit": 1})

        self.assertEqual([actionable["task_id"]], [item["task_id"] for item in page["records"]])
        self.assertFalse(page["pagination"]["has_more"])
        self.assertGreaterEqual(page["pagination"]["scanned_raw"], 3)
        self.assertEqual(1, page["filtered_classification_counts"]["decision_closed"])
        self.assertEqual(1, page["filtered_classification_counts"]["decision_superseded"])

    def test_reconciliation_rejects_unknown_view(self) -> None:
        with self.assertRaisesRegex(attention.TaskAttentionInputError, "view must be current or history"):
            attention.reconcile_attention({"view": "other"})

    def test_reconciliation_rejects_cursor_from_other_view_as_input_error(self) -> None:
        self._failed_task()
        self._failed_task()
        history = attention.reconcile_attention({"limit": 1, "view": "history"})
        cursor = history["pagination"]["next_cursor"]
        self.assertIsNotNone(cursor)

        with self.assertRaisesRegex(
            attention.TaskAttentionInputError,
            "cursor does not match this view or filter",
        ):
            attention.reconcile_attention({"limit": 1, "cursor": cursor})

    def test_reconciliation_rejects_malformed_cursor_as_input_error(self) -> None:
        with self.assertRaises(attention.TaskAttentionInputError):
            attention.reconcile_attention({"cursor": "not-a-valid-cursor"})

    def test_current_reconciliation_exact_scan_budget_does_not_invent_continuation(self) -> None:
        for decision in ("closed", "superseded"):
            record = self._failed_task()
            attention.record_decision(self._parameters(record, decision=decision))

        with patch.object(attention, "MAX_CURRENT_SCAN_ROWS", 2):
            page = attention.reconcile_attention({"limit": 1})

        self.assertEqual([], page["records"])
        self.assertFalse(page["pagination"]["has_more"])
        self.assertIsNone(page["pagination"]["next_cursor"])
        self.assertEqual(2, page["pagination"]["scanned_raw"])
        self.assertEqual("scanned_raw_window", page["filtered_classification_counts_scope"])

    def test_current_reconciliation_scan_budget_returns_progress_cursor_when_all_rows_filter(self) -> None:
        for decision in ("closed", "superseded", "closed"):
            record = self._failed_task()
            attention.record_decision(self._parameters(record, decision=decision))

        with patch.object(attention, "MAX_CURRENT_SCAN_ROWS", 2):
            first = attention.reconcile_attention({"limit": 1})
            second = attention.reconcile_attention(
                {"limit": 1, "cursor": first["pagination"]["next_cursor"]}
            )

        self.assertEqual([], first["records"])
        self.assertTrue(first["pagination"]["has_more"])
        self.assertIsNotNone(first["pagination"]["next_cursor"])
        self.assertEqual(2, first["pagination"]["scanned_raw"])
        self.assertEqual([], second["records"])
        self.assertFalse(second["pagination"]["has_more"])
        self.assertIsNone(second["pagination"]["next_cursor"])

    def test_missing_terminal_outcome_and_invalid_decision_are_visible(self) -> None:
        record = self._failed_task()
        (self.outcomes / f"{record['task_id']}.json").unlink()
        result = attention.reconcile_attention({"limit": 20})
        item = next(entry for entry in result["records"] if entry["task_id"] == record["task_id"])
        self.assertEqual("invalid_evidence", item["classification"])
        self.assertEqual("FileNotFoundError", item["evidence_error"])

    def test_outcome_unknown_with_decision_artifact_is_invalid_not_closed(self) -> None:
        started = self._start()["task"]
        task_id = str(started["task_id"])
        tasks._set_state(task_id, "outcome_unknown", observation={"state": "outcome_unknown"})
        self.decisions.mkdir(mode=0o700, parents=True)
        artifact = self.decisions / f"{task_id}.a1.json"
        artifact.write_text("{}", encoding="utf-8")
        os.chmod(artifact, 0o600)

        result = attention.reconcile_attention({"limit": 20})
        item = next(entry for entry in result["records"] if entry["task_id"] == task_id)
        self.assertEqual("invalid_evidence", item["classification"])
        self.assertEqual("decision_without_eligible_outcome", item["evidence_error"])

    def test_reconciliation_is_bounded_and_cursor_stable(self) -> None:
        first = self._failed_task()
        second = self._failed_task()
        page = attention.reconcile_attention({"limit": 1, "view": "history"})
        self.assertEqual(1, page["pagination"]["returned"])
        self.assertTrue(page["pagination"]["has_more"])
        next_page = attention.reconcile_attention(
            {"limit": 1, "view": "history", "cursor": page["pagination"]["next_cursor"]}
        )
        ids = {page["records"][0]["task_id"], next_page["records"][0]["task_id"]}
        self.assertEqual({first["task_id"], second["task_id"]}, ids)


    def test_current_surfaces_preserve_runtime_convergence_error_detail(self) -> None:
        self._failed_task()
        message = "retry successor convergence scan limit exceeded"

        with patch.object(
            tasks,
            "_task_retry_successor_records",
            side_effect=RuntimeError(message),
        ):
            reconciled = attention.reconcile_attention({"limit": 20})
        self.assertEqual("degraded", reconciled["attention_convergence_status"])
        self.assertEqual(message, reconciled["attention_convergence_error"])

        with patch.object(
            tasks,
            "_task_retry_successor_records",
            side_effect=RuntimeError(message),
        ):
            listed = tasks.grabowski_task_list(
                state="attention",
                view="evidence",
                limit=20,
            )
        self.assertEqual("degraded", listed["attention_projection"]["status"])
        self.assertEqual(
            message,
            listed["attention_projection"]["evidence_error"],
        )


if __name__ == "__main__":
    unittest.main()
