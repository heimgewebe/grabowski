from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
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
        self.patches = [
            patch.object(tasks, "TASK_DB", self.database),
            patch.object(tasks, "TASK_OUTCOMES_DIR", self.outcomes),
            patch.object(tasks.resources, "RESOURCE_DB", self.resource_database),
            patch.dict(os.environ, {"GRABOWSKI_TASK_ATTENTION_ROOT": str(self.decisions)}),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _start(self) -> dict[str, object]:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
        ):
            return tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "ok"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="verify-then-retry",
            )

    def _failed_task(self) -> dict[str, object]:
        started = self._start()
        task_id = started["task"]["task_id"]
        tasks._set_state(task_id, "failed", observation={"state": "failed"})
        return tasks._row(task_id)

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


if __name__ == "__main__":
    unittest.main()
