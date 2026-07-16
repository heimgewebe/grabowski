from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_blockade_runtime as runtime  # noqa: E402
import grabowski_blockade_store as store  # noqa: E402
import grabowski_mcp as base  # noqa: E402


class BlockadeRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.state.chmod(0o700)
        self.marker = self.state / "operator-kill-switch"
        self.audit = self.state / "write-audit.jsonl"
        self.quarantine = self.state / "quarantine"
        self.blockade_quarantine = self.state / "recovery" / "blockade-quarantine"
        self.stack = ExitStack()
        self.stack.enter_context(mock.patch.object(base, "STATE_DIR", self.state))
        self.stack.enter_context(
            mock.patch.object(base, "KILL_SWITCH_PATH", self.marker)
        )
        self.stack.enter_context(mock.patch.object(base, "AUDIT_LOG", self.audit))
        self.stack.enter_context(
            mock.patch.object(base, "QUARANTINE_DIR", self.quarantine)
        )
        self.stack.enter_context(
            mock.patch.object(runtime, "QUARANTINE_ROOT", self.blockade_quarantine)
        )
        self.stack.enter_context(
            mock.patch.object(base, "_require_capability", return_value=None)
        )
        self.stack.enter_context(
            mock.patch.dict(os.environ, {"GRABOWSKI_OPERATOR_KILL_SWITCH": ""})
        )
        self.stack.enter_context(
            mock.patch.object(
                runtime.recovery,
                "recovery_status",
                side_effect=self.recovery_status,
            )
        )

    def tearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    def recovery_status(self) -> dict[str, object]:
        return {
            "checks": {
                "audit_chain": True,
                "deployment_provenance": True,
                "local_backup_fresh": True,
                "backup_timer_enabled": True,
                "backup_timer_active": True,
                "server_recovery_fresh": True,
                "server_recovery_source_current": True,
                "kill_switch_clear": not self.marker.exists(),
                "privileged_broker_ready": True,
            },
            "effective_recovery_gate": {
                "ready": not self.marker.exists(),
                "reason": "kill-switch-engaged" if self.marker.exists() else "ready",
            },
        }

    def engage(
        self,
        *,
        blockade_id: str = "blockade-runtime-1",
        posture: str = "hard_stop",
        scope_kind: str = "global",
        scope_value: str = "*",
        trigger_class: str = "audit_provenance_unknown",
    ) -> dict[str, object]:
        return runtime.grabowski_operator_blockade_engage(
            blockade_id=blockade_id,
            posture=posture,
            scope_kind=scope_kind,
            scope_value=scope_value,
            reason="Runtime integration proof.",
            trigger_class=trigger_class,
            evidence_refs=["test:runtime-integration"],
            request_id="request-1",
            session_id="session-1",
            task_id="TASK-1",
            owner_id="owner-1",
        )

    def snapshot(self) -> store.MarkerSnapshot:
        return store.read_blockade_marker(
            self.marker,
            expected_marker_path=self.marker,
        )

    def disarm(self, snapshot: store.MarkerSnapshot) -> dict[str, object]:
        return runtime.grabowski_operator_blockade_disarm(
            blockade_id=snapshot.record.blockade_id,
            expected_record_sha256=snapshot.record_sha256,
            expected_marker_file_sha256=snapshot.file_sha256,
        )

    def test_engage_persists_typed_marker_and_matching_audit(self) -> None:
        result = self.engage()
        snapshot = self.snapshot()

        self.assertEqual(snapshot.record.blockade_id, "blockade-runtime-1")
        self.assertEqual(snapshot.record_sha256, result["record_sha256"])
        self.assertEqual(snapshot.file_sha256, result["marker_file_sha256"])
        metadata = self.marker.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertTrue(base._verify_audit_log(self.audit)["valid"])
        audit_records = base._audit_records()
        self.assertEqual(len(audit_records), 1)
        self.assertEqual(audit_records[0]["operation"], "operator-blockade-engage")
        self.assertEqual(
            audit_records[0]["blockade_record_sha256"], snapshot.record_sha256
        )
        self.assertNotEqual(audit_records[0]["record_sha256"], snapshot.record_sha256)
        state = base._kill_switch_state()
        self.assertTrue(state["engaged"])
        self.assertEqual(state["effective_posture"], "hard_stop")
        self.assertEqual(state["diagnostics"]["marker_source"], "typed")

    def test_path_scope_blocks_only_matching_mutation(self) -> None:
        blocked_root = self.root / "repo"
        blocked_root.mkdir()
        self.engage(
            posture="mutation_freeze",
            scope_kind="path",
            scope_value=str(blocked_root),
            trigger_class="manual_path_freeze",
        )

        matching = runtime.grabowski_operator_blockade_status(
            action_class="mutate",
            path=str(blocked_root / "nested" / "file.txt"),
            capability="file_write",
        )
        outside = runtime.grabowski_operator_blockade_status(
            action_class="mutate",
            path=str(self.root / "outside.txt"),
            capability="file_write",
        )
        read_lane = runtime.grabowski_operator_blockade_status(
            action_class="read",
            path=str(blocked_root / "nested" / "file.txt"),
        )

        self.assertTrue(matching["decision"]["blocked"])
        self.assertEqual(
            matching["decision"]["reasons"], ["mutation_blocked_by_mutation_freeze"]
        )
        self.assertTrue(outside["decision"]["allowed"])
        self.assertTrue(read_lane["decision"]["allowed"])
        self.assertIn(
            "immutable_read_lane_remains_available", read_lane["decision"]["reasons"]
        )
        self.assertFalse(base._kill_switch_state()["engaged"])
        self.assertTrue(base._kill_switch_state()["present"])

    def test_opaque_command_fails_closed_for_active_path_scope(self) -> None:
        blocked_root = self.root / "repo"
        blocked_root.mkdir()
        self.engage(
            posture="mutation_freeze",
            scope_kind="path",
            scope_value=str(blocked_root),
            trigger_class="manual_path_freeze",
        )

        with self.assertRaisesRegex(
            PermissionError, "opaque command execution cannot prove isolation"
        ):
            base._require_blockade_allows_mutation(
                "terminal_execute",
                path=str(self.root / "outside"),
                opaque_command=True,
            )

        base._require_blockade_allows_mutation(
            "file_write", path=str(self.root / "outside.txt")
        )

    def test_disarm_requires_file_move_authority(self) -> None:
        self.engage()
        snapshot = self.snapshot()

        def require(capability: str) -> None:
            if capability == "file_move":
                raise PermissionError("Access capability is not enabled: file_move")

        with mock.patch.object(base, "_require_capability", side_effect=require):
            with self.assertRaisesRegex(PermissionError, "file_move"):
                self.disarm(snapshot)

        self.assertTrue(self.marker.is_file())
        self.assertEqual(len(base._audit_records()), 1)

    def test_expired_typed_marker_can_be_collected_by_exact_disarm(self) -> None:
        now = datetime.now(timezone.utc)
        record = runtime.policy.BlockadeRecord(
            blockade_id="expired-observe-1",
            posture="observe",
            scope=runtime.policy.Scope("path", str(self.root / "repo")),
            reason="Expired observation marker.",
            trigger_class="manual_observation",
            engaged_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            evidence_refs=("test:expired-marker",),
            provenance=runtime.policy.Provenance(
                tool="grabowski_operator_blockade_engage",
                request_id="request-expired",
                session_id="session-expired",
                task_id="TASK-EXPIRED",
                owner_id="owner-expired",
            ),
        )
        receipt = store.engage_blockade_marker(
            record,
            self.marker,
            expected_marker_path=self.marker,
        )
        runtime._append_verified_audit(
            {
                "timestamp": now.isoformat(),
                "operation": "operator-blockade-engage",
                "transaction_id": receipt.transaction_id,
                "path": str(self.marker),
                "before_sha256": None,
                "after_sha256": receipt.marker_file_sha256,
                "blockade_id": record.blockade_id,
                "blockade_record_sha256": record.sha256,
                "posture": record.posture,
                "scope": record.scope.to_mapping(),
                "evidence_refs": list(record.evidence_refs),
                "provenance": record.provenance.to_mapping(),
            }
        )
        snapshot = self.snapshot()
        self.assertFalse(snapshot.record.active_at())

        result = self.disarm(snapshot)

        self.assertFalse(self.marker.exists())
        self.assertEqual(
            result["decision"]["matched_blockade_ids"],
            ["expired-observe-1"],
        )
        self.assertIn(
            "evidence_bound_recovery_allowed", result["decision"]["reasons"]
        )

    def test_disarm_is_hash_bound_and_audit_verified(self) -> None:
        self.engage()
        snapshot = self.snapshot()
        result = self.disarm(snapshot)

        self.assertFalse(self.marker.exists())
        receipt = result["receipt"]
        self.assertTrue(Path(receipt["quarantine_path"]).is_file())
        self.assertTrue(Path(receipt["receipt_path"]).is_file())
        self.assertEqual(
            result["receipt_sha256"],
            store.DisarmReceipt(
                transaction_id=receipt["transaction_id"],
                created_at=receipt["created_at"],
                marker_path=receipt["marker_path"],
                quarantine_directory=receipt["quarantine_directory"],
                quarantine_path=receipt["quarantine_path"],
                receipt_path=receipt["receipt_path"],
                marker_file_sha256=receipt["marker_file_sha256"],
                record_sha256=receipt["record_sha256"],
                record=snapshot.record,
            ).receipt_sha256,
        )
        self.assertTrue(base._verify_audit_log(self.audit)["valid"])
        audit_records = base._audit_records()
        self.assertEqual(
            [item["operation"] for item in audit_records],
            ["operator-blockade-engage", "operator-blockade-disarm"],
        )
        self.assertEqual(
            audit_records[-1]["blockade_record_sha256"], snapshot.record_sha256
        )
        self.assertFalse(result["kill_switch"]["engaged"])

    def test_environment_stop_cannot_be_disarmed_in_band(self) -> None:
        self.engage()
        snapshot = self.snapshot()
        with mock.patch.dict(
            os.environ,
            {"GRABOWSKI_OPERATOR_KILL_SWITCH": "true"},
        ):
            with self.assertRaisesRegex(
                PermissionError, "external_stop_requires_external_clear"
            ):
                self.disarm(snapshot)
        self.assertTrue(self.marker.is_file())
        self.assertEqual(len(base._audit_records()), 1)

    def test_engage_audit_failure_removes_exact_marker(self) -> None:
        with mock.patch.object(
            runtime,
            "_append_verified_audit",
            side_effect=OSError("audit append fault"),
        ):
            with self.assertRaisesRegex(
                store.BlockadeRollbackError, "exact marker was removed"
            ):
                self.engage()

        self.assertFalse(self.marker.exists())
        self.assertEqual(base._audit_records(), [])
        self.assertFalse(base._kill_switch_state()["present"])

    def test_disarm_audit_failure_restores_exact_marker(self) -> None:
        self.engage()
        snapshot = self.snapshot()
        original = self.marker.read_bytes()
        with mock.patch.object(
            runtime,
            "_append_verified_audit",
            side_effect=OSError("audit append fault"),
        ):
            with self.assertRaisesRegex(
                store.BlockadeRollbackError, "exact marker was restored"
            ):
                self.disarm(snapshot)

        self.assertTrue(self.marker.is_file())
        self.assertEqual(self.marker.read_bytes(), original)
        restored = self.snapshot()
        self.assertEqual(restored.file_sha256, snapshot.file_sha256)
        self.assertEqual(restored.record_sha256, snapshot.record_sha256)
        self.assertEqual(len(base._audit_records()), 1)

    def test_marker_observation_race_is_fail_closed_for_current_decision(self) -> None:
        self.marker.write_text("moving marker\n", encoding="utf-8")
        self.marker.chmod(0o600)
        with (
            mock.patch.object(
                base.blockade_store,
                "read_blockade_marker",
                side_effect=FileNotFoundError("marker moved"),
            ),
            mock.patch.object(
                base.os,
                "lstat",
                side_effect=FileNotFoundError("marker disappeared"),
            ),
        ):
            state = base._kill_switch_state()
        self.assertTrue(state["engaged"])
        self.assertEqual(
            state["diagnostics"]["marker_source"],
            "marker_observation_uncertain",
        )
        self.assertEqual(state["effective_posture"], "hard_stop")

    def test_legacy_or_unsafe_marker_fails_closed_without_content_trust(self) -> None:
        self.marker.write_text("legacy stop\n", encoding="utf-8")
        self.marker.chmod(0o600)
        state = base._kill_switch_state()
        self.assertTrue(state["engaged"])
        self.assertEqual(state["diagnostics"]["marker_source"], "legacy_file")
        self.assertIn("marker_error", state["diagnostics"])
        with self.assertRaisesRegex(PermissionError, "kill switch/blockade"):
            base._require_mutations_enabled("file_write", path=str(self.root / "x"))


if __name__ == "__main__":
    unittest.main()
