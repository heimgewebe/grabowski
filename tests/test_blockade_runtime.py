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
        self.legacy_marker = self.state / "legacy-operator-kill-switch"
        self.audit = self.state / "write-audit.jsonl"
        self.quarantine = self.state / "quarantine"
        self.blockade_quarantine = self.state / "recovery" / "blockade-quarantine"
        self.stack = ExitStack()
        self.stack.enter_context(mock.patch.object(base, "STATE_DIR", self.state))
        self.stack.enter_context(
            mock.patch.object(base, "KILL_SWITCH_PATH", self.marker)
        )
        self.stack.enter_context(
            mock.patch.object(base, "LEGACY_KILL_SWITCH_PATH", self.legacy_marker)
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
        self.stack.enter_context(
            mock.patch.object(
                runtime.privileged,
                "run_blockade_lifecycle_reference",
                side_effect=self.broker_lifecycle,
            )
        )

    def tearDown(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    def broker_lifecycle(
        self,
        payload: dict[str, object],
        *,
        justification: str,
    ) -> dict[str, object]:
        del justification
        operation = payload["operation"]
        transaction_id = str(payload["transaction_id"])
        self.blockade_quarantine.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.blockade_quarantine.chmod(0o700)
        if operation == "engage":
            record = runtime.policy.BlockadeRecord.from_mapping(payload["record"])
            receipt = store.engage_blockade_marker(
                record,
                self.marker,
                expected_marker_path=self.marker,
                transaction_id=transaction_id,
            )
            lifecycle = {
                "operation": operation,
                "receipt": receipt.to_mapping(),
            }
        elif operation == "rollback-engage":
            snapshot = self.snapshot()
            receipt = store.EngageReceipt(
                transaction_id=transaction_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                marker_path=str(self.marker),
                marker_file_sha256=snapshot.file_sha256,
                record_sha256=snapshot.record_sha256,
                record=snapshot.record,
            )
            lifecycle = {
                "operation": operation,
                "rollback": store.rollback_engaged_marker(
                    receipt,
                    self.marker,
                    expected_marker_path=self.marker,
                ),
            }
        elif operation == "migrate":
            legacy_snapshot = store.read_blockade_marker(
                self.legacy_marker,
                expected_marker_path=self.legacy_marker,
            )
            canonical_receipt = store.engage_blockade_marker(
                legacy_snapshot.record,
                self.marker,
                expected_marker_path=self.marker,
                transaction_id=transaction_id,
            )
            lifecycle = {
                "operation": operation,
                "canonical_receipt": canonical_receipt.to_mapping(),
                "legacy_preserved": True,
            }
        elif operation == "disarm":
            snapshot = self.snapshot()
            evidence = runtime.policy.DisarmEvidence(
                blockade_id=snapshot.record.blockade_id,
                record_sha256=snapshot.record_sha256,
                scope=snapshot.record.scope,
                marker_path=str(self.marker),
                marker_present=True,
                marker_regular=True,
                marker_nlink=snapshot.nlink,
                marker_mode=snapshot.mode,
                marker_owner_matches=True,
                environment_switch_off=True,
                audit_valid=True,
                deployment_provenance_valid=True,
                canonical_recovery_fresh=True,
                root_broker_ready=True,
            )
            receipt = store.disarm_blockade_marker(
                snapshot.record,
                evidence,
                self.marker,
                self.blockade_quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.blockade_quarantine,
                transaction_id=transaction_id,
            )
            lifecycle = {
                "operation": operation,
                "receipt": receipt.to_mapping(),
                "receipt_sha256": receipt.receipt_sha256,
            }
        elif operation == "restore-disarm":
            receipt = store.restore_disarmed_marker(
                transaction_id,
                self.marker,
                self.blockade_quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.blockade_quarantine,
                expected_record_sha256=str(payload["expected_record_sha256"]),
                expected_marker_file_sha256=str(
                    payload["expected_marker_file_sha256"]
                ),
                expected_disarm_receipt_sha256=str(
                    payload["expected_disarm_receipt_sha256"]
                ),
            )
            lifecycle = {
                "operation": operation,
                "receipt": receipt.to_mapping(),
            }
        elif operation == "observe":
            if self.marker.exists() or self.marker.is_symlink():
                snapshot = self.snapshot()
                lifecycle = {
                    "operation": operation,
                    "state": "engaged",
                    "record_sha256": snapshot.record_sha256,
                    "marker_file_sha256": snapshot.file_sha256,
                }
            else:
                try:
                    receipt, receipt_sha256 = store.read_disarm_receipt(
                        transaction_id,
                        self.blockade_quarantine,
                        expected_quarantine_root=self.blockade_quarantine,
                        expected_marker_path=self.marker,
                        expected_record_sha256=str(
                            payload["expected_record_sha256"]
                        ),
                        expected_marker_file_sha256=str(
                            payload["expected_marker_file_sha256"]
                        ),
                    )
                except FileNotFoundError:
                    lifecycle = {
                        "operation": operation,
                        "state": "absent_unproven",
                    }
                else:
                    lifecycle = {
                        "operation": operation,
                        "state": "disarmed",
                        "receipt": receipt,
                        "receipt_sha256": receipt_sha256,
                    }
        else:
            raise AssertionError(f"unexpected broker lifecycle operation: {operation}")
        return {
            "success": True,
            "outcome": "succeeded",
            "failure_reason": None,
            "lifecycle": lifecycle,
        }

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

    def test_exact_legacy_migration_preserves_blockade_and_disarm_contract(self) -> None:
        record = runtime.policy.BlockadeRecord(
            blockade_id="legacy-migration-1",
            posture="hard_stop",
            scope=runtime.policy.Scope("global", "*"),
            reason="Legacy migration runtime test.",
            trigger_class="audit_provenance_unknown",
            engaged_at=datetime.now(timezone.utc),
            evidence_refs=("test:legacy-migration",),
            provenance=runtime.policy.Provenance(
                tool="legacy-test",
                request_id="legacy-request",
                session_id="legacy-session",
                task_id="legacy-task",
                owner_id="legacy-owner",
            ),
        )
        legacy_receipt = store.engage_blockade_marker(
            record,
            self.legacy_marker,
            expected_marker_path=self.legacy_marker,
            transaction_id="legacy-engage",
        )

        result = runtime.grabowski_operator_blockade_migrate_legacy(
            blockade_id=record.blockade_id,
            expected_record_sha256=legacy_receipt.record_sha256,
            expected_marker_file_sha256=legacy_receipt.marker_file_sha256,
        )

        self.assertFalse(self.legacy_marker.exists())
        snapshot = self.snapshot()
        self.assertEqual(snapshot.record, record)
        self.assertEqual(result["record_sha256"], snapshot.record_sha256)
        operations = [item["operation"] for item in base._audit_records()]
        self.assertIn("operator-blockade-migration-intent", operations)
        self.assertIn("operator-blockade-migration-complete", operations)

        disarmed = self.disarm(snapshot)
        self.assertFalse(self.marker.exists())
        self.assertEqual(
            disarmed["receipt"]["record_sha256"],
            snapshot.record_sha256,
        )

    def test_legacy_cleanup_failure_keeps_both_markers_fail_closed(self) -> None:
        record = runtime.policy.BlockadeRecord(
            blockade_id="legacy-migration-failure-1",
            posture="hard_stop",
            scope=runtime.policy.Scope("global", "*"),
            reason="Legacy cleanup failure proof.",
            trigger_class="audit_provenance_unknown",
            engaged_at=datetime.now(timezone.utc),
            evidence_refs=("test:legacy-cleanup-failure",),
            provenance=runtime.policy.Provenance(
                tool="legacy-test",
                request_id="legacy-request",
                session_id="legacy-session",
                task_id="legacy-task",
                owner_id="legacy-owner",
            ),
        )
        legacy_receipt = store.engage_blockade_marker(
            record,
            self.legacy_marker,
            expected_marker_path=self.legacy_marker,
            transaction_id="legacy-engage-failure",
        )
        with mock.patch.object(
            runtime.store,
            "rollback_engaged_marker",
            side_effect=OSError("injected legacy cleanup failure"),
        ):
            with self.assertRaisesRegex(
                store.BlockadeRollbackError,
                "canonical marker is engaged",
            ):
                runtime.grabowski_operator_blockade_migrate_legacy(
                    blockade_id=record.blockade_id,
                    expected_record_sha256=legacy_receipt.record_sha256,
                    expected_marker_file_sha256=legacy_receipt.marker_file_sha256,
                )
        self.assertTrue(self.marker.exists())
        self.assertTrue(self.legacy_marker.exists())
        self.assertEqual(self.snapshot().record, record)

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
        self.assertEqual(state["diagnostics"]["marker_source"], "canonical_typed")

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

    def test_engage_unknown_response_is_classified_by_exact_readback(self) -> None:
        real_broker = self.broker_lifecycle

        def unknown_after_commit(payload, *, justification):
            result = real_broker(payload, justification=justification)
            if payload["operation"] == "engage":
                return {
                    "success": False,
                    "outcome": "unknown",
                    "failure_reason": "response lost after commit",
                    "lifecycle": None,
                }
            return result

        with mock.patch.object(
            runtime.privileged,
            "run_blockade_lifecycle_reference",
            side_effect=unknown_after_commit,
        ):
            result = self.engage(blockade_id="unknown-engage")

        snapshot = self.snapshot()
        self.assertEqual(snapshot.record.blockade_id, "unknown-engage")
        self.assertEqual(result["record_sha256"], snapshot.record_sha256)
        self.assertEqual(result["broker"]["outcome"], "unknown")

    def test_disarm_unknown_response_is_classified_by_root_receipt(self) -> None:
        self.engage(blockade_id="unknown-disarm")
        snapshot = self.snapshot()
        real_broker = self.broker_lifecycle

        def unknown_after_commit(payload, *, justification):
            result = real_broker(payload, justification=justification)
            if payload["operation"] == "disarm":
                return {
                    "success": False,
                    "outcome": "unknown",
                    "failure_reason": "response lost after commit",
                    "lifecycle": None,
                }
            return result

        with mock.patch.object(
            runtime.privileged,
            "run_blockade_lifecycle_reference",
            side_effect=unknown_after_commit,
        ):
            result = self.disarm(snapshot)

        self.assertFalse(self.marker.exists())
        self.assertEqual(result["receipt"]["record_sha256"], snapshot.record_sha256)
        self.assertEqual(result["broker"]["outcome"], "unknown")

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
                store.BlockadeRollbackError, "exact root-owned marker was rolled back"
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
                store.BlockadeRollbackError, "exact root-owned marker was restored"
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
            "canonical_observation_uncertain",
        )
        self.assertEqual(state["effective_posture"], "hard_stop")

    def test_legacy_or_unsafe_marker_fails_closed_without_content_trust(self) -> None:
        self.marker.write_text("legacy stop\n", encoding="utf-8")
        self.marker.chmod(0o600)
        state = base._kill_switch_state()
        self.assertTrue(state["engaged"])
        self.assertEqual(state["diagnostics"]["marker_source"], "canonical_unsafe_file")
        self.assertIn("marker_error", state["diagnostics"])
        with self.assertRaisesRegex(PermissionError, "kill switch/blockade"):
            base._require_mutations_enabled("file_write", path=str(self.root / "x"))


if __name__ == "__main__":
    unittest.main()
