from __future__ import annotations

from datetime import datetime, timezone
import json
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

import grabowski_blockade_store as blockade_store  # noqa: E402
from grabowski_blockades import (  # noqa: E402
    BlockadeRecord,
    DisarmEvidence,
    Provenance,
    Scope,
    canonical_json,
)
from grabowski_blockade_store import (  # noqa: E402
    BlockadeAlreadyEngaged,
    BlockadeRecoveryDenied,
    BlockadeRollbackError,
    disarm_blockade_marker,
    engage_blockade_marker,
    read_blockade_marker,
    restore_disarmed_marker,
    rollback_engaged_marker,
)


NOW = datetime(2026, 7, 14, 20, 0, tzinfo=timezone.utc)


def record(*, blockade_id: str = "blockade-1") -> BlockadeRecord:
    return BlockadeRecord(
        blockade_id=blockade_id,
        posture="hard_stop",
        scope=Scope("global", "*"),
        reason="Audit integrity is invalid.",
        trigger_class="audit_integrity_invalid",
        engaged_at=NOW,
        evidence_refs=("audit:invalid",),
        provenance=Provenance(
            tool="grabowski_operator_blockade_engage",
            request_id="request-1",
            session_id="session-1",
            task_id="TASK-1",
            owner_id="owner-1",
        ),
    )


def evidence(item: BlockadeRecord, marker: Path, **overrides: object) -> DisarmEvidence:
    values: dict[str, object] = {
        "blockade_id": item.blockade_id,
        "record_sha256": item.sha256,
        "scope": item.scope,
        "marker_path": str(marker),
        "marker_present": True,
        "marker_regular": True,
        "marker_nlink": 1,
        "marker_mode": 0o600,
        "marker_owner_matches": True,
        "environment_switch_off": True,
        "audit_valid": True,
        "deployment_provenance_valid": True,
        "canonical_recovery_fresh": True,
        "root_broker_ready": True,
    }
    values.update(overrides)
    return DisarmEvidence(**values)  # type: ignore[arg-type]


class BlockadeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        self.quarantine = self.state / "blockade-quarantine"
        self.state.mkdir(mode=0o700)
        self.quarantine.mkdir(mode=0o700)
        self.marker = self.state / "operator-kill-switch"
        self.item = record()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def engage(self):
        return engage_blockade_marker(
            self.item,
            self.marker,
            expected_marker_path=self.marker,
            transaction_id="engage-1",
            now=NOW,
        )

    def disarm(self, **kwargs: object):
        values: dict[str, object] = {
            "record": self.item,
            "evidence": evidence(self.item, self.marker),
            "marker_path": self.marker,
            "quarantine_root": self.quarantine,
            "expected_marker_path": self.marker,
            "expected_quarantine_root": self.quarantine,
            "transaction_id": "disarm-1",
            "now": NOW,
        }
        values.update(kwargs)
        return disarm_blockade_marker(**values)  # type: ignore[arg-type]

    def test_engage_is_create_only_canonical_and_read_back(self) -> None:
        receipt = self.engage()
        self.assertTrue(self.marker.is_file())
        self.assertFalse(self.marker.is_symlink())
        metadata = self.marker.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertEqual(
            self.marker.read_bytes(), canonical_json(self.item.to_mapping())
        )

        snapshot = read_blockade_marker(
            self.marker,
            expected_marker_path=self.marker,
        )
        self.assertEqual(snapshot.record, self.item)
        self.assertEqual(snapshot.record_sha256, self.item.sha256)
        self.assertEqual(snapshot.file_sha256, receipt.marker_file_sha256)
        self.assertEqual(receipt.record_sha256, self.item.sha256)
        self.assertEqual(receipt.transaction_id, "engage-1")
        self.assertTrue(receipt.to_mapping()["create_only"])

    def test_exact_engage_rollback_removes_only_matching_marker(self) -> None:
        receipt = self.engage()
        result = rollback_engaged_marker(
            receipt,
            self.marker,
            expected_marker_path=self.marker,
        )
        self.assertFalse(self.marker.exists())
        self.assertTrue(result["source_absent_readback"])
        self.assertEqual(
            result["removed_marker_file_sha256"], receipt.marker_file_sha256
        )
        self.assertEqual(result["removed_record_sha256"], receipt.record_sha256)

    def test_engage_rollback_rejects_identity_drift_before_mutation(self) -> None:
        receipt = self.engage()
        mismatched = blockade_store.EngageReceipt(
            transaction_id=receipt.transaction_id,
            created_at=receipt.created_at,
            marker_path=receipt.marker_path,
            marker_file_sha256="0" * 64,
            record_sha256=receipt.record_sha256,
            record=receipt.record,
        )
        with self.assertRaisesRegex(BlockadeRecoveryDenied, "does not match"):
            rollback_engaged_marker(
                mismatched,
                self.marker,
                expected_marker_path=self.marker,
            )
        self.assertTrue(self.marker.is_file())
        self.assertEqual(
            self.marker.read_bytes(), canonical_json(self.item.to_mapping())
        )

    def test_engage_rollback_surfaces_unverified_unlink(self) -> None:
        receipt = self.engage()
        with mock.patch(
            "grabowski_blockade_store._unlink_same_inode", return_value=False
        ):
            with self.assertRaisesRegex(BlockadeRollbackError, "absence was verified"):
                rollback_engaged_marker(
                    receipt,
                    self.marker,
                    expected_marker_path=self.marker,
                )
        self.assertTrue(self.marker.is_file())

    def test_engage_rolls_back_if_post_publish_readback_fails(self) -> None:
        with mock.patch(
            "grabowski_blockade_store._snapshot_from_open_file",
            side_effect=OSError("engage readback fault"),
        ):
            with self.assertRaisesRegex(OSError, "engage readback fault"):
                self.engage()
        self.assertFalse(self.marker.exists())

    def test_engage_surfaces_unverified_rollback_as_hard_error(self) -> None:
        with (
            mock.patch(
                "grabowski_blockade_store._snapshot_from_open_file",
                side_effect=OSError("engage readback fault"),
            ),
            mock.patch(
                "grabowski_blockade_store._unlink_same_inode",
                return_value=False,
            ),
        ):
            with self.assertRaisesRegex(
                BlockadeRollbackError, "rollback could not be verified"
            ):
                self.engage()
        self.assertTrue(self.marker.exists())

    def test_engage_refuses_existing_marker_without_replacement(self) -> None:
        first = self.engage()
        before = self.marker.read_bytes()
        with self.assertRaises(BlockadeAlreadyEngaged):
            engage_blockade_marker(
                record(blockade_id="blockade-2"),
                self.marker,
                expected_marker_path=self.marker,
                transaction_id="engage-2",
                now=NOW,
            )
        self.assertEqual(self.marker.read_bytes(), before)
        self.assertEqual(first.record, self.item)

    def test_engage_and_read_require_exact_trusted_path(self) -> None:
        other = self.state / "other-marker"
        with self.assertRaisesRegex(PermissionError, "trusted runtime path"):
            engage_blockade_marker(
                self.item,
                other,
                expected_marker_path=self.marker,
            )
        self.engage()
        with self.assertRaisesRegex(PermissionError, "trusted runtime path"):
            read_blockade_marker(
                self.marker,
                expected_marker_path=other,
            )

    def test_directory_chain_rejects_symlink_and_nonprivate_parent(self) -> None:
        public = self.root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        public_marker = public / "operator-kill-switch"
        with self.assertRaisesRegex(PermissionError, "not private"):
            engage_blockade_marker(
                self.item,
                public_marker,
                expected_marker_path=public_marker,
            )

        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        linked = self.root / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        linked_marker = linked / "operator-kill-switch"
        with self.assertRaises(OSError):
            engage_blockade_marker(
                self.item,
                linked_marker,
                expected_marker_path=linked_marker,
            )

    def test_read_rejects_symlink_hardlink_mode_and_noncanonical_json(self) -> None:
        target = self.state / "target"
        target.write_bytes(canonical_json(self.item.to_mapping()))
        target.chmod(0o600)
        self.marker.symlink_to(target)
        with self.assertRaises(OSError):
            read_blockade_marker(self.marker, expected_marker_path=self.marker)
        self.marker.unlink()

        self.engage()
        hardlink = self.state / "hardlink"
        os.link(self.marker, hardlink)
        with self.assertRaisesRegex(PermissionError, "single-link"):
            read_blockade_marker(self.marker, expected_marker_path=self.marker)
        hardlink.unlink()

        self.marker.chmod(0o644)
        with self.assertRaisesRegex(PermissionError, "0600"):
            read_blockade_marker(self.marker, expected_marker_path=self.marker)
        self.marker.unlink()

        pretty = json.dumps(self.item.to_mapping(), indent=2).encode("utf-8")
        self.marker.write_bytes(pretty)
        self.marker.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "canonical JSON"):
            read_blockade_marker(self.marker, expected_marker_path=self.marker)

    def test_read_rejects_duplicate_json_keys_and_wrong_owner_expectation(self) -> None:
        self.marker.write_text(
            '{"schema_version":1,"schema_version":1}',
            encoding="utf-8",
        )
        self.marker.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            read_blockade_marker(self.marker, expected_marker_path=self.marker)
        self.marker.unlink()

        self.engage()
        with self.assertRaisesRegex(PermissionError, "owner"):
            read_blockade_marker(
                self.marker,
                expected_marker_path=self.marker,
                expected_uid=os.getuid() + 1,
            )

    def test_disarm_moves_exact_marker_and_writes_canonical_receipt(self) -> None:
        engaged = self.engage()
        receipt = self.disarm()
        self.assertFalse(self.marker.exists())
        preimage = Path(receipt.quarantine_path)
        receipt_path = Path(receipt.receipt_path)
        self.assertTrue(preimage.is_file())
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(stat.S_IMODE(preimage.stat().st_mode), 0o600)
        self.assertEqual(preimage.stat().st_nlink, 1)
        self.assertEqual(receipt.marker_file_sha256, engaged.marker_file_sha256)
        self.assertEqual(receipt.record_sha256, self.item.sha256)
        self.assertEqual(
            receipt_path.read_bytes(),
            canonical_json(receipt.to_mapping()),
        )
        quarantined = read_blockade_marker(
            preimage,
            expected_marker_path=preimage,
        )
        self.assertEqual(quarantined.record, self.item)
        self.assertEqual(quarantined.file_sha256, engaged.marker_file_sha256)

    def test_disarm_denial_occurs_before_mutation(self) -> None:
        self.engage()
        denied = evidence(self.item, self.marker, audit_valid=False)
        with self.assertRaisesRegex(BlockadeRecoveryDenied, "audit_invalid"):
            self.disarm(evidence=denied)
        self.assertTrue(self.marker.is_file())
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_disarm_rejects_record_or_marker_identity_drift(self) -> None:
        self.engage()
        other = record(blockade_id="blockade-2")
        with self.assertRaises(BlockadeRecoveryDenied):
            self.disarm(
                record=other,
                evidence=evidence(other, self.marker),
            )
        self.assertTrue(self.marker.is_file())

        hardlink = self.state / "hardlink"
        os.link(self.marker, hardlink)
        with self.assertRaisesRegex(PermissionError, "single-link"):
            self.disarm()
        hardlink.unlink()
        self.assertTrue(self.marker.is_file())

    def test_disarm_requires_exact_private_quarantine_root(self) -> None:
        self.engage()
        other = self.state / "other-quarantine"
        other.mkdir(mode=0o700)
        with self.assertRaisesRegex(PermissionError, "trusted runtime path"):
            self.disarm(quarantine_root=other)
        self.assertTrue(self.marker.is_file())

        self.quarantine.chmod(0o755)
        with self.assertRaisesRegex(PermissionError, "not private"):
            self.disarm()
        self.assertTrue(self.marker.is_file())

    def test_disarm_rolls_back_if_receipt_publication_fails(self) -> None:
        engaged = self.engage()
        with mock.patch(
            "grabowski_blockade_store._publish_create_only_bytes_at",
            side_effect=OSError("receipt fault"),
        ):
            with self.assertRaisesRegex(OSError, "receipt fault"):
                self.disarm()
        restored = read_blockade_marker(
            self.marker,
            expected_marker_path=self.marker,
        )
        self.assertEqual(restored.file_sha256, engaged.marker_file_sha256)
        self.assertEqual(list(self.quarantine.iterdir()), [])

    def test_disarm_surfaces_unverified_rollback_as_hard_error(self) -> None:
        self.engage()
        original_unlink = blockade_store._unlink_same_inode
        calls = 0

        def fail_second_unlink(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                return False
            return original_unlink(*args, **kwargs)

        with (
            mock.patch(
                "grabowski_blockade_store._publish_create_only_bytes_at",
                side_effect=OSError("receipt fault"),
            ),
            mock.patch(
                "grabowski_blockade_store._unlink_same_inode",
                side_effect=fail_second_unlink,
            ),
        ):
            with self.assertRaisesRegex(
                BlockadeRollbackError, "rollback could not be verified"
            ):
                self.disarm()
        self.assertTrue(self.marker.exists())
        self.assertTrue((self.quarantine / "disarm-1").exists())

    def test_restore_round_trip_is_hash_bound_and_auditable(self) -> None:
        engaged = self.engage()
        disarmed = self.disarm()
        restored = restore_disarmed_marker(
            disarmed.transaction_id,
            self.marker,
            self.quarantine,
            expected_marker_path=self.marker,
            expected_quarantine_root=self.quarantine,
            expected_record_sha256=disarmed.record_sha256,
            expected_marker_file_sha256=disarmed.marker_file_sha256,
            expected_disarm_receipt_sha256=disarmed.receipt_sha256,
            now=NOW,
        )
        self.assertTrue(self.marker.is_file())
        self.assertFalse(Path(disarmed.quarantine_path).exists())
        self.assertTrue(Path(restored.receipt_path).is_file())
        snapshot = read_blockade_marker(
            self.marker,
            expected_marker_path=self.marker,
        )
        self.assertEqual(snapshot.file_sha256, engaged.marker_file_sha256)
        self.assertEqual(snapshot.record, self.item)
        self.assertEqual(
            Path(restored.receipt_path).read_bytes(),
            canonical_json(restored.to_mapping()),
        )

    def test_restore_refuses_wrong_hash_or_occupied_source(self) -> None:
        self.engage()
        disarmed = self.disarm()
        with self.assertRaisesRegex(BlockadeRecoveryDenied, "receipt mismatch"):
            restore_disarmed_marker(
                disarmed.transaction_id,
                self.marker,
                self.quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.quarantine,
                expected_record_sha256="f" * 64,
                expected_marker_file_sha256=disarmed.marker_file_sha256,
                expected_disarm_receipt_sha256=disarmed.receipt_sha256,
            )
        self.assertFalse(self.marker.exists())
        self.assertTrue(Path(disarmed.quarantine_path).exists())

        with self.assertRaisesRegex(BlockadeRecoveryDenied, "SHA-256 mismatch"):
            restore_disarmed_marker(
                disarmed.transaction_id,
                self.marker,
                self.quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.quarantine,
                expected_record_sha256=disarmed.record_sha256,
                expected_marker_file_sha256=disarmed.marker_file_sha256,
                expected_disarm_receipt_sha256="0" * 64,
            )
        self.assertFalse(self.marker.exists())
        self.assertTrue(Path(disarmed.quarantine_path).exists())

        self.marker.write_bytes(b"occupied")
        self.marker.chmod(0o600)
        with self.assertRaisesRegex(BlockadeRecoveryDenied, "not absent"):
            restore_disarmed_marker(
                disarmed.transaction_id,
                self.marker,
                self.quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.quarantine,
                expected_record_sha256=disarmed.record_sha256,
                expected_marker_file_sha256=disarmed.marker_file_sha256,
                expected_disarm_receipt_sha256=disarmed.receipt_sha256,
            )
        self.assertEqual(self.marker.read_bytes(), b"occupied")
        self.assertTrue(Path(disarmed.quarantine_path).exists())

    def test_restore_rolls_back_if_restore_receipt_fails(self) -> None:
        self.engage()
        disarmed = self.disarm()
        with mock.patch(
            "grabowski_blockade_store._publish_create_only_bytes_at",
            side_effect=OSError("restore receipt fault"),
        ):
            with self.assertRaisesRegex(OSError, "restore receipt fault"):
                restore_disarmed_marker(
                    disarmed.transaction_id,
                    self.marker,
                    self.quarantine,
                    expected_marker_path=self.marker,
                    expected_quarantine_root=self.quarantine,
                    expected_record_sha256=disarmed.record_sha256,
                    expected_marker_file_sha256=disarmed.marker_file_sha256,
                    expected_disarm_receipt_sha256=disarmed.receipt_sha256,
                )
        self.assertFalse(self.marker.exists())
        self.assertTrue(Path(disarmed.quarantine_path).is_file())
        snapshot = read_blockade_marker(
            Path(disarmed.quarantine_path),
            expected_marker_path=Path(disarmed.quarantine_path),
        )
        self.assertEqual(snapshot.record, self.item)

    def test_restore_surfaces_unverified_rollback_as_hard_error(self) -> None:
        self.engage()
        disarmed = self.disarm()
        original_unlink = blockade_store._unlink_same_inode
        calls = 0

        def fail_second_unlink(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                return False
            return original_unlink(*args, **kwargs)

        with (
            mock.patch(
                "grabowski_blockade_store._publish_create_only_bytes_at",
                side_effect=OSError("restore receipt fault"),
            ),
            mock.patch(
                "grabowski_blockade_store._unlink_same_inode",
                side_effect=fail_second_unlink,
            ),
        ):
            with self.assertRaisesRegex(
                BlockadeRollbackError, "rollback could not be verified"
            ):
                restore_disarmed_marker(
                    disarmed.transaction_id,
                    self.marker,
                    self.quarantine,
                    expected_marker_path=self.marker,
                    expected_quarantine_root=self.quarantine,
                    expected_record_sha256=disarmed.record_sha256,
                    expected_marker_file_sha256=disarmed.marker_file_sha256,
                    expected_disarm_receipt_sha256=disarmed.receipt_sha256,
                )
        self.assertTrue(self.marker.exists())
        self.assertTrue(Path(disarmed.quarantine_path).exists())

    def test_transaction_identity_and_sha_inputs_are_strict(self) -> None:
        with self.assertRaises(ValueError):
            engage_blockade_marker(
                self.item,
                self.marker,
                expected_marker_path=self.marker,
                transaction_id="bad/id",
            )
        self.engage()
        disarmed = self.disarm()
        with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
            restore_disarmed_marker(
                disarmed.transaction_id,
                self.marker,
                self.quarantine,
                expected_marker_path=self.marker,
                expected_quarantine_root=self.quarantine,
                expected_record_sha256="INVALID",
                expected_marker_file_sha256=disarmed.marker_file_sha256,
                expected_disarm_receipt_sha256=disarmed.receipt_sha256,
            )

    def test_numeric_limits_are_strict_before_filesystem_mutation(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            engage_blockade_marker(
                self.item,
                self.marker,
                expected_marker_path=self.marker,
                max_bytes=0,
            )
        with self.assertRaisesRegex(ValueError, "expected_uid"):
            engage_blockade_marker(
                self.item,
                self.marker,
                expected_marker_path=self.marker,
                expected_uid=-1,
            )
        self.assertFalse(self.marker.exists())

        self.engage()
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            read_blockade_marker(
                self.marker,
                expected_marker_path=self.marker,
                max_bytes=False,
            )
        self.assertTrue(self.marker.is_file())

    def test_production_path_is_never_touched_by_isolated_proof(self) -> None:
        production = Path("/home/alex/.local/state/grabowski/operator-kill-switch")
        before_exists = production.exists()
        before_bytes = production.read_bytes() if before_exists else None

        self.engage()
        disarmed = self.disarm()
        restore_disarmed_marker(
            disarmed.transaction_id,
            self.marker,
            self.quarantine,
            expected_marker_path=self.marker,
            expected_quarantine_root=self.quarantine,
            expected_record_sha256=disarmed.record_sha256,
            expected_marker_file_sha256=disarmed.marker_file_sha256,
            expected_disarm_receipt_sha256=disarmed.receipt_sha256,
        )

        self.assertEqual(production.exists(), before_exists)
        if before_exists:
            self.assertEqual(production.read_bytes(), before_bytes)


if __name__ == "__main__":
    unittest.main()
