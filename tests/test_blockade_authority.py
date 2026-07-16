from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_blockade_authority as authority  # noqa: E402
from grabowski_blockades import (  # noqa: E402
    BlockadeRecord,
    Provenance,
    Scope,
    canonical_json,
)
from grabowski_blockade_store import (  # noqa: E402
    engage_blockade_marker,
    read_blockade_marker,
)


class BlockadeAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.authority_root = self.root / "authority"
        self.marker = self.authority_root / "operator-kill-switch"
        self.quarantine = self.authority_root / "quarantine"
        self.legacy_root = self.root / "legacy"
        self.legacy_root.mkdir(mode=0o700)
        self.legacy = self.legacy_root / "operator-kill-switch"
        self.uid = os.getuid()
        self.candidate = {
            "enabled": True,
            "mode": "blockade-marker-lifecycle",
            "marker_path": str(self.marker),
            "legacy_marker_path": str(self.legacy),
            "quarantine_root": str(self.quarantine),
            "authority_uid": self.uid,
            "legacy_uid": self.uid,
            "allowed_peer_unit": "grabowski-operator.service",
            "allowed_peer_uid": self.uid,
            "recovery_gate": {"fixture": True},
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def recovery_gate(_value) -> dict[str, object]:
        return {
            "recovery_marker_sha256": "a" * 64,
            "recovery_marker_source_sha256": "b" * 64,
            "recovery_marker_timestamp_unix": 1,
        }

    @staticmethod
    def record(blockade_id: str = "authority-test-1") -> BlockadeRecord:
        return BlockadeRecord(
            blockade_id=blockade_id,
            posture="hard_stop",
            scope=Scope("global", "*"),
            reason="Root authority lifecycle test.",
            trigger_class="audit_provenance_unknown",
            engaged_at=datetime.now(timezone.utc),
            evidence_refs=("test:blockade-authority",),
            provenance=Provenance(
                tool="test_blockade_authority",
                request_id="request-1",
                session_id="session-1",
                task_id="task-1",
                owner_id="owner-1",
            ),
        )

    def resolve(self, payload: dict[str, object]) -> dict[str, object]:
        return authority.resolve_lifecycle(
            self.candidate,
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            recovery_gate_validator=self.recovery_gate,
        )

    @staticmethod
    def hashes(record: BlockadeRecord) -> tuple[str, str]:
        payload = canonical_json(record.to_mapping())
        return record.sha256, hashlib.sha256(payload).hexdigest()

    def engage(self, *, transaction_id: str = "tx-engage"):
        record = self.record()
        record_sha256, file_sha256 = self.hashes(record)
        execution = self.resolve(
            {
                "operation": "engage",
                "record": record.to_mapping(),
                "record_sha256": record_sha256,
                "marker_file_sha256": file_sha256,
                "transaction_id": transaction_id,
            }
        )
        result = authority.execute_lifecycle(execution)
        return record, record_sha256, file_sha256, result

    def test_engage_observe_and_exact_rollback(self) -> None:
        record, record_sha256, file_sha256, result = self.engage()

        metadata = self.marker.stat()
        self.assertEqual(metadata.st_uid, self.uid)
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.authority_root.stat().st_mode), 0o711)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(result["receipt"]["record_sha256"], record_sha256)

        observed = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "observe",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "transaction_id": "tx-observe",
                }
            )
        )
        self.assertEqual(observed["state"], "engaged")
        self.assertEqual(observed["record"], record.to_mapping())

        rolled_back = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "rollback-engage",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "transaction_id": "tx-engage",
                }
            )
        )
        self.assertEqual(rolled_back["operation"], "rollback-engage")
        self.assertFalse(self.marker.exists())

    def test_disarm_observe_and_exact_restore(self) -> None:
        _record, record_sha256, file_sha256, _result = self.engage()
        disarmed = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "disarm",
                    "blockade_id": "authority-test-1",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "transaction_id": "tx-disarm",
                }
            )
        )
        self.assertFalse(self.marker.exists())
        self.assertEqual(stat.S_IMODE(self.quarantine.stat().st_mode), 0o700)

        observed = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "observe",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "transaction_id": "tx-disarm",
                }
            )
        )
        self.assertEqual(observed["state"], "disarmed")
        self.assertEqual(
            observed["receipt_sha256"], disarmed["receipt_sha256"]
        )

        restored = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "restore-disarm",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "expected_disarm_receipt_sha256": disarmed[
                        "receipt_sha256"
                    ],
                    "transaction_id": "tx-disarm",
                }
            )
        )
        self.assertEqual(restored["operation"], "restore-disarm")
        snapshot = authority.read_authority_marker(
            self.marker, authority_uid=self.uid
        )
        self.assertEqual(snapshot.record_sha256, record_sha256)
        self.assertEqual(snapshot.file_sha256, file_sha256)

    def test_root_legacy_migration_publishes_canonical_and_preserves_legacy(self) -> None:
        record = self.record("authority-migration-1")
        legacy_receipt = engage_blockade_marker(
            record,
            self.legacy,
            expected_marker_path=self.legacy,
            transaction_id="legacy-engage",
        )
        migrated = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "migrate",
                    "expected_record_sha256": legacy_receipt.record_sha256,
                    "expected_marker_file_sha256": legacy_receipt.marker_file_sha256,
                    "transaction_id": "tx-migrate",
                }
            )
        )
        self.assertEqual(migrated["operation"], "migrate")
        self.assertTrue(migrated["legacy_preserved"])
        self.assertTrue(self.legacy.exists())
        legacy_snapshot = read_blockade_marker(
            self.legacy,
            expected_marker_path=self.legacy,
        )
        self.assertEqual(legacy_snapshot.record, record)
        snapshot = authority.read_authority_marker(
            self.marker, authority_uid=self.uid
        )
        self.assertEqual(snapshot.record, record)
        self.assertEqual(stat.S_IMODE(self.marker.stat().st_mode), 0o644)

    def test_resolver_rejects_caller_supplied_paths_and_hash_drift(self) -> None:
        record = self.record()
        record_sha256, file_sha256 = self.hashes(record)
        with self.assertRaisesRegex(ValueError, "keys are invalid"):
            self.resolve(
                {
                    "operation": "engage",
                    "record": record.to_mapping(),
                    "record_sha256": record_sha256,
                    "marker_file_sha256": file_sha256,
                    "transaction_id": "tx-engage",
                    "marker_path": "/tmp/attacker-selected",
                }
            )
        with self.assertRaisesRegex(PermissionError, "hashes do not match"):
            self.resolve(
                {
                    "operation": "engage",
                    "record": record.to_mapping(),
                    "record_sha256": "0" * 64,
                    "marker_file_sha256": file_sha256,
                    "transaction_id": "tx-engage",
                }
            )

    def test_existing_writable_authority_directory_is_rejected(self) -> None:
        self.authority_root.mkdir(mode=0o700)
        self.authority_root.chmod(0o777)
        record = self.record()
        record_sha256, file_sha256 = self.hashes(record)
        with self.assertRaisesRegex(PermissionError, "ownership or mode"):
            authority.execute_lifecycle(
                self.resolve(
                    {
                        "operation": "engage",
                        "record": record.to_mapping(),
                        "record_sha256": record_sha256,
                        "marker_file_sha256": file_sha256,
                        "transaction_id": "tx-engage",
                    }
                )
            )

    def test_symlink_authority_directory_and_hardlinked_marker_fail_closed(self) -> None:
        real = self.root / "real-authority"
        real.mkdir(mode=0o711)
        self.authority_root.symlink_to(real, target_is_directory=True)
        record = self.record()
        record_sha256, file_sha256 = self.hashes(record)
        with self.assertRaises(OSError):
            authority.execute_lifecycle(
                self.resolve(
                    {
                        "operation": "engage",
                        "record": record.to_mapping(),
                        "record_sha256": record_sha256,
                        "marker_file_sha256": file_sha256,
                        "transaction_id": "tx-engage",
                    }
                )
            )

        self.authority_root.unlink()
        _record, _record_sha256, _file_sha256, _result = self.engage()
        alias = self.authority_root / "marker-alias"
        os.link(self.marker, alias)
        with self.assertRaisesRegex(PermissionError, "single-link"):
            authority.read_authority_marker(
                self.marker, authority_uid=self.uid
            )

    def test_observe_absent_without_receipt_is_explicitly_unproven(self) -> None:
        record = self.record()
        record_sha256, file_sha256 = self.hashes(record)
        observed = authority.execute_lifecycle(
            self.resolve(
                {
                    "operation": "observe",
                    "expected_record_sha256": record_sha256,
                    "expected_marker_file_sha256": file_sha256,
                    "transaction_id": "unknown-transaction",
                }
            )
        )
        self.assertEqual(observed["state"], "absent_unproven")


if __name__ == "__main__":
    unittest.main()
