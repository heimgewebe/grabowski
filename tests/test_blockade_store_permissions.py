from __future__ import annotations

from datetime import datetime, timezone
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

import grabowski_blockade_store as store  # noqa: E402
from grabowski_blockades import BlockadeRecord, Provenance, Scope  # noqa: E402


class BlockadeStorePermissionTests(unittest.TestCase):
    def test_read_succeeds_through_execute_only_parent_without_read_permission(self) -> None:
        if not hasattr(os, "O_PATH"):
            self.skipTest("Linux O_PATH is required by the production contract")

        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "operator-blockade"
            parent.mkdir(mode=0o700)
            marker = parent / "operator-kill-switch"
            record = BlockadeRecord(
                blockade_id="execute-only-read-proof",
                posture="mutation_freeze",
                scope=Scope("task", "TASK-EXECUTE-ONLY"),
                reason="Prove exact marker reads without directory read permission.",
                trigger_class="permission_regression_test",
                engaged_at=datetime(2026, 9, 4, 11, 0, tzinfo=timezone.utc),
                evidence_refs=("test:execute-only-parent",),
                provenance=Provenance(
                    tool="test_blockade_store_permissions",
                    request_id="request-execute-only",
                    session_id="session-execute-only",
                    task_id="TASK-EXECUTE-ONLY",
                    owner_id="test-owner",
                ),
            )
            receipt = store.engage_blockade_marker(
                record,
                marker,
                expected_marker_path=marker,
                transaction_id="execute-only-engage",
            )

            parent.chmod(0o100)
            try:
                with self.assertRaises(PermissionError):
                    descriptor = os.open(parent, store._directory_flags())
                    os.close(descriptor)

                snapshot = store.read_blockade_marker(
                    marker,
                    expected_marker_path=marker,
                )

                self.assertEqual(snapshot.record, record)
                self.assertEqual(snapshot.record_sha256, receipt.record_sha256)
                self.assertEqual(snapshot.file_sha256, receipt.marker_file_sha256)
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o100)
            finally:
                parent.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
