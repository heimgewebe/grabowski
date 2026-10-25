from __future__ import annotations

import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch

from test_recovery import recovery


class StagedFundusRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.legacy = str(recovery.operator.HOME / ".local/share/schauwerk/fundus")
        self.staged = str(
            recovery.operator.HOME
            / ".local/state/heim-pc-priorities/.fundus-restic-source"
        )
        self.base_paths = [
            str(recovery.operator.HOME / "repos"),
            str(recovery.operator.HOME / "artifacts/merges"),
            str(
                recovery.operator.HOME
                / ".local/state/heim-pc-priorities/backup-sentinel.txt"
            ),
        ]
        self.snapshot_id = "a" * 64

    def parse(self, paths: list[str]) -> dict[str, object]:
        row = {
            "id": self.snapshot_id,
            "hostname": "heim-pc",
            "tags": ["daily", "heim-pc-daily-fixture"],
            "paths": paths,
            "time": "2026-10-20T16:00:00+02:00",
        }
        with patch.object(
            recovery, "_run_logged", return_value=types.SimpleNamespace(
                stdout=json.dumps([row])
            )
        ):
            return recovery._local_recovery_snapshot_metadata(
                snapshot_id=self.snapshot_id,
                restic_env={},
                log_path=Path("/tmp/mock-recovery.log"),
            )

    def test_private_stage_snapshot_is_accepted_and_binds_its_exact_path(self) -> None:
        result = self.parse(self.base_paths + [self.staged])
        self.assertEqual(result["fundus_source_path"], self.staged)
        self.assertEqual(result["snapshot_id"], self.snapshot_id)

    def test_legacy_direct_fundus_snapshot_remains_accepted(self) -> None:
        result = self.parse(self.base_paths + [self.legacy])
        self.assertEqual(result["fundus_source_path"], self.legacy)

    def test_ambiguous_unknown_and_missing_sources_fail_closed(self) -> None:
        for paths in (
            self.base_paths,
            self.base_paths + [str(recovery.operator.HOME / "other")],
            self.base_paths + [self.legacy, self.staged],
            self.base_paths[:-1] + [self.staged],
        ):
            with self.subTest(paths=paths):
                with self.assertRaisesRegex(
                    RuntimeError, "local recovery snapshot source contract mismatch"
                ):
                    self.parse(paths)

    def test_staged_restore_uses_archive_path_and_verifies_fundus_inventory(self) -> None:
        original = b"restored-through-private-stage\n"
        inventory = {
            "schema_version": "schauwerk-fundus-inventory.v1",
            "files": [
                {
                    "path": "receipts/proof.txt",
                    "bytes": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                }
            ],
        }
        digest = hashlib.sha256(
            json.dumps(
                inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        durability = {
            "inventory_sha256": digest,
            "file_count": 1,
            "total_bytes": len(original),
        }

        def fake_restore(argv: list[str], **_kwargs: object) -> types.SimpleNamespace:
            self.assertEqual(argv[argv.index("--include") + 1], self.staged)
            self.assertIn("--verify", argv)
            target = Path(argv[argv.index("--target") + 1])
            file = target / self.staged.lstrip("/") / "receipts/proof.txt"
            file.parent.mkdir(parents=True)
            file.write_bytes(original)
            return types.SimpleNamespace(stdout="", stderr="", returncode=0)

        with patch.object(recovery, "_run_logged", side_effect=fake_restore):
            result = recovery._local_recovery_restore_probe(
                snapshot_id=self.snapshot_id,
                restic_env={},
                durability=durability,
                log_path=Path("/tmp/mock-recovery.log"),
                snapshot_fundus_source=self.staged,
            )
        self.assertEqual(result["inventory_sha256"], digest)
        self.assertEqual(result["file_count"], 1)

    def test_missing_empty_and_arbitrary_sources_are_rejected_before_restic(self) -> None:
        for invalid in (None, "", "/home/alex/secret-data", [], {}):
            with self.subTest(source=repr(invalid)), patch.object(recovery, "_run_logged") as run:
                with self.assertRaisesRegex(RuntimeError, "Fundus source is unsafe"):
                    recovery._local_recovery_restore_probe(
                        snapshot_id=self.snapshot_id,
                        restic_env={},
                        durability={},
                        log_path=Path("/tmp/mock-recovery.log"),
                        snapshot_fundus_source=invalid,
                    )
                run.assert_not_called()

    def test_full_probe_threads_validated_staged_source_to_restore(self) -> None:
        import tempfile

        snapshot = {
            "snapshot_id": self.snapshot_id,
            "hostname": "heim-pc",
            "tags": ["daily"],
            "paths": self.base_paths + [self.staged],
            "fundus_source_path": self.staged,
            "time": "1970-01-01T00:03:00+00:00",
            "time_unix": 180,
        }
        durability = {
            "snapshot_id": self.snapshot_id,
            "verified_at_unix": 190,
            "receipt_digest": "b" * 64,
            "inventory_sha256": "c" * 64,
            "file_count": 1,
            "total_bytes": 4,
        }
        canonical = {
            "valid": True,
            "source_record_sha256": "d" * 64,
            "record_sha256": "e" * 64,
            "snapshot_id": self.snapshot_id[:8],
        }
        with tempfile.TemporaryDirectory() as raw, patch.object(
            recovery.time, "time", return_value=200
        ), patch.object(
            recovery.operator, "STATE_DIR", Path(raw)
        ), patch.object(
            recovery, "_local_recovery_durability_evidence", return_value=durability
        ), patch.object(
            recovery, "_local_recovery_repository",
            return_value=(Path("/mnt/backup/restic/heim-pc"), {}, "/dev/sda1"),
        ), patch.object(
            recovery, "_local_recovery_snapshot_metadata", return_value=snapshot
        ), patch.object(
            recovery, "_local_recovery_restore_probe",
            return_value={"inventory_sha256": "c" * 64, "file_count": 1, "total_bytes": 4},
        ) as restore, patch.object(
            recovery, "_run_logged",
            return_value=types.SimpleNamespace(stdout="", stderr="", returncode=0),
        ), patch.object(
            recovery, "_write_server_marker",
            return_value={"source_record_sha256": "d" * 64, "generated_at_unix": 200},
        ), patch.object(
            recovery.privileged, "publish_recovery_marker_reference",
            return_value={"success": True},
        ), patch.object(
            recovery, "_server_source_marker", return_value={"valid": True}
        ), patch.object(
            recovery, "_canonical_server_marker", return_value=canonical
        ), patch.object(recovery.base, "_append_audit"):
            result = recovery._local_recovery_probe_locked(
                {
                    "kind": "local_backup_disk",
                    "backup_uuid": "249180DA265E8DE0",
                    "repository_name": "heim-pc",
                }
            )
        self.assertTrue(result["repository_check_valid"])
        self.assertEqual(
            restore.call_args.kwargs["snapshot_fundus_source"], self.staged
        )


class NativeResticTimerScopeTests(unittest.TestCase):
    def test_system_timer_uses_system_manager(self) -> None:
        with patch.object(recovery, "BACKUP_TIMER_SCOPE", "system"), patch.object(
            recovery, "BACKUP_TIMER", "restic-backups-heim-pc.timer"
        ), patch.object(
            recovery.operator, "_run", return_value={"returncode": 0}
        ) as run:
            result = recovery._timer_probe("is-enabled")

        self.assertTrue(result["ok"])
        run.assert_called_once_with(
            ["systemctl", "is-enabled", "restic-backups-heim-pc.timer"],
            cwd=recovery.operator.HOME,
            timeout_seconds=30,
            max_output_bytes=recovery.operator.DEFAULT_OUTPUT_BYTES,
        )

    def test_legacy_timer_stays_on_user_manager(self) -> None:
        with patch.object(recovery, "BACKUP_TIMER_SCOPE", "user"), patch.object(
            recovery, "BACKUP_TIMER", "restic-backup-1930.timer"
        ), patch.object(
            recovery.operator, "_run", return_value={"returncode": 0}
        ) as run:
            result = recovery._timer_probe("is-active")

        self.assertTrue(result["ok"])
        self.assertEqual(
            run.call_args.args[0],
            ["systemctl", "--user", "is-active", "restic-backup-1930.timer"],
        )

    def test_invalid_scope_fails_closed_without_command(self) -> None:
        with patch.object(recovery, "BACKUP_TIMER_SCOPE", "nonsense"), patch.object(
            recovery.operator, "_run"
        ) as run:
            result = recovery._timer_probe("is-active")
        self.assertFalse(result["ok"])
        run.assert_not_called()

if __name__ == "__main__":
    unittest.main()