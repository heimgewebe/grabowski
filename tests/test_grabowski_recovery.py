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


class NativeNixOSResticProofTests(unittest.TestCase):
    def setUp(self) -> None:
        import time
        from datetime import datetime, timezone
        self.now = int(time.time())
        self.snapshot = {
            "id": "c" * 64, "hostname": "heim-pc-nixos",
            "tags": ["nixos-seagate"], "paths": ["/etc", str(recovery.operator.HOME), "/persist"],
            "time": datetime.fromtimestamp(self.now - 60, timezone.utc).isoformat(),
        }
        self.target = {
            "kind": "local_backup_disk",
            "backup_uuid": "9b626294-7913-4be0-88fa-96b314e96ee5",
            "repository_name": "heim-pc",
        }

    def test_accepts_fresh_complete_nixos_snapshot(self) -> None:
        result = recovery._nixos_restic_snapshot([self.snapshot], now=self.now)
        self.assertEqual(result["id"], "c" * 64)

    def test_ignores_smoke_and_prefers_latest_full_snapshot(self) -> None:
        from datetime import datetime, timezone
        smoke = dict(self.snapshot, id="d" * 64, paths=["/etc"])
        older = dict(
            self.snapshot, id="e" * 64,
            time=datetime.fromtimestamp(self.now - 600, timezone.utc).isoformat(),
        )
        result = recovery._nixos_restic_snapshot(
            [smoke, older, self.snapshot], now=self.now
        )
        self.assertEqual(result["id"], self.snapshot["id"])

    def test_missing_tag_wrong_host_missing_path_and_staleness_rejected(self) -> None:
        from datetime import datetime, timezone
        cases = (
            dict(self.snapshot, hostname="heim-pc"),
            dict(self.snapshot, tags=["daily"]),
            dict(self.snapshot, paths=["/etc", str(recovery.operator.HOME)]),
            dict(self.snapshot, id="not-a-snapshot"),
            dict(
                self.snapshot,
                time=datetime.fromtimestamp(
                    self.now - recovery.MAX_AGE_SECONDS - 5, timezone.utc
                ).isoformat(),
            ),
        )
        for row in cases:
            with self.subTest(row=row):
                with self.assertRaisesRegex(RuntimeError, "fresh complete"):
                    recovery._nixos_restic_snapshot([row], now=self.now)

    def test_backend_dispatch_keeps_legacy_probe(self) -> None:
        from contextlib import nullcontext
        with patch.object(recovery, "_local_recovery_repository_operation_lock",
                          return_value=nullcontext()), patch.object(
            recovery, "_local_recovery_probe_locked", return_value={"mode": "legacy"}
        ) as legacy, patch.object(
            recovery, "_nixos_local_recovery_probe_locked",
            return_value={"mode": "nixos"}
        ) as native:
            with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", False):
                self.assertEqual(recovery._local_recovery_probe(self.target)["mode"], "legacy")
            with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True):
                self.assertEqual(recovery._local_recovery_probe(self.target)["mode"], "nixos")
            legacy.assert_called_once()
            native.assert_called_once()

    def test_missing_medium_wrong_uuid_repo_id_and_failed_restore_never_publish(self) -> None:
        import tempfile
        real_is_dir = Path.is_dir
        repository = "/var/lib/heim-pc-backup/restic/heim-pc"
        for scenario in ("missing_medium", "wrong_uuid", "wrong_repo", "restore_failure"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                def is_dir(path: Path) -> bool:
                    if str(path) == repository:
                        return scenario != "missing_medium"
                    return real_is_dir(path)

                def fake_run(argv: list[str], **_kwargs: object) -> types.SimpleNamespace:
                    command = " ".join(argv)
                    if "/findmnt " in command:
                        output = "/var/lib/heim-pc-backup /dev/sda1 ext4\n"
                    elif "/lsblk " in command:
                        output = (
                            "wrong-uuid\n" if scenario == "wrong_uuid"
                            else self.target["backup_uuid"] + "\n"
                        )
                    elif " cat config" in command:
                        value = (
                            "0" * 64 if scenario == "wrong_repo"
                            else recovery.LOCAL_RECOVERY_REPOSITORY_ID
                        )
                        output = json.dumps({"id": value})
                    elif argv[0] == "systemctl":
                        output = "Result=success\nExecMainStatus=0\n"
                    elif " snapshots " in command:
                        output = json.dumps([self.snapshot])
                    elif " ls " in command:
                        output = json.dumps({
                            "message_type": "node",
                            "path": "/persist/secrets/restic/heim-pc-excludes",
                            "type": "file", "size": 879,
                        })
                    elif " restore " in command:
                        raise RuntimeError("simulated restore error")
                    elif "/rm " in command:
                        output = ""
                    else:
                        raise AssertionError("unexpected command: " + command)
                    return types.SimpleNamespace(stdout=output, returncode=0)

                with patch.object(recovery.Path, "is_dir", new=is_dir), patch.object(
                    recovery.operator, "STATE_DIR", Path(tmp)
                ), patch.object(
                    recovery, "_run_logged", side_effect=fake_run
                ), patch.object(
                    recovery, "_timer_probe", return_value={"ok": True}
                ), patch.object(
                    recovery, "_write_server_marker"
                ) as marker, patch.object(
                    recovery.privileged, "publish_recovery_marker_reference"
                ) as publish:
                    with self.assertRaises(RuntimeError):
                        recovery._nixos_local_recovery_probe_locked(self.target)
                    marker.assert_not_called()
                    publish.assert_not_called()

    def test_valid_nixos_source_replaces_only_legacy_local_marker(self) -> None:
        source = {
            "path": "/tmp/native-recovery.json", "exists": True, "valid": True,
            "timestamp_unix": self.now, "age_seconds": 0, "error": None,
            "source_record_sha256": "a" * 64, "snapshot_id": "c" * 8,
            "snapshot_time_unix": self.now - 60,
            "snapshot_age_seconds": 60, "snapshot_fresh": True,
            "target": recovery.SERVER_RECOVERY_TARGET,
        }
        with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True), patch.object(
            recovery.base, "_verify_audit_log", return_value={"valid": True}
        ), patch.object(
            recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
        ), patch.object(
            recovery, "_canonical_server_marker", return_value={"valid": True}
        ), patch.object(
            recovery, "_server_source_marker", return_value=source
        ), patch.object(
            recovery, "_source_publication_state", return_value={"current": True}
        ), patch.object(
            recovery.base, "_kill_switch_state", return_value={"engaged": False}
        ), patch.object(
            recovery, "_test_kill_switch_recovery_status", return_value={}
        ), patch.object(
            recovery, "_timer_probe", return_value={"ok": True}
        ), patch.object(
            recovery.privileged, "grabowski_privileged_broker_status",
            return_value={"ready": True}
        ), patch.object(
            recovery, "_fresh_text_marker"
        ) as legacy:
            result = recovery.recovery_status()
        self.assertTrue(result["checks"]["local_backup_fresh"])
        self.assertEqual(result["local_backup"]["source"], "verified-nixos-native-restic")
        legacy.assert_not_called()


    def test_native_lock_uses_existing_operator_state_without_legacy_directory(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True), patch.object(
                recovery.operator, "STATE_DIR", root
            ), patch.object(
                recovery, "LOCAL_RECOVERY_OPERATION_STATE", root / "absent-legacy"
            ):
                with recovery._local_recovery_repository_operation_lock():
                    self.assertFalse((root / "absent-legacy").exists())
            with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True), patch.object(
                recovery.operator, "STATE_DIR", root / "not-provisioned"
            ):
                with self.assertRaisesRegex(RuntimeError, "lock is unavailable"):
                    with recovery._local_recovery_repository_operation_lock():
                        self.fail("missing native state lock was accepted")

    def test_native_source_binds_original_snapshot_time_and_expires(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "recovery.json"
            with patch.object(recovery, "SERVER_RECOVERY", marker), patch.object(
                recovery.time, "time", return_value=self.now
            ):
                recovery._write_server_marker(
                    completed_at_unix=self.now,
                    snapshot_id="a" * 8,
                    snapshot_time_unix=self.now - 60,
                )
                payload = json.loads(marker.read_text())
                self.assertEqual(payload["snapshot_time_unix"], self.now - 60)
                recent = recovery._server_source_marker()
                self.assertTrue(recent["valid"])
                self.assertTrue(recent["snapshot_fresh"])
                self.assertEqual(recent["snapshot_age_seconds"], 60)
                payload["snapshot_time_unix"] = self.now - recovery.MAX_AGE_SECONDS - 1
                marker.write_text(json.dumps(payload), encoding="utf-8")
                marker.chmod(0o600)
                old = recovery._server_source_marker()
                self.assertFalse(old["valid"])
                self.assertFalse(old["snapshot_fresh"])
                with self.assertRaisesRegex(ValueError, "snapshot timestamp"):
                    recovery._write_server_marker(
                        completed_at_unix=self.now,
                        snapshot_id="a" * 8,
                        snapshot_time_unix=self.now - recovery.MAX_AGE_SECONDS - 1,
                    )

    def test_nixos_gate_rejects_legacy_source_without_snapshot_timestamp(self) -> None:
        now = self.now
        source = {
            "path": "/tmp/legacy-proof.json", "exists": True,
            "valid": True, "timestamp_unix": now, "age_seconds": 0,
            "snapshot_time_unix": None, "snapshot_age_seconds": None,
            "snapshot_fresh": False, "error": None, "source_record_sha256": "a" * 64,
            "snapshot_id": "c" * 8, "target": recovery.SERVER_RECOVERY_TARGET,
        }
        with patch.object(recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True), patch.object(
            recovery.base, "_verify_audit_log", return_value={"valid": True}
        ), patch.object(
            recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
        ), patch.object(
            recovery, "_canonical_server_marker", return_value={"valid": True}
        ), patch.object(
            recovery, "_server_source_marker", return_value=source
        ), patch.object(
            recovery, "_source_publication_state", return_value={"current": True}
        ), patch.object(
            recovery.base, "_kill_switch_state", return_value={"engaged": False}
        ), patch.object(
            recovery, "_test_kill_switch_recovery_status", return_value={}
        ), patch.object(
            recovery, "_timer_probe", return_value={"ok": True}
        ), patch.object(
            recovery.privileged, "grabowski_privileged_broker_status", return_value={"ready": True}
        ), patch.object(recovery, "_fresh_text_marker") as legacy:
            status = recovery.recovery_status()
        self.assertFalse(status["checks"]["local_backup_fresh"])
        self.assertFalse(status["ready_for_privileged_actions"])
        legacy.assert_not_called()


if __name__ == "__main__":
    unittest.main()