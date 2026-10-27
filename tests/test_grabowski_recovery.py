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

    def test_restored_stat_numeric_mode_is_locale_independent(self) -> None:
        import stat

        regular = format(stat.S_IFREG | 0o600, "x")
        symlink = format(stat.S_IFLNK | 0o777, "x")
        directory = format(stat.S_IFDIR | 0o700, "x")
        self.assertTrue(recovery._nixos_restored_regular_file_stat(
            f"{regular} 879\n", expected_size=879
        ))
        for output in (
            f"{symlink} 879",
            f"{directory} 879",
            f"{regular} 878",
            "regular file 879",
            "fichier régulier 879",
            "0 879",
            f"{regular} garbage",
            f"{regular} 879 extra",
            "",
        ):
            with self.subTest(output=output):
                self.assertFalse(recovery._nixos_restored_regular_file_stat(
                    output, expected_size=879
                ))

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

    def _root_proof(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "heim_pc.nixos_restic_recovery_root_proof",
            "started_at_unix": self.now - 3,
            "completed_at_unix": self.now - 1,
            "snapshot_id": "c" * 64,
            "snapshot_time_unix": self.now - 60,
            "repository_id": recovery.LOCAL_RECOVERY_REPOSITORY_ID,
            "backup_uuid": self.target["backup_uuid"],
            "backup_source": "/dev/sda1",
            "restore_sha256": "d" * 64,
            "restore_probe_valid": True,
            "repository_check_valid": True,
        }

    def test_root_owned_proof_payload_rejects_stale_or_invalid_sources(self) -> None:
        proof = self._root_proof()
        self.assertEqual(
            recovery._validated_nixos_root_proof(
                proof, not_before_unix=self.now - 5, now=self.now,
                expected_backup_uuid=self.target["backup_uuid"]
            ), proof,
        )
        cases = (
            dict(proof, backup_uuid="wrong"),
            dict(proof, repository_id="a" * 64),
            dict(proof, restore_sha256="invalid"),
            dict(proof, snapshot_id="not-a-real-snapshot"),
            dict(proof, restore_probe_valid=False),
            dict(proof, repository_check_valid=False),
            dict(proof, started_at_unix=self.now - 120),
            dict(proof, completed_at_unix=self.now - 200),
            dict(proof, snapshot_time_unix=self.now - recovery.MAX_AGE_SECONDS - 1),
            dict(proof, backup_source="/home/alex/unsafe"),
            dict(proof, backup_source="/dev/../tmp/unsafe"),
            {**proof, "unexpected": True},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(RuntimeError):
                    recovery._validated_nixos_root_proof(
                        case, not_before_unix=self.now - 5, now=self.now,
                        expected_backup_uuid=self.target["backup_uuid"],
                    )

    def test_root_proof_read_validates_root_owner_and_descriptor(self) -> None:
        import os
        import stat
        import tempfile
        real_lstat, real_fstat = Path.lstat, os.fstat
        proof_payload = self._root_proof()
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            proof = parent / "proof.json"
            proof.write_text(json.dumps(proof_payload), encoding="utf-8")

            def trusted_lstat(path):
                original = real_lstat(path)
                if path == parent:
                    return types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                return original

            def trusted_fstat(fd):
                original = real_fstat(fd)
                return types.SimpleNamespace(
                    st_mode=original.st_mode, st_uid=0, st_nlink=original.st_nlink,
                    st_size=original.st_size,
                )

            with patch.object(recovery, "NIXOS_RESTIC_ROOT_PROOF_PATH", proof), patch.object(
                recovery.Path, "lstat", new=trusted_lstat
            ), patch.object(recovery.os, "fstat", side_effect=trusted_fstat):
                self.assertEqual(
                    recovery._nixos_root_proof_read(
                        not_before_unix=self.now - 5,
                        now=self.now,
                        expected_backup_uuid=self.target["backup_uuid"],
                    ),
                    proof_payload,
                )

    def test_root_proof_read_rejects_owner_modes_symlinks_and_size(self) -> None:
        import os
        import stat
        import tempfile
        real_lstat, real_fstat = Path.lstat, os.fstat
        scenarios = (
            "file_symlink", "parent_symlink", "parent_nonroot",
            "parent_writable", "file_nonroot", "file_writable",
            "hardlink", "oversize", "malformed_json", "missing",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                proof = parent / "proof.json"
                proof.write_text(json.dumps(self._root_proof()), encoding="utf-8")
                if scenario == "file_symlink":
                    target = parent / "target.json"
                    proof.rename(target)
                    proof.symlink_to(target)
                elif scenario == "hardlink":
                    os.link(proof, parent / "second.json")
                elif scenario == "oversize":
                    proof.write_text(" " * 8193, encoding="utf-8")
                elif scenario == "malformed_json":
                    proof.write_text("{malformed", encoding="utf-8")
                elif scenario == "missing":
                    proof.unlink()

                def synthetic_lstat(path):
                    original = real_lstat(path)
                    if path != parent:
                        return original
                    mode = (
                        stat.S_IFLNK | 0o777 if scenario == "parent_symlink"
                        else stat.S_IFDIR | (0o777 if scenario == "parent_writable" else 0o755)
                    )
                    return types.SimpleNamespace(
                        st_mode=mode, st_uid=1000 if scenario == "parent_nonroot" else 0,
                    )

                def synthetic_fstat(fd):
                    original = real_fstat(fd)
                    return types.SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o666 if scenario == "file_writable" else original.st_mode,
                        st_uid=1000 if scenario == "file_nonroot" else 0,
                        st_nlink=original.st_nlink,
                        st_size=original.st_size,
                    )

                with patch.object(recovery, "NIXOS_RESTIC_ROOT_PROOF_PATH", proof), patch.object(
                    recovery.Path, "lstat", new=synthetic_lstat
                ), patch.object(recovery.os, "fstat", side_effect=synthetic_fstat):
                    with self.assertRaises(RuntimeError):
                        recovery._nixos_root_proof_read(
                            not_before_unix=self.now - 5,
                            now=self.now,
                            expected_backup_uuid=self.target["backup_uuid"],
                        )

    def test_root_proof_failure_never_publishes_canonical_marker(self) -> None:
        import tempfile
        for scenario in ("unit_failure", "missing_proof", "invalid_proof"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                fake_run = (
                    RuntimeError("NixOS recovery unit failed")
                    if scenario == "unit_failure"
                    else types.SimpleNamespace(returncode=0, stdout="")
                )
                with patch.object(
                    recovery.operator, "STATE_DIR", Path(tmp)
                ), patch.object(
                    recovery, "_run_logged",
                    side_effect=fake_run if isinstance(fake_run, Exception) else None,
                    return_value=None if isinstance(fake_run, Exception) else fake_run,
                ), patch.object(
                    recovery, "_nixos_root_proof_read",
                    side_effect=RuntimeError(scenario)
                ), patch.object(
                    recovery, "_write_server_marker"
                ) as marker, patch.object(
                    recovery.privileged, "publish_recovery_marker_reference"
                ) as publish:
                    with self.assertRaises(RuntimeError):
                        recovery._nixos_local_recovery_probe_locked(self.target)
                    marker.assert_not_called()
                    publish.assert_not_called()

    def test_nixos_native_probe_invokes_only_fixed_root_unit_and_uses_root_receipt(self) -> None:
        import tempfile
        proof = self._root_proof()
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            recovery.operator, "STATE_DIR", Path(tmp)
        ), patch.object(
            recovery.time, "time", return_value=self.now
        ), patch.object(
            recovery, "_run_logged",
            return_value=types.SimpleNamespace(returncode=0, stdout="")
        ) as run, patch.object(
            recovery, "_nixos_root_proof_read", return_value=proof
        ) as read_proof, patch.object(
            recovery, "_timer_probe", return_value={"ok": True}
        ), patch.object(
            recovery, "_write_server_marker",
            return_value={"source_record_sha256": digest}
        ) as marker, patch.object(
            recovery.privileged, "publish_recovery_marker_reference",
            return_value={"success": True}
        ) as publish, patch.object(
            recovery, "_canonical_server_marker",
            return_value={
                "valid": True, "source_record_sha256": digest,
                "record_sha256": "b" * 64,
            }
        ), patch.object(
            recovery, "_server_source_marker", return_value={"valid": True}
        ), patch.object(recovery.base, "_append_audit"):
            result = recovery._nixos_local_recovery_probe_locked(self.target)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], [
            "/run/current-system/sw/bin/systemctl", "--system", "start",
            "heim-pc-restic-recovery-probe.service",
        ])
        self.assertEqual(run.call_args.kwargs["timeout_seconds"], 4800)
        read_proof.assert_called_once()
        marker.assert_called_once_with(
            completed_at_unix=self.now,
            snapshot_id="c" * 8,
            snapshot_time_unix=self.now - 60,
        )
        publish.assert_called_once_with(
            source_record_sha256=digest,
            generated_at_unix=self.now,
        )
        self.assertEqual(result["restore_sha256"], "d" * 64)
        self.assertTrue(result["root_proof"]["validated"])

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

    def test_nixos_native_backup_completion_requires_actual_fresh_systemd_exit(self) -> None:
        reference_monotonic = 100000
        fresh_completion = reference_monotonic * 1000000 - 30000000
        def output(completion=fresh_completion, **overrides):
            fields = {
                "LoadState": "loaded", "ActiveState": "inactive",
                "Result": "success", "ExecMainCode": "1",
                "ExecMainStatus": "0",
                "ExecMainExitTimestampMonotonic": str(completion),
                "ExecMainExitTimestamp": f"@{self.now - 30}",
            }
            fields.update(overrides)
            return "\n".join(f"{key}={value}" for key, value in fields.items()) + "\n"

        for label, payload, returncode, expected in (
            ("valid", output(), 0, True),
            ("valid_fractional", output(ExecMainExitTimestamp=f"@{self.now - 30}.123456"), 0, True),
            # CLOCK_MONOTONIC counts just 30 seconds awake even after 48h
            # suspended; systemd's epoch second value must still expire.
            ("suspend_48h", output(ExecMainExitTimestamp=f"@{self.now - 48 * 3600}"), 0, False),
            ("stale_realtime", output(ExecMainExitTimestamp=f"@{self.now - recovery.MAX_AGE_SECONDS - 1}"), 0, False),
            ("future_realtime", output(ExecMainExitTimestamp=f"@{self.now + 10}"), 0, False),
            ("localized_date", output(ExecMainExitTimestamp="Mon 2026-10-26 19:31:02 CET"), 0, False),
            ("missing_realtime", output().replace(f"ExecMainExitTimestamp=@{self.now - 30}\n", ""), 0, False),
            ("invalid_fraction", output(ExecMainExitTimestamp=f"@{self.now - 30}.a"), 0, False),
            ("never_run", output(completion=0), 0, False),
            ("failed_backup", output(Result="exit-code"), 0, False),
            ("unit_not_loaded", output(LoadState="not-found"), 0, False),
            ("still_running", output(ActiveState="activating"), 0, False),
            ("not_exited", output(ExecMainCode="0"), 0, False),
            ("exit_failure", output(ExecMainStatus="1"), 0, False),
            ("stale", output(completion=(reference_monotonic - recovery.MAX_AGE_SECONDS - 1) * 1000000), 0, False),
            ("future", output(completion=(reference_monotonic + 5) * 1000000), 0, False),
            ("invalid_timestamp", output(completion="not-a-timestamp"), 0, False),
            ("duplicate_field", output() + "Result=success\n", 0, False),
            ("missing_field", output().replace("ExecMainCode=1\n", ""), 0, False),
            ("systemctl_error", "", 1, False),
        ):
            with self.subTest(case=label), patch.object(
                recovery.operator, "_run",
                return_value={"returncode": returncode, "stdout": payload},
            ) as run, patch.object(
                recovery.time, "monotonic", return_value=reference_monotonic
            ), patch.object(recovery.time, "time", return_value=self.now):
                state = recovery._nixos_native_backup_service_fresh()
            self.assertEqual(state["valid"], expected)
            self.assertEqual(
                run.call_args.args[0][:5],
                ["/run/current-system/sw/bin/systemctl", "--system",
                 "--timestamp=unix", "show", "restic-backups-heim-pc.service"],
            )
            if expected:
                self.assertEqual(state["timestamp_unix"], self.now - 30)
                self.assertEqual(state["age_seconds"], 30)
                self.assertIsNone(state["error"])
            else:
                self.assertIsNotNone(state["error"])

    def test_nixos_remote_target_keeps_independent_local_backup_freshness(self) -> None:
        remote_target = "wg-prod-1:rest-server/grabowski-recovery-probe"
        remote_info = {
            "valid": True, "kind": "rest_server", "host": "wg-prod-1",
            "probe": "grabowski-recovery-probe",
        }
        source = {
            "valid": True, "exists": True, "target": remote_target,
            "snapshot_time_unix": None, "snapshot_age_seconds": None,
            "snapshot_fresh": False, "source_record_sha256": "a" * 64,
        }
        for locally_fresh in (True, False):
            with self.subTest(locally_fresh=locally_fresh), patch.object(
                recovery, "_NIXOS_RESTIC_TIMER_PRESENT", True
            ), patch.object(
                recovery, "SERVER_RECOVERY_TARGET", remote_target
            ), patch.object(
                recovery, "_configured_recovery_target_info", return_value=remote_info
            ), patch.object(
                recovery.base, "_verify_audit_log", return_value={"valid": True}
            ), patch.object(
                recovery.base, "_deployment_metadata", return_value={"provenance_valid": True}
            ), patch.object(
                recovery, "_canonical_server_marker",
                return_value={"valid": True, "target": remote_target, "freshness_reason": "ready"},
            ), patch.object(
                recovery, "_server_source_marker", return_value=source
            ), patch.object(
                recovery, "_source_publication_state",
                return_value={"current": True, "reason": "ready"}
            ), patch.object(
                recovery, "_server_recovery_evidence_fresh", return_value=True
            ), patch.object(
                recovery, "_server_recovery_evidence_boundary", return_value={}
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
                recovery, "_nixos_native_backup_service_fresh",
                return_value={
                    "path": "systemd:restic-backups-heim-pc.service", "exists": True,
                    "valid": locally_fresh, "timestamp_unix": self.now - 60,
                    "age_seconds": 60, "source": "nixos-system-restic-backup-completion",
                    "error": None if locally_fresh else "native backup is stale",
                }
            ) as native_service, patch.object(recovery, "_fresh_text_marker") as legacy_marker:
                status = recovery.recovery_status()
            native_service.assert_called_once_with()
            legacy_marker.assert_not_called()
            self.assertEqual(status["checks"]["local_backup_fresh"], locally_fresh)
            self.assertEqual(status["ready_for_user_power_worker"], locally_fresh)
            self.assertEqual(status["ready_for_privileged_actions"], locally_fresh)
            self.assertEqual(status["local_backup"]["path"], "systemd:restic-backups-heim-pc.service")

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
