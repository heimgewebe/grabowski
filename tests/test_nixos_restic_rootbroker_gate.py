from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_privileged_broker as broker


class FixedRootResticServiceActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.action = {
            "enabled": True, "mode": "template",
            "target_pattern": r"heim-pc-restic-recovery-probe\.service",
            "argv": list(broker.NIXOS_RESTIC_ROOT_UNIT_ARGV),
            "timeout_seconds": 2700,
            "allowed_peer_uid": 1000,
            "allowed_peer_unit": "grabowski-operator.service",
            "kill_switch_path": "/var/lib/grabowski/operator-blockade/operator-kill-switch",
            "legacy_kill_switch_path": "/home/alex/.local/state/grabowski/operator-kill-switch",
        }
        self.ref = {
            "action": broker.NIXOS_RESTIC_ROOT_UNIT_ACTION,
            "target": broker.NIXOS_RESTIC_ROOT_UNIT,
        }

    def resolve(self, candidate=None, reference=None):
        with patch.object(broker.os.path, "lexists", return_value=False):
            return broker.resolve_regular_execution(
                {"actions": {broker.NIXOS_RESTIC_ROOT_UNIT_ACTION: candidate or self.action}},
                reference or self.ref,
            )

    def test_only_single_fixed_systemd_action_and_MainPID_peer_pass(self) -> None:
        execution = self.resolve()
        self.assertEqual(execution["argv"], broker.NIXOS_RESTIC_ROOT_UNIT_ARGV)
        self.assertEqual(execution["allowed_peer_uid"], 1000)
        self.assertEqual(execution["allowed_peer_unit"], "grabowski-operator.service")
        self.assertEqual(execution["timeout_seconds"], 2700)

    def test_target_argv_peer_timeout_and_kill_switch_substitutions_fail(self) -> None:
        for modified in (
            {"argv": ["/bin/sh", "-c", "id"]},
            {"argv": ["/run/current-system/sw/bin/systemctl", "--system", "start", "sshd.service"]},
            {"argv": ["/run/current-system/sw/bin/systemctl", "--system", "stop", broker.NIXOS_RESTIC_ROOT_UNIT]},
            {"allowed_peer_uid": 0},
            {"allowed_peer_uid": True},
            {"allowed_peer_unit": "grabowski-job-evil.service"},
            {"timeout_seconds": 60},
            {"kill_switch_path": "/tmp/absent"},
            {"legacy_kill_switch_path": "/tmp/absent"},
            {"untrusted": "extra"},
        ):
            with self.subTest(modified=modified), self.assertRaises(PermissionError):
                self.resolve(candidate={**self.action, **modified})
        with self.assertRaises(PermissionError):
            self.resolve(reference={**self.ref, "target": "sshd.service"})

    def test_kill_switch_fails_closed_including_dangling_symlink(self) -> None:
        with patch.object(broker.os.path, "lexists", return_value=True):
            with self.assertRaisesRegex(PermissionError, "kill-switch"):
                broker.resolve_regular_execution(
                    {"actions": {broker.NIXOS_RESTIC_ROOT_UNIT_ACTION: self.action}},
                    self.ref,
                )


class RootOwnedResticProofBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 200000
        self.proof = {
            "schema_version": 1,
            "kind": "heim_pc.nixos_restic_recovery_root_proof",
            "started_at_unix": self.now - 30,
            "completed_at_unix": self.now - 2,
            "snapshot_id": "a" * 64,
            "snapshot_time_unix": self.now - 50,
            "repository_id": broker.NIXOS_RESTIC_REPO_ID,
            "backup_uuid": broker.NIXOS_RESTIC_UUID,
            "backup_source": "/dev/sdb1",
            "restore_sha256": "b" * 64,
            "restore_probe_valid": True,
            "repository_check_valid": True,
        }
        self.source = {
            "schema_version": 1,
            "completed_at_unix": self.now - 1,
            "snapshot_id": "a" * 8,
            "snapshot_time_unix": self.now - 50,
            "restore_probe_valid": True,
            "repository_check_valid": True,
            "target": broker.NIXOS_RESTIC_TARGET,
        }

    def evaluate(self, proof=None, source=None, now=None, expected=None) -> str:
        raw = (json.dumps(self.proof if proof is None else proof, sort_keys=True) + "\n").encode()
        parent = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch.object(broker.Path, "lstat", return_value=parent), patch.object(
            broker, "_read_safe_regular_file", return_value=(raw, object())
        ) as read:
            digest = broker._validated_nixos_root_oneshot_proof(
                self.source if source is None else source,
                now=self.now if now is None else now,
                expected_digest=expected,
            )
            read.assert_called_once_with(
                broker.NIXOS_RESTIC_ROOT_PROOF,
                label="native Restic root proof",
                require_root_owned=True,
            )
        return digest

    def test_exact_root_proof_sha_and_source_identity_are_required(self) -> None:
        root_sha = self.evaluate()
        self.assertEqual(len(root_sha), 64)
        self.assertEqual(self.evaluate(expected=root_sha), root_sha)
        with self.assertRaisesRegex(PermissionError, "changed"):
            self.evaluate(expected="0" * 64)

    def test_wrong_uuid_repository_spoofing_or_staleness_does_not_authorize(self) -> None:
        modifications = (
            {"backup_uuid": "wrong"},
            {"repository_id": "0" * 64},
            {"restore_sha256": "unsafe"},
            {"restore_probe_valid": False},
            {"repository_check_valid": False},
            {"backup_source": "/home/alex/not-device"},
            {"unexpected_argv": ["/bin/bash"]},
            {"completed_at_unix": self.now - 150},
            {"snapshot_time_unix": self.now - 86401},
        )
        for change in modifications:
            with self.subTest(change=change), self.assertRaises(PermissionError):
                self.evaluate(proof={**self.proof, **change})
        for change in (
            {"snapshot_id": "c" * 8},
            {"snapshot_time_unix": self.now - 1},
            {"completed_at_unix": self.now - 200},
            {"target": "/tmp/evil"},
        ):
            with self.subTest(source=change), self.assertRaises(PermissionError):
                self.evaluate(source={**self.source, **change})
        with self.assertRaises(PermissionError):
            self.evaluate(now=self.now + 86401)

    def test_parent_symlink_and_unsafe_root_ownership_fail_closed(self) -> None:
        raw = (json.dumps(self.proof) + "\n").encode()
        for metadata in (
            types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
            types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
            types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=1000),
        ):
            with patch.object(broker.Path, "lstat", return_value=metadata), patch.object(
                broker, "_read_safe_regular_file", return_value=(raw, object())
            ) as read, self.assertRaises(PermissionError):
                broker._validated_nixos_root_oneshot_proof(self.source, now=self.now)
            read.assert_not_called()

    def test_legacy_canonical_nixos_record_without_root_sha_is_no_longer_authority(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "canonical.json"
            record = broker._canonical_recovery_payload(
                self.source, source_record_sha256="e" * 64,
                source_owner_uid=1000, max_age_seconds=86400,
                configured_target=broker.NIXOS_RESTIC_TARGET,
            )
            def status(value):
                dest.write_text(json.dumps(value))
                return broker.inspect_canonical_recovery_record(
                    dest, now=self.now, expected_target=broker.NIXOS_RESTIC_TARGET,
                    expected_max_age_seconds=86400, require_root_owned=False,
                )
            invalid = status(record)
            self.assertFalse(invalid["valid"])
            self.assertEqual(invalid["freshness_reason"], "contract-mismatch")
            root_bound = {**record, "root_proof_sha256": "c" * 64}
            with patch.object(
                broker, "_validated_nixos_root_oneshot_proof",
                return_value="c" * 64,
            ) as check:
                self.assertTrue(status(root_bound)["valid"])
                check.assert_called_once_with(
                    {
                        "completed_at_unix": record["generated_at_unix"],
                        "snapshot_id": record["snapshot_id"],
                        "snapshot_time_unix": record["snapshot_time_unix"],
                        "target": broker.NIXOS_RESTIC_TARGET,
                    },
                    now=self.now,
                    expected_digest="c" * 64,
                )
            # Heim-PC #263 deliberately unlinks its prior proof on the next
            # failed probe. An old canonical record must then close both gates.
            with patch.object(
                broker, "_validated_nixos_root_oneshot_proof",
                side_effect=FileNotFoundError("root-owned proof missing"),
            ):
                revoked = status(root_bound)
                self.assertFalse(revoked["valid"])
                self.assertEqual(revoked["freshness_reason"], "root-proof-invalid")
                self.assertIn("missing", revoked["error"])
                gate = {
                    "recovery_marker_path": str(dest),
                    "max_recovery_age_seconds": 86400,
                    "require_root_owned_gate_files": False,
                    "configured_target": broker.NIXOS_RESTIC_TARGET,
                }
                with self.assertRaises(PermissionError):
                    broker._validate_recovery_gate(gate, now=self.now)
            self.assertFalse(status({**record, "root_proof_sha256": "/tmp/evil"})["valid"])


if __name__ == "__main__":
    unittest.main()