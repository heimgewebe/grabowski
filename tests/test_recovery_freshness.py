from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


import grabowski_privileged_broker as broker


TARGET = "heimberry:rest-server/grabowski-recovery-probe"
MAX_AGE = 86400


def _source_payload(generated_at: int, *, snapshot_id: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "completed_at_unix": generated_at,
        "snapshot_id": snapshot_id,
        "restore_probe_valid": True,
        "repository_check_valid": True,
        "target": TARGET,
    }


def _write_source(path: Path, generated_at: int, *, snapshot_id: str) -> tuple[str, bytes]:
    raw = (
        json.dumps(
            _source_payload(generated_at, snapshot_id=snapshot_id),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest(), raw


def _execution(source: Path, destination: Path, digest: str, generated_at: int) -> dict[str, object]:
    return {
        "mode": "recovery-marker-publish",
        "internal_action": "publish-recovery-marker",
        "source_path": str(source),
        "destination_path": str(destination),
        "expected_source_uid": os.getuid(),
        "expected_source_record_sha256": digest,
        "expected_generated_at_unix": generated_at,
        "max_recovery_age_seconds": MAX_AGE,
        "configured_target": TARGET,
        "kill_switch_path": str(destination.parent / "operator-kill-switch"),
        "require_root_owned_destination": False,
    }


class RecoveryFreshnessContractTests(unittest.TestCase):
    def test_example_config_binds_publisher_and_power_gate_to_same_record(self) -> None:
        config = json.loads((ROOT / "config/privileged-actions.example.json").read_text(encoding="utf-8"))
        publisher = config["actions"]["publish_recovery_marker"]
        power_gate = config["actions"]["operator_power_argv"]["gate"]

        self.assertTrue(publisher["enabled"])
        self.assertEqual(publisher["mode"], "recovery-marker-publish")
        self.assertEqual(publisher["destination_path"], power_gate["recovery_marker_path"])
        self.assertEqual(publisher["max_recovery_age_seconds"], power_gate["max_recovery_age_seconds"])
        self.assertEqual(publisher["kill_switch_path"], power_gate["kill_switch_path"])
        self.assertEqual(publisher["configured_target"], power_gate["configured_target"])
        self.assertTrue(publisher["require_root_owned_destination"])
        self.assertTrue(power_gate["require_root_owned_gate_files"])

    def test_canonical_inspector_reports_typed_fail_closed_reasons(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            marker = root / "canonical.json"

            missing = broker.inspect_canonical_recovery_record(
                marker,
                now=now,
                expected_max_age_seconds=MAX_AGE,
                expected_target=TARGET,
                require_root_owned=False,
            )
            self.assertFalse(missing["valid"])
            self.assertEqual(missing["freshness_reason"], "missing")

            marker.write_text("{", encoding="utf-8")
            malformed = broker.inspect_canonical_recovery_record(
                marker,
                now=now,
                expected_max_age_seconds=MAX_AGE,
                expected_target=TARGET,
                require_root_owned=False,
            )
            self.assertFalse(malformed["valid"])
            self.assertEqual(malformed["freshness_reason"], "malformed")

            for generated_at, reason in (
                (now + 1, "future-dated"),
                (now - MAX_AGE - 1, "stale"),
            ):
                source = root / f"source-{reason}.json"
                digest, source_raw = _write_source(source, generated_at, snapshot_id=reason)
                canonical = broker._canonical_recovery_payload(
                    json.loads(source_raw.decode("utf-8")),
                    source_record_sha256=digest,
                    source_owner_uid=os.getuid(),
                    max_age_seconds=MAX_AGE,
                    configured_target=TARGET,
                )
                marker.write_text(
                    json.dumps(canonical, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                inspected = broker.inspect_canonical_recovery_record(
                    marker,
                    now=now,
                    expected_max_age_seconds=MAX_AGE,
                    expected_target=TARGET,
                    require_root_owned=False,
                )
                self.assertFalse(inspected["valid"])
                self.assertEqual(inspected["freshness_reason"], reason)

    def test_publish_is_atomic_digest_bound_and_idempotent(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="abc12345")
            execution = _execution(source, destination, digest, now)

            first = broker.publish_recovery_marker(execution, now=now)
            second = broker.publish_recovery_marker(execution, now=now)
            inspected = broker.inspect_canonical_recovery_record(
                destination,
                now=now,
                expected_max_age_seconds=MAX_AGE,
                expected_target=TARGET,
                require_root_owned=False,
            )

            self.assertTrue(first["published"])
            self.assertFalse(first["idempotent"])
            self.assertFalse(second["published"])
            self.assertTrue(second["idempotent"])
            self.assertTrue(inspected["valid"])
            self.assertEqual(inspected["freshness_reason"], "ready")
            self.assertEqual(inspected["source_record_sha256"], digest)
            self.assertEqual(first["record_sha256"], second["record_sha256"])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)
            self.assertEqual(list(root.glob(".grabowski-recovery-*")), [])

    def test_safe_legacy_owner_is_rewritten_instead_of_false_idempotence(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="legacy-owner")
            base_execution = _execution(source, destination, digest, now)
            broker.publish_recovery_marker(base_execution, now=now)
            strict_calls = 0
            original_inspect = broker.inspect_canonical_recovery_record
            original_parent = broker._validated_recovery_destination_parent
            original_atomic = broker._atomic_write_recovery_record

            def inspect_with_legacy_owner(
                path: Path,
                *,
                now: int | None = None,
                expected_max_age_seconds: int | None = None,
                expected_target: str | None = None,
                require_root_owned: bool = True,
            ) -> dict[str, object]:
                nonlocal strict_calls
                result = original_inspect(
                    path,
                    now=now,
                    expected_max_age_seconds=expected_max_age_seconds,
                    expected_target=expected_target,
                    require_root_owned=False,
                )
                if require_root_owned:
                    strict_calls += 1
                    if strict_calls == 1:
                        result = dict(result)
                        result.update(
                            valid=False,
                            freshness_reason="unsafe-file",
                            error="canonical recovery record must be root-owned",
                        )
                return result

            def parent_without_test_uid_requirement(
                path: Path,
                *,
                require_root_owned_destination: bool,
            ) -> tuple[Path, tuple[int, int, int, int, int]]:
                return original_parent(path, require_root_owned_destination=False)

            def atomic_without_test_uid_requirement(
                path: Path,
                value: dict[str, object],
                *,
                require_root_owned_destination: bool,
            ) -> str:
                return original_atomic(path, value, require_root_owned_destination=False)

            def record_lock_acquisition(
                descriptor: int,
                *,
                timeout_seconds: float | None = None,
            ) -> None:
                del descriptor, timeout_seconds
                events.append("locked")

            def record_owner_repair(
                descriptor: int,
                metadata: os.stat_result,
                *,
                require_root_owned: bool,
            ) -> os.stat_result:
                del descriptor, require_root_owned
                events.append("owner-repaired")
                return metadata

            execution = dict(base_execution)
            execution["require_root_owned_destination"] = True
            events: list[str] = []

            with patch.object(
                broker,
                "inspect_canonical_recovery_record",
                side_effect=inspect_with_legacy_owner,
            ), patch.object(
                broker,
                "_validated_recovery_destination_parent",
                side_effect=parent_without_test_uid_requirement,
            ), patch.object(
                broker,
                "_atomic_write_recovery_record",
                side_effect=atomic_without_test_uid_requirement,
            ), patch.object(
                broker,
                "_acquire_recovery_lock",
                side_effect=record_lock_acquisition,
            ), patch.object(
                broker,
                "_repair_recovery_lock_owner",
                side_effect=record_owner_repair,
            ):
                outcome = broker.publish_recovery_marker(execution, now=now)

            self.assertTrue(outcome["published"])
            self.assertFalse(outcome["idempotent"])
            self.assertGreaterEqual(strict_calls, 2)
            self.assertEqual(events, ["locked", "owner-repaired"])

    def test_safe_legacy_owner_still_preserves_generation_rollback_guard(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            destination = root / "canonical.json"
            newer_source = root / "newer.json"
            older_source = root / "older.json"
            newer_digest, _ = _write_source(newer_source, now, snapshot_id="newer")
            older_digest, _ = _write_source(older_source, now - 1, snapshot_id="older")
            broker.publish_recovery_marker(
                _execution(newer_source, destination, newer_digest, now),
                now=now,
            )
            original_inspect = broker.inspect_canonical_recovery_record
            original_parent = broker._validated_recovery_destination_parent

            def inspect_with_legacy_owner(
                path: Path,
                *,
                now: int | None = None,
                expected_max_age_seconds: int | None = None,
                expected_target: str | None = None,
                require_root_owned: bool = True,
            ) -> dict[str, object]:
                result = original_inspect(
                    path,
                    now=now,
                    expected_max_age_seconds=expected_max_age_seconds,
                    expected_target=expected_target,
                    require_root_owned=False,
                )
                if require_root_owned:
                    result = dict(result)
                    result.update(valid=False, freshness_reason="unsafe-file", error="legacy owner")
                return result

            def parent_without_test_uid_requirement(
                path: Path,
                *,
                require_root_owned_destination: bool,
            ) -> tuple[Path, tuple[int, int, int, int, int]]:
                return original_parent(path, require_root_owned_destination=False)

            execution = _execution(older_source, destination, older_digest, now - 1)
            execution["require_root_owned_destination"] = True
            with patch.object(
                broker,
                "inspect_canonical_recovery_record",
                side_effect=inspect_with_legacy_owner,
            ), patch.object(
                broker,
                "_validated_recovery_destination_parent",
                side_effect=parent_without_test_uid_requirement,
            ), patch.object(
                broker,
                "_repair_recovery_lock_owner",
                side_effect=lambda descriptor, metadata, require_root_owned: metadata,
            ):
                with self.assertRaisesRegex(PermissionError, "rollback"):
                    broker.publish_recovery_marker(execution, now=now)

    def test_recovery_lock_owner_repair_is_descriptor_bound(self) -> None:
        initial = cast(
            os.stat_result,
            SimpleNamespace(st_dev=7, st_ino=11, st_uid=1000, st_gid=1000),
        )
        repaired = cast(
            os.stat_result,
            SimpleNamespace(
                st_dev=7,
                st_ino=11,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFREG | 0o600,
                st_nlink=1,
            ),
        )
        with patch.object(broker.os, "fchown") as fchown, patch.object(
            broker.os,
            "fstat",
            return_value=repaired,
        ):
            result = broker._repair_recovery_lock_owner(
                23,
                initial,
                require_root_owned=True,
            )
        fchown.assert_called_once_with(23, 0, 0)
        self.assertIs(result, repaired)

    def test_replaceable_destination_still_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            symlink = root / "symlink.json"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(PermissionError, "non-symlink"):
                broker._validate_replaceable_recovery_destination(symlink)

            hardlink = root / "hardlink.json"
            os.link(target, hardlink)
            with self.assertRaisesRegex(PermissionError, "hard links"):
                broker._validate_replaceable_recovery_destination(target)

    def test_source_digest_change_is_denied_before_publication(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="before")
            execution = _execution(source, destination, digest, now)
            _write_source(source, now, snapshot_id="after")

            with self.assertRaisesRegex(PermissionError, "source changed"):
                broker.publish_recovery_marker(execution, now=now)
            self.assertFalse(destination.exists())

    def test_newer_generation_wins_under_concurrent_publish(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            destination = root / "canonical.json"
            older = root / "older.json"
            newer = root / "newer.json"
            older_digest, _ = _write_source(older, now - 1, snapshot_id="older")
            newer_digest, _ = _write_source(newer, now, snapshot_id="newer")
            executions = (
                _execution(older, destination, older_digest, now - 1),
                _execution(newer, destination, newer_digest, now),
            )
            barrier = threading.Barrier(2)
            outcomes: list[object] = []

            def publish(execution: dict[str, object]) -> None:
                barrier.wait()
                try:
                    outcomes.append(broker.publish_recovery_marker(execution, now=now))
                except PermissionError as exc:
                    outcomes.append(exc)

            threads = [threading.Thread(target=publish, args=(execution,)) for execution in executions]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

            self.assertEqual(len(outcomes), 2)
            inspected = broker.inspect_canonical_recovery_record(
                destination,
                now=now,
                expected_max_age_seconds=MAX_AGE,
                expected_target=TARGET,
                require_root_owned=False,
            )
            self.assertTrue(inspected["valid"])
            self.assertEqual(inspected["generated_at_unix"], now)
            self.assertEqual(inspected["snapshot_id"], "newer")
            self.assertEqual(inspected["source_record_sha256"], newer_digest)

    def test_source_is_revalidated_after_lock_acquisition(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="before-lock")
            execution = _execution(source, destination, digest, now)
            original_acquire = broker._acquire_recovery_lock

            def acquire_then_replace(descriptor: int, *, timeout_seconds: float | None = None) -> None:
                original_acquire(descriptor, timeout_seconds=timeout_seconds)
                _write_source(source, now, snapshot_id="after-lock")

            with patch.object(
                broker,
                "_acquire_recovery_lock",
                side_effect=acquire_then_replace,
            ):
                with self.assertRaisesRegex(PermissionError, "source changed"):
                    broker.publish_recovery_marker(execution, now=now)
            self.assertFalse(destination.exists())

    def test_lock_contention_fails_within_bound(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "canonical.json.lock"
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
            holder = os.open(lock, flags, 0o600)
            contender = os.open(lock, flags, 0o600)
            try:
                broker.fcntl.flock(holder, broker.fcntl.LOCK_EX | broker.fcntl.LOCK_NB)
                started = time.monotonic()
                with self.assertRaisesRegex(PermissionError, "currently locked"):
                    broker._acquire_recovery_lock(contender, timeout_seconds=0.03)
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                broker.fcntl.flock(holder, broker.fcntl.LOCK_UN)
                os.close(contender)
                os.close(holder)

    def test_temporary_record_stays_private_until_fully_written(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="private-temp")
            observed_modes: list[int] = []
            original_write = broker.os.write

            def observe_mode(descriptor: int, data: bytes) -> int:
                observed_modes.append(os.fstat(descriptor).st_mode & 0o777)
                return original_write(descriptor, data)

            with patch.object(broker.os, "write", side_effect=observe_mode):
                broker.publish_recovery_marker(
                    _execution(source, destination, digest, now),
                    now=now,
                )
            self.assertTrue(observed_modes)
            self.assertEqual(set(observed_modes), {0o600})
            self.assertEqual(destination.stat().st_mode & 0o777, 0o644)

    def test_source_hardlinks_are_rejected(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="hardlink")
            os.link(source, root / "source-link.json")

            with self.assertRaisesRegex(PermissionError, "hard links"):
                broker.publish_recovery_marker(
                    _execution(source, destination, digest, now),
                    now=now,
                )
            self.assertFalse(destination.exists())

    def test_kill_switch_is_rechecked_after_lock_acquisition(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="kill-switch")
            execution = _execution(source, destination, digest, now)
            kill_switch = Path(str(execution["kill_switch_path"]))
            original_acquire = broker._acquire_recovery_lock

            def acquire_then_stop(descriptor: int, *, timeout_seconds: float | None = None) -> None:
                original_acquire(descriptor, timeout_seconds=timeout_seconds)
                kill_switch.write_text("stop\n", encoding="utf-8")

            with patch.object(
                broker,
                "_acquire_recovery_lock",
                side_effect=acquire_then_stop,
            ):
                with self.assertRaisesRegex(PermissionError, "kill-switch"):
                    broker.publish_recovery_marker(execution, now=now)
            self.assertFalse(destination.exists())

    def test_publish_action_is_fixed_and_has_no_argv_contract(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="publish")
            reference = {
                "action": "publish_recovery_marker",
                "target": json.dumps(
                    {
                        "source_record_sha256": digest,
                        "generated_at_unix": now,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
            config = {
                "actions": {
                    "publish_recovery_marker": {
                        "enabled": True,
                        "mode": "recovery-marker-publish",
                        "source_path": str(source),
                        "destination_path": str(destination),
                        "expected_source_uid": os.getuid(),
                        "max_recovery_age_seconds": MAX_AGE,
                        "configured_target": TARGET,
                        "kill_switch_path": str(root / "operator-kill-switch"),
                        "require_root_owned_destination": False,
                    }
                }
            }

            execution = broker.resolve_execution(config, reference)
            self.assertEqual(execution["internal_action"], "publish-recovery-marker")
            self.assertNotIn("argv", execution)
            with self.assertRaisesRegex(PermissionError, "no argv contract"):
                broker.resolve_action(config, reference)

            source.write_text("{}\n", encoding="utf-8")
            with self.assertRaises((PermissionError, ValueError)):
                broker.resolve_execution(config, reference)
            self.assertFalse(destination.exists())

    def test_power_gate_denies_stale_future_and_malformed_without_execution(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            marker = root / "canonical.json"
            gate = {
                "kill_switch_path": str(root / "operator-kill-switch"),
                "recovery_marker_path": str(marker),
                "max_recovery_age_seconds": MAX_AGE,
                "require_root_owned_gate_files": False,
                "configured_target": TARGET,
            }
            marker.write_text("{\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON"):
                broker._validate_power_gate(gate, now=now)

            for generated_at, message in (
                (now + 1, "timestamp"),
                (now - MAX_AGE - 1, "stale"),
            ):
                source = root / f"source-{generated_at}.json"
                digest, source_raw = _write_source(source, generated_at, snapshot_id=str(generated_at))
                canonical = broker._canonical_recovery_payload(
                    json.loads(source_raw.decode("utf-8")),
                    source_record_sha256=digest,
                    source_owner_uid=os.getuid(),
                    max_age_seconds=MAX_AGE,
                    configured_target=TARGET,
                )
                marker.write_text(
                    json.dumps(canonical, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(PermissionError, message):
                    broker._validate_power_gate(gate, now=now)

    def test_power_gate_and_status_reader_share_record_identity(self) -> None:
        now = int(time.time())
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source.json"
            destination = root / "canonical.json"
            digest, _ = _write_source(source, now, snapshot_id="identity")
            broker.publish_recovery_marker(
                _execution(source, destination, digest, now),
                now=now,
            )
            inspected = broker.inspect_canonical_recovery_record(
                destination,
                now=now,
                expected_max_age_seconds=MAX_AGE,
                expected_target=TARGET,
                require_root_owned=False,
            )
            gate = broker._validate_power_gate(
                {
                    "kill_switch_path": str(root / "operator-kill-switch"),
                    "recovery_marker_path": str(destination),
                    "max_recovery_age_seconds": MAX_AGE,
                    "require_root_owned_gate_files": False,
                    "configured_target": TARGET,
                },
                now=now,
            )

            self.assertEqual(gate["recovery_marker_sha256"], inspected["record_sha256"])
            self.assertEqual(gate["recovery_marker_source_sha256"], inspected["source_record_sha256"])
            self.assertEqual(gate["recovery_marker_timestamp_unix"], inspected["generated_at_unix"])
            self.assertEqual(gate["recovery_marker_age_seconds"], inspected["age_seconds"])
            self.assertEqual(gate["recovery_marker_max_age_seconds"], inspected["max_age_seconds"])
            self.assertEqual(gate["recovery_marker_freshness_reason"], "ready")


if __name__ == "__main__":
    unittest.main()
