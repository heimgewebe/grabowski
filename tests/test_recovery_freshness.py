from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest


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
