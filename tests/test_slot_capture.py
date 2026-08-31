from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_slot_capture as capture  # noqa: E402


SLOT_A = hashlib.sha256(b"slot-a").hexdigest()
SLOT_B = hashlib.sha256(b"slot-b").hexdigest()
SESSION_A = hashlib.sha256(b"session-a").hexdigest()
SESSION_B = hashlib.sha256(b"session-b").hexdigest()


class FakeAuthority:
    def __init__(self, current: str | None = SESSION_A) -> None:
        self.current = current
        self.states: dict[str, str] = {
            SESSION_A: "live",
            SESSION_B: "live",
        }
        self.lock = threading.Lock()

    def current_session_identity_sha256(self) -> str | None:
        with self.lock:
            return self.current

    def session_state(self, session_identity_sha256: str) -> str:
        with self.lock:
            return self.states.get(session_identity_sha256, "unknown")

    @contextmanager
    def live_session_guard(self, session_identity_sha256: str):
        with self.lock:
            if self.states.get(session_identity_sha256, "unknown") != "live":
                raise capture.SlotCaptureSessionError(
                    "session is not authoritatively live"
                )
            yield

    @contextmanager
    def lost_session_guard(self, session_identity_sha256: str):
        with self.lock:
            if self.states.get(session_identity_sha256, "unknown") != "lost":
                raise capture.SlotCaptureSessionError(
                    "session is not authoritatively lost"
                )
            yield


class IncrementingClock:
    def __init__(self, *, boot_id: str = "boot-a", start_ns: int = 1_000_000_000) -> None:
        self.boot_id = boot_id
        self.monotonic_ns = start_ns
        self.unix_ns = 1_800_000_000_000_000_000
        self.lock = threading.Lock()

    def sample(self) -> capture.ClockSample:
        with self.lock:
            value = capture.ClockSample(
                boot_id=self.boot_id,
                monotonic_ns=self.monotonic_ns,
                unix_ns=self.unix_ns,
            )
            self.monotonic_ns += 1_000_000_000
            self.unix_ns += 1_000_000_000
            return value


class ScriptedClock:
    def __init__(self, samples: list[capture.ClockSample]) -> None:
        self.samples = list(samples)

    def sample(self) -> capture.ClockSample:
        if not self.samples:
            raise AssertionError("unexpected clock sample")
        return self.samples.pop(0)


class SlotCaptureProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="grabowski-slot-capture-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "state"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)

    def provider(
        self,
        authority: FakeAuthority | None = None,
        clock: capture.ProviderClock | None = None,
    ) -> capture.SlotCaptureProvider:
        return capture.SlotCaptureProvider(
            self.root / "slots.sqlite3",
            session_authority=authority if authority is not None else FakeAuthority(),
            clock=clock if clock is not None else IncrementingClock(),
        )

    def test_absent_readback_is_exact_and_effect_free(self) -> None:
        item = self.provider().read(SLOT_A)
        self.assertEqual(item["state"], "absent")
        self.assertEqual(item["slot_id"], SLOT_A)
        self.assertIsNone(item["evidence_sha256"])
        self.assertIn("bureau_candidate_identity_birth", item["does_not_establish"])

    def test_begin_persists_immutable_birth_binding_and_replays(self) -> None:
        store = self.provider()
        binding = {"experiment_id": "exp-a", "ordinal": 1, "event_id": 123}

        first = store.begin(SLOT_A, binding)
        second = store.begin(SLOT_A, binding)
        readback = store.read(SLOT_A)

        self.assertEqual(first["state"], "begun")
        self.assertTrue(first["created"])
        self.assertFalse(first["replayed"])
        self.assertTrue(first["session_matches_current"])
        self.assertFalse(second["created"])
        self.assertTrue(second["replayed"])
        self.assertEqual(second["evidence_sha256"], first["evidence_sha256"])
        self.assertEqual(readback["evidence_sha256"], first["evidence_sha256"])
        self.assertEqual(readback["birth_binding"], binding)
        self.assertEqual(readback["birth_binding_sha256"], capture.sha256_json(binding))

    def test_same_slot_different_birth_binding_is_hard_conflict(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 1})

        with self.assertRaises(capture.SlotCaptureConflictError):
            store.begin(SLOT_A, {"event_id": 2})

        self.assertEqual(store.read(SLOT_A)["birth_binding"], {"event_id": 1})

    def test_concurrent_same_begin_converges_to_one_begun_record(self) -> None:
        authority = FakeAuthority()
        store = self.provider(authority, IncrementingClock())
        binding = {"candidate_id": "candidate-a", "event_id": 99}

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: store.begin(SLOT_A, binding), range(2)))

        self.assertEqual(sorted(item["created"] for item in results), [False, True])
        self.assertEqual(len({item["evidence_sha256"] for item in results}), 1)
        self.assertEqual(store.read(SLOT_A)["state"], "begun")

    def test_replacement_session_cannot_rebind_or_finalize_begun_slot(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        binding = {"candidate_id": "candidate-a"}
        original = store.begin(SLOT_A, binding)

        authority.current = SESSION_B
        replay = store.begin(SLOT_A, binding)

        self.assertFalse(replay["created"])
        self.assertFalse(replay["session_matches_current"])
        self.assertEqual(replay["session_identity_sha256"], original["session_identity_sha256"])
        self.assertEqual(original["session_identity_sha256"], SESSION_A)

        with self.assertRaises(capture.SlotCaptureSessionError):
            store.finalize(SLOT_A, {"state": "frozen"})

        self.assertEqual(store.read(SLOT_A)["state"], "begun")

    def test_finalize_is_atomic_immutable_and_same_payload_replays(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 44})
        payload = {"state": "frozen", "evidence": ["ref-a"]}

        first = store.finalize(SLOT_A, payload)
        replay = store.finalize(SLOT_A, payload)
        readback = store.read(SLOT_A)

        self.assertEqual(first["state"], "terminal")
        self.assertTrue(first["created"])
        self.assertEqual(first["elapsed_ns"], 1_000_000_000)
        self.assertEqual(first["elapsed_seconds"], 1.0)
        self.assertEqual(first["elapsed_clock"], "provider_boottime")
        self.assertFalse(replay["created"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["evidence_sha256"], first["evidence_sha256"])
        self.assertEqual(readback["evidence_sha256"], first["evidence_sha256"])
        self.assertEqual(readback["terminal_payload"], payload)

    def test_concurrent_same_finalize_converges_to_one_terminal_record(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 45})
        payload = {"state": "frozen", "evidence": ["ref-a"]}

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _index: store.finalize(SLOT_A, payload), range(2)))

        self.assertEqual(sorted(item["created"] for item in results), [False, True])
        self.assertEqual(len({item["evidence_sha256"] for item in results}), 1)
        self.assertEqual(store.read(SLOT_A)["state"], "terminal")

    def test_concurrent_different_finalize_never_overwrites_winner(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 46})
        payloads = [{"state": "frozen"}, {"state": "not_applicable"}]

        def finalize(payload: dict[str, str]) -> tuple[str, object]:
            try:
                return "ok", store.finalize(SLOT_A, payload)
            except capture.SlotCaptureConflictError as exc:
                return "conflict", exc

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(finalize, payloads))

        self.assertEqual(sorted(kind for kind, _value in outcomes), ["conflict", "ok"])
        winner_payloads = [
            value["terminal_payload"]
            for kind, value in outcomes
            if kind == "ok" and isinstance(value, dict)
        ]
        self.assertEqual(len(winner_payloads), 1)
        self.assertEqual(store.read(SLOT_A)["terminal_payload"], winner_payloads[0])

    def test_same_slot_different_terminal_payload_is_hard_conflict(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 44})
        store.finalize(SLOT_A, {"state": "frozen"})

        with self.assertRaises(capture.SlotCaptureConflictError):
            store.finalize(SLOT_A, {"state": "not_applicable"})

        self.assertEqual(store.read(SLOT_A)["terminal_payload"], {"state": "frozen"})

    def test_lost_session_terminalization_is_provider_owned_and_fail_closed(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        store.begin(SLOT_A, {"event_id": 55})

        authority.current = SESSION_B
        authority.states[SESSION_A] = "lost"
        result = store.terminalize_lost_session(SLOT_A)

        self.assertEqual(result["state"], "terminal")
        self.assertEqual(
            result["terminal_payload"],
            {"state": "indeterminate", "reason": "capture_session_lost"},
        )
        self.assertEqual(result["elapsed_seconds"], 1.0)

        authority.states[SESSION_A] = "live"
        replay = store.terminalize_lost_session(SLOT_A)
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["evidence_sha256"], result["evidence_sha256"])

    def test_lost_session_terminalization_refuses_live_or_unknown_session(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        store.begin(SLOT_A, {"event_id": 55})

        with self.assertRaises(capture.SlotCaptureSessionError):
            store.terminalize_lost_session(SLOT_A)

        authority.states[SESSION_A] = "unknown"
        with self.assertRaises(capture.SlotCaptureSessionError):
            store.terminalize_lost_session(SLOT_A)

        self.assertEqual(store.read(SLOT_A)["state"], "begun")

    def test_finalize_refuses_unknown_original_session_without_terminal_mutation(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        store.begin(SLOT_A, {"event_id": 56})
        authority.states[SESSION_A] = "unknown"

        with self.assertRaises(capture.SlotCaptureSessionError):
            store.finalize(SLOT_A, {"state": "frozen"})

        self.assertEqual(store.read(SLOT_A)["state"], "begun")

    def test_terminal_same_payload_replay_does_not_require_a_new_session(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        store.begin(SLOT_A, {"event_id": 57})
        payload = {"state": "frozen"}
        terminal = store.finalize(SLOT_A, payload)

        replay_only = capture.SlotCaptureProvider(
            store.database,
            session_authority=None,
            clock=IncrementingClock(),
        )
        replay = replay_only.finalize(SLOT_A, payload)

        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["created"])
        self.assertEqual(replay["evidence_sha256"], terminal["evidence_sha256"])

    def test_lost_session_terminalization_conflicts_with_other_terminal_payload(self) -> None:
        authority = FakeAuthority(SESSION_A)
        store = self.provider(authority)
        store.begin(SLOT_A, {"event_id": 58})
        store.finalize(SLOT_A, {"state": "frozen"})
        authority.states[SESSION_A] = "lost"

        with self.assertRaises(capture.SlotCaptureConflictError):
            store.terminalize_lost_session(SLOT_A)

        self.assertEqual(store.read(SLOT_A)["terminal_payload"], {"state": "frozen"})

    def test_invalid_provider_clock_sample_fails_before_begin_persistence(self) -> None:
        authority = FakeAuthority(SESSION_A)
        clock = ScriptedClock([capture.ClockSample("", -1, -1)])
        store = self.provider(authority, clock)

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            store.begin(SLOT_A, {"event_id": 59})

        self.assertEqual(store.read(SLOT_A)["state"], "absent")

    def test_begun_row_with_terminal_fields_is_rejected_as_corrupt(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 60})
        connection = sqlite3.connect(store.database)
        try:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(
                "UPDATE slots SET terminal_payload_json=? WHERE slot_id=?",
                ('{}', SLOT_A),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            store.read(SLOT_A)

    def test_process_restart_preserves_begun_and_terminal_evidence(self) -> None:
        authority = FakeAuthority(SESSION_A)
        clock = IncrementingClock()
        first = self.provider(authority, clock)
        begun = first.begin(SLOT_A, {"event_id": 88})

        second = capture.SlotCaptureProvider(
            first.database,
            session_authority=authority,
            clock=clock,
        )
        self.assertEqual(second.read(SLOT_A)["evidence_sha256"], begun["evidence_sha256"])
        terminal = second.finalize(SLOT_A, {"state": "frozen"})

        third = capture.SlotCaptureProvider(
            first.database,
            session_authority=authority,
            clock=clock,
        )
        self.assertEqual(third.read(SLOT_A)["evidence_sha256"], terminal["evidence_sha256"])
        self.assertEqual(third.read(SLOT_A)["terminal_payload"], {"state": "frozen"})

    def test_cross_boot_elapsed_is_provider_computed_from_persisted_realtime(self) -> None:
        authority = FakeAuthority(SESSION_A)
        clock = ScriptedClock(
            [
                capture.ClockSample("boot-a", 9_000_000_000, 100_000_000_000),
                capture.ClockSample("boot-b", 1_000_000_000, 106_500_000_000),
            ]
        )
        store = self.provider(authority, clock)
        store.begin(SLOT_A, {"event_id": 101})
        terminal = store.finalize(SLOT_A, {"state": "frozen"})

        self.assertEqual(terminal["elapsed_ns"], 6_500_000_000)
        self.assertEqual(terminal["elapsed_seconds"], 6.5)
        self.assertEqual(terminal["elapsed_clock"], "provider_realtime_cross_boot")

    def test_cross_boot_backwards_realtime_fails_without_terminal_mutation(self) -> None:
        authority = FakeAuthority(SESSION_A)
        clock = ScriptedClock(
            [
                capture.ClockSample("boot-a", 9_000_000_000, 100_000_000_000),
                capture.ClockSample("boot-b", 1_000_000_000, 99_000_000_000),
            ]
        )
        store = self.provider(authority, clock)
        store.begin(SLOT_A, {"event_id": 101})

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            store.finalize(SLOT_A, {"state": "frozen"})

        self.assertEqual(store.read(SLOT_A)["state"], "begun")

    def test_readback_detects_durable_payload_corruption(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 222})
        store.finalize(SLOT_A, {"state": "frozen"})

        connection = sqlite3.connect(store.database)
        try:
            connection.execute(
                "UPDATE slots SET terminal_payload_json=? WHERE slot_id=?",
                ('{"state":"tampered"}', SLOT_A),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            store.read(SLOT_A)

    def test_unversioned_foreign_database_is_rejected_without_schema_adoption(self) -> None:
        database = self.root / "foreign.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE foreign_truth(value TEXT NOT NULL)")
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            capture.SlotCaptureProvider(
                database,
                session_authority=FakeAuthority(),
                clock=IncrementingClock(),
            )

        connection = sqlite3.connect(database)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            version = connection.execute("PRAGMA user_version").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(tables, {"foreign_truth"})
        self.assertEqual(version, 0)

    def test_versioned_database_missing_exact_schema_is_rejected(self) -> None:
        database = self.root / "versioned.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(f"PRAGMA user_version={capture.SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            capture.SlotCaptureProvider(
                database,
                session_authority=FakeAuthority(),
                clock=IncrementingClock(),
            )

        connection = sqlite3.connect(database)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            connection.close()
        self.assertEqual(tables, set())

    def test_versioned_matching_columns_without_strict_schema_is_rejected(self) -> None:
        database = self.root / "weakened.sqlite3"
        connection = sqlite3.connect(database)
        try:
            weakened_schema = capture.SLOTS_SCHEMA_SQL.removesuffix(" STRICT")
            connection.execute(weakened_schema)
            connection.execute(f"PRAGMA user_version={capture.SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            capture.SlotCaptureProvider(
                database,
                session_authority=FakeAuthority(),
                clock=IncrementingClock(),
            )

    def test_database_is_private_before_first_sqlite_connect(self) -> None:
        database = self.root / "precreated.sqlite3"
        original_connect = capture.sqlite3.connect
        observed_modes: list[int] = []

        def observing_connect(*args, **kwargs):
            path = Path(args[0])
            if path == database:
                observed_modes.append(stat_mode(path))
            return original_connect(*args, **kwargs)

        with mock.patch.object(capture.sqlite3, "connect", side_effect=observing_connect):
            capture.SlotCaptureProvider(
                database,
                session_authority=FakeAuthority(),
                clock=IncrementingClock(),
            )

        self.assertTrue(observed_modes)
        self.assertEqual(set(observed_modes), {0o600})

    def test_symlinked_state_root_is_rejected_before_database_creation(self) -> None:
        real_root = self.root / "real-root"
        real_root.mkdir(mode=0o700)
        linked_root = self.root / "linked-root"
        linked_root.symlink_to(real_root, target_is_directory=True)
        database = linked_root / "slots.sqlite3"

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            capture.SlotCaptureProvider(
                database,
                session_authority=FakeAuthority(),
                clock=IncrementingClock(),
            )

        self.assertFalse((real_root / "slots.sqlite3").exists())

    def test_semantic_json_reformat_is_detected_as_byte_integrity_drift(self) -> None:
        store = self.provider()
        store.begin(SLOT_A, {"event_id": 334})
        connection = sqlite3.connect(store.database)
        try:
            connection.execute(
                "UPDATE slots SET birth_binding_json=? WHERE slot_id=?",
                ('{ "event_id": 334 }', SLOT_A),
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(capture.SlotCaptureIntegrityError):
            store.read(SLOT_A)

    def test_database_and_parent_are_private(self) -> None:
        store = self.provider()
        store.begin(SLOT_B, {"event_id": 333})

        self.assertEqual(stat_mode(store.database.parent), 0o700)
        self.assertEqual(stat_mode(store.database), 0o600)

    def test_mutations_require_server_owned_session_authority(self) -> None:
        store = capture.SlotCaptureProvider(
            self.root / "slots.sqlite3",
            clock=IncrementingClock(),
        )

        self.assertEqual(store.read(SLOT_A)["state"], "absent")
        with self.assertRaises(capture.SlotCaptureSessionError):
            store.begin(SLOT_A, {"event_id": 1})


def stat_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
