import json
import hashlib
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_chronik as chronik  # noqa: E402


def record(**overrides):
    value = {
        "task_id": "a" * 24,
        "unit": "grabowski-task-" + "a" * 24 + "-a1.service",
        "attempt": 1,
        "created_at_unix": 1_700_000_000,
        "updated_at_unix": 1_700_000_100,
        "terminalized_at_unix": 1_700_000_200,
    }
    value.update(overrides)
    return value


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def write_archive_fixture(root, source_name, events):
    source_dir = root / "grabowski" / "chronik-outbox"
    bundle_dir = source_dir / "bundles"
    bundle_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    source_path = source_dir / source_name
    source_raw = b"".join(
        chronik._canonical_bytes(event) + b"\n" for event in events
    )
    source_sha256 = sha256_bytes(source_raw)
    bundle_sha256 = sha256_bytes(source_raw)
    bundle_file = f"grabowski-{bundle_sha256}.bundle.jsonl"
    (bundle_dir / bundle_file).write_bytes(source_raw)
    source_record = {
        "schema_version": chronik.BUNDLE_SOURCE_SCHEMA,
        "source_name": source_name,
        "source_path": str(source_path),
        "source_sha256": source_sha256,
        "source_bytes": len(source_raw),
        "offset": 0,
        "event_ids": [event["event_id"] for event in events],
        "terminal_kind": events[-1]["kind"],
    }
    source_record["record_sha256"] = sha256_bytes(
        chronik._canonical_bytes(source_record)
    )
    manifest = {
        "schema_version": chronik.BUNDLE_MANIFEST_SCHEMA,
        "domain": "agent.ledger",
        "created_at": "2026-07-18T00:00:00Z",
        "bundle_file": bundle_file,
        "bundle_sha256": bundle_sha256,
        "bundle_bytes": len(source_raw),
        "source_count": 1,
        "event_count": len(events),
        "sources": [source_record],
        "historical_only": True,
        "does_not_establish": ["writer_authority"],
    }
    manifest["manifest_sha256"] = sha256_bytes(
        chronik._canonical_bytes(manifest)
    )
    manifest_file = f"grabowski-{bundle_sha256}.manifest.json"
    (bundle_dir / manifest_file).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    index = {
        "schema_version": chronik.ARCHIVE_INDEX_SCHEMA,
        "domain": "agent.ledger",
        "manifest_count": 1,
        "source_count": 1,
        "manifests": [
            {"file": manifest_file, "sha256": manifest["manifest_sha256"]}
        ],
        "sources": [
            {
                "source_name": source_name,
                "source_sha256": source_sha256,
                "event_ids": [event["event_id"] for event in events],
                "manifest_index": 0,
            }
        ],
        "historical_only": True,
        "authoritative": False,
        "reconstructible": True,
        "does_not_establish": ["writer_authority"],
    }
    index["index_sha256"] = sha256_bytes(chronik._canonical_bytes(index))
    index_path = bundle_dir / chronik.ARCHIVE_INDEX_FILENAME
    index_path.write_bytes(chronik._canonical_bytes(index) + b"\n")
    return {
        "source_path": source_path,
        "bundle_path": bundle_dir / bundle_file,
        "manifest_path": bundle_dir / manifest_file,
        "index_path": index_path,
        "index": index,
        "manifest": manifest,
    }


class ChronikAgentOutboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_enabled = os.environ.get(chronik.ENABLED_ENV)
        self.old_root = os.environ.get(chronik.STATE_ROOT_ENV)

    def tearDown(self):
        if self.old_enabled is None:
            os.environ.pop(chronik.ENABLED_ENV, None)
        else:
            os.environ[chronik.ENABLED_ENV] = self.old_enabled
        if self.old_root is None:
            os.environ.pop(chronik.STATE_ROOT_ENV, None)
        else:
            os.environ[chronik.STATE_ROOT_ENV] = self.old_root
        self.tmp.cleanup()

    def enable(self):
        os.environ[chronik.ENABLED_ENV] = "1"
        os.environ[chronik.STATE_ROOT_ENV] = str(self.root)

    def lines(self):
        files = sorted(self.root.glob("grabowski/chronik-outbox/*.jsonl"))
        self.assertTrue(files)
        return files[0].read_text(encoding="utf-8").splitlines()

    def test_disabled_by_default(self):
        os.environ.pop(chronik.ENABLED_ENV, None)
        os.environ[chronik.STATE_ROOT_ENV] = str(self.root)
        self.assertEqual(chronik.record_task_state(record(), "running"), {"enabled": False, "written": False})
        self.assertEqual(list(self.root.rglob("*.jsonl")), [])

    def test_task_opt_in_writes_without_global_environment(self):
        os.environ.pop(chronik.ENABLED_ENV, None)
        os.environ.pop(chronik.STATE_ROOT_ENV, None)
        result = chronik.record_task_state(
            record(
                chronik_outbox_enabled=1,
                chronik_outbox_state_root=str(self.root),
            ),
            "running",
        )
        self.assertTrue(result["written"])
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.started")

    def test_started_event_when_enabled(self):
        self.enable()
        result = chronik.record_task_state(record(), "running")
        self.assertTrue(result["written"])
        event = json.loads(self.lines()[0])
        self.assertEqual(event["schema_version"], "agent-run-event.v0")
        self.assertEqual(event["kind"], "agent.run.started")
        self.assertEqual(event["source"]["repo"], "heimgewebe/grabowski")
        self.assertEqual(event["subject"], {"scope": "host", "host": "unknown"})
        self.assertEqual(event["data"], {"result": "started", "operation": "other", "task_class": "other"})
        self.assertLessEqual(len(event["caused_by"]), 3)
        self.assertLessEqual(len(event["evidence_refs"]), 5)

    def test_completed_and_blocked_events(self):
        self.enable()
        chronik.record_task_state(record(), "completed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.completed")
        self.assertEqual(event["data"], {"result": "completed", "operation": "other", "task_class": "other"})
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ[chronik.STATE_ROOT_ENV] = str(self.root)
        chronik.record_task_state(record(), "failed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["kind"], "agent.run.blocked")
        self.assertEqual(event["data"], {"result": "blocked", "blocker_code": "task-failed", "operation": "other", "task_class": "other"})

    def test_repository_context_is_projected_without_raw_execution_data(self):
        self.enable()
        context = {
            "subject_scope": "repository",
            "repo": "heimgewebe/chronik",
            "operation": "implement",
            "task_class": "coding",
            "branch": "fix/target-identity",
            "head": "a" * 40,
        }
        chronik.record_task_state(record(host="local", chronik_context_json=json.dumps(context)), "completed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["subject"], {
            "scope": "repository", "repo": "heimgewebe/chronik",
            "branch": "fix/target-identity", "head": "a" * 40,
        })
        self.assertEqual(event["data"], {
            "result": "completed", "operation": "implement", "task_class": "coding",
        })
        rendered = json.dumps(event, sort_keys=True)
        self.assertNotIn("argv", rendered)
        self.assertNotIn("cwd", rendered)
        self.assertNotIn("environment", rendered)

    def test_repository_context_projects_optional_component_bureau_and_pr(self):
        self.enable()
        context = {
            "subject_scope": "repository",
            "repo": "heimgewebe/chronik",
            "operation": "implement",
            "task_class": "coding",
            "component": "task-runner",
            "bureau_task_id": "CCM-V1-T002",
            "pr_number": 306,
        }
        chronik.record_task_state(record(host="local", chronik_context_json=json.dumps(context)), "completed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["subject"], {
            "scope": "repository",
            "repo": "heimgewebe/chronik",
            "component": "task-runner",
            "bureau_task_id": "CCM-V1-T002",
            "pr_number": 306,
        })

    def test_host_context_never_fabricates_repository(self):
        self.enable()
        context = {
            "subject_scope": "host", "host": "heim-pc",
            "operation": "recovery", "task_class": "recovery",
        }
        chronik.record_task_state(record(host="heim-pc", chronik_context_json=json.dumps(context)), "failed")
        event = json.loads(self.lines()[0])
        self.assertEqual(event["subject"], {"scope": "host", "host": "heim-pc"})
        self.assertNotIn("repo", event["subject"])
        self.assertEqual(event["data"]["operation"], "recovery")
        self.assertEqual(event["data"]["task_class"], "recovery")

    def test_deduplicates_same_event(self):
        self.enable()
        chronik.record_task_state(record(), "running")
        chronik.record_task_state(record(), "running")
        self.assertEqual(len(self.lines()), 1)

    def test_event_ids_are_state_unique_and_retry_stable(self):
        value = record(host="local")
        started = chronik.build_event(value, "running")
        completed = chronik.build_event(value, "completed")
        blocked = chronik.build_event(value, "failed")
        self.assertEqual(started["event_id"], chronik.build_event(value, "running")["event_id"])
        self.assertEqual(len({started["event_id"], completed["event_id"], blocked["event_id"]}), 3)
        self.assertEqual(started["ts"], "2023-11-14T22:13:20Z")
        self.assertEqual(completed["ts"], "2023-11-14T22:16:40Z")

    def test_non_finite_persisted_timestamp_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "non-finite terminalized_at_unix"):
            chronik.build_event(record(terminalized_at_unix=float("nan")), "failed")

    def test_event_id_binds_timestamp_subject_and_data(self):
        base = record(host="local")
        original = chronik.build_event(base, "failed")
        later = chronik.build_event(record(host="local", terminalized_at_unix=1_700_000_201), "failed")
        changed_context = chronik.build_event(
            record(
                host="local",
                chronik_context_json={
                    "subject_scope": "host",
                    "host": "heim-pc",
                    "operation": "recovery",
                    "task_class": "recovery",
                },
            ),
            "failed",
        )
        self.assertNotEqual(original["event_id"], later["event_id"])
        self.assertNotEqual(original["event_id"], changed_context["event_id"])

    def test_recreated_outbox_event_is_byte_identical_for_same_task_projection(self):
        self.enable()
        value = record()
        first = chronik.record_task_state(value, "failed")
        path = Path(first["path"])
        original = path.read_bytes()
        path.unlink()
        second = chronik.record_task_state(value, "failed")
        self.assertTrue(second["written"])
        self.assertEqual(path.read_bytes(), original)

    def test_existing_event_id_with_different_payload_fails_closed(self):
        self.enable()
        value = record()
        event = chronik.build_event(value, "failed")
        path = chronik.outbox_path(event, self.root)
        changed = json.loads(json.dumps(event))
        changed["data"]["operation"] = "recovery"
        path.parent.mkdir(parents=True)
        path.write_text(chronik.canonical_json(changed) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "different payload"):
            chronik.append_unique(path, event)

    def test_archived_duplicate_is_not_recreated(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [event]
        )

        self.assertFalse(chronik.append_unique(fixture["source_path"], event))
        self.assertFalse(fixture["source_path"].exists())
        lock_path = fixture["source_path"].parent / chronik.WRITER_COMPACTION_LOCK_FILENAME
        self.assertTrue(lock_path.is_file())
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_archived_duplicate_matches_any_distinct_source_generation(self):
        self.enable()
        first_event = chronik.build_event(record(), "completed")
        first = write_archive_fixture(
            self.root, "grabowski_task-generation-a1.jsonl", [first_event]
        )
        second_event = chronik.build_event(
            record(
                task_id="d" * 24,
                unit="grabowski-task-" + "d" * 24 + "-a1.service",
            ),
            "completed",
        )
        second = write_archive_fixture(
            self.root, "grabowski_task-generation-a1.jsonl", [second_event]
        )
        manifests = [first["manifest"], second["manifest"]]
        manifest_paths = [first["manifest_path"], second["manifest_path"]]
        manifest_order = sorted(
            range(2), key=lambda index: manifest_paths[index].name
        )
        manifest_index_by_original = {
            original_index: sorted_index
            for sorted_index, original_index in enumerate(manifest_order)
        }
        index = {
            "schema_version": chronik.ARCHIVE_INDEX_SCHEMA,
            "domain": "agent.ledger",
            "manifest_count": 2,
            "source_count": 2,
            "manifests": [
                {
                    "file": manifest_paths[index].name,
                    "sha256": manifests[index]["manifest_sha256"],
                }
                for index in manifest_order
            ],
            "sources": sorted(
                [
                    {
                        "source_name": "grabowski_task-generation-a1.jsonl",
                        "source_sha256": manifests[index]["sources"][0][
                            "source_sha256"
                        ],
                        "event_ids": manifests[index]["sources"][0][
                            "event_ids"
                        ],
                        "manifest_index": manifest_index_by_original[index],
                    }
                    for index in range(2)
                ],
                key=lambda item: (
                    item["source_name"], item["source_sha256"]
                ),
            ),
            "historical_only": True,
            "authoritative": False,
            "reconstructible": True,
            "does_not_establish": ["writer_authority"],
        }
        index["index_sha256"] = sha256_bytes(chronik._canonical_bytes(index))
        second["index_path"].write_bytes(
            chronik._canonical_bytes(index) + b"\n"
        )

        self.assertFalse(
            chronik.append_unique(second["source_path"], first_event)
        )
        self.assertFalse(
            chronik.append_unique(second["source_path"], second_event)
        )
        self.assertFalse(second["source_path"].exists())

    def test_archived_source_allows_disjoint_successor_generation(self):
        self.enable()
        archived = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [archived]
        )
        successor = chronik.build_event(
            record(terminalized_at_unix=1_700_000_400), "completed"
        )
        self.assertNotEqual(successor["event_id"], archived["event_id"])

        self.assertTrue(chronik.append_unique(fixture["source_path"], successor))
        self.assertEqual(
            [json.loads(line) for line in fixture["source_path"].read_text().splitlines()],
            [successor],
        )
        self.assertFalse(chronik.append_unique(fixture["source_path"], successor))

    def test_archived_event_id_payload_mismatch_fails_closed(self):
        self.enable()
        archived = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [archived]
        )
        forged = json.loads(json.dumps(archived))
        forged["data"]["operation"] = "recovery"

        with self.assertRaisesRegex(ValueError, "event_id does not match payload"):
            chronik.append_unique(fixture["source_path"], forged)
        self.assertFalse(fixture["source_path"].exists())

    def test_missing_archive_index_with_manifests_fails_closed(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-missing-index-a1.jsonl", [event]
        )
        fixture["index_path"].unlink()

        with self.assertRaisesRegex(ValueError, "index is missing"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_archive_index_must_cover_every_manifest(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-extra-manifest-a1.jsonl", [event]
        )
        extra = fixture["manifest_path"].with_name("extra.manifest.json")
        extra.write_bytes(fixture["manifest_path"].read_bytes())

        with self.assertRaisesRegex(ValueError, "cover all bundle manifests"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_corrupt_archive_index_fails_closed(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [event]
        )
        fixture["index_path"].write_text("{broken\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_manifest_or_bundle_mismatch_fails_closed(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [event]
        )
        fixture["bundle_path"].write_bytes(b"changed\n")

        with self.assertRaisesRegex(ValueError, "bundle content mismatch"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_manifest_cache_invalidates_after_bundle_change(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [event]
        )
        self.assertFalse(chronik.append_unique(fixture["source_path"], event))
        fixture["bundle_path"].write_bytes(b"changed after cache\n")

        with self.assertRaisesRegex(ValueError, "bundle content mismatch"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_cache_invalidates_on_ctime_when_size_and_mtime_are_restored(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-ctime-a1.jsonl", [event]
        )
        self.assertFalse(chronik.append_unique(fixture["source_path"], event))
        bundle = fixture["bundle_path"]
        original = bundle.read_bytes()
        original_stat = bundle.stat()
        tampered = bytearray(original)
        tampered[0] ^= 1
        bundle.write_bytes(tampered)
        os.utime(
            bundle,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )

        with self.assertRaises(ValueError):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_unchanged_archive_cache_avoids_reloading_large_files(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-cached-a1.jsonl", [event]
        )
        self.assertFalse(chronik.append_unique(fixture["source_path"], event))

        with patch.object(
            chronik, "_read_regular_file", wraps=chronik._read_regular_file
        ) as reader:
            self.assertFalse(
                chronik.append_unique(fixture["source_path"], event)
            )

        reader.assert_not_called()
        self.assertFalse(fixture["source_path"].exists())

    def test_archive_index_cache_invalidates_after_atomic_replace(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        fixture = write_archive_fixture(
            self.root, "grabowski_task-archived-a1.jsonl", [event]
        )
        self.assertFalse(chronik.append_unique(fixture["source_path"], event))
        replacement = fixture["index_path"].with_name("replacement.json")
        replacement.write_text("{broken\n", encoding="utf-8")
        os.replace(replacement, fixture["index_path"])

        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            chronik.append_unique(fixture["source_path"], event)
        self.assertFalse(fixture["source_path"].exists())

    def test_non_archived_source_still_writes_normally(self):
        self.enable()
        archived = chronik.build_event(record(), "completed")
        write_archive_fixture(
            self.root, "grabowski_task-other-a1.jsonl", [archived]
        )
        event = chronik.build_event(
            record(task_id="c" * 24, unit="grabowski-task-" + "c" * 24 + "-a1.service"),
            "completed",
        )
        path = chronik.outbox_path(event, self.root)

        self.assertTrue(chronik.append_unique(path, event))
        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_writer_rejects_symlinked_outbox_directory(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        source_dir = self.root / "grabowski" / "chronik-outbox"
        target = self.root / "redirected-outbox"
        source_dir.parent.mkdir(parents=True)
        target.mkdir()
        source_dir.symlink_to(target, target_is_directory=True)
        path = source_dir / "grabowski_task-symlink-a1.jsonl"

        with self.assertRaisesRegex(ValueError, "must be real"):
            chronik.append_unique(path, event)

        self.assertEqual(list(target.iterdir()), [])

    def test_writer_rejects_hardlinked_compaction_lock(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        source_dir = self.root / "grabowski" / "chronik-outbox"
        source_dir.mkdir(parents=True, mode=0o700)
        origin = self.root / "shared-lock"
        origin.write_text("", encoding="utf-8")
        os.chmod(origin, 0o600)
        os.link(origin, source_dir / chronik.WRITER_COMPACTION_LOCK_FILENAME)
        path = source_dir / "grabowski_task-hardlink-a1.jsonl"

        with self.assertRaisesRegex(ValueError, "private owned file"):
            chronik.append_unique(path, event)

        self.assertFalse(path.exists())

    def test_writer_waits_for_compaction_lock(self):
        self.enable()
        event = chronik.build_event(record(), "completed")
        path = chronik.outbox_path(event, self.root)
        started = threading.Event()
        completed = threading.Event()
        results = []

        def writer():
            started.set()
            results.append(chronik.append_unique(path, event))
            completed.set()

        with chronik._writer_compaction_lock(path.parent):
            thread = threading.Thread(target=writer)
            thread.start()
            self.assertTrue(started.wait(1))
            time.sleep(0.05)
            self.assertFalse(completed.is_set())
        thread.join(1)

        self.assertFalse(thread.is_alive())
        self.assertEqual(results, [True])
        self.assertTrue(path.is_file())

    def test_writer_lock_wait_is_bounded_and_safe_wrapper_reports_error(self):
        self.enable()
        value = record()
        path = chronik.outbox_path(
            chronik.build_event(value, "completed"), self.root
        )

        with patch.object(
            chronik, "WRITER_COMPACTION_LOCK_TIMEOUT_SECONDS", 0.05
        ):
            with chronik._writer_compaction_lock(path.parent):
                started = time.monotonic()
                result = chronik.record_task_state_safely(value, "completed")
                elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.5)
        self.assertFalse(result["written"])
        self.assertIn("acquisition timed out", result["error"])
        self.assertFalse(path.exists())

    def test_failure_is_non_blocking(self):
        bad_root = self.root / "occupied"
        bad_root.write_text("x", encoding="utf-8")
        os.environ[chronik.ENABLED_ENV] = "1"
        os.environ[chronik.STATE_ROOT_ENV] = str(bad_root)
        result = chronik.record_task_state_safely(record(), "running")
        self.assertFalse(result["written"])
        self.assertIn("error", result)


class PlexerFlushTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_url = os.environ.get(chronik.PLEXER_EVENTS_URL_ENV)

    def tearDown(self):
        if self.old_url is None:
            os.environ.pop(chronik.PLEXER_EVENTS_URL_ENV, None)
        else:
            os.environ[chronik.PLEXER_EVENTS_URL_ENV] = self.old_url
        self.tmp.cleanup()

    def test_plexer_url_normalization(self):
        self.assertEqual(
            chronik.plexer_events_url("http://plexer.local"),
            "http://plexer.local/v1/events",
        )
        self.assertEqual(
            chronik.plexer_events_url("http://plexer.local/v1/events/"),
            "http://plexer.local/v1/events",
        )

    def test_missing_plexer_url_is_non_blocking(self):
        os.environ.pop(chronik.PLEXER_EVENTS_URL_ENV, None)
        result = chronik.send_event_to_plexer_safely({"kind": "agent.run.completed"})
        self.assertFalse(result["configured"])
        self.assertFalse(result["sent"])

    def test_send_event_posts_json_to_plexer(self):
        class Response:
            status = 202

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def getcode(self):
                return self.status

        seen = {}

        def fake_urlopen(request, timeout):
            seen["url"] = request.full_url
            seen["body"] = request.data.decode("utf-8")
            seen["timeout"] = timeout
            return Response()

        event = {"schema_version": "agent-run-event.v0", "kind": "agent.run.completed", "data": {"result": "completed"}}
        with patch.object(chronik, "urlopen", fake_urlopen):
            result = chronik.send_event_to_plexer(event, url="http://plexer.local", timeout_seconds=2.5)

        self.assertTrue(result["sent"])
        self.assertEqual(result["status_code"], 202)
        self.assertEqual(seen["url"], "http://plexer.local/v1/events")
        self.assertEqual(json.loads(seen["body"]), event)
        self.assertEqual(seen["timeout"], 2.5)

    def test_flush_outbox_file_is_non_destructive(self):
        event = chronik.build_event(record(), "completed")
        self.assertIsNotNone(event)
        path = self.root / "event.jsonl"
        path.write_text(chronik.canonical_json(event) + "\n", encoding="utf-8")

        with patch.object(chronik, "send_event_to_plexer_safely", return_value={"sent": True}):
            result = chronik.flush_outbox_file_to_plexer(path, url="http://plexer.local")

        self.assertEqual(result["events"], 1)
        self.assertEqual(result["sent"], 1)
        self.assertTrue(path.exists())
        self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
