from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "maintain_runtime_state_test", ROOT / "tools" / "maintain_runtime_state.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load runtime retention module")
RETENTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RETENTION)


class RuntimeRetentionTests(unittest.TestCase):
    def _task_db(self, path: Path, unit: str, state: str) -> Path:
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE tasks (unit TEXT NOT NULL, state TEXT NOT NULL)")
            connection.execute("INSERT INTO tasks(unit, state) VALUES (?, ?)", (unit, state))
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o600)
        return path

    def _state(
        self,
        unit: str,
        *,
        active: str = "inactive",
        load: str = "not-found",
        result: str = "success",
    ) -> dict[str, str]:
        return {
            "Id": unit,
            "LoadState": load,
            "ActiveState": active,
            "SubState": "running" if active == "active" else "dead",
            "Result": result,
            "ExecMainCode": "0",
            "ExecMainStatus": "0",
        }

    def _job(
        self,
        root: Path,
        name: str,
        created_at: int,
        runtime_seconds: int = 30,
    ) -> Path:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        directory = root / name
        directory.mkdir(mode=0o700)
        for path, content in (
            (
                directory / "metadata.json",
                json.dumps(
                    {
                        "unit": name,
                        "created_at_unix": created_at,
                        "runtime_seconds": runtime_seconds,
                    }
                )
                + "\n",
            ),
            (directory / "stdout.log", "done\n"),
            (directory / "stderr.log", ""),
        ):
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        return directory

    def _worker_state_dbs(
        self,
        root: Path,
        *,
        worker_id: str,
        kind: str = "gui",
        state: str = "failed",
        lease_keys: list[str] | None = None,
        live_lease: bool = False,
    ) -> tuple[Path, Path, str]:
        worker_root = root / "workers"
        worker_root.mkdir(mode=0o700)
        worker_db = worker_root / "workers.sqlite3"
        unit = f"grabowski-{kind}-worker-{worker_id}.service"
        connection = sqlite3.connect(worker_db)
        try:
            connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO metadata(key, value) VALUES ('schema_version', '1')")
            connection.execute(
                """
                CREATE TABLE workers (
                    worker_id TEXT,
                    kind TEXT,
                    unit TEXT,
                    state TEXT,
                    lease_keys_json TEXT,
                    updated_at_unix INTEGER,
                    last_observation_json TEXT
                )
                """
            )
            connection.execute(
                "INSERT INTO workers VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    worker_id,
                    kind,
                    unit,
                    state,
                    json.dumps(lease_keys or []),
                    900,
                    json.dumps({
                        "state": "failed",
                        "properties": {
                            "LoadState": "loaded",
                            "ActiveState": "failed",
                            "SubState": "dead",
                            "Result": "timeout",
                            "ExecMainStatus": "0",
                        },
                    }),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        worker_db.chmod(0o600)

        resource_db = root / "resources.sqlite3"
        connection = sqlite3.connect(resource_db)
        try:
            connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO metadata(key, value) VALUES ('schema_version', '1')")
            connection.execute(
                """
                CREATE TABLE leases (
                    resource_key TEXT,
                    owner_id TEXT,
                    expires_at_unix INTEGER
                )
                """
            )
            if live_lease:
                connection.execute(
                    "INSERT INTO leases VALUES (?, ?, ?)",
                    ((lease_keys or ["display:98"])[0], f"worker:{worker_id}", 2_000),
                )
            connection.commit()
        finally:
            connection.close()
        resource_db.chmod(0o600)
        return worker_db, resource_db, unit

    def _legacy_collection(
        self,
        jobs: Path,
        archive: Path,
        *,
        tamper_stdout: bool = False,
        include_finalization: bool = False,
        tamper_finalization: bool = False,
    ) -> Path:
        jobs.mkdir(mode=0o700, exist_ok=True)
        archive.mkdir(mode=0o700, exist_ok=True)
        collection = archive / "legacy-self-deploy-without-finalization-1783721038"
        collection.mkdir(mode=0o700)
        unit = "grabowski-job-012345abcdef"
        child = collection / unit
        child.mkdir(mode=0o700)
        expected_head = "a" * 40
        metadata_bytes = (
            json.dumps(
                {
                    "schema_version": 1,
                    "unit": unit,
                    "argv": ["python3", "runner.py", "--expected-head", expected_head],
                    "argv_sha256": "c" * 64,
                },
                sort_keys=True,
            )
            + "\n"
        ).encode()
        stdout_bytes = b"PASS: Deployment erfolgreich\n"
        stderr_bytes = b""
        for name, payload in (
            ("metadata.json", metadata_bytes),
            ("stdout.log", stdout_bytes),
            ("stderr.log", stderr_bytes),
        ):
            target = child / name
            target.write_bytes(payload)
            target.chmod(0o600)
        if include_finalization:
            finalization_material = {
                "argv_sha256": "c" * 64,
                "completion_status": "complete",
                "expected_head": expected_head,
                "failure_type": None,
                "final_status": "completed",
                "job_id": unit.removeprefix("grabowski-job-"),
                "kind": "grabowski_runtime_deploy_finalization",
                "receipt_paths": {
                    "finalization": str(jobs / unit / "finalization.json"),
                    "metadata": str(jobs / unit / "metadata.json"),
                    "stderr": str(jobs / unit / "stderr.log"),
                    "stdout": str(jobs / unit / "stdout.log"),
                },
                "release_id": "release-test",
                "repo_head": expected_head,
                "schema_version": 1,
                "timestamp_unix": 1_000,
                "unit": unit,
            }
            finalization = {
                **finalization_material,
                "payload_sha256": RETENTION._sha256(finalization_material),
            }
            if tamper_finalization:
                finalization["repo_head"] = "d" * 40
            finalization_path = child / "finalization.json"
            finalization_path.write_text(json.dumps(finalization, sort_keys=True) + "\n")
            finalization_path.chmod(0o600)
        manifest = {
            "schema_version": 1,
            "created_at_unix": 1_783_721_038,
            "repo_head": "b" * 40,
            "operation": "archive_legacy_self_deploy_jobs",
            "reversible": True,
            "entries": [
                {
                    "destination": str(child),
                    "expected_head": expected_head,
                    "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                    "reason": RETENTION.LEGACY_SELF_DEPLOY_REASON,
                    "source": str(jobs / unit),
                    "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                    "unit": unit,
                }
            ],
        }
        manifest_path = collection / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        manifest_path.chmod(0o600)
        if tamper_stdout:
            (child / "stdout.log").write_text("tampered\n")
            (child / "stdout.log").chmod(0o600)
        return collection

    def test_plan_resets_only_proven_terminal_units_and_preserves_unknown_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-abcdef012345"
            job_unit = job_name + ".service"
            task_unit = "grabowski-task-" + "a" * 24 + "-a1.service"
            self._job(jobs, job_name, 100)
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")

            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=receipts,
                task_db=task_db,
                failed_units=[job_unit, task_unit, "grabowski-gui-worker-deadbeef.service"],
                unit_states={job_unit: self._state(job_unit)},
            )

            self.assertEqual(plan["reset_failed_units"], [job_unit, task_unit])
            self.assertEqual([item["unit"] for item in plan["archive_jobs"]], [job_unit])
            self.assertEqual(plan["blocked"][0]["unit"], "grabowski-gui-worker-deadbeef.service")
            self.assertRegex(plan["plan_sha256"], r"^[0-9a-f]{64}$")

    def test_failed_worker_reset_requires_bound_db_systemd_and_no_live_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            worker_id = "1" * 20
            worker_db, resource_db, unit = self._worker_state_dbs(
                root,
                worker_id=worker_id,
                lease_keys=["display:98"],
            )
            state = self._state(
                unit,
                active="failed",
                load="loaded",
                result="timeout",
            )
            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )

            self.assertEqual(plan["schema_version"], 3)
            self.assertEqual(plan["reset_failed_units"], [unit])
            self.assertEqual(plan["blocked"], [])
            evidence = plan["worker_reset_evidence"][0]
            self.assertEqual(evidence["worker_id"], worker_id)
            self.assertEqual(evidence["declared_lease_keys"], ["display:98"])
            self.assertEqual(
                evidence["terminal_evidence"],
                "worker_db_and_systemd_failed_without_live_leases",
            )

    def test_failed_worker_with_live_lease_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            worker_id = "2" * 20
            worker_db, resource_db, unit = self._worker_state_dbs(
                root,
                worker_id=worker_id,
                lease_keys=["display:99"],
                live_lease=True,
            )
            state = self._state(
                unit,
                active="failed",
                load="loaded",
                result="timeout",
            )
            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )

            self.assertEqual(plan["reset_failed_units"], [])
            self.assertEqual(plan["worker_reset_evidence"], [])
            self.assertIn("live resource leases", plan["blocked"][0]["reason"])

    def test_worker_reset_revalidation_detects_state_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            worker_id = "3" * 20
            worker_db, resource_db, unit = self._worker_state_dbs(
                root,
                worker_id=worker_id,
            )
            state = self._state(
                unit,
                active="failed",
                load="loaded",
                result="timeout",
            )
            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )
            connection = sqlite3.connect(worker_db)
            try:
                connection.execute("UPDATE workers SET updated_at_unix=901")
                connection.commit()
            finally:
                connection.close()
            worker_db.chmod(0o600)

            with patch.object(RETENTION, "_systemd_unit_states", return_value={unit: state}):
                with self.assertRaisesRegex(RuntimeError, "drifted"):
                    RETENTION._prepare_worker_resets(plan)

    def test_legacy_self_deploy_collection_is_validated_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(jobs, archive)
            receipt = RETENTION.legacy_archive_status(
                jobs_root=jobs,
                archive_root=archive,
                now=1_000,
            )

            self.assertEqual(receipt["authority"], "read_only_legacy_archive_evidence")
            self.assertEqual(receipt["collection_count"], 1)
            self.assertRegex(receipt["status_sha256"], r"^[0-9a-f]{64}$")
            status = receipt["collections"][0]
            self.assertTrue(status["valid"])
            self.assertEqual(status["entry_count"], 1)
            self.assertGreater(status["observed_bytes"], 0)
            self.assertEqual(status["bound_files_per_entry"], ["metadata.json", "stdout.log"])
            self.assertEqual(status["observed_unbound_files_per_entry"], ["stderr.log"])
            self.assertRegex(status["manifest_file_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(status["observed_entries_sha256"], r"^[0-9a-f]{64}$")

    def test_legacy_status_is_read_only_and_excluded_from_retention_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(jobs, archive, include_finalization=True)

            def snapshot() -> dict[str, bytes]:
                return {
                    str(path.relative_to(root)): path.read_bytes()
                    for path in sorted(root.rglob("*"))
                    if path.is_file() and not path.is_symlink()
                }

            before = snapshot()
            plan_before = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states={},
            )
            status = RETENTION.legacy_archive_status(
                jobs_root=jobs, archive_root=archive, now=1_000
            )
            plan_after = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states={},
            )

            self.assertEqual(snapshot(), before)
            self.assertEqual(plan_after["plan_sha256"], plan_before["plan_sha256"])
            self.assertFalse(any("legacy" in key for key in plan_after))
            self.assertEqual(status["collection_count"], 1)

    def test_legacy_self_deploy_collection_accepts_self_bound_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(jobs, archive, include_finalization=True)
            receipt = RETENTION.legacy_archive_status(
                jobs_root=jobs,
                archive_root=archive,
                now=1_000,
            )

            self.assertEqual(receipt["authority"], "read_only_legacy_archive_evidence")
            self.assertEqual(receipt["collection_count"], 1)
            self.assertRegex(receipt["status_sha256"], r"^[0-9a-f]{64}$")
            status = receipt["collections"][0]
            self.assertTrue(status["valid"])
            self.assertEqual(status["self_bound_finalization_count"], 1)

    def test_legacy_self_deploy_collection_rejects_tampered_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(
                jobs,
                archive,
                include_finalization=True,
                tamper_finalization=True,
            )
            receipt = RETENTION.legacy_archive_status(
                jobs_root=jobs,
                archive_root=archive,
                now=1_000,
            )

            self.assertEqual(receipt["authority"], "read_only_legacy_archive_evidence")
            self.assertEqual(receipt["collection_count"], 1)
            self.assertRegex(receipt["status_sha256"], r"^[0-9a-f]{64}$")
            status = receipt["collections"][0]
            self.assertFalse(status["valid"])
            self.assertIn("finalization binding", status["error"])

    def test_legacy_self_deploy_collection_rejects_ambiguous_expected_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            collection = self._legacy_collection(jobs, archive)
            unit = "grabowski-job-012345abcdef"
            metadata_path = collection / unit / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["argv"].extend(["--expected-head", "d" * 40])
            metadata_bytes = (json.dumps(metadata, sort_keys=True) + "\n").encode()
            metadata_path.write_bytes(metadata_bytes)
            metadata_path.chmod(0o600)
            manifest_path = collection / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["entries"][0]["metadata_sha256"] = hashlib.sha256(
                metadata_bytes
            ).hexdigest()
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
            manifest_path.chmod(0o600)

            receipt = RETENTION.legacy_archive_status(
                jobs_root=jobs, archive_root=archive, now=1_000
            )
            self.assertFalse(receipt["collections"][0]["valid"])
            self.assertIn("metadata binding", receipt["collections"][0]["error"])

    def test_legacy_self_deploy_collection_rejects_symlink_and_hardlink_files(self) -> None:
        for link_kind in ("symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o700)
                jobs = root / "jobs"
                archive = root / "archive"
                collection = self._legacy_collection(jobs, archive)
                unit = "grabowski-job-012345abcdef"
                target = root / "outside.log"
                target.write_text("outside\n", encoding="utf-8")
                target.chmod(0o600)
                candidate = collection / unit / "stderr.log"
                candidate.unlink()
                if link_kind == "symlink":
                    candidate.symlink_to(target)
                else:
                    candidate.hardlink_to(target)

                receipt = RETENTION.legacy_archive_status(
                    jobs_root=jobs, archive_root=archive, now=1_000
                )
                status = receipt["collections"][0]
                self.assertFalse(status["valid"])
                self.assertTrue(
                    "symlink" in status["error"]
                    or "bounded private" in status["error"]
                )

    def test_legacy_self_deploy_collection_total_bytes_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(jobs, archive)
            with patch.object(RETENTION, "MAX_LEGACY_COLLECTION_BYTES", 1):
                receipt = RETENTION.legacy_archive_status(
                    jobs_root=jobs,
                    archive_root=archive,
                    now=1_000,
                )

            status = receipt["collections"][0]
            self.assertFalse(status["valid"])
            self.assertIn("total byte bound", status["error"])

    def test_legacy_archive_root_scan_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            archive = root / "archive"
            archive.mkdir(mode=0o700)
            (archive / "ordinary-a").mkdir(mode=0o700)
            (archive / "ordinary-b").mkdir(mode=0o700)

            with patch.object(RETENTION, "MAX_LEGACY_ARCHIVE_ROOT_ENTRIES", 1):
                with self.assertRaisesRegex(RuntimeError, "root scan exceeds"):
                    RETENTION.legacy_archive_status(
                        jobs_root=jobs,
                        archive_root=archive,
                        now=1_000,
                    )

    def test_legacy_self_deploy_collection_hash_tamper_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            self._legacy_collection(jobs, archive, tamper_stdout=True)
            receipt = RETENTION.legacy_archive_status(
                jobs_root=jobs,
                archive_root=archive,
                now=1_000,
            )

            self.assertEqual(receipt["authority"], "read_only_legacy_archive_evidence")
            self.assertEqual(receipt["collection_count"], 1)
            self.assertRegex(receipt["status_sha256"], r"^[0-9a-f]{64}$")
            status = receipt["collections"][0]
            self.assertFalse(status["valid"])
            self.assertIn("hash mismatch", status["error"])

    def test_failed_worker_oversized_observation_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            worker_id = "4" * 20
            worker_db, resource_db, unit = self._worker_state_dbs(
                root,
                worker_id=worker_id,
            )
            connection = sqlite3.connect(worker_db)
            try:
                connection.execute(
                    "UPDATE workers SET last_observation_json=?",
                    ("x" * (RETENTION.MAX_WORKER_OBSERVATION_JSON_BYTES + 1),),
                )
                connection.commit()
            finally:
                connection.close()
            worker_db.chmod(0o600)
            state = self._state(
                unit,
                active="failed",
                load="loaded",
                result="timeout",
            )

            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )

            self.assertEqual(plan["reset_failed_units"], [])
            self.assertIn("exceeds its bound", plan["blocked"][0]["reason"])

    def test_apply_worker_reset_requires_kind_capability_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            worker_id = "5" * 20
            worker_db, resource_db, unit = self._worker_state_dbs(
                root,
                worker_id=worker_id,
                kind="gui",
            )
            state = self._state(
                unit,
                active="failed",
                load="loaded",
                result="timeout",
            )
            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION,
                "_systemd_unit_states",
                return_value={unit: state},
            ):
                result = RETENTION.apply_plan(
                    plan,
                    expected_plan_sha256=plan["plan_sha256"],
                )

            self.assertTrue(result["completed"])
            self.assertEqual(result["reset_failed"][0]["unit"], unit)
            self.assertEqual(
                [call.args[0] for call in fake_base._require_capability.call_args_list],
                ["durable_job", "gui_worker"],
            )
            self.assertGreaterEqual(reset.call_count, 1)
            self.assertEqual(reset.call_args.args[0], ["systemctl", "--user", "reset-failed", unit])

    def test_unknown_task_outcome_remains_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            task_unit = "grabowski-task-" + "b" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "outcome_unknown")
            plan = RETENTION.build_plan(
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=task_db,
                failed_units=[task_unit],
                unit_states={},
            )
            self.assertEqual(plan["reset_failed_units"], [])
            self.assertIn("not proven terminal", plan["blocked"][0]["reason"])

    def test_archive_collision_blocks_reset_of_old_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            archive.mkdir(mode=0o700)
            job_name = "grabowski-job-abcdef012345"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            (archive / job_name).mkdir(mode=0o700)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(plan["reset_failed_units"], [])
            self.assertEqual(plan["archive_jobs"], [])
            self.assertIn("already exists", plan["blocked"][0]["reason"])

    def test_active_old_job_is_protected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            job_name = "grabowski-job-111111111111"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=10_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states={
                    unit: self._state(
                        unit, active="active", load="loaded", result=""
                    )
                },
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["protected_nonterminal_jobs"][0]["unit"], unit)
            self.assertEqual(
                plan["protected_nonterminal_jobs"][0]["reason"],
                "systemd_nonterminal",
            )

    def test_young_missing_unit_is_not_assumed_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            job_name = "grabowski-job-222222222222"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100, runtime_seconds=3_600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=200,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(
                plan["protected_nonterminal_jobs"][0]["reason"],
                "terminality_unproven",
            )

    def test_archive_batch_is_bounded_and_reports_deferred_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            states: dict[str, dict[str, str]] = {}
            for index in range(3):
                job_name = f"grabowski-job-{index + 1:012x}"
                unit = job_name + ".service"
                self._job(jobs, job_name, 100 + index)
                states[unit] = self._state(unit)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                max_archive_jobs=2,
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states=states,
            )
            self.assertEqual(len(plan["archive_jobs"]), 2)
            self.assertEqual(plan["archive_eligible_count"], 3)
            self.assertEqual(plan["archive_deferred_count"], 1)

    def test_oversized_job_registry_keeps_task_reset_planning_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            states: dict[str, dict[str, str]] = {}
            for index in range(3):
                job_name = f"grabowski-job-{index + 1:012x}"
                unit = job_name + ".service"
                self._job(jobs, job_name, 100 + index)
                if index < 2:
                    states[unit] = self._state(unit)
            task_unit = "grabowski-task-" + "a" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            with patch.object(RETENTION, "MAX_JOB_SCAN_ENTRIES", 2):
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50,
                    max_archive_jobs=2,
                    now=1_000,
                    jobs_root=jobs,
                    archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=task_db,
                    failed_units=[task_unit],
                    unit_states=states,
                )
            self.assertEqual(plan["job_registry_entry_count"], 3)
            self.assertEqual(plan["job_scan_count"], 2)
            self.assertTrue(plan["job_scan_truncated"])
            self.assertEqual(plan["job_scan_deferred_count"], 1)
            self.assertFalse(plan["archive_inventory_complete"])
            self.assertEqual(plan["reset_failed_units"], [task_unit])

    def test_failed_job_outside_primary_scan_is_still_classified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            names = [
                "grabowski-job-000000000001",
                "grabowski-job-000000000002",
                "grabowski-job-ffffffffffff",
            ]
            states: dict[str, dict[str, str]] = {}
            for index, job_name in enumerate(names):
                unit = job_name + ".service"
                self._job(jobs, job_name, 100 + index)
                states[unit] = self._state(
                    unit,
                    active="failed" if index == 2 else "inactive",
                    load="loaded" if index == 2 else "not-found",
                    result="exit-code" if index == 2 else "success",
                )
            failed_unit = names[-1] + ".service"
            with patch.object(RETENTION, "MAX_JOB_SCAN_ENTRIES", 2):
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50,
                    max_archive_jobs=3,
                    now=1_000,
                    jobs_root=jobs,
                    archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=[failed_unit],
                    unit_states=states,
                )
            self.assertEqual(plan["job_registry_entry_count"], 3)
            self.assertEqual(plan["job_scan_count"], 3)
            self.assertFalse(plan["job_scan_truncated"])
            self.assertIn(failed_unit, plan["reset_failed_units"])

    def test_job_registry_discovery_limit_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            for index in range(3):
                self._job(jobs, f"grabowski-job-{index + 1:012x}", 100 + index)
            with patch.object(RETENTION, "MAX_JOB_REGISTRY_ENTRIES", 2):
                with self.assertRaisesRegex(RuntimeError, "bounded discovery limit"):
                    RETENTION.build_plan(
                        jobs_root=jobs,
                        archive_root=root / "archive",
                        receipt_root=root / "receipts",
                        task_db=root / "missing.sqlite3",
                        failed_units=[],
                        unit_states={},
                    )

    def test_job_registry_discovery_stops_at_bounded_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            consumed: list[int] = []

            class FakeJobsRoot:
                def iterdir(self):
                    for index in range(4):
                        consumed.append(index)
                        if index == 3:
                            raise AssertionError("discovery consumed beyond limit + 1")
                        yield root / f"grabowski-job-{index + 1:012x}"

            with (
                patch.object(RETENTION, "MAX_JOB_REGISTRY_ENTRIES", 2),
                patch.object(RETENTION, "_private_directory", return_value=FakeJobsRoot()),
            ):
                with self.assertRaisesRegex(RuntimeError, "bounded discovery limit"):
                    RETENTION.build_plan(
                        jobs_root=root / "jobs",
                        archive_root=root / "archive",
                        receipt_root=root / "receipts",
                        task_db=root / "missing.sqlite3",
                        failed_units=[],
                        unit_states={},
                    )
            self.assertEqual(consumed, [0, 1, 2])

    def test_failed_job_keeps_failed_state_while_archive_is_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            states: dict[str, dict[str, str]] = {}
            units: list[str] = []
            for index in range(2):
                job_name = f"grabowski-job-{index + 1:012x}"
                unit = job_name + ".service"
                self._job(jobs, job_name, 100 + index)
                states[unit] = self._state(
                    unit,
                    active="failed",
                    load="loaded",
                    result="exit-code",
                )
                units.append(unit)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                max_archive_jobs=1,
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=units,
                unit_states=states,
            )
            self.assertEqual(plan["reset_failed_units"], [units[0]])
            self.assertEqual(
                plan["deferred_failed_units"],
                [
                    {
                        "unit": units[1],
                        "reason": "archive deferred by bounded batch",
                    }
                ],
            )

    def test_systemd_show_parser_requires_bound_unit_ids(self) -> None:
        parsed = RETENTION._parse_systemd_show(
            "Id=grabowski-job-abcdef012345.service\n"
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        self.assertIn("grabowski-job-abcdef012345.service", parsed)
        with self.assertRaisesRegex(RuntimeError, "unbound unit"):
            RETENTION._parse_systemd_show("Id=other.service\nActiveState=inactive\n")

    def test_legacy_job_registry_names_are_counted_and_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            legacy = jobs / "grabowski-job-legacy-runtime-deploy"
            legacy.mkdir(mode=0o700)
            plan = RETENTION.build_plan(
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[],
                unit_states={},
            )
            self.assertEqual(plan["job_scan_count"], 1)
            self.assertEqual(plan["blocked"][0]["unit"], legacy.name)
            self.assertIn("legacy", plan["blocked"][0]["reason"])

    def test_archived_failed_job_can_resume_reset_after_interrupted_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            archive = root / "archive"
            archive.mkdir(mode=0o700)
            job_name = "grabowski-job-333333333333"
            unit = job_name + ".service"
            destination = archive / job_name
            destination.mkdir(mode=0o700)
            output = destination / "stdout.log"
            output.write_text("done\n", encoding="utf-8")
            output.chmod(0o600)
            files = RETENTION._archive_file_manifest(destination)
            manifest = {
                "schema_version": 1,
                "unit": unit,
                "job_name": job_name,
                "source": str(jobs / job_name),
                "archived_at_unix": 1_000,
                "plan_sha256": "a" * 64,
                "terminal_evidence": "runtime_bound_expired",
                "files": files,
            }
            manifest["manifest_sha256"] = RETENTION._sha256(manifest)
            manifest_path = destination / "archive-manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)

            plan = RETENTION.build_plan(
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={},
            )

            self.assertEqual(plan["reset_failed_units"], [unit])
            self.assertEqual(
                plan["recovered_archived_failed_units"][0]["unit"],
                unit,
            )
            self.assertEqual(plan["archive_jobs"], [])

    def test_plan_hash_is_stable_while_eligibility_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-abcdef012345"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            first = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000, jobs_root=jobs, archive_root=archive,
                receipt_root=receipts, task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            second = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_001, jobs_root=jobs, archive_root=archive,
                receipt_root=receipts, task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(first["plan_sha256"], second["plan_sha256"])

    def test_hash_mismatch_blocks_apply_before_mutation(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
            RETENTION.apply_plan({"plan_sha256": "a" * 64}, expected_plan_sha256="b" * 64)

    def test_archive_manifest_rejects_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.write_text("data", encoding="utf-8")
            real.chmod(0o600)
            (root / "hardlink").hardlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "private owner-controlled"):
                RETENTION._archive_file_manifest(root)

    def test_apply_archives_then_resets_and_writes_receipt_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-abcdef012345"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            audit_records: list[dict[str, object]] = []
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = audit_records.append
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            completed = Mock(returncode=0, stderr="")
            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(RETENTION, "_run", return_value=completed), patch.object(
                RETENTION,
                "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ):
                result = RETENTION.apply_plan(
                    plan,
                    expected_plan_sha256=plan["plan_sha256"],
                )

            self.assertFalse((jobs / job_name).exists())
            self.assertTrue((archive / job_name / "archive-manifest.json").is_file())
            self.assertTrue(Path(result["receipt_path"]).is_file())
            self.assertTrue(result["completed"])
            self.assertEqual(len(audit_records), 2)
            self.assertEqual(
                [record["operation"] for record in audit_records],
                [
                    "runtime-state-retention-intent",
                    "runtime-state-retention-complete",
                ],
            )
            fake_base._require_mutations_enabled.assert_called_once_with(
                "user_service_control"
            )
            fake_base._require_capability.assert_called_once_with("durable_job")

    def test_apply_detects_file_drift_during_archive_move_before_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-444444444444"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            original_manifest = RETENTION._archive_file_manifest
            calls = 0

            def drifting_manifest(directory: Path) -> list[dict[str, object]]:
                nonlocal calls
                calls += 1
                files = original_manifest(directory)
                if calls == 3:
                    return [*files, {"path": "late", "bytes": 1, "sha256": "0" * 64}]
                return files

            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION,
                "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ), patch.object(
                RETENTION,
                "_archive_file_manifest",
                side_effect=drifting_manifest,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during move"):
                    RETENTION.apply_plan(
                        plan,
                        expected_plan_sha256=plan["plan_sha256"],
                    )

            self.assertTrue((archive / job_name).is_dir())
            self.assertEqual(list(receipts.glob("*.json")), [])
            reset.assert_not_called()
            fake_base._append_audit.assert_called_once()

    def test_worker_revalidation_failure_after_archive_writes_partial_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-555555555555"
            job_unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            worker_db, resource_db, worker_unit = self._worker_state_dbs(
                root, worker_id="6" * 20
            )
            job_state = self._state(job_unit)
            worker_state = self._state(
                worker_unit, active="failed", load="loaded", result="timeout"
            )
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=receipts,
                task_db=root / "missing-tasks.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[job_unit, worker_unit],
                unit_states={job_unit: job_state, worker_unit: worker_state},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            audit_records: list[dict[str, object]] = []
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = audit_records.append
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            sensitive_error = "worker database path /private/secret drifted"

            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(
                RETENTION,
                "_prepare_worker_resets",
                side_effect=[None, RuntimeError(sensitive_error)],
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value={job_unit: job_state}
            ), patch.object(RETENTION, "_run", reset):
                with self.assertRaisesRegex(RuntimeError, "receipt="):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )

            receipt_path = receipts / f"{plan['plan_sha256']}.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertFalse(receipt["completed"])
            self.assertTrue(receipt["retry"]["required"])
            self.assertEqual(
                receipt["retry"]["strategy"], "rebuild_live_plan_and_chain_partial_receipt"
            )
            self.assertEqual(receipt["archived_jobs"][0]["unit"], job_unit)
            self.assertEqual(
                receipt["reset_failures"][0]["stage"], "worker_revalidation"
            )
            self.assertEqual(
                receipt["reset_failures"][0]["error_type"], "RuntimeError"
            )
            self.assertNotIn(sensitive_error, receipt_path.read_text(encoding="utf-8"))
            reset_units = [call.args[0][-1] for call in reset.call_args_list]
            self.assertIn(job_unit, reset_units)
            self.assertNotIn(worker_unit, reset_units)
            self.assertEqual(len(audit_records), 2)
            self.assertFalse(audit_records[-1]["completed"])
            self.assertEqual(audit_records[-1]["reset_failure_count"], 1)

    def test_reset_exception_after_archive_writes_redacted_partial_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-666666666666"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            state = self._state(unit)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=archive,
                receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={unit: state},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            sensitive_error = "systemd internal path /private/secret failed"

            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: state}
            ), patch.object(
                RETENTION, "_run", side_effect=RuntimeError(sensitive_error)
            ):
                with self.assertRaisesRegex(RuntimeError, "receipt="):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )

            receipt_path = receipts / f"{plan['plan_sha256']}.json"
            receipt_text = receipt_path.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertFalse(receipt["completed"])
            self.assertEqual(receipt["reset_failures"][0]["stage"], "reset_command")
            self.assertNotIn(sensitive_error, receipt_text)
            self.assertTrue((archive / job_name).is_dir())

    def test_reset_only_retry_chains_partial_receipt_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            receipts = root / "receipts"
            worker_db, resource_db, unit = self._worker_state_dbs(
                root, worker_id="7" * 20
            )
            state = self._state(
                unit, active="failed", load="loaded", result="timeout"
            )
            plan = RETENTION.build_plan(
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                worker_db=worker_db,
                resource_db=resource_db,
                failed_units=[unit],
                unit_states={unit: state},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            audit_records: list[dict[str, object]] = []
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = audit_records.append
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(
                side_effect=[
                    RuntimeError("transient reset transport detail"),
                    Mock(returncode=0, stderr=""),
                ]
            )

            with patch.dict(
                "sys.modules",
                {
                    "grabowski_self_deploy": fake_self_deploy,
                    "grabowski_mcp": fake_base,
                },
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: state}
            ), patch.object(RETENTION, "_run", reset):
                with self.assertRaisesRegex(RuntimeError, "receipt="):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
                first_path = receipts / f"{plan['plan_sha256']}.json"
                first = json.loads(first_path.read_text(encoding="utf-8"))
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
                with self.assertRaisesRegex(RuntimeError, "terminal receipt"):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )

            self.assertEqual(first["attempt"], 1)
            self.assertIsNone(first["previous_receipt_sha256"])
            self.assertFalse(first["completed"])
            self.assertEqual(result["attempt"], 2)
            self.assertEqual(
                result["previous_receipt_sha256"], first["receipt_sha256"]
            )
            self.assertTrue(result["completed"])
            self.assertTrue(result["receipt_path"].endswith(".retry-02.json"))
            self.assertEqual(reset.call_count, 2)
            self.assertEqual(len(audit_records), 4)

    def test_private_sqlite_file_rejects_symlink_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            real = root / "real.sqlite3"
            real.write_bytes(b"sqlite")
            real.chmod(0o600)
            symlink = root / "symlink.sqlite3"
            symlink.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                RETENTION._private_sqlite_file(symlink)
            hardlink = root / "hardlink.sqlite3"
            hardlink.hardlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "bounded private"):
                RETENTION._private_sqlite_file(hardlink)

    def test_private_sqlite_file_rejects_unsafe_sidecars_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            database = root / "workers.sqlite3"
            database.write_bytes(b"sqlite")
            database.chmod(0o600)
            target = root / "target"
            target.write_bytes(b"wal")
            target.chmod(0o600)
            wal = Path(str(database) + "-wal")
            wal.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                RETENTION._private_sqlite_file(database)
            wal.unlink()
            wal.touch(mode=0o600)
            with wal.open("r+b") as handle:
                handle.truncate(512 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(RuntimeError, "bounded private"):
                RETENTION._private_sqlite_file(database)

    def test_large_valid_partial_receipt_can_open_bounded_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan_sha256 = "a" * 64
            payload = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": plan_sha256,
                "attempt": 1,
                "previous_receipt_sha256": None,
                "completed": False,
                "retry": {
                    "required": True,
                    "strategy": "rebuild_live_plan_and_chain_partial_receipt",
                },
                "preserved_blocked_units": [
                    {
                        "unit": f"grabowski-job-{index:012x}.service",
                        "reason": "bounded evidence " + "x" * 64,
                    }
                    for index in range(2_000)
                ],
            }
            payload["receipt_sha256"] = RETENTION._sha256(payload)
            path = root / f"{plan_sha256}.json"
            path.write_text(
                json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            self.assertGreater(path.stat().st_size, RETENTION.MAX_JSON_BYTES)
            self.assertLess(path.stat().st_size, RETENTION.MAX_RETENTION_RECEIPT_BYTES)
            target, attempt, previous = RETENTION._select_receipt_target(
                root, plan_sha256=plan_sha256
            )
            self.assertEqual(attempt, 2)
            self.assertEqual(previous, payload["receipt_sha256"])
            self.assertTrue(target.name.endswith(".retry-02.json"))

    def test_retention_receipt_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "receipts"
            directory.mkdir(mode=0o700)
            path = directory / "receipt.json"
            RETENTION._write_json_atomic(path, {"value": 1})
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                RETENTION._write_json_atomic(path, {"value": 2})
            self.assertEqual(json.loads(path.read_text()), {"value": 1})

    def test_write_all_handles_short_writes(self) -> None:
        writes: list[bytes] = []

        def short_write(_descriptor: int, data: object) -> int:
            payload = bytes(data)
            chunk = payload[:2]
            writes.append(chunk)
            return len(chunk)

        with patch.object(RETENTION.os, "write", side_effect=short_write):
            RETENTION._write_all(3, b"abcdef")
        self.assertEqual(b"".join(writes), b"abcdef")

    def test_archive_manifest_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "real").write_text("data", encoding="utf-8")
            (root / "link").symlink_to(root / "real")
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                RETENTION._archive_file_manifest(root)


if __name__ == "__main__":
    unittest.main()
