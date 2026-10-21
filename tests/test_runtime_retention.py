from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
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
# Production always refuses unsafe job effects until a privileged
# root/index transaction actually exists; never patch this reference.
PRODUCTION_JOB_RETENTION_AUTHORITY = RETENTION._protected_job_retention_authority


class RuntimeRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        # Existing positive archive/FD-hardening tests model a hypothetical
        # separately authorized transaction. This mock is TEST-ONLY; no
        # production authority is inferred from their PASS results.
        grant = patch.object(
            RETENTION, "_protected_job_retention_authority", return_value=True
        )
        self._simulated_protected_authority = grant.start()
        self.addCleanup(grant.stop)

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
        # Normal retention runs against pre-provisioned private output roots.
        # Untrusted apply may not create/adopt an archive or receipt directory
        # that was absent at planning time; explicit missing-root tests remove
        # the provisioned fixture themselves.
        if root.name == "jobs":
            for output_name in ("archive", "receipts"):
                output_root = root.parent / output_name
                output_root.mkdir(mode=0o700, exist_ok=True)
                output_root.chmod(0o700)
        # Ordinary retention runs against an existing private deployment
        # index. Tests exercising absence or foreign replacement explicitly
        # remove/replace it; other tests must not rely on an unsafe implicit
        # "no index means empty" assumption.
        index = root / "runtime-deploy-index.json"
        if not index.exists() and not index.is_symlink():
            index.write_text(json.dumps({
                "schema_version": 1,
                "units": [],
                "pending_unit": None,
                "updated_at_unix": 0,
            }) + "\n")
            index.chmod(0o600)
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
                failed_units=[
                    job_unit,
                    task_unit,
                    "grabowski-gui-worker-deadbeef.service",
                    "grabowski-operator.service",
                ],
                unit_states={job_unit: self._state(job_unit)},
            )

            self.assertEqual(plan["reset_failed_units"], [job_unit, task_unit])
            self.assertEqual([item["unit"] for item in plan["archive_jobs"]], [job_unit])
            blocked_units = {item["unit"] for item in plan["blocked"]}
            self.assertEqual(
                blocked_units,
                {"grabowski-gui-worker-deadbeef.service", "grabowski-operator.service"},
            )
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
            # Existing private output roots are an apply-time safety precondition.
            (root / "archive").mkdir(mode=0o700)
            (root / "receipts").mkdir(mode=0o700)
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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

    def test_nonterminal_and_ambiguous_task_outcomes_remain_blocked(self) -> None:
        for state in ("running", "outcome_unknown", "interrupted"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                jobs = root / "jobs"
                jobs.mkdir(mode=0o700)
                task_unit = "grabowski-task-" + "b" * 24 + "-a1.service"
                task_db = self._task_db(root / "tasks.sqlite3", task_unit, state)
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

    def test_task_reset_preserves_durable_failed_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            # Existing private output roots are an apply-time safety precondition.
            (root / "archive").mkdir(mode=0o700)
            (root / "receipts").mkdir(mode=0o700)
            task_unit = "grabowski-task-" + "c" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=task_db,
                failed_units=[task_unit],
                unit_states={},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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
            ), patch.object(RETENTION, "_run", reset):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )

            self.assertTrue(result["completed"])
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", task_unit]
            )
            with sqlite3.connect(task_db) as connection:
                state = connection.execute(
                    "SELECT state FROM tasks WHERE unit = ?", (task_unit,)
                ).fetchone()[0]
            self.assertEqual(state, "failed")

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

    def test_oversized_terminal_stderr_does_not_stall_other_job_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            oversized_name = "grabowski-job-000000000001"
            good_name = "grabowski-job-000000000002"
            bad_unit = oversized_name + ".service"
            good_unit = good_name + ".service"
            oversized = self._job(jobs, oversized_name, 100)
            self._job(jobs, good_name, 101)
            stderr = oversized / "stderr.log"
            original = b"preserve terminal error evidence\n" * 100
            stderr.write_bytes(original)
            stderr.chmod(0o600)
            states = {unit: self._state(unit) for unit in (bad_unit, good_unit)}
            with patch.object(RETENTION, "MAX_ARCHIVE_FILE_BYTES", 1_024):
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50,
                    max_archive_jobs=2,
                    now=1_000,
                    jobs_root=jobs,
                    archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=[bad_unit, good_unit],
                    unit_states=states,
                )
                with patch.object(RETENTION, "_systemd_unit_states", return_value=states):
                    _, _, _, prepared, _ = RETENTION._prepare_archives(plan)
            self.assertEqual([item["unit"] for item in plan["archive_jobs"]], [good_unit])
            self.assertEqual([item["record"]["unit"] for item in prepared], [good_unit])
            self.assertNotIn(bad_unit, plan["reset_failed_units"])
            self.assertEqual(plan["reset_failed_units"], [good_unit])
            self.assertEqual(plan["archive_deferred_count"], 0)
            self.assertTrue(any(
                item["unit"] == bad_unit and "bounded" in item["reason"]
                for item in plan["blocked"]
            ))
            self.assertEqual(stderr.read_bytes(), original)

    def test_archive_manifest_symlink_swap_cannot_read_foreign_files(self) -> None:
        # Reproduce an exact timing race: the source directory is exchanged
        # after initial verification, just before the directory enumeration.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "job"
            saved = root / "saved-original"
            outside = root / "outside"
            source.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            original = b"job-owned archive evidence"
            foreign = b"secret outside the archive job"
            (source / "safe.log").write_bytes(original)
            (outside / "safe.log").write_bytes(foreign)
            (source / "safe.log").chmod(0o600)
            (outside / "safe.log").chmod(0o600)
            actual_scandir = os.scandir
            swaps: list[bool] = []

            def swap_just_before_scan(target):
                if not swaps and (
                    isinstance(target, int) or os.fspath(target) == str(source)
                ):
                    source.rename(saved)
                    source.symlink_to(outside, target_is_directory=True)
                    swaps.append(True)
                return actual_scandir(target)

            with patch.object(RETENTION.os, "scandir", side_effect=swap_just_before_scan):
                with self.assertRaisesRegex(
                    RuntimeError, "archive source directory changed during inspection"
                ):
                    RETENTION._archive_file_manifest(source)
            self.assertEqual(swaps, [True])
            self.assertEqual((outside / "safe.log").read_bytes(), foreign)
            self.assertEqual((saved / "safe.log").read_bytes(), original)

    def test_archive_rejects_nested_directories_without_following(self) -> None:
        # A job archive needs files at its root only; do not recursively
        # traverse job-controlled directory trees or symlink-swap windows.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "job"
            source.mkdir(mode=0o700)
            child = source / "subdir"
            child.mkdir(mode=0o700)
            item = child / "private.log"
            item.write_bytes(b"retain, never follow")
            item.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "nested directory"):
                RETENTION._archive_file_shape_preflight(source)
            with self.assertRaisesRegex(RuntimeError, "nested directory"):
                RETENTION._archive_file_manifest(source)
            self.assertEqual(item.read_bytes(), b"retain, never follow")

    def test_unsafe_terminal_archive_source_preserves_evidence_and_allows_safe_batch(self) -> None:
        # An unsafe old terminal job must never consume the archive/reset
        # budget or prevent an unrelated safe job from progressing.
        cases = (
            ("symlink", "symlink"),
            ("hidden-symlink", "symlink"),
            ("directory-symlink", "symlink"),
            ("hardlink", "private owner-controlled regular file"),
            ("world-readable", "private owner-controlled regular file"),
            ("file-count", "file-count bound"),
            ("directory-count", "nested directory"),
        )
        for shape, reason in cases:
            with self.subTest(unsafe_source=shape):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    jobs = root / "jobs"
                    bad_name = "grabowski-job-000000000001"
                    good_name = "grabowski-job-000000000002"
                    bad_unit = bad_name + ".service"
                    good_unit = good_name + ".service"
                    bad = self._job(jobs, bad_name, 100)
                    self._job(jobs, good_name, 101)
                    stderr = bad / "stderr.log"
                    original = b"retain the unsafe job's terminal evidence\n"
                    stderr.write_bytes(original)
                    stderr.chmod(0o600)
                    metadata_before = (bad / "metadata.json").read_bytes()
                    extra = bad / (".hidden-link" if shape == "hidden-symlink" else "extra.log")
                    outside = root / "independent-evidence.log"
                    if shape in {"symlink", "hidden-symlink"}:
                        outside.write_bytes(b"external evidence must survive\n")
                        extra.symlink_to(outside)
                    elif shape == "directory-symlink":
                        outside.mkdir(mode=0o700)
                        extra.symlink_to(outside, target_is_directory=True)
                    elif shape == "hardlink":
                        os.link(stderr, extra)
                    elif shape == "world-readable":
                        stderr.chmod(0o644)
                    elif shape == "file-count":
                        extra.write_bytes(b"counted, never deleted\n")
                        extra.chmod(0o600)
                    elif shape == "directory-count":
                        for number in range(12):
                            (bad / f"subdir-{number:02d}").mkdir(mode=0o700)

                    states = {unit: self._state(unit) for unit in (bad_unit, good_unit)}
                    # Both jobs have three normal files. For file-count only,
                    # the bad job's fourth file exceeds the limit.
                    limit = 3 if shape == "file-count" else RETENTION.MAX_ARCHIVE_FILES
                    with patch.object(RETENTION, "MAX_ARCHIVE_FILES", limit), patch.object(
                        RETENTION, "MAX_ARCHIVE_ENTRIES", 10, create=True
                    ):
                        plan = RETENTION.build_plan(
                            minimum_job_age_seconds=50,
                            max_archive_jobs=2,
                            now=1_000,
                            jobs_root=jobs,
                            archive_root=root / "archive",
                            receipt_root=root / "receipts",
                            task_db=root / "missing.sqlite3",
                            failed_units=[bad_unit, good_unit],
                            unit_states=states,
                        )
                        with patch.object(RETENTION, "_systemd_unit_states", return_value=states):
                            _, _, _, prepared, _ = RETENTION._prepare_archives(plan)

                    blocked_reasons = [
                        item["reason"] for item in plan["blocked"]
                        if item["unit"] == bad_unit
                    ]
                    self.assertEqual(len(blocked_reasons), 1)
                    self.assertIn(reason, blocked_reasons[0])
                    self.assertNotIn(
                        bad_unit, [item["unit"] for item in plan["archive_jobs"]]
                    )
                    self.assertNotIn(bad_unit, plan["reset_failed_units"])
                    self.assertEqual(
                        [item["unit"] for item in plan["archive_jobs"]], [good_unit]
                    )
                    self.assertEqual(
                        [item["record"]["unit"] for item in prepared], [good_unit]
                    )
                    self.assertEqual(plan["reset_failed_units"], [good_unit])
                    self.assertEqual(plan["archive_deferred_count"], 0)

                    # Planning/preparation must preserve every unsafe source,
                    # link and permission. Never repair, delete or truncate.
                    self.assertEqual(stderr.read_bytes(), original)
                    self.assertEqual((bad / "metadata.json").read_bytes(), metadata_before)
                    self.assertTrue(bad.is_dir())
                    if shape in {"symlink", "hidden-symlink"}:
                        self.assertTrue(extra.is_symlink())
                        self.assertEqual(
                            outside.read_bytes(), b"external evidence must survive\n"
                        )
                    elif shape == "directory-symlink":
                        self.assertTrue(extra.is_symlink())
                        self.assertTrue(outside.is_dir())
                    elif shape == "hardlink":
                        self.assertTrue(extra.samefile(stderr))
                        self.assertEqual(extra.read_bytes(), original)
                        self.assertEqual(stderr.stat().st_nlink, 2)
                    elif shape == "world-readable":
                        self.assertEqual(stderr.stat().st_mode & 0o777, 0o644)
                    elif shape == "file-count":
                        self.assertEqual(extra.read_bytes(), b"counted, never deleted\n")
                    else:
                        self.assertTrue((bad / "subdir-00").is_dir())

    def test_exchange_retains_stale_manifest_without_breaking_archive_receipt(self) -> None:
        # RENAME_EXCHANGE preserves prior private archive metadata. The
        # recovered archive receipt must still validate the payload files.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-353535353535"
            unit = name + ".service"
            source = self._job(jobs, name, 100)
            stale = source / "archive-manifest.json"
            previous = b'{"retry":true}\n'
            stale.write_bytes(previous)
            stale.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_self_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_run", return_value=Mock(returncode=0, stderr="")
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
                verified = RETENTION._archived_job_receipt(unit, jobs, archive)
            self.assertTrue(result["completed"])
            self.assertEqual(verified["unit"], unit)
            archived = archive / name
            prior = list(archived.glob(".archive-manifest.json.*.tmp"))
            self.assertEqual(len(prior), 1)
            self.assertEqual(prior[0].read_bytes(), previous)
            self.assertEqual((archived / "stdout.log").read_bytes(), b"done\n")
            self.assertFalse(source.exists())

    def test_unsafe_retained_internal_manifest_is_never_ignored(self) -> None:
        # Reserved auxiliary metadata cannot make a symlink or oversize
        # private artifact invisible to the archive safety preflight.
        for kind in ("symlink", "oversized"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                jobs = root / "jobs"
                bad_name = "grabowski-job-353535353536"
                good_name = "grabowski-job-353535353537"
                bad = self._job(jobs, bad_name, 100)
                self._job(jobs, good_name, 101)
                ghost = bad / ".archive-manifest.json.123.456.tmp"
                if kind == "symlink":
                    foreign = root / "foreign"
                    foreign.write_bytes(b"preserve foreign")
                    foreign.chmod(0o600)
                    ghost.symlink_to(foreign)
                else:
                    ghost.write_bytes(b"X" * (RETENTION.MAX_JSON_BYTES + 1))
                    ghost.chmod(0o600)
                states = {
                    name + ".service": self._state(name + ".service")
                    for name in (bad_name, good_name)
                }
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50, now=1_000,
                    jobs_root=jobs, archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=list(states), unit_states=states,
                )
                selected = [row["job_name"] for row in plan["archive_jobs"]]
                self.assertEqual(selected, [good_name])
                self.assertTrue(any(
                    row["unit"] == bad_name + ".service"
                    for row in plan["blocked"]
                ))
                self.assertTrue(ghost.is_symlink() if kind == "symlink" else ghost.is_file())

    def test_stale_internal_archive_manifest_does_not_exhaust_file_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            retry_name = "grabowski-job-000000000001"
            good_name = "grabowski-job-000000000002"
            retry_unit = retry_name + ".service"
            good_unit = good_name + ".service"
            retry_job = self._job(jobs, retry_name, 100)
            self._job(jobs, good_name, 101)
            stale_manifest = retry_job / "archive-manifest.json"
            original = b'{"retry":true}\n'
            stale_manifest.write_bytes(original)
            stale_manifest.chmod(0o600)
            states = {unit: self._state(unit) for unit in (retry_unit, good_unit)}
            with patch.object(RETENTION, "MAX_ARCHIVE_FILES", 3):
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50,
                    max_archive_jobs=2,
                    now=1_000,
                    jobs_root=jobs,
                    archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=[retry_unit, good_unit],
                    unit_states=states,
                )
                with patch.object(RETENTION, "_systemd_unit_states", return_value=states):
                    _, _, _, prepared, _ = RETENTION._prepare_archives(plan)
            self.assertEqual(
                [item["unit"] for item in plan["archive_jobs"]],
                [retry_unit, good_unit],
            )
            self.assertEqual(
                [item["record"]["unit"] for item in prepared],
                [retry_unit, good_unit],
            )
            self.assertNotIn(retry_unit, [item["unit"] for item in plan["blocked"]])
            self.assertEqual(plan["reset_failed_units"], [retry_unit, good_unit])
            self.assertEqual(stale_manifest.read_bytes(), original)

    def test_unsafe_internal_archive_manifest_preserves_evidence_and_safe_job(self) -> None:
        # The manifest is exempt from the payload COUNT, not file-shape checks.
        # A dangerous reserved-name entry must not consume/reset the batch.
        for shape in ("symlink", "hardlink", "world-readable", "oversized", "directory", "fifo"):
            with self.subTest(unsafe_manifest=shape), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                jobs = root / "jobs"
                bad_name = "grabowski-job-000000000001"
                good_name = "grabowski-job-000000000002"
                bad_unit = bad_name + ".service"
                good_unit = good_name + ".service"
                bad = self._job(jobs, bad_name, 100)
                self._job(jobs, good_name, 101)
                manifest = bad / "archive-manifest.json"
                outside = root / "external-evidence"
                original = b"external evidence must be preserved\n"
                if shape in {"symlink", "hardlink"}:
                    outside.write_bytes(original)
                    outside.chmod(0o600)
                    if shape == "symlink":
                        manifest.symlink_to(outside)
                    else:
                        os.link(outside, manifest)
                elif shape == "world-readable":
                    manifest.write_bytes(original)
                    manifest.chmod(0o644)
                elif shape == "oversized":
                    manifest.write_bytes(b"x" * (RETENTION.MAX_JSON_BYTES + 1))
                    manifest.chmod(0o600)
                elif shape == "directory":
                    manifest.mkdir(mode=0o700)
                else:
                    os.mkfifo(manifest, mode=0o600)
                states = {unit: self._state(unit) for unit in (bad_unit, good_unit)}
                with patch.object(RETENTION, "MAX_ARCHIVE_FILES", 3):
                    plan = RETENTION.build_plan(
                        minimum_job_age_seconds=50, max_archive_jobs=1, now=1_000,
                        jobs_root=jobs, archive_root=root / "archive",
                        receipt_root=root / "receipts", task_db=root / "missing.sqlite3",
                        failed_units=[bad_unit, good_unit], unit_states=states,
                    )
                    self.assertEqual(
                        [item["unit"] for item in plan["archive_jobs"]], [good_unit]
                    )
                    self.assertEqual(plan["reset_failed_units"], [good_unit])
                    blocked = [item for item in plan["blocked"] if item["unit"] == bad_unit]
                    self.assertEqual(len(blocked), 1)
                    with patch.object(RETENTION, "_systemd_unit_states", return_value=states):
                        _, _, _, prepared, _ = RETENTION._prepare_archives(plan)
                    self.assertEqual(
                        [item["record"]["unit"] for item in prepared], [good_unit]
                    )
                self.assertTrue((bad / "metadata.json").is_file())
                if shape == "symlink":
                    self.assertTrue(manifest.is_symlink())
                    self.assertEqual(outside.read_bytes(), original)
                elif shape == "hardlink":
                    self.assertTrue(manifest.samefile(outside))
                    self.assertEqual(outside.read_bytes(), original)
                    self.assertEqual(manifest.stat().st_nlink, 2)
                elif shape == "world-readable":
                    self.assertEqual(manifest.read_bytes(), original)
                    self.assertEqual(manifest.stat().st_mode & 0o777, 0o644)
                elif shape == "oversized":
                    self.assertEqual(manifest.stat().st_size, RETENTION.MAX_JSON_BYTES + 1)
                elif shape == "directory":
                    self.assertTrue(manifest.is_dir())
                else:
                    self.assertTrue(manifest.exists())
                    self.assertFalse(manifest.is_file())

    def test_manifest_replaced_with_symlink_after_plan_blocks_before_apply_effect(self) -> None:
        # Apply must revalidate even when the original plan was admissible.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jobs = root / "jobs"
            name = "grabowski-job-000000000001"
            unit = name + ".service"
            bad = self._job(jobs, name, 100)
            manifest = bad / "archive-manifest.json"
            manifest.write_bytes(b"old safe retry marker\n")
            manifest.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, max_archive_jobs=1, now=1_000,
                jobs_root=jobs, archive_root=root / "archive",
                receipt_root=root / "receipts", task_db=root / "missing.sqlite3",
                failed_units=[unit], unit_states=states,
            )
            self.assertEqual(len(plan["archive_jobs"]), 1)
            outside = root / "outside-immutable-evidence"
            outside.write_bytes(b"outside must not change\n")
            manifest.unlink()
            manifest.symlink_to(outside)
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base},
            ), patch.object(RETENTION, "_systemd_unit_states", return_value=states), patch.object(
                RETENTION, "_run", reset,
            ):
                with self.assertRaisesRegex(RuntimeError, "symlink|private|manifest"):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertTrue((jobs / name).is_dir())
            self.assertFalse((root / "archive" / name).exists())
            self.assertTrue(manifest.is_symlink())
            self.assertEqual(outside.read_bytes(), b"outside must not change\n")
            reset.assert_not_called()
            fake_base._append_audit.assert_not_called()

    def test_atomic_json_replace_never_discards_oversized_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = root / "other-maintenance-receipt.json"
            data = b"x" * (RETENTION.MAX_JSON_BYTES + 1)
            previous.write_bytes(data)
            previous.chmod(0o600)
            # The tempdir itself is private; bypass only _private_directory's
            # unrelated recursive /tmp ancestor policy for this size-gate test.
            with patch.object(RETENTION, "_private_directory", return_value=root):
                with self.assertRaisesRegex(RuntimeError, "not owner-controlled"):
                    RETENTION._write_json_atomic(
                        previous, {"replacement": True}, replace_existing=True
                    )
            self.assertEqual(previous.read_bytes(), data)

    def test_atomic_manifest_directory_swap_after_preflight_never_writes_foreign(self) -> None:
        # RED on path-based os.open/os.replace: verified source is renamed
        # and replaced by a symlink immediately after directory validation.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "job"
            source.mkdir(mode=0o700)
            original = source / "stderr.log"
            original.write_bytes(b"must be retained\n")
            original.chmod(0o600)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            foreign = outside / "sentinel"
            foreign.write_bytes(b"untouched\n")
            foreign.chmod(0o600)
            saved = root / "original-job"
            checked_private = RETENTION._private_directory
            swaps: list[bool] = []

            def swap_after_check(path: Path, *, create: bool = False) -> Path:
                checked = checked_private(path, create=create)
                if create and path == source and not swaps:
                    source.rename(saved)
                    source.symlink_to(outside, target_is_directory=True)
                    swaps.append(True)
                return checked

            with patch.object(RETENTION, "_private_directory", side_effect=swap_after_check):
                with self.assertRaisesRegex(
                    RuntimeError, "changed|unsafe|symlink|unavailable"
                ):
                    RETENTION._write_json_atomic(
                        source / "archive-manifest.json",
                        {"schema_version": 1},
                        replace_existing=True,
                    )
            self.assertEqual(swaps, [True])
            self.assertFalse((outside / "archive-manifest.json").exists())
            self.assertEqual(foreign.read_bytes(), b"untouched\n")
            self.assertEqual((saved / "stderr.log").read_bytes(), b"must be retained\n")
            self.assertFalse((saved / "archive-manifest.json").exists())
            self.assertTrue(source.is_symlink())

    def test_archive_apply_rejects_private_destination_swap_before_manifest_write(self) -> None:
        # After verification and move a peer can replace the destination with
        # another owner-private dir. The post-move writer must bind the
        # manifest to the already verified moved inode, never that peer dir.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            job_name = "grabowski-job-999999999999"
            unit = job_name + ".service"
            source = self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            atomic_write = RETENTION._write_json_atomic
            swaps: list[bool] = []
            original_dir = archive / (job_name + "-original")
            destination = archive / job_name

            def replace_source_on_manifest(path: Path, payload: dict, **kwargs):
                if path == destination / "archive-manifest.json" and not swaps:
                    destination.rename(original_dir)
                    destination.mkdir(mode=0o700)
                    marker = destination / "do-not-touch"
                    marker.write_bytes(b"foreign evidence\n")
                    marker.chmod(0o600)
                    swaps.append(True)
                return atomic_write(path, payload, **kwargs)

            with patch.dict(
                "sys.modules",
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base},
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION, "_write_json_atomic", side_effect=replace_source_on_manifest,
            ):
                with self.assertRaisesRegex(RuntimeError, "identity changed|changed during inspection|private child root changed"):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])

            self.assertEqual(swaps, [True])
            self.assertEqual((original_dir / "stderr.log").read_bytes(), b"")
            self.assertFalse((original_dir / "archive-manifest.json").exists())
            self.assertEqual((destination / "do-not-touch").read_bytes(), b"foreign evidence\n")
            self.assertFalse((destination / "archive-manifest.json").exists())
            self.assertFalse(source.exists())
            self.assertFalse(list(receipts.glob("*.json")))
            reset.assert_not_called()
            fake_base._append_audit.assert_called_once()


    def test_atomic_replace_preserves_raced_foreign_target(self) -> None:
        # P1: a same-UID peer can swap a valid private target after stat.
        # An atomic exchange must preserve the foreign object, then fail closed.
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "jobs"
            parent.mkdir(mode=0o700)
            target = parent / "archive-manifest.json"
            old = b"original-index-bytes\\n"
            foreign = b"foreign-index-evidence\\n"
            target.write_bytes(old)
            target.chmod(0o600)
            saved = parent / ".original-index-preserved"
            real_check = RETENTION._archive_require_unchanged_root
            checks = []

            def substitute_after_stat(directory: Path, descriptor: int) -> None:
                checks.append(True)
                if directory == parent and len(checks) == 2:
                    target.rename(saved)
                    target.write_bytes(foreign)
                    target.chmod(0o600)
                return real_check(directory, descriptor)

            with patch.object(
                RETENTION, "_archive_require_unchanged_root",
                side_effect=substitute_after_stat,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed|identity|raced"):
                    RETENTION._write_json_atomic(
                        target, {"schema_version": 1}, replace_existing=True
                    )
            self.assertGreaterEqual(len(checks), 2)
            self.assertEqual(saved.read_bytes(), old)
            self.assertIn(foreign, [p.read_bytes() for p in parent.iterdir() if p.is_file()])

    def test_atomic_replace_retains_prior_evidence_on_success(self) -> None:
        # No unconditional unlink of the former target after publication.
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "jobs"
            parent.mkdir(mode=0o700)
            target = parent / "archive-manifest.json"
            previous = b"previous-authentic-evidence\\n"
            target.write_bytes(previous)
            target.chmod(0o600)
            RETENTION._write_json_atomic(
                target, {"schema_version": 1}, replace_existing=True
            )
            self.assertEqual(json.loads(target.read_text())["schema_version"], 1)
            saved = [p for p in parent.iterdir() if p != target]
            self.assertEqual(len(saved), 1)
            self.assertEqual(saved[0].read_bytes(), previous)
            self.assertEqual(saved[0].stat().st_mode & 0o077, 0)

    def test_atomic_replace_does_not_clobber_new_target_after_absent_probe(self) -> None:
        # replace_existing=True must not imply unconditional replacement when
        # the target did not exist at the initial pinned-root inspection.
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "jobs"
            parent.mkdir(mode=0o700)
            target = parent / "archive-manifest.json"
            peer_data = b"raced-new-entry\\n"
            real_check = RETENTION._archive_require_unchanged_root
            checks = []

            def create_after_absent_probe(directory: Path, descriptor: int) -> None:
                checks.append(True)
                if directory == parent and len(checks) == 2:
                    target.write_bytes(peer_data)
                    target.chmod(0o600)
                return real_check(directory, descriptor)

            with patch.object(
                RETENTION, "_archive_require_unchanged_root",
                side_effect=create_after_absent_probe,
            ):
                with self.assertRaises(FileExistsError):
                    RETENTION._write_json_atomic(
                        target, {"schema_version": 1}, replace_existing=True
                    )
            self.assertEqual(target.read_bytes(), peer_data)

    def test_atomic_temp_replaced_after_failed_noreplace_is_not_deleted(self) -> None:
        # Concurrent same-UID writer moves our temp away and places a foreign
        # private file at the original name after publication failed.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "job"
            directory.mkdir(mode=0o700)
            original_open = RETENTION._archive_open_private_root
            captured: list[int] = []
            swapped: list[str] = []

            def capture_root(path):
                fd = original_open(path)
                captured.append(fd)
                return fd

            def swap_at_rename(source_fd, name, dest_fd, dest_name):
                os.rename(name, ".retained-writer-temp", src_dir_fd=source_fd,
                          dst_dir_fd=source_fd)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=source_fd)
                try:
                    os.write(fd, b"foreign evidence\n")
                finally:
                    os.close(fd)
                swapped.append(name)
                raise FileExistsError("simulated no-clobber refusal")

            with patch.object(
                RETENTION, "_archive_open_private_root", side_effect=capture_root,
            ), patch.object(
                RETENTION, "_archive_rename_noreplace", side_effect=swap_at_rename,
            ):
                with self.assertRaisesRegex(FileExistsError, "no-clobber refusal"):
                    RETENTION._write_json_atomic(
                        directory / "retention-receipt.json", {"schema_version": 3}
                    )
            self.assertEqual(len(swapped), 1)
            self.assertEqual((directory / swapped[0]).read_bytes(), b"foreign evidence\n")
            self.assertTrue((directory / ".retained-writer-temp").is_file())
            self.assertFalse((directory / "retention-receipt.json").exists())
            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_atomic_failed_publication_closes_root_even_if_unlink_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "job"
            directory.mkdir(mode=0o700)
            original_open = RETENTION._archive_open_private_root
            captured: list[int] = []

            def capture_root(path):
                fd = original_open(path)
                captured.append(fd)
                return fd

            with patch.object(
                RETENTION, "_archive_open_private_root", side_effect=capture_root,
            ), patch.object(
                RETENTION, "_archive_rename_noreplace",
                side_effect=FileExistsError("simulated publication collision"),
            ), patch.object(
                RETENTION.os, "unlink",
                side_effect=PermissionError("cannot safely remove untrusted temp"),
            ):
                with self.assertRaisesRegex(FileExistsError, "publication collision"):
                    RETENTION._write_json_atomic(
                        directory / "retention-receipt.json", {"schema_version": 3}
                    )
            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_atomic_manifest_temp_collision_preserves_existing_private_file(self) -> None:
        # O_EXCL can fail after a same-UID peer wins the temp name. Cleanup
        # must not remove the peer's already-existing file.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "job"
            job.mkdir(mode=0o700)
            real_open = os.open
            collided: list[str] = []

            def colliding_open(path, flags, mode=0o777, *, dir_fd=None):
                if (
                    isinstance(path, str)
                    and path.startswith(".archive-manifest.json.")
                    and (flags & os.O_EXCL)
                    and not collided
                ):
                    descriptor = real_open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=dir_fd,
                    )
                    try:
                        os.write(descriptor, b"peer-owned temp evidence\n")
                    finally:
                        os.close(descriptor)
                    collided.append(path)
                    raise FileExistsError("simulated exclusive-temp collision")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with patch.object(RETENTION.os, "open", side_effect=colliding_open):
                with self.assertRaises(FileExistsError):
                    RETENTION._write_json_atomic(
                        job / "archive-manifest.json", {"schema_version": 1}
                    )
            self.assertEqual(len(collided), 1)
            self.assertEqual(
                (job / collided[0]).read_bytes(), b"peer-owned temp evidence\n"
            )
            self.assertFalse((job / "archive-manifest.json").exists())

    def test_archive_move_stays_in_pinned_root_during_parent_symlink_swap(self) -> None:
        # Swapping the archive root after its last absence probe must never move a
        # verified job into the peer's directory or reset its systemd unit.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            job_name = "grabowski-job-eeeeeeeeeeee"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            outside = root / "outside-private-archive"
            outside.mkdir(mode=0o700)
            marker = outside / "do-not-touch"
            marker.write_bytes(b"foreign archive root\n")
            marker.chmod(0o600)
            original_archive = root / "archive-original"
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            real_stat = os.stat
            swaps: list[bool] = []

            def swap_root_after_empty_archive_probe(path, *args, **kwargs):
                descriptor = kwargs.get("dir_fd")
                if (
                    path == job_name
                    and isinstance(descriptor, int)
                    and os.readlink(f"/proc/self/fd/{descriptor}") == str(archive)
                    and not swaps
                ):
                    try:
                        return real_stat(path, *args, **kwargs)
                    except FileNotFoundError:
                        archive.rename(original_archive)
                        archive.symlink_to(outside, target_is_directory=True)
                        swaps.append(True)
                        raise
                return real_stat(path, *args, **kwargs)

            with patch.dict(
                "sys.modules",
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base},
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION.os, "stat", side_effect=swap_root_after_empty_archive_probe
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during inspection"):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])

            self.assertEqual(swaps, [True])
            self.assertEqual(marker.read_bytes(), b"foreign archive root\n")
            self.assertFalse((outside / job_name).exists())
            moved = original_archive / job_name / "stdout.log"
            self.assertTrue(moved.is_file() or (jobs / job_name / "stdout.log").is_file())
            if moved.is_file():
                self.assertEqual(moved.read_bytes(), b"done\n")
            self.assertFalse(list(receipts.glob("*.json")))
            reset.assert_not_called()
            fake_base._append_audit.assert_not_called()

    def test_oversized_stale_archive_manifest_cannot_be_replaced_at_effect_time(self) -> None:
        # The last atomic writer boundary must reject unsafe original evidence.
        with tempfile.TemporaryDirectory() as tmp:
            private_root = Path(tmp) / "job"
            private_root.mkdir(mode=0o700)
            path = private_root / "archive-manifest.json"
            original = b"x" * (RETENTION.MAX_JSON_BYTES + 1)
            path.write_bytes(original)
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "existing evidence is not owner-controlled"):
                RETENTION._write_json_atomic(
                    path, {"schema_version": 1}, replace_existing=True
                )
            self.assertEqual(path.read_bytes(), original)

    def test_periodic_noop_keeps_oversized_artifact_blocker_visible(self) -> None:
        blocked = [{"unit": "grabowski-job-000000000001.service",
                    "reason": "archive source is too large"}]
        plan = {"plan_sha256": "f" * 64, "reset_failed_units": [],
                "archive_jobs": [], "blocked": blocked}
        with patch.object(RETENTION, "build_plan", side_effect=[plan, plan]), patch.object(
            RETENTION, "_apply_periodic_worktree_hygiene", return_value={"completed": True}
        ):
            result = RETENTION.apply_periodic_plan()
        self.assertTrue(result["completed"])
        self.assertFalse(result["mutated"])
        self.assertEqual(result["preserved_blocked_units"], blocked)

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

    def test_reserved_repoground_jobs_enter_typed_retention_and_failed_reset(self) -> None:
        job_name = "grabowski-job-rgpm-" + "a" * 16 + "-01"
        unit = job_name + ".service"
        self.assertIsNotNone(RETENTION.JOB_NAME.fullmatch(job_name))
        self.assertIsNotNone(RETENTION.JOB_UNIT.fullmatch(unit))
        self.assertIsNone(RETENTION.JOB_NAME.fullmatch(job_name + "-extra"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50,
                now=1_000,
                jobs_root=jobs,
                archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3",
                failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertIn(unit, [item["unit"] for item in plan["archive_jobs"]])
            self.assertIn(unit, plan["reset_failed_units"])
            self.assertFalse(
                any(
                    item["unit"] == job_name and "legacy" in item["reason"]
                    for item in plan["blocked"]
                )
            )

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

            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)

            class FakePinnedScan:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def __iter__(self):
                    for index in range(4):
                        consumed.append(index)
                        if index == 3:
                            raise AssertionError("discovery consumed beyond limit + 1")
                        yield types.SimpleNamespace(
                            name=f"grabowski-job-{index + 1:012x}"
                        )

            with (
                patch.object(RETENTION, "MAX_JOB_REGISTRY_ENTRIES", 2),
                patch.object(RETENTION.os, "scandir", return_value=FakePinnedScan()),
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

    def test_archived_failed_job_is_recorded_for_manual_recovery_not_auto_reset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            index = jobs / "runtime-deploy-index.json"
            index.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 0,
            }) + "\n")
            index.chmod(0o600)
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

            self.assertEqual(plan["reset_failed_units"], [])
            self.assertTrue(any(
                row["unit"] == unit and "manual" in row["reason"]
                for row in plan["blocked"]
            ))
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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

    def test_archived_job_hashes_pinned_moved_inode_not_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive = root / "jobs", root / "archive"
            name = "grabowski-job-585858585858"
            self._job(jobs, name, 100)
            archive.mkdir(mode=0o700, exist_ok=True)
            source = jobs / name
            target = archive / name
            expected = RETENTION._archive_file_manifest(source)
            metadata = source.stat()
            source_identity = (metadata.st_dev, metadata.st_ino)
            jobs_identity = (jobs.stat().st_dev, jobs.stat().st_ino)
            archive_identity = (archive.stat().st_dev, archive.stat().st_ino)
            real_path_manifest = RETENTION._archive_file_manifest

            def forbid_archived_path_reopen(directory: Path):
                if directory == target:
                    raise AssertionError("post-move archive may only be read by pinned fd")
                return real_path_manifest(directory)

            with patch.object(
                RETENTION, "_archive_file_manifest",
                side_effect=forbid_archived_path_reopen,
            ):
                RETENTION._archive_move_job_pinned(
                    source, target,
                    source_identity=source_identity,
                    jobs_root_identity=jobs_identity,
                    archive_root_identity=archive_identity,
                    expected_files=expected,
                )
            self.assertFalse(source.exists())
            self.assertEqual(real_path_manifest(target), expected)

    def test_source_basename_swap_at_rename_preserves_foreign_archive_evidence(self) -> None:
        # A same-UID peer can substitute the job basename just before rename.
        # Inode-conditional quarantine cannot be implemented via renameat2;
        # fail closed without renaming or deleting another inode.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            job_name = "grabowski-job-989898989898"
            unit = job_name + ".service"
            source = self._job(jobs, job_name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            saved = jobs / (job_name + "-original")
            real_stat = os.stat
            swaps: list[bool] = []
            reset = Mock(return_value=Mock(returncode=0, stderr=""))

            def swap_source_after_empty_archive_probe(path, *args, **kwargs):
                descriptor = kwargs.get("dir_fd")
                if (
                    path == job_name
                    and isinstance(descriptor, int)
                    and os.readlink(f"/proc/self/fd/{descriptor}") == str(archive)
                    and not swaps
                ):
                    try:
                        return real_stat(path, *args, **kwargs)
                    except FileNotFoundError:
                        source.rename(saved)
                        source.mkdir(mode=0o700)
                        replacement = source / "peer-evidence"
                        replacement.write_bytes(b"never archive peer\n")
                        replacement.chmod(0o600)
                        swaps.append(True)
                        raise
                return real_stat(path, *args, **kwargs)
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_self_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION.os, "stat", side_effect=swap_source_after_empty_archive_probe
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "manual recovery required|archive source file is unavailable|archive source metadata inode drift",
                ):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(swaps, [True])
            # Earlier failure is safer than moving an unauthenticated peer:
            # either root is acceptable only if its evidence is preserved.
            peer = (
                source / "peer-evidence" if source.exists()
                else archive / job_name / "peer-evidence"
            )
            self.assertEqual(peer.read_bytes(), b"never archive peer\n")
            self.assertFalse((archive / job_name / "archive-manifest.json").exists())
            self.assertFalse(list(archive.glob(f".{job_name}.unverified-*")))
            self.assertEqual((saved / "stdout.log").read_bytes(), b"done\n")
            self.assertFalse(list(receipts.glob("*.json")))
            reset.assert_not_called()


    def test_post_move_hash_failure_never_publishes_complete_archive_manifest(self) -> None:
        # Move publication must not precede the hash of the moved inode.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-373737373737"
            unit = name + ".service"
            self._job(jobs, name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            actual_manifest = RETENTION._archive_file_manifest_on_fd

            def tampered_moved_manifest(directory: Path, fd: int):
                if directory == archive / name:
                    return []  # post-move payload no longer matches preimage
                return actual_manifest(directory, fd)

            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_self_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ), patch.object(
                RETENTION, "_archive_file_manifest_on_fd",
                side_effect=tampered_moved_manifest,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "archived job files changed during move"
                ):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertTrue((archive / name / "stdout.log").is_file())
            self.assertFalse((archive / name / "archive-manifest.json").exists())
            self.assertFalse(list(receipts.glob("*.json")))
            reset.assert_not_called()

    def test_quarantine_cannot_rename_unverified_inodes_under_basename_swap(self) -> None:
        # Linux renameat2 lacks an atomic "rename iff this inode" predicate.
        # The safe response to a concurrent peer is to preserve BOTH trees.
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "archive"
            archive.mkdir(mode=0o700)
            name = "grabowski-job-383838383838"
            peer = archive / name
            peer.mkdir(mode=0o700)
            (peer / "peer-marker").write_bytes(b"peer")
            authentic = archive / "authentic"
            authentic.mkdir(mode=0o700)
            (authentic / "trusted-marker").write_bytes(b"trusted")
            observed = peer.stat()
            actual_rename = RETENTION._archive_rename_noreplace
            swaps: list[bool] = []

            def swap_just_before_rename(source_fd, source_name, dest_fd, dest_name):
                if source_name == name:
                    peer.rename(archive / "peer-preimage")
                    authentic.rename(peer)
                    swaps.append(True)
                return actual_rename(source_fd, source_name, dest_fd, dest_name)

            archive_fd = os.open(archive, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    RETENTION, "_archive_rename_noreplace",
                    side_effect=swap_just_before_rename,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "manual|quarantine|identity changed"
                    ):
                        RETENTION._archive_quarantine_mismatched_move(
                            archive_fd, name, (observed.st_dev, observed.st_ino)
                        )
            finally:
                os.close(archive_fd)
            self.assertEqual(swaps, [], "never trust check-then-rename on peer pathname")
            self.assertEqual((peer / "peer-marker").read_bytes(), b"peer")
            self.assertEqual((authentic / "trusted-marker").read_bytes(), b"trusted")

    def test_archive_move_noreplace_preserves_racing_destination(self) -> None:
        # A peer can introduce an empty archive directory after the absent
        # check. renameat2(NOREPLACE) must keep both inodes untouched.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-676767676767"
            unit = name + ".service"
            source = self._job(jobs, name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000, jobs_root=jobs,
                archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            real_stat = os.stat
            injected: list[bool] = []
            reset = Mock(return_value=Mock(returncode=0, stderr=""))

            def appear_after_empty_archive_probe(path, *args, **kwargs):
                descriptor = kwargs.get("dir_fd")
                if (
                    path == name and isinstance(descriptor, int)
                    and os.readlink(f"/proc/self/fd/{descriptor}") == str(archive)
                    and not injected
                ):
                    try:
                        return real_stat(path, *args, **kwargs)
                    except FileNotFoundError:
                        (archive / name).mkdir(mode=0o700)
                        injected.append(True)
                        raise
                return real_stat(path, *args, **kwargs)

            with patch.dict(
                "sys.modules",
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base}
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION.os, "stat", side_effect=appear_after_empty_archive_probe
            ):
                with self.assertRaises((OSError, RuntimeError)):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(injected, [True])
            self.assertTrue((archive / name).is_dir())
            self.assertEqual(list((archive / name).iterdir()), [])
            self.assertEqual((source / "stdout.log").read_bytes(), b"done\n")
            self.assertFalse(list(receipts.glob("*.json")))
            reset.assert_not_called()

    def test_hidden_index_during_verified_move_cannot_reset_stale_member(self) -> None:
        # The source job really moves in this apply. An attacker hides the
        # index ONLY for the pinned read and restores it before reset-failed.
        # The existing index membership must be reconciled or reset blocked.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-515151515151"
            unit = name + ".service"
            self._job(jobs, name, 100)
            index_file = jobs / "runtime-deploy-index.json"
            index_file.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }) + "\n")
            index_file.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                failed_units=[unit], unit_states=states,
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            index_file.write_text(json.dumps({"schema_version": 1, "units": [name], "pending_unit": None, "updated_at_unix": 600}) + "\n")
            real_read = RETENTION._archive_read_deploy_index_pinned
            seen = []
            def missing_only_initially(*args, **kwargs):
                result = real_read(*args, **kwargs)
                if not seen:
                    seen.append(True)
                    self.assertEqual(result["units"], [name])
                    return None
                return result
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_run", reset
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_archive_read_deploy_index_pinned",
                side_effect=missing_only_initially,
            ):
                with self.assertRaises((FileExistsError, RuntimeError)):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(seen, [True])
            self.assertEqual(json.loads(index_file.read_text())["units"], [name])
            self.assertTrue((jobs / name / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            reset.assert_not_called()

    def test_missing_index_never_claimed_before_archiving(self) -> None:
        # Missing deployment index cannot prove nonmembership. The retention
        # planner must not synthesize an empty canonical control-plane index.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-525252525252"
            unit = name + ".service"
            job = self._job(jobs, name, 100)
            index = jobs / "runtime-deploy-index.json"
            index.unlink()  # this test-owned fixture deliberately has no index
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [])
            self.assertTrue(any("index absent" in row["reason"] for row in plan["blocked"]))
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertTrue((job / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertFalse(index.exists())
            reset.assert_not_called()

    def test_missing_index_does_not_hide_live_bootstrap_deployments(self) -> None:
        # Codex P1: creating an empty index (or an unpinned bootstrap) hides
        # running deploy/resume jobs. Require explicit recovery instead.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-585858585858"
            unit = name + ".service"
            live_name = "grabowski-job-595959595959"
            live_unit = live_name + ".service"
            old = self._job(jobs, name, 100)
            live = self._job(jobs, live_name, 990, runtime_seconds=500)
            index = jobs / "runtime-deploy-index.json"
            index.unlink()  # source index is deliberately absent
            states = {
                unit: self._state(unit),
                live_unit: self._state(live_unit, active="active", load="loaded"),
            }
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["archive_jobs"], [])
            bootstrap = Mock(return_value={
                "schema_version": 1, "units": [live_name],
                "pending_unit": None, "updated_at_unix": 500,
            })
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_deploy._bootstrap_deploy_index = bootstrap
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            bootstrap.assert_not_called()
            self.assertTrue((old / "metadata.json").is_file())
            self.assertTrue((live / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertFalse(index.exists())
            reset.assert_not_called()

    def test_pending_deployment_added_after_plan_blocks_live_reset(self) -> None:
        # Forged/stale self-hashed plans do not authorize reset-failed of a
        # live, pending runtime deployment reservation.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-606060606060"
            unit = name + ".service"
            job = self._job(jobs, name, int(RETENTION.time.time()) - 400)
            now = int(RETENTION.time.time())
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=600, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["reset_failed_units"], [unit])
            index = jobs / "runtime-deploy-index.json"
            index.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": name, "updated_at_unix": 500,
            }) + "\n")
            index.chmod(0o600)
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete"
                ):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            self.assertTrue((job / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertEqual(json.loads(index.read_text())["pending_unit"], name)
            reset.assert_not_called()

    def test_pending_deployment_reservation_blocks_archival_before_move(self) -> None:
        # A plan built while the index was empty loses authorization if a
        # pending reservation appears before apply. No archive move or reset.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-565656565656"
            unit = name + ".service"
            job = self._job(jobs, name, 100)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual([row["unit"] for row in plan["archive_jobs"]], [unit])
            index = jobs / "runtime-deploy-index.json"
            index.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": name, "updated_at_unix": 500,
            }) + "\n")
            index.chmod(0o600)
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                with self.assertRaisesRegex(RuntimeError, "pending deployment job"):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            self.assertTrue((job / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertEqual(json.loads(index.read_text())["pending_unit"], name)
            reset.assert_not_called()

    def test_pending_plan_blocks_reservation_and_archives_unrelated_safe_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            pending_name = "grabowski-job-626262626262"
            safe_name = "grabowski-job-636363636363"
            pending_unit, safe_unit = pending_name + ".service", safe_name + ".service"
            self._job(jobs, pending_name, 100)
            self._job(jobs, safe_name, 100)
            index = jobs / "runtime-deploy-index.json"
            index.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": pending_name, "updated_at_unix": 500,
            }) + "\n")
            index.chmod(0o600)
            states = {
                pending_unit: self._state(pending_unit),
                safe_unit: self._state(safe_unit),
            }
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[pending_unit],
                unit_states=states,
            )
            self.assertEqual(
                [row["unit"] for row in plan["archive_jobs"]], [safe_unit]
            )
            self.assertNotIn(pending_unit, plan["reset_failed_units"])
            self.assertTrue(any(
                row["unit"] == pending_unit and "pending" in row["reason"]
                for row in plan["blocked"]
            ))

    def test_missing_current_deployment_index_blocks_postmove_reset(self) -> None:
        # A peer can hide the index during the post-move reset authorization.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-575757575757"
            unit = name + ".service"
            self._job(jobs, name, 100)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            real_read = RETENTION._archive_read_deploy_index_pinned
            observed = []
            def invisible_only_at_reset(*args, **kwargs):
                value = real_read(*args, **kwargs)
                observed.append(value)
                return None if len(observed) == 3 else value
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_archive_read_deploy_index_pinned",
                side_effect=invisible_only_at_reset
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete"
                ):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(len(observed), 3)
            self.assertIsNotNone(observed[0])
            self.assertTrue((archive / name / "archive-manifest.json").is_file())
            self.assertTrue((jobs / "runtime-deploy-index.json").is_file())
            reset.assert_not_called()

    def test_manifest_exchange_rolls_back_raced_canonical_target(self) -> None:
        # Independent R3 P1: a same-UID peer substitutes index B
        # immediately before EXCHANGE. Do not leave stale payload at the
        # canonical index name even after detecting the displaced inode.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "jobs"
            directory.mkdir(mode=0o700)
            target = directory / "archive-manifest.json"
            original = b'{"schema_version":1,"units":["original"]}\n'
            foreign = b'{"schema_version":1,"units":["foreign"]}\n'
            target.write_bytes(original)
            target.chmod(0o600)
            pinned_fd = RETENTION._archive_open_private_root(directory)
            try:
                _, token = RETENTION._archive_pinned_json_preimage(
                    pinned_fd, target.name
                )
            finally:
                os.close(pinned_fd)
            real_exchange = RETENTION._archive_rename_exchange
            exchanges = []
            def swap_just_before_exchange(fd: int, incoming: str, published: str):
                exchanges.append(True)
                if len(exchanges) == 1:
                    target.rename(directory / "original-index-preserved")
                    target.write_bytes(foreign)
                    target.chmod(0o600)
                return real_exchange(fd, incoming, published)
            with patch.object(
                RETENTION, "_archive_rename_exchange",
                side_effect=swap_just_before_exchange,
            ):
                with self.assertRaisesRegex(RuntimeError, "changed|identity|exchange"):
                    RETENTION._write_json_atomic(
                        target, {"schema_version": 1, "units": []},
                        replace_existing=True,
                        expected_existing_preimage=token,
                    )
            self.assertGreaterEqual(len(exchanges), 2, "must undo stale exchange")
            self.assertEqual(target.read_bytes(), foreign)
            self.assertEqual((directory / "original-index-preserved").read_bytes(), original)
            self.assertTrue(any(
                p.name.startswith(".archive-manifest.json.")
                and p.read_bytes().startswith(b"{")
                for p in directory.iterdir() if p.is_file() and p != target
            ))

    def test_exhausted_manifest_temps_block_only_the_affected_job(self) -> None:
        # Codex P2: apply-time temp exhaustion must not repeatedly starve
        # other safe jobs in the planner's bounded archive batch.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            bad_name = "grabowski-job-656565656565"
            good_name = "grabowski-job-666666666666"
            bad, good = bad_name + ".service", good_name + ".service"
            source_bad = self._job(jobs, bad_name, 100)
            self._job(jobs, good_name, 101)
            for serial in range(1, 4):
                temp = source_bad / f".archive-manifest.json.123.{serial}.tmp"
                temp.write_text("retained evidence\n")
                temp.chmod(0o600)
            states = {bad: self._state(bad), good: self._state(good)}
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.object(RETENTION, "MAX_RETAINED_JSON_TEMPS", 3):
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50, now=1000,
                    jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                    task_db=root / "missing.sqlite3", failed_units=[bad, good],
                    unit_states=states,
                )
                self.assertEqual(
                    [entry["unit"] for entry in plan["archive_jobs"]], [good]
                )
                self.assertTrue(any(
                    row["unit"] == bad and "temp" in row["reason"]
                    for row in plan["blocked"]
                ))
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy,
                    "grabowski_mcp": fake_base,
                }), patch.object(RETENTION, "_run", reset), patch.object(
                    RETENTION, "_systemd_unit_states", return_value=states
                ):
                    result = RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            self.assertTrue(result["completed"])
            self.assertTrue((source_bad / "metadata.json").is_file())
            self.assertFalse((archive / bad_name).exists())
            self.assertTrue((archive / good_name / "archive-manifest.json").is_file())
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", good]
            )

    def test_manifest_temp_budget_preflight_prevents_orphan_archive_move(self) -> None:
        # Independent R3 P2: reject exhausted manifest temp budget BEFORE move,
        # not after successful irreversible archive publication.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-535353535353"
            unit = name + ".service"
            source = self._job(jobs, name, 100)
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps({
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }) + "\n")
            index_path.chmod(0o600)
            for seq in range(3):
                orphan = source / f".archive-manifest.json.123.{seq + 1}.tmp"
                orphan.write_text(f"prior-{seq}\n")
                orphan.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "MAX_RETAINED_JSON_TEMPS", 3
            ):
                with self.assertRaisesRegex(RuntimeError, "retained.*temp|temp.*bound"):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertTrue((source / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            reset.assert_not_called()

    def test_live_indexed_reset_keeps_verified_fd_open_through_systemd_action(self) -> None:
        # Independent R3 P2: a live pathname can be swapped after its
        # inode/digest validation but before systemctl reset-failed.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-545454545454"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            job = self._job(jobs, name, now - 400)
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps({
                "schema_version": 1, "units": [name],
                "pending_unit": None, "updated_at_unix": now - 500,
            }) + "\n")
            index_path.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=500, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            real_open = RETENTION._archive_open_child_root
            live_descriptors = []
            inspected = []
            original = job.stat()
            def record_fd(parent_fd, child_name, path):
                fd = real_open(parent_fd, child_name, path)
                if path == job:
                    live_descriptors.append(fd)
                return fd
            def reset_observer(actual_unit):
                self.assertEqual(actual_unit, unit)
                held = False
                for fd in live_descriptors:
                    try:
                        metadata = os.fstat(fd)
                    except OSError:
                        continue
                    if (metadata.st_dev, metadata.st_ino) == (original.st_dev, original.st_ino):
                        held = True
                self.assertTrue(held, "live original job inode not pinned through reset")
                inspected.append(True)
                return {"unit": unit, "returncode": 0, "stderr_sha256": "0" * 64}
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_archive_open_child_root", side_effect=record_fd
            ), patch.object(
                RETENTION, "_reset_failed", side_effect=reset_observer
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertEqual(inspected, [True])

    def test_changed_index_after_pinned_read_cannot_drop_foreign_members(self) -> None:
        # R3 P1: after snapshot A, a same-UID peer replaces the index
        # with B containing unrelated members. Writer must refuse the
        # stale A-based update; even EXCHANGE may not publish it.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-505050505050"
            other = "grabowski-job-505050505051"
            newly_added = "grabowski-job-505050505052"
            unit = name + ".service"
            self._job(jobs, name, 100)
            index_file = jobs / "runtime-deploy-index.json"
            first_index = {
                "schema_version": 1, "units": [other],
                "pending_unit": None, "updated_at_unix": 500,
            }
            index_file.write_text(json.dumps(first_index) + "\n")
            index_file.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            real_read = RETENTION._archive_read_deploy_index_pinned
            mutated = []
            foreign_data = json.dumps({
                **first_index, "units": [name, other, newly_added],
                "updated_at_unix": 900,
            }) + "\n"
            def race_after_read(*args, **kwargs):
                result = real_read(*args, **kwargs)
                if not mutated:
                    index_file.rename(root / "preimage-index")
                    index_file.write_text(foreign_data)
                    index_file.chmod(0o600)
                    mutated.append(True)
                return result
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_archive_read_deploy_index_pinned", side_effect=race_after_read
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "index.*changed|index.*identity|index.*snapshot"
                ):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(mutated, [True])
            self.assertEqual(index_file.read_text(), foreign_data)
            self.assertEqual(
                json.loads((root / "preimage-index").read_text())["units"],
                [other],
            )
            reset.assert_not_called()


    def test_index_membership_snapshot_omission_cannot_reset_archived_unit(self) -> None:
        # A self-hashed historical manifest plus transient empty index view
        # cannot authorize reset after the live source has disappeared.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-484848484848"
            unit = name + ".service"
            job = self._job(jobs, name, 100)
            archive.mkdir(mode=0o700, exist_ok=True)
            destination = archive / name
            job.rename(destination)
            files = RETENTION._archive_file_manifest(destination)
            manifest = {
                "schema_version": 1,
                "unit": unit,
                "job_name": name,
                "source": str(jobs / name),
                "archived_at_unix": 1000,
                "plan_sha256": "a" * 64,
                "terminal_evidence": "runtime_bound_expired",
                "files": files,
            }
            manifest["manifest_sha256"] = RETENTION._sha256(manifest)
            manifest_path = destination / "archive-manifest.json"
            manifest_path.write_text(json.dumps(manifest) + "\n")
            manifest_path.chmod(0o600)
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps({
                "schema_version": 1, "units": [name],
                "pending_unit": None, "updated_at_unix": 500,
            }) + "\n")
            index_path.chmod(0o600)
            plan = RETENTION.build_plan(
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={},
            )
            self.assertEqual(plan["reset_failed_units"], [])
            self.assertEqual(
                [item["unit"] for item in plan["recovered_archived_failed_units"]],
                [unit],
            )
            forged = json.loads(json.dumps(plan))
            forged["reset_failed_units"] = [unit]
            forged["recovered_archived_failed_units"] = []
            forged["plan_sha256"] = RETENTION._sha256({
                key: val for key, val in forged.items() if key != "plan_sha256"
            })
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            real_reader = RETENTION._archive_read_deploy_index_pinned
            def hide_membership(*args, **kwargs):
                observed = real_reader(*args, **kwargs)
                if observed is not None:
                    return {**observed, "units": []}
                return None
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_archive_read_deploy_index_pinned",
                side_effect=hide_membership
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete|lacks trusted in-process root custody"
                ):
                    RETENTION.apply_plan(
                        forged, expected_plan_sha256=forged["plan_sha256"]
                    )
            self.assertEqual(json.loads(index_path.read_text())["units"], [name])
            self.assertTrue(manifest_path.is_file())
            reset.assert_not_called()

    def test_rehashed_plan_cannot_widen_indexed_job_archive_age(self) -> None:
        # Independent R3 P2: no self-hashed caller plan may turn a
        # day-old failed indexed job into a recent one eligible for reset.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-494949494949"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            source = self._job(jobs, name, now - 100_000)
            index_file = jobs / "runtime-deploy-index.json"
            index_file.write_text(json.dumps({
                "schema_version": 1, "units": [name],
                "pending_unit": None, "updated_at_unix": now - 200,
            }) + "\n")
            index_file.chmod(0o600)
            states = {unit: self._state(unit)}
            widened = RETENTION.build_plan(
                minimum_job_age_seconds=31_536_000, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(widened["archive_jobs"], [])
            self.assertEqual(widened["reset_failed_units"], [])
            self.assertTrue(any(
                row["unit"] == unit and "archive age" in row["reason"]
                for row in widened["blocked"]
            ))
            # A caller can still add the reset back and recompute the
            # self-hash; apply must refuse it using the intrinsic day bound.
            forged = json.loads(json.dumps(widened))
            forged["reset_failed_units"] = [unit]
            forged["plan_sha256"] = RETENTION._sha256({
                key: val for key, val in forged.items() if key != "plan_sha256"
            })
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete|lacks trusted in-process root custody"
                ):
                    RETENTION.apply_plan(
                        forged, expected_plan_sha256=forged["plan_sha256"]
                    )
            self.assertTrue((source / "metadata.json").is_file())
            self.assertEqual(json.loads(index_file.read_text())["units"], [name])
            reset.assert_not_called()

    def test_retained_atomic_temp_cap_blocks_without_unlinking_evidence(self) -> None:
        # Independent R3 P3: index revisions and receipt collision temps
        # must share a bounded per-directory retention budget.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "jobs"
            directory.mkdir(mode=0o700)
            index = directory / "archive-manifest.json"
            index.write_bytes(b"legacy-evidence\n")
            index.chmod(0o600)
            with patch.object(RETENTION, "MAX_RETAINED_JSON_TEMPS", 3, create=True):
                for version in range(3):
                    RETENTION._write_json_atomic(
                        index, {"schema_version": version}, replace_existing=True
                    )
                before = sorted(p.name for p in directory.iterdir())
                self.assertEqual(len(before), 4)
                with self.assertRaisesRegex(RuntimeError, "retained.*temp|temp.*bound"):
                    RETENTION._write_json_atomic(
                        index, {"schema_version": 4}, replace_existing=True
                    )
                with self.assertRaisesRegex(RuntimeError, "retained.*temp|temp.*bound"):
                    RETENTION._write_json_atomic(
                        directory / "unrelated-receipt.json", {"schema_version": 5}
                    )
            self.assertEqual(sorted(p.name for p in directory.iterdir()), before)
            self.assertEqual(json.loads(index.read_text())["schema_version"], 2)
            self.assertIn(
                b"legacy-evidence\n", [p.read_bytes() for p in directory.iterdir()]
            )

    def test_indexed_live_source_aba_swap_cannot_authorize_reset(self) -> None:
        # P1: a same-UID writer can temporarily present a younger registry
        # directory during path-based _job_record, then restore the older
        # directory before a pinned-fd/path identity check.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            name = "grabowski-job-474747474747"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            young = self._job(jobs, name, now - 400)
            old = self._job(root / "old-jobs", name, now - 1_200)
            held_young = root / "held-young"
            parked_old = root / "parked-old"
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps({
                "schema_version": 1, "units": [name],
                "pending_unit": None, "updated_at_unix": now - 600,
            }) + "\n", encoding="utf-8")
            index_path.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=500, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3",
                failed_units=[unit], unit_states=states,
            )
            self.assertEqual(plan["reset_failed_units"], [unit])
            self.assertEqual(plan["archive_jobs"], [])
            young.rename(held_young)
            old.rename(jobs / name)
            actual_reader = RETENTION._job_record
            swaps = []

            def briefly_swap_source(*args, **kwargs):
                (jobs / name).rename(parked_old)
                held_young.rename(jobs / name)
                try:
                    observed = actual_reader(*args, **kwargs)
                    swaps.append(observed["archive"])
                    return observed
                finally:
                    (jobs / name).rename(held_young)
                    parked_old.rename(jobs / name)

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(
                RETENTION, "_job_record", side_effect=briefly_swap_source
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete"
                ):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            self.assertEqual(swaps, [False], "the attacker presented younger metadata")
            reset.assert_not_called()
            self.assertEqual(
                json.loads((jobs / name / "metadata.json").read_text())["created_at_unix"],
                now - 1_200,
            )
            self.assertEqual(json.loads(index_path.read_text())["units"], [name])


    def test_forged_recovery_plan_cannot_reset_indexed_moved_archive(self) -> None:
        # Even if a caller re-hashes a forged plan and adds an indexed job to
        # the archive+reset batch, current indexed membership blocks the move.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-464646464646"
            unit = name + ".service"
            source = self._job(jobs, name, 100)
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps({
                "schema_version": 1, "units": [name],
                "pending_unit": None, "updated_at_unix": 500,
            }) + "\n")
            index_path.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["archive_jobs"], [])
            record = RETENTION._job_record(
                unit, jobs, now=1000, minimum_age_seconds=50,
                systemd_state=states[unit],
            )
            self.assertTrue(record["archive"])
            forged = json.loads(json.dumps(plan))
            forged["archive_jobs"] = [record]
            forged["reset_failed_units"] = [unit]
            forged["plan_sha256"] = RETENTION._sha256({
                key: val for key, val in forged.items() if key != "plan_sha256"
            })
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                with self.assertRaisesRegex(RuntimeError, "indexed deployment archive|lacks trusted in-process root custody"):
                    RETENTION.apply_plan(
                        forged, expected_plan_sha256=forged["plan_sha256"]
                    )
            self.assertTrue((source / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertEqual(json.loads(index_path.read_text())["units"], [name])
            reset.assert_not_called()

    def test_recent_indexed_failed_job_can_reset_without_archive_recovery(self) -> None:
        # Codex P1: a live terminal job younger than the retention age
        # remains in the deploy index. Its verified local failed-state reset
        # does not use an untrusted historical archive receipt.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-414141414141"
            unit = name + ".service"
            observed_now = int(RETENTION.time.time())
            source = self._job(jobs, name, observed_now - 400)
            index_file = jobs / "runtime-deploy-index.json"
            index_file.write_text(json.dumps({
                "schema_version": 1, "units": [name], "pending_unit": None,
                "updated_at_unix": 500,
            }) + "\n", encoding="utf-8")
            index_file.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=500, now=observed_now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["recovered_archived_failed_units"], [])
            self.assertEqual(plan["reset_failed_units"], [unit])
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_self_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ), patch.object(RETENTION, "_run", reset):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertEqual([r["unit"] for r in result["reset_failed"]], [unit])
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", unit]
            )
            self.assertTrue((source / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertEqual(json.loads(index_file.read_text())["units"], [name])


    def test_post_move_archive_without_trusted_proof_preserves_index_and_failed_unit(self) -> None:
        # A self-hashed plan cannot turn an indexed live deployment into a
        # disposable archive or reset. It remains blocked without partial retries.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-454545454545"
            unit = name + ".service"
            source = self._job(jobs, name, 100)
            index_path = jobs / "runtime-deploy-index.json"
            value = {"schema_version": 1, "units": [name],
                     "pending_unit": None, "updated_at_unix": 500}
            index_path.write_text(json.dumps(value) + "\n")
            index_path.chmod(0o600)
            states = {unit: self._state(unit)}
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states=states,
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertTrue(any("indexed deployment" in row["reason"]
                                for row in plan["blocked"]))
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_deploy._write_deploy_index = Mock(
                side_effect=AssertionError("unsafe control-plane index write")
            )
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_run", reset
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value=states
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertFalse(result["retry"]["required"])
            self.assertEqual(result["archived_jobs"], [])
            self.assertTrue((source / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            self.assertEqual(json.loads(index_path.read_text()), value)
            fake_deploy._write_deploy_index.assert_not_called()
            reset.assert_not_called()

    def test_index_remains_unchanged_if_archive_move_fails(self) -> None:
        # R3 P3: index forget must occur only after verified archive effects.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            job_name = "grabowski-job-565656565656"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            index_path = jobs / "runtime-deploy-index.json"
            old_index = {
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }
            initial = json.dumps(old_index, sort_keys=True).encode() + b"\n"
            index_path.write_bytes(initial)
            index_path.chmod(0o600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: old_index
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_self_deploy,
                "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION, "_archive_move_job_pinned",
                side_effect=RuntimeError("simulated verified move failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "verified move failure"):
                    RETENTION.apply_plan(plan, expected_plan_sha256=plan["plan_sha256"])
            self.assertEqual(index_path.read_bytes(), initial)
            self.assertTrue((jobs / job_name / "metadata.json").is_file())
            self.assertFalse((archive / job_name).exists())
            reset.assert_not_called()

    def test_archive_index_update_uses_pinned_jobs_root_not_path_writer(self) -> None:
        # The ordinary self-deploy writer addresses jobs_root by path and
        # cannot attest that it still names the root scanned by retention.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            job_name = "grabowski-job-121212121212"
            unit = job_name + ".service"
            self._job(jobs, job_name, 100)
            index_path = jobs / "runtime-deploy-index.json"
            old_index = {
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }
            index_path.write_text(json.dumps(old_index) + "\n", encoding="utf-8")
            index_path.chmod(0o600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: old_index
            fake_self_deploy._write_deploy_index = Mock(
                side_effect=AssertionError("unsafe unpinned deploy-index writer")
            )
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict(
                "sys.modules",
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base},
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: self._state(unit)}
            ):
                receipt = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(receipt["completed"])
            self.assertTrue((archive / job_name / "archive-manifest.json").is_file())
            updated_index = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(updated_index["schema_version"], 1)
            self.assertEqual(updated_index["units"], [])
            self.assertIsNone(updated_index["pending_unit"])
            self.assertEqual(updated_index, old_index)
            fake_self_deploy._write_deploy_index.assert_not_called()

    def test_archive_index_reader_uses_fd_not_swapped_jobs_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-575757575757"
            unit = name + ".service"
            self._job(jobs, name, 100)
            original_index = {
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }
            index = jobs / "runtime-deploy-index.json"
            index.write_text(json.dumps(original_index) + "\n")
            index.chmod(0o600)
            forged = root / "forged-index-root"
            forged.mkdir(mode=0o700)
            (forged / "runtime-deploy-index.json").write_text(json.dumps({
                **original_index, "units": [name],
            }) + "\n")
            (forged / "runtime-deploy-index.json").chmod(0o600)
            hidden = root / "original-index-root"
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            unsafe_path_reads: list[str] = []

            def forged_path_read(path: Path) -> dict:
                # Simulate same-UID swap and restore entirely inside the
                # path reader, so a later path/FD root-identity test passes.
                jobs.rename(hidden)
                jobs.symlink_to(forged, target_is_directory=True)
                try:
                    unsafe_path_reads.append(str(path))
                    return json.loads(
                        (path / "runtime-deploy-index.json").read_text()
                    )
                finally:
                    jobs.unlink()
                    hidden.rename(jobs)

            fake_self_deploy = types.ModuleType("grabowski_self_deploy")
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = forged_path_read
            fake_self_deploy._write_deploy_index = Mock(
                side_effect=AssertionError("path-based index writer prohibited")
            )
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            with patch.dict(
                "sys.modules",
                {"grabowski_self_deploy": fake_self_deploy, "grabowski_mcp": fake_base},
            ), patch.object(
                RETENTION, "_run",
                return_value=Mock(returncode=0, stderr=""),
            ), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertEqual(unsafe_path_reads, [])
            self.assertEqual(json.loads(index.read_text())["units"], [])
            self.assertTrue((archive / name / "archive-manifest.json").is_file())


    def test_archive_root_swap_after_plan_before_apply_must_fail_closed(self) -> None:
        # A real swap, not a mock hook that might never be invoked. Both
        # directories are user-private; the original plan held the first FD.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-a2a2a2a2a2a2"
            unit = name + ".service"
            self._job(jobs, name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(len(plan["archive_jobs"]), 1)
            foreign = root / "foreign-archive"
            foreign.mkdir(mode=0o700)
            hidden = root / "authentic-archive"
            archive.rename(hidden)
            foreign.rename(archive)
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
                }), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ), patch.object(RETENTION, "_run", reset):
                    with self.assertRaisesRegex(
                        RuntimeError, "root changed|source directory changed",
                    ):
                        RETENTION.apply_plan(
                            plan, expected_plan_sha256=plan["plan_sha256"]
                        )
                self.assertFalse((archive / name).exists())
                self.assertFalse((hidden / name).exists())
                self.assertTrue((jobs / name / "metadata.json").is_file())
                reset.assert_not_called()
                fake_base._append_audit.assert_not_called()
            finally:
                archive.rename(foreign)
                hidden.rename(archive)

    def test_prepare_swap_and_back_must_not_use_foreign_file_manifest(self) -> None:
        # RED for material P2-B: a held root FD is security-relevant only if
        # the subsequent file inspection uses that same verified root.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-b2b2b2b2b2b2"
            unit = name + ".service"
            genuine = self._job(jobs, name, 100)
            genuine_manifest = RETENTION._archive_file_manifest(genuine)
            foreign = root / "foreign-jobs"
            counterfeit = self._job(foreign, name, 100)
            (counterfeit / "stdout.log").write_text("foreign-evidence\n")
            (counterfeit / "stdout.log").chmod(0o600)
            hidden = root / "hidden-jobs"
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            original_record = RETENTION._job_record
            original_require = RETENTION._archive_require_unchanged_root
            swapped = [False]
            restored = [False]
            source_checks = [0]

            def swap_before_record(
                record_unit: str, record_root: Path, **kwargs: object
            ) -> dict[str, object]:
                if record_root == jobs and not swapped[0]:
                    jobs.rename(hidden)
                    foreign.rename(jobs)
                    swapped[0] = True
                return original_record(record_unit, record_root, **kwargs)

            def restore_after_source_check(path: Path, fd: int) -> None:
                original_require(path, fd)
                if path == jobs / name and swapped[0] and not restored[0]:
                    source_checks[0] += 1
                    if source_checks[0] == 2:
                        # First check belongs to manifest(), second to the
                        # surrounding source-FD pin. Swap back only after
                        # both observed the foreign inode.
                        jobs.rename(foreign)
                        hidden.rename(jobs)
                        restored[0] = True

            prepared = None
            try:
                with patch.object(
                    RETENTION, "_job_record", side_effect=swap_before_record
                ), patch.object(
                    RETENTION, "_archive_require_unchanged_root",
                    side_effect=restore_after_source_check,
                ), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    try:
                        prepared = RETENTION._prepare_archives(plan)[3]
                    except (RuntimeError, OSError):
                        pass  # Fail closed is allowed.
            finally:
                if swapped[0] and not restored[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
            if prepared:
                self.assertEqual(
                    prepared[0]["files"], genuine_manifest,
                    "foreign files were used for the pinned real root's archive plan",
                )
            self.assertTrue((jobs / name / "metadata.json").is_file())

    def test_build_plan_swap_and_back_must_not_mix_foreign_inventory(self) -> None:
        # RED for P2-C: enumerating by pathname after releasing the original
        # jobs-root FD can mix foreign entries with the genuine index.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            genuine_name = "grabowski-job-c2c2c2c2c2c2"
            foreign_names = ["grabowski-job-d2d2d2d2d2d2", "grabowski-job-e2e2e2e2e2e2"]
            self._job(jobs, genuine_name, 100)
            foreign = root / "foreign-jobs"
            for name in foreign_names:
                self._job(foreign, name, 100)
            hidden = root / "hidden-jobs"
            original_require = RETENTION._archive_require_unchanged_root
            original_open = RETENTION._archive_open_private_root
            swapped = [False]
            restored = [False]

            def swap_after_initial_check(path: Path, fd: int) -> None:
                original_require(path, fd)
                if path == jobs and not swapped[0]:
                    jobs.rename(hidden)
                    foreign.rename(jobs)
                    swapped[0] = True

            def restore_before_later_open(
                path: Path, *, allow_readable_parent: bool = False,
            ) -> int:
                if path == jobs and swapped[0] and not restored[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
                    restored[0] = True
                return original_open(
                    path, allow_readable_parent=allow_readable_parent
                )

            state = {
                name + ".service": self._state(name + ".service")
                for name in [genuine_name, *foreign_names]
            }
            plan = None
            try:
                with patch.object(
                    RETENTION, "_archive_require_unchanged_root",
                    side_effect=swap_after_initial_check,
                ), patch.object(
                    RETENTION, "_archive_open_private_root",
                    side_effect=restore_before_later_open,
                ):
                    try:
                        plan = RETENTION.build_plan(
                            minimum_job_age_seconds=50, now=1000,
                            jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                            task_db=root / "missing.sqlite3", failed_units=[],
                            unit_states=state,
                        )
                    except (RuntimeError, OSError):
                        pass  # Fail-closed is acceptable.
            finally:
                if swapped[0] and not restored[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
            if plan is not None:
                self.assertEqual(
                    plan["job_registry_entry_count"], 1,
                    "foreign job count was mixed with genuine deployment index",
                )
            self.assertTrue((jobs / genuine_name / "metadata.json").is_file())

    def test_production_job_archive_and_reset_fail_closed_without_broker(self) -> None:
        self.assertFalse(PRODUCTION_JOB_RETENTION_AUTHORITY())
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            name = "grabowski-job-aaaaaaaaaaaa"
            unit = name + ".service"
            self._job(jobs, name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [])
            self.assertTrue(any(
                blocked["unit"] == unit and "protected root/index authority" in blocked["reason"]
                for blocked in plan["blocked"]
            ))
            self.assertTrue((jobs / name / "metadata.json").is_file())
            # A plan created under simulated privilege cannot later be
            # applied without it: the irreversible effect boundary denies.
            self._simulated_protected_authority.return_value = True
            unsafe_plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=root / "archive",
                receipt_root=root / "receipts",
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertTrue(unsafe_plan["archive_jobs"] or unsafe_plan["reset_failed_units"])
            self._simulated_protected_authority.return_value = False
            with self.assertRaisesRegex(RuntimeError, "protected root/index authority"):
                RETENTION.apply_plan(
                    unsafe_plan, expected_plan_sha256=unsafe_plan["plan_sha256"]
                )
            self.assertTrue((jobs / name / "metadata.json").is_file())
            self.assertFalse((root / "archive" / name).exists())

    def test_untrusted_job_retention_still_resets_independent_terminal_task(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            job = "grabowski-job-bbbbbbbbbbbb"
            job_unit = job + ".service"
            self._job(jobs, job, 100)
            (root / "archive").mkdir(mode=0o700, exist_ok=True)
            (root / "receipts").mkdir(mode=0o700, exist_ok=True)
            task_unit = "grabowski-task-" + "c" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000, jobs_root=jobs,
                archive_root=root / "archive", receipt_root=root / "receipts",
                task_db=task_db, failed_units=[job_unit, task_unit],
                unit_states={job_unit: self._state(job_unit)},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [task_unit])
            self.assertTrue(any(item["unit"] == job_unit for item in plan["blocked"]))
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_deploy._read_deploy_index = lambda _root: None
            fake_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset):
                receipt = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(receipt["completed"])
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", task_unit]
            )
            self.assertEqual([item["unit"] for item in receipt["reset_failed"]], [task_unit])
            self.assertTrue((jobs / job / "metadata.json").is_file())
            self.assertFalse((root / "archive" / job).exists())

    def test_corrupt_deploy_index_does_not_block_unrelated_task_plan(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            index = jobs / "runtime-deploy-index.json"
            index.write_text("{invalid-json\n", encoding="utf-8")
            index.chmod(0o600)
            task_unit = "grabowski-task-" + "c" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=root / "archive",
                receipt_root=root / "receipts", task_db=task_db,
                failed_units=[task_unit], unit_states={},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [task_unit])

    def test_missing_archive_root_does_not_block_task_only_reset(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            jobs.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            self.assertFalse(archive.exists())
            task_unit = "grabowski-task-" + "d" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=task_db, failed_units=[task_unit], unit_states={},
            )
            self.assertEqual(plan["reset_failed_units"], [task_unit])
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset):
                receipt = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(receipt["completed"])
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", task_unit]
            )
            self.assertFalse(archive.exists())

    def test_world_readable_owner_state_parent_does_not_block_task_reset(self) -> None:
        # The shared ~/.local/state/grabowski parent may be 0755; it must
        # not be chmodded or mistaken for the private 0700 receipts leaf.
        # With production job effects disabled, no archive parent is needed.
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            jobs, receipts = root / "jobs", root / "receipts"
            archive = root / "absent-parent" / "job-archive"
            jobs.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            self.assertFalse(archive.parent.exists())
            unit = "grabowski-task-" + "1" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive,
                receipt_root=receipts, task_db=task_db,
                failed_units=[unit], unit_states={},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [unit])
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset):
                receipt = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(receipt["completed"])
            reset.assert_called_once_with(
                ["systemctl", "--user", "reset-failed", unit]
            )
            self.assertEqual(root.stat().st_mode & 0o777, 0o755)
            self.assertFalse(archive.parent.exists())
            self.assertEqual(receipts.stat().st_mode & 0o777, 0o700)

    def test_group_writable_state_parent_remains_denied(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o775)
            jobs, receipts = root / "jobs", root / "receipts"
            jobs.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            unit = "grabowski-task-" + "2" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", unit, "failed")
            with self.assertRaisesRegex(RuntimeError, "writable|private"):
                RETENTION.build_plan(
                    minimum_job_age_seconds=50, now=1000,
                    jobs_root=jobs, archive_root=root / "archive",
                    receipt_root=receipts, task_db=task_db,
                    failed_units=[unit], unit_states={},
                )

    def test_unrelated_receipt_temps_do_not_block_task_reset(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            jobs.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            for index in range(1, 5):
                (receipts / (".unrelated.json.1." + str(index) + ".tmp")).write_text("")
            task_unit = "grabowski-task-" + "e" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=task_db, failed_units=[task_unit], unit_states={},
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "MAX_JOB_REGISTRY_ENTRIES", 3
            ), patch.object(RETENTION, "MAX_RETAINED_JSON_TEMPS", 3):
                receipt = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(receipt["completed"])
            reset.assert_called_once()
            for index in range(1, 5):
                self.assertTrue(
                    (receipts / (".unrelated.json.1." + str(index) + ".tmp")).exists()
                )

    def test_receipt_temp_capacity_preflight_precedes_task_reset(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            jobs.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            receipts.mkdir(mode=0o700)
            task_unit = "grabowski-task-" + "f" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=task_db, failed_units=[task_unit], unit_states={},
            )
            for index in range(1, 4):
                (receipts / (
                    "." + plan["plan_sha256"] + ".json.1."
                    + str(index) + ".tmp"
                )).write_text("")
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "MAX_RETAINED_JSON_TEMPS", 3
            ):
                with self.assertRaisesRegex(RuntimeError, "retained atomic temp bound"):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            reset.assert_not_called()
            for index in range(1, 4):
                self.assertTrue(
                    (receipts / (
                        "." + plan["plan_sha256"] + ".json.1."
                        + str(index) + ".tmp"
                    )).exists()
                )

    def test_systemd_retention_requires_preprovisioned_receipt_root(self) -> None:
        unit = (
            ROOT / "systemd/grabowski-runtime-retention.service.example"
        ).read_text(encoding="utf-8")
        root = "%h/.local/state/grabowski/retention-receipts"
        # systemd 249 resolves StateDirectory in per-user units below
        # XDG_CONFIG_HOME, not the actual Grabowski state path.
        self.assertNotIn("StateDirectory=", unit)
        provision = "ExecStartPre=/usr/bin/install -d -m 0700 -- " + root
        precheck = "ExecStartPre=/usr/bin/test ! -L " + root
        verify = "ExecStartPre=/usr/bin/test -d " + root
        self.assertIn(provision, unit)
        self.assertIn(verify, unit)
        self.assertEqual(unit.count(precheck), 2)
        self.assertLess(unit.index(precheck), unit.index(provision))
        self.assertLess(unit.index(provision), unit.index(verify))
        self.assertNotIn("ExecStartPre=/usr/bin/mkdir", unit)

    def test_missing_receipt_root_never_resets_task_before_failure(self) -> None:
        self._simulated_protected_authority.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            jobs.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            self.assertFalse(receipts.exists())
            task_unit = "grabowski-task-" + "a" * 24 + "-a1.service"
            task_db = self._task_db(root / "tasks.sqlite3", task_unit, "failed")
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=task_db, failed_units=[task_unit], unit_states={},
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset):
                with self.assertRaisesRegex(RuntimeError, "receipt root absent"):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            reset.assert_not_called()
            self.assertFalse(receipts.exists())

    def test_jobs_root_forged_before_initial_fd_never_resets_pending_unit(self) -> None:
        # Until the broker can authenticate roots, the real security outcome
        # is fail-closed, not acceptance of a forged first-opened directory.
        self._simulated_protected_authority.return_value = False
        # Hostile SAME-UID writer installed a valid private directory before
        # the first pathname open. The plan hash and local FDs do not prove
        # that this is the deployment owner's genuine registry.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, foreign, hidden = root / "jobs", root / "foreign-jobs", root / "real-jobs"
            name = "grabowski-job-fafafafafafa"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            self._job(jobs, name, now - 400)
            self._job(foreign, name, now - 400)
            free = {
                "schema_version": 1, "units": [], "pending_unit": None,
                "updated_at_unix": now - 500,
            }
            protected = {**free, "pending_unit": name}
            for directory, index in ((jobs, protected), (foreign, free)):
                target = directory / "runtime-deploy-index.json"
                target.write_text(json.dumps(index) + "\n")
                target.chmod(0o600)

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            jobs.rename(hidden)
            foreign.rename(jobs)
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
                }), patch.object(RETENTION, "_run", reset), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    try:
                        plan = RETENTION.build_plan(
                            minimum_job_age_seconds=500, now=now,
                            jobs_root=jobs, archive_root=root / "archive",
                            receipt_root=root / "receipts",
                            task_db=root / "missing.sqlite3", failed_units=[unit],
                            unit_states={unit: self._state(unit)},
                        )
                        if plan["reset_failed_units"]:
                            RETENTION.apply_plan(
                                plan, expected_plan_sha256=plan["plan_sha256"]
                            )
                    except (RuntimeError, OSError):
                        pass  # Rejection before systemd is permitted.
            finally:
                jobs.rename(foreign)
                hidden.rename(jobs)
            self.assertEqual(
                json.loads((jobs / "runtime-deploy-index.json").read_text())["pending_unit"],
                name,
            )
            self.assertTrue((jobs / name / "metadata.json").is_file())
            reset.assert_not_called()

    def test_missing_output_roots_fail_closed_without_adopting_foreign_dir(self) -> None:
        # mkdirat(final basename) followed by openat lets a same-UID peer
        # exchange the directory BEFORE the first FD pin. Until a protected
        # creator exists, missing roots require explicit trusted recovery.
        for output_name, root_opener, fd_name in (
            ("archive", RETENTION._archive_root_fd_for_plan, "archive_fd"),
            ("receipts", RETENTION._receipt_root_fd_for_plan, "receipt_fd"),
        ):
            with self.subTest(output=output_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                jobs = root / "jobs"
                name = "grabowski-job-abcabcabcabc"
                self._job(jobs, name, 100)
                target = root / output_name
                target.rmdir()
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50, now=1000,
                    jobs_root=jobs, archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=[],
                    unit_states={name + ".service": self._state(name + ".service")},
                )
                self.assertEqual(getattr(plan, fd_name), -1)
                # A substitute appearing after planning cannot gain
                # authority merely because its mode and owner are plausible.
                foreign = root / "foreign"
                foreign.mkdir(mode=0o700)
                foreign.rename(target)
                with patch.object(
                    RETENTION.os, "mkdir",
                    side_effect=AssertionError("unsafe mkdirat called"),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "root absent during planning"
                    ):
                        root_opener(plan)
                self.assertTrue(target.is_dir())
                self.assertEqual(getattr(plan, fd_name), -1)

    def test_missing_output_root_apply_fails_before_archive_reset_or_audit(self) -> None:
        # The root may be missing at plan time and an attacker may publish a
        # replacement before apply. No trusted FD means no irreversible effect.
        for output in ("archive", "receipts"):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                jobs = root / "jobs"
                name = "grabowski-job-aabaabbaabba"
                unit = name + ".service"
                source = self._job(jobs, name, 100)
                target = root / output
                target.rmdir()
                plan = RETENTION.build_plan(
                    minimum_job_age_seconds=50, now=1000,
                    jobs_root=jobs, archive_root=root / "archive",
                    receipt_root=root / "receipts",
                    task_db=root / "missing.sqlite3",
                    failed_units=[unit],
                    unit_states={unit: self._state(unit)},
                )
                self.assertEqual(len(plan["archive_jobs"]), 1)
                foreign = root / "foreign-private-output"
                foreign.mkdir(mode=0o700)
                foreign.rename(target)
                fake_deploy = types.ModuleType("grabowski_self_deploy")
                fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
                fake_deploy._deploy_schedule_lock = lambda: nullcontext()
                fake_base = types.ModuleType("grabowski_mcp")
                fake_base._append_audit = Mock()
                fake_base._require_mutations_enabled = Mock()
                fake_base._require_capability = Mock()
                reset = Mock(return_value=Mock(returncode=0, stderr=""))
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy,
                    "grabowski_mcp": fake_base,
                }), patch.object(RETENTION, "_run", reset), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "root absent during planning"
                    ):
                        RETENTION.apply_plan(
                            plan, expected_plan_sha256=plan["plan_sha256"]
                        )
                self.assertTrue((source / "metadata.json").is_file())
                self.assertFalse((target / name).exists())
                self.assertFalse((root / "receipts" / f"{plan['plan_sha256']}.json").exists())
                reset.assert_not_called()
                fake_base._append_audit.assert_not_called()

    def test_archive_root_forged_before_initial_fd_never_redirects_move(self) -> None:
        self._simulated_protected_authority.return_value = False
        # A private counterfeit archive root can be present BEFORE build_plan.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            foreign, hidden = root / "foreign-archive", root / "genuine-archive"
            name = "grabowski-job-abababababab"
            unit = name + ".service"
            self._job(jobs, name, 100)
            archive.mkdir(mode=0o700, exist_ok=True)
            foreign.mkdir(mode=0o700)
            archive.rename(hidden)
            foreign.rename(archive)
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            redirected = False
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
                }), patch.object(RETENTION, "_run", reset), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    try:
                        plan = RETENTION.build_plan(
                            minimum_job_age_seconds=50, now=1000,
                            jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                            task_db=root / "missing.sqlite3", failed_units=[unit],
                            unit_states={unit: self._state(unit)},
                        )
                        if plan["archive_jobs"]:
                            RETENTION.apply_plan(
                                plan, expected_plan_sha256=plan["plan_sha256"]
                            )
                    except (RuntimeError, OSError):
                        pass
            finally:
                redirected = (archive / name / "archive-manifest.json").is_file()
                archive.rename(foreign)
                hidden.rename(archive)
            self.assertFalse(redirected, "genuine job moved into substituted archive root")
            self.assertTrue((jobs / name / "metadata.json").is_file())
            reset.assert_not_called()

    def test_archive_detachment_after_manifest_never_authorizes_reset(self) -> None:
        # A verified move and manifest do not grant permission to reset when
        # the canonical archived basename was replaced before the systemd effect.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-bcbcbcbcbcbc"
            unit = name + ".service"
            self._job(jobs, name, 100)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            real_read = RETENTION._archive_read_deploy_index_pinned
            count = [0]
            detached = [False]
            hidden = root / "authentic-archived-job"

            def detach_after_manifest(path, fd, deploy):
                count[0] += 1
                if count[0] == 3 and not detached[0]:
                    assert (archive / name / "archive-manifest.json").is_file()
                    (archive / name).rename(hidden)
                    counterfeit = archive / name
                    counterfeit.mkdir(mode=0o700)
                    marker = counterfeit / "peer-evidence"
                    marker.write_bytes(b"not a valid archived job\n")
                    marker.chmod(0o600)
                    detached[0] = True
                return real_read(path, fd, deploy)

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ), patch.object(
                RETENTION, "_archive_read_deploy_index_pinned",
                side_effect=detach_after_manifest,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "retention reset phase did not complete",
                ):
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
            self.assertTrue(detached[0], "attack must follow verified manifest")
            self.assertTrue((hidden / "archive-manifest.json").is_file())
            self.assertEqual(
                (archive / name / "peer-evidence").read_bytes(),
                b"not a valid archived job\n",
            )
            reset.assert_not_called()

    def test_index_reservation_immediately_before_rename_keeps_live_source(self) -> None:
        self._simulated_protected_authority.return_value = False
        # Even correct FDs do not make index read and renameat2 one atomic
        # decision. A non-cooperating writer can reserve the job in between.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-eeeeeeababab"
            unit = name + ".service"
            self._job(jobs, name, 100)
            index = jobs / "runtime-deploy-index.json"
            free = {
                "schema_version": 1, "units": [], "pending_unit": None,
                "updated_at_unix": 500,
            }
            index.write_text(json.dumps(free) + "\n")
            index.chmod(0o600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            actual_rename = RETENTION._archive_rename_noreplace
            race = [False]

            def reserve_before_rename(source_fd, source_name, target_fd, target_name):
                if source_name == name and target_name == name and not race[0]:
                    index.write_text(json.dumps({**free, "pending_unit": name}) + "\n")
                    index.chmod(0o600)
                    race[0] = True
                return actual_rename(source_fd, source_name, target_fd, target_name)

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_archive_rename_noreplace",
                side_effect=reserve_before_rename,
            ), patch.object(RETENTION, "_run", reset), patch.object(
                RETENTION, "_systemd_unit_states",
                return_value={unit: self._state(unit)},
            ):
                try:
                    RETENTION.apply_plan(
                        plan, expected_plan_sha256=plan["plan_sha256"]
                    )
                except (RuntimeError, OSError):
                    pass  # Fail-closed before archive move is acceptable.
            if race[0]:
                self.assertEqual(
                    json.loads(index.read_text())["pending_unit"], name
                )
            self.assertTrue((jobs / name / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            reset.assert_not_called()

    def test_forged_self_hashed_foreign_plan_never_resets_pending_job(self) -> None:
        # RED for P2-C: a caller-recomputed hash cannot certify root authority
        # or permit reset of the genuine pending deployment unit.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, foreign = root / "jobs", root / "foreign-jobs"
            archive, receipts = root / "archive", root / "receipts"
            hidden = root / "genuine-jobs"
            name = "grabowski-job-f2f2f2f2f2f2"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            self._job(jobs, name, now - 400)
            self._job(foreign, name, now - 400)
            free = {
                "schema_version": 1, "units": [], "pending_unit": None,
                "updated_at_unix": now - 500,
            }
            protected = {**free, "pending_unit": name}
            for directory, data in ((jobs, protected), (foreign, free)):
                index = directory / "runtime-deploy-index.json"
                index.write_text(json.dumps(data) + "\n")
                index.chmod(0o600)
            forged = RETENTION.build_plan(
                minimum_job_age_seconds=500, now=now,
                jobs_root=foreign, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(forged["reset_failed_units"], [unit])
            self.assertEqual(forged["archive_jobs"], [])
            forged["jobs_root"] = str(jobs)
            forged["plan_sha256"] = RETENTION._sha256({
                key: value for key, value in forged.items()
                if key != "plan_sha256"
            })
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            jobs.rename(hidden)
            foreign.rename(jobs)
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
                }), patch.object(RETENTION, "_run", reset), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    try:
                        RETENTION.apply_plan(
                            forged, expected_plan_sha256=forged["plan_sha256"]
                        )
                    except (RuntimeError, OSError):
                        pass  # Fail-closed is acceptable.
            finally:
                jobs.rename(foreign)
                hidden.rename(jobs)
            self.assertEqual(json.loads(
                (jobs / "runtime-deploy-index.json").read_text()
            )["pending_unit"], name)
            self.assertTrue((jobs / name / "metadata.json").is_file())
            reset.assert_not_called()

    def test_reset_only_prepare_time_foreign_root_never_authorizes_reset(self) -> None:
        # Independent high-critical R3 P1: the canonical root can be swapped
        # immediately after _private_directory() resolves the original tree
        # but before the old late _prepare_archives root-FD snapshot.
        # A foreign tree with matching job metadata and permissive index must
        # never authorize clearing a real, now-pending deployment unit.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-636363636363"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            self._job(jobs, name, now - 400)
            free_index = {
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": now - 500,
            }
            real_index = jobs / "runtime-deploy-index.json"
            real_index.write_text(json.dumps(free_index) + "\n")
            real_index.chmod(0o600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=500, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(plan["archive_jobs"], [])
            self.assertEqual(plan["reset_failed_units"], [unit])

            protected_index = {**free_index, "pending_unit": name}
            real_index.write_text(json.dumps(protected_index) + "\n")
            real_index.chmod(0o600)
            foreign = root / "foreign-private-jobs"
            self._job(foreign, name, now - 400)
            foreign_index = foreign / "runtime-deploy-index.json"
            foreign_index.write_text(json.dumps(free_index) + "\n")
            foreign_index.chmod(0o600)
            hidden = root / "authentic-jobs"
            actual_private = RETENTION._private_directory
            swapped = [False]

            def swap_after_private(path: Path, *, create: bool = False) -> Path:
                result = actual_private(path, create=create)
                if path == jobs and not swapped[0]:
                    jobs.rename(hidden)
                    foreign.rename(jobs)
                    swapped[0] = True
                return result

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy,
                    "grabowski_mcp": fake_base,
                }), patch.object(
                    RETENTION, "_private_directory", side_effect=swap_after_private
                ), patch.object(
                    RETENTION, "_run", reset
                ), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "jobs root identity changed|archive source directory changed"
                    ):
                        RETENTION.apply_plan(
                            plan, expected_plan_sha256=plan["plan_sha256"]
                        )
            finally:
                if swapped[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
            self.assertTrue(swapped[0])
            self.assertEqual(json.loads(real_index.read_text()), protected_index)
            self.assertTrue((jobs / name / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            reset.assert_not_called()

    def _assert_fd_root_swap_blocks_unsafe_effect(
        self, *, name: str, archive_job: bool, when: str
    ) -> None:
        """Same-UID adversary exchanges the root exactly at its FD read."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            unit = name + ".service"
            now = int(RETENTION.time.time())
            created = 100 if archive_job else now - 400
            minimum_age = 50 if archive_job else 500
            self._job(jobs, name, created)
            original = jobs / "runtime-deploy-index.json"
            free = {
                "schema_version": 1,
                "units": [] if archive_job else [name],
                "pending_unit": None, "updated_at_unix": now - 500,
            }
            original.write_text(json.dumps(free) + "\n")
            original.chmod(0o600)
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=minimum_age, now=now,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            self.assertEqual(bool(plan["archive_jobs"]), archive_job)
            foreign = root / "untrusted-jobs"
            self._job(foreign, name, created)
            untrusted_index = foreign / original.name
            untrusted_index.write_text(json.dumps(free) + "\n")
            untrusted_index.chmod(0o600)
            hidden = root / "authentic-jobs"
            protected = {**free, "pending_unit": name}
            swapped, readings = [False], [0]

            def attack() -> None:
                if swapped[0]:
                    return
                original.write_text(json.dumps(protected) + "\n")
                original.chmod(0o600)
                jobs.rename(hidden)
                foreign.rename(jobs)
                swapped[0] = True

            old_prepare = RETENTION._prepare_archives
            old_read = RETENTION._archive_read_deploy_index_pinned

            def prepare_then_attack(actual_plan, **kwargs):
                result = old_prepare(actual_plan, **kwargs)
                if when == "after_prepare":
                    attack()
                return result

            def read_then_attack(path, fd, deploy):
                readings[0] += 1
                if when == "second_index" and readings[0] == 2:
                    attack()
                # The real read must use the authentic previously opened FD,
                # even if the canonical pathname currently names a foreign tree.
                self.assertEqual(
                    (os.fstat(fd).st_dev, os.fstat(fd).st_ino),
                    tuple(plan["jobs_root_identity"]),
                )
                return old_read(path, fd, deploy)

            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
                }), patch.object(
                    RETENTION, "_prepare_archives", side_effect=prepare_then_attack,
                ), patch.object(
                    RETENTION, "_archive_read_deploy_index_pinned",
                    side_effect=read_then_attack,
                ), patch.object(
                    RETENTION, "_run", reset
                ), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "changed during inspection|deployment index changed|"
                        "retention reset phase did not complete|identity changed",
                    ):
                        RETENTION.apply_plan(
                            plan, expected_plan_sha256=plan["plan_sha256"]
                        )
            finally:
                if swapped[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
            self.assertTrue(swapped[0], "attack did not reach its exact hook")
            self.assertEqual(json.loads(original.read_text()), protected)
            self.assertTrue((jobs / name / "metadata.json").is_file())
            self.assertFalse((archive / name).exists())
            reset.assert_not_called()

    def test_reset_only_index_read_rejects_foreign_jobs_root(self) -> None:
        self._assert_fd_root_swap_blocks_unsafe_effect(
            name="grabowski-job-626262626262", archive_job=False, when="after_prepare"
        )
    def test_archive_index_prepared_root_replacement_cannot_spoof_fd_read(self) -> None:
        self._assert_fd_root_swap_blocks_unsafe_effect(
            name="grabowski-job-454545454545", archive_job=True, when="after_prepare"
        )
    def test_archive_index_per_job_recheck_rejects_foreign_jobs_root(self) -> None:
        self._assert_fd_root_swap_blocks_unsafe_effect(
            name="grabowski-job-686868686868", archive_job=True, when="second_index"
        )
    def test_postmove_reset_rejects_index_read_from_foreign_jobs_root(self) -> None:
        # A peer can exchange jobs_root at the *postmove reset* read,
        # restore the authentic root only for a separate identity probe,
        # then return a syntactically valid stale index from another inode.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-787878787878"
            unit = name + ".service"
            self._job(jobs, name, 100)
            old_index = {
                "schema_version": 1, "units": [],
                "pending_unit": None, "updated_at_unix": 500,
            }
            index_path = jobs / "runtime-deploy-index.json"
            index_path.write_text(json.dumps(old_index) + "\n")
            index_path.chmod(0o600)
            foreign = root / "foreign-jobs"
            foreign.mkdir(mode=0o700)
            (foreign / index_path.name).write_text(json.dumps(old_index) + "\n")
            (foreign / index_path.name).chmod(0o600)
            hidden = root / "hidden-jobs"
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            real_open = RETENTION._archive_open_private_root
            real_identity = RETENTION._archive_require_pinned_identity
            swapped = [False]
            reset = Mock(return_value=Mock(returncode=0, stderr=""))

            def swap_for_postmove_read(path):
                if path == jobs and not swapped[0] and (archive / name / "archive-manifest.json").is_file():
                    index_path.write_text(json.dumps({
                        **old_index, "units": [name],
                    }) + "\n")
                    index_path.chmod(0o600)
                    jobs.rename(hidden)
                    foreign.rename(jobs)
                    swapped[0] = True
                return real_open(path)

            def authenticate_another_root(path, identity):
                if path == jobs and swapped[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
                    try:
                        return real_identity(path, identity)
                    finally:
                        jobs.rename(hidden)
                        foreign.rename(jobs)
                return real_identity(path, identity)

            try:
                with patch.dict("sys.modules", {
                    "grabowski_self_deploy": fake_deploy,
                    "grabowski_mcp": fake_base,
                }), patch.object(
                    RETENTION, "_archive_open_private_root",
                    side_effect=swap_for_postmove_read,
                ), patch.object(
                    RETENTION, "_archive_require_pinned_identity",
                    side_effect=authenticate_another_root,
                ), patch.object(
                    RETENTION, "_run", reset,
                ), patch.object(
                    RETENTION, "_systemd_unit_states",
                    return_value={unit: self._state(unit)},
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "retention reset phase did not complete",
                    ):
                        RETENTION.apply_plan(
                            plan, expected_plan_sha256=plan["plan_sha256"],
                        )
            finally:
                if swapped[0]:
                    jobs.rename(foreign)
                    hidden.rename(jobs)
            self.assertTrue(swapped[0], "attack must reach postmove index read")
            self.assertEqual(json.loads(index_path.read_text())["units"], [name])
            self.assertTrue((archive / name / "archive-manifest.json").is_file())
            reset.assert_not_called()

    def test_live_reset_rejects_index_read_from_foreign_jobs_root(self) -> None:
        self._assert_fd_root_swap_blocks_unsafe_effect(
            name="grabowski-job-797979797979", archive_job=False, when="second_index"
        )
    def test_archive_index_root_swap_never_redirects_index_write(self) -> None:
        # Retention must never attempt a canonical index write. Previously
        # this could redirect through a same-UID jobs-root replacement.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
            name = "grabowski-job-343434343434"
            unit = name + ".service"
            self._job(jobs, name, 100)
            index_file = jobs / "runtime-deploy-index.json"
            original = index_file.read_bytes()
            plan = RETENTION.build_plan(
                minimum_job_age_seconds=50, now=1_000,
                jobs_root=jobs, archive_root=archive, receipt_root=receipts,
                task_db=root / "missing.sqlite3", failed_units=[unit],
                unit_states={unit: self._state(unit)},
            )
            foreign = root / "foreign-private"
            foreign.mkdir(mode=0o700)
            outside_index = foreign / index_file.name
            outside_index.write_bytes(b"foreign index, never replace\n")
            outside_index.chmod(0o600)
            attempted_index_writes = []
            actual_write = RETENTION._write_json_atomic
            def reject_index_write(path, payload, **kwargs):
                if path == index_file:
                    attempted_index_writes.append(True)
                    raise AssertionError("retention must not write canonical deploy index")
                return actual_write(path, payload, **kwargs)
            fake_deploy = types.ModuleType("grabowski_self_deploy")
            fake_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            with patch.dict("sys.modules", {
                "grabowski_self_deploy": fake_deploy, "grabowski_mcp": fake_base,
            }), patch.object(
                RETENTION, "_run", reset
            ), patch.object(
                RETENTION, "_systemd_unit_states", return_value={unit: self._state(unit)}
            ), patch.object(
                RETENTION, "_write_json_atomic", side_effect=reject_index_write
            ):
                result = RETENTION.apply_plan(
                    plan, expected_plan_sha256=plan["plan_sha256"]
                )
            self.assertTrue(result["completed"])
            self.assertEqual(attempted_index_writes, [])
            self.assertEqual(index_file.read_bytes(), original)
            self.assertEqual(outside_index.read_bytes(), b"foreign index, never replace\n")
            self.assertTrue((archive / name / "archive-manifest.json").is_file())
            reset.assert_called_once()
            with self.assertRaisesRegex(RuntimeError, "may not publish deployment index"):
                RETENTION._write_json_atomic(
                    index_file, {"schema_version": 1}, replace_existing=True
                )
            self.assertEqual(index_file.read_bytes(), original)

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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            fake_base._append_audit = Mock()
            fake_base._require_mutations_enabled = Mock()
            fake_base._require_capability = Mock()
            reset = Mock(return_value=Mock(returncode=0, stderr=""))
            original_manifest_on_fd = RETENTION._archive_file_manifest_on_fd

            def drifting_manifest(
                directory: Path, descriptor: int
            ) -> list[dict[str, object]]:
                files = original_manifest_on_fd(directory, descriptor)
                if directory == archive / job_name:
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
                "_archive_file_manifest_on_fd",
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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
            # Existing private output roots are an apply-time safety precondition.
            (root / "archive").mkdir(mode=0o700)
            (root / "receipts").mkdir(mode=0o700)
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
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

    def test_atomic_json_create_does_not_overwrite_racing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "receipts"
            directory.mkdir(mode=0o700)
            target = directory / "receipt.json"
            authentic_move = RETENTION._archive_rename_noreplace
            foreign = b"unrelated owner-controlled receipt\n"

            def race_no_replace(
                source_fd: int, source_name: str,
                destination_fd: int, destination_name: str,
            ) -> None:
                target.write_bytes(foreign)
                target.chmod(0o600)
                return authentic_move(
                    source_fd, source_name, destination_fd, destination_name,
                )

            with patch.object(
                RETENTION, "_archive_rename_noreplace",
                side_effect=race_no_replace,
            ):
                with self.assertRaises(FileExistsError):
                    RETENTION._write_json_atomic(target, {"value": 1})
            self.assertEqual(target.read_bytes(), foreign)
            # The immutable destination is preserved; never unlink a mutable
            # temporary pathname after a failed RENAME_NOREPLACE. Keep only
            # the writer's private orphan for later controlled maintenance.
            private_orphans = [p for p in directory.iterdir() if p != target]
            self.assertEqual(len(private_orphans), 1)
            self.assertTrue(private_orphans[0].name.startswith(".receipt.json."))
            self.assertEqual(private_orphans[0].suffix, ".tmp")
            self.assertEqual(private_orphans[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(private_orphans[0].read_text()), {"value": 1})

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

    def test_plan_hash_binds_existing_archive_and_receipt_root_identities(self) -> None:
        # Output roots may be replaced *between* the two periodic snapshots.
        # Identical jobs and a self-hash without these identities otherwise
        # pass the double-plan check despite writing to a different directory.
        for kind in ("archive", "receipts"):
            with self.subTest(root=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                jobs, archive, receipts = root / "jobs", root / "archive", root / "receipts"
                name = "grabowski-job-aaaaaaaaaaaa"
                unit = name + ".service"
                self._job(jobs, name, 100)
                kwargs = {
                    "minimum_job_age_seconds": 50,
                    "now": 1000,
                    "jobs_root": jobs,
                    "archive_root": archive,
                    "receipt_root": receipts,
                    "task_db": root / "missing.sqlite3",
                    "failed_units": [],
                    "unit_states": {unit: self._state(unit)},
                }
                first = RETENTION.build_plan(**kwargs)
                original = root / f"authentic-{kind}"
                replacement = root / f"foreign-{kind}"
                replacement.mkdir(mode=0o700)
                target = root / kind
                target.rename(original)
                replacement.rename(target)
                try:
                    second = RETENTION.build_plan(**kwargs)
                    binding_key = (
                        "archive_root_identity" if kind == "archive"
                        else "receipt_root_identity"
                    )
                    self.assertNotEqual(first[binding_key], second[binding_key])
                    self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])
                    self.assertEqual(first["jobs_root_identity"], second["jobs_root_identity"])
                finally:
                    target.rename(replacement)
                    original.rename(target)
                self.assertTrue((jobs / name / "metadata.json").is_file())

    def test_periodic_apply_rejects_plan_drift_before_mutation(self) -> None:
        first = {
            "plan_sha256": "a" * 64,
            "reset_failed_units": ["grabowski-task-" + "a" * 24 + "-a1.service"],
            "archive_jobs": [],
        }
        second = {
            "plan_sha256": "b" * 64,
            "reset_failed_units": first["reset_failed_units"],
            "archive_jobs": [],
        }
        with patch.object(
            RETENTION, "build_plan", side_effect=[first, second]
        ), patch.object(RETENTION, "apply_plan") as apply:
            with self.assertRaisesRegex(RuntimeError, "drifted"):
                RETENTION.apply_periodic_plan()
        apply.assert_not_called()

    def test_periodic_apply_stable_noop_is_idempotent(self) -> None:
        plan = {
            "plan_sha256": "c" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with patch.object(
            RETENTION, "build_plan", side_effect=[plan, plan, plan, plan]
        ), patch.object(RETENTION, "apply_plan") as apply:
            first = RETENTION.apply_periodic_plan()
            second = RETENTION.apply_periodic_plan()
        self.assertEqual(first, second)
        self.assertTrue(first["completed"])
        self.assertFalse(first["mutated"])
        apply.assert_not_called()

    def test_periodic_apply_reuses_hash_bound_apply_contract(self) -> None:
        plan = {
            "plan_sha256": "d" * 64,
            "reset_failed_units": ["grabowski-task-" + "d" * 24 + "-a1.service"],
            "archive_jobs": [],
        }
        receipt = {"completed": True, "plan_sha256": plan["plan_sha256"]}
        with patch.object(
            RETENTION, "build_plan", side_effect=[plan, plan]
        ), patch.object(RETENTION, "apply_plan", return_value=receipt) as apply:
            result = RETENTION.apply_periodic_plan()
        self.assertEqual(result, receipt)
        apply.assert_called_once_with(
            plan, expected_plan_sha256=plan["plan_sha256"]
        )


    def test_periodic_worktree_hygiene_reuses_retention_producer_and_bound(self) -> None:
        plan = {
            "plan_sha256": "e" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_one = root / "repo-one"
            repo_two = root / "repo-two"
            allowed = root / "worktrees"
            repo_one.mkdir()
            repo_two.mkdir()
            allowed.mkdir()
            runner = Mock(
                return_value={
                    "status": "passed",
                    "output": {"actions": 2, "archived": [], "cleaned": []},
                }
            )
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ), patch.object(RETENTION, "apply_plan") as apply:
                result = RETENTION.apply_periodic_plan(
                    worktree_hygiene_repositories=[str(repo_one), str(repo_two)],
                    worktree_hygiene_allowed_roots=[str(allowed)],
                    max_worktree_hygiene_actions=2,
                    worktree_hygiene_runner=runner,
                )

        apply.assert_not_called()
        runner.assert_called_once()
        args, kwargs = runner.call_args
        self.assertEqual(args[0], "worktree-hygiene-reconcile")
        self.assertTrue(kwargs["allow_mutation"])
        self.assertEqual(args[1]["max_actions"], 2)
        self.assertEqual(args[1]["allowed_checkout_roots"], [str(allowed.resolve())])
        self.assertEqual(result["operation"], "grabowski-runtime-retention-convergence-periodic")
        self.assertEqual(result["worktree_hygiene"]["actions"], 2)
        self.assertTrue(result["worktree_hygiene"]["bounded"])
        self.assertTrue(result["mutated"])

    def test_periodic_worktree_hygiene_accepts_blocked_fail_closed_receipt(self) -> None:
        plan = {
            "plan_sha256": "f" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            allowed = root / "worktrees"
            repo.mkdir()
            allowed.mkdir()
            runner = Mock(
                return_value={
                    "status": "blocked",
                    "output": {
                        "actions": 0,
                        "error": "dirty or foreign worktree remains protected",
                    },
                }
            )
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ):
                result = RETENTION.apply_periodic_plan(
                    worktree_hygiene_repositories=[str(repo)],
                    worktree_hygiene_allowed_roots=[str(allowed)],
                    worktree_hygiene_runner=runner,
                )
        self.assertTrue(result["completed"])
        self.assertFalse(result["mutated"])
        self.assertEqual(
            result["worktree_hygiene"]["receipts"][0]["status"],
            "blocked",
        )

    def test_periodic_worktree_hygiene_skips_missing_optional_roots(self) -> None:
        plan = {
            "plan_sha256": "2" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            existing = root / "existing-worktrees"
            missing = root / "missing-worktrees"
            repo.mkdir()
            existing.mkdir()
            runner = Mock(
                return_value={
                    "status": "passed",
                    "output": {"actions": 0, "archived": [], "cleaned": []},
                }
            )
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ):
                result = RETENTION.apply_periodic_plan(
                    worktree_hygiene_repositories=[str(repo)],
                    worktree_hygiene_allowed_roots=[
                        str(existing),
                        str(missing),
                    ],
                    worktree_hygiene_runner=runner,
                )

        runner.assert_called_once()
        parameters = runner.call_args.args[1]
        self.assertEqual(
            parameters["allowed_checkout_roots"], [str(existing.resolve())]
        )
        self.assertTrue(result["completed"])

    def test_periodic_worktree_hygiene_noops_when_all_optional_roots_are_absent(self) -> None:
        plan = {
            "plan_sha256": "3" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            runner = Mock()
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ):
                result = RETENTION.apply_periodic_plan(
                    worktree_hygiene_repositories=[str(repo)],
                    worktree_hygiene_allowed_roots=[
                        str(root / "missing-one"),
                        str(root / "missing-two"),
                    ],
                    worktree_hygiene_runner=runner,
                )

        runner.assert_not_called()
        hygiene = result["worktree_hygiene"]
        self.assertTrue(result["completed"])
        self.assertFalse(result["mutated"])
        self.assertEqual(hygiene["actions"], 0)
        self.assertEqual(hygiene["allowed_checkout_roots"], [])
        self.assertEqual(
            hygiene["reason"], "configured_optional_checkout_roots_absent"
        )

    def test_periodic_worktree_hygiene_rejects_existing_nondirectory_root(self) -> None:
        plan = {
            "plan_sha256": "4" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            invalid_root = root / "not-a-directory"
            repo.mkdir()
            invalid_root.write_text("not a root", encoding="utf-8")
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ):
                with self.assertRaisesRegex(ValueError, "must be directories"):
                    RETENTION.apply_periodic_plan(
                        worktree_hygiene_repositories=[str(repo)],
                        worktree_hygiene_allowed_roots=[str(invalid_root)],
                    )

    def test_periodic_worktree_hygiene_rejects_missing_allowed_root(self) -> None:
        plan = {
            "plan_sha256": "1" * 64,
            "reset_failed_units": [],
            "archive_jobs": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "repo"
            repo.mkdir()
            with patch.object(
                RETENTION, "build_plan", side_effect=[plan, plan]
            ):
                with self.assertRaisesRegex(ValueError, "allowed checkout root"):
                    RETENTION.apply_periodic_plan(
                        worktree_hygiene_repositories=[str(repo)],
                    )


    def test_completion_audit_failure_keeps_terminal_receipt_and_prevents_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            jobs = root / "jobs"
            archive = root / "archive"
            receipts = root / "receipts"
            job_name = "grabowski-job-acdeff012345"
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
            fake_self_deploy.DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
            fake_self_deploy._deploy_schedule_lock = lambda: nullcontext()
            fake_self_deploy._read_deploy_index = lambda _root: None
            fake_self_deploy._write_deploy_index = Mock()
            fake_base = types.ModuleType("grabowski_mcp")
            appended: list[dict[str, object]] = []

            def append_audit(record: dict[str, object]) -> None:
                appended.append(record)
                if len(appended) == 2:
                    raise OSError("simulated completion append failure")

            fake_base._append_audit = append_audit
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
                with self.assertRaisesRegex(RuntimeError, "completion audit failed"):
                    RETENTION.apply_plan(
                        plan,
                        expected_plan_sha256=plan["plan_sha256"],
                    )

            receipt_path = receipts / f"{plan['plan_sha256']}.json"
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertTrue(receipt["completed"])
            self.assertFalse(receipt["retry"]["required"])
            self.assertEqual(len(appended), 2)
            with self.assertRaisesRegex(RuntimeError, "terminal receipt"):
                RETENTION._select_receipt_target(
                    receipts, plan_sha256=plan["plan_sha256"]
                )

    def test_reconciliation_appends_only_audit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan_sha256 = "a" * 64
            path = root / f"{plan_sha256}.json"
            intent_sha256 = "b" * 64
            payload = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": plan_sha256,
                "attempt": 1,
                "previous_receipt_sha256": None,
                "reset_failed": [{"unit": "one"}],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {"required": False, "strategy": "rebuild_live_plan_and_chain_partial_receipt"},
                "completed_at_unix": 1_800_000_000,
            }
            payload["receipt_sha256"] = RETENTION._sha256(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with patch.object(
                RETENTION, "RECEIPT_ROOT", root
            ), patch.object(
                RETENTION, "_require_reconciliation_mutation_authority"
            ) as mutation_authority, patch.object(
                RETENTION, "_retention_coordination_lock", return_value=nullcontext()
            ), patch.object(
                RETENTION,
                "_retention_audit_reconciliation_state",
                return_value={
                    "original_completion": None,
                    "existing_reconciliation": None,
                },
            ), patch.object(
                RETENTION, "_append_audit_record", side_effect=lambda record: record
            ) as append_audit, patch.object(RETENTION, "apply_plan") as apply_plan:
                result = RETENTION.reconcile_retention_completion_audit(
                    intent_record_sha256=intent_sha256,
                    plan_sha256=plan_sha256,
                    attempt=1,
                    receipt_path=path,
                    expected_receipt_sha256=payload["receipt_sha256"],
                )
            self.assertEqual(result["status"], "reconciled")
            mutation_authority.assert_called_once_with()
            self.assertFalse(result["retention_effect_retried"])
            apply_plan.assert_not_called()
            record = append_audit.call_args.args[0]
            self.assertEqual(
                record["operation"],
                RETENTION.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
            )
            self.assertEqual(record["intent_record_sha256"], intent_sha256)
            self.assertEqual(record["receipt_sha256"], payload["receipt_sha256"])

    def test_reconciliation_is_idempotent_for_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan_sha256 = "d" * 64
            path = root / f"{plan_sha256}.json"
            intent_sha256 = "e" * 64
            payload = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": plan_sha256,
                "attempt": 1,
                "previous_receipt_sha256": None,
                "reset_failed": [],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {"required": False, "strategy": "rebuild_live_plan_and_chain_partial_receipt"},
                "completed_at_unix": 1_800_000_000,
            }
            payload["receipt_sha256"] = RETENTION._sha256(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with patch.object(
                RETENTION, "RECEIPT_ROOT", root
            ), patch.object(
                RETENTION, "_require_reconciliation_mutation_authority"
            ) as mutation_authority, patch.object(
                RETENTION, "_retention_coordination_lock", return_value=nullcontext()
            ), patch.object(
                RETENTION,
                "_retention_audit_reconciliation_state",
                return_value={
                    "original_completion": None,
                    "existing_reconciliation": {
                        "record_sha256": "1" * 64,
                        "record": {},
                    },
                },
            ), patch.object(RETENTION, "_append_audit_record") as append_audit:
                result = RETENTION.reconcile_retention_completion_audit(
                    intent_record_sha256=intent_sha256,
                    plan_sha256=plan_sha256,
                    attempt=1,
                    receipt_path=path,
                    expected_receipt_sha256=payload["receipt_sha256"],
                )
            self.assertEqual(result["status"], "already-reconciled")
            mutation_authority.assert_called_once_with()
            self.assertTrue(result["idempotent"])
            append_audit.assert_not_called()

    def test_reconciliation_rejects_foreign_terminal_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            expected_plan_sha256 = "4" * 64
            path = root / f"{expected_plan_sha256}.json"
            payload = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": "2" * 64,
                "attempt": 1,
                "previous_receipt_sha256": None,
                "reset_failed": [],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {"required": False, "strategy": "rebuild_live_plan_and_chain_partial_receipt"},
                "completed_at_unix": 1_800_000_000,
            }
            payload["receipt_sha256"] = RETENTION._sha256(payload)
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with patch.object(
                RETENTION, "RECEIPT_ROOT", root
            ), patch.object(
                RETENTION, "_require_reconciliation_mutation_authority"
            ) as mutation_authority, patch.object(
                RETENTION, "_retention_coordination_lock", return_value=nullcontext()
            ), self.assertRaisesRegex(RuntimeError, "binding is invalid"):
                RETENTION.reconcile_retention_completion_audit(
                    intent_record_sha256="3" * 64,
                    plan_sha256=expected_plan_sha256,
                    attempt=1,
                    receipt_path=path,
                    expected_receipt_sha256=payload["receipt_sha256"],
                )
            mutation_authority.assert_called_once_with()

    def test_reconciliation_rejects_self_consistent_receipt_outside_canonical_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            canonical_root = root / "receipts"
            canonical_root.mkdir(mode=0o700)
            plan_sha256 = "5" * 64
            forged_path = root / "forged.json"
            payload = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": plan_sha256,
                "attempt": 1,
                "previous_receipt_sha256": None,
                "reset_failed": [],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {
                    "required": False,
                    "strategy": "rebuild_live_plan_and_chain_partial_receipt",
                },
                "completed_at_unix": 1_800_000_000,
            }
            payload["receipt_sha256"] = RETENTION._sha256(payload)
            forged_path.write_text(json.dumps(payload), encoding="utf-8")
            forged_path.chmod(0o600)
            with patch.object(RETENTION, "RECEIPT_ROOT", canonical_root):
                with self.assertRaisesRegex(RuntimeError, "canonical receipt target"):
                    RETENTION._verified_terminal_retention_receipt(
                        forged_path,
                        plan_sha256=plan_sha256,
                        attempt=1,
                        expected_receipt_sha256=payload["receipt_sha256"],
                    )

    def test_canonical_retention_receipt_path_binds_attempt_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan_sha256 = "6" * 64
            self.assertEqual(
                RETENTION._canonical_retention_receipt_path(
                    plan_sha256=plan_sha256,
                    attempt=1,
                    receipt_root=root,
                ),
                root / f"{plan_sha256}.json",
            )
            self.assertEqual(
                RETENTION._canonical_retention_receipt_path(
                    plan_sha256=plan_sha256,
                    attempt=2,
                    receipt_root=root,
                ),
                root / f"{plan_sha256}.retry-02.json",
            )
            with self.assertRaisesRegex(RuntimeError, "attempt is invalid"):
                RETENTION._canonical_retention_receipt_path(
                    plan_sha256=plan_sha256,
                    attempt=RETENTION.MAX_RETENTION_RECEIPT_ATTEMPTS + 1,
                    receipt_root=root,
                )

    def test_terminal_reconciliation_receipt_binds_partial_receipt_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan_sha256 = "c" * 64
            partial = {
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
            }
            partial["receipt_sha256"] = RETENTION._sha256(partial)
            partial_path = root / f"{plan_sha256}.json"
            partial_path.write_text(json.dumps(partial), encoding="utf-8")
            partial_path.chmod(0o600)
            terminal = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": plan_sha256,
                "attempt": 2,
                "previous_receipt_sha256": partial["receipt_sha256"],
                "reset_failed": [],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {
                    "required": False,
                    "strategy": "rebuild_live_plan_and_chain_partial_receipt",
                },
                "completed_at_unix": 1_800_000_000,
            }
            terminal["receipt_sha256"] = RETENTION._sha256(terminal)
            terminal_path = root / f"{plan_sha256}.retry-02.json"
            terminal_path.write_text(json.dumps(terminal), encoding="utf-8")
            terminal_path.chmod(0o600)
            with patch.object(RETENTION, "RECEIPT_ROOT", root):
                verified = RETENTION._verified_terminal_retention_receipt(
                    terminal_path,
                    plan_sha256=plan_sha256,
                    attempt=2,
                    expected_receipt_sha256=terminal["receipt_sha256"],
                )
                self.assertEqual(verified["receipt_sha256"], terminal["receipt_sha256"])

                wrong_chain = dict(terminal)
                wrong_chain["previous_receipt_sha256"] = "d" * 64
                wrong_chain["receipt_sha256"] = RETENTION._sha256(
                    {key: value for key, value in wrong_chain.items() if key != "receipt_sha256"}
                )
                terminal_path.write_text(json.dumps(wrong_chain), encoding="utf-8")
                terminal_path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "binding is invalid"):
                    RETENTION._verified_terminal_retention_receipt(
                        terminal_path,
                        plan_sha256=plan_sha256,
                        attempt=2,
                        expected_receipt_sha256=wrong_chain["receipt_sha256"],
                    )

            first_plan_sha256 = "e" * 64
            first_path = root / f"{first_plan_sha256}.json"
            first_terminal = {
                "schema_version": 3,
                "operation": "grabowski-runtime-state-retention",
                "plan_sha256": first_plan_sha256,
                "attempt": 1,
                "previous_receipt_sha256": "f" * 64,
                "reset_failed": [],
                "reset_failures": [],
                "archived_jobs": [],
                "completed": True,
                "retry": {
                    "required": False,
                    "strategy": "rebuild_live_plan_and_chain_partial_receipt",
                },
                "completed_at_unix": 1_800_000_000,
            }
            first_terminal["receipt_sha256"] = RETENTION._sha256(first_terminal)
            first_path.write_text(json.dumps(first_terminal), encoding="utf-8")
            first_path.chmod(0o600)
            with patch.object(RETENTION, "RECEIPT_ROOT", root):
                with self.assertRaisesRegex(RuntimeError, "binding is invalid"):
                    RETENTION._verified_terminal_retention_receipt(
                        first_path,
                        plan_sha256=first_plan_sha256,
                        attempt=1,
                        expected_receipt_sha256=first_terminal["receipt_sha256"],
                    )

    def test_reconciliation_state_requires_explicit_negative_retry_evidence(self) -> None:
        plan_sha256 = "7" * 64
        intent_sha256 = "8" * 64
        receipt_sha256 = "9" * 64
        for retry_fields in ({}, {"retention_effect_retried": True}):
            with self.subTest(retry_fields=retry_fields):
                fake_query = types.ModuleType("grabowski_audit_query")
                fake_query.capture_verified_audit_snapshot = lambda: types.SimpleNamespace(
                    last_record_sha256="a" * 64
                )
                items = [
                    {
                        "evidence": {"record_sha256": intent_sha256},
                        "record": {
                            "operation": "runtime-state-retention-intent",
                            "plan_sha256": plan_sha256,
                            "attempt": 1,
                        },
                    },
                    {
                        "evidence": {"record_sha256": "b" * 64},
                        "record": {
                            "operation": RETENTION.RETENTION_COMPLETION_AUDIT_RECONCILIATION_OPERATION,
                            "plan_sha256": plan_sha256,
                            "attempt": 1,
                            "intent_record_sha256": intent_sha256,
                            "receipt_sha256": receipt_sha256,
                            "reconciliation_kind": "completion_audit_gap",
                            "completed": True,
                            **retry_fields,
                        },
                    },
                ]
                fake_query._iter_snapshot_items = lambda _snapshot, order: iter(items)
                with patch.dict("sys.modules", {"grabowski_audit_query": fake_query}):
                    with self.assertRaisesRegex(RuntimeError, "binding conflicts"):
                        RETENTION._retention_audit_reconciliation_state(
                            intent_record_sha256=intent_sha256,
                            plan_sha256=plan_sha256,
                            attempt=1,
                            receipt_sha256=receipt_sha256,
                        )

    def test_reconciliation_mutation_gate_denial_prevents_receipt_and_audit_work(self) -> None:
        with patch.object(
            RETENTION,
            "_require_reconciliation_mutation_authority",
            side_effect=PermissionError("blocked by test mutation gate"),
        ) as mutation_authority, patch.object(
            RETENTION, "_retention_coordination_lock"
        ) as coordination_lock, patch.object(
            RETENTION, "_verified_terminal_retention_receipt"
        ) as receipt_read, patch.object(
            RETENTION, "_append_audit_record"
        ) as append_audit:
            with self.assertRaisesRegex(PermissionError, "blocked by test mutation gate"):
                RETENTION.reconcile_retention_completion_audit(
                    intent_record_sha256="a" * 64,
                    plan_sha256="b" * 64,
                    attempt=1,
                    receipt_path=Path("/does/not/matter.json"),
                    expected_receipt_sha256="c" * 64,
                )
        mutation_authority.assert_called_once_with()
        coordination_lock.assert_not_called()
        receipt_read.assert_not_called()
        append_audit.assert_not_called()

    def test_reconciliation_mutation_authority_uses_central_file_write_gate(self) -> None:
        fake_base = types.ModuleType("grabowski_mcp")
        fake_base.AUDIT_LOG = Path("/tmp/grabowski-audit-test/write-audit.jsonl")
        fake_base._require_mutations_enabled = Mock()
        with patch.dict("sys.modules", {"grabowski_mcp": fake_base}):
            RETENTION._require_reconciliation_mutation_authority()
        fake_base._require_mutations_enabled.assert_called_once_with(
            "file_write",
            path=str(fake_base.AUDIT_LOG),
            fresh_preflight=True,
        )

if __name__ == "__main__":
    unittest.main()
