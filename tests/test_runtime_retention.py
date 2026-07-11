from __future__ import annotations

from contextlib import nullcontext
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
