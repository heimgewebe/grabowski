from __future__ import annotations

import ast
import asyncio
from contextlib import closing, contextmanager
import hashlib
import inspect
import io
import json
import os
import sqlite3
import stat
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import types
from typing import get_args, get_type_hints
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types


import grabowski_command_identity as command_identity
import grabowski_resources as resources
import grabowski_operator_routing_shadow_capture as routing_shadow
import grabowski_tasks as tasks
import grabowski_task_attention as task_attention
import grabowski_task_reconcile as task_reconcile_cli


LOCAL_HOST = {
    "transport": "local",
    "target": "local",
    "enabled": True,
    "roles": ["test"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}
REMOTE_HOST = {
    "transport": "ssh",
    "target": "remote",
    "enabled": True,
    "roles": ["worker"],
    "command_allowlist": ["*"],
    "connect_timeout_seconds": 10,
}


def _launcher(returncode: int = 0) -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": "",
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }


def _missing_unit_observation(
    *,
    observed_at_unix: int,
    duration_seconds: float,
    returncode: int = 0,
) -> dict[str, object]:
    probe = _launcher(returncode)
    probe["duration_seconds"] = duration_seconds
    return {
        "state": "completed",
        "properties": {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "Result": "success",
            "ExecMainCode": "0",
            "ExecMainStatus": "0",
        },
        "probe": probe,
        "observer": {
            "kind": "fleet-dispatch-v1",
            "execution_backend": "systemd-user",
            "systemd_scope": "user",
        },
        "observed_at_unix": observed_at_unix,
    }


class TaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / ".git").write_text("gitdir: /tmp/test-worktree\n")
        self.database = self.root / "state" / "tasks.sqlite3"
        self.db_patch = patch.object(tasks, "TASK_DB", self.database)
        self.outcomes_patch = patch.object(
            tasks,
            "TASK_OUTCOMES_DIR",
            self.database.with_suffix(".outcomes"),
        )
        self.output_root = self.root / "output-home"
        self.output_root.mkdir(mode=0o700)
        self.output_root_patch = patch.object(
            tasks, "TASK_OUTPUT_ROOT", self.output_root
        )
        self.legacy_output_root_patch = patch.object(
            tasks, "TASK_OUTPUT_LEGACY_ROOT", self.output_root
        )
        self.resource_database = self.root / "state" / "resources.sqlite3"
        self.resource_patch = patch.object(
            tasks.resources, "RESOURCE_DB", self.resource_database
        )
        self.admission_patch = patch.object(
            tasks.resources.work_admission,
            "require_repository_admission",
            return_value={
                "schema_version": 1,
                "decision": "allow",
                "assessment_sha256": "a" * 64,
                "read_only": True,
            },
        )
        self.real_reposkop_attest = tasks._attest_mutating_agent_workspace
        self.reposkop_attestation = {
            "schema_version": 1,
            "kind": tasks.REPOSKOP_EXECUTION_ATTESTATION_KIND,
            "policy_version": (
                tasks.REPOSKOP_EXECUTION_ATTESTATION_POLICY_VERSION
            ),
            "required": True,
            "status": "verified",
            "task_id": "test-task",
            "lease_owner_id": "task:test-task",
            "workspace_lease_resource_keys": [f"repo:{self.root}"],
            "workspace_lease_resource_keys_sha256": tasks._sha256_json(
                [f"repo:{self.root}"]
            ),
            "workspace": str(self.root),
            "argv_sha256": "1" * 64,
            "execution_identity_sha256": "2" * 64,
            "purpose": "grabowski-task-start:codex:12345678",
            "reposkop_executable_sha256": "3" * 64,
            "report_sha256": "4" * 64,
            "observation_sha256": "5" * 64,
            "projection_sha256": "6" * 64,
            "repository_identity_sha256": "7" * 64,
            "checkout_identity_sha256": "8" * 64,
            "usage_receipt_path": "/tmp/test-reposkop-receipt.json",
            "usage_receipt_sha256": "9" * 64,
            "usage_key_sha256": "a" * 64,
            "audit_ref": "audit-record-sha256:" + "b" * 64,
            "finding_summary": {
                "finding_taxonomy_status": "available_v2",
                "finding_taxonomy_version": 2,
                "finding_count": 1,
                "finding_counts": {
                    "critical": 0,
                    "error": 0,
                    "warning": 0,
                    "information": 1,
                },
                "finding_categories": {"lifecycle_evidence": 1},
                "finding_reason_codes": ["lifecycle_evidence_missing"],
                "projection_state": "inconclusive",
                "advisory_posture": "informational",
            },
            "effect_authorized": False,
            "execution_binding_sha256": "c" * 64,
        }
        self.reposkop_patch = patch.object(
            tasks,
            "_attest_mutating_agent_workspace",
            return_value=self.reposkop_attestation,
        )
        self.reposkop_shadow_before_patch = patch.object(
            tasks,
            "_capture_reposkop_shadow_before_best_effort",
            return_value={
                "phase": "before",
                "status": "completed",
                "before_observation_sha256": "d" * 64,
                "decision_effect": False,
                "effect_authorized": False,
                "audit_ref": "audit-record-sha256:" + "e" * 64,
            },
        )
        def shadow_prepare(*, task_id, before_summary):
            material = {
                "schema_version": 1,
                "kind": "grabowski.reposkop_checkout_shadow_evidence",
                "phase": "terminal_prepare",
                "status": "completed",
                "task_id": task_id,
                "evaluation_id": before_summary.get("evaluation_id"),
                "reposkop_cohort": before_summary.get("reposkop_cohort"),
                "captured_at_unix": 123,
                "before_evidence_sha256": before_summary.get(
                    "evidence_sha256", "1" * 64
                ),
                "before_observation_sha256": before_summary.get(
                    "before_observation_sha256", "d" * 64
                ),
                "after_observation_sha256": "2" * 64,
                "transition_sha256": "3" * 64,
                "continuity_sha256": "4" * 64,
                "continuity_state": "intact",
                "measurement_class": "intact/explainable_drift",
                "reason_codes": [],
                "anomaly_codes": [],
                "reposkop_executable_sha256": "5" * 64,
                "decision_effect": False,
                "effect_authorized": False,
            }
            return {**material, "evidence_sha256": tasks._sha256_json(material)}

        def shadow_finalize(
            *,
            task_id,
            terminalization_sha256,
            lifecycle_receipt_sha256,
            prepared,
        ):
            return {
                "phase": "terminal",
                "status": prepared["status"],
                "task_id": task_id,
                "evidence_sha256": "6" * 64,
                "decision_effect": False,
                "effect_authorized": False,
                "audit_ref": "audit-record-sha256:" + "7" * 64,
            }

        self.default_reposkop_shadow_prepare = shadow_prepare
        self.default_reposkop_shadow_finalize = shadow_finalize
        self.reposkop_shadow_prepare_patch = patch.object(
            tasks,
            "_prepare_reposkop_shadow_terminal_best_effort",
            side_effect=shadow_prepare,
        )
        self.reposkop_shadow_terminal_patch = patch.object(
            tasks,
            "_finalize_reposkop_shadow_terminal_best_effort",
            side_effect=shadow_finalize,
        )
        self.real_reposkop_shadow_terminal_finalize = (
            tasks._finalize_reposkop_shadow_terminal_best_effort
        )
        self.task_archive_root = self.root / "state" / "task-archives"
        self.task_projection_root = self.root / "state" / "task-projection"
        (self.root / "state").mkdir(parents=True, exist_ok=True)
        os.chmod(self.root / "state", 0o700)
        self.audit_log = self.root / "state" / "write-audit.jsonl"
        self.audit_patch = patch.object(tasks.base, "AUDIT_LOG", self.audit_log)
        self.audit_patch.start()
        self.db_patch.start()
        self.outcomes_patch.start()
        self.output_root_patch.start()
        self.legacy_output_root_patch.start()
        self.resource_patch.start()
        self.admission_patch.start()
        self.reposkop_attestation_mock = self.reposkop_patch.start()
        self.reposkop_shadow_before_mock = self.reposkop_shadow_before_patch.start()
        self.reposkop_shadow_prepare_mock = self.reposkop_shadow_prepare_patch.start()
        self.reposkop_shadow_terminal_mock = self.reposkop_shadow_terminal_patch.start()
        self.start_counter = 0

    def tearDown(self) -> None:
        self.reposkop_shadow_terminal_patch.stop()
        self.reposkop_shadow_prepare_patch.stop()
        self.reposkop_shadow_before_patch.stop()
        self.reposkop_patch.stop()
        self.admission_patch.stop()
        self.resource_patch.stop()
        self.legacy_output_root_patch.stop()
        self.output_root_patch.stop()
        self.outcomes_patch.stop()
        self.db_patch.stop()
        self.audit_patch.stop()
        self.temporary.cleanup()

    def _archive_and_project_tasks(self, task_ids: list[str]) -> dict[str, object]:
        lifecycle_evidence = tasks.lifecycle_projection.effect_plan.lifecycle_evidence
        records: list[dict[str, object]] = []
        for task_id in task_ids:
            current = tasks._row_raw(task_id)
            if current["state"] not in tasks.TASK_STATE_PROJECTIONS["terminal"]:
                tasks._set_state(
                    task_id,
                    "completed",
                    observation={"state": "completed", "source": "archive-test"},
                )
            records.append(tasks._task_archive_record(tasks._row_raw(task_id)))
        archived = tasks.lifecycle_projection.lifecycle.write_task_archive_segment(
            records,
            archive_root=self.task_archive_root,
            source_store_sha256="c" * 64,
            source_schema_version="5",
            plan_sha256="d" * 64,
        )
        all_sources = frozenset(lifecycle_evidence.REQUIRED_SOURCES)
        source_sha256s = {
            source: format(index + 1, "x") * 64
            for index, source in enumerate(sorted(all_sources))
        }
        classifications = [
            lifecycle_evidence.classify_observation_bundle(
                lifecycle_evidence.LifecycleObservationBundle(
                    identity=task_id,
                    kind="task",
                    observed_sources=all_sources,
                    source_sha256s=source_sha256s,
                    source_applicability={source: "observed" for source in all_sources},
                    state="completed",
                    archived=True,
                    receipt_integrity_valid=True,
                )
            )
            for task_id in task_ids
        ]
        now_unix = tasks._now()
        projection_resource = tasks.lifecycle_projection._projection_resource_key(
            self.task_projection_root
        )
        plan = tasks.lifecycle_projection.effect_plan.build_effect_plan(
            classifications,
            effect_kind="current_projection_switch",
            lease_owner_id="operator:test-current-task-projection",
            required_resource_keys=[projection_resource],
            created_at_unix=now_unix,
        )
        revalidation = tasks.lifecycle_projection.effect_plan.revalidate_effect_plan(
            plan,
            {item["identity"]: item for item in classifications},
            [
                tasks.lifecycle_projection.effect_plan.LeaseObservation(
                    resource_key=projection_resource,
                    owner_id="operator:test-current-task-projection",
                    expires_at_unix=now_unix + 1000,
                    metadata_sha256="a" * 64,
                )
            ],
            now_unix=now_unix,
        )
        return tasks.lifecycle_projection.apply_task_archive_projection_switch(
            Path(str(archived["segment_dir"])),
            projection_root=self.task_projection_root,
            plan=plan,
            revalidation=revalidation,
            applied_at_unix=now_unix + 1,
        )

    def _start(
        self,
        *,
        host: str = "local",
        resource_keys: list[str] | None = None,
    ) -> dict[str, object]:
        selected = LOCAL_HOST if host == "local" else REMOTE_HOST
        self.start_counter += 1
        command_argument = "ok" if self.start_counter == 1 else f"ok-{self.start_counter}"
        managed_runtime = {
            "XDG_RUNTIME_DIR": "/run/user/1000",
            "HEIM_NODE_RUNTIME_ENV_DIR": "/run/user/1000/grabowski-node-runtime-env",
            "UV_CACHE_DIR": "/run/user/1000/grabowski-uv-cache",
        }
        with patch.object(tasks.fleet, "fleet_host", return_value=selected), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ) as dispatch, patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
        ), patch.object(
            tasks.operator, "_managed_runtime_environment", return_value=managed_runtime
        ):
            result = tasks.grabowski_task_start(
                host,
                ["/bin/echo", command_argument],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="verify-then-retry",
                cpu_weight=50,
                io_weight=25,
                memory_max_bytes=64 * 1024 * 1024,
                resource_keys=resource_keys,
            )
        launch = dispatch.call_args.args[1]
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski task grabowski-task-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
        self.assertIn("--slice=grabowski-tasks.slice", launch)
        self.assertNotIn("--expand-environment=no", launch)
        self.assertEqual(launch.count("--property=LimitCORE=0"), 1)
        self.assertIn("--property=CPUWeight=50", launch)
        self.assertIn("--property=IOWeight=25", launch)
        self.assertIn("--property=MemoryMax=67108864", launch)
        self.assertIn("--property=NoNewPrivileges=no", launch)
        self.assertIn("--property=ProtectHome=no", launch)
        self.assertIn("--property=MemoryDenyWriteExecute=no", launch)
        self.assertIn("--property=UMask=0077", launch)
        managed_launch_env = {
            "--setenv=XDG_RUNTIME_DIR=/run/user/1000",
            "--setenv=HEIM_NODE_RUNTIME_ENV_DIR=/run/user/1000/grabowski-node-runtime-env",
            "--setenv=UV_CACHE_DIR=/run/user/1000/grabowski-uv-cache",
        }
        if selected["transport"] == "local":
            self.assertTrue(managed_launch_env.issubset(set(launch)))
        else:
            self.assertTrue(managed_launch_env.isdisjoint(set(launch)))
        self.assertEqual(launch.count("--property=StandardOutput=null"), 1)
        self.assertEqual(launch.count("--property=StandardError=journal"), 1)
        self.assertEqual(tasks.TASK_LOG_RATE_LIMIT_INTERVAL_SECONDS, 30)
        self.assertEqual(tasks.TASK_LOG_RATE_LIMIT_BURST, 200)
        self.assertEqual(
            launch.count("--property=LogRateLimitIntervalSec=30s"),
            1,
        )
        self.assertEqual(
            launch.count("--property=LogRateLimitBurst=200"),
            1,
        )
        separator = launch.index("--")
        capture = launch[separator + 1 :]
        paths = tasks._task_output_paths(result["task"])
        self.assertEqual(
            capture[:6],
            [
                tasks.TASK_OUTPUT_CAPTURE_PYTHON,
                "-c",
                tasks.TASK_OUTPUT_CAPTURE_CODE,
                str(paths["directory"]),
                str(tasks.TASK_OUTPUT_MAX_BYTES),
                str(tasks.TASK_OUTPUT_TAIL_BYTES),
            ],
        )
        self.assertEqual(capture[-2:], ["/bin/echo", command_argument])
        self.assertEqual(result["task"]["runtime_seconds"], 60)
        self.assertIn("--property=RuntimeMaxSec=60s", launch)
        return result

    def test_persistent_task_and_job_defaults_are_six_hours(self) -> None:
        self.assertEqual(tasks.operator.DEFAULT_JOB_RUNTIME, 21_600)
        for function in (
            tasks.grabowski_task_start,
            tasks._grabowski_task_start_tool,
            tasks.operator._start_job,
            tasks.operator.grabowski_job_start,
        ):
            self.assertEqual(
                inspect.signature(function).parameters["runtime_seconds"].default,
                21_600,
            )

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "default-runtime"],
                cwd=str(self.root),
                resume_policy="never",
            )

        launch = dispatch.call_args.args[1]
        self.assertEqual(result["task"]["runtime_seconds"], 21_600)
        self.assertIn("--property=RuntimeMaxSec=21600s", launch)

    def _write_task_output(
        self,
        task: dict[str, object],
        *,
        stdout: str = "",
        stderr: str = "",
    ) -> dict[str, Path]:
        paths = tasks._task_output_paths(task)
        paths["directory"].mkdir(mode=0o700)
        paths["stdout"].write_text(stdout, encoding="utf-8")
        paths["stderr"].write_text(stderr, encoding="utf-8")
        os.chmod(paths["stdout"], 0o600)
        os.chmod(paths["stderr"], 0o600)
        return paths

    def test_task_output_paths_are_attempt_bound(self) -> None:
        record = {"task_id": "a" * 24, "attempt": 1}
        first = tasks._task_output_paths(record)
        second = tasks._task_output_paths({**record, "attempt": 2})
        self.assertNotEqual(first["directory"], second["directory"])
        self.assertEqual(first["stdout"].name, "stdout.log")
        self.assertEqual(first["stderr"].name, "stderr.log")
        self.assertEqual(first["directory"].parent, self.output_root)

    def test_task_output_cutover_uses_legacy_before_binding_and_managed_after(self) -> None:
        managed = self.root / "managed-output"
        legacy = self.root / "legacy-output"
        managed.mkdir(mode=0o700)
        legacy.mkdir(mode=0o700)
        record = {
            "task_id": "e" * 24,
            "attempt": 1,
            "launcher_json": json.dumps(
                {tasks.TASK_OUTPUT_LAUNCHER_BINDING_KEY: 2}
            ),
        }
        with patch.object(tasks, "TASK_OUTPUT_ROOT", managed), patch.object(
            tasks, "TASK_OUTPUT_LEGACY_ROOT", legacy
        ):
            first = tasks._task_output_paths(record)
            second_record = {**record, "attempt": 2}
            second = tasks._task_output_paths(second_record)
            self.assertEqual(tasks._task_output_contract_version(record), 1)
            self.assertEqual(tasks._task_output_contract_version(second_record), 2)
        self.assertEqual(first["directory"].parent, legacy)
        self.assertEqual(second["directory"].parent, managed)

    def test_local_task_start_persists_managed_output_binding(self) -> None:
        started = self._start()
        task = started["task"]
        self.assertEqual(
            task["launcher"][tasks.TASK_OUTPUT_LAUNCHER_BINDING_KEY],
            1,
        )
        self.assertEqual(
            tasks._task_output_paths(tasks._row_raw(str(task["task_id"])))["directory"].parent,
            self.output_root,
        )
        self.assertEqual(started["audit"]["task_output_managed_from_attempt"], 1)

    def test_remote_task_start_retains_legacy_output_contract(self) -> None:
        started = self._start(host="remote")
        task = started["task"]
        self.assertNotIn(tasks.TASK_OUTPUT_LAUNCHER_BINDING_KEY, task["launcher"])
        self.assertIsNone(started["audit"]["task_output_managed_from_attempt"])
        self.assertEqual(
            tasks._task_output_contract_version(tasks._row_raw(str(task["task_id"]))),
            1,
        )

    def test_ensure_local_task_output_root_creates_private_idempotent_root(self) -> None:
        parent = self.root / "managed-state"
        parent.mkdir(mode=0o700)
        managed = parent / "task-output"
        with patch.object(tasks, "TASK_OUTPUT_ROOT", managed):
            tasks._ensure_local_task_output_root()
            before = managed.stat()
            tasks._ensure_local_task_output_root()
            after = managed.stat()
        self.assertTrue(managed.is_dir())
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

    def test_ensure_local_task_output_root_rejects_group_writable_parent(self) -> None:
        parent = self.root / "unsafe-managed-state"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o775)
        managed = parent / "task-output"
        with patch.object(tasks, "TASK_OUTPUT_ROOT", managed):
            with self.assertRaisesRegex(RuntimeError, "root parent identity is unsafe"):
                tasks._ensure_local_task_output_root()
        self.assertFalse(managed.exists())

    def test_capture_wrapper_bounds_streams_and_preserves_exit_status(self) -> None:
        child = (
            "import sys\n"
            "for i in range(1000): print(f'out-{i:04d}', flush=True)\n"
            "for i in range(1000): print(f'err-{i:04d}', file=sys.stderr, flush=True)\n"
            "raise SystemExit(7)\n"
        )
        record = {
            "task_id": "b" * 24,
            "attempt": 1,
            "argv_json": json.dumps(["/usr/bin/python3", "-c", child]),
        }
        os.chmod(self.output_root, 0o755)
        with patch.object(tasks, "TASK_OUTPUT_MAX_BYTES", 4096), patch.object(
            tasks, "TASK_OUTPUT_TAIL_BYTES", 512
        ):
            argv = tasks._task_output_capture_argv(record)
            completed = subprocess.run(
                argv,
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")
        paths = tasks._task_output_paths(record)
        self.assertEqual(stat.S_IMODE(paths["directory"].stat().st_mode), 0o700)
        for stream in ("stdout", "stderr"):
            self.assertEqual(stat.S_IMODE(paths[stream].stat().st_mode), 0o600)
            self.assertLessEqual(paths[stream].stat().st_size, 4096)
        stdout = paths["stdout"].read_text(encoding="utf-8")
        stderr = paths["stderr"].read_text(encoding="utf-8")
        self.assertIn("out-0000", stdout)
        self.assertIn("out-0999", stdout)
        self.assertIn("GRABOWSKI_TASK_OUTPUT_TRUNCATED stdout", stdout)
        self.assertIn("err-0000", stderr)
        self.assertIn("err-0999", stderr)
        self.assertIn("GRABOWSKI_TASK_OUTPUT_TRUNCATED stderr", stderr)

    def test_capture_wrapper_treats_direct_rg_no_match_as_success(self) -> None:
        fake_rg = self.root / "rg"
        fake_rg.write_text("#!/usr/bin/python3\nraise SystemExit(1)\n", encoding="utf-8")
        fake_rg.chmod(0o755)
        record = {
            "task_id": "9" * 24,
            "attempt": 1,
            "argv_json": json.dumps([str(fake_rg)]),
        }
        completed = subprocess.run(
            tasks._task_output_capture_argv(record),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_capture_wrapper_does_not_mask_missing_rg_executable(self) -> None:
        missing_rg = self.root / "missing" / "rg"
        record = {
            "task_id": "a" * 24,
            "attempt": 1,
            "argv_json": json.dumps([str(missing_rg)]),
        }
        completed = subprocess.run(
            tasks._task_output_capture_argv(record),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)

    def test_capture_wrapper_refuses_existing_output_directory_before_child(self) -> None:
        side_effect = self.root / "child-started"
        record = {
            "task_id": "c" * 24,
            "attempt": 1,
            "argv_json": json.dumps(
                [
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path; Path(" + repr(str(side_effect)) + ").write_text('yes')",
                ]
            ),
        }
        paths = tasks._task_output_paths(record)
        paths["directory"].mkdir(mode=0o700)
        completed = subprocess.run(
            tasks._task_output_capture_argv(record),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(side_effect.exists())
        self.assertFalse(paths["stdout"].exists())
        self.assertFalse(paths["stderr"].exists())

    def test_capture_wrapper_rejects_group_writable_parent_before_child(self) -> None:
        side_effect = self.root / "unsafe-parent-child-started"
        record = {
            "task_id": "d" * 24,
            "attempt": 1,
            "argv_json": json.dumps(
                [
                    "/usr/bin/python3",
                    "-c",
                    "from pathlib import Path; Path("
                    + repr(str(side_effect))
                    + ").write_text('yes')",
                ]
            ),
        }
        os.chmod(self.output_root, 0o775)
        completed = subprocess.run(
            tasks._task_output_capture_argv(record),
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("task output parent identity is unsafe", completed.stderr)
        self.assertFalse(side_effect.exists())
        self.assertFalse(tasks._task_output_paths(record)["directory"].exists())

    def test_task_logs_rejects_group_writable_parent(self) -> None:
        task = self._start()["task"]
        self._write_task_output(task, stdout="private\n", stderr="")
        os.chmod(self.output_root, 0o775)
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(RuntimeError, "parent identity is unsafe"):
                tasks.grabowski_task_logs(str(task["task_id"]), max_lines=20)

    def test_task_logs_reads_private_files_without_journal_dispatch(self) -> None:
        task = self._start()["task"]
        self._write_task_output(
            task,
            stdout="out-one\nout-two\nout-three\n",
            stderr="err-one\nerr-two\n",
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch"
        ) as dispatch:
            output = tasks.grabowski_task_logs(str(task["task_id"]), max_lines=2)
        dispatch.assert_not_called()
        self.assertEqual(output["output_source"], "private-task-files-v1")
        self.assertEqual(output["result"]["output_reader"], "local-descriptor-v1")
        self.assertEqual(output["result"]["stdout"], "out-two\nout-three\n")
        self.assertEqual(output["result"]["stderr"], "err-one\nerr-two\n")
        self.assertTrue(output["result"]["stdout_truncated"])
        self.assertFalse(output["result"]["stderr_truncated"])
        self.assertEqual(
            output["result"]["does_not_establish"],
            [
                "same_uid_output_authenticity",
                "complete_output_beyond_stream_cap",
                "retention_or_archive_completion",
            ],
        )

    def test_task_logs_falls_back_to_user_journal_when_directory_is_absent(self) -> None:
        task = self._start()["task"]
        legacy = _launcher()
        legacy["stdout"] = "legacy journal\n"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=legacy
        ) as dispatch:
            output = tasks.grabowski_task_logs(str(task["task_id"]), max_lines=20)
        self.assertEqual(output["output_source"], "user-journal-fallback-v1")
        self.assertEqual(output["result"]["stdout"], "legacy journal\n")
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(dispatch.call_args.args[1][0], "journalctl")

    def test_task_logs_rejects_incomplete_private_output_contract(self) -> None:
        task = self._start()["task"]
        paths = tasks._task_output_paths(task)
        paths["directory"].mkdir(mode=0o700)
        paths["stdout"].write_text("partial\n", encoding="utf-8")
        os.chmod(paths["stdout"], 0o600)
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch"
        ) as dispatch:
            with self.assertRaisesRegex(RuntimeError, "missing stderr"):
                tasks.grabowski_task_logs(str(task["task_id"]), max_lines=20)
        dispatch.assert_not_called()

    def test_task_logs_rejects_symlink_broad_mode_and_hardlink(self) -> None:
        symlink_task = self._start()["task"]
        symlink_paths = tasks._task_output_paths(symlink_task)
        symlink_paths["directory"].mkdir(mode=0o700)
        target = self.output_root / "symlink-target"
        target.write_text("secret\n", encoding="utf-8")
        os.chmod(target, 0o600)
        symlink_paths["stdout"].symlink_to(target)
        symlink_paths["stderr"].write_text("", encoding="utf-8")
        os.chmod(symlink_paths["stderr"], 0o600)
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(RuntimeError, "opened safely"):
                tasks.grabowski_task_logs(str(symlink_task["task_id"]), max_lines=20)

        broad_task = self._start()["task"]
        broad_paths = self._write_task_output(broad_task, stdout="broad\n")
        os.chmod(broad_paths["stdout"], 0o644)
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                tasks.grabowski_task_logs(str(broad_task["task_id"]), max_lines=20)

        hardlink_task = self._start()["task"]
        hardlink_paths = self._write_task_output(hardlink_task, stdout="linked\n")
        os.link(hardlink_paths["stdout"], self.output_root / "second-link")
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                tasks.grabowski_task_logs(str(hardlink_task["task_id"]), max_lines=20)

    def test_remote_task_logs_use_descriptor_bound_reader_for_each_stream(self) -> None:
        task = self._start(host="remote")["task"]
        stdout = _launcher()
        stdout.update(
            {
                "stdout": "remote-out\n",
                "stderr": (
                    "GRABOWSKI_TASK_OUTPUT_READ_METADATA "
                    "byte_truncated=0 line_truncated=0\n"
                ),
            }
        )
        stderr = _launcher()
        stderr.update(
            {
                "stdout": "remote-err\n",
                "stderr": (
                    "GRABOWSKI_TASK_OUTPUT_READ_METADATA "
                    "byte_truncated=0 line_truncated=1\n"
                ),
            }
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=REMOTE_HOST), patch.object(
            tasks.fleet,
            "run_fleet_task_output_read",
            side_effect=[{"result": stdout}, {"result": stderr}],
        ) as reader:
            output = tasks.grabowski_task_logs(str(task["task_id"]), max_lines=25)
        self.assertEqual(reader.call_count, 2)
        for call in reader.call_args_list:
            self.assertEqual(call.args[1][:3], [
                tasks.TASK_OUTPUT_CAPTURE_PYTHON,
                "-c",
                tasks.TASK_OUTPUT_REMOTE_READ_CODE,
            ])
            self.assertEqual(call.kwargs["timeout_seconds"], 30)
            self.assertEqual(
                call.kwargs["max_output_bytes"],
                int(tasks.operator.DEFAULT_OUTPUT_BYTES),
            )
        self.assertEqual(output["output_source"], "private-task-files-v1")
        self.assertEqual(output["result"]["output_reader"], "fleet-descriptor-v1")
        self.assertEqual(output["result"]["stdout"], "remote-out\n")
        self.assertEqual(output["result"]["stderr"], "remote-err\n")
        self.assertFalse(output["result"]["stdout_truncated"])
        self.assertTrue(output["result"]["stderr_truncated"])

    def test_remote_task_logs_fail_closed_on_invalid_reader_metadata(self) -> None:
        task = self._start(host="remote")["task"]
        invalid = _launcher()
        invalid.update({"stdout": "remote-out\n", "stderr": "not metadata\n"})
        with patch.object(tasks.fleet, "fleet_host", return_value=REMOTE_HOST), patch.object(
            tasks.fleet,
            "run_fleet_task_output_read",
            return_value={"result": invalid},
        ):
            with self.assertRaisesRegex(RuntimeError, "metadata is invalid"):
                tasks.grabowski_task_logs(str(task["task_id"]), max_lines=25)

    def test_remote_reader_code_executes_descriptor_bound_contract(self) -> None:
        task = self._start()["task"]
        paths = self._write_task_output(
            task,
            stdout="remote-one\nremote-two\nremote-three\n",
            stderr="",
        )
        completed = subprocess.run(
            [
                tasks.TASK_OUTPUT_CAPTURE_PYTHON,
                "-c",
                tasks.TASK_OUTPUT_REMOTE_READ_CODE,
                str(paths["directory"]),
                "stdout.log",
                "2",
                "60000",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "remote-two\nremote-three\n")
        self.assertIn(
            "GRABOWSKI_TASK_OUTPUT_READ_METADATA byte_truncated=0 line_truncated=1",
            completed.stderr,
        )

    def _cleanup_command(
        self,
        mode: str,
        task: dict[str, object],
        token: str,
        *,
        stdout_sha256: str = "-",
        stderr_sha256: str = "-",
        stdout_bytes: int = -1,
        stderr_bytes: int = -1,
    ) -> list[str]:
        paths = tasks._task_output_paths(task)
        return [
            tasks.TASK_OUTPUT_CAPTURE_PYTHON,
            "-c",
            tasks.TASK_OUTPUT_CLEANUP_CODE,
            mode,
            str(paths["directory"]),
            token,
            stdout_sha256,
            stderr_sha256,
            str(stdout_bytes),
            str(stderr_bytes),
        ]

    def test_cleanup_code_inspects_and_deletes_exact_private_output(self) -> None:
        task = self._start()["task"]
        paths = self._write_task_output(
            task, stdout="alpha\nbeta\n", stderr="error\n"
        )
        token = "1" * 64
        inspected = subprocess.run(
            self._cleanup_command("inspect", task, token),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(inspected.returncode, 0)
        inventory = json.loads(inspected.stdout)
        self.assertEqual(inventory["task_id"], task["task_id"])
        self.assertEqual(inventory["attempt"], task["attempt"])
        self.assertEqual(inventory["streams"]["stdout"]["bytes"], 11)
        self.assertEqual(inventory["streams"]["stderr"]["bytes"], 6)
        deleted = subprocess.run(
            self._cleanup_command(
                "delete",
                task,
                token,
                stdout_sha256=inventory["streams"]["stdout"]["sha256"],
                stderr_sha256=inventory["streams"]["stderr"]["sha256"],
                stdout_bytes=inventory["streams"]["stdout"]["bytes"],
                stderr_bytes=inventory["streams"]["stderr"]["bytes"],
            ),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(deleted.returncode, 0, deleted.stderr)
        result = json.loads(deleted.stdout)
        self.assertEqual(result["post_state"], "absent")
        self.assertEqual(result["removed"], ["stdout.log", "stderr.log"])
        self.assertFalse(paths["directory"].exists())
        self.assertFalse(any(self.output_root.glob(".grabowski-task-output-cleanup-*")))

    def test_cleanup_code_hash_drift_preserves_original_directory(self) -> None:
        task = self._start()["task"]
        paths = self._write_task_output(task, stdout="original\n", stderr="")
        token = "2" * 64
        inspected = subprocess.run(
            self._cleanup_command("inspect", task, token),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        inventory = json.loads(inspected.stdout)
        paths["stdout"].write_text("changed\n", encoding="utf-8")
        os.chmod(paths["stdout"], 0o600)
        deleted = subprocess.run(
            self._cleanup_command(
                "delete",
                task,
                token,
                stdout_sha256=inventory["streams"]["stdout"]["sha256"],
                stderr_sha256=inventory["streams"]["stderr"]["sha256"],
                stdout_bytes=inventory["streams"]["stdout"]["bytes"],
                stderr_bytes=inventory["streams"]["stderr"]["bytes"],
            ),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(deleted.returncode, 0)
        self.assertIn("inventory mismatch", deleted.stderr)
        self.assertTrue(paths["directory"].is_dir())
        self.assertEqual(paths["stdout"].read_text(encoding="utf-8"), "changed\n")
        self.assertFalse(any(self.output_root.glob(".grabowski-task-output-cleanup-*")))

    def test_cleanup_code_resumes_exact_staging_after_partial_delete(self) -> None:
        task = self._start()["task"]
        paths = self._write_task_output(task, stdout="stdout\n", stderr="stderr\n")
        token = "3" * 64
        inspected = subprocess.run(
            self._cleanup_command("inspect", task, token),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        inventory = json.loads(inspected.stdout)
        staging = self.output_root / (
            f".grabowski-task-output-cleanup-{task['task_id']}-a{task['attempt']}-"
            + token[:16]
        )
        paths["directory"].rename(staging)
        (staging / "stdout.log").unlink()
        resumed = subprocess.run(
            self._cleanup_command(
                "delete",
                task,
                token,
                stdout_sha256=inventory["streams"]["stdout"]["sha256"],
                stderr_sha256=inventory["streams"]["stderr"]["sha256"],
                stdout_bytes=inventory["streams"]["stdout"]["bytes"],
                stderr_bytes=inventory["streams"]["stderr"]["bytes"],
            ),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        result = json.loads(resumed.stdout)
        self.assertTrue(result["resumed_from_staging"])
        self.assertEqual(result["removed"], ["stderr.log"])
        self.assertFalse(staging.exists())
        self.assertFalse(paths["directory"].exists())

    def test_cleanup_code_rejects_unexpected_directory_entry(self) -> None:
        task = self._start()["task"]
        paths = self._write_task_output(task, stdout="stdout\n", stderr="")
        extra = paths["directory"] / "unexpected"
        extra.write_text("no", encoding="utf-8")
        os.chmod(extra, 0o600)
        inspected = subprocess.run(
            self._cleanup_command("inspect", task, "4" * 64),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(inspected.returncode, 0)
        self.assertIn("unexpected entries", inspected.stderr)
        self.assertTrue(paths["directory"].exists())

    def _prepare_pending_terminalization(
        self,
        *,
        terminal_state: str = "failed",
        prepared_at_unix: int | None = None,
    ) -> dict[str, object]:
        started = self._start()["task"]
        task_id = str(started["task_id"])
        record = tasks._row_raw(task_id)
        observation = {
            "state": terminal_state,
            "source": "pending-reconcile-fixture",
        }
        projection = tasks._terminal_projection(
            record,
            terminal_state,
            observation=observation,
        )
        transition = resources.begin_task_terminalization(
            task_id,
            int(record["attempt"]),
            str(record["lease_owner_id"]),
            terminal_state,
            tasks._record_resource_keys(record),
            task_projection=projection,
            observation_sha256=tasks._sha256_json(observation),
        )
        if prepared_at_unix is not None:
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE task_terminalizations SET prepared_at_unix=? "
                    "WHERE task_id=?",
                    (prepared_at_unix, task_id),
                )
                connection.commit()
            transition = resources.task_terminalization_record(
                task_id,
                include_projection=True,
            )
        if transition is None:
            raise AssertionError("pending terminalization fixture disappeared")
        return transition

    def _store_terminalization_recovery_cycle(
        self,
        *,
        high_water: tuple[int, str],
        cursor: tuple[int, str],
    ) -> str:
        payload = tasks._canonical_json(
            {
                "version": tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_VERSION,
                "high_water": {
                    "prepared_at_unix": high_water[0],
                    "task_id": high_water[1],
                },
                "cursor": {
                    "prepared_at_unix": cursor[0],
                    "task_id": cursor[1],
                },
            }
        )
        with tasks._database() as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (
                    tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,
                    payload,
                ),
            )
            connection.commit()
        return payload

    def test_task_start_captures_verified_direct_route_before_launch(self) -> None:
        from tests.test_task_routing_shadow_capture import direct_route_evidence

        capture_result = {
            "schema_version": 1,
            "status": "created",
            "binding_status": "created",
            "binding_id": "b" * 64,
            "no_effect": dict(routing_shadow.NO_EFFECT),
        }
        order: list[str] = []

        def capture_side_effect(**kwargs):
            order.append("capture")
            self.assertEqual(
                "direct_operator", kwargs["route_evidence"]["actual_route"]
            )
            self.assertEqual(str(self.root), kwargs["cwd"])
            self.assertEqual(60, kwargs["runtime_seconds"])
            return capture_result

        def dispatch_side_effect(*args, **kwargs):
            order.append("launch")
            return _launcher()

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", side_effect=dispatch_side_effect),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
            patch.object(
                routing_shadow,
                "capture_direct_task_start_best_effort",
                side_effect=capture_side_effect,
            ),
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "ok"],
                cwd=str(self.root),
                runtime_seconds=60,
                route_evidence=direct_route_evidence(),
            )

        self.assertEqual("capture", order[0])
        self.assertIn("launch", order)
        self.assertEqual(capture_result, result["routing_shadow_capture"])
        self.assertEqual(capture_result, result["audit"]["routing_shadow_capture"])
    def test_task_start_capture_error_does_not_block_launch(self) -> None:
        from tests.test_task_routing_shadow_capture import direct_route_evidence

        capture_result = {
            "schema_version": 1,
            "status": "error",
            "reason_code": "capture_error",
            "binding_status": "not_created",
            "no_effect": dict(routing_shadow.NO_EFFECT),
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
            patch.object(
                routing_shadow,
                "capture_direct_task_start_best_effort",
                return_value=capture_result,
            ),
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "ok"],
                cwd=str(self.root),
                runtime_seconds=60,
                route_evidence=direct_route_evidence(),
            )
        self.assertTrue(dispatch.called)
        self.assertEqual(capture_result, result["routing_shadow_capture"])
        self.assertIn(result["task"]["state"], {"running", "completed"})
    def test_task_start_rejects_non_direct_route_before_launch(self) -> None:
        from tests.test_task_routing_shadow_capture import direct_route_evidence

        invalid = direct_route_evidence()
        invalid["actual_route"] = "workspace_with_contrast"
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            with self.assertRaisesRegex(ValueError, "route evidence is invalid"):
                tasks.grabowski_task_start(
                    "local",
                    ["/bin/echo", "ok"],
                    cwd=str(self.root),
                    runtime_seconds=60,
                    route_evidence=invalid,
                )
        dispatch.assert_not_called()
    def test_task_routing_shadow_seal_requires_terminal_compatible_provenance(
        self,
    ) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        sealed = {
            "schema_version": 1,
            "status": "created",
            "record_id": "r" * 64,
            "eligibility_id": "e" * 64,
            "case_id": "c" * 64,
            "record_schema_version": routing_shadow.RECORD_V3_SCHEMA_VERSION,
            "no_effect": dict(routing_shadow.NO_EFFECT),
        }
        with (
            patch.object(tasks, "_observe", return_value={"state": "completed"}),
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                routing_shadow, "seal_direct_task_case", return_value=sealed
            ) as seal_call,
        ):
            result = tasks.grabowski_task_routing_shadow_seal(
                task_id,
                {
                    "status": "abstained",
                    "reason_code": "no_semantic_review",
                    "observed_at": "2026-07-24T17:31:00Z",
                },
                [],
                {
                    "status": "completed",
                    "observed_at": "2026-07-24T17:30:30Z",
                    "evidence_refs": ["artifact:task-finalization"],
                },
                [],
            )
        self.assertEqual("completed", result["observed_task_state"])
        self.assertEqual(sealed, result["sealed"])
        seal_call.assert_called_once()
        record = tasks._row(task_id)
        self.assertEqual(
            routing_shadow.build_direct_task_identity(
                host=str(record["host"]),
                argv_sha256=str(record["argv_sha256"]),
                cwd=str(record["cwd"]),
                resource_keys=tasks._record_resource_keys(record),
                runtime_seconds=int(record["runtime_seconds"]),
            ),
            seal_call.call_args.kwargs["authoritative_task_identity"],
        )

        with patch.object(tasks, "_observe", return_value={"state": "completed"}):
            with self.assertRaisesRegex(ValueError, "requires execution_provenance"):
                tasks.grabowski_task_routing_shadow_seal(
                    task_id,
                    {
                        "status": "abstained",
                        "reason_code": "no_semantic_review",
                        "observed_at": "2026-07-24T17:31:00Z",
                    },
                    [],
                    {
                        "status": "infrastructure_failure",
                        "observed_at": "2026-07-24T17:30:30Z",
                        "evidence_refs": ["artifact:task-finalization"],
                    },
                    [],
                )

    def test_task_routing_shadow_seal_rejects_missing_direct_binding(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        cohort_root = self.root / "routing-shadow-cohort"
        with (
            patch.object(tasks, "_observe", return_value={"state": "completed"}),
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.dict(
                os.environ,
                {"GRABOWSKI_ROUTING_SHADOW_COHORT_ROOT": str(cohort_root)},
            ),
        ):
            with self.assertRaises(routing_shadow.ShadowCaptureError):
                tasks.grabowski_task_routing_shadow_seal(
                    task_id,
                    {
                        "status": "abstained",
                        "reason_code": "no_semantic_review",
                        "observed_at": "2026-07-24T17:31:00Z",
                    },
                    [],
                    {
                        "status": "completed",
                        "observed_at": "2026-07-24T17:30:30Z",
                        "evidence_refs": ["artifact:task-finalization"],
                    },
                    [],
                )
        self.assertFalse((cohort_root / "eligibility").exists())
        self.assertFalse((cohort_root / "records").exists())

    def test_systemd_escape_argv_doubles_only_dollars_without_mutating_input(self) -> None:
        command = [
            "$HOME",
            "${cluster}",
            "$(uname)",
            "${{ github.sha }}",
            "$$",
            "plain",
            "Grüße 🌍",
        ]
        original = list(command)

        self.assertEqual(
            command_identity.systemd_escape_argv(command),
            [
                "$$HOME",
                "$${cluster}",
                "$$(uname)",
                "$${{ github.sha }}",
                "$$$$",
                "plain",
                "Grüße 🌍",
            ],
        )
        self.assertEqual(command, original)

    def test_task_start_preserves_literal_shell_and_template_argv_end_to_end(self) -> None:
        command = [
            "/usr/bin/bash",
            "-lc",
            "cluster=alpha\nexpected=beta\nprintf '%s|%s\\n' \"${cluster}\" \"${expected}\"",
            "$HOME",
            "$(uname)",
            "${{ github.sha }}",
            "quote='\"'",
            "heredoc=<<'EOF'\n${cluster}\nEOF",
            "Grüße 🌍",
        ]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ) as dispatch, patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
        ):
            result = tasks.grabowski_task_start(
                "local",
                command,
                cwd=str(self.root),
                runtime_seconds=60,
            )

        task = result["task"]
        launch = dispatch.call_args.args[1]
        separator = launch.index("--")
        self.assertEqual(command, task["argv"])
        self.assertEqual(command_identity.argv_sha256(command), task["argv_sha256"])
        capture = tasks._task_output_capture_argv(
            {
                "task_id": task["task_id"],
                "attempt": task["attempt"],
                "argv_json": json.dumps(command),
            }
        )
        self.assertEqual(
            command_identity.systemd_escape_argv(capture),
            launch[separator + 1 :],
        )
        self.assertEqual(
            command_identity.systemd_escape_argv(command),
            launch[-len(command) :],
        )
        self.assertNotIn("--expand-environment=no", launch[:separator])

    def test_start_chronik_context_persists_target_component_bureau_and_pr_refs(self) -> None:
        outbox_root = self.root / "chronik-context-state"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.operator, "_run", return_value={"returncode": 0, "stdout": "git@github.com:heimgewebe/grabowski.git"}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/usr/bin/python3", "-c", "print('ok')"],
                cwd=str(self.root),
                resource_keys=[f"repo:{self.root}"],
                chronik_outbox=True,
                chronik_outbox_state_root=str(outbox_root),
                chronik_operation="implement",
                chronik_component="task-runner",
                chronik_bureau_task_id="CCM-V1-T002",
                chronik_pr_number=306,
            )
        context = result["task"]["chronik_context"]
        self.assertEqual("repository", context["subject_scope"])
        self.assertEqual("heimgewebe/grabowski", context["repo"])
        self.assertEqual("implement", context["operation"])
        self.assertEqual("task-runner", context["component"])
        self.assertEqual("CCM-V1-T002", context["bureau_task_id"])
        self.assertEqual(306, context["pr_number"])

    def test_start_rejects_chronik_context_metadata_without_outbox(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(ValueError, "requires chronik_outbox"):
                tasks.grabowski_task_start(
                    "local",
                    ["/usr/bin/python3", "-c", "print('ok')"],
                    cwd=str(self.root),
                    chronik_component="task-runner",
                )

    def test_start_rejects_invalid_chronik_pr_reference(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            for value in (-1, 0, 2_147_483_648, True, "306"):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(
                        ValueError, "chronik_pr_number"
                    ):
                        tasks.grabowski_task_start(
                            "local",
                            ["/usr/bin/python3", "-c", "print('ok')"],
                            cwd=str(self.root),
                            chronik_outbox=True,
                            chronik_pr_number=value,
                        )

    def test_server_task_lease_delegation_requires_running_task_and_live_leases(self) -> None:
        result = self._start(resource_keys=["component:test-task-delegation"])
        task = result["task"]
        owner = task["lease_owner_id"]

        evidence = tasks.server_task_lease_delegation_evidence(owner)

        self.assertEqual(task["task_id"], evidence["task_id"])
        self.assertEqual(owner, evidence["lease_owner_id"])
        self.assertEqual("running", evidence["state"])
        self.assertEqual(task["resource_keys"], evidence["resource_keys"])
        self.assertRegex(evidence["task_record_sha256"], r"[0-9a-f]{64}\Z")

        tasks._set_state(task["task_id"], "completed")
        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(owner)

    def test_terminalization_atomically_revokes_owner_leases_and_binds_lifecycle_receipt(self) -> None:
        result = self._start(
            resource_keys=[
                "component:test-terminalization-a",
                "service:test-terminalization-b",
            ]
        )
        task = result["task"]
        task_id = task["task_id"]
        owner = task["lease_owner_id"]
        resources.acquire_resources(
            owner,
            ["component:test-terminalization-late"],
            purpose="late owner-bound task lease",
            ttl_seconds=120,
            metadata={"task_id": task_id, "attempt": 1},
        )
        observation = {"state": "completed", "source": "unit-test"}

        stored = tasks._set_state(
            task_id,
            "completed",
            observation=observation,
        )

        self.assertEqual("completed", stored["state"])
        transition = resources.task_terminalization_record(task_id)
        self.assertIsNotNone(transition)
        self.assertEqual("projected", transition["phase"])
        self.assertEqual(
            sorted(
                [
                    "component:test-terminalization-a",
                    "component:test-terminalization-late",
                    "service:test-terminalization-b",
                ]
            ),
            transition["revoked_resource_keys"],
        )
        self.assertEqual([], resources.list_resources(owner_id=owner))
        self.assertEqual(
            transition["transition_sha256"], stored["terminalization_sha256"]
        )
        receipt_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(2, payload["schema_version"])
        self.assertEqual("grabowski_task_lifecycle_receipt", payload["kind"])
        self.assertEqual(
            transition["transition_sha256"],
            payload["terminalization"]["transition_sha256"],
        )
        self.assertEqual(payload["receipt_sha256"], stored["lifecycle_receipt_sha256"])
        self.assertEqual(payload["receipt_sha256"], transition["lifecycle_receipt_sha256"])
        self.reposkop_shadow_terminal_mock.assert_not_called()
        with self.assertRaisesRegex(ValueError, "terminalized task owner"):
            resources.acquire_resources(
                owner,
                ["component:test-terminalization-revival"],
                purpose="forbidden terminal task revival",
                ttl_seconds=120,
                metadata={"task_id": task_id, "attempt": 1},
            )

    def test_terminal_shadow_runs_only_after_recorded_before_attempt(self) -> None:
        result = self._start(resource_keys=["component:test-terminal-shadow-before"])
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        launcher = json.loads(record["launcher_json"])
        launcher["reposkop_checkout_shadow_before"] = {
            "phase": "before",
            "status": "unavailable",
            "measurement_class": "inconclusive/unavailable",
            "failure_category": "capability_unavailable",
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "f" * 64,
        }

        stored = tasks._set_state(
            task_id,
            "completed",
            launcher=launcher,
            observation={"state": "completed", "source": "shadow-gate-test"},
        )

        transition = resources.task_terminalization_record(task_id)
        self.assertIsNotNone(transition)
        receipt_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual("completed", stored["state"])
        self.reposkop_shadow_prepare_mock.assert_called_once()
        stored_launcher = json.loads(stored["launcher_json"])
        prepared = stored_launcher["reposkop_checkout_shadow_terminal_prepare"]
        self.reposkop_shadow_terminal_mock.assert_called_once_with(
            task_id=task_id,
            terminalization_sha256=transition["transition_sha256"],
            lifecycle_receipt_sha256=payload["receipt_sha256"],
            prepared=prepared,
        )
        self.assertIsNotNone(tasks._reposkop_shadow_terminal_marker(task_id))

    def test_terminal_shadow_prepare_runs_while_writer_lease_is_held(self) -> None:
        path_key = f"path:{self.root}"
        result = self._start(resource_keys=[path_key])
        task_id = str(result["task"]["task_id"])
        owner = str(result["task"]["lease_owner_id"])
        original_prepare = self.default_reposkop_shadow_prepare

        def assert_owned(*, task_id, before_summary):
            lease = resources.inspect_resource(path_key)
            self.assertIsNotNone(lease)
            self.assertEqual(owner, lease["owner_id"])
            return original_prepare(task_id=task_id, before_summary=before_summary)

        self.reposkop_shadow_prepare_mock.side_effect = assert_owned
        record = tasks._row_raw(task_id)
        launcher = json.loads(record["launcher_json"])
        launcher["reposkop_checkout_shadow_before"] = {
            "phase": "before",
            "status": "completed",
            "evaluation_id": "8" * 64,
            "reposkop_cohort": "prospective_control",
            "before_observation_sha256": "d" * 64,
            "evidence_sha256": "1" * 64,
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "e" * 64,
        }

        stored = tasks._set_state(
            task_id,
            "completed",
            launcher=launcher,
            observation={"state": "completed", "source": "ownership-test"},
        )

        self.assertEqual("completed", stored["state"])
        self.reposkop_shadow_prepare_mock.assert_called_once()
        self.assertIsNone(resources.inspect_resource(path_key))

    def test_terminal_shadow_adapter_failure_cannot_block_terminal_state(self) -> None:
        import grabowski_reposkop_shadow

        before_summary = {
            "evaluation_id": "8" * 64,
            "reposkop_cohort": "prospective_control",
            "before_observation_sha256": "d" * 64,
            "evidence_sha256": "1" * 64,
        }
        prepared = self.default_reposkop_shadow_prepare(
            task_id="0123456789abcdef01234567",
            before_summary=before_summary,
        )
        with patch.object(
            grabowski_reposkop_shadow,
            "finalize_terminal_best_effort",
            side_effect=RuntimeError("shadow unavailable"),
        ):
            result = self.real_reposkop_shadow_terminal_finalize(
                task_id="0123456789abcdef01234567",
                terminalization_sha256="1" * 64,
                lifecycle_receipt_sha256="2" * 64,
                prepared=prepared,
            )

        self.assertIsNone(result)

    def test_lifecycle_receipt_link_race_with_legacy_primary_uses_lifecycle_path(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-receipt-race"]
        )
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        observation = {"state": "failed", "source": "legacy-link-race"}
        legacy_digest = tasks._write_outcome_receipt(
            record,
            "failed",
            observation,
        )
        self.assertIsNotNone(legacy_digest)
        primary_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        lifecycle_path = tasks.TASK_OUTCOMES_DIR / f"{task_id}.lifecycle.json"
        legacy_bytes = primary_path.read_bytes()
        primary_path.unlink()
        original_link = os.link
        raced = False

        def race_link(source: str, destination: str) -> None:
            nonlocal raced
            if not raced and Path(destination) == primary_path:
                raced = True
                primary_path.write_bytes(legacy_bytes)
                os.chmod(primary_path, 0o600)
                raise FileExistsError(destination)
            original_link(source, destination)

        with patch.object(tasks.os, "link", side_effect=race_link):
            stored = tasks._set_state(
                task_id,
                "failed",
                observation=observation,
            )

        self.assertTrue(raced)
        self.assertEqual(legacy_digest, json.loads(primary_path.read_text())["receipt_sha256"])
        self.assertTrue(lifecycle_path.exists())
        lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
        self.assertEqual(2, lifecycle["schema_version"])
        self.assertEqual("grabowski_task_lifecycle_receipt", lifecycle["kind"])
        self.assertEqual(
            lifecycle["receipt_sha256"],
            tasks._sha256_json(
                {key: value for key, value in lifecycle.items() if key != "receipt_sha256"}
            ),
        )
        self.assertEqual(lifecycle["receipt_sha256"], stored["lifecycle_receipt_sha256"])
        self.assertNotEqual(legacy_digest, stored["lifecycle_receipt_sha256"])

    def test_pending_resource_terminalization_recovers_task_projection_and_blocks_delegation(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-crash"]
        )
        task_id = result["task"]["task_id"]
        record = tasks._row_raw(task_id)
        observation = {"state": "failed", "source": "crash-fixture"}
        projection = tasks._terminal_projection(
            record,
            "failed",
            observation=observation,
        )
        transition = resources.begin_task_terminalization(
            task_id,
            int(record["attempt"]),
            record["lease_owner_id"],
            "failed",
            tasks._record_resource_keys(record),
            task_projection=projection,
            observation_sha256=tasks._sha256_json(observation),
        )
        self.assertEqual("leases_revoked", transition["phase"])
        self.assertEqual("running", tasks._row_raw(task_id)["state"])
        self.assertEqual([], resources.list_resources(owner_id=record["lease_owner_id"]))

        listed = tasks.grabowski_task_list(limit=100, view="evidence")
        listed_task = next(item for item in listed["tasks"] if item["task_id"] == task_id)
        self.assertEqual("failed", listed_task["state"])
        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(record["lease_owner_id"])

        recovered = tasks._row_raw(task_id)
        self.assertEqual("failed", recovered["state"])
        final = resources.task_terminalization_record(task_id)
        self.assertEqual("projected", final["phase"])
        self.assertEqual("recovered_after_revocation", final["recovery_status"])
        self.assertEqual(final["transition_sha256"], recovered["terminalization_sha256"])

    def test_projected_terminalization_recovery_replays_missing_shadow_terminal(self) -> None:
        result = self._start(resource_keys=["component:test-terminal-shadow-recovery"])
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        launcher = json.loads(record["launcher_json"])
        launcher["reposkop_checkout_shadow_before"] = {
            "phase": "before",
            "status": "completed",
            "evaluation_id": "9" * 64,
            "reposkop_cohort": "prospective_control",
            "before_observation_sha256": "d" * 64,
            "evidence_sha256": "1" * 64,
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "e" * 64,
        }
        self.reposkop_shadow_terminal_mock.side_effect = SystemExit(
            "crash after projection"
        )
        with self.assertRaisesRegex(SystemExit, "crash after projection"):
            tasks._set_state(
                task_id,
                "completed",
                launcher=launcher,
                observation={
                    "state": "completed",
                    "source": "shadow-recovery-fixture",
                },
            )

        projected = resources.task_terminalization_record(task_id)
        self.assertEqual("projected", projected["phase"])
        record = tasks._row_raw(task_id)
        self.assertEqual("completed", record["state"])
        self.assertTrue(tasks._reposkop_shadow_terminal_recovery_needed(record))
        self.assertIsNone(tasks._reposkop_shadow_terminal_marker(task_id))

        self.reposkop_shadow_terminal_mock.side_effect = lambda **_kwargs: None
        self.reposkop_shadow_terminal_mock.reset_mock()

        failed_refresh = tasks._reconcile_tasks_refresh_locked(batch_size=100)

        self.assertGreaterEqual(failed_refresh["scanned"], 1)
        self.assertIsNone(tasks._reposkop_shadow_terminal_marker(task_id))
        self.assertTrue(
            any(item["task_id"] == task_id for item in failed_refresh["blocked"])
        )
        self.assertFalse(
            any(item["task_id"] == task_id for item in failed_refresh["refreshed"])
        )

        self.reposkop_shadow_terminal_mock.side_effect = self.default_reposkop_shadow_finalize
        self.reposkop_shadow_terminal_mock.reset_mock()

        refreshed = tasks._reconcile_tasks_refresh_locked(batch_size=100)

        self.assertGreaterEqual(refreshed["scanned"], 1)
        self.assertIsNotNone(tasks._reposkop_shadow_terminal_marker(task_id))
        self.assertFalse(
            tasks._reposkop_shadow_terminal_recovery_needed(tasks._row_raw(task_id))
        )
        self.reposkop_shadow_terminal_mock.assert_called_once()

    def test_finalized_shadow_history_does_not_consume_reconcile_page_budget(self) -> None:
        def launcher_for(task_id: str, token: str) -> dict[str, object]:
            record = tasks._row_raw(task_id)
            launcher = json.loads(record["launcher_json"])
            launcher["reposkop_checkout_shadow_before"] = {
                "phase": "before",
                "status": "completed",
                "evaluation_id": token * 64,
                "reposkop_cohort": "prospective_control",
                "before_observation_sha256": "d" * 64,
                "evidence_sha256": "1" * 64,
                "decision_effect": False,
                "effect_authorized": False,
                "audit_ref": "audit-record-sha256:" + "e" * 64,
            }
            return launcher

        finalized: list[str] = []
        for index in range(6):
            result = self._start(
                resource_keys=[f"component:test-shadow-finalized-{index}"]
            )
            task_id = str(result["task"]["task_id"])
            stored = tasks._set_state(
                task_id,
                "completed",
                launcher=launcher_for(task_id, format(index + 1, "x")),
                observation={"state": "completed", "source": "finalized-history"},
            )
            marker = tasks._reposkop_shadow_terminal_marker(task_id)
            self.assertIsNotNone(marker)
            assert marker is not None
            key = tasks._reposkop_shadow_terminal_finalization_metadata_key(
                task_id=task_id,
                terminalization_sha256=stored["terminalization_sha256"],
                lifecycle_receipt_sha256=stored["lifecycle_receipt_sha256"],
            )
            with tasks._database_connection() as connection:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key=?", (key,)
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(stored["lifecycle_receipt_sha256"], row[0])
            finalized.append(task_id)

        missing_result = self._start(
            resource_keys=["component:test-shadow-finalization-missing"]
        )
        missing_id = str(missing_result["task"]["task_id"])
        self.reposkop_shadow_terminal_mock.side_effect = lambda **_kwargs: None
        tasks._set_state(
            missing_id,
            "completed",
            launcher=launcher_for(missing_id, "a"),
            observation={"state": "completed", "source": "missing-finalization"},
        )
        self.reposkop_shadow_terminal_mock.side_effect = (
            self.default_reposkop_shadow_finalize
        )

        active_result = self._start(
            resource_keys=["component:test-shadow-current-running"]
        )
        active_id = str(active_result["task"]["task_id"])

        with tasks._database_connection() as connection:
            cycle = tasks._ensure_reconcile_cycle(connection)
            selected = tasks._select_reconcile_task_rows(
                connection, cycle, limit=2
            )

        selected_ids = {str(row["task_id"]) for row in selected}
        self.assertEqual({missing_id, active_id}, selected_ids)
        self.assertTrue(set(finalized).isdisjoint(selected_ids))

    def test_existing_shadow_marker_backfills_missing_finalization_index(self) -> None:
        result = self._start(
            resource_keys=["component:test-shadow-finalization-backfill"]
        )
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        launcher = json.loads(record["launcher_json"])
        launcher["reposkop_checkout_shadow_before"] = {
            "phase": "before",
            "status": "completed",
            "evaluation_id": "c" * 64,
            "reposkop_cohort": "prospective_control",
            "before_observation_sha256": "d" * 64,
            "evidence_sha256": "1" * 64,
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "e" * 64,
        }
        stored = tasks._set_state(
            task_id,
            "completed",
            launcher=launcher,
            observation={"state": "completed", "source": "backfill-index"},
        )
        key = tasks._reposkop_shadow_terminal_finalization_metadata_key(
            task_id=task_id,
            terminalization_sha256=stored["terminalization_sha256"],
            lifecycle_receipt_sha256=stored["lifecycle_receipt_sha256"],
        )
        with tasks._database_connection() as connection:
            connection.execute("DELETE FROM metadata WHERE key=?", (key,))

        self.assertFalse(
            tasks._reposkop_shadow_terminal_recovery_needed(
                tasks._row_raw(task_id)
            )
        )
        with tasks._database_connection() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?", (key,)
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(stored["lifecycle_receipt_sha256"], row[0])

    def test_corrupt_shadow_finalization_index_is_not_treated_as_final(self) -> None:
        result = self._start(
            resource_keys=["component:test-shadow-finalization-corrupt-index"]
        )
        task_id = str(result["task"]["task_id"])
        record = tasks._row_raw(task_id)
        launcher = json.loads(record["launcher_json"])
        launcher["reposkop_checkout_shadow_before"] = {
            "phase": "before",
            "status": "completed",
            "evaluation_id": "b" * 64,
            "reposkop_cohort": "prospective_control",
            "before_observation_sha256": "d" * 64,
            "evidence_sha256": "1" * 64,
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "e" * 64,
        }
        stored = tasks._set_state(
            task_id,
            "completed",
            launcher=launcher,
            observation={"state": "completed", "source": "corrupt-index"},
        )
        key = tasks._reposkop_shadow_terminal_finalization_metadata_key(
            task_id=task_id,
            terminalization_sha256=stored["terminalization_sha256"],
            lifecycle_receipt_sha256=stored["lifecycle_receipt_sha256"],
        )
        with tasks._database_connection() as connection:
            connection.execute(
                "UPDATE metadata SET value=? WHERE key=?",
                ("f" * 64, key),
            )
            cycle = tasks._ensure_reconcile_cycle(connection)
            selected = tasks._select_reconcile_task_rows(
                connection, cycle, limit=10
            )

        self.assertIn(task_id, {str(row["task_id"]) for row in selected})

    def test_legacy_row_first_terminal_state_is_recovered_before_delegation(self) -> None:
        result = self._start(
            resource_keys=["component:test-terminalization-legacy-row-first"]
        )
        task_id = result["task"]["task_id"]
        owner = result["task"]["lease_owner_id"]
        observation = {"state": "completed", "source": "legacy-row-first"}
        with tasks._database_connection() as connection:
            connection.execute(
                "UPDATE tasks SET state='completed', last_observation_json=? "
                "WHERE task_id=?",
                (tasks._canonical_json(observation), task_id),
            )
            connection.commit()
        self.assertIsNotNone(
            resources.inspect_resource("component:test-terminalization-legacy-row-first")
        )

        with self.assertRaisesRegex(ValueError, "state does not permit"):
            tasks.server_task_lease_delegation_evidence(owner)

        recovered = tasks._row_raw(task_id)
        transition = resources.task_terminalization_record(task_id)
        self.assertEqual("completed", recovered["state"])
        self.assertEqual([], resources.list_resources(owner_id=owner))
        self.assertEqual("projected", transition["phase"])
        self.assertEqual("recovered_legacy_row_first", transition["recovery_status"])
        self.assertEqual(transition["transition_sha256"], recovered["terminalization_sha256"])

    def test_server_task_lease_delegation_rejects_missing_live_lease(self) -> None:
        result = self._start(resource_keys=["component:test-task-delegation-missing"])
        task = result["task"]
        owner = task["lease_owner_id"]
        tasks.resources.release_resources(owner, task["resource_keys"])

        with self.assertRaisesRegex(ValueError, "not live"):
            tasks.server_task_lease_delegation_evidence(owner)

    def test_start_persists_auditable_record(self) -> None:
        result = self._start()
        task = result["task"]
        self.assertEqual(task["state"], "running")
        self.assertEqual(task["attempt"], 1)
        self.assertEqual(task["host"], "local")
        self.assertEqual(task["execution_backend"], "systemd-user")
        self.assertEqual(task["systemd_scope"], "user")
        self.assertEqual(task["authoritative_unit"], task["unit"])
        self.assertEqual(task["argv"], ["/bin/echo", "ok"])
        self.assertFalse(task["chronik_outbox_enabled"])
        self.assertIsNone(task["chronik_outbox_state_root"])
        self.assertIsNone(task["chronik_context"])
        self.assertTrue(self.database.is_file())
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])
        self.assertEqual(listed["state_filter_kind"], "all")
        self.assertEqual(listed["projection_counts"]["active"], 1)

    def test_task_list_supports_compact_state_projections(self) -> None:
        task = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='failed' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()

        attention = tasks.grabowski_task_list(state="attention")

        self.assertEqual(attention["state_filter_kind"], "projection")
        self.assertEqual(
            attention["state_filter_states"],
            ["interrupted", "outcome_unknown", "failed", "timed_out", "signalled"],
        )
        self.assertEqual(attention["total_matching"], 1)
        self.assertEqual(attention["tasks"][0]["state"], "failed")
        self.assertEqual(attention["state_counts"]["failed"], 1)
        self.assertEqual(attention["state_counts_scope"], "current_projection")
        self.assertEqual(attention["projection_counts"]["attention"], 1)
        self.assertEqual(attention["projection_counts_scope"], "current_projection")
        self.assertEqual(attention["projection_counts"]["terminal"], 1)
        self.assertEqual(attention["projection_counts"]["active"], 0)
        self.assertTrue(attention["projection_counts_overlap"])
        self.assertTrue(attention["state_counts_complete"])
        self.assertEqual(attention["unknown_state_count"], 0)
        self.assertEqual(tasks.grabowski_task_list(state="active")["count"], 0)

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='interrupted' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()
        interrupted = tasks.grabowski_task_list(state="attention")
        self.assertEqual(interrupted["count"], 1)
        self.assertEqual(interrupted["tasks"][0]["state"], "interrupted")
        self.assertEqual(interrupted["projection_counts"]["active"], 0)
        self.assertEqual(interrupted["projection_counts"]["attention"], 1)
        self.assertEqual(interrupted["projection_counts"]["terminal"], 0)
        self.assertEqual(tasks.grabowski_task_list(state="active")["count"], 0)
        self.assertIn("reconcile_check", interrupted["tasks"][0]["recommended_next_action"])

        self.assertEqual(
            tasks.grabowski_task_list(state="failed")["state_filter_kind"],
            "exact",
        )
        with self.assertRaisesRegex(ValueError, "state must be one of"):
            tasks.grabowski_task_list(state="stale")

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='legacy_unknown' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()
        unknown = tasks.grabowski_task_list()
        self.assertFalse(unknown["state_counts_complete"])
        self.assertEqual(unknown["unknown_state_count"], 1)
        self.assertEqual(unknown["warnings"][0]["code"], "unknown_task_states")
        self.assertEqual(
            unknown["recommended_next_action"],
            "inspect unknown task states before relying on projections",
        )

    def test_task_list_hides_hash_bound_archived_tasks_and_projects_counts(self) -> None:
        archived_task = self._start()["task"]
        current_task = self._start()["task"]
        self._archive_and_project_tasks([archived_task["task_id"]])
        listed = tasks.grabowski_task_list(limit=100, view="evidence")
        self.assertEqual([item["task_id"] for item in listed["tasks"]], [current_task["task_id"]])
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["total_matching"], 1)
        self.assertEqual(listed["state_counts"]["completed"], 0)
        self.assertEqual(listed["state_counts"]["running"], 1)
        self.assertEqual(listed["projection_counts"]["terminal"], 0)
        self.assertEqual(listed["projection_counts"]["active"], 1)
        self.assertEqual(listed["current_projection"]["projected_task_count"], 1)
        self.assertEqual(listed["current_projection"]["switch_count"], 1)
        self.assertEqual(listed["pagination"]["snapshot_sha256"], listed["current_projection"]["projection_sha256"])
        self.assertEqual(tasks.grabowski_task_list(state="completed")["count"], 0)
        with sqlite3.connect(self.database) as connection:
            retained = connection.execute("SELECT state FROM tasks WHERE task_id=?", (archived_task["task_id"],)).fetchone()
        self.assertEqual(retained[0], "completed")

    def test_task_list_pagination_skips_archived_rows(self) -> None:
        first = self._start()["task"]
        archived = self._start()["task"]
        last = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE tasks SET created_at_unix=300 WHERE task_id=?", (first["task_id"],))
            connection.execute("UPDATE tasks SET created_at_unix=200 WHERE task_id=?", (archived["task_id"],))
            connection.execute("UPDATE tasks SET created_at_unix=100 WHERE task_id=?", (last["task_id"],))
            connection.commit()
        self._archive_and_project_tasks([archived["task_id"]])
        page_one = tasks.grabowski_task_list(limit=1)
        self.assertEqual(page_one["tasks"][0]["task_id"], first["task_id"])
        self.assertTrue(page_one["pagination"]["has_more"])
        page_two = tasks.grabowski_task_list(limit=1, cursor=page_one["pagination"]["next_cursor"])
        self.assertEqual(page_two["tasks"][0]["task_id"], last["task_id"])
        self.assertFalse(page_two["pagination"]["has_more"])
        self.assertEqual(page_two["total_matching"], 2)

    def test_task_list_fails_closed_when_projection_changes_during_read(self) -> None:
        self._start()
        first_projection = tasks._task_current_projection()
        changed_projection = {**first_projection, "projection_sha256": "f" * 64}
        with patch.object(
            tasks,
            "_task_current_projection",
            side_effect=[first_projection, changed_projection],
        ):
            with self.assertRaisesRegex(
                tasks.lifecycle_projection.LifecycleProjectionIntegrityError,
                "projection changed during list read",
            ):
                tasks.grabowski_task_list()

    def test_task_list_cursor_is_invalidated_when_projection_changes(self) -> None:
        first = self._start()["task"]
        second = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE tasks SET created_at_unix=200 WHERE task_id=?", (first["task_id"],))
            connection.execute("UPDATE tasks SET created_at_unix=100 WHERE task_id=?", (second["task_id"],))
            connection.commit()
        page = tasks.grabowski_task_list(limit=1)
        self.assertIsNotNone(page["pagination"]["next_cursor"])
        self._archive_and_project_tasks([second["task_id"]])
        with self.assertRaisesRegex(ValueError, "cursor_snapshot_changed"):
            tasks.grabowski_task_list(limit=1, cursor=page["pagination"]["next_cursor"])

    def test_task_projection_binding_is_independent_of_later_redaction_policy(self) -> None:
        projected = self._start()["task"]
        self._archive_and_project_tasks([projected["task_id"]])
        with patch.object(tasks.operator, "_redact_argv", return_value=["<changed-policy>"]):
            listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 0)
        self.assertEqual(listed["current_projection"]["projected_task_count"], 1)

    def test_task_list_fails_closed_on_projected_record_drift(self) -> None:
        projected = self._start()["task"]
        self._archive_and_project_tasks([projected["task_id"]])
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE tasks SET updated_at_unix=updated_at_unix+1 WHERE task_id=?", (projected["task_id"],))
            connection.commit()
        with self.assertRaises(tasks.lifecycle_projection.LifecycleProjectionIntegrityError):
            tasks.grabowski_task_list()

    def test_task_list_fails_closed_when_projected_row_is_missing(self) -> None:
        projected = self._start()["task"]
        self._archive_and_project_tasks([projected["task_id"]])
        with sqlite3.connect(self.database) as connection:
            connection.execute("DELETE FROM tasks WHERE task_id=?", (projected["task_id"],))
            connection.commit()
        with self.assertRaisesRegex(tasks.lifecycle_projection.LifecycleProjectionIntegrityError, "projected task row is missing"):
            tasks.grabowski_task_list()

    def test_database_connection_closes_after_success_and_failure(self) -> None:
        with tasks._database_connection() as connection:
            connection.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

        with self.assertRaisesRegex(RuntimeError, "connection failure"):
            with tasks._database_connection() as failed_connection:
                raise RuntimeError("connection failure")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")

    def test_task_read_snapshot_closes_after_success_and_failure(self) -> None:
        with tasks._task_read_snapshot() as connection:
            self.assertTrue(connection.in_transaction)
            connection.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

        with self.assertRaisesRegex(RuntimeError, "snapshot failure"):
            with tasks._task_read_snapshot() as failed_connection:
                self.assertTrue(failed_connection.in_transaction)
                raise RuntimeError("snapshot failure")
        with self.assertRaises(sqlite3.ProgrammingError):
            failed_connection.execute("SELECT 1")

    def test_task_list_derives_total_from_single_grouped_count_query(self) -> None:
        task = self._start()["task"]
        statements: list[str] = []
        original_snapshot = tasks._task_read_snapshot

        @contextmanager
        def traced_snapshot():
            with original_snapshot() as connection:
                connection.set_trace_callback(statements.append)
                try:
                    yield connection
                finally:
                    connection.set_trace_callback(None)

        with patch.object(tasks, "_task_read_snapshot", traced_snapshot):
            listed = tasks.grabowski_task_list(state="running")

        normalized = [" ".join(statement.upper().split()) for statement in statements]
        grouped_counts = [
            statement
            for statement in normalized
            if statement.startswith("SELECT STATE, COUNT(*) AS COUNT FROM TASKS GROUP BY STATE")
        ]
        standalone_counts = [
            statement
            for statement in normalized
            if statement.startswith("SELECT COUNT(*) FROM TASKS")
        ]
        self.assertEqual(len(grouped_counts), 1)
        self.assertEqual(standalone_counts, [])
        self.assertEqual(listed["total_matching"], 1)
        self.assertEqual(listed["state_counts"]["running"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])

    def test_task_list_exact_filter_skips_unrelated_attention_projection(self) -> None:
        task = self._start()["task"]
        import grabowski_task_attention as task_attention

        with patch.object(
            tasks,
            "_task_attention_projection",
            side_effect=AssertionError("attention projection must not run"),
        ) as projection, patch.object(
            task_attention,
            "decision_snapshot_guard",
            side_effect=AssertionError("decision lock must not be acquired"),
        ) as decision_guard:
            listed = tasks.grabowski_task_list(state="running")

        projection.assert_not_called()
        decision_guard.assert_not_called()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["task_id"], task["task_id"])
        self.assertEqual(listed["attention_projection"]["status"], "not_evaluated")
        self.assertIsNone(
            listed["attention_projection"]["current_attention_count"]
        )
        self.assertEqual(
            listed["projection_counts"]["attention"],
            listed["raw_projection_counts"]["attention"],
        )
        self.assertEqual(
            listed["projection_counts_semantics"]["attention"],
            "raw_current_task_states_attention_not_decision_filtered",
        )
        self.assertNotIn(
            "attention_projection_degraded",
            {warning["code"] for warning in listed["warnings"]},
        )
        self.assertEqual(
            listed["recommended_next_action"],
            "inspect returned tasks before deciding the next action",
        )
        self.assertIn(
            "decision-aware attention count for this non-attention filter",
            listed["does_not_establish"],
        )

        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='failed' WHERE task_id=?",
                (task["task_id"],),
            )
            connection.commit()
        empty = tasks.grabowski_task_list(state="running")
        self.assertEqual(0, empty["count"])
        self.assertEqual(1, empty["raw_projection_counts"]["attention"])
        self.assertEqual("none", empty["recommended_next_action"])

    def test_task_list_reads_rows_and_counts_from_one_snapshot(self) -> None:
        task = self._start()["task"]
        original_state_counts = tasks._task_state_counts

        def mutate_then_count(
            connection: sqlite3.Connection,
        ) -> tuple[dict[str, int], dict[str, int], int]:
            with sqlite3.connect(self.database) as writer:
                writer.execute(
                    "UPDATE tasks SET state='failed' WHERE task_id=?",
                    (task["task_id"],),
                )
                writer.commit()
            return original_state_counts(connection)

        with patch.object(
            tasks,
            "_task_state_counts",
            side_effect=mutate_then_count,
        ):
            listed = tasks.grabowski_task_list(state="running")

        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["total_matching"], 1)
        self.assertEqual(listed["tasks"][0]["state"], "running")
        self.assertEqual(listed["state_counts"]["running"], 1)
        self.assertEqual(listed["state_counts"]["failed"], 0)
        with sqlite3.connect(self.database) as connection:
            stored_state = connection.execute(
                "SELECT state FROM tasks WHERE task_id=?",
                (task["task_id"],),
            ).fetchone()[0]
        self.assertEqual(stored_state, "failed")

    def test_start_uses_shared_unicode_argv_identity(self) -> None:
        argv = ["/bin/echo", "Grüße"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 139}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["argv_sha256"], command_identity.argv_sha256(argv))

    def test_start_chronik_outbox_opt_in_writes_without_global_env(self) -> None:
        outbox_root = self.root / "chronik-state"
        with patch.dict(
            "os.environ",
            {
                tasks.chronik.ENABLED_ENV: "",
                tasks.chronik.STATE_ROOT_ENV: "",
            },
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 140}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                chronik_outbox=True,
                chronik_outbox_state_root=str(outbox_root),
                chronik_operation="deploy",
            )
        task = result["task"]
        self.assertTrue(task["chronik_outbox_enabled"])
        self.assertEqual(task["chronik_outbox_state_root"], str(outbox_root))
        files = sorted(outbox_root.rglob("*.jsonl"))
        self.assertEqual(len(files), 1)
        event = json.loads(files[0].read_text().splitlines()[0])
        self.assertEqual(event["kind"], "agent.run.started")
        self.assertEqual(event["data"]["operation"], "deploy")
        self.assertEqual(event["data"]["task_class"], "deploy")

    def test_chronik_outcome_unknown_persists_private_source_expectation(self) -> None:
        outbox_root = self.root / "chronik-outcome-unknown-state"
        launcher = _launcher()
        launcher["outcome_unknown"] = True
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=launcher
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                chronik_outbox=True,
                chronik_outbox_state_root=str(outbox_root),
                chronik_operation="implement",
            )

        task = result["task"]
        self.assertEqual(task["state"], "outcome_unknown")
        self.assertNotIn(
            tasks.CHRONIK_RETAINED_SOURCE_EXPECTATION_KEY, task["launcher"]
        )
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            stored = dict(
                connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (task["task_id"],)
                ).fetchone()
            )
        markers = json.loads(stored["launcher_json"])[
            tasks.CHRONIK_RETAINED_SOURCE_EXPECTATION_KEY
        ]
        self.assertEqual(len(markers), 1)
        marker = markers[0]
        self.assertEqual(
            marker,
            {
                "schema_version": 1,
                "attempt": 1,
                "run_id": tasks.chronik.run_id(stored),
                "event_kind": "agent.run.blocked",
            },
        )
        self.assertEqual(tasks._chronik_retained_source_expectations(stored), [marker])

        fresh_launcher = {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
        }
        tasks._set_state(
            task["task_id"],
            "running",
            launcher=fresh_launcher,
            attempt=2,
        )
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            resumed = dict(
                connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (task["task_id"],)
                ).fetchone()
            )
        self.assertEqual(
            json.loads(resumed["launcher_json"])[
                tasks.CHRONIK_RETAINED_SOURCE_EXPECTATION_KEY
            ],
            [marker],
        )
        self.assertEqual(tasks._chronik_retained_source_expectations(resumed), [marker])

        ambiguous_launcher = {**fresh_launcher, "outcome_unknown": True}
        tasks._set_state(
            task["task_id"],
            "outcome_unknown",
            launcher=ambiguous_launcher,
            attempt=2,
        )
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            ambiguous = dict(
                connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (task["task_id"],)
                ).fetchone()
            )
        marker_2 = {
            "schema_version": 1,
            "attempt": 2,
            "run_id": tasks.chronik.run_id(ambiguous),
            "event_kind": "agent.run.blocked",
        }
        self.assertEqual(
            tasks._chronik_retained_source_expectations(ambiguous),
            [marker, marker_2],
        )
        self.assertNotIn(
            tasks.CHRONIK_RETAINED_SOURCE_EXPECTATION_KEY,
            tasks._public(ambiguous)["launcher"],
        )

    def test_chronik_context_derives_repository_from_canonical_repo_claim(self) -> None:
        result = {"returncode": 0, "stdout": "git@github.com:heimgewebe/chronik.git\n", "stderr": "", "timed_out": False}
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(tasks.operator, "_run", return_value=result) as run:
            context = json.loads(tasks._chronik_context("local", ["repo:/work/chronik"], "implement"))
        self.assertEqual(context, {
            "subject_scope": "repository", "repo": "heimgewebe/chronik",
            "operation": "implement", "task_class": "coding",
        })
        self.assertEqual(run.call_args.args[0], ["git", "-C", "/work/chronik", "config", "--get", "remote.origin.url"])

    def test_chronik_context_falls_back_to_host_for_ambiguous_or_foreign_claims(self) -> None:
        remote = {"returncode": 0, "stdout": "git@github.com:other/private.git\n", "stderr": "", "timed_out": False}
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(tasks.operator, "_run", return_value=remote):
            foreign = json.loads(tasks._chronik_context("heim-pc", ["repo:/work/private"], "recovery"))
            ambiguous = json.loads(tasks._chronik_context("heim-pc", ["repo:/a", "repo:/b"], "recovery"))
        expected = {"subject_scope": "host", "host": "heim-pc", "operation": "recovery", "task_class": "recovery"}
        self.assertEqual(foreign, expected)
        self.assertEqual(ambiguous, expected)

    def test_start_rejects_chronik_operation_without_outbox(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "chronik_operation requires chronik_outbox"):
                tasks.grabowski_task_start(
                    "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60,
                    chronik_operation="implement",
                )

    def test_start_rejects_unknown_chronik_operation(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "chronik_operation must be one of"):
                tasks.grabowski_task_start(
                    "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60,
                    chronik_outbox=True, chronik_operation="shell-text",
                )

    def test_start_rejects_chronik_state_root_without_opt_in(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            with self.assertRaisesRegex(ValueError, "requires chronik_outbox"):
                tasks.grabowski_task_start(
                    "local",
                    ["/bin/true"],
                    cwd=str(self.root),
                    runtime_seconds=60,
                    chronik_outbox_state_root=str(self.root / "chronik-state"),
                )

    def test_bad_setting_running_task_projects_degraded_unit_health(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=bad-setting\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=probe):
            status = tasks.grabowski_task_status(task_id)

        self.assertEqual(status["state"], "running")
        self.assertEqual(status["systemd_unit_health"]["status"], "degraded")
        self.assertEqual(
            status["systemd_unit_health"]["reason"],
            "systemd_load_state_bad_setting",
        )
        self.assertEqual(status["systemd_unit_health"]["load_state"], "bad-setting")

        listed = tasks.grabowski_task_list(state="active", view="standard")
        listed_task = next(item for item in listed["tasks"] if item["task_id"] == task_id)
        self.assertEqual(listed_task["systemd_unit_health"]["status"], "degraded")
        self.assertIn("degraded systemd unit", listed_task["recommended_next_action"])
        self.assertIn(
            {
                "code": "task_systemd_unit_degraded",
                "task_id": task_id,
                "state": "running",
                "reason": "systemd_load_state_bad_setting",
                "load_state": "bad-setting",
            },
            listed["warnings"],
        )

        stale_observation = dict(status["last_observation"])
        stale_properties = dict(stale_observation["properties"])
        stale_properties["LoadState"] = "loaded"
        stale_observation["properties"] = stale_properties
        stale_observation["observed_at_unix"] = (
            tasks._now() - tasks.TASK_ACTIVE_OBSERVATION_MAX_AGE_SECONDS - 1
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET last_observation_json=? WHERE task_id=?",
                (json.dumps(stale_observation, sort_keys=True), task_id),
            )
            connection.commit()

        stale_listed = tasks.grabowski_task_list(state="active", view="standard")
        stale_task = next(
            item for item in stale_listed["tasks"] if item["task_id"] == task_id
        )
        self.assertEqual(stale_task["systemd_unit_health"]["status"], "unknown")
        self.assertEqual(
            stale_task["systemd_unit_health"]["reason"],
            "stale_or_invalid_systemd_observation",
        )

    def test_collected_success_unit_maps_to_completed_not_unknown(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=probe):
            status = tasks.grabowski_task_status(task_id)
        self.assertEqual(status["state"], "completed")
        receipt = tasks.TASK_OUTCOMES_DIR / f"{task_id}.json"
        self.assertTrue(receipt.is_file())
        payload = json.loads(receipt.read_text())
        self.assertEqual(payload["state"], "completed")
        self.assertIn("receipt_sha256", payload)

    def test_status_resolves_legacy_local_host_to_unique_registered_local_host(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        registry = {"schema_version": 1, "hosts": {"heim-pc": LOCAL_HOST}}
        with patch.object(
            tasks.fleet,
            "fleet_host",
            side_effect=ValueError("Unknown fleet host: local"),
        ), patch.object(tasks.fleet, "load_fleet", return_value=registry), patch.object(
            tasks.operator, "_run", return_value=probe
        ) as run:
            status = tasks.grabowski_task_status(task_id)
        self.assertEqual(status["state"], "completed")
        self.assertEqual(
            status["last_observation"]["probe"]["task_host_resolution"],
            {
                "kind": "legacy-local-task-host-v1",
                "stored_host": "local",
                "resolved_host": "heim-pc",
                "transport": "local",
            },
        )
        run.assert_called_once()

    def test_status_rejects_legacy_local_host_without_unique_local_target(self) -> None:
        for hosts in (
            {},
            {
                "heim-pc": LOCAL_HOST,
                "other-local": {**LOCAL_HOST, "roles": ["other"]},
            },
        ):
            with self.subTest(hosts=sorted(hosts)):
                started = self._start()
                task_id = started["task"]["task_id"]
                registry = {"schema_version": 1, "hosts": hosts}
                with patch.object(
                    tasks.fleet,
                    "fleet_host",
                    side_effect=ValueError("Unknown fleet host: local"),
                ), patch.object(tasks.fleet, "load_fleet", return_value=registry), patch.object(
                    tasks.operator, "_run"
                ) as run:
                    with self.assertRaisesRegex(ValueError, "Unknown fleet host: local"):
                        tasks.grabowski_task_status(task_id)
                run.assert_not_called()
                self.assertEqual(tasks._row(task_id)["state"], "running")

    def test_dispatch_keeps_legacy_local_alias_disabled_by_default(self) -> None:
        registry = {"schema_version": 1, "hosts": {"heim-pc": LOCAL_HOST}}
        with patch.object(
            tasks.fleet,
            "fleet_host",
            side_effect=ValueError("Unknown fleet host: local"),
        ), patch.object(tasks.fleet, "load_fleet", return_value=registry) as load_fleet, patch.object(
            tasks.operator, "_run"
        ) as run:
            with self.assertRaisesRegex(ValueError, "Unknown fleet host: local"):
                tasks._dispatch("local", ["/bin/true"])
        load_fleet.assert_not_called()
        run.assert_not_called()

    def test_start_keeps_legacy_local_alias_rejected_after_registry_rename(self) -> None:
        registry = {"schema_version": 1, "hosts": {"heim-pc": LOCAL_HOST}}
        with patch.object(
            tasks.fleet,
            "fleet_host",
            side_effect=ValueError("Unknown fleet host: local"),
        ), patch.object(tasks.fleet, "load_fleet", return_value=registry) as load_fleet, patch.object(
            tasks, "_dispatch"
        ) as dispatch:
            with self.assertRaisesRegex(ValueError, "Unknown fleet host: local"):
                tasks.grabowski_task_start(
                    "local",
                    ["/bin/true"],
                    cwd=str(self.root),
                    runtime_seconds=60,
                )
        load_fleet.assert_not_called()
        dispatch.assert_not_called()

    def test_status_maps_successful_inactive_unit_to_completed(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=1\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=probe):
            status = tasks.grabowski_task_status(task_id)
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["last_observation"]["properties"]["Result"], "success")

    def test_legacy_local_resume_binds_managed_output_from_next_attempt(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        with tasks._database_connection() as connection:
            row = connection.execute(
                "SELECT launcher_json FROM tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
            assert row is not None
            launcher = json.loads(str(row["launcher_json"]))
            launcher.pop(tasks.TASK_OUTPUT_LAUNCHER_BINDING_KEY, None)
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                (tasks._canonical_json(launcher), task_id),
            )
        before = tasks._row_raw(task_id)
        self.assertIsNone(tasks._task_output_managed_from_attempt(before))
        observation = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        captured: dict[str, object] = {}

        def launch(candidate: dict[str, object]) -> dict[str, object]:
            captured.update(candidate)
            return _launcher()

        with patch.object(tasks, "_observe", return_value=observation), patch.object(
            tasks, "_launch", side_effect=launch
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            resumed = tasks.grabowski_task_resume(task_id)
        self.assertEqual(resumed["task"]["attempt"], 2)
        self.assertEqual(
            resumed["task"]["launcher"][tasks.TASK_OUTPUT_LAUNCHER_BINDING_KEY],
            2,
        )
        self.assertEqual(resumed["audit"]["task_output_managed_from_attempt"], 2)
        self.assertEqual(tasks._task_output_managed_from_attempt(captured), 2)
        first_attempt = {**captured, "attempt": 1}
        self.assertEqual(
            tasks._task_output_contract_version(first_attempt),
            tasks.TASK_OUTPUT_LEGACY_CONTRACT_VERSION,
        )
        self.assertEqual(
            tasks._task_output_contract_version(captured),
            tasks.TASK_OUTPUT_CONTRACT_VERSION,
        )

    def test_managed_local_resume_rejects_fleet_transition_to_ssh(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        before = tasks._row_raw(task_id)
        self.assertEqual(tasks._task_output_managed_from_attempt(before), 1)
        observation = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        with patch.object(tasks, "_observe", return_value=observation), patch.object(
            tasks.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(tasks, "_launch") as launch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            with self.assertRaisesRegex(
                RuntimeError, "managed local output cannot resume on non-local transport"
            ):
                tasks.grabowski_task_resume(task_id)
        launch.assert_not_called()
        after = tasks._row_raw(task_id)
        self.assertEqual(after["attempt"], before["attempt"])
        self.assertEqual(
            tasks._task_output_managed_from_attempt(after),
            tasks._task_output_managed_from_attempt(before),
        )

    def test_resume_renews_live_lease_without_rebinding_identity(self) -> None:
        key = "component:task-resume-renew"
        started = self._start(resource_keys=[key])
        task_id = str(started["task"]["task_id"])
        before = tasks.resources.inspect_resource(key)
        self.assertIsNotNone(before)
        observation = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        with patch.object(tasks, "_observe", return_value=observation), patch.object(
            tasks, "_launch", return_value=_launcher()
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            resumed = tasks.grabowski_task_resume(task_id)
        after = tasks.resources.inspect_resource(key)
        self.assertIsNotNone(after)
        assert before is not None and after is not None
        self.assertEqual(after["acquired_at_unix"], before["acquired_at_unix"])
        self.assertEqual(after["purpose"], before["purpose"])
        self.assertEqual(after["metadata_sha256"], before["metadata_sha256"])
        self.assertEqual(
            after["reclaimed_from_owner"], before["reclaimed_from_owner"]
        )
        self.assertGreaterEqual(after["expires_at_unix"], before["expires_at_unix"])
        self.assertEqual(resumed["task"]["attempt"], 2)
        self.assertEqual(resumed["audit"]["resource_lease_mode"], "renewed")

    def test_resume_reacquires_missing_lease_as_new_identity(self) -> None:
        key = "component:task-resume-reacquire"
        started = self._start(resource_keys=[key])
        task_id = str(started["task"]["task_id"])
        owner = str(started["task"]["lease_owner_id"])
        tasks.resources.release_resources(owner, [key])
        observation = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        with patch.object(tasks, "_observe", return_value=observation), patch.object(
            tasks, "_launch", return_value=_launcher()
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}
        ):
            resumed = tasks.grabowski_task_resume(task_id)
        lease = tasks.resources.inspect_resource(key)
        self.assertIsNotNone(lease)
        self.assertEqual(resumed["task"]["attempt"], 2)
        self.assertEqual(resumed["audit"]["resource_lease_mode"], "reacquired")

    def test_resume_reconciles_mixed_live_and_missing_leases(self) -> None:
        live_key = "component:task-resume-mixed-live"
        missing_key = "component:task-resume-mixed-missing"
        started = self._start(resource_keys=[live_key, missing_key])
        task_id = str(started["task"]["task_id"])
        owner = str(started["task"]["lease_owner_id"])
        live_before = tasks.resources.inspect_resource(live_key)
        missing_before = tasks.resources.inspect_resource(missing_key)
        self.assertIsNotNone(live_before)
        self.assertIsNotNone(missing_before)
        tasks.resources.release_resources(owner, [missing_key])
        observation = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": int(time.time()),
        }
        with patch.object(tasks, "_observe", return_value=observation), patch.object(
            tasks, "_launch", return_value=_launcher()
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 126}
        ):
            resumed = tasks.grabowski_task_resume(task_id)

        live_after = tasks.resources.inspect_resource(live_key)
        missing_after = tasks.resources.inspect_resource(missing_key)
        self.assertIsNotNone(live_after)
        self.assertIsNotNone(missing_after)
        assert live_before is not None and live_after is not None
        assert missing_before is not None and missing_after is not None
        self.assertEqual(
            live_after["acquired_at_unix"], live_before["acquired_at_unix"]
        )
        self.assertEqual(
            live_after["metadata_sha256"], live_before["metadata_sha256"]
        )
        self.assertNotEqual(
            missing_after["metadata_sha256"], missing_before["metadata_sha256"]
        )
        self.assertEqual(resumed["task"]["attempt"], 2)
        self.assertEqual(resumed["audit"]["resource_lease_mode"], "reconciled")
        with sqlite3.connect(self.resource_database) as connection:
            rows = {
                row[0]: json.loads(row[1])
                for row in connection.execute(
                    "SELECT resource_key, metadata_json FROM leases "
                    "WHERE resource_key IN (?, ?)",
                    (live_key, missing_key),
                ).fetchall()
            }
        self.assertEqual(rows[live_key]["attempt"], 1)
        self.assertNotIn("recovered_after_expiry", rows[live_key])
        self.assertEqual(rows[missing_key]["attempt"], 2)
        self.assertIs(rows[missing_key]["recovered_after_expiry"], True)

    def test_maintenance_reconciles_mixed_live_and_missing_leases(self) -> None:
        live_key = "component:task-maintain-mixed-live"
        missing_key = "component:task-maintain-mixed-missing"
        started = self._start(resource_keys=[live_key, missing_key])
        task_id = str(started["task"]["task_id"])
        owner = str(started["task"]["lease_owner_id"])
        live_before = tasks.resources.inspect_resource(live_key)
        self.assertIsNotNone(live_before)
        tasks.resources.release_resources(owner, [missing_key])

        result = tasks._maintain_record_resources(
            tasks._row_raw(task_id), "running"
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result["maintained"])
        self.assertEqual(result["mode"], "reconciled")
        live_after = tasks.resources.inspect_resource(live_key)
        missing_after = tasks.resources.inspect_resource(missing_key)
        self.assertIsNotNone(live_after)
        self.assertIsNotNone(missing_after)
        assert live_before is not None and live_after is not None
        self.assertEqual(
            live_after["acquired_at_unix"], live_before["acquired_at_unix"]
        )
        self.assertEqual(
            live_after["metadata_sha256"], live_before["metadata_sha256"]
        )
        with sqlite3.connect(self.resource_database) as connection:
            rows = {
                row[0]: json.loads(row[1])
                for row in connection.execute(
                    "SELECT resource_key, metadata_json FROM leases "
                    "WHERE resource_key IN (?, ?)",
                    (live_key, missing_key),
                ).fetchall()
            }
        self.assertNotIn("recovered_after_expiry", rows[live_key])
        self.assertIs(rows[missing_key]["recovered_after_expiry"], True)

    def test_completed_observation_blocks_direct_resume_before_launch(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        with patch.object(tasks, "_observe", return_value={
            "state": "completed",
            "properties": {"Result": "success"},
            "probe": completed,
            "observer": {"kind": "test"},
            "observed_at_unix": 123,
        }), patch.object(tasks, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "already completed"):
                tasks.grabowski_task_resume(task_id)
        launch.assert_not_called()
        stored = tasks._row(task_id)
        self.assertEqual(stored["state"], "completed")

    def test_terminal_record_blocks_direct_resume_before_observation(self) -> None:
        started = self._start()
        task_id = started["task"]["task_id"]
        tasks._set_state(task_id, "failed", observation={"state": "failed"})
        with patch.object(tasks, "_observe") as observe, patch.object(tasks, "_launch") as launch:
            with self.assertRaisesRegex(RuntimeError, "Terminal task"):
                tasks.grabowski_task_resume(task_id)
        observe.assert_not_called()
        launch.assert_not_called()

    def test_missing_unit_outcome_unknown_blocks_manual_resume(self) -> None:
        started = self._start(host="remote")
        task_id = started["task"]["task_id"]
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
        ):
            with self.assertRaisesRegex(RuntimeError, "outcome is unknown"):
                tasks.grabowski_task_resume(task_id)
        task = tasks.grabowski_task_list(view="evidence")["tasks"][0]
        self.assertEqual(task["attempt"], 1)
        self.assertEqual(task["state"], "outcome_unknown")
        self.assertEqual(task["last_observation"]["state"], "outcome_unknown")

    def test_resume_reacquisition_binds_scope_and_blocks_before_launch(self) -> None:
        key = f"repo:{self.root}"
        started = self._start(resource_keys=[key])
        task_id = started["task"]["task_id"]
        with sqlite3.connect(self.resource_database) as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?",
                (key,),
            )
            connection.commit()
        assessment = {
            "schema_version": 1,
            "decision": "blocked",
            "blocker_codes": ["dirty-worktree"],
            "blockers": [{"code": "dirty-worktree", "path": str(self.root)}],
            "assessment_sha256": "d" * 64,
            "read_only": True,
        }
        observed = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": 321,
        }

        with patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(tasks, "_observe", return_value=observed), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 321}
        ), patch.object(
            tasks.resources.work_admission,
            "require_repository_admission",
            side_effect=tasks.resources.work_admission.WorkAdmissionBlocked(
                assessment
            ),
        ) as assessor, patch.object(tasks, "_launch") as launch:
            with self.assertRaises(tasks.resources.work_admission.WorkAdmissionBlocked):
                tasks.grabowski_task_resume(task_id)

        launch.assert_not_called()
        self.assertEqual(assessor.call_count, 1)
        requested_scope = assessor.call_args.kwargs["requested_scope"]
        self.assertEqual(requested_scope["repository"], str(self.root))
        self.assertEqual(requested_scope["task_id"], task_id)
        self.assertEqual(assessor.call_args.kwargs["mode"], "normal")

    def test_resume_without_bound_repository_scope_fails_closed(self) -> None:
        key = f"repo:{self.root}"
        started = self._start(resource_keys=[key])
        task_id = started["task"]["task_id"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET repository_scope_manifest_json=NULL "
                "WHERE task_id=?",
                (task_id,),
            )
            connection.commit()
        with sqlite3.connect(self.resource_database) as connection:
            connection.execute("DELETE FROM leases WHERE resource_key=?", (key,))
            connection.commit()
        observed = {
            "state": "failed",
            "properties": {"Result": "exit-code"},
            "probe": _launcher(returncode=1),
            "observer": {"kind": "test"},
            "observed_at_unix": 322,
        }

        with patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(tasks, "_observe", return_value=observed), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 322}
        ), patch.object(
            tasks.resources.work_admission,
            "require_repository_admission",
        ) as assessor, patch.object(tasks, "_launch") as launch:
            with self.assertRaisesRegex(
                RuntimeError, "scope manifest evidence is required"
            ):
                tasks.grabowski_task_resume(task_id)

        assessor.assert_not_called()
        launch.assert_not_called()

    def test_reconcile_observer_falls_back_to_narrow_production_probe(self) -> None:
        probe = _launcher()
        probe["stdout"] = (
            "LoadState=not-found\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        observed = {
            "host": "wg-prod-1",
            "transport": "ssh",
            "roles": ["vps", "production"],
            "observer": tasks.fleet.TASK_UNIT_SHOW_OBSERVER,
            "result": probe,
        }
        with patch.object(
            tasks,
            "_dispatch",
            side_effect=tasks.fleet.FleetCommandDenied("Executable is not allowed for fleet host wg-prod-1: systemctl"),
        ), patch.object(
            tasks.fleet, "run_fleet_task_unit_show", return_value=observed
        ) as show:
            result = tasks._observe({
                "host": "wg-prod-1",
                "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
            })
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["observer"]["kind"], tasks.fleet.TASK_UNIT_SHOW_OBSERVER)
        self.assertEqual(
            result["observer"]["fallback_from"],
            "fleet-dispatch-permission-denied",
        )
        show.assert_called_once_with(
            "wg-prod-1",
            "grabowski-task-0123456789abcdef01234567-a1.service",
            tasks.fleet.TASK_UNIT_SHOW_PROPERTIES,
            timeout_seconds=30,
            max_output_bytes=8192,
        )

    def test_reconcile_observer_propagates_narrow_probe_failure(self) -> None:
        with patch.object(
            tasks,
            "_dispatch",
            side_effect=tasks.fleet.FleetCommandDenied("Executable is not allowed for fleet host wg-prod-1: systemctl"),
        ), patch.object(
            tasks.fleet, "run_fleet_task_unit_show", side_effect=RuntimeError("ssh failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "ssh failed"):
                tasks._observe({
                    "host": "wg-prod-1",
                    "unit": "grabowski-task-0123456789abcdef01234567-a1.service",
                })

    def test_task_start_resume_policy_schema_matches_runtime_contract(self) -> None:
        expected = frozenset({"manual", "never", "retry-safe", "verify-then-retry"})

        self.assertIsInstance(tasks.RESUME_POLICIES, frozenset)
        self.assertEqual(expected, tasks.RESUME_POLICIES)
        self.assertEqual(expected, frozenset(get_args(tasks.ResumePolicy)))
        for entry_point in (
            tasks.grabowski_task_start,
            tasks._grabowski_task_start_tool,
        ):
            with self.subTest(entry_point=entry_point.__name__):
                hints = get_type_hints(entry_point)
                self.assertEqual(
                    expected,
                    frozenset(get_args(hints["resume_policy"])),
                )
        validator_hints = get_type_hints(tasks._validate_resume_policy)
        self.assertEqual(
            expected,
            frozenset(get_args(validator_hints["return"])),
        )

        for policy in sorted(expected):
            with self.subTest(policy=policy):
                self.assertEqual(policy, tasks._validate_resume_policy(policy))

        with self.assertRaises(ValueError) as raised:
            tasks._validate_resume_policy("automatic")
        self.assertEqual(
            str(raised.exception),
            "resume_policy must be one of "
            "['manual', 'never', 'retry-safe', 'verify-then-retry']",
        )

    def test_task_start_published_schema_matches_resume_policy_contract(self) -> None:
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import asyncio,json,sys; "
                    "sys.path.insert(0, sys.argv[1]); "
                    "import mcp.server.fastmcp; "
                    "import grabowski_tasks as tasks; "
                    "tool=next(item for item in asyncio.run(tasks.mcp.list_tools()) "
                    "if item.name=='grabowski_task_start'); "
                    "print(json.dumps(tool.inputSchema['properties']['resume_policy'], "
                    "sort_keys=True))"
                ),
                str(SRC),
            ],
            capture_output=True,
            text=True,
        )
        if probe.returncode != 0 and "No module named 'mcp'" in probe.stderr:
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        self.assertEqual(0, probe.returncode, probe.stderr)
        schema = json.loads(probe.stdout)
        self.assertEqual(list(get_args(tasks.ResumePolicy)), schema["enum"])
        self.assertEqual("verify-then-retry", schema["default"])
        self.assertEqual("string", schema["type"])

    def test_manual_resume_policy_fails_closed(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="manual",
            )
        with self.assertRaisesRegex(PermissionError, "does not permit"):
            tasks.grabowski_task_resume(started["task"]["task_id"])

    def test_ordinary_task_does_not_depend_on_recovery_evidence(self) -> None:
        with patch.object(tasks.recovery, "recovery_status", side_effect=AssertionError("unexpected recovery probe")), patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ):
            result = tasks.grabowski_task_start(
                "local", ["/bin/true"], cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["state"], "running")
        self.assertFalse(result["audit"]["recovery_required"])
        self.assertIsNone(result["audit"]["recovery_checked_at_unix"])

    def test_power_worker_fails_closed_when_recovery_is_not_ready(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": False,
                "required_actions": ["produce recovery evidence"],
            },
        ):
            with self.assertRaisesRegex(PermissionError, "recovery gate"):
                tasks.grabowski_task_start(
                    "local", ["/usr/local/bin/sleep-heimserver"], cwd=str(self.root)
                )

    def test_root_task_runtime_preserves_lease_grace(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 199,
            },
        ), patch.object(
            tasks.operator, "_job_runtime", side_effect=lambda value: value
        ), patch.object(tasks.operator, "_require_operator_mutation") as mutation:
            with self.assertRaisesRegex(ValueError, "300 seconds"):
                tasks.grabowski_task_start(
                    "local",
                    ["/usr/local/bin/sleep-heimserver"],
                    cwd=str(self.root),
                    runtime_seconds=tasks.resources.MAX_TTL_SECONDS - 299,
                )
        mutation.assert_not_called()

    def test_local_power_worker_task_starts_through_root_broker_backend(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 200,
            },
        ), patch.object(
            tasks.privileged, "root_task_systemd_request", return_value=_launcher()
        ) as broker, patch.object(tasks, "_dispatch") as dispatch, patch.object(
            tasks.base, "_append_audit"
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )

        task = result["task"]
        self.assertEqual(task["state"], "running")
        self.assertEqual(task["execution_backend"], "systemd-root-broker")
        self.assertEqual(task["systemd_scope"], "system")
        self.assertEqual(task["authoritative_unit"], task["unit"])
        dispatch.assert_not_called()
        broker.assert_called_once()
        payload = broker.call_args.args[0]
        self.assertEqual(payload["operation"], "start")
        self.assertEqual(payload["unit"], task["authoritative_unit"])
        self.assertEqual(payload["argv"], ["/usr/local/bin/sleep-heimserver"])
        self.assertEqual(payload["runtime_seconds"], 300)
        self.assertEqual(result["audit"]["execution_backend"], "systemd-root-broker")

    def test_root_task_status_logs_and_cancel_route_by_stored_scope(self) -> None:
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        logs = _launcher()
        logs["stdout"] = "root log\n"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 201,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[_launcher(), running, logs, _launcher()],
        ) as broker, patch.object(tasks, "_dispatch") as dispatch, patch.object(
            tasks.base, "_append_audit"
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )
            task_id = started["task"]["task_id"]
            status = tasks.grabowski_task_status(task_id)
            output = tasks.grabowski_task_logs(task_id, max_lines=50)
            cancelled = tasks.grabowski_task_cancel(task_id)

        self.assertEqual(status["state"], "running")
        self.assertEqual(status["last_observation"]["observer"]["kind"], "root-systemd-broker-show-v1")
        self.assertEqual(output["result"]["stdout"], "root log\n")
        self.assertEqual(cancelled["task"]["state"], "cancelled")
        self.assertEqual(
            [call.args[0]["operation"] for call in broker.call_args_list],
            ["start", "show", "journal", "stop"],
        )
        self.assertEqual(broker.call_args_list[2].args[0]["max_lines"], 50)
        dispatch.assert_not_called()

    def test_root_scope_observation_denial_does_not_fallback_to_user_scope(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 202,
            },
        ), patch.object(
            tasks.privileged, "root_task_systemd_request", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
            )

        with patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=PermissionError("privileged broker is not ready"),
        ) as broker, patch.object(tasks, "_dispatch") as dispatch:
            result = tasks.reconcile_tasks_check(task_id=started["task"]["task_id"])

        self.assertEqual(result["blocked"][0]["execution_backend"], "systemd-root-broker")
        self.assertIn("observation denied", result["blocked"][0]["reason"])
        broker.assert_called_once()
        dispatch.assert_not_called()


    def test_root_broker_pre_dispatch_failure_is_terminal_and_releases_lease(self) -> None:
        resource_key = "service:root-task-pre-dispatch-failure"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 205,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=PermissionError("privileged broker is not ready"),
        ), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )

        self.assertEqual(result["task"]["state"], "failed")
        self.assertTrue(result["task"]["launcher"]["launch_not_dispatched"])
        self.assertFalse(result["task"]["launcher"]["outcome_unknown"])
        self.assertIsNone(tasks.resources.inspect_resource(resource_key))
        receipt = tasks.TASK_OUTCOMES_DIR / f"{result['task']['task_id']}.json"
        self.assertTrue(receipt.is_file())
        self.assertEqual(json.loads(receipt.read_text())["state"], "failed")

    def test_root_unknown_start_retains_lease_and_later_reattaches(self) -> None:
        unknown = _launcher(returncode=1)
        unknown["outcome_unknown"] = True
        unknown["root_truth_observable"] = False
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        resource_key = "service:root-task-lifetime-test"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 203,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[unknown, running, completed, unknown],
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )
            task_id = started["task"]["task_id"]
            self.assertEqual(started["task"]["state"], "outcome_unknown")
            lease = tasks.resources.inspect_resource(resource_key)
            self.assertIsNotNone(lease)
            self.assertGreaterEqual(
                lease["expires_at_unix"],
                tasks._now() + tasks.resources.MAX_TTL_SECONDS - 5,
            )
            self.assertEqual(
                started["audit"]["resource_lease_maintenance"]["mode"],
                "renewed",
            )
            self.assertFalse((tasks.TASK_OUTCOMES_DIR / f"{task_id}.json").exists())

            reattached = tasks.grabowski_task_status(task_id)
            self.assertEqual(reattached["state"], "running")
            self.assertIsNotNone(tasks.resources.inspect_resource(resource_key))

            terminal = tasks.grabowski_task_status(task_id)
            self.assertEqual(terminal["state"], "completed")
            self.assertIsNone(tasks.resources.inspect_resource(resource_key))
            receipt = json.loads(
                (tasks.TASK_OUTCOMES_DIR / f"{task_id}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["state"], "completed")
            self.assertEqual(receipt["systemd_scope"], "system")

            terminal_readback = tasks.grabowski_task_status(task_id)
            self.assertEqual(terminal_readback["state"], "completed")
            self.assertIsNone(terminal_readback["lease_maintenance"])
            self.assertIsNone(tasks.resources.inspect_resource(resource_key))

    def test_unknown_root_task_reacquires_expired_free_lease(self) -> None:
        unknown = _launcher(returncode=1)
        unknown["outcome_unknown"] = True
        unknown["root_truth_observable"] = False
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        resource_key = "service:root-task-expired-lease-test"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks.recovery,
            "recovery_status",
            return_value={
                "ready_for_user_power_worker": True,
                "checked_at_unix": 204,
            },
        ), patch.object(
            tasks.privileged,
            "root_task_systemd_request",
            side_effect=[unknown, running],
        ), patch.object(tasks.base, "_append_audit"):
            started = tasks.grabowski_task_start(
                "local",
                ["/usr/local/bin/sleep-heimserver"],
                cwd=str(self.root),
                runtime_seconds=300,
                resource_keys=[resource_key],
            )
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?",
                    (resource_key,),
                )
                connection.commit()

            with patch.object(tasks, "_set_state", wraps=tasks._set_state) as set_state:
                status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(1, set_state.call_count)
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["lease_maintenance"]["mode"], "reacquired")
        lease = tasks.resources.inspect_resource(resource_key)
        self.assertIsNotNone(lease)
        self.assertEqual(lease["owner_id"], started["task"]["lease_owner_id"])

    def test_mutating_codex_task_implicitly_leases_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 150}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        key = f"repo:{self.root}"
        self.assertEqual(result["task"]["resource_keys"], [key])
        self.assertEqual(result["audit"]["requested_resource_keys"], [])
        self.assertEqual(result["audit"]["implicit_workspace_resource_key"], key)
        lease = tasks.resources.inspect_resource(key)
        self.assertEqual(lease["owner_id"], result["task"]["lease_owner_id"])
        with sqlite3.connect(self.resource_database) as connection:
            row = connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()
        metadata = json.loads(row[0])
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])
        self.assertEqual(
            metadata["scope_manifest"]["task_id"], result["task"]["task_id"]
        )
        self.assertEqual(metadata["scope_manifest"]["head"], "0" * 40)
        self.assertEqual(metadata["scope_manifest"]["branch"], "unversioned")
        self.assertRegex(
            result["audit"]["repository_scope_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_mutating_agent_reposkop_attestation_is_lease_and_execution_bound(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        key = f"repo:{self.root}"

        def attest(**kwargs):
            lease = tasks.resources.inspect_resource(key)
            self.assertIsNotNone(lease)
            self.assertEqual(lease["owner_id"], kwargs["lease_owner_id"])
            self.assertEqual(
                kwargs["workspace_lease_resource_keys"], [key]
            )
            evidence = {
                **self.reposkop_attestation,
                "task_id": kwargs["task_id"],
                "lease_owner_id": kwargs["lease_owner_id"],
                "workspace_lease_resource_keys": kwargs[
                    "workspace_lease_resource_keys"
                ],
                "workspace_lease_resource_keys_sha256": tasks._sha256_json(
                    kwargs["workspace_lease_resource_keys"]
                ),
                "workspace": kwargs["workspace"],
                "argv_sha256": kwargs["argv_sha256"],
                "execution_identity_sha256": kwargs[
                    "execution_identity_sha256"
                ],
            }
            evidence["execution_binding_sha256"] = tasks._sha256_json(
                {
                    key: value
                    for key, value in evidence.items()
                    if key != "execution_binding_sha256"
                }
            )
            return evidence

        self.reposkop_attestation_mock.side_effect = attest
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 151}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        attestation = result["reposkop_execution_attestation"]
        self.assertEqual(attestation["task_id"], result["task"]["task_id"])
        self.assertEqual(
            attestation["execution_identity_sha256"],
            result["execution_identity"]["identity_sha256"],
        )
        self.assertEqual(
            result["audit"]["reposkop_execution_attestation_sha256"],
            attestation["execution_binding_sha256"],
        )
        with sqlite3.connect(self.database) as connection:
            launcher = json.loads(
                connection.execute(
                    "SELECT launcher_json FROM tasks WHERE task_id=?",
                    (result["task"]["task_id"],),
                ).fetchone()[0]
            )
        self.assertEqual(
            launcher["reposkop_execution_attestation"], attestation
        )

    def test_unrelated_path_resource_does_not_replace_workspace_lease(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        unrelated = self.root.parent / f"{self.root.name}-other"
        unrelated_key = f"path:{unrelated}"
        workspace_key = f"repo:{self.root}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 154}
        ):
            result = tasks.grabowski_task_start(
                "local",
                argv,
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[unrelated_key],
            )

        self.assertEqual(
            result["task"]["resource_keys"],
            sorted([unrelated_key, workspace_key]),
        )
        self.assertEqual(
            self.reposkop_attestation_mock.call_args.kwargs[
                "workspace_lease_resource_keys"
            ],
            [workspace_key],
        )
        self.assertIsNotNone(tasks.resources.inspect_resource(workspace_key))

    def test_exact_path_resource_covers_workspace_without_implicit_repo_lease(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        path_key = f"path:{self.root}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 155}
        ):
            result = tasks.grabowski_task_start(
                "local",
                argv,
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[path_key],
            )

        self.assertEqual(result["task"]["resource_keys"], [path_key])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])
        self.assertEqual(
            self.reposkop_attestation_mock.call_args.kwargs[
                "workspace_lease_resource_keys"
            ],
            [path_key],
        )

    def test_unrelated_repository_resource_fails_before_acquisition(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        unrelated = self.root.parent / f"{self.root.name}-repo"
        unrelated_key = f"repo:{unrelated}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 156}
        ):
            with self.assertRaisesRegex(
                ValueError, "at most one broad repository"
            ):
                tasks.grabowski_task_start(
                    "local",
                    argv,
                    cwd=str(self.root),
                    runtime_seconds=60,
                    resource_keys=[unrelated_key],
                )

        dispatch.assert_not_called()
        self.reposkop_attestation_mock.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(unrelated_key))
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))

    def test_admitted_feature_branch_can_enter_reposkop_control_without_attestation_run(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        base = tasks.reposkop_effectiveness.classify_task_effect(
            transport="local",
            argv=argv,
            mutating_workspace=str(self.root),
        )
        control_key = next(
            f"{index:024x}"
            for index in range(1, 256)
            if tasks.reposkop_effectiveness.select_prospective_policy(
                base, sampling_key=f"{index:024x}", admission_verified=True
            )["reposkop_cohort"]
            == "prospective_control"
        )
        fake_uuid = types.SimpleNamespace(hex=control_key + "0" * 8)
        tasks.resources.work_admission.require_repository_admission.return_value = {
            "schema_version": 1,
            "kind": "grabowski.repository_work_admission",
            "repository": str(self.root),
            "decision": "allow",
            "assessment_sha256": "a" * 64,
            "read_only": True,
        }
        with patch.object(tasks.uuid, "uuid4", return_value=fake_uuid), patch.object(
            tasks, "_workspace_scope_identity", return_value=("1" * 40, "feat/test-control")
        ), patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 157}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        classification = result["task_effect_classification"]
        self.assertEqual(classification["reposkop_cohort"], "prospective_control")
        self.assertEqual(classification["reposkop_policy"], "not_required")
        self.assertIs(classification["prospective_admission_verified"], True)
        self.reposkop_attestation_mock.assert_not_called()
        attestation = result["reposkop_execution_attestation"]
        self.assertIsNotNone(attestation)
        self.assertIs(attestation["reposkop_execution_skipped"], True)
        self.assertIs(attestation["required"], False)
        self.assertEqual(attestation["status"], "skipped_control")
        self.assertEqual(attestation["task_id"], control_key)
        self.assertRegex(attestation["decision_audit_ref"], r"^audit-record-sha256:[0-9a-f]{64}$")
        self.assertIs(result["audit"]["reposkop_execution_attestation_required"], False)
        self.assertEqual(result["audit"]["reposkop_cohort"], "prospective_control")
        self.assertEqual(
            result["reposkop_checkout_shadow_before"]["status"],
            "completed",
        )
        self.reposkop_shadow_before_mock.assert_called_once_with(
            task_id=control_key,
            workspace=str(self.root),
            evaluation_id=result["audit"]["evaluation_id"],
            reposkop_cohort="prospective_control",
        )
        self.assertIsNotNone(tasks.resources.inspect_resource(f"repo:{self.root}"))

    def test_exact_feature_path_and_branch_leases_can_enter_reposkop_control(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        branch = "feat/test-exact-control"
        head = "1" * 40
        canonical_repo = self.root.parent / f"{self.root.name}-canonical-repo"
        canonical_repo.mkdir()
        (canonical_repo / ".git").write_text("gitdir: /tmp/canonical.git\n")
        path_key = f"path:{self.root}"
        branch_key = f"repo:{canonical_repo}:branch:{branch}"
        base = tasks.reposkop_effectiveness.classify_task_effect(
            transport="local", argv=argv, mutating_workspace=str(self.root)
        )
        control_key = next(
            f"{index:024x}"
            for index in range(1, 256)
            if tasks.reposkop_effectiveness.select_prospective_policy(
                base, sampling_key=f"{index:024x}", admission_verified=True
            )["reposkop_cohort"] == "prospective_control"
        )
        fake_uuid = types.SimpleNamespace(hex=control_key + "0" * 8)
        exact_assessment = {
            "schema_version": 1,
            "kind": "grabowski.repository_work_admission",
            "repository": str(canonical_repo),
            "operation": "task_existing_checkout",
            "scope_mode": "exact_checkout",
            "scope_identity": {
                "target_path": str(self.root),
                "branch": branch,
                "head": head,
            },
            "decision": "allow",
            "assessment_sha256": "a" * 64,
            "read_only": True,
        }
        tasks.resources.work_admission.require_repository_admission.return_value = exact_assessment
        with patch.object(tasks.uuid, "uuid4", return_value=fake_uuid), patch.object(
            tasks, "_workspace_scope_identity", return_value=(head, branch)
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 157}
        ):
            result = tasks.grabowski_task_start(
                "local",
                argv,
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[path_key, branch_key],
            )

        classification = result["task_effect_classification"]
        self.assertEqual(classification["reposkop_cohort"], "prospective_control")
        self.assertEqual(classification["reposkop_policy"], "not_required")
        self.assertIs(classification["prospective_admission_verified"], True)
        self.reposkop_attestation_mock.assert_not_called()
        kwargs = tasks.resources.work_admission.require_repository_admission.call_args.kwargs
        self.assertEqual(kwargs["operation"], "task_existing_checkout")
        self.assertEqual(kwargs["repo"], str(canonical_repo))
        self.assertEqual(kwargs["target_path"], str(self.root))
        self.assertEqual(
            result["reposkop_execution_attestation"]["admission_evidence_sha256"],
            tasks._sha256_json(exact_assessment),
        )

    def test_exact_feature_pair_falls_back_to_required_when_exact_admission_blocks(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        branch = "feat/test-exact-blocked"
        head = "2" * 40
        canonical_repo = self.root.parent / f"{self.root.name}-canonical-repo-blocked"
        canonical_repo.mkdir()
        (canonical_repo / ".git").write_text("gitdir: /tmp/canonical-blocked.git\n")
        path_key = f"path:{self.root}"
        branch_key = f"repo:{canonical_repo}:branch:{branch}"
        tasks.resources.work_admission.require_repository_admission.side_effect = (
            tasks.resources.work_admission.WorkAdmissionBlocked(
                {
                    "decision": "blocked",
                    "blocker_codes": ["dirty-worktree"],
                }
            )
        )
        with patch.object(
            tasks, "_workspace_scope_identity", return_value=(head, branch)
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 157}
        ):
            result = tasks.grabowski_task_start(
                "local",
                argv,
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[path_key, branch_key],
            )

        classification = result["task_effect_classification"]
        self.assertEqual(classification["reposkop_cohort"], "risk_required")
        self.assertEqual(classification["reposkop_policy"], "required")
        self.assertIs(classification["prospective_admission_verified"], False)
        self.reposkop_attestation_mock.assert_called_once()
        self.reposkop_shadow_before_mock.assert_called_once()

    def test_reposkop_shadow_start_failure_is_nonblocking_and_recorded(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        self.reposkop_shadow_before_mock.return_value = {
            "phase": "before",
            "status": "unavailable",
            "task_id": "test-task",
            "measurement_class": "inconclusive/unavailable",
            "failure_category": "capability_unavailable",
            "decision_effect": False,
            "effect_authorized": False,
            "audit_ref": "audit-record-sha256:" + "f" * 64,
        }
        with patch.object(
            tasks.fleet, "fleet_host", return_value=LOCAL_HOST
        ), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 159}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        dispatch.assert_called_once()
        self.assertEqual(result["task"]["state"], "running")
        self.assertEqual(
            result["audit"]["reposkop_checkout_shadow_before"]["status"],
            "unavailable",
        )
        self.assertIs(
            result["audit"]["reposkop_checkout_shadow_before"]["decision_effect"],
            False,
        )

    def test_unversioned_workspace_write_skips_checkout_reposkop(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with tempfile.TemporaryDirectory(dir=self.root.parent) as scratch_name:
            scratch = Path(scratch_name)
            with patch.object(
                tasks, "_workspace_scope_identity", return_value=("0" * 40, "unversioned")
            ), patch.object(
                tasks.fleet, "fleet_host", return_value=LOCAL_HOST
            ), patch.object(
                tasks, "_validate_command", return_value=argv
            ), patch.object(
                tasks, "_dispatch", return_value=_launcher()
            ) as dispatch, patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
            ):
                result = tasks.grabowski_task_start(
                    "local", argv, cwd=str(scratch), runtime_seconds=60
                )

            dispatch.assert_called_once()
            classification = result["task_effect_classification"]
            self.assertEqual(classification["effect_profile"], "workspace_write")
            self.assertEqual(classification["reposkop_policy"], "not_required")
            self.assertEqual(classification["reposkop_cohort"], "not_applicable")
            self.assertEqual(
                classification["reposkop_applicability"], "no_git_marker"
            )
            self.assertIs(classification["prospective_admission_verified"], False)
            self.assertIsNone(result["reposkop_execution_attestation"])
            self.assertIsNone(result["reposkop_checkout_shadow_before"])
            self.reposkop_attestation_mock.assert_not_called()
            self.reposkop_shadow_before_mock.assert_not_called()
            self.assertIsNotNone(
                tasks.resources.inspect_resource(f"repo:{scratch}")
            )

    def test_unversioned_workspace_write_ignores_invalid_ancestor_git_marker(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with tempfile.TemporaryDirectory(dir=self.root.parent) as ambient_name:
            ambient = Path(ambient_name)
            (ambient / ".git").mkdir()
            scratch = ambient / "scratch"
            scratch.mkdir()
            with patch.object(
                tasks.fleet, "fleet_host", return_value=LOCAL_HOST
            ), patch.object(
                tasks, "_validate_command", return_value=argv
            ), patch.object(
                tasks, "_dispatch", return_value=_launcher()
            ) as dispatch, patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
            ):
                result = tasks.grabowski_task_start(
                    "local", argv, cwd=str(scratch), runtime_seconds=60
                )

            dispatch.assert_called_once()
            classification = result["task_effect_classification"]
            self.assertEqual(classification["effect_profile"], "workspace_write")
            self.assertEqual(classification["reposkop_policy"], "not_required")
            self.assertEqual(classification["reposkop_cohort"], "not_applicable")
            self.assertEqual(
                classification["reposkop_applicability"], "no_git_marker"
            )
            self.assertEqual(
                result["audit"]["implicit_workspace_resource_key"],
                f"repo:{scratch}",
            )
            self.assertIsNone(tasks.resources.inspect_resource(f"repo:{ambient}"))
            self.assertIsNotNone(tasks.resources.inspect_resource(f"repo:{scratch}"))

    def test_git_workspace_discovery_ignores_repository_selection_environment(self) -> None:
        repository = self.root / "selected-repository"
        unrelated = self.root / "unrelated-repository"
        for path, branch in ((repository, "expected"), (unrelated, "wrong")):
            subprocess.run(
                ["git", "init", "-q", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "-C", str(path), "symbolic-ref", "HEAD", f"refs/heads/{branch}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        nested = repository / "src" / "feature"
        nested.mkdir(parents=True)

        with patch.dict(
            os.environ,
            {
                "GIT_DIR": str(unrelated / ".git"),
                "GIT_WORK_TREE": str(unrelated),
                "GIT_CEILING_DIRECTORIES": str(repository),
            },
            clear=False,
        ):
            self.assertEqual(
                tasks._local_workspace_path(None, cwd=str(nested)),
                str(repository),
            )
            self.assertEqual(
                tasks._workspace_scope_identity(str(repository)),
                ("0" * 40, "expected"),
            )

    def test_nested_git_workspace_discovery_failure_fails_closed(self) -> None:
        repository = self.root / "discovery-failure-repository"
        subprocess.run(
            ["git", "init", "-q", str(repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        nested = repository / "src" / "feature"
        nested.mkdir(parents=True)

        with patch.object(tasks, "_local_git_root", return_value=None):
            with self.assertRaisesRegex(
                RuntimeError, "unable to validate ancestor Git workspace root"
            ):
                tasks._local_workspace_path(None, cwd=str(nested))

    def test_unversioned_repository_write_remains_reposkop_required(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with tempfile.TemporaryDirectory(dir=self.root.parent) as scratch_name:
            scratch = Path(scratch_name)
            with patch.object(
                tasks, "_workspace_scope_identity", return_value=("0" * 40, "unversioned")
            ), patch.object(
                tasks.fleet, "fleet_host", return_value=LOCAL_HOST
            ), patch.object(
                tasks, "_validate_command", return_value=argv
            ), patch.object(
                tasks, "_dispatch", return_value=_launcher()
            ) as dispatch, patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
            ):
                result = tasks.grabowski_task_start(
                    "local",
                    argv,
                    cwd=str(scratch),
                    runtime_seconds=60,
                    effect_profile="repository_write",
                )

            dispatch.assert_called_once()
            classification = result["task_effect_classification"]
            self.assertEqual(classification["effect_profile"], "repository_write")
            self.assertEqual(classification["reposkop_policy"], "required")
            self.assertEqual(
                classification["reposkop_cohort"], "repository_write_required"
            )
            self.reposkop_attestation_mock.assert_called_once()
            self.reposkop_shadow_before_mock.assert_called_once()

    def test_main_branch_and_exact_path_writers_remain_reposkop_required(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        tasks.resources.work_admission.require_repository_admission.return_value = {
            "schema_version": 1,
            "kind": "grabowski.repository_work_admission",
            "repository": str(self.root),
            "decision": "allow",
            "assessment_sha256": "a" * 64,
            "read_only": True,
        }
        with patch.object(
            tasks, "_workspace_scope_identity", return_value=("1" * 40, "main")
        ), patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
        ):
            main_result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(main_result["task_effect_classification"]["reposkop_policy"], "required")
        self.assertEqual(main_result["task_effect_classification"]["reposkop_cohort"], "risk_required")

    def test_mutating_agent_reposkop_failure_releases_lease_before_launch(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        self.reposkop_attestation_mock.side_effect = RuntimeError(
            "reposkop unavailable"
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ) as append_audit, patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 152}
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Reposkop execution attestation failed before task launch",
            ):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60
                )

        dispatch.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0],
                0,
            )
        blocked = [
            call.args[0]
            for call in append_audit.call_args_list
            if call.args
            and call.args[0].get("operation")
            == "reposkop-execution-attestation-blocked"
        ]
        self.assertEqual(len(blocked), 1)
        self.assertIs(blocked[0]["no_process_started"], True)
        self.assertIs(blocked[0]["no_task_record_created"], True)

    def test_read_only_codex_task_does_not_require_reposkop(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "read-only"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 153}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )

        self.assertIsNone(result["reposkop_execution_attestation"])
        self.assertIs(
            result["audit"]["reposkop_execution_attestation_required"],
            False,
        )
        self.reposkop_attestation_mock.assert_not_called()
        self.reposkop_shadow_before_mock.assert_not_called()

    def test_remote_writer_is_not_forced_through_checkout_shadow(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(
            tasks.fleet, "fleet_host", return_value=REMOTE_HOST
        ), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 160}
        ):
            result = tasks.grabowski_task_start(
                "remote", argv, cwd=str(self.root), runtime_seconds=60
            )

        self.assertEqual(
            result["task_effect_classification"]["effect_profile"],
            "remote_write",
        )
        self.assertIsNone(result["reposkop_checkout_shadow_before"])
        self.reposkop_attestation_mock.assert_not_called()
        self.reposkop_shadow_before_mock.assert_not_called()

    def test_reposkop_execution_attestation_contract_is_hash_bound(self) -> None:
        workspace = str(self.root)

        def sha(character: str) -> str:
            return character * 64

        def loader(repo: str, purpose: str) -> dict[str, object]:
            self.assertEqual(repo, workspace)
            return {
                "schema_version": 2,
                "kind": "grabowski_reposkop_context",
                "effect_authorized": False,
                "target": {"path": repo, "purpose": purpose},
                "reposkop": {"sha256": sha("1")},
                "report": {
                    "schema_version": 2,
                    "kind": "reposkop_coherence_report",
                    "effect_authorized": False,
                    "report_sha256": sha("2"),
                    "observation": {
                        "observation_complete": True,
                        "observation_sha256": sha("3"),
                        "identities": {
                            "path": repo,
                            "purpose": purpose,
                            "repository_identity_sha256": sha("4"),
                            "checkout_identity_sha256": sha("5"),
                        },
                    },
                    "projection": {
                        "effect_authorized": False,
                        "projection_sha256": sha("6"),
                    },
                },
                "usage_receipt": {
                    "path": "/tmp/receipt.json",
                    "sha256": sha("7"),
                    "usage_key_sha256": sha("8"),
                    "audit_ref": "audit-record-sha256:" + sha("9"),
                },
            }

        result = self.real_reposkop_attest(
            workspace=workspace,
            task_id="a" * 24,
            lease_owner_id="task:" + "a" * 24,
            workspace_lease_resource_keys=[f"repo:{workspace}"],
            argv=["/opt/codex", "exec"],
            argv_sha256=sha("a"),
            execution_identity_sha256=sha("b"),
            reposkop_context_loader=loader,
        )
        material = dict(result)
        claimed = material.pop("execution_binding_sha256")
        self.assertEqual(claimed, tasks._sha256_json(material))
        self.assertEqual(result["status"], "verified")
        self.assertIs(result["effect_authorized"], False)
        self.assertEqual(
            result["finding_summary"]["finding_taxonomy_status"],
            "available_v2",
        )
        self.assertIn(
            "git_observation_missing",
            result["finding_summary"]["finding_reason_codes"],
        )
        with self.assertRaisesRegex(
            ValueError, "workspace-covering lease resources"
        ):
            self.real_reposkop_attest(
                workspace=workspace,
                task_id="b" * 24,
                lease_owner_id="task:" + "b" * 24,
                workspace_lease_resource_keys=[
                    f"path:{Path(workspace).parent / (Path(workspace).name + '-outside')}"
                ],
                argv=["/opt/codex", "exec"],
                argv_sha256=sha("c"),
                execution_identity_sha256=sha("d"),
                reposkop_context_loader=loader,
            )

    def test_expired_implicit_repository_lease_reacquires_complete_scope(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", side_effect=[_launcher(), running]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 161}
        ), patch.object(
            tasks, "_workspace_scope_identity",
            side_effect=[("a" * 40, "main"), ("b" * 40, "feat/changed")],
        ) as identity:
            started = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            key = f"repo:{self.root}"
            empty_json, empty_sha256 = tasks.resources._metadata({})
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE leases SET expires_at_unix=0, metadata_json=?, "
                    "metadata_sha256=? WHERE resource_key=?",
                    (empty_json, empty_sha256, key),
                )
                connection.commit()
            status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(status["lease_maintenance"]["mode"], "reacquired")
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertIs(metadata["recovered_after_expiry"], True)
        self.assertEqual(metadata["implicit_workspace_resource_key"], key)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])
        self.assertEqual(metadata["scope_manifest"]["head"], "a" * 40)
        self.assertEqual(metadata["scope_manifest"]["branch"], "main")
        self.assertEqual(identity.call_count, 1)
        with sqlite3.connect(self.database) as connection:
            stored = json.loads(connection.execute(
                "SELECT repository_scope_manifest_json FROM tasks WHERE task_id=?",
                (started["task"]["task_id"],),
            ).fetchone()[0])
        self.assertEqual(stored, metadata["scope_manifest"])

    def test_schema4_task_recovers_manifest_from_expired_lease_metadata(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", side_effect=[_launcher(), running]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 164}
        ), patch.object(
            tasks, "_workspace_scope_identity",
            side_effect=[("c" * 40, "main"), ("d" * 40, "feat/changed")],
        ) as identity:
            started = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            key = f"repo:{self.root}"
            with sqlite3.connect(self.database) as connection:
                connection.execute(
                    "UPDATE tasks SET repository_scope_manifest_json=NULL WHERE task_id=?",
                    (started["task"]["task_id"],),
                )
                connection.commit()
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute(
                    "UPDATE leases SET expires_at_unix=0 WHERE resource_key=?",
                    (key,),
                )
                connection.commit()
            status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertEqual(status["lease_maintenance"]["mode"], "reacquired")
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(connection.execute(
                "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
            ).fetchone()[0])
        self.assertEqual(metadata["scope_manifest"]["head"], "c" * 40)
        self.assertEqual(metadata["scope_manifest"]["branch"], "main")
        self.assertEqual(identity.call_count, 1)

    def test_legacy_task_without_scope_evidence_fails_closed_on_reacquire(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        running = _launcher()
        running["stdout"] = (
            "LoadState=loaded\nActiveState=active\nSubState=running\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(
            tasks, "_dispatch", side_effect=[_launcher(), running]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 165}
        ), patch.object(
            tasks, "_workspace_scope_identity",
            side_effect=[("e" * 40, "main"), ("f" * 40, "feat/changed")],
        ) as identity:
            started = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            key = f"repo:{self.root}"
            with sqlite3.connect(self.database) as connection:
                connection.execute(
                    "UPDATE tasks SET repository_scope_manifest_json=NULL WHERE task_id=?",
                    (started["task"]["task_id"],),
                )
                connection.commit()
            with sqlite3.connect(self.resource_database) as connection:
                connection.execute("DELETE FROM leases WHERE resource_key=?", (key,))
                connection.commit()
            status = tasks.grabowski_task_status(started["task"]["task_id"])

        self.assertFalse(status["lease_maintenance"]["maintained"])
        self.assertEqual(status["lease_maintenance"]["mode"], "failed")
        self.assertIn("scope manifest evidence is required", status["lease_maintenance"]["error"])
        self.assertIsNone(tasks.resources.inspect_resource(key))
        self.assertEqual(identity.call_count, 1)

    def test_explicit_repository_task_scope_is_attested(self) -> None:
        key = f"repo:{self.root}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 160}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[key],
            )
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertIs(metadata["scope_manifest_complete"], True)
        self.assertEqual(metadata["scope_manifest"]["repository"], str(self.root))
        self.assertEqual(metadata["scope_manifest"]["paths"], [str(self.root)])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])
        self.assertRegex(
            result["audit"]["repository_scope_manifest_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_broad_repository_task_path_with_scope_marker_is_attested(self) -> None:
        for marker in ("branch", "operation"):
            with self.subTest(marker=marker):
                repository = self.root / f"repo:{marker}:literal"
                repository.mkdir()
                (repository / ".git").write_text("gitdir: /tmp/task-marker-repo\n")
                key = f"repo:{repository}"
                with patch.object(
                    tasks.fleet, "fleet_host", return_value=LOCAL_HOST
                ), patch.object(
                    tasks, "_dispatch", return_value=_launcher()
                ), patch.object(tasks.base, "_append_audit"), patch.object(
                    tasks, "_require_recovery_gate", return_value={"checked_at_unix": 163}
                ):
                    result = tasks.grabowski_task_start(
                        "local",
                        ["/bin/true"],
                        cwd=str(repository),
                        runtime_seconds=60,
                        resource_keys=[key],
                    )
                with sqlite3.connect(self.resource_database) as connection:
                    metadata = json.loads(
                        connection.execute(
                            "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                        ).fetchone()[0]
                    )
                self.assertIs(metadata["scope_manifest_complete"], True)
                self.assertEqual(
                    metadata["scope_manifest"]["repository"], str(repository)
                )
                tasks.resources.release_resources(
                    result["task"]["lease_owner_id"], [key]
                )

    def test_scoped_repository_task_key_binds_underlying_repository(self) -> None:
        key = f"repo:{self.root}:branch:feat/scoped-task"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 162}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=[key],
            )
        with sqlite3.connect(self.resource_database) as connection:
            metadata = json.loads(
                connection.execute(
                    "SELECT metadata_json FROM leases WHERE resource_key=?", (key,)
                ).fetchone()[0]
            )
        self.assertNotIn("scope_manifest", metadata)
        self.assertNotIn("scope_manifest_complete", metadata)
        self.assertIsNone(result["audit"]["repository_scope_manifest_sha256"])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_mutating_agents_cannot_share_one_implicit_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 151}
        ):
            tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
            with self.assertRaises(tasks.resources.ResourceConflict):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60
                )
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(tasks.grabowski_task_list()["count"], 1)

    def test_explicit_file_scopes_do_not_replace_workspace_guard(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        left = f"path:{self.root / 'left.py'}"
        right = f"path:{self.root / 'right.py'}"
        workspace = f"repo:{self.root}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch, patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 152}
        ):
            first = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60,
                resource_keys=[left],
            )
            with self.assertRaises(tasks.resources.ResourceConflict):
                tasks.grabowski_task_start(
                    "local", argv, cwd=str(self.root), runtime_seconds=60,
                    resource_keys=[right],
                )
        self.assertEqual(first["task"]["resource_keys"], sorted([left, workspace]))
        self.assertEqual(first["audit"]["implicit_workspace_resource_key"], workspace)
        self.assertEqual(dispatch.call_count, 1)

    def test_exact_disjoint_workspace_paths_allow_parallel_agent_tasks(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        left_workspace = self.root / "left"
        right_workspace = self.root / "right"
        left_workspace.mkdir()
        right_workspace.mkdir()
        (left_workspace / ".git").write_text("gitdir: /tmp/test-left-worktree\n")
        (right_workspace / ".git").write_text("gitdir: /tmp/test-right-worktree\n")
        left = f"path:{left_workspace}"
        right = f"path:{right_workspace}"
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 153}
        ):
            first = tasks.grabowski_task_start(
                "local", argv, cwd=str(left_workspace), runtime_seconds=60,
                resource_keys=[left],
            )
            second = tasks.grabowski_task_start(
                "local", argv, cwd=str(right_workspace), runtime_seconds=60,
                resource_keys=[right],
            )
        self.assertEqual(first["task"]["resource_keys"], [left])
        self.assertEqual(second["task"]["resource_keys"], [right])
        self.assertIsNone(first["audit"]["implicit_workspace_resource_key"])
        self.assertIsNone(second["audit"]["implicit_workspace_resource_key"])

    def test_nested_agent_working_directories_share_git_root_guard(self) -> None:
        repository = self.root / "repository"
        subprocess.run(
            ["git", "init", "-q", str(repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        nested = repository / "src" / "feature"
        nested.mkdir(parents=True)
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 159}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(nested), runtime_seconds=60
            )
        self.assertEqual(
            result["audit"]["implicit_workspace_resource_key"],
            f"repo:{repository}",
        )

    def test_codex_explicit_working_directory_is_the_guarded_workspace(self) -> None:
        repository = self.root / "explicit-repository"
        subprocess.run(
            ["git", "init", "-q", str(repository)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        workspace = repository / "writer-worktree"
        workspace.mkdir()
        argv = [
            "/opt/codex", "exec", "-C", str(workspace),
            "--sandbox", "workspace-write",
        ]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 155}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(
            result["audit"]["implicit_workspace_resource_key"],
            f"repo:{repository}",
        )

    def test_framework_writer_wrapper_keeps_workspace_owned_lease_contract(self) -> None:
        argv = [
            "/usr/bin/python3", "-m", "grabowski_agent_writer",
            "--repository", str(self.root),
        ]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 158}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["resource_keys"], [])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_non_path_resource_does_not_disable_workspace_guard(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 157}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60,
                resource_keys=["port:4567"],
            )
        self.assertEqual(
            result["task"]["resource_keys"],
            ["port:4567", f"repo:{self.root}"],
        )

    def test_read_only_codex_task_does_not_lease_workspace(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "read-only"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher()), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 153}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["resource_keys"], [])
        self.assertIsNone(result["audit"]["implicit_workspace_resource_key"])

    def test_launch_failure_releases_implicit_workspace_lease(self) -> None:
        argv = ["/opt/codex", "exec", "--sandbox", "workspace-write"]
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_validate_command", return_value=argv
        ), patch.object(tasks, "_dispatch", return_value=_launcher(returncode=1)), patch.object(
            tasks.base, "_append_audit"
        ), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 154}
        ):
            result = tasks.grabowski_task_start(
                "local", argv, cwd=str(self.root), runtime_seconds=60
            )
        self.assertEqual(result["task"]["state"], "failed")
        self.assertIsNone(tasks.resources.inspect_resource(f"repo:{self.root}"))

    def test_task_resource_lease_is_released_after_completion(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 130}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=["port:9222"],
            )
        task = started["task"]
        lease = tasks.resources.inspect_resource("port:9222")
        self.assertEqual(lease["owner_id"], task["lease_owner_id"])
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=completed):
            status = tasks.grabowski_task_status(task["task_id"])
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(tasks.resources.inspect_resource("port:9222"))

    def test_launch_failure_releases_task_resource_lease(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher(returncode=1)
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 131}
        ):
            result = tasks.grabowski_task_start(
                "local",
                ["/bin/false"],
                cwd=str(self.root),
                runtime_seconds=60,
                resource_keys=["service:example.service"],
            )
        self.assertEqual(result["task"]["state"], "failed")
        self.assertIsNone(
            tasks.resources.inspect_resource("service:example.service")
        )

    def test_legacy_reconcile_auto_resume_is_disabled_compatibility_path(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 132}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["display:12"],
            )
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(
            tasks, "_dispatch", side_effect=[missing, missing, _launcher()]
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 133}
        ):
            result = tasks.reconcile_tasks(auto_resume=True)
        self.assertTrue(result["legacy_auto_resume_disabled"])
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertIn("outcome_unknown", result["blocked"][0]["reason"])
        self.assertTrue(
            all(
                "legacy auto_resume reconcile is disabled" in item["reason"]
                for item in result["blocked"][1:]
            )
        )
        self.assertIsNotNone(tasks.resources.inspect_resource("display:12"))

    def test_exact_reconcile_resume_allows_named_manual_policy_override(self) -> None:
        started = self._start()
        source = tasks._set_state(
            str(started["task"]["task_id"]),
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            result = tasks.reconcile_tasks_resume(
                task_id=str(source["task_id"]),
                reason="repository dependency changed after the failed attempt",
                max_resumes=1,
            )
        self.assertEqual([], result["blocked"])
        self.assertEqual(1, len(result["resumed"]))
        successor = result["resumed"][0]
        self.assertTrue(successor["explicit_policy_override"])
        self.assertEqual(source["task_id"], successor["retry_of_task_id"])

    def test_exact_reconcile_resume_allows_named_interrupted_recovery(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        source = tasks._set_state(
            task_id,
            "interrupted",
            observation={"state": "interrupted", "source": "startup-recovery"},
        )
        admitted = _missing_unit_observation(
            observed_at_unix=170,
            duration_seconds=0.01,
        )
        revalidated = _missing_unit_observation(
            observed_at_unix=171,
            duration_seconds=0.99,
        )
        launch_bindings: list[dict[str, object]] = []

        def launch_with_persisted_binding(record: dict[str, object]) -> dict[str, object]:
            pending = tasks._row_raw(task_id)
            launcher = json.loads(str(pending["launcher_json"]))
            binding = launcher["interrupted_recovery_binding"]
            launch_bindings.append(binding)
            self.assertEqual("launching", pending["state"])
            self.assertEqual(source["task_id"], binding["source_task_id"])
            self.assertEqual(
                tasks._record_execution_identity(source)["identity_sha256"],
                binding["source_execution_identity_sha256"],
            )
            with self.assertRaisesRegex(RuntimeError, "unresolved recovery attempt"):
                tasks._guard_direct_terminal_retry_record(pending)
            return _launcher()

        with (
            patch.object(tasks, "_reconcile_observation", return_value=admitted),
            patch.object(tasks, "_observe", return_value=revalidated),
            patch.object(tasks, "_launch", side_effect=launch_with_persisted_binding),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 171},
            ),
        ):
            result = tasks.reconcile_tasks_resume(
                task_id=task_id,
                reason="operator repaired the interrupted dependency state",
                max_resumes=1,
            )

        self.assertEqual([], result["blocked"])
        self.assertEqual(1, len(result["resumed"]))
        resumed = result["resumed"][0]
        self.assertTrue(resumed["explicit_interrupted_recovery"])
        self.assertEqual(2, resumed["attempt"])
        self.assertEqual(1, len(launch_bindings))
        persisted = tasks._row_raw(task_id)
        persisted_launcher = json.loads(str(persisted["launcher_json"]))
        self.assertEqual(
            launch_bindings[0]["context_sha256"],
            persisted_launcher["interrupted_recovery_binding"]["context_sha256"],
        )


    def test_interrupted_retry_successor_recovery_preserves_retry_binding(self) -> None:
        started = self._start()
        source = tasks._set_state(
            str(started["task"]["task_id"]),
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 180},
            ),
        ):
            first_retry = tasks.reconcile_tasks_resume(
                task_id=str(source["task_id"]),
                reason="operator repaired the original failure",
                max_resumes=1,
            )
        self.assertEqual([], first_retry["blocked"])
        successor_id = str(first_retry["resumed"][0]["task_id"])
        successor = tasks._row_raw(successor_id)
        retry_binding = tasks._persisted_retry_binding_or_raise(successor)
        self.assertIsNotNone(retry_binding)

        tasks._set_state(
            successor_id,
            "interrupted",
            observation={"state": "interrupted", "source": "host-restart"},
        )
        admitted = _missing_unit_observation(
            observed_at_unix=181,
            duration_seconds=0.01,
        )
        revalidated = _missing_unit_observation(
            observed_at_unix=182,
            duration_seconds=0.02,
        )
        observed_launchers: list[dict[str, object]] = []

        def launch_with_retry_edge(record: dict[str, object]) -> dict[str, object]:
            pending = tasks._row_raw(successor_id)
            launcher = json.loads(str(pending["launcher_json"]))
            self.assertEqual("launching", pending["state"])
            self.assertEqual(retry_binding, launcher["retry_binding"])
            self.assertIn("interrupted_recovery_binding", launcher)
            observed_launchers.append(launcher)
            return _launcher()

        with (
            patch.object(tasks, "_reconcile_observation", return_value=admitted),
            patch.object(tasks, "_observe", return_value=revalidated),
            patch.object(tasks, "_launch", side_effect=launch_with_retry_edge),
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 182},
            ),
        ):
            recovered = tasks.reconcile_tasks_resume(
                task_id=successor_id,
                reason="operator repaired the interrupted successor",
                max_resumes=1,
            )

        self.assertEqual([], recovered["blocked"])
        self.assertEqual(1, len(recovered["resumed"]))
        self.assertEqual(1, len(observed_launchers))
        persisted = tasks._row_raw(successor_id)
        persisted_launcher = json.loads(str(persisted["launcher_json"]))
        self.assertEqual(retry_binding, persisted_launcher["retry_binding"])
        self.assertIn("interrupted_recovery_binding", persisted_launcher)
        self.assertEqual(
            retry_binding,
            tasks._persisted_retry_binding_or_raise(persisted),
        )
        retained = tasks._retained_retry_successor_for_source(
            str(source["task_id"])
        )
        self.assertIsNotNone(retained)
        self.assertEqual(successor_id, retained["task_id"])

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 183},
            ),
        ):
            duplicate = tasks.reconcile_tasks_resume(
                task_id=str(source["task_id"]),
                reason="attempted duplicate successor",
                max_resumes=1,
            )
        self.assertEqual([], duplicate["resumed"])
        self.assertIn("retry successor", duplicate["blocked"][0]["reason"])

    def test_interrupted_recovery_rejects_malformed_retry_binding_before_effects(
        self,
    ) -> None:
        resource_key = f"path:{self.root}"
        started = self._start(resource_keys=[resource_key])
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "interrupted",
            observation={"state": "interrupted", "source": "host-restart"},
        )
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                (json.dumps({"retry_binding": {"source_task_id": "bad"}}), task_id),
            )
            connection.commit()
        admitted = _missing_unit_observation(
            observed_at_unix=184,
            duration_seconds=0.01,
        )
        revalidated = _missing_unit_observation(
            observed_at_unix=185,
            duration_seconds=0.02,
        )
        with (
            patch.object(tasks, "_reconcile_observation", return_value=admitted),
            patch.object(tasks, "_observe", return_value=revalidated),
            patch.object(tasks.resources, "acquire_resources") as acquire,
            patch.object(tasks, "_launch") as launch,
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 185},
            ),
        ):
            result = tasks.reconcile_tasks_resume(
                task_id=task_id,
                reason="operator repaired the interrupted task",
                max_resumes=1,
            )
        self.assertEqual([], result["resumed"])
        self.assertIn(
            "stored retry admission evidence is invalid",
            result["blocked"][0]["reason"],
        )
        acquire.assert_not_called()
        launch.assert_not_called()
        persisted = tasks._row_raw(task_id)
        self.assertEqual("interrupted", persisted["state"])
        self.assertEqual(1, persisted["attempt"])

    def test_interrupted_recovery_requires_exact_task_target(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "interrupted",
            observation={"state": "interrupted", "source": "startup-recovery"},
        )
        observation = _missing_unit_observation(
            observed_at_unix=172,
            duration_seconds=0.01,
        )
        with (
            patch.object(tasks, "_reconcile_observation", return_value=observation),
            patch.object(tasks, "_set_state") as set_state,
            patch.object(tasks, "_launch") as launch,
        ):
            result = tasks.reconcile_tasks_resume(
                reason="broad scans do not establish interrupted recovery authority",
                max_resumes=1,
            )
        self.assertEqual([], result["resumed"])
        self.assertEqual(task_id, result["blocked"][0]["task_id"])
        self.assertEqual("evidence_drift", result["blocked"][0]["reason_class"])
        set_state.assert_not_called()
        launch.assert_not_called()

    def test_interrupted_recovery_revalidates_material_evidence_before_effects(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "interrupted",
            observation={"state": "interrupted", "source": "startup-recovery"},
        )
        admitted = _missing_unit_observation(
            observed_at_unix=173,
            duration_seconds=0.01,
            returncode=0,
        )
        changed = _missing_unit_observation(
            observed_at_unix=174,
            duration_seconds=0.02,
            returncode=4,
        )
        with (
            patch.object(tasks, "_reconcile_observation", return_value=admitted),
            patch.object(tasks, "_observe", return_value=changed),
            patch.object(tasks.resources, "acquire_resources") as acquire,
            patch.object(tasks, "_launch") as launch,
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 174},
            ),
        ):
            result = tasks.reconcile_tasks_resume(
                task_id=task_id,
                reason="operator repaired the interrupted dependency state",
                max_resumes=1,
            )
        self.assertEqual([], result["resumed"])
        self.assertEqual("evidence_drift", result["blocked"][0]["reason_class"])
        self.assertIn("binding is stale", result["blocked"][0]["reason"])
        acquire.assert_not_called()
        launch.assert_not_called()

    def test_interrupted_recovery_persists_binding_before_lease_effect(self) -> None:
        resource_key = f"path:{self.root}"
        started = self._start(resource_keys=[resource_key])
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "interrupted",
            observation={"state": "interrupted", "source": "startup-recovery"},
        )
        admitted = _missing_unit_observation(
            observed_at_unix=175,
            duration_seconds=0.01,
        )
        revalidated = _missing_unit_observation(
            observed_at_unix=176,
            duration_seconds=0.02,
        )

        def fail_after_binding(*args: object, **kwargs: object) -> dict[str, object]:
            pending = tasks._row_raw(task_id)
            launcher = json.loads(str(pending["launcher_json"]))
            self.assertEqual("launching", pending["state"])
            self.assertEqual(2, pending["attempt"])
            self.assertIn("interrupted_recovery_binding", launcher)
            with self.assertRaisesRegex(RuntimeError, "unresolved recovery attempt"):
                tasks._guard_direct_terminal_retry_record(pending)
            raise RuntimeError("synthetic lease renewal failure")

        with (
            patch.object(tasks, "_reconcile_observation", return_value=admitted),
            patch.object(tasks, "_observe", return_value=revalidated),
            patch.object(
                tasks.resources,
                "renew_resources",
                side_effect=fail_after_binding,
            ) as renew,
            patch.object(tasks, "_launch") as launch,
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 176},
            ),
        ):
            result = tasks.reconcile_tasks_resume(
                task_id=task_id,
                reason="operator repaired the interrupted dependency state",
                max_resumes=1,
            )

        self.assertEqual([], result["resumed"])
        self.assertIn("lease renewal failure", result["blocked"][0]["reason"])
        renew.assert_called_once()
        launch.assert_not_called()
        persisted = tasks._row_raw(task_id)
        self.assertEqual("launching", persisted["state"])
        self.assertIn(
            "interrupted_recovery_binding",
            json.loads(str(persisted["launcher_json"])),
        )

    def test_direct_resume_requires_recovery_evidence_for_every_interrupted_policy(self) -> None:
        for policy in ("manual", "verify-then-retry", "retry-safe"):
            with self.subTest(policy=policy):
                started = self._start()
                task_id = str(started["task"]["task_id"])
                with tasks._database() as connection:
                    connection.execute(
                        "UPDATE tasks SET resume_policy=? WHERE task_id=?",
                        (policy, task_id),
                    )
                tasks._set_state(
                    task_id,
                    "interrupted",
                    observation={"state": "interrupted", "source": "startup-recovery"},
                )
                with (
                    patch.object(tasks, "_observe") as observe,
                    patch.object(tasks, "_launch") as launch,
                    self.assertRaisesRegex(
                        PermissionError,
                        "requires exact recovery evidence",
                    ),
                ):
                    tasks.grabowski_task_resume(task_id)
                observe.assert_not_called()
                launch.assert_not_called()

    def test_terminal_retry_replays_managed_cargo_binding_once(self) -> None:
        cache_key = "a" * 64
        target = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
        lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
        bound = [
            tasks.FLOCK_EXECUTABLE,
            "--shared",
            str(lock),
            tasks.SYSTEMD_ENV_EXECUTABLE,
            f"CARGO_TARGET_DIR={target}",
            "/usr/bin/cargo",
            "test",
        ]
        record = {
            "argv_json": json.dumps(bound),
            "host": "local",
            "execution_backend": "systemd-user",
        }
        with patch.object(tasks, "_managed_cargo_lifecycle_lock") as prepare_lock:
            replay = tasks._terminal_retry_command(record)
        self.assertEqual(bound[3:], replay)
        prepare_lock.assert_not_called()

        record["argv_json"] = json.dumps(
            [bound[0], bound[1], "/tmp/wrong.lock", *bound[3:]]
        )
        with patch.object(
            tasks, "_managed_cargo_lifecycle_lock"
        ) as prepare_lock, self.assertRaisesRegex(
            RuntimeError, "lock binding is invalid"
        ):
            tasks._terminal_retry_command(record)
        prepare_lock.assert_not_called()

    def test_terminal_retry_replays_every_accepted_env_spelling(self) -> None:
        cache_key = "b" * 64
        target = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
        lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
        for env_executable in ("env", "/bin/env", tasks.SYSTEMD_ENV_EXECUTABLE):
            with self.subTest(env_executable=env_executable):
                bound = [
                    tasks.FLOCK_EXECUTABLE,
                    "--shared",
                    str(lock),
                    env_executable,
                    f"CARGO_TARGET_DIR={target}",
                    "/usr/bin/cargo",
                    "test",
                ]
                record = {
                    "argv_json": json.dumps(bound),
                    "host": "local",
                    "execution_backend": "systemd-user",
                }
                with patch.object(
                    tasks, "_managed_cargo_lifecycle_lock"
                ) as prepare_lock:
                    replay = tasks._terminal_retry_command(record)
                self.assertEqual(bound[3:], replay)
                prepare_lock.assert_not_called()

    def test_exact_reconcile_resume_allows_named_retry_safe_budget_override(self) -> None:
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "retry-safe-exhausted"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
            )["task"]
        task_id = str(started["task_id"])
        with tasks._database() as connection:
            unit = f"grabowski-task-{task_id}-a2.service"
            connection.execute(
                "UPDATE tasks SET attempt=2, unit=?, authoritative_unit=? "
                "WHERE task_id=?",
                (unit, unit, task_id),
            )
        source = tasks._set_state(
            task_id,
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        successor = {
            "task_id": "f" * 24,
            "state": "running",
            "explicit_policy_override": True,
        }
        with patch.object(
            tasks,
            "_terminal_retry_successor",
            return_value=successor,
        ) as retry:
            result = tasks.reconcile_tasks_resume(
                task_id=task_id,
                max_resumes=1,
                reason="repository dependency changed after retry budget exhaustion",
            )

        self.assertEqual([], result["blocked"])
        self.assertEqual([successor], result["resumed"])
        retry.assert_called_once_with(
            tasks._row_raw(task_id),
            reason="repository dependency changed after retry budget exhaustion",
            explicit_policy_override=True,
        )
        self.assertEqual("retry-safe", source["resume_policy"])

    def test_exact_reconcile_resume_keeps_never_policy_non_overridable(self) -> None:
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "never-retry"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="never",
            )
            source = tasks._set_state(
                str(started["task"]["task_id"]),
                "failed",
                observation={"state": "failed", "source": "test"},
            )
            result = tasks.reconcile_tasks_resume(
                task_id=str(source["task_id"]),
                reason="repository dependency changed after the failed attempt",
                max_resumes=1,
            )

        self.assertEqual([], result["resumed"])
        self.assertEqual(1, len(result["blocked"]))
        self.assertEqual(source["task_id"], result["blocked"][0]["task_id"])
        self.assertEqual("never", result["blocked"][0]["resume_policy"])
        self.assertEqual(
            "non_retryable_failure",
            result["blocked"][0]["reason_class"],
        )

    def test_reconcile_resume_blocks_unverified_policy(self) -> None:
        started = self._start()
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing):
            result = tasks.reconcile_tasks_resume(
                reason="test unsafe policy block", max_resumes=1
            )
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertEqual(
            result["blocked"][0]["resume_policy"], "verify-then-retry"
        )

    def test_reconcile_check_is_read_only_preview(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 140}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["service:preview.service"],
            )
        task = started["task"]
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing):
            result = tasks.reconcile_tasks_check()
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["would_release"], [])
        self.assertEqual(result["would_resume"], [])
        self.assertIn("outcome_unknown", result["blocked"][0]["reason"])
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["tasks"][0]["state"], "running")
        self.assertIsNotNone(tasks.resources.inspect_resource("service:preview.service"))

    def test_exact_reconcile_check_includes_named_converged_terminal_task(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        observation = {
            "state": "failed",
            "properties": {"ActiveState": "failed", "SubState": "failed"},
            "probe": None,
            "observer": {"kind": "test"},
            "observed_at_unix": 203,
        }
        with patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(True, True)
        ), patch.object(tasks, "_reconcile_observation", return_value=observation):
            result = tasks.reconcile_tasks_check(task_id=task_id)
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["observations"][0]["task_id"], task_id)

    def test_reconcile_check_global_pages_without_duplicates(self) -> None:
        started = [
            self._start(resource_keys=[f"service:reconcile-page-{index}.service"])
            for index in range(3)
        ]

        def observation(record: dict[str, object]) -> dict[str, object]:
            return {
                "state": "running",
                "properties": {"ActiveState": "active", "SubState": "running"},
                "probe": None,
                "observer": {"kind": "test"},
                "observed_at_unix": 200,
            }

        pages = []
        cursor = None
        with patch.object(
            tasks, "_reconcile_observation", side_effect=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ):
            while True:
                page = tasks.reconcile_tasks_check(limit=2, cursor=cursor)
                pages.append(page)
                if not page["pagination"]["has_more"]:
                    break
                cursor = page["pagination"]["next_cursor"]

        observed = [
            item["task_id"]
            for page in pages
            for item in page["observations"]
        ]
        expected = {str(item["task"]["task_id"]) for item in started}
        observed_started = [task_id for task_id in observed if task_id in expected]
        self.assertEqual(expected, set(observed_started))
        self.assertEqual(len(expected), len(observed_started))
        self.assertEqual(len(observed), len(set(observed)))
        self.assertTrue(pages[0]["pagination"]["has_more"])
        self.assertFalse(pages[-1]["pagination"]["has_more"])
        for page in pages:
            self.assertLessEqual(
                page["pagination"]["payload_bytes"],
                tasks.TASK_RECONCILE_CHECK_MAX_BYTES,
            )

    def test_reconcile_check_cursor_fails_closed_after_store_change(self) -> None:
        self._start(resource_keys=["service:reconcile-cursor-a.service"])
        self._start(resource_keys=["service:reconcile-cursor-b.service"])
        observation = {
            "state": "running",
            "properties": {"ActiveState": "active", "SubState": "running"},
            "probe": None,
            "observer": {"kind": "test"},
            "observed_at_unix": 201,
        }
        with patch.object(
            tasks, "_reconcile_observation", return_value=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ):
            page = tasks.reconcile_tasks_check(limit=1)
        self._start(resource_keys=["service:reconcile-cursor-c.service"])
        with patch.object(
            tasks, "_reconcile_observation", return_value=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ), self.assertRaisesRegex(ValueError, "cursor_snapshot_changed"):
            tasks.reconcile_tasks_check(
                limit=1,
                cursor=page["pagination"]["next_cursor"],
            )

    def test_reconcile_check_returns_frozen_page_when_store_changes_during_observation(
        self,
    ) -> None:
        self._start(resource_keys=["service:reconcile-live-a.service"])
        self._start(resource_keys=["service:reconcile-live-b.service"])
        mutated = False

        def observation(record: dict[str, object]) -> dict[str, object]:
            nonlocal mutated
            if not mutated:
                mutated = True
                self._start(resource_keys=["service:reconcile-live-c.service"])
            return {
                "state": "running",
                "properties": {"ActiveState": "active", "SubState": "running"},
                "probe": None,
                "observer": {"kind": "test"},
                "observed_at_unix": 202,
            }

        with patch.object(
            tasks, "_reconcile_observation", side_effect=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ):
            page = tasks.reconcile_tasks_check(limit=1)
        self.assertTrue(mutated)
        self.assertEqual(1, page["scanned"])
        self.assertTrue(page["pagination"]["has_more"])
        self.assertIsNotNone(page["pagination"]["next_cursor"])

        with patch.object(
            tasks, "_reconcile_observation", side_effect=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ), self.assertRaisesRegex(ValueError, "cursor_snapshot_changed"):
            tasks.reconcile_tasks_check(
                limit=1,
                cursor=page["pagination"]["next_cursor"],
            )

    def test_reconcile_check_task_specific_shape_remains_unpaged(self) -> None:
        started = self._start(resource_keys=["service:reconcile-exact.service"])
        task_id = str(started["task"]["task_id"])
        observation = {
            "state": "running",
            "properties": {"ActiveState": "active", "SubState": "running"},
            "probe": None,
            "observer": {"kind": "test"},
            "observed_at_unix": 202,
        }
        with patch.object(
            tasks, "_reconcile_observation", return_value=observation
        ), patch.object(
            tasks, "_terminal_convergence_evidence", return_value=(False, False)
        ):
            result = tasks.reconcile_tasks_check(task_id=task_id)
        self.assertEqual(1, result["scanned"])
        self.assertNotIn("pagination", result)
        self.assertIn("resource_keys", result["observations"][0])
        self.assertNotIn("resource_key_count", result["observations"][0])

    def test_reconcile_check_large_store_first_page_is_bounded(self) -> None:
        self._start(resource_keys=["service:reconcile-large.service"])
        for index in range(8):
            self._prepare_pending_terminalization(prepared_at_unix=10_000 + index)
        for index in range(8):
            terminal = self._start()["task"]
            tasks._set_state(
                str(terminal["task_id"]),
                "failed",
                observation={
                    "state": "failed",
                    "source": f"reconcile-projected-fixture-{index}",
                },
            )

        candidate_states = tasks._reconcile_candidate_states()
        state_placeholders = ",".join("?" for _ in candidate_states)
        with tasks._database_connection() as connection:
            columns = [
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
            ]
            base = dict(connection.execute("SELECT * FROM tasks LIMIT 1").fetchone())
            existing_ids = {
                str(row[0])
                for row in connection.execute("SELECT task_id FROM tasks").fetchall()
            }
            existing_candidates = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM tasks WHERE state IN ({state_placeholders})",
                    candidate_states,
                ).fetchone()[0]
            )
            insert_count = 30_000 - existing_candidates
            self.assertGreater(insert_count, 0)
            row_placeholders = ",".join("?" for _ in columns)
            statement = (
                f"INSERT INTO tasks({','.join(columns)}) VALUES({row_placeholders})"
            )
            rows = []
            sequence = 1
            states = ("running", "failed", "timed_out", "signalled")
            while len(rows) < insert_count:
                task_id = f"{sequence:024x}"
                sequence += 1
                if task_id in existing_ids:
                    continue
                record = dict(base)
                record.update(
                    {
                        "task_id": task_id,
                        "unit": f"grabowski-task-{task_id}-a1.service",
                        "authoritative_unit": f"grabowski-task-{task_id}-a1.service",
                        "state": states[sequence % len(states)],
                        "created_at_unix": 100_000 + sequence,
                        "updated_at_unix": 100_000 + sequence,
                        "resource_keys_json": "[]",
                        "lease_owner_id": f"task:{task_id}",
                        "terminalization_sha256": None,
                        "terminalized_at_unix": None,
                        "lifecycle_receipt_sha256": None,
                    }
                )
                rows.append(tuple(record[column] for column in columns))
            connection.executemany(statement, rows)
            candidate_count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM tasks WHERE state IN ({state_placeholders})",
                    candidate_states,
                ).fetchone()[0]
            )
            decision_records = [
                dict(row)
                for row in connection.execute(
                    f"SELECT * FROM tasks WHERE state IN ({state_placeholders}) "
                    "ORDER BY task_id LIMIT 5000",
                    candidate_states,
                ).fetchall()
            ]
        del rows
        self.assertEqual(30_000, candidate_count)

        attention_root = self.root / "state" / "task-attention-decisions"
        attention_root.mkdir(parents=True, mode=0o700)
        outcome_receipt_sha256 = "a" * 64
        outcome_file_sha256 = "b" * 64
        for record in decision_records:
            binding = task_attention._task_binding(record)
            material = {
                "kind": task_attention.DECISION_KIND,
                "schema_version": task_attention.SCHEMA_VERSION,
                "task_binding": binding,
                "decision": "deferred",
                "authority": "test:reconcile-stress",
                "evidence_ref": "fixture:reconcile-stress",
                "outcome_receipt_sha256": outcome_receipt_sha256,
                "outcome_file_sha256": outcome_file_sha256,
            }
            decision = {
                **material,
                "created_at_unix": 123,
                "material_sha256": task_attention._sha256_json(material),
            }
            decision["receipt_sha256"] = task_attention._sha256_json(decision)
            task_attention._validate_decision_record(
                decision,
                binding=binding,
                outcome_receipt_sha256=outcome_receipt_sha256,
                outcome_file_sha256=outcome_file_sha256,
            )
            target = attention_root / f"{binding['task_id']}.a{binding['attempt']}.json"
            target.write_bytes(task_attention._canonical_bytes(decision))
            os.chmod(target, 0o600)
        decision_paths = [
            path
            for path in attention_root.iterdir()
            if task_attention.DECISION_FILE_RE.fullmatch(path.name) is not None
        ]
        self.assertEqual(5_000, len(decision_paths))

        with sqlite3.connect(self.resource_database) as connection:
            phase_counts = {
                str(phase): int(count)
                for phase, count in connection.execute(
                    "SELECT phase, COUNT(*) FROM task_terminalizations GROUP BY phase"
                ).fetchall()
            }
        self.assertGreater(phase_counts.get("projected", 0), 0)
        self.assertGreater(
            sum(count for phase, count in phase_counts.items() if phase != "projected"),
            0,
        )

        def observation(record: dict[str, object]) -> dict[str, object]:
            return {
                "state": record["state"],
                "properties": {},
                "probe": None,
                "observer": {"kind": "fixture"},
                "observed_at_unix": 203,
            }

        tracemalloc.start()
        started_at = time.perf_counter()
        try:
            with patch.dict(
                os.environ,
                {"GRABOWSKI_TASK_ATTENTION_ROOT": str(attention_root)},
            ), patch.object(
                tasks, "_reconcile_observation", side_effect=observation
            ), patch.object(
                tasks, "_terminal_convergence_evidence", return_value=(False, False)
            ):
                result = tasks.reconcile_tasks_check(limit=200)
            elapsed = time.perf_counter() - started_at
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(200, result["pagination"]["examined"])
        self.assertEqual(30_000, result["pagination"]["total_candidates"])
        self.assertTrue(result["pagination"]["has_more"])
        self.assertLess(elapsed, 10.0)
        self.assertLess(result["pagination"]["timings_ms"]["total"], 10_000.0)
        self.assertEqual(
            {
                "snapshot",
                "cursor_and_query",
                "page_setup_total",
                "observation",
                "serialization",
                "total",
            },
            set(result["pagination"]["timings_ms"]),
        )
        self.assertLess(peak, 256 * 1024 * 1024)
        self.assertLessEqual(
            result["pagination"]["payload_bytes"],
            tasks.TASK_RECONCILE_CHECK_MAX_BYTES,
        )

    def test_reconcile_refresh_does_not_resume_processes(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 141}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                resource_keys=["service:refresh.service"],
            )
        missing = _launcher(returncode=1)
        missing["stderr"] = "unit not found"
        with patch.object(tasks, "_dispatch", return_value=missing) as dispatch:
            result = tasks.reconcile_tasks_refresh()
        self.assertEqual(dispatch.call_count, 1)
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["released"], [])
        self.assertEqual(result["refreshed"][0]["state"], "outcome_unknown")
        self.assertIsNotNone(tasks.resources.inspect_resource("service:refresh.service"))

    def test_reconcile_refresh_runs_bounded_archived_output_cleanup(self) -> None:
        cleanup = {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_reconcile",
            "status": "ok",
            "scanned": 2,
            "counts": {
                "deleted": 1,
                "deferred": 0,
                "not_present": 1,
                "errors": 0,
            },
        }
        with patch.object(
            task_attention,
            "reconcile_archived_task_outputs",
            return_value=cleanup,
        ) as converge:
            result = tasks.reconcile_tasks_refresh(batch_size=1)
        converge.assert_called_once_with(
            limit=task_attention.DEFAULT_TASK_OUTPUT_CLEANUP_BATCH_SIZE
        )
        self.assertEqual(result["task_output_cleanup"], cleanup)

    def test_reconcile_refresh_runs_output_cleanup_after_mutation_lock_release(self) -> None:
        lock_active = False
        order: list[str] = []
        core = {
            "mode": "refresh",
            "task_id": "",
            "scanned": 0,
            "refreshed": [],
            "released": [],
            "resumed": [],
            "blocked": [],
            "checked_at_unix": 123,
            "batch": {"limit": 1},
        }
        cleanup = {
            "schema_version": 1,
            "kind": "grabowski_task_output_cleanup_reconcile",
            "status": "ok",
            "scanned": 0,
        }

        @contextmanager
        def mutation_lock():
            nonlocal lock_active
            self.assertFalse(lock_active)
            lock_active = True
            order.append("lock-enter")
            try:
                yield
            finally:
                lock_active = False
                order.append("lock-exit")

        def run_cleanup(*, limit: int) -> dict[str, object]:
            self.assertFalse(lock_active)
            self.assertEqual(
                limit, task_attention.DEFAULT_TASK_OUTPUT_CLEANUP_BATCH_SIZE
            )
            order.append("cleanup")
            return cleanup

        with patch.object(
            tasks, "_task_mutation_lock", side_effect=mutation_lock
        ), patch.object(
            tasks, "_reconcile_tasks_refresh_locked", return_value=core
        ), patch.object(
            task_attention,
            "reconcile_archived_task_outputs",
            side_effect=run_cleanup,
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=1)

        self.assertEqual(order, ["lock-enter", "lock-exit", "cleanup"])
        self.assertEqual(result["task_output_cleanup"], cleanup)

    def test_mcp_refresh_guard_releases_mutation_lock_before_output_cleanup(self) -> None:
        lock_active = False
        order: list[str] = []
        core = {
            "mode": "refresh",
            "task_id": "",
            "scanned": 0,
            "refreshed": [],
            "released": [],
            "resumed": [],
            "blocked": [],
            "checked_at_unix": 123,
            "batch": {"limit": 1},
        }

        @contextmanager
        def mutation_lock():
            nonlocal lock_active
            lock_active = True
            order.append("lock-enter")
            try:
                yield
            finally:
                lock_active = False
                order.append("lock-exit")

        def run_cleanup(*, limit: int) -> dict[str, object]:
            self.assertFalse(lock_active)
            order.append("cleanup")
            return {
                "schema_version": 1,
                "kind": "grabowski_task_output_cleanup_reconcile",
                "status": "ok",
                "scanned": 0,
            }

        with patch.object(
            tasks, "_task_mutation_lock", side_effect=mutation_lock
        ), patch.object(
            tasks.operator, "_require_operator_mutation"
        ), patch.object(
            tasks, "_reconcile_tasks_refresh_locked", return_value=core
        ), patch.object(
            task_attention,
            "reconcile_archived_task_outputs",
            side_effect=run_cleanup,
        ), patch.object(tasks.base, "_append_audit"):
            result = tasks._task_reconcile_refresh_after_guard("")

        self.assertEqual(order, ["lock-enter", "lock-exit", "cleanup"])
        self.assertEqual(result["task_output_cleanup"]["status"], "ok")

    def test_reconcile_refresh_isolates_archived_output_cleanup_failure(self) -> None:
        with patch.object(
            task_attention,
            "reconcile_archived_task_outputs",
            side_effect=RuntimeError("cleanup unavailable"),
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=1)
        cleanup = result["task_output_cleanup"]
        self.assertEqual(cleanup["status"], "degraded")
        self.assertEqual(cleanup["error_type"], "RuntimeError")
        self.assertIn("cleanup unavailable", cleanup["error"])
        self.assertEqual(result["mode"], "refresh")
        self.assertIn("batch", result)

    def test_exact_task_refresh_does_not_run_global_output_cleanup(self) -> None:
        started = self._start()["task"]
        task_id = str(started["task_id"])
        with patch.object(
            task_attention, "reconcile_archived_task_outputs"
        ) as converge, patch.object(
            tasks, "_reconcile_observation", return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
            }
        ), patch.object(tasks, "_maintain_record_resources", return_value=None):
            result = tasks.reconcile_tasks_refresh(task_id=task_id)
        converge.assert_not_called()
        self.assertNotIn("task_output_cleanup", result)

    def test_serialized_task_mcp_entrypoints_offload_to_worker_threads(self) -> None:
        expected = {
            "grabowski_task_start",
            "grabowski_task_status",
            "grabowski_task_routing_shadow_seal",
            "grabowski_task_logs",
            "grabowski_task_cancel",
            "grabowski_task_resume",
            "grabowski_task_list",
        }
        module = ast.parse((SRC / "grabowski_tasks.py").read_text(encoding="utf-8"))
        observed: set[str] = set()
        for node in module.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tool_name = None
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "tool"
                ):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        tool_name = keyword.value.value
            if tool_name not in expected:
                continue
            observed.add(tool_name)
            self.assertIsInstance(node, ast.AsyncFunctionDef, tool_name)
            self.assertTrue(
                any(
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id == "asyncio"
                    and child.func.attr == "to_thread"
                    for child in ast.walk(node)
                ),
                tool_name,
            )
        self.assertEqual(observed, expected)

    def test_mcp_task_status_lock_wait_does_not_block_event_loop(self) -> None:
        task_id = "a" * 24
        lock_held = threading.Event()
        release_lock = threading.Event()
        worker_threads: list[int] = []
        caller_thread = threading.get_ident()

        def hold_lock() -> None:
            with tasks.TASK_RECONCILE_LOCK:
                lock_held.set()
                release_lock.wait(timeout=2)

        def status(identifier: str) -> dict[str, object]:
            with tasks.TASK_RECONCILE_LOCK:
                worker_threads.append(threading.get_ident())
                return {"task_id": identifier}

        holder = threading.Thread(target=hold_lock)
        holder.start()
        self.assertTrue(lock_held.wait(timeout=2))
        fallback_release = threading.Timer(0.5, release_lock.set)

        async def exercise() -> dict[str, object]:
            started = time.monotonic()
            pending = asyncio.create_task(tasks._grabowski_task_status_tool(task_id))
            await asyncio.sleep(0.05)
            self.assertLess(time.monotonic() - started, 0.25)
            self.assertFalse(pending.done())
            release_lock.set()
            return await asyncio.wait_for(pending, timeout=2)

        fallback_release.start()
        try:
            with (
                patch.object(tasks.operator, "_require_operator_capability"),
                patch.object(tasks, "grabowski_task_status", side_effect=status),
            ):
                result = asyncio.run(exercise())
        finally:
            release_lock.set()
            fallback_release.cancel()
            holder.join(timeout=2)

        self.assertFalse(holder.is_alive())
        self.assertEqual(result, {"task_id": task_id})
        self.assertEqual(len(worker_threads), 1)
        self.assertNotEqual(worker_threads[0], caller_thread)

    def test_task_mutation_waits_for_external_process_lock(self) -> None:
        task = self._start()["task"]
        lock_path = self.database.with_suffix(".mutation.lock")
        child = (
            "import fcntl, os, sys; "
            "fd=os.open(sys.argv[1], os.O_RDWR|os.O_CREAT, 0o600); "
            "fcntl.flock(fd, fcntl.LOCK_EX); "
            "print('locked', flush=True); "
            "sys.stdin.readline(); "
            "fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", child, str(lock_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        completed = threading.Event()
        errors: list[BaseException] = []

        def read_task() -> None:
            try:
                tasks._row(str(task["task_id"]))
            except BaseException as exc:
                errors.append(exc)
            finally:
                completed.set()

        thread = threading.Thread(target=read_task)
        try:
            assert process.stdout is not None
            self.assertEqual(process.stdout.readline().strip(), "locked")
            thread.start()
            self.assertFalse(completed.wait(timeout=0.15))
            assert process.stdin is not None
            process.stdin.write("\n")
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=2), 0)
            self.assertTrue(completed.wait(timeout=2))
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        finally:
            if process.poll() is None:
                if process.stdin is not None:
                    process.stdin.write("\n")
                    process.stdin.flush()
                process.kill()
                process.wait(timeout=2)
            if thread.is_alive():
                thread.join(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def test_task_mutation_creates_private_lock_parent(self) -> None:
        database = self.root / "fresh-state" / "tasks.sqlite3"
        with patch.object(tasks, "TASK_DB", database):
            with tasks._task_mutation_lock():
                pass

        self.assertEqual(
            tasks.stat.S_IMODE(database.parent.stat().st_mode),
            0o700,
        )
        self.assertEqual(
            tasks.stat.S_IMODE(database.with_suffix(".mutation.lock").stat().st_mode),
            0o600,
        )

    def test_task_mutation_rejects_public_lock_parent(self) -> None:
        parent = self.root / "public-state"
        parent.mkdir(mode=0o700)
        parent.chmod(0o755)
        database = parent / "tasks.sqlite3"

        with (
            patch.object(tasks, "TASK_DB", database),
            self.assertRaisesRegex(
                PermissionError,
                "Task mutation lock parent violates its directory contract",
            ),
        ):
            with tasks._task_mutation_lock():
                pass

    def test_task_mutation_rejects_symlink_lock_parent(self) -> None:
        target = self.root / "real-state"
        target.mkdir(mode=0o700)
        parent = self.root / "linked-state"
        parent.symlink_to(target, target_is_directory=True)
        database = parent / "tasks.sqlite3"

        with (
            patch.object(tasks, "TASK_DB", database),
            self.assertRaisesRegex(
                PermissionError,
                "Task mutation lock parent may not be a symlink",
            ),
        ):
            with tasks._task_mutation_lock():
                pass

    def test_task_mutation_rejects_symlink_lock(self) -> None:
        task = self._start()["task"]
        lock_path = self.database.with_suffix(".mutation.lock")
        lock_path.unlink()
        target = self.root / "foreign.lock"
        target.write_text("foreign", encoding="utf-8")
        target.chmod(0o600)
        lock_path.symlink_to(target)

        with self.assertRaisesRegex(
            PermissionError,
            "Task mutation lock cannot be opened safely",
        ):
            tasks._row(str(task["task_id"]))

    def test_task_mutation_rejects_permissive_lock_mode(self) -> None:
        task = self._start()["task"]
        lock_path = self.database.with_suffix(".mutation.lock")
        lock_path.chmod(0o640)

        with self.assertRaisesRegex(
            PermissionError,
            "Task mutation lock violates its file contract",
        ):
            tasks._row(str(task["task_id"]))

    def test_mcp_reconcile_refresh_runs_store_work_off_event_loop(self) -> None:
        caller_thread = threading.get_ident()
        worker_threads: list[int] = []
        payload = {
            "mode": "refresh",
            "task_id": "",
            "scanned": 0,
            "refreshed": [],
            "released": [],
            "resumed": [],
            "blocked": [],
            "checked_at_unix": 123,
        }

        def refresh(task_id: str) -> dict[str, object]:
            self.assertEqual(task_id, "")
            worker_threads.append(threading.get_ident())
            return payload

        with (
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.object(
                tasks,
                "_task_reconcile_refresh_after_guard",
                side_effect=refresh,
            ),
        ):
            result = asyncio.run(tasks._grabowski_task_reconcile_refresh_tool())

        self.assertEqual(result, payload)
        self.assertEqual(len(worker_threads), 1)
        self.assertNotEqual(worker_threads[0], caller_thread)

    def test_mcp_reconcile_refresh_serializes_store_mutations(self) -> None:
        active = 0
        maximum_active = 0
        counter_lock = threading.Lock()

        def refresh(*, task_id: str = "") -> dict[str, object]:
            nonlocal active, maximum_active
            with counter_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            try:
                time.sleep(0.03)
                return {
                    "mode": "refresh",
                    "task_id": task_id,
                    "scanned": 0,
                    "refreshed": [],
                    "released": [],
                    "resumed": [],
                    "blocked": [],
                    "checked_at_unix": 123,
                }
            finally:
                with counter_lock:
                    active -= 1

        async def run_both() -> None:
            await asyncio.gather(
                tasks._grabowski_task_reconcile_refresh_tool("a" * 24),
                tasks._grabowski_task_reconcile_refresh_tool("b" * 24),
            )

        with (
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.object(
                tasks, "_reconcile_tasks_refresh_locked", side_effect=refresh
            ),
            patch.object(tasks.base, "_append_audit"),
        ):
            asyncio.run(run_both())

        self.assertEqual(maximum_active, 1)

    def test_reconcile_refresh_serializes_with_cancel(self) -> None:
        resource_key = "service:reconcile-cancel-race.service"
        task = self._start(resource_keys=[resource_key])["task"]
        reconcile_entered = threading.Event()
        allow_reconcile = threading.Event()
        cancel_started = threading.Event()
        cancel_dispatched = threading.Event()
        errors: list[BaseException] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            self.assertEqual(record["task_id"], task["task_id"])
            reconcile_entered.set()
            if not allow_reconcile.wait(timeout=2):
                raise RuntimeError("test did not release reconcile observation")
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        def dispatch(*args, **kwargs) -> dict[str, object]:
            cancel_dispatched.set()
            return _launcher()

        def run_refresh() -> None:
            try:
                tasks.grabowski_task_reconcile_refresh(str(task["task_id"]))
            except BaseException as exc:
                errors.append(exc)

        def run_cancel() -> None:
            cancel_started.set()
            try:
                tasks.grabowski_task_cancel(str(task["task_id"]))
            except BaseException as exc:
                errors.append(exc)

        with (
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.object(tasks, "_reconcile_observation", side_effect=observe),
            patch.object(tasks, "_dispatch", side_effect=dispatch),
            patch.object(tasks.base, "_append_audit"),
        ):
            refresh_thread = threading.Thread(target=run_refresh)
            cancel_thread = threading.Thread(target=run_cancel)
            refresh_thread.start()
            self.assertTrue(reconcile_entered.wait(timeout=2))
            cancel_thread.start()
            self.assertTrue(cancel_started.wait(timeout=2))
            self.assertFalse(cancel_dispatched.wait(timeout=0.1))
            allow_reconcile.set()
            refresh_thread.join(timeout=2)
            cancel_thread.join(timeout=2)

        self.assertFalse(refresh_thread.is_alive())
        self.assertFalse(cancel_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(cancel_dispatched.is_set())
        self.assertEqual(tasks._row(str(task["task_id"]))["state"], "cancelled")
        self.assertIsNone(tasks.resources.inspect_resource(resource_key))

    def test_mcp_reconcile_refresh_rechecks_authority_inside_lock(self) -> None:
        with (
            patch.object(tasks.operator, "_require_operator_capability") as capability,
            patch.object(
                tasks.operator,
                "_require_operator_mutation",
                side_effect=PermissionError("blocked after wait"),
            ) as mutation,
            patch.object(tasks, "_reconcile_tasks_refresh_locked") as refresh,
        ):
            with self.assertRaisesRegex(PermissionError, "blocked after wait"):
                asyncio.run(tasks._grabowski_task_reconcile_refresh_tool())

        capability.assert_called_once_with("durable_job")
        mutation.assert_called_once_with("durable_job")
        refresh.assert_not_called()

    def test_mcp_reconcile_mutations_recheck_authority_inside_process_lock(self) -> None:
        cases = (
            (
                "refresh",
                lambda: tasks._task_reconcile_refresh_after_guard(""),
                "_reconcile_tasks_refresh_locked",
            ),
            (
                "resume",
                lambda: tasks._task_reconcile_resume_after_guard("", 1, "test"),
                "reconcile_tasks_resume",
            ),
            (
                "reconcile",
                lambda: tasks._task_reconcile_after_guard(False),
                "_reconcile_tasks_locked",
            ),
        )

        for label, invoke, target_name in cases:
            with self.subTest(label=label):
                order: list[str] = []

                @contextmanager
                def process_guard():
                    order.append("lock-enter")
                    try:
                        yield
                    finally:
                        order.append("lock-exit")

                def deny_inside_lock(capability: str) -> None:
                    self.assertEqual(capability, "durable_job")
                    self.assertEqual(order, ["lock-enter"])
                    raise PermissionError("blocked inside process lock")

                with (
                    patch.object(
                        tasks,
                        "_task_mutation_lock",
                        side_effect=process_guard,
                    ),
                    patch.object(
                        tasks.operator,
                        "_require_operator_mutation",
                        side_effect=deny_inside_lock,
                    ),
                    patch.object(tasks, target_name) as mutation_target,
                    self.assertRaisesRegex(
                        PermissionError,
                        "blocked inside process lock",
                    ),
                ):
                    invoke()

                mutation_target.assert_not_called()
                self.assertEqual(order, ["lock-enter", "lock-exit"])

    def test_mcp_reconcile_refresh_rechecks_authority_after_external_lock_wait(self) -> None:
        lock_path = self.database.with_suffix(".mutation.lock")
        with tasks._task_mutation_lock():
            pass
        child = (
            "import fcntl, os, sys; "
            "fd=os.open(sys.argv[1], os.O_RDWR); "
            "fcntl.flock(fd, fcntl.LOCK_EX); "
            "print('locked', flush=True); "
            "sys.stdin.readline(); "
            "fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", child, str(lock_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        mutation_checked = threading.Event()
        completed = threading.Event()
        errors: list[BaseException] = []

        def deny_after_wait(capability: str) -> None:
            self.assertEqual(capability, "durable_job")
            mutation_checked.set()
            raise PermissionError("blocked after process wait")

        def run_tool() -> None:
            try:
                asyncio.run(tasks._grabowski_task_reconcile_refresh_tool())
            except BaseException as exc:
                errors.append(exc)
            finally:
                completed.set()

        thread = threading.Thread(target=run_tool)
        try:
            assert process.stdout is not None
            self.assertEqual(process.stdout.readline().strip(), "locked")
            with (
                patch.object(tasks.operator, "_require_operator_capability"),
                patch.object(
                    tasks.operator,
                    "_require_operator_mutation",
                    side_effect=deny_after_wait,
                ),
                patch.object(tasks, "_reconcile_tasks_refresh_locked") as refresh,
            ):
                thread.start()
                self.assertFalse(mutation_checked.wait(timeout=0.15))
                self.assertFalse(completed.is_set())
                assert process.stdin is not None
                process.stdin.write("\n")
                process.stdin.flush()
                self.assertEqual(process.wait(timeout=2), 0)
                self.assertTrue(completed.wait(timeout=2))
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
                refresh.assert_not_called()

            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], PermissionError)
            self.assertEqual(str(errors[0]), "blocked after process wait")
            self.assertTrue(mutation_checked.is_set())
        finally:
            if process.poll() is None:
                if process.stdin is not None:
                    process.stdin.write("\n")
                    process.stdin.flush()
                process.kill()
                process.wait(timeout=2)
            if thread.is_alive():
                thread.join(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()

    def test_mcp_reconcile_refresh_runs_full_mutation_guard_off_event_loop(self) -> None:
        caller_thread = threading.get_ident()
        mutation_threads: list[int] = []
        payload = {
            "mode": "refresh",
            "task_id": "",
            "scanned": 0,
            "refreshed": [],
            "released": [],
            "resumed": [],
            "blocked": [],
            "checked_at_unix": 123,
        }

        def mutation(capability: str) -> None:
            self.assertEqual(capability, "durable_job")
            mutation_threads.append(threading.get_ident())

        with (
            patch.object(tasks.operator, "_require_operator_capability"),
            patch.object(tasks.operator, "_require_operator_mutation", side_effect=mutation),
            patch.object(
                tasks, "_reconcile_tasks_refresh_locked", return_value=payload
            ),
            patch.object(tasks.base, "_append_audit"),
        ):
            result = asyncio.run(tasks._grabowski_task_reconcile_refresh_tool())

        self.assertEqual(result, payload)
        self.assertEqual(len(mutation_threads), 1)
        self.assertNotEqual(mutation_threads[0], caller_thread)

    def test_reconcile_refresh_isolates_retired_host_and_continues(self) -> None:
        retired = self._start()["task"]
        healthy = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET host='heimserver' WHERE task_id=?",
                (retired["task_id"],),
            )
            connection.commit()

        def observe(record: dict[str, object]) -> dict[str, object]:
            if record["host"] == "heimserver":
                raise ValueError("Unknown fleet host: heimserver")
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            result = tasks.reconcile_tasks_refresh()

        self.assertEqual(result["scanned"], 2)
        self.assertEqual(len(result["blocked"]), 1)
        self.assertEqual(result["blocked"][0]["task_id"], retired["task_id"])
        self.assertEqual(
            result["blocked"][0]["reason_class"],
            "host_retired_or_unregistered",
        )
        self.assertEqual([item["task_id"] for item in result["refreshed"]], [healthy["task_id"]])

    def test_bounded_reconcile_cursor_visits_large_store_incrementally(self) -> None:
        started = [self._start()["task"] for _ in range(5)]
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE tasks SET created_at_unix=100")
            connection.commit()
        expected = sorted((100, str(item["task_id"])) for item in started)
        observed: list[tuple[int, str]] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(
                (int(record["created_at_unix"]), str(record["task_id"]))
            )
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        results: list[dict[str, object]] = []
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            for _ in range(3):
                results.append(tasks.reconcile_tasks_refresh(batch_size=2))

        self.assertEqual(expected, observed)
        self.assertEqual(
            [result["batch"]["examined"] for result in results],
            [2, 2, 1],
        )
        self.assertFalse(results[0]["batch"]["cycle_completed"])
        self.assertFalse(results[1]["batch"]["cycle_completed"])
        self.assertTrue(results[2]["batch"]["cycle_completed"])
        self.assertEqual(
            [result["batch"]["cycle_phase"] for result in results],
            [tasks.TASK_RECONCILE_CYCLE_PHASE] * 3,
        )
        self.assertEqual(
            len(
                {
                    result["batch"]["cycle_high_water_sequence"]
                    for result in results
                }
            ),
            1,
        )
        self.assertIsNone(results[2]["batch"]["cursor_after"])
        with sqlite3.connect(self.database) as connection:
            stored_cursor = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks.TASK_RECONCILE_CURSOR_METADATA_KEY,),
            ).fetchone()
        self.assertIsNone(stored_cursor)

    def test_terminalization_recovery_large_backlog_is_strictly_bounded(self) -> None:
        pending = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(7)
        ]
        results: list[dict[str, object]] = []
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            for _ in range(7):
                results.append(tasks.reconcile_tasks_refresh(batch_size=2))

        recovery = [
            result["batch"]["terminalization_recovery"]
            for result in results
        ]
        self.assertEqual([1] * 7, [item["examined"] for item in recovery])
        self.assertTrue(all(item["limit"] == 1 for item in recovery))
        self.assertTrue(all(result["batch"]["examined"] <= 1 for result in results))
        self.assertTrue(
            all(result["batch"]["total_examined"] <= 2 for result in results)
        )
        self.assertTrue(
            all(result["batch"]["total_examined_limit"] == 2 for result in results)
        )
        self.assertEqual(
            {str(item["task_id"]) for item in pending},
            {
                task_id
                for item in recovery
                for task_id in item["recovered"]
            },
        )
        self.assertEqual([], [item for item in recovery if item["failed"]])
        self.assertTrue(recovery[-1]["cycle_completed"])

    def test_reconcile_refresh_reserves_stale_active_before_terminal_history(self) -> None:
        terminal_ids: list[str] = []
        for index in range(100):
            started = self._start()
            task_id = str(started["task"]["task_id"])
            tasks._set_state(
                task_id,
                "failed",
                observation={
                    "state": "failed",
                    "properties": {"ActiveState": "failed"},
                    "probe": _launcher(),
                    "observer": {"kind": "test"},
                    "observed_at_unix": 100 + index,
                },
            )
            terminal_ids.append(task_id)

        active = self._start()
        active_id = str(active["task"]["task_id"])
        now = tasks._now()
        with sqlite3.connect(self.database) as connection:
            connection.executemany(
                "UPDATE tasks SET created_at_unix=? WHERE task_id=?",
                [(index + 1, task_id) for index, task_id in enumerate(terminal_ids)],
            )
            connection.execute(
                "UPDATE tasks SET created_at_unix=?, updated_at_unix=?, runtime_seconds=? "
                "WHERE task_id=?",
                (now - 300, now - 300, 3600, active_id),
            )
            connection.commit()

        observed: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {
                "state": "completed",
                "properties": {
                    "LoadState": "not-found",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "Result": "success",
                },
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": now,
            }

        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            result = tasks.reconcile_tasks_refresh(
                batch_size=tasks.DEFAULT_TASK_RECONCILE_BATCH_SIZE
            )

        self.assertEqual([active_id], observed)
        self.assertEqual([active_id], [item["task_id"] for item in result["refreshed"]])
        self.assertEqual("completed", tasks._row_raw(active_id)["state"])
        batch = result["batch"]
        self.assertEqual(20, batch["active_refresh"]["limit"])
        self.assertEqual(1, batch["active_refresh"]["examined"])
        self.assertEqual(99, batch["task_examined"])
        self.assertEqual(100, batch["total_examined"])
        self.assertEqual(1, result["scanned"])

    def test_active_refresh_cursor_rotates_past_permission_denials(self) -> None:
        active_ids: list[str] = []
        now = tasks._now()
        for index in range(25):
            started = self._start()
            task_id = str(started["task"]["task_id"])
            active_ids.append(task_id)
            with sqlite3.connect(self.database) as connection:
                connection.execute(
                    "UPDATE tasks SET created_at_unix=?, updated_at_unix=?, runtime_seconds=? "
                    "WHERE task_id=?",
                    (now - 500 + index, now - 300, 3600, task_id),
                )
                connection.commit()

        with (
            patch.object(tasks, "_select_reconcile_task_rows", return_value=[]),
            patch.object(
                tasks,
                "_reconcile_observation",
                side_effect=PermissionError("test observer denied"),
            ),
        ):
            first = tasks.reconcile_tasks_refresh(batch_size=100)
            second = tasks.reconcile_tasks_refresh(batch_size=100)

        first_ids = [item["task_id"] for item in first["blocked"]]
        second_ids = [item["task_id"] for item in second["blocked"]]
        self.assertEqual(20, first["batch"]["active_refresh"]["examined"])
        self.assertEqual(20, first["batch"]["active_refresh"]["selected"])
        self.assertIsNotNone(first["batch"]["active_refresh"]["cursor_after"])
        self.assertFalse(first["batch"]["active_refresh"]["cycle_completed"])
        self.assertEqual(5, second["batch"]["active_refresh"]["examined"])
        self.assertEqual(5, second["batch"]["active_refresh"]["selected"])
        self.assertIsNone(second["batch"]["active_refresh"]["cursor_after"])
        self.assertTrue(second["batch"]["active_refresh"]["cycle_completed"])
        self.assertEqual(set(active_ids), set(first_ids) | set(second_ids))
        self.assertTrue(set(first_ids).isdisjoint(second_ids))

        for task_id in active_ids:
            record = tasks._row_raw(task_id)
            self.assertEqual("running", record["state"])
            self.assertEqual(now - 300, record["updated_at_unix"])

    def test_reconcile_shared_budget_bounds_simultaneous_full_backlogs(self) -> None:
        for index in range(4):
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
        for _ in range(4):
            self._start()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=4)
        batch = result["batch"]
        self.assertEqual(2, batch["terminalization_recovery"]["examined"])
        self.assertEqual(2, batch["task_examined"])
        self.assertEqual(batch["examined"], batch["task_examined"])
        self.assertEqual(4, batch["total_examined"])
        self.assertEqual(4, batch["total_examined_limit"])

    def test_reconcile_shared_budget_uses_full_terminalization_only_capacity(self) -> None:
        pending = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(6)
        ]
        with sqlite3.connect(self.database) as connection:
            connection.executemany(
                "UPDATE tasks SET state='completed' WHERE task_id=?",
                [(item["task_id"],) for item in pending],
            )
            connection.commit()
        with patch.object(tasks, "_reconcile_observation") as observe:
            result = tasks.reconcile_tasks_refresh(batch_size=4)
        observe.assert_not_called()
        batch = result["batch"]
        self.assertEqual(4, batch["terminalization_recovery"]["examined"])
        self.assertEqual(0, batch["task_examined"])
        self.assertEqual(4, batch["total_examined"])

    def test_reconcile_shared_budget_uses_full_task_only_capacity(self) -> None:
        for _ in range(6):
            self._start()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=4)
        batch = result["batch"]
        self.assertEqual(0, batch["terminalization_recovery"]["examined"])
        self.assertEqual(4, batch["task_examined"])
        self.assertEqual(4, batch["total_examined"])

    def test_reconcile_shared_budget_assigns_partial_remaining_capacity(self) -> None:
        pending = self._prepare_pending_terminalization(prepared_at_unix=100)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET state='completed' WHERE task_id=?",
                (pending["task_id"],),
            )
            connection.commit()
        for _ in range(6):
            self._start()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=4)
        batch = result["batch"]
        self.assertEqual(1, batch["terminalization_recovery"]["examined"])
        self.assertEqual(3, batch["task_examined"])
        self.assertEqual(3, batch["task_limit"])
        self.assertEqual(4, batch["total_examined"])

    def test_reconcile_shared_budget_isolates_poison_first_terminalization(self) -> None:
        pending = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(3)
        ]
        poison_id = str(pending[0]["task_id"])
        original_apply = tasks._apply_terminalization_projection

        def apply(terminalization: dict[str, object], *, recovered: bool = False):
            if terminalization["task_id"] == poison_id:
                raise RuntimeError("poison terminalization")
            return original_apply(terminalization, recovered=recovered)

        for _ in range(4):
            self._start()
        with (
            patch.object(
                tasks,
                "_apply_terminalization_projection",
                side_effect=apply,
            ),
            patch.object(
                tasks,
                "_reconcile_observation",
                return_value={
                    "state": "running",
                    "properties": {"ActiveState": "active"},
                    "probe": _launcher(),
                    "observer": {"kind": "test"},
                    "observed_at_unix": 123,
                },
            ),
        ):
            result = tasks.reconcile_tasks_refresh(batch_size=4)
        batch = result["batch"]
        recovery = batch["terminalization_recovery"]
        self.assertEqual(poison_id, recovery["failed"][0]["task_id"])
        self.assertEqual(1, len(recovery["recovered"]))
        self.assertEqual(4, batch["total_examined"])
        self.assertEqual(4, batch["total_examined_limit"])

    def test_reconcile_batch_one_rotates_fairly_between_full_phases(self) -> None:
        for index in range(2):
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
        for _ in range(2):
            self._start()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            first = tasks.reconcile_tasks_refresh(batch_size=1)
            second = tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertEqual(
            [
                tasks.TASK_RECONCILE_PHASE_TERMINALIZATION,
                tasks.TASK_RECONCILE_PHASE_TASKS,
            ],
            [first["batch"]["phase_first"], second["batch"]["phase_first"]],
        )
        self.assertEqual(
            [1, 0],
            [
                first["batch"]["terminalization_recovery"]["examined"],
                second["batch"]["terminalization_recovery"]["examined"],
            ],
        )
        self.assertEqual(
            [0, 1],
            [first["batch"]["task_examined"], second["batch"]["task_examined"]],
        )
        self.assertEqual(
            [1, 1],
            [
                first["batch"]["total_examined"],
                second["batch"]["total_examined"],
            ],
        )

    def test_default_systemd_batch_size_is_exact_shared_maximum(self) -> None:
        for index in range(51):
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
        for _ in range(51):
            self._start()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ):
            result = tasks.reconcile_tasks_refresh(
                batch_size=tasks.DEFAULT_TASK_RECONCILE_BATCH_SIZE
            )
        batch = result["batch"]
        self.assertEqual(50, batch["terminalization_recovery"]["examined"])
        self.assertEqual(50, batch["task_examined"])
        self.assertEqual(100, batch["total_examined"])
        self.assertEqual(100, batch["total_examined_limit"])

    def test_poison_terminalization_does_not_starve_later_rows_or_task_scan(self) -> None:
        pending = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(3)
        ]
        poison_id = str(pending[0]["task_id"])
        later_ids = {str(item["task_id"]) for item in pending[1:]}
        original_apply = tasks._apply_terminalization_projection

        def apply(terminalization: dict[str, object], *, recovered: bool = False):
            if terminalization["task_id"] == poison_id:
                raise RuntimeError("poison terminalization")
            return original_apply(terminalization, recovered=recovered)

        task_observations: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            task_observations.append(str(record["task_id"]))
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        results: list[dict[str, object]] = []
        with (
            patch.object(
                tasks,
                "_apply_terminalization_projection",
                side_effect=apply,
            ),
            patch.object(tasks, "_reconcile_observation", side_effect=observe),
        ):
            for _ in range(6):
                results.append(tasks.reconcile_tasks_refresh(batch_size=1))

        recovery = [
            result["batch"]["terminalization_recovery"]
            for result in results
        ]
        self.assertEqual(poison_id, recovery[0]["failed"][0]["task_id"])
        self.assertEqual(
            later_ids,
            {
                task_id
                for item in recovery
                for task_id in item["recovered"]
            },
        )
        self.assertTrue(
            all(result["batch"]["total_examined"] == 1 for result in results)
        )
        self.assertTrue(
            any(result["batch"]["task_examined"] == 1 for result in results)
        )
        self.assertTrue(
            any(result["batch"]["cursor_after"] is not None for result in results)
        )
        self.assertEqual(
            "leases_revoked",
            resources.task_terminalization_record(poison_id)["phase"],
        )
        for task_id in later_ids:
            self.assertEqual(
                "projected",
                resources.task_terminalization_record(task_id)["phase"],
            )

    def test_terminalization_recovery_defers_insertions_and_survives_deletion(self) -> None:
        observation_patcher = patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        )
        observation_patcher.start()
        self.addCleanup(observation_patcher.stop)
        initial = [
            self._prepare_pending_terminalization(prepared_at_unix=100)
            for _ in range(3)
        ]
        first = tasks.reconcile_tasks_refresh(batch_size=1)
        first_recovery = first["batch"]["terminalization_recovery"]
        recovered_first = set(first_recovery["recovered"])
        remaining = [
            str(item["task_id"])
            for item in initial
            if str(item["task_id"]) not in recovered_first
        ]
        with sqlite3.connect(self.resource_database) as connection:
            connection.execute(
                "DELETE FROM task_terminalizations WHERE task_id=?",
                (remaining[0],),
            )
            connection.commit()
        behind = self._prepare_pending_terminalization(prepared_at_unix=99)
        ahead = self._prepare_pending_terminalization(prepared_at_unix=101)

        cycle = [first]
        while not cycle[-1]["batch"]["terminalization_recovery"][
            "cycle_completed"
        ]:
            cycle.append(tasks.reconcile_tasks_refresh(batch_size=1))
        cycle_recovered = {
            task_id
            for result in cycle
            for task_id in result["batch"]["terminalization_recovery"][
                "recovered"
            ]
        }
        self.assertNotIn(str(behind["task_id"]), cycle_recovered)
        self.assertNotIn(str(ahead["task_id"]), cycle_recovered)
        self.assertEqual(
            {tuple(first_recovery["cycle_high_water"])},
            {
                tuple(
                    result["batch"]["terminalization_recovery"][
                        "cycle_high_water"
                    ]
                )
                for result in cycle
            },
        )

        next_cycle: list[dict[str, object]] = []
        for _ in range(4):
            result = tasks.reconcile_tasks_refresh(batch_size=1)
            next_cycle.append(result)
            if result["batch"]["terminalization_recovery"]["cycle_completed"]:
                break
        self.assertEqual(
            {str(behind["task_id"]), str(ahead["task_id"])},
            {
                task_id
                for result in next_cycle
                for task_id in result["batch"]["terminalization_recovery"][
                    "recovered"
                ]
            },
        )
        self.assertTrue(
            next_cycle[-1]["batch"]["terminalization_recovery"][
                "cycle_completed"
            ]
        )

    def test_terminalization_recovery_cycle_completes_under_sustained_arrivals(self) -> None:
        initial = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(3)
        ]
        results: list[dict[str, object]] = []
        arrivals: list[dict[str, object]] = []
        for index in range(6):
            result = tasks.reconcile_tasks_refresh(batch_size=1)
            results.append(result)
            arrivals.append(
                self._prepare_pending_terminalization(
                    prepared_at_unix=1_000 + index
                )
            )
            if result["batch"]["terminalization_recovery"]["cycle_completed"]:
                break
        recovery = [
            result["batch"]["terminalization_recovery"]
            for result in results
        ]
        self.assertTrue(recovery[-1]["cycle_completed"])
        self.assertEqual(
            {tuple(recovery[0]["cycle_high_water"])},
            {tuple(item["cycle_high_water"]) for item in recovery},
        )
        self.assertEqual(
            {str(item["task_id"]) for item in initial},
            {
                task_id
                for item in recovery
                for task_id in item["recovered"]
            },
        )
        self.assertTrue(
            all(
                resources.task_terminalization_record(str(item["task_id"]))[
                    "phase"
                ]
                == "leases_revoked"
                for item in arrivals
            )
        )

    def test_terminalization_recovery_crash_before_cursor_save_replays_from_truth(self) -> None:
        pending = [
            self._prepare_pending_terminalization(prepared_at_unix=100 + index)
            for index in range(2)
        ]
        with (
            patch.object(
                tasks,
                "_save_terminalization_recovery_cycle",
                side_effect=RuntimeError("simulated terminal cursor crash"),
            ),
            self.assertRaisesRegex(RuntimeError, "terminal cursor crash"),
        ):
            tasks.reconcile_tasks_refresh(batch_size=1)
        phases = {
            str(item["task_id"]): resources.task_terminalization_record(
                str(item["task_id"])
            )["phase"]
            for item in pending
        }
        self.assertEqual(1, list(phases.values()).count("projected"))
        self.assertEqual(1, list(phases.values()).count("leases_revoked"))

        replay = tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertEqual(
            1,
            len(
                replay["batch"]["terminalization_recovery"]["recovered"]
            ),
        )
        self.assertTrue(
            replay["batch"]["terminalization_recovery"]["cycle_completed"]
        )
        self.assertTrue(
            all(
                resources.task_terminalization_record(str(item["task_id"]))[
                    "phase"
                ]
                == "projected"
                for item in pending
            )
        )

    def test_terminalization_recovery_output_contract_is_deterministic(self) -> None:
        self._prepare_pending_terminalization(prepared_at_unix=100)
        result = tasks.reconcile_tasks_refresh(batch_size=1)
        recovery = result["batch"]["terminalization_recovery"]
        self.assertEqual(
            [
                "cursor_after",
                "cursor_before",
                "cycle_completed",
                "cycle_high_water",
                "examined",
                "failed",
                "limit",
                "recovered",
            ],
            sorted(recovery),
        )
        self.assertEqual(1, recovery["limit"])
        self.assertEqual(1, recovery["examined"])
        self.assertEqual([], recovery["failed"])

    def test_bounded_reconcile_defers_insertions_behind_and_ahead_of_cursor(self) -> None:
        initial = [self._start()["task"] for _ in range(4)]
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE tasks SET created_at_unix=100")
            connection.commit()
        observed: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            first = tasks.reconcile_tasks_refresh(batch_size=2)
            behind = self._start()["task"]
            ahead = self._start()["task"]
            with sqlite3.connect(self.database) as connection:
                connection.execute(
                    "UPDATE tasks SET created_at_unix=99 WHERE task_id=?",
                    (behind["task_id"],),
                )
                connection.execute(
                    "UPDATE tasks SET created_at_unix=101 WHERE task_id=?",
                    (ahead["task_id"],),
                )
                connection.commit()
            second = tasks.reconcile_tasks_refresh(batch_size=2)

        initial_ids = {str(item["task_id"]) for item in initial}
        self.assertEqual(set(observed), initial_ids)
        self.assertFalse(first["batch"]["cycle_completed"])
        self.assertTrue(second["batch"]["cycle_completed"])
        self.assertEqual(
            first["batch"]["cycle_high_water_sequence"],
            second["batch"]["cycle_high_water_sequence"],
        )
        self.assertNotIn(str(behind["task_id"]), observed)
        self.assertNotIn(str(ahead["task_id"]), observed)

        observed.clear()
        results: list[dict[str, object]] = []
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            for _ in range(3):
                results.append(tasks.reconcile_tasks_refresh(batch_size=2))
        self.assertTrue(results[-1]["batch"]["cycle_completed"])
        self.assertIn(str(behind["task_id"]), observed)
        self.assertIn(str(ahead["task_id"]), observed)

    def test_bounded_reconcile_replays_before_cursor_save_and_advances_after(self) -> None:
        started = [self._start()["task"] for _ in range(3)]
        expected = [
            str(item["task_id"])
            for item in sorted(
                started,
                key=lambda item: (
                    int(item["created_at_unix"]),
                    str(item["task_id"]),
                ),
            )
        ]
        observed: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        with (
            patch.object(tasks, "_reconcile_observation", side_effect=observe),
            patch.object(
                tasks,
                "_save_reconcile_cycle",
                side_effect=RuntimeError("simulated crash before cursor save"),
            ),
            self.assertRaisesRegex(RuntimeError, "simulated crash"),
        ):
            tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertEqual([expected[0]], observed)

        observed.clear()
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            first_saved = tasks.reconcile_tasks_refresh(batch_size=1)
            second_saved = tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertEqual(expected[:2], observed)
        self.assertEqual(first_saved["batch"]["cursor_before"], None)
        self.assertEqual(
            second_saved["batch"]["cursor_before"],
            first_saved["batch"]["cursor_after"],
        )

    def test_bounded_reconcile_completion_is_truthful_after_deletion(self) -> None:
        started = [self._start()["task"] for _ in range(3)]
        observed: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            first = tasks.reconcile_tasks_refresh(batch_size=1)
        remaining = {
            str(item["task_id"]) for item in started
        } - set(observed)
        with sqlite3.connect(self.database) as connection:
            connection.executemany(
                "DELETE FROM tasks WHERE task_id=?",
                [(task_id,) for task_id in remaining],
            )
            connection.commit()
        replacement = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET created_at_unix=0 WHERE task_id=?",
                (replacement["task_id"],),
            )
            connection.commit()
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            completed = tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertFalse(first["batch"]["cycle_completed"])
        self.assertTrue(completed["batch"]["cycle_completed"])
        self.assertEqual(0, completed["batch"]["examined"])
        self.assertIsNone(completed["batch"]["cursor_after"])
        self.assertNotIn(str(replacement["task_id"]), observed)

        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            tasks.reconcile_tasks_refresh(batch_size=1)
        self.assertEqual(str(replacement["task_id"]), observed[-1])

    def test_bounded_reconcile_cycle_completes_under_sustained_tail_arrivals(self) -> None:
        initial = [self._start()["task"] for _ in range(3)]
        observed: list[str] = []

        def observe(record: dict[str, object]) -> dict[str, object]:
            observed.append(str(record["task_id"]))
            return {
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            }

        arrivals: list[dict[str, object]] = []
        first_cycle: list[dict[str, object]] = []
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            for index in range(3):
                first_cycle.append(
                    tasks.reconcile_tasks_refresh(batch_size=1)
                )
                arrival = self._start()["task"]
                arrivals.append(arrival)
                with sqlite3.connect(self.database) as connection:
                    connection.execute(
                        "UPDATE tasks SET created_at_unix=? WHERE task_id=?",
                        (1_000 + index, arrival["task_id"]),
                    )
                    connection.commit()

        self.assertTrue(first_cycle[-1]["batch"]["cycle_completed"])
        self.assertEqual(
            {
                result["batch"]["cycle_high_water_sequence"]
                for result in first_cycle
            },
            {first_cycle[0]["batch"]["cycle_high_water_sequence"]},
        )
        self.assertEqual(
            set(observed), {str(item["task_id"]) for item in initial}
        )

        observed.clear()
        second_cycle: list[dict[str, object]] = []
        with patch.object(tasks, "_reconcile_observation", side_effect=observe):
            for index in range(6):
                second_cycle.append(
                    tasks.reconcile_tasks_refresh(batch_size=1)
                )
                arrival = self._start()["task"]
                with sqlite3.connect(self.database) as connection:
                    connection.execute(
                        "UPDATE tasks SET created_at_unix=? WHERE task_id=?",
                        (2_000 + index, arrival["task_id"]),
                    )
                    connection.commit()

        self.assertTrue(second_cycle[-1]["batch"]["cycle_completed"])
        self.assertEqual(
            {
                result["batch"]["cycle_high_water_sequence"]
                for result in second_cycle
            },
            {second_cycle[0]["batch"]["cycle_high_water_sequence"]},
        )
        self.assertTrue(
            {str(item["task_id"]) for item in arrivals}.issubset(observed)
        )

    def test_bounded_reconcile_migrates_legacy_cursor_by_replaying_safely(self) -> None:
        started = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                (
                    tasks.TASK_RECONCILE_CURSOR_METADATA_KEY,
                    tasks._canonical_json(
                        {
                            "created_at_unix": int(started["created_at_unix"]),
                            "task_id": str(started["task_id"]),
                        }
                    ),
                ),
            )
            connection.commit()
        with patch.object(
            tasks,
            "_reconcile_observation",
            return_value={
                "state": "running",
                "properties": {"ActiveState": "active"},
                "probe": _launcher(),
                "observer": {"kind": "test"},
                "observed_at_unix": 123,
            },
        ) as observe:
            result = tasks.reconcile_tasks_refresh(batch_size=1)
        observe.assert_called_once()
        self.assertIsNone(result["batch"]["cursor_before"])
        self.assertTrue(result["batch"]["cycle_completed"])

    def test_bounded_reconcile_rejects_malformed_cursor_without_observation(self) -> None:
        started = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                (tasks.TASK_RECONCILE_CURSOR_METADATA_KEY, '{"task_id":"bad"}'),
            )
            connection.commit()
        with (
            patch.object(tasks, "_reconcile_observation") as observe,
            self.assertRaisesRegex(
                RuntimeError,
                "Task reconcile cursor metadata is invalid",
            ),
        ):
            tasks.reconcile_tasks_refresh(batch_size=2)
        observe.assert_not_called()
        self.assertEqual(
            "running",
            tasks._row_raw(str(started["task_id"]))["state"],
        )

    def test_reconcile_rejects_terminalization_cursor_after_high_water_without_deletion(self) -> None:
        started = self._start()["task"]
        stored = self._store_terminalization_recovery_cycle(
            high_water=(100, "a" * 24),
            cursor=(100, "b" * 24),
        )
        with (
            patch.object(
                resources,
                "pending_task_terminalizations",
            ) as pending,
            patch.object(tasks, "_reconcile_observation") as observe,
            self.assertRaisesRegex(
                RuntimeError,
                "terminalization recovery cursor metadata is inconsistent",
            ),
        ):
            tasks.reconcile_tasks_refresh(batch_size=1)
        pending.assert_not_called()
        observe.assert_not_called()
        with sqlite3.connect(self.database) as connection:
            current = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
            ).fetchone()
        self.assertEqual((stored,), current)
        self.assertEqual(
            "running",
            tasks._row_raw(str(started["task_id"]))["state"],
        )

    def test_reconcile_rejects_contradictory_terminalization_page_without_deletion(self) -> None:
        stored = self._store_terminalization_recovery_cycle(
            high_water=(100, "b" * 24),
            cursor=(100, "a" * 24),
        )
        contradictory_page = {
            "terminalizations": [],
            "limit": 1,
            "examined": 0,
            "cursor_before": (100, "a" * 24),
            "cursor_after": (100, "c" * 24),
            "high_water": (100, "b" * 24),
            "cycle_completed": False,
        }
        with (
            patch.object(
                resources,
                "pending_task_terminalizations_exist",
                return_value=True,
            ),
            patch.object(
                resources,
                "pending_task_terminalizations",
                return_value=contradictory_page,
            ),
            patch.object(tasks, "_apply_terminalization_projection") as apply,
            patch.object(tasks, "_reconcile_observation") as observe,
            self.assertRaisesRegex(
                RuntimeError,
                "terminalization recovery page is inconsistent",
            ),
        ):
            tasks.reconcile_tasks_refresh(batch_size=1)
        apply.assert_not_called()
        observe.assert_not_called()
        with sqlite3.connect(self.database) as connection:
            current = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
            ).fetchone()
        self.assertEqual((stored,), current)

    def test_reconcile_accepts_terminalization_cursor_equal_to_high_water(self) -> None:
        boundary = (100, "a" * 24)
        self._store_terminalization_recovery_cycle(
            high_water=boundary,
            cursor=boundary,
        )
        result = tasks.reconcile_tasks_refresh(batch_size=1)
        recovery = result["batch"]["terminalization_recovery"]
        self.assertEqual(0, recovery["examined"])
        self.assertTrue(recovery["cycle_completed"])
        with sqlite3.connect(self.database) as connection:
            stored = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
            ).fetchone()
        self.assertIsNone(stored)

    def test_terminalization_recovery_deleted_high_water_completes_cycle(self) -> None:
        self._prepare_pending_terminalization(prepared_at_unix=100)
        high_water = self._prepare_pending_terminalization(prepared_at_unix=101)
        first = tasks._recover_pending_task_terminalizations(limit=1)
        self.assertFalse(first["cycle_completed"])
        with sqlite3.connect(self.resource_database) as connection:
            connection.execute(
                "DELETE FROM task_terminalizations WHERE task_id=?",
                (high_water["task_id"],),
            )
            connection.commit()
        completed = tasks._recover_pending_task_terminalizations(limit=1)
        self.assertEqual(0, completed["examined"])
        self.assertTrue(completed["cycle_completed"])
        with sqlite3.connect(self.database) as connection:
            stored = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,),
            ).fetchone()
        self.assertIsNone(stored)

    def test_reconcile_rejects_malformed_terminalization_cursor_before_reads(self) -> None:
        started = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES(?, ?)",
                (
                    tasks.TASK_TERMINALIZATION_RECOVERY_CURSOR_METADATA_KEY,
                    '{"version":1,"high_water":{},"cursor":{}}',
                ),
            )
            connection.commit()
        with (
            patch.object(
                resources,
                "pending_task_terminalizations",
            ) as pending,
            patch.object(tasks, "_reconcile_observation") as observe,
            self.assertRaisesRegex(
                RuntimeError,
                "terminalization recovery cursor metadata is invalid",
            ),
        ):
            tasks.reconcile_tasks_refresh(batch_size=1)
        pending.assert_not_called()
        observe.assert_not_called()
        self.assertEqual(
            "running",
            tasks._row_raw(str(started["task_id"]))["state"],
        )

    def test_reconcile_resume_keeps_converged_retry_safe_failure_eligible(self) -> None:
        started = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET resume_policy='retry-safe' WHERE task_id=?",
                (started["task_id"],),
            )
            connection.commit()
        tasks._set_state(
            started["task_id"],
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        successor = {"task_id": "f" * 24, "state": "running"}
        with patch.object(
            tasks,
            "_terminal_retry_successor",
            return_value=successor,
        ) as retry:
            result = tasks.reconcile_tasks_resume(
                task_id=started["task_id"],
                max_resumes=1,
                reason="bounded retry proof",
            )
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["resumed"], [successor])
        self.assertEqual(result["blocked"], [])
        retry.assert_called_once()

    def test_reconcile_retired_host_terminal_without_evidence_stays_blocked(self) -> None:
        retired = self._start()["task"]
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tasks SET host='heimserver', state='failed' WHERE task_id=?",
                (retired["task_id"],),
            )
            connection.commit()

        with patch.object(
            tasks,
            "_reconcile_observation",
            side_effect=ValueError("Unknown fleet host: heimserver"),
        ):
            result = tasks.reconcile_tasks_refresh()

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["refreshed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], retired["task_id"])
        self.assertTrue(result["blocked"][0]["owner_decision_required"])
        self.assertTrue(result["blocked"][0]["terminal_evidence_required"])

    def test_reconcile_skips_fully_converged_terminal_tasks(self) -> None:
        started = self._start()["task"]
        tasks._set_state(
            started["task_id"],
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with patch.object(tasks, "_reconcile_observation") as observe:
            result = tasks.reconcile_tasks_check()
        self.assertEqual(result["scanned"], 0)
        observe.assert_not_called()

    def test_reconcile_resume_requires_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "reason is required"):
            tasks.reconcile_tasks_resume()

    def test_reconcile_cli_check_mode_is_read_only(self) -> None:
        preview = {"mode": "check", "scanned": 0}
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_check",
                return_value=preview,
            ) as check,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_refresh"
            ) as refresh,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_resume"
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print") as output,
        ):
            self.assertEqual(task_reconcile_cli.main(["--mode", "check"]), 0)
        check.assert_called_once_with(task_id="")
        refresh.assert_not_called()
        resume.assert_not_called()
        audit.assert_not_called()
        self.assertIn('"mode": "check"', output.call_args.args[0])

    def test_reconcile_cli_refresh_does_not_resume_processes(self) -> None:
        task_id = "a" * 24
        refreshed = {"mode": "refresh", "scanned": 0}
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_refresh",
                return_value=refreshed,
            ) as refresh,
            patch.object(
                task_reconcile_cli.grabowski_tasks, "reconcile_tasks_resume"
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print"),
        ):
            self.assertEqual(
                task_reconcile_cli.main(["--mode", "refresh", "--task-id", task_id]),
                0,
            )
        refresh.assert_called_once_with(task_id=task_id)
        resume.assert_not_called()
        audit.assert_not_called()

    def test_reconcile_cli_refresh_defaults_to_bounded_cursor_mode(self) -> None:
        refreshed = {"mode": "refresh", "scanned": 0}
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_refresh",
                return_value=refreshed,
            ) as refresh,
            patch("builtins.print"),
        ):
            self.assertEqual(
                task_reconcile_cli.main(["--mode", "refresh"]),
                0,
            )
        refresh.assert_called_once_with(
            batch_size=task_reconcile_cli.DEFAULT_REFRESH_BATCH_SIZE
        )
        self.assertEqual(100, task_reconcile_cli.DEFAULT_REFRESH_BATCH_SIZE)
        self.assertIn(
            "in total across terminalization recovery and task scanning",
            " ".join(task_reconcile_cli.parser().format_help().split()),
        )

    def test_reconcile_cli_resume_requires_reason(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main(["--mode", "resume"])
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_resume_bounds_max_resumes(self) -> None:
        for value in ("0", "51"):
            with self.subTest(value=value):
                with patch("sys.stderr", new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as raised:
                        task_reconcile_cli.main(
                            [
                                "--mode",
                                "resume",
                                "--reason",
                                "bounded test",
                                "--max-resumes",
                                value,
                            ]
                        )
                self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_rejects_legacy_auto_resume(self) -> None:
        legacy = "--auto-" + "resume"
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main([legacy])
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_rejects_unsupported_expected_state_hash(self) -> None:
        with patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                task_reconcile_cli.main(
                    [
                        "--mode",
                        "resume",
                        "--reason",
                        "precondition test",
                        "--expected-state-hash",
                        "a" * 64,
                    ]
                )
        self.assertEqual(raised.exception.code, 2)

    def test_reconcile_cli_resume_is_explicit_bounded_and_audited(self) -> None:
        result = {
            "mode": "resume",
            "task_id": "",
            "max_resumes": 2,
            "reason": "operator proof",
            "scanned": 2,
            "refreshed": [],
            "released": [],
            "resumed": [{"task_id": "a" * 24}],
            "blocked": [{"task_id": "b" * 24}],
            "checked_at_unix": 1234,
        }
        with (
            patch.object(
                task_reconcile_cli.grabowski_tasks,
                "reconcile_tasks_resume",
                return_value=result,
            ) as resume,
            patch.object(
                task_reconcile_cli.grabowski_tasks.base, "_append_audit"
            ) as audit,
            patch("builtins.print"),
        ):
            self.assertEqual(
                task_reconcile_cli.main(
                    [
                        "--mode",
                        "resume",
                        "--reason",
                        "operator proof",
                        "--max-resumes",
                        "2",
                    ]
                ),
                0,
            )
        resume.assert_called_once_with(
            task_id="", max_resumes=2, reason="operator proof"
        )
        audit.assert_called_once()
        audit_record = audit.call_args.args[0]
        self.assertEqual(audit_record["mode"], "resume")
        self.assertEqual(audit_record["reason"], "operator proof")
        self.assertEqual(audit_record["max_resumes"], 2)
        self.assertEqual(audit_record["resumed_count"], 1)
        self.assertEqual(audit_record["blocked_count"], 1)

    def test_reconcile_does_not_resume_completed_tasks(self) -> None:
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST), patch.object(
            tasks, "_dispatch", return_value=_launcher()
        ), patch.object(tasks.base, "_append_audit"), patch.object(
            tasks, "_require_recovery_gate", return_value={"checked_at_unix": 142}
        ):
            started = tasks.grabowski_task_start(
                "local",
                ["/bin/true"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
            )
        completed = _launcher()
        completed["stdout"] = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
            "Result=success\nExecMainCode=0\nExecMainStatus=0\n"
        )
        with patch.object(tasks, "_dispatch", return_value=completed):
            result = tasks.reconcile_tasks_resume(
                reason="test completed no-resume", max_resumes=1
            )
        self.assertEqual(result["resumed"], [])
        self.assertEqual(result["blocked"][0]["task_id"], started["task"]["task_id"])
        self.assertIn("completed", result["blocked"][0]["reason"])

    def _task_migration_backups(self) -> list[Path]:
        return sorted(
            self.database.parent.glob(
                f"{self.database.name}.schema-*.backup"
            )
        )

    def _create_task_schema_version(
        self,
        version: str,
    ) -> tuple[str, dict[str, object]]:
        keep_by_version = {
            "1": tasks.TASK_SCHEMA_V1_COLUMNS,
            "2": tasks.TASK_SCHEMA_V2_COLUMNS,
            "3": tasks.TASK_SCHEMA_V3_COLUMNS,
            "4": tasks.TASK_SCHEMA_V4_COLUMNS,
        }
        keep = keep_by_version[version]
        task_id = version * 24
        unit = f"grabowski-task-{task_id}-a7.service"
        values: dict[str, object] = {
            "task_id": task_id,
            "host": "local",
            "unit": unit,
            "attempt": 7,
            "state": "outcome_unknown",
            "resume_policy": "manual",
            "argv_json": '["/bin/true", "schema"]',
            "argv_sha256": "a" * 64,
            "cwd": str(self.root),
            "runtime_seconds": 91,
            "cpu_weight": 321,
            "io_weight": 654,
            "memory_max_bytes": 123456,
            "created_at_unix": 11,
            "updated_at_unix": 22,
            "launcher_json": '{"returncode":0}',
            "last_observation_json": '{"state":"outcome_unknown"}',
            "resource_keys_json": '["component:schema-migration"]',
            "lease_owner_id": f"task:{task_id}",
            "request_id": "request-schema",
            "origin_ref": "origin-schema",
            "external_run_id": "external-schema",
            "execution_envelope_sha256": "b" * 64,
            "acceptance_json": '[{"criterion":"preserve"}]',
            "request_sha256": "c" * 64,
            "execution_backend": "systemd-root-broker",
            "systemd_scope": "system",
            "authoritative_unit": unit,
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": "/tmp/chronik",
            "chronik_context_json": '{"operation":"migration"}',
            "terminalization_sha256": "d" * 64,
            "terminalized_at_unix": 33,
            "lifecycle_receipt_sha256": "e" * 64,
            "repository_scope_manifest_json": '{"schema_version":1}',
        }
        with tasks._database():
            pass
        with closing(sqlite3.connect(self.database)) as connection:
            columns = [
                str(row[1])
                for row in connection.execute("PRAGMA table_info(tasks)")
            ]
            connection.execute(
                "INSERT INTO tasks(" + ", ".join(columns) + ") VALUES(" +
                ", ".join("?" for _ in columns) + ")",
                tuple(values[name] for name in columns),
            )
            for name in reversed(columns):
                if name not in keep:
                    connection.execute(f'ALTER TABLE tasks DROP COLUMN "{name}"')
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='schema_version'",
                (version,),
            )
            connection.row_factory = sqlite3.Row
            original = dict(
                connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone()
            )
            connection.commit()
        return task_id, original

    def test_schema_v1_database_migrates_without_losing_records(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO metadata(key, value) VALUES('schema_version', '1');
            CREATE TABLE tasks (
                task_id TEXT PRIMARY KEY, host TEXT NOT NULL, unit TEXT NOT NULL,
                attempt INTEGER NOT NULL, state TEXT NOT NULL, resume_policy TEXT NOT NULL,
                argv_json TEXT NOT NULL, argv_sha256 TEXT NOT NULL, cwd TEXT NOT NULL,
                runtime_seconds INTEGER NOT NULL, cpu_weight INTEGER NOT NULL,
                io_weight INTEGER NOT NULL, memory_max_bytes INTEGER,
                created_at_unix INTEGER NOT NULL, updated_at_unix INTEGER NOT NULL,
                launcher_json TEXT NOT NULL, last_observation_json TEXT
            );
            """
        )
        connection.execute(
            "INSERT INTO tasks VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "a" * 24, "local", f"grabowski-task-{'a' * 24}-a1.service",
                1, "interrupted", "manual", '["/bin/true"]', "b" * 64,
                str(self.root), 60, 100, 100, None, 1, 1, '{}', None,
            ),
        )
        connection.commit()
        connection.close()
        listed = tasks.grabowski_task_list()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["tasks"][0]["resource_keys"], [])
        self.assertEqual(listed["tasks"][0]["execution_backend"], "systemd-user")
        self.assertEqual(listed["tasks"][0]["systemd_scope"], "user")
        self.assertEqual(
            listed["tasks"][0]["authoritative_unit"],
            f"grabowski-task-{'a' * 24}-a1.service",
        )
        with sqlite3.connect(self.database) as migrated:
            version = migrated.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            columns = {row[1] for row in migrated.execute("PRAGMA table_info(tasks)")}
            indexes = {row[1] for row in migrated.execute("PRAGMA index_list(tasks)")}
            journal_mode = migrated.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(version, "5")
        self.assertIn("resource_keys_json", columns)
        self.assertIn("lease_owner_id", columns)
        self.assertIn("request_id", columns)
        self.assertIn("origin_ref", columns)
        self.assertIn("external_run_id", columns)
        self.assertIn("execution_envelope_sha256", columns)
        self.assertIn("acceptance_json", columns)
        self.assertIn("request_sha256", columns)
        self.assertIn("chronik_outbox_enabled", columns)
        self.assertIn("chronik_outbox_state_root", columns)
        self.assertIn("execution_backend", columns)
        self.assertIn("systemd_scope", columns)
        self.assertIn("authoritative_unit", columns)
        self.assertIn("repository_scope_manifest_json", columns)
        self.assertIn("tasks_state_created_task_idx", indexes)
        self.assertIn("tasks_created_task_idx", indexes)
        self.assertEqual(journal_mode, "wal")
        backups = self._task_migration_backups()
        self.assertEqual(1, len(backups))
        self.assertEqual(0o400, backups[0].stat().st_mode & 0o777)
        with sqlite3.connect(backups[0]) as backup:
            self.assertEqual(
                "1",
                backup.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                "ok", backup.execute("PRAGMA integrity_check").fetchone()[0]
            )
            self.assertEqual(
                "a" * 24,
                backup.execute("SELECT task_id FROM tasks").fetchone()[0],
            )
        with tasks._database() as reopened:
            self.assertEqual(
                reopened.total_changes,
                0,
                "schema-5 fast path must not repeat migration writes",
            )
        self.assertEqual(backups, self._task_migration_backups())

    def test_schema_v2_and_v3_migrations_preserve_all_existing_fields(self) -> None:
        for version in ("2", "3"):
            with self.subTest(version=version):
                database = self.root / f"state-v{version}" / "tasks.sqlite3"
                with patch.object(tasks, "TASK_DB", database):
                    previous = self.database
                    self.database = database
                    try:
                        task_id, original = self._create_task_schema_version(version)
                        listed = tasks.grabowski_task_list(limit=10)
                        self.assertTrue(
                            any(item["task_id"] == task_id for item in listed["tasks"])
                        )
                        with sqlite3.connect(database) as migrated:
                            migrated.row_factory = sqlite3.Row
                            self.assertEqual(
                                "5",
                                migrated.execute(
                                    "SELECT value FROM metadata WHERE key='schema_version'"
                                ).fetchone()[0],
                            )
                            after = dict(
                                migrated.execute(
                                    "SELECT * FROM tasks WHERE task_id=?",
                                    (task_id,),
                                ).fetchone()
                            )
                        for name, value in original.items():
                            self.assertEqual(value, after[name], name)
                        backups = self._task_migration_backups()
                        self.assertEqual(1, len(backups))
                        with sqlite3.connect(backups[0]) as backup:
                            self.assertEqual(
                                version,
                                backup.execute(
                                    "SELECT value FROM metadata WHERE key='schema_version'"
                                ).fetchone()[0],
                            )
                            self.assertEqual(
                                "ok",
                                backup.execute("PRAGMA integrity_check").fetchone()[0],
                            )
                    finally:
                        self.database = previous

    def test_task_schema_only_inventory_reports_migration_without_mutation(self) -> None:
        self._create_task_schema_version("2")
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        inventory = tasks.grabowski_task_list(schema_only=True)
        self.assertEqual("tasks", inventory["store"])
        self.assertEqual("2", inventory["observed_version"])
        self.assertEqual("5", inventory["current_version"])
        self.assertEqual(["1", "2", "3", "4", "5"], inventory["supported_versions"])
        self.assertEqual("migration_required", inventory["status"])
        self.assertTrue(inventory["migration_required"])
        self.assertFalse(inventory["write_compatible"])
        self.assertFalse(inventory["mutation_performed"])
        self.assertEqual(
            "supported_with_exclusive_migration",
            inventory["rolling_upgrade"][
                "current_runtime_supported_older_store"
            ],
        )
        self.assertEqual(
            "unsupported_require_full_runtime_drain",
            inventory["rolling_upgrade"][
                "pre_t062_runtime_overlap_with_future_schema"
            ],
        )
        self.assertEqual(
            [{
                "from": "2",
                "to": "5",
                "lock": "exclusive_store_directory",
                "transaction": "immediate",
                "verified_backup_required": True,
            }],
            inventory["migration_path"],
        )
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(before_names, sorted(item.name for item in self.database.parent.iterdir()))
        self.assertEqual([], self._task_migration_backups())
        with self.assertRaisesRegex(ValueError, "schema_only must be boolean"):
            tasks.grabowski_task_list(schema_only=1)
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            tasks.grabowski_task_list(schema_only=True, limit=1)

    def test_current_task_schema_inventory_is_byte_stable(self) -> None:
        connection = tasks._database()
        connection.close()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        original_integrity = tasks._sqlite_integrity
        with patch.object(
            tasks,
            "_sqlite_integrity",
            wraps=original_integrity,
        ) as integrity:
            connection = tasks._database()
            connection.close()
        self.assertEqual(1, integrity.call_count)
        inventory = tasks.grabowski_task_list(schema_only=True)
        self.assertEqual("5", inventory["observed_version"])
        self.assertEqual("current", inventory["status"])
        self.assertTrue(inventory["write_compatible"])
        self.assertFalse(inventory["migration_required"])
        self.assertEqual("none", inventory["required_action"])
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(before_names, sorted(item.name for item in self.database.parent.iterdir()))

    def test_task_schema_inventory_blocks_if_wal_appears_during_immutable_read(self) -> None:
        connection = tasks._database()
        connection.close()
        wal = Path(str(self.database) + "-wal")
        self.assertFalse(wal.exists())
        original = tasks._task_schema_version

        def create_wal_during_read(connection: sqlite3.Connection) -> str | None:
            version = original(connection)
            wal.write_bytes(b"concurrent-writer-marker")
            return version

        try:
            with patch.object(
                tasks,
                "_task_schema_version",
                side_effect=create_wal_during_read,
            ):
                inventory = tasks.grabowski_task_list(schema_only=True)
            self.assertEqual("blocked", inventory["status"])
            self.assertEqual("retry_schema_inventory", inventory["required_action"])
            self.assertFalse(inventory["write_compatible"])
            self.assertFalse(inventory["mutation_performed"])
            self.assertIn("changed while schema inventory", inventory["error"])
        finally:
            wal.unlink(missing_ok=True)

    def test_task_schema_inventory_reads_uncheckpointed_future_wal(self) -> None:
        connection = tasks._database()
        connection.close()
        keeper = sqlite3.connect(self.database)
        try:
            self.assertEqual("wal", keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0])
            self.assertEqual(
                0, keeper.execute("PRAGMA wal_autocheckpoint=0").fetchone()[0]
            )
            keeper.execute(
                "UPDATE metadata SET value='6' WHERE key='schema_version'"
            )
            keeper.commit()
            wal = Path(str(self.database) + "-wal")
            self.assertTrue(wal.exists())
            before_database = self.database.read_bytes()
            before_wal = wal.read_bytes()
            before_names = sorted(item.name for item in self.database.parent.iterdir())
            original_connect = sqlite3.connect
            source_uri = self.database.absolute().as_uri()

            def reject_source_sqlite_open(
                database: object,
                *args: object,
                **kwargs: object,
            ) -> sqlite3.Connection:
                database_text = str(database)
                if (
                    database_text == str(self.database)
                    or database_text.startswith(source_uri)
                ):
                    raise AssertionError(
                        "Task schema inventory must not open the source database when WAL is present"
                    )
                return original_connect(database, *args, **kwargs)

            with patch.object(
                tasks.sqlite3,
                "connect",
                side_effect=reject_source_sqlite_open,
            ):
                inventory = tasks.grabowski_task_list(schema_only=True)
            self.assertEqual("6", inventory["observed_version"])
            self.assertEqual("unsupported_future", inventory["status"])
            self.assertFalse(inventory["write_compatible"])
            self.assertFalse(inventory["mutation_performed"])
            self.assertEqual(
                "fail_closed_without_mutation",
                inventory["rolling_upgrade"][
                    "current_runtime_newer_store"
                ],
            )
            self.assertEqual(
                "unsupported_require_full_runtime_drain",
                inventory["rolling_upgrade"][
                    "pre_t062_runtime_overlap_with_future_schema"
                ],
            )
            self.assertIsNotNone(inventory["recovery_instruction"])
            self.assertEqual(before_database, self.database.read_bytes())
            self.assertEqual(before_wal, wal.read_bytes())
            self.assertEqual(
                before_names,
                sorted(item.name for item in self.database.parent.iterdir()),
            )
            self.assertEqual([], self._task_migration_backups())
        finally:
            keeper.close()

    def test_task_backup_includes_committed_uncheckpointed_wal_data(self) -> None:
        task_id, _ = self._create_task_schema_version("2")
        keeper = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                "wal",
                keeper.execute("PRAGMA journal_mode=WAL").fetchone()[0],
            )
            keeper.execute(
                "UPDATE tasks SET updated_at_unix=999 WHERE task_id=?",
                (task_id,),
            )
            keeper.commit()
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            tasks.grabowski_task_list()
            backup = self._task_migration_backups()[0]
            with sqlite3.connect(backup) as connection:
                self.assertEqual(
                    999,
                    connection.execute(
                        "SELECT updated_at_unix FROM tasks WHERE task_id=?",
                        (task_id,),
                    ).fetchone()[0],
                )
        finally:
            keeper.close()

    def test_task_backup_failure_rolls_back_without_partial_schema(self) -> None:
        task_id, original = self._create_task_schema_version("2")
        with patch.object(
            tasks.os,
            "link",
            side_effect=OSError("simulated backup publish failure"),
        ):
            with self.assertRaisesRegex(OSError, "backup publish failure"):
                tasks.grabowski_task_list()
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            self.assertEqual(
                "2",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            after = dict(
                connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (task_id,)
                ).fetchone()
            )
        self.assertEqual(original, after)
        self.assertEqual([], self._task_migration_backups())
        self.assertEqual([], list(self.database.parent.glob("*.backup.tmp")))
        tasks.grabowski_task_list()
        self.assertEqual(1, len(self._task_migration_backups()))

    def test_interrupted_task_migration_rolls_back_and_reuses_backup(self) -> None:
        task_id, original = self._create_task_schema_version("3")
        original_validator = tasks._validate_task_schema_current

        def fail_after_migration(connection: sqlite3.Connection) -> None:
            if tasks._task_schema_version(connection) == "5":
                raise RuntimeError("simulated post-migration validation failure")
            original_validator(connection)

        with patch.object(
            tasks,
            "_validate_task_schema_current",
            side_effect=fail_after_migration,
        ):
            with self.assertRaisesRegex(RuntimeError, "post-migration"):
                tasks.grabowski_task_list()
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            self.assertEqual(
                "3",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                original,
                dict(connection.execute(
                    "SELECT * FROM tasks WHERE task_id=?", (task_id,)
                ).fetchone()),
            )
        backups = self._task_migration_backups()
        self.assertEqual(1, len(backups))
        tasks.grabowski_task_list()
        self.assertEqual(backups, self._task_migration_backups())

    def test_tampered_task_backup_blocks_retry(self) -> None:
        self._create_task_schema_version("4")
        with patch.object(
            tasks,
            "_validate_task_schema_current",
            side_effect=RuntimeError("stop after backup"),
        ):
            with self.assertRaisesRegex(RuntimeError, "stop after backup"):
                tasks.grabowski_task_list()
        backup = self._task_migration_backups()[0]
        backup.chmod(0o600)
        backup.write_bytes(b"not a sqlite database")
        with self.assertRaisesRegex(RuntimeError, "corrupt"):
            tasks.grabowski_task_list()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "4",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_concurrent_task_openers_create_one_verified_backup(self) -> None:
        self._create_task_schema_version("2")
        barrier = threading.Barrier(3)
        errors: list[BaseException] = []

        def open_store() -> None:
            try:
                barrier.wait(timeout=2)
                with tasks._database():
                    pass
            except BaseException as exc:
                errors.append(exc)

        workers = [threading.Thread(target=open_store) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=2)
        for worker in workers:
            worker.join(timeout=5)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual([], errors)
        self.assertEqual(1, len(self._task_migration_backups()))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "5",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def _promote_to_additive_schema_v4(self, *, incomplete: bool = False) -> str:
        task_id = "d" * 24
        with tasks._database():
            pass
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE tasks DROP COLUMN repository_scope_manifest_json")
            connection.execute("ALTER TABLE tasks DROP COLUMN lifecycle_receipt_sha256")
            connection.execute("ALTER TABLE tasks DROP COLUMN terminalized_at_unix")
            connection.execute("ALTER TABLE tasks DROP COLUMN terminalization_sha256")
            connection.execute("UPDATE metadata SET value='3' WHERE key='schema_version'")
            connection.execute(
                """
                INSERT INTO tasks(
                    task_id, host, unit, attempt, state, resume_policy,
                    argv_json, argv_sha256, cwd, runtime_seconds,
                    cpu_weight, io_weight, memory_max_bytes,
                    created_at_unix, updated_at_unix, launcher_json,
                    last_observation_json, resource_keys_json,
                    execution_backend, systemd_scope, authoritative_unit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (task_id, "local", f"grabowski-task-{task_id}-a1.service", 1,
                 "completed", "manual", '["/bin/true"]', "b" * 64,
                 str(self.root), 60, 100, 100, None, 1, 1, '{}', None, '[]',
                 "systemd-user", "user", f"grabowski-task-{task_id}-a1.service"),
            )
            connection.execute("ALTER TABLE tasks ADD COLUMN terminalization_sha256 TEXT")
            connection.execute("ALTER TABLE tasks ADD COLUMN terminalized_at_unix INTEGER")
            if not incomplete:
                connection.execute("ALTER TABLE tasks ADD COLUMN lifecycle_receipt_sha256 TEXT")
            connection.execute("UPDATE metadata SET value='4' WHERE key='schema_version'")
            connection.execute(
                "UPDATE tasks SET terminalization_sha256=?, terminalized_at_unix=? WHERE task_id=?",
                ("c" * 64, 42, task_id),
            )
            if not incomplete:
                connection.execute(
                    "UPDATE tasks SET lifecycle_receipt_sha256=? WHERE task_id=?",
                    ("e" * 64, task_id),
                )
            connection.commit()
        return task_id

    def test_additive_schema_v4_migrates_and_preserves_terminalization_state(self) -> None:
        task_id = self._promote_to_additive_schema_v4()
        listed = tasks.grabowski_task_list(limit=10)
        self.assertTrue(any(item["task_id"] == task_id for item in listed["tasks"]))
        with sqlite3.connect(self.database) as connection:
            self.assertEqual("5", connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0])
            self.assertIn(
                "repository_scope_manifest_json",
                {row[1] for row in connection.execute("PRAGMA table_info(tasks)")},
            )
            self.assertEqual(
                ("c" * 64, 42, "e" * 64),
                connection.execute(
                    "SELECT terminalization_sha256, terminalized_at_unix, lifecycle_receipt_sha256 FROM tasks WHERE task_id=?",
                    (task_id,),
                ).fetchone(),
            )

    def test_incomplete_additive_schema_v4_fails_closed(self) -> None:
        self._promote_to_additive_schema_v4(incomplete=True)
        with self.assertRaisesRegex(RuntimeError, "schema 4 is incomplete"):
            tasks.grabowski_task_list()

    def test_schema_v4_unknown_column_fails_closed_without_version_flip(self) -> None:
        self._promote_to_additive_schema_v4()
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE tasks ADD COLUMN unknown_future_field TEXT")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "schema 4 is incomplete or unsupported"):
            tasks.grabowski_task_list()
        with sqlite3.connect(self.database) as connection:
            self.assertEqual(
                "4",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_task_integrity_check_reports_busy_separately_from_corruption(self) -> None:
        class BusyConnection:
            def execute(self, statement: str) -> object:
                raise sqlite3.OperationalError("database is locked")

        with self.assertRaisesRegex(RuntimeError, "busy; retry"):
            tasks._sqlite_integrity(BusyConnection(), "Task database")

    def test_current_task_store_reopen_is_byte_stable(self) -> None:
        connection = tasks._database()
        connection.close()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_names = sorted(item.name for item in self.database.parent.iterdir())
        reopened = tasks._database()
        self.assertEqual(0, reopened.total_changes)
        reopened.close()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            before_names,
            sorted(item.name for item in self.database.parent.iterdir()),
        )
        self.assertEqual([], self._task_migration_backups())

    def test_raced_away_current_task_store_is_not_recreated(self) -> None:
        with tasks._database():
            pass
        self.database.unlink()
        with patch.object(tasks, "_preflight_task_store", return_value="5"):
            with self.assertRaises(sqlite3.OperationalError):
                tasks._database()
        self.assertFalse(self.database.exists())

    def test_corrupt_task_store_fails_without_side_effects(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        payload = b"not-a-sqlite-task-store\x00corrupt"
        self.database.write_bytes(payload)
        before_stat = self.database.stat()
        with self.assertRaisesRegex(RuntimeError, "corrupt"):
            tasks.grabowski_task_list()
        self.assertEqual(payload, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            [], list(self.database.parent.glob(self.database.name + "-*"))
        )
        self.assertEqual([], self._task_migration_backups())

    def test_malformed_task_metadata_fails_without_side_effects(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT, value TEXT NOT NULL);
                INSERT INTO metadata VALUES('schema_version', '4');
                INSERT INTO metadata VALUES('schema_version', '5');
                CREATE TABLE tasks (task_id TEXT PRIMARY KEY);
                """
            )
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        with self.assertRaisesRegex(RuntimeError, "metadata table is malformed"):
            tasks.grabowski_task_list()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            [], list(self.database.parent.glob(self.database.name + "-*"))
        )
        self.assertEqual([], self._task_migration_backups())

    def test_unknown_task_schema_still_fails_closed(self) -> None:
        with tasks._database() as connection:
            connection.execute("UPDATE metadata SET value='6' WHERE key='schema_version'")
            connection.commit()
        before = self.database.read_bytes()
        before_stat = self.database.stat()
        before_sidecars = {
            item.name for item in self.database.parent.glob(self.database.name + "-*")
        }
        with self.assertRaisesRegex(RuntimeError, "Unsupported task database schema"):
            tasks.grabowski_task_list()
        self.assertEqual(before, self.database.read_bytes())
        self.assertEqual(before_stat.st_mtime_ns, self.database.stat().st_mtime_ns)
        self.assertEqual(
            before_sidecars,
            {item.name for item in self.database.parent.glob(self.database.name + "-*")},
        )
        self.assertEqual([], self._task_migration_backups())

    def test_schema_v3_missing_root_contract_column_fails_closed(self) -> None:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO metadata(key, value) VALUES('schema_version', '3');
                CREATE TABLE tasks (task_id TEXT PRIMARY KEY);
                """
            )
        with self.assertRaisesRegex(RuntimeError, "schema 3 is incomplete"):
            tasks.grabowski_task_list()

    def test_schema_v5_missing_index_fails_closed_without_repair_write(self) -> None:
        with tasks._database() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "5",
            )
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP INDEX tasks_created_task_idx")
            connection.commit()
        with self.assertRaisesRegex(RuntimeError, "indexes are incomplete"):
            tasks.grabowski_task_list()

    def test_database_rejects_symlink(self) -> None:
        target = self.root / "real.sqlite3"
        target.write_bytes(b"")
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.database.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "may not be a symlink"):
            tasks.grabowski_task_list()



    def test_managed_cargo_retry_is_blocked_before_environment_preparation(self) -> None:
        raw_command = ["/usr/bin/cargo", "test"]
        cache_key = "c" * 64
        target_dir = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
        lifecycle_lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
        bound_command = [
            tasks.FLOCK_EXECUTABLE,
            "--shared",
            str(lifecycle_lock),
            tasks.SYSTEMD_ENV_EXECUTABLE,
            f"CARGO_TARGET_DIR={target_dir}",
            *raw_command,
        ]
        common = {
            "host": "local",
            "argv": raw_command,
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_managed_cargo_request_root", return_value=self.root),
            patch.object(
                tasks,
                "_bind_managed_cargo_environment",
                return_value=bound_command,
            ),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
        tasks._set_state(
            str(first["task_id"]),
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_managed_cargo_request_root", return_value=self.root),
            patch.object(tasks, "_bind_managed_cargo_environment") as prepare,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "unchanged terminal task retry blocked",
            ),
        ):
            tasks.grabowski_task_start(**common)
        prepare.assert_not_called()

    def test_explicit_managed_cargo_retry_is_blocked_before_lock_preparation(self) -> None:
        cache_key = "d" * 64
        target_dir = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
        lifecycle_lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
        command = [
            tasks.SYSTEMD_ENV_EXECUTABLE,
            f"CARGO_TARGET_DIR={target_dir}",
            "/usr/bin/cargo",
            "test",
        ]
        common = {
            "host": "local",
            "argv": command,
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(
                tasks,
                "_managed_cargo_lifecycle_lock",
                return_value=lifecycle_lock,
            ),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
        tasks._set_state(
            str(first["task_id"]),
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_managed_cargo_lifecycle_lock") as prepare_lock,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "unchanged terminal task retry blocked",
            ),
        ):
            tasks.grabowski_task_start(**common)
        prepare_lock.assert_not_called()

    def test_unprepared_managed_cargo_blocks_exposed_cancelled_successor_source(self) -> None:
        raw_command = ["/usr/bin/cargo", "check"]
        identity = tasks._task_execution_identity(
            host="local",
            argv_sha256=tasks.command_identity.argv_sha256(raw_command),
            cwd=str(self.root),
            resource_keys=[],
            runtime_seconds=60,
            cpu_weight=50,
            io_weight=25,
            memory_max_bytes=None,
            chronik_outbox_enabled=False,
            chronik_outbox_state_root=None,
            chronik_context_json=None,
            execution_backend="systemd-user",
            systemd_scope="user",
        )
        source = {"task_id": "c" * 24, "state": "failed"}
        cancelled = {"task_id": "d" * 24, "state": "cancelled"}
        with (
            patch.object(tasks, "_managed_cargo_request_root", return_value=self.root),
            patch.object(
                tasks,
                "_latest_matching_unprepared_managed_cargo_record",
                return_value=cancelled,
            ),
            patch.object(
                tasks,
                "_matching_attention_unprepared_managed_cargo_records",
                return_value=[source],
            ),
            patch.object(
                tasks, "_retained_retry_successor_for_source", return_value=None
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "unchanged terminal task retry blocked",
            ),
        ):
            tasks._guard_unprepared_managed_cargo_retry(
                raw_command,
                target=LOCAL_HOST,
                cwd=str(self.root),
                execution_backend="systemd-user",
                identity=identity,
                retry_context=None,
            )

    def test_invalid_named_managed_cargo_retry_is_rejected_before_preparation(self) -> None:
        raw_command = ["/usr/bin/cargo", "check"]
        identity = tasks._task_execution_identity(
            host="local",
            argv_sha256=tasks.command_identity.argv_sha256(raw_command),
            cwd=str(self.root),
            resource_keys=[],
            runtime_seconds=60,
            cpu_weight=50,
            io_weight=25,
            memory_max_bytes=None,
            chronik_outbox_enabled=False,
            chronik_outbox_state_root=None,
            chronik_context_json=None,
            execution_backend="systemd-user",
            systemd_scope="user",
        )
        with (
            patch.object(tasks, "_managed_cargo_request_root", return_value=self.root),
            patch.object(tasks, "_row_raw") as row,
            self.assertRaisesRegex(ValueError, "source task is invalid"),
        ):
            tasks._guard_unprepared_managed_cargo_retry(
                raw_command,
                target=LOCAL_HOST,
                cwd=str(self.root),
                execution_backend="systemd-user",
                identity=identity,
                retry_context={},
            )
        row.assert_not_called()


    def test_managed_cargo_attention_limit_counts_only_command_matches(self) -> None:
        raw_command = ["/usr/bin/cargo", "test"]

        def start_failed(command: list[str], cache_key: str) -> dict[str, object]:
            target_dir = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
            lifecycle_lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
            bound = [
                tasks.FLOCK_EXECUTABLE,
                "--shared",
                str(lifecycle_lock),
                tasks.SYSTEMD_ENV_EXECUTABLE,
                f"CARGO_TARGET_DIR={target_dir}",
                *command,
            ]
            with (
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(
                    tasks, "_managed_cargo_request_root", return_value=self.root
                ),
                patch.object(
                    tasks, "_bind_managed_cargo_environment", return_value=bound
                ),
                patch.object(tasks, "_dispatch", return_value=_launcher()),
                patch.object(tasks.base, "_append_audit"),
                patch.object(
                    tasks,
                    "_require_recovery_gate",
                    return_value={"checked_at_unix": 123},
                ),
            ):
                started = tasks.grabowski_task_start(
                    "local",
                    command,
                    cwd=str(self.root),
                    runtime_seconds=60,
                    resume_policy="retry-safe",
                    cpu_weight=50,
                    io_weight=25,
                )["task"]
            return tasks._set_state(
                str(started["task_id"]),
                "failed",
                observation={"state": "failed", "source": "test"},
            )

        relevant = start_failed(raw_command, "a" * 64)
        start_failed(["/usr/bin/cargo", "check"], "b" * 64)
        start_failed(["/usr/bin/cargo", "clippy"], "c" * 64)
        identity = tasks._task_execution_identity(
            host="local",
            argv_sha256=tasks.command_identity.argv_sha256(raw_command),
            cwd=str(self.root),
            resource_keys=[],
            runtime_seconds=60,
            cpu_weight=50,
            io_weight=25,
            memory_max_bytes=None,
            chronik_outbox_enabled=False,
            chronik_outbox_state_root=None,
            chronik_context_json=None,
            execution_backend="systemd-user",
            systemd_scope="user",
        )
        with patch.object(tasks, "MANAGED_CARGO_ATTENTION_MATCH_LIMIT", 1):
            records = tasks._matching_attention_unprepared_managed_cargo_records(
                identity, raw_command
            )
        self.assertEqual(
            [relevant["task_id"]],
            [item["task_id"] for item in records],
        )

        duplicate = dict(tasks._row_raw(str(relevant["task_id"])))
        duplicate["task_id"] = "f" * 24
        duplicate["unit"] = tasks._task_unit(duplicate["task_id"], 1)
        duplicate["authoritative_unit"] = duplicate["unit"]
        duplicate["lease_owner_id"] = f"task:{duplicate['task_id']}"
        duplicate["created_at_unix"] = int(duplicate["created_at_unix"]) + 1
        duplicate["updated_at_unix"] = int(duplicate["updated_at_unix"]) + 1
        columns = tuple(duplicate)
        with tasks._database() as connection:
            connection.execute(
                f"INSERT INTO tasks ({','.join(columns)}) VALUES "
                f"({','.join('?' for _ in columns)})",
                tuple(duplicate[column] for column in columns),
            )
            connection.commit()
        with (
            patch.object(tasks, "MANAGED_CARGO_ATTENTION_MATCH_LIMIT", 1),
            self.assertRaisesRegex(RuntimeError, "scan limit exceeded"),
        ):
            tasks._matching_attention_unprepared_managed_cargo_records(
                identity, raw_command
            )

    def test_managed_cargo_attention_scan_keeps_corrupt_argv_fail_closed(self) -> None:
        raw_command = ["/usr/bin/cargo", "test"]
        relevant = self._start()["task"]
        task_id = str(relevant["task_id"])
        tasks._set_state(
            task_id,
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET argv_json='{' WHERE task_id=?",
                (task_id,),
            )
            connection.commit()
        identity = tasks._task_execution_identity(
            host="local",
            argv_sha256=tasks.command_identity.argv_sha256(raw_command),
            cwd=str(self.root),
            resource_keys=[],
            runtime_seconds=60,
            cpu_weight=50,
            io_weight=25,
            memory_max_bytes=64 * 1024 * 1024,
            chronik_outbox_enabled=False,
            chronik_outbox_state_root=None,
            chronik_context_json=None,
            execution_backend="systemd-user",
            systemd_scope="user",
        )
        with self.assertRaisesRegex(RuntimeError, "stored task argv is invalid"):
            tasks._matching_attention_unprepared_managed_cargo_records(
                identity, raw_command
            )

    def test_task_start_blocks_unchanged_terminal_failure_without_named_change(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "retry"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
            tasks._set_state(
                str(first["task_id"]),
                "failed",
                observation={"state": "failed", "source": "test"},
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "unchanged terminal task retry blocked",
            ):
                tasks.grabowski_task_start(**common)
        rows = tasks.grabowski_task_list(limit=20, view="evidence")
        self.assertEqual(1, rows["total_matching"])

    def test_latest_matching_execution_breaks_same_second_ties_by_rowid(self) -> None:
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            original = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "rowid-order"],
                cwd=str(self.root),
                runtime_seconds=60,
                resume_policy="retry-safe",
                cpu_weight=50,
                io_weight=25,
                memory_max_bytes=64 * 1024 * 1024,
            )["task"]
        template = tasks._row_raw(str(original["task_id"]))
        columns = list(template)
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET created_at_unix=1 WHERE task_id=?",
                (original["task_id"],),
            )
            for task_id, marker in (("f" * 24, "a"), ("0" * 24, "b")):
                clone = dict(template)
                clone.update(
                    {
                        "task_id": task_id,
                        "unit": f"grabowski-task-{task_id}-a1.service",
                        "authoritative_unit": f"grabowski-task-{task_id}-a1.service",
                        "state": "failed",
                        "created_at_unix": 100,
                        "updated_at_unix": 100,
                        "terminalized_at_unix": 100,
                        "terminalization_sha256": marker * 64,
                        "lifecycle_receipt_sha256": marker * 64,
                    }
                )
                connection.execute(
                    f"INSERT INTO tasks ({','.join(columns)}) VALUES "
                    f"({','.join('?' for _ in columns)})",
                    tuple(clone[column] for column in columns),
                )
        newest = tasks._row_raw("0" * 24)
        identity = tasks._record_execution_identity(newest)
        selected = tasks._latest_matching_execution_record(identity)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual("0" * 24, selected["task_id"])

    def test_named_retry_validation_uses_exact_source_not_latest_independent_failure(self) -> None:
        source_id = "1" * 24
        latest_id = "2" * 24
        identity = {"identity_sha256": "a" * 64}
        source = {"task_id": source_id, "state": "failed"}
        latest = {"task_id": latest_id, "state": "failed"}
        context = {"source_task_id": source_id}
        validated = {"source_task_id": source_id, "context_sha256": "b" * 64}

        with patch.object(
            tasks, "_latest_matching_execution_record", return_value=latest
        ), patch.object(tasks, "_row_raw", return_value=source), patch.object(
            tasks, "_record_execution_identity", return_value=identity
        ), patch.object(
            tasks, "_persisted_retry_binding_or_raise", return_value=None
        ), patch.object(
            tasks, "_validate_terminal_retry_context", return_value=validated
        ) as validate:
            observed = tasks._guard_unchanged_terminal_retry(identity, context)

        self.assertEqual(validated, observed)
        validate.assert_called_once_with(
            context, predecessor=source, identity=identity
        )

    def test_named_retry_validation_allows_source_after_cancelled_linked_successor(self) -> None:
        source_id = "3" * 24
        latest_id = "4" * 24
        identity = {"identity_sha256": "c" * 64}
        source = {"task_id": source_id, "state": "failed"}
        latest = {"task_id": latest_id, "state": "cancelled"}
        context = {"source_task_id": source_id}
        binding = {"source_task_id": source_id}

        with patch.object(
            tasks, "_latest_matching_execution_record", return_value=latest
        ), patch.object(tasks, "_row_raw", return_value=source), patch.object(
            tasks, "_record_execution_identity", return_value=identity
        ), patch.object(
            tasks, "_persisted_retry_binding_or_raise", return_value=binding
        ), patch.object(
            tasks,
            "_validate_terminal_retry_context",
            return_value={"source_task_id": source_id},
        ):
            observed = tasks._guard_unchanged_terminal_retry(identity, context)

        self.assertEqual(source_id, observed["source_task_id"])

    def test_direct_start_blocks_exposed_source_after_cancelled_successor(self) -> None:
        source_id = "a" * 24
        cancelled_id = "b" * 24
        identity = {"identity_sha256": "c" * 64}
        source = {"task_id": source_id, "state": "failed"}
        latest = {"task_id": cancelled_id, "state": "cancelled"}

        with patch.object(
            tasks, "_latest_matching_execution_record", return_value=latest
        ), patch.object(
            tasks, "_matching_attention_execution_records", return_value=[source]
        ), patch.object(
            tasks, "_retained_retry_successor_for_source", return_value=None
        ), self.assertRaisesRegex(RuntimeError, "unchanged terminal task retry blocked"):
            tasks._guard_unchanged_terminal_retry(identity, None)


    def test_named_retry_validation_blocks_active_linked_successor(self) -> None:
        source_id = "5" * 24
        latest_id = "6" * 24
        identity = {"identity_sha256": "d" * 64}
        source = {"task_id": source_id, "state": "failed"}
        latest = {"task_id": latest_id, "state": "running"}
        context = {"source_task_id": source_id}
        binding = {"source_task_id": source_id}

        with patch.object(
            tasks, "_latest_matching_execution_record", return_value=latest
        ), patch.object(tasks, "_row_raw", return_value=source), patch.object(
            tasks, "_record_execution_identity", return_value=identity
        ), patch.object(
            tasks, "_persisted_retry_binding_or_raise", return_value=binding
        ), self.assertRaisesRegex(RuntimeError, "unresolved retry successor"):
            tasks._guard_unchanged_terminal_retry(identity, context)

    def test_retained_retry_successor_search_is_bound_to_exact_source(self) -> None:
        source = self._start()["task"]
        relevant = self._start()["task"]
        unrelated = self._start()["task"]
        source_id = str(source["task_id"])
        relevant_id = str(relevant["task_id"])
        unrelated_id = str(unrelated["task_id"])
        for task_id, bound_source in (
            (relevant_id, source_id),
            (unrelated_id, "f" * 24),
        ):
            tasks._set_state(
                task_id,
                "completed",
                observation={"state": "completed", "source": "test"},
            )
            with tasks._database() as connection:
                connection.execute(
                    "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                    (
                        tasks._canonical_json(
                            {"retry_binding": {"source_task_id": bound_source}}
                        ),
                        task_id,
                    ),
                )
        with patch.object(
            tasks,
            "_persisted_retry_binding_or_raise",
            side_effect=lambda record: json.loads(str(record["launcher_json"]))[
                "retry_binding"
            ],
        ):
            retained = tasks._retained_retry_successor_for_source(source_id)
        self.assertIsNotNone(retained)
        assert retained is not None
        self.assertEqual(relevant_id, retained["task_id"])

    def test_named_retry_blocks_retained_successor_behind_newer_ordinary_task(self) -> None:
        source_id = "7" * 24
        retained_id = "8" * 24
        latest_id = "9" * 24
        identity = {"identity_sha256": "e" * 64}
        source = {"task_id": source_id, "state": "failed"}
        latest = {"task_id": latest_id, "state": "running"}
        retained = {"task_id": retained_id, "state": "completed"}
        context = {"source_task_id": source_id}

        with patch.object(
            tasks, "_latest_matching_execution_record", return_value=latest
        ), patch.object(tasks, "_row_raw", return_value=source), patch.object(
            tasks, "_record_execution_identity", return_value=identity
        ), patch.object(
            tasks, "_persisted_retry_binding_or_raise", return_value=None
        ), patch.object(
            tasks,
            "_retained_retry_successor_for_source",
            return_value=retained,
        ), self.assertRaisesRegex(RuntimeError, "already has a retained successor"):
            tasks._guard_unchanged_terminal_retry(identity, context)

    def test_terminal_retry_command_does_not_prepare_lock_for_retained_successor(
        self,
    ) -> None:
        """Named reconcile must not mkdir lock roots before successor admission."""
        cache_key = "c" * 64
        target = tasks.MANAGED_CARGO_CACHE_ROOT / cache_key / "target"
        lock = tasks.MANAGED_CARGO_LOCK_ROOT / f"{cache_key}.lock"
        bound = [
            tasks.FLOCK_EXECUTABLE,
            "--shared",
            str(lock),
            tasks.SYSTEMD_ENV_EXECUTABLE,
            f"CARGO_TARGET_DIR={target}",
            "/usr/bin/cargo",
            "test",
        ]
        record = {
            "argv_json": json.dumps(bound),
            "host": "local",
            "execution_backend": "systemd-user",
        }
        with patch.object(tasks, "_managed_cargo_lifecycle_lock") as prepare_lock:
            replay = tasks._terminal_retry_command(record)
        self.assertEqual(bound[3:], replay)
        prepare_lock.assert_not_called()

    def test_retry_binding_is_persisted_before_dispatch_and_blocks_duplicate_start(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "predispatch-retry-binding"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
        source = tasks._set_state(
            str(first["task_id"]),
            "failed",
            observation={"state": "failed", "source": "test"},
        )
        retry_context = tasks._build_terminal_retry_context(
            source,
            reason="repository head advanced after the failed validation",
        )
        dispatched: dict[str, object] = {}

        def launch_after_persist(record: dict[str, object]) -> dict[str, object]:
            stored = tasks._row_raw(str(record["task_id"]))
            pending = json.loads(str(stored["launcher_json"]))
            self.assertIs(True, pending["pending"])
            self.assertEqual(
                retry_context["context_sha256"],
                pending["retry_binding"]["context_sha256"],
            )
            dispatched["task_id"] = record["task_id"]
            return _launcher()

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_launch", side_effect=launch_after_persist),
            patch.object(
                tasks,
                "_set_state",
                side_effect=RuntimeError("simulated crash after dispatch"),
            ),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
            self.assertRaisesRegex(RuntimeError, "simulated crash after dispatch"),
        ):
            tasks.grabowski_task_start(
                **common,
                _retry_context=retry_context,
            )

        successor_id = str(dispatched["task_id"])
        successor = tasks._row_raw(successor_id)
        self.assertEqual("launching", successor["state"])
        persisted = json.loads(str(successor["launcher_json"]))
        self.assertEqual(
            source["task_id"],
            persisted["retry_binding"]["source_task_id"],
        )

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 123},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "unresolved retry successor",
            ),
        ):
            tasks.grabowski_task_start(**common)

    def test_reconcile_resume_allows_one_named_state_bound_successor(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "retry"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "retry-safe",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        audit_records: list[dict[str, object]] = []
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit", side_effect=audit_records.append),
            patch.object(tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}),
        ):
            first = tasks.grabowski_task_start(**common)["task"]
            source = tasks._set_state(
                str(first["task_id"]),
                "failed",
                observation={"state": "failed", "source": "test"},
            )
            result = tasks.reconcile_tasks_resume(
                task_id=str(first["task_id"]),
                max_resumes=1,
                reason="repository head advanced after the failed validation",
            )
        self.assertEqual(1, len(result["resumed"]))
        successor = result["resumed"][0]
        self.assertEqual(first["task_id"], successor["retry_of_task_id"])
        self.assertEqual("manual", successor["resume_policy"])
        self.assertRegex(successor["retry_context_sha256"], r"^[0-9a-f]{64}$")
        persisted_retry = successor["launcher"]["retry_binding"]
        self.assertEqual(first["task_id"], persisted_retry["source_task_id"])
        self.assertEqual(
            source["lifecycle_receipt_sha256"],
            persisted_retry["source_lifecycle_receipt_sha256"],
        )
        self.assertEqual(
            source["terminalization_sha256"],
            persisted_retry["source_terminalization_sha256"],
        )
        self.assertEqual(
            successor["retry_context_sha256"],
            persisted_retry["context_sha256"],
        )
        retry_audit = next(
            item
            for item in audit_records
            if item.get("operation") == "task-reconcile-retry-successor"
        )
        self.assertEqual(source["lifecycle_receipt_sha256"], retry_audit["source_lifecycle_receipt_sha256"])
        self.assertEqual(successor["retry_context_sha256"], retry_audit["retry_context_sha256"])
    def test_record_execution_identity_rejects_malformed_stored_json(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])

        record = tasks._row_raw(task_id)
        record["resource_keys_json"] = "{"
        with self.assertRaisesRegex(
            RuntimeError, "stored task resource keys are invalid"
        ):
            tasks._record_execution_identity(record)

        record = tasks._row_raw(task_id)
        record["chronik_context_json"] = "{"
        with self.assertRaisesRegex(
            RuntimeError, "stored task Chronik context is invalid"
        ):
            tasks._record_execution_identity(record)

    def test_resource_keys_are_canonicalized_before_identity_lookup(self) -> None:
        started = self._start(resource_keys=["display:12", "display:11"])
        record = tasks._row_raw(str(started["task"]["task_id"]))
        self.assertEqual(
            ["display:11", "display:12"],
            json.loads(str(record["resource_keys_json"])),
        )

    def test_retry_successor_scan_ignores_nested_retry_binding_keys(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "completed",
            observation={"state": "completed", "source": "test"},
        )
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                (
                    tasks._canonical_json(
                        {"diagnostic": {"retry_binding": "not-a-top-level-binding"}}
                    ),
                    task_id,
                ),
            )
            records = tasks._task_retry_successor_records(
                connection,
                source_task_ids={task_id},
                limit=0,
            )
        self.assertEqual([], records)

    def test_retry_successor_scan_scopes_support_to_current_sources(self) -> None:
        relevant = self._start()
        unrelated = self._start()
        relevant_id = str(relevant["task"]["task_id"])
        unrelated_id = str(unrelated["task"]["task_id"])
        relevant_successor = self._start()
        unrelated_successor = self._start()
        relevant_successor_id = str(relevant_successor["task"]["task_id"])
        unrelated_successor_id = str(unrelated_successor["task"]["task_id"])
        for task_id in (relevant_successor_id, unrelated_successor_id):
            tasks._set_state(
                task_id,
                "completed",
                observation={"state": "completed", "source": "test"},
            )
        with tasks._database() as connection:
            for task_id, source_task_id in (
                (relevant_successor_id, relevant_id),
                (unrelated_successor_id, unrelated_id),
            ):
                connection.execute(
                    "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                    (
                        tasks._canonical_json(
                            {"retry_binding": {"source_task_id": source_task_id}}
                        ),
                        task_id,
                    ),
                )
            with patch.object(
                tasks.terminal_convergence,
                "persisted_retry_binding",
                side_effect=lambda record: json.loads(record["launcher_json"])[
                    "retry_binding"
                ],
            ):
                records = tasks._task_retry_successor_records(
                    connection,
                    source_task_ids={relevant_id},
                    limit=1,
                )
        self.assertEqual(
            [relevant_successor_id],
            [str(record["task_id"]) for record in records],
        )

    def test_retry_successor_scan_rejects_malformed_potential_binding(self) -> None:
        started = self._start()
        task_id = str(started["task"]["task_id"])
        tasks._set_state(
            task_id,
            "completed",
            observation={"state": "completed", "source": "test"},
        )
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET launcher_json=? WHERE task_id=?",
                ('{"retry_binding":', task_id),
            )
            with self.assertRaisesRegex(ValueError, "persisted task launcher is invalid"):
                tasks._task_retry_successor_records(
                    connection,
                    source_task_ids={task_id},
                    limit=1,
                )


    def _operation_identity_fixture(self, *, source: str = "b") -> dict[str, str]:
        return {
            "repository_head": "a" * 40,
            "source_fingerprint_sha256": source * 64,
            "purpose": "validate exact source scope",
            "scope_sha256": "c" * 64,
        }

    def test_operation_identity_reuses_recent_success_across_argv_changes(self) -> None:
        operation_identity = self._operation_identity_fixture()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as first_dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "syntax-a"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        self.assertTrue(first_dispatch.called)
        source_task_id = str(first["task"]["task_id"])
        tasks._set_state(
            source_task_id,
            "completed",
            observation={"state": "completed", "observed_at_unix": tasks._now()},
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as second_dispatch,
            patch.object(
                tasks.operator, "_require_operator_mutation"
            ) as mutation_gate,
            patch.object(
                tasks, "_bind_managed_cargo_environment"
            ) as managed_cargo,
            patch.object(tasks.base, "_append_audit") as audit,
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            second = tasks.grabowski_task_start(
                "local",
                ["env", "PYTHONPATH=src", "/bin/echo", "syntax-b"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        second_dispatch.assert_not_called()
        mutation_gate.assert_not_called()
        managed_cargo.assert_not_called()
        self.assertEqual(source_task_id, second["task"]["task_id"])
        self.assertEqual(
            "recent_successful_operation_identity",
            second["deduplicated_reuse"]["reason"],
        )
        self.assertEqual("task-start-deduplicated", audit.call_args.args[0]["operation"])

    def test_operation_identity_stale_active_hit_is_reobserved_once(self) -> None:
        operation_identity = self._operation_identity_fixture()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "stale-a"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        task_id = str(first["task"]["task_id"])
        tasks._set_state(
            task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": tasks._now() - 121,
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )

        def terminalize(observed_task_id: str) -> dict[str, object]:
            self.assertEqual(task_id, observed_task_id)
            return tasks._public(
                tasks._set_state(
                    task_id,
                    "completed",
                    observation={
                        "state": "completed",
                        "observed_at_unix": tasks._now(),
                    },
                )
            )

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(
                tasks, "grabowski_task_status", side_effect=terminalize
            ) as status,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            reused = tasks.grabowski_task_start(
                "local",
                ["env", "FIXED=1", "/bin/echo", "stale-b"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        status.assert_called_once_with(task_id)
        dispatch.assert_not_called()
        self.assertEqual(task_id, reused["task"]["task_id"])
        self.assertEqual(
            "recent_successful_operation_identity",
            reused["deduplicated_reuse"]["reason"],
        )

    def test_operation_identity_fresh_active_hit_is_not_reobserved(self) -> None:
        operation_identity = self._operation_identity_fixture()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "active-a"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        task_id = str(first["task"]["task_id"])
        now = tasks._now()
        tasks._set_state(
            task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": now,
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks, "_observe") as observe,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            reused = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "active-b"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        observe.assert_not_called()
        dispatch.assert_not_called()
        self.assertEqual(task_id, reused["task"]["task_id"])
        self.assertEqual("active_operation_identity", reused["deduplicated_reuse"]["reason"])

    def test_operation_identity_fresh_active_past_runtime_budget_is_reobserved(
        self,
    ) -> None:
        operation_identity = self._operation_identity_fixture()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                "local",
                ["/bin/echo", "budget-a"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        task_id = str(first["task"]["task_id"])
        now = tasks._now()
        with tasks._database() as connection:
            connection.execute(
                "UPDATE tasks SET created_at_unix=? WHERE task_id=?",
                (now - 61, task_id),
            )
        tasks._set_state(
            task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": now,
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )

        def terminalize(observed_task_id: str) -> dict[str, object]:
            self.assertEqual(task_id, observed_task_id)
            return tasks._public(
                tasks._set_state(
                    task_id,
                    "completed",
                    observation={
                        "state": "completed",
                        "observed_at_unix": tasks._now(),
                    },
                )
            )

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(
                tasks, "grabowski_task_status", side_effect=terminalize
            ) as status,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            reused = tasks.grabowski_task_start(
                "local",
                ["env", "FIXED=1", "/bin/echo", "budget-b"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        status.assert_called_once_with(task_id)
        dispatch.assert_not_called()
        self.assertEqual(task_id, reused["task"]["task_id"])
        self.assertEqual(
            "recent_successful_operation_identity",
            reused["deduplicated_reuse"]["reason"],
        )

    def test_active_execution_identity_is_reused_without_operation_identity(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "active-execution"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "verify-then-retry",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(**common)
        task_id = str(first["task"]["task_id"])
        now = tasks._now()
        tasks._set_state(
            task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": now,
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )
        dispatch.reset_mock()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as second_dispatch,
            patch.object(tasks, "_observe") as observe,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            reused = tasks.grabowski_task_start(**common)
        second_dispatch.assert_not_called()
        observe.assert_not_called()
        self.assertEqual(task_id, reused["task"]["task_id"])
        self.assertEqual(
            "active_execution_identity",
            reused["deduplicated_reuse"]["reason"],
        )
        rows = tasks.grabowski_task_list(limit=20, view="evidence")
        self.assertEqual(1, rows["total_matching"])

    def test_active_execution_identity_scan_skips_newer_operation_bound_rows(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "active-mixed-execution"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "verify-then-retry",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            unbound = tasks.grabowski_task_start(**common)
        unbound_task_id = str(unbound["task"]["task_id"])
        tasks._set_state(
            unbound_task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": tasks._now(),
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )
        for source in ("d", "e"):
            with (
                patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
                patch.object(tasks, "_dispatch", return_value=_launcher()),
                patch.object(tasks.base, "_append_audit"),
                patch.object(
                    tasks,
                    "_require_recovery_gate",
                    return_value={"checked_at_unix": 124},
                ),
            ):
                bound = tasks.grabowski_task_start(
                    **common,
                    operation_identity=self._operation_identity_fixture(source=source),
                )
            tasks._set_state(
                str(bound["task"]["task_id"]),
                "running",
                observation={
                    "state": "running",
                    "observed_at_unix": tasks._now(),
                    "properties": {"ActiveState": "active", "SubState": "running"},
                },
            )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks, "_observe") as observe,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}
            ),
        ):
            reused = tasks.grabowski_task_start(**common)
        dispatch.assert_not_called()
        observe.assert_not_called()
        self.assertEqual(unbound_task_id, reused["task"]["task_id"])
        self.assertEqual(
            "active_execution_identity",
            reused["deduplicated_reuse"]["reason"],
        )

    def test_active_execution_identity_resume_policy_mismatch_blocks_duplicate(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "active-policy"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                **common,
                resume_policy="verify-then-retry",
            )
        task_id = str(first["task"]["task_id"])
        tasks._set_state(
            task_id,
            "running",
            observation={
                "state": "running",
                "observed_at_unix": tasks._now(),
                "properties": {"ActiveState": "active", "SubState": "running"},
            },
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
            self.assertRaisesRegex(RuntimeError, "different resume policy"),
        ):
            tasks.grabowski_task_start(
                **common,
                resume_policy="never",
            )
        dispatch.assert_not_called()
        rows = tasks.grabowski_task_list(limit=20, view="evidence")
        self.assertEqual(1, rows["total_matching"])

    def test_completed_execution_identity_allows_new_start(self) -> None:
        common = {
            "host": "local",
            "argv": ["/bin/echo", "completed-execution"],
            "cwd": str(self.root),
            "runtime_seconds": 60,
            "resume_policy": "verify-then-retry",
            "cpu_weight": 50,
            "io_weight": 25,
            "memory_max_bytes": 64 * 1024 * 1024,
        }
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(**common)
        tasks._set_state(
            str(first["task"]["task_id"]),
            "completed",
            observation={
                "state": "completed",
                "observed_at_unix": tasks._now(),
            },
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            second = tasks.grabowski_task_start(**common)
        self.assertTrue(dispatch.called)
        self.assertNotEqual(first["task"]["task_id"], second["task"]["task_id"])
        self.assertIsNone(second["deduplicated_reuse"])

    def test_operation_identity_attention_retry_requires_bound_supersession(self) -> None:
        operation_identity = self._operation_identity_fixture()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()),
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
        ):
            first = tasks.grabowski_task_start(
                "local",
                ["/bin/false"],
                cwd=str(self.root),
                runtime_seconds=60,
                operation_identity=operation_identity,
            )
        source_task_id = str(first["task"]["task_id"])
        failed = tasks._set_state(
            source_task_id,
            "failed",
            observation={"state": "failed", "observed_at_unix": tasks._now()},
        )
        receipt = str(failed["lifecycle_receipt_sha256"])
        common = dict(
            host="local",
            argv=["env", "FIXED=1", "/bin/false"],
            cwd=str(self.root),
            runtime_seconds=60,
            operation_identity=operation_identity,
        )
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as blocked_dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 124}
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "attention predecessor"):
                tasks.grabowski_task_start(**common)
        blocked_dispatch.assert_not_called()
        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "_dispatch", return_value=_launcher()) as retry_dispatch,
            patch.object(tasks.base, "_append_audit"),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 125}
            ),
        ):
            retried = tasks.grabowski_task_start(
                **common,
                supersedes_task_id=source_task_id,
                supersedes_receipt_sha256=receipt,
                force_new_reason="launcher environment corrected",
            )
        self.assertTrue(retry_dispatch.called)
        binding = retried["operation_retry_binding"]
        self.assertEqual(source_task_id, binding["source_task_id"])
        self.assertEqual(receipt, binding["source_lifecycle_receipt_sha256"])
        self.assertEqual(
            retried["operation_identity"]["operation_identity_sha256"],
            binding["source_operation_identity_sha256"],
        )

    def _runtime_refresh_prelaunch_fixture(
        self, resource_keys: list[str] | None = None
    ) -> dict[str, object]:
        keys = resource_keys or [
            f"path:{self.root / 'runtime-refresh-task-a'}",
            "service:bureau-runtime-refresh-test.service",
        ]
        keys = list(keys)
        approval_task_id = "BUREAU-RUNTIME-REFRESH-TEST"
        target_sha256 = "a" * 64
        authority_revision = 1
        authority_spec_sha256 = "b" * 64
        payload: dict[str, object] = {
            "schema_version": 1,
            "kind": "bureau_runtime_refresh_intent",
            "approval_task_id": approval_task_id,
            "created_at": "2026-09-01T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "authorized_by": "test-reviewer",
            "authorization": "test-runtime-authorization",
            "authority_task_spec": {
                "task_id": approval_task_id,
                "revision": authority_revision,
                "spec_sha256": authority_spec_sha256,
                "state": "ready",
            },
            "runtime_approval": {
                "schema_version": 1,
                "action_class": "runtime_mutation",
                "action_classes": ["runtime_mutation"],
                "allowed": True,
                "reason": "approved",
                "required": True,
                "required_level": "break_glass",
                "expected_task_id": approval_task_id,
                "expected_reference": target_sha256,
                "evidence": {
                    "schema_version": 1,
                    "source": "test-runtime-authorization",
                    "approved": True,
                    "level": "break_glass",
                    "reviewer": "test-reviewer",
                    "task_id": approval_task_id,
                    "reference": target_sha256,
                    "scope": ["runtime_mutation"],
                    "note": "Bureau immutable runtime refresh",
                },
            },
            "required_resource_keys": keys,
            "target_sha256": target_sha256,
        }
        intent_sha256 = hashlib.sha256(
            (tasks._canonical_json(payload) + "\n").encode("utf-8")
        ).hexdigest()
        intent = {**payload, "intent_sha256": intent_sha256}
        lease_owner = f"runtime-refresh:{intent_sha256[:16]}"
        request = {
            "intent": str(self.root / "runtime-refresh-intent.json"),
            "expected_intent_sha256": intent_sha256,
            "lease_owner": lease_owner,
            "lease_task_id": approval_task_id,
        }
        return {
            "argv": [tasks.bureau_runtime_refresh_executor.RESERVED_TASK_COMMAND],
            "request": request,
            "intent": intent,
            "intent_sha256": intent_sha256,
            "lease_owner": lease_owner,
            "approval_task_id": approval_task_id,
            "resource_keys": keys,
            "authority": {
                "task_id": approval_task_id,
                "revision": authority_revision,
                "spec_sha256": authority_spec_sha256,
            },
        }

    def _runtime_refresh_lease_metadata(
        self, resource_keys: list[str]
    ) -> dict[str, dict[str, object]]:
        with sqlite3.connect(self.resource_database) as connection:
            connection.row_factory = sqlite3.Row
            placeholders = ",".join("?" for _ in resource_keys)
            rows = connection.execute(
                f"SELECT resource_key, metadata_json FROM leases "
                f"WHERE resource_key IN ({placeholders}) ORDER BY resource_key",
                resource_keys,
            ).fetchall()
        return {
            row["resource_key"]: json.loads(row["metadata_json"]) for row in rows
        }

    @contextmanager
    def _runtime_refresh_start_environment(
        self, fixture: dict[str, object], *, dispatch_effect=None
    ):
        managed_runtime = {
            "XDG_RUNTIME_DIR": "/run/user/1000",
            "HEIM_NODE_RUNTIME_ENV_DIR": "/run/user/1000/grabowski-node-runtime-env",
            "UV_CACHE_DIR": "/run/user/1000/grabowski-uv-cache",
        }

        def dispatch(*args, **kwargs):
            if dispatch_effect is not None:
                return dispatch_effect(*args, **kwargs)
            return _launcher()

        with (
            patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST),
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", Path(sys.executable)),
            patch.object(
                tasks.bureau_runtime_refresh_executor,
                "parse_reserved_task_request",
                return_value=fixture["request"],
            ),
            patch.object(
                tasks.bureau_runtime_refresh_executor,
                "load_bound_intent",
                return_value=fixture["intent"],
            ),
            patch.object(
                tasks.bureau_runtime_refresh_executor,
                "validate_authority_execution_contract",
                return_value=fixture["authority"],
            ),
            patch.object(
                tasks.bureau_runtime_refresh_executor,
                "operation_identity",
                return_value=None,
            ),
            patch.object(
                tasks, "_validate_cwd", return_value=str(tasks.operator.HOME)
            ),
            patch.object(
                tasks, "_require_recovery_gate", return_value={"checked_at_unix": 123}
            ),
            patch.object(
                tasks.operator, "_managed_runtime_environment", return_value=managed_runtime
            ),
            patch.object(tasks, "_dispatch", side_effect=dispatch) as dispatch_mock,
            patch.object(tasks.base, "_append_audit") as audit_mock,
        ):
            yield dispatch_mock, audit_mock

    def test_runtime_refresh_prelaunch_request_binds_real_task_identity(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        task_id = "7" * 24
        unit = f"grabowski-task-{task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"], fixture["intent"], fixture["authority"], task_id, unit
        )
        self.assertEqual(task_id, request["task_id"])
        self.assertEqual(unit, request["executor_unit"])
        self.assertEqual(fixture["resource_keys"], request["resource_keys"])
        self.assertEqual(600, request["minimum_remaining_seconds"])
        material = {key: value for key, value in request.items() if key != "request_sha256"}
        self.assertEqual(tasks._sha256_json(material), request["request_sha256"])

        for keys in (
            list(reversed(fixture["resource_keys"])),
            [fixture["resource_keys"][0], fixture["resource_keys"][0]],
        ):
            payload = {
                key: value
                for key, value in fixture["intent"].items()
                if key != "intent_sha256"
            }
            payload["required_resource_keys"] = keys
            digest = hashlib.sha256(
                (tasks._canonical_json(payload) + "\n").encode("utf-8")
            ).hexdigest()
            bad_intent = {**payload, "intent_sha256": digest}
            bad_request = {
                **fixture["request"],
                "expected_intent_sha256": digest,
                "lease_owner": f"runtime-refresh:{digest[:16]}",
            }
            with self.assertRaisesRegex(ValueError, "not canonical"):
                tasks._runtime_refresh_prelaunch_lease_binding_request(
                    bad_request, bad_intent, fixture["authority"], task_id, unit
                )

        bad_unit = "grabowski-task-" + "8" * 24 + "-a1.service"
        with self.assertRaises(
            tasks.bureau_runtime_refresh_executor.BureauRuntimeRefreshExecutorError
        ):
            tasks._runtime_refresh_prelaunch_lease_binding_request(
                fixture["request"], fixture["intent"], fixture["authority"], task_id, bad_unit
            )

    def test_runtime_refresh_prelaunch_rejects_unbound_owner_approval_and_resource_kind(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        task_id = "9" * 24
        unit = f"grabowski-task-{task_id}-a1.service"

        foreign_owner = {**fixture["request"], "lease_owner": "runtime-refresh:foreign"}
        with self.assertRaisesRegex(ValueError, "lease owner is not intent-bound"):
            tasks._runtime_refresh_prelaunch_lease_binding_request(
                foreign_owner,
                fixture["intent"],
                fixture["authority"],
                task_id,
                unit,
            )

        bad_approval_payload = {
            key: value
            for key, value in fixture["intent"].items()
            if key != "intent_sha256"
        }
        bad_approval_payload["runtime_approval"] = {
            **bad_approval_payload["runtime_approval"],
            "allowed": False,
        }
        bad_approval_digest = hashlib.sha256(
            (tasks._canonical_json(bad_approval_payload) + "\n").encode("utf-8")
        ).hexdigest()
        bad_approval_intent = {
            **bad_approval_payload,
            "intent_sha256": bad_approval_digest,
        }
        bad_approval_request = {
            **fixture["request"],
            "expected_intent_sha256": bad_approval_digest,
            "lease_owner": f"runtime-refresh:{bad_approval_digest[:16]}",
        }
        with self.assertRaisesRegex(ValueError, "approval binding is invalid"):
            tasks._runtime_refresh_prelaunch_lease_binding_request(
                bad_approval_request,
                bad_approval_intent,
                fixture["authority"],
                task_id,
                unit,
            )

        expired_payload = {
            key: value
            for key, value in fixture["intent"].items()
            if key != "intent_sha256"
        }
        expired_payload["expires_at"] = "2000-01-01T00:00:00Z"
        expired_digest = hashlib.sha256(
            (tasks._canonical_json(expired_payload) + "\n").encode("utf-8")
        ).hexdigest()
        expired_intent = {**expired_payload, "intent_sha256": expired_digest}
        expired_request = {
            **fixture["request"],
            "expected_intent_sha256": expired_digest,
            "lease_owner": f"runtime-refresh:{expired_digest[:16]}",
        }
        with self.assertRaisesRegex(ValueError, "approval expires too soon"):
            tasks._runtime_refresh_prelaunch_lease_binding_request(
                expired_request,
                expired_intent,
                fixture["authority"],
                task_id,
                unit,
            )

        bad_kind_payload = {
            key: value
            for key, value in fixture["intent"].items()
            if key != "intent_sha256"
        }
        bad_kind_payload["required_resource_keys"] = ["component:unrelated-live-lease"]
        bad_kind_digest = hashlib.sha256(
            (tasks._canonical_json(bad_kind_payload) + "\n").encode("utf-8")
        ).hexdigest()
        bad_kind_intent = {**bad_kind_payload, "intent_sha256": bad_kind_digest}
        bad_kind_request = {
            **fixture["request"],
            "expected_intent_sha256": bad_kind_digest,
            "lease_owner": f"runtime-refresh:{bad_kind_digest[:16]}",
        }
        with self.assertRaisesRegex(ValueError, "unsupported resource kind"):
            tasks._runtime_refresh_prelaunch_lease_binding_request(
                bad_kind_request,
                bad_kind_intent,
                fixture["authority"],
                task_id,
                unit,
            )

    def test_runtime_refresh_invalid_prelaunch_contract_never_prepares_lease_mutation(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture(
            ["component:unrelated-live-lease"]
        )
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="unrelated live lease",
            ttl_seconds=1200,
            metadata={"marker": "must-remain-unbound"},
        )
        original = tasks.resources.inspect_resource(fixture["resource_keys"][0])
        with self._runtime_refresh_start_environment(fixture):
            with patch.object(
                tasks.resources,
                "prepare_runtime_refresh_executor_lease_binding",
                side_effect=AssertionError("prelaunch mutation preparation must not run"),
            ) as prepare:
                with self.assertRaisesRegex(ValueError, "unsupported resource kind"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        prepare.assert_not_called()
        self.assertEqual(
            original,
            tasks.resources.inspect_resource(fixture["resource_keys"][0]),
        )

    def test_runtime_refresh_reserved_task_rejects_caller_resource_keys(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        with patch.object(tasks.fleet, "fleet_host", return_value=LOCAL_HOST):
            with self.assertRaisesRegex(ValueError, "server-owned by the bound"):
                tasks.grabowski_task_start(
                    "local",
                    fixture["argv"],
                    cwd=str(tasks.operator.HOME),
                    resume_policy="never",
                    resource_keys=[],
                )

    def test_runtime_refresh_task_binds_actual_unit_before_dispatch(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh task start",
            ttl_seconds=1200,
            metadata=metadata,
        )
        observed: dict[str, object] = {}

        def dispatch(*args, **kwargs):
            launch = args[1]
            persisted = self._runtime_refresh_lease_metadata(fixture["resource_keys"])
            units = {item["executor_unit"] for item in persisted.values()}
            self.assertEqual(1, len(units))
            unit = next(iter(units))
            self.assertTrue(
                any(item == unit or item == f"--unit={unit}" for item in launch)
            )
            observed["unit"] = unit
            observed["metadata"] = persisted
            return _launcher()

        with self._runtime_refresh_start_environment(
            fixture, dispatch_effect=dispatch
        ) as (dispatch_mock, audit_mock):
            result = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )

        self.assertEqual(1, dispatch_mock.call_count)
        self.assertEqual(result["task"]["unit"], observed["unit"])
        evidence = result["runtime_refresh_executor_lease_binding"]
        self.assertEqual(result["task"]["unit"], evidence["executor_unit"])
        self.assertEqual(len(fixture["resource_keys"]), evidence["resource_count"])
        self.assertEqual(
            evidence,
            result["task"]["launcher"]["runtime_refresh_executor_lease_binding"],
        )
        audit_records = [
            call.args[0]
            for call in audit_mock.call_args_list
            if call.args and isinstance(call.args[0], dict)
            and call.args[0].get("operation") == "task-start"
        ]
        self.assertEqual(1, len(audit_records))
        self.assertEqual(
            evidence, audit_records[0]["runtime_refresh_executor_lease_binding"]
        )
        with sqlite3.connect(self.database) as connection:
            journals = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual([], journals)

    def test_runtime_refresh_task_server_acquires_missing_intent_leases(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        observed: dict[str, object] = {}

        def dispatch(*args, **kwargs):
            observed["leases"] = {
                key: tasks.resources.inspect_resource(key)
                for key in fixture["resource_keys"]
            }
            observed["metadata"] = self._runtime_refresh_lease_metadata(
                fixture["resource_keys"]
            )
            return _launcher()

        with self._runtime_refresh_start_environment(
            fixture, dispatch_effect=dispatch
        ) as (dispatch_mock, _audit_mock):
            result = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )
        self.assertEqual(1, dispatch_mock.call_count)
        self.assertEqual([], result["task"]["resource_keys"])
        self.assertEqual(
            {fixture["lease_owner"]},
            {item["owner_id"] for item in observed["leases"].values()},
        )
        metadata = observed["metadata"]
        self.assertEqual(
            {fixture["approval_task_id"]},
            {item["approval_task_id"] for item in metadata.values()},
        )
        self.assertEqual(
            {fixture["intent_sha256"]},
            {item["intent_sha256"] for item in metadata.values()},
        )
        self.assertEqual(
            {result["task"]["unit"]},
            {item["executor_unit"] for item in metadata.values()},
        )
        self.assertEqual(
            {result["task"]["task_id"]},
            {
                item[tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_ACQUISITION_METADATA_KEY][
                    "task_id"
                ]
                for item in metadata.values()
            },
        )

    def test_runtime_refresh_orphan_server_acquisition_recovers_without_binding_journal(
        self,
    ) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        old_task_id = "7" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"],
            fixture["intent"],
            fixture["authority"],
            old_task_id,
            old_unit,
        )
        acquisition_journal = tasks._runtime_refresh_prelaunch_acquisition_journal(
            request
        )
        tasks._persist_runtime_refresh_prelaunch_acquisition_journal(
            acquisition_journal
        )
        acquisition = tasks._acquire_missing_runtime_refresh_prelaunch_leases(
            request, fixture["intent"]
        )
        self.assertIsNotNone(acquisition)
        metadata = self._runtime_refresh_lease_metadata(fixture["resource_keys"])
        self.assertEqual(
            {old_task_id},
            {
                item[tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_ACQUISITION_METADATA_KEY][
                    "task_id"
                ]
                for item in metadata.values()
            },
        )
        recovery = tasks._reconcile_runtime_refresh_prelaunch_binding_journals(
            fixture["resource_keys"]
        )
        released = [
            item
            for item in recovery["acquisition_recovery"]["recovered"]
            if item.get("action") == "server_acquisition_released"
        ]
        self.assertEqual(1, len(released))
        self.assertEqual(old_task_id, released[0]["task_id"])
        self.assertEqual(set(fixture["resource_keys"]), set(released[0]["resource_keys"]))
        self.assertEqual(
            [None] * len(fixture["resource_keys"]),
            [tasks.resources.inspect_resource(key) for key in fixture["resource_keys"]],
        )

    def test_runtime_refresh_orphan_server_acquisition_recovers_after_binding_journal(
        self,
    ) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        old_task_id = "8" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"],
            fixture["intent"],
            fixture["authority"],
            old_task_id,
            old_unit,
        )
        acquisition_journal = tasks._runtime_refresh_prelaunch_acquisition_journal(
            request
        )
        tasks._persist_runtime_refresh_prelaunch_acquisition_journal(
            acquisition_journal
        )
        acquisition = tasks._acquire_missing_runtime_refresh_prelaunch_leases(
            request, fixture["intent"]
        )
        self.assertIsNotNone(acquisition)
        plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            expected_approval_task_id=fixture["approval_task_id"],
            expected_intent_sha256=fixture["intent_sha256"],
        )
        journal = tasks._runtime_refresh_prelaunch_binding_journal(
            request, argv_sha256="9" * 64, binding_plan=plan
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(journal)
        tasks.resources.bind_runtime_refresh_executor_leases(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            prepared_binding=plan,
        )
        recovery = tasks._reconcile_runtime_refresh_prelaunch_binding_journals(
            fixture["resource_keys"]
        )
        self.assertTrue(
            any(
                item.get("task_id") == old_task_id
                and item.get("action") in {"restored", "already_original"}
                for item in recovery["recovered"]
            )
        )
        released = [
            item
            for item in recovery["acquisition_recovery"]["recovered"]
            if item.get("task_id") == old_task_id
            and item.get("action") == "server_acquisition_released"
        ]
        self.assertEqual(1, len(released))
        self.assertEqual(set(fixture["resource_keys"]), set(released[0]["resource_keys"]))
        self.assertEqual(
            [None] * len(fixture["resource_keys"]),
            [tasks.resources.inspect_resource(key) for key in fixture["resource_keys"]],
        )

    def test_runtime_refresh_task_reclaims_expired_foreign_intent_lease(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        first = fixture["resource_keys"][0]
        tasks.resources.acquire_resources(
            "runtime-refresh:expiredowner",
            [first],
            purpose="expired runtime refresh",
            ttl_seconds=1200,
            metadata={"marker": "expired"},
        )
        with sqlite3.connect(self.resource_database) as connection:
            connection.execute(
                "UPDATE leases SET expires_at_unix=1 WHERE resource_key=?",
                (first,),
            )
            connection.commit()
        with self._runtime_refresh_start_environment(fixture) as (
            dispatch_mock,
            _audit_mock,
        ):
            result = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )
        self.assertEqual(1, dispatch_mock.call_count)
        self.assertEqual(
            fixture["lease_owner"],
            tasks.resources.inspect_resource(first)["owner_id"],
        )
        self.assertEqual(
            result["task"]["unit"],
            self._runtime_refresh_lease_metadata([first])[first]["executor_unit"],
        )

    def test_runtime_refresh_task_foreign_intent_lease_blocks_before_server_acquire(
        self,
    ) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        first, second = fixture["resource_keys"]
        tasks.resources.acquire_resources(
            "runtime-refresh:foreignowner",
            [first],
            purpose="foreign runtime refresh",
            ttl_seconds=1200,
            metadata={"marker": "foreign"},
        )
        with self._runtime_refresh_start_environment(fixture) as (
            dispatch_mock,
            _audit_mock,
        ):
            with self.assertRaisesRegex(
                PermissionError, "resource lease is owned by another owner"
            ):
                tasks.grabowski_task_start(
                    "local",
                    fixture["argv"],
                    cwd=str(tasks.operator.HOME),
                    runtime_seconds=60,
                    resume_policy="never",
                )
        dispatch_mock.assert_not_called()
        self.assertIsNone(tasks.resources.inspect_resource(second))
        self.assertEqual(
            "runtime-refresh:foreignowner",
            tasks.resources.inspect_resource(first)["owner_id"],
        )

    def test_runtime_refresh_task_precommit_failure_releases_server_acquired_leases(
        self,
    ) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        with self._runtime_refresh_start_environment(fixture) as (
            dispatch_mock,
            _audit_mock,
        ):
            with patch.object(
                tasks,
                "_register_task_reconcile_sequence",
                side_effect=RuntimeError("forced precommit failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "forced precommit failure"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        dispatch_mock.assert_not_called()
        self.assertEqual(
            [None] * len(fixture["resource_keys"]),
            [
                tasks.resources.inspect_resource(key)
                for key in fixture["resource_keys"]
            ],
        )

    def test_runtime_refresh_task_precommit_failure_restores_external_leases(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "original",
        }
        acquired = tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh compensation",
            ttl_seconds=1200,
            metadata=metadata,
        )
        original = acquired["leases"]
        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            with patch.object(
                tasks,
                "_register_task_reconcile_sequence",
                side_effect=RuntimeError("forced precommit failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "forced precommit failure"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertEqual(0, dispatch_mock.call_count)
        self.assertEqual(
            original,
            [tasks.resources.inspect_resource(key) for key in fixture["resource_keys"]],
        )
        self.assertEqual(
            {key: metadata for key in fixture["resource_keys"]},
            self._runtime_refresh_lease_metadata(fixture["resource_keys"]),
        )

    def test_runtime_refresh_task_ambiguous_commit_retains_binding_for_reconcile(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh ambiguous commit",
            ttl_seconds=1200,
            metadata={
                "approval_task_id": fixture["approval_task_id"],
                "intent_sha256": fixture["intent_sha256"],
                "marker": "ambiguous",
            },
        )
        real_database_connection = tasks._database_connection

        class AmbiguousCommitConnection:
            def __init__(self, connection):
                self.connection = connection
                self.task_insert_seen = False

            def execute(self, sql, parameters=()):
                result = self.connection.execute(sql, parameters)
                if "INSERT INTO tasks(" in sql:
                    self.task_insert_seen = True
                return result

            def commit(self):
                self.connection.commit()
                if self.task_insert_seen:
                    raise RuntimeError("forced ambiguous task commit")

            def __getattr__(self, name):
                return getattr(self.connection, name)

        @contextmanager
        def ambiguous_database_connection():
            with real_database_connection() as connection:
                yield AmbiguousCommitConnection(connection)

        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            with patch.object(tasks, "_database_connection", ambiguous_database_connection):
                with self.assertRaisesRegex(
                    RuntimeError, "persistence requires reconciliation"
                ):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertEqual(0, dispatch_mock.call_count)
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT task_id, unit FROM tasks ORDER BY created_at_unix LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        metadata_by_key = self._runtime_refresh_lease_metadata(fixture["resource_keys"])
        self.assertEqual({row[1]}, {item["executor_unit"] for item in metadata_by_key.values()})
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(row[0]),),
            ).fetchone()
        self.assertIsNotNone(journal_row)

    def test_runtime_refresh_task_launch_failure_retains_committed_binding(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh launch failure",
            ttl_seconds=1200,
            metadata={
                "approval_task_id": fixture["approval_task_id"],
                "intent_sha256": fixture["intent_sha256"],
                "marker": "launch",
            },
        )
        with self._runtime_refresh_start_environment(fixture):
            with patch.object(tasks, "_launch", side_effect=RuntimeError("forced launch failure")):
                with self.assertRaisesRegex(RuntimeError, "forced launch failure"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT task_id, unit FROM tasks ORDER BY created_at_unix LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        metadata_by_key = self._runtime_refresh_lease_metadata(fixture["resource_keys"])
        self.assertEqual({row[1]}, {item["executor_unit"] for item in metadata_by_key.values()})
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(row[0]),),
            ).fetchone()
        self.assertIsNotNone(journal_row)

    def test_runtime_refresh_definitive_launch_failure_restores_external_leases(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "definitive-launch-failure",
        }
        original = tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh definitive launch failure",
            ttl_seconds=1200,
            metadata=metadata,
        )["leases"]
        with self._runtime_refresh_start_environment(fixture):
            with patch.object(tasks, "_launch", return_value=_launcher(1)):
                result = tasks.grabowski_task_start(
                    "local",
                    fixture["argv"],
                    cwd=str(tasks.operator.HOME),
                    runtime_seconds=60,
                    resume_policy="never",
                )
        self.assertEqual("failed", result["task"]["state"])
        self.assertEqual(
            original,
            [
                tasks.resources.inspect_resource(key)
                for key in fixture["resource_keys"]
            ],
        )
        self.assertEqual(
            {key: metadata for key in fixture["resource_keys"]},
            self._runtime_refresh_lease_metadata(fixture["resource_keys"]),
        )
        with sqlite3.connect(self.database) as connection:
            journals = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual([], journals)

    def test_runtime_refresh_live_authority_drift_blocks_before_journal_recovery(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "pending-live-drift-journal",
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh pending live drift journal",
            ttl_seconds=1200,
            metadata=metadata,
        )
        old_task_id = "e" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"],
            fixture["intent"],
            fixture["authority"],
            old_task_id,
            old_unit,
        )
        plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            expected_approval_task_id=fixture["approval_task_id"],
            expected_intent_sha256=fixture["intent_sha256"],
        )
        journal = tasks._runtime_refresh_prelaunch_binding_journal(
            request,
            argv_sha256="e" * 64,
            binding_plan=plan,
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(journal)
        tasks.resources.bind_runtime_refresh_executor_leases(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            prepared_binding=plan,
        )
        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            with (
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "load_bound_intent",
                    side_effect=[fixture["intent"], fixture["intent"]],
                ) as load_intent,
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "validate_authority_execution_contract",
                    side_effect=[
                        fixture["authority"],
                        PermissionError("simulated live authority drift before recovery"),
                    ],
                ) as validate_authority,
                patch.object(
                    tasks,
                    "_reconcile_runtime_refresh_prelaunch_binding_journals",
                    side_effect=AssertionError("journal recovery must not run"),
                ) as reconcile,
            ):
                with self.assertRaisesRegex(PermissionError, "drift before recovery"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertEqual(2, load_intent.call_count)
        self.assertEqual(2, validate_authority.call_count)
        reconcile.assert_not_called()
        dispatch_mock.assert_not_called()
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNotNone(journal_row)
        self.assertEqual(
            {old_unit},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )

    def test_runtime_refresh_live_authority_drift_blocks_before_lease_prepare(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "live-authority-drift",
        }
        original = tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh live authority drift",
            ttl_seconds=1200,
            metadata=metadata,
        )["leases"]
        real_prepare = tasks.resources.prepare_runtime_refresh_executor_lease_binding
        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            with (
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "load_bound_intent",
                    side_effect=[
                        fixture["intent"],
                        fixture["intent"],
                        fixture["intent"],
                    ],
                ) as load_intent,
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "validate_authority_execution_contract",
                    side_effect=[
                        fixture["authority"],
                        fixture["authority"],
                        PermissionError("simulated live authority drift"),
                    ],
                ) as validate_authority,
                patch.object(
                    tasks.resources,
                    "prepare_runtime_refresh_executor_lease_binding",
                    wraps=real_prepare,
                ) as prepare_binding,
            ):
                with self.assertRaisesRegex(PermissionError, "live authority drift"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertEqual(3, load_intent.call_count)
        self.assertEqual(3, validate_authority.call_count)
        prepare_binding.assert_not_called()
        dispatch_mock.assert_not_called()
        self.assertEqual(
            original,
            [
                tasks.resources.inspect_resource(key)
                for key in fixture["resource_keys"]
            ],
        )
        self.assertEqual(
            {key: metadata for key in fixture["resource_keys"]},
            self._runtime_refresh_lease_metadata(fixture["resource_keys"]),
        )
        with sqlite3.connect(self.database) as connection:
            journals = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual([], journals)

    def test_runtime_refresh_invalid_authority_precedes_dedup_and_journal_recovery(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "pending-journal",
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh pending journal",
            ttl_seconds=1200,
            metadata=metadata,
        )
        old_task_id = "f" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"],
            fixture["intent"],
            fixture["authority"],
            old_task_id,
            old_unit,
        )
        plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            expected_approval_task_id=fixture["approval_task_id"],
            expected_intent_sha256=fixture["intent_sha256"],
        )
        journal = tasks._runtime_refresh_prelaunch_binding_journal(
            request,
            argv_sha256="f" * 64,
            binding_plan=plan,
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(journal)
        tasks.resources.bind_runtime_refresh_executor_leases(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            prepared_binding=plan,
        )

        expired_payload = {
            key: value
            for key, value in fixture["intent"].items()
            if key != "intent_sha256"
        }
        expired_payload["expires_at"] = "2000-01-01T00:00:00Z"
        expired_digest = hashlib.sha256(
            (tasks._canonical_json(expired_payload) + "\n").encode("utf-8")
        ).hexdigest()
        expired_fixture = {
            **fixture,
            "intent": {**expired_payload, "intent_sha256": expired_digest},
            "intent_sha256": expired_digest,
            "lease_owner": f"runtime-refresh:{expired_digest[:16]}",
            "request": {
                **fixture["request"],
                "expected_intent_sha256": expired_digest,
                "lease_owner": f"runtime-refresh:{expired_digest[:16]}",
            },
        }

        with self._runtime_refresh_start_environment(expired_fixture):
            with (
                patch.object(
                    tasks,
                    "_resolve_task_operation_identity",
                    side_effect=AssertionError("dedup resolution must not run"),
                ) as resolve_operation,
                patch.object(
                    tasks,
                    "_reconcile_runtime_refresh_prelaunch_binding_journals",
                    side_effect=AssertionError("journal recovery must not run"),
                ) as reconcile,
            ):
                with self.assertRaisesRegex(ValueError, "approval expires too soon"):
                    tasks.grabowski_task_start(
                        "local",
                        expired_fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        resolve_operation.assert_not_called()
        reconcile.assert_not_called()
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNotNone(journal_row)
        self.assertEqual(
            {old_unit},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )

    def test_runtime_refresh_precommit_compensation_failure_preserves_primary_cause(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh compensation cause",
            ttl_seconds=1200,
            metadata={
                "approval_task_id": fixture["approval_task_id"],
                "intent_sha256": fixture["intent_sha256"],
                "marker": "compensation-cause",
            },
        )
        primary = sqlite3.OperationalError("forced primary persistence failure")
        secondary = RuntimeError("forced compensation failure")
        with self._runtime_refresh_start_environment(fixture):
            with (
                patch.object(
                    tasks,
                    "_register_task_reconcile_sequence",
                    side_effect=primary,
                ),
                patch.object(
                    tasks.resources,
                    "unbind_runtime_refresh_executor_leases",
                    side_effect=secondary,
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "compensation failed"
                ) as raised:
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        self.assertIs(primary, raised.exception.__cause__)
        self.assertIn(
            "RuntimeError: forced compensation failure", str(raised.exception)
        )

    def test_runtime_refresh_recovery_retains_journal_on_unbound_drift(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "recovery-drift",
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh recovery drift",
            ttl_seconds=1200,
            metadata=metadata,
        )
        old_task_id = "8" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"], fixture["intent"], fixture["authority"], old_task_id, old_unit
        )
        plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            expected_approval_task_id=fixture["approval_task_id"],
            expected_intent_sha256=fixture["intent_sha256"],
        )
        journal = tasks._runtime_refresh_prelaunch_binding_journal(
            request, argv_sha256="8" * 64, binding_plan=plan
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(journal)
        tasks.resources.renew_resources(
            fixture["lease_owner"],
            [fixture["resource_keys"][0]],
            ttl_seconds=1800,
        )
        with self.assertRaisesRegex(RuntimeError, "journal retained"):
            tasks._reconcile_runtime_refresh_prelaunch_binding_journals(
                fixture["resource_keys"]
            )
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNotNone(row)

    def test_runtime_refresh_undispatched_task_recovers_before_operation_identity(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "undispatched-crash",
        }
        tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh undispatched crash",
            ttl_seconds=1200,
            metadata=metadata,
        )
        operation_identity = {
            "repository_head": "1" * 40,
            "source_fingerprint_sha256": "2" * 64,
            "purpose": "runtime refresh undispatched recovery test",
            "scope_sha256": "3" * 64,
        }
        with self._runtime_refresh_start_environment(fixture):
            with (
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "operation_identity",
                    return_value=operation_identity,
                ),
                patch.object(
                    tasks,
                    "_launch",
                    side_effect=RuntimeError("simulated process death before dispatch"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "before dispatch"):
                    tasks.grabowski_task_start(
                        "local",
                        fixture["argv"],
                        cwd=str(tasks.operator.HOME),
                        runtime_seconds=60,
                        resume_policy="never",
                    )
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT task_id, state, unit FROM tasks ORDER BY created_at_unix LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(row)
        old_task_id, old_state, old_unit = row
        self.assertEqual("launching", old_state)
        self.assertEqual(
            {old_unit},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )

        missing_observation = {
            "state": "outcome_unknown",
            "properties": {
                "LoadState": "not-found",
                "ActiveState": "inactive",
                "SubState": "dead",
            },
            "probe": {
                "returncode": 4,
                "stdout": "LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
                "stderr": "",
                "timed_out": False,
                "outcome_unknown": False,
            },
            "observer": {"kind": "test"},
            "observed_at_unix": 123,
        }
        with self._runtime_refresh_start_environment(fixture):
            with (
                patch.object(
                    tasks.bureau_runtime_refresh_executor,
                    "operation_identity",
                    return_value=operation_identity,
                ),
                patch.object(
                    tasks,
                    "_read_local_task_output_files",
                    return_value=None,
                ) as read_output,
                patch.object(
                    tasks,
                    "_observe",
                    return_value=missing_observation,
                ) as observe,
            ):
                restarted = tasks.grabowski_task_start(
                    "local",
                    fixture["argv"],
                    cwd=str(tasks.operator.HOME),
                    runtime_seconds=60,
                    resume_policy="never",
                )
        read_output.assert_called_once()
        observe.assert_called_once()
        self.assertNotEqual(old_task_id, restarted["task"]["task_id"])
        old_record = tasks._row_raw(old_task_id)
        self.assertEqual("cancelled", old_record["state"])
        self.assertRegex(
            str(old_record["lifecycle_receipt_sha256"]), r"[0-9a-f]{64}\Z"
        )
        recovery = restarted["runtime_refresh_executor_prelaunch_recovery"]
        recovered = [
            item for item in recovery["recovered"] if item["task_id"] == old_task_id
        ]
        self.assertEqual(1, len(recovered))
        self.assertEqual("undispatched_cancelled", recovered[0]["action"])
        with sqlite3.connect(self.database) as connection:
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNone(journal_row)
        self.assertEqual(
            {restarted["task"]["unit"]},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )

    def test_runtime_refresh_orphan_binding_journal_recovers_after_hard_crash(self) -> None:
        fixture = self._runtime_refresh_prelaunch_fixture()
        metadata = {
            "approval_task_id": fixture["approval_task_id"],
            "intent_sha256": fixture["intent_sha256"],
            "marker": "orphan-prelaunch",
        }
        original = tasks.resources.acquire_resources(
            fixture["lease_owner"],
            fixture["resource_keys"],
            purpose="runtime refresh hard crash",
            ttl_seconds=1200,
            metadata=metadata,
        )["leases"]
        old_task_id = "d" * 24
        old_unit = f"grabowski-task-{old_task_id}-a1.service"
        request = tasks._runtime_refresh_prelaunch_lease_binding_request(
            fixture["request"], fixture["intent"], fixture["authority"], old_task_id, old_unit
        )
        plan = tasks.resources.prepare_runtime_refresh_executor_lease_binding(
            fixture["lease_owner"], fixture["resource_keys"], old_unit
        )
        journal = tasks._runtime_refresh_prelaunch_binding_journal(
            request,
            argv_sha256="e" * 64,
            binding_plan=plan,
        )
        tasks._persist_runtime_refresh_prelaunch_binding_journal(journal)
        tasks.resources.bind_runtime_refresh_executor_leases(
            fixture["lease_owner"],
            fixture["resource_keys"],
            old_unit,
            prepared_binding=plan,
        )

        # Simulate SIGKILL/process loss here: resource commit and durable journal exist,
        # but no task row was ever inserted and no Python exception handler ran.
        with sqlite3.connect(self.database) as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT task_id FROM tasks WHERE task_id=?", (old_task_id,)
                ).fetchone()
            )
            journal_row = connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                (tasks._runtime_refresh_prelaunch_journal_key(old_task_id),),
            ).fetchone()
        self.assertIsNotNone(journal_row)
        self.assertEqual(
            {old_unit},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )

        with self._runtime_refresh_start_environment(fixture) as (dispatch_mock, _audit_mock):
            started = tasks.grabowski_task_start(
                "local",
                fixture["argv"],
                cwd=str(tasks.operator.HOME),
                runtime_seconds=60,
                resume_policy="never",
            )

        self.assertEqual(1, dispatch_mock.call_count)
        self.assertNotEqual(old_unit, started["task"]["unit"])
        recovery = started["runtime_refresh_executor_prelaunch_recovery"]
        self.assertEqual(1, len(recovery["recovered"]))
        self.assertEqual(old_task_id, recovery["recovered"][0]["task_id"])
        self.assertEqual("restored", recovery["recovered"][0]["action"])
        self.assertEqual(
            {started["task"]["unit"]},
            {
                item["executor_unit"]
                for item in self._runtime_refresh_lease_metadata(
                    fixture["resource_keys"]
                ).values()
            },
        )
        with sqlite3.connect(self.database) as connection:
            remaining = connection.execute(
                "SELECT key FROM metadata WHERE key LIKE ?",
                (tasks.BUREAU_RUNTIME_REFRESH_PRELAUNCH_JOURNAL_KEY_PREFIX + "%",),
            ).fetchall()
        self.assertEqual([], remaining)
        self.assertNotEqual(
            original,
            [tasks.resources.inspect_resource(key) for key in fixture["resource_keys"]],
        )



class RuntimeContractTests(unittest.TestCase):
    def test_task_output_root_is_managed_state_with_explicit_legacy_home(self) -> None:
        self.assertEqual(
            tasks.TASK_OUTPUT_ROOT,
            tasks.operator.STATE_DIR / "task-output",
        )
        self.assertNotEqual(tasks.TASK_OUTPUT_ROOT, tasks.operator.HOME)
        self.assertEqual(tasks.TASK_OUTPUT_LEGACY_ROOT, tasks.operator.HOME)
        self.assertEqual(tasks.TASK_OUTPUT_CONTRACT_VERSION, 2)
        self.assertEqual(tasks.TASK_OUTPUT_LEGACY_CONTRACT_VERSION, 1)

    def test_reconcile_service_example_uses_refresh_not_resume(self) -> None:
        source = (
            ROOT / "systemd" / "grabowski-reconcile-tasks.service.example"
        ).read_text(encoding="utf-8")
        legacy = "--auto-" + "resume"
        self.assertNotIn(legacy, source)
        self.assertIn("--mode refresh", source)
        self.assertIn("--batch-size 100", source)
        self.assertNotIn("--mode resume", source)

    def test_reconcile_timer_waits_from_prior_run_completion(self) -> None:
        source = (
            ROOT / "systemd" / "grabowski-reconcile-tasks.timer.example"
        ).read_text(encoding="utf-8")
        self.assertIn("OnUnitInactiveSec=1min", source)
        self.assertNotIn("OnUnitActiveSec=", source)

    def test_shared_command_identity_is_in_runtime_contract(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        modules = {
            item["module"]: item["source"]
            for item in contract["supporting_sources"]
        }
        self.assertEqual(
            modules.get("grabowski_command_identity"),
            "src/grabowski_command_identity.py",
        )

    def test_runtime_registers_control_plane_and_tasks(self) -> None:
        source = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        for module in (
            "grabowski_fleet",
            "grabowski_operations",
            "grabowski_privileged",
            "grabowski_tasks",
            "grabowski_resources",
            "grabowski_checkouts",
            "grabowski_artifacts",
            "grabowski_workers",
            "grabowski_agent_workspace",
        ):
            self.assertIn(f"import {module}", source)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        expected = set(contract["expected_tools"])
        for tool in (
            "grabowski_fleet_list",
            "grabowski_fleet_run",
            "grabowski_operation_list",
            "grabowski_operation_plan",
            "grabowski_operation_run",
            "grabowski_privileged_broker_status",
            "grabowski_task_start",
            "grabowski_task_status",
            "grabowski_task_logs",
            "grabowski_task_cancel",
            "grabowski_task_resume",
            "grabowski_task_list",
            "grabowski_task_reconcile_check",
            "grabowski_task_reconcile_refresh",
            "grabowski_task_reconcile_resume",
            "grabowski_task_reconcile",
            "grabowski_resource_acquire",
            "grabowski_resource_renew",
            "grabowski_resource_release",
            "grabowski_resource_inspect",
            "grabowski_resource_list",
            "grabowski_checkout_inventory",
            "grabowski_checkout_retain",
            "grabowski_checkout_archive",
            "grabowski_checkout_cleanup",
            "grabowski_agent_workspace_create",
            "grabowski_agent_workspace_status",
            "grabowski_agent_workspace_attach",
            "grabowski_agent_workspace_collect",
            "grabowski_agent_workspace_close",
        ):
            self.assertIn(tool, expected)
        self.assertNotIn("grabowski_agent_workspace_adopt", expected)
        workspace_source = (ROOT / "src" / "grabowski_agent_workspace.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('name="grabowski_agent_workspace_adopt"', workspace_source)
        self.assertIn("manager.remove_tool(tool_name)", source)




class ChronikCodingMemoryToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "chronik"
        self.data_dir = self.root / "chronik-data"
        tools_dir = self.repository / "tools"
        tools_dir.mkdir(parents=True)
        self.cli = tools_dir / "coding_memory.py"
        self.cli.write_text(
            """#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def event_id(event):
    unsigned = dict(event)
    unsigned.pop('event_id', None)
    return 'sha256:' + hashlib.sha256(canonical(unsigned)).hexdigest()


def make_event(target_scope, target_value, index, operation, task_class, subject_component):
    task_id = ('a' if index == 0 else 'b') * 24
    subject = ({'scope': 'repository', 'repo': target_value}
               if target_scope == 'repository'
               else {'scope': 'host', 'host': target_value})
    if subject_component:
        subject['component'] = subject_component
    event = {
        'schema_version': 'agent-run-event.v0',
        'kind': 'agent.run.completed',
        'ts': '2026-07-19T00:00:00Z',
        'source': {'repo': 'heimgewebe/grabowski', 'component': 'grabowski', 'run_id': f'task-{task_id}-a1'},
        'subject': subject,
        'trust_tier': 'observed',
        'status': 'active',
        'caused_by': [],
        'evidence_refs': [f'grabowski-task:{task_id}', f'grabowski-unit:grabowski-task-{task_id}-a1.service'],
        'data': {'result': 'completed', 'operation': operation or 'other', 'task_class': task_class or 'coding'},
    }
    event['event_id'] = event_id(event)
    return event


parser = argparse.ArgumentParser()
parser.add_argument('--data-dir', required=True)
sub = parser.add_subparsers(dest='command', required=True)
imp = sub.add_parser('import')
imp.add_argument('input', type=Path)
query = sub.add_parser('query')
target = query.add_mutually_exclusive_group(required=True)
target.add_argument('--repo')
target.add_argument('--host')
query.add_argument('--component')
query.add_argument('--subject-component')
query.add_argument('--operation')
query.add_argument('--task-class')
query.add_argument('--outcome')
query.add_argument('--since')
query.add_argument('--limit', type=int, default=20)
args = parser.parse_args()
data_dir = Path(args.data_dir)

if args.command == 'import':
    data_dir.mkdir(parents=True, exist_ok=True)
    events = [json.loads(line) for line in args.input.read_text().splitlines() if line]
    ledger = data_dir / 'event-ids.json'
    existing = set(json.loads(ledger.read_text())) if ledger.exists() else set()
    incoming = {event['event_id'] for event in events}
    new = sorted(incoming - existing)
    ledger.write_text(json.dumps(sorted(existing | incoming)))
    receipt = {'schema_version': 'chronik-import-receipt.v1', 'domain': 'agent.ledger', 'event_ids': sorted(incoming), 'requested': len(incoming), 'imported': len(new), 'skipped_existing': len(incoming) - len(new), 'recorded_at': '2026-07-19T00:00:00Z', 'source_sha256': hashlib.sha256(b'\\n'.join(canonical(event) for event in events)).hexdigest(), 'historical_only': True, 'does_not_establish': ['current_git_state', 'current_ci_state', 'current_runtime_state', 'safe_retry']}
    unsigned = canonical(receipt)
    receipt['receipt_sha256'] = hashlib.sha256(unsigned).hexdigest()
    print(json.dumps(receipt))
else:
    if args.component == 'fail':
        raise SystemExit(2)
    target_scope = 'repository' if args.repo else 'host'
    target_value = args.repo or args.host
    fault = target_value.removeprefix('fault-') if target_value.startswith('fault-') else args.component
    events = [make_event(target_scope, target_value, index, args.operation, args.task_class, 'task-runner') for index in range(2)]
    if args.subject_component:
        events = [event for event in events if event['subject'].get('component') == args.subject_component]
    if fault == 'leak':
        events[0]['stdout'] = 'sensitive historical output'
    if fault == 'extra-data':
        events[0]['data']['summary'] = 'sensitive summary'
    if fault == 'extra-top':
        events[0]['metadata'] = 'sensitive metadata'
    if fault == 'bad-data-value':
        events[0]['data']['operation'] = 'sensitive-operation'
        events[0]['event_id'] = event_id(events[0])
    if fault == 'bad-event-target':
        events[0]['subject']['repo'] = 'heimgewebe/other'
        events[0]['event_id'] = event_id(events[0])
    query_value = {'repo': args.repo, 'host': args.host, 'component': args.component, 'operation': args.operation, 'task_class': args.task_class, 'outcome': args.outcome, 'since': args.since, 'limit': args.limit}
    if args.subject_component is not None:
        query_value['subject_component'] = args.subject_component
    if fault == 'bad-query':
        query_value['repo'] = 'heimgewebe/other'
    target_value_obj = ({'scope': 'repository', 'repo': args.repo}
                        if args.repo else {'scope': 'host', 'host': args.host})
    if fault == 'bad-target':
        target_value_obj = {'scope': 'repository', 'repo': 'heimgewebe/other'}
    snapshot = {'domain': 'agent.ledger', 'sha256': '0' * 64, 'complete_bytes': 123, 'total_record_count': 2, 'valid_record_count': 2, 'invalid_record_count': 0, 'integrity_valid': True, 'diagnostics': [], 'diagnostics_truncated': False}
    if fault == 'bad-integrity':
        snapshot.update({'valid_record_count': 1, 'invalid_record_count': 1, 'integrity_valid': False})
    if fault == 'bad-diagnostics':
        snapshot['diagnostics'] = ['sensitive diagnostic']
    history = {'schema_version': 'chronik-coding-history.v1', 'query': query_value, 'target': target_value_obj, 'events': events[:args.limit], 'event_ids': [event['event_id'] for event in events[:args.limit]], 'ledger_snapshot': snapshot, 'historical_only': True, 'does_not_establish': ['current_git_state', 'current_ci_state', 'current_runtime_state', 'safe_retry']}
    if fault == 'unknown-history':
        history['debug'] = 'sensitive debug output'
    if fault == 'extra-claims':
        history['does_not_establish'].append('sensitive claim')
    print(json.dumps(history))
""",
            encoding="utf-8",
        )
        self.outbox_dir = self.root / "state" / "grabowski" / "chronik-outbox"
        self.outbox_dir.mkdir(parents=True)
        context = {
            "subject_scope": "repository",
            "repo": "heimgewebe/grabowski",
            "operation": "implement",
            "task_class": "coding",
            "component": "task-runner",
            "bureau_task_id": "CCM-V1-T002",
            "pr_number": 404,
        }
        event = tasks.chronik.build_event(
            {
                "task_id": "c" * 24,
                "unit": "grabowski-task-" + "c" * 24 + "-a1.service",
                "attempt": 1,
                "created_at_unix": 1_700_000_000,
                "updated_at_unix": 1_700_000_100,
                "terminalized_at_unix": 1_700_000_200,
                "chronik_context_json": context,
            },
            "completed",
        )
        self.source = self.outbox_dir / "grabowski_task-cccccccccccccccccccccccc-a1.jsonl"
        self.source.write_bytes(tasks.chronik._canonical_bytes(event) + b"\n")
        self.audit_log = self.root / "state" / "write-audit.jsonl"
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.audit_log.parent, 0o700)
        self.audit_patch = patch.object(tasks.base, "AUDIT_LOG", self.audit_log)
        self.audit_patch.start()
        self.environment = patch.dict(
            os.environ,
            {
                tasks.chronik.CODING_MEMORY_REPO_ENV: str(self.repository),
                tasks.chronik.CODING_MEMORY_DATA_DIR_ENV: str(self.data_dir),
                tasks.chronik.CODING_MEMORY_PYTHON_ENV: sys.executable,
                tasks.chronik.STATE_ROOT_ENV: str(self.root / "state"),
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.audit_patch.stop()
        self.temporary.cleanup()

    def test_coding_memory_configuration_resolves_canonical_release_pointer(self) -> None:
        runtime_root = self.root / "chronik-runtime"
        release = runtime_root / "releases" / ("a" * 40)
        cli = release / "tools" / "coding_memory.py"
        cli.parent.mkdir(parents=True)
        cli.write_text("print('{}')\n", encoding="utf-8")
        current = runtime_root / "current"
        current.symlink_to(Path("releases") / release.name)
        with patch.dict(
            os.environ,
            {
                tasks.chronik.CODING_MEMORY_REPO_ENV: str(current),
                tasks.chronik.CODING_MEMORY_DATA_DIR_ENV: str(self.data_dir),
            },
            clear=False,
        ):
            configuration = tasks.chronik.coding_memory_configuration()
        self.assertTrue(configuration["available"])
        self.assertEqual(str(release), configuration["repository"])
        self.assertEqual(sys.executable, configuration["python"])
        self.assertEqual(str(cli), configuration["cli"])

    def test_coding_memory_configuration_default_python_ignores_developer_checkout(self) -> None:
        fake_home = self.root / "fake-home"
        developer_python = fake_home / "repos" / "chronik" / ".venv" / "bin" / "python"
        developer_python.parent.mkdir(parents=True)
        developer_python.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        developer_python.chmod(0o755)
        with patch.dict(
            os.environ,
            {
                "HOME": str(fake_home),
                tasks.chronik.CODING_MEMORY_REPO_ENV: str(self.repository),
                tasks.chronik.CODING_MEMORY_DATA_DIR_ENV: str(self.data_dir),
            },
            clear=True,
        ):
            configuration = tasks.chronik.coding_memory_configuration()
        self.assertEqual(sys.executable, configuration["python"])
        self.assertNotEqual(str(developer_python), configuration["python"])

    def test_coding_memory_configuration_rejects_missing_runtime_python(self) -> None:
        with patch.dict(
            os.environ,
            {tasks.chronik.CODING_MEMORY_PYTHON_ENV: str(self.root / "missing-python")},
            clear=False,
        ):
            configuration = tasks.chronik.coding_memory_configuration()
        self.assertFalse(configuration["available"])
        self.assertEqual("chronik_python_unavailable", configuration["reason"])

    def test_chronik_cli_run_uses_configured_runtime_python(self) -> None:
        configuration = {
            "python": "/opt/chronik-runtime/bin/python",
            "cli": "/opt/chronik-release/tools/coding_memory.py",
            "repository": str(self.repository),
        }
        with patch.object(
            tasks.operator,
            "_run",
            return_value={"returncode": 0, "stdout": "{}", "stderr": "", "timed_out": False},
        ) as run:
            tasks._chronik_cli_run(["query", "--repo=heimgewebe/grabowski"], configuration=configuration, data_dir=self.data_dir)
        command = run.call_args.args[0]
        self.assertEqual("/opt/chronik-runtime/bin/python", command[0])
        self.assertEqual("/opt/chronik-release/tools/coding_memory.py", command[1])

    def test_coding_memory_configuration_rejects_noncanonical_symlink(self) -> None:
        target = self.root / "foreign-chronik"
        (target / "tools").mkdir(parents=True)
        (target / "tools" / "coding_memory.py").write_text("print('{}')\n", encoding="utf-8")
        linked = self.root / "chronik-link"
        linked.symlink_to(target)
        with patch.dict(
            os.environ,
            {
                tasks.chronik.CODING_MEMORY_REPO_ENV: str(linked),
                tasks.chronik.CODING_MEMORY_DATA_DIR_ENV: str(self.data_dir),
            },
            clear=False,
        ):
            configuration = tasks.chronik.coding_memory_configuration()
        self.assertFalse(configuration["available"])
        self.assertEqual("chronik_repository_unavailable", configuration["reason"])

    def test_outbox_import_is_idempotent_hash_bound_and_preserves_source(self) -> None:
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            first = tasks.grabowski_chronik_outbox_import(str(self.source))
            second = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertTrue(first["available"])
        self.assertTrue(first["succeeded"])
        self.assertEqual(1, first["events_imported"])
        self.assertEqual(0, first["events_skipped_existing"])
        self.assertTrue(second["succeeded"])
        self.assertEqual(0, second["events_imported"])
        self.assertEqual(1, second["events_skipped_existing"])
        self.assertTrue(first["source_unchanged"])
        self.assertEqual(before, hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertRegex(first["receipt_sha256"], r"[0-9a-f]{64}\Z")

    def test_outbox_import_uses_validated_snapshot_even_if_original_changes(self) -> None:
        original_run = tasks._chronik_cli_run
        calls = 0

        def run_and_mutate(*args, **kwargs):
            nonlocal calls
            result = original_run(*args, **kwargs)
            calls += 1
            if calls == 1:
                self.source.write_bytes(self.source.read_bytes() + b"changed-after-snapshot\n")
            return result

        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"), patch.object(tasks, "_chronik_cli_run", side_effect=run_and_mutate):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertTrue(result["available"])
        self.assertTrue(result["succeeded"])
        self.assertFalse(result["source_unchanged"])
        self.assertFalse(result["outcome_unknown"])
        self.assertEqual(1, result["events_imported"])

    def test_outbox_import_accepts_host_subject_without_optional_metadata(self) -> None:
        context = {
            "subject_scope": "host",
            "host": "heim-pc",
            "operation": "recovery",
            "task_class": "recovery",
        }
        event = tasks.chronik.build_event(
            {
                "task_id": "c" * 24,
                "unit": "grabowski-task-" + "c" * 24 + "-a1.service",
                "attempt": 1,
                "created_at_unix": 1_700_000_000,
                "updated_at_unix": 1_700_000_100,
                "terminalized_at_unix": 1_700_000_200,
                "chronik_context_json": context,
            },
            "completed",
        )
        self.source.write_bytes(tasks.chronik._canonical_bytes(event) + b"\n")
        with (
            patch.object(tasks.operator, "_require_operator_mutation"),
            patch.object(tasks.base, "_append_audit"),
        ):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertTrue(result["available"])
        self.assertTrue(result["succeeded"])
        self.assertEqual(1, result["events_imported"])

    def test_outbox_import_rejects_invalid_receipt_digest_without_real_mutation(self) -> None:
        source = self.cli.read_text(encoding="utf-8")
        self.cli.write_text(
            source.replace(
                "receipt['receipt_sha256'] = hashlib.sha256(unsigned).hexdigest()",
                "receipt['receipt_sha256'] = '0' * 64",
            ),
            encoding="utf-8",
        )
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(result["available"])
        self.assertFalse(result["succeeded"])
        self.assertFalse(result["outcome_unknown"])
        self.assertFalse((self.data_dir / "event-ids.json").exists())
        self.assertEqual("chronik_coding_memory_preflight_failed", result["failure"]["code"])
        self.assertIn("receipt digest", result["failure"]["contract_error"])

    def test_outbox_import_rejects_noncanonical_state_root(self) -> None:
        foreign = self.root / "foreign" / "chronik-outbox" / self.source.name
        foreign.parent.mkdir(parents=True)
        foreign.write_bytes(self.source.read_bytes())
        with patch.object(tasks.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(ValueError, "configured state root"):
                tasks.grabowski_chronik_outbox_import(str(foreign))

    def test_outbox_import_rejects_non_allowlisted_event_fields(self) -> None:
        for location, key, value in (("data", "summary", "secret"), ("top", "metadata", "secret")):
            event = json.loads(self.source.read_text(encoding="utf-8"))
            if location == "data":
                event["data"][key] = value
            else:
                event[key] = value
            event["event_id"] = tasks.chronik.event_id(event)
            self.source.write_bytes(tasks.chronik._canonical_bytes(event) + b"\n")
            with patch.object(tasks.operator, "_require_operator_mutation"):
                with self.assertRaisesRegex(ValueError, "invalid fields|invalid data"):
                    tasks.grabowski_chronik_outbox_import(str(self.source))
            self.setUp_source_again()

    def setUp_source_again(self) -> None:
        context = {"subject_scope": "repository", "repo": "heimgewebe/grabowski", "operation": "implement", "task_class": "coding", "component": "task-runner", "bureau_task_id": "CCM-V1-T002", "pr_number": 404}
        event = tasks.chronik.build_event({"task_id": "c" * 24, "unit": "grabowski-task-" + "c" * 24 + "-a1.service", "attempt": 1, "created_at_unix": 1_700_000_000, "updated_at_unix": 1_700_000_100, "terminalized_at_unix": 1_700_000_200, "chronik_context_json": context}, "completed")
        self.source.write_bytes(tasks.chronik._canonical_bytes(event) + b"\n")

    def test_history_is_bounded_and_explicitly_historical(self) -> None:
        with patch.object(tasks.operator, "_require_operator_mutation"):
            tasks.grabowski_chronik_outbox_import(str(self.source))
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(repo="heimgewebe/grabowski", operation="implement", limit=1)
        self.assertTrue(result["available"])
        self.assertTrue(result["historical_only"])
        self.assertEqual(1, len(result["events"]))
        self.assertEqual(1, len(result["history"]["event_ids"]))
        self.assertNotIn("events", result["history"])
        self.assertEqual({"scope": "repository", "repo": "heimgewebe/grabowski"}, result["history"]["target"])
        self.assertTrue(result["history"]["ledger_snapshot"]["integrity_valid"])

    def test_history_matcher_supports_v1_execution_outcomes(self) -> None:
        event = json.loads(self.source.read_text(encoding="utf-8"))
        normalized = {
            "repo": "heimgewebe/grabowski",
            "host": "",
            "component": "",
            "subject_component": "",
            "operation": "",
            "task_class": "",
            "outcome": "",
        }
        for kind in {
            "agent.run.started",
            "agent.run.completed",
            "agent.run.failed",
            "agent.run.cancelled",
            "agent.run.timed_out",
            "agent.run.signalled",
            "agent.run.blocked",
        }:
            with self.subTest(kind=kind):
                candidate = json.loads(json.dumps(event))
                candidate["schema_version"] = "agent-run-event.v1"
                candidate["kind"] = kind
                candidate["data"]["result"] = kind.removeprefix("agent.run.")
                if kind == "agent.run.blocked":
                    candidate["data"]["blocker_code"] = "task-outcome-unknown"
                else:
                    candidate["data"].pop("blocker_code", None)
                candidate["event_id"] = tasks.chronik.event_id(candidate)
                self.assertTrue(
                    tasks._chronik_history_event_matches_query(
                        candidate, normalized, since_timestamp=None
                    )
                )

        legacy = json.loads(json.dumps(event))
        legacy["schema_version"] = "agent-run-event.v0"
        legacy["kind"] = "agent.run.completed"
        legacy["data"]["result"] = "completed"
        legacy["data"].pop("blocker_code", None)
        legacy["event_id"] = tasks.chronik.event_id(legacy)
        self.assertTrue(
            tasks._chronik_history_event_matches_query(
                legacy, normalized, since_timestamp=None
            )
        )
        legacy["kind"] = "agent.run.failed"
        legacy["data"]["result"] = "failed"
        legacy["event_id"] = tasks.chronik.event_id(legacy)
        self.assertFalse(
            tasks._chronik_history_event_matches_query(
                legacy, normalized, since_timestamp=None
            )
        )

    def test_history_component_filter_uses_chronik_source_component(self) -> None:
        event = json.loads(self.source.read_text(encoding="utf-8"))
        self.assertEqual("task-runner", event["subject"]["component"])
        self.assertEqual("grabowski", event["source"]["component"])
        normalized = {
            "repo": "heimgewebe/grabowski",
            "host": "",
            "component": "grabowski",
            "subject_component": "",
            "operation": "",
            "task_class": "",
            "outcome": "",
            "since": "",
        }
        self.assertTrue(
            tasks._chronik_history_event_matches_query(
                event, normalized, since_timestamp=None
            )
        )
        normalized["component"] = "task-runner"
        self.assertFalse(
            tasks._chronik_history_event_matches_query(
                event, normalized, since_timestamp=None
            )
        )
        normalized["component"] = "grabowski"
        normalized["subject_component"] = "task-runner"
        self.assertTrue(
            tasks._chronik_history_event_matches_query(
                event, normalized, since_timestamp=None
            )
        )
        normalized["subject_component"] = "grabowski"
        self.assertFalse(
            tasks._chronik_history_event_matches_query(
                event, normalized, since_timestamp=None
            )
        )

    def test_history_subject_component_filter_is_explicit_and_query_bound(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(
                repo="heimgewebe/grabowski",
                component="grabowski",
                subject_component="task-runner",
                limit=1,
            )
        self.assertTrue(result["available"])
        self.assertEqual("task-runner", result["query"]["subject_component"])
        self.assertEqual("task-runner", result["history"]["query"]["subject_component"])
        self.assertEqual(1, len(result["events"]))

    def test_history_subject_component_filter_can_return_no_matches(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(
                repo="heimgewebe/grabowski", subject_component="other", limit=2
            )
        self.assertTrue(result["available"])
        self.assertEqual([], result["events"])
        self.assertEqual([], result["history"]["event_ids"])

    def test_history_rejects_unredacted_or_extra_event_fields_without_exposure(self) -> None:
        for component, secret in (("leak", "sensitive historical output"), ("extra-data", "sensitive summary"), ("extra-top", "sensitive metadata"), ("bad-data-value", "sensitive-operation")):
            with patch.object(tasks.operator, "_require_operator_capability"):
                result = tasks.grabowski_chronik_history(repo="heimgewebe/grabowski", component=component, limit=2)
            self.assertFalse(result["available"])
            self.assertEqual([], result["events"])
            self.assertNotIn(secret, json.dumps(result))

    def test_history_rejects_unbound_query_target_and_invalid_ledger(self) -> None:
        for component, marker in (("bad-query", "query"), ("bad-target", "target")):
            with patch.object(tasks.operator, "_require_operator_capability"):
                result = tasks.grabowski_chronik_history(repo="heimgewebe/grabowski", component=component, limit=2)
            self.assertFalse(result["available"])
            self.assertIn(marker, result["failure"]["contract_error"])
        for fault, marker in (("bad-integrity", "integrity"), ("bad-diagnostics", "fields")):
            with patch.object(tasks.operator, "_require_operator_capability"):
                result = tasks.grabowski_chronik_history(host=f"fault-{fault}", limit=2)
            self.assertFalse(result["available"])
            self.assertIn(marker, result["failure"]["contract_error"])

    def test_history_rejects_unknown_top_level_cli_fields_without_exposure(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(repo="heimgewebe/grabowski", component="unknown-history")
        self.assertFalse(result["available"])
        self.assertNotIn("sensitive debug output", json.dumps(result))
        self.assertIn("invalid fields", result["failure"]["contract_error"])

    def test_history_rejects_extra_truth_claims_without_exposure(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(host="fault-extra-claims")
        self.assertFalse(result["available"])
        self.assertNotIn("sensitive claim", json.dumps(result))
        self.assertIn("truth exclusions", result["failure"]["contract_error"])

    def test_history_rejects_event_outside_requested_target_without_exposure(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(
                repo="heimgewebe/grabowski", component="bad-event-target", limit=2
            )
        self.assertFalse(result["available"])
        self.assertEqual([], result["events"])
        self.assertIn("requested query", result["failure"]["contract_error"])
        self.assertNotIn("heimgewebe/other", json.dumps(result))

    def test_history_rejects_invalid_since_before_cli_execution(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"), patch.object(tasks, "_chronik_cli_run") as cli_run:
            with self.assertRaisesRegex(ValueError, "ISO-8601"):
                tasks.grabowski_chronik_history(
                    repo="heimgewebe/grabowski", since="not-a-timestamp"
                )
        cli_run.assert_not_called()

    def test_history_rejects_cli_result_bound_to_different_query(self) -> None:
        with patch.object(tasks.operator, "_require_operator_capability"):
            result = tasks.grabowski_chronik_history(
                repo="heimgewebe/grabowski", component="bad-query", limit=2
            )
        self.assertFalse(result["available"])
        self.assertIn("query is unbound", result["failure"]["contract_error"])

    def test_bad_preflight_never_mutates_real_data_dir(self) -> None:
        self.cli.write_text("import json\nprint(json.dumps({'schema_version': 'legacy-import.v0'}))\n", encoding="utf-8")
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(result["succeeded"])
        self.assertFalse(result["outcome_unknown"])
        self.assertFalse((self.data_dir / "event-ids.json").exists())
        self.assertEqual("chronik_coding_memory_preflight_failed", result["failure"]["code"])

    def test_import_receipt_unknown_field_is_rejected_before_real_mutation(self) -> None:
        source = self.cli.read_text(encoding="utf-8")
        self.cli.write_text(source.replace("unsigned = canonical(receipt)", "receipt['debug'] = 'secret'\n    unsigned = canonical(receipt)"), encoding="utf-8")
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(result["succeeded"])
        self.assertFalse((self.data_dir / "event-ids.json").exists())
        self.assertNotIn("secret", json.dumps(result))
        self.assertIn("invalid fields", result["failure"]["contract_error"])

    def test_import_receipt_extra_truth_claim_is_rejected_before_real_mutation(self) -> None:
        source = self.cli.read_text(encoding="utf-8")
        self.cli.write_text(source.replace("unsigned = canonical(receipt)", "receipt['does_not_establish'].append('sensitive-claim')\n    unsigned = canonical(receipt)"), encoding="utf-8")
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            result = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(result["succeeded"])
        self.assertFalse((self.data_dir / "event-ids.json").exists())
        self.assertNotIn("sensitive-claim", json.dumps(result))
        self.assertIn("truth exclusions", result["failure"]["contract_error"])

    def test_missing_or_failing_cli_is_visible_without_success_claim(self) -> None:
        self.cli.unlink()
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            imported = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(imported["available"])
        self.assertFalse(imported["succeeded"])
        self.assertEqual("chronik_coding_memory_cli_unavailable", imported["failure"]["code"])
        self.cli.write_text("import sys\nraise SystemExit(2)\n", encoding="utf-8")
        with patch.object(tasks.operator, "_require_operator_mutation"), patch.object(tasks.base, "_append_audit"):
            failed_import = tasks.grabowski_chronik_outbox_import(str(self.source))
        self.assertFalse(failed_import["available"])
        self.assertFalse(failed_import["succeeded"])
        self.assertFalse(failed_import["outcome_unknown"])
        with patch.object(tasks.operator, "_require_operator_capability"):
            history = tasks.grabowski_chronik_history(repo="heimgewebe/grabowski", component="fail")
        self.assertFalse(history["available"])
        self.assertEqual("chronik_coding_memory_cli_failed", history["failure"]["code"])
        self.assertEqual([], history["events"])


    def test_deployed_runtime_tool_executes_historical_recall(self) -> None:
        event = {
            "schema_version": "agent-run-event.v0",
            "kind": "agent.run.completed",
            "ts": "2026-07-28T18:37:00Z",
            "source": {
                "repo": "heimgewebe/grabowski",
                "component": "grabowski",
                "run_id": "task-0123456789abcdef01234567-a1",
            },
            "subject": {
                "scope": "host",
                "host": "heim-pc",
                "component": "operator-convergence",
            },
            "trust_tier": "observed",
            "status": "active",
            "caused_by": [],
            "evidence_refs": ["grabowski-task:0123456789abcdef01234567"],
            "data": {
                "result": "completed",
                "operation": "operator-convergence-check",
                "task_class": "runtime_verify",
            },
        }
        event["event_id"] = tasks.recall._chronik_event_id(event)
        query = {
            "host": "heim-pc",
            "operation": "operator-convergence-check",
            "limit": 1,
        }
        history = {
            "schema_version": 1,
            "kind": "grabowski_chronik_history",
            "query": query,
            "cli_present": True,
            "available": True,
            "historical_only": True,
            "events": [event],
            "history": {
                "schema_version": "chronik-coding-history.v1",
                "query": query,
                "target": {"scope": "host", "host": "heim-pc"},
                "event_ids": [event["event_id"]],
                "historical_only": True,
                "does_not_establish": list(
                    tasks.recall.CHRONIK_HISTORY_DOES_NOT_ESTABLISH
                ),
                "ledger_snapshot": {"sha256": "b" * 64},
            },
            "does_not_establish": list(
                tasks.recall.CHRONIK_HISTORY_DOES_NOT_ESTABLISH
            ),
        }
        history["result_sha256"] = tasks.recall._sha256_json(history)

        with (
            patch.object(tasks.operator, "_require_operator_capability") as capability,
            patch.object(
                tasks, "grabowski_chronik_history", return_value=history
            ) as provider,
        ):
            result = tasks.grabowski_operator_historical_recall(
                host="heim-pc",
                operation="operator-convergence-check",
                limit=1,
            )

        capability.assert_called_once_with("durable_job")
        provider.assert_called_once_with(
            repo="",
            host="heim-pc",
            component="",
            subject_component="",
            operation="operator-convergence-check",
            task_class="",
            outcome="",
            since="",
            limit=1,
        )
        self.assertTrue(result["available"])
        self.assertEqual(result["returned"], 1)
        self.assertEqual(
            result["result_reference"]["result_sha256"],
            history["result_sha256"],
        )
        self.assertEqual(
            result["result_reference"]["ledger_snapshot_sha256"],
            "b" * 64,
        )

    def test_deployed_runtime_tool_reports_missing_recall_helper(self) -> None:
        manifest = self.root / "deployment-manifest.json"
        manifest.write_text(
            json.dumps({"source_commit": "a" * 40}),
            encoding="utf-8",
        )
        with (
            patch.object(tasks.operator, "_require_operator_capability", None),
            patch.object(tasks.base, "DEPLOYMENT_MANIFEST", manifest),
            patch.object(tasks, "grabowski_chronik_history") as provider,
        ):
            result = tasks.grabowski_operator_historical_recall(
                operation="operator-convergence-check",
                limit=1,
            )

        provider.assert_not_called()
        self.assertFalse(result["available"])
        self.assertEqual(
            result["failure_code"],
            "operator_runtime_dependency_missing",
        )
        self.assertEqual(
            result["failure"]["tool"],
            "grabowski_operator_historical_recall",
        )
        self.assertEqual(result["failure"]["runtime_head"], "a" * 40)
        self.assertEqual(result["failure"]["capability"], "durable_job")
        self.assertTrue(
            result["failure"]["missing_dependency"].endswith(
                "._require_operator_capability"
            )
        )





if __name__ == "__main__":
    unittest.main()
