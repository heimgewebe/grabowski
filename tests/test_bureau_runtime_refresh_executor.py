from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_bureau_runtime_refresh_executor as executor
import grabowski_fleet as fleet
import grabowski_operator as operator
import grabowski_tasks as tasks


INTENT_SHA = "a" * 64
TARGET_SHA = "b" * 64
MAIN_SHA = "c" * 40
TASK_ID = "BUREAU-RUNTIME-REFRESH-TEST"
LEASE_OWNER = "runtime-refresh:test-executor"
AUTH_SHA = "e" * 64
GRABOWSKI_TASK_ID = "1" * 24
GRABOWSKI_TASK_UNIT = f"grabowski-task-{GRABOWSKI_TASK_ID}-a1.service"


def _intent_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "bureau_runtime_refresh_intent",
        "intent_sha256": INTENT_SHA,
        "state_root": str(executor.CANONICAL_STATE_ROOT),
        "prefix": "/home/alex/.local/share/bureau",
        "approval_task_id": TASK_ID,
        "main_commit": MAIN_SHA,
        "target_sha256": TARGET_SHA,
        "authority_state_store": {
            "state_db": str(executor.CANONICAL_BUREAU_STATE_DB),
            "state_root": str(executor.CANONICAL_BUREAU_STATE_DB.parent),
        },
        "authority_task_spec": {
            "revision": 1,
            "spec_sha256": AUTH_SHA,
        },
    }


def _preflight_intent(root: str) -> dict[str, object]:
    intent = _intent_payload()
    for field in executor.INTENT_MUTATION_ROOT_FIELDS:
        intent[field] = root
    authority = dict(intent["authority_state_store"])
    authority["state_root"] = root
    intent["authority_state_store"] = authority
    return intent


def _task_environment() -> dict[str, str]:
    return executor.task_identity_environment(GRABOWSKI_TASK_ID, GRABOWSKI_TASK_UNIT)


def _authority_contract() -> dict[str, object]:
    return {
        "schema_version": 1,
        "task_id": TASK_ID,
        "revision": 1,
        "spec_sha256": AUTH_SHA,
        "contract": executor.EXPECTED_RUNTIME_EXECUTION_CONTEXT,
        "execution_contract_sha256": executor._sha256_json(
            executor.EXPECTED_RUNTIME_EXECUTION_CONTEXT
        ),
    }


def _request() -> dict[str, str]:
    return {
        "intent": str(executor.CANONICAL_INTENTS_ROOT / f"{INTENT_SHA}.json"),
        "expected_intent_sha256": INTENT_SHA,
        "lease_owner": LEASE_OWNER,
        "lease_task_id": TASK_ID,
    }


def _reserved_argv() -> list[str]:
    request = _request()
    return [
        executor.RESERVED_TASK_COMMAND,
        "--intent",
        request["intent"],
        "--expected-intent-sha256",
        INTENT_SHA,
        "--lease-owner",
        LEASE_OWNER,
        "--lease-task-id",
        TASK_ID,
    ]


class BureauRuntimeRefreshExecutorTests(unittest.TestCase):
    def test_generic_surfaces_reject_direct_runtime_refresh_apply(self) -> None:
        argv = [
            "/home/alex/.local/bin/bureau-runtime-refresh",
            "--state-root",
            str(executor.CANONICAL_STATE_ROOT),
            "apply",
            "--intent",
            str(executor.CANONICAL_INTENTS_ROOT / f"{INTENT_SHA}.json"),
            "--lease-owner",
            LEASE_OWNER,
            "--lease-task-id",
            TASK_ID,
        ]
        for surface in (
            "grabowski_terminal_run",
            "grabowski_fleet_run",
            "grabowski_task_start",
        ):
            with self.assertRaisesRegex(PermissionError, "direct bureau-runtime-refresh apply"):
                executor.reject_generic_runtime_refresh_execution(argv, surface=surface)

    def test_generic_surfaces_reject_simple_wrapped_runtime_refresh_apply(self) -> None:
        wrapped = [
            [
                "env",
                "LANG=C",
                "/home/alex/.local/bin/bureau-runtime-refresh",
                "apply",
            ],
            [
                "bash",
                "-lc",
                "/home/alex/.local/bin/bureau-runtime-refresh --state-root /tmp/x apply",
            ],
            ["python3", "-m", "bureau.runtime_refresh", "apply"],
            [
                "python3",
                "-c",
                "from bureau import runtime_refresh; runtime_refresh.apply_runtime_refresh()",
            ],
        ]
        for argv in wrapped:
            with self.assertRaisesRegex(PermissionError, "direct bureau-runtime-refresh apply"):
                executor.reject_generic_runtime_refresh_execution(
                    argv, surface="grabowski_task_start"
                )

    def test_python_options_before_module_do_not_bypass_executor_guard(self) -> None:
        request = _request()
        argv = [
            "python3",
            "-u",
            "-X",
            "faulthandler",
            "-m",
            executor.EXECUTOR_MODULE,
            "--intent",
            request["intent"],
            "--expected-intent-sha256",
            INTENT_SHA,
            "--lease-owner",
            LEASE_OWNER,
            "--lease-task-id",
            TASK_ID,
        ]
        self.assertTrue(executor.is_executor_module_command(argv))
        self.assertEqual(request, executor.parse_executor_module_request(argv))
        with self.assertRaisesRegex(PermissionError, "reserved for grabowski_task_start"):
            executor.reject_generic_runtime_refresh_execution(
                argv, surface="grabowski_terminal_run"
            )
        self.assertTrue(
            executor.is_direct_bureau_runtime_refresh_apply(
                ["python3", "-I", "-m", "bureau.runtime_refresh", "apply"]
            )
        )

    def test_unrelated_runtime_refresh_search_terms_are_not_blocked(self) -> None:
        harmless = [
            ["rg", "apply", "docs/runtime_refresh.md"],
            ["grep", "apply", "notes/bureau-runtime-refresh.txt"],
            ["cat", "apply_runtime_refresh.py"],
        ]
        for argv in harmless:
            executor.reject_generic_runtime_refresh_execution(
                argv, surface="grabowski_terminal_run"
            )

    def test_terminal_and_fleet_guards_run_before_process_start(self) -> None:
        raw = ["/home/alex/.local/bin/bureau-runtime-refresh", "apply"]
        terminal_started = False
        fleet_started = False

        def terminal_run(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal terminal_started
            terminal_started = True
            return {}

        def fleet_run(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal fleet_started
            fleet_started = True
            return {}

        with (
            patch.object(operator, "_require_operator_mutation", lambda *_a, **_k: None),
            patch.object(operator, "_run", terminal_run),
            patch.object(fleet, "run_fleet_host", fleet_run),
            patch.object(
                fleet,
                "fleet_host",
                lambda _host: {"transport": "local", "target": "local"},
            ),
        ):
            with self.assertRaisesRegex(PermissionError, "direct bureau-runtime-refresh apply"):
                operator.grabowski_terminal_run(raw, cwd=str(ROOT))
            with self.assertRaisesRegex(PermissionError, "direct bureau-runtime-refresh apply"):
                fleet.grabowski_fleet_run("heim-pc", raw)
            with self.assertRaisesRegex(PermissionError, "direct bureau-runtime-refresh apply"):
                operator.grabowski_job_start(raw, cwd=str(ROOT))
        self.assertFalse(terminal_started)
        self.assertFalse(fleet_started)

    def test_reserved_task_request_is_server_bound_and_never_resumable(self) -> None:
        request = _request()
        intent = _intent_payload()
        runtime_python = Path("/tmp/grabowski-runtime-python")
        with (
            patch.object(
                tasks.fleet,
                "fleet_host",
                lambda _host: {"transport": "local", "target": "local"},
            ),
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", runtime_python),
            patch.object(executor, "load_bound_intent", lambda observed: intent if observed == request else None),
            patch.object(executor, "parse_reserved_task_request", lambda _argv: request),
            patch.object(
                executor,
                "validate_authority_execution_contract",
                lambda _intent: _authority_contract(),
            ),
            patch.object(
                executor,
                "build_executor_command",
                lambda observed, runtime_python: [
                    str(runtime_python),
                    "-m",
                    executor.EXECUTOR_MODULE,
                    "--bound",
                ],
            ),
            patch.object(tasks, "_validate_command", lambda command: list(command)),
            patch.object(tasks, "_require_recovery_gate", lambda _command: None),
            patch.object(tasks, "_validate_cwd", lambda _host, _cwd: "/home/alex"),
            patch.object(
                tasks,
                "_bind_grabowski_runtime_python",
                lambda command, **_kwargs: command,
            ),
        ):
            with self.assertRaisesRegex(ValueError, "resume_policy=never"):
                tasks.grabowski_task_start(
                    "heim-pc",
                    _reserved_argv(),
                    cwd="/home/alex",
                    resume_policy="verify-then-retry",
                )
            supplied_identity = {
                "repository_head": MAIN_SHA,
                "source_fingerprint_sha256": INTENT_SHA,
                "purpose": "caller supplied",
                "scope_sha256": TARGET_SHA,
            }
            with self.assertRaisesRegex(ValueError, "operation_identity is server-owned"):
                tasks.grabowski_task_start(
                    "heim-pc",
                    _reserved_argv(),
                    cwd="/home/alex",
                    resume_policy="never",
                    operation_identity=supplied_identity,
                )

        with (
            patch.object(
                tasks.fleet,
                "fleet_host",
                lambda _host: {"transport": "local", "target": "local"},
            ),
            patch.object(tasks, "GRABOWSKI_RUNTIME_PYTHON", runtime_python),
            patch.object(executor, "load_bound_intent", lambda _request: intent),
            patch.object(executor, "parse_reserved_task_request", lambda _argv: request),
            patch.object(
                executor,
                "validate_authority_execution_contract",
                lambda _intent: _authority_contract(),
            ),
            patch.object(
                executor,
                "build_executor_command",
                lambda observed, runtime_python: [str(runtime_python), "-m", executor.EXECUTOR_MODULE],
            ),
            patch.object(tasks, "_validate_command", lambda command: list(command)),
            patch.object(tasks, "_require_recovery_gate", lambda _command: None),
            patch.object(tasks, "_validate_cwd", lambda _host, _cwd: "/tmp"),
        ):
            with self.assertRaisesRegex(ValueError, "requires cwd=/home/alex"):
                tasks.grabowski_task_start(
                    "heim-pc",
                    _reserved_argv(),
                    cwd="/tmp",
                    resume_policy="never",
                )

    def test_execution_context_preflight_rejects_read_only_mount(self) -> None:
        request = _request()
        with tempfile.TemporaryDirectory() as directory:
            intent = _preflight_intent(directory)
            with (
                patch.dict(os.environ, _task_environment(), clear=False),
                patch.object(
                    executor.os, "statvfs", lambda _path: SimpleNamespace(f_flag=os.ST_RDONLY)
                ),
                patch.object(executor.os, "access", lambda _path, _mode: False),
                patch.object(
                    executor.subprocess,
                    "run",
                    lambda *_a, **_k: SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(
                            {
                                "filesystems": [
                                    {
                                        "target": "/",
                                        "fstype": "ext4",
                                        "options": "ro,nosuid",
                                    }
                                ]
                            }
                        ),
                        stderr="",
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    executor.BureauRuntimeRefreshExecutorError, "not writable"
                ):
                    executor.execution_context_preflight(
                        request, intent, _authority_contract()
                    )

    def test_execution_context_preflight_rejects_non_searchable_directory(self) -> None:
        request = _request()
        with tempfile.TemporaryDirectory() as directory:
            intent = _preflight_intent(directory)

            def access(_path: object, mode: int) -> bool:
                return mode == os.W_OK

            with (
                patch.dict(os.environ, _task_environment(), clear=False),
                patch.object(executor.os, "statvfs", lambda _path: SimpleNamespace(f_flag=0)),
                patch.object(executor.os, "access", access),
                patch.object(
                    executor.subprocess,
                    "run",
                    lambda *_a, **_k: SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(
                            {
                                "filesystems": [
                                    {"target": "/", "fstype": "ext4", "options": "rw"}
                                ]
                            }
                        ),
                        stderr="",
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    executor.BureauRuntimeRefreshExecutorError, "not writable"
                ):
                    executor.execution_context_preflight(
                        request, intent, _authority_contract()
                    )

    def test_execution_context_preflight_binds_all_intent_mutation_roots(self) -> None:
        request = _request()
        with tempfile.TemporaryDirectory() as directory:
            intent = _preflight_intent(directory)
            with (
                patch.dict(os.environ, _task_environment(), clear=False),
                patch.object(executor.os, "statvfs", lambda _path: SimpleNamespace(f_flag=0)),
                patch.object(executor.os, "access", lambda _path, _mode: True),
                patch.object(
                    executor.subprocess,
                    "run",
                    lambda *_a, **_k: SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(
                            {
                                "filesystems": [
                                    {
                                        "target": "/",
                                        "fstype": "ext4",
                                        "options": "rw,noatime,errors=remount-ro",
                                    }
                                ]
                            }
                        ),
                        stderr="",
                    ),
                ),
            ):
                evidence = executor.execution_context_preflight(
                    request, intent, _authority_contract()
                )
        self.assertTrue(evidence["writable"])
        self.assertEqual(
            {*executor.INTENT_MUTATION_ROOT_FIELDS, executor.AUTHORITY_MUTATION_ROOT_FIELD},
            set(evidence["mutation_roots"]),
        )
        self.assertEqual(GRABOWSKI_TASK_ID, evidence["task_identity"]["task_id"])
        self.assertEqual(GRABOWSKI_TASK_UNIT, evidence["task_identity"]["systemd_unit"])
        for field in (*executor.INTENT_MUTATION_ROOT_FIELDS, executor.AUTHORITY_MUTATION_ROOT_FIELD):
            item = evidence["mutation_roots"][field]
            self.assertTrue(item["is_directory"])
            self.assertTrue(item["mount_rw"])
            self.assertFalse(item["filesystem_read_only"])
            self.assertTrue(item["path_writable"])
            self.assertTrue(item["path_searchable"])
            self.assertTrue(item["writable"])
        self.assertEqual(INTENT_SHA, evidence["intent_sha256"])
        self.assertEqual(TARGET_SHA, evidence["target_sha256"])
        digest = str(evidence.pop("execution_context_sha256"))
        self.assertEqual(digest, executor._sha256_json(evidence))

    def test_load_bound_intent_verifies_payload_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intents = root / "intents"
            intents.mkdir()
            payload = _intent_payload()
            payload["state_root"] = str(root)
            payload.pop("intent_sha256", None)
            digest = executor._bureau_payload_digest(payload, "intent_sha256")
            payload["intent_sha256"] = digest
            path = intents / f"{digest}.json"
            path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            request = {
                "intent": str(path),
                "expected_intent_sha256": digest,
                "lease_owner": LEASE_OWNER,
                "lease_task_id": TASK_ID,
            }
            with (
                patch.object(executor, "CANONICAL_STATE_ROOT", root),
                patch.object(executor, "CANONICAL_INTENTS_ROOT", intents),
            ):
                loaded = executor.load_bound_intent(request)
                self.assertEqual(digest, loaded["intent_sha256"])
                payload["target_sha256"] = "f" * 64
                path.write_text(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    executor.BureauRuntimeRefreshExecutorError,
                    "SHA-256 does not match payload",
                ):
                    executor.load_bound_intent(request)

    def test_task_identity_is_server_injected_and_bound_into_launch(self) -> None:
        environment = _task_environment()
        self.assertEqual(GRABOWSKI_TASK_ID, environment[executor.EXECUTOR_TASK_ID_ENV])
        self.assertEqual(GRABOWSKI_TASK_UNIT, environment[executor.EXECUTOR_TASK_UNIT_ENV])
        with patch.dict(os.environ, environment, clear=False):
            identity = executor.current_task_identity()
        self.assertEqual(GRABOWSKI_TASK_ID, identity["task_id"])
        self.assertEqual(GRABOWSKI_TASK_UNIT, identity["systemd_unit"])
        self.assertEqual(64, len(identity["task_identity_sha256"]))
        with self.assertRaisesRegex(
            executor.BureauRuntimeRefreshExecutorError, "systemd unit is invalid"
        ):
            executor.task_identity_environment(
                GRABOWSKI_TASK_ID, "grabowski-task-deadbeef-a1.service"
            )

        record = {
            "task_id": GRABOWSKI_TASK_ID,
            "unit": GRABOWSKI_TASK_UNIT,
            "authoritative_unit": GRABOWSKI_TASK_UNIT,
            "argv_sha256": "a" * 64,
            "runtime_seconds": 60,
            "cwd": "/home/alex",
            "cpu_weight": 100,
            "io_weight": 100,
            "memory_max_bytes": None,
            "argv_json": json.dumps(
                ["/runtime/python", "-m", executor.EXECUTOR_MODULE, "--intent", "/x"]
            ),
        }
        with patch.object(tasks, "_task_output_capture_argv", lambda _record: ["capture"]):
            launch = tasks._launch_argv(record, include_managed_runtime=False)
        self.assertIn(
            f"--setenv={executor.EXECUTOR_TASK_ID_ENV}={GRABOWSKI_TASK_ID}", launch
        )
        self.assertIn(
            f"--setenv={executor.EXECUTOR_TASK_UNIT_ENV}={GRABOWSKI_TASK_UNIT}", launch
        )

    def test_authority_execution_contract_is_state_store_and_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "bureau.sqlite3"
            contract_spec = {
                "id": TASK_ID,
                "metadata": {
                    "runtime_execution_context": executor.EXPECTED_RUNTIME_EXECUTION_CONTEXT
                },
            }
            spec_sha = executor._sha256_json(contract_spec)
            connection = sqlite3.connect(state_db)
            try:
                connection.executescript(
                    "CREATE TABLE task_specs (task_id TEXT PRIMARY KEY, current_revision INTEGER, spec_sha256 TEXT);"
                    "CREATE TABLE task_spec_revisions (task_id TEXT, revision INTEGER, spec_sha256 TEXT, spec_json TEXT);"
                )
                connection.execute(
                    "INSERT INTO task_specs(task_id,current_revision,spec_sha256) VALUES(?,?,?)",
                    (TASK_ID, 1, spec_sha),
                )
                connection.execute(
                    "INSERT INTO task_spec_revisions(task_id,revision,spec_sha256,spec_json) VALUES(?,?,?,?)",
                    (
                        TASK_ID,
                        1,
                        spec_sha,
                        json.dumps(contract_spec, sort_keys=True, separators=(",", ":")),
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            os.chmod(state_db, 0o600)
            with patch.object(executor, "CANONICAL_BUREAU_STATE_DB", state_db):
                intent = _intent_payload()
                intent["authority_state_store"] = {
                    "state_db": str(state_db),
                    "state_root": str(state_db.parent),
                }
                intent["authority_task_spec"] = {
                    "revision": 1,
                    "spec_sha256": spec_sha,
                }
                proof = executor.validate_authority_execution_contract(intent)
            self.assertEqual(spec_sha, proof["spec_sha256"])
            self.assertEqual(
                executor._sha256_json(executor.EXPECTED_RUNTIME_EXECUTION_CONTEXT),
                proof["execution_contract_sha256"],
            )

    def test_authority_execution_contract_rejects_missing_contract_and_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_db = Path(directory) / "bureau.sqlite3"
            spec = {"id": TASK_ID, "metadata": {}}
            spec_sha = executor._sha256_json(spec)
            connection = sqlite3.connect(state_db)
            try:
                connection.executescript(
                    "CREATE TABLE task_specs (task_id TEXT PRIMARY KEY, current_revision INTEGER, spec_sha256 TEXT);"
                    "CREATE TABLE task_spec_revisions (task_id TEXT, revision INTEGER, spec_sha256 TEXT, spec_json TEXT);"
                )
                connection.execute(
                    "INSERT INTO task_specs(task_id,current_revision,spec_sha256) VALUES(?,?,?)",
                    (TASK_ID, 1, spec_sha),
                )
                connection.execute(
                    "INSERT INTO task_spec_revisions(task_id,revision,spec_sha256,spec_json) VALUES(?,?,?,?)",
                    (TASK_ID, 1, spec_sha, json.dumps(spec)),
                )
                connection.commit()
            finally:
                connection.close()
            os.chmod(state_db, 0o600)
            with patch.object(executor, "CANONICAL_BUREAU_STATE_DB", state_db):
                intent = _intent_payload()
                intent["authority_state_store"] = {
                    "state_db": str(state_db),
                    "state_root": str(state_db.parent),
                }
                intent["authority_task_spec"] = {
                    "revision": 1,
                    "spec_sha256": spec_sha,
                }
                with self.assertRaisesRegex(
                    executor.BureauRuntimeRefreshExecutorError,
                    "execution-context contract is missing",
                ):
                    executor.validate_authority_execution_contract(intent)
                connection = sqlite3.connect(state_db)
                try:
                    connection.execute(
                        "UPDATE task_spec_revisions SET spec_json=? WHERE task_id=?",
                        (
                            json.dumps(
                                {
                                    "id": TASK_ID,
                                    "metadata": {
                                        "runtime_execution_context": executor.EXPECTED_RUNTIME_EXECUTION_CONTEXT
                                    },
                                    "tampered": True,
                                }
                            ),
                            TASK_ID,
                        ),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(
                    executor.BureauRuntimeRefreshExecutorError,
                    "TaskSpec digest drifted",
                ):
                    executor.validate_authority_execution_contract(intent)

    def test_executor_main_execs_exact_immutable_apply_only_after_preflight(self) -> None:
        request = _request()
        intent = _intent_payload()
        evidence = {
            "schema_version": 1,
            "kind": "grabowski_bureau_runtime_refresh_execution_context_preflight",
            "writable": True,
            "execution_context_sha256": "d" * 64,
        }
        with (
            patch.object(executor, "parse_executor_module_request", lambda _argv: request),
            patch.object(executor, "load_bound_intent", lambda _request: intent),
            patch.object(
                executor,
                "validate_authority_execution_contract",
                lambda _intent: _authority_contract(),
            ),
            patch.object(
                executor,
                "execution_context_preflight",
                lambda _request, _intent, _authority: evidence,
            ),
            patch.object(
                executor,
                "_validate_bureau_launcher",
                lambda: executor.CANONICAL_BUREAU_REFRESH,
            ),
            patch.object(executor.os, "execv", side_effect=RuntimeError("exec-called")) as execv,
        ):
            with self.assertRaisesRegex(RuntimeError, "exec-called"):
                executor.main(
                    [
                        "--intent",
                        request["intent"],
                        "--expected-intent-sha256",
                        INTENT_SHA,
                        "--lease-owner",
                        LEASE_OWNER,
                        "--lease-task-id",
                        TASK_ID,
                    ]
                )
        execv.assert_called_once_with(
            str(executor.CANONICAL_BUREAU_REFRESH),
            [
                str(executor.CANONICAL_BUREAU_REFRESH),
                "--state-root",
                str(executor.CANONICAL_STATE_ROOT),
                "apply",
                "--intent",
                request["intent"],
                "--lease-owner",
                LEASE_OWNER,
                "--lease-task-id",
                TASK_ID,
            ],
        )

    def test_operation_identity_is_intent_and_scope_bound(self) -> None:
        identity = executor.operation_identity(
            _request(), _intent_payload(), _authority_contract()
        )
        self.assertEqual(MAIN_SHA, identity["repository_head"])
        self.assertEqual(INTENT_SHA, identity["source_fingerprint_sha256"])
        self.assertTrue(identity["purpose"].endswith(INTENT_SHA[:16]))
        self.assertEqual(64, len(identity["scope_sha256"]))


if __name__ == "__main__":
    unittest.main()
