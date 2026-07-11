from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_operator.py"


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


def _load_operator_module():
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_base = types.ModuleType("grabowski_mcp")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_base.mcp = _FakeFastMCP()

    def load_policy():
        return {
            "active_profile": "operator",
            "forbidden_capabilities": [],
            "profiles": {
                "operator": {
                    "capabilities": [
                        "terminal_execute",
                        "durable_job",
                        "git_cli",
                        "github_cli",
                        "user_service_control",
                        "tmux_interaction",
                        "process_inspect",
                        "process_signal",
                        "port_inspect",
                        "privileged_reference",
                    ],
                },
            },
        }

    def active_profile(policy):
        return {
            "name": "operator",
            **policy["profiles"]["operator"],
        }

    fake_base._load_policy = load_policy
    fake_base._active_profile = active_profile
    fake_base._kill_switch_state = lambda: {"engaged": False}
    fake_base._require_valid_audit_chain = lambda: None
    fake_base._reject_forbidden_hosts_in_argv = lambda argv, *, policy=None: None

    module_name = "grabowski_operator_contract_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_operator")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
            "mcp.types": fake_types,
            "grabowski_mcp": fake_base,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


class OperatorContractTests(unittest.TestCase):
    def test_operator_source_compiles(self) -> None:
        tree = ast.parse(
            SOURCE.read_text(encoding="utf-8"),
            filename=str(SOURCE),
        )
        self.assertIsInstance(tree, ast.Module)

    def test_runtime_deploy_runner_is_reserved_for_typed_scheduler(self) -> None:
        operator = _load_operator_module()
        repo = operator.HOME / "repos" / "grabowski"
        runner = "tools/run_scheduled_deploy.py"
        commands = [
            ["/usr/bin/python3", runner, "--expected-head", "a" * 40],
            ["python3", runner],
            ["/usr/bin/env", "python3", runner],
            ["bash", "-c", f"python3 {runner} --expected-head {'a' * 40}"],
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(
                    operator._reserved_runtime_deploy_command(command, repo)
                )
        self.assertFalse(
            operator._reserved_runtime_deploy_command(
                ["python3", "-c", "print(1)"],
                repo,
            )
        )

    def test_expected_tools_are_declared(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        declared = set()

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                function = decorator.func
                if not (
                    isinstance(function, ast.Attribute)
                    and function.attr == "tool"
                ):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                    ):
                        declared.add(keyword.value.value)

        expected = {
            "grabowski_terminal_run",
            "grabowski_job_start",
            "grabowski_job_status",
            "grabowski_job_logs",
            "grabowski_job_cancel",
            "grabowski_git",
            "grabowski_github",
            "grabowski_user_service",
            "grabowski_tmux_list",
            "grabowski_tmux_capture",
            "grabowski_tmux_send",
            "grabowski_process_list",
            "grabowski_process_signal",
            "grabowski_ports",
            "grabowski_privileged_action_reference",
        }
        self.assertEqual(expected, declared)

    def test_policy_no_longer_forbids_operator_core(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.example.json"
            ).read_text(encoding="utf-8")
        )
        forbidden = set(policy["forbidden_capabilities"])
        self.assertNotIn("shell_execute", forbidden)
        self.assertNotIn("git_mutate", forbidden)
        self.assertNotIn("service_control", forbidden)

    def test_privilege_escalation_is_explicitly_blocked(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for command in ("sudo", "su", "pkexec", "doas"):
            self.assertIn(command, source)

    def test_evidence_root_is_guarded(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('HOME / "repos" / "merges"', source)
        self.assertIn("immutable evidence", source)

    def test_synchronous_commands_have_bounded_runtime(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                assignments[target.id] = node.value.value
        self.assertEqual(60, assignments.get("DEFAULT_TIMEOUT"))
        self.assertEqual(120, assignments.get("MAX_TIMEOUT"))

    def test_timeout_kills_the_full_process_group(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)

    def test_http_transport_is_loopback_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('choices=("stdio", "streamable-http")', source)
        self.assertIn('args.host != "127.0.0.1"', source)
        self.assertIn('mcp.run(transport=args.transport)', source)

    def test_background_jobs_have_a_separate_runtime_budget(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("DEFAULT_JOB_RUNTIME = 7_200", source)
        self.assertIn("MAX_JOB_RUNTIME = 86_400", source)
        self.assertIn("--property=RuntimeMaxSec=", source)

    def test_background_job_evidence_is_persistent(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('JOBS_DIR = STATE_DIR / "jobs"', source)
        self.assertIn('directory / "metadata.json"', source)
        self.assertIn("--property=KillMode=control-group", source)
        self.assertIn("--property=StandardOutput=append:", source)
        self.assertIn("--property=StandardError=append:", source)
        self.assertIn("--description=", source)
        self.assertIn('"job_id"', source)
        self.assertIn('"expected_receipt"', source)
        self.assertIn('"terminalization_evidence"', source)
        self.assertIn('"notify_on_done"', source)

    def test_job_start_records_identity_receipt_and_no_default_notify(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="deadbeefcafe1234")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ) as run:
                job = operator.grabowski_job_start(["python3", "-c", "print(1)"], cwd=str(cwd), runtime_seconds=60)

            self.assertEqual(job["job_id"], "deadbeefcafe")
            self.assertEqual(job["unit"], "grabowski-job-deadbeefcafe")
            self.assertTrue(job["owner"].startswith("uid:"))
            self.assertEqual(job["scope"]["cwd"], str(cwd.resolve()))
            self.assertEqual(job["scope"]["runtime_seconds"], 60)
            self.assertIn("started_at", job)
            self.assertTrue(job["started_at"].endswith("Z"))
            self.assertEqual(job["started_at_unix"], job["created_at_unix"])
            self.assertEqual(job["expected_receipt"]["status_tool"], "grabowski_job_status")
            self.assertEqual(job["expected_receipt"]["logs_tool"], "grabowski_job_logs")
            self.assertEqual(job["final_status"], "launch_submitted")
            self.assertEqual(job["terminalization_evidence"]["final_status"], "launch_submitted")
            self.assertEqual(job["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(job["launcher_evidence"]["returncode"], 0)
            self.assertEqual(job["notification_evidence"]["final_status_preserved"], "launch_submitted")
            self.assertIn("receipt_exists", job["expected_receipt"]["does_not_establish"])
            self.assertIn("job_success", job["expected_receipt"]["does_not_establish"])
            self.assertFalse(job["notify_on_done"]["requested"])
            self.assertFalse(job["notify_on_done"]["delivery_enabled"])
            self.assertEqual(job["notify_on_done"]["delivery_mode"], "metadata_only")
            self.assertEqual(job["notification_evidence"]["delivery_state"], "not_sent")
            persisted = json.loads(Path(job["metadata_path"]).read_text(encoding="utf-8"))
            self.assertEqual(persisted["final_status"], "launch_submitted")
            self.assertEqual(persisted["terminalization_evidence"]["source"], "systemd-run-launch")
            invoked = run.call_args_list[0].args[0]
            self.assertIn("systemd-run", invoked)
            self.assertNotIn("mail", invoked)
            self.assertNotIn("notify-send", invoked)

    def test_job_final_status_classification_is_explicit(self) -> None:
        operator = _load_operator_module()

        self.assertEqual(operator._job_final_status(False, {}), "missing_finalization_evidence")
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "active", "Result": "success", "ExecMainStatus": "0"}),
            "running",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0"}),
            "succeeded",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "exit-code", "ExecMainStatus": "1"}),
            "failed",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "", "ExecMainStatus": ""}),
            "terminated_unclear",
        )

    def test_launch_failure_persists_failed_evidence_not_started(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="badlaunch0000ffff")
            launcher = {
                "returncode": 1,
                "stdout": "",
                "stderr": "systemd refused launch",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                with self.assertRaisesRegex(RuntimeError, "systemd refused launch"):
                    operator.grabowski_job_start(["python3", "-c", "print(1)"], cwd=str(cwd))

            metadata_path = jobs / "grabowski-job-badlaunch000" / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["final_status"], "launch_failed")
            self.assertEqual(metadata["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(metadata["terminalization_evidence"]["final_status"], "launch_failed")
            self.assertFalse(metadata["terminalization_evidence"]["systemd_visible"])
            self.assertEqual(metadata["launcher_evidence"]["returncode"], 1)
            self.assertNotEqual(metadata["final_status"], "started")

            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=\nExecMainCode=\nExecMainStatus=\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status("grabowski-job-badlaunch000")

            self.assertFalse(status["systemd_visible"])
            self.assertEqual(status["final_status"], "launch_failed")
            self.assertEqual(status["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(status["notification_evidence"]["final_status_preserved"], "launch_failed")

    def test_not_found_systemd_unit_has_valid_query_but_missing_finalization(self) -> None:
        operator = _load_operator_module()
        result = {"returncode": 0}
        properties = {"LoadState": "not-found", "ActiveState": "inactive"}

        self.assertTrue(operator._systemd_job_query_valid(result, properties))
        self.assertFalse(operator._systemd_job_query_visible(result, properties))
        evidence = operator._job_terminalization_evidence(False, properties, query_valid=True)
        self.assertTrue(evidence["query_valid"])
        self.assertFalse(evidence["systemd_visible"])
        self.assertEqual(evidence["final_status"], "missing_finalization_evidence")

    def test_malformed_systemd_show_is_missing_finalization_evidence(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="emptyshow0000ffff")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(["python3", "-c", "print(1)"], cwd=str(cwd))

            systemctl = {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(job["unit"])

            self.assertFalse(status["systemd_visible"])
            self.assertEqual(status["final_status"], "missing_finalization_evidence")
            self.assertFalse(status["terminalization_evidence"]["query_valid"])

    def test_notify_on_done_metadata_does_not_hide_failed_finalization(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="feedfacecafe9999")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "raise SystemExit(1)"],
                    cwd=str(cwd),
                    runtime_seconds=60,
                    notify_on_done={"requested": True, "channels": ["chat"], "note": "done"},
                )

            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nRuntimeMaxUSec=60000000\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(job["unit"])

            self.assertEqual(status["final_status"], "failed")
            self.assertEqual(status["job_record"]["final_status"], "failed")
            self.assertTrue(status["job_record"]["notify_on_done"]["requested"])
            self.assertEqual(status["job_record"]["notify_on_done"]["channels"], ["chat"])
            self.assertFalse(status["notification_evidence"]["delivery_enabled"])
            self.assertEqual(status["notification_evidence"]["delivery_state"], "not_sent")
            self.assertEqual(status["notification_evidence"]["final_status_preserved"], "failed")
            self.assertIn("hidden_finalization_failure", status["terminalization_evidence"]["does_not_establish"])

    def test_notify_on_done_metadata_is_strict_and_bounded(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(operator._normalize_notify_on_done(None)["requested"], False)
        self.assertEqual(operator._normalize_notify_on_done({})["requested"], False)
        self.assertEqual(operator._normalize_notify_on_done({"requested": True})["requested"], True)
        with self.assertRaisesRegex(ValueError, "Unknown notify_on_done"):
            operator._normalize_notify_on_done({"requested": True, "send": True})
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            operator._normalize_notify_on_done({"requested": "yes"})
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._normalize_notify_on_done({"requested": True, "channels": ["bad\nchannel"]})
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._normalize_notify_on_done({"requested": True, "note": "done\n"})

    def test_legacy_metadata_is_projected_for_status_and_logs(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            unit = "grabowski-job-legacy000001"
            directory = jobs / unit
            directory.mkdir(parents=True)
            stdout_path = directory / "stdout.log"
            stderr_path = directory / "stderr.log"
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            metadata = {
                "schema_version": 1,
                "unit": unit,
                "argv": ["python3"],
                "argv_sha256": "a" * 64,
                "command": "python3",
                "cwd": str(root),
                "runtime_seconds": 60,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            }
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(unit)
            with patch.object(operator, "STATE_DIR", state), patch.object(operator, "JOBS_DIR", jobs):
                logs = operator.grabowski_job_logs(unit, max_lines=5)

            self.assertEqual(status["job_record"]["job_id"], "legacy000001")
            self.assertTrue(status["job_record"]["owner"].startswith("uid:"))
            self.assertEqual(status["job_record"]["scope"]["argv_sha256"], "a" * 64)
            self.assertEqual(status["job_record"]["expected_receipt"]["status_tool"], "grabowski_job_status")
            self.assertFalse(status["job_record"]["notify_on_done"]["requested"])
            self.assertTrue(status["job_record"]["metadata_projection"]["legacy_fields_projected"])
            self.assertEqual(logs["job_identity"]["job_id"], "legacy000001")
            self.assertEqual(logs["expected_receipt"]["logs_tool"], "grabowski_job_logs")
            self.assertFalse(logs["notify_on_done"]["requested"])

    def test_invalid_stored_notify_metadata_degrades_without_delivery(self) -> None:
        operator = _load_operator_module()
        metadata = {
            "schema_version": 1,
            "unit": "grabowski-job-invalidnotify",
            "notify_on_done": {"requested": "yes"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            directory = jobs / metadata["unit"]
            directory.mkdir(parents=True)
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            (directory / "stdout.log").write_text("", encoding="utf-8")
            (directory / "stderr.log").write_text("", encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])

            notify = status["job_record"]["notify_on_done"]
            self.assertFalse(notify["requested"])
            self.assertTrue(notify["metadata_invalid"])
            self.assertFalse(status["notification_evidence"]["delivery_enabled"])
            self.assertEqual(status["notification_evidence"]["delivery_state"], "not_sent")

            metadata["notify_on_done"] = {"requested": True, "send": True}
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])

            notify = status["job_record"]["notify_on_done"]
            self.assertFalse(notify["requested"])
            self.assertTrue(notify["metadata_invalid"])
            self.assertIn("Unknown notify_on_done field", notify["metadata_error"])
            self.assertFalse(status["notification_evidence"]["delivery_enabled"])

            for invalid_notify, expected_error in (
                ({"requested": True, "delivery_enabled": True}, "delivery_enabled must be false"),
                ({"requested": True, "delivery_mode": "real_delivery"}, "delivery_mode must be metadata_only"),
                ({"requested": True, "does_not_establish": ["job_success"]}, "does_not_establish is invalid"),
            ):
                metadata["notify_on_done"] = invalid_notify
                (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
                with patch.object(operator, "STATE_DIR", state), patch.object(
                    operator, "JOBS_DIR", jobs
                ), patch.object(operator, "_run", return_value=systemctl):
                    status = operator.grabowski_job_status(metadata["unit"])

                notify = status["job_record"]["notify_on_done"]
                self.assertFalse(notify["requested"])
                self.assertTrue(notify["metadata_invalid"])
                self.assertIn(expected_error, notify["metadata_error"])
                self.assertFalse(status["notification_evidence"]["delivery_enabled"])

            metadata["notify_on_done"] = {"requested": True, "send\nnow": True}
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])
            self.assertIn("�", status["job_record"]["notify_on_done"]["metadata_error"])

    def test_job_metadata_projection_marks_identity_mismatch(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            unit = "grabowski-job-realjobid001"
            directory = jobs / unit
            directory.mkdir(parents=True)
            (directory / "stdout.log").write_text("", encoding="utf-8")
            (directory / "stderr.log").write_text("", encoding="utf-8")
            metadata = {
                "schema_version": 1,
                "unit": unit,
                "job_id": "wrongjobid",
                "stdout_path": str(directory / "stdout.log"),
                "stderr_path": str(directory / "stderr.log"),
            }
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(unit)

            self.assertEqual(status["job_record"]["job_id"], "realjobid001")
            projection = status["job_record"]["metadata_projection"]
            self.assertTrue(projection["job_id_projected"])
            self.assertTrue(projection["stored_job_id_mismatch"])

    def test_replace_job_metadata_uses_unique_temp_and_cleans_failed_write(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            first = {"unit": "grabowski-job-temp000000", "n": 1}
            second = {"unit": "grabowski-job-temp000000", "n": 2}
            broken = {"unit": "grabowski-job-temp000000", "n": 3}
            operator._replace_job_metadata(directory, first)
            operator._replace_job_metadata(directory, second)
            self.assertEqual(json.loads((directory / "metadata.json").read_text(encoding="utf-8"))["n"], 2)
            self.assertEqual(list(directory.glob("metadata.json.*.tmp")), [])

            with patch.object(operator.os, "write", side_effect=RuntimeError("write failed")):
                with self.assertRaisesRegex(RuntimeError, "write failed"):
                    operator._replace_job_metadata(directory, broken)
            self.assertEqual(json.loads((directory / "metadata.json").read_text(encoding="utf-8"))["n"], 2)
            self.assertEqual(list(directory.glob("metadata.json.*.tmp")), [])

    def test_job_logs_expose_identity_receipt_and_notify_metadata(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="abc123abc123ffff")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "print(1)"],
                    cwd=str(cwd),
                    notify_on_done={"requested": True, "channels": ["chat"]},
                )
            with patch.object(operator, "STATE_DIR", state), patch.object(operator, "JOBS_DIR", jobs):
                logs = operator.grabowski_job_logs(job["unit"], max_lines=5)

            self.assertEqual(logs["job_identity"]["job_id"], "abc123abc123")
            self.assertEqual(logs["expected_receipt"]["metadata_path"], job["metadata_path"])
            self.assertTrue(logs["notify_on_done"]["requested"])
            self.assertEqual(logs["stdout"]["text"], "")
            self.assertEqual(logs["stderr"]["text"], "")

    def test_systemd_description_is_bounded_single_line_metadata(self) -> None:
        operator = _load_operator_module()
        digest = "a" * 64

        description = operator._systemd_safe_description(
            "job",
            "grabowski-job-deadbeefcafe.service",
            digest,
        )

        self.assertEqual(
            "Grabowski job grabowski-job-deadbeefcafe.service argv=aaaaaaaaaaaa",
            description,
        )
        self.assertNotIn("\n", description)
        self.assertNotIn("\r", description)
        self.assertLessEqual(len(description.encode("utf-8")), 200)

    def test_systemd_description_rejects_payload_like_values(self) -> None:
        operator = _load_operator_module()
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job\n[Service]", "grabowski-job-x.service")
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job", "grabowski-job-x.service\n[Service]")
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job", "grabowski-job-x.service", "bad")

    def test_secret_bearing_argv_is_redacted_in_results(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("def _redact_argv", source)
        self.assertIn('"argv_sha256"', source)
        self.assertIn("_redacted_command", source)

    def test_operator_mutations_have_capability_and_kill_switch_gate(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("OPERATOR_CAPABILITIES", source)
        self.assertIn("def _require_operator_mutation", source)
        self.assertIn("base._kill_switch_state()", source)
        self.assertIn("base._require_valid_audit_chain()", source)

    def test_operator_mutations_require_valid_audit_chain(self) -> None:
        operator = _load_operator_module()
        with patch.object(
            operator.base,
            "_require_valid_audit_chain",
            side_effect=RuntimeError("Audit log verification failed: bad-chain"),
        ):
            with self.assertRaisesRegex(RuntimeError, "bad-chain"):
                operator._require_operator_mutation("git_cli")

    def test_operator_mutation_gate_uses_operator_capabilities_only(self) -> None:
        operator_capabilities = _load_operator_module().OPERATOR_CAPABILITIES
        allowed = set(operator_capabilities)
        violations: list[str] = []

        for path in sorted((ROOT / "src").glob("grabowski*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                is_operator_gate = (
                    isinstance(function, ast.Attribute)
                    and function.attr == "_require_operator_mutation"
                ) or (
                    isinstance(function, ast.Name)
                    and function.id == "_require_operator_mutation"
                )
                if not is_operator_gate:
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: non-literal capability")
                    continue
                capability = node.args[0].value
                if not isinstance(capability, str):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: non-string capability")
                    continue
                if capability not in allowed:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: {capability} is not an operator capability"
                    )

        self.assertEqual([], violations)

    def test_privileged_action_tool_is_reference_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("PRIVILEGED_REFERENCE_ACTIONS", source)
        self.assertIn('"unprivileged-reference-only"', source)
        self.assertIn('"may_execute": False', source)
        self.assertIn('"requires_external_privileged_agent": True', source)
        self.assertIn('"expires_at_unix"', source)
        self.assertIn('"replay_policy"', source)

    def test_secret_argv_values_are_redacted_from_command_output(self) -> None:
        operator = _load_operator_module()
        secret = "plain-secret-value-12345"
        script = (
            "import sys; "
            "print(sys.argv[2]); "
            "print(sys.argv[2], file=sys.stderr)"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", secret],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(result["returncode"], 0)
        self.assertNotIn(secret, result["argv"])
        self.assertNotIn(secret, result["command"])
        self.assertNotIn(secret, result["stdout"])
        self.assertNotIn(secret, result["stderr"])
        self.assertIn("<REDACTED>", result["stdout"])
        self.assertIn("<REDACTED>", result["stderr"])

    def test_short_secret_values_do_not_corrupt_diagnostic_output(self) -> None:
        operator = _load_operator_module()
        script = "print('status=true count=1 build=101 feature=false')"
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", "true"],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(
            result["stdout"],
            "status=true count=1 build=101 feature=false\n",
        )

    def test_short_secret_value_is_redacted_when_emitted_as_complete_line(self) -> None:
        operator = _load_operator_module()
        script = "import sys; print(sys.argv[2])"
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", "1"],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(result["stdout"], "<REDACTED>\n")

    def test_short_secret_value_is_redacted_in_named_context(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(
            operator._redact("token: 1 status=101", ["1"]),
            "token: <REDACTED> status=101",
        )

    def test_validate_argv_uses_forbidden_host_guard_fail_closed(self) -> None:
        operator = _load_operator_module()
        observed: list[list[str]] = []

        def reject(argv: list[str], *, policy=None) -> None:
            observed.append([*argv, f"policy={policy['active_profile']}"])
            if "blocked.example" in argv:
                raise PermissionError("Forbidden host in command arguments: blocked.example")

        operator.base._reject_forbidden_hosts_in_argv = reject
        self.assertEqual(operator._validate_argv(["echo", "ok"]), ["echo", "ok"])
        self.assertEqual(observed, [["echo", "ok", "policy=operator"]])
        with self.assertRaisesRegex(PermissionError, "blocked.example"):
            operator._validate_argv(["ssh", "blocked.example"])

        delattr(operator.base, "_reject_forbidden_hosts_in_argv")
        with self.assertRaises(AttributeError):
            operator._validate_argv(["echo", "unguarded"])

    def test_relative_command_arguments_may_not_target_merges(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "repos" / "merges"
            evidence.mkdir(parents=True)
            with patch.object(operator, "EVIDENCE_ROOT", evidence):
                with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                    operator._validate_argv(
                        ["touch", "repos/merges/proof.txt"],
                        cwd=root,
                    )
                with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                    operator._validate_argv(
                        ["tool", "--output=repos/merges/proof.txt"],
                        cwd=root,
                    )

    def test_shell_command_fragments_may_not_target_merges(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "repos" / "merges"
            evidence.mkdir(parents=True)
            with (
                patch.object(operator, "HOME", root),
                patch.object(operator, "EVIDENCE_ROOT", evidence),
                patch.dict("os.environ", {"HOME": str(root)}),
            ):
                for argv in (
                    ["sh", "-c", "touch ~/repos/merges/proof.txt"],
                    ["sh", "-c", "touch $HOME/repos/merges/proof.txt"],
                    ["sh", "-c", "touch ${HOME}/repos/merges/proof.txt"],
                    ["tool", "--output=$HOME/repos/merges/proof.txt"],
                ):
                    with self.subTest(argv=argv):
                        with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                            operator._validate_argv(argv, cwd=root)

    def test_push_force_delete_aggregate_and_indirect_options_are_blocked(self) -> None:
        operator = _load_operator_module()
        blocked = (
            ["push", "--force", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-with-lease", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-with-lease=feature", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-if-includes", "origin", "HEAD:refs/heads/feature"],
            ["push", "-fu", "origin", "HEAD:refs/heads/feature"],
            ["push", "origin", "+HEAD:refs/heads/feature"],
            ["push", "--delete", "origin", "feature"],
            ["push", "--delete=feature", "origin"],
            ["push", "-d", "origin", "feature"],
            ["push", "--prune", "origin", "HEAD:refs/heads/feature"],
            ["push", "--mirror", "origin"],
            ["push", "--all", "origin"],
            ["push", "--tags", "origin"],
            ["push", "--follow-tags", "origin", "HEAD:refs/heads/feature"],
            ["push", "--push-option=ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "--push-option", "ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "-o", "ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "-oci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "--receive-pack=git-receive-pack", "origin", "HEAD:refs/heads/feature"],
            ["push", "--exec", "git-receive-pack", "origin", "HEAD:refs/heads/feature"],
            ["push", "--recurse-submodules=on-demand", "origin", "HEAD:refs/heads/feature"],
            ["push", "--no-verify", "origin", "HEAD:refs/heads/feature"],
            ["push", "--repo=origin", "HEAD:refs/heads/feature"],
            ["push", "--for", "origin", "HEAD:refs/heads/feature"],
            ["push", "--mir", "origin"],
            ["push", "--del", "origin", "feature"],
            ["push", "--signed", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=true", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=false", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=if-asked", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=always", "origin", "HEAD:refs/heads/feature"],
            ["push", "--atomic=true", "origin", "HEAD:refs/heads/feature"],
        )
        with patch.object(operator, "_git_config_entries", return_value=[]):
            for arguments in blocked:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_push_requires_one_explicit_non_protected_branch_refspec(self) -> None:
        operator = _load_operator_module()
        blocked = (
            ["push"],
            ["push", "origin"],
            ["push", "origin", "feature"],
            ["push", "origin", "HEAD:feature"],
            ["push", "origin", "HEAD:refs/tags/feature"],
            ["push", "origin", "HEAD:refs/heads/main"],
            ["push", "origin", "HEAD:refs/heads/master"],
            ["push", "origin", ":refs/heads/feature"],
            ["push", "origin", "HEAD:"],
            ["push", "origin", "HEAD:refs/heads/*"],
            ["push", "origin", "HEAD:refs/heads/feature", "HEAD:refs/heads/other"],
            ["push", "origin", "HEAD:refs/heads/feature:refs/heads/other"],
            ["push", "https://example.invalid/repo.git", "HEAD:refs/heads/feature"],
            ["push", "origin", "HEAD:refs/heads/feature name"],
            ["push", "origin", "HEAD:refs/heads/.invalid"],
        )
        with patch.object(operator, "_git_config_entries", return_value=[]):
            for arguments in blocked:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_push_guard_does_not_weaken_in_trusted_owner_mode(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator, "_trusted_owner_mode", return_value=True),
            patch.object(operator, "_git_config_entries", return_value=[]),
        ):
            for arguments in (
                ["push", "--force-with-lease", "origin", "HEAD:refs/heads/feature"],
                ["push", "origin", "HEAD:refs/heads/main"],
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_git_push_config_control_characters_are_rejected(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._guard_git(
                [
                    "-c",
                    "remote.origin.push=HEAD:refs/heads/feature\nalias.ship=!sh",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )

    def test_push_command_line_configuration_is_blocked_fail_closed(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(PermissionError, "configuration"):
            operator._guard_git(
                [
                    "-c",
                    "core.pager=cat",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )
        with self.assertRaises(PermissionError):
            operator._guard_git(
                [
                    "--config-env=remote.origin.push=FORCE_REFSPEC",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )

    def test_repository_push_configuration_is_blocked_for_selected_remote(self) -> None:
        operator = _load_operator_module()
        configurations = (
            ("remote.origin.push", "HEAD:refs/heads/feature"),
            ("remote.origin.mirror", "true"),
            ("remote.origin.receivepack", "git-receive-pack"),
            ("push.pushOption", "ci.skip"),
            ("push.followTags", "true"),
            ("push.gpgSign", "if-asked"),
            ("push.recurseSubmodules", "on-demand"),
        )
        for key, value in configurations:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    repo = Path(directory)
                    operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
                    operator.subprocess.run(
                        ["git", "-C", str(repo), "config", key, value],
                        check=True,
                    )
                    with self.assertRaisesRegex(PermissionError, "configuration"):
                        operator._guard_git(
                            ["push", "origin", "HEAD:refs/heads/feature"],
                            repo,
                        )

    def test_unrelated_remote_configuration_does_not_block_explicit_safe_push(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "remote.backup.mirror", "true"],
                check=True,
            )
            operator._guard_git(
                ["push", "origin", "HEAD:refs/heads/feature"],
                repo,
            )

    def test_git_repository_rebinding_and_alias_injection_are_blocked(self) -> None:
        operator = _load_operator_module()
        for arguments in (
            ["-C", "/tmp/other", "push", "origin", "HEAD:refs/heads/feature"],
            ["--git-dir=/tmp/other.git", "push", "origin", "HEAD:refs/heads/feature"],
            ["--work-tree", "/tmp/other", "status"],
            ["-c", "alias.ship=push origin HEAD:refs/heads/main", "ship"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(PermissionError):
                    operator._guard_git(arguments, Path("/repo"))

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "alias.ship",
                    "push origin HEAD:refs/heads/main",
                ],
                check=True,
            )
            with self.assertRaisesRegex(PermissionError, "Configured Git aliases"):
                operator._guard_git(["ship"], repo)

    def test_explicit_safe_feature_push_subset_is_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for arguments in (
                ["push", "origin", "HEAD:refs/heads/feature"],
                [
                    "push",
                    "--dry-run",
                    "--porcelain",
                    "--atomic",
                    "--thin",
                    "--ipv4",
                    "--set-upstream",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                ["push", "-nquv4", "origin", "HEAD:refs/heads/feature"],
                ["push", "--", "backup.with.dot", "HEAD:refs/heads/feature"],
            ):
                with self.subTest(arguments=arguments):
                    operator._guard_git(arguments, repo)

    def test_git_environment_strips_repository_and_config_injection(self) -> None:
        operator = _load_operator_module()
        injected = {
            "PATH": "/usr/bin",
            "SSH_AUTH_SOCK": "/run/user/1000/agent",
            "GIT_DIR": "/tmp/other.git",
            "GIT_WORK_TREE": "/tmp/other",
            "GIT_EXEC_PATH": "/tmp/git-tools",
            "GIT_CONFIG": "/tmp/gitconfig",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "remote.origin.push",
            "GIT_CONFIG_VALUE_0": "+HEAD:refs/heads/main",
        }
        with patch.object(operator, "_safe_environment", return_value=injected):
            environment = operator._git_environment()
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["SSH_AUTH_SOCK"], "/run/user/1000/agent")
        for key in injected:
            if key.startswith("GIT_CONFIG_") or key in operator.GIT_ENVIRONMENT_EXACT_DENY:
                self.assertNotIn(key, environment)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GCM_INTERACTIVE"], "never")

    def test_prune_and_direct_remote_write_bypasses_are_blocked(self) -> None:
        operator = _load_operator_module()
        for arguments in (
            ["push", "--prune", "origin"],
            ["send-pack", "--force", "origin", "HEAD:main"],
            ["http-push", "--force", "origin", "HEAD:main"],
            ["subtree", "push", "--prefix", "docs", "origin", "pages"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(PermissionError):
                    operator._guard_git(arguments, Path("/repo"))

    def test_grabowski_git_uses_sanitized_git_environment(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            environment = {"PATH": "/usr/bin", "GIT_TERMINAL_PROMPT": "0"}
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(operator, "_git_environment", return_value=environment),
                patch.object(operator, "_run", return_value={"returncode": 0}) as run,
            ):
                operator.grabowski_git(str(repo), ["status"])
        self.assertEqual(run.call_args.kwargs["environment"], environment)

    def test_grabowski_git_push_disables_hooks_helpers_and_unsafe_protocols(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            environment = {"PATH": "/usr/bin"}
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(operator, "_git_push_environment", return_value=environment),
                patch.object(operator, "_run", return_value={"returncode": 0}) as run,
            ):
                operator.grabowski_git(
                    str(repo),
                    ["push", "origin", "HEAD:refs/heads/feature"],
                )
        command = run.call_args.args[0]
        self.assertIn("core.hooksPath=/dev/null", command)
        self.assertIn("core.fsmonitor=false", command)
        self.assertIn("protocol.ext.allow=never", command)
        self.assertIn("remote.origin.mirror=false", command)
        self.assertIn("remote.origin.receivepack=git-receive-pack", command)
        self.assertIn("remote.origin.push=", command)
        self.assertIn("push.followTags=false", command)
        self.assertIn("push.pushOption=", command)
        self.assertIn("push.gpgSign=false", command)
        self.assertIn("push.recurseSubmodules=no", command)
        self.assertEqual(environment, run.call_args.kwargs["environment"])

    def test_git_push_environment_disables_executable_transport_overrides(self) -> None:
        operator = _load_operator_module()
        injected = {
            "PATH": "/usr/bin",
            "GIT_SSH": "/tmp/evil-ssh",
            "GIT_SSH_COMMAND": "/tmp/evil-command",
            "GIT_PROXY_COMMAND": "/tmp/evil-proxy",
            "GIT_ASKPASS": "/tmp/evil-askpass",
            "SSH_ASKPASS": "/tmp/evil-ssh-askpass",
            "GIT_ALLOW_PROTOCOL": "ext:file:ssh:https",
        }
        with patch.object(operator, "_git_environment", return_value=injected):
            environment = operator._git_push_environment()
        self.assertNotIn("GIT_SSH", environment)
        self.assertNotIn("GIT_PROXY_COMMAND", environment)
        self.assertEqual("/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no -oClearAllForwardings=yes", environment["GIT_SSH_COMMAND"])
        self.assertEqual("ssh", environment["GIT_SSH_VARIANT"])
        self.assertEqual("/bin/false", environment["GIT_ASKPASS"])
        self.assertEqual("/bin/false", environment["SSH_ASKPASS"])
        self.assertEqual("ssh", environment["GIT_ALLOW_PROTOCOL"])

    def test_benign_global_config_and_normal_feature_push_remain_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "symbolic-ref", "HEAD", "refs/heads/feature"],
                check=True,
            )
            operator._guard_git(["-c", "core.pager=cat", "status"], repo)
            operator._guard_git(
                ["push", "origin", "HEAD:refs/heads/feature"],
                repo,
            )

    def test_privileged_reference_has_expiry_replay_policy_and_bound_hash(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator, "_require_operator_capability", return_value=None),
            patch.object(operator.time, "time", return_value=1_700_000_000),
        ):
            payload = operator.grabowski_privileged_action_reference(
                "reset_failed_systemd_unit",
                "user@111.service",
                "document external approval request",
            )

        self.assertEqual(payload["created_at_unix"], 1_700_000_000)
        self.assertEqual(payload["expires_at_unix"], 1_700_000_900)
        self.assertEqual(payload["replay_policy"], "single-use-external-broker")
        material = {
            key: value
            for key, value in payload.items()
            if key != "reference_sha256"
        }
        expected = hashlib.sha256(
            json.dumps(
                material,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(payload["reference_sha256"], expected)


class DurableJobFinalizationReceiptTests(unittest.TestCase):
    def _systemd_not_found(self, root: Path) -> dict[str, object]:
        return {
            "returncode": 0,
            "stdout": (
                "LoadState=not-found\n"
                "ActiveState=inactive\n"
                "SubState=dead\n"
                "Result=success\n"
                "ExecMainCode=0\n"
                "ExecMainStatus=0\n"
            ),
            "stderr": "",
            "argv": [],
            "argv_sha256": "1" * 64,
            "command": "systemctl show",
            "cwd": str(root),
            "timed_out": False,
            "duration_seconds": 0.01,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    def _systemd_visible_success(self, root: Path) -> dict[str, object]:
        result = self._systemd_not_found(root)
        result["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        return result

    def _fixture(
        self,
        operator,
        root: Path,
        *,
        final_status: str = "completed",
        write_receipt: bool = True,
        raw_receipt: bytes | None = None,
        mutate_payload=None,
    ) -> tuple[Path, Path, str, str]:
        state = root / "state"
        jobs = state / "jobs"
        unit = "grabowski-job-deadbeefcafe"
        directory = jobs / unit
        directory.mkdir(parents=True)
        expected_head = "a" * 40
        argv = [
            "/usr/bin/python3",
            "/repo/tools/run_scheduled_deploy.py",
            "--repo",
            "/repo",
            "--expected-head",
            expected_head,
            "--delay-seconds",
            "8",
        ]
        argv_sha256 = operator._argv_hash(argv)
        stdout_path = directory / "stdout.log"
        stderr_path = directory / "stderr.log"
        stdout_path.write_text("runner output\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        contract = operator._job_finalization_contract(
            unit=unit,
            directory=directory,
            argv_sha256=argv_sha256,
            expected_head=expected_head,
        )
        metadata = {
            "schema_version": 1,
            "unit": unit,
            "job_id": "deadbeefcafe",
            "owner": "uid:1000",
            "argv": argv,
            "argv_sha256": argv_sha256,
            "command": " ".join(argv),
            "cwd": str(root),
            "runtime_seconds": 3600,
            "created_at_unix": 1000,
            "started_at": "1970-01-01T00:16:40Z",
            "started_at_unix": 1000,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "scope": {
                "cwd": str(root),
                "argv_sha256": argv_sha256,
                "runtime_seconds": 3600,
            },
            "finalization_contract": contract,
            "final_status": "launch_submitted",
            "notify_on_done": {
                "requested": False,
                "channels": [],
                "delivery_mode": "metadata_only",
                "delivery_enabled": False,
                "does_not_establish": [
                    "notification_sent",
                    "notification_delivery",
                    "job_success",
                ],
            },
        }
        (directory / "metadata.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        if write_receipt:
            finalization_path = directory / "finalization.json"
            if raw_receipt is not None:
                finalization_path.write_bytes(raw_receipt)
            else:
                material = {
                    "schema_version": 1,
                    "kind": operator.RUNTIME_DEPLOY_FINALIZATION_KIND,
                    "unit": unit,
                    "job_id": "deadbeefcafe",
                    "argv_sha256": argv_sha256,
                    "expected_head": expected_head,
                    "receipt_paths": operator._job_receipt_paths(directory),
                    "final_status": final_status,
                    "completion_status": (
                        "complete" if final_status == "completed" else "failed"
                    ),
                    "repo_head": expected_head if final_status == "completed" else None,
                    "release_id": "release-test" if final_status == "completed" else None,
                    "failure_type": None if final_status == "completed" else "RuntimeError",
                    "timestamp_unix": 1001,
                }
                if mutate_payload is not None:
                    mutate_payload(material)
                payload = {
                    **material,
                    "payload_sha256": operator._json_sha256(material),
                }
                finalization_path.write_text(
                    json.dumps(payload), encoding="utf-8"
                )
        return state, jobs, unit, expected_head

    def _status(self, operator, state: Path, jobs: Path, unit: str, result: dict[str, object]):
        with patch.object(operator, "STATE_DIR", state), patch.object(
            operator, "JOBS_DIR", jobs
        ), patch.object(operator, "_run", return_value=result):
            return operator.grabowski_job_status(unit)

    def test_collected_unit_with_valid_bound_complete_receipt_is_completed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, expected_head = self._fixture(operator, root)
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "completed")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "persisted-runner-receipt",
        )
        self.assertTrue(status["terminalization_evidence"]["fallback_used"])
        self.assertEqual(
            status["terminalization_evidence"]["expected_head"], expected_head
        )
        self.assertTrue(status["finalization_receipt"]["valid"])

    def test_collected_unit_without_receipt_stays_missing_finalization_evidence(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, write_receipt=False
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(status["finalization_receipt"]["state"], "missing_receipt")
        self.assertFalse(status["terminalization_evidence"]["fallback_used"])

    def test_wrong_expected_head_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def mutate(material):
                material["expected_head"] = "c" * 40
                material["repo_head"] = "c" * 40
            state, jobs, unit, _ = self._fixture(
                operator, root, mutate_payload=mutate
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(
            status["finalization_receipt"]["reason"],
            "receipt_binding_mismatch:expected_head",
        )

    def test_wrong_argv_sha256_or_job_id_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        for key, wrong in (("argv_sha256", "d" * 64), ("job_id", "feedfacecafe")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                def mutate(material, key=key, wrong=wrong):
                    material[key] = wrong
                state, jobs, unit, _ = self._fixture(
                    operator, root, mutate_payload=mutate
                )
                status = self._status(
                    operator, state, jobs, unit, self._systemd_not_found(root)
                )
                self.assertEqual(
                    status["final_status"], "missing_finalization_evidence"
                )
                self.assertEqual(
                    status["finalization_receipt"]["reason"],
                    f"receipt_binding_mismatch:{key}",
                )

    def test_failed_receipt_maps_to_failed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, final_status="failed"
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "failed")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "persisted-runner-receipt",
        )
        self.assertTrue(status["finalization_receipt"]["valid"])

    def test_truncated_or_invalid_json_receipt_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        for raw in (b'{"truncated":', b'not-json'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state, jobs, unit, _ = self._fixture(
                    operator, root, raw_receipt=raw
                )
                status = self._status(
                    operator, state, jobs, unit, self._systemd_not_found(root)
                )
                self.assertEqual(
                    status["final_status"], "missing_finalization_evidence"
                )
                self.assertEqual(
                    status["finalization_receipt"]["reason"],
                    "receipt_json_invalid",
                )

    def test_symlinked_receipt_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(operator, root)
            receipt = jobs / unit / "finalization.json"
            target = root / "outside-receipt.json"
            target.write_bytes(receipt.read_bytes())
            receipt.unlink()
            receipt.symlink_to(target)
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(status["finalization_receipt"]["reason"], "receipt_symlink")

    def test_fifo_receipt_is_rejected_without_blocking(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "finalization.json"
            os.mkfifo(fifo, 0o600)
            started = time.monotonic()
            result = operator._read_finalization_receipt_file(fifo)
            duration = time.monotonic() - started
        self.assertLess(duration, 0.5)
        self.assertEqual(result["state"], "invalid_receipt")
        self.assertEqual(result["reason"], "receipt_not_regular_file")

    def test_stale_metadata_temp_cleanup_is_bounded_and_conservative(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "grabowski-job-cleanup0001"
            job.mkdir(mode=0o700)
            stale = job / ("metadata.json." + "a" * 32 + ".tmp")
            fresh = job / ("metadata.json." + "b" * 32 + ".tmp")
            malformed = job / "metadata.json.not-a-uuid.tmp"
            stale.write_text("stale", encoding="utf-8")
            fresh.write_text("fresh", encoding="utf-8")
            malformed.write_text("keep", encoding="utf-8")
            now = 10_000
            os.utime(stale, (now - operator.JOB_METADATA_TEMP_STALE_SECONDS - 1,) * 2)
            os.utime(fresh, (now,) * 2)
            result = operator._cleanup_stale_job_metadata_temps(root, now_unix=now)
            self.assertEqual(result, {"inspected": 2, "removed": 1, "errors": 0})
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
            self.assertTrue(malformed.exists())

    def test_metadata_temp_cleanup_bounds_nonmatching_entries(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "grabowski-job-entrybound01"
            job.mkdir(mode=0o700)
            for index in range(4):
                (job / f"unrelated-{index}").write_text("keep", encoding="utf-8")
            stale = job / ("metadata.json." + "c" * 32 + ".tmp")
            stale.write_text("stale", encoding="utf-8")
            now = 10_000
            os.utime(stale, (now - operator.JOB_METADATA_TEMP_STALE_SECONDS - 1,) * 2)
            with patch.object(operator, "JOB_METADATA_ENTRY_SWEEP_LIMIT", 0):
                result = operator._cleanup_stale_job_metadata_temps(root, now_unix=now)
            self.assertEqual(result["inspected"], 0)
            self.assertTrue(stale.exists())

    def test_visible_systemd_status_remains_primary_over_valid_receipt(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, final_status="failed"
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_visible_success(root)
            )
        self.assertEqual(status["final_status"], "succeeded")
        self.assertEqual(
            status["terminalization_evidence"]["source"], "systemd-show"
        )
        self.assertTrue(status["systemd_visible"])
        self.assertTrue(status["finalization_receipt"]["valid"])


if __name__ == "__main__":
    unittest.main()
