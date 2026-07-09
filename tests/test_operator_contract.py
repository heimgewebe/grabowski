from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import sys
import tempfile
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
            self.assertEqual(job["final_status"], "launch_prepared")
            self.assertEqual(job["terminalization_evidence"]["final_status"], "launch_prepared")
            self.assertEqual(job["terminalization_evidence"]["source"], "prelaunch-metadata")
            self.assertIn("receipt_exists", job["expected_receipt"]["does_not_establish"])
            self.assertIn("job_success", job["expected_receipt"]["does_not_establish"])
            self.assertFalse(job["notify_on_done"]["requested"])
            self.assertFalse(job["notify_on_done"]["delivery_enabled"])
            self.assertEqual(job["notify_on_done"]["delivery_mode"], "metadata_only")
            self.assertEqual(job["notification_evidence"]["delivery_state"], "not_sent")
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

    def test_force_push_to_explicit_protected_destination_is_blocked(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator, "_git_branch", return_value="feature"):
            with self.assertRaisesRegex(PermissionError, "protected main branch"):
                operator._guard_git(
                    ["push", "--force", "origin", "HEAD:main"],
                    Path("/repo"),
                )
            with self.assertRaisesRegex(PermissionError, "protected main branch"):
                operator._guard_git(
                    ["push", "origin", "+refs/heads/master:refs/heads/master"],
                    Path("/repo"),
                )

    def test_forced_aggregate_push_is_blocked(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator, "_git_branch", return_value="feature") as branch:
            for arguments in (
                ["push", "--force", "--all", "origin"],
                ["push", "--force-with-lease", "--tags", "origin"],
                ["push", "origin", "+refs/heads/*:refs/heads/*"],
                ["push", "--mirror", "origin"],
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(PermissionError, "aggregate"):
                        operator._guard_git(arguments, Path("/repo"))
            branch.assert_not_called()

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


if __name__ == "__main__":
    unittest.main()
