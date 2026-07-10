from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
from typing import get_args
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]

class _FakeFastMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

def _load_self_deploy():
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.Field = lambda **kwargs: kwargs
    operator = types.ModuleType("grabowski_operator_core")
    operator.mcp = _FakeFastMCP()
    operator._require_operator_mutation = Mock()
    operator._require_operator_capability = Mock()
    operator.grabowski_job_start = Mock()
    operator._start_job = Mock()
    base = types.ModuleType("grabowski_mcp")
    base._append_audit = Mock()
    read_surface = types.ModuleType("grabowski_read_surface")
    read_surface._git_command = lambda repo, *args: ["git", "-C", str(repo), *args]
    read_surface._run_read = Mock()
    name = "grabowski_self_deploy_test"
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / "grabowski_self_deploy.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load self deploy module")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types, "pydantic": fake_pydantic, "grabowski_operator_core": operator, "grabowski_mcp": base, "grabowski_read_surface": read_surface, name: module}, clear=False):
        spec.loader.exec_module(module)
    return module

def _result(stdout: str = "", returncode: int = 0) -> dict[str, object]:
    return {"returncode": returncode, "timed_out": False, "stdout_truncated": False, "stderr_truncated": False, "stdout": stdout, "stderr": ""}

SELF_DEPLOY = _load_self_deploy()

RUNNER_SPEC = importlib.util.spec_from_file_location("run_scheduled_deploy_test", ROOT / "tools" / "run_scheduled_deploy.py")
if RUNNER_SPEC is None or RUNNER_SPEC.loader is None:
    raise RuntimeError("cannot load scheduled deployment runner")
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)

SCHEDULER_SPEC = importlib.util.spec_from_file_location("schedule_runtime_deploy_test", ROOT / "tools" / "schedule_runtime_deploy.py")
if SCHEDULER_SPEC is None or SCHEDULER_SPEC.loader is None:
    raise RuntimeError("cannot load runtime deployment scheduler")
SCHEDULER = importlib.util.module_from_spec(SCHEDULER_SPEC)
SCHEDULER_SPEC.loader.exec_module(SCHEDULER)

class SelfDeployToolTests(unittest.TestCase):
    def test_annotations_and_schema_bounds(self) -> None:
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.readOnlyHint)
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.destructiveHint)
        self.assertFalse(SELF_DEPLOY.DEPLOY_MUTATING.idempotentHint)
        self.assertTrue(SELF_DEPLOY.DEPLOY_MUTATING.openWorldHint)
        self.assertEqual(get_args(SELF_DEPLOY.DelaySeconds)[1]["ge"], 5)
        self.assertEqual(get_args(SELF_DEPLOY.DelaySeconds)[1]["le"], 60)

    def test_preflight_requires_clean_synchronized_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            runner = repo / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "a" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", repo), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[_result(expected), _result("main"), _result(expected), _result("")],
            ):
                resolved_repo, resolved_runner = SELF_DEPLOY._canonical_preflight(expected)
            self.assertEqual(resolved_repo, repo)
            self.assertEqual(resolved_runner, runner)

    def test_preflight_rejects_dirty_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            runner = repo / "tools" / "run_scheduled_deploy.py"
            runner.parent.mkdir()
            runner.write_text("pass\n", encoding="utf-8")
            expected = "b" * 40
            with patch.object(SELF_DEPLOY, "CANONICAL_REPOSITORY", repo), patch.object(
                SELF_DEPLOY,
                "_git_result",
                side_effect=[_result(expected), _result("main"), _result(expected), _result(" M file")],
            ):
                with self.assertRaisesRegex(RuntimeError, "dirty"):
                    SELF_DEPLOY._canonical_preflight(expected)

    def test_schedule_uses_fixed_delayed_runner(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        expected = "c" * 40
        job = {"unit": "grabowski-job-test", "argv_sha256": "d" * 64, "metadata_path": "/state/meta", "stdout_path": "/state/out", "stderr_path": "/state/err"}
        SELF_DEPLOY.operator._start_job.reset_mock()
        SELF_DEPLOY.base._append_audit.reset_mock()
        SELF_DEPLOY.operator._start_job.return_value = job
        with patch.object(SELF_DEPLOY, "_canonical_preflight", return_value=(repo, runner)):
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 9)
        SELF_DEPLOY.operator._start_job.assert_called_once_with(
            ["/usr/bin/python3", str(runner), "--repo", str(repo), "--expected-head", expected, "--delay-seconds", "9"],
            cwd=str(repo),
            runtime_seconds=3600,
            finalization_expected_head=expected,
        )
        self.assertTrue(result["scheduled"])
        self.assertTrue(result["expected_connector_disconnect"])
        self.assertEqual(result["unit"], "grabowski-job-test")
        self.assertEqual(SELF_DEPLOY.base._append_audit.call_count, 2)
        self.assertEqual(result["audit"]["intent"]["operation"], "runtime-deploy-schedule-intent")
        self.assertEqual(result["audit"]["scheduled"]["operation"], "runtime-deploy-scheduled")

class ScheduledDeployRunnerTests(unittest.TestCase):
    def test_capture_fails_closed_on_excess_output(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exceeded"):
            RUNNER.run_capture(
                [sys.executable, "-c", 'print("x" * 70000)'],
                cwd=Path("/tmp"),
            )

    def test_verify_repository_rejects_non_main(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary).resolve()
            expected = "e" * 40
            with patch.object(RUNNER, "run_capture", side_effect=[expected, "topic", expected, ""]):
                with self.assertRaisesRegex(RuntimeError, "not on main"):
                    RUNNER.verify_repository(repo, expected)

    def test_main_validates_before_deploying(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository") as verify, patch.object(RUNNER, "run_streamed") as streamed, patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "r", "repo_head": expected, "completion_status": "complete"}):
            self.assertEqual(RUNNER.main(), 0)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(streamed.call_args_list[0].args[0], ["make", "validate"])
        self.assertEqual(streamed.call_args_list[1].args[0], ["make", "deploy-apply"])

    def test_finalization_binding_and_atomic_receipt_are_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            expected = "a" * 40
            argv_sha256 = "b" * 64
            env = {
                "GRABOWSKI_JOB_ID": "deadbeefcafe",
                "GRABOWSKI_JOB_UNIT": "grabowski-job-deadbeefcafe",
                "GRABOWSKI_JOB_ARGV_SHA256": argv_sha256,
                "GRABOWSKI_JOB_EXPECTED_HEAD": expected,
                "GRABOWSKI_JOB_METADATA_PATH": str(directory / "metadata.json"),
                "GRABOWSKI_JOB_STDOUT_PATH": str(directory / "stdout.log"),
                "GRABOWSKI_JOB_STDERR_PATH": str(directory / "stderr.log"),
                "GRABOWSKI_JOB_FINALIZATION_PATH": str(directory / "finalization.json"),
            }
            with patch.dict(os.environ, env, clear=False):
                binding = RUNNER.load_finalization_binding()
            self.assertIsNotNone(binding)
            with patch.object(RUNNER.time, "time", return_value=1001):
                receipt_path = RUNNER.write_finalization_receipt(
                    binding,
                    final_status="completed",
                    repo_head=expected,
                    release_id="release-test",
                    failure_type=None,
                )
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            material = {key: value for key, value in payload.items() if key != "payload_sha256"}
            self.assertEqual(payload["payload_sha256"], RUNNER.canonical_json_sha256(material))
            self.assertEqual(payload["job_id"], "deadbeefcafe")
            self.assertEqual(payload["argv_sha256"], argv_sha256)
            self.assertEqual(payload["expected_head"], expected)
            self.assertEqual(payload["final_status"], "completed")
            with self.assertRaises(FileExistsError):
                RUNNER.write_finalization_receipt(
                    binding,
                    final_status="failed",
                    repo_head=None,
                    release_id=None,
                    failure_type="RuntimeError",
                )

    def test_receipt_publish_failure_removes_visible_partial_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            binding = {
                "schema_version": 1,
                "kind": RUNNER.FINALIZATION_KIND,
                "job_id": "deadbeefcafe",
                "unit": "grabowski-job-deadbeefcafe",
                "argv_sha256": "b" * 64,
                "expected_head": "a" * 40,
                "receipt_paths": {
                    "metadata": str(directory / "metadata.json"),
                    "stdout": str(directory / "stdout.log"),
                    "stderr": str(directory / "stderr.log"),
                    "finalization": str(directory / "finalization.json"),
                },
            }
            with patch.object(
                RUNNER.os,
                "fsync",
                side_effect=[None, OSError("directory fsync failed"), None],
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failed"):
                    RUNNER.write_finalization_receipt(
                        binding,
                        final_status="completed",
                        repo_head="a" * 40,
                        release_id="release-test",
                        failure_type=None,
                    )
            self.assertFalse((directory / "finalization.json").exists())
            self.assertEqual(list(directory.glob(".finalization.json.*.tmp")), [])

    def test_verify_live_manifest_rejects_missing_release_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            manifest = home / ".local/share/grabowski-mcp/deployment-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "repo_head": "a" * 40,
                        "completion_status": "complete",
                        "release_id": None,
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(RUNNER.Path, "home", return_value=home):
                with self.assertRaisesRegex(RuntimeError, "release_id is invalid"):
                    RUNNER.verify_live_manifest("a" * 40)

    def test_main_writes_completed_receipt_after_live_manifest_verification(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=binding), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository"), patch.object(RUNNER, "run_streamed"), patch.object(RUNNER, "verify_live_manifest", return_value={"release_id": "release", "repo_head": expected, "completion_status": "complete"}), patch.object(RUNNER, "write_finalization_receipt") as write:
            self.assertEqual(RUNNER.main(), 0)
        write.assert_called_once_with(
            binding,
            final_status="completed",
            repo_head=expected,
            release_id="release",
            failure_type=None,
        )

    def test_main_writes_failed_receipt_for_runner_failure(self) -> None:
        repo = Path("/tmp/repository")
        expected = "f" * 40
        binding = {"expected_head": expected}
        with patch.object(sys, "argv", ["runner", "--repo", str(repo), "--expected-head", expected, "--delay-seconds", "5"]), patch.object(RUNNER, "load_finalization_binding", return_value=binding), patch.object(RUNNER.time, "sleep"), patch.object(RUNNER, "verify_repository", side_effect=RuntimeError("preflight failed")), patch.object(RUNNER, "write_finalization_receipt") as write:
            self.assertEqual(RUNNER.main(), 1)
        write.assert_called_once_with(
            binding,
            final_status="failed",
            repo_head=None,
            release_id=None,
            failure_type="RuntimeError",
        )

    def test_make_deploy_schedules_not_direct_apply(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("deploy-apply: context-check deploy-tooling", makefile)
        self.assertIn("tools/deploy_runtime_dual.py --apply", makefile)
        self.assertIn('deploy: context-check\n>$(PYTHON) tools/schedule_runtime_deploy.py --repo "$(CURDIR)" --delay-seconds 8', makefile)


class RuntimeDeploySchedulerTests(unittest.TestCase):
    def test_build_systemd_run_argv_uses_fixed_runner_and_expected_head(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        head = "a" * 40
        argv = SCHEDULER.build_systemd_run_argv(repo, runner, head, 9, now=123)
        self.assertEqual(argv[:2], ["systemd-run", "--user"])
        self.assertIn("grabowski-scheduled-deploy-aaaaaaaaaaaa-123", argv)
        self.assertIn("/usr/bin/python3", argv)
        self.assertIn(str(runner), argv)
        self.assertEqual(argv[argv.index("--expected-head") + 1], head)
        self.assertEqual(argv[argv.index("--delay-seconds") + 1], "9")

    def test_schedule_verifies_repository_before_systemd_run(self) -> None:
        repo = Path("/home/alex/repos/grabowski")
        runner = repo / "tools/run_scheduled_deploy.py"
        head = "b" * 40
        with patch.object(SCHEDULER, "verify_repository", return_value=(repo, head, runner)) as verify, \
            patch.object(SCHEDULER.time, "time", return_value=456), \
            patch.object(SCHEDULER, "run_systemd_run", return_value={"returncode": 0, "stdout": "started", "stderr": ""}) as run:
            result = SCHEDULER.schedule(repo, 8)
        verify.assert_called_once_with(repo)
        self.assertEqual(result["expected_head"], head)
        self.assertEqual(result["unit"], "grabowski-scheduled-deploy-bbbbbbbbbbbb-456")
        self.assertTrue(result["expected_connector_disconnect"])
        self.assertIn("run_scheduled_deploy.py", result["runner"])
        self.assertEqual(run.call_args.kwargs["cwd"], repo)

    def test_schedule_bounds_delay_seconds(self) -> None:
        with self.assertRaises(ValueError):
            SCHEDULER.schedule(Path("/home/alex/repos/grabowski"), 4)
        with self.assertRaises(ValueError):
            SCHEDULER.schedule(Path("/home/alex/repos/grabowski"), 61)


if __name__ == "__main__":
    unittest.main()
