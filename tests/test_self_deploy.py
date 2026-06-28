from __future__ import annotations

import importlib.util
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
        SELF_DEPLOY.operator.grabowski_job_start.reset_mock()
        SELF_DEPLOY.base._append_audit.reset_mock()
        SELF_DEPLOY.operator.grabowski_job_start.return_value = job
        with patch.object(SELF_DEPLOY, "_canonical_preflight", return_value=(repo, runner)):
            result = SELF_DEPLOY.grabowski_runtime_deploy_schedule(expected, 9)
        SELF_DEPLOY.operator.grabowski_job_start.assert_called_once_with(
            ["/usr/bin/python3", str(runner), "--repo", str(repo), "--expected-head", expected, "--delay-seconds", "9"],
            cwd=str(repo),
            runtime_seconds=3600,
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
        self.assertEqual(streamed.call_args_list[1].args[0], ["make", "deploy"])

if __name__ == "__main__":
    unittest.main()
