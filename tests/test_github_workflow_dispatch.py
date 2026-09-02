from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "grabowski_github_workflow_dispatch.py"


class _FakeMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function


def _load_module():
    fake_operator = types.ModuleType("grabowski_operator_core")
    fake_operator.mcp = _FakeMCP()
    fake_operator.MUTATING = object()
    fake_operator.HOME = Path("/tmp")
    fake_operator._redact = (
        lambda value: "<REDACTED>"
        if "ghp_" in value or "Bearer " in value
        else value
    )
    fake_operator._trusted_owner_mode = lambda: True
    fake_operator._require_operator_mutation = lambda *args, **kwargs: None
    fake_operator._validate_argv = lambda argv, cwd=None: argv
    fake_operator._run = lambda *args, **kwargs: {}

    module_name = "grabowski_github_workflow_dispatch_test_target"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load workflow dispatch module")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        sys.modules,
        {
            "grabowski_operator_core": fake_operator,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module, fake_operator


class _FakeGitHub:
    def __init__(
        self,
        *,
        head: str = "a" * 40,
        workflow_state: str = "active",
        post_mode: str = "accepted",
        create_run_on_post: bool = True,
    ) -> None:
        self.head = head
        self.workflow_state = workflow_state
        self.post_mode = post_mode
        self.create_run_on_post = create_run_on_post
        self.calls: list[list[str]] = []
        self.post_count = 0
        self.runs: list[int] = []

    @staticmethod
    def _result(
        *,
        returncode: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        timed_out: bool = False,
    ) -> dict[str, object]:
        return {
            "returncode": returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
        }

    def __call__(self, args: list[str]) -> dict[str, object]:
        self.calls.append(list(args))
        endpoint = next(
            (
                item
                for item in args
                if isinstance(item, str) and item.startswith("repos/")
            ),
            "",
        )
        if endpoint == "repos/heimgewebe/commonthing":
            return self._result(
                stdout=json.dumps(
                    {
                        "full_name": "heimgewebe/commonthing",
                        "archived": False,
                        "disabled": False,
                        "default_branch": "main",
                    }
                )
            )
        if (
            "/actions/workflows/" in endpoint
            and "/runs?" not in endpoint
            and "--method" not in args
        ):
            return self._result(
                stdout=json.dumps(
                    {
                        "id": 42,
                        "name": "Staging image promotion",
                        "path": ".github/workflows/staging-image-promotion.yml",
                        "state": self.workflow_state,
                    }
                )
            )
        if "/commits/" in endpoint:
            return self._result(stdout=json.dumps({"sha": self.head}))
        if "/runs?" in endpoint:
            rows = [
                {
                    "id": run_id,
                    "workflow_id": 42,
                    "event": "workflow_dispatch",
                    "head_sha": self.head,
                    "head_branch": "main",
                    "status": "queued",
                    "conclusion": None,
                    "html_url": f"https://github.example/runs/{run_id}",
                    "created_at": "2026-09-02T05:00:00Z",
                    "updated_at": "2026-09-02T05:00:00Z",
                    "run_attempt": 1,
                    "run_number": run_id,
                }
                for run_id in self.runs
            ]
            return self._result(stdout=json.dumps({"workflow_runs": rows}))
        if "--method" in args and "POST" in args:
            self.post_count += 1
            if self.create_run_on_post:
                self.runs.append(100 + self.post_count)
            if self.post_mode == "accepted":
                return self._result()
            if self.post_mode == "422":
                return self._result(
                    returncode=1,
                    stderr="gh: invalid workflow input (HTTP 422)",
                )
            if self.post_mode == "403":
                return self._result(
                    returncode=1,
                    stderr="gh: resource not accessible (HTTP 403)",
                )
            if self.post_mode == "timeout":
                return self._result(returncode=None, timed_out=True)
            if self.post_mode == "unknown":
                return self._result(returncode=1, stderr="connection reset")
        raise AssertionError(f"unexpected GitHub call: {args!r}")


class GitHubWorkflowDispatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dispatch, self.operator = _load_module()

    def _call(
        self,
        runner: _FakeGitHub,
        directory: str,
        *,
        expected_head: str | None = "a" * 40,
        inputs: dict[str, str] | None = None,
    ):
        return self.dispatch.dispatch_workflow(
            "heimgewebe/commonthing",
            "staging-image-promotion.yml",
            "main",
            inputs=inputs or {"source_commit": "a" * 40},
            expected_head=expected_head,
            runner=runner,
            state_root=Path(directory),
            sleep=lambda _seconds: None,
            poll_attempts=2,
        )

    def test_exact_head_success_returns_unique_run_and_private_receipt(self) -> None:
        runner = _FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
            receipt_path = Path(result["receipt"]["path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_mode = receipt_path.stat().st_mode & 0o777

        self.assertTrue(result["ok"])
        self.assertEqual(result["result_code"], "dispatch_accepted")
        self.assertEqual(result["observed_head"], "a" * 40)
        self.assertEqual(result["run"]["run_id"], 101)
        self.assertEqual(result["run"]["event"], "workflow_dispatch")
        self.assertEqual(runner.post_count, 1)
        self.assertEqual(receipt["run"]["run_id"], 101)
        self.assertEqual(receipt["inputs"]["keys"], ["source_commit"])
        self.assertNotIn("a" * 40, json.dumps(receipt["inputs"], sort_keys=True))
        self.assertEqual(receipt_mode, 0o600)

    def test_expected_head_drift_never_posts(self) -> None:
        runner = _FakeGitHub(head="b" * 40)
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
        self.assertEqual(result["result_code"], "ref_head_drift")
        self.assertEqual(result["effect_state"], "not_started")
        self.assertEqual(runner.post_count, 0)

    def test_disabled_workflow_fails_closed_before_post(self) -> None:
        runner = _FakeGitHub(workflow_state="disabled_manually")
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
        self.assertEqual(result["result_code"], "workflow_inactive")
        self.assertEqual(runner.post_count, 0)

    def test_invalid_workflow_input_is_typed_422_and_not_started(self) -> None:
        runner = _FakeGitHub(post_mode="422", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
        self.assertEqual(result["result_code"], "invalid_workflow_inputs")
        self.assertEqual(result["effect_state"], "not_started")
        self.assertEqual(result["receipt"]["sha256"].__len__(), 64)
        self.assertEqual(runner.post_count, 1)

    def test_ambiguous_timeout_recovers_unique_run_without_retry(self) -> None:
        runner = _FakeGitHub(post_mode="timeout", create_run_on_post=True)
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
        self.assertEqual(
            result["result_code"],
            "dispatch_recovered_after_ambiguous_transport",
        )
        self.assertEqual(result["run"]["run_id"], 101)
        self.assertEqual(runner.post_count, 1)

    def test_ambiguous_timeout_without_run_blocks_second_post(self) -> None:
        runner = _FakeGitHub(post_mode="timeout", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            self.assertEqual(first["result_code"], "dispatch_outcome_unknown")
            runner.post_mode = "accepted"
            runner.create_run_on_post = True
            second = self._call(runner, directory)

        self.assertEqual(
            second["result_code"],
            "prior_ambiguous_outcome_unresolved",
        )
        self.assertEqual(second["effect_state"], "unknown")
        self.assertEqual(runner.post_count, 1)
        self.assertFalse(second["retry_authorized"])

    def test_ambiguous_timeout_can_be_recovered_on_later_readback(self) -> None:
        runner = _FakeGitHub(post_mode="timeout", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            self.assertEqual(first["result_code"], "dispatch_outcome_unknown")
            runner.runs.append(777)
            second = self._call(runner, directory)
        self.assertEqual(
            second["result_code"],
            "dispatch_recovered_after_ambiguous_transport",
        )
        self.assertEqual(second["run"]["run_id"], 777)
        self.assertEqual(runner.post_count, 1)

    def test_unclassified_post_failure_is_reconciled_not_blindly_retried(self) -> None:
        runner = _FakeGitHub(post_mode="unknown", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            second = self._call(runner, directory)
        self.assertEqual(first["result_code"], "dispatch_outcome_unknown")
        self.assertEqual(second["result_code"], "prior_ambiguous_outcome_unresolved")
        self.assertEqual(runner.post_count, 1)

    def test_secret_like_input_key_is_rejected_before_runner(self) -> None:
        runner = _FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(
                runner,
                directory,
                inputs={"github_token": "not-even-a-secret"},
            )
        self.assertEqual(result["result_code"], "secret_input_rejected")
        self.assertEqual(runner.calls, [])

    def test_secret_like_input_value_is_rejected_before_runner(self) -> None:
        runner = _FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(
                runner,
                directory,
                inputs={"source_commit": "ghp_" + "x" * 30},
            )
        self.assertEqual(result["result_code"], "secret_input_rejected")
        self.assertEqual(runner.calls, [])

    def test_dispatch_body_values_never_appear_in_command_argv(self) -> None:
        runner = _FakeGitHub()
        marker = "value-that-must-not-enter-argv"
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(
                runner,
                directory,
                expected_head="a" * 40,
                inputs={"source_commit": marker},
            )
        self.assertTrue(result["ok"])
        flattened = json.dumps(runner.calls, sort_keys=True)
        self.assertNotIn(marker, flattened)
        post = next(call for call in runner.calls if "--method" in call and "POST" in call)
        self.assertIn("--input", post)

    def test_public_tool_requires_github_cli_mutation_authority(self) -> None:
        with mock.patch.object(
            self.operator,
            "_require_operator_mutation",
        ) as require:
            with mock.patch.object(
                self.dispatch,
                "dispatch_workflow",
                return_value={"ok": True},
            ) as dispatch:
                result = self.dispatch.grabowski_github_workflow_dispatch(
                    "heimgewebe/commonthing",
                    "staging-image-promotion.yml",
                    "main",
                    inputs={"source_commit": "a" * 40},
                    expected_head="a" * 40,
                )
        self.assertEqual(result, {"ok": True})
        require.assert_called_once_with(
            "github_cli",
            repo="heimgewebe/commonthing",
            fresh_preflight=True,
        )
        dispatch.assert_called_once()

    def test_runtime_contract_publishes_typed_tool_and_supporting_module(self) -> None:
        runtime_contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            "grabowski_github_workflow_dispatch",
            runtime_contract["expected_tools"],
        )
        supporting = {
            item["module"]: item["source"]
            for item in runtime_contract["supporting_sources"]
        }
        self.assertEqual(
            supporting.get("grabowski_github_workflow_dispatch"),
            "src/grabowski_github_workflow_dispatch.py",
        )

        runtime_source = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        self.assertIn("import grabowski_github_workflow_dispatch", runtime_source)

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"grabowski_github_workflow_dispatch"', pyproject)


if __name__ == "__main__":
    unittest.main()
