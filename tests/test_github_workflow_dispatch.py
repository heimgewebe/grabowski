from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "src" / "grabowski_github_workflow_dispatch.py"
NOW = datetime(2026, 9, 2, 5, 0, 0, tzinfo=timezone.utc).timestamp()


@dataclass(frozen=True)
class _GripSpec:
    name: str
    version: str
    summary: str
    effect: str
    required_parameters: tuple[str, ...]
    acceptance_ids: tuple[str, ...]
    runner: str
    uses_github: bool = False
    operation_effect_class: str = "unknown"
    operation_class: str = "unknown"
    capability: str = "terminal_execute"


class _GripPreflightError(ValueError):
    pass


def _load_module():
    fake_operator = types.ModuleType("grabowski_operator_core")
    fake_operator.HOME = Path("/tmp")
    fake_operator._redact = (
        lambda value: "<REDACTED>"
        if "ghp_" in value or "Bearer " in value
        else value
    )
    fake_operator._trusted_owner_mode = lambda: True

    fake_grips = types.ModuleType("grabowski_grips")
    fake_grips.GripSpec = _GripSpec
    fake_grips.GripPreflightError = _GripPreflightError
    fake_grips.MUTATING = "mutating"
    fake_grips.CommandRunner = object
    fake_grips.GithubRunner = object
    fake_grips.GRIP_SPECS = {}
    fake_grips._RUNNERS = {}
    fake_grips.GRIP_SURFACE_ALLOWLIST = frozenset()
    fake_grips.GRIP_RISK_LEVELS = {}
    fake_grips.GRIP_SURFACE_TARGETS = {}
    fake_grips.GRIP_RECOVERY_PATHS_BY_NAME = {}

    def check(receipt, name, status, detail):
        receipt.setdefault("checks", []).append(
            {"name": name, "status": status, "detail": detail}
        )

    fake_grips._check = check

    module_name = f"grabowski_github_workflow_dispatch_test_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load workflow dispatch module")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(
        sys.modules,
        {
            "grabowski_operator_core": fake_operator,
            "grabowski_grips": fake_grips,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module, fake_operator, fake_grips


class _FakeGitHub:
    def __init__(
        self,
        *,
        head: str = "a" * 40,
        workflow_state: str = "active",
        post_mode: str = "accepted",
        create_run_on_post: bool = True,
        runs_per_post: int = 1,
        run_readback_failures: int = 0,
        run_snapshots: list[list[int]] | None = None,
    ) -> None:
        self.head = head
        self.workflow_state = workflow_state
        self.post_mode = post_mode
        self.create_run_on_post = create_run_on_post
        self.runs_per_post = runs_per_post
        self.run_readback_failures = run_readback_failures
        self.calls: list[list[str]] = []
        self.post_count = 0
        self.runs: list[int] = []
        self.run_branches: dict[int, str] = {}
        self.run_snapshots = run_snapshots
        self.run_readback_count = 0

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
            if self.post_count > 0 and self.run_readback_failures > 0:
                self.run_readback_failures -= 1
                return self._result(returncode=1, stderr="connection reset")
            run_ids = self.runs
            if self.post_count > 0 and self.run_snapshots is not None:
                snapshot_index = min(
                    self.run_readback_count, len(self.run_snapshots) - 1
                )
                run_ids = self.run_snapshots[snapshot_index]
                self.run_readback_count += 1
            rows = [
                {
                    "id": run_id,
                    "workflow_id": 42,
                    "event": "workflow_dispatch",
                    "head_sha": self.head,
                    "head_branch": self.run_branches.get(run_id, "main"),
                    "status": "queued",
                    "conclusion": None,
                    "html_url": f"https://github.example/runs/{run_id}",
                    "created_at": "2026-09-02T05:00:00Z",
                    "updated_at": "2026-09-02T05:00:00Z",
                    "run_attempt": 1,
                    "run_number": run_id,
                }
                for run_id in run_ids
            ]
            return self._result(stdout=json.dumps({"workflow_runs": rows}))
        if "--method" in args and "POST" in args:
            self.post_count += 1
            if self.create_run_on_post:
                first_run_id = 100 + (self.post_count - 1) * 10 + 1
                self.runs.extend(
                    first_run_id + offset for offset in range(self.runs_per_post)
                )
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
        self.dispatch, self.operator, self.grips = _load_module()

    def _call(
        self,
        runner: _FakeGitHub,
        directory: str,
        *,
        expected_head: str | None = "a" * 40,
        inputs: dict[str, str] | None = None,
        poll_attempts: int = 2,
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
            time_fn=lambda: NOW,
            poll_attempts=poll_attempts,
        )

    def test_exact_head_success_returns_unique_run_and_private_receipt(self) -> None:
        runner = _FakeGitHub()
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
            receipt_path = Path(result["receipt"]["path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_mode = receipt_path.stat().st_mode & 0o777
            lock_mode = (receipt_path.parent / ".lock").stat().st_mode & 0o777

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
        self.assertEqual(lock_mode, 0o600)
        workflow_lookup = next(
            call
            for call in runner.calls
            if any(
                "/actions/workflows/" in item and "/runs?" not in item
                for item in call
                if isinstance(item, str)
            )
            and "--method" not in call
        )
        endpoint = next(
            item
            for item in workflow_lookup
            if isinstance(item, str) and "/actions/workflows/" in item
        )
        self.assertTrue(endpoint.endswith("/staging-image-promotion.yml"))
        self.assertNotIn("%2F", endpoint)

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
        self.assertEqual(len(result["receipt"]["sha256"]), 64)
        self.assertEqual(runner.post_count, 1)

    def test_auth_failure_is_typed_and_not_started(self) -> None:
        runner = _FakeGitHub(post_mode="403", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory)
        self.assertEqual(result["result_code"], "github_auth_or_permission")
        self.assertEqual(result["effect_state"], "not_started")
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

    def test_dispatch_attempt_is_durable_before_external_post(self) -> None:
        runner = _FakeGitHub(create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                self.dispatch,
                "_post",
                side_effect=SystemExit("simulated process loss"),
            ):
                with self.assertRaises(SystemExit):
                    self._call(runner, directory)

            active_path = next(
                Path(directory).glob(f"*/{self.dispatch.ACTIVE_ATTEMPT_FILE}")
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            second = self._call(runner, directory)

        self.assertEqual(active["result_code"], "dispatch_in_flight")
        self.assertEqual(active["effect_state"], "unknown")
        self.assertRegex(active["dispatch_attempt_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(
            second["result_code"], "prior_ambiguous_outcome_unresolved"
        )
        self.assertEqual(runner.post_count, 0)

    def test_active_attempt_survives_bounded_receipt_history(self) -> None:
        runner = _FakeGitHub(post_mode="timeout", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            request_dir = Path(first["receipt"]["path"]).parent
            original = json.loads(
                Path(first["receipt"]["path"]).read_text(encoding="utf-8")
            )
            original.pop("receipt_sha256")
            for index in range(70):
                noise = {
                    **original,
                    "dispatch_attempt_id": f"{index + 1:032x}",
                    "dispatch_attempted_at_unix": NOW + index + 1,
                    "effect_state": "not_started",
                    "result_code": "noise_terminal",
                    "completed_at_unix": NOW + index + 1,
                }
                self.dispatch._write_receipt(request_dir, noise)

            runner.post_mode = "accepted"
            runner.create_run_on_post = True
            second = self._call(runner, directory)

        self.assertEqual(first["result_code"], "dispatch_outcome_unknown")
        self.assertEqual(
            second["result_code"], "prior_ambiguous_outcome_unresolved"
        )
        self.assertEqual(runner.post_count, 1)

    def test_unique_run_observes_full_stabilization_window(self) -> None:
        runner = _FakeGitHub(
            create_run_on_post=False,
            run_snapshots=[[101], [101], [101, 102]],
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory, poll_attempts=3)

        self.assertEqual(result["result_code"], "run_identity_ambiguous")
        self.assertEqual(result["effect_state"], "unknown")
        self.assertEqual(runner.post_count, 1)
        self.assertFalse(result["retry_authorized"])

    def test_candidate_must_remain_visible_through_stabilization_window(self) -> None:
        runner = _FakeGitHub(
            create_run_on_post=False,
            run_snapshots=[[101], [], []],
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._call(runner, directory, poll_attempts=3)

        self.assertEqual(result["result_code"], "accepted_run_not_observed")
        self.assertEqual(result["effect_state"], "unknown")
        self.assertEqual(runner.post_count, 1)
        self.assertFalse(result["retry_authorized"])

    def test_readback_ignores_same_head_run_from_other_ref(self) -> None:
        runner = _FakeGitHub(create_run_on_post=False)
        runner.runs = [101]
        runner.run_branches[101] = "release"

        run, state, error = self.dispatch._readback(
            runner,
            repository="heimgewebe/commonthing",
            workflow_id=42,
            workflow_path=".github/workflows/staging-image-promotion.yml",
            ref="main",
            head="a" * 40,
            baseline=set(),
            attempted_at=NOW,
            attempts=1,
            sleep=lambda _seconds: None,
            time_fn=lambda: NOW,
        )

        self.assertIsNone(run)
        self.assertEqual(state, "missing")
        self.assertIsNone(error)

    def test_prior_ambiguous_outcome_survives_later_ref_drift(self) -> None:
        runner = _FakeGitHub(post_mode="timeout", create_run_on_post=False)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            self.assertEqual(first["result_code"], "dispatch_outcome_unknown")

            runner.head = "b" * 40
            second = self._call(runner, directory)
            self.assertEqual(second["result_code"], "prior_ambiguous_ref_drift")
            self.assertEqual(second["effect_state"], "unknown")

            runner.head = "a" * 40
            third = self._call(runner, directory)

        self.assertEqual(third["result_code"], "prior_ambiguous_outcome_unresolved")
        self.assertEqual(third["effect_state"], "unknown")
        self.assertEqual(runner.post_count, 1)

    def test_accepted_readback_failure_blocks_duplicate_post_and_recovers(self) -> None:
        runner = _FakeGitHub(run_readback_failures=1)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            self.assertEqual(first["result_code"], "accepted_run_readback_failed")
            second = self._call(runner, directory)

        self.assertEqual(
            second["result_code"],
            "dispatch_recovered_after_ambiguous_transport",
        )
        self.assertEqual(second["run"]["run_id"], 101)
        self.assertEqual(runner.post_count, 1)

    def test_multiple_matching_runs_block_duplicate_post(self) -> None:
        runner = _FakeGitHub(runs_per_post=2)
        with tempfile.TemporaryDirectory() as directory:
            first = self._call(runner, directory)
            self.assertEqual(first["result_code"], "run_identity_ambiguous")
            second = self._call(runner, directory)

        self.assertEqual(second["result_code"], "prior_ambiguous_multiple_runs")
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
        self.assertEqual(
            second["result_code"], "prior_ambiguous_outcome_unresolved"
        )
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
        post = next(
            call for call in runner.calls if "--method" in call and "POST" in call
        )
        self.assertIn("--input", post)

    def test_import_registers_high_risk_github_cli_grip_not_mcp_tool(self) -> None:
        spec = self.grips.GRIP_SPECS["github-workflow-dispatch"]
        self.assertEqual(spec.effect, "mutating")
        self.assertEqual(spec.capability, "github_cli")
        self.assertTrue(spec.uses_github)
        self.assertEqual(spec.operation_effect_class, "external_provider")
        self.assertIn("github-workflow-dispatch", self.grips.GRIP_SURFACE_ALLOWLIST)
        self.assertEqual(
            self.grips.GRIP_RISK_LEVELS["github-workflow-dispatch"], "high"
        )
        self.assertIn("github_workflow_dispatch", self.grips._RUNNERS)
        self.assertFalse(hasattr(self.dispatch, "grabowski_github_workflow_dispatch"))

    def test_grip_runner_adapts_remote_github_runner_and_blocks_unknown_parameter(self) -> None:
        runner = _FakeGitHub()
        seen_cwds: list[Path] = []

        def grip_github_runner(cwd: Path, arguments: list[str]):
            seen_cwds.append(cwd)
            return runner(arguments)

        original_dispatch = self.dispatch.dispatch_workflow

        def deterministic_dispatch(*args, **kwargs):
            kwargs["time_fn"] = lambda: NOW
            kwargs["sleep"] = lambda _seconds: None
            return original_dispatch(*args, **kwargs)

        receipt: dict[str, object] = {}
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    self.dispatch,
                    "DEFAULT_STATE_DIR",
                    Path(directory),
                ),
                mock.patch.object(
                    self.dispatch,
                    "dispatch_workflow",
                    side_effect=deterministic_dispatch,
                ),
            ):
                output = self.grips._RUNNERS["github_workflow_dispatch"](
                    self.grips.GRIP_SPECS["github-workflow-dispatch"],
                    {
                        "repository": "heimgewebe/commonthing",
                        "workflow": "staging-image-promotion.yml",
                        "ref": "main",
                        "inputs": {"source_commit": "a" * 40},
                        "expected_head": "a" * 40,
                    },
                    receipt,
                    object(),
                    grip_github_runner,
                )
        self.assertTrue(output["ok"])
        self.assertEqual(output["receipt_status"], "passed")
        self.assertTrue(seen_cwds)
        self.assertTrue(all(cwd == self.operator.HOME for cwd in seen_cwds))
        check_names = {item["name"] for item in receipt["checks"]}
        self.assertIn("unique-run-readback", check_names)

        with self.assertRaises(_GripPreflightError):
            self.grips._RUNNERS["github_workflow_dispatch"](
                self.grips.GRIP_SPECS["github-workflow-dispatch"],
                {
                    "repository": "heimgewebe/commonthing",
                    "workflow": "staging-image-promotion.yml",
                    "ref": "main",
                    "inputs": {},
                    "unexpected": True,
                },
                {},
                object(),
                grip_github_runner,
            )

    def test_runtime_contract_keeps_public_tool_surface_stable(self) -> None:
        runtime_contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn(
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

        runtime_source = (ROOT / "src" / "grabowski_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("import grabowski_github_workflow_dispatch", runtime_source)

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"grabowski_github_workflow_dispatch"', pyproject)


if __name__ == "__main__":
    unittest.main()
