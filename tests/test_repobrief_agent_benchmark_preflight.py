from __future__ import annotations

import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = Path(__file__).resolve().parent / "repobrief_agent_benchmark_preflight_cases.py"
SPEC = importlib.util.spec_from_file_location(
    "repobrief_agent_benchmark_preflight_cases", SUPPORT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RepoBrief preflight test cases")
support = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = support
SPEC.loader.exec_module(support)

_ORIGINAL_EXECUTE_PREFLIGHT = support.preflight.execute_preflight


def _fake_claude(
    root: Path,
    baseline: dict,
    treatment: dict,
    *,
    treatment_uses_mcp: bool = True,
    baseline_cost: str = "0.01",
    treatment_cost: str = "0.01",
) -> Path:
    script = root / "claude"
    baseline_stream = support.stream(baseline, cost=baseline_cost).decode("utf-8")
    treatment_stream = support.stream(
        treatment, cost=treatment_cost, use_repobrief=treatment_uses_mcp
    ).decode("utf-8")
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"log_path = {str(root / 'claude-invocations.jsonl')!r}\n"
        "with open(log_path, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if '--version' in sys.argv:\n"
        "    print('claude-code fixture 1.0')\n"
        "    raise SystemExit(0)\n"
        f"baseline = {baseline_stream!r}\n"
        f"treatment = {treatment_stream!r}\n"
        "index = sys.argv.index('--mcp-config') + 1\n"
        "config = json.load(open(sys.argv[index], encoding='utf-8'))\n"
        "is_treatment = bool(config.get('mcpServers'))\n"
        "sys.stdout.write(treatment if is_treatment else baseline)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _execute_with_test_provider_binding(*args, **kwargs):
    synthetic = (
        kwargs.get("baseline_fixture") is not None
        or kwargs.get("treatment_fixture") is not None
    )
    if not synthetic:
        state_root = Path(kwargs["state_root"]).expanduser().resolve()
        credential = state_root.parent / "fixture-claude-credentials.json"
        credential.write_text("{}\n", encoding="utf-8")
        credential.chmod(0o600)
        executable = Path(kwargs["claude"]).expanduser().resolve()
        kwargs["claude_credential_file"] = credential
        kwargs["claude_command_sha256"] = hashlib.sha256(
            executable.read_bytes()
        ).hexdigest()
    return _ORIGINAL_EXECUTE_PREFLIGHT(*args, **kwargs)


support.fake_claude = _fake_claude
support.preflight.execute_preflight = _execute_with_test_provider_binding
RepoBriefAgentBenchmarkPreflightTests = (
    support.RepoBriefAgentBenchmarkPreflightTests
)


def _preflight_kwargs(root: Path, environment: dict) -> dict:
    return {
        "pair_id": support.PAIR_ID,
        "request_root": environment["request_root"],
        "repository_map": environment["repository_map"],
        "state_root": root / "state",
        "transcript_root": root / "transcripts",
        "evidence_root": root / "evidence",
        "claude": str(environment["claude"]),
        "max_cost_usd": support.Decimal("1.00"),
        "validator_command": [sys.executable, str(root / "validator.py")],
    }


def _fixture_kwargs(root: Path, environment: dict) -> dict:
    baseline = root / "baseline.jsonl"
    treatment = root / "treatment.jsonl"
    baseline.write_bytes(support.stream(environment["baseline"]))
    treatment.write_bytes(support.stream(environment["treatment"]))
    return {
        **_preflight_kwargs(root, environment),
        "baseline_fixture": baseline,
        "treatment_fixture": treatment,
    }


class RepoBriefAgentBenchmarkPreflightAdapterTests(unittest.TestCase):
    def test_live_call_requires_explicit_provider_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "requires credential file and Claude executable SHA-256",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(
                    pair_id=support.PAIR_ID,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[
                        sys.executable,
                        str(root / "validator.py"),
                    ],
                )

    def test_fixture_rejects_live_provider_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            baseline_fixture = root / "baseline.jsonl"
            treatment_fixture = root / "treatment.jsonl"
            baseline_fixture.write_bytes(support.stream(environment["baseline"]))
            treatment_fixture.write_bytes(support.stream(environment["treatment"]))
            credential = root / "credentials.json"
            credential.write_text("{}\n", encoding="utf-8")
            credential.chmod(0o600)
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "synthetic fixtures must not carry live provider bindings",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(
                    pair_id=support.PAIR_ID,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[
                        sys.executable,
                        str(root / "validator.py"),
                    ],
                    baseline_fixture=baseline_fixture,
                    treatment_fixture=treatment_fixture,
                    claude_credential_file=credential,
                    claude_command_sha256="0" * 64,
                )

    def test_main_rejects_missing_live_bindings_before_core(self) -> None:
        self.assertEqual(support.preflight.main([]), 2)

    def test_live_preflight_starts_exactly_two_claude_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            report = _execute_with_test_provider_binding(
                **_preflight_kwargs(root, environment)
            )
            invocations = [
                json.loads(line)
                for line in (root / "claude-invocations.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(invocations), 2)
            self.assertTrue(all("--version" not in item for item in invocations))
            self.assertEqual(
                report["dispatch_ledger"]["provider_process_intents"], 2
            )
            self.assertIsNone(report["environment"]["claude"]["version"])
            self.assertFalse(
                report["environment"]["claude"]["version_probed"]
            )


class RepoBriefAgentBenchmarkPreflightLedgerTests(unittest.TestCase):
    def test_fixture_success_is_one_shot_and_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            report = _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            ledger = report["dispatch_ledger"]
            self.assertEqual(ledger["condition_intents"], ["baseline", "treatment"])
            self.assertEqual(ledger["provider_process_intents"], 0)
            self.assertEqual(ledger["fixture_intents"], 2)
            self.assertEqual(ledger["event_count"], 6)
            self.assertFalse(ledger["retry_permitted"])
            events = support.ledger_events(root / "state")
            previous = events[0]["contract_sha256"]
            for event in events:
                self.assertEqual(event["previous_event_sha256"], previous)
                previous = support.preflight._sha256_json(event)
            self.assertEqual(previous, ledger["final_event_sha256"])
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "blocks retry"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)

    def test_changed_binding_cannot_reuse_existing_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            kwargs["max_cost_usd"] = support.Decimal("0.50")
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "different schema, code, plan, path, or budget"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)

    def test_ambiguous_launch_records_intent_and_blocks_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            error = support.preflight.runner.RunnerError(
                "provider process launch outcome is unknown"
            )
            with mock.patch.object(
                support.preflight._core.runner, "execute", side_effect=error
            ):
                with self.assertRaisesRegex(
                    support.preflight.runner.RunnerError, "outcome is unknown"
                ):
                    _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-failed",
                    "preflight-failed",
                ],
            )
            self.assertTrue(
                events[2]["payload"]["transcript"]["outcome_ambiguous"]
            )
            self.assertEqual(
                events[-1]["payload"]["provider_process_intents"], 1
            )
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "blocks retry"
            ):
                _execute_with_test_provider_binding(**kwargs)

    def test_budget_stop_preserves_observed_overshoot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            environment["claude"] = _fake_claude(
                root,
                environment["baseline"],
                environment["treatment"],
                treatment_cost="1.25",
            )
            kwargs = _preflight_kwargs(root, environment)
            with self.assertRaisesRegex(
                support.preflight.runner.RunnerError, "cost exceeds max_budget_usd"
            ):
                _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            failure = next(
                event
                for event in events
                if event["event"] == "condition-failed"
            )
            transcript = failure["payload"]["transcript"]
            self.assertEqual(transcript["observed_cost_usd"], "1.25")
            self.assertFalse(transcript["outcome_ambiguous"])
            terminal = events[-1]["payload"]
            self.assertEqual(terminal["observed_costs"]["baseline"], "0.01")
            self.assertEqual(terminal["observed_costs"]["treatment"], "1.25")
            self.assertEqual(terminal["provider_process_intents"], 2)
            self.assertFalse(terminal["retry_permitted"])

    def test_existing_receipt_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            receipt = support.preflight._receipt_path(
                root / "evidence", environment["baseline"]
            )
            receipt.parent.mkdir(parents=True)
            receipt.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "receipt path already exists"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            self.assertEqual(receipt.read_text(encoding="utf-8"), "sentinel\n")
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                ["authorized", "preflight-failed"],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 0)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])

    def test_duplicate_condition_and_third_intent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            with mock.patch.object(
                support.preflight._core,
                "_dispatch_provider_binding",
                return_value={"mode": "live_provider_fixture"},
            ):
                binding = support.preflight._dispatch_binding(
                    baseline=environment["baseline"],
                    treatment=environment["treatment"],
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=None,
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                    synthetic=False,
                )
            ledger = support.preflight._initialize_dispatch_ledger(
                binding=binding, state_root=root / "state"
            )
            support.preflight._record_dispatch_intent(
                ledger,
                environment["baseline"],
                synthetic=False,
                max_cost_usd=support.Decimal("1.00"),
            )
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "already exists for baseline"
            ):
                support.preflight._record_dispatch_intent(
                    ledger,
                    environment["baseline"],
                    synthetic=False,
                    max_cost_usd=support.Decimal("1.00"),
                )
            support.preflight._record_dispatch_intent(
                ledger,
                environment["treatment"],
                synthetic=False,
                max_cost_usd=support.Decimal("1.00"),
            )
            third = dict(environment["baseline"])
            third["condition"] = "baseline"
            ledger["condition_intents"] = ["treatment", "other"]
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "third process intent"
            ):
                support.preflight._record_dispatch_intent(
                    ledger,
                    third,
                    synthetic=False,
                    max_cost_usd=support.Decimal("1.00"),
                )


    def test_request_mutation_after_baseline_blocks_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            original = support.preflight._core.runner.execute

            def mutate_plan_after_baseline(request: dict, **run_kwargs):
                output = original(request, **run_kwargs)
                if request["condition"] == "baseline":
                    path = support.preflight._request_path(
                        environment["request_root"], environment["treatment"]
                    )
                    changed = json.loads(path.read_text(encoding="utf-8"))
                    changed["prompt"] += " changed"
                    path.write_text(
                        json.dumps(changed, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                return output

            with mock.patch.object(
                support.preflight._core.runner,
                "execute",
                side_effect=mutate_plan_after_baseline,
            ):
                with self.assertRaises(support.preflight.PreflightError):
                    _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-completed",
                    "preflight-failed",
                ],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 1)

    def test_credential_mutation_after_intent_blocks_before_provider_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            original = support.preflight._core._record_dispatch_intent
            credential = root / "fixture-claude-credentials.json"

            def mutate_after_intent(*args, **record_kwargs):
                result = original(*args, **record_kwargs)
                request = args[1]
                if request["condition"] == "baseline":
                    credential.write_text('{"changed":true}\n', encoding="utf-8")
                    credential.chmod(0o600)
                return result

            with mock.patch.object(
                support.preflight._core,
                "_record_dispatch_intent",
                side_effect=mutate_after_intent,
            ):
                with self.assertRaisesRegex(
                    support.preflight.runner.RunnerError,
                    "credential file changed after authorization",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            self.assertFalse((root / "claude-invocations.jsonl").exists())
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-failed",
                    "preflight-failed",
                ],
            )
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 1)

    def test_credential_mutation_after_baseline_blocks_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            original = support.preflight._core.runner.execute
            credential = root / "fixture-claude-credentials.json"

            def mutate_credential_after_baseline(request: dict, **run_kwargs):
                output = original(request, **run_kwargs)
                if request["condition"] == "baseline":
                    credential.write_text('{"changed":true}\n', encoding="utf-8")
                    credential.chmod(0o600)
                return output

            with mock.patch.object(
                support.preflight._core.runner,
                "execute",
                side_effect=mutate_credential_after_baseline,
            ):
                with self.assertRaisesRegex(
                    support.preflight.PreflightError,
                    "credential file changed after authorization",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(events[-1]["event"], "preflight-failed")
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 1)
            self.assertEqual(events[-1]["payload"]["observed_costs"]["baseline"], "0.01")


    def test_synthetic_cli_publishes_report_bound_in_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            fixtures = _fixture_kwargs(root, environment)
            report = root / "published-report.json"
            argv = [
                "--pair-id",
                support.PAIR_ID,
                "--request-root",
                str(environment["request_root"]),
                "--repository-map",
                str(environment["repository_map"]),
                "--state-root",
                str(root / "state"),
                "--transcript-root",
                str(root / "transcripts"),
                "--evidence-root",
                str(root / "evidence"),
                "--report-out",
                str(report),
                "--validator-command",
                str(environment["validator_command"]),
                "--max-cost-usd",
                "1.00",
                "--baseline-stream-fixture",
                str(fixtures["baseline_fixture"]),
                "--treatment-stream-fixture",
                str(fixtures["treatment_fixture"]),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = support.preflight.main(argv)
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertTrue(report.is_file())
            self.assertTrue(Path(str(report) + ".sha256").is_file())
            parent = root / "state" / "preflight-dispatch-ledger"
            pair_root = next(parent.iterdir())
            authorization = json.loads(
                (pair_root / "authorization.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                authorization["binding"]["report_out"], str(report.resolve())
            )
            self.assertEqual(
                authorization["binding"]["report_digest_out"],
                str(Path(str(report.resolve()) + ".sha256")),
            )
            published = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(published["status"], "synthetic_only")
            self.assertFalse(published["dispatch_ledger"]["retry_permitted"])

    def test_preexisting_report_path_blocks_before_process_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            report = root / "report.json"
            report.write_text("sentinel\n", encoding="utf-8")
            kwargs["report_out"] = report
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "preflight report path already exists",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            self.assertEqual(report.read_text(encoding="utf-8"), "sentinel\n")
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                ["authorized", "preflight-failed"],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 0)

    def test_source_mutation_records_terminal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            original = support.preflight._core.source_state
            calls = 0

            def mutating_source_state(source: Path) -> dict:
                nonlocal calls
                calls += 1
                if calls == 2:
                    (source / "mutation.txt").write_text(
                        "changed", encoding="utf-8"
                    )
                return original(source)

            with mock.patch.object(
                support.preflight._core,
                "source_state",
                side_effect=mutating_source_state,
            ):
                with self.assertRaisesRegex(
                    support.preflight.PreflightError, "source checkout changed"
                ):
                    _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(events[-1]["event"], "preflight-failed")
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 2)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])


if __name__ == "__main__":
    unittest.main()
