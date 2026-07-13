from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

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
) -> Path:
    script = root / "claude"
    baseline_stream = support.stream(baseline).decode("utf-8")
    treatment_stream = support.stream(
        treatment, use_repobrief=treatment_uses_mcp
    ).decode("utf-8")
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
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


if __name__ == "__main__":
    unittest.main()
