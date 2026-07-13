from __future__ import annotations

from decimal import Decimal
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "repobrief_agent_benchmark_preflight.py"
SPEC = importlib.util.spec_from_file_location("repobrief_agent_benchmark_preflight", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)
runner = preflight.runner

MODEL = "claude-opus-4-1-20250805"
TASKSET = "repobrief-agent-benchmark-v1-20260713"
CASE = "grounding-clean-freshness"
PAIR_ID = f"{TASKSET}:{CASE}:r1"


def git(command: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *command], cwd=cwd, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def repository(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    git(["init"], source)
    git(["config", "user.email", "test@example.invalid"], source)
    git(["config", "user.name", "Test"], source)
    (source / "src").mkdir()
    (source / "src" / "example.py").write_text(
        "def example():\n    return True\n", encoding="utf-8"
    )
    git(["add", "."], source)
    git(["commit", "-m", "fixture"], source)
    return source, git(["rev-parse", "HEAD"], source)


def request(
    *,
    condition: str,
    commit: str,
    manifest: Path,
    manifest_sha256: str,
    mcp_command: list[str],
) -> dict:
    allowed = {"glob", "grep", "read_file", "search"}
    repobrief = None
    if condition == "treatment":
        allowed.update(
            {
                "ask_context",
                "grounding_verify",
                "live_freshness",
                "repobrief_resource_read",
            }
        )
        repobrief = {
            "manifest": str(manifest),
            "manifest_sha256": manifest_sha256,
            "mcp_command": mcp_command,
        }
    request_id = f"{PAIR_ID}:{condition}"
    return {
        "kind": runner.REQUEST_KIND,
        "version": runner.VERSION,
        "request_id": request_id,
        "pair_id": PAIR_ID,
        "case_id": CASE,
        "condition": condition,
        "order": 1 if condition == "baseline" else 2,
        "repetition": 1,
        "taskset_id": TASKSET,
        "taskset_sha256": "a" * 64,
        "repository": {
            "id": "repo",
            "repository": "heimgewebe/repo",
            "commit": commit,
        },
        "session_id": f"session:{request_id}",
        "workspace_id": f"workspace:{request_id}",
        "prompt": "Check whether the snapshot is fresh.",
        "allowed_tools": sorted(allowed),
        "budgets": {
            "wall_seconds": 30,
            "input_tokens": 64000,
            "output_tokens": 6000,
            "max_tool_calls": 80,
            "max_tool_input_bytes": 1048576,
            "max_tool_output_bytes": 8388608,
        },
        "runner": {
            "provider": runner.PROVIDER,
            "model": MODEL,
            "sampling": {},
        },
        "repobrief": repobrief,
        "isolation": {
            "fresh_session": True,
            "fresh_workspace": True,
            "cross_condition_reuse_allowed": False,
        },
        "does_not_establish": list(runner.DOES_NOT_ESTABLISH),
    }


def answer(condition: str) -> dict:
    if condition == "baseline":
        return {
            "text": "Freshness cannot be established without the bound tool.",
            "outcome": "abstain",
            "reported_paths": [],
            "reported_symbols": [],
            "citations": [],
            "claims": ["freshness_not_established"],
            "asserted_sufficient_evidence": False,
        }
    return {
        "text": "The bound snapshot is fresh.",
        "outcome": "answer",
        "reported_paths": [],
        "reported_symbols": [],
        "citations": [],
        "claims": ["snapshot_fresh"],
        "asserted_sufficient_evidence": True,
    }


def stream(value: dict, *, cost: str = "0.01", use_repobrief: bool = True) -> bytes:
    condition = value["condition"]
    tool_name = "Read"
    if condition == "treatment" and use_repobrief:
        tool_name = "mcp__repobrief__live_freshness"
    tools = list(runner.READ_ONLY_BUILTINS)
    if condition == "treatment":
        tools.extend(runner.TREATMENT_RESOURCE_TOOLS)
        tools.extend(runner.TREATMENT_MCP_TOOLS)
    messages = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": f"provider-{condition}",
            "model": MODEL,
            "tools": tools,
        },
        {
            "type": "assistant",
            "session_id": f"provider-{condition}",
            "message": {
                "id": f"message-{condition}",
                "content": [
                    {
                        "type": "tool_use",
                        "id": f"tool-{condition}",
                        "name": tool_name,
                        "input": {"bundle_manifest": value.get("repobrief", {}).get("manifest")}
                        if condition == "treatment"
                        else {"file_path": "src/example.py"},
                    }
                ],
                "usage": {"input_tokens": 100, "output_tokens": 5},
            },
        },
        {
            "type": "user",
            "session_id": f"provider-{condition}",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": f"tool-{condition}",
                        "content": {"status": "fresh"}
                        if condition == "treatment"
                        else "def example(): return True",
                        "is_error": False,
                    }
                ]
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "session_id": f"provider-{condition}",
            "usage": {"input_tokens": 100, "output_tokens": 20},
            "structured_output": answer(condition),
            "total_cost_usd": cost,
        },
    ]
    return b"".join(
        json.dumps(message, sort_keys=True).encode("utf-8") + b"\n"
        for message in messages
    )


def mcp_script(root: Path, *, status: str = "fresh") -> Path:
    script = root / f"mcp-{status}.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    if request['method'] == 'initialize':\n"
        "        result = {'protocolVersion': '2025-06-18', 'capabilities': {}}\n"
        "    else:\n"
        f"        payload = {{'status': {status!r}, 'reason': 'fixture'}}\n"
        "        result = {'structuredContent': payload, 'isError': False, 'content': []}\n"
        "    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)\n",
        encoding="utf-8",
    )
    return script


def fake_claude(root: Path, baseline: dict, treatment: dict, *, treatment_uses_mcp: bool = True) -> Path:
    script = root / "claude"
    baseline_stream = stream(baseline).decode("utf-8")
    treatment_stream = stream(treatment, use_repobrief=treatment_uses_mcp).decode("utf-8")
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('claude-code fixture 1.0')\n"
        "    raise SystemExit(0)\n"
        f"baseline = {baseline_stream!r}\n"
        f"treatment = {treatment_stream!r}\n"
        "sys.stdout.write(treatment if '--mcp-config' in sys.argv else baseline)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def validator(root: Path, *, success: bool = True) -> tuple[Path, Path]:
    script = root / "validator.py"
    script.write_text(
        "import json, sys\n"
        + ("print(json.dumps({'status': 'valid', 'errors': []}))\n" if success else "raise SystemExit(2)\n"),
        encoding="utf-8",
    )
    command = root / "validator-command.json"
    command.write_text(
        json.dumps({"command": [sys.executable, str(script)]}), encoding="utf-8"
    )
    return script, command


def fixture_environment(root: Path, *, freshness: str = "fresh") -> dict:
    source, commit = repository(root)
    manifest = root / "repo.bundle.manifest.json"
    manifest.write_text('{"kind":"fixture"}\n', encoding="utf-8")
    manifest_sha = preflight._sha256_bytes(manifest.read_bytes())
    mcp = mcp_script(root, status=freshness)
    mcp_command = [sys.executable, str(mcp)]
    baseline = request(
        condition="baseline",
        commit=commit,
        manifest=manifest,
        manifest_sha256=manifest_sha,
        mcp_command=mcp_command,
    )
    treatment = request(
        condition="treatment",
        commit=commit,
        manifest=manifest,
        manifest_sha256=manifest_sha,
        mcp_command=mcp_command,
    )
    request_root = root / "requests"
    request_root.mkdir()
    for value in (baseline, treatment):
        name = value["request_id"].replace(":", "__") + ".json"
        (request_root / name).write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )
    repository_map = root / "repositories.json"
    repository_map.write_text(
        json.dumps(
            {"repo": {"repository": "heimgewebe/repo", "root": str(source)}}
        ),
        encoding="utf-8",
    )
    _script, validator_command = validator(root)
    return {
        "source": source,
        "baseline": baseline,
        "treatment": treatment,
        "request_root": request_root,
        "repository_map": repository_map,
        "validator_command": validator_command,
        "claude": fake_claude(root, baseline, treatment),
    }


def ledger_events(state_root: Path) -> list[dict]:
    parent = state_root / "preflight-dispatch-ledger"
    pair_roots = list(parent.iterdir())
    if len(pair_roots) != 1:
        raise AssertionError(f"expected one pair ledger, got {len(pair_roots)}")
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((pair_roots[0] / "events").glob("*.json"))
    ]


class RepoBriefAgentBenchmarkPreflightTests(unittest.TestCase):
    def test_load_pair_requires_exact_matching_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            baseline, treatment = preflight.load_pair(env["request_root"], PAIR_ID)
            self.assertEqual(baseline["condition"], "baseline")
            self.assertEqual(treatment["condition"], "treatment")
            treatment_path = next(
                path
                for path in env["request_root"].glob("*.json")
                if "treatment" in path.name
            )
            value = json.loads(treatment_path.read_text(encoding="utf-8"))
            value["prompt"] = "post-hoc prompt"
            treatment_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(preflight.PreflightError, "disagree on prompt"):
                preflight.load_pair(env["request_root"], PAIR_ID)

    def test_snapshot_and_freshness_are_measured_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            snapshot, preparation_ms = preflight.prepare_snapshot(env["treatment"])
            freshness, freshness_ms = preflight.probe_freshness(env["treatment"])
            self.assertTrue(snapshot["snapshot_reused"])
            self.assertFalse(snapshot["snapshot_rebuilt"])
            self.assertEqual(freshness["status"], "fresh")
            self.assertFalse(freshness["stale_blocked"])
            self.assertGreaterEqual(preparation_ms, 0)
            self.assertGreaterEqual(freshness_ms, 0)

    def test_stale_snapshot_stops_before_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root, freshness="stale")
            with self.assertRaisesRegex(preflight.PreflightError, "not fresh"):
                preflight.execute_preflight(
                    pair_id=PAIR_ID,
                    request_root=env["request_root"],
                    repository_map=env["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(env["claude"]),
                    max_cost_usd=Decimal("1.00"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                    baseline_fixture=None,
                    treatment_fixture=None,
                )
            events = ledger_events(root / "state")
            self.assertEqual([event["event"] for event in events], ["authorized", "preflight-failed"])
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 0)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])
            with self.assertRaisesRegex(preflight.PreflightError, "blocks retry"):
                preflight.execute_preflight(
                    pair_id=PAIR_ID,
                    request_root=env["request_root"],
                    repository_map=env["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(env["claude"]),
                    max_cost_usd=Decimal("1.00"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                )

    def test_source_integrity_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            before = preflight.source_state(env["source"])
            (env["source"] / "untracked.txt").write_text("changed", encoding="utf-8")
            after = preflight.source_state(env["source"])
            with self.assertRaisesRegex(preflight.PreflightError, "source checkout changed"):
                preflight._assert_source_unchanged(before, after)

    def test_synthetic_pair_returns_fixture_report_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            baseline_fixture = root / "baseline.jsonl"
            treatment_fixture = root / "treatment.jsonl"
            baseline_fixture.write_bytes(stream(env["baseline"]))
            treatment_fixture.write_bytes(stream(env["treatment"]))
            report = preflight.execute_preflight(
                pair_id=PAIR_ID,
                request_root=env["request_root"],
                repository_map=env["repository_map"],
                state_root=root / "state",
                transcript_root=root / "transcripts",
                evidence_root=root / "evidence",
                claude=str(env["claude"]),
                max_cost_usd=Decimal("1.00"),
                validator_command=[sys.executable, str(root / "validator.py")],
                baseline_fixture=baseline_fixture,
                treatment_fixture=treatment_fixture,
            )
            self.assertEqual(report["kind"], preflight.FIXTURE_REPORT_KIND)
            self.assertEqual(report["status"], "synthetic_only")
            self.assertIsNone(report["cost"]["total_observed_usd"])
            self.assertFalse(report["default_promoted"])
            self.assertEqual(report["snapshot"]["status"], "fresh")
            self.assertEqual(
                set(report["timings"]),
                {
                    "snapshot_preparation_ms",
                    "freshness_check_ms",
                    "agent_execution_ms",
                    "runner_execution_ms",
                    "total_time_to_answer_ms",
                },
            )

    def test_live_shaped_fake_processes_produce_valid_preflight_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            report = preflight.execute_preflight(
                pair_id=PAIR_ID,
                request_root=env["request_root"],
                repository_map=env["repository_map"],
                state_root=root / "state",
                transcript_root=root / "transcripts",
                evidence_root=root / "evidence",
                claude=str(env["claude"]),
                max_cost_usd=Decimal("1.00"),
                validator_command=[sys.executable, str(root / "validator.py")],
            )
            self.assertEqual(report["kind"], preflight.REPORT_KIND)
            self.assertEqual(report["status"], "valid")
            self.assertIsNotNone(report["environment"]["claude"]["sha256"])
            self.assertIsNotNone(report["runs"]["baseline"]["lenskit_validation_sha256"])
            self.assertEqual(report["cost"]["total_observed_usd"], "0.02")
            self.assertEqual(report["source_before"], report["source_after"])
            self.assertFalse(report["default_promoted"])

    def test_treatment_must_use_repobrief(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            env["claude"] = fake_claude(
                root,
                env["baseline"],
                env["treatment"],
                treatment_uses_mcp=False,
            )
            with self.assertRaisesRegex(preflight.PreflightError, "used no RepoBrief"):
                preflight.execute_preflight(
                    pair_id=PAIR_ID,
                    request_root=env["request_root"],
                    repository_map=env["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(env["claude"]),
                    max_cost_usd=Decimal("1.00"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                )

    def test_preflight_rejects_cost_above_registered_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = fixture_environment(root)
            with self.assertRaisesRegex(preflight.PreflightError, "max cost"):
                preflight.execute_preflight(
                    pair_id=PAIR_ID,
                    request_root=env["request_root"],
                    repository_map=env["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(env["claude"]),
                    max_cost_usd=Decimal("1.01"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                )

    def test_mcp_environment_excludes_provider_credentials(self) -> None:
        previous_key = os.environ.get("ANTHROPIC_API_KEY")
        previous_home = os.environ.get("HOME")
        try:
            os.environ["ANTHROPIC_API_KEY"] = "secret"
            os.environ["HOME"] = "/home/operator"
            environment = preflight._mcp_environment()
            validator_environment = preflight._unprivileged_environment()
        finally:
            if previous_key is None:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            else:
                os.environ["ANTHROPIC_API_KEY"] = previous_key
            if previous_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = previous_home
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertEqual(environment["HOME"], "/nonexistent/repobrief-preflight")
        self.assertNotIn("ANTHROPIC_API_KEY", validator_environment)
        self.assertEqual(validator_environment["HOME"], "/nonexistent/repobrief-preflight")

    def test_report_and_digest_are_published_together(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_path = root / "preflight.json"
            preflight._write_report_artifacts(report_path, {"status": "fixture"})
            digest_path = Path(str(report_path) + ".sha256")
            self.assertTrue(report_path.is_file())
            self.assertTrue(digest_path.is_file())
            expected = preflight._sha256_bytes(report_path.read_bytes())
            self.assertTrue(digest_path.read_text(encoding="ascii").startswith(expected))
            with self.assertRaisesRegex(preflight.PreflightError, "already exists"):
                preflight._write_report_artifacts(report_path, {"status": "second"})
