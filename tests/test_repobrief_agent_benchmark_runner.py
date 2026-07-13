from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "repobrief_agent_benchmark_runner.py"
SPEC = importlib.util.spec_from_file_location("repobrief_agent_benchmark_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

MODEL = "claude-opus-4-1-20250805"
TASKSET_SHA = "a" * 64
MANIFEST_SHA = "b" * 64
COMMIT = "c" * 40


def request(*, condition: str = "baseline", commit: str = COMMIT) -> dict:
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
            "manifest": "/bundles/repo.bundle.manifest.json",
            "manifest_sha256": MANIFEST_SHA,
            "mcp_command": ["python", "repobrief-mcp-stdio.py", "--bundle-root", "/bundles"],
        }
    pair_id = "taskset:case:r1"
    request_id = f"{pair_id}:{condition}"
    return {
        "kind": runner.REQUEST_KIND,
        "version": runner.VERSION,
        "request_id": request_id,
        "pair_id": pair_id,
        "case_id": "case",
        "condition": condition,
        "order": 1 if condition == "baseline" else 2,
        "repetition": 1,
        "taskset_id": "taskset",
        "taskset_sha256": TASKSET_SHA,
        "repository": {
            "id": "repo",
            "repository": "heimgewebe/repo",
            "commit": commit,
        },
        "session_id": f"session:{request_id}",
        "workspace_id": f"workspace:{request_id}",
        "prompt": "Find the implementation and cite it.",
        "allowed_tools": sorted(allowed),
        "budgets": {
            "wall_seconds": 300,
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


def answer() -> dict:
    return {
        "text": "The implementation is in src/example.py.",
        "outcome": "answer",
        "reported_paths": ["src/example.py"],
        "reported_symbols": ["example"],
        "citations": [{"path": "src/example.py", "start_line": 1, "end_line": 3}],
        "claims": ["read_only_default"],
        "asserted_sufficient_evidence": True,
    }


def stream(
    request_value: dict,
    *,
    tool_name: str = "Read",
    include_result: bool = True,
    model: str = MODEL,
    input_tokens: int = 120,
    output_tokens: int = 30,
    tool_error: bool = False,
    init_tools: list[str] | None = None,
    init_session: str = "provider-session",
    result_session: str = "provider-session",
    total_cost_usd: float = 0.01,
) -> bytes:
    tools = list(runner.READ_ONLY_BUILTINS)
    if request_value["condition"] == "treatment":
        tools.extend(runner.TREATMENT_RESOURCE_TOOLS)
        tools.extend(runner.TREATMENT_MCP_TOOLS)
    if init_tools is not None:
        tools = init_tools
    messages = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": init_session,
            "model": model,
            "tools": tools,
        },
        {
            "type": "assistant",
            "session_id": init_session,
            "message": {
                "id": "message-1",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "tool-1",
                        "name": tool_name,
                        "input": {"file_path": "src/example.py"},
                    }
                ],
                "usage": {"input_tokens": input_tokens, "output_tokens": 5},
            },
        },
        {
            "type": "user",
            "session_id": init_session,
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tool-1",
                        "content": "def example():\n    return True\n",
                        "is_error": tool_error,
                    }
                ]
            },
        },
    ]
    if include_result:
        messages.append(
            {
                "type": "result",
                "subtype": "success",
                "is_error": False,
                "session_id": result_session,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                },
                "structured_output": answer(),
                "total_cost_usd": total_cost_usd,
            }
        )
    return b"".join(
        json.dumps(message, sort_keys=True).encode("utf-8") + b"\n"
        for message in messages
    )


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


def planned_request_root(root: Path, value: dict) -> Path:
    request_root = root / "requests"
    request_root.mkdir()
    filename = value["request_id"].replace(":", "__") + ".json"
    (request_root / filename).write_text(
        json.dumps(value, sort_keys=True), encoding="utf-8"
    )
    return request_root


class RepoBriefAgentBenchmarkRunnerTests(unittest.TestCase):
    def test_validate_request_accepts_both_conditions(self) -> None:
        runner.validate_request(request())
        runner.validate_request(request(condition="treatment"))

    def test_validate_request_rejects_contract_drift(self) -> None:
        mutations = [
            (lambda value: value.update({"unknown": True}), "unknown fields"),
            (
                lambda value: value["runner"].update({"provider": "other"}),
                "runner.provider",
            ),
            (
                lambda value: value["runner"].update({"model": "opus"}),
                "exact Claude model id",
            ),
            (
                lambda value: value["runner"].update(
                    {"sampling": {"temperature": 0}}
                ),
                "sampling",
            ),
            (
                lambda value: value["isolation"].update(
                    {"fresh_session": False}
                ),
                "isolation",
            ),
            (
                lambda value: value["allowed_tools"].append("write"),
                "allowed_tools",
            ),
            (
                lambda value: value.update({"repobrief": {}}),
                "baseline request",
            ),
        ]
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = request()
                mutate(value)
                with self.assertRaisesRegex(runner.RunnerError, message):
                    runner.validate_request(value)

    def test_treatment_requires_strict_repobrief_binding(self) -> None:
        value = request(condition="treatment")
        value["repobrief"]["manifest_sha256"] = "bad"
        with self.assertRaisesRegex(runner.RunnerError, "manifest_sha256"):
            runner.validate_request(value)

    def test_request_identity_is_derived_and_bounded(self) -> None:
        cases = [
            ("repetition", 3, "repetition must be 1 or 2"),
            ("order", 3, "order must be 1 or 2"),
            ("pair_id", "wrong", "pair_id does not match"),
            ("request_id", "wrong", "request_id does not match"),
            ("session_id", "wrong", "session_id does not match"),
            ("workspace_id", "wrong", "workspace_id does not match"),
        ]
        for field, replacement, message in cases:
            with self.subTest(field=field):
                value = request()
                value[field] = replacement
                with self.assertRaisesRegex(runner.RunnerError, message):
                    runner.validate_request(value)

        value = request()
        value["does_not_establish"] = []
        with self.assertRaisesRegex(runner.RunnerError, "does_not_establish"):
            runner.validate_request(value)

    def test_load_planned_request_requires_exact_frozen_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = request()
            request_root = planned_request_root(root, value)
            self.assertEqual(
                runner.load_planned_request(value, request_root), value
            )
            mutated = copy.deepcopy(value)
            mutated["prompt"] = "post-hoc prompt"
            with self.assertRaisesRegex(
                runner.RunnerError, "does not match the frozen plan request"
            ):
                runner.load_planned_request(mutated, request_root)

    def test_provider_input_contains_exactly_one_frozen_task_turn(self) -> None:
        value = request()
        lines = runner.build_provider_input(value).decode("utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        message = json.loads(lines[0])
        text = message["message"]["content"][0]["text"]
        self.assertIn(value["prompt"], text)
        self.assertNotIn("Initialization turn", text)

    def test_build_baseline_command_exposes_only_read_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "mcp.json"
            config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
            command = runner.build_claude_command(
                request(),
                claude="/opt/claude",
                mcp_config=config,
                max_budget_usd="0.05",
            )
        joined = " ".join(command)
        self.assertNotIn("--safe-mode", command)
        self.assertIn("--no-chrome", command)
        self.assertIn("--disable-slash-commands", command)
        self.assertIn("--setting-sources=", command)
        settings_index = command.index("--settings")
        self.assertEqual(
            json.loads(command[settings_index + 1]),
            runner.ISOLATED_CLAUDE_SETTINGS,
        )
        self.assertIn("--strict-mcp-config", command)
        self.assertIn("--disallowedTools", command)
        self.assertIn("mcp__*", command)
        self.assertNotIn("--bare", command)
        self.assertIn("stream-json", command)
        input_index = command.index("--input-format")
        self.assertEqual(command[input_index + 1], "stream-json")
        self.assertNotIn(request()["prompt"], command)
        self.assertIn("--no-session-persistence", command)
        budget_index = command.index("--max-budget-usd")
        self.assertEqual(command[budget_index + 1], "0.05")
        self.assertIn("Read,Glob,Grep", command)
        self.assertNotIn("--allowedTools", command)
        self.assertNotIn("mcp__repobrief", joined)
        self.assertNotIn("Bash", joined)
        self.assertNotIn("Write", joined)
        self.assertNotIn("Edit", joined)

    def test_build_treatment_command_binds_only_repobrief_mcp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "mcp.json"
            config.write_text("{}", encoding="utf-8")
            command = runner.build_claude_command(
                request(condition="treatment"),
                claude="claude",
                mcp_config=config,
                max_budget_usd="0.05",
            )
        joined = " ".join(command)
        self.assertIn("--strict-mcp-config", command)
        self.assertIn(str(config), command)
        self.assertNotIn("--safe-mode", command)
        self.assertNotIn("mcp__*", command)
        self.assertIn("ListMcpResources", joined)
        self.assertIn("ReadMcpResource", joined)
        self.assertIn("mcp__repobrief__ask_context", joined)
        self.assertIn("mcp__repobrief__grounding_verify", joined)
        self.assertIn("mcp__repobrief__live_freshness", joined)
        tools_index = command.index("--tools")
        exposed = command[tools_index + 1].split(",")
        self.assertEqual(
            set(exposed),
            set(runner.READ_ONLY_BUILTINS)
            | set(runner.TREATMENT_RESOURCE_TOOLS)
            | set(runner.TREATMENT_MCP_TOOLS),
        )
        allowed_index = command.index("--allowedTools")
        allowed = command[allowed_index + 1].split(",")
        self.assertNotIn("Read", allowed)
        self.assertNotIn("Glob", allowed)
        self.assertNotIn("Grep", allowed)
        self.assertEqual(
            set(allowed),
            set(runner.TREATMENT_RESOURCE_TOOLS) | set(runner.TREATMENT_MCP_TOOLS),
        )

    def test_provider_budget_is_positive_bounded_and_enforced(self) -> None:
        self.assertEqual(runner._parse_max_budget_usd("0.0500"), "0.05")
        self.assertEqual(runner._parse_max_budget_usd("1.00"), "1")
        for invalid in ("0", "-1", "NaN", "Infinity", "1.01", "not-a-number"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(runner.RunnerError, "positive bounded"):
                    runner._parse_max_budget_usd(invalid)

        value = request()
        started = datetime.now(timezone.utc)
        with self.assertRaisesRegex(runner.RunnerError, "cost exceeds"):
            runner.build_receipt(
                value,
                stream(value, total_cost_usd=0.051),
                transcript_artifact="transcript.jsonl",
                returncode=0,
                started_at=started,
                ended_at=started,
                max_budget_usd="0.05",
            )

    def test_build_receipt_normalizes_provider_evidence(self) -> None:
        value = request()
        raw = stream(value)
        started = datetime(2026, 7, 13, 10, 0, tzinfo=timezone.utc)
        receipt = runner.build_receipt(
            value,
            raw,
            transcript_artifact="transcript.jsonl",
            returncode=0,
            started_at=started,
            ended_at=started + timedelta(seconds=1),
        )
        self.assertEqual(receipt["kind"], runner.RECEIPT_KIND)
        self.assertEqual(receipt["request_sha256"], runner._sha256_json(value))
        self.assertEqual(
            receipt["provider"],
            {
                "name": runner.PROVIDER,
                "model": MODEL,
                "sampling": {},
                "input_tokens": 120,
                "output_tokens": 30,
                "token_source": "provider_reported",
            },
        )
        self.assertEqual(
            receipt["tool_calls"],
            [
                {
                    "sequence": 1,
                    "name": "read_file",
                    "status": "success",
                    "duration_ms": 0,
                    "input_bytes": len(
                        runner._canonical_json(
                            {"file_path": "src/example.py"}
                        ).encode("utf-8")
                    ),
                    "output_bytes": len(
                        runner._canonical_json(
                            "def example():\n    return True\n"
                        ).encode("utf-8")
                    ),
                }
            ],
        )
        self.assertEqual(receipt["answer"], answer())
        self.assertEqual(
            receipt["transcript"]["sha256"], runner._sha256_bytes(raw)
        )
        self.assertEqual(receipt["transcript"]["bytes"], len(raw))

    def test_treatment_maps_repobrief_tool(self) -> None:
        value = request(condition="treatment")
        raw = stream(value, tool_name="mcp__repobrief__ask_context")
        started = datetime.now(timezone.utc)
        receipt = runner.build_receipt(
            value,
            raw,
            transcript_artifact="transcript.jsonl",
            returncode=0,
            started_at=started,
            ended_at=started,
        )
        self.assertEqual(receipt["tool_calls"][0]["name"], "ask_context")

    def test_provider_evidence_fails_closed(self) -> None:
        cases = [
            (lambda value: stream(value, include_result=False), "requires one result"),
            (
                lambda value: stream(value, model="claude-other"),
                "model does not match",
            ),
            (
                lambda value: stream(value, input_tokens=999999),
                "input token budget exceeded",
            ),
            (
                lambda value: stream(value, tool_name="Write"),
                "unapproved tool",
            ),
            (
                lambda value: stream(
                    value,
                    init_session="session-a",
                    result_session="session-b",
                ),
                "session does not match",
            ),
        ]
        for raw_builder, message in cases:
            with self.subTest(message=message):
                value = request()
                started = datetime.now(timezone.utc)
                with self.assertRaisesRegex(runner.RunnerError, message):
                    runner.build_receipt(
                        value,
                        raw_builder(value),
                        transcript_artifact="transcript.jsonl",
                        returncode=0,
                        started_at=started,
                        ended_at=started,
                    )

    def test_treatment_requires_all_repobrief_tools_in_init(self) -> None:
        value = request(condition="treatment")
        incomplete = list(runner.READ_ONLY_BUILTINS)
        started = datetime.now(timezone.utc)
        with self.assertRaisesRegex(
            runner.RunnerError, "did not expose all required tools"
        ):
            runner.build_receipt(
                value,
                stream(value, init_tools=incomplete),
                transcript_artifact="transcript.jsonl",
                returncode=0,
                started_at=started,
                ended_at=started,
            )

    def test_duplicate_tool_use_and_orphan_result_are_rejected(self) -> None:
        value = request()
        messages = runner.parse_jsonl(stream(value))
        assistant = next(item for item in messages if item["type"] == "assistant")
        assistant["message"]["content"].append(
            copy.deepcopy(assistant["message"]["content"][0])
        )
        with self.assertRaisesRegex(
            runner.RunnerError, "duplicate provider tool-use id"
        ):
            runner.normalize_tool_calls(value, messages)

        messages = runner.parse_jsonl(stream(value))
        user = next(item for item in messages if item["type"] == "user")
        user["message"]["content"][0]["tool_use_id"] = "orphan"
        with self.assertRaisesRegex(runner.RunnerError, "no matching result"):
            runner.normalize_tool_calls(value, messages)

    def test_failed_tool_is_retained_as_failed_call(self) -> None:
        value = request()
        messages = runner.parse_jsonl(stream(value, tool_error=True))
        calls = runner.normalize_tool_calls(value, messages)
        self.assertEqual(calls[0]["status"], "failed")

    def test_answer_rejects_unknown_claim_and_unsafe_citation(self) -> None:
        invalid = answer()
        invalid["claims"] = ["invented_claim"]
        with self.assertRaisesRegex(runner.RunnerError, "unknown labels"):
            runner.validate_answer(invalid)

        invalid = answer()
        invalid["citations"] = [
            {"path": "../secret", "start_line": 1, "end_line": 1}
        ]
        with self.assertRaisesRegex(runner.RunnerError, "repository-relative"):
            runner.validate_answer(invalid)

    def test_jsonl_rejects_empty_invalid_and_oversized_transcripts(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "empty or oversized"):
            runner.parse_jsonl(b"")
        with self.assertRaisesRegex(runner.RunnerError, "invalid JSON"):
            runner.parse_jsonl(b"not-json\n")
        with self.assertRaisesRegex(runner.RunnerError, "empty or oversized"):
            runner.parse_jsonl(b"x" * (runner.MAX_TRANSCRIPT_BYTES + 1))

    def test_create_isolated_checkout_is_exact_clean_and_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            checkout = runner.create_isolated_checkout(
                value, source, root / "state"
            )
            self.assertEqual(git(["rev-parse", "HEAD"], checkout), commit)
            self.assertEqual(git(["status", "--porcelain"], checkout), "")
            with self.assertRaisesRegex(runner.RunnerError, "already used"):
                runner.create_isolated_checkout(value, source, root / "state")

    def test_load_repository_root_binds_owner_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            map_path = root / "repositories.json"
            map_path.write_text(
                json.dumps(
                    {
                        "repo": {
                            "repository": "heimgewebe/repo",
                            "root": str(source),
                        }
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                runner.load_repository_root(value, map_path), source.resolve()
            )
            document = json.loads(map_path.read_text(encoding="utf-8"))
            document["repo"]["repository"] = "other/repo"
            map_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                runner.RunnerError, "owner/name mismatch"
            ):
                runner.load_repository_root(value, map_path)

    def test_live_execute_requires_explicit_authorization_before_filesystem_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            common = {
                "request_root": root / "missing-requests",
                "repository_map": root / "missing-repositories.json",
                "state_root": root / "state",
                "transcript_root": root / "transcripts",
                "claude": "claude",
            }
            with self.assertRaisesRegex(
                runner.RunnerError, "explicit allow_live_provider"
            ):
                runner.execute(request(), **common)
            with self.assertRaisesRegex(
                runner.RunnerError, "live execution requires max_budget_usd"
            ):
                runner.execute(request(), allow_live_provider=True, **common)
            with self.assertRaisesRegex(
                runner.RunnerError, "requires claude_credential_file"
            ):
                runner.execute(
                    request(),
                    allow_live_provider=True,
                    max_budget_usd="0.05",
                    **common,
                )
            credential = root / "credentials.json"
            credential.write_bytes(b"{}")
            with self.assertRaisesRegex(
                runner.RunnerError, "requires claude_command_sha256"
            ):
                runner.execute(
                    request(),
                    allow_live_provider=True,
                    max_budget_usd="0.05",
                    claude_credential_file=credential,
                    **common,
                )
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "transcripts").exists())

    def test_fixture_rejects_live_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixture.jsonl"
            fixture.write_bytes(b"{}\n")
            with self.assertRaisesRegex(
                runner.RunnerError, "must not carry live-provider authorization"
            ):
                runner.execute(
                    request(),
                    request_root=root / "missing-requests",
                    repository_map=root / "missing-repositories.json",
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    claude="claude",
                    stream_fixture=fixture,
                    allow_live_provider=True,
                    max_budget_usd="0.05",
                )
            self.assertFalse((root / "state").exists())

    def test_execute_with_synthetic_stream_is_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            map_path = root / "repositories.json"
            map_path.write_text(
                json.dumps(
                    {
                        "repo": {
                            "repository": "heimgewebe/repo",
                            "root": str(source),
                        }
                    }
                ),
                encoding="utf-8",
            )
            fixture = root / "stream.jsonl"
            fixture.write_bytes(stream(value))
            request_root = planned_request_root(root, value)
            report = runner.execute(
                value,
                request_root=request_root,
                repository_map=map_path,
                state_root=root / "state",
                transcript_root=root / "transcripts",
                claude="claude",
                stream_fixture=fixture,
            )
            candidate = report["normalized_candidate"]
            artifact = root / "transcripts" / candidate["transcript"]["artifact"]
            self.assertEqual(artifact.read_bytes(), fixture.read_bytes())
            self.assertEqual(report["kind"], runner.FIXTURE_REPORT_KIND)
            self.assertTrue(report["synthetic_fixture"])
            self.assertEqual(candidate["provider"]["name"], "synthetic-fixture")
            self.assertEqual(candidate["provider"]["token_source"], "synthetic")
            self.assertEqual(
                report["does_not_establish"], list(runner.DOES_NOT_ESTABLISH)
            )

    def test_write_mcp_config_uses_request_argv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = request(condition="treatment")
            workspace = Path(temporary) / "workspace" / "repo"
            workspace.mkdir(parents=True)
            path = runner.write_mcp_config(value, workspace)
            document = json.loads(path.read_text(encoding="utf-8"))
            server = document["mcpServers"]["repobrief"]
            self.assertEqual(server["type"], "stdio")
            self.assertEqual(server["command"], "python")
            self.assertEqual(
                server["args"],
                ["repobrief-mcp-stdio.py", "--bundle-root", "/bundles"],
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_write_baseline_mcp_config_is_explicitly_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace" / "repo"
            workspace.mkdir(parents=True)
            path = runner.write_mcp_config(request(), workspace)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"mcpServers": {}},
            )

    def test_auth_only_config_is_private_scrubbed_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            credential = root / "credentials.json"
            credential.write_bytes(b'{"oauth": "test-only"}')
            credential.chmod(0o600)
            data = runner._read_credential_file(credential)
            workspace = root / "workspace" / "repo"
            workspace.mkdir(parents=True)
            auth_config = runner.stage_auth_only_config(workspace, data)
            copied = auth_config / ".credentials.json"
            self.assertEqual(copied.read_bytes(), data)
            self.assertEqual(auth_config.stat().st_mode & 0o777, 0o700)
            self.assertEqual(copied.stat().st_mode & 0o777, 0o600)
            self.assertEqual([item.name for item in auth_config.iterdir()], [".credentials.json"])
            with patch.dict(
                os.environ,
                {
                    "PATH": "/usr/bin",
                    "HOME": "/home/test",
                    "ANTHROPIC_API_KEY": "must-not-leak",
                },
                clear=True,
            ):
                environment = runner._provider_environment(auth_config)
            self.assertNotIn("ANTHROPIC_API_KEY", environment)
            self.assertEqual(environment["CLAUDE_CONFIG_DIR"], str(auth_config))
            self.assertEqual(environment["ENABLE_CLAUDEAI_MCP_SERVERS"], "false")
            self.assertEqual(environment["CLAUDE_CODE_SKIP_PROMPT_HISTORY"], "1")
            runner.remove_auth_only_config(auth_config)
            self.assertFalse(auth_config.exists())

    def test_live_provider_executable_is_absolute_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "claude"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            self.assertEqual(
                runner._validate_provider_executable(
                    stream_fixture=None,
                    executable=str(executable),
                    expected_sha256=digest,
                ),
                str(executable),
            )
            with self.assertRaisesRegex(runner.RunnerError, "SHA-256 mismatch"):
                runner._validate_provider_executable(
                    stream_fixture=None,
                    executable=str(executable),
                    expected_sha256="0" * 64,
                )
            with self.assertRaisesRegex(runner.RunnerError, "path must be absolute"):
                runner._validate_provider_executable(
                    stream_fixture=None,
                    executable="claude",
                    expected_sha256=digest,
                )
            link = root / "claude-link"
            link.symlink_to(executable)
            with self.assertRaisesRegex(runner.RunnerError, "non-symlink"):
                runner._validate_provider_executable(
                    stream_fixture=None,
                    executable=str(link),
                    expected_sha256=digest,
                )

    def test_credential_reader_rejects_symlink_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_bytes(b"{}")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(runner.RunnerError, "non-symlink"):
                runner._read_credential_file(link)
            public = root / "public.json"
            public.write_bytes(b"{}")
            public.chmod(0o644)
            with self.assertRaisesRegex(runner.RunnerError, "group- or world-accessible"):
                runner._read_credential_file(public)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (runner.MAX_CREDENTIAL_BYTES + 1))
            oversized.chmod(0o600)
            with self.assertRaisesRegex(runner.RunnerError, "size is invalid"):
                runner._read_credential_file(oversized)

    def test_run_bounded_rejects_timeout_and_output_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "runner.py"
            script.write_text(
                "import sys, time\n"
                "if sys.argv[1] == 'sleep': time.sleep(2)\n"
                "else: print('x' * 1000)\n",
                encoding="utf-8",
            )
            auth_config = root / "auth"
            auth_config.mkdir()
            with self.assertRaisesRegex(runner.RunnerError, "timed out"):
                runner.run_bounded(
                    [sys.executable, str(script), "sleep"],
                    cwd=root,
                    timeout_seconds=1,
                    auth_config=auth_config,
                    stdin_data=b"",
                    stdout_limit=1024,
                )
            with self.assertRaisesRegex(runner.RunnerError, "stdout exceeds"):
                runner.run_bounded(
                    [sys.executable, str(script), "output"],
                    cwd=root,
                    timeout_seconds=5,
                    auth_config=auth_config,
                    stdin_data=b"",
                    stdout_limit=32,
                )


if __name__ == "__main__":
    unittest.main()
