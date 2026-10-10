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



def bind_manifest(
    value: dict,
    root: Path,
    *,
    commit: str = COMMIT,
    provenance_key: str = "snapshot_provenance",
    repositories: list[dict] | None = None,
) -> Path:
    if repositories is None:
        repositories = [{"git_commit": commit, "repo_root": "/tmp/repo"}]
    manifest = {
        "kind": "repoground.bundle.manifest",
        "version": "2.0",
        provenance_key: {"repositories": repositories},
    }
    raw = json.dumps(
        manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    path = root / "repo.bundle.manifest.json"
    path.write_bytes(raw)
    value["repobrief"]["manifest"] = str(path)
    value["repobrief"]["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return path


def complete(payload: dict) -> dict:
    """Fill the production contract fields a minimal fixture leaves out."""
    value = copy.deepcopy(payload)
    freshness = value if value.get("kind") == "repobrief.live_freshness" else value.get("live_freshness")
    if isinstance(freshness, dict):
        freshness.setdefault("does_not_establish", list(runner.EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH))
        if "snapshot_provenance" in freshness:
            freshness.setdefault("freshness_values", list(runner.EXPECTED_REPOGROUND_FRESHNESS_VALUES))
            freshness.setdefault("current_provenance", None)
    if value.get("kind") != runner.EXPECTED_REPOGROUND_READ_ONLY_KIND:
        return value
    value.setdefault("mutation_boundary", {"writes": []})
    value.setdefault("does_not_establish", list(runner.EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH))
    pack = value.get("context_pack")
    if value.get("tool") == "ask_context":
        value.setdefault("request_semantics", "repobrief.ask_request.v1")
        value.setdefault("context_pack_semantics", "repobrief.ask_context_pack.v1")
    if isinstance(pack, dict):
        used = pack.get("budget", {}).get("context_bytes_used", 0)
        defaults = {
            "request_id": "0123456789abcdef",
            "availability": {"status": "available"},
            "required_reading": {},
            "retrieval": {},
            "retrieval_infrastructure": {"status": "available"},
            "retrieval_hits": [],
            "answer_scaffold": {
                "citation_obligations": [],
                "caveats_to_surface": [],
                "non_claims_to_surface": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
            },
            "forbidden_operations": list(runner.EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS),
            "does_not_establish": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
        }
        for key, default in defaults.items():
            pack.setdefault(key, default)
        budget = pack["budget"]
        for key in (
            "max_context_tokens", "token_derived_byte_ceiling", "max_context_bytes",
            "max_answer_tokens", "context_bytes_used",
            "context_unicode_characters_used", "approx_context_chars_used",
        ):
            budget.setdefault(key, used)
        budget.setdefault("byte_budget_is_hard", True)
        budget.setdefault("unit", "utf8_bytes")
        budget.setdefault("accounting", "utf8")
        budget.setdefault("omissions", [])
        budget.setdefault("truncated", False)
        budget.setdefault("does_not_establish_quality", True)
    verdict = value.get("verdict")
    if isinstance(verdict, dict):
        value.setdefault("declaration_semantics", "repobrief.answer_grounding_declaration.v1")
        value.setdefault("verdict_semantics", "repobrief.answer_grounding_verdict.v1")
        for key, default in {
            "checked_declaration": {}, "snapshot_ref": {}, "citation_checks": [],
            "range_checks": [], "required_reading_checks": [], "diagnostics": [],
            "freshness_caveats": [], "availability_caveats": [],
            "does_not_establish": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
        }.items():
            verdict.setdefault(key, default)
    return value


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

    def test_validate_request_accepts_known_execution_contract(self) -> None:
        value = request()
        value["runner"]["execution_contract"] = runner.EXECUTION_CONTRACT

        runner.validate_request(value)

    def test_validate_request_rejects_unknown_execution_contract_and_fields(self) -> None:
        unknown_contract = request()
        unknown_contract["runner"]["execution_contract"] = "unknown-live-contract"
        with self.assertRaisesRegex(runner.RunnerError, "execution_contract"):
            runner.validate_request(unknown_contract)

        unknown_field = request()
        unknown_field["runner"]["unexpected"] = True
        with self.assertRaisesRegex(runner.RunnerError, "runner contract mismatch"):
            runner.validate_request(unknown_field)

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

    def test_current_resource_aliases_and_structured_output_are_internal(self) -> None:
        value = request(condition="treatment")
        current_tools = [
            *runner.READ_ONLY_BUILTINS,
            runner.STRUCTURED_OUTPUT_TOOL,
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
            *runner.TREATMENT_MCP_TOOLS,
        ]
        messages = runner.parse_jsonl(
            stream(
                value,
                tool_name="ReadMcpResourceTool",
                init_tools=current_tools,
            )
        )
        assistant = next(item for item in messages if item["type"] == "assistant")
        assistant["message"]["content"].append(
            {
                "type": "tool_use",
                "id": "structured-output-1",
                "name": runner.STRUCTURED_OUTPUT_TOOL,
                "input": answer(),
            }
        )
        raw = b"".join(
            json.dumps(item, sort_keys=True).encode("utf-8") + b"\n"
            for item in messages
        )
        started = datetime.now(timezone.utc)
        receipt = runner.build_receipt(
            value,
            raw,
            transcript_artifact="transcript.jsonl",
            returncode=0,
            started_at=started,
            ended_at=started,
        )
        self.assertEqual(
            receipt["tool_calls"],
            [
                {
                    "sequence": 1,
                    "name": "repobrief_resource_read",
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
        baseline = request()
        runner.build_receipt(
            baseline,
            stream(
                baseline,
                init_tools=[*runner.READ_ONLY_BUILTINS, runner.STRUCTURED_OUTPUT_TOOL],
            ),
            transcript_artifact="baseline.jsonl",
            returncode=0,
            started_at=started,
            ended_at=started,
        )

    def test_extra_repobrief_tool_surface_and_use_are_rejected(self) -> None:
        value = request(condition="treatment")
        current_tools = [
            *runner.READ_ONLY_BUILTINS,
            "ListMcpResourcesTool",
            "ReadMcpResourceTool",
            *runner.TREATMENT_MCP_TOOLS,
        ]
        started = datetime.now(timezone.utc)
        t002h_extra_tools = [
            "mcp__repobrief__bundle_discover",
            "mcp__repobrief__find_references",
            "mcp__repobrief__find_symbol",
            "mcp__repobrief__get_callees",
            "mcp__repobrief__get_callers",
            "mcp__repobrief__query_existing_index",
            "mcp__repobrief__range_get",
            "mcp__repobrief__snapshot_status",
        ]
        with self.assertRaisesRegex(runner.RunnerError, "exposed unapproved tools"):
            runner.build_receipt(
                value,
                stream(
                    value,
                    init_tools=[*current_tools, *t002h_extra_tools],
                ),
                transcript_artifact="extra-tool.jsonl",
                returncode=0,
                started_at=started,
                ended_at=started,
            )
        with self.assertRaisesRegex(runner.RunnerError, "used unapproved tool"):
            runner.build_receipt(
                value,
                stream(
                    value,
                    tool_name="mcp__repobrief__find_symbol",
                    init_tools=current_tools,
                ),
                transcript_artifact="unauthorized-use.jsonl",
                returncode=0,
                started_at=started,
                ended_at=started,
            )

    def test_benchmark_mcp_proxy_filters_list_and_rejects_unauthorized_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "calls.json"
            upstream = root / "fake_mcp.py"
            upstream.write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "log = Path(sys.argv[1])\n"
                "calls = []\n"
                "for line in sys.stdin:\n"
                "    message = json.loads(line)\n"
                "    method = message.get('method')\n"
                "    if method == 'tools/list':\n"
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'method': 'sampling/createMessage', 'params': {}}), flush=True)\n"
                "        result = {'tools': ["
                "{'name': 'ask_context'}, {'name': 'find_symbol'}, "
                "{'name': 'grounding_verify'}]}\n"
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': result}), flush=True)\n"
                "    elif method == 'tools/call':\n"
                "        name = message['params']['name']\n"
                "        calls.append(name)\n"
                "        log.write_text(json.dumps(calls))\n"
                "        print(json.dumps({'jsonrpc': '2.0', 'id': message['id'], 'result': {'content': name}}), flush=True)\n",
                encoding="utf-8",
            )
            encoded_upstream = runner._canonical_json(
                [sys.executable, str(upstream), str(log)]
            )
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "find_symbol", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ask_context", "arguments": {}},
                },
            ]
            payload = b"".join(
                json.dumps(item, sort_keys=True).encode("utf-8") + b"\n"
                for item in requests
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(MODULE_PATH),
                    "--benchmark-mcp-proxy",
                    encoded_upstream,
                ],
                input=payload,
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            responses = {
                item["id"]: item
                for item in runner.parse_jsonl(completed.stdout)
            }
            self.assertEqual(
                [tool["name"] for tool in responses[1]["result"]["tools"]],
                ["ask_context", "grounding_verify"],
            )
            self.assertEqual(responses[2]["error"]["code"], -32601)
            self.assertIn("not authorized", responses[2]["error"]["message"])
            self.assertEqual(responses[3]["result"]["content"], "ask_context")
            self.assertEqual(json.loads(log.read_text()), ["ask_context"])

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

    def test_malformed_optional_snapshot_values_never_raise(self) -> None:
        manifest_path = "/tmp/repoground-pinned-manifest.json"
        manifest_paths = frozenset({manifest_path})
        binding = ("a" * 64, COMMIT, "/tmp/repo", manifest_paths)
        valid = {
            "kind": "repobrief.live_freshness",
            "version": "v1",
            "status": "fresh",
            "reason": "git_head_matches_snapshot",
            "bundle_manifest": manifest_path,
            "repo_root": "/tmp/repo",
            "read_only_git_probe": True,
            "implicit_refresh": False,
            "snapshot_provenance": {"git_commit": COMMIT},
        }
        for invalid in ([], {"untrusted": True}):
            with self.subTest(field="snapshot_ref.manifest_path", invalid=invalid):
                self.assertFalse(runner._snapshot_ref_matches_manifest(
                    {"manifest_path": invalid},
                    manifest_paths=manifest_paths,
                    manifest_sha256=binding[0],
                    require_sha=False,
                ))
            for field in ("status", "bundle_manifest"):
                with self.subTest(field=field, invalid=invalid):
                    corrupted = {**valid, field: invalid}
                    self.assertIsNone(runner._live_snapshot_commit(
                        corrupted,
                        manifest_paths=manifest_paths,
                        manifest_commit=COMMIT,
                        manifest_repo_root="/tmp/repo",
                    ))
                    self.assertIsNone(runner._repoground_resource_read_evidence(
                        manifest_binding=binding,
                        sequence=1,
                        live_freshness=corrupted,
                        content_bytes=7,
                    ))

    def test_malformed_grounding_status_types_omit_optional_evidence(self) -> None:
        path = "/tmp/pinned-grounding-manifest.json"
        binding = ("a" * 64, COMMIT, "/tmp/repo", frozenset({path}))
        fresh = {
            "kind": "repobrief.live_freshness",
            "version": "v1",
            "status": "fresh",
            "reason": "git_head_matches_snapshot",
            "bundle_manifest": path,
            "repo_root": "/tmp/repo",
            "read_only_git_probe": True,
            "implicit_refresh": False,
            "snapshot_provenance": {"git_commit": COMMIT},
        }
        payload = {
            "kind": "repobrief.mcp.read_only_frontdoor",
            "version": "v1",
            "tool": "grounding_verify",
            "status": "degraded",
            "verdict": {
                "kind": "repobrief.answer_grounding_verdict",
                "version": "1.0",
                "status": "degraded",
                "snapshot_ref": {"manifest_path": path},
            },
            "live_freshness": fresh,
        }
        def projection(value):
            return runner._repoground_evidence_from_payload(
                manifest_binding=binding,
                tool_name="grounding_verify",
                sequence=1,
                payload=value,
            )
        self.assertEqual(projection(payload)[0], COMMIT)
        for invalid in ([], {"invalid": True}):
            for section, field in (
                ("verdict", "status"),
                ("verdict.snapshot_ref", "freshness_status"),
                ("live_freshness", "status"),
                ("live_freshness", "bundle_manifest"),
            ):
                with self.subTest(section=section, field=field, invalid=invalid):
                    changed = copy.deepcopy(payload)
                    target = changed
                    for name in section.split("."):
                        target = target[name]
                    target[field] = invalid
                    self.assertIsNone(projection(changed))

    def test_legacy_manifest_version_rejects_explicit_null(self) -> None:
        legacy = {"kind": runner._REPOGROUND_LEGACY_MANIFEST_KIND}
        runner._require_repoground_manifest_envelope(legacy)
        runner._require_repoground_manifest_envelope(
            {**legacy, "version": runner._REPOGROUND_LEGACY_MANIFEST_VERSION}
        )
        with self.assertRaisesRegex(
            runner.RunnerError, "RepoGround manifest version is invalid"
        ):
            runner._require_repoground_manifest_envelope({**legacy, "version": None})

    def test_treatment_projects_bound_repoground_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            logical_parent = Path(directory) / "sub"
            logical_parent.mkdir()
            logical_manifest = logical_parent / ".." / manifest.name
            value["repobrief"]["manifest"] = str(logical_manifest)
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__ask_context")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "ask_context",
                "status": "ok",
                "context_pack": {
                    "kind": "repobrief.ask_context_pack",
                    "version": "1.0",
                    "snapshot_ref": {
                        "manifest_path": str(manifest),
                        "manifest_sha256": value["repobrief"]["manifest_sha256"],
                        "git_commit": None,
                        "freshness_status": "not_comparable",
                    },
                    "freshness": {"status": "not_comparable"},
                    "resolved_ranges": [{
                        "status": "resolved",
                        "source_path": "src/example.py",
                        "text_excerpt": "def example():",
                        "range_ref": {
                            "path": "src/example.py",
                            "start_line": 1,
                            "end_line": 1,
                        },
                    }],
                    "budget": {"context_bytes_used": 321},
                },
                "live_freshness": {
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "fresh",
                    "reason": "git_head_matches_snapshot",
                    "bundle_manifest": str(logical_manifest),
                    "repo_root": "/tmp/repo",
                    "read_only_git_probe": True,
                    "implicit_refresh": False,
                    "snapshot_provenance": {"git_commit": COMMIT},
                },
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertEqual(
                runner.normalize_repoground_evidence(value, messages, calls),
                {
                    "target_commit": COMMIT,
                    "bundle_commit": COMMIT,
                    "calls": [{
                        "sequence": 1,
                        "tool": "ask_context",
                        "freshness_status": "fresh",
                        "resolved_range_count": 1,
                        "context_bytes_used": 321,
                        "grounding_status": None,
                    }],
                },
            )

            alternate_parent = Path(directory) / "alternate"
            alternate_parent.mkdir()
            unexpected_alias = alternate_parent / ".." / manifest.name
            unexpected = copy.deepcopy(payload)
            unexpected["live_freshness"]["bundle_manifest"] = str(unexpected_alias)
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(unexpected)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )

            wrong = json.loads(json.dumps(payload))
            wrong["context_pack"]["snapshot_ref"]["manifest_sha256"] = "0" * 64
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(wrong)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

    def test_authorized_manifest_paths_include_only_request_derived_forms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory)).resolve()
            relative = os.path.relpath(manifest, Path.cwd())
            value["repobrief"]["manifest"] = relative
            paths = runner._authorized_manifest_paths(
                value, manifest_path=manifest
            )
            self.assertIn(relative, paths)
            self.assertIn(str(Path(relative).expanduser()), paths)
            self.assertIn(str(manifest), paths)

            unexpected_parent = Path(directory) / "other"
            unexpected_parent.mkdir()
            unexpected_alias = unexpected_parent / ".." / manifest.name
            self.assertNotIn(str(unexpected_alias), paths)

            with patch.dict(os.environ, {"HOME": directory}):
                value["repobrief"]["manifest"] = f"~/{manifest.name}"
                tilde_paths = runner._authorized_manifest_paths(
                    value, manifest_path=manifest
                )
            self.assertIn(f"~/{manifest.name}", tilde_paths)
            self.assertIn(str(manifest), tilde_paths)

    def test_treatment_manifest_bind_failure_omits_optional_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory), repositories=[])
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": {
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "fresh",
                    "reason": "git_head_matches_snapshot",
                    "bundle_manifest": str(manifest),
                    "repo_root": "/tmp/repo",
                    "read_only_git_probe": True,
                    "implicit_refresh": False,
                    "snapshot_provenance": {"git_commit": COMMIT},
                }},
                sort_keys=True,
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertIsNone(
                runner.normalize_repoground_evidence(value, messages, calls)
            )

    def test_treatment_uses_same_call_live_freshness_and_semantic_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__ask_context")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "ask_context",
                "status": "ok",
                "context_pack": {
                    "kind": "repobrief.ask_context_pack",
                    "version": "1.0",
                    "snapshot_ref": {
                        "manifest_path": str(manifest),
                        "manifest_sha256": value["repobrief"]["manifest_sha256"],
                        "git_commit": COMMIT,
                        "freshness_status": "not_comparable",
                    },
                    "freshness": {"status": "not_comparable"},
                    "resolved_ranges": [
                        {
                            "status": "resolved",
                            "source_path": "src/resolved.py",
                            "text_excerpt": "def resolved(): ...",
                            "range_ref": {"ref": "resolved"},
                        },
                        {"source_path": "src/no-status.py"},
                        {"status": "candidate", "source_path": "src/candidate.py"},
                    ],
                    "budget": {"context_bytes_used": 17},
                },
                "live_freshness": {
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "fresh",
                    "reason": "git_head_matches_snapshot",
                    "bundle_manifest": str(manifest),
                    "repo_root": "/tmp/repo",
                    "read_only_git_probe": True,
                    "implicit_refresh": False,
                    "snapshot_provenance": {"git_commit": COMMIT},
                },
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            calls = runner.normalize_tool_calls(value, messages)
            evidence = runner.normalize_repoground_evidence(value, messages, calls)
            self.assertEqual(evidence["calls"][0]["freshness_status"], "fresh")
            self.assertEqual(evidence["calls"][0]["resolved_range_count"], 1)

            missing_live = copy.deepcopy(payload)
            missing_live.pop("live_freshness")
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(missing_live)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            invalid_variants = [
                ("implicit_refresh_true", {"implicit_refresh": True}, ()),
                ("missing_implicit_refresh", {}, ("implicit_refresh",)),
                ("non_boolean_read_only_git_probe", {"read_only_git_probe": "yes"}, ()),
                ("missing_reason", {}, ("reason",)),
                ("missing_repo_root", {}, ("repo_root",)),
            ]
            for name, updates, removals in invalid_variants:
                with self.subTest(name=name):
                    invalid = copy.deepcopy(payload)
                    freshness = invalid["live_freshness"]
                    freshness.update(updates)
                    for field in removals:
                        freshness.pop(field)
                    tool_result["content"] = json.dumps(
                        {"structuredContent": complete(invalid)}, sort_keys=True
                    )
                    self.assertIsNone(
                        runner.normalize_repoground_evidence(
                            value,
                            messages,
                            runner.normalize_tool_calls(value, messages),
                        )
                    )

    def test_resolved_range_entries_require_identity_and_text(self) -> None:
        good = {
            "status": "resolved",
            "source_path": "src/a.py",
            "text_excerpt": "x = 1",
            "range_ref": {"ref": "a"},
        }
        self.assertTrue(runner._resolved_range_entries_valid([]))
        self.assertTrue(runner._resolved_range_entries_valid([good]))
        self.assertTrue(runner._resolved_range_entries_valid(
            [{"status": "candidate"}, {"source_path": "src/b.py"}, good]
        ))
        self.assertTrue(runner._resolved_range_entries_valid(
            [{"status": "resolved", "path": "src/a.py", "text_excerpt": "x"}]
        ))
        self.assertTrue(runner._resolved_range_entries_valid(
            [{"status": "resolved", "range_ref": {"ref": "r"}, "text_excerpt": "x"}]
        ))
        malformed = [
            {"status": "resolved"},
            {"status": "resolved", "source_path": "src/a.py"},
            {"status": "resolved", "text_excerpt": "x"},
            {"status": "resolved", "text_excerpt": "  ", "source_path": "a.py"},
            {"status": "resolved", "text_excerpt": 5, "source_path": "a.py"},
            {"status": "resolved", "text_excerpt": "x", "source_path": ""},
            {"status": "resolved", "text_excerpt": "x", "source_path": 7},
            {"status": "resolved", "text_excerpt": "x", "range_ref": {}},
            {"status": "resolved", "text_excerpt": "x", "range_ref": "r"},
            "resolved",
            None,
        ]
        for entry in malformed:
            with self.subTest(entry=entry):
                self.assertFalse(runner._resolved_range_entries_valid([entry]))
                self.assertFalse(runner._resolved_range_entries_valid([good, entry]))
        self.assertFalse(runner._resolved_range_entries_valid(None))
        self.assertFalse(runner._resolved_range_entries_valid({"status": "resolved"}))

    def test_resolved_range_structured_language_evidence(self) -> None:
        lang = {
            "artifact_role": "language_structure_json",
            "status": "resolved",
            "range_ref": {
                "ref": "rust:fn:main", "path": "src/main.rs",
                "range": {"start_line": 3, "end_line": 9}, "language": "rust",
            },
            "source_path": "src/main.rs",
            "source_line_range": {"start_line": 3, "end_line": 9, "display": "3-9"},
        }
        canonical = {
            "artifact_role": "canonical_md", "status": "resolved",
            "range_ref": {"ref": "c1"}, "text_excerpt": "x",
        }
        self.assertTrue(runner._resolved_range_entries_valid([lang, canonical]))
        self.assertTrue(runner._resolved_range_entries_valid(
            [{"status": "resolved", "range_ref": {"path": "a.md"}, "text_excerpt": "x"}]
        ))

        def mut(**changes):
            entry = copy.deepcopy(lang)
            for key, val in changes.items():
                target = entry
                *parents, last = key.split("__")
                for part in parents:
                    target = target[part]
                target[last] = val
            return entry

        bad = [
            {"artifact_role": "language_structure_json", "status": "resolved"},
            {"status": "resolved", "range_ref": {"junk": "x"}, "text_excerpt": "fake"},
            {"status": "resolved", "range_ref": {"junk": "x"}},
            mut(range_ref__ref=""), mut(range_ref__ref=5), mut(range_ref__path=""),
            mut(source_path="other.rs"), mut(source_path=""),
            mut(range_ref__range={"start_line": True, "end_line": 9}),
            mut(range_ref__range={"start_line": 3, "end_line": 2.0}),
            mut(range_ref__range={"start_line": 9, "end_line": 3}),
            mut(range_ref__range={"start_line": "3", "end_line": 9}),
            mut(source_line_range={"start_line": 3, "end_line": 8}),
            mut(source_line_range=None), mut(range_ref=["x"]),
        ]
        for entry in bad:
            with self.subTest(entry=entry):
                self.assertFalse(runner._resolved_range_entries_valid([entry]))
                self.assertFalse(runner._resolved_range_entries_valid([canonical, entry]))
        self.assertTrue(runner._resolved_range_entries_valid(
            [{**lang, "status": "candidate", "range_ref": {}}]
        ))

    def test_treatment_rejects_identityless_resolved_ranges_without_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__ask_context")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )

            def payload(ranges: object) -> dict:
                return {
                    "kind": "repobrief.mcp.read_only_frontdoor",
                    "version": "v1",
                    "tool": "ask_context",
                    "status": "ok",
                    "context_pack": {
                        "kind": "repobrief.ask_context_pack",
                        "version": "1.0",
                        "snapshot_ref": {
                            "manifest_path": str(manifest),
                            "manifest_sha256": value["repobrief"]["manifest_sha256"],
                            "git_commit": COMMIT,
                            "freshness_status": "not_comparable",
                        },
                        "freshness": {"status": "not_comparable"},
                        "resolved_ranges": ranges,
                        "budget": {"context_bytes_used": 3},
                    },
                    "live_freshness": {
                        "kind": "repobrief.live_freshness",
                        "version": "v1",
                        "status": "fresh",
                        "reason": "git_head_matches_snapshot",
                        "bundle_manifest": str(manifest),
                        "repo_root": "/tmp/repo",
                        "read_only_git_probe": True,
                        "implicit_refresh": False,
                        "snapshot_provenance": {"git_commit": COMMIT},
                    },
                }

            def evidence_for(ranges: object):
                tool_result["content"] = json.dumps(
                    {"structuredContent": complete(payload(ranges))}, sort_keys=True
                )
                calls = runner.normalize_tool_calls(value, messages)
                return runner.normalize_repoground_evidence(value, messages, calls)

            for ranges in (
                [{"status": "resolved"}],
                [{"status": "resolved", "source_path": "src/a.py"}],
                [{"status": "resolved", "text_excerpt": "x"}],
                [{"status": "resolved", "text_excerpt": "x", "range_ref": {}}],
                [{"status": "resolved", "text_excerpt": "fake", "range_ref": {"junk": "x"}}],
                [{"artifact_role": "language_structure_json", "status": "resolved"}],
                [{"artifact_role": "language_structure_json", "status": "resolved",
                  "range_ref": {"ref": "r", "path": "a.rs", "range": {"start_line": True, "end_line": 2}},
                  "source_path": "a.rs",
                  "source_line_range": {"start_line": 1, "end_line": 2}}],
                ["resolved"],
                [None],
            ):
                with self.subTest(ranges=ranges):
                    self.assertIsNone(evidence_for(ranges))

            good = evidence_for([{
                "status": "resolved",
                "source_path": "src/a.py",
                "text_excerpt": "x = 1",
                "range_ref": {"ref": "a"},
            }])
            self.assertEqual(good["calls"][0]["resolved_range_count"], 1)
            structured = evidence_for([
                {
                "artifact_role": "language_structure_json",
                "status": "resolved",
                "range_ref": {
                    "ref": "rust:fn:main", "path": "src/main.rs",
                    "range": {"start_line": 3, "end_line": 9}, "language": "rust",
                },
                "source_path": "src/main.rs",
                "source_line_range": {"start_line": 3, "end_line": 9, "display": "3-9"},
            },
                {"status": "resolved", "range_ref": {"ref": "c"}, "text_excerpt": "x"},
            ])
            self.assertEqual(structured["calls"][0]["resolved_range_count"], 2)
            empty = evidence_for([])
            self.assertEqual(empty["calls"][0]["resolved_range_count"], 0)

    def test_treatment_binds_manifest_once_for_multiple_evidence_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_use = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_use"
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.live_freshness",
                "version": "v1",
                "status": "fresh",
                "reason": "git_head_matches_snapshot",
                "bundle_manifest": str(manifest),
                "repo_root": "/tmp/repo",
                "read_only_git_probe": True,
                "implicit_refresh": False,
                "snapshot_provenance": {"git_commit": COMMIT},
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            second_use = copy.deepcopy(tool_use)
            second_use["id"] = "tool-2"
            second_result = copy.deepcopy(tool_result)
            second_result["tool_use_id"] = "tool-2"
            next(message for message in messages if message.get("type") == "assistant")[
                "message"
            ]["content"].append(second_use)
            next(message for message in messages if message.get("type") == "user")[
                "message"
            ]["content"].append(second_result)
            calls = runner.normalize_tool_calls(value, messages)

            with patch.object(
                runner,
                "_bound_repoground_manifest",
                wraps=runner._bound_repoground_manifest,
            ) as bound_manifest:
                evidence = runner.normalize_repoground_evidence(
                    value, messages, calls
                )

            self.assertEqual(bound_manifest.call_count, 1)
            self.assertEqual(len(evidence["calls"]), 2)

    def test_treatment_projects_revision_bound_resource_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(
                value,
                Path(directory),
                repositories=[{"git_commit": COMMIT, "repo_root": "/tmp/repo"}],
            )
            logical_parent = Path(directory) / "sub"
            logical_parent.mkdir()
            logical_manifest = logical_parent / ".." / manifest.name
            value["repobrief"]["manifest"] = str(logical_manifest)
            uri = "repoground://snapshot/demo/canonical"
            messages = runner.parse_jsonl(
                stream(value, tool_name="ReadMcpResource")
            )
            tool_use = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_use"
            )
            tool_use["input"] = {"uri": uri}
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            live_freshness = {
                "kind": "repobrief.live_freshness",
                "version": "v1",
                "status": "fresh",
                "reason": "git_head_matches_snapshot",
                "bundle_manifest": str(logical_manifest),
                "repo_root": "/tmp/repo",
                "read_only_git_probe": True,
                "implicit_refresh": False,
                "snapshot_provenance": {"git_commit": COMMIT},
            }
            resource = {
                "contents": [{
                    "uri": uri,
                    "text": "# Demo\n",
                    "mimeType": "text/markdown",
                }],
                "_meta": {
                    "repoground": {
                        "status": "available",
                        "implicitRefresh": False,
                        "snapshotContext": {},
                        "identity": {},
                        "liveFreshness": live_freshness,
                    }
                },
            }
            tool_result["content"] = json.dumps(resource, sort_keys=True)
            calls = runner.normalize_tool_calls(value, messages)
            self.assertEqual(
                runner.normalize_repoground_evidence(value, messages, calls),
                {
                    "target_commit": COMMIT,
                    "bundle_commit": COMMIT,
                    "calls": [{
                        "sequence": 1,
                        "tool": "repobrief_resource_read",
                        "freshness_status": "fresh",
                        "resolved_range_count": None,
                        "context_bytes_used": len("# Demo\n".encode("utf-8")),
                        "grounding_status": None,
                    }],
                },
            )

            bad_surrogate_resource = copy.deepcopy(resource)
            bad_surrogate_resource["contents"][0]["text"] = "\ud800"
            tool_result["content"] = json.dumps(bad_surrogate_resource, sort_keys=True)
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            unknown_resource = copy.deepcopy(resource)
            unknown_freshness = unknown_resource["_meta"]["repoground"]["liveFreshness"]
            unknown_freshness.update({
                "status": "unknown",
                "reason": "git_probe_failed",
                "repo_root": "/tmp/repo",
                "read_only_git_probe": True,
                "implicit_refresh": False,
            })
            unknown_freshness.pop("snapshot_provenance")
            tool_result["content"] = json.dumps(unknown_resource, sort_keys=True)
            unknown_evidence = runner.normalize_repoground_evidence(
                value,
                messages,
                runner.normalize_tool_calls(value, messages),
            )
            self.assertEqual(
                unknown_evidence["calls"][0]["freshness_status"], "unknown"
            )

            unknown_freshness["repo_root"] = "/tmp/other-repo"
            tool_result["content"] = json.dumps(unknown_resource, sort_keys=True)
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value,
                    messages,
                    runner.normalize_tool_calls(value, messages),
                )
            )

            tool_result["content"] = json.dumps(resource, sort_keys=True)
            invalid_variants = [
                ("implicit_refresh_true", {"implicit_refresh": True}, ()),
                ("missing_implicit_refresh", {}, ("implicit_refresh",)),
                ("non_boolean_read_only_git_probe", {"read_only_git_probe": "yes"}, ()),
                ("missing_reason", {}, ("reason",)),
                ("missing_repo_root", {}, ("repo_root",)),
            ]
            for name, updates, removals in invalid_variants:
                with self.subTest(name=name):
                    invalid = copy.deepcopy(resource)
                    freshness = invalid["_meta"]["repoground"]["liveFreshness"]
                    freshness.update(updates)
                    for field in removals:
                        freshness.pop(field)
                    tool_result["content"] = json.dumps(invalid, sort_keys=True)
                    self.assertIsNone(
                        runner.normalize_repoground_evidence(
                            value,
                            messages,
                            runner.normalize_tool_calls(value, messages),
                        )
                    )

            tool_result["content"] = json.dumps(resource, sort_keys=True)
            resource["contents"][0]["uri"] = "repoground://snapshot/other"
            tool_result["content"] = json.dumps(resource, sort_keys=True)
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            list_messages = runner.parse_jsonl(
                stream(value, tool_name="ListMcpResources")
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value,
                    list_messages,
                    runner.normalize_tool_calls(value, list_messages),
                )
            )

    def test_bound_manifest_accepts_canonical_multi_repo_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(
                value,
                Path(directory),
                provenance_key="snapshotProvenance",
                repositories=[
                    {"repository": "other/repo", "git_commit": "b" * 40},
                    {
                        "repository": "heimgewebe/repo",
                        "git_commit": COMMIT,
                        "repo_root": "/tmp/repo",
                    },
                ],
            )
            path, sha256, commit, repo_root = runner._bound_repoground_manifest(value)
            self.assertEqual(path, manifest.resolve())
            self.assertEqual(sha256, value["repobrief"]["manifest_sha256"])
            self.assertEqual(commit, COMMIT)
            self.assertEqual(repo_root, "/tmp/repo")

    def _bind_envelope(self, directory: str, **envelope) -> dict:
        value = request(condition="treatment")
        manifest = bind_manifest(value, Path(directory))
        document = json.loads(manifest.read_bytes())
        document.pop("kind")
        document.pop("version")
        document.update(envelope)
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        manifest.write_bytes(raw)
        value["repobrief"]["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        return value

    def test_bound_manifest_accepts_v2_and_legacy_envelopes(self) -> None:
        cases = (
            {"kind": "repoground.bundle.manifest", "version": "2.0"},
            {"kind": "repolens.bundle.manifest", "version": "1.0"},
            {"kind": "repolens.bundle.manifest"},
        )
        for envelope in cases:
            with self.subTest(envelope=envelope), tempfile.TemporaryDirectory() as directory:
                value = self._bind_envelope(directory, **envelope)
                _, _, commit, _ = runner._bound_repoground_manifest(value)
                self.assertEqual(commit, COMMIT)
                self.assertIsNotNone(
                    runner._optional_repoground_manifest_binding(value)
                )

    def test_bound_manifest_rejects_invalid_envelopes(self) -> None:
        cases = (
            ({}, "kind is invalid"),
            ({"kind": "other.manifest", "version": "2.0"}, "kind is invalid"),
            ({"kind": "repoground.bundle.manifest"}, "version is invalid"),
            ({"kind": "repoground.bundle.manifest", "version": "1.0"}, "version is invalid"),
            ({"kind": "repoground.bundle.manifest", "version": 2.0}, "version is invalid"),
            ({"kind": "repolens.bundle.manifest", "version": "2.0"}, "version is invalid"),
        )
        for envelope, message in cases:
            with self.subTest(envelope=envelope), tempfile.TemporaryDirectory() as directory:
                value = self._bind_envelope(directory, **envelope)
                with self.assertRaisesRegex(runner.RunnerError, message):
                    runner._bound_repoground_manifest(value)
                self.assertIsNone(
                    runner._optional_repoground_manifest_binding(value)
                )

    def test_bound_manifest_accepts_supported_commit_fields(self) -> None:
        for field in ("git_commit", "commit", "head"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                value = request(condition="treatment")
                bind_manifest(
                    value,
                    Path(directory),
                    repositories=[{field: COMMIT}],
                )
                _, _, commit, _ = runner._bound_repoground_manifest(value)
                self.assertEqual(commit, COMMIT)

    def test_bound_manifest_normalizes_uppercase_commit(self) -> None:
        for raw_commit in (COMMIT.upper(), ("ab" * 32).upper()):
            with self.subTest(length=len(raw_commit)), tempfile.TemporaryDirectory() as directory:
                value = request(condition="treatment")
                bind_manifest(value, Path(directory), commit=raw_commit)
                _, _, commit, _ = runner._bound_repoground_manifest(value)
                self.assertEqual(commit, raw_commit.lower())

    def test_bound_manifest_rejects_oversized_before_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            with manifest.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            with patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("unbounded manifest read"),
            ):
                with self.assertRaisesRegex(
                    runner.RunnerError, "exceeds configured limit"
                ):
                    runner._bound_repoground_manifest(value)

    def test_bound_manifest_rejects_ambiguous_multi_repo_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            bind_manifest(
                value,
                Path(directory),
                provenance_key="snapshotProvenance",
                repositories=[
                    {"repo": "repo", "git_commit": COMMIT},
                    {"repository": "heimgewebe/repo", "git_commit": "b" * 40},
                ],
            )
            with self.assertRaises(runner.RunnerError):
                runner._bound_repoground_manifest(value)

    def test_bound_manifest_singleton_identity_semantics(self) -> None:
        foreign = "b" * 40
        for field in ("repo", "repository", "repo_id", "name"):
            for wrong in ("other", "other/repo-x", "heimgewebe/other.git"):
                with self.subTest(field=field, wrong=wrong), tempfile.TemporaryDirectory() as directory:
                    value = request(condition="treatment")
                    bind_manifest(
                        value,
                        Path(directory),
                        repositories=[{field: wrong, "git_commit": foreign}],
                    )
                    with self.assertRaises(runner.RunnerError):
                        runner._bound_repoground_manifest(value)
                    self.assertIsNone(
                        runner._optional_repoground_manifest_binding(value)
                    )
        for field, good in (
            ("repo", "repo"),
            ("repository", "heimgewebe/repo"),
            ("repo_id", "repo"),
            ("name", "heimgewebe/repo.git"),
        ):
            with self.subTest(field=field, good=good), tempfile.TemporaryDirectory() as directory:
                value = request(condition="treatment")
                bind_manifest(
                    value,
                    Path(directory),
                    repositories=[{field: good, "git_commit": COMMIT}],
                )
                _, _, commit, _ = runner._bound_repoground_manifest(value)
                self.assertEqual(commit, COMMIT)
        # Anonymous legacy singleton (no identity fields, blank ignored).
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            bind_manifest(
                value,
                Path(directory),
                repositories=[{"name": "  ", "git_commit": COMMIT}],
            )
            _, _, commit, _ = runner._bound_repoground_manifest(value)
            self.assertEqual(commit, COMMIT)

    def _bind_repositories(self, directory: str, repositories: list[dict]) -> dict:
        value = request(condition="treatment")
        bind_manifest(
            value,
            Path(directory),
            provenance_key="snapshotProvenance",
            repositories=repositories,
        )
        return value

    def test_bound_manifest_normalizes_canonical_identity_forms(self) -> None:
        sha = "c" * 40
        forms = (
            "repo.git",
            "heimgewebe/repo",
            "heimgewebe__repo__main",
            f"heimgewebe__repo__main--{sha}",
            f"heimgewebe__repo__main--{'d' * 64}--recovery-0123456789ab",
        )
        for form in forms:
            for singleton in (True, False):
                with self.subTest(form=form, singleton=singleton), tempfile.TemporaryDirectory() as directory:
                    repositories = [{"repository": form, "git_commit": COMMIT}]
                    if not singleton:
                        repositories.insert(
                            0,
                            {"repository": "owner__other__main", "git_commit": "b" * 40},
                        )
                    value = self._bind_repositories(directory, repositories)
                    _, _, commit, _ = runner._bound_repoground_manifest(value)
                    self.assertEqual(commit, COMMIT)

    def test_provenance_match_preserves_double_underscore_repo_segments(self) -> None:
        sha = "e" * 40
        positive = (
            ({"foo__bar"}, "owner__foo__bar__main"),
            ({"foo__bar"}, f"owner__foo__bar__main--{sha}"),
            ({"foo__bar"}, f"owner__foo__bar__main--{sha}--recovery-0123456789ab"),
            ({"foo__bar"}, "foo__bar__main"),
            ({"foo__bar"}, "foo__bar.git"),
            ({"owner/foo__bar"}, "owner/foo__bar"),
            ({"repo"}, "repo__main"),
            ({"repo"}, "owner__repo__main"),
        )
        for requested, identity in positive:
            with self.subTest(requested=requested, identity=identity):
                self.assertEqual(
                    runner._provenance_match({"repository": identity}, requested),
                    "match",
                )
        unmatched = (
            ({"foo"}, "owner__foo__bar__main"),
            ({"foo__bar"}, "owner__foo__main"),
            ({"foo__bar"}, "owner__xfoo__bar__main"),
            ({"foo__bar"}, "owner__foo__bar__"),
            ({"foo__bar"}, "owner__foo__bar"),
            ({"foo__bar"}, "owner__foo__bar__main/x"),
            ({"repo"}, "owner__repo"),
            ({"repo"}, "repo__other__main"),
        )
        for requested, identity in unmatched:
            with self.subTest(requested=requested, identity=identity):
                self.assertIsNone(
                    runner._provenance_match({"repository": identity}, requested)
                )
        self.assertEqual(
            runner._provenance_match({"repository": "other/foo__bar"}, {"foo__bar"}),
            "foreign",
        )

    def test_canonical_provenance_owner_requires_exact_requested_owner(self) -> None:
        cases = (
            ("heimgewebe/bar", "bar", "owner__foo__bar__main", False),
            ("heimgewebe/foo__bar", "foo__bar", "other__foo__bar__main", False),
            ("heimgewebe/foo__bar", "foo__bar", "heimgewebe__foo__bar__main", True),
            ("owner__foo/bar", "bar", "owner__foo__bar__main", True),
            ("heimgewebe/repo", "repo", "repo__main", True),
            ("heimgewebe/repo", "alias", "heimgewebe__alias__main", True),
        )
        for slug, repo_id, identity, accepted in cases:
            with self.subTest(slug=slug, identity=identity), tempfile.TemporaryDirectory() as directory:
                value = request(condition="treatment")
                value["repository"]["id"] = repo_id
                value["repository"]["repository"] = slug
                bind_manifest(
                    value, Path(directory),
                    repositories=[{"repository": identity, "git_commit": COMMIT, "repo_root": "/tmp/repo"}],
                )
                if accepted:
                    _, _, commit, _ = runner._bound_repoground_manifest(value)
                    self.assertEqual(commit, COMMIT)
                else:
                    with self.assertRaisesRegex(runner.RunnerError, "does not match request"):
                        runner._bound_repoground_manifest(value)
                    self.assertIsNone(runner._optional_repoground_manifest_binding(value))

        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            value["repository"]["id"] = "bar"
            value["repository"]["repository"] = "heimgewebe/bar"
            bind_manifest(
                value, Path(directory),
                repositories=[
                    {"repository": "other__foo__bar__main", "git_commit": "b" * 40},
                    {"repository": "heimgewebe__bar__main", "git_commit": COMMIT},
                ],
            )
            _, _, commit, _ = runner._bound_repoground_manifest(value)
            self.assertEqual(commit, COMMIT)

    def test_bound_manifest_double_underscore_repo_collision_and_ambiguity(self) -> None:
        sha = "e" * 40
        for requested_repo in ("foo__bar", "foo"):
            for repositories, expected in (
                ([{"repository": "heimgewebe__foo__bar__main", "git_commit": COMMIT}], "foo__bar"),
                ([{"repository": f"heimgewebe__foo__bar__main--{sha}", "git_commit": COMMIT},
                  {"repository": "owner__other__main", "git_commit": "b" * 40}], "foo__bar"),
                (
                    [
                        {"repository": "heimgewebe__foo__bar__main", "git_commit": COMMIT},
                        {"repository": "heimgewebe__foo__bar__dev", "git_commit": "b" * 40},
                    ],
                    "ambiguous",
                ),
                ([{"repository": "other/foo__bar", "git_commit": COMMIT}], "foreign"),
            ):
                with self.subTest(
                    requested=requested_repo, expected=expected
                ), tempfile.TemporaryDirectory() as directory:
                    value = self._bind_repositories(directory, repositories)
                    value["repository"] = {**value.get("repository", {}), "id": requested_repo, "repository": f"heimgewebe/{requested_repo}"}
                    if requested_repo == "foo" or expected in {"ambiguous", "foreign"}:
                        with self.assertRaises(runner.RunnerError):
                            runner._bound_repoground_manifest(value)
                    else:
                        _, _, commit, _ = runner._bound_repoground_manifest(value)
                        self.assertEqual(commit, COMMIT)

    def test_bound_manifest_rejects_foreign_and_unknown_identities(self) -> None:
        cases = (
            [{"repository": "owner__other__main"}, {"repository": "x__y__main"}],
            [{"repository": "owner__repo-x__main"}, {"repository": "owner/repo-x"}],
            [{"repository": "repo__other__main"}, {"repository": "other"}],
            [{"repository": "owner__repo"}, {"repository": "owner__repo__"}],
            [{"repository": "owner__repo__main/x"}, {"repository": "other"}],
        )
        for repositories in cases:
            with self.subTest(repositories=repositories), tempfile.TemporaryDirectory() as directory:
                value = self._bind_repositories(
                    directory,
                    [dict(item, git_commit=COMMIT) for item in repositories],
                )
                with self.assertRaises(runner.RunnerError):
                    runner._bound_repoground_manifest(value)
        with tempfile.TemporaryDirectory() as directory:
            value = self._bind_repositories(
                directory, [{"repository": "owner__other__main", "git_commit": COMMIT}]
            )
            with self.assertRaises(runner.RunnerError):
                runner._bound_repoground_manifest(value)

    def test_bound_manifest_never_binds_foreign_owner_identity(self) -> None:
        foreign = {"repository": "other/repo", "git_commit": "b" * 40}
        cases = {
            "singleton": [foreign],
            "multi_only_unmatched": [
                foreign,
                {"repository": "owner__other__main", "git_commit": "c" * 40},
            ],
            "multi_two_foreign": [
                foreign,
                {"repository": "third/repo", "git_commit": "c" * 40},
            ],
            "mixed_fields": [
                {"repository": "other/repo", "name": "repo", "git_commit": COMMIT}
            ],
        }
        for label, repositories in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                value = self._bind_repositories(directory, repositories)
                with self.assertRaises(runner.RunnerError):
                    runner._bound_repoground_manifest(value)
                self.assertIsNone(runner._optional_repoground_manifest_binding(value))
                messages = runner.parse_jsonl(
                    stream(value, tool_name="mcp__repobrief__ask_context")
                )
                self.assertIsNone(
                    runner.normalize_repoground_evidence(
                        value, messages, runner.normalize_tool_calls(value, messages)
                    )
                )
        # Exactly one real match: a foreign entry is ignored, not ambiguous.
        with tempfile.TemporaryDirectory() as directory:
            value = self._bind_repositories(
                directory,
                [foreign, {"repository": "heimgewebe/repo", "git_commit": COMMIT}],
            )
            _, _, commit, _ = runner._bound_repoground_manifest(value)
            self.assertEqual(commit, COMMIT)

    def test_bound_manifest_rejects_ambiguous_normalized_aliases(self) -> None:
        for first, second in (
            ("repo.git", "heimgewebe__repo__main"),
            ("heimgewebe__repo__main", f"heimgewebe__repo__dev--{'c' * 40}"),
            ("heimgewebe__repo__main", "heimgewebe__repo__main--" + "c" * 64),
            ("heimgewebe/repo", "heimgewebe__repo__main"),
        ):
            with self.subTest(first=first, second=second), tempfile.TemporaryDirectory() as directory:
                value = self._bind_repositories(
                    directory,
                    [
                        {"repository": first, "git_commit": COMMIT},
                        {"repository": second, "git_commit": "b" * 40},
                    ],
                )
                with self.assertRaises(runner.RunnerError):
                    runner._bound_repoground_manifest(value)

    def test_mismatched_singleton_provenance_yields_no_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(
                value,
                Path(directory),
                repositories=[{"repo": "other", "git_commit": "b" * 40}],
            )
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__ask_context")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "ask_context",
                "status": "ok",
                "context_pack": {
                    "kind": "repobrief.ask_context_pack",
                    "version": "1.0",
                    "snapshot_ref": {
                        "manifest_path": str(manifest),
                        "manifest_sha256": value["repobrief"]["manifest_sha256"],
                        "git_commit": None,
                        "freshness_status": "not_comparable",
                    },
                    "freshness": {"status": "not_comparable"},
                    "resolved_ranges": [],
                    "budget": {"context_bytes_used": 1},
                },
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertIsNone(
                runner.normalize_repoground_evidence(value, messages, calls)
            )

    def test_treatment_projects_grounding_from_verdict_snapshot_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            logical_parent = Path(directory) / "sub"
            logical_parent.mkdir()
            logical_manifest = logical_parent / ".." / manifest.name
            value["repobrief"]["manifest"] = str(logical_manifest)
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__grounding_verify")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "grounding_verify",
                "status": "pass",
                "verdict": {
                    "kind": "repobrief.answer_grounding_verdict",
                    "version": "1.0",
                    "status": "pass",
                    "snapshot_ref": {
                        "manifest_path": str(logical_manifest),
                        "git_commit": COMMIT.upper(),
                        "freshness_status": "fresh",
                    },
                },
                "live_freshness": {
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "fresh",
                    "reason": "git_head_matches_snapshot",
                    "bundle_manifest": str(logical_manifest),
                    "repo_root": "/tmp/repo",
                    "read_only_git_probe": True,
                    "implicit_refresh": False,
                    "snapshot_provenance": {"git_commit": COMMIT.upper()},
                },
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertEqual(
                runner.normalize_repoground_evidence(value, messages, calls),
                {
                    "target_commit": COMMIT,
                    "bundle_commit": COMMIT,
                    "calls": [{
                        "sequence": 1,
                        "tool": "grounding_verify",
                        "freshness_status": "fresh",
                        "resolved_range_count": None,
                        "context_bytes_used": None,
                        "grounding_status": "pass",
                    }],
                },
            )

            conflicting = copy.deepcopy(payload)
            conflicting["live_freshness"]["status"] = "stale"
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(conflicting)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )

            payload["verdict"]["snapshot_ref"]["manifest_path"] = str(
                Path(directory) / "other.bundle.manifest.json"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            payload["verdict"]["snapshot_ref"]["manifest_path"] = str(manifest)
            payload["live_freshness"]["bundle_manifest"] = str(
                Path(directory) / "other.bundle.manifest.json"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            payload["live_freshness"]["bundle_manifest"] = str(manifest)
            payload["live_freshness"]["status"] = "not_applicable"
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

    def test_treatment_does_not_project_version_drift_as_repoground_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": {
                    "kind": "repobrief.live_freshness",
                    "version": "v2",
                    "status": "fresh",
                    "bundle_manifest": str(manifest),
                    "snapshot_provenance": {"git_commit": COMMIT},
                }},
                sort_keys=True,
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertIsNone(
                runner.normalize_repoground_evidence(value, messages, calls)
            )

    def test_treatment_rejects_not_applicable_live_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": {
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "not_applicable",
                    "bundle_manifest": str(manifest),
                    "snapshot_provenance": {"git_commit": COMMIT},
                }},
                sort_keys=True,
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertIsNone(
                runner.normalize_repoground_evidence(value, messages, calls)
            )

    def test_treatment_projects_bound_not_comparable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            logical_parent = Path(directory) / "sub"
            logical_parent.mkdir()
            logical_manifest = logical_parent / ".." / manifest.name
            value["repobrief"]["manifest"] = str(logical_manifest)
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            tool_result["content"] = json.dumps(
                {"structuredContent": complete({
                    "kind": "repobrief.live_freshness",
                    "version": "v1",
                    "status": "not_comparable",
                    "reason": "repo_root_not_configured",
                    "bundle_manifest": str(logical_manifest),
                    "repo_root": None,
                    "read_only_git_probe": False,
                    "implicit_refresh": False,
                })},
                sort_keys=True,
            )
            calls = runner.normalize_tool_calls(value, messages)
            self.assertEqual(
                runner.normalize_repoground_evidence(value, messages, calls),
                {
                    "target_commit": COMMIT,
                    "bundle_commit": COMMIT,
                    "calls": [{
                        "sequence": 1,
                        "tool": "live_freshness",
                        "freshness_status": "not_comparable",
                        "resolved_range_count": None,
                        "context_bytes_used": None,
                        "grounding_status": None,
                    }],
                },
            )
            drifted = json.loads(tool_result["content"])
            drifted["structuredContent"]["bundle_manifest"] = str(
                Path(directory) / "other.bundle.manifest.json"
            )
            tool_result["content"] = json.dumps(drifted, sort_keys=True)
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

    def _evidence_for_payload(
        self, tool: str, payload, *, root: str | None = "/tmp/repo", fill: bool = True
    ):
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            repositories = [{"git_commit": COMMIT}]
            if root is not None:
                repositories[0]["repo_root"] = root
            manifest = bind_manifest(value, Path(directory), repositories=repositories)
            messages = runner.parse_jsonl(
                stream(value, tool_name=f"mcp__repobrief__{tool}")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            built = payload(str(manifest))
            pack = built.get("context_pack")
            if isinstance(pack, dict):
                pack["snapshot_ref"]["manifest_sha256"] = value["repobrief"][
                    "manifest_sha256"
                ]
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(built) if fill else built},
                sort_keys=True,
            )
            calls = runner.normalize_tool_calls(value, messages)
            return runner.normalize_repoground_evidence(value, messages, calls)

    @staticmethod
    def _freshness(manifest: str, **overrides) -> dict:
        value = {
            "kind": "repobrief.live_freshness",
            "version": "v1",
            "status": "fresh",
            "reason": "git_head_matches_snapshot",
            "bundle_manifest": manifest,
            "repo_root": "/tmp/repo",
            "read_only_git_probe": True,
            "implicit_refresh": False,
            "snapshot_provenance": {"git_commit": COMMIT},
        }
        value.update(overrides)
        return value

    def test_live_freshness_fresh_and_stale_require_proven_probe(self) -> None:
        for status in ("fresh", "stale"):
            with self.subTest(status=status, case="valid"):
                evidence = self._evidence_for_payload(
                    "live_freshness",
                    lambda m: self._freshness(m, status=status),
                )
                self.assertEqual(evidence["calls"][0]["freshness_status"], status)
            for case, overrides in (
                ("probe_false", {"read_only_git_probe": False}),
                ("root_none", {"repo_root": None}),
                ("root_empty", {"repo_root": ""}),
                ("root_mismatch", {"repo_root": "/tmp/other-repo"}),
                ("implicit_refresh", {"implicit_refresh": True}),
            ):
                with self.subTest(status=status, case=case):
                    self.assertIsNone(
                        self._evidence_for_payload(
                            "live_freshness",
                            lambda m: self._freshness(m, status=status, **overrides),
                        )
                    )
        with self.subTest(case="manifest_without_repo_root"):
            self.assertIsNone(
                self._evidence_for_payload(
                    "live_freshness", self._freshness, root=None
                )
            )

    def test_live_freshness_snapshot_binds_every_status_to_proven_probe(self) -> None:
        reasons = {
            "fresh": "git_head_matches_snapshot",
            "stale": "git_head_differs_from_snapshot",
            "unknown": "snapshot_working_tree_cleanliness_unavailable",
            "not_comparable": "current_git_provenance_unavailable",
        }
        for status, reason in reasons.items():
            with self.subTest(status=status, case="valid"):
                evidence = self._evidence_for_payload(
                    "live_freshness",
                    lambda m: self._freshness(m, status=status, reason=reason),
                )
                self.assertEqual(evidence["calls"][0]["freshness_status"], status)
            for case, overrides in (
                ("probe_false", {"read_only_git_probe": False}),
                ("root_none", {"repo_root": None}),
                ("root_mismatch", {"repo_root": "/tmp/other-repo"}),
                ("implicit_refresh", {"implicit_refresh": True}),
            ):
                with self.subTest(status=status, case=case):
                    self.assertIsNone(
                        self._evidence_for_payload(
                            "live_freshness",
                            lambda m: self._freshness(
                                m, status=status, reason=reason, **overrides
                            ),
                        )
                    )
        with self.subTest(case="malformed_not_comparable"):
            self.assertIsNone(
                self._evidence_for_payload(
                    "live_freshness",
                    lambda m: self._freshness(
                        m,
                        status="not_comparable",
                        reason="random_reason",
                        read_only_git_probe=False,
                    ),
                )
            )

    def test_live_freshness_preserves_unknown_and_not_comparable_fallbacks(self) -> None:
        unknown = self._evidence_for_payload(
            "live_freshness",
            lambda m: self._freshness(
                m, status="unknown", reason="git_probe_failed"
            ),
        )
        self.assertEqual(unknown["calls"][0]["freshness_status"], "unknown")
        fallback = self._evidence_for_payload(
            "live_freshness",
            lambda m: {
                "kind": "repobrief.live_freshness",
                "version": "v1",
                "status": "not_comparable",
                "reason": "repo_root_not_configured",
                "bundle_manifest": m,
                "repo_root": None,
                "read_only_git_probe": False,
                "implicit_refresh": False,
            },
        )
        self.assertEqual(fallback["calls"][0]["freshness_status"], "not_comparable")

    def test_claude_nested_live_freshness_requires_proven_probe(self) -> None:
        def ask_context(manifest: str, **freshness) -> dict:
            return {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "ask_context",
                "status": "ok",
                "context_pack": {
                    "kind": "repobrief.ask_context_pack",
                    "version": "1.0",
                    "snapshot_ref": {
                        "manifest_path": manifest,
                        "manifest_sha256": hashlib.sha256(b"x").hexdigest(),
                        "git_commit": COMMIT,
                        "freshness_status": "fresh",
                    },
                    "freshness": {"status": "fresh"},
                    "resolved_ranges": [],
                    "budget": {"context_bytes_used": 1},
                },
                "live_freshness": self._freshness(manifest, **freshness),
            }

        valid = self._evidence_for_payload("ask_context", ask_context)
        self.assertEqual(valid["calls"][0]["tool"], "ask_context")
        self.assertIsNone(
            self._evidence_for_payload(
                "ask_context",
                lambda m: ask_context(m, read_only_git_probe=False),
            )
        )
        self.assertIsNone(
            self._evidence_for_payload(
                "ask_context",
                lambda m: ask_context(m, repo_root="/tmp/other-repo"),
            )
        )

    def test_claude_payload_contract_rejects_invalid_forms_without_crashing(self) -> None:
        def frontdoor(manifest: str, tool: str) -> dict:
            if tool == "ask_context":
                return {
                    "kind": "repobrief.mcp.read_only_frontdoor",
                    "version": "v1",
                    "tool": "ask_context",
                    "status": "ok",
                    "context_pack": {
                        "kind": "repobrief.ask_context_pack",
                        "version": "1.0",
                        "snapshot_ref": {
                            "manifest_path": manifest,
                            "git_commit": COMMIT,
                            "freshness_status": "fresh",
                        },
                        "freshness": {"status": "fresh"},
                        "resolved_ranges": [],
                        "budget": {"context_bytes_used": 1},
                    },
                    "live_freshness": self._freshness(manifest),
                }
            return {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "grounding_verify",
                "status": "pass",
                "verdict": {
                    "kind": "repobrief.answer_grounding_verdict",
                    "version": "1.0",
                    "status": "pass",
                    "snapshot_ref": {
                        "manifest_path": manifest,
                        "git_commit": COMMIT,
                        "freshness_status": "fresh",
                    },
                },
                "live_freshness": self._freshness(manifest),
            }

        for tool in ("ask_context", "grounding_verify"):
            def mutate_writes(payload: dict) -> dict:
                payload["mutation_boundary"] = {"writes": ["/tmp/x"]}
                return payload

            def drop_semantics(payload: dict) -> dict:
                payload["verdict_semantics" if tool == "grounding_verify" else "context_pack_semantics"] = "wrong"
                return payload

            def drop_live(payload: dict) -> dict:
                payload["live_freshness"].pop("does_not_establish", None)
                payload["live_freshness"]["does_not_establish"] = []
                return payload

            for case, mutate in (
                ("writes_not_empty", mutate_writes),
                ("wrong_semantics", drop_semantics),
                ("bad_live_non_claims", drop_live),
            ):
                with self.subTest(tool=tool, case=case):
                    self.assertIsNone(
                        self._evidence_for_payload(
                            tool, lambda m: mutate(complete(frontdoor(m, tool)))
                        )
                    )
        with self.subTest(case="missing_pack_field"):
            def missing(manifest: str) -> dict:
                payload = complete(frontdoor(manifest, "ask_context"))
                payload["context_pack"].pop("request_id")
                return payload

            self.assertIsNone(
                self._evidence_for_payload("ask_context", missing, fill=False)
            )
        with self.subTest(case="grounding_missing_verdict_field"):
            def missing_verdict(manifest: str) -> dict:
                payload = complete(frontdoor(manifest, "grounding_verify"))
                payload["verdict"].pop("range_checks")
                return payload

            self.assertIsNone(
                self._evidence_for_payload(
                    "grounding_verify", missing_verdict, fill=False
                )
            )
        with self.subTest(case="valid_production_forms"):
            self.assertEqual(
                self._evidence_for_payload(
                    "ask_context", lambda m: frontdoor(m, "ask_context")
                )["calls"][0]["tool"],
                "ask_context",
            )
            self.assertEqual(
                self._evidence_for_payload(
                    "grounding_verify",
                    lambda m: frontdoor(m, "grounding_verify"),
                )["calls"][0]["grounding_status"],
                "pass",
            )

    def test_claude_ask_context_enforces_hard_context_byte_ceilings(self) -> None:
        def ask_context(budget: dict):
            def build(manifest: str) -> dict:
                return {
                    "kind": "repobrief.mcp.read_only_frontdoor",
                    "version": "v1",
                    "tool": "ask_context",
                    "status": "ok",
                    "context_pack": {
                        "kind": "repobrief.ask_context_pack",
                        "version": "1.0",
                        "snapshot_ref": {
                            "manifest_path": manifest,
                            "git_commit": COMMIT,
                            "freshness_status": "fresh",
                        },
                        "freshness": {"status": "fresh"},
                        "resolved_ranges": [],
                        "budget": dict(budget),
                    },
                    "live_freshness": self._freshness(manifest),
                }

            return build

        cases = (
            ("used_zero", 0, 8, 16, True),
            ("used_equals_both_limits", 16, 16, 16, True),
            ("used_equals_lower_requested_limit", 8, 8, 16, True),
            ("used_below_limits", 3, 8, 16, True),
            ("used_over_requested_limit", 2, 1, 16, False),
            ("used_over_token_ceiling", 2, 1, 1, False),
            ("requested_limit_over_ceiling", 1, 32, 16, False),
        )
        for name, used, limit, ceiling, accepted in cases:
            with self.subTest(case=name):
                evidence = self._evidence_for_payload(
                    "ask_context",
                    ask_context({
                        "context_bytes_used": used,
                        "max_context_bytes": limit,
                        "token_derived_byte_ceiling": ceiling,
                        # Unicode counts are separate from byte limits.
                        "context_unicode_characters_used": 1000,
                        "approx_context_chars_used": 1000,
                    }),
                )
                if accepted:
                    self.assertEqual(
                        evidence["calls"][0]["context_bytes_used"], used
                    )
                else:
                    self.assertIsNone(evidence)

    def test_malformed_claude_payload_shapes_do_not_raise(self) -> None:
        for tool, payload in (
            ("live_freshness", lambda m: {"kind": "repobrief.live_freshness", "bundle_manifest": m}),
            ("ask_context", lambda m: {"live_freshness": [m], "context_pack": 1}),
            ("grounding_verify", lambda m: {"live_freshness": {"bundle_manifest": m}, "verdict": []}),
        ):
            with self.subTest(tool=tool):
                self.assertIsNone(
                    self._evidence_for_payload(tool, payload, fill=False)
                )

    def test_invalid_tool_kind_does_not_fail_completed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            bind_manifest(value, Path(directory))
            for invalid_kind in ([], {}):
                with self.subTest(kind=type(invalid_kind).__name__):
                    messages = runner.parse_jsonl(
                        stream(value, tool_name="mcp__repobrief__live_freshness")
                    )
                    tool_result = next(
                        block
                        for message in messages
                        for block in runner._list(
                            runner._mapping(message.get("message")).get("content")
                        )
                        if runner._mapping(block).get("type") == "tool_result"
                    )
                    tool_result["content"] = json.dumps({"kind": invalid_kind})
                    raw = b"".join(
                        runner._canonical_json(message).encode("utf-8") + b"\n"
                        for message in messages
                    )
                    started = datetime.now(timezone.utc)
                    receipt = runner.build_receipt(
                        value,
                        raw,
                        transcript_artifact="transcript.jsonl",
                        returncode=0,
                        started_at=started,
                        ended_at=started,
                    )
                    self.assertEqual(receipt["kind"], runner.RECEIPT_KIND)
                    self.assertIsNone(receipt.get("repoground_evidence"))

    def test_unhashable_optional_repoground_fields_do_not_break_receipt(self) -> None:
        for bad in ([], {}):
            with self.subTest(field="decoded_kind", bad_type=type(bad).__name__):
                self.assertIsNone(runner._decoded_repoground_payload({
                    "content": [{"type": "text", "text": json.dumps({"kind": bad})}]
                }))

        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(value, Path(directory))
            bound = runner._optional_repoground_manifest_binding(value)
            self.assertIsNotNone(bound)
            live = self._freshness(str(manifest))
            original = {
                "kind": "repobrief.mcp.read_only_frontdoor",
                "version": "v1",
                "tool": "grounding_verify",
                "status": "pass",
                "verdict": {
                    "kind": "repobrief.answer_grounding_verdict",
                    "version": "1.0",
                    "status": "pass",
                    "snapshot_ref": {
                        "manifest_path": str(manifest),
                        "git_commit": COMMIT,
                        "freshness_status": "fresh",
                    },
                },
                "live_freshness": live,
            }
            self.assertIsNotNone(runner._repoground_evidence_from_payload(
                manifest_binding=bound,
                tool_name="grounding_verify",
                sequence=1,
                payload=original,
            ))
            for path in (
                ("verdict", "status"),
                ("verdict", "snapshot_ref", "manifest_path"),
                ("verdict", "snapshot_ref", "freshness_status"),
                ("live_freshness", "status"),
                ("live_freshness", "bundle_manifest"),
            ):
                for bad in ([], {}):
                    with self.subTest(path=path, bad_type=type(bad).__name__):
                        payload = copy.deepcopy(original)
                        field = payload
                        for name in path[:-1]:
                            field = field[name]
                        field[path[-1]] = bad
                        self.assertIsNone(runner._repoground_evidence_from_payload(
                            manifest_binding=bound,
                            tool_name="grounding_verify",
                            sequence=1,
                            payload=payload,
                        ))
            for bad in ([], {}):
                with self.subTest(field="ask_context.freshness_status", bad_type=type(bad).__name__):
                    payload = {
                        "kind": "repobrief.mcp.read_only_frontdoor",
                        "version": "v1",
                        "tool": "ask_context",
                        "status": "ok",
                        "live_freshness": copy.deepcopy(live),
                        "context_pack": {
                            "kind": "repobrief.ask_context_pack",
                            "version": "1.0",
                            "freshness": {"status": bad},
                            "snapshot_ref": {
                                "manifest_sha256": value["repobrief"]["manifest_sha256"],
                                "freshness_status": bad,
                            },
                        },
                    }
                    self.assertIsNone(runner._repoground_evidence_from_payload(
                        manifest_binding=bound,
                        tool_name="ask_context",
                        sequence=1,
                        payload=payload,
                    ))

    def test_snapshot_and_live_membership_reject_unhashable_json_values(self) -> None:
        paths = frozenset({"/logical/manifest.json"})
        original = {
            "kind": "repobrief.live_freshness",
            "version": "v1",
            "status": "fresh",
            "reason": "git_head_matches_snapshot",
            "bundle_manifest": "/logical/manifest.json",
            "repo_root": "/tmp/repo",
            "read_only_git_probe": True,
            "implicit_refresh": False,
            "snapshot_provenance": {"git_commit": COMMIT},
        }
        for bad in ([], {}):
            with self.subTest(field="snapshot_ref.manifest_path", kind=type(bad).__name__):
                self.assertFalse(runner._snapshot_ref_matches_manifest(
                    {"manifest_path": bad},
                    manifest_paths=paths,
                    manifest_sha256="0" * 64,
                    require_sha=False,
                ))
            for field in ("status", "bundle_manifest"):
                with self.subTest(field="live_freshness." + field, kind=type(bad).__name__):
                    payload = copy.deepcopy(original)
                    payload[field] = bad
                    self.assertIsNone(runner._live_snapshot_commit(
                        payload,
                        manifest_paths=paths,
                        manifest_commit=COMMIT,
                        manifest_repo_root="/tmp/repo",
                    ))

    def test_treatment_projects_strict_unknown_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = request(condition="treatment")
            manifest = bind_manifest(
                value,
                Path(directory),
                repositories=[{"git_commit": COMMIT, "repo_root": "/tmp/repo"}],
            )
            messages = runner.parse_jsonl(
                stream(value, tool_name="mcp__repobrief__live_freshness")
            )
            tool_result = next(
                block
                for message in messages
                for block in runner._list(
                    runner._mapping(message.get("message")).get("content")
                )
                if runner._mapping(block).get("type") == "tool_result"
            )
            payload = {
                "kind": "repobrief.live_freshness",
                "version": "v1",
                "status": "unknown",
                "reason": "git_probe_failed",
                "bundle_manifest": str(manifest),
                "repo_root": "/tmp/repo",
                "read_only_git_probe": True,
                "implicit_refresh": False,
            }
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            calls = runner.normalize_tool_calls(value, messages)
            evidence = runner.normalize_repoground_evidence(value, messages, calls)
            self.assertEqual(evidence["calls"][0]["freshness_status"], "unknown")

            payload["repo_root"] = "/tmp/other-repo"
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

            payload["repo_root"] = "/tmp/repo"
            payload["implicit_refresh"] = True
            tool_result["content"] = json.dumps(
                {"structuredContent": complete(payload)}, sort_keys=True
            )
            self.assertIsNone(
                runner.normalize_repoground_evidence(
                    value, messages, runner.normalize_tool_calls(value, messages)
                )
            )

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
            credential.chmod(0o600)
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
            self.assertEqual(server["command"], sys.executable)
            self.assertEqual(server["args"][0], str(MODULE_PATH.resolve()))
            self.assertEqual(server["args"][1], "--benchmark-mcp-proxy")
            self.assertEqual(
                json.loads(server["args"][2]),
                ["python", "repobrief-mcp-stdio.py", "--bundle-root", "/bundles"],
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
            self.assertEqual(
                runner._validate_provider_executable(
                    stream_fixture=None,
                    executable=str(link),
                    expected_sha256=digest,
                ),
                str(executable.resolve()),
            )
            replacement = root / "claude-replacement"
            replacement.write_bytes(b"#!/bin/sh\nexit 1\n")
            replacement.chmod(0o700)
            link.unlink()
            link.symlink_to(replacement)
            with self.assertRaisesRegex(runner.RunnerError, "SHA-256 mismatch"):
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
