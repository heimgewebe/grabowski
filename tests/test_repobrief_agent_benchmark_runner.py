from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

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
    return {
        "kind": runner.REQUEST_KIND,
        "version": runner.VERSION,
        "request_id": f"task:case:r1:{condition}",
        "pair_id": "task:case:r1",
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
        "session_id": f"session:{condition}",
        "workspace_id": f"workspace:{condition}",
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
) -> bytes:
    tools = list(runner.READ_ONLY_BUILTINS)
    if request_value["condition"] == "treatment":
        tools.extend(runner.TREATMENT_RESOURCE_TOOLS)
        tools.extend(runner.TREATMENT_MCP_TOOLS)
    messages = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "provider-session",
            "model": model,
            "tools": tools,
        },
        {
            "type": "assistant",
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
                "session_id": "provider-session",
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cache_creation_input_tokens": 0,
                    "cache_read_input_tokens": 0,
                },
                "structured_output": answer(),
                "total_cost_usd": 0.01,
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


def repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "source"
    root.mkdir()
    git(["init"], root)
    git(["config", "user.email", "test@example.invalid"], root)
    git(["config", "user.name", "Test"], root)
    (root / "src").mkdir()
    (root / "src" / "example.py").write_text(
        "def example():\n    return True\n", encoding="utf-8"
    )
    git(["add", "."], root)
    git(["commit", "-m", "fixture"], root)
    return root, git(["rev-parse", "HEAD"], root)


def test_validate_request_accepts_both_conditions() -> None:
    runner.validate_request(request())
    runner.validate_request(request(condition="treatment"))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
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
            lambda value: value["runner"].update({"sampling": {"temperature": 0}}),
            "sampling",
        ),
        (
            lambda value: value["isolation"].update({"fresh_session": False}),
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
    ],
)
def test_validate_request_rejects_contract_drift(mutate, message: str) -> None:
    value = request()
    mutate(value)
    with pytest.raises(runner.RunnerError, match=message):
        runner.validate_request(value)


def test_treatment_requires_strict_repobrief_binding() -> None:
    value = request(condition="treatment")
    value["repobrief"]["manifest_sha256"] = "bad"
    with pytest.raises(runner.RunnerError, match="manifest_sha256"):
        runner.validate_request(value)


def test_build_baseline_command_exposes_only_read_tools() -> None:
    command = runner.build_claude_command(request(), claude="claude", mcp_config=None)
    joined = " ".join(command)
    assert "--bare" in command
    assert "stream-json" in command
    assert "--no-session-persistence" in command
    assert "Read,Glob,Grep" in command
    assert "mcp__" not in joined
    assert "Bash" not in joined
    assert "Write" not in joined
    assert "Edit" not in joined


def test_build_treatment_command_binds_only_repobrief_mcp(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text("{}", encoding="utf-8")
    command = runner.build_claude_command(
        request(condition="treatment"), claude="claude", mcp_config=config
    )
    joined = " ".join(command)
    assert "--strict-mcp-config" in command
    assert str(config) in command
    assert "ListMcpResources" in joined
    assert "ReadMcpResource" in joined
    assert "mcp__repobrief__ask_context" in joined
    assert "mcp__repobrief__grounding_verify" in joined
    assert "mcp__repobrief__live_freshness" in joined


def test_build_receipt_normalizes_provider_evidence() -> None:
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
    assert receipt["kind"] == runner.RECEIPT_KIND
    assert receipt["request_sha256"] == runner._sha256_json(value)
    assert receipt["provider"] == {
        "name": runner.PROVIDER,
        "model": MODEL,
        "sampling": {},
        "input_tokens": 120,
        "output_tokens": 30,
        "token_source": "provider_reported",
    }
    assert receipt["tool_calls"] == [
        {
            "sequence": 1,
            "name": "read_file",
            "status": "success",
            "duration_ms": 0,
            "input_bytes": len(
                runner._canonical_json({"file_path": "src/example.py"}).encode("utf-8")
            ),
            "output_bytes": len(
                runner._canonical_json("def example():\n    return True\n").encode("utf-8")
            ),
        }
    ]
    assert receipt["answer"] == answer()
    assert receipt["transcript"]["sha256"] == runner._sha256_bytes(raw)
    assert receipt["transcript"]["bytes"] == len(raw)


def test_treatment_maps_repobrief_tool() -> None:
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
    assert receipt["tool_calls"][0]["name"] == "ask_context"


@pytest.mark.parametrize(
    ("raw_builder", "message"),
    [
        (lambda value: stream(value, include_result=False), "requires one result"),
        (lambda value: stream(value, model="claude-other"), "model does not match"),
        (
            lambda value: stream(value, input_tokens=999999),
            "input token budget exceeded",
        ),
        (
            lambda value: stream(value, tool_name="Write"),
            "unapproved tool",
        ),
    ],
)
def test_provider_evidence_fails_closed(raw_builder, message: str) -> None:
    value = request()
    started = datetime.now(timezone.utc)
    with pytest.raises(runner.RunnerError, match=message):
        runner.build_receipt(
            value,
            raw_builder(value),
            transcript_artifact="transcript.jsonl",
            returncode=0,
            started_at=started,
            ended_at=started,
        )


def test_duplicate_tool_use_and_orphan_result_are_rejected() -> None:
    value = request()
    messages = runner.parse_jsonl(stream(value))
    assistant = next(item for item in messages if item["type"] == "assistant")
    assistant["message"]["content"].append(
        copy.deepcopy(assistant["message"]["content"][0])
    )
    with pytest.raises(runner.RunnerError, match="duplicate provider tool-use id"):
        runner.normalize_tool_calls(value, messages)

    messages = runner.parse_jsonl(stream(value))
    user = next(item for item in messages if item["type"] == "user")
    user["message"]["content"][0]["tool_use_id"] = "orphan"
    with pytest.raises(runner.RunnerError, match="no matching result"):
        runner.normalize_tool_calls(value, messages)


def test_failed_tool_is_retained_as_failed_call() -> None:
    value = request()
    messages = runner.parse_jsonl(stream(value, tool_error=True))
    calls = runner.normalize_tool_calls(value, messages)
    assert calls[0]["status"] == "failed"


def test_answer_rejects_unknown_claim_and_unsafe_citation() -> None:
    invalid = answer()
    invalid["claims"] = ["invented_claim"]
    with pytest.raises(runner.RunnerError, match="unknown labels"):
        runner.validate_answer(invalid)

    invalid = answer()
    invalid["citations"] = [{"path": "../secret", "start_line": 1, "end_line": 1}]
    with pytest.raises(runner.RunnerError, match="repository-relative"):
        runner.validate_answer(invalid)


def test_jsonl_rejects_empty_invalid_and_oversized_transcripts() -> None:
    with pytest.raises(runner.RunnerError, match="empty or oversized"):
        runner.parse_jsonl(b"")
    with pytest.raises(runner.RunnerError, match="invalid JSON"):
        runner.parse_jsonl(b"not-json\n")
    with pytest.raises(runner.RunnerError, match="empty or oversized"):
        runner.parse_jsonl(b"x" * (runner.MAX_TRANSCRIPT_BYTES + 1))


def test_create_isolated_checkout_is_exact_clean_and_create_only(tmp_path: Path) -> None:
    source, commit = repository(tmp_path)
    value = request(commit=commit)
    checkout = runner.create_isolated_checkout(value, source, tmp_path / "state")
    assert git(["rev-parse", "HEAD"], checkout) == commit
    assert git(["status", "--porcelain"], checkout) == ""
    with pytest.raises(runner.RunnerError, match="already used"):
        runner.create_isolated_checkout(value, source, tmp_path / "state")


def test_load_repository_root_binds_owner_name(tmp_path: Path) -> None:
    source, commit = repository(tmp_path)
    value = request(commit=commit)
    map_path = tmp_path / "repositories.json"
    map_path.write_text(
        json.dumps(
            {"repo": {"repository": "heimgewebe/repo", "root": str(source)}}
        ),
        encoding="utf-8",
    )
    assert runner.load_repository_root(value, map_path) == source.resolve()
    document = json.loads(map_path.read_text(encoding="utf-8"))
    document["repo"]["repository"] = "other/repo"
    map_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="owner/name mismatch"):
        runner.load_repository_root(value, map_path)


def test_execute_with_synthetic_stream_is_end_to_end(tmp_path: Path) -> None:
    source, commit = repository(tmp_path)
    value = request(commit=commit)
    map_path = tmp_path / "repositories.json"
    map_path.write_text(
        json.dumps(
            {"repo": {"repository": "heimgewebe/repo", "root": str(source)}}
        ),
        encoding="utf-8",
    )
    fixture = tmp_path / "stream.jsonl"
    fixture.write_bytes(stream(value))
    receipt = runner.execute(
        value,
        repository_map=map_path,
        state_root=tmp_path / "state",
        transcript_root=tmp_path / "transcripts",
        claude="claude",
        stream_fixture=fixture,
    )
    artifact = tmp_path / "transcripts" / receipt["transcript"]["artifact"]
    assert artifact.read_bytes() == fixture.read_bytes()
    assert receipt["status"] == "success"
    assert receipt["does_not_establish"] == list(runner.DOES_NOT_ESTABLISH)


def test_write_mcp_config_uses_request_argv(tmp_path: Path) -> None:
    value = request(condition="treatment")
    workspace = tmp_path / "workspace" / "repo"
    workspace.mkdir(parents=True)
    path = runner.write_mcp_config(value, workspace)
    document = json.loads(path.read_text(encoding="utf-8"))
    server = document["mcpServers"]["repobrief"]
    assert server["type"] == "stdio"
    assert server["command"] == "python"
    assert server["args"] == [
        "repobrief-mcp-stdio.py",
        "--bundle-root",
        "/bundles",
    ]
    assert path.stat().st_mode & 0o777 == 0o600


def test_run_bounded_rejects_timeout_and_output_limit(tmp_path: Path) -> None:
    script = tmp_path / "runner.py"
    script.write_text(
        "import sys, time\n"
        "if sys.argv[1] == 'sleep': time.sleep(2)\n"
        "else: print('x' * 1000)\n",
        encoding="utf-8",
    )
    with pytest.raises(runner.RunnerError, match="timed out"):
        runner.run_bounded(
            [sys.executable, str(script), "sleep"],
            cwd=tmp_path,
            timeout_seconds=1,
            stdout_limit=1024,
        )
    with pytest.raises(runner.RunnerError, match="stdout exceeds"):
        runner.run_bounded(
            [sys.executable, str(script), "output"],
            cwd=tmp_path,
            timeout_seconds=5,
            stdout_limit=32,
        )
