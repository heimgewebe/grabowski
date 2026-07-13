#!/usr/bin/env python3
"""Read-only Claude runner for RepoBrief Agent Benchmark v1.

The runner consumes one Lenskit benchmark request from stdin and emits one
Lenskit-compatible receipt to stdout. It is intentionally not an MCP tool and
has no apply, commit, merge, deploy, resume, or retry authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any

REQUEST_KIND = "repobrief.agent_benchmark_run_request"
RECEIPT_KIND = "repobrief.agent_benchmark_run_receipt"
VERSION = "1.0"
PROVIDER = "anthropic-claude-code"
MAX_REQUEST_BYTES = 1 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
MAX_TOOL_CALLS = 1000
READ_ONLY_BUILTINS = ("Read", "Glob", "Grep")
TREATMENT_RESOURCE_TOOLS = ("ListMcpResources", "ReadMcpResource")
TREATMENT_MCP_TOOLS = (
    "mcp__repobrief__ask_context",
    "mcp__repobrief__grounding_verify",
    "mcp__repobrief__live_freshness",
)
ABSTRACT_TOOL_MAP = {
    "Read": "read_file",
    "Glob": "glob",
    "Grep": "grep",
    "ListMcpResources": "repobrief_resource_read",
    "ReadMcpResource": "repobrief_resource_read",
    "mcp__repobrief__ask_context": "ask_context",
    "mcp__repobrief__grounding_verify": "grounding_verify",
    "mcp__repobrief__live_freshness": "live_freshness",
}
BASELINE_ABSTRACT = {"glob", "grep", "read_file", "search"}
TREATMENT_ABSTRACT = BASELINE_ABSTRACT | {
    "ask_context",
    "grounding_verify",
    "live_freshness",
    "repobrief_resource_read",
}
CLAIM_VOCABULARY = (
    "arbitrary_write_authority",
    "citation_invalid",
    "citation_not_verified",
    "complete_blast_radius",
    "complete_call_graph",
    "complete_call_graph_not_established",
    "complete_repository_understanding",
    "current_working_tree_is_dirty",
    "default_promoted_false",
    "freshness_not_established",
    "git_head_mismatch",
    "grounding_valid",
    "repo_root_not_configured",
    "read_only_default",
    "snapshot_fresh",
    "snapshot_git_provenance_unavailable",
    "snapshot_write_opt_in",
    "test_sufficiency_established",
    "test_sufficiency_not_established",
)
DOES_NOT_ESTABLISH = (
    "real_agent_usefulness",
    "answer_correctness_outside_fixed_expectations",
    "complete_repository_understanding",
    "test_sufficiency",
    "review_completeness",
    "merge_readiness",
    "default_promotion",
)
REQUEST_FIELDS = {
    "kind",
    "version",
    "request_id",
    "pair_id",
    "case_id",
    "condition",
    "order",
    "repetition",
    "taskset_id",
    "taskset_sha256",
    "repository",
    "session_id",
    "workspace_id",
    "prompt",
    "allowed_tools",
    "budgets",
    "runner",
    "repobrief",
    "isolation",
    "does_not_establish",
}
ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "text",
        "outcome",
        "reported_paths",
        "reported_symbols",
        "citations",
        "claims",
        "asserted_sufficient_evidence",
    ],
    "properties": {
        "text": {"type": "string", "maxLength": 20000},
        "outcome": {
            "enum": [
                "answer",
                "abstain",
                "stale",
                "not_comparable",
                "invalid_evidence",
            ]
        },
        "reported_paths": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "minLength": 1},
        },
        "reported_symbols": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "minLength": 1},
        },
        "citations": {
            "type": "array",
            "uniqueItems": True,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path", "start_line", "end_line"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                },
            },
        },
        "claims": {
            "type": "array",
            "uniqueItems": True,
            "items": {"type": "string", "enum": list(CLAIM_VOCABULARY)},
        },
        "asserted_sufficient_evidence": {"type": "boolean"},
    },
}


class RunnerError(ValueError):
    """The request, provider stream, or isolation contract is invalid."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _bounded_stdin(limit: int = MAX_REQUEST_BYTES) -> bytes:
    raw = sys.stdin.buffer.read(limit + 1)
    if len(raw) > limit:
        raise RunnerError(f"request exceeds {limit} bytes")
    if not raw.strip():
        raise RunnerError("request is empty")
    return raw


def _load_object_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"{label} is not one UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be one JSON object")
    return value


def _load_object(path: Path, *, limit: int = MAX_REQUEST_BYTES) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RunnerError(f"cannot read {path}") from exc
    if len(raw) > limit:
        raise RunnerError(f"{path} exceeds {limit} bytes")
    return _load_object_bytes(raw, label=str(path))


def _require_string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RunnerError(f"{label} must be a non-empty bounded string")
    return value


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RunnerError(f"{label} must be an integer >= {minimum}")
    return value


def _safe_identifier(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_hex(value: Any, label: str, *, length: int) -> str:
    text = _require_string(value, label, maximum=length)
    if len(text) != length or any(char not in "0123456789abcdef" for char in text):
        raise RunnerError(f"{label} must be {length} lowercase hex characters")
    return text


def validate_request(request: Mapping[str, Any]) -> None:
    unknown = set(request).difference(REQUEST_FIELDS)
    missing = REQUEST_FIELDS.difference(request)
    if unknown:
        raise RunnerError(f"request contains unknown fields: {sorted(unknown)!r}")
    if missing:
        raise RunnerError(f"request misses fields: {sorted(missing)!r}")
    if request.get("kind") != REQUEST_KIND or request.get("version") != VERSION:
        raise RunnerError("request kind/version mismatch")
    condition = request.get("condition")
    if condition not in {"baseline", "treatment"}:
        raise RunnerError("request condition is invalid")
    _require_string(request.get("request_id"), "request_id")
    _require_string(request.get("pair_id"), "pair_id")
    _require_string(request.get("case_id"), "case_id")
    _require_string(request.get("session_id"), "session_id")
    _require_string(request.get("workspace_id"), "workspace_id")
    _require_string(request.get("prompt"), "prompt", maximum=4000)
    _validate_hex(request.get("taskset_sha256"), "taskset_sha256", length=64)
    _require_int(request.get("order"), "order", minimum=1)
    _require_int(request.get("repetition"), "repetition", minimum=1)
    _validate_repository(request)
    _validate_runner(request)
    _validate_budgets(request)
    _validate_isolation(request)
    _validate_tool_policy(request)
    _validate_repobrief(request)


def _validate_repository(request: Mapping[str, Any]) -> None:
    repository = _mapping(request.get("repository"))
    if set(repository) != {"id", "repository", "commit"}:
        raise RunnerError("repository contract mismatch")
    _require_string(repository.get("id"), "repository.id")
    name = _require_string(repository.get("repository"), "repository.repository")
    if name.count("/") != 1:
        raise RunnerError("repository.repository must use owner/name")
    _validate_hex(repository.get("commit"), "repository.commit", length=40)


def _validate_runner(request: Mapping[str, Any]) -> None:
    runner = _mapping(request.get("runner"))
    if set(runner) != {"provider", "model", "sampling"}:
        raise RunnerError("runner contract mismatch")
    if runner.get("provider") != PROVIDER:
        raise RunnerError(f"runner.provider must be {PROVIDER}")
    model = _require_string(runner.get("model"), "runner.model", maximum=200)
    if not model.startswith("claude-"):
        raise RunnerError("runner.model must be an exact Claude model id")
    if _mapping(runner.get("sampling")) != {}:
        raise RunnerError("runner.sampling must be the explicit empty Claude CLI contract")


def _validate_budgets(request: Mapping[str, Any]) -> None:
    budgets = _mapping(request.get("budgets"))
    required = {
        "wall_seconds",
        "input_tokens",
        "output_tokens",
        "max_tool_calls",
        "max_tool_input_bytes",
        "max_tool_output_bytes",
    }
    if set(budgets) != required:
        raise RunnerError("budgets contract mismatch")
    wall = _require_int(budgets.get("wall_seconds"), "wall_seconds", minimum=1)
    if wall > 3600:
        raise RunnerError("wall_seconds exceeds runner limit")
    _require_int(budgets.get("input_tokens"), "input_tokens", minimum=1)
    _require_int(budgets.get("output_tokens"), "output_tokens", minimum=1)
    calls = _require_int(budgets.get("max_tool_calls"), "max_tool_calls", minimum=1)
    if calls > MAX_TOOL_CALLS:
        raise RunnerError("max_tool_calls exceeds runner limit")
    _require_int(budgets.get("max_tool_input_bytes"), "max_tool_input_bytes", minimum=1)
    _require_int(budgets.get("max_tool_output_bytes"), "max_tool_output_bytes", minimum=1)


def _validate_isolation(request: Mapping[str, Any]) -> None:
    expected = {
        "fresh_session": True,
        "fresh_workspace": True,
        "cross_condition_reuse_allowed": False,
    }
    if dict(_mapping(request.get("isolation"))) != expected:
        raise RunnerError("request isolation contract mismatch")


def _validate_tool_policy(request: Mapping[str, Any]) -> None:
    actual = set(_list(request.get("allowed_tools")))
    expected = BASELINE_ABSTRACT if request.get("condition") == "baseline" else TREATMENT_ABSTRACT
    if actual != expected:
        raise RunnerError("request allowed_tools do not match benchmark condition")


def _validate_repobrief(request: Mapping[str, Any]) -> None:
    condition = request.get("condition")
    value = request.get("repobrief")
    if condition == "baseline":
        if value is not None:
            raise RunnerError("baseline request must not contain RepoBrief binding")
        return
    binding = _mapping(value)
    if set(binding) != {"manifest", "manifest_sha256", "mcp_command"}:
        raise RunnerError("treatment RepoBrief binding mismatch")
    _require_string(binding.get("manifest"), "repobrief.manifest")
    _validate_hex(binding.get("manifest_sha256"), "repobrief.manifest_sha256", length=64)
    command = _list(binding.get("mcp_command"))
    if not command or any(not isinstance(item, str) or not item for item in command):
        raise RunnerError("repobrief.mcp_command must be a non-empty argv array")


def load_repository_root(request: Mapping[str, Any], map_path: Path) -> Path:
    document = _load_object(map_path)
    repository = _mapping(request.get("repository"))
    repository_id = str(repository.get("id"))
    entry = _mapping(document.get(repository_id))
    if set(entry) != {"repository", "root"}:
        raise RunnerError(f"repository map misses strict entry for {repository_id}")
    if entry.get("repository") != repository.get("repository"):
        raise RunnerError("repository map owner/name mismatch")
    root = Path(_require_string(entry.get("root"), "repository map root")).expanduser().resolve()
    if not root.is_dir() or not (root / ".git").exists():
        raise RunnerError("repository map root is not a Git checkout")
    return root


def _git_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def _run_checked(command: Sequence[str], *, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RunnerError(f"command failed: {command[0]}") from exc
    return completed.stdout.strip()


def create_isolated_checkout(
    request: Mapping[str, Any], source: Path, state_root: Path
) -> Path:
    workspace_id = _require_string(request.get("workspace_id"), "workspace_id")
    workspace = state_root.resolve() / "workspaces" / _safe_identifier(workspace_id)
    workspace.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        workspace.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise RunnerError("workspace identity was already used") from exc
    checkout = workspace / "repo"
    commit = str(_mapping(request.get("repository")).get("commit"))
    _run_checked(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(source),
            str(checkout),
        ]
    )
    _run_checked(
        ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--detach", commit],
        cwd=checkout,
    )
    head = _run_checked(["git", "rev-parse", "HEAD"], cwd=checkout)
    if head != commit:
        raise RunnerError("isolated checkout HEAD mismatch")
    if _run_checked(["git", "status", "--porcelain"], cwd=checkout):
        raise RunnerError("isolated checkout is not clean")
    return checkout


def _write_private_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def write_mcp_config(request: Mapping[str, Any], workspace: Path) -> Path:
    binding = _mapping(request.get("repobrief"))
    command = [str(item) for item in _list(binding.get("mcp_command"))]
    document = {
        "mcpServers": {
            "repobrief": {
                "type": "stdio",
                "command": command[0],
                "args": command[1:],
            }
        }
    }
    path = workspace.parent / "repobrief-mcp.json"
    _write_private_exclusive(
        path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    return path


def _prompt(request: Mapping[str, Any]) -> str:
    vocabulary = ", ".join(CLAIM_VOCABULARY)
    return (
        f"{request['prompt']}\n\n"
        "Work read-only. Use only the exposed tools. Return the final answer through "
        "the required structured-output schema. Paths must be repository-relative. "
        "Citations must use exact inclusive line ranges. Use only these machine claim "
        f"labels when supported: {vocabulary}. Do not guess missing evidence."
    )


def build_claude_command(
    request: Mapping[str, Any], *, claude: str, mcp_config: Path | None
) -> list[str]:
    condition = str(request.get("condition"))
    tools = list(READ_ONLY_BUILTINS)
    allowed = list(READ_ONLY_BUILTINS)
    command = [
        claude,
        "--bare",
        "-p",
        _prompt(request),
        "--model",
        str(_mapping(request.get("runner")).get("model")),
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-partial-messages",
        "--no-session-persistence",
        "--permission-mode",
        "dontAsk",
        "--json-schema",
        _canonical_json(ANSWER_SCHEMA),
    ]
    if condition == "treatment":
        if mcp_config is None:
            raise RunnerError("treatment command requires MCP config")
        tools.extend(TREATMENT_RESOURCE_TOOLS)
        allowed.extend(TREATMENT_RESOURCE_TOOLS)
        allowed.extend(TREATMENT_MCP_TOOLS)
        command.extend(
            [
                "--strict-mcp-config",
                "--mcp-config",
                str(mcp_config),
            ]
        )
    command.extend(["--tools", ",".join(tools), "--allowedTools", ",".join(allowed)])
    return command


def _provider_environment() -> dict[str, str]:
    allowed = {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "ANTHROPIC_API_KEY",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    stdout_limit: int = MAX_TRANSCRIPT_BYTES,
    stderr_limit: int = MAX_STDERR_BYTES,
) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_provider_environment(),
        )
    except OSError as exc:
        raise RunnerError("Claude process could not be started") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise RunnerError("Claude process pipes are unavailable")
    selector = selectors.DefaultSelector()
    for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise RunnerError("Claude process timed out")
            for key, _mask in selector.select(timeout=min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                label = str(key.data)
                buffers[label].extend(chunk)
                if len(buffers[label]) > limits[label]:
                    process.kill()
                    process.wait()
                    raise RunnerError(f"Claude {label} exceeds configured limit")
            if process.poll() is not None and not selector.get_map():
                break
        returncode = process.wait(timeout=5)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def parse_jsonl(raw: bytes) -> list[dict[str, Any]]:
    if not raw or len(raw) > MAX_TRANSCRIPT_BYTES:
        raise RunnerError("provider transcript is empty or oversized")
    messages: list[dict[str, Any]] = []
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError(f"provider transcript line {number} is invalid JSON") from exc
        if not isinstance(value, dict):
            raise RunnerError(f"provider transcript line {number} is not an object")
        messages.append(value)
    if not messages:
        raise RunnerError("provider transcript contains no messages")
    return messages


def _single_message(
    messages: Sequence[Mapping[str, Any]], *, message_type: str, subtype: str | None = None
) -> Mapping[str, Any]:
    matches = [
        item
        for item in messages
        if item.get("type") == message_type
        and (subtype is None or item.get("subtype") == subtype)
    ]
    if len(matches) != 1:
        raise RunnerError(
            f"provider transcript requires one {message_type}/{subtype or '*'} message"
        )
    return matches[0]


def _validate_init(request: Mapping[str, Any], init: Mapping[str, Any]) -> str:
    model = _require_string(init.get("model"), "provider init model", maximum=200)
    expected = str(_mapping(request.get("runner")).get("model"))
    if model != expected:
        raise RunnerError("provider model does not match request")
    available = set(_list(init.get("tools")))
    required = set(READ_ONLY_BUILTINS)
    allowed = set(required)
    if request.get("condition") == "treatment":
        treatment_tools = set(TREATMENT_RESOURCE_TOOLS) | set(TREATMENT_MCP_TOOLS)
        required.update(treatment_tools)
        allowed.update(treatment_tools)
    unknown = available.difference(allowed)
    if unknown:
        raise RunnerError(f"provider exposed unapproved tools: {sorted(unknown)!r}")
    missing = required.difference(available)
    if missing:
        raise RunnerError(
            f"provider did not expose all required tools: {sorted(missing)!r}"
        )
    return model


def _validate_provider_session(
    init: Mapping[str, Any], result: Mapping[str, Any]
) -> None:
    init_session = _require_string(
        init.get("session_id"), "provider init session", maximum=300
    )
    result_session = _require_string(
        result.get("session_id"), "provider result session", maximum=300
    )
    if init_session != result_session:
        raise RunnerError("provider result session does not match init session")


def _usage(request: Mapping[str, Any], result: Mapping[str, Any]) -> tuple[int, int]:
    usage = _mapping(result.get("usage"))
    input_tokens = _require_int(usage.get("input_tokens"), "usage.input_tokens")
    output_tokens = _require_int(usage.get("output_tokens"), "usage.output_tokens")
    budgets = _mapping(request.get("budgets"))
    if input_tokens > int(budgets.get("input_tokens", -1)):
        raise RunnerError("provider input token budget exceeded")
    if output_tokens > int(budgets.get("output_tokens", -1)):
        raise RunnerError("provider output token budget exceeded")
    return input_tokens, output_tokens


def _tool_blocks(messages: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    uses: list[dict[str, Any]] = []
    results: dict[str, dict[str, Any]] = {}
    seen_use_ids: set[str] = set()
    for message in messages:
        nested = _mapping(message.get("message"))
        for raw_block in _list(nested.get("content")):
            block = _mapping(raw_block)
            block_type = block.get("type")
            if block_type == "tool_use":
                identifier = _require_string(block.get("id"), "tool_use.id", maximum=200)
                if identifier in seen_use_ids:
                    raise RunnerError("duplicate provider tool-use id")
                seen_use_ids.add(identifier)
                uses.append(dict(block))
            elif block_type == "tool_result":
                identifier = _require_string(
                    block.get("tool_use_id"), "tool_result.tool_use_id", maximum=200
                )
                if identifier in results:
                    raise RunnerError("duplicate provider tool-result id")
                results[identifier] = dict(block)
    return uses, results


def normalize_tool_calls(
    request: Mapping[str, Any], messages: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    uses, results = _tool_blocks(messages)
    budgets = _mapping(request.get("budgets"))
    if len(uses) > int(budgets.get("max_tool_calls", -1)):
        raise RunnerError("provider tool-call budget exceeded")
    calls: list[dict[str, Any]] = []
    total_input = 0
    total_output = 0
    for sequence, use in enumerate(uses, start=1):
        identifier = str(use.get("id"))
        result = results.get(identifier)
        if result is None:
            raise RunnerError("provider tool use has no matching result")
        concrete = _require_string(use.get("name"), "tool_use.name", maximum=300)
        abstract = ABSTRACT_TOOL_MAP.get(concrete)
        if abstract is None or abstract not in set(_list(request.get("allowed_tools"))):
            raise RunnerError(f"provider used unapproved tool: {concrete}")
        input_bytes = len(_canonical_json(use.get("input")).encode("utf-8"))
        output_bytes = len(_canonical_json(result.get("content")).encode("utf-8"))
        total_input += input_bytes
        total_output += output_bytes
        calls.append(
            {
                "sequence": sequence,
                "name": abstract,
                "status": "failed" if result.get("is_error") is True else "success",
                "duration_ms": 0,
                "input_bytes": input_bytes,
                "output_bytes": output_bytes,
            }
        )
    extra_results = set(results).difference(str(item.get("id")) for item in uses)
    if extra_results:
        raise RunnerError("provider transcript contains orphan tool results")
    if total_input > int(budgets.get("max_tool_input_bytes", -1)):
        raise RunnerError("provider tool-input byte budget exceeded")
    if total_output > int(budgets.get("max_tool_output_bytes", -1)):
        raise RunnerError("provider tool-output byte budget exceeded")
    return calls


def validate_answer(value: Any) -> dict[str, Any]:
    answer = _mapping(value)
    required = set(ANSWER_SCHEMA["required"])
    if set(answer) != required:
        raise RunnerError("provider structured output fields mismatch")
    text = _require_string(answer.get("text"), "answer.text", maximum=20000)
    outcome = answer.get("outcome")
    allowed_outcomes = set(ANSWER_SCHEMA["properties"]["outcome"]["enum"])
    if outcome not in allowed_outcomes:
        raise RunnerError("answer.outcome is invalid")
    paths = _unique_strings(answer.get("reported_paths"), "reported_paths")
    symbols = _unique_strings(answer.get("reported_symbols"), "reported_symbols")
    claims = _unique_strings(answer.get("claims"), "claims")
    if not set(claims).issubset(CLAIM_VOCABULARY):
        raise RunnerError("answer.claims contain unknown labels")
    citations = _citations(answer.get("citations"))
    sufficient = answer.get("asserted_sufficient_evidence")
    if not isinstance(sufficient, bool):
        raise RunnerError("answer.asserted_sufficient_evidence must be boolean")
    return {
        "text": text,
        "outcome": outcome,
        "reported_paths": paths,
        "reported_symbols": symbols,
        "citations": citations,
        "claims": claims,
        "asserted_sufficient_evidence": sufficient,
    }


def _unique_strings(value: Any, label: str) -> list[str]:
    items = _list(value)
    if any(not isinstance(item, str) or not item for item in items):
        raise RunnerError(f"answer.{label} must contain non-empty strings")
    if len(set(items)) != len(items):
        raise RunnerError(f"answer.{label} contains duplicates")
    return [str(item) for item in items]


def _citations(value: Any) -> list[dict[str, Any]]:
    citations: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for raw in _list(value):
        item = _mapping(raw)
        if set(item) != {"path", "start_line", "end_line"}:
            raise RunnerError("answer citation fields mismatch")
        path = _require_string(item.get("path"), "citation.path")
        if path.startswith("/") or ".." in Path(path).parts or "\\" in path:
            raise RunnerError("citation path must be repository-relative")
        start = _require_int(item.get("start_line"), "citation.start_line", minimum=1)
        end = _require_int(item.get("end_line"), "citation.end_line", minimum=1)
        if end < start:
            raise RunnerError("citation range is reversed")
        key = (path, start, end)
        if key in seen:
            raise RunnerError("answer citations contain duplicates")
        seen.add(key)
        citations.append({"path": path, "start_line": start, "end_line": end})
    return citations


def build_receipt(
    request: Mapping[str, Any],
    transcript: bytes,
    *,
    transcript_artifact: str,
    returncode: int,
    started_at: datetime,
    ended_at: datetime,
) -> dict[str, Any]:
    messages = parse_jsonl(transcript)
    init = _single_message(messages, message_type="system", subtype="init")
    result = _single_message(messages, message_type="result")
    model = _validate_init(request, init)
    _validate_provider_session(init, result)
    input_tokens, output_tokens = _usage(request, result)
    if returncode != 0 or result.get("is_error") is True or result.get("subtype") != "success":
        raise RunnerError("provider did not produce a successful result")
    answer = validate_answer(result.get("structured_output"))
    calls = normalize_tool_calls(request, messages)
    elapsed = max(int((ended_at - started_at).total_seconds() * 1000), 0)
    wall_limit = int(_mapping(request.get("budgets")).get("wall_seconds", 0)) * 1000
    if elapsed > wall_limit:
        raise RunnerError("provider elapsed time exceeds request budget")
    return {
        "kind": RECEIPT_KIND,
        "version": VERSION,
        "request_id": request["request_id"],
        "request_sha256": _sha256_json(request),
        "status": "success",
        "provider": {
            "name": PROVIDER,
            "model": model,
            "sampling": {},
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "token_source": "provider_reported",
        },
        "started_at": _iso(started_at),
        "ended_at": _iso(ended_at),
        "duration_ms": elapsed,
        "exit_code": returncode,
        "tool_calls": calls,
        "answer": answer,
        "transcript": {
            "storage": "artifact",
            "sha256": _sha256_bytes(transcript),
            "bytes": len(transcript),
            "inline": None,
            "artifact": transcript_artifact,
        },
        "error": None,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }


def _transcript_path(request: Mapping[str, Any], transcript_root: Path) -> tuple[Path, str]:
    filename = f"{_safe_identifier(str(request['request_id']))}.jsonl"
    return transcript_root.resolve() / filename, filename


def execute(
    request: Mapping[str, Any],
    *,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    claude: str,
    stream_fixture: Path | None = None,
) -> dict[str, Any]:
    validate_request(request)
    source = load_repository_root(request, repository_map)
    checkout = create_isolated_checkout(request, source, state_root)
    mcp_config = (
        write_mcp_config(request, checkout)
        if request.get("condition") == "treatment"
        else None
    )
    started = _utc_now()
    if stream_fixture is None:
        command = build_claude_command(request, claude=claude, mcp_config=mcp_config)
        returncode, stdout, stderr = run_bounded(
            command,
            cwd=checkout,
            timeout_seconds=int(_mapping(request.get("budgets")).get("wall_seconds")),
        )
        if stderr:
            raise RunnerError(
                f"Claude stderr is non-empty: {_sha256_bytes(stderr)} ({len(stderr)} bytes)"
            )
    else:
        stdout = stream_fixture.read_bytes()
        returncode = 0
    ended = _utc_now()
    transcript_path, artifact = _transcript_path(request, transcript_root)
    _write_private_exclusive(transcript_path, stdout)
    return build_receipt(
        request,
        stdout,
        transcript_artifact=artifact,
        returncode=returncode,
        started_at=started,
        ended_at=ended,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one isolated read-only RepoBrief agent benchmark request."
    )
    parser.add_argument("--repository-map", required=True, type=Path)
    parser.add_argument("--state-root", required=True, type=Path)
    parser.add_argument("--transcript-root", required=True, type=Path)
    parser.add_argument("--claude-command", default="claude")
    parser.add_argument(
        "--stream-fixture",
        type=Path,
        help="Synthetic JSONL provider stream for contract tests; never proves live availability.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        request = _load_object_bytes(_bounded_stdin(), label="stdin request")
        receipt = execute(
            request,
            repository_map=args.repository_map,
            state_root=args.state_root,
            transcript_root=args.transcript_root,
            claude=args.claude_command,
            stream_fixture=args.stream_fixture,
        )
    except RunnerError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    json.dump(receipt, sys.stdout, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
