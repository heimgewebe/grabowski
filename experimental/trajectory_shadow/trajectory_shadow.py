#!/usr/bin/env python3
"""Read-only post-hoc trajectory shadow pilot for Grabowski.

This module is intentionally experimental. It does not define a public runtime
contract and does not intervene in live work. It reads local Work Lane receipts
and provider session logs, normalizes only bounded action metadata, and emits
sanitized traces plus aggregate detector evidence.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from typing import Any, Iterable

SCHEMA_VERSION = 2
DETECTORS = (
    "repeated_failure_without_state_delta",
    "verification_gap",
    "mutation_without_evidenced_localization",
    "action_oscillation_without_progress",
)
SUCCESS_CLOSEOUTS = {
    "pr_merged",
    "pr_opened",
    "pr_updated",
    "deployed",
    "no_change_proven",
}
VERIFY_DIRECT_EXES = {"pytest", "tox", "nox", "mypy", "pyright"}
SHELL_CONTROL_TOKENS = {"&&", "||", ";", "|"}
READ_EXES = {"cat", "sed", "head", "tail", "less", "git"}
SEARCH_EXES = {"rg", "grep"}
DISCOVER_EXES = {"find", "fd", "ls"}
MUTATE_EXES = {"cp", "mv", "rm", "install", "touch", "patch"}
CONTEXT_TOOL_MARKERS = ("repoground", "reposkop", "context_compose", "find_symbol", "get_callers")
CODEX_SHELL_NAMES = {"exec", "exec_command", "shell", "local_shell", "local_shell_call"}
CODEX_PROCESS_EXIT_RE = re.compile(r"(?m)^Process exited with code (-?\d+)\s*$")


def _hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()


def _parse_time(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        return dt.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _repo_relative(raw: Any, cwd: str) -> str | None:
    if not isinstance(raw, str) or not raw or "\\x00" in raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    try:
        rel = os.path.relpath(os.path.normpath(str(candidate)), os.path.normpath(cwd))
    except (TypeError, ValueError):
        return None
    if rel == ".":
        return "."
    if rel == ".." or rel.startswith("../"):
        return None
    return rel


def _safe_target_from_tokens(command: str, cwd: str) -> str | None:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    for token in reversed(tokens[1:]):
        if not token or token.startswith("-") or token in {"|", "&&", "||", ";"}:
            continue
        if token.startswith(("http://", "https://")):
            continue
        rel = _repo_relative(token, cwd)
        if rel is not None and rel != ".":
            return rel
    return None


def _is_shell_assignment(token: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token) is not None


def _is_verification_segment(tokens: list[str]) -> bool:
    segment = list(tokens)
    while segment and _is_shell_assignment(segment[0]):
        segment.pop(0)
    if not segment:
        return False

    exe = os.path.basename(segment[0])
    if exe == "env":
        value_options = {"-a", "--argv0", "-C", "--chdir", "-u", "--unset"}
        index = 1
        while index < len(segment):
            token = segment[index]
            if token == "--":
                index += 1
                break
            if _is_shell_assignment(token):
                index += 1
                continue
            if token in value_options:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            break
        return _is_verification_segment(segment[index:])
    if exe == "timeout":
        value_options = {"-k", "--kill-after", "-s", "--signal"}
        index = 1
        while index < len(segment):
            token = segment[index]
            if token == "--":
                index += 1
                break
            if token in value_options:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            break
        if index < len(segment):
            index += 1  # duration
        return _is_verification_segment(segment[index:])
    if exe in {"bash", "sh", "zsh"}:
        for index, token in enumerate(segment[1:], start=1):
            if token in {"-c", "-lc"} and index + 1 < len(segment):
                try:
                    nested = shlex.split(segment[index + 1], posix=True)
                except ValueError:
                    return False
                return _is_verification_command(nested)
        return False

    if exe in VERIFY_DIRECT_EXES:
        return True
    if exe == "ruff":
        return len(segment) > 1 and segment[1] == "check"
    if exe in {"python", "python3"}:
        for index, token in enumerate(segment[1:], start=1):
            if token == "-m" and index + 1 < len(segment):
                module = segment[index + 1]
                return module in {"pytest", "unittest", "ruff", "mypy", "pyright"}
        return False
    if exe == "uv":
        if len(segment) < 3 or segment[1] != "run":
            return False
        nested = segment[2:]
        while nested and nested[0].startswith("-"):
            nested = nested[1:]
        return _is_verification_segment(nested)
    if exe in {"cargo", "go"}:
        return len(segment) > 1 and segment[1] == "test"
    if exe in {"npm", "pnpm", "yarn"}:
        if len(segment) > 1 and segment[1] == "test":
            return True
        return len(segment) > 2 and segment[1] == "run" and segment[2] == "test"
    if exe == "make":
        return any(token in {"test", "check", "validate", "deploy-check"} for token in segment[1:] if not token.startswith("-"))
    return False


def _is_verification_command(tokens: list[str]) -> bool:
    # A successful `a || verify` can skip verification entirely, while
    # `verify || fallback` can mask a failed verification.  Without full shell
    # control-flow evaluation, either form is unsafe evidence of verification.
    if "||" in tokens:
        return False

    segments: list[list[str]] = []
    separators: list[str] = []
    segment: list[str] = []
    for token in tokens:
        if token in SHELL_CONTROL_TOKENS:
            segments.append(segment)
            separators.append(token)
            segment = []
        else:
            segment.append(token)
    segments.append(segment)

    for index, candidate in enumerate(segments):
        if not _is_verification_segment(candidate):
            continue
        # `;` and `|` after verification can replace/mask its exit status.
        # `&&` preserves the invariant that overall success implies the
        # verification segment ran and succeeded.
        if all(separator == "&&" for separator in separators[index:]):
            return True
    return False


def _classify_shell(command: str, cwd: str) -> tuple[str, str | None, str]:
    normalized = " ".join(command.strip().split())
    lowered = normalized.lower()
    fingerprint = _hash({"command": normalized})
    try:
        tokens = shlex.split(normalized, posix=True)
    except ValueError:
        return "execute", None, fingerprint
    if not tokens:
        return "execute", None, fingerprint
    if _is_verification_command(tokens):
        return "verify", _safe_target_from_tokens(normalized, cwd), fingerprint
    exe = os.path.basename(tokens[0])
    if exe in SEARCH_EXES:
        return "search", _safe_target_from_tokens(normalized, cwd), fingerprint
    if exe in DISCOVER_EXES:
        return "discover", _safe_target_from_tokens(normalized, cwd), fingerprint
    if exe in READ_EXES:
        if exe == "git" and len(tokens) > 1 and tokens[1] in {"add", "commit", "merge", "rebase", "reset", "checkout", "switch", "cherry-pick"}:
            return "mutate", None, fingerprint
        return "read", _safe_target_from_tokens(normalized, cwd), fingerprint
    if exe in MUTATE_EXES or "sed -i" in lowered or re.search(r"(?:^|\\s)(?:tee|truncate)\\s", lowered):
        return "mutate", _safe_target_from_tokens(normalized, cwd), fingerprint
    return "execute", _safe_target_from_tokens(normalized, cwd), fingerprint


def _exit_code(value: Any) -> int | None:
    if isinstance(value, dict):
        for key in ("returncode", "return_code", "exitCode", "exit_code"):
            code = value.get(key)
            if isinstance(code, int) and not isinstance(code, bool):
                return code
        for nested in value.values():
            code = _exit_code(nested)
            if code is not None:
                return code
    if isinstance(value, list):
        for nested in value:
            code = _exit_code(nested)
            if code is not None:
                return code
    return None


def _result_fingerprint(value: Any) -> str:
    # Raw tool output is consumed only transiently to derive a digest.
    return _hash({"tool_result": value})


@dataclasses.dataclass
class Event:
    sequence: int
    timestamp: float | None
    actor: str
    operation: str
    target_kind: str | None
    target: str | None
    outcome: str
    action_fingerprint: str
    result_fingerprint: str | None
    source_adapter: str
    evidence_ref: str
    attribution: str = "exact"
    confidence: float = 1.0
    mutation_from: str | None = None
    mutation_to: str | None = None
    state_epoch: int = 0

    def sanitized(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Lane:
    lane_id: str
    target_path: str
    branch: str | None
    base_head: str | None
    repo: str | None
    source_kind: str | None
    source_id: str | None
    state: str | None
    created_at: float | None
    updated_at: float | None
    closeout_state: str | None
    baseline_observed_at: float | None
    baseline_reason_codes: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Session:
    adapter: str
    path: Path
    session_id: str
    cwd: str
    branch: str | None
    base_commit: str | None
    tool_actions: int
    first_at: float | None
    last_at: float | None


def load_lanes(root: Path) -> list[Lane]:
    lanes: list[Lane] = []
    for path in root.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        inputs = data.get("inputs")
        if not isinstance(inputs, dict):
            continue
        target = inputs.get("target_path")
        lane_id = data.get("lane_id")
        if not isinstance(target, str) or not isinstance(lane_id, str):
            continue
        source = inputs.get("source") if isinstance(inputs.get("source"), dict) else {}
        terminal = data.get("terminal_closeout") if isinstance(data.get("terminal_closeout"), dict) else {}
        assessment = terminal.get("assessment") if isinstance(terminal.get("assessment"), dict) else {}
        reasons = tuple(str(item) for item in (assessment.get("reason_codes") or []) if isinstance(item, str))
        lanes.append(
            Lane(
                lane_id=lane_id,
                target_path=target,
                branch=inputs.get("branch") if isinstance(inputs.get("branch"), str) else None,
                base_head=inputs.get("base_head") if isinstance(inputs.get("base_head"), str) else None,
                repo=inputs.get("repo") if isinstance(inputs.get("repo"), str) else None,
                source_kind=source.get("kind") if isinstance(source.get("kind"), str) else None,
                source_id=source.get("id") if isinstance(source.get("id"), str) else None,
                state=data.get("state") if isinstance(data.get("state"), str) else None,
                created_at=_parse_time(data.get("created_at_unix")),
                updated_at=_parse_time(data.get("updated_at_unix")),
                closeout_state=assessment.get("closeout_state") if isinstance(assessment.get("closeout_state"), str) else None,
                baseline_observed_at=_parse_time(assessment.get("observed_at_unix")),
                baseline_reason_codes=reasons,
            )
        )
    return lanes


def index_claude(root: Path) -> list[Session]:
    sessions: list[Session] = []
    for path in root.glob("**/*.jsonl"):
        cwd = sid = branch = None
        first = last = None
        tool_actions = 0
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for raw in handle:
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if cwd is None and isinstance(row.get("cwd"), str):
                    cwd = row["cwd"]
                if sid is None and isinstance(row.get("sessionId"), str):
                    sid = row["sessionId"]
                if branch is None and isinstance(row.get("gitBranch"), str):
                    branch = row["gitBranch"]
                stamp = _parse_time(row.get("timestamp"))
                if stamp is not None:
                    first = stamp if first is None else min(first, stamp)
                    last = stamp if last is None else max(last, stamp)
                message = row.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), list):
                    tool_actions += sum(
                        1
                        for item in message["content"]
                        if isinstance(item, dict) and item.get("type") == "tool_use"
                    )
        if cwd:
            sessions.append(Session("claude", path, sid or _hash(str(path))[:16], cwd, branch, None, tool_actions, first, last))
    return sessions


def index_codex(root: Path) -> list[Session]:
    sessions: list[Session] = []
    for path in root.glob("**/*.jsonl"):
        cwd = sid = branch = commit = None
        first = last = None
        tool_actions = 0
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for raw in handle:
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                stamp = _parse_time(row.get("timestamp"))
                if stamp is not None:
                    first = stamp if first is None else min(first, stamp)
                    last = stamp if last is None else max(last, stamp)
                payload = row.get("payload")
                if row.get("type") == "session_meta" and isinstance(payload, dict):
                    if isinstance(payload.get("cwd"), str):
                        cwd = payload["cwd"]
                    if isinstance(payload.get("id"), str):
                        sid = payload["id"]
                    git = payload.get("git")
                    if isinstance(git, dict):
                        if isinstance(git.get("branch"), str):
                            branch = git["branch"]
                        if isinstance(git.get("commit_hash"), str):
                            commit = git["commit_hash"]
                if (
                    row.get("type") == "response_item"
                    and isinstance(payload, dict)
                    and payload.get("type") in {"custom_tool_call", "function_call", "local_shell_call"}
                ):
                    tool_actions += 1
        if cwd:
            sessions.append(Session("codex", path, sid or _hash(str(path))[:16], cwd, branch, commit, tool_actions, first, last))
    return sessions


def exact_attributions(
    lanes: Iterable[Lane],
    sessions: Iterable[Session],
) -> dict[str, tuple[Lane, list[tuple[Session, tuple[str, ...]]]]]:
    by_target: dict[str, list[Lane]] = collections.defaultdict(list)
    for lane in lanes:
        by_target[lane.target_path].append(lane)
    grouped: dict[str, tuple[Lane, list[tuple[Session, tuple[str, ...]]]]] = {}
    for session in sessions:
        candidates = by_target.get(session.cwd, [])
        if len(candidates) != 1:
            continue
        lane = candidates[0]
        if session.base_commit and lane.base_head and session.base_commit != lane.base_head:
            continue
        reinforcement: list[str] = []
        if session.branch and lane.branch and session.branch == lane.branch:
            reinforcement.append("branch")
        if session.base_commit and lane.base_head and session.base_commit == lane.base_head:
            reinforcement.append("base_revision")
        if not reinforcement:
            continue
        if lane.lane_id not in grouped:
            grouped[lane.lane_id] = (lane, [])
        grouped[lane.lane_id][1].append((session, tuple(reinforcement)))
    for _, bindings in grouped.values():
        bindings.sort(key=lambda item: (item[0].first_at is None, item[0].first_at or 0, str(item[0].path)))
    return grouped


def _event_from_claude_tool(
    sequence: int,
    timestamp: float | None,
    tool: dict[str, Any],
    cwd: str,
    session_id: str,
) -> Event:
    name = str(tool.get("name") or "unknown")
    payload = tool.get("input") if isinstance(tool.get("input"), dict) else {}
    target = None
    operation = "execute"
    target_kind = None
    mutation_from = mutation_to = None
    if name == "Read":
        target = _repo_relative(payload.get("file_path"), cwd)
        if target is not None:
            operation, target_kind = "read", "file"
    elif name in {"Grep", "Glob"}:
        raw_path = payload.get("path")
        if raw_path is None:
            target = "."
        else:
            target = _repo_relative(raw_path, cwd)
        if target is not None:
            operation = "search" if name == "Grep" else "discover"
            target_kind = "path"
    elif name in {"Edit", "Write"}:
        target = _repo_relative(payload.get("file_path"), cwd)
        if target is not None:
            operation, target_kind = "edit", "file"
            if name == "Edit":
                if isinstance(payload.get("old_string"), str):
                    mutation_from = _hash(payload["old_string"])
                if isinstance(payload.get("new_string"), str):
                    mutation_to = _hash(payload["new_string"])
    elif name == "Bash":
        command = payload.get("command") if isinstance(payload.get("command"), str) else ""
        operation, target, command_hash = _classify_shell(command, cwd)
        target_kind = "path" if target is not None else None
        return Event(
            sequence,
            timestamp,
            "writer",
            operation,
            target_kind,
            target,
            "unknown",
            _hash({"tool": name, "command": command_hash, "target": target}),
            None,
            "claude",
            f"session:{_hash(session_id)[:16]}#{sequence}",
            mutation_from=mutation_from,
            mutation_to=mutation_to,
        )
    elif any(marker in name.lower() for marker in CONTEXT_TOOL_MARKERS):
        operation, target_kind, target = "context", "repository", "."
    elif name in {"ToolSearch"}:
        operation, target_kind, target = "discover", "tool", None
    action_payload = {"tool": name, "operation": operation, "target": target}
    if mutation_from or mutation_to:
        action_payload["mutation_from"] = mutation_from
        action_payload["mutation_to"] = mutation_to
    return Event(
        sequence,
        timestamp,
        "writer",
        operation,
        target_kind,
        target,
        "unknown",
        _hash(action_payload),
        None,
        "claude",
        f"session:{_hash(session_id)[:16]}#{sequence}",
        mutation_from=mutation_from,
        mutation_to=mutation_to,
    )


def extract_claude(session: Session) -> list[Event]:
    events: list[Event] = []
    pending: dict[str, int] = {}
    sequence = 0
    try:
        handle = session.path.open(encoding="utf-8", errors="replace")
    except OSError:
        return events
    with handle:
        for raw in handle:
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            stamp = _parse_time(row.get("timestamp"))
            message = row.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                continue
            for item in message["content"]:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_use":
                    sequence += 1
                    event = _event_from_claude_tool(sequence, stamp, item, session.cwd, session.session_id)
                    events.append(event)
                    call_id = item.get("id")
                    if isinstance(call_id, str):
                        pending[call_id] = len(events) - 1
                elif item.get("type") == "tool_result":
                    call_id = item.get("tool_use_id")
                    if not isinstance(call_id, str) or call_id not in pending:
                        continue
                    event = events[pending.pop(call_id)]
                    code = _exit_code(row.get("toolUseResult"))
                    is_error = item.get("is_error") is True or (code is not None and code != 0)
                    event.outcome = "failure" if is_error else "success"
                    event.result_fingerprint = _result_fingerprint(item.get("content"))
    for event in events:
        if event.outcome == "unknown":
            event.confidence = 0.8
    _assign_state_epochs(events)
    return events


def _parse_codex_input(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _codex_command(name: str, subtype: str, raw_input: Any, parsed_input: dict[str, Any]) -> str:
    if name not in CODEX_SHELL_NAMES and subtype != "local_shell_call":
        return ""
    candidate: Any = None
    if name == "exec" and isinstance(raw_input, str) and not parsed_input:
        candidate = raw_input
    else:
        for key in ("cmd", "command", "shell_command"):
            value = parsed_input.get(key)
            if isinstance(value, (str, list)):
                candidate = value
                break
    if isinstance(candidate, str):
        return candidate
    if isinstance(candidate, list) and candidate and all(isinstance(item, str) for item in candidate):
        if (
            len(candidate) >= 3
            and os.path.basename(candidate[0]) in {"bash", "sh", "zsh"}
            and candidate[1] in {"-c", "-lc"}
        ):
            return candidate[2]
        return shlex.join(candidate)
    return ""


def _codex_exit_code(name: str, output: Any) -> int | None:
    code = _exit_code(output)
    if code is not None:
        return code
    # The live 2026-08-29 schema audit found this wrapper on exec_command
    # outputs. Other free-form output text is deliberately not interpreted as
    # process status because it may merely quote a command's own output.
    if name == "exec_command" and isinstance(output, str):
        match = CODEX_PROCESS_EXIT_RE.search(output)
        if match:
            return int(match.group(1))
    return None


def extract_codex(session: Session) -> list[Event]:
    events: list[Event] = []
    pending: dict[str, tuple[int, str]] = {}
    sequence = 0
    try:
        handle = session.path.open(encoding="utf-8", errors="replace")
    except OSError:
        return events
    with handle:
        for raw in handle:
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if row.get("type") != "response_item":
                continue
            payload = row.get("payload")
            if not isinstance(payload, dict):
                continue
            subtype = payload.get("type")
            stamp = _parse_time(row.get("timestamp"))
            if subtype in {"custom_tool_call", "function_call", "local_shell_call"}:
                sequence += 1
                call_id = payload.get("call_id") or payload.get("id")
                name = str(payload.get("name") or subtype)
                raw_input = payload.get("input") if payload.get("input") is not None else payload.get("arguments")
                inp = _parse_codex_input(raw_input)
                command = _codex_command(name, subtype, raw_input, inp)
                if command:
                    operation, target, command_hash = _classify_shell(command, session.cwd)
                elif any(marker in name.lower() for marker in CONTEXT_TOOL_MARKERS):
                    operation, target, command_hash = "context", ".", _hash({"tool": name})
                elif name in {"spawn_agent", "send_message", "followup_task"}:
                    operation, target, command_hash = "delegate", None, _hash({"tool": name})
                else:
                    operation, target, command_hash = "execute", None, _hash({"tool": name})
                event = Event(
                    sequence,
                    stamp,
                    "writer",
                    operation,
                    "path" if target else None,
                    target,
                    "unknown",
                    _hash({"tool": name, "command": command_hash, "target": target}),
                    None,
                    "codex",
                    f"session:{_hash(session.session_id)[:16]}#{sequence}",
                    confidence=0.9 if operation in {"execute", "mutate"} else 1.0,
                )
                events.append(event)
                if isinstance(call_id, str):
                    pending[call_id] = (len(events) - 1, name)
            elif subtype in {"custom_tool_call_output", "function_call_output", "local_shell_call_output"}:
                call_id = payload.get("call_id")
                if not isinstance(call_id, str) or call_id not in pending:
                    continue
                event_index, name = pending.pop(call_id)
                event = events[event_index]
                output = payload.get("output")
                code = _codex_exit_code(name, output)
                if code is not None:
                    event.outcome = "failure" if code != 0 else "success"
                event.result_fingerprint = _result_fingerprint(output)
                if code is None:
                    event.confidence = min(event.confidence, 0.75)
    for event in events:
        if event.outcome == "unknown":
            event.confidence = min(event.confidence, 0.7)
    _assign_state_epochs(events)
    return events


def _assign_state_epochs(events: list[Event]) -> None:
    epoch = 0
    for event in events:
        event.state_epoch = epoch
        if event.operation in {"edit", "mutate"} and event.outcome == "success":
            epoch += 1



def merge_session_events(bindings: list[tuple[Session, tuple[str, ...]]]) -> list[Event]:
    events: list[Event] = []
    for session, _ in bindings:
        extracted = extract_claude(session) if session.adapter == "claude" else extract_codex(session)
        events.extend(extracted)
    events.sort(
        key=lambda event: (
            event.timestamp is None,
            event.timestamp if event.timestamp is not None else float("inf"),
            event.evidence_ref,
        )
    )
    for sequence, event in enumerate(events, start=1):
        event.sequence = sequence
    _assign_state_epochs(events)
    return events

def _localized(target: str, seen_targets: set[str], global_context: bool) -> bool:
    if global_context:
        return True
    for candidate in seen_targets:
        if candidate == "." or candidate == target:
            return True
        if target.startswith(candidate.rstrip("/") + "/"):
            return True
        if candidate.startswith(target.rstrip("/") + "/"):
            return True
    return False


def detect(
    events: list[Event],
    *,
    terminal_evidenced: bool,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # A. Same action + same failure fingerprint, with no state or evidence delta.
    previous_failures: dict[tuple[str, str], tuple[Event, int]] = {}
    evidence_epoch = 0
    for event in events:
        current_evidence_epoch = evidence_epoch
        if event.outcome == "failure" and event.result_fingerprint:
            key = (event.action_fingerprint, event.result_fingerprint)
            previous = previous_failures.get(key)
            if previous is not None:
                prior, prior_evidence_epoch = previous
                if prior.state_epoch == event.state_epoch and prior_evidence_epoch == current_evidence_epoch:
                    findings.append(
                        _finding(
                            "repeated_failure_without_state_delta",
                            event,
                            prior_sequence=prior.sequence,
                            recovery=["inspect_failure_origin", "rerun_after_state_change", "prevent_identical_retry"],
                        )
                    )
            previous_failures[key] = (event, current_evidence_epoch)
        if event.operation in {"read", "search", "discover", "context"} and event.outcome != "failure":
            evidence_epoch += 1

    # B. Only if Work Lane closeout proves that the analyzed lane reached a closeout boundary.
    if terminal_evidenced:
        last_mutation = max(
            (e.sequence for e in events if e.operation in {"edit", "mutate"} and e.outcome == "success"),
            default=None,
        )
        last_verify = max(
            (e.sequence for e in events if e.operation == "verify" and e.outcome == "success"),
            default=None,
        )
        if last_mutation is not None and (last_verify is None or last_verify < last_mutation):
            event = next(e for e in reversed(events) if e.sequence == last_mutation)
            findings.append(
                _finding(
                    "verification_gap",
                    event,
                    last_successful_verification_sequence=last_verify,
                    recovery=["rerun_after_state_change"],
                )
            )

    # C. Conservative target-bound mutation localization. Task-supplied prompt context is
    # deliberately unobserved, so these findings are advisory and never promotion-grade.
    seen_targets: set[str] = set()
    global_context = False
    for event in events:
        if event.operation == "context" and event.outcome != "failure":
            global_context = True
        elif event.operation in {"read", "search", "discover"} and event.outcome != "failure" and event.target:
            seen_targets.add(event.target)
        elif (
            event.operation in {"edit", "mutate"}
            and event.outcome == "success"
            and event.target
            and not _localized(event.target, seen_targets, global_context)
        ):
            findings.append(
                _finding(
                    "mutation_without_evidenced_localization",
                    event,
                    confidence=0.55,
                    task_supplied_evidence_unobservable=True,
                    recovery=["request_new_context", "repoground_or_reposkop"],
                )
            )

    # D1. A,B,A,B with identical repeated results and no successful mutation.
    actionable_ops = {"verify", "read", "search", "discover", "execute"}
    filtered = [e for e in events if e.operation in actionable_ops]
    for index in range(3, len(filtered)):
        a, b, c, d = filtered[index - 3 : index + 1]
        if (
            a.action_fingerprint == c.action_fingerprint
            and b.action_fingerprint == d.action_fingerprint
            and a.action_fingerprint != b.action_fingerprint
            and a.state_epoch == b.state_epoch == c.state_epoch == d.state_epoch
            and a.result_fingerprint
            and b.result_fingerprint
            and a.result_fingerprint == c.result_fingerprint
            and b.result_fingerprint == d.result_fingerprint
        ):
            findings.append(
                _finding(
                    "action_oscillation_without_progress",
                    d,
                    first_sequence=a.sequence,
                    pattern="ABAB_same_results_no_state_delta",
                    recovery=["request_new_context", "writer_handoff"],
                )
            )

    # D2. Edit A->B, failed verify, inverse B->A, same A->B, same failed verify.
    for index in range(4, len(events)):
        e1, v1, undo, e2, v2 = events[index - 4 : index + 1]
        if not all((e1.mutation_from, e1.mutation_to, undo.mutation_from, undo.mutation_to, e2.mutation_from, e2.mutation_to)):
            continue
        if not (
            e1.operation == undo.operation == e2.operation == "edit"
            and e1.outcome == undo.outcome == e2.outcome == "success"
            and v1.operation == v2.operation == "verify"
            and v1.outcome == v2.outcome == "failure"
            and e1.target == undo.target == e2.target
            and e1.mutation_from == undo.mutation_to == e2.mutation_from
            and e1.mutation_to == undo.mutation_from == e2.mutation_to
            and v1.action_fingerprint == v2.action_fingerprint
            and v1.result_fingerprint
            and v1.result_fingerprint == v2.result_fingerprint
        ):
            continue
        findings.append(
            _finding(
                "action_oscillation_without_progress",
                v2,
                first_sequence=e1.sequence,
                pattern="edit_fail_undo_same_edit_same_fail",
                recovery=["inspect_failure_origin", "writer_handoff"],
            )
        )

    findings.sort(key=lambda item: (item["sequence"], DETECTORS.index(item["detector"])))
    return findings


def _finding(detector: str, event: Event, confidence: float = 0.95, **extra: Any) -> dict[str, Any]:
    return {
        "detector": detector,
        "sequence": event.sequence,
        "timestamp": event.timestamp,
        "evidence_ref": event.evidence_ref,
        "confidence": confidence,
        **extra,
    }


def _baseline_class(lane: Lane) -> str:
    if lane.closeout_state in SUCCESS_CLOSEOUTS:
        return "success"
    if lane.state == "blocked" or lane.closeout_state == "blocked_with_durable_followup":
        return "blocked"
    return "unknown"


def evaluate_lane(lane: Lane, session: Session, events: list[Event], reinforcement: tuple[str, ...]) -> dict[str, Any]:
    findings = detect(events, terminal_evidenced=lane.closeout_state in SUCCESS_CLOSEOUTS)
    first_by_detector: dict[str, dict[str, Any]] = {}
    for finding in findings:
        first_by_detector.setdefault(finding["detector"], finding)
    baseline_class = _baseline_class(lane)
    baseline_text = " ".join(lane.baseline_reason_codes).lower()
    promotion_candidates = []
    for finding in findings:
        detector = finding["detector"]
        # Localization cannot be promotion-grade without prompt/task-context observability.
        if detector == "mutation_without_evidenced_localization":
            continue
        overlap_tokens = {
            "repeated_failure_without_state_delta": ("retry", "failure"),
            "verification_gap": ("verification", "validation"),
            "action_oscillation_without_progress": ("retry", "revision", "needs_change"),
        }[detector]
        overlaps = any(token in baseline_text for token in overlap_tokens)
        if overlaps:
            continue
        later_actions = sum(1 for e in events if e.sequence > finding["sequence"])
        lead = None
        if lane.baseline_observed_at is not None and finding.get("timestamp") is not None:
            lead = lane.baseline_observed_at - float(finding["timestamp"])
        # High-precision incremental candidates require exact attribution, a concrete
        # recovery action, and either measurable lead or demonstrable redundant work.
        if finding["confidence"] >= 0.9 and (later_actions >= 2 or (lead is not None and lead > 0)):
            promotion_candidates.append(
                {
                    "detector": detector,
                    "sequence": finding["sequence"],
                    "lead_seconds": lead if lead is not None and lead > 0 else None,
                    "redundant_actions_after_signal": later_actions,
                    "recovery": finding.get("recovery", []),
                }
            )
    lead_values = [
        x["lead_seconds"]
        for x in promotion_candidates
        if isinstance(x.get("lead_seconds"), (int, float))
    ]
    return {
        "lane_id": lane.lane_id,
        "source_adapter": session.adapter,
        "attribution": "exact",
        "attribution_reinforcement": list(reinforcement),
        "baseline": {
            "class": baseline_class,
            "lane_state": lane.state,
            "closeout_state": lane.closeout_state,
            "reason_codes": list(lane.baseline_reason_codes),
        },
        "event_count": len(events),
        "operation_counts": dict(collections.Counter(event.operation for event in events)),
        "outcome_counts": dict(collections.Counter(event.outcome for event in events)),
        "finding_counts": dict(collections.Counter(item["detector"] for item in findings)),
        "findings": findings,
        "promotion_candidates": promotion_candidates,
        "lead_time_seconds_max": max(lead_values) if lead_values else None,
        "privacy": {
            "prompts_persisted": False,
            "file_contents_persisted": False,
            "raw_tool_outputs_persisted": False,
            "commands_persisted": False,
            "credentials_persisted": False,
            "only_result_digests_used_for_equality": True,
        },
    }


def build_report(
    work_lane_root: Path,
    claude_root: Path,
    codex_root: Path,
    output_root: Path | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    lanes = load_lanes(work_lane_root)
    claude = index_claude(claude_root) if claude_root.exists() else []
    codex = index_codex(codex_root) if codex_root.exists() else []
    matches = exact_attributions(lanes, [*claude, *codex])
    selected = [
        value
        for value in matches.values()
        if any(session.tool_actions > 0 for session, _ in value[1])
    ]
    selected.sort(key=lambda value: (value[0].updated_at or 0, value[0].lane_id), reverse=True)
    selected = selected[:limit]

    runs: list[dict[str, Any]] = []
    for lane, bindings in selected:
        events = merge_session_events(bindings)
        if not events:
            continue
        adapters = sorted({session.adapter for session, _ in bindings})
        reinforcement = tuple(sorted({item for _, proof in bindings for item in proof}))
        representative = Session(
            adapter="+".join(adapters),
            path=Path("."),
            session_id="combined",
            cwd=lane.target_path,
            branch=lane.branch,
            base_commit=lane.base_head if "base_revision" in reinforcement else None,
            tool_actions=sum(session.tool_actions for session, _ in bindings),
            first_at=min((session.first_at for session, _ in bindings if session.first_at is not None), default=None),
            last_at=max((session.last_at for session, _ in bindings if session.last_at is not None), default=None),
        )
        run = evaluate_lane(lane, representative, events, reinforcement)
        run["source_adapters"] = adapters
        run["session_count"] = len(bindings)
        run["session_tool_actions_indexed"] = representative.tool_actions
        runs.append(run)
        if output_root is not None:
            output_root.mkdir(parents=True, exist_ok=True)
            (output_root / f"{lane.lane_id}.json").write_text(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "kind": "experimental_trajectory_shadow_trace",
                        "lane_id": lane.lane_id,
                        "source_adapters": adapters,
                        "attribution": "exact",
                        "events": [event.sanitized() for event in events],
                        "findings": run["findings"],
                        "privacy": run["privacy"],
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

    detector_counts = collections.Counter()
    promotion_candidate_counts = collections.Counter()
    operation_counts = collections.Counter()
    outcome_counts = collections.Counter()
    run_adapter_sets = collections.Counter()
    session_adapters = collections.Counter()
    baselines = collections.Counter()
    total_events = 0
    promotion_candidate_runs = 0
    lead_values: list[float] = []
    redundant_after_signal = 0
    for run in runs:
        run_adapter_sets[run["source_adapter"]] += 1
        for adapter in run["source_adapters"]:
            session_adapters[adapter] += 1
        baselines[run["baseline"]["class"]] += 1
        total_events += run["event_count"]
        operation_counts.update(run["operation_counts"])
        outcome_counts.update(run["outcome_counts"])
        detector_counts.update(run["finding_counts"])
        if run["promotion_candidates"]:
            promotion_candidate_runs += 1
        for item in run["promotion_candidates"]:
            promotion_candidate_counts[item["detector"]] += 1
            redundant_after_signal += int(item["redundant_actions_after_signal"])
            if isinstance(item.get("lead_seconds"), (int, float)):
                lead_values.append(float(item["lead_seconds"]))

    success_findings = 0
    success_runs = 0
    for run in runs:
        if run["baseline"]["class"] == "success":
            success_runs += 1
            if any(run["finding_counts"].values()):
                success_findings += 1

    high_conf_findings = sum(
        1
        for run in runs
        for finding in run["findings"]
        if finding["confidence"] >= 0.9
    )
    promotion_candidate_items = sum(len(run["promotion_candidates"]) for run in runs)
    exact_session_bindings = sum(len(bindings) for _, bindings in matches.values())
    report = {
        "schema_version": SCHEMA_VERSION,
        "kind": "experimental_trajectory_shadow_pilot_report",
        "generated_from_live_local_sources": True,
        "public_runtime_contract": False,
        "online_intervention": False,
        "decision": {
            "promotion": (
                "stop" if promotion_candidate_items == 0 else "manual_baseline_validation_required"
            ),
            "trajectory_evidence_v1": False,
            "online_shadow": False,
            "reason": (
                "No promotion-grade actionable incremental information was observed in the exact cohort."
                if promotion_candidate_items == 0
                else "At least one candidate needs full existing PR/CI/review baseline validation before any promotion."
            ),
        },
        "cohort": {
            "work_lanes_indexed": len(lanes),
            "claude_sessions_indexed": len(claude),
            "codex_sessions_indexed": len(codex),
            "exact_attributions": len(matches),
            "exact_session_bindings": exact_session_bindings,
            "exact_with_tool_actions": sum(
                1 for _, bindings in matches.values() if any(session.tool_actions > 0 for session, _ in bindings)
            ),
            "analyzed_runs": len(runs),
            "run_adapter_sets": dict(run_adapter_sets),
            "session_adapter_counts": dict(session_adapters),
            "baseline_classes": dict(baselines),
        },
        "signals": {
            "events": total_events,
            "operation_counts": dict(operation_counts),
            "outcome_counts": dict(outcome_counts),
            "runs_with_failure_events": sum(1 for run in runs if run["outcome_counts"].get("failure", 0) > 0),
            "runs_with_delegation": sum(1 for run in runs if run["operation_counts"].get("delegate", 0) > 0),
            "detector_counts": {name: detector_counts.get(name, 0) for name in DETECTORS},
            "high_confidence_findings": high_conf_findings,
        },
        "incremental_information": {
            "promotion_candidate_runs": promotion_candidate_runs,
            "promotion_candidate_items": promotion_candidate_items,
            "promotion_candidates_by_detector": dict(promotion_candidate_counts),
            "candidate_redundant_actions_after_first_signal": redundant_after_signal,
            "candidate_lead_time_seconds": {
                "count": len(lead_values),
                "max": max(lead_values) if lead_values else None,
                "median": sorted(lead_values)[len(lead_values) // 2] if lead_values else None,
            },
            "baseline_overlap_rule": "detector-specific tokens in existing Work Lane closeout reason_codes suppress promotion",
            "external_baseline_validation_in_report": False,
            "externally_validated_actionable_items": 0,
            "recoverable_cases": 0 if promotion_candidate_items == 0 else None,
            "existing_recovery_action_earlier_opportunities": (
                0 if promotion_candidate_items == 0 else None
            ),
            "evidence_supported_runtime_seconds_saved": (
                0 if promotion_candidate_items == 0 else None
            ),
            "evidence_supported_tool_actions_saved": (
                0 if promotion_candidate_items == 0 else None
            ),
            "token_or_compute_savings": None,
        },
        "precision": {
            "empirical_precision": None,
            "promotion_grade_candidates": promotion_candidate_items,
            "externally_validated_actionable_findings": 0,
            "reason": "No labeled ground truth exists for the cohort; do not convert structural detector matches into a fake precision percentage.",
        },
        "false_positive_risk": {
            "success_cohort_runs": success_runs,
            "success_cohort_with_any_finding": success_findings,
            "success_cohort_alert_rate": (success_findings / success_runs) if success_runs else None,
            "localization_findings_promotion_eligible": False,
            "note": (
                "Success-cohort alert rate is a conservative false-positive proxy, not ground truth; "
                "successful runs can still contain real waste."
            ),
        },
        "recovery_simulation": {
            "allowed_existing_actions": [
                "inspect_failure_origin",
                "request_new_context",
                "repoground_or_reposkop",
                "rerun_after_state_change",
                "writer_handoff",
                "prevent_identical_retry",
            ],
            "live_actions_taken": 0,
        },
        "privacy": {
            "chain_of_thought_read_or_persisted": False,
            "prompts_persisted": False,
            "file_contents_persisted": False,
            "raw_tool_outputs_persisted": False,
            "commands_persisted": False,
            "credentials_persisted": False,
            "result_equality_uses_sha256_only": True,
        },
        "limitations": [
            "Agent Workspace event logs do not bind directly to provider session cwd; Work Lane target_path plus branch/revision is used.",
            "All exactly attributable provider sessions for one Work Lane are merged chronologically; target-only and ambiguous matches are excluded.",
            "Codex command normalization covers the live-validated exec_command, free-form exec, and bash-wrapped shell forms; direct mutation tools are not expanded from raw patch payloads, and outputs without explicit process status remain unknown.",
            "Shell verification is recognized only from structurally known test/check runner invocations; incidental test-related words in reads, searches, scripts, or free text do not count as verification.",
            "Task-supplied localization evidence is intentionally not read from prompts, so detector C is advisory only.",
            "Historical provider logs do not expose a canonical post-every-action repository revision.",
            "Work Lane closeout reason codes are a narrower baseline than full PR CI/review evidence; any positive promotion candidate requires external baseline validation.",
            "Lead time is available only when existing Work Lane closeout has a bound observed_at timestamp.",
        ],
        "runs": runs,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-lanes", type=Path, default=Path.home() / ".local/state/grabowski/work-lanes")
    parser.add_argument("--claude-root", type=Path, default=Path.home() / ".claude/projects")
    parser.add_argument("--codex-root", type=Path, default=Path.home() / ".codex/sessions")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args(argv)
    if args.limit < 1 or args.limit > 50:
        parser.error("--limit must be between 1 and 50")
    report = build_report(args.work_lanes, args.claude_root, args.codex_root, args.output_root, args.limit)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
