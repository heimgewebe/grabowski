"""Read-only, evidence-bound full-ledger Chronik search through the installed Grabowski MCP.

This adapter invokes the canonical Chronik release. It neither copies historical
events nor builds a second index; CLI integrity and snapshot-bound cursors remain
authoritative. Callers must not treat historical evidence as live system truth.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable

FILTER_NAMES = (
    "event_id", "repo", "host", "component", "subject_component", "kind",
    "operation", "task_class", "outcome", "pr_number", "bureau_task_id",
    "run_id", "task_id", "since", "until", "keyword",
)
MAX_LIMIT = 20
MAX_OUTPUT_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
Executor = Callable[[list[str], Path], dict[str, Any]]


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _failure(code: str) -> dict[str, Any]:
    return {
        "kind": "grabowski_chronik_full_search", "schema_version": 1,
        "available": False, "historical_only": True,
        "failure_code": code, "events": [],
        "does_not_establish": ["current runtime state", "successful deployment", "unrecorded events"],
    }


def _selectors(values: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(values, dict) or set(values) != set(FILTER_NAMES):
        raise ValueError("Chronik selectors must bind every supported field")
    normalized: dict[str, Any] = {}
    for name in FILTER_NAMES:
        value = values[name]
        if name == "pr_number":
            if value is not None and (type(value) is not int or not 1 <= value <= 2_147_483_647):
                raise ValueError("pr_number must be a positive integer")
        elif value is not None:
            if not isinstance(value, str) or not value.strip() or len(value) > 500 or "\x00" in value:
                raise ValueError("invalid selector " + name)
        normalized[name] = value
    if all(value is None or value == "" for value in normalized.values()):
        raise ValueError("at least one historical selector required")
    return normalized


def _validate(payload: Any, filters: dict[str, Any], limit: int) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Chronik search response is not an object")
    if (
        payload.get("schema_version") != "chronik-agent-search.v1"
        or payload.get("query") != filters
        or payload.get("query_sha256") != _sha(filters)
        or payload.get("historical_only") is not True
        or payload.get("result_scope") != "complete_committed_agent_ledger_snapshot"
        or payload.get("search_exhaustive") is not True
        or not isinstance(payload.get("does_not_establish"), list)
        or type(payload.get("has_more")) is not bool
    ):
        raise ValueError("Chronik search contract mismatch")
    events = payload.get("events")
    count = payload.get("matching_count")
    remaining = payload.get("remaining_from_cursor")
    if (not isinstance(events, list) or len(events) > limit
        or type(payload.get("returned")) is not int or payload["returned"] != len(events)
        or type(count) is not int or count < len(events)
        or type(remaining) is not int or remaining < len(events)
        or (payload["has_more"] and (not events or remaining <= len(events)))
        or (not payload["has_more"] and payload.get("next_cursor") is not None)
        or (payload["has_more"] and (
            not isinstance(payload.get("next_cursor"), str)
            or not 1 <= len(payload["next_cursor"]) <= 4096
        ))):
        raise ValueError("Chronik pagination receipt mismatch")
    snap = payload.get("ledger_snapshot")
    if (not isinstance(snap, dict) or snap.get("domain") != "agent.ledger"
        or snap.get("integrity_valid") is not True
        or snap.get("invalid_record_count") != 0
        or type(snap.get("valid_record_count")) is not int
        or type(snap.get("total_record_count")) is not int
        or snap["valid_record_count"] != snap["total_record_count"]
        or not isinstance(snap.get("sha256"), str)
        or not SHA.fullmatch(snap["sha256"])):
        raise ValueError("Chronik ledger is invalid or unbound")
    seen: set[str] = set()
    for item in events:
        if not isinstance(item, dict) or not isinstance(item.get("event"), dict):
            raise ValueError("Chronik event receipt shape mismatch")
        event = item["event"]
        eid = event.get("event_id")
        if (not isinstance(eid, str) or eid in seen
            or item.get("event_id") != eid
            or item.get("event_ref") != "chronik:agent.ledger:" + eid
            or item.get("canonical_event_sha256") != _sha(event)):
            raise ValueError("Chronik event payload is not hash-bound")
        seen.add(eid)
    return payload


def read_only_search_argv(
    argv: list[str], repository: Path, data_dir: Path,
) -> list[str]:
    """Confine the selected Chronik CLI to read-only source and ledger mounts.

    The existing Grabowski bubblewrap runner supplies a private /tmp and no
    host-writable mounts. The optional historical search must not inherit
    the normal operator subprocess's access to the host filesystem.
    """
    from grabowski_agent_sandbox import minimal_sandbox_argv, require_bwrap

    if (
        not repository.is_absolute() or not data_dir.is_absolute()
        or repository.is_symlink() or data_dir.is_symlink()
        or not repository.is_dir() or not data_dir.is_dir()
        or len(argv) < 2 or argv[1] != str(repository / "tools" / "chronik_search.py")
    ):
        raise ValueError("Chronik sandbox source/data identity invalid")
    runtime_python = Path(argv[0])
    if not runtime_python.is_absolute() or not runtime_python.is_file():
        raise ValueError("Chronik sandbox Python unavailable")
    # The serving Grabowski process may run from a release-local virtualenv,
    # not directly from /nix/store. Its pyvenv.cfg and site-packages must be
    # readable without giving the subprocess host write permissions.
    venv = runtime_python.parent.parent
    virtualenv = (
        not runtime_python.is_relative_to(Path("/nix/store"))
        and runtime_python.parent.name == "bin"
        and (venv / "pyvenv.cfg").is_file()
    )
    if not virtualenv and not (
        runtime_python.is_relative_to(Path("/nix/store"))
        or runtime_python.is_relative_to(Path("/usr"))
    ):
        raise ValueError("Chronik sandbox Python is not a trusted runtime")
    mount_paths = (repository, data_dir, *((venv,) if virtualenv else ()))
    parents = {
        ancestor for path in mount_paths
        for ancestor in path.parents
        if str(ancestor) not in {"/", "/dev", "/proc", "/usr", "/etc", "/tmp", "/nix"}
        and not ancestor.is_relative_to(Path("/nix"))
    }
    readonly = ((data_dir, data_dir),) + (((venv, venv),) if virtualenv else ())
    command = minimal_sandbox_argv(
        workspace=repository,
        command=argv,
        workspace_writable=False,
        extra_read_only=readonly,
        extra_directories=tuple(sorted(
            parents, key=lambda path: (len(path.parts), str(path)),
        )),
    )
    command[0] = str(require_bwrap())
    return command


def query(
    *, selectors: dict[str, Any], limit: int = 10, cursor: str | None = None,
    configuration: dict[str, Any], executor: Executor,
) -> dict[str, Any]:
    """Read the complete committed ledger, rejecting truncated/invalid evidence."""
    filters = _selectors(selectors)
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError("limit must be between 1 and 20")
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 4096):
        raise ValueError("invalid cursor")
    if not configuration.get("available"):
        return _failure(str(configuration.get("reason") or "chronik_unavailable"))
    repo = Path(configuration["repository"])
    cli = repo / "tools" / "chronik_search.py"
    python = Path(configuration["python"])
    data_dir = Path(configuration["data_dir"])
    if (not repo.is_absolute() or not repo.is_dir()
        or not cli.is_file() or cli.is_symlink()
        or not python.is_absolute() or not python.is_file()
        or not data_dir.is_dir()):
        return _failure("chronik_full_search_runtime_unavailable")
    argv = [str(python), str(cli), "--data-dir", str(data_dir), "search"]
    for name, value in filters.items():
        if value is not None and value != "":
            argv.extend(("--" + name.replace("_", "-"), str(value)))
    argv.extend(("--limit", str(limit)))
    if cursor is not None:
        argv.extend(("--cursor", cursor))
    result = executor(argv, repo)
    if isinstance(result, dict) and result.get("returncode") != 0:
        stderr = result.get("stderr")
        if isinstance(stderr, str) and "stale search cursor: ledger changed" in stderr:
            return _failure("chronik_cursor_stale_restart_from_first_page")
    if (not isinstance(result, dict) or result.get("returncode") != 0
        or result.get("timed_out") is True
        or result.get("stdout_truncated") is True):
        return _failure("chronik_full_search_cli_failed")
    try:
        raw = result.get("stdout")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("search output missing or too large")
        data = _validate(json.loads(raw), filters, limit)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return _failure("chronik_full_search_contract_failed")
    return {
        "kind": "grabowski_chronik_full_search", "schema_version": 1,
        "available": True, "historical_only": True,
        "query": filters, "query_sha256": data["query_sha256"], "returned": data["returned"],
        "matching_count": data["matching_count"], "has_more": data["has_more"],
        "next_cursor": data["next_cursor"], "events": data["events"],
        "ledger_snapshot": data["ledger_snapshot"],
        "search_exhaustive": True, "result_scope": data["result_scope"],
        "does_not_establish": data["does_not_establish"],
        "result_sha256": _sha(data),
    }
