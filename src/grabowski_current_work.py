from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA_VERSION = 1
MAX_REPOSITORIES = 8
MAX_TASKS = 500
MAX_LEASES = 1000
MAX_WORKTREES = 1000
MAX_WORKERS = 500
MAX_TMUX_SESSIONS = 500
MAX_PROCESSES = 1000
MAX_GROUPS = 1000
MAX_EVIDENCE = 100
MAX_UNBOUND_SAMPLE = 50
MAX_TEXT = 512
MAX_CURSOR = 128
PAGE_LIMIT_MAX = 50

ACTIVE_TASK_STATES = {"launching", "running"}
TERMINAL_TASK_STATES = {
    "cancelled",
    "completed",
    "failed",
    "interrupted",
    "signalled",
    "timed_out",
}
ACTIVE_WORKER_STATES = {"launching", "running"}
CURRENT_WORK_VIEWS = {"current", "history"}
PROJECTION_STATES = {"active", "blocking", "resumable", "terminal_archived", "unknown"}
ATTENTION_BLOCKING_CLASSIFICATIONS = {"actionable", "outcome_unknown", "invalid_evidence"}
ATTENTION_RESUMABLE_CLASSIFICATIONS = {"decision_deferred"}
ATTENTION_ARCHIVED_CLASSIFICATIONS = {"decision_closed", "decision_superseded"}
WORKSPACE_PROCESS_RE = re.compile(
    r"(?:^|\s)-m\s+grabowski_agent_workspace\s+pane\s+(?P<workspace>[^\s]+)(?:\s|$)"
)
CURSOR_RE = re.compile(r"cw1\.([0-9a-f]{32})\.([0-9]{1,6})\Z")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9_.:@/+\-=]{1,256}\Z")


class CurrentWorkProjectionError(ValueError):
    pass


def _text(value: Any, field: str, *, empty: bool = False) -> str:
    if value is None and empty:
        return ""
    if not isinstance(value, str):
        raise CurrentWorkProjectionError(f"{field} must be text")
    value = value.strip()
    if not value and not empty:
        raise CurrentWorkProjectionError(f"{field} must not be empty")
    if len(value) > MAX_TEXT:
        raise CurrentWorkProjectionError(f"{field} exceeds {MAX_TEXT} characters")
    return value


def _identifier(value: Any, field: str) -> str:
    value = _text(value, field)
    if SAFE_ID_RE.fullmatch(value) is None:
        raise CurrentWorkProjectionError(f"{field} contains unsupported characters")
    return value


def _integer(value: Any, field: str, *, default: int = 0) -> int:
    if value is None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CurrentWorkProjectionError(f"{field} must be a non-negative integer")
    return value


def _boolean(value: Any, field: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise CurrentWorkProjectionError(f"{field} must be boolean")
    return value


def _records(
    payload: dict[str, Any] | None,
    key: str,
    maximum: int,
    source: str,
) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if not isinstance(payload, dict):
        raise CurrentWorkProjectionError(f"{source} payload must be an object")
    rows = payload.get(key, [])
    if not isinstance(rows, list):
        raise CurrentWorkProjectionError(f"{source}.{key} must be a list")
    if len(rows) > maximum:
        raise CurrentWorkProjectionError(
            f"{source}.{key} exceeds the bounded maximum of {maximum}"
        )
    if not all(isinstance(row, dict) for row in rows):
        raise CurrentWorkProjectionError(f"{source}.{key} must contain objects")
    return list(rows)


def _append(items: list[Any], value: Any) -> None:
    if len(items) < MAX_EVIDENCE:
        items.append(value)


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _group(work_id: str, kind: str, binding_id: str) -> dict[str, Any]:
    return {
        "work_id": work_id,
        "binding": {"kind": kind, "id": binding_id},
        "binding_status": "unbound",
        "projection_state": "unknown",
        "action_required": False,
        "action_reasons": [],
        "authority_refs": [],
        "heuristic_refs": [],
        "explicit_bindings": [],
        "lease_refs": [],
        "lease_summary": {"count": 0, "resource_classes": {}, "sample_truncated": False},
        "checkout_refs": [],
        "worker_refs": [],
        "physical_refs": {"tmux_sessions": [], "processes": []},
        "related_work_ids": [],
        "latest_activity_unix": 0,
        "source_states": [],
    }


def _ensure(
    groups: dict[str, dict[str, Any]], work_id: str, kind: str, binding_id: str
) -> dict[str, Any]:
    if work_id not in groups:
        if len(groups) >= MAX_GROUPS:
            raise CurrentWorkProjectionError(
                f"projected work groups exceed the bounded maximum of {MAX_GROUPS}"
            )
        groups[work_id] = _group(work_id, kind, binding_id)
    return groups[work_id]


def _set_projection_state(group: dict[str, Any], state: str) -> None:
    if state not in PROJECTION_STATES:
        raise CurrentWorkProjectionError(f"unsupported projection state: {state}")
    priority = {"unknown": 0, "terminal_archived": 1, "resumable": 2, "active": 3, "blocking": 4}
    if priority[state] >= priority[group["projection_state"]]:
        group["projection_state"] = state


def _blocking(group: dict[str, Any], reason: str) -> None:
    group["action_required"] = True
    _set_projection_state(group, "blocking")
    if reason and reason not in group["action_reasons"]:
        group["action_reasons"].append(reason)


def _resumable(group: dict[str, Any], reason: str = "") -> None:
    _set_projection_state(group, "resumable")
    if reason and reason not in group["action_reasons"]:
        group["action_reasons"].append(reason)


def _unknown(group: dict[str, Any], reason: str) -> None:
    group["action_required"] = True
    if group["projection_state"] not in {"active", "blocking", "resumable"}:
        group["projection_state"] = "unknown"
    if reason and reason not in group["action_reasons"]:
        group["action_reasons"].append(reason)


def _resource_binding(resource_key: str) -> dict[str, str]:
    if resource_key.startswith("path:"):
        return {"kind": "path", "id": resource_key.removeprefix("path:")}
    if resource_key.startswith("workspace:"):
        return {"kind": "workspace", "id": resource_key.removeprefix("workspace:")}
    if resource_key.startswith("component:"):
        return {"kind": "component", "id": resource_key.removeprefix("component:")}
    if resource_key.startswith("repo:"):
        value = resource_key.removeprefix("repo:")
        for marker, kind in ((":branch:", "branch"), (":operation:", "operation")):
            if marker in value:
                repository, binding_id = value.rsplit(marker, 1)
                return {"kind": kind, "id": binding_id, "repository": repository}
        return {"kind": "repository", "id": value}
    return {"kind": resource_key.split(":", 1)[0], "id": resource_key}


def _resource_class(resource_key: str) -> str:
    return resource_key.split(":", 1)[0] if ":" in resource_key else "unknown"


def parse_tmux_sessions(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        payload = {"returncode": None, "stdout": ""}
    if not isinstance(payload, dict) or not isinstance(payload.get("stdout", ""), str):
        raise CurrentWorkProjectionError("tmux payload and stdout must be typed")
    lines = [line for line in payload.get("stdout", "").splitlines() if line.strip()]
    truncated = len(lines) > MAX_TMUX_SESSIONS
    sessions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, line in enumerate(lines[:MAX_TMUX_SESSIONS], 1):
        parts = line.split("\t")
        if len(parts) != 4:
            errors.append({"line": index, "code": "invalid-field-count"})
            continue
        try:
            name = _identifier(parts[0], "tmux.session_name")
            windows, attached, activity = (int(item) for item in parts[1:])
            if min(windows, attached, activity) < 0:
                raise ValueError
        except (CurrentWorkProjectionError, ValueError):
            errors.append({"line": index, "code": "invalid-session-record"})
            continue
        sessions.append(
            {
                "session_name": name,
                "windows": windows,
                "attached": attached,
                "activity_unix": activity,
            }
        )
    return {
        "sessions": sessions,
        "errors": errors,
        "truncated": truncated,
        "returncode": payload.get("returncode"),
    }


def parse_processes(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        payload = {"returncode": None, "lines": []}
    if not isinstance(payload, dict) or not isinstance(payload.get("lines", []), list):
        raise CurrentWorkProjectionError("process payload and lines must be typed")
    lines = payload.get("lines", [])
    truncated = len(lines) > MAX_PROCESSES
    processes: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for index, line in enumerate(lines[:MAX_PROCESSES], 1):
        if not isinstance(line, str):
            errors.append({"line": index, "code": "non-text-process-line"})
            continue
        parts = line.split(None, 5)
        if len(parts) != 6:
            errors.append({"line": index, "code": "invalid-field-count"})
            continue
        pid_raw, ppid_raw, state, elapsed_raw, executable, arguments = parts
        try:
            pid, ppid, elapsed = int(pid_raw), int(ppid_raw), int(elapsed_raw)
            if pid <= 0 or ppid < 0 or elapsed < 0:
                raise ValueError
        except ValueError:
            errors.append({"line": index, "code": "invalid-process-value"})
            continue
        match = WORKSPACE_PROCESS_RE.search(arguments)
        workspace_id = (
            _identifier(match.group("workspace"), "process.workspace_id")
            if match
            else None
        )
        command_class = "other"
        if workspace_id:
            command_class = "agent-workspace-pane"
        elif executable in {"claude", "codex", "agy"}:
            command_class = "coding-agent"
        elif "grabowski_operator" in arguments:
            command_class = "operator-runtime"
        processes.append(
            {
                "pid": pid,
                "ppid": ppid,
                "state": state[:32],
                "elapsed_seconds": elapsed,
                "executable": executable[:128],
                "command_class": command_class,
                "workspace_id": workspace_id,
            }
        )
    return {
        "processes": processes,
        "errors": errors,
        "truncated": truncated,
        "count": len(processes),
    }


def _task(raw: dict[str, Any]) -> dict[str, Any]:
    action_required = _boolean(raw.get("action_required"), "task.action_required")
    resource_keys = raw.get("resource_keys", [])
    if not isinstance(resource_keys, list):
        raise CurrentWorkProjectionError("task.resource_keys must be a list")
    return {
        "task_id": _identifier(raw.get("task_id"), "task.task_id"),
        "state": _text(raw.get("state"), "task.state"),
        "attempt": _integer(raw.get("attempt", 1), "task.attempt"),
        "action_required": action_required,
        "action_reason": str(raw.get("action_reason", ""))[:128],
        "host": str(raw.get("host", ""))[:128],
        "unit": str(raw.get("unit", ""))[:256],
        "cwd": str(raw.get("cwd", ""))[:MAX_TEXT],
        "lease_owner_id": str(raw.get("lease_owner_id", ""))[:256],
        "resource_keys": [str(item)[:MAX_TEXT] for item in resource_keys if isinstance(item, str)][:MAX_EVIDENCE],
        "created_at_unix": _integer(raw.get("created_at_unix"), "task.created_at_unix"),
        "updated_at_unix": _integer(raw.get("updated_at_unix", raw.get("created_at_unix")), "task.updated_at_unix"),
        "recommended_next_action": str(raw.get("recommended_next_action", ""))[:MAX_TEXT],
    }


def _lease(raw: dict[str, Any]) -> dict[str, Any]:
    resource_key = _text(raw.get("resource_key"), "lease.resource_key")
    return {
        "resource_key": resource_key,
        "resource_binding": _resource_binding(resource_key),
        "resource_class": _resource_class(resource_key),
        "owner_id": _identifier(raw.get("owner_id"), "lease.owner_id"),
        "purpose": str(raw.get("purpose", ""))[:MAX_TEXT],
        "expires_at_unix": _integer(raw.get("expires_at_unix"), "lease.expires_at_unix"),
        "updated_at_unix": _integer(raw.get("updated_at_unix", raw.get("acquired_at_unix")), "lease.updated_at_unix"),
    }


def _worker(raw: dict[str, Any], kind: str) -> dict[str, Any]:
    projection = raw.get("projection", {})
    if not isinstance(projection, dict):
        projection = {}
    return {
        "worker_id": _identifier(raw.get("worker_id"), f"{kind}.worker_id"),
        "kind": kind,
        "state": _text(raw.get("state"), f"{kind}.state"),
        "unit": str(raw.get("unit", ""))[:256],
        "created_at_unix": _integer(
            raw.get("created_at_unix"), f"{kind}.created_at_unix"
        ),
        "updated_at_unix": _integer(
            raw.get("updated_at_unix", raw.get("created_at_unix")),
            f"{kind}.updated_at_unix",
        ),
        "fresh": bool(projection.get("fresh", False)),
        "action_required": bool(projection.get("action_required", False)),
        "reason": str(projection.get("reason", ""))[:128],
    }


def _checkout(raw: dict[str, Any], repository: str) -> dict[str, Any]:
    status = raw.get("status", {})
    coordination = raw.get("coordination", {})
    lifecycle = raw.get("lifecycle", {})
    if not all(isinstance(item, dict) for item in (status, coordination, lifecycle)):
        raise CurrentWorkProjectionError("checkout status, coordination and lifecycle must be objects")
    task_rows = coordination.get("tasks", [])
    lease_rows = coordination.get("resource_leases", [])
    process_rows = coordination.get("processes", [])
    if not all(isinstance(item, list) for item in (task_rows, lease_rows, process_rows)):
        raise CurrentWorkProjectionError("checkout coordination lists are invalid")
    retention = lifecycle.get("retention")
    binding = lifecycle.get("binding")
    return {
        "checkout_key": _identifier(raw.get("checkout_key"), "checkout.checkout_key"),
        "repository": repository,
        "path": _text(raw.get("path"), "checkout.path"),
        "head": str(raw.get("head", ""))[:64],
        "branch": str(raw.get("branch") or "")[:256],
        "is_main": _boolean(raw.get("is_main"), "checkout.is_main"),
        "dirty": _boolean(status.get("dirty"), "checkout.status.dirty"),
        "entry_count": _integer(status.get("entry_count"), "checkout.status.entry_count"),
        "lifecycle_state": str(raw.get("lifecycle_state", ""))[:128],
        "cleanup_candidate": _boolean(raw.get("cleanup_candidate"), "checkout.cleanup_candidate"),
        "coordination_blocking": _boolean(coordination.get("blocking"), "checkout.coordination.blocking"),
        "heuristic_task_ids": [str(item.get("task_id")) for item in task_rows if isinstance(item, dict) and item.get("task_id")][:MAX_EVIDENCE],
        "resource_leases": [
            {"resource_key": str(item.get("resource_key", ""))[:MAX_TEXT], "owner_id": str(item.get("owner_id", ""))[:256]}
            for item in lease_rows
            if isinstance(item, dict) and item.get("owner_id") and item.get("resource_key")
        ][:MAX_EVIDENCE],
        "processes": [
            {"pid": int(item.get("pid", 0) or 0), "command": str(item.get("command", ""))[:128]}
            for item in process_rows if isinstance(item, dict)
        ][:MAX_EVIDENCE],
        "retention_owner_id": str(retention.get("owner_id")) if isinstance(retention, dict) and retention.get("owner_id") else "",
        "binding_owner_id": str(binding.get("owner_id")) if isinstance(binding, dict) and binding.get("owner_id") else "",
        "binding_source": dict(binding.get("source")) if isinstance(binding, dict) and isinstance(binding.get("source"), dict) else None,
    }


def _owner_binding(owner_id: str, known_task_ids: set[str]) -> tuple[str, str, str]:
    prefixes = {"task:": "task", "agent-workspace:": "agent-workspace", "worker:": "worker"}
    for prefix, kind in prefixes.items():
        if owner_id.startswith(prefix):
            binding_id = owner_id.removeprefix(prefix)
            if kind != "task" or binding_id in known_task_ids:
                work_kind = "workspace" if kind == "agent-workspace" else kind
                return f"{work_kind}:{binding_id}", kind, binding_id
    if owner_id.startswith("operator:"):
        return f"operation:{owner_id}", "operation-owner", owner_id
    return f"owner:{owner_id}", "lease-owner", owner_id


def _path_in_checkout(path: str, checkout_path: str) -> bool:
    path, checkout_path = path.rstrip("/"), checkout_path.rstrip("/")
    return bool(path and checkout_path) and (
        path == checkout_path or path.startswith(checkout_path + "/")
    )


def _cursor_offset(cursor: str | None, snapshot_sha256: str) -> int:
    if cursor in {None, ""}:
        return 0
    if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR:
        raise CurrentWorkProjectionError("cursor is invalid")
    match = CURSOR_RE.fullmatch(cursor)
    if not match:
        raise CurrentWorkProjectionError("cursor is invalid")
    if match.group(1) != snapshot_sha256[:32]:
        raise CurrentWorkProjectionError("cursor is bound to another live snapshot")
    return int(match.group(2))


def _has_more(payload: dict[str, Any] | None, source: str) -> bool:
    if payload is None:
        return False
    value = payload.get("has_more", False)
    if not isinstance(value, bool):
        raise CurrentWorkProjectionError(f"{source}.has_more must be boolean")
    return value


def _task_has_more(payload: dict[str, Any] | None) -> bool:
    if payload is None:
        return False
    pagination = payload.get("pagination", {})
    if not isinstance(pagination, dict):
        raise CurrentWorkProjectionError("tasks.pagination must be an object")
    return _has_more(pagination, "tasks.pagination")


def _sort_key(group: dict[str, Any]) -> tuple[int, int, str]:
    rank = {"blocking": 0, "active": 1, "resumable": 2, "unknown": 3, "terminal_archived": 4}.get(group["projection_state"], 5)
    return rank, -int(group["latest_activity_unix"]), group["work_id"]


def _add_tasks(
    groups: dict[str, dict[str, Any]], task_rows: list[dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    tasks: dict[str, dict[str, Any]] = {}
    task_paths: dict[str, str] = {}
    for raw in task_rows:
        item = _task(raw)
        tasks[item["task_id"]] = item
        task_paths[item["task_id"]] = item["cwd"]
        group = _ensure(groups, f"task:{item['task_id']}", "task", item["task_id"])
        group["binding_status"] = "authority-bound"
        _append(group["explicit_bindings"], {"kind": "task", "id": item["task_id"]})
        for resource_key in item["resource_keys"]:
            _append(group["explicit_bindings"], _resource_binding(resource_key))
        if item["cwd"]:
            _append(group["heuristic_refs"], {"kind": "task-cwd", "path": item["cwd"], "authority": False})
        _append(
            group["authority_refs"],
            {
                "source": "task-ledger",
                "task_id": item["task_id"],
                "attempt": item["attempt"],
                "state": item["state"],
                "host": item["host"],
                "unit": item["unit"],
                "cwd": item["cwd"],
                "lease_owner_id": item["lease_owner_id"],
                "resource_keys": item["resource_keys"],
                "recommended_next_action": item["recommended_next_action"],
            },
        )
        group["latest_activity_unix"] = item["updated_at_unix"]
        group["source_states"].append(f"task:{item['state']}")
        if item["state"] in ACTIVE_TASK_STATES:
            _set_projection_state(group, "active")
        elif item["state"] == "interrupted":
            _resumable(group, "task-interrupted")
        elif item["state"] == "outcome_unknown":
            _blocking(group, "task-outcome_unknown")
        elif item["state"] in TERMINAL_TASK_STATES:
            _set_projection_state(group, "terminal_archived")
        elif item["action_required"]:
            _blocking(group, item["action_reason"] or f"task-{item['state']}")
        else:
            _unknown(group, "unknown-task-state")
    return tasks, task_paths


def _attention_records(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    rows = _records(payload, "records", MAX_TASKS, "attention")
    normalized: list[dict[str, Any]] = []
    for raw in rows:
        classification = _text(raw.get("classification"), "attention.classification")
        normalized.append(
            {
                "task_id": _identifier(raw.get("task_id"), "attention.task_id"),
                "attempt": _integer(raw.get("attempt", 1), "attention.attempt"),
                "state": _text(raw.get("state"), "attention.state"),
                "classification": classification,
                "decision": raw.get("decision") if isinstance(raw.get("decision"), str) else None,
                "authority": raw.get("authority") if isinstance(raw.get("authority"), str) else None,
                "evidence_ref": raw.get("evidence_ref") if isinstance(raw.get("evidence_ref"), str) else None,
                "outcome_receipt_sha256": raw.get("outcome_receipt_sha256") if isinstance(raw.get("outcome_receipt_sha256"), str) else None,
                "evidence_error": raw.get("evidence_error") if isinstance(raw.get("evidence_error"), str) else None,
            }
        )
    return normalized


def _apply_attention(
    groups: dict[str, dict[str, Any]],
    tasks: dict[str, dict[str, Any]],
    attention_rows: list[dict[str, Any]],
) -> None:
    for item in attention_rows:
        task_id = item["task_id"]
        group = _ensure(groups, f"task:{task_id}", "task", task_id)
        group["binding_status"] = "authority-bound"
        _append(group["explicit_bindings"], {"kind": "task", "id": task_id})
        _append(
            group["authority_refs"],
            {
                "source": "task-attention-decision-evidence",
                "task_id": task_id,
                "attempt": item["attempt"],
                "state": item["state"],
                "classification": item["classification"],
                "decision": item["decision"],
                "authority": item["authority"],
                "evidence_ref": item["evidence_ref"],
                "outcome_receipt_sha256": item["outcome_receipt_sha256"],
                "evidence_error": item["evidence_error"],
            },
        )
        group["source_states"].append(f"attention:{item['classification']}")
        classification = item["classification"]
        if classification in ATTENTION_BLOCKING_CLASSIFICATIONS:
            _blocking(group, f"attention-{classification}")
        elif classification in ATTENTION_RESUMABLE_CLASSIFICATIONS:
            _resumable(group, f"attention-{classification}")
        elif classification in ATTENTION_ARCHIVED_CLASSIFICATIONS:
            _set_projection_state(group, "terminal_archived")
        else:
            _unknown(group, f"unknown-attention-classification:{classification}")
        task = tasks.get(task_id)
        if task is not None:
            group["latest_activity_unix"] = max(group["latest_activity_unix"], task["updated_at_unix"])


def _add_leases(
    groups: dict[str, dict[str, Any]],
    lease_rows: list[dict[str, Any]],
    known_task_ids: set[str],
) -> None:
    for raw in lease_rows:
        item = _lease(raw)
        work_id, kind, binding_id = _owner_binding(item["owner_id"], known_task_ids)
        group = _ensure(groups, work_id, kind, binding_id)
        summary = group["lease_summary"]
        summary["count"] += 1
        resource_class = item["resource_class"]
        summary["resource_classes"][resource_class] = summary["resource_classes"].get(resource_class, 0) + 1
        before = len(group["lease_refs"])
        _append(group["lease_refs"], item)
        if len(group["lease_refs"]) == before:
            summary["sample_truncated"] = True
        _append(group["explicit_bindings"], item["resource_binding"])
        group["latest_activity_unix"] = max(group["latest_activity_unix"], item["updated_at_unix"])
        group["source_states"].append("lease:active")
        if group["binding_status"] == "unbound":
            group["binding_status"] = "lease-bound"
        _set_projection_state(group, "active")


def _add_workers(
    groups: dict[str, dict[str, Any]],
    browser_rows: list[dict[str, Any]],
    gui_rows: list[dict[str, Any]],
) -> None:
    rows = [(item, "browser") for item in browser_rows]
    rows.extend((item, "gui") for item in gui_rows)
    for raw, kind in rows:
        item = _worker(raw, kind)
        group = _ensure(groups, f"worker:{item['worker_id']}", "worker", item["worker_id"])
        group["binding_status"] = "authority-bound"
        _append(group["explicit_bindings"], {"kind": "worker", "id": item["worker_id"]})
        _append(group["worker_refs"], item)
        _append(
            group["authority_refs"],
            {"source": "worker-registry", "worker_id": item["worker_id"], "kind": kind, "state": item["state"], "fresh": item["fresh"]},
        )
        group["latest_activity_unix"] = max(group["latest_activity_unix"], item["updated_at_unix"])
        group["source_states"].append(f"worker:{item['state']}")
        if item["action_required"]:
            _blocking(group, item["reason"] or "worker-attention")
        elif item["state"] in ACTIVE_WORKER_STATES:
            _set_projection_state(group, "active")
        elif item["state"] == "interrupted":
            _resumable(group, "worker-interrupted")
        else:
            _set_projection_state(group, "terminal_archived")


def _resource_identifies_checkout(resource_key: str, item: dict[str, Any]) -> bool:
    binding = _resource_binding(resource_key)
    kind = binding["kind"]
    if kind == "path":
        path = binding["id"]
        return _path_in_checkout(path, item["path"])
    if kind == "branch":
        return (
            binding.get("repository", "").rstrip("/") == item["repository"].rstrip("/")
            and bool(item["branch"])
            and binding["id"] == item["branch"]
        )
    return False


def _resource_relates_to_checkout(resource_key: str, item: dict[str, Any]) -> bool:
    binding = _resource_binding(resource_key)
    kind = binding["kind"]
    if _resource_identifies_checkout(resource_key, item):
        return True
    if kind == "repository":
        return binding["id"].rstrip("/") == item["repository"].rstrip("/")
    if kind == "component":
        return binding["id"].startswith(item["repository"].rstrip("/") + ":")
    if kind == "operation":
        return binding.get("repository", "").rstrip("/") == item["repository"].rstrip("/")
    return False


def _checkout_candidates(
    item: dict[str, Any],
    tasks: dict[str, dict[str, Any]],
    task_paths: dict[str, str],
) -> tuple[list[tuple[int, str, str, str]], list[dict[str, Any]]]:
    exact: dict[str, tuple[int, str, str, str]] = {}
    heuristic: list[dict[str, Any]] = []
    known_task_ids = set(tasks)

    # Lifecycle binding is the strongest explicit checkout ownership signal.
    if item["binding_owner_id"]:
        owner_id = _identifier(item["binding_owner_id"], "checkout.binding_owner_id")
        work_id, kind, binding_id = _owner_binding(owner_id, known_task_ids)
        exact[work_id] = (0, work_id, kind, binding_id)
    elif item["retention_owner_id"]:
        owner_id = _identifier(item["retention_owner_id"], "checkout.retention_owner_id")
        work_id, kind, binding_id = _owner_binding(owner_id, known_task_ids)
        exact[work_id] = (1, work_id, kind, binding_id)
    else:
        # Only path/branch resources identify one concrete checkout. Repo-wide
        # resources relate to the repository but cannot establish checkout ownership.
        for lease in item["resource_leases"]:
            if not _resource_identifies_checkout(lease["resource_key"], item):
                heuristic.append(
                    {
                        "kind": "checkout-resource-overlap",
                        "owner_id": lease["owner_id"],
                        "resource_key": lease["resource_key"],
                        "authority": False,
                    }
                )
                continue
            owner_id = _identifier(lease["owner_id"], "checkout.lease_owner_id")
            work_id, kind, binding_id = _owner_binding(owner_id, known_task_ids)
            exact.setdefault(work_id, (2, work_id, kind, binding_id))

        for task_id, task_item in tasks.items():
            identifying = [
                key for key in task_item["resource_keys"]
                if _resource_identifies_checkout(key, item)
            ]
            if identifying:
                exact.setdefault(f"task:{task_id}", (2, f"task:{task_id}", "task", task_id))
            else:
                related = [
                    key for key in task_item["resource_keys"]
                    if _resource_relates_to_checkout(key, item)
                ]
                for resource_key in related[:MAX_EVIDENCE]:
                    heuristic.append(
                        {
                            "kind": "task-resource-repository-overlap",
                            "candidate_work_id": f"task:{task_id}",
                            "task_id": task_id,
                            "resource_key": resource_key,
                            "authority": False,
                        }
                    )

    for task_id, cwd in task_paths.items():
        if cwd and _path_in_checkout(cwd, item["path"]):
            heuristic.append(
                {
                    "kind": "task-cwd-overlap",
                    "candidate_work_id": f"task:{task_id}",
                    "task_id": task_id,
                    "path": cwd,
                    "authority": False,
                }
            )

    for task_id in item["heuristic_task_ids"]:
        if task_id in tasks:
            heuristic.append(
                {
                    "kind": "checkout-inventory-task-proximity",
                    "candidate_work_id": f"task:{task_id}",
                    "task_id": task_id,
                    "authority": False,
                }
            )

    deduped_heuristic = {_digest(ref): ref for ref in heuristic}
    return sorted(exact.values()), [deduped_heuristic[key] for key in sorted(deduped_heuristic)]


def _add_checkouts(
    groups: dict[str, dict[str, Any]],
    checkouts: list[dict[str, Any]],
    tasks: dict[str, dict[str, Any]],
    task_paths: dict[str, str],
    *,
    view: str,
) -> None:
    for item in checkouts:
        exact, heuristic = _checkout_candidates(item, tasks, task_paths)
        current_surface = bool(
            exact
            or item["dirty"]
            or item["cleanup_candidate"]
            or item["coordination_blocking"]
            or item["processes"]
        )
        if view == "current" and not current_surface:
            continue

        if len(exact) == 1:
            _, work_id, kind, binding_id = exact[0]
            group = _ensure(groups, work_id, kind, binding_id)
            if group["binding_status"] == "unbound":
                group["binding_status"] = "checkout-bound"
        elif len(exact) > 1:
            work_id = f"checkout:{item['checkout_key']}"
            group = _ensure(groups, work_id, "ambiguous-checkout", item["checkout_key"])
            group["binding_status"] = "ambiguous"
            group["related_work_ids"].extend(candidate[1] for candidate in exact)
            _unknown(group, "ambiguous-exact-checkout-bindings")
        else:
            work_id = f"checkout:{item['checkout_key']}"
            group = _ensure(groups, work_id, "checkout", item["checkout_key"])
            if group["binding_status"] == "unbound":
                group["binding_status"] = "checkout-bound"

        _append(group["explicit_bindings"], {"kind": "path", "id": item["path"]})
        if item["branch"]:
            _append(group["explicit_bindings"], {"kind": "branch", "id": item["branch"], "repository": item["repository"]})
        for ref in heuristic:
            _append(group["heuristic_refs"], ref)
            candidate = ref.get("candidate_work_id")
            if isinstance(candidate, str) and candidate != group["work_id"]:
                group["related_work_ids"].append(candidate)

        if item["binding_owner_id"]:
            _append(
                group["authority_refs"],
                {
                    "source": "checkout-lifecycle-binding",
                    "checkout_key": item["checkout_key"],
                    "owner_id": item["binding_owner_id"],
                    "binding_source": item["binding_source"],
                },
            )
        _append(group["checkout_refs"], item)
        for process in item["processes"]:
            _append(
                group["physical_refs"]["processes"],
                {"source": "checkout-inventory", "pid": process["pid"], "command": process["command"], "checkout_path": item["path"]},
            )
        group["source_states"].append(f"checkout:{item['lifecycle_state'] or 'unknown'}")

        if item["dirty"]:
            _blocking(group, "dirty-main-checkout" if item["is_main"] else "dirty-checkout")
        elif item["cleanup_candidate"]:
            _blocking(group, "cleanup-candidate")
        elif item["coordination_blocking"]:
            _set_projection_state(group, "active")
        elif item["processes"] and not exact:
            group["binding_status"] = "physical-only"
            _unknown(group, "physical-checkout-without-authority")
        elif item["lifecycle_state"] in {"archived", "completed_retained"}:
            _set_projection_state(group, "terminal_archived")
        elif view == "history":
            _set_projection_state(group, "terminal_archived")


def _add_physical_surfaces(
    groups: dict[str, dict[str, Any]],
    tmux: dict[str, Any],
    processes: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]], int]:
    unbound_tmux: list[dict[str, Any]] = []
    unbound_tmux_total = 0
    for session in tmux["sessions"]:
        name = session["session_name"]
        authoritative_work_id = f"workspace:{name}"
        if authoritative_work_id in groups:
            group = groups[authoritative_work_id]
            _append(group["physical_refs"]["tmux_sessions"], {"source": "tmux", **session})
            group["latest_activity_unix"] = max(group["latest_activity_unix"], session["activity_unix"])
        elif name.startswith("gaw-"):
            group = _ensure(groups, f"physical-tmux:{name}", "physical-session", name)
            group["binding_status"] = "physical-only"
            _append(group["physical_refs"]["tmux_sessions"], {"source": "tmux", **session})
            _append(
                group["heuristic_refs"],
                {
                    "kind": "tmux-session-name-workspace-candidate",
                    "candidate_work_id": authoritative_work_id,
                    "session_name": name,
                    "authority": False,
                },
            )
            group["related_work_ids"].append(authoritative_work_id)
            group["latest_activity_unix"] = max(group["latest_activity_unix"], session["activity_unix"])
            _unknown(group, "physical-workspace-without-authority")
        else:
            unbound_tmux_total += 1
            if len(unbound_tmux) < MAX_UNBOUND_SAMPLE:
                unbound_tmux.append(session)

    unbound_processes: list[dict[str, Any]] = []
    unbound_process_total = 0
    for process in processes["processes"]:
        workspace_id = process["workspace_id"]
        if workspace_id:
            authoritative_work_id = f"workspace:{workspace_id}"
            if authoritative_work_id in groups:
                group = groups[authoritative_work_id]
            else:
                group = _ensure(groups, f"physical-workspace:{workspace_id}", "physical-workspace", workspace_id)
                group["binding_status"] = "physical-only"
                _append(
                    group["heuristic_refs"],
                    {
                        "kind": "process-argv-workspace-candidate",
                        "candidate_work_id": authoritative_work_id,
                        "workspace_id": workspace_id,
                        "authority": False,
                    },
                )
                group["related_work_ids"].append(authoritative_work_id)
                _unknown(group, "physical-workspace-without-authority")
            _append(group["physical_refs"]["processes"], {"source": "process-list", **process})
        elif process["command_class"] == "coding-agent":
            unbound_process_total += 1
            if len(unbound_processes) < MAX_UNBOUND_SAMPLE:
                unbound_processes.append(process)
    return unbound_tmux, unbound_tmux_total, unbound_processes, unbound_process_total


def _finalize_groups(
    groups: dict[str, dict[str, Any]],
    tasks: dict[str, dict[str, Any]],
    *,
    view: str,
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for group in groups.values():
        task_item = tasks.get(group["binding"]["id"]) if group["binding"]["kind"] == "task" else None
        has_live_surface = bool(
            group["lease_summary"]["count"]
            or group["checkout_refs"]
            or group["worker_refs"]
            or group["physical_refs"]["tmux_sessions"]
            or group["physical_refs"]["processes"]
        )
        if task_item and task_item["state"] in TERMINAL_TASK_STATES and has_live_surface:
            _blocking(group, "terminal-task-with-live-surfaces")
        if view == "current" and group["projection_state"] == "terminal_archived" and not has_live_surface and not group["action_required"]:
            continue

        if group["binding_status"] != "ambiguous":
            if group["authority_refs"]:
                group["binding_status"] = "authority-bound"
            elif group["lease_summary"]["count"]:
                group["binding_status"] = "lease-bound"
            elif group["checkout_refs"] and group["binding_status"] != "physical-only":
                group["binding_status"] = "checkout-bound"
            elif group["physical_refs"]["tmux_sessions"] or group["physical_refs"]["processes"]:
                group["binding_status"] = "physical-only"

        group["action_reasons"] = sorted(set(group["action_reasons"]))
        group["source_states"] = sorted(set(group["source_states"]))
        group["related_work_ids"] = sorted(set(group["related_work_ids"]))
        group["authority_refs"].sort(key=_digest)
        group["heuristic_refs"] = [
            {_k: _v for _k, _v in item.items()}
            for _digest_key, item in sorted({_digest(item): item for item in group["heuristic_refs"]}.items())
        ]
        group["explicit_bindings"] = [
            item for _digest_key, item in sorted({_digest(item): item for item in group["explicit_bindings"]}.items())
        ]
        group["lease_refs"].sort(key=lambda item: item["resource_key"])
        group["lease_summary"]["resource_classes"] = dict(sorted(group["lease_summary"]["resource_classes"].items()))
        group["lease_summary"]["sample_truncated"] = bool(
            group["lease_summary"]["sample_truncated"]
            or group["lease_summary"]["count"] > len(group["lease_refs"])
        )
        group["checkout_refs"].sort(key=lambda item: item["path"])
        group["worker_refs"].sort(key=lambda item: item["worker_id"])
        group["physical_refs"]["tmux_sessions"].sort(key=lambda item: item["session_name"])
        group["physical_refs"]["processes"].sort(key=lambda item: (item.get("pid", 0), item.get("command", "")))
        group["surface_counts"] = {
            "authority_refs": len(group["authority_refs"]),
            "leases": group["lease_summary"]["count"],
            "checkouts": len(group["checkout_refs"]),
            "workers": len(group["worker_refs"]),
            "tmux_sessions": len(group["physical_refs"]["tmux_sessions"]),
            "processes": len(group["physical_refs"]["processes"]),
            "heuristic_refs": len(group["heuristic_refs"]),
        }
        drill_down: list[dict[str, Any]] = []
        if group["binding"]["kind"] == "task":
            drill_down.append({"surface": "grabowski_task_list", "task_id": group["binding"]["id"]})
        if group["lease_summary"]["count"]:
            owner_id = group["binding"]["id"] if group["binding"]["kind"] in {"lease-owner", "operation-owner", "agent-workspace"} else None
            drill_down.append({"surface": "grabowski_resource_list", "owner_id": owner_id})
        for repository in sorted({item["repository"] for item in group["checkout_refs"]}):
            drill_down.append({"surface": "grabowski_checkout_inventory", "repository": repository})
        if group["worker_refs"]:
            drill_down.append({"surface": "worker-status", "worker_ids": [item["worker_id"] for item in group["worker_refs"]]})
        group["drill_down_refs"] = drill_down
        projected.append(group)
    projected.sort(key=_sort_key)
    return projected


def _annotate_groups(
    groups: list[dict[str, Any]],
    *,
    generated_at_unix: int,
    source_truncation: dict[str, bool],
    source_errors: list[dict[str, Any]],
) -> None:
    global_error_sources = {str(item.get("source", "unknown")) for item in source_errors}
    for group in groups:
        authoritative_sources = {
            str(item.get("source"))
            for item in group["authority_refs"]
            if item.get("source")
        }
        relevant_sources: set[str] = set()
        if group["binding"]["kind"] == "task" or any(
            item.get("source") in {"task-ledger", "task-attention-decision-evidence"}
            for item in group["authority_refs"]
        ):
            relevant_sources.update({"tasks", "attention"})
        if group["lease_summary"]["count"]:
            authoritative_sources.add("resource-lease-store")
            relevant_sources.add("resources")
        if group["checkout_refs"]:
            authoritative_sources.add("checkout-inventory")
            relevant_sources.add("checkouts")
        if group["worker_refs"]:
            authoritative_sources.add("worker-registry")
            worker_kinds = {str(item.get("kind", "")) for item in group["worker_refs"]}
            if "browser" in worker_kinds:
                relevant_sources.add("browser_workers")
            if "gui" in worker_kinds:
                relevant_sources.add("gui_workers")
        observed_sources: set[str] = set()
        if group["physical_refs"]["tmux_sessions"]:
            observed_sources.add("tmux")
            relevant_sources.add("tmux")
        if group["physical_refs"]["processes"]:
            observed_sources.add("process-list")
            relevant_sources.add("processes")

        partial_sources = sorted(
            source for source in relevant_sources if source_truncation.get(source, False)
        )
        error_sources = sorted(relevant_sources & global_error_sources)
        uncertainty_reasons: list[str] = []
        if group["binding_status"] in {"ambiguous", "physical-only", "unbound"}:
            uncertainty_reasons.append(f"binding:{group['binding_status']}")
        if group["heuristic_refs"]:
            uncertainty_reasons.append("heuristic-relations-present")
        if partial_sources:
            uncertainty_reasons.append("truncated-sources:" + ",".join(partial_sources))
        if error_sources:
            uncertainty_reasons.append("source-errors:" + ",".join(error_sources))
        high_uncertainty = group["binding_status"] in {"ambiguous", "physical-only", "unbound"}
        medium_uncertainty = bool(
            partial_sources
            or error_sources
            or (group["heuristic_refs"] and group["binding_status"] == "checkout-bound")
        )
        group["observation"] = {
            "observed_at_unix": generated_at_unix,
            "authoritative_sources": sorted(authoritative_sources),
            "observed_non_authoritative_sources": sorted(observed_sources),
            "relevant_sources": sorted(relevant_sources),
            "completeness": "partial" if partial_sources or error_sources else "complete",
            "uncertainty": {
                "level": "high" if high_uncertainty else "medium" if medium_uncertainty else "low",
                "reasons": uncertainty_reasons,
            },
        }


def build_current_work_projection(
    *,
    tasks_payload: dict[str, Any] | None,
    attention_payload: dict[str, Any] | None,
    resources_payload: dict[str, Any] | None,
    checkout_payloads: list[dict[str, Any]] | None,
    repository_filters: list[str],
    tmux_payload: dict[str, Any] | None,
    process_payload: dict[str, Any] | None,
    browser_payload: dict[str, Any] | None,
    gui_payload: dict[str, Any] | None,
    source_errors: list[dict[str, Any]] | None = None,
    generated_at_unix: int,
    view: str = "current",
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, Any]:
    generated_at_unix = _integer(generated_at_unix, "generated_at_unix")
    if view not in CURRENT_WORK_VIEWS:
        raise CurrentWorkProjectionError("view must be current or history")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= PAGE_LIMIT_MAX:
        raise CurrentWorkProjectionError(f"limit must be between 1 and {PAGE_LIMIT_MAX}")
    if not isinstance(repository_filters, list) or not 1 <= len(repository_filters) <= MAX_REPOSITORIES:
        raise CurrentWorkProjectionError(
            f"repository_filters must contain between 1 and {MAX_REPOSITORIES} repositories"
        )
    repositories = [_text(item, "repository_filter") for item in repository_filters]
    if len(repositories) != len(set(repositories)):
        raise CurrentWorkProjectionError("repository_filters must be unique")

    task_rows = _records(tasks_payload, "tasks", MAX_TASKS, "tasks")
    attention_rows = _attention_records(attention_payload)
    lease_rows = _records(resources_payload, "leases", MAX_LEASES, "resources")
    browser_rows = _records(browser_payload, "workers", MAX_WORKERS, "browser")
    gui_rows = _records(gui_payload, "workers", MAX_WORKERS, "gui")
    if checkout_payloads is None:
        checkout_payloads = []
    if not isinstance(checkout_payloads, list) or len(checkout_payloads) > MAX_REPOSITORIES:
        raise CurrentWorkProjectionError("checkout_payloads exceed repository bound")

    checkouts: list[dict[str, Any]] = []
    checkout_truncated = False
    seen_repositories: set[str] = set()
    for index, payload in enumerate(checkout_payloads):
        if not isinstance(payload, dict):
            raise CurrentWorkProjectionError(f"checkout_payloads[{index}] must be an object")
        repository = _text(payload.get("repository"), "checkout.repository")
        if repository not in repositories:
            raise CurrentWorkProjectionError(
                f"checkout repository {repository!r} is outside repository_filters"
            )
        seen_repositories.add(repository)
        checkout_truncated |= _boolean(payload.get("truncated"), f"checkout_payloads[{index}].truncated")
        for raw in _records(payload, "worktrees", MAX_WORKTREES, f"checkout[{repository}]"):
            checkouts.append(_checkout(raw, repository))
        if len(checkouts) > MAX_WORKTREES:
            raise CurrentWorkProjectionError(
                f"combined worktrees exceed the bounded maximum of {MAX_WORKTREES}"
            )

    tmux = parse_tmux_sessions(tmux_payload)
    processes = parse_processes(process_payload)
    if source_errors is None:
        source_errors = []
    if not isinstance(source_errors, list) or not all(isinstance(item, dict) for item in source_errors):
        raise CurrentWorkProjectionError("source_errors must be a list of objects")
    source_errors_truncated = len(source_errors) > 100
    errors = [dict(item) for item in source_errors[:100]]
    if tmux["errors"]:
        errors.append({"source": "tmux", "parse_errors": tmux["errors"]})
    if processes["errors"]:
        errors.append({"source": "processes", "parse_errors": processes["errors"]})

    groups: dict[str, dict[str, Any]] = {}
    tasks, task_paths = _add_tasks(groups, task_rows)
    _apply_attention(groups, tasks, attention_rows)
    _add_leases(groups, lease_rows, set(tasks) | {item["task_id"] for item in attention_rows})
    _add_workers(groups, browser_rows, gui_rows)
    _add_checkouts(groups, checkouts, tasks, task_paths, view=view)
    unbound_tmux, unbound_tmux_total, unbound_processes, unbound_process_total = _add_physical_surfaces(
        groups, tmux, processes
    )
    projected = _finalize_groups(groups, tasks, view=view)

    resource_count = _integer(
        resources_payload.get("count", len(lease_rows)) if resources_payload else 0,
        "resources.count",
    )
    resource_truncated = resource_count > len(lease_rows) or _boolean(
        resources_payload.get("truncated") if resources_payload else False,
        "resources.truncated",
    )
    source_truncation = {
        "tasks": _task_has_more(tasks_payload),
        "attention": _task_has_more(attention_payload),
        "resources": resource_truncated,
        "checkouts": checkout_truncated,
        "tmux": tmux["truncated"],
        "processes": processes["truncated"],
        "browser_workers": _has_more(browser_payload, "browser"),
        "gui_workers": _has_more(gui_payload, "gui"),
        "source_errors": source_errors_truncated,
    }
    _annotate_groups(
        projected,
        generated_at_unix=generated_at_unix,
        source_truncation=source_truncation,
        source_errors=errors,
    )

    snapshot_material = {
        "view": view,
        "groups": projected,
        "unbound_tmux": unbound_tmux,
        "unbound_processes": unbound_processes,
        "source_errors": errors,
        "source_truncation": source_truncation,
        "repository_filters": repositories,
    }
    snapshot_sha256 = _digest(snapshot_material)
    offset = _cursor_offset(cursor, snapshot_sha256)
    if offset > len(projected):
        raise CurrentWorkProjectionError("cursor offset exceeds live snapshot")
    page = projected[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(projected)
    state_counts = {
        state: sum(1 for group in projected if group["projection_state"] == state)
        for state in sorted(PROJECTION_STATES)
    }

    warnings: list[str] = []
    if any(source_truncation.values()):
        warnings.append("one or more source surfaces were truncated")
    if errors:
        warnings.append("one or more source surfaces returned errors or malformed records")

    return {
        "schema_version": SCHEMA_VERSION,
        "projection": "current-operator-work",
        "view": view,
        "generated_at_unix": generated_at_unix,
        "snapshot_sha256": snapshot_sha256,
        "repository_filters": repositories,
        "count": len(page),
        "total_projected": len(projected),
        "state_counts": state_counts,
        "work": page,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_cursor": f"cw1.{snapshot_sha256[:32]}.{next_offset}" if has_more else None,
            "snapshot_bound": True,
        },
        "source_authority": {
            "tasks": "persistent task store",
            "attention": "task store plus create-only decision and outcome receipts",
            "resources": "resource lease store",
            "checkouts": "Git linked-worktree state plus checkout lifecycle store",
            "workers": "browser and GUI worker registries with bounded fresh observation",
            "tmux": "non-authoritative physical observation",
            "processes": "non-authoritative physical observation",
        },
        "source_counts": {
            "tasks": len(task_rows),
            "attention_records": len(attention_rows),
            "leases": len(lease_rows),
            "repositories": len(seen_repositories),
            "worktrees": len(checkouts),
            "tmux_sessions": len(tmux["sessions"]),
            "processes": len(processes["processes"]),
            "browser_workers": len(browser_rows),
            "gui_workers": len(gui_rows),
        },
        "source_truncation": source_truncation,
        "source_errors": errors,
        "unbound_physical": {
            "tmux_sessions": unbound_tmux,
            "tmux_total_unbound": unbound_tmux_total,
            "processes": unbound_processes,
            "process_total_unbound": unbound_process_total,
            "sample_truncated": unbound_tmux_total > len(unbound_tmux) or unbound_process_total > len(unbound_processes),
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect the first blocking work group and its authority references"
            if state_counts["blocking"]
            else "inspect resumable work groups"
            if state_counts["resumable"]
            else "none"
        ),
        "does_not_establish": [
            "a new independently mutable lifecycle or work-state truth",
            "a new task, lease, checkout, worker, process or tmux authority",
            "permission to stop processes, release leases or remove checkouts",
            "terminal success from a tmux session, process or heuristic relation alone",
            "absence of work beyond any explicitly truncated or failed source",
            "authority from task cwd overlap or session naming heuristics",
        ],
    }
