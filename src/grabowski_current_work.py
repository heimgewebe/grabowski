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
        "projection_state": "uncertain",
        "action_required": False,
        "action_reasons": [],
        "authority_refs": [],
        "lease_refs": [],
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


def _attention(group: dict[str, Any], reason: str) -> None:
    group["action_required"] = True
    group["projection_state"] = "attention"
    if reason and reason not in group["action_reasons"]:
        group["action_reasons"].append(reason)


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
    return {
        "task_id": _identifier(raw.get("task_id"), "task.task_id"),
        "state": _text(raw.get("state"), "task.state"),
        "action_required": action_required,
        "action_reason": str(raw.get("action_reason", ""))[:128],
        "host": str(raw.get("host", ""))[:128],
        "unit": str(raw.get("unit", ""))[:256],
        "cwd": str(raw.get("cwd", ""))[:MAX_TEXT],
        "lease_owner_id": str(raw.get("lease_owner_id", ""))[:256],
        "resource_keys": [
            str(item)[:MAX_TEXT]
            for item in raw.get("resource_keys", [])
            if isinstance(item, str)
        ][:MAX_EVIDENCE],
        "created_at_unix": _integer(raw.get("created_at_unix"), "task.created_at_unix"),
        "updated_at_unix": _integer(
            raw.get("updated_at_unix", raw.get("created_at_unix")),
            "task.updated_at_unix",
        ),
        "recommended_next_action": str(raw.get("recommended_next_action", ""))[
            :MAX_TEXT
        ],
    }


def _lease(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "resource_key": _text(raw.get("resource_key"), "lease.resource_key"),
        "owner_id": _identifier(raw.get("owner_id"), "lease.owner_id"),
        "purpose": str(raw.get("purpose", ""))[:MAX_TEXT],
        "expires_at_unix": _integer(
            raw.get("expires_at_unix"), "lease.expires_at_unix"
        ),
        "updated_at_unix": _integer(
            raw.get("updated_at_unix", raw.get("acquired_at_unix")),
            "lease.updated_at_unix",
        ),
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
    entry_count = _integer(status.get("entry_count"), "checkout.status.entry_count")
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
        "entry_count": entry_count,
        "lifecycle_state": str(raw.get("lifecycle_state", ""))[:128],
        "cleanup_candidate": _boolean(
            raw.get("cleanup_candidate"), "checkout.cleanup_candidate"
        ),
        "coordination_blocking": _boolean(
            coordination.get("blocking"), "checkout.coordination.blocking"
        ),
        "task_ids": [
            str(item.get("task_id"))
            for item in task_rows
            if isinstance(item, dict) and item.get("task_id")
        ][:MAX_EVIDENCE],
        "lease_owner_ids": [
            str(item.get("owner_id"))
            for item in lease_rows
            if isinstance(item, dict) and item.get("owner_id")
        ][:MAX_EVIDENCE],
        "processes": [
            {
                "pid": int(item.get("pid", 0) or 0),
                "command": str(item.get("command", ""))[:128],
            }
            for item in process_rows
            if isinstance(item, dict)
        ][:MAX_EVIDENCE],
        "retention_owner_id": (
            str(retention.get("owner_id"))
            if isinstance(retention, dict) and retention.get("owner_id")
            else ""
        ),
        "binding_owner_id": (
            str(binding.get("owner_id"))
            if isinstance(binding, dict) and binding.get("owner_id")
            else ""
        ),
    }


def _owner_binding(
    owner_id: str, known_task_ids: set[str]
) -> tuple[str, str, str]:
    prefixes = {
        "task:": "task",
        "agent-workspace:": "agent-workspace",
        "worker:": "worker",
    }
    for prefix, kind in prefixes.items():
        if owner_id.startswith(prefix):
            binding_id = owner_id.removeprefix(prefix)
            if kind != "task" or binding_id in known_task_ids:
                return f"{kind if kind != 'agent-workspace' else 'workspace'}:{binding_id}", kind, binding_id
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
    rank = {"attention": 0, "active": 1, "uncertain": 2}.get(
        group["projection_state"], 3
    )
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
        _append(
            group["authority_refs"],
            {
                "source": "task-ledger",
                "task_id": item["task_id"],
                "state": item["state"],
                "host": item["host"],
                "unit": item["unit"],
                "cwd": item["cwd"],
                "lease_owner_id": item["lease_owner_id"],
                "resource_keys": item["resource_keys"],
                "recommended_next_action": item["recommended_next_action"],
                "action_required": item["action_required"],
                "action_reason": item["action_reason"],
            },
        )
        group["latest_activity_unix"] = item["updated_at_unix"]
        group["source_states"].append(f"task:{item['state']}")
        if item["state"] in ACTIVE_TASK_STATES:
            group["projection_state"] = "active"
        elif item["state"] == "outcome_unknown":
            _attention(group, "task-outcome_unknown")
        elif item["action_required"]:
            _attention(group, item["action_reason"] or f"task-{item['state']}")
        elif item["state"] not in TERMINAL_TASK_STATES:
            _attention(group, "unknown-task-state")
    return tasks, task_paths


def _add_leases(
    groups: dict[str, dict[str, Any]],
    lease_rows: list[dict[str, Any]],
    known_task_ids: set[str],
) -> None:
    for raw in lease_rows:
        item = _lease(raw)
        work_id, kind, binding_id = _owner_binding(item["owner_id"], known_task_ids)
        group = _ensure(groups, work_id, kind, binding_id)
        _append(group["lease_refs"], item)
        group["latest_activity_unix"] = max(
            group["latest_activity_unix"], item["updated_at_unix"]
        )
        group["source_states"].append("lease:active")
        if group["binding_status"] == "unbound":
            group["binding_status"] = "lease-bound"
        if group["projection_state"] == "uncertain":
            group["projection_state"] = "active"


def _add_workers(
    groups: dict[str, dict[str, Any]],
    browser_rows: list[dict[str, Any]],
    gui_rows: list[dict[str, Any]],
) -> None:
    rows = [(item, "browser") for item in browser_rows]
    rows.extend((item, "gui") for item in gui_rows)
    for raw, kind in rows:
        item = _worker(raw, kind)
        group = _ensure(
            groups, f"worker:{item['worker_id']}", "worker", item["worker_id"]
        )
        group["binding_status"] = "authority-bound"
        _append(group["worker_refs"], item)
        _append(
            group["authority_refs"],
            {
                "source": "worker-registry",
                "worker_id": item["worker_id"],
                "kind": kind,
                "state": item["state"],
                "fresh": item["fresh"],
            },
        )
        group["latest_activity_unix"] = max(
            group["latest_activity_unix"], item["updated_at_unix"]
        )
        group["source_states"].append(f"worker:{item['state']}")
        if item["action_required"]:
            _attention(group, item["reason"] or "worker-attention")
        elif item["state"] in ACTIVE_WORKER_STATES:
            group["projection_state"] = "active"


def _checkout_candidates(
    item: dict[str, Any],
    tasks: dict[str, dict[str, Any]],
    task_paths: dict[str, str],
) -> list[tuple[int, str, str, str]]:
    candidates: dict[str, tuple[int, str, str, str]] = {}
    for task_id in item["task_ids"]:
        if task_id in tasks:
            candidates[f"task:{task_id}"] = (0, f"task:{task_id}", "task", task_id)
    for task_id, cwd in task_paths.items():
        if _path_in_checkout(cwd, item["path"]):
            candidates[f"task:{task_id}"] = (0, f"task:{task_id}", "task", task_id)
    known_task_ids = set(tasks)
    for owner_id in [
        *item["lease_owner_ids"],
        item["binding_owner_id"],
        item["retention_owner_id"],
    ]:
        if not owner_id:
            continue
        work_id, kind, binding_id = _owner_binding(
            _identifier(owner_id, "checkout.owner_id"), known_task_ids
        )
        candidates.setdefault(work_id, (1, work_id, kind, binding_id))
    return sorted(candidates.values())


def _add_checkouts(
    groups: dict[str, dict[str, Any]],
    checkouts: list[dict[str, Any]],
    tasks: dict[str, dict[str, Any]],
    task_paths: dict[str, str],
) -> None:
    for item in checkouts:
        ordered = _checkout_candidates(item, tasks, task_paths)
        if not (
            ordered
            or item["dirty"]
            or item["cleanup_candidate"]
            or item["coordination_blocking"]
            or item["processes"]
        ):
            continue
        if ordered:
            _, work_id, kind, binding_id = ordered[0]
        else:
            work_id = f"checkout:{item['checkout_key']}"
            kind, binding_id = "unbound-checkout", item["checkout_key"]
        group = _ensure(groups, work_id, kind, binding_id)
        if len(ordered) > 1:
            group["binding_status"] = "ambiguous"
            group["related_work_ids"].extend(
                candidate[1] for candidate in ordered[1:]
            )
        elif ordered and group["binding_status"] == "unbound":
            group["binding_status"] = "checkout-bound"
        _append(group["checkout_refs"], item)
        for process in item["processes"]:
            _append(
                group["physical_refs"]["processes"],
                {
                    "source": "checkout-inventory",
                    "pid": process["pid"],
                    "command": process["command"],
                    "checkout_path": item["path"],
                },
            )
        group["source_states"].append(
            f"checkout:{item['lifecycle_state'] or 'unknown'}"
        )
        if item["dirty"]:
            _attention(
                group,
                "dirty-main-checkout" if item["is_main"] else "dirty-checkout",
            )
        elif item["cleanup_candidate"]:
            _attention(group, "cleanup-candidate")
        elif item["coordination_blocking"] and group["projection_state"] == "uncertain":
            group["projection_state"] = "active"
        elif not ordered and item["processes"]:
            group["binding_status"] = "physical-only"
            _attention(group, "physical-checkout-without-authority")


def _add_physical_surfaces(
    groups: dict[str, dict[str, Any]],
    tmux: dict[str, Any],
    processes: dict[str, Any],
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]], int]:
    unbound_tmux: list[dict[str, Any]] = []
    unbound_tmux_total = 0
    for session in tmux["sessions"]:
        name = session["session_name"]
        work_id = f"workspace:{name}"
        if work_id in groups or name.startswith("gaw-"):
            group = _ensure(groups, work_id, "agent-workspace", name)
            _append(
                group["physical_refs"]["tmux_sessions"],
                {"source": "tmux", **session},
            )
            group["latest_activity_unix"] = max(
                group["latest_activity_unix"], session["activity_unix"]
            )
            if group["binding_status"] == "unbound":
                group["binding_status"] = "physical-only"
                _attention(group, "physical-workspace-without-authority")
        else:
            unbound_tmux_total += 1
            if len(unbound_tmux) < MAX_UNBOUND_SAMPLE:
                unbound_tmux.append(session)

    unbound_processes: list[dict[str, Any]] = []
    unbound_process_total = 0
    for process in processes["processes"]:
        workspace_id = process["workspace_id"]
        if workspace_id:
            group = _ensure(
                groups,
                f"workspace:{workspace_id}",
                "agent-workspace",
                workspace_id,
            )
            _append(
                group["physical_refs"]["processes"],
                {"source": "process-list", **process},
            )
            if group["binding_status"] == "unbound":
                group["binding_status"] = "physical-only"
                _attention(group, "physical-workspace-without-authority")
        elif process["command_class"] == "coding-agent":
            unbound_process_total += 1
            if len(unbound_processes) < MAX_UNBOUND_SAMPLE:
                unbound_processes.append(process)
    return unbound_tmux, unbound_tmux_total, unbound_processes, unbound_process_total


def _finalize_groups(
    groups: dict[str, dict[str, Any]], tasks: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    projected: list[dict[str, Any]] = []
    for group in groups.values():
        task_item = (
            tasks.get(group["binding"]["id"])
            if group["binding"]["kind"] == "task"
            else None
        )
        has_surface = bool(
            group["lease_refs"]
            or group["checkout_refs"]
            or group["worker_refs"]
            or group["physical_refs"]["tmux_sessions"]
            or group["physical_refs"]["processes"]
        )
        if task_item and task_item["state"] in TERMINAL_TASK_STATES and has_surface:
            _attention(group, "terminal-task-with-live-surfaces")
        if (
            task_item
            and task_item["state"] in TERMINAL_TASK_STATES
            and not has_surface
            and not group["action_required"]
        ):
            continue
        if group["binding_status"] != "ambiguous":
            if group["authority_refs"]:
                group["binding_status"] = "authority-bound"
            elif group["lease_refs"]:
                group["binding_status"] = "lease-bound"
            elif group["checkout_refs"] and group["binding_status"] != "physical-only":
                group["binding_status"] = "checkout-bound"
            elif group["physical_refs"]["tmux_sessions"] or group["physical_refs"]["processes"]:
                group["binding_status"] = "physical-only"
        group["action_reasons"] = sorted(set(group["action_reasons"]))
        group["source_states"] = sorted(set(group["source_states"]))
        group["related_work_ids"] = sorted(set(group["related_work_ids"]))
        group["authority_refs"].sort(key=lambda item: _digest(item))
        group["lease_refs"].sort(key=lambda item: item["resource_key"])
        group["checkout_refs"].sort(key=lambda item: item["path"])
        group["worker_refs"].sort(key=lambda item: item["worker_id"])
        group["physical_refs"]["tmux_sessions"].sort(
            key=lambda item: item["session_name"]
        )
        group["physical_refs"]["processes"].sort(
            key=lambda item: (item.get("pid", 0), item.get("command", ""))
        )
        projected.append(group)
    projected.sort(key=_sort_key)
    return projected

def build_current_work_projection(
    *,
    tasks_payload: dict[str, Any] | None,
    resources_payload: dict[str, Any] | None,
    checkout_payloads: list[dict[str, Any]] | None,
    repository_filters: list[str],
    tmux_payload: dict[str, Any] | None,
    process_payload: dict[str, Any] | None,
    browser_payload: dict[str, Any] | None,
    gui_payload: dict[str, Any] | None,
    source_errors: list[dict[str, Any]] | None = None,
    generated_at_unix: int,
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, Any]:
    generated_at_unix = _integer(generated_at_unix, "generated_at_unix")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= PAGE_LIMIT_MAX:
        raise CurrentWorkProjectionError(
            f"limit must be between 1 and {PAGE_LIMIT_MAX}"
        )
    if not isinstance(repository_filters, list) or not 1 <= len(repository_filters) <= MAX_REPOSITORIES:
        raise CurrentWorkProjectionError(
            f"repository_filters must contain between 1 and {MAX_REPOSITORIES} repositories"
        )
    repositories = [_text(item, "repository_filter") for item in repository_filters]
    if len(repositories) != len(set(repositories)):
        raise CurrentWorkProjectionError("repository_filters must be unique")

    task_rows = _records(tasks_payload, "tasks", MAX_TASKS, "tasks")
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
        checkout_truncated |= _boolean(
            payload.get("truncated"), f"checkout_payloads[{index}].truncated"
        )
        for raw in _records(
            payload, "worktrees", MAX_WORKTREES, f"checkout[{repository}]"
        ):
            checkouts.append(_checkout(raw, repository))
        if len(checkouts) > MAX_WORKTREES:
            raise CurrentWorkProjectionError(
                f"combined worktrees exceed the bounded maximum of {MAX_WORKTREES}"
            )

    tmux = parse_tmux_sessions(tmux_payload)
    processes = parse_processes(process_payload)
    if source_errors is None:
        source_errors = []
    if not isinstance(source_errors, list) or not all(
        isinstance(item, dict) for item in source_errors
    ):
        raise CurrentWorkProjectionError("source_errors must be a list of objects")
    source_errors_truncated = len(source_errors) > 100
    errors = [dict(item) for item in source_errors[:100]]
    if tmux["errors"]:
        errors.append({"source": "tmux", "parse_errors": tmux["errors"]})
    if processes["errors"]:
        errors.append({"source": "processes", "parse_errors": processes["errors"]})

    groups: dict[str, dict[str, Any]] = {}
    tasks, task_paths = _add_tasks(groups, task_rows)
    _add_leases(groups, lease_rows, set(tasks))
    _add_workers(groups, browser_rows, gui_rows)
    _add_checkouts(groups, checkouts, tasks, task_paths)
    (
        unbound_tmux,
        unbound_tmux_total,
        unbound_processes,
        unbound_process_total,
    ) = _add_physical_surfaces(groups, tmux, processes)
    projected = _finalize_groups(groups, tasks)

    snapshot_material = {
        "groups": projected,
        "unbound_tmux": unbound_tmux,
        "unbound_processes": unbound_processes,
        "source_errors": errors,
        "repository_filters": repositories,
    }
    snapshot_sha256 = _digest(snapshot_material)
    offset = _cursor_offset(cursor, snapshot_sha256)
    if offset > len(projected):
        raise CurrentWorkProjectionError("cursor offset exceeds live snapshot")
    page = projected[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < len(projected)

    resource_count = _integer(
        resources_payload.get("count", len(lease_rows)) if resources_payload else 0,
        "resources.count",
    )
    resource_truncated = (
        resource_count > len(lease_rows)
        or _boolean(
            resources_payload.get("truncated") if resources_payload else False,
            "resources.truncated",
        )
    )
    source_truncation = {
        "tasks": _task_has_more(tasks_payload),
        "resources": resource_truncated,
        "checkouts": checkout_truncated,
        "tmux": tmux["truncated"],
        "processes": processes["truncated"],
        "browser_workers": _has_more(browser_payload, "browser"),
        "gui_workers": _has_more(gui_payload, "gui"),
        "source_errors": source_errors_truncated,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "projection": "current-operator-work",
        "generated_at_unix": generated_at_unix,
        "snapshot_sha256": snapshot_sha256,
        "repository_filters": repositories,
        "count": len(page),
        "total_projected": len(projected),
        "work": page,
        "pagination": {
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "next_cursor": (
                f"cw1.{snapshot_sha256[:32]}.{next_offset}" if has_more else None
            ),
            "snapshot_bound": True,
        },
        "source_counts": {
            "tasks": len(task_rows),
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
            "sample_truncated": (
                unbound_tmux_total > len(unbound_tmux)
                or unbound_process_total > len(unbound_processes)
            ),
        },
        "warnings": (
            ["one or more source surfaces were truncated"]
            if any(source_truncation.values())
            else []
        ),
        "recommended_next_action": (
            "inspect the first attention work item and its authority references"
            if any(group["projection_state"] == "attention" for group in projected)
            else "none"
        ),
        "does_not_establish": [
            "a new task, lease, checkout, worker, process or tmux authority",
            "permission to stop processes, release leases or remove checkouts",
            "terminal success from a tmux session or process alone",
            "absence of work beyond any explicitly truncated source",
            "historical task or worker completeness",
        ],
    }
