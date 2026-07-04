from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ENABLED_ENV = "GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX"
STATE_ROOT_ENV = "GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT"
PLEXER_EVENTS_URL_ENV = "GRABOWSKI_PLEXER_EVENTS_URL"
TASK_ENABLED_FIELD = "chronik_outbox_enabled"
TASK_STATE_ROOT_FIELD = "chronik_outbox_state_root"
TRUTHY = {"1", "true", "yes", "on"}
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}


def enabled() -> bool:
    return os.environ.get(ENABLED_ENV, "").strip().lower() in TRUTHY


def task_enabled(record: dict[str, Any]) -> bool:
    value = record.get(TASK_ENABLED_FIELD)
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in TRUTHY
    return False


def record_enabled(record: dict[str, Any]) -> bool:
    return enabled() or task_enabled(record)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def event_id(kind: str, run_id: str) -> str:
    raw = canonical_json({"schema_version": "agent-run-event.v0", "kind": kind, "run_id": run_id})
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def state_root(record: dict[str, Any] | None = None) -> Path:
    raw = None
    if record is not None:
        candidate = record.get(TASK_STATE_ROOT_FIELD)
        if isinstance(candidate, str) and candidate.strip():
            raw = candidate
    if raw is None:
        raw = os.environ.get(STATE_ROOT_ENV)
    return Path(raw).expanduser() if raw else Path.home() / ".local" / "state"


def run_id(record: dict[str, Any]) -> str:
    return f"task-{record['task_id']}-a{record['attempt']}"


def classify(state: str) -> tuple[str, dict[str, Any]] | None:
    if state in {"launching", "running"}:
        return "agent.run.started", {"result": "started"}
    if state == "completed":
        return "agent.run.completed", {"result": "completed"}
    if state in TERMINAL:
        return "agent.run.blocked", {"result": "blocked", "blocker_code": f"task-{state.replace('_', '-')}"}
    return None


def build_event(record: dict[str, Any], state: str) -> dict[str, Any] | None:
    result = classify(state)
    if result is None:
        return None
    kind, data = result
    rid = run_id(record)
    return {
        "schema_version": "agent-run-event.v0",
        "event_id": event_id(kind, rid),
        "kind": kind,
        "ts": now_z(),
        "source": {"repo": "heimgewebe/grabowski", "component": "grabowski", "run_id": rid},
        "subject": {"repo": "heimgewebe/grabowski"},
        "trust_tier": "observed" if state in TERMINAL else "declared",
        "status": "active",
        "caused_by": [],
        "evidence_refs": [f"grabowski-task:{record['task_id']}", f"grabowski-unit:{record['unit']}"],
        "data": data,
    }


def outbox_path(event: dict[str, Any], root: Path | None = None) -> Path:
    rid = event["source"]["run_id"].replace("/", "_")
    return (root or state_root()) / "grabowski" / "chronik-outbox" / f"grabowski_{rid}.jsonl"


def append_unique(path: Path, event: dict[str, Any]) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                if json.loads(line).get("event_id") == event["event_id"]:
                    return False
            except json.JSONDecodeError:
                continue
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(event))
        handle.write("\n")
    os.chmod(path, 0o600)
    return True


def record_task_state(record: dict[str, Any], state: str) -> dict[str, Any]:
    if not record_enabled(record):
        return {"enabled": False, "written": False}
    event = build_event(record, state)
    if event is None:
        return {"enabled": True, "written": False}
    path = outbox_path(event, state_root(record))
    return {"enabled": True, "written": append_unique(path, event), "path": str(path), "kind": event["kind"]}


def record_task_state_safely(record: dict[str, Any], state: str) -> dict[str, Any]:
    try:
        return record_task_state(record, state)
    except Exception as exc:
        return {"enabled": record_enabled(record), "written": False, "error": str(exc)}


def plexer_events_url(raw: str | None = None) -> str | None:
    value = raw if raw is not None else os.environ.get(PLEXER_EVENTS_URL_ENV)
    if not isinstance(value, str):
        return None
    stripped = value.strip().rstrip("/")
    if not stripped:
        return None
    if stripped.endswith("/v1/events"):
        return stripped
    return f"{stripped}/v1/events"


def send_event_to_plexer(
    event: dict[str, Any],
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    target = plexer_events_url(url)
    if target is None:
        return {"configured": False, "sent": False, "retryable": False}
    request = Request(
        target,
        data=canonical_json(event).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", response.getcode()))
        return {"configured": True, "sent": 200 <= status_code < 300, "retryable": status_code == 429 or status_code >= 500, "status_code": status_code}
    except HTTPError as exc:
        return {"configured": True, "sent": False, "retryable": exc.code == 429 or exc.code >= 500, "status_code": exc.code, "error": str(exc)}
    except (TimeoutError, URLError, OSError) as exc:
        return {"configured": True, "sent": False, "retryable": True, "error": str(exc)}


def send_event_to_plexer_safely(
    event: dict[str, Any],
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    try:
        return send_event_to_plexer(event, url=url, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return {"configured": plexer_events_url(url) is not None, "sent": False, "retryable": True, "error": str(exc)}


def flush_outbox_file_to_plexer(
    path: Path,
    url: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            results.append({"line": line_number, "sent": False, "retryable": False, "error": f"invalid json: {exc}"})
            continue
        result = send_event_to_plexer_safely(event, url=url, timeout_seconds=timeout_seconds)
        result["line"] = line_number
        results.append(result)
    return {"events": len(results), "sent": sum(1 for result in results if result.get("sent") is True), "results": results}
