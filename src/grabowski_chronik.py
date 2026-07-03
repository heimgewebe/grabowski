from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ENABLED_ENV = "GRABOWSKI_CHRONIK_AGENT_RUN_OUTBOX"
STATE_ROOT_ENV = "GRABOWSKI_CHRONIK_OUTBOX_STATE_ROOT"
TRUTHY = {"1", "true", "yes", "on"}
TERMINAL = {"completed", "failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}


def enabled() -> bool:
    return os.environ.get(ENABLED_ENV, "").strip().lower() in TRUTHY


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def event_id(kind: str, run_id: str) -> str:
    raw = canonical_json({"schema_version": "agent-run-event.v0", "kind": kind, "run_id": run_id})
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def state_root() -> Path:
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


def outbox_path(event: dict[str, Any]) -> Path:
    rid = event["source"]["run_id"].replace("/", "_")
    return state_root() / "grabowski" / "chronik-outbox" / f"grabowski_{rid}.jsonl"


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
    if not enabled():
        return {"enabled": False, "written": False}
    event = build_event(record, state)
    if event is None:
        return {"enabled": True, "written": False}
    path = outbox_path(event)
    return {"enabled": True, "written": append_unique(path, event), "path": str(path), "kind": event["kind"]}


def record_task_state_safely(record: dict[str, Any], state: str) -> dict[str, Any]:
    try:
        return record_task_state(record, state)
    except Exception as exc:
        return {"enabled": enabled(), "written": False, "error": str(exc)}
