from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from typing import Any

import grabowski_fleet as fleet
import grabowski_mcp as base
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
TASK_DB = Path(
    os.environ.get(
        "GRABOWSKI_TASK_DB",
        str(operator.STATE_DIR / "tasks.sqlite3"),
    )
).expanduser()
TASK_ID = re.compile(r"[0-9a-f]{24}\Z")
UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
RESUME_POLICIES = {"never", "retry-safe", "verify-then-retry", "manual"}
TASK_STATES = {
    "launching",
    "running",
    "completed",
    "failed",
    "cancelled",
    "interrupted",
}


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _database() -> sqlite3.Connection:
    parent = TASK_DB.parent
    if parent.is_symlink():
        raise PermissionError(f"Task state directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if TASK_DB.is_symlink():
        raise PermissionError(f"Task database may not be a symlink: {TASK_DB}")
    connection = sqlite3.connect(TASK_DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            unit TEXT NOT NULL,
            attempt INTEGER NOT NULL,
            state TEXT NOT NULL,
            resume_policy TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            argv_sha256 TEXT NOT NULL,
            cwd TEXT NOT NULL,
            runtime_seconds INTEGER NOT NULL,
            cpu_weight INTEGER NOT NULL,
            io_weight INTEGER NOT NULL,
            memory_max_bytes INTEGER,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            launcher_json TEXT NOT NULL,
            last_observation_json TEXT
        )
        """
    )
    current = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    if current is None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
        )
    elif current["value"] != "1":
        connection.close()
        raise RuntimeError("Unsupported task database schema")
    connection.commit()
    try:
        os.chmod(TASK_DB, 0o600)
    except FileNotFoundError:
        connection.close()
        raise
    return connection


def _validate_task_id(task_id: str) -> str:
    if not isinstance(task_id, str) or TASK_ID.fullmatch(task_id) is None:
        raise ValueError("Invalid task id")
    return task_id


def _validate_unit(unit: str) -> str:
    if UNIT.fullmatch(unit) is None:
        raise ValueError("Invalid task unit")
    return unit


def _task_unit(task_id: str, attempt: int) -> str:
    if attempt < 1:
        raise ValueError("Task attempt must be positive")
    return f"grabowski-task-{task_id}-a{attempt}.service"


def _validate_cwd(host: str, raw: str | None) -> str:
    candidate = str(operator.HOME) if raw is None else raw
    if not isinstance(candidate, str) or not candidate.startswith("/"):
        raise ValueError("Task cwd must be an absolute path")
    if len(candidate.encode("utf-8")) > 4096 or "\x00" in candidate:
        raise ValueError("Task cwd is too large or contains NUL")
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        return str(operator._resolve_cwd(candidate))
    return candidate


def _validate_weights(cpu_weight: int, io_weight: int) -> tuple[int, int]:
    if not isinstance(cpu_weight, int) or not 1 <= cpu_weight <= 10_000:
        raise ValueError("cpu_weight must be between 1 and 10000")
    if not isinstance(io_weight, int) or not 1 <= io_weight <= 10_000:
        raise ValueError("io_weight must be between 1 and 10000")
    return cpu_weight, io_weight


def _validate_memory(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or value < 16 * 1024 * 1024:
        raise ValueError("memory_max_bytes must be at least 16 MiB")
    return value


def _validate_resume_policy(value: str) -> str:
    if value not in RESUME_POLICIES:
        raise ValueError(f"resume_policy must be one of {sorted(RESUME_POLICIES)}")
    return value


def _validate_command(argv: list[str]) -> list[str]:
    command = operator._validate_argv(argv, cwd=operator.HOME)
    if operator._redact_argv(command) != command:
        raise ValueError("Task argv appears to contain secret material")
    return command


def _dispatch(host: str, argv: list[str], *, timeout_seconds: int = 60) -> dict[str, Any]:
    target = fleet.fleet_host(host)
    if target["transport"] == "local":
        return operator._run(
            argv,
            cwd=operator.HOME,
            timeout_seconds=timeout_seconds,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    remote = fleet.run_fleet_host(
        host,
        argv,
        timeout_seconds=timeout_seconds,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    return remote["result"]


def _launch_argv(record: dict[str, Any]) -> list[str]:
    command = json.loads(record["argv_json"])
    unit = _validate_unit(record["unit"])
    argv = [
        "systemd-run",
        "--user",
        "--unit",
        unit,
        "--slice=grabowski-tasks.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=NoNewPrivileges=no",
        "--property=ProtectSystem=off",
        "--property=ProtectHome=no",
        "--property=PrivateTmp=no",
        "--property=MemoryDenyWriteExecute=no",
        "--property=UMask=0077",
        f"--property=RuntimeMaxSec={record['runtime_seconds']}s",
        f"--property=WorkingDirectory={record['cwd']}",
        f"--property=CPUWeight={record['cpu_weight']}",
        f"--property=IOWeight={record['io_weight']}",
    ]
    if record["memory_max_bytes"] is not None:
        argv.append(f"--property=MemoryMax={record['memory_max_bytes']}")
    return [*argv, "--", *command]


def _row(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (identifier,)
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown task: {identifier}")
    return dict(row)


def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "attempt": record["attempt"],
        "state": record["state"],
        "resume_policy": record["resume_policy"],
        "argv": operator._redact_argv(json.loads(record["argv_json"])),
        "argv_sha256": record["argv_sha256"],
        "cwd": record["cwd"],
        "runtime_seconds": record["runtime_seconds"],
        "cpu_weight": record["cpu_weight"],
        "io_weight": record["io_weight"],
        "memory_max_bytes": record["memory_max_bytes"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "launcher": json.loads(record["launcher_json"]),
        "last_observation": (
            json.loads(record["last_observation_json"])
            if record["last_observation_json"]
            else None
        ),
    }


def _set_state(
    task_id: str,
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    attempt: int | None = None,
) -> dict[str, Any]:
    if state not in TASK_STATES:
        raise ValueError("Invalid task state")
    updates = ["state=?", "updated_at_unix=?"]
    values: list[Any] = [state, _now()]
    if launcher is not None:
        updates.append("launcher_json=?")
        values.append(_canonical_json(launcher))
    if observation is not None:
        updates.append("last_observation_json=?")
        values.append(_canonical_json(observation))
    if unit is not None:
        updates.append("unit=?")
        values.append(_validate_unit(unit))
    if attempt is not None:
        updates.append("attempt=?")
        values.append(attempt)
    values.append(_validate_task_id(task_id))
    with _database() as connection:
        connection.execute(
            f"UPDATE tasks SET {', '.join(updates)} WHERE task_id=?",
            values,
        )
        connection.commit()
    return _row(task_id)


def _observe(record: dict[str, Any]) -> dict[str, Any]:
    result = _dispatch(
        record["host"],
        [
            "systemctl",
            "--user",
            "show",
            record["unit"],
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
        ],
        timeout_seconds=30,
    )
    properties: dict[str, str] = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    active = properties.get("ActiveState")
    load = properties.get("LoadState")
    unit_result = properties.get("Result")
    if result["returncode"] != 0 or load in {None, "not-found"}:
        state = "interrupted"
    elif active in {"active", "activating", "reloading"}:
        state = "running"
    elif active == "failed" or unit_result not in {None, "", "success"}:
        state = "failed"
    elif active in {"inactive", "deactivating"}:
        state = "completed" if unit_result in {None, "", "success"} else "failed"
    else:
        state = "interrupted"
    return {
        "state": state,
        "properties": properties,
        "probe": result,
        "observed_at_unix": _now(),
    }


@mcp.tool(name="grabowski_task_start", annotations=MUTATING)
def grabowski_task_start(
    host: str,
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = operator.DEFAULT_JOB_RUNTIME,
    resume_policy: str = "verify-then-retry",
    cpu_weight: int = 100,
    io_weight: int = 100,
    memory_max_bytes: int | None = None,
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit."""
    operator._require_operator_mutation("durable_job")
    target = fleet.fleet_host(host)
    command = _validate_command(argv)
    working_directory = _validate_cwd(host, cwd)
    runtime = operator._job_runtime(runtime_seconds)
    policy = _validate_resume_policy(resume_policy)
    cpu, io = _validate_weights(cpu_weight, io_weight)
    memory = _validate_memory(memory_max_bytes)
    task_id = uuid.uuid4().hex[:24]
    attempt = 1
    unit = _task_unit(task_id, attempt)
    now = _now()
    record = {
        "task_id": task_id,
        "host": host,
        "unit": unit,
        "attempt": attempt,
        "state": "launching",
        "resume_policy": policy,
        "argv_json": _canonical_json(command),
        "argv_sha256": _sha256_json(command),
        "cwd": working_directory,
        "runtime_seconds": runtime,
        "cpu_weight": cpu,
        "io_weight": io,
        "memory_max_bytes": memory,
        "created_at_unix": now,
        "updated_at_unix": now,
        "launcher_json": _canonical_json({"pending": True}),
        "last_observation_json": None,
    }
    with _database() as connection:
        connection.execute(
            """
            INSERT INTO tasks(
                task_id, host, unit, attempt, state, resume_policy,
                argv_json, argv_sha256, cwd, runtime_seconds,
                cpu_weight, io_weight, memory_max_bytes,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json
            ) VALUES(
                :task_id, :host, :unit, :attempt, :state, :resume_policy,
                :argv_json, :argv_sha256, :cwd, :runtime_seconds,
                :cpu_weight, :io_weight, :memory_max_bytes,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json
            )
            """,
            record,
        )
        connection.commit()
    launcher = _dispatch(host, _launch_argv(record), timeout_seconds=60)
    state = "running" if launcher["returncode"] == 0 else "failed"
    stored = _set_state(task_id, state, launcher=launcher)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-start",
        "task_id": task_id,
        "host": host,
        "transport": target["transport"],
        "argv_sha256": record["argv_sha256"],
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


@mcp.tool(name="grabowski_task_status", annotations=READ_ONLY)
def grabowski_task_status(task_id: str) -> dict[str, Any]:
    """Observe one persistent task and refresh its recorded state."""
    operator._require_operator_capability("durable_job")
    record = _row(task_id)
    observation = _observe(record)
    stored = _set_state(
        task_id,
        observation["state"],
        observation=observation,
    )
    return _public(stored)


@mcp.tool(name="grabowski_task_logs", annotations=READ_ONLY)
def grabowski_task_logs(task_id: str, max_lines: int = 200) -> dict[str, Any]:
    """Read redacted journal output for one local or fleet task."""
    operator._require_operator_capability("durable_job")
    if not isinstance(max_lines, int) or not 1 <= max_lines <= 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    record = _row(task_id)
    result = _dispatch(
        record["host"],
        [
            "journalctl",
            "--user",
            "--unit",
            record["unit"],
            "--no-pager",
            "--output=cat",
            "--lines",
            str(max_lines),
        ],
        timeout_seconds=30,
    )
    return {
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "result": result,
    }


@mcp.tool(name="grabowski_task_cancel", annotations=MUTATING)
def grabowski_task_cancel(task_id: str) -> dict[str, Any]:
    """Stop one task process group and retain its persistent task record."""
    operator._require_operator_mutation("durable_job")
    record = _row(task_id)
    result = _dispatch(
        record["host"],
        ["systemctl", "--user", "stop", record["unit"]],
        timeout_seconds=60,
    )
    state = "cancelled" if result["returncode"] == 0 else record["state"]
    stored = _set_state(task_id, state, observation={"cancel": result})
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-cancel",
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "returncode": result["returncode"],
    }
    base._append_audit(audit)
    return {"task": _public(stored), "result": result, "audit": audit}


@mcp.tool(name="grabowski_task_resume", annotations=MUTATING)
def grabowski_task_resume(task_id: str) -> dict[str, Any]:
    """Recreate a missing or stopped task unit from its persistent record."""
    operator._require_operator_mutation("durable_job")
    record = _row(task_id)
    if record["resume_policy"] in {"never", "manual"}:
        raise PermissionError("Task resume policy does not permit automatic retry")
    observation = _observe(record)
    if observation["state"] == "running":
        raise RuntimeError("Task is still running")
    attempt = int(record["attempt"]) + 1
    unit = _task_unit(task_id, attempt)
    candidate = {**record, "attempt": attempt, "unit": unit}
    launcher = _dispatch(record["host"], _launch_argv(candidate), timeout_seconds=60)
    state = "running" if launcher["returncode"] == 0 else "failed"
    stored = _set_state(
        task_id,
        state,
        launcher=launcher,
        observation=observation,
        unit=unit,
        attempt=attempt,
    )
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-resume",
        "task_id": task_id,
        "host": record["host"],
        "attempt": attempt,
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


@mcp.tool(name="grabowski_task_list", annotations=READ_ONLY)
def grabowski_task_list(
    limit: int = 50,
    state: str | None = None,
) -> dict[str, Any]:
    """List recent persistent task records, optionally filtered by state."""
    operator._require_operator_capability("durable_job")
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    if state is not None and state not in TASK_STATES:
        raise ValueError(f"state must be one of {sorted(TASK_STATES)}")
    with _database() as connection:
        if state is None:
            rows = connection.execute(
                "SELECT * FROM tasks ORDER BY created_at_unix DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM tasks WHERE state=? "
                "ORDER BY created_at_unix DESC LIMIT ?",
                (state, limit),
            ).fetchall()
    return {
        "database": str(TASK_DB),
        "count": len(rows),
        "tasks": [_public(dict(row)) for row in rows],
    }
