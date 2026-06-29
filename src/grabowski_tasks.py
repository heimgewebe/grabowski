from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
import uuid
from typing import Any

import grabowski_fleet as fleet
import grabowski_mcp as base
import grabowski_recovery as recovery
import grabowski_resources as resources
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
TASK_OUTCOMES_DIR = TASK_DB.with_suffix(".outcomes")

TASK_ID = re.compile(r"[0-9a-f]{24}\Z")
EXTERNAL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,255}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
RESUME_POLICIES = {"never", "retry-safe", "verify-then-retry", "manual"}
TASK_STATES = {
    "launching",
    "running",
    "completed",
    "failed",
    "cancelled",
    "timed_out",
    "signalled",
    "outcome_unknown",
    "interrupted",
}


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _redact_reason(text: str) -> str:
    redact_text = getattr(operator, "_redact_text", None)
    if callable(redact_text):
        return redact_text(text)
    redact = getattr(operator, "_redact", None)
    if callable(redact):
        return redact(text)
    return text


def _is_terminal_state(state: str) -> bool:
    return state in {"completed", "failed", "cancelled", "timed_out", "signalled", "outcome_unknown"}


def _write_outcome_receipt(record: dict[str, Any], state: str, observation: dict[str, Any] | None) -> None:
    if not _is_terminal_state(state):
        return
    TASK_OUTCOMES_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = TASK_OUTCOMES_DIR / f"{record['task_id']}.json"
    if path.exists():
        return
    payload = {
        "schema_version": 1,
        "task_id": record["task_id"],
        "unit": record["unit"],
        "attempt": record["attempt"],
        "state": state,
        "argv_sha256": record["argv_sha256"],
        "execution_envelope_sha256": record.get("execution_envelope_sha256"),
        "resource_keys": _record_resource_keys(record),
        "observed_at_unix": _now(),
        "observation_sha256": _sha256_json(observation or {}),
        "observation": observation or {},
    }
    payload["receipt_sha256"] = _sha256_json({k: v for k, v in payload.items() if k != "receipt_sha256"})
    fd, tmp_name = tempfile.mkstemp(prefix=f".{record['task_id']}.", suffix=".tmp", dir=TASK_OUTCOMES_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.link(tmp_name, path)
    except FileExistsError:
        pass
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _classify_observation(result: dict[str, Any], properties: dict[str, str]) -> str:
    active = properties.get("ActiveState")
    load = properties.get("LoadState")
    unit_result = properties.get("Result")
    exec_code = properties.get("ExecMainCode")
    exec_status = properties.get("ExecMainStatus")
    if unit_result == "success" and exec_status in {None, "", "0"}:
        return "completed" if active not in {"active", "activating", "reloading"} else "running"
    if active in {"active", "activating", "reloading"}:
        return "running"
    if unit_result == "timeout":
        return "timed_out"
    if unit_result in {"signal", "core-dump"} or exec_code in {"2", "3"}:
        return "signalled"
    if unit_result in {"exit-code", "resources", "protocol", "watchdog"} or active == "failed":
        return "failed"
    if result["returncode"] != 0 or load in {None, "not-found"}:
        return "outcome_unknown"
    if active in {"inactive", "deactivating"}:
        return "completed" if unit_result in {None, "", "success"} else "failed"
    return "outcome_unknown"


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
            last_observation_json TEXT,
            resource_keys_json TEXT NOT NULL DEFAULT '[]',
            lease_owner_id TEXT,
            request_id TEXT,
            origin_ref TEXT,
            external_run_id TEXT,
            execution_envelope_sha256 TEXT,
            acceptance_json TEXT NOT NULL DEFAULT '[]',
            request_sha256 TEXT
        )
        """
    )
    current = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    if current is None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', '2')"
        )
    elif current["value"] == "1":
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(tasks)")
        }
        if "resource_keys_json" not in columns:
            connection.execute(
                "ALTER TABLE tasks ADD COLUMN resource_keys_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
        if "lease_owner_id" not in columns:
            connection.execute(
                "ALTER TABLE tasks ADD COLUMN lease_owner_id TEXT"
            )
        connection.execute(
            "UPDATE metadata SET value='2' WHERE key='schema_version'"
        )
    elif current["value"] != "2":
        connection.close()
        raise RuntimeError("Unsupported task database schema")
    connection.commit()
    try:
        os.chmod(TASK_DB, 0o600)
    except FileNotFoundError:
        connection.close()
        raise
    return connection


def _command_requires_recovery(argv: list[str]) -> bool:
    names = [Path(item).name.lower() for item in argv if isinstance(item, str)]
    if not names:
        return False
    direct = {
        "shutdown", "reboot", "poweroff", "halt", "hibernate",
        "sleep-heimserver", "sleep-heim-pc", "sleep-heimberry",
    }
    if any(name in direct for name in names[:2]):
        return True
    joined = " ".join(item.lower() for item in argv)
    power_actions = (
        "systemctl poweroff", "systemctl reboot", "systemctl suspend",
        "systemctl hibernate", "loginctl poweroff", "loginctl reboot",
        "loginctl suspend", "loginctl hibernate",
    )
    return any(action in joined for action in power_actions)


def _require_recovery_gate(argv: list[str]) -> dict[str, Any]:
    if not _command_requires_recovery(argv):
        return {"required": False, "checked_at_unix": None}
    status = recovery.recovery_status()
    if not status["ready_for_user_power_worker"]:
        actions = status.get("required_actions", [])
        detail = "; ".join(actions) if actions else "recovery evidence is incomplete"
        raise PermissionError(f"Power-worker recovery gate is not ready: {detail}")
    return {**status, "required": True}


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


def _resource_keys(values: list[str] | None) -> list[str]:
    if values is None or values == []:
        return []
    return resources.normalize_resource_keys(values)


def _lease_owner(task_id: str) -> str:
    return f"task:{_validate_task_id(task_id)}"


def _record_resource_keys(record: dict[str, Any]) -> list[str]:
    raw = record.get("resource_keys_json") or "[]"
    values = json.loads(raw)
    if not isinstance(values, list):
        raise RuntimeError("Stored task resource keys are invalid")
    return [resources.normalize_resource_key(value) for value in values]


def _release_record_resources(record: dict[str, Any]) -> dict[str, Any] | None:
    keys = _record_resource_keys(record)
    if not keys:
        return None
    owner = record.get("lease_owner_id") or _lease_owner(record["task_id"])
    return resources.release_resources(owner, keys)


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
        "resource_keys": _record_resource_keys(record),
        "lease_owner_id": record.get("lease_owner_id"),
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
        current = connection.execute(
            "SELECT * FROM tasks WHERE task_id=?", (values[-1],)
        ).fetchone()
        if current is not None and _is_terminal_state(current["state"]):
            return dict(current)
        connection.execute(
            f"UPDATE tasks SET {', '.join(updates)} WHERE task_id=?",
            values,
        )
        connection.commit()
    updated = _row(task_id)
    _write_outcome_receipt(updated, state, observation)
    return updated


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
    state = _classify_observation(result, properties)
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
    resource_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit."""
    operator._require_operator_mutation("durable_job")
    target = fleet.fleet_host(host)
    command = _validate_command(argv)
    recovery_gate = _require_recovery_gate(command)
    working_directory = _validate_cwd(host, cwd)
    runtime = operator._job_runtime(runtime_seconds)
    policy = _validate_resume_policy(resume_policy)
    cpu, io = _validate_weights(cpu_weight, io_weight)
    memory = _validate_memory(memory_max_bytes)
    task_resources = _resource_keys(resource_keys)
    task_id = uuid.uuid4().hex[:24]
    lease_owner = _lease_owner(task_id)
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
        "resource_keys_json": _canonical_json(task_resources),
        "lease_owner_id": lease_owner,
    }
    lease_result = None
    if task_resources:
        lease_result = resources.acquire_resources(
            lease_owner,
            task_resources,
            purpose=f"persistent task {task_id}",
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                max(resources.MIN_TTL_SECONDS, runtime + 300),
            ),
            metadata={"task_id": task_id, "host": host, "attempt": attempt},
        )
    try:
        with _database() as connection:
            connection.execute(
            """
            INSERT INTO tasks(
                task_id, host, unit, attempt, state, resume_policy,
                argv_json, argv_sha256, cwd, runtime_seconds,
                cpu_weight, io_weight, memory_max_bytes,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json, resource_keys_json, lease_owner_id
            ) VALUES(
                :task_id, :host, :unit, :attempt, :state, :resume_policy,
                :argv_json, :argv_sha256, :cwd, :runtime_seconds,
                :cpu_weight, :io_weight, :memory_max_bytes,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json, :resource_keys_json, :lease_owner_id
            )
            """,
                record,
            )
            connection.commit()
    except Exception:
        if task_resources:
            resources.release_resources(lease_owner, task_resources)
        raise
    launcher = _dispatch(host, _launch_argv(record), timeout_seconds=60)
    state = "running" if launcher["returncode"] == 0 else "failed"
    stored = _set_state(task_id, state, launcher=launcher)
    if launcher["returncode"] != 0:
        _release_record_resources(stored)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-start",
        "task_id": task_id,
        "host": host,
        "transport": target["transport"],
        "argv_sha256": record["argv_sha256"],
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
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
    if observation["state"] not in {"launching", "running"}:
        _release_record_resources(stored)
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
    if result["returncode"] == 0:
        _release_record_resources(stored)
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
    command = json.loads(record["argv_json"])
    recovery_gate = _require_recovery_gate(command)
    observation = _observe(record)
    if observation["state"] == "running":
        raise RuntimeError("Task is still running")
    attempt = int(record["attempt"]) + 1
    unit = _task_unit(task_id, attempt)
    candidate = {**record, "attempt": attempt, "unit": unit}
    task_resources = _record_resource_keys(record)
    lease_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    lease_result = None
    if task_resources:
        lease_result = resources.acquire_resources(
            lease_owner,
            task_resources,
            purpose=f"persistent task {task_id}",
            ttl_seconds=min(
                resources.MAX_TTL_SECONDS,
                max(resources.MIN_TTL_SECONDS, int(record["runtime_seconds"]) + 300),
            ),
            metadata={
                "task_id": task_id,
                "host": record["host"],
                "attempt": attempt,
            },
        )
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
    if launcher["returncode"] != 0:
        _release_record_resources(stored)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-resume",
        "task_id": task_id,
        "host": record["host"],
        "attempt": attempt,
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


def _reconcile_candidate_rows(task_id: str = "") -> list[dict[str, Any]]:
    if task_id:
        record = _row(task_id)
        return [record] if record["state"] in {"launching", "running"} else []
    with _database() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE state IN ('launching', 'running') "
            "ORDER BY created_at_unix, task_id"
        ).fetchall()
    return [dict(row) for row in rows]


def _reconcile_blocker(record: dict[str, Any], observation: dict[str, Any]) -> dict[str, Any] | None:
    if observation["state"] == "running":
        return None
    if observation["state"] == "completed":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "completed task does not require resume",
        }
    if observation["state"] == "outcome_unknown":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "outcome_unknown requires verification before retry",
        }
    if record["resume_policy"] != "retry-safe":
        return {
            "task_id": record["task_id"],
            "resume_policy": record["resume_policy"],
            "reason": "automatic resume requires retry-safe policy",
        }
    return None


def reconcile_tasks_check(*, task_id: str = "") -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    rows = _reconcile_candidate_rows(task_id)
    observations: list[dict[str, Any]] = []
    would_refresh: list[dict[str, Any]] = []
    would_release: list[str] = []
    would_resume: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for record in rows:
        observation = _observe(record)
        item = {
            "task_id": record["task_id"],
            "current_state": record["state"],
            "observed_state": observation["state"],
            "resume_policy": record["resume_policy"],
            "resource_keys": _record_resource_keys(record),
        }
        observations.append(item)
        if observation["state"] != record["state"]:
            would_refresh.append(item)
        if observation["state"] not in {"launching", "running"}:
            would_release.append(record["task_id"])
        blocker = _reconcile_blocker(record, observation)
        if blocker is not None:
            blocked.append(blocker)
        elif observation["state"] != "running":
            would_resume.append(item)
    return {
        "mode": "check",
        "task_id": task_id,
        "scanned": len(rows),
        "observations": observations,
        "would_refresh": would_refresh,
        "would_release": would_release,
        "would_resume": would_resume,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }


def reconcile_tasks_refresh(*, task_id: str = "") -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    rows = _reconcile_candidate_rows(task_id)
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    for record in rows:
        observation = _observe(record)
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if observation["state"] not in {"launching", "running"}:
            _release_record_resources(stored)
            released.append(stored["task_id"])
        refreshed.append(_public(stored))
    return {
        "mode": "refresh",
        "task_id": task_id,
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": [],
        "blocked": [],
        "checked_at_unix": _now(),
    }


def reconcile_tasks_resume(
    *,
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    if not isinstance(task_id, str):
        raise ValueError("task_id must be a string")
    if task_id:
        _validate_task_id(task_id)
    if not isinstance(max_resumes, int) or not 1 <= max_resumes <= 50:
        raise ValueError("max_resumes must be between 1 and 50")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason is required for task reconcile resume")
    rows = _reconcile_candidate_rows(task_id)
    refreshed: list[dict[str, Any]] = []
    released: list[str] = []
    resumed: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for record in rows:
        observation = _observe(record)
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if observation["state"] not in {"launching", "running"}:
            _release_record_resources(stored)
            released.append(stored["task_id"])
        refreshed.append(_public(stored))
        if observation["state"] == "running":
            continue
        blocker = _reconcile_blocker(stored, observation)
        if blocker is not None:
            blocked.append(blocker)
            continue
        if len(resumed) >= max_resumes:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": "max_resumes reached",
                }
            )
            continue
        try:
            resumed.append(grabowski_task_resume(stored["task_id"])["task"])
        except Exception as exc:
            blocked.append(
                {
                    "task_id": stored["task_id"],
                    "resume_policy": stored["resume_policy"],
                    "reason": _redact_reason(str(exc)),
                }
            )
    return {
        "mode": "resume",
        "task_id": task_id,
        "max_resumes": max_resumes,
        "reason": _redact_reason(reason.strip()),
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": resumed,
        "blocked": blocked,
        "checked_at_unix": _now(),
    }


def reconcile_tasks(*, auto_resume: bool = False) -> dict[str, Any]:
    if not isinstance(auto_resume, bool):
        raise ValueError("auto_resume must be boolean")
    if auto_resume:
        result = reconcile_tasks_resume(
            max_resumes=50,
            reason="legacy auto_resume reconcile",
        )
    else:
        result = reconcile_tasks_refresh()
    return {
        "auto_resume": auto_resume,
        "scanned": result["scanned"],
        "refreshed": result["refreshed"],
        "resumed": result["resumed"],
        "blocked": result["blocked"],
        "checked_at_unix": result["checked_at_unix"],
    }


@mcp.tool(name="grabowski_task_reconcile_check", annotations=READ_ONLY)
def grabowski_task_reconcile_check(task_id: str = "") -> dict[str, Any]:
    """Read-only reconcile preview for persistent tasks."""
    operator._require_operator_capability("durable_job")
    return reconcile_tasks_check(task_id=task_id)


@mcp.tool(name="grabowski_task_reconcile_refresh", annotations=MUTATING)
def grabowski_task_reconcile_refresh(task_id: str = "") -> dict[str, Any]:
    """Refresh persistent task states without resuming processes."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks_refresh(task_id=task_id)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile-refresh",
            "task_id": task_id,
            "scanned": result["scanned"],
            "released_count": len(result["released"]),
        }
    )
    return result


@mcp.tool(name="grabowski_task_reconcile_resume", annotations=MUTATING)
def grabowski_task_reconcile_resume(
    task_id: str = "",
    max_resumes: int = 1,
    reason: str = "",
) -> dict[str, Any]:
    """Resume retry-safe tasks after reconcile verification."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks_resume(
        task_id=task_id,
        max_resumes=max_resumes,
        reason=reason,
    )
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile-resume",
            "task_id": task_id,
            "max_resumes": max_resumes,
            "reason": result["reason"],
            "scanned": result["scanned"],
            "resumed_count": len(result["resumed"]),
            "blocked_count": len(result["blocked"]),
        }
    )
    return result


@mcp.tool(name="grabowski_task_reconcile", annotations=MUTATING)
def grabowski_task_reconcile(auto_resume: bool = False) -> dict[str, Any]:
    """Reconcile persistent tasks after process loss or host restart."""
    operator._require_operator_mutation("durable_job")
    result = reconcile_tasks(auto_resume=auto_resume)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": "task-reconcile",
            "auto_resume": auto_resume,
            "scanned": result["scanned"],
            "resumed_count": len(result["resumed"]),
            "blocked_count": len(result["blocked"]),
        }
    )
    return result


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
