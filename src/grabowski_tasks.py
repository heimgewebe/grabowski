from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
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
import grabowski_chronik as chronik
import grabowski_privileged as privileged
import grabowski_recovery as recovery
import grabowski_resources as resources
import grabowski_consumer_surface as consumer_surface
import grabowski_command_identity as command_identity
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
# Deliberately canonical: only names emitted by _task_unit are accepted.
# Manual or future-format units must never be adopted as authoritative by accident.
UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
RESUME_POLICIES = {"never", "retry-safe", "verify-then-retry", "manual"}
CHRONIK_OPERATION_TASK_CLASS = {
    "implement": "coding",
    "review": "review",
    "merge": "merge",
    "deploy": "deploy",
    "runtime_verify": "runtime_verify",
    "recovery": "recovery",
    "other": "other",
}
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
TASK_STATE_PROJECTIONS: dict[str, tuple[str, ...]] = {
    "active": ("launching", "running", "interrupted"),
    "attention": ("interrupted", "outcome_unknown", "failed", "timed_out", "signalled"),
    "terminal": ("completed", "failed", "cancelled", "timed_out", "signalled"),
}
MUTATING_AGENT_EXECUTABLES = frozenset({"agy", "claude", "cline", "codex"})
READ_ONLY_AGENT_MODES = frozenset({"plan", "read-only"})
TASK_EXECUTION_BACKENDS = {"systemd-user", "systemd-root-broker"}
SYSTEMD_SCOPES = {"user", "system"}
ACTIVE_TASK_STATES = {"running", "outcome_unknown"}
TASK_LEASE_DELEGATION_STATES = frozenset({"running"})


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
    return state in {"completed", "failed", "cancelled", "timed_out", "signalled"}


def _state_releases_resources(state: str) -> bool:
    return _is_terminal_state(state)


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
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
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

    def table_exists(name: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone() is not None

    def schema_version() -> str | None:
        if not table_exists("metadata"):
            return None
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
        return str(row["value"]) if row is not None else None

    def task_columns() -> set[str]:
        if not table_exists("tasks"):
            return set()
        return {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(tasks)")
        }

    def task_indexes() -> set[str]:
        if not table_exists("tasks"):
            return set()
        return {
            str(row["name"])
            for row in connection.execute("PRAGMA index_list(tasks)")
        }

    required_columns = {
        "task_id", "host", "unit", "attempt", "state", "resume_policy",
        "argv_json", "argv_sha256", "cwd", "runtime_seconds",
        "cpu_weight", "io_weight", "memory_max_bytes",
        "created_at_unix", "updated_at_unix", "launcher_json",
        "last_observation_json", "resource_keys_json", "lease_owner_id",
        "request_id", "origin_ref", "external_run_id",
        "execution_envelope_sha256", "acceptance_json", "request_sha256",
        "execution_backend", "systemd_scope", "authoritative_unit",
        "chronik_outbox_enabled", "chronik_outbox_state_root",
        "chronik_context_json",
    }
    required_indexes = {
        "tasks_state_created_task_idx",
        "tasks_created_task_idx",
    }

    version = schema_version()
    if version not in {None, "1", "2", "3"}:
        connection.close()
        raise RuntimeError("Unsupported task database schema")

    # Established schema-3 databases stay read-only here. Migration writes,
    # backfills, index creation and the version flip are serialized together.
    if version != "3":
        connection.execute("BEGIN IMMEDIATE")
        try:
            # Re-read after acquiring the writer lock because another process
            # may have completed the migration while this connection waited.
            version = schema_version()
            if version not in {None, "1", "2", "3"}:
                raise RuntimeError("Unsupported task database schema")
            if version is None:
                if table_exists("metadata") or table_exists("tasks"):
                    raise RuntimeError(
                        "Task database schema metadata is missing from an existing database"
                    )
                connection.execute(
                    """
                    CREATE TABLE metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE tasks (
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
                        request_sha256 TEXT,
                        execution_backend TEXT NOT NULL DEFAULT 'systemd-user',
                        systemd_scope TEXT NOT NULL DEFAULT 'user',
                        authoritative_unit TEXT,
                        chronik_outbox_enabled INTEGER NOT NULL DEFAULT 0,
                        chronik_outbox_state_root TEXT,
                        chronik_context_json TEXT
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', '3')"
                )
            elif version in {"1", "2"}:
                if not table_exists("metadata") or not table_exists("tasks"):
                    raise RuntimeError("Legacy task database is structurally incomplete")
                columns = task_columns()
                additions = (
                    ("resource_keys_json", "TEXT NOT NULL DEFAULT '[]'"),
                    ("lease_owner_id", "TEXT"),
                    ("request_id", "TEXT"),
                    ("origin_ref", "TEXT"),
                    ("external_run_id", "TEXT"),
                    ("execution_envelope_sha256", "TEXT"),
                    ("acceptance_json", "TEXT NOT NULL DEFAULT '[]'"),
                    ("request_sha256", "TEXT"),
                    ("chronik_outbox_enabled", "INTEGER NOT NULL DEFAULT 0"),
                    ("chronik_outbox_state_root", "TEXT"),
                    ("chronik_context_json", "TEXT"),
                    ("execution_backend", "TEXT NOT NULL DEFAULT 'systemd-user'"),
                    ("systemd_scope", "TEXT NOT NULL DEFAULT 'user'"),
                    ("authoritative_unit", "TEXT"),
                )
                for name, definition in additions:
                    if name not in columns:
                        connection.execute(
                            f"ALTER TABLE tasks ADD COLUMN {name} {definition}"
                        )
                # Newly added NOT NULL columns already expose their SQLite
                # defaults for every legacy row. Only repair these fields when
                # they pre-existed, which preserves recovery from a partial
                # migration without forcing two avoidable full-table writes.
                if "execution_backend" in columns:
                    connection.execute(
                        "UPDATE tasks SET execution_backend='systemd-user' "
                        "WHERE execution_backend IS NULL OR execution_backend=''"
                    )
                if "systemd_scope" in columns:
                    connection.execute(
                        "UPDATE tasks SET systemd_scope='user' "
                        "WHERE systemd_scope IS NULL OR systemd_scope=''"
                    )
                connection.execute(
                    "UPDATE tasks SET authoritative_unit=unit "
                    "WHERE authoritative_unit IS NULL OR authoritative_unit=''"
                )
                connection.execute(
                    "UPDATE metadata SET value='3' WHERE key='schema_version'"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_state_created_task_idx "
                "ON tasks(state, created_at_unix DESC, task_id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS tasks_created_task_idx "
                "ON tasks(created_at_unix DESC, task_id DESC)"
            )
            connection.commit()
        except Exception:
            connection.rollback()
            connection.close()
            raise

    missing_columns = required_columns - task_columns()
    if missing_columns:
        connection.close()
        raise RuntimeError(
            "Task database schema 3 is incomplete: "
            + ", ".join(sorted(missing_columns))
        )
    missing_indexes = required_indexes - task_indexes()
    if missing_indexes:
        connection.close()
        raise RuntimeError(
            "Task database schema 3 indexes are incomplete: "
            + ", ".join(sorted(missing_indexes))
        )
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


def _validate_execution_backend(value: str) -> str:
    if value not in TASK_EXECUTION_BACKENDS:
        raise ValueError("Invalid task execution backend")
    return value


def _validate_systemd_scope(value: str) -> str:
    if value not in SYSTEMD_SCOPES:
        raise ValueError("Invalid task systemd scope")
    return value


def _execution_backend(record: dict[str, Any]) -> str:
    return _validate_execution_backend(record.get("execution_backend") or "systemd-user")


def _systemd_scope(record: dict[str, Any]) -> str:
    return _validate_systemd_scope(record.get("systemd_scope") or "user")


def _authoritative_unit(record: dict[str, Any]) -> str:
    return _validate_unit(record.get("authoritative_unit") or record["unit"])


def _is_root_systemd_backend(record: dict[str, Any]) -> bool:
    return _execution_backend(record) == "systemd-root-broker"


def _execution_contract(target: dict[str, Any], command: list[str]) -> tuple[str, str]:
    if target["transport"] == "local" and _command_requires_recovery(command):
        return "systemd-root-broker", "system"
    return "systemd-user", "user"


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


def _validate_chronik_outbox(
    enabled: bool,
    state_root: str | None,
) -> tuple[int, str | None]:
    if not isinstance(enabled, bool):
        raise ValueError("chronik_outbox must be boolean")
    if state_root in {None, ""}:
        return (1 if enabled else 0), None
    if not enabled:
        raise ValueError("chronik_outbox_state_root requires chronik_outbox")
    if not isinstance(state_root, str) or not state_root.startswith("/"):
        raise ValueError("chronik_outbox_state_root must be an absolute path")
    if len(state_root.encode("utf-8")) > 4096 or "\x00" in state_root:
        raise ValueError("chronik_outbox_state_root is too large or contains NUL")
    return 1, state_root


def _validate_chronik_operation(value: str, *, enabled: bool) -> str:
    if not isinstance(value, str) or value not in CHRONIK_OPERATION_TASK_CLASS:
        raise ValueError(
            f"chronik_operation must be one of {sorted(CHRONIK_OPERATION_TASK_CLASS)}"
        )
    if value != "other" and not enabled:
        raise ValueError("chronik_operation requires chronik_outbox")
    return value


def _validate_resume_policy(value: str) -> str:
    if value not in RESUME_POLICIES:
        raise ValueError(f"resume_policy must be one of {sorted(RESUME_POLICIES)}")
    return value


def _resource_keys(values: list[str] | None) -> list[str]:
    if values is None or values == []:
        return []
    return resources.normalize_resource_keys(values)


def _argument_value(argv: list[str], *names: str) -> str | None:
    for index, item in enumerate(argv):
        if item in names:
            if index + 1 >= len(argv):
                return None
            return argv[index + 1]
        for name in names:
            prefix = f"{name}="
            if item.startswith(prefix):
                return item[len(prefix):]
    return None


def _local_workspace_path(raw: str | None, *, cwd: str) -> str:
    candidate = Path(cwd) if raw in {None, ""} else Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    resolved = Path(operator._resolve_cwd(str(candidate)))
    for current in (resolved, *resolved.parents):
        marker = current / ".git"
        if marker.is_symlink():
            continue
        if marker.is_file() or marker.is_dir():
            return str(current)
    return str(resolved)


def _mutating_agent_workspace(
    host: str,
    argv: list[str],
    *,
    cwd: str,
) -> str | None:
    if fleet.fleet_host(host)["transport"] != "local":
        return None
    executable = Path(argv[0]).name.lower()
    if executable == "codex":
        sandbox = _argument_value(argv, "--sandbox", "-s")
        if sandbox in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(_argument_value(argv, "-C", "--cd"), cwd=cwd)
    if executable in MUTATING_AGENT_EXECUTABLES - {"codex"}:
        permission_mode = _argument_value(argv, "--permission-mode")
        if permission_mode in READ_ONLY_AGENT_MODES:
            return None
        return _local_workspace_path(None, cwd=cwd)
    # Framework-managed writers already hold a workspace-level lease owned by
    # their workspace lifecycle. Inferring a second task-owned lease here would
    # make the formal workspace deadlock against itself.
    return None


def _task_resource_keys(
    host: str,
    argv: list[str],
    *,
    cwd: str,
    requested: list[str],
) -> tuple[list[str], str | None]:
    workspace = _mutating_agent_workspace(host, argv, cwd=cwd)
    if workspace is None:
        return requested, None
    if any(key.startswith(("path:", "repo:")) for key in requested):
        return requested, None
    implicit = resources.normalize_resource_key(f"repo:{workspace}")
    return sorted({*requested, implicit}), implicit


def _chronik_context(host: str, resource_keys: list[str], operation: str) -> str:
    context: dict[str, str] = {
        "subject_scope": "host",
        "host": host,
        "operation": operation,
        "task_class": CHRONIK_OPERATION_TASK_CLASS[operation],
    }
    if fleet.fleet_host(host)["transport"] != "local":
        return _canonical_json(context)
    repositories = [key.removeprefix("repo:") for key in resource_keys if key.startswith("repo:")]
    if len(repositories) != 1:
        return _canonical_json(context)
    result = operator._run(
        ["git", "-C", repositories[0], "config", "--get", "remote.origin.url"],
        cwd=operator.HOME, timeout_seconds=5, max_output_bytes=4096,
    )
    if result["returncode"] != 0:
        return _canonical_json(context)
    remote = result["stdout"].strip()
    match = re.search(r"(?:github\.com[:/])(?P<slug>[^/\s]+/[^/\s]+?)(?:\.git)?$", remote)
    if match is None or not match.group("slug").startswith("heimgewebe/"):
        return _canonical_json(context)
    return _canonical_json({
        "subject_scope": "repository",
        "repo": match.group("slug"),
        "operation": operation,
        "task_class": CHRONIK_OPERATION_TASK_CLASS[operation],
    })


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


def _task_lease_ttl(record: dict[str, Any], state: str) -> int:
    if state == "outcome_unknown":
        # Unknown root truth must remain protected long enough for operator
        # recovery, but the lease is still bounded and therefore not permanent.
        return resources.MAX_TTL_SECONDS
    return min(
        resources.MAX_TTL_SECONDS,
        max(
            resources.MIN_TTL_SECONDS,
            int(record["runtime_seconds"]) + 300,
        ),
    )


def _effective_observed_state(record: dict[str, Any], observed_state: str) -> str:
    """Preserve authoritative terminal truth before lease maintenance."""
    stored_state = str(record["state"])
    return stored_state if _is_terminal_state(stored_state) else observed_state


def _maintain_record_resources(
    record: dict[str, Any],
    state: str,
) -> dict[str, Any] | None:
    if state not in ACTIVE_TASK_STATES:
        return None
    keys = _record_resource_keys(record)
    if not keys:
        return None
    owner = record.get("lease_owner_id") or _lease_owner(record["task_id"])
    ttl = _task_lease_ttl(record, state)
    try:
        renewed = resources.renew_resources(owner, keys, ttl_seconds=ttl)
        leases = renewed.get("leases", [])
        return {
            "maintained": True,
            "mode": "renewed",
            "expires_at_unix": (
                min(int(item["expires_at_unix"]) for item in leases)
                if leases
                else None
            ),
        }
    except (ValueError, RuntimeError):
        # A lease may have expired between observations. Reacquire only when the
        # resource is still free; a foreign owner remains a hard conflict.
        try:
            acquired = resources.acquire_resources(
                owner,
                keys,
                purpose=f"persistent task {record['task_id']} lease recovery",
                ttl_seconds=ttl,
                metadata={
                    "task_id": record["task_id"],
                    "host": record["host"],
                    "attempt": int(record["attempt"]),
                    "recovered_after_expiry": True,
                },
            )
        except Exception as exc:
            return {
                "maintained": False,
                "mode": "failed",
                "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
            }
        return {
            "maintained": True,
            "mode": "reacquired",
            "expires_at_unix": acquired.get("expires_at_unix"),
        }
    except Exception as exc:
        # Ownership drift is evidence, not a reason to hide task status. Keep
        # the task observable and surface the lease failure explicitly.
        return {
            "maintained": False,
            "mode": "failed",
            "error": _redact_reason(f"{type(exc).__name__}: {exc}"),
        }


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
    unit = _authoritative_unit(record)
    argv = [
        "systemd-run",
        "--user",
        f"--description={operator._systemd_safe_description('task', unit, record['argv_sha256'])}",
        "--unit",
        unit,
        "--slice=grabowski-tasks.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=LimitCORE=0",
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


def _root_task_start_payload(record: dict[str, Any]) -> dict[str, Any]:
    unit = _authoritative_unit(record)
    return {
        "operation": "start",
        "unit": unit,
        "argv": json.loads(record["argv_json"]),
        "cwd": record["cwd"],
        "runtime_seconds": int(record["runtime_seconds"]),
        "cpu_weight": int(record["cpu_weight"]),
        "io_weight": int(record["io_weight"]),
        "memory_max_bytes": record["memory_max_bytes"],
        "description": operator._systemd_safe_description(
            "task",
            unit,
            record["argv_sha256"],
        ),
    }


def _root_task_payload(record: dict[str, Any], operation: str, **extra: Any) -> dict[str, Any]:
    return {"operation": operation, "unit": _authoritative_unit(record), **extra}


def _launch(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        try:
            return privileged.root_task_systemd_request(
                _root_task_start_payload(record),
                timeout_seconds=60,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            # These failures occur before a structured broker response exists:
            # broker readiness, local reference creation or client execution
            # failed, so no accepted root dispatch is evidenced. Mark the
            # attempt failed and release its resources instead of stranding a
            # launching record. Once the client has contacted the broker, its
            # timeout and malformed-response paths return outcome_unknown.
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": _redact_reason(f"{type(exc).__name__}: {exc}"),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "root_truth_observable": False,
                "outcome_unknown": False,
                "launch_not_dispatched": True,
                "privileged_broker": None,
            }
    return _dispatch(record["host"], _launch_argv(record), timeout_seconds=60)


def _launch_state(result: dict[str, Any]) -> str:
    if result.get("outcome_unknown"):
        return "outcome_unknown"
    return "running" if result["returncode"] == 0 else "failed"


def _row(task_id: str) -> dict[str, Any]:
    identifier = _validate_task_id(task_id)
    with _database_connection() as connection:
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
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
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
        "chronik_outbox_enabled": bool(record.get("chronik_outbox_enabled")),
        "chronik_outbox_state_root": record.get("chronik_outbox_state_root"),
        "chronik_context": json.loads(record["chronik_context_json"]) if record.get("chronik_context_json") else None,
    }


@contextmanager
def _database_connection() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


@contextmanager
def _task_read_snapshot() -> Iterator[sqlite3.Connection]:
    connection = _database()
    try:
        connection.execute("BEGIN DEFERRED")
        yield connection
    finally:
        if connection.in_transaction:
            connection.rollback()
        connection.close()


def _task_filter_states(state: str | None) -> tuple[str, ...] | None:
    if state is None:
        return None
    if state in TASK_STATES:
        return (state,)
    projection = TASK_STATE_PROJECTIONS.get(state)
    if projection is None:
        allowed = sorted(TASK_STATES | set(TASK_STATE_PROJECTIONS))
        raise ValueError(f"state must be one of {allowed}")
    return projection


def _task_state_counts(
    connection: sqlite3.Connection,
) -> tuple[dict[str, int], dict[str, int], int]:
    rows = connection.execute(
        "SELECT state, COUNT(*) AS count FROM tasks GROUP BY state"
    ).fetchall()
    exact = {state: 0 for state in sorted(TASK_STATES)}
    unknown_state_count = 0
    for row in rows:
        state = str(row["state"])
        count = int(row["count"])
        if state in exact:
            exact[state] = count
        else:
            unknown_state_count += count
    projections = {
        name: sum(exact[state] for state in states)
        for name, states in sorted(TASK_STATE_PROJECTIONS.items())
    }
    return exact, projections, unknown_state_count


def _task_recommended_next_action(state: str) -> str:
    if state in {"launching", "running", "interrupted"}:
        return "read grabowski_task_status before deciding the next action"
    if state == "outcome_unknown":
        return "reconcile and read post-state before any unchanged retry"
    if state in {"failed", "timed_out", "signalled"}:
        return "inspect bounded task logs and recovery evidence"
    if state == "completed":
        return "consume the outcome receipt and close external bookkeeping"
    if state == "cancelled":
        return "confirm resource release and retained evidence"
    return "inspect task status"


def _public_for_view(record: dict[str, Any], view: str) -> dict[str, Any]:
    full = _public(record)
    if view == "evidence":
        return full
    minimal = {
        "task_id": full["task_id"],
        "host": full["host"],
        "unit": full["unit"],
        "authoritative_unit": full["authoritative_unit"],
        "execution_backend": full["execution_backend"],
        "systemd_scope": full["systemd_scope"],
        "attempt": full["attempt"],
        "state": full["state"],
        "resume_policy": full["resume_policy"],
        "argv_sha256": full["argv_sha256"],
        "created_at_unix": full["created_at_unix"],
        "updated_at_unix": full["updated_at_unix"],
        "resource_keys": full["resource_keys"],
        "recommended_next_action": _task_recommended_next_action(full["state"]),
    }
    if view == "standard":
        minimal.update({
            "argv": full["argv"],
            "cwd": full["cwd"],
            "runtime_seconds": full["runtime_seconds"],
            "memory_max_bytes": full["memory_max_bytes"],
            "last_observation": full["last_observation"],
            "lease_owner_id": full["lease_owner_id"],
            "chronik_outbox_enabled": full["chronik_outbox_enabled"],
        })
    return minimal


def _set_state(
    task_id: str,
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
    unit: str | None = None,
    authoritative_unit: str | None = None,
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
    if authoritative_unit is not None:
        updates.append("authoritative_unit=?")
        values.append(_validate_unit(authoritative_unit))
    if attempt is not None:
        updates.append("attempt=?")
        values.append(attempt)
    values.append(_validate_task_id(task_id))
    with _database_connection() as connection:
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
    chronik.record_task_state_safely(updated, state)
    return updated


def _observe(record: dict[str, Any]) -> dict[str, Any]:
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(
                record,
                "show",
                properties=list(fleet.TASK_UNIT_SHOW_PROPERTIES),
            ),
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        observer: dict[str, Any] = {
            "kind": "root-systemd-broker-show-v1",
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
        }
        properties: dict[str, str] = {}
        for line in result.get("stdout", "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        state = "outcome_unknown" if result.get("outcome_unknown") else _classify_observation(result, properties)
        return {
            "state": state,
            "properties": properties,
            "probe": result,
            "observer": observer,
            "observed_at_unix": _now(),
        }

    command = [
        "systemctl",
        "--user",
        "show",
        _authoritative_unit(record),
        "--no-pager",
    ]
    command.extend(f"--property={item}" for item in fleet.TASK_UNIT_SHOW_PROPERTIES)
    observer: dict[str, Any] = {
        "kind": "fleet-dispatch-v1",
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
    }
    try:
        result = _dispatch(record["host"], command, timeout_seconds=30)
    except fleet.FleetCommandDenied:
        # Production hosts intentionally do not expose generic systemctl through
        # fleet_run.  Reconcile still needs one fixed read-only observation shape
        # for Grabowski-owned task units, so fall back to the narrow fleet helper.
        observed = fleet.run_fleet_task_unit_show(
            record["host"],
            _authoritative_unit(record),
            fleet.TASK_UNIT_SHOW_PROPERTIES,
            timeout_seconds=30,
            max_output_bytes=8192,
        )
        result = observed["result"]
        observer = {
            "host": observed["host"],
            "transport": observed["transport"],
            "roles": observed["roles"],
            "kind": observed["observer"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            "fallback_from": "fleet-dispatch-permission-denied",
        }
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
        "observer": observer,
        "observed_at_unix": _now(),
    }


def server_task_lease_delegation_evidence(lease_owner_id: str) -> dict[str, Any]:
    """Validate one live task and its complete current lease set for server delegation."""
    if not isinstance(lease_owner_id, str):
        raise ValueError("task lease owner must be text")
    match = re.fullmatch(r"task:([0-9a-f]{24})", lease_owner_id)
    if match is None:
        raise ValueError("task lease owner is invalid")
    task_id = match.group(1)
    record = _row(task_id)
    effective_owner = record.get("lease_owner_id") or _lease_owner(task_id)
    if effective_owner != lease_owner_id:
        raise ValueError("task record lease owner mismatch")
    state = str(record.get("state", ""))
    if state not in TASK_LEASE_DELEGATION_STATES:
        raise ValueError(f"task state does not permit lease delegation: {state}")
    resource_keys = _record_resource_keys(record)
    if not resource_keys:
        raise ValueError("task has no resource leases to delegate")
    lease_evidence = resources.task_lease_delegation_evidence(
        lease_owner_id,
        task_id,
        resource_keys,
    )
    task_binding = {
        "task_id": task_id,
        "lease_owner_id": lease_owner_id,
        "state": state,
        "attempt": int(record["attempt"]),
        "updated_at_unix": int(record["updated_at_unix"]),
        "resource_keys_sha256": lease_evidence["resource_keys_sha256"],
        "lease_bindings_sha256": lease_evidence["lease_bindings_sha256"],
    }
    return {
        "schema_version": 1,
        "kind": "grabowski_live_task_lease_delegation_evidence",
        **task_binding,
        "task_record_sha256": _sha256_json(task_binding),
        "resource_keys": lease_evidence["resource_keys"],
        "minimum_expires_at_unix": lease_evidence["minimum_expires_at_unix"],
        "observed_at_unix": lease_evidence["observed_at_unix"],
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
    chronik_outbox: bool = False,
    chronik_outbox_state_root: str | None = None,
    chronik_operation: str = "other",
) -> dict[str, Any]:
    """Start one persistent local or fleet task in its own systemd unit.

    Direct local write-capable agent CLIs receive an implicit repository lease
    unless the caller supplies an explicit path or repository scope.
    """
    target = fleet.fleet_host(host)
    command = _validate_command(argv)
    recovery_gate = _require_recovery_gate(command)
    working_directory = _validate_cwd(host, cwd)
    runtime = operator._job_runtime(runtime_seconds)
    policy = _validate_resume_policy(resume_policy)
    cpu, io = _validate_weights(cpu_weight, io_weight)
    memory = _validate_memory(memory_max_bytes)
    chronik_enabled, chronik_state_root = _validate_chronik_outbox(
        chronik_outbox,
        chronik_outbox_state_root,
    )
    chronik_operation = _validate_chronik_operation(
        chronik_operation, enabled=bool(chronik_enabled)
    )
    requested_resources = _resource_keys(resource_keys)
    task_resources, implicit_workspace_resource = _task_resource_keys(
        host,
        command,
        cwd=working_directory,
        requested=requested_resources,
    )
    chronik_context_json = (
        _chronik_context(host, task_resources, chronik_operation)
        if chronik_enabled
        else None
    )
    task_id = uuid.uuid4().hex[:24]
    lease_owner = _lease_owner(task_id)
    execution_backend, systemd_scope = _execution_contract(target, command)
    if (
        execution_backend == "systemd-root-broker"
        and runtime + 300 > resources.MAX_TTL_SECONDS
    ):
        raise ValueError(
            "root task runtime must leave 300 seconds of lease and stop grace"
        )
    operator._require_operator_mutation(
        "durable_job",
        path=working_directory,
        repo=working_directory,
        task_id=task_id,
        owner_id=lease_owner,
        host=host,
        opaque_command=True,
    )
    attempt = 1
    unit = _task_unit(task_id, attempt)
    now = _now()
    record = {
        "task_id": task_id,
        "host": host,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "attempt": attempt,
        "state": "launching",
        "resume_policy": policy,
        "argv_json": _canonical_json(command),
        "argv_sha256": command_identity.argv_sha256(command),
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
        "chronik_outbox_enabled": chronik_enabled,
        "chronik_outbox_state_root": chronik_state_root,
        "chronik_context_json": chronik_context_json,
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
            metadata={
                "task_id": task_id,
                "host": host,
                "attempt": attempt,
                "implicit_workspace_resource_key": implicit_workspace_resource,
            },
        )
    try:
        with _database_connection() as connection:
            connection.execute(
            """
            INSERT INTO tasks(
                task_id, host, unit, attempt, state, resume_policy,
                argv_json, argv_sha256, cwd, runtime_seconds,
                cpu_weight, io_weight, memory_max_bytes,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json, resource_keys_json, lease_owner_id,
                execution_backend, systemd_scope, authoritative_unit,
                chronik_outbox_enabled, chronik_outbox_state_root,
                chronik_context_json
            ) VALUES(
                :task_id, :host, :unit, :attempt, :state, :resume_policy,
                :argv_json, :argv_sha256, :cwd, :runtime_seconds,
                :cpu_weight, :io_weight, :memory_max_bytes,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json, :resource_keys_json, :lease_owner_id,
                :execution_backend, :systemd_scope, :authoritative_unit,
                :chronik_outbox_enabled, :chronik_outbox_state_root,
                :chronik_context_json
            )
            """,
                record,
            )
            connection.commit()
    except Exception:
        if task_resources:
            resources.release_resources(lease_owner, task_resources)
        raise
    launcher = _launch(record)
    state = _launch_state(launcher)
    stored = _set_state(task_id, state, launcher=launcher)
    lease_maintenance = _maintain_record_resources(stored, state)
    if _state_releases_resources(state):
        _release_record_resources(stored)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-start",
        "task_id": task_id,
        "host": host,
        "transport": target["transport"],
        "execution_backend": execution_backend,
        "systemd_scope": systemd_scope,
        "authoritative_unit": unit,
        "argv_sha256": record["argv_sha256"],
        "unit": unit,
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "requested_resource_keys": requested_resources,
        "implicit_workspace_resource_key": implicit_workspace_resource,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


@mcp.tool(name="grabowski_task_status", annotations=READ_ONLY)
def grabowski_task_status(task_id: str) -> dict[str, Any]:
    """Observe one persistent task and refresh its recorded state."""
    operator._require_operator_capability("durable_job")
    record = _row(task_id)
    observation = _observe(record)
    effective_state = _effective_observed_state(record, observation["state"])
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(
        task_id,
        observation["state"],
        observation=observation,
    )
    if _state_releases_resources(observation["state"]):
        _release_record_resources(stored)
    result = _public(stored)
    result["lease_maintenance"] = lease_maintenance
    return result


@mcp.tool(name="grabowski_task_logs", annotations=READ_ONLY)
def grabowski_task_logs(task_id: str, max_lines: int = 200) -> dict[str, Any]:
    """Read redacted journal output for one local or fleet task."""
    operator._require_operator_capability("durable_job")
    if not isinstance(max_lines, int) or not 1 <= max_lines <= 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    record = _row(task_id)
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "journal", max_lines=max_lines),
            timeout_seconds=30,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
    else:
        result = _dispatch(
            record["host"],
            [
                "journalctl",
                "--user",
                "--unit",
                _authoritative_unit(record),
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
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "result": result,
    }


@mcp.tool(name="grabowski_task_cancel", annotations=MUTATING)
def grabowski_task_cancel(task_id: str) -> dict[str, Any]:
    """Stop one task process group and retain its persistent task record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
    )
    if _is_root_systemd_backend(record):
        result = privileged.root_task_systemd_request(
            _root_task_payload(record, "stop"),
            timeout_seconds=60,
        )
    else:
        result = _dispatch(
            record["host"],
            ["systemctl", "--user", "stop", _authoritative_unit(record)],
            timeout_seconds=60,
        )
    if result.get("outcome_unknown"):
        state = "outcome_unknown"
    else:
        state = "cancelled" if result["returncode"] == 0 else record["state"]
    cancel_observation = {"cancel": result}
    effective_state = _effective_observed_state(record, state)
    lease_maintenance = _maintain_record_resources(record, effective_state)
    if lease_maintenance is not None:
        cancel_observation["lease_maintenance"] = lease_maintenance
    stored = _set_state(task_id, state, observation=cancel_observation)
    if _state_releases_resources(state):
        _release_record_resources(stored)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-cancel",
        "task_id": task_id,
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "returncode": result["returncode"],
        "outcome_unknown": bool(result.get("outcome_unknown")),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "result": result, "audit": audit}


@mcp.tool(name="grabowski_task_resume", annotations=MUTATING)
def grabowski_task_resume(task_id: str) -> dict[str, Any]:
    """Recreate a missing or stopped task unit from its persistent record."""
    record = _row(task_id)
    operator._require_operator_mutation(
        "durable_job",
        path=record["cwd"],
        repo=record["cwd"],
        task_id=task_id,
        owner_id=record.get("lease_owner_id"),
        host=record["host"],
        opaque_command=True,
    )
    if _is_terminal_state(record["state"]):
        raise RuntimeError("Terminal task cannot be resumed")
    if record["resume_policy"] in {"never", "manual"}:
        raise PermissionError("Task resume policy does not permit automatic retry")
    command = json.loads(record["argv_json"])
    recovery_gate = _require_recovery_gate(command)
    observation = _observe(record)
    if observation["state"] == "running":
        raise RuntimeError("Task is still running")
    if observation["state"] == "completed":
        stored = _set_state(
            task_id,
            "completed",
            observation=observation,
        )
        _release_record_resources(stored)
        raise RuntimeError("Task already completed; refusing retry")
    if observation["state"] == "outcome_unknown":
        _set_state(
            task_id,
            "outcome_unknown",
            observation=observation,
        )
        raise RuntimeError("Task outcome is unknown; verify the authoritative unit before retry")
    attempt = int(record["attempt"]) + 1
    unit = _task_unit(task_id, attempt)
    candidate = {**record, "attempt": attempt, "unit": unit, "authoritative_unit": unit}
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
    launcher = _launch(candidate)
    state = _launch_state(launcher)
    stored = _set_state(
        task_id,
        state,
        launcher=launcher,
        observation=observation,
        unit=unit,
        authoritative_unit=unit,
        attempt=attempt,
    )
    lease_maintenance = _maintain_record_resources(stored, state)
    if _state_releases_resources(state):
        _release_record_resources(stored)
    audit = {
        "timestamp_unix": _now(),
        "operation": "task-resume",
        "task_id": task_id,
        "host": record["host"],
        "attempt": attempt,
        "unit": unit,
        "authoritative_unit": unit,
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "launcher_returncode": launcher["returncode"],
        "launcher_outcome_unknown": bool(launcher.get("outcome_unknown")),
        "recovery_required": recovery_gate.get("required", False),
        "recovery_checked_at_unix": recovery_gate.get("checked_at_unix"),
        "resource_keys": task_resources,
        "resource_lease_expires_at_unix": (
            lease_result["expires_at_unix"] if lease_result else None
        ),
        "resource_lease_maintenance": lease_maintenance,
    }
    base._append_audit(audit)
    return {"task": _public(stored), "audit": audit}


def _reconcile_candidate_rows(task_id: str = "") -> list[dict[str, Any]]:
    if task_id:
        record = _row(task_id)
        return (
            [record]
            if record["state"] in {"launching", "running", "outcome_unknown"}
            else []
        )
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM tasks WHERE state IN ('launching', 'running', 'outcome_unknown') "
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


def _reconcile_observe_denial(record: dict[str, Any], exc: PermissionError) -> dict[str, Any]:
    return {
        "task_id": record["task_id"],
        "host": record["host"],
        "unit": record["unit"],
        "authoritative_unit": _authoritative_unit(record),
        "execution_backend": _execution_backend(record),
        "systemd_scope": _systemd_scope(record),
        "current_state": record["state"],
        "resume_policy": record["resume_policy"],
        "reason": f"observation denied: {_redact_reason(str(exc))}",
    }


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
        try:
            observation = _observe(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        item = {
            "task_id": record["task_id"],
            "current_state": record["state"],
            "observed_state": observation["state"],
            "resume_policy": record["resume_policy"],
            "execution_backend": _execution_backend(record),
            "systemd_scope": _systemd_scope(record),
            "resource_keys": _record_resource_keys(record),
        }
        observations.append(item)
        if observation["state"] != record["state"]:
            would_refresh.append(item)
        if _state_releases_resources(observation["state"]):
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
    denied: list[dict[str, Any]] = []
    for record in rows:
        try:
            observation = _observe(record)
        except PermissionError as exc:
            denied.append(_reconcile_observe_denial(record, exc))
            continue
        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            _release_record_resources(stored)
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
    return {
        "mode": "refresh",
        "task_id": task_id,
        "scanned": len(rows),
        "refreshed": refreshed,
        "released": released,
        "resumed": [],
        "blocked": denied,
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
        try:
            observation = _observe(record)
        except PermissionError as exc:
            blocked.append(_reconcile_observe_denial(record, exc))
            continue
        effective_state = _effective_observed_state(record, observation["state"])
        lease_maintenance = _maintain_record_resources(record, effective_state)
        if lease_maintenance is not None:
            observation["lease_maintenance"] = lease_maintenance
        stored = _set_state(
            record["task_id"],
            observation["state"],
            observation=observation,
        )
        if _state_releases_resources(observation["state"]):
            _release_record_resources(stored)
            released.append(stored["task_id"])
        public = _public(stored)
        public["lease_maintenance"] = lease_maintenance
        refreshed.append(public)
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
        preview = reconcile_tasks_check()
        result = reconcile_tasks_refresh()
        disabled = [
            {
                "task_id": item["task_id"],
                "resume_policy": item["resume_policy"],
                "reason": "legacy auto_resume reconcile is disabled; use explicit resume mode",
            }
            for item in preview["would_resume"]
        ]
        return {
            "auto_resume": auto_resume,
            "legacy_auto_resume_disabled": True,
            "scanned": result["scanned"],
            "refreshed": result["refreshed"],
            "resumed": [],
            "blocked": [*preview["blocked"], *disabled],
            "checked_at_unix": result["checked_at_unix"],
        }
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
    limit: int = 20,
    state: str | None = None,
    view: str = "minimal",
    cursor: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """List persistent tasks with keyset pagination and compact default records."""
    operator._require_operator_capability("durable_job")
    selected_view = consumer_surface.normalize_view(view)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    filter_states = _task_filter_states(state)
    scope = f"task-list:{selected_view}:{state or 'all'}"
    position = consumer_surface.decode_cursor(cursor, scope)
    cursor_created_at: int | None = None
    cursor_task_id: str | None = None
    if position is not None:
        cursor_created_at = position.get("created_at_unix")
        cursor_task_id = position.get("task_id")
        if (
            isinstance(cursor_created_at, bool)
            or not isinstance(cursor_created_at, int)
            or cursor_created_at < 0
            or not isinstance(cursor_task_id, str)
            or not TASK_ID.fullmatch(cursor_task_id)
        ):
            raise ValueError("cursor position is invalid")
    where: list[str] = []
    parameters: list[Any] = []
    if filter_states is not None:
        placeholders = ",".join("?" for _ in filter_states)
        where.append(f"state IN ({placeholders})")
        parameters.extend(filter_states)
    if cursor_created_at is not None and cursor_task_id is not None:
        where.append("(created_at_unix < ? OR (created_at_unix = ? AND task_id < ?))")
        parameters.extend([cursor_created_at, cursor_created_at, cursor_task_id])
    where_sql = f" WHERE {' AND '.join(where)}" if where else ""
    with _task_read_snapshot() as connection:
        rows = connection.execute(
            f"SELECT * FROM tasks{where_sql} "
            "ORDER BY created_at_unix DESC, task_id DESC LIMIT ?",
            (*parameters, limit + 1),
        ).fetchall()
        state_counts, projection_counts, unknown_state_count = _task_state_counts(connection)
        if filter_states is None:
            total_matching = sum(state_counts.values()) + unknown_state_count
        else:
            total_matching = sum(state_counts[item] for item in filter_states)
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    tasks = [_public_for_view(dict(row), selected_view) for row in page_rows]
    next_cursor = None
    if has_more and page_rows:
        last = dict(page_rows[-1])
        next_cursor = consumer_surface.encode_cursor(
            scope,
            {
                "created_at_unix": int(last["created_at_unix"]),
                "task_id": str(last["task_id"]),
            },
        )
    warning_states = {
        "interrupted",
        "failed",
        "timed_out",
        "signalled",
        "outcome_unknown",
    }
    warnings: list[dict[str, Any]] = []
    if unknown_state_count:
        warnings.append({
            "code": "unknown_task_states",
            "count": unknown_state_count,
        })
    warnings.extend(
        {
            "code": "task_requires_attention",
            "task_id": task["task_id"],
            "state": task["state"],
        }
        for task in tasks
        if task.get("state") in warning_states
    )
    payload: dict[str, Any] = {
        "schema_version": 2,
        "view": selected_view,
        "count": len(tasks),
        "total_matching": total_matching,
        "state_filter": state,
        "state_filter_kind": (
            "all" if state is None else "projection" if state in TASK_STATE_PROJECTIONS else "exact"
        ),
        "state_filter_states": list(filter_states or ()),
        "state_counts": state_counts,
        "state_counts_scope": "all_tasks",
        "state_counts_complete": unknown_state_count == 0,
        "unknown_state_count": unknown_state_count,
        "projection_counts": projection_counts,
        "projection_counts_scope": "all_tasks",
        "projection_counts_overlap": True,
        "tasks": tasks,
        "pagination": {
            "limit": limit,
            "returned": len(tasks),
            "has_more": has_more,
            "next_cursor": next_cursor,
            "ordering": "created_at_unix_desc_task_id_desc",
        },
        "warnings": warnings,
        "recommended_next_action": (
            "inspect unknown task states before relying on projections"
            if unknown_state_count
            else "inspect attention tasks before retry" if warnings else "none"
        ),
        "does_not_establish": [
            "task_output_correctness",
            "safe_unchanged_retry",
            "resource_release_complete",
        ],
    }
    if selected_view == "evidence":
        payload["database"] = str(TASK_DB)
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=(
            "schema_version",
            "view",
            "warnings",
            "recommended_next_action",
            "does_not_establish",
        ),
    )
