from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import sys
import time
import uuid
from typing import Any
from urllib.parse import urlsplit

import grabowski_mcp as base
import grabowski_resources as resources
try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
WORKER_STATE = Path(
    os.environ.get(
        "GRABOWSKI_WORKER_STATE",
        str(operator.STATE_DIR / "workers"),
    )
).expanduser()
WORKER_DB = WORKER_STATE / "workers.sqlite3"
WORKER_ID = re.compile(r"[0-9a-f]{20}\Z")
WORKER_STATES = {"launching", "running", "completed", "failed", "stopped", "interrupted"}
WORKER_ACTIVE_STATES = {"launching", "running"}
WORKER_HISTORY_STATES = {"completed", "failed", "stopped", "interrupted"}
WORKER_LIST_VIEWS = {"current", "history"}
WORKER_LIST_MAX_SCAN = 500
WORKER_LIST_CURSOR = re.compile(
    r"(browser|gui):(current|history):([0-9]{1,20}):([0-9a-f]{20})\Z"
)
DEFAULT_BROWSER_EXECUTABLES = (
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/brave-browser",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)
DEFAULT_GUI_EXECUTABLES = (
    "/usr/bin/gedit",
    "/usr/bin/evince",
    "/usr/bin/libreoffice",
    "/usr/bin/firefox",
    "/usr/bin/nautilus",
)


def _now() -> int:
    return int(time.time())


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _database() -> sqlite3.Connection:
    if WORKER_STATE.is_symlink():
        raise PermissionError("Worker state directory may not be a symlink")
    WORKER_STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if WORKER_DB.is_symlink():
        raise PermissionError("Worker database may not be a symlink")
    connection = sqlite3.connect(WORKER_DB, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
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
        CREATE TABLE IF NOT EXISTS workers (
            worker_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            unit TEXT NOT NULL,
            state TEXT NOT NULL,
            executable TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            profile_path TEXT,
            port INTEGER,
            display_number INTEGER,
            lease_keys_json TEXT NOT NULL,
            ephemeral_paths_json TEXT NOT NULL,
            config_path TEXT NOT NULL,
            runtime_seconds INTEGER NOT NULL,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            launcher_json TEXT NOT NULL,
            last_observation_json TEXT
        )
        """
    )
    row = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    if row is None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
        )
    elif row["value"] != "1":
        connection.close()
        raise RuntimeError("Unsupported worker database schema")
    connection.commit()
    os.chmod(WORKER_DB, 0o600)
    return connection


def _read_database() -> sqlite3.Connection | None:
    if WORKER_STATE.is_symlink():
        raise PermissionError("Worker state directory may not be a symlink")
    if not WORKER_DB.exists():
        return None
    if WORKER_DB.is_symlink():
        raise PermissionError("Worker database may not be a symlink")
    if not WORKER_DB.is_file():
        raise PermissionError("Worker database must be a regular file")
    connection = sqlite3.connect(
        f"file:{WORKER_DB}?mode=ro",
        uri=True,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
    except sqlite3.DatabaseError:
        connection.close()
        raise
    if row is None or row["value"] != "1":
        connection.close()
        raise RuntimeError("Unsupported worker database schema")
    return connection


def _validate_worker_id(value: str) -> str:
    if not isinstance(value, str) or WORKER_ID.fullmatch(value) is None:
        raise ValueError("Invalid worker id")
    return value


def _validate_args(values: list[str] | None) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError("worker args must be a bounded list")
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item or "\x00" in item:
            raise ValueError("worker args must contain non-empty NUL-free strings")
        if len(item.encode("utf-8")) > 8192:
            raise ValueError("worker argument is too large")
        result.append(item)
    return result


def _configured_executables(environment_name: str, defaults: tuple[str, ...]) -> set[Path]:
    values = list(defaults)
    configured = os.environ.get(environment_name, "")
    if configured:
        values.extend(item for item in configured.split(os.pathsep) if item)
    result: set[Path] = set()
    for raw in values:
        candidate = Path(raw).expanduser()
        try:
            result.add(candidate.resolve(strict=True))
        except FileNotFoundError:
            continue
    return result


def _executable(
    raw: str,
    *,
    environment_name: str,
    defaults: tuple[str, ...],
) -> Path:
    if not isinstance(raw, str):
        raise ValueError("executable must be text")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise ValueError("worker executable must be absolute")
    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise PermissionError("worker executable is not an executable regular file")
    if resolved not in _configured_executables(environment_name, defaults):
        raise PermissionError(
            f"worker executable is not in {environment_name} or the built-in allowlist"
        )
    return resolved


def _browser_profile(worker_id: str, persistent_profile: str | None) -> tuple[Path, bool]:
    if persistent_profile is None:
        profile = WORKER_STATE / "profiles" / worker_id
        profile.mkdir(parents=True, exist_ok=False, mode=0o700)
        return profile, True
    candidate = Path(persistent_profile).expanduser()
    if not candidate.is_absolute():
        raise ValueError("persistent browser profile must be absolute")
    if candidate.exists() or candidate.is_symlink():
        if candidate.is_symlink() or not candidate.is_dir():
            raise PermissionError("persistent browser profile must be a non-symlink directory")
        resolved = candidate.resolve(strict=True)
    else:
        parent = candidate.parent.resolve(strict=True)
        resolved = parent / candidate.name
    roots = base._roots("browser_profile", ignore_missing=True)
    if not base._is_within(resolved, roots):
        raise PermissionError("persistent browser profile is outside configured roots")
    if not resolved.exists():
        resolved.mkdir(mode=0o700)
    return resolved, False


def _worker_directory(worker_id: str) -> Path:
    directory = WORKER_STATE / "instances" / worker_id
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    return directory


def _write_config(directory: Path, config: dict[str, Any]) -> Path:
    target = directory / "worker.json"
    temporary = directory / ".worker.json.tmp"
    payload = (_canonical_json(config) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target


def _launch_argv(record: dict[str, Any], writable_paths: list[Path]) -> list[str]:
    argv_hash = operator._argv_hash(json.loads(record["argv_json"]))
    argv = [
        "systemd-run",
        "--user",
        f"--description={operator._systemd_safe_description('browser-worker', record['unit'], argv_hash)}",
        "--unit",
        record["unit"],
        "--slice=grabowski-workers.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=LimitCORE=0",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=full",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=MemoryDenyWriteExecute=no",
        "--property=UMask=0077",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        f"--property=RuntimeMaxSec={record['runtime_seconds']}s",
        "--property=MemoryMax=2G",
        "--property=CPUWeight=100",
        "--property=IOWeight=100",
    ]
    for path in sorted({str(item) for item in writable_paths}):
        argv.append(f"--property=ReadWritePaths={path}")
    return [
        *argv,
        "--",
        sys.executable,
        "-m",
        "grabowski_worker_process",
        "--config",
        record["config_path"],
    ]


def _insert(record: dict[str, Any]) -> None:
    with _database() as connection:
        connection.execute(
            """
            INSERT INTO workers(
                worker_id, kind, unit, state, executable, argv_json,
                profile_path, port, display_number, lease_keys_json,
                ephemeral_paths_json, config_path, runtime_seconds,
                created_at_unix, updated_at_unix, launcher_json,
                last_observation_json
            ) VALUES(
                :worker_id, :kind, :unit, :state, :executable, :argv_json,
                :profile_path, :port, :display_number, :lease_keys_json,
                :ephemeral_paths_json, :config_path, :runtime_seconds,
                :created_at_unix, :updated_at_unix, :launcher_json,
                :last_observation_json
            )
            """,
            record,
        )
        connection.commit()


def _row(worker_id: str) -> dict[str, Any]:
    identifier = _validate_worker_id(worker_id)
    with _database() as connection:
        row = connection.execute(
            "SELECT * FROM workers WHERE worker_id=?", (identifier,)
        ).fetchone()
    if row is None:
        raise ValueError(f"Unknown worker: {identifier}")
    return dict(row)


def _update(
    worker_id: str,
    state: str,
    *,
    launcher: dict[str, Any] | None = None,
    observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if state not in WORKER_STATES:
        raise ValueError("Invalid worker state")
    updates = ["state=?", "updated_at_unix=?"]
    values: list[Any] = [state, _now()]
    if launcher is not None:
        updates.append("launcher_json=?")
        values.append(_canonical_json(launcher))
    if observation is not None:
        updates.append("last_observation_json=?")
        values.append(_canonical_json(observation))
    values.append(_validate_worker_id(worker_id))
    with _database() as connection:
        connection.execute(
            f"UPDATE workers SET {', '.join(updates)} WHERE worker_id=?", values
        )
        connection.commit()
    return _row(worker_id)


def _public(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "worker_id": record["worker_id"],
        "kind": record["kind"],
        "unit": record["unit"],
        "state": record["state"],
        "executable": record["executable"],
        "argv": operator._redact_argv(json.loads(record["argv_json"])),
        "profile_path": record["profile_path"],
        "port": record["port"],
        "display_number": record["display_number"],
        "runtime_seconds": record["runtime_seconds"],
        "created_at_unix": record["created_at_unix"],
        "updated_at_unix": record["updated_at_unix"],
        "launcher": json.loads(record["launcher_json"]),
        "last_observation": (
            json.loads(record["last_observation_json"])
            if record["last_observation_json"]
            else None
        ),
        "lease_keys": json.loads(record["lease_keys_json"]),
    }


def _release(record: dict[str, Any]) -> dict[str, Any]:
    keys = json.loads(record["lease_keys_json"])
    owner = f"worker:{record['worker_id']}"
    released: list[str] = []
    absent: list[str] = []
    blocked: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for key in keys:
        try:
            current = resources.inspect_resource(key)
        except (PermissionError, ValueError) as exc:
            errors.append({"resource_key": key, "error": str(exc)})
            continue
        if current is None:
            absent.append(key)
            continue
        current_owner = str(current.get("owner_id", ""))
        if current_owner != owner:
            blocked.append({"resource_key": key, "owner_id": current_owner})
            continue
        try:
            result = resources.release_resources(owner, [key])
        except (PermissionError, ValueError) as exc:
            errors.append({"resource_key": key, "error": str(exc)})
            continue
        released.extend(
            str(item["resource_key"]) for item in result.get("released", [])
        )

    remaining: list[dict[str, str]] = []
    for key in keys:
        try:
            current = resources.inspect_resource(key)
        except (PermissionError, ValueError) as exc:
            errors.append({"resource_key": key, "error": str(exc)})
            continue
        if current is not None:
            remaining.append(
                {
                    "resource_key": key,
                    "owner_id": str(current.get("owner_id", "")),
                }
            )

    if blocked or errors:
        status = "partial" if released or absent else "blocked"
    elif remaining:
        status = "incomplete"
    elif released:
        status = "released"
    else:
        status = "already-absent"
    return {
        "status": status,
        "owner_id": owner,
        "requested": keys,
        "released": released,
        "already_absent": absent,
        "blocked": blocked,
        "errors": errors,
        "remaining": remaining,
    }


def _cleanup(record: dict[str, Any]) -> dict[str, Any]:
    removed: list[str] = []
    absent: list[str] = []
    preserved: list[str] = []
    errors: list[dict[str, str]] = []
    evidence_directory = WORKER_STATE / "instances" / record["worker_id"]
    for raw in json.loads(record["ephemeral_paths_json"]):
        path = Path(raw)
        if path == evidence_directory:
            preserved.append(str(path))
            continue
        if path == WORKER_STATE or WORKER_STATE not in path.parents:
            preserved.append(str(path))
            continue
        try:
            shutil.rmtree(path)
            removed.append(str(path))
        except FileNotFoundError:
            absent.append(str(path))
        except OSError as exc:
            errors.append({"path": str(path), "error": str(exc)})
    return {
        "status": "partial" if errors else "completed",
        "removed": removed,
        "already_absent": absent,
        "preserved_evidence": preserved,
        "errors": errors,
    }


def _terminalization_action_required(observation: dict[str, Any]) -> bool:
    terminalization = observation.get("terminalization")
    if not isinstance(terminalization, dict):
        return False
    release = terminalization.get("release")
    cleanup = terminalization.get("cleanup")
    return bool(
        isinstance(release, dict)
        and release.get("status") in {"blocked", "partial", "incomplete"}
    ) or bool(isinstance(cleanup, dict) and cleanup.get("status") == "partial")


def _reconcile_record(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = _observe(record)
    stored = _update(record["worker_id"], observation["state"], observation=observation)
    if observation["state"] not in WORKER_ACTIVE_STATES:
        observation = {
            **observation,
            "terminalization": {
                "release": _release(stored),
                "cleanup": _cleanup(stored),
            },
        }
        stored = _update(
            record["worker_id"], observation["state"], observation=observation
        )
    return stored, observation


def _observe(record: dict[str, Any]) -> dict[str, Any]:
    result = operator._run(
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
            "--property=ExecMainStatus",
        ],
        cwd=operator.HOME,
        timeout_seconds=30,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    properties: dict[str, str] = {}
    for line in result.get("stdout", "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    active = properties.get("ActiveState")
    load = properties.get("LoadState")
    unit_result = properties.get("Result")
    exec_main_status = properties.get("ExecMainStatus")
    if result["returncode"] != 0:
        state = "interrupted"
    elif load in {None, "not-found"}:
        if unit_result == "success" and exec_main_status == "0":
            state = "completed"
        elif (
            unit_result not in {None, "", "success"}
            or exec_main_status not in {None, "", "0"}
        ):
            state = "failed"
        else:
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


def _start(
    *,
    kind: str,
    executable: Path,
    argv: list[str],
    config: dict[str, Any],
    profile_path: Path | None,
    port: int | None,
    display_number: int | None,
    lease_keys: list[str],
    ephemeral_paths: list[Path],
    runtime_seconds: int,
    writable_paths: list[Path],
) -> dict[str, Any]:
    worker_id = config.pop("worker_id")
    directory = _worker_directory(worker_id)
    ephemeral_paths.append(directory)
    config_path = _write_config(directory, config)
    now = _now()
    record = {
        "worker_id": worker_id,
        "kind": kind,
        "unit": f"grabowski-{kind}-worker-{worker_id}.service",
        "state": "launching",
        "executable": str(executable),
        "argv_json": _canonical_json(argv),
        "profile_path": str(profile_path) if profile_path else None,
        "port": port,
        "display_number": display_number,
        "lease_keys_json": _canonical_json(lease_keys),
        "ephemeral_paths_json": _canonical_json([str(item) for item in ephemeral_paths]),
        "config_path": str(config_path),
        "runtime_seconds": runtime_seconds,
        "created_at_unix": now,
        "updated_at_unix": now,
        "launcher_json": _canonical_json({"pending": True}),
        "last_observation_json": None,
    }
    owner = f"worker:{worker_id}"
    try:
        resources.acquire_resources(
            owner,
            lease_keys,
            purpose=f"isolated {kind} worker",
            ttl_seconds=min(resources.MAX_TTL_SECONDS, runtime_seconds + 300),
            metadata={"worker_id": worker_id, "kind": kind},
        )
        _insert(record)
        launcher = operator._run(
            _launch_argv(record, writable_paths),
            cwd=operator.HOME,
            timeout_seconds=60,
            max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
        )
        state = "running" if launcher["returncode"] == 0 else "failed"
        stored = _update(worker_id, state, launcher=launcher)
        if state == "failed":
            _release(stored)
            _cleanup(stored)
        return {"worker": _public(stored), "launcher": launcher}
    except Exception:
        try:
            resources.release_resources(owner, lease_keys)
        except (PermissionError, ValueError):
            pass
        for path in reversed(ephemeral_paths):
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass
        raise


BROWSER_FORM_SELECTOR = re.compile(r"[^\x00\r\n]{1,512}\Z")
BROWSER_FORM_CHOICE = re.compile(r"[^\x00\r\n]{1,256}\Z")
BROWSER_FORM_CONFIRMATION_PREFIX = "AUTHORIZE_BROWSER_STORED_FORM_ACTION"
BROWSER_FORM_RESULT_CODES = {
    "ok",
    "target-discovery",
    "target-origin",
    "transport",
    "element-contract",
    "identity-choice",
    "browser-fill",
    "submit-target",
    "submit-effect",
    "post-origin",
    "protocol",
    "cleanup",
    "ready",
}
BROWSER_FORM_LOCAL_V4 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
BROWSER_FORM_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
BROWSER_FORM_NODE_SOURCE = r"""
import fs from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const digest = (value) => crypto.createHash('sha256').update(value, 'utf8').digest('hex');
const FORM_READY_POLL_MS = 50;
const FORM_READY_TIMEOUT_MS = 1000;
const FORM_ALLOWED_IDENTITY_TYPES = new Set(['text', 'email', 'select']);
const FORM_ALLOWED_SUBMIT_TYPES = new Set(['submit', 'button']);
const RESULT_CODES = new Set([
  'ok', 'target-discovery', 'target-origin', 'transport', 'element-contract',
  'identity-choice', 'browser-fill', 'submit-target', 'submit-effect',
  'post-origin', 'protocol', 'cleanup', 'ready',
]);
let ws = null;
let nextId = 1;
const pending = new Map();
const eventQueue = [];
const eventWaiters = [];
let eventSequence = 0;
let stage = 'target-discovery';
let cleaned = false;
let fillConfirmed = false;
let submitted = false;
let actionEffectObserved = false;
let navigationObserved = false;
let formDisappeared = false;
let remoteAddressSha256 = null;

function emit(payload, status = 0) {
  process.stdout.write(JSON.stringify(payload) + '\n');
  process.exitCode = status;
}

function expression(selectors, body) {
  return `(() => { const s = ${JSON.stringify(selectors)}; ${body} })()`;
}

function rejectTransportOperations() {
  for (const entry of pending.values()) {
    clearTimeout(entry.timer);
    entry.reject(new Error('transport'));
  }
  pending.clear();
  for (const waiter of eventWaiters.splice(0)) {
    clearTimeout(waiter.timer);
    waiter.reject(new Error('transport'));
  }
}

async function connect(url) {
  return await new Promise((resolve, reject) => {
    ws = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error('transport')), request.timeout_ms);
    ws.onopen = () => { clearTimeout(timer); resolve(); };
    ws.onerror = () => { clearTimeout(timer); reject(new Error('transport')); };
    ws.onmessage = (event) => {
      let message;
      try { message = JSON.parse(event.data); } catch { return; }
      if (message.id && pending.has(message.id)) {
        const entry = pending.get(message.id);
        pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.error) entry.reject(new Error('protocol'));
        else entry.resolve(message.result || {});
        return;
      }
      if (typeof message.method !== 'string') return;
      const sequence = ++eventSequence;
      for (let index = 0; index < eventWaiters.length; index += 1) {
        const waiter = eventWaiters[index];
        if (sequence <= waiter.afterSequence || waiter.method !== message.method ||
            !waiter.predicate(message.params || {})) continue;
        eventWaiters.splice(index, 1);
        clearTimeout(waiter.timer);
        waiter.resolve(message.params || {});
        return;
      }
      eventQueue.push({message, sequence});
      if (eventQueue.length > 128) eventQueue.shift();
    };
    ws.onclose = rejectTransportOperations;
  });
}

async function call(method, params = {}) {
  if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error('transport');
  const id = nextId++;
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('protocol'));
    }, request.timeout_ms);
    pending.set(id, {resolve, reject, timer});
    ws.send(JSON.stringify({id, method, params}));
  });
}

async function waitEvent(method, predicate = () => true, afterSequence = 0) {
  const existing = eventQueue.findIndex((entry) =>
    entry.sequence > afterSequence && entry.message.method === method &&
      predicate(entry.message.params || {})
  );
  if (existing >= 0) {
    const [entry] = eventQueue.splice(existing, 1);
    return entry.message.params || {};
  }
  return await new Promise((resolve, reject) => {
    const waiter = {method, predicate, afterSequence, resolve, reject, timer: null};
    waiter.timer = setTimeout(() => {
      const index = eventWaiters.indexOf(waiter);
      if (index >= 0) eventWaiters.splice(index, 1);
      reject(new Error('protocol'));
    }, request.timeout_ms);
    eventWaiters.push(waiter);
  });
}

function normalizeRemoteAddress(raw) {
  let value = String(raw || '').trim();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) value = value.slice(0, zoneIndex);
  const version = net.isIP(value);
  if (version === 4) return value;
  if (version !== 6) return null;
  try {
    const hostname = new URL('http://[' + value + ']/').hostname;
    return hostname.slice(1, -1).toLowerCase();
  } catch {
    return null;
  }
}

async function evaluate(source) {
  const response = await call('Runtime.evaluate', {
    expression: source,
    returnByValue: true,
    awaitPromise: true,
  });
  if (response.exceptionDetails) throw new Error('protocol');
  return response.result ? response.result.value : undefined;
}

async function key(key, code, virtualKeyCode) {
  const common = {key, code, windowsVirtualKeyCode: virtualKeyCode, nativeVirtualKeyCode: virtualKeyCode};
  await call('Input.dispatchKeyEvent', {type: 'rawKeyDown', ...common});
  await call('Input.dispatchKeyEvent', {type: 'keyUp', ...common});
}

async function clickSelector(selectorName, failureCode) {
  const source = `(() => {
    const s = ${JSON.stringify(request.selectors)};
    const selectorName = ${JSON.stringify(selectorName)};
    let element = null;
    try { element = document.querySelector(s[selectorName]); } catch { return null; }
    if (!element || !element.isConnected) return null;
    const rect = element.getBoundingClientRect();
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    const top = document.elementFromPoint(x, y);
    if (!(top === element || element.contains(top))) return null;
    return {x, y};
  })()`;
  const point = await evaluate(source);
  if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
    throw new Error(failureCode);
  }
  await call('Input.dispatchMouseEvent', {type: 'mouseMoved', x: point.x, y: point.y});
  await call('Input.dispatchMouseEvent', {
    type: 'mousePressed', x: point.x, y: point.y, button: 'left', clickCount: 1,
  });
  await call('Input.dispatchMouseEvent', {
    type: 'mouseReleased', x: point.x, y: point.y, button: 'left', clickCount: 1,
  });
}

async function guardedEnter() {
  const guardSource = `(() => {
    const key = '__grabowskiStoredFormEnterGuard';
    if (window[key]) window.removeEventListener('keydown', window[key], true);
    const handler = (event) => {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      event.stopImmediatePropagation();
    };
    window[key] = handler;
    window.addEventListener('keydown', handler, true);
    return true;
  })()`;
  const removeSource = `(() => {
    const key = '__grabowskiStoredFormEnterGuard';
    if (!window[key]) return false;
    window.removeEventListener('keydown', window[key], true);
    delete window[key];
    return true;
  })()`;
  await evaluate(guardSource);
  try {
    await key('Enter', 'Enter', 13);
  } finally {
    try { await evaluate(removeSource); } catch {}
  }
}

async function clearFields() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  try {
    return Boolean(await evaluate(expression(request.selectors, `
      let changed = false;
      for (const selector of [s.identity, s.protected]) {
        let element = null;
        try { element = document.querySelector(selector); } catch { continue; }
        if (!element || !('value' in element)) continue;
        element.value = '';
        element.dispatchEvent(new Event('input', {bubbles: true}));
        element.dispatchEvent(new Event('change', {bubbles: true}));
        changed = true;
      }
      return changed;
    `)));
  } catch {
    return false;
  }
}

function formReadyDeadline() {
  return Date.now() + Math.min(FORM_READY_TIMEOUT_MS, request.timeout_ms);
}

async function inspectFormContract() {
  return await evaluate(expression(request.selectors, `
    const visible = (element) => {
      if (!element || !element.isConnected) return false;
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
    };
    let identity, protectedField, submit;
    try {
      identity = document.querySelector(s.identity);
      protectedField = document.querySelector(s.protected);
      submit = document.querySelector(s.submit);
    } catch {
      return {valid: false, origin: location.origin, selector_error: true};
    }
    const identityTag = identity ? identity.tagName.toLowerCase() : '';
    const identityType = identityTag === 'input' ? (identity.type || 'text').toLowerCase() : identityTag;
    const protectedType = protectedField && protectedField.tagName.toLowerCase() === 'input'
      ? (protectedField.type || 'text').toLowerCase() : '';
    const submitTag = submit ? submit.tagName.toLowerCase() : '';
    const submitType = submitTag === 'input' || submitTag === 'button'
      ? (submit.type || 'submit').toLowerCase() : submitTag;
    return {
      valid: Boolean(identity && protectedField && submit),
      origin: location.origin,
      selector_error: false,
      identity_type: identityType,
      protected_type: protectedType,
      submit_type: submitType,
      identity_visible: visible(identity),
      protected_visible: visible(protectedField),
      submit_visible: visible(submit),
      identity_disabled: Boolean(identity && identity.disabled),
      protected_disabled: Boolean(protectedField && protectedField.disabled),
      submit_disabled: Boolean(submit && submit.disabled),
    };
  `));
}

function formContractReady(inspected) {
  return Boolean(inspected && inspected.valid && !inspected.selector_error &&
    inspected.origin === request.expected_origin &&
    FORM_ALLOWED_IDENTITY_TYPES.has(inspected.identity_type) &&
    inspected.protected_type === 'password' &&
    FORM_ALLOWED_SUBMIT_TYPES.has(inspected.submit_type) &&
    inspected.identity_visible && inspected.protected_visible && inspected.submit_visible &&
    !inspected.identity_disabled && !inspected.protected_disabled && !inspected.submit_disabled);
}

async function waitForFormContract() {
  const deadline = formReadyDeadline();
  while (true) {
    const inspected = await inspectFormContract();
    if (inspected && (inspected.selector_error ||
        (typeof inspected.origin === 'string' && inspected.origin !== request.expected_origin))) {
      throw new Error('element-contract');
    }
    if (formContractReady(inspected)) return inspected;
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error('element-contract');
    await sleep(Math.min(FORM_READY_POLL_MS, remaining));
  }
}

async function clearFieldsAfterHydration() {
  const deadline = formReadyDeadline();
  while (true) {
    if (await clearFields()) return true;
    const remaining = deadline - Date.now();
    if (remaining <= 0) return false;
    await sleep(Math.min(FORM_READY_POLL_MS, remaining));
  }
}

try {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), request.timeout_ms);
  const response = await fetch(`http://127.0.0.1:${request.port}/json/list`, {signal: controller.signal});
  clearTimeout(timer);
  if (!response.ok) throw new Error('target-discovery');
  const targets = await response.json();
  const matches = targets.filter((target) => {
    if (target.type !== 'page' || typeof target.webSocketDebuggerUrl !== 'string') return false;
    try {
      const page = new URL(target.url);
      const endpoint = new URL(target.webSocketDebuggerUrl);
      const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
      return page.origin === request.expected_origin && endpoint.protocol === 'ws:' &&
        loopbackHosts.has(endpoint.hostname) && Number(endpoint.port) === request.port;
    } catch { return false; }
  });
  if (matches.length !== 1) throw new Error('target-origin');

  stage = 'transport';
  await connect(matches[0].webSocketDebuggerUrl);
  await call('Runtime.enable');
  await call('Page.enable');
  await call('Page.setLifecycleEventsEnabled', {enabled: true});
  await call('Network.enable');
  await call('Network.setCacheDisabled', {cacheDisabled: true});
  const frameTree = await call('Page.getFrameTree');
  const mainFrame = frameTree.frameTree && frameTree.frameTree.frame
    ? frameTree.frameTree.frame : null;
  const mainFrameId = mainFrame && typeof mainFrame.id === 'string' ? mainFrame.id : null;
  const currentLoaderId = mainFrame && typeof mainFrame.loaderId === 'string'
    ? mainFrame.loaderId : null;
  if (!mainFrameId || !currentLoaderId) throw new Error('protocol');

  const reloadEventFloor = eventSequence;
  const documentResponsePromise = waitEvent('Network.responseReceived', (params) =>
    params.type === 'Document' && params.frameId === mainFrameId &&
      typeof params.loaderId === 'string' && params.loaderId.length > 0 &&
      params.loaderId !== currentLoaderId &&
      params.response && typeof params.response.url === 'string',
  reloadEventFloor);
  const lifecycleLoadPromise = waitEvent('Page.lifecycleEvent', (params) =>
    params.name === 'load' && params.frameId === mainFrameId &&
      typeof params.loaderId === 'string' && params.loaderId.length > 0 &&
      params.loaderId !== currentLoaderId,
  reloadEventFloor);
  try {
    const [, documentResponse, lifecycleLoad] = await Promise.all([
      call('Page.reload', {ignoreCache: true, loaderId: currentLoaderId}),
      documentResponsePromise,
      lifecycleLoadPromise,
    ]);
    if (documentResponse.loaderId !== lifecycleLoad.loaderId) {
      throw new Error('target-origin');
    }
    let responseOrigin;
    try { responseOrigin = new URL(documentResponse.response.url).origin; }
    catch { throw new Error('target-origin'); }
    const remoteAddress = normalizeRemoteAddress(documentResponse.response.remoteIPAddress);
    if (responseOrigin !== request.expected_origin || !remoteAddress ||
        !request.allowed_addresses.includes(remoteAddress)) {
      throw new Error('target-origin');
    }

    const verifiedFrameTree = await call('Page.getFrameTree');
    const verifiedFrame = verifiedFrameTree.frameTree && verifiedFrameTree.frameTree.frame
      ? verifiedFrameTree.frameTree.frame : null;
    let verifiedOrigin = null;
    try { verifiedOrigin = verifiedFrame ? new URL(verifiedFrame.url).origin : null; }
    catch {}
    if (!verifiedFrame || verifiedFrame.id !== mainFrameId ||
        verifiedFrame.loaderId !== documentResponse.loaderId ||
        verifiedOrigin !== request.expected_origin) {
      throw new Error('target-origin');
    }
    // Public evidence is committed only after loader, frame, origin, and allowlist verification.
    remoteAddressSha256 = digest(remoteAddress);
  } catch (error) {
    rejectTransportOperations();
    try { if (ws) ws.close(); } catch {}
    throw error;
  }
  if (request.cleanup_only === true) {
    cleaned = await clearFieldsAfterHydration();
    emit({
      schema_version: 1, ok: true, result_code: 'cleanup', fill_confirmed: false,
      submitted: false, action_effect_observed: false, navigation_observed: false,
      form_disappeared: false, post_origin: request.expected_origin,
      post_path_sha256: null, remote_address_sha256: remoteAddressSha256, cleaned,
    });
  } else {
  stage = 'element-contract';
  const inspected = await waitForFormContract();

  if (request.identity_choice !== null) {
    stage = 'identity-choice';
    const choiceApplied = await evaluate(expression(request.selectors, `
      const element = document.querySelector(s.identity);
      const choice = ${JSON.stringify(request.identity_choice)};
      if (element.tagName.toLowerCase() === 'select') {
        const option = Array.from(element.options).find((candidate) =>
          candidate.value === choice || candidate.textContent.trim() === choice
        );
        if (!option) return false;
        element.value = option.value;
      } else {
        element.value = choice;
      }
      element.dispatchEvent(new Event('input', {bubbles: true}));
      element.dispatchEvent(new Event('change', {bubbles: true}));
      return true;
    `));
    if (!choiceApplied) throw new Error('identity-choice');
  }

  stage = 'browser-fill';
  const initialTarget = (
    request.identity_choice === null && ['text', 'email'].includes(inspected.identity_type)
  ) ? 'identity' : 'protected';
  await clickSelector(initialTarget, 'browser-fill');
  await key('ArrowDown', 'ArrowDown', 40);
  await key('Tab', 'Tab', 9);
  await sleep(350);
  let filled = await evaluate(expression(request.selectors, `
    const identity = document.querySelector(s.identity);
    const protectedField = document.querySelector(s.protected);
    const identityReady = identity.tagName.toLowerCase() === 'select'
      ? Boolean(identity.value) : Boolean(identity.value && identity.value.length > 0);
    return {identity_filled: identityReady, protected_filled: Boolean(protectedField.value && protectedField.value.length > 0)};
  `));
  if (!filled.identity_filled || !filled.protected_filled) {
    await clickSelector('protected', 'browser-fill');
    await key('ArrowDown', 'ArrowDown', 40);
    await guardedEnter();
    await sleep(350);
    filled = await evaluate(expression(request.selectors, `
      const identity = document.querySelector(s.identity);
      const protectedField = document.querySelector(s.protected);
      const identityReady = identity.tagName.toLowerCase() === 'select'
        ? Boolean(identity.value) : Boolean(identity.value && identity.value.length > 0);
      return {identity_filled: identityReady, protected_filled: Boolean(protectedField.value && protectedField.value.length > 0)};
    `));
  }
  if (!filled.identity_filled || !filled.protected_filled) throw new Error('browser-fill');
  fillConfirmed = true;

  if (request.action_mode === 'readiness') {
    stage = 'cleanup';
    cleaned = await clearFields();
    if (!cleaned) throw new Error('cleanup');
    emit({
      schema_version: 1, ok: true, result_code: 'ready', fill_confirmed: true,
      submitted: false, action_effect_observed: false, navigation_observed: false,
      form_disappeared: false, post_origin: request.expected_origin,
      post_path_sha256: null, remote_address_sha256: remoteAddressSha256, cleaned: true,
    });
  } else {
  stage = 'submit-target';
  const before = await evaluate(`({origin: location.origin, path: location.pathname})`);
  await clickSelector('submit', 'submit-target');
  submitted = true;

  stage = 'submit-effect';
  const deadline = Date.now() + Math.min(5000, request.timeout_ms);
  let post = null;
  let effect = false;
  while (Date.now() < deadline) {
    await sleep(200);
    try {
      post = await evaluate(expression(request.selectors, `
        let protectedField = null;
        try { protectedField = document.querySelector(s.protected); } catch {}
        return {origin: location.origin, path: location.pathname, protected_present: Boolean(protectedField)};
      `));
      formDisappeared = !post.protected_present;
      effect = post.origin !== before.origin || post.path !== before.path || formDisappeared;
      if (effect) {
        actionEffectObserved = true;
        navigationObserved = post.origin !== before.origin || post.path !== before.path;
        break;
      }
    } catch {
      // A navigation can temporarily destroy the execution context. Retry until
      // the new document is readable and its exact origin can be verified.
      continue;
    }
  }
  if (!effect) {
    cleaned = await clearFields();
    throw new Error('submit-effect');
  }
  if (post && post.origin !== request.expected_origin) {
    cleaned = await clearFields();
    throw new Error('post-origin');
  }
  cleaned = formDisappeared ? true : await clearFields();

  emit({
    schema_version: 1,
    ok: true,
    result_code: 'ok',
    fill_confirmed: fillConfirmed,
    submitted,
    action_effect_observed: actionEffectObserved,
    navigation_observed: navigationObserved,
    form_disappeared: formDisappeared,
    post_origin: post ? post.origin : request.expected_origin,
    post_path_sha256: post ? digest(post.path) : null,
    remote_address_sha256: remoteAddressSha256,
    cleaned,
  });
  }
  }
} catch (error) {
  if (!cleaned) cleaned = await clearFields();
  const message = error && typeof error.message === 'string' ? error.message : '';
  const code = RESULT_CODES.has(message)
    ? message
    : (RESULT_CODES.has(stage) ? stage : 'protocol');
  emit({
    schema_version: 1,
    ok: false,
    result_code: code,
    fill_confirmed: fillConfirmed,
    submitted,
    action_effect_observed: actionEffectObserved,
    navigation_observed: navigationObserved,
    form_disappeared: formDisappeared,
    post_origin: null,
    post_path_sha256: null,
    remote_address_sha256: remoteAddressSha256,
    cleaned,
  }, 2);
} finally {
  try { if (ws) ws.close(); } catch {}
}
"""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_form_selector(value: str, label: str) -> str:
    if not isinstance(value, str) or BROWSER_FORM_SELECTOR.fullmatch(value) is None:
        raise ValueError(f"{label} must be bounded single-line selector text")
    return value


def _validate_form_action_mode(value: str) -> str:
    if value not in {"submit", "readiness"}:
        raise ValueError("action_mode must be submit or readiness")
    return value


def _validate_identity_choice(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or BROWSER_FORM_CHOICE.fullmatch(value) is None:
        raise ValueError("identity_choice must be bounded single-line text")
    return value


def _canonical_local_origin(value: str) -> tuple[str, str, list[str]]:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
        raise ValueError("expected_origin must be bounded text")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("expected_origin must be one canonical HTTP(S) origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("expected_origin contains an invalid port") from exc
    hostname = parsed.hostname.lower().rstrip(".")
    if not hostname:
        raise ValueError("expected_origin hostname is empty")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("expected_origin hostname is invalid") from exc
    default_port = 443 if parsed.scheme == "https" else 80
    service_port = port or default_port
    try:
        answers = socket.getaddrinfo(hostname, service_port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError("expected_origin hostname did not resolve") from exc
    try:
        addresses = sorted(
            {
                str(ipaddress.ip_address(answer[4][0].split("%", 1)[0]))
                for answer in answers
            }
        )
    except ValueError as exc:
        raise RuntimeError("expected_origin resolved to an invalid address") from exc
    if not addresses:
        raise RuntimeError("expected_origin hostname has no addresses")
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if address.version == 4:
            allowed = (
                address.is_loopback
                or address.is_link_local
                or any(address in network for network in BROWSER_FORM_LOCAL_V4)
            )
        else:
            allowed = (
                address.is_loopback
                or address.is_link_local
                or address in BROWSER_FORM_LOCAL_V6
            )
        if not allowed:
            raise PermissionError("expected_origin resolved outside local address space")
    host_text = f"[{hostname}]" if ":" in hostname else hostname
    port_text = "" if service_port == default_port else f":{service_port}"
    origin = f"{parsed.scheme}://{host_text}{port_text}"
    return origin, _sha256_text("\n".join(addresses)), addresses


def _write_private_action_file(path: Path, payload: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        data = payload.encode("utf-8")
        while data:
            written = os.write(descriptor, data)
            if written <= 0:
                raise OSError("browser action file write made no progress")
            data = data[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_node_form_action(
    record: dict[str, Any],
    request: dict[str, Any],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required for browser CDP actions")
    node_path = Path(node)
    if not node_path.is_absolute():
        raise RuntimeError("Node.js executable must resolve from an absolute alias")
    node_target = node_path.resolve(strict=True)
    node_metadata = node_target.stat()
    if not stat.S_ISREG(node_metadata.st_mode) or not os.access(node_target, os.X_OK):
        raise PermissionError("Node.js target is not an executable regular file")
    directory = Path(record["config_path"]).parent
    if directory.is_symlink() or WORKER_STATE not in directory.parents:
        raise PermissionError("worker action directory is outside worker state")
    token = uuid.uuid4().hex
    script_path = directory / f".stored-form-{token}.mjs"
    request_path = directory / f".stored-form-{token}.json"
    created: list[Path] = []
    try:
        _write_private_action_file(script_path, BROWSER_FORM_NODE_SOURCE)
        created.append(script_path)
        _write_private_action_file(request_path, _canonical_json(request) + "\n")
        created.append(request_path)
        execution = operator._run(
            [str(node_path), str(script_path), str(request_path)],
            cwd=directory,
            timeout_seconds=timeout_seconds + 10,
            max_output_bytes=65536,
        )
    finally:
        for created_path in reversed(created):
            try:
                created_path.unlink()
            except FileNotFoundError:
                pass
    lines = [line for line in execution.get("stdout", "").splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("browser action returned no receipt")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError("browser action returned an invalid receipt") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("browser action receipt schema mismatch")
    code = payload.get("result_code")
    if code not in BROWSER_FORM_RESULT_CODES:
        raise RuntimeError("browser action receipt result code is invalid")
    for key in (
        "ok",
        "fill_confirmed",
        "submitted",
        "action_effect_observed",
        "navigation_observed",
        "form_disappeared",
        "cleaned",
    ):
        if not isinstance(payload.get(key), bool):
            raise RuntimeError("browser action receipt boolean contract mismatch")
    post_origin = payload.get("post_origin")
    if post_origin is not None and not isinstance(post_origin, str):
        raise RuntimeError("browser action receipt origin contract mismatch")
    post_path_sha256 = payload.get("post_path_sha256")
    if post_path_sha256 is not None and (
        not isinstance(post_path_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", post_path_sha256) is None
    ):
        raise RuntimeError("browser action receipt path digest contract mismatch")
    remote_address_sha256 = payload.get("remote_address_sha256")
    if remote_address_sha256 is not None and (
        not isinstance(remote_address_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", remote_address_sha256) is None
    ):
        raise RuntimeError("browser action receipt remote-address digest mismatch")
    cleanup_only = request.get("cleanup_only") is True
    readiness = request.get("action_mode") == "readiness"
    if cleanup_only:
        if code != "cleanup" or payload["ok"] is not True or payload["submitted"] is not False:
            raise RuntimeError("browser cleanup receipt semantic mismatch")
    elif payload["ok"] is True:
        if readiness:
            if (
                code != "ready"
                or payload["fill_confirmed"] is not True
                or payload["submitted"] is not False
                or payload["action_effect_observed"] is not False
                or payload["navigation_observed"] is not False
                or payload["form_disappeared"] is not False
                or payload["post_origin"] != request.get("expected_origin")
                or payload["post_path_sha256"] is not None
                or payload["cleaned"] is not True
            ):
                raise RuntimeError("browser readiness receipt semantic mismatch")
        elif (
            code != "ok"
            or payload["fill_confirmed"] is not True
            or payload["submitted"] is not True
            or payload["action_effect_observed"] is not True
        ):
            raise RuntimeError("browser action success receipt semantic mismatch")
    elif code in {"ok", "ready", "cleanup"}:
        raise RuntimeError("browser action failure receipt semantic mismatch")
    if execution["returncode"] == 0 and payload["ok"] is not True:
        raise RuntimeError("browser action success exit disagrees with receipt")
    if execution["returncode"] != 0 and payload["ok"] is not False:
        raise RuntimeError("browser action failure exit disagrees with receipt")
    return payload


def _browser_form_action_scope(
    worker_id: str,
    origin: str,
    selectors: dict[str, str],
    identity_choice: str | None,
    action_mode: str = "submit",
) -> tuple[str, dict[str, str], str | None]:
    selector_hashes = {
        key: _sha256_text(selectors[key])
        for key in ("identity", "protected", "submit")
    }
    choice_hash = _sha256_text(identity_choice) if identity_choice is not None else None
    scope = {
        "schema_version": 1,
        "worker_id": worker_id,
        "expected_origin": origin,
        "selector_sha256": selector_hashes,
        "identity_choice_sha256": choice_hash,
        "action_mode": action_mode,
    }
    return _sha256_text(_canonical_json(scope)), selector_hashes, choice_hash


def _browser_form_confirmation(worker_id: str, origin: str, scope_sha256: str) -> str:
    return f"{BROWSER_FORM_CONFIRMATION_PREFIX} {worker_id} {origin} {scope_sha256}"


def browser_stored_form_action(
    worker_id: str,
    *,
    expected_origin: str,
    identity_selector: str,
    protected_selector: str,
    submit_selector: str,
    confirmation: str,
    identity_choice: str | None = None,
    action_mode: str = "submit",
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    identifier = _validate_worker_id(worker_id)
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 5 <= timeout_seconds <= 30:
        raise ValueError("timeout_seconds must be between 5 and 30")
    selectors = {
        "identity": _validate_form_selector(identity_selector, "identity_selector"),
        "protected": _validate_form_selector(protected_selector, "protected_selector"),
        "submit": _validate_form_selector(submit_selector, "submit_selector"),
    }
    choice = _validate_identity_choice(identity_choice)
    mode = _validate_form_action_mode(action_mode)
    origin, address_sha256, allowed_addresses = _canonical_local_origin(expected_origin)
    action_scope_sha256, selector_hashes, choice_hash = _browser_form_action_scope(
        identifier, origin, selectors, choice, mode
    )
    expected_confirmation = _browser_form_confirmation(
        identifier, origin, action_scope_sha256
    )
    if confirmation != expected_confirmation:
        raise PermissionError("browser stored-form action confirmation mismatch")
    public = worker_status(identifier, expected_kind="browser")
    if public["state"] != "running":
        raise RuntimeError("browser worker is not running")
    record = _row(identifier)
    if not isinstance(record.get("port"), int):
        raise RuntimeError("browser worker has no CDP port")
    port_lease = resources.inspect_resource(f"port:{record['port']}")
    if port_lease is None or port_lease.get("owner_id") != f"worker:{identifier}":
        raise RuntimeError("browser worker no longer owns its CDP port")

    action_id = uuid.uuid4().hex
    owner = f"browser-action:{action_id}"
    lease_key = f"component:browser-action:{identifier}"
    resources.acquire_resources(
        owner,
        [lease_key],
        purpose="target-bound browser stored-form action",
        ttl_seconds=timeout_seconds + 30,
        metadata={
            "worker_id": identifier,
            "expected_origin": origin,
            "action_scope_sha256": action_scope_sha256,
        },
    )
    try:
        base._append_audit(
            {
                "timestamp_unix": _now(),
                "operation": "browser-worker-stored-form-action-intent",
                "action_id": action_id,
                "worker_id": identifier,
                "kind": "browser",
                "unit": record["unit"],
                "expected_origin": origin,
                "resolved_addresses_sha256": address_sha256,
                "action_scope_sha256": action_scope_sha256,
                "selector_sha256": selector_hashes,
                "identity_choice_sha256": choice_hash,
                "confirmation_sha256": _sha256_text(confirmation),
                "action_mode": mode,
            }
        )
        intent_record_sha256 = base._verify_audit_log(base.AUDIT_LOG)[
            "last_record_sha256"
        ]
    except Exception:
        try:
            resources.release_resources(owner, [lease_key])
        except (PermissionError, ValueError):
            pass
        raise
    payload: dict[str, Any]
    action_error: Exception | None = None
    try:
        payload = _run_node_form_action(
            record,
            {
                "schema_version": 1,
                "port": record["port"],
                "expected_origin": origin,
                "allowed_addresses": allowed_addresses,
                "cleanup_only": False,
                "action_mode": mode,
                "selectors": selectors,
                "identity_choice": choice,
                "timeout_ms": timeout_seconds * 1000,
            },
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        action_error = exc
        cleaned = False
        remote_address_sha256: str | None = None
        try:
            cleanup = _run_node_form_action(
                record,
                {
                    "schema_version": 1,
                    "port": record["port"],
                    "expected_origin": origin,
                    "allowed_addresses": allowed_addresses,
                    "cleanup_only": True,
                    "selectors": selectors,
                    "identity_choice": None,
                    "timeout_ms": timeout_seconds * 1000,
                },
                timeout_seconds=timeout_seconds,
            )
            cleaned = cleanup["cleaned"]
            remote_address_sha256 = cleanup["remote_address_sha256"]
        except Exception:
            pass
        payload = {
            "schema_version": 1,
            "ok": None,
            "result_code": "protocol",
            "fill_confirmed": None,
            "submitted": None,
            "action_effect_observed": None,
            "navigation_observed": None,
            "form_disappeared": None,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": remote_address_sha256,
            "cleaned": cleaned,
        }
    finally:
        try:
            resources.release_resources(owner, [lease_key])
        except (PermissionError, ValueError):
            pass

    audit = {
        "timestamp_unix": _now(),
        "operation": "browser-worker-stored-form-action",
        "action_id": action_id,
        "worker_id": identifier,
        "kind": "browser",
        "unit": record["unit"],
        "expected_origin": origin,
        "resolved_addresses_sha256": address_sha256,
        "action_scope_sha256": action_scope_sha256,
        "selector_sha256": selector_hashes,
        "identity_choice_sha256": choice_hash,
        "confirmation_sha256": _sha256_text(confirmation),
        "action_mode": mode,
        "intent_record_sha256": intent_record_sha256,
        "result_code": payload["result_code"],
        "outcome_known": action_error is None,
        "ok": payload["ok"],
        "fill_confirmed": payload["fill_confirmed"],
        "submitted": payload["submitted"],
        "action_effect_observed": payload["action_effect_observed"],
        "navigation_observed": payload["navigation_observed"],
        "form_disappeared": payload["form_disappeared"],
        "post_origin": payload["post_origin"],
        "post_path_sha256": payload["post_path_sha256"],
        "remote_address_sha256": payload["remote_address_sha256"],
        "cleaned": payload["cleaned"],
    }
    base._append_audit(audit)
    audit_sha256 = base._verify_audit_log(base.AUDIT_LOG)["last_record_sha256"]
    if payload["post_origin"] not in {None, origin}:
        raise RuntimeError("browser stored-form action changed to an unexpected origin")
    return {
        "schema_version": 1,
        "ok": payload["ok"],
        "action_id": action_id,
        "worker_id": identifier,
        "expected_origin": origin,
        "resolved_addresses_sha256": address_sha256,
        "action_scope_sha256": action_scope_sha256,
        "selector_sha256": selector_hashes,
        "identity_choice_sha256": choice_hash,
        "action_mode": mode,
        "intent_record_sha256": intent_record_sha256,
        "result_code": payload["result_code"],
        "fill_confirmed": payload["fill_confirmed"],
        "submitted": payload["submitted"],
        "action_effect_observed": payload["action_effect_observed"],
        "navigation_observed": payload["navigation_observed"],
        "form_disappeared": payload["form_disappeared"],
        "post_origin": payload["post_origin"],
        "post_path_sha256": payload["post_path_sha256"],
        "remote_address_sha256": payload["remote_address_sha256"],
        "cleaned": payload["cleaned"],
        "audit_record_sha256": audit_sha256,
        "does_not_establish": (
            [
                "authentication_success_without_target-specific readback",
                "absence_of_server_side_effects_beyond_the_submitted_form",
            ]
            if mode == "submit"
            else [
                "authentication_success",
                "future_submit_success",
                "browser_profile_contains_a_reusable_stored_entry",
            ]
        ),
    }


def browser_start(
    executable: str,
    *,
    port: int,
    args: list[str] | None = None,
    persistent_profile: str | None = None,
    runtime_seconds: int = 3600,
) -> dict[str, Any]:
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError("browser CDP port must be between 1024 and 65535")
    runtime = operator._job_runtime(runtime_seconds)
    binary = _executable(
        executable,
        environment_name="GRABOWSKI_BROWSER_EXECUTABLES",
        defaults=DEFAULT_BROWSER_EXECUTABLES,
    )
    extra = _validate_args(args)
    forbidden = (
        "--remote-debugging-address",
        "--remote-debugging-port",
        "--user-data-dir",
    )
    if any(any(item == prefix or item.startswith(prefix + "=") for prefix in forbidden) for item in extra):
        raise ValueError("browser args may not override profile or CDP binding")
    worker_id = uuid.uuid4().hex[:20]
    profile, ephemeral = _browser_profile(worker_id, persistent_profile)
    argv = [
        str(binary),
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        *extra,
    ]
    lease_keys = [f"port:{port}", f"browser-profile:{profile}"]
    ephemeral_paths = [profile] if ephemeral else []
    config = {
        "schema_version": 1,
        "kind": "browser",
        "argv": argv,
        "environment": {"HOME": str(operator.HOME)},
        "xvfb_argv": None,
        "worker_id": worker_id,
    }
    return _start(
        kind="browser",
        executable=binary,
        argv=argv,
        config=config,
        profile_path=profile,
        port=port,
        display_number=None,
        lease_keys=lease_keys,
        ephemeral_paths=ephemeral_paths,
        runtime_seconds=runtime,
        writable_paths=[WORKER_STATE, profile],
    )


def gui_start(
    executable: str,
    *,
    display_number: int,
    args: list[str] | None = None,
    runtime_seconds: int = 3600,
) -> dict[str, Any]:
    if not isinstance(display_number, int) or not 10 <= display_number <= 4095:
        raise ValueError("GUI display number must be between 10 and 4095")
    runtime = operator._job_runtime(runtime_seconds)
    xvfb = shutil.which("Xvfb")
    if not xvfb:
        raise RuntimeError("Xvfb is not installed")
    binary = _executable(
        executable,
        environment_name="GRABOWSKI_GUI_EXECUTABLES",
        defaults=DEFAULT_GUI_EXECUTABLES,
    )
    extra = _validate_args(args)
    worker_id = uuid.uuid4().hex[:20]
    directory = WORKER_STATE / "gui" / worker_id
    xdg_config = directory / "config"
    xdg_cache = directory / "cache"
    xdg_data = directory / "data"
    for path in (xdg_config, xdg_cache, xdg_data):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    display = f":{display_number}"
    argv = [str(binary), *extra]
    xvfb_argv = [
        str(Path(xvfb).resolve(strict=True)),
        display,
        "-screen",
        "0",
        "1920x1080x24",
        "-nolisten",
        "tcp",
        "-noreset",
    ]
    config = {
        "schema_version": 1,
        "kind": "gui",
        "argv": argv,
        "environment": {
            "HOME": str(operator.HOME),
            "DISPLAY": display,
            "XDG_CONFIG_HOME": str(xdg_config),
            "XDG_CACHE_HOME": str(xdg_cache),
            "XDG_DATA_HOME": str(xdg_data),
        },
        "xvfb_argv": xvfb_argv,
        "worker_id": worker_id,
    }
    return _start(
        kind="gui",
        executable=binary,
        argv=argv,
        config=config,
        profile_path=None,
        port=None,
        display_number=display_number,
        lease_keys=[f"display:{display_number}"],
        ephemeral_paths=[directory],
        runtime_seconds=runtime,
        writable_paths=[WORKER_STATE, directory],
    )


def worker_status(worker_id: str, *, expected_kind: str | None = None) -> dict[str, Any]:
    record = _row(worker_id)
    if expected_kind is not None and record["kind"] != expected_kind:
        raise ValueError(f"Worker is not a {expected_kind} worker")
    stored, _observation = _reconcile_record(record)
    return _public(stored)


def worker_stop(worker_id: str, *, expected_kind: str | None = None) -> dict[str, Any]:
    record = _row(worker_id)
    if expected_kind is not None and record["kind"] != expected_kind:
        raise ValueError(f"Worker is not a {expected_kind} worker")
    result = operator._run(
        ["systemctl", "--user", "stop", record["unit"]],
        cwd=operator.HOME,
        timeout_seconds=60,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    state = "stopped" if result["returncode"] == 0 else record["state"]
    observation: dict[str, Any] = {
        "state": state,
        "stop": result,
        "observed_at_unix": _now(),
    }
    stored = _update(worker_id, state, observation=observation)
    if result["returncode"] == 0:
        observation["terminalization"] = {
            "release": _release(stored),
            "cleanup": _cleanup(stored),
        }
        stored = _update(worker_id, state, observation=observation)
    return {"worker": _public(stored), "result": result}


def _worker_cursor_encode(
    kind: str, view: str, created_at_unix: int, worker_id: str
) -> str:
    return f"{kind}:{view}:{created_at_unix}:{worker_id}"


def _worker_cursor_decode(
    cursor: str | None, *, kind: str, view: str
) -> tuple[int, str] | None:
    if cursor in {None, ""}:
        return None
    if not isinstance(cursor, str):
        raise ValueError("cursor must be text")
    if len(cursor) > 128:
        raise ValueError("cursor is too large")
    match = WORKER_LIST_CURSOR.fullmatch(cursor)
    if match is None or match.group(1) != kind or match.group(2) != view:
        raise ValueError("cursor is invalid or bound to another worker view")
    return int(match.group(3)), match.group(4)


def _worker_rows(
    kind: str,
    view: str,
    *,
    cursor: tuple[int, str] | None,
    row_limit: int,
) -> list[dict[str, Any]]:
    states = (
        tuple(sorted(WORKER_STATES))
        if view == "current"
        else tuple(sorted(WORKER_HISTORY_STATES))
    )
    placeholders = ",".join("?" for _ in states)
    query = (
        f"SELECT * FROM workers WHERE kind=? AND state IN ({placeholders})"
    )
    parameters: list[Any] = [kind, *states]
    if cursor is not None:
        created_at_unix, worker_id = cursor
        query += (
            " AND (created_at_unix < ? OR "
            "(created_at_unix = ? AND worker_id < ?))"
        )
        parameters.extend([created_at_unix, created_at_unix, worker_id])
    query += " ORDER BY created_at_unix DESC, worker_id DESC LIMIT ?"
    parameters.append(row_limit)
    connection = _read_database()
    if connection is None:
        return []
    try:
        rows = connection.execute(query, parameters).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _observed_projection_record(
    record: dict[str, Any], observation: dict[str, Any]
) -> dict[str, Any]:
    projected = dict(record)
    projected["state"] = observation["state"]
    projected["updated_at_unix"] = max(
        int(record["updated_at_unix"]), int(observation["observed_at_unix"])
    )
    projected["last_observation_json"] = _canonical_json(observation)
    return projected


def _current_worker_projection(
    record: dict[str, Any],
    observation: dict[str, Any],
    *,
    freshly_observed: bool,
) -> dict[str, Any] | None:
    state = record["state"]
    if state in WORKER_ACTIVE_STATES:
        return {
            "bucket": "active",
            "fresh": True,
            "action_required": False,
            "reason": None,
        }
    if _terminalization_action_required(observation):
        return {
            "bucket": "attention",
            "fresh": False,
            "action_required": True,
            "reason": "terminalization-incomplete",
        }
    if freshly_observed and state == "failed":
        return {
            "bucket": "attention",
            "fresh": True,
            "action_required": True,
            "reason": "worker-failed",
        }
    if freshly_observed and state == "interrupted":
        return {
            "bucket": "attention",
            "fresh": True,
            "action_required": True,
            "reason": "systemd-observation-ambiguous",
        }
    return None


def worker_list(
    kind: str,
    limit: int = 100,
    *,
    view: str = "current",
    cursor: str | None = None,
) -> dict[str, Any]:
    if kind not in {"browser", "gui"}:
        raise ValueError("kind must be browser or gui")
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    if view not in WORKER_LIST_VIEWS:
        raise ValueError("view must be current or history")
    decoded_cursor = _worker_cursor_decode(cursor, kind=kind, view=view)

    if view == "history":
        rows = _worker_rows(
            kind, view, cursor=decoded_cursor, row_limit=limit + 1
        )
        selected = rows[:limit]
        has_more = len(rows) > limit
        next_cursor = (
            _worker_cursor_encode(
                kind,
                view,
                selected[-1]["created_at_unix"],
                selected[-1]["worker_id"],
            )
            if has_more and selected
            else None
        )
        public_workers: list[dict[str, Any]] = []
        for record in selected:
            item = _public(record)
            item["projection"] = {
                "bucket": "history",
                "fresh": False,
                "action_required": False,
                "reason": None,
            }
            public_workers.append(item)
        return {
            "schema_version": 2,
            "kind": kind,
            "view": view,
            "count": len(public_workers),
            "workers": public_workers,
            "scanned_count": len(selected),
            "observed_count": 0,
            "has_more": has_more,
            "next_cursor": next_cursor,
            "scan_truncated": False,
            "does_not_establish": [
                "fresh systemd state for historical records",
                "permission to delete worker evidence",
            ],
        }

    rows = _worker_rows(
        kind,
        view,
        cursor=decoded_cursor,
        row_limit=WORKER_LIST_MAX_SCAN + 1,
    )
    public_workers: list[dict[str, Any]] = []
    processed = 0
    observed = 0
    next_cursor: str | None = None
    has_more = False
    for index, record in enumerate(rows[:WORKER_LIST_MAX_SCAN]):
        processed += 1
        freshly_observed = record["state"] in WORKER_ACTIVE_STATES
        if freshly_observed:
            observation = _observe(record)
            projected = _observed_projection_record(record, observation)
            observed += 1
        else:
            observation = (
                json.loads(record["last_observation_json"])
                if record["last_observation_json"]
                else {}
            )
            projected = record
        projection = _current_worker_projection(
            projected, observation, freshly_observed=freshly_observed
        )
        if projection is not None:
            item = _public(projected)
            item["projection"] = {
                **projection,
                "stored_state": record["state"],
                "persisted_by_list": False,
            }
            public_workers.append(item)
        if len(public_workers) >= limit:
            has_more = index + 1 < len(rows)
            if has_more:
                next_cursor = _worker_cursor_encode(
                    kind, view, record["created_at_unix"], record["worker_id"]
                )
            break
    else:
        if len(rows) > WORKER_LIST_MAX_SCAN:
            has_more = True
            last = rows[WORKER_LIST_MAX_SCAN - 1]
            next_cursor = _worker_cursor_encode(
                kind, view, last["created_at_unix"], last["worker_id"]
            )

    return {
        "schema_version": 2,
        "kind": kind,
        "view": view,
        "count": len(public_workers),
        "workers": public_workers,
        "scanned_count": processed,
        "observed_count": observed,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "scan_truncated": len(rows) > WORKER_LIST_MAX_SCAN,
        "does_not_establish": [
            "stored lifecycle convergence or lease release from list output",
            "absence of older active records beyond a truncated scan",
            "permission to release foreign leases",
            "worker action success from registry state alone",
        ],
        "recommended_next_action": (
            "call the exact worker status surface for persisted reconciliation"
            if any(item["projection"]["action_required"] for item in public_workers)
            else "none"
        ),
    }


def _audit(operation: str, result: dict[str, Any]) -> None:
    worker = result.get("worker", result)
    base._append_audit(
        {
            "timestamp_unix": _now(),
            "operation": operation,
            "worker_id": worker["worker_id"],
            "kind": worker["kind"],
            "unit": worker["unit"],
            "state": worker["state"],
            "port": worker.get("port"),
            "display_number": worker.get("display_number"),
        }
    )


@mcp.tool(name="grabowski_browser_worker_start", annotations=MUTATING)
def grabowski_browser_worker_start(
    executable: str,
    port: int,
    args: list[str] | None = None,
    persistent_profile: str | None = None,
    runtime_seconds: int = 3600,
) -> dict[str, Any]:
    """Start one agent-owned browser with loopback-only CDP in a separate unit."""
    operator._require_operator_mutation("browser_worker")
    result = browser_start(
        executable,
        port=port,
        args=args,
        persistent_profile=persistent_profile,
        runtime_seconds=runtime_seconds,
    )
    _audit("browser-worker-start", result)
    return result


@mcp.tool(name="grabowski_browser_worker_stored_form_action", annotations=MUTATING)
def grabowski_browser_worker_stored_form_action(
    worker_id: str,
    expected_origin: str,
    identity_selector: str,
    protected_selector: str,
    submit_selector: str,
    confirmation: str,
    identity_choice: str | None = None,
    action_mode: str = "submit",
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Use browser-managed stored form data on one exact local origin.

    Confirmation must be one line containing the authorization prefix,
    worker id, canonical origin and the exact action-scope SHA-256. The result never
    returns field contents, raw selectors, query strings or URL fragments.
    Readiness mode verifies fill and clears the fields without submitting.
    """
    operator._require_operator_mutation("browser_worker")
    return browser_stored_form_action(
        worker_id,
        expected_origin=expected_origin,
        identity_selector=identity_selector,
        protected_selector=protected_selector,
        submit_selector=submit_selector,
        confirmation=confirmation,
        identity_choice=identity_choice,
        action_mode=action_mode,
        timeout_seconds=timeout_seconds,
    )


@mcp.tool(name="grabowski_browser_worker_status", annotations=READ_ONLY)
def grabowski_browser_worker_status(worker_id: str) -> dict[str, Any]:
    """Observe one isolated browser worker and release terminal leases."""
    operator._require_operator_capability("browser_worker")
    return worker_status(worker_id, expected_kind="browser")


@mcp.tool(name="grabowski_browser_worker_stop", annotations=MUTATING)
def grabowski_browser_worker_stop(worker_id: str) -> dict[str, Any]:
    """Stop one isolated browser worker and clean ephemeral state."""
    operator._require_operator_mutation("browser_worker")
    result = worker_stop(worker_id, expected_kind="browser")
    _audit("browser-worker-stop", result)
    return result


@mcp.tool(name="grabowski_browser_worker_list", annotations=READ_ONLY)
def grabowski_browser_worker_list(
    limit: int = 100,
    view: str = "current",
    cursor: str | None = None,
) -> dict[str, Any]:
    """List current or historical browser workers with fresh read-only observation."""
    operator._require_operator_capability("browser_worker")
    return worker_list("browser", limit, view=view, cursor=cursor)


@mcp.tool(name="grabowski_gui_worker_start", annotations=MUTATING)
def grabowski_gui_worker_start(
    executable: str,
    display_number: int,
    args: list[str] | None = None,
    runtime_seconds: int = 3600,
) -> dict[str, Any]:
    """Start one argv-only GUI child on an isolated Xvfb display without a listener."""
    operator._require_operator_mutation("gui_worker")
    result = gui_start(
        executable,
        display_number=display_number,
        args=args,
        runtime_seconds=runtime_seconds,
    )
    _audit("gui-worker-start", result)
    return result


@mcp.tool(name="grabowski_gui_worker_status", annotations=READ_ONLY)
def grabowski_gui_worker_status(worker_id: str) -> dict[str, Any]:
    """Observe one isolated GUI worker and release terminal leases."""
    operator._require_operator_capability("gui_worker")
    return worker_status(worker_id, expected_kind="gui")


@mcp.tool(name="grabowski_gui_worker_stop", annotations=MUTATING)
def grabowski_gui_worker_stop(worker_id: str) -> dict[str, Any]:
    """Stop one isolated GUI worker and clean its ephemeral XDG state."""
    operator._require_operator_mutation("gui_worker")
    result = worker_stop(worker_id, expected_kind="gui")
    _audit("gui-worker-stop", result)
    return result


@mcp.tool(name="grabowski_gui_worker_list", annotations=READ_ONLY)
def grabowski_gui_worker_list(
    limit: int = 100,
    view: str = "current",
    cursor: str | None = None,
) -> dict[str, Any]:
    """List current or historical GUI workers with fresh read-only observation."""
    operator._require_operator_capability("gui_worker")
    return worker_list("gui", limit, view=view, cursor=cursor)
