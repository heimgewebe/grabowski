from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time
import uuid
from typing import Any

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


def _release(record: dict[str, Any]) -> None:
    keys = json.loads(record["lease_keys_json"])
    if keys:
        try:
            resources.release_resources(f"worker:{record['worker_id']}", keys)
        except (PermissionError, ValueError):
            pass


def _cleanup(record: dict[str, Any]) -> None:
    for raw in json.loads(record["ephemeral_paths_json"]):
        path = Path(raw)
        try:
            if path == WORKER_STATE or WORKER_STATE not in path.parents:
                continue
            shutil.rmtree(path)
        except FileNotFoundError:
            pass


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
    observation = _observe(record)
    stored = _update(worker_id, observation["state"], observation=observation)
    if observation["state"] not in {"launching", "running"}:
        _release(stored)
        _cleanup(stored)
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
    stored = _update(worker_id, state, observation={"stop": result})
    if result["returncode"] == 0:
        _release(stored)
        _cleanup(stored)
    return {"worker": _public(stored), "result": result}


def worker_list(kind: str, limit: int = 100) -> dict[str, Any]:
    if kind not in {"browser", "gui"}:
        raise ValueError("kind must be browser or gui")
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    with _database() as connection:
        rows = connection.execute(
            "SELECT * FROM workers WHERE kind=? ORDER BY created_at_unix DESC LIMIT ?",
            (kind, limit),
        ).fetchall()
    return {"kind": kind, "count": len(rows), "workers": [_public(dict(row)) for row in rows]}


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
def grabowski_browser_worker_list(limit: int = 100) -> dict[str, Any]:
    """List isolated agent-owned browser workers."""
    operator._require_operator_capability("browser_worker")
    return worker_list("browser", limit)


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
def grabowski_gui_worker_list(limit: int = 100) -> dict[str, Any]:
    """List isolated GUI workers."""
    operator._require_operator_capability("gui_worker")
    return worker_list("gui", limit)
