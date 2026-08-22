from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
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
import grabowski_browser_bidi as browser_bidi
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
BROWSER_SEMANTIC_TEMP_NAME = re.compile(
    r"\.browser-semantic-[0-9a-f]{32}\.(?:json|mjs)\Z"
)
BROWSER_SEMANTIC_TEMP_CLEANUP_LIMIT = 256
BROWSER_BIDI_SESSION_NAME = ".webdriver-bidi-session.json"
BROWSER_BIDI_ADAPTER_ID = "chrome-webdriver-bidi"
BROWSER_FALLBACK_SAFE_START_ARGS = frozenset({"--headless", "--headless=new", "--disable-gpu", "--no-default-browser-check", "--disable-dev-shm-usage"})
WORKER_LIMIT_CORE_PROPERTY = "--property=LimitCORE=0"
DEFAULT_BROWSER_EXECUTABLES = (
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/brave-browser",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
)
BROWSER_CONTROL_PLANE_SCHEMA_VERSION = 1
BROWSER_CONTROL_PLANE_AUTHORITY = "grabowski"
BROWSER_CONTROL_PLANE_FUTURE_ADAPTERS = (
    {
        "id": "webdriver-bidi",
        "protocol": "webdriver-bidi",
        "implemented": False,
        "intended_browser_family": "firefox",
    },
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


def _browser_adapter_policy(
    executable: str | Path, *, require_supported: bool = True
) -> dict[str, Any]:
    path = Path(str(executable))
    normalized = str(path).lower().replace("_", "-")
    name = path.name.lower()
    parts = tuple(part.lower() for part in path.parts)

    if "brave" in normalized:
        family = "brave"
        vendor = "brave"
        adapter_id = "chromium-cdp"
        role = "fallback-test"
    elif "chromium" in normalized:
        family = "chromium"
        vendor = "chromium"
        adapter_id = "chromium-cdp"
        role = "fallback-test"
    elif (
        "chrome-for-testing" in normalized
        or "chrome-headless-shell" in normalized
        or any(part.startswith("chrome-linux") for part in parts)
    ):
        family = "chrome-for-testing"
        vendor = "google"
        adapter_id = "chrome-cdp"
        role = "reproducible-test"
    elif (
        "google-chrome" in normalized
        or "/google/chrome/" in normalized
        or name == "chrome"
    ):
        nonstable = any(channel in normalized for channel in ("beta", "unstable", "dev"))
        family = "chrome-nonstable" if nonstable else "chrome-stable"
        vendor = "google"
        adapter_id = "chrome-cdp"
        role = "fallback-test" if nonstable else "canonical-operator"
    else:
        if require_supported:
            raise ValueError(
                "browser executable has no supported CDP adapter; "
                "WebDriver BiDi is not implemented"
            )
        return {
            "family": "unsupported",
            "vendor": "unknown",
            "adapter_id": None,
            "protocol": None,
            "selection_role": "unsupported",
            "implemented": False,
        }

    return {
        "family": family,
        "vendor": vendor,
        "adapter_id": adapter_id,
        "protocol": "cdp",
        "selection_role": role,
        "implemented": True,
    }


def _browser_record_adapter(record: dict[str, Any]) -> dict[str, Any]:
    base_adapter = _browser_adapter_policy(record["executable"], require_supported=False)
    try:
        argv = json.loads(record.get("argv_json") or "[]")
    except json.JSONDecodeError:
        argv = []
    expected_port = record.get("port")
    if (
        isinstance(argv, list)
        and len(argv) == 4
        and isinstance(argv[0], str)
        and Path(argv[0]).is_absolute()
        and isinstance(expected_port, int)
        and not isinstance(expected_port, bool)
        and argv[1:] == [
            f"--port={expected_port}",
            "--allowed-ips=127.0.0.1",
            "--verbose",
        ]
        and base_adapter.get("family") == "chrome-stable"
    ):
        return {
            **base_adapter,
            "adapter_id": BROWSER_BIDI_ADAPTER_ID,
            "protocol": "webdriver-bidi",
            "selection_role": "qualified-pre-effect-fallback",
            "implemented": True,
        }
    return base_adapter


def _chromedriver_executable(raw: str) -> Path:
    if not isinstance(raw, str):
        raise ValueError("chromedriver executable must be text")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise ValueError("chromedriver executable must be absolute")
    resolved = candidate.resolve(strict=True)
    metadata = resolved.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(resolved, os.X_OK)
    ):
        raise PermissionError("chromedriver executable metadata is unsafe")
    configured = _configured_executables("GRABOWSKI_CHROMEDRIVER_EXECUTABLES", ())
    cache_root = (operator.HOME / ".cache" / "selenium" / "chromedriver").resolve(strict=False)
    if resolved not in configured and not resolved.is_relative_to(cache_root):
        raise PermissionError(
            "chromedriver executable is outside GRABOWSKI_CHROMEDRIVER_EXECUTABLES and the bounded Selenium cache"
        )
    return resolved


_BROWSER_CDP_ADAPTER_IDS = frozenset({"chrome-cdp", "chromium-cdp"})
_BROWSER_CDP_CAPABILITIES = (
    "loopback-debugging",
    "profile-isolation",
    "exclusive-profile-lease",
    "terminal-outcome-readback",
)


def _browser_adapter_runtime_contract(
    adapter: dict[str, Any], *, port: int | None
) -> dict[str, Any]:
    if adapter.get("implemented") is not True:
        return {
            "capabilities": [],
            "endpoint": {"address": None, "port": port, "loopback_only": False},
        }
    adapter_id = adapter.get("adapter_id")
    if adapter_id in _BROWSER_CDP_ADAPTER_IDS:
        capabilities = list(_BROWSER_CDP_CAPABILITIES)
    elif adapter_id == BROWSER_BIDI_ADAPTER_ID:
        capabilities = [
            "loopback-webdriver",
            "webdriver-bidi",
            "profile-isolation",
            "exclusive-profile-lease",
            "terminal-outcome-readback",
            "qualified-pre-effect-fallback",
        ]
    else:
        raise ValueError("browser adapter runtime contract is not implemented")
    return {
        "capabilities": capabilities,
        "endpoint": {
            "address": "127.0.0.1",
            "port": port,
            "loopback_only": True,
        },
    }


def _browser_adapter_launch_preflight(
    adapter: dict[str, Any], *, port: int, args: list[str]
) -> dict[str, Any]:
    if adapter.get("adapter_id") not in _BROWSER_CDP_ADAPTER_IDS:
        raise ValueError("browser adapter launch is not implemented")
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("browser CDP port must be between 1024 and 65535")
    forbidden = (
        "--remote-debugging-address",
        "--remote-debugging-port",
        "--user-data-dir",
    )
    if any(
        any(item == prefix or item.startswith(prefix + "=") for prefix in forbidden)
        for item in args
    ):
        raise ValueError("browser args may not override profile or CDP binding")
    return _browser_adapter_runtime_contract(adapter, port=port)


def _browser_adapter_launch_argv(
    adapter: dict[str, Any],
    *,
    executable: Path,
    port: int,
    profile: Path,
    args: list[str],
) -> list[str]:
    if adapter.get("adapter_id") not in _BROWSER_CDP_ADAPTER_IDS:
        raise ValueError("browser adapter launch is not implemented")
    return [
        str(executable),
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile}",
        "--no-first-run",
        *args,
    ]


def _browser_profile_mode(record: dict[str, Any]) -> str:
    profile_path = record.get("profile_path")
    if not isinstance(profile_path, str) or not profile_path:
        return "unknown"
    ephemeral_paths = {
        str(item) for item in json.loads(record.get("ephemeral_paths_json") or "[]")
    }
    return "ephemeral" if profile_path in ephemeral_paths else "persistent"


def _browser_profile_identity(profile_path: str | None) -> str | None:
    if not profile_path:
        return None
    normalized = os.path.normpath(profile_path)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _browser_control_plane(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("kind") != "browser":
        raise ValueError("browser control-plane projection requires a browser worker")
    adapter = _browser_record_adapter(record)
    runtime_contract = _browser_adapter_runtime_contract(
        adapter, port=record.get("port")
    )
    profile_path = record.get("profile_path")
    profile_mode = _browser_profile_mode(record)
    profile_identity = _browser_profile_identity(profile_path)
    profile_lease_identity = (
        hashlib.sha256(f"browser-profile:{profile_path}".encode("utf-8")).hexdigest()
        if profile_path
        else None
    )
    return {
        "schema_version": BROWSER_CONTROL_PLANE_SCHEMA_VERSION,
        "kind": "browser-control-plane",
        "authority": {
            "control_plane": BROWSER_CONTROL_PLANE_AUTHORITY,
            "lease": "grabowski-resource-store",
            "worker_state": "grabowski-worker-registry",
            "outcome_readback": "grabowski-browser-worker-status",
            "audit": "grabowski-audit-chain",
        },
        "intent": {
            "kind": "browser-session",
            "effect_class": "managed-runtime-process",
        },
        "adapter": {
            "id": adapter["adapter_id"],
            "protocol": adapter["protocol"],
            "implemented": adapter["implemented"],
            "capabilities": runtime_contract["capabilities"],
            "future_adapters": [dict(item) for item in BROWSER_CONTROL_PLANE_FUTURE_ADAPTERS],
        },
        "browser": {
            "family": adapter["family"],
            "vendor": adapter["vendor"],
            "selection_role": adapter["selection_role"],
        },
        "endpoint": runtime_contract["endpoint"],
        "profile": {
            "mode": profile_mode,
            "scope_kind": (
                "worker-ephemeral"
                if profile_mode == "ephemeral"
                else "explicit-auth-trust-scope"
                if profile_mode == "persistent"
                else "unknown"
            ),
            "canonicalized": profile_mode in {"ephemeral", "persistent"},
            "exclusive_lease": True,
            "identity_sha256": profile_identity,
            "lease_identity_sha256": profile_lease_identity,
        },
        "outcome": {
            "state": record.get("state"),
            "readback": "grabowski-browser-worker-status",
        },
        "does_not_establish": [
            "browser authentication success",
            "profile credential contents",
            *(
                ["Firefox availability", "WebDriver BiDi availability beyond this exact worker session"]
                if adapter["adapter_id"] == BROWSER_BIDI_ADAPTER_ID
                else ["Firefox or WebDriver BiDi availability"]
            ),
            "remote debugging beyond loopback",
        ],
    }


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


def _write_private_worker_json(directory: Path, name: str, value: dict[str, Any]) -> Path:
    target = directory / name
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"private worker file already exists: {name}")
    payload = (_canonical_json(value) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target


def _read_browser_bidi_session(record: dict[str, Any]) -> dict[str, str]:
    directory = Path(record["config_path"]).parent
    target = directory / BROWSER_BIDI_SESSION_NAME
    if target.is_symlink():
        raise PermissionError("BiDi session file may not be a symlink")
    metadata = target.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 32 * 1024
    ):
        raise PermissionError("BiDi session file metadata is unsafe")
    value = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeError("BiDi session file contract mismatch")
    result: dict[str, str] = {}
    for key in ("session_id", "websocket_url", "browser_version", "driver_version"):
        field = value.get(key)
        if not isinstance(field, str) or not field:
            raise RuntimeError("BiDi session identity is incomplete")
        result[key] = field
    return result


def _write_browser_semantic_handle_key(directory: Path) -> None:
    target = directory / ".semantic-handle-key"
    payload = (secrets.token_hex(32) + "\n").encode("ascii")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
        WORKER_LIMIT_CORE_PROPERTY,
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
    public = {
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
    if record["kind"] == "browser":
        public["control_plane"] = _browser_control_plane(record)
    return public


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


def _cleanup_browser_semantic_temps(
    directory: Path,
) -> tuple[list[str], list[str], list[dict[str, str]]]:
    removed: list[str] = []
    preserved: list[str] = []
    errors: list[dict[str, str]] = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, flags)
    except FileNotFoundError:
        return removed, preserved, errors
    except OSError as exc:
        return removed, preserved, [{"path": str(directory), "error": str(exc)}]
    try:
        try:
            entries = os.scandir(directory_fd)
        except OSError as exc:
            return removed, preserved, [{"path": str(directory), "error": str(exc)}]
        with entries:
            for index, entry in enumerate(entries):
                if index >= BROWSER_SEMANTIC_TEMP_CLEANUP_LIMIT:
                    break
                if BROWSER_SEMANTIC_TEMP_NAME.fullmatch(entry.name) is None:
                    continue
                path = directory / entry.name
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    errors.append({"path": str(path), "error": str(exc)})
                    continue
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    preserved.append(str(path))
                    continue
                try:
                    rebound = os.stat(
                        entry.name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        rebound.st_dev != metadata.st_dev
                        or rebound.st_ino != metadata.st_ino
                        or not stat.S_ISREG(rebound.st_mode)
                    ):
                        preserved.append(str(path))
                        continue
                    os.unlink(entry.name, dir_fd=directory_fd)
                    removed.append(str(path))
                except OSError as exc:
                    errors.append({"path": str(path), "error": str(exc)})
    finally:
        os.close(directory_fd)
    return removed, preserved, errors


def _cleanup_browser_bidi_session_file(directory: Path) -> dict[str, Any]:
    target = directory / BROWSER_BIDI_SESSION_NAME
    removed: list[str] = []
    absent: list[str] = []
    errors: list[dict[str, str]] = []
    try:
        target.unlink()
        removed.append(str(target))
    except FileNotFoundError:
        absent.append(str(target))
    except OSError as exc:
        errors.append({"path": str(target), "error": str(exc)})
    return {
        "status": "partial" if errors else "completed",
        "removed": removed,
        "already_absent": absent,
        "preserved_evidence": [],
        "errors": errors,
    }


def _cleanup(record: dict[str, Any]) -> dict[str, Any]:
    removed: list[str] = []
    absent: list[str] = []
    preserved: list[str] = []
    errors: list[dict[str, str]] = []
    evidence_directory = WORKER_STATE / "instances" / record["worker_id"]
    if record.get("kind") == "browser":
        temp_removed, temp_preserved, temp_errors = (
            _cleanup_browser_semantic_temps(evidence_directory)
        )
        removed.extend(temp_removed)
        preserved.extend(temp_preserved)
        errors.extend(temp_errors)
        handle_key = evidence_directory / ".semantic-handle-key"
        try:
            handle_key.unlink()
            removed.append(str(handle_key))
        except FileNotFoundError:
            absent.append(str(handle_key))
        except OSError as exc:
            errors.append({"path": str(handle_key), "error": str(exc)})
        bidi_cleanup = _cleanup_browser_bidi_session_file(evidence_directory)
        removed.extend(bidi_cleanup["removed"])
        absent.extend(bidi_cleanup["already_absent"])
        errors.extend(bidi_cleanup["errors"])
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


def _terminalization_core_complete(terminalization: dict[str, Any]) -> bool:
    release = terminalization.get("release")
    cleanup = terminalization.get("cleanup")
    return bool(
        isinstance(release, dict)
        and release.get("status") in {"released", "already-absent"}
        and isinstance(cleanup, dict)
        and cleanup.get("status") == "completed"
    )


def _failed_unit_evidence(observation: dict[str, Any]) -> bool:
    candidates = [observation, observation.get("prior_observation")]
    terminalization = observation.get("terminalization")
    if isinstance(terminalization, dict):
        unit_reset = terminalization.get("unit_reset")
        if isinstance(unit_reset, dict):
            probe = unit_reset.get("probe")
            if isinstance(probe, dict):
                candidates.append(probe)
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        properties = candidate.get("properties")
        if isinstance(properties, dict) and properties.get("ActiveState") == "failed":
            return True
    return False


def _probe_failed_unit_state(record: dict[str, Any]) -> dict[str, Any]:
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
    if result.get("returncode") != 0:
        state = "unknown"
    elif active == "failed":
        state = "failed"
    elif load == "not-found" or active in {"inactive", "deactivating"}:
        state = "not-failed"
    else:
        state = "unknown"
    return {
        "status": state,
        "properties": properties,
        "result": result,
    }


def _reset_failed_unit(
    record: dict[str, Any],
    observation: dict[str, Any],
    *,
    probe_current: bool = False,
) -> dict[str, Any]:
    terminalization = observation.get("terminalization")
    if not isinstance(terminalization, dict) or not _terminalization_core_complete(
        terminalization
    ):
        return {"status": "deferred"}
    failed_evidence = _failed_unit_evidence(observation)
    probe = None
    if not failed_evidence and probe_current:
        probe = _probe_failed_unit_state(record)
        if probe["status"] == "unknown":
            return {"status": "incomplete", "probe": probe}
        if probe["status"] == "failed":
            failed_evidence = True
        else:
            return {"status": "not-required", "probe": probe}
    if not failed_evidence:
        return {"status": "not-required"}
    result = operator._run(
        ["systemctl", "--user", "reset-failed", record["unit"]],
        cwd=operator.HOME,
        timeout_seconds=30,
        max_output_bytes=operator.DEFAULT_OUTPUT_BYTES,
    )
    outcome: dict[str, Any] = {
        "status": "reset" if result.get("returncode") == 0 else "incomplete",
        "result": result,
    }
    if result.get("returncode") != 0:
        readback = _probe_failed_unit_state(record)
        outcome["readback"] = readback
        if readback["status"] == "not-failed":
            outcome["status"] = "not-required"
    if probe is not None:
        outcome["probe"] = probe
    return outcome


def _terminalization_settled(observation: dict[str, Any]) -> bool:
    terminalization = observation.get("terminalization")
    if not isinstance(terminalization, dict) or not _terminalization_core_complete(
        terminalization
    ):
        return False
    unit_reset = terminalization.get("unit_reset")
    if isinstance(unit_reset, dict):
        return unit_reset.get("status") in {"reset", "not-required"}
    return not _failed_unit_evidence(observation)


def _terminalization_action_required(observation: dict[str, Any]) -> bool:
    terminalization = observation.get("terminalization")
    if not isinstance(terminalization, dict):
        return False
    release = terminalization.get("release")
    cleanup = terminalization.get("cleanup")
    if bool(
        isinstance(release, dict)
        and release.get("status") in {"blocked", "partial", "incomplete"}
    ) or bool(isinstance(cleanup, dict) and cleanup.get("status") == "partial"):
        return True
    unit_reset = terminalization.get("unit_reset")
    if isinstance(unit_reset, dict) and unit_reset.get("status") in {
        "deferred",
        "incomplete",
    }:
        return True
    return bool(
        _terminalization_core_complete(terminalization)
        and _failed_unit_evidence(observation)
        and not isinstance(unit_reset, dict)
    )


def _reconcile_record(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = _observe(record)
    stored = _update(record["worker_id"], observation["state"], observation=observation)
    if observation["state"] not in WORKER_ACTIVE_STATES:
        terminalization = {
            "release": _release(stored),
            "cleanup": _cleanup(stored),
        }
        observation = {
            **observation,
            "terminalization": terminalization,
        }
        if _terminalization_core_complete(terminalization):
            terminalization["unit_reset"] = _reset_failed_unit(stored, observation)
        stored = _update(
            record["worker_id"], observation["state"], observation=observation
        )
    return stored, observation


_SYSTEMD_TIMESPAN_FACTORS_US = {
    "us": 1,
    "ms": 1_000,
    "s": 1_000_000,
    "min": 60 * 1_000_000,
    "h": 60 * 60 * 1_000_000,
    "d": 24 * 60 * 60 * 1_000_000,
    "w": 7 * 24 * 60 * 60 * 1_000_000,
}
_SYSTEMD_TIMESPAN_TOKEN = re.compile(r"(\d+)(us|ms|s|min|h|d|w)")


def _systemd_timespan_us(value: str | None) -> int | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or raw == "infinity":
        return None
    total = 0
    position = 0
    matched = False
    for match in _SYSTEMD_TIMESPAN_TOKEN.finditer(raw):
        if raw[position : match.start()].strip():
            return None
        total += int(match.group(1)) * _SYSTEMD_TIMESPAN_FACTORS_US[match.group(2)]
        position = match.end()
        matched = True
    if not matched or raw[position:].strip():
        return None
    return total


def _planned_runtime_limit_reached(
    record: dict[str, Any], properties: dict[str, str]
) -> bool:
    try:
        runtime_seconds = int(record["runtime_seconds"])
        active_enter_us = int(properties["ActiveEnterTimestampMonotonic"])
        active_exit_us = int(properties["ActiveExitTimestampMonotonic"])
    except (KeyError, TypeError, ValueError):
        return False
    if runtime_seconds <= 0 or active_enter_us <= 0 or active_exit_us <= active_enter_us:
        return False
    expected_runtime_us = runtime_seconds * 1_000_000
    if _systemd_timespan_us(properties.get("RuntimeMaxUSec")) != expected_runtime_us:
        return False
    if active_exit_us - active_enter_us < expected_runtime_us:
        return False
    exec_main_code = properties.get("ExecMainCode")
    exec_main_status = properties.get("ExecMainStatus")
    if exec_main_status == "0":
        return exec_main_code in {None, "", "1"}
    return exec_main_code == "2" and exec_main_status == "15"


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
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            "--property=RuntimeMaxUSec",
            "--property=ActiveEnterTimestampMonotonic",
            "--property=ActiveExitTimestampMonotonic",
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
    observed_at_unix = _now()
    planned_runtime_limit = bool(
        unit_result == "timeout" and _planned_runtime_limit_reached(record, properties)
    )
    if result["returncode"] != 0:
        state = "interrupted"
    elif load in {None, "not-found"}:
        if (unit_result == "success" and exec_main_status == "0") or planned_runtime_limit:
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
    elif planned_runtime_limit:
        state = "completed"
    elif (
        active == "failed"
        or unit_result not in {None, "", "success"}
        or exec_main_status not in {None, "", "0"}
    ):
        state = "failed"
    elif active in {"inactive", "deactivating"}:
        state = "completed" if unit_result in {None, "", "success"} else "failed"
    else:
        state = "interrupted"
    return {
        "state": state,
        "properties": properties,
        "probe": result,
        "observed_at_unix": observed_at_unix,
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
    try:
        if kind == "browser":
            _write_browser_semantic_handle_key(directory)
        config_path = _write_config(directory, config)
    except Exception:
        for path in reversed(ephemeral_paths):
            try:
                shutil.rmtree(path)
            except FileNotFoundError:
                pass
        raise
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
            terminalization = {
                "release": _release(stored),
                "cleanup": _cleanup(stored),
            }
            observation: dict[str, Any] = {
                "state": "failed",
                "launcher": launcher,
                "observed_at_unix": _now(),
                "terminalization": terminalization,
            }
            if _terminalization_core_complete(terminalization):
                terminalization["unit_reset"] = _reset_failed_unit(
                    stored, observation, probe_current=True
                )
            stored = _update(worker_id, state, observation=observation)
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
const EXIT_FLUSH_TIMEOUT_MS = 1000;
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
let receiptEmitted = false;

function emit(payload, status = 0) {
  if (receiptEmitted) return;
  receiptEmitted = true;
  const line = JSON.stringify(payload) + '\n';
  process.exitCode = status;
  const finish = () => {
    try { if (ws) ws.close(); } catch {}
    process.exit(status);
  };
  const forcedExit = setTimeout(finish, EXIT_FLUSH_TIMEOUT_MS);
  process.stdout.write(line, () => {
    clearTimeout(forcedExit);
    finish();
  });
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


# --- Browser semantic contract (observe -> snapshot -> act -> verify) ------
#
# This is a backend-neutral foundation layered on top of the Chrome/CDP
# adapter helpers above. It never surfaces raw CDP method names, selectors,
# backend node ids, or other backend-specific element locators to callers.
# Every action is bound to worker_id + an opaque immutable snapshot_id;
# element-targeted actions additionally require an opaque element_id derived
# from that exact snapshot. The adapter re-observes semantic DOM state before
# every effect and revalidates the selected node again immediately before the
# effect. This slice implements read, local_ui and network_navigation. Other
# external effect classes remain named but fail closed. See
# docs/browser-control-plane-v1.md.

BROWSER_EFFECT_CONTRACTS: dict[str, dict[str, Any]] = {
    "read": {
        "admission": "implemented",
        "requires_operator_mutation": False,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "local_ui": {
        "admission": "implemented",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "network_navigation": {
        "admission": "implemented",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "reversible_external": {
        "admission": "fail_closed",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "external_mutation": {
        "admission": "fail_closed",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "high_impact": {
        "admission": "fail_closed",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
}
BROWSER_EFFECT_CLASSES = tuple(BROWSER_EFFECT_CONTRACTS)
BROWSER_EFFECT_CLASSES_IMPLEMENTED = frozenset(
    effect_class
    for effect_class, contract in BROWSER_EFFECT_CONTRACTS.items()
    if contract["admission"] == "implemented"
)
BROWSER_ACTION_CATALOG: dict[str, dict[str, Any]] = {
    "read_state": {"effect_class": "read", "requires_element": False},
    "navigate": {
        "effect_class": "network_navigation",
        "requires_element": False,
        "requires_navigation_target": True,
    },
    "scroll_into_view": {"effect_class": "local_ui", "requires_element": True},
    "activate": {
        "effect_class": "network_navigation",
        "requires_element": True,
        "required_element_role": "link",
        "requires_bound_navigation_target": True,
    },
}
BROWSER_SEMANTIC_GATEWAY_OPERATIONS = ("observe", "act")
BROWSER_SEMANTIC_EFFECT_STATES = {
    "not_started",
    "not_applicable",
    "observed",
    "unknown",
}
BROWSER_SNAPSHOT_ID_PREFIX = "bsid2_"
BROWSER_ELEMENT_ID_PREFIX = "beid1_"
BROWSER_MAX_ELEMENTS = 80
BROWSER_ELEMENT_ROLE_MAX = 64
BROWSER_ELEMENT_NAME_MAX = 160
BROWSER_SEMANTIC_RESULT_CODES = {
    "ok",
    "transport",
    "protocol",
    "target-discovery",
    "element-contract",
    "navigation-error",
    "navigation-uncorrelated",
    "stale-snapshot",
    "unsupported-op",
}
BROWSER_SEMANTIC_OUTCOME_CODES = {
    "ok",
    "stale_snapshot",
    "effect_not_implemented",
    "target_unavailable",
    "element_contract",
    "fresh_worker_required",
    "navigation_failed",
    "observation_failed",
    "outcome_unknown",
    "protocol",
}
_BROWSER_NODE_RESULT_TO_OUTCOME = {
    "target-discovery": "target_unavailable",
    "transport": "protocol",
    "protocol": "protocol",
    "unsupported-op": "protocol",
    "element-contract": "element_contract",
    "navigation-error": "navigation_failed",
    "navigation-uncorrelated": "outcome_unknown",
    "stale-snapshot": "stale_snapshot",
}
BROWSER_SEMANTIC_NODE_SOURCE = r"""
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const request = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
let ws = null;
let nextId = 1;
let receiptEmitted = false;
const pending = new Map();
const sameDocumentNavigations = [];
const semanticRoles = new Set([
  'button', 'link', 'textbox', 'checkbox', 'radio', 'combobox', 'listbox',
  'option', 'slider', 'spinbutton', 'switch', 'tab', 'menuitem', 'treeitem',
  'heading',
]);

function emit(payload, status = 0) {
  if (receiptEmitted) return;
  receiptEmitted = true;
  const line = JSON.stringify(payload) + '\n';
  process.exitCode = status;
  process.stdout.write(line, () => {
    try { if (ws) ws.close(); } catch {}
    process.exit(status);
  });
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
      if (message.method === 'Page.navigatedWithinDocument') {
        const params = message.params || {};
        if (typeof params.frameId === 'string' && params.frameId) {
          sameDocumentNavigations.push({frame_id: params.frameId});
          if (sameDocumentNavigations.length > 16) sameDocumentNavigations.shift();
        }
      }
      if (message.id && pending.has(message.id)) {
        const entry = pending.get(message.id);
        pending.delete(message.id);
        clearTimeout(entry.timer);
        if (message.error) entry.reject(new Error('protocol'));
        else entry.resolve(message.result || {});
      }
    };
    ws.onclose = () => {
      for (const entry of pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(new Error('transport'));
      }
      pending.clear();
    };
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

function boundedText(value, limit) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, limit);
}

function semanticDomRawAttribute(node, name, maxBytes = 4096) {
  const attributes = Array.isArray(node && node.attributes) ? node.attributes : [];
  for (let index = 0; index + 1 < attributes.length; index += 2) {
    if (String(attributes[index] || '').toLowerCase() !== name) continue;
    const value = String(attributes[index + 1] || '');
    if (Buffer.byteLength(value, 'utf8') > maxBytes) {
      return {found: true, valid: false, value: ''};
    }
    return {found: true, valid: true, value};
  }
  return {found: false, valid: true, value: ''};
}

function semanticDomAttribute(node, name) {
  const raw = semanticDomRawAttribute(node, name);
  return raw.found && raw.valid ? boundedText(raw.value, 160) : '';
}

function semanticDomVisibilitySubtreeBlocked(node) {
  const localName = typeof node.localName === 'string'
    ? node.localName.toLowerCase() : '';
  const nodeName = typeof node.nodeName === 'string'
    ? node.nodeName.toLowerCase() : '';
  const inertNames = new Set(['script', 'style', 'noscript', 'template']);
  if (inertNames.has(localName) || inertNames.has(nodeName)) return true;
  const hidden = semanticDomRawAttribute(node, 'hidden', 64);
  const inert = semanticDomRawAttribute(node, 'inert', 64);
  if (hidden.found || inert.found) return true;
  const ariaHidden = semanticDomRawAttribute(node, 'aria-hidden', 64);
  if (!ariaHidden.valid) return true;
  return ariaHidden.found && ariaHidden.value.trim().toLowerCase() === 'true';
}

function semanticDomValueBearingSubtreeBlocked(node) {
  const localName = typeof node.localName === 'string'
    ? node.localName.toLowerCase() : '';
  const nodeName = typeof node.nodeName === 'string'
    ? node.nodeName.toLowerCase() : '';
  const valueBearingTags = new Set([
    'input', 'textarea', 'select', 'option', 'optgroup', 'output', 'meter', 'progress'
  ]);
  const valueBearingRoles = new Set([
    'textbox', 'searchbox', 'combobox', 'listbox', 'option', 'slider', 'spinbutton',
    'scrollbar', 'progressbar', 'meter'
  ]);
  if (valueBearingTags.has(localName) || valueBearingTags.has(nodeName)) return true;
  const rawRole = semanticDomRawAttribute(node, 'role', 512);
  if (!rawRole.valid) return true;
  const roleTokens = rawRole.value.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return roleTokens.some((token) => valueBearingRoles.has(token));
}

function semanticDomTextSubtreeBlocked(node) {
  if (semanticDomVisibilitySubtreeBlocked(node)) return true;
  if (semanticDomValueBearingSubtreeBlocked(node)) return true;

  const contentEditable = semanticDomRawAttribute(node, 'contenteditable', 64);
  if (!contentEditable.valid) return true;
  if (contentEditable.found) {
    return contentEditable.value.trim().toLowerCase() !== 'false';
  }
  return false;
}

function semanticSnapshotString(strings, index, maxBytes = 4096) {
  if (!Array.isArray(strings) || !Number.isInteger(index) || index < 0 || index >= strings.length) {
    return null;
  }
  const value = strings[index];
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maxBytes) return null;
  return value;
}

function semanticSnapshotNode(document, strings, nodeIndex) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const nodeTypes = nodes && Array.isArray(nodes.nodeType) ? nodes.nodeType : null;
  const nodeNames = nodes && Array.isArray(nodes.nodeName) ? nodes.nodeName : null;
  const attributes = nodes && Array.isArray(nodes.attributes) ? nodes.attributes : null;
  if (!backendNodeIds || !nodeTypes || !nodeNames || !attributes ||
      !Number.isInteger(nodeIndex) || nodeIndex < 0 || nodeIndex >= backendNodeIds.length ||
      nodeTypes.length !== backendNodeIds.length || nodeNames.length !== backendNodeIds.length ||
      attributes.length !== backendNodeIds.length) {
    return null;
  }
  const nodeName = semanticSnapshotString(strings, nodeNames[nodeIndex], 256);
  const encodedAttributes = attributes[nodeIndex];
  if (nodeName === null || !Array.isArray(encodedAttributes) ||
      encodedAttributes.length > 128 || encodedAttributes.length % 2 !== 0) {
    return null;
  }
  const decodedAttributes = [];
  for (const stringIndex of encodedAttributes) {
    const value = semanticSnapshotString(strings, stringIndex, 4096);
    if (value === null) return null;
    decodedAttributes.push(value);
  }
  return {
    backendNodeId: backendNodeIds[nodeIndex],
    nodeType: nodeTypes[nodeIndex],
    nodeName,
    localName: nodeName.toLowerCase(),
    attributes: decodedAttributes,
  };
}

function semanticSnapshotPathToTarget(parentIndex, nodeIndex, targetIndex, nodeCount) {
  if (!Array.isArray(parentIndex) || parentIndex.length !== nodeCount) return {ok: false, path: null};
  const path = [];
  let current = nodeIndex;
  for (let depth = 0; depth < 256; depth += 1) {
    if (!Number.isInteger(current) || current < 0 || current >= nodeCount) {
      return {ok: false, path: null};
    }
    path.push(current);
    if (current === targetIndex) return {ok: true, path};
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= nodeCount || parent === current) {
      return {ok: false, path: null};
    }
    if (parent === -1) return {ok: true, path: null};
    current = parent;
  }
  return {ok: false, path: null};
}

function semanticSnapshotHasHiddenAncestor(document, strings, targetIndex) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const parentIndex = nodes && Array.isArray(nodes.parentIndex) ? nodes.parentIndex : null;
  if (!backendNodeIds || !parentIndex || parentIndex.length !== backendNodeIds.length ||
      !Number.isInteger(targetIndex) || targetIndex < 0 || targetIndex >= backendNodeIds.length) {
    return {ok: false, blocked: true};
  }
  let current = parentIndex[targetIndex];
  for (let depth = 0; depth < 256; depth += 1) {
    if (!Number.isInteger(current) || current < -1 || current >= backendNodeIds.length ||
        current === targetIndex) {
      return {ok: false, blocked: true};
    }
    if (current === -1) return {ok: true, blocked: false};
    const node = semanticSnapshotNode(document, strings, current);
    if (!node) return {ok: false, blocked: true};
    if (semanticDomVisibilitySubtreeBlocked(node)) return {ok: true, blocked: true};
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= backendNodeIds.length ||
        parent === current) {
      return {ok: false, blocked: true};
    }
    current = parent;
  }
  return {ok: false, blocked: true};
}

function semanticSnapshotHasValueBearingAncestor(document, strings, targetIndex) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const parentIndex = nodes && Array.isArray(nodes.parentIndex) ? nodes.parentIndex : null;
  if (!backendNodeIds || !parentIndex || parentIndex.length !== backendNodeIds.length ||
      !Number.isInteger(targetIndex) || targetIndex < 0 || targetIndex >= backendNodeIds.length) {
    return {ok: false, blocked: true};
  }
  let current = parentIndex[targetIndex];
  for (let depth = 0; depth < 256; depth += 1) {
    if (!Number.isInteger(current) || current < -1 || current >= backendNodeIds.length ||
        current === targetIndex) {
      return {ok: false, blocked: true};
    }
    if (current === -1) return {ok: true, blocked: false};
    const node = semanticSnapshotNode(document, strings, current);
    if (!node) return {ok: false, blocked: true};
    if (semanticDomValueBearingSubtreeBlocked(node)) return {ok: true, blocked: true};
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= backendNodeIds.length ||
        parent === current) {
      return {ok: false, blocked: true};
    }
    current = parent;
  }
  return {ok: false, blocked: true};
}

function semanticSnapshotEffectiveContentEditable(document, strings, targetIndex) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const parentIndex = nodes && Array.isArray(nodes.parentIndex) ? nodes.parentIndex : null;
  if (!backendNodeIds || !parentIndex || parentIndex.length !== backendNodeIds.length ||
      !Number.isInteger(targetIndex) || targetIndex < 0 || targetIndex >= backendNodeIds.length) {
    return {ok: false, editable: true};
  }
  let current = targetIndex;
  for (let depth = 0; depth < 256; depth += 1) {
    const node = semanticSnapshotNode(document, strings, current);
    if (!node) return {ok: false, editable: true};
    const contentEditable = semanticDomRawAttribute(node, 'contenteditable', 64);
    if (!contentEditable.valid) return {ok: false, editable: true};
    if (contentEditable.found) {
      const value = contentEditable.value.trim().toLowerCase();
      if (value === 'false') return {ok: true, editable: false};
      // The empty string, true and plaintext-only are editing hosts. Unknown or
      // future tokens are treated conservatively as editable rather than risking
      // publication of inherited user-entered content.
      return {ok: true, editable: true};
    }
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= backendNodeIds.length ||
        parent === current) {
      return {ok: false, editable: true};
    }
    if (parent === -1) return {ok: true, editable: false};
    current = parent;
  }
  return {ok: false, editable: true};
}

function semanticFilterOpacityVisibility(filterText) {
  const normalized = filterText.trim().toLowerCase();
  if (!normalized || normalized === 'none') return {ok: true, visible: true};
  const pattern = /opacity\(([^()]*)\)/g;
  let matched = false;
  for (const match of normalized.matchAll(pattern)) {
    matched = true;
    const token = match[1].trim();
    const percentage = token.endsWith('%');
    const numericToken = percentage ? token.slice(0, -1).trim() : token;
    const value = Number(numericToken);
    if (!Number.isFinite(value)) return {ok: false, visible: false};
    const opacity = percentage ? value / 100 : value;
    if (opacity <= 0) return {ok: true, visible: false};
  }
  if (normalized.includes('opacity(') && !matched) return {ok: false, visible: false};
  return {ok: true, visible: true};
}

function semanticLayoutBoundsBox(bounds) {
  if (!Array.isArray(bounds) || bounds.length !== 4) return {ok: false, box: null};
  const values = bounds.map((value) => Number(value));
  if (values.some((value) => !Number.isFinite(value) || Math.abs(value) > 1000000000)) {
    return {ok: false, box: null};
  }
  const [left, top, width, height] = values;
  if (width < 0 || height < 0) return {ok: false, box: null};
  const right = left + width;
  const bottom = top + height;
  if (![right, bottom].every((value) => Number.isFinite(value) && Math.abs(value) <= 1000000000)) {
    return {ok: false, box: null};
  }
  return {ok: true, box: {left, top, right, bottom, width, height}};
}

function semanticLayoutBoundsVisibility(bounds) {
  const parsed = semanticLayoutBoundsBox(bounds);
  if (!parsed.ok) return {ok: false, visible: false};
  // DOMSnapshot bounds already include transforms.  Reject collapsed or
  // sub-pixel-degenerate rendered text instead of treating it as a visible label.
  return {ok: true, visible: parsed.box.width >= 0.5 && parsed.box.height >= 0.5};
}

function semanticOverflowClipping(overflowText) {
  const normalized = overflowText.trim().toLowerCase();
  if (normalized === 'visible') return {ok: true, clips: false};
  if (['hidden', 'clip', 'scroll', 'auto'].includes(normalized)) {
    return {ok: true, clips: true};
  }
  return {ok: false, clips: true};
}

function semanticAlphaVisibilityToken(token) {
  const trimmed = token.trim().toLowerCase();
  const percentage = trimmed.endsWith('%');
  const numericToken = percentage ? trimmed.slice(0, -1).trim() : trimmed;
  const value = Number(numericToken);
  if (!Number.isFinite(value)) return {ok: false, visible: false};
  const alpha = percentage ? value / 100 : value;
  return {ok: true, visible: alpha > 0};
}

function semanticCssColorVisibility(colorText) {
  const normalized = colorText.trim().toLowerCase();
  if (!normalized || Buffer.byteLength(normalized, 'utf8') > 256) {
    return {ok: false, visible: false};
  }
  if (normalized === 'transparent') return {ok: true, visible: false};
  if (normalized.endsWith(')')) {
    const slashIndex = normalized.lastIndexOf('/');
    if (slashIndex >= 0) {
      return semanticAlphaVisibilityToken(normalized.slice(slashIndex + 1, -1));
    }
    if (normalized.startsWith('rgba(') || normalized.startsWith('hsla(')) {
      const body = normalized.slice(normalized.indexOf('(') + 1, -1);
      const parts = body.split(',');
      if (parts.length !== 4) return {ok: false, visible: false};
      return semanticAlphaVisibilityToken(parts[3]);
    }
  }
  return {ok: true, visible: true};
}

function semanticTextPaintVisibility(strings, styleIndexes) {
  if (!Array.isArray(styleIndexes) || styleIndexes.length !== 10) {
    return {ok: false, visible: false};
  }
  const colorText = semanticSnapshotString(strings, styleIndexes[8], 256);
  const textFillColorText = semanticSnapshotString(strings, styleIndexes[9], 256);
  if (colorText === null || textFillColorText === null) {
    return {ok: false, visible: false};
  }
  const normalizedFill = textFillColorText.trim().toLowerCase();
  const effectiveFill = normalizedFill === 'currentcolor' ? colorText : textFillColorText;
  return semanticCssColorVisibility(effectiveFill);
}

function semanticLayoutVisibility(strings, styleIndexes, checkVisibility = true) {
  if (!Array.isArray(styleIndexes) || styleIndexes.length !== 10 ||
      typeof checkVisibility !== 'boolean') {
    return {ok: false, visible: false, clipsX: true, clipsY: true};
  }
  const visibility = semanticSnapshotString(strings, styleIndexes[0], 64);
  const opacityText = semanticSnapshotString(strings, styleIndexes[1], 64);
  const contentVisibility = semanticSnapshotString(strings, styleIndexes[2], 64);
  const filterText = semanticSnapshotString(strings, styleIndexes[3], 512);
  const clipPathText = semanticSnapshotString(strings, styleIndexes[4], 512);
  const clipText = semanticSnapshotString(strings, styleIndexes[5], 512);
  const overflowXText = semanticSnapshotString(strings, styleIndexes[6], 64);
  const overflowYText = semanticSnapshotString(strings, styleIndexes[7], 64);
  if (visibility === null || opacityText === null || contentVisibility === null ||
      filterText === null || clipPathText === null || clipText === null ||
      overflowXText === null || overflowYText === null) {
    return {ok: false, visible: false, clipsX: true, clipsY: true};
  }
  const overflowX = semanticOverflowClipping(overflowXText);
  const overflowY = semanticOverflowClipping(overflowYText);
  if (!overflowX.ok || !overflowY.ok) {
    return {ok: false, visible: false, clipsX: true, clipsY: true};
  }
  const normalizedVisibility = visibility.trim().toLowerCase();
  const normalizedContentVisibility = contentVisibility.trim().toLowerCase();
  const normalizedClipPath = clipPathText.trim().toLowerCase();
  const normalizedClip = clipText.trim().toLowerCase();
  const opacity = Number(opacityText.trim());
  if (!Number.isFinite(opacity)) {
    return {ok: false, visible: false, clipsX: overflowX.clips, clipsY: overflowY.clips};
  }
  if ((checkVisibility && ['hidden', 'collapse'].includes(normalizedVisibility)) ||
      normalizedContentVisibility === 'hidden' || opacity <= 0) {
    return {ok: true, visible: false, clipsX: overflowX.clips, clipsY: overflowY.clips};
  }
  // A non-default clipping primitive can remove all rendered pixels while
  // retaining normal layout bounds.  The semantic fallback cannot safely
  // prove partial paint visibility from DOMSnapshot alone, so fail closed for
  // any explicit clip-path / legacy clip rather than publishing hidden text.
  if ((normalizedClipPath && normalizedClipPath !== 'none') ||
      (normalizedClip && normalizedClip !== 'auto')) {
    return {ok: true, visible: false, clipsX: overflowX.clips, clipsY: overflowY.clips};
  }
  const filterVisibility = semanticFilterOpacityVisibility(filterText);
  if (!filterVisibility.ok) {
    return {ok: false, visible: false, clipsX: overflowX.clips, clipsY: overflowY.clips};
  }
  return {
    ok: true, visible: filterVisibility.visible,
    clipsX: overflowX.clips, clipsY: overflowY.clips,
  };
}

function semanticLayoutBoundsWithinClipping(candidateBounds, clippingBounds, clipsX, clipsY) {
  if (typeof clipsX !== 'boolean' || typeof clipsY !== 'boolean') {
    return {ok: false, visible: false};
  }
  if (!clipsX && !clipsY) return {ok: true, visible: true};
  const candidate = semanticLayoutBoundsBox(candidateBounds);
  const clipping = semanticLayoutBoundsBox(clippingBounds);
  if (!candidate.ok || !clipping.ok) return {ok: false, visible: false};
  // Exact paint clipping can use the padding/scrollport box, which DOMSnapshot
  // does not expose in the bounded no-DOMRects contract.  Require full
  // containment in the rendered ancestor bounds on each clipping axis rather
  // than guessing partial visibility.  This is intentionally fail-closed.
  if (clipsX && (candidate.box.left < clipping.box.left ||
      candidate.box.right > clipping.box.right)) {
    return {ok: true, visible: false};
  }
  if (clipsY && (candidate.box.top < clipping.box.top ||
      candidate.box.bottom > clipping.box.bottom)) {
    return {ok: true, visible: false};
  }
  return {ok: true, visible: true};
}

function semanticSnapshotBoundsWithinClippingAncestors(
  document, strings, nodeIndex, layoutByNode, candidateBounds
) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const parentIndex = nodes && Array.isArray(nodes.parentIndex) ? nodes.parentIndex : null;
  const layout = document && document.layout ? document.layout : null;
  const layoutStyles = layout && Array.isArray(layout.styles) ? layout.styles : null;
  const layoutBounds = layout && Array.isArray(layout.bounds) ? layout.bounds : null;
  if (!backendNodeIds || !parentIndex || !layoutStyles || !layoutBounds ||
      !(layoutByNode instanceof Map) || parentIndex.length !== backendNodeIds.length ||
      layoutStyles.length !== layoutBounds.length || !Number.isInteger(nodeIndex) ||
      nodeIndex < 0 || nodeIndex >= backendNodeIds.length) {
    return {ok: false, visible: false};
  }
  let current = nodeIndex;
  for (let depth = 0; depth < 256; depth += 1) {
    const layoutIndex = layoutByNode.get(current);
    if (layoutIndex !== undefined) {
      if (!Number.isInteger(layoutIndex) || layoutIndex < 0 ||
          layoutIndex >= layoutStyles.length) {
        return {ok: false, visible: false};
      }
      const visibility = semanticLayoutVisibility(
        strings, layoutStyles[layoutIndex], current === nodeIndex
      );
      if (!visibility.ok) return {ok: false, visible: false};
      if (!visibility.visible) return {ok: true, visible: false};
      const clipping = semanticLayoutBoundsWithinClipping(
        candidateBounds, layoutBounds[layoutIndex], visibility.clipsX, visibility.clipsY
      );
      if (!clipping.ok) return {ok: false, visible: false};
      if (!clipping.visible) return {ok: true, visible: false};
    }
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= backendNodeIds.length ||
        parent === current) {
      return {ok: false, visible: false};
    }
    if (parent === -1) return {ok: true, visible: true};
    current = parent;
  }
  return {ok: false, visible: false};
}

function semanticSnapshotTargetAncestorsLayoutVisible(
  document, strings, targetIndex, layoutByNode
) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const parentIndex = nodes && Array.isArray(nodes.parentIndex) ? nodes.parentIndex : null;
  const layout = document && document.layout ? document.layout : null;
  const layoutStyles = layout && Array.isArray(layout.styles) ? layout.styles : null;
  if (!backendNodeIds || !parentIndex || !layoutStyles || !(layoutByNode instanceof Map) ||
      parentIndex.length !== backendNodeIds.length ||
      !Number.isInteger(targetIndex) || targetIndex < 0 || targetIndex >= backendNodeIds.length) {
    return {ok: false, visible: false};
  }
  let current = targetIndex;
  for (let depth = 0; depth < 256; depth += 1) {
    const layoutIndex = layoutByNode.get(current);
    if (layoutIndex !== undefined) {
      if (!Number.isInteger(layoutIndex) || layoutIndex < 0 || layoutIndex >= layoutStyles.length) {
        return {ok: false, visible: false};
      }
      const visibility = semanticLayoutVisibility(
        strings, layoutStyles[layoutIndex], current === targetIndex
      );
      if (!visibility.ok) return {ok: false, visible: false};
      if (!visibility.visible) return {ok: true, visible: false};
    }
    const parent = parentIndex[current];
    if (!Number.isInteger(parent) || parent < -1 || parent >= backendNodeIds.length ||
        parent === current) {
      return {ok: false, visible: false};
    }
    if (parent === -1) return {ok: true, visible: true};
    current = parent;
  }
  return {ok: false, visible: false};
}

function semanticSnapshotContentDocumentOwners(documents) {
  if (!Array.isArray(documents) || documents.length < 1 || documents.length > 32) {
    return {ok: false, owners: null, rootDocumentIndex: null};
  }
  const owners = new Map();
  for (let documentIndex = 0; documentIndex < documents.length; documentIndex += 1) {
    const document = documents[documentIndex];
    const nodes = document && document.nodes ? document.nodes : null;
    const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
    const contentDocumentIndex = nodes && nodes.contentDocumentIndex;
    const ownerIndexes = contentDocumentIndex && Array.isArray(contentDocumentIndex.index)
      ? contentDocumentIndex.index : null;
    const childIndexes = contentDocumentIndex && Array.isArray(contentDocumentIndex.value)
      ? contentDocumentIndex.value : null;
    if (!backendNodeIds || backendNodeIds.length > 50000 || !ownerIndexes || !childIndexes ||
        ownerIndexes.length !== childIndexes.length || ownerIndexes.length > documents.length - 1) {
      return {ok: false, owners: null, rootDocumentIndex: null};
    }
    for (let offset = 0; offset < ownerIndexes.length; offset += 1) {
      const ownerNodeIndex = ownerIndexes[offset];
      const childDocumentIndex = childIndexes[offset];
      if (!Number.isInteger(ownerNodeIndex) || ownerNodeIndex < 0 ||
          ownerNodeIndex >= backendNodeIds.length || !Number.isInteger(childDocumentIndex) ||
          childDocumentIndex < 0 || childDocumentIndex >= documents.length ||
          childDocumentIndex === documentIndex || owners.has(childDocumentIndex)) {
        return {ok: false, owners: null, rootDocumentIndex: null};
      }
      owners.set(childDocumentIndex, {documentIndex, nodeIndex: ownerNodeIndex});
    }
  }
  const roots = [];
  for (let documentIndex = 0; documentIndex < documents.length; documentIndex += 1) {
    if (!owners.has(documentIndex)) roots.push(documentIndex);
  }
  if (roots.length !== 1 || owners.size !== documents.length - 1) {
    return {ok: false, owners: null, rootDocumentIndex: null};
  }
  const rootDocumentIndex = roots[0];
  for (let start = 0; start < documents.length; start += 1) {
    const seen = new Set();
    let current = start;
    for (let depth = 0; depth <= documents.length; depth += 1) {
      if (current === rootDocumentIndex) break;
      if (seen.has(current)) return {ok: false, owners: null, rootDocumentIndex: null};
      seen.add(current);
      const owner = owners.get(current);
      if (!owner) return {ok: false, owners: null, rootDocumentIndex: null};
      current = owner.documentIndex;
      if (depth === documents.length) {
        return {ok: false, owners: null, rootDocumentIndex: null};
      }
    }
  }
  return {ok: true, owners, rootDocumentIndex};
}

function semanticSnapshotLayoutIndexMap(document) {
  const nodes = document && document.nodes ? document.nodes : null;
  const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
  const layout = document && document.layout ? document.layout : null;
  const layoutNodeIndexes = layout && Array.isArray(layout.nodeIndex) ? layout.nodeIndex : null;
  const layoutStyles = layout && Array.isArray(layout.styles) ? layout.styles : null;
  const layoutBounds = layout && Array.isArray(layout.bounds) ? layout.bounds : null;
  if (!backendNodeIds || backendNodeIds.length > 50000 || !layoutNodeIndexes || !layoutStyles ||
      !layoutBounds || layoutNodeIndexes.length > 50000 ||
      layoutStyles.length !== layoutNodeIndexes.length || layoutBounds.length !== layoutNodeIndexes.length) {
    return {ok: false, layoutByNode: null, layoutStyles: null, layoutBounds: null};
  }
  const layoutByNode = new Map();
  for (let layoutIndex = 0; layoutIndex < layoutNodeIndexes.length; layoutIndex += 1) {
    const nodeIndex = layoutNodeIndexes[layoutIndex];
    if (!Number.isInteger(nodeIndex) || nodeIndex < 0 || nodeIndex >= backendNodeIds.length ||
        layoutByNode.has(nodeIndex)) {
      return {ok: false, layoutByNode: null, layoutStyles: null, layoutBounds: null};
    }
    layoutByNode.set(nodeIndex, layoutIndex);
  }
  return {ok: true, layoutByNode, layoutStyles, layoutBounds};
}

function semanticSnapshotEmbeddingChainVisible(documents, strings, targetDocumentIndex) {
  const ownership = semanticSnapshotContentDocumentOwners(documents);
  if (!ownership.ok || !Number.isInteger(targetDocumentIndex) || targetDocumentIndex < 0 ||
      targetDocumentIndex >= documents.length) {
    return {ok: false, visible: false};
  }
  let currentDocumentIndex = targetDocumentIndex;
  const seen = new Set();
  for (let depth = 0; depth < documents.length; depth += 1) {
    if (currentDocumentIndex === ownership.rootDocumentIndex) {
      return {ok: true, visible: true};
    }
    if (seen.has(currentDocumentIndex)) return {ok: false, visible: false};
    seen.add(currentDocumentIndex);
    const owner = ownership.owners.get(currentDocumentIndex);
    if (!owner) return {ok: false, visible: false};
    const parentDocument = documents[owner.documentIndex];
    const ownerNode = semanticSnapshotNode(parentDocument, strings, owner.nodeIndex);
    if (!ownerNode) return {ok: false, visible: false};
    if (semanticDomVisibilitySubtreeBlocked(ownerNode) ||
        semanticDomValueBearingSubtreeBlocked(ownerNode)) {
      return {ok: true, visible: false};
    }
    const hiddenAncestor = semanticSnapshotHasHiddenAncestor(
      parentDocument, strings, owner.nodeIndex
    );
    if (!hiddenAncestor.ok) return {ok: false, visible: false};
    if (hiddenAncestor.blocked) return {ok: true, visible: false};
    const valueBearingAncestor = semanticSnapshotHasValueBearingAncestor(
      parentDocument, strings, owner.nodeIndex
    );
    if (!valueBearingAncestor.ok) return {ok: false, visible: false};
    if (valueBearingAncestor.blocked) return {ok: true, visible: false};
    const effectiveEditable = semanticSnapshotEffectiveContentEditable(
      parentDocument, strings, owner.nodeIndex
    );
    if (!effectiveEditable.ok) return {ok: false, visible: false};
    if (effectiveEditable.editable) return {ok: true, visible: false};
    const layoutInfo = semanticSnapshotLayoutIndexMap(parentDocument);
    if (!layoutInfo.ok) return {ok: false, visible: false};
    const ownerLayoutIndex = layoutInfo.layoutByNode.get(owner.nodeIndex);
    if (ownerLayoutIndex === undefined) return {ok: true, visible: false};
    const geometry = semanticLayoutBoundsVisibility(layoutInfo.layoutBounds[ownerLayoutIndex]);
    if (!geometry.ok) return {ok: false, visible: false};
    if (!geometry.visible) return {ok: true, visible: false};
    const clipping = semanticSnapshotBoundsWithinClippingAncestors(
      parentDocument, strings, owner.nodeIndex, layoutInfo.layoutByNode,
      layoutInfo.layoutBounds[ownerLayoutIndex]
    );
    if (!clipping.ok) return {ok: false, visible: false};
    if (!clipping.visible) return {ok: true, visible: false};
    const visibility = semanticSnapshotTargetAncestorsLayoutVisible(
      parentDocument, strings, owner.nodeIndex, layoutInfo.layoutByNode
    );
    if (!visibility.ok) return {ok: false, visible: false};
    if (!visibility.visible) return {ok: true, visible: false};
    currentDocumentIndex = owner.documentIndex;
  }
  return {ok: false, visible: false};
}

function semanticFrameIds(frameTree) {
  if (!frameTree || typeof frameTree !== 'object') return {ok: false, frameIds: null};
  const frameIds = [];
  const seen = new Set();
  const stack = [frameTree];
  while (stack.length > 0) {
    if (frameIds.length >= 64) return {ok: false, frameIds: null};
    const current = stack.pop();
    const frame = current && current.frame ? current.frame : null;
    const frameId = frame && typeof frame.id === 'string' ? frame.id : '';
    if (!frameId || Buffer.byteLength(frameId, 'utf8') > 256 || seen.has(frameId)) {
      return {ok: false, frameIds: null};
    }
    seen.add(frameId);
    frameIds.push(frameId);
    const children = current.childFrames === undefined ? [] : current.childFrames;
    if (!Array.isArray(children) || children.length > 64) {
      return {ok: false, frameIds: null};
    }
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push(children[index]);
    }
  }
  return frameIds.length > 0 ? {ok: true, frameIds} : {ok: false, frameIds: null};
}

async function readSemanticDesignModes() {
  try {
    const frameTree = await call('Page.getFrameTree');
    const frames = semanticFrameIds(frameTree && frameTree.frameTree);
    if (!frames.ok) return {ok: false, values: null};
    const values = [];
    for (const frameId of frames.frameIds) {
      const world = await call('Page.createIsolatedWorld', {
        frameId,
        worldName: 'grabowski-semantic-design-mode-v1',
        grantUniveralAccess: false,
      });
      const contextId = world && world.executionContextId;
      if (!Number.isSafeInteger(contextId) || contextId <= 0) {
        return {ok: false, values: null};
      }
      const response = await call('Runtime.evaluate', {
        expression: 'document.designMode',
        contextId,
        returnByValue: true,
        awaitPromise: false,
      });
      if (response.exceptionDetails || !response.result ||
          typeof response.result.value !== 'string') {
        return {ok: false, values: null};
      }
      const value = response.result.value.trim().toLowerCase();
      if (!['on', 'off'].includes(value)) return {ok: false, values: null};
      values.push([frameId, value]);
    }
    return {ok: true, values};
  } catch {
    return {ok: false, values: null};
  }
}

function semanticDesignModesAllOff(observation) {
  if (!observation || !observation.ok || !Array.isArray(observation.values) ||
      observation.values.length < 1 || observation.values.length > 64) {
    return false;
  }
  return observation.values.every((entry) =>
    Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string' &&
    entry[0] && entry[1] === 'off'
  );
}

async function captureSemanticVisibleSnapshot() {
  try {
    const designModesBefore = await readSemanticDesignModes();
    if (!semanticDesignModesAllOff(designModesBefore)) {
      return {ok: false, snapshot: null};
    }
    const snapshot = await call('DOMSnapshot.captureSnapshot', {
      computedStyles: ['visibility', 'opacity', 'content-visibility', 'filter', 'clip-path', 'clip', 'overflow-x', 'overflow-y', 'color', '-webkit-text-fill-color'],
      includePaintOrder: false,
      includeDOMRects: false,
    });
    const designModesAfter = await readSemanticDesignModes();
    if (!semanticDesignModesAllOff(designModesAfter) ||
        JSON.stringify(designModesAfter.values) !== JSON.stringify(designModesBefore.values)) {
      return {ok: false, snapshot: null};
    }
    return {ok: true, snapshot};
  } catch {
    return {ok: false, snapshot: null};
  }
}

function semanticVisibleTextFromSnapshot(snapshot, backendNodeId) {
  const strings = snapshot && Array.isArray(snapshot.strings) ? snapshot.strings : null;
  const documents = snapshot && Array.isArray(snapshot.documents) ? snapshot.documents : null;
  if (!strings || !documents || documents.length < 1 || documents.length > 32) {
    return {ok: false, name: ''};
  }
  let selected = null;
  for (let documentIndex = 0; documentIndex < documents.length; documentIndex += 1) {
    const document = documents[documentIndex];
    const nodes = document && document.nodes ? document.nodes : null;
    const backendNodeIds = nodes && Array.isArray(nodes.backendNodeId) ? nodes.backendNodeId : null;
    if (!backendNodeIds || backendNodeIds.length > 50000) return {ok: false, name: ''};
    const targetIndex = backendNodeIds.indexOf(backendNodeId);
    if (targetIndex < 0) continue;
    if (selected !== null) return {ok: false, name: ''};
    selected = {document, documentIndex, targetIndex};
  }
  if (selected === null) return {ok: false, name: ''};
  const embeddingVisibility = semanticSnapshotEmbeddingChainVisible(
    documents, strings, selected.documentIndex
  );
  if (!embeddingVisibility.ok) return {ok: false, name: ''};
  if (!embeddingVisibility.visible) return {ok: true, name: ''};
  const document = selected.document;
  const nodes = document.nodes;
  const nodeCount = nodes.backendNodeId.length;
  const targetNode = semanticSnapshotNode(document, strings, selected.targetIndex);
  if (!targetNode || targetNode.backendNodeId !== backendNodeId) return {ok: false, name: ''};
  if (semanticDomTextSubtreeBlocked(targetNode)) return {ok: true, name: ''};
  const hiddenAncestor = semanticSnapshotHasHiddenAncestor(
    document, strings, selected.targetIndex
  );
  if (!hiddenAncestor.ok) return {ok: false, name: ''};
  if (hiddenAncestor.blocked) return {ok: true, name: ''};
  const valueBearingAncestor = semanticSnapshotHasValueBearingAncestor(
    document, strings, selected.targetIndex
  );
  if (!valueBearingAncestor.ok) return {ok: false, name: ''};
  if (valueBearingAncestor.blocked) return {ok: true, name: ''};
  const effectiveEditable = semanticSnapshotEffectiveContentEditable(
    document, strings, selected.targetIndex
  );
  if (!effectiveEditable.ok) return {ok: false, name: ''};
  if (effectiveEditable.editable) return {ok: true, name: ''};

  const layout = document && document.layout ? document.layout : null;
  const layoutNodeIndexes = layout && Array.isArray(layout.nodeIndex) ? layout.nodeIndex : null;
  const layoutStyles = layout && Array.isArray(layout.styles) ? layout.styles : null;
  const layoutBounds = layout && Array.isArray(layout.bounds) ? layout.bounds : null;
  const layoutText = layout && Array.isArray(layout.text) ? layout.text : null;
  if (!layoutNodeIndexes || !layoutStyles || !layoutBounds || !layoutText ||
      layoutNodeIndexes.length > 50000 || layoutStyles.length !== layoutNodeIndexes.length ||
      layoutBounds.length !== layoutNodeIndexes.length || layoutText.length !== layoutNodeIndexes.length) {
    return {ok: false, name: ''};
  }
  const layoutByNode = new Map();
  for (let index = 0; index < layoutNodeIndexes.length; index += 1) {
    const nodeIndex = layoutNodeIndexes[index];
    if (!Number.isInteger(nodeIndex) || nodeIndex < 0 || nodeIndex >= nodeCount || layoutByNode.has(nodeIndex)) {
      return {ok: false, name: ''};
    }
    layoutByNode.set(nodeIndex, index);
  }

  const targetVisibility = semanticSnapshotTargetAncestorsLayoutVisible(
    document, strings, selected.targetIndex, layoutByNode
  );
  if (!targetVisibility.ok) return {ok: false, name: ''};
  if (!targetVisibility.visible) return {ok: true, name: ''};

  const pieces = [];
  let visitedTextLayouts = 0;
  for (let layoutIndex = 0; layoutIndex < layoutNodeIndexes.length; layoutIndex += 1) {
    const nodeIndex = layoutNodeIndexes[layoutIndex];
    const ancestry = semanticSnapshotPathToTarget(
      nodes.parentIndex, nodeIndex, selected.targetIndex, nodeCount
    );
    if (!ancestry.ok) return {ok: false, name: ''};
    if (!ancestry.path) continue;
    const text = semanticSnapshotString(strings, layoutText[layoutIndex], 4096);
    if (text === null) return {ok: false, name: ''};
    if (!boundedText(text, 160)) continue;
    const renderedGeometry = semanticLayoutBoundsVisibility(layoutBounds[layoutIndex]);
    if (!renderedGeometry.ok) return {ok: false, name: ''};
    if (!renderedGeometry.visible) continue;
    const textPaint = semanticTextPaintVisibility(strings, layoutStyles[layoutIndex]);
    if (!textPaint.ok) return {ok: false, name: ''};
    if (!textPaint.visible) continue;
    const clipping = semanticSnapshotBoundsWithinClippingAncestors(
      document, strings, nodeIndex, layoutByNode, layoutBounds[layoutIndex]
    );
    if (!clipping.ok) return {ok: false, name: ''};
    if (!clipping.visible) continue;
    visitedTextLayouts += 1;
    if (visitedTextLayouts > 512) return {ok: false, name: ''};
    let allowed = true;
    for (const pathIndex of ancestry.path) {
      const node = semanticSnapshotNode(document, strings, pathIndex);
      if (!node) return {ok: false, name: ''};
      if (semanticDomTextSubtreeBlocked(node)) {
        allowed = false;
        break;
      }
      const ancestorLayoutIndex = layoutByNode.get(pathIndex);
      if (ancestorLayoutIndex === undefined) continue;
      const visibility = semanticLayoutVisibility(
        strings, layoutStyles[ancestorLayoutIndex], pathIndex === nodeIndex
      );
      if (!visibility.ok) return {ok: false, name: ''};
      if (!visibility.visible) {
        allowed = false;
        break;
      }
    }
    if (!allowed) continue;
    pieces.push(text);
    if (boundedText(pieces.join(' '), 160).length >= 160) break;
  }
  return {ok: true, name: boundedText(pieces.join(' '), 160)};
}

async function readSemanticVisibleDomText(backendNodeId, snapshotProvider) {
  const captured = await snapshotProvider();
  if (!captured || !captured.ok) return {ok: false, name: ''};
  return semanticVisibleTextFromSnapshot(captured.snapshot, backendNodeId);
}

async function readSemanticElementName(
  backendNodeId,
  role,
  accessibilityName,
  snapshotProvider = captureSemanticVisibleSnapshot
) {
  const primary = boundedText(accessibilityName, 160);
  if (primary) return {ok: true, name: primary};
  let described;
  try {
    described = await call('DOM.describeNode', {
      backendNodeId, depth: 6, pierce: false,
    });
  } catch {
    return {ok: false, name: ''};
  }
  const node = described && described.node ? described.node : null;
  if (!node || node.backendNodeId !== backendNodeId) {
    return {ok: false, name: ''};
  }
  const candidates = [
    semanticDomAttribute(node, 'aria-label'),
    semanticDomAttribute(node, 'title'),
    role === 'textbox' ? semanticDomAttribute(node, 'placeholder') : '',
  ];
  const labeled = candidates.find((candidate) => Boolean(candidate));
  if (labeled) return {ok: true, name: labeled};
  const visibleLabelRoles = new Set([
    'button', 'link', 'tab', 'menuitem', 'treeitem', 'heading'
  ]);
  if (!visibleLabelRoles.has(role)) return {ok: true, name: ''};
  return readSemanticVisibleDomText(backendNodeId, snapshotProvider);
}

function sha256Text(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function canonicalLinkNavigationTarget(rawHref, baseUrl) {
  if (typeof rawHref !== 'string' || !rawHref || rawHref !== rawHref.trim() ||
      rawHref.includes(String.fromCharCode(92)) || Buffer.byteLength(rawHref, 'utf8') > 4096) {
    return null;
  }
  for (const character of rawHref) {
    const code = character.codePointAt(0);
    if (code <= 0x20 || code === 0x7f) return null;
  }
  let target;
  try {
    target = new URL(rawHref, baseUrl);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(target.protocol) || !target.hostname ||
      target.username || target.password || target.port === '0') {
    return null;
  }
  const value = target.href;
  return Buffer.byteLength(value, 'utf8') <= 4096 ? value : null;
}

async function readDocumentBaseUrl() {
  const document = await call('DOM.getDocument', {depth: 0, pierce: false});
  const root = document && document.root ? document.root : null;
  const value = root && typeof root.baseURL === 'string' && root.baseURL
    ? root.baseURL
    : (root && typeof root.documentURL === 'string' ? root.documentURL : '');
  if (!value) throw new Error('protocol');
  return value;
}

async function readLinkNavigationBinding(backendNodeId, baseUrl) {
  let described;
  try {
    described = await call('DOM.describeNode', {
      backendNodeId, depth: 0, pierce: false,
    });
  } catch {
    return null;
  }
  const node = described && described.node ? described.node : null;
  const localName = node && typeof node.localName === 'string'
    ? node.localName.toLowerCase() : '';
  const nodeName = node && typeof node.nodeName === 'string'
    ? node.nodeName.toLowerCase() : '';
  if (!node || (localName !== 'a' && nodeName !== 'a')) return null;
  const attributes = Array.isArray(node.attributes) ? node.attributes : [];
  let rawHref = null;
  for (let index = 0; index + 1 < attributes.length; index += 2) {
    if (attributes[index] === 'href') {
      rawHref = attributes[index + 1];
      break;
    }
  }
  const target = canonicalLinkNavigationTarget(rawHref, baseUrl);
  return target ? {target, sha256: sha256Text(target)} : null;
}

async function readElements() {
  const tree = await call('Accessibility.getFullAXTree');
  const elements = [];
  const seen = new Set();
  let baseUrl = null;
  let cachedVisibleSnapshot = null;
  const observedSnapshotProvider = async () => {
    if (cachedVisibleSnapshot === null) cachedVisibleSnapshot = await captureSemanticVisibleSnapshot();
    return cachedVisibleSnapshot;
  };
  for (const node of Array.isArray(tree.nodes) ? tree.nodes : []) {
    if (elements.length >= 80) break;
    if (!node || node.ignored === true || !Number.isInteger(node.backendDOMNodeId)) continue;
    if (node.backendDOMNodeId <= 0 || seen.has(node.backendDOMNodeId)) continue;
    const role = boundedText(node.role && node.role.value, 64);
    if (!semanticRoles.has(role)) continue;
    seen.add(node.backendDOMNodeId);
    let navigationTargetSha256 = null;
    if (role === 'link') {
      if (baseUrl === null) baseUrl = await readDocumentBaseUrl();
      const binding = await readLinkNavigationBinding(node.backendDOMNodeId, baseUrl);
      navigationTargetSha256 = binding ? binding.sha256 : null;
    }
    const naming = await readSemanticElementName(
      node.backendDOMNodeId,
      role,
      node.name && node.name.value,
      observedSnapshotProvider
    );
    elements.push({
      backend_node_id: String(node.backendDOMNodeId),
      role,
      name: naming.ok ? naming.name : '',
      navigation_target_sha256: navigationTargetSha256,
    });
  }
  return elements;
}

async function readNavigationIdentity() {
  const frameTree = await call('Page.getFrameTree');
  const mainFrame = frameTree.frameTree && frameTree.frameTree.frame
    ? frameTree.frameTree.frame : null;
  const mainFrameId = mainFrame && typeof mainFrame.id === 'string' ? mainFrame.id : null;
  const loaderId = mainFrame && typeof mainFrame.loaderId === 'string'
    ? mainFrame.loaderId : null;
  if (!mainFrameId || !loaderId) throw new Error('protocol');
  const history = await call('Page.getNavigationHistory');
  const entries = Array.isArray(history.entries) ? history.entries : [];
  const currentIndex = Number.isInteger(history.currentIndex) ? history.currentIndex : -1;
  const currentEntry = currentIndex >= 0 && currentIndex < entries.length
    ? entries[currentIndex] : null;
  const navigationEntryId = currentEntry &&
    (typeof currentEntry.id === 'number' || typeof currentEntry.id === 'string')
    ? String(currentEntry.id) : null;
  if (!navigationEntryId) throw new Error('protocol');
  return {
    main_frame_id: mainFrameId,
    loader_id: loaderId,
    navigation_entry_id: navigationEntryId,
  };
}

async function readState() {
  const identity = await readNavigationIdentity();
  const stateResponse = await call('Runtime.evaluate', {
    expression: `({
      origin: location.origin,
      ready_state: document.readyState,
      title: (document.title || '').slice(0, 200),
    })`,
    returnByValue: true,
    awaitPromise: true,
  });
  if (stateResponse.exceptionDetails) throw new Error('protocol');
  const state = stateResponse.result ? stateResponse.result.value : undefined;
  if (!state || typeof state.origin !== 'string') throw new Error('protocol');
  return {
    origin: state.origin,
    ready_state: String(state.ready_state || ''),
    title: String(state.title || ''),
    main_frame_id: identity.main_frame_id,
    loader_id: identity.loader_id,
    navigation_entry_id: identity.navigation_entry_id,
    elements: await readElements(),
  };
}

function sameElements(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  return left.every((element, index) => {
    const expected = right[index];
    return expected &&
      element.backend_node_id === expected.backend_node_id &&
      element.role === expected.role &&
      element.name === expected.name &&
      element.navigation_target_sha256 === expected.navigation_target_sha256;
  });
}

function sameState(left, right) {
  if (!left || !right) return false;
  for (const key of [
    'origin', 'ready_state', 'title', 'main_frame_id', 'loader_id',
    'navigation_entry_id',
  ]) {
    if (left[key] !== right[key]) return false;
  }
  return sameElements(left.elements, right.elements);
}

async function verifyElementImmediately(expected) {
  if (!expected || !/^[1-9][0-9]{0,19}$/.test(String(expected.backend_node_id || ''))) {
    throw new Error('element-contract');
  }
  const backendNodeId = Number(expected.backend_node_id);
  if (!Number.isSafeInteger(backendNodeId) || backendNodeId <= 0) {
    throw new Error('element-contract');
  }
  let partial;
  try {
    partial = await call('Accessibility.getPartialAXTree', {backendNodeId, fetchRelatives: false});
  } catch {
    throw new Error('stale-snapshot');
  }
  const nodes = Array.isArray(partial.nodes) ? partial.nodes : [];
  const node = nodes.find((item) => item && item.backendDOMNodeId === backendNodeId);
  if (!node || node.ignored === true) throw new Error('stale-snapshot');
  const role = boundedText(node.role && node.role.value, 64);
  const naming = await readSemanticElementName(
    backendNodeId,
    role,
    node.name && node.name.value
  );
  if (!naming.ok) throw new Error('stale-snapshot');
  if (role !== expected.role || naming.name !== expected.name) throw new Error('stale-snapshot');
  let resolved;
  try {
    resolved = await call('DOM.resolveNode', {backendNodeId});
  } catch {
    throw new Error('stale-snapshot');
  }
  const objectId = resolved && resolved.object && resolved.object.objectId;
  if (typeof objectId !== 'string' || !objectId) throw new Error('stale-snapshot');
  return objectId;
}


async function readLinkNavigationTarget(expected) {
  if (!expected || expected.role !== 'link' ||
      typeof expected.navigation_target_sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(expected.navigation_target_sha256)) {
    throw new Error('element-contract');
  }
  const objectId = await verifyElementImmediately(expected);
  try {
    const baseUrl = await readDocumentBaseUrl();
    const binding = await readLinkNavigationBinding(
      Number(expected.backend_node_id), baseUrl
    );
    if (!binding || binding.sha256 !== expected.navigation_target_sha256) {
      throw new Error('stale-snapshot');
    }
    return binding.target;
  } finally {
    try {
      await call('Runtime.releaseObject', {objectId});
    } catch {}
  }
}

async function performCorrelatedNavigation(before, navigationTarget) {
  sameDocumentNavigations.length = 0;
  const navigation = await call('Page.navigate', {url: navigationTarget});
  if (typeof navigation.errorText === 'string' && navigation.errorText.trim()) {
    throw new Error('navigation-error');
  }
  const acknowledgedFrameId = typeof navigation.frameId === 'string'
    ? navigation.frameId : null;
  const acknowledgedLoaderId = typeof navigation.loaderId === 'string'
    ? navigation.loaderId : null;
  if (!acknowledgedFrameId) throw new Error('navigation-uncorrelated');
  const deadline = Date.now() + request.timeout_ms;
  let correlation = null;
  let correlatedState = null;
  while (Date.now() <= deadline) {
    const identity = await readNavigationIdentity();
    const identityCorrelated = identity.main_frame_id === acknowledgedFrameId && (
      acknowledgedLoaderId
        ? identity.loader_id === acknowledgedLoaderId
        : identity.navigation_entry_id !== before.navigation_entry_id
    );
    if (identityCorrelated) {
      const state = await readState();
      const changed = !sameState(before, state);
      const newDocument = Boolean(
        acknowledgedLoaderId && changed &&
        state.main_frame_id === acknowledgedFrameId &&
        state.loader_id === acknowledgedLoaderId
      );
      const sameDocument = Boolean(
        !acknowledgedLoaderId && changed &&
        state.main_frame_id === acknowledgedFrameId &&
        state.navigation_entry_id !== before.navigation_entry_id &&
        sameDocumentNavigations.some((entry) => entry.frame_id === acknowledgedFrameId)
      );
      if (newDocument || sameDocument) {
        correlation = newDocument ? 'new-document' : 'same-document';
        correlatedState = state;
        break;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  if (!correlation) throw new Error('navigation-uncorrelated');
  return {state: correlatedState, correlation};
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
      const endpoint = new URL(target.webSocketDebuggerUrl);
      const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);
      return endpoint.protocol === 'ws:' && loopbackHosts.has(endpoint.hostname) &&
        Number(endpoint.port) === request.port;
    } catch { return false; }
  });
  if (matches.length !== 1) throw new Error('target-discovery');

  await connect(matches[0].webSocketDebuggerUrl);
  await call('Runtime.enable');
  await call('Page.enable');
  await call('DOM.enable');
  await call('Accessibility.enable');

  if (request.op === 'read_state') {
    const state = await readState();
    emit({schema_version: 1, ok: true, result_code: 'ok', state}, 0);
  } else if (request.op === 'navigate') {
    const before = await readState();
    if (!sameState(before, request.expected_state)) throw new Error('stale-snapshot');
    const navigation = await performCorrelatedNavigation(before, request.navigation_target);
    emit({
      schema_version: 1,
      ok: true,
      result_code: 'ok',
      state: navigation.state,
      navigation_correlation: navigation.correlation,
    }, 0);
  } else if (request.op === 'activate') {
    const before = await readState();
    if (!sameState(before, request.expected_state)) throw new Error('stale-snapshot');
    const expectedElement = request.expected_element;
    const selected = before.elements.find((element) =>
      expectedElement && element.backend_node_id === expectedElement.backend_node_id &&
      element.role === expectedElement.role && element.name === expectedElement.name
    );
    if (!selected || expectedElement.role !== 'link') throw new Error('element-contract');
    const navigationTarget = await readLinkNavigationTarget(expectedElement);
    const navigation = await performCorrelatedNavigation(before, navigationTarget);
    emit({
      schema_version: 1,
      ok: true,
      result_code: 'ok',
      state: navigation.state,
      navigation_correlation: navigation.correlation,
    }, 0);
  } else if (request.op === 'scroll_into_view') {
    const before = await readState();
    if (!sameState(before, request.expected_state)) throw new Error('stale-snapshot');
    const expectedElement = request.expected_element;
    const selected = before.elements.find((element) =>
      expectedElement && element.backend_node_id === expectedElement.backend_node_id &&
      element.role === expectedElement.role && element.name === expectedElement.name
    );
    if (!selected) throw new Error('element-contract');

    // Re-resolve and re-check the exact AX node immediately before the effect.
    // This closes the Python -> adapter gap without exposing backend ids publicly.
    const objectId = await verifyElementImmediately(expectedElement);
    let effect;
    try {
      effect = await call('Runtime.callFunctionOn', {
        objectId,
        functionDeclaration: `function () {
          if (!this || !this.isConnected) return false;
          this.scrollIntoView({block: 'center', inline: 'nearest'});
          return true;
        }`,
        returnByValue: true,
        awaitPromise: false,
      });
    } finally {
      try {
        await call('Runtime.releaseObject', {objectId});
      } catch {}
    }
    if (effect.exceptionDetails || !effect.result || effect.result.value !== true) {
      throw new Error('stale-snapshot');
    }
    const state = await readState();
    emit({schema_version: 1, ok: true, result_code: 'ok', state}, 0);
  } else {
    throw new Error('unsupported-op');
  }
} catch (error) {
  const code = ['transport', 'protocol', 'target-discovery', 'element-contract', 'navigation-error', 'navigation-uncorrelated', 'stale-snapshot'].includes(error.message)
    ? error.message : 'protocol';
  emit({schema_version: 1, ok: false, result_code: code, state: null}, 1);
}
"""


class _BrowserSemanticError(RuntimeError):
    def __init__(self, result_code: str) -> None:
        super().__init__(f"browser semantic operation failed: {result_code}")
        self.result_code = result_code


class _BrowserSemanticFreshWorkerRequired(RuntimeError):
    """The worker predates semantic handles and must be restarted."""


def _browser_semantic_node_runner_argv(
    *,
    token: str,
    node_alias: Path,
    script_path: Path,
    request_path: Path,
    timeout_seconds: int,
) -> list[str]:
    """Run the short-lived V8 helper outside the hardened operator process.

    The operator can legitimately run with ``MemoryDenyWriteExecute=yes``. Node/V8
    needs executable memory even for this bounded helper, so only the transient
    helper unit receives ``MemoryDenyWriteExecute=no``. All browser/session, effect,
    readback and audit authority remains in the parent process.
    """
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise ValueError("browser semantic runner token is invalid")
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or timeout_seconds <= 0
    ):
        raise ValueError("browser semantic runner timeout must be positive")
    if not node_alias.is_absolute():
        raise ValueError("browser semantic runner node alias must be absolute")
    unit = f"grabowski-browser-semantic-{token[:20]}.service"
    # Keep the validated public alias as argv[0]. The canonical Heim Node wrapper
    # dispatches on that public name; executing its resolved target directly would
    # change semantics even though the target identity was already validated above.
    child_argv = [
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C.UTF-8",
        str(node_alias),
        str(script_path),
        str(request_path),
    ]
    return [
        "systemd-run",
        "--user",
        "--quiet",
        "--wait",
        "--collect",
        "--pipe",
        "--same-dir",
        f"--description={operator._systemd_safe_description('browser-semantic', unit, operator._argv_hash(child_argv))}",
        "--unit",
        unit,
        "--slice=grabowski-workers.slice",
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=3s",
        WORKER_LIMIT_CORE_PROPERTY,
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=full",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=MemoryDenyWriteExecute=no",
        "--property=UMask=0077",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        f"--property=RuntimeMaxSec={timeout_seconds + 5}s",
        "--property=MemoryMax=512M",
        "--",
        *child_argv,
    ]


def _run_node_browser_semantic(
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
    script_path = directory / f".browser-semantic-{token}.mjs"
    request_path = directory / f".browser-semantic-{token}.json"
    created: list[Path] = []
    try:
        _write_private_action_file(script_path, BROWSER_SEMANTIC_NODE_SOURCE)
        created.append(script_path)
        _write_private_action_file(request_path, _canonical_json(request) + "\n")
        created.append(request_path)
        execution = operator._run(
            _browser_semantic_node_runner_argv(
                token=token,
                node_alias=node_path,
                script_path=script_path,
                request_path=request_path,
                timeout_seconds=timeout_seconds,
            ),
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
        returncode = execution.get("returncode")
        timed_out = str(bool(execution.get("timed_out"))).lower()
        raise RuntimeError(
            "browser semantic action returned no receipt "
            f"(runner_returncode={returncode}, runner_timed_out={timed_out})"
        )
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise RuntimeError("browser semantic action returned an invalid receipt") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError("browser semantic action receipt schema mismatch")
    code = payload.get("result_code")
    if code not in BROWSER_SEMANTIC_RESULT_CODES:
        raise RuntimeError("browser semantic action receipt result code is invalid")
    if not isinstance(payload.get("ok"), bool):
        raise RuntimeError("browser semantic action receipt boolean contract mismatch")
    state = payload.get("state")
    if state is not None and not isinstance(state, dict):
        raise RuntimeError("browser semantic action receipt state contract mismatch")
    navigation_correlation = payload.get("navigation_correlation")
    if navigation_correlation not in {None, "new-document", "same-document"}:
        raise RuntimeError("browser semantic navigation correlation is invalid")
    if request.get("op") in {"navigate", "activate"}:
        if payload["ok"] is True and (
            not isinstance(state, dict) or navigation_correlation is None
        ):
            raise RuntimeError(
                "browser semantic navigation success lacks correlated readback"
            )
        if payload["ok"] is False and (
            state is not None or navigation_correlation is not None
        ):
            raise RuntimeError(
                "browser semantic navigation failure claims correlated readback"
            )
    if payload["ok"] is True and code != "ok":
        raise RuntimeError("browser semantic action success receipt semantic mismatch")
    if payload["ok"] is False and code == "ok":
        raise RuntimeError("browser semantic action failure receipt semantic mismatch")
    if execution["returncode"] == 0 and payload["ok"] is not True:
        raise RuntimeError("browser semantic action success exit disagrees with receipt")
    if execution["returncode"] != 0 and payload["ok"] is not False:
        raise RuntimeError("browser semantic action failure exit disagrees with receipt")
    return payload


def _bounded_semantic_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _bounded_browser_elements(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    bounded: list[dict[str, Any]] = []
    seen_backend_ids: set[str] = set()
    for entry in raw:
        if len(bounded) >= BROWSER_MAX_ELEMENTS:
            break
        if not isinstance(entry, dict):
            continue
        backend_node_id = str(entry.get("backend_node_id") or "")
        if re.fullmatch(r"[1-9][0-9]{0,19}", backend_node_id) is None:
            continue
        if backend_node_id in seen_backend_ids:
            continue
        role = _bounded_semantic_text(entry.get("role"), BROWSER_ELEMENT_ROLE_MAX)
        if not role:
            continue
        navigation_target_sha256 = entry.get("navigation_target_sha256")
        if not isinstance(navigation_target_sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", navigation_target_sha256
        ) is None:
            navigation_target_sha256 = None
        seen_backend_ids.add(backend_node_id)
        bounded.append(
            {
                "backend_node_id": backend_node_id,
                "role": role,
                "name": _bounded_semantic_text(
                    entry.get("name"), BROWSER_ELEMENT_NAME_MAX
                ),
                "navigation_target_sha256": navigation_target_sha256,
            }
        )
    return bounded


def _bounded_browser_state(raw: dict[str, Any]) -> dict[str, Any]:
    """Trim CDP-sourced readback to the private bounded material we hash."""
    return {
        "origin": str(raw.get("origin") or "")[:512],
        "ready_state": str(raw.get("ready_state") or "")[:32],
        "title": str(raw.get("title") or "")[:200],
        "main_frame_id": str(raw.get("main_frame_id") or "")[:128],
        "loader_id": str(raw.get("loader_id") or "")[:128],
        "navigation_entry_id": str(raw.get("navigation_entry_id") or "")[:128],
        "elements": _bounded_browser_elements(raw.get("elements")),
    }


BROWSER_BIDI_STATE_EXPRESSION = r"""JSON.stringify((()=>{
  const semanticRoles=new Set(['button','link','textbox','checkbox','radio','combobox','listbox','option','slider','spinbutton','switch','tab','menuitem','treeitem','heading']);
  const ids=globalThis.__grabowskiSemanticIds||(globalThis.__grabowskiSemanticIds=new WeakMap());
  const counter=globalThis.__grabowskiSemanticCounter||(globalThis.__grabowskiSemanticCounter={value:1});
  const nodeId=(el)=>{let value=ids.get(el);if(!value){value=counter.value++;ids.set(el,value)}return String(value)};
  const clean=(v,n)=>String(v||'').replace(/\s+/g,' ').trim().slice(0,n);
  const visible=(el)=>{const s=getComputedStyle(el);return !el.hidden&&el.getAttribute('aria-hidden')!=='true'&&s.display!=='none'&&s.visibility!=='hidden'};
  const role=(el)=>{const explicit=clean(el.getAttribute('role'),64);if(semanticRoles.has(explicit))return explicit;const t=el.tagName.toLowerCase();if(t==='a'&&el.hasAttribute('href'))return 'link';if(t==='button')return 'button';if(/^h[1-6]$/.test(t))return 'heading';if(t==='textarea')return 'textbox';if(t==='select')return el.multiple?'listbox':'combobox';if(t==='option')return 'option';if(t==='input'){const ty=(el.getAttribute('type')||'text').toLowerCase();if(ty==='checkbox')return 'checkbox';if(ty==='radio')return 'radio';if(ty==='range')return 'slider';if(ty==='number')return 'spinbutton';if(['button','submit','reset'].includes(ty))return 'button';if(!['hidden','file','image','color','date','datetime-local','month','time','week'].includes(ty))return 'textbox'}return ''};
  const name=(el,r)=>clean(el.getAttribute('aria-label')||el.getAttribute('title')||(r==='textbox'?el.getAttribute('placeholder'):'')||el.innerText||el.textContent||el.getAttribute('value'),160);
  const target=(el)=>{if(el.tagName.toLowerCase()!=='a')return null;const raw=el.getAttribute('href');if(typeof raw!=='string'||!raw||raw!==raw.trim()||raw.includes('\\')||raw.length>4096||/[\u0000-\u0020\u007f]/.test(raw))return null;try{const u=new URL(raw,document.baseURI);if(!['http:','https:'].includes(u.protocol)||!u.hostname||u.username||u.password||u.port==='0'||u.href.length>4096)return null;return u.href}catch{return null}};
  const nodes=[...document.querySelectorAll('a[href],button,input,textarea,select,option,[role],h1,h2,h3,h4,h5,h6')];
  const elements=[];for(const el of nodes){if(elements.length>=80||!visible(el))continue;const r=role(el);if(!r)continue;elements.push({backend_node_id:nodeId(el),role:r,name:name(el,r),navigation_target:r==='link'?target(el):null})}
  return {origin:location.origin,ready_state:document.readyState,title:clean(document.title,200),href:location.href,time_origin:String(performance.timeOrigin||''),elements};
})())"""

BROWSER_BIDI_TARGET_EXPRESSION_TEMPLATE = r"""JSON.stringify((()=>{const wanted='__NODE_ID__';const ids=globalThis.__grabowskiSemanticIds||(globalThis.__grabowskiSemanticIds=new WeakMap());const counter=globalThis.__grabowskiSemanticCounter||(globalThis.__grabowskiSemanticCounter={value:1});const nodeId=(el)=>{let value=ids.get(el);if(!value){value=counter.value++;ids.set(el,value)}return String(value)};const nodes=[...document.querySelectorAll('a[href],button,input,textarea,select,option,[role],h1,h2,h3,h4,h5,h6')];const semanticRoles=new Set(['button','link','textbox','checkbox','radio','combobox','listbox','option','slider','spinbutton','switch','tab','menuitem','treeitem','heading']);const visible=(el)=>{const s=getComputedStyle(el);return !el.hidden&&el.getAttribute('aria-hidden')!=='true'&&s.display!=='none'&&s.visibility!=='hidden'};const role=(el)=>{const e=(el.getAttribute('role')||'').trim();if(semanticRoles.has(e))return e;const t=el.tagName.toLowerCase();if(t==='a'&&el.hasAttribute('href'))return 'link';if(t==='button')return 'button';if(/^h[1-6]$/.test(t))return 'heading';if(t==='textarea')return 'textbox';if(t==='select')return el.multiple?'listbox':'combobox';if(t==='option')return 'option';if(t==='input'){const y=(el.getAttribute('type')||'text').toLowerCase();if(y==='checkbox')return 'checkbox';if(y==='radio')return 'radio';if(y==='range')return 'slider';if(y==='number')return 'spinbutton';if(['button','submit','reset'].includes(y))return 'button';if(!['hidden','file','image','color','date','datetime-local','month','time','week'].includes(y))return 'textbox'}return ''};let el=null;for(const item of nodes){if(!visible(item)||!role(item))continue;if(nodeId(item)===wanted){el=item;break}}if(!el||el.tagName.toLowerCase()!=='a')return null;const raw=el.getAttribute('href');if(typeof raw!=='string'||!raw||raw!==raw.trim()||raw.includes('\\')||raw.length>4096||/[\u0000-\u0020\u007f]/.test(raw))return null;try{const u=new URL(raw,document.baseURI);if(!['http:','https:'].includes(u.protocol)||!u.hostname||u.username||u.password||u.port==='0'||u.href.length>4096)return null;return u.href}catch{return null}})())"""

BROWSER_BIDI_SCROLL_EXPRESSION_TEMPLATE = r"""JSON.stringify((()=>{const wanted='__NODE_ID__';const ids=globalThis.__grabowskiSemanticIds||(globalThis.__grabowskiSemanticIds=new WeakMap());const counter=globalThis.__grabowskiSemanticCounter||(globalThis.__grabowskiSemanticCounter={value:1});const nodeId=(el)=>{let value=ids.get(el);if(!value){value=counter.value++;ids.set(el,value)}return String(value)};const clean=(v,n)=>String(v||'').replace(/\s+/g,' ').trim().slice(0,n);const nodes=[...document.querySelectorAll('a[href],button,input,textarea,select,option,[role],h1,h2,h3,h4,h5,h6')];const semanticRoles=new Set(['button','link','textbox','checkbox','radio','combobox','listbox','option','slider','spinbutton','switch','tab','menuitem','treeitem','heading']);const visible=(el)=>{const s=getComputedStyle(el);return !el.hidden&&el.getAttribute('aria-hidden')!=='true'&&s.display!=='none'&&s.visibility!=='hidden'};const role=(el)=>{const e=clean(el.getAttribute('role'),64);if(semanticRoles.has(e))return e;const t=el.tagName.toLowerCase();if(t==='a'&&el.hasAttribute('href'))return 'link';if(t==='button')return 'button';if(/^h[1-6]$/.test(t))return 'heading';if(t==='textarea')return 'textbox';if(t==='select')return el.multiple?'listbox':'combobox';if(t==='option')return 'option';if(t==='input'){const y=(el.getAttribute('type')||'text').toLowerCase();if(y==='checkbox')return 'checkbox';if(y==='radio')return 'radio';if(y==='range')return 'slider';if(y==='number')return 'spinbutton';if(['button','submit','reset'].includes(y))return 'button';if(!['hidden','file','image','color','date','datetime-local','month','time','week'].includes(y))return 'textbox'}return ''};const name=(el,r)=>clean(el.getAttribute('aria-label')||el.getAttribute('title')||(r==='textbox'?el.getAttribute('placeholder'):'')||el.innerText||el.textContent||el.getAttribute('value'),160);let el=null;let r='';for(const item of nodes){if(!visible(item))continue;const candidate=role(item);if(!candidate)continue;if(nodeId(item)===wanted){el=item;r=candidate;break}}if(!el)return null;const n=name(el,r);el.scrollIntoView({block:'center',inline:'center'});return {role:r,name:n}})())"""

_BROWSER_BIDI_ALLOWED_ROLES = frozenset({
    "button", "link", "textbox", "checkbox", "radio", "combobox", "listbox",
    "option", "slider", "spinbutton", "switch", "tab", "menuitem", "treeitem",
    "heading",
})


def _browser_bidi_remote_value(result: dict[str, Any]) -> Any:
    remote = result.get("result")
    if not isinstance(remote, dict):
        raise _BrowserSemanticError("protocol")
    value_type = remote.get("type")
    if value_type in {"string", "boolean"}:
        return remote.get("value")
    if value_type == "null":
        return None
    raise _BrowserSemanticError("protocol")


def _browser_bidi_context(connection: browser_bidi.BidiJsonConnection) -> str:
    try:
        result = connection.call("browsingContext.getTree", {"maxDepth": 0})
    except (browser_bidi.BrowserBidiError, OSError) as exc:
        raise _BrowserSemanticError("transport") from exc
    contexts = result.get("contexts")
    if not isinstance(contexts, list) or len(contexts) != 1 or not isinstance(contexts[0], dict):
        raise _BrowserSemanticError("protocol")
    context = contexts[0].get("context")
    if not isinstance(context, str) or not context:
        raise _BrowserSemanticError("protocol")
    return context


def _browser_bidi_evaluate(connection: browser_bidi.BidiJsonConnection, context: str, expression: str) -> Any:
    try:
        result = connection.call("script.evaluate", {"expression": expression, "target": {"context": context, "sandbox": "grabowski-semantic"}, "awaitPromise": True, "resultOwnership": "none"})
    except (browser_bidi.BrowserBidiError, OSError) as exc:
        raise _BrowserSemanticError("transport") from exc
    return _browser_bidi_remote_value(result)


def _bounded_browser_bidi_state(raw: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _BrowserSemanticError("protocol")
    elements: list[dict[str, Any]] = []
    raw_elements = raw.get("elements") if isinstance(raw.get("elements"), list) else []
    for index, item in enumerate(raw_elements):
        if len(elements) >= BROWSER_MAX_ELEMENTS or not isinstance(item, dict):
            continue
        role = _bounded_semantic_text(item.get("role"), BROWSER_ELEMENT_ROLE_MAX)
        if role not in _BROWSER_BIDI_ALLOWED_ROLES:
            continue
        target_digest = None
        target = item.get("navigation_target")
        if role == "link" and isinstance(target, str):
            try:
                canonical = _validate_browser_navigation_target(target)
            except ValueError:
                canonical = None
            if canonical is not None:
                target_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        backend_node_id = str(item.get("backend_node_id") or "")
        if re.fullmatch(r"[1-9][0-9]{0,19}", backend_node_id) is None:
            continue
        elements.append({"backend_node_id": backend_node_id, "role": role, "name": _bounded_semantic_text(item.get("name"), BROWSER_ELEMENT_NAME_MAX), "navigation_target_sha256": target_digest})
    href = str(raw.get("href") or "")[:4096]
    time_origin = str(raw.get("time_origin") or "")[:128]
    return _bounded_browser_state({
        "origin": str(raw.get("origin") or "")[:512],
        "ready_state": str(raw.get("ready_state") or "")[:32],
        "title": str(raw.get("title") or "")[:200],
        "main_frame_id": context[:128],
        "loader_id": hashlib.sha256(f"{context}:{time_origin}".encode("utf-8")).hexdigest(),
        "navigation_entry_id": hashlib.sha256(href.encode("utf-8")).hexdigest(),
        "elements": elements,
    })


def _browser_bidi_decode_state(connection: browser_bidi.BidiJsonConnection, context: str) -> dict[str, Any]:
    serialized = _browser_bidi_evaluate(connection, context, BROWSER_BIDI_STATE_EXPRESSION)
    if not isinstance(serialized, str):
        raise _BrowserSemanticError("protocol")
    try:
        raw = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise _BrowserSemanticError("protocol") from exc
    return _bounded_browser_bidi_state(raw, context=context)


def _browser_bidi_element_node_id(element: dict[str, Any]) -> str:
    raw = str(element.get("backend_node_id") or "")
    if re.fullmatch(r"[1-9][0-9]{0,19}", raw) is None:
        raise _BrowserSemanticError("element-contract")
    return raw


def _browser_bidi_wait_for_post_state(connection: browser_bidi.BidiJsonConnection, context: str, *, expected_state: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_state: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last_state = _browser_bidi_decode_state(connection, context)
        if last_state["ready_state"] == "complete" and last_state != expected_state:
            return last_state
        time.sleep(0.05)
    if last_state == expected_state:
        raise _BrowserSemanticError("navigation-uncorrelated")
    raise _BrowserSemanticError("transport")


class CDPAdapter:
    """Internal browser-adapter boundary; no CDP vocabulary crosses it."""

    def observe_state(self) -> dict[str, Any]:
        raise NotImplementedError

    def perform_local_ui_effect(
        self,
        intent: dict[str, Any],
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError

    def navigate(
        self,
        navigation_target: str,
        *,
        expected_state: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError

    def activate_link(
        self,
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        raise NotImplementedError


class ChromeCDPAdapter(CDPAdapter):
    """Chrome-family CDP implementation of the private semantic adapter."""

    def __init__(self, record: dict[str, Any], *, timeout_seconds: int) -> None:
        self._record = record
        self._timeout_seconds = timeout_seconds

    def _run(self, request: dict[str, Any]) -> dict[str, Any]:
        return _run_node_browser_semantic(
            self._record,
            {
                "schema_version": 1,
                "port": self._record["port"],
                "timeout_ms": self._timeout_seconds * 1000,
                **request,
            },
            timeout_seconds=self._timeout_seconds,
        )

    def observe_state(self) -> dict[str, Any]:
        payload = self._run({"op": "read_state"})
        if payload["ok"] is not True or not isinstance(payload.get("state"), dict):
            raise _BrowserSemanticError(payload.get("result_code") or "protocol")
        return _bounded_browser_state(payload["state"])

    def perform_local_ui_effect(
        self,
        intent: dict[str, Any],
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        payload = self._run(
            {
                "op": intent["action_kind"],
                "expected_state": expected_state,
                "expected_element": expected_element,
            }
        )
        if payload["ok"] is not True or not isinstance(payload.get("state"), dict):
            raise _BrowserSemanticError(payload.get("result_code") or "protocol")
        return _bounded_browser_state(payload["state"])

    def navigate(
        self,
        navigation_target: str,
        *,
        expected_state: dict[str, Any],
    ) -> dict[str, Any]:
        payload = self._run(
            {
                "op": "navigate",
                "navigation_target": navigation_target,
                "expected_state": expected_state,
            }
        )
        if payload["ok"] is not True or not isinstance(payload.get("state"), dict):
            raise _BrowserSemanticError(payload.get("result_code") or "protocol")
        if payload.get("navigation_correlation") not in {
            "new-document",
            "same-document",
        }:
            raise _BrowserSemanticError("navigation-uncorrelated")
        state = _bounded_browser_state(payload["state"])
        if state == expected_state:
            raise _BrowserSemanticError("navigation-uncorrelated")
        return state

    def activate_link(
        self,
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        payload = self._run(
            {
                "op": "activate",
                "expected_state": expected_state,
                "expected_element": expected_element,
            }
        )
        if payload["ok"] is not True or not isinstance(payload.get("state"), dict):
            raise _BrowserSemanticError(payload.get("result_code") or "protocol")
        if payload.get("navigation_correlation") not in {
            "new-document",
            "same-document",
        }:
            raise _BrowserSemanticError("navigation-uncorrelated")
        state = _bounded_browser_state(payload["state"])
        if state == expected_state:
            raise _BrowserSemanticError("navigation-uncorrelated")
        return state


class ChromeWebDriverBidiAdapter(CDPAdapter):
    """Qualified Chrome/WebDriver-BiDi semantic adapter for pre-effect fallback workers."""

    def __init__(self, record: dict[str, Any], *, timeout_seconds: int) -> None:
        self._record = record
        self._timeout_seconds = timeout_seconds
        self._session = _read_browser_bidi_session(record)

    def _connection(self) -> browser_bidi.BidiJsonConnection:
        return browser_bidi.BidiJsonConnection(
            self._session["websocket_url"], timeout_seconds=self._timeout_seconds
        )

    def observe_state(self) -> dict[str, Any]:
        with self._connection() as connection:
            context = _browser_bidi_context(connection)
            return _browser_bidi_decode_state(connection, context)

    def _revalidate(
        self,
        connection: browser_bidi.BidiJsonConnection,
        context: str,
        expected_state: dict[str, Any],
    ) -> None:
        fresh_state = _browser_bidi_decode_state(connection, context)
        if fresh_state != expected_state:
            raise _BrowserSemanticError("stale-snapshot")

    def _navigate_with_readback(
        self,
        connection: browser_bidi.BidiJsonConnection,
        context: str,
        target: str,
        *,
        expected_state: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            connection.call(
                "browsingContext.navigate",
                {"context": context, "url": target, "wait": "complete"},
            )
        except (browser_bidi.BrowserBidiError, OSError) as exc:
            raise _BrowserSemanticError("transport") from exc
        return _browser_bidi_wait_for_post_state(
            connection,
            context,
            expected_state=expected_state,
            timeout_seconds=self._timeout_seconds,
        )

    def perform_local_ui_effect(
        self,
        intent: dict[str, Any],
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        if intent.get("action_kind") != "scroll_into_view":
            raise _BrowserSemanticError("unsupported-op")
        node_id = _browser_bidi_element_node_id(expected_element)
        with self._connection() as connection:
            context = _browser_bidi_context(connection)
            self._revalidate(connection, context, expected_state)
            expression = BROWSER_BIDI_SCROLL_EXPRESSION_TEMPLATE.replace(
                "__NODE_ID__", node_id
            )
            serialized = _browser_bidi_evaluate(connection, context, expression)
            if not isinstance(serialized, str):
                raise _BrowserSemanticError("element-contract")
            try:
                observed = json.loads(serialized)
            except json.JSONDecodeError as exc:
                raise _BrowserSemanticError("protocol") from exc
            if not isinstance(observed, dict) or (
                _bounded_semantic_text(observed.get("role"), BROWSER_ELEMENT_ROLE_MAX)
                != expected_element.get("role")
                or _bounded_semantic_text(observed.get("name"), BROWSER_ELEMENT_NAME_MAX)
                != expected_element.get("name")
            ):
                raise _BrowserSemanticError("stale-snapshot")
            return _browser_bidi_decode_state(connection, context)

    def navigate(
        self,
        navigation_target: str,
        *,
        expected_state: dict[str, Any],
    ) -> dict[str, Any]:
        target = _validate_browser_navigation_target(navigation_target)
        with self._connection() as connection:
            context = _browser_bidi_context(connection)
            self._revalidate(connection, context, expected_state)
            return self._navigate_with_readback(
                connection, context, target, expected_state=expected_state
            )

    def activate_link(
        self,
        *,
        expected_state: dict[str, Any],
        expected_element: dict[str, Any],
    ) -> dict[str, Any]:
        node_id = _browser_bidi_element_node_id(expected_element)
        expected_digest = expected_element.get("navigation_target_sha256")
        if not isinstance(expected_digest, str) or re.fullmatch(
            r"[0-9a-f]{64}", expected_digest
        ) is None:
            raise _BrowserSemanticError("element-contract")
        with self._connection() as connection:
            context = _browser_bidi_context(connection)
            self._revalidate(connection, context, expected_state)
            expression = BROWSER_BIDI_TARGET_EXPRESSION_TEMPLATE.replace(
                "__NODE_ID__", node_id
            )
            serialized = _browser_bidi_evaluate(connection, context, expression)
            if not isinstance(serialized, str):
                raise _BrowserSemanticError("element-contract")
            try:
                target_value = json.loads(serialized)
            except json.JSONDecodeError as exc:
                raise _BrowserSemanticError("protocol") from exc
            if not isinstance(target_value, str):
                raise _BrowserSemanticError("element-contract")
            try:
                target = _validate_browser_navigation_target(target_value)
            except ValueError as exc:
                raise _BrowserSemanticError("element-contract") from exc
            observed_digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(observed_digest, expected_digest):
                raise _BrowserSemanticError("stale-snapshot")
            return self._navigate_with_readback(
                connection, context, target, expected_state=expected_state
            )


def _browser_semantic_adapter(
    record: dict[str, Any], *, timeout_seconds: int
) -> CDPAdapter:
    adapter = _browser_record_adapter(record)
    adapter_id = adapter.get("adapter_id")
    if adapter_id in _BROWSER_CDP_ADAPTER_IDS:
        return ChromeCDPAdapter(record, timeout_seconds=timeout_seconds)
    if adapter_id == BROWSER_BIDI_ADAPTER_ID:
        return ChromeWebDriverBidiAdapter(record, timeout_seconds=timeout_seconds)
    raise RuntimeError("browser worker has no implemented semantic adapter")


def _browser_semantic_handle_key(record: dict[str, Any]) -> bytes:
    directory = Path(record["config_path"]).parent
    if directory.is_symlink() or WORKER_STATE not in directory.parents:
        raise PermissionError("browser semantic key directory is outside worker state")
    key_path = directory / ".semantic-handle-key"
    if key_path.is_symlink():
        raise PermissionError("browser semantic handle key may not be a symlink")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(key_path, flags)
    except FileNotFoundError as exc:
        raise _BrowserSemanticFreshWorkerRequired(
            "browser worker predates semantic handle keys; start a fresh browser worker"
        ) from exc
    except OSError as exc:
        raise PermissionError(
            "browser semantic handle key could not be opened safely"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size > 128
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise PermissionError("browser semantic handle key metadata is unsafe")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            raw = handle.read(129)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > 128:
        raise PermissionError("browser semantic handle key metadata is unsafe")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("browser semantic handle key is invalid") from exc
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError("browser worker lacks a valid semantic handle key")
    return bytes.fromhex(value)


def _browser_mac(prefix: str, handle_key: bytes, payload: dict[str, Any]) -> str:
    digest = hmac.new(
        handle_key,
        _canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return prefix + digest


def _browser_snapshot_id(
    worker_id: str, state: dict[str, Any], handle_key: bytes
) -> str:
    payload = {
        "worker_id": worker_id,
        "origin": state["origin"],
        "ready_state": state["ready_state"],
        "title": state["title"],
        "main_frame_id": state["main_frame_id"],
        "loader_id": state["loader_id"],
        "navigation_entry_id": state["navigation_entry_id"],
        "elements": state["elements"],
    }
    return _browser_mac(BROWSER_SNAPSHOT_ID_PREFIX, handle_key, payload)


def _is_browser_snapshot_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(BROWSER_SNAPSHOT_ID_PREFIX)
        and re.fullmatch(
            r"[0-9a-f]{64}", value[len(BROWSER_SNAPSHOT_ID_PREFIX):]
        )
        is not None
    )


def _browser_element_id(
    worker_id: str,
    snapshot_id: str,
    element: dict[str, Any],
    handle_key: bytes,
) -> str:
    payload = {
        "worker_id": worker_id,
        "snapshot_id": snapshot_id,
        "backend_node_id": element["backend_node_id"],
        "role": element["role"],
        "name": element["name"],
        "navigation_target_sha256": element.get("navigation_target_sha256"),
    }
    return _browser_mac(BROWSER_ELEMENT_ID_PREFIX, handle_key, payload)


def _browser_navigation_target_digest(
    worker_id: str, navigation_target: str, handle_key: bytes
) -> str:
    return _browser_mac(
        "",
        handle_key,
        {
            "purpose": "browser-navigation-target-v1",
            "worker_id": worker_id,
            "navigation_target": navigation_target,
        },
    )


def _is_browser_element_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(BROWSER_ELEMENT_ID_PREFIX)
        and re.fullmatch(
            r"[0-9a-f]{64}", value[len(BROWSER_ELEMENT_ID_PREFIX):]
        )
        is not None
    )


def _browser_element_for_id(
    worker_id: str,
    snapshot_id: str,
    state: dict[str, Any],
    element_id: str,
    handle_key: bytes,
) -> dict[str, Any] | None:
    for element in state["elements"]:
        candidate = _browser_element_id(
            worker_id, snapshot_id, element, handle_key
        )
        if hmac.compare_digest(candidate, element_id):
            return element
    return None


def _browser_observation(
    worker_id: str, state: dict[str, Any], handle_key: bytes
) -> dict[str, Any]:
    """Public BrowserObservation: semantic and bounded, with opaque handles only."""
    snapshot_id = _browser_snapshot_id(worker_id, state, handle_key)
    return {
        "schema_version": 1,
        "worker_id": worker_id,
        "snapshot_id": snapshot_id,
        "observed_at_unix": _now(),
        "origin": state["origin"],
        "ready_state": state["ready_state"],
        "title": state["title"],
        "elements": [
            {
                "element_id": _browser_element_id(
                    worker_id, snapshot_id, element, handle_key
                ),
                "role": element["role"],
                "name": element["name"],
            }
            for element in state["elements"]
        ],
    }


def _browser_outcome_code_from_node(result_code: str) -> str:
    return _BROWSER_NODE_RESULT_TO_OUTCOME.get(result_code, "protocol")


def _browser_intent(
    action_kind: str,
    *,
    element_id: str | None,
    navigation_target: str | None,
) -> dict[str, Any]:
    """Internal BrowserIntent: abstract action kind, never a CDP method or selector."""
    if not isinstance(action_kind, str):
        raise ValueError("action_kind must be text")
    spec = BROWSER_ACTION_CATALOG.get(action_kind)
    if spec is None:
        raise ValueError("unsupported browser action kind")
    if spec["requires_element"]:
        if element_id is None:
            raise ValueError(f"browser action {action_kind!r} requires an element_id")
        if not _is_browser_element_id(element_id):
            raise ValueError("element_id is not a recognized opaque browser element id")
    elif element_id is not None:
        raise ValueError(f"browser action {action_kind!r} does not accept an element_id")
    if spec.get("requires_navigation_target") is True:
        navigation_target = _validate_browser_navigation_target(navigation_target)
    elif navigation_target is not None:
        raise ValueError(
            f"browser action {action_kind!r} does not accept a navigation_target"
        )
    return {
        "schema_version": 1,
        "action_kind": action_kind,
        "effect_class": spec["effect_class"],
        "element_id": element_id,
        "navigation_target": navigation_target,
    }


def _validate_browser_navigation_target(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("navigate requires a navigation_target")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("navigation_target is too large")
    if value != value.strip() or "\\" in value:
        raise ValueError("navigation_target is not a conservative absolute URL")
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("navigation_target contains whitespace or control characters")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise ValueError("navigation_target must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("navigation_target may not contain user information")
    try:
        port = parsed.port
        parsed.hostname.encode("idna")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("navigation_target authority is invalid") from exc
    if port is not None and port == 0:
        raise ValueError("navigation_target port is invalid")
    return value


def _browser_action(
    worker_id: str,
    snapshot_id: str,
    intent: dict[str, Any],
    handle_key: bytes,
) -> dict[str, Any]:
    """Internal BrowserAction: intent bound to worker + snapshot + opaque element."""
    return {
        "schema_version": 1,
        "worker_id": worker_id,
        "snapshot_id": snapshot_id,
        "action_kind": intent["action_kind"],
        "effect_class": intent["effect_class"],
        "element_id": intent["element_id"],
        "target_hmac_sha256": (
            _browser_navigation_target_digest(
                worker_id, intent["navigation_target"], handle_key
            )
            if intent["navigation_target"] is not None
            else None
        ),
    }


def _browser_outcome(
    action: dict[str, Any],
    *,
    ok: bool,
    result_code: str,
    effect_state: str,
    pre_observation: dict[str, Any] | None,
    post_observation: dict[str, Any] | None,
) -> dict[str, Any]:
    if result_code not in BROWSER_SEMANTIC_OUTCOME_CODES:
        raise ValueError("unsupported browser outcome result code")
    if effect_state not in BROWSER_SEMANTIC_EFFECT_STATES:
        raise ValueError("unsupported browser outcome effect state")
    return {
        "schema_version": 1,
        "ok": ok,
        "result_code": result_code,
        "effect_state": effect_state,
        "worker_id": action["worker_id"],
        "action_kind": action["action_kind"],
        "effect_class": action["effect_class"],
        "requested_snapshot_id": action["snapshot_id"],
        "requested_element_id": action["element_id"],
        "target_hmac_sha256": action["target_hmac_sha256"],
        "pre_action_snapshot_id": pre_observation["snapshot_id"] if pre_observation else None,
        "post_action_snapshot_id": post_observation["snapshot_id"] if post_observation else None,
        "observation": post_observation if post_observation is not None else pre_observation,
        "does_not_establish": [
            "generic_external_submission_safety",
            "credential_handling_safety",
            "reversible_external_or_external_mutation_or_high_impact_effect_semantics",
        ],
    }


def _browser_semantic_preflight(identifier: str) -> dict[str, Any]:
    record = _row(identifier)
    if record["kind"] != "browser":
        raise ValueError("Worker is not a browser worker")
    observation = _observe(record)
    if observation["state"] != "running":
        raise RuntimeError("browser worker is not running")
    if not isinstance(record.get("port"), int):
        raise RuntimeError("browser worker has no CDP port")
    port_lease = resources.inspect_resource(f"port:{record['port']}")
    if port_lease is None or port_lease.get("owner_id") != f"worker:{identifier}":
        raise RuntimeError("browser worker no longer owns its CDP port")
    return record


def _validate_browser_semantic_timeout(timeout_seconds: int) -> int:
    if (
        not isinstance(timeout_seconds, int)
        or isinstance(timeout_seconds, bool)
        or not 5 <= timeout_seconds <= 30
    ):
        raise ValueError("timeout_seconds must be between 5 and 30")
    return timeout_seconds


def browser_semantic_observe(
    worker_id: str, *, timeout_seconds: int = 10
) -> dict[str, Any]:
    """Produce a fresh BrowserObservation with snapshot-bound opaque elements."""
    identifier = _validate_worker_id(worker_id)
    timeout_seconds = _validate_browser_semantic_timeout(timeout_seconds)
    record = _browser_semantic_preflight(identifier)
    handle_key = _browser_semantic_handle_key(record)
    adapter = _browser_semantic_adapter(record, timeout_seconds=timeout_seconds)
    state = adapter.observe_state()
    return _browser_observation(identifier, state, handle_key)


def browser_semantic_act(
    worker_id: str,
    snapshot_id: str,
    action_kind: str,
    *,
    element_id: str | None = None,
    navigation_target: str | None = None,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Execute a state-bound BrowserAction and return an authoritative outcome.

    Every effect is bound to worker_id + snapshot_id. Element-targeted actions
    additionally require an opaque element_id from that exact observation. A
    fresh semantic DOM observation must still match immediately before effect;
    the adapter then revalidates the internal node fingerprint once more.
    Navigation accepts only a validated backend-neutral target and succeeds only
    after adapter-internal correlation to an authoritative post-command observation.
    """
    identifier = _validate_worker_id(worker_id)
    if not _is_browser_snapshot_id(snapshot_id):
        raise ValueError("snapshot_id is not a recognized opaque browser snapshot id")
    timeout_seconds = _validate_browser_semantic_timeout(timeout_seconds)
    intent = _browser_intent(
        action_kind,
        element_id=element_id,
        navigation_target=navigation_target,
    )
    record = _browser_semantic_preflight(identifier)
    handle_key = _browser_semantic_handle_key(record)
    adapter = _browser_semantic_adapter(record, timeout_seconds=timeout_seconds)
    action = _browser_action(identifier, snapshot_id, intent, handle_key)

    try:
        fresh_state = adapter.observe_state()
    except _BrowserSemanticError as exc:
        return _browser_outcome(
            action,
            ok=False,
            result_code=_browser_outcome_code_from_node(exc.result_code),
            effect_state="not_started",
            pre_observation=None,
            post_observation=None,
        )
    pre_observation = _browser_observation(identifier, fresh_state, handle_key)
    if pre_observation["snapshot_id"] != snapshot_id:
        return _browser_outcome(
            action,
            ok=False,
            result_code="stale_snapshot",
            effect_state="not_started",
            pre_observation=pre_observation,
            post_observation=None,
        )

    expected_element: dict[str, Any] | None = None
    if intent["element_id"] is not None:
        expected_element = _browser_element_for_id(
            identifier, snapshot_id, fresh_state, intent["element_id"], handle_key
        )
        if expected_element is None:
            return _browser_outcome(
                action,
                ok=False,
                result_code="element_contract",
                effect_state="not_started",
                pre_observation=pre_observation,
                post_observation=None,
            )
        required_role = BROWSER_ACTION_CATALOG[intent["action_kind"]].get(
            "required_element_role"
        )
        if required_role is not None and expected_element["role"] != required_role:
            return _browser_outcome(
                action,
                ok=False,
                result_code="element_contract",
                effect_state="not_started",
                pre_observation=pre_observation,
                post_observation=None,
            )
        if BROWSER_ACTION_CATALOG[intent["action_kind"]].get(
            "requires_bound_navigation_target"
        ) is True:
            navigation_target_sha256 = expected_element.get(
                "navigation_target_sha256"
            )
            if not isinstance(navigation_target_sha256, str) or re.fullmatch(
                r"[0-9a-f]{64}", navigation_target_sha256
            ) is None:
                return _browser_outcome(
                    action,
                    ok=False,
                    result_code="element_contract",
                    effect_state="not_started",
                    pre_observation=pre_observation,
                    post_observation=None,
                )

    if intent["effect_class"] not in BROWSER_EFFECT_CLASSES_IMPLEMENTED:
        return _browser_outcome(
            action,
            ok=False,
            result_code="effect_not_implemented",
            effect_state="not_started",
            pre_observation=pre_observation,
            post_observation=None,
        )
    if intent["action_kind"] == "read_state":
        post_state = fresh_state
        effect_state = "not_applicable"
    elif intent["action_kind"] in {"navigate", "activate"}:
        try:
            if intent["action_kind"] == "navigate":
                post_state = adapter.navigate(
                    intent["navigation_target"], expected_state=fresh_state
                )
            else:
                if expected_element is None:
                    raise RuntimeError(
                        "link activation lost its snapshot-bound element binding"
                    )
                post_state = adapter.activate_link(
                    expected_state=fresh_state,
                    expected_element=expected_element,
                )
        except _BrowserSemanticError as exc:
            if exc.result_code in {"stale-snapshot", "element-contract"}:
                return _browser_outcome(
                    action,
                    ok=False,
                    result_code=_browser_outcome_code_from_node(exc.result_code),
                    effect_state="not_started",
                    pre_observation=pre_observation,
                    post_observation=None,
                )
            return _browser_outcome(
                action,
                ok=False,
                result_code=(
                    "navigation_failed"
                    if exc.result_code == "navigation-error"
                    else "outcome_unknown"
                ),
                effect_state="unknown",
                pre_observation=pre_observation,
                post_observation=None,
            )
        effect_state = "observed"
    else:
        if expected_element is None:
            raise RuntimeError("element-targeted browser action lost its element binding")
        try:
            post_state = adapter.perform_local_ui_effect(
                intent,
                expected_state=fresh_state,
                expected_element=expected_element,
            )
        except _BrowserSemanticError as exc:
            return _browser_outcome(
                action,
                ok=False,
                result_code=_browser_outcome_code_from_node(exc.result_code),
                effect_state="unknown",
                pre_observation=pre_observation,
                post_observation=None,
            )
        effect_state = "observed"
    return _browser_outcome(
        action,
        ok=True,
        result_code="ok",
        effect_state=effect_state,
        pre_observation=pre_observation,
        post_observation=_browser_observation(identifier, post_state, handle_key),
    )


def _browser_public_observation(
    observation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Return public handles with bounded semantic role/name labels."""
    if observation is None:
        return None
    return {
        "schema_version": 1,
        "worker_id": observation["worker_id"],
        "snapshot_id": observation["snapshot_id"],
        "observed_at_unix": observation["observed_at_unix"],
        "ready_state": observation["ready_state"],
        "elements": [
            {
                "element_id": element["element_id"],
                "role": element["role"],
                "name": element["name"],
            }
            for element in observation["elements"]
        ],
    }


def _browser_effect_contract(effect_class: str) -> dict[str, Any]:
    contract = BROWSER_EFFECT_CONTRACTS[effect_class]
    return {
        "effect_class": effect_class,
        "admission": contract["admission"],
        "requires_operator_mutation": contract["requires_operator_mutation"],
        "ambiguous_outcome": dict(contract["ambiguous_outcome"]),
    }


def _browser_semantic_catalog() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "operations": list(BROWSER_SEMANTIC_GATEWAY_OPERATIONS),
        "intents": {
            action_kind: {
                "effect_class": spec["effect_class"],
                "requires_element": spec["requires_element"],
                "requires_navigation_target": spec.get(
                    "requires_navigation_target", False
                ),
                "requires_bound_navigation_target": spec.get(
                    "requires_bound_navigation_target", False
                ),
                "admission": BROWSER_EFFECT_CONTRACTS[spec["effect_class"]][
                    "admission"
                ],
            }
            for action_kind, spec in sorted(BROWSER_ACTION_CATALOG.items())
        },
        "effect_classes": {
            effect_class: _browser_effect_contract(effect_class)
            for effect_class in BROWSER_EFFECT_CLASSES
        },
    }


def _browser_retry_readback_contract(
    *, effect_state: str, readback_state: str
) -> dict[str, Any]:
    return {
        "retry_authorized": False,
        "retry_authority": "not_granted",
        "effect_state": effect_state,
        "authoritative_readback_state": readback_state,
        "authoritative_readback_required": effect_state == "unknown",
        "readback_grants_retry_authority": False,
        "next_action_after_ambiguous_effect": (
            "perform_authoritative_readback_then_form_a_new_explicit_intent"
            if effect_state == "unknown"
            else "none"
        ),
    }


def _browser_semantic_public_result(
    *,
    semantic_operation: str,
    worker_id: str,
    intent: str,
    effect_class: str,
    ok: bool,
    result_code: str,
    effect_state: str,
    requested_snapshot_id: str | None,
    requested_element_id: str | None,
    pre_action_snapshot_id: str | None,
    post_action_snapshot_id: str | None,
    observation: dict[str, Any] | None,
    target_hmac_sha256: str | None = None,
) -> dict[str, Any]:
    if post_action_snapshot_id is not None:
        readback_state = "authoritative_post_action_observation"
    elif semantic_operation == "observe" and observation is not None:
        readback_state = "authoritative_fresh_observation"
    elif pre_action_snapshot_id is not None:
        readback_state = "pre_action_observation_only"
    else:
        readback_state = "unavailable"
    return {
        "schema_version": 1,
        "operation": semantic_operation,
        "intent": intent,
        "ok": ok,
        "result_code": result_code,
        "worker_id": worker_id,
        "effect_class": effect_class,
        "effect_state": effect_state,
        "requested_snapshot_id": requested_snapshot_id,
        "requested_element_id": requested_element_id,
        "target_hmac_sha256": target_hmac_sha256,
        "pre_action_snapshot_id": pre_action_snapshot_id,
        "post_action_snapshot_id": post_action_snapshot_id,
        "observation": _browser_public_observation(observation),
        "effect_contract": _browser_effect_contract(effect_class),
        "retry_readback": _browser_retry_readback_contract(
            effect_state=effect_state,
            readback_state=readback_state,
        ),
        "does_not_establish": [
            "retry_authority",
            "external_effect_completion_without_target_specific_readback",
            "permission_for_reversible_external_external_mutation_or_high_impact",
        ],
    }


def _browser_semantic_audit_record(
    result: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    observation = result.get("observation")
    observation_snapshot_id = (
        observation.get("snapshot_id") if isinstance(observation, dict) else None
    )
    return {
        "timestamp_unix": _now(),
        "operation": f"browser-semantic-{phase}",
        "semantic_operation": result["operation"],
        "worker_id": result["worker_id"],
        "intent": result["intent"],
        "effect_class": result["effect_class"],
        "ok": result["ok"],
        "result_code": result["result_code"],
        "effect_state": result["effect_state"],
        "requested_snapshot_id": result["requested_snapshot_id"],
        "requested_element_id": result["requested_element_id"],
        "target_hmac_sha256": result["target_hmac_sha256"],
        "pre_action_snapshot_id": result["pre_action_snapshot_id"],
        "post_action_snapshot_id": result["post_action_snapshot_id"],
        "observation_snapshot_id": observation_snapshot_id,
        "retry_authorized": result["retry_readback"]["retry_authorized"],
        "authoritative_readback_state": result["retry_readback"][
            "authoritative_readback_state"
        ],
        "authoritative_readback_required": result["retry_readback"][
            "authoritative_readback_required"
        ],
        "readback_grants_retry_authority": result["retry_readback"][
            "readback_grants_retry_authority"
        ],
    }


def _browser_semantic_append_audit(
    result: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    try:
        digest = base._append_audit_with_digest(
            _browser_semantic_audit_record(result, phase=phase)
        )
    except Exception:
        return {
            "recorded": False,
            "result_code": "audit_unavailable",
            "record_sha256": None,
        }
    return {
        "recorded": True,
        "result_code": "ok",
        "record_sha256": digest,
    }


def _browser_semantic_audit_unavailable_result(
    *,
    worker_id: str,
    action_kind: str,
    effect_class: str,
    snapshot_id: str,
    element_id: str | None,
    target_hmac_sha256: str | None,
    intent_audit: dict[str, Any],
) -> dict[str, Any]:
    result = _browser_semantic_public_result(
        semantic_operation="act",
        worker_id=worker_id,
        intent=action_kind,
        effect_class=effect_class,
        ok=False,
        result_code="audit_unavailable",
        effect_state="not_started",
        requested_snapshot_id=snapshot_id,
        requested_element_id=element_id,
        pre_action_snapshot_id=None,
        post_action_snapshot_id=None,
        observation=None,
        target_hmac_sha256=target_hmac_sha256,
    )
    result["audit"] = {
        "intent": intent_audit,
        "outcome": {
            "recorded": False,
            "result_code": "not_attempted",
            "record_sha256": None,
        },
    }
    return result


def browser_semantic_gateway(
    worker_id: str,
    operation: str,
    *,
    snapshot_id: str | None = None,
    action_kind: str | None = None,
    element_id: str | None = None,
    navigation_target: str | None = None,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Dispatch one bounded semantic operation with content-free audit records."""
    identifier = _validate_worker_id(worker_id)
    if operation not in BROWSER_SEMANTIC_GATEWAY_OPERATIONS:
        raise ValueError("unsupported browser semantic operation")
    timeout_seconds = _validate_browser_semantic_timeout(timeout_seconds)
    operator._require_operator_capability("browser_worker")

    if operation == "observe":
        if any(
            value is not None
            for value in (snapshot_id, action_kind, element_id, navigation_target)
        ):
            raise ValueError(
                "observe does not accept snapshot, action, element or navigation targets"
            )
        try:
            observation = browser_semantic_observe(
                identifier, timeout_seconds=timeout_seconds
            )
        except _BrowserSemanticFreshWorkerRequired:
            result = _browser_semantic_public_result(
                semantic_operation="observe",
                worker_id=identifier,
                intent="observe",
                effect_class="read",
                ok=False,
                result_code="fresh_worker_required",
                effect_state="not_applicable",
                requested_snapshot_id=None,
                requested_element_id=None,
                pre_action_snapshot_id=None,
                post_action_snapshot_id=None,
                observation=None,
            )
        except _BrowserSemanticError as exc:
            result = _browser_semantic_public_result(
                semantic_operation="observe",
                worker_id=identifier,
                intent="observe",
                effect_class="read",
                ok=False,
                result_code=_browser_outcome_code_from_node(exc.result_code),
                effect_state="not_applicable",
                requested_snapshot_id=None,
                requested_element_id=None,
                pre_action_snapshot_id=None,
                post_action_snapshot_id=None,
                observation=None,
            )
        except Exception:
            result = _browser_semantic_public_result(
                semantic_operation="observe",
                worker_id=identifier,
                intent="observe",
                effect_class="read",
                ok=False,
                result_code="protocol",
                effect_state="not_applicable",
                requested_snapshot_id=None,
                requested_element_id=None,
                pre_action_snapshot_id=None,
                post_action_snapshot_id=None,
                observation=None,
            )
        else:
            result = _browser_semantic_public_result(
                semantic_operation="observe",
                worker_id=identifier,
                intent="observe",
                effect_class="read",
                ok=True,
                result_code="ok",
                effect_state="not_applicable",
                requested_snapshot_id=None,
                requested_element_id=None,
                pre_action_snapshot_id=None,
                post_action_snapshot_id=None,
                observation=observation,
            )
            result["semantic_catalog"] = _browser_semantic_catalog()
        result["audit"] = {
            "intent": {
                "recorded": False,
                "result_code": "not_required_for_read",
                "record_sha256": None,
            },
            "outcome": _browser_semantic_append_audit(result, phase="outcome"),
        }
        return result

    if snapshot_id is None or action_kind is None:
        raise ValueError("act requires snapshot_id and action_kind")
    if not _is_browser_snapshot_id(snapshot_id):
        raise ValueError("snapshot_id is not a recognized opaque browser snapshot id")
    intent = _browser_intent(
        action_kind,
        element_id=element_id,
        navigation_target=navigation_target,
    )
    effect_class = intent["effect_class"]
    target_hmac_sha256 = None
    effect_contract = BROWSER_EFFECT_CONTRACTS[effect_class]
    if effect_contract["admission"] == "implemented" and effect_contract[
        "requires_operator_mutation"
    ]:
        operator._require_operator_mutation("browser_worker")
        try:
            target_hmac_sha256 = (
                _browser_navigation_target_digest(
                    identifier,
                    intent["navigation_target"],
                    _browser_semantic_handle_key(_row(identifier)),
                )
                if intent["navigation_target"] is not None
                else None
            )
        except _BrowserSemanticFreshWorkerRequired:
            result = _browser_semantic_public_result(
                semantic_operation="act",
                worker_id=identifier,
                intent=action_kind,
                effect_class=effect_class,
                ok=False,
                result_code="fresh_worker_required",
                effect_state="not_started",
                requested_snapshot_id=snapshot_id,
                requested_element_id=element_id,
                pre_action_snapshot_id=None,
                post_action_snapshot_id=None,
                observation=None,
                target_hmac_sha256=None,
            )
            result["audit"] = {
                "intent": {
                    "recorded": False,
                    "result_code": "not_attempted",
                    "record_sha256": None,
                },
                "outcome": _browser_semantic_append_audit(result, phase="outcome"),
            }
            return result
        intent_result = _browser_semantic_public_result(
            semantic_operation="act",
            worker_id=identifier,
            intent=action_kind,
            effect_class=effect_class,
            ok=False,
            result_code="intent_recorded",
            effect_state="not_started",
            requested_snapshot_id=snapshot_id,
            requested_element_id=element_id,
            pre_action_snapshot_id=None,
            post_action_snapshot_id=None,
            observation=None,
            target_hmac_sha256=target_hmac_sha256,
        )
        intent_audit = _browser_semantic_append_audit(intent_result, phase="intent")
        if intent_audit["recorded"] is not True:
            return _browser_semantic_audit_unavailable_result(
                worker_id=identifier,
                action_kind=action_kind,
                effect_class=effect_class,
                snapshot_id=snapshot_id,
                element_id=element_id,
                target_hmac_sha256=target_hmac_sha256,
                intent_audit=intent_audit,
            )
    else:
        intent_audit = {
            "recorded": False,
            "result_code": "not_required_without_implemented_effect",
            "record_sha256": None,
        }

    try:
        outcome = browser_semantic_act(
            identifier,
            snapshot_id,
            action_kind,
            element_id=element_id,
            navigation_target=navigation_target,
            timeout_seconds=timeout_seconds,
        )
    except _BrowserSemanticFreshWorkerRequired:
        result = _browser_semantic_public_result(
            semantic_operation="act",
            worker_id=identifier,
            intent=action_kind,
            effect_class=effect_class,
            ok=False,
            result_code="fresh_worker_required",
            effect_state="not_started",
            requested_snapshot_id=snapshot_id,
            requested_element_id=element_id,
            pre_action_snapshot_id=None,
            post_action_snapshot_id=None,
            observation=None,
            target_hmac_sha256=target_hmac_sha256,
        )
    except Exception:
        possible_effect = (
            effect_contract["admission"] == "implemented"
            and effect_contract["requires_operator_mutation"] is True
        )
        result = _browser_semantic_public_result(
            semantic_operation="act",
            worker_id=identifier,
            intent=action_kind,
            effect_class=effect_class,
            ok=False,
            result_code="outcome_unknown" if possible_effect else "protocol",
            effect_state="unknown" if possible_effect else "not_started",
            requested_snapshot_id=snapshot_id,
            requested_element_id=element_id,
            pre_action_snapshot_id=None,
            post_action_snapshot_id=None,
            observation=None,
            target_hmac_sha256=target_hmac_sha256,
        )
    else:
        result = _browser_semantic_public_result(
            semantic_operation="act",
            worker_id=identifier,
            intent=action_kind,
            effect_class=effect_class,
            ok=outcome["ok"],
            result_code=outcome["result_code"],
            effect_state=outcome["effect_state"],
            requested_snapshot_id=outcome["requested_snapshot_id"],
            requested_element_id=outcome["requested_element_id"],
            pre_action_snapshot_id=outcome["pre_action_snapshot_id"],
            post_action_snapshot_id=outcome["post_action_snapshot_id"],
            observation=outcome["observation"],
            target_hmac_sha256=outcome["target_hmac_sha256"],
        )
    result["audit"] = {
        "intent": intent_audit,
        "outcome": _browser_semantic_append_audit(result, phase="outcome"),
    }
    return result


# --- End browser semantic contract ------------------------------------------


def _browser_start_cdp_worker(
    *,
    binary: Path,
    adapter: dict[str, Any],
    port: int,
    extra: list[str],
    persistent_profile: str | None,
    runtime: int,
) -> dict[str, Any]:
    worker_id = uuid.uuid4().hex[:20]
    profile, ephemeral = _browser_profile(worker_id, persistent_profile)
    argv = _browser_adapter_launch_argv(
        adapter,
        executable=binary,
        port=port,
        profile=profile,
        args=extra,
    )
    lease_keys = [f"port:{port}", f"browser-profile:{profile}"]
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
        ephemeral_paths=[profile] if ephemeral else [],
        runtime_seconds=runtime,
        writable_paths=[WORKER_STATE, profile],
    )


def _browser_start_bidi_worker(
    *,
    binary: Path,
    driver: Path,
    port: int,
    extra: list[str],
    runtime: int,
    fallback_evidence: dict[str, Any],
) -> dict[str, Any]:
    worker_id = uuid.uuid4().hex[:20]
    profile, ephemeral = _browser_profile(worker_id, None)
    if not ephemeral:
        raise RuntimeError("qualified BiDi fallback unexpectedly received a persistent profile")
    argv = [
        str(driver),
        f"--port={port}",
        "--allowed-ips=127.0.0.1",
        "--verbose",
    ]
    lease_keys = [f"port:{port}", f"browser-profile:{profile}"]
    config = {
        "schema_version": 1,
        "kind": "browser",
        "argv": argv,
        "environment": {"HOME": str(operator.HOME)},
        "xvfb_argv": None,
        "worker_id": worker_id,
    }
    result = _start(
        kind="browser",
        executable=binary,
        argv=argv,
        config=config,
        profile_path=profile,
        port=port,
        display_number=None,
        lease_keys=lease_keys,
        ephemeral_paths=[profile],
        runtime_seconds=runtime,
        writable_paths=[WORKER_STATE, profile],
    )
    if result["worker"]["state"] != "running":
        result["fallback"] = {
            **fallback_evidence,
            "selected_adapter": BROWSER_BIDI_ADAPTER_ID,
            "session_ready": False,
        }
        return result
    try:
        browser_bidi.driver_ready(port, timeout_seconds=min(10.0, float(runtime)))
        session = browser_bidi.create_chrome_session(
            port=port,
            chrome=binary,
            profile=profile,
            args=extra,
            timeout_seconds=min(10.0, float(runtime)),
        )
        record = _row(worker_id)
        directory = Path(record["config_path"]).parent
        _write_private_worker_json(
            directory,
            BROWSER_BIDI_SESSION_NAME,
            {"schema_version": 1, **session},
        )
    except Exception as session_error:
        try:
            stopped = worker_stop(worker_id, expected_kind="browser")
            settled = worker_status(worker_id, expected_kind="browser")
        except Exception as compensation_error:
            raise RuntimeError(
                "BiDi session setup failed and worker compensation could not be verified"
            ) from compensation_error
        if (
            stopped["worker"]["state"] != "stopped"
            or settled["state"] != "stopped"
            or resources.inspect_resource(f"port:{port}") is not None
            or resources.inspect_resource(f"browser-profile:{profile}") is not None
            or profile.exists()
        ):
            raise RuntimeError(
                "BiDi session setup failed and worker compensation remained incomplete"
            ) from session_error
        raise
    result["worker"] = _public(_row(worker_id))
    result["fallback"] = {
        **fallback_evidence,
        "selected_adapter": BROWSER_BIDI_ADAPTER_ID,
        "session_ready": True,
    }
    return result


def browser_start(
    executable: str,
    *,
    port: int,
    args: list[str] | None = None,
    persistent_profile: str | None = None,
    runtime_seconds: int = 3600,
    chromedriver_executable: str | None = None,
) -> dict[str, Any]:
    runtime = operator._job_runtime(runtime_seconds)
    binary = _executable(
        executable,
        environment_name="GRABOWSKI_BROWSER_EXECUTABLES",
        defaults=DEFAULT_BROWSER_EXECUTABLES,
    )
    adapter = _browser_adapter_policy(binary)
    extra = _validate_args(args)
    _browser_adapter_launch_preflight(adapter, port=port, args=extra)

    if chromedriver_executable is None:
        return _browser_start_cdp_worker(
            binary=binary,
            adapter=adapter,
            port=port,
            extra=extra,
            persistent_profile=persistent_profile,
            runtime=runtime,
        )

    if adapter.get("family") != "chrome-stable":
        raise ValueError("qualified BiDi fallback is limited to Chrome Stable")
    if persistent_profile is not None:
        raise ValueError("qualified BiDi fallback requires an ephemeral primary and standby")
    if any(item not in BROWSER_FALLBACK_SAFE_START_ARGS for item in extra):
        raise PermissionError(
            "qualified BiDi fallback requires effect-free Chrome startup arguments"
        )
    driver = _chromedriver_executable(chromedriver_executable)

    primary = _browser_start_cdp_worker(
        binary=binary,
        adapter=adapter,
        port=port,
        extra=extra,
        persistent_profile=None,
        runtime=runtime,
    )
    primary_worker = primary["worker"]
    primary_id = primary_worker["worker_id"]
    primary_ready = False
    if primary_worker["state"] == "running":
        primary_ready = browser_bidi.cdp_endpoint_ready(
            port, timeout_seconds=min(5.0, float(runtime))
        )
    if primary_ready:
        primary["fallback"] = {
            "schema_version": 1,
            "armed": True,
            "selected": False,
            "selected_adapter": "chrome-cdp",
            "decision_reason": "primary_cdp_ready_before_worker_return",
            "effect_started": False,
            "effect_state": "not_started",
        }
        return primary

    if primary_worker["state"] == "running":
        stopped = worker_stop(primary_id, expected_kind="browser")
        primary_state = stopped["worker"]["state"]
        if primary_state != "stopped":
            raise RuntimeError("CDP primary could not be terminalized before fallback")
    else:
        primary_state = worker_status(primary_id, expected_kind="browser")["state"]
        if primary_state not in WORKER_HISTORY_STATES:
            raise RuntimeError("CDP primary startup outcome is not terminal")

    if resources.inspect_resource(f"port:{port}") is not None:
        raise RuntimeError("CDP primary port lease remains active after terminalization")
    if browser_bidi.cdp_endpoint_ready(port, timeout_seconds=0.5):
        raise RuntimeError("CDP primary endpoint remains reachable after terminalization")

    fallback_evidence = {
        "schema_version": 1,
        "armed": True,
        "selected": True,
        "primary_worker_id": primary_id,
        "primary_adapter": "chrome-cdp",
        "primary_state": primary_state,
        "decision_reason": "primary_cdp_unavailable_before_worker_return",
        "effect_started": False,
        "effect_state": "not_started",
        "fallback_authorized": True,
    }
    return _browser_start_bidi_worker(
        binary=binary,
        driver=driver,
        port=port,
        extra=extra,
        runtime=runtime,
        fallback_evidence=fallback_evidence,
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


def _prior_observation_summary(record: dict[str, Any]) -> dict[str, Any] | None:
    raw = record.get("last_observation_json")
    if not raw:
        return None
    previous = json.loads(raw)
    preserved = previous.get("prior_observation")
    if isinstance(preserved, dict):
        previous = preserved
    summary = {
        key: previous[key]
        for key in ("state", "properties", "observed_at_unix")
        if key in previous
    }
    return summary or None


def _browser_private_cleanup_pending(record: dict[str, Any]) -> bool:
    if record.get("kind") != "browser":
        return False
    target = (
        WORKER_STATE
        / "instances"
        / str(record["worker_id"])
        / BROWSER_BIDI_SESSION_NAME
    )
    try:
        os.lstat(target)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _reconcile_stopped_record(
    record: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = (
        json.loads(record["last_observation_json"])
        if record["last_observation_json"]
        else {"state": "stopped"}
    )
    terminalization = observation.get("terminalization")
    if isinstance(terminalization, dict):
        unit_reset = terminalization.get("unit_reset")
        if isinstance(unit_reset, dict) and _terminalization_settled(observation):
            if not _browser_private_cleanup_pending(record):
                return record, observation
            terminalization = dict(terminalization)
            terminalization["private_session_cleanup"] = (
                _cleanup_browser_bidi_session_file(
                    WORKER_STATE / "instances" / str(record["worker_id"])
                )
            )
            observation = {
                **observation,
                "observed_at_unix": _now(),
                "terminalization": terminalization,
            }
            stored = _update(
                record["worker_id"], "stopped", observation=observation
            )
            return stored, observation
        if _terminalization_core_complete(terminalization):
            terminalization = dict(terminalization)
            observation = {**observation, "terminalization": terminalization}
            terminalization["unit_reset"] = _reset_failed_unit(
                record,
                observation,
                probe_current=not isinstance(unit_reset, dict),
            )
            stored = _update(
                record["worker_id"], "stopped", observation=observation
            )
            return stored, observation
    terminalization = {
        "release": _release(record),
        "cleanup": _cleanup(record),
    }
    observation = {
        **observation,
        "state": "stopped",
        "observed_at_unix": _now(),
        "terminalization": terminalization,
    }
    if _terminalization_core_complete(terminalization):
        terminalization["unit_reset"] = _reset_failed_unit(
            record, observation, probe_current=True
        )
    stored = _update(record["worker_id"], "stopped", observation=observation)
    return stored, observation


def worker_status(worker_id: str, *, expected_kind: str | None = None) -> dict[str, Any]:
    record = _row(worker_id)
    if expected_kind is not None and record["kind"] != expected_kind:
        raise ValueError(f"Worker is not a {expected_kind} worker")
    if record["state"] == "stopped":
        stored, _observation = _reconcile_stopped_record(record)
    elif record["state"] in WORKER_HISTORY_STATES and record[
        "last_observation_json"
    ]:
        observation = json.loads(record["last_observation_json"])
        terminalization = observation.get("terminalization")
        if _terminalization_settled(observation):
            if _browser_private_cleanup_pending(record):
                terminalization = dict(terminalization)
                terminalization["private_session_cleanup"] = (
                    _cleanup_browser_bidi_session_file(
                        WORKER_STATE / "instances" / str(record["worker_id"])
                    )
                )
                observation = {
                    **observation,
                    "observed_at_unix": _now(),
                    "terminalization": terminalization,
                }
                stored = _update(
                    worker_id, record["state"], observation=observation
                )
            else:
                stored = record
        elif isinstance(terminalization, dict) and _terminalization_core_complete(
            terminalization
        ):
            terminalization = dict(terminalization)
            observation = {**observation, "terminalization": terminalization}
            terminalization["unit_reset"] = _reset_failed_unit(record, observation)
            stored = _update(
                worker_id, record["state"], observation=observation
            )
        else:
            stored, _observation = _reconcile_record(record)
    else:
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
    prior_observation = _prior_observation_summary(record)
    if prior_observation is not None:
        observation["prior_observation"] = prior_observation
    stored = _update(worker_id, state, observation=observation)
    if result["returncode"] == 0:
        terminalization = {
            "release": _release(stored),
            "cleanup": _cleanup(stored),
        }
        observation["terminalization"] = terminalization
        if _terminalization_core_complete(terminalization):
            terminalization["unit_reset"] = _reset_failed_unit(
                stored, observation
            )
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
    audit = {
        "timestamp_unix": _now(),
        "operation": operation,
        "worker_id": worker["worker_id"],
        "kind": worker["kind"],
        "unit": worker["unit"],
        "state": worker["state"],
        "port": worker.get("port"),
        "display_number": worker.get("display_number"),
    }
    control_plane = worker.get("control_plane")
    if worker["kind"] == "browser" and isinstance(control_plane, dict):
        adapter = control_plane["adapter"]
        browser = control_plane["browser"]
        profile = control_plane["profile"]
        audit["browser_control_plane"] = {
            "schema_version": control_plane["schema_version"],
            "authority": control_plane["authority"]["control_plane"],
            "adapter_id": adapter["id"],
            "protocol": adapter["protocol"],
            "browser_family": browser["family"],
            "selection_role": browser["selection_role"],
            "profile_mode": profile["mode"],
            "profile_identity_sha256": profile["identity_sha256"],
            "loopback_only": control_plane["endpoint"]["loopback_only"],
        }
    base._append_audit(audit)


@mcp.tool(name="grabowski_browser_worker_start", annotations=MUTATING)
def grabowski_browser_worker_start(
    executable: str,
    port: int,
    args: list[str] | None = None,
    persistent_profile: str | None = None,
    runtime_seconds: int = 3600,
    chromedriver_executable: str | None = None,
) -> dict[str, Any]:
    """Start Chrome/CDP, optionally arming one fail-closed startup-only BiDi standby.

    Supplying ``chromedriver_executable`` does not select BiDi directly. Grabowski first
    starts the canonical Chrome/CDP worker and returns it when the CDP endpoint becomes
    ready. Only when CDP startup remains unavailable before any worker is returned does
    Grabowski terminalize that private primary attempt and start a new Chrome/WebDriver-
    BiDi worker on the same leased loopback port. No later worker/backend switch exists.
    """
    operator._require_operator_mutation("browser_worker")
    result = browser_start(
        executable,
        port=port,
        args=args,
        persistent_profile=persistent_profile,
        runtime_seconds=runtime_seconds,
        chromedriver_executable=chromedriver_executable,
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


@mcp.tool(name="grabowski_browser_worker_semantic", annotations=MUTATING)
def grabowski_browser_worker_semantic(
    worker_id: str,
    operation: str,
    snapshot_id: str | None = None,
    action_kind: str | None = None,
    element_id: str | None = None,
    navigation_target: str | None = None,
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Observe or act through semantic snapshot and element handles only.

    ``operation`` is either ``observe`` or ``act``. Element observations expose
    only opaque element ids plus bounded Accessibility roles and names. Navigate
    accepts one conservatively validated ``navigation_target`` but never echoes it
    into the outcome or audit. Origins, titles, selectors, browser backend
    identifiers and protocol method names stay private. Effect class and
    retry/readback authority come from the server-owned semantic catalog.
    """
    operator._require_operator_capability("browser_worker")
    return browser_semantic_gateway(
        worker_id,
        operation,
        snapshot_id=snapshot_id,
        action_kind=action_kind,
        element_id=element_id,
        navigation_target=navigation_target,
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
