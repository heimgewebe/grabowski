#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import http.client
import json
import os
from pathlib import Path
import random
import select
import signal
import stat as statmod
import subprocess
import sys
import tempfile
import time
from typing import Callable, Iterator
from urllib.parse import urlsplit


DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski"
DEFAULT_RUNTIME_ROOT = Path.home() / ".local/share/grabowski-mcp"
DEFAULT_PROFILE = "grabowski"
DEFAULT_MODULE = "grabowski_operator"
DEFAULT_OPERATOR_SERVICE = "grabowski-operator.service"
DEFAULT_TUNNEL_SERVICE = "tunnel-client-grabowski.service"
DEFAULT_MCP_URL = "http://127.0.0.1:18181/_grabowski/mcp-liveness"
DEFAULT_HEALTH_URL = "http://127.0.0.1:18080/healthz"
DEFAULT_READY_URL = "http://127.0.0.1:18080/readyz"
PROTOCOL_VERSION = "2025-06-18"
MCP_HEALTH_TOOL = "grabowski_runtime_health"
MCP_MAX_RESPONSE_BYTES = 65536
MCP_STDIO_SHUTDOWN_TIMEOUT = 2.0
STACK_DUMP_PATH = DEFAULT_STATE_DIR / "operator-stackdump.log"
STACK_DUMP_MAX_BYTES = 1_048_576
DEFAULT_BACKOFF_BASE = 60
DEFAULT_BACKOFF_MAX = 900
BACKOFF_MAX_LEVEL = 32
BACKOFF_JITTER_RATIO = 0.2


class WatchdogError(RuntimeError):
    pass


class LockBusy(WatchdogError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    status: str
    reasons: tuple[str, ...] = ()
    pid: int | None = None
    age_seconds: float | None = None


@dataclass
class WatchdogState:
    consecutive_failures: int = 0
    restart_timestamps: list[int] = field(default_factory=list)
    backoff_level: int = 0
    next_restart_not_before: int = 0
    restart_generation: int = 0


def emit(event: str, **fields: object) -> None:
    print(
        json.dumps(
            {"event": event, "timestamp": int(time.time()), **fields},
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def parse_show(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def service_properties(service: str) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [
                "systemctl",
                "--user",
                "show",
                service,
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchdogError("systemctl-query-failed") from exc
    properties = parse_show(completed.stdout)
    if set(properties) != {"LoadState", "ActiveState", "SubState", "MainPID"}:
        raise WatchdogError("systemctl-query-incomplete")
    return properties


def read_cmdline(proc_root: Path, pid: int) -> list[str]:
    raw = (proc_root / str(pid) / "cmdline").read_bytes()
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0")
        if item
    ]


def process_age_seconds(proc_root: Path, pid: int) -> float:
    stat_text = (proc_root / str(pid) / "stat").read_text(
        encoding="utf-8", errors="replace"
    )
    closing = stat_text.rfind(")")
    if closing < 0:
        raise WatchdogError("proc-stat-malformed")
    fields = stat_text[closing + 2 :].split()
    if len(fields) <= 19:
        raise WatchdogError("proc-stat-incomplete")
    start_ticks = int(fields[19])
    uptime = float((proc_root / "uptime").read_text(encoding="ascii").split()[0])
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return max(0.0, uptime - (start_ticks / ticks))


def tunnel_identity_ok(proc_root: Path, pid: int, profile: str) -> bool:
    try:
        argv = read_cmdline(proc_root, pid)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False
    return (
        len(argv) == 4
        and Path(argv[0]).name == "tunnel-client"
        and argv[1:] == ["run", "--profile", profile]
    )


def operator_identity_ok(
    proc_root: Path,
    pid: int,
    runtime_root: Path,
    module: str,
    host: str,
    port: int,
) -> bool:
    python_path = runtime_root / ".venv/bin/python"
    expected = [
        str(python_path),
        "-m",
        module,
        "--transport",
        "streamable-http",
        "--host",
        host,
        "--port",
        str(port),
    ]
    try:
        argv = read_cmdline(proc_root, pid)
        executable = (proc_root / str(pid) / "exe").resolve(strict=True)
        expected_executable = python_path.resolve(strict=True)
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return False
    return argv == expected and executable == expected_executable


def loopback_http_url(url: str) -> tuple[str, int, str]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise WatchdogError("non-loopback-url")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, parsed.port or 80, path


def get_probe(url: str, expected_body: str, timeout: float) -> bool:
    host, port, path = loopback_http_url(url)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(256).decode("utf-8", errors="replace").strip()
        return response.status == 200 and body == expected_body
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


class McpProbeFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _send_stdio_message(process: subprocess.Popen, message: dict) -> None:
    if process.stdin is None:
        raise McpProbeFailure("mcp-stdio-unavailable")
    payload = (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    try:
        process.stdin.write(payload)
        process.stdin.flush()
    except (BrokenPipeError, OSError) as exc:
        raise McpProbeFailure("mcp-stdio-write-failed") from exc


def _read_stdio_response(
    process: subprocess.Popen,
    buffer: bytearray,
    *,
    expected_id: int,
    deadline: float,
) -> dict:
    if process.stdout is None:
        raise McpProbeFailure("mcp-stdio-unavailable")
    consumed = 0
    while True:
        newline = buffer.find(b"\n")
        if newline >= 0:
            raw_line = bytes(buffer[:newline])
            del buffer[: newline + 1]
            consumed += len(raw_line) + 1
            if consumed > MCP_MAX_RESPONSE_BYTES:
                raise McpProbeFailure("mcp-response-too-large")
            if not raw_line.strip():
                continue
            try:
                message = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise McpProbeFailure("mcp-json-invalid") from exc
            if (
                isinstance(message, dict)
                and message.get("jsonrpc") == "2.0"
                and message.get("id") == expected_id
            ):
                return message
            continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise McpProbeFailure("mcp-stdio-timeout")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise McpProbeFailure("mcp-stdio-timeout")
        try:
            chunk = os.read(process.stdout.fileno(), 4096)
        except OSError as exc:
            raise McpProbeFailure("mcp-stdio-read-failed") from exc
        if not chunk:
            raise McpProbeFailure("mcp-stdio-process-exited")
        buffer.extend(chunk)
        if consumed + len(buffer) > MCP_MAX_RESPONSE_BYTES:
            raise McpProbeFailure("mcp-response-too-large")


def _shutdown_stdio_process(process: subprocess.Popen) -> str | None:
    failure: str | None = None
    if process.stdin is not None and not process.stdin.closed:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        returncode = process.wait(timeout=MCP_STDIO_SHUTDOWN_TIMEOUT)
        if returncode != 0:
            failure = "mcp-stdio-cleanup-failed"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1.0)
        failure = "mcp-stdio-cleanup-failed"
    finally:
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
    return failure


def tool_health_payload(result: dict) -> dict | None:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    content = result.get("content")
    if not isinstance(content, list):
        return None
    for item in content:
        if (
            isinstance(item, dict)
            and item.get("type") == "text"
            and isinstance(item.get("text"), str)
        ):
            try:
                payload = json.loads(item["text"])
            except json.JSONDecodeError:
                return None
            return payload if isinstance(payload, dict) else None
    return None


def _mcp_http_request(
    *,
    host: str,
    port: int,
    path: str,
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "Accept": "application/json",
        "Connection": "close",
    }
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        response_body = response.read(MCP_MAX_RESPONSE_BYTES + 1)
        response_headers = {
            key.lower(): value for key, value in response.getheaders()
        }
        return response.status, response_headers, response_body
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise McpProbeFailure("mcp-http-request-failed") from exc
    finally:
        connection.close()


def mcp_http_probe(url: str, timeout: float) -> str | None:
    # Probe the live event loop and session-creation lock without creating a session.
    if timeout <= 0:
        raise WatchdogError("invalid-mcp-timeout")
    host, port, path = loopback_http_url(url)
    try:
        status, headers, body = _mcp_http_request(
            host=host,
            port=port,
            path=path,
            timeout=timeout,
        )
    except McpProbeFailure as failure:
        return failure.reason
    if status == 503:
        return "mcp-session-creation-lock-busy"
    if status != 200:
        return "mcp-http-liveness-status"
    if len(body) > MCP_MAX_RESPONSE_BYTES:
        return "mcp-http-response-too-large"
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        return "mcp-http-content-type-invalid"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "mcp-http-json-invalid"
    if not isinstance(payload, dict):
        return "mcp-http-liveness-shape-invalid"
    if (
        payload.get("healthy") is not True
        or payload.get("session_creation_lock_available") is not True
    ):
        return "mcp-session-creation-lock-busy"
    return None


def mcp_stdio_probe(
    command: str,
    arguments: list[str],
    timeout: float,
    *,
    cwd: Path | None = None,
) -> str | None:
    """Run one bounded real MCP lifecycle over an isolated stdio subprocess."""
    if timeout <= 0:
        raise WatchdogError("invalid-mcp-timeout")
    process: subprocess.Popen | None = None
    primary_failure: str | None = None
    cleanup_failure: str | None = None
    try:
        child_environment = os.environ.copy()
        child_environment.pop("PYTHONHOME", None)
        child_environment.pop("PYTHONPATH", None)
        child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        child_environment["PYTHONNOUSERSITE"] = "1"
        try:
            process = subprocess.Popen(
                [command, *arguments],
                cwd=str(cwd) if cwd is not None else None,
                env=child_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
            )
        except OSError:
            return "mcp-stdio-start-failed"

        deadline = time.monotonic() + timeout
        buffer = bytearray()
        _send_stdio_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "grabowski-component-watchdog",
                        "version": "1",
                    },
                },
            },
        )
        initialize = _read_stdio_response(
            process, buffer, expected_id=1, deadline=deadline
        )
        if "error" in initialize:
            raise McpProbeFailure("mcp-initialize-invalid")
        result = initialize.get("result")
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("protocolVersion"), str)
            or len(result["protocolVersion"]) > 64
            or not isinstance(result.get("capabilities"), dict)
            or not isinstance(result.get("serverInfo"), dict)
        ):
            raise McpProbeFailure("mcp-initialize-shape-invalid")

        _send_stdio_message(
            process,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        _send_stdio_message(
            process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": MCP_HEALTH_TOOL, "arguments": {}},
            },
        )
        call = _read_stdio_response(process, buffer, expected_id=2, deadline=deadline)
        if "error" in call:
            raise McpProbeFailure("mcp-tool-call-invalid")
        result = call.get("result")
        if not isinstance(result, dict):
            raise McpProbeFailure("mcp-tool-shape-invalid")
        is_error = result.get("isError", False)
        if not isinstance(is_error, bool):
            raise McpProbeFailure("mcp-tool-shape-invalid")
        if is_error:
            raise McpProbeFailure("mcp-tool-error")
        payload = tool_health_payload(result)
        if payload is None or not isinstance(payload.get("healthy"), bool):
            raise McpProbeFailure("mcp-tool-shape-invalid")
        if payload["healthy"] is not True:
            raise McpProbeFailure("mcp-runtime-unhealthy")
    except McpProbeFailure as failure:
        primary_failure = failure.reason
    finally:
        if process is not None:
            cleanup_failure = _shutdown_stdio_process(process)
    return primary_failure or cleanup_failure


def mcp_stdio_probe_from_runtime(
    runtime_root: Path,
    module: str,
    timeout: float,
) -> str | None:
    try:
        root = runtime_root.expanduser().resolve(strict=True)
    except OSError as exc:
        raise WatchdogError("runtime-root-unavailable") from exc
    if not module or any(not part.isidentifier() for part in module.split(".")):
        raise WatchdogError("invalid-mcp-module")
    executable = root / ".venv/bin/python"
    if (
        not executable.is_file()
        or not os.access(executable, os.X_OK)
        or not executable.parent.resolve().is_relative_to(root)
    ):
        raise WatchdogError("runtime-python-unavailable")
    return mcp_stdio_probe(
        str(executable),
        ["-m", module, "--transport", "stdio"],
        timeout,
        cwd=root,
    )


def probe_component(
    *,
    component: str,
    service: str,
    runtime_root: Path,
    module: str,
    profile: str,
    host: str,
    port: int,
    health_url: str,
    ready_url: str,
    startup_grace: float,
    http_timeout: float,
    mcp_url: str = DEFAULT_MCP_URL,
    proc_root: Path = Path("/proc"),
) -> ProbeResult:
    try:
        properties = service_properties(service)
    except WatchdogError as exc:
        return ProbeResult("indeterminate", (str(exc),))
    try:
        pid = int(properties["MainPID"])
    except (KeyError, ValueError):
        return ProbeResult("indeterminate", ("invalid-main-pid",))
    if (
        properties.get("LoadState") != "loaded"
        or properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or pid <= 0
    ):
        return ProbeResult("unhealthy", ("service-inactive",), pid or None)

    try:
        age = process_age_seconds(proc_root, pid)
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, WatchdogError):
        return ProbeResult("indeterminate", ("process-age-unavailable",), pid)

    reasons: list[str] = []
    if component == "operator":
        if not operator_identity_ok(proc_root, pid, runtime_root, module, host, port):
            reasons.append("operator-identity-mismatch")
        try:
            live_failure = mcp_http_probe(mcp_url, http_timeout)
            isolated_failure = mcp_stdio_probe_from_runtime(
                runtime_root, module, http_timeout
            )
        except WatchdogError as exc:
            return ProbeResult("indeterminate", (str(exc),), pid, age)
        failures = tuple(
            failure
            for failure in (live_failure, isolated_failure)
            if failure is not None
        )
        concrete_failures = tuple(
            failure
            for failure in failures
            if failure != "mcp-runtime-unhealthy"
        )
        if concrete_failures:
            reasons.extend(concrete_failures)
        elif "mcp-runtime-unhealthy" in failures:
            if not reasons:
                return ProbeResult(
                    "indeterminate", ("mcp-runtime-unhealthy",), pid, age
                )
            reasons.append("mcp-runtime-unhealthy")
    elif component == "tunnel":
        if not tunnel_identity_ok(proc_root, pid, profile):
            reasons.append("tunnel-identity-mismatch")
        try:
            if not get_probe(health_url, "live", http_timeout):
                reasons.append("health-failed")
            if not get_probe(ready_url, "ready", http_timeout):
                reasons.append("readiness-failed")
        except WatchdogError as exc:
            return ProbeResult("indeterminate", (str(exc),), pid, age)
    else:
        raise WatchdogError("invalid-component")

    if not reasons:
        return ProbeResult("healthy", pid=pid, age_seconds=age)
    if age < startup_grace:
        return ProbeResult("startup-grace", tuple(reasons), pid, age)
    return ProbeResult("unhealthy", tuple(reasons), pid, age)


def ensure_state_dir(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise WatchdogError("state-dir-is-symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not statmod.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise WatchdogError("unsafe-state-dir")
    return path.resolve(strict=True)


def open_owned_regular(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    if not statmod.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        os.close(descriptor)
        raise WatchdogError("unsafe-state-file")
    return descriptor


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    descriptor = open_owned_regular(path)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("watchdog-already-running") from exc
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def deployment_shared_lock(path: Path) -> Iterator[bool]:
    descriptor = open_owned_regular(path)
    acquired = False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            pass
        yield acquired
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def load_state(path: Path) -> WatchdogState:
    if not path.exists():
        return WatchdogState()
    if path.is_symlink():
        raise WatchdogError("state-file-is-symlink")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WatchdogError("invalid-state-file") from exc
    if not isinstance(raw, dict):
        raise WatchdogError("invalid-state-shape")
    failures = raw.get("consecutive_failures")
    timestamps = raw.get("restart_timestamps")
    # Legacy state files predate the backoff fields; default them to zero.
    backoff_level = raw.get("backoff_level", 0)
    next_restart_not_before = raw.get("next_restart_not_before", 0)
    restart_generation = raw.get("restart_generation", 0)
    if (
        type(failures) is not int
        or failures < 0
        or not isinstance(timestamps, list)
        or any(type(item) is not int or item < 0 for item in timestamps)
        or type(backoff_level) is not int
        or backoff_level < 0
        or type(next_restart_not_before) is not int
        or next_restart_not_before < 0
        or type(restart_generation) is not int
        or restart_generation < 0
    ):
        raise WatchdogError("invalid-state-shape")
    return WatchdogState(
        failures,
        list(timestamps),
        backoff_level,
        next_restart_not_before,
        restart_generation,
    )


def save_state(path: Path, state: WatchdogState) -> None:
    payload = (
        json.dumps(
            {
                "consecutive_failures": state.consecutive_failures,
                "restart_timestamps": state.restart_timestamps,
                "backoff_level": state.backoff_level,
                "next_restart_not_before": state.next_restart_not_before,
                "restart_generation": state.restart_generation,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def backoff_delay_seconds(
    level: int,
    *,
    base: int = DEFAULT_BACKOFF_BASE,
    maximum: int = DEFAULT_BACKOFF_MAX,
    jitter: float = 0.0,
) -> int:
    if base < 1 or maximum < base:
        raise WatchdogError("invalid-backoff-policy")
    if (
        isinstance(jitter, bool)
        or not isinstance(jitter, (int, float))
        or not 0.0 <= float(jitter) < 1.0
    ):
        raise WatchdogError("invalid-jitter-value")
    if level < 1:
        return 0
    nominal = base * (2 ** (min(level, BACKOFF_MAX_LEVEL) - 1))
    jittered = int(nominal * (1.0 + BACKOFF_JITTER_RATIO * float(jitter)))
    return min(maximum, jittered)


def reset_after_healthy(
    state: WatchdogState, *, now: int, restart_window: int
) -> WatchdogState:
    return WatchdogState(
        0,
        [item for item in state.restart_timestamps if item > now - restart_window],
        0,
        0,
        state.restart_generation,
    )


def decide(
    state: WatchdogState,
    *,
    now: int,
    failure_threshold: int,
    max_restarts: int,
    restart_window: int,
    backoff_base: int = DEFAULT_BACKOFF_BASE,
    backoff_max: int = DEFAULT_BACKOFF_MAX,
    jitter_source: Callable[[], float] = random.random,
) -> tuple[str, WatchdogState]:
    recent = [item for item in state.restart_timestamps if item > now - restart_window]
    failures = state.consecutive_failures + 1
    carried = WatchdogState(
        failures,
        recent,
        state.backoff_level,
        state.next_restart_not_before,
        state.restart_generation,
    )
    if failures < failure_threshold:
        return "observe", carried
    if len(recent) >= max_restarts:
        return "budget-exhausted", carried
    if now < state.next_restart_not_before:
        return "backoff-wait", carried
    level = min(state.backoff_level + 1, BACKOFF_MAX_LEVEL)
    delay = backoff_delay_seconds(
        level, base=backoff_base, maximum=backoff_max, jitter=jitter_source()
    )
    return "restart", WatchdogState(
        0,
        recent + [now],
        level,
        now + delay,
        state.restart_generation + 1,
    )


def _prepare_stack_dump_target(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not statmod.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return False
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    except OSError:
        return False
    return True


def _cap_stack_dump_target(path: Path, max_bytes: int) -> bool:
    flags = os.O_WRONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not statmod.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                return False
            if metadata.st_size > max_bytes:
                os.ftruncate(descriptor, max_bytes)
        finally:
            os.close(descriptor)
    except OSError:
        return False
    return True


def request_python_stack_dump(
    pid: int,
    path: Path = STACK_DUMP_PATH,
    max_bytes: int = STACK_DUMP_MAX_BYTES,
) -> bool:
    if pid <= 0 or max_bytes <= 0 or not hasattr(signal, "SIGUSR1"):
        return False
    if not _prepare_stack_dump_target(path):
        return False
    try:
        os.kill(pid, signal.SIGUSR1)
    except OSError:
        return False
    time.sleep(0.25)
    return _cap_stack_dump_target(path, max_bytes)


def restart_service(service: str) -> None:
    try:
        subprocess.run(
            ["systemctl", "--user", "restart", service],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WatchdogError("service-restart-failed") from exc


def run_watchdog(args: argparse.Namespace) -> int:
    if args.component not in {"operator", "tunnel"}:
        raise WatchdogError("invalid-component")
    if args.failure_threshold < 1 or args.max_restarts < 1:
        raise WatchdogError("invalid-restart-policy")
    if args.restart_window < 1 or args.startup_grace < 0:
        raise WatchdogError("invalid-time-policy")
    if args.backoff_base < 1 or args.backoff_max < args.backoff_base:
        raise WatchdogError("invalid-backoff-policy")

    state_dir = ensure_state_dir(args.state_dir)
    state_path = state_dir / f"{args.component}-watchdog-state.json"
    lock_path = state_dir / f"{args.component}-watchdog.lock"
    deploy_lock = state_dir / "deploy.lock"

    with exclusive_lock(lock_path):
        with deployment_shared_lock(deploy_lock) as deployment_clear:
            if not deployment_clear:
                emit(
                    "grabowski.component_watchdog.skipped",
                    component=args.component,
                    reason="deployment-in-progress",
                )
                return 0

            probe = probe_component(
                component=args.component,
                service=args.service,
                runtime_root=args.runtime_root,
                module=args.module,
                profile=args.profile,
                host=args.host,
                port=args.port,
                health_url=args.health_url,
                ready_url=args.ready_url,
                startup_grace=args.startup_grace,
                http_timeout=args.http_timeout,
                mcp_url=args.mcp_url,
            )
            state = load_state(state_path)
            common = {
                "component": args.component,
                "service": args.service,
                "status": probe.status,
                "reasons": list(probe.reasons),
                "pid": probe.pid,
            }

            if probe.status == "healthy":
                state = reset_after_healthy(
                    state,
                    now=int(time.time()),
                    restart_window=args.restart_window,
                )
                save_state(state_path, state)
                emit(
                    "grabowski.component_watchdog.healthy",
                    **common,
                    restart_generation=state.restart_generation,
                )
                return 0
            if probe.status == "startup-grace":
                emit("grabowski.component_watchdog.skipped", **common)
                return 0
            if probe.status == "indeterminate":
                emit("grabowski.component_watchdog.indeterminate", **common)
                return 2
            if args.check_only:
                emit("grabowski.component_watchdog.unhealthy", **common)
                return 1

            action, next_state = decide(
                state,
                now=int(time.time()),
                failure_threshold=args.failure_threshold,
                max_restarts=args.max_restarts,
                restart_window=args.restart_window,
                backoff_base=args.backoff_base,
                backoff_max=args.backoff_max,
            )
            save_state(state_path, next_state)
            if action == "observe":
                emit(
                    "grabowski.component_watchdog.failure_observed",
                    **common,
                    consecutive_failures=next_state.consecutive_failures,
                )
                return 1
            if action == "budget-exhausted":
                emit(
                    "grabowski.component_watchdog.restart_budget_exhausted",
                    **common,
                    restarts_in_window=len(next_state.restart_timestamps),
                    restart_generation=next_state.restart_generation,
                )
                return 3
            if action == "backoff-wait":
                emit(
                    "grabowski.component_watchdog.restart_deferred",
                    **common,
                    consecutive_failures=next_state.consecutive_failures,
                    backoff_level=next_state.backoff_level,
                    next_restart_not_before=next_state.next_restart_not_before,
                    restart_generation=next_state.restart_generation,
                )
                return 1

            stack_dump_requested = (
                args.component == "operator"
                and probe.pid is not None
                and request_python_stack_dump(probe.pid)
            )
            emit(
                "grabowski.component_watchdog.restarting",
                **common,
                stack_dump_requested=stack_dump_requested,
                backoff_level=next_state.backoff_level,
                next_restart_not_before=next_state.next_restart_not_before,
                restart_generation=next_state.restart_generation,
            )
            restart_service(args.service)
            if stack_dump_requested:
                emit(
                    "grabowski.component_watchdog.stack_dump_finalized",
                    component=args.component,
                    service=args.service,
                    capped=_cap_stack_dump_target(
                        STACK_DUMP_PATH, STACK_DUMP_MAX_BYTES
                    ),
                    max_bytes=STACK_DUMP_MAX_BYTES,
                )
            deadline = time.monotonic() + args.recovery_timeout
            final_probe = probe
            while time.monotonic() < deadline:
                time.sleep(1)
                final_probe = probe_component(
                    component=args.component,
                    service=args.service,
                    runtime_root=args.runtime_root,
                    module=args.module,
                    profile=args.profile,
                    host=args.host,
                    port=args.port,
                    health_url=args.health_url,
                    ready_url=args.ready_url,
                    startup_grace=0,
                    http_timeout=args.http_timeout,
                    mcp_url=args.mcp_url,
                )
                if final_probe.status == "healthy":
                    recovered_state = reset_after_healthy(
                        next_state,
                        now=int(time.time()),
                        restart_window=args.restart_window,
                    )
                    save_state(state_path, recovered_state)
                    emit(
                        "grabowski.component_watchdog.recovered",
                        component=args.component,
                        service=args.service,
                        pid=final_probe.pid,
                        backoff_level=recovered_state.backoff_level,
                        next_restart_not_before=recovered_state.next_restart_not_before,
                        restart_generation=recovered_state.restart_generation,
                    )
                    return 0

            next_state.consecutive_failures = 1
            save_state(state_path, next_state)
            emit(
                "grabowski.component_watchdog.restart_unhealthy",
                component=args.component,
                service=args.service,
                status=final_probe.status,
                reasons=list(final_probe.reasons),
                backoff_level=next_state.backoff_level,
                next_restart_not_before=next_state.next_restart_not_before,
                restart_generation=next_state.restart_generation,
            )
            return 4


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Grabowski component watchdog")
    result.add_argument("--component", choices=("operator", "tunnel"), required=True)
    result.add_argument("--service")
    result.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    result.add_argument("--module", default=DEFAULT_MODULE)
    result.add_argument("--profile", default=DEFAULT_PROFILE)
    result.add_argument("--host", default="127.0.0.1")
    result.add_argument("--port", type=int, default=18181)
    # Retained as a hidden compatibility argument for older installed units.
    # When omitted, normalize_args binds it to the exact loopback listener.
    result.add_argument("--mcp-url", default=None, help=argparse.SUPPRESS)
    result.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    result.add_argument("--ready-url", default=DEFAULT_READY_URL)
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    result.add_argument("--failure-threshold", type=int, default=3)
    result.add_argument("--max-restarts", type=int, default=3)
    result.add_argument("--restart-window", type=int, default=900)
    result.add_argument("--backoff-base", type=int, default=DEFAULT_BACKOFF_BASE)
    result.add_argument("--backoff-max", type=int, default=DEFAULT_BACKOFF_MAX)
    result.add_argument("--startup-grace", type=float, default=20)
    result.add_argument("--http-timeout", type=float, default=2)
    result.add_argument("--recovery-timeout", type=float, default=20)
    result.add_argument("--check-only", action="store_true")
    return result


def normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    if args.service is None:
        args.service = (
            DEFAULT_OPERATOR_SERVICE
            if args.component == "operator"
            else DEFAULT_TUNNEL_SERVICE
        )
    if args.host != "127.0.0.1" or not 1024 <= args.port <= 65535:
        raise WatchdogError("invalid-operator-listener")
    if args.mcp_url is None:
        args.mcp_url = (
            f"http://{args.host}:{args.port}/_grabowski/mcp-liveness"
        )
    mcp_host, mcp_port, mcp_path = loopback_http_url(args.mcp_url)
    if (
        mcp_host != args.host
        or mcp_port != args.port
        or mcp_path != "/_grabowski/mcp-liveness"
    ):
        raise WatchdogError("mcp-url-listener-mismatch")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        return run_watchdog(normalize_args(parser().parse_args(argv)))
    except LockBusy as exc:
        emit("grabowski.component_watchdog.skipped", reason=str(exc))
        return 0
    except WatchdogError as exc:
        emit("grabowski.component_watchdog.error", reason=str(exc))
        return 2
    except Exception as exc:
        emit(
            "grabowski.component_watchdog.error",
            reason=type(exc).__name__,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
