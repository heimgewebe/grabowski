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
import stat as statmod
import subprocess
import sys
import tempfile
import time
from typing import Iterator
from urllib.parse import urlsplit


DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski"
DEFAULT_RUNTIME_ROOT = Path.home() / ".local/share/grabowski-mcp"
DEFAULT_PROFILE = "grabowski"
DEFAULT_MODULE = "grabowski_operator"
DEFAULT_OPERATOR_SERVICE = "grabowski-operator.service"
DEFAULT_TUNNEL_SERVICE = "tunnel-client-grabowski.service"
DEFAULT_MCP_URL = "http://127.0.0.1:18181/mcp"
DEFAULT_HEALTH_URL = "http://127.0.0.1:18080/healthz"
DEFAULT_READY_URL = "http://127.0.0.1:18080/readyz"
PROTOCOL_VERSION = "2025-06-18"


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


def mcp_probe(url: str, timeout: float) -> bool:
    host, port, path = loopback_http_url(url)
    body = json.dumps(
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
        separators=(",", ":"),
    ).encode("utf-8")
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        payload = response.read(8192).decode("utf-8", errors="replace")
        content_type = response.getheader("content-type", "")
        session_id = response.getheader("mcp-session-id")
        return (
            response.status == 200
            and "text/event-stream" in content_type
            and isinstance(session_id, str)
            and bool(session_id)
            and '"result"' in payload
        )
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def probe_component(
    *,
    component: str,
    service: str,
    runtime_root: Path,
    module: str,
    profile: str,
    host: str,
    port: int,
    mcp_url: str,
    health_url: str,
    ready_url: str,
    startup_grace: float,
    http_timeout: float,
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
            if not mcp_probe(mcp_url, http_timeout):
                reasons.append("mcp-probe-failed")
        except WatchdogError as exc:
            return ProbeResult("indeterminate", (str(exc),), pid, age)
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
    failures = raw.get("consecutive_failures")
    timestamps = raw.get("restart_timestamps")
    if (
        not isinstance(failures, int)
        or failures < 0
        or not isinstance(timestamps, list)
        or any(not isinstance(item, int) or item < 0 for item in timestamps)
    ):
        raise WatchdogError("invalid-state-shape")
    return WatchdogState(failures, list(timestamps))


def save_state(path: Path, state: WatchdogState) -> None:
    payload = (
        json.dumps(
            {
                "consecutive_failures": state.consecutive_failures,
                "restart_timestamps": state.restart_timestamps,
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


def decide(
    state: WatchdogState,
    *,
    now: int,
    failure_threshold: int,
    max_restarts: int,
    restart_window: int,
) -> tuple[str, WatchdogState]:
    recent = [item for item in state.restart_timestamps if item > now - restart_window]
    failures = state.consecutive_failures + 1
    if failures < failure_threshold:
        return "observe", WatchdogState(failures, recent)
    if len(recent) >= max_restarts:
        return "budget-exhausted", WatchdogState(failures, recent)
    recent.append(now)
    return "restart", WatchdogState(0, recent)


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
                mcp_url=args.mcp_url,
                health_url=args.health_url,
                ready_url=args.ready_url,
                startup_grace=args.startup_grace,
                http_timeout=args.http_timeout,
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
                state.consecutive_failures = 0
                state.restart_timestamps = [
                    item
                    for item in state.restart_timestamps
                    if item > int(time.time()) - args.restart_window
                ]
                save_state(state_path, state)
                emit("grabowski.component_watchdog.healthy", **common)
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
                )
                return 3

            restart_service(args.service)
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
                    mcp_url=args.mcp_url,
                    health_url=args.health_url,
                    ready_url=args.ready_url,
                    startup_grace=0,
                    http_timeout=args.http_timeout,
                )
                if final_probe.status == "healthy":
                    emit(
                        "grabowski.component_watchdog.recovered",
                        component=args.component,
                        service=args.service,
                        pid=final_probe.pid,
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
    result.add_argument("--mcp-url", default=DEFAULT_MCP_URL)
    result.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    result.add_argument("--ready-url", default=DEFAULT_READY_URL)
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    result.add_argument("--failure-threshold", type=int, default=3)
    result.add_argument("--max-restarts", type=int, default=3)
    result.add_argument("--restart-window", type=int, default=900)
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
