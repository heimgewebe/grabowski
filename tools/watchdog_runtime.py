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


DEFAULT_SERVICE = "tunnel-client-grabowski.service"
DEFAULT_PROFILE = "grabowski"
DEFAULT_MODULE = "grabowski_operator"
DEFAULT_RUNTIME_ROOT = Path.home() / ".local/share/grabowski-mcp"
DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski"
DEFAULT_HEALTH_URL = "http://127.0.0.1:18080/healthz"
DEFAULT_READY_URL = "http://127.0.0.1:18080/readyz"


class WatchdogError(RuntimeError):
    pass


class LockBusy(WatchdogError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    status: str
    reasons: tuple[str, ...] = ()
    main_pid: int | None = None
    operator_pid: int | None = None
    process_age_seconds: float | None = None


@dataclass
class WatchdogState:
    consecutive_failures: int = 0
    restart_timestamps: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class Decision:
    action: str
    state: WatchdogState


def emit(event: str, **fields: object) -> None:
    payload = {
        "event": event,
        "timestamp": int(time.time()),
        **fields,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), flush=True)


def parse_systemctl_show(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
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
    properties = parse_systemctl_show(completed.stdout)
    if set(properties) != {"ActiveState", "SubState", "MainPID"}:
        raise WatchdogError("systemctl-query-incomplete")
    return properties


def read_cmdline(proc_root: Path, pid: int) -> list[str]:
    raw = (proc_root / str(pid) / "cmdline").read_bytes()
    return [part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part]


def read_ppid(proc_root: Path, pid: int) -> int:
    for line in (proc_root / str(pid) / "status").read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        if line.startswith("PPid:"):
            return int(line.split(":", 1)[1].strip())
    raise WatchdogError("proc-status-missing-ppid")


def descendant_pids(proc_root: Path, root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            ppid = read_ppid(proc_root, pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, WatchdogError):
            continue
        children.setdefault(ppid, []).append(pid)

    descendants: set[int] = set()
    pending = list(children.get(root_pid, []))
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children.get(pid, []))
    return descendants


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
    ticks_per_second = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return max(0.0, uptime - (start_ticks / ticks_per_second))


def main_identity_ok(proc_root: Path, pid: int, profile: str) -> bool:
    try:
        argv = read_cmdline(proc_root, pid)
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return False
    return (
        len(argv) == 4
        and Path(argv[0]).name == "tunnel-client"
        and argv[1:] == ["run", "--profile", profile]
    )


def operator_candidates(
    proc_root: Path,
    main_pid: int,
    runtime_root: Path,
    expected_module: str,
) -> list[int]:
    expected_argv0 = runtime_root / ".venv/bin/python"
    try:
        expected_exe = expected_argv0.resolve(strict=True)
    except OSError:
        return []

    candidates: list[int] = []
    for pid in sorted(descendant_pids(proc_root, main_pid)):
        try:
            argv = read_cmdline(proc_root, pid)
            exe = (proc_root / str(pid) / "exe").resolve(strict=True)
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            continue
        if (
            argv == [str(expected_argv0), "-m", expected_module]
            and exe == expected_exe
        ):
            candidates.append(pid)
    return candidates


def http_probe(url: str, expected_body: str, timeout: float) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise WatchdogError("non-loopback-health-url")
    if parsed.username is not None or parsed.password is not None:
        raise WatchdogError("credentialed-health-url")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(128).decode("utf-8", errors="replace").strip()
        return response.status == 200 and body == expected_body
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def probe_runtime(
    *,
    service: str,
    profile: str,
    expected_module: str,
    runtime_root: Path,
    health_url: str,
    ready_url: str,
    startup_grace: float,
    http_timeout: float,
    proc_root: Path = Path("/proc"),
) -> ProbeResult:
    try:
        properties = service_properties(service)
    except WatchdogError as exc:
        return ProbeResult(status="indeterminate", reasons=(str(exc),))

    try:
        main_pid = int(properties["MainPID"])
    except (KeyError, ValueError):
        return ProbeResult(status="indeterminate", reasons=("invalid-main-pid",))

    if (
        properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or main_pid <= 0
    ):
        return ProbeResult(status="inactive", main_pid=main_pid or None)

    reasons: list[str] = []
    if not main_identity_ok(proc_root, main_pid, profile):
        reasons.append("main-identity-mismatch")

    try:
        age = process_age_seconds(proc_root, main_pid)
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, WatchdogError):
        return ProbeResult(
            status="indeterminate",
            reasons=("main-process-age-unavailable",),
            main_pid=main_pid,
        )

    operators = operator_candidates(
        proc_root,
        main_pid,
        runtime_root,
        expected_module,
    )
    if len(operators) != 1:
        reasons.append(f"operator-count-{len(operators)}")

    try:
        if not http_probe(health_url, "live", http_timeout):
            reasons.append("health-failed")
        if not http_probe(ready_url, "ready", http_timeout):
            reasons.append("readiness-failed")
    except WatchdogError as exc:
        return ProbeResult(
            status="indeterminate",
            reasons=(str(exc),),
            main_pid=main_pid,
            operator_pid=operators[0] if len(operators) == 1 else None,
            process_age_seconds=age,
        )

    if not reasons:
        return ProbeResult(
            status="healthy",
            main_pid=main_pid,
            operator_pid=operators[0],
            process_age_seconds=age,
        )
    if age < startup_grace:
        return ProbeResult(
            status="startup_grace",
            reasons=tuple(reasons),
            main_pid=main_pid,
            operator_pid=operators[0] if len(operators) == 1 else None,
            process_age_seconds=age,
        )
    return ProbeResult(
        status="unhealthy",
        reasons=tuple(reasons),
        main_pid=main_pid,
        operator_pid=operators[0] if len(operators) == 1 else None,
        process_age_seconds=age,
    )


def ensure_state_dir(path: Path) -> Path:
    path = path.expanduser()
    if path.is_symlink():
        raise WatchdogError("state-dir-is-symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if not statmod.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise WatchdogError("unsafe-state-dir")
    os.chmod(path, 0o700)
    return path.resolve(strict=True)


def _open_owned_regular(path: Path, *, create: bool) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC
    if create:
        flags |= os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if not statmod.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        os.close(fd)
        raise WatchdogError("unsafe-lock-file")
    os.fchmod(fd, 0o600)
    return fd


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    fd = _open_owned_regular(path, create=True)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("watchdog-already-running") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


@contextmanager
def deployment_shared_lock(path: Path) -> Iterator[bool]:
    fd = _open_owned_regular(path, create=True)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            acquired = False
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_state(path: Path) -> WatchdogState:
    if not path.exists():
        return WatchdogState()
    if path.is_symlink():
        raise WatchdogError("state-file-is-symlink")
    info = path.stat()
    if not statmod.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise WatchdogError("unsafe-state-file")
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
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def decide_failure(
    state: WatchdogState,
    *,
    now: int,
    failure_threshold: int,
    max_restarts: int,
    restart_window: int,
) -> Decision:
    recent = [item for item in state.restart_timestamps if item > now - restart_window]
    failures = state.consecutive_failures + 1
    if failures < failure_threshold:
        return Decision("observe", WatchdogState(failures, recent))
    if len(recent) >= max_restarts:
        return Decision("budget-exhausted", WatchdogState(failures, recent))
    recent.append(now)
    return Decision("restart", WatchdogState(0, recent))


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
    if args.failure_threshold < 1 or args.max_restarts < 1:
        raise WatchdogError("invalid-restart-policy")
    if args.restart_window < 1 or args.startup_grace < 0:
        raise WatchdogError("invalid-time-policy")

    state_dir = ensure_state_dir(args.state_dir)
    state_path = state_dir / "watchdog-state.json"
    watchdog_lock = state_dir / "watchdog.lock"
    deploy_lock = state_dir / "deploy.lock"

    with exclusive_lock(watchdog_lock):
        with deployment_shared_lock(deploy_lock) as deployment_clear:
            if not deployment_clear:
                emit("grabowski.watchdog.skipped", reason="deployment-in-progress")
                return 0

            state = load_state(state_path)
            probe = probe_runtime(
                service=args.service,
                profile=args.profile,
                expected_module=args.expected_module,
                runtime_root=args.runtime_root,
                health_url=args.health_url,
                ready_url=args.ready_url,
                startup_grace=args.startup_grace,
                http_timeout=args.http_timeout,
            )

            common = {
                "service": args.service,
                "status": probe.status,
                "reasons": list(probe.reasons),
                "main_pid": probe.main_pid,
                "operator_pid": probe.operator_pid,
            }

            if probe.status == "healthy":
                state.consecutive_failures = 0
                state.restart_timestamps = [
                    item
                    for item in state.restart_timestamps
                    if item > int(time.time()) - args.restart_window
                ]
                save_state(state_path, state)
                emit("grabowski.watchdog.healthy", **common)
                return 0

            if probe.status in {"inactive", "startup_grace"}:
                emit("grabowski.watchdog.skipped", **common)
                return 0

            if probe.status == "indeterminate":
                emit("grabowski.watchdog.indeterminate", **common)
                return 2

            if args.check_only:
                emit("grabowski.watchdog.unhealthy", **common)
                return 1

            decision = decide_failure(
                state,
                now=int(time.time()),
                failure_threshold=args.failure_threshold,
                max_restarts=args.max_restarts,
                restart_window=args.restart_window,
            )
            save_state(state_path, decision.state)

            if decision.action == "observe":
                emit(
                    "grabowski.watchdog.failure-observed",
                    **common,
                    consecutive_failures=decision.state.consecutive_failures,
                    threshold=args.failure_threshold,
                )
                return 1

            if decision.action == "budget-exhausted":
                emit(
                    "grabowski.watchdog.restart-budget-exhausted",
                    **common,
                    restarts_in_window=len(decision.state.restart_timestamps),
                    restart_window=args.restart_window,
                )
                return 3

            restart_service(args.service)
            deadline = time.monotonic() + args.recovery_timeout
            final_probe = probe
            while time.monotonic() < deadline:
                time.sleep(1)
                final_probe = probe_runtime(
                    service=args.service,
                    profile=args.profile,
                    expected_module=args.expected_module,
                    runtime_root=args.runtime_root,
                    health_url=args.health_url,
                    ready_url=args.ready_url,
                    startup_grace=0,
                    http_timeout=args.http_timeout,
                )
                if final_probe.status == "healthy":
                    emit(
                        "grabowski.watchdog.recovered",
                        service=args.service,
                        main_pid=final_probe.main_pid,
                        operator_pid=final_probe.operator_pid,
                        restarts_in_window=len(decision.state.restart_timestamps),
                    )
                    return 0

            failed_state = decision.state
            failed_state.consecutive_failures = 1
            save_state(state_path, failed_state)
            emit(
                "grabowski.watchdog.restart-unhealthy",
                service=args.service,
                status=final_probe.status,
                reasons=list(final_probe.reasons),
                restarts_in_window=len(failed_state.restart_timestamps),
            )
            return 4


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Grabowski semantic runtime watchdog")
    result.add_argument("--service", default=DEFAULT_SERVICE)
    result.add_argument("--profile", default=DEFAULT_PROFILE)
    result.add_argument("--expected-module", default=DEFAULT_MODULE)
    result.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    result.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    result.add_argument("--ready-url", default=DEFAULT_READY_URL)
    result.add_argument("--failure-threshold", type=int, default=3)
    result.add_argument("--max-restarts", type=int, default=3)
    result.add_argument("--restart-window", type=int, default=900)
    result.add_argument("--startup-grace", type=float, default=20)
    result.add_argument("--http-timeout", type=float, default=2)
    result.add_argument("--recovery-timeout", type=float, default=20)
    result.add_argument("--check-only", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        return run_watchdog(parser().parse_args(argv))
    except LockBusy as exc:
        emit("grabowski.watchdog.skipped", reason=str(exc))
        return 0
    except WatchdogError as exc:
        emit("grabowski.watchdog.error", reason=str(exc))
        return 2
    except Exception as exc:
        emit("grabowski.watchdog.error", reason=type(exc).__name__)
        return 2


if __name__ == "__main__":
    sys.exit(main())
