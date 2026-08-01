#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
import fcntl
import hashlib
import http.client
import json
import math
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
import uuid

import watchdog_admission_recovery as admission_recovery


DEFAULT_STATE_DIR = Path.home() / ".local/state/grabowski"
DEFAULT_RUNTIME_ROOT = Path.home() / ".local/share/grabowski-mcp"
DEFAULT_PROFILE = "grabowski"
DEFAULT_MODULE = "grabowski_operator"
DEFAULT_OPERATOR_SERVICE = "grabowski-operator.service"
DEFAULT_TUNNEL_SERVICE = "tunnel-client-grabowski.service"
DEFAULT_MCP_URL = "http://127.0.0.1:18181/_grabowski/mcp-liveness"
DEFAULT_HEALTH_URL = "http://127.0.0.1:18080/healthz"
DEFAULT_READY_URL = "http://127.0.0.1:18080/readyz"
DEFAULT_METRICS_URL = "http://127.0.0.1:18080/metrics"
DEFAULT_CONTROL_PLANE_POLL_MAX_AGE = 90.0
TUNNEL_METRICS_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
CONTROL_PLANE_POLL_METRIC = "commands_poll_last_successful_timestamp_seconds"
PROTOCOL_VERSION = "2025-06-18"
MCP_HEALTH_TOOL = "grabowski_runtime_health"
MCP_MAX_RESPONSE_BYTES = 65536
MCP_STDIO_SHUTDOWN_TIMEOUT = 2.0
CONNECTOR_SNAPSHOT_REFRESH_MAX_OUTPUT_BYTES = 64 * 1024
CONNECTOR_SNAPSHOT_REFRESH_TIMEOUT_SECONDS = 20.0
SERVICE_RESTART_REQUEST_TIMEOUT_SECONDS = 5.0
SERVICE_RESTART_ERROR_MAX_CHARS = 512
DEFAULT_RECOVERY_TIMEOUT_SECONDS = 60.0
WATCHDOG_MAX_RECOVERY_TIMEOUT_SECONDS = 120.0
WATCHDOG_MAX_RESTART_DRAIN_TIMEOUT_SECONDS = 60.0
WATCHDOG_SERVICE_ACTION_TIMEOUT_SECONDS = 15.0
# Tunnel stop can wait for an in-flight poll before SIGKILL; keep start tighter.
WATCHDOG_TUNNEL_STOP_TIMEOUT_SECONDS = 30.0
WATCHDOG_MAX_RUN_SECONDS = 900.0
WATCHDOG_RECOVERY_MARGIN_SECONDS = 30.0
STACK_DUMP_DIRECTORY_NAME = "operator-stackdumps-v1"
STACK_DUMP_SLOT_COUNT = 8
STACK_DUMP_MEMFD_NAME = "grabowski-operator-stackdump"
STACK_DUMP_MAX_BYTES = 1_048_576
DEFAULT_BACKOFF_BASE = 60
DEFAULT_BACKOFF_MAX = 900
BACKOFF_MAX_LEVEL = 32
BACKOFF_JITTER_RATIO = 0.2
DEPENDENCY_UNAVAILABLE_EXIT = 5
WATCHDOG_ADMISSION_MARKER_NAME = admission_recovery.ADMISSION_MARKER_NAME
WATCHDOG_ADMISSION_MAX_LIFETIME_SECONDS = (
    admission_recovery.ADMISSION_MAX_LIFETIME_SECONDS
)
WATCHDOG_ADMISSION_DRAIN_TIMEOUT_SECONDS = 30.0
WATCHDOG_RUNTIME_MANIFEST_NAME = admission_recovery.RUNTIME_MANIFEST_NAME
WatchdogError = admission_recovery.WatchdogError


class RecoveryMutationError(WatchdogError):
    def __init__(self, reason: str, *, rollback_recovered: bool) -> None:
        super().__init__(reason)
        self.rollback_recovered = rollback_recovered


class LockBusy(WatchdogError):
    pass


@dataclass(frozen=True)
class ProbeResult:
    status: str
    reasons: tuple[str, ...] = ()
    pid: int | None = None
    age_seconds: float | None = None
    start_ticks: int | None = None
    boot_id: str | None = None


@dataclass(frozen=True)
class TunnelProcessIdentity:
    boot_id: str
    pid: int
    start_ticks: int
    age_seconds: float


@dataclass
class WatchdogState:
    consecutive_failures: int = 0
    restart_timestamps: list[int] = field(default_factory=list)
    backoff_level: int = 0
    next_restart_not_before: int = 0
    restart_generation: int = 0
    readiness_dependency_unavailable_boot_id: str | None = None
    readiness_dependency_unavailable_pid: int | None = None
    readiness_dependency_unavailable_start_ticks: int | None = None
    _readiness_dependency_evidence_loaded_from_disk: bool = field(
        default=False,
        init=False,
        repr=False,
        compare=False,
    )


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


def process_start_ticks(proc_root: Path, pid: int) -> int:
    stat_text = (proc_root / str(pid) / "stat").read_text(
        encoding="utf-8", errors="replace"
    )
    closing = stat_text.rfind(")")
    if closing < 0:
        raise WatchdogError("proc-stat-malformed")
    fields = stat_text[closing + 2 :].split()
    if len(fields) <= 19:
        raise WatchdogError("proc-stat-incomplete")
    try:
        start_ticks = int(fields[19])
    except ValueError as exc:
        raise WatchdogError("proc-stat-invalid-start-time") from exc
    if start_ticks < 0:
        raise WatchdogError("proc-stat-invalid-start-time")
    return start_ticks


def process_age_seconds(
    proc_root: Path,
    pid: int,
    *,
    start_ticks: int | None = None,
) -> float:
    if start_ticks is None:
        start_ticks = process_start_ticks(proc_root, pid)
    uptime = float((proc_root / "uptime").read_text(encoding="ascii").split()[0])
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return max(0.0, uptime - (start_ticks / ticks))


def read_boot_id(proc_root: Path) -> str:
    try:
        raw = (
            proc_root / "sys/kernel/random/boot_id"
        ).read_text(encoding="ascii").strip()
        parsed = str(uuid.UUID(raw))
    except (OSError, UnicodeError, ValueError) as exc:
        raise WatchdogError("boot-id-unavailable") from exc
    if raw.lower() != parsed:
        raise WatchdogError("boot-id-invalid")
    return parsed


def tunnel_identity_ok(proc_root: Path, pid: int, profile: str) -> bool:
    try:
        argv = read_cmdline(proc_root, pid)
    except OSError:
        return False
    return (
        len(argv) == 4
        and Path(argv[0]).name == "tunnel-client"
        and argv[1:] == ["run", "--profile", profile]
    )


def tunnel_service_process_identity(
    service: str,
    profile: str,
    startup_grace: float,
    *,
    proc_root: Path = Path("/proc"),
) -> tuple[TunnelProcessIdentity | None, str | None]:
    """Re-probe one stable, active tunnel process identity fail-closed."""
    try:
        before = service_properties(service)
    except WatchdogError:
        return None, "tunnel-service-identity-unavailable-after-dependency-probe"
    try:
        pid = int(before["MainPID"])
    except (KeyError, ValueError):
        return None, "tunnel-service-identity-unavailable-after-dependency-probe"
    if (
        before.get("LoadState") != "loaded"
        or before.get("ActiveState") != "active"
        or before.get("SubState") != "running"
        or pid <= 0
    ):
        return None, "tunnel-service-disappeared-after-dependency-probe"
    try:
        boot_id = read_boot_id(proc_root)
        start_ticks = process_start_ticks(proc_root, pid)
        age = process_age_seconds(proc_root, pid, start_ticks=start_ticks)
    except (OSError, ValueError, WatchdogError):
        return None, "tunnel-service-identity-unavailable-after-dependency-probe"
    if not tunnel_identity_ok(proc_root, pid, profile):
        return None, "tunnel-service-identity-unavailable-after-dependency-probe"
    try:
        after = service_properties(service)
        final_start_ticks = process_start_ticks(proc_root, pid)
        final_boot_id = read_boot_id(proc_root)
    except (OSError, ValueError, WatchdogError):
        return None, "tunnel-service-identity-unavailable-after-dependency-probe"
    if (
        after.get("LoadState") != "loaded"
        or after.get("ActiveState") != "active"
        or after.get("SubState") != "running"
        or after.get("MainPID") != str(pid)
        or final_start_ticks != start_ticks
        or final_boot_id != boot_id
    ):
        return None, "tunnel-service-changed-after-dependency-probe"
    if age < startup_grace:
        return None, "tunnel-service-startup-grace-after-dependency-probe"
    return TunnelProcessIdentity(boot_id, pid, start_ticks, age), None


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


def get_bounded_text(url: str, timeout: float, max_bytes: int) -> str | None:
    if max_bytes < 1:
        raise WatchdogError("invalid-http-response-limit")
    host, port, path = loopback_http_url(url)
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
        if response.status != 200 or len(body) > max_bytes:
            return None
        return body.decode("utf-8", errors="strict")
    except (OSError, UnicodeDecodeError, http.client.HTTPException):
        return None
    finally:
        connection.close()



def read_watchdog_admission_marker(
    path: Path,
) -> dict[str, object] | None:
    return admission_recovery.read_admission_marker(path)


def engage_watchdog_admission(
    *, state_dir: Path, runtime_root: Path, lifetime_seconds: int
) -> dict[str, object]:
    return admission_recovery.engage_admission(
        state_dir=state_dir,
        runtime_root=runtime_root,
        lifetime_seconds=lifetime_seconds,
    )


def release_watchdog_admission(
    *, state_dir: Path, marker: dict[str, object]
) -> None:
    admission_recovery.release_admission(state_dir=state_dir, marker=marker)


def operator_admission_observation(
    *, host: str, port: int, timeout: float
) -> dict[str, object]:
    return admission_recovery.operator_admission_observation(
        host=host, port=port, timeout=timeout
    )


def wait_for_watchdog_admission_idle(
    marker: dict[str, object],
    *,
    host: str,
    port: int,
    timeout: float,
) -> dict[str, object]:
    return admission_recovery.wait_for_admission_idle(
        marker,
        host=host,
        port=port,
        timeout=timeout,
        observation_fn=operator_admission_observation,
    )


def _watchdog_tunnel_metrics(text: str) -> dict[str, float]:
    return admission_recovery.parse_tunnel_metrics(text)


def wait_for_watchdog_tunnel_idle(
    *, metrics_url: str, timeout: float
) -> dict[str, object]:
    return admission_recovery.wait_for_tunnel_idle(
        metrics_url=metrics_url,
        timeout=timeout,
        text_getter=get_bounded_text,
    )


def service_action(
    service: str,
    action: str,
    *,
    timeout_seconds: float | None = None,
) -> None:
    if action not in {"start", "stop"}:
        raise WatchdogError("invalid-service-action")
    timeout = (
        WATCHDOG_SERVICE_ACTION_TIMEOUT_SECONDS
        if timeout_seconds is None
        else timeout_seconds
    )
    if type(timeout) is not float and type(timeout) is not int:
        raise WatchdogError("invalid-service-action-timeout")
    if float(timeout) <= 0:
        raise WatchdogError("invalid-service-action-timeout")
    try:
        subprocess.run(
            ["systemctl", "--user", action, service],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=float(timeout),
        )
    except subprocess.TimeoutExpired as exc:
        raise WatchdogError(f"service-{action}-timeout") from exc
    except subprocess.CalledProcessError as exc:
        detail = _bounded_restart_stderr(exc.stderr)
        suffix = f": {detail}" if detail else ""
        raise WatchdogError(f"service-{action}-failed{suffix}") from exc
    except OSError as exc:
        raise WatchdogError(f"service-{action}-exec-failed") from exc


def _operator_process_is_live(
    previous: ProbeResult | None,
    *,
    service: str,
    runtime_root: Path,
    module: str,
    host: str,
    port: int,
    mcp_url: str,
    timeout: float,
    proc_root: Path = Path("/proc"),
) -> ProbeResult:
    try:
        properties = service_properties(service)
        pid = int(properties["MainPID"])
        start_ticks = process_start_ticks(proc_root, pid)
        age = process_age_seconds(proc_root, pid, start_ticks=start_ticks)
    except (KeyError, OSError, ValueError, WatchdogError):
        return ProbeResult("indeterminate", ("operator-recovery-identity-unavailable",))
    if (
        properties.get("LoadState") != "loaded"
        or properties.get("ActiveState") != "active"
        or properties.get("SubState") != "running"
        or pid <= 0
        or not operator_identity_ok(proc_root, pid, runtime_root, module, host, port)
    ):
        return ProbeResult("unhealthy", ("operator-recovery-service-unhealthy",), pid, age, start_ticks)
    failure = mcp_http_probe(mcp_url, timeout)
    if failure is not None:
        return ProbeResult("unhealthy", (failure,), pid, age, start_ticks)
    current = ProbeResult("healthy", pid=pid, age_seconds=age, start_ticks=start_ticks)
    if previous is not None and not _is_new_process_instance(previous, current):
        return ProbeResult(
            "indeterminate",
            ("operator-recovery-process-not-replaced",),
            pid,
            age,
            start_ticks,
        )
    return current


def _restore_service_pair_after_failed_recovery(
    args: argparse.Namespace, marker: dict[str, object]
) -> dict[str, object] | None:
    try:
        service_action(args.service, "start")
    except WatchdogError:
        return None
    operator_deadline = time.monotonic() + args.recovery_timeout
    recovered = ProbeResult(
        "indeterminate", ("operator-rollback-recovery-not-started",)
    )
    while time.monotonic() < operator_deadline:
        time.sleep(1)
        recovered = _operator_process_is_live(
            None,
            service=args.service,
            runtime_root=args.runtime_root,
            module=args.module,
            host=args.host,
            port=args.port,
            mcp_url=args.mcp_url,
            timeout=args.http_timeout,
        )
        if recovered.status != "healthy":
            continue
        observed = operator_admission_observation(
            host=args.host, port=args.port, timeout=args.http_timeout
        )
        if (
            observed.get("active") is True
            and observed.get("valid") is True
            and observed.get("admission_gate_installed") is True
            and observed.get("token") == marker.get("token")
            and observed.get("expected_head") == marker.get("expected_head")
            and observed.get("source_identity_sha256")
            == marker.get("source_identity_sha256")
            and observed.get("active_tool_calls") == 0
        ):
            break
    else:
        return None

    try:
        service_action(args.tunnel_service, "start")
    except WatchdogError:
        return None
    tunnel_deadline = time.monotonic() + args.recovery_timeout
    while time.monotonic() < tunnel_deadline:
        time.sleep(1)
        if (
            get_probe(args.health_url, "live", args.http_timeout)
            and get_probe(args.ready_url, "ready", args.http_timeout)
        ):
            release_watchdog_admission(state_dir=args.state_dir, marker=marker)
            return {
                "operator_pid": recovered.pid,
                "operator_start_ticks": recovered.start_ticks,
                "tunnel_restarted": True,
            }
    return None


def _operator_recovered_without_replacement(
    args: argparse.Namespace,
) -> ProbeResult:
    return _operator_process_is_live(
        None,
        service=args.service,
        runtime_root=args.runtime_root,
        module=args.module,
        host=args.host,
        port=args.port,
        mcp_url=args.mcp_url,
        timeout=args.http_timeout,
    )


def safe_operator_restart(
    args: argparse.Namespace,
    previous_probe: ProbeResult,
) -> tuple[str, ProbeResult | None, dict[str, object]]:
    # Ceil so the admission marker never under-covers the recovery envelope.
    lifetime = math.ceil(
        2 * args.restart_drain_timeout
        + 4 * args.recovery_timeout
        + 2 * WATCHDOG_TUNNEL_STOP_TIMEOUT_SECONDS
        + 2 * WATCHDOG_SERVICE_ACTION_TIMEOUT_SECONDS
        + WATCHDOG_RECOVERY_MARGIN_SECONDS
    )
    if lifetime > WATCHDOG_ADMISSION_MAX_LIFETIME_SECONDS:
        raise WatchdogError("watchdog-admission-lifetime-unrepresentable")
    marker = engage_watchdog_admission(
        state_dir=args.state_dir,
        runtime_root=args.runtime_root,
        lifetime_seconds=lifetime,
    )
    mutated = False
    proof: dict[str, object] = {"marker": marker}
    try:
        proof["admission"] = wait_for_watchdog_admission_idle(
            marker,
            host=args.host,
            port=args.port,
            timeout=args.restart_drain_timeout,
        )
        proof["tunnel"] = wait_for_watchdog_tunnel_idle(
            metrics_url=args.metrics_url,
            timeout=args.restart_drain_timeout,
        )
        recovered_without_restart = _operator_recovered_without_replacement(args)
        proof["operator_recheck"] = {
            "status": recovered_without_restart.status,
            "reasons": list(recovered_without_restart.reasons),
            "pid": recovered_without_restart.pid,
            "start_ticks": recovered_without_restart.start_ticks,
        }
        if recovered_without_restart.status == "healthy":
            release_watchdog_admission(state_dir=args.state_dir, marker=marker)
            return "recovered-without-restart", recovered_without_restart, proof

        # The first tunnel proof can become stale while liveness is rechecked.
        # Admission is already closed, so a second stable balance proof directly
        # before mutation establishes that every polled command received a final
        # response and that no queue item remains.
        proof["tunnel_final"] = wait_for_watchdog_tunnel_idle(
            metrics_url=args.metrics_url,
            timeout=args.restart_drain_timeout,
        )
        recovered_without_restart = _operator_recovered_without_replacement(args)
        proof["operator_recheck"] = {
            "status": recovered_without_restart.status,
            "reasons": list(recovered_without_restart.reasons),
            "pid": recovered_without_restart.pid,
            "start_ticks": recovered_without_restart.start_ticks,
        }
        if recovered_without_restart.status == "healthy":
            release_watchdog_admission(state_dir=args.state_dir, marker=marker)
            return "recovered-without-restart", recovered_without_restart, proof
        emit(
            "grabowski.component_watchdog.restart_drained",
            component=args.component,
            service=args.service,
            tunnel_service=args.tunnel_service,
            admission=proof["admission"],
            tunnel=proof["tunnel_final"],
        )
        # A timed-out systemctl stop may already have taken effect. Mark the
        # recovery as mutating before issuing the request so every ambiguous
        # outcome retains admission and enters rollback handling.
        mutated = True
        service_action(
            args.tunnel_service,
            "stop",
            timeout_seconds=WATCHDOG_TUNNEL_STOP_TIMEOUT_SECONDS,
        )
        restart_service(args.service)
        deadline = time.monotonic() + args.recovery_timeout
        recovered = ProbeResult("indeterminate", ("operator-recovery-not-started",))
        while time.monotonic() < deadline:
            time.sleep(1)
            recovered = _operator_process_is_live(
                previous_probe,
                service=args.service,
                runtime_root=args.runtime_root,
                module=args.module,
                host=args.host,
                port=args.port,
                mcp_url=args.mcp_url,
                timeout=args.http_timeout,
            )
            if recovered.status == "healthy":
                observed = operator_admission_observation(
                    host=args.host, port=args.port, timeout=args.http_timeout
                )
                if (
                    observed.get("active") is True
                    and observed.get("valid") is True
                    and observed.get("admission_gate_installed") is True
                    and observed.get("token") == marker.get("token")
                    and observed.get("expected_head")
                    == marker.get("expected_head")
                    and observed.get("source_identity_sha256")
                    == marker.get("source_identity_sha256")
                    and observed.get("active_tool_calls") == 0
                ):
                    break
        else:
            raise WatchdogError("operator-safe-recovery-timeout")

        service_action(args.tunnel_service, "start")
        tunnel_deadline = time.monotonic() + args.recovery_timeout
        while time.monotonic() < tunnel_deadline:
            time.sleep(1)
            if (
                get_probe(args.health_url, "live", args.http_timeout)
                and get_probe(args.ready_url, "ready", args.http_timeout)
            ):
                release_watchdog_admission(state_dir=args.state_dir, marker=marker)
                return "restarted", recovered, proof
        raise WatchdogError("tunnel-safe-recovery-timeout")
    except RecoveryMutationError:
        raise
    except Exception as exc:
        if not mutated:
            try:
                release_watchdog_admission(state_dir=args.state_dir, marker=marker)
            except WatchdogError:
                pass
            raise

        emit(
            "grabowski.component_watchdog.recovery_exception",
            component=args.component,
            service=args.service,
            tunnel_service=args.tunnel_service,
            exception_type=type(exc).__name__,
            reason=str(exc),
            mutated=True,
        )
        rollback = None
        try:
            rollback = _restore_service_pair_after_failed_recovery(args, marker)
        except WatchdogError as rollback_exc:
            emit(
                "grabowski.component_watchdog.rollback_exception",
                component=args.component,
                service=args.service,
                tunnel_service=args.tunnel_service,
                exception_type=type(rollback_exc).__name__,
                reason=str(rollback_exc),
            )
            rollback = None
        if rollback is not None:
            emit(
                "grabowski.component_watchdog.rollback_recovered",
                component=args.component,
                service=args.service,
                tunnel_service=args.tunnel_service,
                rollback=rollback,
            )
            raise RecoveryMutationError(
                str(exc), rollback_recovered=True
            ) from exc

        emit(
            "grabowski.component_watchdog.rollback_fail_closed",
            component=args.component,
            service=args.service,
            tunnel_service=args.tunnel_service,
            marker_expires_at_unix=marker["expires_at_unix"],
            exception_type=type(exc).__name__,
            reason=str(exc),
        )
        raise RecoveryMutationError(
            str(exc), rollback_recovered=False
        ) from exc


def prometheus_metric_samples(text: str, metric_name: str) -> tuple[float, ...]:
    if not metric_name or any(char.isspace() for char in metric_name):
        raise WatchdogError("invalid-prometheus-metric-name")
    values: list[float] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        token = parts[0]
        if token != metric_name and not token.startswith(metric_name + "{"):
            continue
        try:
            value = float(parts[1])
        except ValueError:
            continue
        if math.isfinite(value):
            values.append(value)
    return tuple(values)


def control_plane_poll_probe(
    metrics_url: str,
    timeout: float,
    max_age_seconds: float,
    *,
    now: float | None = None,
) -> str | None:
    if max_age_seconds <= 0:
        raise WatchdogError("invalid-control-plane-poll-max-age")
    text = get_bounded_text(
        metrics_url, timeout, TUNNEL_METRICS_MAX_RESPONSE_BYTES
    )
    if text is None:
        return "control-plane-metrics-unavailable"
    samples = prometheus_metric_samples(text, CONTROL_PLANE_POLL_METRIC)
    if not samples:
        return "control-plane-poll-missing"
    observed = max(samples)
    current = time.time() if now is None else now
    age = current - observed
    if age < -max_age_seconds:
        return "control-plane-poll-timestamp-invalid"
    if age > max_age_seconds:
        return "control-plane-poll-stale"
    return None


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
    metrics_url: str = DEFAULT_METRICS_URL,
    control_plane_poll_max_age: float = DEFAULT_CONTROL_PLANE_POLL_MAX_AGE,
    proc_root: Path = Path("/proc"),
) -> ProbeResult:
    boot_id: str | None = None
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

    if component == "tunnel":
        try:
            boot_id = read_boot_id(proc_root)
        except WatchdogError as exc:
            return ProbeResult("indeterminate", (str(exc),), pid)
    try:
        start_ticks = process_start_ticks(proc_root, pid)
        age = process_age_seconds(proc_root, pid, start_ticks=start_ticks)
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
            return ProbeResult("indeterminate", (str(exc),), pid, age, start_ticks)
        if live_failure is None:
            if not reasons:
                diagnostic = (
                    (f"isolated-probe-{isolated_failure}",)
                    if isolated_failure is not None
                    else ()
                )
                return ProbeResult(
                    "healthy", diagnostic, pid, age, start_ticks
                )
            if isolated_failure is not None:
                reasons.append(f"isolated-probe-{isolated_failure}")
        else:
            # Only the live process probe may make the running operator restartable.
            # The isolated stdio probe validates the deployed artifact, but under host
            # pressure it must not turn a responsive live operator into a restart
            # candidate and destroy in-flight tunnel work.
            reasons.append(live_failure)
    elif component == "tunnel":
        try:
            final_boot_id = read_boot_id(proc_root)
        except WatchdogError as exc:
            return ProbeResult(
                "indeterminate", (str(exc),), pid, age, start_ticks
            )
        if final_boot_id != boot_id:
            return ProbeResult(
                "indeterminate",
                ("boot-id-changed-during-probe",),
                pid,
                age,
                start_ticks,
            )
        if not tunnel_identity_ok(proc_root, pid, profile):
            reasons.append("tunnel-identity-mismatch")
        try:
            live_ok = get_probe(health_url, "live", http_timeout)
            ready_ok = get_probe(ready_url, "ready", http_timeout)
            poll_failure = control_plane_poll_probe(
                metrics_url, http_timeout, control_plane_poll_max_age
            )
            if not live_ok:
                reasons.append("health-failed")
            if poll_failure in {
                "control-plane-metrics-unavailable",
                "control-plane-poll-missing",
                "control-plane-poll-timestamp-invalid",
            } and not reasons:
                indeterminate_reasons = []
                if not ready_ok:
                    indeterminate_reasons.append("readiness-failed")
                indeterminate_reasons.append(poll_failure)
                return ProbeResult(
                    "indeterminate",
                    tuple(indeterminate_reasons),
                    pid,
                    age,
                    start_ticks,
                    boot_id,
                )
            if poll_failure is not None:
                reasons.append(poll_failure)
            if not ready_ok:
                # Readiness may legitimately drop while the dispatcher applies
                # backpressure. A live process with a fresh control-plane poll is
                # degraded but not restartable: restarting it destroys in-flight
                # work and can create a self-amplifying restart loop.
                if not reasons:
                    return ProbeResult(
                        "indeterminate",
                        ("readiness-failed",),
                        pid,
                        age,
                        start_ticks,
                        boot_id,
                    )
                reasons.append("readiness-failed")
        except WatchdogError as exc:
            return ProbeResult("indeterminate", (str(exc),), pid, age, start_ticks)
    else:
        raise WatchdogError("invalid-component")

    if not reasons:
        return ProbeResult(
            "healthy",
            pid=pid,
            age_seconds=age,
            start_ticks=start_ticks,
            boot_id=boot_id,
        )
    if age < startup_grace:
        return ProbeResult(
            "startup-grace", tuple(reasons), pid, age, start_ticks, boot_id
        )
    return ProbeResult(
        "unhealthy", tuple(reasons), pid, age, start_ticks, boot_id
    )


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
    allowed_fields = {
        "consecutive_failures",
        "restart_timestamps",
        "backoff_level",
        "next_restart_not_before",
        "restart_generation",
        "readiness_dependency_unavailable_boot_id",
        "readiness_dependency_unavailable_pid",
        "readiness_dependency_unavailable_start_ticks",
    }
    if not set(raw).issubset(allowed_fields):
        raise WatchdogError("invalid-state-shape")
    failures = raw.get("consecutive_failures")
    timestamps = raw.get("restart_timestamps")
    # Legacy state files predate the backoff fields; default them to zero.
    backoff_level = raw.get("backoff_level", 0)
    next_restart_not_before = raw.get("next_restart_not_before", 0)
    restart_generation = raw.get("restart_generation", 0)
    dependency_boot_id = raw.get("readiness_dependency_unavailable_boot_id")
    dependency_pid = raw.get("readiness_dependency_unavailable_pid")
    dependency_start_ticks = raw.get(
        "readiness_dependency_unavailable_start_ticks"
    )
    dependency_boot_id_valid = False
    if isinstance(dependency_boot_id, str):
        try:
            dependency_boot_id_valid = (
                str(uuid.UUID(dependency_boot_id)) == dependency_boot_id
            )
        except ValueError:
            pass
    legacy_dependency_identity = (
        dependency_boot_id is None
        and type(dependency_pid) is int
        and dependency_pid > 0
        and type(dependency_start_ticks) is int
        and dependency_start_ticks >= 0
    )
    dependency_identity_valid = (
        dependency_boot_id is None
        and dependency_pid is None
        and dependency_start_ticks is None
    ) or (
        dependency_boot_id_valid
        and type(dependency_pid) is int
        and dependency_pid > 0
        and type(dependency_start_ticks) is int
        and dependency_start_ticks >= 0
    ) or legacy_dependency_identity
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
        or not dependency_identity_valid
    ):
        raise WatchdogError("invalid-state-shape")
    if legacy_dependency_identity:
        dependency_pid = None
        dependency_start_ticks = None
    state = WatchdogState(
        consecutive_failures=failures,
        restart_timestamps=list(timestamps),
        backoff_level=backoff_level,
        next_restart_not_before=next_restart_not_before,
        restart_generation=restart_generation,
        readiness_dependency_unavailable_boot_id=dependency_boot_id,
        readiness_dependency_unavailable_pid=dependency_pid,
        readiness_dependency_unavailable_start_ticks=dependency_start_ticks,
    )
    state._readiness_dependency_evidence_loaded_from_disk = (
        dependency_boot_id is not None
    )
    return state


def save_state(path: Path, state: WatchdogState) -> None:
    payload = (
        json.dumps(
            {
                "consecutive_failures": state.consecutive_failures,
                "restart_timestamps": state.restart_timestamps,
                "backoff_level": state.backoff_level,
                "next_restart_not_before": state.next_restart_not_before,
                "restart_generation": state.restart_generation,
                "readiness_dependency_unavailable_boot_id": (
                    state.readiness_dependency_unavailable_boot_id
                ),
                "readiness_dependency_unavailable_pid": (
                    state.readiness_dependency_unavailable_pid
                ),
                "readiness_dependency_unavailable_start_ticks": (
                    state.readiness_dependency_unavailable_start_ticks
                ),
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
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
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
        consecutive_failures=0,
        restart_timestamps=[
            item for item in state.restart_timestamps
            if item > now - restart_window
        ],
        backoff_level=0,
        next_restart_not_before=0,
        restart_generation=state.restart_generation,
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
        consecutive_failures=failures,
        restart_timestamps=recent,
        backoff_level=state.backoff_level,
        next_restart_not_before=state.next_restart_not_before,
        restart_generation=state.restart_generation,
        readiness_dependency_unavailable_boot_id=(
            state.readiness_dependency_unavailable_boot_id
        ),
        readiness_dependency_unavailable_pid=(
            state.readiness_dependency_unavailable_pid
        ),
        readiness_dependency_unavailable_start_ticks=(
            state.readiness_dependency_unavailable_start_ticks
        ),
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
        consecutive_failures=0,
        restart_timestamps=recent + [now],
        backoff_level=level,
        next_restart_not_before=now + delay,
        restart_generation=state.restart_generation + 1,
        readiness_dependency_unavailable_boot_id=(
            state.readiness_dependency_unavailable_boot_id
        ),
        readiness_dependency_unavailable_pid=(
            state.readiness_dependency_unavailable_pid
        ),
        readiness_dependency_unavailable_start_ticks=(
            state.readiness_dependency_unavailable_start_ticks
        ),
    )


def _process_start_ticks(
    pid: int,
    proc_root: Path = Path("/proc"),
) -> int | None:
    if pid <= 0:
        return None
    try:
        return process_start_ticks(proc_root, pid)
    except (OSError, ValueError, WatchdogError):
        return None


def _stack_dump_pidfd(pid: int) -> int | None:
    if (
        pid <= 0
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal")
    ):
        return None
    try:
        return os.pidfd_open(pid, 0)
    except (OSError, ValueError):
        return None


def _stack_dump_memfd(
    pid: int,
    proc_root: Path = Path("/proc"),
) -> int | None:
    if pid <= 0:
        return None
    directory = proc_root / str(pid) / "fd"
    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        return None
    expected = f"memfd:{STACK_DUMP_MEMFD_NAME}"
    matches: list[int] = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            target = os.readlink(entry).lstrip("/")
        except OSError:
            continue
        if target in {expected, f"{expected} (deleted)"}:
            matches.append(int(entry.name))
    return matches[0] if len(matches) == 1 else None


def _stack_dump_memfd_is_bounded(
    pid: int,
    descriptor: int,
    max_bytes: int,
    proc_root: Path = Path("/proc"),
) -> bool:
    if pid <= 0 or descriptor < 0 or max_bytes <= 0:
        return False
    seal_names = ("F_GET_SEALS", "F_SEAL_GROW", "F_SEAL_SHRINK")
    if any(not hasattr(fcntl, name) for name in seal_names):
        return False
    path = proc_root / str(pid) / "fd" / str(descriptor)
    expected = f"memfd:{STACK_DUMP_MEMFD_NAME}"
    try:
        target = os.readlink(path).lstrip("/")
    except OSError:
        return False
    if target not in {expected, f"{expected} (deleted)"}:
        return False
    flags = os.O_RDONLY | os.O_CLOEXEC
    source = -1
    try:
        source = os.open(path, flags)
        metadata = os.fstat(source)
        required_seals = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
        seals = fcntl.fcntl(source, fcntl.F_GET_SEALS)
        return (
            statmod.S_ISREG(metadata.st_mode)
            and metadata.st_size == max_bytes
            and seals & required_seals == required_seals
        )
    except OSError:
        return False
    finally:
        if source >= 0:
            os.close(source)


def _stack_dump_memfd_position(
    pid: int,
    descriptor: int,
    max_bytes: int,
    proc_root: Path = Path("/proc"),
) -> int | None:
    if pid <= 0 or descriptor < 0 or max_bytes <= 0:
        return None
    path = proc_root / str(pid) / "fdinfo" / str(descriptor)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if len(text.encode("utf-8")) > 4096:
        return None
    for line in text.splitlines():
        if not line.startswith("pos:"):
            continue
        try:
            position = int(line.split(":", 1)[1].strip(), 10)
        except ValueError:
            return None
        if not 0 <= position <= max_bytes:
            return None
        return position
    return None


def _read_stack_dump_memfd(
    pid: int,
    descriptor: int,
    start: int,
    end: int,
    max_bytes: int,
    proc_root: Path = Path("/proc"),
) -> bytes | None:
    if (
        pid <= 0
        or descriptor < 0
        or start < 0
        or end <= start
        or end > max_bytes
    ):
        return None
    seal_names = ("F_GET_SEALS", "F_SEAL_GROW", "F_SEAL_SHRINK")
    if any(not hasattr(fcntl, name) for name in seal_names):
        return None
    path = proc_root / str(pid) / "fd" / str(descriptor)
    expected = f"memfd:{STACK_DUMP_MEMFD_NAME}"
    try:
        target = os.readlink(path).lstrip("/")
    except OSError:
        return None
    if target not in {expected, f"{expected} (deleted)"}:
        return None
    flags = os.O_RDONLY | os.O_CLOEXEC
    try:
        source = os.open(path, flags)
        try:
            metadata = os.fstat(source)
            if (
                not statmod.S_ISREG(metadata.st_mode)
                or metadata.st_size != max_bytes
            ):
                return None
            required_seals = fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
            seals = fcntl.fcntl(source, fcntl.F_GET_SEALS)
            if seals & required_seals != required_seals:
                return None
            payload = os.pread(source, end - start, start)
        finally:
            os.close(source)
    except OSError:
        return None
    return payload if len(payload) == end - start else None


def _stack_dump_slot_path(
    state_dir: Path,
    restart_generation: int,
) -> Path:
    if restart_generation < 1:
        raise ValueError("restart_generation must be positive")
    slot = restart_generation % STACK_DUMP_SLOT_COUNT
    return state_dir / STACK_DUMP_DIRECTORY_NAME / f"slot-{slot}.dump"


def _stack_dump_evidence_bytes(
    payload: bytes,
    *,
    pid: int,
    restart_generation: int,
    captured_at_unix: int,
    process_start_ticks: int,
    max_bytes: int,
) -> tuple[bytes, dict[str, object]] | None:
    if (
        not payload
        or pid <= 0
        or restart_generation < 1
        or captured_at_unix <= 0
        or process_start_ticks < 0
        or max_bytes <= 0
    ):
        return None
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    header = {
        "captured_at_unix": captured_at_unix,
        "kind": "grabowski_operator_stack_dump",
        "payload_bytes": len(payload),
        "payload_sha256": payload_sha256,
        "pid": pid,
        "process_start_ticks": process_start_ticks,
        "restart_generation": restart_generation,
        "schema_version": 1,
    }
    encoded_header = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    evidence = encoded_header + b"\n" + payload
    if len(evidence) > max_bytes:
        return None
    return evidence, header


def _write_stack_dump_target(
    path: Path,
    payload: bytes,
    max_bytes: int,
) -> bool:
    if not payload or max_bytes <= 0 or len(payload) > max_bytes:
        return False
    temporary_path: Path | None = None
    descriptor = -1
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_metadata = path.parent.lstat()
        if (
            not statmod.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
        ):
            return False
        os.chmod(path.parent, 0o700)
        temporary_path = path.parent / ".stackdump.pending.tmp"
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
        ):
            return False
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                return False
            written += count
        os.fsync(descriptor)
        os.replace(temporary_path, path)
        temporary_path = None
        directory_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError:
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        statmod.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata.st_uid == os.getuid()
        and statmod.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_size == len(payload)
    )


def request_python_stack_dump(
    pid: int,
    *,
    state_dir: Path,
    restart_generation: int,
    captured_at_unix: int,
    expected_start_ticks: int | None = None,
    max_bytes: int = STACK_DUMP_MAX_BYTES,
    proc_root: Path = Path("/proc"),
) -> dict[str, object] | None:
    if (
        pid <= 0
        or restart_generation < 1
        or captured_at_unix <= 0
        or expected_start_ticks is None
        or expected_start_ticks < 0
        or max_bytes <= 0
        or not hasattr(signal, "SIGUSR1")
    ):
        return None
    pidfd = _stack_dump_pidfd(pid)
    if pidfd is None:
        return None
    try:
        if _process_start_ticks(pid, proc_root) != expected_start_ticks:
            return None
        descriptor = _stack_dump_memfd(pid, proc_root)
        if descriptor is None or not _stack_dump_memfd_is_bounded(
            pid, descriptor, max_bytes, proc_root
        ):
            return None
        before = _stack_dump_memfd_position(
            pid, descriptor, max_bytes, proc_root
        )
        if before is None or before >= max_bytes:
            return None
        if _process_start_ticks(pid, proc_root) != expected_start_ticks:
            return None
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGUSR1)
        except OSError:
            return None
        time.sleep(0.25)
        if _process_start_ticks(pid, proc_root) != expected_start_ticks:
            return None
        after = _stack_dump_memfd_position(pid, descriptor, max_bytes, proc_root)
        if after is None or after <= before:
            return None
        payload = _read_stack_dump_memfd(
            pid, descriptor, before, after, max_bytes, proc_root
        )
        if payload is None:
            return None
        packaged = _stack_dump_evidence_bytes(
            payload,
            pid=pid,
            restart_generation=restart_generation,
            captured_at_unix=captured_at_unix,
            process_start_ticks=expected_start_ticks,
            max_bytes=max_bytes,
        )
        if packaged is None:
            return None
        evidence, header = packaged
        path = _stack_dump_slot_path(state_dir, restart_generation)
        if not _write_stack_dump_target(path, evidence, max_bytes):
            return None
        receipt: dict[str, object] = {
            **header,
            "evidence_bytes": len(evidence),
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "relative_path": str(path.relative_to(state_dir)),
            "slot": restart_generation % STACK_DUMP_SLOT_COUNT,
        }
        return receipt
    finally:
        os.close(pidfd)


def refresh_connector_snapshot_from_runtime(
    *,
    runtime_root: Path,
    host: str,
    port: int,
    connector_pid: int,
    connector_start_ticks: int,
    timeout_seconds: float = CONNECTOR_SNAPSHOT_REFRESH_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Refresh snapshot evidence without making snapshot failure a tunnel restart signal."""
    try:
        root = runtime_root.expanduser().resolve(strict=True)
    except OSError:
        return {"state": "error", "reason": "runtime-root-unavailable"}
    executable = root / ".venv/bin/python"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return {"state": "error", "reason": "runtime-python-unavailable"}
    if connector_pid <= 0 or connector_start_ticks < 0:
        return {"state": "error", "reason": "connector-process-identity-unavailable"}
    mcp_url = f"http://{host}:{port}/mcp"
    child_environment = os.environ.copy()
    child_environment.pop("PYTHONHOME", None)
    child_environment.pop("PYTHONPATH", None)
    child_environment["PYTHONDONTWRITEBYTECODE"] = "1"
    child_environment["PYTHONNOUSERSITE"] = "1"
    command = [
        str(executable),
        "-I",
        "-m",
        "grabowski_client_snapshot",
        "refresh-if-needed",
        "--runtime-root",
        str(root),
        "--mcp-url",
        mcp_url,
        "--connector-pid",
        str(connector_pid),
        "--connector-start-ticks",
        str(connector_start_ticks),
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            env=child_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=max(1.0, timeout_seconds + 2.0),
        )
    except (OSError, subprocess.SubprocessError):
        return {"state": "error", "reason": "snapshot-refresh-process-failed"}
    encoded = completed.stdout.encode("utf-8", errors="replace")
    if len(encoded) > CONNECTOR_SNAPSHOT_REFRESH_MAX_OUTPUT_BYTES:
        return {"state": "error", "reason": "snapshot-refresh-output-too-large"}
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return {"state": "error", "reason": "snapshot-refresh-output-missing"}
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"state": "error", "reason": "snapshot-refresh-output-invalid"}
    if not isinstance(payload, dict):
        return {"state": "error", "reason": "snapshot-refresh-output-invalid"}
    state = payload.get("state")
    if completed.returncode != 0 or state not in {"not_due", "renewed"}:
        reason = payload.get("reason")
        return {
            "state": "error",
            "reason": reason if isinstance(reason, str) and len(reason) <= 256 else "snapshot-refresh-failed",
        }
    allowed = {
        key: payload[key]
        for key in (
            "state",
            "reason",
            "tool_count",
            "names_sha256",
            "release_id",
            "receipt_sha256",
            "session_id_sha256",
        )
        if key in payload
    }
    return allowed


def _emit_connector_snapshot_refresh(
    args: argparse.Namespace,
    probe: ProbeResult,
) -> None:
    if (
        args.component != "tunnel"
        or args.check_only
        or probe.pid is None
        or probe.start_ticks is None
    ):
        return
    result = refresh_connector_snapshot_from_runtime(
        runtime_root=args.runtime_root,
        host=args.host,
        port=args.port,
        connector_pid=probe.pid,
        connector_start_ticks=probe.start_ticks,
    )
    emit(
        "grabowski.connector_snapshot.refresh",
        component=args.component,
        service=args.service,
        **result,
    )


def _bounded_restart_stderr(stderr: str | None) -> str:
    if not stderr:
        return ""
    return " ".join(stderr.split())[:SERVICE_RESTART_ERROR_MAX_CHARS]


def restart_service(service: str) -> None:
    try:
        subprocess.run(
            ["systemctl", "--user", "--no-block", "restart", service],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SERVICE_RESTART_REQUEST_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise WatchdogError("service-restart-timeout") from exc
    except subprocess.CalledProcessError as exc:
        detail = _bounded_restart_stderr(exc.stderr)
        if detail:
            raise WatchdogError(f"service-restart-failed: {detail}") from exc
        raise WatchdogError(f"service-restart-failed: exit-{exc.returncode}") from exc
    except OSError as exc:
        raise WatchdogError("service-restart-exec-failed") from exc


def _is_new_process_instance(previous: ProbeResult, current: ProbeResult) -> bool:
    if current.pid is None:
        return False
    if previous.pid is None:
        return True
    if current.pid != previous.pid:
        return True
    if previous.start_ticks is None or current.start_ticks is None:
        return False
    return current.start_ticks != previous.start_ticks


def classify_tunnel_readiness_dependency(
    probe: ProbeResult,
    state: WatchdogState,
    *,
    service: str,
    profile: str,
    startup_grace: float,
    mcp_url: str,
    timeout: float,
    proc_root: Path = Path("/proc"),
) -> tuple[ProbeResult, WatchdogState]:
    """Separate a missing readiness dependency from stale tunnel state."""
    evidence_matches_process = (
        state._readiness_dependency_evidence_loaded_from_disk
        and state.readiness_dependency_unavailable_boot_id is not None
        and state.readiness_dependency_unavailable_pid is not None
        and state.readiness_dependency_unavailable_start_ticks is not None
        and probe.boot_id == state.readiness_dependency_unavailable_boot_id
        and probe.pid == state.readiness_dependency_unavailable_pid
        and probe.start_ticks
        == state.readiness_dependency_unavailable_start_ticks
    )
    if (
        state.readiness_dependency_unavailable_boot_id is not None
        and not evidence_matches_process
    ):
        state = replace(
            state,
            readiness_dependency_unavailable_boot_id=None,
            readiness_dependency_unavailable_pid=None,
            readiness_dependency_unavailable_start_ticks=None,
        )
        evidence_matches_process = False
    if probe.status != "indeterminate" or probe.reasons != ("readiness-failed",):
        return probe, state
    dependency_failure = mcp_http_probe(mcp_url, timeout)
    identity, identity_failure = tunnel_service_process_identity(
        service,
        profile,
        startup_grace,
        proc_root=proc_root,
    )
    if (
        identity_failure is not None
        or identity is None
        or probe.boot_id != identity.boot_id
        or probe.pid != identity.pid
        or probe.start_ticks != identity.start_ticks
    ):
        state = replace(
            state,
            readiness_dependency_unavailable_boot_id=None,
            readiness_dependency_unavailable_pid=None,
            readiness_dependency_unavailable_start_ticks=None,
        )
        return (
            ProbeResult(
                "indeterminate",
                (
                    identity_failure
                    or "tunnel-service-changed-after-dependency-probe",
                ),
                probe.pid,
                probe.age_seconds,
                probe.start_ticks,
                probe.boot_id,
            ),
            state,
        )
    if dependency_failure == "mcp-http-request-failed":
        state = replace(
            state,
            readiness_dependency_unavailable_boot_id=identity.boot_id,
            readiness_dependency_unavailable_pid=identity.pid,
            readiness_dependency_unavailable_start_ticks=identity.start_ticks,
        )
        return (
            ProbeResult(
                "dependency-unavailable",
                ("readiness-dependency-unavailable",),
                probe.pid,
                probe.age_seconds,
                probe.start_ticks,
                probe.boot_id,
            ),
            state,
        )
    if dependency_failure is None and evidence_matches_process:
        return (
            ProbeResult(
                "unhealthy",
                ("readiness-stale-after-dependency-recovered",),
                probe.pid,
                probe.age_seconds,
                probe.start_ticks,
                probe.boot_id,
            ),
            state,
        )
    if dependency_failure is None:
        return probe, state
    return (
        ProbeResult(
            "indeterminate",
            ("readiness-failed", f"readiness-dependency-{dependency_failure}"),
            probe.pid,
            probe.age_seconds,
            probe.start_ticks,
            probe.boot_id,
        ),
        state,
    )


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
    # All admission operations must use the same canonical, owner-checked path
    # as the watchdog state and deployment lock.
    args.state_dir = state_dir
    state_path = state_dir / f"{args.component}-watchdog-state.json"
    lock_path = state_dir / f"{args.component}-watchdog.lock"
    recovery_lock_path = state_dir / "component-recovery.lock"
    deploy_lock = state_dir / "deploy.lock"

    with ExitStack() as locks:
        locks.enter_context(exclusive_lock(lock_path))
        locks.enter_context(exclusive_lock(recovery_lock_path))
        with deployment_shared_lock(deploy_lock) as deployment_clear:
            if not deployment_clear:
                emit(
                    "grabowski.component_watchdog.skipped",
                    component=args.component,
                    reason="deployment-in-progress",
                )
                return 0

            if args.component == "tunnel":
                marker = read_watchdog_admission_marker(
                    state_dir / WATCHDOG_ADMISSION_MARKER_NAME
                )
                if marker is not None:
                    now = int(time.time())
                    marker_state = (
                        "active"
                        if int(marker["expires_at_unix"]) > now
                        else "expired-unreconciled"
                    )
                    emit(
                        "grabowski.component_watchdog.recovery_admission_present",
                        component=args.component,
                        service=args.service,
                        marker_state=marker_state,
                        expected_head=marker["expected_head"],
                        expires_at_unix=marker["expires_at_unix"],
                    )
                    return 1

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
                metrics_url=args.metrics_url,
                control_plane_poll_max_age=args.control_plane_poll_max_age,
            )
            state = load_state(state_path)
            if args.component == "tunnel":
                probe, state = classify_tunnel_readiness_dependency(
                    probe,
                    state,
                    service=args.service,
                    profile=args.profile,
                    startup_grace=args.startup_grace,
                    mcp_url=args.mcp_url,
                    timeout=args.http_timeout,
                )
                save_state(state_path, state)
            common = {
                "component": args.component,
                "service": args.service,
                "status": probe.status,
                "reasons": list(probe.reasons),
                "pid": probe.pid,
            }

            if probe.status == "healthy":
                _emit_connector_snapshot_refresh(args, probe)
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
            if probe.status == "dependency-unavailable":
                emit(
                    "grabowski.component_watchdog.dependency_unavailable",
                    **common,
                )
                return DEPENDENCY_UNAVAILABLE_EXIT
            if probe.status == "indeterminate":
                emit("grabowski.component_watchdog.indeterminate", **common)
                return 2
            if args.check_only:
                emit("grabowski.component_watchdog.unhealthy", **common)
                return 1

            decision_now = int(time.time())
            action, next_state = decide(
                state,
                now=decision_now,
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

            stack_dump_receipt = None
            if args.component == "operator" and probe.pid is not None:
                stack_dump_receipt = request_python_stack_dump(
                    probe.pid,
                    state_dir=state_dir,
                    restart_generation=next_state.restart_generation,
                    captured_at_unix=decision_now,
                    expected_start_ticks=probe.start_ticks,
                )
            stack_dump_requested = stack_dump_receipt is not None

            if args.component == "operator":
                emit(
                    "grabowski.component_watchdog.restart_preparing",
                    **common,
                    stack_dump_requested=stack_dump_requested,
                    stack_dump_receipt=stack_dump_receipt,
                    restart_generation=next_state.restart_generation,
                )
                try:
                    outcome, final_probe, safety_proof = safe_operator_restart(
                        args, probe
                    )
                except RecoveryMutationError as exc:
                    if stack_dump_requested:
                        emit(
                            "grabowski.component_watchdog.stack_dump_finalized",
                            component=args.component,
                            service=args.service,
                            persisted=True,
                            receipt=stack_dump_receipt,
                            max_bytes=STACK_DUMP_MAX_BYTES,
                            recovery_outcome=(
                                "rollback_recovered"
                                if exc.rollback_recovered
                                else "fail_closed"
                            ),
                        )
                    if exc.rollback_recovered:
                        deferred_state = replace(
                            state,
                            consecutive_failures=max(
                                state.consecutive_failures,
                                args.failure_threshold,
                            ),
                            next_restart_not_before=(
                                decision_now + args.backoff_base
                            ),
                        )
                        save_state(state_path, deferred_state)
                        emit(
                            "grabowski.component_watchdog.restart_rolled_back",
                            **common,
                            reason=str(exc),
                            next_restart_not_before=(
                                deferred_state.next_restart_not_before
                            ),
                            restart_generation=state.restart_generation,
                        )
                        return 1

                    failed_state = replace(
                        next_state, consecutive_failures=1
                    )
                    save_state(state_path, failed_state)
                    emit(
                        "grabowski.component_watchdog.restart_fail_closed",
                        **common,
                        reason=str(exc),
                        marker_present=True,
                        restart_generation=failed_state.restart_generation,
                    )
                    return 4
                except WatchdogError as exc:
                    if stack_dump_requested:
                        emit(
                            "grabowski.component_watchdog.stack_dump_finalized",
                            component=args.component,
                            service=args.service,
                            persisted=True,
                            receipt=stack_dump_receipt,
                            max_bytes=STACK_DUMP_MAX_BYTES,
                            recovery_outcome="safety_deferred",
                        )
                    deferred_state = replace(
                        state,
                        consecutive_failures=max(
                            state.consecutive_failures, args.failure_threshold
                        ),
                        next_restart_not_before=decision_now + args.backoff_base,
                    )
                    save_state(state_path, deferred_state)
                    emit(
                        "grabowski.component_watchdog.restart_safety_deferred",
                        **common,
                        reason=str(exc),
                        stack_dump_requested=stack_dump_requested,
                        stack_dump_receipt=stack_dump_receipt,
                        next_restart_not_before=(
                            deferred_state.next_restart_not_before
                        ),
                        restart_generation=state.restart_generation,
                    )
                    return 1

                if stack_dump_requested:
                    emit(
                        "grabowski.component_watchdog.stack_dump_finalized",
                        component=args.component,
                        service=args.service,
                        persisted=True,
                        receipt=stack_dump_receipt,
                        max_bytes=STACK_DUMP_MAX_BYTES,
                        recovery_outcome=outcome,
                    )
                if outcome == "recovered-without-restart":
                    recovered_state = reset_after_healthy(
                        state,
                        now=int(time.time()),
                        restart_window=args.restart_window,
                    )
                    save_state(state_path, recovered_state)
                    emit(
                        "grabowski.component_watchdog.recovered_without_restart",
                        component=args.component,
                        service=args.service,
                        pid=(
                            final_probe.pid
                            if final_probe is not None
                            else probe.pid
                        ),
                        safety_proof=safety_proof,
                        restart_generation=recovered_state.restart_generation,
                    )
                    return 0
                if outcome != "restarted" or final_probe is None:
                    raise WatchdogError("operator-safe-recovery-outcome-invalid")

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
                    metrics_url=args.metrics_url,
                    control_plane_poll_max_age=args.control_plane_poll_max_age,
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
                        safety_proof=safety_proof,
                        backoff_level=recovered_state.backoff_level,
                        next_restart_not_before=(
                            recovered_state.next_restart_not_before
                        ),
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
                    restart_generation=next_state.restart_generation,
                )
                return 4

            emit(
                "grabowski.component_watchdog.restarting",
                **common,
                stack_dump_requested=stack_dump_requested,
                stack_dump_receipt=stack_dump_receipt,
                backoff_level=next_state.backoff_level,
                next_restart_not_before=next_state.next_restart_not_before,
                restart_generation=next_state.restart_generation,
            )
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
                    health_url=args.health_url,
                    ready_url=args.ready_url,
                    startup_grace=0,
                    http_timeout=args.http_timeout,
                    mcp_url=args.mcp_url,
                    metrics_url=args.metrics_url,
                    control_plane_poll_max_age=args.control_plane_poll_max_age,
                )
                if final_probe.status == "healthy" and _is_new_process_instance(
                    probe, final_probe
                ):
                    _emit_connector_snapshot_refresh(args, final_probe)
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
    result.add_argument("--tunnel-service", default=DEFAULT_TUNNEL_SERVICE)
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
    result.add_argument("--metrics-url", default=DEFAULT_METRICS_URL)
    result.add_argument(
        "--control-plane-poll-max-age",
        type=float,
        default=DEFAULT_CONTROL_PLANE_POLL_MAX_AGE,
    )
    result.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    result.add_argument("--failure-threshold", type=int, default=3)
    result.add_argument("--max-restarts", type=int, default=3)
    result.add_argument("--restart-window", type=int, default=900)
    result.add_argument("--backoff-base", type=int, default=DEFAULT_BACKOFF_BASE)
    result.add_argument("--backoff-max", type=int, default=DEFAULT_BACKOFF_MAX)
    result.add_argument("--startup-grace", type=float, default=20)
    result.add_argument("--http-timeout", type=float, default=2)
    result.add_argument(
        "--recovery-timeout", type=float, default=DEFAULT_RECOVERY_TIMEOUT_SECONDS
    )
    result.add_argument(
        "--restart-drain-timeout",
        type=float,
        default=WATCHDOG_ADMISSION_DRAIN_TIMEOUT_SECONDS,
    )
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
    if args.control_plane_poll_max_age <= 0:
        raise WatchdogError("invalid-control-plane-poll-max-age")
    if (
        args.restart_drain_timeout <= 0
        or args.restart_drain_timeout > WATCHDOG_MAX_RESTART_DRAIN_TIMEOUT_SECONDS
        or args.recovery_timeout <= 0
        or args.recovery_timeout > WATCHDOG_MAX_RECOVERY_TIMEOUT_SECONDS
    ):
        raise WatchdogError("invalid-recovery-time-policy")
    recovery_envelope = (
        2 * args.restart_drain_timeout
        + 4 * args.recovery_timeout
        + 2 * WATCHDOG_TUNNEL_STOP_TIMEOUT_SECONDS
        + 2 * WATCHDOG_SERVICE_ACTION_TIMEOUT_SECONDS
        + WATCHDOG_RECOVERY_MARGIN_SECONDS
    )
    if recovery_envelope > WATCHDOG_MAX_RUN_SECONDS:
        raise WatchdogError("recovery-time-policy-exceeds-service-budget")
    if not args.tunnel_service or len(args.tunnel_service) > 255:
        raise WatchdogError("invalid-tunnel-service")
    loopback_http_url(args.metrics_url)
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
