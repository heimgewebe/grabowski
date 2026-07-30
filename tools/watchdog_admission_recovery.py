from __future__ import annotations

import http.client
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat as statmod
import time
from urllib.parse import urlsplit


class WatchdogError(RuntimeError):
    pass


ADMISSION_MARKER_NAME = "deployment-admission-drain.json"
ADMISSION_MARKER_KIND = "grabowski_deployment_admission_drain"
ADMISSION_STATUS_PATH = "/_grabowski/deployment-admission"
ADMISSION_MAX_BYTES = 4096
ADMISSION_MAX_LIFETIME_SECONDS = 1800
ADMISSION_IDLE_SAMPLES = 2
TUNNEL_DRAIN_IDLE_SAMPLES = 3
TUNNEL_DRAIN_SAMPLE_SECONDS = 0.2
TUNNEL_METRICS_MAX_BYTES = 2 * 1024 * 1024
TUNNEL_METRIC_NAMES = (
    "commands_queue_length",
    "commands_polled_total",
    "commands_enqueued_total",
    "process_start_time_seconds",
)
TUNNEL_FINAL_RESPONSE_METRIC = "command_end_to_end_latency_milliseconds_count"
RUNTIME_MANIFEST_NAME = "deployment-manifest.json"


def _read_bounded_fd(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > max_bytes:
        raise WatchdogError("watchdog-admission-marker-too-large")
    return payload


def _runtime_manifest_identity(runtime_root: Path) -> tuple[str, str]:
    try:
        root = runtime_root.expanduser().resolve(strict=True)
        raw = (root / RUNTIME_MANIFEST_NAME).read_bytes()
    except OSError as exc:
        raise WatchdogError("runtime-manifest-unavailable") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise WatchdogError("runtime-manifest-too-large")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WatchdogError("runtime-manifest-invalid") from exc
    if not isinstance(manifest, dict):
        raise WatchdogError("runtime-manifest-invalid")
    head = manifest.get("repo_head")
    source_sha256 = manifest.get("source_sha256")
    if (
        not isinstance(head, str)
        or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", head) is None
        or not isinstance(source_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_sha256) is None
    ):
        raise WatchdogError("runtime-manifest-identity-invalid")
    return head, source_sha256


def _validate_marker(value: object) -> dict[str, object]:
    expected_keys = {
        "schema_version",
        "kind",
        "token",
        "expected_head",
        "source_identity_sha256",
        "created_at_unix",
        "expires_at_unix",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise WatchdogError("watchdog-admission-marker-invalid")
    created = value.get("created_at_unix")
    expires = value.get("expires_at_unix")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != ADMISSION_MARKER_KIND
        or not isinstance(value.get("token"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["token"]) is None
        or not isinstance(value.get("expected_head"), str)
        or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value["expected_head"])
        is None
        or not isinstance(value.get("source_identity_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["source_identity_sha256"])
        is None
        or type(created) is not int
        or type(expires) is not int
        or expires <= created
        or expires - created > ADMISSION_MAX_LIFETIME_SECONDS
    ):
        raise WatchdogError("watchdog-admission-marker-invalid")
    return value


def read_admission_marker(path: Path) -> dict[str, object] | None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise WatchdogError("watchdog-admission-marker-open-failed") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not statmod.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or statmod.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > ADMISSION_MAX_BYTES
        ):
            raise WatchdogError("watchdog-admission-marker-unsafe")
        raw = _read_bounded_fd(descriptor, ADMISSION_MAX_BYTES)
    finally:
        os.close(descriptor)
    try:
        return _validate_marker(json.loads(raw.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WatchdogError("watchdog-admission-marker-invalid") from exc


def engage_admission(
    *, state_dir: Path, runtime_root: Path, lifetime_seconds: int
) -> dict[str, object]:
    if not 1 <= lifetime_seconds <= ADMISSION_MAX_LIFETIME_SECONDS:
        raise WatchdogError("watchdog-admission-lifetime-invalid")
    head, source_sha256 = _runtime_manifest_identity(runtime_root)
    path = state_dir / ADMISSION_MARKER_NAME
    if read_admission_marker(path) is not None:
        raise WatchdogError("watchdog-admission-marker-exists")
    now = int(time.time())
    marker: dict[str, object] = {
        "schema_version": 1,
        "kind": ADMISSION_MARKER_KIND,
        "token": secrets.token_hex(32),
        "expected_head": head,
        "source_identity_sha256": source_sha256,
        "created_at_unix": now,
        "expires_at_unix": now + lifetime_seconds,
    }
    payload = (
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
    except OSError as exc:
        raise WatchdogError("watchdog-admission-parent-open-failed") from exc
    descriptor = -1
    try:
        parent_linked = path.parent.lstat()
        parent_opened = os.fstat(parent_descriptor)
        if (
            not statmod.S_ISDIR(parent_opened.st_mode)
            or statmod.S_ISLNK(parent_linked.st_mode)
            or parent_opened.st_uid != os.getuid()
            or statmod.S_IMODE(parent_opened.st_mode) & 0o077
            or (parent_linked.st_dev, parent_linked.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
        ):
            raise WatchdogError("watchdog-admission-parent-unsafe")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                path.name, flags, 0o600, dir_fd=parent_descriptor
            )
        except OSError as exc:
            raise WatchdogError("watchdog-admission-marker-create-failed") from exc
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise WatchdogError("watchdog-admission-marker-write-failed")
            offset += written
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise WatchdogError("watchdog-admission-marker-create-unsafe")
        os.fsync(parent_descriptor)
    except Exception:
        if descriptor >= 0:
            try:
                linked = os.stat(
                    path.name, dir_fd=parent_descriptor, follow_symlinks=False
                )
                opened = os.fstat(descriptor)
                if (linked.st_dev, linked.st_ino) == (opened.st_dev, opened.st_ino):
                    os.unlink(path.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
    if read_admission_marker(path) != marker:
        raise WatchdogError("watchdog-admission-marker-readback-drift")
    return marker


def release_admission(*, state_dir: Path, marker: dict[str, object]) -> None:
    path = state_dir / ADMISSION_MARKER_NAME
    parent_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(path.parent, parent_flags)
    except OSError as exc:
        raise WatchdogError("watchdog-admission-parent-open-failed") from exc
    descriptor = -1
    try:
        file_flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path.name, file_flags, dir_fd=parent_descriptor)
        except FileNotFoundError as exc:
            raise WatchdogError("watchdog-admission-marker-missing") from exc
        opened = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not statmod.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or statmod.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise WatchdogError("watchdog-admission-marker-release-unsafe")
        raw = _read_bounded_fd(descriptor, ADMISSION_MAX_BYTES)
        try:
            observed = _validate_marker(json.loads(raw.decode("utf-8")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise WatchdogError("watchdog-admission-marker-invalid") from exc
        if observed != marker:
            raise WatchdogError("watchdog-admission-marker-owner-drift")
        linked_again = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (opened.st_dev, opened.st_ino) != (
            linked_again.st_dev,
            linked_again.st_ino,
        ):
            raise WatchdogError("watchdog-admission-marker-release-drift")
        os.unlink(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)
    if path.exists() or path.is_symlink():
        raise WatchdogError("watchdog-admission-marker-release-drift")


def _loopback_http_get(url: str, timeout: float, max_bytes: int) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}:
        raise WatchdogError("watchdog-loopback-url-invalid")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise WatchdogError("watchdog-loopback-url-invalid")
    port = parsed.port
    if port is None or not 1 <= port <= 65535:
        raise WatchdogError("watchdog-loopback-url-invalid")
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        if response.status != 200:
            raise WatchdogError("watchdog-loopback-http-status-invalid")
        payload = response.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise WatchdogError("watchdog-loopback-response-too-large")
        return payload
    except (OSError, http.client.HTTPException) as exc:
        raise WatchdogError("watchdog-loopback-http-unreachable") from exc
    finally:
        connection.close()


def operator_admission_observation(
    *, host: str, port: int, timeout: float
) -> dict[str, object]:
    if host not in {"127.0.0.1", "::1"} or not 1 <= port <= 65535:
        raise WatchdogError("watchdog-admission-status-target-invalid")
    authority = f"[{host}]" if host == "::1" else host
    payload = _loopback_http_get(
        f"http://{authority}:{port}{ADMISSION_STATUS_PATH}",
        timeout,
        ADMISSION_MAX_BYTES,
    )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WatchdogError("watchdog-admission-status-invalid") from exc
    if not isinstance(value, dict):
        raise WatchdogError("watchdog-admission-status-invalid")
    return value


def wait_for_admission_idle(
    marker: dict[str, object],
    *,
    host: str,
    port: int,
    timeout: float,
    observation_fn: object | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    consecutive_idle = 0
    attempts = 0
    while True:
        attempts += 1
        observer = observation_fn or operator_admission_observation
        observed = observer(
            host=host, port=port, timeout=min(2.0, max(0.1, timeout))
        )
        active_calls = observed.get("active_tool_calls")
        valid = (
            observed.get("valid") is True
            and observed.get("active") is True
            and observed.get("state") == "active"
            and observed.get("admission_gate_installed") is True
            and observed.get("token") == marker.get("token")
            and observed.get("expected_head") == marker.get("expected_head")
            and observed.get("source_identity_sha256")
            == marker.get("source_identity_sha256")
            and type(active_calls) is int
            and active_calls >= 0
        )
        if not valid:
            raise WatchdogError("watchdog-admission-status-drift")
        consecutive_idle = consecutive_idle + 1 if active_calls == 0 else 0
        if consecutive_idle >= ADMISSION_IDLE_SAMPLES:
            return {
                "attempts": attempts,
                "consecutive_idle_samples": consecutive_idle,
                "observation": observed,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WatchdogError("watchdog-admission-active-calls-timeout")
        time.sleep(min(TUNNEL_DRAIN_SAMPLE_SECONDS, remaining))


def parse_tunnel_metrics(text: str) -> dict[str, float]:
    """Parse required tunnel counters and optional final-response series.

    Cold Prometheus exporters often omit histogram/summary series until the first
    sample is observed. Missing
    ``command_end_to_end_latency_milliseconds_count{latency_type="enqueue_to_response"}``
    is therefore treated as idle ``commands_final_responses_total=0``. Balance
    checks still reject traffic without matching final responses because
    ``polled``/``enqueued`` would then exceed zero.
    """
    direct: dict[str, float] = {}
    duplicates: set[str] = set()
    final_responses = 0.0
    final_series = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        metric, value_text = parts[0], parts[1]
        if (
            metric.startswith(TUNNEL_FINAL_RESPONSE_METRIC + "{")
            and 'latency_type="enqueue_to_response"' in metric
        ):
            try:
                value = float(value_text)
            except ValueError as exc:
                raise WatchdogError("watchdog-tunnel-metric-invalid") from exc
            if not math.isfinite(value) or value < 0:
                raise WatchdogError("watchdog-tunnel-metric-invalid")
            final_responses += value
            final_series += 1
            continue
        for name in TUNNEL_METRIC_NAMES:
            if metric != name and not metric.startswith(name + "{"):
                continue
            if name in direct:
                duplicates.add(name)
                continue
            try:
                value = float(value_text)
            except ValueError as exc:
                raise WatchdogError("watchdog-tunnel-metric-invalid") from exc
            if not math.isfinite(value) or value < 0:
                raise WatchdogError("watchdog-tunnel-metric-invalid")
            direct[name] = value
    missing = [name for name in TUNNEL_METRIC_NAMES if name not in direct]
    if missing or duplicates:
        raise WatchdogError("watchdog-tunnel-metrics-incomplete")
    # Idle tunnels may never have exported the final-response series.
    direct["commands_final_responses_total"] = (
        final_responses if final_series > 0 else 0.0
    )
    return direct


def wait_for_tunnel_idle(
    *,
    metrics_url: str,
    timeout: float,
    text_getter: object | None = None,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    attempts = 0
    consecutive_idle = 0
    previous_stability: tuple[float, ...] | None = None
    while True:
        attempts += 1
        if text_getter is None:
            payload = _loopback_http_get(
                metrics_url,
                min(2.0, max(0.1, timeout)),
                TUNNEL_METRICS_MAX_BYTES,
            )
            try:
                text = payload.decode("utf-8")
            except UnicodeError as exc:
                raise WatchdogError("watchdog-tunnel-metrics-invalid") from exc
        else:
            text = text_getter(
                metrics_url,
                min(2.0, max(0.1, timeout)),
                TUNNEL_METRICS_MAX_BYTES,
            )
            if text is None:
                raise WatchdogError("watchdog-tunnel-metrics-unreachable")
        observed = parse_tunnel_metrics(text)
        stability = tuple(
            observed[name]
            for name in (
                "commands_polled_total",
                "commands_enqueued_total",
                "commands_final_responses_total",
                "process_start_time_seconds",
            )
        )
        balanced = (
            observed["commands_queue_length"] == 0
            and observed["commands_polled_total"]
            == observed["commands_enqueued_total"]
            == observed["commands_final_responses_total"]
        )
        consecutive_idle = (
            consecutive_idle + 1
            if balanced and stability == previous_stability
            else 1 if balanced else 0
        )
        previous_stability = stability
        if consecutive_idle >= TUNNEL_DRAIN_IDLE_SAMPLES:
            return {
                "attempts": attempts,
                "consecutive_idle_samples": consecutive_idle,
                "metrics": observed,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WatchdogError("watchdog-tunnel-drain-timeout")
        time.sleep(min(TUNNEL_DRAIN_SAMPLE_SECONDS, remaining))
