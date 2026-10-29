#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

SERVICE_NAME = "grabowski-juno-openai-gateway.service"
PROBE_SERVICE_NAME = "grabowski-coding-agent-router-probe.service"
PROBE_TIMER_NAME = "grabowski-coding-agent-router-probe.timer"
MODEL_ID = "grabowski-juno"
LOCAL_BASE_URL = "http://127.0.0.1:18195"
INSTALL_SMOKE_REPLY = "JUNO_INSTALL_SMOKE_OK"
STATE_DIR = Path.home() / ".local" / "state" / "grabowski" / "juno-openai-gateway"
TOKEN_PATH = STATE_DIR / "token"
USER_UNIT_DIR = Path.home() / ".config" / "systemd" / "user"
UNIT_PATH = USER_UNIT_DIR / SERVICE_NAME
REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "systemd" / f"{SERVICE_NAME}.example"
PROBE_SERVICE_TEMPLATE_PATH = REPO_ROOT / "systemd" / f"{PROBE_SERVICE_NAME}.example"
PROBE_TIMER_TEMPLATE_PATH = REPO_ROOT / "systemd" / f"{PROBE_TIMER_NAME}.example"
PROBE_SERVICE_PATH = USER_UNIT_DIR / PROBE_SERVICE_NAME
PROBE_TIMER_PATH = USER_UNIT_DIR / PROBE_TIMER_NAME
LAUNCHER_SOURCE_PATH = REPO_ROOT / "tools/grabowski_juno_runtime_launcher.py"
LAUNCHER_EXEC_PATH = Path.home() / ".local/libexec/grabowski/grabowski_juno_runtime_launcher.py"
GATEWAY_SOURCE_PATH = REPO_ROOT / "src" / "grabowski_juno_openai_gateway.py"
GATEWAY_EXEC_PATH = (
    Path.home()
    / ".local"
    / "libexec"
    / "grabowski"
    / "grabowski_juno_openai_gateway.py"
)
MAX_INSTALL_ARTIFACT_BYTES = 2 * 1024 * 1024
KNOWN_GATEWAY_FAILURE_CODES = frozenset({
    "router_unavailable", "no_safe_route", "unsafe_route",
    "route_revalidation_failed", "backend_feature_probe_failed",
    "backend_failed", "backend_unavailable", "backend_timeout",
    "backend_output_missing", "backend_output_invalid",
})


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secure_existing_token(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("gateway token must be a regular file")
        if metadata.st_uid != os.getuid():
            raise RuntimeError("gateway token owner is invalid")
        if metadata.st_nlink != 1:
            raise RuntimeError("gateway token must have exactly one hard link")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("gateway token permissions are too broad")
        if not 32 <= metadata.st_size <= 4096:
            raise RuntimeError("gateway token size is invalid")
        data = os.read(descriptor, metadata.st_size + 1)
        if len(data) != metadata.st_size:
            raise RuntimeError("gateway token changed while being read")
    finally:
        os.close(descriptor)


def _ensure_token(path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        _secure_existing_token(path)
        return False
    try:
        token = secrets.token_urlsafe(48).encode("ascii") + b"\n"
        written = os.write(descriptor, token)
        if written != len(token):
            raise RuntimeError("short write while creating gateway token")
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        os.close(descriptor)
    _secure_existing_token(path)
    return True


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_regular_file(path: Path, *, label: str) -> tuple[bytes, int]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"{label} must be a regular file")
        if before.st_uid != os.getuid():
            raise RuntimeError(f"{label} owner is invalid")
        if before.st_nlink != 1:
            raise RuntimeError(f"{label} must have exactly one hard link")
        if before.st_size > MAX_INSTALL_ARTIFACT_BYTES:
            raise RuntimeError(f"{label} exceeds the installer size limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise RuntimeError(f"{label} ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"{label} grew while being read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise RuntimeError(f"{label} changed while being read")
    return b"".join(chunks), stat.S_IMODE(before.st_mode)


def _snapshot_file(path: Path, *, label: str) -> tuple[bytes, int] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return _read_regular_file(path, label=label)


def _atomic_write_bytes(destination: Path, data: bytes, *, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeError(f"short write while installing {destination}")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _install_file(source: Path, destination: Path, *, mode: int) -> str:
    data, _source_mode = _read_regular_file(source, label="install source")
    source_sha256 = hashlib.sha256(data).hexdigest()
    _atomic_write_bytes(destination, data, mode=mode)
    installed_data, installed_mode = _read_regular_file(
        destination, label="installed artifact"
    )
    if hashlib.sha256(installed_data).hexdigest() != source_sha256:
        raise RuntimeError(f"installed copy hash mismatch: {destination}")
    if installed_mode != mode:
        raise RuntimeError(f"installed mode mismatch: {destination}")
    return source_sha256


def _install_unit(template: Path, destination: Path) -> str:
    return _install_file(template, destination, mode=0o644)


def _restore_file(
    destination: Path,
    snapshot: tuple[bytes, int] | None,
    *,
    label: str,
) -> None:
    if snapshot is not None:
        data, mode = snapshot
        _atomic_write_bytes(destination, data, mode=mode)
        return
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError(f"refusing to remove unexpected rollback {label}")
    destination.unlink()
    _fsync_directory(destination.parent)


def _systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=100 if arguments == ("start", PROBE_SERVICE_NAME) else 30,
    )


def _systemctl_probe(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def _unit_state(name: str) -> dict[str, bool]:
    observation = _systemctl_probe(
        "show",
        name,
        "--no-pager",
        "--property=LoadState",
        "--property=ActiveState",
        "--property=UnitFileState",
    )
    if observation.returncode != 0:
        raise RuntimeError(
            f"cannot observe prior {name} state: exit {observation.returncode}"
        )
    properties: dict[str, str] = {}
    for line in observation.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    if not {"LoadState", "ActiveState", "UnitFileState"} <= properties.keys():
        raise RuntimeError(f"prior {name} state readback is incomplete")
    enabled_states = {"enabled", "enabled-runtime", "linked", "linked-runtime"}
    return {
        "active": properties["ActiveState"] == "active",
        "enabled": properties["UnitFileState"] in enabled_states,
    }


def _service_state() -> dict[str, bool]:
    return _unit_state(SERVICE_NAME)


def _probe_timer_state() -> dict[str, bool]:
    return _unit_state(PROBE_TIMER_NAME)


def _read_token_for_smoke(path: Path) -> str:
    _secure_existing_token(path)
    return path.read_text(encoding="ascii").strip()


def _read_json_response(response: Any, *, label: str) -> dict[str, Any]:
    if response.status != 200:
        raise RuntimeError(f"{label} returned HTTP {response.status}")
    try:
        value = json.loads(response.read())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} did not return valid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} did not return a JSON object")
    return value


def _verified_https_smoke_url(value: str) -> str:
    """Send the local credential only to the existing Tailscale Serve backend."""
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or not parsed.hostname.endswith(".ts.net")
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("smoke URL must be a bare HTTPS Tailscale Serve origin")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise RuntimeError("smoke URL port is invalid") from exc
    key = parsed.hostname + (f":{port}" if port != 443 else ":443")
    try:
        result = subprocess.run(
            ["tailscale", "serve", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
        serve = json.loads(result.stdout)
        handler = serve["Web"][key]["Handlers"]["/"]
    except (OSError, subprocess.SubprocessError, KeyError, TypeError,
            ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("cannot attest Tailscale Serve smoke target") from exc
    if handler.get("Proxy") != LOCAL_BASE_URL or serve.get("AllowFunnel", {}).get(key):
        raise RuntimeError("smoke target is not private Serve for the Juno backend")
    return f"https://{parsed.hostname}:{port}"


def _wait_for_ready(token_path: Path, timeout_seconds: int = 20, *, base_url: str = LOCAL_BASE_URL) -> str:
    deadline = time.monotonic() + timeout_seconds
    last_error = "service did not become ready"
    token = _read_token_for_smoke(token_path)
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                base_url + "/healthz", timeout=2
            ) as response:
                _read_json_response(response, label="health endpoint")
            request = urllib.request.Request(
                base_url + "/v1/models",
                headers={"Authorization": "Bearer " + token},
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                payload = _read_json_response(response, label="models endpoint")
            data = payload.get("data")
            if not isinstance(data, list) or MODEL_ID not in [
                entry.get("id") for entry in data if isinstance(entry, dict)
            ]:
                raise RuntimeError("model endpoint did not expose the expected model")
            return token
        except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
    raise RuntimeError(f"gateway readiness smoke failed: {last_error}")


def _completion_smoke(token: str, timeout_seconds: int = 130, *, base_url: str = LOCAL_BASE_URL) -> None:
    body = json.dumps(
        {
            "model": MODEL_ID,
            "messages": [
                {
                    "role": "user",
                    "content": f"Reply with exactly: {INSTALL_SMOKE_REPLY}",
                }
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        base_url + "/v1/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = _read_json_response(response, label="completion endpoint")
    except urllib.error.HTTPError as exc:
        code = "unknown"
        try:
            body = json.loads(exc.read(4096).decode("utf-8"))
            candidate = body["error"]["code"]
            if candidate in KNOWN_GATEWAY_FAILURE_CODES:
                code = candidate
        except (ValueError, KeyError, TypeError, UnicodeError):
            pass
        raise RuntimeError(
            f"gateway completion smoke failed: HTTP {exc.code}, code={code}"
        ) from exc
    except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
        raise RuntimeError(
            f"gateway completion smoke failed: {type(exc).__name__}: {exc}"
        ) from exc
    try:
        text = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("completion smoke response shape is invalid") from exc
    if text != INSTALL_SMOKE_REPLY:
        raise RuntimeError("completion smoke returned unexpected assistant content")


def _wait_for_smoke(token_path: Path, *, base_url: str = LOCAL_BASE_URL) -> None:
    token = _wait_for_ready(token_path, base_url=base_url)
    _completion_smoke(token, base_url=base_url)


def _rollback_install(
    *,
    artifacts: list[tuple[Path, tuple[bytes, int] | None, str]],
    service_state: dict[str, bool],
    timer_state: dict[str, bool],
    restore_service_state: bool,
) -> None:
    errors: list[str] = []
    if restore_service_state:
        for name in (SERVICE_NAME, PROBE_TIMER_NAME):
            for action in ("stop", "disable"):
                try:
                    result = _systemctl_probe(action, name)
                except BaseException as exc:
                    errors.append(f"{action} {name}: {type(exc).__name__}: {exc}")
                else:
                    if result.returncode not in {0, 1, 5}:
                        errors.append(f"{action} {name}: exit {result.returncode}")
    for destination, snapshot, label in reversed(artifacts):
        try:
            _restore_file(destination, snapshot, label=label)
        except BaseException as exc:
            errors.append(f"restore {label}: {type(exc).__name__}: {exc}")
    try:
        _systemctl("daemon-reload")
    except BaseException as exc:
        errors.append(f"daemon-reload: {type(exc).__name__}: {exc}")
    if restore_service_state:
        for name, old_state, exists in (
            (SERVICE_NAME, service_state, any(
                destination == UNIT_PATH and snapshot is not None
                for destination, snapshot, _ in artifacts
            )),
            (PROBE_TIMER_NAME, timer_state, any(
                destination == PROBE_TIMER_PATH and snapshot is not None
                for destination, snapshot, _ in artifacts
            )),
        ):
            if not exists:
                continue
            try:
                if old_state["enabled"]:
                    _systemctl("enable", name)
                else:
                    result = _systemctl_probe("disable", name)
                    if result.returncode not in {0, 1, 5}:
                        raise RuntimeError(f"disable exited {result.returncode}")
                if old_state["active"]:
                    _systemctl("restart", name)
                else:
                    result = _systemctl_probe("stop", name)
                    if result.returncode not in {0, 1, 5}:
                        raise RuntimeError(f"stop exited {result.returncode}")
            except BaseException as exc:
                errors.append(f"restore service state {name}: {type(exc).__name__}: {exc}")
    if errors:
        raise RuntimeError("installer rollback failed: " + "; ".join(errors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the controlled Juno OpenAI-compatible gateway"
    )
    parser.add_argument(
        "--smoke-only", action="store_true",
        help="test existing live service including a real authenticated Codex reply without installation",
    )
    parser.add_argument(
        "--smoke-https-origin", metavar="URL",
        help="optional private Tailscale Serve HTTPS origin, verified against live Serve status",
    )
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="install files but do not enable, start, or restart the service",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.smoke_https_origin and not args.smoke_only:
        raise RuntimeError("--smoke-https-origin requires --smoke-only")
    if args.smoke_only:
        if args.no_start:
            raise RuntimeError("--smoke-only cannot be combined with --no-start")
        base_url = (
            _verified_https_smoke_url(args.smoke_https_origin)
            if args.smoke_https_origin else LOCAL_BASE_URL
        )
        _wait_for_smoke(TOKEN_PATH, base_url=base_url)
        print(json.dumps({
            "status": "passed", "model": MODEL_ID,
            "base_url": base_url, "completion_smoke": True,
            "tailscale_serve_changed": False,
        }, sort_keys=True, separators=(",", ":")))
        return 0
    artifacts = [
        (GATEWAY_EXEC_PATH, _snapshot_file(
            GATEWAY_EXEC_PATH, label="existing gateway executable"
        ), "gateway executable"),
        (LAUNCHER_EXEC_PATH, _snapshot_file(
            LAUNCHER_EXEC_PATH, label="existing runtime launcher"
        ), "runtime launcher"),
        (UNIT_PATH, _snapshot_file(
            UNIT_PATH, label="existing systemd unit"
        ), "systemd unit"),
        (PROBE_SERVICE_PATH, _snapshot_file(
            PROBE_SERVICE_PATH, label="existing probe service"
        ), "probe service"),
        (PROBE_TIMER_PATH, _snapshot_file(
            PROBE_TIMER_PATH, label="existing probe timer"
        ), "probe timer"),
    ]
    previous_service_state = _service_state()
    previous_timer_state = _probe_timer_state()
    token_created = False
    hashes: dict[str, str] = {}
    service_mutation_started = False
    try:
        token_created = _ensure_token(TOKEN_PATH)
        hashes["gateway_sha256"] = _install_file(
            GATEWAY_SOURCE_PATH, GATEWAY_EXEC_PATH, mode=0o700
        )
        hashes["launcher_sha256"] = _install_file(
            LAUNCHER_SOURCE_PATH, LAUNCHER_EXEC_PATH, mode=0o700
        )
        hashes["unit_sha256"] = _install_unit(TEMPLATE_PATH, UNIT_PATH)
        hashes["probe_service_sha256"] = _install_unit(
            PROBE_SERVICE_TEMPLATE_PATH, PROBE_SERVICE_PATH
        )
        hashes["probe_timer_sha256"] = _install_unit(
            PROBE_TIMER_TEMPLATE_PATH, PROBE_TIMER_PATH
        )
        _systemctl("daemon-reload")
        state = "installed"
        if not args.no_start:
            service_mutation_started = True
            # A stale catalog must not block an otherwise valid initial install.
            _systemctl("start", PROBE_SERVICE_NAME)
            _systemctl("enable", "--now", PROBE_TIMER_NAME)
            _systemctl("enable", SERVICE_NAME)
            _systemctl("restart", SERVICE_NAME)
            _wait_for_smoke(TOKEN_PATH)
            state = _systemctl("is-active", SERVICE_NAME).stdout.strip()
            if state != "active":
                raise RuntimeError(f"gateway service is not active: {state}")
    except BaseException as install_error:
        try:
            _rollback_install(
                artifacts=artifacts,
                service_state=previous_service_state,
                timer_state=previous_timer_state,
                restore_service_state=service_mutation_started,
            )
        except BaseException as rollback_error:
            raise RuntimeError(
                f"gateway installation failed and rollback also failed: {rollback_error}"
            ) from install_error
        raise
    print(
        json.dumps(
            {
                "service": SERVICE_NAME,
                "state": state,
                "token_created": token_created,
                "gateway_path": str(GATEWAY_EXEC_PATH),
                "launcher_path": str(LAUNCHER_EXEC_PATH),
                "local_base_url": LOCAL_BASE_URL,
                "model": MODEL_ID,
                "completion_smoke": not args.no_start,
                "tailscale_serve_changed": False,
                **hashes,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())