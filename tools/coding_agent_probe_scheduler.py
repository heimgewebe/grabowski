#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterator


DEFAULT_ROUTER = Path.home() / "bin" / "agent-route"
DEFAULT_STATE = (
    Path.home()
    / ".local"
    / "state"
    / "grabowski"
    / "coding-agent-router"
    / "state.json"
)
DEFAULT_STATE_DIR = DEFAULT_STATE.parent
DEFAULT_ROUTER_DIGEST = (
    Path.home() / ".config" / "grabowski" / "coding-agent-probe-scheduler-router.sha256"
)
DEFAULT_LOCK = DEFAULT_STATE_DIR / "probe-scheduler.lock"
DEFAULT_RECEIPT = DEFAULT_STATE_DIR / "probe-scheduler-receipt.json"
DEFAULT_FAILURE = DEFAULT_STATE_DIR / "probe-scheduler-failure.json"
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_ROUTER_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024
FORBIDDEN_API_KEY_ENV = (
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "AZURE_OPENAI_API_KEY",
)


class ProbeSchedulerError(RuntimeError):
    pass


class LockBusy(ProbeSchedulerError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def value_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def read_json(path: Path, *, required: bool = True) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if required:
            raise ProbeSchedulerError(f"missing JSON file: {path}") from None
        return {}, b""
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open JSON file: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError(f"JSON path is not a regular file: {path}")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError(f"JSON file has an unexpected owner: {path}")
        if before.st_size < 0 or before.st_size > MAX_STATE_BYTES:
            raise ProbeSchedulerError(f"JSON file exceeds the size limit: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ProbeSchedulerError(f"JSON file ended early: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProbeSchedulerError(f"JSON file grew while being read: {path}")
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
        raise ProbeSchedulerError(f"JSON file changed while being read: {path}")
    payload = b"".join(chunks)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeSchedulerError(f"invalid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ProbeSchedulerError(f"JSON root is not an object: {path}")
    return value, payload


def read_expected_router_sha256(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise ProbeSchedulerError(f"router digest pin is missing: {path}") from None
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open router digest pin: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError("router digest pin must be a regular file")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError("router digest pin has an unexpected owner")
        if before.st_mode & 0o077:
            raise ProbeSchedulerError("router digest pin must be private")
        if before.st_size < 64 or before.st_size > 128:
            raise ProbeSchedulerError("router digest pin has an invalid size")
        payload = os.read(descriptor, before.st_size + 1)
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
    if len(payload) != before.st_size or identity_before != identity_after:
        raise ProbeSchedulerError("router digest pin changed while being read")
    try:
        digest = payload.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ProbeSchedulerError("router digest pin is not ASCII") from exc
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ProbeSchedulerError("router digest pin is invalid")
    return digest


def atomic_write_private(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def safe_unlink(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ProbeSchedulerError(f"refusing to remove unsafe path: {path}")
    path.unlink()


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ProbeSchedulerError("probe scheduler lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LockBusy("probe scheduler is already running") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextmanager
def validated_router(
    path: Path, expected_sha256: str
) -> Iterator[tuple[str, str, int]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise ProbeSchedulerError(f"router executable is missing: {path}") from None
    except OSError as exc:
        raise ProbeSchedulerError(f"cannot open router executable: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ProbeSchedulerError("router executable must be a regular file")
        if before.st_uid != os.getuid():
            raise ProbeSchedulerError("router executable has an unexpected owner")
        if before.st_mode & 0o022:
            raise ProbeSchedulerError("router executable is group- or world-writable")
        if before.st_mode & 0o111 == 0:
            raise ProbeSchedulerError("router executable is not executable")
        if before.st_size < 1 or before.st_size > MAX_ROUTER_BYTES:
            raise ProbeSchedulerError("router executable exceeds the size limit")
        payload = os.read(descriptor, before.st_size + 1)
        if len(payload) != before.st_size:
            raise ProbeSchedulerError("router executable changed while being read")
        after = os.fstat(descriptor)
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
            raise ProbeSchedulerError("router executable changed while being read")
        actual_sha256 = bytes_sha256(payload)
        if actual_sha256 != expected_sha256:
            raise ProbeSchedulerError("router executable does not match its digest pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield f"/proc/self/fd/{descriptor}", actual_sha256, descriptor
    finally:
        os.close(descriptor)


def sanitized_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in FORBIDDEN_API_KEY_ENV:
        environment.pop(name, None)
    environment["GRABOWSKI_PROBE_SCHEDULER"] = "1"
    environment["NO_COLOR"] = "1"
    return environment


def run_json_command(
    argv: list[str],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            timeout=timeout_seconds,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeSchedulerError(f"command failed to execute: {argv[-1]}") from exc
    if (
        len(completed.stdout) > MAX_COMMAND_OUTPUT_BYTES
        or len(completed.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise ProbeSchedulerError(f"command output exceeded the limit: {argv[-1]}")
    if completed.returncode != 0:
        raise ProbeSchedulerError(
            f"command returned nonzero status for {argv[-1]} "
            f"(exit {completed.returncode})"
        )
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeSchedulerError(f"command did not return JSON: {argv[-1]}") from exc
    if not isinstance(value, dict):
        raise ProbeSchedulerError(f"command JSON root is not an object: {argv[-1]}")
    return value


def validate_probe(probe: dict[str, Any]) -> None:
    if probe.get("schema_version") != 2:
        raise ProbeSchedulerError("probe schema_version is invalid")
    observed_at = parse_time(probe.get("observed_at"))
    if observed_at is None:
        raise ProbeSchedulerError("probe observed_at is invalid")
    age_seconds = (utc_now() - observed_at).total_seconds()
    if not -300 <= age_seconds <= 300:
        raise ProbeSchedulerError("probe observed_at is outside the bounded window")
    digest = probe.get("catalog_probe_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ProbeSchedulerError("probe digest is invalid")
    digest_input = dict(probe)
    digest_input.pop("catalog_probe_sha256", None)
    if digest != value_sha256(digest_input):
        raise ProbeSchedulerError("probe digest does not match its payload")
    if not isinstance(probe.get("providers"), dict):
        raise ProbeSchedulerError("probe providers are missing")


def validate_state_after_probe(
    before: dict[str, Any],
    after: dict[str, Any],
    probe: dict[str, Any],
) -> None:
    if after.get("schema_version") != 2:
        raise ProbeSchedulerError("router state schema_version is invalid")
    if after.get("catalog") != probe:
        raise ProbeSchedulerError("router state is not bound to the probe output")
    if after.get("history", {}) != before.get("history", {}):
        raise ProbeSchedulerError("probe changed router history")
    if after.get("routes", {}) != before.get("routes", {}):
        raise ProbeSchedulerError("probe changed route outcome history")
    if not isinstance(after.get("routes", {}), dict):
        raise ProbeSchedulerError("router route history is invalid")
    if not isinstance(after.get("pools", {}), dict):
        raise ProbeSchedulerError("router pool state is invalid")


def validate_status(status_value: dict[str, Any]) -> None:
    if status_value.get("schema_version") != 2:
        raise ProbeSchedulerError("router status schema_version is invalid")
    if status_value.get("catalog_fresh") is not True:
        raise ProbeSchedulerError("router status does not confirm a fresh catalog")
    if status_value.get("automatic_execution_authorized") is not False:
        raise ProbeSchedulerError("router status unexpectedly authorizes execution")


def bounded_failure(exc: BaseException) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "coding-agent-probe-scheduler-failure",
        "status": "failed",
        "failed_at": iso_now(),
        "error_type": type(exc).__name__,
        "error": "probe_scheduler_failed_closed",
        "automatic_execution_authorized": False,
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Refresh the advisory coding-agent catalog without model execution."
    )
    result.add_argument("--router", type=Path, default=DEFAULT_ROUTER)
    result.add_argument(
        "--router-sha256-file", type=Path, default=DEFAULT_ROUTER_DIGEST
    )
    result.add_argument("--state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    result.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    result.add_argument("--failure", type=Path, default=DEFAULT_FAILURE)
    result.add_argument("--timeout-seconds", type=int, default=120)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.timeout_seconds < 1 or arguments.timeout_seconds > 300:
        print("timeout-seconds must be between 1 and 300", file=sys.stderr)
        return 2
    try:
        expected_router_sha256 = read_expected_router_sha256(
            arguments.router_sha256_file
        )
        with (
            exclusive_lock(arguments.lock),
            validated_router(arguments.router, expected_router_sha256) as router,
        ):
            router_invocation, router_sha256, router_descriptor = router
            before, before_bytes = read_json(arguments.state, required=False)
            environment = sanitized_environment()
            probe = run_json_command(
                [router_invocation, "probe"],
                environment=environment,
                timeout_seconds=arguments.timeout_seconds,
                pass_fds=(router_descriptor,),
            )
            validate_probe(probe)
            after, after_bytes = read_json(arguments.state)
            validate_state_after_probe(before, after, probe)
            status_value = run_json_command(
                [router_invocation, "status"],
                environment=environment,
                timeout_seconds=arguments.timeout_seconds,
                pass_fds=(router_descriptor,),
            )
            validate_status(status_value)
            receipt = {
                "schema_version": 1,
                "kind": "coding-agent-probe-scheduler-receipt",
                "status": "ok",
                "completed_at": iso_now(),
                "router": str(arguments.router),
                "router_sha256": router_sha256,
                "router_sha256_pin": str(arguments.router_sha256_file),
                "state": str(arguments.state),
                "state_sha256_before": bytes_sha256(before_bytes),
                "state_sha256_after": bytes_sha256(after_bytes),
                "history_sha256": value_sha256(after.get("history", {})),
                "catalog_probe_sha256": probe["catalog_probe_sha256"],
                "observed_at": probe["observed_at"],
                "status_readback": {
                    "catalog_fresh": True,
                    "automatic_execution_authorized": False,
                },
                "invocation_policy": "metadata-only",
                "model_invocations": 0,
                "paid_api_requests_authorized": 0,
                "api_key_environment_removed": list(FORBIDDEN_API_KEY_ENV),
                "does_not_establish": [
                    "provider quota remaining beyond observed metadata",
                    "future route availability",
                    "execution authority",
                ],
            }
            atomic_write_private(arguments.receipt, receipt)
            safe_unlink(arguments.failure)
            print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
            return 0
    except LockBusy:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "coding-agent-probe-scheduler-receipt",
                    "status": "skipped-lock-busy",
                    "automatic_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:
        failure = bounded_failure(exc)
        try:
            atomic_write_private(arguments.failure, failure)
        except Exception:
            pass
        print(
            json.dumps(failure, sort_keys=True, separators=(",", ":")), file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
