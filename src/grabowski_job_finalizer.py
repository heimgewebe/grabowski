from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any

MAX_METADATA_BYTES = 256 * 1024
NOTIFICATION_NAME = "notification.json"
JOBS_ROOT = Path.home() / ".local" / "state" / "grabowski" / "jobs"
UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_private_json(path: Path, *, max_bytes: int) -> dict[str, Any]:
    descriptor: int | None = None
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        linked = path.lstat()
        mode = stat.S_IMODE(opened.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or _identity(opened) != _identity(linked)
            or opened.st_nlink != 1
            or mode not in {0o400, 0o600}
            or opened.st_size > max_bytes
        ):
            raise RuntimeError("job metadata/receipt is not one private regular file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise RuntimeError("job metadata/receipt is too large")
        after = os.fstat(descriptor)
        rebound = path.lstat()
        if _identity(opened) != _identity(after) or _identity(opened) != _identity(rebound):
            raise RuntimeError("job metadata/receipt changed while reading")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("job metadata/receipt is invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("job metadata/receipt must be an object")
    return value


def _validate_job_directory(directory: Path) -> Path:
    root = Path(os.path.abspath(os.fspath(JOBS_ROOT.expanduser())))
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise RuntimeError("Grabowski jobs root is unavailable") from exc
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) & 0o077
    ):
        raise RuntimeError("Grabowski jobs root is not a private directory")

    raw = Path(os.path.abspath(os.fspath(directory.expanduser())))
    if raw.parent != root or not UNIT_RE.fullmatch(raw.name):
        raise RuntimeError("job directory is outside the Grabowski jobs root")
    try:
        metadata = raw.lstat()
    except OSError as exc:
        raise RuntimeError("job directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("job directory is not a private non-symlink directory")
    resolved = raw.resolve(strict=True)
    if resolved != raw:
        raise RuntimeError("job directory changed identity during validation")
    return raw


def _read_metadata(directory: Path) -> dict[str, Any]:
    return _read_private_json(directory / "metadata.json", max_bytes=MAX_METADATA_BYTES)


def _terminal_status(environment: dict[str, str]) -> str:
    service_result = environment.get("SERVICE_RESULT", "")
    exit_status = environment.get("EXIT_STATUS", "")
    if service_result == "success" and exit_status in {"", "0"}:
        return "succeeded"
    if service_result == "timeout":
        return "timed_out"
    if service_result in {"signal", "core-dump", "watchdog"}:
        return "signalled"
    if service_result:
        return "failed"
    return "terminated_unclear"


def _publish_create_only_json(
    directory: Path,
    target: Path,
    payload: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    temporary = directory / (
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    published = False
    temporary_identity: tuple[int, ...] | None = None
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_metadata = temporary.lstat()
        temporary_identity = _identity(temporary_metadata)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink != 1
        ):
            raise RuntimeError("temporary notification receipt is unsafe")
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing = _read_private_json(target, max_bytes=MAX_METADATA_BYTES)
            if existing != payload:
                raise RuntimeError("existing job notification receipt conflicts")
            return False, existing
        published = True
        try:
            temporary.unlink()
        except OSError:
            try:
                current = target.lstat()
                if _identity(current)[:2] == temporary_identity[:2]:
                    target.unlink()
                    published = False
            finally:
                raise
        target_metadata = target.lstat()
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or stat.S_IMODE(target_metadata.st_mode) != 0o600
            or target_metadata.st_nlink != 1
            or _identity(target_metadata)[:2] != temporary_identity[:2]
        ):
            try:
                current = target.lstat()
                if _identity(current)[:2] == temporary_identity[:2]:
                    target.unlink()
                    published = False
            except FileNotFoundError:
                published = False
            raise RuntimeError("published notification receipt failed integrity validation")
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return True, payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if published and temporary_identity is not None:
            try:
                current = target.lstat()
            except FileNotFoundError as exc:
                raise RuntimeError("published notification receipt disappeared") from exc
            if current.st_nlink != 1:
                if _identity(current)[:2] == temporary_identity[:2]:
                    target.unlink()
                raise RuntimeError(
                    "published notification receipt lost single-link integrity"
                )


def finalize(directory: Path, environment: dict[str, str] | None = None) -> dict[str, Any]:
    env = dict(os.environ if environment is None else environment)
    directory = _validate_job_directory(directory)
    metadata = _read_metadata(directory)
    notify = metadata.get("notify_on_done")
    if not isinstance(notify, dict) or notify.get("requested") is not True:
        return {"created": False, "reason": "notification_not_requested"}

    unit = metadata.get("unit")
    job_id = metadata.get("job_id")
    argv_sha256 = metadata.get("argv_sha256")
    unit_match = UNIT_RE.fullmatch(unit) if isinstance(unit, str) else None
    if (
        unit_match is None
        or unit != directory.name
        or not isinstance(job_id, str)
        or unit_match.group(1) != job_id
    ):
        raise RuntimeError("job unit binding is invalid")
    if not isinstance(argv_sha256, str) or SHA256_RE.fullmatch(argv_sha256) is None:
        raise RuntimeError("job argv hash is invalid")

    terminal_status = _terminal_status(env)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_job_notification",
        "notification_id": hashlib.sha256(
            f"{unit}:{argv_sha256}".encode("utf-8")
        ).hexdigest()[:32],
        "job_id": job_id,
        "unit": unit,
        "owner": metadata.get("owner"),
        "scope": metadata.get("scope"),
        "argv_sha256": argv_sha256,
        "terminal_status": terminal_status,
        "terminalization": {
            "service_result": env.get("SERVICE_RESULT", ""),
            "exit_code": env.get("EXIT_CODE", ""),
            "exit_status": env.get("EXIT_STATUS", ""),
        },
        "requested_channels": notify.get("channels", []),
        "note": notify.get("note"),
        "delivery_mode": "operator_outbox",
        "delivery_state": "queued",
        "does_not_establish": [
            "external_push_delivery",
            "user_has_seen_notification",
            "job_success_beyond_terminalization_evidence",
        ],
    }
    payload["receipt_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    created, receipt = _publish_create_only_json(
        directory, directory / NOTIFICATION_NAME, payload
    )
    return {
        "created": created,
        "reason": "queued" if created else "already_exists",
        "receipt": receipt,
    }


def main() -> int:
    raw = os.environ.get("GRABOWSKI_JOB_DIRECTORY", "")
    if not raw:
        print("GRABOWSKI_JOB_DIRECTORY is required", file=sys.stderr)
        return 2
    try:
        result = finalize(Path(raw).expanduser())
    except Exception as exc:
        print(f"job notification finalizer failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
