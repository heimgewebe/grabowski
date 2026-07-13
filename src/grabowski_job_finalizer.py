from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
from typing import Any

import grabowski_job_origin as job_origin
import grabowski_private_io as private_io

MAX_METADATA_BYTES = 256 * 1024
NOTIFICATION_NAME = "notification.json"
JOBS_ROOT = Path.home() / ".local" / "state" / "grabowski" / "jobs"
UNIT_RE = re.compile(r"grabowski-job-([0-9a-f]{12})")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ORIGIN_BINDING = "systemd_unit_environment_sha256_precondition"
TRUST_BOUNDARY = "same_uid_authorized_job"
FINALIZER_NOFILE_SOFT_LIMIT = 65_536
FINALIZER_ENV_KEYS = frozenset({
    "SERVICE_RESULT",
    "EXIT_CODE",
    "EXIT_STATUS",
    "GRABOWSKI_JOB_DIRECTORY",
    "GRABOWSKI_JOB_ORIGIN_SHA256",
    "GRABOWSKI_JOB_INVOKER_TOOL",
})


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
    created = private_io.publish_private_create_only_json(
        directory,
        target,
        payload,
        max_bytes=MAX_METADATA_BYTES,
        label="job notification receipt",
    )
    if created:
        return True, payload
    existing = _read_private_json(target, max_bytes=MAX_METADATA_BYTES)
    if existing != payload:
        raise RuntimeError("existing job notification receipt conflicts")
    return False, existing


def _legacy_identity(metadata: dict[str, Any], directory: Path) -> dict[str, Any]:
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
    notify = metadata.get("notify_on_done")
    if not isinstance(notify, dict):
        notify = {"requested": False, "channels": []}
    return {
        "unit": unit,
        "job_id": job_id,
        "owner": metadata.get("owner"),
        "scope": metadata.get("scope"),
        "argv_sha256": argv_sha256,
        "notify_on_done": notify,
        "origin_sha256": None,
        "invoker_tool": None,
        "legacy": True,
    }


def _origin_identity(
    metadata: dict[str, Any],
    directory: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    raw_origin = metadata.get("origin")
    stored_hash = metadata.get("origin_sha256")
    expected_hash = environment.get("GRABOWSKI_JOB_ORIGIN_SHA256", "")
    expected_invoker = environment.get("GRABOWSKI_JOB_INVOKER_TOOL", "")
    origin_material_present = raw_origin is not None or stored_hash is not None
    launcher_precondition_present = bool(expected_hash or expected_invoker)
    if not origin_material_present and not launcher_precondition_present:
        return _legacy_identity(metadata, directory)
    if not origin_material_present or not expected_hash or not expected_invoker:
        raise RuntimeError("job origin contract is incomplete")
    try:
        origin = job_origin.validate_origin(
            raw_origin,
            stored_hash,
            expected_unit=directory.name,
            expected_invoker_tool=expected_invoker,
            expected_origin_sha256=expected_hash,
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc

    for key in ("unit", "job_id", "owner", "argv_sha256", "scope"):
        if metadata.get(key) != origin.get(key):
            raise RuntimeError(f"job metadata {key} changed after launcher binding")
    try:
        top_level_notify = job_origin.notification_request(metadata.get("notify_on_done", {}))
    except ValueError as exc:
        raise RuntimeError("job notification request changed after launcher binding") from exc
    if top_level_notify != origin.get("notify_on_done"):
        raise RuntimeError("job notification request changed after launcher binding")
    return {
        **origin,
        "origin_sha256": stored_hash,
        "legacy": False,
    }


def _harden_process() -> None:
    """Apply limits to the finalizer process without changing job semantics."""
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = (
        FINALIZER_NOFILE_SOFT_LIMIT
        if hard == resource.RLIM_INFINITY
        else min(FINALIZER_NOFILE_SOFT_LIMIT, hard)
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))


def _filtered_environment(environment: dict[str, str] | None) -> dict[str, str]:
    source = os.environ if environment is None else environment
    return {key: str(source.get(key, "")) for key in FINALIZER_ENV_KEYS}


def finalize(directory: Path, environment: dict[str, str] | None = None) -> dict[str, Any]:
    env = _filtered_environment(environment)
    directory = _validate_job_directory(directory)
    metadata = _read_metadata(directory)
    identity = _origin_identity(metadata, directory, env)
    notify = identity["notify_on_done"]
    if not isinstance(notify, dict) or notify.get("requested") is not True:
        return {"created": False, "reason": "notification_not_requested"}

    terminal_status = _terminal_status(env)
    notification_seed = (
        f"{identity['unit']}:{identity['argv_sha256']}:"
        f"{identity.get('origin_sha256') or 'legacy'}"
    )
    payload: dict[str, Any] = {
        "schema_version": 1 if identity["legacy"] else 2,
        "kind": "grabowski_job_notification",
        "notification_id": hashlib.sha256(notification_seed.encode("utf-8")).hexdigest()[:32],
        "job_id": identity["job_id"],
        "unit": identity["unit"],
        "owner": identity.get("owner"),
        "scope": identity.get("scope"),
        "argv_sha256": identity["argv_sha256"],
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
            "untrusted_same_uid_job_authenticity",
        ],
    }
    if not identity["legacy"]:
        payload.update({
            "origin_sha256": identity["origin_sha256"],
            "invoker_tool": identity["invoker_tool"],
            "origin_binding": ORIGIN_BINDING,
            "trust_boundary": TRUST_BOUNDARY,
        })
    payload["receipt_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    created, receipt = _publish_create_only_json(
        directory, directory / NOTIFICATION_NAME, payload
    )
    return {
        "created": created,
        "reason": "queued" if created else "already_exists",
        "receipt": receipt,
    }


def _log_failure(stage: str, error: str) -> None:
    print(
        json.dumps(
            {
                "kind": "grabowski_job_notification_finalizer_error",
                "stage": stage,
                "error": error[:500],
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )


def main() -> int:
    env = _filtered_environment(None)
    raw = env.get("GRABOWSKI_JOB_DIRECTORY", "")
    if not raw:
        _log_failure("environment", "GRABOWSKI_JOB_DIRECTORY is required")
        return 2
    try:
        _harden_process()
    except (OSError, ValueError) as exc:
        _log_failure("process_hardening", str(exc))
        return 1
    try:
        result = finalize(Path(raw).expanduser(), env)
    except Exception as exc:
        _log_failure("finalization", str(exc))
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
