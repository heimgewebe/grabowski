from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
from typing import Annotated, Any, Iterator

from mcp.types import ToolAnnotations
from pydantic import Field

import grabowski_mcp as base
import grabowski_operator_core as operator
import grabowski_read_surface as read_surface


mcp = operator.mcp

DEPLOY_MUTATING = ToolAnnotations(
    title="Schedule verified Grabowski runtime deployment",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
ExpectedHead = Annotated[
    str,
    Field(
        min_length=40,
        max_length=64,
        pattern=OBJECT_ID_RE.pattern,
    ),
]
DelaySeconds = Annotated[int, Field(ge=5, le=60)]
SourceRepository = Annotated[str, Field(min_length=1, max_length=4096)]
SourceLeaseOwner = Annotated[str, Field(min_length=1, max_length=128, pattern=r"[A-Za-z0-9._:@-]{1,128}")]
SOURCE_KINDS = frozenset({"canonical-main", "detached-worktree"})
CANONICAL_REPOSITORY = Path.home() / "repos/grabowski"
RUNNER_RELATIVE_PATH = Path("tools/run_scheduled_deploy.py")
DEPLOY_SCHEDULE_LOCK = Path.home() / ".local/state/grabowski/runtime-deploy-schedule.lock"
DEPLOY_JOB_PREFIX = operator.JOB_PREFIX
DEPLOY_JOB_ROOT = operator.JOBS_DIR
DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS = 10.0
DEPLOY_SCHEDULE_LOCK_POLL_SECONDS = 0.05
MAX_JOB_SCAN_ENTRIES = 2_000
MAX_DEPLOY_INDEX_ENTRIES = 512
DEPLOY_INDEX_FILENAME = "runtime-deploy-index.json"
REUSABLE_JOB_STATUSES = frozenset({"running"})
TERMINAL_JOB_STATUSES = frozenset({"completed", "succeeded", "failed", "launch_failed"})


def _git_result(repository: Path, *arguments: str) -> dict[str, Any]:
    return read_surface._run_read(
        read_surface._git_command(repository, *arguments),
        cwd=repository,
        timeout_seconds=30,
        max_output_bytes=65_536,
    )


def _required_stdout(result: dict[str, Any], label: str) -> str:
    if result["returncode"] != 0 or result["timed_out"]:
        message = result["stderr"].strip() or result["stdout"].strip()
        raise RuntimeError(message or f"{label} failed")
    if result["stdout_truncated"] or result["stderr_truncated"]:
        raise RuntimeError(f"{label} output exceeded the preflight bound")
    return result["stdout"].strip()


def _deploy_command(
    repository: Path,
    runner: Path,
    expected_head: str,
    delay_seconds: int,
    *,
    canonical_repository: Path | None = None,
    source_kind: str = "canonical-main",
    source_identity_sha256: str = "0" * 64,
) -> list[str]:
    canonical = canonical_repository or CANONICAL_REPOSITORY
    return [
        "/usr/bin/python3",
        str(runner),
        "--repo",
        str(repository),
        "--canonical-repo",
        str(canonical),
        "--source-kind",
        source_kind,
        "--source-identity-sha256",
        source_identity_sha256,
        "--expected-head",
        expected_head,
        "--delay-seconds",
        str(delay_seconds),
    ]


def _deploy_command_sha256(command: list[str]) -> str:
    return operator._argv_hash(command)


def _deploy_command_fields(command: Any) -> dict[str, str] | None:
    if (
        not isinstance(command, list)
        or len(command) != 14
        or not all(isinstance(item, str) for item in command)
        or command[0] != "/usr/bin/python3"
    ):
        return None
    values: dict[str, str] = {}
    allowed = {
        "--repo",
        "--canonical-repo",
        "--source-kind",
        "--source-identity-sha256",
        "--expected-head",
        "--delay-seconds",
    }
    for index in range(2, len(command), 2):
        option = command[index]
        if option not in allowed or option in values:
            return None
        values[option] = command[index + 1]
    if (
        set(values) != allowed
        or not OBJECT_ID_RE.fullmatch(values["--expected-head"])
        or values["--source-kind"] not in SOURCE_KINDS
        or re.fullmatch(r"[0-9a-f]{64}", values["--source-identity-sha256"]) is None
    ):
        return None
    for name in ("--repo", "--canonical-repo"):
        if not Path(values[name]).is_absolute():
            return None
    try:
        delay_seconds = int(values["--delay-seconds"])
    except ValueError:
        return None
    if not 5 <= delay_seconds <= 60:
        return None
    return {
        "python": command[0],
        "runner": command[1],
        "repository": values["--repo"],
        "canonical_repository": values["--canonical-repo"],
        "source_kind": values["--source-kind"],
        "source_identity_sha256": values["--source-identity-sha256"],
        "expected_head": values["--expected-head"],
        "delay_seconds": str(delay_seconds),
    }


def _deploy_identity(command: Any) -> tuple[str, ...] | None:
    fields = _deploy_command_fields(command)
    if fields is None:
        return None
    return (
        fields["python"],
        fields["runner"],
        fields["repository"],
        fields["canonical_repository"],
        fields["source_kind"],
        fields["source_identity_sha256"],
        fields["expected_head"],
    )


@contextmanager
def _deploy_schedule_lock() -> Iterator[None]:
    parent = DEPLOY_SCHEDULE_LOCK.parent
    if parent.is_symlink():
        raise PermissionError(f"runtime deploy lock directory may not be a symlink: {parent}")
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if DEPLOY_SCHEDULE_LOCK.is_symlink():
        raise PermissionError(f"runtime deploy lock may not be a symlink: {DEPLOY_SCHEDULE_LOCK}")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(DEPLOY_SCHEDULE_LOCK, flags, 0o600)
    locked = False
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.getuid():
            raise PermissionError("runtime deploy lock must be one owner-controlled regular file")
        deadline = time.monotonic() + DEPLOY_SCHEDULE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("runtime deploy schedule lock acquisition timed out") from exc
                time.sleep(DEPLOY_SCHEDULE_LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _durable_job_unit(name: str) -> bool:
    return re.fullmatch(rf"{re.escape(DEPLOY_JOB_PREFIX)}[0-9a-f]{{12}}", name) is not None


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("short write while publishing runtime deploy index")
        offset += written


def _deploy_index_path(jobs_root: Path) -> Path:
    return jobs_root / DEPLOY_INDEX_FILENAME


def _private_jobs_root(jobs_root: Path) -> Path:
    if jobs_root.is_symlink():
        raise RuntimeError("runtime deploy index directory may not be a symlink")
    try:
        metadata = jobs_root.stat()
    except FileNotFoundError as exc:
        raise RuntimeError("runtime deploy index directory is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("runtime deploy index directory must be private and owner-controlled")
    return jobs_root.resolve(strict=True)


def _validate_index_unit(value: Any) -> str:
    if not isinstance(value, str) or not _durable_job_unit(value):
        raise RuntimeError("runtime deploy index contains an invalid unit")
    return value


def _read_index_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 128 * 1024
        ):
            raise RuntimeError("runtime deploy index must be one private owner-controlled regular file")
        data = bytearray()
        while len(data) <= 128 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 128 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 128 * 1024:
            raise RuntimeError("runtime deploy index exceeds its size bound")
        return bytes(data)
    finally:
        os.close(descriptor)


def _read_deploy_index(jobs_root: Path) -> dict[str, Any] | None:
    root = _private_jobs_root(jobs_root)
    path = _deploy_index_path(root)
    if path.is_symlink():
        raise RuntimeError("runtime deploy index may not be a symlink")
    if not path.exists():
        return None
    try:
        payload = json.loads(_read_index_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("runtime deploy index is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "units", "pending_unit", "updated_at_unix"
    }:
        raise RuntimeError("runtime deploy index shape is invalid")
    if payload.get("schema_version") != 1:
        raise RuntimeError("runtime deploy index schema is unsupported")
    units_raw = payload.get("units")
    if not isinstance(units_raw, list) or len(units_raw) > MAX_DEPLOY_INDEX_ENTRIES:
        raise RuntimeError("runtime deploy index entry count is invalid")
    units = [_validate_index_unit(item) for item in units_raw]
    if len(units) != len(set(units)):
        raise RuntimeError("runtime deploy index contains duplicate units")
    pending = payload.get("pending_unit")
    if pending is not None:
        pending = _validate_index_unit(pending)
    updated = payload.get("updated_at_unix")
    if isinstance(updated, bool) or not isinstance(updated, int) or updated < 0:
        raise RuntimeError("runtime deploy index timestamp is invalid")
    return {
        "schema_version": 1,
        "units": sorted(units),
        "pending_unit": pending,
        "updated_at_unix": updated,
    }


def _write_deploy_index(
    jobs_root: Path,
    *,
    units: list[str],
    pending_unit: str | None,
) -> dict[str, Any]:
    normalized = sorted({_validate_index_unit(item) for item in units})
    if len(normalized) > MAX_DEPLOY_INDEX_ENTRIES:
        raise RuntimeError("runtime deploy index exceeds its bounded entry count")
    pending = None if pending_unit is None else _validate_index_unit(pending_unit)
    payload = {
        "schema_version": 1,
        "units": normalized,
        "pending_unit": pending,
        "updated_at_unix": int(time.time()),
    }
    root = _private_jobs_root(jobs_root)
    path = _deploy_index_path(root)
    if path.is_symlink():
        raise RuntimeError("runtime deploy index may not be a symlink")
    if path.exists():
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise RuntimeError("runtime deploy index must be one private owner-controlled regular file")
    temporary = root / f".{path.name}.{uuid.uuid4().hex}.tmp"
    data = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    return payload


def _bootstrap_deploy_index(jobs_root: Path, repository: Path) -> dict[str, Any]:
    expected_runner = str(repository / RUNNER_RELATIVE_PATH)
    entries = sorted(
        (entry for entry in jobs_root.iterdir() if _durable_job_unit(entry.name)),
        key=lambda path: path.name,
    )
    if len(entries) > MAX_JOB_SCAN_ENTRIES:
        raise RuntimeError("job registry exceeds the bounded runtime deploy index bootstrap scan")
    units: list[str] = []
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir():
            raise RuntimeError(f"durable job entry is not a real directory: {entry.name}")
        try:
            metadata = operator._read_job_metadata(entry.name)
        except (OSError, ValueError, PermissionError) as exc:
            raise RuntimeError(f"durable job metadata is unreadable: {entry.name}") from exc
        candidate_command = metadata.get("argv")
        if not isinstance(candidate_command, list) or not all(isinstance(item, str) for item in candidate_command):
            raise RuntimeError(f"durable job argv is malformed: {entry.name}")
        if (
            len(candidate_command) >= 2
            and candidate_command[0] == "/usr/bin/python3"
            and candidate_command[1] == expected_runner
            and metadata.get("final_status") not in TERMINAL_JOB_STATUSES
        ):
            units.append(entry.name)
    return _write_deploy_index(jobs_root, units=units, pending_unit=None)


def _deploy_index(jobs_root: Path, repository: Path) -> dict[str, Any]:
    index = _read_deploy_index(jobs_root)
    if index is None:
        index = _bootstrap_deploy_index(jobs_root, repository)
    pending = index["pending_unit"]
    if pending is not None:
        pending_entry = jobs_root / pending
        if pending_entry.is_symlink():
            raise RuntimeError("pending runtime deploy job path is a symlink")
        if pending_entry.exists():
            if not pending_entry.is_dir():
                raise RuntimeError("pending runtime deploy job path is not a directory")
            units = sorted(set(index["units"]) | {pending})
        else:
            units = list(index["units"])
        index = _write_deploy_index(jobs_root, units=units, pending_unit=None)
    return index


def _validated_deploy_job_receipt(entry: Path, metadata: dict[str, Any]) -> dict[str, str]:
    expected_receipt = metadata.get("expected_receipt")
    if not isinstance(expected_receipt, dict):
        raise RuntimeError(f"deploy job receipt is unavailable: {entry.name}")
    expected = {
        "unit": entry.name,
        "metadata_path": str(entry / "metadata.json"),
        "stdout_path": str(entry / "stdout.log"),
        "stderr_path": str(entry / "stderr.log"),
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
    }
    for key, value in expected.items():
        if expected_receipt.get(key) != value:
            raise RuntimeError(f"deploy job receipt {key} is not bound to {entry.name}")
    return {
        "metadata_path": expected["metadata_path"],
        "stdout_path": expected["stdout_path"],
        "stderr_path": expected["stderr_path"],
    }


def _matching_inflight_deploy_job(command: list[str], repository: Path) -> dict[str, Any] | None:
    expected_identity = _deploy_identity(command)
    if expected_identity is None:
        raise ValueError("runtime deploy command identity is invalid")
    expected_runner = str(repository / RUNNER_RELATIVE_PATH)
    jobs_root = operator._jobs_root()
    index = _deploy_index(jobs_root, repository)
    entries = [jobs_root / unit for unit in index["units"]]

    matches: list[dict[str, Any]] = []
    retained_units: list[str] = []
    for entry in reversed(entries):
        if entry.is_symlink() or not entry.is_dir():
            raise RuntimeError(f"durable job entry is not a real directory: {entry.name}")
        try:
            metadata = operator._read_job_metadata(entry.name)
        except (OSError, ValueError, PermissionError) as exc:
            raise RuntimeError(f"durable job metadata is unreadable: {entry.name}") from exc
        candidate_command = metadata.get("argv")
        if not isinstance(candidate_command, list) or not all(
            isinstance(item, str) for item in candidate_command
        ):
            raise RuntimeError(f"durable job argv is malformed: {entry.name}")
        references_self_deploy = (
            len(candidate_command) >= 2
            and candidate_command[0] == "/usr/bin/python3"
            and candidate_command[1] == expected_runner
        )
        if not references_self_deploy:
            continue
        candidate_fields = _deploy_command_fields(candidate_command)
        candidate_identity = _deploy_identity(candidate_command)
        if candidate_fields is None or candidate_identity is None or metadata.get("cwd") != str(repository):
            raise RuntimeError(f"self deploy job metadata is malformed: {entry.name}")
        argv_sha256 = metadata.get("argv_sha256")
        if argv_sha256 != _deploy_command_sha256(candidate_command):
            raise RuntimeError(f"self deploy job command hash mismatch: {entry.name}")
        status = operator.grabowski_job_status(entry.name)
        if not isinstance(status, dict):
            raise RuntimeError(f"self deploy job status is unavailable: {entry.name}")
        final_status = status.get("final_status")
        if final_status in TERMINAL_JOB_STATUSES:
            continue
        retained_units.append(entry.name)
        if final_status not in REUSABLE_JOB_STATUSES:
            raise RuntimeError(
                f"self deploy job has an uncertain non-reusable outcome: {entry.name} ({final_status})"
            )
        if candidate_identity != expected_identity:
            raise RuntimeError(
                f"another Grabowski self deploy is already running for a different head: {entry.name}"
            )
        receipt_paths = _validated_deploy_job_receipt(entry, metadata)
        matches.append(
            {
                "unit": entry.name,
                "argv_sha256": argv_sha256,
                "delay_seconds": int(candidate_fields["delay_seconds"]),
                **receipt_paths,
                "final_status": final_status,
            }
        )

    _write_deploy_index(jobs_root, units=retained_units, pending_unit=None)
    if len(matches) > 1:
        units = ", ".join(sorted(item["unit"] for item in matches))
        raise RuntimeError(f"multiple identical Grabowski self deploy jobs are running: {units}")
    return matches[0] if matches else None


def _schedule_result(
    *,
    expected_head: str,
    requested_delay_seconds: int,
    effective_delay_seconds: int,
    job: dict[str, Any],
    intent: dict[str, Any] | None,
    scheduled: dict[str, Any],
    already_scheduled: bool,
    source_identity: dict[str, Any],
) -> dict[str, Any]:
    return {
        "scheduled": True,
        "already_scheduled": already_scheduled,
        "expected_head": expected_head,
        "requested_delay_seconds": requested_delay_seconds,
        "delay_seconds": effective_delay_seconds,
        "source_identity": source_identity,
        "source_identity_sha256": source_identity["identity_sha256"],
        "unit": job["unit"],
        "argv_sha256": job["argv_sha256"],
        "metadata_path": job["metadata_path"],
        "stdout_path": job["stdout_path"],
        "stderr_path": job["stderr_path"],
        "expected_connector_disconnect": True,
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
        "audit": {
            "intent": intent,
            "scheduled": scheduled,
        },
    }


def _validated_repository_path(raw: Path, *, label: str) -> Path:
    if not raw.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if raw.is_symlink() or not raw.is_dir():
        raise RuntimeError(f"{label} is unavailable: {raw}")
    resolved = raw.resolve(strict=True)
    if resolved != raw:
        raise RuntimeError(f"{label} must not traverse a symlink or relative segment")
    return resolved


def _git_common_directory(repository: Path) -> Path:
    raw = _required_stdout(
        _git_result(repository, "rev-parse", "--git-common-dir"),
        "git common directory lookup",
    )
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repository / candidate
    if candidate.is_symlink():
        raise RuntimeError("git common directory may not be a symlink")
    resolved = candidate.resolve(strict=True)
    if resolved != candidate or not resolved.is_dir():
        raise RuntimeError("git common directory must be an exact real directory")
    return resolved


def _resource_inspect(resource_key: str) -> dict[str, Any]:
    import grabowski_resources

    return grabowski_resources.grabowski_resource_inspect(resource_key)


def _source_lease_evidence(
    repository: Path,
    expected_owner: str | None,
) -> dict[str, Any]:
    resource_key = f"path:{repository}"
    payload = _resource_inspect(resource_key)
    if not isinstance(payload, dict) or payload.get("resource_key") != resource_key:
        raise RuntimeError("source repository lease readback is malformed")
    lease = payload.get("lease")
    if lease is None:
        if expected_owner is not None:
            raise RuntimeError("expected source repository lease is absent")
        return {"resource_key": resource_key, "lease": None}
    if not isinstance(lease, dict):
        raise RuntimeError("source repository lease readback is malformed")
    owner = lease.get("owner_id")
    if expected_owner is None:
        raise RuntimeError(f"source repository has an active lease: {owner}")
    if owner != expected_owner:
        raise RuntimeError(
            f"source repository lease owner drift: expected {expected_owner}, found {owner}"
        )
    required = (
        "resource_key",
        "owner_id",
        "acquired_at_unix",
        "updated_at_unix",
        "expires_at_unix",
        "metadata_sha256",
    )
    snapshot = {name: lease.get(name) for name in required}
    if snapshot["resource_key"] != resource_key or any(
        snapshot[name] is None for name in required
    ):
        raise RuntimeError("source repository lease snapshot is incomplete")
    return {"resource_key": resource_key, "lease": snapshot}


def _source_identity_sha256(identity: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _deployment_source_preflight(
    expected_head: str,
    source_repository: str | None,
    source_lease_owner_id: str | None,
) -> tuple[Path, Path, dict[str, Any]]:
    if not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if source_lease_owner_id is not None and re.fullmatch(
        r"[A-Za-z0-9._:@-]{1,128}", source_lease_owner_id
    ) is None:
        raise ValueError("source_lease_owner_id is invalid")

    canonical = _validated_repository_path(
        CANONICAL_REPOSITORY,
        label="canonical repository",
    )
    if source_repository is None:
        repository = canonical
    else:
        repository = _validated_repository_path(
            Path(source_repository).expanduser(),
            label="source repository",
        )

    canonical_common = _git_common_directory(canonical)
    source_common = (
        canonical_common
        if repository == canonical
        else _git_common_directory(repository)
    )
    if source_common != canonical_common:
        raise RuntimeError("source repository does not share the canonical Git common directory")

    head = _required_stdout(
        _git_result(repository, "rev-parse", "--verify", "HEAD"),
        "HEAD lookup",
    )
    branch = _required_stdout(
        _git_result(repository, "rev-parse", "--abbrev-ref", "HEAD"),
        "branch lookup",
    )
    origin_main = _required_stdout(
        _git_result(
            repository,
            "rev-parse",
            "--verify",
            "refs/remotes/origin/main",
        ),
        "origin/main lookup",
    )
    status = _required_stdout(
        _git_result(
            repository,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        ),
        "working-tree status",
    )

    source_kind = "canonical-main" if repository == canonical else "detached-worktree"
    expected_branch = "main" if source_kind == "canonical-main" else "HEAD"
    if head != expected_head:
        raise RuntimeError(f"HEAD drift: expected {expected_head}, found {head}")
    if branch != expected_branch:
        raise RuntimeError(
            f"{source_kind} source has invalid branch state: expected {expected_branch}, found {branch}"
        )
    if origin_main != expected_head:
        raise RuntimeError(
            f"origin/main drift: expected {expected_head}, found {origin_main}"
        )
    if status:
        raise RuntimeError("source repository is dirty")

    runner = repository / RUNNER_RELATIVE_PATH
    if runner.is_symlink() or not runner.is_file():
        raise RuntimeError(f"scheduled deployment runner is unavailable: {runner}")
    if source_kind == "detached-worktree" and source_lease_owner_id is None:
        raise ValueError(
            "detached deployment source requires source_lease_owner_id"
        )
    lease_evidence = _source_lease_evidence(repository, source_lease_owner_id)
    identity = {
        "schema_version": 1,
        "kind": "grabowski_runtime_deploy_source_identity",
        "source_kind": source_kind,
        "repository": str(repository),
        "canonical_repository": str(canonical),
        "git_common_directory": str(source_common),
        "head": head,
        "origin_main": origin_main,
        "clean": True,
        "lease_evidence": lease_evidence,
    }
    return repository, runner, {
        **identity,
        "identity_sha256": _source_identity_sha256(identity),
    }


def _canonical_preflight(expected_head: str) -> tuple[Path, Path]:
    repository, runner, _identity = _deployment_source_preflight(
        expected_head,
        None,
        None,
    )
    return repository, runner


@mcp.tool(name="grabowski_runtime_deploy_schedule", annotations=DEPLOY_MUTATING)
def grabowski_runtime_deploy_schedule(
    expected_head: ExpectedHead,
    delay_seconds: DelaySeconds = 8,
    source_repository: SourceRepository | None = None,
    source_lease_owner_id: SourceLeaseOwner | None = None,
) -> dict[str, Any]:
    """Schedule one source-identity-bound self-deployment, reusing an identical in-flight job."""
    operator._require_operator_mutation("durable_job")
    operator._require_operator_capability("git_cli")
    with _deploy_schedule_lock():
        repository, runner, source_identity = _deployment_source_preflight(
            expected_head,
            source_repository,
            source_lease_owner_id,
        )
        canonical_repository = Path(source_identity["canonical_repository"])
        command = _deploy_command(
            repository,
            runner,
            expected_head,
            delay_seconds,
            canonical_repository=canonical_repository,
            source_kind=source_identity["source_kind"],
            source_identity_sha256=source_identity["identity_sha256"],
        )
        existing = _matching_inflight_deploy_job(command, repository)
        if existing is not None:
            observed = {
                "timestamp_unix": int(time.time()),
                "operation": "runtime-deploy-existing-schedule-observed",
                "expected_head": expected_head,
                "requested_delay_seconds": delay_seconds,
                "delay_seconds": existing["delay_seconds"],
                "unit": existing["unit"],
                "argv_sha256": existing["argv_sha256"],
                "final_status": existing["final_status"],
                "source_identity_sha256": source_identity["identity_sha256"],
            }
            base._append_audit(observed)
            return _schedule_result(
                expected_head=expected_head,
                requested_delay_seconds=delay_seconds,
                effective_delay_seconds=existing["delay_seconds"],
                job=existing,
                intent=None,
                scheduled=observed,
                already_scheduled=True,
                source_identity=source_identity,
            )

        intent = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-schedule-intent",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
            "source_identity": source_identity,
            "source_identity_sha256": source_identity["identity_sha256"],
        }
        base._append_audit(intent)
        jobs_root = operator._jobs_root()
        index = _deploy_index(jobs_root, repository)
        reserved_unit = DEPLOY_JOB_PREFIX + uuid.uuid4().hex[:12]
        _write_deploy_index(
            jobs_root,
            units=index["units"],
            pending_unit=reserved_unit,
        )
        job = operator._start_job(
            command,
            cwd=str(repository),
            runtime_seconds=3_600,
            finalization_expected_head=expected_head,
            reserved_unit=reserved_unit,
            allow_reserved_runtime_deploy=True,
        )
        _write_deploy_index(
            jobs_root,
            units=[*index["units"], reserved_unit],
            pending_unit=None,
        )
        scheduled = {
            "timestamp_unix": int(time.time()),
            "operation": "runtime-deploy-scheduled",
            "expected_head": expected_head,
            "delay_seconds": delay_seconds,
            "unit": job["unit"],
            "argv_sha256": job["argv_sha256"],
            "source_identity_sha256": source_identity["identity_sha256"],
        }
        base._append_audit(scheduled)
        return _schedule_result(
            expected_head=expected_head,
            requested_delay_seconds=delay_seconds,
            effective_delay_seconds=delay_seconds,
            job=job,
            intent=intent,
            scheduled=scheduled,
            already_scheduled=False,
            source_identity=source_identity,
        )
