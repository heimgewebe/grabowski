#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable


CONFIG_TARGET = Path("/etc/grabowski/privileged-actions.json")
RUNTIME_CONTRACT_SCHEMA_TARGET = Path("/etc/grabowski/runtime-contract-schema.py")
BLOCKADES_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockades.py")
BLOCKADE_STORE_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockade_store.py")
BLOCKADE_AUTHORITY_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockade_authority.py")
COMMAND_IDENTITY_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_command_identity.py")
BROKER_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_privileged_broker.py")
BROKER_WRAPPER_TARGET = Path("/usr/local/libexec/grabowski-privileged-broker")
PROCESS_OBSERVER_TARGET = Path("/usr/local/libexec/grabowski-process-reference-observer")
REQUEST_CLIENT_TARGET = Path("/usr/local/bin/grabowski-privileged-request")
BOOTSTRAP_RECOVERY_TARGET = Path(
    "/usr/local/libexec/grabowski-runtime-bootstrap-recover"
)
BACKUP_MOUNT_RECONCILE_TARGET = Path(
    "/usr/local/libexec/grabowski-backup-mount-reconcile"
)
CUTOVER_HELPER_TARGET = Path("/usr/local/libexec/grabowski-rootbroker-cutover")
AUTOMATIC_STAGING_ROOT = Path("/var/lib/grabowski/rootbroker-cutover-staging")
AUTOMATIC_HELPER_SOURCE = "tools/grabowski_rootbroker_cutover.py"
BROKER_SERVICE_TARGET = Path("/etc/systemd/system/grabowski-privileged-broker@.service")
OPERATOR_SERVICE_TARGET = Path("/etc/systemd/system/grabowski-operator.service")
RECOVERY_SOURCE_DROPIN_TARGET = Path(
    "/etc/systemd/system/grabowski-privileged-broker@.service.d/recovery-source.conf"
)
BACKUP_ROOT = Path("/var/lib/grabowski/rootbroker-cutover-backups")
RECEIPT_ROOT = Path("/var/lib/grabowski/rootbroker-cutover-receipts")
OPERATOR_AUTHORITY_ATTESTATION_TARGET = Path(
    "/var/lib/grabowski/operator-authority-attestation.v1.json"
)
CUTOVER_LOCK = Path("/run/grabowski/rootbroker-cutover.lock")
SOCKET_UNIT = "grabowski-privileged-broker.socket"
OPERATOR_UNIT = "grabowski-operator.service"
LEGACY_OPERATOR_WATCHDOG_TIMER = "grabowski-operator-watchdog.timer"
CONFIGURED_TARGET = "local-backup-disk:UUID=249180DA265E8DE0/restic/heim-pc"
LEGACY_CONFIGURED_TARGET = "heimberry:rest-server/grabowski-recovery-probe"
CANONICAL_REPOSITORY = Path("/home/alex/repos/grabowski")
CANONICAL_ORIGIN_URL = "git@github.com:heimgewebe/grabowski.git"
CANONICAL_REMOTE_READ_URL = "https://github.com/heimgewebe/grabowski.git"
CANONICAL_KILL_SWITCH = Path("/var/lib/grabowski/operator-blockade") / "operator-kill-switch"
LEGACY_KILL_SWITCH = Path("/home/alex/.local/state/grabowski") / "operator-kill-switch"
PUBLISH_ACTION = "publish_recovery_marker"
POWER_ACTION = "operator_power_argv"
OPERATOR_SERVICE_CONTROL_ACTION = "operator_system_service_control"
ROOTBROKER_CUTOVER_ACTION = "operator_rootbroker_cutover"
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOT_TASK_ACTION = "operator_root_task_systemd_unit"
PROCESS_OBSERVER_ACTION = "observe_process_references"
BOOTSTRAP_RECOVERY_ACTION = "runtime_bootstrap_recover"
LOCAL_BACKUP_NTFS_CHECK_ACTION = "local_backup_ntfs_check"
LOCAL_BACKUP_NTFS_CLEAR_DIRTY_ACTION = "local_backup_ntfs_clear_dirty"
LOCAL_BACKUP_SMART_READ_ACTION = "local_backup_smart_read"
LOCAL_BACKUP_MOUNT_RECONCILE_ACTION = "local_backup_mount_reconcile"
LOCAL_BACKUP_NTFS_DEVICE = "/dev/disk/by-uuid/249180DA265E8DE0"
LOCAL_BACKUP_SMART_DEVICE = "/dev/disk/by-id/usb-Freecom_Freecom_Mobile_Drive_XXS_3.0_93300000078D-0:0"
LOCAL_BACKUP_STORAGE_ACTIONS = (
    LOCAL_BACKUP_NTFS_CHECK_ACTION,
    LOCAL_BACKUP_NTFS_CLEAR_DIRTY_ACTION,
    LOCAL_BACKUP_SMART_READ_ACTION,
    LOCAL_BACKUP_MOUNT_RECONCILE_ACTION,
)
AUTOMATIC_CUTOVER_BIND_PATHS = (
    "/home/alex/repos/grabowski",
)
PROCESS_OBSERVER_BIND_PATHS = (
    "/home/alex/repos/.weltgewebe-audit-implementation",
    "/home/alex/repos/.weltgewebe-audit-main-20260717",
    "/home/alex/repos/.weltgewebe-release-worktrees",
    "/home/alex/repos/.weltgewebe-standalone",
    "/home/alex/repos/.weltgewebe-worktrees",
    "/home/alex/worktrees",
    "/home/alex/repos/.semantah-standalone",
    "/home/alex/repos/.semantah-worktrees",
    "/home/alex/repos/.heimlern-worktrees",
    "/home/alex/repos/.operator-redundancy-worktrees",
    "/home/alex/repos/.audio-standalone",
    "/home/alex/repos/.audio-worktrees",
    "/home/alex/repos/.hauski-worktrees",
    "/home/alex/repos/.hauski-audio-worktrees",
    "/home/alex/repos/.grabowski-deploy-worktrees",
    "/home/alex/repos/.grabowski-standalone",
    "/home/alex/repos/.grabowski-worktrees",
    "/home/alex/repos/.heim-pc-standalone",
    "/home/alex/repos/.heim-pc-worktrees",
    "/home/alex/repos/.bureau-audit-clones",
    "/home/alex/repos/.bureau-audits",
    "/home/alex/repos/.bureau-standalone",
    "/home/alex/repos/.bureau-task-worktrees",
    "/home/alex/repos/.bureau-worktrees",
    "/home/alex/repos/.repoground-audits",
    "/home/alex/repos/.repoground-standalone",
    "/home/alex/repos/.repoground-task-worktrees",
    "/home/alex/repos/.repoground-worktrees",
    "/home/alex/repos/.commonworld-audits",
    "/home/alex/repos/.commonworld-standalone",
    "/home/alex/repos/.commonworld-worktrees",
    "/home/alex/repos/.plexer-worktrees",
    "/home/alex/repos/.worktree-target-quarantine",
)


class CutoverError(RuntimeError):
    pass


def _termination_requested(signum: int, _frame: object) -> None:
    raise CutoverError(f"termination signal received: {signum}")


@dataclass(frozen=True)
class Artifact:
    source_relative: str
    target: Path
    mode: int
    python_source: bool = False


ARTIFACTS = (
    Artifact(
        "src/grabowski_runtime_contract.py",
        RUNTIME_CONTRACT_SCHEMA_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "src/grabowski_blockades.py",
        BLOCKADES_MODULE_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "src/grabowski_blockade_store.py",
        BLOCKADE_STORE_MODULE_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "src/grabowski_blockade_authority.py",
        BLOCKADE_AUTHORITY_MODULE_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "src/grabowski_command_identity.py",
        COMMAND_IDENTITY_MODULE_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "src/grabowski_privileged_broker.py",
        BROKER_MODULE_TARGET,
        0o644,
        True,
    ),
    Artifact(
        "tools/grabowski_privileged_broker.py",
        BROKER_WRAPPER_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "tools/grabowski_process_reference_observer.py",
        PROCESS_OBSERVER_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "tools/grabowski_privileged_request.py",
        REQUEST_CLIENT_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "tools/grabowski_runtime_bootstrap_recover.py",
        BOOTSTRAP_RECOVERY_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "tools/grabowski_backup_mount_reconcile.py",
        BACKUP_MOUNT_RECONCILE_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "tools/grabowski_rootbroker_cutover.py",
        CUTOVER_HELPER_TARGET,
        0o755,
        True,
    ),
    Artifact(
        "systemd/grabowski-privileged-broker@.service",
        BROKER_SERVICE_TARGET,
        0o644,
    ),
    Artifact(
        "systemd/grabowski-operator.service.example",
        OPERATOR_SERVICE_TARGET,
        0o644,
    ),
    Artifact(
        "systemd/grabowski-privileged-broker@.service.d/recovery-source.conf",
        RECOVERY_SOURCE_DROPIN_TARGET,
        0o644,
    ),
)


@dataclass
class Preimage:
    target: Path
    existed: bool
    data: bytes | None
    mode: int | None
    uid: int | None
    gid: int | None
    sha256: str | None


RunCommand = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _validate_directory(
    path: Path,
    *,
    expected_uid: int,
    label: str,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CutoverError(f"cannot inspect {label}: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise CutoverError(f"{label} is not a safe directory: {path}")
    if metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
        raise CutoverError(f"{label} owner or mode is unsafe: {path}")
    return metadata


def _ensure_private_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    parent = path.parent
    _validate_directory(parent, expected_uid=expected_uid, label="directory parent")
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    metadata = _validate_directory(
        path,
        expected_uid=expected_uid,
        label="private directory",
    )
    if metadata.st_gid != expected_gid:
        os.chown(path, expected_uid, expected_gid)
    os.chmod(path, 0o700)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def _exclusive_cutover_lock(
    path: Path,
    *,
    expected_uid: int,
):
    parent = path.parent
    _validate_directory(parent, expected_uid=expected_uid, label="lock parent")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CutoverError("cannot safely open the cutover lock") from exc
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise CutoverError("cutover lock must be one regular single-link file")
        if metadata.st_uid != expected_uid:
            raise CutoverError("cutover lock owner is invalid")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CutoverError("another Rootbroker cutover is already running") from exc
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular_file(
    path: Path,
    *,
    require_root_owned: bool = False,
    max_bytes: int = 1024 * 1024,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CutoverError(f"cannot safely open {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CutoverError(f"not a regular file: {path}")
        if before.st_nlink != 1:
            raise CutoverError(f"multiple hard links are forbidden: {path}")
        if before.st_mode & 0o022:
            raise CutoverError(f"group/world writable file is forbidden: {path}")
        if require_root_owned and before.st_uid != 0:
            raise CutoverError(f"root ownership required: {path}")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise CutoverError(f"invalid file size: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
    )
    if len(data) != before.st_size or identity_before != identity_after:
        raise CutoverError(f"file changed while being read: {path}")
    return data, before


def _decode_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CutoverError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        raise CutoverError(f"JSON object required: {label}")
    return value


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
        timeout=120,
    )


def _checked_run(runner: RunCommand, argv: list[str]) -> subprocess.CompletedProcess[str]:
    completed = runner(argv)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "command failed").strip()
        raise CutoverError(f"{' '.join(argv)}: {detail[:500]}")
    return completed


def _validate_commit_id(value: str, *, label: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise CutoverError(f"{label} is not a SHA-1 commit id")
    return value


def _git_argv(repository: Path, *arguments: str) -> list[str]:
    return [
        "/usr/bin/git",
        "--no-replace-objects",
        "-c",
        f"safe.directory={repository}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.pager=cat",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.file.allow=never",
        "-C",
        str(repository),
        *arguments,
    ]


def _repository_head(repository: Path, runner: RunCommand) -> str:
    completed = _checked_run(
        runner,
        _git_argv(repository, "rev-parse", "HEAD"),
    )
    return _validate_commit_id(completed.stdout.strip(), label="repository HEAD")


_BLOCKADE_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,255}\Z")
_BLOCKADE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,127}\Z")
_GLOBAL_HARD_STOP_TRIGGER_CLASSES = {
    "audit_integrity_invalid",
    "audit_provenance_unknown",
    "deployment_provenance_invalid",
    "broker_identity_invalid",
    "recovery_identity_invalid",
    "external_environment_stop",
    "host_wide_damage_unknown",
    "legacy_operator_marker",
    "global_trust_unknown",
}


def _blockade_text(
    value: Any,
    *,
    label: str,
    max_chars: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CutoverError(f"canonical operator kill-switch {label} is invalid")
    if len(value) > max_chars or (pattern is not None and pattern.fullmatch(value) is None):
        raise CutoverError(f"canonical operator kill-switch {label} is invalid")
    return value


def _blockade_timestamp(value: Any, *, label: str) -> datetime:
    text = _blockade_text(value, label=label, max_chars=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CutoverError(
            f"canonical operator kill-switch {label} is not ISO-8601"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CutoverError(
            f"canonical operator kill-switch {label} lacks timezone"
        )
    return parsed.astimezone(timezone.utc)


def _blockade_absolute_path(value: Any, *, label: str) -> str:
    text = _blockade_text(value, label=label, max_chars=4096)
    path = PurePosixPath(text)
    if (
        not path.is_absolute()
        or any(part in {".", ".."} for part in text.split("/"))
        or str(path) != text
    ):
        raise CutoverError(f"canonical operator kill-switch {label} is invalid")
    return text


def _strict_blockade_json(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CutoverError("canonical operator kill-switch is not UTF-8") from exc

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise CutoverError("canonical operator kill-switch has duplicate JSON keys")
            result[key] = item
        return result

    try:
        value = json.loads(text, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise CutoverError("canonical operator kill-switch is not valid JSON") from exc
    if not isinstance(value, dict):
        raise CutoverError("canonical operator kill-switch must contain one JSON object")
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if data != canonical:
        raise CutoverError("canonical operator kill-switch is not canonical JSON")
    return value


def _automatic_typed_blockade_scope(value: Any) -> tuple[str, str, bool]:
    if not isinstance(value, dict):
        raise CutoverError("canonical operator kill-switch must be a JSON object")
    required = {
        "schema_version",
        "blockade_id",
        "posture",
        "scope",
        "reason",
        "trigger_class",
        "engaged_at",
        "evidence_refs",
        "provenance",
        "source",
        "disarm_policy",
    }
    if set(value) - required - {"expires_at"} or not required.issubset(value):
        raise CutoverError("canonical operator kill-switch keys are invalid")
    schema_version = value.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
    ):
        raise CutoverError("canonical operator kill-switch schema is unsupported")
    if value.get("source") != "typed" or value.get("disarm_policy") != "in_band":
        raise CutoverError("canonical operator kill-switch is not typed in-band authority")
    posture = value.get("posture")
    if posture not in {"observe", "preflight_required", "mutation_freeze", "hard_stop"}:
        raise CutoverError("canonical operator kill-switch posture is invalid")
    _blockade_text(
        value.get("blockade_id"),
        label="blockade_id",
        max_chars=128,
        pattern=_BLOCKADE_ID_RE,
    )
    _blockade_text(value.get("reason"), label="reason", max_chars=1000)
    trigger_class = _blockade_text(
        value.get("trigger_class"),
        label="trigger_class",
        max_chars=256,
        pattern=_BLOCKADE_IDENTIFIER_RE,
    )
    engaged_text = value.get("engaged_at")
    engaged_at = _blockade_timestamp(engaged_text, label="engaged_at")
    if engaged_text != engaged_at.isoformat().replace("+00:00", "Z"):
        raise CutoverError("canonical operator kill-switch engaged_at is not canonical")
    evidence_refs = value.get("evidence_refs")
    if (
        not isinstance(evidence_refs, list)
        or not 1 <= len(evidence_refs) <= 64
        or len(evidence_refs) != len(set(evidence_refs))
        or evidence_refs != sorted(evidence_refs)
    ):
        raise CutoverError("canonical operator kill-switch evidence_refs are invalid")
    for ref in evidence_refs:
        _blockade_text(ref, label="evidence_ref", max_chars=1000)
    provenance = value.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "tool",
        "request_id",
        "session_id",
        "task_id",
        "owner_id",
    }:
        raise CutoverError("canonical operator kill-switch provenance is invalid")
    for item in provenance.values():
        _blockade_text(item, label="provenance", max_chars=256)
    expires_at: datetime | None = None
    if "expires_at" in value:
        expires_text = value["expires_at"]
        expires_at = _blockade_timestamp(expires_text, label="expires_at")
        if expires_text != expires_at.isoformat().replace("+00:00", "Z"):
            raise CutoverError("canonical operator kill-switch expires_at is not canonical")
        if expires_at <= engaged_at or posture in {"mutation_freeze", "hard_stop"}:
            raise CutoverError("canonical operator kill-switch expiry contract is invalid")
    scope = value.get("scope")
    if not isinstance(scope, dict) or set(scope) != {"kind", "value"}:
        raise CutoverError("canonical operator kill-switch scope is invalid")
    kind = scope.get("kind")
    if kind not in {
        "path",
        "capability",
        "task",
        "owner",
        "repo",
        "service",
        "host",
        "global",
    }:
        raise CutoverError("canonical operator kill-switch scope is invalid")
    if kind == "global":
        if scope.get("value") != "*":
            raise CutoverError("canonical global operator kill-switch scope is invalid")
        scope_value = "*"
    elif kind in {"path", "repo"}:
        scope_value = _blockade_absolute_path(
            scope.get("value"), label=f"{kind} scope"
        )
    else:
        scope_value = _blockade_text(
            scope.get("value"),
            label=f"{kind} scope",
            max_chars=256,
            pattern=_BLOCKADE_IDENTIFIER_RE,
        )
    if (
        posture == "hard_stop"
        and kind == "global"
        and trigger_class not in _GLOBAL_HARD_STOP_TRIGGER_CLASSES
    ):
        raise CutoverError("canonical global hard-stop trigger class is invalid")
    active = expires_at is None or datetime.now(timezone.utc) < expires_at
    return kind, scope_value, active


def _path_scope_matches(base: str, candidate: Path) -> bool:
    base_path = Path(base)
    return candidate == base_path or base_path in candidate.parents


def _path_scope_overlaps_tree(base: str, root: Path) -> bool:
    base_path = Path(base)
    return (
        base_path == root
        or base_path in root.parents
        or root in base_path.parents
    )


def _automatic_blockade_matches_cutover(value: Any) -> bool:
    kind, scope_value, active = _automatic_typed_blockade_scope(value)
    if not active:
        return False
    if kind == "global":
        return True
    if kind in {"task", "owner"}:
        # Automatic Rootbroker authority refresh is not a Bureau task/owner
        # mutation.  These scopes remain enforced by the caller-side policy,
        # but an unrelated task/owner marker must not become host-global here.
        return False
    if kind == "capability":
        return scope_value in {
            "durable_job",
            "git_cli",
            "privileged_reference",
            ROOTBROKER_CUTOVER_ACTION,
        }
    if kind == "repo":
        return _path_scope_matches(scope_value, CANONICAL_REPOSITORY)
    if kind == "service":
        return scope_value in {
            OPERATOR_UNIT,
            SOCKET_UNIT,
            LEGACY_OPERATOR_WATCHDOG_TIMER,
            "grabowski-privileged-broker@.service",
        }
    if kind == "host":
        return scope_value == os.uname().nodename
    if kind == "path":
        fixed_cutover_paths = (
            CONFIG_TARGET,
            RUNTIME_CONTRACT_SCHEMA_TARGET,
            BLOCKADES_MODULE_TARGET,
            BLOCKADE_STORE_MODULE_TARGET,
            BLOCKADE_AUTHORITY_MODULE_TARGET,
            COMMAND_IDENTITY_MODULE_TARGET,
            BROKER_MODULE_TARGET,
            BROKER_WRAPPER_TARGET,
            PROCESS_OBSERVER_TARGET,
            REQUEST_CLIENT_TARGET,
            BOOTSTRAP_RECOVERY_TARGET,
            CUTOVER_HELPER_TARGET,
            BROKER_SERVICE_TARGET,
            OPERATOR_SERVICE_TARGET,
            RECOVERY_SOURCE_DROPIN_TARGET,
            OPERATOR_AUTHORITY_ATTESTATION_TARGET,
            CUTOVER_LOCK,
        )
        dynamic_cutover_roots = (
            AUTOMATIC_STAGING_ROOT,
            BACKUP_ROOT,
            RECEIPT_ROOT,
        )
        return (
            any(_path_scope_matches(scope_value, path) for path in fixed_cutover_paths)
            or any(
                _path_scope_overlaps_tree(scope_value, path)
                for path in dynamic_cutover_roots
            )
        )
    raise CutoverError("canonical operator kill-switch scope is unsupported")


def _automatic_kill_switch_clear() -> None:
    # This root-side gate independently revalidates the canonical marker on
    # every critical phase.  It evaluates the marker against the concrete
    # Rootbroker cutover footprint instead of promoting every scoped marker to
    # a host-global stop.  Unknown, legacy, malformed or in-scope authority
    # still fails closed.
    if os.path.lexists(LEGACY_KILL_SWITCH):
        raise CutoverError("automatic Rootbroker cutover blocked by legacy operator kill-switch")
    if not os.path.lexists(CANONICAL_KILL_SWITCH):
        return
    try:
        _validate_directory(
            CANONICAL_KILL_SWITCH.parent,
            expected_uid=0,
            label="canonical blockade parent",
        )
        data, metadata = _read_regular_file(
            CANONICAL_KILL_SWITCH,
            require_root_owned=True,
            max_bytes=64 * 1024,
        )
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise CutoverError("canonical operator kill-switch mode is invalid")
        value = _strict_blockade_json(data)
        matches_cutover = _automatic_blockade_matches_cutover(value)
    except Exception as exc:
        raise CutoverError(
            "automatic Rootbroker cutover blocked by unsafe canonical operator kill-switch"
        ) from exc
    if matches_cutover and value.get("posture") != "observe":
        raise CutoverError(
            "automatic Rootbroker cutover blocked by in-scope operator kill-switch"
        )


def _authoritative_remote_main_head(runner: RunCommand) -> str:
    argv = [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--service-type=exec",
        "--property=DynamicUser=yes",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectControlGroups=yes",
        "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=RuntimeMaxSec=60s",
        "--property=TimeoutStopSec=5s",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=WorkingDirectory=/",
        "--setenv=HOME=/nonexistent",
        "--setenv=GIT_CONFIG_NOSYSTEM=1",
        "--setenv=GIT_CONFIG_GLOBAL=/dev/null",
        "--setenv=GIT_TERMINAL_PROMPT=0",
        "--setenv=GCM_INTERACTIVE=never",
        "--setenv=LANG=C.UTF-8",
        "--setenv=LC_ALL=C.UTF-8",
        "--",
        "/usr/bin/git",
        "-c",
        "protocol.file.allow=never",
        "ls-remote",
        "--exit-code",
        CANONICAL_REMOTE_READ_URL,
        "refs/heads/main",
    ]
    completed = _checked_run(runner, argv)
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise CutoverError("authoritative remote main lookup returned an invalid result")
    commit_id, separator, ref = lines[0].partition("\t")
    if separator != "\t" or ref != "refs/heads/main":
        raise CutoverError("authoritative remote main lookup returned an invalid ref")
    return _validate_commit_id(commit_id, label="authoritative remote main")


def _automatic_repository_preflight(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> None:
    canonical = CANONICAL_REPOSITORY.resolve(strict=True)
    if repository != canonical:
        raise CutoverError("automatic cutover requires the canonical repository")
    origin = _checked_run(
        runner, _git_argv(repository, "remote", "get-url", "origin")
    ).stdout.strip()
    if origin != CANONICAL_ORIGIN_URL:
        raise CutoverError("automatic cutover origin differs from host contract")
    origin_main = _validate_commit_id(
        _checked_run(
            runner,
            _git_argv(
                repository,
                "rev-parse",
                "--verify",
                "refs/remotes/origin/main",
            ),
        ).stdout.strip(),
        label="origin/main",
    )
    if origin_main != expected_head:
        raise CutoverError("automatic cutover target differs from origin/main")
    remote_main = _authoritative_remote_main_head(runner)
    if remote_main != expected_head:
        raise CutoverError("automatic cutover target differs from authoritative remote main")


def _automatic_staged_helper_path(expected_head: str) -> Path:
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    return AUTOMATIC_STAGING_ROOT / f"{expected_head}.py"


def _stage_automatic_helper(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand = _run,
) -> Path:
    if os.geteuid() != 0:
        raise CutoverError("automatic helper staging requires root privileges")
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    repository = repository.resolve(strict=True)
    _automatic_kill_switch_clear()
    _automatic_repository_preflight(
        repository, expected_head=expected_head, runner=runner
    )
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=AUTOMATIC_HELPER_SOURCE,
        runner=runner,
    )
    if not data:
        raise CutoverError("automatic staged helper is empty")
    target = _automatic_staged_helper_path(expected_head)
    digest = _sha256(data)
    _validate_source_artifacts(
        {target: (data, 0o700, digest)},
        python_targets={target},
    )
    _ensure_private_directory(
        AUTOMATIC_STAGING_ROOT, expected_uid=0, expected_gid=0
    )
    _automatic_kill_switch_clear()
    _automatic_repository_preflight(
        repository, expected_head=expected_head, runner=runner
    )
    _atomic_install(
        target,
        data,
        mode=0o700,
        uid=0,
        gid=0,
        expected_parent_uid=0,
    )
    readback, metadata = _read_regular_file(target, require_root_owned=True)
    if (
        readback != data
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != 0
        or metadata.st_gid != 0
    ):
        raise CutoverError("automatic staged helper readback failed")
    return target


def _verify_automatic_continuation_helper(
    staged_helper: Path,
    *,
    repository: Path,
    expected_head: str,
    runner: RunCommand = _run,
) -> dict[str, str]:
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    expected_path = _automatic_staged_helper_path(expected_head)
    resolved_helper = staged_helper.resolve(strict=True)
    if staged_helper != expected_path or resolved_helper != expected_path:
        raise CutoverError("automatic continuation staged helper path differs from contract")
    if Path(__file__).resolve() != expected_path:
        raise CutoverError("automatic continuation is not running from the staged helper")
    if os.geteuid() != 0:
        raise CutoverError("automatic continuation helper verification requires root")
    data, metadata = _read_regular_file(expected_path, require_root_owned=True)
    if (
        stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        raise CutoverError("automatic continuation staged helper identity is invalid")
    expected_data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=AUTOMATIC_HELPER_SOURCE,
        runner=runner,
    )
    if data != expected_data:
        raise CutoverError("automatic continuation staged helper differs from expected commit")
    return {
        "path": str(expected_path),
        "sha256": _sha256(data),
        "expected_head": expected_head,
    }


def _exec_staged_automatic_helper(
    staged_helper: Path,
    *,
    repository: Path,
    expected_head: str,
) -> None:
    expected = _automatic_staged_helper_path(expected_head)
    if staged_helper != expected:
        raise CutoverError("automatic staged helper path differs from contract")
    argv = [
        "/usr/bin/python3",
        str(staged_helper),
        "--repository",
        str(repository),
        "--expected-head",
        expected_head,
        "--apply",
        "--automatic",
        "--automatic-continuation",
        "--staged-helper-path",
        str(staged_helper),
    ]
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    os.execve(argv[0], argv, env)
    raise CutoverError("automatic staged helper exec unexpectedly returned")


def _cleanup_staged_helper(path: Path) -> None:
    expected_parent = AUTOMATIC_STAGING_ROOT
    if path.parent != expected_parent:
        raise CutoverError("staged helper cleanup path differs from contract")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
    ):
        raise CutoverError("staged helper cleanup target is unsafe")
    path.unlink()
    directory_fd = os.open(expected_parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _repository_blob(
    repository: Path,
    *,
    commit_id: str,
    relative_path: str,
    runner: RunCommand,
) -> bytes:
    _validate_commit_id(commit_id, label="expected_head")
    completed = _checked_run(
        runner,
        _git_argv(repository, "show", f"{commit_id}:{relative_path}"),
    )
    try:
        data = completed.stdout.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CutoverError(f"repository blob is not UTF-8: {relative_path}") from exc
    if not data or len(data) > 1024 * 1024:
        raise CutoverError(f"repository blob size is invalid: {relative_path}")
    return data


def _source_artifacts(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[Path, tuple[bytes, int, str]]:
    result: dict[Path, tuple[bytes, int, str]] = {}
    for artifact in ARTIFACTS:
        data = _repository_blob(
            repository,
            commit_id=expected_head,
            relative_path=artifact.source_relative,
            runner=runner,
        )
        if not data:
            raise CutoverError(f"repository artifact is empty: {artifact.source_relative}")
        result[artifact.target] = (data, artifact.mode, _sha256(data))
    return result


def _validate_source_artifacts(
    artifacts: dict[Path, tuple[bytes, int, str]],
    *,
    python_targets: set[Path],
) -> None:
    parsed_python: dict[Path, ast.AST] = {}
    for target, (data, _mode, expected_sha256) in artifacts.items():
        if _sha256(data) != expected_sha256:
            raise CutoverError(f"source artifact digest mismatch: {target}")
        if target not in python_targets:
            continue
        try:
            source = data.decode("utf-8")
            tree = ast.parse(source, filename=str(target))
            compile(tree, str(target), "exec", dont_inherit=True)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise CutoverError(f"source artifact is not valid Python: {target}") from exc
        parsed_python[target] = tree

    installed_modules = {target.stem for target in python_targets}
    for target, tree in parsed_python.items():
        dependencies: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                dependencies.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                dependencies.add(node.module.split(".", 1)[0])
        missing = sorted(
            dependency
            for dependency in dependencies
            if dependency.startswith("grabowski_")
            and dependency not in installed_modules
        )
        if missing:
            raise CutoverError(
                f"source artifact local dependency is missing: {target}: "
                + ", ".join(missing)
            )


def _expected_recovery_source_dropin(publisher: dict[str, Any]) -> bytes:
    source_path = publisher.get("source_path")
    legacy_kill_switch_path = publisher.get("legacy_kill_switch_path")
    if legacy_kill_switch_path is None:
        # Commit-bound compatibility for pre-authority publisher fixtures, where
        # kill_switch_path still named the operator-home marker. Current
        # contracts always provide the explicit legacy path.
        legacy_kill_switch_path = publisher.get("kill_switch_path")
    if not isinstance(source_path, str) or not source_path.startswith("/"):
        raise CutoverError("recovery publisher source path is invalid")
    if (
        not isinstance(legacy_kill_switch_path, str)
        or not legacy_kill_switch_path.startswith("/")
    ):
        raise CutoverError("recovery publisher legacy kill-switch path is invalid")
    if any(
        character in source_path + legacy_kill_switch_path
        for character in "\n\r "
    ):
        raise CutoverError("recovery sandbox paths contain forbidden whitespace")
    lines = [
        "[Service]",
        "ProtectHome=tmpfs",
        "BindReadOnlyPaths=",
        f"BindReadOnlyPaths={source_path}",
        f"BindReadOnlyPaths=-{legacy_kill_switch_path}",
    ]
    lines.extend(
        f"BindReadOnlyPaths=-{path}" for path in AUTOMATIC_CUTOVER_BIND_PATHS
    )
    lines.extend(
        f"BindReadOnlyPaths=-{path}" for path in PROCESS_OBSERVER_BIND_PATHS
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _validate_recovery_source_dropin(
    artifacts: dict[Path, tuple[bytes, int, str]],
    *,
    publisher: dict[str, Any],
) -> None:
    artifact = artifacts.get(RECOVERY_SOURCE_DROPIN_TARGET)
    if artifact is None:
        raise CutoverError("commit-bound recovery source drop-in is missing")
    data, mode, digest = artifact
    expected = _expected_recovery_source_dropin(publisher)
    if data != expected or digest != _sha256(expected) or mode != 0o644:
        raise CutoverError("recovery source drop-in differs from publisher contract")


def _verify_running_helper(
    artifacts: dict[Path, tuple[bytes, int, str]],
    *,
    running_path: Path | None = None,
) -> None:
    expected = artifacts.get(CUTOVER_HELPER_TARGET)
    if expected is None:
        raise CutoverError("commit-bound cutover helper artifact is missing")
    path = Path(__file__).resolve() if running_path is None else running_path
    data, _metadata = _read_regular_file(path)
    if _sha256(data) != expected[2] or data != expected[0]:
        raise CutoverError("running cutover helper differs from expected commit")


def _validate_repository_recovery_target(value: Any, *, automatic: bool) -> str:
    if not isinstance(value, str):
        raise CutoverError("recovery target must be a string")
    if value == CONFIGURED_TARGET:
        return value
    if automatic and value == LEGACY_CONFIGURED_TARGET:
        return value
    raise CutoverError("recovery target differs from host contract")


def _publisher_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
    automatic: bool = False,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    publisher = actions.get(PUBLISH_ACTION)
    if not isinstance(publisher, dict):
        raise CutoverError("example catalog has no recovery publisher")
    required = {
        "enabled",
        "mode",
        "source_path",
        "destination_path",
        "expected_source_uid",
        "max_recovery_age_seconds",
        "configured_target",
        "kill_switch_path",
        "require_root_owned_destination",
    }
    optional = {"legacy_kill_switch_path"}
    if not required.issubset(publisher) or set(publisher) - required - optional:
        raise CutoverError("recovery publisher contract keys are invalid")
    if publisher.get("enabled") is not True:
        raise CutoverError("recovery publisher must be enabled")
    if publisher.get("mode") != "recovery-marker-publish":
        raise CutoverError("recovery publisher mode is invalid")
    _validate_repository_recovery_target(
        publisher.get("configured_target"), automatic=automatic
    )
    return json.loads(json.dumps(publisher))


def _lifecycle_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
    automatic: bool = False,
) -> dict[str, Any] | None:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    lifecycle = actions.get(BLOCKADE_LIFECYCLE_ACTION)
    if lifecycle is None:
        return None
    if not isinstance(lifecycle, dict):
        raise CutoverError("example blockade lifecycle is malformed")
    required = {
        "enabled",
        "mode",
        "marker_path",
        "legacy_marker_path",
        "quarantine_root",
        "authority_uid",
        "legacy_uid",
        "allowed_peer_unit",
        "allowed_peer_uid",
        "recovery_gate",
    }
    if set(lifecycle) != required:
        raise CutoverError("blockade lifecycle contract keys are invalid")
    if lifecycle.get("enabled") is not True:
        raise CutoverError("blockade lifecycle must be enabled")
    if lifecycle.get("mode") != "blockade-marker-lifecycle":
        raise CutoverError("blockade lifecycle mode is invalid")
    marker = lifecycle.get("marker_path")
    legacy = lifecycle.get("legacy_marker_path")
    quarantine = lifecycle.get("quarantine_root")
    if not all(isinstance(item, str) and item.startswith("/") for item in (marker, legacy, quarantine)):
        raise CutoverError("blockade lifecycle paths are invalid")
    if Path(marker).parent != Path(quarantine).parent:
        raise CutoverError("blockade marker and quarantine authority roots differ")
    if lifecycle.get("authority_uid") != 0:
        raise CutoverError("blockade lifecycle authority_uid must be root")
    if lifecycle.get("allowed_peer_unit") != "grabowski-operator.service":
        raise CutoverError("blockade lifecycle peer unit is invalid")
    if lifecycle.get("allowed_peer_uid") != lifecycle.get("legacy_uid"):
        raise CutoverError("blockade lifecycle peer UID differs from operator UID")
    gate = lifecycle.get("recovery_gate")
    if not isinstance(gate, dict) or set(gate) != {
        "recovery_marker_path",
        "max_recovery_age_seconds",
        "require_root_owned_gate_files",
        "configured_target",
    }:
        raise CutoverError("blockade lifecycle recovery gate is invalid")
    _validate_repository_recovery_target(
        gate.get("configured_target"), automatic=automatic
    )
    return json.loads(json.dumps(lifecycle))


def _root_task_action_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
    automatic: bool = False,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    root_task = actions.get(ROOT_TASK_ACTION)
    if not isinstance(root_task, dict):
        raise CutoverError("example catalog has no root task action")
    required = {
        "enabled",
        "mode",
        "target_pattern",
        "cwd_pattern",
        "timeout_seconds",
        "max_argv",
        "allow_shell",
        "policy_intent",
        "allowed_argv_prefixes",
        "start_gate",
    }
    if set(root_task) != required:
        raise CutoverError("root task action contract keys are invalid")
    if root_task.get("enabled") is not True:
        raise CutoverError("root task action must be enabled")
    if root_task.get("mode") != "root-task-systemd":
        raise CutoverError("root task action mode is invalid")
    if root_task.get("allow_shell") is not False:
        raise CutoverError("root task action must forbid shell execution")
    if root_task.get("policy_intent") != "recovery-gated-root-task-catalog":
        raise CutoverError("root task policy intent is invalid")
    if root_task.get("timeout_seconds") != 60 or root_task.get("max_argv") != 16:
        raise CutoverError("root task execution bounds are invalid")
    if root_task.get("target_pattern") != r"\{.{1,49152}\}":
        raise CutoverError("root task target pattern is invalid")
    if root_task.get("cwd_pattern") != r"/[A-Za-z0-9._/@:+-]{0,999}":
        raise CutoverError("root task cwd pattern is invalid")
    prefixes = root_task.get("allowed_argv_prefixes")
    expected_prefixes = {
        ("/usr/local/bin/sleep-heimserver",),
        ("/usr/local/bin/sleep-heim-pc",),
        ("/usr/local/bin/sleep-heimberry",),
    }
    if not isinstance(prefixes, list) or any(
        not isinstance(prefix, list)
        or len(prefix) != 1
        or not isinstance(prefix[0], str)
        for prefix in prefixes
    ):
        raise CutoverError("root task command catalog is invalid")
    if {tuple(prefix) for prefix in prefixes} != expected_prefixes:
        raise CutoverError("root task command catalog is invalid")
    gate = root_task.get("start_gate")
    if not isinstance(gate, dict):
        raise CutoverError("root task start gate is malformed")
    required_gate = {
        "kill_switch_path",
        "legacy_kill_switch_path",
        "recovery_marker_path",
        "max_recovery_age_seconds",
        "require_root_owned_gate_files",
        "configured_target",
    }
    if set(gate) != required_gate:
        raise CutoverError("root task start gate keys are invalid")
    _validate_repository_recovery_target(
        gate.get("configured_target"), automatic=automatic
    )
    return json.loads(json.dumps(root_task))



def _process_observer_action_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    observer = actions.get(PROCESS_OBSERVER_ACTION)
    if not isinstance(observer, dict):
        raise CutoverError("example catalog has no process reference observer")
    required = {"enabled", "target_pattern", "argv", "timeout_seconds"}
    if set(observer) != required:
        raise CutoverError("process reference observer contract keys are invalid")
    if observer.get("enabled") is not True:
        raise CutoverError("process reference observer must be enabled")
    if observer.get("target_pattern") != r"\{.{1,49152}\}":
        raise CutoverError("process reference observer target pattern is invalid")
    if observer.get("argv") != [str(PROCESS_OBSERVER_TARGET), "{target}"]:
        raise CutoverError("process reference observer argv is invalid")
    if observer.get("timeout_seconds") != 30:
        raise CutoverError("process reference observer timeout is invalid")
    return json.loads(json.dumps(observer))


def _operator_service_control_action_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    action = actions.get(OPERATOR_SERVICE_CONTROL_ACTION)
    if not isinstance(action, dict):
        raise CutoverError("example catalog has no operator service control action")
    required = {"enabled", "target_pattern", "argv", "timeout_seconds"}
    if set(action) != required:
        raise CutoverError("operator service control action keys are invalid")
    if action.get("enabled") is not True:
        raise CutoverError("operator service control action must be enabled")
    if action.get("target_pattern") != r"(?:start|stop|restart|is-active)":
        raise CutoverError("operator service control target pattern is invalid")
    if action.get("argv") != [
        "/usr/bin/systemctl",
        "{target}",
        "grabowski-operator.service",
    ]:
        raise CutoverError("operator service control argv is invalid")
    if action.get("timeout_seconds") != 60:
        raise CutoverError("operator service control timeout is invalid")
    return json.loads(json.dumps(action))


def _rootbroker_cutover_action_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    action = actions.get(ROOTBROKER_CUTOVER_ACTION)
    if not isinstance(action, dict):
        raise CutoverError("example catalog has no automatic Rootbroker cutover action")
    required = {
        "enabled",
        "mode",
        "target_pattern",
        "argv",
        "timeout_seconds",
        "kill_switch_path",
        "legacy_kill_switch_path",
        "allowed_peer_uid",
        "allowed_peer_unit",
    }
    if set(action) != required:
        raise CutoverError("automatic Rootbroker cutover action keys are invalid")
    if action.get("enabled") is not True or action.get("mode") != "template":
        raise CutoverError("automatic Rootbroker cutover must be an enabled template")
    if action.get("target_pattern") != r"[0-9a-f]{40}":
        raise CutoverError("automatic Rootbroker cutover target pattern is invalid")
    if action.get("argv") != [
        str(CUTOVER_HELPER_TARGET),
        "--repository",
        str(CANONICAL_REPOSITORY),
        "--expected-head",
        "{target}",
        "--apply",
        "--automatic",
    ]:
        raise CutoverError("automatic Rootbroker cutover argv is invalid")
    if action.get("timeout_seconds") != 2700:
        raise CutoverError("automatic Rootbroker cutover timeout is invalid")
    if (
        action.get("kill_switch_path") != str(CANONICAL_KILL_SWITCH)
        or action.get("legacy_kill_switch_path") != str(LEGACY_KILL_SWITCH)
    ):
        raise CutoverError("automatic Rootbroker cutover kill-switch binding is invalid")
    if (
        action.get("allowed_peer_uid") != 1000
        or action.get("allowed_peer_unit") != OPERATOR_UNIT
    ):
        raise CutoverError("automatic Rootbroker cutover peer binding is invalid")
    return json.loads(json.dumps(action))


def _bootstrap_recovery_action_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[str, Any]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository,
        commit_id=expected_head,
        relative_path=relative_path,
        runner=runner,
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    action = actions.get(BOOTSTRAP_RECOVERY_ACTION)
    if not isinstance(action, dict):
        raise CutoverError("example catalog has no runtime bootstrap recovery action")
    required = {"enabled", "mode", "target_pattern", "argv", "timeout_seconds"}
    if set(action) != required:
        raise CutoverError("runtime bootstrap recovery action keys are invalid")
    if action.get("enabled") is not True or action.get("mode") != "template":
        raise CutoverError("runtime bootstrap recovery action must be an enabled template")
    if action.get("target_pattern") != r"\{.{1,4096}\}":
        raise CutoverError("runtime bootstrap recovery target pattern is invalid")
    if action.get("argv") != [
        str(BOOTSTRAP_RECOVERY_TARGET),
        "root-execute",
        "{target}",
    ]:
        raise CutoverError("runtime bootstrap recovery argv is invalid")
    if action.get("timeout_seconds") != 3600:
        raise CutoverError("runtime bootstrap recovery timeout is invalid")
    return json.loads(json.dumps(action))


def _local_backup_ntfs_actions_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
) -> dict[str, dict[str, Any]]:
    relative_path = "config/privileged-actions.example.json"
    data = _repository_blob(
        repository, commit_id=expected_head, relative_path=relative_path, runner=runner
    )
    example = _decode_json_object(data, label=relative_path)
    actions = example.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("example privileged action catalog is malformed")
    specs = {
        LOCAL_BACKUP_NTFS_CHECK_ACTION: (
            "check", ["/usr/bin/ntfsfix", "-n", LOCAL_BACKUP_NTFS_DEVICE]
        ),
        LOCAL_BACKUP_NTFS_CLEAR_DIRTY_ACTION: (
            "clear-dirty", ["/usr/bin/ntfsfix", "-d", LOCAL_BACKUP_NTFS_DEVICE]
        ),
        LOCAL_BACKUP_SMART_READ_ACTION: (
            "smart-read",
            ["/usr/sbin/smartctl", "-d", "sat", "-a", LOCAL_BACKUP_SMART_DEVICE],
        ),
        LOCAL_BACKUP_MOUNT_RECONCILE_ACTION: (
            "reconcile",
            [str(BACKUP_MOUNT_RECONCILE_TARGET), "reconcile"],
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    required = {
        "enabled", "mode", "target_pattern", "argv", "timeout_seconds",
        "kill_switch_path", "legacy_kill_switch_path",
        "allowed_peer_uid", "allowed_peer_unit",
    }
    for name, (target_pattern, expected_argv) in specs.items():
        action = actions.get(name)
        if not isinstance(action, dict) or set(action) != required:
            raise CutoverError(f"{name} action contract is invalid")
        if action.get("enabled") is not True or action.get("mode") != "template":
            raise CutoverError(f"{name} must be an enabled template")
        if action.get("target_pattern") != target_pattern:
            raise CutoverError(f"{name} target pattern is invalid")
        if action.get("argv") != expected_argv:
            raise CutoverError(f"{name} argv is invalid")
        if action.get("timeout_seconds") != 120:
            raise CutoverError(f"{name} timeout is invalid")
        if (
            action.get("kill_switch_path") != str(CANONICAL_KILL_SWITCH)
            or action.get("legacy_kill_switch_path") != str(LEGACY_KILL_SWITCH)
            or action.get("allowed_peer_uid") != 1000
            or action.get("allowed_peer_unit") != OPERATOR_UNIT
        ):
            raise CutoverError(f"{name} authority binding is invalid")
        result[name] = json.loads(json.dumps(action))
    return result


def _validate_root_task_coherence(
    root_task: dict[str, Any],
    *,
    publisher: dict[str, Any],
    lifecycle: dict[str, Any] | None,
    configured_target: str,
) -> None:
    if lifecycle is None:
        raise CutoverError("root task cutover requires blockade lifecycle")
    legacy_path = publisher.get("legacy_kill_switch_path")
    if not isinstance(legacy_path, str) or not legacy_path.startswith("/"):
        raise CutoverError("root task cutover requires publisher legacy path")
    expected_gate = {
        "kill_switch_path": publisher["kill_switch_path"],
        "legacy_kill_switch_path": legacy_path,
        "recovery_marker_path": publisher["destination_path"],
        "max_recovery_age_seconds": publisher["max_recovery_age_seconds"],
        "require_root_owned_gate_files": publisher[
            "require_root_owned_destination"
        ],
        "configured_target": configured_target,
    }
    if root_task.get("start_gate") != expected_gate:
        raise CutoverError("root task start gate differs from publisher contract")
    if lifecycle.get("marker_path") != expected_gate["kill_switch_path"]:
        raise CutoverError("root task gate differs from lifecycle marker")
    if lifecycle.get("legacy_marker_path") != expected_gate[
        "legacy_kill_switch_path"
    ]:
        raise CutoverError("root task gate differs from lifecycle legacy marker")


def merge_privileged_config(
    current: dict[str, Any],
    *,
    publisher: dict[str, Any],
    lifecycle: dict[str, Any] | None = None,
    root_task: dict[str, Any] | None = None,
    process_observer: dict[str, Any] | None = None,
    bootstrap_recovery: dict[str, Any] | None = None,
    operator_service_control: dict[str, Any] | None = None,
    rootbroker_cutover: dict[str, Any] | None = None,
    local_backup_ntfs_actions: dict[str, dict[str, Any]] | None = None,
    allow_controlled_updates: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if set(current) != {"schema_version", "actions"}:
        raise CutoverError("installed privileged config has invalid top-level keys")
    if current.get("schema_version") != 2:
        raise CutoverError("installed privileged config schema is unsupported")
    actions = current.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("installed privileged actions must be an object")
    power_before = actions.get(POWER_ACTION)
    if not isinstance(power_before, dict):
        raise CutoverError("installed operator power action is missing")
    if power_before.get("enabled") is not True:
        raise CutoverError("installed operator power action is not enabled")
    gate_before = power_before.get("gate")
    if not isinstance(gate_before, dict):
        raise CutoverError("installed operator power gate is malformed")

    configured_target = _validate_repository_recovery_target(
        publisher.get("configured_target"), automatic=allow_controlled_updates
    )

    merged = json.loads(json.dumps(current))
    merged_actions = merged["actions"]
    merged_actions[PUBLISH_ACTION] = json.loads(json.dumps(publisher))
    process_observer_before = actions.get(PROCESS_OBSERVER_ACTION)
    if process_observer is not None:
        merged_actions[PROCESS_OBSERVER_ACTION] = json.loads(json.dumps(process_observer))
    bootstrap_recovery_before = actions.get(BOOTSTRAP_RECOVERY_ACTION)
    if bootstrap_recovery is not None:
        if (
            not allow_controlled_updates
            and bootstrap_recovery_before is not None
            and bootstrap_recovery_before != bootstrap_recovery
        ):
            raise CutoverError(
                "installed runtime bootstrap recovery action differs from commit-bound contract"
            )
        merged_actions[BOOTSTRAP_RECOVERY_ACTION] = json.loads(
            json.dumps(bootstrap_recovery)
        )
    operator_service_control_before = actions.get(OPERATOR_SERVICE_CONTROL_ACTION)
    if operator_service_control is not None:
        if (
            not allow_controlled_updates
            and operator_service_control_before is not None
            and operator_service_control_before != operator_service_control
        ):
            raise CutoverError(
                "installed operator service control differs from commit-bound contract"
            )
        merged_actions[OPERATOR_SERVICE_CONTROL_ACTION] = json.loads(
            json.dumps(operator_service_control)
        )

    rootbroker_cutover_before = actions.get(ROOTBROKER_CUTOVER_ACTION)
    if rootbroker_cutover is not None:
        if (
            not allow_controlled_updates
            and rootbroker_cutover_before is not None
            and rootbroker_cutover_before != rootbroker_cutover
        ):
            raise CutoverError(
                "installed automatic Rootbroker cutover differs from commit-bound contract"
            )
        merged_actions[ROOTBROKER_CUTOVER_ACTION] = json.loads(
            json.dumps(rootbroker_cutover)
        )

    local_backup_ntfs_before: dict[str, Any] = {}
    if local_backup_ntfs_actions is not None:
        for name in LOCAL_BACKUP_STORAGE_ACTIONS:
            action = local_backup_ntfs_actions.get(name)
            if not isinstance(action, dict):
                raise CutoverError("local BACKUP storage action set is incomplete")
            before = actions.get(name)
            local_backup_ntfs_before[name] = before
            if not allow_controlled_updates and before is not None and before != action:
                raise CutoverError(f"installed {name} differs from commit-bound contract")
            merged_actions[name] = json.loads(json.dumps(action))

    merged_power = merged_actions[POWER_ACTION]
    merged_gate = merged_power["gate"]
    if lifecycle is None:
        # Backward-compatible unit-test and recovery seam for an unchanged
        # authority model. Production cutover always supplies lifecycle.
        coherence = {
            "kill_switch_path": "kill_switch_path",
            "recovery_marker_path": "destination_path",
            "max_recovery_age_seconds": "max_recovery_age_seconds",
            "require_root_owned_gate_files": "require_root_owned_destination",
        }
        for gate_key, publisher_key in coherence.items():
            if gate_before.get(gate_key) != publisher.get(publisher_key):
                raise CutoverError(
                    f"installed power gate differs from publisher contract: {gate_key}"
                )
        merged_gate["configured_target"] = configured_target
    else:
        legacy_path = publisher.get("legacy_kill_switch_path")
        if not isinstance(legacy_path, str) or not legacy_path.startswith("/"):
            raise CutoverError(
                "lifecycle cutover requires publisher legacy_kill_switch_path"
            )
        gate_updates = {
            "kill_switch_path": publisher["kill_switch_path"],
            "legacy_kill_switch_path": legacy_path,
            "recovery_marker_path": publisher["destination_path"],
            "max_recovery_age_seconds": publisher["max_recovery_age_seconds"],
            "require_root_owned_gate_files": publisher[
                "require_root_owned_destination"
            ],
            "configured_target": configured_target,
        }
        for key, value in gate_updates.items():
            merged_gate[key] = value
        merged_actions[BLOCKADE_LIFECYCLE_ACTION] = json.loads(
            json.dumps(lifecycle)
        )
        merged_power["allowed_peer_unit"] = lifecycle["allowed_peer_unit"]
        merged_power["allowed_peer_uid"] = lifecycle["allowed_peer_uid"]
        if lifecycle.get("marker_path") != publisher.get("kill_switch_path"):
            raise CutoverError("lifecycle marker differs from publisher gate")
        if lifecycle.get("legacy_marker_path") != publisher.get(
            "legacy_kill_switch_path"
        ):
            raise CutoverError("lifecycle legacy marker differs from publisher gate")
        if lifecycle.get("legacy_uid") != publisher.get("expected_source_uid"):
            raise CutoverError("lifecycle legacy UID differs from publisher source UID")
        lifecycle_gate = lifecycle.get("recovery_gate")
        if not isinstance(lifecycle_gate, dict):
            raise CutoverError("lifecycle recovery gate is malformed")
        expected_lifecycle_gate = {
            "recovery_marker_path": publisher["destination_path"],
            "max_recovery_age_seconds": publisher["max_recovery_age_seconds"],
            "require_root_owned_gate_files": publisher[
                "require_root_owned_destination"
            ],
            "configured_target": configured_target,
        }
        if lifecycle_gate != expected_lifecycle_gate:
            raise CutoverError("lifecycle recovery gate differs from publisher")

    root_task_before = actions.get(ROOT_TASK_ACTION)
    if root_task is not None:
        _validate_root_task_coherence(
            root_task,
            publisher=publisher,
            lifecycle=lifecycle,
            configured_target=configured_target,
        )
        if (
            not allow_controlled_updates
            and root_task_before is not None
            and root_task_before != root_task
        ):
            raise CutoverError(
                "installed root task action differs from commit-bound contract"
            )
        merged_actions[ROOT_TASK_ACTION] = json.loads(json.dumps(root_task))

    expected_power = json.loads(json.dumps(power_before))
    if lifecycle is None:
        expected_power["gate"]["configured_target"] = configured_target
    else:
        expected_power["gate"].update(gate_updates)
        expected_power["allowed_peer_unit"] = lifecycle["allowed_peer_unit"]
        expected_power["allowed_peer_uid"] = lifecycle["allowed_peer_uid"]
    if merged_power != expected_power:
        raise CutoverError("operator power action changed beyond gate migration")

    controlled = {PUBLISH_ACTION, POWER_ACTION}
    if lifecycle is not None:
        controlled.add(BLOCKADE_LIFECYCLE_ACTION)
    if root_task is not None:
        controlled.add(ROOT_TASK_ACTION)
    if process_observer is not None:
        controlled.add(PROCESS_OBSERVER_ACTION)
    if bootstrap_recovery is not None:
        controlled.add(BOOTSTRAP_RECOVERY_ACTION)
    if operator_service_control is not None:
        controlled.add(OPERATOR_SERVICE_CONTROL_ACTION)
    if rootbroker_cutover is not None:
        controlled.add(ROOTBROKER_CUTOVER_ACTION)
    if local_backup_ntfs_actions is not None:
        controlled.update(local_backup_ntfs_actions)
    evidence = {
        "controlled_updates_allowed": allow_controlled_updates,
        "operator_power_before_sha256": _sha256(_canonical_json(power_before)),
        "operator_power_after_sha256": _sha256(_canonical_json(merged_power)),
        "publisher_sha256": _sha256(_canonical_json(publisher)),
        "lifecycle_sha256": (
            _sha256(_canonical_json(lifecycle)) if lifecycle is not None else None
        ),
        "root_task_sha256": (
            _sha256(_canonical_json(root_task)) if root_task is not None else None
        ),
        "root_task_preexisting": root_task_before is not None,
        "process_observer_sha256": (
            _sha256(_canonical_json(process_observer))
            if process_observer is not None else None
        ),
        "process_observer_preexisting": process_observer_before is not None,
        "process_observer_before_sha256": (
            _sha256(_canonical_json(process_observer_before))
            if isinstance(process_observer_before, dict) else None
        ),
        "bootstrap_recovery_sha256": (
            _sha256(_canonical_json(bootstrap_recovery))
            if bootstrap_recovery is not None else None
        ),
        "operator_service_control_sha256": (
            _sha256(_canonical_json(operator_service_control))
            if operator_service_control is not None else None
        ),
        "operator_service_control_preexisting": (
            operator_service_control_before is not None
        ),
        "rootbroker_cutover_sha256": (
            _sha256(_canonical_json(rootbroker_cutover))
            if rootbroker_cutover is not None else None
        ),
        "rootbroker_cutover_preexisting": rootbroker_cutover_before is not None,
        "local_backup_ntfs_action_sha256": (
            {name: _sha256(_canonical_json(action)) for name, action in sorted(local_backup_ntfs_actions.items())}
            if local_backup_ntfs_actions is not None else {}
        ),
        "local_backup_ntfs_preexisting": {
            name: local_backup_ntfs_before.get(name) is not None
            for name in sorted(local_backup_ntfs_before)
        },
        "bootstrap_recovery_preexisting": bootstrap_recovery_before is not None,
        "bootstrap_recovery_before_sha256": (
            _sha256(_canonical_json(bootstrap_recovery_before))
            if isinstance(bootstrap_recovery_before, dict) else None
        ),
        "root_task_before_sha256": (
            _sha256(_canonical_json(root_task_before))
            if isinstance(root_task_before, dict)
            else None
        ),
        "unrelated_action_names": sorted(
            name for name in actions if name not in controlled
        ),
    }
    for name in evidence["unrelated_action_names"]:
        if merged_actions.get(name) != actions.get(name):
            raise CutoverError(f"unrelated action changed: {name}")
    return merged, evidence


def _operator_authority_attestation(
    *,
    expected_head: str,
    source_artifacts: dict[Path, tuple[bytes, int, str]],
    merged_config: dict[str, Any],
    cutover_receipt_sha256: str,
) -> dict[str, Any]:
    required_artifacts = {
        "broker_module": BROKER_MODULE_TARGET,
        "broker_wrapper": BROKER_WRAPPER_TARGET,
        "cutover_helper": CUTOVER_HELPER_TARGET,
        "operator_service": OPERATOR_SERVICE_TARGET,
    }
    artifact_sha256: dict[str, str] = {}
    for label, target in required_artifacts.items():
        artifact = source_artifacts.get(target)
        if artifact is None:
            raise CutoverError(
                f"operator authority attestation lacks artifact: {label}"
            )
        artifact_sha256[label] = artifact[2]

    actions = merged_config.get("actions")
    if not isinstance(actions, dict):
        raise CutoverError("operator authority attestation config is malformed")
    power = actions.get(POWER_ACTION)
    lifecycle = actions.get(BLOCKADE_LIFECYCLE_ACTION)
    service_control = actions.get(OPERATOR_SERVICE_CONTROL_ACTION)
    rootbroker_cutover = actions.get(ROOTBROKER_CUTOVER_ACTION)
    local_backup_storage = {
        name: actions.get(name) for name in LOCAL_BACKUP_STORAGE_ACTIONS
    }
    if not all(
        isinstance(item, dict)
        for item in (power, lifecycle, service_control, rootbroker_cutover)
    ):
        raise CutoverError("operator authority attestation actions are incomplete")
    present_backup_storage = {
        name: action
        for name, action in local_backup_storage.items()
        if action is not None
    }
    if present_backup_storage and set(present_backup_storage) != set(LOCAL_BACKUP_STORAGE_ACTIONS):
        raise CutoverError("operator authority attestation BACKUP storage actions are incomplete")
    if any(not isinstance(action, dict) for action in present_backup_storage.values()):
        raise CutoverError("operator authority attestation BACKUP storage action is invalid")
    assert isinstance(power, dict)
    assert isinstance(lifecycle, dict)
    assert isinstance(service_control, dict)
    assert isinstance(rootbroker_cutover, dict)
    peer_binding = {
        "allowed_peer_uid": power.get("allowed_peer_uid"),
        "allowed_peer_unit": power.get("allowed_peer_unit"),
    }
    expected_peer_binding = {
        "allowed_peer_uid": lifecycle.get("allowed_peer_uid"),
        "allowed_peer_unit": lifecycle.get("allowed_peer_unit"),
    }
    if (
        peer_binding != expected_peer_binding
        or peer_binding["allowed_peer_uid"] != 1000
        or peer_binding["allowed_peer_unit"] != OPERATOR_UNIT
    ):
        raise CutoverError("operator authority peer binding is incoherent")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_operator_authority_attestation",
        "expected_head": expected_head,
        "cutover_receipt_sha256": cutover_receipt_sha256,
        "config_sha256": _sha256(_canonical_json(merged_config)),
        "artifact_sha256": artifact_sha256,
        "action_sha256": {
            POWER_ACTION: _sha256(_canonical_json(power)),
            BLOCKADE_LIFECYCLE_ACTION: _sha256(_canonical_json(lifecycle)),
            OPERATOR_SERVICE_CONTROL_ACTION: _sha256(
                _canonical_json(service_control)
            ),
            ROOTBROKER_CUTOVER_ACTION: _sha256(
                _canonical_json(rootbroker_cutover)
            ),
            **{
                name: _sha256(_canonical_json(action))
                for name, action in sorted(present_backup_storage.items())
                if isinstance(action, dict)
            },
        },
        "power_peer_binding": peer_binding,
        "operator_system_unit": {
            "unit": OPERATOR_UNIT,
            "fragment_path": str(OPERATOR_SERVICE_TARGET),
            "control_group": f"/system.slice/{OPERATOR_UNIT}",
            "run_uid": 1000,
        },
        "does_not_establish": [
            "current_operator_main_pid",
            "runtime_release_integrity",
            "future_rootbroker_configuration",
        ],
    }
    payload["attestation_sha256"] = _sha256(_canonical_json(payload))
    return payload


def _atomic_install(
    target: Path,
    data: bytes,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
    expected_parent_uid: int = 0,
) -> None:
    parent = target.parent
    metadata = parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise CutoverError(f"target parent is unsafe: {parent}")
    if metadata.st_uid != expected_parent_uid or metadata.st_mode & 0o022:
        raise CutoverError(
            f"target parent owner or mode is unsafe: {parent}"
        )
    parent_identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.cutover-", dir=parent)
    temporary = Path(temporary_name)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        current = parent.lstat()
        current_identity = (
            current.st_dev,
            current.st_ino,
            current.st_mode,
            current.st_uid,
            current.st_gid,
        )
        if current_identity != parent_identity:
            raise CutoverError(f"target parent changed before replace: {parent}")
        os.replace(temporary, target)
        readback = target.lstat()
        if target.is_symlink() or not stat.S_ISREG(readback.st_mode):
            raise CutoverError(f"installed target is not a regular file: {target}")
        if stat.S_IMODE(readback.st_mode) != mode:
            raise CutoverError(f"installed target mode mismatch: {target}")
        if readback.st_uid != uid or readback.st_gid != gid:
            raise CutoverError(f"installed target owner mismatch: {target}")
        installed, installed_metadata = _read_regular_file(
            target,
            require_root_owned=uid == 0,
        )
        if installed_metadata.st_uid != uid or installed_metadata.st_gid != gid:
            raise CutoverError(f"installed target owner changed during readback: {target}")
        if installed != data:
            raise CutoverError(f"installed target content mismatch: {target}")
        directory_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _capture_preimage(
    target: Path,
    *,
    require_root_owned: bool,
) -> Preimage:
    if not target.exists() and not target.is_symlink():
        return Preimage(target, False, None, None, None, None, None)
    data, metadata = _read_regular_file(
        target,
        require_root_owned=require_root_owned,
    )
    return Preimage(
        target=target,
        existed=True,
        data=data,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        sha256=_sha256(data),
    )


def _assert_preimage_unchanged(
    preimage: Preimage,
    *,
    require_root_owned: bool,
) -> None:
    target = preimage.target
    if not preimage.existed:
        if target.exists() or target.is_symlink():
            raise CutoverError(f"target appeared after preimage capture: {target}")
        return
    data, metadata = _read_regular_file(
        target,
        require_root_owned=require_root_owned,
    )
    observed = (
        _sha256(data),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )
    expected = (
        preimage.sha256,
        preimage.mode,
        preimage.uid,
        preimage.gid,
    )
    if observed != expected:
        raise CutoverError(f"target changed after preimage capture: {target}")


def _unlink_and_sync(path: Path, *, expected_parent_uid: int) -> None:
    parent = path.parent
    _validate_directory(parent, expected_uid=expected_parent_uid, label="unlink parent")
    path.unlink(missing_ok=True)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _backup_preimages(
    preimages: list[Preimage],
    *,
    backup_directory: Path,
    expected_head: str,
    install_uid: int,
    install_gid: int,
) -> dict[str, Any]:
    _ensure_private_directory(
        backup_directory.parent,
        expected_uid=install_uid,
        expected_gid=install_gid,
    )
    if backup_directory.exists() or backup_directory.is_symlink():
        raise CutoverError(f"backup directory already exists: {backup_directory}")
    _ensure_private_directory(
        backup_directory,
        expected_uid=install_uid,
        expected_gid=install_gid,
    )
    records: list[dict[str, Any]] = []
    for index, preimage in enumerate(preimages):
        backup_name: str | None = None
        if preimage.existed:
            assert preimage.data is not None
            backup_name = f"{index:02d}-{preimage.target.name}"
            _atomic_install(
                backup_directory / backup_name,
                preimage.data,
                mode=0o600,
                uid=install_uid,
                gid=install_gid,
                expected_parent_uid=install_uid,
            )
        records.append(
            {
                "target": str(preimage.target),
                "existed": preimage.existed,
                "backup_name": backup_name,
                "sha256": preimage.sha256,
                "mode": preimage.mode,
                "uid": preimage.uid,
                "gid": preimage.gid,
            }
        )
    manifest = {
        "schema_version": 1,
        "kind": "grabowski_rootbroker_cutover_preimages",
        "expected_head": expected_head,
        "created_at_unix": int(time.time()),
        "records": records,
    }
    _atomic_install(
        backup_directory / "manifest.json",
        _canonical_json(manifest),
        mode=0o600,
        uid=install_uid,
        gid=install_gid,
        expected_parent_uid=install_uid,
    )
    return manifest


def _restore_preimages(
    preimages: list[Preimage],
    *,
    expected_parent_uid: int,
) -> None:
    errors: list[str] = []
    for preimage in reversed(preimages):
        try:
            if preimage.existed:
                assert preimage.data is not None
                assert preimage.mode is not None
                assert preimage.uid is not None
                assert preimage.gid is not None
                _atomic_install(
                    preimage.target,
                    preimage.data,
                    mode=preimage.mode,
                    uid=preimage.uid,
                    gid=preimage.gid,
                    expected_parent_uid=expected_parent_uid,
                )
            else:
                _unlink_and_sync(
                    preimage.target,
                    expected_parent_uid=expected_parent_uid,
                )
        except Exception as exc:
            errors.append(f"{preimage.target}: {exc}")
    if errors:
        raise CutoverError("preimage restore incomplete: " + " | ".join(errors))


def _operator_username(runner: RunCommand) -> str:
    argv = ["/usr/bin/id", "-nu", "1000"]
    completed = runner(argv)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "uid lookup failed").strip()
        raise CutoverError(f"operator account uid 1000 is unavailable: {detail[:500]}")
    if completed.stdout not in {"alex", "alex\n"}:
        raise CutoverError("operator account identity differs from host contract")
    return "alex"


def _systemctl_scope_prefix(runner: RunCommand, *, user: bool) -> list[str]:
    argv = ["/usr/bin/systemctl"]
    if user:
        argv.extend(["--user", f"--machine={_operator_username(runner)}@.host"])
    return argv


def _unit_scope_argv(runner: RunCommand, unit: str, *, user: bool) -> list[str]:
    argv = _systemctl_scope_prefix(runner, user=user)
    argv.extend(
        [
            "show",
            unit,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            "--no-pager",
        ]
    )
    return argv


def _read_unit_state(
    runner: RunCommand, unit: str, *, user: bool
) -> dict[str, object]:
    completed = runner(_unit_scope_argv(runner, unit, user=user))
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "systemctl show failed").strip()
        raise CutoverError(f"cannot inspect service state for {unit}: {detail[:500]}")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise CutoverError(f"service state is malformed for {unit}")
        values[key] = value
    if set(values) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise CutoverError(f"service state is incomplete for {unit}")
    return {
        "unit": unit,
        "user": user,
        "load_state": values["LoadState"],
        "active": values["ActiveState"] == "active",
        "enabled": values["UnitFileState"] in {"enabled", "enabled-runtime"},
    }


def _systemctl_unit_mutation(
    runner: RunCommand, *, user: bool, action: str, unit: str
) -> None:
    if action not in {"start", "stop", "enable", "disable"}:
        raise CutoverError("unsupported service migration action")
    argv = _systemctl_scope_prefix(runner, user=user)
    argv.append(action)
    if action in {"enable", "disable"}:
        argv.append("--now")
    argv.append(unit)
    _checked_run(runner, argv)


def _restore_unit_state(
    runner: RunCommand, state: dict[str, object]
) -> None:
    if state.get("load_state") == "not-found":
        return
    user = bool(state["user"])
    unit = str(state["unit"])
    if bool(state["enabled"]):
        _systemctl_unit_mutation(runner, user=user, action="enable", unit=unit)
    else:
        _systemctl_unit_mutation(runner, user=user, action="disable", unit=unit)
    if bool(state["active"]):
        _systemctl_unit_mutation(runner, user=user, action="start", unit=unit)
    else:
        _systemctl_unit_mutation(runner, user=user, action="stop", unit=unit)


def _verify_system_operator_state(runner: RunCommand) -> dict[str, object]:
    state = _read_unit_state(runner, OPERATOR_UNIT, user=False)
    if (
        state["load_state"] != "loaded"
        or not state["active"]
        or not state["enabled"]
    ):
        raise CutoverError("root-managed operator service is not active and enabled")
    completed = runner(
        [
            "/usr/bin/systemctl",
            "show",
            OPERATOR_UNIT,
            "--property=MainPID",
            "--property=ControlGroup",
            "--property=User",
            "--property=FragmentPath",
            "--no-pager",
        ]
    )
    if completed.returncode != 0:
        raise CutoverError("root-managed operator identity readback failed")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise CutoverError("root-managed operator identity readback is malformed")
        values[key] = value
    if set(values) != {"MainPID", "ControlGroup", "User", "FragmentPath"}:
        raise CutoverError("root-managed operator identity readback is incomplete")
    try:
        main_pid = int(values["MainPID"])
    except ValueError as exc:
        raise CutoverError("root-managed operator MainPID is invalid") from exc
    if (
        main_pid <= 1
        or values["ControlGroup"] != f"/system.slice/{OPERATOR_UNIT}"
        or values["User"] != "alex"
        or values["FragmentPath"] != str(OPERATOR_SERVICE_TARGET)
    ):
        raise CutoverError("root-managed operator identity differs from contract")
    return {**state, "main_pid": main_pid, "control_group": values["ControlGroup"]}


def _socket_active(runner: RunCommand) -> bool:
    completed = runner(["/usr/bin/systemctl", "is-active", "--quiet", SOCKET_UNIT])
    if completed.returncode == 0:
        return True
    if completed.returncode == 3:
        return False
    detail = (completed.stderr or completed.stdout or "systemctl is-active failed").strip()
    raise CutoverError(f"cannot determine Rootbroker socket state: {detail[:500]}")


def _require_no_active_broker_instances(
    runner: RunCommand, *, allow_invoking_parent: bool = False
) -> None:
    completed = _checked_run(
        runner,
        [
            "/usr/bin/systemctl",
            "list-units",
            "--type=service",
            "--state=activating,running",
            "--no-legend",
            "--plain",
            "grabowski-privileged-broker@*.service",
        ],
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return
    if not allow_invoking_parent or len(lines) != 1:
        raise CutoverError("an active Rootbroker request instance blocks cutover")
    unit = lines[0].split()[0]
    if not unit.startswith("grabowski-privileged-broker@") or not unit.endswith(".service"):
        raise CutoverError("automatic cutover broker instance identity is invalid")
    observed = _checked_run(
        runner,
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--property=MainPID",
            "--value",
            "--no-pager",
        ],
    ).stdout.strip()
    try:
        main_pid = int(observed)
    except ValueError as exc:
        raise CutoverError("automatic cutover broker MainPID is invalid") from exc
    if main_pid != os.getppid():
        raise CutoverError("automatic cutover active broker is not the invoking parent")


def apply_cutover(
    *,
    repository: Path,
    expected_head: str,
    backup_root: Path = BACKUP_ROOT,
    receipt_root: Path = RECEIPT_ROOT,
    config_target: Path = CONFIG_TARGET,
    artifact_targets: dict[Path, tuple[bytes, int, str]] | None = None,
    lock_path: Path = CUTOVER_LOCK,
    runner: RunCommand = _run,
    require_root: bool = True,
    automatic: bool = False,
) -> dict[str, Any]:
    if require_root and os.geteuid() != 0:
        raise CutoverError("root privileges are required")
    install_uid = 0 if require_root else os.getuid()
    if not lock_path.is_absolute():
        raise CutoverError("cutover lock path must be absolute")
    with _exclusive_cutover_lock(lock_path, expected_uid=install_uid):
        return _apply_cutover_locked(
            repository=repository,
            expected_head=expected_head,
            backup_root=backup_root,
            receipt_root=receipt_root,
            config_target=config_target,
            artifact_targets=artifact_targets,
            runner=runner,
            require_root=require_root,
            automatic=automatic,
        )


def _apply_cutover_locked(
    *,
    repository: Path,
    expected_head: str,
    backup_root: Path,
    receipt_root: Path,
    config_target: Path,
    artifact_targets: dict[Path, tuple[bytes, int, str]] | None,
    runner: RunCommand,
    require_root: bool,
    automatic: bool,
) -> dict[str, Any]:
    if require_root and os.geteuid() != 0:
        raise CutoverError("root privileges are required")
    install_uid = 0 if require_root else os.getuid()
    install_gid = 0 if require_root else os.getgid()
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    repository = repository.resolve(strict=True)
    if automatic:
        _automatic_kill_switch_clear()
        _automatic_repository_preflight(
            repository, expected_head=expected_head, runner=runner
        )
    elif _repository_head(repository, runner) != expected_head:
        raise CutoverError("repository HEAD differs from expected_head")
    source_artifacts = artifact_targets or _source_artifacts(
        repository,
        expected_head=expected_head,
        runner=runner,
    )
    python_targets = (
        set(source_artifacts)
        if artifact_targets is not None
        else {artifact.target for artifact in ARTIFACTS if artifact.python_source}
    )
    _validate_source_artifacts(
        source_artifacts,
        python_targets=python_targets,
    )
    if artifact_targets is None and not automatic:
        _verify_running_helper(source_artifacts)
    publisher = _publisher_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
        automatic=automatic,
    )
    lifecycle = _lifecycle_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
        automatic=automatic,
    )
    root_task = _root_task_action_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
        automatic=automatic,
    )
    process_observer = _process_observer_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    bootstrap_recovery = _bootstrap_recovery_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    operator_service_control = _operator_service_control_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    rootbroker_cutover = _rootbroker_cutover_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    local_backup_ntfs_actions = (
        _local_backup_ntfs_actions_from_repository(
            repository, expected_head=expected_head, runner=runner
        )
        if artifact_targets is None
        else None
    )
    if artifact_targets is None:
        _validate_recovery_source_dropin(
            source_artifacts,
            publisher=publisher,
        )
    current_config_data, _ = _read_regular_file(
        config_target,
        require_root_owned=require_root,
    )
    current_config = _decode_json_object(current_config_data, label=str(config_target))
    merged_config, merge_evidence = merge_privileged_config(
        current_config,
        publisher=publisher,
        lifecycle=lifecycle,
        root_task=root_task,
        process_observer=process_observer,
        bootstrap_recovery=bootstrap_recovery,
        operator_service_control=operator_service_control,
        rootbroker_cutover=rootbroker_cutover,
        local_backup_ntfs_actions=local_backup_ntfs_actions,
        allow_controlled_updates=automatic,
    )
    merged_config_data = _canonical_json(merged_config)

    legacy_operator_state = _read_unit_state(
        runner, OPERATOR_UNIT, user=True
    )
    legacy_watchdog_state = _read_unit_state(
        runner, LEGACY_OPERATOR_WATCHDOG_TIMER, user=True
    )
    system_operator_state_before = _read_unit_state(
        runner, OPERATOR_UNIT, user=False
    )

    desired: dict[Path, tuple[bytes, int, str]] = dict(source_artifacts)
    desired[config_target] = (
        merged_config_data,
        0o600,
        _sha256(merged_config_data),
    )
    was_active = _socket_active(runner)
    if not was_active:
        raise CutoverError("Rootbroker socket must be active before cutover")
    preimages = [
        _capture_preimage(target, require_root_owned=require_root)
        for target in desired
    ]
    publish_authority_attestation = artifact_targets is None
    if publish_authority_attestation:
        preimages.append(
            _capture_preimage(
                OPERATOR_AUTHORITY_ATTESTATION_TARGET,
                require_root_owned=require_root,
            )
        )
    stamp = f"{time.time_ns()}-{expected_head[:12]}"
    backup_directory = backup_root / stamp
    receipt_path = receipt_root / f"{stamp}.json"
    backup_manifest = _backup_preimages(
        preimages,
        backup_directory=backup_directory,
        expected_head=expected_head,
        install_uid=install_uid,
        install_gid=install_gid,
    )
    preimage_by_target = {preimage.target: preimage for preimage in preimages}
    attempted_targets: list[str] = []
    try:
        for preimage in preimages:
            _assert_preimage_unchanged(
                preimage,
                require_root_owned=require_root,
            )
        if automatic:
            _automatic_kill_switch_clear()
            _automatic_repository_preflight(
                repository, expected_head=expected_head, runner=runner
            )
        if was_active:
            _checked_run(runner, ["/usr/bin/systemctl", "stop", SOCKET_UNIT])
        _require_no_active_broker_instances(
            runner, allow_invoking_parent=automatic
        )
        if automatic:
            _automatic_kill_switch_clear()
        for target, (data, mode, _digest) in desired.items():
            _assert_preimage_unchanged(
                preimage_by_target[target],
                require_root_owned=require_root,
            )
            attempted_targets.append(str(target))
            _atomic_install(
                target,
                data,
                mode=mode,
                uid=install_uid,
                gid=install_gid,
                expected_parent_uid=install_uid,
            )
        if legacy_watchdog_state["load_state"] != "not-found":
            _systemctl_unit_mutation(
                runner,
                user=True,
                action="disable",
                unit=LEGACY_OPERATOR_WATCHDOG_TIMER,
            )
        if legacy_operator_state["load_state"] != "not-found":
            _systemctl_unit_mutation(
                runner, user=True, action="disable", unit=OPERATOR_UNIT
            )
        _checked_run(runner, ["/usr/bin/systemctl", "daemon-reload"])
        _systemctl_unit_mutation(
            runner, user=False, action="enable", unit=OPERATOR_UNIT
        )
        system_operator_state_after = _verify_system_operator_state(runner)
        _checked_run(runner, ["/usr/bin/systemctl", "start", SOCKET_UNIT])
        _checked_run(runner, ["/usr/bin/systemctl", "is-active", "--quiet", SOCKET_UNIT])
        installed: dict[str, Any] = {}
        for target, (_data, mode, expected_sha) in desired.items():
            readback, metadata = _read_regular_file(
                target,
                require_root_owned=require_root,
            )
            digest = _sha256(readback)
            if digest != expected_sha:
                raise CutoverError(f"installed digest mismatch: {target}")
            if stat.S_IMODE(metadata.st_mode) != mode:
                raise CutoverError(f"installed mode mismatch: {target}")
            if metadata.st_uid != install_uid or metadata.st_gid != install_gid:
                raise CutoverError(f"installed owner mismatch: {target}")
            installed[str(target)] = {
                "sha256": digest,
                "mode": format(mode, "04o"),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
        receipt = {
            "schema_version": 1,
            "kind": "grabowski_rootbroker_cutover_receipt",
            "success": True,
            "expected_head": expected_head,
            "completed_at_unix": int(time.time()),
            "backup_directory": str(backup_directory),
            "backup_manifest_sha256": _sha256(_canonical_json(backup_manifest)),
            "merge_evidence": merge_evidence,
            "installed": installed,
            "socket_unit": SOCKET_UNIT,
            "socket_active": True,
            "socket_was_active": was_active,
            "daemon_reload_complete": True,
            "operator_service_migration": {
                "legacy_operator_before": legacy_operator_state,
                "legacy_watchdog_before": legacy_watchdog_state,
                "system_operator_before": system_operator_state_before,
                "system_operator_after": system_operator_state_after,
            },
            "rollback_performed": False,
        }
        _ensure_private_directory(
            receipt_root,
            expected_uid=install_uid,
            expected_gid=install_gid,
        )
        _atomic_install(
            receipt_path,
            _canonical_json(receipt),
            mode=0o600,
            uid=install_uid,
            gid=install_gid,
            expected_parent_uid=install_uid,
        )
        receipt["receipt_path"] = str(receipt_path)
        receipt["receipt_sha256"] = _sha256(receipt_path.read_bytes())
        if publish_authority_attestation:
            attestation = _operator_authority_attestation(
                expected_head=expected_head,
                source_artifacts=source_artifacts,
                merged_config=merged_config,
                cutover_receipt_sha256=receipt["receipt_sha256"],
            )
            attestation_data = _canonical_json(attestation)
            attempted_targets.append(str(OPERATOR_AUTHORITY_ATTESTATION_TARGET))
            _atomic_install(
                OPERATOR_AUTHORITY_ATTESTATION_TARGET,
                attestation_data,
                mode=0o644,
                uid=install_uid,
                gid=install_gid,
                expected_parent_uid=install_uid,
            )
            readback, metadata = _read_regular_file(
                OPERATOR_AUTHORITY_ATTESTATION_TARGET,
                require_root_owned=require_root,
            )
            if (
                readback != attestation_data
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_uid != install_uid
                or metadata.st_gid != install_gid
            ):
                raise CutoverError("operator authority attestation readback failed")
            receipt["authority_attestation"] = {
                "path": str(OPERATOR_AUTHORITY_ATTESTATION_TARGET),
                "sha256": _sha256(readback),
                "attestation_sha256": attestation["attestation_sha256"],
            }
        return receipt
    except Exception as exc:
        rollback_errors: list[str] = []

        def attempt(label: str, operation: Callable[[], None]) -> None:
            try:
                operation()
            except Exception as rollback_exc:
                rollback_errors.append(f"{label}: {rollback_exc}")

        attempt(
            "disable migrated system operator",
            lambda: _systemctl_unit_mutation(
                runner, user=False, action="disable", unit=OPERATOR_UNIT
            ),
        )
        attempt(
            "restore preimages",
            lambda: _restore_preimages(
                preimages,
                expected_parent_uid=install_uid,
            ),
        )
        attempt(
            "reload restored systemd units",
            lambda: _checked_run(runner, ["/usr/bin/systemctl", "daemon-reload"]),
        )
        attempt(
            "restore system operator state",
            lambda: _restore_unit_state(runner, system_operator_state_before),
        )
        attempt(
            "restore legacy operator state",
            lambda: _restore_unit_state(runner, legacy_operator_state),
        )
        attempt(
            "restore legacy operator watchdog state",
            lambda: _restore_unit_state(runner, legacy_watchdog_state),
        )
        if was_active:
            attempt(
                "restore active socket",
                lambda: _checked_run(
                    runner,
                    ["/usr/bin/systemctl", "start", SOCKET_UNIT],
                ),
            )
        else:
            attempt(
                "restore inactive socket",
                lambda: _checked_run(
                    runner,
                    ["/usr/bin/systemctl", "stop", SOCKET_UNIT],
                ),
            )
        failure = {
            "schema_version": 1,
            "kind": "grabowski_rootbroker_cutover_receipt",
            "success": False,
            "expected_head": expected_head,
            "completed_at_unix": int(time.time()),
            "backup_directory": str(backup_directory),
            "attempted_targets": attempted_targets,
            "rollback_performed": True,
            "rollback_complete": not rollback_errors,
            "rollback_errors": rollback_errors,
            "socket_was_active": was_active,
            "daemon_reload_restored": not any(
                item.startswith("reload restored systemd units:")
                for item in rollback_errors
            ),
            "error": str(exc)[:1000],
        }

        def write_failure_receipt() -> None:
            _ensure_private_directory(
                receipt_root,
                expected_uid=install_uid,
                expected_gid=install_gid,
            )
            _atomic_install(
                receipt_path,
                _canonical_json(failure),
                mode=0o600,
                uid=install_uid,
                gid=install_gid,
                expected_parent_uid=install_uid,
            )

        attempt("write failure receipt", write_failure_receipt)
        detail = str(exc)
        if rollback_errors:
            detail += "; rollback issues: " + " | ".join(rollback_errors)
        raise CutoverError(detail[:2000]) from exc



def build_plan(*, repository: Path, expected_head: str, runner: RunCommand = _run) -> dict[str, Any]:
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    repository = repository.resolve(strict=True)
    actual_head = _repository_head(repository, runner)
    source_artifacts = _source_artifacts(
        repository,
        expected_head=expected_head,
        runner=runner,
    )
    _validate_source_artifacts(
        source_artifacts,
        python_targets={
            artifact.target for artifact in ARTIFACTS if artifact.python_source
        },
    )
    _verify_running_helper(source_artifacts)
    publisher = _publisher_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
    )
    lifecycle = _lifecycle_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
    )
    root_task = _root_task_action_from_repository(
        repository,
        expected_head=expected_head,
        runner=runner,
    )
    process_observer = _process_observer_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    bootstrap_recovery = _bootstrap_recovery_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    operator_service_control = _operator_service_control_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    rootbroker_cutover = _rootbroker_cutover_action_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    local_backup_ntfs_actions = _local_backup_ntfs_actions_from_repository(
        repository, expected_head=expected_head, runner=runner
    )
    _validate_recovery_source_dropin(
        source_artifacts,
        publisher=publisher,
    )
    current_data, metadata = _read_regular_file(CONFIG_TARGET, require_root_owned=True)
    current = _decode_json_object(current_data, label=str(CONFIG_TARGET))
    merged, merge_evidence = merge_privileged_config(
        current,
        publisher=publisher,
        lifecycle=lifecycle,
        root_task=root_task,
        process_observer=process_observer,
        bootstrap_recovery=bootstrap_recovery,
        operator_service_control=operator_service_control,
        rootbroker_cutover=rootbroker_cutover,
        local_backup_ntfs_actions=local_backup_ntfs_actions,
    )
    return {
        "schema_version": 1,
        "kind": "grabowski_rootbroker_cutover_plan",
        "ready": actual_head == expected_head,
        "expected_head": expected_head,
        "actual_head": actual_head,
        "installed_config_sha256": _sha256(current_data),
        "installed_config_mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
        "desired_config_sha256": _sha256(_canonical_json(merged)),
        "source_artifacts": {
            str(target): {"sha256": digest, "mode": format(mode, "04o")}
            for target, (_data, mode, digest) in source_artifacts.items()
        },
        "merge_evidence": merge_evidence,
        "root_mutation": False,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply the reviewed Grabowski Rootbroker recovery-publisher cutover."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("--automatic-continuation", action="store_true")
    parser.add_argument("--staged-helper-path")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    repository = Path(args.repository)
    if args.automatic and not args.apply:
        raise CutoverError("--automatic requires --apply")
    if args.automatic_continuation and not (args.automatic and args.apply):
        raise CutoverError("--automatic-continuation requires --automatic --apply")
    expected_staged: Path | None = None
    if args.automatic_continuation:
        if not args.staged_helper_path:
            raise CutoverError("automatic continuation requires staged helper path")
        expected_staged = _automatic_staged_helper_path(args.expected_head)
        supplied_staged = Path(args.staged_helper_path)
        _verify_automatic_continuation_helper(
            supplied_staged,
            repository=repository.resolve(strict=True),
            expected_head=args.expected_head,
        )
    elif args.staged_helper_path:
        raise CutoverError("staged helper path is valid only for automatic continuation")

    previous_handlers: dict[int, Any] = {}
    if args.automatic:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, _termination_requested)
    try:
        if args.automatic and args.apply and not args.automatic_continuation:
            staged = _stage_automatic_helper(
                repository, expected_head=args.expected_head
            )
            try:
                _exec_staged_automatic_helper(
                    staged, repository=repository, expected_head=args.expected_head
                )
            except Exception:
                _cleanup_staged_helper(staged)
                raise
            raise CutoverError("automatic staged helper handoff unexpectedly returned")
        if args.apply:
            result = apply_cutover(
                repository=repository,
                expected_head=args.expected_head,
                automatic=args.automatic,
            )
        else:
            result = build_plan(
                repository=repository,
                expected_head=args.expected_head,
            )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if expected_staged is not None:
            _cleanup_staged_helper(expected_staged)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("success", result.get("ready", False)) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
