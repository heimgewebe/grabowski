#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable


CONFIG_TARGET = Path("/etc/grabowski/privileged-actions.json")
BLOCKADES_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockades.py")
BLOCKADE_STORE_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockade_store.py")
BLOCKADE_AUTHORITY_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_blockade_authority.py")
COMMAND_IDENTITY_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_command_identity.py")
BROKER_MODULE_TARGET = Path("/usr/local/lib/grabowski/grabowski_privileged_broker.py")
BROKER_WRAPPER_TARGET = Path("/usr/local/libexec/grabowski-privileged-broker")
PROCESS_OBSERVER_TARGET = Path("/usr/local/libexec/grabowski-process-reference-observer")
REQUEST_CLIENT_TARGET = Path("/usr/local/bin/grabowski-privileged-request")
CUTOVER_HELPER_TARGET = Path("/usr/local/libexec/grabowski-rootbroker-cutover")
BROKER_SERVICE_TARGET = Path("/etc/systemd/system/grabowski-privileged-broker@.service")
RECOVERY_SOURCE_DROPIN_TARGET = Path(
    "/etc/systemd/system/grabowski-privileged-broker@.service.d/recovery-source.conf"
)
BACKUP_ROOT = Path("/var/lib/grabowski/rootbroker-cutover-backups")
RECEIPT_ROOT = Path("/var/lib/grabowski/rootbroker-cutover-receipts")
CUTOVER_LOCK = Path("/run/grabowski/rootbroker-cutover.lock")
SOCKET_UNIT = "grabowski-privileged-broker.socket"
CONFIGURED_TARGET = "heimberry:rest-server/grabowski-recovery-probe"
PUBLISH_ACTION = "publish_recovery_marker"
POWER_ACTION = "operator_power_argv"
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOT_TASK_ACTION = "operator_root_task_systemd_unit"
PROCESS_OBSERVER_ACTION = "observe_process_references"


class CutoverError(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifact:
    source_relative: str
    target: Path
    mode: int
    python_source: bool = False


ARTIFACTS = (
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
    for target, (data, _mode, expected_sha256) in artifacts.items():
        if _sha256(data) != expected_sha256:
            raise CutoverError(f"source artifact digest mismatch: {target}")
        if target not in python_targets:
            continue
        try:
            source = data.decode("utf-8")
            compile(source, str(target), "exec", dont_inherit=True)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise CutoverError(f"source artifact is not valid Python: {target}") from exc


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
    return (
        "[Service]\n"
        "ProtectHome=tmpfs\n"
        "BindReadOnlyPaths=\n"
        f"BindReadOnlyPaths={source_path}\n"
        f"BindReadOnlyPaths=-{legacy_kill_switch_path}\n"
    ).encode("utf-8")


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


def _publisher_from_repository(
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
    if publisher.get("configured_target") != CONFIGURED_TARGET:
        raise CutoverError("recovery publisher target differs from host contract")
    return json.loads(json.dumps(publisher))


def _lifecycle_from_repository(
    repository: Path,
    *,
    expected_head: str,
    runner: RunCommand,
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
    if gate.get("configured_target") != CONFIGURED_TARGET:
        raise CutoverError("blockade lifecycle target differs from host contract")
    return json.loads(json.dumps(lifecycle))


def _root_task_action_from_repository(
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
    if gate.get("configured_target") != CONFIGURED_TARGET:
        raise CutoverError("root task target differs from host contract")
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


def _validate_root_task_coherence(
    root_task: dict[str, Any],
    *,
    publisher: dict[str, Any],
    lifecycle: dict[str, Any] | None,
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
        "configured_target": CONFIGURED_TARGET,
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

    merged = json.loads(json.dumps(current))
    merged_actions = merged["actions"]
    merged_actions[PUBLISH_ACTION] = json.loads(json.dumps(publisher))
    process_observer_before = actions.get(PROCESS_OBSERVER_ACTION)
    if process_observer is not None:
        merged_actions[PROCESS_OBSERVER_ACTION] = json.loads(json.dumps(process_observer))
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
        merged_gate["configured_target"] = CONFIGURED_TARGET
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
            "configured_target": CONFIGURED_TARGET,
        }
        for key, value in gate_updates.items():
            merged_gate[key] = value
        merged_actions[BLOCKADE_LIFECYCLE_ACTION] = json.loads(
            json.dumps(lifecycle)
        )
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
            "configured_target": CONFIGURED_TARGET,
        }
        if lifecycle_gate != expected_lifecycle_gate:
            raise CutoverError("lifecycle recovery gate differs from publisher")

    root_task_before = actions.get(ROOT_TASK_ACTION)
    if root_task is not None:
        _validate_root_task_coherence(
            root_task,
            publisher=publisher,
            lifecycle=lifecycle,
        )
        if root_task_before is not None and root_task_before != root_task:
            raise CutoverError(
                "installed root task action differs from commit-bound contract"
            )
        merged_actions[ROOT_TASK_ACTION] = json.loads(json.dumps(root_task))

    expected_power = json.loads(json.dumps(power_before))
    if lifecycle is None:
        expected_power["gate"]["configured_target"] = CONFIGURED_TARGET
    else:
        expected_power["gate"].update(gate_updates)
    if merged_power != expected_power:
        raise CutoverError("operator power action changed beyond gate migration")

    controlled = {PUBLISH_ACTION, POWER_ACTION}
    if lifecycle is not None:
        controlled.add(BLOCKADE_LIFECYCLE_ACTION)
    if root_task is not None:
        controlled.add(ROOT_TASK_ACTION)
    if process_observer is not None:
        controlled.add(PROCESS_OBSERVER_ACTION)
    evidence = {
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


def _socket_active(runner: RunCommand) -> bool:
    completed = runner(["/usr/bin/systemctl", "is-active", "--quiet", SOCKET_UNIT])
    if completed.returncode == 0:
        return True
    if completed.returncode == 3:
        return False
    detail = (completed.stderr or completed.stdout or "systemctl is-active failed").strip()
    raise CutoverError(f"cannot determine Rootbroker socket state: {detail[:500]}")


def _require_no_active_broker_instances(runner: RunCommand) -> None:
    completed = _checked_run(
        runner,
        [
            "/usr/bin/systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "grabowski-privileged-broker@*.service",
        ],
    )
    if completed.stdout.strip():
        raise CutoverError("an active Rootbroker request instance blocks cutover")


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
) -> dict[str, Any]:
    if require_root and os.geteuid() != 0:
        raise CutoverError("root privileges are required")
    install_uid = 0 if require_root else os.getuid()
    install_gid = 0 if require_root else os.getgid()
    expected_head = _validate_commit_id(expected_head, label="expected_head")
    repository = repository.resolve(strict=True)
    if _repository_head(repository, runner) != expected_head:
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
    if artifact_targets is None:
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
    )
    merged_config_data = _canonical_json(merged_config)

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
        if was_active:
            _checked_run(runner, ["/usr/bin/systemctl", "stop", SOCKET_UNIT])
        _require_no_active_broker_instances(runner)
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
        _checked_run(runner, ["/usr/bin/systemctl", "daemon-reload"])
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
        return receipt
    except Exception as exc:
        rollback_errors: list[str] = []

        def attempt(label: str, operation: Callable[[], None]) -> None:
            try:
                operation()
            except Exception as rollback_exc:
                rollback_errors.append(f"{label}: {rollback_exc}")

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
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    repository = Path(args.repository)
    if args.apply:
        result = apply_cutover(
            repository=repository,
            expected_head=args.expected_head,
        )
    else:
        result = build_plan(
            repository=repository,
            expected_head=args.expected_head,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("success", result.get("ready", False)) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
