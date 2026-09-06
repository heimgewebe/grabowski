from __future__ import annotations

from collections.abc import Mapping
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any
import uuid

import grabowski_effect_receipt as receipts


FENCE_ENFORCEMENT_SCHEMA_VERSION = 1
FENCE_ENFORCEMENT_CONFIG_KIND = "grabowski.operator_fence_enforcement_config"
FENCE_ENFORCEMENT_STATE_KIND = "grabowski.operator_fence_enforcement_state"
FENCE_ENFORCEMENT_CONFIG_PATH = (
    Path.home() / ".config" / "grabowski" / "operator-fence-enforcement.v1.json"
)
FENCE_ENFORCEMENT_STATE_PATH = (
    Path.home() / ".local" / "state" / "grabowski" / "operator-fence-enforcement-state.v1.json"
)
FENCE_ENFORCEMENT_MAX_BYTES = 32 * 1024
FENCE_ENFORCEMENT_LOCK_TIMEOUT_SECONDS = 5.0
FENCE_ENFORCEMENT_PEERS = frozenset({"grabowski", "der-kleine-maulwurf"})
FENCE_ENFORCEMENT_PHASES = frozenset(
    {
        "prepared",
        "granted",
        "begun",
        "dispatching",
        "completion_ready",
        "outcome_unknown",
        "settled",
    }
)
FENCE_ENFORCEMENT_TERMINAL_OUTCOMES = frozenset(
    {"effect_applied", "effect_not_applied"}
)
_FENCE_ENFORCEMENT_LOCK = threading.Lock()
_FENCE_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_FENCE_INSTANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_FENCE_SESSION_RE = re.compile(r"[0-9a-f]{32}\Z")


class OperatorFenceEnforcementError(RuntimeError):
    pass


class OperatorFenceEnforcementDenied(OperatorFenceEnforcementError):
    pass


def _fence_canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _fence_sha256_json(value: Any) -> str:
    return hashlib.sha256(_fence_canonical_bytes(value)).hexdigest()


def _fence_directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _fence_open_parent(target: Path, *, create: bool) -> tuple[Path, int]:
    expanded = target.expanduser()
    if not expanded.is_absolute() or not expanded.name:
        raise OperatorFenceEnforcementError("unsafe_fence_path")
    parent = expanded.parent
    flags = _fence_directory_flags()
    descriptor = os.open("/", flags)
    try:
        for part in parent.parts[1:]:
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise OperatorFenceEnforcementError("unsafe_fence_parent") from exc
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise OperatorFenceEnforcementError("unsafe_fence_parent")
        return parent, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _fence_read_json(path: Path, *, maximum_bytes: int = FENCE_ENFORCEMENT_MAX_BYTES) -> tuple[dict[str, Any], str]:
    target = path.expanduser()
    _parent, parent_fd = _fence_open_parent(target, create=False)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(target.name, flags, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 2
            or before.st_size > maximum_bytes
        ):
            raise OperatorFenceEnforcementError("unsafe_fence_file")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        signature_before = (
            before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_ctime_ns, before.st_mode, before.st_uid, before.st_nlink,
        )
        signature_after = (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_mode, after.st_uid, after.st_nlink,
        )
        if len(payload) > maximum_bytes or signature_after != signature_before:
            raise OperatorFenceEnforcementError("fence_file_changed_during_read")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorFenceEnforcementError("invalid_fence_json") from exc
    if not isinstance(value, dict):
        raise OperatorFenceEnforcementError("invalid_fence_json_shape")
    return value, _fence_sha256_json(value)


def _fence_write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short fence state write")
        view = view[written:]


def _fence_process_lock_path(state_path: Path) -> Path:
    target = state_path.expanduser()
    return target.with_name(f"{target.name}.lock")


def _fence_acquire_process_lock(
    state_path: Path, *, timeout_seconds: float = FENCE_ENFORCEMENT_LOCK_TIMEOUT_SECONDS
) -> int:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
        or timeout_seconds > 60
    ):
        raise ValueError("invalid fence process-lock timeout")
    target = _fence_process_lock_path(state_path)
    _parent, parent_fd = _fence_open_parent(target, create=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(target.name, flags, 0o600, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        linked = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_nlink != linked.st_nlink
        ):
            raise OperatorFenceEnforcementError("unsafe_fence_lock_file")
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return descriptor
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise OperatorFenceEnforcementDenied("local_effect_inflight")
                time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    finally:
        os.close(parent_fd)


def _fence_release_locks(token: Mapping[str, Any]) -> None:
    if token.get("lock_held") is not True:
        return
    descriptor = token.get("process_lock_fd")
    token["lock_held"] = False
    try:
        if isinstance(descriptor, int) and not isinstance(descriptor, bool):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
    finally:
        _FENCE_ENFORCEMENT_LOCK.release()


def _fence_write_json(path: Path, material: Mapping[str, Any]) -> dict[str, Any]:
    target = path.expanduser()
    _parent, parent_fd = _fence_open_parent(target, create=True)
    document = dict(material)
    document["state_sha256"] = _fence_sha256_json(document)
    payload = _fence_canonical_bytes(document) + b"\n"
    if len(payload) > FENCE_ENFORCEMENT_MAX_BYTES:
        os.close(parent_fd)
        raise OperatorFenceEnforcementError("fence_state_too_large")
    temporary = f".{target.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    temporary_exists = False
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        temporary_exists = True
        os.fchmod(descriptor, 0o600)
        _fence_write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, target.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary_exists = False
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    return document


def _fence_load_config(path: Path) -> tuple[dict[str, Any], str]:
    value, digest = _fence_read_json(path)
    required = {
        "schema_version", "kind", "mode", "host", "remote_user", "peer_id",
        "known_hosts_path", "identity_file", "host_key_alias",
        "expected_instance_id", "minimum_generation_seen", "lease_seconds",
    }
    if set(value) != required:
        raise OperatorFenceEnforcementError("invalid_fence_config_shape")
    if (
        value.get("schema_version") != FENCE_ENFORCEMENT_SCHEMA_VERSION
        or isinstance(value.get("schema_version"), bool)
        or value.get("kind") != FENCE_ENFORCEMENT_CONFIG_KIND
        or value.get("mode") != "enforce"
    ):
        raise OperatorFenceEnforcementError("unsupported_fence_config")
    for field in (
        "host", "remote_user", "known_hosts_path", "identity_file", "host_key_alias"
    ):
        item = value.get(field)
        if not isinstance(item, str) or not item.strip() or "\x00" in item:
            raise OperatorFenceEnforcementError(f"invalid_fence_{field}")
    if value.get("peer_id") not in FENCE_ENFORCEMENT_PEERS:
        raise OperatorFenceEnforcementError("invalid_fence_peer_id")
    instance = value.get("expected_instance_id")
    if not isinstance(instance, str) or _FENCE_INSTANCE_RE.fullmatch(instance) is None:
        raise OperatorFenceEnforcementError("invalid_fence_instance_id")
    minimum = value.get("minimum_generation_seen")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
        raise OperatorFenceEnforcementError("invalid_fence_minimum_generation")
    lease_seconds = value.get("lease_seconds")
    if (
        isinstance(lease_seconds, bool)
        or not isinstance(lease_seconds, int)
        or lease_seconds < 5
        or lease_seconds > 600
    ):
        raise OperatorFenceEnforcementError("invalid_fence_lease_seconds")
    return value, digest


def fence_enforcement_required(config_path: Path | None = None) -> bool:
    target = FENCE_ENFORCEMENT_CONFIG_PATH if config_path is None else config_path
    try:
        _fence_load_config(target)
    except FileNotFoundError:
        return False
    return True


def _fence_validate_pending(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise OperatorFenceEnforcementError("invalid_fence_pending")
    required = {
        "session_id", "operation_id", "operation_name", "intent_sha256",
        "phase", "generation", "outcome", "evidence_sha256", "created_at_unix",
    }
    if set(value) != required:
        raise OperatorFenceEnforcementError("invalid_fence_pending_shape")
    pending = dict(value)
    if not isinstance(pending["session_id"], str) or _FENCE_SESSION_RE.fullmatch(pending["session_id"]) is None:
        raise OperatorFenceEnforcementError("invalid_fence_session")
    if not isinstance(pending["operation_id"], str) or not pending["operation_id"]:
        raise OperatorFenceEnforcementError("invalid_fence_operation_id")
    if not isinstance(pending["operation_name"], str) or not pending["operation_name"]:
        raise OperatorFenceEnforcementError("invalid_fence_operation_name")
    if not isinstance(pending["intent_sha256"], str) or _FENCE_SHA256_RE.fullmatch(pending["intent_sha256"]) is None:
        raise OperatorFenceEnforcementError("invalid_fence_intent")
    if pending["phase"] not in FENCE_ENFORCEMENT_PHASES:
        raise OperatorFenceEnforcementError("invalid_fence_phase")
    generation = pending["generation"]
    if generation is not None and (
        isinstance(generation, bool) or not isinstance(generation, int) or generation < 0
    ):
        raise OperatorFenceEnforcementError("invalid_fence_generation")
    outcome = pending["outcome"]
    if outcome is not None and outcome not in FENCE_ENFORCEMENT_TERMINAL_OUTCOMES | {"outcome_unknown"}:
        raise OperatorFenceEnforcementError("invalid_fence_outcome")
    evidence = pending["evidence_sha256"]
    if evidence is not None and (
        not isinstance(evidence, str) or _FENCE_SHA256_RE.fullmatch(evidence) is None
    ):
        raise OperatorFenceEnforcementError("invalid_fence_evidence")
    created = pending["created_at_unix"]
    if isinstance(created, bool) or not isinstance(created, int) or created < 0:
        raise OperatorFenceEnforcementError("invalid_fence_created_at")
    return pending


def _fence_initial_state(config: Mapping[str, Any], config_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": FENCE_ENFORCEMENT_SCHEMA_VERSION,
        "kind": FENCE_ENFORCEMENT_STATE_KIND,
        "config_sha256": config_sha256,
        "peer_id": config["peer_id"],
        "instance_id": config["expected_instance_id"],
        "minimum_generation_seen": config["minimum_generation_seen"],
        "pending": None,
    }


def _fence_load_state(
    config: Mapping[str, Any], config_sha256: str, state_path: Path
) -> dict[str, Any]:
    try:
        value, _digest = _fence_read_json(state_path)
    except FileNotFoundError:
        return _fence_initial_state(config, config_sha256)
    required = {
        "schema_version", "kind", "config_sha256", "peer_id", "instance_id",
        "minimum_generation_seen", "pending", "state_sha256",
    }
    if set(value) != required:
        raise OperatorFenceEnforcementError("invalid_fence_state_shape")
    claimed = value.get("state_sha256")
    if not isinstance(claimed, str) or _FENCE_SHA256_RE.fullmatch(claimed) is None:
        raise OperatorFenceEnforcementError("invalid_fence_state_digest")
    material = {key: value[key] for key in required if key != "state_sha256"}
    if _fence_sha256_json(material) != claimed:
        raise OperatorFenceEnforcementError("fence_state_digest_mismatch")
    if (
        value.get("schema_version") != FENCE_ENFORCEMENT_SCHEMA_VERSION
        or value.get("kind") != FENCE_ENFORCEMENT_STATE_KIND
        or value.get("config_sha256") != config_sha256
        or value.get("peer_id") != config["peer_id"]
        or value.get("instance_id") != config["expected_instance_id"]
    ):
        raise OperatorFenceEnforcementError("fence_state_config_drift")
    minimum = value.get("minimum_generation_seen")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < config["minimum_generation_seen"]:
        raise OperatorFenceEnforcementError("fence_state_generation_regression")
    return {**material, "pending": _fence_validate_pending(value.get("pending"))}


def _fence_store_state(state_path: Path, state: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(state)
    material.pop("state_sha256", None)
    return _fence_write_json(state_path, material)


def _fence_client(config: Mapping[str, Any], client_factory: Any = None) -> Any:
    if client_factory is None:
        from grabowski_operator_fence_rpc import OperatorFenceSshClient
        client_factory = OperatorFenceSshClient
    return client_factory(
        host=config["host"],
        remote_user=config["remote_user"],
        expected_peer_id=config["peer_id"],
        known_hosts_path=config["known_hosts_path"],
        identity_file=config["identity_file"],
        host_key_alias=config["host_key_alias"],
        timeout_seconds=5,
    )


def _fence_rpc(client: Any, operation: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
    from grabowski_operator_fence_rpc import request_document
    response = client.call(
        request_document(
            request_id=f"g65-{operation}-{uuid.uuid4().hex}",
            operation=operation,
            arguments=arguments,
        )
    )
    if not isinstance(response, Mapping) or response.get("ok") is not True:
        error = response.get("error") if isinstance(response, Mapping) else None
        code = error.get("code") if isinstance(error, Mapping) else "rpc_not_ok"
        raise OperatorFenceEnforcementDenied(str(code))
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise OperatorFenceEnforcementError("invalid_fence_rpc_result")
    return result


def _fence_common_arguments(config: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "expected_instance_id": config["expected_instance_id"],
        "minimum_generation_seen": state["minimum_generation_seen"],
    }


def _fence_validate_grant(
    result: Mapping[str, Any], config: Mapping[str, Any], state: Mapping[str, Any]
) -> int:
    generation = result.get("generation")
    if (
        result.get("instance_id") != config["expected_instance_id"]
        or result.get("owner_id") != config["peer_id"]
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation <= state["minimum_generation_seen"]
        or not isinstance(result.get("fencing_mark"), Mapping)
    ):
        raise OperatorFenceEnforcementError("invalid_fence_grant")
    from grabowski_operator_fence import OperatorFenceStore
    OperatorFenceStore.validate_fencing_mark(
        result["fencing_mark"],
        expected_instance_id=config["expected_instance_id"],
        minimum_generation_seen=state["minimum_generation_seen"],
    )
    return generation


def _fence_pending_evidence(pending: Mapping[str, Any], outcome: str) -> str:
    return _fence_sha256_json(
        {
            "schema_version": 1,
            "kind": "grabowski.operator_fence_local_recovery_evidence",
            "operation_id": pending["operation_id"],
            "operation_name": pending["operation_name"],
            "intent_sha256": pending["intent_sha256"],
            "phase": pending["phase"],
            "outcome": outcome,
        }
    )


def _fence_set_pending(
    state_path: Path,
    state: Mapping[str, Any],
    pending: Mapping[str, Any] | None,
    *,
    minimum_generation_seen: int | None = None,
) -> dict[str, Any]:
    updated = dict(state)
    updated["pending"] = None if pending is None else dict(pending)
    if minimum_generation_seen is not None:
        updated["minimum_generation_seen"] = max(
            int(updated["minimum_generation_seen"]), minimum_generation_seen
        )
    stored = _fence_store_state(state_path, updated)
    return {key: stored[key] for key in stored if key != "state_sha256"}


def _fence_status(client: Any, config: Mapping[str, Any], state: Mapping[str, Any]) -> Mapping[str, Any]:
    result = _fence_rpc(client, "status", {})
    if result.get("instance_id") != config["expected_instance_id"]:
        raise OperatorFenceEnforcementDenied("stale_fence_instance")
    generation = result.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise OperatorFenceEnforcementError("invalid_fence_status_generation")
    if generation < state["minimum_generation_seen"]:
        raise OperatorFenceEnforcementDenied("generation_rollback_detected")
    return result


def _fence_settle_arguments(
    config: Mapping[str, Any], state: Mapping[str, Any], pending: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "session_id": pending["session_id"],
        "generation": pending["generation"],
        "operation_id": pending["operation_id"],
        "operation_name": pending["operation_name"],
        "intent_sha256": pending["intent_sha256"],
        "outcome": pending["outcome"],
        "evidence_sha256": pending["evidence_sha256"],
        **_fence_common_arguments(config, state),
    }


def _fence_release_or_observe(
    client: Any,
    config: Mapping[str, Any],
    state_path: Path,
    state: Mapping[str, Any],
    pending: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        _fence_rpc(
            client,
            "release",
            {
                "session_id": pending["session_id"],
                "generation": pending["generation"],
                **_fence_common_arguments(config, state),
            },
        )
        return _fence_set_pending(state_path, state, None)
    except Exception as release_error:
        status = _fence_status(client, config, state)
        generation = int(status["generation"])
        writer = status.get("writer")
        inflight = status.get("inflight")
        if inflight is None and (
            writer is None
            or generation > int(pending["generation"])
            or not isinstance(writer, Mapping)
            or writer.get("owner_id") != config["peer_id"]
        ):
            return _fence_set_pending(
                state_path, state, None, minimum_generation_seen=generation
            )
        raise OperatorFenceEnforcementError("fence_release_unresolved") from release_error


def _fence_recover_pending(
    client: Any,
    config: Mapping[str, Any],
    config_sha256: str,
    state_path: Path,
    state: Mapping[str, Any],
) -> dict[str, Any]:
    pending = _fence_validate_pending(state.get("pending"))
    if pending is None:
        return dict(state)
    phase = pending["phase"]
    if phase == "outcome_unknown":
        status = _fence_status(client, config, state)
        settlement = status.get("last_settlement")
        if (
            status.get("inflight") is None
            and isinstance(settlement, Mapping)
            and settlement.get("generation") == pending["generation"]
            and settlement.get("owner_id") == config["peer_id"]
            and settlement.get("operation_id") == pending["operation_id"]
            and settlement.get("operation_name") == pending["operation_name"]
            and settlement.get("intent_sha256") == pending["intent_sha256"]
            and settlement.get("outcome") == "effect_applied"
            and settlement.get("resolution_source") == "reconcile"
        ):
            return _fence_set_pending(
                state_path,
                state,
                None,
                minimum_generation_seen=int(status["generation"]),
            )
        raise OperatorFenceEnforcementDenied("unresolved_inflight")
    if phase == "prepared":
        try:
            grant = _fence_rpc(
                client,
                "acquire",
                {
                    "session_id": pending["session_id"],
                    "reason": "g6.5_effect",
                    "lease_seconds": config["lease_seconds"],
                    **_fence_common_arguments(config, state),
                },
            )
        except OperatorFenceEnforcementDenied as denied:
            status = _fence_status(client, config, state)
            if denied.args and denied.args[0] == "writer_active" and status.get("inflight") is None:
                writer = status.get("writer")
                if not isinstance(writer, Mapping) or writer.get("owner_id") != config["peer_id"]:
                    return _fence_set_pending(
                        state_path,
                        state,
                        None,
                        minimum_generation_seen=int(status["generation"]),
                    )
            raise
        generation = _fence_validate_grant(grant, config, state)
        pending = {**pending, "phase": "granted", "generation": generation}
        state = _fence_set_pending(
            state_path, state, pending, minimum_generation_seen=generation
        )
        phase = "granted"
    if phase == "granted":
        pending = dict(state["pending"])
        _fence_rpc(
            client,
            "begin",
            {
                "session_id": pending["session_id"],
                "generation": pending["generation"],
                "operation_id": pending["operation_id"],
                "operation_name": pending["operation_name"],
                "intent_sha256": pending["intent_sha256"],
                **_fence_common_arguments(config, state),
            },
        )
        pending["phase"] = "begun"
        state = _fence_set_pending(state_path, state, pending)
        phase = "begun"
    if phase == "begun":
        pending = dict(state["pending"])
        evidence = _fence_pending_evidence(pending, "effect_not_applied")
        pending.update(
            phase="completion_ready",
            outcome="effect_not_applied",
            evidence_sha256=evidence,
        )
        state = _fence_set_pending(state_path, state, pending)
        phase = "completion_ready"
    if phase == "dispatching":
        pending = dict(state["pending"])
        evidence = _fence_pending_evidence(pending, "outcome_unknown")
        pending.update(
            phase="completion_ready",
            outcome="outcome_unknown",
            evidence_sha256=evidence,
        )
        state = _fence_set_pending(state_path, state, pending)
        phase = "completion_ready"
    if phase == "completion_ready":
        pending = dict(state["pending"])
        result = _fence_rpc(client, "settle", _fence_settle_arguments(config, state, pending))
        if pending["outcome"] == "outcome_unknown":
            pending["phase"] = "outcome_unknown"
            _fence_set_pending(state_path, state, pending)
            raise OperatorFenceEnforcementDenied("outcome_unknown")
        if result.get("terminal") is not True:
            raise OperatorFenceEnforcementError("fence_terminal_settlement_missing")
        pending["phase"] = "settled"
        state = _fence_set_pending(state_path, state, pending)
        phase = "settled"
    if phase == "settled":
        pending = dict(state["pending"])
        return _fence_release_or_observe(client, config, state_path, state, pending)
    raise OperatorFenceEnforcementError("unsupported_fence_recovery_phase")


def begin_fence_enforcement(
    admission: Mapping[str, Any],
    *,
    config_path: Path | None = None,
    state_path: Path | None = None,
    client_factory: Any = None,
) -> dict[str, Any] | None:
    config_target = FENCE_ENFORCEMENT_CONFIG_PATH if config_path is None else config_path
    state_target = FENCE_ENFORCEMENT_STATE_PATH if state_path is None else state_path
    try:
        config, config_sha256 = _fence_load_config(config_target)
    except FileNotFoundError:
        return None
    validated = receipts.validate_admission(admission)
    if not _FENCE_ENFORCEMENT_LOCK.acquire(timeout=FENCE_ENFORCEMENT_LOCK_TIMEOUT_SECONDS):
        raise OperatorFenceEnforcementDenied("local_effect_inflight")
    lock_held = True
    process_lock_fd: int | None = None
    try:
        process_lock_fd = _fence_acquire_process_lock(state_target)
        state = _fence_load_state(config, config_sha256, state_target)
        client = _fence_client(config, client_factory)
        if state.get("pending") is not None:
            state = _fence_recover_pending(
                client, config, config_sha256, state_target, state
            )
        if state.get("pending") is not None:
            raise OperatorFenceEnforcementDenied("pending_effect_unresolved")
        pending = {
            "session_id": uuid.uuid4().hex,
            "operation_id": validated["request_id"],
            "operation_name": validated["tool"],
            "intent_sha256": validated["admission_sha256"],
            "phase": "prepared",
            "generation": None,
            "outcome": None,
            "evidence_sha256": None,
            "created_at_unix": int(time.time()),
        }
        state = _fence_set_pending(state_target, state, pending)
        grant = _fence_rpc(
            client,
            "acquire",
            {
                "session_id": pending["session_id"],
                "reason": "g6.5_effect",
                "lease_seconds": config["lease_seconds"],
                **_fence_common_arguments(config, state),
            },
        )
        generation = _fence_validate_grant(grant, config, state)
        pending.update(phase="granted", generation=generation)
        state = _fence_set_pending(
            state_target, state, pending, minimum_generation_seen=generation
        )
        _fence_rpc(
            client,
            "begin",
            {
                "session_id": pending["session_id"],
                "generation": generation,
                "operation_id": pending["operation_id"],
                "operation_name": pending["operation_name"],
                "intent_sha256": pending["intent_sha256"],
                **_fence_common_arguments(config, state),
            },
        )
        pending["phase"] = "begun"
        state = _fence_set_pending(state_target, state, pending)
        token = {
            "config": dict(config),
            "config_sha256": config_sha256,
            "state_path": state_target,
            "client": client,
            "operation_id": pending["operation_id"],
            "process_lock_fd": process_lock_fd,
            "lock_held": True,
        }
        process_lock_fd = None
        lock_held = False
        return token
    finally:
        if process_lock_fd is not None:
            try:
                fcntl.flock(process_lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(process_lock_fd)
        if lock_held:
            _FENCE_ENFORCEMENT_LOCK.release()


def mark_fence_dispatching(token: Mapping[str, Any] | None) -> None:
    if token is None:
        return
    config = token["config"]
    state_path = token["state_path"]
    state = _fence_load_state(config, token["config_sha256"], state_path)
    pending = _fence_validate_pending(state.get("pending"))
    if (
        pending is None
        or pending["operation_id"] != token["operation_id"]
        or pending["phase"] != "begun"
    ):
        raise OperatorFenceEnforcementError("fence_dispatch_state_mismatch")
    pending["phase"] = "dispatching"
    _fence_set_pending(state_path, state, pending)


def _finish_fence_enforcement(
    token: Mapping[str, Any] | None,
    *,
    outcome: str,
    evidence_sha256: str,
) -> dict[str, Any] | None:
    if token is None:
        return None
    if outcome not in FENCE_ENFORCEMENT_TERMINAL_OUTCOMES | {"outcome_unknown"}:
        raise ValueError("unsupported fence enforcement outcome")
    if not isinstance(evidence_sha256, str) or _FENCE_SHA256_RE.fullmatch(evidence_sha256) is None:
        raise ValueError("fence evidence must be a lowercase SHA-256")
    config = token["config"]
    state_path = token["state_path"]
    client = token["client"]
    try:
        state = _fence_load_state(config, token["config_sha256"], state_path)
        pending = _fence_validate_pending(state.get("pending"))
        if (
            pending is None
            or pending["operation_id"] != token["operation_id"]
            or pending["phase"] != "dispatching"
        ):
            raise OperatorFenceEnforcementError("fence_completion_state_mismatch")
        pending.update(
            phase="completion_ready",
            outcome=outcome,
            evidence_sha256=evidence_sha256,
        )
        state = _fence_set_pending(state_path, state, pending)
        result = _fence_rpc(client, "settle", _fence_settle_arguments(config, state, pending))
        if outcome == "outcome_unknown":
            pending["phase"] = "outcome_unknown"
            _fence_set_pending(state_path, state, pending)
            return {"terminal": False, "outcome": outcome}
        if result.get("terminal") is not True:
            raise OperatorFenceEnforcementError("fence_terminal_settlement_missing")
        pending["phase"] = "settled"
        state = _fence_set_pending(state_path, state, pending)
        _fence_release_or_observe(client, config, state_path, state, pending)
        return {"terminal": True, "outcome": outcome}
    finally:
        _fence_release_locks(token)


def finish_fence_success(
    token: Mapping[str, Any] | None, *, evidence_sha256: str
) -> dict[str, Any] | None:
    return _finish_fence_enforcement(
        token, outcome="effect_applied", evidence_sha256=evidence_sha256
    )


def finish_fence_unknown(
    token: Mapping[str, Any] | None, *, evidence_sha256: str
) -> dict[str, Any] | None:
    return _finish_fence_enforcement(
        token, outcome="outcome_unknown", evidence_sha256=evidence_sha256
    )


def abort_fence_before_dispatch(token: Mapping[str, Any] | None) -> None:
    if token is None:
        return
    config = token["config"]
    state_path = token["state_path"]
    try:
        state = _fence_load_state(config, token["config_sha256"], state_path)
        pending = _fence_validate_pending(state.get("pending"))
        if pending is None or pending["operation_id"] != token["operation_id"]:
            raise OperatorFenceEnforcementError("fence_abort_state_mismatch")
        if pending["phase"] == "begun":
            evidence = _fence_pending_evidence(pending, "effect_not_applied")
            pending.update(
                phase="completion_ready",
                outcome="effect_not_applied",
                evidence_sha256=evidence,
            )
            state = _fence_set_pending(state_path, state, pending)
            _fence_rpc(token["client"], "settle", _fence_settle_arguments(config, state, pending))
            pending["phase"] = "settled"
            state = _fence_set_pending(state_path, state, pending)
            _fence_release_or_observe(token["client"], config, state_path, state, pending)
        elif pending["phase"] not in {"settled"}:
            raise OperatorFenceEnforcementError("fence_abort_after_dispatch_forbidden")
    finally:
        _fence_release_locks(token)


__all__ = [
    "FENCE_ENFORCEMENT_CONFIG_KIND",
    "FENCE_ENFORCEMENT_CONFIG_PATH",
    "FENCE_ENFORCEMENT_STATE_KIND",
    "FENCE_ENFORCEMENT_STATE_PATH",
    "OperatorFenceEnforcementDenied",
    "OperatorFenceEnforcementError",
    "abort_fence_before_dispatch",
    "begin_fence_enforcement",
    "fence_enforcement_required",
    "finish_fence_success",
    "finish_fence_unknown",
    "mark_fence_dispatching",
]
