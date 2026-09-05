from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from grabowski_operator_fence import SCHEMA_VERSION as FENCE_SCHEMA_VERSION, STATUS_KIND


SCHEMA_VERSION = 1
CONFIG_KIND = "grabowski.operator_fence_shadow_config"
SNAPSHOT_KIND = "grabowski.operator_fence_shadow_snapshot"
OBSERVATION_KIND = "grabowski.operator_fence_shadow_observation"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "grabowski" / "operator-fence-shadow.v1.json"
DEFAULT_SNAPSHOT_PATH = Path.home() / ".local" / "state" / "grabowski" / "operator-fence-shadow-status.v1.json"
MAX_CONFIG_BYTES = 16 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024
MAX_SNAPSHOT_AGE_SECONDS = 15
MAX_TOOL_NAME_BYTES = 255
MAX_JSON_CACHE_ENTRIES = 8
PEER_IDS = frozenset({"grabowski", "der-kleine-maulwurf"})
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DOES_NOT_ESTABLISH = (
    "mutation_authority",
    "writer_acquisition",
    "effect_finality",
    "safe_failover",
)


class OperatorFenceShadowError(RuntimeError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_signature(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_uid,
        info.st_nlink,
    )


_JSON_CACHE: dict[
    tuple[str, int, int],
    tuple[tuple[int, int, int, int, int, int, int, int], dict[str, Any], str],
] = {}


def _open_owned_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int,
) -> tuple[int, os.stat_result, Path]:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise OperatorFenceShadowError("unsafe_file_path")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OperatorFenceShadowError("unreadable_file") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_size < 2
            or info.st_size > maximum_bytes
            or stat.S_IMODE(info.st_mode) != exact_mode
        ):
            raise OperatorFenceShadowError("unsafe_file")
        return descriptor, info, candidate
    except BaseException:
        os.close(descriptor)
        raise


def _load_json_file(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int,
) -> tuple[dict[str, Any], str]:
    descriptor, before, candidate = _open_owned_regular_file(
        path,
        maximum_bytes=maximum_bytes,
        exact_mode=exact_mode,
    )
    cache_key = (str(candidate), maximum_bytes, exact_mode)
    signature = _file_signature(before)
    try:
        cached = _JSON_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            return dict(cached[1]), cached[2]
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > maximum_bytes or _file_signature(after) != signature:
            raise OperatorFenceShadowError("file_changed_during_read")
    except OSError as exc:
        raise OperatorFenceShadowError("unreadable_file") from exc
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorFenceShadowError("invalid_json_file") from exc
    if not isinstance(value, dict):
        raise OperatorFenceShadowError("invalid_json_shape")
    material = dict(value)
    digest = _sha256_json(material)
    if cache_key not in _JSON_CACHE and len(_JSON_CACHE) >= MAX_JSON_CACHE_ENTRIES:
        _JSON_CACHE.clear()
    _JSON_CACHE[cache_key] = (signature, material, digest)
    return dict(material), digest


def _validate_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    allowed: set[str],
    error: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing or unknown:
        raise OperatorFenceShadowError(error)


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def _validate_peer_id(value: Any) -> str:
    if not isinstance(value, str) or value not in PEER_IDS:
        raise OperatorFenceShadowError("invalid_peer_id")
    return value


def _load_config(path: Path) -> tuple[dict[str, Any], str]:
    value, digest = _load_json_file(
        path,
        maximum_bytes=MAX_CONFIG_BYTES,
        exact_mode=0o600,
    )
    required = {
        "schema_version",
        "kind",
        "mode",
        "host",
        "remote_user",
        "peer_id",
        "known_hosts_path",
        "identity_file",
        "host_key_alias",
    }
    _validate_keys(value, required=required, allowed=set(required), error="invalid_config_shape")
    schema_version = value.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
        or value.get("kind") != CONFIG_KIND
    ):
        raise OperatorFenceShadowError("unsupported_config_contract")
    if value.get("mode") != "shadow":
        raise OperatorFenceShadowError("unsupported_mode")
    for field in required - {"schema_version", "peer_id"}:
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise OperatorFenceShadowError(f"invalid_{field}")
    _validate_peer_id(value.get("peer_id"))
    return value, digest


def _bounded_writer(result: Mapping[str, Any]) -> tuple[str | None, bool | None]:
    writer = result.get("writer")
    if writer is None:
        return None, None
    if not isinstance(writer, Mapping):
        raise OperatorFenceShadowError("invalid_writer_status")
    owner = writer.get("owner_id")
    lease_active = writer.get("lease_active")
    if (
        not isinstance(owner, str)
        or not owner
        or len(owner.encode("utf-8")) > 160
        or not isinstance(lease_active, bool)
    ):
        raise OperatorFenceShadowError("invalid_writer_status")
    return owner, lease_active


def _status_summary(response: Mapping[str, Any]) -> dict[str, Any]:
    if response.get("ok") is not True or not isinstance(response.get("result"), Mapping):
        raise OperatorFenceShadowError("status_rpc_not_ok")
    result = response["result"]
    generation = result.get("generation")
    instance_id = result.get("instance_id")
    if (
        result.get("schema_version") != FENCE_SCHEMA_VERSION
        or result.get("kind") != STATUS_KIND
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
        or not isinstance(instance_id, str)
        or not instance_id
        or not isinstance(result.get("clock_regressed"), bool)
    ):
        raise OperatorFenceShadowError("invalid_status_contract")
    writer_owner, writer_lease_active = _bounded_writer(result)
    inflight = result.get("inflight")
    if inflight is not None and not isinstance(inflight, Mapping):
        raise OperatorFenceShadowError("invalid_inflight_status")
    if inflight is not None and writer_owner is None:
        raise OperatorFenceShadowError("invalid_inflight_status")
    return {
        "authority_status": "observed",
        "reason": "status_observed",
        "instance_id": instance_id,
        "generation": generation,
        "clock_regressed": result["clock_regressed"],
        "writer_owner_id": writer_owner,
        "writer_lease_active": writer_lease_active,
        "inflight_present": inflight is not None,
    }


def unavailable_summary(reason: str = "status_transport_or_contract_failed") -> dict[str, Any]:
    return {
        "authority_status": "unavailable",
        "reason": reason,
        "instance_id": None,
        "generation": None,
        "clock_regressed": None,
        "writer_owner_id": None,
        "writer_lease_active": None,
        "inflight_present": None,
    }


def _decision(*, peer_id: str, summary: Mapping[str, Any]) -> tuple[str, str]:
    if summary.get("authority_status") != "observed":
        return "unavailable", str(summary.get("reason") or "authority_unavailable")
    if summary.get("clock_regressed") is True:
        return "would_deny", "clock_regressed"
    if summary.get("inflight_present") is True:
        return "would_deny", "inflight_present"
    writer_owner = summary.get("writer_owner_id")
    lease_active = summary.get("writer_lease_active")
    if writer_owner is None or lease_active is False:
        return "would_acquire", "writer_idle_or_expired"
    if writer_owner == peer_id:
        return "would_continue", "same_writer"
    return "would_deny", "writer_active"


def snapshot_material(
    *,
    config_sha256: str,
    peer_id: str,
    observed_at_unix: int,
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": SNAPSHOT_KIND,
        "config_sha256": config_sha256,
        "peer_id": peer_id,
        "observed_at_unix": observed_at_unix,
        "authority_status": summary.get("authority_status"),
        "reason": summary.get("reason"),
        "instance_id": summary.get("instance_id"),
        "generation": summary.get("generation"),
        "clock_regressed": summary.get("clock_regressed"),
        "writer_owner_id": summary.get("writer_owner_id"),
        "writer_lease_active": summary.get("writer_lease_active"),
        "inflight_present": summary.get("inflight_present"),
    }


def _validate_snapshot_types(value: Mapping[str, Any]) -> None:
    if not _valid_sha256(value.get("config_sha256")):
        raise OperatorFenceShadowError("invalid_snapshot_config_sha256")
    _validate_peer_id(value.get("peer_id"))
    observed_at = value.get("observed_at_unix")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise OperatorFenceShadowError("invalid_snapshot_time")
    authority_status = value.get("authority_status")
    reason = value.get("reason")
    if authority_status not in {"observed", "unavailable"}:
        raise OperatorFenceShadowError("invalid_snapshot_authority_status")
    if not isinstance(reason, str) or not reason or len(reason.encode("utf-8")) > 256:
        raise OperatorFenceShadowError("invalid_snapshot_reason")
    if authority_status == "unavailable":
        for field in (
            "instance_id",
            "generation",
            "clock_regressed",
            "writer_owner_id",
            "writer_lease_active",
            "inflight_present",
        ):
            if value.get(field) is not None:
                raise OperatorFenceShadowError("invalid_unavailable_snapshot")
        return
    instance_id = value.get("instance_id")
    generation = value.get("generation")
    clock_regressed = value.get("clock_regressed")
    writer_owner = value.get("writer_owner_id")
    writer_lease_active = value.get("writer_lease_active")
    inflight_present = value.get("inflight_present")
    if not isinstance(instance_id, str) or not instance_id:
        raise OperatorFenceShadowError("invalid_snapshot_instance_id")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        raise OperatorFenceShadowError("invalid_snapshot_generation")
    if not isinstance(clock_regressed, bool) or not isinstance(inflight_present, bool):
        raise OperatorFenceShadowError("invalid_snapshot_boolean")
    if writer_owner is None:
        if writer_lease_active is not None or inflight_present:
            raise OperatorFenceShadowError("invalid_snapshot_writer_state")
    elif (
        not isinstance(writer_owner, str)
        or not writer_owner
        or len(writer_owner.encode("utf-8")) > 160
        or not isinstance(writer_lease_active, bool)
    ):
        raise OperatorFenceShadowError("invalid_snapshot_writer_state")


def _validate_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "kind",
        "config_sha256",
        "peer_id",
        "observed_at_unix",
        "authority_status",
        "reason",
        "instance_id",
        "generation",
        "clock_regressed",
        "writer_owner_id",
        "writer_lease_active",
        "inflight_present",
        "snapshot_sha256",
    }
    _validate_keys(value, required=required, allowed=set(required), error="invalid_snapshot_shape")
    schema_version = value.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != SCHEMA_VERSION
        or value.get("kind") != SNAPSHOT_KIND
    ):
        raise OperatorFenceShadowError("unsupported_snapshot_contract")
    claimed = value.get("snapshot_sha256")
    if not _valid_sha256(claimed):
        raise OperatorFenceShadowError("snapshot_digest_mismatch")
    material = {key: value[key] for key in required if key != "snapshot_sha256"}
    if _sha256_json(material) != claimed:
        raise OperatorFenceShadowError("snapshot_digest_mismatch")
    _validate_snapshot_types(value)
    return dict(value)


def _validate_observation_inputs(*, tool_name: str, arguments_sha256: str) -> None:
    if (
        not isinstance(tool_name, str)
        or not tool_name.strip()
        or len(tool_name.encode("utf-8")) > MAX_TOOL_NAME_BYTES
    ):
        raise OperatorFenceShadowError("invalid_tool_name")
    if not _valid_sha256(arguments_sha256):
        raise OperatorFenceShadowError("invalid_arguments_sha256")


def _observation(
    *,
    tool_name: str,
    arguments_sha256: str,
    mode: str = "shadow",
    status: str,
    decision: str,
    reason: str,
    peer_id: str | None = None,
    snapshot_sha256: str | None = None,
    snapshot_age_seconds: int | None = None,
    instance_id: str | None = None,
    generation: int | None = None,
    writer_owner_id: str | None = None,
    inflight_present: bool | None = None,
) -> dict[str, Any]:
    _validate_observation_inputs(tool_name=tool_name, arguments_sha256=arguments_sha256)
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": OBSERVATION_KIND,
        "mode": mode,
        "status": status,
        "decision": decision,
        "reason": reason,
        "peer_id": peer_id,
        "tool": tool_name,
        "arguments_sha256": arguments_sha256,
        "snapshot_sha256": snapshot_sha256,
        "snapshot_age_seconds": snapshot_age_seconds,
        "instance_id": instance_id,
        "generation": generation,
        "writer_owner_id": writer_owner_id,
        "inflight_present": inflight_present,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }
    # Contract: observation_sha256 covers the complete returned observation
    # material except the observation_sha256 field itself. In particular,
    # does_not_establish is integrity-bound and may not be appended afterward.
    document = dict(material)
    document["observation_sha256"] = _sha256_json(material)
    return document


def observation_from_error(
    *,
    tool_name: str,
    arguments_sha256: str,
    error: BaseException,
) -> dict[str, Any]:
    return _observation(
        tool_name=tool_name,
        arguments_sha256=arguments_sha256,
        status="observer_error",
        decision="unavailable",
        reason=type(error).__name__,
    )


def observe(
    *,
    tool_name: str,
    arguments_sha256: str,
    config_path: Path | None = None,
    snapshot_path: Path | None = None,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    _validate_observation_inputs(tool_name=tool_name, arguments_sha256=arguments_sha256)
    config_target = DEFAULT_CONFIG_PATH if config_path is None else config_path
    snapshot_target = DEFAULT_SNAPSHOT_PATH if snapshot_path is None else snapshot_path
    now = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise OperatorFenceShadowError("invalid_observed_time")
    try:
        config, config_sha256 = _load_config(config_target)
    except FileNotFoundError:
        return _observation(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            mode="off",
            status="disabled",
            decision="not_observed",
            reason="config_absent",
        )
    except OperatorFenceShadowError as exc:
        return _observation(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            status="config_error",
            decision="unavailable",
            reason=str(exc),
        )
    peer_id = config["peer_id"]
    try:
        snapshot_value, _file_sha256 = _load_json_file(
            snapshot_target,
            maximum_bytes=MAX_SNAPSHOT_BYTES,
            exact_mode=0o600,
        )
        snapshot = _validate_snapshot(snapshot_value)
        if snapshot["config_sha256"] != config_sha256 or snapshot["peer_id"] != peer_id:
            raise OperatorFenceShadowError("snapshot_config_drift")
        snapshot_time = snapshot["observed_at_unix"]
        if now < snapshot_time:
            raise OperatorFenceShadowError("snapshot_from_future")
        age = now - snapshot_time
        if age > MAX_SNAPSHOT_AGE_SECONDS:
            raise OperatorFenceShadowError("snapshot_stale")
        decision, reason = _decision(peer_id=peer_id, summary=snapshot)
        return _observation(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            status=snapshot["authority_status"],
            decision=decision,
            reason=reason,
            peer_id=peer_id,
            snapshot_sha256=snapshot["snapshot_sha256"],
            snapshot_age_seconds=age,
            instance_id=snapshot["instance_id"],
            generation=snapshot["generation"],
            writer_owner_id=snapshot["writer_owner_id"],
            inflight_present=snapshot["inflight_present"],
        )
    except FileNotFoundError:
        return _observation(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            status="snapshot_missing",
            decision="unavailable",
            reason="snapshot_missing",
            peer_id=peer_id,
        )
    except OperatorFenceShadowError as exc:
        return _observation(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
            status="snapshot_error",
            decision="unavailable",
            reason=str(exc),
            peer_id=peer_id,
        )


__all__ = [
    "CONFIG_KIND",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_SNAPSHOT_PATH",
    "MAX_SNAPSHOT_AGE_SECONDS",
    "OBSERVATION_KIND",
    "OperatorFenceShadowError",
    "SCHEMA_VERSION",
    "SNAPSHOT_KIND",
    "observation_from_error",
    "observe",
]
