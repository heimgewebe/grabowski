from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Any, Callable
import uuid

from grabowski_operator_fence import SCHEMA_VERSION as FENCE_SCHEMA_VERSION, STATUS_KIND
from grabowski_operator_fence_rpc import (
    OperatorFenceRpcError,
    OperatorFenceSshClient,
    request_document,
)


SCHEMA_VERSION = 1
CONFIG_KIND = "grabowski.operator_fence_shadow_config"
SNAPSHOT_KIND = "grabowski.operator_fence_shadow_snapshot"
OBSERVATION_KIND = "grabowski.operator_fence_shadow_observation"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "grabowski" / "operator-fence-shadow.v1.json"
DEFAULT_SNAPSHOT_PATH = Path.home() / ".local" / "state" / "grabowski" / "operator-fence-shadow-status.v1.json"
MAX_CONFIG_BYTES = 16 * 1024
MAX_SNAPSHOT_BYTES = 16 * 1024
MAX_SNAPSHOT_AGE_SECONDS = 15
REFRESH_TIMEOUT_SECONDS = 5
ClientFactory = Callable[..., OperatorFenceSshClient]


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


def _safe_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int | None = None,
) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or candidate.is_symlink():
        raise OperatorFenceShadowError("unsafe_file_path")
    try:
        info = candidate.stat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise OperatorFenceShadowError("unreadable_file") from exc
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_size < 2
        or info.st_size > maximum_bytes
        or (exact_mode is None and mode & 0o022)
        or (exact_mode is not None and mode != exact_mode)
    ):
        raise OperatorFenceShadowError("unsafe_file")
    return candidate


def _load_json_file(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int | None = None,
) -> tuple[dict[str, Any], str]:
    safe = _safe_regular_file(
        path,
        maximum_bytes=maximum_bytes,
        exact_mode=exact_mode,
    )
    try:
        raw = safe.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorFenceShadowError("invalid_json_file") from exc
    if not isinstance(value, dict):
        raise OperatorFenceShadowError("invalid_json_shape")
    return dict(value), hashlib.sha256(raw).hexdigest()


def _load_config(path: Path) -> tuple[dict[str, Any], str]:
    value, digest = _load_json_file(
        path,
        maximum_bytes=MAX_CONFIG_BYTES,
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
    if set(value) != required:
        raise OperatorFenceShadowError("invalid_config_shape")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != CONFIG_KIND:
        raise OperatorFenceShadowError("unsupported_config_contract")
    if value.get("mode") != "shadow":
        raise OperatorFenceShadowError("unsupported_mode")
    for field in required - {"schema_version"}:
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise OperatorFenceShadowError(f"invalid_{field}")
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
    if (
        result.get("schema_version") != FENCE_SCHEMA_VERSION
        or result.get("kind") != STATUS_KIND
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 0
        or not isinstance(result.get("instance_id"), str)
        or not result["instance_id"]
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
        "instance_id": result["instance_id"],
        "generation": generation,
        "clock_regressed": result["clock_regressed"],
        "writer_owner_id": writer_owner,
        "writer_lease_active": writer_lease_active,
        "inflight_present": inflight is not None,
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


def _snapshot_material(
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
    if set(value) != required:
        raise OperatorFenceShadowError("invalid_snapshot_shape")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != SNAPSHOT_KIND:
        raise OperatorFenceShadowError("unsupported_snapshot_contract")
    material = {key: value[key] for key in required if key != "snapshot_sha256"}
    claimed = value.get("snapshot_sha256")
    if (
        not isinstance(claimed, str)
        or len(claimed) != 64
        or _sha256_json(material) != claimed
    ):
        raise OperatorFenceShadowError("snapshot_digest_mismatch")
    observed_at = value.get("observed_at_unix")
    if isinstance(observed_at, bool) or not isinstance(observed_at, int) or observed_at < 0:
        raise OperatorFenceShadowError("invalid_snapshot_time")
    return dict(value)


def _safe_snapshot_parent(path: Path) -> Path:
    parent = path.expanduser().parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink():
        raise OperatorFenceShadowError("unsafe_snapshot_parent")
    info = parent.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise OperatorFenceShadowError("unsafe_snapshot_parent")
    return parent


def _write_snapshot(path: Path, material: Mapping[str, Any]) -> dict[str, Any]:
    target = path.expanduser()
    if not target.is_absolute() or target.is_symlink():
        raise OperatorFenceShadowError("unsafe_snapshot_path")
    parent = _safe_snapshot_parent(target)
    document = dict(material)
    document["snapshot_sha256"] = _sha256_json(document)
    payload = _canonical_bytes(document) + b"\n"
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise OperatorFenceShadowError("snapshot_too_large")
    temporary = parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short snapshot write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    os.chmod(target, 0o600)
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return document


def refresh_snapshot(
    *,
    config_path: Path | None = None,
    snapshot_path: Path | None = None,
    client_factory: ClientFactory = OperatorFenceSshClient,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    config_target = DEFAULT_CONFIG_PATH if config_path is None else config_path
    snapshot_target = DEFAULT_SNAPSHOT_PATH if snapshot_path is None else snapshot_path
    now = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise OperatorFenceShadowError("invalid_observed_time")
    try:
        config, config_sha256 = _load_config(config_target)
    except FileNotFoundError:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": SNAPSHOT_KIND,
            "status": "disabled",
            "reason": "config_absent",
        }
    peer_id = config["peer_id"]
    try:
        client = client_factory(
            host=config["host"],
            remote_user=config["remote_user"],
            expected_peer_id=peer_id,
            known_hosts_path=config["known_hosts_path"],
            identity_file=config["identity_file"],
            host_key_alias=config["host_key_alias"],
            timeout_seconds=REFRESH_TIMEOUT_SECONDS,
        )
        response = client.call(
            request_document(
                request_id="shadow-status-" + uuid.uuid4().hex,
                operation="status",
                arguments={},
            )
        )
        summary = _status_summary(response)
    except (OperatorFenceRpcError, OperatorFenceShadowError, OSError, ValueError):
        summary = {
            "authority_status": "unavailable",
            "reason": "status_transport_or_contract_failed",
            "instance_id": None,
            "generation": None,
            "clock_regressed": None,
            "writer_owner_id": None,
            "writer_lease_active": None,
            "inflight_present": None,
        }
    material = _snapshot_material(
        config_sha256=config_sha256,
        peer_id=peer_id,
        observed_at_unix=now,
        summary=summary,
    )
    return _write_snapshot(snapshot_target, material)


def observe(
    *,
    tool_name: str,
    arguments_sha256: str,
    config_path: Path | None = None,
    snapshot_path: Path | None = None,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    config_target = DEFAULT_CONFIG_PATH if config_path is None else config_path
    snapshot_target = DEFAULT_SNAPSHOT_PATH if snapshot_path is None else snapshot_path
    now = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise OperatorFenceShadowError("invalid_observed_time")
    try:
        config, config_sha256 = _load_config(config_target)
    except FileNotFoundError:
        material = {
            "schema_version": SCHEMA_VERSION,
            "kind": OBSERVATION_KIND,
            "mode": "off",
            "status": "disabled",
            "decision": "not_observed",
            "reason": "config_absent",
            "peer_id": None,
            "tool": tool_name,
            "arguments_sha256": arguments_sha256,
            "snapshot_sha256": None,
            "snapshot_age_seconds": None,
            "instance_id": None,
            "generation": None,
            "writer_owner_id": None,
            "inflight_present": None,
        }
    except OperatorFenceShadowError as exc:
        material = {
            "schema_version": SCHEMA_VERSION,
            "kind": OBSERVATION_KIND,
            "mode": "shadow",
            "status": "config_error",
            "decision": "unavailable",
            "reason": str(exc),
            "peer_id": None,
            "tool": tool_name,
            "arguments_sha256": arguments_sha256,
            "snapshot_sha256": None,
            "snapshot_age_seconds": None,
            "instance_id": None,
            "generation": None,
            "writer_owner_id": None,
            "inflight_present": None,
        }
    else:
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
            material = {
                "schema_version": SCHEMA_VERSION,
                "kind": OBSERVATION_KIND,
                "mode": "shadow",
                "status": snapshot["authority_status"],
                "decision": decision,
                "reason": reason,
                "peer_id": peer_id,
                "tool": tool_name,
                "arguments_sha256": arguments_sha256,
                "snapshot_sha256": snapshot["snapshot_sha256"],
                "snapshot_age_seconds": age,
                "instance_id": snapshot["instance_id"],
                "generation": snapshot["generation"],
                "writer_owner_id": snapshot["writer_owner_id"],
                "inflight_present": snapshot["inflight_present"],
            }
        except FileNotFoundError:
            material = {
                "schema_version": SCHEMA_VERSION,
                "kind": OBSERVATION_KIND,
                "mode": "shadow",
                "status": "snapshot_missing",
                "decision": "unavailable",
                "reason": "snapshot_missing",
                "peer_id": peer_id,
                "tool": tool_name,
                "arguments_sha256": arguments_sha256,
                "snapshot_sha256": None,
                "snapshot_age_seconds": None,
                "instance_id": None,
                "generation": None,
                "writer_owner_id": None,
                "inflight_present": None,
            }
        except OperatorFenceShadowError as exc:
            material = {
                "schema_version": SCHEMA_VERSION,
                "kind": OBSERVATION_KIND,
                "mode": "shadow",
                "status": "snapshot_error",
                "decision": "unavailable",
                "reason": str(exc),
                "peer_id": peer_id,
                "tool": tool_name,
                "arguments_sha256": arguments_sha256,
                "snapshot_sha256": None,
                "snapshot_age_seconds": None,
                "instance_id": None,
                "generation": None,
                "writer_owner_id": None,
                "inflight_present": None,
            }
    material["observation_sha256"] = _sha256_json(material)
    material["does_not_establish"] = [
        "mutation_authority",
        "writer_acquisition",
        "effect_finality",
        "safe_failover",
    ]
    return material


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh the read-only operator-fence shadow snapshot.")
    parser.add_argument("command", choices=("refresh",))
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    parser.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT_PATH))
    arguments = parser.parse_args(argv)
    result = refresh_snapshot(
        config_path=Path(arguments.config),
        snapshot_path=Path(arguments.snapshot),
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CONFIG_KIND",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_SNAPSHOT_PATH",
    "MAX_SNAPSHOT_AGE_SECONDS",
    "OBSERVATION_KIND",
    "OperatorFenceShadowError",
    "SCHEMA_VERSION",
    "SNAPSHOT_KIND",
    "main",
    "observe",
    "refresh_snapshot",
]
