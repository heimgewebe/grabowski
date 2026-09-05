from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Any, Callable
import uuid

import grabowski_operator_fence_shadow as shadow
from grabowski_operator_fence_rpc import OperatorFenceSshClient, request_document


REFRESH_TIMEOUT_SECONDS = 5
ClientFactory = Callable[..., OperatorFenceSshClient]


def _directory_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_snapshot_parent(target: Path, *, create: bool) -> tuple[Path, int]:
    expanded = target.expanduser()
    if not expanded.is_absolute() or not expanded.name:
        raise shadow.OperatorFenceShadowError("unsafe_snapshot_path")
    parent = expanded.parent
    flags = _directory_flags()
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
                raise shadow.OperatorFenceShadowError("unsafe_snapshot_parent") from exc
            os.close(descriptor)
            descriptor = next_descriptor
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise shadow.OperatorFenceShadowError("unsafe_snapshot_parent")
        return parent, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short snapshot write")
        view = view[written:]


def _write_snapshot(path: Path, material: Mapping[str, Any]) -> dict[str, Any]:
    target = path.expanduser()
    parent, parent_fd = _open_snapshot_parent(target, create=True)
    document = dict(material)
    document["snapshot_sha256"] = shadow._sha256_json(document)
    payload = shadow._canonical_bytes(document) + b"\n"
    if len(payload) > shadow.MAX_SNAPSHOT_BYTES:
        os.close(parent_fd)
        raise shadow.OperatorFenceShadowError("snapshot_too_large")
    temporary_name = f".{target.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    temporary_exists = False
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        temporary_exists = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_exists = False
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    return document


def _remove_snapshot(path: Path) -> None:
    target = path.expanduser()
    try:
        _parent, parent_fd = _open_snapshot_parent(target, create=False)
    except FileNotFoundError:
        return
    try:
        try:
            info = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            raise shadow.OperatorFenceShadowError("unsafe_snapshot_path")
        os.unlink(target.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def refresh_snapshot(
    *,
    config_path: Path | None = None,
    snapshot_path: Path | None = None,
    client_factory: ClientFactory = OperatorFenceSshClient,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    config_target = shadow.DEFAULT_CONFIG_PATH if config_path is None else config_path
    snapshot_target = shadow.DEFAULT_SNAPSHOT_PATH if snapshot_path is None else snapshot_path
    now = int(time.time()) if observed_at_unix is None else observed_at_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise shadow.OperatorFenceShadowError("invalid_observed_time")
    try:
        config, config_sha256 = shadow._load_config(config_target)
    except FileNotFoundError:
        _remove_snapshot(snapshot_target)
        return {
            "schema_version": shadow.SCHEMA_VERSION,
            "kind": shadow.SNAPSHOT_KIND,
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
        summary = shadow._status_summary(response)
    except Exception:
        summary = shadow.unavailable_summary()
    material = shadow.snapshot_material(
        config_sha256=config_sha256,
        peer_id=peer_id,
        observed_at_unix=now,
        summary=summary,
    )
    return _write_snapshot(snapshot_target, material)


def _exit_code(result: Mapping[str, Any]) -> int:
    if result.get("status") == "disabled":
        return 0
    if result.get("authority_status") == "observed":
        return 0
    if result.get("authority_status") == "unavailable":
        return 2
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refresh the read-only operator-fence shadow snapshot.")
    parser.add_argument("command", choices=("refresh",))
    parser.add_argument("--config", default=str(shadow.DEFAULT_CONFIG_PATH))
    parser.add_argument("--snapshot", default=str(shadow.DEFAULT_SNAPSHOT_PATH))
    arguments = parser.parse_args(argv)
    try:
        result = refresh_snapshot(
            config_path=Path(arguments.config),
            snapshot_path=Path(arguments.snapshot),
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": shadow.SCHEMA_VERSION,
                    "kind": shadow.SNAPSHOT_KIND,
                    "status": "error",
                    "reason": type(exc).__name__,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return _exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["REFRESH_TIMEOUT_SECONDS", "main", "refresh_snapshot"]
