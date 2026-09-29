#!/usr/bin/env python3
"""Narrow privileged runner for the Heim-PC critical-user-data inventory."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any

SCHEMA_VERSION = 1
RESULT_KIND = "grabowski.critical_user_data_inventory_result.v1"
INVENTORY_KIND = "heim_pc.critical_user_data_aggregate_inventory.v1"
INVENTORY_ALGORITHM = "member-inventory-sha256-v1"
MEMBER_INVENTORY_KIND = "heim_pc.critical_user_data_inventory.v1"
MEMBER_INVENTORY_ALGORITHM = "canonical-record-stream-sha256-v1"
SCOPE_KIND = "heim_pc.critical_user_data_scope_contract"
SCOPE_SEMANTICS = "explicit-root-set-default-include"
SCANNER_SOURCE = Path(
    "/home/alex/repos/.grabowski-worktrees/"
    "heim-pc-critical-user-data-scope-20260928/"
    "scripts/nixos_critical_user_data_inventory.py"
)
CONTRACT_SOURCE = Path(
    "/home/alex/repos/.grabowski-worktrees/"
    "heim-pc-critical-user-data-scope-20260928/"
    "nixos/production/critical-user-data-contract-v1.json"
)
SCANNER_SHA256 = ""
CONTRACT_SHA256 = ""
HELPER = Path("/usr/local/libexec/grabowski-critical-user-data-inventory")
PYTHON = Path("/usr/bin/python3")
DOCKER = Path("/usr/bin/docker")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
STATE_ROOT = Path("/var/lib/grabowski/critical-user-data-inventory")
SNAPSHOT_ROOT = STATE_ROOT / "unbound"
SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "inventory.py"
CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-data-contract-v1.json"
RESULT_PATH = SNAPSHOT_ROOT / "result.json"
FAILED_ROOT = SNAPSHOT_ROOT / "failed-results"
LOCK_PATH = SNAPSHOT_ROOT / "operation.lock"
UNIT = "grabowski-critical-user-data-inventory-unbound.service"
RUNTIME_SECONDS = 6 * 60 * 60
SCANNER_TIMEOUT_SECONDS = (RUNTIME_SECONDS - 300) // 2
MAX_SCANNER_BYTES = 2 * 1024 * 1024
MAX_CONTRACT_BYTES = 512 * 1024
MAX_SCANNER_OUTPUT_BYTES = 128 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_DOCKER_EVENT_OUTPUT_BYTES = 64 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CLASS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

MEMBER_IDENTITIES: dict[str, dict[str, Any]] = {
    "home": {
        "source": CONTRACT_SOURCE.with_name("critical-user-home-data-contract-v1.json"),
        "snapshot_name": "critical-user-home-data-contract-v1.json",
        "scope": "critical-user-data-home",
        "scope_semantics": "whole-home-by-default",
        "root": "/home/alex",
        "destination": {
            "nixos_storage_domain": "@home",
            "logical_path": "/home/alex",
        },
        "restore_mode": "active-user-data",
    },
    "docker-volumes": {
        "source": CONTRACT_SOURCE.with_name("critical-docker-volume-data-contract-v1.json"),
        "snapshot_name": "critical-docker-volume-data-contract-v1.json",
        "scope": "critical-user-data-docker-volumes",
        "scope_semantics": "whole-root-by-default",
        "root": "/var/lib/docker/volumes",
        "destination": {
            "nixos_storage_domain": "@data",
            "logical_path": "/var/lib/heim-pc-data/legacy-docker-volumes",
        },
        "restore_mode": "staged-archive-not-active-docker-store",
    },
}

MEMBER_INVENTORY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "scope",
        "root",
        "algorithm",
        "critical_scope_sha256",
        "contract_sha256",
        "authoritative_inventory",
        "inventory_sha256",
        "record_count",
        "type_counts",
        "regular_file_bytes",
        "exclusion_boundary_count",
        "exclusion_boundary_sha256",
        "exclusion_class_counts",
        "exclusion_samples",
        "production_effects_authorized",
    }
)
INVENTORY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "scope",
        "scope_semantics",
        "algorithm",
        "critical_scope_sha256",
        "contract_sha256",
        "authoritative_inventory",
        "inventory_sha256",
        "member_count",
        "record_count",
        "type_counts",
        "regular_file_bytes",
        "exclusion_boundary_count",
        "exclusion_boundary_sha256",
        "exclusion_class_counts",
        "exclusion_samples",
        "production_effects_authorized",
    }
)


class InventoryHelperError(RuntimeError):
    pass


def _validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise InventoryHelperError(f"{label} is invalid")
    return value


def _apply_binding(scanner_sha256: str, contract_sha256: str) -> None:
    global SCANNER_SHA256, CONTRACT_SHA256
    global SNAPSHOT_ROOT, SCANNER_SNAPSHOT, CONTRACT_SNAPSHOT
    global RESULT_PATH, FAILED_ROOT, LOCK_PATH, UNIT

    scanner = _validate_digest(scanner_sha256, "scanner_sha256")
    contract = _validate_digest(contract_sha256, "contract_sha256")
    SCANNER_SHA256 = scanner
    CONTRACT_SHA256 = contract
    SNAPSHOT_ROOT = STATE_ROOT / f"source-{scanner}-{contract}"
    SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "inventory.py"
    CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-data-contract-v1.json"
    RESULT_PATH = SNAPSHOT_ROOT / "result.json"
    FAILED_ROOT = SNAPSHOT_ROOT / "failed-results"
    LOCK_PATH = SNAPSHOT_ROOT / "operation.lock"
    UNIT = (
        "grabowski-critical-user-data-inventory-"
        f"{scanner}-{contract}.service"
    )


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_stable_regular(
    path: Path,
    *,
    max_bytes: int,
    require_root_owned: bool = False,
    required_mode: int | None = None,
) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise InventoryHelperError("inventory input is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > max_bytes
        or (require_root_owned and before.st_uid != 0)
        or (
            required_mode is not None
            and stat.S_IMODE(before.st_mode) != required_mode
        )
    ):
        raise InventoryHelperError("inventory input metadata is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InventoryHelperError("inventory input cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise InventoryHelperError("inventory input changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise InventoryHelperError("inventory input exceeds size bound")
            chunks.append(block)
        after = os.fstat(descriptor)
        if _identity(after) != _identity(opened):
            raise InventoryHelperError("inventory input changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_parent(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InventoryHelperError("inventory state parent is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise InventoryHelperError("inventory state parent is unsafe")


def _ensure_private_directory(path: Path) -> None:
    _validate_parent(path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise InventoryHelperError("inventory private directory is unsafe")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_create_only(path: Path, payload: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError:
        existing = _read_stable_regular(
            path,
            max_bytes=max(len(payload), 1),
            require_root_owned=True,
            required_mode=mode,
        )
        if existing != payload:
            raise InventoryHelperError("existing inventory state differs")
        return
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, 0)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise InventoryHelperError("inventory state write was incomplete")
            offset += written
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
        ):
            raise InventoryHelperError("inventory state file metadata is unsafe")
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _member_snapshot(member_id: str) -> Path:
    identity = MEMBER_IDENTITIES.get(member_id)
    if identity is None:
        raise InventoryHelperError("inventory member identity is invalid")
    return SNAPSHOT_ROOT / str(identity["snapshot_name"])


def _validate_contract(payload: bytes) -> dict[str, str]:
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("critical-user-data contract is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != SCOPE_KIND
        or value.get("scope") != "critical-user-data"
        or value.get("scope_semantics") != SCOPE_SEMANTICS
    ):
        raise InventoryHelperError("critical-user-data contract identity mismatch")

    members = value.get("members")
    if not isinstance(members, list) or len(members) != len(MEMBER_IDENTITIES):
        raise InventoryHelperError("critical-user-data member set is invalid")
    observed: dict[str, dict[str, Any]] = {}
    required_keys = {
        "id",
        "contract_file",
        "contract_sha256",
        "destination",
        "restore_mode",
    }
    for item in members:
        if not isinstance(item, dict) or set(item) != required_keys:
            raise InventoryHelperError("critical-user-data member identity is invalid")
        member_id = item.get("id")
        if (
            not isinstance(member_id, str)
            or member_id not in MEMBER_IDENTITIES
            or member_id in observed
        ):
            raise InventoryHelperError("critical-user-data member identity is invalid")
        observed[member_id] = item
    if set(observed) != set(MEMBER_IDENTITIES):
        raise InventoryHelperError("critical-user-data member set is invalid")

    member_digests: dict[str, str] = {}
    for member_id, expected in MEMBER_IDENTITIES.items():
        item = observed[member_id]
        if (
            item.get("contract_file") != expected["snapshot_name"]
            or item.get("destination") != expected["destination"]
            or item.get("restore_mode") != expected["restore_mode"]
        ):
            raise InventoryHelperError("critical-user-data member policy mismatch")
        member_digests[member_id] = _validate_digest(
            item.get("contract_sha256"),
            f"{member_id} contract_sha256",
        )

    implementation = value.get("inventory_implementation")
    required_implementation = {
        "algorithm",
        "root_inventory_script",
        "root_inventory_script_sha256",
        "aggregate_inventory_script",
        "aggregate_inventory_script_sha256",
        "member_contract_digest_bound",
        "source_and_restored_aggregate_inventory_sha256_must_match",
    }
    if not isinstance(implementation, dict) or set(implementation) != required_implementation:
        raise InventoryHelperError("critical-user-data inventory implementation is invalid")
    aggregate_script_sha = _validate_digest(
        implementation.get("aggregate_inventory_script_sha256"),
        "aggregate inventory script sha256",
    )
    if (
        implementation.get("algorithm") != INVENTORY_ALGORITHM
        or implementation.get("root_inventory_script")
        != "scripts/nixos_critical_user_data_inventory.py"
        or implementation.get("root_inventory_script_sha256") != SCANNER_SHA256
        or implementation.get("aggregate_inventory_script")
        != "scripts/nixos_critical_data_inventory.py"
        or aggregate_script_sha != implementation.get("aggregate_inventory_script_sha256")
        or implementation.get("member_contract_digest_bound") is not True
        or implementation.get(
            "source_and_restored_aggregate_inventory_sha256_must_match"
        )
        is not True
    ):
        raise InventoryHelperError("critical-user-data inventory implementation mismatch")
    return member_digests


def _validate_member_contract(
    member_id: str,
    payload: bytes,
    *,
    expected_sha256: str,
) -> None:
    if _sha256(payload) != expected_sha256:
        raise InventoryHelperError("critical-user-data member contract digest mismatch")
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("critical-user-data member contract is invalid") from exc
    identity = MEMBER_IDENTITIES.get(member_id)
    if identity is None or not isinstance(value, dict):
        raise InventoryHelperError("critical-user-data member contract identity is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != SCOPE_KIND
        or value.get("scope") != identity["scope"]
        or value.get("scope_semantics") != identity["scope_semantics"]
        or value.get("root") != identity["root"]
        or value.get("logical_root") != identity["root"]
    ):
        raise InventoryHelperError("critical-user-data member contract identity mismatch")
    required_inventory = {
        "schema": MEMBER_INVENTORY_KIND,
        "algorithm": MEMBER_INVENTORY_ALGORITHM,
        "same_filesystem_only": True,
        "follow_symlinks": False,
        "regular_file_content_sha256": True,
        "directory_mode_bound": True,
        "regular_file_mode_bound": True,
        "symlink_target_bound": True,
        "special_files": "excluded-runtime-only",
        "unreadable_included_path": "fail",
        "changed_during_hash": "fail",
    }
    if value.get("inventory") != required_inventory:
        raise InventoryHelperError("critical-user-data member inventory policy is invalid")
    exclusions = value.get("exclusions")
    if not isinstance(exclusions, dict) or set(exclusions) != {
        "top_level_prefixes",
        "roots",
        "directory_names_under",
        "file_name_prefixes_under",
        "file_name_prefix_suffixes_under",
    }:
        raise InventoryHelperError("critical-user-data member exclusions are invalid")
    if member_id == "docker-volumes":
        consistency = value.get("source_consistency")
        if (
            not isinstance(consistency, dict)
            or consistency.get(
                "full_authoritative_inventory_requires_docker_quiesced"
            )
            is not True
        ):
            raise InventoryHelperError("Docker inventory consistency contract is invalid")


def _snapshot_sources() -> dict[str, str]:
    scanner = _read_stable_regular(SCANNER_SOURCE, max_bytes=MAX_SCANNER_BYTES)
    contract = _read_stable_regular(CONTRACT_SOURCE, max_bytes=MAX_CONTRACT_BYTES)
    if _sha256(scanner) != SCANNER_SHA256:
        raise InventoryHelperError("inventory scanner digest mismatch")
    if _sha256(contract) != CONTRACT_SHA256:
        raise InventoryHelperError("critical-user-data contract digest mismatch")
    member_digests = _validate_contract(contract)

    member_payloads: dict[str, bytes] = {}
    for member_id, identity in MEMBER_IDENTITIES.items():
        source = identity["source"]
        if not isinstance(source, Path):
            raise InventoryHelperError("critical-user-data member source is invalid")
        payload = _read_stable_regular(source, max_bytes=MAX_CONTRACT_BYTES)
        _validate_member_contract(
            member_id,
            payload,
            expected_sha256=member_digests[member_id],
        )
        member_payloads[member_id] = payload

    _ensure_private_directory(STATE_ROOT)
    _ensure_private_directory(SNAPSHOT_ROOT)
    _write_create_only(SCANNER_SNAPSHOT, scanner, mode=0o500)
    _write_create_only(CONTRACT_SNAPSHOT, contract, mode=0o400)
    for member_id, payload in member_payloads.items():
        _write_create_only(_member_snapshot(member_id), payload, mode=0o400)

    if _sha256(
        _read_stable_regular(
            SCANNER_SNAPSHOT,
            max_bytes=MAX_SCANNER_BYTES,
            require_root_owned=True,
            required_mode=0o500,
        )
    ) != SCANNER_SHA256:
        raise InventoryHelperError("inventory scanner snapshot mismatch")
    if _sha256(
        _read_stable_regular(
            CONTRACT_SNAPSHOT,
            max_bytes=MAX_CONTRACT_BYTES,
            require_root_owned=True,
            required_mode=0o400,
        )
    ) != CONTRACT_SHA256:
        raise InventoryHelperError("inventory contract snapshot mismatch")
    for member_id, expected_sha in member_digests.items():
        if _sha256(
            _read_stable_regular(
                _member_snapshot(member_id),
                max_bytes=MAX_CONTRACT_BYTES,
                require_root_owned=True,
                required_mode=0o400,
            )
        ) != expected_sha:
            raise InventoryHelperError("inventory member contract snapshot mismatch")
    return dict(member_digests)


def scanner_argv(member_id: str, contract_sha256: str) -> list[str]:
    if member_id not in MEMBER_IDENTITIES:
        raise InventoryHelperError("inventory member identity is invalid")
    member_sha = _validate_digest(contract_sha256, "member contract sha256")
    return [
        str(PYTHON),
        "-B",
        str(SCANNER_SNAPSHOT),
        "--contract",
        str(_member_snapshot(member_id)),
        "--max-exclusion-samples",
        "0",
        "--expected-script-sha256",
        SCANNER_SHA256,
        "--expected-contract-sha256",
        member_sha,
    ]


def _docker_quiesced() -> None:
    if not DOCKER.is_file():
        raise InventoryHelperError("Docker quiescence cannot be verified")
    try:
        completed = subprocess.run(
            [str(DOCKER), "ps", "-q"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InventoryHelperError("Docker quiescence cannot be verified") from exc
    if completed.returncode != 0:
        raise InventoryHelperError("Docker quiescence cannot be verified")
    if completed.stdout.strip():
        raise InventoryHelperError(
            "authoritative Docker-volume inventory requires all containers stopped"
        )


def _start_docker_event_monitor() -> subprocess.Popen[bytes]:
    if not DOCKER.is_file():
        raise InventoryHelperError("Docker quiescence cannot be verified")
    # Start slightly before the subscription.  Docker replays events since this
    # timestamp, closing the short subscription race before the initial ps check.
    since = str(max(0, int(time.time()) - 1))
    try:
        monitor = subprocess.Popen(
            [
                str(DOCKER),
                "events",
                "--since",
                since,
                "--format",
                "{{.Action}}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENV,
        )
    except OSError as exc:
        raise InventoryHelperError(
            "Docker quiescence monitor cannot be started"
        ) from exc
    if monitor.stdout is None:
        try:
            monitor.terminate()
        except OSError:
            pass
        raise InventoryHelperError("Docker quiescence monitor is unavailable")
    return monitor


def _close_docker_event_monitor(
    monitor: subprocess.Popen[bytes],
    *,
    require_live: bool,
) -> bytes:
    was_live = monitor.poll() is None
    if was_live:
        try:
            monitor.terminate()
        except OSError as exc:
            raise InventoryHelperError(
                "Docker quiescence monitor cannot be stopped"
            ) from exc
    try:
        stdout, _stderr = monitor.communicate(timeout=5)
    except subprocess.TimeoutExpired as exc:
        try:
            monitor.kill()
            stdout, _stderr = monitor.communicate(timeout=5)
        except (OSError, subprocess.SubprocessError) as cleanup_exc:
            raise InventoryHelperError(
                "Docker quiescence monitor cannot be stopped"
            ) from cleanup_exc
        if require_live:
            raise InventoryHelperError(
                "Docker quiescence monitor did not terminate safely"
            ) from exc
    if require_live and not was_live:
        raise InventoryHelperError(
            "Docker quiescence monitor ended before the volume scan completed"
        )
    if (
        not isinstance(stdout, bytes)
        or len(stdout) > MAX_DOCKER_EVENT_OUTPUT_BYTES
    ):
        raise InventoryHelperError("Docker quiescence monitor output is invalid")
    return stdout


def _run_member_scanner(
    member_id: str,
    contract_sha256: str,
) -> subprocess.CompletedProcess[bytes]:
    argv = scanner_argv(member_id, contract_sha256)
    if member_id != "docker-volumes":
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            check=False,
            timeout=SCANNER_TIMEOUT_SECONDS,
        )

    monitor: subprocess.Popen[bytes] | None = _start_docker_event_monitor()
    try:
        _docker_quiesced()
        if monitor.poll() is not None:
            raise InventoryHelperError(
                "Docker quiescence monitor ended before the volume scan started"
            )
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            check=False,
            timeout=SCANNER_TIMEOUT_SECONDS,
        )
        _docker_quiesced()
        if monitor.poll() is not None:
            raise InventoryHelperError(
                "Docker quiescence monitor ended during the volume scan"
            )
        events = _close_docker_event_monitor(monitor, require_live=True)
        monitor = None
    except BaseException:
        if monitor is not None:
            try:
                _close_docker_event_monitor(monitor, require_live=False)
            except InventoryHelperError:
                pass
        raise
    if events.strip():
        raise InventoryHelperError(
            "Docker activity occurred during authoritative Docker-volume inventory"
        )
    return completed


def _request_json(operation: str) -> str:
    if operation not in {"start", "status", "result", "execute"}:
        raise InventoryHelperError("inventory helper operation is invalid")
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "operation": operation,
            "scanner_sha256": SCANNER_SHA256,
            "contract_sha256": CONTRACT_SHA256,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def systemd_start_argv() -> list[str]:
    return [
        str(SYSTEMD_RUN),
        "--system",
        f"--unit={UNIT.removesuffix('.service')}",
        "--collect",
        (
            "--description=Hash-pinned read-only Heim-PC critical-user-data "
            f"inventory {SCANNER_SHA256[:8]}/{CONTRACT_SHA256[:8]}"
        ),
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        f"--property=RuntimeMaxSec={RUNTIME_SECONDS}s",
        "--property=LimitCORE=0",
        "--property=LimitFSIZE=262144",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=PrivateNetwork=yes",
        "--property=PrivateDevices=yes",
        "--property=NoNewPrivileges=yes",
        "--property=UMask=0077",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectHostname=yes",
        "--property=ProtectClock=yes",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=RestrictSUIDSGID=yes",
        "--property=RestrictRealtime=yes",
        "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH",
        "--property=AmbientCapabilities=",
        f"--property=ReadWritePaths={STATE_ROOT}",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        "--property=WorkingDirectory=/",
        "--",
        str(HELPER),
        _request_json("execute"),
    ]


def _parse_show(stdout: str) -> dict[str, str]:
    value: dict[str, str] = {}
    for raw in stdout.splitlines():
        if "=" not in raw:
            continue
        key, item = raw.split("=", 1)
        value[key] = item
    return value


def _unit_state() -> dict[str, str]:
    completed = subprocess.run(
        [
            str(SYSTEMCTL),
            "--system",
            "show",
            UNIT,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=SAFE_ENV,
        check=False,
        timeout=10,
        text=True,
    )
    if completed.returncode != 0:
        raise InventoryHelperError("inventory unit status is unavailable")
    value = _parse_show(completed.stdout)
    required = {"LoadState", "ActiveState", "SubState", "Result"}
    if set(value) != required:
        raise InventoryHelperError("inventory unit status is malformed")
    return value


def _validate_nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InventoryHelperError(f"{label} is invalid")
    return value


def _normalize_counts(value: Any, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise InventoryHelperError(f"{label} is invalid")
    normalized: dict[str, int] = {}
    for key, item in value.items():
        if not isinstance(key, str) or CLASS_RE.fullmatch(key) is None:
            raise InventoryHelperError(f"{label} name is invalid")
        normalized[key] = _validate_nonnegative_int(item, f"{label}.{key}")
    return dict(sorted(normalized.items()))


def _validate_member_inventory_output(
    payload: bytes,
    *,
    member_id: str,
    contract_sha256: str,
) -> dict[str, Any]:
    if not payload or len(payload) > MAX_SCANNER_OUTPUT_BYTES:
        raise InventoryHelperError("inventory member output size is invalid")
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("inventory member output is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != MEMBER_INVENTORY_FIELDS:
        raise InventoryHelperError("inventory member output fields are invalid")
    identity = MEMBER_IDENTITIES.get(member_id)
    member_sha = _validate_digest(contract_sha256, "member contract sha256")
    if identity is None:
        raise InventoryHelperError("inventory member identity is invalid")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != MEMBER_INVENTORY_KIND
        or value.get("scope") != identity["scope"]
        or value.get("root") != identity["root"]
        or value.get("algorithm") != MEMBER_INVENTORY_ALGORITHM
        or value.get("critical_scope_sha256") != member_sha
        or value.get("contract_sha256") != member_sha
        or value.get("authoritative_inventory") is not True
        or value.get("production_effects_authorized") is not False
        or value.get("exclusion_samples") != []
        or not isinstance(value.get("inventory_sha256"), str)
        or SHA256_RE.fullmatch(value["inventory_sha256"]) is None
        or not isinstance(value.get("exclusion_boundary_sha256"), str)
        or SHA256_RE.fullmatch(value["exclusion_boundary_sha256"]) is None
    ):
        raise InventoryHelperError("inventory member output identity is invalid")
    record_count = _validate_nonnegative_int(value.get("record_count"), "record_count")
    regular_bytes = _validate_nonnegative_int(
        value.get("regular_file_bytes"), "regular_file_bytes"
    )
    exclusion_count = _validate_nonnegative_int(
        value.get("exclusion_boundary_count"), "exclusion_boundary_count"
    )
    type_counts = value.get("type_counts")
    if (
        not isinstance(type_counts, dict)
        or set(type_counts) != {"directory", "regular", "symlink"}
    ):
        raise InventoryHelperError("inventory member type counts are invalid")
    normalized_types = {
        key: _validate_nonnegative_int(item, f"type_counts.{key}")
        for key, item in type_counts.items()
    }
    if sum(normalized_types.values()) != record_count:
        raise InventoryHelperError("inventory member record count is inconsistent")
    normalized_classes = _normalize_counts(
        value.get("exclusion_class_counts"),
        "exclusion_class_counts",
    )
    if sum(normalized_classes.values()) != exclusion_count:
        raise InventoryHelperError("inventory member exclusion count is inconsistent")
    return {
        **value,
        "record_count": record_count,
        "regular_file_bytes": regular_bytes,
        "exclusion_boundary_count": exclusion_count,
        "type_counts": dict(sorted(normalized_types.items())),
        "exclusion_class_counts": normalized_classes,
    }


def _aggregate_member_inventories(
    members: dict[str, dict[str, Any]],
    member_digests: dict[str, str],
) -> dict[str, Any]:
    if set(members) != set(MEMBER_IDENTITIES) or set(member_digests) != set(MEMBER_IDENTITIES):
        raise InventoryHelperError("inventory aggregate member set is invalid")
    inventory_digest = hashlib.sha256()
    exclusion_digest = hashlib.sha256()
    type_counts = {"directory": 0, "regular": 0, "symlink": 0}
    exclusion_classes: dict[str, int] = {}
    record_count = 0
    regular_file_bytes = 0
    exclusion_boundary_count = 0
    for member_id in sorted(MEMBER_IDENTITIES):
        value = members[member_id]
        member_sha = _validate_digest(
            member_digests[member_id],
            f"{member_id} contract sha256",
        )
        inventory_digest.update(
            _canonical(
                {
                    "id": member_id,
                    "contract_sha256": member_sha,
                    "inventory_sha256": value["inventory_sha256"],
                }
            )
        )
        exclusion_digest.update(
            _canonical(
                {
                    "id": member_id,
                    "contract_sha256": member_sha,
                    "exclusion_boundary_sha256": value["exclusion_boundary_sha256"],
                }
            )
        )
        record_count += value["record_count"]
        regular_file_bytes += value["regular_file_bytes"]
        exclusion_boundary_count += value["exclusion_boundary_count"]
        for key, item in value["type_counts"].items():
            type_counts[key] += item
        for key, item in value["exclusion_class_counts"].items():
            exclusion_classes[key] = exclusion_classes.get(key, 0) + item
    return {
        "schema_version": 1,
        "kind": INVENTORY_KIND,
        "scope": "critical-user-data",
        "scope_semantics": SCOPE_SEMANTICS,
        "algorithm": INVENTORY_ALGORITHM,
        "critical_scope_sha256": CONTRACT_SHA256,
        "contract_sha256": CONTRACT_SHA256,
        "authoritative_inventory": True,
        "inventory_sha256": inventory_digest.hexdigest(),
        "member_count": len(MEMBER_IDENTITIES),
        "record_count": record_count,
        "type_counts": dict(sorted(type_counts.items())),
        "regular_file_bytes": regular_file_bytes,
        "exclusion_boundary_count": exclusion_boundary_count,
        "exclusion_boundary_sha256": exclusion_digest.hexdigest(),
        "exclusion_class_counts": dict(sorted(exclusion_classes.items())),
        "exclusion_samples": [],
        "production_effects_authorized": False,
    }


def _validate_inventory_output(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > MAX_RESULT_BYTES:
        raise InventoryHelperError("inventory output size is invalid")
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("inventory output is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != INVENTORY_FIELDS:
        raise InventoryHelperError("inventory output fields are invalid")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != INVENTORY_KIND
        or value.get("scope") != "critical-user-data"
        or value.get("scope_semantics") != SCOPE_SEMANTICS
        or value.get("algorithm") != INVENTORY_ALGORITHM
        or value.get("critical_scope_sha256") != CONTRACT_SHA256
        or value.get("contract_sha256") != CONTRACT_SHA256
        or value.get("authoritative_inventory") is not True
        or value.get("production_effects_authorized") is not False
        or value.get("exclusion_samples") != []
        or value.get("member_count") != len(MEMBER_IDENTITIES)
        or not isinstance(value.get("inventory_sha256"), str)
        or SHA256_RE.fullmatch(value["inventory_sha256"]) is None
        or not isinstance(value.get("exclusion_boundary_sha256"), str)
        or SHA256_RE.fullmatch(value["exclusion_boundary_sha256"]) is None
    ):
        raise InventoryHelperError("inventory output identity is invalid")
    record_count = _validate_nonnegative_int(value.get("record_count"), "record_count")
    regular_bytes = _validate_nonnegative_int(
        value.get("regular_file_bytes"), "regular_file_bytes"
    )
    exclusion_count = _validate_nonnegative_int(
        value.get("exclusion_boundary_count"), "exclusion_boundary_count"
    )
    type_counts = value.get("type_counts")
    if (
        not isinstance(type_counts, dict)
        or set(type_counts) != {"directory", "regular", "symlink"}
    ):
        raise InventoryHelperError("inventory type counts are invalid")
    normalized_types = {
        key: _validate_nonnegative_int(item, f"type_counts.{key}")
        for key, item in type_counts.items()
    }
    if sum(normalized_types.values()) != record_count:
        raise InventoryHelperError("inventory record count is inconsistent")
    normalized_classes = _normalize_counts(
        value.get("exclusion_class_counts"),
        "exclusion_class_counts",
    )
    if sum(normalized_classes.values()) != exclusion_count:
        raise InventoryHelperError("inventory exclusion count is inconsistent")
    return {
        **value,
        "record_count": record_count,
        "regular_file_bytes": regular_bytes,
        "exclusion_boundary_count": exclusion_count,
        "type_counts": dict(sorted(normalized_types.items())),
        "exclusion_class_counts": normalized_classes,
    }


def _unsigned_result(
    *,
    status: str,
    inventory: dict[str, Any] | None = None,
    failure_code: str | None = None,
    returncode: int | None = None,
    stdout_sha256: str | None = None,
    stdout_bytes: int | None = None,
    stderr_sha256: str | None = None,
    stderr_bytes: int | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": RESULT_KIND,
        "status": status,
        "unit": UNIT,
        "scanner_sha256": SCANNER_SHA256,
        "contract_sha256": CONTRACT_SHA256,
        "completed_at_unix": int(time.time()),
    }
    if status == "passed":
        if inventory is None:
            raise InventoryHelperError("passed result lacks inventory")
        value["inventory"] = inventory
    else:
        value.update(
            {
                "failure_code": failure_code,
                "returncode": returncode,
                "stdout_sha256": stdout_sha256,
                "stdout_bytes": stdout_bytes,
                "stderr_sha256": stderr_sha256,
                "stderr_bytes": stderr_bytes,
            }
        )
    return value


def _seal_result(value: dict[str, Any]) -> dict[str, Any]:
    sealed = dict(value)
    sealed["result_sha256"] = _sha256(_canonical(value))
    return sealed


def _validate_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryHelperError("inventory result is invalid")
    self_hash = value.get("result_sha256")
    unsigned = dict(value)
    unsigned.pop("result_sha256", None)
    if (
        not isinstance(self_hash, str)
        or SHA256_RE.fullmatch(self_hash) is None
        or _sha256(_canonical(unsigned)) != self_hash
        or unsigned.get("schema_version") != SCHEMA_VERSION
        or unsigned.get("kind") != RESULT_KIND
        or unsigned.get("status") not in {"passed", "failed"}
        or unsigned.get("unit") != UNIT
        or unsigned.get("scanner_sha256") != SCANNER_SHA256
        or unsigned.get("contract_sha256") != CONTRACT_SHA256
    ):
        raise InventoryHelperError("inventory result binding is invalid")
    if unsigned["status"] == "passed":
        expected = {
            "schema_version",
            "kind",
            "status",
            "unit",
            "scanner_sha256",
            "contract_sha256",
            "completed_at_unix",
            "inventory",
        }
        if set(unsigned) != expected:
            raise InventoryHelperError("passed inventory result fields are invalid")
        _validate_nonnegative_int(
            unsigned.get("completed_at_unix"), "completed_at_unix"
        )
        inventory = unsigned.get("inventory")
        if not isinstance(inventory, dict):
            raise InventoryHelperError("passed inventory result payload is invalid")
        normalized = _validate_inventory_output(_canonical(inventory))
        if normalized != inventory:
            raise InventoryHelperError("inventory result is not canonical")
    else:
        expected = {
            "schema_version",
            "kind",
            "status",
            "unit",
            "scanner_sha256",
            "contract_sha256",
            "completed_at_unix",
            "failure_code",
            "returncode",
            "stdout_sha256",
            "stdout_bytes",
            "stderr_sha256",
            "stderr_bytes",
        }
        if set(unsigned) != expected:
            raise InventoryHelperError("failed inventory result fields are invalid")
        _validate_nonnegative_int(
            unsigned.get("completed_at_unix"), "completed_at_unix"
        )
        if (
            not isinstance(unsigned.get("failure_code"), str)
            or not unsigned["failure_code"]
            or unsigned.get("returncode") is None
            or isinstance(unsigned["returncode"], bool)
            or not isinstance(unsigned["returncode"], int)
        ):
            raise InventoryHelperError("failed inventory result metadata is invalid")
        for key in ("stdout_sha256", "stderr_sha256"):
            if (
                not isinstance(unsigned.get(key), str)
                or SHA256_RE.fullmatch(unsigned[key]) is None
            ):
                raise InventoryHelperError("failed inventory result digest is invalid")
        for key in ("stdout_bytes", "stderr_bytes"):
            _validate_nonnegative_int(unsigned.get(key), key)
    return dict(value)


def _write_result(value: dict[str, Any]) -> None:
    _ensure_private_directory(STATE_ROOT)
    sealed = _seal_result(value)
    payload = _canonical(sealed)
    if len(payload) > MAX_RESULT_BYTES:
        raise InventoryHelperError("inventory result exceeds size bound")
    _write_create_only(RESULT_PATH, payload, mode=0o600)


def _read_result() -> dict[str, Any] | None:
    if not os.path.lexists(RESULT_PATH):
        return None
    payload = _read_stable_regular(
        RESULT_PATH,
        max_bytes=MAX_RESULT_BYTES,
        require_root_owned=True,
        required_mode=0o600,
    )
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("inventory result JSON is invalid") from exc
    return _validate_result(value)


def _archive_failed_result(value: dict[str, Any]) -> None:
    if value.get("status") != "failed":
        raise InventoryHelperError("only failed inventory results may be archived")
    _ensure_private_directory(FAILED_ROOT)
    target = FAILED_ROOT / f"result-{time.time_ns()}.json"
    os.replace(RESULT_PATH, target)
    info = target.lstat()
    if (
        target.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise InventoryHelperError("archived inventory result is unsafe")
    _fsync_directory(FAILED_ROOT)
    _fsync_directory(STATE_ROOT)


def _lock() -> int:
    _ensure_private_directory(STATE_ROOT)
    _ensure_private_directory(SNAPSHOT_ROOT)
    descriptor = os.open(
        LOCK_PATH,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        os.close(descriptor)
        raise InventoryHelperError("inventory lock is unsafe")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _public_result(value: dict[str, Any]) -> dict[str, Any]:
    return _validate_result(value)


def _status_payload() -> dict[str, Any]:
    result = _read_result()
    unit = _unit_state()
    if result is not None:
        status = str(result["status"])
    elif unit["ActiveState"] == "active":
        status = "running"
    else:
        status = "not-started"
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski.critical_user_data_inventory_status.v1",
        "status": status,
        "unit": UNIT,
        "scanner_sha256": SCANNER_SHA256,
        "contract_sha256": CONTRACT_SHA256,
        "unit_state": {
            "load": unit["LoadState"],
            "active": unit["ActiveState"],
            "sub": unit["SubState"],
            "result": unit["Result"],
        },
        "result_sha256": (
            result.get("result_sha256") if result is not None else None
        ),
    }


def _start() -> dict[str, Any]:
    descriptor = _lock()
    try:
        _snapshot_sources()
        unit = _unit_state()
        if unit["ActiveState"] == "active":
            return _status_payload()
        result = _read_result()
        if result is not None and result["status"] == "passed":
            return _public_result(result)
        if result is not None:
            _archive_failed_result(result)
        completed = subprocess.run(
            systemd_start_argv(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            check=False,
            timeout=30,
            text=True,
        )
        if completed.returncode != 0:
            raise InventoryHelperError("inventory systemd unit could not be started")
        state = _unit_state()
        if state["ActiveState"] != "active":
            raise InventoryHelperError("inventory systemd unit did not become active")
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.critical_user_data_inventory_start.v1",
            "status": "started",
            "unit": UNIT,
            "scanner_sha256": SCANNER_SHA256,
            "contract_sha256": CONTRACT_SHA256,
            "runtime_seconds": RUNTIME_SECONDS,
        }
    finally:
        os.close(descriptor)


def _execute() -> int:
    descriptor = _lock()
    try:
        if _read_result() is not None:
            raise InventoryHelperError("inventory result already exists")
        member_digests = _snapshot_sources()
    finally:
        os.close(descriptor)

    stdout = b""
    stderr = b""
    try:
        _docker_quiesced()
        member_results: dict[str, dict[str, Any]] = {}
        for member_id in sorted(MEMBER_IDENTITIES):
            completed = _run_member_scanner(
                member_id,
                member_digests[member_id],
            )
            stdout = completed.stdout
            stderr = completed.stderr
            if (
                len(stdout) > MAX_SCANNER_OUTPUT_BYTES
                or len(stderr) > MAX_SCANNER_OUTPUT_BYTES
            ):
                result = _unsigned_result(
                    status="failed",
                    failure_code="inventory-output-too-large",
                    returncode=completed.returncode,
                    stdout_sha256=_sha256(stdout),
                    stdout_bytes=len(stdout),
                    stderr_sha256=_sha256(stderr),
                    stderr_bytes=len(stderr),
                )
                _write_result(result)
                print(json.dumps(_seal_result(result), sort_keys=True, separators=(",", ":")))
                return 2
            if completed.returncode != 0:
                result = _unsigned_result(
                    status="failed",
                    failure_code="inventory-safety-check",
                    returncode=completed.returncode,
                    stdout_sha256=_sha256(stdout),
                    stdout_bytes=len(stdout),
                    stderr_sha256=_sha256(stderr),
                    stderr_bytes=len(stderr),
                )
                _write_result(result)
                print(json.dumps(_seal_result(result), sort_keys=True, separators=(",", ":")))
                return 2
            member_results[member_id] = _validate_member_inventory_output(
                stdout,
                member_id=member_id,
                contract_sha256=member_digests[member_id],
            )
        inventory = _aggregate_member_inventories(member_results, member_digests)
        inventory = _validate_inventory_output(_canonical(inventory))
        result = _unsigned_result(status="passed", inventory=inventory)
        _write_result(result)
        print(json.dumps(_seal_result(result), sort_keys=True, separators=(",", ":")))
        return 0
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        result = _unsigned_result(
            status="failed",
            failure_code="inventory-timeout",
            returncode=124,
            stdout_sha256=_sha256(stdout),
            stdout_bytes=len(stdout),
            stderr_sha256=_sha256(stderr),
            stderr_bytes=len(stderr),
        )
        _write_result(result)
        print(json.dumps(_seal_result(result), sort_keys=True, separators=(",", ":")))
        return 124
    except InventoryHelperError:
        result = _unsigned_result(
            status="failed",
            failure_code="inventory-safety-check",
            returncode=2,
            stdout_sha256=_sha256(stdout),
            stdout_bytes=len(stdout),
            stderr_sha256=_sha256(stderr),
            stderr_bytes=len(stderr),
        )
        _write_result(result)
        print(json.dumps(_seal_result(result), sort_keys=True, separators=(",", ":")))
        return 2


def _result() -> dict[str, Any]:
    value = _read_result()
    if value is None:
        raise InventoryHelperError("inventory result is unavailable")
    return _public_result(value)


def _parse_request(raw: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > 1024:
        raise InventoryHelperError("inventory helper request is invalid")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InventoryHelperError("inventory helper request is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "operation",
            "scanner_sha256",
            "contract_sha256",
        }
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("operation") not in {"start", "status", "result", "execute"}
    ):
        raise InventoryHelperError("inventory helper request is invalid")
    _apply_binding(
        _validate_digest(value.get("scanner_sha256"), "scanner_sha256"),
        _validate_digest(value.get("contract_sha256"), "contract_sha256"),
    )
    return str(value["operation"])


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        raise InventoryHelperError("critical-user-data inventory helper requires root")
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        raise InventoryHelperError("inventory helper operation is invalid")
    operation = _parse_request(args[0])
    if operation == "start":
        value = _start()
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    if operation == "status":
        print(json.dumps(_status_payload(), sort_keys=True, separators=(",", ":")))
        return 0
    if operation == "result":
        print(json.dumps(_result(), sort_keys=True, separators=(",", ":")))
        return 0
    return _execute()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InventoryHelperError:
        error = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.critical_user_data_inventory_error.v1",
            "status": "blocked",
        }
        if SHA256_RE.fullmatch(SCANNER_SHA256):
            error["scanner_sha256"] = SCANNER_SHA256
        if SHA256_RE.fullmatch(CONTRACT_SHA256):
            error["contract_sha256"] = CONTRACT_SHA256
        print(json.dumps(error, sort_keys=True, separators=(",", ":")))
        raise SystemExit(2)
    except Exception:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "grabowski.critical_user_data_inventory_error.v1",
                    "status": "blocked",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        raise SystemExit(2)
