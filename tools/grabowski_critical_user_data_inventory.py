#!/usr/bin/env python3
"""Narrow privileged runner for the Heim-PC critical-user-data inventory."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types
from typing import Any

SCHEMA_VERSION = 1
RESULT_KIND = "grabowski.critical_user_data_inventory_result.v1"
INVENTORY_KIND = "heim_pc.critical_user_data_aggregate_inventory.v1"
INVENTORY_ALGORITHM = "member-inventory-sha256-v1"
SCOPE_KIND = "heim_pc.critical_user_data_scope_contract"
SCOPE_SEMANTICS = "explicit-positive-selection"
SOURCE_STABILITY_MODE = "kernel-local-pci-nvme-readonly-mountinfo-v3"
AGGREGATE_EXECUTION_MODE = "external-verified-payload-exec-v1"
SOURCE_ROOT = Path(
    "/home/alex/repos/.repoground-sources/"
    "heimgewebe__heim-pc__main--d6d4b3c4337d8bd51758d10d83975c9d61fd18d7"
)
SCANNER_SOURCE = SOURCE_ROOT / "scripts/nixos_critical_user_data_inventory.py"
AGGREGATE_SCANNER_SOURCE = SOURCE_ROOT / "scripts/nixos_critical_data_inventory.py"
CONTRACT_SOURCE = SOURCE_ROOT / "nixos/production/critical-user-data-contract-v1.json"
HOME_CONTRACT_SOURCE = (
    SOURCE_ROOT / "nixos/production/critical-user-home-data-contract-v1.json"
)
RECOVERY_CONTRACT_SOURCE = SOURCE_ROOT / "nixos/production/recovery-contract-v1.json"

# These pins are authority, not observations supplied by the UID-1000 caller.
# The installed helper artifact is itself commit-bound by the Rootbroker/runtime
# operator-authority attestation.  A changed migration source therefore fails
# closed until a new reviewed Grabowski commit updates these constants.
AUTHORIZED_SCANNER_SHA256 = "5f3b9aa1e2ad49da932ac699023f7f020e562d1d6ec0584a8c9dafb6ffaef572"
AUTHORIZED_AGGREGATE_SCANNER_SHA256 = "f71996ac1b3722a0785465e9504c2cfd23878d1b85597ddaff7a5bebf0a49d84"
AUTHORIZED_CONTRACT_SHA256 = "d979b42a8a030ca37b5a3c57ac192c81324d72bf3ac292adbda427eeec2c8097"
AUTHORIZED_HOME_CONTRACT_SHA256 = "385cf944e6a28c94a4593eeb1e6e5c87141cb26a4dc8a6cc96b783e21a623347"
AUTHORIZED_RECOVERY_CONTRACT_SHA256 = "fcd9856f9038652469605b97818bb6904bf34bb54843b4e322e797dc3533a5b6"

SCANNER_SHA256 = ""
CONTRACT_SHA256 = ""
HELPER = Path("/usr/local/libexec/grabowski-critical-user-data-inventory")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
STATE_PARENT = Path("/dev/shm")
STATE_ROOT = STATE_PARENT / "grabowski-critical-user-data-inventory"
DURABLE_STATE_ROOT = Path("/var/lib/grabowski/critical-user-data-inventory")
SNAPSHOT_ROOT = STATE_ROOT / "unbound"
RESULT_ROOT = DURABLE_STATE_ROOT / "unbound"
SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "nixos_critical_user_data_inventory.py"
AGGREGATE_SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "nixos_critical_data_inventory.py"
CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-data-contract-v1.json"
HOME_CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-home-data-contract-v1.json"
RECOVERY_CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "recovery-contract-v1.json"
RESULT_PATH = RESULT_ROOT / "result.json"
FAILED_ROOT = RESULT_ROOT / "failed-results"
START_ATTEMPT_PATH = SNAPSHOT_ROOT / "start-attempt.json"
LOCK_PATH = SNAPSHOT_ROOT / "operation.lock"
UNIT = "grabowski-critical-user-data-inventory-unbound.service"
RUNTIME_SECONDS = 6 * 60 * 60
SCANNER_TIMEOUT_SECONDS = RUNTIME_SECONDS - 300
MAX_SCANNER_BYTES = 2 * 1024 * 1024
MAX_CONTRACT_BYTES = 512 * 1024
MAX_SCANNER_OUTPUT_BYTES = 256 * 1024
MAX_RESULT_BYTES = 256 * 1024
AT_FDCWD = getattr(os, "AT_FDCWD", -100)
RENAME_NOREPLACE = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

MEMBER_SUMMARY_FIELDS = frozenset(
    {
        "id",
        "scope",
        "contract_sha256",
        "inventory_sha256",
        "record_count",
        "regular_file_bytes",
        "exclusion_boundary_count",
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
        "members",
        "record_count",
        "regular_file_bytes",
        "exclusion_boundary_count",
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
    global SNAPSHOT_ROOT, RESULT_ROOT, SCANNER_SNAPSHOT, AGGREGATE_SCANNER_SNAPSHOT
    global CONTRACT_SNAPSHOT, HOME_CONTRACT_SNAPSHOT, RECOVERY_CONTRACT_SNAPSHOT
    global RESULT_PATH, FAILED_ROOT, START_ATTEMPT_PATH, LOCK_PATH, UNIT

    scanner = _validate_digest(scanner_sha256, "scanner_sha256")
    contract = _validate_digest(contract_sha256, "contract_sha256")
    if (
        scanner != AUTHORIZED_SCANNER_SHA256
        or contract != AUTHORIZED_CONTRACT_SHA256
    ):
        raise InventoryHelperError("inventory source digest pair is not authorized")
    SCANNER_SHA256 = scanner
    CONTRACT_SHA256 = contract
    SNAPSHOT_ROOT = STATE_ROOT / f"source-{scanner}-{contract}"
    RESULT_ROOT = DURABLE_STATE_ROOT / f"source-{scanner}-{contract}"
    SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "nixos_critical_user_data_inventory.py"
    AGGREGATE_SCANNER_SNAPSHOT = SNAPSHOT_ROOT / "nixos_critical_data_inventory.py"
    CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-data-contract-v1.json"
    HOME_CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "critical-user-home-data-contract-v1.json"
    RECOVERY_CONTRACT_SNAPSHOT = SNAPSHOT_ROOT / "recovery-contract-v1.json"
    RESULT_PATH = RESULT_ROOT / "result.json"
    FAILED_ROOT = RESULT_ROOT / "failed-results"
    START_ATTEMPT_PATH = SNAPSHOT_ROOT / "start-attempt.json"
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


def _ensure_state_root() -> None:
    if STATE_ROOT.parent != STATE_PARENT:
        _ensure_private_directory(STATE_ROOT)
        return
    try:
        parent = STATE_PARENT.lstat()
        source = SOURCE_ROOT.lstat()
    except OSError as exc:
        raise InventoryHelperError("inventory state backing is unavailable") from exc
    if (
        STATE_PARENT.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_gid != 0
        or stat.S_IMODE(parent.st_mode) != 0o1777
        or SOURCE_ROOT.is_symlink()
        or not stat.S_ISDIR(source.st_mode)
        or parent.st_dev == source.st_dev
    ):
        raise InventoryHelperError("inventory state backing is unsafe")
    try:
        STATE_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = STATE_ROOT.lstat()
    if (
        STATE_ROOT.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_dev == source.st_dev
    ):
        raise InventoryHelperError("inventory state root is unsafe")


def _ensure_result_root() -> None:
    # Snapshot/fence state stays on tmpfs so the inventory never needs a writable
    # bind on the source filesystem. Only the small sealed terminal result is
    # durable across reboot.
    _ensure_private_directory(DURABLE_STATE_ROOT)
    _ensure_private_directory(RESULT_ROOT)


def _start_attempt_payload() -> bytes:
    return _canonical(
        {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.critical_user_data_inventory_start_attempt.v1",
            "scanner_sha256": SCANNER_SHA256,
            "contract_sha256": CONTRACT_SHA256,
        }
    )


def _start_attempt_exists() -> bool:
    if not os.path.lexists(START_ATTEMPT_PATH):
        return False
    observed = _read_stable_regular(
        START_ATTEMPT_PATH,
        max_bytes=4096,
        require_root_owned=True,
        required_mode=0o600,
    )
    if observed != _start_attempt_payload():
        raise InventoryHelperError("inventory start-attempt marker is invalid")
    return True


def _claim_start_attempt() -> bool:
    if _start_attempt_exists():
        return False
    _write_create_only(START_ATTEMPT_PATH, _start_attempt_payload(), mode=0o600)
    return True


def _clear_start_attempt() -> None:
    if not _start_attempt_exists():
        return
    os.unlink(START_ATTEMPT_PATH)
    _fsync_directory(SNAPSHOT_ROOT)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> bool:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except (OSError, AttributeError) as exc:
        raise InventoryHelperError(
            "atomic inventory result publish is unavailable"
        ) from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        ctypes.c_int(AT_FDCWD),
        os.fsencode(source),
        ctypes.c_int(AT_FDCWD),
        os.fsencode(destination),
        ctypes.c_uint(RENAME_NOREPLACE),
    )
    if result == 0:
        return True
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        return False
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise InventoryHelperError(
            "atomic inventory result publish is unavailable"
        ) from OSError(error, os.strerror(error))
    raise InventoryHelperError(
        "atomic inventory result publish failed"
    ) from OSError(error, os.strerror(error))


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


def _validate_contract(payload: bytes) -> None:
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
    if not isinstance(members, list) or len(members) != 1:
        raise InventoryHelperError("critical-user-data member set is invalid")
    member = members[0]
    if (
        not isinstance(member, dict)
        or set(member)
        != {
            "id",
            "contract_file",
            "contract_sha256",
            "destination",
            "restore_mode",
        }
        or member.get("id") != "home"
        or member.get("contract_file") != HOME_CONTRACT_SOURCE.name
        or member.get("contract_sha256") != AUTHORIZED_HOME_CONTRACT_SHA256
    ):
        raise InventoryHelperError("critical-user-data home member binding is invalid")

    implementation = value.get("inventory_implementation")
    required_implementation = {
        "algorithm",
        "root_inventory_script",
        "root_inventory_script_sha256",
        "aggregate_inventory_script",
        "aggregate_inventory_script_sha256",
        "aggregate_execution_mode",
        "member_contract_digest_bound",
        "source_and_restored_aggregate_inventory_sha256_must_match",
        "authoritative_member_source_stability",
    }
    if (
        not isinstance(implementation, dict)
        or set(implementation) != required_implementation
        or implementation.get("algorithm") != INVENTORY_ALGORITHM
        or implementation.get("root_inventory_script")
        != "scripts/nixos_critical_user_data_inventory.py"
        or implementation.get("root_inventory_script_sha256")
        != AUTHORIZED_SCANNER_SHA256
        or implementation.get("aggregate_inventory_script")
        != "scripts/nixos_critical_data_inventory.py"
        or implementation.get("aggregate_inventory_script_sha256")
        != AUTHORIZED_AGGREGATE_SCANNER_SHA256
        or implementation.get("aggregate_execution_mode")
        != AGGREGATE_EXECUTION_MODE
        or implementation.get("member_contract_digest_bound") is not True
        or implementation.get(
            "source_and_restored_aggregate_inventory_sha256_must_match"
        )
        is not True
        or implementation.get("authoritative_member_source_stability")
        != SOURCE_STABILITY_MODE
    ):
        raise InventoryHelperError(
            "critical-user-data inventory implementation mismatch"
        )

    migration_policy = value.get("migration_policy")
    if (
        not isinstance(migration_policy, dict)
        or migration_policy.get("selection_model") != "explicit-positive-allowlist"
        or migration_policy.get("legacy_docker_volume_tree_migrated") is not False
    ):
        raise InventoryHelperError("critical-user-data migration policy mismatch")


def _validate_home_contract(payload: bytes) -> None:
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("critical-user-data home contract is invalid") from exc
    inventory = value.get("inventory") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != SCOPE_KIND
        or value.get("scope") != "critical-user-data-home"
        or value.get("scope_semantics") != "explicit-path-set"
        or value.get("root") != "/home/alex"
        or value.get("logical_root") != "/home/alex"
        or not isinstance(inventory, dict)
        or inventory.get("schema") != "heim_pc.critical_user_data_inventory.v1"
        or inventory.get("algorithm") != "canonical-record-stream-sha256-v7"
        or inventory.get("explicit_ancestor_metadata_bound") is not True
        or inventory.get("authoritative_source_stability")
        != SOURCE_STABILITY_MODE
    ):
        raise InventoryHelperError("critical-user-data home contract identity mismatch")


def _validate_recovery_contract(payload: bytes) -> None:
    try:
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("recovery contract is invalid") from exc
    critical_scope = value.get("critical_user_data_scope") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != "heim_pc.nixos_recovery_readiness_contract"
        or not isinstance(critical_scope, dict)
        or critical_scope.get("contract_kind") != SCOPE_KIND
        or critical_scope.get("scope") != "critical-user-data"
        or critical_scope.get("sha256") != AUTHORIZED_CONTRACT_SHA256
        or critical_scope.get("off_host_restore_critical_scope_sha256_bound")
        is not True
        or critical_scope.get("aggregate_member_contracts_bound") is not True
        or critical_scope.get("off_host_restore_source_inventory_sha256_bound")
        is not True
        or critical_scope.get("off_host_restore_restored_inventory_sha256_bound")
        is not True
        or critical_scope.get("off_host_restore_inventory_sha256_equality_required")
        is not True
    ):
        raise InventoryHelperError("recovery contract critical-user-data binding mismatch")


def _snapshot_sources() -> None:
    scanner = _read_stable_regular(SCANNER_SOURCE, max_bytes=MAX_SCANNER_BYTES)
    aggregate_scanner = _read_stable_regular(
        AGGREGATE_SCANNER_SOURCE, max_bytes=MAX_SCANNER_BYTES
    )
    contract = _read_stable_regular(
        CONTRACT_SOURCE, max_bytes=MAX_CONTRACT_BYTES
    )
    home_contract = _read_stable_regular(
        HOME_CONTRACT_SOURCE, max_bytes=MAX_CONTRACT_BYTES
    )
    recovery_contract = _read_stable_regular(
        RECOVERY_CONTRACT_SOURCE, max_bytes=MAX_CONTRACT_BYTES
    )
    if _sha256(scanner) != AUTHORIZED_SCANNER_SHA256:
        raise InventoryHelperError("inventory scanner digest mismatch")
    if _sha256(aggregate_scanner) != AUTHORIZED_AGGREGATE_SCANNER_SHA256:
        raise InventoryHelperError("aggregate inventory scanner digest mismatch")
    if _sha256(contract) != AUTHORIZED_CONTRACT_SHA256:
        raise InventoryHelperError("critical-user-data contract digest mismatch")
    if _sha256(home_contract) != AUTHORIZED_HOME_CONTRACT_SHA256:
        raise InventoryHelperError("critical-user-data home contract digest mismatch")
    if _sha256(recovery_contract) != AUTHORIZED_RECOVERY_CONTRACT_SHA256:
        raise InventoryHelperError("recovery contract digest mismatch")
    _validate_contract(contract)
    _validate_home_contract(home_contract)
    _validate_recovery_contract(recovery_contract)

    _ensure_state_root()
    _ensure_private_directory(SNAPSHOT_ROOT)
    _write_create_only(SCANNER_SNAPSHOT, scanner, mode=0o500)
    _write_create_only(
        AGGREGATE_SCANNER_SNAPSHOT, aggregate_scanner, mode=0o500
    )
    _write_create_only(CONTRACT_SNAPSHOT, contract, mode=0o400)
    _write_create_only(HOME_CONTRACT_SNAPSHOT, home_contract, mode=0o400)
    _write_create_only(RECOVERY_CONTRACT_SNAPSHOT, recovery_contract, mode=0o400)

    expected = (
        (SCANNER_SNAPSHOT, AUTHORIZED_SCANNER_SHA256, MAX_SCANNER_BYTES, 0o500),
        (
            AGGREGATE_SCANNER_SNAPSHOT,
            AUTHORIZED_AGGREGATE_SCANNER_SHA256,
            MAX_SCANNER_BYTES,
            0o500,
        ),
        (
            CONTRACT_SNAPSHOT,
            AUTHORIZED_CONTRACT_SHA256,
            MAX_CONTRACT_BYTES,
            0o400,
        ),
        (
            HOME_CONTRACT_SNAPSHOT,
            AUTHORIZED_HOME_CONTRACT_SHA256,
            MAX_CONTRACT_BYTES,
            0o400,
        ),
        (
            RECOVERY_CONTRACT_SNAPSHOT,
            AUTHORIZED_RECOVERY_CONTRACT_SHA256,
            MAX_CONTRACT_BYTES,
            0o400,
        ),
    )
    for path, digest, maximum, mode in expected:
        observed = _read_stable_regular(
            path,
            max_bytes=maximum,
            require_root_owned=True,
            required_mode=mode,
        )
        if _sha256(observed) != digest:
            raise InventoryHelperError("inventory source snapshot mismatch")


def _verified_aggregate_inventory() -> dict[str, Any]:
    aggregate_payload = _read_stable_regular(
        AGGREGATE_SCANNER_SNAPSHOT,
        max_bytes=MAX_SCANNER_BYTES,
        require_root_owned=True,
        required_mode=0o500,
    )
    contract_payload = _read_stable_regular(
        CONTRACT_SNAPSHOT,
        max_bytes=MAX_CONTRACT_BYTES,
        require_root_owned=True,
        required_mode=0o400,
    )
    if _sha256(aggregate_payload) != AUTHORIZED_AGGREGATE_SCANNER_SHA256:
        raise InventoryHelperError("aggregate inventory snapshot digest mismatch")
    if _sha256(contract_payload) != AUTHORIZED_CONTRACT_SHA256:
        raise InventoryHelperError("aggregate contract snapshot digest mismatch")
    try:
        contract_value = json.loads(contract_payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryHelperError("aggregate contract snapshot is invalid") from exc
    if not isinstance(contract_value, dict):
        raise InventoryHelperError("aggregate contract snapshot is invalid")

    module = types.ModuleType("grabowski_verified_critical_data_inventory")
    module.__file__ = str(AGGREGATE_SCANNER_SNAPSHOT)
    try:
        code = compile(
            aggregate_payload,
            str(AGGREGATE_SCANNER_SNAPSHOT),
            "exec",
        )
        exec(code, module.__dict__)
    except (SyntaxError, ValueError, RuntimeError, OSError) as exc:
        raise InventoryHelperError("aggregate inventory payload is invalid") from exc
    if module.__dict__.get("AGGREGATE_EXECUTION_MODE") != AGGREGATE_EXECUTION_MODE:
        raise InventoryHelperError("aggregate inventory execution mode mismatch")
    module.__dict__["_VERIFIED_EXECUTION"] = True
    collect_inventory = module.__dict__.get("collect_inventory")
    if not callable(collect_inventory):
        raise InventoryHelperError("aggregate inventory entrypoint is unavailable")
    try:
        value = collect_inventory(
            CONTRACT_SNAPSHOT,
            classification_only=False,
            max_exclusion_samples=0,
            _contract_snapshot=(contract_value, contract_payload),
            _aggregate_script_bytes=aggregate_payload,
        )
    except Exception as exc:
        raise InventoryHelperError(
            "aggregate inventory execution failed closed"
        ) from exc
    if not isinstance(value, dict):
        raise InventoryHelperError("aggregate inventory result is invalid")
    return value


def _aggregate_payload_execute() -> int:
    try:
        inventory = _verified_aggregate_inventory()
    except InventoryHelperError:
        print("critical aggregate inventory blocked by a safety check", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical(inventory))
    return 0


def aggregate_argv() -> list[str]:
    return [str(HELPER), _request_json("aggregate")]


def _request_json(operation: str) -> str:
    if operation not in {"start", "status", "result", "execute", "aggregate"}:
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
        f"--property=BindPaths={STATE_ROOT}",
        f"--property=ReadWritePaths={STATE_ROOT}",
        f"--property=BindPaths={DURABLE_STATE_ROOT}",
        f"--property=ReadWritePaths={DURABLE_STATE_ROOT}",
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
        or value.get("member_count") != 1
    ):
        raise InventoryHelperError("inventory output identity is invalid")
    inventory_sha = _validate_digest(
        value.get("inventory_sha256"), "inventory_sha256"
    )
    members = value.get("members")
    if (
        not isinstance(members, list)
        or len(members) != 1
        or not isinstance(members[0], dict)
        or set(members[0]) != MEMBER_SUMMARY_FIELDS
    ):
        raise InventoryHelperError("inventory member summary is invalid")
    member = members[0]
    if (
        member.get("id") != "home"
        or member.get("scope") != "critical-user-data-home"
        or member.get("contract_sha256") != AUTHORIZED_HOME_CONTRACT_SHA256
    ):
        raise InventoryHelperError("inventory member binding is invalid")
    member_inventory_sha = _validate_digest(
        member.get("inventory_sha256"), "home inventory_sha256"
    )
    member_record_count = _validate_nonnegative_int(
        member.get("record_count"), "home record_count"
    )
    member_regular_bytes = _validate_nonnegative_int(
        member.get("regular_file_bytes"), "home regular_file_bytes"
    )
    member_exclusion_count = _validate_nonnegative_int(
        member.get("exclusion_boundary_count"), "home exclusion_boundary_count"
    )
    record_count = _validate_nonnegative_int(
        value.get("record_count"), "record_count"
    )
    regular_bytes = _validate_nonnegative_int(
        value.get("regular_file_bytes"), "regular_file_bytes"
    )
    exclusion_count = _validate_nonnegative_int(
        value.get("exclusion_boundary_count"), "exclusion_boundary_count"
    )
    if (
        record_count != member_record_count
        or regular_bytes != member_regular_bytes
        or exclusion_count != member_exclusion_count
    ):
        raise InventoryHelperError("inventory aggregate counts are inconsistent")
    expected_inventory_sha = _sha256(
        _canonical(
            {
                "id": "home",
                "contract_sha256": AUTHORIZED_HOME_CONTRACT_SHA256,
                "inventory_sha256": member_inventory_sha,
            }
        )
    )
    if inventory_sha != expected_inventory_sha:
        raise InventoryHelperError("inventory aggregate digest is inconsistent")
    return {
        **value,
        "members": [dict(member)],
        "record_count": record_count,
        "regular_file_bytes": regular_bytes,
        "exclusion_boundary_count": exclusion_count,
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
    _ensure_state_root()
    _ensure_result_root()
    sealed = _seal_result(value)
    payload = _canonical(sealed)
    if len(payload) > MAX_RESULT_BYTES:
        raise InventoryHelperError("inventory result exceeds size bound")
    temporary = RESULT_PATH.with_name(
        f".{RESULT_PATH.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
    )
    try:
        _write_create_only(temporary, payload, mode=0o600)
        if _rename_noreplace(temporary, RESULT_PATH):
            _fsync_directory(RESULT_ROOT)
            return
        existing = _read_stable_regular(
            RESULT_PATH,
            max_bytes=MAX_RESULT_BYTES,
            require_root_owned=True,
            required_mode=0o600,
        )
        if existing != payload:
            raise InventoryHelperError("existing inventory result differs")
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        _fsync_directory(RESULT_ROOT)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


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
    _ensure_result_root()
    _ensure_private_directory(FAILED_ROOT)
    target = FAILED_ROOT / f"result-{time.time_ns()}.json"
    if not _rename_noreplace(RESULT_PATH, target):
        raise InventoryHelperError("archived inventory result already exists")
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
    _fsync_directory(RESULT_ROOT)


def _lock() -> int:
    _ensure_state_root()
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
    elif _start_attempt_exists():
        status = "outcome-unknown"
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
        _ensure_result_root()
        _snapshot_sources()
        unit = _unit_state()
        if unit["ActiveState"] == "active":
            return _status_payload()
        result = _read_result()
        if result is not None:
            if result["status"] != "failed":
                return _public_result(result)
            # An explicit new start is the recovery action for a terminal failed
            # scan: retain the sealed failure durably, then establish a fresh
            # start fence.
            _archive_failed_result(result)
            _clear_start_attempt()
        elif _start_attempt_exists():
            # Fresh status has already shown the unit inactive and no result is
            # present. The scan is read-only, so an explicit new start may
            # recover this stale transient fence without claiming retry safety
            # for the ambiguous prior request.
            _clear_start_attempt()
        if not _claim_start_attempt():
            raise InventoryHelperError(
                "previous inventory start outcome is unresolved"
            )
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
            result = _read_result()
            if result is not None:
                return _public_result(result)
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
    stdout = b""
    stderr = b""
    try:
        try:
            existing_result = _read_result()
        except InventoryHelperError:
            _clear_start_attempt()
            raise
        if existing_result is not None:
            raise InventoryHelperError("inventory result already exists")
        try:
            _snapshot_sources()
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
            print(
                json.dumps(
                    _seal_result(result),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 2
    finally:
        os.close(descriptor)

    try:
        completed = subprocess.run(
            aggregate_argv(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            check=False,
            timeout=SCANNER_TIMEOUT_SECONDS,
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
        inventory = _validate_inventory_output(stdout)
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
        or value.get("operation") not in {"start", "status", "result", "execute", "aggregate"}
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
    if operation == "aggregate":
        return _aggregate_payload_execute()
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
