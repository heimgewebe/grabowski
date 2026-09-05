#!/usr/bin/env python3
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import pwd
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

LIB_DIR = Path("/usr/local/lib/grabowski")
sys.path.insert(0, str(LIB_DIR))

from grabowski_blockade_authority import execute_lifecycle
from grabowski_privileged_broker import (
    MAX_INPUT_BYTES,
    canonical_sha256,
    claim_once,
    load_root_config,
    parse_reference,
    publish_recovery_marker,
    resolve_execution,
)

CONFIG = Path("/etc/grabowski/privileged-actions.json")
STATE = Path("/var/lib/grabowski/privileged-broker")
AUDIT = STATE / "audit.jsonl"
OUTPUT_EVIDENCE_ROOT = Path("/run/grabowski/privileged-broker-evidence")
OUTPUT_EVIDENCE_KIND = "grabowski_privileged_output_evidence"
PACKAGE_UPDATE_STAGE_ROOT = Path("/var/lib/heim-pc/package-update-stages")
PACKAGE_UPDATE_PLAN_ID_RE = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
PACKAGE_UPDATE_BASENAME_RE = re.compile(r"[-A-Za-z0-9._+@:]{1,255}\Z")
OUTPUT_EVIDENCE_GROUP = "grabowski"
PACKAGE_UPDATE_STAGE_LOCK = STATE / "package-update-stage.lock"
PACKAGE_UPDATE_APPLY_CONSUMED_ROOT = STATE / "package-update-apply-consumed"
PACKAGE_OUTPUT_EVIDENCE_MAX_AGE_SECONDS = 3600
MAX_OUTPUT_EVIDENCE_FILES = 4096
MAX_OUTPUT_BYTES = 250_000
POWER_ACTION = "operator_power_argv"
BLOCKADE_LIFECYCLE_ACTION = "operator_blockade_marker_lifecycle"
ROOTBROKER_CUTOVER_ACTION = "operator_rootbroker_cutover"
LOCAL_BACKUP_SMART_READ_ACTION = "local_backup_smart_read"
LOCAL_BACKUP_SMART_DEVICE = Path(
    "/dev/disk/by-id/usb-Freecom_Freecom_Mobile_Drive_XXS_3.0_93300000078D-0:0"
)
LOCAL_BACKUP_SMART_ARGV = [
    "/usr/sbin/smartctl", "-d", "sat", "-a", str(LOCAL_BACKUP_SMART_DEVICE)
]
ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS = 900
CGROUP_ROOT = Path("/sys/fs/cgroup")
RUN_USER_ROOT = Path("/run/user")
MAX_PEER_CGROUP_PROCESSES = 256
MAX_SYSTEMD_SHOW_BYTES = 16 * 1024
SYSTEMCTL = "/usr/bin/systemctl"
OPERATOR_UNIT_PATH = Path("/etc/systemd/system/grabowski-operator.service")
SAFE_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def append_audit(record: dict[str, object]) -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    state_metadata = STATE.lstat()
    if (
        STATE.is_symlink()
        or not stat.S_ISDIR(state_metadata.st_mode)
        or state_metadata.st_uid != 0
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
    ):
        raise PermissionError("privileged broker audit state is unsafe")
    line = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(AUDIT, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("privileged broker audit file is unsafe")
        written = os.write(descriptor, line)
        if written != len(line):
            raise OSError("privileged broker audit append was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        STATE,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _package_stage_binding(raw_path: object) -> tuple[str, str | None, str | None] | None:
    if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute() or os.path.normpath(raw_path) != raw_path:
        return None
    try:
        relative = path.relative_to(PACKAGE_UPDATE_STAGE_ROOT)
    except ValueError:
        return None
    if not 1 <= len(relative.parts) <= 3:
        return None
    plan_id = relative.parts[0]
    if PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None:
        return None
    if len(relative.parts) == 1:
        return plan_id, None, None
    bucket = relative.parts[1]
    if bucket not in {"debs", "snaps"}:
        return None
    if len(relative.parts) == 2:
        return plan_id, bucket, None
    filename = relative.parts[2]
    if PACKAGE_UPDATE_BASENAME_RE.fullmatch(filename) is None:
        return None
    return plan_id, bucket, filename


def _argv_mentions_package_stage(argv: object) -> bool:
    if not isinstance(argv, list):
        return False
    root = str(PACKAGE_UPDATE_STAGE_ROOT)
    prefix = root + os.sep
    for value in argv:
        if not isinstance(value, str) or "\x00" in value:
            continue
        # Fail closed on lexical descendants before canonical parsing so that
        # alternate spellings cannot opt out of the package-stage guard.
        if value == root or value.startswith(prefix):
            return True
        if not os.path.isabs(value):
            continue
        normalized = os.path.normpath(value)
        try:
            if os.path.commonpath((root, normalized)) == root:
                return True
        except ValueError:
            continue
    return False


def _expected_package_dpkg_preflight_argv(paths: list[str]) -> list[str]:
    return [
        "/usr/bin/dpkg",
        "--simulate",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        *paths,
    ]


def _expected_package_apt_systemd_argv(plan_id: str, paths: list[str]) -> list[str]:
    capture = f"/run/heim-pc-package-update-captures/{plan_id}"
    return [
        "/usr/bin/systemd-run",
        "--system",
        "--wait",
        "--collect",
        "--pipe",
        f"--unit=heim-pc-package-update-{plan_id}.service",
        "--property=Type=exec",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateMounts=yes",
        "--property=PrivateNetwork=yes",
        f"--property=BindPaths={capture}:/run",
        "--property=ProtectProc=invisible",
        # Do not set ProcSubset=pid: kernel package maintainer scripts need
        # read-only non-process /proc interfaces such as cmdline, cpuinfo,
        # mounts and swaps while building initramfs and updating kernelstub.
        "--property=BindReadOnlyPaths=/dev/null:/run/systemd/private /dev/null:/run/dbus/system_bus_socket",
        "--property=ProtectKernelTunables=yes",
        # Kernel DEBs legitimately create /usr/lib/modules/<version> during unpack.
        # ProtectKernelModules= would make that tree read-only and turns a verified
        # offline kernel update into a deterministic partial dpkg transaction.
        "--property=ProtectControlGroups=yes",
        # Kernel package hooks must identify the root/ESP block devices. Keep
        # the device cgroup closed while allowing read-only identity for the
        # audited root and ESP devices only.
        "--property=DevicePolicy=closed",
        "--property=DeviceAllow=/dev/nvme0n1p3 r",
        "--property=DeviceAllow=/dev/nvme0n1p1 r",
        "--property=RestrictNamespaces=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=LockPersonality=yes",
        "--property=CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE CAP_SYS_BOOT CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_TIME CAP_SYS_TTY_CONFIG",
        "--property=MemoryDenyWriteExecute=no",
        "--property=RestrictAddressFamilies=AF_UNIX AF_NETLINK",
        "--property=IPAddressDeny=any",
        "--",
        "/usr/bin/dpkg",
        "--refuse-downgrade",
        "--force-confold",
        "--install",
        *paths,
    ]

def _package_stage_operation(argv: object) -> dict[str, object] | None:
    """Classify package-stage argv for additional fail-closed broker guards."""
    if not _argv_mentions_package_stage(argv):
        return None
    if not isinstance(argv, list) or not argv:
        raise PermissionError("package stage operation argv is invalid")
    root = str(PACKAGE_UPDATE_STAGE_ROOT)
    if argv == ["/usr/bin/stat", "-f", "-c", "%a:%S", root]:
        return {"kind": "readback", "plan_id": None, "package_paths": [], "exact_evidence": False}
    if _package_output_evidence_allowed(argv) and argv[0] == "/usr/bin/sha256sum":
        bindings = [_package_stage_binding(value) for value in argv[1:]]
        plan_ids = {binding[0] for binding in bindings if binding is not None}
        if len(plan_ids) != 1 or any(binding is None or binding[2] is None for binding in bindings):
            raise PermissionError("package hash readback paths are not exact stage files")
        return {
            "kind": "readback",
            "plan_id": next(iter(plan_ids)),
            "package_paths": list(argv[1:]),
            "exact_evidence": False,
        }
    if argv[0] == "/usr/bin/install":
        stage_values = [
            value for value in argv[1:]
            if isinstance(value, str) and _argv_mentions_package_stage([value])
        ]
        bindings = [_package_stage_binding(value) for value in stage_values]
        if not bindings or any(binding is None for binding in bindings):
            raise PermissionError("package install stage binding is invalid")
        canonical = [binding for binding in bindings if binding is not None]
        if len({binding[0] for binding in canonical}) != 1:
            raise PermissionError("package install spans multiple plans")
        return {"kind": "mutation", "plan_id": canonical[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/rm":
        stage_values = [
            value for value in argv[1:]
            if isinstance(value, str) and _argv_mentions_package_stage([value])
        ]
        bindings = [_package_stage_binding(value) for value in stage_values]
        if not bindings or any(binding is None for binding in bindings):
            raise PermissionError("package cleanup stage binding is invalid")
        canonical = [binding for binding in bindings if binding is not None]
        if len({binding[0] for binding in canonical}) != 1:
            raise PermissionError("package cleanup spans multiple plans")
        return {"kind": "mutation", "plan_id": canonical[0][0], "package_paths": [], "exact_evidence": False}
    if argv[0] == "/usr/bin/dpkg":
        file_bindings = [
            (value, binding)
            for value in argv[1:]
            if (binding := _package_stage_binding(value)) is not None and binding[2] is not None
        ]
        if (
            not file_bindings
            or any(binding[1] != "debs" for _, binding in file_bindings)
            or len({binding[0] for _, binding in file_bindings}) != 1
        ):
            raise PermissionError("dpkg package stage execution is not exact-file bound")
        plan_id = file_bindings[0][1][0]
        paths = [value for value, _ in file_bindings]
        if argv != _expected_package_dpkg_preflight_argv(paths):
            raise PermissionError("dpkg package stage preflight argv is not the exact released simulation")
        return {
            "kind": "preflight",
            "operation": "apt_preflight",
            "plan_id": plan_id,
            "package_paths": paths,
            "exact_evidence": True,
        }
    if argv[0] == "/usr/bin/systemd-run":
        file_bindings = [
            (value, binding)
            for value in argv[1:]
            if (binding := _package_stage_binding(value)) is not None and binding[2] is not None
        ]
        if (
            not file_bindings
            or any(binding[1] != "debs" for _, binding in file_bindings)
            or len({binding[0] for _, binding in file_bindings}) != 1
        ):
            raise PermissionError("package systemd dpkg paths are not exact stage DEBs")
        plan_id = file_bindings[0][1][0]
        paths = [value for value, _ in file_bindings]
        if argv != _expected_package_apt_systemd_argv(plan_id, paths):
            raise PermissionError("package systemd execution is not the exact synchronous local APT apply")
        return {
            "kind": "apply",
            "operation": "apt_apply",
            "plan_id": plan_id,
            "package_paths": paths,
            "exact_evidence": True,
        }
    if argv[:2] in (["/usr/bin/snap", "ack"], ["/usr/bin/snap", "install"]):
        if len(argv) != 3:
            raise PermissionError("snap package stage execution has unexpected arguments")
        binding = _package_stage_binding(argv[2])
        if binding is None or binding[1] != "snaps" or binding[2] is None:
            raise PermissionError("snap package stage execution is not exact-file bound")
        return {
            "kind": "apply",
            "operation": "snap_ack" if argv[1] == "ack" else "snap_install",
            "plan_id": binding[0],
            "package_paths": [argv[2]],
            "exact_evidence": True,
        }
    raise PermissionError("unclassified package stage operation is forbidden")

def _ensure_package_state_root() -> None:
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = STATE.lstat()
    if (
        STATE.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid() or metadata.st_nlink < 1
        or (stat.S_IMODE(metadata.st_mode) & 0o022) != 0
    ):
        raise PermissionError("privileged broker package state root is unsafe")


@contextmanager
def _package_stage_lock():
    _ensure_package_state_root()
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(PACKAGE_UPDATE_STAGE_LOCK, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
        ):
            raise PermissionError("privileged broker package stage lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _parse_package_sha256_output(argv: list[str], stdout_bytes: bytes) -> dict[str, str]:
    if not _package_output_evidence_allowed(argv) or argv[0] != "/usr/bin/sha256sum":
        raise ValueError("package hash evidence requires classified sha256sum argv")
    try:
        text = stdout_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("package hash output is not UTF-8") from exc
    observed: dict[str, str] = {}
    for raw_line in text.splitlines():
        parts = raw_line.split(maxsplit=1)
        if len(parts) != 2 or re.fullmatch(r"[0-9a-f]{64}", parts[0]) is None:
            raise ValueError("package hash output line is malformed")
        path = parts[1].lstrip("*").strip()
        if path in observed:
            raise ValueError("package hash output contains a duplicate path")
        observed[path] = parts[0]
    expected = list(argv[1:])
    if list(observed) != expected:
        raise ValueError("package hash output paths differ from requested argv order")
    return observed


def _read_package_output_evidence(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o640 or metadata.st_nlink != 1
        or metadata.st_size > 64 * 1024
    ):
        raise PermissionError("package output evidence file is unsafe")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("kind") != OUTPUT_EVIDENCE_KIND:
        raise ValueError("package output evidence schema is invalid")
    digest = value.get("evidence_sha256")
    unsigned = dict(value)
    unsigned.pop("evidence_sha256", None)
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or canonical_sha256(unsigned) != digest
    ):
        raise ValueError("package output evidence digest is invalid")
    return value


def _read_package_hash_evidence(path: Path) -> dict[str, object]:
    value = _read_package_output_evidence(path)
    paths = value.get("package_paths")
    hashes = value.get("package_sha256")
    plan_id = value.get("package_plan_id")
    if (
        not isinstance(paths, list) or not paths or not isinstance(hashes, dict)
        or set(hashes) != set(paths) or len(hashes) != len(paths) or not isinstance(plan_id, str)
        or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
    ):
        raise ValueError("package hash evidence package binding is invalid")
    for raw_path, digest_value in hashes.items():
        binding = _package_stage_binding(raw_path)
        if binding is None or binding[0] != plan_id or binding[2] is None:
            raise ValueError("package hash evidence contains an unsafe path")
        if not isinstance(digest_value, str) or re.fullmatch(r"[0-9a-f]{64}", digest_value) is None:
            raise ValueError("package hash evidence contains an invalid digest")
    return value

def _sha256_regular_root_file(path: Path) -> str:
    _package_path_identity(path, directory=False)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    _package_path_identity(path, directory=False)
    return digest.hexdigest()


def _package_evidence_candidates() -> list[Path]:
    metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if (
        OUTPUT_EVIDENCE_ROOT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise PermissionError("package output evidence root is unsafe")
    candidates: list[Path] = []
    with os.scandir(OUTPUT_EVIDENCE_ROOT) as entries:
        for entry in entries:
            if len(candidates) >= MAX_OUTPUT_EVIDENCE_FILES:
                raise PermissionError("package output evidence inventory exceeds bound")
            if entry.name.endswith(".json") and entry.is_file(follow_symlinks=False):
                candidates.append(Path(entry.path))
    return candidates


def _find_package_apply_evidence(
    operation: dict[str, object], *, peer_uid: int, peer_unit: str
) -> dict[str, object]:
    required_paths = operation.get("package_paths")
    plan_id = operation.get("plan_id")
    if not isinstance(required_paths, list) or not required_paths or not isinstance(plan_id, str):
        raise PermissionError("package operation lacks exact stage paths")
    now = int(time.time())
    valid: list[dict[str, object]] = []
    for path in _package_evidence_candidates():
        try:
            value = _read_package_hash_evidence(path)
        except (OSError, PermissionError, ValueError, json.JSONDecodeError):
            continue
        timestamp = value.get("timestamp_unix")
        evidence_paths = value.get("package_paths")
        if (
            value.get("peer_uid") != peer_uid
            or value.get("peer_unit") != peer_unit
            or value.get("package_plan_id") != plan_id
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp > now + 5
            or now - timestamp > PACKAGE_OUTPUT_EVIDENCE_MAX_AGE_SECONDS
            or not isinstance(evidence_paths, list)
            or any(path_value not in evidence_paths for path_value in required_paths)
        ):
            continue
        valid.append(value)
    if not valid:
        raise PermissionError("no fresh root-owned package hash evidence matches operation")
    valid.sort(key=lambda item: (int(item["timestamp_unix"]), str(item["request_id"])), reverse=True)
    evidence = valid[0]
    hashes = evidence["package_sha256"]
    assert isinstance(hashes, dict)
    for raw_path in required_paths:
        expected = hashes.get(raw_path)
        if not isinstance(expected, str) or _sha256_regular_root_file(Path(raw_path)) != expected:
            raise PermissionError("package stage bytes changed after authenticated hash readback")
    return evidence


def _argv_sha256(argv: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _find_package_preflight_evidence(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    peer_uid: int,
    peer_unit: str,
) -> dict[str, object]:
    required_paths = operation.get("package_paths")
    plan_id = operation.get("plan_id")
    guard_sha256 = guard_evidence.get("evidence_sha256")
    guard_timestamp = guard_evidence.get("timestamp_unix")
    if (
        operation.get("operation") != "apt_apply"
        or not isinstance(required_paths, list)
        or not required_paths
        or not isinstance(plan_id, str)
        or not isinstance(guard_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
        or isinstance(guard_timestamp, bool)
        or not isinstance(guard_timestamp, int)
    ):
        raise PermissionError("APT apply lacks authenticated preflight binding inputs")
    expected_argv_sha256 = _argv_sha256(_expected_package_dpkg_preflight_argv(required_paths))
    now = int(time.time())
    valid: list[dict[str, object]] = []
    for path in _package_evidence_candidates():
        try:
            value = _read_package_output_evidence(path)
        except (OSError, PermissionError, ValueError, json.JSONDecodeError):
            continue
        timestamp = value.get("timestamp_unix")
        if (
            value.get("package_preflight_completed") is not True
            or value.get("package_operation") != "apt_preflight"
            or value.get("package_exact_evidence") is not True
            or value.get("package_plan_id") != plan_id
            or value.get("package_paths") != required_paths
            or value.get("package_preflight_guard_evidence_sha256") != guard_sha256
            or value.get("argv_sha256") != expected_argv_sha256
            or value.get("peer_uid") != peer_uid
            or value.get("peer_unit") != peer_unit
            or value.get("returncode") != 0
            or value.get("timed_out") is not False
            or value.get("stdout_truncated") is not False
            or value.get("stderr_truncated") is not False
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp < guard_timestamp
            or timestamp > now + 5
            or now - timestamp > PACKAGE_OUTPUT_EVIDENCE_MAX_AGE_SECONDS
        ):
            continue
        valid.append(value)
    if not valid:
        raise PermissionError("no fresh authenticated successful APT preflight matches apply")
    valid.sort(key=lambda item: (int(item["timestamp_unix"]), str(item["request_id"])), reverse=True)
    return valid[0]


def _package_apply_consumption_binding(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    argv: list[str],
) -> dict[str, object]:
    plan_id = operation.get("plan_id")
    paths = operation.get("package_paths")
    guard_sha256 = guard_evidence.get("evidence_sha256")
    if (
        operation.get("kind") != "apply"
        or not isinstance(plan_id, str)
        or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
        or not isinstance(paths, list)
        or not paths
        or any(
            not isinstance(path, str)
            or (binding := _package_stage_binding(path)) is None
            or binding[0] != plan_id
            or binding[2] is None
            for path in paths
        )
        or not isinstance(guard_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
    ):
        raise PermissionError("package apply consumption binding is invalid")
    return {
        "schema_version": 1,
        "package_plan_id": plan_id,
        "package_paths": list(paths),
        "package_guard_evidence_sha256": guard_sha256,
        "argv_sha256": _argv_sha256(argv),
    }


def _package_apply_consumption_path(binding: dict[str, object]) -> Path:
    return PACKAGE_UPDATE_APPLY_CONSUMED_ROOT / f"{canonical_sha256(binding)}.json"


def _ensure_package_apply_consumption_root() -> None:
    _ensure_package_state_root()
    try:
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    metadata = PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.lstat()
    if (
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 1
    ):
        raise PermissionError("package apply consumption root is unsafe")


def _assert_package_apply_not_consumed(
    operation: dict[str, object],
    *,
    guard_evidence: dict[str, object],
    argv: list[str],
) -> dict[str, object]:
    binding = _package_apply_consumption_binding(
        operation, guard_evidence=guard_evidence, argv=argv
    )
    _ensure_package_apply_consumption_root()
    path = _package_apply_consumption_path(binding)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return binding
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise PermissionError("package apply consumption marker is unsafe")
    raise PermissionError("package apply guard evidence was already consumed for this exact operation")


def _consume_package_apply(binding: dict[str, object]) -> dict[str, str]:
    _ensure_package_apply_consumption_root()
    path = _package_apply_consumption_path(binding)
    record: dict[str, object] = {
        **binding,
        "package_apply_completed": True,
        "timestamp_unix": int(time.time()),
    }
    record["record_sha256"] = canonical_sha256(record)
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise PermissionError(
            "package apply guard evidence was already consumed for this exact operation"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise PermissionError("package apply consumption marker is unsafe")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("package apply consumption marker write was incomplete")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        PACKAGE_UPDATE_APPLY_CONSUMED_ROOT,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(path), "sha256": str(record["record_sha256"])}

def _package_output_evidence_allowed(argv: object) -> bool:
    """Allow public evidence only for bounded non-secret package readbacks."""
    if argv == [
        "/usr/bin/stat", "-f", "-c", "%a:%S", str(PACKAGE_UPDATE_STAGE_ROOT)
    ]:
        return True
    if not isinstance(argv, list) or len(argv) < 2 or argv[0] != "/usr/bin/sha256sum":
        return False
    plan_ids: set[str] = set()
    for raw_path in argv[1:]:
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            return False
        path = Path(raw_path)
        if not path.is_absolute() or os.path.normpath(raw_path) != raw_path:
            return False
        try:
            relative = path.relative_to(PACKAGE_UPDATE_STAGE_ROOT)
        except ValueError:
            return False
        if len(relative.parts) != 3:
            return False
        plan_id, bucket, filename = relative.parts
        if (
            PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
            or bucket not in {"debs", "snaps"}
            or filename in {"", ".", ".."}
        ):
            return False
        plan_ids.add(plan_id)
    return len(plan_ids) == 1


def _package_path_identity(path: Path, *, directory: bool) -> tuple[int, ...]:
    metadata = path.lstat()
    expected_uid = os.geteuid()
    if stat.S_ISLNK(metadata.st_mode):
        raise PermissionError("package readback path may not be a symlink")
    if directory:
        if not stat.S_ISDIR(metadata.st_mode):
            raise PermissionError("package readback directory is not a directory")
    else:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PermissionError("package readback artifact must be a single-link regular file")
    if metadata.st_uid != expected_uid or metadata.st_mode & 0o022:
        raise PermissionError("package readback path is not root-controlled")
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _package_output_identity_snapshot(argv: list[str]) -> dict[str, tuple[int, ...]]:
    if not _package_output_evidence_allowed(argv):
        raise PermissionError("package output evidence argv is not classified")
    snapshot: dict[str, tuple[int, ...]] = {}
    # The fixed parent and stage root close component-level symlink replacement
    # before any classified readback is spawned.
    for directory in (PACKAGE_UPDATE_STAGE_ROOT.parent, PACKAGE_UPDATE_STAGE_ROOT):
        snapshot[str(directory)] = _package_path_identity(directory, directory=True)
    if argv[0] == "/usr/bin/stat":
        return snapshot
    for raw_path in argv[1:]:
        path = Path(raw_path)
        relative = path.relative_to(PACKAGE_UPDATE_STAGE_ROOT)
        plan_id, bucket, filename = relative.parts
        if PACKAGE_UPDATE_BASENAME_RE.fullmatch(filename) is None:
            raise PermissionError("package readback artifact basename is unsafe")
        plan_dir = PACKAGE_UPDATE_STAGE_ROOT / plan_id
        bucket_dir = plan_dir / bucket
        for directory in (plan_dir, bucket_dir):
            key = str(directory)
            if key not in snapshot:
                snapshot[key] = _package_path_identity(directory, directory=True)
        snapshot[str(path)] = _package_path_identity(path, directory=False)
    return snapshot


def _write_output_evidence(
    record: dict[str, object], *, argv: list[str] | None = None, stdout_bytes: bytes | None = None,
    package_operation: dict[str, object] | None = None,
    package_guard_evidence: dict[str, object] | None = None,
    package_preflight_evidence: dict[str, object] | None = None,
) -> dict[str, str]:
    """Publish root-owned evidence only for classified non-secret output."""
    request_id = record.get("request_id")
    if not isinstance(request_id, str) or len(request_id) != 32 or any(
        character not in "0123456789abcdef" for character in request_id
    ):
        raise ValueError("privileged output evidence request_id is invalid")
    if record.get("action") != POWER_ACTION:
        raise ValueError("privileged output evidence is only defined for operator power argv")
    if not isinstance(record.get("peer_uid"), int) or not isinstance(record.get("peer_unit"), str):
        raise ValueError("privileged output evidence peer identity is invalid")
    required = {
        "reference_sha256", "action", "mode", "argv_sha256", "cwd_sha256",
        "returncode", "timed_out", "stdout_sha256", "stdout_bytes",
        "stdout_truncated", "stderr_truncated", "timestamp_unix",
    }
    if any(key not in record for key in required):
        raise ValueError("privileged output evidence source record is incomplete")
    if (
        record.get("returncode") != 0
        or record.get("timed_out") is not False
        or record.get("stdout_truncated") is not False
        or record.get("stderr_truncated") is not False
    ):
        raise ValueError("privileged output evidence requires complete successful output")

    parent = OUTPUT_EVIDENCE_ROOT.parent
    parent_metadata = parent.lstat()
    expected_uid = os.geteuid()
    try:
        configured_gid = grp.getgrnam(OUTPUT_EVIDENCE_GROUP).gr_gid
    except KeyError as exc:
        raise PermissionError("privileged output evidence group is unavailable") from exc
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_uid
        or parent_metadata.st_gid != configured_gid
        or parent_metadata.st_mode & 0o022
    ):
        raise PermissionError("privileged output evidence parent is unsafe")
    created = False
    try:
        OUTPUT_EVIDENCE_ROOT.mkdir(parents=False, mode=0o750)
        created = True
    except FileExistsError:
        pass
    metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
    ):
        raise PermissionError("privileged output evidence directory is unsafe")
    if created:
        os.chown(OUTPUT_EVIDENCE_ROOT, expected_uid, configured_gid)
        os.chmod(OUTPUT_EVIDENCE_ROOT, 0o750)
        metadata = OUTPUT_EVIDENCE_ROOT.lstat()
    if metadata.st_gid != configured_gid or stat.S_IMODE(metadata.st_mode) != 0o750:
        raise PermissionError("privileged output evidence directory contract drifted")
    evidence_gid = configured_gid

    evidence: dict[str, object] = {
        "schema_version": 1,
        "kind": OUTPUT_EVIDENCE_KIND,
        "request_id": request_id,
        "reference_sha256": record["reference_sha256"],
        "action": record["action"],
        "mode": record["mode"],
        "argv_sha256": record["argv_sha256"],
        "cwd_sha256": record["cwd_sha256"],
        "peer_uid": record.get("peer_uid"),
        "peer_unit": record.get("peer_unit"),
        "returncode": record["returncode"],
        "timed_out": record["timed_out"],
        "stdout_sha256": record["stdout_sha256"],
        "stdout_bytes": record["stdout_bytes"],
        "stdout_truncated": record["stdout_truncated"],
        "stderr_truncated": record["stderr_truncated"],
        "timestamp_unix": record["timestamp_unix"],
    }
    if isinstance(argv, list) and argv and argv[0] == "/usr/bin/sha256sum":
        if stdout_bytes is None:
            raise ValueError("package hash evidence requires exact stdout bytes")
        package_sha256 = _parse_package_sha256_output(argv, stdout_bytes)
        binding = _package_stage_binding(argv[1])
        if binding is None:
            raise ValueError("package hash evidence has no canonical plan binding")
        evidence["package_plan_id"] = binding[0]
        evidence["package_paths"] = list(argv[1:])
        evidence["package_sha256"] = package_sha256
    if package_operation is not None:
        kind = package_operation.get("kind")
        if kind not in {"preflight", "apply"}:
            raise ValueError("package completion evidence requires a preflight or apply operation")
        plan_id = package_operation.get("plan_id")
        package_paths = package_operation.get("package_paths")
        guard_sha256 = (package_guard_evidence or {}).get("evidence_sha256")
        if (
            not isinstance(plan_id, str) or PACKAGE_UPDATE_PLAN_ID_RE.fullmatch(plan_id) is None
            or not isinstance(package_paths, list) or not package_paths
            or any(not isinstance(path, str) or _package_stage_binding(path) is None for path in package_paths)
            or not isinstance(guard_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", guard_sha256) is None
        ):
            raise ValueError("package completion evidence binding is invalid")
        evidence["package_plan_id"] = plan_id
        evidence["package_paths"] = list(package_paths)
        evidence["package_operation"] = package_operation.get("operation")
        evidence["package_exact_evidence"] = package_operation.get("exact_evidence") is True
        if kind == "preflight":
            evidence["package_preflight_completed"] = True
            evidence["package_preflight_guard_evidence_sha256"] = guard_sha256
        else:
            evidence["package_apply_completed"] = True
            evidence["package_apply_guard_evidence_sha256"] = guard_sha256
            if package_operation.get("operation") == "apt_apply":
                preflight_sha256 = (package_preflight_evidence or {}).get("evidence_sha256")
                if (
                    not isinstance(preflight_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", preflight_sha256) is None
                ):
                    raise ValueError("APT apply completion evidence lacks authenticated preflight")
                evidence["package_apply_preflight_evidence_sha256"] = preflight_sha256
    evidence["evidence_sha256"] = canonical_sha256(evidence)
    raw = (json.dumps(evidence, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    destination = OUTPUT_EVIDENCE_ROOT / f"{request_id}.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.fchown(descriptor, expected_uid, evidence_gid)
        os.fchmod(descriptor, 0o640)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("privileged output evidence write was incomplete")
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != evidence_gid
            or stat.S_IMODE(metadata.st_mode) != 0o640
            or metadata.st_nlink != 1
        ):
            raise PermissionError("privileged output evidence file is unsafe")
    finally:
        os.close(descriptor)
    directory = os.open(
        OUTPUT_EVIDENCE_ROOT,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {"path": str(destination), "sha256": str(evidence["evidence_sha256"])}


def _public_audit_record(record: dict[str, object]) -> dict[str, object]:
    public = dict(record)
    for key in ("stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes"):
        public.pop(key, None)
    return public

def _base_audit_record(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
) -> dict[str, object]:
    argv = execution.get("argv")
    cwd = execution.get("cwd")
    record = {
        "schema_version": 1,
        "timestamp_unix": int(time.time()),
        "request_id": str(reference["request_id"]),
        "reference_sha256": str(reference["reference_sha256"]),
        "action": str(reference["action"]),
        "mode": str(execution.get("mode", "template")),
        "target_sha256": hashlib.sha256(str(reference["target"]).encode("utf-8")).hexdigest(),
        "cwd_sha256": hashlib.sha256(str(cwd or "").encode("utf-8")).hexdigest(),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if isinstance(argv, list):
        record["argv_sha256"] = hashlib.sha256(
            json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    if execution.get("internal_action") is not None:
        record["internal_action"] = str(execution["internal_action"])
    gate = execution.get("gate")
    if isinstance(gate, dict):
        record["gate_recovery_marker_sha256"] = gate.get("recovery_marker_sha256")
        record["gate_recovery_marker_source_sha256"] = gate.get("recovery_marker_source_sha256")
        record["gate_recovery_marker_timestamp_unix"] = gate.get("recovery_marker_timestamp_unix")
        record["gate_recovery_marker_age_seconds"] = gate.get("recovery_marker_age_seconds")
        record["gate_recovery_marker_max_age_seconds"] = gate.get("recovery_marker_max_age_seconds")
        record["gate_recovery_marker_freshness_reason"] = gate.get("recovery_marker_freshness_reason")
    for optional_key in (
        "policy_intent",
        "argv_catalog_sha256",
        "matched_argv_prefix_sha256",
    ):
        optional_value = execution.get(optional_key)
        if optional_value is not None:
            record[optional_key] = optional_value
    return record



def _run_recovery_publication(
    reference: dict[str, object],
    execution: dict[str, object],
) -> int:
    claim_once(STATE / "used", str(reference["request_id"]))
    started = time.monotonic()
    published = publish_recovery_marker(execution)
    record = {
        **_base_audit_record(reference, execution, started),
        "returncode": 0,
        "timed_out": False,
        "published": published.get("published"),
        "idempotent": published.get("idempotent"),
        "recovery_record_sha256": published.get("record_sha256"),
        "recovery_source_record_sha256": published.get("source_record_sha256"),
        "recovery_generated_at_unix": published.get("generated_at_unix"),
        "recovery_freshness_reason": published.get("freshness_reason"),
    }
    append_audit(record)
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution["mode"],
        "returncode": 0,
        "timed_out": False,
        "publication": published,
        "audit": record,
    }, ensure_ascii=False, sort_keys=True))
    return 0

def _socket_peer_credentials(descriptor: int = 0) -> tuple[int, int, int]:
    duplicate = os.dup(descriptor)
    try:
        with socket.socket(fileno=duplicate) as connection:
            raw = connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer is not observable") from exc
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PermissionError("blockade lifecycle peer credentials are invalid")
    return pid, uid, gid


def _unified_cgroup_path(pid: int, *, proc_root: Path) -> str:
    try:
        cgroup_raw = (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8")
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer cgroup is not observable") from exc
    unified_paths: list[str] = []
    for line in cgroup_raw.splitlines():
        fields = line.split(":", 2)
        if len(fields) == 3 and fields[0] == "0" and fields[1] == "":
            unified_paths.append(fields[2])
    if len(unified_paths) != 1 or not unified_paths[0].startswith("/"):
        raise PermissionError("blockade lifecycle peer cgroup is not canonical")
    return unified_paths[0]


def _process_identity(pid: int, *, proc_root: Path) -> tuple[int, int]:
    try:
        raw = (proc_root / str(pid) / "stat").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer process identity is not observable") from exc
    closing = raw.rfind(")")
    if closing <= 0 or not raw.startswith(f"{pid} ("):
        raise PermissionError("blockade lifecycle peer process identity is malformed")
    fields = raw[closing + 1 :].strip().split()
    if len(fields) < 20:
        raise PermissionError("blockade lifecycle peer process identity is incomplete")
    try:
        parent_pid = int(fields[1])
        starttime_ticks = int(fields[19])
    except ValueError as exc:
        raise PermissionError("blockade lifecycle peer process identity is invalid") from exc
    if parent_pid <= 0 or starttime_ticks <= 0:
        raise PermissionError("blockade lifecycle peer process identity is invalid")
    return parent_pid, starttime_ticks


def _cgroup_processes(
    unified_path: str,
    *,
    cgroup_root: Path,
) -> tuple[int, ...]:
    relative = Path(unified_path.lstrip("/"))
    if not relative.parts or ".." in relative.parts:
        raise PermissionError("blockade lifecycle service cgroup path is invalid")
    try:
        raw = (cgroup_root / relative / "cgroup.procs").read_text(encoding="utf-8")
    except OSError as exc:
        raise PermissionError("blockade lifecycle service process set is not observable") from exc
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines or len(lines) > MAX_PEER_CGROUP_PROCESSES:
        raise PermissionError("blockade lifecycle service process set is invalid")
    try:
        processes = tuple(sorted({int(line) for line in lines}))
    except ValueError as exc:
        raise PermissionError("blockade lifecycle service process set is malformed") from exc
    if len(processes) != len(lines) or any(pid <= 0 for pid in processes):
        raise PermissionError("blockade lifecycle service process set is invalid")
    return processes


def _operator_system_unit_identity(uid: int, unit: str) -> dict[str, object]:
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise PermissionError("blockade lifecycle operator account is unavailable") from exc
    username = account.pw_name
    if (
        not username
        or len(username) > 64
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in username
        )
    ):
        raise PermissionError("blockade lifecycle operator account is invalid")
    completed = subprocess.run(
        [
            SYSTEMCTL,
            "show",
            unit,
            "--property=MainPID",
            "--property=ControlGroup",
            "--property=ActiveState",
            "--property=SubState",
            "--property=User",
            "--property=FragmentPath",
            "--no-pager",
        ],
        cwd="/",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
        env=SAFE_ENV,
    )
    if completed.returncode != 0 or len(completed.stdout) > MAX_SYSTEMD_SHOW_BYTES:
        raise PermissionError("blockade lifecycle operator system unit identity is unavailable")
    try:
        text = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PermissionError("blockade lifecycle operator system unit identity is malformed") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise PermissionError("blockade lifecycle operator system unit identity is malformed")
        values[key] = value
    required = {
        "MainPID",
        "ControlGroup",
        "ActiveState",
        "SubState",
        "User",
        "FragmentPath",
    }
    if set(values) != required:
        raise PermissionError("blockade lifecycle operator system unit identity is incomplete")
    try:
        main_pid = int(values["MainPID"])
    except ValueError as exc:
        raise PermissionError("blockade lifecycle operator MainPID is invalid") from exc
    control_group = values["ControlGroup"]
    fragment = Path(values["FragmentPath"])
    if (
        main_pid <= 1
        or not control_group.startswith("/system.slice/")
        or values["ActiveState"] != "active"
        or values["SubState"] != "running"
        or values["User"] != username
        or fragment != OPERATOR_UNIT_PATH
    ):
        raise PermissionError("blockade lifecycle operator system unit is not authoritative")
    try:
        fragment_meta = fragment.lstat()
    except OSError as exc:
        raise PermissionError("blockade lifecycle operator system unit fragment is unavailable") from exc
    if (
        fragment.is_symlink()
        or not stat.S_ISREG(fragment_meta.st_mode)
        or fragment_meta.st_uid != 0
        or fragment_meta.st_mode & 0o022
    ):
        raise PermissionError("blockade lifecycle operator system unit fragment is unsafe")
    return {
        "main_pid": main_pid,
        "control_group": control_group,
        "active_state": values["ActiveState"],
        "sub_state": values["SubState"],
        "username": username,
        "home": account.pw_dir,
        "fragment_path": str(fragment),
    }


def _validate_system_cgroup_authority(
    unified_path: str, *, cgroup_root: Path
) -> None:
    relative = Path(unified_path.lstrip("/"))
    if not relative.parts or ".." in relative.parts:
        raise PermissionError("blockade lifecycle operator system cgroup path is invalid")
    target = cgroup_root / relative
    try:
        metadata = target.lstat()
        procs = (target / "cgroup.procs").lstat()
    except OSError as exc:
        raise PermissionError("blockade lifecycle operator system cgroup is unavailable") from exc
    if (
        target.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not stat.S_ISREG(procs.st_mode)
        or procs.st_uid != 0
        or procs.st_mode & 0o022
    ):
        raise PermissionError("blockade lifecycle operator system cgroup is not root-controlled")


def _operator_expected_argv(home: str) -> tuple[str, ...]:
    if not isinstance(home, str) or not home.startswith("/") or "\x00" in home:
        raise PermissionError("blockade lifecycle operator home is invalid")
    python = str(Path(home) / ".local/share/grabowski-mcp/.venv/bin/python")
    return (
        python,
        "-m",
        "grabowski_operator",
        "--transport",
        "streamable-http",
        "--host",
        "127.0.0.1",
        "--port",
        "18181",
    )


def _process_cmdline(pid: int, *, proc_root: Path) -> tuple[str, ...]:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise PermissionError("blockade lifecycle peer command identity is not observable") from exc
    if not raw or len(raw) > 16 * 1024 or not raw.endswith(b"\x00"):
        raise PermissionError("blockade lifecycle peer command identity is malformed")
    try:
        argv = tuple(item.decode("utf-8", errors="strict") for item in raw[:-1].split(b"\x00"))
    except UnicodeDecodeError as exc:
        raise PermissionError("blockade lifecycle peer command identity is malformed") from exc
    if not argv or any(not item or "\x00" in item for item in argv):
        raise PermissionError("blockade lifecycle peer command identity is invalid")
    return argv


def _validate_blockade_lifecycle_peer(
    execution: dict[str, object],
    *,
    descriptor: int = 0,
    proc_root: Path = Path("/proc"),
    cgroup_root: Path = CGROUP_ROOT,
    unit_identity: dict[str, object] | None = None,
    expected_argv: tuple[str, ...] | None = None,
) -> dict[str, object]:
    pid, uid, gid = _socket_peer_credentials(descriptor)
    expected_uid = execution.get("allowed_peer_uid")
    expected_unit = execution.get("allowed_peer_unit")
    if (
        isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or uid != expected_uid
    ):
        raise PermissionError("blockade lifecycle peer UID is not authorized")
    if not isinstance(expected_unit, str) or not expected_unit:
        raise PermissionError("blockade lifecycle peer unit is not configured")
    observed_unit = (
        _operator_system_unit_identity(expected_uid, expected_unit)
        if unit_identity is None
        else dict(unit_identity)
    )
    systemd_main_pid = observed_unit.get("main_pid")
    systemd_control_group = observed_unit.get("control_group")
    if systemd_main_pid != pid:
        raise PermissionError("blockade lifecycle peer is not systemd MainPID")
    if not isinstance(systemd_control_group, str) or not systemd_control_group:
        raise PermissionError("blockade lifecycle operator ControlGroup is invalid")

    unified_path = _unified_cgroup_path(pid, proc_root=proc_root)
    expected_suffix = "/" + expected_unit
    if (
        not unified_path.endswith(expected_suffix)
        or unified_path != systemd_control_group
    ):
        raise PermissionError("blockade lifecycle peer is outside the operator service")
    _validate_system_cgroup_authority(
        unified_path, cgroup_root=cgroup_root
    )
    effective_expected_argv = (
        _operator_expected_argv(str(observed_unit.get("home", "")))
        if expected_argv is None
        else tuple(expected_argv)
    )
    if _process_cmdline(pid, proc_root=proc_root) != effective_expected_argv:
        raise PermissionError("blockade lifecycle peer command identity is unauthorized")

    members_before = _cgroup_processes(unified_path, cgroup_root=cgroup_root)
    if pid not in members_before:
        raise PermissionError("blockade lifecycle peer is absent from the operator service cgroup")
    identities = {
        member: _process_identity(member, proc_root=proc_root)
        for member in members_before
    }
    oldest_starttime = min(identity[1] for identity in identities.values())
    oldest_members = tuple(
        member
        for member in members_before
        if identities[member][1] == oldest_starttime
    )
    if len(oldest_members) != 1:
        raise PermissionError(
            "blockade lifecycle operator service main process is ambiguous"
        )
    parent_pid, starttime_ticks = identities[pid]
    if oldest_members[0] != pid:
        raise PermissionError(
            "blockade lifecycle peer is not the operator service main process"
        )
    try:
        parent_cgroup = _unified_cgroup_path(parent_pid, proc_root=proc_root)
    except PermissionError as exc:
        raise PermissionError("blockade lifecycle peer parent is not observable") from exc
    if parent_cgroup == unified_path:
        raise PermissionError("blockade lifecycle peer is a child of the operator service")
    members_after = _cgroup_processes(unified_path, cgroup_root=cgroup_root)
    if members_after != members_before:
        raise PermissionError("blockade lifecycle service process set changed during validation")
    return {
        "pid": pid,
        "uid": uid,
        "gid": gid,
        "cgroup": unified_path,
        "unit": expected_unit,
        "starttime_ticks": starttime_ticks,
        "cgroup_process_count": len(members_before),
        "systemd_main_pid": systemd_main_pid,
        "systemd_control_group": systemd_control_group,
    }


def _operator_peer_audit_fields(peer: dict[str, object]) -> dict[str, object]:
    return {
        "peer_pid": peer["pid"],
        "peer_uid": peer["uid"],
        "peer_gid": peer["gid"],
        "peer_cgroup": peer["cgroup"],
        "peer_unit": peer["unit"],
        "peer_starttime_ticks": peer.get("starttime_ticks"),
        "peer_cgroup_process_count": peer.get("cgroup_process_count"),
        "peer_systemd_main_pid": peer.get("systemd_main_pid"),
        "peer_systemd_control_group": peer.get("systemd_control_group"),
    }


def _lifecycle_audit_base(
    reference: dict[str, object],
    execution: dict[str, object],
    started: float,
    peer: dict[str, object],
) -> dict[str, object]:
    record = {
        **_base_audit_record(reference, execution, started),
        **_operator_peer_audit_fields(peer),
        "lifecycle_operation": execution.get("operation"),
    }
    gate = execution.get("recovery_gate")
    if isinstance(gate, dict):
        record["gate_recovery_marker_sha256"] = gate.get(
            "recovery_marker_sha256"
        )
        record["gate_recovery_marker_source_sha256"] = gate.get(
            "recovery_marker_source_sha256"
        )
    return record


def _append_lifecycle_audit(record: dict[str, object]) -> dict[str, object]:
    enriched = dict(record)
    enriched["record_sha256"] = canonical_sha256(enriched)
    append_audit(enriched)
    return enriched


def _run_blockade_lifecycle(
    reference: dict[str, object],
    execution: dict[str, object],
    *,
    peer: dict[str, object],
) -> int:
    claim_once(STATE / "used", str(reference["request_id"]))
    started = time.monotonic()
    intent = _append_lifecycle_audit(
        {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "intent",
            "returncode": None,
            "timed_out": False,
        }
    )
    try:
        lifecycle = execute_lifecycle(execution)
    except BaseException as lifecycle_failure:
        failure = {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "failure",
            "returncode": 1,
            "timed_out": False,
            "intent_record_sha256": intent["record_sha256"],
            "error_type": type(lifecycle_failure).__name__,
            "error": str(lifecycle_failure)[:500],
        }
        try:
            _append_lifecycle_audit(failure)
        except BaseException as audit_failure:
            raise RuntimeError(
                "blockade lifecycle failed after intent and failure audit could not be written"
            ) from audit_failure
        raise
    completion = _append_lifecycle_audit(
        {
            **_lifecycle_audit_base(reference, execution, started, peer),
            "phase": "complete",
            "returncode": 0,
            "timed_out": False,
            "intent_record_sha256": intent["record_sha256"],
            "lifecycle_sha256": canonical_sha256(lifecycle),
            "lifecycle_receipt_sha256": lifecycle.get("receipt_sha256"),
        }
    )
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution["mode"],
        "returncode": 0,
        "timed_out": False,
        "lifecycle": lifecycle,
        "audit_intent": intent,
        "audit": completion,
    }, ensure_ascii=False, sort_keys=True))
    return 0


def _communicate_after_timeout(
    *,
    action: object,
    process: object,
) -> tuple[bytes, bytes]:
    if action == ROOTBROKER_CUTOVER_ACTION:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            return process.communicate(
                timeout=ROOTBROKER_TIMEOUT_ROLLBACK_GRACE_SECONDS
            )
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return process.communicate()


def _local_backup_smart_device_identity() -> tuple[str, int]:
    """Resolve the fixed USB By-ID and prove it still names one block device."""
    try:
        link_metadata = LOCAL_BACKUP_SMART_DEVICE.lstat()
    except OSError as exc:
        raise PermissionError("BACKUP SMART By-ID is unavailable") from exc
    if not stat.S_ISLNK(link_metadata.st_mode):
        raise PermissionError("BACKUP SMART By-ID is not a symlink")
    try:
        resolved = LOCAL_BACKUP_SMART_DEVICE.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise PermissionError("BACKUP SMART By-ID target is unavailable") from exc
    if not stat.S_ISBLK(metadata.st_mode):
        raise PermissionError("BACKUP SMART By-ID target is not a block device")
    return str(resolved), int(metadata.st_rdev)


def _assert_local_backup_smart_pre_spawn(
    *,
    reference: dict[str, object],
    argv: object,
) -> None:
    if reference.get("action") != LOCAL_BACKUP_SMART_READ_ACTION:
        return
    if argv != LOCAL_BACKUP_SMART_ARGV:
        raise PermissionError("BACKUP SMART argv differs from the fixed read-only contract")
    first = _local_backup_smart_device_identity()
    second = _local_backup_smart_device_identity()
    if second != first:
        raise PermissionError("BACKUP SMART By-ID identity changed before spawn")


def _execute_broker_command(
    *,
    reference: dict[str, object],
    execution: dict[str, object],
    operator_peer: dict[str, object] | None,
) -> dict[str, object]:
    argv = execution["argv"]
    timeout = execution["timeout_seconds"]
    cwd = execution.get("cwd")
    package_operation = _package_stage_operation(argv) if reference.get("action") == POWER_ACTION else None
    package_identity_before: dict[str, tuple[int, ...]] | None = None
    package_guard_evidence: dict[str, object] | None = None
    package_preflight_evidence: dict[str, object] | None = None
    package_consumption_binding: dict[str, object] | None = None
    package_consumption: dict[str, str] | None = None
    context = _package_stage_lock() if package_operation is not None else nullcontext()
    with context:
        if (
            package_operation is not None
            and package_operation.get("kind") == "readback"
            and _package_output_evidence_allowed(argv)
        ):
            package_identity_before = _package_output_identity_snapshot(argv)
        if package_operation is not None and package_operation.get("kind") in {"preflight", "apply"}:
            if operator_peer is None:
                raise PermissionError("package preflight/apply requires validated operator peer")
            peer_fields = _operator_peer_audit_fields(operator_peer)
            package_guard_evidence = _find_package_apply_evidence(
                package_operation,
                peer_uid=int(peer_fields["peer_uid"]),
                peer_unit=str(peer_fields["peer_unit"]),
            )
            if package_operation.get("kind") == "apply":
                if package_operation.get("operation") == "apt_apply":
                    package_preflight_evidence = _find_package_preflight_evidence(
                        package_operation,
                        guard_evidence=package_guard_evidence,
                        peer_uid=int(peer_fields["peer_uid"]),
                        peer_unit=str(peer_fields["peer_unit"]),
                    )
                package_consumption_binding = _assert_package_apply_not_consumed(
                    package_operation,
                    guard_evidence=package_guard_evidence,
                    argv=argv,
                )
        _assert_local_backup_smart_pre_spawn(reference=reference, argv=argv)
        started = time.monotonic()
        process = subprocess.Popen(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SAFE_ENV,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            stdout_bytes, stderr_bytes = _communicate_after_timeout(
                action=reference.get("action"), process=process,
            )
        stdout = stdout_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr = stderr_bytes[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        record = {
            **_base_audit_record(reference, execution, started),
            **(_operator_peer_audit_fields(operator_peer) if operator_peer is not None else {}),
            "returncode": None if timed_out else process.returncode,
            "timed_out": timed_out,
            "stdout_truncated": len(stdout_bytes) > MAX_OUTPUT_BYTES,
            "stderr_truncated": len(stderr_bytes) > MAX_OUTPUT_BYTES,
        }
        if reference["action"] == POWER_ACTION:
            record.update({
                "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
                "stdout_bytes": len(stdout_bytes),
                "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
                "stderr_bytes": len(stderr_bytes),
            })
        if reference["action"] == LOCAL_BACKUP_SMART_READ_ACTION:
            public_stdout = stdout.encode("utf-8")
            public_stderr = stderr.encode("utf-8")
            record.update({
                "smart_stdout_sha256": hashlib.sha256(public_stdout).hexdigest(),
                "smart_stdout_bytes": len(public_stdout),
                "smart_stderr_sha256": hashlib.sha256(public_stderr).hexdigest(),
                "smart_stderr_bytes": len(public_stderr),
            })
        if package_operation is not None:
            record["package_stage_guard"] = str(package_operation.get("kind"))
            record["package_stage_plan_id"] = package_operation.get("plan_id")
            record["package_stage_operation"] = package_operation.get("operation")
        if package_guard_evidence is not None:
            record["package_guard_evidence_sha256"] = package_guard_evidence.get("evidence_sha256")
            record["package_guard_evidence_request_id"] = package_guard_evidence.get("request_id")
            if package_operation is not None and package_operation.get("kind") == "apply":
                record["package_apply_evidence_sha256"] = package_guard_evidence.get("evidence_sha256")
                record["package_apply_evidence_request_id"] = package_guard_evidence.get("request_id")
        if package_preflight_evidence is not None:
            record["package_apply_preflight_evidence_sha256"] = package_preflight_evidence.get("evidence_sha256")
            record["package_apply_preflight_evidence_request_id"] = package_preflight_evidence.get("request_id")

        consumption_error: Exception | None = None
        if (
            package_operation is not None
            and package_operation.get("kind") == "apply"
            and record["returncode"] == 0
            and record["timed_out"] is False
        ):
            if package_consumption_binding is None:
                raise RuntimeError("package apply has no replay-consumption binding")
            try:
                package_consumption = _consume_package_apply(package_consumption_binding)
                record["package_apply_consumed_sha256"] = package_consumption["sha256"]
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                consumption_error = exc
                record["package_apply_consumption_error"] = type(exc).__name__

        append_audit(record)
        if consumption_error is not None:
            raise PermissionError(
                "package apply succeeded but replay-consumption marker could not be committed"
            ) from consumption_error

        output_evidence = None
        output_evidence_status = "not-applicable"
        readback_retry_safe = False
        if package_identity_before is not None:
            readback_retry_safe = True
            output_evidence_status = "unavailable"
            if (
                record["returncode"] == 0
                and record["timed_out"] is False
                and record["stdout_truncated"] is False
                and record["stderr_truncated"] is False
            ):
                try:
                    package_identity_after = _package_output_identity_snapshot(argv)
                    if package_identity_after != package_identity_before:
                        raise PermissionError("package readback identity changed during execution")
                    output_evidence = _write_output_evidence(
                        record, argv=argv, stdout_bytes=stdout_bytes
                    )
                    output_evidence_status = "published"
                except (OSError, PermissionError, RuntimeError, ValueError):
                    output_evidence = None
                    output_evidence_status = "unavailable"
        elif package_operation is not None and package_operation.get("kind") in {"preflight", "apply"}:
            output_evidence_status = "unavailable"
            if (
                record["returncode"] == 0
                and record["timed_out"] is False
                and record["stdout_truncated"] is False
                and record["stderr_truncated"] is False
            ):
                try:
                    output_evidence = _write_output_evidence(
                        record,
                        argv=argv,
                        stdout_bytes=stdout_bytes,
                        package_operation=package_operation,
                        package_guard_evidence=package_guard_evidence,
                        package_preflight_evidence=package_preflight_evidence,
                    )
                    output_evidence_status = "published"
                except (OSError, PermissionError, RuntimeError, ValueError):
                    output_evidence = None
                    output_evidence_status = "unavailable"
    return {
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "record": record,
        "timed_out": timed_out,
        "returncode": None if timed_out else process.returncode,
        "output_evidence": output_evidence,
        "output_evidence_status": output_evidence_status,
        "readback_retry_safe": readback_retry_safe,
        "package_apply_consumption": package_consumption,
    }

def main() -> int:
    if os.geteuid() != 0:
        raise PermissionError("privileged broker must run as root")
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    reference = parse_reference(data)
    config = load_root_config(CONFIG)
    execution = resolve_execution(config, reference)
    operator_peer: dict[str, object] | None = None
    if (
        reference.get("action") in {
            POWER_ACTION,
            BLOCKADE_LIFECYCLE_ACTION,
            ROOTBROKER_CUTOVER_ACTION,
        }
        or execution.get("allowed_peer_uid") is not None
        or execution.get("allowed_peer_unit") is not None
    ):
        operator_peer = _validate_blockade_lifecycle_peer(execution)
    if execution.get("mode") == "recovery-marker-publish":
        return _run_recovery_publication(reference, execution)
    if execution.get("mode") == "blockade-marker-lifecycle":
        assert operator_peer is not None
        return _run_blockade_lifecycle(
            reference, execution, peer=operator_peer
        )
    argv = execution["argv"]
    timeout = execution["timeout_seconds"]
    cwd = execution.get("cwd")
    if cwd is not None and not Path(str(cwd)).is_dir():
        raise ValueError("privileged cwd is not an existing directory")
    claim_once(STATE / "used", str(reference["request_id"]))
    if reference.get("action") == POWER_ACTION:
        refreshed_execution = resolve_execution(config, reference)
        stable_fields = (
            "mode", "argv", "cwd", "timeout_seconds",
            "allowed_peer_uid", "allowed_peer_unit",
        )
        if any(refreshed_execution.get(key) != execution.get(key) for key in stable_fields):
            raise PermissionError("power execution contract changed before spawn")
        execution = refreshed_execution
        operator_peer = _validate_blockade_lifecycle_peer(execution)
        argv = execution["argv"]
        timeout = execution["timeout_seconds"]
        cwd = execution.get("cwd")
        if cwd is not None and not Path(str(cwd)).is_dir():
            raise ValueError("privileged cwd changed before final gate")
        final_execution = resolve_execution(config, reference)
        if any(final_execution.get(key) != execution.get(key) for key in stable_fields):
            raise PermissionError("power execution contract changed at final gate")
        execution = final_execution
        argv = execution["argv"]
        timeout = execution["timeout_seconds"]
        cwd = execution.get("cwd")
    command_result = _execute_broker_command(
        reference=reference, execution=execution, operator_peer=operator_peer
    )
    stdout = str(command_result["stdout"])
    stderr = str(command_result["stderr"])
    record = command_result["record"]
    assert isinstance(record, dict)
    timed_out = command_result["timed_out"] is True
    output_evidence = command_result["output_evidence"]
    output_evidence_status = str(command_result["output_evidence_status"])
    readback_retry_safe = command_result["readback_retry_safe"] is True
    returncode = command_result["returncode"]
    print(json.dumps({
        "request_id": reference["request_id"],
        "action": reference["action"],
        "mode": execution.get("mode", "template"),
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "audit": _public_audit_record(record),
        "output_evidence": output_evidence,
        "output_evidence_status": output_evidence_status,
        "readback_retry_safe": readback_retry_safe,
    }, ensure_ascii=False, sort_keys=True))
    # The socket client returns non-zero for non-zero action returncodes. The
    # broker process itself exits successfully after a structured response so a
    # handled request failure does not leave a failed transient systemd unit.
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileExistsError, FileNotFoundError, PermissionError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(0)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
