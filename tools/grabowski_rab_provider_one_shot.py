"""Root-only, non-authorizing-by-itself primitive for RAB provider one-shots.

This module is NOT a socket listener, grant issuer, systemd launcher or model
runner. A separately reviewed root-owned broker must install a root-owned policy,
authenticate its connected socket and call authorize_once for *each* provider
intent. Until those integrations are complete both existing Codex guards must
remain fail-closed. No invocation of this module can start Codex.

An unknown outcome is consumed: never delete or retry the corresponding marker.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
from typing import Any, Mapping

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UNIT = re.compile(r"grabowski-rab-[a-z][a-z0-9-]{0,16}\.service\Z")
_ARMS = frozenset({"baseline", "treatment"})
_MAX_BYTES = 16 * 1024
_MAX_JSON_NESTING = 32
# Linux UAPI /usr/include/asm-generic/socket.h; absent support must fail closed.
_SO_PEERPIDFD = 77
_TRUSTED_POLICY_ROOT = Path("/etc/grabowski/rab-provider-one-shot")
_TRUSTED_STATE_ROOT = Path("/var/lib/grabowski/rab-provider-one-shot")


class ProviderGrantDenied(RuntimeError):
    """Fail closed before an irreversible model start."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _hex(value: Any) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _secure_directory(path: Path) -> int:
    """Open one root-owned, non-symlinked directory chain in host namespace."""
    if not path.is_absolute() or ".." in path.parts:
        raise ProviderGrantDenied("trusted directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ProviderGrantDenied("trusted directory is mutable or non-root")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _bounded_json_object(raw: bytes) -> dict[str, Any]:
    """Parse only bounded UTF-8 JSON with shallow nesting, no recursive scan.

    The byte limit alone does not protect a small-stack rootbroker thread from
    deeply nested JSON. Track braces and brackets outside strings, including
    escaped quotes. The standard JSON decoder still owns syntax validation.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_BYTES:
        raise ProviderGrantDenied("provider JSON exceeds byte budget")
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ProviderGrantDenied("provider JSON must be UTF-8") from exc
    nesting = 0
    in_string = False
    escaped = False
    for char in decoded:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            nesting += 1
            if nesting > _MAX_JSON_NESTING:
                raise ProviderGrantDenied("provider JSON nesting budget exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise ProviderGrantDenied("provider JSON nesting is unbalanced")
    if nesting or in_string:
        raise ProviderGrantDenied("provider JSON nesting is incomplete")
    try:
        value = json.loads(decoded)
    except (ValueError, RecursionError) as exc:
        raise ProviderGrantDenied("provider JSON cannot be decoded") from exc
    if not isinstance(value, dict):
        raise ProviderGrantDenied("provider JSON must be an object")
    return value


def _read_root_file(directory_fd: int, filename: str) -> dict[str, Any]:
    if filename in {"", ".", ".."} or "/" in filename:
        raise ProviderGrantDenied("unsafe trusted filename")
    fd = os.open(
        filename,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & 0o022
            or not 0 < before.st_size <= _MAX_BYTES
        ):
            raise ProviderGrantDenied(
                "trusted policy/receipt is not root-owned immutable"
            )
        raw = os.read(fd, _MAX_BYTES + 1)
        after = os.fstat(fd)
        if len(raw) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ProviderGrantDenied("trusted policy/receipt changed while reading")
        return _bounded_json_object(raw)
    finally:
        os.close(fd)


def _validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or set(policy) != {
        "schema_version",
        "epoch_sha256",
        "pair_id",
        "service_unit",
        "invocation_id",
        "main_cmdline_sha256",
        "source_manifest_sha256",
        "runtime_code_sha256",
        "codex_binary_sha256",
        "mode",
        "provider",
        "model",
        "reasoning",
        "max_exec",
        "positions",
    }:
        raise ProviderGrantDenied("trusted one-shot policy shape invalid")
    if policy["schema_version"] != 1 or type(policy["schema_version"]) is not int:
        raise ProviderGrantDenied("trusted one-shot schema invalid")
    for field in (
        "epoch_sha256",
        "main_cmdline_sha256",
        "source_manifest_sha256",
        "runtime_code_sha256",
        "codex_binary_sha256",
    ):
        if not _hex(policy[field]):
            raise ProviderGrantDenied("trusted one-shot digest invalid")
    if not isinstance(policy["service_unit"], str) or not _UNIT.fullmatch(
        policy["service_unit"]
    ):
        raise ProviderGrantDenied("trusted one-shot service unit invalid")
    if (
        not isinstance(policy["invocation_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", policy["invocation_id"]) is None
    ):
        raise ProviderGrantDenied("trusted one-shot invocation identity invalid")
    if (
        not isinstance(policy["pair_id"], str)
        or not 0 < len(policy["pair_id"].encode("utf-8")) <= 256
        or any(ord(char) < 32 for char in policy["pair_id"])
    ):
        raise ProviderGrantDenied("trusted one-shot pair identity invalid")
    if (
        policy["mode"] != "chatgpt_subscription"
        or policy["provider"] != "openai-codex-cli"
        or policy["model"] != "gpt-6-astra"
        or policy["reasoning"] != "medium"
        or type(policy["max_exec"]) is not int
        or policy["max_exec"] != 2
    ):
        raise ProviderGrantDenied("trusted one-shot provider contract invalid")
    positions = policy["positions"]
    if not isinstance(positions, list) or len(positions) != 2:
        raise ProviderGrantDenied("one-shot policy requires two positions")
    arms: set[str] = set()
    for index, pos in enumerate(positions):
        if (
            not isinstance(pos, dict)
            or set(pos) != {"arm", "index", "request_sha256", "slot_id"}
            or not isinstance(pos["arm"], str)
            or pos["arm"] not in _ARMS
            or pos["arm"] in arms
            or type(pos["index"]) is not int
            or pos["index"] != index
            or not _hex(pos["request_sha256"])
            or not _hex(pos["slot_id"])
        ):
            raise ProviderGrantDenied("one-shot position shape or ordering invalid")
        arms.add(pos["arm"])
    if (
        arms != _ARMS
        or positions[0]["slot_id"] == positions[1]["slot_id"]
        or positions[0]["request_sha256"] == positions[1]["request_sha256"]
    ):
        raise ProviderGrantDenied("one-shot positions are not unique")
    return policy


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    # Ignore all caller-supplied PID/UID claims.
    if not isinstance(connection, socket.socket):
        raise ProviderGrantDenied("one-shot request must use authenticated socket")
    if not hasattr(socket, "SO_PEERCRED"):
        raise ProviderGrantDenied("kernel peer credentials unavailable")
    raw = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    if len(raw) != struct.calcsize("3i"):
        raise ProviderGrantDenied("kernel peer credentials malformed")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 1 or uid <= 0 or gid < 0:
        raise ProviderGrantDenied("unqualified kernel peer identity")
    return pid, uid, gid


def _receive_authenticated_request(
    connection: socket.socket,
) -> tuple[dict[str, Any], tuple[int, int, int]]:
    """Receive one bounded UNIX record from the actual kernel sender.

    SO_PEERCRED alone is captured at connect/socketpair time: a process
    inheriting/passing the descriptor can send from a different PID.
    SO_PASSCRED supplies SCM_CREDENTIALS for the received packet. Require it
    to equal the connection's original peer. No caller-supplied request object
    may bypass this read. This is a SOCK_SEQPACKET protocol, not a stream.
    """
    if (
        not isinstance(connection, socket.socket)
        or connection.family != socket.AF_UNIX
        or connection.type != socket.SOCK_SEQPACKET
        or not hasattr(socket, "SO_PASSCRED")
        or not hasattr(socket, "SCM_CREDENTIALS")
    ):
        raise ProviderGrantDenied("one-shot requires UNIX SOCK_SEQPACKET credentials")
    peer = _peer_credentials(connection)
    credential_size = struct.calcsize("3i")
    if not hasattr(socket, "MSG_CMSG_CLOEXEC"):
        raise ProviderGrantDenied("close-on-exec ancillary receive is unavailable")
    previous_timeout = connection.gettimeout()
    try:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        connection.settimeout(5.0)
        raw, ancillary, flags, _source = connection.recvmsg(
            _MAX_BYTES + 1,
            socket.CMSG_SPACE(credential_size),
            socket.MSG_CMSG_CLOEXEC,
        )
    except (OSError, ValueError) as exc:
        raise ProviderGrantDenied("authenticated provider packet unavailable") from exc
    finally:
        connection.settimeout(previous_timeout)
    # recvmsg may install rights even when ancillary is truncated. Never retain
    # an untrusted passed file descriptor in the privileged broker.
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            word = struct.calcsize("i")
            for (fd,) in struct.iter_unpack("i", data[: len(data) // word * word]):
                os.close(fd)
    if (
        not raw
        or len(raw) > _MAX_BYTES
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or len(ancillary) != 1
    ):
        raise ProviderGrantDenied("provider packet missing, oversized or truncated")
    level, kind, data = ancillary[0]
    if (
        level != socket.SOL_SOCKET
        or kind != socket.SCM_CREDENTIALS
        or len(data) != credential_size
    ):
        raise ProviderGrantDenied("kernel per-message credentials missing or invalid")
    sender = struct.unpack("3i", data)
    if sender != peer:
        raise ProviderGrantDenied(
            "inherited/forwarded socket sender is not original peer"
        )
    try:
        request = _bounded_json_object(raw)
    except ProviderGrantDenied as exc:
        raise ProviderGrantDenied("authenticated provider packet is not JSON") from exc
    return request, sender


def _open_peer_pidfd(connection: socket.socket, expected_pid: int) -> int:
    """Pin the connected peer's original struct pid, not merely its PID number.

    SO_PEERCRED and SCM_CREDENTIALS expose PID numbers that can be reused.
    Linux SO_PEERPIDFD pins the socket peer's kernel identity. On hosts with
    modern per-PID pidfs inodes, that identity must equal pidfd_open(MainPID).
    Fail closed on unsupported kernels and old shared anon-inode pidfds.
    Caller owns the returned descriptor and MUST close it.
    """
    if (
        not hasattr(os, "pidfd_open")
        or expected_pid <= 1
        or os.uname().sysname != "Linux"
        or os.uname().machine != "x86_64"
    ):
        raise ProviderGrantDenied("stable kernel PID identity unavailable")
    peer_fd = -1
    current_fd = -1
    anchor_fd = -1
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, _SO_PEERPIDFD, struct.calcsize("i")
        )
        if len(raw) != struct.calcsize("i"):
            raise ProviderGrantDenied("SO_PEERPIDFD was not returned by the kernel")
        peer_fd = struct.unpack("i", raw)[0]
        if peer_fd < 0:
            raise ProviderGrantDenied("invalid kernel SO_PEERPIDFD")
        os.set_inheritable(peer_fd, False)
        current_fd = os.pidfd_open(expected_pid, 0)
        # PID 1 is distinct from any admitted request PID. If its descriptor
        # has the same inode as the target, this is an old shared anonymous
        # inode rather than a collision-resistant pidfs process identity.
        anchor_fd = os.pidfd_open(1, 0)

        def identity(fd: int) -> tuple[int, int]:
            info = os.fstat(fd)
            return info.st_dev, info.st_ino

        if identity(peer_fd) != identity(current_fd) or identity(peer_fd) == identity(
            anchor_fd
        ):
            raise ProviderGrantDenied("peer PIDFD does not match the live MainPID")
        poll = select.poll()
        poll.register(peer_fd, select.POLLIN | select.POLLERR | select.POLLHUP)
        if poll.poll(0):
            raise ProviderGrantDenied("connected peer has exited")
        accepted_fd, peer_fd = peer_fd, -1
        return accepted_fd
    except (OSError, ValueError) as exc:
        raise ProviderGrantDenied(
            "kernel SO_PEERPIDFD attestation unavailable"
        ) from exc
    finally:
        for fd in (peer_fd, current_fd, anchor_fd):
            if fd >= 0:
                os.close(fd)


def _service_observation(unit: str) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--system",
                unit,
                "--property=MainPID,ActiveState,ControlGroup,InvocationID,DynamicUser,UID",
                "--no-pager",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProviderGrantDenied("PID1 service identity unavailable") from exc
    if len(completed.stdout) > 4096:
        raise ProviderGrantDenied("PID1 response exceeds bound")
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, sep, value = line.partition("=")
        if not sep or not key or key in values:
            raise ProviderGrantDenied("PID1 service metadata malformed")
        values[key] = value
    if set(values) != {
        "MainPID",
        "ActiveState",
        "ControlGroup",
        "InvocationID",
        "DynamicUser",
        "UID",
    }:
        raise ProviderGrantDenied("PID1 service metadata incomplete")
    return values


def _attest_service(
    policy: Mapping[str, Any],
    peer_pid: int,
    peer_uid: int,
    observed: Mapping[str, str],
    cgroup: bytes,
    cmdline: bytes,
) -> None:
    unit = str(policy["service_unit"])
    expected_group = "/system.slice/" + unit
    if (
        observed.get("ActiveState") != "active"
        or observed.get("MainPID") != str(peer_pid)
        or observed.get("ControlGroup") != expected_group
        or observed.get("InvocationID") != policy["invocation_id"]
        or observed.get("DynamicUser") != "yes"
        or observed.get("UID") != str(peer_uid)
        or cgroup != ("0::" + expected_group + "\n").encode()
        or _sha(cmdline) != policy["main_cmdline_sha256"]
        or peer_uid <= 0
    ):
        raise ProviderGrantDenied("peer is not the exact trusted Systemd MainPID")


def _position(policy: Mapping[str, Any], request: Any) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != {
        "epoch_sha256",
        "pair_id",
        "arm",
        "index",
        "request_sha256",
        "slot_id",
    }:
        raise ProviderGrantDenied("one-shot request shape invalid")
    if (
        request["epoch_sha256"] != policy["epoch_sha256"]
        or request["pair_id"] != policy["pair_id"]
    ):
        raise ProviderGrantDenied("one-shot epoch or pair changed")
    index = request["index"]
    if type(index) is not int or index not in (0, 1):
        raise ProviderGrantDenied("one-shot position index invalid")
    if request != {
        "epoch_sha256": policy["epoch_sha256"],
        "pair_id": policy["pair_id"],
        **policy["positions"][index],
    }:
        raise ProviderGrantDenied("one-shot request digest or arm mismatch")
    return policy["positions"][index]


def _first_outcome_digest(
    policy: Mapping[str, Any],
    first: Mapping[str, Any],
    first_token: str,
    receipt: Any,
) -> str:
    """Canonical SHA of an independently written root-owned first-turn receipt.

    The future trusted root issuer must verify the actual provider output,
    usage and model before writing this receipt; no unprivileged caller may do
    so. Merely finding a spent intent marker NEVER releases the second arm.
    """
    if not isinstance(receipt, dict) or set(receipt) != {
        "kind",
        "schema_version",
        "epoch_sha256",
        "policy_sha256",
        "pair_id",
        "first_token_sha256",
        "arm",
        "slot_id",
        "request_sha256",
        "service_unit",
        "invocation_id",
        "provider",
        "model",
        "outcome",
        "codex_exec_process_count",
        "provider_output_sha256",
        "usage_receipt_sha256",
    }:
        raise ProviderGrantDenied("first provider outcome receipt shape invalid")
    checks = (
        receipt["kind"] == "rab.root_first_arm_outcome_receipt",
        type(receipt["schema_version"]) is int and receipt["schema_version"] == 1,
        receipt["epoch_sha256"] == policy["epoch_sha256"],
        receipt["policy_sha256"] == _digest(policy),
        receipt["pair_id"] == policy["pair_id"],
        receipt["first_token_sha256"] == first_token,
        receipt["arm"] == first["arm"],
        receipt["slot_id"] == first["slot_id"],
        receipt["request_sha256"] == first["request_sha256"],
        receipt["service_unit"] == policy["service_unit"],
        receipt["invocation_id"] == policy["invocation_id"],
        receipt["provider"] == policy["provider"],
        receipt["model"] == policy["model"],
        receipt["outcome"] == "provider_completed",
        type(receipt["codex_exec_process_count"]) is int
        and receipt["codex_exec_process_count"] == 1,
        _hex(receipt["provider_output_sha256"]),
        _hex(receipt["usage_receipt_sha256"]),
    )
    if not all(checks):
        raise ProviderGrantDenied("first provider outcome receipt identity invalid")
    return _digest(receipt)


def _consume_position(
    state_fd: int,
    policy: Mapping[str, Any],
    request: Any,
    peer: tuple[int, int, int],
) -> dict[str, Any]:
    """Consume one root-owned marker atomically; caller must attest peer first.

    This function has no public dispatch authority. It is intentionally kept
    separate to test crash/replay/concurrency without using a root broker.
    """
    pos = _position(policy, request)
    index = pos["index"]
    first = policy["positions"][0]
    first_token = _digest(
        {
            "epoch": policy["epoch_sha256"],
            "pair": policy["pair_id"],
            "position": first,
        }
    )
    if index == 1:
        # Root-issued release is separate from simply consuming the first turn.
        try:
            release = _read_root_file(state_fd, "release-" + pos["slot_id"] + ".json")
        except OSError as exc:
            raise ProviderGrantDenied(
                "second position lacks independent root release"
            ) from exc
        if (
            release
            != {
                "kind": "rab.second_position_release",
                "schema_version": 1,
                "pair_id": policy["pair_id"],
                "slot_id": pos["slot_id"],
                "first_token_sha256": first_token,
                "first_receipt_sha256": release.get("first_receipt_sha256"),
            }
            or not _hex(release.get("first_receipt_sha256"))
            or type(release.get("schema_version")) is not int
        ):
            raise ProviderGrantDenied("second position root release is not bound")
        try:
            first_record = _read_root_file(state_fd, "spent-" + first_token + ".json")
        except OSError as exc:
            raise ProviderGrantDenied("first position not previously consumed") from exc
        if any(
            (
                first_record.get("kind") != "rab.root_provider_intent_consumed",
                type(first_record.get("schema_version")) is not int,
                first_record.get("schema_version") != 1,
                set(first_record)
                != {
                    "kind",
                    "schema_version",
                    "token_sha256",
                    "policy_sha256",
                    "epoch_sha256",
                    "pair_id",
                    "arm",
                    "request_sha256",
                    "slot_id",
                    "service_unit",
                    "invocation_id",
                    "peer_pid",
                    "peer_uid",
                    "peer_gid",
                },
                type(first_record.get("peer_pid")) is not int,
                type(first_record.get("peer_uid")) is not int,
                type(first_record.get("peer_gid")) is not int,
                first_record.get("peer_pid", 0) <= 1,
                first_record.get("peer_uid", 0) <= 0,
                first_record.get("peer_gid", -1) < 0,
                first_record.get("service_unit") != policy["service_unit"],
                first_record.get("invocation_id") != policy["invocation_id"],
                first_record.get("token_sha256") != first_token,
                first_record.get("policy_sha256") != _digest(policy),
                first_record.get("epoch_sha256") != policy["epoch_sha256"],
                first_record.get("pair_id") != policy["pair_id"],
                first_record.get("arm") != first["arm"],
                first_record.get("slot_id") != first["slot_id"],
                first_record.get("request_sha256") != first["request_sha256"],
            )
        ):
            raise ProviderGrantDenied("first position root intent marker changed")
        try:
            first_receipt = _read_root_file(
                state_fd, "receipt-" + first_token + ".json"
            )
        except OSError as exc:
            raise ProviderGrantDenied(
                "first position lacks trusted root outcome receipt"
            ) from exc
        expected_receipt_digest = _first_outcome_digest(
            policy, first, first_token, first_receipt
        )
        if release["first_receipt_sha256"] != expected_receipt_digest:
            raise ProviderGrantDenied("second release does not bind first outcome")
    token = _digest(
        {
            "epoch": policy["epoch_sha256"],
            "pair": policy["pair_id"],
            "position": pos,
        }
    )
    record = {
        "kind": "rab.root_provider_intent_consumed",
        "schema_version": 1,
        "token_sha256": token,
        "policy_sha256": _digest(policy),
        "epoch_sha256": policy["epoch_sha256"],
        "pair_id": policy["pair_id"],
        "arm": pos["arm"],
        "request_sha256": pos["request_sha256"],
        "slot_id": pos["slot_id"],
        "service_unit": policy["service_unit"],
        "invocation_id": policy["invocation_id"],
        "peer_pid": peer[0],
        "peer_uid": peer[1],
        "peer_gid": peer[2],
    }
    filename = "spent-" + token + ".json"
    try:
        fd = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=state_fd,
        )
    except FileExistsError as exc:
        raise ProviderGrantDenied(
            "one-shot already consumed or outcome unknown"
        ) from exc
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        while raw:
            written = os.write(fd, raw)
            if written <= 0:
                raise ProviderGrantDenied("cannot persist one-shot intent")
            raw = raw[written:]
        os.fsync(fd)
    except BaseException:
        # Deliberately retain a partial marker; uncertain starts cannot replay.
        raise
    finally:
        os.close(fd)
    os.fsync(state_fd)
    return {"status": "consumed", "token_sha256": token, "arm": pos["arm"]}


def authorize_once(
    connection: socket.socket,
    *,
    policy_path: Path,
    state_dir: Path,
) -> dict[str, Any]:
    """Root-only socket broker seam; no authority to start or install Codex.

    The broker must install immutable code and policy, then receive one kernel
    sender-attested packet for the exact active systemd MainPID before CAS.
    This standalone primitive does NOT issue first-arm success receipts.
    """
    if os.geteuid() != 0:
        raise ProviderGrantDenied("only an independent root-owned broker may consume")
    if not isinstance(policy_path, Path) or not isinstance(state_dir, Path):
        raise ProviderGrantDenied("trusted paths must be Path values")
    if (
        policy_path.parent != _TRUSTED_POLICY_ROOT
        or state_dir != _TRUSTED_STATE_ROOT
        or re.fullmatch(r"epoch-[0-9a-f]{64}\.json", policy_path.name) is None
    ):
        raise ProviderGrantDenied("one-shot root policy or state path is not canonical")
    try:
        parent_fd = _secure_directory(policy_path.parent)
    except OSError as exc:
        raise ProviderGrantDenied("root provider policy parent unavailable") from exc
    try:
        try:
            state_fd = _secure_directory(state_dir)
        except OSError as exc:
            raise ProviderGrantDenied(
                "root provider state directory unavailable"
            ) from exc
        try:
            policy = _validate_policy(_read_root_file(parent_fd, policy_path.name))
            if policy_path.name != "epoch-" + policy["epoch_sha256"] + ".json":
                raise ProviderGrantDenied("root policy filename does not match epoch")
            request, peer = _receive_authenticated_request(connection)
            pid, uid, _gid = peer
            pidfd = _open_peer_pidfd(connection, pid)
            try:
                observed = _service_observation(policy["service_unit"])
                cgroup = Path("/proc").joinpath(str(pid), "cgroup").read_bytes()
                cmdline = Path("/proc").joinpath(str(pid), "cmdline").read_bytes()
                if len(cgroup) > 4096 or len(cmdline) > 16384:
                    raise ProviderGrantDenied("kernel process projection exceeds bound")
                _attest_service(policy, pid, uid, observed, cgroup, cmdline)
                watcher = select.poll()
                watcher.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if watcher.poll(0):
                    raise ProviderGrantDenied(
                        "trusted MainPID exited before consumption"
                    )
                return _consume_position(state_fd, policy, request, peer)
            finally:
                os.close(pidfd)
        finally:
            os.close(state_fd)
    except OSError as exc:
        raise ProviderGrantDenied(
            "root one-shot filesystem or process unavailable"
        ) from exc
    finally:
        os.close(parent_fd)
