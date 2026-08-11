from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Iterator


SCHEMA_VERSION = 1
ASSERTION_VERSION = "signed-one-call-v1"
ASSERTION_AUDIENCE = "grabowski-mcp"
ASSERTION_MAX_AGE_SECONDS = 90
ASSERTION_CLOCK_SKEW_SECONDS = 30
# Kept as a public compatibility constant for tests/documentation that refer to
# the original short replay window. The durable replay filter never expires.
REPLAY_RETENTION_SECONDS = 900
CONSUMPTION_KIND = "grabowski_transport_one_call_consumption"
STATE_ROOT = Path.home() / ".local/state/grabowski/transport-one-call"
LOCK_PATH = STATE_ROOT / ".lock"
REPLAY_FILTER_FILENAME = "replay-filter-v1.bin"
REPLAY_FILTER_BITS = 1 << 29  # 64 MiB of monotone replay bits.
REPLAY_FILTER_HASH_COUNT = 7
REPLAY_FILTER_HEADER_BYTES = 128
REPLAY_FILTER_BYTES = REPLAY_FILTER_BITS // 8
REPLAY_FILTER_TOTAL_BYTES = REPLAY_FILTER_HEADER_BYTES + REPLAY_FILTER_BYTES
REPLAY_FILTER_HEADER = (
    b"grabowski-transport-replay-filter-v1\n"
    + f"bits={REPLAY_FILTER_BITS}\nhashes={REPLAY_FILTER_HASH_COUNT}\n".encode("ascii")
).ljust(REPLAY_FILTER_HEADER_BYTES, b"\x00")
LEGACY_TOMBSTONE_MAX_BYTES = 4096
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class TransportAssertionError(RuntimeError):
    """Raised when one-call transport evidence cannot be trusted."""


class TransportAssertionReplay(TransportAssertionError):
    """Raised when an already consumed signed request is presented again."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TransportAssertionError("transport assertion value is not canonical JSON") from exc


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _text(value: Any, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum
    ):
        raise TransportAssertionError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TransportAssertionError(f"{label} must be a lowercase SHA-256")
    return value


def _request_id(value: Any) -> str:
    if not isinstance(value, str) or _REQUEST_ID_RE.fullmatch(value) is None:
        raise TransportAssertionError("transport request id must be 32 lowercase hexadecimal characters")
    return value


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str) or not 16 <= len(secret.encode("ascii", errors="ignore")) <= 256:
        raise TransportAssertionError("transport connector secret is invalid")
    try:
        encoded = secret.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TransportAssertionError("transport connector secret must be ASCII") from exc
    if b"\x00" in encoded or secret != secret.strip():
        raise TransportAssertionError("transport connector secret is invalid")
    return encoded


def canonical_arguments_sha256(arguments: Any) -> str:
    if not isinstance(arguments, dict):
        raise TransportAssertionError("mutating tool arguments must be an object")
    return _sha256_json(arguments)


def runtime_binding_sha256(binding: Any) -> str:
    if not isinstance(binding, dict):
        raise TransportAssertionError("runtime binding must be an object")
    return _sha256_json(binding)


def derive_request_id(
    *,
    secret: str,
    session_id: str,
    rpc_request_id: str,
    body_sha256: str,
) -> str:
    key = _secret_bytes(secret)
    session = session_id if isinstance(session_id, str) else ""
    rpc_id = _text(rpc_request_id, "JSON-RPC request id", 512)
    body = _sha256(body_sha256, "transport request body hash")
    material = b"\x00".join(
        (
            b"grabowski-one-call-request-id-v1",
            session.encode("utf-8", errors="strict"),
            rpc_id.encode("utf-8"),
            body.encode("ascii"),
        )
    )
    return hmac.new(key, material, hashlib.sha256).hexdigest()[:32]


def assertion_material(
    *,
    request_id: str,
    issued_at_unix: int,
    audience: str,
    tool_name: str,
    arguments_sha256: str,
    body_sha256: str,
    runtime_binding_sha256: str,
) -> dict[str, Any]:
    rid = _request_id(request_id)
    if isinstance(issued_at_unix, bool) or not isinstance(issued_at_unix, int) or issued_at_unix < 0:
        raise TransportAssertionError("transport assertion timestamp is invalid")
    return {
        "version": ASSERTION_VERSION,
        "request_id": rid,
        "issued_at_unix": issued_at_unix,
        "audience": _text(audience, "transport assertion audience", 128),
        "tool_name": _text(tool_name, "transport assertion tool name", 256),
        "arguments_sha256": _sha256(arguments_sha256, "transport assertion arguments hash"),
        "body_sha256": _sha256(body_sha256, "transport assertion body hash"),
        "runtime_binding_sha256": _sha256(
            runtime_binding_sha256, "transport assertion runtime binding hash"
        ),
    }


def assertion_mac(
    *,
    secret: str,
    request_id: str,
    issued_at_unix: int,
    audience: str,
    tool_name: str,
    arguments_sha256: str,
    body_sha256: str,
    runtime_binding_sha256: str,
) -> str:
    material = assertion_material(
        request_id=request_id,
        issued_at_unix=issued_at_unix,
        audience=audience,
        tool_name=tool_name,
        arguments_sha256=arguments_sha256,
        body_sha256=body_sha256,
        runtime_binding_sha256=runtime_binding_sha256,
    )
    return hmac.new(_secret_bytes(secret), _canonical_bytes(material), hashlib.sha256).hexdigest()


def _validate_private_directory(path: Path) -> None:
    meta = path.lstat()
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != os.getuid()
        or stat.S_IMODE(meta.st_mode) & 0o077
    ):
        raise TransportAssertionError("transport assertion state directory is unsafe")


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_private_directory(path)


def _validate_private_file(meta: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(meta.st_mode)
        or meta.st_uid != os.getuid()
        or stat.S_IMODE(meta.st_mode) != 0o600
        or meta.st_nlink != 1
    ):
        raise TransportAssertionError(f"{label} is not a private regular file")


@contextmanager
def _state_lock() -> Iterator[None]:
    _ensure_private_directory(STATE_ROOT)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOCK_PATH, flags, 0o600)
    try:
        _validate_private_file(os.fstat(fd), "transport assertion lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _tombstone_path(scope_sha256: str, request_id: str) -> Path:
    scope = _sha256(scope_sha256, "transport client scope hash")
    request = _request_id(request_id)
    return STATE_ROOT / scope / f"{request}.json"


def _read_tombstone(path: Path) -> dict[str, Any] | None:
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        meta = os.fstat(fd)
        _validate_private_file(meta, "transport assertion replay tombstone")
        if meta.st_size > LEGACY_TOMBSTONE_MAX_BYTES:
            raise TransportAssertionError("transport assertion replay tombstone exceeds size limit")
        raw = os.read(fd, LEGACY_TOMBSTONE_MAX_BYTES + 1)
        if len(raw) > LEGACY_TOMBSTONE_MAX_BYTES or os.read(fd, 1):
            raise TransportAssertionError("transport assertion replay tombstone exceeds size limit")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportAssertionError("transport assertion replay tombstone is invalid JSON") from exc
    if not isinstance(value, dict):
        raise TransportAssertionError("transport assertion replay tombstone contract mismatch")
    return value


def _replay_filter_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_FILENAME


def _replay_scope_sha256(secret: str) -> str:
    return hashlib.sha256(
        b"grabowski-one-call-replay-scope-v1\x00" + _secret_bytes(secret)
    ).hexdigest()


def _replay_filter_positions(scope_sha256: str, request_id: str) -> tuple[int, ...]:
    if REPLAY_FILTER_BITS <= 0 or REPLAY_FILTER_BITS & (REPLAY_FILTER_BITS - 1):
        raise TransportAssertionError("transport replay filter size must be a power of two")
    scope = bytes.fromhex(_sha256(scope_sha256, "transport client scope hash"))
    request = bytes.fromhex(_request_id(request_id))
    digest = hashlib.sha512(b"grabowski-replay-filter-v1\x00" + scope + request).digest()
    start = int.from_bytes(digest[:8], "big")
    step = int.from_bytes(digest[8:16], "big") | 1
    mask = REPLAY_FILTER_BITS - 1
    return tuple((start + index * step) & mask for index in range(REPLAY_FILTER_HASH_COUNT))


def _open_replay_filter() -> int:
    path = _replay_filter_path()
    base_flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(path, base_flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(path, base_flags)
    try:
        meta = os.fstat(fd)
        _validate_private_file(meta, "transport assertion replay filter")
        if created:
            os.ftruncate(fd, REPLAY_FILTER_TOTAL_BYTES)
            if os.pwrite(fd, REPLAY_FILTER_HEADER, 0) != len(REPLAY_FILTER_HEADER):
                raise TransportAssertionError("transport assertion replay filter header write was short")
            os.fsync(fd)
            directory_fd = os.open(STATE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        else:
            if meta.st_size != REPLAY_FILTER_TOTAL_BYTES:
                raise TransportAssertionError("transport assertion replay filter size mismatch")
            header = os.pread(fd, REPLAY_FILTER_HEADER_BYTES, 0)
            if header != REPLAY_FILTER_HEADER:
                raise TransportAssertionError("transport assertion replay filter header mismatch")
        return fd
    except BaseException:
        os.close(fd)
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise


def _consume_replay_filter(scope_sha256: str, request_id: str) -> None:
    masks: dict[int, int] = {}
    for bit in _replay_filter_positions(scope_sha256, request_id):
        byte_offset = REPLAY_FILTER_HEADER_BYTES + bit // 8
        masks[byte_offset] = masks.get(byte_offset, 0) | (1 << (bit % 8))

    fd = _open_replay_filter()
    try:
        observed: dict[int, int] = {}
        already_consumed = True
        for byte_offset, mask in masks.items():
            raw = os.pread(fd, 1, byte_offset)
            if len(raw) != 1:
                raise TransportAssertionError("transport assertion replay filter read was short")
            value = raw[0]
            observed[byte_offset] = value
            if value & mask != mask:
                already_consumed = False
        if already_consumed:
            raise TransportAssertionReplay(
                "signed one-call transport request was already consumed or conservatively rejected by the durable replay filter; do not repeat the mutation; reconcile target state"
            )

        for byte_offset, mask in masks.items():
            value = observed[byte_offset] | mask
            if value == observed[byte_offset]:
                continue
            if os.pwrite(fd, bytes((value,)), byte_offset) != 1:
                raise TransportAssertionError("transport assertion replay filter write was short")
        # The mutation gate is allowed to continue only after every replay bit is
        # durable. A crash before this fsync cannot be followed by target execution.
        os.fsync(fd)
    finally:
        os.close(fd)


def consume_assertion(
    *,
    secret: str,
    client_scope_sha256: str,
    runtime_binding_sha256: str,
    asserted_runtime_binding_sha256: str,
    request_id: str,
    issued_at_unix: int,
    audience: str,
    tool_name: str,
    arguments_sha256: str,
    body_sha256: str,
    mac_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope_hash = _sha256(client_scope_sha256, "transport client scope hash")
    replay_scope_hash = _replay_scope_sha256(secret)
    runtime_hash = _sha256(runtime_binding_sha256, "transport runtime binding hash")
    asserted_runtime_hash = _sha256(
        asserted_runtime_binding_sha256, "asserted transport runtime binding hash"
    )
    material = assertion_material(
        request_id=request_id,
        issued_at_unix=issued_at_unix,
        audience=audience,
        tool_name=tool_name,
        arguments_sha256=arguments_sha256,
        body_sha256=body_sha256,
        runtime_binding_sha256=asserted_runtime_hash,
    )
    if material["audience"] != ASSERTION_AUDIENCE:
        raise TransportAssertionError("transport assertion audience mismatch")
    now = int(time.time()) if now_unix is None else now_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise TransportAssertionError("transport assertion observation timestamp is invalid")
    if issued_at_unix > now + ASSERTION_CLOCK_SKEW_SECONDS:
        raise TransportAssertionError("transport assertion timestamp is from the future")
    if now - issued_at_unix > ASSERTION_MAX_AGE_SECONDS:
        raise TransportAssertionError("transport assertion is stale")
    supplied_mac = _sha256(mac_sha256, "transport assertion MAC")
    expected_mac = hmac.new(_secret_bytes(secret), _canonical_bytes(material), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise TransportAssertionError("transport assertion MAC mismatch")
    if not hmac.compare_digest(asserted_runtime_hash, runtime_hash):
        raise TransportAssertionError("transport assertion runtime binding mismatch")

    legacy_path = _tombstone_path(scope_hash, material["request_id"])
    with _state_lock():
        existing = _read_tombstone(legacy_path)
        if existing is not None:
            exact = (
                existing.get("request_id") == material["request_id"]
                and existing.get("client_scope_sha256") == scope_hash
                and existing.get("tool_name") == material["tool_name"]
                and existing.get("arguments_sha256") == material["arguments_sha256"]
                and existing.get("body_sha256") == material["body_sha256"]
                and existing.get("runtime_binding_sha256") == material["runtime_binding_sha256"]
            )
            if not exact:
                raise TransportAssertionError("transport request id was reused for different evidence")
            raise TransportAssertionReplay(
                "signed one-call transport request was already consumed; do not repeat the mutation; reconcile target state"
            )
        _consume_replay_filter(replay_scope_hash, material["request_id"])

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": CONSUMPTION_KIND,
        "request_id": material["request_id"],
        "client_scope_sha256": scope_hash,
        "runtime_binding_sha256": material["runtime_binding_sha256"],
        "issued_at_unix": material["issued_at_unix"],
        "consumed_at_unix": now,
        "audience": material["audience"],
        "tool_name": material["tool_name"],
        "arguments_sha256": material["arguments_sha256"],
        "body_sha256": material["body_sha256"],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return {
        "schema_version": SCHEMA_VERSION,
        "state": "consumed",
        "single_use": True,
        "transport_mode": ASSERTION_VERSION,
        "client_scope_sha256": scope_hash,
        "runtime_binding_sha256": material["runtime_binding_sha256"],
        "request_id": material["request_id"],
        "tool_name": material["tool_name"],
        "arguments_sha256": material["arguments_sha256"],
        "consumption_receipt_sha256": receipt["receipt_sha256"],
        "does_not_establish": [
            "application-level success of the admitted mutation",
            "safe replay after response loss",
            "human identity behind the authenticated connector",
        ],
    }
