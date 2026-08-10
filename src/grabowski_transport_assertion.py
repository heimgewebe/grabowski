from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Iterator


SCHEMA_VERSION = 1
ASSERTION_VERSION = "signed-one-call-v1"
ASSERTION_AUDIENCE = "grabowski-mcp"
ASSERTION_MAX_AGE_SECONDS = 90
ASSERTION_CLOCK_SKEW_SECONDS = 30
REPLAY_RETENTION_SECONDS = 900
MAX_REPLAY_RECORDS = 512
MAX_STATE_BYTES = 512 * 1024
STATE_KIND = "grabowski_transport_one_call_state"
CONSUMPTION_KIND = "grabowski_transport_one_call_consumption"
STATE_ROOT = Path.home() / ".local/state/grabowski/transport-one-call"
LOCK_PATH = STATE_ROOT / ".lock"
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


def _state_path(scope_sha256: str) -> Path:
    return STATE_ROOT / f"{_sha256(scope_sha256, 'transport client scope hash')}.json"


def _empty_state(scope_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": STATE_KIND,
        "client_scope_sha256": _sha256(scope_sha256, "transport client scope hash"),
        "consumed": [],
    }


def _read_state(path: Path, scope_sha256: str) -> dict[str, Any]:
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except FileNotFoundError:
        return _empty_state(scope_sha256)
    try:
        meta = os.fstat(fd)
        _validate_private_file(meta, "transport assertion state")
        if meta.st_size > MAX_STATE_BYTES:
            raise TransportAssertionError("transport assertion state exceeds size limit")
        raw = os.read(fd, MAX_STATE_BYTES + 1)
        if len(raw) > MAX_STATE_BYTES or os.read(fd, 1):
            raise TransportAssertionError("transport assertion state exceeds size limit")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportAssertionError("transport assertion state is invalid JSON") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "kind", "client_scope_sha256", "consumed"}
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("kind") != STATE_KIND
        or value.get("client_scope_sha256") != scope_sha256
        or not isinstance(value.get("consumed"), list)
        or len(value["consumed"]) > MAX_REPLAY_RECORDS
    ):
        raise TransportAssertionError("transport assertion state contract mismatch")
    return value


def _write_state(path: Path, state: dict[str, Any]) -> None:
    raw = json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(raw) > MAX_STATE_BYTES:
        raise TransportAssertionError("transport assertion state exceeds size limit")
    if path.exists() or path.is_symlink():
        _validate_private_file(path.lstat(), "existing transport assertion state")
    tmp = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


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

    path = _state_path(scope_hash)
    with _state_lock():
        state = _read_state(path, scope_hash)
        current: list[dict[str, Any]] = []
        for item in state["consumed"]:
            if not isinstance(item, dict):
                raise TransportAssertionError("transport assertion replay record is invalid")
            expires = item.get("expires_at_unix")
            if isinstance(expires, bool) or not isinstance(expires, int):
                raise TransportAssertionError("transport assertion replay expiry is invalid")
            if expires >= now:
                current.append(item)
        matching = [item for item in current if item.get("request_id") == material["request_id"]]
        if matching:
            first = matching[0]
            exact = (
                first.get("tool_name") == material["tool_name"]
                and first.get("arguments_sha256") == material["arguments_sha256"]
                and first.get("body_sha256") == material["body_sha256"]
                and first.get("runtime_binding_sha256") == material["runtime_binding_sha256"]
            )
            if not exact:
                raise TransportAssertionError("transport request id was reused for different evidence")
            raise TransportAssertionReplay(
                "signed one-call transport request was already consumed; do not repeat the mutation; reconcile target state"
            )
        if len(current) >= MAX_REPLAY_RECORDS:
            raise TransportAssertionError("transport assertion replay store is full")
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "kind": CONSUMPTION_KIND,
            "request_id": material["request_id"],
            "client_scope_sha256": scope_hash,
            "runtime_binding_sha256": material["runtime_binding_sha256"],
            "issued_at_unix": material["issued_at_unix"],
            "consumed_at_unix": now,
            "expires_at_unix": now + REPLAY_RETENTION_SECONDS,
            "audience": material["audience"],
            "tool_name": material["tool_name"],
            "arguments_sha256": material["arguments_sha256"],
            "body_sha256": material["body_sha256"],
        }
        receipt["receipt_sha256"] = _sha256_json(receipt)
        current.append(receipt)
        _write_state(path, {**state, "consumed": current})
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
