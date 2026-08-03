from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Iterator


SCHEMA_VERSION = 1
STATE_KIND = "grabowski_transport_roundtrip_state"
CHALLENGE_KIND = "grabowski_transport_roundtrip_challenge"
VERIFICATION_KIND = "grabowski_transport_roundtrip_verification"
CONSUMPTION_KIND = "grabowski_transport_roundtrip_consumption"
CHALLENGE_TTL_SECONDS = 300
VERIFICATION_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30
MAX_STATE_BYTES = 32 * 1024
STATE_ROOT = Path.home() / ".local/state/grabowski/transport-roundtrip"
LOCK_PATH = STATE_ROOT / ".lock"
SHARED_UNLABELED_SCOPE = "shared-unlabeled-transport-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
_RUNTIME_BINDING_KEYS = frozenset(
    {
        "release_id",
        "repo_head",
        "registered_names_sha256",
        "agent_instructions_sha256",
    }
)
_CLIENT_SCOPE_KEYS = frozenset({"kind", "label"})
_CLIENT_SCOPE_KINDS = frozenset({"client_declared_meta", "shared_unlabeled"})
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "client_scope_sha256",
        "client_scope_kind",
        "pending_challenge",
        "verified_receipt",
        "last_consumption_receipt",
    }
)


class TransportRoundtripError(RuntimeError):
    """Raised when transport-roundtrip state cannot be trusted."""


class TransportRoundtripRequired(TransportRoundtripError):
    """Raised when a mutating call lacks a fresh roundtrip verification."""


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
        raise TransportRoundtripError(
            "transport value is not canonical JSON"
        ) from exc


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def canonical_arguments_sha256(arguments: Any) -> str:
    if not isinstance(arguments, dict):
        raise TransportRoundtripError("mutating tool arguments must be an object")
    return _sha256_json(arguments)


def _validate_sha256(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise TransportRoundtripError(f"{label} must be a lowercase SHA-256")
    return value


def _validate_text(value: Any, *, label: str, maximum_bytes: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or "\x00" in value
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise TransportRoundtripError(f"{label} is invalid")
    return value


def validate_client_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _CLIENT_SCOPE_KEYS:
        raise TransportRoundtripError("transport client scope is incomplete")
    kind = value.get("kind")
    label = _validate_text(value.get("label"), label="transport client scope label")
    if kind not in _CLIENT_SCOPE_KINDS:
        raise TransportRoundtripError("transport client scope kind is invalid")
    if kind == "shared_unlabeled" and label != SHARED_UNLABELED_SCOPE:
        raise TransportRoundtripError("shared transport client scope is invalid")
    return {"kind": str(kind), "label": label}


def client_scope_sha256(value: Any) -> str:
    return _sha256_json(validate_client_scope(value))


def validate_runtime_binding(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _RUNTIME_BINDING_KEYS:
        raise TransportRoundtripError("transport runtime binding is incomplete")
    release_id = _validate_text(
        value.get("release_id"), label="transport runtime release id"
    )
    repo_head = value.get("repo_head")
    if not isinstance(repo_head, str) or _HEAD_RE.fullmatch(repo_head) is None:
        raise TransportRoundtripError("transport repository head is invalid")
    return {
        "release_id": release_id,
        "repo_head": repo_head,
        "registered_names_sha256": _validate_sha256(
            value.get("registered_names_sha256"),
            label="transport registered tool names hash",
        ),
        "agent_instructions_sha256": _validate_sha256(
            value.get("agent_instructions_sha256"),
            label="transport agent instructions hash",
        ),
    }


def _timestamp(now_unix: int | None) -> int:
    value = int(time.time()) if now_unix is None else now_unix
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TransportRoundtripError("transport roundtrip timestamp is invalid")
    return value


def _validate_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise TransportRoundtripError(
            "transport roundtrip state directory is unsafe"
        )


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _validate_private_directory(path)


def _validate_private_file(metadata: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise TransportRoundtripError(f"{label} is not a private regular file")


@contextmanager
def _state_lock() -> Iterator[None]:
    _ensure_private_directory(STATE_ROOT)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(LOCK_PATH, flags, 0o600)
    try:
        _validate_private_file(
            os.fstat(descriptor), label="transport roundtrip lock"
        )
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _state_path(scope_sha256: str) -> Path:
    digest = _validate_sha256(scope_sha256, label="client scope hash")
    return STATE_ROOT / f"{digest}.json"


def _read_private_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        _validate_private_file(before, label="transport roundtrip state")
        if before.st_size > MAX_STATE_BYTES:
            raise TransportRoundtripError(
                "transport roundtrip state exceeds size limit"
            )
        chunks: list[bytes] = []
        remaining = MAX_STATE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise TransportRoundtripError(
                "transport roundtrip state changed while reading"
            )
    finally:
        os.close(descriptor)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportRoundtripError(
            "transport roundtrip state is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise TransportRoundtripError(
            "transport roundtrip state must be an object"
        )
    return value


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_STATE_BYTES:
        raise TransportRoundtripError(
            "transport roundtrip state exceeds size limit"
        )
    if path.exists() or path.is_symlink():
        _validate_private_file(
            path.lstat(), label="existing transport roundtrip state"
        )
    temporary = path.parent / (
        f".{path.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        _validate_private_file(
            temporary.lstat(), label="temporary transport roundtrip state"
        )
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _validate_private_file(
            path.lstat(), label="published transport roundtrip state"
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _receipt_sha256(receipt: dict[str, Any]) -> str:
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    return _sha256_json(unsigned)


def _receipt_base(
    *,
    kind: str,
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    created_at_unix: int,
    expires_at_unix: int,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "client_scope_kind": scope["kind"],
        "client_scope_sha256": _sha256_json(scope),
        "created_at_unix": created_at_unix,
        "expires_at_unix": expires_at_unix,
        "runtime_binding": runtime_binding,
    }


def _validate_receipt(
    receipt: Any,
    *,
    expected_kind: str,
    scope: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise TransportRoundtripError(
            "transport roundtrip receipt must be an object"
        )
    scope_hash = _sha256_json(scope)
    if (
        receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("kind") != expected_kind
        or receipt.get("client_scope_kind") != scope["kind"]
        or receipt.get("client_scope_sha256") != scope_hash
    ):
        raise TransportRoundtripError(
            "transport roundtrip receipt contract mismatch"
        )
    declared = _validate_sha256(
        receipt.get("receipt_sha256"), label="transport receipt hash"
    )
    if _receipt_sha256(receipt) != declared:
        raise TransportRoundtripError(
            "transport roundtrip receipt hash mismatch"
        )
    validate_runtime_binding(receipt.get("runtime_binding"))
    created = receipt.get("created_at_unix")
    expires = receipt.get("expires_at_unix")
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or created < 0
        or isinstance(expires, bool)
        or not isinstance(expires, int)
        or expires < created
    ):
        raise TransportRoundtripError(
            "transport roundtrip receipt timestamp contract mismatch"
        )
    return receipt


def _empty_state(scope: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": STATE_KIND,
        "client_scope_sha256": _sha256_json(scope),
        "client_scope_kind": scope["kind"],
        "pending_challenge": None,
        "verified_receipt": None,
        "last_consumption_receipt": None,
    }


def _validate_state(state: Any, *, scope: dict[str, str]) -> dict[str, Any]:
    scope_hash = _sha256_json(scope)
    if (
        not isinstance(state, dict)
        or set(state) != _STATE_KEYS
        or state.get("schema_version") != SCHEMA_VERSION
        or state.get("kind") != STATE_KIND
        or state.get("client_scope_sha256") != scope_hash
        or state.get("client_scope_kind") != scope["kind"]
    ):
        raise TransportRoundtripError(
            "transport roundtrip state contract mismatch"
        )
    pending = state.get("pending_challenge")
    verified = state.get("verified_receipt")
    consumption = state.get("last_consumption_receipt")
    if pending is not None:
        _validate_receipt(pending, expected_kind=CHALLENGE_KIND, scope=scope)
        _validate_sha256(
            pending.get("challenge_nonce_sha256"),
            label="transport challenge nonce hash",
        )
    if verified is not None:
        _validate_receipt(
            verified, expected_kind=VERIFICATION_KIND, scope=scope
        )
        _validate_sha256(
            verified.get("challenge_receipt_sha256"),
            label="transport challenge receipt hash",
        )
    if consumption is not None:
        _validate_receipt(
            consumption, expected_kind=CONSUMPTION_KIND, scope=scope
        )
        _validate_sha256(
            consumption.get("verification_receipt_sha256"),
            label="transport verification receipt hash",
        )
        _validate_sha256(
            consumption.get("arguments_sha256"),
            label="transport mutation arguments hash",
        )
        _validate_text(
            consumption.get("tool_name"),
            label="transport mutation tool name",
            maximum_bytes=256,
        )
    return state


def _load_state(scope: dict[str, str]) -> dict[str, Any]:
    path = _state_path(_sha256_json(scope))
    try:
        state = _read_private_json(path)
    except FileNotFoundError:
        return _empty_state(scope)
    return _validate_state(state, scope=scope)


def _receipt_is_current(
    receipt: dict[str, Any] | None,
    *,
    runtime_binding: dict[str, str],
    now_unix: int,
) -> bool:
    return bool(
        isinstance(receipt, dict)
        and receipt.get("runtime_binding") == runtime_binding
        and receipt.get("created_at_unix", now_unix + 1)
        <= now_unix + CLOCK_SKEW_SECONDS
        and now_unix <= receipt.get("expires_at_unix", -1)
    )


def _projection(
    *,
    state: dict[str, Any],
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    now_unix: int,
    action: str,
    replayed: bool,
) -> dict[str, Any]:
    pending = state.get("pending_challenge")
    verified = state.get("verified_receipt")
    consumption = state.get("last_consumption_receipt")
    pending_current = _receipt_is_current(
        pending, runtime_binding=runtime_binding, now_unix=now_unix
    )
    verified_current = _receipt_is_current(
        verified, runtime_binding=runtime_binding, now_unix=now_unix
    )
    if verified_current:
        state_name = "verified"
        next_action = "invoke exactly one mutating tool"
    elif pending_current:
        state_name = "challenge_pending"
        next_action = (
            "call grip_run for transport-roundtrip with action=ack and the "
            "exact challenge_receipt_sha256"
        )
    elif verified is not None:
        state_name = (
            "binding_mismatch"
            if verified.get("runtime_binding") != runtime_binding
            else "stale"
        )
        next_action = "start a new transport handshake"
    elif consumption is not None:
        state_name = "consumed"
        next_action = "start a new transport handshake before another mutation"
    else:
        state_name = "missing"
        next_action = "start a new transport handshake"
    return {
        "schema_version": SCHEMA_VERSION,
        "state": state_name,
        "action": action,
        "replayed": replayed,
        "mutation_gate_open": verified_current,
        "single_use": True,
        "client_scope_kind": scope["kind"],
        "client_scope_sha256": _sha256_json(scope),
        "challenge_receipt_sha256": (
            pending.get("receipt_sha256") if pending_current else None
        ),
        "challenge_created_at_unix": (
            pending.get("created_at_unix") if pending_current else None
        ),
        "challenge_expires_at_unix": (
            pending.get("expires_at_unix") if pending_current else None
        ),
        "verification_receipt_sha256": (
            verified.get("receipt_sha256") if verified_current else None
        ),
        "verified_at_unix": (
            verified.get("created_at_unix") if verified_current else None
        ),
        "verification_expires_at_unix": (
            verified.get("expires_at_unix") if verified_current else None
        ),
        "last_consumption_receipt_sha256": (
            consumption.get("receipt_sha256")
            if isinstance(consumption, dict)
            else None
        ),
        "last_consumed_tool_name": (
            consumption.get("tool_name")
            if isinstance(consumption, dict)
            else None
        ),
        "runtime_binding_sha256": _sha256_json(runtime_binding),
        "recommended_next_action": next_action,
        "does_not_establish": [
            "authenticated client identity",
            "application-level success of a mutating tool",
            "absence of response loss after a mutation",
            "client instruction compliance",
            "resistance to compromised same-uid code",
        ],
    }


def begin(
    *,
    client_scope: dict[str, Any],
    runtime_binding: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope = validate_client_scope(client_scope)
    binding = validate_runtime_binding(runtime_binding)
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _load_state(scope)
        verified = state.get("verified_receipt")
        if _receipt_is_current(
            verified, runtime_binding=binding, now_unix=timestamp
        ):
            return _projection(
                state=state,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="begin",
                replayed=True,
            )
        pending = state.get("pending_challenge")
        if _receipt_is_current(
            pending, runtime_binding=binding, now_unix=timestamp
        ):
            return _projection(
                state=state,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="begin",
                replayed=True,
            )
        previous_verified = state.get("verified_receipt")
        challenge = _receipt_base(
            kind=CHALLENGE_KIND,
            scope=scope,
            runtime_binding=binding,
            created_at_unix=timestamp,
            expires_at_unix=timestamp + CHALLENGE_TTL_SECONDS,
        )
        challenge.update(
            {
                "challenge_nonce_sha256": hashlib.sha256(
                    secrets.token_bytes(32)
                ).hexdigest(),
                "previous_verification_receipt_sha256": (
                    previous_verified.get("receipt_sha256")
                    if isinstance(previous_verified, dict)
                    else None
                ),
            }
        )
        challenge["receipt_sha256"] = _receipt_sha256(challenge)
        state = {**state, "pending_challenge": challenge}
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return _projection(
            state=state,
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
            action="begin",
            replayed=False,
        )


def acknowledge(
    *,
    client_scope: dict[str, Any],
    challenge_receipt_sha256: str,
    runtime_binding: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope = validate_client_scope(client_scope)
    challenge_hash = _validate_sha256(
        challenge_receipt_sha256, label="challenge_receipt_sha256"
    )
    binding = validate_runtime_binding(runtime_binding)
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _load_state(scope)
        verified = state.get("verified_receipt")
        if (
            isinstance(verified, dict)
            and verified.get("challenge_receipt_sha256") == challenge_hash
            and _receipt_is_current(
                verified, runtime_binding=binding, now_unix=timestamp
            )
        ):
            return _projection(
                state=state,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="ack",
                replayed=True,
            )
        pending = state.get("pending_challenge")
        if not isinstance(pending, dict):
            raise TransportRoundtripError(
                "transport challenge is missing; begin a new handshake"
            )
        if pending.get("receipt_sha256") != challenge_hash:
            raise TransportRoundtripError(
                "transport challenge receipt does not match the pending challenge"
            )
        if pending.get("runtime_binding") != binding:
            raise TransportRoundtripError(
                "transport challenge is bound to a different runtime"
            )
        if not _receipt_is_current(
            pending, runtime_binding=binding, now_unix=timestamp
        ):
            raise TransportRoundtripError(
                "transport challenge is stale; begin a new handshake"
            )
        verification = _receipt_base(
            kind=VERIFICATION_KIND,
            scope=scope,
            runtime_binding=binding,
            created_at_unix=timestamp,
            expires_at_unix=timestamp + VERIFICATION_TTL_SECONDS,
        )
        verification.update(
            {
                "challenge_receipt_sha256": challenge_hash,
                "previous_verification_receipt_sha256": (
                    verified.get("receipt_sha256")
                    if isinstance(verified, dict)
                    else None
                ),
            }
        )
        verification["receipt_sha256"] = _receipt_sha256(verification)
        state = {
            **state,
            "pending_challenge": None,
            "verified_receipt": verification,
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return _projection(
            state=state,
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
            action="ack",
            replayed=False,
        )


def status(
    *,
    client_scope: dict[str, Any],
    runtime_binding: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope = validate_client_scope(client_scope)
    binding = validate_runtime_binding(runtime_binding)
    timestamp = _timestamp(now_unix)
    try:
        try:
            _validate_private_directory(STATE_ROOT)
        except FileNotFoundError:
            state = _empty_state(scope)
        else:
            state = _load_state(scope)
    except (OSError, ValueError, TransportRoundtripError) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "state": "invalid",
            "mutation_gate_open": False,
            "single_use": True,
            "client_scope_kind": scope["kind"],
            "client_scope_sha256": _sha256_json(scope),
            "error": type(exc).__name__,
            "recommended_next_action": (
                "inspect and repair transport roundtrip state before mutation"
            ),
            "does_not_establish": [
                "authenticated client identity",
                "application-level success of any mutating tool",
                "absence of response loss after a mutation",
                "resistance to compromised same-uid code",
            ],
        }
    return _projection(
        state=state,
        scope=scope,
        runtime_binding=binding,
        now_unix=timestamp,
        action="status",
        replayed=True,
    )


def require_verified(
    *,
    client_scope: dict[str, Any],
    runtime_binding: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    result = status(
        client_scope=client_scope,
        runtime_binding=runtime_binding,
        now_unix=now_unix,
    )
    if result.get("mutation_gate_open") is not True:
        raise TransportRoundtripRequired(
            "mutating MCP calls require a fresh single-use transport verification; "
            "call grip_run for transport-roundtrip with action=begin and, when it "
            "returns challenge_pending, action=ack using the exact receipt"
        )
    return result


def consume_verified(
    *,
    client_scope: dict[str, Any],
    runtime_binding: dict[str, Any],
    tool_name: str,
    arguments_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope = validate_client_scope(client_scope)
    binding = validate_runtime_binding(runtime_binding)
    name = _validate_text(
        tool_name, label="transport mutation tool name", maximum_bytes=256
    )
    arguments_hash = _validate_sha256(
        arguments_sha256, label="transport mutation arguments hash"
    )
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _load_state(scope)
        verified = state.get("verified_receipt")
        if not _receipt_is_current(
            verified, runtime_binding=binding, now_unix=timestamp
        ):
            raise TransportRoundtripRequired(
                "mutating MCP calls require a fresh single-use transport verification"
            )
        assert isinstance(verified, dict)
        consumption = _receipt_base(
            kind=CONSUMPTION_KIND,
            scope=scope,
            runtime_binding=binding,
            created_at_unix=timestamp,
            expires_at_unix=timestamp,
        )
        consumption.update(
            {
                "verification_receipt_sha256": verified["receipt_sha256"],
                "tool_name": name,
                "arguments_sha256": arguments_hash,
            }
        )
        consumption["receipt_sha256"] = _receipt_sha256(consumption)
        state = {
            **state,
            "pending_challenge": None,
            "verified_receipt": None,
            "last_consumption_receipt": consumption,
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return {
            "schema_version": SCHEMA_VERSION,
            "state": "consumed",
            "single_use": True,
            "client_scope_kind": scope["kind"],
            "client_scope_sha256": _sha256_json(scope),
            "runtime_binding_sha256": _sha256_json(binding),
            "verification_receipt_sha256": verified["receipt_sha256"],
            "consumption_receipt_sha256": consumption["receipt_sha256"],
            "tool_name": name,
            "arguments_sha256": arguments_hash,
            "does_not_establish": [
                "authenticated client identity",
                "application-level success of the admitted mutation",
                "absence of response loss after the admitted mutation",
            ],
        }
