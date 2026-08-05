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
STATE_SCHEMA_VERSION = 4
STATE_KIND = "grabowski_transport_roundtrip_state"
CHALLENGE_KIND = "grabowski_transport_roundtrip_challenge"
VERIFICATION_KIND = "grabowski_transport_roundtrip_verification"
CONSUMPTION_KIND = "grabowski_transport_roundtrip_consumption"
CHALLENGE_TTL_SECONDS = 300
VERIFICATION_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30
MAX_STATE_BYTES = 128 * 1024
# Pool is private to one connector session (name kept for test/patch compatibility).
MAX_SHARED_PENDING_CHALLENGES = 32
MAX_SHARED_VERIFIED_RECEIPTS = 32
MAX_SESSION_PENDING_CHALLENGES = MAX_SHARED_PENDING_CHALLENGES
MAX_SESSION_VERIFIED_RECEIPTS = MAX_SHARED_VERIFIED_RECEIPTS
STATE_ROOT = Path.home() / ".local/state/grabowski/transport-roundtrip"
LOCK_PATH = STATE_ROOT / ".lock"
# Legacy labels retained only so migration can recognize and reject them.
SHARED_UNLABELED_SCOPE = "shared-unlabeled-transport-v1"
CONNECTOR_SESSION_SCOPE_KIND = "connector_session"
MCP_SESSION_ID_HEADER = "mcp-session-id"
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
_CLIENT_SCOPE_KINDS = frozenset({CONNECTOR_SESSION_SCOPE_KIND})
_LEGACY_SCOPE_KINDS = frozenset(
    {"client_declared_meta", "shared_unlabeled", "caller_session"}
)
_MUTATION_INTENT_KEYS = frozenset({"tool_name", "arguments_sha256"})
_LEGACY_STATE_KEYS = frozenset(
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
_STATE_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "client_scope_sha256",
        "client_scope_kind",
        "pending_challenges",
        "verified_receipts",
        "last_consumption_receipt",
    }
)
_LEGACY_STATE_SCHEMA_VERSIONS = frozenset({1, 2, 3})


class TransportRoundtripError(RuntimeError):
    """Raised when transport-roundtrip state cannot be trusted."""


class TransportRoundtripRequired(TransportRoundtripError):
    """Raised when a mutating call lacks a fresh roundtrip verification."""


class TransportMutationIntentMismatch(TransportRoundtripRequired):
    """Raised when only verifications for other mutation intents are available."""


class TransportMutationIntentRequired(TransportRoundtripError):
    """Raised when a handshake is attempted without an exact target intent."""


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


def validate_mutation_intent(value: Any) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _MUTATION_INTENT_KEYS:
        raise TransportRoundtripError("transport mutation intent is incomplete")
    return {
        "tool_name": _validate_text(
            value.get("tool_name"),
            label="transport mutation tool name",
            maximum_bytes=256,
        ),
        "arguments_sha256": _validate_sha256(
            value.get("arguments_sha256"), label="transport mutation arguments hash"
        ),
    }


def _receipt_mutation_intent(receipt: dict[str, Any]) -> dict[str, str] | None:
    present = {key for key in _MUTATION_INTENT_KEYS if key in receipt}
    if not present:
        return None
    if present != _MUTATION_INTENT_KEYS:
        raise TransportRoundtripError("transport receipt mutation intent is incomplete")
    return validate_mutation_intent(
        {key: receipt[key] for key in _MUTATION_INTENT_KEYS}
    )


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
    if kind in _LEGACY_SCOPE_KINDS:
        raise TransportRoundtripError(
            "legacy transport client scope cannot authorize mutation; "
            "connector_session identity is required"
        )
    if kind not in _CLIENT_SCOPE_KINDS:
        raise TransportRoundtripError(
            "transport connector-session scope is required"
        )
    return {"kind": str(kind), "label": label}


def client_scope_sha256(value: Any) -> str:
    return _sha256_json(validate_client_scope(value))


def derive_connector_session_scope(
    *,
    client_id: str | None,
    connector_session_id: str,
    server_instance_id: str,
) -> dict[str, str]:
    """Bind transport authority to a protocol-level connector session.

    The connector_session_id must be a stable transport identity such as the
    Streamable HTTP ``mcp-session-id``. Python object identity, weakrefs and
    per-call context wrappers are not accepted here; callers must supply the
    already-resolved protocol string.
    """
    normalized_client_id = (
        None
        if client_id is None
        else _validate_text(client_id, label="transport connector client id")
    )
    normalized_session_id = _validate_text(
        connector_session_id, label="transport connector session id"
    )
    normalized_server_instance_id = _validate_text(
        server_instance_id,
        label="transport server instance id",
    )
    return validate_client_scope(
        {
            "kind": CONNECTOR_SESSION_SCOPE_KIND,
            "label": _sha256_json(
                {
                    "client_id": normalized_client_id,
                    "connector_session_id": normalized_session_id,
                    "server_instance_id": normalized_server_instance_id,
                }
            ),
        }
    )


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


def _is_session_pool(scope: dict[str, str]) -> bool:
    """A pool is private to one connector session; there is no global pool."""
    return scope["kind"] == CONNECTOR_SESSION_SCOPE_KIND


def _is_shared_pool(scope: dict[str, str]) -> bool:
    # Compatibility alias used by older call sites and tests.
    return _is_session_pool(scope)


def _empty_state(scope: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "kind": STATE_KIND,
        "client_scope_sha256": _sha256_json(scope),
        "client_scope_kind": scope["kind"],
        "pending_challenges": [],
        "verified_receipts": [],
        "last_consumption_receipt": None,
    }


def _validate_state_identity(
    state: dict[str, Any], *, scope: dict[str, str], schema_version: int
) -> None:
    scope_hash = _sha256_json(scope)
    if (
        state.get("schema_version") != schema_version
        or state.get("kind") != STATE_KIND
        or state.get("client_scope_sha256") != scope_hash
        or state.get("client_scope_kind") != scope["kind"]
    ):
        raise TransportRoundtripError(
            "transport roundtrip state contract mismatch"
        )


def _validate_receipt_sequence(
    value: Any,
    *,
    expected_kind: str,
    scope: dict[str, str],
    maximum: int,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > maximum:
        raise TransportRoundtripError(
            "transport roundtrip receipt pool contract mismatch"
        )
    receipts: list[dict[str, Any]] = []
    receipt_hashes: set[str] = set()
    challenge_hashes: set[str] = set()
    for receipt in value:
        validated = _validate_receipt(receipt, expected_kind=expected_kind, scope=scope)
        receipt_hash = str(validated["receipt_sha256"])
        if receipt_hash in receipt_hashes:
            raise TransportRoundtripError(
                "transport roundtrip receipt pool contains duplicates"
            )
        receipt_hashes.add(receipt_hash)
        if expected_kind == CHALLENGE_KIND:
            _validate_sha256(
                validated.get("challenge_nonce_sha256"),
                label="transport challenge nonce hash",
            )
        elif expected_kind == VERIFICATION_KIND:
            challenge_hash = _validate_sha256(
                validated.get("challenge_receipt_sha256"),
                label="transport challenge receipt hash",
            )
            if challenge_hash in challenge_hashes:
                raise TransportRoundtripError(
                    "transport verification pool reuses one challenge"
                )
            challenge_hashes.add(challenge_hash)
        _receipt_mutation_intent(validated)
        receipts.append(validated)
    return receipts


def _legacy_state_to_current(
    state: dict[str, Any], *, scope: dict[str, str]
) -> dict[str, Any]:
    _validate_state_identity(state, scope=scope, schema_version=SCHEMA_VERSION)
    pending = state.get("pending_challenge")
    verified = state.get("verified_receipt")
    consumption = state.get("last_consumption_receipt")
    pending_values = [] if pending is None else [pending]
    verified_values = [] if verified is None else [verified]
    _validate_receipt_sequence(
        pending_values,
        expected_kind=CHALLENGE_KIND,
        scope=scope,
        maximum=1,
    )
    _validate_receipt_sequence(
        verified_values,
        expected_kind=VERIFICATION_KIND,
        scope=scope,
        maximum=1,
    )
    if consumption is not None:
        _validate_consumption_receipt(consumption, scope=scope)
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "kind": STATE_KIND,
        "client_scope_sha256": state["client_scope_sha256"],
        "client_scope_kind": state["client_scope_kind"],
        "pending_challenges": pending_values,
        "verified_receipts": verified_values,
        "last_consumption_receipt": consumption,
    }


def _validate_consumption_receipt(
    receipt: Any, *, scope: dict[str, str]
) -> dict[str, Any]:
    validated = _validate_receipt(
        receipt, expected_kind=CONSUMPTION_KIND, scope=scope
    )
    _validate_sha256(
        validated.get("verification_receipt_sha256"),
        label="transport verification receipt hash",
    )
    _validate_sha256(
        validated.get("arguments_sha256"),
        label="transport mutation arguments hash",
    )
    _validate_text(
        validated.get("tool_name"),
        label="transport mutation tool name",
        maximum_bytes=256,
    )
    return validated


def _validate_state(state: Any, *, scope: dict[str, str]) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise TransportRoundtripError(
            "transport roundtrip state must be an object"
        )
    schema_version = state.get("schema_version")
    # Schema v1 single-slot, v2 shared_unlabeled pools, and v3 object/weakref-
    # bound caller_session states may contain cross-client or object-tied
    # authority. They never become v4 connector-session authority.
    if state.get("kind") == STATE_KIND and schema_version in _LEGACY_STATE_SCHEMA_VERSIONS:
        return _empty_state(scope)
    if (
        schema_version == SCHEMA_VERSION
        and set(state) == _LEGACY_STATE_KEYS
    ):
        return _empty_state(scope)
    if set(state) != _STATE_KEYS:
        raise TransportRoundtripError(
            "transport roundtrip state contract mismatch"
        )
    _validate_state_identity(
        state, scope=scope, schema_version=STATE_SCHEMA_VERSION
    )
    session_pool = _is_session_pool(scope)
    pending = _validate_receipt_sequence(
        state.get("pending_challenges"),
        expected_kind=CHALLENGE_KIND,
        scope=scope,
        maximum=MAX_SHARED_PENDING_CHALLENGES if session_pool else 1,
    )
    verified = _validate_receipt_sequence(
        state.get("verified_receipts"),
        expected_kind=VERIFICATION_KIND,
        scope=scope,
        maximum=MAX_SHARED_VERIFIED_RECEIPTS if session_pool else 1,
    )
    consumption = state.get("last_consumption_receipt")
    if consumption is not None:
        _validate_consumption_receipt(consumption, scope=scope)
    return {
        **state,
        "pending_challenges": pending,
        "verified_receipts": verified,
        "last_consumption_receipt": consumption,
    }

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


def _current_receipts(
    receipts: list[dict[str, Any]],
    *,
    runtime_binding: dict[str, str],
    now_unix: int,
) -> list[dict[str, Any]]:
    """Keep only receipts that are current *and* bound to an exact target.

    An unbound receipt authorizes nothing, so keeping it would only let stale
    legacy entries occupy the bounded pool and crowd out exact handshakes.
    They are discarded on sight rather than at TTL.
    """
    return [
        receipt
        for receipt in receipts
        if _receipt_mutation_intent(receipt) is not None
        and _receipt_is_current(
            receipt,
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        )
    ]


def _receipt_order(receipt: dict[str, Any]) -> tuple[int, str]:
    return (
        int(receipt["created_at_unix"]),
        str(receipt["receipt_sha256"]),
    )


def _prune_state(
    state: dict[str, Any],
    *,
    runtime_binding: dict[str, str],
    now_unix: int,
) -> dict[str, Any]:
    return {
        **state,
        "pending_challenges": _current_receipts(
            state["pending_challenges"],
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        "verified_receipts": _current_receipts(
            state["verified_receipts"],
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
    }


def _receipt_for_hash(
    receipts: list[dict[str, Any]], receipt_sha256: str
) -> dict[str, Any] | None:
    return next(
        (
            receipt
            for receipt in receipts
            if receipt.get("receipt_sha256") == receipt_sha256
        ),
        None,
    )


def _verification_for_challenge(
    receipts: list[dict[str, Any]], challenge_sha256: str
) -> dict[str, Any] | None:
    return next(
        (
            receipt
            for receipt in receipts
            if receipt.get("challenge_receipt_sha256")
            == challenge_sha256
        ),
        None,
    )


def _new_challenge(
    *,
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    timestamp: int,
    previous_verification: dict[str, Any] | None,
    mutation_intent: dict[str, str] | None,
) -> dict[str, Any]:
    challenge = _receipt_base(
        kind=CHALLENGE_KIND,
        scope=scope,
        runtime_binding=runtime_binding,
        created_at_unix=timestamp,
        expires_at_unix=timestamp + CHALLENGE_TTL_SECONDS,
    )
    challenge.update(
        {
            "challenge_nonce_sha256": hashlib.sha256(
                secrets.token_bytes(32)
            ).hexdigest(),
            "previous_verification_receipt_sha256": (
                previous_verification.get("receipt_sha256")
                if isinstance(previous_verification, dict)
                else None
            ),
        }
    )
    if mutation_intent is not None:
        challenge.update(mutation_intent)
    challenge["receipt_sha256"] = _receipt_sha256(challenge)
    return challenge


def _new_verification(
    *,
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    timestamp: int,
    challenge_sha256: str,
    previous_verification: dict[str, Any] | None,
    mutation_intent: dict[str, str] | None,
) -> dict[str, Any]:
    verification = _receipt_base(
        kind=VERIFICATION_KIND,
        scope=scope,
        runtime_binding=runtime_binding,
        created_at_unix=timestamp,
        expires_at_unix=timestamp + VERIFICATION_TTL_SECONDS,
    )
    verification.update(
        {
            "challenge_receipt_sha256": challenge_sha256,
            "previous_verification_receipt_sha256": (
                previous_verification.get("receipt_sha256")
                if isinstance(previous_verification, dict)
                else None
            ),
        }
    )
    if mutation_intent is not None:
        verification.update(mutation_intent)
    verification["receipt_sha256"] = _receipt_sha256(verification)
    return verification


def _verified_projection(receipt: dict[str, Any]) -> tuple[str, bool, str]:
    """Project one verification: only an intent-bound one opens the gate.

    This is the single place where "may the gate open" is decided, and it
    re-derives the answer from the receipt on every call. Four upstream guards
    already make an unbound receipt impossible here -- begin() and
    acknowledge() refuse one, _current_receipts() drops stored ones on sight,
    and consume_verified() admits only an exact match -- so the closed branch
    is a deliberate second line rather than a reachable state. It is kept
    because the cost is one comparison and the failure mode it covers is a
    gate that opens for an unbound receipt.
    """
    if _receipt_mutation_intent(receipt) is not None:
        return "verified", True, "invoke exactly one mutating tool"
    return (
        "unbound_verification",
        False,
        (
            "start a new transport handshake bound to the exact "
            "target_tool_name and target_arguments"
        ),
    )


def _projection(
    *,
    state: dict[str, Any],
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    now_unix: int,
    action: str,
    replayed: bool,
    selected_pending: dict[str, Any] | None = None,
    selected_verified: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending_current = sorted(
        _current_receipts(
            state["pending_challenges"],
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        key=_receipt_order,
    )
    verified_current = sorted(
        _current_receipts(
            state["verified_receipts"],
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        key=_receipt_order,
    )
    consumption = state.get("last_consumption_receipt")
    selected_pending_current = (
        selected_pending if selected_pending in pending_current else None
    )
    selected_verified_current = (
        selected_verified if selected_verified in verified_current else None
    )
    if selected_verified_current is not None:
        projected_pending = None
        projected_verified = selected_verified_current
        state_name, gate_open, next_action = _verified_projection(
            selected_verified_current
        )
    elif selected_pending_current is not None:
        projected_pending = selected_pending_current
        projected_verified = None
        state_name = "challenge_pending"
        gate_open = False
        next_action = (
            "call grip_run for transport-roundtrip with action=ack and the "
            "exact challenge_receipt_sha256"
        )
    elif verified_current:
        # _current_receipts already dropped every unbound receipt, so no second
        # filter is needed here.
        projected_pending = pending_current[0] if pending_current else None
        projected_verified = verified_current[0]
        state_name, gate_open, next_action = _verified_projection(projected_verified)
    elif pending_current:
        projected_pending = pending_current[0]
        projected_verified = None
        state_name = "challenge_pending"
        gate_open = False
        next_action = (
            "call grip_run for transport-roundtrip with action=ack and the "
            "exact challenge_receipt_sha256"
        )
    elif state["verified_receipts"] or state["pending_challenges"]:
        projected_pending = None
        projected_verified = None
        state_name = (
            "binding_mismatch"
            if any(
                receipt.get("runtime_binding") != runtime_binding
                for receipt in (
                    state["verified_receipts"] + state["pending_challenges"]
                )
            )
            else "stale"
        )
        gate_open = False
        next_action = "start a new transport handshake"
    elif consumption is not None:
        projected_pending = None
        projected_verified = None
        state_name = "consumed"
        gate_open = False
        next_action = "start a new transport handshake before another mutation"
    else:
        projected_pending = None
        projected_verified = None
        state_name = "missing"
        gate_open = False
        next_action = "start a new transport handshake"

    projected_receipt = projected_verified or projected_pending
    projected_intent = (
        _receipt_mutation_intent(projected_receipt)
        if projected_receipt is not None
        else None
    )
    if projected_intent is not None and gate_open:
        next_action = (
            "invoke exactly one bound mutating tool: " + projected_intent["tool_name"]
        )
    session_pool = _is_session_pool(scope)
    does_not_establish = [
        "authenticated client identity",
        "application-level success of a mutating tool",
        "absence of response loss after a mutation",
        "client instruction compliance",
        "resistance to compromised same-uid code",
        "that Python object identity or weakrefs authorize transport mutation",
        "that a global shared_unlabeled pool can authorize mutation",
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "state": state_name,
        "action": action,
        "replayed": replayed,
        "mutation_gate_open": gate_open,
        "single_use": True,
        "pool_mode": (
            "connector-session-token-pool" if session_pool else "single-slot"
        ),
        "pending_challenge_count": len(pending_current),
        "verified_receipt_count": len(verified_current),
        "pool_limits": (
            {
                "pending_challenges": MAX_SHARED_PENDING_CHALLENGES,
                "verified_receipts": MAX_SHARED_VERIFIED_RECEIPTS,
            }
            if session_pool
            else {
                "pending_challenges": 1,
                "verified_receipts": 1,
            }
        ),
        "client_scope_kind": scope["kind"],
        "client_scope_sha256": _sha256_json(scope),
        "mutation_intent_bound": projected_intent is not None,
        "target_tool_name": projected_intent["tool_name"]
        if projected_intent is not None
        else None,
        "target_arguments_sha256": projected_intent["arguments_sha256"]
        if projected_intent is not None
        else None,
        "challenge_receipt_sha256": (
            projected_pending.get("receipt_sha256")
            if projected_pending is not None
            else None
        ),
        "challenge_created_at_unix": (
            projected_pending.get("created_at_unix")
            if projected_pending is not None
            else None
        ),
        "challenge_expires_at_unix": (
            projected_pending.get("expires_at_unix")
            if projected_pending is not None
            else None
        ),
        "verification_receipt_sha256": (
            projected_verified.get("receipt_sha256")
            if projected_verified is not None
            else None
        ),
        "verified_at_unix": (
            projected_verified.get("created_at_unix")
            if projected_verified is not None
            else None
        ),
        "verification_expires_at_unix": (
            projected_verified.get("expires_at_unix")
            if projected_verified is not None
            else None
        ),
        "last_consumption_receipt_sha256": (
            consumption.get("receipt_sha256") if isinstance(consumption, dict) else None
        ),
        "last_consumed_tool_name": (
            consumption.get("tool_name") if isinstance(consumption, dict) else None
        ),
        "runtime_binding_sha256": _sha256_json(runtime_binding),
        "recommended_next_action": next_action,
        "does_not_establish": does_not_establish,
    }


def begin(
    *,
    client_scope: dict[str, Any],
    runtime_binding: dict[str, Any],
    mutation_intent: dict[str, Any] | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    scope = validate_client_scope(client_scope)
    binding = validate_runtime_binding(runtime_binding)
    intent = validate_mutation_intent(mutation_intent)
    if intent is None:
        raise TransportMutationIntentRequired(
            "transport handshake requires an exact mutation intent: supply "
            "target_tool_name and target_arguments; an unbound handshake "
            "authorizes nothing and would only occupy the bounded pool"
        )
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _prune_state(
            _load_state(scope),
            runtime_binding=binding,
            now_unix=timestamp,
        )
        verified = sorted(state["verified_receipts"], key=_receipt_order)
        pending = sorted(state["pending_challenges"], key=_receipt_order)
        session_pool = _is_session_pool(scope)
        matching_verified = [
            receipt
            for receipt in verified
            if _receipt_mutation_intent(receipt) == intent
        ]
        if matching_verified:
            return _projection(
                state=state,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="begin",
                replayed=True,
                selected_verified=matching_verified[0],
            )
        matching_pending = [
            receipt
            for receipt in pending
            if _receipt_mutation_intent(receipt) == intent
        ]
        if matching_pending:
            return _projection(
                state=state,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="begin",
                replayed=True,
                selected_pending=matching_pending[0],
            )
        if session_pool and len(pending) >= MAX_SHARED_PENDING_CHALLENGES:
            raise TransportRoundtripRequired(
                "connector-session transport pending challenge pool is full"
            )
        previous = verified[-1] if verified else None
        challenge = _new_challenge(
            scope=scope,
            runtime_binding=binding,
            timestamp=timestamp,
            previous_verification=previous,
            mutation_intent=intent,
        )
        state = {
            **state,
            "pending_challenges": (
                [*pending, challenge] if session_pool else [challenge]
            ),
            "verified_receipts": (verified if session_pool else []),
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return _projection(
            state=state,
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
            action="begin",
            replayed=False,
            selected_pending=challenge,
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
        challenge_receipt_sha256,
        label="challenge_receipt_sha256",
    )
    binding = validate_runtime_binding(runtime_binding)
    timestamp = _timestamp(now_unix)
    with _state_lock():
        loaded = _load_state(scope)
        existing = _verification_for_challenge(
            loaded["verified_receipts"], challenge_hash
        )
        if existing is not None and _receipt_mutation_intent(existing) is None:
            # This replay path reads unpruned state, so a legacy unbound
            # verification would otherwise be handed back instead of discarded.
            raise TransportMutationIntentRequired(
                "stored transport verification carries no exact mutation "
                "intent and cannot be replayed; begin a new handshake with "
                "target_tool_name and target_arguments"
            )
        if existing is not None and _receipt_is_current(
            existing,
            runtime_binding=binding,
            now_unix=timestamp,
        ):
            return _projection(
                state=loaded,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="ack",
                replayed=True,
                selected_verified=existing,
            )
        pending = _receipt_for_hash(loaded["pending_challenges"], challenge_hash)
        if pending is None:
            if existing is not None:
                if existing.get("runtime_binding") != binding:
                    raise TransportRoundtripError(
                        "transport verification is bound to a different runtime"
                    )
                raise TransportRoundtripError(
                    "transport verification is stale; begin a new handshake"
                )
            raise TransportRoundtripError(
                "transport challenge is missing; begin a new handshake"
            )
        if _receipt_mutation_intent(pending) is None:
            raise TransportMutationIntentRequired(
                "transport challenge carries no exact mutation intent and "
                "cannot be acknowledged; begin a new handshake with "
                "target_tool_name and target_arguments"
            )
        if pending.get("runtime_binding") != binding:
            raise TransportRoundtripError(
                "transport challenge is bound to a different runtime"
            )
        if not _receipt_is_current(
            pending,
            runtime_binding=binding,
            now_unix=timestamp,
        ):
            raise TransportRoundtripError(
                "transport challenge is stale; begin a new handshake"
            )

        state = _prune_state(
            loaded,
            runtime_binding=binding,
            now_unix=timestamp,
        )
        current_verified = sorted(state["verified_receipts"], key=_receipt_order)
        session_pool = _is_session_pool(scope)
        if session_pool and len(current_verified) >= MAX_SHARED_VERIFIED_RECEIPTS:
            raise TransportRoundtripRequired(
                "connector-session transport verified receipt pool is full"
            )
        previous = current_verified[-1] if current_verified else None
        verification = _new_verification(
            scope=scope,
            runtime_binding=binding,
            timestamp=timestamp,
            challenge_sha256=challenge_hash,
            previous_verification=previous,
            mutation_intent=_receipt_mutation_intent(pending),
        )
        remaining_pending = [
            item
            for item in state["pending_challenges"]
            if item.get("receipt_sha256") != challenge_hash
        ]
        state = {
            **state,
            "pending_challenges": (remaining_pending if session_pool else []),
            "verified_receipts": (
                [*current_verified, verification]
                if session_pool
                else [verification]
            ),
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return _projection(
            state=state,
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
            action="ack",
            replayed=False,
            selected_verified=verification,
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


# require_verified() was removed on purpose. It asserted only that *some*
# bound verification existed, not that one existed for the requested target,
# so any future caller reaching for it would have re-introduced exactly the
# target confusion this module exists to prevent. Admission has one entry
# point: consume_verified(), which names the exact tool and arguments digest.


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
        tool_name,
        label="transport mutation tool name",
        maximum_bytes=256,
    )
    arguments_hash = _validate_sha256(
        arguments_sha256,
        label="transport mutation arguments hash",
    )
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _prune_state(
            _load_state(scope),
            runtime_binding=binding,
            now_unix=timestamp,
        )
        verified_receipts = sorted(state["verified_receipts"], key=_receipt_order)
        if not verified_receipts:
            raise TransportRoundtripRequired(
                "mutating MCP calls require a fresh single-use transport verification"
            )
        requested_intent = {"tool_name": name, "arguments_sha256": arguments_hash}
        exact = [
            r
            for r in verified_receipts
            if _receipt_mutation_intent(r) == requested_intent
        ]
        if not exact:
            # An unbound verification must never authorize a mutation. Selecting
            # one would let any handshake admit any target, which is the whole
            # defect this gate exists to prevent.
            bound_count = sum(
                1 for r in verified_receipts if _receipt_mutation_intent(r) is not None
            )
            unbound_count = len(verified_receipts) - bound_count
            raise TransportMutationIntentMismatch(
                "no transport verification is bound to this exact mutation: "
                f"client_scope_sha256={_sha256_json(scope)} "
                f"tool_name={name} arguments_sha256={arguments_hash}; "
                f"intent_bound_verifications={bound_count} "
                f"unbound_verifications={unbound_count}; "
                "unbound verifications cannot authorize any mutation"
            )
        verified = exact[0]
        verification_intent = _receipt_mutation_intent(verified)
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
        if _is_session_pool(scope):
            remaining_verified = [
                receipt
                for receipt in verified_receipts
                if receipt.get("receipt_sha256") != verified["receipt_sha256"]
            ]
            remaining_pending = state["pending_challenges"]
        else:
            remaining_verified = []
            remaining_pending = []
        state = {
            **state,
            "pending_challenges": remaining_pending,
            "verified_receipts": remaining_verified,
            "last_consumption_receipt": consumption,
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        does_not_establish = [
            "authenticated client identity",
            "application-level success of the admitted mutation",
            "absence of response loss after the admitted mutation",
            "that the admitted effect completed: admission is consumed before "
            "the effect runs, so a failed or lost effect leaves no reusable "
            "proof and requires a new handshake plus target readback",
            "that Python object identity or weakrefs authorize transport mutation",
            "that identical target arguments alone admit a mutation",
            "that a global shared_unlabeled pool can authorize mutation",
        ]
        return {
            "schema_version": SCHEMA_VERSION,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "state": "consumed",
            "single_use": True,
            "pool_mode": (
                "connector-session-token-pool"
                if _is_session_pool(scope)
                else "single-slot"
            ),
            "pending_challenge_count": len(remaining_pending),
            "verified_receipt_count": len(remaining_verified),
            "client_scope_kind": scope["kind"],
            "client_scope_sha256": _sha256_json(scope),
            "runtime_binding_sha256": _sha256_json(binding),
            "verification_receipt_sha256": verified["receipt_sha256"],
            "consumption_receipt_sha256": consumption["receipt_sha256"],
            "tool_name": name,
            "arguments_sha256": arguments_hash,
            "verification_was_intent_bound": verification_intent is not None,
            "does_not_establish": does_not_establish,
        }
