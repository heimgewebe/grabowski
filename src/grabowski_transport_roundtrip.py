from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
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
EXECUTION_RESERVATION_TTL_SECONDS = 30
CLOCK_SKEW_SECONDS = 30
MAX_STATE_BYTES = 512 * 1024
MAX_SHARED_PENDING_CHALLENGES = 32
MAX_SHARED_VERIFIED_RECEIPTS = 32
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
_CLIENT_SCOPE_KINDS = frozenset(
    {"client_declared_meta", "connector_capability", "shared_unlabeled"}
)
_MUTATION_INTENT_KEYS = frozenset({"tool_name", "arguments_sha256"})
_EXECUTION_CAPABILITY_KEY = "execution_capability_sha256"
_EXECUTION_CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar(
    "grabowski_transport_execution_context", default=None
)
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


class TransportRoundtripError(RuntimeError):
    """Raised when transport-roundtrip state cannot be trusted."""


class TransportRoundtripRequired(TransportRoundtripError):
    """Raised when a mutating call lacks a fresh roundtrip verification."""


class TransportMutationIntentMismatch(TransportRoundtripRequired):
    """Raised when only verifications for other mutation intents are available."""


class TransportMutationIntentRequired(TransportRoundtripError):
    """Raised when a handshake is attempted without an exact target intent."""


class TransportAtomicExecutionRequired(TransportRoundtripRequired):
    """Raised when a shared caller must use the atomic execute action."""


class TransportExecutionReservationConflict(TransportRoundtripRequired):
    """Raised when an exact challenge already has an active execution reservation."""


class TransportExecutionCapabilityRequired(TransportRoundtripRequired):
    """Raised when a reserved verification is consumed outside its execution context."""


class TransportExecutionCapabilityMismatch(TransportMutationIntentMismatch):
    """Raised when an execution context does not own the exact reservation."""


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


def _execution_capability_sha256(challenge_receipt_sha256: Any) -> str:
    challenge_hash = _validate_sha256(
        challenge_receipt_sha256, label="transport execution challenge hash"
    )
    return hashlib.sha256(
        ("grabowski-transport-execution-v1:" + challenge_hash).encode("ascii")
    ).hexdigest()


@contextmanager
def execution_capability(
    challenge_receipt_sha256: str,
) -> Iterator[dict[str, Any]]:
    """Bind one challenge-derived in-process ownership tag to dispatch.

    The digest is deterministic from the challenge, so it is not a secret or
    authentication factor. Authority comes from the private ContextVar that a
    remote caller cannot inject into a target invocation.
    """

    capability_sha256 = _execution_capability_sha256(challenge_receipt_sha256)
    if _EXECUTION_CONTEXT.get() is not None:
        raise TransportExecutionCapabilityMismatch(
            "nested transport execution capabilities are not allowed"
        )
    session: dict[str, Any] = {
        "capability_sha256": capability_sha256,
        "verification_receipt_sha256": None,
        "consumption_receipt_sha256": None,
    }
    token = _EXECUTION_CONTEXT.set(session)
    try:
        yield session
    finally:
        _EXECUTION_CONTEXT.reset(token)


def execution_capability_snapshot(session: Any) -> dict[str, str | None]:
    if not isinstance(session, dict):
        raise TransportExecutionCapabilityMismatch(
            "transport execution session is invalid"
        )
    capability_sha256 = _validate_sha256(
        session.get("capability_sha256"),
        label="transport execution capability hash",
    )
    verification = session.get("verification_receipt_sha256")
    consumption = session.get("consumption_receipt_sha256")
    if verification is not None:
        verification = _validate_sha256(
            verification, label="transport execution verification receipt hash"
        )
    if consumption is not None:
        consumption = _validate_sha256(
            consumption, label="transport execution consumption receipt hash"
        )
    return {
        "capability_sha256": capability_sha256,
        "verification_receipt_sha256": verification,
        "consumption_receipt_sha256": consumption,
    }


def _require_execution_consumption_owner(
    *, capability_sha256: str
) -> dict[str, Any]:
    session = _EXECUTION_CONTEXT.get()
    if not isinstance(session, dict):
        raise TransportExecutionCapabilityRequired(
            "reserved transport verification requires its atomic execution context"
        )
    if not secrets.compare_digest(
        str(session.get("capability_sha256")), capability_sha256
    ):
        raise TransportExecutionCapabilityMismatch(
            "transport execution capability does not own this reservation"
        )
    if session.get("consumption_receipt_sha256") is not None:
        raise TransportExecutionCapabilityMismatch(
            "transport execution capability has already been consumed"
        )
    return session


def _record_execution_consumption(
    session: dict[str, Any],
    *,
    verification_receipt_sha256: str,
    consumption_receipt_sha256: str,
) -> None:
    session["verification_receipt_sha256"] = verification_receipt_sha256
    session["consumption_receipt_sha256"] = consumption_receipt_sha256

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


def _receipt_execution_capability_sha256(
    receipt: dict[str, Any],
) -> str | None:
    value = receipt.get(_EXECUTION_CAPABILITY_KEY)
    if value is None:
        return None
    return _validate_sha256(
        value, label="transport execution capability hash"
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


def _is_shared_pool(scope: dict[str, str]) -> bool:
    return scope["kind"] == "shared_unlabeled"


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
            _receipt_execution_capability_sha256(validated)
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
    if _is_shared_pool(scope):
        verified_values = [
            receipt
            for receipt in verified_values
            if _receipt_execution_capability_sha256(receipt) is not None
        ]
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


def _state_v2_to_current(
    state: dict[str, Any], *, scope: dict[str, str]
) -> dict[str, Any]:
    """Migrate exact-intent v2 state and discard transferable shared proofs."""

    _validate_state_identity(state, scope=scope, schema_version=2)
    shared = _is_shared_pool(scope)
    pending = _validate_receipt_sequence(
        state.get("pending_challenges"),
        expected_kind=CHALLENGE_KIND,
        scope=scope,
        maximum=MAX_SHARED_PENDING_CHALLENGES if shared else 1,
    )
    verified = _validate_receipt_sequence(
        state.get("verified_receipts"),
        expected_kind=VERIFICATION_KIND,
        scope=scope,
        maximum=MAX_SHARED_VERIFIED_RECEIPTS if shared else 1,
    )
    if shared:
        verified = [
            receipt
            for receipt in verified
            if _receipt_execution_capability_sha256(receipt) is not None
        ]
    consumption = state.get("last_consumption_receipt")
    if consumption is not None:
        _validate_consumption_receipt(consumption, scope=scope)
    return {
        **state,
        "schema_version": STATE_SCHEMA_VERSION,
        "pending_challenges": pending,
        "verified_receipts": verified,
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
    if (
        state.get("schema_version") == SCHEMA_VERSION
        and set(state) == _LEGACY_STATE_KEYS
    ):
        return _legacy_state_to_current(state, scope=scope)
    if state.get("schema_version") == 2 and set(state) == _STATE_KEYS:
        return _state_v2_to_current(state, scope=scope)
    if state.get("schema_version") == 3 and set(state) == _STATE_KEYS:
        # T142: schema-v3 scopes were not protocol-authenticated.  Validate only
        # their storage identity, then discard every challenge/verification so
        # no pre-capability receipt can authorize a schema-v4 mutation.
        _validate_state_identity(state, scope=scope, schema_version=3)
        return _empty_state(scope)
    if set(state) != _STATE_KEYS:
        raise TransportRoundtripError(
            "transport roundtrip state contract mismatch"
        )
    _validate_state_identity(
        state, scope=scope, schema_version=STATE_SCHEMA_VERSION
    )
    shared = _is_shared_pool(scope)
    pending = _validate_receipt_sequence(
        state.get("pending_challenges"),
        expected_kind=CHALLENGE_KIND,
        scope=scope,
        maximum=MAX_SHARED_PENDING_CHALLENGES if shared else 1,
    )
    verified = _validate_receipt_sequence(
        state.get("verified_receipts"),
        expected_kind=VERIFICATION_KIND,
        scope=scope,
        maximum=MAX_SHARED_VERIFIED_RECEIPTS if shared else 1,
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
    scope: dict[str, str],
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
        and (
            receipt.get("kind") != VERIFICATION_KIND
            or not _is_shared_pool(scope)
            or _receipt_execution_capability_sha256(receipt) is not None
        )
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
    scope: dict[str, str],
    runtime_binding: dict[str, str],
    now_unix: int,
) -> dict[str, Any]:
    return {
        **state,
        "pending_challenges": _current_receipts(
            state["pending_challenges"],
            scope=scope,
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        "verified_receipts": _current_receipts(
            state["verified_receipts"],
            scope=scope,
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
    execution_capability_sha256: str | None = None,
) -> dict[str, Any]:
    ttl_seconds = (
        EXECUTION_RESERVATION_TTL_SECONDS
        if execution_capability_sha256 is not None
        else VERIFICATION_TTL_SECONDS
    )
    verification = _receipt_base(
        kind=VERIFICATION_KIND,
        scope=scope,
        runtime_binding=runtime_binding,
        created_at_unix=timestamp,
        expires_at_unix=timestamp + ttl_seconds,
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
    if execution_capability_sha256 is not None:
        verification[_EXECUTION_CAPABILITY_KEY] = _validate_sha256(
            execution_capability_sha256,
            label="transport execution capability hash",
        )
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
        if _receipt_execution_capability_sha256(receipt) is not None:
            return (
                "execution_reserved",
                False,
                "dispatch the exact target inside the private atomic execution context",
            )
        return "verified", True, "invoke exactly one mutating tool"
    return (
        "unbound_verification",
        False,
        (
            "start a new transport handshake bound to the exact "
            "target_tool_name and target_arguments"
        ),
    )


def _pending_challenge_next_action(scope: dict[str, str]) -> str:
    """Return an executable next step for the caller's actual scope."""
    if _is_shared_pool(scope):
        return (
            "call grip_run for transport-roundtrip with action=execute and the exact "
            "challenge_receipt_sha256; the server retains the exact target briefly; "
            "do not retry the target separately"
        )
    return (
        "call grip_run for transport-roundtrip with action=ack and the "
        "exact challenge_receipt_sha256"
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
            scope=scope,
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        key=_receipt_order,
    )
    verified_current = sorted(
        _current_receipts(
            state["verified_receipts"],
            scope=scope,
            runtime_binding=runtime_binding,
            now_unix=now_unix,
        ),
        key=_receipt_order,
    )
    consumption = state.get("last_consumption_receipt")
    shared = _is_shared_pool(scope)
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
        next_action = _pending_challenge_next_action(scope)
    elif shared and (verified_current or pending_current):
        projected_pending = None
        projected_verified = None
        state_name = "pooled"
        gate_open = False
        next_action = (
            "continue only with the caller-owned challenge; pooled shared state "
            "does not project another caller's target"
        )
    elif verified_current:
        projected_pending = pending_current[0] if pending_current else None
        projected_verified = verified_current[0]
        state_name, gate_open, next_action = _verified_projection(projected_verified)
    elif pending_current:
        projected_pending = pending_current[0]
        projected_verified = None
        state_name = "challenge_pending"
        gate_open = False
        next_action = _pending_challenge_next_action(scope)
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
    execution_capability_bound = bool(
        projected_verified is not None
        and _receipt_execution_capability_sha256(projected_verified) is not None
    )
    if projected_intent is not None and gate_open:
        next_action = (
            "invoke exactly one bound mutating tool: " + projected_intent["tool_name"]
        )
    does_not_establish = [
        "authenticated client identity",
        "application-level success of a mutating tool",
        "absence of response loss after a mutation",
        "client instruction compliance",
        "resistance to compromised same-uid code",
    ]
    if shared:
        does_not_establish.extend(
            [
                "which unlabeled caller owns a pooled verification",
                "caller identity: shared_unlabeled is a shared storage "
                "partition, not an identity",
                "that two unlabeled callers of the same exact intent are "
                "distinguishable",
            ]
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "state_schema_version": STATE_SCHEMA_VERSION,
        "state": state_name,
        "action": action,
        "replayed": replayed,
        "mutation_gate_open": gate_open,
        "single_use": True,
        "pool_mode": (
            "bounded-shared-capability-pool" if shared else "single-slot"
        ),
        "pending_challenge_count": len(pending_current),
        "verified_receipt_count": len(verified_current),
        "pool_limits": (
            {
                "pending_challenges": MAX_SHARED_PENDING_CHALLENGES,
                "verified_receipts": MAX_SHARED_VERIFIED_RECEIPTS,
            }
            if shared
            else {
                "pending_challenges": 1,
                "verified_receipts": 1,
            }
        ),
        "client_scope_kind": scope["kind"],
        "client_scope_sha256": _sha256_json(scope),
        "mutation_intent_bound": projected_intent is not None,
        "execution_capability_bound": execution_capability_bound,
        "atomic_execution_ready": execution_capability_bound,
        "target_tool_name": projected_intent["tool_name"]
        if projected_intent is not None
        else None,
        "target_arguments_sha256": projected_intent["arguments_sha256"]
        if projected_intent is not None
        else None,
        "challenge_receipt_sha256": (
            projected_pending.get("receipt_sha256")
            if action == "begin" and selected_pending_current is not None
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
            consumption.get("receipt_sha256")
            if isinstance(consumption, dict) and not shared
            else None
        ),
        "last_consumed_tool_name": (
            consumption.get("tool_name")
            if isinstance(consumption, dict) and not shared
            else None
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
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
        )
        verified = sorted(state["verified_receipts"], key=_receipt_order)
        pending = sorted(state["pending_challenges"], key=_receipt_order)
        shared = _is_shared_pool(scope)
        # A shared unlabeled caller is not an identity. Replaying a pending
        # challenge for an identical intent would disclose another caller's
        # bearer capability, so every shared begin gets a fresh challenge.
        if not shared:
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
        if shared and len(pending) >= MAX_SHARED_PENDING_CHALLENGES:
            # Pending challenges have admitted no effect. Evict the oldest one
            # rather than wedging every shared caller for the full challenge TTL.
            keep = max(0, MAX_SHARED_PENDING_CHALLENGES - 1)
            pending = pending[-keep:] if keep else []
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
                [*pending, challenge] if _is_shared_pool(scope) else [challenge]
            ),
            "verified_receipts": (verified if _is_shared_pool(scope) else []),
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
        if _is_shared_pool(scope):
            raise TransportAtomicExecutionRequired(
                "shared_unlabeled transport cannot acknowledge into a transferable "
                "verification; use action=execute with the exact challenge, target "
                "tool and target arguments"
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
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
        )
        current_verified = sorted(state["verified_receipts"], key=_receipt_order)
        if (
            _is_shared_pool(scope)
            and len(current_verified) >= MAX_SHARED_VERIFIED_RECEIPTS
        ):
            raise TransportRoundtripRequired(
                "shared transport verified receipt pool is full"
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
            "pending_challenges": (remaining_pending if _is_shared_pool(scope) else []),
            "verified_receipts": (
                [*current_verified, verification]
                if _is_shared_pool(scope)
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

def reserve_execution(
    *,
    client_scope: dict[str, Any],
    challenge_receipt_sha256: str,
    runtime_binding: dict[str, Any],
    tool_name: str,
    arguments_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Reserve one verified challenge for bearer-bound in-process execution."""

    scope = validate_client_scope(client_scope)
    challenge_hash = _validate_sha256(
        challenge_receipt_sha256, label="challenge_receipt_sha256"
    )
    binding = validate_runtime_binding(runtime_binding)
    name = _validate_text(
        tool_name, label="transport mutation tool name", maximum_bytes=256
    )
    arguments_hash = _validate_sha256(
        arguments_sha256, label="transport mutation arguments hash"
    )
    requested_intent = {"tool_name": name, "arguments_sha256": arguments_hash}
    capability_sha256 = _execution_capability_sha256(challenge_hash)
    timestamp = _timestamp(now_unix)
    with _state_lock():
        loaded = _load_state(scope)
        existing = _verification_for_challenge(
            loaded["verified_receipts"], challenge_hash
        )
        if existing is not None:
            if not _receipt_is_current(
                existing, runtime_binding=binding, now_unix=timestamp
            ):
                raise TransportRoundtripError(
                    "transport execution reservation is stale or runtime-bound elsewhere"
                )
            if _receipt_mutation_intent(existing) != requested_intent:
                raise TransportExecutionCapabilityMismatch(
                    "transport execution reservation targets another exact mutation"
                )
            if _receipt_execution_capability_sha256(existing) != capability_sha256:
                raise TransportExecutionCapabilityMismatch(
                    "transport execution reservation capability mismatch"
                )
            return _projection(
                state=loaded,
                scope=scope,
                runtime_binding=binding,
                now_unix=timestamp,
                action="execute",
                replayed=True,
                selected_verified=existing,
            )
        pending = _receipt_for_hash(loaded["pending_challenges"], challenge_hash)
        if pending is None:
            raise TransportRoundtripError(
                "transport challenge is missing; begin a new handshake"
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
        if _receipt_mutation_intent(pending) != requested_intent:
            raise TransportMutationIntentMismatch(
                "transport challenge is not bound to the requested atomic mutation"
            )
        state = _prune_state(
            loaded, scope=scope, runtime_binding=binding, now_unix=timestamp
        )
        current_verified = sorted(state["verified_receipts"], key=_receipt_order)
        if (
            _is_shared_pool(scope)
            and len(current_verified) >= MAX_SHARED_VERIFIED_RECEIPTS
        ):
            raise TransportRoundtripRequired(
                "shared transport verified receipt pool is full"
            )
        previous = current_verified[-1] if current_verified else None
        verification = _new_verification(
            scope=scope,
            runtime_binding=binding,
            timestamp=timestamp,
            challenge_sha256=challenge_hash,
            previous_verification=previous,
            mutation_intent=requested_intent,
            execution_capability_sha256=capability_sha256,
        )
        remaining_pending = [
            item
            for item in state["pending_challenges"]
            if item.get("receipt_sha256") != challenge_hash
        ]
        state = {
            **state,
            "pending_challenges": remaining_pending if _is_shared_pool(scope) else [],
            "verified_receipts": (
                [*current_verified, verification]
                if _is_shared_pool(scope)
                else [verification]
            ),
        }
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return _projection(
            state=state,
            scope=scope,
            runtime_binding=binding,
            now_unix=timestamp,
            action="execute",
            replayed=False,
            selected_verified=verification,
        )


def revoke_execution_reservation(
    *,
    client_scope: dict[str, Any],
    challenge_receipt_sha256: str,
    runtime_binding: dict[str, Any],
) -> bool:
    """Remove an unconsumed exact reservation after pre-effect dispatch failure."""

    scope = validate_client_scope(client_scope)
    challenge_hash = _validate_sha256(
        challenge_receipt_sha256, label="challenge_receipt_sha256"
    )
    binding = validate_runtime_binding(runtime_binding)
    capability_sha256 = _execution_capability_sha256(challenge_hash)
    with _state_lock():
        state = _load_state(scope)
        remaining: list[dict[str, Any]] = []
        removed = False
        for receipt in state["verified_receipts"]:
            if (
                receipt.get("challenge_receipt_sha256") == challenge_hash
                and receipt.get("runtime_binding") == binding
                and _receipt_execution_capability_sha256(receipt)
                == capability_sha256
            ):
                removed = True
                continue
            remaining.append(receipt)
        if not removed:
            return False
        state = {**state, "verified_receipts": remaining}
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return True


def cancel_pending_execution_challenge(
    *,
    client_scope: dict[str, Any],
    challenge_receipt_sha256: str,
    runtime_binding: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    """Atomically cancel only a still-unreserved challenge for safe retry."""

    scope = validate_client_scope(client_scope)
    challenge_hash = _validate_sha256(
        challenge_receipt_sha256, label="challenge_receipt_sha256"
    )
    binding = validate_runtime_binding(runtime_binding)
    capability_sha256 = _execution_capability_sha256(challenge_hash)
    timestamp = _timestamp(now_unix)
    with _state_lock():
        loaded = _load_state(scope)
        verification = _verification_for_challenge(
            loaded["verified_receipts"], challenge_hash
        )
        if verification is not None:
            if _receipt_is_current(
                verification, runtime_binding=binding, now_unix=timestamp
            ):
                return {
                    "state": "reserved",
                    "cancelled": False,
                    "effect_possible": True,
                    "challenge_receipt_sha256": challenge_hash,
                    "recommended_next_action": (
                        "perform target-specific readback before any retry"
                    ),
                }
            if verification.get("runtime_binding") == binding:
                remaining_verified = [
                    item
                    for item in loaded["verified_receipts"]
                    if item.get("challenge_receipt_sha256") != challenge_hash
                ]
                state = {**loaded, "verified_receipts": remaining_verified}
                _write_private_json(_state_path(_sha256_json(scope)), state)
                return {
                    "state": "cancelled_expired_reservation",
                    "cancelled": True,
                    "effect_possible": False,
                    "challenge_receipt_sha256": challenge_hash,
                    "recommended_next_action": (
                        "retry the original target call to obtain a new challenge"
                    ),
                }
            return {
                "state": "runtime_mismatch",
                "cancelled": False,
                "effect_possible": True,
                "challenge_receipt_sha256": challenge_hash,
                "recommended_next_action": (
                    "perform target-specific readback before any retry"
                ),
            }
        consumption = loaded.get("last_consumption_receipt")
        if (
            isinstance(consumption, dict)
            and _receipt_execution_capability_sha256(consumption)
            == capability_sha256
        ):
            return {
                "state": "consumed",
                "cancelled": False,
                "effect_possible": True,
                "challenge_receipt_sha256": challenge_hash,
                "recommended_next_action": (
                    "perform target-specific readback before any retry"
                ),
            }
        pending = _receipt_for_hash(loaded["pending_challenges"], challenge_hash)
        if pending is None:
            return {
                "state": "unknown",
                "cancelled": False,
                "effect_possible": True,
                "challenge_receipt_sha256": challenge_hash,
                "recommended_next_action": (
                    "perform target-specific readback before any retry"
                ),
            }
        if pending.get("runtime_binding") != binding:
            return {
                "state": "runtime_mismatch",
                "cancelled": False,
                "effect_possible": True,
                "challenge_receipt_sha256": challenge_hash,
                "recommended_next_action": (
                    "perform target-specific readback before any retry"
                ),
            }
        remaining_pending = [
            item
            for item in loaded["pending_challenges"]
            if item.get("receipt_sha256") != challenge_hash
        ]
        state = {**loaded, "pending_challenges": remaining_pending}
        _write_private_json(_state_path(_sha256_json(scope)), state)
        return {
            "state": "cancelled_pending",
            "cancelled": True,
            "effect_possible": False,
            "challenge_receipt_sha256": challenge_hash,
            "challenge_was_current": _receipt_is_current(
                pending, runtime_binding=binding, now_unix=timestamp
            ),
            "recommended_next_action": (
                "retry the original target call to obtain a new challenge"
            ),
        }


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
    execution_session = _EXECUTION_CONTEXT.get()
    execution_capability_sha256: str | None = None
    if execution_session is not None:
        if not isinstance(execution_session, dict):
            raise TransportExecutionCapabilityMismatch(
                "transport execution context is invalid"
            )
        execution_capability_sha256 = _validate_sha256(
            execution_session.get("capability_sha256"),
            label="transport execution capability hash",
        )
    timestamp = _timestamp(now_unix)
    with _state_lock():
        state = _prune_state(
            _load_state(scope),
            scope=scope,
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
            receipt
            for receipt in verified_receipts
            if _receipt_mutation_intent(receipt) == requested_intent
        ]
        if not exact:
            bound_count = sum(
                1
                for receipt in verified_receipts
                if _receipt_mutation_intent(receipt) is not None
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
        if execution_capability_sha256 is not None:
            matching = [
                receipt
                for receipt in exact
                if _receipt_execution_capability_sha256(receipt)
                == execution_capability_sha256
            ]
            if not matching:
                raise TransportExecutionCapabilityMismatch(
                    "atomic transport capability is not bound to this exact reservation"
                )
            verified = matching[0]
        else:
            unreserved = [
                receipt
                for receipt in exact
                if _receipt_execution_capability_sha256(receipt) is None
            ]
            if not unreserved:
                if _is_shared_pool(scope):
                    raise TransportAtomicExecutionRequired(
                        "shared_unlabeled mutation requires action=execute; a direct "
                        "target call cannot consume another caller's reservation"
                    )
                raise TransportExecutionCapabilityRequired(
                    "reserved transport verification requires its atomic execution context"
                )
            verified = unreserved[0]
        verification_intent = _receipt_mutation_intent(verified)
        reserved_capability_sha256 = _receipt_execution_capability_sha256(verified)
        execution_session = None
        if reserved_capability_sha256 is not None:
            execution_session = _require_execution_consumption_owner(
                capability_sha256=reserved_capability_sha256
            )
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
        if reserved_capability_sha256 is not None:
            consumption[_EXECUTION_CAPABILITY_KEY] = reserved_capability_sha256
        consumption["receipt_sha256"] = _receipt_sha256(consumption)
        if _is_shared_pool(scope):
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
        if execution_session is not None:
            _record_execution_consumption(
                execution_session,
                verification_receipt_sha256=str(verified["receipt_sha256"]),
                consumption_receipt_sha256=str(consumption["receipt_sha256"]),
            )
        does_not_establish = [
            "authenticated client identity",
            "application-level success of the admitted mutation",
            "absence of response loss after the admitted mutation",
            "that the admitted effect completed: admission is consumed before "
            "the effect runs, so a failed or lost effect leaves no reusable "
            "proof and requires a new handshake plus target readback",
        ]
        if _is_shared_pool(scope):
            does_not_establish.extend(
                [
                    "caller identity: shared_unlabeled remains a storage partition, "
                    "while admission is bound only to possession of the private challenge",
                    "resistance to compromised same-uid code that can read private state",
                ]
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "state_schema_version": STATE_SCHEMA_VERSION,
            "state": "consumed",
            "single_use": True,
            "pool_mode": (
                "bounded-shared-capability-pool"
                if _is_shared_pool(scope)
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
            "execution_capability_bound": reserved_capability_sha256 is not None,
            "does_not_establish": does_not_establish,
        }
