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
REPLAY_FILTER_INTEGRITY_FILENAME = "replay-filter-v1.integrity"
REPLAY_FILTER_INTEGRITY_ROOT_FILENAME = "replay-filter-v1.integrity-root"
REPLAY_FILTER_INTEGRITY_MARKER_FILENAME = "integrity-required-v1"
REPLAY_FILTER_TRANSACTION_FILENAME = "mutation-in-progress-v1"
REPLAY_FILTER_BITS = 1 << 29  # 64 MiB of monotone replay bits.
REPLAY_FILTER_HASH_COUNT = 7
REPLAY_FILTER_HEADER_BYTES = 128
REPLAY_FILTER_BYTES = REPLAY_FILTER_BITS // 8
REPLAY_FILTER_TOTAL_BYTES = REPLAY_FILTER_HEADER_BYTES + REPLAY_FILTER_BYTES
REPLAY_FILTER_HEADER = (
    b"grabowski-transport-replay-filter-v1\n"
    + f"bits={REPLAY_FILTER_BITS}\nhashes={REPLAY_FILTER_HASH_COUNT}\n".encode("ascii")
).ljust(REPLAY_FILTER_HEADER_BYTES, b"\x00")
REPLAY_FILTER_PAGE_BYTES = 4096
REPLAY_FILTER_PAGE_COUNT = REPLAY_FILTER_BYTES // REPLAY_FILTER_PAGE_BYTES
REPLAY_FILTER_INTEGRITY_DIGEST_BYTES = hashlib.sha256().digest_size
REPLAY_FILTER_INTEGRITY_HEADER_BYTES = 256
REPLAY_FILTER_INTEGRITY_HEADER = (
    b"grabowski-transport-replay-integrity-v1\n"
    + f"page_bytes={REPLAY_FILTER_PAGE_BYTES}\npage_count={REPLAY_FILTER_PAGE_COUNT}\n".encode(
        "ascii"
    )
    + b"filter_header_sha256="
    + hashlib.sha256(REPLAY_FILTER_HEADER).hexdigest().encode("ascii")
    + b"\n"
).ljust(REPLAY_FILTER_INTEGRITY_HEADER_BYTES, b"\x00")
REPLAY_FILTER_INTEGRITY_TOTAL_BYTES = (
    REPLAY_FILTER_INTEGRITY_HEADER_BYTES
    + REPLAY_FILTER_PAGE_COUNT * REPLAY_FILTER_INTEGRITY_DIGEST_BYTES
)
REPLAY_FILTER_INTEGRITY_MARKER = b"grabowski-replay-integrity-required-v1\n"
REPLAY_FILTER_INTEGRITY_ROOT_PREFIX = b"grabowski-replay-integrity-root-v1\nsha256="
REPLAY_FILTER_INTEGRITY_ROOT_BYTES = (
    len(REPLAY_FILTER_INTEGRITY_ROOT_PREFIX) + 64 + 1
)
REPLAY_FILTER_TRANSACTION_MARKER = b"grabowski-replay-mutation-in-progress-v1\n"
LEGACY_TOMBSTONE_MAX_BYTES = 4096
LEGACY_SCOPE_DIRECTORY_MAX = 4096
LEGACY_TOMBSTONE_TOTAL_MAX = 4096
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_LEGACY_TOMBSTONE_NAME_RE = re.compile(r"[0-9a-f]{32}\.json\Z")


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
        raise TransportAssertionError(
            "transport assertion value is not canonical JSON"
        ) from exc


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
        raise TransportAssertionError(
            "transport request id must be 32 lowercase hexadecimal characters"
        )
    return value


def _secret_bytes(secret: Any) -> bytes:
    if (
        not isinstance(secret, str)
        or not 16 <= len(secret.encode("ascii", errors="ignore")) <= 256
    ):
        raise TransportAssertionError("transport connector secret is invalid")
    try:
        encoded = secret.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TransportAssertionError(
            "transport connector secret must be ASCII"
        ) from exc
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
    if (
        isinstance(issued_at_unix, bool)
        or not isinstance(issued_at_unix, int)
        or issued_at_unix < 0
    ):
        raise TransportAssertionError("transport assertion timestamp is invalid")
    return {
        "version": ASSERTION_VERSION,
        "request_id": rid,
        "issued_at_unix": issued_at_unix,
        "audience": _text(audience, "transport assertion audience", 128),
        "tool_name": _text(tool_name, "transport assertion tool name", 256),
        "arguments_sha256": _sha256(
            arguments_sha256, "transport assertion arguments hash"
        ),
        "body_sha256": _sha256(body_sha256, "transport assertion body hash"),
        "runtime_binding_sha256": _sha256(
            runtime_binding_sha256, "transport assertion runtime binding hash"
        ),
    }


def validate_assertion_freshness(
    *,
    issued_at_unix: int,
    now_unix: int | None = None,
) -> int:
    """Validate the shared signed-assertion clock window without consuming it."""
    if (
        isinstance(issued_at_unix, bool)
        or not isinstance(issued_at_unix, int)
        or issued_at_unix < 0
    ):
        raise TransportAssertionError("transport assertion timestamp is invalid")
    now = int(time.time()) if now_unix is None else now_unix
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        raise TransportAssertionError(
            "transport assertion observation timestamp is invalid"
        )
    if issued_at_unix > now + ASSERTION_CLOCK_SKEW_SECONDS:
        raise TransportAssertionError(
            "transport assertion timestamp is from the future"
        )
    if now - issued_at_unix > ASSERTION_MAX_AGE_SECONDS:
        raise TransportAssertionError("transport assertion is stale")
    return now


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
    return hmac.new(
        _secret_bytes(secret), _canonical_bytes(material), hashlib.sha256
    ).hexdigest()


def _validate_private_directory(path: Path) -> None:
    meta = path.lstat()
    if (
        not stat.S_ISDIR(meta.st_mode)
        or stat.S_ISLNK(meta.st_mode)
        or meta.st_uid != os.getuid()
        or stat.S_IMODE(meta.st_mode) & 0o077
    ):
        raise TransportAssertionError("transport assertion state directory is unsafe")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISDIR(meta.st_mode):
            raise TransportAssertionError(
                "transport assertion durability target is not a directory"
            )
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_private_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while True:
        try:
            cursor.lstat()
            break
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise TransportAssertionError(
                    "transport assertion state directory has no existing ancestor"
                )
            cursor = parent
    for directory in reversed(missing):
        try:
            os.mkdir(directory, mode=0o700)
        except FileExistsError:
            pass
        _validate_private_directory(directory)
        # The child directory must survive a crash before any replay file can
        # become authoritative, so persist each newly introduced name edge.
        _fsync_directory(directory.parent)
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
    created = False
    try:
        fd = os.open(LOCK_PATH, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(LOCK_PATH, flags, 0o600)
    try:
        _validate_private_file(os.fstat(fd), "transport assertion lock")
        if created:
            os.fsync(fd)
            _fsync_directory(STATE_ROOT)
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
            raise TransportAssertionError(
                "transport assertion replay tombstone exceeds size limit"
            )
        raw = os.read(fd, LEGACY_TOMBSTONE_MAX_BYTES + 1)
        if len(raw) > LEGACY_TOMBSTONE_MAX_BYTES or os.read(fd, 1):
            raise TransportAssertionError(
                "transport assertion replay tombstone exceeds size limit"
            )
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransportAssertionError(
            "transport assertion replay tombstone is invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise TransportAssertionError(
            "transport assertion replay tombstone contract mismatch"
        )
    return value


def _legacy_tombstone_inventory(
    scope_sha256: str, request_id: str
) -> list[tuple[str, Path]]:
    current_scope = _sha256(scope_sha256, "transport client scope hash")
    request = _request_id(request_id)
    candidates = [(current_scope, _tombstone_path(current_scope, request))]
    allowed_files = {
        LOCK_PATH.name,
        REPLAY_FILTER_FILENAME,
        REPLAY_FILTER_INTEGRITY_FILENAME,
        REPLAY_FILTER_INTEGRITY_ROOT_FILENAME,
        REPLAY_FILTER_INTEGRITY_MARKER_FILENAME,
        REPLAY_FILTER_TRANSACTION_FILENAME,
    }
    entries = sorted(os.scandir(STATE_ROOT), key=lambda entry: entry.name)
    if len(entries) > LEGACY_SCOPE_DIRECTORY_MAX + len(allowed_files):
        raise TransportAssertionError(
            "transport assertion legacy replay scope inventory exceeds bound"
        )
    tombstone_count = 0
    for entry in entries:
        if entry.name in allowed_files:
            continue
        if _SHA256_RE.fullmatch(entry.name) is None:
            raise TransportAssertionError(
                "transport assertion state contains an unknown entry"
            )
        try:
            meta = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            raise TransportAssertionError(
                "transport assertion legacy replay scope drifted during lookup"
            )
        if (
            not stat.S_ISDIR(meta.st_mode)
            or stat.S_ISLNK(meta.st_mode)
            or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) & 0o077
        ):
            raise TransportAssertionError(
                "transport assertion legacy replay scope is unsafe"
            )
        tombstones = sorted(os.scandir(entry.path), key=lambda item: item.name)
        for tombstone in tombstones:
            tombstone_count += 1
            if tombstone_count > LEGACY_TOMBSTONE_TOTAL_MAX:
                raise TransportAssertionError(
                    "transport assertion legacy replay inventory exceeds bound"
                )
            if _LEGACY_TOMBSTONE_NAME_RE.fullmatch(tombstone.name) is None:
                raise TransportAssertionError(
                    "transport assertion legacy replay scope contains an unknown entry"
                )
            candidate = (entry.name, Path(tombstone.path))
            if candidate != candidates[0]:
                candidates.append(candidate)
    return candidates


def _validated_legacy_tombstone(
    value: dict[str, Any], scope_sha256: str, path: Path
) -> dict[str, str]:
    try:
        evidence = {
            "request_id": _request_id(value.get("request_id")),
            "client_scope_sha256": _sha256(
                value.get("client_scope_sha256"),
                "legacy transport client scope hash",
            ),
            "tool_name": _text(
                value.get("tool_name"), "legacy transport assertion tool name", 256
            ),
            "arguments_sha256": _sha256(
                value.get("arguments_sha256"),
                "legacy transport assertion arguments hash",
            ),
            "body_sha256": _sha256(
                value.get("body_sha256"), "legacy transport assertion body hash"
            ),
            "runtime_binding_sha256": _sha256(
                value.get("runtime_binding_sha256"),
                "legacy transport assertion runtime binding hash",
            ),
        }
    except TransportAssertionError as exc:
        raise TransportAssertionError(
            "transport assertion legacy replay tombstone contract mismatch"
        ) from exc
    if (
        evidence["client_scope_sha256"] != scope_sha256
        or path.name != f'{evidence["request_id"]}.json'
    ):
        raise TransportAssertionError(
            "transport assertion legacy replay tombstone binding mismatch"
        )
    return evidence


def _replay_filter_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_FILENAME


def _replay_filter_integrity_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_INTEGRITY_FILENAME


def _replay_filter_integrity_root_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_INTEGRITY_ROOT_FILENAME


def _replay_filter_integrity_marker_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_INTEGRITY_MARKER_FILENAME


def _replay_filter_transaction_path() -> Path:
    return STATE_ROOT / REPLAY_FILTER_TRANSACTION_FILENAME


def _replay_scope_sha256(secret: str) -> str:
    return hashlib.sha256(
        b"grabowski-one-call-replay-scope-v1\x00" + _secret_bytes(secret)
    ).hexdigest()


def _replay_filter_positions(scope_sha256: str, request_id: str) -> tuple[int, ...]:
    if REPLAY_FILTER_BITS <= 0 or REPLAY_FILTER_BITS & (REPLAY_FILTER_BITS - 1):
        raise TransportAssertionError(
            "transport replay filter size must be a power of two"
        )
    scope = bytes.fromhex(_sha256(scope_sha256, "transport client scope hash"))
    request = bytes.fromhex(_request_id(request_id))
    digest = hashlib.sha512(
        b"grabowski-replay-filter-v1\x00" + scope + request
    ).digest()
    start = int.from_bytes(digest[:8], "big")
    step = int.from_bytes(digest[8:16], "big") | 1
    mask = REPLAY_FILTER_BITS - 1
    return tuple(
        (start + index * step) & mask for index in range(REPLAY_FILTER_HASH_COUNT)
    )


def _stable_scope_replay_id(body_sha256: str) -> str:
    body = bytes.fromhex(_sha256(body_sha256, "transport assertion body hash"))
    return hashlib.sha256(
        b"grabowski-stable-client-scope-body-replay-id-v1\x00" + body
    ).hexdigest()[:32]


def _pread_exact(fd: int, size: int, offset: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    cursor = offset
    while remaining:
        chunk = os.pread(fd, remaining, cursor)
        if not chunk:
            raise TransportAssertionError(f"{label} read was short")
        chunks.append(chunk)
        remaining -= len(chunk)
        cursor += len(chunk)
    return b"".join(chunks)


def _pwrite_exact(fd: int, value: bytes, offset: int, label: str) -> None:
    view = memoryview(value)
    cursor = offset
    while view:
        written = os.pwrite(fd, view, cursor)
        if written <= 0:
            raise TransportAssertionError(f"{label} write was short")
        view = view[written:]
        cursor += written


def _replay_page_digest(page_index: int, value: bytes) -> bytes:
    if len(value) != REPLAY_FILTER_PAGE_BYTES:
        raise TransportAssertionError("transport replay filter page size mismatch")
    return hashlib.sha256(
        b"grabowski-replay-filter-page-v1\x00"
        + page_index.to_bytes(8, "big")
        + REPLAY_FILTER_HEADER
        + value
    ).digest()


def _replay_page_offset(page_index: int) -> int:
    return REPLAY_FILTER_HEADER_BYTES + page_index * REPLAY_FILTER_PAGE_BYTES


def _integrity_digest_offset(page_index: int) -> int:
    return (
        REPLAY_FILTER_INTEGRITY_HEADER_BYTES
        + page_index * REPLAY_FILTER_INTEGRITY_DIGEST_BYTES
    )


def _read_replay_page(filter_fd: int, page_index: int) -> bytes:
    return _pread_exact(
        filter_fd,
        REPLAY_FILTER_PAGE_BYTES,
        _replay_page_offset(page_index),
        "transport replay filter page",
    )


def _validate_replay_page(
    filter_fd: int, integrity_fd: int, page_index: int
) -> bytes:
    page = _read_replay_page(filter_fd, page_index)
    observed = _pread_exact(
        integrity_fd,
        REPLAY_FILTER_INTEGRITY_DIGEST_BYTES,
        _integrity_digest_offset(page_index),
        "transport replay integrity digest",
    )
    expected = _replay_page_digest(page_index, page)
    if not hmac.compare_digest(observed, expected):
        raise TransportAssertionError(
            "transport assertion replay filter integrity mismatch; state is fail-closed"
        )
    return page


def _validate_all_replay_pages(filter_fd: int, integrity_fd: int) -> None:
    for page_index in range(REPLAY_FILTER_PAGE_COUNT):
        _validate_replay_page(filter_fd, integrity_fd, page_index)


def _initialize_replay_integrity(filter_fd: int, path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(
        os, "O_NOFOLLOW", 0
    )
    integrity_fd = os.open(path, flags, 0o600)
    try:
        _validate_private_file(
            os.fstat(integrity_fd), "transport assertion replay integrity"
        )
        digests = bytearray()
        for page_index in range(REPLAY_FILTER_PAGE_COUNT):
            digests.extend(
                _replay_page_digest(page_index, _read_replay_page(filter_fd, page_index))
            )
        os.ftruncate(integrity_fd, REPLAY_FILTER_INTEGRITY_TOTAL_BYTES)
        _pwrite_exact(
            integrity_fd,
            REPLAY_FILTER_INTEGRITY_HEADER + bytes(digests),
            0,
            "transport replay integrity initialization",
        )
        os.fsync(integrity_fd)
        return integrity_fd
    except BaseException:
        os.close(integrity_fd)
        raise


def _open_existing_replay_integrity(path: Path) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        _validate_private_file(meta, "transport assertion replay integrity")
        if meta.st_size != REPLAY_FILTER_INTEGRITY_TOTAL_BYTES:
            raise TransportAssertionError(
                "transport assertion replay integrity size mismatch"
            )
        header = _pread_exact(
            fd,
            REPLAY_FILTER_INTEGRITY_HEADER_BYTES,
            0,
            "transport replay integrity header",
        )
        if header != REPLAY_FILTER_INTEGRITY_HEADER:
            raise TransportAssertionError(
                "transport assertion replay integrity header mismatch"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _replay_integrity_root_value(integrity_fd: int) -> bytes:
    image = _pread_exact(
        integrity_fd,
        REPLAY_FILTER_INTEGRITY_TOTAL_BYTES,
        0,
        "transport replay integrity image",
    )
    digest = hashlib.sha256(
        b"grabowski-replay-integrity-root-v1\x00" + image
    ).hexdigest()
    return REPLAY_FILTER_INTEGRITY_ROOT_PREFIX + digest.encode("ascii") + b"\n"


def _initialize_replay_integrity_root(integrity_fd: int, path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(
        os, "O_NOFOLLOW", 0
    )
    root_fd = os.open(path, flags, 0o600)
    try:
        _validate_private_file(
            os.fstat(root_fd), "transport assertion replay integrity root"
        )
        value = _replay_integrity_root_value(integrity_fd)
        _pwrite_exact(
            root_fd,
            value,
            0,
            "transport replay integrity root initialization",
        )
        os.ftruncate(root_fd, len(value))
        os.fsync(root_fd)
        return root_fd
    except BaseException:
        os.close(root_fd)
        raise


def _open_existing_replay_integrity_root(path: Path, integrity_fd: int) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(path, flags)
    try:
        meta = os.fstat(root_fd)
        _validate_private_file(meta, "transport assertion replay integrity root")
        if meta.st_size != REPLAY_FILTER_INTEGRITY_ROOT_BYTES:
            raise TransportAssertionError(
                "transport assertion replay integrity root size mismatch"
            )
        observed = _pread_exact(
            root_fd,
            REPLAY_FILTER_INTEGRITY_ROOT_BYTES,
            0,
            "transport replay integrity root",
        )
        expected = _replay_integrity_root_value(integrity_fd)
        if not hmac.compare_digest(observed, expected):
            raise TransportAssertionError(
                "transport assertion replay integrity root mismatch; state is fail-closed"
            )
        return root_fd
    except BaseException:
        os.close(root_fd)
        raise


def _refresh_replay_integrity_root(integrity_fd: int, root_fd: int) -> None:
    value = _replay_integrity_root_value(integrity_fd)
    _pwrite_exact(
        root_fd,
        value,
        0,
        "transport replay integrity root",
    )
    os.ftruncate(root_fd, len(value))
    os.fsync(root_fd)


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _install_integrity_marker() -> None:
    path = _replay_filter_integrity_marker_path()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(
        os, "O_NOFOLLOW", 0
    )
    fd = os.open(path, flags, 0o600)
    try:
        _validate_private_file(
            os.fstat(fd), "transport assertion replay integrity marker"
        )
        _pwrite_exact(
            fd,
            REPLAY_FILTER_INTEGRITY_MARKER,
            0,
            "transport replay integrity marker",
        )
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(STATE_ROOT)


def _require_integrity_marker() -> None:
    path = _replay_filter_integrity_marker_path()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        _validate_private_file(
            meta, "transport assertion replay integrity marker"
        )
        if meta.st_size != len(REPLAY_FILTER_INTEGRITY_MARKER):
            raise TransportAssertionError(
                "transport assertion replay integrity marker size mismatch"
            )
        value = _pread_exact(
            fd,
            len(REPLAY_FILTER_INTEGRITY_MARKER),
            0,
            "transport replay integrity marker",
        )
        if value != REPLAY_FILTER_INTEGRITY_MARKER:
            raise TransportAssertionError(
                "transport assertion replay integrity marker mismatch"
            )
    finally:
        os.close(fd)


def _install_replay_transaction_marker() -> None:
    path = _replay_filter_transaction_path()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(
        os, "O_NOFOLLOW", 0
    )
    fd = os.open(path, flags, 0o600)
    try:
        _validate_private_file(
            os.fstat(fd), "transport assertion replay transaction marker"
        )
        _pwrite_exact(
            fd,
            REPLAY_FILTER_TRANSACTION_MARKER,
            0,
            "transport replay transaction marker",
        )
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(STATE_ROOT)


def _require_replay_transaction_marker() -> None:
    path = _replay_filter_transaction_path()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        _validate_private_file(
            meta, "transport assertion replay transaction marker"
        )
        if meta.st_size != len(REPLAY_FILTER_TRANSACTION_MARKER):
            raise TransportAssertionError(
                "transport assertion replay transaction marker size mismatch"
            )
        value = _pread_exact(
            fd,
            len(REPLAY_FILTER_TRANSACTION_MARKER),
            0,
            "transport replay transaction marker",
        )
        if value != REPLAY_FILTER_TRANSACTION_MARKER:
            raise TransportAssertionError(
                "transport assertion replay transaction marker mismatch"
            )
    finally:
        os.close(fd)


def _clear_replay_transaction_marker() -> None:
    path = _replay_filter_transaction_path()
    _require_replay_transaction_marker()
    path.unlink()
    _fsync_directory(STATE_ROOT)


def _open_replay_filter() -> tuple[int, int, int]:
    path = _replay_filter_path()
    integrity_path = _replay_filter_integrity_path()
    integrity_root_path = _replay_filter_integrity_root_path()
    marker_path = _replay_filter_integrity_marker_path()
    transaction_path = _replay_filter_transaction_path()
    if _path_entry_exists(transaction_path):
        _require_replay_transaction_marker()
        raise TransportAssertionError(
            "transport assertion replay mutation was interrupted; state is fail-closed"
        )
    base_flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    created = False
    integrity_fd = -1
    integrity_root_fd = -1
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
            _pwrite_exact(
                fd,
                REPLAY_FILTER_HEADER,
                0,
                "transport replay filter header",
            )
            os.fsync(fd)
        else:
            if meta.st_size != REPLAY_FILTER_TOTAL_BYTES:
                raise TransportAssertionError(
                    "transport assertion replay filter size mismatch"
                )
            header = os.pread(fd, REPLAY_FILTER_HEADER_BYTES, 0)
            if header != REPLAY_FILTER_HEADER:
                raise TransportAssertionError(
                    "transport assertion replay filter header mismatch"
                )
        integrity_exists = _path_entry_exists(integrity_path)
        integrity_root_exists = _path_entry_exists(integrity_root_path)
        marker_exists = _path_entry_exists(marker_path)
        if created:
            if integrity_exists or integrity_root_exists or marker_exists:
                raise TransportAssertionError(
                    "transport assertion replay integrity has an orphaned entry"
                )
            integrity_fd = _initialize_replay_integrity(fd, integrity_path)
            integrity_root_fd = _initialize_replay_integrity_root(
                integrity_fd, integrity_root_path
            )
            _install_integrity_marker()
        elif marker_exists:
            _require_integrity_marker()
            if not integrity_exists or not integrity_root_exists:
                raise TransportAssertionError(
                    "transport assertion replay integrity is required but missing"
                )
            integrity_fd = _open_existing_replay_integrity(integrity_path)
            integrity_root_fd = _open_existing_replay_integrity_root(
                integrity_root_path, integrity_fd
            )
        else:
            # One-time upgrade of the prior replay-filter-v1 format. The
            # current durable image becomes the migration baseline; after the
            # marker is installed, missing or corrupt metadata is never rebuilt.
            if integrity_exists:
                integrity_fd = _open_existing_replay_integrity(integrity_path)
                _validate_all_replay_pages(fd, integrity_fd)
            else:
                if integrity_root_exists:
                    raise TransportAssertionError(
                        "transport assertion replay integrity root is orphaned"
                    )
                integrity_fd = _initialize_replay_integrity(fd, integrity_path)
            if integrity_root_exists:
                integrity_root_fd = _open_existing_replay_integrity_root(
                    integrity_root_path, integrity_fd
                )
            else:
                integrity_root_fd = _initialize_replay_integrity_root(
                    integrity_fd, integrity_root_path
                )
            _install_integrity_marker()
        _fsync_directory(STATE_ROOT)
        return fd, integrity_fd, integrity_root_fd
    except BaseException:
        if integrity_root_fd >= 0:
            os.close(integrity_root_fd)
        if integrity_fd >= 0:
            os.close(integrity_fd)
        os.close(fd)
        raise


def _consume_replay_filter(
    scope_replay_ids: tuple[tuple[str, str], ...],
) -> None:
    masks_by_scope: list[dict[tuple[int, int], int]] = []
    all_masks: dict[tuple[int, int], int] = {}
    for scope_sha256, replay_id in dict.fromkeys(scope_replay_ids):
        scope_masks: dict[tuple[int, int], int] = {}
        for bit in _replay_filter_positions(scope_sha256, replay_id):
            byte_index = bit // 8
            page_index = byte_index // REPLAY_FILTER_PAGE_BYTES
            page_byte_index = byte_index % REPLAY_FILTER_PAGE_BYTES
            key = (page_index, page_byte_index)
            mask = 1 << (bit % 8)
            scope_masks[key] = scope_masks.get(key, 0) | mask
            all_masks[key] = all_masks.get(key, 0) | mask
        masks_by_scope.append(scope_masks)

    fd, integrity_fd, integrity_root_fd = _open_replay_filter()
    try:
        pages = {
            page_index: bytearray(
                _validate_replay_page(fd, integrity_fd, page_index)
            )
            for page_index in sorted({key[0] for key in all_masks})
        }
        for scope_masks in masks_by_scope:
            if all(
                pages[page_index][page_byte_index] & mask == mask
                for (page_index, page_byte_index), mask in scope_masks.items()
            ):
                raise TransportAssertionReplay(
                    "signed one-call transport request was already consumed or conservatively rejected by the durable replay filter; do not repeat the mutation; reconcile target state"
                )

        changed_pages: set[int] = set()
        for (page_index, page_byte_index), mask in all_masks.items():
            before = pages[page_index][page_byte_index]
            after = before | mask
            if after != before:
                pages[page_index][page_byte_index] = after
                changed_pages.add(page_index)
        _install_replay_transaction_marker()
        for page_index in sorted(changed_pages):
            _pwrite_exact(
                fd,
                bytes(pages[page_index]),
                _replay_page_offset(page_index),
                "transport replay filter page",
            )
        # Data is durable before its integrity record. A crash in the following
        # window yields a digest mismatch and therefore fails closed.
        os.fsync(fd)
        for page_index in sorted(changed_pages):
            _pwrite_exact(
                integrity_fd,
                _replay_page_digest(page_index, bytes(pages[page_index])),
                _integrity_digest_offset(page_index),
                "transport replay integrity digest",
            )
        # Mutation is admitted only after both replay bits and their bound
        # integrity metadata are durable. The global root makes corruption in
        # any digest record visible before an unrelated later request can run.
        os.fsync(integrity_fd)
        _refresh_replay_integrity_root(integrity_fd, integrity_root_fd)
        _clear_replay_transaction_marker()
    finally:
        try:
            os.close(integrity_root_fd)
        finally:
            try:
                os.close(integrity_fd)
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
    legacy_replay_scope_hash = _replay_scope_sha256(secret)
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
    now = validate_assertion_freshness(
        issued_at_unix=issued_at_unix,
        now_unix=now_unix,
    )
    supplied_mac = _sha256(mac_sha256, "transport assertion MAC")
    expected_mac = hmac.new(
        _secret_bytes(secret), _canonical_bytes(material), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise TransportAssertionError("transport assertion MAC mismatch")
    if not hmac.compare_digest(asserted_runtime_hash, runtime_hash):
        raise TransportAssertionError("transport assertion runtime binding mismatch")

    with _state_lock():
        for legacy_scope_hash, legacy_path in _legacy_tombstone_inventory(
            scope_hash, material["request_id"]
        ):
            existing = _read_tombstone(legacy_path)
            if existing is None:
                continue
            legacy = _validated_legacy_tombstone(
                existing, legacy_scope_hash, legacy_path
            )
            same_target = (
                legacy["tool_name"] == material["tool_name"]
                and legacy["arguments_sha256"] == material["arguments_sha256"]
                and legacy["body_sha256"] == material["body_sha256"]
                and legacy["runtime_binding_sha256"]
                == material["runtime_binding_sha256"]
            )
            if legacy["request_id"] == material["request_id"] and not same_target:
                raise TransportAssertionError(
                    "transport request id was reused for different evidence"
                )
            if legacy["body_sha256"] == material["body_sha256"]:
                if not same_target:
                    raise TransportAssertionError(
                        "transport request body was rebound to different legacy evidence"
                    )
                # Legacy receipts predate stable connector identities, so token
                # rotation cannot be linked back to one connector scope. Exact
                # body-and-target evidence is conservatively authoritative
                # across the bounded legacy inventory.
                raise TransportAssertionReplay(
                    "signed one-call transport request was already consumed; do not repeat the mutation; reconcile target state"
                )
        _consume_replay_filter(
            (
                (legacy_replay_scope_hash, material["request_id"]),
                (
                    scope_hash,
                    _stable_scope_replay_id(material["body_sha256"]),
                ),
            )
        )

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
