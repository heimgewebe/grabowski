#!/usr/bin/env python3

from __future__ import annotations

import argparse
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
from typing import Any
from urllib.parse import urlsplit

import grabowski_transport_assertion as assertion


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18180
DEFAULT_UPSTREAM = "http://127.0.0.1:18181/mcp"
GREEN_UPSTREAM = "http://127.0.0.1:18182/mcp"
ROUTING_SLOTS = {
    "canonical": 18181,
    "green": 18182,
}
DEFAULT_TOKEN_FILE = (
    Path.home() / ".local/state/grabowski/transport-connectors/primary.token"
)
DEFAULT_SELECTOR_FILE = (
    Path.home()
    / ".local/state/grabowski/transport-connectors/operator-routing-selector.json"
)
DEFAULT_DEPLOYMENT_MANIFEST = (
    Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"
)
DEPLOYMENT_RELEASE_ROOT = Path.home() / ".local/share/grabowski-mcp-releases"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SELECTOR_BYTES = 16 * 1024
ROUTING_SELECTOR_KIND = "grabowski_transport_ingress_routing_selector"
ROUTING_SELECTOR_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "generation",
        "selected_slot",
        "upstream_port",
        "runtime_binding",
        "runtime_binding_sha256",
        "cutover_id",
        "previous_selector_sha256",
        "updated_at_unix",
        "selector_sha256",
    }
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
MANAGED_HEADER_PREFIX = "x-grabowski-"
CAPABILITY_HEADER = "X-Grabowski-Connector-Capability"
INGRESS_AUTH_HEADER = "X-Grabowski-Ingress-Auth"
INGRESS_VERSION_HEADER = "X-Grabowski-Ingress-Version"
REQUEST_ID_HEADER = "X-Grabowski-Request-Id"
REQUEST_TIMESTAMP_HEADER = "X-Grabowski-Request-Timestamp"
REQUEST_AUDIENCE_HEADER = "X-Grabowski-Request-Audience"
REQUEST_BODY_SHA256_HEADER = "X-Grabowski-Request-Body-Sha256"
RUNTIME_BINDING_SHA256_HEADER = "X-Grabowski-Runtime-Binding-Sha256"
REQUEST_MAC_HEADER = "X-Grabowski-Request-Mac"
OAUTH_PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
OAUTH_PROTECTED_RESOURCE_MCP_PATH = "/.well-known/oauth-protected-resource/mcp"


class IngressConfigurationError(RuntimeError):
    pass


class RequestBodyTooLarge(ValueError):
    pass


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _validate_private_parent(path: Path, *, create: bool) -> Path:
    parent = path.parent
    if create:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        linked = parent.lstat()
    except OSError as exc:
        raise IngressConfigurationError(
            "routing selector directory is unavailable"
        ) from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or linked.st_uid != os.getuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
    ):
        raise IngressConfigurationError(
            "routing selector directory must be private and owner-controlled"
        )
    resolved = parent.resolve(strict=True)
    if resolved != parent:
        raise IngressConfigurationError(
            "routing selector directory must be an exact real path"
        )
    return resolved


def _read_private_selector_bytes(path: Path) -> bytes:
    _validate_private_parent(path, create=False)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise IngressConfigurationError("routing selector is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > MAX_SELECTOR_BYTES
        ):
            raise IngressConfigurationError(
                "routing selector must be one private owner-controlled regular file"
            )
        raw = os.read(descriptor, MAX_SELECTOR_BYTES + 1)
        after = os.fstat(descriptor)
        if len(raw) > MAX_SELECTOR_BYTES or os.read(descriptor, 1):
            raise IngressConfigurationError("routing selector exceeds size bound")
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
            raise IngressConfigurationError(
                "routing selector changed while being read"
            )
        return raw
    finally:
        os.close(descriptor)


def _validate_runtime_binding(value: Any) -> tuple[dict[str, str], str]:
    if not isinstance(value, dict) or set(value) != {
        "release_id",
        "repo_head",
        "registered_names_sha256",
        "agent_instructions_sha256",
    }:
        raise IngressConfigurationError("routing runtime binding shape is invalid")
    release_id = value.get("release_id")
    if (
        not isinstance(release_id, str)
        or not release_id
        or release_id.strip() != release_id
        or len(release_id.encode("utf-8")) > 512
    ):
        raise IngressConfigurationError("routing release id is invalid")
    for name in (
        "registered_names_sha256",
        "agent_instructions_sha256",
    ):
        if not isinstance(value.get(name), str) or SHA256_RE.fullmatch(value[name]) is None:
            raise IngressConfigurationError(f"routing {name} is invalid")
    repo_head = value.get("repo_head")
    if not isinstance(repo_head, str) or HEAD_RE.fullmatch(repo_head) is None:
        raise IngressConfigurationError("routing repository head is invalid")
    normalized = {
        "release_id": release_id,
        "repo_head": repo_head,
        "registered_names_sha256": value["registered_names_sha256"],
        "agent_instructions_sha256": value["agent_instructions_sha256"],
    }
    return normalized, assertion.runtime_binding_sha256(normalized)


def _validate_routing_selector(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ROUTING_SELECTOR_KEYS:
        raise IngressConfigurationError("routing selector shape is invalid")
    if value.get("schema_version") != 1 or value.get("kind") != ROUTING_SELECTOR_KIND:
        raise IngressConfigurationError("routing selector contract is invalid")
    generation = value.get("generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise IngressConfigurationError("routing selector generation is invalid")
    slot = value.get("selected_slot")
    if slot not in ROUTING_SLOTS or value.get("upstream_port") != ROUTING_SLOTS[slot]:
        raise IngressConfigurationError("routing selector target is not allowed")
    binding, binding_sha256 = _validate_runtime_binding(value.get("runtime_binding"))
    if value.get("runtime_binding_sha256") != binding_sha256:
        raise IngressConfigurationError("routing runtime binding hash mismatch")
    cutover_id = value.get("cutover_id")
    if (
        not isinstance(cutover_id, str)
        or re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", cutover_id) is None
    ):
        raise IngressConfigurationError("routing selector cutover id is invalid")
    previous = value.get("previous_selector_sha256")
    if previous is not None and (
        not isinstance(previous, str) or SHA256_RE.fullmatch(previous) is None
    ):
        raise IngressConfigurationError("routing selector predecessor hash is invalid")
    updated = value.get("updated_at_unix")
    if isinstance(updated, bool) or not isinstance(updated, int) or updated < 0:
        raise IngressConfigurationError("routing selector timestamp is invalid")
    declared = value.get("selector_sha256")
    if not isinstance(declared, str) or SHA256_RE.fullmatch(declared) is None:
        raise IngressConfigurationError("routing selector hash is invalid")
    unsigned = dict(value)
    unsigned.pop("selector_sha256")
    if _sha256_json(unsigned) != declared:
        raise IngressConfigurationError("routing selector hash mismatch")
    return {
        **value,
        "runtime_binding": binding,
        "upstream": f"http://127.0.0.1:{ROUTING_SLOTS[slot]}/mcp",
    }


def read_routing_selector(path: Path = DEFAULT_SELECTOR_FILE) -> dict[str, Any]:
    try:
        value = json.loads(_read_private_selector_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IngressConfigurationError("routing selector is invalid JSON") from exc
    return _validate_routing_selector(value)


@contextmanager
def _selector_lock(path: Path):
    _validate_private_parent(path, create=True)
    lock_path = path.parent / f".{path.name}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise IngressConfigurationError("routing selector lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def publish_routing_selector(
    *,
    path: Path = DEFAULT_SELECTOR_FILE,
    expected_selector_sha256: str | None,
    selected_slot: str,
    runtime_binding: dict[str, str],
    cutover_id: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    """CAS-publish one of the two fixed operator routes and verify readback."""
    if selected_slot not in ROUTING_SLOTS:
        raise IngressConfigurationError("routing selector target is not allowed")
    binding, binding_sha256 = _validate_runtime_binding(runtime_binding)
    if re.fullmatch(r"[A-Za-z0-9._:@-]{1,128}", cutover_id or "") is None:
        raise IngressConfigurationError("routing selector cutover id is invalid")
    timestamp = int(time.time()) if now_unix is None else now_unix
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise IngressConfigurationError("routing selector timestamp is invalid")
    with _selector_lock(path):
        current: dict[str, Any] | None
        try:
            current = read_routing_selector(path)
        except IngressConfigurationError as exc:
            if path.exists() or path.is_symlink():
                raise
            current = None
        observed_sha = current.get("selector_sha256") if current is not None else None
        if observed_sha != expected_selector_sha256:
            raise IngressConfigurationError("routing selector CAS precondition failed")
        material = {
            "schema_version": 1,
            "kind": ROUTING_SELECTOR_KIND,
            "generation": 1 if current is None else current["generation"] + 1,
            "selected_slot": selected_slot,
            "upstream_port": ROUTING_SLOTS[selected_slot],
            "runtime_binding": binding,
            "runtime_binding_sha256": binding_sha256,
            "cutover_id": cutover_id,
            "previous_selector_sha256": observed_sha,
            "updated_at_unix": timestamp,
        }
        payload = {**material, "selector_sha256": _sha256_json(material)}
        encoded = _canonical_json_bytes(payload) + b"\n"
        if len(encoded) > MAX_SELECTOR_BYTES:
            raise IngressConfigurationError("routing selector exceeds size bound")
        temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("routing selector write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            parent_descriptor = os.open(
                path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        observed = read_routing_selector(path)
        if observed.get("selector_sha256") != payload["selector_sha256"]:
            raise IngressConfigurationError("routing selector readback mismatch")
        return observed


def _read_private_token(path: Path) -> str:
    try:
        linked = os.lstat(path)
    except FileNotFoundError as exc:
        raise IngressConfigurationError(
            "transport connector token file is missing"
        ) from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
        or linked.st_nlink != 1
        or linked.st_size > 256
    ):
        raise IngressConfigurationError("transport connector token file is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_nlink != linked.st_nlink
        ):
            raise IngressConfigurationError(
                "transport connector token changed during open"
            )
        raw = os.read(fd, 257)
        if len(raw) > 256 or os.read(fd, 1):
            raise IngressConfigurationError(
                "transport connector token exceeds size bound"
            )
    finally:
        os.close(fd)
    try:
        token = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise IngressConfigurationError(
            "transport connector token must be ASCII"
        ) from exc
    if token.endswith("\n"):
        token = token[:-1]
    if TOKEN_RE.fullmatch(token) is None:
        raise IngressConfigurationError("transport connector token is invalid")
    return token


def _read_runtime_binding(path: Path) -> tuple[dict[str, str], str]:
    try:
        release_root = DEPLOYMENT_RELEASE_ROOT.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise IngressConfigurationError("deployment manifest is unavailable") from exc
    if resolved == release_root or not resolved.is_relative_to(release_root):
        raise IngressConfigurationError(
            "deployment manifest is outside the immutable release root"
        )
    linked = resolved.lstat()
    if (
        not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or stat.S_IMODE(linked.st_mode) & 0o022
        or linked.st_nlink != 1
        or linked.st_size > MAX_MANIFEST_BYTES
    ):
        raise IngressConfigurationError("deployment manifest is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(resolved, flags)
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_nlink != linked.st_nlink
        ):
            raise IngressConfigurationError("deployment manifest changed during open")
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES or os.read(fd, 1):
            raise IngressConfigurationError("deployment manifest exceeds size bound")
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IngressConfigurationError("deployment manifest is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("completion_status") != "complete":
        raise IngressConfigurationError("deployment manifest is incomplete")
    release_id = value.get("release_id")
    repo_head = value.get("repo_head")
    instructions = value.get("agent_instructions")
    entrypoint = value.get("entrypoint_contract")
    expected_tools = (
        entrypoint.get("expected_tools") if isinstance(entrypoint, dict) else None
    )
    if (
        not isinstance(release_id, str)
        or not release_id
        or resolved.parent.name != release_id
        or not isinstance(repo_head, str)
        or HEAD_RE.fullmatch(repo_head) is None
        or not isinstance(instructions, dict)
        or not isinstance(instructions.get("sha256"), str)
        or SHA256_RE.fullmatch(instructions["sha256"]) is None
        or not isinstance(expected_tools, list)
        or not expected_tools
        or not all(isinstance(item, str) and item for item in expected_tools)
        or len(set(expected_tools)) != len(expected_tools)
    ):
        raise IngressConfigurationError(
            "deployment manifest runtime binding is invalid"
        )
    registered_names_sha256 = hashlib.sha256(
        json.dumps(
            sorted(expected_tools),
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    binding = {
        "release_id": release_id,
        "repo_head": repo_head,
        "registered_names_sha256": registered_names_sha256,
        "agent_instructions_sha256": instructions["sha256"],
    }
    return binding, assertion.runtime_binding_sha256(binding)


def _validate_upstream(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise IngressConfigurationError("upstream URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port not in set(ROUTING_SLOTS.values())
        or parsed.path.rstrip("/") != "/mcp"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise IngressConfigurationError(
            "upstream must be one of the two bound loopback Grabowski operators"
        )
    return value.rstrip("/")


def _forward_headers(request: Any, token: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in request.headers.items():
        lowered = name.lower()
        if (
            lowered in HOP_BY_HOP_HEADERS
            or lowered in {"host", "content-length"}
            or lowered.startswith(MANAGED_HEADER_PREFIX)
        ):
            continue
        result[name] = value
    result[CAPABILITY_HEADER] = token
    result[INGRESS_VERSION_HEADER] = assertion.ASSERTION_VERSION
    return result


def _response_headers(response: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in response.headers.items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP_HEADERS or lowered == "content-length":
            continue
        result[name] = value
    return result


def _ingress_client_authenticated(headers: Any, token: str) -> bool:
    supplied = headers.get(INGRESS_AUTH_HEADER)
    return isinstance(supplied, str) and hmac.compare_digest(supplied, token)


def _rpc_request_id(payload: dict[str, Any]) -> str:
    if "id" not in payload or payload["id"] is None:
        raise ValueError("tools/call requires a JSON-RPC request id")
    try:
        encoded = json.dumps(
            payload["id"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("JSON-RPC request id is not canonical JSON") from exc
    if not encoded or len(encoded.encode("utf-8")) > 512:
        raise ValueError("JSON-RPC request id is too large")
    return encoded


def signed_tool_headers(
    *,
    token: str,
    body: bytes,
    session_id: str,
    runtime_binding_sha256: str,
    now_unix: int | None = None,
) -> dict[str, str]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return {}
    params = payload.get("params")
    if not isinstance(params, dict):
        raise ValueError("tools/call params must be an object")
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    if (
        not isinstance(tool_name, str)
        or not tool_name
        or len(tool_name.encode("utf-8")) > 256
    ):
        raise ValueError("tools/call name is invalid")
    if not isinstance(arguments, dict):
        raise ValueError("tools/call arguments must be an object")
    rpc_id = _rpc_request_id(payload)
    body_sha256 = hashlib.sha256(body).hexdigest()
    arguments_sha256 = assertion.canonical_arguments_sha256(arguments)
    request_id = assertion.derive_request_id(
        secret=token,
        session_id=session_id,
        rpc_request_id=rpc_id,
        body_sha256=body_sha256,
    )
    issued_at = int(time.time()) if now_unix is None else now_unix
    mac = assertion.assertion_mac(
        secret=token,
        request_id=request_id,
        issued_at_unix=issued_at,
        audience=assertion.ASSERTION_AUDIENCE,
        tool_name=tool_name,
        arguments_sha256=arguments_sha256,
        body_sha256=body_sha256,
        runtime_binding_sha256=runtime_binding_sha256,
    )
    return {
        REQUEST_ID_HEADER: request_id,
        REQUEST_TIMESTAMP_HEADER: str(issued_at),
        REQUEST_AUDIENCE_HEADER: assertion.ASSERTION_AUDIENCE,
        REQUEST_BODY_SHA256_HEADER: body_sha256,
        RUNTIME_BINDING_SHA256_HEADER: runtime_binding_sha256,
        REQUEST_MAC_HEADER: mac,
    }


async def _read_bounded_request_body(request: Any) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not isinstance(chunk, bytes):
            raise ValueError("request body stream yielded a non-byte chunk")
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise RequestBodyTooLarge("request body exceeds the size bound")
        chunks.append(chunk)
    return b"".join(chunks)


def _oauth_protected_resource_metadata(base_url: object) -> dict[str, object]:
    return {
        "resource": f"{str(base_url).rstrip('/')}/mcp",
        "resource_name": "Grabowski MCP",
        "authorization_servers": [],
        "bearer_methods_supported": [],
    }


class TransportIngress:
    def __init__(
        self,
        *,
        token: str,
        selector_file: Path | None = None,
        upstream: str | None = None,
        runtime_binding_sha256: str | None = None,
    ) -> None:
        self._token = token
        self._selector_file = selector_file
        self._static_route: dict[str, Any] | None = None
        if selector_file is not None:
            if upstream is not None or runtime_binding_sha256 is not None:
                raise IngressConfigurationError(
                    "selector routing cannot be combined with a static upstream"
                )
            read_routing_selector(selector_file)
        else:
            if upstream is None or runtime_binding_sha256 is None:
                raise IngressConfigurationError(
                    "explicit static routing requires upstream and runtime binding"
                )
            if SHA256_RE.fullmatch(runtime_binding_sha256) is None:
                raise IngressConfigurationError("runtime binding digest is invalid")
            validated = _validate_upstream(upstream)
            self._static_route = {
                "upstream": validated,
                "upstream_port": urlsplit(validated).port,
                "runtime_binding_sha256": runtime_binding_sha256,
                "selected_slot": "static-test-only",
                "selector_sha256": None,
                "generation": None,
                "runtime_binding": {},
            }

    def _route(self) -> dict[str, Any]:
        if self._selector_file is not None:
            return read_routing_selector(self._selector_file)
        assert self._static_route is not None
        return dict(self._static_route)

    async def health(self, request: Any) -> Any:
        from starlette.responses import JSONResponse

        try:
            route = self._route()
        except IngressConfigurationError as exc:
            return JSONResponse(
                {
                    "schema_version": 2,
                    "service": "grabowski-transport-ingress",
                    "healthy": False,
                    "selector_authoritative": self._selector_file is not None,
                    "error": type(exc).__name__,
                },
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(
            {
                "schema_version": 2,
                "service": "grabowski-transport-ingress",
                "healthy": True,
                "assertion_version": assertion.ASSERTION_VERSION,
                "runtime_binding_sha256": route["runtime_binding_sha256"],
                "release_id": route.get("runtime_binding", {}).get("release_id"),
                "repo_head": route.get("runtime_binding", {}).get("repo_head"),
                "upstream": "loopback-operator",
                "upstream_port": route["upstream_port"],
                "selected_slot": route["selected_slot"],
                "selector_authoritative": self._selector_file is not None,
                "selector_sha256": route["selector_sha256"],
                "selector_generation": route["generation"],
            },
            headers={"Cache-Control": "no-store"},
        )

    async def oauth_resource(self, request: Any) -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse(
            _oauth_protected_resource_metadata(request.base_url),
            headers={"Cache-Control": "no-store"},
        )

    async def proxy(self, request: Any) -> Any:
        import httpx
        from starlette.background import BackgroundTask
        from starlette.responses import JSONResponse, StreamingResponse

        if not _ingress_client_authenticated(request.headers, self._token):
            return JSONResponse(
                {"error": "unauthorized_ingress_client"}, status_code=401
            )
        try:
            route = self._route()
        except IngressConfigurationError:
            return JSONResponse(
                {"error": "routing_selector_unavailable"}, status_code=503
            )
        declared_length: int | None = None
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length, 10)
            except ValueError:
                return JSONResponse(
                    {"error": "invalid_content_length"}, status_code=400
                )
            if declared_length < 0:
                return JSONResponse(
                    {"error": "invalid_content_length"}, status_code=400
                )
            if declared_length > MAX_REQUEST_BYTES:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        try:
            body = await _read_bounded_request_body(request)
        except RequestBodyTooLarge:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        except (TypeError, ValueError):
            return JSONResponse({"error": "invalid_request_body"}, status_code=400)
        if declared_length is not None and len(body) != declared_length:
            return JSONResponse({"error": "content_length_mismatch"}, status_code=400)
        headers = _forward_headers(request, self._token)
        try:
            headers.update(
                signed_tool_headers(
                    token=self._token,
                    body=body,
                    session_id=request.headers.get("mcp-session-id", ""),
                    runtime_binding_sha256=route["runtime_binding_sha256"],
                )
            )
        except (ValueError, assertion.TransportAssertionError) as exc:
            return JSONResponse(
                {"error": "invalid_mcp_request", "detail": str(exc)},
                status_code=400,
            )
        query = request.url.query
        url = route["upstream"] + (f"?{query}" if query else "")
        client = httpx.AsyncClient(
            timeout=None, follow_redirects=False, trust_env=False
        )
        outbound = client.build_request(
            request.method,
            url,
            headers=headers,
            content=body if body else None,
        )
        try:
            upstream = await client.send(outbound, stream=True)
        except BaseException:
            await client.aclose()
            raise

        async def close_upstream() -> None:
            await upstream.aclose()
            await client.aclose()

        return StreamingResponse(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers=_response_headers(upstream),
            background=BackgroundTask(close_upstream),
        )


def build_app(
    *,
    token: str,
    selector_file: Path | None = None,
    upstream: str | None = None,
    runtime_binding_sha256: str | None = None,
) -> Any:
    from starlette.applications import Starlette
    from starlette.routing import Route

    ingress = TransportIngress(
        token=token,
        selector_file=selector_file,
        upstream=upstream,
        runtime_binding_sha256=runtime_binding_sha256,
    )
    return Starlette(
        routes=[
            Route("/_grabowski/transport-ingress", ingress.health, methods=["GET"]),
            Route(
                OAUTH_PROTECTED_RESOURCE_PATH,
                ingress.oauth_resource,
                methods=["GET"],
            ),
            Route(
                OAUTH_PROTECTED_RESOURCE_MCP_PATH,
                ingress.oauth_resource,
                methods=["GET"],
            ),
            Route("/mcp", ingress.proxy, methods=["GET", "POST", "DELETE"]),
        ]
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the signed Grabowski transport ingress."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--selector-file", default=str(DEFAULT_SELECTOR_FILE))
    parser.add_argument("--token-file", default=str(DEFAULT_TOKEN_FILE))
    parser.add_argument(
        "--deployment-manifest", default=str(DEFAULT_DEPLOYMENT_MANIFEST)
    )
    return parser.parse_args()


def main() -> None:
    import uvicorn

    args = _parse_args()
    if args.host != DEFAULT_HOST:
        raise SystemExit("transport ingress must bind to 127.0.0.1")
    if not 1024 <= args.port <= 65535 or args.port == 18181:
        raise SystemExit("transport ingress port is invalid")
    token = _read_private_token(Path(args.token_file).expanduser())
    app = build_app(
        token=token,
        selector_file=Path(args.selector_file).expanduser(),
    )
    uvicorn.run(
        app, host=args.host, port=args.port, log_level="warning", access_log=False
    )


if __name__ == "__main__":
    main()
