#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route
import uvicorn

import grabowski_transport_assertion as assertion


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18180
DEFAULT_UPSTREAM = "http://127.0.0.1:18181/mcp"
DEFAULT_TOKEN_FILE = Path.home() / ".local/state/grabowski/transport-connectors/primary.token"
DEFAULT_DEPLOYMENT_MANIFEST = Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"
DEPLOYMENT_RELEASE_ROOT = Path.home() / ".local/share/grabowski-mcp-releases"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
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
INGRESS_VERSION_HEADER = "X-Grabowski-Ingress-Version"
REQUEST_ID_HEADER = "X-Grabowski-Request-Id"
REQUEST_TIMESTAMP_HEADER = "X-Grabowski-Request-Timestamp"
REQUEST_AUDIENCE_HEADER = "X-Grabowski-Request-Audience"
REQUEST_BODY_SHA256_HEADER = "X-Grabowski-Request-Body-Sha256"
RUNTIME_BINDING_SHA256_HEADER = "X-Grabowski-Runtime-Binding-Sha256"
REQUEST_MAC_HEADER = "X-Grabowski-Request-Mac"


class IngressConfigurationError(RuntimeError):
    pass


def _read_private_token(path: Path) -> str:
    try:
        linked = os.lstat(path)
    except FileNotFoundError as exc:
        raise IngressConfigurationError("transport connector token file is missing") from exc
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
            raise IngressConfigurationError("transport connector token changed during open")
        raw = os.read(fd, 257)
        if len(raw) > 256 or os.read(fd, 1):
            raise IngressConfigurationError("transport connector token exceeds size bound")
    finally:
        os.close(fd)
    try:
        token = raw.decode("ascii").rstrip("\n")
    except UnicodeDecodeError as exc:
        raise IngressConfigurationError("transport connector token must be ASCII") from exc
    if not token or token != token.strip() or len(token) < 16:
        raise IngressConfigurationError("transport connector token is invalid")
    return token


def _read_runtime_binding(path: Path) -> tuple[dict[str, str], str]:
    try:
        release_root = DEPLOYMENT_RELEASE_ROOT.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise IngressConfigurationError("deployment manifest is unavailable") from exc
    if resolved == release_root or not resolved.is_relative_to(release_root):
        raise IngressConfigurationError("deployment manifest is outside the immutable release root")
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
    expected_tools = entrypoint.get("expected_tools") if isinstance(entrypoint, dict) else None
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
        raise IngressConfigurationError("deployment manifest runtime binding is invalid")
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
        or port != 18181
        or parsed.path.rstrip("/") != "/mcp"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise IngressConfigurationError("upstream must be the bound loopback Grabowski operator")
    return value.rstrip("/")


def _forward_headers(request: Request, token: str) -> dict[str, str]:
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


def _response_headers(response: httpx.Response) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in response.headers.items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP_HEADERS or lowered == "content-length":
            continue
        result[name] = value
    return result


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
    if not isinstance(tool_name, str) or not tool_name or len(tool_name.encode("utf-8")) > 256:
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


class TransportIngress:
    def __init__(self, *, token: str, upstream: str, runtime_binding_sha256: str) -> None:
        self._token = token
        self._upstream = _validate_upstream(upstream)
        if SHA256_RE.fullmatch(runtime_binding_sha256) is None:
            raise IngressConfigurationError("runtime binding digest is invalid")
        self._runtime_binding_sha256 = runtime_binding_sha256

    async def health(self, request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "schema_version": 1,
                "service": "grabowski-transport-ingress",
                "healthy": True,
                "assertion_version": assertion.ASSERTION_VERSION,
                "runtime_binding_sha256": self._runtime_binding_sha256,
                "upstream": "loopback-operator",
            }
        )

    async def proxy(self, request: Request) -> StreamingResponse | JSONResponse:
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length, 10)
            except ValueError:
                return JSONResponse({"error": "invalid_content_length"}, status_code=400)
            if declared_length < 0:
                return JSONResponse({"error": "invalid_content_length"}, status_code=400)
            if declared_length > MAX_REQUEST_BYTES:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        body = await request.body()
        if len(body) > MAX_REQUEST_BYTES:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        headers = _forward_headers(request, self._token)
        try:
            headers.update(
                signed_tool_headers(
                    token=self._token,
                    body=body,
                    session_id=request.headers.get("mcp-session-id", ""),
                    runtime_binding_sha256=self._runtime_binding_sha256,
                )
            )
        except ValueError as exc:
            return JSONResponse(
                {"error": "invalid_mcp_request", "detail": str(exc)},
                status_code=400,
            )
        query = request.url.query
        url = self._upstream + (f"?{query}" if query else "")
        client = httpx.AsyncClient(timeout=None, follow_redirects=False, trust_env=False)
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


def build_app(*, token: str, upstream: str, runtime_binding_sha256: str) -> Starlette:
    ingress = TransportIngress(
        token=token, upstream=upstream, runtime_binding_sha256=runtime_binding_sha256
    )
    return Starlette(
        routes=[
            Route("/_grabowski/transport-ingress", ingress.health, methods=["GET"]),
            Route("/mcp", ingress.proxy, methods=["GET", "POST", "DELETE"]),
        ]
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the signed Grabowski transport ingress.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--token-file", default=str(DEFAULT_TOKEN_FILE))
    parser.add_argument("--deployment-manifest", default=str(DEFAULT_DEPLOYMENT_MANIFEST))
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.host != DEFAULT_HOST:
        raise SystemExit("transport ingress must bind to 127.0.0.1")
    if not 1024 <= args.port <= 65535 or args.port == 18181:
        raise SystemExit("transport ingress port is invalid")
    token = _read_private_token(Path(args.token_file).expanduser())
    _, runtime_binding_sha256 = _read_runtime_binding(
        Path(args.deployment_manifest).expanduser()
    )
    app = build_app(
        token=token,
        upstream=args.upstream,
        runtime_binding_sha256=runtime_binding_sha256,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
