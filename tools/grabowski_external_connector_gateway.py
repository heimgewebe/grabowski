#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hmac
import json
import os
from pathlib import Path
import stat
from typing import Any
from urllib.parse import urlsplit

import grabowski_connector_policy
import grabowski_transport_ingress as signed_ingress


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18184
DEFAULT_UPSTREAM = "http://127.0.0.1:18183/mcp"
DEFAULT_CONNECTOR_ID = "maulwurf-x"
DEFAULT_INTERNAL_TOKEN_FILE = (
    Path.home() / ".local/state/grabowski/transport-connectors/maulwurf-x.token"
)
DEFAULT_EXTERNAL_TOKEN_FILE = (
    Path.home() / ".local/state/grabowski/external-connectors/maulwurf-x.token"
)
DEFAULT_POLICY_FILE = (
    Path.home() / ".local/state/grabowski/transport-connectors/maulwurf-x.tools.json"
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
ALLOWED_JSON_RPC_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "notifications/cancelled",
        "ping",
        "tools/list",
        "tools/call",
    }
)


class GatewayConfigurationError(RuntimeError):
    pass


def _validate_upstream(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise GatewayConfigurationError("gateway upstream URL is invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1024 <= port <= 65535
        or parsed.path.rstrip("/") != "/mcp"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise GatewayConfigurationError(
            "gateway upstream must be one loopback MCP endpoint"
        )
    return value.rstrip("/")


def _read_gateway_token(path: Path) -> str:
    parent = path.parent
    try:
        linked = parent.lstat()
    except OSError as exc:
        raise GatewayConfigurationError("gateway token directory is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) & 0o077
    ):
        raise GatewayConfigurationError(
            "gateway token directory must be private and owner-controlled"
        )
    try:
        resolved = parent.resolve(strict=True)
    except OSError as exc:
        raise GatewayConfigurationError("gateway token directory is unavailable") from exc
    if resolved != parent:
        raise GatewayConfigurationError(
            "gateway token directory must be an exact real path"
        )
    try:
        return signed_ingress._read_private_token(path)
    except signed_ingress.IngressConfigurationError as exc:
        raise GatewayConfigurationError(str(exc)) from exc


def _load_gateway_policy(path: Path, connector_id: str) -> dict[str, Any]:
    if path.name != f"{connector_id}{grabowski_connector_policy.POLICY_SUFFIX}":
        raise GatewayConfigurationError("gateway policy filename does not match connector")
    try:
        policy = grabowski_connector_policy.load_policy(path.parent, connector_id)
    except grabowski_connector_policy.ConnectorPolicyError as exc:
        raise GatewayConfigurationError(str(exc)) from exc
    if (
        policy.get("enforced") is not True
        or policy.get("mode") != "allowlist"
        or policy.get("read_only_only") is not True
    ):
        raise GatewayConfigurationError(
            "external connector gateway requires an enforced read-only allowlist policy"
        )
    allowed = policy.get("allowed_tools")
    if not isinstance(allowed, list) or not allowed:
        raise GatewayConfigurationError("external connector allowlist is empty")
    return policy


def _header_values(headers: Any, name: str) -> list[str] | None:
    try:
        getlist = getattr(headers, "getlist", None)
        if callable(getlist):
            values = getlist(name)
            if not isinstance(values, list) or not all(
                isinstance(value, str) for value in values
            ):
                return None
            return values
        value = headers.get(name)
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None
    if value is None:
        return []
    return [value] if isinstance(value, str) else None


def _external_client_authenticated(headers: Any, token: str) -> bool:
    authorization_values = _header_values(headers, "authorization")
    api_key_values = _header_values(headers, "x-api-key")
    if authorization_values is None or api_key_values is None:
        return False
    if len(authorization_values) + len(api_key_values) != 1:
        return False
    if authorization_values:
        scheme, separator, credential = authorization_values[0].partition(" ")
        if not separator or scheme.casefold() != "bearer" or not credential:
            return False
        candidate = credential
    else:
        candidate = api_key_values[0]
        if not candidate:
            return False
    return hmac.compare_digest(candidate, token)


def _forward_headers(request: Any, internal_token: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in request.headers.items():
        lowered = name.lower()
        if (
            lowered in signed_ingress.HOP_BY_HOP_HEADERS
            or lowered in {"host", "content-length", "authorization", "x-api-key"}
            or lowered.startswith(signed_ingress.MANAGED_HEADER_PREFIX)
        ):
            continue
        result[name] = value
    result[signed_ingress.INGRESS_AUTH_HEADER] = internal_token
    return result


def _response_headers(response: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in response.headers.items():
        lowered = name.lower()
        if lowered in signed_ingress.HOP_BY_HOP_HEADERS or lowered == "content-length":
            continue
        result[name] = value
    return result


def _parse_json_rpc(body: bytes) -> dict[str, Any] | None:
    if not body:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _json_rpc_method(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    method = payload.get("method")
    return method if isinstance(method, str) and method else None


def _tool_call_name(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return ""
    name = params.get("name")
    return name if isinstance(name, str) else ""


def _tools_list_request(payload: dict[str, Any] | None) -> bool:
    return isinstance(payload, dict) and payload.get("method") == "tools/list"


def _tool_not_available_response(payload: dict[str, Any] | None) -> dict[str, Any]:
    request_id = payload.get("id") if isinstance(payload, dict) else None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32601,
            "message": "Tool not available for this connector",
        },
    }


def _preflight_json_rpc_request(
    method: str, body: bytes, allowed_tools: frozenset[str] | set[str]
) -> tuple[int, dict[str, Any]] | None:
    payload = _parse_json_rpc(body)
    if body and method != "POST":
        return 400, {"error": "request_body_not_allowed_for_http_method"}
    if method == "POST" and body:
        if payload is None:
            return 400, {"error": "invalid_json_rpc_object"}
        rpc_method = _json_rpc_method(payload)
        if rpc_method is None:
            return 400, {"error": "invalid_json_rpc_method"}
        if rpc_method not in ALLOWED_JSON_RPC_METHODS:
            return 200, _tool_not_available_response(payload)
    tool_name = _tool_call_name(payload)
    if tool_name is not None and tool_name not in allowed_tools:
        return 200, _tool_not_available_response(payload)
    return None


def _filter_tools_list_payload(raw: bytes, allowed_tools: set[str]) -> bytes:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayConfigurationError("upstream tools/list response is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise GatewayConfigurationError("upstream tools/list response is not an object")
    result = payload.get("result")
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        raise GatewayConfigurationError("upstream tools/list response has no tool list")
    filtered: list[dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            raise GatewayConfigurationError("upstream tools/list contains invalid tool")
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            raise GatewayConfigurationError("upstream tools/list contains invalid name")
        if name in allowed_tools:
            filtered.append(tool)
    # MCP tools/list may be paginated. Filter only the current page and preserve
    # the upstream cursor; authoritative existence/authorization is enforced by
    # the operator-side connector policy on tools/call.
    result["tools"] = filtered
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class ExternalConnectorGateway:
    def __init__(
        self,
        *,
        connector_id: str,
        external_token: str,
        internal_token: str,
        allowed_tools: list[str],
        upstream: str,
    ) -> None:
        if not connector_id:
            raise GatewayConfigurationError("gateway connector id is missing")
        if not external_token or not internal_token:
            raise GatewayConfigurationError("gateway credentials are missing")
        if hmac.compare_digest(external_token, internal_token):
            raise GatewayConfigurationError(
                "external and internal connector credentials must be distinct"
            )
        if not allowed_tools or len(allowed_tools) != len(set(allowed_tools)):
            raise GatewayConfigurationError("gateway tool allowlist is invalid")
        self._connector_id = connector_id
        self._external_token = external_token
        self._internal_token = internal_token
        self._allowed_tools = frozenset(allowed_tools)
        self._upstream = _validate_upstream(upstream)

    async def health(self, _request: Any) -> Any:
        from starlette.responses import JSONResponse

        return JSONResponse(
            {
                "schema_version": 1,
                "service": "grabowski-external-connector-gateway",
                "healthy": True,
                "connector_id": self._connector_id,
                "tool_count": len(self._allowed_tools),
                "upstream": "loopback-signed-ingress",
            },
            headers={"Cache-Control": "no-store"},
        )


    async def proxy(self, request: Any) -> Any:
        from starlette.background import BackgroundTask
        from starlette.responses import JSONResponse, Response, StreamingResponse

        if not _external_client_authenticated(request.headers, self._external_token):
            return JSONResponse(
                {"error": "unauthorized_external_connector"},
                status_code=401,
                headers={
                    "Cache-Control": "no-store",
                    "WWW-Authenticate": 'Bearer realm="maulwurf-x"',
                },
            )
        declared_length: int | None = None
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length, 10)
            except ValueError:
                return JSONResponse({"error": "invalid_content_length"}, status_code=400)
            if declared_length < 0:
                return JSONResponse({"error": "invalid_content_length"}, status_code=400)
            if declared_length > signed_ingress.MAX_REQUEST_BYTES:
                return JSONResponse({"error": "request_too_large"}, status_code=413)
        try:
            body = await signed_ingress._read_bounded_request_body(request)
        except signed_ingress.RequestBodyTooLarge:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        except (TypeError, ValueError):
            return JSONResponse({"error": "invalid_request_body"}, status_code=400)
        if declared_length is not None and len(body) != declared_length:
            return JSONResponse({"error": "content_length_mismatch"}, status_code=400)

        payload = _parse_json_rpc(body)
        rejection = _preflight_json_rpc_request(
            request.method, body, self._allowed_tools
        )
        if rejection is not None:
            status_code, rejection_payload = rejection
            return JSONResponse(rejection_payload, status_code=status_code)

        import httpx

        query = request.url.query
        url = self._upstream + (f"?{query}" if query else "")
        client = httpx.AsyncClient(timeout=None, follow_redirects=False, trust_env=False)
        outbound = client.build_request(
            request.method,
            url,
            headers=_forward_headers(request, self._internal_token),
            content=body if body else None,
        )
        try:
            upstream = await client.send(outbound, stream=True)
        except BaseException:
            await client.aclose()
            raise

        if _tools_list_request(payload) and upstream.status_code == 200:
            try:
                declared_response = upstream.headers.get("content-length")
                if declared_response is not None and int(declared_response, 10) > MAX_RESPONSE_BYTES:
                    raise GatewayConfigurationError("upstream tools/list response is too large")
                raw = await upstream.aread()
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise GatewayConfigurationError("upstream tools/list response is too large")
                filtered = _filter_tools_list_payload(raw, set(self._allowed_tools))
                headers = _response_headers(upstream)
            except (GatewayConfigurationError, ValueError):
                await upstream.aclose()
                await client.aclose()
                return JSONResponse(
                    {"error": "tools_list_projection_failed"},
                    status_code=502,
                    headers={"Cache-Control": "no-store"},
                )
            await upstream.aclose()
            await client.aclose()
            return Response(
                filtered,
                status_code=200,
                media_type="application/json",
                headers=headers,
            )

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
    connector_id: str,
    external_token: str,
    internal_token: str,
    allowed_tools: list[str],
    upstream: str,
) -> Any:
    from starlette.applications import Starlette
    from starlette.routing import Route

    gateway = ExternalConnectorGateway(
        connector_id=connector_id,
        external_token=external_token,
        internal_token=internal_token,
        allowed_tools=allowed_tools,
        upstream=upstream,
    )
    return Starlette(
        routes=[
            Route("/_grabowski/external-connector", gateway.health, methods=["GET"]),
            Route("/mcp", gateway.proxy, methods=["GET", "POST", "DELETE"]),
        ]
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a least-privilege external MCP gateway for Grabowski."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--connector-id", default=DEFAULT_CONNECTOR_ID)
    parser.add_argument("--external-token-file", default=str(DEFAULT_EXTERNAL_TOKEN_FILE))
    parser.add_argument("--internal-token-file", default=str(DEFAULT_INTERNAL_TOKEN_FILE))
    parser.add_argument("--tool-policy-file", default=str(DEFAULT_POLICY_FILE))
    return parser.parse_args()


def main() -> None:
    import uvicorn

    args = _parse_args()
    if args.host != DEFAULT_HOST:
        raise SystemExit("external connector gateway must bind to 127.0.0.1")
    if not 1024 <= args.port <= 65535:
        raise SystemExit("external connector gateway port is invalid")
    external_token = _read_gateway_token(
        Path(args.external_token_file).expanduser()
    )
    internal_token = _read_gateway_token(
        Path(args.internal_token_file).expanduser()
    )
    policy = _load_gateway_policy(
        Path(args.tool_policy_file).expanduser(),
        args.connector_id,
    )
    app = build_app(
        connector_id=args.connector_id,
        external_token=external_token,
        internal_token=internal_token,
        allowed_tools=list(policy["allowed_tools"]),
        upstream=args.upstream,
    )
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
