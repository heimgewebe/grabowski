#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
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
from urllib.parse import parse_qs, urlencode, urlsplit

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
OAUTH_SCOPE = "mcp"
OAUTH_CODE_TTL_SECONDS = 120
OAUTH_CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9_-]{43}")
OAUTH_CODE_VERIFIER_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}")
OAUTH_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
OAUTH_CODE_PREFIX = "mxc1"


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


def _oauth_client_id(connector_id: str) -> str:
    return f"{connector_id}-grok"


def _oauth_redirect_uri_allowed(value: str) -> bool:
    if not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value:
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    host = (parsed.hostname or "").casefold()
    trusted_host = (
        host == "grok.com"
        or host.endswith(".grok.com")
        or host == "x.ai"
        or host.endswith(".x.ai")
    )
    return bool(
        parsed.scheme == "https"
        and trusted_host
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and parsed.path.startswith("/")
    )


def _oauth_b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _oauth_b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or OAUTH_B64URL_RE.fullmatch(value) is None:
        raise ValueError("invalid base64url value")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc


def _oauth_pkce_s256(verifier: str) -> str:
    if OAUTH_CODE_VERIFIER_RE.fullmatch(verifier or "") is None:
        raise ValueError("invalid PKCE verifier")
    return _oauth_b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())


def _oauth_issue_code(
    *,
    secret: str,
    connector_id: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    now: int | None = None,
) -> str:
    if (
        client_id != _oauth_client_id(connector_id)
        or not _oauth_redirect_uri_allowed(redirect_uri)
        or OAUTH_CODE_CHALLENGE_RE.fullmatch(code_challenge or "") is None
    ):
        raise GatewayConfigurationError("OAuth authorization request is invalid")
    issued = int(time.time()) if now is None else int(now)
    payload = {
        "v": 1,
        "aud": connector_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "exp": issued + OAUTH_CODE_TTL_SECONDS,
        "nonce": secrets.token_urlsafe(18),
    }
    encoded = _oauth_b64url_encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signature = _oauth_b64url_encode(
        hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{OAUTH_CODE_PREFIX}.{encoded}.{signature}"


def _oauth_consume_code(
    code: str,
    *,
    secret: str,
    connector_id: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    consumed: set[str],
    now: int | None = None,
) -> bool:
    try:
        prefix, encoded, signature = code.split(".")
    except (AttributeError, ValueError):
        return False
    if prefix != OAUTH_CODE_PREFIX:
        return False
    expected = _oauth_b64url_encode(
        hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(signature, expected):
        return False
    try:
        payload = json.loads(_oauth_b64url_decode(encoded).decode("utf-8"))
        challenge = _oauth_pkce_s256(code_verifier)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    current = int(time.time()) if now is None else int(now)
    if (
        not isinstance(payload, dict)
        or payload.get("v") != 1
        or payload.get("aud") != connector_id
        or payload.get("client_id") != client_id
        or payload.get("redirect_uri") != redirect_uri
        or not _oauth_redirect_uri_allowed(redirect_uri)
        or payload.get("code_challenge") != challenge
        or not isinstance(payload.get("exp"), int)
        or isinstance(payload.get("exp"), bool)
        or payload["exp"] <= current
    ):
        return False
    digest = hashlib.sha256(code.encode("ascii")).hexdigest()
    if digest in consumed:
        return False
    consumed.add(digest)
    return True


def _oauth_basic_client(headers: Any) -> tuple[str, str] | None:
    values = _header_values(headers, "authorization")
    if values is None or len(values) != 1:
        return None
    scheme, separator, encoded = values[0].partition(" ")
    if not separator or scheme.casefold() != "basic" or not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError, binascii.Error):
        return None
    client_id, separator, client_secret = decoded.partition(":")
    if not separator or not client_id or not client_secret:
        return None
    return client_id, client_secret


async def _oauth_form(request: Any) -> dict[str, list[str]]:
    if (
        request.headers.get("content-type", "").partition(";")[0].strip().lower()
        != "application/x-www-form-urlencoded"
    ):
        raise ValueError("OAuth token request content type is invalid")
    body = await signed_ingress._read_bounded_request_body(request)
    try:
        form = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=20,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("OAuth token request body is invalid") from exc
    if any(len(values) != 1 for values in form.values()):
        raise ValueError("OAuth token request contains duplicate fields")
    return form


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


def _filter_tools_list_sse_payload(raw: bytes, allowed_tools: set[str]) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GatewayConfigurationError(
            "upstream tools/list SSE response is not UTF-8"
        ) from exc

    parts = re.split(r"(\r\n\r\n|\n\n)", text)
    saw_json_rpc_event = False
    for index in range(0, len(parts), 2):
        block = parts[index]
        if not block:
            continue
        lines = block.splitlines()
        data_indexes: list[int] = []
        data_parts: list[str] = []
        for line_index, line in enumerate(lines):
            if not line.startswith("data:"):
                continue
            value = line[5:]
            if value.startswith(" "):
                value = value[1:]
            data_indexes.append(line_index)
            data_parts.append(value)
        if not data_indexes or not any(data_parts):
            # Keep comments, retry/id-only fields and the MCP resumability
            # priming event byte-for-byte.
            continue
        data = "\n".join(data_parts)
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise GatewayConfigurationError(
                "upstream tools/list SSE event is invalid JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise GatewayConfigurationError(
                "upstream tools/list SSE event is not a JSON-RPC object"
            )
        if isinstance(payload.get("error"), dict):
            saw_json_rpc_event = True
            continue
        result = payload.get("result")
        if not isinstance(result, dict) or "tools" not in result:
            raise GatewayConfigurationError(
                "upstream tools/list SSE event has an unexpected result"
            )
        filtered = _filter_tools_list_payload(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            ),
            allowed_tools,
        ).decode("utf-8")
        first_data = data_indexes[0]
        lines[first_data] = f"data: {filtered}"
        for extra_data in reversed(data_indexes[1:]):
            del lines[extra_data]
        newline = "\r\n" if "\r\n" in block else "\n"
        parts[index] = newline.join(lines)
        saw_json_rpc_event = True
    if not saw_json_rpc_event:
        raise GatewayConfigurationError(
            "upstream tools/list SSE response has no JSON-RPC event"
        )
    return "".join(parts).encode("utf-8")


def _filter_tools_list_response(
    raw: bytes, content_type: str, allowed_tools: set[str]
) -> bytes:
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "application/json":
        return _filter_tools_list_payload(raw, allowed_tools)
    if media_type == "text/event-stream":
        return _filter_tools_list_sse_payload(raw, allowed_tools)
    raise GatewayConfigurationError(
        "upstream tools/list response has an unsupported content type"
    )


async def _read_bounded_upstream_response(
    response: Any, *, maximum_bytes: int = MAX_RESPONSE_BYTES
) -> bytes:
    if maximum_bytes <= 0:
        raise GatewayConfigurationError("upstream response size bound is invalid")
    chunks: list[bytes] = []
    total = 0
    try:
        iterator = response.aiter_raw()
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise GatewayConfigurationError("upstream response stream is unavailable") from exc
    async for chunk in iterator:
        if not isinstance(chunk, bytes):
            raise GatewayConfigurationError("upstream response stream returned invalid bytes")
        total += len(chunk)
        if total > maximum_bytes:
            raise GatewayConfigurationError("upstream tools/list response is too large")
        chunks.append(chunk)
    return b"".join(chunks)


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
        self._oauth_used_codes: set[str] = set()

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


    async def oauth_authorize(self, request: Any) -> Any:
        from starlette.responses import JSONResponse, RedirectResponse

        def one(name: str, *, required: bool = True) -> str | None:
            values = request.query_params.getlist(name)
            if len(values) == 1:
                return values[0]
            return None if not required and not values else ""

        response_type = one("response_type")
        client_id = one("client_id")
        redirect_uri = one("redirect_uri")
        scope = one("scope")
        code_challenge = one("code_challenge")
        code_challenge_method = one("code_challenge_method")
        state = one("state", required=False)
        if (
            response_type != "code"
            or client_id != _oauth_client_id(self._connector_id)
            or redirect_uri is None
            or not _oauth_redirect_uri_allowed(redirect_uri)
            or scope != OAUTH_SCOPE
            or code_challenge_method != "S256"
            or OAUTH_CODE_CHALLENGE_RE.fullmatch(code_challenge or "") is None
            or state == ""
            or (state is not None and len(state) > 1024)
        ):
            return JSONResponse(
                {"error": "invalid_request"},
                status_code=400,
                headers={"Cache-Control": "no-store"},
            )
        code = _oauth_issue_code(
            secret=self._external_token,
            connector_id=self._connector_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
        )
        query = {"code": code}
        if state is not None:
            query["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{separator}{urlencode(query)}",
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )

    async def oauth_token(self, request: Any) -> Any:
        from starlette.responses import JSONResponse

        def error(name: str, status_code: int = 400) -> Any:
            headers = {"Cache-Control": "no-store", "Pragma": "no-cache"}
            if status_code == 401:
                headers["WWW-Authenticate"] = 'Basic realm="maulwurf-x-oauth"'
            return JSONResponse({"error": name}, status_code=status_code, headers=headers)

        try:
            form = await _oauth_form(request)
        except (signed_ingress.RequestBodyTooLarge, ValueError):
            return error("invalid_request")
        credentials = _oauth_basic_client(request.headers)
        if credentials is None:
            return error("invalid_client", 401)
        client_id, client_secret = credentials
        if (
            client_id != _oauth_client_id(self._connector_id)
            or not hmac.compare_digest(client_secret, self._external_token)
        ):
            return error("invalid_client", 401)
        if form.get("grant_type", [""])[0] != "authorization_code":
            return error("unsupported_grant_type")
        redirect_uri = form.get("redirect_uri", [""])[0]
        if not _oauth_consume_code(
            form.get("code", [""])[0],
            secret=self._external_token,
            connector_id=self._connector_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=form.get("code_verifier", [""])[0],
            consumed=self._oauth_used_codes,
        ):
            return error("invalid_grant")
        return JSONResponse(
            {
                "access_token": self._external_token,
                "token_type": "Bearer",
                "scope": OAUTH_SCOPE,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
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
                raw = await _read_bounded_upstream_response(upstream)
                content_type = upstream.headers.get("content-type", "")
                filtered = _filter_tools_list_response(
                    raw,
                    content_type,
                    set(self._allowed_tools),
                )
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
            Route("/oauth/authorize", gateway.oauth_authorize, methods=["GET"]),
            Route("/oauth/token", gateway.oauth_token, methods=["POST"]),
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
