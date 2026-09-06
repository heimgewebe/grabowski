#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import math
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
DEFAULT_DEPLOYMENT_MANIFEST = (
    Path.home() / ".local/share/grabowski-mcp/deployment-manifest.json"
)
DEFAULT_FINDING_ROOT = (
    Path.home() / ".local/state/grabowski/external-connectors/maulwurf-x-findings"
)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_DEPLOYMENT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FINDING_BYTES = 64 * 1024
MAX_FINDING_FILES = 256
FINDING_FILENAME_RE = re.compile(r"[0-9a-f]{64}\.json")
FINDING_LOCK_NAME = ".proposal.lock"
PROPOSAL_TOOL_NAME = "maulwurfx_propose_finding"
PROPOSAL_CATEGORIES = frozenset(
    {"runtime", "bureau", "resource", "audit", "connector", "catalog", "other"}
)
PROPOSAL_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
PROPOSAL_REQUIRED_FIELDS = frozenset(
    {
        "title",
        "category",
        "severity",
        "facts",
        "evidence_refs",
        "interpretation",
        "uncertainty",
        "proposed_action",
        "does_not_establish",
    }
)
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
    gateway_tools = policy.get("gateway_tools", [])
    if not isinstance(allowed, list) or not allowed:
        raise GatewayConfigurationError("external connector allowlist is empty")
    if not isinstance(gateway_tools, list):
        raise GatewayConfigurationError("external connector gateway-tool allowlist is invalid")
    if gateway_tools and (
        policy.get("schema_version") != 2
        or connector_id != DEFAULT_CONNECTOR_ID
        or set(gateway_tools) != {PROPOSAL_TOOL_NAME}
    ):
        raise GatewayConfigurationError(
            "external connector gateway proposal surface is not authorized"
        )
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


def _json_rpc_error(
    payload: dict[str, Any] | None, code: int, message: str
) -> dict[str, Any]:
    request_id = payload.get("id") if isinstance(payload, dict) else None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tool_call_arguments(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    arguments = params.get("arguments", {})
    return arguments if isinstance(arguments, dict) else None


def _proposal_tool_descriptor() -> dict[str, Any]:
    return {
        "name": PROPOSAL_TOOL_NAME,
        "description": (
            "Record one evidence-bound maulwurfX finding as a private, create-only "
            "proposal. This never creates a Bureau task, claims resources, changes a "
            "repository, deploys, or executes the proposed action."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(PROPOSAL_REQUIRED_FIELDS),
            "properties": {
                "title": {"type": "string", "minLength": 1, "maxLength": 200},
                "category": {"type": "string", "enum": sorted(PROPOSAL_CATEGORIES)},
                "severity": {"type": "string", "enum": sorted(PROPOSAL_SEVERITIES)},
                "facts": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 12,
                    "items": {"type": "string", "minLength": 1, "maxLength": 800},
                },
                "evidence_refs": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 24,
                    "items": {"type": "string", "minLength": 1, "maxLength": 512},
                },
                "interpretation": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2500,
                },
                "uncertainty": {"type": "number", "minimum": 0, "maximum": 1},
                "proposed_action": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 2000,
                },
                "does_not_establish": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 12,
                    "items": {"type": "string", "minLength": 1, "maxLength": 500},
                },
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    }


def _normalize_proposal_text(value: Any, *, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or any(c in value for c in ("\x00", "\r")):
        raise ValueError(f"{label} is invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} is invalid")
    return normalized


def _normalize_proposal_list(
    value: Any,
    *,
    label: str,
    maximum_items: int,
    maximum_item_bytes: int,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum_items
    ):
        raise ValueError(f"{label} is invalid")
    normalized = [
        _normalize_proposal_text(item, label=label, maximum_bytes=maximum_item_bytes)
        for item in value
    ]
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label} contains duplicates")
    return normalized


def _normalize_finding_arguments(arguments: Any) -> dict[str, Any]:
    if not isinstance(arguments, dict) or set(arguments) != PROPOSAL_REQUIRED_FIELDS:
        raise ValueError("finding proposal shape is invalid")
    category = _normalize_proposal_text(
        arguments.get("category"), label="category", maximum_bytes=32
    )
    severity = _normalize_proposal_text(
        arguments.get("severity"), label="severity", maximum_bytes=16
    )
    if category not in PROPOSAL_CATEGORIES:
        raise ValueError("finding proposal category is invalid")
    if severity not in PROPOSAL_SEVERITIES:
        raise ValueError("finding proposal severity is invalid")
    uncertainty = arguments.get("uncertainty")
    if (
        not isinstance(uncertainty, (int, float))
        or isinstance(uncertainty, bool)
        or not math.isfinite(float(uncertainty))
        or not 0 <= float(uncertainty) <= 1
    ):
        raise ValueError("finding proposal uncertainty is invalid")
    return {
        "title": _normalize_proposal_text(
            arguments.get("title"), label="title", maximum_bytes=200
        ),
        "category": category,
        "severity": severity,
        "facts": _normalize_proposal_list(
            arguments.get("facts"),
            label="facts",
            maximum_items=12,
            maximum_item_bytes=800,
        ),
        "evidence_refs": _normalize_proposal_list(
            arguments.get("evidence_refs"),
            label="evidence_refs",
            maximum_items=24,
            maximum_item_bytes=512,
        ),
        "interpretation": _normalize_proposal_text(
            arguments.get("interpretation"),
            label="interpretation",
            maximum_bytes=2500,
        ),
        "uncertainty": float(uncertainty),
        "proposed_action": _normalize_proposal_text(
            arguments.get("proposed_action"),
            label="proposed_action",
            maximum_bytes=2000,
        ),
        "does_not_establish": _normalize_proposal_list(
            arguments.get("does_not_establish"),
            label="does_not_establish",
            maximum_items=12,
            maximum_item_bytes=500,
        ),
    }


def _read_runtime_binding(path: Path) -> dict[str, str]:
    try:
        linked = os.lstat(path)
    except OSError as exc:
        raise GatewayConfigurationError("deployment manifest is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or linked.st_nlink != 1
        or linked.st_size > MAX_DEPLOYMENT_MANIFEST_BYTES
        or stat.S_IMODE(linked.st_mode) & 0o022
    ):
        raise GatewayConfigurationError("deployment manifest file is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_gid != linked.st_gid
            or opened.st_nlink != linked.st_nlink
        ):
            raise GatewayConfigurationError("deployment manifest changed while opening")
        raw = os.read(descriptor, MAX_DEPLOYMENT_MANIFEST_BYTES + 1)
        if len(raw) > MAX_DEPLOYMENT_MANIFEST_BYTES or os.read(descriptor, 1):
            raise GatewayConfigurationError("deployment manifest exceeds size bound")
    finally:
        os.close(descriptor)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayConfigurationError("deployment manifest is invalid JSON") from exc
    release_id = manifest.get("release_id") if isinstance(manifest, dict) else None
    repo_head = manifest.get("repo_head") if isinstance(manifest, dict) else None
    completion_status = (
        manifest.get("completion_status") if isinstance(manifest, dict) else None
    )
    if (
        completion_status != "complete"
        or not isinstance(release_id, str)
        or not release_id
        or len(release_id.encode("utf-8")) > 512
        or not isinstance(repo_head, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", repo_head) is None
    ):
        raise GatewayConfigurationError("deployment manifest identity is invalid")
    return {"release_id": release_id, "repo_head": repo_head}


def _ensure_private_finding_root(root: Path) -> None:
    parent = root.parent
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise GatewayConfigurationError("finding parent directory is unavailable") from exc
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise GatewayConfigurationError("finding parent directory is unsafe")
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        pass
    try:
        linked = os.lstat(root)
    except OSError as exc:
        raise GatewayConfigurationError("finding directory is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISDIR(linked.st_mode)
        or linked.st_uid != os.geteuid()
        or stat.S_IMODE(linked.st_mode) != 0o700
    ):
        raise GatewayConfigurationError("finding directory is unsafe")


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _acquire_finding_store_lock(root: Path) -> int:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(root, directory_flags)
    descriptor = -1
    try:
        directory = os.fstat(directory_fd)
        linked_directory = os.lstat(root)
        if (
            not stat.S_ISDIR(directory.st_mode)
            or stat.S_ISLNK(linked_directory.st_mode)
            or directory.st_uid != os.geteuid()
            or stat.S_IMODE(directory.st_mode) != 0o700
            or directory.st_dev != linked_directory.st_dev
            or directory.st_ino != linked_directory.st_ino
            or directory.st_mode != linked_directory.st_mode
            or directory.st_uid != linked_directory.st_uid
            or directory.st_gid != linked_directory.st_gid
        ):
            raise GatewayConfigurationError("finding directory identity is unsafe")
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(FINDING_LOCK_NAME, flags, 0o600, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        linked = os.stat(
            FINDING_LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or opened.st_size != 0
            or opened.st_dev != linked.st_dev
            or opened.st_ino != linked.st_ino
            or opened.st_mode != linked.st_mode
            or opened.st_uid != linked.st_uid
            or opened.st_gid != linked.st_gid
            or opened.st_nlink != linked.st_nlink
            or opened.st_size != linked.st_size
        ):
            raise GatewayConfigurationError("finding proposal lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        after = os.fstat(descriptor)
        linked_after = os.stat(
            FINDING_LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False
        )
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_mode != opened.st_mode
            or after.st_uid != opened.st_uid
            or after.st_gid != opened.st_gid
            or after.st_nlink != 1
            or after.st_size != 0
            or linked_after.st_dev != opened.st_dev
            or linked_after.st_ino != opened.st_ino
            or linked_after.st_mode != opened.st_mode
            or linked_after.st_uid != opened.st_uid
            or linked_after.st_gid != opened.st_gid
            or linked_after.st_nlink != 1
            or linked_after.st_size != 0
        ):
            raise GatewayConfigurationError(
                "finding proposal lock identity changed during acquisition"
            )
        return descriptor
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(directory_fd)


def _release_finding_store_lock(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short finding proposal write")
        view = view[written:]


def _publish_private_create_only_json(
    directory: Path,
    target: Path,
    payload: dict[str, Any],
) -> bool:
    if target.parent != directory:
        raise ValueError("finding proposal target must be a direct child")
    target_name = target.name
    if FINDING_FILENAME_RE.fullmatch(target_name) is None:
        raise ValueError("finding proposal target name is invalid")
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_FINDING_BYTES:
        raise ValueError("finding proposal is too large")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory_fd = os.open(directory, directory_flags)
    temporary_name = f".{target_name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    temporary_present = False
    published_inode: tuple[int, int] | None = None
    try:
        opened_directory = os.fstat(directory_fd)
        linked_directory = os.lstat(directory)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or stat.S_ISLNK(linked_directory.st_mode)
            or opened_directory.st_uid != os.geteuid()
            or stat.S_IMODE(opened_directory.st_mode) != 0o700
            or opened_directory.st_dev != linked_directory.st_dev
            or opened_directory.st_ino != linked_directory.st_ino
            or opened_directory.st_mode != linked_directory.st_mode
            or opened_directory.st_uid != linked_directory.st_uid
            or opened_directory.st_gid != linked_directory.st_gid
        ):
            raise GatewayConfigurationError("finding directory identity is unsafe")

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        temporary_present = True
        temporary = os.fstat(descriptor)
        published_inode = (temporary.st_dev, temporary.st_ino)
        if (
            not stat.S_ISREG(temporary.st_mode)
            or stat.S_IMODE(temporary.st_mode) != 0o600
            or temporary.st_uid != os.geteuid()
            or temporary.st_nlink != 1
        ):
            raise GatewayConfigurationError("temporary finding proposal is unsafe")
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        after_write = os.fstat(descriptor)
        if (
            (after_write.st_dev, after_write.st_ino) != published_inode
            or after_write.st_mode != temporary.st_mode
            or after_write.st_uid != temporary.st_uid
            or after_write.st_gid != temporary.st_gid
            or after_write.st_nlink != 1
            or after_write.st_size != len(encoded)
        ):
            raise GatewayConfigurationError(
                "temporary finding proposal changed during write"
            )
        os.close(descriptor)
        descriptor = -1

        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            published_inode = None
            return False

        linked = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (linked.st_dev, linked.st_ino) != published_inode
            or not stat.S_ISREG(linked.st_mode)
            or stat.S_IMODE(linked.st_mode) != 0o600
            or linked.st_uid != os.geteuid()
            or linked.st_nlink != 2
            or linked.st_size != len(encoded)
        ):
            raise GatewayConfigurationError(
                "linked finding proposal failed integrity validation"
            )
        os.unlink(temporary_name, dir_fd=directory_fd)
        temporary_present = False
        linked = os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            (linked.st_dev, linked.st_ino) != published_inode
            or stat.S_IMODE(linked.st_mode) != 0o600
            or linked.st_uid != os.geteuid()
            or linked.st_nlink != 1
            or linked.st_size != len(encoded)
        ):
            raise GatewayConfigurationError(
                "published finding proposal failed integrity validation"
            )
        os.fsync(directory_fd)
        directory_after = os.fstat(directory_fd)
        linked_directory_after = os.lstat(directory)
        if (
            directory_after.st_dev != opened_directory.st_dev
            or directory_after.st_ino != opened_directory.st_ino
            or directory_after.st_mode != opened_directory.st_mode
            or directory_after.st_uid != opened_directory.st_uid
            or directory_after.st_gid != opened_directory.st_gid
            or linked_directory_after.st_dev != opened_directory.st_dev
            or linked_directory_after.st_ino != opened_directory.st_ino
            or linked_directory_after.st_mode != opened_directory.st_mode
        ):
            raise GatewayConfigurationError(
                "finding directory identity changed during publication"
            )
        return True
    except BaseException:
        if published_inode is not None:
            try:
                current = os.stat(
                    target_name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) == published_inode:
                    os.unlink(target_name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_present:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except (FileNotFoundError, OSError):
                pass
        os.close(directory_fd)


def _read_existing_finding(path: Path) -> dict[str, Any] | None:
    try:
        raw = grabowski_connector_policy._read_private_file(
            path, maximum_bytes=MAX_FINDING_BYTES
        )
    except FileNotFoundError:
        return None
    except (OSError, RuntimeError) as exc:
        raise GatewayConfigurationError(
            "existing finding proposal cannot be verified"
        ) from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GatewayConfigurationError(
            "existing finding proposal cannot be verified"
        ) from exc
    if not isinstance(value, dict):
        raise GatewayConfigurationError("existing finding proposal is invalid")
    return value


def _enforce_finding_store_capacity(root: Path, target: Path) -> None:
    if target.exists():
        return
    count = 0
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                linked = entry.stat(follow_symlinks=False)
                if entry.name == FINDING_LOCK_NAME:
                    if (
                        not stat.S_ISREG(linked.st_mode)
                        or linked.st_uid != os.geteuid()
                        or linked.st_nlink != 1
                        or stat.S_IMODE(linked.st_mode) != 0o600
                        or linked.st_size != 0
                    ):
                        raise GatewayConfigurationError(
                            "finding store lock entry is unsafe"
                        )
                    continue
                if FINDING_FILENAME_RE.fullmatch(entry.name) is None:
                    raise GatewayConfigurationError(
                        "finding store contains an unexpected entry"
                    )
                if (
                    not stat.S_ISREG(linked.st_mode)
                    or linked.st_uid != os.geteuid()
                    or linked.st_nlink != 1
                    or stat.S_IMODE(linked.st_mode) != 0o600
                    or linked.st_size > MAX_FINDING_BYTES
                ):
                    raise GatewayConfigurationError(
                        "finding store contains an unsafe entry"
                    )
                count += 1
                if count >= MAX_FINDING_FILES:
                    raise GatewayConfigurationError("finding proposal store is full")
    except GatewayConfigurationError:
        raise
    except OSError as exc:
        raise GatewayConfigurationError("finding proposal store is unavailable") from exc


def _verify_existing_finding(
    existing: dict[str, Any],
    *,
    finding_id: str,
    proposal_sha256: str,
    connector_id: str,
    runtime: dict[str, str],
    normalized: dict[str, Any],
) -> None:
    if (
        existing.get("finding_id") != finding_id
        or existing.get("proposal_sha256") != proposal_sha256
        or existing.get("principal") != connector_id
        or existing.get("runtime") != runtime
        or existing.get("finding") != normalized
    ):
        raise GatewayConfigurationError("existing finding proposal identity mismatch")


def _record_finding_proposal(
    *,
    connector_id: str,
    arguments: dict[str, Any],
    finding_root: Path,
    deployment_manifest: Path,
) -> dict[str, Any]:
    if connector_id != DEFAULT_CONNECTOR_ID:
        raise GatewayConfigurationError("finding proposal principal is not authorized")
    normalized = _normalize_finding_arguments(arguments)
    runtime = _read_runtime_binding(deployment_manifest)
    identity = {
        "schema_version": 1,
        "principal": connector_id,
        "runtime": runtime,
        "finding": normalized,
    }
    proposal_sha256 = hashlib.sha256(_canonical_json_bytes(identity)).hexdigest()
    finding_id = proposal_sha256
    _ensure_private_finding_root(finding_root)
    target = finding_root / f"{finding_id}.json"
    record = {
        "schema_version": 1,
        "kind": "maulwurfx_finding_proposal",
        "finding_id": finding_id,
        "proposal_sha256": proposal_sha256,
        "principal": connector_id,
        "runtime": runtime,
        "finding": normalized,
        "created_at_unix": int(time.time()),
        "record_semantics": "private-create-only-content-addressed-v1",
    }
    lock_descriptor = _acquire_finding_store_lock(finding_root)
    try:
        existing = _read_existing_finding(target)
        if existing is not None:
            _verify_existing_finding(
                existing,
                finding_id=finding_id,
                proposal_sha256=proposal_sha256,
                connector_id=connector_id,
                runtime=runtime,
                normalized=normalized,
            )
            created = False
        else:
            _enforce_finding_store_capacity(finding_root, target)
            try:
                created = _publish_private_create_only_json(
                    finding_root,
                    target,
                    record,
                )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise GatewayConfigurationError(
                    "finding proposal publication failed"
                ) from exc
            if not created:
                existing = _read_existing_finding(target)
                if existing is None:
                    raise GatewayConfigurationError(
                        "finding proposal publication outcome is ambiguous"
                    )
                _verify_existing_finding(
                    existing,
                    finding_id=finding_id,
                    proposal_sha256=proposal_sha256,
                    connector_id=connector_id,
                    runtime=runtime,
                    normalized=normalized,
                )
    finally:
        _release_finding_store_lock(lock_descriptor)
    return {
        "schema_version": 1,
        "kind": "maulwurfx_finding_proposal_receipt",
        "status": "recorded" if created else "duplicate",
        "finding_id": finding_id,
        "proposal_sha256": proposal_sha256,
        "principal": connector_id,
        "runtime": runtime,
        "create_only": True,
        "execution_authority": False,
        "does_not_establish": [
            "finding_correctness",
            "bureau_task_creation",
            "bureau_readiness",
            "resource_claim_or_lease",
            "repository_mutation",
            "deployment_or_service_effect",
            "proposed_action_execution",
            "deletion_resistance_against_same_uid",
        ],
    }


def _proposal_tool_result(
    payload: dict[str, Any] | None, receipt: dict[str, Any]
) -> dict[str, Any]:
    request_id = payload.get("id") if isinstance(payload, dict) else None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        receipt, ensure_ascii=False, separators=(",", ":")
                    ),
                }
            ],
            "structuredContent": receipt,
            "isError": False,
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


def _filter_tools_list_payload(
    raw: bytes,
    allowed_tools: set[str],
    gateway_tools: set[str] | None = None,
) -> bytes:
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
    projected = list(filtered)
    if gateway_tools:
        if gateway_tools != {PROPOSAL_TOOL_NAME}:
            raise GatewayConfigurationError("unsupported gateway tool projection")
        # Project the gateway-local tool exactly once even when upstream tools/list
        # is paginated. The terminal page is the only page whose nextCursor is absent.
        if result.get("nextCursor") in (None, ""):
            projected.append(_proposal_tool_descriptor())
    # MCP tools/list may be paginated. Filter only the current page and preserve
    # the upstream cursor; internal tool authorization remains operator-side,
    # while the one gateway-local proposal tool is handled before upstream.
    result["tools"] = projected
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _filter_tools_list_sse_payload(
    raw: bytes,
    allowed_tools: set[str],
    gateway_tools: set[str] | None = None,
) -> bytes:
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
            gateway_tools,
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
    raw: bytes,
    content_type: str,
    allowed_tools: set[str],
    gateway_tools: set[str] | None = None,
) -> bytes:
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "application/json":
        return _filter_tools_list_payload(raw, allowed_tools, gateway_tools)
    if media_type == "text/event-stream":
        return _filter_tools_list_sse_payload(raw, allowed_tools, gateway_tools)
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
        gateway_tools: list[str] | None = None,
        finding_root: Path | None = None,
        deployment_manifest: Path | None = None,
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
        normalized_gateway_tools = list(gateway_tools or [])
        if (
            len(normalized_gateway_tools) != len(set(normalized_gateway_tools))
            or set(normalized_gateway_tools)
            - grabowski_connector_policy.GATEWAY_ONLY_TOOL_NAMES
            or set(normalized_gateway_tools) & set(allowed_tools)
        ):
            raise GatewayConfigurationError("gateway-local tool allowlist is invalid")
        if normalized_gateway_tools and (
            connector_id != DEFAULT_CONNECTOR_ID
            or set(normalized_gateway_tools) != {PROPOSAL_TOOL_NAME}
        ):
            raise GatewayConfigurationError("gateway-local proposal tool is not authorized")
        self._connector_id = connector_id
        self._external_token = external_token
        self._internal_token = internal_token
        self._allowed_tools = frozenset(allowed_tools)
        self._gateway_tools = frozenset(normalized_gateway_tools)
        self._visible_tools = self._allowed_tools | self._gateway_tools
        self._finding_root = finding_root or (
            DEFAULT_FINDING_ROOT
            if connector_id == DEFAULT_CONNECTOR_ID
            else DEFAULT_FINDING_ROOT.parent / f"{connector_id}-findings"
        )
        self._deployment_manifest = deployment_manifest or DEFAULT_DEPLOYMENT_MANIFEST
        self._proposal_lock = asyncio.Lock()
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
                "tool_count": len(self._visible_tools),
                "internal_tool_count": len(self._allowed_tools),
                "gateway_tool_count": len(self._gateway_tools),
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
            request.method, body, self._visible_tools
        )
        if rejection is not None:
            status_code, rejection_payload = rejection
            return JSONResponse(rejection_payload, status_code=status_code)

        tool_name = _tool_call_name(payload)
        if tool_name in self._gateway_tools:
            arguments = _tool_call_arguments(payload)
            if arguments is None:
                return JSONResponse(
                    _json_rpc_error(payload, -32602, "Invalid finding proposal arguments"),
                    status_code=200,
                )
            try:
                async with self._proposal_lock:
                    receipt = _record_finding_proposal(
                        connector_id=self._connector_id,
                        arguments=arguments,
                        finding_root=self._finding_root,
                        deployment_manifest=self._deployment_manifest,
                    )
            except ValueError:
                return JSONResponse(
                    _json_rpc_error(payload, -32602, "Invalid finding proposal arguments"),
                    status_code=200,
                )
            except GatewayConfigurationError:
                return JSONResponse(
                    _json_rpc_error(payload, -32000, "Finding proposal recording unavailable"),
                    status_code=200,
                )
            return JSONResponse(_proposal_tool_result(payload, receipt), status_code=200)

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
                    set(self._gateway_tools),
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
    gateway_tools: list[str] | None = None,
    finding_root: Path | None = None,
    deployment_manifest: Path | None = None,
) -> Any:
    from starlette.applications import Starlette
    from starlette.routing import Route

    gateway = ExternalConnectorGateway(
        connector_id=connector_id,
        external_token=external_token,
        internal_token=internal_token,
        allowed_tools=allowed_tools,
        upstream=upstream,
        gateway_tools=gateway_tools,
        finding_root=finding_root,
        deployment_manifest=deployment_manifest,
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
        gateway_tools=list(policy.get("gateway_tools", [])),
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
