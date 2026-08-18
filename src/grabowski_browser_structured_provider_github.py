"""One explicit anonymous GitHub REST StructuredToolProvider backend.

This module is deliberately not a router.  It implements exactly one public,
credential-free, read-only provider on top of the existing StructuredToolProvider
contract and reuses that contract for effect, target, receipt and retry semantics.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from grabowski_browser_structured_tools import (
    StructuredToolContractError,
    StructuredToolProviderRegistry,
    StructuredToolReceiptError,
)

SCHEMA_VERSION = 1
PROVIDER_ID = "github.public-rest"
PROVIDER_ORIGIN = "https://api.github.com"
OPERATION = "repository.read"
EFFECT_CLASS = "read"
REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 131_072
MAX_SEGMENT_BYTES = 100
MAX_DEFAULT_BRANCH_BYTES = 255

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_JSON_CONTENT_TYPES = frozenset({"application/json", "application/vnd.github+json"})
_FIXED_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "grabowski-structured-provider-github/1",
}


class GitHubStructuredProviderError(ValueError):
    """A provider-specific target, transport, or response contract failed closed."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        effect_state: str = "not_started",
        authoritative_readback: bool = False,
        http_status: int | None = None,
        response_bytes: int | None = None,
        response_sha256: str | None = None,
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.effect_state = effect_state
        self.authoritative_readback = authoritative_readback
        self.http_status = http_status
        self.response_bytes = response_bytes
        self.response_sha256 = response_sha256


@dataclass(frozen=True)
class _HttpObservation:
    status: int
    content_type: str
    body: bytes


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8"))


def provider_spec() -> dict[str, Any]:
    """Return the one immutable-by-copy provider declaration."""
    return {
        "schema_version": SCHEMA_VERSION,
        "provider_id": PROVIDER_ID,
        "origins": [PROVIDER_ORIGIN],
        "operations": [{"operation": OPERATION, "effect_class": EFFECT_CLASS}],
    }


def provider_registry() -> StructuredToolProviderRegistry:
    """Build a fresh registry and bind the provider to the live effect catalog."""
    registry = StructuredToolProviderRegistry()
    registry.register(provider_spec())
    return registry


def provider_contract() -> dict[str, Any]:
    """Return the normalized provider contract without performing provider I/O."""
    return provider_registry().contract(PROVIDER_ID)


def _canonical_repository_target(target_url: str) -> tuple[str, str, str]:
    if not isinstance(target_url, str) or not target_url:
        raise GitHubStructuredProviderError("target_invalid", "target must be non-empty text")
    parsed = urlsplit(target_url)
    parts = parsed.path.split("/")
    if len(parts) != 4 or parts[0] or parts[1] != "repos":
        raise GitHubStructuredProviderError(
            "target_path_unsupported", "target path must be /repos/<owner>/<repo>"
        )
    owner, repository = parts[2], parts[3]
    for field, value in (("owner", owner), ("repository", repository)):
        if (
            value in {".", ".."}
            or len(value.encode("utf-8")) > MAX_SEGMENT_BYTES
            or _SEGMENT_RE.fullmatch(value) is None
        ):
            raise GitHubStructuredProviderError(
                "target_path_unsupported", f"{field} segment is not conservative"
            )
    canonical = f"{PROVIDER_ORIGIN}/repos/{owner}/{repository}"
    if target_url != canonical:
        raise GitHubStructuredProviderError(
            "target_noncanonical", "target must use the exact canonical GitHub API spelling"
        )
    return canonical, owner, repository


def assess_repository_read(target_url: str) -> dict[str, Any]:
    """Assess only the explicitly named GitHub provider and repository.read operation."""
    registry = provider_registry()
    assessment = registry.assess(PROVIDER_ID, OPERATION, target_url)
    if assessment["eligible"] is not True:
        return assessment
    try:
        _canonical_repository_target(target_url)
    except GitHubStructuredProviderError as exc:
        assessment["eligible"] = False
        assessment["result_code"] = exc.code
    return assessment


def _https_get_once(path: str) -> _HttpObservation:
    """Perform exactly one direct HTTPS GET to the fixed provider origin."""
    connection = http.client.HTTPSConnection(
        "api.github.com",
        port=443,
        timeout=REQUEST_TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )
    try:
        connection.request("GET", path, headers=dict(_FIXED_HEADERS))
        response = connection.getresponse()
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise GitHubStructuredProviderError(
                    "response_length_invalid",
                    "Content-Length is not an integer",
                    effect_state="observed",
                    authoritative_readback=False,
                    http_status=response.status,
                ) from exc
            if declared_length < 0 or declared_length > MAX_RESPONSE_BYTES:
                raise GitHubStructuredProviderError(
                    "response_too_large",
                    "declared response size exceeds the provider bound",
                    effect_state="observed",
                    authoritative_readback=False,
                    http_status=response.status,
                )
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise GitHubStructuredProviderError(
                "response_too_large",
                "response body exceeds the provider bound",
                effect_state="observed",
                authoritative_readback=False,
                http_status=response.status,
                response_bytes=len(body),
                response_sha256=_sha256_bytes(body),
            )
        return _HttpObservation(
            status=response.status,
            content_type=response.getheader("Content-Type", ""),
            body=body,
        )
    except GitHubStructuredProviderError:
        raise
    except Exception as exc:
        raise GitHubStructuredProviderError(
            "transport_error",
            "anonymous GitHub HTTPS request did not produce a bounded response",
            effect_state="unknown",
            authoritative_readback=False,
        ) from exc
    finally:
        connection.close()


def _bounded_text(value: Any, *, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise GitHubStructuredProviderError("response_schema_invalid", f"{field} is invalid")
    if len(value.encode("utf-8")) > limit or _CONTROL_RE.search(value):
        raise GitHubStructuredProviderError("response_schema_invalid", f"{field} is unbounded")
    return value


def _bounded_nonnegative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2_147_483_647:
        raise GitHubStructuredProviderError("response_schema_invalid", f"{field} is invalid")
    return value


def _repository_projection(
    payload: Any, *, expected_owner: str, expected_repository: str
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise GitHubStructuredProviderError("response_schema_invalid", "response JSON is not an object")
    owner = payload.get("owner")
    if not isinstance(owner, Mapping):
        raise GitHubStructuredProviderError("response_schema_invalid", "owner object is missing")
    owner_login = _bounded_text(owner.get("login"), field="owner.login", limit=MAX_SEGMENT_BYTES)
    name = _bounded_text(payload.get("name"), field="name", limit=MAX_SEGMENT_BYTES)
    full_name = _bounded_text(payload.get("full_name"), field="full_name", limit=205)
    default_branch = _bounded_text(
        payload.get("default_branch"), field="default_branch", limit=MAX_DEFAULT_BRANCH_BYTES
    )
    visibility = _bounded_text(payload.get("visibility"), field="visibility", limit=16)
    if visibility not in {"public", "private", "internal"}:
        raise GitHubStructuredProviderError("response_schema_invalid", "visibility is unknown")
    if owner_login.casefold() != expected_owner.casefold() or name.casefold() != expected_repository.casefold():
        raise GitHubStructuredProviderError(
            "response_target_mismatch", "response repository identity differs from the requested target"
        )
    if full_name.casefold() != f"{owner_login}/{name}".casefold():
        raise GitHubStructuredProviderError(
            "response_schema_invalid", "full_name does not match owner and repository name"
        )
    bool_fields: dict[str, bool] = {}
    for field in ("private", "fork", "archived", "disabled"):
        value = payload.get(field)
        if not isinstance(value, bool):
            raise GitHubStructuredProviderError("response_schema_invalid", f"{field} is invalid")
        bool_fields[field] = value
    return {
        "full_name": full_name,
        "owner_login": owner_login,
        "name": name,
        "default_branch": default_branch,
        "visibility": visibility,
        **bool_fields,
        "open_issues_count": _bounded_nonnegative_int(
            payload.get("open_issues_count"), field="open_issues_count"
        ),
    }


def _provider_receipt(
    assessment: Mapping[str, Any],
    *,
    ok: bool,
    result_code: str,
    effect_state: str,
    authoritative_readback: bool,
    readback: Mapping[str, Any],
) -> dict[str, Any]:
    core = {
        "schema_version": SCHEMA_VERSION,
        "kind": "structured_tool_provider_receipt",
        "provider_id": assessment["provider_id"],
        "operation": assessment["operation"],
        "effect_class": assessment["effect_class"],
        "effect_contract_sha256": assessment["effect_contract_sha256"],
        "target_sha256": assessment["target"]["target_sha256"],
        "ok": ok,
        "result_code": result_code,
        "effect_state": effect_state,
        "authoritative_readback": authoritative_readback,
        "provider_readback_sha256": _sha256_json(readback),
    }
    return {**core, "provider_receipt_sha256": _sha256_json(core)}


def _pre_effect_failure(code: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "github_structured_tool_provider_result",
        "state": "failed_closed",
        "provider_id": PROVIDER_ID,
        "operation": OPERATION,
        "ok": False,
        "result_code": code,
        "effect_state": "not_started",
        "provider_execution_performed": False,
        "automatic_route_selected": False,
        "retry_authorized": False,
        "authoritative_readback_required": True,
        "readback_grants_retry_authority": False,
    }


def _normalize_provider_result(
    registry: StructuredToolProviderRegistry,
    target_url: str,
    assessment: Mapping[str, Any],
    *,
    ok: bool,
    result_code: str,
    effect_state: str,
    authoritative_readback: bool,
    readback: Mapping[str, Any],
    repository: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = _provider_receipt(
        assessment,
        ok=ok,
        result_code=result_code,
        effect_state=effect_state,
        authoritative_readback=authoritative_readback,
        readback=readback,
    )
    try:
        outcome = registry.normalize_receipt(PROVIDER_ID, OPERATION, target_url, receipt)
    except (StructuredToolContractError, StructuredToolReceiptError) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "github_structured_tool_provider_result",
            "state": "failed_closed",
            "provider_id": PROVIDER_ID,
            "operation": OPERATION,
            "ok": False,
            "result_code": "receipt_normalization_failed",
            "effect_state": effect_state,
            "provider_execution_performed": True,
            "provider_receipt": receipt,
            "automatic_route_selected": False,
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
            "normalization_error_code": exc.code,
        }
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "github_structured_tool_provider_result",
        "state": "succeeded" if ok else "failed_closed",
        "provider_id": PROVIDER_ID,
        "operation": OPERATION,
        "ok": ok,
        "result_code": result_code,
        "effect_state": effect_state,
        "provider_execution_performed": True,
        "provider_receipt": receipt,
        "outcome": outcome,
        "automatic_route_selected": False,
        "retry_authorized": False,
        "authoritative_readback_required": True,
        "readback_grants_retry_authority": False,
    }
    if repository is not None:
        result["repository"] = dict(repository)
        result["repository_sha256"] = _sha256_json(repository)
    for key in ("http_status", "response_bytes", "response_sha256"):
        if key in readback and readback[key] is not None:
            result[key] = readback[key]
    return result


def execute_repository_read(target_url: str) -> dict[str, Any]:
    """Execute exactly this provider and operation; never choose or retry a provider."""
    try:
        registry = provider_registry()
        assessment = registry.assess(PROVIDER_ID, OPERATION, target_url)
    except StructuredToolContractError as exc:
        return _pre_effect_failure(exc.code)
    if assessment["eligible"] is not True:
        return _pre_effect_failure(str(assessment["result_code"]))
    try:
        _canonical, owner, repository_name = _canonical_repository_target(target_url)
    except GitHubStructuredProviderError as exc:
        return _pre_effect_failure(exc.code)

    path = f"/repos/{owner}/{repository_name}"
    try:
        observation = _https_get_once(path)
    except GitHubStructuredProviderError as exc:
        readback = {
            "http_status": exc.http_status,
            "response_bytes": exc.response_bytes,
            "response_sha256": exc.response_sha256,
        }
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code=exc.code,
            effect_state=exc.effect_state,
            authoritative_readback=exc.authoritative_readback,
            readback=readback,
        )

    response_sha256 = _sha256_bytes(observation.body)
    readback = {
        "http_status": observation.status,
        "response_bytes": len(observation.body),
        "response_sha256": response_sha256,
    }
    if len(observation.body) > MAX_RESPONSE_BYTES:
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code="response_too_large",
            effect_state="observed",
            authoritative_readback=False,
            readback=readback,
        )
    if observation.status != 200:
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code="http_status",
            effect_state="observed",
            authoritative_readback=True,
            readback=readback,
        )
    content_type = observation.content_type.split(";", 1)[0].strip().lower()
    if content_type not in _JSON_CONTENT_TYPES:
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code="content_type_invalid",
            effect_state="observed",
            authoritative_readback=True,
            readback=readback,
        )
    try:
        payload = json.loads(observation.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code="response_json_invalid",
            effect_state="observed",
            authoritative_readback=True,
            readback=readback,
        )
    try:
        repository = _repository_projection(
            payload,
            expected_owner=owner,
            expected_repository=repository_name,
        )
    except GitHubStructuredProviderError as exc:
        return _normalize_provider_result(
            registry,
            target_url,
            assessment,
            ok=False,
            result_code=exc.code,
            effect_state="observed",
            authoritative_readback=True,
            readback=readback,
        )
    return _normalize_provider_result(
        registry,
        target_url,
        assessment,
        ok=True,
        result_code="ok",
        effect_state="observed",
        authoritative_readback=True,
        readback=readback,
        repository=repository,
    )
