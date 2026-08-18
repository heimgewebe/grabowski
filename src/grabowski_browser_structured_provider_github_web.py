"""One explicit anonymous GitHub web StructuredToolProvider backend.

This module is deliberately not a router. It implements exactly one public,
credential-free, read-only provider against canonical GitHub repository pages
and reuses the existing StructuredToolProvider contract for effect, target,
receipt and retry semantics.
"""

from __future__ import annotations

import hashlib
import http.client
from html.parser import HTMLParser
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
PROVIDER_ID = "github.public-web"
PROVIDER_ORIGIN = "https://github.com"
OPERATION = "repository.read"
EFFECT_CLASS = "read"
REQUEST_TIMEOUT_SECONDS = 10
MAX_HTML_PREFIX_BYTES = 262_144
MAX_SEGMENT_BYTES = 100

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_HTML_CONTENT_TYPES = frozenset({"text/html"})
_FIXED_HEADERS = {
    "Accept": "text/html",
    "User-Agent": "grabowski-structured-provider-github-web/1",
}
_META_REPOSITORY_NWO = "octolytics-dimension-repository_nwo"
_META_REPOSITORY_PUBLIC = "octolytics-dimension-repository_public"
_ALLOWED_META_NAMES = frozenset({_META_REPOSITORY_NWO, _META_REPOSITORY_PUBLIC})


class GitHubWebStructuredProviderError(ValueError):
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
    body_prefix: bytes


class _RepositoryMetaParser(HTMLParser):
    """Extract only two fixed public repository identity meta values."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}
        self.invalid = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() != "meta":
            return
        attributes = {key.casefold(): value for key, value in attrs if key}
        name = attributes.get("name")
        if name not in _ALLOWED_META_NAMES:
            return
        content = attributes.get("content")
        if not isinstance(content, str) or name in self.values:
            self.invalid = True
            return
        self.values[name] = content


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


def _conservative_segment(value: str, *, field: str, response: bool = False) -> str:
    code = "response_schema_invalid" if response else "target_path_unsupported"
    if (
        value in {".", ".."}
        or len(value.encode("utf-8")) > MAX_SEGMENT_BYTES
        or _SEGMENT_RE.fullmatch(value) is None
    ):
        raise GitHubWebStructuredProviderError(code, f"{field} segment is not conservative")
    return value


def _canonical_repository_target(target_url: str) -> tuple[str, str, str]:
    if not isinstance(target_url, str) or not target_url:
        raise GitHubWebStructuredProviderError("target_invalid", "target must be non-empty text")
    parsed = urlsplit(target_url)
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0]:
        raise GitHubWebStructuredProviderError(
            "target_path_unsupported", "target path must be /<owner>/<repo>"
        )
    owner = _conservative_segment(parts[1], field="owner")
    repository = _conservative_segment(parts[2], field="repository")
    canonical = f"{PROVIDER_ORIGIN}/{owner}/{repository}"
    if target_url != canonical:
        raise GitHubWebStructuredProviderError(
            "target_noncanonical", "target must use the exact canonical GitHub web spelling"
        )
    return canonical, owner, repository


def assess_repository_read(target_url: str) -> dict[str, Any]:
    """Assess only the explicitly named web provider and repository.read operation."""
    registry = provider_registry()
    assessment = registry.assess(PROVIDER_ID, OPERATION, target_url)
    if assessment["eligible"] is not True:
        return assessment
    try:
        _canonical_repository_target(target_url)
    except GitHubWebStructuredProviderError as exc:
        assessment["eligible"] = False
        assessment["result_code"] = exc.code
    return assessment


def _https_get_once(path: str) -> _HttpObservation:
    """Perform exactly one direct anonymous HTTPS GET to the fixed provider origin."""
    connection = http.client.HTTPSConnection(
        "github.com",
        port=443,
        timeout=REQUEST_TIMEOUT_SECONDS,
        context=ssl.create_default_context(),
    )
    try:
        connection.request("GET", path, headers=dict(_FIXED_HEADERS))
        response = connection.getresponse()
        body_prefix = response.read(MAX_HTML_PREFIX_BYTES)
        return _HttpObservation(
            status=response.status,
            content_type=response.getheader("Content-Type", ""),
            body_prefix=body_prefix,
        )
    except Exception as exc:
        raise GitHubWebStructuredProviderError(
            "transport_error",
            "anonymous GitHub HTTPS request did not produce a bounded response",
            effect_state="unknown",
            authoritative_readback=False,
        ) from exc
    finally:
        connection.close()


def _repository_projection(
    body_prefix: bytes, *, expected_owner: str, expected_repository: str
) -> dict[str, Any]:
    try:
        html = body_prefix.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubWebStructuredProviderError(
            "response_html_invalid", "HTML prefix is not valid UTF-8"
        ) from exc
    parser = _RepositoryMetaParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        raise GitHubWebStructuredProviderError(
            "response_html_invalid", "HTML prefix could not be parsed conservatively"
        ) from exc
    if parser.invalid:
        raise GitHubWebStructuredProviderError(
            "response_schema_invalid", "required repository metadata is duplicated or invalid"
        )
    full_name = parser.values.get(_META_REPOSITORY_NWO)
    public = parser.values.get(_META_REPOSITORY_PUBLIC)
    if full_name is None or public is None:
        raise GitHubWebStructuredProviderError(
            "response_schema_invalid", "required repository identity metadata is missing from prefix"
        )
    if full_name.count("/") != 1:
        raise GitHubWebStructuredProviderError(
            "response_schema_invalid", "repository identity metadata is invalid"
        )
    owner_login, name = full_name.split("/", 1)
    _conservative_segment(owner_login, field="owner", response=True)
    _conservative_segment(name, field="repository", response=True)
    if (
        owner_login.casefold() != expected_owner.casefold()
        or name.casefold() != expected_repository.casefold()
    ):
        raise GitHubWebStructuredProviderError(
            "response_target_mismatch", "repository identity differs from the requested target"
        )
    if public != "true":
        raise GitHubWebStructuredProviderError(
            "repository_not_public", "repository metadata does not establish a public repository"
        )
    return {
        "full_name": full_name,
        "owner_login": owner_login,
        "name": name,
        "visibility": "public",
        "private": False,
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
        "kind": "github_web_structured_tool_provider_result",
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
            "kind": "github_web_structured_tool_provider_result",
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
        "kind": "github_web_structured_tool_provider_result",
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
    except GitHubWebStructuredProviderError as exc:
        return _pre_effect_failure(exc.code)

    path = f"/{owner}/{repository_name}"
    try:
        observation = _https_get_once(path)
    except GitHubWebStructuredProviderError as exc:
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

    response_sha256 = _sha256_bytes(observation.body_prefix)
    readback = {
        "http_status": observation.status,
        "response_bytes": len(observation.body_prefix),
        "response_sha256": response_sha256,
    }
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
    if content_type not in _HTML_CONTENT_TYPES:
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
        repository = _repository_projection(
            observation.body_prefix,
            expected_owner=owner,
            expected_repository=repository_name,
        )
    except GitHubWebStructuredProviderError as exc:
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
