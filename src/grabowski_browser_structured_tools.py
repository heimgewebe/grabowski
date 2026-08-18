"""Pure StructuredToolProvider contract for the Browser Control Plane.

This module deliberately does not execute providers and does not choose a provider.
It validates immutable provider declarations, checks one explicitly named provider
against one target, and normalizes an already-produced provider receipt into the
existing conservative browser effect/readback vocabulary.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
PROVIDER_KIND = "structured_tool"
MAX_PROVIDER_ID_BYTES = 64
MAX_OPERATION_ID_BYTES = 64
MAX_EFFECT_CLASS_BYTES = 64
MAX_ORIGINS = 32
MAX_OPERATIONS = 32
MAX_RESULT_CODE_BYTES = 80

_PROVIDER_ID_RE = re.compile(r"[a-z][a-z0-9.-]{0,63}")
_OPERATION_ID_RE = re.compile(r"[a-z][a-z0-9._-]{0,63}")
_EFFECT_CLASS_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_RESULT_CODE_RE = re.compile(r"[a-z][a-z0-9._-]{0,79}")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_EFFECT_STATES = frozenset({"not_started", "not_applicable", "observed", "unknown"})
_EFFECT_ADMISSIONS = frozenset({"implemented", "fail_closed"})

EffectResolver = Callable[[str], Mapping[str, Any] | None]


class StructuredToolContractError(ValueError):
    """A provider, target, or effect contract is invalid."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class StructuredToolReceiptError(ValueError):
    """A caller-supplied provider receipt is not bound to the requested contract."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_text(_canonical_json(value))


def _bounded_identifier(value: Any, *, field: str, pattern: re.Pattern[str], limit: int) -> str:
    if not isinstance(value, str) or not value:
        raise StructuredToolContractError("identifier-invalid", f"{field} must be non-empty text")
    if len(value.encode("utf-8")) > limit or pattern.fullmatch(value) is None:
        raise StructuredToolContractError("identifier-invalid", f"{field} is not canonical")
    return value


def _canonical_host(hostname: str) -> tuple[str, bool]:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            canonical = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise StructuredToolContractError("url-invalid", "hostname is not valid IDNA") from exc
        if not canonical or len(canonical.encode("ascii")) > 253:
            raise StructuredToolContractError("url-invalid", "hostname is not bounded")
        labels = canonical.split(".")
        if any(
            not label
            or len(label) > 63
            or _DNS_LABEL_RE.fullmatch(label) is None
            for label in labels
        ):
            raise StructuredToolContractError("url-invalid", "hostname labels are invalid")
        return canonical, False
    return address.compressed.lower(), address.version == 6


def _url_parts(value: Any) -> tuple[str, str, int | None, bool, str, str, str]:
    if not isinstance(value, str) or not value:
        raise StructuredToolContractError("url-invalid", "URL must be non-empty text")
    if len(value.encode("utf-8")) > 4096:
        raise StructuredToolContractError("url-invalid", "URL is too large")
    if _CONTROL_OR_SPACE_RE.search(value) or "\\" in value:
        raise StructuredToolContractError("url-invalid", "URL contains forbidden characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise StructuredToolContractError("url-invalid", "URL port is invalid") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise StructuredToolContractError("url-invalid", "URL scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise StructuredToolContractError("url-invalid", "URL userinfo is forbidden")
    if not parsed.hostname:
        raise StructuredToolContractError("url-invalid", "URL hostname is required")
    host, ipv6 = _canonical_host(parsed.hostname)
    if port is not None and not 1 <= port <= 65535:
        raise StructuredToolContractError("url-invalid", "URL port is out of range")
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    return scheme, host, port, ipv6, parsed.path, parsed.query, parsed.fragment


def _authority(scheme: str, host: str, port: int | None, ipv6: bool) -> str:
    rendered_host = f"[{host}]" if ipv6 else host
    suffix = "" if port is None else f":{port}"
    return f"{scheme}://{rendered_host}{suffix}"


def canonical_origin(value: Any) -> str:
    scheme, host, port, ipv6, path, query, fragment = _url_parts(value)
    if path or query or fragment:
        raise StructuredToolContractError(
            "origin-invalid", "provider origins must not contain path, query, or fragment"
        )
    canonical = _authority(scheme, host, port, ipv6)
    if value != canonical:
        raise StructuredToolContractError("origin-noncanonical", "provider origin is not canonical")
    return canonical


def _target_binding(value: Any) -> dict[str, str]:
    scheme, host, port, ipv6, path, query, fragment = _url_parts(value)
    if query or fragment:
        raise StructuredToolContractError(
            "target-query-fragment-unsupported",
            "structured provider v1 rejects target query and fragment data",
        )
    origin = _authority(scheme, host, port, ipv6)
    canonical_path = path or "/"
    if not canonical_path.startswith("/"):
        raise StructuredToolContractError("url-invalid", "target path is not absolute")
    canonical_target = origin + canonical_path
    return {
        "target_sha256": _sha256_text(canonical_target),
        "origin_sha256": _sha256_text(origin),
        "path_sha256": _sha256_text(canonical_path),
        "origin": origin,
    }


def _default_effect_resolver(effect_class: str) -> Mapping[str, Any] | None:
    try:
        module = importlib.import_module("grabowski_workers")
    except Exception as exc:  # Runtime availability is an authority precondition.
        raise StructuredToolContractError(
            "effect-catalog-unavailable", "authoritative browser effect catalog is unavailable"
        ) from exc
    catalog = getattr(module, "BROWSER_EFFECT_CONTRACTS", None)
    if not isinstance(catalog, Mapping):
        raise StructuredToolContractError(
            "effect-catalog-unavailable", "authoritative browser effect catalog is invalid"
        )
    raw = catalog.get(effect_class)
    return raw if isinstance(raw, Mapping) else None


def _effect_contract(effect_class: str, resolver: EffectResolver) -> dict[str, Any]:
    effect = _bounded_identifier(
        effect_class,
        field="effect_class",
        pattern=_EFFECT_CLASS_RE,
        limit=MAX_EFFECT_CLASS_BYTES,
    )
    try:
        raw = resolver(effect)
    except StructuredToolContractError:
        raise
    except Exception as exc:
        raise StructuredToolContractError(
            "effect-catalog-unavailable", "effect resolver failed"
        ) from exc
    if not isinstance(raw, Mapping):
        raise StructuredToolContractError("effect-unknown", f"effect class {effect!r} is unknown")
    admission = raw.get("admission")
    requires_mutation = raw.get("requires_operator_mutation")
    ambiguous = raw.get("ambiguous_outcome")
    if admission not in _EFFECT_ADMISSIONS or not isinstance(requires_mutation, bool):
        raise StructuredToolContractError("effect-contract-invalid", "effect contract is incomplete")
    if not isinstance(ambiguous, Mapping):
        raise StructuredToolContractError("effect-contract-invalid", "ambiguity contract is missing")
    if (
        ambiguous.get("retry_authorized") is not False
        or ambiguous.get("authoritative_readback_required") is not True
        or ambiguous.get("readback_grants_retry_authority") is not False
    ):
        raise StructuredToolContractError(
            "effect-contract-invalid", "effect ambiguity contract is not conservative"
        )
    projection = {
        "effect_class": effect,
        "admission": admission,
        "requires_operator_mutation": requires_mutation,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    }
    projection["effect_contract_sha256"] = _sha256_json(projection)
    return projection


def normalize_provider_spec(
    spec: Mapping[str, Any], *, effect_resolver: EffectResolver | None = None
) -> dict[str, Any]:
    if not isinstance(spec, Mapping):
        raise StructuredToolContractError("provider-invalid", "provider spec must be an object")
    allowed = {"schema_version", "provider_id", "origins", "operations"}
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise StructuredToolContractError(
            "provider-fields-unknown", "provider spec contains unknown fields: " + ", ".join(unknown)
        )
    if spec.get("schema_version") != SCHEMA_VERSION:
        raise StructuredToolContractError("provider-schema", "unsupported provider schema")
    provider_id = _bounded_identifier(
        spec.get("provider_id"),
        field="provider_id",
        pattern=_PROVIDER_ID_RE,
        limit=MAX_PROVIDER_ID_BYTES,
    )
    origins_raw = spec.get("origins")
    if not isinstance(origins_raw, list) or not 1 <= len(origins_raw) <= MAX_ORIGINS:
        raise StructuredToolContractError("provider-origins", "provider origins are missing or unbounded")
    origins = [canonical_origin(item) for item in origins_raw]
    if len(set(origins)) != len(origins):
        raise StructuredToolContractError("provider-origins", "provider origins contain duplicates")

    operations_raw = spec.get("operations")
    if not isinstance(operations_raw, list) or not 1 <= len(operations_raw) <= MAX_OPERATIONS:
        raise StructuredToolContractError(
            "provider-operations", "provider operations are missing or unbounded"
        )
    resolver = effect_resolver or _default_effect_resolver
    operations: list[dict[str, str]] = []
    seen_operations: set[str] = set()
    for item in operations_raw:
        if not isinstance(item, Mapping) or set(item) != {"operation", "effect_class"}:
            raise StructuredToolContractError(
                "provider-operation-invalid", "operation entries require only operation and effect_class"
            )
        operation = _bounded_identifier(
            item.get("operation"),
            field="operation",
            pattern=_OPERATION_ID_RE,
            limit=MAX_OPERATION_ID_BYTES,
        )
        if operation in seen_operations:
            raise StructuredToolContractError(
                "provider-operation-duplicate", f"operation {operation!r} is duplicated"
            )
        effect_class = _bounded_identifier(
            item.get("effect_class"),
            field="effect_class",
            pattern=_EFFECT_CLASS_RE,
            limit=MAX_EFFECT_CLASS_BYTES,
        )
        _effect_contract(effect_class, resolver)
        seen_operations.add(operation)
        operations.append({"operation": operation, "effect_class": effect_class})

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "kind": "structured_tool_provider_contract",
        "provider_id": provider_id,
        "origins": sorted(origins),
        "operations": sorted(operations, key=lambda entry: entry["operation"]),
        "provider_execution_available": False,
        "automatic_routing_available": False,
    }
    normalized["contract_sha256"] = _sha256_json(normalized)
    return normalized


def _copy_json(value: Any) -> Any:
    return json.loads(_canonical_json(value))


class StructuredToolProviderRegistry:
    """In-memory contract registry with explicit-provider operations only.

    The registry stores declarations only.  It owns no sessions, leases, provider
    callables, routing state, retry state, or persistence.
    """

    def __init__(self, *, effect_resolver: EffectResolver | None = None) -> None:
        self._effect_resolver = effect_resolver or _default_effect_resolver
        self._providers: dict[str, dict[str, Any]] = {}

    def register(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        normalized = normalize_provider_spec(spec, effect_resolver=self._effect_resolver)
        provider_id = normalized["provider_id"]
        if provider_id in self._providers:
            raise StructuredToolContractError(
                "provider-duplicate", f"provider {provider_id!r} is already registered"
            )
        self._providers[provider_id] = normalized
        return _copy_json(normalized)

    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def contract(self, provider_id: str) -> dict[str, Any]:
        checked = _bounded_identifier(
            provider_id,
            field="provider_id",
            pattern=_PROVIDER_ID_RE,
            limit=MAX_PROVIDER_ID_BYTES,
        )
        try:
            provider = self._providers[checked]
        except KeyError as exc:
            raise StructuredToolContractError(
                "provider-unknown", f"provider {checked!r} is not registered"
            ) from exc
        return _copy_json(provider)

    def assess(self, provider_id: str, operation: str, target_url: str) -> dict[str, Any]:
        provider = self.contract(provider_id)
        checked_operation = _bounded_identifier(
            operation,
            field="operation",
            pattern=_OPERATION_ID_RE,
            limit=MAX_OPERATION_ID_BYTES,
        )
        target = _target_binding(target_url)
        operation_spec = next(
            (entry for entry in provider["operations"] if entry["operation"] == checked_operation),
            None,
        )
        effect: dict[str, Any] | None = None
        if operation_spec is None:
            eligible = False
            result_code = "operation_unsupported"
        else:
            effect = _effect_contract(operation_spec["effect_class"], self._effect_resolver)
            if target["origin"] not in provider["origins"]:
                eligible = False
                result_code = "target_out_of_scope"
            elif effect["admission"] != "implemented":
                eligible = False
                result_code = "effect_fail_closed"
            else:
                eligible = True
                result_code = "eligible"
        public_target = {
            "target_sha256": target["target_sha256"],
            "origin_sha256": target["origin_sha256"],
            "path_sha256": target["path_sha256"],
        }
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "structured_tool_provider_eligibility",
            "provider_id": provider["provider_id"],
            "provider_contract_sha256": provider["contract_sha256"],
            "operation": checked_operation,
            "effect_class": None if effect is None else effect["effect_class"],
            "effect_contract_sha256": (
                None if effect is None else effect["effect_contract_sha256"]
            ),
            "effect_admission": None if effect is None else effect["admission"],
            "requires_operator_mutation": (
                None if effect is None else effect["requires_operator_mutation"]
            ),
            "target": public_target,
            "eligible": eligible,
            "result_code": result_code,
            "provider_execution_performed": False,
            "automatic_route_selected": False,
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
            "does_not_establish": [
                "provider execution",
                "provider availability",
                "automatic provider routing",
                "browser session authority",
                "retry authority",
                "target effect correctness",
            ],
        }

    def normalize_receipt(
        self,
        provider_id: str,
        operation: str,
        target_url: str,
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        assessment = self.assess(provider_id, operation, target_url)
        if assessment["eligible"] is not True:
            raise StructuredToolReceiptError(
                "provider-not-eligible", f"eligibility result is {assessment['result_code']}"
            )
        if not isinstance(receipt, Mapping):
            raise StructuredToolReceiptError("receipt-invalid", "provider receipt must be an object")
        required = {
            "schema_version",
            "kind",
            "provider_id",
            "operation",
            "effect_class",
            "effect_contract_sha256",
            "target_sha256",
            "ok",
            "result_code",
            "effect_state",
            "authoritative_readback",
            "provider_receipt_sha256",
        }
        missing = sorted(required - set(receipt))
        if missing:
            raise StructuredToolReceiptError(
                "receipt-missing", "provider receipt misses fields: " + ", ".join(missing)
            )
        if receipt.get("schema_version") != SCHEMA_VERSION or receipt.get("kind") != "structured_tool_provider_receipt":
            raise StructuredToolReceiptError("receipt-schema", "provider receipt schema is invalid")
        bindings = {
            "provider_id": assessment["provider_id"],
            "operation": assessment["operation"],
            "effect_class": assessment["effect_class"],
            "effect_contract_sha256": assessment["effect_contract_sha256"],
            "target_sha256": assessment["target"]["target_sha256"],
        }
        mismatched = sorted(key for key, value in bindings.items() if receipt.get(key) != value)
        if mismatched:
            raise StructuredToolReceiptError(
                "receipt-binding", "provider receipt binding mismatch: " + ", ".join(mismatched)
            )
        ok = receipt.get("ok")
        authoritative_readback = receipt.get("authoritative_readback")
        if not isinstance(ok, bool) or not isinstance(authoritative_readback, bool):
            raise StructuredToolReceiptError("receipt-invalid", "receipt booleans are invalid")
        result_code = receipt.get("result_code")
        if (
            not isinstance(result_code, str)
            or len(result_code.encode("utf-8")) > MAX_RESULT_CODE_BYTES
            or _RESULT_CODE_RE.fullmatch(result_code) is None
        ):
            raise StructuredToolReceiptError("receipt-invalid", "result_code is invalid")
        if (ok and result_code != "ok") or (not ok and result_code == "ok"):
            raise StructuredToolReceiptError("receipt-invalid", "ok and result_code disagree")
        effect_state = receipt.get("effect_state")
        if effect_state not in _EFFECT_STATES:
            raise StructuredToolReceiptError("receipt-invalid", "effect_state is invalid")
        if ok and effect_state not in {"observed", "not_applicable"}:
            raise StructuredToolReceiptError(
                "receipt-invalid", "successful receipt lacks a terminal observed state"
            )
        if ok and authoritative_readback is not True:
            raise StructuredToolReceiptError(
                "receipt-invalid", "successful receipt lacks authoritative readback"
            )
        provider_receipt_sha256 = receipt.get("provider_receipt_sha256")
        if not isinstance(provider_receipt_sha256, str) or _SHA256_RE.fullmatch(provider_receipt_sha256) is None:
            raise StructuredToolReceiptError(
                "receipt-invalid", "provider_receipt_sha256 is invalid"
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "structured_tool_outcome",
            "provider_id": assessment["provider_id"],
            "provider_contract_sha256": assessment["provider_contract_sha256"],
            "operation": assessment["operation"],
            "effect_class": assessment["effect_class"],
            "effect_contract_sha256": assessment["effect_contract_sha256"],
            "target": assessment["target"],
            "ok": ok,
            "result_code": result_code,
            "effect_state": effect_state,
            "authoritative_readback_observed": authoritative_readback,
            "provider_receipt_sha256": provider_receipt_sha256,
            "normalizer_execution_performed": False,
            "automatic_route_selected": False,
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
            "does_not_establish": [
                "provider receipt authenticity",
                "provider effect correctness",
                "provider execution authority",
                "automatic provider routing",
                "permission to retry",
                "browser session authority",
            ],
        }
