from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import json
import re
import time
from typing import Any
import uuid


SCHEMA_VERSION = 1
ADMISSION_KIND = "grabowski.effect_admission"
COMPLETION_KIND = "grabowski.effect_completion"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
EFFECT_CLASSES = frozenset({"read_only", "mutating"})
COMPLETION_CLASSES = frozenset(
    {
        "succeeded",
        "rejected_before_effect",
        "failed_before_effect",
        "effect_observed",
        "outcome_unknown",
        "deduplicated",
    }
)
MAX_DOMAIN_RECEIPTS = 64
MAX_RECEIPT_SCAN_DEPTH = 6
MAX_IDENTITY_LENGTH = 256

AuditAppender = Callable[[dict[str, Any]], str | None]


class EffectReceiptError(RuntimeError):
    pass


class EffectReceiptIntegrityError(EffectReceiptError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _identity(value: Any, field: str, *, default: str | None = None) -> str:
    if value is None and default is not None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_IDENTITY_LENGTH:
        raise ValueError(f"{field} must be a bounded non-empty string")
    if any(character in normalized for character in "\r\n\x00"):
        raise ValueError(f"{field} contains an invalid control character")
    return normalized


def _request_id(value: Any | None) -> str:
    if value is None:
        return uuid.uuid4().hex
    if not isinstance(value, str) or REQUEST_ID.fullmatch(value) is None:
        raise ValueError("request_id must be 32 lowercase hexadecimal characters")
    return value


def _timestamp(value: int | None) -> int:
    result = int(time.time()) if value is None else value
    if isinstance(result, bool) or not isinstance(result, int) or result < 0:
        raise ValueError("timestamp must be a non-negative integer")
    return result


def normalize_resource_keys(resource_keys: Sequence[str] | None) -> list[str]:
    if resource_keys is None:
        return []
    if isinstance(resource_keys, (str, bytes)):
        raise ValueError("resource_keys must be a sequence of strings")
    normalized: set[str] = set()
    for value in resource_keys:
        normalized.add(_identity(value, "resource_key"))
    return sorted(normalized)


def _audit_ref(value: Any) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, "audit_ref")


def admit(
    *,
    tool: str,
    arguments: Any,
    runtime_sha256: str,
    effect_class: str,
    lane_id: str | None = None,
    actor_id: str | None = None,
    resource_keys: Sequence[str] | None = None,
    transport_receipt_sha256: str | None = None,
    request_id: str | None = None,
    admitted_at_unix: int | None = None,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    """Create one thin admission correlation record.

    The record is evidence only. It grants no tool, lane, resource, retry, or
    integration authority and does not replace any domain lifecycle.
    """

    normalized_effect_class = _identity(effect_class, "effect_class")
    if normalized_effect_class not in EFFECT_CLASSES:
        raise ValueError(f"unsupported effect_class: {normalized_effect_class}")
    normalized_resources = normalize_resource_keys(resource_keys)
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": ADMISSION_KIND,
        "request_id": _request_id(request_id),
        "lane_id": _identity(lane_id, "lane_id", default="unbound"),
        "actor_id": _identity(
            actor_id, "actor_id", default="shared_unlabeled"
        ),
        "tool": _identity(tool, "tool"),
        "arguments_sha256": sha256_json(arguments),
        "runtime_sha256": _require_sha256(runtime_sha256, "runtime_sha256"),
        "resource_set_sha256": sha256_json(normalized_resources),
        "transport_receipt_sha256": (
            _require_sha256(
                transport_receipt_sha256, "transport_receipt_sha256"
            )
            if transport_receipt_sha256 is not None
            else None
        ),
        "effect_class": normalized_effect_class,
        "admitted_at_unix": _timestamp(admitted_at_unix),
    }
    admission_sha256 = sha256_json(material)
    audit_record_sha256: str | None = None
    if append_audit is not None:
        audit_record_sha256 = _audit_ref(
            append_audit(
                {
                    "timestamp_unix": material["admitted_at_unix"],
                    "operation": "effect-admission",
                    **material,
                    "admission_sha256": admission_sha256,
                }
            )
        )
    return {
        **material,
        "admission_sha256": admission_sha256,
        "audit_record_sha256": audit_record_sha256,
        "does_not_establish": [
            "execution_authority",
            "effect_success",
            "domain_lifecycle_state",
            "safe_retry_after_response_loss",
        ],
    }


def validate_admission(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EffectReceiptIntegrityError("admission must be an object")
    required = {
        "schema_version",
        "kind",
        "request_id",
        "lane_id",
        "actor_id",
        "tool",
        "arguments_sha256",
        "runtime_sha256",
        "resource_set_sha256",
        "transport_receipt_sha256",
        "effect_class",
        "admitted_at_unix",
        "admission_sha256",
    }
    missing = sorted(required - set(value))
    if missing:
        raise EffectReceiptIntegrityError(
            f"admission is missing required fields: {', '.join(missing)}"
        )
    material = {key: value[key] for key in required if key != "admission_sha256"}
    if material["schema_version"] != SCHEMA_VERSION:
        raise EffectReceiptIntegrityError("admission schema version is unsupported")
    if material["kind"] != ADMISSION_KIND:
        raise EffectReceiptIntegrityError("admission kind is invalid")
    _request_id(material["request_id"])
    _identity(material["lane_id"], "lane_id")
    _identity(material["actor_id"], "actor_id")
    _identity(material["tool"], "tool")
    _require_sha256(material["arguments_sha256"], "arguments_sha256")
    _require_sha256(material["runtime_sha256"], "runtime_sha256")
    _require_sha256(material["resource_set_sha256"], "resource_set_sha256")
    if material["transport_receipt_sha256"] is not None:
        _require_sha256(
            material["transport_receipt_sha256"],
            "transport_receipt_sha256",
        )
    if material["effect_class"] not in EFFECT_CLASSES:
        raise EffectReceiptIntegrityError("admission effect_class is invalid")
    _timestamp(material["admitted_at_unix"])
    claimed = _require_sha256(value["admission_sha256"], "admission_sha256")
    if sha256_json(material) != claimed:
        raise EffectReceiptIntegrityError("admission digest mismatch")
    return dict(value)


def _receipt_digest_key(key: str) -> bool:
    normalized = key.lower()
    return normalized.endswith("_sha256") and (
        "receipt" in normalized
        or "transaction" in normalized
        or "effect" in normalized
        or "terminalization" in normalized
    )


def collect_domain_receipts(value: Any) -> list[str]:
    """Collect bounded digest references without retaining arbitrary result data."""

    receipts: set[str] = set()

    def visit(current: Any, depth: int) -> None:
        if depth > MAX_RECEIPT_SCAN_DEPTH or len(receipts) >= MAX_DOMAIN_RECEIPTS:
            return
        if isinstance(current, Mapping):
            for raw_key, item in current.items():
                if len(receipts) >= MAX_DOMAIN_RECEIPTS:
                    return
                if isinstance(raw_key, str) and _receipt_digest_key(raw_key):
                    if isinstance(item, str) and SHA256.fullmatch(item):
                        receipts.add(item)
                if isinstance(item, (Mapping, list, tuple)):
                    visit(item, depth + 1)
            return
        if isinstance(current, (list, tuple)):
            for item in current:
                if len(receipts) >= MAX_DOMAIN_RECEIPTS:
                    return
                if isinstance(item, (Mapping, list, tuple)):
                    visit(item, depth + 1)

    visit(value, 0)
    return sorted(receipts)


def _normalize_domain_receipts(
    explicit: Sequence[str] | None,
    result: Any,
) -> list[str]:
    values = set(collect_domain_receipts(result))
    if explicit is not None:
        if isinstance(explicit, (str, bytes)):
            raise ValueError("domain_receipts must be a sequence")
        for value in explicit:
            values.add(_require_sha256(value, "domain_receipt"))
    if len(values) > MAX_DOMAIN_RECEIPTS:
        raise ValueError("too many domain receipts")
    return sorted(values)


def _safe_result_sha256(result: Any) -> str | None:
    if result is None:
        return None
    try:
        return sha256_json(result)
    except (TypeError, ValueError):
        return None


def complete(
    admission: Mapping[str, Any],
    *,
    completion_class: str,
    result: Any = None,
    domain_receipts: Sequence[str] | None = None,
    post_state: Any = None,
    error: BaseException | None = None,
    completed_at_unix: int | None = None,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    validated = validate_admission(admission)
    normalized_class = _identity(completion_class, "completion_class")
    if normalized_class not in COMPLETION_CLASSES:
        raise ValueError(f"unsupported completion_class: {normalized_class}")
    completed_at = _timestamp(completed_at_unix)
    if completed_at < validated["admitted_at_unix"]:
        raise ValueError("completion predates admission")
    receipts = _normalize_domain_receipts(domain_receipts, result)
    post_state_observed = post_state is not None
    post_state_sha256 = sha256_json(
        post_state if post_state_observed else {"state": "not_observed"}
    )
    error_class = type(error).__name__ if error is not None else None
    error_sha256 = (
        hashlib.sha256(str(error).encode("utf-8", errors="replace")).hexdigest()
        if error is not None
        else None
    )
    material = {
        "schema_version": SCHEMA_VERSION,
        "kind": COMPLETION_KIND,
        "request_id": validated["request_id"],
        "admission_sha256": validated["admission_sha256"],
        "completion_class": normalized_class,
        "domain_receipts": receipts,
        "domain_receipts_sha256": sha256_json(receipts),
        "post_state_observed": post_state_observed,
        "post_state_sha256": post_state_sha256,
        "result_sha256": _safe_result_sha256(result),
        "error_class": error_class,
        "error_sha256": error_sha256,
        "completed_at_unix": completed_at,
    }
    completion_sha256 = sha256_json(material)
    audit_record_sha256: str | None = None
    if append_audit is not None:
        audit_record_sha256 = _audit_ref(
            append_audit(
                {
                    "timestamp_unix": completed_at,
                    "operation": "effect-completion",
                    **material,
                    "completion_sha256": completion_sha256,
                }
            )
        )
    return {
        **material,
        "completion_sha256": completion_sha256,
        "audit_record_sha256": audit_record_sha256,
        "does_not_establish": [
            "a_second_domain_lifecycle",
            "safe_retry_when_completion_is_outcome_unknown",
            "authority_for_another_request",
        ],
    }


def exception_completion_class(
    *,
    effect_started: bool,
    rejected: bool = False,
) -> str:
    if effect_started:
        return "outcome_unknown"
    return "rejected_before_effect" if rejected else "failed_before_effect"
