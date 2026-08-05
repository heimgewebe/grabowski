from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import logging
from typing import Any

import grabowski_effect_receipt as receipts


LOGGER = logging.getLogger(__name__)
MAX_INFERRED_RESOURCE_KEYS = 32
RESOURCE_FIELDS = (
    ("path", "path"),
    ("target_path", "path"),
    ("workspace", "path"),
    ("worktree", "path"),
    ("cwd", "path"),
    ("repo", "repo"),
    ("repository", "repo"),
)
LANE_FIELDS = (
    ("lane_id", "lane"),
    ("workspace_id", "workspace"),
    ("task_id", "task"),
)

AuditAppender = Callable[[dict[str, Any]], str | None]
CompletionErrorHandler = Callable[[BaseException], None]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _bounded_text(value: Any, *, maximum: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > maximum
        or any(character in normalized for character in "\r\n\x00")
    ):
        return None
    return normalized


def actor_id(arguments: Any, context: Any = None) -> str:
    data = _mapping(arguments)
    for field in ("actor_id", "controller_actor", "delegated_actor"):
        value = _bounded_text(data.get(field), maximum=256)
        if value is not None:
            return value
    client_id: Any = None
    if context is not None:
        try:
            client_id = context.client_id
        except (AttributeError, RuntimeError, ValueError):
            client_id = None
    client = _bounded_text(client_id, maximum=1024)
    if client is None:
        return "shared_unlabeled"
    digest = hashlib.sha256(client.encode("utf-8")).hexdigest()
    return f"client:{digest}"


def lane_id(arguments: Any) -> str:
    data = _mapping(arguments)
    for field, prefix in LANE_FIELDS:
        value = _bounded_text(data.get(field), maximum=384)
        if value is not None:
            return value if field == "lane_id" else f"{prefix}:{value}"
    nested = data.get("request")
    if isinstance(nested, Mapping):
        value = _bounded_text(nested.get("lane_id"), maximum=384)
        if value is not None:
            return value
    return "unbound"


def _explicit_resource_keys(data: Mapping[str, Any]) -> list[str]:
    raw = data.get("resource_keys")
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        return []
    values: list[str] = []
    for item in raw:
        value = _bounded_text(item, maximum=2048)
        if value is not None:
            values.append(value)
    return values


def resource_keys(arguments: Any) -> list[str]:
    data = _mapping(arguments)
    values = set(_explicit_resource_keys(data))
    for field, prefix in RESOURCE_FIELDS:
        value = _bounded_text(data.get(field), maximum=2048)
        if value is not None:
            values.add(f"{prefix}:{value}")
        if len(values) >= MAX_INFERRED_RESOURCE_KEYS:
            break
    return sorted(values)[:MAX_INFERRED_RESOURCE_KEYS]


def _transport_digest(evidence: Mapping[str, Any]) -> str:
    value = evidence.get("consumption_receipt_sha256")
    if not isinstance(value, str):
        raise ValueError("transport evidence is missing a consumption receipt")
    return value


def _runtime_digest(evidence: Mapping[str, Any]) -> str:
    value = evidence.get("runtime_binding_sha256")
    if not isinstance(value, str):
        raise ValueError("transport evidence is missing a runtime binding")
    return value


def admit_mutation(
    *,
    tool_name: str,
    arguments: Any,
    transport_evidence: Mapping[str, Any],
    context: Any = None,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    return receipts.admit(
        tool=tool_name,
        arguments=arguments if arguments is not None else {},
        runtime_sha256=_runtime_digest(transport_evidence),
        transport_receipt_sha256=_transport_digest(transport_evidence),
        effect_class="mutating",
        lane_id=lane_id(arguments),
        actor_id=actor_id(arguments, context),
        resource_keys=resource_keys(arguments),
        append_audit=append_audit,
    )


def success_completion_class(result: Any) -> str:
    data = _mapping(result)
    if data.get("deduplicated") is True or data.get("deduplicated_reuse") is not None:
        return "deduplicated"
    if data.get("effect_started") is True:
        return "effect_observed"
    if receipts.collect_domain_receipts(result):
        return "effect_observed"
    return "succeeded"


def _post_state(result: Any) -> Any:
    data = _mapping(result)
    for field in ("post_state", "target_state", "readback"):
        value = data.get(field)
        if value is not None:
            return value
    return None


def record_success(
    admission: Mapping[str, Any],
    result: Any,
    *,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    return receipts.complete(
        admission,
        completion_class=success_completion_class(result),
        result=result,
        post_state=_post_state(result),
        append_audit=append_audit,
    )


def record_exception(
    admission: Mapping[str, Any],
    error: BaseException,
    *,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    return receipts.complete(
        admission,
        completion_class="outcome_unknown",
        error=error,
        append_audit=append_audit,
    )


def _default_completion_error(error: BaseException) -> None:
    LOGGER.error(
        "effect completion evidence failed after tool admission: %s",
        type(error).__name__,
        exc_info=error,
    )


def record_success_best_effort(
    admission: Mapping[str, Any],
    result: Any,
    *,
    append_audit: AuditAppender | None = None,
    on_error: CompletionErrorHandler | None = None,
) -> dict[str, Any] | None:
    try:
        return record_success(admission, result, append_audit=append_audit)
    except BaseException as error:  # the domain result must remain observable
        (on_error or _default_completion_error)(error)
        return None


def record_exception_best_effort(
    admission: Mapping[str, Any],
    error: BaseException,
    *,
    append_audit: AuditAppender | None = None,
    on_error: CompletionErrorHandler | None = None,
) -> dict[str, Any] | None:
    try:
        return record_exception(admission, error, append_audit=append_audit)
    except BaseException as completion_error:  # preserve the original exception
        (on_error or _default_completion_error)(completion_error)
        return None
