from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping, Sequence
import hashlib
import logging
from pathlib import Path
import re
from typing import Any

import grabowski_effect_receipt as receipts
import grabowski_operator_fence_enforcement as fence_enforcement


LOGGER = logging.getLogger(__name__)
MAX_INFERRED_RESOURCE_KEYS = 32
MAX_LANE_RESOURCE_PROBES = 128
MAX_LANE_PATH_ANCESTORS = 16
LANE_OWNER_RE = re.compile(r"lane:([0-9a-f]{32})\Z")
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
ResourceInspector = Callable[[str], Mapping[str, Any] | None]
LaneInputsReader = Callable[[str], Mapping[str, Any]]


FENCE_ENFORCEMENT_CONFIG_KIND = fence_enforcement.FENCE_ENFORCEMENT_CONFIG_KIND
FENCE_ENFORCEMENT_CONFIG_PATH = fence_enforcement.FENCE_ENFORCEMENT_CONFIG_PATH
FENCE_ENFORCEMENT_STATE_KIND = fence_enforcement.FENCE_ENFORCEMENT_STATE_KIND
FENCE_ENFORCEMENT_STATE_PATH = fence_enforcement.FENCE_ENFORCEMENT_STATE_PATH
OperatorFenceEnforcementDenied = fence_enforcement.OperatorFenceEnforcementDenied
OperatorFenceEnforcementError = fence_enforcement.OperatorFenceEnforcementError
fence_enforcement_required = fence_enforcement.fence_enforcement_required
begin_fence_enforcement = fence_enforcement.begin_fence_enforcement
mark_fence_dispatching = fence_enforcement.mark_fence_dispatching
finish_fence_success = fence_enforcement.finish_fence_success
finish_fence_unknown = fence_enforcement.finish_fence_unknown
abort_fence_before_dispatch = fence_enforcement.abort_fence_before_dispatch


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


def lane_id(
    arguments: Any,
    *,
    resource_inspector: ResourceInspector | None = None,
    lane_inputs_reader: LaneInputsReader | None = None,
) -> str:
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
    return _implicit_lane_id(
        data,
        resource_inspector=resource_inspector,
        lane_inputs_reader=lane_inputs_reader,
    )


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


def _absolute_resource_path(resource_key: str) -> Path | None:
    if not resource_key.startswith("path:"):
        return None
    raw = resource_key[5:]
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        return None
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def _lane_resource_probe_keys(arguments: Mapping[str, Any]) -> list[str] | None:
    explicit = _explicit_resource_keys(arguments)
    if len(explicit) > MAX_INFERRED_RESOURCE_KEYS:
        return None
    probes = set(resource_keys(arguments))
    for field in ("repo", "repository"):
        raw = _bounded_text(arguments.get(field), maximum=2048)
        if raw is None:
            continue
        candidate = Path(raw).expanduser()
        if candidate.is_absolute():
            try:
                probes.add(f"path:{candidate.resolve(strict=False)}")
            except (OSError, RuntimeError):
                return None
    for resource_key in list(probes):
        path = _absolute_resource_path(resource_key)
        if path is None:
            continue
        current = path
        for _index in range(MAX_LANE_PATH_ANCESTORS):
            if str(current) == "/":
                break
            probes.add(f"path:{current}")
            parent = current.parent
            if parent == current:
                break
            current = parent
        if len(probes) > MAX_LANE_RESOURCE_PROBES:
            return None
    return sorted(probes)


def _default_resource_snapshots(
    resource_keys: Sequence[str],
) -> Mapping[str, Mapping[str, Any]]:
    import grabowski_resources as resources

    return resources.inspect_resources(resource_keys)


def _default_lane_inputs_reader(lane: str) -> Mapping[str, Any]:
    import grabowski_work_acquire as work_acquire

    return work_acquire._stored_lane_inputs(lane)


def _verified_lane_for_lease(
    lease: Mapping[str, Any],
    *,
    lane_inputs_reader: LaneInputsReader,
) -> str | None:
    owner = _bounded_text(lease.get("owner_id"), maximum=128)
    match = LANE_OWNER_RE.fullmatch(owner or "")
    if match is None:
        return None
    lane = match.group(1)
    inputs = lane_inputs_reader(lane)
    if not isinstance(inputs, Mapping):
        raise RuntimeError("work-lane inputs reader returned a non-mapping")
    if inputs.get("lane_id") != lane or inputs.get("lease_owner_id") != owner:
        raise RuntimeError("work-lane receipt identity does not match its lease owner")
    stored_resources = inputs.get("resource_keys")
    if (
        not isinstance(stored_resources, list)
        or not all(isinstance(item, str) for item in stored_resources)
        or lease.get("resource_key") not in stored_resources
    ):
        raise RuntimeError("work-lane receipt does not bind the observed lease")
    return lane


def _implicit_lane_id(
    arguments: Mapping[str, Any],
    *,
    resource_inspector: ResourceInspector | None = None,
    lane_inputs_reader: LaneInputsReader | None = None,
) -> str:
    """Resolve audit attribution only; never establish mutation authority."""
    probes = _lane_resource_probe_keys(arguments)
    if not probes:
        return "unbound"
    read_lane = lane_inputs_reader or _default_lane_inputs_reader
    candidates: set[str] = set()
    seen_leases: set[str] = set()
    try:
        snapshots = (
            None
            if resource_inspector is not None
            else _default_resource_snapshots(probes)
        )
        for resource_key in probes:
            lease = (
                resource_inspector(resource_key)
                if resource_inspector is not None
                else snapshots.get(resource_key) if snapshots is not None else None
            )
            if lease is None:
                continue
            if not isinstance(lease, Mapping) or lease.get("resource_key") != resource_key:
                return "unbound"
            observed_key = _bounded_text(lease.get("resource_key"), maximum=2048)
            if observed_key is None or observed_key in seen_leases:
                continue
            seen_leases.add(observed_key)
            owner = _bounded_text(lease.get("owner_id"), maximum=128)
            if LANE_OWNER_RE.fullmatch(owner or "") is None:
                continue
            lane = _verified_lane_for_lease(
                lease,
                lane_inputs_reader=read_lane,
            )
            if lane is None:
                continue
            candidates.add(lane)
            if len(candidates) > 1:
                return "unbound"
    except Exception:
        return "unbound"
    return next(iter(candidates)) if len(candidates) == 1 else "unbound"


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


def _shadow_observation_best_effort(
    *,
    admission: Mapping[str, Any],
    tool_name: str,
    append_audit: AuditAppender | None,
) -> None:
    try:
        import grabowski_operator_fence_shadow as fence_shadow
    except Exception as error:
        LOGGER.error(
            "operator-fence shadow import failed: %s",
            type(error).__name__,
            exc_info=error,
        )
        return None
    arguments_sha256 = admission.get("arguments_sha256")
    if not isinstance(arguments_sha256, str):
        LOGGER.error("operator-fence shadow admission hash is unavailable")
        return None
    try:
        observation = fence_shadow.observe(
            tool_name=tool_name,
            arguments_sha256=arguments_sha256,
        )
    except Exception as error:  # shadow must never gate an existing mutation
        LOGGER.error(
            "operator-fence shadow observation failed: %s",
            type(error).__name__,
            exc_info=error,
        )
        try:
            observation = fence_shadow.observation_from_error(
                tool_name=tool_name,
                arguments_sha256=arguments_sha256,
                error=error,
            )
        except Exception as fallback_error:
            LOGGER.error(
                "operator-fence shadow error observation failed: %s",
                type(fallback_error).__name__,
                exc_info=fallback_error,
            )
            return None
    if append_audit is not None and observation.get("status") != "disabled":
        try:
            append_audit(
                {
                    "timestamp_unix": admission["admitted_at_unix"],
                    "operation": "operator-fence-shadow",
                    "admission_sha256": admission["admission_sha256"],
                    "decision": observation.get("decision"),
                    "observation_sha256": observation.get("observation_sha256"),
                }
            )
        except Exception as error:  # audit correlation is also shadow-only here
            LOGGER.error(
                "operator-fence shadow audit append failed: %s",
                type(error).__name__,
                exc_info=error,
            )
    return None


def admit_mutation(
    *,
    tool_name: str,
    arguments: Any,
    transport_evidence: Mapping[str, Any] | None,
    runtime_sha256: str | None = None,
    context: Any = None,
    append_audit: AuditAppender | None = None,
    resource_inspector: ResourceInspector | None = None,
    lane_inputs_reader: LaneInputsReader | None = None,
) -> dict[str, Any]:
    if transport_evidence is None:
        if (
            not isinstance(runtime_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", runtime_sha256) is None
        ):
            raise ValueError(
                "untransported mutation admission requires one explicit runtime SHA-256"
            )
        resolved_runtime_sha256 = runtime_sha256
        transport_receipt_sha256 = None
    else:
        if runtime_sha256 is not None:
            raise ValueError(
                "runtime_sha256 override is forbidden when transport evidence exists"
            )
        resolved_runtime_sha256 = _runtime_digest(transport_evidence)
        transport_receipt_sha256 = _transport_digest(transport_evidence)
    admission = receipts.admit(
        tool=tool_name,
        arguments=arguments if arguments is not None else {},
        runtime_sha256=resolved_runtime_sha256,
        transport_receipt_sha256=transport_receipt_sha256,
        effect_class="mutating",
        lane_id=lane_id(
            arguments,
            resource_inspector=resource_inspector,
            lane_inputs_reader=lane_inputs_reader,
        ),
        actor_id=actor_id(arguments, context),
        resource_keys=resource_keys(arguments),
        append_audit=None,
    )
    if append_audit is not None:
        try:
            audit_ref = append_audit(
                {
                    "timestamp_unix": admission["admitted_at_unix"],
                    "operation": "effect-admission",
                    **{
                        key: admission.get(key)
                        for key in (
                            "schema_version", "kind", "request_id", "lane_id",
                            "actor_id", "tool", "arguments_sha256", "runtime_sha256",
                            "resource_set_sha256", "transport_receipt_sha256",
                            "effect_class", "admitted_at_unix", "admission_sha256",
                        )
                    },
                }
            )
            if isinstance(audit_ref, str):
                admission["audit_record_sha256"] = audit_ref
        except Exception as error:
            LOGGER.error(
                "effect admission audit append failed: %s",
                type(error).__name__,
                exc_info=error,
            )
    _shadow_observation_best_effort(
        admission=admission,
        tool_name=tool_name,
        append_audit=append_audit,
    )
    return admission


def _positive_deduplicated_reuse(value: Any) -> bool:
    """Return True only for the documented positive reuse signal.

    Accepted positive forms:
    - mapping with ``reused is True`` (task-start dedup shape)
    Rejected (not reuse):
    - None, False, 0, empty containers, bare True, mappings without reused=True
    """

    if not isinstance(value, Mapping):
        return False
    return value.get("reused") is True


def success_completion_class(result: Any) -> str:
    """Classify a successful domain result for completion evidence.

    ``deduplicated`` is accepted only as the boolean True.
    ``deduplicated_reuse`` is accepted only as a mapping with ``reused is True``.
    False, 0, empty, or other truthy non-document values are not reuse signals.
    """

    data = _mapping(result)
    if data.get("deduplicated") is True or _positive_deduplicated_reuse(
        data.get("deduplicated_reuse")
    ):
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


def _completion_audit_best_effort(
    completion: Mapping[str, Any],
    append_audit: AuditAppender | None,
) -> None:
    if append_audit is None:
        return
    try:
        append_audit(
            {
                "timestamp_unix": completion["completed_at_unix"],
                "operation": "effect-completion",
                **{
                    key: completion.get(key)
                    for key in (
                        "schema_version", "kind", "request_id", "admission_sha256",
                        "completion_class", "domain_receipts", "domain_receipts_sha256",
                        "post_state_observed", "post_state_sha256", "result_sha256",
                        "error_class", "error_sha256", "completed_at_unix",
                        "completion_sha256",
                    )
                },
            }
        )
    except Exception as error:
        LOGGER.error(
            "effect completion audit append failed after durable completion identity: %s",
            type(error).__name__,
            exc_info=error,
        )


def build_success_completion(admission: Mapping[str, Any], result: Any) -> dict[str, Any]:
    return receipts.complete(
        admission,
        completion_class=success_completion_class(result),
        result=result,
        post_state=_post_state(result),
        append_audit=None,
    )


def build_exception_completion(
    admission: Mapping[str, Any], error: BaseException
) -> dict[str, Any]:
    return receipts.complete(
        admission,
        completion_class="outcome_unknown",
        error=error,
        append_audit=None,
    )


def record_success_enforced(
    admission: Mapping[str, Any],
    result: Any,
    token: MutableMapping[str, Any],
    *,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    completion = build_success_completion(admission, result)
    _completion_audit_best_effort(completion, append_audit)
    try:
        finish_fence_success(token, evidence_sha256=completion["completion_sha256"])
    except Exception as error:
        LOGGER.error(
            "operator-fence terminal settlement remains pending after successful domain effect: %s",
            type(error).__name__,
            exc_info=error,
        )
    return completion


def record_exception_enforced(
    admission: Mapping[str, Any],
    error: BaseException,
    token: MutableMapping[str, Any],
    *,
    append_audit: AuditAppender | None = None,
) -> dict[str, Any]:
    completion = build_exception_completion(admission, error)
    _completion_audit_best_effort(completion, append_audit)
    try:
        finish_fence_unknown(token, evidence_sha256=completion["completion_sha256"])
    except Exception as fence_error:
        LOGGER.error(
            "operator-fence outcome-unknown settlement remains pending: %s",
            type(fence_error).__name__,
            exc_info=fence_error,
        )
    return completion


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