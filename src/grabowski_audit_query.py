from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

import grabowski_mcp as base
import grabowski_operator_core as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

MAX_QUERY_LIMIT = 200
MAX_TRACE_LIMIT = 200
MAX_TOP_VALUES = 50
MAX_CORRELATION_VALUES = 64

_SAFE_RECORD_FIELDS = (
    "timestamp",
    "timestamp_unix",
    "operation",
    "task_id",
    "owner_id",
    "transaction_id",
    "host",
    "unit",
    "authoritative_unit",
    "execution_backend",
    "transport",
    "systemd_scope",
    "path",
    "repo",
    "service",
    "branch",
    "head",
    "commit",
    "release_id",
    "returncode",
    "launcher_returncode",
    "launcher_outcome_unknown",
    "recovery_required",
    "recovery_checked_at_unix",
    "resource_keys",
    "requested_resource_keys",
    "resource_lease_expires_at_unix",
    "record_sha256",
    "previous_record_sha256",
    "sequence",
    "audit_schema_version",
)

_EXACT_FILTER_FIELDS = {
    "operation",
    "task_id",
    "owner_id",
    "transaction_id",
    "host",
    "unit",
    "authoritative_unit",
    "path",
    "repo",
    "service",
    "branch",
}

_TRACE_SCALAR_FIELDS = (
    "task_id",
    "owner_id",
    "transaction_id",
    "unit",
    "authoritative_unit",
    "path",
    "repo",
    "branch",
)

_TRACE_ANCHOR_KINDS = {
    "record_sha256",
    "task_id",
    "owner_id",
    "transaction_id",
    "resource_key",
    "unit",
    "path",
}


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _bounded_positive_int(value: Any, *, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be between 1 and {maximum}")
    return value


def _bounded_nonempty_text(value: Any, *, label: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty string of at most {maximum} characters")
    return value


def _sha256_text(value: Any, *, label: str) -> str:
    text = _bounded_nonempty_text(value, label=label, maximum=64)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return text


def _validate_filters(filters: dict[str, Any]) -> None:
    for key, expected in filters.items():
        if key in _EXACT_FILTER_FIELDS:
            _bounded_nonempty_text(expected, label=f"filters.{key}")
        elif key == "operation_prefix":
            _bounded_nonempty_text(expected, label="filters.operation_prefix", maximum=256)
        elif key == "resource_key":
            _bounded_nonempty_text(expected, label="filters.resource_key")
        elif key == "record_sha256":
            _sha256_text(expected, label="filters.record_sha256")
        elif key in {"since_unix", "until_unix"}:
            if not isinstance(expected, int) or isinstance(expected, bool):
                raise ValueError(f"filters.{key} must be an integer")
        elif key == "has_failure_signal":
            if not isinstance(expected, bool):
                raise ValueError("filters.has_failure_signal must be a boolean")
        else:
            raise ValueError(f"Unsupported audit query filter: {key}")
    since = filters.get("since_unix")
    until = filters.get("until_unix")
    if isinstance(since, int) and isinstance(until, int) and since > until:
        raise ValueError("filters.since_unix must be less than or equal to filters.until_unix")


def _safe_record_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list) and len(value) <= 256:
        if all(item is None or isinstance(item, (str, int, float, bool)) for item in value):
            return list(value)
    if isinstance(value, dict) and len(value) <= 64:
        safe: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                continue
            if item is None or isinstance(item, (str, int, float, bool)):
                safe[key] = item
        return safe
    return None


def _project_record(record: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for key in _SAFE_RECORD_FIELDS:
        if key not in record:
            continue
        safe = _safe_record_value(record[key])
        if safe is not None:
            projected[key] = safe
    return projected


def _record_evidence_digest(record: dict[str, Any], raw_line: bytes) -> str:
    stored = record.get("record_sha256")
    if (
        isinstance(stored, str)
        and len(stored) == 64
        and all(char in "0123456789abcdef" for char in stored)
    ):
        return stored
    return hashlib.sha256(raw_line).hexdigest()


def build_audit_projection(path: Path | None = None) -> dict[str, Any]:
    """Build a discardable, evidence-bound projection from the verified audit chain."""
    active_path = path if path is not None else base.AUDIT_LOG
    with base._audit_coordination_lock(active_path, exclusive=False):
        components, compatibility = base._read_audit_chain_unlocked(
            active_path,
            use_segment_cache=False,
        )
        ordered_components = list(reversed(components))
        segment_evidence: list[dict[str, Any]] = []
        items: list[dict[str, Any]] = []
        global_ordinal = 0
        for segment_ordinal, (segment_path, data, status) in enumerate(
            ordered_components,
            start=1,
        ):
            segment_sha256 = hashlib.sha256(data).hexdigest()
            segment_evidence.append(
                {
                    "segment_ordinal": segment_ordinal,
                    "path": str(segment_path),
                    "sha256": segment_sha256,
                    "bytes": len(data),
                    "records": status["records"],
                    "legacy_records": status["legacy_records"],
                    "v2_records": status["v2_records"],
                    "last_record_sha256": status["last_record_sha256"],
                }
            )
            for record_ordinal, raw_line in enumerate(data.splitlines(), start=1):
                parsed = json.loads(raw_line.decode("utf-8"))
                if not isinstance(parsed, dict):
                    raise RuntimeError("Verified audit chain yielded a non-object record")
                global_ordinal += 1
                digest = _record_evidence_digest(parsed, raw_line)
                items.append(
                    {
                        "audit_ref": f"audit-record-sha256:{digest}",
                        "evidence": {
                            "record_sha256": digest,
                            "stored_record_sha256": parsed.get("record_sha256"),
                            "legacy_record": parsed.get("record_sha256") is None,
                            "segment_path": str(segment_path),
                            "segment_sha256": segment_sha256,
                            "segment_ordinal": segment_ordinal,
                            "record_ordinal": record_ordinal,
                            "global_ordinal": global_ordinal,
                        },
                        "record": _project_record(parsed),
                    }
                )

    chain_fingerprint = hashlib.sha256(_canonical_json_bytes(segment_evidence)).hexdigest()
    active_status = components[0][2] if components else {}
    return {
        "schema_version": 1,
        "kind": "grabowski_audit_projection",
        "authority": "derived_from_verified_audit_chain",
        "source": {
            "active_path": str(active_path),
            "chain_fingerprint_sha256": chain_fingerprint,
            "last_record_sha256": active_status.get("last_record_sha256"),
            "total_records": len(items),
            "archived_segment_count": max(0, len(components) - 1),
            "legacy_rotation_compatibility": compatibility,
            "segments": segment_evidence,
        },
        "items": items,
        "does_not_establish": [
            "causality",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "external_state_not_recorded_by_grabowski",
            "future_action_authority",
        ],
    }


def _resource_values(record: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for key in ("resource_keys", "requested_resource_keys"):
        raw = record.get(key)
        if isinstance(raw, list):
            values.update(item for item in raw if isinstance(item, str))
    return values


def _record_matches_filters(item: dict[str, Any], filters: dict[str, Any]) -> bool:
    record = item["record"]
    evidence = item["evidence"]
    for key, expected in filters.items():
        if key in _EXACT_FILTER_FIELDS:
            expected_text = _bounded_nonempty_text(expected, label=f"filters.{key}")
            if record.get(key) != expected_text:
                return False
        elif key == "operation_prefix":
            prefix = _bounded_nonempty_text(expected, label="filters.operation_prefix", maximum=256)
            operation = record.get("operation")
            if not isinstance(operation, str) or not operation.startswith(prefix):
                return False
        elif key == "resource_key":
            resource_key = _bounded_nonempty_text(expected, label="filters.resource_key")
            if resource_key not in _resource_values(record):
                return False
        elif key == "record_sha256":
            digest = _sha256_text(expected, label="filters.record_sha256")
            if evidence.get("record_sha256") != digest:
                return False
        elif key == "since_unix":
            if not isinstance(expected, int) or isinstance(expected, bool):
                raise ValueError("filters.since_unix must be an integer")
            observed = record.get("timestamp_unix")
            if not isinstance(observed, int) or observed < expected:
                return False
        elif key == "until_unix":
            if not isinstance(expected, int) or isinstance(expected, bool):
                raise ValueError("filters.until_unix must be an integer")
            observed = record.get("timestamp_unix")
            if not isinstance(observed, int) or observed > expected:
                return False
        elif key == "has_failure_signal":
            if not isinstance(expected, bool):
                raise ValueError("filters.has_failure_signal must be a boolean")
            if _has_failure_signal(record) is not expected:
                return False
        else:
            raise ValueError(f"Unsupported audit query filter: {key}")
    return True


def query_audit(
    filters: dict[str, Any] | None = None,
    *,
    limit: int = 50,
    order: str = "desc",
    path: Path | None = None,
) -> dict[str, Any]:
    """Query the verified audit chain through a bounded, safe-field projection."""
    selected_limit = _bounded_positive_int(limit, label="limit", maximum=MAX_QUERY_LIMIT)
    if order not in {"asc", "desc"}:
        raise ValueError("order must be 'asc' or 'desc'")
    selected_filters = {} if filters is None else filters
    if not isinstance(selected_filters, dict):
        raise ValueError("filters must be an object")
    _validate_filters(selected_filters)
    projection = build_audit_projection(path)
    matches = [
        item
        for item in projection["items"]
        if _record_matches_filters(item, selected_filters)
    ]
    if order == "desc":
        matches.reverse()
    returned = matches[:selected_limit]
    return {
        "schema_version": 1,
        "kind": "grabowski_audit_query_result",
        "authority": projection["authority"],
        "source": projection["source"],
        "filters": selected_filters,
        "order": order,
        "matched": len(matches),
        "returned": len(returned),
        "truncated": len(matches) > len(returned),
        "items": returned,
        "does_not_establish": list(projection["does_not_establish"]),
    }


def _anchor_matches(item: dict[str, Any], kind: str, value: str) -> bool:
    record = item["record"]
    if kind == "record_sha256":
        return item["evidence"].get("record_sha256") == value
    if kind == "resource_key":
        return value in _resource_values(record)
    return record.get(kind) == value


def _correlation_tokens(
    items: list[dict[str, Any]],
) -> tuple[dict[str, list[str]], dict[str, int]]:
    values: dict[str, set[str]] = {field: set() for field in _TRACE_SCALAR_FIELDS}
    values["resource_key"] = set()
    for item in items:
        record = item["record"]
        for field in _TRACE_SCALAR_FIELDS:
            value = record.get(field)
            if isinstance(value, str) and value:
                values[field].add(value)
        values["resource_key"].update(_resource_values(record))
    tokens: dict[str, list[str]] = {}
    truncated: dict[str, int] = {}
    for key, entries in values.items():
        if not entries:
            continue
        ordered = sorted(entries)
        tokens[key] = ordered[:MAX_CORRELATION_VALUES]
        omitted = len(ordered) - len(tokens[key])
        if omitted > 0:
            truncated[key] = omitted
    return tokens, truncated


def _shared_correlations(item: dict[str, Any], tokens: dict[str, list[str]]) -> list[str]:
    record = item["record"]
    matches: list[str] = []
    for field in _TRACE_SCALAR_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value in tokens.get(field, []):
            matches.append(f"{field}:{value}")
    resources = _resource_values(record)
    for resource in tokens.get("resource_key", []):
        if resource in resources:
            matches.append(f"resource_key:{resource}")
    return matches


def trace_audit(
    anchor_kind: str,
    anchor_value: str,
    *,
    limit: int = 100,
    order: str = "asc",
    path: Path | None = None,
) -> dict[str, Any]:
    """Return a one-hop correlation trace without claiming causality."""
    if anchor_kind not in _TRACE_ANCHOR_KINDS:
        raise ValueError(f"anchor_kind must be one of {sorted(_TRACE_ANCHOR_KINDS)}")
    value = (
        _sha256_text(anchor_value, label="anchor_value")
        if anchor_kind == "record_sha256"
        else _bounded_nonempty_text(anchor_value, label="anchor_value")
    )
    selected_limit = _bounded_positive_int(limit, label="limit", maximum=MAX_TRACE_LIMIT)
    if order not in {"asc", "desc"}:
        raise ValueError("order must be 'asc' or 'desc'")
    projection = build_audit_projection(path)
    seeds = [item for item in projection["items"] if _anchor_matches(item, anchor_kind, value)]
    tokens, truncated_tokens = _correlation_tokens(seeds)
    traced: list[dict[str, Any]] = []
    for item in projection["items"]:
        direct = _anchor_matches(item, anchor_kind, value)
        correlations = _shared_correlations(item, tokens) if seeds else []
        if not direct and not correlations:
            continue
        traced.append(
            {
                **item,
                "trace": {
                    "direct_anchor_match": direct,
                    "shared_correlations": correlations,
                },
            }
        )
    if order == "desc":
        traced.reverse()
    returned = traced[:selected_limit]
    return {
        "schema_version": 1,
        "kind": "grabowski_audit_trace_result",
        "authority": projection["authority"],
        "source": projection["source"],
        "anchor": {"kind": anchor_kind, "value": value},
        "seed_count": len(seeds),
        "correlation_tokens": tokens,
        "correlation_tokens_truncated": bool(truncated_tokens),
        "correlation_token_omissions": truncated_tokens,
        "matched": len(traced),
        "returned": len(returned),
        "truncated": len(traced) > len(returned),
        "order": order,
        "items": returned,
        "does_not_establish": [
            "causality_between_correlated_records",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "external_state_not_recorded_by_grabowski",
            "future_action_authority",
        ],
    }


def _has_failure_signal(record: dict[str, Any]) -> bool:
    if record.get("launcher_outcome_unknown") is True or record.get("recovery_required") is True:
        return True
    for key in ("returncode", "launcher_returncode"):
        value = record.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value != 0:
            return True
    return False


def _top_counter(counter: Counter[str], *, limit: int) -> list[dict[str, Any]]:
    return [
        {"value": value, "count": count}
        for value, count in counter.most_common(limit)
    ]


def analyze_audit(
    filters: dict[str, Any] | None = None,
    *,
    top: int = 20,
    path: Path | None = None,
) -> dict[str, Any]:
    """Compute bounded descriptive statistics from the verified audit projection."""
    selected_top = _bounded_positive_int(top, label="top", maximum=MAX_TOP_VALUES)
    selected_filters = {} if filters is None else filters
    if not isinstance(selected_filters, dict):
        raise ValueError("filters must be an object")
    _validate_filters(selected_filters)
    projection = build_audit_projection(path)
    items = [
        item
        for item in projection["items"]
        if _record_matches_filters(item, selected_filters)
    ]
    operations: Counter[str] = Counter()
    resources: Counter[str] = Counter()
    task_ids: Counter[str] = Counter()
    owner_ids: Counter[str] = Counter()
    failure_refs: list[str] = []
    unknown_outcome_refs: list[str] = []
    recovery_refs: list[str] = []
    timestamps: list[int] = []
    for item in items:
        record = item["record"]
        operation = record.get("operation")
        if isinstance(operation, str):
            operations[operation] += 1
        task_id = record.get("task_id")
        if isinstance(task_id, str):
            task_ids[task_id] += 1
        owner_id = record.get("owner_id")
        if isinstance(owner_id, str):
            owner_ids[owner_id] += 1
        resources.update(_resource_values(record))
        timestamp_unix = record.get("timestamp_unix")
        if isinstance(timestamp_unix, int) and not isinstance(timestamp_unix, bool):
            timestamps.append(timestamp_unix)
        if _has_failure_signal(record):
            failure_refs.append(item["audit_ref"])
        if record.get("launcher_outcome_unknown") is True:
            unknown_outcome_refs.append(item["audit_ref"])
        if record.get("recovery_required") is True:
            recovery_refs.append(item["audit_ref"])
    return {
        "schema_version": 1,
        "kind": "grabowski_audit_analysis",
        "authority": projection["authority"],
        "source": projection["source"],
        "filters": selected_filters,
        "record_count": len(items),
        "time_range_unix": {
            "minimum": min(timestamps) if timestamps else None,
            "maximum": max(timestamps) if timestamps else None,
        },
        "top_operations": _top_counter(operations, limit=selected_top),
        "top_resource_keys": _top_counter(resources, limit=selected_top),
        "top_task_ids": _top_counter(task_ids, limit=selected_top),
        "top_owner_ids": _top_counter(owner_ids, limit=selected_top),
        "signals": {
            "failure_signal_count": len(failure_refs),
            "failure_signal_sample_refs": failure_refs[:20],
            "launcher_outcome_unknown_count": len(unknown_outcome_refs),
            "launcher_outcome_unknown_sample_refs": unknown_outcome_refs[:20],
            "recovery_required_count": len(recovery_refs),
            "recovery_required_sample_refs": recovery_refs[:20],
        },
        "does_not_establish": [
            "causality",
            "root_cause",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "future_failure_probability",
            "future_action_authority",
        ],
    }


@mcp.tool(name="grabowski_audit_query", annotations=READ_ONLY)
def grabowski_audit_query(
    filters: dict[str, Any] | None = None,
    limit: int = 50,
    order: str = "desc",
) -> dict[str, Any]:
    """Query the verified audit chain through a bounded evidence projection."""
    base._require_capability("audit_verify")
    return query_audit(filters, limit=limit, order=order)


@mcp.tool(name="grabowski_audit_trace", annotations=READ_ONLY)
def grabowski_audit_trace(
    anchor_kind: str,
    anchor_value: str,
    limit: int = 100,
    order: str = "asc",
) -> dict[str, Any]:
    """Trace one audit anchor through bounded one-hop correlations."""
    base._require_capability("audit_verify")
    return trace_audit(anchor_kind, anchor_value, limit=limit, order=order)


@mcp.tool(name="grabowski_audit_analyze", annotations=READ_ONLY)
def grabowski_audit_analyze(
    filters: dict[str, Any] | None = None,
    top: int = 20,
) -> dict[str, Any]:
    """Compute bounded descriptive statistics from the verified audit chain."""
    base._require_capability("audit_verify")
    return analyze_audit(filters, top=top)
