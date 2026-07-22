from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterator

import grabowski_mcp as base
import grabowski_operator_core as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY

MAX_QUERY_LIMIT = 200
MAX_TRACE_LIMIT = 200
MAX_TOP_VALUES = 50
MAX_CORRELATION_VALUES = 64
MAX_TRACE_SEEDS = 256
MAX_SCAN_RECORDS = 100_000
MAX_SEGMENT_SAMPLE = 8
MAX_ANALYSIS_COUNTER_ENTRIES = 512
MAX_FAILURE_SAMPLE_REFS = 20

_SCALAR_RECORD_FIELDS = (
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
    "resource_lease_expires_at_unix",
    "record_sha256",
    "previous_record_sha256",
    "sequence",
    "audit_schema_version",
)
_STRING_LIST_RECORD_FIELDS = (
    "resource_keys",
    "requested_resource_keys",
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
    "held_resource_key",
    "requested_resource_key",
    "unit",
    "path",
}


@dataclass(frozen=True)
class AuditSegmentSnapshot:
    path: Path
    segment_sha256: str
    segment_ordinal: int
    records: int
    legacy_records: int
    v2_records: int
    last_record_sha256: str | None
    bytes: int
    global_start_ordinal: int
    global_end_ordinal: int
    captured_data: bytes | None
    active: bool


@dataclass(frozen=True)
class VerifiedAuditSnapshot:
    active_path: Path
    segments: tuple[AuditSegmentSnapshot, ...]
    total_records: int
    archived_segment_count: int
    legacy_rotation_compatibility: bool
    last_record_sha256: str | None
    chain_content_sha256: str
    chain_materialization_sha256: str


class _BoundedTopCounter:
    """Bounded-memory Space-Saving counter with explicit error bounds."""

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self._entries: dict[str, tuple[int, int]] = {}
        self.evictions = 0

    def add(self, value: str) -> None:
        current = self._entries.get(value)
        if current is not None:
            self._entries[value] = (current[0] + 1, current[1])
            return
        if len(self._entries) < self.capacity:
            self._entries[value] = (1, 0)
            return
        victim, (minimum_count, _) = min(
            self._entries.items(),
            key=lambda item: (item[1][0], item[0]),
        )
        del self._entries[victim]
        self._entries[value] = (minimum_count + 1, minimum_count)
        self.evictions += 1

    def top(self, limit: int) -> list[dict[str, Any]]:
        ordered = sorted(
            self._entries.items(),
            key=lambda item: (-item[1][0], item[0]),
        )[:limit]
        return [
            {
                "value": value,
                "count": estimate,
                "error_upper_bound": error,
            }
            for value, (estimate, error) in ordered
        ]

    def quality(self) -> dict[str, Any]:
        return {
            "exact": self.evictions == 0,
            "capacity": self.capacity,
            "tracked_values": len(self._entries),
            "evictions": self.evictions,
            "count_semantics": (
                "exact" if self.evictions == 0 else "space_saving_estimate_with_error_upper_bound"
            ),
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
        elif key in {"resource_key", "held_resource_key", "requested_resource_key"}:
            _bounded_nonempty_text(expected, label=f"filters.{key}")
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


def _project_record(record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    projected: dict[str, Any] = {}
    omitted: list[str] = []
    for key in _SCALAR_RECORD_FIELDS:
        if key not in record:
            continue
        value = record[key]
        if value is None or isinstance(value, (str, int, float, bool)):
            projected[key] = value
        else:
            omitted.append(key)
    for key in _STRING_LIST_RECORD_FIELDS:
        if key not in record:
            continue
        value = record[key]
        if (
            isinstance(value, list)
            and len(value) <= 256
            and all(isinstance(item, str) for item in value)
        ):
            projected[key] = list(value)
        else:
            omitted.append(key)
    return projected, sorted(omitted)


def _record_evidence_digest(record: dict[str, Any], raw_line: bytes) -> str:
    stored = record.get("record_sha256")
    if (
        isinstance(stored, str)
        and len(stored) == 64
        and all(char in "0123456789abcdef" for char in stored)
    ):
        return stored
    return hashlib.sha256(raw_line).hexdigest()


def capture_verified_audit_snapshot(path: Path | None = None) -> VerifiedAuditSnapshot:
    """Capture a verified immutable audit view while minimizing shared-lock hold time.

    The active segment bytes are retained because they may change after the lock is
    released. Historical segments are represented by verified hashes and are loaded
    lazily outside the coordination lock. A cold verification cache may still require
    one full historical verification pass; subsequent captures can reuse the existing
    immutable-segment verification cache without losing historical record access.
    """
    active_path = path if path is not None else base.AUDIT_LOG
    with base._audit_coordination_lock(active_path, exclusive=False):
        components, compatibility = base._read_audit_chain_unlocked(
            active_path,
            use_segment_cache=True,
            retain_verified_segment_data=False,
        )
        captured_components = [
            (segment_path, data, dict(status), index == 0)
            for index, (segment_path, data, status) in enumerate(components)
        ]

    ordered = list(reversed(captured_components))
    segments: list[AuditSegmentSnapshot] = []
    next_global_ordinal = 1
    for segment_ordinal, (segment_path, data, status, active) in enumerate(ordered, start=1):
        stored_sha = status.get("segment_sha256")
        if isinstance(stored_sha, str) and len(stored_sha) == 64:
            segment_sha256 = stored_sha
        elif data:
            segment_sha256 = hashlib.sha256(data).hexdigest()
        else:
            raise RuntimeError("verified audit segment is missing its evidence digest")
        records = int(status.get("records") or 0)
        global_start = next_global_ordinal
        global_end = next_global_ordinal + records - 1
        next_global_ordinal += records
        segments.append(
            AuditSegmentSnapshot(
                path=segment_path,
                segment_sha256=segment_sha256,
                segment_ordinal=segment_ordinal,
                records=records,
                legacy_records=int(status.get("legacy_records") or 0),
                v2_records=int(status.get("v2_records") or 0),
                last_record_sha256=status.get("last_record_sha256"),
                bytes=int(status.get("active_bytes") or len(data)),
                global_start_ordinal=global_start,
                global_end_ordinal=global_end,
                captured_data=data if data or active else None,
                active=active,
            )
        )

    content_binding = [
        {
            "segment_ordinal": segment.segment_ordinal,
            "sha256": segment.segment_sha256,
        }
        for segment in segments
    ]
    materialization_binding = [
        {
            **entry,
            "path": str(segment.path),
        }
        for entry, segment in zip(content_binding, segments, strict=True)
    ]
    active_status = components[0][2] if components else {}
    return VerifiedAuditSnapshot(
        active_path=active_path,
        segments=tuple(segments),
        total_records=sum(segment.records for segment in segments),
        archived_segment_count=max(0, len(segments) - 1),
        legacy_rotation_compatibility=compatibility,
        last_record_sha256=active_status.get("last_record_sha256"),
        chain_content_sha256=hashlib.sha256(_canonical_json_bytes(content_binding)).hexdigest(),
        chain_materialization_sha256=hashlib.sha256(
            _canonical_json_bytes(materialization_binding)
        ).hexdigest(),
    )


def _public_segment(segment: AuditSegmentSnapshot) -> dict[str, Any]:
    return {
        "segment_ordinal": segment.segment_ordinal,
        "path": str(segment.path),
        "sha256": segment.segment_sha256,
        "bytes": segment.bytes,
        "records": segment.records,
        "legacy_records": segment.legacy_records,
        "v2_records": segment.v2_records,
        "last_record_sha256": segment.last_record_sha256,
        "global_start_ordinal": segment.global_start_ordinal,
        "global_end_ordinal": segment.global_end_ordinal,
        "active": segment.active,
    }


def _sample_segments(segments: tuple[AuditSegmentSnapshot, ...]) -> tuple[list[dict[str, Any]], int]:
    if len(segments) <= MAX_SEGMENT_SAMPLE:
        return [_public_segment(segment) for segment in segments], 0
    head_count = MAX_SEGMENT_SAMPLE // 2
    tail_count = MAX_SEGMENT_SAMPLE - head_count
    selected = (*segments[:head_count], *segments[-tail_count:])
    return [_public_segment(segment) for segment in selected], len(segments) - len(selected)


def _source_payload(snapshot: VerifiedAuditSnapshot) -> dict[str, Any]:
    segment_sample, omissions = _sample_segments(snapshot.segments)
    return {
        "active_path": str(snapshot.active_path),
        "chain_content_sha256": snapshot.chain_content_sha256,
        "chain_materialization_sha256": snapshot.chain_materialization_sha256,
        "chain_fingerprint_sha256": snapshot.chain_materialization_sha256,
        "chain_fingerprint_semantics": "materialization_v1_compatibility_alias",
        "last_record_sha256": snapshot.last_record_sha256,
        "total_records": snapshot.total_records,
        "segment_count": len(snapshot.segments),
        "archived_segment_count": snapshot.archived_segment_count,
        "legacy_rotation_compatibility": snapshot.legacy_rotation_compatibility,
        "first_segment": _public_segment(snapshot.segments[0]) if snapshot.segments else None,
        "last_segment": _public_segment(snapshot.segments[-1]) if snapshot.segments else None,
        "segments": segment_sample,
        "segments_truncated": omissions > 0,
        "segment_omissions": omissions,
    }


def _load_snapshot_segment(segment: AuditSegmentSnapshot) -> bytes:
    if segment.captured_data is not None:
        return segment.captured_data
    data, status = base._read_audit_file(segment.path)
    if not status.get("valid"):
        raise ValueError(f"audit-segment-invalid:{status.get('error')}")
    observed_sha = hashlib.sha256(data).hexdigest()
    if observed_sha != segment.segment_sha256:
        raise ValueError("audit-segment-sha256-mismatch-after-snapshot")
    if int(status.get("records") or 0) != segment.records:
        raise ValueError("audit-segment-record-count-mismatch-after-snapshot")
    if status.get("last_record_sha256") != segment.last_record_sha256:
        raise ValueError("audit-segment-last-hash-mismatch-after-snapshot")
    return data


def _iter_snapshot_items(
    snapshot: VerifiedAuditSnapshot,
    *,
    order: str,
) -> Iterator[dict[str, Any]]:
    segments = snapshot.segments if order == "asc" else tuple(reversed(snapshot.segments))
    for segment in segments:
        data = _load_snapshot_segment(segment)
        lines = data.splitlines()
        if len(lines) != segment.records:
            raise RuntimeError("verified audit segment record count changed during projection")
        indexes = range(len(lines)) if order == "asc" else range(len(lines) - 1, -1, -1)
        for zero_based_index in indexes:
            raw_line = lines[zero_based_index]
            try:
                parsed = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "verified audit record decode invariant violated"
                ) from exc
            if not isinstance(parsed, dict):
                raise RuntimeError("verified audit chain yielded a non-object record")
            digest = _record_evidence_digest(parsed, raw_line)
            projected, omitted_fields = _project_record(parsed)
            record_ordinal = zero_based_index + 1
            global_ordinal = segment.global_start_ordinal + zero_based_index
            yield {
                "audit_ref": f"audit-record-sha256:{digest}",
                "evidence": {
                    "record_sha256": digest,
                    "stored_record_sha256": parsed.get("record_sha256"),
                    "legacy_record": parsed.get("record_sha256") is None,
                    "segment_path": str(segment.path),
                    "segment_sha256": segment.segment_sha256,
                    "segment_ordinal": segment.segment_ordinal,
                    "record_ordinal": record_ordinal,
                    "global_ordinal": global_ordinal,
                    "projection_schema_mismatch": bool(omitted_fields),
                    "projection_omitted_fields": omitted_fields,
                },
                "record": projected,
            }


def build_audit_projection(path: Path | None = None) -> dict[str, Any]:
    """Compatibility helper that materializes the full verified projection.

    Public query/trace/analyze tools do not call this helper; they stream from the
    verified snapshot and enforce scan/result bounds.
    """
    snapshot = capture_verified_audit_snapshot(path)
    return {
        "schema_version": 2,
        "kind": "grabowski_audit_projection",
        "authority": "derived_from_verified_audit_chain",
        "source": _source_payload(snapshot),
        "items": list(_iter_snapshot_items(snapshot, order="asc")),
        "does_not_establish": [
            "causality",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "external_state_not_recorded_by_grabowski",
            "future_action_authority",
        ],
    }


def _string_values(record: dict[str, Any], key: str) -> set[str]:
    raw = record.get(key)
    if not isinstance(raw, list):
        return set()
    return {item for item in raw if isinstance(item, str)}


def _held_resource_values(record: dict[str, Any]) -> set[str]:
    return _string_values(record, "resource_keys")


def _requested_resource_values(record: dict[str, Any]) -> set[str]:
    return _string_values(record, "requested_resource_keys")


def _any_resource_values(record: dict[str, Any]) -> set[str]:
    return _held_resource_values(record) | _requested_resource_values(record)


def _record_matches_filters(item: dict[str, Any], filters: dict[str, Any]) -> bool:
    """Match already-validated filters without repeating static input validation."""
    record = item["record"]
    evidence = item["evidence"]
    for key, expected in filters.items():
        if key in _EXACT_FILTER_FIELDS:
            if record.get(key) != expected:
                return False
        elif key == "operation_prefix":
            operation = record.get("operation")
            if not isinstance(operation, str) or not operation.startswith(expected):
                return False
        elif key == "resource_key":
            if expected not in _any_resource_values(record):
                return False
        elif key == "held_resource_key":
            if expected not in _held_resource_values(record):
                return False
        elif key == "requested_resource_key":
            if expected not in _requested_resource_values(record):
                return False
        elif key == "record_sha256":
            if evidence.get("record_sha256") != expected:
                return False
        elif key == "since_unix":
            observed = record.get("timestamp_unix")
            if not isinstance(observed, int) or isinstance(observed, bool) or observed < expected:
                return False
        elif key == "until_unix":
            observed = record.get("timestamp_unix")
            if not isinstance(observed, int) or isinstance(observed, bool) or observed > expected:
                return False
        elif key == "has_failure_signal":
            if _has_failure_signal(record) is not expected:
                return False
        else:
            raise RuntimeError(f"validated audit query filter became unsupported: {key}")
    return True


def _scan_summary(
    snapshot: VerifiedAuditSnapshot,
    *,
    scanned_records: int,
    order: str,
    first_global_ordinal: int | None,
    last_global_ordinal: int | None,
) -> dict[str, Any]:
    truncated = snapshot.total_records > scanned_records
    return {
        "order": order,
        "scan_limit": MAX_SCAN_RECORDS,
        "scanned_records": scanned_records,
        "total_records": snapshot.total_records,
        "scan_truncated": truncated,
        "scan_complete": not truncated,
        "first_global_ordinal": first_global_ordinal,
        "last_global_ordinal": last_global_ordinal,
        "continuation_supported": False,
        "does_not_establish": (
            ["absence_of_matches_outside_the_scan_window"] if truncated else []
        ),
    }


def query_audit(
    filters: dict[str, Any] | None = None,
    *,
    limit: int = 50,
    order: str = "desc",
    path: Path | None = None,
) -> dict[str, Any]:
    """Query a bounded scan of the verified audit chain with bounded result memory."""
    selected_limit = _bounded_positive_int(limit, label="limit", maximum=MAX_QUERY_LIMIT)
    if order not in {"asc", "desc"}:
        raise ValueError("order must be 'asc' or 'desc'")
    selected_filters = {} if filters is None else filters
    if not isinstance(selected_filters, dict):
        raise ValueError("filters must be an object")
    _validate_filters(selected_filters)

    snapshot = capture_verified_audit_snapshot(path)
    returned: list[dict[str, Any]] = []
    matched = 0
    scanned = 0
    first_global: int | None = None
    last_global: int | None = None
    for item in _iter_snapshot_items(snapshot, order=order):
        if scanned >= MAX_SCAN_RECORDS:
            break
        scanned += 1
        ordinal = int(item["evidence"]["global_ordinal"])
        if first_global is None:
            first_global = ordinal
        last_global = ordinal
        if not _record_matches_filters(item, selected_filters):
            continue
        matched += 1
        if len(returned) < selected_limit:
            returned.append(item)

    scan = _scan_summary(
        snapshot,
        scanned_records=scanned,
        order=order,
        first_global_ordinal=first_global,
        last_global_ordinal=last_global,
    )
    result_truncated = matched > len(returned)
    return {
        "schema_version": 2,
        "kind": "grabowski_audit_query_result",
        "authority": "derived_from_verified_audit_chain",
        "source": _source_payload(snapshot),
        "filters": selected_filters,
        "filter_semantics": {
            "resource_key": "compatibility alias matching held or requested resources",
            "held_resource_key": "matches resource_keys only",
            "requested_resource_key": "matches requested_resource_keys only",
        },
        "order": order,
        "matched": matched,
        "matched_scope": "scanned_records",
        "matched_total_known": not scan["scan_truncated"],
        "returned": len(returned),
        "result_truncated": result_truncated,
        "scan": scan,
        "truncated": result_truncated or bool(scan["scan_truncated"]),
        "items": returned,
        "does_not_establish": [
            "causality",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "external_state_not_recorded_by_grabowski",
            "future_action_authority",
            *(
                ["absence_of_matching_records_outside_the_scan_window"]
                if scan["scan_truncated"]
                else []
            ),
        ],
    }


def _anchor_matches(item: dict[str, Any], kind: str, value: str) -> bool:
    record = item["record"]
    if kind == "record_sha256":
        return item["evidence"].get("record_sha256") == value
    if kind == "resource_key":
        return value in _any_resource_values(record)
    if kind == "held_resource_key":
        return value in _held_resource_values(record)
    if kind == "requested_resource_key":
        return value in _requested_resource_values(record)
    return record.get(kind) == value


def _correlation_tokens(
    items: list[dict[str, Any]],
) -> tuple[dict[str, list[str]], dict[str, int]]:
    values: dict[str, set[str]] = {field: set() for field in _TRACE_SCALAR_FIELDS}
    values["held_resource_key"] = set()
    values["requested_resource_key"] = set()
    for item in items:
        record = item["record"]
        for field in _TRACE_SCALAR_FIELDS:
            value = record.get(field)
            if isinstance(value, str) and value:
                values[field].add(value)
        values["held_resource_key"].update(_held_resource_values(record))
        values["requested_resource_key"].update(_requested_resource_values(record))
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
    held = _held_resource_values(record)
    for resource in tokens.get("held_resource_key", []):
        if resource in held:
            matches.append(f"held_resource_key:{resource}")
    requested = _requested_resource_values(record)
    for resource in tokens.get("requested_resource_key", []):
        if resource in requested:
            matches.append(f"requested_resource_key:{resource}")
    return matches


def trace_audit(
    anchor_kind: str,
    anchor_value: str,
    *,
    limit: int = 100,
    order: str = "asc",
    path: Path | None = None,
) -> dict[str, Any]:
    """Return a bounded one-hop correlation trace without claiming causality."""
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

    snapshot = capture_verified_audit_snapshot(path)
    seeds: list[dict[str, Any]] = []
    seed_count = 0
    scanned = 0
    first_global: int | None = None
    last_global: int | None = None
    for item in _iter_snapshot_items(snapshot, order=order):
        if scanned >= MAX_SCAN_RECORDS:
            break
        scanned += 1
        ordinal = int(item["evidence"]["global_ordinal"])
        if first_global is None:
            first_global = ordinal
        last_global = ordinal
        if not _anchor_matches(item, anchor_kind, value):
            continue
        seed_count += 1
        if len(seeds) < MAX_TRACE_SEEDS:
            seeds.append(item)

    scan = _scan_summary(
        snapshot,
        scanned_records=scanned,
        order=order,
        first_global_ordinal=first_global,
        last_global_ordinal=last_global,
    )
    tokens, truncated_tokens = _correlation_tokens(seeds)
    seed_truncated = seed_count > len(seeds)

    traced: list[dict[str, Any]] = []
    matched = 0
    if seed_count:
        second_scan = 0
        for item in _iter_snapshot_items(snapshot, order=order):
            if second_scan >= scanned:
                break
            second_scan += 1
            direct = _anchor_matches(item, anchor_kind, value)
            correlations = _shared_correlations(item, tokens)
            if not direct and not correlations:
                continue
            matched += 1
            if len(traced) >= selected_limit:
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

    result_truncated = matched > len(traced)
    correlation_incomplete = bool(
        scan["scan_truncated"] or seed_truncated or truncated_tokens
    )
    return {
        "schema_version": 2,
        "kind": "grabowski_audit_trace_result",
        "authority": "derived_from_verified_audit_chain",
        "source": _source_payload(snapshot),
        "anchor": {"kind": anchor_kind, "value": value},
        "seed_count": seed_count,
        "seed_count_scope": "scanned_records",
        "seed_count_total_known": not scan["scan_truncated"],
        "seed_count_used": len(seeds),
        "seed_limit": MAX_TRACE_SEEDS,
        "seed_truncated": seed_truncated,
        "correlation_tokens": tokens,
        "correlation_tokens_truncated": bool(truncated_tokens),
        "correlation_token_omissions": truncated_tokens,
        "correlation_incomplete": correlation_incomplete,
        "matched": matched,
        "matched_scope": "scanned_records",
        "matched_total_known": not correlation_incomplete,
        "returned": len(traced),
        "result_truncated": result_truncated,
        "truncated": result_truncated or correlation_incomplete,
        "order": order,
        "scan": scan,
        "items": traced,
        "does_not_establish": [
            "causality_between_correlated_records",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "external_state_not_recorded_by_grabowski",
            "future_action_authority",
            *(
                ["complete_correlation_graph"] if correlation_incomplete else []
            ),
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


def analyze_audit(
    filters: dict[str, Any] | None = None,
    *,
    top: int = 20,
    path: Path | None = None,
) -> dict[str, Any]:
    """Compute bounded-memory descriptive statistics over a bounded verified scan."""
    selected_top = _bounded_positive_int(top, label="top", maximum=MAX_TOP_VALUES)
    selected_filters = {} if filters is None else filters
    if not isinstance(selected_filters, dict):
        raise ValueError("filters must be an object")
    _validate_filters(selected_filters)

    snapshot = capture_verified_audit_snapshot(path)
    counter_capacity = min(
        MAX_ANALYSIS_COUNTER_ENTRIES,
        max(64, selected_top * 8),
    )
    operations = _BoundedTopCounter(counter_capacity)
    held_resources = _BoundedTopCounter(counter_capacity)
    requested_resources = _BoundedTopCounter(counter_capacity)
    task_ids = _BoundedTopCounter(counter_capacity)
    owner_ids = _BoundedTopCounter(counter_capacity)
    failure_refs: list[str] = []
    unknown_outcome_refs: list[str] = []
    recovery_refs: list[str] = []
    failure_count = 0
    unknown_outcome_count = 0
    recovery_count = 0
    matched_records = 0
    scanned = 0
    minimum_timestamp: int | None = None
    maximum_timestamp: int | None = None
    first_global: int | None = None
    last_global: int | None = None

    for item in _iter_snapshot_items(snapshot, order="asc"):
        if scanned >= MAX_SCAN_RECORDS:
            break
        scanned += 1
        ordinal = int(item["evidence"]["global_ordinal"])
        if first_global is None:
            first_global = ordinal
        last_global = ordinal
        if not _record_matches_filters(item, selected_filters):
            continue
        matched_records += 1
        record = item["record"]
        operation = record.get("operation")
        if isinstance(operation, str):
            operations.add(operation)
        task_id = record.get("task_id")
        if isinstance(task_id, str):
            task_ids.add(task_id)
        owner_id = record.get("owner_id")
        if isinstance(owner_id, str):
            owner_ids.add(owner_id)
        for resource in _held_resource_values(record):
            held_resources.add(resource)
        for resource in _requested_resource_values(record):
            requested_resources.add(resource)
        timestamp_unix = record.get("timestamp_unix")
        if isinstance(timestamp_unix, int) and not isinstance(timestamp_unix, bool):
            minimum_timestamp = (
                timestamp_unix
                if minimum_timestamp is None
                else min(minimum_timestamp, timestamp_unix)
            )
            maximum_timestamp = (
                timestamp_unix
                if maximum_timestamp is None
                else max(maximum_timestamp, timestamp_unix)
            )
        if _has_failure_signal(record):
            failure_count += 1
            if len(failure_refs) < MAX_FAILURE_SAMPLE_REFS:
                failure_refs.append(item["audit_ref"])
        if record.get("launcher_outcome_unknown") is True:
            unknown_outcome_count += 1
            if len(unknown_outcome_refs) < MAX_FAILURE_SAMPLE_REFS:
                unknown_outcome_refs.append(item["audit_ref"])
        if record.get("recovery_required") is True:
            recovery_count += 1
            if len(recovery_refs) < MAX_FAILURE_SAMPLE_REFS:
                recovery_refs.append(item["audit_ref"])

    scan = _scan_summary(
        snapshot,
        scanned_records=scanned,
        order="asc",
        first_global_ordinal=first_global,
        last_global_ordinal=last_global,
    )
    quality = {
        "operations": operations.quality(),
        "held_resource_keys": held_resources.quality(),
        "requested_resource_keys": requested_resources.quality(),
        "task_ids": task_ids.quality(),
        "owner_ids": owner_ids.quality(),
    }
    any_approximate = any(not value["exact"] for value in quality.values())
    return {
        "schema_version": 2,
        "kind": "grabowski_audit_analysis",
        "authority": "derived_from_verified_audit_chain",
        "source": _source_payload(snapshot),
        "filters": selected_filters,
        "record_count": matched_records,
        "record_count_scope": "scanned_records",
        "record_count_total_known": not scan["scan_truncated"],
        "scan": scan,
        "time_range_unix": {
            "minimum": minimum_timestamp,
            "maximum": maximum_timestamp,
        },
        "top_operations": operations.top(selected_top),
        "top_resource_keys": held_resources.top(selected_top),
        "top_requested_resource_keys": requested_resources.top(selected_top),
        "top_task_ids": task_ids.top(selected_top),
        "top_owner_ids": owner_ids.top(selected_top),
        "top_value_quality": quality,
        "top_values_approximate": any_approximate,
        "signals": {
            "failure_signal_count": failure_count,
            "failure_signal_sample_refs": failure_refs,
            "launcher_outcome_unknown_count": unknown_outcome_count,
            "launcher_outcome_unknown_sample_refs": unknown_outcome_refs,
            "recovery_required_count": recovery_count,
            "recovery_required_sample_refs": recovery_refs,
        },
        "does_not_establish": [
            "causality",
            "root_cause",
            "semantic_correctness_of_logged_actions",
            "task_success",
            "future_failure_probability",
            "future_action_authority",
            *(
                ["complete_chain_statistics"] if scan["scan_truncated"] else []
            ),
            *(
                ["exact_top_values_for_evicted_categories"] if any_approximate else []
            ),
        ],
    }


@mcp.tool(name="grabowski_audit_query", annotations=READ_ONLY)
def grabowski_audit_query(
    filters: dict[str, Any] | None = None,
    limit: int = 50,
    order: str = "desc",
) -> dict[str, Any]:
    """Query the verified audit chain through a bounded evidence projection."""
    base._require_capability("audit_read")
    return query_audit(filters, limit=limit, order=order)


@mcp.tool(name="grabowski_audit_trace", annotations=READ_ONLY)
def grabowski_audit_trace(
    anchor_kind: str,
    anchor_value: str,
    limit: int = 100,
    order: str = "asc",
) -> dict[str, Any]:
    """Trace one audit anchor through bounded one-hop correlations."""
    base._require_capability("audit_read")
    return trace_audit(anchor_kind, anchor_value, limit=limit, order=order)


@mcp.tool(name="grabowski_audit_analyze", annotations=READ_ONLY)
def grabowski_audit_analyze(
    filters: dict[str, Any] | None = None,
    top: int = 20,
) -> dict[str, Any]:
    """Compute bounded descriptive statistics from the verified audit chain."""
    base._require_capability("audit_read")
    return analyze_audit(filters, top=top)
