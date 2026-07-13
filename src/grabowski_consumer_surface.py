from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any

CONSUMER_VIEWS = frozenset({"minimal", "standard", "evidence"})
CONSUMER_VIEW_ALIASES = {"concise": "minimal", "full": "evidence"}
MAX_CONSUMER_FIELDS = 40
MAX_CONSUMER_CURSOR_BYTES = 2048
CURSOR_SNAPSHOT_CHANGED_ERROR = (
    "cursor_snapshot_changed: result snapshot changed; "
    "restart pagination from the first page"
)
_FIELD_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def normalize_view(value: str | None, *, default: str = "minimal") -> str:
    selected = default if value is None else value
    if not isinstance(selected, str):
        raise ValueError("view must be a string")
    selected = CONSUMER_VIEW_ALIASES.get(selected, selected)
    if selected not in CONSUMER_VIEWS:
        raise ValueError(f"view must be one of {sorted(CONSUMER_VIEWS)}")
    return selected


def normalize_fields(fields: list[str] | None) -> list[str] | None:
    if fields is None:
        return None
    if not isinstance(fields, list) or len(fields) > MAX_CONSUMER_FIELDS:
        raise ValueError(
            f"fields must be a list with at most {MAX_CONSUMER_FIELDS} entries"
        )
    normalized: list[str] = []
    for field in fields:
        if not isinstance(field, str) or _FIELD_RE.fullmatch(field) is None:
            raise ValueError("fields entries must be bounded lower-case identifiers")
        if field not in normalized:
            normalized.append(field)
    return normalized


def project_fields(
    payload: dict[str, Any],
    *,
    fields: list[str] | None,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    selected = normalize_fields(fields)
    if selected is None:
        return payload
    unknown = sorted(set(selected) - set(payload))
    if unknown:
        raise ValueError(f"Unknown response field(s): {', '.join(unknown)}")
    keep = set(selected) | {key for key in required if key in payload}
    projected = {key: value for key, value in payload.items() if key in keep}
    projected["projection"] = {
        "selected_fields": sorted(keep),
        "omitted_fields": sorted(set(payload) - keep),
        "required_fields_preserved": [key for key in required if key in payload],
    }
    return projected


def encode_cursor(scope: str, position: dict[str, Any]) -> str:
    if not isinstance(scope, str) or not scope or len(scope) > 200:
        raise ValueError("cursor scope is invalid")
    if not isinstance(position, dict):
        raise ValueError("cursor position must be an object")
    body = {"schema_version": 1, "scope": scope, "position": position}
    body["checksum"] = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
    encoded = base64.urlsafe_b64encode(canonical_json_bytes(body)).decode("ascii").rstrip("=")
    if len(encoded) > MAX_CONSUMER_CURSOR_BYTES:
        raise ValueError("cursor is too large")
    return encoded


def decode_cursor(
    cursor: str | None,
    scope: str,
    *,
    snapshot_scope: str | None = None,
) -> dict[str, Any] | None:
    if cursor in (None, ""):
        return None
    if not isinstance(cursor, str) or len(cursor) > MAX_CONSUMER_CURSOR_BYTES:
        raise ValueError("cursor is invalid")
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + padding))
    except (ValueError, json.JSONDecodeError, binascii.Error) as exc:
        raise ValueError("cursor is invalid") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("cursor schema is invalid")
    checksum = value.pop("checksum", None)
    expected = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected):
        raise ValueError("cursor checksum is invalid")
    actual_scope = value.get("scope")
    position = value.get("position")
    if not isinstance(position, dict):
        raise ValueError("cursor position is invalid")
    if actual_scope != scope:
        if (
            snapshot_scope
            and isinstance(actual_scope, str)
            and actual_scope.startswith(snapshot_scope + ":")
            and scope.startswith(snapshot_scope + ":")
        ):
            raise ValueError(CURSOR_SNAPSHOT_CHANGED_ERROR)
        raise ValueError("cursor does not match this view or filter")
    return position
