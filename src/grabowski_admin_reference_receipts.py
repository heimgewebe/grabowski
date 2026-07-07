from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

REFERENCE_RECEIPT_KIND = "grabowski.admin_reference_receipt"
REFERENCE_RECEIPT_SCHEMA_VERSION = 1
REFERENCE_SCHEMA_VERSION = 1
REFERENCE_TTL_SECONDS = 900
REFERENCE_REPLAY_POLICY = "single-use-external-broker"
REFERENCE_ACTIONS = {
    "install_system_package",
    "edit_system_service",
    "change_file_owner",
    "mount_filesystem",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_text(label: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > 1000 or "\x00" in value:
        raise ValueError(f"{label} is too large or contains NUL")
    return value


def build_reference_receipt(
    *,
    action: str,
    target: str,
    justification: str,
    now_unix: int | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    action = _validate_text("action", action)
    target = _validate_text("target", target)
    justification = _validate_text("justification", justification)
    if action not in REFERENCE_ACTIONS:
        raise ValueError(f"action must be one of {sorted(REFERENCE_ACTIONS)}")
    created_at = int(time.time() if now_unix is None else now_unix)
    if created_at < 0:
        raise ValueError("now_unix must be non-negative")
    request = request_id or uuid.uuid4().hex
    if not isinstance(request, str) or len(request) != 32:
        raise ValueError("request_id must be a 32-character hex string")
    try:
        int(request, 16)
    except ValueError as exc:
        raise ValueError("request_id must be hex") from exc
    reference = {
        "schema_version": REFERENCE_SCHEMA_VERSION,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_agent": True,
        "replay_policy": REFERENCE_REPLAY_POLICY,
        "action": action,
        "target": target,
        "justification": justification,
        "request_id": request,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + REFERENCE_TTL_SECONDS,
    }
    reference["reference_sha256"] = sha256_json(reference)
    receipt = {
        "kind": REFERENCE_RECEIPT_KIND,
        "schema_version": REFERENCE_RECEIPT_SCHEMA_VERSION,
        "reference_sha256": reference["reference_sha256"],
        "action": action,
        "target_sha256": sha256_text(target),
        "request_id": request,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + REFERENCE_TTL_SECONDS,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_agent": True,
        "replay_policy": REFERENCE_REPLAY_POLICY,
        "outcome": "reference-created",
    }
    receipt["receipt_sha256"] = sha256_json(receipt)
    return {
        "reference": reference,
        "receipt": receipt,
        "non_claims": [
            "does not execute action",
            "does not contact external broker",
            "does not grant ambient authority",
        ],
    }
