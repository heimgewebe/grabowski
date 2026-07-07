from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

RECEIPT_KIND = "grabowski.reference_receipt"
RECEIPT_SCHEMA_VERSION = 1
MAX_REFERENCE_TTL_SECONDS = 900
REPLAY_POLICY = "single-use-external-broker"
EXECUTION_MODE = "unprivileged-reference-only"
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")

RECEIPT_PROFILES: dict[str, dict[str, Any]] = {
    "runtime-deploy-check": {
        "scope": "runtime-deploy-preflight",
        "risk_level": "low",
        "irreversibility": "none",
        "recovery_path": "No runtime mutation is performed; repeat the read-only check after fixing inputs.",
        "read_only": True,
    },
    "runtime-deploy": {
        "scope": "runtime-release-activation",
        "risk_level": "high",
        "irreversibility": "partially-reversible",
        "recovery_path": "Use deployment manifest rollback pointers and service logs; do not retry without a fresh reference.",
        "read_only": False,
    },
    "service-restart": {
        "scope": "single-service-control",
        "risk_level": "medium",
        "irreversibility": "transient-side-effects",
        "recovery_path": "Inspect unit status and logs; revert config or restart the previous known-good service if needed.",
        "read_only": False,
    },
    "pr-merge": {
        "scope": "remote-git-history-change",
        "risk_level": "high",
        "irreversibility": "not-fully-reversible",
        "recovery_path": "Use revert PR or protected-branch incident path; never force-push as rollback.",
        "read_only": False,
    },
}


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_reference(reference: dict[str, Any], *, now: int | None = None) -> dict[str, Any]:
    required = {
        "schema_version",
        "execution",
        "may_execute",
        "requires_external_privileged_agent",
        "replay_policy",
        "action",
        "target",
        "justification",
        "request_id",
        "created_at_unix",
        "expires_at_unix",
        "reference_sha256",
    }
    if not isinstance(reference, dict) or set(reference) != required:
        raise ValueError("reference has invalid keys")
    reference_hash = reference["reference_sha256"]
    unsigned = dict(reference)
    unsigned.pop("reference_sha256")
    if not isinstance(reference_hash, str) or canonical_sha256(unsigned) != reference_hash:
        raise ValueError("reference hash is invalid")
    if reference["schema_version"] != 1:
        raise ValueError("reference schema is unsupported")
    if reference["execution"] != EXECUTION_MODE or reference["may_execute"] is not False:
        raise ValueError("reference execution contract is invalid")
    if reference["requires_external_privileged_agent"] is not True:
        raise ValueError("reference external-agent contract is invalid")
    if reference["replay_policy"] != REPLAY_POLICY:
        raise ValueError("reference replay policy is invalid")
    for key in ("action", "target", "justification"):
        if not isinstance(reference[key], str) or not reference[key].strip():
            raise ValueError(f"reference {key} must be a non-empty string")
    if not isinstance(reference["request_id"], str) or not REQUEST_ID.fullmatch(reference["request_id"]):
        raise ValueError("reference request_id is invalid")
    created = reference["created_at_unix"]
    expires = reference["expires_at_unix"]
    if not isinstance(created, int) or not isinstance(expires, int):
        raise ValueError("reference timestamps are invalid")
    current = int(time.time()) if now is None else now
    if created > current + 30 or expires < current:
        raise PermissionError("reference is not currently valid")
    if expires <= created or expires - created > MAX_REFERENCE_TTL_SECONDS:
        raise ValueError("reference TTL is invalid")
    return {
        "action": reference["action"],
        "request_id": reference["request_id"],
        "created_at_unix": created,
        "expires_at_unix": expires,
        "replay_policy": reference["replay_policy"],
        "reference_sha256": reference_hash,
        "target_sha256": sha256_text(reference["target"]),
    }


def build_reference_receipt(reference: dict[str, Any], grip: str, *, now: int | None = None) -> dict[str, Any]:
    if grip not in RECEIPT_PROFILES:
        raise ValueError(f"grip must be one of {sorted(RECEIPT_PROFILES)}")
    summary = validate_reference(reference, now=now)
    profile = RECEIPT_PROFILES[grip]
    created_at = int(time.time()) if now is None else now
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "created_at_unix": created_at,
        "grip": grip,
        "scope": profile["scope"],
        "risk_level": profile["risk_level"],
        "irreversibility": profile["irreversibility"],
        "recovery_path": profile["recovery_path"],
        "read_only": profile["read_only"],
        "may_execute": False,
        "captain_default_enabled": False,
        "reference_body_included": False,
        "reference_sha256": summary["reference_sha256"],
        "reference_action": summary["action"],
        "target_sha256": summary["target_sha256"],
        "target_disclosure": "sha256-only",
        "request_id_sha256": sha256_text(summary["request_id"]),
        "reference_created_at_unix": summary["created_at_unix"],
        "reference_expires_at_unix": summary["expires_at_unix"],
        "replay_policy": summary["replay_policy"],
        "external_agent_contract": {
            "required": True,
            "single_use": True,
            "expiry_required": True,
            "broker_compatible_reference_body": True,
            "receipt_is_metadata_only": True,
            "receipt_review_before_effect": True,
        },
    }
    receipt["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    return receipt
