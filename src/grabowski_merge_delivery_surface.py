from __future__ import annotations

import importlib
import time
from typing import Any

import grabowski_merge_delivery as delivery


def _module(name: str) -> Any:
    return importlib.import_module(name)


def _base() -> Any:
    return _module("grabowski_mcp")


def _audit_delivery(result: dict[str, Any]) -> dict[str, Any]:
    receipt = result["receipt"]
    return {
        "timestamp_unix": int(time.time()),
        "operation": "merge-delivery-record",
        "repository": receipt["repository"],
        "pull_request": receipt["pull_request"],
        "base_sha": receipt["base_sha"],
        "head_sha": receipt["head_sha"],
        "diff_sha256": receipt["diff_sha256"],
        "artifact_id": receipt["artifact_id"],
        "delivery_channel": receipt["delivery_channel"],
        "delivery_reference_sha256": receipt["delivery_reference_sha256"],
        "delivery_confirmed_at_unix_ns": receipt["delivery_confirmed_at_unix_ns"],
        "receipt_sha256": result["receipt_sha256"],
    }


def grabowski_merge_delivery_record(
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    diff_sha256: str,
    artifact_id: str,
    artifact_sha256: str,
    artifact_receipt_sha256: str,
    delivery_channel: str,
    delivery_reference: str,
) -> dict[str, Any]:
    """Record one durable, exact diff delivery before a possible PR merge."""
    try:
        result = delivery.record_merge_delivery(
            repository=repository,
            pull_request=pull_request,
            base_sha=base_sha,
            head_sha=head_sha,
            diff_sha256=diff_sha256,
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            artifact_receipt_sha256=artifact_receipt_sha256,
            delivery_channel=delivery_channel,
            delivery_reference=delivery_reference,
        )
    except Exception as exc:
        raise RuntimeError(
            f"merge delivery record failed: {type(exc).__name__}: {exc}"
        ) from None
    _base()._append_audit(_audit_delivery(result))
    return result
