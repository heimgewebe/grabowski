from __future__ import annotations

import pytest

from grabowski_admin_reference_receipts import build_reference_receipt
from grabowski_admin_reference_receipts import sha256_json
from grabowski_admin_reference_receipts import sha256_text


def test_build_reference_receipt_binds_reference_and_target_hash() -> None:
    result = build_reference_receipt(
        action="edit_system_service",
        target="grabowski-mcp.service",
        justification="Need operator runtime restart after reviewed deploy.",
        now_unix=1_783_400_000,
        request_id="a" * 32,
    )

    reference = result["reference"]
    receipt = result["receipt"]

    assert reference["may_execute"] is False
    assert reference["requires_external_agent"] is True
    assert reference["expires_at_unix"] == 1_783_400_900
    assert reference["reference_sha256"] == sha256_json(
        {key: value for key, value in reference.items() if key != "reference_sha256"}
    )
    assert receipt["reference_sha256"] == reference["reference_sha256"]
    assert receipt["target_sha256"] == sha256_text("grabowski-mcp.service")
    assert receipt["receipt_sha256"] == sha256_json(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    assert "does not execute action" in result["non_claims"]


def test_build_reference_receipt_rejects_unknown_action() -> None:
    with pytest.raises(ValueError, match="action must be one of"):
        build_reference_receipt(
            action="do_everything",
            target="grabowski-mcp.service",
            justification="too broad",
            now_unix=1,
            request_id="b" * 32,
        )


def test_build_reference_receipt_validates_request_id() -> None:
    with pytest.raises(ValueError, match="request_id"):
        build_reference_receipt(
            action="edit_system_service",
            target="grabowski-mcp.service",
            justification="Need controlled broker handoff.",
            now_unix=1,
            request_id="not-hex",
        )
