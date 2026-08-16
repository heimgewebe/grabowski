#!/usr/bin/env python3
"""Durable runner for the receipt-bound mid-cutover resume.

The resume restarts the canonical operator, so it cannot run inside the process
it replaces.  This runner is the smallest possible wrapper around
``deploy_runtime_dual.resume_production_blue_green_cutover``: it re-derives the
classification from durable evidence, refuses if the authorising operator's
exact resume binding no longer classifies, and reports the resulting receipt.

It deliberately offers no target selection, no build, no rollback and no shell.
Everything it may act on is already fixed by the receipt it continues.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import deploy_runtime_dual as deploy_dual

HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
CUTOVER_ID_RE = re.compile(r"[A-Za-z0-9._:@-]{1,128}\Z")


class MidCutoverResumeIncomplete(RuntimeError):
    """The resume produced a durable non-completed receipt."""


def emit(phase: str, **fields: Any) -> None:
    print(
        json.dumps(
            {"timestamp_unix": int(time.time()), "phase": phase, **fields},
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )


def _resume_summary(result: dict[str, Any]) -> dict[str, Any]:
    receipt = result.get("receipt")
    if not isinstance(receipt, dict):
        raise RuntimeError("mid-cutover resume result lacks a receipt")
    summary = {
        "schema_version": 1,
        "kind": "grabowski_midcutover_resume_summary",
        "receipt_sha256": receipt.get("receipt_sha256"),
        "receipt_path": result.get("receipt_path"),
        "receipt_persisted": result.get("receipt_persisted") is True,
        "outcome": receipt.get("outcome"),
        "phase": receipt.get("phase"),
        "resume_id": receipt.get("resume_id"),
        "resumed_cutover_id": receipt.get("resumed_cutover_id"),
        "resumed_receipt_sha256": receipt.get("resumed_receipt_sha256"),
        "expected_head": receipt.get("expected_head"),
        "green_release_id": receipt.get("green_release_id"),
        "final_selector_sha256": (
            receipt.get("final_routing", {}).get("selector_sha256")
            if isinstance(receipt.get("final_routing"), dict)
            else None
        ),
        "authoritative_readback_sha256": (
            receipt.get("authoritative_readback", {}).get("readback_sha256")
            if isinstance(receipt.get("authoritative_readback"), dict)
            else None
        ),
        "blind_retry_allowed": receipt.get("outcome") == "denied",
    }
    return {**summary, "summary_sha256": deploy_dual._json_sha256(summary)}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continue one already-switched blue-green cutover to canonical."
    )
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--cutover-id", required=True)
    parser.add_argument("--resume-binding-sha256", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=40)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if HEAD_RE.fullmatch(args.expected_head) is None:
        raise ValueError("expected_head must be a lowercase 40-hex commit id")
    if CUTOVER_ID_RE.fullmatch(args.cutover_id) is None:
        raise ValueError("cutover_id is invalid")
    if SHA256_RE.fullmatch(args.resume_binding_sha256) is None:
        raise ValueError("resume_binding_sha256 must be a lowercase SHA-256")
    if not 5 <= args.timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be between 5 and 120")
    repo = args.repo.expanduser()
    if not repo.is_absolute():
        raise ValueError("repo must be an absolute path")

    emit(
        "midcutover-resume-scheduled",
        repo=str(repo),
        expected_head=args.expected_head,
        cutover_id=args.cutover_id,
        resume_binding_sha256=args.resume_binding_sha256,
    )
    try:
        result = deploy_dual.resume_production_blue_green_cutover(
            repo=repo,
            expected_head=args.expected_head,
            timeout_seconds=args.timeout_seconds,
            require_resume_binding_sha256=args.resume_binding_sha256,
        )
    except deploy_dual.ProductionBlueGreenReceiptPersistenceError as exc:
        summary = _resume_summary(
            {
                "receipt": exc.receipt,
                "receipt_path": None,
                "receipt_sha256": exc.receipt_sha256,
                "receipt_persisted": False,
            }
        )
        emit("midcutover-resume-receipt-persistence-failed", **summary)
        return 1
    summary = _resume_summary(result)
    emit("midcutover-resume-receipt", **summary)
    receipt = result["receipt"]
    if receipt.get("resumed_cutover_id") not in (None, args.cutover_id):
        emit(
            "midcutover-resume-lineage-drift",
            expected_cutover_id=args.cutover_id,
            observed_cutover_id=receipt.get("resumed_cutover_id"),
        )
        return 1
    if result.get("outcome") != "completed":
        emit("midcutover-resume-incomplete", outcome=result.get("outcome"))
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - runner boundary reports, never hides
        emit("midcutover-resume-failed", error_type=type(exc).__name__)
        sys.exit(1)
