#!/usr/bin/env python3
"""Validate Heim-PC recovery provenance and emit a bound attestation predicate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

PROVENANCE_KINDS = {
    "heim_pc.nixos_recovery_evidence_provenance",
    "heim_pc.nixos_recovery_restore_test_provenance",
}
ATTESTATION_KIND = "heim_pc.nixos_recovery_provenance_attestation"
PRODUCER_RECEIPT_KIND = "heim_pc.grabowski_recovery_producer_receipt"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ValidationError(ValueError):
    pass


def _read_json(path: Path, label: str, *, max_bytes: int = 256 * 1024) -> tuple[dict[str, Any], bytes]:
    payload = path.read_bytes()
    if not payload or len(payload) > max_bytes:
        raise ValidationError(f"{label} size is outside the bounded contract")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    return value, payload


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256(payload)


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be lowercase sha256")
    return value


def _revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or REVISION_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be exact 40-hex")
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise ValidationError(f"{label} must be canonical UTC seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValidationError(f"{label} is not a valid UTC timestamp") from exc
    return value


def _expected_schema(evidence_id: str, provenance_kind: str) -> str:
    base = f"heim_pc.recovery.{evidence_id.replace('-', '_')}.v1"
    if provenance_kind == "heim_pc.nixos_recovery_restore_test_provenance":
        return base + ".restore_test"
    return base


def validate(
    provenance_path: Path,
    producer_receipt_path: Path,
    *,
    expected_source_revision: str,
    expected_recovery_contract_sha256: str,
) -> dict[str, Any]:
    expected_source_revision = _revision(expected_source_revision, "expected source revision")
    expected_recovery_contract_sha256 = _sha(
        expected_recovery_contract_sha256,
        "expected recovery contract digest",
    )
    provenance, provenance_payload = _read_json(provenance_path, "provenance")
    receipt, receipt_payload = _read_json(producer_receipt_path, "producer receipt")

    expected_provenance_keys = {
        "schema_version",
        "kind",
        "evidence_id",
        "evidence_scope",
        "source_revision",
        "recovery_contract_sha256",
        "status",
        "observed_at",
        "producer",
        "evidence_schema",
        "evidence",
        "production_effects_authorized",
    }
    if set(provenance) != expected_provenance_keys:
        raise ValidationError("provenance keys do not match the exact contract")
    if provenance.get("schema_version") != 1 or provenance.get("kind") not in PROVENANCE_KINDS:
        raise ValidationError("provenance identity mismatch")
    evidence_id = provenance.get("evidence_id")
    evidence_scope = provenance.get("evidence_scope")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ValidationError("provenance evidence_id is invalid")
    if not isinstance(evidence_scope, str) or not evidence_scope:
        raise ValidationError("provenance evidence_scope is invalid")
    if provenance.get("source_revision") != expected_source_revision:
        raise ValidationError("provenance source revision mismatch")
    if provenance.get("recovery_contract_sha256") != expected_recovery_contract_sha256:
        raise ValidationError("provenance recovery contract digest mismatch")
    if provenance.get("status") != "passed":
        raise ValidationError("provenance status did not pass")
    observed_at = _utc(provenance.get("observed_at"), "provenance observed_at")
    expected_producer = f"heim_pc.external_recovery_producer.{evidence_id.replace('-', '_')}.v1"
    if provenance.get("producer") != expected_producer:
        raise ValidationError("provenance producer mismatch")
    expected_schema = _expected_schema(evidence_id, provenance["kind"])
    if provenance.get("evidence_schema") != expected_schema:
        raise ValidationError("provenance evidence schema mismatch")
    if provenance.get("production_effects_authorized") is not False:
        raise ValidationError("provenance must not authorize production effects")

    evidence = provenance.get("evidence")
    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"schema_version", "kind", "result", "producer_receipt_sha256"}
        or evidence.get("schema_version") != 1
        or evidence.get("kind") != expected_schema
        or evidence.get("result") != "passed"
    ):
        raise ValidationError("provenance evidence payload is invalid")
    producer_receipt_sha256 = _sha(
        evidence.get("producer_receipt_sha256"),
        "provenance producer receipt digest",
    )
    if producer_receipt_sha256 != _sha256(receipt_payload):
        raise ValidationError("producer receipt digest mismatch")

    expected_receipt_keys = {
        "schema_version",
        "kind",
        "evidence_id",
        "evidence_scope",
        "producer",
        "provenance_kind",
        "evidence_schema",
        "source_revision",
        "recovery_contract_sha256",
        "observed_at",
        "result",
        "evidence_summary_sha256",
        "production_effects_authorized",
    }
    if set(receipt) != expected_receipt_keys:
        raise ValidationError("producer receipt keys do not match the exact contract")
    if receipt.get("schema_version") != 1 or receipt.get("kind") != PRODUCER_RECEIPT_KIND:
        raise ValidationError("producer receipt identity mismatch")
    for key in (
        "evidence_id",
        "evidence_scope",
        "producer",
        "provenance_kind",
        "evidence_schema",
        "source_revision",
        "recovery_contract_sha256",
        "observed_at",
    ):
        if receipt.get(key) != provenance.get(key):
            raise ValidationError(f"producer receipt {key} mismatch")
    if receipt.get("result") != "passed":
        raise ValidationError("producer receipt did not pass")
    _sha(receipt.get("evidence_summary_sha256"), "producer receipt evidence summary digest")
    if receipt.get("production_effects_authorized") is not False:
        raise ValidationError("producer receipt must not authorize production effects")

    return {
        "schema_version": 1,
        "kind": ATTESTATION_KIND,
        "provenance_kind": provenance["kind"],
        "provenance_sha256": _sha256(provenance_payload),
        "producer": provenance["producer"],
        "evidence_id": evidence_id,
        "evidence_scope": evidence_scope,
        "evidence_schema": expected_schema,
        "evidence_sha256": _sha256_json(evidence),
        "producer_receipt_sha256": producer_receipt_sha256,
        "source_revision": expected_source_revision,
        "recovery_contract_sha256": expected_recovery_contract_sha256,
        "observed_at": observed_at,
        "production_effects_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--producer-receipt", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-recovery-contract-sha256", required=True)
    parser.add_argument("--predicate-out", type=Path, required=True)
    args = parser.parse_args()

    predicate = validate(
        args.provenance,
        args.producer_receipt,
        expected_source_revision=args.expected_source_revision,
        expected_recovery_contract_sha256=args.expected_recovery_contract_sha256,
    )
    args.predicate_out.write_text(
        json.dumps(predicate, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "evidence_id": predicate["evidence_id"],
        "provenance_sha256": predicate["provenance_sha256"],
        "producer_receipt_sha256": predicate["producer_receipt_sha256"],
        "source_revision": predicate["source_revision"],
        "recovery_contract_sha256": predicate["recovery_contract_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
