import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.heim_pc_recovery_attest import ValidationError, validate


SOURCE = "9" * 40
CONTRACT = "8" * 64
EVIDENCE_ID = "off-host-home-restore"
SCOPE = "critical-user-data"
PRODUCER = "heim_pc.external_recovery_producer.off_host_home_restore.v1"
SCHEMA = "heim_pc.recovery.off_host_home_restore.v1"


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _fixture(tmp_path: Path):
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc.grabowski_recovery_producer_receipt",
        "evidence_id": EVIDENCE_ID,
        "evidence_scope": SCOPE,
        "producer": PRODUCER,
        "source_revision": SOURCE,
        "recovery_contract_sha256": CONTRACT,
        "observed_at": "2026-09-19T08:00:00Z",
        "result": "passed",
        "evidence_summary_sha256": "7" * 64,
        "production_effects_authorized": False,
    }
    receipt_path = tmp_path / "receipt.json"
    _write(receipt_path, receipt)
    receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    provenance = {
        "schema_version": 1,
        "kind": "heim_pc.nixos_recovery_evidence_provenance",
        "evidence_id": EVIDENCE_ID,
        "evidence_scope": SCOPE,
        "source_revision": SOURCE,
        "recovery_contract_sha256": CONTRACT,
        "status": "passed",
        "observed_at": "2026-09-19T08:00:00Z",
        "producer": PRODUCER,
        "evidence_schema": SCHEMA,
        "evidence": {
            "schema_version": 1,
            "kind": SCHEMA,
            "result": "passed",
            "producer_receipt_sha256": receipt_sha,
        },
        "production_effects_authorized": False,
    }
    provenance_path = tmp_path / "provenance.json"
    _write(provenance_path, provenance)
    return provenance_path, receipt_path


class RecoveryAttestationTest(unittest.TestCase):
    def test_validate_emits_exact_heim_pc_predicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt = _fixture(Path(tmp))
            result = validate(
                provenance,
                receipt,
                expected_source_revision=SOURCE,
                expected_recovery_contract_sha256=CONTRACT,
            )
        self.assertEqual(
            set(result),
            {
                "schema_version",
                "kind",
                "provenance_kind",
                "provenance_sha256",
                "producer",
                "evidence_id",
                "evidence_scope",
                "evidence_schema",
                "evidence_sha256",
                "producer_receipt_sha256",
                "source_revision",
                "recovery_contract_sha256",
                "observed_at",
                "production_effects_authorized",
            },
        )
        self.assertEqual(result["kind"], "heim_pc.nixos_recovery_provenance_attestation")
        self.assertEqual(result["producer"], PRODUCER)
        self.assertEqual(result["source_revision"], SOURCE)
        self.assertIs(result["production_effects_authorized"], False)

    def test_validate_rejects_receipt_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt = _fixture(Path(tmp))
            value = json.loads(receipt.read_text())
            value["evidence_summary_sha256"] = "6" * 64
            _write(receipt, value)
            with self.assertRaisesRegex(ValidationError, "producer receipt digest mismatch"):
                validate(
                    provenance,
                    receipt,
                    expected_source_revision=SOURCE,
                    expected_recovery_contract_sha256=CONTRACT,
                )

    def test_validate_rejects_source_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt = _fixture(Path(tmp))
            with self.assertRaisesRegex(ValidationError, "source revision mismatch"):
                validate(
                    provenance,
                    receipt,
                    expected_source_revision="a" * 40,
                    expected_recovery_contract_sha256=CONTRACT,
                )

    def test_validate_restore_schema_is_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt = _fixture(Path(tmp))
            value = json.loads(provenance.read_text())
            value["kind"] = "heim_pc.nixos_recovery_restore_test_provenance"
            value["evidence_schema"] = SCHEMA + ".restore_test"
            value["evidence"]["kind"] = SCHEMA + ".restore_test"
            _write(provenance, value)
            result = validate(
                provenance,
                receipt,
                expected_source_revision=SOURCE,
                expected_recovery_contract_sha256=CONTRACT,
            )
        self.assertEqual(
            result["provenance_kind"],
            "heim_pc.nixos_recovery_restore_test_provenance",
        )
        self.assertEqual(result["evidence_schema"], SCHEMA + ".restore_test")


if __name__ == "__main__":
    unittest.main()
