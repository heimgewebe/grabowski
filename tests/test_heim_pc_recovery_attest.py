import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.heim_pc_recovery_attest import (
    PRODUCER_SIGNATURE_NAMESPACE,
    PRODUCER_SIGNER_PRINCIPAL,
    SSH_KEYGEN,
    ValidationError,
    validate,
)


SOURCE = "9" * 40
EVIDENCE_ID = "off-host-home-restore"
SCOPE = "critical-user-data"
PRODUCER = "heim_pc.external_recovery_producer.off_host_home_restore.v1"
SCHEMA = "heim_pc.recovery.off_host_home_restore.v1"
RECOVERY_CONTRACT = {
    "schema_version": 1,
    "kind": "heim_pc.nixos_recovery_readiness_contract",
    "required_evidence": [
        {
            "id": EVIDENCE_ID,
            "scope": SCOPE,
            "requires_restore_test": True,
            "producer": PRODUCER,
            "evidence_schema": SCHEMA,
            "restore_test_schema": SCHEMA + ".restore_test",
        }
    ],
}
RECOVERY_CONTRACT_BYTES = (
    json.dumps(RECOVERY_CONTRACT, sort_keys=True) + "\n"
).encode("utf-8")
CONTRACT = hashlib.sha256(RECOVERY_CONTRACT_BYTES).hexdigest()


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _signing_material(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "producer-signing-key"
    subprocess.run(
        [SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    public_key = Path(str(key) + ".pub").read_text(encoding="utf-8").strip()
    allowed_signers = tmp_path / "allowed-signers"
    allowed_signers.write_text(
        (
            f'{PRODUCER_SIGNER_PRINCIPAL} '
            f'namespaces="{PRODUCER_SIGNATURE_NAMESPACE}" {public_key}\n'
        ),
        encoding="utf-8",
    )
    return key, allowed_signers


def _sign_receipt(
    receipt_path: Path,
    signing_key: Path,
    *,
    namespace: str = PRODUCER_SIGNATURE_NAMESPACE,
) -> Path:
    signature_path = Path(str(receipt_path) + ".sig")
    signature_path.unlink(missing_ok=True)
    subprocess.run(
        [
            SSH_KEYGEN,
            "-Y",
            "sign",
            "-f",
            str(signing_key),
            "-n",
            namespace,
            str(receipt_path),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return signature_path


def _fixture(tmp_path: Path):
    signing_key, allowed_signers = _signing_material(tmp_path)
    contract_path = tmp_path / "recovery-contract-v1.json"
    contract_path.write_bytes(RECOVERY_CONTRACT_BYTES)
    receipt = {
        "schema_version": 1,
        "kind": "heim_pc.grabowski_recovery_producer_receipt",
        "evidence_id": EVIDENCE_ID,
        "evidence_scope": SCOPE,
        "producer": PRODUCER,
        "provenance_kind": "heim_pc.nixos_recovery_evidence_provenance",
        "evidence_schema": SCHEMA,
        "source_revision": SOURCE,
        "recovery_contract_sha256": CONTRACT,
        "observed_at": "2026-09-19T08:00:00Z",
        "result": "passed",
        "evidence_summary_sha256": "7" * 64,
        "production_effects_authorized": False,
    }
    receipt_path = tmp_path / "receipt.json"
    _write(receipt_path, receipt)
    signature_path = _sign_receipt(receipt_path, signing_key)
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
    return (
        provenance_path,
        receipt_path,
        signature_path,
        allowed_signers,
        signing_key,
    )


def _validate(
    provenance: Path,
    receipt: Path,
    signature: Path,
    allowed_signers: Path,
    *,
    source_revision: str = SOURCE,
):
    return validate(
        provenance,
        receipt,
        signature,
        allowed_signers,
        provenance.parent / "recovery-contract-v1.json",
        expected_source_revision=source_revision,
        expected_recovery_contract_sha256=CONTRACT,
    )


class RecoveryAttestationTest(unittest.TestCase):
    def test_validate_emits_exact_heim_pc_predicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt, signature, allowed_signers, _ = _fixture(Path(tmp))
            result = _validate(provenance, receipt, signature, allowed_signers)
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

    def test_validate_rejects_self_consistent_but_unauthenticated_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                provenance,
                receipt,
                signature,
                allowed_signers,
                _,
            ) = _fixture(Path(tmp))
            receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
            receipt_value["evidence_summary_sha256"] = "6" * 64
            _write(receipt, receipt_value)

            provenance_value = json.loads(provenance.read_text(encoding="utf-8"))
            provenance_value["evidence"]["producer_receipt_sha256"] = hashlib.sha256(
                receipt.read_bytes()
            ).hexdigest()
            _write(provenance, provenance_value)

            with self.assertRaisesRegex(
                ValidationError,
                "producer receipt signature is not authenticated",
            ):
                _validate(provenance, receipt, signature, allowed_signers)

    def test_validate_rejects_evidence_not_required_by_bound_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt, signature, allowed_signers, _ = _fixture(Path(tmp))
            value = json.loads(provenance.read_text(encoding="utf-8"))
            value["evidence_id"] = "not-required-by-contract"
            _write(provenance, value)
            with self.assertRaisesRegex(
                ValidationError, "evidence_id is not required by recovery contract"
            ):
                _validate(provenance, receipt, signature, allowed_signers)

    def test_validate_rejects_scope_not_bound_by_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt, signature, allowed_signers, _ = _fixture(Path(tmp))
            value = json.loads(provenance.read_text(encoding="utf-8"))
            value["evidence_scope"] = "wrong-scope"
            _write(provenance, value)
            with self.assertRaisesRegex(
                ValidationError, "provenance evidence scope mismatch"
            ):
                _validate(provenance, receipt, signature, allowed_signers)

    def test_validate_rejects_receipt_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                provenance,
                receipt,
                _,
                allowed_signers,
                signing_key,
            ) = _fixture(Path(tmp))
            value = json.loads(receipt.read_text(encoding="utf-8"))
            value["evidence_summary_sha256"] = "6" * 64
            _write(receipt, value)
            signature = _sign_receipt(receipt, signing_key)
            with self.assertRaisesRegex(ValidationError, "producer receipt digest mismatch"):
                _validate(provenance, receipt, signature, allowed_signers)

    def test_validate_rejects_source_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt, signature, allowed_signers, _ = _fixture(Path(tmp))
            with self.assertRaisesRegex(ValidationError, "source revision mismatch"):
                _validate(
                    provenance,
                    receipt,
                    signature,
                    allowed_signers,
                    source_revision="a" * 40,
                )

    def test_validate_rejects_cross_use_of_evidence_receipt_for_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            provenance, receipt, signature, allowed_signers, _ = _fixture(Path(tmp))
            value = json.loads(provenance.read_text(encoding="utf-8"))
            value["kind"] = "heim_pc.nixos_recovery_restore_test_provenance"
            value["evidence_schema"] = SCHEMA + ".restore_test"
            value["evidence"]["kind"] = SCHEMA + ".restore_test"
            _write(provenance, value)
            with self.assertRaisesRegex(ValidationError, "provenance_kind mismatch"):
                _validate(provenance, receipt, signature, allowed_signers)

    def test_validate_restore_schema_is_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            (
                provenance,
                receipt,
                _,
                allowed_signers,
                signing_key,
            ) = _fixture(Path(tmp))
            receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
            receipt_value["provenance_kind"] = (
                "heim_pc.nixos_recovery_restore_test_provenance"
            )
            receipt_value["evidence_schema"] = SCHEMA + ".restore_test"
            _write(receipt, receipt_value)
            signature = _sign_receipt(receipt, signing_key)
            receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()

            value = json.loads(provenance.read_text(encoding="utf-8"))
            value["kind"] = "heim_pc.nixos_recovery_restore_test_provenance"
            value["evidence_schema"] = SCHEMA + ".restore_test"
            value["evidence"]["kind"] = SCHEMA + ".restore_test"
            value["evidence"]["producer_receipt_sha256"] = receipt_sha
            _write(provenance, value)
            result = _validate(provenance, receipt, signature, allowed_signers)
        self.assertEqual(
            result["provenance_kind"],
            "heim_pc.nixos_recovery_restore_test_provenance",
        )
        self.assertEqual(result["evidence_schema"], SCHEMA + ".restore_test")


if __name__ == "__main__":
    unittest.main()
