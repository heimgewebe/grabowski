from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pr_review_gate_ci as ci  # noqa: E402
import review_evidence_schemas as schemas  # noqa: E402


def _audit(**overrides) -> bytes:
    payload = {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "generated_at": "2026-07-23T00:00:00+00:00",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "base_sha": "c" * 40,
        "diff_sha256": "b" * 64,
        "review_policy_version": schemas.REVIEW_POLICY_VERSION,
        "review_tier": "standard",
        "minimum_review_iterations": 2,
        "actual_review_iterations": 2,
        "all_findings_triaged": True,
        "finding_count": 0,
        "material_findings_after_first_review": 0,
        "material_findings_remaining": 0,
        "uncertainty": 0.1,
        "residual_risk_accepted": False,
        "residual_risk_reason": "private",
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "tuning_signal": "observe",
    }
    payload.update(overrides)
    return (json.dumps(payload, sort_keys=True) + "\n").encode()


class ReviewEvidenceProvenanceEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.key_a = self.root / "key-a"
        self.key_b = self.root / "key-b"
        self.allowed = self.root / "allowed_signers"
        self._generate_key(self.key_a)
        self._generate_key(self.key_b)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _generate_key(path: Path) -> None:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def _public_key(path: Path) -> tuple[str, str]:
        parts = path.with_suffix(".pub").read_text(encoding="utf-8").strip().split()
        return parts[0], parts[1]

    def _write_allowlist(self, *keys: Path) -> None:
        lines = []
        for key in keys:
            key_type, encoded = self._public_key(key)
            lines.append(
                f'{ci.SIGNER_PRINCIPAL} namespaces="{ci.SIGNATURE_NAMESPACE}" '
                f"{key_type} {encoded}"
            )
        self.allowed.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_rotation_allowlist_accepts_old_and_new_key_during_overlap(self) -> None:
        self._write_allowlist(self.key_a, self.key_b)
        for key in (self.key_a, self.key_b):
            with self.subTest(key=key.name):
                attestation = ci.build_signed_status_attestation(
                    _audit(), signing_key=key
                )
                encoded = ci.encode_signed_status_attestation(attestation)
                verified = ci.decode_signed_status_attestation(
                    encoded, allowed_signers_path=self.allowed
                )
                self.assertEqual(verified["head_sha"], "a" * 40)

    def test_signer_principal_mismatch_is_rejected_before_signature_acceptance(self) -> None:
        self._write_allowlist(self.key_a)
        attestation = ci.build_signed_status_attestation(
            _audit(), signing_key=self.key_a
        )
        attestation["signer_principal"] = "other-review-gate@example.invalid"
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signer_principal"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.allowed
            )

    def test_signature_namespace_mismatch_is_rejected_before_signature_acceptance(self) -> None:
        self._write_allowlist(self.key_a)
        attestation = ci.build_signed_status_attestation(
            _audit(), signing_key=self.key_a
        )
        attestation["signature_namespace"] = "other-namespace"
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signature_namespace"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.allowed
            )

    def test_non_ssh_signature_armor_is_rejected(self) -> None:
        self._write_allowlist(self.key_a)
        attestation = ci.build_signed_status_attestation(
            _audit(), signing_key=self.key_a
        )
        attestation["signature_b64"] = base64.b64encode(
            b"not an ssh signature"
        ).decode("ascii")
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signature is invalid"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.allowed
            )

    def test_oversized_attestation_base64_is_rejected_before_decode(self) -> None:
        oversized = "A" * (ci.MAX_ATTESTATION_B64_BYTES + 1)
        with self.assertRaisesRegex(ci.CiEvidenceError, "exceeds"):
            ci.decode_signed_status_attestation(
                oversized, allowed_signers_path=self.allowed
            )

    def test_stale_review_policy_audit_is_rejected_by_canonical_schema(self) -> None:
        stale_policy = schemas.REVIEW_POLICY_VERSION - 1
        with self.assertRaisesRegex(ci.CiEvidenceError, "review_policy_version"):
            ci.build_status_projection(_audit(review_policy_version=stale_policy))


if __name__ == "__main__":
    unittest.main()
