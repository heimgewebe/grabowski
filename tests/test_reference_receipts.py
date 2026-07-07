from __future__ import annotations

from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_reference_receipts as receipts


class ReferenceReceiptTests(unittest.TestCase):
    def _reference(self, *, target: str = "grabowski-mcp.service", now: int = 1000) -> dict[str, object]:
        value: dict[str, object] = {
            "schema_version": 1,
            "execution": receipts.EXECUTION_MODE,
            "may_execute": False,
            "requires_external_privileged_agent": True,
            "replay_policy": receipts.REPLAY_POLICY,
            "action": "edit_system_service",
            "target": target,
            "justification": "Operate the explicitly named managed service",
            "request_id": "a" * 32,
            "created_at_unix": now,
            "expires_at_unix": now + receipts.MAX_REFERENCE_TTL_SECONDS,
        }
        value["reference_sha256"] = receipts.canonical_sha256(value)
        return value

    def test_receipt_binds_reference_hash_without_plain_target(self) -> None:
        reference = self._reference()
        receipt = receipts.build_reference_receipt(reference, "service-restart", now=1000)
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertEqual(receipt["reference_sha256"], reference["reference_sha256"])
        self.assertEqual(receipt["target_disclosure"], "sha256-only")
        self.assertIn("target_sha256", receipt)
        self.assertNotIn(str(reference["target"]), encoded)
        self.assertFalse(receipt["reference_body_included"])
        self.assertFalse(receipt["may_execute"])
        expected_hash = receipts.canonical_sha256(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        self.assertEqual(receipt["receipt_sha256"], expected_hash)

    def test_runtime_deploy_check_profile_is_read_only(self) -> None:
        receipt = receipts.build_reference_receipt(
            self._reference(target="runtime-check"),
            "runtime-deploy-check",
            now=1000,
        )
        self.assertTrue(receipt["read_only"])
        self.assertEqual(receipt["risk_level"], "low")
        self.assertEqual(receipt["irreversibility"], "none")
        self.assertFalse(receipt["captain_default_enabled"])

    def test_rejects_tampered_or_expired_reference(self) -> None:
        reference = self._reference()
        tampered = dict(reference)
        tampered["target"] = "other.service"
        with self.assertRaises(ValueError):
            receipts.build_reference_receipt(tampered, "service-restart", now=1000)
        with self.assertRaises(PermissionError):
            receipts.build_reference_receipt(reference, "service-restart", now=2000)

    def test_external_agent_contract_is_visible(self) -> None:
        receipt = receipts.build_reference_receipt(self._reference(), "runtime-deploy", now=1000)
        contract = receipt["external_agent_contract"]
        self.assertTrue(contract["required"])
        self.assertTrue(contract["single_use"])
        self.assertTrue(contract["expiry_required"])
        self.assertTrue(contract["broker_compatible_reference_body"])
        self.assertTrue(contract["receipt_is_metadata_only"])


if __name__ == "__main__":
    unittest.main()
