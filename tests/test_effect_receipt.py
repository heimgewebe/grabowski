from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_effect_receipt as effect_receipt


class EffectReceiptTests(unittest.TestCase):
    def admission(self, **overrides):
        parameters = {
            "tool": "grabowski_git",
            "arguments": {"repo": "/tmp/repo", "arguments": ["status"]},
            "runtime_sha256": "a" * 64,
            "effect_class": "mutating",
            "lane_id": "lane-1",
            "actor_id": "controller:chatgpt",
            "resource_keys": ["path:/tmp/repo/b", "path:/tmp/repo/a"],
            "request_id": "1" * 32,
            "admitted_at_unix": 100,
        }
        parameters.update(overrides)
        return effect_receipt.admit(**parameters)

    def test_admission_is_exactly_hash_bound_and_resource_order_independent(self) -> None:
        records = []

        def append(record):
            records.append(record)
            return "f" * 64

        first = effect_receipt.admit(
            tool="grabowski_git",
            arguments={"arguments": ["status"], "repo": "/tmp/repo"},
            runtime_sha256="a" * 64,
            effect_class="mutating",
            lane_id="lane-1",
            actor_id="controller:chatgpt",
            resource_keys=["path:/tmp/repo/b", "path:/tmp/repo/a"],
            request_id="1" * 32,
            admitted_at_unix=100,
            append_audit=append,
        )
        second = self.admission(
            resource_keys=["path:/tmp/repo/a", "path:/tmp/repo/b"]
        )
        self.assertEqual(first["admission_sha256"], second["admission_sha256"])
        self.assertEqual(first["audit_record_sha256"], "f" * 64)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["operation"], "effect-admission")
        effect_receipt.validate_admission(first)

    def test_tampered_admission_fails_closed(self) -> None:
        admission = self.admission()
        admission["tool"] = "grabowski_github"
        with self.assertRaisesRegex(
            effect_receipt.EffectReceiptIntegrityError,
            "digest mismatch",
        ):
            effect_receipt.validate_admission(admission)

    def test_completion_collects_only_bounded_receipt_digests(self) -> None:
        admission = self.admission()
        result = {
            "receipt_sha256": "2" * 64,
            "nested": {
                "lifecycle_receipt_sha256": "3" * 64,
                "ordinary_sha256": "4" * 64,
                "secret": "do-not-copy",
            },
        }
        records = []
        completion = effect_receipt.complete(
            admission,
            completion_class="effect_observed",
            result=result,
            domain_receipts=["5" * 64],
            post_state={"head": "abc"},
            completed_at_unix=101,
            append_audit=lambda record: records.append(record) or "6" * 64,
        )
        self.assertEqual(
            completion["domain_receipts"],
            ["2" * 64, "3" * 64, "5" * 64],
        )
        self.assertTrue(completion["post_state_observed"])
        self.assertEqual(completion["audit_record_sha256"], "6" * 64)
        self.assertNotIn("secret", records[0])
        self.assertNotIn("result", records[0])

    def test_error_is_fingerprinted_without_copying_error_text(self) -> None:
        error = RuntimeError("sensitive diagnostic text")
        completion = effect_receipt.complete(
            self.admission(),
            completion_class="outcome_unknown",
            error=error,
            completed_at_unix=102,
        )
        self.assertEqual(completion["error_class"], "RuntimeError")
        self.assertRegex(completion["error_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("sensitive diagnostic text", str(completion))
        self.assertFalse(completion["post_state_observed"])

    def test_exception_classification_preserves_effect_boundary(self) -> None:
        self.assertEqual(
            effect_receipt.exception_completion_class(effect_started=True),
            "outcome_unknown",
        )
        self.assertEqual(
            effect_receipt.exception_completion_class(
                effect_started=False, rejected=True
            ),
            "rejected_before_effect",
        )
        self.assertEqual(
            effect_receipt.exception_completion_class(effect_started=False),
            "failed_before_effect",
        )

    def test_invalid_identity_and_digest_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.admission(actor_id="bad\nactor")
        with self.assertRaises(ValueError):
            self.admission(runtime_sha256="not-a-digest")
        with self.assertRaises(ValueError):
            self.admission(effect_class="unknown")


if __name__ == "__main__":
    unittest.main()
