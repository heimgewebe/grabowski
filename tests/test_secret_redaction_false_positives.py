from __future__ import annotations

import unittest

import grabowski_mcp
import grabowski_operator
from tools import build_local_evidence
from tools import grabowski_safety_observer


def _provider_prefix() -> str:
    return "s" + "k-"


class SecretRedactionFalsePositiveTests(unittest.TestCase):
    def test_task_identifiers_are_not_redacted_as_api_keys(self) -> None:
        samples = [
            "task-reconcile",
            "grabowski-task-1234567890abcdef12345678-a1.service",
            "operation=task-start unit=grabowski-task-abcdefabcdefabcdefabcdef-a2.service",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(grabowski_operator._redact(sample), sample)
                self.assertEqual(grabowski_mcp._redact_sensitive_text(sample)[0], sample)
                self.assertEqual(build_local_evidence._redact(sample), (sample, 0))
                self.assertNotIn("<REDACTED>", grabowski_safety_observer.redact(sample))

    def test_realistic_provider_keys_are_still_redacted(self) -> None:
        prefix = _provider_prefix()
        samples = [
            prefix + "a" * 24,
            prefix + "proj-" + "A" * 32,
            prefix + "ant-" + "B" * 32,
        ]
        for sample in samples:
            with self.subTest(sample=sample[:8]):
                self.assertNotEqual(grabowski_operator._redact(sample), sample)
                self.assertNotEqual(grabowski_mcp._redact_sensitive_text(sample)[0], sample)
                self.assertNotEqual(build_local_evidence._redact(sample)[0], sample)
                self.assertIn("<REDACTED", grabowski_safety_observer.redact(sample))


if __name__ == "__main__":
    unittest.main()
