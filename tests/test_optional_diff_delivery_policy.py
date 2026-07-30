from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class OptionalDiffDeliveryPolicyTests(unittest.TestCase):
    def test_normative_sources_do_not_reintroduce_merge_prerequisite(self) -> None:
        paths = [
            ROOT / "contracts" / "tool-surface-budget.v1.json",
            ROOT / "docs" / "grip-mechanic-captain-boundary-v1.md",
            ROOT / "docs" / "merge-delivery-v1.md",
            ROOT / "docs" / "external-review-loop.md",
            ROOT / "docs" / "proofs" / "convergence-closure-surface-coverage-v1.json",
            ROOT / "src" / "grabowski_grips.py",
            ROOT / "src" / "grabowski_merge_guard.py",
        ]
        forbidden_phrases = [
            "diff-delivery-recorded",
            "delivery-receipt revalidation",
            "independently revalidated by Captain",
            "Diff delivery is pre-merge evidence.",
            "delivery_before_merge",
            "delivery_after_merge",
        ]

        for path in paths:
            text = path.read_text(encoding="utf-8")
            for phrase in forbidden_phrases:
                with self.subTest(path=path.relative_to(ROOT), phrase=phrase):
                    self.assertNotIn(phrase, text)

    def test_optional_handoff_is_explicitly_separate_from_merge_authority(self) -> None:
        budget = (ROOT / "contracts" / "tool-surface-budget.v1.json").read_text(
            encoding="utf-8"
        )
        boundary = (
            ROOT / "docs" / "grip-mechanic-captain-boundary-v1.md"
        ).read_text(encoding="utf-8")

        self.assertIn("optional append-only artifact-handoff boundary", budget)
        self.assertIn("Captain and the atomic merge guard do not require", budget)
        self.assertIn("no user-visible diff artifact is required", boundary)
        self.assertIn("artifact-delivery timestamps and ordering are not part", boundary)
        self.assertIn("former `merge_delivery_receipt_sha256`", (ROOT / "docs" / "merge-delivery-v1.md").read_text(encoding="utf-8"))
        self.assertIn("LEGACY_OPTIONAL_EVIDENCE_KEYS", (ROOT / "src" / "grabowski_grips.py").read_text(encoding="utf-8"))

    def test_legacy_delivery_digest_is_compatibility_only(self) -> None:
        source = (ROOT / "src" / "grabowski_grips.py").read_text(encoding="utf-8")
        documentation = (ROOT / "docs" / "merge-delivery-v1.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("CAPTAIN_EXECUTION_INTENT_LEGACY_OPTIONAL_EVIDENCE_KEYS", source)
        self.assertIn("creates no gate and grants no merge authority", documentation)


if __name__ == "__main__":
    unittest.main()
