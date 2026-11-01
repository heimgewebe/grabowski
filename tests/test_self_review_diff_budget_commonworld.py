"""Bound canonical signed-diff admission for source-heavy immutable snapshot PRs.

The concrete Commonworld PR #237 measurement is evidence for the required
ceiling, not an exemption from immutable signing or full source-read coverage.
"""
from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402


class SignedGeneratedDiffBudgetTests(unittest.TestCase):
    def test_measured_generated_snapshot_fits_still_bounded_limits(self) -> None:
        # PR #237 on base 9390e869 -> head 2e6f343c with --full-index.
        self.assertLessEqual(35_776_527, review.FIRST_PARTY_MAX_DIFF_BYTES)
        self.assertLessEqual(4_158, review.FIRST_PARTY_MAX_CHANGED_PATHS)
        self.assertEqual(review.FIRST_PARTY_MAX_DIFF_BYTES, 36 * 1024 * 1024)
        self.assertEqual(review.FIRST_PARTY_MAX_CHANGED_PATHS, 4_608)
        # The existing bounded, signed chunk contract remains unchanged.
        self.assertEqual(review.FIRST_PARTY_MAX_READ_BYTES, 768 * 1024)
        self.assertEqual(review.FIRST_PARTY_MAX_READ_LINES, 1_000)

    def test_changed_path_limit_accepts_boundary_and_rejects_one_more(self) -> None:
        binding = {"base_sha": "a" * 40, "head_sha": "b" * 40}
        for count, expected_valid in [(review.FIRST_PARTY_MAX_CHANGED_PATHS, True),
                                      (review.FIRST_PARTY_MAX_CHANGED_PATHS + 1, False)]:
            names = [f"releases/generated/project_{i:05}.json" for i in range(count)]
            raw = b"\0".join(name.encode("ascii") for name in names) + b"\0"
            with self.subTest(count=count), mock.patch.object(review, "_git_read", return_value=raw) as read:
                if expected_valid:
                    self.assertEqual(len(review._first_party_changed_paths(Path("."), binding)), count)
                else:
                    with self.assertRaisesRegex(review.ReviewExecutionRejected, "changed path set invalid"):
                        review._first_party_changed_paths(Path("."), binding)
                self.assertEqual(read.call_args.kwargs["maximum"], review.FIRST_PARTY_MAX_DIFF_BYTES)

    def test_canonical_diff_reader_retains_full_index_and_strict_cap(self) -> None:
        binding = {"base_sha": "a" * 40, "head_sha": "b" * 40,
                   "review_purpose": "pull_request"}
        with mock.patch.object(review, "_git_read", return_value=b"diff --git a/x b/x\n") as read:
            review._first_party_diff(Path("."), binding)
        self.assertEqual(read.call_args.kwargs["maximum"], 36 * 1024 * 1024)
        argv = read.call_args.args[1]
        self.assertIn("--full-index", argv)
        self.assertIn("--no-renames", argv)
        self.assertIn("--ignore-submodules=none", argv)


if __name__ == "__main__":
    unittest.main()
