"""Pure Git object ID format contract for provenance-bound decision reviews.

All values here are synthetic test identities, never actual review receipts.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_decision_reviews as reviews
import grabowski_job_origin as origin


def binding(head: str, base: str, *, digest: str = "c" * 64) -> dict:
    return {
        "schema_version": reviews.BINDING_SCHEMA_VERSION,
        "kind": reviews.BINDING_KIND,
        "repo": "heimgewebe/grabowski",
        "pr": 1477,
        "head_sha": head,
        "base_sha": base,
        "diff_sha256": digest,
        "slot": "synthetic-oid-schema-only",
    }


class DecisionReviewGitObjectFormatTests(unittest.TestCase):
    def test_sha1_binding_preserves_exact_identity(self) -> None:
        normalized = reviews.normalize_binding(binding("a" * 40, "b" * 40))
        self.assertEqual("a" * 40, normalized["head_sha"])
        self.assertEqual("b" * 40, normalized["base_sha"])

    def test_sha256_binding_preserves_all_64_characters(self) -> None:
        normalized = reviews.normalize_binding(binding("a" * 64, "b" * 64))
        self.assertEqual("a" * 64, normalized["head_sha"])
        self.assertEqual("b" * 64, normalized["base_sha"])
        self.assertEqual(64, len(normalized["diff_sha256"]))
        contract = reviews.result_contract(binding("a" * 64, "b" * 64))
        self.assertEqual("b" * 64, contract["required_result"]["base_sha"])

    def test_incomplete_and_extra_long_ids_fail_closed(self) -> None:
        for size in (0, 1, 39, 41, 52, 63, 65):
            for field in ("head_sha", "base_sha"):
                with self.subTest(length=size, field=field):
                    data = binding("a" * 40, "b" * 40)
                    data[field] = "a" * size
                    with self.assertRaises(ValueError):
                        reviews.normalize_binding(data)

    def test_mixed_sha1_and_sha256_head_base_fail_closed(self) -> None:
        for head, base in (("a" * 40, "b" * 64), ("a" * 64, "b" * 40)):
            with self.subTest(head_length=len(head), base_length=len(base)):
                with self.assertRaises(ValueError):
                    reviews.normalize_binding(binding(head, base))

    def test_review_binding_and_job_clock_reject_noncanonical_oid_aliases(self) -> None:
        for width in (40, 64):
            for mutation in (lambda oid: oid.upper(), lambda oid: oid + "\n", lambda oid: oid + "\r"):
                for field in ("head_sha", "base_sha"):
                    with self.subTest(width=width, field=field, mutation=mutation("a")):
                        data = binding("a" * width, "b" * width)
                        data[field] = mutation(data[field])
                        with self.assertRaises(ValueError):
                            reviews.normalize_binding(data)
                        with self.assertRaises(ValueError):
                            origin._decision_review_order_key(
                                {"decision_bound_review": data}
                            )

    def test_job_clock_rejects_mixed_oid_formats(self) -> None:
        for first, second in ((40, 64), (64, 40)):
            with self.subTest(first=first, second=second):
                with self.assertRaises(ValueError):
                    origin._decision_review_order_key(
                        {"decision_bound_review": binding("a" * first, "b" * second)}
                    )

    def test_causal_review_clock_binds_base_and_diff_not_only_head(self) -> None:
        for width in (40, 64):
            current = binding("a" * width, "b" * width)
            same = {**current, "slot": "independent-claude-review"}
            other_base = {**current, "base_sha": "d" * width}
            other_diff = {**current, "diff_sha256": "e" * 64}
            key = origin._decision_review_order_key(
                {"decision_bound_review": current}
            )
            with self.subTest(width=width):
                self.assertEqual(key, origin._decision_review_order_key(
                    {"decision_bound_review": same}
                ))
                self.assertNotEqual(key, origin._decision_review_order_key(
                    {"decision_bound_review": other_base}
                ))
                self.assertNotEqual(key, origin._decision_review_order_key(
                    {"decision_bound_review": other_diff}
                ))
                for malformed in ("C" * 64, "c" * 63, "c" * 64 + "\n"):
                    with self.subTest(malformed_digest=malformed[:8]):
                        with self.assertRaises(ValueError):
                            origin._decision_review_order_key({
                                "decision_bound_review": {**current, "diff_sha256": malformed}
                            })

    def test_diff_digest_is_always_sha256_independent_of_git_format(self) -> None:
        for digest in ("c" * 40, "c" * 63, "c" * 65):
            with self.subTest(digest_length=len(digest)):
                with self.assertRaises(ValueError):
                    reviews.normalize_binding(binding("a" * 64, "b" * 64, digest=digest))

    def test_sha256_review_namespace_without_real_jobs_is_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing_jobs = Path(temporary) / "no-review-jobs"
            result = reviews.reconcile(
                repo="heimgewebe/grabowski", pr=1477,
                head_sha="a" * 64, base_sha="b" * 64,
                diff_sha256="c" * 64, jobs_root=missing_jobs,
            )
        self.assertEqual("not_applicable", result["status"])
        self.assertEqual(0, result["attempt_count"])
        self.assertEqual([], result["slots"])
        self.assertEqual("a" * 64, result["binding"]["head_sha"])


if __name__ == "__main__":
    unittest.main()
