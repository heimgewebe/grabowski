"""Scoping regressions for Captain's decision-bound review reconciliation."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import grabowski_decision_reviews as reviews
from test_decision_reviews import (
    BASE,
    DIFF,
    HEAD,
    PR,
    REPO,
    make_job,
    result,
    write_private,
)


class CrossPrHistoricalReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.jobs = Path(temporary.name) / "jobs"
        self.jobs.mkdir(mode=0o700)

    def _reconcile_original(self) -> dict:
        return reviews.reconcile(
            repo=REPO, pr=PR, head_sha=HEAD,
            base_sha=BASE, diff_sha256=DIFF, jobs_root=self.jobs,
        )

    def _reconcile_foreign(self) -> dict:
        return reviews.reconcile(
            repo="heimgewebe/bureau", pr=2363,
            head_sha="d" * 40, base_sha="e" * 40,
            diff_sha256="f" * 64, jobs_root=self.jobs,
        )

    def test_authenticated_foreign_review_with_stale_provenance_cannot_block_other_pr(self) -> None:
        job = make_job(
            self.jobs, suffix="a123456789ab", slot="independent-other-pr",
            terminal_status="succeeded", review_result=None,
            review_role=True, attempt_bound=True, attempt_epoch=2,
        )
        path = job / "metadata.json"
        metadata = json.loads(path.read_text())
        provenance = dict(metadata["scope"]["decision_review_provenance"])
        provenance["role_receipt_path"] = str(job / "obsolete-review-role.json")
        provenance["provenance_sha256"] = reviews.sha256_json({
            key: value for key, value in provenance.items()
            if key != "provenance_sha256"
        })
        metadata["scope"]["decision_review_provenance"] = provenance
        metadata["origin"]["scope"] = metadata["scope"]
        metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
        write_private(path, json.dumps(metadata))
        with self.assertRaises(ValueError):
            reviews._validated_origin_binding(job)

        unrelated = self._reconcile_foreign()
        self.assertEqual(unrelated["errors"], [])
        self.assertEqual(unrelated["status"], "not_applicable")
        self.assertEqual(unrelated["attempt_count"], 0)

        relevant = self._reconcile_original()
        self.assertEqual(relevant["status"], "blocked")
        self.assertTrue(any(
            "decision_review_origin_invalid" in value for value in relevant["errors"]
        ))

    def _ordinary_long_output(self, *, marker: bytes = b"") -> Path:
        job = make_job(
            self.jobs, suffix="b123456789ab", slot="not-a-review",
            terminal_status="succeeded", review_result=None,
        )
        path = job / "metadata.json"
        metadata = json.loads(path.read_text())
        scope = dict(metadata["scope"])
        scope.pop("decision_bound_review", None)
        scope.pop("decision_review_provenance", None)
        scope.pop("decision_review_attempt_epoch", None)
        metadata["scope"] = scope
        metadata["origin"]["scope"] = scope
        metadata["origin_sha256"] = reviews.sha256_json(metadata["origin"])
        write_private(path, json.dumps(metadata))
        with (job / "stdout.log").open("wb") as stream:
            if marker:
                stream.write(marker)
            stream.truncate(24_100_000)
        os.chmod(job / "stdout.log", 0o600)
        return job

    def test_valid_ordinary_24mb_stdout_without_review_marker_does_not_block(self) -> None:
        self._ordinary_long_output()
        outcome = self._reconcile_original()
        self.assertEqual(outcome["status"], "not_applicable")
        self.assertEqual(outcome["errors"], [])

    def test_ordinary_24mb_stdout_with_original_revision_reject_still_blocks(self) -> None:
        marker = (
            reviews.RESULT_PREFIX
            + json.dumps(result("not-a-review", "REJECT_THIS_REVISION", 1))
            + "\n"
        ).encode()
        self._ordinary_long_output(marker=marker)
        outcome = self._reconcile_original()
        self.assertEqual(outcome["status"], "blocked")
        self.assertTrue(any(
            "decision_review_unbound_result" in value for value in outcome["errors"]
        ))


if __name__ == "__main__":
    unittest.main()
