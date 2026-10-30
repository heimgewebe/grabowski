"""Signed historical repository-case and cross-PR review invariants.

Exercise actual SSH-signed sessions and the same verifier used by Captain.
These are negative controls, not mock assertions of an expected PASS.
"""
from __future__ import annotations

import unittest

import tests.test_self_review_first_party as fixtures


class SignedHistoryCaseAliasBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reuse the existing real-Git, SSH-signature and authenticated
        # controller-issuer fixture without importing its TestCase into this
        # module's test discovery namespace.
        self.fixture = fixtures.FirstPartySemanticReviewTests(
            methodName="test_prior_signed_material_reject_remains_blocking_across_batches"
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def _legacy_check(self, binding: dict) -> None:
        f = self.fixture
        fixtures.review._assert_no_first_party_reject_for_legacy_review(
            binding, repository=f.repo, root=f.state,
            signers=f.signers, root_owned_signers=False,
        )

    def test_signed_reject_remains_after_unrelated_pr_seals(self) -> None:
        f = self.fixture
        review = fixtures.review
        plan = f._first_party_plan()
        started = f._start_plan(plan)
        f._submit_axis(started, review.REQUIRED_AXES[0], 1, reject=True)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._legacy_check(plan["binding"])

        # A new PR for the same identical Git diff has its own authority.
        another = fixtures.producer.plan_first_party_review(
            repo=f.repo, pr=1650, base_sha=f.base, head_sha=f.head,
            diff_sha256=plan["binding"]["diff_sha256"],
        )
        later = f._start_plan(another)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            f._submit_axis(later, axis, number)
        audit, receipts = f._seal_direct(another)
        self.assertEqual([], f._receipt_errors(audit, receipts))

        # This is the crucial *post-sibling* check: sealing PR1650 must
        # not retire the old authenticated material finding for PR1649.
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._legacy_check(plan["binding"])
        same_pr = f._first_party_plan()
        retry = f._start_plan(same_pr)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            f._submit_axis(retry, axis, number)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            f._seal_direct(same_pr)

    def test_legacy_verifies_original_signed_repo_spelling_not_caller_alias(self) -> None:
        f = self.fixture
        review = fixtures.review
        original = f.repo
        signed_repo = f.root / "Grabowski"
        original.rename(signed_repo)
        f.repo = signed_repo
        f._git("remote", "set-url", "origin", "git@github.com:heimgewebe/Grabowski.git")

        historical = f._first_party_plan()
        self.assertEqual("heimgewebe/Grabowski", historical["binding"]["repo"])
        signed = f._start_plan(historical)
        f._submit_axis(signed, review.REQUIRED_AXES[0], 1, reject=True)
        saved = review._read_signed_record(
            f.state / "sessions" / signed["review_session_id"] / "session.json",
            signers=f.signers, root_owned_signers=False,
        )
        self.assertEqual("heimgewebe/Grabowski", saved["binding"]["repo"])
        # The caller's lowercase GitHub alias intentionally disagrees with
        # the signed original Git remote. If _current_source uses the caller
        # spelling this would produce 'review source repository origin invalid'
        # rather than authenticated 'previous signed material'.
        alias = {**historical["binding"], "repo": "heimgewebe/grabowski"}
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._legacy_check(alias)

        # Only a genuinely later signed resolution of this *same* PR is valid.
        f.now += 1
        resolved = f._start_plan(f._first_party_plan())
        f._submit_axis(
            resolved, review.REQUIRED_AXES[0], 1,
            resolve_ids=("material-1",),
        )
        self._legacy_check(alias)

    def test_unicode_aliases_fail_at_captain_entry_before_signed_lookup(self) -> None:
        import grabowski_merge_guard as captain
        from unittest import mock

        f = self.fixture
        plan = f._first_party_plan()
        # Never rely on the developer's production review registry. The guard
        # intentionally returns [] if no signed session registry exists.
        # Create a real, SSH-signed fixture REJECT and explicitly bind it.
        started = f._start_plan(plan)
        f._submit_axis(started, fixtures.review.REQUIRED_AXES[0], 1, reject=True)
        self.assertTrue((f.state / "sessions" / started["review_session_id"] / "session.json").is_file())
        binding = {
            "repository": "heimgewebe/grabowski", "pull_request": 1649,
            "base_sha": f.base, "head_sha": f.head,
            "diff_sha256": plan["binding"]["diff_sha256"],
        }
        with mock.patch.object(fixtures.review, "FIRST_PARTY_REVIEW_ROOT", f.state):
            for alias in (
                "heimgewebe/Grabow\u017fki",  # Unicode long-s casefolds to ASCII 's'
                "Heimgewebe/Grabow\u017fki",
                "heimgewebe/grabo\u00dfki",  # sharp-s casefold expands to 'ss'
                "heimgewebe/grabo\ufb01ki",  # Unicode fi ligature
            ):
                self.assertEqual(
                    ["merge_guard_signed_first_party_history_binding_invalid"],
                    captain._signed_first_party_material_history_errors({
                        **binding, "repository": alias,
                    }),
                    f"non-ASCII repository alias must fail closed: {alias!r}",
                )
            self.assertEqual(
                ["merge_guard_signed_first_party_material_reject_or_invalid_history"],
                captain._signed_first_party_material_history_errors(binding),
                "The same signed fixture must still block its canonical repository",
            )


if __name__ == "__main__":
    unittest.main()
