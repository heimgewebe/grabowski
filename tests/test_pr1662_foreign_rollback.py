"""Regression for the PR #1662 historical rollback / foreign recovery deadlock.

A cleanly rolled-back, authentically receipt-bound deployment A must stay
terminal when a *different* later deployment B has a valid post-switch
outcome_unknown. B must remain unresolved and recoverable, not be hidden.
"""
import unittest

import test_midcutover_resume as fixture
from test_pr1662_successor_terminal import PublicationRollbackTerminalProofTests
import test_self_deploy as source

SD = source.SELF_DEPLOY


class HistoricalRollbackForeignRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing producer-shaped, SHA-bound clean-blue rollback.
        case = PublicationRollbackTerminalProofTests(
            "test_actual_effect_free_and_verified_rollback_are_terminal"
        )
        case.setUp()
        self.a = case.original

    def test_clean_rollback_remains_terminal_with_later_foreign_unknown(self):
        b = fixture.cutover_receipt(
            cutover_id="bgc-later-unrelated-outcome-unknown",
            outcome="outcome_unknown",
            phase="outcome_unknown",
        )
        receipts = [self.a, b]
        self.assertTrue(SD._signed_clean_blue_rollback_is_terminal(self.a, [self.a]))
        self.assertEqual(
            [b["cutover_id"]],
            [r["cutover_id"] for r in SD.midcutover.unresolved_post_switch_receipts(receipts)],
            "later B must remain unresolved, visible and blocking for ordinary deploy",
        )
        self.assertTrue(
            SD._signed_clean_blue_rollback_is_terminal(self.a, receipts),
            "historical fully rolled-back A must not be resurrected by B",
        )
        self.assertFalse(
            SD._signed_clean_blue_rollback_is_terminal(b, receipts),
            "B's unresolved result must not inherit A's terminality",
        )

    def test_same_cutover_unresolved_conflict_is_not_historical_settlement(self):
        conflicting = fixture.cutover_receipt(
            cutover_id=self.a["cutover_id"],
            outcome="outcome_unknown",
            phase="outcome_unknown",
        )
        self.assertTrue(SD.midcutover.unresolved_post_switch_receipts([self.a, conflicting]))
        self.assertFalse(
            SD._signed_clean_blue_rollback_is_terminal(self.a, [self.a, conflicting]),
            "unresolved proof for A's *own* cutover is not a foreign B",
        )


if __name__ == "__main__":
    unittest.main()
