from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest
from unittest import mock

import test_codex_review_settlement as settlement_fixtures
import test_grips as captain_fixtures


RECEIPT_HEADER = "<!-- codex-review-receipt:v1 -->\n\n"


def invalid_bodies(body: str) -> list[str]:
    return [
        "<!-- codex-review-receipt:v2 -->\n\n" + body,
        "<!-- unrelated -->\n\n" + body,
        RECEIPT_HEADER * 2 + body,
        "\n" + RECEIPT_HEADER + body,
        "Untrusted preface\n" + RECEIPT_HEADER + body,
        RECEIPT_HEADER + "Blocking issue: do not merge.\n" + body,
        RECEIPT_HEADER + body + "\nBlocking issue: do not merge.",
    ]


class CodexReceiptHeaderSettlementTests(unittest.TestCase):
    def evaluate_comment(self, comment: dict) -> dict:
        fixture = settlement_fixtures
        state = fixture.base_state()
        state["comments"] = fixture.connection(
            [fixture.request_comment(), comment], hasPreviousPage=False,
        )
        with mock.patch.object(
            fixture.settlement, "_live_state", return_value=deepcopy(state),
        ):
            return fixture.settlement.evaluate(
                fixture.ROOT, fixture.REPOSITORY, fixture.PR,
                explicitly_required=True,
            )

    def test_v1_header_and_legacy_clean_receipts_settle_exact_head(self) -> None:
        fixture = settlement_fixtures
        for header in ("", RECEIPT_HEADER):
            with self.subTest(header=header):
                comment = fixture.codex_clean_comment(closing=":rocket:")
                comment["body"] = header + comment["body"]
                result = self.evaluate_comment(comment)
                self.assertEqual("pass", result["status"])
                self.assertTrue(result["settled"])
                completion = result["evidence"]["completion"]
                self.assertEqual("clean_comment", completion["mode"])
                self.assertEqual(fixture.HEAD[:10], completion["reviewed_commit_prefix"])
                self.assertEqual(
                    hashlib.sha256(comment["body"].encode()).hexdigest(),
                    completion["body_sha256"],
                )

    def test_header_does_not_accept_unknown_duplicate_or_injected_content(self) -> None:
        template = settlement_fixtures.codex_clean_comment(closing=":rocket:")
        for body in invalid_bodies(template["body"]):
            with self.subTest(body=body[:100]):
                result = self.evaluate_comment({**template, "body": body})
                self.assertFalse(result["settled"])
                self.assertIsNone(result["evidence"]["completion"])

    def test_header_preserves_actor_head_and_request_time_authority(self) -> None:
        fixture = settlement_fixtures
        for comment in (
            fixture.codex_clean_comment(actor="untrusted-bot", closing=":rocket:"),
            fixture.codex_clean_comment(head="d" * 40, closing=":rocket:"),
            fixture.codex_clean_comment(
                created_at="2026-07-26T07:59:59Z", closing=":rocket:",
            ),
        ):
            comment["body"] = RECEIPT_HEADER + comment["body"]
            with self.subTest(comment=comment):
                result = self.evaluate_comment(comment)
                self.assertFalse(result["settled"])
                self.assertIsNone(result["evidence"]["completion"])


class CodexReceiptHeaderCaptainTests(unittest.TestCase):
    def run_guard(self, comment: dict, *, evidence_body: str | None = None):
        fixture = captain_fixtures.CaptainAuthorityPathTests(
            "test_atomic_merge_guard_accepts_bound_clean_comment",
        )
        fixture.setUp()
        try:
            source = captain_fixtures
            parameters = source.authorized_captain_run_parameters()
            parameters["codex_review_evidence"] = source.captain_codex_clean_comment_evidence(
                body=comment["body"] if evidence_body is None else evidence_body,
            )
            parameters["execution_intent"] = source.captain_execution_intent(parameters)
            view = {
                "number": 96,
                "state": "OPEN",
                "baseRefName": "main",
                "baseRefOid": source.CAPTAIN_BASE_SHA,
                "headRefName": "feat/captain",
                "headRefOid": source.CAPTAIN_HEAD,
                "isDraft": False,
                "mergeable": "MERGEABLE",
                "mergeStateStatus": "CLEAN",
            }
            template = source.captain_codex_live_state(view, review_pages=[[]])
            state = source.captain_codex_live_state(
                view,
                request_pages=[[deepcopy(template["request_comment"]), comment]],
                review_pages=[[]],
            )
            github = source.FakeGh(
                view=view, diff_text=source.CAPTAIN_DIFF_TEXT, codex_state=state,
            )
            result = source.grips.grip_run(
                "captain-run", parameters, profile="captain", allow_mutation=True,
                command_runner=source.FakeGit(), github_runner=github,
            )
            return result["output"]["executions"][0], github
        finally:
            fixture.tearDown()

    def assert_blocked_without_dispatch(self, comment: dict, **kwargs) -> None:
        execution, github = self.run_guard(comment, **kwargs)
        self.assertFalse(execution["verification_passed"])
        self.assertEqual([], [
            call for call in github.calls if call[:2] == ("pr", "merge")
        ])

    def test_atomic_guard_accepts_v1_header_and_legacy_with_bound_body_hash(self) -> None:
        for header in ("", RECEIPT_HEADER):
            with self.subTest(header=header):
                comment = captain_fixtures.captain_codex_clean_comment(closing=":rocket:")
                comment["body"] = header + comment["body"]
                execution, _github = self.run_guard(comment)
                self.assertTrue(execution["verification_passed"])
                self.assertEqual(
                    "settled",
                    execution["merge_lease_guard"]["dispatch_codex_review_revalidation"]["status"],
                )

    def test_atomic_guard_denies_unknown_duplicate_or_injected_content(self) -> None:
        template = captain_fixtures.captain_codex_clean_comment(closing=":rocket:")
        for body in invalid_bodies(template["body"]):
            with self.subTest(body=body[:100]):
                self.assert_blocked_without_dispatch({**template, "body": body})

    def test_atomic_guard_preserves_actor_head_and_request_time_authority(self) -> None:
        template = captain_fixtures.captain_codex_clean_comment(closing=":rocket:")
        wrong_head = captain_fixtures.captain_codex_clean_comment(
            head="d" * 40, closing=":rocket:",
        )
        for comment in (
            {**template, "user": {"login": "untrusted-bot"}},
            wrong_head,
            {**template, "created_at": "2026-07-26T07:59:59Z"},
        ):
            comment["body"] = RECEIPT_HEADER + comment["body"]
            with self.subTest(comment=comment):
                self.assert_blocked_without_dispatch(comment)

    def test_atomic_guard_keeps_full_provider_body_hash_binding(self) -> None:
        comment = captain_fixtures.captain_codex_clean_comment(closing=":rocket:")
        old_body = comment["body"]
        comment["body"] = RECEIPT_HEADER + old_body
        self.assert_blocked_without_dispatch(comment, evidence_body=old_body)


if __name__ == "__main__":
    unittest.main()
