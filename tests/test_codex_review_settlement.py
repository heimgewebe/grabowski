from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "grabowski_codex_review_settlement_test",
    TOOLS / "codex_review_settlement.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load codex review settlement module")
settlement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(settlement)


HEAD = "a" * 40
BASE = "b" * 40
DIFF = "c" * 64
REPOSITORY = "heimgewebe/grabowski"
PR = 91
REQUEST_TIME = "2026-07-26T08:00:00Z"
REVIEW_TIME = "2026-07-26T08:01:00Z"


def connection(nodes: list[dict], **page: bool) -> dict:
    return {"nodes": nodes, "pageInfo": page}


def base_state(*, path: str = "src/grabowski_grips.py") -> dict:
    return {
        "number": PR,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": HEAD,
        "baseRefOid": BASE,
        "changedFiles": 1,
        "additions": 10,
        "deletions": 2,
        "diff_sha256": DIFF,
        "files": connection([{"path": path}], hasNextPage=False),
        "comments": connection([], hasPreviousPage=False),
        "reviews": connection([], hasPreviousPage=False),
        "reviewThreads": connection([], hasNextPage=False),
    }


def request_comment(
    *,
    actor: str = "alex",
    association: str = "OWNER",
    comment_id: int = 1001,
    created_at: str = REQUEST_TIME,
) -> dict:
    payload = settlement._request_payload(REPOSITORY, PR, HEAD, DIFF)
    return {
        "databaseId": comment_id,
        "body": settlement._request_body(payload),
        "createdAt": created_at,
        "authorAssociation": association,
        "author": {"login": actor},
        "reactions": connection([], hasNextPage=False),
    }


def codex_review(
    *,
    head: str = HEAD,
    state: str = "COMMENTED",
    review_id: int = 2001,
    submitted_at: str = REVIEW_TIME,
) -> dict:
    return {
        "databaseId": review_id,
        "state": state,
        "body": "reviewed",
        "submittedAt": submitted_at,
        "url": "https://github.com/example/review/2001",
        "author": {"login": "chatgpt-codex-connector[bot]"},
        "commit": {"oid": head},
    }


def codex_thread(*, resolved: bool, created_at: str = REVIEW_TIME) -> dict:
    return {
        "id": "PRRT_kwDOexample",
        "isResolved": resolved,
        "comments": connection(
            [
                {
                    "databaseId": 3001,
                    "createdAt": created_at,
                    "author": {"login": "chatgpt-codex-connector[bot]"},
                    "commit": {"oid": HEAD},
                    "pullRequestReview": {"databaseId": 2001},
                }
            ],
            hasNextPage=False,
        ),
    }


class CodexReviewSettlementTests(unittest.TestCase):
    def evaluate(self, state: dict, *, required: bool = False) -> dict:
        with mock.patch.object(settlement, "_live_state", return_value=deepcopy(state)):
            return settlement.evaluate(
                ROOT,
                REPOSITORY,
                PR,
                explicitly_required=required,
            )

    def test_high_critical_change_without_request_is_pending(self) -> None:
        result = self.evaluate(base_state())
        self.assertTrue(result["required"])
        self.assertEqual(result["status"], "pending")
        self.assertFalse(result["settled"])

    def test_documentation_change_without_request_passes_as_not_required(self) -> None:
        result = self.evaluate(base_state(path="docs/example.md"))
        self.assertFalse(result["required"])
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["settled"])

    def test_current_head_review_after_bound_request_settles(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection([codex_review()], hasPreviousPage=False)
        result = self.evaluate(state)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["settled"])
        self.assertEqual(result["evidence"]["completion"]["mode"], "review")

    def test_duplicate_request_uses_earliest_and_keeps_intermediate_thread(self) -> None:
        state = base_state()
        state["comments"] = connection(
            [
                request_comment(comment_id=1001, created_at="2026-07-26T08:00:00Z"),
                request_comment(comment_id=1002, created_at="2026-07-26T08:02:00Z"),
            ],
            hasPreviousPage=False,
        )
        state["reviews"] = connection(
            [codex_review(review_id=2002, submitted_at="2026-07-26T08:03:00Z")],
            hasPreviousPage=False,
        )
        state["reviewThreads"] = connection(
            [codex_thread(resolved=False, created_at="2026-07-26T08:01:00Z")],
            hasNextPage=False,
        )

        result = self.evaluate(state)

        self.assertEqual("block", result["status"])
        self.assertEqual(1001, result["evidence"]["request"]["comment_id"])
        self.assertEqual(1, result["unresolved_thread_count"])

    def test_commented_review_does_not_override_changes_requested(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection(
            [
                codex_review(
                    state="CHANGES_REQUESTED",
                    review_id=2001,
                    submitted_at="2026-07-26T08:01:00Z",
                ),
                codex_review(
                    state="COMMENTED",
                    review_id=2002,
                    submitted_at="2026-07-26T08:02:00Z",
                ),
            ],
            hasPreviousPage=False,
        )

        result = self.evaluate(state)

        self.assertEqual("block", result["status"])
        self.assertEqual("CHANGES_REQUESTED", result["evidence"]["completion"]["state"])
        self.assertTrue(result["evidence"]["completion"]["blocking_state"])

    def test_approval_after_blocker_supersedes_changes_requested(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection(
            [
                codex_review(
                    state="CHANGES_REQUESTED",
                    review_id=2001,
                    submitted_at="2026-07-26T08:01:00Z",
                ),
                codex_review(
                    state="APPROVED",
                    review_id=2002,
                    submitted_at="2026-07-26T08:02:00Z",
                ),
            ],
            hasPreviousPage=False,
        )

        result = self.evaluate(state)

        self.assertEqual("pass", result["status"])
        self.assertTrue(result["settled"])
        self.assertEqual("APPROVED", result["evidence"]["completion"]["state"])

    def test_stale_review_commit_does_not_settle_current_head(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection(
            [codex_review(head="d" * 40)],
            hasPreviousPage=False,
        )
        result = self.evaluate(state)
        self.assertEqual(result["status"], "pending")
        self.assertFalse(result["settled"])

    def test_unresolved_current_head_codex_thread_blocks(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection([codex_review()], hasPreviousPage=False)
        state["reviewThreads"] = connection(
            [codex_thread(resolved=False)],
            hasNextPage=False,
        )
        result = self.evaluate(state)
        self.assertEqual(result["status"], "block")
        self.assertFalse(result["settled"])
        self.assertEqual(result["unresolved_thread_count"], 1)

    def test_resolved_current_head_codex_thread_is_terminal(self) -> None:
        state = base_state()
        state["comments"] = connection([request_comment()], hasPreviousPage=False)
        state["reviews"] = connection([codex_review()], hasPreviousPage=False)
        state["reviewThreads"] = connection(
            [codex_thread(resolved=True)],
            hasNextPage=False,
        )
        result = self.evaluate(state)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["settled"])
        self.assertEqual(result["finding_count"], 1)
        self.assertTrue(result["evidence"]["all_findings_triaged"])

    def test_trusted_thumbsup_reaction_settles_clean_review(self) -> None:
        state = base_state()
        request = request_comment()
        request["reactions"] = connection(
            [
                {
                    "content": "THUMBS_UP",
                    "createdAt": REVIEW_TIME,
                    "user": {"login": "chatgpt-codex-connector[bot]"},
                }
            ],
            hasNextPage=False,
        )
        state["comments"] = connection([request], hasPreviousPage=False)
        result = self.evaluate(state)
        self.assertEqual(result["status"], "pass")
        self.assertTrue(result["settled"])
        self.assertEqual(result["evidence"]["completion"]["mode"], "reaction")

    def test_untrusted_request_marker_is_ignored(self) -> None:
        state = base_state()
        state["comments"] = connection(
            [request_comment(actor="outsider", association="NONE")],
            hasPreviousPage=False,
        )
        state["reviews"] = connection([codex_review()], hasPreviousPage=False)
        result = self.evaluate(state)
        self.assertEqual(result["status"], "pending")
        self.assertFalse(result["request_present"])

    def test_truncated_review_threads_fail_closed(self) -> None:
        state = base_state()
        state["reviewThreads"]["pageInfo"]["hasNextPage"] = True
        result = self.evaluate(state)
        self.assertEqual(result["status"], "block")
        self.assertIn("reviewThreads exceeds", result["errors"][0])

    def test_request_is_idempotent_for_current_head_and_diff(self) -> None:
        state = base_state()
        state["comments"] = connection(
            [
                request_comment(comment_id=1001, created_at="2026-07-26T08:00:00Z"),
                request_comment(comment_id=1002, created_at="2026-07-26T08:02:00Z"),
            ],
            hasPreviousPage=False,
        )
        with mock.patch.object(settlement, "_live_state", return_value=state), mock.patch.object(
            settlement, "_run_json"
        ) as run_json:
            result = settlement.ensure_request(ROOT, REPOSITORY, PR)
        self.assertFalse(result["requested"])
        self.assertEqual(result["comment_id"], 1001)
        run_json.assert_not_called()

    def test_request_posts_exact_bound_marker(self) -> None:
        state = base_state()
        with mock.patch.object(settlement, "_live_state", return_value=state), mock.patch.object(
            settlement,
            "_run_json",
            return_value={"id": 4001},
        ) as run_json:
            result = settlement.ensure_request(ROOT, REPOSITORY, PR)
        self.assertTrue(result["requested"])
        args = run_json.call_args.args[1]
        body_arg = next(item for item in args if item.startswith("body="))
        self.assertIn("@codex review", body_arg)
        self.assertIn(HEAD, body_arg)
        self.assertIn(DIFF, body_arg)


if __name__ == "__main__":
    unittest.main()
