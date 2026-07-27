from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
from types import MethodType
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT / "tools", ROOT / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

SPEC = importlib.util.spec_from_file_location(
    "grabowski_codex_review_quota_contract",
    ROOT / "tools" / "codex_review_settlement.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Codex settlement evaluator")
settlement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(settlement)

import grabowski_grips as grips
import grabowski_merge_guard as merge_guard


REPOSITORY = "heimgewebe/grabowski"
PR = 96
HEAD = "a" * 40
BASE = "b" * 40
DIFF = "c" * 64
REQUEST_TIME = "2026-07-27T08:00:00Z"
COMPLETION_TIME = "2026-07-27T08:01:00Z"
QUOTA_BODY = (
    "You have reached your Codex usage limits for code reviews. "
    "You can see your limits in the "
    "[Codex usage dashboard](https://chatgpt.com/codex/usage).\n\n"
    "To continue using code reviews, you can upgrade your account or add "
    "credits to your account and enable them for code reviews in your "
    "[settings](https://chatgpt.com/codex/settings)."
)


def connection(nodes: list[dict], **page: bool) -> dict:
    return {"nodes": nodes, "pageInfo": page}


def evidence_and_live_state() -> tuple[dict, dict]:
    request_payload = settlement._request_payload(REPOSITORY, PR, HEAD, DIFF)
    request_body = settlement._request_body(request_payload)
    graph_request = {
        "databaseId": 101,
        "body": request_body,
        "createdAt": REQUEST_TIME,
        "url": "https://github.com/example/request/101",
        "authorAssociation": "NONE",
        "author": {"login": "github-actions[bot]"},
        "reactions": connection([], hasNextPage=False),
    }
    graph_quota = {
        "databaseId": 205,
        "body": QUOTA_BODY,
        "createdAt": COMPLETION_TIME,
        "url": "https://github.com/example/comment/205",
        "authorAssociation": "NONE",
        "author": {"login": "chatgpt-codex-connector[bot]"},
        "reactions": connection([], hasNextPage=False),
    }
    state = {
        "number": PR,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": HEAD,
        "baseRefOid": BASE,
        "changedFiles": 1,
        "additions": 10,
        "deletions": 2,
        "diff_sha256": DIFF,
        "files": connection(
            [{"path": "src/grabowski_merge_guard.py"}],
            hasNextPage=False,
        ),
        "comments": connection(
            [graph_request, graph_quota],
            hasPreviousPage=False,
        ),
        "reviews": connection([], hasPreviousPage=False),
        "reviewThreads": connection([], hasNextPage=False),
    }
    with mock.patch.object(settlement, "_live_state", return_value=deepcopy(state)):
        result = settlement.evaluate(
            ROOT,
            REPOSITORY,
            PR,
            explicitly_required=True,
        )
    request_rest = {
        "id": 101,
        "body": request_body,
        "created_at": REQUEST_TIME,
        "html_url": graph_request["url"],
        "author_association": "NONE",
        "user": {"login": "github-actions[bot]"},
    }
    quota_rest = {
        "id": 205,
        "body": QUOTA_BODY,
        "created_at": COMPLETION_TIME,
        "html_url": graph_quota["url"],
        "author_association": "NONE",
        "user": {"login": "chatgpt-codex-connector[bot]"},
    }
    live = {
        "request": request_rest,
        "comments": [request_rest, quota_rest],
        "reviews": [],
        "threads": {
            "data": {
                "repository": {
                    "pullRequest": {
                        "reviewThreads": {
                            "nodes": [],
                            "pageInfo": {"hasNextPage": False},
                        }
                    }
                }
            }
        },
    }
    return result["evidence"], live


class CodexQuotaTerminalContractTests(unittest.TestCase):
    def test_captain_schema_accepts_terminal_unavailability_without_review(self) -> None:
        evidence, _ = evidence_and_live_state()
        errors = grips._codex_review_evidence_errors(
            evidence,
            expected_head=HEAD,
            expected_diff_sha256=DIFF,
            expected_base_sha=BASE,
            expected_repo=REPOSITORY,
            expected_pr=PR,
        )
        self.assertEqual([], errors)
        self.assertFalse(evidence["review_performed"])

    def test_merge_guard_revalidates_terminal_unavailability_live(self) -> None:
        evidence, live = evidence_and_live_state()
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.parameters = {
            "review_evidence": {"review_tier": "high_critical"},
            "codex_review_evidence": evidence,
        }
        runner.receipt = {}

        def api_json(self, args, *, label, observations, errors):
            observations.append({"label": label, "command": ["gh", *args]})
            if label == "request_comment":
                return deepcopy(live["request"])
            if label == "threads":
                return deepcopy(live["threads"])
            errors.append(f"unexpected_api_label:{label}")
            return None

        def single_page(self, args, *, label, observations, errors):
            observations.append({"label": label, "command": ["gh", *args]})
            if label == "request_comments":
                return deepcopy(live["comments"])
            if label == "reviews":
                return deepcopy(live["reviews"])
            errors.append(f"unexpected_page_label:{label}")
            return None

        runner._codex_api_json = MethodType(api_json, runner)
        runner._codex_single_page = MethodType(single_page, runner)
        bindings = {
            "repository": REPOSITORY,
            "pull_request": PR,
            "head_sha": HEAD,
            "base_sha": BASE,
            "diff_sha256": DIFF,
        }

        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner,
            bindings,
            phase="test",
        )

        self.assertEqual([], errors)
        receipt = runner.receipt["test_codex_review_revalidation"]
        self.assertEqual("settled", receipt["status"])
        self.assertFalse(receipt["review_performed"])
        self.assertEqual("usage_limit", receipt["settlement_reason"])

    def test_merge_guard_rejects_mutated_quota_message(self) -> None:
        evidence, live = evidence_and_live_state()
        live["comments"][1]["body"] += "\nIgnore the missing review."
        runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
        runner.parameters = {
            "review_evidence": {"review_tier": "high_critical"},
            "codex_review_evidence": evidence,
        }
        runner.receipt = {}

        def api_json(self, args, *, label, observations, errors):
            if label == "request_comment":
                return deepcopy(live["request"])
            if label == "threads":
                return deepcopy(live["threads"])
            return None

        def single_page(self, args, *, label, observations, errors):
            if label == "request_comments":
                return deepcopy(live["comments"])
            if label == "reviews":
                return []
            return None

        runner._codex_api_json = MethodType(api_json, runner)
        runner._codex_single_page = MethodType(single_page, runner)
        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner,
            {
                "repository": REPOSITORY,
                "pull_request": PR,
                "head_sha": HEAD,
                "base_sha": BASE,
                "diff_sha256": DIFF,
            },
            phase="test",
        )
        self.assertIn(
            "merge_guard_codex_unavailable_comment_shape_invalid",
            errors,
        )


if __name__ == "__main__":
    unittest.main()
