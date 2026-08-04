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
    "[Codex usage dashboard](https://chatgpt.com/codex/cloud/settings/usage).\n\n"
    "To continue using code reviews, you can upgrade your account or add "
    "credits to your account and enable them for code reviews in your "
    "[settings](https://chatgpt.com/codex/cloud/settings/code-review)."
)


def connection(nodes: list[dict], **page: bool) -> dict:
    return {"nodes": nodes, "pageInfo": page}


def request_payloads() -> tuple[dict, dict, dict]:
    payload = settlement._request_payload(REPOSITORY, PR, HEAD, DIFF)
    body = settlement._request_body(payload)
    graph = {
        "databaseId": 101,
        "body": body,
        "createdAt": REQUEST_TIME,
        "updatedAt": REQUEST_TIME,
        "url": "https://github.com/example/request/101",
        "authorAssociation": "OWNER",
        "author": {"login": "alexdermohr"},
        "reactions": connection([], hasNextPage=False),
    }
    rest = {
        "id": 101,
        "body": body,
        "created_at": REQUEST_TIME,
        "html_url": graph["url"],
        "author_association": "OWNER",
        "user": {"login": "alexdermohr"},
    }
    return payload, graph, rest


def quota_payloads() -> tuple[dict, dict]:
    graph = {
        "databaseId": 205,
        "body": QUOTA_BODY,
        "createdAt": COMPLETION_TIME,
        "url": "https://github.com/example/comment/205",
        "authorAssociation": "NONE",
        "author": {"login": "chatgpt-codex-connector[bot]"},
        "reactions": connection([], hasNextPage=False),
    }
    rest = {
        "id": 205,
        "body": QUOTA_BODY,
        "created_at": COMPLETION_TIME,
        "html_url": graph["url"],
        "author_association": "NONE",
        "user": {"login": "chatgpt-codex-connector[bot]"},
    }
    return graph, rest


def state(*, reviews: list[dict] | None = None) -> dict:
    _, graph_request, _ = request_payloads()
    graph_quota, _ = quota_payloads()
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
        "files": connection(
            [{"path": "src/grabowski_merge_guard.py"}],
            hasNextPage=False,
        ),
        "comments": connection(
            [graph_request, graph_quota],
            hasPreviousPage=False,
        ),
        "reviews": connection(reviews or [], hasPreviousPage=False),
        "reviewThreads": connection([], hasNextPage=False),
    }


def evaluate(value: dict) -> dict:
    with mock.patch.object(settlement, "_live_state", return_value=deepcopy(value)):
        return settlement.evaluate(
            ROOT,
            REPOSITORY,
            PR,
            explicitly_required=True,
        )


def valid_review_evidence_and_live() -> tuple[dict, dict]:
    review_graph = {
        "databaseId": 301,
        "state": "COMMENTED",
        "body": "reviewed",
        "submittedAt": COMPLETION_TIME,
        "url": "https://github.com/example/review/301",
        "author": {"login": "chatgpt-codex-connector[bot]"},
        "commit": {"oid": HEAD},
    }
    result = evaluate(state(reviews=[review_graph]))
    self_check = result["status"] == "pass" and result["settled"] is True
    if not self_check:
        raise RuntimeError("review fixture did not settle")
    _, _, request_rest = request_payloads()
    _, quota_rest = quota_payloads()
    review_rest = {
        "id": 301,
        "state": "COMMENTED",
        "body": "reviewed",
        "submitted_at": COMPLETION_TIME,
        "commit_id": HEAD,
        "user": {"login": "chatgpt-codex-connector[bot]"},
    }
    live = {
        "request": request_rest,
        "comments": [request_rest, quota_rest],
        "reviews": [review_rest],
        "review": review_rest,
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


def fabricated_unavailable_evidence() -> dict:
    evidence, _ = valid_review_evidence_and_live()
    payload, _, _ = request_payloads()
    evidence = deepcopy(evidence)
    evidence["completion"] = {
        "mode": "unavailable_comment",
        "review_id": None,
        "comment_id": 205,
        "actor": "chatgpt-codex-connector[bot]",
        "state": "UNAVAILABLE",
        "reason": "usage_limit",
        "submitted_at": COMPLETION_TIME,
        "body_sha256": settlement._sha256_text(QUOTA_BODY),
        "url": "https://github.com/example/comment/205",
        "accepted_state": True,
        "blocking_state": False,
        "review_performed": False,
        "request_id": payload["request_id"],
        "request_binding": "sole_canonical_request_identity",
    }
    evidence["review_performed"] = False
    evidence["settled"] = True
    evidence["status"] = "pass"
    evidence["errors"] = []
    core = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    evidence["evidence_sha256"] = grips.sha256_json(core)
    return evidence


def runner_for(evidence: dict, live: dict) -> merge_guard.CaptainMergeGuardRunner:
    runner = object.__new__(merge_guard.CaptainMergeGuardRunner)
    runner.parameters = {
        "review_evidence": {
            "review_tier": "high_critical",
            "external_review_required": True,
        },
        "codex_review_evidence": evidence,
    }
    runner.receipt = {}

    def api_json(self, args, *, label, observations, errors):
        observations.append({"label": label, "command": ["gh", *args]})
        if label == "request_comment":
            return deepcopy(live["request"])
        if label == "review":
            return deepcopy(live["review"])
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
    return runner


def bindings() -> dict:
    return {
        "repository": REPOSITORY,
        "pull_request": PR,
        "head_sha": HEAD,
        "base_sha": BASE,
        "diff_sha256": DIFF,
    }


class CodexQuotaTerminalContractTests(unittest.TestCase):
    def test_unbound_usage_limit_remains_pending(self) -> None:
        result = evaluate(state())
        self.assertEqual("pending", result["status"])
        self.assertEqual("required_provider_unavailable", result["status_code"])
        self.assertFalse(result["settled"])
        self.assertFalse(result["completion_present"])
        self.assertFalse(result["review_performed"])
        self.assertTrue(result["provider_outcome_present"])

    def test_captain_schema_rejects_unbound_terminalization(self) -> None:
        evidence = fabricated_unavailable_evidence()
        errors = grips._codex_review_evidence_errors(
            evidence,
            expected_head=HEAD,
            expected_diff_sha256=DIFF,
            expected_base_sha=BASE,
            expected_repo=REPOSITORY,
            expected_pr=PR,
        )
        self.assertIn(
            "completion.mode must be review, reaction or clean_comment",
            errors,
        )

    def test_merge_guard_rejects_unbound_terminalization(self) -> None:
        evidence = fabricated_unavailable_evidence()
        _, live = valid_review_evidence_and_live()
        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner_for(evidence, live),
            bindings(),
            phase="test",
        )
        self.assertIn("merge_guard_codex_unavailable_comment_unbound", errors)

    def test_merge_guard_rejects_non_boolean_explicit_requirement(self) -> None:
        evidence, live = valid_review_evidence_and_live()
        runner = runner_for(evidence, live)
        runner.parameters["codex_review_required"] = "yes"

        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner,
            bindings(),
            phase="test",
        )

        self.assertEqual(["merge_guard_codex_required_invalid"], errors)
        receipt = runner.receipt["test_codex_review_revalidation"]
        self.assertEqual("blocked", receipt["status"])
        self.assertEqual([], receipt["observations"])

    def test_merge_guard_revalidates_performed_review(self) -> None:
        evidence, live = valid_review_evidence_and_live()
        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner_for(evidence, live),
            bindings(),
            phase="test",
        )
        self.assertEqual([], errors)

    def test_merge_guard_honors_pre_request_approval_ordering(self) -> None:
        evidence, live = valid_review_evidence_and_live()
        live["reviews"][0:0] = [
            {
                "id": 299,
                "state": "CHANGES_REQUESTED",
                "body": "blocking",
                "submitted_at": "2026-07-27T07:58:00Z",
                "commit_id": HEAD,
                "user": {"login": "chatgpt-codex-connector[bot]"},
            },
            {
                "id": 300,
                "state": "APPROVED",
                "body": "cleared",
                "submitted_at": "2026-07-27T07:59:00Z",
                "commit_id": HEAD,
                "user": {"login": "chatgpt-codex-connector[bot]"},
            },
        ]
        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner_for(evidence, live),
            bindings(),
            phase="test",
        )
        self.assertEqual([], errors)

    def test_merge_guard_keeps_pre_request_blocking_review(self) -> None:
        evidence, live = valid_review_evidence_and_live()
        live["reviews"].insert(
            0,
            {
                "id": 300,
                "state": "CHANGES_REQUESTED",
                "body": "blocking",
                "submitted_at": "2026-07-27T07:59:00Z",
                "commit_id": HEAD,
                "user": {"login": "chatgpt-codex-connector[bot]"},
            },
        )
        errors = merge_guard.CaptainMergeGuardRunner._revalidate_codex_review(
            runner_for(evidence, live),
            bindings(),
            phase="test",
        )
        self.assertIn("merge_guard_codex_outstanding_blocking_review", errors)


if __name__ == "__main__":
    unittest.main()
