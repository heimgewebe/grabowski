from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pr_review_gate_ci as ci  # noqa: E402
import review_evidence_schemas as schemas  # noqa: E402


def _pr(*, base: str = "c") -> dict:
    return {
        "number": 42,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": "a" * 40,
        "baseRefOid": base * 40,
        "changedFiles": 1,
        "additions": 10,
        "deletions": 1,
        "files": [{"path": "src/example.py"}],
    }


def _comment_body() -> str:
    audit = {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "generated_at": "2026-07-21T00:00:00+00:00",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "base_sha": "c" * 40,
        "diff_sha256": "b" * 64,
        "review_policy_version": schemas.REVIEW_POLICY_VERSION,
        "review_tier": "standard",
        "minimum_review_iterations": 2,
        "actual_review_iterations": 2,
        "all_findings_triaged": True,
        "finding_count": 0,
        "material_findings_after_first_review": 0,
        "material_findings_remaining": 0,
        "uncertainty": 0.1,
        "residual_risk_accepted": False,
        "residual_risk_reason": "",
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "tuning_signal": "observe",
    }
    raw = (json.dumps(audit, sort_keys=True) + "\n").encode()
    status = ci.build_status_projection(raw)
    return f"{ci.COMMENT_PREFIX} {ci.encode_status_projection(status)}"


def _args() -> argparse.Namespace:
    return argparse.Namespace(
        repo_name="heimgewebe/grabowski",
        pr=42,
        actor="writer",
        comment_id=99,
        comment_body_env="REVIEW_GATE_COMMENT_BODY",
        publish_status=True,
    )


class ReviewEvidencePublicationRaceTests(unittest.TestCase):
    def _env(self, body: str = "ignored"):
        return mock.patch.dict(
            os.environ,
            {
                "GITHUB_ACTOR": "writer",
                "REVIEW_GATE_COMMENT_BODY": body,
            },
            clear=False,
        )

    def test_outside_window_publishes_failure_instead_of_preserving_green(self) -> None:
        with self._env(), mock.patch.object(
            ci, "collaborator_permission", return_value="write"
        ), mock.patch.object(ci, "load_live_pr", return_value=_pr()), mock.patch.object(
            ci,
            "current_comment_authorization_state",
            return_value=ci.COMMENT_STATE_OUTSIDE_WINDOW,
        ), mock.patch.object(ci, "publish_commit_status") as publish:
            rc = ci.evaluate_comment_command(_args())
        self.assertEqual(rc, 1)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=False,
            failure_count=1,
        )

    def test_superseded_command_is_safe_noop(self) -> None:
        with self._env(), mock.patch.object(
            ci, "collaborator_permission", return_value="write"
        ), mock.patch.object(ci, "load_live_pr", return_value=_pr()), mock.patch.object(
            ci,
            "current_comment_authorization_state",
            return_value=ci.COMMENT_STATE_SUPERSEDED,
        ), mock.patch.object(ci, "publish_commit_status") as publish:
            rc = ci.evaluate_comment_command(_args())
        self.assertEqual(rc, 0)
        publish.assert_not_called()

    def test_newer_authorized_command_before_publish_suppresses_old_write(self) -> None:
        with self._env(_comment_body()), mock.patch.object(
            ci, "collaborator_permission", return_value="write"
        ), mock.patch.object(ci, "load_live_pr", side_effect=[_pr(), _pr()]), mock.patch.object(
            ci, "current_diff_sha256", return_value="b" * 64
        ), mock.patch.object(
            ci,
            "current_comment_authorization_state",
            side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_SUPERSEDED],
        ), mock.patch.object(ci, "publish_commit_status") as publish:
            rc = ci.evaluate_comment_command(_args())
        self.assertEqual(rc, 0)
        publish.assert_not_called()

    def test_base_change_during_evaluation_publishes_failure(self) -> None:
        with self._env(_comment_body()), mock.patch.object(
            ci, "collaborator_permission", return_value="write"
        ), mock.patch.object(
            ci, "load_live_pr", side_effect=[_pr(base="c"), _pr(base="d")]
        ), mock.patch.object(ci, "current_diff_sha256", return_value="b" * 64), mock.patch.object(
            ci,
            "current_comment_authorization_state",
            side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_CURRENT],
        ), mock.patch.object(ci, "publish_commit_status") as publish:
            rc = ci.evaluate_comment_command(_args())
        self.assertEqual(rc, 1)
        publish.assert_called_once()
        self.assertFalse(publish.call_args.kwargs["passed"])
        self.assertEqual(publish.call_args.kwargs["head_sha"], "a" * 40)

    def test_permission_lookup_is_cached_within_comment_window_read(self) -> None:
        payload = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "comments": {
                            "nodes": [
                                {
                                    "databaseId": 10,
                                    "body": f"{ci.COMMENT_PREFIX} old",
                                    "author": {"login": "writer"},
                                },
                                {
                                    "databaseId": 11,
                                    "body": f"{ci.COMMENT_PREFIX} new",
                                    "author": {"login": "writer"},
                                },
                            ]
                        }
                    }
                }
            }
        }
        with mock.patch.object(ci, "_run_json", return_value=payload), mock.patch.object(
            ci, "collaborator_permission", return_value="write"
        ) as permission:
            state = ci.current_comment_authorization_state(
                "heimgewebe/grabowski",
                42,
                comment_id=11,
                comment_body=f"{ci.COMMENT_PREFIX} new",
            )
        self.assertEqual(state, ci.COMMENT_STATE_CURRENT)
        permission.assert_called_once_with("heimgewebe/grabowski", "writer")


if __name__ == "__main__":
    unittest.main()
