from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pr_review_gate as gate  # noqa: E402
import pr_review_gate_ci as ci  # noqa: E402


REVIEW_FOCUS = ["correctness", "regression_risk", "tests", "security", "integration"]


def _audit(**overrides) -> dict:
    payload = {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "generated_at": "2026-07-21T00:00:00+00:00",
        "repo": "heimgewebe/grabowski",
        "pr": 42,
        "head_sha": "a" * 40,
        "diff_sha256": "b" * 64,
        "review_tier": "standard",
        "minimum_review_iterations": 2,
        "actual_review_iterations": 2,
        "all_findings_triaged": True,
        "finding_count": 0,
        "material_findings_after_first_review": 0,
        "material_findings_remaining": 0,
        "uncertainty": 0.1,
        "residual_risk_accepted": False,
        "residual_risk_reason": "private review prose must not enter CI",
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "tuning_signal": "observe",
    }
    payload.update(overrides)
    return payload


def _audit_bytes(**overrides) -> bytes:
    return (json.dumps(_audit(**overrides), indent=2, sort_keys=True) + "\n").encode()


def _pr(**overrides) -> dict:
    payload = {
        "number": 42,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": "a" * 40,
        "baseRefOid": "c" * 40,
        "changedFiles": 1,
        "additions": 50,
        "deletions": 5,
        "files": [{"path": "src/example.py"}],
    }
    payload.update(overrides)
    return payload


class ReviewEvidenceCiProjectionTests(unittest.TestCase):
    def test_projection_strips_private_audit_content(self) -> None:
        audit_bytes = _audit_bytes()
        projection = ci.build_status_projection(audit_bytes)
        rendered = json.dumps(projection, sort_keys=True)

        self.assertNotIn("residual_risk_reason", projection)
        self.assertNotIn("generated_at", projection)
        self.assertNotIn("private review prose", rendered)
        self.assertEqual(projection["audit_sha256"], ci.hashlib.sha256(audit_bytes).hexdigest())

    def test_comment_round_trip_uses_only_sanitized_projection(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        comment = f"{ci.COMMENT_PREFIX} {ci.encode_status_projection(projection)}"
        self.assertEqual(ci.parse_comment_status(comment), projection)

    def test_missing_comment_payload_is_rejected(self) -> None:
        with self.assertRaisesRegex(ci.CiEvidenceError, "status evidence is missing"):
            ci.parse_comment_status(ci.COMMENT_PREFIX)

    def test_unknown_projection_fields_are_rejected(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        projection["private_note"] = "must not be accepted"
        encoded = base64.b64encode(ci.canonical_status_bytes(projection)).decode()
        with self.assertRaisesRegex(ci.CiEvidenceError, "unknown field"):
            ci.decode_status_projection(encoded)


class ReviewEvidenceCiEvaluationTests(unittest.TestCase):
    def _complexity(self, pr: dict | None = None) -> dict:
        return gate.classify_complexity(
            pr or _pr(),
            None,
            repo_name="heimgewebe/grabowski",
        )

    def test_green_projection_passes_current_head_and_diff(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=_pr(),
            diff_sha256="b" * 64,
            complexity=self._complexity(),
        )
        self.assertEqual(failures, [])

    def test_stale_head_is_blocked(self) -> None:
        projection = ci.build_status_projection(_audit_bytes(head_sha="d" * 40))
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=_pr(),
            diff_sha256="b" * 64,
            complexity=self._complexity(),
        )
        self.assertIn("status evidence head_sha mismatch", failures)

    def test_stale_diff_is_blocked(self) -> None:
        projection = ci.build_status_projection(_audit_bytes(diff_sha256="d" * 64))
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=_pr(),
            diff_sha256="b" * 64,
            complexity=self._complexity(),
        )
        self.assertIn("status evidence diff_sha256 mismatch", failures)

    def test_red_audit_is_blocked(self) -> None:
        projection = ci.build_status_projection(
            _audit_bytes(
                gate_verdict="BLOCK",
                self_review_gate_valid=False,
                tuning_signal="repair_evidence",
            )
        )
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=_pr(),
            diff_sha256="b" * 64,
            complexity=self._complexity(),
        )
        self.assertIn("status evidence gate_verdict is not PASS", failures)
        self.assertIn("status evidence self_review_gate_valid is not true", failures)
        self.assertIn("status evidence tuning_signal is not observe", failures)

    def test_current_high_critical_depth_cannot_be_weakened(self) -> None:
        pr = _pr(
            changedFiles=1,
            additions=20,
            deletions=0,
            files=[{"path": "tools/pr_review_gate.py"}],
        )
        projection = ci.build_status_projection(_audit_bytes())
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=pr,
            diff_sha256="b" * 64,
            complexity=self._complexity(pr),
        )
        self.assertIn("status evidence minimum review depth is stale or too weak", failures)
        self.assertIn("status evidence review tier is stale or too weak", failures)

    def test_only_write_level_permissions_can_publish(self) -> None:
        for permission in ("admin", "maintain", "write", "push"):
            with self.subTest(permission=permission):
                self.assertTrue(ci.permission_allows_publish(permission))
        for permission in ("read", "pull", "triage", None):
            with self.subTest(permission=permission):
                self.assertFalse(ci.permission_allows_publish(permission))

    def test_latest_authorized_command_wins_without_unauthorized_suppression(self) -> None:
        comments = [
            {
                "id": 10,
                "body": f"{ci.COMMENT_PREFIX} old",
                "user": {"login": "writer"},
            },
            {
                "id": 11,
                "body": f"{ci.COMMENT_PREFIX} malicious",
                "user": {"login": "reader"},
            },
            {
                "id": 12,
                "body": "unrelated comment",
                "user": {"login": "admin"},
            },
            {
                "id": 13,
                "body": f"{ci.COMMENT_PREFIX} newest",
                "user": {"login": "admin"},
            },
        ]
        permissions = {"writer": "write", "reader": "read", "admin": "admin"}
        selected = ci.select_latest_authorized_command_comment_id(
            comments, permission_lookup=permissions.get
        )
        self.assertEqual(selected, 13)

    def test_edited_comment_body_is_rejected_even_with_same_comment_id(self) -> None:
        comments = [
            {
                "databaseId": 25,
                "body": f"{ci.COMMENT_PREFIX} new-payload",
                "author": {"login": "writer"},
            }
        ]
        self.assertFalse(
            ci.command_comment_is_current_and_latest_authorized(
                comments,
                current_comment_id=25,
                current_comment_body=f"{ci.COMMENT_PREFIX} old-payload",
                permission_lookup=lambda actor: "write",
            )
        )
        self.assertTrue(
            ci.command_comment_is_current_and_latest_authorized(
                comments,
                current_comment_id=25,
                current_comment_body=f"{ci.COMMENT_PREFIX} new-payload",
                permission_lookup=lambda actor: "write",
            )
        )

    def test_no_authorized_command_is_fail_closed_for_publication_selection(self) -> None:
        comments = [
            {
                "id": 30,
                "body": f"{ci.COMMENT_PREFIX} invalid",
                "user": {"login": "reader"},
            }
        ]
        selected = ci.select_latest_authorized_command_comment_id(
            comments, permission_lookup=lambda actor: "read"
        )
        self.assertIsNone(selected)

    def test_unauthorized_newer_command_cannot_supersede_authorized_status(self) -> None:
        comments = [
            {
                "id": 20,
                "body": f"{ci.COMMENT_PREFIX} valid",
                "user": {"login": "writer"},
            },
            {
                "id": 21,
                "body": f"{ci.COMMENT_PREFIX} invalid",
                "user": {"login": "reader"},
            },
        ]
        permissions = {"writer": "write", "reader": "read"}
        selected = ci.select_latest_authorized_command_comment_id(
            comments, permission_lookup=permissions.get
        )
        self.assertEqual(selected, 20)


class ReviewEvidenceCiRecursionTests(unittest.TestCase):
    def test_derived_review_status_does_not_block_its_source_gate(self) -> None:
        state = {
            "repoName": "heimgewebe/grabowski",
            "pr_diff_bypass": True,
            "pr_diff_bypass_reason": gate.SELF_REVIEW_DIFF_BYPASS_REASON,
            "pr": {
                "number": 42,
                "state": "OPEN",
                "isDraft": False,
                "mergeStateStatus": "CLEAN",
                "mergeable": "MERGEABLE",
                "headRefOid": "a" * 40,
                "baseRefOid": "b" * 40,
                "changedFiles": 1,
                "additions": 1,
                "deletions": 0,
                "files": [{"path": "docs/note.md"}],
            },
            "checks": [
                {"bucket": "pass", "name": "validate (3.10)"},
                {"bucket": "pass", "name": "validate (3.12)"},
                {"bucket": "fail", "name": ci.STATUS_CONTEXT},
            ],
        }
        review = {
            "schema_version": 1,
            "kind": "grabowski_self_review",
            "review_mode": "critical_diff_review",
            "verdict": "PASS",
            "repo": "heimgewebe/grabowski",
            "pr": 42,
            "head_sha": "a" * 40,
            "reviewed_files": ["docs/note.md"],
            "review_focus": REVIEW_FOCUS,
            "diff_reviewed": True,
            "all_findings_triaged": True,
            "review_iterations": [
                {"n": 1, "summary": "documentation review", "material_findings": 0}
            ],
            "stop_reason": "clean_pass",
            "findings": [],
            "material_findings_remaining": 0,
            "material_findings_after_first_review": 0,
            "uncertainty": 0.1,
        }
        result = gate.evaluate_review_gate(state, self_review=review)
        self.assertEqual(result["verdict"], "PASS")


class ReviewEvidenceCiWorkflowContractTests(unittest.TestCase):
    def test_workflow_uses_default_branch_comment_event_and_minimal_permissions(self) -> None:
        text = (ROOT / ".github" / "workflows" / "review-evidence-status.yml").read_text()
        self.assertIn("issue_comment:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertIn("contents: read", text)
        self.assertIn("pull-requests: read", text)
        self.assertIn("statuses: write", text)
        self.assertIn("evaluate-comment", text)
        self.assertIn("--publish-status", text)
        self.assertIn("author_association", text)
        self.assertIn("OWNER", text)
        self.assertIn("MEMBER", text)
        self.assertIn("COLLABORATOR", text)
        self.assertNotIn("secrets.", text)


if __name__ == "__main__":
    unittest.main()
