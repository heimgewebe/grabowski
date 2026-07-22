from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pr_review_gate as gate  # noqa: E402
import pr_review_gate_ci as ci  # noqa: E402
import review_evidence_schemas as schemas  # noqa: E402


def _audit(**overrides) -> dict:
    payload = {
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
        "residual_risk_reason": "private",
        "gate_verdict": "PASS",
        "self_review_gate_valid": True,
        "tuning_signal": "observe",
    }
    payload.update(overrides)
    return payload


def _audit_bytes(**overrides) -> bytes:
    return (json.dumps(_audit(**overrides), sort_keys=True) + "\n").encode()


def _pr(**overrides) -> dict:
    payload = {
        "number": 42,
        "state": "OPEN",
        "isDraft": False,
        "headRefOid": "a" * 40,
        "baseRefOid": "c" * 40,
        "changedFiles": 1,
        "additions": 10,
        "deletions": 1,
        "files": [{"path": "src/example.py"}],
    }
    payload.update(overrides)
    return payload


class ReviewEvidenceHardeningTests(unittest.TestCase):
    def test_audit_builder_binds_base_and_policy_version(self) -> None:
        state = {
            "repoName": "heimgewebe/grabowski",
            "pr_diff_sha256": "b" * 64,
            "pr": {
                "number": 42,
                "headRefOid": "a" * 40,
                "baseRefOid": "c" * 40,
            },
        }
        result = {
            "verdict": "PASS",
            "complexity": {
                "review_tier": "standard",
                "minimum_self_review_iterations": 2,
            },
            "review_sources": {"self_review_gate_valid": True},
        }
        review = {
            "review_iterations": [{"n": 1}, {"n": 2}],
            "all_findings_triaged": True,
            "findings": [],
            "material_findings_after_first_review": 0,
            "material_findings_remaining": 0,
            "uncertainty": 0.1,
            "residual_risk": {"accepted": False, "reason": ""},
        }
        audit = gate.build_self_review_audit(state, result, review)
        self.assertEqual(audit["base_sha"], "c" * 40)
        self.assertEqual(audit["review_policy_version"], schemas.REVIEW_POLICY_VERSION)

    def test_projection_rejects_pre_policy_binding_audit(self) -> None:
        payload = _audit()
        payload.pop("review_policy_version")
        with self.assertRaisesRegex(ci.CiEvidenceError, "review_policy_version"):
            ci.build_status_projection((json.dumps(payload) + "\n").encode())

    def test_projection_rejects_pre_base_binding_audit(self) -> None:
        payload = _audit()
        payload.pop("base_sha")
        with self.assertRaisesRegex(ci.CiEvidenceError, "base_sha"):
            ci.build_status_projection((json.dumps(payload) + "\n").encode())

    def test_same_head_with_new_base_is_blocked(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        pr = _pr(baseRefOid="d" * 40)
        complexity = gate.classify_complexity(
            pr, None, repo_name="heimgewebe/grabowski"
        )
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=pr,
            diff_sha256="b" * 64,
            complexity=complexity,
        )
        self.assertIn("status evidence base_sha mismatch", failures)

    def test_old_policy_version_is_rejected_by_status_schema(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        projection["review_policy_version"] = schemas.REVIEW_POLICY_VERSION - 1
        failures = ci.evaluate_status_projection(
            projection,
            repo_name="heimgewebe/grabowski",
            pr=_pr(),
            diff_sha256="b" * 64,
            complexity=gate.classify_complexity(
                _pr(), None, repo_name="heimgewebe/grabowski"
            ),
        )
        self.assertTrue(any("review_policy_version" in failure for failure in failures))

    def test_comment_state_distinguishes_superseded_stale_and_outside_window(self) -> None:
        comments = [
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
        def permission(_actor: str) -> str:
            return "write"
        self.assertEqual(
            ci.command_comment_authorization_state(
                comments,
                current_comment_id=10,
                current_comment_body=f"{ci.COMMENT_PREFIX} old",
                permission_lookup=permission,
            ),
            ci.COMMENT_STATE_SUPERSEDED,
        )
        self.assertEqual(
            ci.command_comment_authorization_state(
                comments,
                current_comment_id=11,
                current_comment_body=f"{ci.COMMENT_PREFIX} changed",
                permission_lookup=permission,
            ),
            ci.COMMENT_STATE_STALE,
        )
        self.assertEqual(
            ci.command_comment_authorization_state(
                comments,
                current_comment_id=99,
                current_comment_body=f"{ci.COMMENT_PREFIX} missing",
                permission_lookup=permission,
            ),
            ci.COMMENT_STATE_OUTSIDE_WINDOW,
        )

    def test_permission_lookup_failure_is_authorization_unknown(self) -> None:
        comments = [
            {
                "databaseId": 10,
                "body": f"{ci.COMMENT_PREFIX} current",
                "author": {"login": "writer"},
            },
            {
                "databaseId": 11,
                "body": f"{ci.COMMENT_PREFIX} newer",
                "author": {"login": "unknown"},
            },
        ]

        def permission(actor: str) -> str:
            if actor == "unknown":
                raise ci.CiEvidenceError("permission lookup failed")
            return "write"

        state = ci.command_comment_authorization_state(
            comments,
            current_comment_id=10,
            current_comment_body=f"{ci.COMMENT_PREFIX} current",
            permission_lookup=permission,
        )
        self.assertEqual(state, ci.COMMENT_STATE_AUTHORIZATION_UNKNOWN)

    def test_future_command_version_does_not_supersede_v1(self) -> None:
        comments = [
            {
                "id": 10,
                "body": f"{ci.COMMENT_PREFIX} valid",
                "user": {"login": "writer"},
            },
            {
                "id": 11,
                "body": "/grabowski-review-evidence v2 future",
                "user": {"login": "writer"},
            },
        ]
        selected = ci.select_latest_authorized_command_comment_id(
            comments, permission_lookup=lambda actor: "write"
        )
        self.assertEqual(selected, 10)

    def test_publish_requires_comment_id_before_external_calls(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=None,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            publish_status=True,
        )
        with self.assertRaisesRegex(ci.CiEvidenceError, "--comment-id is required"):
            ci.evaluate_comment_command(args)

    def test_publish_actor_must_match_github_event_actor(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="claimed-admin",
            comment_id=1,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            publish_status=True,
        )
        with mock.patch.dict(os.environ, {"GITHUB_ACTOR": "actual-writer"}, clear=False):
            with self.assertRaisesRegex(ci.CiEvidenceError, "must match GITHUB_ACTOR"):
                ci.evaluate_comment_command(args)

    def test_comment_window_read_failure_replaces_old_green_with_failure(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GITHUB_ACTOR": "writer",
                    "REVIEW_GATE_COMMENT_BODY": f"{ci.COMMENT_PREFIX} payload",
                },
                clear=False,
            ),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()),
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                side_effect=ci.CiEvidenceError("comment API unavailable"),
            ),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 1)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=False,
            failure_count=1,
            context=ci.ADVISORY_STATUS_CONTEXT,
        )

    def test_authorization_unknown_replaces_old_green_with_failure(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GITHUB_ACTOR": "writer",
                    "REVIEW_GATE_COMMENT_BODY": f"{ci.COMMENT_PREFIX} payload",
                },
                clear=False,
            ),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()),
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                return_value=ci.COMMENT_STATE_AUTHORIZATION_UNKNOWN,
            ),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 1)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=False,
            failure_count=1,
            context=ci.ADVISORY_STATUS_CONTEXT,
        )

    def test_newer_authorized_command_on_final_freshness_skips_old_status_mutation(self) -> None:
        projection = ci.build_status_projection(_audit_bytes())
        body = f"{ci.COMMENT_PREFIX} {ci.encode_status_projection(projection)}"
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GITHUB_ACTOR": "writer", "REVIEW_GATE_COMMENT_BODY": body},
                clear=False,
            ),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()) as load_pr,
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_SUPERSEDED],
            ) as freshness,
            mock.patch.object(ci, "current_diff_sha256", return_value="b" * 64),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 0)
        self.assertEqual(freshness.call_count, 2)
        self.assertEqual(load_pr.call_count, 1)
        publish.assert_not_called()

    def test_subprocess_timeout_fails_closed(self) -> None:
        with mock.patch.object(
            ci.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd=["gh"], timeout=30),
        ):
            with self.assertRaisesRegex(ci.CiEvidenceError, "timed out"):
                ci._run_json(["gh", "api", "rate_limit"])

    def test_prepare_output_modes_are_mutually_exclusive(self) -> None:
        parser = ci.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["prepare", "--audit", "audit.json", "--base64", "--comment"]
            )

    def test_derived_status_is_forbidden_in_local_required_check_catalog(self) -> None:
        raw = json.dumps(
            {"schema_version": 1, "required_checks": [ci.STATUS_CONTEXT]}
        )
        with self.assertRaisesRegex(gate.GateInputError, "derived review status"):
            gate._required_check_names_from_catalog(raw)

    def test_legacy_review_status_is_forbidden_in_required_catalog(self) -> None:
        raw = json.dumps(
            {"schema_version": 1, "required_checks": [ci.LEGACY_STATUS_CONTEXT]}
        )
        with self.assertRaisesRegex(gate.GateInputError, "derived review status"):
            gate._required_check_names_from_catalog(raw)

    def test_advisory_derived_status_is_also_forbidden_in_required_catalog(self) -> None:
        raw = json.dumps(
            {"schema_version": 1, "required_checks": [ci.ADVISORY_STATUS_CONTEXT]}
        )
        with self.assertRaisesRegex(gate.GateInputError, "derived review status"):
            gate._required_check_names_from_catalog(raw)

    def test_workflow_uses_created_only_and_no_concurrency_queue(self) -> None:
        text = (
            ROOT / ".github" / "workflows" / "review-evidence-status.yml"
        ).read_text()
        self.assertIn("- created", text)
        self.assertNotIn("- edited", text)
        self.assertNotIn("concurrency:", text)
        self.assertIn("github.event.comment.body == '/grabowski-review-evidence v1'", text)
        self.assertIn("'/grabowski-review-evidence v1 '", text)
        self.assertIn("github.event.comment.body == '/grabowski-review-evidence v2'", text)
        self.assertIn("'/grabowski-review-evidence v2 '", text)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", text)


class ReviewEvidenceSchemaHardeningTests(unittest.TestCase):
    def test_canonical_audit_schema_allows_private_extension_fields(self) -> None:
        payload = _audit(private_operator_note="not projected")
        self.assertEqual(
            schemas.validate_evidence(payload, label="self-review audit"), ()
        )

    def test_canonical_status_schema_is_strict(self) -> None:
        status = ci.build_status_projection(_audit_bytes())
        status["private_operator_note"] = "must not cross boundary"
        self.assertIn(
            "unknown field(s): private_operator_note",
            schemas.validate_evidence(status, label="review gate status"),
        )


if __name__ == "__main__":
    unittest.main()
