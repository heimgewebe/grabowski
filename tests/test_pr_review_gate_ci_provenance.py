from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pr_review_gate_ci as ci  # noqa: E402
import review_evidence_schemas as schemas  # noqa: E402


def _audit(**overrides) -> dict:
    payload = {
        "schema_version": 1,
        "kind": "grabowski_self_review_audit",
        "generated_at": "2026-07-22T00:00:00+00:00",
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


class ReviewEvidenceProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.key = self.root / "review-key"
        self.other_key = self.root / "other-key"
        self.allowed = self.root / "allowed_signers"
        self.other_allowed = self.root / "other_allowed_signers"
        self._generate_key(self.key)
        self._generate_key(self.other_key)
        self._write_allowed(self.allowed, self.key)
        self._write_allowed(self.other_allowed, self.other_key)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _generate_key(path: Path) -> None:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    @staticmethod
    def _write_allowed(path: Path, key: Path) -> None:
        public_parts = key.with_suffix(".pub").read_text().strip().split()
        path.write_text(
            f'{ci.SIGNER_PRINCIPAL} namespaces="{ci.SIGNATURE_NAMESPACE}" '
            f"{public_parts[0]} {public_parts[1]}\n"
        )

    def _signed_body(self) -> str:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        return (
            f"{ci.COMMENT_PREFIX_V2} "
            f"{ci.encode_signed_status_attestation(attestation)}"
        )

    def test_signed_attestation_round_trip_verifies_exact_status(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        encoded = ci.encode_signed_status_attestation(attestation)
        status = ci.decode_signed_status_attestation(
            encoded, allowed_signers_path=self.allowed
        )
        self.assertEqual(status, ci.build_status_projection(_audit_bytes()))
        self.assertEqual(attestation["signer_principal"], ci.SIGNER_PRINCIPAL)
        self.assertEqual(attestation["signature_namespace"], ci.SIGNATURE_NAMESPACE)

    def test_tampered_signed_status_is_rejected(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        attestation["status"]["head_sha"] = "d" * 40
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signature operation failed"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.allowed
            )

    def test_signature_from_untrusted_key_is_rejected(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signature operation failed"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.other_allowed
            )

    def test_missing_allowed_signers_fails_closed(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        encoded = ci.encode_signed_status_attestation(attestation)
        with self.assertRaisesRegex(ci.CiEvidenceError, "signer allowlist is missing"):
            ci.decode_signed_status_attestation(
                encoded, allowed_signers_path=self.root / "missing"
            )

    def test_private_audit_extension_is_not_projected_or_signed(self) -> None:
        audit = _audit_bytes(private_operator_note="must stay local")
        attestation = ci.build_signed_status_attestation(audit, signing_key=self.key)
        rendered = json.dumps(attestation, sort_keys=True)
        self.assertNotIn("private_operator_note", rendered)
        self.assertNotIn("must stay local", rendered)

    def test_v1_and_v2_freshness_generations_are_independent(self) -> None:
        comments = [
            {
                "databaseId": 10,
                "body": f"{ci.COMMENT_PREFIX_V2} signed",
                "author": {"login": "writer"},
            },
            {
                "databaseId": 11,
                "body": f"{ci.COMMENT_PREFIX_V1} advisory",
                "author": {"login": "writer"},
            },
        ]
        state = ci.command_comment_authorization_state(
            comments,
            current_comment_id=10,
            current_comment_body=f"{ci.COMMENT_PREFIX_V2} signed",
            permission_lookup=lambda _actor: "write",
        )
        self.assertEqual(state, ci.COMMENT_STATE_CURRENT)

    def test_valid_v2_publishes_only_attested_required_context(self) -> None:
        body = self._signed_body()
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            allowed_signers=None,
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GITHUB_ACTOR": "writer", "REVIEW_GATE_COMMENT_BODY": body},
                clear=False,
            ),
            mock.patch.object(ci, "DEFAULT_ALLOWED_SIGNERS_PATH", self.allowed),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()),
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_CURRENT],
            ),
            mock.patch.object(ci, "current_diff_sha256", return_value="b" * 64),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 0)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=True,
            failure_count=0,
            context=ci.ATTESTED_STATUS_CONTEXT,
        )

    def test_valid_v1_can_only_publish_advisory_context(self) -> None:
        status = ci.build_status_projection(_audit_bytes())
        body = f"{ci.COMMENT_PREFIX_V1} {ci.encode_status_projection(status)}"
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            allowed_signers=None,
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GITHUB_ACTOR": "writer", "REVIEW_GATE_COMMENT_BODY": body},
                clear=False,
            ),
            mock.patch.object(ci, "DEFAULT_ALLOWED_SIGNERS_PATH", self.allowed),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()),
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_CURRENT],
            ),
            mock.patch.object(ci, "current_diff_sha256", return_value="b" * 64),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 0)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=True,
            failure_count=0,
            context=ci.ADVISORY_STATUS_CONTEXT,
        )

    def test_tampered_v2_publishes_blocking_attested_status(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        attestation["status"]["head_sha"] = "d" * 40
        body = (
            f"{ci.COMMENT_PREFIX_V2} "
            f"{ci.encode_signed_status_attestation(attestation)}"
        )
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            allowed_signers=None,
            publish_status=True,
        )
        with (
            mock.patch.dict(
                os.environ,
                {"GITHUB_ACTOR": "writer", "REVIEW_GATE_COMMENT_BODY": body},
                clear=False,
            ),
            mock.patch.object(ci, "DEFAULT_ALLOWED_SIGNERS_PATH", self.allowed),
            mock.patch.object(ci, "collaborator_permission", return_value="write"),
            mock.patch.object(ci, "load_live_pr", return_value=_pr()),
            mock.patch.object(
                ci,
                "current_comment_authorization_state",
                side_effect=[ci.COMMENT_STATE_CURRENT, ci.COMMENT_STATE_CURRENT],
            ),
            mock.patch.object(ci, "current_diff_sha256", return_value="b" * 64),
            mock.patch.object(ci, "publish_commit_status") as publish,
        ):
            result = ci.evaluate_comment_command(args)

        self.assertEqual(result, 1)
        publish.assert_called_once_with(
            repo_name="heimgewebe/grabowski",
            head_sha="a" * 40,
            passed=False,
            failure_count=1,
            context=ci.ATTESTED_STATUS_CONTEXT,
        )


    def test_publish_rejects_allowed_signers_override_before_external_calls(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            allowed_signers=str(self.allowed),
            publish_status=True,
        )
        with mock.patch.dict(
            os.environ, {"GITHUB_ACTOR": "writer"}, clear=False
        ):
            with self.assertRaisesRegex(
                ci.CiEvidenceError,
                "cannot override the trusted repository allowlist",
            ):
                ci.evaluate_comment_command(args)

    def test_publish_rejects_allowed_signers_environment_override(self) -> None:
        args = argparse.Namespace(
            repo_name="heimgewebe/grabowski",
            pr=42,
            actor="writer",
            comment_id=10,
            comment_body_env="REVIEW_GATE_COMMENT_BODY",
            allowed_signers=None,
            publish_status=True,
        )
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_ACTOR": "writer",
                "REVIEW_GATE_ALLOWED_SIGNERS": str(self.allowed),
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                ci.CiEvidenceError,
                "cannot override the trusted repository allowlist",
            ):
                ci.evaluate_comment_command(args)

    def test_prepare_attested_output_modes_are_mutually_exclusive(self) -> None:
        parser = ci.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "prepare-attested",
                    "--audit",
                    "audit.json",
                    "--signing-key",
                    "key",
                    "--base64",
                    "--comment",
                ]
            )

    def test_signed_attestation_schema_is_strict(self) -> None:
        attestation = ci.build_signed_status_attestation(
            _audit_bytes(), signing_key=self.key
        )
        attestation["private_note"] = "no"
        self.assertIn(
            "unknown field(s): private_note",
            schemas.validate_evidence(
                attestation, label="signed review gate status"
            ),
        )


if __name__ == "__main__":
    unittest.main()
