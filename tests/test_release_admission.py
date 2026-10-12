from __future__ import annotations

import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_release_admission as admission  # noqa: E402

SERVING = "a" * 40
TARGET = "b" * 40
DIFF = "d" * 64


def _ci_result(name: str, run_id: int, *, sha: str = TARGET,
               conclusion: str = "success", app: str = "github-actions") -> dict:
    return {
        "name": name, "id": run_id, "head_sha": sha,
        "status": "completed", "conclusion": conclusion,
        "app": {"slug": app},
    }


def _reconciliation(*, proven: int = 1, status: str = "settled",
                    errors: list[str] | None = None,
                    head: str = TARGET, base: str = SERVING,
                    diff: str = DIFF, deferred: int = 0) -> dict:
    return {
        "status": status, "errors": [] if errors is None else errors,
        "binding": {
            "repo": admission.REPOSITORY, "pr": 1452,
            "head_sha": head, "base_sha": base, "diff_sha256": diff,
        },
        "binding_sha256": "c" * 64,
        "attempts_sha256": "e" * 64,
        "deferred_diff_identity_count": deferred,
        "slots": [{
            "slot": "independent-claude", "pass_count": 1,
            "independent_pass_count": proven,
        }],
    }


class AuthoritativeCIReadTests(unittest.TestCase):
    def query(self, checks: list[dict], *, status: int = 200, link: str = ""):
        response = Mock()
        response.status = status
        response.getheader.return_value = link
        response.read.return_value = json.dumps({
            "total_count": len(checks), "check_runs": checks,
        }).encode()
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(admission.http.client, "HTTPSConnection", return_value=connection):
            return admission._fresh_github_checks(TARGET)

    def test_accepts_server_observed_exact_green_checks(self):
        result = self.query([
            _ci_result("validate (3.10)", 100),
            _ci_result("validate (3.12)", 101),
            _ci_result("CodeQL", 200),
        ])
        self.assertEqual(2, len(result["checks"]))
        self.assertEqual("validate (3.10)", result["checks"][0]["name"])
        self.assertEqual(64, len(result["checks_sha256"]))

    def test_newer_failure_cannot_be_hidden_by_earlier_pass(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "not green"):
            self.query([
                _ci_result("validate (3.10)", 100),
                _ci_result("validate (3.10)", 103, conclusion="failure"),
                _ci_result("validate (3.12)", 101),
            ])

    def test_failed_older_rerun_can_be_superseded_by_new_green(self):
        record = self.query([
            _ci_result("validate (3.10)", 100, conclusion="failure"),
            _ci_result("validate (3.10)", 104),
            _ci_result("validate (3.12)", 105),
        ])
        self.assertEqual(104, record["checks"][0]["id"])

    def test_spoofed_provider_blocks(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "origin"):
            self.query([
                _ci_result("validate (3.10)", 100, app="third-party"),
                _ci_result("validate (3.12)", 101),
            ])

    def test_stale_commit_blocks(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "commit mismatch"):
            self.query([
                _ci_result("validate (3.10)", 100, sha=SERVING),
                _ci_result("validate (3.12)", 101),
            ])

    def test_missing_required_check_blocks(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "missing"):
            self.query([_ci_result("validate (3.10)", 100)])

    def test_truncated_page_blocks(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "paginated"):
            self.query([
                _ci_result("validate (3.10)", 100),
                _ci_result("validate (3.12)", 101),
            ], link='<https://api.github.com/test?page=2>; rel="next"')

    def test_http_failure_blocks(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "HTTP 403"):
            self.query([], status=403)


class DecisionBoundReleaseReviewTests(unittest.TestCase):
    def reconcile(self, evidence: dict):
        decision_module = types.ModuleType("grabowski_decision_reviews")
        merge_module = types.ModuleType("grabowski_merge_guard")
        decision_module.reconcile = Mock(return_value=evidence)
        merge_module.independent_review_reconciliation_summary = lambda item: {
            "pass_count": item["slots"][0]["independent_pass_count"],
            "admissible_slots": (
                ["independent-claude"] if item["slots"][0]["independent_pass_count"] else []
            ),
            "errors": [],
        }
        with patch.dict(sys.modules, {
            "grabowski_decision_reviews": decision_module,
            "grabowski_merge_guard": merge_module,
        }):
            result = admission.validate_independent_release_review(
                serving_head=SERVING, target_head=TARGET, diff_sha256=DIFF,
                review_pr=1452,
            )
        return result, decision_module.reconcile

    def test_accepts_origin_proven_reconciled_full_delta(self):
        result, reconcile = self.reconcile(_reconciliation())
        self.assertEqual(1, result["independent_pass_count"])
        self.assertEqual(SERVING, reconcile.call_args.kwargs["base_sha"])
        self.assertEqual(TARGET, reconcile.call_args.kwargs["head_sha"])
        self.assertEqual(DIFF, reconcile.call_args.kwargs["diff_sha256"])
        self.assertFalse(reconcile.call_args.kwargs["defer_diff_identity"])

    def test_generic_PASS_without_proven_reviewer_is_rejected(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "R3 PASS"):
            self.reconcile(_reconciliation(proven=0))

    def test_rejects_any_material_review_debt(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "R3 PASS"):
            self.reconcile(_reconciliation(errors=["material_reject"]))

    def test_rejects_review_of_stale_commit(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "binding drift"):
            self.reconcile(_reconciliation(head="f" * 40))

    def test_rejects_deferred_diff_identity(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "R3 PASS"):
            self.reconcile(_reconciliation(deferred=1))

    def test_rejects_invalid_caller_namespace(self):
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "invalid"):
            admission.validate_independent_release_review(
                serving_head=SERVING, target_head=TARGET, diff_sha256=DIFF,
                review_pr=True,
            )

    def test_valid_review_does_not_claim_captain(self):
        with (
            patch.object(admission, "validate_independent_release_review", return_value={
                "review_pr": 1452, "independent_pass_count": 1,
            }),
            patch.object(admission, "_fresh_github_checks", return_value={
                "checks": [], "checks_sha256": "e" * 64,
            }),
        ):
            result = admission.validate_release(
                serving_head=SERVING, target_head=TARGET, serving_release_id="release-blue",
                serving_tree="1" * 40, target_tree="2" * 40,
                diff_sha256=DIFF, review_pr=1452,
            )
        self.assertEqual("authenticated-post-merge-r3-ci", result["status"])
        self.assertIn("Captain runtime-deploy decision", result["does_not_establish"])
        self.assertIn("historical pre-merge review authorization", result["does_not_establish"])


class GitObjectWidthContractTests(unittest.TestCase):
    """Syntax-only compatibility, never a substitute for protected R3/Captain."""

    def test_exact_sha256_target_is_forwarded_to_real_check_origin_contract(self) -> None:
        target = "b" * 64
        response = Mock()
        response.status = 200
        response.getheader.return_value = ""
        response.read.return_value = json.dumps({
            "total_count": 2,
            "check_runs": [
                _ci_result("validate (3.10)", 201, sha=target),
                _ci_result("validate (3.12)", 202, sha=target),
            ],
        }).encode()
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(admission.http.client, "HTTPSConnection", return_value=connection):
            result = admission._fresh_github_checks(target)
        self.assertEqual(target, result["checks"][0]["head_sha"])
        self.assertIn(target, connection.request.call_args.args[1])

    def test_incomplete_and_wrongcase_git_ids_reject_before_github_lookup(self) -> None:
        with patch.object(admission.http.client, "HTTPSConnection") as connection:
            for head in ("b" * 39, "b" * 41, "b" * 52, "b" * 63,
                         "b" * 65, "B" * 40, "B" * 64):
                with self.subTest(length=len(head), case=head[:1]):
                    with self.assertRaises(admission.ReleaseAdmissionDenied):
                        admission._fresh_github_checks(head)
        connection.assert_not_called()

    def test_exact_sha256_review_namespace_is_not_an_automatic_pass(self) -> None:
        target = "b" * 64
        serving = "a" * 64
        decisions = types.ModuleType("grabowski_decision_reviews")
        merge_guard = types.ModuleType("grabowski_merge_guard")
        decisions.reconcile = Mock(return_value=_reconciliation(head=target, base=serving))
        merge_guard.independent_review_reconciliation_summary = Mock(
            return_value={"pass_count": 1, "admissible_slots": ["synthetic-only"],
                          "errors": []})
        with patch.dict(sys.modules, {
            "grabowski_decision_reviews": decisions,
            "grabowski_merge_guard": merge_guard,
        }):
            result = admission.validate_independent_release_review(
                serving_head=serving, target_head=target,
                diff_sha256=DIFF, review_pr=1452)
        self.assertEqual(1, result["independent_pass_count"])
        self.assertEqual(target, decisions.reconcile.call_args.kwargs["head_sha"])

    def test_mixed_git_object_formats_deny_before_any_external_review(self) -> None:
        with (
            patch.object(admission, "validate_independent_release_review") as review,
            patch.object(admission, "_fresh_github_checks") as ci,
        ):
            for serving, target, source_tree, target_tree in (
                ("a" * 40, "b" * 64, "1" * 40, "2" * 64),
                ("a" * 64, "b" * 64, "1" * 40, "2" * 64),
                ("a" * 64, "b" * 64, "1" * 64, "2" * 40),
                ("a" * 64, "b" * 63, "1" * 64, "2" * 64),
            ):
                with self.subTest(lengths=(len(serving), len(target),
                                           len(source_tree), len(target_tree))):
                    with self.assertRaises(admission.ReleaseAdmissionDenied):
                        admission.validate_release(
                            serving_head=serving, target_head=target,
                            serving_release_id="test-only", serving_tree=source_tree,
                            target_tree=target_tree, diff_sha256=DIFF, review_pr=1452)
        review.assert_not_called()
        ci.assert_not_called()

    def test_matching_sha256_tree_ids_are_only_a_syntactic_admission(self) -> None:
        with (
            patch.object(admission, "validate_independent_release_review",
                         return_value={"synthetic-only": True}) as review,
            patch.object(admission, "_fresh_github_checks",
                         return_value={"checks": [], "checks_sha256": "e" * 64}) as ci,
        ):
            response = admission.validate_release(
                serving_head="a" * 64, target_head="b" * 64,
                serving_release_id="test-only", serving_tree="1" * 64,
                target_tree="2" * 64, diff_sha256=DIFF, review_pr=1452)
        self.assertEqual("b" * 64, response["target_head"])
        self.assertIn("Captain runtime-deploy decision", response["does_not_establish"])
        review.assert_called_once()
        ci.assert_called_once_with("b" * 64)


class DirectSchedulerDenialTests(unittest.TestCase):
    def test_critical_source_cannot_use_review_pr_without_captain_context(self):
        import grabowski_self_deploy as deploy

        def git_output(stdout: str) -> dict:
            return {
                "returncode": 0, "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
                "stdout": stdout, "stderr": "",
            }

        blue = {"completion_status": "complete", "runtime_binding_valid": True,
                "artifact_integrity_valid": True, "provenance_valid": True,
                "repo_head": SERVING, "release_id": "release-blue"}
        process = {
            "matches_deployed_manifest": True, "process_release_id": "release-blue",
            "process_repo_head": SERVING,
        }
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=blue),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                git_output(""), git_output("src/grabowski_self_deploy.py\x00")
            ]) as read,
        ):
            with self.assertRaisesRegex(RuntimeError, "Captain release action"):
                deploy._require_release_source_admission(TARGET, release_review_pr=1452)
        self.assertEqual(2, read.call_count)

    def test_captain_scoped_token_is_ephemeral_and_exact(self):
        import grabowski_self_deploy as deploy
        record = {
            "independent_review_required": True,
            "serving_head": SERVING, "serving_release_id": "release-blue",
            "release_review_identity_sha256": "a" * 64,
        }
        self.assertIsNone(deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get())
        with patch.object(deploy, "_require_release_source_admission", return_value=record):
            with deploy._captain_release_scope(TARGET, 1452):
                state = deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get()
                self.assertEqual(TARGET, state["target_head"])
                self.assertEqual(1452, state["review_pr"])
        self.assertIsNone(deploy._CAPTAIN_RUNTIME_RELEASE_SCOPE.get())


    def test_docs_only_symlink_cannot_receive_documentation_exemption(self):
        import grabowski_self_deploy as deploy
        def git_output(stdout: str) -> dict:
            return {
                "returncode": 0, "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
                "stdout": stdout, "stderr": "",
            }
        blue = {
            "completion_status": "complete", "runtime_binding_valid": True,
            "artifact_integrity_valid": True, "provenance_valid": True,
            "repo_head": SERVING, "release_id": "release-blue",
        }
        process = {
            "matches_deployed_manifest": True, "process_release_id": "release-blue",
            "process_repo_head": SERVING,
        }
        raw_symlink = (
            ":120000 120000 " + "1" * 40 + " " + "2" * 40
            + " M\x00docs/guide.md\x00"
        )
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=blue),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                git_output(""), git_output("docs/guide.md\x00"),
                git_output(raw_symlink),
            ]),
        ):
            with self.assertRaisesRegex(RuntimeError, "document.*mode|plain.*documentation"):
                deploy._require_release_source_admission(TARGET)


class RealGitDocumentationModeTests(unittest.TestCase):
    """Do not trust a synthetic raw-diff fixture for the docs-only exemption."""

    def _run_real_git_delta(self, *, symlink: bool):
        import subprocess
        import tempfile
        import grabowski_self_deploy as deploy

        with tempfile.TemporaryDirectory(prefix="grabowski-release-docs-") as tmp:
            repo = Path(tmp)
            def git(*args):
                return subprocess.run(
                    ["git", "-C", str(repo), *args],
                    capture_output=True, text=True, check=True,
                    env={"PATH": "/usr/bin:/bin", "HOME": str(repo)},
                ).stdout.strip()

            git("init", "-q")
            path = repo / "docs" / "guide.md"
            path.parent.mkdir()
            path.write_text("Initial safe documentation\n")
            git("add", "--", "docs/guide.md")
            git("-c", "user.name=Release Tests", "-c", "user.email=release@example.invalid",
                "commit", "-qm", "Initial documentation")
            serving = git("rev-parse", "HEAD")
            if symlink:
                path.unlink()
                path.symlink_to("../src/grabowski_self_deploy.py")
            else:
                path.write_text("A safe textual documentation change\n")
            git("add", "--", "docs/guide.md")
            git("-c", "user.name=Release Tests", "-c", "user.email=release@example.invalid",
                "commit", "-qm", "Update documentation")
            target = git("rev-parse", "HEAD")
            metadata = {
                "completion_status": "complete", "runtime_binding_valid": True,
                "artifact_integrity_valid": True, "provenance_valid": True,
                "repo_head": serving, "release_id": "docs-base",
            }
            identity = {
                "matches_deployed_manifest": True,
                "process_release_id": "docs-base", "process_repo_head": serving,
            }
            with (
                patch.object(deploy, "CANONICAL_REPOSITORY", repo),
                patch.object(deploy.base, "_deployment_metadata", return_value=metadata),
                patch.object(deploy.serving_process, "identity", return_value=identity),
            ):
                if symlink:
                    with self.assertRaisesRegex(RuntimeError, "non-plain documentation|documentation Git mode"):
                        deploy._require_release_source_admission(target)
                else:
                    result = deploy._require_release_source_admission(target)
                    self.assertEqual("non-runtime-documentation", result["status"])

    def test_genuine_git_regular_file_delta_allowed(self):
        self._run_real_git_delta(symlink=False)

    def test_genuine_git_symlink_delta_blocked(self):
        self._run_real_git_delta(symlink=True)




if __name__ == "__main__":
    unittest.main()
