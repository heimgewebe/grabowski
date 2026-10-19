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
SERVING_TREE = "c" * 40
TARGET_TREE = "e" * 40


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
    """GitHub-owned, actual workflow/run/job/check provenance, not just names."""

    def fixture(self):
        prefix = f"/repos/{admission.REPOSITORY}"
        workflow_id, run_id, suite_id = 301891383, 800, 900
        identity = {
            "id": run_id, "workflow_id": workflow_id,
            "path": admission.CANONICAL_WORKFLOW_PATH,
            "head_sha": TARGET, "run_number": 42,
            "run_attempt": 1, "check_suite_id": suite_id,
            "event": "push", "head_branch": "main",
            "repository": {"full_name": admission.REPOSITORY},
            "head_repository": {"full_name": admission.REPOSITORY},
            "status": "completed", "conclusion": "success",
        }
        jobs = [
            {
                "name": name, "id": check_id, "run_id": run_id,
                "run_attempt": 1, "head_sha": TARGET,
                "status": "completed", "conclusion": "success",
                "check_run_url": f"https://{admission.GITHUB_HOST}{prefix}/check-runs/{check_id}",
            }
            for name, check_id in zip(admission.REQUIRED_CI_CHECKS, (101, 102), strict=True)
        ]
        checks = [
            {
                **_ci_result(job["name"], job["id"]),
                "check_suite": {"id": suite_id},
            }
            for job in jobs
        ]
        paths = {
            "workflow": f"{prefix}/actions/workflows/validate.yml",
            "serving_workflow": f"{prefix}/contents/{admission.CANONICAL_WORKFLOW_PATH}?ref={SERVING}",
            "target_workflow": f"{prefix}/contents/{admission.CANONICAL_WORKFLOW_PATH}?ref={TARGET}",
            "serving_commit": f"{prefix}/git/commits/{SERVING}",
            "target_commit": f"{prefix}/git/commits/{TARGET}",
            "serving_tree": f"{prefix}/git/trees/{SERVING_TREE}",
            "target_tree": f"{prefix}/git/trees/{TARGET_TREE}",
            "runs": f"{prefix}/actions/workflows/{workflow_id}/runs?head_sha={TARGET}&per_page=100&page=1",
            "run": f"{prefix}/actions/runs/{run_id}",
            "jobs": f"{prefix}/actions/runs/{run_id}/jobs?filter=all&per_page=100&page=1",
            "checks": f"{prefix}/commits/{TARGET}/check-runs?filter=all&per_page=100&page=1",
        }
        root_entries = [
            {"path": path, "type": kind, "mode": mode, "sha": "1" * 40}
            for path, kind, mode in (
                (".github", "tree", "040000"),
                (".gitignore", "blob", "100644"),
                ("AGENTS.md", "blob", "100644"),
                ("Makefile", "blob", "100644"),
                ("pyproject.toml", "blob", "100644"),
                ("README.md", "blob", "100644"),
                ("src", "tree", "040000"),
                ("docs", "tree", "040000"),
                ("config", "tree", "040000"),
                ("contracts", "tree", "040000"),
                ("deploy", "tree", "040000"),
                ("requirements", "tree", "040000"),
                ("systemd", "tree", "040000"),
                ("tests", "tree", "040000"),
                ("tmpfiles", "tree", "040000"),
                ("tools", "tree", "040000"),
            )
        ]
        pages = {
            paths["workflow"]: {
                "id": workflow_id, "path": admission.CANONICAL_WORKFLOW_PATH,
                "state": "active",
            },
            paths["serving_workflow"]: {"path": admission.CANONICAL_WORKFLOW_PATH, "type": "file", "sha": "1" * 40},
            paths["target_workflow"]: {"path": admission.CANONICAL_WORKFLOW_PATH, "type": "file", "sha": "1" * 40},
            paths["serving_commit"]: {"sha": SERVING, "tree": {"sha": SERVING_TREE}},
            paths["target_commit"]: {"sha": TARGET, "tree": {"sha": TARGET_TREE}},
            paths["serving_tree"]: {"sha": SERVING_TREE, "truncated": False, "tree": [e.copy() for e in root_entries]},
            paths["target_tree"]: {"sha": TARGET_TREE, "truncated": False, "tree": [e.copy() for e in root_entries]},
            paths["runs"]: {"total_count": 1, "workflow_runs": [identity.copy()]},
            paths["run"]: identity.copy(),
            paths["jobs"]: {"total_count": len(jobs), "jobs": jobs},
            paths["checks"]: {"total_count": len(checks), "check_runs": checks},
        }
        return paths, pages

    def query(self, pages, *, http_codes=None, links=None,
              transition_review_pr=None, transition_diff_sha256=None):
        current = {"path": None}
        requests = []
        connection = Mock()

        def request(method, path, *, headers):
            self.assertEqual("GET", method)
            self.assertEqual("Bearer " + "test-only-credential", headers.get("Authorization"))
            self.assertTrue(path.startswith(f"/repos/{admission.REPOSITORY}/"))
            current["path"] = path
            requests.append(path)

        def response():
            path = current["path"]
            self.assertIsNotNone(path)
            payload = pages.get(path)
            if payload is None and "/check-runs/" in path:
                # The implementation must read each canonical Actions job's
                # exact check-run ID, never all same-name commit checks.
                check_id = int(path.rsplit("/", 1)[-1])
                inventory = [
                    value["check_runs"]
                    for key, value in pages.items()
                    if "/commits/" in key and "/check-runs?" in key
                ]
                checks = [
                    check for entries in inventory for check in entries
                    if check["id"] == check_id
                ]
                if len(checks) == 1:
                    payload = checks[0]
            if payload is None:
                raise AssertionError(f"Unexpected GitHub endpoint: {path}")
            result = Mock()
            result.status = (http_codes or {}).get(path, 200)
            result.read.return_value = json.dumps(payload).encode("utf-8")
            result.getheader.side_effect = lambda name, default="": (
                (links or {}).get(path, "") if name == "Link" else default
            )
            return result

        connection.request.side_effect = request
        connection.getresponse.side_effect = response
        with (patch.object(admission, "_github_token", return_value="test-only-credential", create=True) as credentials,
              patch.object(admission.http.client, "HTTPSConnection", return_value=connection)):
            value = admission._fresh_github_checks(
                TARGET, serving_head=SERVING, review_pr=transition_review_pr,
                diff_sha256=transition_diff_sha256,
            )
        credentials.assert_called_once_with()
        return value, requests

    def test_accepts_full_canonical_green_workflow_and_jobs(self):
        paths, pages = self.fixture()
        result, requests = self.query(pages)
        self.assertEqual(2, len(result["checks"]))
        self.assertEqual(101, result["checks"][0]["id"])
        self.assertEqual(301891383, result["checks"][0]["workflow_id"])
        self.assertEqual(800, result["workflow"]["run_id"])
        self.assertEqual(64, len(result["checks_sha256"]))
        self.assertNotIn(paths["checks"], requests)
        self.assertEqual([
            f"/repos/{admission.REPOSITORY}/check-runs/101",
            f"/repos/{admission.REPOSITORY}/check-runs/102",
        ], requests[-2:])
        self.assertEqual(12, len(requests))

    def test_verified_git_commit_tree_oid_is_used_for_validation_policy(self):
        paths, pages = self.fixture()
        result, requests = self.query(pages)
        self.assertEqual(2, len(result["checks"]))
        self.assertIn(paths["serving_commit"], requests)
        self.assertIn(paths["target_commit"], requests)
        self.assertIn(paths["serving_tree"], requests)
        self.assertIn(paths["target_tree"], requests)
        self.assertNotEqual(SERVING, SERVING_TREE)
        self.assertNotEqual(TARGET, TARGET_TREE)

    def test_commit_to_root_tree_mismatch_fails_closed(self):
        for defect in ("commit_sha", "tree_oid", "tree_missing", "tree_not_dict",
                       "tree_response", "commit_link"):
            with self.subTest(defect=defect):
                paths, pages = self.fixture()
                links = {}
                if defect == "commit_sha":
                    pages[paths["target_commit"]]["sha"] = SERVING
                elif defect == "tree_oid":
                    pages[paths["target_commit"]]["tree"]["sha"] = "f" * 40
                elif defect == "tree_missing":
                    pages[paths["target_commit"]].pop("tree")
                elif defect == "tree_not_dict":
                    pages[paths["target_commit"]]["tree"] = TARGET_TREE
                elif defect == "tree_response":
                    pages[paths["target_tree"]]["sha"] = SERVING_TREE
                else:
                    links[paths["target_commit"]] = '<https://api.github.com/other>; rel="next"'
                with self.assertRaises(admission.ReleaseAdmissionDenied):
                    self.query(pages, links=links)

    def test_target_control_changes_cannot_self_grade_with_green_validate(self):
        # The YAML can stay byte-identical while target-controlled policy
        # sources become no-op validators or scripts.
        for changed in ("Makefile", "tests", "tools", "requirements",
                        "config", "contracts", "deploy", "systemd",
                        ".github", "pyproject.toml", ".gitignore"):
            with self.subTest(changed=changed):
                paths, pages = self.fixture()
                target_entries = pages[paths["target_tree"]]["tree"]
                next(e for e in target_entries if e["path"] == changed)["sha"] = "2" * 40
                with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "trusted Validate.*(policy|control|input).*changed"):
                    self.query(pages)

    def test_passive_docs_are_not_validation_policy(self):
        paths, pages = self.fixture()
        for path in ("docs", "README.md"):
            next(e for e in pages[paths["target_tree"]]["tree"]
                 if e["path"] == path)["sha"] = "2" * 40
        accepted, requests = self.query(pages)
        self.assertEqual(2, len(accepted["checks"]))
        self.assertEqual(64, len(accepted["workflow"]["trusted_control_sources_sha256"]))
        self.assertEqual(12, len(requests))

    def test_executable_src_tree_requires_independent_r3_even_with_green_ci(self):
        # Makefile calls PYTHONPATH=src python -m ...; src/sitecustomize.py
        # executes before any validator and can mutate validation scripts.
        paths, pages = self.fixture()
        next(e for e in pages[paths["target_tree"]]["tree"]
             if e["path"] == "src")["sha"] = "2" * 40
        with patch.object(admission, "validate_independent_release_review") as review:
            with self.assertRaisesRegex(
                admission.ReleaseAdmissionDenied, "control sources changed.*R3",
            ):
                self.query(pages)
        review.assert_not_called()

    def test_executable_src_change_only_after_bound_independent_r3(self):
        paths, pages = self.fixture()
        next(e for e in pages[paths["target_tree"]]["tree"]
             if e["path"] == "src")["sha"] = "2" * 40
        proof = {
            "review_pr": 1452,
            "review_binding_sha256": "a" * 64,
            "review_attempts_sha256": "b" * 64,
            "independent_pass_count": 1,
            "admissible_slots": ["independent-grok-4.6"],
        }
        with patch.object(
            admission, "validate_independent_release_review", return_value=proof,
        ) as reviewer:
            accepted, _ = self.query(
                pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
            )
        reviewer.assert_called_once_with(
            serving_head=SERVING, target_head=TARGET,
            diff_sha256=DIFF, review_pr=1452,
        )
        self.assertTrue(accepted["workflow"]["ci_policy_transition_required"])

    def test_changed_validation_policy_requires_authentic_full_delta_r3(self):
        paths, pages = self.fixture()
        next(item for item in pages[paths["target_tree"]]["tree"]
             if item["path"] == "tests")["sha"] = "2" * 40
        with patch.object(admission, "validate_independent_release_review") as review:
            with self.assertRaisesRegex(
                admission.ReleaseAdmissionDenied, "policy transition.*R3",
            ):
                self.query(pages)
        review.assert_not_called()

    def test_valid_independent_release_r3_authorizes_exact_policy_transition(self):
        paths, pages = self.fixture()
        next(item for item in pages[paths["target_tree"]]["tree"]
             if item["path"] == "tests")["sha"] = "2" * 40
        proof = {
            "review_pr": 1452,
            "review_binding_sha256": "a" * 64,
            "review_attempts_sha256": "b" * 64,
            "independent_pass_count": 1,
            "admissible_slots": ["independent-grok-4.6"],
        }
        with patch.object(
            admission, "validate_independent_release_review", return_value=proof,
        ) as verified:
            result, requests = self.query(
                pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
            )
        verified.assert_called_once_with(
            serving_head=SERVING, target_head=TARGET,
            diff_sha256=DIFF, review_pr=1452,
        )
        self.assertEqual(2, len(result["checks"]))
        self.assertTrue(result["workflow"]["ci_policy_transition_required"])
        self.assertEqual("a" * 64, result["workflow"]["ci_policy_transition_review_binding_sha256"])
        self.assertIn(paths["target_tree"], requests)

    def test_invalid_independent_review_cannot_authorize_changed_policy(self):
        paths, pages = self.fixture()
        next(item for item in pages[paths["target_tree"]]["tree"]
             if item["path"] == "Makefile")["sha"] = "2" * 40
        with patch.object(
            admission, "validate_independent_release_review",
            side_effect=admission.ReleaseAdmissionDenied(
                "authentic independent release R3 PASS is missing"
            ),
        ) as verified:
            with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "R3 PASS is missing"):
                self.query(
                    pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
                )
        verified.assert_called_once_with(
            serving_head=SERVING, target_head=TARGET,
            diff_sha256=DIFF, review_pr=1452,
        )

    def test_malformed_independent_review_result_cannot_authorize_policy_transition(self):
        for invalid in (None, {}, {"review_binding_sha256": "a" * 64},
                        {"review_binding_sha256": "a" * 64,
                         "review_attempts_sha256": "b" * 64,
                         "independent_pass_count": 0,
                         "admissible_slots": []}):
            with self.subTest(invalid=invalid):
                paths, pages = self.fixture()
                next(item for item in pages[paths["target_tree"]]["tree"]
                     if item["path"] == "Makefile")["sha"] = "2" * 40
                with patch.object(
                    admission, "validate_independent_release_review", return_value=invalid,
                ):
                    with self.assertRaisesRegex(
                        admission.ReleaseAdmissionDenied, "authentic independent.*R3",
                    ):
                        self.query(
                            pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
                        )

    def test_removed_required_target_root_requires_independent_full_r3(self):
        for root in ("tmpfiles", "contracts"):
            with self.subTest(root=root):
                paths, pages = self.fixture()
                pages[paths["target_tree"]]["tree"] = [
                    entry for entry in pages[paths["target_tree"]]["tree"]
                    if entry["path"] != root
                ]
                with patch.object(admission, "validate_independent_release_review") as reviewer:
                    with self.assertRaisesRegex(
                        admission.ReleaseAdmissionDenied, "control sources changed.*R3",
                    ):
                        self.query(pages)
                reviewer.assert_not_called()

    def test_independently_reviewed_target_root_removal_can_transition(self):
        for root in ("tmpfiles", "contracts"):
            with self.subTest(root=root):
                paths, pages = self.fixture()
                pages[paths["target_tree"]]["tree"] = [
                    entry for entry in pages[paths["target_tree"]]["tree"]
                    if entry["path"] != root
                ]
                proof = {
                    "review_pr": 1452,
                    "review_binding_sha256": "a" * 64,
                    "review_attempts_sha256": "b" * 64,
                    "independent_pass_count": 1,
                    "admissible_slots": ["independent-grok-4.6"],
                }
                with patch.object(
                    admission, "validate_independent_release_review", return_value=proof,
                ) as reviewer:
                    result, _ = self.query(
                        pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
                    )
                reviewer.assert_called_once_with(
                    serving_head=SERVING, target_head=TARGET, diff_sha256=DIFF, review_pr=1452,
                )
                self.assertEqual(2, len(result["checks"]))
                self.assertTrue(result["workflow"]["ci_policy_transition_required"])

    def test_missing_serving_root_is_not_approved_as_valid_trust_anchor(self):
        paths, pages = self.fixture()
        pages[paths["serving_tree"]]["tree"] = [
            entry for entry in pages[paths["serving_tree"]]["tree"]
            if entry["path"] != "tools"
        ]
        with patch.object(admission, "validate_independent_release_review") as reviewer:
            with self.assertRaisesRegex(
                admission.ReleaseAdmissionDenied, "trusted Validate control roots are missing",
            ):
                self.query(pages, transition_review_pr=1452, transition_diff_sha256=DIFF)
        reviewer.assert_not_called()

    def test_malformed_policy_tree_never_consults_review_authorizer(self):
        paths, pages = self.fixture()
        pages[paths["target_tree"]]["truncated"] = True
        with patch.object(admission, "validate_independent_release_review") as review:
            with self.assertRaisesRegex(
                admission.ReleaseAdmissionDenied, "inventory is unproved",
            ):
                self.query(
                    pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
                )
        review.assert_not_called()

    def test_independent_review_transition_may_cover_changed_workflow(self):
        paths, pages = self.fixture()
        pages[paths["target_workflow"]]["sha"] = "2" * 40
        proof = {
            "review_pr": 1452,
            "review_binding_sha256": "a" * 64,
            "review_attempts_sha256": "b" * 64,
            "independent_pass_count": 1,
            "admissible_slots": ["independent-grok-4.6"],
        }
        with patch.object(
            admission, "validate_independent_release_review", return_value=proof,
        ) as verified:
            result, _ = self.query(
                pages, transition_review_pr=1452, transition_diff_sha256=DIFF,
            )
        verified.assert_called_once_with(
            serving_head=SERVING, target_head=TARGET, diff_sha256=DIFF, review_pr=1452,
        )
        self.assertTrue(result["workflow"]["ci_policy_transition_required"])
        self.assertEqual("1" * 40, result["workflow"]["trusted_blob_oid"])
        self.assertEqual("2" * 40, result["workflow"]["target_blob_oid"])

    def test_unmodified_validation_controls_never_consume_transition_review(self):
        paths, pages = self.fixture()
        with patch.object(admission, "validate_independent_release_review") as review:
            result, _ = self.query(pages)
        review.assert_not_called()
        self.assertFalse(result["workflow"]["ci_policy_transition_required"])

    def test_new_root_execution_input_cannot_evade_tree_pin(self):
        paths, pages = self.fixture()
        pages[paths["target_tree"]]["tree"].append(
            {"path": "sitecustomize.py", "type": "blob", "mode": "100644", "sha": "2" * 40}
        )
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "trusted Validate"):
            self.query(pages)

    def test_invalid_root_tree_evidence_denied_before_accepting_ci(self):
        for defect in ("truncated", "missing", "duplicate", "wrong_type", "drift"):
            with self.subTest(defect=defect):
                paths, pages = self.fixture()
                tree = pages[paths["target_tree"]]
                if defect == "truncated":
                    tree["truncated"] = True
                elif defect == "missing":
                    tree["tree"] = [entry for entry in tree["tree"] if entry["path"] != "tools"]
                elif defect == "duplicate":
                    tree["tree"].append(tree["tree"][0].copy())
                elif defect == "wrong_type":
                    next(e for e in tree["tree"] if e["path"] == "Makefile")["type"] = "tree"
                else:
                    tree["sha"] = SERVING
                with self.assertRaises(admission.ReleaseAdmissionDenied):
                    self.query(pages)

    def test_mutated_validate_workflow_is_not_admitted_with_green_job_names(self):
        # A target commit may replace validation steps with no-ops while
        # retaining the canonical workflow id and two green job names.
        paths, pages = self.fixture()
        pages[paths["target_workflow"]]["sha"] = "2" * 40
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "workflow.*(changed|mismatch|untrusted)"):
            self.query(pages)

    def test_workflow_blob_missing_or_wrong_path_fails_closed(self):
        for field, value in (("type", "symlink"), ("path", "other.yml"), ("sha", "not-an-oid")):
            with self.subTest(field=field):
                paths, pages = self.fixture()
                pages[paths["target_workflow"]][field] = value
                with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "workflow"):
                    self.query(pages)

    def test_missing_authenticated_github_credential_has_no_network_fallback(self):
        with (patch.object(admission, "_github_token", side_effect=admission.ReleaseAdmissionDenied(
                  "authenticated GitHub credential unavailable"), create=True),
              patch.object(admission.http.client, "HTTPSConnection") as network):
            with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "authenticated GitHub credential"):
                admission._fresh_github_checks(TARGET, serving_head=SERVING)
        network.assert_not_called()

    def test_malformed_credential_is_refused_before_any_network_access(self):
        for token in ("", "bad\nsecret", "bad\rsecret"):
            with (self.subTest(token=repr(token)),
                  patch.object(admission, "_github_token", return_value=token),
                  patch.object(admission.http.client, "HTTPSConnection") as network):
                with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "credential invalid"):
                    admission._fresh_github_checks(TARGET, serving_head=SERVING)
                network.assert_not_called()

    def test_operator_credential_failure_is_redacted(self):
        import types
        fake = types.ModuleType("grabowski_operator")
        fake.TRUSTED_GITHUB_CLI_PATH = Path("/usr/bin/gh")
        def reject(*_args):
            raise RuntimeError("secret must not reach a receipt: secret-fixture")
        fake._github_pr_view_auth_token = reject
        with patch.dict(sys.modules, {"grabowski_operator": fake}):
            with self.assertRaises(admission.ReleaseAdmissionDenied) as raised:
                admission._github_token()
        self.assertNotIn("secret-fixture", str(raised.exception))
        self.assertIn("authenticated GitHub credential", str(raised.exception))

    def test_unexpected_credential_lookup_errors_hide_original_exception(self):
        import subprocess

        fake = types.ModuleType("grabowski_operator")
        fake.TRUSTED_GITHUB_CLI_PATH = Path("/usr/bin/gh")
        failures = (
            subprocess.CalledProcessError(
                2, ["gh", "auth", "token"], output=b"secret-credential-canary"
            ),
            subprocess.TimeoutExpired(
                ["gh", "auth", "token"], 1, output=b"secret-credential-canary"
            ),
            UnicodeError("secret-credential-canary"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                fake._github_pr_view_auth_token = Mock(side_effect=failure)
                with patch.dict(sys.modules, {"grabowski_operator": fake}):
                    with self.assertRaises(admission.ReleaseAdmissionDenied) as raised:
                        admission._github_token()
                self.assertEqual(
                    "authenticated GitHub credential unavailable",
                    str(raised.exception),
                )
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)

    def test_authenticated_network_errors_do_not_expose_bearer_in_exception_chain(self):
        import traceback

        bearer = "secret-credential-canary"
        request_path = f"/repos/{admission.REPOSITORY}/actions/workflows/validate.yml"
        for failure_type in (OSError, admission.http.client.HTTPException, RuntimeError):
            with self.subTest(failure_type=failure_type.__name__):
                connection = Mock()
                connection.request.side_effect = failure_type(
                    "Authorization: Bearer " + bearer
                )
                with patch.object(
                    admission.http.client, "HTTPSConnection", return_value=connection
                ):
                    with self.assertRaises(admission.ReleaseAdmissionDenied) as raised:
                        admission._github_json(request_path, token=bearer)
                self.assertEqual("authoritative CI lookup failed", str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)
                self.assertNotIn(
                    bearer, "".join(traceback.format_exception(raised.exception))
                )
                connection.close.assert_called_once_with()

    def test_authenticated_connection_close_errors_fail_closed_and_redacted(self):
        import traceback

        bearer = "secret-credential-canary"
        connection = Mock()
        response = Mock()
        response.status = 200
        response.getheader.return_value = ""
        response.read.return_value = b"{}"
        connection.getresponse.return_value = response
        connection.close.side_effect = RuntimeError(
            "Authorization: Bearer " + bearer
        )
        with patch.object(
            admission.http.client, "HTTPSConnection", return_value=connection
        ):
            with self.assertRaises(admission.ReleaseAdmissionDenied) as raised:
                admission._github_json(
                    f"/repos/{admission.REPOSITORY}/actions/workflows/validate.yml",
                    token=bearer,
                )
        self.assertEqual("authoritative CI lookup failed", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(bearer, "".join(traceback.format_exception(raised.exception)))
        connection.close.assert_called_once_with()

    def test_non_ascii_credential_is_denied_before_any_network_access(self):
        for token in ("secret-\u2603", "secret-\u00e9", "secret-\u00a0"):
            with self.subTest(token=ascii(token)):
                with patch.object(admission.http.client, "HTTPSConnection") as network:
                    with self.assertRaises(admission.ReleaseAdmissionDenied) as raised:
                        admission._github_json(
                            f"/repos/{admission.REPOSITORY}/actions/workflows/validate.yml",
                            token=token,
                        )
                self.assertEqual(
                    "authenticated GitHub credential invalid",
                    str(raised.exception),
                )
                network.assert_not_called()

    def test_newer_green_foreign_workflow_cannot_override_failed_canonical(self):
        paths, pages = self.fixture()
        pages[paths["run"]]["conclusion"] = "failure"
        pages[paths["runs"]]["workflow_runs"][0]["conclusion"] = "failure"
        pages[paths["checks"]]["check_runs"].extend([
            {**_ci_result(name, i), "check_suite": {"id": 9999}}
            for i, name in enumerate(admission.REQUIRED_CI_CHECKS, start=9900)
        ])
        pages[paths["checks"]]["total_count"] = 4
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "canonical Validate run.*green"):
            self.query(pages)

    def test_same_name_foreign_actions_check_cannot_fill_missing_canonical_job(self):
        paths, pages = self.fixture()
        pages[paths["jobs"]]["jobs"].pop(0)
        pages[paths["jobs"]]["total_count"] = 1
        pages[paths["checks"]]["check_runs"].append({
            **_ci_result(admission.REQUIRED_CI_CHECKS[0], 1100),
            "check_suite": {"id": 9999},
        })
        pages[paths["checks"]]["total_count"] = 3
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "canonical Validate jobs are missing"):
            self.query(pages)

    def test_other_workflow_path_cannot_claim_validate_identity(self):
        paths, pages = self.fixture()
        pages[paths["workflow"]]["path"] = ".github/workflows/fake-validate.yml"
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "workflow identity"):
            self.query(pages)

    def test_run_from_wrong_workflow_path_blocks(self):
        paths, pages = self.fixture()
        pages[paths["runs"]]["workflow_runs"][0]["path"] = ".github/workflows/other.yml"
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "run origin"):
            self.query(pages)

    def test_only_push_event_is_admissible(self):
        paths, pages = self.fixture()
        pages[paths["runs"]]["workflow_runs"][0]["event"] = "pull_request"
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "push run is missing"):
            self.query(pages)

    def test_other_branch_or_repository_same_sha_cannot_count_as_main_push(self):
        for key, value in (
            ("head_branch", "integration"),
            ("repository", {"full_name": "attacker/fork"}),
            ("head_repository", {"full_name": "attacker/fork"}),
        ):
            with self.subTest(key):
                paths, pages = self.fixture()
                pages[paths["runs"]]["workflow_runs"][0][key] = value
                with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "push run is missing"):
                    self.query(pages)

    def test_foreign_branch_newer_run_cannot_hide_canonical_main(self):
        paths, pages = self.fixture()
        foreign = dict(pages[paths["runs"]]["workflow_runs"][0])
        foreign["id"] = 900
        foreign["run_number"] = 43
        foreign["head_branch"] = "dev"
        pages[paths["runs"]]["workflow_runs"].append(foreign)
        pages[paths["runs"]]["total_count"] = 2
        result, _ = self.query(pages)
        self.assertEqual(800, result["workflow"]["run_id"])
        self.assertEqual("main", result["workflow"]["head_branch"])

    def test_run_detail_main_branch_drift_blocks(self):
        paths, pages = self.fixture()
        pages[paths["run"]]["head_branch"] = "other"
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "not authenticated green"):
            self.query(pages)

    def test_wrong_commit_and_check_suite_fail_closed(self):
        for modified, value, fragment in [
            ("head_sha", SERVING, "provenance"),
            ("check_suite", {"id": 7777}, "provenance"),
            ("app", {"slug": "third-party"}, "provenance"),
            ("check_run_url", "https://api.github.com/other", "provenance"),
        ]:
            with self.subTest(modified):
                paths, pages = self.fixture()
                if modified == "check_run_url":
                    pages[paths["jobs"]]["jobs"][0][modified] = value
                else:
                    pages[paths["checks"]]["check_runs"][0][modified] = value
                with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, fragment):
                    self.query(pages)

    def test_latest_canonical_job_failure_is_not_overridden_by_old_green(self):
        paths, pages = self.fixture()
        pages[paths["jobs"]]["jobs"][0]["conclusion"] = "failure"
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "not green"):
            self.query(pages)

    @staticmethod
    def two_page_jobs(paths, pages):
        # Two required jobs plus exactly enough irrelevant jobs to force page 2.
        jobs = pages[paths["jobs"]]["jobs"]
        jobs.extend({"id": i + 500, "name": "irrelevant"} for i in
                    range(admission.GITHUB_PAGE_SIZE - 1))
        page_size = admission.GITHUB_PAGE_SIZE
        pages[paths["jobs"]]["total_count"] = len(jobs)
        pages[paths["jobs"]]["jobs"] = jobs[:page_size]
        next_path = paths["jobs"].replace("&page=1", "&page=2")
        pages[next_path] = {
            "total_count": len(jobs), "jobs": jobs[page_size:],
        }
        return next_path

    def test_incomplete_inventory_and_missing_pagination_are_blocked(self):
        paths, pages = self.fixture()
        pages[paths["jobs"]]["total_count"] = admission.GITHUB_PAGE_SIZE + 1
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "pagination incomplete"):
            self.query(pages)
        paths, pages = self.fixture()
        self.two_page_jobs(paths, pages)
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "pagination link mismatch"):
            self.query(pages)

    def test_legitimate_second_page_is_checked_not_silently_ignored(self):
        paths, pages = self.fixture()
        second = self.two_page_jobs(paths, pages)
        link = f'<https://{admission.GITHUB_HOST}{second}>; rel="next"'
        result, requests = self.query(pages, links={paths["jobs"]: link})
        self.assertEqual(2, len(result["checks"]))
        self.assertIn(second, requests)

    def test_replayed_page_id_and_cross_origin_link_fail_closed(self):
        paths, pages = self.fixture()
        second = self.two_page_jobs(paths, pages)
        pages[second]["jobs"] = [pages[paths["jobs"]]["jobs"][0]]
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "destination"):
            self.query(pages, links={paths["jobs"]:
                f'<https://evil.invalid{second}>; rel="next"'})
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "duplicate"):
            self.query(pages, links={paths["jobs"]:
                f'<https://{admission.GITHUB_HOST}{second}>; rel="next"'})

    def test_later_legitimate_rerun_can_supersede_failed_previous_attempt(self):
        paths, pages = self.fixture()
        pages[paths["run"]]["run_attempt"] = 2
        pages[paths["runs"]]["workflow_runs"][0]["run_attempt"] = 2
        for job in pages[paths["jobs"]]["jobs"]:
            job["run_attempt"] = 2
        old = {
            **pages[paths["jobs"]]["jobs"][0],
            "id": 99, "run_attempt": 1, "conclusion": "failure",
            "check_run_url": f"https://{admission.GITHUB_HOST}/repos/{admission.REPOSITORY}/check-runs/99",
        }
        pages[paths["jobs"]]["jobs"].append(old)
        pages[paths["jobs"]]["total_count"] = 3
        pages[paths["checks"]]["check_runs"].append({
            **_ci_result(old["name"], old["id"], conclusion="failure"),
            "check_suite": {"id": 900},
        })
        pages[paths["checks"]]["total_count"] = 3
        result, _ = self.query(pages)
        self.assertEqual(2, result["workflow"]["run_attempt"])
        self.assertEqual(101, result["checks"][0]["id"])

    def test_http_failure_blocks(self):
        paths, pages = self.fixture()
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "HTTP 403"):
            self.query(pages, http_codes={paths["workflow"]: 403})



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
                git_output(""), git_output(":100644 100644 " + "a"*40 + " " + "b"*40 + " M\x00src/grabowski_self_deploy.py\x00")
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
        # A completed independent R3/CI review alone is not an accepted
        # Captain dispatch. The old expectation minted a critical source
        # release scope directly from this caller-provided review record.
        with patch.object(deploy, "_require_release_source_admission", return_value=record):
            with self.assertRaisesRegex(RuntimeError, "accepted Captain action"):
                with deploy._captain_release_scope(TARGET, 1452):
                    self.fail("R3-only data cannot authorize a release scope")
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
                git_output(""), git_output(raw_symlink),
            ]),
        ):
            with self.assertRaisesRegex(RuntimeError, "raw modes|modes are not plain documents"):
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
                    with self.assertRaisesRegex(RuntimeError, "raw modes|documentation Git mode"):
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