from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_operator_obligation as obligations
import grabowski_operator_obligation_evidence as evidence


class OperatorObligationEvidenceTests(unittest.TestCase):
    @staticmethod
    def _stored_evidence(
        *,
        acceptance_id: str = "runtime",
        source: str = "runtime",
        reference: str = "runtime:revision-a",
        sha256: str = "a" * 64,
        status: str = "passed",
    ) -> dict[str, str]:
        return {
            "acceptance_id": acceptance_id,
            "status": status,
            "source": source,
            "reference": reference,
            "sha256": sha256,
        }

    @staticmethod
    def _status(
        *,
        state: str = "completed",
        close_schema_version: int | None = obligations.CLOSE_SCHEMA_VERSION,
        acceptance_ids: list[str] | None = None,
        stored_evidence: list[dict[str, str]] | None = None,
    ) -> dict[str, object]:
        acceptance = acceptance_ids or ["runtime"]
        items = stored_evidence if stored_evidence is not None else [
            OperatorObligationEvidenceTests._stored_evidence()
        ]
        evidenced = {item["acceptance_id"] for item in items}
        return {
            "obligation_id": "goo-shadow-evidence-test-0001",
            "state": state,
            "close_schema_version": close_schema_version,
            "open_file_sha256": "e" * 64,
            "close_file_sha256": None if state == "open" else "f" * 64,
            "acceptance_ids": acceptance,
            "evidence": items,
            "missing_acceptance_ids": [
                acceptance_id
                for acceptance_id in acceptance
                if acceptance_id not in evidenced
            ],
        }

    @staticmethod
    def _observation(
        *,
        acceptance_id: str = "runtime",
        source: str = "runtime",
        reference: str = "runtime:revision-a",
        sha256: str = "a" * 64,
        status: str = "verified",
    ) -> dict[str, object]:
        return {
            "schema_version": evidence.SCHEMA_VERSION,
            "kind": evidence.OBSERVATION_KIND,
            "acceptance_id": acceptance_id,
            "source": source,
            "reference": reference,
            "sha256": sha256,
            "status": status,
        }

    @staticmethod
    def _github_v2_workflow_check(
        *,
        database_id: int,
        name: str,
        started_at: str,
        conclusion: str = "SUCCESS",
        workflow_id: int = 320669873,
        workflow_name: str = "Codex review settlement",
        workflow_run_id: int = 32860034363,
        event: str = "pull_request_review",
        run_number: int = 5693,
        run_attempt: int = 1,
    ) -> dict[str, object]:
        return {
            "__typename": "CheckRun",
            "databaseId": database_id,
            "name": name,
            "startedAt": started_at,
            "status": "COMPLETED",
            "conclusion": conclusion,
            "checkSuite": {
                "databaseId": database_id + 100000,
                "app": {"id": "MDM6QXBwMTUzNjg=", "slug": "github-actions"},
                "workflowRun": {
                    "databaseId": workflow_run_id,
                    "event": event,
                    "runNumber": run_number,
                    "runAttempt": run_attempt,
                    "workflow": {
                        "databaseId": workflow_id,
                        "name": workflow_name,
                    },
                },
            },
        }

    @staticmethod
    def _github_v2_external_check(
        *,
        database_id: int,
        name: str,
        started_at: str,
        conclusion: str = "SUCCESS",
    ) -> dict[str, object]:
        return {
            "__typename": "CheckRun",
            "databaseId": database_id,
            "name": name,
            "startedAt": started_at,
            "status": "COMPLETED",
            "conclusion": conclusion,
            "checkSuite": {
                "databaseId": database_id + 100000,
                "app": {"id": "MDM6QXBwNTc3ODk=", "slug": "github-advanced-security"},
                "workflowRun": None,
            },
        }

    @staticmethod
    def _github_v2_status_context(
        *,
        node_id: str = "SC_test",
        context: str = "Codex review settled",
        created_at: str = "2026-08-25T14:31:40Z",
        state: str = "SUCCESS",
    ) -> dict[str, object]:
        return {
            "__typename": "StatusContext",
            "id": node_id,
            "context": context,
            "createdAt": created_at,
            "state": state,
            "creator": {"login": "github-actions"},
        }

    @staticmethod
    def _github_v2_payload(
        *,
        head: str,
        base: str,
        merge: str,
        checks: list[dict[str, object]],
        has_next_page: bool = False,
        head_ref: str = "feature/test",
        base_ref: str = "main",
        merge_checks: list[dict[str, object]] | None = None,
        merge_has_next_page: bool = False,
    ) -> dict[str, object]:
        merge_commit: dict[str, object] = {"oid": merge}
        if merge_checks is not None:
            merge_commit["statusCheckRollup"] = {
                "contexts": {
                    "totalCount": len(merge_checks),
                    "pageInfo": {"hasNextPage": merge_has_next_page},
                    "nodes": merge_checks,
                }
            }
        return {
            "data": {
                "repository": {
                    "pullRequest": {
                        "state": "MERGED",
                        "isDraft": False,
                        "baseRefOid": base,
                        "baseRefName": base_ref,
                        "headRefOid": head,
                        "headRefName": head_ref,
                        "mergeCommit": merge_commit,
                        "commits": {
                            "nodes": [
                                {
                                    "commit": {
                                        "oid": head,
                                        "statusCheckRollup": {
                                            "contexts": {
                                                "totalCount": len(checks),
                                                "pageInfo": {
                                                    "hasNextPage": has_next_page
                                                },
                                                "nodes": checks,
                                            }
                                        },
                                    }
                                }
                            ]
                        },
                    }
                }
            }
        }

    @staticmethod
    def _github_v2_command_side_effect(
        payload: dict[str, object],
        *,
        pr: int,
        run_pr_overrides: dict[int, int] | None = None,
        run_head_sha_overrides: dict[int, str] | None = None,
        run_pull_requests_empty: set[int] | None = None,
        run_head_branch_overrides: dict[int, str] | None = None,
    ):
        repository = payload["data"]["repository"]
        pull_request = repository["pullRequest"]
        head = pull_request["headRefOid"]
        head_ref = pull_request["headRefName"]
        base = pull_request["baseRefOid"]
        base_ref = pull_request["baseRefName"]
        merge = pull_request["mergeCommit"]["oid"]
        checks = list(
            pull_request["commits"]["nodes"][0]["commit"]["statusCheckRollup"]["contexts"]["nodes"]
        )
        merge_commit = pull_request.get("mergeCommit")
        merge_rollup = merge_commit.get("statusCheckRollup") if isinstance(merge_commit, dict) else None
        merge_contexts = merge_rollup.get("contexts") if isinstance(merge_rollup, dict) else None
        merge_nodes = merge_contexts.get("nodes") if isinstance(merge_contexts, dict) else None
        if isinstance(merge_nodes, list):
            checks.extend(merge_nodes)
        workflow_events: dict[int, str] = {}
        for check in checks:
            if not isinstance(check, dict):
                continue
            suite = check.get("checkSuite")
            workflow_run = suite.get("workflowRun") if isinstance(suite, dict) else None
            if not isinstance(workflow_run, dict):
                continue
            run_id = workflow_run.get("databaseId")
            event = workflow_run.get("event")
            if isinstance(run_id, int) and not isinstance(run_id, bool) and isinstance(event, str):
                workflow_events[run_id] = event
        encoded_graphql = json.dumps(payload).encode("utf-8")
        pr_overrides = run_pr_overrides or {}
        sha_overrides = run_head_sha_overrides or {}
        empty_pull_runs = run_pull_requests_empty or set()
        branch_overrides = run_head_branch_overrides or {}

        def run(argv, **_kwargs):
            if argv[:3] == ["gh", "api", "graphql"]:
                return 0, encoded_graphql, b""
            endpoint = next(
                (
                    part
                    for part in argv
                    if isinstance(part, str)
                    and part.startswith("repos/")
                    and part.endswith("/actions/runs")
                ),
                None,
            )
            if argv[:2] == ["gh", "api"] and endpoint is not None:
                queried_head_sha = next(
                    (
                        part.split("=", 1)[1]
                        for part in argv
                        if isinstance(part, str) and part.startswith("head_sha=")
                    ),
                    None,
                )
                repo_slug = endpoint[len("repos/") : -len("/actions/runs")]
                run_payloads: list[dict[str, object]] = []
                for run_id, event in workflow_events.items():
                    default_run_head = merge if event == "merge_group" else head
                    run_head_sha = sha_overrides.get(run_id, default_run_head)
                    if queried_head_sha != run_head_sha:
                        continue
                    bound_pr = pr_overrides.get(run_id, pr)
                    if event == "merge_group":
                        default_branch = f"gh-readonly-queue/{base_ref}/pr-{bound_pr}-{base}"
                    else:
                        default_branch = head_ref if bound_pr == pr else f"feature/pr-{bound_pr}"
                    bound_head_ref = branch_overrides.get(run_id, default_branch)
                    pull_requests: list[dict[str, object]] = []
                    if run_id not in empty_pull_runs and event != "merge_group":
                        pull_requests = [
                            {
                                "number": bound_pr,
                                "head": {
                                    "ref": head_ref if bound_pr == pr else f"feature/pr-{bound_pr}",
                                    "sha": head,
                                },
                                "base": {"ref": base_ref, "sha": base},
                            }
                        ]
                    run_payloads.append(
                        {
                            "id": run_id,
                            "event": event,
                            "head_sha": run_head_sha,
                            "head_branch": bound_head_ref,
                            "repository": {"full_name": repo_slug},
                            "pull_requests": pull_requests,
                        }
                    )
                encoded_runs = b"\n".join(
                    json.dumps(item).encode("utf-8") for item in run_payloads
                )
                if encoded_runs:
                    encoded_runs += b"\n"
                return 0, encoded_runs, b""
            return 1, b"", b"unexpected command"

        return run

    def test_fake_hash_is_not_verified(self) -> None:
        result = evidence.assess_status(self._status())

        self.assertEqual("unverified", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])
        self.assertTrue(result["declared_hash_bound_completion"])
        self.assertTrue(result["false_confidence_risk"])

    def test_assessment_digest_binds_exact_obligation_records(self) -> None:
        status = self._status()
        first = evidence.assess_status(status)
        rebound = dict(status)
        rebound["open_file_sha256"] = "d" * 64
        second = evidence.assess_status(rebound)

        self.assertEqual(
            {
                "open_file_sha256": "e" * 64,
                "close_file_sha256": "f" * 64,
            },
            first["record_binding"],
        )
        self.assertNotEqual(first["assessment_sha256"], second["assessment_sha256"])

    def test_missing_evidence_is_classified_per_acceptance(self) -> None:
        result = evidence.assess_status(
            self._status(
                state="open",
                close_schema_version=None,
                stored_evidence=[],
            )
        )

        self.assertEqual(["runtime"], result["missing_acceptance_ids"])
        self.assertEqual("missing", result["acceptance"][0]["classification"])
        self.assertEqual(1, result["classifications"]["missing"])

    def test_wrong_revision_reference_is_mismatch(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={
                "runtime": self._observation(reference="runtime:revision-b")
            },
        )

        self.assertEqual("mismatch", result["acceptance"][0]["classification"])
        self.assertEqual(
            "observation_identity_mismatch", result["acceptance"][0]["reason"]
        )

    def test_stale_trusted_observation_is_stale(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={"runtime": self._observation(status="stale")},
        )

        self.assertEqual("stale", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])

    def test_only_typed_matching_observation_can_verify(self) -> None:
        result = evidence.assess_status(
            self._status(),
            observations={"runtime": self._observation()},
        )

        self.assertEqual("verified", result["acceptance"][0]["classification"])
        self.assertTrue(result["fully_verified"])
        self.assertFalse(result["false_confidence_risk"])

        malformed = self._observation()
        malformed["kind"] = "caller.assertion"
        with self.assertRaisesRegex(evidence.EvidenceAssessmentError, "kind is invalid"):
            evidence.assess_status(
                self._status(), observations={"runtime": malformed}
            )

    def test_legacy_hash_bound_close_is_not_retroactively_verified(self) -> None:
        result = evidence.assess_status(
            self._status(close_schema_version=obligations.LEGACY_CLOSE_SCHEMA_VERSION)
        )

        self.assertTrue(result["legacy_close"])
        self.assertEqual(
            "legacy_unverifiable", result["acceptance"][0]["classification"]
        )
        self.assertFalse(result["fully_verified"])
        self.assertTrue(result["false_confidence_risk"])

    def test_legacy_matching_observation_stays_unverifiable(self) -> None:
        result = evidence.assess_status(
            self._status(close_schema_version=obligations.LEGACY_CLOSE_SCHEMA_VERSION),
            observations={"runtime": self._observation()},
        )

        self.assertEqual("legacy_unverifiable", result["acceptance"][0]["classification"])
        self.assertEqual("legacy_close_not_reverified", result["acceptance"][0]["reason"])
        self.assertFalse(result["fully_verified"])

    def test_human_assertion_is_unsupported_for_machine_verification(self) -> None:
        result = evidence.assess_status(
            self._status(
                stored_evidence=[self._stored_evidence(source="user")]
            )
        )

        self.assertEqual("unsupported", result["acceptance"][0]["classification"])
        self.assertFalse(result["fully_verified"])

    def test_free_form_reference_never_self_attests(self) -> None:
        status = self._status(
            stored_evidence=[
                self._stored_evidence(
                    source="github",
                    reference="PR #1 looked green when I checked it",
                )
            ]
        )
        observations = evidence.collect_trusted_observations(status)

        self.assertEqual({}, observations)
        result = evidence.assess_status(status, observations=observations)
        self.assertEqual("unverified", result["acceptance"][0]["classification"])

    def test_github_adapter_binds_exact_merged_pr_and_check_count(self) -> None:
        parsed = {
            "repo": "heimgewebe/grabowski",
            "pr": 919,
            "head": "1" * 40,
            "base": "2" * 40,
            "merge": "3" * 40,
            "passed": 2,
            "total": 2,
        }
        reference = (
            "github-pr:heimgewebe/grabowski#919@"
            + parsed["head"]
            + ":base="
            + parsed["base"]
            + ":merge="
            + parsed["merge"]
            + ":checks=2/2-success"
        )
        digest = evidence._sha256(evidence._github_observation_material(parsed))
        payload = {
            "state": "MERGED",
            "isDraft": False,
            "baseRefOid": parsed["base"],
            "headRefOid": parsed["head"],
            "mergeCommit": {"oid": parsed["merge"]},
            "statusCheckRollup": [
                {
                    "__typename": "CheckRun",
                    "status": "COMPLETED",
                    "conclusion": "SUCCESS",
                },
                {"__typename": "StatusContext", "state": "SUCCESS"},
            ],
        }
        stored = self._stored_evidence(
            source="github", reference=reference, sha256=digest
        )
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            observation = evidence._github_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(digest, observation["sha256"])

        payload["headRefOid"] = "4" * 40
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            mismatch = evidence._github_observation(stored)
        assert mismatch is not None
        self.assertEqual("mismatch", mismatch["status"])

    def test_git_adapter_hashes_exact_commit_payload(self) -> None:
        commit_payload = b"tree " + b"a" * 40 + b"\n\nmessage\n"
        digest = hashlib.sha256(commit_payload).hexdigest()
        stored = self._stored_evidence(
            source="git",
            reference="git-commit:heimgewebe/grabowski@" + "b" * 40,
            sha256=digest,
        )
        with patch.object(evidence, "_local_git_repo", return_value=Path("/tmp/repo")), patch.object(
            evidence, "_run_command", return_value=(0, commit_payload, b"")
        ):
            observation = evidence._git_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(digest, observation["sha256"])

    def test_receipt_adapter_requires_successful_worktree_receipt_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"GRABOWSKI_EVIDENCE_RECEIPT_ROOT": tmp}
        ):
            key = "b" * 64
            root = Path(tmp)
            path = root / "grip-receipts" / "worktree-ensure" / f"{key}.json"
            path.parent.mkdir(parents=True, mode=0o700)
            payload = {
                "schema_version": 1,
                "kind": "grabowski.worktree_ensure_receipt",
                "state": "complete",
                "error": "",
                "result_state": "CREATED",
                "idempotency_key_sha256": key,
                "receipt_sha256": "1" * 64,
            }
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            path.write_bytes(raw)
            path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            stored = self._stored_evidence(
                source="receipt",
                reference=f"grabowski-receipt:grip-receipts/worktree-ensure/{key}.json",
                sha256=digest,
            )
            observation = evidence._receipt_observation(stored)
            assert observation is not None
            self.assertEqual("verified", observation["status"])
            self.assertEqual(digest, observation["sha256"])

            payload["error"] = "capacity saturated"
            payload["result_state"] = "NOT_ACCEPTED"
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            path.write_bytes(raw)
            path.chmod(0o600)
            stored["sha256"] = hashlib.sha256(raw).hexdigest()
            failed = evidence._receipt_observation(stored)
            assert failed is not None
            self.assertEqual("mismatch", failed["status"])

            payload["error"] = {"unexpected": "shape"}
            payload["result_state"] = ["CREATED"]
            raw = json.dumps(payload, sort_keys=True).encode("utf-8")
            path.write_bytes(raw)
            path.chmod(0o600)
            stored["sha256"] = hashlib.sha256(raw).hexdigest()
            malformed = evidence._receipt_observation(stored)
            assert malformed is not None
            self.assertEqual("mismatch", malformed["status"])

    def test_receipt_adapter_refuses_unknown_receipt_classes(self) -> None:
        stored = self._stored_evidence(
            source="receipt",
            reference="grabowski-receipt:jobs/example/finalization.json",
        )
        self.assertIsNone(evidence._receipt_observation(stored))

    def test_receipt_adapter_refuses_non_durable_generic_grip_receipt(self) -> None:
        stored = self._stored_evidence(
            source="receipt",
            reference=(
                "grip:operator-obligation-evidence-assess:sample:"
                + "1" * 64
                + ":receipt:"
                + "2" * 64
            ),
        )
        self.assertIsNone(evidence._receipt_observation(stored))

    def test_bureau_adapter_binds_idempotency_selected_candidate(self) -> None:
        candidate_id = "candidate-" + "6" * 24
        event_id = 11086
        idempotency_key = "operator-obligation:trusted-adapters:postdeploy-sample-gap-20260824"
        fingerprint = "7" * 64
        stored = self._stored_evidence(
            source="bureau",
            reference=(
                f"bureau-candidate:{candidate_id}:event={event_id}:"
                f"idempotency={idempotency_key}"
            ),
            sha256=fingerprint,
        )
        invoke = unittest.mock.Mock(
            return_value={
                "status": "assessed",
                "candidate_id": candidate_id,
                "event_id": event_id,
                "content_fingerprint": fingerprint,
            }
        )
        module = types.ModuleType("grabowski_bureau_intake")
        module._invoke_bureau = invoke
        with patch.dict(sys.modules, {"grabowski_bureau_intake": module}):
            observation = evidence._bureau_observation(
                stored, deadline_monotonic=evidence.time.monotonic() + 5.0
            )
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(fingerprint, observation["sha256"])
        arguments = invoke.call_args.args[0]
        self.assertEqual("operator-candidate-assess", arguments[2])
        self.assertEqual(idempotency_key, arguments[-1])
        self.assertLessEqual(invoke.call_args.kwargs["timeout_seconds"], 5)

        invoke.return_value = {
            "status": "assessed",
            "candidate_id": candidate_id,
            "event_id": event_id + 1,
            "content_fingerprint": fingerprint,
        }
        with patch.dict(sys.modules, {"grabowski_bureau_intake": module}):
            mismatch = evidence._bureau_observation(stored)
        assert mismatch is not None
        self.assertEqual("mismatch", mismatch["status"])

    def test_bureau_adapter_treats_runtime_failure_as_stale(self) -> None:
        stored = self._stored_evidence(
            source="bureau",
            reference=(
                "bureau-candidate:candidate-" + "8" * 24
                + ":event=42:idempotency=operator-obligation:test"
            ),
        )
        module = types.ModuleType("grabowski_bureau_intake")
        module._invoke_bureau = unittest.mock.Mock(
            return_value={"kind": "grabowski_bureau_intake_adapter_failure"}
        )
        with patch.dict(sys.modules, {"grabowski_bureau_intake": module}):
            observation = evidence._bureau_observation(stored)
        assert observation is not None
        self.assertEqual("stale", observation["status"])

    def test_bureau_adapter_does_not_start_when_shared_deadline_is_under_one_second(self) -> None:
        stored = self._stored_evidence(
            source="bureau",
            reference=(
                "bureau-candidate:candidate-" + "9" * 24
                + ":event=43:idempotency=operator-obligation:deadline-test"
            ),
        )
        module = types.ModuleType("grabowski_bureau_intake")
        module._invoke_bureau = unittest.mock.Mock()
        with patch.dict(sys.modules, {"grabowski_bureau_intake": module}), patch.object(
            evidence.time, "monotonic", return_value=100.25
        ):
            observation = evidence._bureau_observation(
                stored, deadline_monotonic=101.0
            )
        assert observation is not None
        self.assertEqual("stale", observation["status"])
        module._invoke_bureau.assert_not_called()

    def test_runtime_adapter_binds_exact_active_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_EVIDENCE_DEPLOYMENT_MANIFEST": str(Path(tmp) / "manifest.json")},
        ):
            runtime_input = "7" * 64
            repo_head = "8" * 40
            release_id = "release-verified-1234567890"
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "completion_status": "complete",
                        "repo_head": repo_head,
                        "release_id": release_id,
                        "runtime_input_sha256": runtime_input,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            stored = self._stored_evidence(
                source="runtime",
                reference=(
                    f"grabowski-runtime-manifest:repo_head={repo_head};"
                    f"release_id={release_id};runtime_input_sha256={runtime_input}"
                ),
                sha256=runtime_input,
            )
            observation = evidence._runtime_observation(stored)

        self.assertIsNotNone(observation)
        assert observation is not None
        self.assertEqual("verified", observation["status"])
        self.assertEqual(runtime_input, observation["sha256"])

    def test_runtime_adapter_verifies_immutable_historical_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_EVIDENCE_RELEASES_ROOT": tmp},
        ):
            runtime_input = "9" * 64
            repo_head = "a" * 40
            release_id = "historical-release-1234567890"
            release = Path(tmp) / release_id
            release.mkdir(mode=0o700)
            manifest = release / "deployment-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "completion_status": "complete",
                        "repo_head": repo_head,
                        "release_id": release_id,
                        "runtime_input_sha256": runtime_input,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            stored = self._stored_evidence(
                source="runtime",
                reference=(
                    f"grabowski-runtime-manifest:repo_head={repo_head};"
                    f"release_id={release_id};runtime_input_sha256={runtime_input}"
                ),
                sha256=runtime_input,
            )
            observation = evidence._runtime_observation(stored)
            assert observation is not None
            self.assertEqual("verified", observation["status"])
            self.assertEqual(runtime_input, observation["sha256"])

            manifest.unlink()
            stale = evidence._runtime_observation(stored)
            assert stale is not None
            self.assertEqual("stale", stale["status"])

    def test_pytest_summary_accepts_non_failing_extra_outcomes(self) -> None:
        self.assertEqual(
            {(53, 0)},
            evidence._pytest_summary_counts(
                b"53 passed, 2 skipped, 1 warning in 0.20s\n"
            ),
        )
        self.assertEqual(
            {(53, 19)},
            evidence._pytest_summary_counts(
                b"53 passed, 19 subtests passed, 2 skipped, 1 xfailed in 0.20s\n"
            ),
        )
        self.assertEqual(set(), evidence._pytest_summary_counts(b"52 passed, 1 failed in 0.20s\n"))

    def test_legacy_collection_skips_all_adapter_io(self) -> None:
        status = {
            "close_schema_version": obligations.LEGACY_CLOSE_SCHEMA_VERSION,
            "evidence": [self._stored_evidence(source="github")],
        }
        adapter = unittest.mock.Mock()
        with patch.dict(evidence._SOURCE_ADAPTERS, {"github": adapter}):
            self.assertEqual({}, evidence.collect_trusted_observations(status))
        adapter.assert_not_called()

    def test_collection_stops_at_shared_deadline(self) -> None:
        status = {
            "close_schema_version": obligations.CLOSE_SCHEMA_VERSION,
            "evidence": [
                self._stored_evidence(acceptance_id="one", source="github"),
                self._stored_evidence(acceptance_id="two", source="github"),
            ],
        }
        adapter = unittest.mock.Mock(return_value=None)
        with patch.dict(evidence._SOURCE_ADAPTERS, {"github": adapter}), patch.object(
            evidence.time, "monotonic", side_effect=[0.0, 11.0]
        ):
            observations = evidence.collect_trusted_observations(
                status, deadline_monotonic=10.0
            )
        self.assertEqual({}, observations)
        self.assertEqual(1, adapter.call_count)

    def test_test_adapter_binds_terminal_task_receipt_and_exact_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "GRABOWSKI_EVIDENCE_TASK_DATABASE": str(Path(tmp) / "tasks.sqlite3"),
                "GRABOWSKI_EVIDENCE_TASK_OUTPUT_ROOT": str(Path(tmp) / "task-output"),
            },
        ):
            task_id = "a" * 24
            lifecycle_receipt = "9" * 64
            connection = sqlite3.connect(Path(tmp) / "tasks.sqlite3")
            try:
                connection.execute(
                    "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, attempt INTEGER, state TEXT, lifecycle_receipt_sha256 TEXT, argv_json TEXT)"
                )
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?, ?, ?)",
                    (task_id, 1, "completed", lifecycle_receipt, json.dumps(["pytest", "-q"])),
                )
                connection.commit()
            finally:
                connection.close()
            output = (
                Path(tmp)
                / "task-output"
                / f".grabowski-task-output-{task_id}-a1"
            )
            output.mkdir(parents=True, mode=0o700)
            (output / "stdout.log").write_text(
                "..................................................... [100%]\n"
                "53 passed, 19 subtests passed in 0.20s\n",
                encoding="utf-8",
            )
            (output / "stdout.log").chmod(0o600)
            stored = self._stored_evidence(
                source="test",
                reference=f"grabowski-task:{task_id}:53-passed+19-subtests",
                sha256=lifecycle_receipt,
            )
            observation = evidence._test_observation(stored)

            self.assertIsNotNone(observation)
            assert observation is not None
            self.assertEqual("verified", observation["status"])
            self.assertNotEqual(lifecycle_receipt, observation["sha256"])
            self.assertEqual(
                "mismatch",
                evidence.assess_evidence_item(stored, observation=observation)["classification"],
            )
            stored["sha256"] = observation["sha256"]
            self.assertEqual(
                "verified",
                evidence.assess_evidence_item(stored, observation=observation)["classification"],
            )

            stored["reference"] = f"grabowski-task:{task_id}:54-passed+19-subtests"
            mismatch = evidence._test_observation(stored)
            assert mismatch is not None
            self.assertEqual("mismatch", mismatch["status"])

            connection = sqlite3.connect(Path(tmp) / "tasks.sqlite3")
            try:
                connection.execute(
                    "UPDATE tasks SET argv_json = ? WHERE task_id = ?",
                    (json.dumps(["python3", "-c", "print('53 passed, 19 subtests passed')"]), task_id),
                )
                connection.commit()
            finally:
                connection.close()
            stored["reference"] = f"grabowski-task:{task_id}:53-passed+19-subtests"
            spoofed = evidence._test_observation(stored)
            assert spoofed is not None
            self.assertEqual("mismatch", spoofed["status"])

    def test_unittest_task_summary_is_supported_when_argv_is_test_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "GRABOWSKI_EVIDENCE_TASK_DATABASE": str(Path(tmp) / "tasks.sqlite3"),
                "GRABOWSKI_EVIDENCE_TASK_OUTPUT_ROOT": str(Path(tmp) / "task-output"),
            },
        ):
            task_id = "c" * 24
            receipt = "d" * 64
            connection = sqlite3.connect(Path(tmp) / "tasks.sqlite3")
            try:
                connection.execute(
                    "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, attempt INTEGER, state TEXT, lifecycle_receipt_sha256 TEXT, argv_json TEXT)"
                )
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?, ?, ?)",
                    (task_id, 1, "completed", receipt, json.dumps(["python3", "-m", "unittest", "tests.test_example"])),
                )
                connection.commit()
            finally:
                connection.close()
            output = Path(tmp) / "task-output" / f".grabowski-task-output-{task_id}-a1"
            output.mkdir(parents=True, mode=0o700)
            (output / "stderr.log").write_text(
                "..\n----------------------------------------------------------------------\nRan 2 tests in 0.010s\n\nOK\n",
                encoding="utf-8",
            )
            (output / "stderr.log").chmod(0o600)
            stored = self._stored_evidence(
                source="test",
                reference=f"grabowski-task:{task_id}:2-passed+0-subtests",
                sha256=receipt,
            )
            observed = evidence._test_observation(stored)
            assert observed is not None
            self.assertEqual("verified", observed["status"])


    def test_prepare_github_matches_trusted_adapter_and_rejects_caller_hash(self) -> None:
        repo = "heimgewebe/grabowski"
        head = "1" * 40
        base = "2" * 40
        merge = "3" * 40
        checks = [
            self._github_v2_workflow_check(
                database_id=97840906739,
                name="Codex review settled",
                started_at="2026-08-25T14:30:01Z",
                conclusion="FAILURE",
                workflow_run_id=32859870973,
                event="pull_request_review",
                run_number=5691,
            ),
            self._github_v2_workflow_check(
                database_id=97841452490,
                name="Codex review settled",
                started_at="2026-08-25T14:31:33Z",
                workflow_run_id=32860034363,
                event="pull_request_review",
                run_number=5693,
            ),
            self._github_v2_status_context(),
        ]
        payload = self._github_v2_payload(
            head=head, base=base, merge=merge, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=943),
        ) as run_command:
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": repo, "pr": 943}
            )
            item = prepared["evidence"]
            assert item is not None
            observed = evidence._github_observation(item)

        self.assertEqual("prepared", prepared["status"])
        self.assertEqual(
            f"github-pr-v2:{repo}#943@{head}:base={base}:merge={merge}:checks=2/2-effective-success",
            item["reference"],
        )
        graphql_calls = [
            call for call in run_command.call_args_list
            if call.args[0][:3] == ["gh", "api", "graphql"]
        ]
        actions_calls = [
            call
            for call in run_command.call_args_list
            if any(
                isinstance(part, str) and part.endswith("/actions/runs")
                for part in call.args[0]
            )
        ]
        self.assertEqual(2, len(graphql_calls))
        self.assertEqual(2, len(actions_calls))
        assert observed is not None
        self.assertEqual("verified", observed["status"])
        self.assertEqual(item["sha256"], observed["sha256"])
        self.assertEqual(
            "verified",
            evidence.assess_evidence_item(item, observation=observed)["classification"],
        )
        with self.assertRaisesRegex(
            evidence.EvidenceAssessmentError, "requires exactly repo and pr"
        ):
            evidence.prepare_evidence(
                "merge",
                "github",
                {"repo": repo, "pr": 943, "sha256": "f" * 64},
            )
        with self.assertRaisesRegex(
            evidence.EvidenceAssessmentError, "generic receipt strings remain intentionally untrusted"
        ):
            evidence.prepare_evidence(
                "receipt",
                "receipt",
                {"reference": "grip:any:receipt:" + "a" * 64},
            )

    def test_prepare_github_accepts_empty_terminal_pr_backlink_when_run_head_is_exact(self) -> None:
        head = "1" * 40
        base = "2" * 40
        merge = "3" * 40
        run_id = 32860034363
        checks = [
            self._github_v2_workflow_check(
                database_id=101,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=7001,
                workflow_run_id=run_id,
                event="pull_request",
                run_number=1,
            )
        ]
        payload = self._github_v2_payload(
            head=head, base=base, merge=merge, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(
                payload,
                pr=943,
                run_pull_requests_empty={run_id},
            ),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 943}
            )

        self.assertEqual("prepared", prepared["status"])
        self.assertTrue(
            prepared["evidence"]["reference"].endswith("checks=1/1-effective-success")
        )

    def test_prepare_github_uses_exact_merge_group_checks_for_merge_queue(self) -> None:
        repo = "heimgewebe/grabowski"
        head = "1" * 40
        base = "2" * 40
        merge = "3" * 40
        head_checks = [
            self._github_v2_external_check(
                database_id=201,
                name="CodeQL",
                started_at="2026-08-25T14:30:01Z",
            )
        ]
        merge_checks = [
            self._github_v2_workflow_check(
                database_id=301,
                name="validate (3.10)",
                started_at="2026-08-25T14:40:01Z",
                workflow_id=8001,
                workflow_name="validate",
                workflow_run_id=9001,
                event="merge_group",
                run_number=7,
            ),
            self._github_v2_workflow_check(
                database_id=302,
                name="validate (3.12)",
                started_at="2026-08-25T14:40:02Z",
                workflow_id=8001,
                workflow_name="validate",
                workflow_run_id=9001,
                event="merge_group",
                run_number=7,
            ),
        ]
        payload = self._github_v2_payload(
            head=head,
            base=base,
            merge=merge,
            checks=head_checks,
            merge_checks=merge_checks,
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=943),
        ) as run_command:
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": repo, "pr": 943}
            )
            item = prepared["evidence"]
            assert item is not None
            observed = evidence._github_observation(item)

        self.assertEqual("prepared", prepared["status"])
        self.assertEqual(
            f"github-pr-v2:{repo}#943@{head}:base={base}:merge={merge}:checks=2/2-effective-success",
            item["reference"],
        )
        assert observed is not None
        self.assertEqual("verified", observed["status"])
        self.assertEqual(item["sha256"], observed["sha256"])
        actions_calls = [
            call
            for call in run_command.call_args_list
            if any(
                isinstance(part, str) and part.endswith("/actions/runs")
                for part in call.args[0]
            )
        ]
        self.assertEqual(2, len(actions_calls))
        self.assertTrue(
            all(f"head_sha={merge}" in call.args[0] for call in actions_calls)
        )

    def test_prepare_github_merge_queue_includes_successful_non_workflow_checks(self) -> None:
        repo = "heimgewebe/grabowski"
        head = "1" * 40
        base = "2" * 40
        merge = "3" * 40
        merge_run = 9051
        payload = self._github_v2_payload(
            head=head,
            base=base,
            merge=merge,
            checks=[
                self._github_v2_external_check(
                    database_id=351,
                    name="head-codeql",
                    started_at="2026-08-25T14:30:01Z",
                )
            ],
            merge_checks=[
                self._github_v2_workflow_check(
                    database_id=352,
                    name="validate",
                    started_at="2026-08-25T14:40:01Z",
                    workflow_id=8051,
                    workflow_run_id=merge_run,
                    event="merge_group",
                    run_number=8,
                ),
                self._github_v2_external_check(
                    database_id=353,
                    name="external-security",
                    started_at="2026-08-25T14:40:02Z",
                ),
                self._github_v2_status_context(
                    node_id="SC_merge_gate",
                    context="external-status",
                    created_at="2026-08-25T14:40:03Z",
                ),
            ],
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=946),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": repo, "pr": 946}
            )

        self.assertEqual("prepared", prepared["status"])
        self.assertTrue(
            prepared["evidence"]["reference"].endswith(
                "checks=3/3-effective-success"
            )
        )

    def test_prepare_github_merge_queue_non_workflow_failure_fails_closed(self) -> None:
        merge_run = 9061
        payload = self._github_v2_payload(
            head="1" * 40,
            base="2" * 40,
            merge="3" * 40,
            checks=[
                self._github_v2_external_check(
                    database_id=361,
                    name="head-codeql",
                    started_at="2026-08-25T14:30:01Z",
                )
            ],
            merge_checks=[
                self._github_v2_workflow_check(
                    database_id=362,
                    name="validate",
                    started_at="2026-08-25T14:40:01Z",
                    workflow_id=8061,
                    workflow_run_id=merge_run,
                    event="merge_group",
                    run_number=9,
                ),
                self._github_v2_external_check(
                    database_id=363,
                    name="external-security",
                    started_at="2026-08-25T14:40:02Z",
                    conclusion="FAILURE",
                ),
            ],
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=947),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 947}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])
        self.assertIsNone(prepared["evidence"])

    def test_prepare_github_merge_queue_failed_check_fails_closed(self) -> None:
        merge_run = 9101
        payload = self._github_v2_payload(
            head="1" * 40,
            base="2" * 40,
            merge="3" * 40,
            checks=[
                self._github_v2_external_check(
                    database_id=401,
                    name="CodeQL",
                    started_at="2026-08-25T14:30:01Z",
                )
            ],
            merge_checks=[
                self._github_v2_workflow_check(
                    database_id=402,
                    name="validate",
                    started_at="2026-08-25T14:40:01Z",
                    conclusion="FAILURE",
                    workflow_id=8101,
                    workflow_run_id=merge_run,
                    event="merge_group",
                    run_number=8,
                )
            ],
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=944),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 944}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])

    def test_prepare_github_merge_queue_ref_drift_fails_closed(self) -> None:
        merge_run = 9201
        base = "2" * 40
        payload = self._github_v2_payload(
            head="1" * 40,
            base=base,
            merge="3" * 40,
            checks=[
                self._github_v2_external_check(
                    database_id=501,
                    name="CodeQL",
                    started_at="2026-08-25T14:30:01Z",
                )
            ],
            merge_checks=[
                self._github_v2_workflow_check(
                    database_id=502,
                    name="validate",
                    started_at="2026-08-25T14:40:01Z",
                    workflow_id=8201,
                    workflow_run_id=merge_run,
                    event="merge_group",
                    run_number=9,
                )
            ],
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(
                payload,
                pr=945,
                run_head_branch_overrides={
                    merge_run: f"gh-readonly-queue/main/pr-999-{base}"
                },
            ),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 945}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_check_shape_invalid", prepared["reason"])

    def test_prepare_github_latest_effective_failure_fails_closed(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=101,
                name="validate",
                started_at="2026-08-25T14:30:01Z",
                workflow_id=301891383,
                workflow_name="validate",
                workflow_run_id=1001,
                event="pull_request",
                run_number=1,
            ),
            self._github_v2_workflow_check(
                database_id=102,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                conclusion="FAILURE",
                workflow_id=301891383,
                workflow_name="validate",
                workflow_run_id=1002,
                event="pull_request",
                run_number=2,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=948),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 948}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])
        self.assertIsNone(prepared["evidence"])

    def test_prepare_github_keeps_same_display_name_from_distinct_workflows(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=201,
                name="validate",
                started_at="2026-08-25T14:30:01Z",
                conclusion="FAILURE",
                workflow_id=7001,
                workflow_name="shared display name",
                workflow_run_id=8001,
            ),
            self._github_v2_workflow_check(
                database_id=202,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=7002,
                workflow_name="shared display name",
                workflow_run_id=8002,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=949),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])

    def test_prepare_github_keeps_same_workflow_job_from_distinct_events(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=251,
                name="validate",
                started_at="2026-08-25T14:30:01Z",
                conclusion="FAILURE",
                workflow_id=7001,
                workflow_run_id=8101,
                event="pull_request",
                run_number=101,
            ),
            self._github_v2_workflow_check(
                database_id=252,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=7001,
                workflow_run_id=8102,
                event="workflow_dispatch",
                run_number=102,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=949),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])

    def test_prepare_github_fails_closed_when_rerun_originates_from_other_pr(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=271,
                name="validate",
                started_at="2026-08-25T14:30:01Z",
                conclusion="FAILURE",
                workflow_id=7001,
                workflow_run_id=8201,
                event="pull_request",
                run_number=101,
            ),
            self._github_v2_workflow_check(
                database_id=272,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=7001,
                workflow_run_id=8202,
                event="pull_request",
                run_number=102,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(
                payload, pr=949, run_pr_overrides={8202: 950}
            ),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_check_shape_invalid", prepared["reason"])
        self.assertIsNone(prepared["evidence"])

    def test_prepare_github_fails_closed_when_single_run_originates_from_other_pr(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=281,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=7001,
                workflow_run_id=8301,
                event="pull_request",
                run_number=101,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(
                payload, pr=949, run_pr_overrides={8301: 950}
            ),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_check_shape_invalid", prepared["reason"])
        self.assertIsNone(prepared["evidence"])

    def test_prepare_github_batches_many_pr_run_provenance_reads(self) -> None:
        head = "1" * 40
        base = "2" * 40
        checks = [
            self._github_v2_workflow_check(
                database_id=10000 + index,
                name=f"job-{index}",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=20000 + index,
                workflow_run_id=30000 + index,
                event="pull_request",
                run_number=1,
            )
            for index in range(80)
        ]
        payload = self._github_v2_payload(
            head=head, base=base, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=949),
        ) as run_command:
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("prepared", prepared["status"])
        actions_calls = [
            call
            for call in run_command.call_args_list
            if any(
                isinstance(part, str) and part.endswith("/actions/runs")
                for part in call.args[0]
            )
        ]
        self.assertEqual(1, len(actions_calls))
        argv = actions_calls[0].args[0]
        self.assertIn("--paginate", argv)
        self.assertIn(f"head_sha={head}", argv)
        self.assertIn("per_page=100", argv)
        self.assertFalse(any("/actions/runs/" in part for part in argv))

    def test_prepare_github_batches_base_sha_fallback_for_target_run(self) -> None:
        head = "1" * 40
        base = "2" * 40
        checks = [
            self._github_v2_workflow_check(
                database_id=951,
                name="target-check",
                started_at="2026-08-25T14:31:01Z",
                workflow_id=952,
                workflow_run_id=953,
                event="pull_request_target",
                run_number=1,
            )
        ]
        payload = self._github_v2_payload(
            head=head, base=base, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(
                payload, pr=949, run_head_sha_overrides={953: base}
            ),
        ) as run_command:
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("prepared", prepared["status"])
        actions_calls = [
            call
            for call in run_command.call_args_list
            if any(
                isinstance(part, str) and part.endswith("/actions/runs")
                for part in call.args[0]
            )
        ]
        self.assertEqual(2, len(actions_calls))
        queried = [
            next(
                part
                for part in call.args[0]
                if isinstance(part, str) and part.startswith("head_sha=")
            )
            for call in actions_calls
        ]
        self.assertEqual([f"head_sha={head}", f"head_sha={base}"], queried)

    def test_prepare_github_keeps_external_same_name_checks_distinct(self) -> None:
        checks = [
            self._github_v2_external_check(
                database_id=301,
                name="CodeQL",
                started_at="2026-08-25T14:30:01Z",
                conclusion="FAILURE",
            ),
            self._github_v2_external_check(
                database_id=302,
                name="CodeQL",
                started_at="2026-08-25T14:31:01Z",
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])

    def test_prepare_github_fails_closed_on_duplicate_name_within_one_workflow_run(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=401,
                name="duplicate",
                started_at="2026-08-25T14:30:01Z",
                workflow_id=7001,
                workflow_run_id=9001,
            ),
            self._github_v2_workflow_check(
                database_id=402,
                name="duplicate",
                started_at="2026-08-25T14:30:02Z",
                workflow_id=7001,
                workflow_run_id=9001,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_check_shape_invalid", prepared["reason"])

    def test_prepare_github_accepts_manual_rerun_as_new_attempt(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=451,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                conclusion="FAILURE",
                workflow_id=7001,
                workflow_run_id=9001,
                run_attempt=1,
            ),
            self._github_v2_workflow_check(
                database_id=452,
                name="validate",
                started_at="2026-08-25T14:30:01Z",
                workflow_id=7001,
                workflow_run_id=9001,
                run_attempt=2,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=949),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("prepared", prepared["status"])
        self.assertTrue(
            prepared["evidence"]["reference"].endswith("checks=1/1-effective-success")
        )

    def test_prepare_github_orders_workflow_runs_by_run_number_not_start_time(self) -> None:
        checks = [
            self._github_v2_workflow_check(
                database_id=461,
                name="validate",
                started_at="2026-08-25T14:32:01Z",
                workflow_id=7001,
                workflow_run_id=9001,
                run_number=101,
            ),
            self._github_v2_workflow_check(
                database_id=462,
                name="validate",
                started_at="2026-08-25T14:31:01Z",
                conclusion="FAILURE",
                workflow_id=7001,
                workflow_run_id=9002,
                run_number=102,
            ),
        ]
        payload = self._github_v2_payload(
            head="1" * 40, base="2" * 40, merge="3" * 40, checks=checks
        )
        with patch.object(
            evidence,
            "_run_command",
            side_effect=self._github_v2_command_side_effect(payload, pr=949),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_checks_not_all_successful", prepared["reason"])

    def test_prepare_github_fails_closed_on_truncated_check_rollup(self) -> None:
        payload = self._github_v2_payload(
            head="1" * 40,
            base="2" * 40,
            merge="3" * 40,
            checks=[
                self._github_v2_external_check(
                    database_id=501,
                    name="CodeQL",
                    started_at="2026-08-25T14:30:01Z",
                )
            ],
            has_next_page=True,
        )
        with patch.object(
            evidence,
            "_run_command",
            return_value=(0, json.dumps(payload).encode("utf-8"), b""),
        ):
            prepared = evidence.prepare_evidence(
                "merge", "github", {"repo": "heimgewebe/grabowski", "pr": 949}
            )

        self.assertEqual("mismatch", prepared["status"])
        self.assertEqual("github_check_shape_invalid", prepared["reason"])

    def test_github_v2_digest_binds_selected_run_identity(self) -> None:
        first = self._github_v2_workflow_check(
            database_id=601,
            name="validate",
            started_at="2026-08-25T14:30:01Z",
            workflow_id=7001,
            workflow_run_id=9001,
        )
        second = self._github_v2_workflow_check(
            database_id=602,
            name="validate",
            started_at="2026-08-25T14:30:01Z",
            workflow_id=7001,
            workflow_run_id=9002,
        )
        first_effective = evidence._effective_github_v2_checks([first])
        second_effective = evidence._effective_github_v2_checks([second])
        assert first_effective is not None and second_effective is not None
        common = {
            "repo": "heimgewebe/grabowski",
            "pr": 949,
            "head": "1" * 40,
            "base": "2" * 40,
            "merge": "3" * 40,
            "passed": 1,
            "total": 1,
            "version": 2,
        }
        first_digest = evidence._sha256(
            evidence._github_observation_material(
                {**common, "effective_checks": first_effective}
            )
        )
        second_digest = evidence._sha256(
            evidence._github_observation_material(
                {**common, "effective_checks": second_effective}
            )
        )

        self.assertNotEqual(first_digest, second_digest)

    def test_prepare_runtime_matches_trusted_adapter_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_EVIDENCE_RELEASES_ROOT": tmp},
        ):
            runtime_input = "7" * 64
            repo_head = "8" * 40
            release_id = "release-v3-prepare-1234567890"
            release = Path(tmp) / release_id
            release.mkdir(mode=0o700)
            manifest = release / "deployment-manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "completion_status": "complete",
                        "repo_head": repo_head,
                        "release_id": release_id,
                        "runtime_input_sha256": runtime_input,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            prepared = evidence.prepare_evidence(
                "runtime", "runtime", {"release_id": release_id}
            )
            item = prepared["evidence"]
            assert item is not None
            observed = evidence._runtime_observation(item)
            assert observed is not None
            self.assertEqual("verified", observed["status"])
            self.assertEqual(runtime_input, item["sha256"])
            self.assertEqual(item["sha256"], observed["sha256"])

            manifest.unlink()
            stale = evidence.prepare_evidence(
                "runtime", "runtime", {"release_id": release_id}
            )
            self.assertEqual("stale", stale["status"])
            self.assertIsNone(stale["evidence"])

    def test_prepare_test_task_matches_trusted_adapter_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "GRABOWSKI_EVIDENCE_TASK_DATABASE": str(Path(tmp) / "tasks.sqlite3"),
                "GRABOWSKI_EVIDENCE_TASK_OUTPUT_ROOT": str(Path(tmp) / "task-output"),
            },
        ):
            task_id = "b" * 24
            lifecycle_receipt = "9" * 64
            database = Path(tmp) / "tasks.sqlite3"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, attempt INTEGER, state TEXT, lifecycle_receipt_sha256 TEXT, argv_json TEXT)"
                )
                connection.execute(
                    "INSERT INTO tasks VALUES (?, ?, ?, ?, ?)",
                    (
                        task_id,
                        1,
                        "completed",
                        lifecycle_receipt,
                        json.dumps(["pytest", "-q"]),
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            output = (
                Path(tmp)
                / "task-output"
                / f".grabowski-task-output-{task_id}-a1"
            )
            output.mkdir(parents=True, mode=0o700)
            (output / "stdout.log").write_text(
                "53 passed, 19 subtests passed in 0.20s\n",
                encoding="utf-8",
            )
            (output / "stdout.log").chmod(0o600)

            prepared = evidence.prepare_evidence(
                "tests", "test", {"task_id": task_id}
            )
            item = prepared["evidence"]
            assert item is not None
            observed = evidence._test_observation(item)

            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE tasks SET argv_json = ? WHERE task_id = ?",
                    (
                        json.dumps(["python3", "-m", "unittest", "tests.test_empty"]),
                        task_id,
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            (output / "stdout.log").write_text(
                "Ran 0 tests in 0.000s\n\nOK\n", encoding="utf-8"
            )
            (output / "stdout.log").chmod(0o600)
            zero_test = evidence.prepare_evidence(
                "tests-zero", "test", {"task_id": task_id}
            )

        assert observed is not None
        self.assertEqual("verified", observed["status"])
        self.assertEqual(
            f"grabowski-task:{task_id}:53-passed+19-subtests",
            item["reference"],
        )
        self.assertEqual(item["sha256"], observed["sha256"])
        self.assertNotEqual(lifecycle_receipt, item["sha256"])
        self.assertEqual("mismatch", zero_test["status"])
        self.assertEqual("test_summary_no_successful_tests", zero_test["reason"])
        self.assertIsNone(zero_test["evidence"])

    def test_root_cause_audit_distinguishes_producer_gap_mismatch_and_human_boundary(self) -> None:
        current = self._status(
            acceptance_ids=["github", "receipt", "human"],
            stored_evidence=[
                self._stored_evidence(
                    acceptance_id="github",
                    source="github",
                    reference="PR 943 merged successfully",
                    sha256="a" * 64,
                ),
                self._stored_evidence(
                    acceptance_id="receipt",
                    source="receipt",
                    reference="grip:operator-obligation-evidence-assess:sample:"
                    + "1" * 64
                    + ":receipt:"
                    + "2" * 64,
                    sha256="b" * 64,
                ),
                self._stored_evidence(
                    acceptance_id="human",
                    source="user",
                    reference="human acceptance",
                    sha256="c" * 64,
                ),
            ],
        )
        result = evidence.assess_status(current)
        by_id = {item["acceptance_id"]: item for item in result["acceptance"]}
        self.assertEqual(
            "evidence_at_source_reference_unbound", by_id["github"]["root_cause"]
        )
        self.assertEqual(
            "evidence_at_source_not_persisted", by_id["receipt"]["root_cause"]
        )
        self.assertEqual("non_machine_verifiable", by_id["human"]["root_cause"])

        mismatch_status = self._status(
            acceptance_ids=["runtime"],
            stored_evidence=[
                self._stored_evidence(
                    source="runtime",
                    reference="runtime:revision-a",
                    sha256="d" * 64,
                )
            ],
        )
        mismatch = evidence.assess_status(
            mismatch_status,
            observations={
                "runtime": self._observation(
                    reference="runtime:revision-b", sha256="d" * 64
                )
            },
        )
        self.assertEqual("identity_mismatch", mismatch["acceptance"][0]["root_cause"])
        self.assertEqual(
            "trusted_observation_mismatch",
            evidence._root_cause_for_assessment(
                {
                    "classification": "mismatch",
                    "reason": "trusted_observation_digest_mismatch",
                }
            ),
        )
        self.assertEqual(
            "stored_evidence_status_mismatch",
            evidence._root_cause_for_assessment(
                {"classification": "mismatch", "reason": "stored_evidence_not_passed"}
            ),
        )
        gap = evidence._gap_audit([result, mismatch])
        causes = {item["root_cause"] for item in gap}
        self.assertTrue(
            {
                "evidence_at_source_reference_unbound",
                "evidence_at_source_not_persisted",
                "non_machine_verifiable",
                "identity_mismatch",
            }.issubset(causes)
        )
        receipt_policy = evidence._gap_policy(
            "receipt", "evidence_at_source_reference_unbound", "Captain merge receipt"
        )
        self.assertFalse(receipt_policy["independent_primary_source_present"])
        self.assertEqual(
            "replace_free_form_receipt_with_primary_source_or_concrete_durable_receipt",
            receipt_policy["recommended_action"],
        )

    def test_prepare_git_and_bureau_reuse_existing_adapter_contracts(self) -> None:
        commit = "b" * 40
        commit_payload = b"tree " + b"a" * 40 + b"\n\nmessage\n"
        with patch.object(
            evidence, "_local_git_repo", return_value=Path("/tmp/repo")
        ), patch.object(
            evidence, "_run_command", return_value=(0, commit_payload, b"")
        ):
            prepared_git = evidence.prepare_evidence(
                "git", "git", {"repo": "heimgewebe/grabowski", "commit": commit}
            )
            git_item = prepared_git["evidence"]
            assert git_item is not None
            git_observation = evidence._git_observation(git_item)
        assert git_observation is not None
        self.assertEqual("verified", git_observation["status"])
        self.assertEqual(git_item["sha256"], git_observation["sha256"])

        candidate_id = "candidate-" + "6" * 24
        event_id = 11086
        idempotency_key = "operator-obligation:v3:producer"
        fingerprint = "7" * 64
        invoke = unittest.mock.Mock(
            return_value={
                "status": "assessed",
                "candidate_id": candidate_id,
                "event_id": event_id,
                "content_fingerprint": fingerprint,
            }
        )
        module = types.ModuleType("grabowski_bureau_intake")
        module._invoke_bureau = invoke
        with patch.dict(sys.modules, {"grabowski_bureau_intake": module}):
            prepared_bureau = evidence.prepare_evidence(
                "bureau",
                "bureau",
                {"idempotency_key": idempotency_key},
            )
            bureau_item = prepared_bureau["evidence"]
            assert bureau_item is not None
            bureau_observation = evidence._bureau_observation(bureau_item)
        assert bureau_observation is not None
        self.assertEqual("verified", bureau_observation["status"])
        self.assertEqual(fingerprint, bureau_item["sha256"])
        self.assertEqual(bureau_item["sha256"], bureau_observation["sha256"])

    def test_cohort_summary_keeps_legacy_and_modern_populations_separate(self) -> None:
        population = [
            {
                "obligation_id": "legacy",
                "close_schema_version": obligations.LEGACY_CLOSE_SCHEMA_VERSION,
            },
            {
                "obligation_id": "modern",
                "close_schema_version": obligations.CLOSE_SCHEMA_VERSION,
            },
        ]
        selected = list(population)
        assessments = [
            {
                "obligation_id": "legacy",
                "legacy_close": True,
                "acceptance_count": 1,
                "acceptance": [
                    {
                        "classification": "legacy_unverifiable",
                        "root_cause": "historical_truth_unavailable",
                        "source": "git",
                    }
                ],
                "fully_verified": False,
                "false_confidence_risk": True,
            },
            {
                "obligation_id": "modern",
                "legacy_close": False,
                "acceptance_count": 1,
                "acceptance": [
                    {
                        "classification": "unverified",
                        "root_cause": "evidence_at_source_reference_unbound",
                        "source": "github",
                    }
                ],
                "fully_verified": False,
                "false_confidence_risk": True,
            },
        ]

        legacy = evidence._cohort_summary(
            population, selected, assessments, legacy=True, integrity_ok=True
        )
        modern = evidence._cohort_summary(
            population, selected, assessments, legacy=False, integrity_ok=True
        )

        self.assertEqual(1, legacy["population_total"])
        self.assertEqual(1, modern["population_total"])
        self.assertTrue(legacy["fully_represented"])
        self.assertTrue(modern["fully_represented"])
        self.assertEqual(
            1, legacy["acceptance_classification_counts"]["legacy_unverifiable"]
        )
        self.assertEqual(1, modern["acceptance_classification_counts"]["unverified"])
        self.assertEqual(
            {"historical_truth_unavailable": 1}, legacy["root_cause_counts"]
        )
        self.assertEqual(
            {"evidence_at_source_reference_unbound": 1}, modern["root_cause_counts"]
        )
    def test_matching_adapter_observation_flows_through_public_assessment(self) -> None:
        stored = self._stored_evidence(
            source="receipt",
            reference="grabowski-receipt:sample.json",
            sha256="a" * 64,
        )
        status = self._status(stored_evidence=[stored])
        trusted = self._observation(
            source="receipt",
            reference="grabowski-receipt:sample.json",
        )
        with patch.object(
            evidence,
            "collect_trusted_observations",
            return_value={"runtime": trusted},
        ), patch.object(obligations, "status_obligation", return_value=status):
            result = evidence.assess_obligation("goo-shadow-evidence-test-0001")

        self.assertTrue(result["fully_verified"])
        self.assertEqual("verified", result["acceptance"][0]["classification"])

    def test_sample_selection_is_schema_stratified_and_input_order_independent(self) -> None:
        legacy = [
            {
                "obligation_id": f"goo-legacy-sample-{index:04d}",
                "close_schema_version": obligations.LEGACY_CLOSE_SCHEMA_VERSION,
            }
            for index in range(40)
        ]
        current = [
            {
                "obligation_id": f"goo-current-sample-{index:04d}",
                "close_schema_version": obligations.CLOSE_SCHEMA_VERSION,
            }
            for index in range(5)
        ]
        population = legacy + current

        first = evidence._select_sample_population(population, 30)
        second = evidence._select_sample_population(list(reversed(population)), 30)

        first_ids = [item["obligation_id"] for item in first]
        self.assertEqual(first_ids, [item["obligation_id"] for item in second])
        self.assertEqual(30, len(first_ids))
        self.assertTrue(
            {item["obligation_id"] for item in current}.issubset(set(first_ids))
        )
        self.assertEqual(
            25,
            sum(
                item["close_schema_version"]
                == obligations.LEGACY_CLOSE_SCHEMA_VERSION
                for item in first
            ),
        )

    def test_sample_is_exactly_bounded_deterministic_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"GRABOWSKI_OPERATOR_OBLIGATION_ROOT": str(Path(tmp) / "obligations")},
        ), patch.object(obligations.alert_outbox, "enqueue_and_schedule"):
            for index in range(evidence.MIN_ROLLOUT_SAMPLE):
                obligation_id = f"goo-shadow-sample-{index:04d}"
                obligations.open_obligation(
                    {
                        "obligation_id": obligation_id,
                        "objective": "Provide one deterministic completed sample record.",
                        "acceptance": [
                            {"id": "runtime", "description": "Runtime is correct."}
                        ],
                        "origin": {"source": "unit-test"},
                        "references": [],
                    }
                )
                obligations.close_obligation(
                    {
                        "obligation_id": obligation_id,
                        "outcome": "completed",
                        "closure_classification": {
                            "convergence_required": False,
                            "reason": "process_only",
                        },
                        "evidence": [
                            self._stored_evidence(
                                reference=f"runtime:sample-{index:04d}",
                                sha256=f"{index + 1:064x}",
                            )
                        ],
                    }
                )

            root = Path(os.environ["GRABOWSKI_OPERATOR_OBLIGATION_ROOT"])
            before = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }
            first = evidence.sample_completed()
            second = evidence.sample_completed()
            after = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }

        self.assertEqual(30, first["sample_size"])
        self.assertEqual(30, first["population_completed_total"])
        self.assertEqual({"2": 30}, first["population_close_schema_counts"])
        self.assertEqual({"2": 30}, first["sample_close_schema_counts"])
        self.assertEqual("schema_stratified_sha256_rank_v1", first["selection_order"])
        self.assertFalse(first["selection_scan_truncated"])
        self.assertEqual([], first["selection_integrity_errors"])
        self.assertEqual(30, first["summary"]["total"])
        self.assertEqual(30, first["summary"]["acceptance_total"])
        self.assertEqual(0, first["summary"]["acceptance_verified"])
        self.assertEqual(30, first["summary"]["unverified"])
        self.assertEqual(0, first["summary"]["obligations_fully_verified"])
        self.assertEqual(
            30, first["summary"]["obligations_with_false_confidence_risk"]
        )
        self.assertEqual("verifiability_gap_observed", first["shadow_signal"])
        self.assertEqual(
            ["bureau", "github", "git", "receipt", "runtime", "test"],
            first["trusted_observation_adapter_sources"],
        )
        self.assertEqual({}, first["trusted_observation_counts"])
        self.assertEqual(
            {"runtime": 30}, first["missing_adapter_source_counts"]
        )
        self.assertFalse(first["rollout_eligible"])
        self.assertEqual(
            "stop_verifiability_threshold_not_met", first["rollout_decision"]
        )
        self.assertFalse(first["verified_completion_enforcement_enabled"])
        self.assertTrue(first["rollout_threshold"]["enforcement_change_separate"])
        self.assertEqual(
            "source_observation_identity_only",
            first["rollout_threshold"]["verification_scope"],
        )
        self.assertFalse(
            first["rollout_threshold"]["semantic_acceptance_relevance_established"]
        )
        self.assertEqual(
            evidence.MAX_ADAPTER_COLLECTION_SECONDS,
            first["rollout_threshold"]["adapter_collection_budget_seconds"],
        )
        self.assertIn(
            "semantic relevance of a verified source artifact to an acceptance condition",
            first["does_not_establish"],
        )
        self.assertIn("completion correctness", first["does_not_establish"])
        self.assertEqual(first["sample_sha256"], second["sample_sha256"])
        self.assertEqual(before, after)

    def test_sample_rejects_more_than_thirty(self) -> None:
        with self.assertRaisesRegex(evidence.EvidenceAssessmentError, "1 to 30"):
            evidence.sample_completed(31)


if __name__ == "__main__":
    unittest.main()
