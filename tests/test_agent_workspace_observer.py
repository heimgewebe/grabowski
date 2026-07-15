from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_agent_workspace as workspace
import grabowski_agent_workspace_observer as observer


class AgentWorkspaceObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "workspaces"
        self.root.mkdir(mode=0o700)
        self.root_patch = mock.patch.object(workspace, "WORKSPACE_ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.cap_patch = mock.patch.object(observer.operator, "_require_operator_capability", return_value=None)
        self.cap_patch.start()
        self.addCleanup(self.cap_patch.stop)

    def _manifest(self, identifier: str) -> dict:
        directory = self.root / identifier
        directory.mkdir(mode=0o700)
        manifest = {
            "schema_version": 1,
            "workspace_id": identifier,
            "event_sequence": 0,
            "binding": {"kind": "bureau_task", "id": "TASK-1"},
            "role_ownership": {
                "operator_may_coordinate_all_roles": True,
                "single_unisolated_agent_may_not_substitute_for_all_roles": True,
            },
        }
        workspace._atomic_json(directory / "manifest.json", manifest)
        return manifest

    @staticmethod
    def _status(*, failure: str | None = None) -> dict:
        role_retry = {
            "tests": {"classification": failure or "not_attempted"},
            "review": {"classification": "not_attempted"},
        }
        return {
            "writer": {"writer_head": "a" * 40, "diff_sha256": "b" * 64},
            "closed": False,
            "closure_outcome": "not_ready",
            "success_ready": False,
            "failed_roles": [],
            "role_retry": role_retry,
            "external_closeout_checklist": [
                {"item": "bureau_task_reconciliation", "status": "unknown"},
            ],
        }

    def test_event_log_is_append_only_hash_bound_and_bounded(self) -> None:
        identifier = "gaw-observer-test-00000001"
        manifest = self._manifest(identifier)
        first = workspace._append_workspace_event(
            manifest,
            "plan_created",
            outcome="planned",
            evidence={"plan_sha256": "a" * 64},
        )
        second = workspace._append_workspace_event(
            manifest,
            "role_preflight",
            role="tests",
            outcome="environment_failure",
            evidence={"failure_classification": "environment_toolchain_failure"},
        )
        events, integrity = observer._read_events(identifier)
        self.assertTrue(integrity["integrity_valid"])
        self.assertEqual([item["sequence"] for item in events], [1, 2])
        self.assertEqual(first["event_sha256"], events[0]["event_sha256"])
        self.assertEqual(second["event_sha256"], events[1]["event_sha256"])
        path = workspace._event_log_path(identifier)
        lines = path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["outcome"] = "passed"
        lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _, integrity = observer._read_events(identifier)
        self.assertFalse(integrity["integrity_valid"])
        self.assertEqual(integrity["reason"], "event_binding_mismatch")

    def test_observer_separates_facts_inferences_and_proposals_without_authority(self) -> None:
        identifier = "gaw-observer-test-00000002"
        manifest = self._manifest(identifier)
        workspace._append_workspace_event(
            manifest,
            "role_preflight",
            role="tests",
            outcome="environment_failure",
            evidence={"failure_classification": "environment_toolchain_failure"},
        )
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=self._status(failure="environment_toolchain_failure")),
        ):
            report = observer.grabowski_agent_workspace_observe(identifier, "high-friction")
        self.assertIn("facts", report)
        self.assertIn("inferences", report)
        self.assertIn("proposals", report)
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["activation"]["adds_mutation_authority"])
        self.assertEqual(report["activation"]["mode"], "explicit_read_only")
        self.assertTrue(report["proposals"])
        self.assertTrue(report["privacy"]["credentials_included"] is False)
        self.assertFalse(report["activation"]["agent_invocation_required"])
        event_path = workspace._event_log_path(identifier)
        before_events = event_path.read_bytes()
        before_manifest = (self.root / identifier / "manifest.json").read_bytes()
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=self._status(failure="environment_toolchain_failure")),
        ):
            observer.grabowski_agent_workspace_observe(identifier, "repeat-read")
        self.assertEqual(event_path.read_bytes(), before_events)
        self.assertEqual((self.root / identifier / "manifest.json").read_bytes(), before_manifest)
        ownership = report["role_ownership"]
        self.assertTrue(ownership["operator_may_coordinate_all_roles"])
        self.assertTrue(ownership["single_unisolated_agent_may_not_substitute_for_all_roles"])

    def test_optimizer_requires_multiple_unique_workspaces_and_is_proposal_only(self) -> None:
        identifiers = ["gaw-observer-test-00000003", "gaw-observer-test-00000004"]
        manifests = {identifier: self._manifest(identifier) for identifier in identifiers}
        for identifier, manifest in manifests.items():
            workspace._append_workspace_event(
                manifest,
                "role_preflight",
                role="tests",
                outcome="environment_failure",
                evidence={"failure_classification": "environment_toolchain_failure"},
            )
        with self.assertRaises(observer.WorkspaceObserverError):
            observer.grabowski_agent_workspace_optimize([identifiers[0]])
        with self.assertRaises(observer.WorkspaceObserverError):
            observer.grabowski_agent_workspace_optimize([identifiers[0], identifiers[0]])

        def load_manifest(identifier: str) -> dict:
            return manifests[identifier]

        with (
            mock.patch.object(workspace, "_manifest", side_effect=load_manifest),
            mock.patch.object(workspace, "_status_data", return_value=self._status(failure="environment_toolchain_failure")),
        ):
            result = observer.grabowski_agent_workspace_optimize(identifiers)
        self.assertEqual(result["sample_size"], 2)
        self.assertTrue(result["minimum_evidence_met"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_code_change"])
        self.assertFalse(result["single_run_can_authorize_change"])
        repeated = {item["failure_class"]: item["workspace_count"] for item in result["repeated_failure_classes"]}
        self.assertEqual(repeated["environment_toolchain_failure"], 2)
        self.assertEqual(
            result["repeated_failure_classes"][0]["workspace_ids"], identifiers
        )
        self.assertEqual(
            result["proposals"][0]["measured_baseline"]["independent_workspace_ids"],
            identifiers,
        )
        self.assertTrue(result["proposals"])
        self.assertTrue(all(item["authority"] == "proposal_only" for item in result["proposals"]))



    def test_specific_retry_classification_suppresses_generic_role_failure(self) -> None:
        identifier = "gaw-observer-test-specific-role-failure"
        manifest = self._manifest(identifier)
        workspace._append_workspace_event(
            manifest,
            "role_finished",
            role="review",
            outcome="failed",
            evidence={"returncode": 126},
        )
        status = self._status()
        status["role_retry"]["review"] = {"classification": "invalid_receipt"}
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=status),
        ):
            report = observer.grabowski_agent_workspace_observe(identifier, "specificity-fixture")
        self.assertIn("review:invalid_receipt", report["facts"]["failure_classes"])
        self.assertNotIn("role_finished:failed", report["facts"]["failure_classes"])

    def test_unclassified_role_failure_retains_generic_failure(self) -> None:
        identifier = "gaw-observer-test-generic-role-failure"
        manifest = self._manifest(identifier)
        workspace._append_workspace_event(
            manifest,
            "role_finished",
            role="review",
            outcome="failed",
            evidence={"returncode": 1},
        )
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=self._status()),
        ):
            report = observer.grabowski_agent_workspace_observe(identifier, "generic-fixture")
        self.assertIn("role_finished:failed", report["facts"]["failure_classes"])

    def test_legacy_missing_pytest_is_toolchain_failure_and_recovers_identity(self) -> None:
        identifier = "gaw-observer-test-legacy-pytest"
        manifest = self._manifest(identifier)
        manifest["expected_base_head"] = "a" * 40
        manifest["commands"] = {
            "tests": ["/usr/bin/python3", "-m", "pytest", "-q"],
            "review": ["/usr/bin/python3", "-c", "print('ok')"],
        }
        manifest["collection"] = {
            "state": "complete",
            "writer_head": "c" * 40,
            "expected_base_head": "a" * 40,
            "diff_sha256": "d" * 64,
            "tests": {"status": "failed"},
            "review": {"status": "passed"},
        }
        status = self._status(failure="semantic_test_failure")
        status["writer"] = {"writer_head": None, "diff_sha256": None}
        status["failed_roles"] = ["tests"]
        receipt = {
            "returncode": 1,
            "stderr_tail": "/usr/bin/python3: No module named pytest\n",
            "stdout_tail": "",
        }
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=status),
            mock.patch.object(workspace, "_role_receipt", side_effect=lambda _manifest, role: receipt if role == "tests" else None),
        ):
            report = observer.grabowski_agent_workspace_observe(identifier, "legacy-fixture")
        self.assertIn("environment_toolchain_failure", report["facts"]["failure_classes"])
        self.assertNotIn("tests:semantic_test_failure", report["facts"]["failure_classes"])
        self.assertEqual(report["facts"]["writer_head"], "c" * 40)
        self.assertEqual(report["facts"]["diff_sha256"], "d" * 64)
        self.assertEqual(report["facts"]["source"], "collection_receipt")

    def test_unrelated_missing_application_module_remains_semantic_failure(self) -> None:
        identifier = "gaw-observer-test-app-module"
        manifest = self._manifest(identifier)
        manifest["commands"] = {
            "tests": ["/usr/bin/python3", "-m", "pytest", "-q"],
            "review": ["/usr/bin/python3", "-c", "print('ok')"],
        }
        receipt = {
            "returncode": 1,
            "stderr_tail": "ImportError: No module named project_dependency\n",
            "stdout_tail": "",
        }
        with mock.patch.object(
            workspace, "_role_receipt", side_effect=lambda _manifest, role: receipt if role == "tests" else None
        ):
            self.assertEqual(
                observer._receipt_failure_class(manifest, "tests"),
                "semantic_test_failure",
            )

    def test_explicit_hash_bound_closeout_evidence_resolves_only_named_items(self) -> None:
        identifier = "gaw-observer-test-closeout-evidence"
        manifest = self._manifest(identifier)
        status = self._status()
        manifest["collection"] = {
            "result_sha256": "a" * 64,
            "writer_head": "b" * 40,
            "diff_sha256": "c" * 64,
        }
        manifest["close_receipt"] = {"receipt_sha256": "d" * 64}
        unsigned = {
            "schema_version": 1,
            "workspace_id": identifier,
            "collection_result_sha256": "a" * 64,
            "close_receipt_sha256": "d" * 64,
            "writer_head": "b" * 40,
            "diff_sha256": "c" * 64,
            "items": [
                {
                    "item": "bureau_task_reconciliation",
                    "status": "verified",
                    "source_of_truth": "bureau",
                    "reference": "bureau-task:TASK-1@verified",
                }
            ],
        }
        evidence = {**unsigned, "evidence_sha256": observer._sha256_json(unsigned)}
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=status),
        ):
            report = observer.grabowski_agent_workspace_observe(
                identifier,
                "closeout",
                evidence,
            )
        self.assertEqual(report["facts"]["unresolved_external_closeout"], [])
        resolved = {
            item["item"]: item
            for item in report["facts"]["external_closeout"]
        }
        self.assertEqual(resolved["bureau_task_reconciliation"]["status"], "verified")
        self.assertEqual(resolved["bureau_task_reconciliation"]["evidence_mode"], "explicit_hash_bound")

    def test_optimizer_excludes_legacy_reports_without_event_logs(self) -> None:
        identifiers = [
            "gaw-observer-test-legacy-opt-1",
            "gaw-observer-test-legacy-opt-2",
        ]
        manifests = {identifier: self._manifest(identifier) for identifier in identifiers}
        for manifest in manifests.values():
            manifest["commands"] = {
                "tests": ["/usr/bin/python3", "-m", "pytest"],
                "review": ["/usr/bin/python3", "-c", "print('ok')"],
            }
            manifest["collection"] = {
                "state": "complete",
                "writer_head": "a" * 40,
                "expected_base_head": "a" * 40,
                "diff_sha256": "b" * 64,
                "tests": {"status": "failed"},
                "review": {"status": "passed"},
            }
            receipt = {
                "schema_version": 1,
                "role": "tests",
                "attempt": 1,
                "returncode": 1,
                "stderr_tail": "/usr/bin/python3: No module named pytest",
                "stdout_tail": "",
            }
            receipt["receipt_sha256"] = workspace._sha256_json(receipt)
            manifest.setdefault("role_receipts", {})["tests"] = receipt

        with (
            mock.patch.object(workspace, "_manifest", side_effect=lambda identifier: manifests[identifier]),
            mock.patch.object(
                workspace,
                "_status_data",
                return_value=self._status(failure="environment_toolchain_failure"),
            ),
        ):
            result = observer.grabowski_agent_workspace_optimize(identifiers)
        self.assertEqual(result["repeated_failure_classes"], [])
        self.assertEqual(result["proposals"], [])

    def test_stale_closeout_evidence_is_rejected_after_collection_changes(self) -> None:
        identifier = "gaw-observer-test-stale-closeout"
        manifest = self._manifest(identifier)
        manifest["collection"] = {
            "result_sha256": "a" * 64,
            "writer_head": "b" * 40,
            "diff_sha256": "c" * 64,
        }
        manifest["close_receipt"] = {"receipt_sha256": "d" * 64}
        unsigned = {
            "schema_version": 1,
            "workspace_id": identifier,
            "collection_result_sha256": "e" * 64,
            "close_receipt_sha256": "d" * 64,
            "writer_head": "b" * 40,
            "diff_sha256": "c" * 64,
            "items": [],
        }
        evidence = {**unsigned, "evidence_sha256": observer._sha256_json(unsigned)}
        with self.assertRaisesRegex(observer.WorkspaceObserverError, "stale or unbound"):
            observer._validate_closeout_evidence(identifier, manifest, evidence)

    def test_optimizer_ignores_success_classifications_and_unknown_closeout(self) -> None:
        identifiers = ["gaw-observer-test-success-01", "gaw-observer-test-success-02"]
        manifests = {identifier: self._manifest(identifier) for identifier in identifiers}

        def load_manifest(identifier: str) -> dict:
            return manifests[identifier]

        success_status = self._status(failure="already_succeeded")
        with (
            mock.patch.object(workspace, "_manifest", side_effect=load_manifest),
            mock.patch.object(workspace, "_status_data", return_value=success_status),
            mock.patch.object(workspace, "_role_receipt", return_value=None),
        ):
            result = observer.grabowski_agent_workspace_optimize(identifiers)
        self.assertEqual(result["repeated_failure_classes"], [])
        self.assertEqual(result["proposals"], [])
        self.assertFalse(result["proposal_threshold"]["success_states_counted_as_failures"])


    def test_closeout_handoff_is_deterministic_and_non_authorizing(self) -> None:
        closeout = [
            {"item": "pr_integration_truth", "status": "verified"},
            {"item": "bureau_task_reconciliation", "status": "unknown"},
        ]
        handoff = observer._closeout_handoff(closeout, ["bureau_task_reconciliation"])
        self.assertEqual(handoff["state"], "pending_external_truth")
        self.assertEqual(handoff["next_action"], "verify:bureau_task_reconciliation")
        self.assertFalse(handoff["mutation_authorized"])

    def test_semantic_test_failure_is_quality_signal_not_platform_friction(self) -> None:
        identifier = "gaw-observer-test-quality-signal"
        manifest = self._manifest(identifier)
        workspace._append_workspace_event(
            manifest,
            "role_finished",
            role="tests",
            outcome="failed",
            evidence={"failure_classification": "semantic_test_failure"},
        )
        with (
            mock.patch.object(workspace, "_manifest", return_value=manifest),
            mock.patch.object(workspace, "_status_data", return_value=self._status(failure="semantic_test_failure")),
        ):
            report = observer.grabowski_agent_workspace_observe(identifier, "quality-signal")
        self.assertEqual(report["facts"]["workspace_friction_classes"], [])
        self.assertEqual(report["facts"]["actionable_failure_classes"], [])
        self.assertEqual(report["facts"]["quality_signal_classes"], ["semantic_test_failure"])

    def test_optimizer_does_not_propose_platform_change_for_quality_signals(self) -> None:
        identifiers = ["gaw-observer-quality-opt-01", "gaw-observer-quality-opt-02"]
        manifests = {identifier: self._manifest(identifier) for identifier in identifiers}
        for manifest in manifests.values():
            workspace._append_workspace_event(
                manifest,
                "role_finished",
                role="tests",
                outcome="failed",
                evidence={"failure_classification": "semantic_test_failure"},
            )
        with (
            mock.patch.object(workspace, "_manifest", side_effect=lambda identifier: manifests[identifier]),
            mock.patch.object(workspace, "_status_data", return_value=self._status(failure="semantic_test_failure")),
        ):
            result = observer.grabowski_agent_workspace_optimize(identifiers)
        self.assertEqual(result["repeated_failure_classes"], [])
        self.assertEqual(result["proposals"], [])
        self.assertEqual(result["quality_signals"][0]["workspace_count"], 2)
        self.assertFalse(result["quality_signals"][0]["drives_workspace_optimization"])

    def test_runtime_identity_creates_versioned_cohort_and_rejects_tampering(self) -> None:
        body = {
            "schema_version": 1,
            "runtime_release": "release-1",
            "runtime_repo_head": "a" * 40,
        }
        manifest = {"runtime_identity": {**body, "identity_sha256": observer._sha256_json(body)}}
        cohort = observer._cohort_identity(manifest)
        self.assertEqual(cohort["kind"], "versioned")
        self.assertEqual(cohort["cohort_key"], "release:release-1")
        manifest["runtime_identity"]["runtime_release"] = "tampered"
        self.assertEqual(observer._cohort_identity(manifest)["kind"], "invalid")

    def test_metrics_summary_is_report_hash_bound_and_read_only(self) -> None:
        reports = [
            {"report_sha256": "a" * 64, "facts": {"closed": True, "closure_outcome": "successful", "failed_roles": [], "actionable_failure_classes": []}},
            {"report_sha256": "b" * 64, "facts": {"closed": False, "closure_outcome": "not_ready", "failed_roles": ["writer"], "actionable_failure_classes": ["writer:failed"]}},
        ]
        metrics = observer._metrics_summary(reports)
        self.assertEqual(metrics["sample_size"], 2)
        self.assertEqual(metrics["successful_close_count"], 1)
        self.assertEqual(metrics["failed_role_workspace_count"], 1)
        self.assertEqual(metrics["success_ratio"], 1.0)
        self.assertEqual(metrics["completion_ratio"], 0.5)
        self.assertEqual(metrics["closed_success_ratio"], 1.0)
        self.assertEqual(metrics["legacy_workspace_count"], 2)
        self.assertTrue(metrics["read_only_projection"])
        self.assertEqual(metrics["source_report_sha256"], ["a" * 64, "b" * 64])

    def _snapshot_report(self, identifier: str, *, activation_reason: str) -> dict:
        manifest = workspace._manifest(identifier)
        cohort = observer._cohort_identity(manifest)
        return {
            "workspace_id": identifier,
            "report_sha256": observer._sha256_json({"workspace_id": identifier}),
            "facts": {
                "closed": True,
                "closure_outcome": "successful",
                "failed_roles": [],
                "workspace_friction_classes": [],
                "quality_signal_classes": [],
                "lifecycle_debt_classes": [],
                "timing": {},
                "cohort": cohort,
                "route_evidence": None,
                "event_log": {"integrity_valid": True},
            },
        }

    def _write_snapshot_manifest(
        self, identifier: str, runtime_identity: dict | None
    ) -> None:
        directory = self.root / identifier
        directory.mkdir(mode=0o700)
        manifest = {
            "schema_version": workspace.SCHEMA_VERSION,
            "workspace_id": identifier,
        }
        if runtime_identity is not None:
            manifest["runtime_identity"] = runtime_identity
        workspace._atomic_json(directory / "manifest.json", manifest)

    def test_metrics_snapshot_prioritizes_complete_current_cohort(self) -> None:
        identity_body = {
            "schema_version": 1,
            "runtime_release": "release-current",
            "runtime_repo_head": "a" * 40,
        }
        identity = {
            **identity_body,
            "identity_sha256": observer._sha256_json(identity_body),
        }
        current = "gaw-snapshot-current-00000001"
        legacy = "gaw-snapshot-legacy-00000001"
        self._write_snapshot_manifest(current, identity)
        self._write_snapshot_manifest(legacy, None)
        with (
            mock.patch.object(workspace, "_workspace_runtime_identity", return_value=identity),
            mock.patch.object(observer, "_observer_report", side_effect=self._snapshot_report),
        ):
            snapshot = observer.workspace_metrics_snapshot(limit=1)
        self.assertEqual(snapshot["selected_workspace_count"], 1)
        self.assertEqual(snapshot["current_cohort_candidate_count"], 1)
        self.assertEqual(snapshot["current_cohort_sample_size"], 1)
        self.assertTrue(snapshot["current_cohort_complete"])
        self.assertTrue(snapshot["integrity_valid"])
        self.assertIsNotNone(snapshot["friction_fingerprint_sha256"])
        self.assertFalse(snapshot["inventory_complete"])

    def test_metrics_snapshot_with_truncated_current_cohort_has_no_fingerprint(self) -> None:
        identity_body = {
            "schema_version": 1,
            "runtime_release": "release-current",
            "runtime_repo_head": "a" * 40,
        }
        identity = {
            **identity_body,
            "identity_sha256": observer._sha256_json(identity_body),
        }
        self._write_snapshot_manifest("gaw-snapshot-current-00000002", identity)
        self._write_snapshot_manifest("gaw-snapshot-current-00000003", identity)
        with (
            mock.patch.object(workspace, "_workspace_runtime_identity", return_value=identity),
            mock.patch.object(observer, "_observer_report", side_effect=self._snapshot_report),
        ):
            snapshot = observer.workspace_metrics_snapshot(limit=1)
        self.assertEqual(snapshot["current_cohort_candidate_count"], 2)
        self.assertEqual(snapshot["current_cohort_sample_size"], 1)
        self.assertFalse(snapshot["current_cohort_complete"])
        self.assertFalse(snapshot["integrity_valid"])
        self.assertIsNone(snapshot["friction_fingerprint_sha256"])
        self.assertEqual(
            snapshot["friction_fingerprint_unavailable_reason"],
            "current_cohort_snapshot_incomplete_or_invalid",
        )

    def test_timing_metric_names_collection_request_truthfully(self) -> None:
        events = [
            {"event_type": "plan_created", "recorded_at": "2026-07-15T10:00:00+00:00"},
            {
                "event_type": "collection_requested",
                "recorded_at": "2026-07-15T10:00:05+00:00",
            },
        ]
        timing = observer._event_timing_metrics(events)
        self.assertEqual(timing["collection_requested_seconds"], 5.0)
        self.assertNotIn("writer_observed_terminal_seconds", timing)


if __name__ == "__main__":
    unittest.main()
