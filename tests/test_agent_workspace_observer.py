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
        self.assertTrue(result["proposals"])
        self.assertTrue(all(item["authority"] == "proposal_only" for item in result["proposals"]))


if __name__ == "__main__":
    unittest.main()
