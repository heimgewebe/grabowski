from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class MaulwurfXPolicyTests(unittest.TestCase):
    def test_policy_keeps_internal_status_plane_read_only_and_adds_one_gateway_proposal(self) -> None:
        policy = json.loads((ROOT / "config" / "maulwurf-x-tools.json").read_text())
        self.assertEqual(policy["schema_version"], 2)
        self.assertEqual(
            set(policy["allowed_tools"]),
            {
                "grabowski_status",
                "grabowski_runtime_health",
                "grabowski_deployment_identity",
                "grabowski_contract_drift",
                "grabowski_systemkatalog_query",
                "grabowski_audit_projection",
            },
        )
        self.assertEqual(policy["gateway_tools"], ["maulwurfx_propose_finding"])
        self.assertTrue(policy["read_only_only"])
        self.assertNotIn("maulwurfx_propose_finding", policy["allowed_tools"])

    def test_policy_excludes_unscoped_content_readers_and_general_mutators(self) -> None:
        policy = json.loads((ROOT / "config" / "maulwurf-x-tools.json").read_text())
        exposed = set(policy["allowed_tools"]) | set(policy["gateway_tools"])
        self.assertTrue(
            exposed.isdisjoint(
                {
                    "grabowski_context",
                    "grabowski_git_status",
                    "grabowski_git_log",
                    "grabowski_git_diff",
                    "grabowski_git_show",
                    "grabowski_github_pr_view",
                    "grabowski_github_checks",
                    "repoground_preflight",
                    "repoground_query",
                    "repoground_query_existing_index",
                    "repoground_context_pack",
                    "grabowski_bureau_candidate_assess",
                    "grabowski_bureau_candidate_record",
                    "grabowski_bureau_task_publish",
                    "grabowski_bureau_pickup_status",
                    "grabowski_operator_historical_recall",
                    "grabowski_task_start",
                    "grabowski_git",
                    "grabowski_power_run",
                    "grabowski_runtime_deploy_schedule",
                }
            )
        )

    def test_internal_policy_tools_are_published_and_read_only(self) -> None:
        policy = json.loads((ROOT / "config" / "maulwurf-x-tools.json").read_text())
        entrypoint = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        catalog = json.loads((ROOT / "contracts" / "capability-catalog.v1.json").read_text())
        records = catalog.get("capabilities", catalog.get("tools", []))
        read_only = {
            record.get("tool")
            for record in records
            if isinstance(record, dict) and record.get("read_only") is True
        }
        allowed = set(policy["allowed_tools"])
        self.assertTrue(allowed <= set(entrypoint["expected_tools"]))
        self.assertTrue(allowed <= read_only)
        self.assertNotIn("maulwurfx_propose_finding", set(entrypoint["expected_tools"]))


if __name__ == "__main__":
    unittest.main()
