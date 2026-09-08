from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operator_relay as relay


class OperatorRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = relay.operator_relay_protocol()

    def test_direct_user_authority_is_machine_readable(self) -> None:
        self.assertIs(self.protocol["bureau_task_required_for_direct_user_work"], False)
        self.assertIs(self.protocol["owner_authorized_automatic_execution"], True)
        self.assertIs(self.protocol["delegated_scoped_writers_allowed"], True)
        self.assertEqual(self.protocol["direct_user_lifecycle_source"], "work_lane")

    def test_authority_is_role_bound_not_model_bound(self) -> None:
        self.assertEqual(
            self.protocol["authority_principle"],
            "model_identity_does_not_grant_authority",
        )
        self.assertEqual(
            set(self.protocol["authority_roles"]),
            {"controller", "scoped_writer", "reviewer", "observer"},
        )
        self.assertEqual(
            self.protocol["execution_priority_semantics"],
            "routing_preference_not_model_authority",
        )
        self.assertEqual(
            self.protocol["coding_agent_priority_semantics"],
            "routing_preference_not_authority",
        )

    def test_scoped_writer_and_controller_effects_are_separated(self) -> None:
        writer = self.protocol["authority_roles"]["scoped_writer"]
        self.assertEqual(
            writer["allowed_effects"],
            [
                "implement",
                "test",
                "commit",
                "push",
                "pull_request_create_or_update",
            ],
        )
        controller_only = ["merge", "deployment", "bureau_terminalization", "closeout"]
        self.assertEqual(self.protocol["controller_only_effects"], controller_only)
        self.assertEqual(writer["forbidden_without_controller"], controller_only)
        self.assertTrue(writer["authoritative_within_lane"])
        self.assertEqual(
            writer["requires"],
            ["explicit_lane", "resource_scope", "controller_binding"],
        )

    def test_g66_failover_is_classified_and_does_not_escalate_denials(self) -> None:
        failover = self.protocol["operator_failover"]
        self.assertEqual(failover["contract"], "G6.6-classified-local-first-v1")
        self.assertEqual(failover["primary_surface"], "grabowski")
        self.assertEqual(failover["secondary_surface"], "der_kleine_maulwurf")
        self.assertEqual(failover["canonical_authority_host"], "heim-pc")
        self.assertEqual(
            failover["implemented_authority_relays"],
            ["systemkatalog", "bureau_intake"],
        )
        self.assertFalse(failover["generic_remote_shell_fallback"])
        self.assertFalse(failover["new_public_tool_required"])
        forbidden = set(failover["never_failover_on"])
        self.assertTrue(
            {
                "policy_denial",
                "authority_denial",
                "bureau_domain_denial",
                "github_denial",
                "ci_failure",
                "dirty_repository",
                "runtime_integrity_failure",
                "outcome_unknown",
            }.issubset(forbidden)
        )
        self.assertEqual(
            failover["failback"],
            "retry-local-authority-first-on-every-operation",
        )

    def test_parallelism_and_hard_blocks_are_explicit(self) -> None:
        self.assertEqual(
            self.protocol["overlapping_writer_invariant"],
            "one_authoritative_mutating_writer_per_overlapping_resource_lane",
        )
        self.assertIs(self.protocol["parallel_disjoint_lanes_allowed"], True)
        self.assertEqual(
            self.protocol["fail_closed_conditions"],
            [
                "live_overlapping_foreign_writer_or_lease",
                "outcome_unknown",
                "invalid_runtime_or_audit_state",
                "missing_cost_approval",
            ],
        )


if __name__ == "__main__":
    unittest.main()
