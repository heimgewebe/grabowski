from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class AgentBootstrapTests(unittest.TestCase):
    def load_module(self):
        spec = importlib.util.spec_from_file_location(
            f"_agent_bootstrap_{id(self)}", ROOT / "src/grabowski_agent_bootstrap.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_call_shape_allows_one_bounded_read(self) -> None:
        module = self.load_module()
        result = module.call_shape_check(
            intent_count=1,
            command_count=1,
            expected_output_bytes=4096,
            may_mutate=False,
            transport_sensitive=False,
            typed_tool_available=True,
            post_state_read_available=True,
        )
        self.assertTrue(result["allowed_shape"])
        self.assertEqual(result["recommendation"], "proceed_bounded")
        self.assertFalse(result["execution_authorized"])

    def test_call_shape_rejects_collection_action(self) -> None:
        module = self.load_module()
        result = module.call_shape_check(
            intent_count=3,
            command_count=4,
            expected_output_bytes=200000,
            may_mutate=True,
            transport_sensitive=True,
            typed_tool_available=True,
            post_state_read_available=False,
        )
        self.assertFalse(result["allowed_shape"])
        self.assertEqual(result["recommendation"], "split_before_execution")
        self.assertIn("multiple_or_missing_independent_intents", result["findings"])
        self.assertIn("mutation_must_be_isolated", result["findings"])
        self.assertIn("mutation_requires_post_state_readback", result["findings"])
        self.assertEqual(result["retry_limit_after_operator_stop"], 0)

    def test_call_shape_is_deterministic(self) -> None:
        module = self.load_module()
        kwargs = dict(
            intent_count=1,
            command_count=1,
            expected_output_bytes=100,
            may_mutate=True,
            transport_sensitive=False,
            typed_tool_available=True,
            post_state_read_available=True,
        )
        self.assertEqual(
            module.call_shape_check(**kwargs)["shape_sha256"],
            module.call_shape_check(**kwargs)["shape_sha256"],
        )

    def test_bootstrap_fail_closed_on_invalid_governor_integrity(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": False,
            "candidates": [],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        result = module.agent_bootstrap()
        self.assertEqual(result["adaptive_mode"], "disabled_fail_closed")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_live_routing_enabled"])

    def test_bootstrap_preserves_immutable_boundaries(self) -> None:
        module = self.load_module()
        module.grabowski_friction.friction_summary = lambda **_: {
            "event_log_integrity": {"integrity_valid": True},
            "decision_log": {"integrity_valid": True},
            "fingerprint_sha256": "a" * 64,
        }
        module.grabowski_friction.execution_governor_summary = lambda **_: {
            "ledger_integrity_valid": True,
            "candidates": [{"circuit_breaker_open": False}],
            "minimum_evidence": 5,
            "decay_seconds": 604800,
            "live_promotions": [],
            "summary_sha256": "b" * 64,
        }
        result = module.agent_bootstrap()
        self.assertEqual(result["adaptive_mode"], "shadow")
        self.assertIn("authorization", result["immutable_boundaries"])
        self.assertIn("resource_leases", result["immutable_boundaries"])
        self.assertTrue(result["call_rules"]["one_independent_intent_per_call"])
        self.assertFalse(result["call_rules"]["unchanged_mutation_retry_allowed"])


if __name__ == "__main__":
    unittest.main()
