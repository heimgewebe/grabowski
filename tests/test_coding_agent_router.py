from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_coding_agent_router as router  # noqa: E402


class CodingAgentRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog_path = self.root / "catalog.json"
        self.state_path = self.root / "state.json"
        self.catalog = json.loads(
            (ROOT / "config" / "coding-agent-catalog.json").read_text(encoding="utf-8")
        )
        self.catalog_path.write_text(
            json.dumps(self.catalog, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        self.state = self._fresh_state()
        self._write_state()
        self.environment = mock.patch.dict(
            os.environ,
            {
                router.CATALOG_ENV: str(self.catalog_path),
                router.STATE_ENV: str(self.state_path),
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def _fresh_state(self) -> dict:
        routes = self.catalog["routes"]
        agy_models: list[str] = []
        grok_models: list[str] = []
        for route in routes:
            argv = route.get("argv_prefix", [])
            for index, item in enumerate(argv[:-1]):
                if item == "--model":
                    model = argv[index + 1]
                    if route["harness"] == "agy":
                        agy_models.append(model)
                    elif route["harness"] == "grok":
                        grok_models.append(model)
        observed = datetime.now(timezone.utc).replace(microsecond=0)
        timestamp = observed.isoformat().replace("+00:00", "Z")
        return {
            "schema_version": 2,
            "updated_at": timestamp,
            "catalog_sha256": router._canonical_sha256(self.catalog),
            "catalog": {
                "schema_version": 2,
                "observed_at": timestamp,
                "harnesses": {
                    harness: {"available": True}
                    for harness in self.catalog["harnesses"]
                },
                "providers": {
                    "codex": {
                        "models": [
                            route["model"]
                            for route in routes
                            if route["harness"] == "codex"
                        ]
                    },
                    "claude": {
                        "auth": {
                            "logged_in": True,
                            "auth_method": "claude.ai",
                            "subscription_type": "pro",
                        },
                        "models": [
                            "claude-fable-5",
                            "claude-opus-4.8",
                            "claude-sonnet-5",
                        ],
                    },
                    "agy": {"models": sorted(set(agy_models))},
                    "grok": {
                        "logged_in": True,
                        "models": sorted(set(grok_models)),
                    },
                    "jules": {"authenticated": True},
                    "cline": {"config": {"free_entitlement_verified": False}},
                    "ollama": {
                        "models": [
                            "qwen2.5-coder:14b",
                            "qwen2.5-coder-32k:7b",
                            "qwen2.5-coder:7b",
                            "llama3:8b",
                        ]
                    },
                },
            },
            "pools": {
                "grok-com": {"verified_at": timestamp},
                "jules-account": {"verified_at": timestamp},
            },
            "routes": {},
            "history": {
                "model_access_probes": {"claude-fable-5": {"runs": 99, "successes": 99}}
            },
        }

    def _write_state(self) -> None:
        self.state_path.write_text(
            json.dumps(self.state, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )

    def _route(self, task_class: str, **kwargs: object) -> dict:
        defaults = {
            "changed_files": 20,
            "duration_minutes": 180,
            "novelty": "high",
            "risk_flags": [],
            "latency_priority": False,
            "need_review": True,
        }
        defaults.update(kwargs)
        return router.grabowski_coding_agent_route(task_class, **defaults)

    def test_catalog_declares_correct_quality_and_effort_hierarchy(self) -> None:
        result = router.grabowski_coding_agent_catalog(include_disabled=True)
        self.assertTrue(result["validation"]["valid"])
        policy = result["frontier_model_policy"]
        self.assertEqual(
            policy["top_class_routes"], ["codex-sol-high", "claude-fable-5-high"]
        )
        self.assertEqual(policy["escalation_route"], "codex-sol-xhigh")
        self.assertFalse(result["provider_peer_balance"]["enabled"])
        self.assertEqual(result["provider_peer_balance"]["selection_effect"], 0)
        routes = {route["id"]: route for route in self.catalog["routes"]}
        self.assertEqual(routes["codex-sol-high"]["quality_class"], "S")
        self.assertEqual(routes["claude-fable-5-high"]["quality_class"], "S")
        self.assertEqual(routes["claude-opus-4.8-high"]["quality_class"], "A")
        self.assertEqual(routes["codex-sol-medium"]["quality_class"], "A")
        self.assertGreater(
            routes["codex-sol-xhigh"]["burn_weight"],
            routes["codex-sol-high"]["burn_weight"],
        )
        self.assertGreater(
            routes["codex-sol-high"]["burn_weight"],
            routes["codex-sol-medium"]["burn_weight"],
        )
        self.assertNotEqual(
            routes["claude-fable-5-high"]["burn_weight"],
            routes["claude-opus-4.8-high"]["burn_weight"],
        )
        self.assertFalse(result["automatic_execution_authorized"])

    def test_sonnet_alias_is_resolved_without_claiming_an_unknown_current_model(
        self,
    ) -> None:
        self.assertIn("claude-sonnet-5", self.catalog["models"])
        self.assertNotIn("claude-sonnet-current", self.catalog["models"])
        model = self.catalog["models"]["claude-sonnet-5"]
        self.assertEqual(model["resolved_alias"], "sonnet")
        self.assertIn("no model invocation", model["evidence"])
        routes = {route["id"]: route for route in self.catalog["routes"]}
        self.assertEqual(routes["claude-sonnet-5-high"]["argv_prefix"][2], "sonnet")

    def test_sol_and_fable_are_same_class_co_primaries_without_provider_forcing(
        self,
    ) -> None:
        result = self._route("complex-patch")
        co_routes = {item["route"] for item in result["co_primaries"]}
        self.assertIn("codex-sol-high", co_routes)
        self.assertIn("claude-fable-5-high", co_routes)
        self.assertEqual(
            {item["quality_class"] for item in result["co_primaries"]}, {"S"}
        )
        self.assertTrue(result["co_primary_is_not_parallel_writer_authority"])
        self.assertTrue(result["single_mutating_writer"])

        self.state["routes"] = {
            "codex-sol-high": {"runs": 100, "successes": 100, "failures": 0}
        }
        self._write_state()
        after_run_count = self._route("complex-patch")
        self.assertFalse(
            any(
                "provider balance" in reason
                for item in [after_run_count["primary"], *after_run_count["fallbacks"]]
                for reason in item["reasons"]
            )
        )

    def test_task_specific_defaults_match_the_corrected_baseline(self) -> None:
        complex_patch = self._route("complex-patch")
        self.assertIn(
            complex_patch["primary"]["route"], {"codex-sol-high", "claude-fable-5-high"}
        )
        migration = self._route("migration", duration_minutes=300)
        self.assertEqual(migration["primary"]["route"], "claude-fable-5-high")
        architecture = self._route("architecture")
        self.assertEqual(architecture["primary"]["route"], "claude-fable-5-high")
        security = self._route(
            "security-review", duration_minutes=120, risk_flags=["security-sensitive"]
        )
        self.assertEqual(security["primary"]["route"], "codex-sol-xhigh")
        normal = self._route(
            "bounded-patch",
            changed_files=4,
            duration_minutes=45,
            novelty="medium",
            need_review=False,
        )
        self.assertIn(
            normal["primary"]["route"],
            {
                "codex-terra-high",
                "claude-sonnet-5-high",
                "codex-terra-medium",
                "claude-sonnet-5-medium",
            },
        )
        trivial = self._route(
            "mechanical",
            changed_files=1,
            duration_minutes=8,
            novelty="low",
            need_review=False,
        )
        self.assertIn(
            trivial["primary"]["route"],
            {"codex-luna-high", "codex-luna-low", "agy-gemini-flash-low"},
        )

    def test_opus_can_overtake_for_judgment_heavy_debugging_but_not_as_general_top_writer(
        self,
    ) -> None:
        normal = self._route("deep-debug")
        self.assertIn(
            normal["primary"]["route"],
            {"codex-sol-high", "claude-fable-5-high", "claude-opus-4.8-high"},
        )
        judgment = self._route(
            "deep-debug",
            risk_flags=["judgment-critical", "uncertainty-heavy", "root-cause"],
        )
        self.assertEqual(judgment["primary"]["route"], "claude-opus-4.8-high")
        complex_patch = self._route("complex-patch")
        self.assertNotEqual(complex_patch["primary"]["route"], "claude-opus-4.8-high")

    def test_learning_requires_five_comparable_runs_and_ignores_access_probes(
        self,
    ) -> None:
        self.state["routes"] = {
            "codex-sol-high": {
                "by_task_class": {
                    "complex-patch": {
                        "runs": 4,
                        "first_pass_successes": 0,
                        "failures": 4,
                    }
                }
            }
        }
        self._write_state()
        pending = self._route("complex-patch")
        sol = next(
            item
            for item in [pending["primary"], *pending["fallbacks"]]
            if item["route"] == "codex-sol-high"
        )
        self.assertEqual(
            sol["adaptive_score"], -20.0 - 6.0
        )  # opaque quota cap + delegation only
        self.assertTrue(
            any("learning pending 4/5" in reason for reason in sol["reasons"])
        )

        self.state["routes"]["codex-sol-high"]["by_task_class"]["complex-patch"] = {
            "runs": 5,
            "first_pass_successes": 0,
            "failures": 5,
            "false_claims": 2,
            "scope_violations": 1,
            "rollbacks": 1,
            "average_rework_minutes": 30,
        }
        self._write_state()
        learned = self._route("complex-patch")
        sol_learned = next(
            item
            for item in [learned["primary"], *learned["fallbacks"]]
            if item["route"] == "codex-sol-high"
        )
        self.assertLess(sol_learned["adaptive_score"], sol["adaptive_score"])
        self.assertTrue(
            any(
                "evidenced outcome posterior" in reason
                for reason in sol_learned["reasons"]
            )
        )

    def test_quota_exhaustion_and_reserve_floor_fail_over_without_lowering_cost_guards(
        self,
    ) -> None:
        self.state["pools"]["openai-agentic"] = {
            "status": "exhausted",
            "reset_at": "2099-01-01T00:00:00Z",
        }
        self._write_state()
        result = self._route("complex-patch")
        self.assertEqual(result["primary"]["provider_family"], "anthropic")

        self.state = self._fresh_state()
        self.state["pools"]["claude-pro"] = {
            "status": "exhausted",
            "reset_at": "2099-01-01T00:00:00Z",
        }
        self._write_state()
        result = self._route("migration")
        self.assertEqual(result["primary"]["provider_family"], "openai")

        cline = router._pool_gate(
            "cline-account", self.catalog, self.state, critical=False
        )
        openrouter = router._pool_gate(
            "openrouter-paid", self.catalog, self.state, critical=True
        )
        self.assertFalse(cline[0])
        self.assertFalse(openrouter[0])

    def test_parent_quota_pool_is_enforced_even_when_route_omits_it(self) -> None:
        catalog = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in catalog["routes"] if item["id"] == "agy-gemini-pro-high"
        )
        route["quota_pools"] = ["agy-gemini"]
        self.assertEqual(
            router._route_quota_pools(route, catalog),
            ["agy-gemini", "agy-account"],
        )

        blocked_parent_states = (
            {
                "status": "exhausted",
                "reset_at": "2099-01-01T00:00:00Z",
            },
            {"active_sessions": 2},
            {"remaining_ratio": 0.10},
        )
        expected_reasons = (
            "agy-account: pool status exhausted",
            "agy-account: pool concurrency is saturated",
            "agy-account: reserve floor reached (0.15)",
        )
        for parent_state, expected_reason in zip(
            blocked_parent_states, expected_reasons, strict=True
        ):
            with self.subTest(parent_state=parent_state):
                state = self._fresh_state()
                state["pools"]["agy-account"] = parent_state
                score, _, _, reasons, exclusion, execution = router._score_route(
                    route,
                    "complex-patch",
                    catalog,
                    state,
                    changed_files=20,
                    duration_minutes=180,
                    novelty="high",
                    risk_flags=[],
                    latency_priority=False,
                    reviewer=False,
                    previous_group=None,
                    previous_provider=None,
                )
                self.assertIsNone(score)
                self.assertFalse(execution)
                self.assertIn(expected_reason, exclusion)
                self.assertIn(expected_reason, reasons)

    def test_runtime_pool_state_cannot_override_static_cost_or_payg_policy(
        self,
    ) -> None:
        self.state["pools"]["openrouter-paid"] = {
            "marginal_cost_usd": 0,
            "cost_mode": "subscription_included",
            "payg_fallback_allowed": False,
            "blocked_reason": None,
        }
        allowed, reasons, _, execution = router._pool_gate(
            "openrouter-paid", self.catalog, self.state, critical=True
        )
        self.assertFalse(allowed)
        self.assertFalse(execution)
        self.assertIn("forbidden fields", reasons[0])

        self.state["pools"]["cline-account"] = {"blocked_reason": ""}
        allowed, reasons, _, execution = router._pool_gate(
            "cline-account", self.catalog, self.state, critical=False
        )
        self.assertFalse(allowed)
        self.assertFalse(execution)
        self.assertIn("invalid pool state", reasons[0])

    def test_malformed_or_future_dated_pool_state_fails_closed(self) -> None:
        for malformed in (
            {"active_sessions": -1},
            {"remaining_ratio": 1.1},
            {"status": "invented"},
        ):
            state = self._fresh_state()
            state["pools"]["openai-agentic"] = malformed
            allowed, reasons, _, execution = router._pool_gate(
                "openai-agentic", self.catalog, state, critical=False
            )
            self.assertFalse(allowed)
            self.assertFalse(execution)
            self.assertIn("invalid pool state", reasons[0])

        future = (
            (datetime.now(timezone.utc) + timedelta(hours=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        state = self._fresh_state()
        state["pools"]["grok-com"] = {"verified_at": future}
        allowed, reasons, _, execution = router._pool_gate(
            "grok-com", self.catalog, state, critical=False
        )
        self.assertFalse(allowed)
        self.assertFalse(execution)
        self.assertIn("future-dated", reasons[0])

    def test_catalog_state_history_and_authentication_validation_fail_closed(
        self,
    ) -> None:
        broken_catalog = json.loads(json.dumps(self.catalog))
        broken_catalog["routes"][0]["task_classes"].append("invented-task")
        with self.assertRaisesRegex(router.CodingAgentRouterError, "task classes"):
            router._validate_catalog(broken_catalog)

        invalid_history = {
            "routes": {
                "codex-sol-high": {
                    "runs": 5,
                    "first_pass_successes": 6,
                    "failures": 0,
                }
            }
        }
        adjustment, reasons = router._outcome_adjustment(
            "codex-sol-high",
            "complex-patch",
            invalid_history,
            self.catalog["policy"]["adaptive_learning"],
        )
        self.assertEqual(adjustment, 0.0)
        self.assertIn("inconsistent counters", reasons[0])

        grok_route = next(
            route for route in self.catalog["routes"] if route["id"] == "grok-4.5-high"
        )
        logged_out_state = self._fresh_state()
        logged_out_state["catalog"]["providers"]["grok"]["logged_in"] = False
        available, reason = router._route_available(
            grok_route, self.catalog, logged_out_state
        )
        self.assertFalse(available)
        self.assertIn("authentication", reason)

    def test_reviewers_are_provider_independent_and_claude_models_are_not_independent(
        self,
    ) -> None:
        for task_class in (
            "complex-patch",
            "deep-debug",
            "architecture",
            "critical-review",
            "security-review",
        ):
            result = self._route(task_class)
            self.assertEqual(result["review_gap"], 0)
            self.assertNotEqual(
                result["primary"]["provider_family"],
                result["reviewers"][0]["provider_family"],
            )
        fable_primary = self._route("migration")
        self.assertEqual(fable_primary["primary"]["provider_family"], "anthropic")
        self.assertEqual(fable_primary["reviewers"][0]["provider_family"], "openai")

    def test_jules_is_a_managed_harness_not_a_ranked_model_claim(self) -> None:
        model = self.catalog["models"]["jules-managed-latest"]
        self.assertEqual(model["identity_kind"], "managed-harness-placeholder")
        self.assertTrue(model["exclude_from_model_hierarchy"])
        hierarchy_models = {
            model_id
            for group in self.catalog["policy"]["quality_classes"].values()
            for model_id in group["models"]
        }
        self.assertNotIn("jules-managed-latest", hierarchy_models)

    def test_missing_stale_or_mismatched_state_requires_a_probe(self) -> None:
        self.state_path.unlink()
        self.assertEqual(self._route("complex-patch")["decision"], "probe-required")
        self.state = self._fresh_state()
        self.state["catalog"]["observed_at"] = (
            (datetime.now(timezone.utc) - timedelta(hours=2))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        self._write_state()
        self.assertEqual(self._route("complex-patch")["decision"], "probe-required")
        self.state = self._fresh_state()
        self.state["catalog_sha256"] = "0" * 64
        self._write_state()
        self.assertEqual(self._route("complex-patch")["decision"], "probe-required")

    def test_controller_owned_work_never_routes_to_an_external_writer(self) -> None:
        result = self._route("deployment")
        self.assertEqual(result["decision"], "controller")
        self.assertFalse(result["automatic_execution_authorized"])

    def test_request_validation_rejects_coercive_values(self) -> None:
        with self.assertRaisesRegex(router.CodingAgentRouterError, "boolean"):
            router.grabowski_coding_agent_catalog(include_disabled="false")  # type: ignore[arg-type]
        with self.assertRaisesRegex(router.CodingAgentRouterError, "changed_files"):
            router.grabowski_coding_agent_route("complex-patch", changed_files=True)  # type: ignore[arg-type]
        with self.assertRaisesRegex(router.CodingAgentRouterError, "unknown"):
            router.grabowski_coding_agent_route("invented-task")
        with self.assertRaisesRegex(router.CodingAgentRouterError, "novelty"):
            router.grabowski_coding_agent_route(
                "complex-patch",
                novelty=["high"],  # type: ignore[arg-type]
            )

    def test_recommendation_never_grants_execution_merge_or_parallel_writer_authority(
        self,
    ) -> None:
        result = self._route("complex-patch")
        self.assertEqual(result["decision"], "route")
        self.assertFalse(result["automatic_execution_authorized"])
        self.assertTrue(result["single_mutating_writer"])
        self.assertTrue(result["external_results_advisory"])
        self.assertIn("execution_authority", result["does_not_establish"])
        self.assertIn("merge_readiness", result["does_not_establish"])

    def test_runtime_capability_and_packaging_integration_is_declared(self) -> None:
        runtime = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        mcp_source = (ROOT / "src" / "grabowski_mcp.py").read_text(encoding="utf-8")
        capabilities = (ROOT / "src" / "grabowski_capabilities.py").read_text(
            encoding="utf-8"
        )
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("import grabowski_coding_agent_router", runtime)
        for tool_name in (
            "grabowski_coding_agent_catalog",
            "grabowski_coding_agent_route",
        ):
            self.assertIn(f'"{tool_name}": ()', mcp_source)
            self.assertIn(f'"{tool_name}": {{', capabilities)
        self.assertIn('"grabowski_coding_agent_router"', pyproject)

    def test_module_exposes_both_read_only_tool_functions(self) -> None:
        self.assertTrue(callable(router.grabowski_coding_agent_catalog))
        self.assertTrue(callable(router.grabowski_coding_agent_route))


if __name__ == "__main__":
    unittest.main()
