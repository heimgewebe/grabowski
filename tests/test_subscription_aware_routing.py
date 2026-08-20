from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "coding-agent-catalog.json"


class SubscriptionAwareRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        cls.routes = {route["id"]: route for route in cls.catalog["routes"]}

    def test_subscription_baselines_never_authorize_overage_or_api_payg(self) -> None:
        expected_plans = {
            "openai-agentic": "ChatGPT Pro",
            "claude-pro": "Claude Pro",
            "grok-com": "SuperGrok",
            "antigravity-account": "Google AI subscription",
            "jules-account": "Google AI subscription",
        }
        for pool_id, plan in expected_plans.items():
            with self.subTest(pool=pool_id):
                pool = self.catalog["quota_pools"][pool_id]
                self.assertEqual(pool["cost_mode"], "subscription_included")
                self.assertEqual(pool["plan"], plan)
                self.assertEqual(pool["marginal_cost_usd"], 0)
                self.assertFalse(pool["payg_fallback_allowed"])
                self.assertFalse(pool["credits_allowed"])
                self.assertFalse(pool["automatic_overage"])
                self.assertEqual(pool["overage_action"], "block_and_surface")

    def test_supergrok_pool_requires_exact_oidc_entitlement_claim(self) -> None:
        contract = self.catalog["quota_pools"]["grok-com"]["entitlement_contract"]
        self.assertEqual(
            contract,
            {
                "kind": "grok_oidc_tier_claim_v1",
                "issuer": "https://auth.x.ai",
                "principal_type": "User",
                "tier_code": 1,
                "plan": "SuperGrok",
            },
        )

    def test_provider_specific_paid_surfaces_are_explicitly_excluded(self) -> None:
        expected = {
            "openai-agentic": {"openai-api", "purchased-codex-credits"},
            "claude-pro": {"anthropic-api", "usage-credits"},
            "grok-com": {"xai-api", "extra-usage-credits", "pay-as-you-go-overage"},
            "antigravity-account": {
                "vertex-ai-api",
                "google-ai-studio-api",
                "purchased-ai-credits",
            },
        }
        for pool_id, excluded in expected.items():
            with self.subTest(pool=pool_id):
                self.assertEqual(
                    set(self.catalog["quota_pools"][pool_id]["excluded_cost_surfaces"]),
                    excluded,
                )

    def test_subscription_policy_is_quality_first_without_provider_balancing(self) -> None:
        policy = self.catalog["policy"]["subscription_routing_policy"]
        self.assertTrue(policy["baseline_quota_only"])
        self.assertEqual(policy["automatic_overage"], "forbidden")
        self.assertEqual(policy["quota_exhaustion_action"], "block_and_surface")
        self.assertFalse(policy["traffic_balancing_by_provider"])
        self.assertEqual(
            policy["route_selection"],
            "quality_and_task_fit_within_remaining_subscription_baselines",
        )

    def test_live_verified_models_replace_stale_generation_defaults(self) -> None:
        models = self.catalog["models"]
        self.assertEqual(models["claude-opus-5"]["availability"], "live-verified-via-claude-pro")
        self.assertEqual(models["claude-sonnet-5"]["availability"], "live-verified-via-claude-pro")
        self.assertEqual(models["gemini-3.1-pro"]["availability"], "live-verified-via-google-ai")
        self.assertEqual(models["gpt-5.6-sol"]["availability"], "live-verified-via-chatgpt-pro")
        self.assertEqual(models["grok-4.5"]["availability"], "live-verified-via-supergrok")
        self.assertEqual(models["gemini-3.6-flash"]["availability"], "live-listed")
        self.assertEqual(models["claude-opus-4.8"]["availability"], "compatibility-only-superseded")

    def test_fable_is_never_treated_as_claude_pro_baseline(self) -> None:
        self.assertEqual(
            self.catalog["models"]["claude-fable-5"]["availability"],
            "usage-credits-required",
        )
        routes = [route for route in self.catalog["routes"] if route.get("model") == "claude-fable-5"]
        self.assertTrue(routes)
        for route in routes:
            with self.subTest(route=route["id"]):
                self.assertTrue(route["paid_only"])
                self.assertNotIn("--max-budget-usd", route["argv_prefix"])
                if route["enabled"]:
                    self.assertIn("usage-credits-required", route["paid_reason"])
                    self.assertNotIn("disabled_reason", route)

    def test_direct_claude_routes_share_one_subscription_lineage(self) -> None:
        groups = {
            route["independence_group"]
            for route in self.catalog["routes"]
            if route.get("harness") == "claude" and "claude-pro" in route.get("quota_pools", [])
        }
        self.assertEqual(groups, {"anthropic-claude-pro"})

    def test_independent_subscription_review_routes_are_executable_and_advisory(self) -> None:
        expected = {
            "claude-opus-5-high": ("claude", "anthropic-claude-pro"),
            "antigravity-gemini-pro-review-high": ("antigravity", "google-gemini-pro"),
            "grok-4.5-review-high": ("grok", "xai-grok-4.5"),
        }
        for route_id, (harness, group) in expected.items():
            with self.subTest(route=route_id):
                route = self.routes[route_id]
                self.assertTrue(route["enabled"])
                self.assertTrue(route["review_only"])
                self.assertEqual(route["harness"], harness)
                self.assertEqual(route["independence_group"], group)
                self.assertIn("independent-review", route["task_classes"])
                self.assertIn("critical-review", route["task_classes"])

    def test_external_codex_routes_remain_contrast_only_except_attested_spark_writer(self) -> None:
        routes = [route for route in self.catalog["routes"] if route.get("harness") == "codex"]
        self.assertTrue(routes)
        spark = self.routes["codex-spark-low"]
        self.assertFalse(spark.get("contrast_only", False))
        self.assertEqual(["openai-codex-spark"], spark["quota_pools"])
        self.assertEqual(["mechanical", "triage", "docs", "tests"], spark["task_classes"])
        legacy_routes = [route for route in routes if route["id"] != "codex-spark-low"]
        self.assertTrue(legacy_routes)
        self.assertTrue(all(route.get("contrast_only") is True for route in legacy_routes))

    def test_runtime_command_prefixes_do_not_duplicate_runner_owned_flags(self) -> None:
        self.assertEqual(
            self.routes["claude-opus-5-high"]["argv_prefix"],
            [
                "claude",
                "--model",
                "opus",
                "--effort",
                "high",
                "--permission-mode",
                "plan",
            ],
        )
        self.assertEqual(
            self.routes["antigravity-gemini-pro-review-high"]["argv_prefix"],
            ["agy", "--model", "gemini-3.1-pro-high"],
        )
        self.assertEqual(
            self.routes["grok-4.5-review-high"]["argv_prefix"],
            ["grok", "--model", "grok-4.5"],
        )


if __name__ == "__main__":
    unittest.main()
