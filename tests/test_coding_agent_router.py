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
            policy["top_contrast_routes"],
            ["codex-sol-high", "claude-fable-5-contrast-high"],
        )
        direct = result["direct_work_policy"]
        self.assertEqual(direct["canonical_primary"], "grabowski-primary")
        self.assertTrue(direct["direct_implementation_required"])
        self.assertTrue(direct["applies_to_all_implementation_sizes"])
        self.assertTrue(direct["external_primary_writer_forbidden"])
        self.assertFalse(direct["capacity_fallback_to_external_writer"])
        self.assertEqual(direct["external_agent_roles"], ["review", "contrast"])
        self.assertFalse(result["provider_peer_balance"]["enabled"])
        self.assertEqual(result["provider_peer_balance"]["selection_effect"], 0)
        self.assertFalse(result["automatic_execution_authorized"])

        fable_routes = {
            route["route"]: route
            for model in result["models"]
            if model["id"] == "claude-fable-5"
            for route in model["routes"]
        }
        legacy = fable_routes["claude-fable-5-high"]
        self.assertFalse(legacy["enabled"])
        self.assertEqual(legacy["route_role"], "reviewer")
        self.assertFalse(legacy["writer_capable"])
        self.assertTrue(legacy["review_only"])

        retired = fable_routes["claude-fable-5-writer-high"]
        self.assertFalse(retired["enabled"])
        self.assertEqual(retired["route_role"], "contrast")
        self.assertFalse(retired["writer_capable"])
        self.assertTrue(retired["contrast_capable"])

        contrast = fable_routes["claude-fable-5-contrast-high"]
        self.assertTrue(contrast["enabled"])
        self.assertEqual(contrast["route_role"], "contrast")
        self.assertTrue(contrast["contrast_only"])
        self.assertTrue(contrast["contrast_capable"])
        self.assertFalse(contrast["writer_capable"])
        self.assertFalse(contrast["review_capable"])

        reviewer = fable_routes["claude-fable-5-review-high"]
        self.assertEqual(reviewer["route_role"], "reviewer")
        self.assertFalse(reviewer["writer_capable"])
        self.assertFalse(reviewer["contrast_capable"])
        self.assertTrue(reviewer["review_capable"])
        for model in result["models"]:
            for public_route in model["routes"]:
                if public_route["route"] != "grabowski-primary":
                    self.assertFalse(public_route["writer_capable"])
                self.assertNotIn("role", public_route)

    def test_direct_first_policy_contract_fails_closed_on_drift(self) -> None:
        cases = [
            (
                lambda catalog: catalog["policy"].pop("direct_work_policy"),
                "direct_work_policy is missing",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"].__setitem__(
                    "capacity_fallback_to_external_writer", True
                ),
                "capacity_fallback_to_external_writer must be false",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"].__setitem__(
                    "external_agent_roles", ["writer", "review"]
                ),
                "external_agent_roles",
            ),
            (
                lambda catalog: next(
                    route
                    for route in catalog["routes"]
                    if route["id"] == "grabowski-primary"
                )["task_classes"].remove("migration"),
                "controller route must own every authoritative task class",
            ),
            (
                lambda catalog: catalog["policy"]["frontier_model_policy"].__setitem__(
                    "top_contrast_routes", ["claude-fable-5-review-high"]
                ),
                "top contrast route",
            ),
        ]
        for mutate, message in cases:
            with self.subTest(message=message):
                catalog = json.loads(json.dumps(self.catalog))
                mutate(catalog)
                with self.assertRaisesRegex(router.CodingAgentRouterError, message):
                    router._validate_catalog(catalog)

    def test_fable_writer_and_reviewer_have_separate_permission_modes(self) -> None:
        routes = {route["id"]: route for route in self.catalog["routes"]}
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        legacy = routes["claude-fable-5-high"]
        retired = routes["claude-fable-5-writer-high"]
        contrast = routes["claude-fable-5-contrast-high"]
        reviewer = routes["claude-fable-5-review-high"]
        self.assertFalse(legacy["enabled"])
        self.assertEqual(public[legacy["id"]]["permission_mode"], "plan")
        self.assertTrue(legacy["review_only"])
        self.assertIn("Compatibility alias", legacy["disabled_reason"])
        self.assertFalse(retired["enabled"])
        self.assertTrue(retired["contrast_only"])
        self.assertEqual(public[retired["id"]]["permission_mode"], "acceptEdits")
        self.assertTrue(contrast["enabled"])
        self.assertIn("--safe-mode", contrast["argv_prefix"])
        self.assertIn("claude-fable-5", contrast["argv_prefix"])
        self.assertEqual(public[contrast["id"]]["permission_mode"], "acceptEdits")
        self.assertTrue(contrast["contrast_only"])
        self.assertEqual(public[reviewer["id"]]["permission_mode"], "plan")
        self.assertTrue(reviewer["review_only"])
        self.assertEqual(
            reviewer["task_classes"],
            ["independent-review", "critical-review", "security-review"],
        )

    def test_permission_mode_projection_accepts_reordered_and_equals_forms(self) -> None:
        catalog = json.loads(json.dumps(self.catalog))
        routes = {route["id"]: route for route in catalog["routes"]}
        routes["claude-fable-5-review-high"]["argv_prefix"] = [
            "claude",
            "--model",
            "claude-fable-5",
            "--permission-mode=plan",
            "-p",
            "--safe-mode",
            "--effort",
            "high",
        ]
        routes["claude-fable-5-writer-high"]["argv_prefix"] = [
            "claude",
            "--model",
            "claude-fable-5",
            "--effort",
            "high",
            "--permission-mode=acceptEdits",
            "-p",
            "--safe-mode",
        ]
        self.catalog_path.write_text(json.dumps(catalog))
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)[
                "models"
            ]
            for route in model["routes"]
        }
        self.assertEqual(
            public["claude-fable-5-review-high"]["permission_mode"], "plan"
        )
        self.assertEqual(
            public["claude-fable-5-writer-high"]["permission_mode"], "acceptEdits"
        )

    def test_route_derivations_are_built_once_for_primary_and_review_ranking(
        self,
    ) -> None:
        original = router._route_capabilities
        calls: list[str] = []

        def counted(
            route: dict[str, object],
            catalog: dict[str, object],
            review_task_classes: frozenset[str] | None = None,
        ) -> dict[str, object]:
            calls.append(str(route["id"]))
            return original(route, catalog, review_task_classes)

        with mock.patch.object(router, "_route_capabilities", side_effect=counted):
            result = self._route("complex-patch", need_review=True)

        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["primary_role"], "direct-writer")
        self.assertEqual(len(calls), len(self.catalog["routes"]))
        self.assertEqual(set(calls), {route["id"] for route in self.catalog["routes"]})

    def test_permission_mode_validation_fails_closed_for_malformed_argv(self) -> None:
        cases = [
            (None, "invalid argv_prefix"),
            (["claude", ""], "invalid argv_prefix"),
            (["claude", "--permission-mode"], "missing a value"),
            (["claude", "--permission-mode", "-p"], "missing a value"),
            (["claude", "--permission-mode="], "empty value"),
            (
                [
                    "claude",
                    "--permission-mode",
                    "plan",
                    "--approval-mode=acceptEdits",
                ],
                "conflicting permission modes",
            ),
        ]
        for argv_prefix, message in cases:
            with self.subTest(argv_prefix=argv_prefix):
                catalog = json.loads(json.dumps(self.catalog))
                route = next(
                    route
                    for route in catalog["routes"]
                    if route["id"] == "claude-fable-5-review-high"
                )
                route["argv_prefix"] = argv_prefix
                self.catalog_path.write_text(json.dumps(catalog))
                with self.assertRaisesRegex(router.CodingAgentRouterError, message):
                    router.grabowski_coding_agent_catalog(include_disabled=True)

    def test_every_public_plan_route_is_review_only_and_non_writer(self) -> None:
        result = router.grabowski_coding_agent_catalog(include_disabled=True)
        public_routes = {
            route["route"]: route
            for model in result["models"]
            for route in model["routes"]
        }
        plan_routes = [
            route
            for route in public_routes.values()
            if route["permission_mode"] == "plan"
        ]
        self.assertTrue(plan_routes)
        for public in plan_routes:
            with self.subTest(route=public["route"]):
                self.assertTrue(public["review_only"])
                self.assertFalse(public["writer_capable"])
                self.assertTrue(public["review_capable"])

    def test_route_role_contract_rejects_ambiguous_or_mutating_plan_routes(self) -> None:
        invalid_boolean = json.loads(json.dumps(self.catalog))
        invalid_boolean["routes"][1]["contrast_only"] = "true"
        with self.assertRaisesRegex(router.CodingAgentRouterError, "boolean"):
            router._validate_catalog(invalid_boolean)

        retired_writer_flag = json.loads(json.dumps(self.catalog))
        retired_writer_flag["routes"][0]["writer_only"] = True
        with self.assertRaisesRegex(router.CodingAgentRouterError, "writer_only is retired"):
            router._validate_catalog(retired_writer_flag)

        ambiguous = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in ambiguous["routes"]
            if item["id"] == "claude-fable-5-contrast-high"
        )
        route["review_only"] = True
        with self.assertRaisesRegex(router.CodingAgentRouterError, "mutually exclusive"):
            router._validate_catalog(ambiguous)

        contrast_in_plan_mode = json.loads(json.dumps(self.catalog))
        contrast = next(
            item for item in contrast_in_plan_mode["routes"]
            if item["id"] == "claude-fable-5-contrast-high"
        )
        mode_index = contrast["argv_prefix"].index("--permission-mode")
        contrast["argv_prefix"][mode_index + 1] = "plan"
        with self.assertRaisesRegex(router.CodingAgentRouterError, "cannot use plan"):
            router._validate_catalog(contrast_in_plan_mode)

        unmarked_plan_route = json.loads(json.dumps(self.catalog))
        review_route = next(
            item for item in unmarked_plan_route["routes"]
            if item["id"] == "claude-fable-5-review-high"
        )
        del review_route["review_only"]
        with self.assertRaisesRegex(router.CodingAgentRouterError, "must be review_only"):
            router._validate_catalog(unmarked_plan_route)

        contrast_with_review_task = json.loads(json.dumps(self.catalog))
        contrast = next(
            item for item in contrast_with_review_task["routes"]
            if item["id"] == "claude-fable-5-contrast-high"
        )
        contrast["task_classes"].append("independent-review")
        with self.assertRaisesRegex(router.CodingAgentRouterError, "no review tasks"):
            router._validate_catalog(contrast_with_review_task)

        contrast_without_task = json.loads(json.dumps(self.catalog))
        contrast = next(
            item for item in contrast_without_task["routes"]
            if item["id"] == "claude-fable-5-contrast-high"
        )
        contrast["task_classes"] = []
        with self.assertRaisesRegex(router.CodingAgentRouterError, "must have contrast"):
            router._validate_catalog(contrast_without_task)

        reviewer_with_contrast_task = json.loads(json.dumps(self.catalog))
        reviewer = next(
            item for item in reviewer_with_contrast_task["routes"]
            if item["id"] == "claude-fable-5-review-high"
        )
        reviewer["task_classes"].append("complex-patch")
        with self.assertRaisesRegex(router.CodingAgentRouterError, "no contrast tasks"):
            router._validate_catalog(reviewer_with_contrast_task)

        reviewer_without_review_task = json.loads(json.dumps(self.catalog))
        reviewer = next(
            item for item in reviewer_without_review_task["routes"]
            if item["id"] == "claude-fable-5-review-high"
        )
        reviewer["task_classes"] = []
        with self.assertRaisesRegex(router.CodingAgentRouterError, "must have review"):
            router._validate_catalog(reviewer_without_review_task)

        enabled_without_capability = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in enabled_without_capability["routes"]
            if item["id"] == "aider-local-14b"
        )
        route["enabled"] = True
        route["task_classes"] = []
        route.pop("contrast_only", None)
        with self.assertRaisesRegex(router.CodingAgentRouterError, "no review or contrast capability"):
            router._validate_catalog(enabled_without_capability)

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

    def test_sol_and_fable_are_top_contrast_peers_without_becoming_writers(
        self,
    ) -> None:
        result = self._route("complex-patch")
        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["controller"], "grabowski-primary")
        self.assertEqual(result["primary_role"], "direct-writer")
        self.assertNotIn("primary", result)
        self.assertNotIn("co_primaries", result)
        policy = router.grabowski_coding_agent_catalog(include_disabled=True)[
            "frontier_model_policy"
        ]
        self.assertEqual(
            policy["top_contrast_routes"],
            ["codex-sol-high", "claude-fable-5-contrast-high"],
        )
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        for route_id in policy["top_contrast_routes"]:
            self.assertTrue(public[route_id]["contrast_capable"])
            self.assertFalse(public[route_id]["writer_capable"])

    def test_task_specific_defaults_keep_all_implementation_direct(self) -> None:
        for task_class, kwargs in (
            ("complex-patch", {}),
            ("migration", {"duration_minutes": 300}),
            ("architecture", {}),
            ("bounded-patch", {"changed_files": 4, "duration_minutes": 45}),
            ("mechanical", {"changed_files": 1, "duration_minutes": 8, "novelty": "low"}),
        ):
            with self.subTest(task_class=task_class):
                result = self._route(task_class, **kwargs)
                self.assertEqual(result["decision"], "controller")
                self.assertEqual(result["controller"], "grabowski-primary")
                self.assertEqual(result["primary_role"], "direct-writer")
                self.assertTrue(result["direct_implementation_required"])
                self.assertTrue(result["external_primary_writer_forbidden"])

        security = self._route(
            "security-review", duration_minutes=120, risk_flags=["security-sensitive"]
        )
        self.assertEqual(security["decision"], "route")
        self.assertEqual(security["primary_role"], "reviewer")
        self.assertTrue(security["primary"]["review_capable"])
        self.assertTrue(security["authoritative_implementation_remains_direct"])

    def test_opus_plan_route_is_reserved_for_review_and_never_becomes_writer(
        self,
    ) -> None:
        for task_class in ("deep-debug", "complex-patch", "architecture"):
            result = self._route(task_class)
            self.assertEqual(result["decision"], "controller")
            self.assertEqual(result["primary_role"], "direct-writer")
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        opus = public["claude-opus-4.8-high"]
        self.assertEqual(opus["permission_mode"], "plan")
        self.assertTrue(opus["review_only"])
        self.assertTrue(opus["review_capable"])
        self.assertFalse(opus["contrast_capable"])
        self.assertFalse(opus["writer_capable"])

    def test_learning_applies_to_review_routes_not_authoritative_writing(
        self,
    ) -> None:
        route_id = "claude-fable-5-review-high"
        self.state["routes"] = {
            route_id: {
                "by_task_class": {
                    "independent-review": {
                        "runs": 4,
                        "first_pass_successes": 0,
                        "failures": 4,
                    }
                }
            }
        }
        self._write_state()
        pending = self._route("independent-review")
        candidates = [pending["primary"], *pending["fallbacks"]]
        fable = next(item for item in candidates if item["route"] == route_id)
        self.assertTrue(any("learning pending 4/5" in reason for reason in fable["reasons"]))
        pending_score = fable["adaptive_score"]

        self.state["routes"][route_id]["by_task_class"]["independent-review"] = {
            "runs": 5,
            "first_pass_successes": 0,
            "failures": 5,
            "false_claims": 2,
            "scope_violations": 1,
            "rollbacks": 1,
            "average_rework_minutes": 30,
        }
        self._write_state()
        learned = self._route("independent-review")
        candidates = [learned["primary"], *learned["fallbacks"]]
        fable_learned = next(item for item in candidates if item["route"] == route_id)
        self.assertLess(fable_learned["adaptive_score"], pending_score)
        self.assertTrue(
            any("evidenced outcome posterior" in reason for reason in fable_learned["reasons"])
        )
        coding = self._route("complex-patch", need_review=False)
        self.assertEqual(coding["decision"], "controller")

    def test_quota_exhaustion_affects_review_not_direct_implementation(
        self,
    ) -> None:
        self.state["pools"]["openai-agentic"] = {
            "status": "exhausted",
            "reset_at": "2099-01-01T00:00:00Z",
        }
        self._write_state()
        coding = self._route("complex-patch", need_review=False)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["controller"], "grabowski-primary")

        self.state = self._fresh_state()
        self.state["pools"]["claude-pro"] = {
            "status": "exhausted",
            "reset_at": "2099-01-01T00:00:00Z",
        }
        self._write_state()
        review = self._route("independent-review")
        self.assertEqual(review["decision"], "route")
        self.assertNotEqual(review["primary"]["provider_family"], "anthropic")

        cline = router._pool_gate("cline-account", self.catalog, self.state, critical=False)
        openrouter = router._pool_gate("openrouter-paid", self.catalog, self.state, critical=True)
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

    def test_external_reviewers_are_independent_from_direct_operator(self) -> None:
        for task_class in ("complex-patch", "deep-debug", "architecture"):
            result = self._route(task_class, need_review=True)
            self.assertEqual(result["decision"], "controller")
            self.assertEqual(result["primary_role"], "direct-writer")
            self.assertEqual(result["review_gap"], 0)
            self.assertNotEqual(
                result["reviewers"][0]["provider_family"],
                "openai",
            )
        for task_class in ("critical-review", "security-review"):
            review = self._route(task_class)
            self.assertEqual(review["primary_role"], "reviewer")
            self.assertTrue(review["primary"]["review_capable"])
            self.assertNotEqual(review["primary"]["provider_family"], "openai")
            self.assertEqual(review["review_gap"], 0)
            self.assertTrue(review["reviewers"][0]["review_capable"])
            self.assertNotEqual(
                review["primary"]["provider_family"],
                review["reviewers"][0]["provider_family"],
            )

    def test_fable_contrast_and_review_routes_never_become_primary_writer(self) -> None:
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["primary_role"], "direct-writer")
        self.assertNotIn("primary", coding)
        self.assertFalse(
            any(reviewer["route"] == "claude-fable-5-contrast-high" for reviewer in coding["reviewers"])
        )

        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        retired = public["claude-fable-5-writer-high"]
        contrast = public["claude-fable-5-contrast-high"]
        reviewer = public["claude-fable-5-review-high"]
        self.assertFalse(retired["enabled"])
        self.assertFalse(retired["writer_capable"])
        self.assertTrue(contrast["contrast_capable"])
        self.assertFalse(contrast["review_capable"])
        self.assertFalse(contrast["writer_capable"])
        self.assertTrue(reviewer["review_capable"])
        self.assertFalse(reviewer["contrast_capable"])
        self.assertFalse(reviewer["writer_capable"])

        review = self._route("independent-review")
        all_review_routes = {review["primary"]["route"], *(item["route"] for item in review["fallbacks"])}
        self.assertNotIn("claude-fable-5-contrast-high", all_review_routes)
        self.assertNotIn("claude-fable-5-writer-high", all_review_routes)

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

    def test_direct_work_survives_missing_state_while_review_routing_probes(self) -> None:
        self.state_path.unlink()
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["review_status"], "router-state-unavailable")
        self.assertEqual(self._route("independent-review")["decision"], "probe-required")

        self.state = self._fresh_state()
        self.state["catalog"]["observed_at"] = (
            (datetime.now(timezone.utc) - timedelta(hours=2))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        self._write_state()
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["review_status"], "router-state-stale")
        self.assertEqual(self._route("independent-review")["decision"], "probe-required")

        self.state = self._fresh_state()
        self.state["catalog_sha256"] = "0" * 64
        self._write_state()
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["review_status"], "router-state-catalog-mismatch")
        self.assertEqual(self._route("independent-review")["decision"], "probe-required")

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

    def test_recommendation_keeps_all_authoritative_work_direct(
        self,
    ) -> None:
        result = self._route("complex-patch")
        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["controller"], "grabowski-primary")
        self.assertEqual(result["primary_role"], "direct-writer")
        self.assertTrue(result["direct_implementation_required"])
        self.assertTrue(result["external_primary_writer_forbidden"])
        self.assertFalse(result["capacity_fallback_to_external_writer"])
        self.assertFalse(result["automatic_execution_authorized"])
        self.assertTrue(result["single_mutating_writer"])
        self.assertTrue(result["external_results_advisory"])
        self.assertTrue(result["contrast_programming"]["requires_explicit_request"])
        self.assertFalse(result["contrast_programming"]["automatic_patch_apply"])
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
