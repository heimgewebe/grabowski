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
                router.CATALOG_OVERRIDE_ENV: "1",
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
                    if route["harness"] == "antigravity":
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
                            "claude-opus-5",
                            "claude-sonnet-5",
                        ],
                    },
                    "antigravity": {"models": sorted(set(agy_models))},
                    "grok": {
                        "logged_in": True,
                        "models": sorted(set(grok_models)),
                    },
                    "opencode": {
                        "free_model_verified": True,
                        "models": [
                            "opencode/deepseek-v4-flash-free",
                            "openrouter/stealth/ox-alpha",
                        ],
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

    def test_implicit_user_catalog_does_not_override_deployment_catalog(self) -> None:
        home = self.root / "home"
        stale = home / ".config" / "grabowski" / "coding-agent-catalog.json"
        stale.parent.mkdir(parents=True)
        stale_catalog = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in stale_catalog["routes"] if item["id"] == "claude-fable-5-high"
        )
        route.pop("review_only", None)
        stale.write_text(json.dumps(stale_catalog), encoding="utf-8")
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(Path, "home", return_value=home),
        ):
            self.assertEqual(
                router._catalog_path(),
                ROOT / "config" / "coding-agent-catalog.json",
            )
            health = router.coding_agent_catalog_health()
        self.assertTrue(health["ready"])
        self.assertEqual(health["source"], "deployment_catalog")

    def test_installed_module_resolves_release_scoped_catalog_from_named_venv(self) -> None:
        release = self.root / "release"
        environment = release / "runtime-env"
        catalog = release / "config" / "coding-agent-catalog.json"
        catalog.parent.mkdir(parents=True)
        catalog.write_text(json.dumps(self.catalog), encoding="utf-8")
        module = environment / "lib/python3.10/site-packages/grabowski_coding_agent_router.py"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(router, "__file__", str(module)),
            mock.patch.object(router.sys, "prefix", str(environment)),
            mock.patch.object(router.sys, "base_prefix", "/usr"),
        ):
            health = router.coding_agent_catalog_health()
        self.assertTrue(health["ready"])
        self.assertEqual(health["source"], "deployment_catalog")
        self.assertEqual(health["path"], str(catalog))

    def test_virtualenv_prefix_does_not_capture_module_outside_prefix(self) -> None:
        environment = self.root / "runtime-env"
        module = self.root / "source" / "src" / "grabowski_coding_agent_router.py"
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(router, "__file__", str(module)),
            mock.patch.object(router.sys, "prefix", str(environment)),
            mock.patch.object(router.sys, "base_prefix", "/usr"),
        ):
            self.assertEqual(
                router._catalog_path(),
                self.root / "source" / "config" / "coding-agent-catalog.json",
            )

    def test_global_prefix_does_not_masquerade_as_release(self) -> None:
        module = Path("/usr/local/lib/python3.10/site-packages/grabowski_coding_agent_router.py")
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(router, "__file__", str(module)),
            mock.patch.object(router.sys, "prefix", "/usr"),
            mock.patch.object(router.sys, "base_prefix", "/usr"),
        ):
            self.assertEqual(
                router._catalog_path(),
                Path("/usr/local/lib/python3.10/config/coding-agent-catalog.json"),
            )

    def test_explicit_invalid_catalog_is_reported_by_health(self) -> None:
        invalid = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in invalid["routes"] if item["id"] == "claude-fable-5-high"
        )
        route.pop("review_only", None)
        self.catalog_path.write_text(json.dumps(invalid), encoding="utf-8")
        health = router.coding_agent_catalog_health()
        self.assertFalse(health["ready"])
        self.assertEqual(health["source"], "environment-override")
        self.assertIn("plan-mode route must be review_only", health["error"])

    def test_catalog_declares_correct_quality_and_effort_hierarchy(self) -> None:
        result = router.grabowski_coding_agent_catalog(include_disabled=True)
        self.assertTrue(result["validation"]["valid"])
        policy = result["frontier_model_policy"]
        self.assertEqual(policy["top_contrast_routes"], ["codex-sol-high"])
        self.assertEqual(
            policy["paid_contrast_routes"], ["claude-fable-5-contrast-high"]
        )
        self.assertTrue(
            self.catalog["policy"]["paid_routes_require_explicit_authorization"]
        )
        self.assertTrue(self.catalog["policy"]["zero_marginal_cost_only"])
        self.assertEqual(
            self.catalog["policy"]["zero_marginal_cost_only_scope"],
            "automatic-and-legacy-provider-only-routes",
        )
        self.assertEqual(
            self.catalog["policy"]["explicit_paid_route_exceptions"],
            ["claude-fable-5-contrast-high"],
        )
        direct = result["direct_work_policy"]
        self.assertEqual(direct["canonical_primary"], "grabowski-primary")
        self.assertFalse(direct["direct_implementation_required"])
        self.assertTrue(direct["applies_to_all_implementation_sizes"])
        self.assertFalse(direct["external_primary_writer_forbidden"])
        self.assertTrue(direct["external_primary_reviewer_forbidden"])
        self.assertTrue(direct["capacity_fallback_to_external_writer"])
        self.assertTrue(direct["delegated_scoped_writers_allowed"])
        self.assertEqual(
            direct["external_agent_roles"],
            ["scoped_writer", "reviewer", "observer"],
        )
        self.assertEqual(
            direct["single_mutating_writer_scope"],
            "overlapping-resource-lane",
        )
        self.assertIn("review", direct["operator_owns"])
        self.assertIn("upper_review_or_contrast_routes", policy)
        self.assertNotIn("upper_work_routes", policy)
        self.assertFalse(result["provider_peer_balance"]["enabled"])
        self.assertEqual(result["provider_peer_balance"]["selection_effect"], 0)
        self.assertTrue(result["automatic_execution_authorized"])
        self.assertEqual(
            result["automatic_execution_authorization_scope"],
            "trusted-owner-or-explicit-mandate",
        )
        self.assertTrue(
            self.catalog["policy"]["critical_external_review_target_independent_family"]
        )
        self.assertTrue(
            self.catalog["policy"]["critical_external_review_target_independent_provider"]
        )
        self.assertNotIn(
            "critical_review_requires_independent_family", self.catalog["policy"]
        )
        self.assertNotIn(
            "critical_review_requires_independent_provider", self.catalog["policy"]
        )

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
        self.assertEqual(retired["route_role"], "scoped-writer")
        self.assertEqual(retired["authority_role"], "scoped_writer")
        self.assertTrue(retired["writer_capable"])
        self.assertTrue(retired["contrast_capable"])

        contrast = fable_routes["claude-fable-5-contrast-high"]
        self.assertTrue(contrast["enabled"])
        self.assertEqual(contrast["route_role"], "scoped-writer")
        self.assertEqual(contrast["authority_role"], "scoped_writer")
        self.assertTrue(contrast["contrast_only"])
        self.assertTrue(contrast["contrast_capable"])
        self.assertTrue(contrast["writer_capable"])
        self.assertFalse(contrast["review_capable"])

        reviewer = fable_routes["claude-fable-5-review-high"]
        self.assertEqual(reviewer["route_role"], "reviewer")
        self.assertFalse(reviewer["writer_capable"])
        self.assertFalse(reviewer["contrast_capable"])
        self.assertTrue(reviewer["review_capable"])
        for model in result["models"]:
            for public_route in model["routes"]:
                if public_route["review_only"]:
                    self.assertFalse(public_route["writer_capable"])
                    self.assertEqual(public_route["authority_role"], "reviewer")
                elif public_route["route"] == "grabowski-primary":
                    self.assertEqual(public_route["authority_role"], "controller")
                    self.assertTrue(public_route["writer_capable"])
                elif public_route["authority_role"] == "observer":
                    self.assertFalse(public_route["writer_capable"])
                else:
                    self.assertEqual(public_route["authority_role"], "scoped_writer")
                    self.assertTrue(public_route["writer_capable"])
                self.assertNotIn("role", public_route)

    def test_direct_first_policy_contract_fails_closed_on_drift(self) -> None:
        cases = [
            (
                lambda catalog: catalog["policy"].pop("direct_work_policy"),
                "direct_work_policy is missing",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"].__setitem__(
                    "capacity_fallback_to_external_writer", False
                ),
                "capacity_fallback_to_external_writer must be true",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"].__setitem__(
                    "external_agent_roles", ["writer", "review"]
                ),
                "external_agent_roles",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"].__setitem__(
                    "external_primary_reviewer_forbidden", False
                ),
                "external_primary_reviewer_forbidden must be true",
            ),
            (
                lambda catalog: catalog["policy"]["direct_work_policy"][
                    "operator_owns"
                ].remove("review"),
                "operator_owns is incomplete",
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
        self.assertEqual(result["primary_role"], "controller-integrator")
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
        with self.assertRaisesRegex(router.CodingAgentRouterError, "no scoped-writer, review or contrast capability"):
            router._validate_catalog(enabled_without_capability)

    def test_sonnet_alias_is_resolved_without_claiming_an_unknown_current_model(
        self,
    ) -> None:
        self.assertIn("claude-sonnet-5", self.catalog["models"])
        self.assertNotIn("claude-sonnet-current", self.catalog["models"])
        model = self.catalog["models"]["claude-sonnet-5"]
        self.assertEqual(model["resolved_alias"], "sonnet")
        self.assertIn("smoke-2026-07-29", model["evidence"])
        self.assertEqual(model["availability"], "live-verified-via-claude-pro")
        routes = {route["id"]: route for route in self.catalog["routes"]}
        self.assertEqual(routes["claude-sonnet-5-high"]["argv_prefix"][2], "sonnet")

    def test_sol_and_fable_are_top_contrast_peers_without_becoming_controllers(
        self,
    ) -> None:
        result = self._route("complex-patch")
        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["controller"], "grabowski-primary")
        self.assertEqual(result["primary_role"], "controller-integrator")
        self.assertNotIn("primary", result)
        self.assertNotIn("co_primaries", result)
        policy = router.grabowski_coding_agent_catalog(include_disabled=True)[
            "frontier_model_policy"
        ]
        self.assertEqual(policy["top_contrast_routes"], ["codex-sol-high"])
        self.assertEqual(
            policy["paid_contrast_routes"], ["claude-fable-5-contrast-high"]
        )
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        for route_id in [
            *policy["top_contrast_routes"],
            *policy["paid_contrast_routes"],
        ]:
            self.assertTrue(public[route_id]["contrast_capable"])
            self.assertTrue(public[route_id]["writer_capable"])
            self.assertEqual(public[route_id]["authority_role"], "scoped_writer")
        fable_route = next(
            route
            for route in self.catalog["routes"]
            if route["id"] == "claude-fable-5-contrast-high"
        )
        self.assertTrue(fable_route["paid_only"])


    def test_fable_routes_are_paid_only_and_never_default_ranked(self) -> None:
        fable_routes = [
            route for route in self.catalog["routes"] if route["model"] == "claude-fable-5"
        ]
        self.assertTrue(fable_routes)
        self.assertTrue(all(route.get("paid_only") is True for route in fable_routes))
        review = self._route("independent-review")
        ranked = [*review["reviewers"], *review["review_fallbacks"]]
        self.assertFalse(any(item["model"] == "claude-fable-5" for item in ranked))

    def test_catalog_rejects_unmarked_fable_and_paid_route_in_free_frontier(self) -> None:
        missing_paid = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in missing_paid["routes"]
            if item["id"] == "claude-fable-5-review-high"
        )
        route.pop("paid_only")
        with self.assertRaisesRegex(router.CodingAgentRouterError, "paid-only model route"):
            router._validate_catalog(missing_paid)

        missing_model_binding = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in missing_model_binding["routes"]
            if item["id"] == "claude-fable-5-contrast-high"
        )
        route["argv_prefix"] = [item for item in route["argv_prefix"] if item not in {"--model", "claude-fable-5"}]
        with self.assertRaisesRegex(router.CodingAgentRouterError, "must bind --model explicitly"):
            router._validate_catalog(missing_model_binding)

        paid_in_free = json.loads(json.dumps(self.catalog))
        paid_in_free["policy"]["frontier_model_policy"]["top_contrast_routes"] = [
            "claude-fable-5-contrast-high"
        ]
        with self.assertRaisesRegex(router.CodingAgentRouterError, "invalid or paid-only"):
            router._validate_catalog(paid_in_free)

    def test_contrast_selector_defaults_to_codex_and_paid_authorization_adds_fable(self) -> None:
        free = router.select_contrast_routes(
            "complex-patch",
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            max_candidates=2,
            allow_paid=False,
            allowed_harnesses={"codex", "claude"},
        )
        self.assertEqual(free["status"], "recommended")
        self.assertEqual(free["routes"][0]["route"], "codex-sol-high")
        self.assertTrue(all(not item["paid_only"] for item in free["routes"]))
        free_seen = {item["route"] for item in free["routes"]} | set(free["excluded"])
        self.assertNotIn("claude-fable-5-contrast-high", free_seen)

        paid = router.select_contrast_routes(
            "complex-patch",
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            max_candidates=2,
            allow_paid=True,
            allowed_harnesses={"codex", "claude"},
        )
        paid_seen = {item["route"] for item in paid["routes"]} | set(paid["excluded"])
        self.assertIn("claude-fable-5-contrast-high", paid_seen)
        self.assertLessEqual(len(paid["routes"]), 2)
        self.assertEqual(
            len({item["harness"] for item in paid["routes"]}), len(paid["routes"])
        )

        antigravity = router.select_contrast_routes(
            "docs",
            changed_files=2,
            duration_minutes=30,
            novelty="medium",
            max_candidates=1,
            allow_paid=False,
            allowed_harnesses={"antigravity"},
        )
        self.assertEqual(antigravity["status"], "recommended")
        self.assertEqual(len(antigravity["routes"]), 1)
        self.assertEqual(antigravity["routes"][0]["harness"], "antigravity")
        self.assertTrue(antigravity["routes"][0]["route"].startswith("antigravity-"))
        self.assertFalse(antigravity["routes"][0]["paid_only"])

    def test_contrast_execution_contract_enforces_fable_paid_boundary(self) -> None:
        codex = router.contrast_route_execution_contract("codex-sol-high")
        self.assertEqual(codex["harness"], "codex")
        self.assertEqual(codex["argv_prefix"], ["codexr", "architecture"])
        self.assertFalse(codex["paid_only"])
        antigravity = router.contrast_route_execution_contract("antigravity-gemini-flash-medium")
        self.assertEqual(antigravity["harness"], "antigravity")
        self.assertEqual(antigravity["argv_prefix"][:2], ["agy", "--model"])
        self.assertFalse(antigravity["paid_only"])
        self.assertEqual(
            codex["route_contract_sha256"],
            router._canonical_sha256(
                {key: value for key, value in codex.items() if key != "route_contract_sha256"}
            ),
        )
        with self.assertRaisesRegex(router.CodingAgentRouterError, "paid-only route"):
            router.contrast_route_execution_contract("claude-fable-5-contrast-high")
        sonnet = router.contrast_route_execution_contract("claude-sonnet-5-high")
        self.assertEqual(sonnet["harness"], "claude")
        self.assertEqual(
            sonnet["argv_prefix"],
            ["claude", "--model", "sonnet", "--effort", "high"],
        )
        self.assertEqual(sonnet["permission_mode"], "acceptEdits")
        self.assertFalse(sonnet["paid_only"])
        fable = router.contrast_route_execution_contract(
            "claude-fable-5-contrast-high", paid_execution_authorized=True
        )
        self.assertTrue(fable["paid_only"])
        self.assertEqual(fable["model"], "claude-fable-5")

    def test_review_execution_contract_accepts_review_only_grok_route(self) -> None:
        with self.assertRaisesRegex(
            router.CodingAgentRouterError, "enabled contrast route"
        ):
            router.contrast_route_execution_contract("grok-4.6-review-high")
        review = router.review_route_execution_contract("grok-4.6-review-high")
        advisory = router.advisory_route_execution_contract(
            "grok-4.6-review-high"
        )
        self.assertEqual(review, advisory)
        self.assertEqual(review["harness"], "grok")
        self.assertEqual(review["model"], "grok-4.6")
        self.assertEqual(review["quota_pools"], ["grok-com"])
        self.assertFalse(review["paid_only"])
        self.assertIsNone(review["permission_mode"])
        self.assertEqual(
            review["route_contract_sha256"],
            router._canonical_sha256(
                {
                    key: value
                    for key, value in review.items()
                    if key != "route_contract_sha256"
                }
            ),
        )

    def test_task_specific_defaults_keep_controller_integration_authoritative(self) -> None:
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
                self.assertEqual(result["primary_role"], "controller-integrator")
                self.assertEqual(result["routing_contract_version"], "agent-execution-fabric-routing-v1")
                self.assertIn(result["executor"], {"controller", "scoped_writer"})
                self.assertEqual(result["effect_profile"], "candidate")
                self.assertEqual(result["verification_policy"], "independent_review")
                self.assertEqual(result["integration_owner"], "controller")
                self.assertEqual(result["decision_semantics"], "integration_owner_compatibility")
                self.assertIn("flags", result["risk"])
                self.assertFalse(result["direct_implementation_required"])
                self.assertFalse(result["external_primary_writer_forbidden"])
                self.assertTrue(result["controller_integration_required"])
                self.assertTrue(result["scoped_writer_allowed"])
                self.assertIn(
                    result["scoped_writer_status"],
                    {"recommended", "no-eligible-scoped-writer"},
                )

        security = self._route(
            "security-review",
            duration_minutes=120,
            risk_flags=["security-sensitive", "public-context"],
        )
        self.assertEqual(security["decision"], "controller")
        self.assertEqual(security["primary_role"], "external-primary-reviewer")
        self.assertTrue(security["direct_review_required"])
        self.assertEqual(security["executor"], "controller")
        self.assertEqual(security["verification_policy"], "independent_review")
        self.assertFalse(security["external_primary_reviewer_forbidden"])
        self.assertEqual(security["review_authority"], "external-primary")
        self.assertEqual(
            security["primary_reviewer_route"],
            "opencode-openrouter-ox-alpha-review-preview",
        )
        self.assertTrue(security["reviewers"][0]["review_capable"])
        self.assertTrue(security["reviewers"][0]["primary_review_authority"])
        self.assertFalse(security["authoritative_implementation_remains_direct"])
        self.assertFalse(security["scoped_writer_allowed"])

    def test_opus_plan_route_is_reserved_for_review_and_never_becomes_writer(
        self,
    ) -> None:
        for task_class in ("deep-debug", "complex-patch", "architecture"):
            result = self._route(task_class)
            self.assertEqual(result["decision"], "controller")
            self.assertEqual(result["primary_role"], "controller-integrator")
        public = {
            route["route"]: route
            for model in router.grabowski_coding_agent_catalog(include_disabled=True)["models"]
            for route in model["routes"]
        }
        opus = public["claude-opus-5-high"]
        self.assertEqual(opus["permission_mode"], "plan")
        self.assertTrue(opus["review_only"])
        self.assertTrue(opus["review_capable"])
        self.assertFalse(opus["contrast_capable"])
        self.assertFalse(opus["writer_capable"])

    def test_learning_applies_to_review_routes_not_authoritative_writing(
        self,
    ) -> None:
        route_id = "claude-opus-5-high"
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
        candidates = [*pending["reviewers"], *pending["review_fallbacks"]]
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
        candidates = [*learned["reviewers"], *learned["review_fallbacks"]]
        fable_learned = next(item for item in candidates if item["route"] == route_id)
        self.assertLess(fable_learned["adaptive_score"], pending_score)
        self.assertTrue(
            any("evidenced outcome posterior" in reason for reason in fable_learned["reasons"])
        )
        coding = self._route("complex-patch", need_review=False)
        self.assertEqual(coding["decision"], "controller")

    def test_quota_exhaustion_affects_delegation_not_controller_authority(
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
        fallback_review = self._route(
            "independent-review", risk_flags=["public-context"]
        )
        self.assertEqual(fallback_review["decision"], "controller")
        self.assertEqual(fallback_review["primary_role"], "external-primary-reviewer")
        self.assertTrue(fallback_review["reviewers"])
        self.assertEqual(fallback_review["reviewers"][0]["provider_family"], "stealth")
        self.assertEqual(fallback_review["review_gap"], 0)

        for pool_id in (
            "grok-com",
            "antigravity-account",
            "openrouter-ox-alpha-preview",
        ):
            self.state["pools"][pool_id] = {
                "status": "exhausted",
                "reset_at": "2099-01-01T00:00:00Z",
            }
        self._write_state()
        exhausted_review = self._route("independent-review")
        self.assertEqual(exhausted_review["decision"], "controller")
        self.assertEqual(exhausted_review["primary_role"], "controller-reviewer")
        self.assertEqual(exhausted_review["reviewers"], [])
        self.assertEqual(
            exhausted_review["review_status"], "no-independent-review-route"
        )
        self.assertEqual(exhausted_review["review_gap"], 1)

        cline = router._pool_gate("cline-account", self.catalog, self.state, critical=False)
        openrouter = router._pool_gate("openrouter-paid", self.catalog, self.state, critical=True)
        self.assertFalse(cline[0])
        self.assertFalse(openrouter[0])

    def test_parent_quota_pool_is_enforced_even_when_route_omits_it(self) -> None:
        catalog = json.loads(json.dumps(self.catalog))
        route = next(
            item for item in catalog["routes"] if item["id"] == "antigravity-gemini-pro-high"
        )
        route["quota_pools"] = ["antigravity-gemini"]
        self.assertEqual(
            router._route_quota_pools(route, catalog),
            ["antigravity-gemini", "antigravity-account"],
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
            "antigravity-account: pool status exhausted",
            "antigravity-account: pool concurrency is saturated",
            "antigravity-account: reserve floor reached (0.15)",
        )
        for parent_state, expected_reason in zip(
            blocked_parent_states, expected_reasons, strict=True
        ):
            with self.subTest(parent_state=parent_state):
                state = self._fresh_state()
                state["pools"]["antigravity-account"] = parent_state
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
        state["pools"]["opencode-free"] = {"verified_at": future}
        allowed, reasons, _, execution = router._pool_gate(
            "opencode-free", self.catalog, state, critical=False
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
            route for route in self.catalog["routes"] if route["id"] == "grok-4.6-high"
        )
        logged_out_state = self._fresh_state()
        logged_out_state["catalog"]["providers"]["grok"]["logged_in"] = False
        available, reason = router._route_available(
            grok_route, self.catalog, logged_out_state
        )
        self.assertFalse(available)
        self.assertIn("authentication", reason)

    def test_external_reviewers_are_independent_from_controller(self) -> None:
        for task_class in ("complex-patch", "deep-debug", "architecture"):
            result = self._route(task_class, need_review=True)
            self.assertEqual(result["decision"], "controller")
            self.assertEqual(result["primary_role"], "controller-integrator")
            self.assertEqual(result["review_gap"], 0)
            self.assertNotEqual(
                result["reviewers"][0]["provider_family"],
                "openai",
            )
        for task_class in ("critical-review", "security-review"):
            review = self._route(task_class, risk_flags=["public-context"])
            self.assertEqual(review["decision"], "controller")
            self.assertEqual(review["primary_role"], "external-primary-reviewer")
            self.assertTrue(review["direct_review_required"])
            self.assertEqual(review["review_gap"], 0)
            self.assertEqual(review["review_quorum"]["direct_operator"], 0)
            self.assertEqual(review["review_quorum"]["external_authoritative_target"], 1)
            self.assertEqual(review["review_quorum"]["external_advisory_target"], 0)
            self.assertFalse(review["external_primary_reviewer_forbidden"])
            self.assertEqual(review["review_authority"], "external-primary")
            self.assertEqual(
                review["primary_reviewer_route"],
                "opencode-openrouter-ox-alpha-review-preview",
            )
            self.assertTrue(review["reviewers"][0]["review_capable"])
            self.assertTrue(review["reviewers"][0]["primary_review_authority"])
            self.assertEqual(review["reviewers"][0]["provider_family"], "stealth")

    def test_external_reviewers_are_bound_to_selected_scoped_writer(self) -> None:
        for harness, state in self.state["catalog"]["harnesses"].items():
            state["available"] = harness in {"claude", "antigravity"}
        self.state["pools"]["claude-pro"] = {"remaining_ratio": 0.9}
        self._write_state()

        result = self._route(
            "architecture",
            changed_files=24,
            duration_minutes=180,
            novelty="high",
            risk_flags=["high-risk"],
            need_review=True,
            verification_policy="independent_review",
        )

        self.assertEqual("claude-opus-5-writer-high", result["writer_route"])
        writer = result["scoped_writer"]
        self.assertIsNotNone(writer)
        reviewer = result["reviewers"][0]
        self.assertEqual("antigravity-gemini-pro-review-high", reviewer["route"])
        self.assertNotEqual(writer["independence_group"], reviewer["independence_group"])
        self.assertNotEqual(writer["provider_family"], reviewer["provider_family"])
        self.assertIn("reviewer:claude-opus-5-high", result["excluded"])
        self.assertIn(
            "reviewer shares the primary model lineage",
            result["excluded"]["reviewer:claude-opus-5-high"],
        )

    def test_selected_scoped_writer_fails_closed_without_independent_review_route(
        self,
    ) -> None:
        for harness, state in self.state["catalog"]["harnesses"].items():
            state["available"] = harness == "claude"
        self.state["pools"]["claude-pro"] = {"remaining_ratio": 0.9}
        self._write_state()

        result = self._route(
            "architecture",
            changed_files=24,
            duration_minutes=180,
            novelty="high",
            risk_flags=["high-risk"],
            need_review=True,
            verification_policy="independent_review",
        )

        self.assertEqual("claude-opus-5-writer-high", result["writer_route"])
        self.assertEqual([], result["reviewers"])
        self.assertEqual("no-independent-review-route", result["review_status"])
        self.assertIn(
            "reviewer shares the primary model lineage",
            result["excluded"]["reviewer:claude-opus-5-high"],
        )

    def test_fable_contrast_and_review_routes_never_become_primary_writer(self) -> None:
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["primary_role"], "controller-integrator")
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
        self.assertTrue(retired["writer_capable"])
        self.assertFalse(retired["enabled"])
        self.assertTrue(contrast["contrast_capable"])
        self.assertFalse(contrast["review_capable"])
        self.assertTrue(contrast["writer_capable"])
        self.assertEqual(contrast["authority_role"], "scoped_writer")
        self.assertTrue(reviewer["review_capable"])
        self.assertFalse(reviewer["contrast_capable"])
        self.assertFalse(reviewer["writer_capable"])

        review = self._route("independent-review")
        all_review_routes = {
            *(item["route"] for item in review["reviewers"]),
            *(item["route"] for item in review["review_fallbacks"]),
        }
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

    def test_controller_work_survives_missing_state_while_routing_probes(self) -> None:
        self.state_path.unlink()
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["review_status"], "router-state-unavailable")
        direct_review = self._route("independent-review")
        self.assertEqual(direct_review["decision"], "controller")
        self.assertEqual(direct_review["primary_role"], "controller-reviewer")
        self.assertEqual(direct_review["review_status"], "router-state-unavailable")

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
        direct_review = self._route("independent-review")
        self.assertEqual(direct_review["decision"], "controller")
        self.assertEqual(direct_review["review_status"], "router-state-stale")

        self.state = self._fresh_state()
        self.state["catalog_sha256"] = "0" * 64
        self._write_state()
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["review_status"], "router-state-catalog-mismatch")
        direct_review = self._route("independent-review")
        self.assertEqual(direct_review["decision"], "controller")
        self.assertEqual(direct_review["review_status"], "router-state-catalog-mismatch")

    def test_controller_work_and_inventory_survive_invalid_advisory_state(self) -> None:
        self.state_path.write_text("{invalid", encoding="utf-8")
        coding = self._route("complex-patch", need_review=True)
        self.assertEqual(coding["decision"], "controller")
        self.assertEqual(coding["primary_role"], "controller-integrator")
        self.assertEqual(coding["review_status"], "router-state-invalid")
        self.assertEqual(coding["review_state_error_type"], "CodingAgentRouterError")
        self.assertTrue(coding["automatic_execution_authorized"])

        direct_review = self._route("independent-review")
        self.assertEqual(direct_review["decision"], "controller")
        self.assertEqual(direct_review["primary_role"], "controller-reviewer")
        self.assertEqual(direct_review["review_status"], "router-state-invalid")

        inventory = router.grabowski_coding_agent_catalog()
        self.assertTrue(inventory["validation"]["valid"])
        self.assertEqual(inventory["state_status"], "invalid")
        self.assertEqual(inventory["state_error_type"], "CodingAgentRouterError")
        self.assertFalse(inventory["catalog_fresh"])

    def test_malformed_nested_advisory_state_cannot_block_direct_review(self) -> None:
        self.state = self._fresh_state()
        self.state["catalog"]["providers"] = []
        self._write_state()
        result = self._route("security-review")
        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["primary_role"], "controller-reviewer")
        self.assertEqual(result["review_status"], "router-state-invalid")
        self.assertEqual(result["review_state_error_type"], "AttributeError")
        self.assertEqual(result["reviewers"], [])
        self.assertTrue(result["automatic_execution_authorized"])

    def test_quota_opaque_advisory_only_route_cannot_be_automatic_scoped_writer(
        self,
    ) -> None:
        for harness, state in self.state["catalog"]["harnesses"].items():
            state["available"] = harness == "claude"
        self._write_state()

        result = self._route(
            "bounded-patch",
            changed_files=2,
            duration_minutes=30,
            novelty="medium",
        )

        self.assertEqual(result["executor"], "controller")
        self.assertEqual(result["writer_route"], "grabowski-primary")
        self.assertIsNone(result["scoped_writer"])
        self.assertEqual(result["scoped_writer_fallbacks"], [])
        self.assertEqual(result["scoped_writer_status"], "no-eligible-scoped-writer")
        for route_id in ("claude-sonnet-5-high", "claude-sonnet-5-medium"):
            self.assertIn(f"scoped-writer:{route_id}", result["excluded"] )
            self.assertIn(
                "automatic scoped-writer execution is forbidden",
                result["excluded"][f"scoped-writer:{route_id}"][0],
            )

    def test_known_quota_reenables_automatic_scoped_writer(self) -> None:
        for harness, state in self.state["catalog"]["harnesses"].items():
            state["available"] = harness == "claude"
        self.state["pools"]["claude-pro"] = {"remaining_ratio": 0.9}
        self._write_state()

        result = self._route(
            "bounded-patch",
            changed_files=2,
            duration_minutes=30,
            novelty="medium",
        )

        self.assertEqual(result["executor"], "scoped_writer")
        self.assertEqual(result["scoped_writer_status"], "recommended")
        self.assertIsNotNone(result["scoped_writer"])
        self.assertTrue(
            result["scoped_writer"]["execution_eligible_if_separately_authorized"]
        )
        self.assertEqual(result["writer_route"], result["scoped_writer"]["route"])

    def test_candidate_effect_profile_remains_the_byte_compatible_default(self) -> None:
        implicit = self._route("bounded-patch")
        explicit = self._route("bounded-patch", effect_profile="candidate")
        self.assertEqual(implicit, explicit)
        self.assertEqual("candidate", implicit["effect_profile"])

    def test_delivery_effect_profile_requires_and_binds_scoped_writer(self) -> None:
        for harness, state in self.state["catalog"]["harnesses"].items():
            state["available"] = harness == "claude"
        self.state["pools"]["claude-pro"] = {"remaining_ratio": 0.9}
        self._write_state()

        result = self._route(
            "bounded-patch",
            changed_files=2,
            duration_minutes=30,
            novelty="medium",
            verification_policy="independent_review",
            effect_profile="delivery",
        )

        self.assertEqual("scoped_writer", result["executor"])
        self.assertEqual("delivery", result["effect_profile"])
        self.assertEqual(result["writer_route"], result["scoped_writer"]["route"])

    def test_delivery_effect_profile_rejects_deterministic_verification(self) -> None:
        with self.assertRaisesRegex(
            router.CodingAgentRouterError,
            "requires verification_policy=independent_review",
        ):
            self._route(
                "bounded-patch",
                verification_policy="deterministic",
                effect_profile="delivery",
            )

    def test_delivery_effect_profile_fails_closed_on_controller_route(self) -> None:
        with self.assertRaisesRegex(
            router.CodingAgentRouterError, "requires an eligible scoped_writer"
        ):
            self._route("security-review", effect_profile="delivery")

    def test_spark_catalog_route_is_lane_writer_not_contrast_alias(self) -> None:
        validation = router._validate_catalog(self.catalog)
        self.assertTrue(validation["valid"])
        model = self.catalog["models"]["gpt-5.3-codex-spark"]
        pool = self.catalog["quota_pools"]["openai-codex-spark"]
        route = next(
            item for item in self.catalog["routes"] if item["id"] == "codex-spark-low"
        )
        self.assertEqual("live-verified-via-codex-app-server", model["availability"])
        self.assertEqual("codex_bengalfox", pool["provider_limit_id"])
        self.assertEqual(0, pool["marginal_cost_usd"])
        self.assertFalse(pool["payg_fallback_allowed"])
        self.assertFalse(pool["automatic_overage"])
        self.assertFalse(route.get("contrast_only", False))
        self.assertEqual(["openai-codex-spark"], route["quota_pools"])
        self.assertEqual(
            ["mechanical", "triage", "docs", "tests"], route["task_classes"]
        )

    def test_separate_spark_quota_enables_low_risk_scoped_writer(self) -> None:
        self.state["pools"]["openai-agentic"] = {
            "status": "exhausted",
            "remaining_ratio": 0.0,
            "reset_at": (
                datetime.now(timezone.utc) + timedelta(hours=6)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "verified_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state["pools"]["openai-codex-spark"] = {
            "status": "available",
            "remaining_ratio": 1.0,
            "reset_at": (
                datetime.now(timezone.utc) + timedelta(days=6)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "verified_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self._write_state()

        result = self._route(
            "docs",
            changed_files=1,
            duration_minutes=15,
            novelty="low",
            need_review=False,
        )

        self.assertEqual("scoped_writer", result["executor"])
        self.assertEqual("codex-spark-low", result["writer_route"])
        self.assertEqual("codex-spark-low", result["scoped_writer"]["route"])
        self.assertTrue(
            result["scoped_writer"]["execution_eligible_if_separately_authorized"]
        )
        self.assertNotIn(
            "codex-spark-low",
            " ".join(result["excluded"].get("scoped-writer:codex-spark-low", [])),
        )

    def test_unknown_spark_quota_remains_advisory_and_cannot_write(self) -> None:
        self.state["pools"]["openai-agentic"] = {
            "status": "exhausted",
            "remaining_ratio": 0.0,
            "reset_at": (
                datetime.now(timezone.utc) + timedelta(hours=6)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "verified_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        self.state["pools"]["openai-codex-spark"] = {
            "status": "unknown",
            "verified_at": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }
        # Keep the assertion scoped to Spark: the newly executable Ox writer
        # is an independent valid fallback and would otherwise satisfy docs.
        self.state["catalog"]["harnesses"]["opencode"]["available"] = False
        self._write_state()

        result = self._route(
            "docs",
            changed_files=1,
            duration_minutes=15,
            novelty="low",
            need_review=False,
        )

        self.assertEqual("controller", result["executor"])
        self.assertIsNone(result["scoped_writer"])
        self.assertEqual([], result["scoped_writer_fallbacks"])
        self.assertIn("scoped-writer:codex-spark-low", result["excluded"])
        self.assertIn(
            "automatic scoped-writer execution is forbidden",
            result["excluded"]["scoped-writer:codex-spark-low"][0],
        )

    def test_ox_alpha_openrouter_preview_routes_are_broad_but_scoped(self) -> None:
        validation = router._validate_catalog(self.catalog)
        self.assertTrue(validation["valid"])
        model = self.catalog["models"]["ox-alpha"]
        pool = self.catalog["quota_pools"]["openrouter-ox-alpha-preview"]
        routes = {item["id"]: item for item in self.catalog["routes"]}
        writer = routes["opencode-openrouter-ox-alpha-free-preview"]
        reviewer = routes["opencode-openrouter-ox-alpha-review-preview"]

        writer_capabilities = router._route_capabilities(writer, self.catalog)
        self.assertEqual(writer_capabilities["route_role"], "scoped-writer")
        self.assertTrue(writer_capabilities["scoped_writer_capable"])
        self.assertFalse(writer["contrast_only"])
        self.assertTrue(writer["experimental_quality_floor_bypass"])
        self.assertEqual(
            set(writer["task_classes"]),
            {
                "mechanical", "triage", "docs", "tests", "bounded-patch",
                "frontend", "refactor", "complex-patch", "deep-debug",
                "architecture", "long-agent", "migration", "isolated-pr",
            },
        )
        self.assertNotIn("local-private", writer["task_classes"])
        expected_private_flags = {
            "user_data", "secrets", "private-context", "customer-data", "credential",
        }
        self.assertEqual(set(writer["forbidden_risk_flags"]), expected_private_flags)
        expected_safe_flags = {"public-context", "synthetic-context", "non-sensitive-context"}
        self.assertEqual(set(writer["required_any_risk_flags"]), expected_safe_flags)

        reviewer_capabilities = router._route_capabilities(reviewer, self.catalog)
        self.assertEqual(reviewer_capabilities["route_role"], "reviewer")
        self.assertTrue(reviewer_capabilities["review_capable"])
        self.assertTrue(reviewer["review_only"])
        self.assertTrue(reviewer["critical_eligible"])
        self.assertTrue(reviewer["primary_review_authority"])
        self.assertTrue(reviewer["experimental_quality_floor_bypass"])
        self.assertEqual(set(reviewer["forbidden_risk_flags"]), expected_private_flags)
        self.assertEqual(set(reviewer["required_any_risk_flags"]), expected_safe_flags)
        self.assertIn("--agent", reviewer["argv_prefix"])
        self.assertIn("plan", reviewer["argv_prefix"])
        self.assertNotIn("--auto", reviewer["argv_prefix"])
        self.assertEqual(
            set(reviewer["task_classes"]),
            {"independent-review", "critical-review", "security-review"},
        )

        self.assertEqual(model["provider_family"], "stealth")
        self.assertEqual(model["quality_prior_class"], "C")
        self.assertLessEqual(model["quality"]["reliability"], 5)
        self.assertEqual(pool["cost_mode"], "temporary-free-account")
        self.assertEqual(pool["marginal_cost_usd"], 0)
        self.assertEqual(pool["max_concurrency"], 1)
        self.assertFalse(pool["payg_fallback_allowed"])
        self.assertEqual(
            pool["unknown_execution"],
            "allowed-while-fresh-zero-cost-preview",
        )
        self.assertIn("revalidated", pool["note"] or "")

    def test_ox_alpha_explicit_experimental_policy_bypasses_quality_floor_without_regrading(self) -> None:
        routes = {item["id"]: item for item in self.catalog["routes"]}
        state = self._fresh_state()
        state["catalog"]["providers"]["opencode"] = {
            "free_model_verified": True,
            "models": [
                "opencode/deepseek-v4-flash-free",
                "openrouter/stealth/ox-alpha",
            ],
        }

        writer = routes["opencode-openrouter-ox-alpha-free-preview"]
        score, _, _, reasons, exclusion, execution = router._score_route(
            writer,
            "architecture",
            self.catalog,
            state,
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            risk_flags=["synthetic-context"],
            latency_priority=False,
            reviewer=False,
            previous_group=None,
            previous_provider=None,
        )
        self.assertIsNotNone(score)
        self.assertEqual(exclusion, [])
        self.assertTrue(execution)
        self.assertTrue(any("quality floor bypassed" in reason for reason in reasons))

        reviewer = routes["opencode-openrouter-ox-alpha-review-preview"]
        score, _, _, reasons, exclusion, execution = router._score_route(
            reviewer,
            "security-review",
            self.catalog,
            state,
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            risk_flags=["public-context"],
            latency_priority=False,
            reviewer=True,
            previous_group="openai-controller",
            previous_provider="openai",
        )
        self.assertIsNotNone(score)
        self.assertEqual(exclusion, [])
        self.assertTrue(execution)
        self.assertTrue(any("quality floor bypassed" in reason for reason in reasons))
        self.assertEqual(self.catalog["models"]["ox-alpha"]["quality"]["review"], 3)

        score, _, _, _, exclusion, execution = router._score_route(
            reviewer,
            "security-review",
            self.catalog,
            state,
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            risk_flags=["security-sensitive"],
            latency_priority=False,
            reviewer=True,
            previous_group="openai-controller",
            previous_provider="openai",
        )
        self.assertIsNone(score)
        self.assertFalse(execution)
        self.assertEqual(
            exclusion,
            [
                "route requires explicit safe-context risk flag: "
                "non-sensitive-context, public-context, synthetic-context"
            ],
        )

        score, _, _, _, exclusion, execution = router._score_route(
            reviewer,
            "security-review",
            self.catalog,
            state,
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            risk_flags=["public-context", "private-context"],
            latency_priority=False,
            reviewer=True,
            previous_group="openai-controller",
            previous_provider="openai",
        )
        self.assertIsNone(score)
        self.assertFalse(execution)
        self.assertEqual(
            exclusion,
            ["route forbids sensitive risk flags: private-context"],
        )

        score, _, _, _, exclusion, execution = router._score_route(
            writer,
            "architecture",
            self.catalog,
            state,
            changed_files=20,
            duration_minutes=180,
            novelty="high",
            risk_flags=["synthetic-context", "user_data"],
            latency_priority=False,
            reviewer=False,
            previous_group=None,
            previous_provider=None,
        )
        self.assertIsNone(score)
        self.assertFalse(execution)
        self.assertEqual(exclusion, ["route forbids sensitive risk flags: user_data"])


    def test_ox_alpha_route_fails_closed_without_local_openrouter_evidence(
        self,
    ) -> None:
        route = next(
            item
            for item in self.catalog["routes"]
            if item["id"] == "opencode-openrouter-ox-alpha-free-preview"
        )
        state = self._fresh_state()
        state["catalog"]["providers"].pop("opencode", None)
        available, reason = router._route_available(route, self.catalog, state)
        self.assertFalse(available)
        self.assertEqual(reason, "OpenCode free model entitlement is unverified")

        # Even if OpenCode's own free tier is verified, the OpenRouter provider
        # and its stealth/ox-alpha model must be separately present before the
        # route is usable; missing OpenRouter provider/auth fails closed.
        state["catalog"]["providers"]["opencode"] = {
            "free_model_verified": True,
            "models": ["opencode/deepseek-v4-flash-free"],
        }
        available, reason = router._route_available(route, self.catalog, state)
        self.assertFalse(available)
        self.assertEqual(reason, "OpenCode model is absent")

        state["catalog"]["providers"]["opencode"]["models"].append(
            "openrouter/stealth/ox-alpha"
        )
        available, reason = router._route_available(route, self.catalog, state)
        self.assertTrue(available)

    def test_openrouter_ox_alpha_preview_pool_requires_fresh_verification(
        self,
    ) -> None:
        state = self._fresh_state()
        state["catalog"]["observed_at"] = "2000-01-01T00:00:00Z"
        allowed, reasons, _, execution = router._pool_gate(
            "openrouter-ox-alpha-preview",
            self.catalog,
            state,
            critical=False,
        )
        self.assertFalse(allowed)
        self.assertFalse(execution)
        self.assertIn("stale or future-dated", reasons[0])

    def test_controller_owned_work_has_no_scoped_writer(self) -> None:
        result = self._route("deployment")
        self.assertEqual(result["decision"], "controller")
        self.assertTrue(result["automatic_execution_authorized"])
        self.assertFalse(result["scoped_writer_allowed"])
        self.assertIsNone(result["scoped_writer"])
        self.assertEqual(result["scoped_writer_status"], "controller-only")
        self.assertEqual(result["executor"], "controller")
        self.assertEqual(result["writer_route"], "grabowski-primary")

    def test_verification_policy_is_an_independent_routing_axis(self) -> None:
        deterministic = self._route("complex-patch", need_review=False)
        self.assertEqual(deterministic["verification_policy"], "deterministic")
        competition = self._route(
            "complex-patch", need_review=False, verification_policy="competition"
        )
        self.assertEqual(competition["verification_policy"], "competition")
        self.assertEqual(competition["executor"], deterministic["executor"])
        with self.assertRaisesRegex(router.CodingAgentRouterError, "need_review requires"):
            self._route("complex-patch", need_review=True, verification_policy="competition")

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

    def test_recommendation_keeps_controller_integration_authoritative(
        self,
    ) -> None:
        self.state["pools"]["claude-pro"] = {"remaining_ratio": 0.9}
        self._write_state()
        result = self._route("complex-patch")
        self.assertEqual(result["decision"], "controller")
        self.assertEqual(result["controller"], "grabowski-primary")
        self.assertEqual(result["primary_role"], "controller-integrator")
        self.assertEqual(result["integration_owner"], "controller")
        self.assertIn(result["executor"], {"controller", "scoped_writer"})
        if result["executor"] == "scoped_writer":
            self.assertEqual(result["writer_route"], result["scoped_writer"]["route"])
        else:
            self.assertEqual(result["writer_route"], "grabowski-primary")
        self.assertEqual(result["effect_profile"], "candidate")
        self.assertEqual(result["verification_policy"], "independent_review")
        self.assertFalse(result["direct_implementation_required"])
        self.assertFalse(result["external_primary_writer_forbidden"])
        self.assertTrue(result["capacity_fallback_to_external_writer"])
        self.assertTrue(result["automatic_execution_authorized"])
        self.assertTrue(result["single_mutating_writer"])
        self.assertEqual(
            result["single_mutating_writer_scope"],
            "overlapping-resource-lane",
        )
        self.assertFalse(result["external_results_advisory"])
        self.assertEqual(result["external_results_authority"], "role-dependent")
        self.assertIsNotNone(result["scoped_writer"])
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
        self.assertTrue(callable(router.canonical_execution_route))


if __name__ == "__main__":
    unittest.main()
