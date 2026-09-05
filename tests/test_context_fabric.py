from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

PR_BINDING = {
    "repository": "heimgewebe/grabowski",
    "pull_request": 561,
    "head_sha": "1" * 40,
}
BUREAU_BINDING = {
    "run_id": "bureau-run-2026-08-02-01",
    "registry_binding_sha256": "b" * 64,
}
DEPLOYMENT_BINDING = {
    "release_id": "release-2026-08-02T09-00-00Z",
    "repo_head": "2" * 40,
}
AS_OF = "2026-08-02T12:00:00Z"


def _pr_observation(**overrides: object) -> dict[str, object]:
    observation: dict[str, object] = {
        "source_tool": "grabowski_github_pr_view",
        "claim_type": "pull_request_state",
        "binding": dict(PR_BINDING),
        "observed_at": "2026-08-02T11:58:00Z",
        "status": "open",
        "evidence_refs": [
            {"type": "pr", "id": "heimgewebe/grabowski#561", "repo": "heimgewebe/grabowski"}
        ],
    }
    observation.update(overrides)
    return observation


class ContextFabricTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.module = self._load_module()

    def _load_module(self):
        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator._redact = lambda value: value

        old_core = sys.modules.get("grabowski_operator_core")
        sys.modules["grabowski_operator_core"] = fake_operator
        name = f"grabowski_context_fabric_under_test_{id(self)}"
        spec = importlib.util.spec_from_file_location(
            name, ROOT / "src/grabowski_context_fabric.py"
        )
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        sys.modules[name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        def restore_modules() -> None:
            if old_core is None:
                sys.modules.pop("grabowski_operator_core", None)
            else:
                sys.modules["grabowski_operator_core"] = old_core
            sys.modules.pop(name, None)

        self.addCleanup(restore_modules)
        return module

    def _compose_pr(self, observations: list[dict[str, object]], **kwargs: object):
        return self.module.compose_context(
            "pr", dict(PR_BINDING), AS_OF, observations, kwargs.get("claim_budget", 50)
        )


class SurfaceContractTests(ContextFabricTestCase):
    def test_source_registers_only_read_only_tools(self) -> None:
        source = (ROOT / "src/grabowski_context_fabric.py").read_text(encoding="utf-8")
        for tool in (
            "grabowski_context_fabric_plan",
            "grabowski_context_fabric_compose",
            "grabowski_context_fabric_explain",
            "grabowski_context_fabric_compare",
        ):
            self.assertIn(f'name="{tool}"', source)
        self.assertEqual(source.count("annotations=READ_ONLY"), 4)
        self.assertNotIn("annotations=MUTATING", source)
        self.assertNotIn("_require_operator_mutation", source)
        self.assertNotIn("_require_mutations_enabled", source)

    def test_surface_performs_no_io_and_keeps_no_store(self) -> None:
        source = (ROOT / "src/grabowski_context_fabric.py").read_text(encoding="utf-8")
        for forbidden in (
            "open(",
            "Path(",
            "sqlite3",
            "subprocess",
            "write_text",
            "requests",
            "urllib",
        ):
            self.assertNotIn(forbidden, source)

    def test_runtime_registers_the_module(self) -> None:
        runtime = (ROOT / "src/grabowski_runtime.py").read_text(encoding="utf-8")
        self.assertIn("import grabowski_context_fabric", runtime)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        supporting = {item["module"]: item["source"] for item in contract["supporting_sources"]}
        self.assertEqual(
            supporting["grabowski_context_fabric"], "src/grabowski_context_fabric.py"
        )
        self.assertTrue(
            {
                "grabowski_context_fabric_plan",
                "grabowski_context_fabric_compose",
                "grabowski_context_fabric_explain",
                "grabowski_context_fabric_compare",
            }.issubset(set(contract["expected_tools"]))
        )

    def test_exactly_three_profiles_exist(self) -> None:
        self.assertEqual(sorted(self.module.PROFILES), ["bureau", "deployment", "pr"])

    def test_every_declared_source_belongs_to_a_declared_profile(self) -> None:
        for name, source in self.module.SOURCES.items():
            with self.subTest(source=name):
                self.assertTrue(source["profiles"])
                for profile in source["profiles"]:
                    self.assertIn(profile, self.module.PROFILES)


class PlanTests(ContextFabricTestCase):
    def test_plan_reports_missing_binding_fields_and_is_not_ready(self) -> None:
        plan = self.module.plan_context("pr", {"repository": "heimgewebe/grabowski"})
        self.assertFalse(plan["ready"])
        self.assertEqual(plan["missing_binding_fields"], ["pull_request", "head_sha"])
        self.assertIn(
            "missing_required_authoritative_source", plan["fail_closed_conditions"]
        )
        self.assertIn(
            "stale_required_authoritative_observation", plan["fail_closed_conditions"]
        )

    def test_plan_separates_required_and_optional_authorities(self) -> None:
        plan = self.module.plan_context("deployment", dict(DEPLOYMENT_BINDING))
        self.assertTrue(plan["ready"])
        required = [
            item["source_tool"]
            for item in plan["sources"]
            if item["requirement"] == "required"
        ]
        self.assertEqual(required, ["grabowski_deployment_identity"])
        self.assertIn("deployment_authorization", plan["does_not_establish"])

    def test_plan_rejects_unknown_profile(self) -> None:
        with self.assertRaises(ValueError):
            self.module.plan_context("merge")

    def test_plan_rejects_binding_fields_outside_the_profile(self) -> None:
        with self.assertRaises(ValueError):
            self.module.plan_context("bureau", {"repository": "heimgewebe/grabowski"})


class ComposeTests(ContextFabricTestCase):
    def test_composed_claim_carries_every_required_field(self) -> None:
        context = self._compose_pr([_pr_observation()])
        self.assertTrue(context["composed"])
        self.assertIsNone(context["failure"])
        claim = context["claims"][0]
        for field in (
            "claim_type",
            "authority",
            "authority_tool",
            "truth_owner",
            "scope",
            "binding",
            "binding_sha256",
            "observed_at",
            "temporal_marker",
            "evidence_refs",
            "sensitivity",
            "status",
            "freshness",
            "observation_requirement",
            "conflicts",
            "does_not_establish",
        ):
            self.assertIn(field, claim)
        self.assertEqual(claim["authority"], "github_pull_request_registry")
        self.assertEqual(claim["temporal_marker"], "observed")
        self.assertEqual(claim["freshness"], "fresh")
        self.assertEqual(claim["age_seconds"], 120)
        self.assertEqual(claim["observation_requirement"]["state"], "observed")
        self.assertEqual(claim["observation_requirement"]["due_at"], "2026-08-02T12:13:00Z")
        self.assertEqual(context["observation_adherence"]["status"], "observed")
        self.assertEqual(context["observation_adherence"]["observed_ratio"], 1.0)
        self.assertEqual(claim["binding"], PR_BINDING)
        self.assertIn("lifecycle_truth_ownership", claim["does_not_establish"])
        self.assertIn("merge_readiness", claim["does_not_establish"])

    def test_context_digest_binds_its_content(self) -> None:
        context = self._compose_pr([_pr_observation()])
        unsigned = {
            key: value for key, value in context.items() if key != "context_sha256"
        }
        self.assertEqual(context["context_sha256"], self.module._sha256_json(unsigned))

    def test_composition_is_deterministic(self) -> None:
        first = self._compose_pr([_pr_observation()])
        second = self._compose_pr([_pr_observation()])
        self.assertEqual(first, second)

    def test_freshness_bands_degrade_with_age(self) -> None:
        aging = self._compose_pr(
            [_pr_observation(observed_at="2026-08-02T11:30:00Z")]
        )
        stale = self._compose_pr(
            [_pr_observation(observed_at="2026-08-02T09:00:00Z")]
        )
        self.assertTrue(aging["composed"])
        self.assertEqual(aging["claims"][0]["freshness"], "aging")
        self.assertEqual(aging["claims"][0]["observation_requirement"]["state"], "due")
        self.assertEqual(aging["observation_adherence"]["status"], "due")
        self.assertEqual(aging["observation_adherence"]["counts"]["due"], 1)

        self.assertFalse(stale["composed"])
        self.assertEqual(stale["claims"], [])
        self.assertEqual(
            stale["failure"]["code"],
            "stale_required_authoritative_observations",
        )
        self.assertEqual(stale["observation_adherence"]["status"], "blocked")
        self.assertEqual(stale["observation_adherence"]["counts"]["missed"], 1)
        self.assertEqual(
            stale["failure"]["stale_required_sources"],
            ["grabowski_github_pr_view"],
        )

    def test_stale_optional_observation_does_not_block_fresh_required_authority(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_github_checks",
                    "claim_type": "pull_request_check_result",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T09:00:00Z",
                    "status": "success",
                    "evidence_refs": [{"type": "check_run", "id": "validate"}],
                },
            ]
        )
        self.assertTrue(context["composed"])
        optional = next(
            claim
            for claim in context["claims"]
            if claim["authority_tool"] == "grabowski_github_checks"
        )
        self.assertEqual(optional["freshness"], "stale")
        self.assertEqual(optional["observation_requirement"]["state"], "missed")
        self.assertEqual(context["observation_adherence"]["status"], "observed")

    def test_historical_observation_is_marked_and_never_dated(self) -> None:
        context = self.module.compose_context(
            "pr",
            dict(PR_BINDING),
            AS_OF,
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_chronik_history",
                    "claim_type": "historical_run_outcome",
                    "binding": dict(PR_BINDING),
                    "historical": True,
                    "status": "completed",
                    "evidence_refs": [{"type": "chronik_event", "id": "sha256:" + "c" * 64}],
                },
            ],
        )
        historical = [
            claim for claim in context["claims"] if claim["historical"] is True
        ]
        self.assertEqual(len(historical), 1)
        self.assertEqual(historical[0]["temporal_marker"], "historical")
        self.assertEqual(historical[0]["freshness"], "historical")
        self.assertIsNone(historical[0]["observed_at"])
        self.assertIn("current_git_state", historical[0]["does_not_establish"])

    def test_contradictions_are_preserved_and_never_resolved(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                _pr_observation(status="closed", observed_at="2026-08-02T11:59:00Z"),
            ]
        )
        self.assertEqual(context["contradiction_count"], 1)
        self.assertEqual(context["conflict_resolution"], "not_performed")
        self.assertEqual(len(context["claims"]), 2)
        for claim in context["claims"]:
            self.assertEqual(len(claim["conflicts"]), 1)
        contradiction = context["contradictions"][0]
        self.assertEqual(contradiction["claim_type"], "pull_request_state")
        self.assertEqual(contradiction["distinct_assertion_count"], 2)

    def test_packing_drops_only_optional_claims_and_reports_them(self) -> None:
        context = self.module.compose_context(
            "pr",
            dict(PR_BINDING),
            AS_OF,
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_github_checks",
                    "claim_type": "pull_request_check_result",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "success",
                    "evidence_refs": [{"type": "check_run", "id": "validate"}],
                },
            ],
            1,
        )
        self.assertTrue(context["composed"])
        self.assertTrue(context["packing"]["truncated"])
        self.assertEqual(context["packing"]["dropped_claim_count"], 1)
        self.assertEqual(context["claims"][0]["authority_tool"], "grabowski_github_pr_view")

    def test_bureau_and_deployment_profiles_compose(self) -> None:
        bureau = self.module.compose_context(
            "bureau",
            dict(BUREAU_BINDING),
            AS_OF,
            [
                {
                    "source_tool": "grabowski_bureau_pickup_status",
                    "claim_type": "bureau_run_state",
                    "binding": dict(BUREAU_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "running",
                    "evidence_refs": [
                        {"type": "bureau_run", "id": BUREAU_BINDING["run_id"]}
                    ],
                }
            ],
        )
        deployment = self.module.compose_context(
            "deployment",
            dict(DEPLOYMENT_BINDING),
            AS_OF,
            [
                {
                    "source_tool": "grabowski_deployment_identity",
                    "claim_type": "deployment_release_identity",
                    "binding": dict(DEPLOYMENT_BINDING),
                    "observed_at": "2026-08-02T11:59:30Z",
                    "status": "complete",
                    "evidence_refs": [
                        {"type": "release", "id": DEPLOYMENT_BINDING["release_id"]}
                    ],
                }
            ],
        )
        self.assertTrue(bureau["composed"])
        self.assertEqual(bureau["scope"], "bureau_run")
        self.assertTrue(deployment["composed"])
        self.assertEqual(deployment["scope"], "runtime_deployment")
        self.assertIn("rollback_permission", deployment["does_not_establish"])


class FailClosedTests(ContextFabricTestCase):
    def test_incomplete_binding_fails_closed_without_claims(self) -> None:
        context = self.module.compose_context(
            "pr",
            {"repository": "heimgewebe/grabowski", "pull_request": 561},
            AS_OF,
            [_pr_observation()],
        )
        self.assertFalse(context["composed"])
        self.assertEqual(context["claims"], [])
        self.assertEqual(context["failure"]["code"], "missing_required_binding_fields")
        self.assertEqual(context["failure"]["missing_binding_fields"], ["head_sha"])

    def test_missing_required_authority_fails_closed(self) -> None:
        context = self._compose_pr(
            [
                {
                    "source_tool": "grabowski_github_checks",
                    "claim_type": "pull_request_check_result",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "success",
                    "evidence_refs": [{"type": "check_run", "id": "validate"}],
                }
            ]
        )
        self.assertFalse(context["composed"])
        self.assertEqual(context["claims"], [])
        self.assertEqual(
            context["failure"]["code"], "missing_required_authoritative_sources"
        )
        self.assertEqual(
            context["failure"]["missing_required_sources"], ["grabowski_github_pr_view"]
        )

    def test_no_observations_fails_closed(self) -> None:
        context = self._compose_pr([])
        self.assertFalse(context["composed"])
        self.assertEqual(context["missing_required_sources"], ["grabowski_github_pr_view"])

    def test_budget_preserves_required_authority_not_every_required_claim(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(claim_type="pull_request_mergeability", status="mergeable")],
            claim_budget=1,
        )
        self.assertTrue(context["composed"])
        self.assertEqual(context["claim_count"], 1)
        self.assertEqual(context["packing"]["dropped_claim_count"], 1)
        self.assertEqual(context["claims"][0]["authority_tool"], "grabowski_github_pr_view")

    def test_budget_that_excludes_a_required_authority_fails_closed(self) -> None:
        original = self.module.PROFILES["pr"]["required_sources"]
        self.module.PROFILES["pr"]["required_sources"] = ("grabowski_github_pr_view", "grabowski_github_checks")
        try:
            context = self.module.compose_context(
                "pr", dict(PR_BINDING), AS_OF,
                [_pr_observation(), {"source_tool": "grabowski_github_checks", "claim_type": "pull_request_check_result", "binding": dict(PR_BINDING), "observed_at": "2026-08-02T11:59:00Z", "status": "success", "evidence_refs": [{"type": "check_run", "id": "validate"}]}],
                1,
            )
        finally:
            self.module.PROFILES["pr"]["required_sources"] = original
        self.assertFalse(context["composed"])
        self.assertEqual(context["failure"]["code"], "claim_budget_excludes_required_authority")
        self.assertEqual(context["claims"], [])

    def test_failed_context_keeps_the_most_restrictive_sensitivity_ceiling(self) -> None:
        context = self._compose_pr([])
        self.assertEqual(context["sensitivity_ceiling"], "restricted_operational")
        self.assertFalse(context["secret_content_returned"])


class RejectionTests(ContextFabricTestCase):
    def test_observation_from_an_undeclared_source_is_rejected(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(source_tool="grabowski_terminal_run")]
        )
        self.assertTrue(context["composed"])
        self.assertEqual(context["rejected_observation_count"], 1)
        self.assertEqual(len(context["claims"]), 1)

    def test_authority_may_not_establish_a_foreign_claim_type(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(claim_type="deployment_release_identity")]
        )
        self.assertEqual(context["rejected_observation_count"], 1)
        self.assertIn("may not establish", context["rejected_observations"][0]["detail"])

    def test_source_outside_the_profile_is_rejected(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_deployment_identity",
                    "claim_type": "deployment_release_identity",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "complete",
                    "evidence_refs": [{"type": "release", "id": "release-1"}],
                },
            ]
        )
        self.assertEqual(context["rejected_observation_count"], 1)
        self.assertEqual(len(context["claims"]), 1)

    def test_observation_bound_to_another_target_is_rejected(self) -> None:
        other = dict(PR_BINDING)
        other["pull_request"] = 562
        context = self._compose_pr([_pr_observation(), _pr_observation(binding=other)])
        self.assertEqual(context["rejected_observation_count"], 1)
        self.assertIn("does not match", context["rejected_observations"][0]["detail"])

    def test_future_observation_is_rejected(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(observed_at="2026-08-02T12:30:00Z")]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_live_observation_without_observed_at_is_rejected(self) -> None:
        observation = _pr_observation()
        del observation["observed_at"]
        context = self._compose_pr([_pr_observation(), observation])
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_historical_source_may_not_claim_a_live_observation(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_chronik_history",
                    "claim_type": "historical_run_outcome",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:00:00Z",
                    "status": "completed",
                    "evidence_refs": [{"type": "chronik_event", "id": "sha256:" + "c" * 64}],
                },
            ]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_observation_without_evidence_is_rejected(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(evidence_refs=[])]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_unsupported_evidence_reference_type_is_rejected(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                _pr_observation(evidence_refs=[{"type": "secret", "id": "ntfy-token"}]),
            ]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_evidence_reference_path_field_is_rejected(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                _pr_observation(
                    evidence_refs=[
                        {"type": "pr", "id": "x", "path": "/home/alex/.config/grabowski"}
                    ]
                ),
            ]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_evidence_reference_rejects_non_https_url(self) -> None:
        context = self._compose_pr([_pr_observation(), _pr_observation(evidence_refs=[{"type": "pr", "id": "x", "url": "file:///home/alex/private"}])])
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_evidence_reference_validates_repo_and_hashes(self) -> None:
        invalid_refs = (
            {"type": "pr", "id": "x", "repo": "not-a-repository"},
            {"type": "commit", "id": "x", "sha256": "not-a-digest"},
            {"type": "commit", "id": "x", "head_sha": "not-a-head"},
        )
        for evidence_ref in invalid_refs:
            with self.subTest(evidence_ref=evidence_ref):
                context = self._compose_pr([_pr_observation(), _pr_observation(evidence_refs=[evidence_ref])])
                self.assertEqual(context["rejected_observation_count"], 1)

    def test_unknown_observation_field_is_rejected(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(note="free form memory")]
        )
        self.assertEqual(context["rejected_observation_count"], 1)

    def test_sensitivity_above_the_source_ceiling_is_rejected(self) -> None:
        context = self._compose_pr(
            [_pr_observation(), _pr_observation(sensitivity="restricted_operational")]
        )
        self.assertEqual(context["rejected_observation_count"], 1)


class SecretBoundaryTests(ContextFabricTestCase):
    def test_secret_bearing_key_is_rejected_outright(self) -> None:
        for key in ("token", "secret", "password", "credentials", "authorization"):
            with self.subTest(key=key):
                observation = _pr_observation()
                observation[key] = "value"
                with self.assertRaises(ValueError) as error:
                    self._compose_pr([observation])
                self.assertIn("secret content", str(error.exception))

    def test_nested_secret_bearing_key_is_rejected(self) -> None:
        observation = _pr_observation()
        observation["evidence_refs"] = [
            {"type": "pr", "id": "x", "value": "placeholder-not-a-real-credential"}
        ]
        with self.assertRaises(ValueError):
            self._compose_pr([observation])

    def test_secret_material_in_the_binding_is_rejected(self) -> None:
        binding = dict(PR_BINDING)
        binding["token"] = "placeholder-not-a-real-credential"
        with self.assertRaises(ValueError):
            self.module.compose_context("pr", binding, AS_OF, [_pr_observation()])

    def test_no_declared_source_may_exceed_the_internal_sensitivity_ceiling(self) -> None:
        for name, source in self.module.SOURCES.items():
            with self.subTest(source=name):
                self.assertIn(
                    source["max_sensitivity"],
                    {"public_operational", "internal_operational"},
                )


class InputValidationTests(ContextFabricTestCase):
    def test_missing_as_of_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.module.compose_context("pr", dict(PR_BINDING), None, [_pr_observation()])

    def test_naive_as_of_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.module.compose_context(
                "pr", dict(PR_BINDING), "2026-08-02T12:00:00", [_pr_observation()]
            )

    def test_claim_budget_bounds_are_enforced(self) -> None:
        for budget in (0, -1, 10_000, True, "50"):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    self._compose_pr([_pr_observation()], claim_budget=budget)

    def test_observation_list_bounds_are_enforced(self) -> None:
        with self.assertRaises(ValueError):
            self._compose_pr([_pr_observation()] * 201)

    def test_observations_must_be_a_list(self) -> None:
        with self.assertRaises(ValueError):
            self.module.compose_context(
                "pr", dict(PR_BINDING), AS_OF, {"0": _pr_observation()}
            )

    def test_malformed_binding_value_is_rejected(self) -> None:
        binding = dict(PR_BINDING)
        binding["head_sha"] = "not-a-sha"
        with self.assertRaises(ValueError):
            self.module.compose_context("pr", binding, AS_OF, [_pr_observation()])


class ExplainTests(ContextFabricTestCase):
    def test_explanation_binds_inclusion_reason_and_reread_target(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_github_checks",
                    "claim_type": "pull_request_check_result",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "success",
                    "evidence_refs": [{"type": "check_run", "id": "validate"}],
                },
            ]
        )
        explanation = self.module.explain_context(context)
        self.assertTrue(explanation["context_digest_matches"])
        self.assertFalse(explanation["producer_authenticated"])
        reasons = {
            item["authority_tool"]: item["inclusion_reason"]
            for item in explanation["explanations"]
        }
        self.assertEqual(reasons["grabowski_github_pr_view"], "required_authority")
        self.assertEqual(
            reasons["grabowski_github_checks"], "optional_supporting_authority"
        )
        for item in explanation["explanations"]:
            self.assertEqual(item["reread_before_acting"], [item["authority_tool"]])
            self.assertIn("lifecycle_truth_ownership", item["does_not_establish"])

    def test_explanation_can_select_one_claim(self) -> None:
        context = self._compose_pr([_pr_observation()])
        claim_id = context["claims"][0]["claim_id"]
        explanation = self.module.explain_context(context, claim_id)
        self.assertEqual(explanation["explanation_count"], 1)
        self.assertEqual(explanation["selected_claim_id"], claim_id)

    def test_explanation_reports_contradicted_claims(self) -> None:
        context = self._compose_pr(
            [
                _pr_observation(),
                _pr_observation(status="closed", observed_at="2026-08-02T11:59:00Z"),
            ]
        )
        explanation = self.module.explain_context(context)
        statuses = {item["conflict_status"] for item in explanation["explanations"]}
        self.assertEqual(statuses, {"contradicted"})

    def test_explanation_rejects_a_tampered_context(self) -> None:
        context = self._compose_pr([_pr_observation()])
        context["claims"][0]["status"] = "merged"
        with self.assertRaises(ValueError) as error:
            self.module.explain_context(context)
        self.assertIn("digest", str(error.exception))

    def test_explanation_rejects_a_foreign_payload(self) -> None:
        with self.assertRaises(ValueError):
            self.module.explain_context({"kind": "grabowski_operator_recall_export"})

    def test_explanation_rejects_an_absent_claim_id(self) -> None:
        context = self._compose_pr([_pr_observation()])
        with self.assertRaises(ValueError):
            self.module.explain_context(context, "sha256:" + "0" * 64)


class CompareTests(ContextFabricTestCase):
    def test_comparison_reports_status_change_without_ranking(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        candidate = self.module.compose_context(
            "pr",
            dict(PR_BINDING),
            "2026-08-02T13:00:00Z",
            [_pr_observation(status="merged", observed_at="2026-08-02T12:59:00Z")],
        )
        comparison = self.module.compare_contexts(baseline, candidate)
        self.assertTrue(comparison["comparable"])
        self.assertEqual(len(comparison["added_claim_ids"]), 1)
        self.assertEqual(len(comparison["removed_claim_ids"]), 1)
        self.assertEqual(
            comparison["changed_assertions"],
            [
                {
                    "claim_type": "pull_request_state",
                    "authority_tool": "grabowski_github_pr_view",
                    "baseline_status": ["open"],
                    "candidate_status": ["merged"],
                }
            ],
        )
        for excluded in ("progress", "regression", "approval_to_proceed"):
            self.assertIn(excluded, comparison["does_not_establish"])
        self.assertNotIn("verdict", comparison)
        self.assertNotIn("recommendation", comparison)

    def test_comparison_of_a_different_target_fails_closed(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        other_binding = dict(PR_BINDING)
        other_binding["pull_request"] = 562
        other_observation = _pr_observation(binding=dict(other_binding))
        candidate = self.module.compose_context(
            "pr", other_binding, AS_OF, [other_observation]
        )
        comparison = self.module.compare_contexts(baseline, candidate)
        self.assertFalse(comparison["comparable"])
        self.assertEqual(comparison["failure"]["code"], "binding_mismatch")

    def test_comparison_of_different_profiles_fails_closed(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        candidate = self.module.compose_context(
            "bureau",
            dict(BUREAU_BINDING),
            AS_OF,
            [
                {
                    "source_tool": "grabowski_bureau_pickup_status",
                    "claim_type": "bureau_run_state",
                    "binding": dict(BUREAU_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "running",
                    "evidence_refs": [
                        {"type": "bureau_run", "id": BUREAU_BINDING["run_id"]}
                    ],
                }
            ],
        )
        comparison = self.module.compare_contexts(baseline, candidate)
        self.assertFalse(comparison["comparable"])
        self.assertEqual(comparison["failure"]["code"], "profile_mismatch")

    def test_comparison_with_a_fail_closed_context_is_not_comparable(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        candidate = self._compose_pr([])
        comparison = self.module.compare_contexts(baseline, candidate)
        self.assertFalse(comparison["comparable"])
        self.assertEqual(comparison["failure"]["code"], "uncomposed_context")

    def test_comparison_rejects_a_tampered_context(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        candidate = self._compose_pr([_pr_observation()])
        candidate["claim_count"] = 99
        with self.assertRaises(ValueError):
            self.module.compare_contexts(baseline, candidate)

    def test_comparison_reports_authority_coverage_delta(self) -> None:
        baseline = self._compose_pr([_pr_observation()])
        candidate = self._compose_pr(
            [
                _pr_observation(),
                {
                    "source_tool": "grabowski_github_checks",
                    "claim_type": "pull_request_check_result",
                    "binding": dict(PR_BINDING),
                    "observed_at": "2026-08-02T11:59:00Z",
                    "status": "success",
                    "evidence_refs": [{"type": "check_run", "id": "validate"}],
                },
            ]
        )
        comparison = self.module.compare_contexts(baseline, candidate)
        self.assertEqual(
            comparison["authority_delta"]["added_sources"], ["grabowski_github_checks"]
        )
        self.assertEqual(comparison["authority_delta"]["removed_sources"], [])


if __name__ == "__main__":
    unittest.main()
