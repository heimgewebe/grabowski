from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_bounty_catalog as catalog  # noqa: E402


class BountyCatalogTests(unittest.TestCase):
    def test_pilot_contract_is_valid_and_passive(self) -> None:
        bundle = catalog.build_pilot_bundle()
        catalog.validate_pilot_bundle(bundle)
        self.assertEqual(6, len(bundle["programs"]))
        self.assertEqual(1, len(bundle["local_review_plans"]))
        plan = bundle["local_review_plans"][0]
        self.assertEqual(0, plan["active_target_requests"])
        self.assertEqual(0, plan["external_submissions"])
        self.assertEqual(0, plan["additional_cost_eur"])
        self.assertEqual(4, plan["time_budget_hours"])

    def test_every_program_has_official_evidence_and_named_scope(self) -> None:
        bundle = catalog.build_pilot_bundle()
        for program in bundle["programs"]:
            self.assertTrue(program["authorization"])
            self.assertTrue(program["scope"])
            self.assertTrue(program["in_scope"])
            self.assertTrue(program["out_of_scope"])
            self.assertTrue(program["methods"])
            self.assertTrue(program["exclusions"])
            self.assertTrue(program["submission"])
            self.assertTrue(program["compensation"])
            self.assertTrue(program["observed_at"])
            self.assertTrue(program["sources"])
            self.assertEqual(catalog.SCORE_KEYS, tuple(program["scores"]))

    def test_microsoft_is_first_and_plan_is_exactly_pinned(self) -> None:
        bundle = catalog.build_pilot_bundle()
        self.assertEqual("microsoft-oss-bounty", bundle["ranking"][0])
        plan = bundle["local_review_plans"][0]
        self.assertEqual("microsoft-oss-bounty", plan["program_id"])
        self.assertEqual(catalog.PINNED_AGENT_FRAMEWORK_REPOSITORY, plan["repository"])
        self.assertEqual(catalog.PINNED_AGENT_FRAMEWORK_COMMIT, plan["exact_commit"])
        self.assertRegex(plan["exact_commit"], r"[0-9a-f]{40}\Z")

    def test_microsoft_scope_preserves_named_exclusions(self) -> None:
        programs = {item["id"]: item for item in catalog.build_pilot_bundle()["programs"]}
        microsoft = programs["microsoft-oss-bounty"]
        self.assertIn("Microsoft Agent Framework", microsoft["in_scope"])
        self.assertIn("microsoft/semantic-kernel", microsoft["out_of_scope"])
        self.assertIn("microsoft/autogen", microsoft["out_of_scope"])
        self.assertTrue(any("checkpoint storage" in item for item in microsoft["out_of_scope"]))

    def test_google_oss_compensation_is_tier_dependent(self) -> None:
        programs = {item["id"]: item for item in catalog.build_pilot_bundle()["programs"]}
        google = programs["google-oss-vrp"]
        self.assertEqual("tier-dependent", google["compensation_path"])
        self.assertLessEqual(google["scores"]["compensation"], 2)
        self.assertTrue(any("OT2 product vulnerabilities" in item for item in google["out_of_scope"]))

    def test_patch_rewards_requires_post_merge_aging(self) -> None:
        programs = {item["id"]: item for item in catalog.build_pilot_bundle()["programs"]}
        patch = programs["google-patch-rewards"]
        self.assertEqual("post-merge", patch["compensation_path"])
        self.assertTrue(any("one month" in item for item in patch["exclusions"]))

    def test_ranking_is_a_deterministic_permutation(self) -> None:
        bundle = catalog.build_pilot_bundle()
        expected = [item["id"] for item in catalog.ranked_programs(bundle["programs"])]
        self.assertEqual(expected, bundle["ranking"])
        self.assertEqual(len(expected), len(set(expected)))
        self.assertEqual(
            expected,
            [item["id"] for item in catalog.ranked_programs(list(reversed(bundle["programs"])))],
        )

    def test_digests_are_stable_and_content_bound(self) -> None:
        bundle = catalog.build_pilot_bundle()
        first = catalog.bundle_digests(bundle)
        self.assertEqual(first, catalog.bundle_digests(deepcopy(bundle)))
        self.assertEqual(
            {
                "catalog_sha256",
                "ranking_sha256",
                "local_review_plan_sha256",
                "bundle_sha256",
            },
            set(first),
        )
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in first.values()))
        changed = deepcopy(bundle)
        changed["programs"][0]["scope"] += " changed"
        self.assertNotEqual(first["catalog_sha256"], catalog.bundle_digests(changed)["catalog_sha256"])

    def test_empty_or_inconsistent_input_fails_closed(self) -> None:
        for operation in (catalog.validate_pilot_bundle, catalog.bundle_digests, catalog.render_markdown):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(ValueError, "top-level contract"):
                    operation({})
        bundle = catalog.build_pilot_bundle()
        bundle["ranking"] = bundle["ranking"][:-1] + [bundle["ranking"][0]]
        with self.assertRaisesRegex(ValueError, "deterministic program permutation"):
            catalog.validate_pilot_bundle(bundle)

    def test_validation_rejects_unofficial_source_and_external_effect(self) -> None:
        bundle = catalog.build_pilot_bundle()
        bundle["programs"][0]["sources"] = ["https://example.com/not-authority"]
        with self.assertRaisesRegex(ValueError, "unapproved source"):
            catalog.validate_pilot_bundle(bundle)
        bundle = catalog.build_pilot_bundle()
        bundle["local_review_plans"][0]["external_submissions"] = 1
        with self.assertRaisesRegex(ValueError, "active, external or paid effect"):
            catalog.validate_pilot_bundle(bundle)

    def test_plan_requires_explicit_compensation_and_named_scope(self) -> None:
        bundle = catalog.build_pilot_bundle()
        bundle["local_review_plans"][0]["program_id"] = "google-oss-vrp"
        with self.assertRaisesRegex(ValueError, "explicit compensation path"):
            catalog.validate_pilot_bundle(bundle)

    def test_rendered_document_is_reproducible(self) -> None:
        expected = catalog.render_markdown()
        document = ROOT / "docs" / "authorized-bounty-catalog-v1.md"
        self.assertEqual(expected, document.read_text(encoding="utf-8"))
        for value in catalog.bundle_digests().values():
            self.assertIn(value, expected)

    def test_module_has_no_active_network_process_or_filesystem_client(self) -> None:
        path = ROOT / "src" / "grabowski_bounty_catalog.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_imports = {
            "http.client",
            "httpx",
            "pathlib",
            "requests",
            "socket",
            "subprocess",
            "urllib.request",
        }
        observed_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                observed_imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed_imports.add(node.module)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "exec", "eval"})
        self.assertTrue(forbidden_imports.isdisjoint(observed_imports))


if __name__ == "__main__":
    unittest.main()
