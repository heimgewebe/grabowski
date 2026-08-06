from __future__ import annotations

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
        self.assertEqual(5, len(bundle["programs"]))
        self.assertEqual(1, len(bundle["local_review_plans"]))
        plan = bundle["local_review_plans"][0]
        self.assertEqual(0, plan["active_target_requests"])
        self.assertEqual(0, plan["external_submissions"])
        self.assertEqual(0, plan["additional_cost_eur"])
        self.assertLessEqual(plan["time_budget_hours"], 8)
        self.assertEqual(catalog.PINNED_ADK_COMMIT, plan["exact_commit"])

    def test_every_program_has_official_evidence_and_ranking_inputs(self) -> None:
        bundle = catalog.build_pilot_bundle()
        for program in bundle["programs"]:
            self.assertTrue(program["authorization"])
            self.assertTrue(program["scope"])
            self.assertTrue(program["methods"])
            self.assertTrue(program["exclusions"])
            self.assertTrue(program["submission"])
            self.assertTrue(program["compensation"])
            self.assertTrue(program["observed_at"])
            self.assertTrue(program["sources"])
            self.assertEqual(len(catalog.SCORE_KEYS), len(program["scores"]))

    def test_ranking_is_deterministic_and_google_oss_is_first(self) -> None:
        bundle = catalog.build_pilot_bundle()
        self.assertEqual("google-oss-vrp", bundle["ranking"][0])
        self.assertEqual(bundle["ranking"], [item["id"] for item in catalog.ranked_programs(bundle["programs"])])
        reversed_programs = list(reversed(bundle["programs"]))
        self.assertEqual(bundle["ranking"], [item["id"] for item in catalog.ranked_programs(reversed_programs)])

    def test_digests_are_stable_and_content_bound(self) -> None:
        bundle = catalog.build_pilot_bundle()
        first = catalog.bundle_digests(bundle)
        second = catalog.bundle_digests(deepcopy(bundle))
        self.assertEqual(first, second)
        self.assertEqual({"catalog_sha256", "ranking_sha256", "local_review_plan_sha256", "bundle_sha256"}, set(first))
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", value) for value in first.values()))
        changed = deepcopy(bundle)
        changed["programs"][0]["scope"] += " changed"
        self.assertNotEqual(first["catalog_sha256"], catalog.bundle_digests(changed)["catalog_sha256"])

    def test_validation_rejects_unofficial_source_and_external_effect(self) -> None:
        bundle = catalog.build_pilot_bundle()
        bundle["programs"][0]["sources"] = ["https://example.com/not-authority"]
        with self.assertRaisesRegex(ValueError, "unapproved source"):
            catalog.validate_pilot_bundle(bundle)
        bundle = catalog.build_pilot_bundle()
        bundle["local_review_plans"][0]["external_submissions"] = 1
        with self.assertRaisesRegex(ValueError, "active, external or paid effect"):
            catalog.validate_pilot_bundle(bundle)

    def test_rendered_document_is_reproducible(self) -> None:
        expected = catalog.render_markdown()
        document = ROOT / "docs" / "authorized-bounty-catalog-v1.md"
        self.assertEqual(expected, document.read_text(encoding="utf-8"))
        for value in catalog.bundle_digests().values():
            self.assertIn(value, expected)

    def test_module_has_no_active_network_or_submission_client(self) -> None:
        source = (ROOT / "src" / "grabowski_bounty_catalog.py").read_text(encoding="utf-8")
        for forbidden in ("import requests", "urllib.request", "import socket", "subprocess", "httpx", "HackerOne(", "Bugcrowd("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
