from __future__ import annotations

import hashlib
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

import grabowski_coding_agent_catalog_data as catalog_data  # noqa: E402
import grabowski_coding_agent_router as router  # noqa: E402


class CodingAgentCatalogDataTests(unittest.TestCase):
    def test_generated_catalog_matches_canonical_source(self) -> None:
        source = (ROOT / "config" / "coding-agent-catalog.json").read_bytes()
        value = json.loads(source.decode("utf-8"))
        canonical = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(source).hexdigest(), catalog_data.CATALOG_SOURCE_SHA256
        )
        self.assertEqual(
            hashlib.sha256(canonical).hexdigest(),
            catalog_data.CATALOG_CANONICAL_SHA256,
        )
        self.assertEqual(canonical.decode("utf-8"), catalog_data.CATALOG_JSON)
        self.assertEqual(
            value["source"], "versioned-repository-default"
        )

    def test_deployment_catalog_ignores_legacy_user_catalog_without_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            legacy = home / ".config" / "grabowski" / "coding-agent-catalog.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text(json.dumps({"legacy": True}) + "\n", encoding="utf-8")
            environment = dict(os.environ)
            environment.pop(router.CATALOG_ENV, None)
            environment.pop(router.CATALOG_OVERRIDE_ENV, None)
            environment["HOME"] = str(home)
            with mock.patch.dict(os.environ, environment, clear=True):
                catalog, validation = router._load_catalog()
        self.assertEqual(validation["catalog_source"], "deployment_catalog")
        self.assertEqual(catalog["catalog_version"], "lane-scoped-writer-v9")
        self.assertNotIn("legacy", catalog)

    def test_catalog_path_without_override_gate_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps({"invalid": True}) + "\n", encoding="utf-8")
            environment = dict(os.environ)
            environment[router.CATALOG_ENV] = str(path)
            environment.pop(router.CATALOG_OVERRIDE_ENV, None)
            with mock.patch.dict(os.environ, environment, clear=True):
                catalog, validation = router._load_catalog()
        self.assertEqual(validation["catalog_source"], "deployment_catalog")
        self.assertEqual(catalog["catalog_version"], "lane-scoped-writer-v9")

    def test_environment_override_remains_explicit_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps({"invalid": True}) + "\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    router.CATALOG_ENV: str(path),
                    router.CATALOG_OVERRIDE_ENV: "1",
                },
            ):
                with self.assertRaises(router.CodingAgentRouterError):
                    router._load_catalog()



    def test_catalog_health_uses_one_catalog_selection(self) -> None:
        selection = (router._deployment_catalog_path(), "deployment_catalog")
        with mock.patch.object(
            router, "_catalog_selection", side_effect=[selection]
        ) as selector:
            health = router.coding_agent_catalog_health()
        self.assertTrue(health["ready"])
        self.assertEqual(health["path"], str(selection[0]))
        self.assertEqual(health["source"], selection[1])
        self.assertEqual(selector.call_count, 1)

    def test_catalog_readback_reuses_loaded_catalog_selection(self) -> None:
        selection = (router._deployment_catalog_path(), "deployment_catalog")
        with mock.patch.object(
            router, "_catalog_selection", side_effect=[selection]
        ) as selector:
            body = router.grabowski_coding_agent_catalog()
        self.assertEqual(body["catalog_path"], str(selection[0]))
        self.assertEqual(body["validation"]["catalog_source"], selection[1])
        self.assertEqual(selector.call_count, 1)


    def test_canonical_harness_additions_are_embedded(self) -> None:
        catalog, _ = router._load_catalog()
        self.assertNotIn("agy", catalog["harnesses"])
        self.assertEqual(catalog["harnesses"]["antigravity"]["binary"], "agy")
        self.assertEqual(catalog["harnesses"]["openhands"]["approval_mode"], "always-approve")
        routes = {item["id"]: item for item in catalog["routes"]}
        self.assertEqual(routes["opencode-deepseek-v4-flash-free"]["harness"], "opencode")
        self.assertIn("--auto", routes["opencode-deepseek-v4-flash-free"]["argv_prefix"])
        self.assertEqual(routes["openhands-always-approve"]["harness"], "openhands")
        self.assertIn("--always-approve", routes["openhands-always-approve"]["argv_prefix"])

    def test_ox_alpha_openrouter_preview_has_broad_but_scoped_authority(self) -> None:
        catalog, _ = router._load_catalog()
        routes = {item["id"]: item for item in catalog["routes"]}
        writer = routes["opencode-openrouter-ox-alpha-free-preview"]
        reviewer = routes["opencode-openrouter-ox-alpha-review-preview"]

        self.assertEqual(writer["harness"], "opencode")
        self.assertEqual(writer["model"], "ox-alpha")
        self.assertIn("openrouter/stealth/ox-alpha", writer["argv_prefix"])
        self.assertFalse(writer["contrast_only"])
        self.assertTrue(writer["experimental_quality_floor_bypass"])
        self.assertTrue(writer["enabled"])
        self.assertEqual(writer["quota_pools"], ["openrouter-ox-alpha-preview"])
        self.assertEqual(
            set(writer["task_classes"]),
            {
                "mechanical", "triage", "docs", "tests", "bounded-patch",
                "frontend", "refactor", "complex-patch", "deep-debug",
                "architecture", "long-agent", "migration", "isolated-pr",
            },
        )
        self.assertNotIn("local-private", writer["task_classes"])

        self.assertTrue(reviewer["review_only"])
        self.assertTrue(reviewer["critical_eligible"])
        self.assertTrue(reviewer["primary_review_authority"])
        self.assertTrue(reviewer["experimental_quality_floor_bypass"])
        self.assertEqual(
            catalog["policy"]["direct_work_policy"]["primary_review_route_exceptions"],
            ["opencode-openrouter-ox-alpha-review-preview"],
        )
        self.assertIn("--agent", reviewer["argv_prefix"])
        self.assertIn("plan", reviewer["argv_prefix"])
        self.assertNotIn("--auto", reviewer["argv_prefix"])
        self.assertEqual(
            set(reviewer["task_classes"]),
            {"independent-review", "critical-review", "security-review"},
        )

        model = catalog["models"]["ox-alpha"]
        self.assertEqual(model["provider_family"], "stealth")
        self.assertEqual(model["quality_prior_class"], "C")
        self.assertLessEqual(model["quality"]["reliability"], 5)
        pool = catalog["quota_pools"]["openrouter-ox-alpha-preview"]
        self.assertEqual(pool["marginal_cost_usd"], 0)
        self.assertEqual(pool["max_concurrency"], 1)
        self.assertFalse(pool["payg_fallback_allowed"])
        self.assertEqual(
            pool["unknown_execution"],
            "allowed-while-fresh-zero-cost-preview",
        )
        self.assertEqual(
            catalog["quota_pools"]["openrouter-paid"]["max_concurrency"], 0
        )
        self.assertFalse(
            catalog["quota_pools"]["openrouter-paid"]["payg_fallback_allowed"]
        )


if __name__ == "__main__":
    unittest.main()
