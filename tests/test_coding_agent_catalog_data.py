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
        self.assertEqual(catalog["catalog_version"], "direct-first-review-contrast-v4")
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
        self.assertEqual(catalog["catalog_version"], "direct-first-review-contrast-v4")

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


if __name__ == "__main__":
    unittest.main()
