"""Regression: the public Chronik search tool is included in immutable deployment sources."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_PATH = ROOT / "tools" / "deploy_runtime.py"
spec = importlib.util.spec_from_file_location("chronik_deploy_runtime_test", DEPLOY_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("deploy_runtime module unavailable")
deploy = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = deploy
spec.loader.exec_module(deploy)


class ChronikDeployClosureTests(unittest.TestCase):
    def test_full_search_module_is_snapshotted_and_import_closure_is_complete(self):
        contract = json.loads((ROOT / "config/runtime-entrypoint.json").read_text(encoding="utf-8"))
        sources = {
            item["module"]: (ROOT / item["source"]).read_bytes()
            for item in contract["supporting_sources"]
        }
        self.assertIn("grabowski_chronik_full_search", sources)
        self.assertIn("grabowski_tasks", sources)
        self.assertIn("grabowski_chronik_full_search", sources["grabowski_tasks"].decode("utf-8"))
        deploy.verify_import_closure(
            module=contract["module"],
            source_bytes=(ROOT / contract["source"]).read_bytes(),
            supporting=sources,
        )

    def test_omitting_full_search_source_reproduces_the_blocking_defect(self):
        contract = json.loads((ROOT / "config/runtime-entrypoint.json").read_text(encoding="utf-8"))
        supporting = {
            item["module"]: (ROOT / item["source"]).read_bytes()
            for item in contract["supporting_sources"]
            if item["module"] != "grabowski_chronik_full_search"
        }
        with self.assertRaisesRegex(deploy.DeployError, "grabowski_chronik_full_search"):
            deploy.verify_import_closure(
                module=contract["module"],
                source_bytes=(ROOT / contract["source"]).read_bytes(),
                supporting=supporting,
            )


if __name__ == "__main__":
    unittest.main()
