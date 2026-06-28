from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_publication_profiles_test",
    ROOT / "tools" / "build_publication_profiles.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load publication-profile builder")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class PublicationProfileTests(unittest.TestCase):
    def test_generated_contract_is_current(self) -> None:
        expected = BUILDER.render(BUILDER.build())
        actual = (ROOT / "contracts" / "publication-profiles.v1.json").read_text(
            encoding="utf-8"
        )
        self.assertEqual(actual, expected)

    def test_full_profile_matches_canonical_order(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        profiles = BUILDER.build()["profiles"]
        self.assertEqual(profiles["full"], contract["expected_tools"])

    def test_core_contains_exact_bounded_observational_tools(self) -> None:
        payload = BUILDER.build()
        catalog = json.loads(
            (ROOT / "contracts" / "capability-catalog.v1.json").read_text(
                encoding="utf-8"
            )
        )
        by_tool = {record["tool"]: record for record in catalog["tools"]}
        self.assertEqual(set(payload["profiles"]["core"]), BUILDER.CORE_TOOLS)
        for tool in payload["profiles"]["core"]:
            record = by_tool[tool]
            self.assertIs(record["read_only"], True)
            self.assertIn(record["risk_class"], {"low", "medium"})
            self.assertTrue(
                set(record["effects"]).issubset({"remote-read"}),
                msg=f"non-observational core effect for {tool}: {record['effects']}",
            )
        for excluded in (
            "grabowski_terminal_run",
            "grabowski_git",
            "grabowski_user_service",
            "grabowski_browser_profile_read",
            "grabowski_list_directory",
            "grabowski_stat",
            "grabowski_read_text",
            "grabowski_tmux_list",
            "grabowski_tmux_capture",
            "grabowski_process_list",
            "grabowski_browser_worker_list",
            "grabowski_gui_worker_list",
            "grabowski_job_logs",
            "grabowski_task_logs",
            "grabowski_operation_plan",
            "grabowski_resource_list",
            "grabowski_artifact_stat",
            "grabowski_context",
            "grabowski_status",
            "grabowski_privileged_action_reference",
            "grabowski_runtime_deploy_schedule",
        ):
            self.assertNotIn(excluded, payload["profiles"]["core"])

    def test_operator_retains_escape_hatches_and_orientation(self) -> None:
        operator = set(BUILDER.build()["profiles"]["operator"])
        for tool in (
            "grabowski_terminal_run",
            "grabowski_git",
            "grabowski_github",
            "grabowski_user_service",
            "grabowski_runtime_deploy_schedule",
            "grabowski_runtime_health",
            "grabowski_contract_drift",
        ):
            self.assertIn(tool, operator)

    def test_no_second_connector_is_registered(self) -> None:
        registration = BUILDER.build()["registration"]
        self.assertFalse(registration["second_connector_created"])
        self.assertTrue(registration["requires_canary_evidence"])


if __name__ == "__main__":
    unittest.main()
