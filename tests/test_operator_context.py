from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "contracts" / "capability-catalog.v1.json"
CONTEXT = ROOT / "docs" / "generated" / "operator-context.v1.json"


class OperatorContextTests(unittest.TestCase):
    def test_generated_context_is_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "tools/build_operator_context.py", "--check"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=completed.stdout + completed.stderr,
        )

    def test_reposkop_context_contract_is_target_bound(self) -> None:
        command = (
            "reposkop report <absolute-target> --purpose "
            "grabowski-repo-state-context --json"
        )
        root_contract = (ROOT / "GRABOWSKI.md").read_text(encoding="utf-8")
        blocked_protocol = (
            ROOT / "docs" / "blocked-action-protocol-v0.md"
        ).read_text(encoding="utf-8")
        relay_source = (
            ROOT / "src" / "grabowski_operator_relay.py"
        ).read_text(encoding="utf-8")
        self.assertIn(command, root_contract)
        self.assertIn(command, blocked_protocol)
        self.assertNotIn("steuerboard operator report", root_contract.lower())
        self.assertNotIn("steuerboard operator report", blocked_protocol.lower())
        self.assertIn("reposkop_target_bound_report", relay_source)
        self.assertIn("reposkop_report_action_approval", relay_source)
        self.assertNotIn("steuerboard_operator_report", relay_source)
        self.assertNotIn("steuerboard_report_action_approval", relay_source)

    def test_catalog_covers_runtime_contract_exactly(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        tools = [item["tool"] for item in catalog["tools"]]
        self.assertEqual(tools, contract["expected_tools"])
        self.assertNotIn("grabowski_agent_workspace_adopt", tools)
        self.assertEqual(
            catalog["publication_staging"]["implemented_unpublished_tools"],
            ["grabowski_agent_workspace_adopt"],
        )
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        self.assertEqual(
            context["publication_staging"], catalog["publication_staging"]
        )
        self.assertTrue(
            all(not values for values in catalog["integrity"].values())
        )
        self.assertTrue(
            all(
                item["risk_class"] != "unclassified"
                for item in catalog["tools"]
            )
        )

    def test_secret_use_is_generated_as_mutating_capability(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        by_tool = {item["tool"]: item for item in catalog["tools"]}
        self.assertIs(by_tool["grabowski_secret_use"]["read_only"], False)

    def test_host_capability_resolver_is_generated_as_read_only_knowledge(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        by_tool = {item["tool"]: item for item in catalog["tools"]}
        resolver = by_tool["grabowski_host_capability_resolve"]
        self.assertIs(resolver["read_only"], True)
        self.assertEqual(resolver["category"], "knowledge")
        self.assertEqual(resolver["risk_class"], "low")
        self.assertEqual(resolver["effects"], [])

    @staticmethod
    def _host_capability_contract() -> dict[str, object]:
        return {
            "schemaVersion": 1,
            "kind": "heim_pc_operator_entry",
            "authority": "static_local_entry_contract",
            "operatorModel": {"liveStateRequiresFreshRead": True},
            "host": {
                "canonicalEntryFile": "${HOME}/repos/heim-pc/manifest/operator-entry.v1.json",
            },
            "projection": {"byteIdenticalContractRequired": True},
            "pathResolution": {
                "variables": {
                    "HOME": {
                        "source": "operator_process_home",
                        "required": True,
                        "mustResolveToAbsoluteDirectory": True,
                    }
                }
            },
            "capabilityLocators": {
                "audioTranscription": {
                    "schemaVersion": 1,
                    "intents": [
                        "audio.transcribe",
                        "speech_to_text",
                        "transcription",
                        "asr",
                    ],
                    "authority": "heim_pc_asr_open_engine",
                    "authorityKind": "capability_locator_only",
                    "policy": "${HOME}/repos/heim-pc/manifest/asr-engine-policy.v1.json",
                    "entryArgvPrefix": [
                        "python3",
                        "${HOME}/repos/heim-pc/scripts/asr_engine.py",
                    ],
                    "policyResolution": "read_at_execution_time",
                    "consumerEnginePinningAllowed": False,
                    "cloudOrMeteredUseAuthorizedByLocator": False,
                }
            },
        }

    def _run_host_capability_resolution(
        self,
        *,
        intent: str,
        drift_canonical: bool = False,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            installed = home / ".config/heimgewebe/operator-entry.v1.json"
            canonical = home / "repos/heim-pc/manifest/operator-entry.v1.json"
            installed.parent.mkdir(parents=True)
            canonical.parent.mkdir(parents=True)
            contract = self._host_capability_contract()
            encoded = json.dumps(contract, ensure_ascii=False, indent=2) + "\n"
            installed.write_text(encoded, encoding="utf-8")
            canonical.write_text(encoded, encoding="utf-8")
            if drift_canonical:
                changed = dict(contract)
                changed["testDrift"] = True
                canonical.write_text(
                    json.dumps(changed, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
            code = f"""
import json
from pathlib import Path
import sys
import types

class FakeMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function

operator = types.ModuleType('grabowski_operator_core')
operator.mcp = FakeMCP()
operator.HOME = Path.home()
operator.EVIDENCE_ROOT = Path.home() / '.local/state/grabowski/evidence'
operator.PROTECTED_BRANCHES = {{'main', 'master'}}
operator.READ_ONLY = object()
operator.MUTATING = object()
operator.MAX_OUTPUT_BYTES = 1024 * 1024
operator._require_operator_capability = lambda capability: None
operator._safe_environment = lambda: {{}}

sys.modules['grabowski_operator_core'] = operator
sys.modules['grabowski_capabilities'] = types.ModuleType('grabowski_capabilities')
sys.modules['grabowski_mcp'] = types.ModuleType('grabowski_mcp')
sys.modules['grabowski_consumer_surface'] = types.ModuleType('grabowski_consumer_surface')

import grabowski_runtime_extensions as runtime
print(json.dumps(runtime.resolve_host_capability({intent!r}), sort_keys=True))
"""
            environment = dict(os.environ)
            environment.update(
                {
                    "HOME": str(home),
                    "PYTHONPATH": str(ROOT / "src"),
                    "GRABOWSKI_HOST_OPERATOR_ENTRY": str(installed),
                }
            )
            completed = subprocess.run(
                [sys.executable, "-c", code],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=completed.stdout + completed.stderr,
            )
            return json.loads(completed.stdout)

    def test_host_capability_resolver_resolves_transcription_without_model_pinning(self) -> None:
        result = self._run_host_capability_resolution(intent="transcription")
        self.assertEqual(result["status"], "resolved")
        self.assertEqual(result["authority"], "heim_pc_asr_open_engine")
        self.assertEqual(result["authority_kind"], "capability_locator_only")
        self.assertEqual(result["matching"]["locator_id"], "audioTranscription")
        self.assertEqual(result["policy_resolution"], "read_at_execution_time")
        self.assertIs(result["locator"]["consumerEnginePinningAllowed"], False)
        self.assertIs(result["locator"]["cloudOrMeteredUseAuthorizedByLocator"], False)
        self.assertTrue(result["contract_identity"]["matches"])
        self.assertEqual(
            result["contract_identity"]["installed"]["sha256"],
            result["contract_identity"]["canonical"]["sha256"],
        )
        self.assertTrue(Path(result["resolved_locator"]["policy"]).is_absolute())
        rendered = json.dumps(result, ensure_ascii=False).lower()
        for engine_name in ("faster-whisper", "qwen", "parakeet"):
            self.assertNotIn(engine_name, rendered)

    def test_host_capability_resolver_blocks_installed_projection_drift(self) -> None:
        result = self._run_host_capability_resolution(
            intent="transcription",
            drift_canonical=True,
        )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["error"]["code"], "installed_projection_drift")

    def test_host_capability_resolver_returns_not_found_without_guessing(self) -> None:
        result = self._run_host_capability_resolution(intent="nonexistent.intent")
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["matching"]["match_count"], 0)
        self.assertNotIn("authority", result)

    def test_browser_operator_default_is_runtime_bound_and_generated(self) -> None:
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        browser = contract["browser_operator_default"]
        self.assertEqual(browser["authority"], "grabowski")
        self.assertEqual(browser["canonical_browser"]["family"], "chrome-stable")
        self.assertEqual(browser["canonical_browser"]["adapter"], "chrome-cdp")
        self.assertEqual(browser["transport"]["primary"], "direct-cdp")
        self.assertEqual(browser["semantic_gateway"]["coverage"], "partial")
        self.assertEqual(
            browser["semantic_gateway"]["tool"],
            "grabowski_browser_worker_semantic",
        )
        self.assertEqual(browser["semantic_gateway"]["operations"], ["observe", "act"])
        self.assertEqual(
            browser["semantic_gateway"]["supported_intents"],
            ["read_state", "navigate", "scroll_into_view"],
        )
        self.assertEqual(browser["semantic_gateway"]["uncovered_intents"], {})
        self.assertEqual(
            browser["semantic_gateway"]["public_target_contract"],
            "opaque-handles-and-validated-navigation-targets",
        )
        self.assertEqual(
            browser["semantic_gateway"]["implemented_effect_classes"],
            ["read", "local_ui", "network_navigation"],
        )
        self.assertFalse(
            browser["semantic_gateway"]["ambiguous_effect_retry_authorized"]
        )
        self.assertIs(browser["transport"]["loopback_only"], True)
        self.assertEqual(browser["profile"]["default"], "ephemeral")
        self.assertIs(browser["human_browser_default"]["preserve"], True)
        self.assertEqual(browser["human_browser_default"]["browser"], "brave")

        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        self.assertEqual(context["browser_operator_contract"], browser)

        capability = next(
            item
            for item in context["capabilities"]
            if item["tool"] == "grabowski_browser_worker_semantic"
        )
        self.assertEqual(capability["risk_class"], "high")
        self.assertIn("browser-network-navigation", capability["effects"])

        entry = (ROOT / "GRABOWSKI.md").read_text(encoding="utf-8")
        self.assertIn("browser_operator_contract", entry)
        runtime = (ROOT / "src" / "grabowski_runtime_extensions.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"browser_operator_contract": browser_operator_contract', runtime)
        consumer = (ROOT / "src" / "grabowski_consumer_surface.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('CONTEXT_REQUIRED_FIELDS = (', consumer)
        self.assertIn('required=consumer_surface.CONTEXT_REQUIRED_FIELDS', runtime)

    def test_secret_reveal_is_not_read_only_in_generated_contracts(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        catalog_tool = next(
            item for item in catalog["tools"]
            if item["tool"] == "grabowski_secret_reveal"
        )
        context_tool = next(
            item for item in context["capabilities"]
            if item["tool"] == "grabowski_secret_reveal"
        )
        self.assertIs(catalog_tool["read_only"], False)
        self.assertIs(context_tool["read_only"], False)

    def test_repository_context_points_to_live_context(self) -> None:
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        self.assertEqual(context["kind"], "repository-operator-context")
        self.assertIn(
            "grabowski_context",
            context["runtime_contract"]["expected_tools"],
        )
        entry = (ROOT / "GRABOWSKI.md").read_text(encoding="utf-8")
        self.assertIn('grabowski_context(profile="concise")', entry)
        self.assertIn("make context-refresh", entry)
        self.assertIn("make validate", entry)
        self.assertIn("docs/blocked-action-protocol-v0.md", entry)
        self.assertIn("Operator Relay v0", entry)

    def test_operator_relay_protocol_is_in_generated_context(self) -> None:
        context = json.loads(CONTEXT.read_text(encoding="utf-8"))
        protocol = context["operating_protocol"]
        self.assertEqual(protocol["name"], "Operator Relay v0")
        self.assertEqual(
            protocol["doc_path"],
            "docs/blocked-action-protocol-v0.md",
        )
        self.assertEqual(
            protocol["control_loop"],
            [
                "typed_grabowski_tool",
                "grabowski_micro_task",
                "receipt_before_next_step",
            ],
        )
        self.assertEqual(
            protocol["execution_priority"],
            ["chatgpt_operator", "claude", "codex", "antigravity", "opencode", "openhands", "cline"],
        )
        self.assertEqual(
            protocol["coding_agent_priority"],
            ["claude", "codex", "antigravity", "opencode", "openhands", "cline"],
        )
        self.assertEqual(
            protocol["review_and_contrast_agent_priority"],
            ["claude", "codex", "antigravity", "opencode", "openhands", "cline"],
        )
        self.assertEqual(
            protocol["coding_agent_priority_semantics"],
            "routing_preference_not_authority",
        )
        self.assertEqual(
            protocol["execution_priority_semantics"],
            "routing_preference_not_model_authority",
        )
        self.assertEqual(
            protocol["authority_principle"],
            "model_identity_does_not_grant_authority",
        )
        self.assertEqual(
            protocol["authority_roles"],
            {
                "controller": {
                    "authoritative": True,
                    "may_delegate": True,
                    "owns": [
                        "planning",
                        "integration",
                        "merge",
                        "deployment",
                        "closeout",
                    ],
                },
                "scoped_writer": {
                    "authoritative_within_lane": True,
                    "requires": [
                        "explicit_lane",
                        "resource_scope",
                        "controller_binding",
                    ],
                    "allowed_effects": [
                        "implement",
                        "test",
                        "commit",
                        "push",
                        "pull_request_create_or_update",
                    ],
                    "forbidden_without_controller": [
                        "merge",
                        "deployment",
                        "bureau_terminalization",
                        "closeout",
                    ],
                },
                "reviewer": {
                    "authoritative": False,
                    "mode": "advisory",
                    "read_only": True,
                },
                "observer": {
                    "authoritative": False,
                    "mode": "evidence",
                    "read_only": True,
                },
            },
        )
        self.assertEqual(
            protocol["workspace_execution_model"],
            {
                "default": "controller_direct_or_delegated_scoped_writer",
                "lane_owner": "controller",
                "operator_self_serves_lanes": [
                    "captain",
                    "writer",
                    "tests",
                    "review",
                    "integration",
                    "merge",
                    "deployment",
                    "closeout",
                ],
                "role_evidence_isolated": True,
                "workspace_not_universal": True,
                "direct_operator_for": [
                    "unscoped_or_ambiguous_work",
                    "integration",
                    "merge",
                    "deployment",
                    "closeout",
                    "recovery",
                ],
                "full_workspace_for": [],
                "external_agent_delegation": "role_bound_scoped_writer_reviewer_or_observer",
                "delegation_triggers": [
                    "bounded_implementation_lane",
                    "disjoint_capacity_lane",
                    "independent_review",
                    "security_or_architecture_review",
                    "explicit_contrast_request",
                    "multiple_plausible_implementations_for_comparison",
                ],
                "external_programming_modes": ["scoped_writer", "competitor", "contrast"],
                "max_external_candidates": 2,
                "external_candidate_authority": "role_dependent",
                "external_primary_writer_forbidden": False,
                "external_primary_reviewer_forbidden": True,
                "capacity_fallback_to_external_writer": True,
                "automatic_patch_apply": False,
                "automatic_winner_selection": False,
            },
        )
        self.assertEqual(
            protocol["routing_roles"]["complex_code_task"],
            "controller_or_lane_bound_scoped_writer",
        )
        self.assertIn(
            "blocked_action_protocol",
            context["sources"],
        )
        self.assertEqual(
            protocol["routing_roles"]["patch_file_relay"],
            "operator_patch_relay",
        )
        self.assertIn(
            "automatic_merge",
            protocol["does_not_establish"],
        )
        self.assertEqual(
            protocol["routing_roles"]["repo_state_context"],
            "reposkop_target_bound_report",
        )
        self.assertIn(
            "reposkop_report_action_approval",
            protocol["does_not_establish"],
        )

    def test_branch_control_is_typed_and_guarded(self) -> None:
        source = (
            ROOT / "src" / "grabowski_runtime_extensions.py"
        ).read_text(encoding="utf-8")
        self.assertIn('name="grabowski_git_branch"', source)
        self.assertIn('"check-ref-format"', source)
        self.assertIn("PROTECTED_BRANCHES", source)
        self.assertIn('operator._require_operator_mutation("git_cli")', source)
        self.assertIn("_append_audit", source)
        self.assertNotIn("shell=True", source)

    def test_runtime_wrapper_preserves_live_module_contract(self) -> None:
        source = (ROOT / "src" / "grabowski_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertLess(
            source.index("import grabowski_operator_core"),
            source.index("import grabowski_runtime_extensions"),
        )
        self.assertIn("grabowski_operator_core.main()", source)
        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(contract["module"], "grabowski_operator")


if __name__ == "__main__":
    unittest.main()
