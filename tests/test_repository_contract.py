from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_live_server_snapshot_exists(self) -> None:
        self.assertTrue((ROOT / "src" / "grabowski_mcp.py").is_file())
        self.assertTrue((ROOT / "src" / "grabowski_operator.py").is_file())
        self.assertTrue(
            (ROOT / "src" / "grabowski_runtime_extensions.py").is_file()
        )
        self.assertTrue((ROOT / "src" / "grabowski_checkouts.py").is_file())
        self.assertTrue((ROOT / "src" / "grabowski_runtime.py").is_file())
        self.assertTrue((ROOT / "src" / "grabowski_read_surface.py").is_file())
        self.assertTrue((ROOT / "src" / "grabowski_grip_orchestration.py").is_file())
        self.assertTrue((ROOT / "src" / "grabowski_merge_guard.py").is_file())

    def test_grabowski_tool_names_are_present(self) -> None:
        source = (
            ROOT / "src" / "grabowski_mcp.py"
        ).read_text(encoding="utf-8")
        expected = {
            "grabowski_status",
            "grabowski_list_directory",
            "grabowski_stat",
            "grabowski_read_text",
            "grabowski_secret_inspect",
            "grabowski_secret_reveal",
            "grabowski_secret_use",
            "grabowski_secret_export",
            "grabowski_browser_profile_read",
            "grabowski_create_text",
            "grabowski_replace_text",
            "grabowski_remove_path",
            "grabowski_restore_removed_path",
            "grabowski_destroy_path",
            "grabowski_rollback_text",
            "grabowski_verify_audit",
            "latest_complete_bundles",
        }
        for tool_name in expected:
            self.assertIn(tool_name, source)
        self.assertNotIn("heim_assi_status", source)

    def test_extension_tool_names_are_present(self) -> None:
        source = (
            ROOT / "src" / "grabowski_runtime_extensions.py"
        ).read_text(encoding="utf-8")
        self.assertIn('name="grabowski_context"', source)
        self.assertIn('name="grabowski_git_branch"', source)
        self.assertIn("connector_snapshot_observable", source)
        self.assertIn("canonical_checkout_matches_runtime", source)

    def test_status_exposes_live_tool_contract_fingerprint(self) -> None:
        source = (ROOT / "src" / "grabowski_mcp.py").read_text(encoding="utf-8")
        self.assertIn("tool_contract = _runtime_tool_contract_summary()", source)
        self.assertIn('"tool_contract": {', source)
        self.assertIn('"registered_names_sha256"', source)
        self.assertIn('"client_snapshot_observable": False', source)

    def test_status_surfaces_operator_relay_protocol(self) -> None:
        source = (ROOT / "src" / "grabowski_mcp.py").read_text(encoding="utf-8")
        self.assertIn("def _operator_relay_protocol()", source)
        self.assertIn('"operating_protocol": _operator_relay_protocol()', source)
        self.assertIn('"Operator Relay v0"', source)
        self.assertIn('"typed_grabowski_tool"', source)
        self.assertIn('"grabowski_micro_task"', source)
        self.assertIn('"routing_roles"', source)
        self.assertIn('"execution_priority"', source)
        self.assertIn('"chatgpt_operator_adaptive_workspace_external_competition_when_high_value"', source)
        self.assertIn('"external_programming_modes": ["competitor", "contrast"]', source)
        self.assertIn('"automatic_winner_selection": False', source)
        self.assertIn('"chatgpt_operator_external_opt_in_agy_print"', source)
        self.assertIn('"cline"', source)
        self.assertIn('"ollama_api_qwen_coder"', source)
        self.assertIn('"operator_patch_relay"', source)
        self.assertIn('"automatic_merge"', source)
        self.assertIn('"automatic_push"', source)
        self.assertIn('"automatic_deploy"', source)

    def test_operator_patch_relay_is_syntax_checked(self) -> None:
        self.assertTrue((ROOT / "tools" / "operator_patch_relay.py").is_file())
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("tools/operator_patch_relay.py", makefile)

    def test_status_exposes_deployment_provenance(self) -> None:
        source = (
            ROOT / "src" / "grabowski_mcp.py"
        ).read_text(encoding="utf-8")
        self.assertIn("DEPLOYMENT_MANIFEST", source)
        self.assertIn("deployment = _deployment_metadata()", source)
        self.assertIn('"deployment": deployment', source)
        self.assertIn('"active_profile"', source)
        self.assertIn('"capabilities"', source)
        self.assertIn('"kill_switch"', source)
        self.assertIn('"audit"', source)
        self.assertIn('"secret_roots"', source)
        self.assertIn('"browser_profile_roots"', source)
        self.assertIn('"secret_export_roots"', source)
        self.assertIn('"repo_head"', source)
        self.assertIn('"runtime_lock_sha256"', source)
        self.assertIn('"manifest_schema_valid"', source)
        self.assertIn('"release_path_valid"', source)
        self.assertIn('"source_identity_valid"', source)
        self.assertIn('"runtime_pointer_valid"', source)
        self.assertIn('"entrypoint_contract_identity_valid"', source)
        self.assertIn('"release_python_identity_valid"', source)
        self.assertIn('"python_runtime_identity_valid"', source)
        self.assertNotIn('"manifest_valid"', source)

    def test_make_test_uses_unique_test_home(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn('mktemp -d "$(CURDIR)/build/test-home.XXXXXX"', makefile)
        self.assertNotIn('test_home="$(CURDIR)/build/test-home"', makefile)

    def test_runtime_entrypoint_contract_exists(self) -> None:
        contract = json.loads(
            (
                ROOT / "config" / "runtime-entrypoint.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(contract["schema_version"], 2)
        self.assertEqual(contract["mode"], "module")
        self.assertEqual(contract["module"], "grabowski_operator")
        self.assertNotIn("script", contract)
        self.assertEqual(contract["source"], "src/grabowski_runtime.py")
        tools = set(contract["expected_tools"])
        self.assertEqual(len(tools), 131)
        self.assertTrue(
            {
                "grabowski_juno_status",
                "grabowski_juno_pair",
                "grabowski_juno_run",
            }.issubset(tools)
        )
        legacy_tools = {
            "grabowski_status",
            "grabowski_context",
            "grabowski_list_directory",
            "grabowski_stat",
            "grabowski_read_text",
            "grabowski_create_text",
            "grabowski_replace_text",
            "latest_complete_bundles",
            "grabowski_terminal_run",
            "grabowski_job_start",
            "grabowski_job_status",
            "grabowski_job_logs",
            "grabowski_job_cancel",
            "grabowski_git",
            "grabowski_git_branch",
            "grabowski_github",
            "grabowski_user_service",
            "grabowski_tmux_list",
            "grabowski_tmux_capture",
            "grabowski_tmux_send",
            "grabowski_process_list",
            "grabowski_process_signal",
            "grabowski_ports",
        }
        self.assertTrue(legacy_tools.issubset(tools))
        self.assertIn("grabowski_status", tools)
        self.assertIn("grabowski_context", tools)
        self.assertIn("grabowski_terminal_run", tools)
        self.assertIn("grabowski_job_start", tools)
        self.assertIn("grabowski_git_branch", tools)
        self.assertIn("grabowski_checkout_inventory", tools)
        self.assertIn("grabowski_checkout_retain", tools)
        self.assertIn("grabowski_checkout_archive", tools)
        self.assertIn("grabowski_checkout_cleanup", tools)
        self.assertIn("grabowski_secret_reveal", tools)
        self.assertIn("grabowski_rollback_text", tools)
        self.assertIn("grabowski_remove_path", tools)
        self.assertIn("grabowski_restore_removed_path", tools)
        self.assertIn("grabowski_destroy_path", tools)
        self.assertIn("grabowski_privileged_action_reference", tools)
        self.assertIn("grabowski_recovery_server_probe", tools)
        self.assertIn("grabowski_friction_record", tools)
        self.assertIn("grabowski_friction_resolve", tools)
        self.assertIn("grabowski_friction_summary", tools)
        self.assertIn("grabowski_execution_shape", tools)
        self.assertIn("grabowski_execution_outcome_record", tools)
        self.assertIn("grabowski_execution_governor_summary", tools)
        self.assertIn("grabowski_connector_transport_diagnostics", tools)
        self.assertIn("grabowski_operator_recall_export", tools)
        supporting = {item["module"]: item["source"] for item in contract["supporting_sources"]}
        self.assertEqual(supporting["grabowski_operator_core"], "src/grabowski_operator.py")
        self.assertEqual(supporting["grabowski_read_surface"], "src/grabowski_read_surface.py")
        self.assertEqual(supporting["grabowski_self_deploy"], "src/grabowski_self_deploy.py")
        self.assertEqual(
            supporting["grabowski_privileged_broker"],
            "src/grabowski_privileged_broker.py",
        )
        self.assertEqual(supporting["grabowski_grip_orchestration"], "src/grabowski_grip_orchestration.py")
        self.assertEqual(supporting["grabowski_merge_guard"], "src/grabowski_merge_guard.py")
        for module in ("grabowski_mcp", "grabowski_grips", "grabowski_convergence", "grabowski_grip_orchestration", "grabowski_merge_guard", "grabowski_operator_obligation", "grabowski_capabilities", "grabowski_runtime_extensions", "grabowski_read_surface", "grabowski_self_deploy", "grabowski_checkouts", "grabowski_fleet", "grabowski_operations", "grabowski_privileged", "grabowski_privileged_broker", "grabowski_tasks", "grabowski_recovery", "grabowski_friction", "grabowski_agent_bootstrap", "grabowski_recall", "grabowski_consumer_surface", "grabowski_private_io", "grabowski_job_origin", "grabowski_job_finalizer"):

            self.assertIn(module, supporting)
            self.assertTrue((ROOT / supporting[module]).is_file())

    def test_runtime_lock_contract_exists(self) -> None:
        runtime_input = ROOT / "requirements" / "runtime.in"
        runtime_lock = ROOT / "requirements" / "runtime.lock.txt"
        self.assertTrue(runtime_input.is_file())
        self.assertTrue(runtime_lock.is_file())
        self.assertEqual(
            runtime_input.read_text(encoding="utf-8").strip(),
            "mcp==1.27.2",
        )
        lock_text = runtime_lock.read_text(encoding="utf-8")
        self.assertIn("mcp==1.27.2", lock_text)
        self.assertIn("--hash=sha256:", lock_text)

    def test_deploy_tooling_lock_contract_exists(self) -> None:
        tooling_input = ROOT / "requirements" / "deploy-tooling.in"
        tooling_lock = ROOT / "requirements" / "deploy-tooling.lock.txt"
        self.assertTrue(tooling_input.is_file())
        self.assertTrue(tooling_lock.is_file())
        self.assertEqual(
            tooling_input.read_text(encoding="utf-8").strip(),
            "PyYAML==6.0.3",
        )
        lock_text = tooling_lock.read_text(encoding="utf-8")
        self.assertIn("pyyaml==6.0.3", lock_text)
        self.assertIn("--hash=sha256:", lock_text)

    def test_merges_is_explicitly_read_only(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertIn(
            "${HOME}/repos/merges",
            policy["write_excluded_roots"],
        )
        for profile in policy["profiles"].values():
            self.assertIn(
                "${HOME}/repos/merges",
                profile["write_excluded_roots"],
            )

    def test_access_profiles_and_capabilities_are_explicit(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(policy["active_profile"], "observe")
        self.assertEqual(policy["version"], 2)
        self.assertEqual(
            set(policy["profiles"]),
            {"observe", "maintain", "mutate", "break-glass"},
        )
        for profile in policy["profiles"].values():
            self.assertIn("allowed_grips", profile)
            self.assertIn("forbidden_hosts", profile)
            self.assertIn("max_risk_level", profile)
            self.assertIn(profile["max_risk_level"], {"low", "medium", "high"})
        observe_caps = set(policy["profiles"]["observe"]["capabilities"])
        maintain_caps = set(policy["profiles"]["maintain"]["capabilities"])
        mutate_caps = set(policy["profiles"]["mutate"]["capabilities"])
        break_glass_caps = set(policy["profiles"]["break-glass"]["capabilities"])
        self.assertEqual(policy["profiles"]["observe"]["max_risk_level"], "low")
        self.assertEqual(policy["profiles"]["mutate"]["max_risk_level"], "medium")
        self.assertEqual(policy["profiles"]["break-glass"]["max_risk_level"], "high")
        self.assertIn("repo-orient", policy["profiles"]["observe"]["allowed_grips"])
        self.assertNotIn("captain-run", policy["profiles"]["mutate"]["allowed_grips"])
        for capability in ("file_read", "audit_verify", "bundle_registry"):
            self.assertIn(capability, observe_caps)
            self.assertIn(capability, maintain_caps)
        for capability in (
            "file_write",
            "terminal_execute",
            "secret_reveal",
            "file_destroy",
            "process_signal",
            "durable_job",
            "resource_lease",
            "git_cli",
            "github_cli",
            "user_service_control",
        ):
            self.assertNotIn(capability, observe_caps)
            self.assertNotIn(capability, maintain_caps)
        for capability in (
            "file_write",
            "durable_job",
            "resource_lease",
            "git_cli",
            "github_cli",
            "user_service_control",
        ):
            self.assertIn(capability, mutate_caps)
        for capability in (
            "terminal_execute",
            "secret_reveal",
            "secret_use",
            "secret_export",
            "browser_profile_read",
            "file_destroy",
            "process_signal",
            "tmux_interaction",
        ):
            self.assertNotIn(capability, mutate_caps)
            self.assertIn(capability, break_glass_caps)
        target_secret_roots = {
            "${HOME}/.ssh",
            "${HOME}/.gnupg",
            "${HOME}/.aws",
            "${HOME}/.kube",
            "${HOME}/.password-store",
            "${HOME}/.local/share/keyrings",
        }
        target_browser_roots = {
            "${HOME}/.mozilla/firefox",
            "${HOME}/.config/BraveSoftware/Brave-Browser",
            "${HOME}/.config/google-chrome",
            "${HOME}/.config/chromium",
        }
        self.assertTrue(
            target_secret_roots.issubset(
                set(policy["profiles"]["break-glass"]["secret_roots"])
            )
        )
        self.assertTrue(
            target_browser_roots.issubset(
                set(policy["profiles"]["break-glass"]["browser_profile_roots"])
            )
        )
        self.assertEqual(policy["forbidden_components"], [".git"])
        self.assertNotIn("id_ed25519", policy["forbidden_file_patterns"])
        self.assertNotIn("id_rsa", policy["forbidden_file_patterns"])

    def test_home_wide_operator_example_is_not_live_metadata(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.home-wide-operator.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(policy["active_profile"], "break-glass")
        self.assertEqual(policy["version"], 2)
        self.assertEqual(policy["read_roots"], ["${HOME}"])
        self.assertEqual(
            set(policy["profiles"]),
            {"observe", "maintain", "mutate", "break-glass"},
        )
        self.assertIn(
            "terminal_execute",
            policy["profiles"]["break-glass"]["capabilities"],
        )
        self.assertIn("privileged_reference", policy["capability_definitions"])
        self.assertIn("secret_use", policy["capability_definitions"])
        self.assertIn("browser_profile_read", policy["capability_definitions"])
        self.assertEqual(policy["profiles"]["break-glass"]["allowed_grips"], ["*"])
        self.assertEqual(policy["profiles"]["break-glass"]["max_risk_level"], "high")
        self.assertEqual(policy["forbidden_components"], [".git"])

    def test_home_wide_profiles_with_home_roots_keep_typed_roots(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.home-wide-operator.example.json"
            ).read_text(encoding="utf-8")
        )
        expected_secret_roots = set(policy["secret_roots"])
        expected_browser_roots = set(policy["browser_profile_roots"])
        for profile_name, profile in policy["profiles"].items():
            if (
                "${HOME}" not in profile["read_roots"]
                and "${HOME}" not in profile["write_roots"]
            ):
                continue
            with self.subTest(profile=profile_name, root_type="secret"):
                self.assertTrue(
                    expected_secret_roots.issubset(set(profile["secret_roots"]))
                )
            with self.subTest(profile=profile_name, root_type="browser"):
                self.assertTrue(
                    expected_browser_roots.issubset(
                        set(profile["browser_profile_roots"])
                    )
                )

    def test_access_policy_schema_versions_are_separate(self) -> None:
        v1 = json.loads(
            (
                ROOT / "contracts" / "access-policy.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        v2 = json.loads(
            (
                ROOT / "contracts" / "access-policy.v2.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(v1["properties"]["version"]["const"], 1)
        self.assertEqual(v2["properties"]["version"]["const"], 2)
        self.assertNotIn("secret_roots", v1["properties"])
        self.assertIn("secret_roots", v2["properties"])
        self.assertIn("allowed_grips", v2["properties"]["profiles"]["additionalProperties"]["required"])
        self.assertIn("forbidden_hosts", v2["properties"]["profiles"]["additionalProperties"]["required"])
        self.assertIn("max_risk_level", v2["properties"]["profiles"]["additionalProperties"]["required"])

    def test_privileged_reference_contract_exists(self) -> None:
        contract = json.loads(
            (
                ROOT / "contracts" / "privileged-action-reference.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            contract["properties"]["execution"]["const"],
            "unprivileged-reference-only",
        )
        self.assertFalse(contract["properties"]["may_execute"]["const"])
        self.assertTrue(
            contract["properties"]["requires_external_privileged_agent"]["const"]
        )
        self.assertIn("expires_at_unix", contract["required"])
        self.assertEqual(
            contract["properties"]["replay_policy"]["const"],
            "single-use-external-broker",
        )

    def test_runtime_credentials_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("*.runtime.env", gitignore)
        self.assertIn(".env", gitignore)
        self.assertIn("access.json", gitignore)


if __name__ == "__main__":
    unittest.main()
