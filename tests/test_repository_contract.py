from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_live_server_snapshot_exists(self) -> None:
        self.assertTrue((ROOT / "src" / "grabowski_mcp.py").is_file())

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
            "grabowski_rollback_text",
            "grabowski_verify_audit",
            "latest_complete_bundles",
        }
        for tool_name in expected:
            self.assertIn(tool_name, source)
        self.assertNotIn("heim_assi_status", source)

    def test_status_exposes_deployment_provenance(self) -> None:
        source = (
            ROOT / "src" / "grabowski_mcp.py"
        ).read_text(encoding="utf-8")
        self.assertIn("DEPLOYMENT_MANIFEST", source)
        self.assertIn('"deployment": _deployment_metadata()', source)
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

    def test_runtime_entrypoint_contract_exists(self) -> None:
        contract = json.loads(
            (
                ROOT / "config" / "runtime-entrypoint.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(contract["mode"], "module")
        self.assertEqual(contract["module"], "grabowski_mcp")
        self.assertNotIn("script", contract)
        self.assertEqual(contract["source"], "src/grabowski_mcp.py")
        self.assertEqual(
            set(contract["expected_tools"]),
            {
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
                "grabowski_rollback_text",
                "grabowski_verify_audit",
                "latest_complete_bundles",
            },
        )

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
        self.assertEqual(policy["active_profile"], "bounded-read-write")
        self.assertEqual(policy["version"], 2)
        self.assertIn("bounded-read-write", policy["profiles"])
        self.assertIn("home-wide-operator", policy["profiles"])
        self.assertIn(
            "terminal_execute",
            policy["profiles"]["home-wide-operator"]["capabilities"],
        )
        for capability in (
            "secret_inspect",
            "secret_reveal",
            "secret_use",
            "secret_export",
            "browser_profile_read",
        ):
            self.assertIn(
                capability,
                policy["profiles"]["home-wide-operator"]["capabilities"],
            )
            self.assertNotIn(
                capability,
                policy["profiles"]["bounded-read-write"]["capabilities"],
            )
        self.assertNotIn(
            "terminal_execute",
            policy["profiles"]["bounded-read-write"]["capabilities"],
        )
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
                set(policy["profiles"]["home-wide-operator"]["secret_roots"])
            )
        )
        self.assertTrue(
            target_browser_roots.issubset(
                set(policy["profiles"]["home-wide-operator"]["browser_profile_roots"])
            )
        )
        self.assertTrue(
            target_secret_roots.isdisjoint(
                set(policy["profiles"]["home-wide-operator"]["write_excluded_roots"])
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
        self.assertEqual(policy["active_profile"], "home-wide-operator")
        self.assertEqual(policy["version"], 2)
        self.assertEqual(policy["read_roots"], ["${HOME}"])
        self.assertIn("privileged_reference", policy["capability_definitions"])
        self.assertIn("secret_use", policy["capability_definitions"])
        self.assertIn("browser_profile_read", policy["capability_definitions"])
        self.assertEqual(policy["forbidden_components"], [".git"])

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

    def test_privileged_reference_contract_exists(self) -> None:
        contract = json.loads(
            (
                ROOT / "contracts" / "privileged-action-reference.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(contract["properties"]["execution"]["const"], "unprivileged-reference-only")
        self.assertFalse(contract["properties"]["may_execute"]["const"])
        self.assertTrue(contract["properties"]["requires_external_privileged_agent"]["const"])
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
