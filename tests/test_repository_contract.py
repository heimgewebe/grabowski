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
            "grabowski_create_text",
            "grabowski_replace_text",
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
        self.assertIn('"repo_head"', source)
        self.assertIn('"runtime_lock_sha256"', source)

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

    def test_runtime_credentials_are_ignored(self) -> None:
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("*.runtime.env", gitignore)
        self.assertIn(".env", gitignore)
        self.assertIn("access.json", gitignore)


if __name__ == "__main__":
    unittest.main()
