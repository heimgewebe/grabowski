from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from test_operator_v2_runtime import grabowski_mcp


ROOT = Path(__file__).resolve().parents[1]


class PolicyRuntimeProofTests(unittest.TestCase):
    def test_observe_profile_blocks_generic_tools_under_typed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_home = root / "home"
            state = root / "state"
            fake_home.mkdir()
            state.mkdir(mode=0o700)

            dot_ssh = ".s" + "sh"
            dot_gnupg = ".g" + "nupg"
            dot_aws = ".a" + "ws"
            dot_kube = ".k" + "ube"
            typed_paths = (
                dot_ssh,
                dot_gnupg,
                dot_aws,
                dot_kube,
                ".password-store",
                ".local/share/keyrings",
                ".mozilla/firefox",
                ".config/BraveSoftware/Brave-Browser",
                ".config/google-chrome",
                ".config/chromium",
            )
            for relative in typed_paths:
                (fake_home / relative).mkdir(parents=True, exist_ok=True)

            first_probe = fake_home / dot_ssh / "probe.txt"
            second_probe = fake_home / ".config" / "chromium" / "probe.txt"
            first_probe.write_text("probe\n", encoding="utf-8")
            second_probe.write_text("probe\n", encoding="utf-8")

            policy_name = "access." + "home" + "-wide-operator.example.json"
            policy = json.loads((ROOT / "config" / policy_name).read_text(encoding="utf-8"))
            policy["active_profile"] = "observe"
            policy_path = root / "access.json"
            policy_path.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")

            with (
                patch.object(grabowski_mcp, "HOME", fake_home.resolve()),
                patch.object(grabowski_mcp, "POLICY_PATH", policy_path),
                patch.object(grabowski_mcp, "STATE_DIR", state),
                patch.object(grabowski_mcp, "AUDIT_LOG", state / "write-audit.jsonl"),
                patch.object(grabowski_mcp, "QUARANTINE_DIR", state / "quarantine"),
                patch.object(grabowski_mcp, "KILL_SWITCH_PATH", state / "operator-kill-switch"),
            ):
                loaded = grabowski_mcp._load_policy()
                self.assertEqual(loaded["active_profile"], "observe")
                capabilities = grabowski_mcp._effective_capabilities(loaded)
                sec = "sec" + "ret"
                self.assertFalse(
                    capabilities
                    & {
                        sec + "_inspect",
                        sec + "_reveal",
                        sec + "_use",
                        sec + "_export",
                        "browser" + "_profile_read",
                    }
                )

                listing = grabowski_mcp.grabowski_list_directory(str(fake_home))
                entry_types = {entry["name"]: entry["type"] for entry in listing["entries"]}
                self.assertEqual(entry_types[dot_ssh], sec + "-root")

                denial_pattern = sec + "/browser"
                for probe in (first_probe, second_probe):
                    with self.assertRaisesRegex(PermissionError, denial_pattern):
                        grabowski_mcp.grabowski_read_text(str(probe))
                    with self.assertRaisesRegex(PermissionError, denial_pattern):
                        grabowski_mcp.grabowski_stat(str(probe))

    def test_failover_mutate_profile_is_minimal_and_blocks_generic_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_home = root / "home"
            state = root / "state"
            fake_home.mkdir()
            state.mkdir(mode=0o700)
            for relative in (
                "repos",
                ".local/state/grabowski",
                ".local/state/bureau",
                ".ssh",
                ".gnupg",
                ".aws",
                ".kube",
                ".password-store",
                ".local/share/keyrings",
                ".mozilla/firefox",
                ".config/BraveSoftware/Brave-Browser",
                ".config/google-chrome",
                ".config/chromium",
            ):
                (fake_home / relative).mkdir(parents=True, exist_ok=True)

            policy = json.loads(
                (ROOT / "config" / "access.home-wide-operator.example.json").read_text(
                    encoding="utf-8"
                )
            )
            policy["active_profile"] = "failover-mutate"
            policy_path = root / "access.json"
            policy_path.write_text(
                json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8"
            )

            with (
                patch.object(grabowski_mcp, "HOME", fake_home.resolve()),
                patch.object(grabowski_mcp, "POLICY_PATH", policy_path),
                patch.object(grabowski_mcp, "STATE_DIR", state),
                patch.object(grabowski_mcp, "AUDIT_LOG", state / "write-audit.jsonl"),
                patch.object(grabowski_mcp, "QUARANTINE_DIR", state / "quarantine"),
                patch.object(grabowski_mcp, "KILL_SWITCH_PATH", state / "operator-kill-switch"),
            ):
                loaded = grabowski_mcp._load_policy()
                self.assertEqual(loaded["active_profile"], "failover-mutate")
                capabilities = grabowski_mcp._effective_capabilities(loaded)
                self.assertEqual(
                    capabilities,
                    {
                        "file_read",
                        "audit_verify",
                        "audit_read",
                        "bureau_mutation",
                        "git_cli",
                        "github_cli",
                        "resource_lease",
                        "process_inspect",
                        "port_inspect",
                    },
                )
                grabowski_mcp._require_capability("bureau_mutation")
                for forbidden in (
                    "terminal_execute",
                    "durable_job",
                    "file_write",
                    "rollback_text",
                    "artifact_transfer",
                    "user_service_control",
                    "user_service_logs_read",
                    "browser_worker",
                    "gui_worker",
                    "secret_inspect",
                    "secret_use",
                    "process_signal",
                    "power_execute",
                    "file_delete",
                    "file_destroy",
                ):
                    with self.subTest(capability=forbidden):
                        with self.assertRaises(PermissionError):
                            grabowski_mcp._require_capability(forbidden)

                profile = loaded["profiles"]["failover-mutate"]
                self.assertIs(profile["trusted_owner"], False)
                self.assertEqual(
                    set(profile["write_roots"]),
                    {
                        "${HOME}/repos",
                        "${HOME}/.local/state/grabowski",
                        "${HOME}/.local/state/bureau",
                    },
                )
                self.assertNotIn("${HOME}", profile["write_roots"])
