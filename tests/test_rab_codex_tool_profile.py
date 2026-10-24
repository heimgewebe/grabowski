"""Verify that official Codex model tools cannot access auth or the network.

Tests construct exact production Codex argv. They never invoke a model.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_repobrief_agent_benchmark_codex_runner import (
    request,
    runner,
    synthetic_parent_mcp_bridge,
    synthetic_prepared_stage,
)


class CodexToolProfileSecurityTests(unittest.TestCase):
    def test_both_arms_deny_auth_file_reads_and_outbound_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "repo"
            checkout.mkdir()
            codex_home = root / "codex-home"
            schema = root / "schema.json"
            baseline = runner.build_command(
                request(), "/opt/codex", checkout, schema, codex_home
            )
            with patch.object(
                runner, "_validated_mcp_proxy_python",
                return_value="/fixture/python3",
            ):
                treatment = runner.build_command(
                    request(condition="treatment"),
                    "/opt/codex", checkout, schema, codex_home,
                    authorized_mcp_files=[],
                    proxy_path=(root / "bound-proxy.py").resolve(),
                    manifest_path=(root / "bound.bundle.manifest.json").resolve(),
                    mcp_runtime_root=(root / "state").resolve(),
                    prepared_mcp_stage=synthetic_prepared_stage(root),
                    mcp_bridge=synthetic_parent_mcp_bridge(codex_home),
                )
            denial = runner._toml_string(str(codex_home / "auth.json")) + '="deny"'
            no_network = (
                f"permissions.{runner.PERMISSION_PROFILE}.network="
                '{enabled=false,mode="limited",allow_local_binding=false,domains={}}'
            )
            for arm, argv in (("baseline", baseline), ("treatment", treatment)):
                with self.subTest(arm=arm):
                    filesystem = [
                        value for value in argv
                        if value.startswith(
                            f"permissions.{runner.PERMISSION_PROFILE}.filesystem="
                        )
                    ]
                    self.assertEqual(len(filesystem), 1)
                    self.assertEqual(filesystem[0].count(denial), 1)
                    self.assertEqual(argv.count(no_network), 1)
                    self.assertNotIn(
                        no_network.replace("enabled=false", "enabled=true"), argv
                    )


if __name__ == "__main__":
    unittest.main()
