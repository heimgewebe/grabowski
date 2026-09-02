from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import kleiner_maulwurf_operator as mole


class TestKleinerMaulwurfOperator(unittest.TestCase):
    def test_source_asset_matches_embedded_icon(self) -> None:
        asset = SRC / "kleiner_maulwurf_logo_512.png"
        payload = asset.read_bytes()

        self.assertEqual(mole.ICON_BYTES, len(payload))
        self.assertEqual(mole.ICON_SHA256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(payload, mole.icon_bytes())
        self.assertTrue(payload.startswith(b"\x89PNG\r\n\x1a\n"))
        width, height = struct.unpack(">II", payload[16:24])
        self.assertEqual((512, 512), (width, height))

    def test_icon_data_uri_is_valid_png(self) -> None:
        prefix = "data:image/png;base64,"
        uri = mole.icon_data_uri()

        self.assertTrue(uri.startswith(prefix))
        decoded = base64.b64decode(uri.removeprefix(prefix), validate=True)
        self.assertEqual(mole.ICON_SHA256, hashlib.sha256(decoded).hexdigest())

    def test_configure_sets_server_info_icon_without_changing_tools(self) -> None:
        server = mole.operator.mcp._mcp_server
        original_icons = server.icons
        before_tools = set(mole.operator.mcp._tool_manager._tools)
        try:
            icon = mole.configure_kleiner_maulwurf_icon()
            self.assertEqual([icon], mole.operator.mcp.icons)
            self.assertEqual("image/png", icon.mimeType)
            self.assertEqual(["512x512"], icon.sizes)
            self.assertEqual(before_tools, set(mole.operator.mcp._tool_manager._tools))
        finally:
            server.icons = original_icons

    def test_runtime_contract_installs_mole_entrypoint(self) -> None:
        contract = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        sources = {
            item["module"]: item["source"]
            for item in contract["supporting_sources"]
        }
        self.assertEqual(
            "src/kleiner_maulwurf_operator.py",
            sources.get("kleiner_maulwurf_operator"),
        )

    def test_main_configures_icon_before_running_operator(self) -> None:
        calls: list[str] = []
        with (
            patch.object(
                mole,
                "configure_kleiner_maulwurf_icon",
                side_effect=lambda: calls.append("configure"),
            ),
            patch.object(
                mole.operator,
                "main",
                side_effect=lambda: calls.append("main"),
            ),
        ):
            mole.main()

        self.assertEqual(["configure", "main"], calls)


if __name__ == "__main__":
    unittest.main()
