from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import der_kleine_maulwurf_operator as mole  # noqa: E402


class _TestIcon:
    def __init__(self, *, src: str, mimeType: str | None = None, sizes=None):
        self.src = src
        self.mimeType = mimeType
        self.sizes = sizes


class TestDerKleineMaulwurfOperator(unittest.TestCase):
    def test_source_asset_matches_embedded_icon(self) -> None:
        asset = SRC / "der_kleine_maulwurf_logo_512.png"
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

    def test_mcp_icons_uses_public_icon_type(self) -> None:
        fake_mcp = types.ModuleType("mcp")
        fake_types = types.ModuleType("mcp.types")
        fake_types.Icon = _TestIcon
        fake_mcp.types = fake_types

        with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types}):
            icons = mole.mcp_icons()

        self.assertEqual(1, len(icons))
        icon = icons[0]
        self.assertEqual("image/png", icon.mimeType)
        self.assertEqual(["512x512"], icon.sizes)
        self.assertEqual(mole.icon_data_uri(), icon.src)

    def test_branding_provider_uses_no_private_fastmcp_state(self) -> None:
        source = (SRC / "der_kleine_maulwurf_operator.py").read_text(encoding="utf-8")
        self.assertNotIn("_mcp_server", source)
        self.assertNotIn("grabowski_operator", source)

    def test_core_selects_branding_at_public_fastmcp_constructor(self) -> None:
        source = (SRC / "grabowski_mcp.py").read_text(encoding="utf-8")
        self.assertIn(
            'MCP_BRANDING_VARIANT_ENV = "GRABOWSKI_MCP_BRANDING_VARIANT"',
            source,
        )
        self.assertIn(
            'DER_KLEINE_MAULWURF_BRANDING_VARIANT = "der-kleine-maulwurf"', source
        )
        self.assertIn(
            'LEGACY_KLEINER_MAULWURF_BRANDING_VARIANT = "kleiner-maulwurf"', source
        )
        self.assertIn(
            'DER_KLEINE_MAULWURF_APP_NAME = "der kleine maulwurf"', source
        )
        self.assertIn(
            "from der_kleine_maulwurf_operator import mcp_icons", source
        )
        self.assertIn("_configured_app_name, _configured_icons", source)

    def test_runtime_contract_installs_branding_provider(self) -> None:
        contract = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        sources = {
            item["module"]: item["source"]
            for item in contract["supporting_sources"]
        }
        self.assertEqual(
            "src/der_kleine_maulwurf_operator.py",
            sources.get("der_kleine_maulwurf_operator"),
        )


if __name__ == "__main__":
    unittest.main()
