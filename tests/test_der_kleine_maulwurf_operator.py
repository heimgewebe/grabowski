from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
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

    def test_recovery_mode_defaults_normal_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            initial = mole.recovery_mode_status(path=path)
            self.assertEqual("normal", initial["mode"])
            self.assertTrue(initial["valid"])
            self.assertFalse(initial["present"])
            self.assertFalse(mole.recovery_mode_enabled(path=path))

            enabled = mole.enable_recovery_mode("test-recovery", path=path)
            self.assertEqual("recovery", enabled["mode"])
            self.assertTrue(mole.recovery_mode_enabled(path=path))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

            disabled = mole.disable_recovery_mode(path=path)
            self.assertEqual("normal", disabled["mode"])
            self.assertFalse(mole.recovery_mode_enabled(path=path))

    def test_direct_recovery_cli_rejects_secret_reason(self) -> None:
        reasons = (
            "".join(("Bear", "er ", "abcdefghijklmnopqrst")),
            "".join(("s", "k-", "a" * 24)),
            "".join(("OPENAI_", "TO", "KEN=", "abcdefghijklmnopqrst")),
            "".join(("-----BEGIN ", "TEST PRIVATE ", "KEY-----")),
        )
        for index, reason in enumerate(reasons):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "mode.json"
                with patch.object(mole, "recovery_mode_path", return_value=path):
                    with self.assertRaisesRegex(ValueError, "secret material"):
                        mole.main(["on", "--reason", reason])
                self.assertFalse(path.exists())

    def test_recovery_status_rejects_secret_bearing_persisted_reason(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            secret = "".join(("s", "k-", "a" * 24))
            path.write_text(
                json.dumps(
                    {
                        "schema_version": mole.RECOVERY_MODE_SCHEMA_VERSION,
                        "kind": mole.RECOVERY_MODE_KIND,
                        "mode": mole.RECOVERY_MODE_RECOVERY,
                        "reason": secret,
                        "changed_at_unix": 1,
                    }
                ),
                encoding="utf-8",
            )
            path.chmod(0o600)
            status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])
        self.assertNotIn(secret, json.dumps(status, sort_keys=True))

    def test_normal_mode_guard_denial_creates_no_lock_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            lock_path = path.with_name(f".{path.name}.lock")
            with self.assertRaisesRegex(PermissionError, "NORMAL mode"):
                mole.acquire_recovery_mutation_guard(path=path)
            self.assertFalse(path.exists())
            self.assertFalse(lock_path.exists())

    def test_recovery_off_drains_active_mutation_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            mole.enable_recovery_mode("test-recovery", path=path)
            guard = mole.acquire_recovery_mutation_guard(path=path)
            started = threading.Event()
            finished = threading.Event()
            outcome: dict[str, object] = {}

            def disable() -> None:
                started.set()
                outcome.update(mole.disable_recovery_mode(path=path))
                finished.set()

            thread = threading.Thread(target=disable)
            thread.start()
            self.assertTrue(started.wait(timeout=1.0))
            time.sleep(0.05)
            self.assertFalse(finished.is_set())
            mole.release_recovery_mutation_guard(guard)
            thread.join(timeout=2.0)
            self.assertFalse(thread.is_alive())
            self.assertEqual("normal", outcome.get("mode"))
            with self.assertRaisesRegex(PermissionError, "NORMAL mode"):
                mole.acquire_recovery_mutation_guard(path=path)

    def test_post_replace_directory_fsync_failure_is_explicitly_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            real_fsync = mole.os.fsync
            calls = 0

            def fail_directory_fsync(descriptor: int) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("directory fsync failed")
                real_fsync(descriptor)

            with patch.object(mole.os, "fsync", side_effect=fail_directory_fsync):
                result = mole.enable_recovery_mode("test-recovery", path=path)
            observed = mole.recovery_mode_status(path=path)
        self.assertTrue(result["valid"])
        self.assertTrue(result["ambiguity"])
        self.assertTrue(result["effect_started"])
        self.assertFalse(result["durability_confirmed"])
        self.assertEqual("effect_observed_durability_unknown", result["write_outcome"])
        self.assertEqual("recovery", observed["mode"])

    def test_direct_recovery_cli_fails_when_readback_disagrees(self) -> None:
        with (
            patch.object(
                mole,
                "enable_recovery_mode",
                return_value={"valid": False, "mode": "normal"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(1, mole.main(["on", "--reason", "primary unavailable"]))
        with (
            patch.object(
                mole,
                "disable_recovery_mode",
                return_value={"valid": True, "mode": "recovery"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(1, mole.main(["off"]))
        with (
            patch.object(
                mole,
                "recovery_mode_status",
                return_value={"valid": True, "mode": "normal"},
            ),
            patch("builtins.print"),
        ):
            self.assertEqual(0, mole.main(["status"]))


    def test_oversized_recovery_mode_fails_closed_without_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            path.write_bytes(b"x" * (mole.RECOVERY_MODE_MAX_BYTES + 1))
            path.chmod(0o600)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("must not use unbounded read")):
                status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

    def test_invalid_recovery_mode_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            path.write_text("not-json", encoding="utf-8")
            path.chmod(0o600)
            status = mole.recovery_mode_status(path=path)
        self.assertFalse(status["valid"])
        self.assertEqual("normal", status["mode"])

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
