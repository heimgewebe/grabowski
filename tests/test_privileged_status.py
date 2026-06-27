from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_privileged_status_core as status


class PrivilegedStatusTests(unittest.TestCase):
    def test_checkout_cli_does_not_require_mcp_package(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/grabowski_privileged_status.py")],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ""},
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        value = json.loads(completed.stdout)
        self.assertTrue(value["fail_closed"])
        self.assertIn("ready", value)

    def test_status_reports_files_without_exposing_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            broker = root / "broker"
            config = root / "config.json"
            socket_path = root / "missing.sock"
            broker.write_text("sensitive broker bytes")
            broker.chmod(0o755)
            config.write_text('{"private":"value"}')
            config.chmod(0o600)
            with patch.object(status.shutil, "which", return_value=None):
                result = status.privileged_broker_status(
                    broker=broker,
                    config=config,
                    socket_path=socket_path,
                )
        encoded = json.dumps(result)
        self.assertNotIn("sensitive broker bytes", encoded)
        self.assertNotIn("private", encoded)
        self.assertFalse(result["ready"])
        self.assertTrue(result["fail_closed"])


if __name__ == "__main__":
    unittest.main()
