from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs

if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_workers as workers


def result(returncode: int = 0, stdout: str = "") -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }

class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "workers"
        self.db = self.state / "workers.sqlite3"
        self.resource_db = self.root / "resources.sqlite3"
        self.patches = [
            patch.object(workers, "WORKER_STATE", self.state),
            patch.object(workers, "WORKER_DB", self.db),
            patch.object(workers.resources, "RESOURCE_DB", self.resource_db),
        ]
        for item in self.patches:
            item.start()
        self.binary = self.root / "browser"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def test_browser_launch_is_loopback_only_and_leased(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ) as run:
            started = workers.browser_start(
                str(self.binary), port=9222, args=["--headless=new"], runtime_seconds=60
            )
        worker = started["worker"]
        self.assertEqual(worker["kind"], "browser")
        self.assertEqual(worker["state"], "running")
        self.assertIn("--remote-debugging-address=127.0.0.1", worker["argv"])
        self.assertIn("--remote-debugging-port=9222", worker["argv"])
        launch = run.call_args.args[0]
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski browser-worker grabowski-browser-worker-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
        self.assertIn("--slice=grabowski-workers.slice", launch)
        self.assertIn("--property=NoNewPrivileges=yes", launch)
        self.assertEqual(
            workers.resources.inspect_resource("port:9222")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_persistent_profile_ignores_missing_alternative_roots(self) -> None:
        existing_root = self.root / "brave"
        existing_root.mkdir()
        missing_root = self.root / "chromium"
        profile = existing_root / "schauwerk"
        configured_roots = [str(existing_root), str(missing_root)]

        with patch.object(
            workers.base, "_load_policy", return_value={}
        ), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ):
            resolved, ephemeral = workers._browser_profile("0" * 20, str(profile))

        self.assertEqual(resolved, profile)
        self.assertTrue(resolved.is_dir())
        self.assertFalse(ephemeral)

    def test_browser_args_cannot_override_binding_or_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()):
            for argument in (
                "--remote-debugging-address=0.0.0.0",
                "--remote-debugging-port=9999",
                "--user-data-dir=/tmp/x",
            ):
                with self.assertRaises(ValueError):
                    workers.browser_start(str(self.binary), port=9222, args=[argument])

    def test_terminal_status_releases_leases_and_ephemeral_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9223, runtime_seconds=60)
        worker = started["worker"]
        profile = Path(worker["profile_path"])
        self.assertTrue(profile.exists())
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9223"))
        self.assertFalse(profile.exists())

    def test_collected_successful_unit_is_completed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9225, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9225"))

    def test_collected_failed_unit_is_failed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9226, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=exit-code\nExecMainStatus=1\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")
        self.assertIsNone(workers.resources.inspect_resource("port:9226"))

    def test_collected_unit_without_result_is_interrupted(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9227, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=\nExecMainStatus=\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "interrupted")
        self.assertIsNone(workers.resources.inspect_resource("port:9227"))

    def test_gui_fails_clearly_without_xvfb(self) -> None:
        with patch.object(workers.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Xvfb is not installed"):
                workers.gui_start(str(self.binary), display_number=20)

    def test_gui_config_has_no_tcp_listener(self) -> None:
        xvfb = self.root / "Xvfb"
        xvfb.write_text("#!/bin/sh\nexit 0\n")
        xvfb.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=str(xvfb)), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.gui_start(
                str(self.binary), display_number=21, args=["--example"], runtime_seconds=60
            )
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        config = json.loads(Path(record["config_path"]).read_text())
        self.assertEqual(config["environment"]["DISPLAY"], ":21")
        self.assertIn("-nolisten", config["xvfb_argv"])
        self.assertIn("tcp", config["xvfb_argv"])
        self.assertNotIn("vnc", " ".join(config["xvfb_argv"]).lower())
        self.assertEqual(
            workers.resources.inspect_resource("display:21")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_launch_failure_releases_worker_leases(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result(returncode=1)
        ):
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        self.assertEqual(started["worker"]["state"], "failed")
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))

if __name__ == "__main__":
    unittest.main()
