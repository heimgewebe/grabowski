from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "install_coding_agent_router_cli.py"
SPEC = importlib.util.spec_from_file_location("install_coding_agent_router_cli", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
INSTALLER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALLER
SPEC.loader.exec_module(INSTALLER)


class InstallCodingAgentRouterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = self.root / "bin" / "agent-route"
        self.pin = self.root / "config" / "router.sha256"
        self.runtime = self.root / "runtime-python"
        self.runtime.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.runtime.chmod(0o755)
        self.validation = {
            "valid": True,
            "catalog_source": "deployment_catalog",
            "catalog_sha256": "a" * 64,
        }
        self.recommendation = {
            "decision": "controller",
            "controller": "grabowski-primary",
            "primary_role": "direct-writer",
            "external_primary_writer_forbidden": True,
            "automatic_execution_authorized": False,
            "catalog_sha256": "a" * 64,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_apply_installs_wrapper_and_private_pin(self) -> None:
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(
                INSTALLER, "_verify_installed", return_value=self.recommendation
            ),
        ):
            receipt = INSTALLER.apply(self.target, self.pin, self.runtime)
        wrapper, _pin_bytes, _digest = INSTALLER._expected(self.runtime)
        self.assertEqual(self.target.read_bytes(), wrapper)
        self.assertIn(str(self.runtime), self.target.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.pin.stat().st_mode), 0o600)
        self.assertEqual(
            self.pin.read_text(encoding="ascii"),
            INSTALLER._sha256(wrapper) + "\n",
        )
        self.assertEqual(receipt["status"], "installed")
        self.assertEqual(receipt["readback"]["controller"], "grabowski-primary")
        self.assertFalse(receipt["automatic_execution_authorized"])
        lock = self.pin.parent / ".coding-agent-router-install.lock"
        self.assertTrue(lock.is_file())
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_failed_readback_restores_previous_target_and_pin(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"old-target")
        self.target.chmod(0o700)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(b"old-pin\n")
        self.pin.chmod(0o600)
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(
                INSTALLER,
                "_verify_installed",
                side_effect=INSTALLER.InstallError("readback failed"),
            ),
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "readback failed"):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertEqual(self.target.read_bytes(), b"old-target")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
        self.assertEqual(self.pin.read_bytes(), b"old-pin\n")
        self.assertEqual(stat.S_IMODE(self.pin.stat().st_mode), 0o600)

    def test_concurrent_drift_is_preserved_and_reported_during_rollback(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"old-target")
        self.target.chmod(0o700)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(b"old-pin\n")
        self.pin.chmod(0o600)

        def drift_then_fail(_target: Path) -> dict:
            self.target.write_bytes(b"external-drift")
            self.target.chmod(0o700)
            raise INSTALLER.InstallError("readback failed")

        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(
                INSTALLER, "_verify_installed", side_effect=drift_then_fail
            ),
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "rollback was incomplete"
            ):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertEqual(self.target.read_bytes(), b"external-drift")
        self.assertEqual(self.pin.read_bytes(), b"old-pin\n")

    def test_check_reports_exact_install_state(self) -> None:
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            missing = INSTALLER.check(self.target, self.pin, self.runtime)
        self.assertFalse(missing["installed"])
        self.assertFalse(self.target.parent.exists())
        self.assertFalse(self.pin.parent.exists())
        self.target.parent.mkdir(parents=True)
        wrapper, _pin_bytes, _digest = INSTALLER._expected(self.runtime)
        self.target.write_bytes(wrapper)
        self.target.chmod(0o755)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_text(
            INSTALLER._sha256(wrapper) + "\n",
            encoding="ascii",
        )
        self.pin.chmod(0o600)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            current = INSTALLER.check(self.target, self.pin, self.runtime)
        self.assertTrue(current["installed"])

    def test_symlink_target_is_rejected_before_replace(self) -> None:
        real = self.root / "real"
        real.write_text("keep", encoding="utf-8")
        self.target.parent.mkdir(parents=True)
        self.target.symlink_to(real)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe existing file"):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertEqual(real.read_text(encoding="utf-8"), "keep")

    def test_world_writable_parent_is_rejected_before_install(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.parent.chmod(0o777)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe parent"):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.pin.exists())

    def test_symlink_parent_is_rejected_before_install(self) -> None:
        real_parent = self.root / "real-bin"
        real_parent.mkdir(mode=0o700)
        self.target.parent.symlink_to(real_parent, target_is_directory=True)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe parent"):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertFalse((real_parent / "agent-route").exists())

    def test_apply_rolls_back_when_installed_catalog_identity_differs(self) -> None:
        previous_target = b"old-target"
        previous_pin = b"old-pin\n"
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(previous_target)
        self.target.chmod(0o700)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(previous_pin)
        self.pin.chmod(0o600)
        mismatched = {**self.recommendation, "catalog_sha256": "b" * 64}
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(INSTALLER, "_verify_installed", return_value=mismatched),
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "catalog identity differs"):
                INSTALLER.apply(self.target, self.pin, self.runtime)
        self.assertEqual(self.target.read_bytes(), previous_target)
        self.assertEqual(self.pin.read_bytes(), previous_pin)

    def test_verification_output_limit_is_enforced_while_child_is_running(self) -> None:
        with mock.patch.object(INSTALLER, "MAX_VERIFY_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(INSTALLER.InstallError, "exceeds byte limit"):
                INSTALLER._run_json(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.write('x' * 1000000)",
                    ],
                    timeout=5,
                )

    def test_verification_requires_absolute_executable(self) -> None:
        with self.assertRaisesRegex(INSTALLER.InstallError, "must be absolute"):
            INSTALLER._run_json(["python3", "-c", "print('{}')"])

    def test_wrapper_only_executes_current_runtime_cli(self) -> None:
        wrapper = INSTALLER.SOURCE.read_text(encoding="utf-8")
        self.assertIn("grabowski_coding_agent_router_cli", wrapper)
        self.assertIn("$HOME/.local/share/grabowski-mcp/.venv/bin/python", wrapper)
        self.assertNotIn("GRABOWSKI_RUNTIME_PYTHON", wrapper)
        self.assertNotIn("recommendation", wrapper)
        self.assertNotIn("claude", wrapper)
        self.assertNotIn("codex", wrapper)


if __name__ == "__main__":
    unittest.main()
