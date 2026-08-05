from __future__ import annotations

import importlib.util
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


def _controller_recommendation(
    catalog_sha256: str = "a" * 64, **overrides: object
) -> dict:
    recommendation = {
        "decision": "controller",
        "controller": "grabowski-primary",
        "primary_role": "controller-integrator",
        "delegated_scoped_writers_allowed": True,
        "controller_integration_required": True,
        "single_mutating_writer": True,
        "single_mutating_writer_scope": "overlapping-resource-lane",
        "external_primary_writer_forbidden": False,
        "automatic_execution_authorized": True,
        "catalog_sha256": catalog_sha256,
    }
    recommendation.update(overrides)
    return recommendation


class InstallCodingAgentRouterCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = self.root / "bin" / "agent-route"
        self.pin = self.root / "config" / "router.sha256"
        self.scheduler = (
            self.root / "libexec" / "coding_agent_probe_scheduler.py"
        )
        self.runtime = self.root / "runtime-python"
        self.runtime.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.runtime.chmod(0o755)
        self.validation = {
            "valid": True,
            "catalog_source": "deployment_catalog",
            "catalog_sha256": "a" * 64,
        }
        self.recommendation = _controller_recommendation()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _apply(self) -> dict:
        return INSTALLER.apply(
            self.target, self.pin, self.runtime, self.scheduler
        )

    def _check(self) -> dict:
        return INSTALLER.check(
            self.target, self.pin, self.runtime, self.scheduler
        )

    def _install_exact_files(self) -> str:
        wrapper, _pin_bytes, _digest, scheduler, scheduler_digest = (
            INSTALLER._expected(self.runtime)
        )
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_bytes(wrapper)
        self.target.chmod(0o755)
        self.pin.parent.mkdir(parents=True, exist_ok=True)
        self.pin.write_text(INSTALLER._sha256(wrapper) + "\n", encoding="ascii")
        self.pin.chmod(0o600)
        self.scheduler.parent.mkdir(parents=True, exist_ok=True)
        self.scheduler.write_bytes(scheduler)
        self.scheduler.chmod(0o755)
        return scheduler_digest

    def test_apply_installs_wrapper_and_private_pin(self) -> None:
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(
                INSTALLER, "_verify_installed", return_value=self.recommendation
            ),
        ):
            receipt = self._apply()
        wrapper, _pin_bytes, _digest, scheduler, scheduler_digest = (
            INSTALLER._expected(self.runtime)
        )
        self.assertEqual(self.target.read_bytes(), wrapper)
        self.assertIn(str(self.runtime), self.target.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.pin.stat().st_mode), 0o600)
        self.assertEqual(
            self.pin.read_text(encoding="ascii"),
            INSTALLER._sha256(wrapper) + "\n",
        )
        self.assertEqual(self.scheduler.read_bytes(), scheduler)
        self.assertEqual(stat.S_IMODE(self.scheduler.stat().st_mode), 0o755)
        self.assertEqual(receipt["scheduler_sha256"], scheduler_digest)
        self.assertEqual(receipt["scheduler_target"], str(self.scheduler))
        self.assertEqual(receipt["status"], "installed")
        self.assertTrue(receipt["installed"])
        self.assertEqual(receipt["readback"]["controller"], "grabowski-primary")
        self.assertEqual(
            receipt["readback"]["primary_role"], "controller-integrator"
        )
        self.assertTrue(receipt["automatic_execution_authorized"])
        self.assertTrue(receipt["readback"]["automatic_execution_authorized"])
        self.assertTrue(receipt["readback"]["delegated_scoped_writers_allowed"])
        self.assertTrue(receipt["readback"]["controller_integration_required"])
        self.assertTrue(receipt["readback"]["single_mutating_writer"])
        self.assertEqual(
            receipt["readback"]["single_mutating_writer_scope"],
            "overlapping-resource-lane",
        )
        self.assertFalse(receipt["readback"]["external_primary_writer_forbidden"])
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
        self.scheduler.parent.mkdir(parents=True)
        self.scheduler.write_bytes(b"old-scheduler")
        self.scheduler.chmod(0o700)
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(
                INSTALLER,
                "_verify_installed",
                side_effect=INSTALLER.InstallError("readback failed"),
            ),
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "readback failed"):
                self._apply()
        self.assertEqual(self.target.read_bytes(), b"old-target")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
        self.assertEqual(self.pin.read_bytes(), b"old-pin\n")
        self.assertEqual(stat.S_IMODE(self.pin.stat().st_mode), 0o600)
        self.assertEqual(self.scheduler.read_bytes(), b"old-scheduler")
        self.assertEqual(stat.S_IMODE(self.scheduler.stat().st_mode), 0o700)

    def test_concurrent_drift_is_preserved_and_reported_during_rollback(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"old-target")
        self.target.chmod(0o700)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(b"old-pin\n")
        self.pin.chmod(0o600)
        self.scheduler.parent.mkdir(parents=True)
        self.scheduler.write_bytes(b"old-scheduler")
        self.scheduler.chmod(0o700)

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
                self._apply()
        self.assertEqual(self.target.read_bytes(), b"external-drift")
        self.assertEqual(self.pin.read_bytes(), b"old-pin\n")
        self.assertEqual(self.scheduler.read_bytes(), b"old-scheduler")

    def test_check_reports_exact_install_state(self) -> None:
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            missing = self._check()
        self.assertFalse(missing["installed"])
        self.assertNotIn("automatic_execution_authorized", missing)
        self.assertFalse(self.target.parent.exists())
        self.assertFalse(self.pin.parent.exists())
        scheduler_digest = self._install_exact_files()
        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(
                INSTALLER, "_verify_installed", return_value=self.recommendation
            ) as verify_installed,
        ):
            current = self._check()
        verify_installed.assert_called_once_with(self.target)
        self.assertTrue(current["installed"])
        self.assertEqual(current["scheduler_sha256"], scheduler_digest)
        self.assertTrue(current["automatic_execution_authorized"])
        self.assertEqual(current["primary_role"], "controller-integrator")
        self.assertEqual(current["decision"], "controller")
        self.assertEqual(current["controller"], "grabowski-primary")
        self.assertTrue(current["delegated_scoped_writers_allowed"])
        self.assertTrue(current["controller_integration_required"])
        self.assertTrue(current["single_mutating_writer"])
        self.assertEqual(
            current["single_mutating_writer_scope"],
            "overlapping-resource-lane",
        )
        self.assertFalse(current["external_primary_writer_forbidden"])
        self.assertEqual(current["catalog_sha256"], "a" * 64)
        self.scheduler.write_bytes(b"scheduler-drift")
        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(
                INSTALLER, "_verify_installed", return_value=self.recommendation
            ) as verify_installed,
        ):
            drifted = self._check()
        verify_installed.assert_not_called()
        self.assertFalse(drifted["installed"])
        self.assertNotIn("automatic_execution_authorized", drifted)

    def test_symlink_target_is_rejected_before_replace(self) -> None:
        real = self.root / "real"
        real.write_text("keep", encoding="utf-8")
        self.target.parent.mkdir(parents=True)
        self.target.symlink_to(real)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe existing file"):
                self._apply()
        self.assertEqual(real.read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.scheduler.exists())

    def test_symlink_scheduler_is_rejected_before_any_replace(self) -> None:
        real = self.root / "real-scheduler"
        real.write_text("keep", encoding="utf-8")
        self.scheduler.parent.mkdir(parents=True)
        self.scheduler.symlink_to(real)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "unsafe existing file"
            ):
                self._apply()
        self.assertEqual(real.read_text(encoding="utf-8"), "keep")
        self.assertFalse(self.target.exists())
        self.assertFalse(self.pin.exists())

    def test_colliding_scheduler_target_is_rejected_before_effect(self) -> None:
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "install targets must be distinct"
            ):
                INSTALLER.apply(
                    self.target, self.pin, self.runtime, self.target
                )
        self.assertFalse(self.target.exists())
        self.assertFalse(self.pin.exists())

    def test_world_writable_parent_is_rejected_before_install(self) -> None:
        self.target.parent.mkdir(parents=True)
        self.target.parent.chmod(0o777)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe parent"):
                self._apply()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.pin.exists())
        self.assertFalse(self.scheduler.exists())

    def test_symlink_parent_is_rejected_before_install(self) -> None:
        real_parent = self.root / "real-bin"
        real_parent.mkdir(mode=0o700)
        self.target.parent.symlink_to(real_parent, target_is_directory=True)
        with mock.patch.object(
            INSTALLER, "_verify_runtime", return_value=self.validation
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "unsafe parent"):
                self._apply()
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
        self.scheduler.parent.mkdir(parents=True)
        self.scheduler.write_bytes(b"old-scheduler")
        self.scheduler.chmod(0o700)
        mismatched = _controller_recommendation(catalog_sha256="b" * 64)
        with (
            mock.patch.object(INSTALLER, "_verify_runtime", return_value=self.validation),
            mock.patch.object(INSTALLER, "_verify_installed", return_value=mismatched),
        ):
            with self.assertRaisesRegex(INSTALLER.InstallError, "catalog identity differs"):
                self._apply()
        self.assertEqual(self.target.read_bytes(), previous_target)
        self.assertEqual(self.pin.read_bytes(), previous_pin)
        self.assertEqual(self.scheduler.read_bytes(), b"old-scheduler")

    def test_controller_integrator_contract_rejects_material_regressions(self) -> None:
        regressions = {
            "direct-writer role": {"primary_role": "direct-writer"},
            "external writer prohibition true": {
                "external_primary_writer_forbidden": True
            },
            "automatic false": {"automatic_execution_authorized": False},
            "missing delegated writers": {
                "delegated_scoped_writers_allowed": False
            },
            "missing controller integration": {
                "controller_integration_required": False
            },
            "missing single writer": {"single_mutating_writer": False},
            "wrong writer scope": {
                "single_mutating_writer_scope": "whole-repository"
            },
        }
        for label, override in regressions.items():
            with self.subTest(label):
                broken = _controller_recommendation(**override)
                with self.assertRaisesRegex(
                    INSTALLER.InstallError, "controller-integrator contract"
                ):
                    INSTALLER._controller_integrator_contract(broken)

    def test_apply_rolls_back_when_controller_contract_regresses(self) -> None:
        previous_target = b"old-target"
        previous_pin = b"old-pin\n"
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(previous_target)
        self.target.chmod(0o700)
        self.pin.parent.mkdir(parents=True)
        self.pin.write_bytes(previous_pin)
        self.pin.chmod(0o600)
        self.scheduler.parent.mkdir(parents=True)
        self.scheduler.write_bytes(b"old-scheduler")
        self.scheduler.chmod(0o700)
        broken = _controller_recommendation(primary_role="direct-writer")
        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(INSTALLER, "_run_json", return_value=broken),
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "controller-integrator contract"
            ):
                self._apply()
        self.assertEqual(self.target.read_bytes(), previous_target)
        self.assertEqual(self.pin.read_bytes(), previous_pin)
        self.assertEqual(self.scheduler.read_bytes(), b"old-scheduler")

    def test_check_fails_closed_when_installed_contract_is_invalid(self) -> None:
        self._install_exact_files()
        broken = _controller_recommendation(
            automatic_execution_authorized=False
        )
        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(
                INSTALLER, "_run_json", return_value=broken
            ),
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "controller-integrator contract"
            ):
                self._check()

    def test_check_fails_closed_when_installed_catalog_identity_differs(
        self,
    ) -> None:
        self._install_exact_files()
        mismatched = _controller_recommendation(catalog_sha256="b" * 64)
        with (
            mock.patch.object(
                INSTALLER, "_verify_runtime", return_value=self.validation
            ),
            mock.patch.object(
                INSTALLER, "_verify_installed", return_value=mismatched
            ),
        ):
            with self.assertRaisesRegex(
                INSTALLER.InstallError, "catalog identity differs"
            ):
                self._check()

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
