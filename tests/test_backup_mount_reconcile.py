from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "tools" / "grabowski_backup_mount_reconcile.py"
SPEC = importlib.util.spec_from_file_location(
    "grabowski_backup_mount_reconcile_test", PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("helper could not be loaded")
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class BackupMountReconcileTests(unittest.TestCase):
    def test_removes_only_missing_stale_source_with_stable_readback(self) -> None:
        with patch.object(
            mod,
            "_configured_device",
            side_effect=["/dev/sdc1", "/dev/sdc1", "/dev/sdc1"],
        ), patch.object(
            mod,
            "_observe_mount",
            side_effect=["/dev/sda1", "/dev/sda1", "/dev/sda1", None],
        ), patch.object(
            mod.os.path, "exists", return_value=False
        ), patch.object(
            mod, "_mount_busy", return_value=False
        ), patch.object(mod, "_run") as run:
            result = mod.reconcile()
        self.assertTrue(result["effect_applied"])
        self.assertEqual(result["status"], "stale_mount_removed")
        run.assert_called_once_with(["/usr/bin/umount", "/mnt/backup"])

    def test_current_mount_is_noop(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(
            mod, "_observe_mount", return_value="/dev/sdc1"
        ), patch.object(mod, "_run") as run:
            result = mod.reconcile()
        self.assertEqual(result["status"], "already_current")
        run.assert_not_called()

    def test_unmounted_is_noop(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(mod, "_observe_mount", return_value=None):
            result = mod.reconcile()
        self.assertEqual(result["status"], "already_unmounted")
        self.assertFalse(result["effect_applied"])

    def test_existing_wrong_source_fails_closed(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(
            mod, "_observe_mount", return_value="/dev/sda1"
        ), patch.object(
            mod.os.path, "exists", return_value=True
        ), patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "source still exists"):
                mod.reconcile()
        run.assert_not_called()

    def test_busy_stale_mount_fails_closed(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(
            mod, "_observe_mount", side_effect=["/dev/sda1", "/dev/sda1"]
        ), patch.object(
            mod.os.path, "exists", return_value=False
        ), patch.object(
            mod, "_mount_busy", return_value=True
        ), patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "busy"):
                mod.reconcile()
        run.assert_not_called()

    def test_pre_unmount_source_change_fails_closed(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(
            mod,
            "_observe_mount",
            side_effect=["/dev/sda1", "/dev/sda1", "/dev/sdd1"],
        ), patch.object(
            mod.os.path, "exists", return_value=False
        ), patch.object(
            mod, "_mount_busy", return_value=False
        ), patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "changed before unmount"):
                mod.reconcile()
        run.assert_not_called()

    def test_source_reappearing_immediately_before_effect_fails_closed(self) -> None:
        with patch.object(
            mod, "_configured_device", return_value="/dev/sdc1"
        ), patch.object(
            mod,
            "_observe_mount",
            side_effect=["/dev/sda1", "/dev/sda1", "/dev/sda1"],
        ), patch.object(
            mod.os.path, "exists", side_effect=[False, True]
        ), patch.object(
            mod, "_mount_busy", return_value=False
        ), patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "source still exists"):
                mod.reconcile()
        run.assert_not_called()

    def test_configured_device_change_before_effect_fails_closed(self) -> None:
        with patch.object(
            mod,
            "_configured_device",
            side_effect=["/dev/sdc1", "/dev/sdb1"],
        ), patch.object(
            mod,
            "_observe_mount",
            side_effect=["/dev/sda1", "/dev/sda1", "/dev/sda1"],
        ), patch.object(
            mod.os.path, "exists", return_value=False
        ), patch.object(
            mod, "_mount_busy", return_value=False
        ), patch.object(mod, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "changed before unmount"):
                mod.reconcile()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
