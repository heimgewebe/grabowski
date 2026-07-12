from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import upgrade_access_profiles as upgrader  # noqa: E402


class UpgradeAccessProfilesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy_path = self.root / "access.json"
        self.trusted_owner = {
            "capabilities": ["file_read", "terminal_execute"],
            "trusted_owner": True,
            "max_risk_level": "high",
        }
        self.policy = {
            "version": 2,
            "active_profile": "trusted-owner",
            "profiles": {"trusted-owner": self.trusted_owner},
            "mode": "trusted-owner",
        }
        self.template = {
            "profiles": {
                "observe": {"capabilities": ["file_read"]},
                "maintain": {"capabilities": ["file_read", "file_write"]},
            }
        }
        self._write_policy(self.policy)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_policy(self, value: dict, *, mode: int = 0o600) -> None:
        self.policy_path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        self.policy_path.chmod(mode)

    def _run_main(self, *arguments: str) -> dict:
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["upgrade_access_profiles.py", *arguments]):
            with contextlib.redirect_stdout(output):
                self.assertEqual(upgrader.main(), 0)
        return json.loads(output.getvalue())

    def test_upgrade_adds_bounded_profiles_without_expanding_trusted_owner(self) -> None:
        result = upgrader.upgraded(self.policy, self.template)
        self.assertEqual(result["active_profile"], "trusted-owner")
        self.assertEqual(sorted(result["profiles"]), ["maintain", "observe", "trusted-owner"])
        self.assertEqual(result["profiles"]["trusted-owner"], self.trusted_owner)
        self.assertIsNot(result["profiles"]["trusted-owner"], self.trusted_owner)
        self.assertEqual(self.policy["profiles"], {"trusted-owner": self.trusted_owner})

    def test_dry_run_does_not_mutate_policy(self) -> None:
        before = self.policy_path.read_bytes()
        before_inode = self.policy_path.stat().st_ino
        with mock.patch.object(upgrader, "TEMPLATE", self.root / "template.json"):
            upgrader.TEMPLATE.write_text(json.dumps(self.template), encoding="utf-8")
            result = self._run_main(str(self.policy_path))
        self.assertTrue(result["changed"])
        self.assertFalse(result["applied"])
        self.assertEqual(self.policy_path.read_bytes(), before)
        self.assertEqual(self.policy_path.stat().st_ino, before_inode)
        self.assertIn("client_tool_snapshot_refresh", result["does_not_establish"])

    def test_apply_is_sha_bound_atomic_private_and_preserves_active_profile(self) -> None:
        before = self.policy_path.read_bytes()
        expected = hashlib.sha256(before).hexdigest()
        before_inode = self.policy_path.stat().st_ino
        template_path = self.root / "template.json"
        template_path.write_text(json.dumps(self.template), encoding="utf-8")
        with mock.patch.object(upgrader, "TEMPLATE", template_path):
            result = self._run_main(
                str(self.policy_path),
                "--expected-sha256",
                expected,
                "--apply",
            )
        value = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.assertTrue(result["applied"])
        self.assertEqual(value["active_profile"], "trusted-owner")
        self.assertEqual(value["profiles"]["trusted-owner"], self.trusted_owner)
        self.assertEqual(stat.S_IMODE(self.policy_path.stat().st_mode), 0o600)
        self.assertNotEqual(self.policy_path.stat().st_ino, before_inode)
        self.assertEqual(hashlib.sha256(self.policy_path.read_bytes()).hexdigest(), result["after_sha256"])

    def test_sha_precondition_failure_does_not_mutate(self) -> None:
        before = self.policy_path.read_bytes()
        template_path = self.root / "template.json"
        template_path.write_text(json.dumps(self.template), encoding="utf-8")
        with mock.patch.object(upgrader, "TEMPLATE", template_path):
            with self.assertRaisesRegex(SystemExit, "precondition failed"):
                self._run_main(
                    str(self.policy_path),
                    "--expected-sha256",
                    "0" * 64,
                    "--apply",
                )
        self.assertEqual(self.policy_path.read_bytes(), before)

    def test_rejects_missing_or_invalid_profiles_and_lost_active_profile(self) -> None:
        invalid_cases = [
            ({"version": 1, "profiles": {"trusted-owner": {}}}, self.template),
            ({"version": 2, "profiles": {}}, self.template),
            ({"version": 2, "profiles": {"trusted-owner": []}}, self.template),
            (self.policy, {"profiles": {"observe": {}}}),
            ({**self.policy, "active_profile": "removed"}, self.template),
        ]
        for policy, template in invalid_cases:
            with self.subTest(policy=policy, template=template):
                with self.assertRaises(ValueError):
                    upgrader.upgraded(policy, template)

    def test_rejects_symlink_hardlink_and_public_policy(self) -> None:
        target = self.root / "target.json"
        target.write_bytes(self.policy_path.read_bytes())
        target.chmod(0o600)
        self.policy_path.unlink()
        self.policy_path.symlink_to(target.name)
        with self.assertRaises(OSError):
            upgrader._open_locked_policy(self.policy_path)

        self.policy_path.unlink()
        os.link(target, self.policy_path)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            upgrader._open_locked_policy(self.policy_path)

        self.policy_path.unlink()
        target.unlink()
        self._write_policy(self.policy, mode=0o644)
        with self.assertRaisesRegex(ValueError, "private regular file"):
            upgrader._open_locked_policy(self.policy_path)

    def test_atomic_apply_detects_identity_drift(self) -> None:
        descriptor, payload, identity = upgrader._open_locked_policy(self.policy_path)
        try:
            expected = hashlib.sha256(payload).hexdigest()
            replacement = self.root / "replacement.json"
            replacement.write_bytes(payload)
            replacement.chmod(0o600)
            os.replace(replacement, self.policy_path)
            with self.assertRaisesRegex(ValueError, "changed|drifted"):
                upgrader._atomic_replace(
                    self.policy_path,
                    payload + b" ",
                    descriptor=descriptor,
                    expected_identity=identity,
                    expected_sha256=expected,
                )
        finally:
            os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
