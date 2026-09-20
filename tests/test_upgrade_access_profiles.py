from __future__ import annotations

import contextlib
import copy
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
        self.managed_browser_roots = [
            "${HOME}/.local/state/grabowski/browser-profiles"
        ]
        self.template = {
            "browser_profile_roots": copy.deepcopy(self.managed_browser_roots),
            "capability_definitions": {
                "bureau_mutation": "Typed Bureau mutation without generic terminal."
            },
            "profiles": {
                "observe": {"capabilities": ["file_read"]},
                "maintain": {"capabilities": ["file_read", "file_write"]},
                "failover-mutate": {
                    "trusted_owner": False,
                    "capabilities": [
                        "file_read", "audit_verify", "audit_read",
                        "bureau_mutation", "maulwurf_recovery_control",
                        "resource_lease", "process_inspect", "port_inspect",
                    ],
                },
                "trusted-owner": {
                    "browser_profile_roots": copy.deepcopy(
                        self.managed_browser_roots
                    ),
                    "capabilities": [
                        "file_read", "terminal_execute", "bureau_mutation"
                    ]
                },
            },
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

    def test_upgrade_adds_failover_profile_with_only_bureau_compatibility_split(self) -> None:
        result = upgrader.upgraded(self.policy, self.template)
        self.assertEqual(result["active_profile"], "trusted-owner")
        self.assertEqual(
            sorted(result["profiles"]),
            ["failover-mutate", "maintain", "observe", "trusted-owner"],
        )
        expected_trusted = copy.deepcopy(self.trusted_owner)
        expected_trusted["capabilities"].extend(
            ["bureau_mutation", "maulwurf_recovery_control"]
        )
        self.assertEqual(result["profiles"]["trusted-owner"], expected_trusted)
        self.assertEqual(
            result["profiles"]["failover-mutate"],
            self.template["profiles"]["failover-mutate"],
        )
        self.assertIsNot(result["profiles"]["trusted-owner"], self.trusted_owner)
        self.assertEqual(self.policy["profiles"], {"trusted-owner": self.trusted_owner})

    def test_upgrade_adds_new_capability_definitions_without_rewriting_existing_ones(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["capability_definitions"] = {
            "file_read": "Existing local wording.",
            "terminal_execute": "Existing terminal wording.",
        }
        template = copy.deepcopy(self.template)
        template["profiles"]["observe"]["capabilities"].append("audit_read")
        template["profiles"]["maintain"]["capabilities"].append("audit_read")
        template["capability_definitions"] = {
            "file_read": "New template wording must not rewrite local metadata.",
            "audit_read": "Read bounded safe fields from the verified audit chain.",
        }

        result = upgrader.upgraded(policy, template)

        self.assertEqual(
            result["capability_definitions"]["file_read"],
            "Existing local wording.",
        )
        self.assertEqual(
            result["capability_definitions"]["audit_read"],
            "Read bounded safe fields from the verified audit chain.",
        )
        self.assertNotIn("audit_read", result["profiles"]["trusted-owner"]["capabilities"])
        self.assertIn("bureau_mutation", result["profiles"]["trusted-owner"]["capabilities"])
        self.assertIn("audit_read", result["profiles"]["observe"]["capabilities"])
        self.assertIn("audit_read", result["profiles"]["maintain"]["capabilities"])

    def test_browser_profile_root_convergence_is_explicit_and_narrow(self) -> None:
        legacy_roots = [
            "${HOME}/.mozilla/firefox",
            "${HOME}/.config/google-chrome",
        ]
        policy = copy.deepcopy(self.policy)
        policy["browser_profile_roots"] = copy.deepcopy(legacy_roots)
        policy["profiles"]["trusted-owner"]["browser_profile_roots"] = copy.deepcopy(
            legacy_roots
        )

        default_result = upgrader.upgraded(policy, self.template)
        self.assertEqual(default_result["browser_profile_roots"], legacy_roots)
        self.assertEqual(
            default_result["profiles"]["trusted-owner"]["browser_profile_roots"],
            legacy_roots,
        )

        result = upgrader.upgraded(
            policy,
            self.template,
            converge_browser_profile_roots=True,
        )
        self.assertEqual(
            result["browser_profile_roots"],
            self.managed_browser_roots,
        )
        expected_trusted = copy.deepcopy(policy["profiles"]["trusted-owner"])
        expected_trusted["browser_profile_roots"] = copy.deepcopy(
            self.managed_browser_roots
        )
        expected_trusted["capabilities"].extend(
            ["bureau_mutation", "maulwurf_recovery_control"]
        )
        self.assertEqual(result["profiles"]["trusted-owner"], expected_trusted)
        self.assertEqual(
            policy["profiles"]["trusted-owner"]["browser_profile_roots"],
            legacy_roots,
        )

    def test_browser_profile_root_convergence_rejects_template_scope_drift(self) -> None:
        template = copy.deepcopy(self.template)
        template["profiles"]["trusted-owner"]["browser_profile_roots"] = [
            "${HOME}/.local/state/grabowski/other-browser-profiles"
        ]
        with self.assertRaisesRegex(
            ValueError,
            "top-level and trusted-owner browser_profile_roots must match",
        ):
            upgrader.upgraded(
                self.policy,
                template,
                converge_browser_profile_roots=True,
            )

    def test_apply_can_converge_browser_roots_with_sha_bound_atomic_replace(self) -> None:
        legacy_roots = [
            "${HOME}/.mozilla/firefox",
            "${HOME}/.config/BraveSoftware/Brave-Browser",
            "${HOME}/.config/google-chrome",
            "${HOME}/.config/chromium",
        ]
        policy = upgrader.upgraded(self.policy, self.template)
        policy["browser_profile_roots"] = copy.deepcopy(legacy_roots)
        policy["profiles"]["trusted-owner"]["browser_profile_roots"] = copy.deepcopy(
            legacy_roots
        )
        self._write_policy(policy)
        before = self.policy_path.read_bytes()
        expected = hashlib.sha256(before).hexdigest()
        template_path = self.root / "template.json"
        template_path.write_text(json.dumps(self.template), encoding="utf-8")

        with mock.patch.object(upgrader, "TEMPLATE", template_path):
            dry_run = self._run_main(
                str(self.policy_path),
                "--converge-browser-profile-roots",
            )
            self.assertTrue(dry_run["changed"])
            self.assertFalse(dry_run["applied"])
            self.assertTrue(dry_run["browser_profile_roots_converged"])
            self.assertTrue(dry_run["browser_profile_roots_changed"])
            self.assertEqual(self.policy_path.read_bytes(), before)

            result = self._run_main(
                str(self.policy_path),
                "--expected-sha256",
                expected,
                "--expected-template-sha256",
                dry_run["template_sha256"],
                "--converge-browser-profile-roots",
                "--apply",
            )

        value = json.loads(self.policy_path.read_text(encoding="utf-8"))
        self.assertTrue(result["applied"])
        self.assertEqual(
            value["browser_profile_roots"],
            self.managed_browser_roots,
        )
        self.assertEqual(
            value["profiles"]["trusted-owner"]["browser_profile_roots"],
            self.managed_browser_roots,
        )
        self.assertEqual(stat.S_IMODE(self.policy_path.stat().st_mode), 0o600)

    def test_browser_root_apply_requires_reviewed_template_sha(self) -> None:
        legacy_roots = ["${HOME}/.config/google-chrome"]
        policy = upgrader.upgraded(self.policy, self.template)
        policy["browser_profile_roots"] = copy.deepcopy(legacy_roots)
        policy["profiles"]["trusted-owner"]["browser_profile_roots"] = copy.deepcopy(
            legacy_roots
        )
        self._write_policy(policy)
        before = self.policy_path.read_bytes()
        expected = hashlib.sha256(before).hexdigest()
        template_path = self.root / "template.json"
        template_path.write_text(json.dumps(self.template), encoding="utf-8")

        with mock.patch.object(upgrader, "TEMPLATE", template_path):
            dry_run = self._run_main(
                str(self.policy_path),
                "--converge-browser-profile-roots",
            )
            with self.assertRaisesRegex(SystemExit, "expected-sha256"):
                self._run_main(
                    str(self.policy_path),
                    "--expected-template-sha256",
                    dry_run["template_sha256"],
                    "--converge-browser-profile-roots",
                    "--apply",
                )
            with self.assertRaisesRegex(SystemExit, "expected-template-sha256"):
                self._run_main(
                    str(self.policy_path),
                    "--expected-sha256",
                    expected,
                    "--converge-browser-profile-roots",
                    "--apply",
                )
            with self.assertRaisesRegex(SystemExit, "template SHA-256 precondition failed"):
                self._run_main(
                    str(self.policy_path),
                    "--expected-sha256",
                    expected,
                    "--expected-template-sha256",
                    "0" * 64,
                    "--converge-browser-profile-roots",
                    "--apply",
                )

        self.assertEqual(self.policy_path.read_bytes(), before)
        self.assertEqual(
            dry_run["template_sha256"],
            hashlib.sha256(template_path.read_bytes()).hexdigest(),
        )

    def test_cli_browser_root_convergence_rejects_unrelated_profile_drift(self) -> None:
        policy = copy.deepcopy(self.policy)
        legacy_roots = ["${HOME}/.config/google-chrome"]
        policy["browser_profile_roots"] = copy.deepcopy(legacy_roots)
        policy["profiles"]["trusted-owner"]["browser_profile_roots"] = copy.deepcopy(
            legacy_roots
        )
        self._write_policy(policy)
        template_path = self.root / "template.json"
        template_path.write_text(json.dumps(self.template), encoding="utf-8")
        output = io.StringIO()

        with mock.patch.object(upgrader, "TEMPLATE", template_path):
            with mock.patch.object(
                sys,
                "argv",
                [
                    "upgrade_access_profiles.py",
                    str(self.policy_path),
                    "--converge-browser-profile-roots",
                ],
            ):
                with contextlib.redirect_stdout(output):
                    with self.assertRaisesRegex(
                        SystemExit,
                        "access-profile baseline to be current",
                    ):
                        upgrader.main()

        self.assertEqual(
            json.loads(self.policy_path.read_text(encoding="utf-8")),
            policy,
        )

    def test_upgrade_rejects_unsafe_failover_template(self) -> None:
        template = copy.deepcopy(self.template)
        template["profiles"]["failover-mutate"]["trusted_owner"] = True
        with self.assertRaisesRegex(ValueError, "disable trusted_owner"):
            upgrader.upgraded(self.policy, template)
        template = copy.deepcopy(self.template)
        template["profiles"]["failover-mutate"]["capabilities"].append("file_write")
        with self.assertRaisesRegex(ValueError, "fixed G6.5 contract"):
            upgrader.upgraded(self.policy, template)

    def test_bureau_compatibility_capability_requires_prior_terminal_authority(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["profiles"]["trusted-owner"]["capabilities"] = ["file_read"]
        result = upgrader.upgraded(policy, self.template)
        self.assertNotIn(
            "bureau_mutation",
            result["profiles"]["trusted-owner"]["capabilities"],
        )

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
        expected_trusted = copy.deepcopy(self.trusted_owner)
        expected_trusted["capabilities"].extend(
            ["bureau_mutation", "maulwurf_recovery_control"]
        )
        self.assertEqual(value["profiles"]["trusted-owner"], expected_trusted)
        self.assertIn("failover-mutate", value["profiles"])
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
            (self.policy, {"profiles": {"observe": {}, "maintain": {}}}),
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
