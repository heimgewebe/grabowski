"""Regression tests for old, immutable NixOS independent-review origins."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_decision_reviews as reviews


class NixReviewerHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Path(self.temp.name) / "nix" / "store"
        self.store.mkdir(parents=True)
        self.package = (
            self.store / ("a" * 32 + "-grabowski-operator-3a9d90f6")
        )
        self.runner = self.package / "bin" / "python3"
        self.module = (
            self.package / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages" / "grabowski_agent_role.py"
        )
        self.runner.parent.mkdir(parents=True)
        self.module.parent.mkdir(parents=True)
        self.runner.write_text("#!/bin/sh\n", encoding="utf-8")
        self.runner.chmod(0o555)
        self.module.write_bytes(b"pinned immutable reviewer module\n")
        self.module.chmod(0o444)
        self.sha = hashlib.sha256(self.module.read_bytes()).hexdigest()
        p1 = mock.patch.object(reviews, "_NIX_REVIEW_STORE_ROOT", self.store)
        p2 = mock.patch.object(reviews, "_NIX_REVIEW_OWNER_UID", os.getuid())
        p3 = mock.patch.object(
            reviews, "_historical_nix_deployed_generation_contains", return_value=True
        )
        p1.start()
        p2.start()
        p3.start()
        self.addCleanup(p1.stop)
        self.addCleanup(p2.stop)
        self.addCleanup(p3.stop)

    def accepted(self, runner: Path | None = None, module: Path | None = None) -> bool:
        return reviews._historical_nix_review_role_matches(
            str(runner or self.runner), str(module or self.module), self.sha
        )

    def test_store_name_without_installed_system_generation_is_rejected(self) -> None:
        with mock.patch.object(
            reviews, "_historical_nix_deployed_generation_contains", return_value=False
        ):
            self.assertFalse(self.accepted())

    def test_same_store_output_with_recorded_module_sha_is_accepted(self) -> None:
        self.assertTrue(self.accepted())

    def test_nix_store_optimised_hardlinks_preserve_valid_module(self) -> None:
        links = self.store / ".links"
        links.mkdir()
        twin = links / "identical-role-module"
        os.link(self.module, twin)
        self.assertEqual(self.module.stat().st_ino, twin.stat().st_ino)
        self.assertGreater(self.module.stat().st_nlink, 1)
        self.assertTrue(self.accepted())

    def test_recorded_module_bytes_must_still_match(self) -> None:
        self.assertTrue(self.accepted())
        self.module.chmod(0o644)
        self.module.write_bytes(b"different bytes")
        self.module.chmod(0o444)
        self.assertFalse(self.accepted())

    def test_runner_and_module_must_share_one_store_output(self) -> None:
        other = (
            self.store / ("b" * 32 + "-grabowski-operator-374d7471")
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages" / "grabowski_agent_role.py"
        )
        other.parent.mkdir(parents=True)
        other.write_bytes(self.module.read_bytes())
        self.assertFalse(self.accepted(module=other))

    def test_arbitrary_runner_name_or_package_is_rejected(self) -> None:
        self.assertFalse(self.accepted(runner=self.package / "bin" / "python"))
        wrong_package = self.store / ("a" * 32 + "-grabowski-stub-3a9d90f6")
        wrong_runner = wrong_package / "bin" / "python3"
        wrong_module = (
            wrong_package / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages" / "grabowski_agent_role.py"
        )
        wrong_runner.parent.mkdir(parents=True)
        wrong_module.parent.mkdir(parents=True)
        wrong_runner.write_bytes(self.runner.read_bytes())
        wrong_module.write_bytes(self.module.read_bytes())
        wrong_runner.chmod(0o555)
        wrong_module.chmod(0o444)
        self.assertFalse(self.accepted(runner=wrong_runner, module=wrong_module))

    def test_root_ownership_and_immutable_package_mode_are_required(self) -> None:
        with mock.patch.object(reviews, "_NIX_REVIEW_OWNER_UID", os.getuid() + 1):
            self.assertFalse(self.accepted())
        self.package.chmod(0o775)
        self.assertFalse(self.accepted())
        self.package.chmod(0o755)
        self.assertTrue(self.accepted())

    def test_all_intermediate_package_directories_are_root_owned_and_nonwritable(self) -> None:
        folders = [
            self.package / "bin",
            self.package / "lib",
            self.package / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}",
            self.module.parent,
        ]
        self.assertTrue(self.accepted())
        for folder in folders:
            with self.subTest(folder=folder):
                folder.chmod(0o775)
                self.assertFalse(self.accepted())
                folder.chmod(0o755)
                self.assertTrue(self.accepted())

    def test_real_nix_store_group_writable_sticky_directory(self) -> None:
        self.store.chmod(0o775)
        self.assertFalse(self.accepted())
        self.store.chmod(0o1775)
        self.assertTrue(self.accepted())
        self.store.chmod(0o1777)
        self.assertFalse(self.accepted())

    def test_symlinked_store_root_is_rejected(self) -> None:
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.store, target_is_directory=True)
        with mock.patch.object(reviews, "_NIX_REVIEW_STORE_ROOT", alias):
            self.assertFalse(self.accepted())

    def test_runner_symlink_must_resolve_within_store(self) -> None:
        resolved_python = self.store / "python-runtime" / "bin" / "python3.12"
        resolved_python.parent.mkdir(parents=True)
        resolved_python.write_text("#!/bin/sh\n", encoding="utf-8")
        resolved_python.chmod(0o555)
        self.runner.unlink()
        self.runner.symlink_to(resolved_python)
        self.assertTrue(self.accepted())
        resolved_python.unlink()
        external_python = Path(self.temp.name) / "other-python"
        external_python.write_text("#!/bin/sh\n", encoding="utf-8")
        external_python.chmod(0o555)
        self.runner.unlink()
        self.runner.symlink_to(external_python)
        self.assertFalse(self.accepted())



class NixInstalledSystemGenerationTests(unittest.TestCase):
    """Root-installed system profile closure is the trust anchor, not Nix hash shape."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = root / "nix" / "store"
        self.store.mkdir(parents=True)
        self.profiles = root / "nix" / "var" / "nix" / "profiles"
        self.profiles.mkdir(parents=True)
        self.system = self.store / ("a" * 32 + "-nixos-system-heim-pc-26.05.test")
        self.system.mkdir()
        self.link = self.profiles / "system-25-link"
        self.link.symlink_to(self.system)
        self.package = self.store / ("b" * 32 + "-grabowski-operator-374d7471")
        self.package.mkdir()
        nix = self.store / ("c" * 32 + "-nix-2.34.9") / "bin" / "nix-store"
        nix.parent.mkdir(parents=True)
        nix.write_text("#!/bin/sh\n", encoding="utf-8")
        nix.chmod(0o555)
        self.bin = root / "bin" / "nix-store"
        self.bin.parent.mkdir()
        self.bin.symlink_to(nix)
        for name, value in (
            ("_NIX_REVIEW_STORE_ROOT", self.store),
            ("_NIX_REVIEW_PROFILES_ROOT", self.profiles),
            ("_NIX_REVIEW_NIX_STORE_BIN", self.bin),
            ("_NIX_REVIEW_OWNER_UID", os.getuid()),
        ):
            patch = mock.patch.object(reviews, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_only_root_installed_generation_closure_is_accepted(self):
        response = mock.Mock(returncode=0, stdout=f"{self.package}\n", stderr="")
        with mock.patch.object(reviews.subprocess, "run", return_value=response) as runner:
            self.assertTrue(reviews._historical_nix_deployed_generation_contains(self.package))
            invoked = runner.call_args.args[0]
            options = runner.call_args.kwargs
            self.assertIn(str(self.system), invoked)
            self.assertNotIn(str(self.link), invoked)
            self.assertEqual(str(self.bin), invoked[0])  # multicall argv[0]
            self.assertEqual(str(self.bin.resolve(strict=True)), options["executable"])
            self.assertEqual("/dev/null", options["env"]["NIX_USER_CONF_FILES"])
            self.assertEqual("/var/empty", options["env"]["HOME"])
            self.assertEqual("/var/empty", options["env"]["XDG_CONFIG_HOME"])
            self.assertFalse(reviews._historical_nix_deployed_generation_contains(
                self.store / ("d" * 32 + "-grabowski-operator-deadbeef")
            ))
            self.assertTrue(reviews._historical_nix_deployed_generation_contains(self.package))
            runner.assert_called_once()  # one immutable installed-generation snapshot

    def test_noninstalled_nix_store_output_cannot_attest_review_origin(self):
        response = mock.Mock(returncode=0, stdout=f"{self.system}\n", stderr="")
        with mock.patch.object(reviews.subprocess, "run", return_value=response):
            self.assertFalse(reviews._historical_nix_deployed_generation_contains(self.package))

    def test_profile_generation_rotation_invalidates_closure_cache(self):
        response = [
            mock.Mock(returncode=0, stdout=f"{self.package}\n", stderr=""),
            mock.Mock(returncode=0, stdout=f"{self.system}\n", stderr=""),
        ]
        with mock.patch.object(reviews.subprocess, "run", side_effect=response) as runner:
            self.assertTrue(reviews._historical_nix_deployed_generation_contains(self.package))
            updated_system = self.store / ("d" * 32 + "-nixos-system-heim-pc-26.05.next")
            updated_system.mkdir()
            self.link.unlink()
            self.link.symlink_to(updated_system)
            self.assertFalse(reviews._historical_nix_deployed_generation_contains(self.package))
            self.assertEqual(runner.call_count, 2)

    def test_nix_executable_and_generation_targets_remain_pinned_if_links_change(self):
        prior_binary = self.bin.resolve(strict=True)
        alternate = self.store / ("d" * 32 + "-nix-2.34.9") / "bin" / "nix-store"
        alternate.parent.mkdir(parents=True)
        alternate.write_text("#!/bin/sh\n", encoding="utf-8")
        alternate.chmod(0o555)
        def retarget_after_validation(argv, **kwargs):
            self.assertEqual(str(prior_binary), kwargs["executable"])
            self.assertIn(str(self.system), argv)
            self.assertNotIn(str(self.link), argv)
            self.bin.unlink()
            self.bin.symlink_to(alternate)
            self.assertNotEqual(str(self.bin.resolve(strict=True)), kwargs["executable"])
            return mock.Mock(returncode=0, stdout=f"{self.package}\n", stderr="")
        with mock.patch.object(reviews.subprocess, "run", side_effect=retarget_after_validation):
            self.assertTrue(reviews._historical_nix_deployed_generation_contains(self.package))

    def test_untrusted_profile_and_binary_links_rejected_before_nix_query(self):
        with mock.patch.object(reviews.subprocess, "run") as runner:
            outside = Path(self.temp.name) / "untrusted-system"
            outside.mkdir()
            self.link.unlink()
            self.link.symlink_to(outside)
            self.assertFalse(reviews._historical_nix_deployed_generation_contains(self.package))
            runner.assert_not_called()
            self.link.unlink()
            self.link.symlink_to(self.system)
            self.bin.unlink()
            self.bin.symlink_to(outside)
            self.assertFalse(reviews._historical_nix_deployed_generation_contains(self.package))
            runner.assert_not_called()



class CurrentRuntimeReviewerFastPathTests(unittest.TestCase):
    def test_valid_current_runtime_review_does_not_launch_nix_closure_query(self):
        import test_decision_reviews as fixtures
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "jobs"
            root.mkdir(mode=0o700)
            job = fixtures.make_job(
                root, suffix="a98765432101", slot="independent-current-review",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
            )
            with mock.patch.object(
                reviews, "_historical_nix_review_role_matches",
                side_effect=AssertionError("current runtime must not query historical Nix"),
            ):
                _, binding, provenance = reviews._validated_origin_binding(job)
            self.assertIsNotNone(binding)
            self.assertIsNotNone(provenance)


if __name__ == "__main__":
    unittest.main()
