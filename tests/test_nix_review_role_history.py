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
        p1.start()
        p2.start()
        self.addCleanup(p1.stop)
        self.addCleanup(p2.stop)

    def accepted(self, runner: Path | None = None, module: Path | None = None) -> bool:
        return reviews._historical_nix_review_role_matches(
            str(runner or self.runner), str(module or self.module), self.sha
        )

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


if __name__ == "__main__":
    unittest.main()
