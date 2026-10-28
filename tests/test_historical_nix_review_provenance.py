"""Regression checks for authentically immutable historical Nix reviewer origins.

The synthetic Nix store is owned by the current test uid; production still
requires uid 0 and the actual immutable /nix/store tree.
"""
from pathlib import Path
import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import grabowski_decision_reviews as reviews
sys.path.insert(0, str(ROOT / "tests"))
import test_decision_reviews as fixtures


class HistoricalNixReviewOriginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.store = base / "store"
        self.store.mkdir()
        self.release = self.store / ("0" * 32 + "-grabowski-operator-3a9d90f6")
        self.bin_dir = self.release / "bin"
        self.site_packages = self.release / "lib" / "python3.12" / "site-packages"
        self.bin_dir.mkdir(parents=True)
        self.site_packages.mkdir(parents=True)
        self.python_target = self.store / "python-runtime" / "bin" / "python3.12"
        self.python_target.parent.mkdir(parents=True)
        self.python_target.write_bytes(b"#!/bin/sh\n")
        self.python_target.chmod(0o555)
        self.interpreter = self.bin_dir / "python3"
        self.interpreter.symlink_to(self.python_target)
        self.module = self.site_packages / f"{reviews.REVIEW_ROLE_MODULE}.py"
        self.module.write_bytes(b"REVIEW_MODULE = True\n")
        self.module.chmod(0o444)
        self.digest = hashlib.sha256(self.module.read_bytes()).hexdigest()
        self.readonly_dirs = (
            self.release,
            self.bin_dir,
            self.release / "lib",
            self.release / "lib" / "python3.12",
            self.site_packages,
        )
        for directory in self.readonly_dirs:
            directory.chmod(0o555)
        self.addCleanup(self._restore_permissions)

        root_patch = mock.patch.object(reviews, "_NIX_REVIEW_STORE_ROOT", self.store)
        owner_patch = mock.patch.object(reviews, "_NIX_REVIEW_OWNER_UID", os.getuid())
        root_patch.start()
        owner_patch.start()
        self.addCleanup(root_patch.stop)
        self.addCleanup(owner_patch.stop)

    def _restore_permissions(self) -> None:
        for directory in self.readonly_dirs:
            if directory.exists():
                directory.chmod(0o755)

    def _accepted(self, *, python=None, module=None, digest=None) -> bool:
        return reviews._historical_nix_review_role_origin_matches(
            str(self.interpreter if python is None else python),
            str(self.module if module is None else module),
            self.digest if digest is None else digest,
        )

    def test_canonical_immutable_historical_release_is_accepted(self) -> None:
        self.assertTrue(self._accepted())
        self.assertFalse(self._accepted(digest="0" * 64))

    def test_current_release_path_is_not_a_trust_shortcut(self) -> None:
        # A syntactically valid interpreter is insufficient without a pinned
        # module inside the *same* immutable operator source package.
        foreign = self.store / "python-runtime" / "lib" / "grabowski_agent_role.py"
        self.assertFalse(self._accepted(module=foreign))
        self.assertFalse(self._accepted(python=self.python_target))
        self.assertFalse(self._accepted(python=self.release / "bin" / "python3.12"))
        self.assertFalse(self._accepted(module=self.release / "lib" / "python3.12" / "other.py"))

    def test_writable_or_wrong_owner_provenance_is_rejected(self) -> None:
        self.module.chmod(0o644)
        self.assertFalse(self._accepted())
        self.module.chmod(0o444)
        self.release.chmod(0o775)
        self.assertFalse(self._accepted())
        self.release.chmod(0o555)
        with mock.patch.object(reviews, "_NIX_REVIEW_OWNER_UID", os.getuid() + 1):
            self.assertFalse(self._accepted())

    def test_interpreter_target_must_stay_in_immutable_store(self) -> None:
        # Changing the symlink cannot grant authority to any system Python.
        self.bin_dir.chmod(0o755)
        self.interpreter.unlink()
        self.interpreter.symlink_to("/usr/bin/python3")
        self.bin_dir.chmod(0o555)
        self.assertFalse(self._accepted())

    def test_module_link_and_hash_integrity_are_mandatory(self) -> None:
        self.site_packages.chmod(0o755)
        self.module.rename(self.site_packages / "actual.py")
        self.module.symlink_to(self.site_packages / "actual.py")
        self.site_packages.chmod(0o555)
        self.assertFalse(self._accepted())

    def test_full_historical_provenance_uses_the_trusted_nix_origin(self) -> None:
        jobs = Path(self.temporary.name) / "jobs"
        jobs.mkdir()
        directory = fixtures.make_job(
            jobs, suffix="a00000000067", slot="independent-reviewer",
            terminal_status="succeeded", review_result=None, review_role=True,
        )
        import json
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        provenance = dict(metadata["scope"]["decision_review_provenance"])
        provenance["runner_python"] = str(self.interpreter)
        provenance["runner_module_path"] = str(self.module)
        provenance["runner_module_sha256"] = self.digest
        provenance["provenance_sha256"] = reviews.sha256_json({
            key: value for key, value in provenance.items()
            if key != "provenance_sha256"
        })
        normalized = reviews.normalize_binding(fixtures.binding("independent-reviewer"))
        self.assertEqual(
            reviews._normalize_review_role_provenance(
                provenance, normalized, cwd="/tmp/review",
            ),
            provenance,
        )
        tampered = dict(provenance)
        tampered["runner_module_sha256"] = "0" * 64
        tampered["provenance_sha256"] = reviews.sha256_json({
            key: value for key, value in tampered.items()
            if key != "provenance_sha256"
        })
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            reviews._normalize_review_role_provenance(
                tampered, normalized, cwd="/tmp/review",
            )

    def test_origin_cannot_be_supplied_as_untrusted_values(self) -> None:
        for python, module, digest in (
            ("", str(self.module), self.digest),
            (str(self.interpreter), "", self.digest),
            (str(self.interpreter), str(self.module), "bad"),
            (None, str(self.module), self.digest),
            (str(self.interpreter), str(self.module), None),
        ):
            with self.subTest(python=python, module=module, digest=digest):
                self.assertFalse(reviews._historical_nix_review_role_origin_matches(
                    python, module, digest,
                ))


if __name__ == "__main__":
    unittest.main()