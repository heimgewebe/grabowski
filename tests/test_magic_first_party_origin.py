"""Exact managed-origin admission for alexdermohr/magic first-party reviews."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402
import grabowski_self_review_producer as producer  # noqa: E402


class MagicFirstPartyOriginTests(unittest.TestCase):
    def test_allowlist_names_only_the_authorized_magic_repository(self) -> None:
        self.assertIsNotNone(review.FIRST_PARTY_ALLOWED_REPO.fullmatch("alexdermohr/magic"))
        self.assertIsNotNone(producer.SUPPORTED_REPO.fullmatch("alexdermohr/magic"))
        for name in (
            "alexdermohr/magic-copy",
            "alexdermohr/magic/extra",
            "alexdermohr/Magic",
            "unrelated-owner/magic",
        ):
            with self.subTest(name=name):
                self.assertIsNone(review.FIRST_PARTY_ALLOWED_REPO.fullmatch(name))
                self.assertIsNone(producer.SUPPORTED_REPO.fullmatch(name))

    def test_canonical_origin_and_managed_checkout_remain_required(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "repos"
            repo = root / "magic"
            repo.mkdir(parents=True)

            def git(*args: str) -> None:
                subprocess.run(
                    ["git", "-C", str(repo), *args],
                    check=True, capture_output=True,
                )

            git("init", "-q")
            git("remote", "add", "origin", "git@github.com:alexdermohr/magic.git")
            with mock.patch.object(producer, "MANAGED_REPOS_ROOT", root):
                resolved, slug = producer._managed_repository_identity(
                    repo, expected_repo="alexdermohr/magic",
                )
                self.assertEqual(repo.resolve(), resolved)
                self.assertEqual("alexdermohr/magic", slug)

                git("remote", "set-url", "origin", "https://github.com/alexdermohr/magic.git")
                self.assertEqual(
                    "alexdermohr/magic",
                    producer._managed_repository_identity(repo)[1],
                )

                git("remote", "set-url", "origin", "git@github.com:alexdermohr/magic-copy.git")
                with self.assertRaisesRegex(review.ReviewExecutionRejected, "origin invalid"):
                    producer._managed_repository_identity(repo)

                git("remote", "set-url", "origin", "git@github.com:alexdermohr/magic.git")
                with self.assertRaisesRegex(review.ReviewExecutionRejected, "origin invalid"):
                    producer._managed_repository_identity(
                        repo, expected_repo="alexdermohr/kleinanzeiger",
                    )


if __name__ == "__main__":
    unittest.main()
