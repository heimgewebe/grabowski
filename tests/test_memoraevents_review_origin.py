"""Ensure MEMORA EVENT alone is admitted beyond existing review repository owners."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402
import grabowski_self_review_producer as producer  # noqa: E402


class MemoraeventsReviewOriginTests(unittest.TestCase):
    def _git(self, directory: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True, text=True, check=True, timeout=20,
        )
        return completed.stdout.strip()

    def test_exact_project_slug_and_signed_binding_contract(self) -> None:
        accepted = "Hall-of-Memory/memoraevents"
        self.assertIsNotNone(producer.SUPPORTED_REPO.fullmatch(accepted))
        self.assertIsNotNone(review.FIRST_PARTY_ALLOWED_REPO.fullmatch(accepted))
        # The PR gate normalizes GitHub repository identity to lowercase.
        canonical_gate_slug = "hall-of-memory/memoraevents"
        self.assertIsNone(producer.SUPPORTED_REPO.fullmatch(canonical_gate_slug))
        self.assertIsNotNone(review.FIRST_PARTY_ALLOWED_REPO.fullmatch(canonical_gate_slug))
        for rejected in (
            "Hall-of-Memory/other",
            "Hall-of-Memory/memoraevents-copy",
            "Other/memoraevents",
            "Hall-of-Memory/memoraevents/extra",
            "Hall-of-Memory/memoraevents.git",
            "Hall-of-Memory/memoraevents ",
        ):
            with self.subTest(rejected=rejected):
                self.assertIsNone(producer.SUPPORTED_REPO.fullmatch(rejected))
                self.assertIsNone(review.FIRST_PARTY_ALLOWED_REPO.fullmatch(rejected))

        binding = {
            "repo": accepted, "pr": 94, "base_sha": "a" * 40,
            "head_sha": "b" * 40, "diff_sha256": "c" * 64,
            "review_batch_id": "d" * 32, "review_purpose": "pull_request",
        }
        self.assertEqual(binding, review._first_party_binding(binding))
        self.assertEqual(binding, producer._binding(binding))
        gate_binding = {**binding, "repo": canonical_gate_slug}
        self.assertEqual(gate_binding, review._first_party_binding(gate_binding))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "source identity invalid"):
            producer._binding(gate_binding)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "binding invalid"):
            review._first_party_binding({**binding, "repo": "Hall-of-Memory/other"})

    def test_real_managed_checkout_origin_binding(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            root = Path(workspace)
            repo = root / "memoraevents"
            repo.mkdir(mode=0o700)
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.name", "Review Fixture")
            self._git(repo, "config", "user.email", "review@example.invalid")
            self._git(repo, "remote", "add", "origin",
                      "https://github.com/Hall-of-Memory/memoraevents.git")
            source = repo / "fixture.txt"
            source.write_text("base\n", encoding="utf-8")
            self._git(repo, "add", "fixture.txt")
            self._git(repo, "commit", "-qm", "base")
            base = self._git(repo, "rev-parse", "HEAD")
            source.write_text("head\n", encoding="utf-8")
            self._git(repo, "commit", "-am", "head", "-q")
            head = self._git(repo, "rev-parse", "HEAD")
            diff = hashlib.sha256(
                review._first_party_diff(repo, {"base_sha": base, "head_sha": head}),
            ).hexdigest()
            with mock.patch.object(producer, "MANAGED_REPOS_ROOT", root):
                self.assertEqual(
                    (repo, "Hall-of-Memory/memoraevents"),
                    producer._managed_repository_identity(repo),
                )
                plan = producer.plan_first_party_review(
                    repo=repo, pr=94, base_sha=base, head_sha=head,
                    diff_sha256=diff,
                )
                self.assertEqual("Hall-of-Memory/memoraevents", plan["binding"]["repo"])
                self.assertEqual(head, plan["binding"]["head_sha"])
                self.assertEqual(diff, plan["binding"]["diff_sha256"])
                for origin in (
                    "https://github.com/Hall-of-Memory/memoraevents-other.git",
                    "https://github.com/Other/memoraevents.git",
                    "https://github.com/Hall-of-Memory/memoraevents",
                    "file:///tmp/memoraevents.git",
                ):
                    self._git(repo, "remote", "set-url", "origin", origin)
                    with self.subTest(origin=origin):
                        with self.assertRaisesRegex(
                            review.ReviewExecutionRejected, "origin invalid",
                        ):
                            producer._managed_repository_identity(repo)


if __name__ == "__main__":
    unittest.main()
