"""Real Git and signed-receipt regression for large immutable PR releases."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402


class LargeFirstPartyReviewTests(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def test_real_git_diff_over_one_megabyte_and_over_256_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"
            repo.mkdir()
            self._git(repo, "init", "-q")
            self._git(repo, "config", "user.name", "Review Scale Test")
            self._git(repo, "config", "user.email", "scale@example.invalid")
            self._git(repo, "commit", "-qm", "baseline", "--allow-empty")
            base = self._git(repo, "rev-parse", "HEAD")
            files = repo / "catalog" / "runtime" / "details"
            files.mkdir(parents=True)
            # These generated text files deliberately exceed the previous
            # 1-MiB textual-diff cap and 256-file source inventory.
            for n in range(320):
                (files / f"snapshot-{n:04d}.json").write_text(
                    json.dumps({"id": n, "description": f"{n:04d}-" + "x" * 5000})
                    + "\n", encoding="utf-8",
                )
            self._git(repo, "add", "catalog/runtime/details")
            self._git(repo, "commit", "-qm", "immutable snapshot")
            head = self._git(repo, "rev-parse", "HEAD")
            binding = {
                "review_purpose": "pull_request",
                "base_sha": base, "head_sha": head,
            }
            diff = review._first_party_diff(repo, binding)
            paths = review._first_party_changed_paths(repo, binding)
            self.assertGreater(len(diff), 1024 * 1024)
            self.assertEqual(320, len(paths))
            self.assertEqual(320, len(set(paths)))
            self.assertTrue(all(path.startswith("catalog/runtime/details/") for path in paths))
            self.assertLessEqual(len(diff), review.FIRST_PARTY_MAX_DIFF_BYTES)

    def test_signed_session_inventory_is_larger_than_ordinary_receipts(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.skipTest("OpenSSH signer not installed")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "review-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True, capture_output=True,
            )
            signers = root / "allowed_signers"
            public = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
            signers.write_text(review.PRINCIPAL + " " + public + "\n", encoding="utf-8")
            signers.chmod(0o600)
            session_dir = root / "sessions" / ("a" * 32)
            session_dir.mkdir(parents=True, mode=0o700)
            session = {
                "kind": review.FIRST_PARTY_SESSION_KIND,
                "changed_paths": [
                    f"releases/abcdef0123456789/catalog/runtime/details/{n:04d}.v1.json"
                    for n in range(1181)
                ],
            }
            self.assertGreater(len(review._canonical(session)), review.MAX_RECEIPT)
            path = session_dir / "session.json"
            review._write_signed_record(
                path, session, key=key, signers=signers,
                max_bytes=review.FIRST_PARTY_MAX_SESSION_BYTES,
            )
            self.assertEqual(
                session,
                review._read_signed_record(
                    path, signers=signers, root_owned_signers=False,
                ),
            )
            with self.assertRaises(review.ReviewExecutionRejected):
                review._write_signed_record(
                    session_dir / "too-large.json",
                    {"payload": "X" * (review.FIRST_PARTY_MAX_SESSION_BYTES + 1)},
                    key=key, signers=signers,
                    max_bytes=review.FIRST_PARTY_MAX_SESSION_BYTES,
                )
            with self.assertRaises(review.ReviewExecutionRejected):
                review._write_signed_record(
                    session_dir / "ordinary.json", session,
                    key=key, signers=signers,
                )


if __name__ == "__main__":
    unittest.main()
