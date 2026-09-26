from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

import grabowski_git_preimage as git_preimage


class GitPreimageOperationStateTests(unittest.TestCase):
    def _run(
        self, repo: Path, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repo), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )

    def _probe(
        self, repo: Path, arguments: list[str]
    ) -> subprocess.CompletedProcess[bytes]:
        return self._run(repo, *arguments, check=False)

    def _init_repo(self, repo: Path) -> None:
        self._run(repo.parent, "init", "-q", "-b", "main", str(repo))
        self._run(repo, "config", "user.name", "Grabowski Test")
        self._run(
            repo,
            "config",
            "user.email",
            "grabowski@example.invalid",
        )
        tracked = repo / "tracked.txt"
        for index in range(3):
            tracked.write_text(f"revision {index}\n", encoding="utf-8")
            self._run(repo, "add", "tracked.txt")
            self._run(repo, "commit", "-q", "-m", f"revision {index}")

    def test_active_no_checkout_bisect_is_bound_into_branch_preimage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            self._init_repo(repo)

            original_head = self._run(repo, "rev-parse", "HEAD").stdout.strip()
            self._run(repo, "bisect", "start", "--no-checkout", "HEAD", "HEAD~2")
            try:
                self.assertEqual(
                    original_head,
                    self._run(repo, "rev-parse", "HEAD").stdout.strip(),
                )
                preimage = git_preimage.capture_branch_preimage(repo, self._probe)
                self.assertEqual(
                    "present",
                    preimage["operation_refs"].get("STATE:BISECT_START"),
                )
            finally:
                self._run(repo, "bisect", "reset")

            settled = git_preimage.capture_branch_preimage(repo, self._probe)
            self.assertNotIn("STATE:BISECT_START", settled["operation_refs"])


if __name__ == "__main__":
    unittest.main()
