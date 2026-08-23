from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_merge_guard as merge_guard  # noqa: E402


_REPO_SLUG = "heimgewebe/infra"
_CANONICAL_ORIGIN = "git@github.com:heimgewebe/infra.git"
_BASE_BRANCH = "main"
_HEAD_BRANCH = "feature/cas-real-git"
_PR_NUMBER = 153
_BASE_REF = f"refs/heads/{_BASE_BRANCH}"
_HEAD_REF = f"refs/heads/{_HEAD_BRANCH}"
_PULL_REF = f"refs/pull/{_PR_NUMBER}/head"


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        },
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"command failed rc={completed.returncode}: {argv!r}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


def _git(repo: Path, *args: str, check: bool = True) -> str:
    return _run(
        ["git", "-C", str(repo), *args],
        check=check,
    ).stdout.strip()


def _bare_git(remote: Path, *args: str, check: bool = True) -> str:
    return _run(
        ["git", f"--git-dir={remote}", *args],
        check=check,
    ).stdout.strip()


class _LocalBareGitRunner:
    """Run the production Git command stream against one local bare remote.

    The merge code must still observe a canonical GitHub SSH origin. Only the
    transport is rewritten command-locally to the test bare repository.
    """

    def __init__(self, remote: Path) -> None:
        self.remote = remote.resolve()
        self.calls: list[tuple[str, ...]] = []
        self._rewrite = (
            f"url.file://{self.remote.as_posix()}.insteadOf={_CANONICAL_ORIGIN}"
        )

    def __call__(
        self,
        repo: Path,
        args: list[str],
        *,
        timeout: int = 60,
    ) -> dict[str, object]:
        self.calls.append(tuple(args))
        command = ["git", "-C", str(repo)]
        if args != ["remote", "get-url", "origin"]:
            command.extend(
                [
                    "-c",
                    "protocol.file.allow=always",
                    "-c",
                    self._rewrite,
                ]
            )
        command.extend(args)
        completed = _run(command, check=False, timeout=timeout)
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }


class _RealGitCasFixture:
    def __init__(self, owner: unittest.TestCase) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        owner.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        self.remote = self.root / "remote.git"
        self.seed = self.root / "seed"
        self.control = self.root / "control"

        _run(["git", "init", "--bare", "--quiet", str(self.remote)])
        _run(["git", "init", "--quiet", str(self.seed)])
        _git(self.seed, "config", "gc.auto", "0")
        _git(self.seed, "config", "maintenance.auto", "false")
        _git(self.seed, "config", "user.name", "Captain Real Git Test")
        _git(self.seed, "config", "user.email", "captain-real-git@example.invalid")

        (self.seed / "payload.txt").write_text("base\n", encoding="utf-8")
        _git(self.seed, "add", "payload.txt")
        _git(self.seed, "commit", "--quiet", "-m", "base")
        _git(self.seed, "branch", "-M", _BASE_BRANCH)
        self.base_sha = _git(self.seed, "rev-parse", "HEAD")

        _git(self.seed, "checkout", "--quiet", "-b", _HEAD_BRANCH)
        (self.seed / "payload.txt").write_text("base\nreviewed head\n", encoding="utf-8")
        _git(self.seed, "commit", "--quiet", "-am", "reviewed head")
        self.head_sha = _git(self.seed, "rev-parse", "HEAD")

        (self.seed / "payload.txt").write_text(
            "base\nreviewed head\nconcurrent head\n",
            encoding="utf-8",
        )
        _git(self.seed, "commit", "--quiet", "-am", "concurrent head")
        self.concurrent_sha = _git(self.seed, "rev-parse", "HEAD")

        _git(self.seed, "remote", "add", "target", str(self.remote))
        _git(
            self.seed,
            "push",
            "--quiet",
            "target",
            f"{self.base_sha}:{_BASE_REF}",
            f"{self.head_sha}:{_HEAD_REF}",
            f"{self.head_sha}:{_PULL_REF}",
            f"{self.concurrent_sha}:refs/test/concurrent-head",
        )

        _run(["git", "init", "--quiet", str(self.control)])
        _git(self.control, "remote", "add", "origin", _CANONICAL_ORIGIN)

    def ref(self, ref: str) -> str:
        return _bare_git(self.remote, "rev-parse", "--verify", ref)

    def ref_missing(self, ref: str) -> bool:
        completed = _run(
            ["git", f"--git-dir={self.remote}", "rev-parse", "--verify", "--quiet", ref],
            check=False,
        )
        return completed.returncode != 0

    def move_pr_head_concurrently(self) -> None:
        transaction = "\n".join(
            [
                "start",
                f"update {_HEAD_REF} {self.concurrent_sha} {self.head_sha}",
                f"update {_PULL_REF} {self.concurrent_sha} {self.head_sha}",
                "prepare",
                "commit",
                "",
            ]
        )
        _run(
            ["git", f"--git-dir={self.remote}", "update-ref", "--stdin"],
            input_text=transaction,
        )


class CaptainExactBaseCasRealGitIntegrationTests(unittest.TestCase):
    def test_real_atomic_success_fast_forwards_base_and_deletes_expected_head(self) -> None:
        fixture = _RealGitCasFixture(self)
        git = _LocalBareGitRunner(fixture.remote)

        result, evidence = merge_guard._exact_base_git_cas_merge(
            fixture.control,
            repo_slug=_REPO_SLUG,
            base_branch=_BASE_BRANCH,
            base_sha=fixture.base_sha,
            head_sha=fixture.head_sha,
            head_branch=_HEAD_BRANCH,
            pr_number=_PR_NUMBER,
            git_runner=git,
        )

        self.assertEqual(0, result["returncode"])
        self.assertEqual("pushed_and_read_back", evidence["status"])
        merge_sha = evidence["merge_sha"]
        self.assertEqual(merge_sha, fixture.ref(_BASE_REF))
        self.assertTrue(fixture.ref_missing(_HEAD_REF))
        parents = _bare_git(
            fixture.remote,
            "rev-list",
            "--parents",
            "-n",
            "1",
            merge_sha,
        ).split()
        self.assertEqual([fixture.base_sha, fixture.head_sha], parents[1:])
        self.assertFalse(evidence["protected_base_force_push"])
        self.assertEqual("fast_forward_no_force", evidence["base_update_mode"])
        self.assertTrue(evidence["atomic_base_update_and_head_delete"])

        push = next(call for call in git.calls if call[:2] == ("push", "--porcelain"))
        self.assertIn("--atomic", push)
        self.assertIn(
            f"--force-with-lease={_HEAD_REF}:{fixture.head_sha}",
            push,
        )
        self.assertNotIn(
            f"--force-with-lease={_BASE_REF}:{fixture.base_sha}",
            push,
        )
        self.assertIn(f"HEAD:{_BASE_REF}", push)
        self.assertEqual(f":{_HEAD_REF}", push[-1])

    def test_real_atomic_head_race_rejects_entire_push_and_preserves_base(self) -> None:
        fixture = _RealGitCasFixture(self)
        git = _LocalBareGitRunner(fixture.remote)

        result, evidence = merge_guard._exact_base_git_cas_merge(
            fixture.control,
            repo_slug=_REPO_SLUG,
            base_branch=_BASE_BRANCH,
            base_sha=fixture.base_sha,
            head_sha=fixture.head_sha,
            head_branch=_HEAD_BRANCH,
            pr_number=_PR_NUMBER,
            git_runner=git,
            on_dispatch=fixture.move_pr_head_concurrently,
        )

        self.assertNotEqual(0, result["returncode"])
        self.assertEqual("push_rejected_or_failed", evidence["status"])
        self.assertEqual(fixture.base_sha, fixture.ref(_BASE_REF))
        self.assertEqual(fixture.concurrent_sha, fixture.ref(_HEAD_REF))
        self.assertEqual(fixture.concurrent_sha, fixture.ref(_PULL_REF))
        push_stage = next(
            stage for stage in evidence["stages"] if stage["stage"] == "atomic-cas-push"
        )
        self.assertNotEqual(0, push_stage["returncode"])


if __name__ == "__main__":
    unittest.main()
