
from __future__ import annotations

import json
from pathlib import Path
import unittest

import grabowski_merge_guard as merge_guard


BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
MERGE_SHA = "c" * 40
TREE_SHA = "d" * 40
REMOTE_URL = "git@github.com:heimgewebe/grabowski.git"


def _result(returncode: int = 0, stdout: str = "", stderr: str = "") -> dict[str, object]:
    return {"returncode": returncode, "stdout": stdout, "stderr": stderr}


class FakeGit:
    def __init__(self, post_base: str | None) -> None:
        self.post_base = post_base
        self.read_counts: dict[str, int] = {}

    def __call__(
        self,
        _repo: Path,
        argv: list[str],
        *,
        timeout: int = 60,
    ) -> dict[str, object]:
        del timeout
        if argv[:1] == ["check-ref-format"]:
            return _result()
        if argv == ["remote", "get-url", "origin"]:
            return _result(stdout=REMOTE_URL + "\n")
        if argv == ["remote", "get-url", "--push", "--all", "origin"]:
            return _result(stdout=REMOTE_URL + "\n")
        if argv[:1] in (["init"], ["config"], ["fetch"], ["checkout"]):
            return _result()
        if argv[:3] == ["remote", "add", "origin"]:
            return _result()
        if "merge" in argv:
            return _result()
        if argv == ["rev-parse", "refs/converge/base^{commit}"]:
            return _result(stdout=BASE_SHA + "\n")
        if argv == ["rev-parse", "refs/converge/head-branch^{commit}"]:
            return _result(stdout=HEAD_SHA + "\n")
        if argv == ["rev-parse", "refs/converge/pr-head^{commit}"]:
            return _result(stdout=HEAD_SHA + "\n")
        if argv == ["rev-list", "--parents", "-n", "1", "HEAD"]:
            return _result(stdout=f"{MERGE_SHA} {HEAD_SHA} {BASE_SHA}\n")
        if argv == ["rev-parse", "HEAD^{tree}"]:
            return _result(stdout=TREE_SHA + "\n")
        if argv[:2] == ["ls-remote", "origin"]:
            ref = argv[2]
            count = self.read_counts.get(ref, 0)
            self.read_counts[ref] = count + 1
            if ref == "refs/heads/main":
                if count == 0:
                    return _result(stdout=f"{BASE_SHA}\t{ref}\n")
                if self.post_base is None:
                    return _result(returncode=2, stderr="readback failed")
                return _result(stdout=f"{self.post_base}\t{ref}\n")
            if ref == "refs/heads/feature":
                sha = HEAD_SHA if count == 0 else MERGE_SHA
                return _result(stdout=f"{sha}\t{ref}\n")
            if ref == "refs/pull/77/head":
                sha = HEAD_SHA if count == 0 else MERGE_SHA
                return _result(stdout=f"{sha}\t{ref}\n")
        if argv[:1] == ["push"]:
            return _result()
        raise AssertionError(f"unexpected git command: {argv}")


def fake_github(_repo: Path, argv: list[str]) -> dict[str, object]:
    if argv[:2] == ["api", "user"]:
        return _result(
            stdout=json.dumps(
                {
                    "login": "alexdermohr",
                    "id": 216529510,
                    "type": "User",
                    "created_at": "2025-01-01T00:00:00Z",
                }
            )
        )
    raise AssertionError(f"unexpected GitHub command: {argv}")


class ExactBasePostPushReadbackTests(unittest.TestCase):
    def test_applied_head_with_unavailable_or_malformed_base_is_unknown(self) -> None:
        for name, post_base in (
            ("missing", None),
            ("malformed", "not-a-sha"),
        ):
            with self.subTest(name=name):
                result, evidence = (
                    merge_guard._exact_base_content_git_head_cas_update_pr_head(
                        Path("/repo"),
                        base_branch="main",
                        base_sha=BASE_SHA,
                        head_sha=HEAD_SHA,
                        head_branch="feature",
                        pr_number=77,
                        github_runner=fake_github,
                        git_runner=FakeGit(post_base),
                    )
                )
            self.assertEqual(2, result["returncode"])
            self.assertEqual("outcome_unknown", evidence["status"])
            self.assertTrue(evidence["effect_proven"])
            self.assertFalse(evidence["effect_not_applied_proven"])
            self.assertEqual(MERGE_SHA, evidence["merge_sha"])
            self.assertIsNone(evidence["remote_readback"]["base_sha"])
            self.assertEqual(MERGE_SHA, evidence["remote_readback"]["head_sha"])
            self.assertEqual(MERGE_SHA, evidence["remote_readback"]["pr_head_sha"])


if __name__ == "__main__":
    unittest.main()
