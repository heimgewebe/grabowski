"""Git SHA-1/SHA-256 object identity in the Captain merge guard.

These syntactic probes are not a review, CI, or release authorization.
"""
from __future__ import annotations

import sys
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_merge_guard as guard


def _one_commit_mbox(head: str, diff: bytes) -> bytes:
    return (
        f"From {head} Mon Sep 17 00:00:00 2001\n"
        "From: Example <a@example.org>\n"
        "Subject: [PATCH] synthetic Git object width test\n\n"
        "---\n"
    ).encode("ascii") + diff


DIFF = (
    b"diff --git a/t.txt b/t.txt\n"
    b"index 1111111..2222222 100644\n"
    b"--- a/t.txt\n"
    b"+++ b/t.txt\n"
    b"@@ -1 +1 @@\n"
    b"-old\n"
    b"+new\n"
)


class MergeGuardGitObjectWidthTests(TestCase):
    def test_only_full_lowercase_sha1_or_sha256_oid(self) -> None:
        for width in (40, 64):
            with self.subTest(width=width):
                self.assertIsNotNone(guard._GIT_OID_RE.fullmatch("a" * width))
        for width in (0, 1, 39, 41, 52, 63, 65):
            with self.subTest(width=width):
                self.assertIsNone(guard._GIT_OID_RE.fullmatch("a" * width))
        self.assertIsNone(guard._GIT_OID_RE.fullmatch("A" * 64))

    def test_consistent_width_requires_matching_git_object_formats(self) -> None:
        for width in (40, 64):
            with self.subTest(width=width):
                self.assertTrue(guard._same_git_oid_format("a" * width, "b" * width))
        for a, b in (("a" * 40, "b" * 64), ("a" * 64, "b" * 40),
                     ("a" * 63, "b" * 63), ("a" * 40, "b" * 41),
                     ("A" * 64, "b" * 64)):
            with self.subTest(a=len(a), b=len(b)):
                self.assertFalse(guard._same_git_oid_format(a, b))

    def test_mbox_patch_accepts_exact_full_width_for_both_formats(self) -> None:
        for width in (40, 64):
            with self.subTest(width=width):
                head = "a" * width
                self.assertTrue(guard._merge_guard_mbox_patch_matches_diff(
                    _one_commit_mbox(head, DIFF), DIFF, head,
                ))

    def test_mbox_patch_rejects_truncated_mismatched_and_wrong_heads(self) -> None:
        for width in (39, 41, 63, 65):
            with self.subTest(width=width):
                head = "a" * width
                self.assertFalse(guard._merge_guard_mbox_patch_matches_diff(
                    _one_commit_mbox(head, DIFF), DIFF, head,
                ))
        head = "a" * 64
        self.assertFalse(guard._merge_guard_mbox_patch_matches_diff(
            _one_commit_mbox(head, DIFF), DIFF, "b" * 64,
        ))
        self.assertFalse(guard._merge_guard_mbox_patch_matches_diff(
            _one_commit_mbox(head, DIFF), DIFF, "a" * 40,
        ))

    def test_mbox_patch_rejects_mixed_sha1_sha256_commit_headers(self) -> None:
        head = "b" * 64
        other = "a" * 40
        first = DIFF.replace(b"a/t.txt", b"a/u.txt").replace(b"b/t.txt", b"b/u.txt")
        mixed = _one_commit_mbox(other, first) + _one_commit_mbox(head, DIFF)
        self.assertFalse(guard._merge_guard_mbox_patch_matches_diff(
            mixed, first + DIFF, head,
        ))

    def test_sha256_oid_probed_without_truncation(self) -> None:
        head = "a" * 64
        with patch.object(
            guard, "_merge_guard_local_git_bytes",
            return_value={"returncode": 0, "stdout_bytes": b"", "stderr_bytes": b""},
        ) as git:
            valid, result = guard._merge_guard_commit_probe(Path("/synthetic"), head)
        self.assertTrue(valid)
        self.assertEqual(head, result["sha"])
        git.assert_called_once_with(
            Path("/synthetic"), ["cat-file", "-e", f"{head}^{{commit}}"]
        )

    def test_malformed_oid_never_reaches_git_probe(self) -> None:
        with patch.object(guard, "_merge_guard_local_git_bytes") as git:
            for head in ("a" * 39, "a" * 41, "a" * 63, "a" * 65, "A" * 64):
                valid, result = guard._merge_guard_commit_probe(
                    Path("/synthetic"), head
                )
                self.assertFalse(valid)
                self.assertFalse(result["valid"])
        git.assert_not_called()


    def test_full_sha256_codex_clean_comment_prefix_matches_head(self) -> None:
        head = "a" * 64
        body = (
            "Codex Review: Didn't find any major issues. Hooray!\n\n"
            f"**Reviewed commit:** \x60{head}\x60\n\n"
            "<details> <summary>ℹ️ About Codex in GitHub</summary>\n"
            "<br/>\n\n"
            "[Your team has set up Codex to review pull requests in this repo]"
            "(https://chatgpt.com/codex/cloud/settings/general). "
            "Reviews are triggered when you\n"
            "- Open a pull request for review\n"
            "- Mark a draft as ready\n"
            '- Comment "@codex review".\n\n'
            "If Codex has suggestions, it will comment; otherwise it will react with 👍."
            "\n\n\n\n\n"
            "Codex can also answer questions or update the PR. Try commenting "
            '"@codex address that feedback".\n\n'
            "</details>"
        )
        clean = guard._normalize_codex_comment_body(body)
        match = guard._CODEX_CLEAN_RESULT_RE.fullmatch(clean)
        self.assertIsNotNone(match)
        self.assertEqual(head, match.group(1))
        self.assertFalse(("b" * 64).startswith(match.group(1)))



    def test_captain_static_binding_rejects_mixed_oid_formats(self) -> None:
        runner = object.__new__(guard.CaptainMergeGuardRunner)
        runner.repository_binding_error = None
        runner.server_actor_identity_error = None
        runner.server_task_lease_delegation_error = None
        runner.server_operator_lease_delegation_error = None
        runner.server_bureau_run_lease_delegation_error = None
        runner.requested_lease_owner_id = "synthetic-test"
        runner.lease_owner_id = "synthetic-test"
        runner.parameters = {
            "expected_head": "a" * 64,
            "expected_base_sha": "b" * 64,
            "diff_sha256": "c" * 64,
        }
        errors = runner._static_binding_errors()
        self.assertNotIn("merge_guard_expected_head_invalid", errors)
        self.assertNotIn("merge_guard_expected_base_sha_invalid", errors)
        self.assertNotIn("merge_guard_expected_git_object_format_mismatch", errors)
        runner.parameters["expected_base_sha"] = "b" * 40
        errors = runner._static_binding_errors()
        self.assertIn("merge_guard_expected_git_object_format_mismatch", errors)
        runner.parameters["expected_head"] = "a" * 41
        errors = runner._static_binding_errors()
        self.assertIn("merge_guard_expected_head_invalid", errors)


    def test_real_sha256_git_repo_commit_diff_and_format_patch(self) -> None:
        def git(repo: Path, *args: str) -> bytes:
            process = subprocess.run(
                [
                    "git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args
                ],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            return process.stdout

        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "sha256-repo"
            repo.mkdir()
            git(repo, "init", "--quiet", "--object-format=sha256")
            git(repo, "config", "user.name", "Git OID Test")
            git(repo, "config", "user.email", "oid@example.org")
            (repo / "sample.txt").write_text("before\n", encoding="utf-8")
            git(repo, "add", "sample.txt")
            git(repo, "commit", "--quiet", "-m", "first")
            base = git(repo, "rev-parse", "HEAD").decode().strip()
            (repo / "sample.txt").write_text("after\n", encoding="utf-8")
            git(repo, "add", "sample.txt")
            git(repo, "commit", "--quiet", "-m", "second")
            head = git(repo, "rev-parse", "HEAD").decode().strip()
            self.assertEqual((64, 64), (len(base), len(head)))
            self.assertTrue(guard._same_git_oid_format(base, head))

            accepted, _proof = guard._merge_guard_commit_probe(repo, head)
            self.assertTrue(accepted)
            paths, _path_info, errors = guard._merge_guard_local_changed_paths(
                repo, base_sha=base, head_sha=head
            )
            self.assertFalse(errors)
            self.assertEqual(["sample.txt"], paths)

            diff, _diff_info, diff_errors = guard._merge_guard_local_diff_bytes(
                repo, base_sha=base, head_sha=head
            )
            self.assertFalse(diff_errors)
            self.assertIn(b"diff --git a/sample.txt b/sample.txt", diff)
            mbox = git(repo, "format-patch", "--stdout", f"{base}..{head}")
            self.assertTrue(guard._merge_guard_mbox_patch_matches_diff(
                mbox, diff, head
            ))


if __name__ == "__main__":
    main()
