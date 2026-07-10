from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HEAD = "a" * 40


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "external_review_claude_test",
        ROOT / "tools" / "external_review_claude.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


claude_review = _load_tool()


class ExternalReviewClaudeTests(unittest.TestCase):
    def _packet(self, root: Path) -> tuple[Path, str]:
        packet = root / "packet"
        packet.mkdir()
        diff = packet / "pr-7-aaaaaaaaaaaa.diff"
        prompt = packet / "prompt.md"
        diff.write_text("diff --git a/x.py b/x.py\n+print('x')\n", encoding="utf-8")
        prompt.write_text("Review this exact PR diff.\n", encoding="utf-8")
        diff_sha = claude_review.sha256_bytes(diff.read_bytes())
        manifest = {
            "schema_version": 1,
            "kind": "external_review_packet",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": HEAD,
            "diff_path": str(diff),
            "diff_sha256": diff_sha,
            "prompt_path": str(prompt),
            "prompt_sha256": claude_review.sha256_bytes(prompt.read_bytes()),
        }
        manifest_path = packet / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path, diff_sha

    def _run(self, root: Path, stdout: str, *, head_after: str = HEAD, returncode: int = 0):
        manifest, diff_sha = self._packet(root)
        repo = root / "repo"
        repo.mkdir()
        output = root / "evidence.json"
        completed = subprocess.CompletedProcess(
            ["claude", "ultrareview", "7", "--json", "--timeout", "30"],
            returncode,
            stdout,
            "upstream error" if returncode else "",
        )
        with (
            mock.patch.object(claude_review, "current_repo_name", return_value="heimgewebe/grabowski"),
            mock.patch.object(claude_review, "current_pr_head", side_effect=[HEAD, head_after]),
            mock.patch.object(claude_review, "current_pr_diff_sha256", side_effect=[diff_sha, diff_sha]),
            mock.patch.object(
                claude_review,
                "run_checked",
                return_value=subprocess.CompletedProcess(["claude", "--version"], 0, "2.1.206 (Claude Code)\n", ""),
            ),
            mock.patch.object(claude_review.subprocess, "run", return_value=completed) as run,
        ):
            evidence = claude_review.run_from_manifest(
                manifest_path=manifest,
                repo=repo,
                output_path=output,
                raw_stdout_path=None,
                raw_stderr_path=None,
                claude_bin="claude",
                timeout_minutes=30,
            )
        return evidence, output, run

    def test_passing_ultrareview_creates_diff_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence, output, run = self._run(Path(directory), json.dumps({"bugs": []}))
            review = evidence["reviews"][0]
            self.assertEqual(review["source"], "claude-cli:ultrareview")
            self.assertEqual(review["command"], ["claude", "ultrareview", "7", "--json", "--timeout", "30"])
            self.assertEqual(review["verdict"], "PASS")
            self.assertEqual(review["finding_count"], 0)
            self.assertFalse(evidence["prompt_includes_diff"])
            self.assertFalse(evidence["prompt_transmitted"])
            self.assertEqual(
                evidence["review_input"],
                {
                    "mode": "claude_ultrareview_pr",
                    "repo": "heimgewebe/grabowski",
                    "pr": 7,
                    "head_sha": HEAD,
                    "diff_sha256": evidence["diff_sha256"],
                },
            )
            self.assertTrue(evidence["external_reviews_triaged"])
            self.assertTrue(output.is_file())
            run.assert_called_once()

    def test_findings_are_not_auto_triaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            finding = {"severity": "high", "file": "x.py", "summary": "problem"}
            evidence, _, _ = self._run(Path(directory), json.dumps({"bugs": [finding]}))
            self.assertEqual(evidence["reviews"][0]["verdict"], "NEEDS_CHANGE")
            self.assertEqual(evidence["reviews"][0]["finding_count"], 1)
            self.assertFalse(evidence["external_reviews_triaged"])
            self.assertEqual(evidence["raw_findings"], [finding])

    def test_head_drift_during_review_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(claude_review.ClaudeReviewError, "head changed"):
                self._run(root, json.dumps({"bugs": []}), head_after="b" * 40)
            self.assertFalse((root / "evidence.json").exists())

    def test_ultrareview_command_failure_creates_no_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(claude_review.ClaudeReviewError, "exited with 7"):
                self._run(root, "", returncode=7)
            self.assertFalse((root / "evidence.json").exists())

    def test_unrecognized_json_fails_closed(self) -> None:
        with self.assertRaisesRegex(claude_review.ClaudeReviewError, "no recognized findings list"):
            claude_review.parse_review_json(json.dumps({"status": "ok"}))


if __name__ == "__main__":
    unittest.main()
