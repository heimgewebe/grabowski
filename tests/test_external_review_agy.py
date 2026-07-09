from __future__ import annotations

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location("external_review_agy_test", ROOT / "tools" / "external_review_agy.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


agy = _load_tool()


class ExternalReviewAgyTests(unittest.TestCase):
    def _packet(self, root: Path) -> Path:
        packet = root / "packet"
        packet.mkdir()
        diff = packet / "pr-7-aaaaaaaaaaaa.diff"
        prompt = packet / "pr-7-aaaaaaaaaaaa-external-review-prompt.md"
        diff.write_text("diff --git a/x.py b/x.py\n+print('x')\n", encoding="utf-8")
        prompt_text = (
            "You are an external LLM reviewer.\n"
            "Repo: heimgewebe/grabowski\n"
            "PR: 7\n"
            "Head SHA: " + "a" * 40 + "\n"
        )
        prompt.write_text(prompt_text, encoding="utf-8")
        manifest = {
            "schema_version": 1,
            "kind": "external_review_packet",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": "a" * 40,
            "diff_path": str(diff),
            "diff_sha256": agy.sha256_bytes(diff.read_bytes()),
            "prompt_path": str(prompt),
            "prompt_sha256": agy.sha256_text(prompt_text),
        }
        manifest_path = packet / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest_path

    def test_builds_diff_inline_prompt_and_passing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._packet(root)
            output = root / "evidence.json"
            calls = []

            def fake_run(argv, **kwargs):
                calls.append((argv, kwargs))
                self.assertEqual(argv[0], "gemini")
                self.assertEqual(argv[1], "--print-timeout=300s")
                self.assertEqual(argv[2], "--model")
                self.assertEqual(argv[3], "Gemini 3.1 Pro (Low)")
                self.assertEqual(argv[4], "--print")
                self.assertIn("--- BEGIN DIFF ---", argv[5])
                self.assertIn("diff --git", argv[5])
                self.assertIn("Return only compact JSON", argv[5])
                return subprocess.CompletedProcess(argv, 0, "```json\n{\"verdict\":\"PASS\",\"finding_count\":0,\"findings\":[]}\n```\n", "")

            with mock.patch.object(agy.subprocess, "run", side_effect=fake_run):
                evidence = agy.run_from_manifest(
                    manifest_path=manifest,
                    output_path=output,
                    raw_review_path=None,
                    gemini_bin="gemini",
                    model="Gemini 3.1 Pro (Low)",
                    timeout_seconds=300,
                    max_prompt_bytes=100_000,
                )

            self.assertEqual(len(calls), 1)
            self.assertEqual(evidence["kind"], "external_review")
            self.assertEqual(evidence["reviews"][0]["source"], "agy:Gemini 3.1 Pro (Low)")
            self.assertEqual(evidence["reviews"][0]["verdict"], "PASS")
            self.assertTrue(evidence["external_reviews_triaged"])
            self.assertTrue(output.is_file())
            self.assertTrue(output.with_suffix(".review.txt").is_file())

    def test_non_pass_review_is_not_auto_triaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._packet(root)
            output = root / "evidence.json"

            def fake_run(argv, **kwargs):
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    json.dumps(
                        {
                            "verdict": "NEEDS_CHANGE",
                            "finding_count": 1,
                            "findings": [{"severity": "medium", "file": "x.py", "summary": "issue", "fix": "fix it"}],
                        }
                    ),
                    "",
                )

            with mock.patch.object(agy.subprocess, "run", side_effect=fake_run):
                evidence = agy.run_from_manifest(
                    manifest_path=manifest,
                    output_path=output,
                    raw_review_path=None,
                    gemini_bin="gemini",
                    model=None,
                    timeout_seconds=300,
                    max_prompt_bytes=100_000,
                )

            self.assertFalse(evidence["external_reviews_triaged"])
            self.assertEqual(evidence["findings"], [])
            self.assertEqual(len(evidence["raw_findings"]), 1)

    def test_rejects_packet_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet = root / "packet"
            packet.mkdir()
            outside = root / "outside.diff"
            outside.write_text("diff", encoding="utf-8")
            prompt = packet / "prompt.md"
            prompt.write_text("prompt", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "kind": "external_review_packet",
                "repo": "heimgewebe/grabowski",
                "pr": 7,
                "head_sha": "a" * 40,
                "diff_path": str(outside),
                "diff_sha256": agy.sha256_text("diff"),
                "prompt_path": str(prompt),
                "prompt_sha256": agy.sha256_text("prompt"),
            }
            manifest_path = packet / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(agy.AgyReviewError, "escapes"):
                agy.run_from_manifest(
                    manifest_path=manifest_path,
                    output_path=root / "out.json",
                    raw_review_path=None,
                    gemini_bin="gemini",
                    model=None,
                    timeout_seconds=300,
                    max_prompt_bytes=100_000,
                )

    def test_rejects_oversized_argv_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._packet(root)
            with self.assertRaisesRegex(agy.AgyReviewError, "too large"):
                agy.run_from_manifest(
                    manifest_path=manifest,
                    output_path=root / "out.json",
                    raw_review_path=None,
                    gemini_bin="gemini",
                    model=None,
                    timeout_seconds=300,
                    max_prompt_bytes=10,
                )

    def test_main_reports_agy_failure_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._packet(root)
            output = root / "evidence.json"

            def fake_run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 7, "", "upstream failed")

            stderr = io.StringIO()
            with (
                mock.patch.object(agy.subprocess, "run", side_effect=fake_run),
                contextlib.redirect_stderr(stderr),
            ):
                rc = agy.main(["--manifest", str(manifest), "--output", str(output), "--gemini-bin", "gemini"])

            self.assertEqual(rc, 2)
            self.assertIn("upstream failed", stderr.getvalue())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
