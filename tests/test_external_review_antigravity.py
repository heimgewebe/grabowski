from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "external_review_antigravity_test",
        ROOT / "tools" / "external_review_antigravity.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load external_review_antigravity")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


antigravity = _load_tool()


class ExternalReviewAntigravityCompatibilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._account_home = tempfile.TemporaryDirectory()
        self.addCleanup(self._account_home.cleanup)
        account_home = Path(self._account_home.name)
        account_home.chmod(0o700)
        self._account_home_patch = mock.patch.dict(
            os.environ,
            {"HOME": str(account_home)},
        )
        self._account_home_patch.start()
        self.addCleanup(self._account_home_patch.stop)

    def _packet(self, root: Path) -> Path:
        packet = root / "packet"
        packet.mkdir(mode=0o700)
        packet.chmod(0o700)
        diff = packet / "diff.txt"
        prompt = packet / "prompt.md"
        diff.write_text(
            "diff --git a/x.py b/x.py\n+print('x')\n",
            encoding="utf-8",
        )
        diff.chmod(0o600)
        prompt.write_text("Review the diff.\n", encoding="utf-8")
        prompt.chmod(0o600)
        manifest = {
            "schema_version": 1,
            "kind": "external_review_packet",
            "repo": "heimgewebe/grabowski",
            "pr": 7,
            "head_sha": "a" * 40,
            "diff_path": str(diff),
            "diff_sha256": antigravity.sha256_bytes(diff.read_bytes()),
            "prompt_path": str(prompt),
            "prompt_sha256": antigravity.sha256_text(
                prompt.read_text(encoding="utf-8")
            ),
        }
        path = packet / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_legacy_entry_point_routes_to_plain_gemini(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence.json"

            def fake_run(argv, **kwargs):
                self.assertEqual(kwargs["timeout_seconds"], 315)
                self.assertEqual(argv[0], "/private/gemini")
                self.assertIn("--sandbox", argv)
                self.assertIn("--print", argv)
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    '{"verdict":"PASS","finding_count":0,"findings":[]}',
                    "",
                )

            with mock.patch.object(
                antigravity.plain,
                "run_bounded_process",
                side_effect=fake_run,
            ), mock.patch.object(
                antigravity.plain,
                "resolve_provider_executable",
                return_value="/private/gemini",
            ):
                evidence = antigravity.run_from_manifest(
                    manifest_path=self._packet(root),
                    output_path=output,
                    raw_review_path=None,
                    antigravity_bin="gemini",
                    model="Gemini 3.1 Pro (Low)",
                    timeout_seconds=300,
                    max_prompt_bytes=100_000,
                )

            self.assertEqual(
                evidence["reviews"][0]["source"],
                "plain-llm:gemini:Gemini 3.1 Pro (Low)",
            )
            self.assertTrue(evidence["external_reviews_triaged"])

    def test_legacy_error_alias_is_preserved(self) -> None:
        self.assertIs(
            antigravity.AntigravityReviewError,
            antigravity.plain.PlainReviewError,
        )


if __name__ == "__main__":
    unittest.main()
