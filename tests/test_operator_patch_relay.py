from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "operator_patch_relay.py"


class OperatorPatchRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", str(self.repo), "init"], check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Test User"], check=True)
        (self.repo / "file.txt").write_text("old\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "file.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-m", "initial"], check=True, stdout=subprocess.PIPE)
        self.head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.patch = self.root / "change.patch"
        self.receipt = self.root / "receipt.json"
        (self.repo / "file.txt").write_text("new\n", encoding="utf-8")
        diff = subprocess.check_output(["git", "-C", str(self.repo), "diff", "--", "file.txt"], text=True)
        self.patch.write_text(diff, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "checkout", "--", "file.txt"], check=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _relay(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(self.repo), "--patch", str(self.patch), "--receipt", str(self.receipt), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def _receipt(self) -> dict[str, object]:
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def test_check_mode_writes_receipt_without_modifying_repo(self) -> None:
        result = self._relay("--mode", "check", "--expected-head", self.head)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self._receipt()
        self.assertEqual(receipt["state"], "checked")
        self.assertEqual(receipt["check_returncode"], 0)
        self.assertEqual(receipt["dirty_after"], False)
        self.assertEqual((self.repo / "file.txt").read_text(encoding="utf-8"), "old\n")

    def test_apply_mode_applies_patch_and_writes_changed_files(self) -> None:
        result = self._relay("--mode", "apply", "--expected-head", self.head)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self._receipt()
        self.assertEqual(receipt["state"], "applied")
        self.assertEqual(receipt["changed_files"], ["file.txt"])
        self.assertEqual((self.repo / "file.txt").read_text(encoding="utf-8"), "new\n")

    def test_expected_head_mismatch_fails_closed(self) -> None:
        result = self._relay("--mode", "check", "--expected-head", "0" * 40)
        self.assertNotEqual(result.returncode, 0)
        receipt = self._receipt()
        self.assertEqual(receipt["state"], "failed")
        self.assertIn("expected-head", receipt["error"])

    def test_three_way_flag_reaches_check_and_apply(self) -> None:
        target = self.repo / "file.txt"
        target.write_text("line1\nline2\nline3\nline4\nline5\nline6\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-am", "multi-line base"], check=True, stdout=subprocess.PIPE)
        target.write_text("line1\nLINE2\nline3\nline4\nline5\nline6\n", encoding="utf-8")
        diff = subprocess.check_output(["git", "-C", str(self.repo), "diff", "--", "file.txt"], text=True)
        self.patch.write_text(diff, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "checkout", "--", "file.txt"], check=True)
        target.write_text("line1\nline2\nline3\ncur4\nline5\nline6\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-am", "context edit"], check=True, stdout=subprocess.PIPE)

        plain = self._relay("--mode", "apply")
        self.assertNotEqual(plain.returncode, 0)
        self.assertEqual(self._receipt()["state"], "failed")

        result = self._relay("--mode", "apply", "--three-way")
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = self._receipt()
        self.assertEqual(receipt["state"], "applied")
        self.assertEqual(target.read_text(encoding="utf-8"), "line1\nLINE2\nline3\ncur4\nline5\nline6\n")

    def test_dirty_repo_is_rejected_without_override(self) -> None:
        (self.repo / "other.txt").write_text("dirty\n", encoding="utf-8")
        result = self._relay("--mode", "check", "--expected-head", self.head)
        self.assertNotEqual(result.returncode, 0)
        receipt = self._receipt()
        self.assertEqual(receipt["state"], "failed")
        self.assertIn("dirty", receipt["error"])


if __name__ == "__main__":
    unittest.main()
