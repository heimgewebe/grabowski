from __future__ import annotations

from pathlib import Path
import importlib.util
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "deploy_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "deploy_runtime",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("deploy_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy_runtime = load_module()


class DeployRuntimeTests(unittest.TestCase):
    def test_sha256_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_text("grabowski\n", encoding="utf-8")
            first = deploy_runtime.sha256(path)
            second = deploy_runtime.sha256(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_require_file_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.txt"
            with self.assertRaises(deploy_runtime.DeployError):
                deploy_runtime.require_file(missing, "test file")

    def test_install_stage_swaps_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            stage = root / "stage"
            runtime.mkdir()
            stage.mkdir()
            (runtime / "old.txt").write_text("old", encoding="utf-8")
            (stage / "new.txt").write_text("new", encoding="utf-8")

            backup = deploy_runtime.install_stage(
                runtime,
                stage,
                stamp="20260625-000000",
            )

            self.assertIsNotNone(backup)
            assert backup is not None
            self.assertTrue((runtime / "new.txt").is_file())
            self.assertTrue((backup / "old.txt").is_file())
            self.assertFalse(stage.exists())

    def test_restore_previous_runtime_reinstates_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            backup = root / "runtime.rollback"
            runtime.mkdir()
            backup.mkdir()
            (runtime / "broken.txt").write_text(
                "broken",
                encoding="utf-8",
            )
            (backup / "old.txt").write_text("old", encoding="utf-8")

            failed = deploy_runtime.restore_previous_runtime(
                runtime,
                backup,
                stamp="20260625-000000",
            )

            self.assertIsNotNone(failed)
            assert failed is not None
            self.assertTrue((runtime / "old.txt").is_file())
            self.assertTrue((failed / "broken.txt").is_file())
            self.assertFalse(backup.exists())

    def test_check_mode_does_not_require_clean_repo(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        check_body = source.split(
            "def check(repo: Path, runtime: Path) -> None:",
            1,
        )[1].split("\ndef parse_args()", 1)[0]
        self.assertIn("repo_dirty(repo)", check_body)
        self.assertNotIn("require_clean_repo(repo)", check_body)

    def test_apply_mode_requires_clean_repo(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        deploy_body = source.split(
            "def deploy(",
            1,
        )[1].split("\ndef check(", 1)[0]
        self.assertIn("require_clean_repo(repo)", deploy_body)

    def test_health_and_readiness_are_both_required(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('http_text(HEALTH_URL) == "live"', source)
        self.assertIn('http_text(READY_URL) == "ready"', source)

    def test_mcp_handshake_and_tool_list_are_gated(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"method": "initialize"', source)
        self.assertIn('"method": "tools/list"', source)
        self.assertIn("EXPECTED_TOOLS - names", source)


if __name__ == "__main__":
    unittest.main()
