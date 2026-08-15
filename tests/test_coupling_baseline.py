from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "coupling_baseline.py"
SPEC = importlib.util.spec_from_file_location("coupling_baseline", TOOL)
assert SPEC and SPEC.loader
coupling = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coupling)


class CouplingBaselineTests(unittest.TestCase):
    def _repo(self) -> tempfile.TemporaryDirectory[str]:
        return tempfile.TemporaryDirectory()

    def _init_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        (root / "src").mkdir()
        (root / "tests").mkdir()

    def _commit(self, root: Path, message: str) -> None:
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", message], check=True)

    def test_plural_resource_module_is_classified(self) -> None:
        self.assertEqual(coupling.domain_for_module("grabowski_resources"), {"resource"})

    def test_tarjan_reports_cycle_and_singleton(self) -> None:
        graph = {"a": {"b"}, "b": {"a"}, "c": set()}
        self.assertEqual(coupling.tarjan_scc(graph), [["a", "b"], ["c"]])

    def test_baseline_measures_imports_tests_functions_and_cochange(self) -> None:
        with self._repo() as directory:
            root = Path(directory)
            self._init_repo(root)
            (root / "src" / "grabowski_resource_store.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "src" / "grabowski_tasks.py").write_text(
                "import grabowski_resource_store\nVALUE = grabowski_resource_store.VALUE\n",
                encoding="utf-8",
            )
            (root / "src" / "grabowski_transport.py").write_text(
                "import grabowski_tasks\nVALUE = grabowski_tasks.VALUE\n",
                encoding="utf-8",
            )
            (root / "src" / "grabowski_operator.py").write_text(
                "import grabowski_resource_store as resources\n"
                "import grabowski_tasks as tasks\n"
                "import grabowski_transport as transport\n"
                "def run():\n"
                "    return resources.VALUE + tasks.VALUE + transport.VALUE\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_operator.py").write_text(
                "import grabowski_operator\nimport grabowski_tasks\n",
                encoding="utf-8",
            )
            self._commit(root, "initial")

            report = coupling.build_baseline(root, max_commits=20)

            self.assertEqual(report["module_count"], 4)
            self.assertEqual(report["edge_count"], 5)
            self.assertEqual(report["largest_scc_size"], 1)
            self.assertEqual(report["cyclic_scc_count"], 0)
            operator = next(item for item in report["fan_out"] if item["module"] == "grabowski_operator")
            self.assertEqual(operator["count"], 3)
            crosscutting = {item["module"] for item in report["crosscutting_modules"]}
            self.assertIn("grabowski_operator", crosscutting)
            functions = {(item["module"], item["function"]) for item in report["multi_authority_functions"]}
            self.assertIn(("grabowski_operator", "run"), functions)
            test_files = report["test_coupling"]["most_crosscutting_tests"]
            self.assertEqual(test_files[0]["dependency_count"], 2)
            self.assertTrue(report["report_sha256"])
            self.assertEqual(len(report["evidence_gaps"]), 2)

    def test_cycle_is_detected(self) -> None:
        with self._repo() as directory:
            root = Path(directory)
            self._init_repo(root)
            (root / "src" / "grabowski_a.py").write_text("import grabowski_b\n", encoding="utf-8")
            (root / "src" / "grabowski_b.py").write_text("import grabowski_a\n", encoding="utf-8")
            self._commit(root, "cycle")
            report = coupling.build_baseline(root, max_commits=10)
            self.assertEqual(report["largest_scc_size"], 2)
            self.assertEqual(report["cyclic_sccs"], [["grabowski_a", "grabowski_b"]])

    def test_report_digest_excludes_its_own_digest(self) -> None:
        with self._repo() as directory:
            root = Path(directory)
            self._init_repo(root)
            (root / "src" / "grabowski_a.py").write_text("VALUE = 1\n", encoding="utf-8")
            self._commit(root, "one")
            report = coupling.build_baseline(root, max_commits=1)
            digest = report.pop("report_sha256")
            self.assertEqual(digest, coupling.sha256_bytes(coupling.canonical_json(report)))

    def test_cli_output_is_valid_json(self) -> None:
        result = subprocess.run(
            ["python3", str(TOOL), "--repo", str(ROOT), "--max-commits", "5"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["kind"], "grabowski-coupling-baseline-v1")


if __name__ == "__main__":
    unittest.main()
