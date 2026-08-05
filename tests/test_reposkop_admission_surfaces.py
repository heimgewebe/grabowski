from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class ReposkopAdmissionSurfaceTests(unittest.TestCase):
    def test_agent_workspace_admission_requires_reposkop(self) -> None:
        tree = ast.parse(
            (SRC / "grabowski_agent_workspace.py").read_text(encoding="utf-8")
        )
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_assess_new_agent_workspace"
        ]
        self.assertEqual(len(functions), 1)
        calls = [
            node
            for node in ast.walk(functions[0])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "require_repository_admission"
        ]
        self.assertEqual(len(calls), 1)
        keywords = {item.arg: item.value for item in calls[0].keywords}
        value = keywords.get("reposkop_required")
        self.assertIsInstance(value, ast.Constant)
        self.assertIs(value.value, True)

    def test_task_start_attests_before_launch_and_persists_binding(self) -> None:
        source = (SRC / "grabowski_tasks.py").read_text(encoding="utf-8")
        start = source.index("def grabowski_task_start(")
        end = source.index("\n\n@_serialize_task_mutation\ndef grabowski_task_status", start)
        function = source[start:end]
        self.assertLess(
            function.index("_attest_mutating_agent_workspace("),
            function.index("_launch(record)"),
        )
        self.assertIn("reposkop_execution_attestation", function)
        self.assertIn("resources._release_lease_snapshot(item)", function)

    def test_future_work_acquire_surface_must_require_reposkop(self) -> None:
        path = SRC / "grabowski_work_acquire.py"
        if not path.exists():
            self.skipTest("work-acquire surface is not present on this revision")
        source = path.read_text(encoding="utf-8")
        self.assertIn(
            "reposkop_required=True",
            source,
            "work-acquire must not create a productive worktree without Reposkop",
        )


if __name__ == "__main__":
    unittest.main()
