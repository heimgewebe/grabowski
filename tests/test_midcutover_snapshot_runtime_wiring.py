from __future__ import annotations

import ast
from pathlib import Path
import unittest


SOURCE_PATH = Path(__file__).resolve().parents[1] / "tools/deploy_runtime_dual.py"


def _tree() -> ast.Module:
    return ast.parse(SOURCE_PATH.read_text(encoding="utf-8"), filename=str(SOURCE_PATH))


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")


def _method(tree: ast.AST, class_name: str, method_name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"method {class_name}.{method_name} not found")


def _matching_calls(node: ast.AST, attribute: str) -> list[ast.Call]:
    return [
        item
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == attribute
    ]


def _assert_inspector(test: unittest.TestCase, call: ast.Call) -> None:
    keywords = {item.arg: item.value for item in call.keywords if item.arg is not None}
    test.assertIn("snapshot_inspector", keywords)
    value = keywords["snapshot_inspector"]
    test.assertIsInstance(value, ast.Attribute)
    test.assertEqual(value.attr, "inspect_cutover_snapshot_binding")
    test.assertIsInstance(value.value, ast.Name)
    test.assertEqual(value.value.id, "client_snapshot")


class MidCutoverSnapshotRuntimeWiringTests(unittest.TestCase):
    def test_rebind_readback_injects_canonical_inspector(self) -> None:
        method = _method(_tree(), "MidCutoverResumeRuntime", "rebind_snapshot")
        calls = _matching_calls(method, "observe_client_snapshot_binding")
        self.assertEqual(len(calls), 1)
        _assert_inspector(self, calls[0])

    def test_cold_observation_injects_canonical_inspector(self) -> None:
        method = _method(_tree(), "MidCutoverResumeRuntime", "cold_snapshot_observation")
        calls = _matching_calls(method, "observe_client_snapshot_binding")
        self.assertEqual(len(calls), 1)
        _assert_inspector(self, calls[0])

    def test_classifier_injects_canonical_inspector(self) -> None:
        function = _function(_tree(), "classify_midcutover_resume")
        calls = _matching_calls(function, "classify_from_durable_state")
        self.assertEqual(len(calls), 1)
        _assert_inspector(self, calls[0])


if __name__ == "__main__":
    unittest.main()
