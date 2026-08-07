import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src" / "grabowski_runtime.py"


class CurrentWorkRuntimeContractTests(unittest.TestCase):
    def _runtime_module(self) -> ast.Module:
        return ast.parse(RUNTIME.read_text(encoding="utf-8"))

    def _current_work_function(self) -> ast.AsyncFunctionDef:
        function = next(
            node
            for node in self._runtime_module().body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "grabowski_current_work"
        )
        return function

    def test_limit_bounds_are_declared_on_the_public_tool_parameter(self) -> None:
        function = self._current_work_function()
        arguments = {argument.arg: argument for argument in function.args.args}
        limit = arguments["limit"]

        self.assertIsInstance(limit.annotation, ast.Subscript)
        annotated = limit.annotation
        self.assertIsInstance(annotated.value, ast.Name)
        self.assertEqual("Annotated", annotated.value.id)
        self.assertIsInstance(annotated.slice, ast.Tuple)
        base_type, field = annotated.slice.elts
        self.assertIsInstance(base_type, ast.Name)
        self.assertEqual("int", base_type.id)
        self.assertIsInstance(field, ast.Call)
        self.assertIsInstance(field.func, ast.Name)
        self.assertEqual("Field", field.func.id)

        keywords = {keyword.arg: keyword.value for keyword in field.keywords}
        self.assertEqual(1, ast.literal_eval(keywords["ge"]))
        self.assertIsInstance(keywords["le"], ast.Attribute)
        self.assertEqual("PAGE_LIMIT_MAX", keywords["le"].attr)
        self.assertIsInstance(keywords["le"].value, ast.Name)
        self.assertEqual("grabowski_current_work_model", keywords["le"].value.id)

        names = [argument.arg for argument in function.args.args]
        defaults = dict(zip(names[-len(function.args.defaults):], function.args.defaults))
        self.assertEqual(20, ast.literal_eval(defaults["limit"]))

    def test_runtime_imports_the_canonical_current_work_limit_source(self) -> None:
        imports = [
            alias
            for node in self._runtime_module().body
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        self.assertTrue(
            any(
                alias.name == "grabowski_current_work"
                and alias.asname == "grabowski_current_work_model"
                for alias in imports
            )
        )


if __name__ == "__main__":
    unittest.main()
