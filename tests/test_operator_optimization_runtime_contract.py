import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "src" / "grabowski_runtime.py"


class OperatorOptimizationRuntimeContractTests(unittest.TestCase):
    def _function(self) -> ast.AsyncFunctionDef:
        module = ast.parse(RUNTIME.read_text(encoding="utf-8"))
        return next(
            node
            for node in module.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "grabowski_operator_optimization_report"
        )

    def test_integer_limits_publish_server_bounds(self) -> None:
        function = self._function()
        arguments = {argument.arg: argument for argument in function.args.args}
        names = [argument.arg for argument in function.args.args]
        defaults = dict(zip(names[-len(function.args.defaults) :], function.args.defaults))
        expected = {
            "top_limit": (10, "MAX_TOP_LIMIT"),
            "friction_limit": (100, "MAX_FRICTION_LIMIT"),
            "outcome_limit": (200, "MAX_OUTCOME_LIMIT"),
            "current_work_limit": (50, "MAX_CURRENT_WORK_LIMIT"),
        }

        for name, (default, maximum_name) in expected.items():
            with self.subTest(parameter=name):
                annotation = arguments[name].annotation
                self.assertIsInstance(annotation, ast.Subscript)
                self.assertIsInstance(annotation.value, ast.Name)
                self.assertEqual("Annotated", annotation.value.id)
                self.assertIsInstance(annotation.slice, ast.Tuple)
                base_type, field = annotation.slice.elts
                self.assertIsInstance(base_type, ast.Name)
                self.assertEqual("int", base_type.id)
                self.assertIsInstance(field, ast.Call)
                self.assertIsInstance(field.func, ast.Name)
                self.assertEqual("Field", field.func.id)

                keywords = {keyword.arg: keyword.value for keyword in field.keywords}
                self.assertEqual(1, ast.literal_eval(keywords["ge"]))
                self.assertIsInstance(keywords["le"], ast.Attribute)
                self.assertEqual(maximum_name, keywords["le"].attr)
                self.assertIsInstance(keywords["le"].value, ast.Name)
                self.assertEqual(
                    "grabowski_operator_optimization", keywords["le"].value.id
                )
                self.assertEqual(default, ast.literal_eval(defaults[name]))


if __name__ == "__main__":
    unittest.main()
