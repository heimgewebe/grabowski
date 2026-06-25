from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PythonCompatibilityTests(unittest.TestCase):
    def test_project_declares_python_310_support(self) -> None:
        pyproject = (
            ROOT / "pyproject.toml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'requires-python = ">=3.10"',
            pyproject,
        )
        self.assertNotIn(
            'requires-python = ">=3.11"',
            pyproject,
        )

    def test_ci_proves_python_310_and_312(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "validate.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('- "3.10"', workflow)
        self.assertIn('- "3.12"', workflow)
        self.assertIn(
            "python-version: ${{ matrix.python-version }}",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
