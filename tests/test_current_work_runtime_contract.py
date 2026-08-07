from pathlib import Path
import sys
import unittest

from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_current_work as current_work  # noqa: E402
import grabowski_runtime  # noqa: E402


class CurrentWorkRuntimeContractTests(unittest.TestCase):
    def _tool(self):
        return grabowski_runtime.mcp._tool_manager._tools["grabowski_current_work"]

    def test_limit_bounds_are_published_in_the_tool_schema(self) -> None:
        limit_schema = self._tool().parameters["properties"]["limit"]

        self.assertEqual(20, limit_schema["default"])
        self.assertEqual(1, limit_schema["minimum"])
        self.assertEqual(current_work.PAGE_LIMIT_MAX, limit_schema["maximum"])

    def test_limit_bounds_are_validated_before_tool_execution(self) -> None:
        argument_model = self._tool().fn_metadata.arg_model
        repository = str(ROOT)

        valid = argument_model.model_validate(
            {"repositories": [repository], "limit": current_work.PAGE_LIMIT_MAX}
        )
        self.assertEqual(current_work.PAGE_LIMIT_MAX, valid.limit)

        for invalid in (0, current_work.PAGE_LIMIT_MAX + 1):
            with self.subTest(limit=invalid), self.assertRaises(ValidationError):
                argument_model.model_validate(
                    {"repositories": [repository], "limit": invalid}
                )


if __name__ == "__main__":
    unittest.main()
