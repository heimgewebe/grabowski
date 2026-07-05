from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import pr_review_gate


class GripGatePathTests(unittest.TestCase):
    def test_grip_module_path_is_classified_for_extra_review(self) -> None:
        path = "src/" + "grabowski_grips.py"
        self.assertTrue(pr_review_gate._is_risk_path(path))


if __name__ == "__main__":
    unittest.main()
