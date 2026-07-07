from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "autonomy.md"


class AutonomyDoctrineDocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")

    def test_grip_oriented_autonomy_terms_are_present(self) -> None:
        for phrase in (
            "Grabowski darf eigenständig handeln, wenn Ziel, Target, Scope, Risiko und",
            "Autonomie bedeutet hier nicht unbegrenzte",
            "Normale Mechanic-Arbeit",
            "High-impact-Arbeit ist nicht pauschal verboten",
            "bestandenes Preflight-Gate ist keine Ausführung",
        ):
            self.assertIn(phrase, self.text)

    def test_organs_are_helpers_not_universal_gates(self) -> None:
        for organ in ("Bureau", "Cabinet", "Chronik", "Plexer", "Lenskit", "Vibe-Lab"):
            self.assertIn(organ, self.text)
        for phrase in (
            "Hilfsorgane mit",
            "keine Freigabeinstanzen",
            "keine High-impact-Aktion",
            "automatisch freigeben",
        ):
            self.assertIn(phrase, self.text)


if __name__ == "__main__":
    unittest.main()
