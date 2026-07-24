from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "blocked-action-protocol-v0.md"


class BlockedActionProtocolDocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = DOC.read_text(encoding="utf-8")

    def test_core_contract_terms_are_present(self) -> None:
        self.assertTrue(DOC.is_file())
        for phrase in (
            "# Blocked Action Protocol v0",
            "ChatGPT bleibt der Operator",
            "Micro-Handoff",
            "Receipt Contract",
            "Does not establish",
        ):
            self.assertIn(phrase, self.text)

    def test_control_loop_keeps_grabowski_close_to_operation(self) -> None:
        self.assertLess(
            self.text.index("**Typed Grabowski Tool**"),
            self.text.index("**Grabowski Micro-Task**"),
        )
        self.assertLess(
            self.text.index("**Grabowski Micro-Task**"),
            self.text.index("**Receipt before next step**"),
        )
        self.assertIn("Danach sind `task_status` und `task_logs` Pflicht.", self.text)
        self.assertIn("Danach wird nach Aufgabenklasse geroutet.", self.text)

    def test_routing_roles_match_live_operator_protocol(self) -> None:
        for phrase in (
            "ChatGPT Operator",
            "Standard fuer alle Lanes",
            "standardmaessig aus",
            "keine Kopien dieses ChatGPT-Kontexts",
            "Claude -> Codex -> Antigravity -> OpenCode -> OpenHands -> Cline",
            "Cline",
            "`agy --print` (Antigravity CLI)",
            "Ollama API mit qwen coder",
            "tmux ist Standard",
            "bounded Patch-Fallback",
            "operator_patch_relay.py",
            "manueller Patchdownload durch den Nutzer ist nur der letzte Notausgang",
        ):
            self.assertIn(phrase, self.text)
        for stale_phrase in (
            "Codex Once",
            "Beste Wahl fuer kleine Repo-Code-Slices",
            "Antigravity / tmux Session",
            "Lokale KI / Goose / Ollama / Aider",
        ):
            self.assertNotIn(stale_phrase, self.text)

    def test_resume_requires_evidence_before_next_step(self) -> None:
        for phrase in (
            "Ohne Receipt darf kein Folgeschritt angenommen werden.",
            "`task_status` plus `task_logs`",
            "Git-Status plus Diff",
            "Testausgabe",
            "PR-Checks",
        ):
            self.assertIn(phrase, self.text)

    def test_resource_key_examples_are_documented(self) -> None:
        for phrase in (
            "`repo:/home/alex/repos/name`",
            "`path:/home/alex/repos/name/subpath`",
            "`service:unit.service`",
            "`port:18181`",
            "Freie Fantasietypen sind ungueltig.",
        ):
            self.assertIn(phrase, self.text)


if __name__ == "__main__":
    unittest.main()
