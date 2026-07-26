from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "codex-review-settlement.yml"


class CodexReviewSettlementWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_uses_only_supported_pull_request_action_events(self) -> None:
        self.assertIn("  pull_request_target:\n", self.text)
        self.assertIn("  pull_request_review:\n", self.text)
        self.assertIn("  pull_request_review_comment:\n", self.text)
        self.assertIn("  issue_comment:\n", self.text)
        self.assertIn("  workflow_dispatch:\n", self.text)
        self.assertNotIn("pull_request_review_thread:", self.text)
        self.assertNotIn("  schedule:\n", self.text)

    def test_uses_trusted_default_branch_evaluator(self) -> None:
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            self.text,
        )
        self.assertNotIn("actions/checkout@v", self.text)
        self.assertNotIn("github.event.pull_request.head", self.text)

    def test_permissions_are_bounded_to_review_status_workflow(self) -> None:
        self.assertIn("  contents: read\n", self.text)
        self.assertIn("  issues: write\n", self.text)
        self.assertIn("  pull-requests: read\n", self.text)
        self.assertIn("  statuses: write\n", self.text)
        self.assertNotIn("contents: write", self.text)

    def test_every_supported_event_can_create_idempotent_request(self) -> None:
        request_section = self.text.split(
            "      - name: Request current-head Codex review\n", 1
        )[1].split("      - name: Evaluate current-head settlement\n", 1)[0]
        self.assertNotIn("        if:", request_section)
        self.assertIn("tools/codex_review_settlement.py", request_section)
        self.assertIn("request > codex-review-request.json", request_section)

    def test_status_is_diagnostic_and_exactly_named(self) -> None:
        self.assertGreaterEqual(self.text.count('context="Codex review settled"'), 2)
        self.assertIn("-f state=pending", self.text)
        self.assertIn('github_state="success"', self.text)
        self.assertIn('github_state="pending"', self.text)
        self.assertIn('github_state="failure"', self.text)

    def test_manual_dispatch_can_recheck_after_thread_resolution(self) -> None:
        self.assertIn("description: Pull request number", self.text)
        self.assertIn('if [ "$EVENT_NAME" = "workflow_dispatch" ]', self.text)
        self.assertIn('pr="$INPUT_PR"', self.text)
        self.assertIn("evaluate > codex-review-settlement.json", self.text)


if __name__ == "__main__":
    unittest.main()
