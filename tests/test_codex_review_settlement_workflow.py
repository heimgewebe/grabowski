from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "codex-review-settlement.yml"
REFRESH_WORKFLOW = (
    ROOT / ".github" / "workflows" / "codex-review-settlement-refresh.yml"
)


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

    def test_permissions_are_observer_only_except_status_publication(self) -> None:
        self.assertIn("  contents: read\n", self.text)
        self.assertIn("  issues: read\n", self.text)
        self.assertIn("  pull-requests: read\n", self.text)
        self.assertNotIn("  pull-requests: write\n", self.text)
        self.assertNotIn("  issues: write\n", self.text)
        self.assertIn("  statuses: write\n", self.text)
        self.assertNotIn("contents: write", self.text)

    def test_workflow_observes_only_and_never_posts_codex_request(self) -> None:
        self.assertNotIn("Request current-head Codex review", self.text)
        self.assertNotIn("request > codex-review-request.json", self.text)
        self.assertNotIn("@codex review", self.text)
        evaluate_section = self.text.split(
            "      - name: Evaluate current-head settlement\n", 1
        )[1].split("      - name: Publish settlement status\n", 1)[0]
        self.assertIn("tools/codex_review_settlement.py", evaluate_section)
        self.assertIn("--require", evaluate_section)
        self.assertIn("evaluate > codex-review-settlement.json", evaluate_section)

    def test_github_actions_issue_comments_do_not_retrigger_settlement(self) -> None:
        self.assertIn(
            "github.event.comment.user.login != 'github-actions[bot]'",
            self.text,
        )

    def test_concurrency_is_bound_to_pull_request_without_bot_special_case(self) -> None:
        concurrency = self.text.split("concurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn("github.event.pull_request.number", concurrency)
        self.assertIn("github.event.issue.number", concurrency)
        self.assertIn("inputs.pr", concurrency)
        self.assertIn("github.run_id", concurrency)
        self.assertNotIn("github.event.comment.user.login", concurrency)
        self.assertIn("cancel-in-progress: true", concurrency)

    def test_bootstrap_without_default_branch_evaluator_fails_explicitly(self) -> None:
        evaluate_section = self.text.split(
            "      - name: Evaluate current-head settlement\n", 1
        )[1].split("      - name: Publish settlement status\n", 1)[0]
        self.assertIn(
            "if [ ! -f tools/codex_review_settlement.py ]; then", evaluate_section
        )
        self.assertIn(
            "trusted_evaluator_missing_on_default_branch", evaluate_section
        )
        self.assertNotIn("github.event.pull_request.head", evaluate_section)

    def test_malformed_evaluator_output_becomes_explicit_failure(self) -> None:
        evaluate_section = self.text.split(
            "      - name: Evaluate current-head settlement\n", 1
        )[1].split("      - name: Publish settlement status\n", 1)[0]
        self.assertIn("if ! jq -e '", evaluate_section)
        self.assertIn("trusted_evaluator_output_invalid", evaluate_section)
        self.assertIn("codex-review-settlement.invalid.json", evaluate_section)
        self.assertIn("rc=2", evaluate_section)
        self.assertLess(
            evaluate_section.index("trusted_evaluator_output_invalid"),
            evaluate_section.index('echo "github_state=$github_state"'),
        )

    def test_status_is_diagnostic_and_exactly_named(self) -> None:
        self.assertGreaterEqual(self.text.count('context="Codex review settled"'), 2)
        self.assertIn("-f state=pending", self.text)
        self.assertIn('github_state="success"', self.text)
        self.assertIn('github_state="pending"', self.text)
        self.assertIn('github_state="failure"', self.text)
        self.assertIn(
            "Current-head Codex review requirement satisfied",
            self.text,
        )
        self.assertIn(
            "Connected user must request current-head Codex review",
            self.text,
        )
        self.assertNotIn("usage limit reached", self.text)

    def test_manual_dispatch_can_recheck_after_thread_resolution(self) -> None:
        self.assertIn("description: Pull request number", self.text)
        self.assertIn('if [ "$EVENT_NAME" = "workflow_dispatch" ]', self.text)
        self.assertIn('pr="$INPUT_PR"', self.text)
        evaluate_section = self.text.split(
            "      - name: Evaluate current-head settlement\n", 1
        )[1].split("      - name: Publish settlement status\n", 1)[0]
        self.assertIn("--require", evaluate_section)
        self.assertIn("evaluate > codex-review-settlement.json", evaluate_section)


class CodexReviewSettlementRefreshWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = REFRESH_WORKFLOW.read_text(encoding="utf-8")

    def test_refresh_is_scheduled_and_manually_dispatchable(self) -> None:
        self.assertIn("  schedule:\n", self.text)
        self.assertIn('    - cron: "*/15 * * * *"\n', self.text)
        self.assertIn("  workflow_dispatch:\n", self.text)

    def test_refresh_permissions_only_allow_trusted_dispatch(self) -> None:
        self.assertIn("  actions: write\n", self.text)
        self.assertIn("  contents: read\n", self.text)
        self.assertIn("  pull-requests: read\n", self.text)
        self.assertNotIn("  contents: write\n", self.text)
        self.assertNotIn("  issues: write\n", self.text)
        self.assertNotIn("  statuses: write\n", self.text)

    def test_refresh_does_not_checkout_or_execute_pull_request_code(self) -> None:
        self.assertNotIn("actions/checkout", self.text)
        self.assertNotIn("github.event.pull_request.head", self.text)
        self.assertNotIn("tools/codex_review_settlement.py", self.text)

    def test_refresh_bounds_open_pull_request_inventory(self) -> None:
        self.assertIn("gh pr list", self.text)
        self.assertIn("--state open", self.text)
        self.assertIn("--limit 101", self.text)
        self.assertIn('"${#pull_requests[@]}" -gt 100', self.text)
        self.assertIn("refusing a truncated refresh", self.text)

    def test_refresh_dispatches_default_branch_settlement_workflow(self) -> None:
        self.assertIn(
            "gh workflow run codex-review-settlement.yml", self.text
        )
        self.assertIn('--ref "$DEFAULT_BRANCH"', self.text)
        self.assertIn('-f "pr=$pr"', self.text)
        self.assertIn(
            "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
