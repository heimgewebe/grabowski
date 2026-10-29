"""Origin-bound historical Grok 402 is infrastructure only before inference.

Synthetic replay of the exact fixed three-event provider stream.  A real
semantic REJECT, unknown stream shape or tool execution remains blocking.
"""
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import test_decision_reviews as fixtures
import grabowski_decision_reviews as reviews
import grabowski_merge_guard as merge_guard


COMMANDS = [
    "compact", "always-approve", "context", "session-info",
    "feedback", "goal",
]
ERROR_MESSAGE = (
    "API error (status 402 Payment Required): "
    "Grok Build usage balance exhausted"
)
WRAPPED = (
    'Internal error: {\n  "message": "' + ERROR_MESSAGE
    + '",\n  "http_status": 402\n}'
)


def stamp_grok_quota(directory: Path, *, updates: dict | None = None,
                     commands: list[str] | None = None) -> None:
    path = directory / reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
    receipt = json.loads(path.read_text(encoding="utf-8"))
    chosen_commands = COMMANDS if commands is None else commands
    events = [
        {"type": "available_commands", "tools": [], "commands": chosen_commands},
        {"type": "available_commands", "tools": [], "commands": chosen_commands},
        {"type": "error", "message": WRAPPED},
    ]
    stdout = "".join(
        json.dumps(event, separators=(",", ":")) + "\n" for event in events
    )
    stderr = "Error: " + WRAPPED + "\n"
    stdout_digest = hashlib.sha256(stdout.encode("utf-8")).hexdigest()
    receipt.update({
        "verdict": "INVALID", "findings": [], "returncode": 126,
        "failure_classification": "invalid_review_output",
        "error": "Grok review stream used unsupported event type: error",
        "review_document_bytes": 0, "review_document_sha256": None,
        "review_document_normalizations": [],
        "review_findings_normalized": False,
        "review_input_source": "committed_diff",
        "review_input_bytes": 12, "review_input_sha256": "e" * 64,
        "post_failure_toolchain_probe": {
            "passed": True, "failure_classification": "passed",
            "missing_executable": False, "missing_python_module": False,
        },
        "review_provider_stream_contract": "grok-streaming-json-bound-diff-review-v2",
        "review_provider_stream_events": 3,
        "review_provider_available_commands_events": 0,
        "review_provider_available_tools": [],
        "review_provider_completed_commands": [],
        "review_provider_completed_tool_calls": 0,
        "review_provider_completed_tools": [],
        "review_provider_stream_bytes": len(stdout.encode("utf-8")),
        "review_provider_stream_sha256": stdout_digest,
        "stdout_tail": stdout,
        "stdout_bytes": len(stdout.encode("utf-8")),
        "stdout_sha256": stdout_digest,
        "stderr_tail": stderr,
        "stderr_bytes": len(stderr.encode("utf-8")),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
    })
    receipt.update(updates or {})
    receipt["receipt_sha256"] = reviews._agent_role_receipt_sha256(receipt)
    fixtures.write_private(path, json.dumps(receipt))


class HistoricalGrokPreResultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.jobs = Path(self.temporary.name) / "jobs"
        self.jobs.mkdir(mode=0o700)

    def grok(self):
        directory = fixtures.make_job(
            self.jobs, suffix="a88888888888", slot="independent-grok",
            terminal_status="failed", review_result=None,
            review_role=True, attempt_bound=True, attempt_epoch=2,
            role_command_override=[
                "grok", "--model", "grok-4.6", "-p", "Read-only frozen revision review",
            ],
        )
        stamp_grok_quota(directory)
        return directory

    def reconcile(self):
        return reviews.reconcile(
            repo=fixtures.REPO, pr=fixtures.PR, head_sha=fixtures.HEAD,
            base_sha=fixtures.BASE, diff_sha256=fixtures.DIFF, jobs_root=self.jobs,
        )

    def test_authenticated_grok_402_before_inference_is_not_a_pass(self):
        self.grok()
        result = self.reconcile()
        self.assertEqual(result["attempt_count"], 1)
        attempt = result["attempts"][0]
        self.assertEqual(attempt["classification"], "infrastructure_error")
        self.assertTrue(attempt["pre_result_quota_failure_verified"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["slots"][0]["independent_pass_count"], 0)
        optional = merge_guard.decision_review_blocking_errors(
            result, independent_required=False,
        )
        self.assertEqual(optional["status"], "optional_unavailable")
        self.assertEqual(optional["errors"], [])

    def test_grok_pre_result_near_misses_cannot_erase_review_debt(self):
        near_misses = (
            {"review_document_bytes": 1},
            {"review_provider_stream_events": 2},
            {"review_provider_completed_tool_calls": 1},
            {"post_failure_toolchain_probe": {"passed": False}},
            {"stdout_tail": "REJECT_THIS_REVISION"},
            {"stderr_tail": "Error: unknown\n"},
        )
        for override in near_misses:
            with self.subTest(override=override):
                if self.jobs.exists():
                    for child in self.jobs.iterdir():
                        import shutil
                        shutil.rmtree(child)
                directory = self.grok()
                stamp_grok_quota(directory, updates=override)
                outcome = self.reconcile()
                self.assertEqual(outcome["status"], "blocked")
                self.assertEqual(
                    outcome["attempts"][0]["classification"], "invalid_result",
                )
                optional = merge_guard.decision_review_blocking_errors(
                    outcome, independent_required=False,
                )
                self.assertNotEqual(optional["errors"], [])

    def test_actual_historical_material_reject_remains_blocking(self):
        self.grok()
        fixtures.make_job(
            self.jobs, suffix="b99999999999", slot="independent-other",
            terminal_status="succeeded",
            review_result=fixtures.result(
                "independent-other", "REJECT_THIS_REVISION", 1,
            ),
        )
        reconciled = self.reconcile()
        optional = merge_guard.decision_review_blocking_errors(
            reconciled, independent_required=False,
        )
        self.assertEqual(optional["status"], "blocked")
        self.assertTrue(any(
            error.startswith("decision_review_material_reject:")
            for error in optional["errors"]
        ))


if __name__ == "__main__":
    unittest.main()
