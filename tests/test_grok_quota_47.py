"""Exact Grok 4.7 free-tier pre-result evidence, never a semantic PASS."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import test_decision_reviews as fixtures
import test_grok_quota_402 as legacy

COMMAND = ["grok", "--model", "grok-4.7", "-p", "Review the frozen revision"]
QUOTA = (
    "You’ve reached your free Grok Build usage limit for now. "
    "Get SuperGrok for much higher limits, or try again later: "
    "https://grok.com/supergrok?referrer=grok-build"
)
CWD = "/tmp/review"


def observed_events(message: str = QUOTA, cwd: str = CWD) -> list[dict]:
    return [
        {"type": "available_commands", "tools": [], "commands": legacy.COMMANDS},
        {"type": "available_commands", "tools": [], "commands": legacy.COMMANDS},
        {"type": "error", "message": message, "cwd": cwd},
    ]


def make_failed(jobs: Path, suffix: str = "a00000000407",
                *, events: list[dict] | None = None,
                stderr: str | None = None,
                updates: dict | None = None,
                raw: str | None = None) -> Path:
    directory = fixtures.make_job(
        jobs, suffix=suffix, slot="independent-grok",
        terminal_status="failed", review_result=None,
        review_role=True, attempt_bound=True, attempt_epoch=2,
        role_command_override=COMMAND, created_at_unix=1787000100,
    )
    # Reuse the production V2 role-receipt envelope fixture; override only
    # authenticated provider-output fields with observed Grok 4.7 raw bytes.
    legacy.amend_private_receipt(directory)
    path = directory / fixtures.reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
    receipt = json.loads(path.read_bytes())
    out = raw if raw is not None else "".join(
        json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n"
        for item in (events if events is not None else observed_events())
    )
    err = stderr if stderr is not None else "Error: " + QUOTA + "\n"
    output = out.encode("utf-8")
    error = err.encode("utf-8")
    receipt.update({
        "stdout_tail": out, "stdout_bytes": len(output),
        "stdout_sha256": hashlib.sha256(output).hexdigest(),
        "review_provider_stream_bytes": len(output),
        "review_provider_stream_sha256": hashlib.sha256(output).hexdigest(),
        "stderr_tail": err, "stderr_bytes": len(error),
        "stderr_sha256": hashlib.sha256(error).hexdigest(),
    })
    receipt.update(updates or {})
    receipt["receipt_sha256"] = fixtures.reviews._agent_role_receipt_sha256(receipt)
    fixtures.write_private(path, json.dumps(receipt))
    return directory


def reconcile(jobs: Path) -> dict:
    return fixtures.reviews.reconcile(
        repo=fixtures.REPO, pr=fixtures.PR,
        head_sha=fixtures.HEAD, base_sha=fixtures.BASE,
        diff_sha256=fixtures.DIFF, jobs_root=jobs,
    )


class Grok47QuotaTests(unittest.TestCase):
    def test_exact_authenticated_quota_is_pre_result_not_review_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_failed(jobs)
            result = reconcile(jobs)
            self.assertEqual(result["status"], "blocked")
            attempt = result["attempts"][0]
            self.assertEqual(attempt["classification"], "infrastructure_error", result["errors"])
            self.assertTrue(attempt["pre_result_quota_failure_verified"])
            self.assertIsNone(attempt["verdict"])
            self.assertEqual(result["slots"][0]["material_reject_count"], 0)
            # Optional exhausted provider is not an additional mandatory
            # reviewer; the original job stays in signed-history evidence.
            from grabowski_merge_guard import decision_review_blocking_errors
            optional = decision_review_blocking_errors(result, independent_required=False)
            self.assertEqual(optional["errors"], [])
            self.assertTrue(optional["ignored_unavailable"])
            required = decision_review_blocking_errors(result, independent_required=True)
            self.assertNotEqual(required["errors"], [])
            self.assertTrue(failed.exists())

    def test_quota_requires_a_later_authentic_same_slot_semantic_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_failed(jobs)
            fixtures.make_job(
                jobs, suffix="b00000000407", slot="independent-grok",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                role_command_override=COMMAND, created_at_unix=1787000200,
            )
            result = reconcile(jobs)
            self.assertEqual(result["status"], "settled", result["errors"])
            self.assertEqual(result["slots"][0]["infrastructure_error_count"], 1)
            self.assertEqual(result["slots"][0]["pass_count"], 1)

    def test_wrong_or_ambiguous_quota47_never_becomes_optional(self):
        altered = {
            "wrong_cwd": {"events": observed_events(cwd="/tmp/other-review")},
            "missing_cwd": {"events": observed_events()[:2] + [
                {"type": "error", "message": QUOTA},
            ]},
            "wrong_unicode_apostrophe": {"events": observed_events(
                message=QUOTA.replace("You’ve", "You've")
            )},
            "quota_message_edited": {"events": observed_events(
                message=QUOTA.replace("for now", "for this week")
            )},
            "missing_stderr_quota": {"stderr": "Error: usage unavailable\n"},
            "completed_tool": {"updates": {
                "review_provider_completed_tool_calls": 1,
            }},
            "bad_probe": {"updates": {
                "post_failure_toolchain_probe": {"passed": False},
            }},
            "unknown_command": {"events": [
                {"type": "available_commands", "tools": [],
                 "commands": [*legacy.COMMANDS, "developer-tools"]},
                *observed_events()[1:],
            ]},
            "extra_event": {"events": observed_events() + [
                {"type": "tool_call", "name": "terminal"},
            ]},
            "truncated_stream": {"raw": (
                json.dumps(observed_events()[0]) + "\n"
            )},
            "duplicate_json_key": {"raw": (
                json.dumps(observed_events()[0]) + "\n"
                + json.dumps(observed_events()[1]) + "\n"
                + '{"type":"error","message":'
                + json.dumps(QUOTA, ensure_ascii=False)
                + ',"cwd":"/tmp/review","cwd":"/tmp/review"}\n'
            )},
            "claimed_completed_document": {"updates": {
                "review_document_bytes": 42,
            }},
        }
        for name, kwargs in altered.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                make_failed(jobs, **kwargs)
                result = reconcile(jobs)
                self.assertEqual(result["status"], "blocked", name)
                self.assertEqual(result["attempts"][0]["classification"], "invalid_result", name)
                from grabowski_merge_guard import decision_review_blocking_errors
                optional = decision_review_blocking_errors(result, independent_required=False)
                self.assertTrue(optional["errors"], name)

    def test_wrong_model_route_never_validates_foreign_quota_message(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            directory = make_failed(jobs)
            # Preserve the exact bytes, but substitute only a legitimate
            # Grok 4.6 route and role command with a new authentic envelope.
            # The helper predicate must not confuse the two quota contracts.
            metadata, binding, origin = fixtures.reviews._validated_origin_binding(directory)
            receipt = json.loads(
                (directory / fixtures.reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME).read_bytes()
            )
            self.assertFalse(fixtures.reviews._proven_grok_quota_failure_before_review(
                receipt, {**origin, "review_route": {
                    **origin["review_route"], "route_id": "grok-4.6-review-high",
                }}
            ))


if __name__ == "__main__":
    unittest.main()
