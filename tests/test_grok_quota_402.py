"""Bounded V2 Grok 402 proof: no semantic review is never a PASS.

Fixtures use catalogue-bound independent reviewer origin, immutable job-finalization
and private role receipt. They do not make provider calls.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import test_decision_reviews as fixtures


GROK_COMMAND = ["grok", "--model", "grok-4.6", "-p", "Review the frozen revision"]
COMMANDS = ["compact", "always-approve", "context", "session-info", "feedback", "goal"]
COMMANDS_WITH_MEMORY = [*COMMANDS[:2], "memory", *COMMANDS[2:]]
QUOTA_MESSAGE = "API error (status 402 Payment Required): Grok Build usage balance exhausted"
INNER = '{\n  "message": "' + QUOTA_MESSAGE + '",\n  "http_status": 402\n}'
RECEIVER_ERROR = "Internal error: " + INNER
STDERR = "Error: " + RECEIVER_ERROR + "\n"


def payload(events=None):
    if events is None:
        events = [
            {"type": "available_commands", "tools": [], "commands": COMMANDS},
            {"type": "available_commands", "tools": [], "commands": COMMANDS},
            {"type": "error", "message": RECEIVER_ERROR},
        ]
    return "".join(json.dumps(event, separators=(",", ":")) + "\n" for event in events)


def amend_private_receipt(directory, receipt_updates=None, events=None, raw=None):
    path = directory / fixtures.reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
    receipt = json.loads(path.read_text(encoding="utf-8"))
    stdout = raw if raw is not None else payload(events)
    raw_bytes = stdout.encode("utf-8")
    err_bytes = STDERR.encode("utf-8")
    receipt.update({
        "verdict": "INVALID",
        "findings": [],
        "returncode": 126,
        "failure_classification": "invalid_review_output",
        "error": "Grok review stream used unsupported event type: error",
        "post_failure_toolchain_probe": {
            "passed": True, "failure_classification": "passed",
            "missing_executable": False, "missing_python_module": False,
        },
        "review_document_bytes": 0,
        "review_document_sha256": None,
        "review_document_normalizations": [],
        "review_findings_normalized": False,
        "review_input_source": "committed_diff",
        "review_input_bytes": 20162,
        "review_input_sha256": "e" * 64,
        "stdout_tail": stdout,
        "stdout_bytes": len(raw_bytes),
        "stdout_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "stderr_tail": STDERR,
        "stderr_bytes": len(err_bytes),
        "stderr_sha256": hashlib.sha256(err_bytes).hexdigest(),
        "review_provider_stream_contract": "grok-streaming-json-bound-diff-review-v2",
        "review_provider_stream_bytes": len(raw_bytes),
        "review_provider_stream_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "review_provider_stream_events": 3,
        "review_provider_available_commands_events": 0,
        "review_provider_available_tools": [],
        "review_provider_completed_commands": [],
        "review_provider_completed_tools": [],
        "review_provider_completed_tool_calls": 0,
    })
    receipt.update(receipt_updates or {})
    receipt["receipt_sha256"] = fixtures.reviews._agent_role_receipt_sha256(receipt)
    fixtures.write_private(path, json.dumps(receipt))


def make_grok_job(jobs, suffix, *, created, failed=False):
    directory = fixtures.make_job(
        jobs,
        suffix=suffix,
        slot="independent-grok",
        terminal_status="failed" if failed else "succeeded",
        review_result=None,
        review_role=True,
        attempt_bound=True,
        attempt_epoch=2,
        role_command_override=GROK_COMMAND,
        created_at_unix=created,
    )
    if failed:
        amend_private_receipt(directory)
    return directory


def reconcile(jobs):
    return fixtures.reviews.reconcile(
        repo=fixtures.REPO, pr=fixtures.PR,
        head_sha=fixtures.HEAD, base_sha=fixtures.BASE,
        diff_sha256=fixtures.DIFF, jobs_root=jobs,
    )


class GrokQuota402Tests(unittest.TestCase):
    def test_authenticated_exact_quota_stays_blocked_until_later_same_provider_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
            before = reconcile(jobs)
            self.assertEqual(before["status"], "blocked")
            self.assertEqual(before["attempts"][0]["classification"], "infrastructure_error")
            metadata, binding, origin = fixtures.reviews._validated_origin_binding(failed)
            evidence = fixtures.reviews._validated_review_role_evidence(metadata, binding, origin)
            self.assertIsNotNone(evidence)
            self.assertTrue(evidence["pre_result_quota_failure_verified"])
            self.assertEqual(before["slots"][0]["independent_pass_count"], 0)
            self.assertIn("decision_review_slot_without_pass:independent-grok", before["errors"])
            make_grok_job(jobs, "b00000000402", created=1787000200)
            after = reconcile(jobs)
            self.assertEqual(after["status"], "settled", after["errors"])
            self.assertEqual(after["errors"], [])
            self.assertEqual(after["slots"][0]["infrastructure_error_count"], 1)
            self.assertEqual(after["slots"][0]["independent_pass_count"], 1)
            self.assertTrue(failed.is_dir())

    def test_authentic_seven_command_pre_result_402_needs_later_xai_pass(self):
        """The observed 1593 CLI advertises memory in addition to six commands."""
        variant = [
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "error", "message": RECEIVER_ERROR},
        ]
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
            amend_private_receipt(failed, events=variant)
            before = reconcile(jobs)
            self.assertEqual(before["status"], "blocked")
            self.assertEqual(before["attempts"][0]["classification"], "infrastructure_error")
            metadata, binding, origin = fixtures.reviews._validated_origin_binding(failed)
            evidence = fixtures.reviews._validated_review_role_evidence(metadata, binding, origin)
            self.assertTrue(evidence["pre_result_quota_failure_verified"])
            self.assertEqual(before["slots"][0]["independent_pass_count"], 0)
            self.assertIn("decision_review_slot_without_pass:independent-grok", before["errors"])
            # Only a later authenticated reviewer from the same xAI slot can settle.
            make_grok_job(jobs, "b00000000402", created=1787000200)
            after = reconcile(jobs)
            self.assertEqual(after["status"], "settled", after["errors"])
            self.assertEqual(after["slots"][0]["infrastructure_error_count"], 1)
            self.assertEqual(after["slots"][0]["independent_pass_count"], 1)

    def test_seven_command_quota_rejects_unreviewed_command_drift(self):
        """Do not turn a narrow transport allowlist into a generic subset match."""
        original = [
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "error", "message": RECEIVER_ERROR},
        ]
        invalid = {
            "new_command": [*COMMANDS_WITH_MEMORY, "diagnostics"],
            "duplicate_memory": [*COMMANDS_WITH_MEMORY[:3], "memory", *COMMANDS_WITH_MEMORY[3:]],
            "reordered": ["memory", *COMMANDS],
            "missing_goal": COMMANDS_WITH_MEMORY[:-1],
            "unexpected_mixed_preflight": COMMANDS,
        }
        for name, commands in invalid.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                events = [dict(item) for item in original]
                events[0]["commands"] = commands
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
                amend_private_receipt(failed, events=events)
                make_grok_job(jobs, "b00000000402", created=1787000200)
                outcome = reconcile(jobs)
                self.assertEqual(outcome["status"], "blocked", name)
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a00000000402:InvalidReviewDocument",
                    outcome["errors"], name,
                )

    def test_seven_command_stream_rejects_extra_or_truncated_events(self):
        """The three-line guard also bounds the parsed event list itself.

        A claimed three-event role receipt cannot turn additional real
        model/tool/result events into a pre-result 402, nor may a truncated
        stream raise IndexError during reconciliation.
        """
        original = [
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "available_commands", "tools": [], "commands": COMMANDS_WITH_MEMORY},
            {"type": "error", "message": RECEIVER_ERROR},
        ]
        invalid = {
            "trailing_reject": original + [
                {"type": "result", "verdict": "REJECT_THIS_REVISION"}
            ],
            "trailing_tool": original + [{"type": "tool_call", "name": "terminal"}],
            "duplicate_error": original + [original[-1]],
            "trailing_thought": original + [{"type": "thought", "data": "analysis"}],
            "two_events": original[:2],
            "one_event": original[:1],
        }
        for name, events in invalid.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
                # Deliberately maintain the claimed provider event count=3
                # even when the authenticated stream bytes contain 1/2/4 events.
                amend_private_receipt(failed, events=events)
                make_grok_job(jobs, "b00000000402", created=1787000200)
                result = reconcile(jobs)
                self.assertEqual(result["status"], "blocked", name)
                self.assertEqual(result["attempts"][0]["classification"], "invalid_result", name)
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a00000000402:InvalidReviewDocument",
                    result["errors"], name,
                )
                self.assertTrue(failed.is_dir())

    def test_old_pass_or_different_provider_cannot_satisfy_latest_grok_quota(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_grok_job(jobs, "a00000000401", created=1787000000)
            make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
            fixtures.make_job(
                jobs, suffix="c00000000402", slot="independent-claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1787000200,
            )
            result = reconcile(jobs)
            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "decision_review_infrastructure_not_superseded:independent-grok:"
                "grabowski-job-a00000000402", result["errors"],
            )

    def test_material_reject_survives_quota_and_any_later_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
            reject = make_grok_job(jobs, "b00000000402", created=1787000200)
            path = reject / fixtures.reviews.REVIEW_ROLE_ATTEMPT_RECEIPT_NAME
            receipt = json.loads(path.read_text(encoding="utf-8"))
            receipt.update({
                "verdict": "BLOCK", "failure_classification": "review_verdict",
                "returncode": 0,
                "findings": [{
                    "severity": "P1", "path": "src/review.py", "line": 1,
                    "evidence": "adversarial material defect",
                    "impact": "unauthorized source trust",
                    "minimal_fix": "preserve material rejection",
                }],
            })
            receipt["receipt_sha256"] = fixtures.reviews._agent_role_receipt_sha256(receipt)
            fixtures.write_private(path, json.dumps(receipt))
            make_grok_job(jobs, "c00000000402", created=1787000300)
            result = reconcile(jobs)
            self.assertEqual(result["status"], "blocked")
            self.assertIn(
                "decision_review_material_reject:independent-grok:grabowski-job-b00000000402",
                result["errors"],
            )
            self.assertEqual(result["slots"][0]["material_reject_count"], 1)

    def test_no_free_text_or_partial_tool_event_can_claim_no_inference(self):
        original = json.loads(json.dumps([
            {"type": "available_commands", "tools": [], "commands": COMMANDS},
            {"type": "available_commands", "tools": [], "commands": COMMANDS},
            {"type": "error", "message": RECEIVER_ERROR},
        ]))
        invalid = {
            "text_before_error": original[:1] + [{"type": "text", "data": "REJECT"}] + original[1:],
            "thought_before_error": original[:2] + [{"type": "thought", "data": "consider"}] + original[2:],
            "tool_before_error": original[:1] + [{"type": "tool_call", "name": "use_tool"}] + original[1:],
            "end_after_error": original + [{"type": "end", "num_turns": 1}],
            "wrong_http": original[:2] + [{"type": "error", "message": RECEIVER_ERROR.replace("402", "401")}],
            "fake_reviewer_text": original[:2] + [{"type": "error", "message": "PASS_THIS_REVISION " + RECEIVER_ERROR}],
            "unexpected_field": original[:2] + [{"type": "error", "message": RECEIVER_ERROR, "result": "PASS"}],
            "advertised_tool": [{"type": "available_commands", "tools": ["terminal"], "commands": COMMANDS}] + original[1:],
            "command_drift": [{"type": "available_commands", "tools": [], "commands": ["different"]}] + original[1:],
            "missing_preflight": original[1:],
        }
        for name, events in invalid.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
                amend_private_receipt(failed, events=events)
                make_grok_job(jobs, "b00000000402", created=1787000200)
                out = reconcile(jobs)
                self.assertEqual(out["status"], "blocked", name)
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a00000000402:InvalidReviewDocument",
                    out["errors"], name,
                )

    def test_bytes_origin_role_and_signed_stream_controls_fail_closed(self):
        amendments = {
            "truncated_stdout": {"stdout_bytes": 1},
            "wrong_stdout_digest": {"stdout_sha256": "f" * 64},
            "wrong_stream_digest": {"review_provider_stream_sha256": "f" * 64},
            "wrong_stream_length": {"review_provider_stream_bytes": 1},
            "false_event_count": {"review_provider_stream_events": 4},
            "float_event_count": {"review_provider_stream_events": 3.0},
            "float_returncode": {"returncode": 126.0},
            "boolean_document_bytes": {"review_document_bytes": False},
            "float_document_bytes": {"review_document_bytes": 0.0},
            "completed_tool": {"review_provider_completed_tool_calls": 1},
            "tool_catalog": {"review_provider_available_tools": ["terminal"]},
            "document": {"review_document_bytes": 1},
            "normalized_finding": {"review_findings_normalized": True},
            "semantic_finding": {"findings": [{"severity": "P1"}]},
            "successful_exit": {"returncode": 0},
            "wrong_stderr_digest": {"stderr_sha256": "a" * 64},
            "changed_stderr": {"stderr_tail": STDERR + "extra"},
        }
        for name, amendment in amendments.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
                amend_private_receipt(failed, receipt_updates=amendment)
                make_grok_job(jobs, "b00000000402", created=1787000200)
                result = reconcile(jobs)
                self.assertEqual(result["status"], "blocked", name)
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a00000000402:InvalidReviewDocument",
                    result["errors"], name,
                )

    def test_duplicate_json_member_is_never_accepted_as_quota_proof(self):
        original = payload()
        # These duplicate members MUST parse as the accepted quota stream under
        # last-member-wins json.loads. The security test would fail if the
        # duplicate-rejection hook were ever removed.
        variants = {
            "error_type": original.replace(
                '{"type":"error","message":',
                '{"type":"text","type":"error","message":',
            ),
            "command_tools": original.replace(
                '"tools":[]', '"tools":["terminal"],"tools":[]', 1,
            ),
            "command_list": original.replace(
                '"commands":', '"commands":["untrusted"],"commands":', 1,
            ),
        }
        accepted_without_duplicate_protection = [
            json.loads(line) for line in original.splitlines()
        ]
        for name, raw in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                self.assertNotEqual(raw, original)
                self.assertEqual(
                    [json.loads(line) for line in raw.splitlines()],
                    accepted_without_duplicate_protection,
                    "The negative test must distinguish duplicate-key rejection",
                )
                jobs = Path(temp) / "jobs"
                jobs.mkdir(mode=0o700)
                failed = make_grok_job(jobs, "a00000000402", created=1787000100, failed=True)
                amend_private_receipt(failed, raw=raw)
                make_grok_job(jobs, "b00000000402", created=1787000200)
                result = reconcile(jobs)
                self.assertEqual(result["status"], "blocked", name)
                self.assertIn(
                    "decision_review_result_invalid:grabowski-job-a00000000402:InvalidReviewDocument",
                    result["errors"], name,
                )

    def test_wrong_provider_family_is_not_recognized_as_grok_quota(self):
        with tempfile.TemporaryDirectory() as temp:
            jobs = Path(temp) / "jobs"
            jobs.mkdir(mode=0o700)
            failed = fixtures.make_job(
                jobs, suffix="a00000000402", slot="independent-claude",
                terminal_status="failed", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1787000100,
            )
            amend_private_receipt(failed)
            fixtures.make_job(
                jobs, suffix="b00000000402", slot="independent-claude",
                terminal_status="succeeded", review_result=None,
                review_role=True, attempt_bound=True, attempt_epoch=2,
                created_at_unix=1787000200,
            )
            result = reconcile(jobs)
            self.assertEqual(result["status"], "blocked")
            self.assertTrue(any("decision_review_result_invalid" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()