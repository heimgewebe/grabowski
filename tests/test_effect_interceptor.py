from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_effect_interceptor as interceptor


class Context:
    client_id = "connector-instance-1"


class EffectInterceptorTests(unittest.TestCase):
    def transport(self):
        return {
            "runtime_binding_sha256": "a" * 64,
            "consumption_receipt_sha256": "b" * 64,
        }

    def test_admission_binds_transport_actor_lane_and_resources(self) -> None:
        admission = interceptor.admit_mutation(
            tool_name="grabowski_git",
            arguments={
                "lane_id": "lane-1",
                "repo": "/tmp/repo",
                "path": "/tmp/repo/file.py",
                "resource_keys": ["path:/tmp/repo/file.py"],
            },
            transport_evidence=self.transport(),
            context=Context(),
        )
        self.assertEqual(admission["lane_id"], "lane-1")
        self.assertRegex(admission["actor_id"], r"^client:[0-9a-f]{64}$")
        self.assertEqual(admission["transport_receipt_sha256"], "b" * 64)
        self.assertRegex(admission["resource_set_sha256"], r"^[0-9a-f]{64}$")

    def test_explicit_actor_precedes_context_identity(self) -> None:
        admission = interceptor.admit_mutation(
            tool_name="grabowski_git",
            arguments={"actor_id": "controller:chatgpt", "task_id": "t-1"},
            transport_evidence=self.transport(),
            context=Context(),
        )
        self.assertEqual(admission["actor_id"], "controller:chatgpt")
        self.assertEqual(admission["lane_id"], "task:t-1")

    def test_unlabeled_context_is_explicit(self) -> None:
        self.assertEqual(interceptor.actor_id({}, None), "shared_unlabeled")
        self.assertEqual(interceptor.lane_id({}), "unbound")

    def test_success_classification_distinguishes_deduplication_and_receipts(self) -> None:
        self.assertEqual(
            interceptor.success_completion_class({"deduplicated": True}),
            "deduplicated",
        )
        self.assertEqual(
            interceptor.success_completion_class(
                {
                    "deduplicated_reuse": {
                        "reused": True,
                        "task_id": "task-1",
                        "reason": "active_execution_identity",
                    }
                }
            ),
            "deduplicated",
        )
        self.assertEqual(
            interceptor.success_completion_class({"receipt_sha256": "c" * 64}),
            "effect_observed",
        )
        self.assertEqual(interceptor.success_completion_class({"ok": True}), "succeeded")

    def test_deduplicated_reuse_requires_positive_documented_signal(self) -> None:
        for negative in (
            None,
            False,
            0,
            "",
            [],
            {},
            True,
            {"reused": False},
            {"reused": 1},
            {"task_id": "task-1"},
        ):
            with self.subTest(negative=negative):
                self.assertEqual(
                    interceptor.success_completion_class(
                        {"ok": True, "deduplicated_reuse": negative}
                    ),
                    "succeeded",
                )
        self.assertEqual(
            interceptor.success_completion_class({"deduplicated": False}),
            "succeeded",
        )
        self.assertEqual(
            interceptor.success_completion_class({"deduplicated": 1}),
            "succeeded",
        )
        self.assertTrue(
            interceptor._positive_deduplicated_reuse({"reused": True})
        )
        self.assertFalse(interceptor._positive_deduplicated_reuse(None))
        self.assertFalse(interceptor._positive_deduplicated_reuse(False))
        self.assertFalse(interceptor._positive_deduplicated_reuse({}))

    def test_success_and_exception_are_audit_bound(self) -> None:
        records = []
        admission = interceptor.admit_mutation(
            tool_name="grabowski_git",
            arguments={},
            transport_evidence=self.transport(),
            append_audit=lambda record: records.append(record) or "d" * 64,
        )
        success = interceptor.record_success(
            admission,
            {"receipt_sha256": "e" * 64, "post_state": {"head": "abc"}},
            append_audit=lambda record: records.append(record) or "f" * 64,
        )
        self.assertEqual(success["completion_class"], "effect_observed")
        self.assertTrue(success["post_state_observed"])
        failure = interceptor.record_exception(
            admission,
            RuntimeError("lost response"),
            append_audit=lambda record: records.append(record) or "1" * 64,
        )
        self.assertEqual(failure["completion_class"], "outcome_unknown")
        self.assertEqual(
            [record["operation"] for record in records],
            ["effect-admission", "effect-completion", "effect-completion"],
        )

    def test_completion_record_failure_does_not_replace_domain_result(self) -> None:
        admission = interceptor.admit_mutation(
            tool_name="grabowski_git",
            arguments={},
            transport_evidence=self.transport(),
        )
        errors = []
        result = interceptor.record_success_best_effort(
            admission,
            {"ok": True},
            append_audit=lambda _record: (_ for _ in ()).throw(
                RuntimeError("audit unavailable")
            ),
            on_error=errors.append,
        )
        self.assertIsNone(result)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], RuntimeError)

    def test_missing_transport_receipt_fails_before_admission(self) -> None:
        with self.assertRaisesRegex(ValueError, "consumption receipt"):
            interceptor.admit_mutation(
                tool_name="grabowski_git",
                arguments={},
                transport_evidence={"runtime_binding_sha256": "a" * 64},
            )


if __name__ == "__main__":
    unittest.main()
