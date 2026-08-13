from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


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

    def test_explicit_lane_precedes_implicit_resolution(self) -> None:
        def unexpected_inspect(_resource_key):
            raise AssertionError("implicit resource inspection must not run")

        self.assertEqual(
            interceptor.lane_id(
                {"lane_id": "explicit-lane", "path": "/tmp/work/file.py"},
                resource_inspector=unexpected_inspect,
                lane_inputs_reader=lambda _lane: {},
            ),
            "explicit-lane",
        )

    def test_implicit_lane_resolves_from_verified_ancestor_path_lease(self) -> None:
        lane = "a" * 32
        workspace = "/tmp/grabowski-lane-a"
        lease_key = f"path:{workspace}"

        def inspect(resource_key):
            if resource_key == lease_key:
                return {
                    "resource_key": lease_key,
                    "owner_id": f"lane:{lane}",
                }
            return None

        def read_lane(observed_lane):
            self.assertEqual(observed_lane, lane)
            return {
                "lane_id": lane,
                "lease_owner_id": f"lane:{lane}",
                "resource_keys": [lease_key],
            }

        self.assertEqual(
            interceptor.lane_id(
                {"path": f"{workspace}/src/module.py"},
                resource_inspector=inspect,
                lane_inputs_reader=read_lane,
            ),
            lane,
        )

    def test_composite_explicit_repo_resource_does_not_create_path_alias(self) -> None:
        composite = "repo:/tmp/repo:operation:review:lane-example"
        observed: list[str] = []

        def inspect(resource_key):
            observed.append(resource_key)
            return None

        self.assertEqual(
            interceptor.lane_id(
                {"resource_keys": [composite]},
                resource_inspector=inspect,
                lane_inputs_reader=lambda _lane: {},
            ),
            "unbound",
        )
        self.assertIn(composite, observed)
        self.assertNotIn("path:/tmp/repo:operation:review:lane-example", observed)

    def test_repo_workspace_resolves_through_its_lane_path_lease(self) -> None:
        lane = "b" * 32
        workspace = "/tmp/grabowski-lane-b"
        lease_key = f"path:{workspace}"

        def inspect(resource_key):
            return (
                {"resource_key": lease_key, "owner_id": f"lane:{lane}"}
                if resource_key == lease_key
                else None
            )

        self.assertEqual(
            interceptor.lane_id(
                {"repo": workspace},
                resource_inspector=inspect,
                lane_inputs_reader=lambda observed_lane: {
                    "lane_id": observed_lane,
                    "lease_owner_id": f"lane:{observed_lane}",
                    "resource_keys": [lease_key],
                },
            ),
            lane,
        )

    def test_implicit_lane_fails_closed_on_missing_or_unbound_receipt(self) -> None:
        lane = "c" * 32
        workspace = "/tmp/grabowski-lane-c"
        lease_key = f"path:{workspace}"

        def inspect(resource_key):
            return (
                {"resource_key": lease_key, "owner_id": f"lane:{lane}"}
                if resource_key == lease_key
                else None
            )

        self.assertEqual(
            interceptor.lane_id(
                {"path": f"{workspace}/file.py"},
                resource_inspector=inspect,
                lane_inputs_reader=lambda _lane: (_ for _ in ()).throw(
                    RuntimeError("missing lane receipt")
                ),
            ),
            "unbound",
        )
        self.assertEqual(
            interceptor.lane_id(
                {"path": f"{workspace}/file.py"},
                resource_inspector=inspect,
                lane_inputs_reader=lambda observed_lane: {
                    "lane_id": observed_lane,
                    "lease_owner_id": f"lane:{observed_lane}",
                    "resource_keys": ["path:/tmp/other"],
                },
            ),
            "unbound",
        )

    def test_implicit_lane_fails_closed_when_two_verified_lanes_match(self) -> None:
        outer_lane = "d" * 32
        inner_lane = "e" * 32
        outer_key = "path:/tmp/grabowski-outer"
        inner_key = "path:/tmp/grabowski-outer/inner"
        leases = {
            outer_key: {"resource_key": outer_key, "owner_id": f"lane:{outer_lane}"},
            inner_key: {"resource_key": inner_key, "owner_id": f"lane:{inner_lane}"},
        }

        def read_lane(lane):
            resource_key = outer_key if lane == outer_lane else inner_key
            return {
                "lane_id": lane,
                "lease_owner_id": f"lane:{lane}",
                "resource_keys": [resource_key],
            }

        self.assertEqual(
            interceptor.lane_id(
                {"path": "/tmp/grabowski-outer/inner/file.py"},
                resource_inspector=leases.get,
                lane_inputs_reader=read_lane,
            ),
            "unbound",
        )

    def test_default_implicit_resolution_uses_one_bounded_resource_snapshot(self) -> None:
        lane = "9" * 32
        workspace = "/tmp/grabowski-lane-default"
        lease_key = f"path:{workspace}"
        with patch.object(
            interceptor,
            "_default_resource_snapshots",
            return_value={
                lease_key: {
                    "resource_key": lease_key,
                    "owner_id": f"lane:{lane}",
                }
            },
        ) as snapshots:
            observed = interceptor.lane_id(
                {"path": f"{workspace}/src/module.py"},
                lane_inputs_reader=lambda observed_lane: {
                    "lane_id": observed_lane,
                    "lease_owner_id": f"lane:{observed_lane}",
                    "resource_keys": [lease_key],
                },
            )
        self.assertEqual(observed, lane)
        snapshots.assert_called_once()
        probed = snapshots.call_args.args[0]
        self.assertIn(lease_key, probed)
        self.assertLessEqual(len(probed), interceptor.MAX_LANE_RESOURCE_PROBES)

    def test_implicit_lane_refuses_truncated_explicit_resource_scope(self) -> None:
        resources = [f"path:/tmp/resource-{index}" for index in range(33)]

        def unexpected_inspect(_resource_key):
            raise AssertionError("truncated resource scope must not be inspected")

        self.assertEqual(
            interceptor.lane_id(
                {"resource_keys": resources},
                resource_inspector=unexpected_inspect,
                lane_inputs_reader=lambda _lane: {},
            ),
            "unbound",
        )

    def test_admission_records_one_implicitly_verified_lane(self) -> None:
        lane = "f" * 32
        workspace = "/tmp/grabowski-lane-f"
        lease_key = f"path:{workspace}"
        admission = interceptor.admit_mutation(
            tool_name="grabowski_replace_text",
            arguments={"path": f"{workspace}/README.md"},
            transport_evidence=self.transport(),
            resource_inspector=lambda resource_key: (
                {"resource_key": lease_key, "owner_id": f"lane:{lane}"}
                if resource_key == lease_key
                else None
            ),
            lane_inputs_reader=lambda observed_lane: {
                "lane_id": observed_lane,
                "lease_owner_id": f"lane:{observed_lane}",
                "resource_keys": [lease_key],
            },
        )
        self.assertEqual(admission["lane_id"], lane)

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
