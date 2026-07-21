from __future__ import annotations

import copy
import unittest

import grabowski_lifecycle_collectors as collectors


DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
NOW = 2_000_000


def observed(payload=None, *, error=None):
    return collectors.SourceReadback(observed=True, payload=payload, error=error)


def base_sources():
    return {
        "task": observed(None),
        "workspace": observed(None),
        "lease": observed({"inspections": []}),
        "checkout": observed(None),
        "process": observed({"processes": [], "scope": "target"}),
        "tmux": observed({"live": False, "role_bound": False}),
        "receipt": observed(None),
    }


class LifecycleCollectorTests(unittest.TestCase):
    def task_request(self, *, state="completed", receipt=DIGEST, sources=None, resource_keys=()):
        values = base_sources() if sources is None else sources
        values["task"] = observed(
            {
                "task_id": "task-a",
                "state": state,
                "updated_at_unix": NOW - 10,
                "terminalized_at_unix": NOW - 10 if state == "completed" else None,
                "terminalization_sha256": OTHER_DIGEST if state == "completed" else None,
                "lifecycle_receipt_sha256": receipt,
                "resource_keys": list(resource_keys),
                "lease_owner_id": "task:task-a",
                "last_observation": {"state": state},
            }
        )
        values["receipt"] = observed({"lifecycle_receipt_sha256": receipt})
        return collectors.LifecycleCollectorRequest(
            identity="task-a",
            kind="task",
            observed_at_unix=NOW,
            sources=values,
            exact_resource_keys=tuple(resource_keys),
        )

    def test_terminal_task_readbacks_are_hash_bound_and_archivable(self):
        result = collectors.collect_lifecycle_classification(self.task_request())
        self.assertEqual(result["classification"], "terminal_archivable")
        self.assertTrue(result["safe_to_archive"])
        self.assertEqual(set(result["evidence"]["source_sha256s"]), collectors.REQUIRED_SOURCES)
        self.assertFalse(result["mutation_performed"])

    def test_running_task_remains_active(self):
        result = collectors.collect_lifecycle_classification(
            self.task_request(state="running", receipt=None)
        )
        self.assertEqual(result["classification"], "active")

    def test_missing_source_is_ambiguous_not_explicit_absence(self):
        sources = base_sources()
        sources.pop("process")
        result = collectors.collect_lifecycle_classification(
            self.task_request(sources=sources)
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn("observation_error:source_unobserved:process", result["reason_codes"])

    def test_invalid_terminal_receipt_requires_recovery(self):
        result = collectors.collect_lifecycle_classification(
            self.task_request(receipt=None)
        )
        self.assertEqual(result["classification"], "recovery_required")
        self.assertIn("terminal_receipt_integrity_missing_or_invalid", result["reason_codes"])

    def test_active_exact_lease_blocks_terminal_task(self):
        key = "path:/tmp/task-a"
        sources = base_sources()
        sources["lease"] = observed(
            {
                "inspections": [
                    {
                        "resource_key": key,
                        "lease": {
                            "resource_key": key,
                            "owner_id": "task:task-a",
                            "expires_at_unix": NOW + 100,
                            "metadata_sha256": DIGEST,
                        },
                    }
                ]
            }
        )
        result = collectors.collect_lifecycle_classification(
            self.task_request(sources=sources, resource_keys=(key,))
        )
        self.assertEqual(result["classification"], "blocking")
        self.assertIn("active_lease", result["reason_codes"])

    def checkout_request(self, record, *, expected_owner="operator:self"):
        sources = base_sources()
        sources["checkout"] = observed({"worktrees": [record]})
        return collectors.LifecycleCollectorRequest(
            identity="checkout-a",
            kind="checkout",
            observed_at_unix=NOW,
            sources=sources,
            expected_owner_id=expected_owner,
            checkout_path="/tmp/checkout-a",
        )

    def checkout_record(self, *, dirty=False, owner=None, until=None, archive=False, state="unclassified_clean"):
        retention = None
        if owner is not None:
            retention = {"owner_id": owner, "retention_until_unix": until}
        latest_archive = {"archive_id": "archive-a"} if archive else None
        return {
            "checkout_key": "checkout-a",
            "path": "/tmp/checkout-a",
            "head": "c" * 40,
            "branch": "feat/a",
            "status": {"dirty": dirty},
            "lifecycle_state": state,
            "lifecycle": {"retention": retention, "latest_archive": latest_archive},
            "lifecycle_decision": {
                "retention_active": bool(owner and until and until > NOW),
                "archive_present": archive,
                "archive_matches_checkout": archive,
                "coordination_blocking": False,
            },
            "coordination": {"processes": [], "tasks": [], "resource_leases": []},
        }

    def test_dirty_checkout_is_untouchable(self):
        result = collectors.collect_lifecycle_classification(
            self.checkout_request(self.checkout_record(dirty=True))
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_active_foreign_retention_is_untouchable(self):
        result = collectors.collect_lifecycle_classification(
            self.checkout_request(
                self.checkout_record(owner="operator:foreign", until=NOW + 100)
            )
        )
        self.assertEqual(result["classification"], "untouchable")
        self.assertIn("foreign_retention", result["reason_codes"])

    def test_expired_foreign_retention_without_recovery_archive_requires_recovery(self):
        result = collectors.collect_lifecycle_classification(
            self.checkout_request(
                self.checkout_record(owner="operator:foreign", until=NOW - 1)
            )
        )
        self.assertEqual(result["classification"], "recovery_required")
        self.assertIn("retention_recovery_archive_required", result["reason_codes"])

    def test_expired_foreign_retention_with_matching_recovery_archive_can_be_archivable(self):
        result = collectors.collect_lifecycle_classification(
            self.checkout_request(
                self.checkout_record(
                    owner="operator:foreign",
                    until=NOW - 1,
                    archive=True,
                    state="cleanup_candidate",
                )
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")

    def workspace_request(self, status, cleanup_plan, *, tmux=None, receipt_valid=True):
        sources = base_sources()
        normalized_cleanup = {
            "workspace_id": "workspace-a",
            "closed": status.get("closed"),
            "close_receipt_integrity": {"valid": status.get("close_integrity", {}).get("valid") is True},
            "liveness": {
                "live_resource_keys": [],
                "resource_observation_error": None,
                "execution_live_roles": [],
            },
            "checkout": {"coordination": {"processes": []}},
            **cleanup_plan,
        }
        sources["workspace"] = observed({"status": status, "cleanup_plan": normalized_cleanup})
        sources["tmux"] = observed(tmux or {"live": False, "role_bound": False})
        sources["receipt"] = observed({"close_integrity": {"valid": receipt_valid}})
        return collectors.LifecycleCollectorRequest(
            identity="workspace-a",
            kind="workspace",
            observed_at_unix=NOW,
            sources=sources,
        )

    def closed_workspace_status(self):
        return {
            "workspace_id": "workspace-a",
            "closed": True,
            "tasks": {
                "writer": {"task_id": "w", "state": "completed", "terminal": True},
                "tests": {"task_id": "t", "state": "completed", "terminal": True},
                "review": {"task_id": "r", "state": "completed", "terminal": True},
            },
            "close_integrity": {"valid": True},
        }

    def test_closed_workspace_without_shared_reference_is_archivable(self):
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                self.closed_workspace_status(),
                {"workspace_references": [], "workspace_reference_scan_errors": []},
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")

    def test_open_workspace_role_is_active(self):
        status = self.closed_workspace_status()
        status["closed"] = False
        status["tasks"]["writer"] = {"task_id": "w", "state": "running", "terminal": False}
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                status,
                {"workspace_references": [], "workspace_reference_scan_errors": []},
            )
        )
        self.assertEqual(result["classification"], "active")
        self.assertIn("open_task_role", result["reason_codes"])

    def test_shared_workspace_reference_is_untouchable(self):
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                self.closed_workspace_status(),
                {
                    "workspace_references": [
                        {"workspace_id": "workspace-b", "current": False, "closed": False}
                    ],
                    "workspace_reference_scan_errors": [],
                },
            )
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_session_only_tmux_is_ambiguous(self):
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                self.closed_workspace_status(),
                {"workspace_references": [], "workspace_reference_scan_errors": []},
                tmux={"live": True, "role_bound": False},
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn("tmux_session_without_live_role_or_process", result["reason_codes"])

    def test_reference_scan_error_fails_closed(self):
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                self.closed_workspace_status(),
                {
                    "workspace_references": [],
                    "workspace_reference_scan_errors": [{"code": "scan-limit"}],
                },
            )
        )
        self.assertEqual(result["classification"], "ambiguous")

    def test_task_resource_scope_must_match_task_observation(self):
        key = "path:/tmp/task-a"
        sources = base_sources()
        sources["task"] = observed(
            {
                "task_id": "task-a",
                "state": "completed",
                "updated_at_unix": NOW - 10,
                "terminalized_at_unix": NOW - 10,
                "terminalization_sha256": OTHER_DIGEST,
                "lifecycle_receipt_sha256": DIGEST,
                "resource_keys": [key],
                "lease_owner_id": "task:task-a",
                "last_observation": {"state": "completed"},
            }
        )
        sources["receipt"] = observed({"lifecycle_receipt_sha256": DIGEST})
        result = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity="task-a",
                kind="task",
                observed_at_unix=NOW,
                sources=sources,
                exact_resource_keys=(),
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_error:lease:task_resource_scope_mismatch",
            result["reason_codes"],
        )

    def test_invalid_terminalization_integrity_requires_recovery(self):
        request = self.task_request()
        sources = dict(request.sources)
        task_payload = copy.deepcopy(sources["task"].payload)
        task_payload["terminalization_sha256"] = "bad"
        sources["task"] = observed(task_payload)
        result = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity=request.identity,
                kind=request.kind,
                observed_at_unix=request.observed_at_unix,
                sources=sources,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_checkout_coordination_process_cannot_be_overwritten_by_empty_process_source(self):
        record = self.checkout_record(state="cleanup_candidate")
        record["coordination"]["processes"] = [{"pid": 123}]
        result = collectors.collect_lifecycle_classification(self.checkout_request(record))
        self.assertEqual(result["classification"], "active")
        self.assertIn("active_process", result["reason_codes"])

    def test_workspace_live_resource_blocks_archive(self):
        result = collectors.collect_lifecycle_classification(
            self.workspace_request(
                self.closed_workspace_status(),
                {
                    "workspace_references": [],
                    "workspace_reference_scan_errors": [],
                    "liveness": {
                        "live_resource_keys": ["path:/tmp/workspace-a"],
                        "resource_observation_error": None,
                        "execution_live_roles": [],
                    },
                },
            )
        )
        self.assertEqual(result["classification"], "blocking")
        self.assertIn("active_lease", result["reason_codes"])

    def test_source_digest_changes_when_typed_readback_changes(self):
        first = collectors.collect_lifecycle_classification(self.task_request())
        request = self.task_request()
        sources = dict(request.sources)
        task_payload = copy.deepcopy(sources["task"].payload)
        task_payload["updated_at_unix"] = NOW - 9
        sources["task"] = observed(task_payload)
        second = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity=request.identity,
                kind=request.kind,
                observed_at_unix=request.observed_at_unix,
                sources=sources,
                exact_resource_keys=request.exact_resource_keys,
            )
        )
        self.assertNotEqual(
            first["evidence"]["source_sha256s"]["task"],
            second["evidence"]["source_sha256s"]["task"],
        )
        self.assertNotEqual(first["evidence_sha256"], second["evidence_sha256"])


    def test_partial_task_list_cannot_prove_absence(self):
        sources = base_sources()
        sources["task"] = observed(
            {
                "tasks": [],
                "snapshot_complete": True,
                "pagination": {"has_more": True},
            }
        )
        sources["receipt"] = observed(None)
        result = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity="task-a",
                kind="task",
                observed_at_unix=NOW,
                sources=sources,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_error:task:task_absence_not_proven_by_complete_snapshot",
            result["reason_codes"],
        )

    def test_terminal_receipt_must_match_task_observation(self):
        request = self.task_request(receipt=DIGEST)
        sources = dict(request.sources)
        sources["receipt"] = observed({"lifecycle_receipt_sha256": OTHER_DIGEST})
        result = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity=request.identity,
                kind=request.kind,
                observed_at_unix=request.observed_at_unix,
                sources=sources,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_missing_exact_lease_inspection_fails_closed(self):
        key = "path:/tmp/task-a"
        result = collectors.collect_lifecycle_classification(
            self.task_request(resource_keys=(key,))
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            f"observation_error:source_error:lease:lease_exact_inspection_missing:{key}",
            result["reason_codes"],
        )

    def test_workspace_cleanup_inventory_is_required_for_reference_safety(self):
        sources = base_sources()
        status = self.closed_workspace_status()
        sources["workspace"] = observed(status)
        sources["receipt"] = observed({"close_integrity": {"valid": True}})
        result = collectors.collect_lifecycle_classification(
            collectors.LifecycleCollectorRequest(
                identity="workspace-a",
                kind="workspace",
                observed_at_unix=NOW,
                sources=sources,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_error:workspace:workspace_cleanup_plan_missing",
            result["reason_codes"],
        )

    def test_raw_process_list_requires_exact_scope_binding(self):
        sources = base_sources()
        sources["process"] = observed({"pattern": "other", "count": 0, "lines": []})
        result = collectors.collect_lifecycle_classification(
            self.task_request(sources=sources)
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn(
            "observation_error:source_error:process:process_scope_missing_for_process_list",
            result["reason_codes"],
        )


if __name__ == "__main__":
    unittest.main()
