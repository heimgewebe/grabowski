from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

import grabowski_convergence_backfill as backfill


RUNTIME = {"release_id": "test-release", "repo_head": "a" * 40}
BUREAU_RUNTIME = {
    "release_id": "bureau-release",
    "source_commit": "b" * 40,
    "package_tree_sha256": "c" * 64,
    "manifest_sha256": "d" * 64,
    "immutable_release_path": "/immutable/bureau",
    "state_path": "/state/bureau.sqlite3",
    "state_schema_version": 3,
}


def _task(task_id: str, state: str, updated_at: int, age: int) -> dict[str, object]:
    return {
        "task_id": task_id,
        "unit": f"grabowski-task-{task_id}.service",
        "state": state,
        "age_seconds": age,
        "updated_at_unix": updated_at,
    }


def _status(obligation_id: str) -> dict[str, object]:
    return {
        "obligation_id": obligation_id,
        "state": "open",
        "objective": f"objective {obligation_id}",
        "created_at": "2026-07-01T00:00:00Z",
        "closed_at": None,
        "open_file_sha256": hashlib.sha256((obligation_id + "-open").encode()).hexdigest(),
        "close_file_sha256": None,
        "recommended_next_action": "continue work",
    }


def _provider(
    *,
    groups: dict[str, list[dict[str, object]]] | None = None,
    counts: dict[str, int] | None = None,
    calls: list[dict[str, object]] | None = None,
):
    selected = {group: [] for group in backfill.BUREAU_ATTENTION_GROUPS}
    selected.update(groups or {})
    selected_counts = {group: len(selected[group]) for group in backfill.BUREAU_ATTENTION_GROUPS}
    selected_counts.update(counts or {})

    def provider(**kwargs):
        if calls is not None:
            calls.append(dict(kwargs))
        current = sum(selected_counts[group] for group in backfill.BUREAU_CURRENT_ATTENTION_GROUPS)
        return {
            "runtime": dict(BUREAU_RUNTIME),
            "output": {
                "available": True,
                "task_db": str(kwargs["task_db"]),
                "attention_horizon_seconds": kwargs["horizon_seconds"],
                "task_count": sum(selected_counts.values()),
                "current_attention_count": current,
                "counts": selected_counts,
                "items": selected,
            },
        }

    return provider


def _classifier(_name: str, parameters: dict[str, object]) -> dict[str, object]:
    raw_records = parameters["records"]
    assert isinstance(raw_records, list)
    records = [
        {**record, "classification": "unknown"}
        for record in raw_records
        if isinstance(record, dict)
    ]
    output = {
        "schema_version": 1,
        "authority": "test-classifier",
        "records": records,
        "counts": {"unknown": len(records)},
        "decision_required_count": len(records),
        "does_not_establish": [],
    }
    receipt = {
        "grip": {"name": "convergence-state-classify"},
        "parameters_sha256": backfill.sha256_json(parameters),
        "output_sha256": backfill.sha256_json(output),
    }
    receipt_sha256 = backfill.sha256_json(receipt)
    receipt["receipt_sha256"] = receipt_sha256
    return {
        "status": "passed",
        "output": output,
        "receipt": receipt,
        "receipt_sha256": receipt_sha256,
    }


class ConvergenceBackfillReviewHardeningTests(unittest.TestCase):
    def test_source_load_limits_follow_max_records(self) -> None:
        bureau_calls: list[dict[str, object]] = []
        inventory = {"records": [], "integrity_errors": [], "scan_truncated": False}
        with patch.object(backfill, "list_obligations", return_value=inventory) as list_obligations:
            backfill.build_projection(
                max_records=3,
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=_provider(calls=bureau_calls),
                classifier=_classifier,
            )
        list_obligations.assert_called_once_with({"state": "attention", "limit": 3})
        self.assertEqual(1, len(bureau_calls))
        self.assertEqual(3, bureau_calls[0]["limit"])

    def test_max_records_one_preserves_canonical_bureau_group_priority(self) -> None:
        inventory = {"records": [], "integrity_errors": [], "scan_truncated": False}
        provider = _provider(
            groups={
                "recent_failed": [_task("recent", "failed", 90, 10)],
                "stale_running": [_task("stale", "running", 10, 90)],
                "historical_failed": [_task("historical", "failed", 1, 99)],
            }
        )
        with patch.object(backfill, "list_obligations", return_value=inventory):
            projection = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=provider,
                classifier=_classifier,
            )
        self.assertEqual(
            ["bureau-attention:stale_running:stale"],
            [record["record_id"] for record in projection["source_records"]],
        )

    def test_implicit_observation_time_is_bound_once_and_forwarded(self) -> None:
        inventory = {"records": [], "integrity_errors": [], "scan_truncated": False}
        bureau_calls: list[dict[str, object]] = []
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill.time, "time", return_value=1234567890
        ) as current_time:
            projection = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                bureau_attention_provider=_provider(calls=bureau_calls),
                classifier=_classifier,
            )
        current_time.assert_called_once_with()
        self.assertEqual(1234567890, bureau_calls[0]["now_unix"])
        self.assertEqual(
            1234567890,
            projection["source_bounds"]["bureau_attention"]["observation_unix"],
        )

    def test_evidence_override_applies_to_selected_bureau_record(self) -> None:
        inventory = {"records": [], "integrity_errors": [], "scan_truncated": False}
        record_id = "bureau-attention:recent_failed:failed-1"
        provider = _provider(
            groups={"recent_failed": [_task("failed-1", "failed", 90, 10)]}
        )
        override = {
            record_id: {
                "resolution_evidence": {
                    "reference": "github:example/repo#1 merged:abc",
                    "sha256": "2" * 64,
                }
            }
        }
        with patch.object(backfill, "list_obligations", return_value=inventory):
            projection = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                observation_unix=100,
                evidence_overrides=override,
                bureau_attention_provider=provider,
                classifier=_classifier,
            )
        source = projection["source_records"][0]
        self.assertEqual(override[record_id], source["explicit_evidence_overrides"])
        evidence = projection["summary"]["per_source_evidence_references"][0]["evidence"]
        self.assertIn("failure_evidence", evidence)
        self.assertEqual(
            "github:example/repo#1 merged:abc:evidence_sha256:" + "2" * 64,
            evidence["resolution_evidence"],
        )

    def test_open_obligation_null_close_hash_is_deterministically_bound(self) -> None:
        obligation_id = "goo-test-open"
        inventory = {
            "records": [{"obligation_id": obligation_id, "state": "open"}],
            "integrity_errors": [],
            "scan_truncated": False,
        }
        status = _status(obligation_id)
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=status
        ):
            first = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                observation_unix=100,
                generated_at="2026-07-23T00:00:00Z",
                bureau_attention_provider=_provider(),
                classifier=_classifier,
            )
            second = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                observation_unix=100,
                generated_at="2026-07-23T00:01:00Z",
                bureau_attention_provider=_provider(),
                classifier=_classifier,
            )
        record = first["source_records"][0]
        self.assertIsNone(record["close_file_sha256"])
        self.assertEqual(
            backfill._sha256(
                {
                    "open_file_sha256": status["open_file_sha256"],
                    "close_file_sha256": None,
                }
            ),
            record["source_content_sha256"],
        )
        self.assertEqual(
            first["deterministic_projection_sha256"],
            second["deterministic_projection_sha256"],
        )

    def test_combined_truncation_lower_bound_remains_conservative(self) -> None:
        obligation_id = "goo-test-open"
        inventory = {
            "records": [{"obligation_id": obligation_id, "state": "open"}],
            "integrity_errors": [],
            "scan_truncated": True,
        }
        provider = _provider(
            groups={
                "stale_running": [_task("stale", "running", 10, 90)],
                "historical_failed": [_task("old", "failed", 1, 99)],
            },
            counts={"stale_running": 3, "historical_failed": 2},
        )
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status(obligation_id)
        ):
            projection = backfill.build_projection(
                max_records=1,
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=provider,
                classifier=_classifier,
            )
        bounds = projection["source_bounds"]
        self.assertTrue(bounds["selection_truncated"])
        self.assertTrue(bounds["operator_obligations"]["scan_truncated"])
        self.assertEqual(0, bounds["operator_obligations"]["known_omitted_count_lower_bound"])
        self.assertEqual(3, bounds["bureau_attention"]["known_omitted_count_lower_bound"])
        self.assertEqual(5, bounds["known_omitted_count_lower_bound"])


if __name__ == "__main__":
    unittest.main()
