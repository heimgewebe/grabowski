from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
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


def _status(obligation_id: str, state: str, *, close_sha: str | None = None) -> dict[str, object]:
    return {
        "obligation_id": obligation_id,
        "state": state,
        "objective": f"objective {obligation_id}",
        "created_at": "2026-07-01T00:00:00Z",
        "closed_at": "2026-07-02T00:00:00Z" if close_sha else None,
        "open_file_sha256": hashlib.sha256((obligation_id + "-open").encode()).hexdigest(),
        "close_file_sha256": close_sha,
        "next_action": "continue later" if state == "blocked" else "",
        "recommended_next_action": "continue work",
    }


def _task(task_id: str, state: str, updated_at: int, age: int) -> dict[str, object]:
    return {
        "task_id": task_id,
        "unit": f"grabowski-task-{task_id}.service",
        "state": state,
        "age_seconds": age,
        "updated_at_unix": updated_at,
    }


def _bureau_provider(*, groups: dict[str, list[dict[str, object]]] | None = None, counts: dict[str, int] | None = None):
    selected = {group: [] for group in backfill.BUREAU_ATTENTION_GROUPS}
    selected.update(groups or {})
    selected_counts = {group: len(selected[group]) for group in backfill.BUREAU_ATTENTION_GROUPS}
    selected_counts.update(counts or {})

    def provider(**kwargs):
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


class ConvergenceBackfillTests(unittest.TestCase):
    def test_projection_is_deterministic_and_preserves_resolution_conflicts(self) -> None:
        obligations = [
            {"obligation_id": "goo-test-blocked", "state": "blocked"},
            {"obligation_id": "goo-test-open", "state": "open"},
        ]
        statuses = {
            "goo-test-blocked": _status("goo-test-blocked", "blocked", close_sha="e" * 64),
            "goo-test-open": _status("goo-test-open", "open"),
        }
        overrides = {
            "operator-obligation:goo-test-blocked": {
                "resolution_evidence": {"reference": "github:example/repo#1 merged:abc", "sha256": "f" * 64}
            }
        }
        inventory = {"records": obligations, "integrity_errors": [], "scan_truncated": False}
        bureau = _bureau_provider(groups={"recent_failed": [_task("failed-1", "failed", 100, 5)]})
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", side_effect=lambda value: statuses[value]
        ):
            first = backfill.build_projection(
                runtime_binding=RUNTIME,
                observation_unix=105,
                evidence_overrides=overrides,
                generated_at="2026-07-22T00:00:00Z",
                bureau_attention_provider=bureau,
            )
            second = backfill.build_projection(
                runtime_binding=RUNTIME,
                observation_unix=105,
                evidence_overrides=overrides,
                generated_at="2026-07-22T00:01:00Z",
                bureau_attention_provider=bureau,
            )
        self.assertEqual(first["deterministic_projection_sha256"], second["deterministic_projection_sha256"])
        self.assertEqual(first["classifier_output"]["counts"], second["classifier_output"]["counts"])
        self.assertEqual(1, first["classifier_output"]["counts"]["resolved"])
        self.assertEqual(1, first["classifier_output"]["counts"]["unknown"])
        self.assertEqual(1, first["classifier_output"]["counts"]["defect"])
        self.assertEqual("bureau.cycle_contract.classify_task_attention", first["source_bounds"]["bureau_attention"]["authority"])
        self.assertEqual(first["classifier_output"]["counts"], first["summary"]["classification_counts"])
        self.assertEqual([], first["summary"]["integrity_errors"])
        self.assertFalse(first["summary"]["truncation"]["selection_truncated"])
        self.assertEqual(3, len(first["summary"]["per_source_evidence_references"]))
        self.assertTrue(first["no_history_mutation"])

    def test_bureau_canonical_groups_preserve_current_and_history_meaning(self) -> None:
        inventory = {"records": [], "integrity_errors": [], "scan_truncated": False}
        provider = _bureau_provider(
            groups={
                "stale_running": [_task("stale", "running", 10, 90)],
                "current_outcome_unknown": [_task("current-unknown", "interrupted", 20, 80)],
                "recent_failed": [_task("recent-failed", "failed", 30, 70)],
                "legacy_outcome_unavailable": [_task("legacy-unknown", "interrupted", 40, 60)],
                "historical_failed": [_task("historical-failed", "failed", 50, 50)],
            }
        )
        with patch.object(backfill, "list_obligations", return_value=inventory):
            projection = backfill.build_projection(
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=provider,
            )
        records = {item["record_id"]: item for item in projection["source_records"]}
        self.assertTrue(records["bureau-attention:stale_running:stale"]["bureau_current_attention"])
        self.assertTrue(records["bureau-attention:recent_failed:recent-failed"]["bureau_current_attention"])
        self.assertFalse(records["bureau-attention:historical_failed:historical-failed"]["bureau_current_attention"])
        counts = projection["classifier_output"]["counts"]
        self.assertEqual(1, counts["blocked"])
        self.assertEqual(2, counts["defect"])
        self.assertEqual(2, counts["unknown"])

    def test_bounded_selection_keeps_current_bureau_attention_before_history(self) -> None:
        inventory = {
            "records": [{"obligation_id": "goo-test-open", "state": "open"}],
            "integrity_errors": [],
            "scan_truncated": False,
        }
        provider = _bureau_provider(
            groups={
                "recent_failed": [_task("current-failed", "failed", 90, 10)],
                "historical_failed": [
                    _task("history-a", "failed", 10, 90),
                    _task("history-b", "failed", 20, 80),
                ],
            }
        )
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status("goo-test-open", "open")
        ):
            projection = backfill.build_projection(
                max_records=2,
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=provider,
            )
        ids = [item["record_id"] for item in projection["source_records"]]
        self.assertEqual(
            ["operator-obligation:goo-test-open", "bureau-attention:recent_failed:current-failed"],
            ids,
        )

    def test_bounded_selection_reports_bureau_and_obligation_truncation(self) -> None:
        inventory = {
            "records": [{"obligation_id": "goo-test-open", "state": "open"}],
            "integrity_errors": [],
            "scan_truncated": True,
        }
        provider = _bureau_provider(
            groups={"historical_failed": [_task("old-1", "failed", 1, 99)]},
            counts={"historical_failed": 4},
        )
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status("goo-test-open", "open")
        ):
            projection = backfill.build_projection(
                max_records=2,
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=provider,
            )
        bounds = projection["source_bounds"]
        self.assertEqual(2, bounds["selected_count"])
        self.assertTrue(bounds["selection_truncated"])
        self.assertTrue(bounds["operator_obligations"]["scan_truncated"])
        self.assertEqual(0, bounds["operator_obligations"]["known_omitted_count_lower_bound"])
        self.assertTrue(bounds["bureau_attention"]["scan_truncated"])
        self.assertEqual(3, bounds["known_omitted_count_lower_bound"])

    def test_runtime_binding_accepts_sha1_and_rejects_invalid_git_oid(self) -> None:
        inventory = {"records": [{"obligation_id": "goo-test-open", "state": "open"}], "integrity_errors": [], "scan_truncated": False}
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status("goo-test-open", "open")
        ):
            projection = backfill.build_projection(
                runtime_binding={"release_id": "release", "repo_head": "a" * 40},
                observation_unix=100,
                bureau_attention_provider=_bureau_provider(),
            )
            self.assertEqual("a" * 40, projection["runtime"]["repo_head"])
            with self.assertRaises(backfill.ConvergenceBackfillInputError):
                backfill.build_projection(
                    runtime_binding={"release_id": "release", "repo_head": "bad"},
                    observation_unix=100,
                    bureau_attention_provider=_bureau_provider(),
                )

    def test_classifier_output_must_match_selected_record_identities_exactly(self) -> None:
        inventory = {
            "records": [
                {"obligation_id": "goo-a", "state": "open"},
                {"obligation_id": "goo-b", "state": "open"},
            ],
            "integrity_errors": [],
            "scan_truncated": False,
        }
        statuses = {
            "goo-a": _status("goo-a", "open"),
            "goo-b": _status("goo-b", "open"),
        }

        def classifier(_name, parameters):
            records = [dict(record) for record in parameters["records"]]
            records.reverse()
            return {
                "status": "passed",
                "output": {"records": records, "counts": {}},
                "receipt": {
                    "grip": "convergence-state-classify",
                    "parameters_sha256": "a" * 64,
                    "output_sha256": "b" * 64,
                },
                "receipt_sha256": "c" * 64,
            }

        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", side_effect=lambda value: statuses[value]
        ):
            with self.assertRaisesRegex(
                backfill.ConvergenceBackfillError,
                "record identities",
            ):
                backfill.build_projection(
                    runtime_binding=RUNTIME,
                    observation_unix=100,
                    bureau_attention_provider=_bureau_provider(),
                    classifier=classifier,
                )

    def test_override_for_unselected_record_fails_closed(self) -> None:
        inventory = {"records": [{"obligation_id": "goo-test-open", "state": "open"}], "integrity_errors": [], "scan_truncated": False}
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status("goo-test-open", "open")
        ):
            with self.assertRaises(backfill.ConvergenceBackfillInputError):
                backfill.build_projection(
                    max_records=1,
                    runtime_binding=RUNTIME,
                    observation_unix=100,
                    bureau_attention_provider=_bureau_provider(),
                    evidence_overrides={
                        "operator-obligation:missing": {
                            "resolution_evidence": {"reference": "missing", "sha256": "f" * 64}
                        }
                    },
                )

    def test_create_only_writer_never_replaces_existing_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "private"
            directory.mkdir(mode=0o700)
            target = directory / "projection.json"
            first = {"schema_version": 1, "deterministic_projection_sha256": "a" * 64}
            second = {"schema_version": 1, "deterministic_projection_sha256": "b" * 64}
            created = backfill.write_projection_create_only(target, first)
            replay = backfill.write_projection_create_only(target, second)
            self.assertTrue(created["created"])
            self.assertTrue(created["matches_requested"])
            self.assertFalse(replay["created"])
            self.assertFalse(replay["matches_requested"])
            self.assertEqual(created["published_file_sha256"], replay["published_file_sha256"])
            self.assertEqual(first, json.loads(target.read_text()))
            self.assertEqual(0o600, target.stat().st_mode & 0o777)

    def test_classifier_keeps_resolved_superseded_and_conflicted_distinct(self) -> None:
        ids = ["goo-resolved", "goo-superseded", "goo-conflicted"]
        inventory = {"records": [{"obligation_id": value, "state": "blocked"} for value in ids], "integrity_errors": [], "scan_truncated": False}
        statuses = {value: _status(value, "blocked", close_sha=hashlib.sha256(value.encode()).hexdigest()) for value in ids}
        overrides = {
            "operator-obligation:goo-resolved": {"resolution_evidence": {"reference": "resolved", "sha256": "1" * 64}},
            "operator-obligation:goo-superseded": {"superseding_evidence": {"reference": "superseded", "sha256": "2" * 64}},
            "operator-obligation:goo-conflicted": {"expected_evidence": {"reference": "expected", "sha256": "3" * 64}},
        }
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", side_effect=lambda value: statuses[value]
        ):
            projection = backfill.build_projection(
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=_bureau_provider(),
                evidence_overrides=overrides,
            )
        counts = projection["classifier_output"]["counts"]
        self.assertEqual(1, counts["resolved"])
        self.assertEqual(1, counts["superseded"])
        self.assertEqual(1, counts["conflicted"])
        self.assertEqual(
            ["operator-obligation:goo-conflicted"],
            projection["summary"]["conflicted_record_ids"],
        )
        evidence_by_id = {
            item["record_id"]: item["evidence"]
            for item in projection["summary"]["per_source_evidence_references"]
        }
        self.assertIn("resolution_evidence", evidence_by_id["operator-obligation:goo-resolved"])
        self.assertIn("superseding_evidence", evidence_by_id["operator-obligation:goo-superseded"])
        self.assertIn("expected_evidence", evidence_by_id["operator-obligation:goo-conflicted"])

    def test_malformed_evidence_and_invalid_obligation_hash_fail_closed(self) -> None:
        inventory = {"records": [{"obligation_id": "goo-test-open", "state": "open"}], "integrity_errors": [], "scan_truncated": False}
        good = _status("goo-test-open", "open")
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(backfill, "status_obligation", return_value=good):
            with self.assertRaises(backfill.ConvergenceBackfillInputError):
                backfill.build_projection(
                    runtime_binding=RUNTIME,
                    observation_unix=100,
                    bureau_attention_provider=_bureau_provider(),
                    evidence_overrides={"operator-obligation:goo-test-open": {"resolution_evidence": {"reference": "bad", "sha256": "not-a-sha"}}},
                )
        broken = dict(good)
        broken["open_file_sha256"] = "invalid"
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(backfill, "status_obligation", return_value=broken):
            with self.assertRaises(backfill.ConvergenceBackfillInputError):
                backfill.build_projection(
                    runtime_binding=RUNTIME,
                    observation_unix=100,
                    bureau_attention_provider=_bureau_provider(),
                )

    def test_invalid_bureau_projection_fails_closed(self) -> None:
        inventory = {"records": [{"obligation_id": "goo-test-open", "state": "open"}], "integrity_errors": [], "scan_truncated": False}
        bad_provider = _bureau_provider(counts={"recent_failed": 1})
        with patch.object(backfill, "list_obligations", return_value=inventory), patch.object(
            backfill, "status_obligation", return_value=_status("goo-test-open", "open")
        ):
            projection = backfill.build_projection(
                runtime_binding=RUNTIME,
                observation_unix=100,
                bureau_attention_provider=bad_provider,
            )
            self.assertTrue(projection["source_bounds"]["bureau_attention"]["scan_truncated"])


if __name__ == "__main__":
    unittest.main()
