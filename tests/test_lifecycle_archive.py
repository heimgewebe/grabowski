from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_effect_plan as effect_plan
import grabowski_lifecycle_evidence as lifecycle_evidence


class LifecycleClassificationTests(unittest.TestCase):
    def test_active_task_wins_over_nonterminal_default(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-a",
                kind="task",
                state="running",
                active_task=True,
            )
        )
        self.assertEqual(result["classification"], "active")
        self.assertFalse(result["safe_to_archive"])

    def test_unknown_observation_fails_closed_as_ambiguous(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="workspace-a",
                kind="workspace",
                closed=True,
                active_process=None,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")
        self.assertIn("observation_unknown:active_process", result["reason_codes"])

    def test_foreign_retention_is_untouchable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="checkout-a",
                kind="checkout",
                closed=True,
                foreign_retention=True,
            )
        )
        self.assertEqual(result["classification"], "untouchable")
        self.assertIn("foreign_retention", result["reason_codes"])

    def test_dirty_checkout_is_untouchable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="checkout-b",
                kind="checkout",
                closed=True,
                dirty=True,
            )
        )
        self.assertEqual(result["classification"], "untouchable")

    def test_recovery_state_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-b",
                kind="task",
                state="outcome_unknown",
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_terminal_with_valid_receipt_is_archivable(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-c",
                kind="task",
                state="completed",
                receipt_integrity_valid=True,
            )
        )
        self.assertEqual(result["classification"], "terminal_archivable")
        self.assertTrue(result["safe_to_archive"])

    def test_terminal_with_invalid_receipt_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-d",
                kind="task",
                state="completed",
                receipt_integrity_valid=False,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")

    def test_archived_with_live_activity_is_ambiguous(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-e",
                kind="task",
                state="completed",
                archived=True,
                active_process=True,
            )
        )
        self.assertEqual(result["classification"], "ambiguous")

    def test_archived_with_invalid_receipt_requires_recovery(self) -> None:
        result = lifecycle.classify_lifecycle(
            lifecycle.LifecycleEvidence(
                identity="task-f",
                kind="task",
                state="completed",
                archived=True,
                receipt_integrity_valid=False,
            )
        )
        self.assertEqual(result["classification"], "recovery_required")


class LifecycleProjectionTests(unittest.TestCase):
    def test_bounded_current_projection_hides_only_archive_history(self) -> None:
        records = [
            {"task_id": "a", "state": "running"},
            {"task_id": "b", "state": "completed"},
            {"task_id": "c", "state": "completed"},
            {"task_id": "d", "state": "failed"},
        ]
        classifications = {
            "a": {"classification": "active"},
            "b": {"classification": "terminal_archivable"},
            "c": {"classification": "archived"},
            "d": {"classification": "recovery_required"},
        }
        current = lifecycle.bounded_current_projection(records, classifications)
        self.assertEqual([record["task_id"] for record in current], ["a", "d"])

    def test_projection_requires_classification_for_every_record(self) -> None:
        with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
            lifecycle.bounded_current_projection(
                [{"task_id": "a", "state": "completed"}],
                {},
            )


class TaskArchivePlanTests(unittest.TestCase):
    @staticmethod
    def task(task_id: str, *, updated_at: int, receipt: str = "a" * 64) -> dict:
        return {
            "task_id": task_id,
            "state": "completed",
            "created_at_unix": updated_at - 10,
            "updated_at_unix": updated_at,
            "terminalized_at_unix": updated_at,
            "lifecycle_receipt_sha256": receipt,
        }

    def test_plan_selects_only_old_archivable_records(self) -> None:
        records = [
            self.task("old", updated_at=100),
            self.task("fresh", updated_at=950),
            self.task("blocked", updated_at=100),
        ]
        classifications = {
            "old": {"classification": "terminal_archivable"},
            "fresh": {"classification": "terminal_archivable"},
            "blocked": {"classification": "untouchable"},
        }
        plan = lifecycle.build_task_archive_plan(
            records,
            classifications,
            now_unix=1000,
            minimum_age_seconds=100,
        )
        self.assertEqual(plan["eligible_task_ids"], ["old"])
        self.assertEqual(
            {entry["task_id"] for entry in plan["blocked"]},
            {"fresh", "blocked"},
        )
        self.assertEqual(len(plan["plan_sha256"]), 64)

    def test_failed_task_archive_requires_authoritative_resolved_attention_closeout(self) -> None:
        record = self.task("failed", updated_at=100)
        record["state"] = "failed"
        classifications = {"failed": {"classification": "terminal_archivable"}}

        with (
            mock.patch("grabowski_tasks._row_raw", return_value=record),
            mock.patch(
                "grabowski_task_attention.terminal_closeout_plan",
                return_value={"archive_ready": False, "closeout_state": "attention_required"},
            ),
        ):
            required = lifecycle.build_task_archive_plan(
                [record], classifications, now_unix=1000, minimum_age_seconds=100
            )
        with (
            mock.patch("grabowski_tasks._row_raw", return_value=record),
            mock.patch(
                "grabowski_task_attention.terminal_closeout_plan",
                return_value={"archive_ready": False, "closeout_state": "attention_deferred"},
            ),
        ):
            deferred = lifecycle.build_task_archive_plan(
                [record], classifications, now_unix=1000, minimum_age_seconds=100
            )
        with (
            mock.patch("grabowski_tasks._row_raw", return_value=record),
            mock.patch(
                "grabowski_task_attention.terminal_closeout_plan",
                return_value={"archive_ready": True, "closeout_state": "ready_to_archive"},
            ),
        ):
            closed = lifecycle.build_task_archive_plan(
                [record], classifications, now_unix=1000, minimum_age_seconds=100
            )

        self.assertEqual([], required["eligible_task_ids"])
        self.assertIn(
            "attention_closeout:attention_required", required["blocked"][0]["reason_codes"]
        )
        self.assertEqual([], deferred["eligible_task_ids"])
        self.assertIn(
            "attention_closeout:attention_deferred", deferred["blocked"][0]["reason_codes"]
        )
        self.assertEqual(["failed"], closed["eligible_task_ids"])

    def test_failed_task_archive_rejects_stale_attention_authority_binding(self) -> None:
        record = self.task("failed", updated_at=100)
        record["state"] = "failed"
        stale = {**record, "lifecycle_receipt_sha256": "b" * 64}
        classifications = {"failed": {"classification": "terminal_archivable"}}

        with (
            mock.patch("grabowski_tasks._row_raw", return_value=stale),
            mock.patch("grabowski_task_attention.terminal_closeout_plan") as closeout_plan,
        ):
            plan = lifecycle.build_task_archive_plan(
                [record], classifications, now_unix=1000, minimum_age_seconds=100
            )

        self.assertEqual([], plan["eligible_task_ids"])
        self.assertIn(
            "attention_authority_binding_mismatch", plan["blocked"][0]["reason_codes"]
        )
        closeout_plan.assert_not_called()

    def test_completed_task_archive_does_not_require_attention_classification(self) -> None:
        record = self.task("completed", updated_at=100)
        classifications = {"completed": {"classification": "terminal_archivable"}}

        plan = lifecycle.build_task_archive_plan(
            [record],
            classifications,
            now_unix=1000,
            minimum_age_seconds=100,
        )

        self.assertEqual(["completed"], plan["eligible_task_ids"])

    def test_plan_digest_changes_when_source_record_changes(self) -> None:
        record = self.task("old", updated_at=100)
        classifications = {"old": {"classification": "terminal_archivable"}}
        first = lifecycle.build_task_archive_plan(
            [record], classifications, now_unix=1000, minimum_age_seconds=100
        )
        changed = {**record, "updated_at_unix": 99, "terminalized_at_unix": 99}
        second = lifecycle.build_task_archive_plan(
            [changed], classifications, now_unix=1000, minimum_age_seconds=100
        )
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])


class TaskArchiveSegmentTests(unittest.TestCase):
    @staticmethod
    def task(task_id: str, created_at: int) -> dict:
        return {
            "task_id": task_id,
            "state": "completed",
            "created_at_unix": created_at,
            "updated_at_unix": created_at + 5,
            "terminalized_at_unix": created_at + 5,
            "lifecycle_receipt_sha256": "b" * 64,
        }

    def test_write_verify_and_idempotent_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            records = [self.task("task-b", 20), self.task("task-a", 10)]
            first = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            self.assertEqual(first["status"], "verified")
            self.assertFalse(first["idempotent_replay"])
            self.assertEqual(
                [record["task_id"] for record in first["records"]],
                ["task-a", "task-b"],
            )
            manifest = first["manifest"]
            self.assertEqual(manifest["record_count"], 2)
            self.assertEqual(manifest["first_task_id"], "task-a")
            self.assertEqual(manifest["last_task_id"], "task-b")
            records_path = Path(first["segment_dir"]) / "records.jsonl"
            self.assertEqual(first["records_bytes"], records_path.stat().st_size)
            self.assertEqual(
                first["record_hash_sequence_sha256"],
                lifecycle.sha256_json(manifest["record_sha256s"]),
            )
            second = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(second["manifest"], manifest)

    def test_same_records_with_different_plan_get_distinct_segment_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            records = [self.task("task-a", 10)]
            first = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            second = lifecycle.write_task_archive_segment(
                records,
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="e" * 64,
            )
            self.assertNotEqual(first["segment_dir"], second["segment_dir"])
            self.assertNotEqual(
                first["manifest"]["segment_identity_sha256"],
                second["manifest"]["segment_identity_sha256"],
            )

    def test_tampered_segment_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            segment_dir = Path(result["segment_dir"])
            records_path = segment_dir / "records.jsonl"
            payload = json.loads(records_path.read_text(encoding="utf-8"))
            payload["state"] = "failed"
            records_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(segment_dir)

    def test_segment_verification_rejects_rehashed_manifest_semantic_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            segment_dir = Path(result["segment_dir"])
            manifest_path = segment_dir / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["kind"] = "tampered_archive_kind"
            body = {
                key: value
                for key, value in manifest.items()
                if key != "manifest_sha256"
            }
            manifest["manifest_sha256"] = lifecycle.sha256_json(body)
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(segment_dir)

    def test_segment_rejects_record_without_lifecycle_receipt(self) -> None:
        record = self.task("task-a", 10)
        record["lifecycle_receipt_sha256"] = None
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(lifecycle.LifecycleArchiveError):
                lifecycle.write_task_archive_segment(
                    [record],
                    archive_root=Path(directory) / "archives",
                    source_store_sha256="c" * 64,
                    source_schema_version="5",
                    plan_sha256="d" * 64,
                )


    def test_segment_writer_rejects_symlink_archive_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            root = base / "archives"
            root.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(
                lifecycle.LifecycleArchiveIntegrityError,
                "task archive root may not be a symlink",
            ):
                lifecycle.write_task_archive_segment(
                    [self.task("task-a", 10)],
                    archive_root=root,
                    source_store_sha256="c" * 64,
                    source_schema_version="5",
                    plan_sha256="d" * 64,
                )

    def test_segment_verification_respects_explicit_records_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_records_bytes=1,
                )

    def test_segment_verification_respects_explicit_manifest_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(lifecycle.LifecycleArchiveIntegrityError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_manifest_bytes=1,
                )

    def test_segment_verification_rejects_invalid_records_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "archives"
            result = lifecycle.write_task_archive_segment(
                [self.task("task-a", 10)],
                archive_root=root,
                source_store_sha256="c" * 64,
                source_schema_version="5",
                plan_sha256="d" * 64,
            )
            with self.assertRaises(ValueError):
                lifecycle.verify_task_archive_segment(
                    Path(result["segment_dir"]),
                    max_records_bytes=-1,
                )


class TaskArchiveEffectTests(unittest.TestCase):
    @staticmethod
    def task(task_id: str, created_at: int = 10) -> dict:
        return {
            "task_id": task_id,
            "state": "completed",
            "created_at_unix": created_at,
            "updated_at_unix": created_at + 5,
            "terminalized_at_unix": created_at + 5,
            "lifecycle_receipt_sha256": "b" * 64,
        }

    @staticmethod
    def classification(task_id: str) -> dict:
        observed = frozenset(lifecycle_evidence.REQUIRED_SOURCES)
        source_sha256s = {
            source: f"{index + 1:x}" * 64
            for index, source in enumerate(sorted(observed))
        }
        return lifecycle_evidence.classify_observation_bundle(
            lifecycle_evidence.LifecycleObservationBundle(
                identity=task_id,
                kind="task",
                observed_sources=observed,
                source_sha256s=source_sha256s,
                state="completed",
                receipt_integrity_valid=True,
            )
        )

    def effect_inputs(self, root: Path, records: list[dict]) -> dict:
        archive_root = root / "archives"
        effect_root = root / "effects"
        classifications = [self.classification(record["task_id"]) for record in records]
        archive_plan = lifecycle.build_task_archive_plan(
            records,
            {item["identity"]: item for item in classifications},
            now_unix=1000,
            minimum_age_seconds=100,
        )
        owner = "operator:test-task-archive-effect"
        resources = [
            lifecycle._task_archive_effect_resource_key(archive_root),
            lifecycle._task_archive_effect_resource_key(effect_root),
        ]
        plan = effect_plan.build_effect_plan(
            classifications,
            effect_kind="task_archive",
            lease_owner_id=owner,
            required_resource_keys=resources,
            created_at_unix=1000,
        )
        lease_observations = [
            effect_plan.LeaseObservation(
                resource_key=resource,
                owner_id=owner,
                expires_at_unix=2000,
                metadata_sha256="a" * 64,
            )
            for resource in resources
        ]
        return {
            "archive_root": archive_root,
            "effect_root": effect_root,
            "archive_plan": archive_plan,
            "plan": plan,
            "current_classifications": {
                item["identity"]: item for item in classifications
            },
            "lease_observations": lease_observations,
        }

    def execute(self, records: list[dict], inputs: dict, *, execution_id: str = "task-archive:test") -> dict:
        with mock.patch.object(lifecycle, "_now_unix", side_effect=[1001, 1002, 1003]):
            return lifecycle.execute_task_archive_effect(
                records,
                archive_root=inputs["archive_root"],
                effect_root=inputs["effect_root"],
                source_store_sha256="c" * 64,
                source_schema_version="5",
                archive_plan=inputs["archive_plan"],
                plan=inputs["plan"],
                current_classifications=inputs["current_classifications"],
                lease_observations=inputs["lease_observations"],
                execution_id=execution_id,
            )

    def test_effect_persists_plan_revalidation_archive_and_success_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            result = self.execute(records, inputs)
            receipt = result["effect_receipt"]["receipt"]
            self.assertEqual(result["status"], "verified")
            self.assertEqual(receipt["status"], "succeeded")
            self.assertFalse(receipt["blind_retry_allowed"])
            self.assertEqual(receipt["effect_kind"], "task_archive")
            self.assertEqual(
                receipt["post_state_sha256s"],
                result["post_state_sha256s"],
            )
            self.assertTrue(Path(result["effect_plan_path"]).is_file())
            self.assertTrue(Path(result["effect_revalidation_path"]).is_file())
            self.assertTrue(Path(result["effect_receipt"]["receipt_path"]).is_file())

    def test_effect_requires_exact_archive_and_effect_resources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            bad_plan = effect_plan.build_effect_plan(
                [self.classification("task-a")],
                effect_kind="task_archive",
                lease_owner_id="operator:test-task-archive-effect",
                required_resource_keys=[
                    lifecycle._task_archive_effect_resource_key(inputs["archive_root"])
                ],
                created_at_unix=1000,
            )
            with self.assertRaisesRegex(
                lifecycle.LifecycleArchiveIntegrityError,
                "lacks exact archive and effect resources",
            ):
                lifecycle.execute_task_archive_effect(
                    records,
                    archive_root=inputs["archive_root"],
                    effect_root=inputs["effect_root"],
                    source_store_sha256="c" * 64,
                    source_schema_version="5",
                    archive_plan=inputs["archive_plan"],
                    plan=bad_plan,
                    current_classifications=inputs["current_classifications"],
                    lease_observations=inputs["lease_observations"],
                    execution_id="task-archive:missing-effect-root",
                )

    def test_effect_rejects_record_drift_from_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            changed = [{**records[0], "updated_at_unix": 99, "terminalized_at_unix": 99}]
            with self.assertRaisesRegex(
                lifecycle.LifecycleArchiveIntegrityError,
                "dry-run record digests",
            ):
                self.execute(changed, inputs)

    def test_effect_exact_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            first = self.execute(records, inputs)
            second = self.execute(records, inputs)
            self.assertTrue(second["idempotent_replay"])
            self.assertTrue(second["effect_receipt"]["idempotent_replay"])
            self.assertEqual(
                first["effect_receipt"]["receipt"],
                second["effect_receipt"]["receipt"],
            )

    def test_effect_rejects_symlink_effect_root_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            records = [self.task("task-a")]
            inputs = self.effect_inputs(base, records)
            target = base / "effect-target"
            target.mkdir()
            inputs["effect_root"].symlink_to(target, target_is_directory=True)
            with mock.patch.object(lifecycle, "write_task_archive_segment") as writer:
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveIntegrityError,
                    "task archive effect root may not be a symlink",
                ):
                    self.execute(records, inputs)
            writer.assert_not_called()

    def test_effect_rejects_symlink_receipt_root_before_archive_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            records = [self.task("task-a")]
            inputs = self.effect_inputs(base, records)
            inputs["effect_root"].mkdir()
            target = base / "receipt-target"
            target.mkdir()
            (inputs["effect_root"] / "receipts").symlink_to(
                target,
                target_is_directory=True,
            )
            with mock.patch.object(lifecycle, "write_task_archive_segment") as writer:
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveIntegrityError,
                    "task archive effect receipt root may not be a symlink",
                ):
                    self.execute(records, inputs)
            writer.assert_not_called()

    def test_effect_revalidation_drift_blocks_before_archive_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            drifted = lifecycle_evidence.classify_observation_bundle(
                lifecycle_evidence.LifecycleObservationBundle(
                    identity="task-a",
                    kind="task",
                    observed_sources=frozenset(lifecycle_evidence.REQUIRED_SOURCES),
                    source_sha256s={
                        source: f"{index + 1:x}" * 64
                        for index, source in enumerate(
                            sorted(lifecycle_evidence.REQUIRED_SOURCES)
                        )
                    },
                    state="running",
                    active_task=True,
                    receipt_integrity_valid=True,
                )
            )
            inputs["current_classifications"] = {"task-a": drifted}
            with mock.patch.object(lifecycle, "write_task_archive_segment") as writer:
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveError,
                    "revalidation is not ready",
                ):
                    self.execute(records, inputs)
            writer.assert_not_called()

    def test_effect_reconciles_lost_success_receipt_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            original_write = effect_plan.write_effect_execution_receipt

            def write_then_lose_response(receipt, **kwargs):
                result = original_write(receipt, **kwargs)
                if receipt["status"] == "succeeded":
                    raise RuntimeError("receipt response lost")
                return result

            with (
                mock.patch.object(
                    effect_plan,
                    "write_effect_execution_receipt",
                    side_effect=write_then_lose_response,
                ),
                mock.patch.object(lifecycle, "_now_unix", side_effect=[1001, 1002, 1003]),
            ):
                result = lifecycle.execute_task_archive_effect(
                    records,
                    archive_root=inputs["archive_root"],
                    effect_root=inputs["effect_root"],
                    source_store_sha256="c" * 64,
                    source_schema_version="5",
                    archive_plan=inputs["archive_plan"],
                    plan=inputs["plan"],
                    current_classifications=inputs["current_classifications"],
                    lease_observations=inputs["lease_observations"],
                    execution_id="task-archive:lost-success-receipt-response",
                )
            self.assertEqual(result["effect_receipt"]["receipt"]["status"], "succeeded")
            self.assertTrue(result["effect_receipt"]["idempotent_replay"])
            self.assertEqual(len(list((inputs["effect_root"] / "receipts").glob("receipt-*.json"))), 1)

    def test_effect_success_receipt_failure_creates_recovery_and_blocks_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            execution_id = "task-archive:success-receipt-failure"
            original_write = effect_plan.write_effect_execution_receipt

            def fail_success_receipt(receipt, **kwargs):
                if receipt["status"] == "succeeded":
                    raise RuntimeError("success receipt unavailable")
                return original_write(receipt, **kwargs)

            with (
                mock.patch.object(
                    effect_plan,
                    "write_effect_execution_receipt",
                    side_effect=fail_success_receipt,
                ),
                mock.patch.object(
                    lifecycle,
                    "_now_unix",
                    side_effect=[1001, 1002, 1003, 1004],
                ),
            ):
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveError,
                    "success receipt outcome is ambiguous",
                ):
                    lifecycle.execute_task_archive_effect(
                        records,
                        archive_root=inputs["archive_root"],
                        effect_root=inputs["effect_root"],
                        source_store_sha256="c" * 64,
                        source_schema_version="5",
                        archive_plan=inputs["archive_plan"],
                        plan=inputs["plan"],
                        current_classifications=inputs["current_classifications"],
                        lease_observations=inputs["lease_observations"],
                        execution_id=execution_id,
                    )
            receipts = list((inputs["effect_root"] / "receipts").glob("receipt-*.json"))
            self.assertEqual(len(receipts), 1)
            revalidation = effect_plan.verify_effect_revalidation(
                next((inputs["effect_root"] / "revalidations").glob("revalidation-*.json")),
                plan=inputs["plan"],
            )["revalidation"]
            verified = effect_plan.verify_effect_execution_receipt(
                receipts[0],
                plan=inputs["plan"],
                revalidation=revalidation,
            )
            self.assertEqual(verified["receipt"]["status"], "recovery_required")
            with mock.patch.object(lifecycle, "write_task_archive_segment") as writer:
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveError,
                    "blind retry is forbidden",
                ):
                    self.execute(records, inputs, execution_id=execution_id)
            writer.assert_not_called()

    def test_effect_recovery_receipt_blocks_same_execution_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            execution_id = "task-archive:ambiguous-retry"
            with mock.patch.object(
                lifecycle,
                "write_task_archive_segment",
                side_effect=RuntimeError("transport outcome unknown"),
            ):
                with self.assertRaisesRegex(RuntimeError, "transport outcome unknown"):
                    self.execute(records, inputs, execution_id=execution_id)
            with mock.patch.object(lifecycle, "write_task_archive_segment") as writer:
                with self.assertRaisesRegex(
                    lifecycle.LifecycleArchiveError,
                    "blind retry is forbidden",
                ):
                    self.execute(records, inputs, execution_id=execution_id)
            writer.assert_not_called()

    def test_effect_ambiguous_archive_failure_writes_recovery_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records = [self.task("task-a")]
            inputs = self.effect_inputs(Path(directory), records)
            with mock.patch.object(
                lifecycle,
                "write_task_archive_segment",
                side_effect=RuntimeError("transport outcome unknown"),
            ):
                with self.assertRaisesRegex(RuntimeError, "transport outcome unknown"):
                    self.execute(records, inputs, execution_id="task-archive:ambiguous")
            receipts = list((inputs["effect_root"] / "receipts").glob("receipt-*.json"))
            self.assertEqual(len(receipts), 1)
            verified = effect_plan.verify_effect_execution_receipt(
                receipts[0],
                plan=inputs["plan"],
                revalidation=effect_plan.verify_effect_revalidation(
                    next((inputs["effect_root"] / "revalidations").glob("revalidation-*.json")),
                    plan=inputs["plan"],
                )["revalidation"],
            )
            receipt = verified["receipt"]
            self.assertEqual(receipt["status"], "recovery_required")
            self.assertEqual(receipt["mutation_state"], "unknown")
            self.assertFalse(receipt["blind_retry_allowed"])
            self.assertEqual(receipt["recovery_refs"], [str(inputs["archive_root"].resolve())])



if __name__ == "__main__":
    unittest.main()
