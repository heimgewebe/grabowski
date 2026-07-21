from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import grabowski_lifecycle_archive as lifecycle
import grabowski_lifecycle_effect_plan as effect_plan
import grabowski_lifecycle_evidence as lifecycle_evidence
import grabowski_lifecycle_projection as projection


ALL_SOURCES = frozenset(lifecycle_evidence.REQUIRED_SOURCES)
SOURCE_SHA256S = {
    source: format(index + 1, "x") * 64
    for index, source in enumerate(sorted(ALL_SOURCES))
}
OWNER = "operator:t071-projection-test"


class LifecycleProjectionTests(unittest.TestCase):
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
    def live_task(task_id: str, created_at: int = 100) -> dict:
        return {
            "task_id": task_id,
            "state": "running",
            "created_at_unix": created_at,
            "updated_at_unix": created_at + 1,
        }

    def archived_classification(self, task_id: str) -> dict:
        return lifecycle_evidence.classify_observation_bundle(
            lifecycle_evidence.LifecycleObservationBundle(
                identity=task_id,
                kind="task",
                observed_sources=ALL_SOURCES,
                source_sha256s=SOURCE_SHA256S,
                state="completed",
                archived=True,
                receipt_integrity_valid=True,
            )
        )

    def write_archive(
        self,
        archive_root: Path,
        records: list[dict],
        *,
        plan_sha256: str = "d" * 64,
    ) -> dict:
        return lifecycle.write_task_archive_segment(
            records,
            archive_root=archive_root,
            source_store_sha256="c" * 64,
            source_schema_version="5",
            plan_sha256=plan_sha256,
        )

    def switch_contract(
        self,
        projection_root: Path,
        task_ids: list[str],
        *,
        lease_expiry: int = 2000,
        include_projection_resource: bool = True,
    ) -> tuple[dict, dict]:
        classifications = [self.archived_classification(task_id) for task_id in task_ids]
        projection_resource = projection._projection_resource_key(projection_root)
        required_resources = (
            [projection_resource]
            if include_projection_resource
            else ["path:/tmp/not-the-projection-root"]
        )
        plan = effect_plan.build_effect_plan(
            classifications,
            effect_kind="current_projection_switch",
            lease_owner_id=OWNER,
            required_resource_keys=required_resources,
            created_at_unix=1000,
        )
        revalidation = effect_plan.revalidate_effect_plan(
            plan,
            {item["identity"]: item for item in classifications},
            [
                effect_plan.LeaseObservation(
                    resource_key=resource_key,
                    owner_id=OWNER,
                    expires_at_unix=lease_expiry,
                    metadata_sha256="a" * 64,
                )
                for resource_key in required_resources
            ],
            now_unix=1500,
        )
        self.assertTrue(revalidation["ready_for_effect"])
        return plan, revalidation

    def test_apply_load_and_current_view_are_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            records = [self.task("task-a", 10), self.task("task-b", 20)]
            archived = self.write_archive(archive_root, records)
            plan, revalidation = self.switch_contract(
                projection_root,
                ["task-a", "task-b"],
            )

            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )

            self.assertFalse(result["idempotent_replay"])
            self.assertEqual(result["status"], "verified")
            loaded = projection.load_task_archive_projection(
                projection_root=projection_root,
                archive_root=archive_root,
            )
            self.assertEqual(set(loaded["archived_task_bindings"]), {"task-a", "task-b"})
            current = projection.bounded_current_task_projection(
                [*records, self.live_task("task-live")],
                projection=loaded,
            )
            self.assertEqual([item["task_id"] for item in current], ["task-live"])
            self.assertEqual(
                result["post_state_sha256s"]["task_projection"],
                loaded["projection_sha256"],
            )

    def test_identical_switch_replay_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            record = self.task("task-a")
            archived = self.write_archive(archive_root, [record])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            first = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            second = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            self.assertFalse(first["idempotent_replay"])
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(first["switch"], second["switch"])

    def test_current_record_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            record = self.task("task-a")
            archived = self.write_archive(archive_root, [record])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            loaded = projection.load_task_archive_projection(
                projection_root=projection_root,
                archive_root=archive_root,
            )
            drifted = {**record, "updated_at_unix": record["updated_at_unix"] + 1}
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.bounded_current_task_projection([drifted], projection=loaded)

    def test_switch_requires_exact_projection_resource(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(
                projection_root,
                ["task-a"],
                include_projection_resource=False,
            )
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.apply_task_archive_projection_switch(
                    Path(archived["segment_dir"]),
                    projection_root=projection_root,
                    plan=plan,
                    revalidation=revalidation,
                    applied_at_unix=1501,
                )
            self.assertFalse(projection_root.exists())

    def test_switch_must_occur_before_earliest_lease_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(
                projection_root,
                ["task-a"],
                lease_expiry=1501,
            )
            with self.assertRaises(projection.LifecycleProjectionError):
                projection.apply_task_archive_projection_switch(
                    Path(archived["segment_dir"]),
                    projection_root=projection_root,
                    plan=plan,
                    revalidation=revalidation,
                    applied_at_unix=1501,
                )
            self.assertFalse(projection_root.exists())

    def test_projection_root_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            real_projection_root = root / "real-projection"
            real_projection_root.mkdir()
            projection_root = root / "projection"
            projection_root.symlink_to(real_projection_root, target_is_directory=True)
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.apply_task_archive_projection_switch(
                    Path(archived["segment_dir"]),
                    projection_root=projection_root,
                    plan=plan,
                    revalidation=revalidation,
                    applied_at_unix=1501,
                )
            self.assertEqual(list(real_projection_root.iterdir()), [])

    def test_verifier_rejects_switch_relocated_outside_bound_projection_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            relocated_root = root / "relocated-projection"
            relocated_root.mkdir()
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            switch_path = Path(result["switch_path"])
            relocated_path = relocated_root / switch_path.name
            relocated_path.write_bytes(switch_path.read_bytes())
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.verify_task_archive_projection_switch(
                    relocated_path,
                    archive_root=archive_root,
                )

    def test_projection_switch_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            switch_path = Path(result["switch_path"])
            outside = root / "outside-switch.json"
            outside.write_bytes(switch_path.read_bytes())
            switch_path.unlink()
            switch_path.symlink_to(outside)
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.verify_task_archive_projection_switch(
                    switch_path,
                    archive_root=archive_root,
                )

    def test_self_consistent_switch_after_lease_expiry_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            switch_path = Path(result["switch_path"])
            value = json.loads(switch_path.read_text())
            value["applied_at_unix"] = 2000
            body = {key: item for key, item in value.items() if key != "switch_sha256"}
            value["switch_sha256"] = lifecycle.sha256_json(body)
            switch_path.write_text(json.dumps(value, sort_keys=True) + "\n")
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.verify_task_archive_projection_switch(
                    switch_path,
                    archive_root=archive_root,
                )

    def test_self_consistent_switch_tamper_fails_archive_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            switch_path = Path(result["switch_path"])
            value = json.loads(switch_path.read_text())
            value["archive_segment_sha256"] = "f" * 64
            body = {key: item for key, item in value.items() if key != "switch_sha256"}
            value["switch_sha256"] = lifecycle.sha256_json(body)
            switch_path.write_text(json.dumps(value, sort_keys=True) + "\n")
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.verify_task_archive_projection_switch(
                    switch_path,
                    archive_root=archive_root,
                )

    def test_archive_tamper_after_switch_invalidates_projection_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            records_path = Path(archived["segment_dir"]) / "records.jsonl"
            records_path.write_bytes(records_path.read_bytes() + b"{}\n")
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.load_task_archive_projection(
                    projection_root=projection_root,
                    archive_root=archive_root,
                )

    def test_overlapping_identical_archive_binding_converges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            record = self.task("task-a")
            first_archive = self.write_archive(
                archive_root,
                [record],
                plan_sha256="d" * 64,
            )
            second_archive = self.write_archive(
                archive_root,
                [record],
                plan_sha256="e" * 64,
            )
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            projection.apply_task_archive_projection_switch(
                Path(first_archive["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            projection.apply_task_archive_projection_switch(
                Path(second_archive["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            loaded = projection.load_task_archive_projection(
                projection_root=projection_root,
                archive_root=archive_root,
            )
            self.assertEqual(len(loaded["switches"]), 2)
            self.assertEqual(set(loaded["archived_task_bindings"]), {"task-a"})

    def test_conflicting_archive_binding_is_rejected_before_second_switch_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            first_record = self.task("task-a")
            second_record = {**first_record, "updated_at_unix": 16, "terminalized_at_unix": 16}
            first_archive = self.write_archive(
                archive_root,
                [first_record],
                plan_sha256="d" * 64,
            )
            second_archive = self.write_archive(
                archive_root,
                [second_record],
                plan_sha256="e" * 64,
            )
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            projection.apply_task_archive_projection_switch(
                Path(first_archive["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            before = sorted(path.name for path in projection_root.iterdir())
            with self.assertRaises(projection.LifecycleProjectionIntegrityError):
                projection.apply_task_archive_projection_switch(
                    Path(second_archive["segment_dir"]),
                    projection_root=projection_root,
                    plan=plan,
                    revalidation=revalidation,
                    applied_at_unix=1501,
                )
            after = sorted(path.name for path in projection_root.iterdir())
            self.assertEqual(before, after)

    def test_projection_post_state_can_feed_execution_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_root = root / "archives"
            projection_root = root / "projection"
            archived = self.write_archive(archive_root, [self.task("task-a")])
            plan, revalidation = self.switch_contract(projection_root, ["task-a"])
            result = projection.apply_task_archive_projection_switch(
                Path(archived["segment_dir"]),
                projection_root=projection_root,
                plan=plan,
                revalidation=revalidation,
                applied_at_unix=1501,
            )
            receipt = effect_plan.build_effect_execution_receipt(
                plan,
                revalidation,
                execution_id="projection-task-a-001",
                started_at_unix=1501,
                completed_at_unix=1502,
                transport_outcome="confirmed_success",
                mutation_state="performed",
                post_state_status="verified",
                post_state_sha256s=result["post_state_sha256s"],
            )
            self.assertEqual(receipt["effect_kind"], "current_projection_switch")
            self.assertEqual(receipt["status"], "succeeded")
            self.assertFalse(receipt["blind_retry_allowed"])


if __name__ == "__main__":
    unittest.main()
