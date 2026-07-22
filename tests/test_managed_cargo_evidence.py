from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

import grabowski_managed_cargo as cargo


class ManagedCargoEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("/home/alex/.cache/heim-pc/managed-builds/cargo")
        self.key = "a" * 64
        self.target = str(self.root / self.key / "target")

    def record(
        self,
        task_id: str,
        state: str,
        updated: int,
        *,
        target: str | None = None,
    ) -> dict:
        argv = ["/usr/bin/env"]
        if target is not None:
            argv.append(f"CARGO_TARGET_DIR={target}")
        argv.extend(["cargo", "test", "--locked"])
        return {
            "task_id": task_id,
            "state": state,
            "updated_at_unix": updated,
            "argv": argv,
            "cwd": "/repo",
            "host": "heim-pc",
        }

    def test_shared_cache_is_protected_when_any_consumer_is_live(self) -> None:
        records = [
            self.record("task-b", "completed", 20, target=self.target),
            self.record("task-a", "running", 10, target=self.target),
        ]
        result = cargo.build_evidence(
            records,
            cache_root=self.root,
            repository_identity_resolver=lambda _record: "f" * 64,
        )
        entry = result["entries"][0]
        self.assertTrue(result["complete"])
        self.assertTrue(entry["protected"])
        self.assertEqual(entry["last_used_at_unix"], 20)
        self.assertEqual(
            [ref["task_id"] for ref in entry["task_refs"]], ["task-a", "task-b"]
        )
        self.assertIn("task_state:running", entry["reasons"])

    def test_terminal_completed_task_supplies_usage_without_protection(self) -> None:
        result = cargo.build_evidence(
            [self.record("task-a", "completed", 42, target=self.target)],
            cache_root=self.root,
            repository_identity_resolver=lambda _record: "f" * 64,
        )
        entry = result["entries"][0]
        self.assertFalse(entry["protected"])
        self.assertEqual(entry["last_used_at_unix"], 42)
        self.assertEqual(entry["reasons"], [])

    def test_nonconverged_states_remain_protected(self) -> None:
        for state in (
            "launching",
            "running",
            "outcome_unknown",
            "interrupted",
        ):
            with self.subTest(state=state):
                result = cargo.build_evidence(
                    [self.record("task-a", state, 42, target=self.target)],
                    cache_root=self.root,
                )
                self.assertTrue(result["entries"][0]["protected"])

    def test_known_terminal_failure_states_supply_usage_without_permanent_protection(self) -> None:
        for state in ("failed", "timed_out", "signalled", "cancelled"):
            with self.subTest(state=state):
                result = cargo.build_evidence(
                    [self.record("task-a", state, 42, target=self.target)],
                    cache_root=self.root,
                )
                self.assertFalse(result["entries"][0]["protected"])
                self.assertEqual(result["entries"][0]["last_used_at_unix"], 42)

    def test_named_legacy_path_below_root_fails_closed(self) -> None:
        target = str(self.root / "public-metrics-pr1532-final" / "target")
        result = cargo.build_evidence(
            [self.record("task-a", "completed", 42, target=target)],
            cache_root=self.root,
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["entries"], [])
        self.assertEqual(len(result["unclassified_bindings"]), 1)
        self.assertEqual(
            result["unclassified_bindings"][0]["reason"], "non_identity_cache_name"
        )

    def test_escaping_or_malformed_managed_path_fails_closed(self) -> None:
        target = str(self.root / self.key / ".." / "escape" / "target")
        result = cargo.build_evidence(
            [self.record("task-a", "running", 42, target=target)],
            cache_root=self.root,
        )
        self.assertFalse(result["complete"])
        self.assertIn("not an absolute normalized path", result["observation_errors"][0])

    def test_flock_wrapped_managed_task_is_still_projected(self) -> None:
        record = self.record("task-a", "running", 42, target=self.target)
        record["argv"] = [
            "/usr/bin/flock",
            "--shared",
            f"/home/alex/.local/state/heim-pc/managed-builds/cache-locks/cargo/{self.key}.lock",
            *record["argv"],
        ]
        result = cargo.build_evidence([record], cache_root=self.root)
        self.assertTrue(result["complete"])
        self.assertEqual(result["entries"][0]["cache_key"], self.key)
        self.assertTrue(result["entries"][0]["protected"])

    def test_unmanaged_external_target_is_ignored(self) -> None:
        result = cargo.build_evidence(
            [self.record("task-a", "running", 42, target="/tmp/custom-target")],
            cache_root=self.root,
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["entries"], [])

    def test_unknown_future_state_is_protected_and_marks_evidence_incomplete(self) -> None:
        result = cargo.build_evidence(
            [self.record("task-a", "future_state", 42, target=self.target)],
            cache_root=self.root,
        )
        self.assertFalse(result["complete"])
        self.assertTrue(result["entries"][0]["protected"])
        self.assertIn("task_state:future_state", result["entries"][0]["reasons"])

    def test_duplicate_task_refs_are_deduplicated_deterministically(self) -> None:
        result = cargo.build_evidence(
            [
                self.record("task-a", "running", 10, target=self.target),
                self.record("task-a", "completed", 20, target=self.target),
            ],
            cache_root=self.root,
        )
        self.assertEqual(len(result["entries"][0]["task_refs"]), 1)
        self.assertEqual(result["entries"][0]["task_refs"][0]["updated_at_unix"], 20)
        # Protection remains conservative because one observed revision was running.
        self.assertTrue(result["entries"][0]["protected"])

    def test_hash_is_deterministic_and_does_not_expose_argv(self) -> None:
        records = [self.record("task-b", "completed", 20, target=self.target)]
        left = cargo.build_evidence(records, cache_root=self.root)
        right = cargo.build_evidence(list(reversed(records)), cache_root=self.root)
        self.assertEqual(left["evidence_sha256"], right["evidence_sha256"])
        core = {key: value for key, value in left.items() if key != "evidence_sha256"}
        expected = hashlib.sha256(
            json.dumps(
                core, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(left["evidence_sha256"], expected)
        self.assertNotIn("argv", json.dumps(left))

    def test_truncation_marks_evidence_incomplete(self) -> None:
        second_key = "b" * 64
        result = cargo.build_evidence(
            [
                self.record("task-a", "completed", 10, target=self.target),
                self.record(
                    "task-b",
                    "completed",
                    20,
                    target=str(self.root / second_key / "target"),
                ),
            ],
            cache_root=self.root,
            max_entries=1,
        )
        self.assertFalse(result["complete"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total_entry_count"], 2)
        self.assertEqual(result["returned_entry_count"], 1)

    def test_task_refs_are_bounded_without_losing_aggregate_usage(self) -> None:
        records = [
            self.record(
                f"task-{index:03d}",
                "completed",
                index,
                target=self.target,
            )
            for index in range(70)
        ]
        result = cargo.build_evidence(records, cache_root=self.root)
        entry = result["entries"][0]
        self.assertEqual(entry["task_ref_count"], 70)
        self.assertEqual(entry["protecting_task_ref_count"], 0)
        self.assertEqual(entry["oldest_task_ref_updated_at_unix"], 0)
        self.assertEqual(entry["newest_task_ref_updated_at_unix"], 69)
        self.assertTrue(entry["task_refs_truncated"])
        self.assertEqual(len(entry["task_refs"]), cargo.MAX_TASK_REFS_PER_ENTRY)
        self.assertEqual(entry["last_used_at_unix"], 69)
        self.assertIn("task-069", {ref["task_id"] for ref in entry["task_refs"]})


if __name__ == "__main__":
    unittest.main()
