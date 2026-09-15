from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_job_origin as job_origin


REPO = "heimgewebe/grabowski"
PR = 1218
HEAD = "a" * 40
BASE = "b" * 40
DIFF = "c" * 64


def binding() -> dict:
    return {
        "schema_version": 1,
        "kind": job_origin.DECISION_REVIEW_BINDING_KIND,
        "repo": REPO,
        "pr": PR,
        "head_sha": HEAD,
        "base_sha": BASE,
        "diff_sha256": DIFF,
        "slot": "independent-reviewer",
    }


def scope(observed_ns: int | None) -> dict:
    value = {
        "cwd": "/tmp/review",
        "argv_sha256": "d" * 64,
        "runtime_seconds": 60,
        "decision_bound_review": binding(),
    }
    if observed_ns is not None:
        value["started_at_unix_ns"] = observed_ns
    return value


def build(suffix: str, observed_ns: int | None) -> tuple[dict, str]:
    created_at_unix = 1_787_000_000
    if observed_ns is not None:
        created_at_unix = observed_ns // 1_000_000_000
    return job_origin.build_origin(
        unit=f"grabowski-job-{suffix}",
        owner=f"uid:{os.getuid()}",
        argv_sha256="e" * 64,
        scope=scope(observed_ns),
        notify_on_done={"requested": False, "channels": []},
        created_at_unix=created_at_unix,
        started_at="2026-09-15T12:00:00Z",
        invoker_tool="grabowski_job_start",
    )


class DecisionReviewLogicalClockTests(unittest.TestCase):
    def roots(self, temporary: str):
        root = Path(temporary)
        return (
            mock.patch.object(
                job_origin, "DECISION_REVIEW_ORDER_ROOT", root / "order"
            ),
            mock.patch.object(
                job_origin, "DECISION_REVIEW_JOBS_ROOT", root / "jobs"
            ),
        )

    def test_clock_rollback_still_produces_strict_causal_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                first_ns = 2_000_000_000_500_000_000
                second_observed_ns = 1_900_000_000_100_000_000
                first, _ = build("000000000001", first_ns)
                second, _ = build("000000000002", second_observed_ns)

        first_logical = first["scope"]["started_at_unix_ns"]
        second_logical = second["scope"]["started_at_unix_ns"]
        self.assertEqual(first_logical, first_ns)
        self.assertEqual(second_logical, first_logical + 1)
        self.assertGreater(second_logical, first_logical)
        self.assertEqual(
            second["created_at_unix"], second_logical // 1_000_000_000
        )

    def test_origin_validation_does_not_advance_logical_clock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                origin, digest = build(
                    "000000000003", 2_000_000_000_500_000_000
                )
                state_path = next(job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.json"))
                before = state_path.read_bytes()
                validated = job_origin.validate_origin(
                    origin,
                    digest,
                    expected_unit="grabowski-job-000000000003",
                )
                after = state_path.read_bytes()

        self.assertEqual(validated, origin)
        self.assertEqual(after, before)

    def test_missing_state_bootstraps_from_hash_valid_job_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                first, first_digest = build(
                    "000000000004", 2_000_000_000_500_000_000
                )
                job_directory = (
                    job_origin.DECISION_REVIEW_JOBS_ROOT
                    / "grabowski-job-000000000004"
                )
                job_directory.mkdir(parents=True, mode=0o700)
                metadata_path = job_directory / "metadata.json"
                metadata_path.write_text(
                    json.dumps(
                        {"origin": first, "origin_sha256": first_digest},
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
                os.chmod(metadata_path, 0o600)
                state_path = next(job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.json"))
                state_path.unlink()

                second, _ = build(
                    "000000000005", 1_900_000_000_100_000_000
                )

        self.assertEqual(
            second["scope"]["started_at_unix_ns"],
            first["scope"]["started_at_unix_ns"] + 1,
        )

    def test_interrupted_replace_preserves_last_valid_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                first, _ = build("000000000009", 2_000_000_000_500_000_000)
                state_path = next(
                    job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.json")
                )
                before = state_path.read_bytes()
                with mock.patch.object(
                    job_origin.os,
                    "replace",
                    side_effect=OSError("simulated interrupted publication"),
                ):
                    with self.assertRaisesRegex(
                        OSError, "simulated interrupted publication"
                    ):
                        build("00000000000a", 1_900_000_000_100_000_000)
                self.assertEqual(state_path.read_bytes(), before)
                self.assertEqual(
                    list(job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.tmp")), []
                )
                third, _ = build(
                    "00000000000b", 1_900_000_000_200_000_000
                )

        self.assertEqual(
            third["scope"]["started_at_unix_ns"],
            first["scope"]["started_at_unix_ns"] + 1,
        )

    def test_corrupt_order_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                build("000000000006", 2_000_000_000_500_000_000)
                state_path = next(job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.json"))
                state_path.write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError, "decision review ordering state"
                ):
                    build("000000000007", 1_900_000_000_100_000_000)

    def test_legacy_scope_without_fine_ordering_evidence_stays_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                origin, _ = build("000000000008", None)
                state_root_exists = job_origin.DECISION_REVIEW_ORDER_ROOT.exists()

        self.assertEqual(origin["created_at_unix"], 1_787_000_000)
        self.assertNotIn("started_at_unix_ns", origin["scope"])
        self.assertFalse(state_root_exists)


if __name__ == "__main__":
    unittest.main()
