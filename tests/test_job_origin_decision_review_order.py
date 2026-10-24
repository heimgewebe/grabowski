from pathlib import Path
import errno
import hashlib
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


class RepoGroundReservedJobOriginTests(unittest.TestCase):
    def test_reserved_unit_must_not_allocate_decision_review_clock(self) -> None:
        unit = "grabowski-job-rgpm-" + "a" * 16 + "-01"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "canonical 12-hex"):
                job_origin.build_origin(
                    unit=unit, owner=f"uid:{os.getuid()}",
                    argv_sha256="e" * 64,
                    scope=scope(1_900_000_000_100_000_000),
                    notify_on_done={"requested": False, "channels": []},
                    created_at_unix=1_900_000_000,
                    started_at="2030-03-17T17:46:40Z",
                    invoker_tool="grabowski_job_start",
                    jobs_root=root / "jobs", order_root=root / "order",
                )
            self.assertFalse((root / "order").exists())

    def test_reserved_unit_origin_round_trip_remains_exact(self) -> None:
        unit = "grabowski-job-rgpm-" + "a" * 16 + "-01"
        origin, digest = job_origin.build_origin(
            unit=unit,
            owner=f"uid:{os.getuid()}",
            argv_sha256="e" * 64,
            scope={
                "cwd": "/tmp",
                "argv_sha256": "e" * 64,
                "runtime_seconds": 60,
            },
            notify_on_done={"requested": False, "channels": []},
            created_at_unix=100,
            started_at="1970-01-01T00:01:40Z",
            invoker_tool="grabowski_job_start",
        )
        self.assertEqual(origin["unit"], unit)
        self.assertEqual(origin["job_id"], "rgpm-" + "a" * 16 + "-01")
        self.assertEqual(
            job_origin.validate_origin(origin, digest, expected_unit=unit),
            origin,
        )

    def test_reserved_unit_name_admits_no_other_shapes(self) -> None:
        names = (
            "grabowski-job-rgpm-" + "a" * 15 + "-01",
            "grabowski-job-rgpm-" + "a" * 17 + "-01",
            "grabowski-job-rgpm-" + "a" * 16 + "-1",
            "grabowski-job-rgpm-" + "a" * 16 + "-001",
            "grabowski-job-rgpm-" + "z" * 16 + "-01",
            "grabowski-job-rgpm-" + "a" * 16 + "-0x",
            "grabowski-job-rgpm-" + "a" * 16 + "-01-extra",
        )
        for name in names:
            with self.subTest(unit=name):
                self.assertIsNone(job_origin.UNIT_RE.fullmatch(name))
        self.assertIsNotNone(
            job_origin.UNIT_RE.fullmatch("grabowski-job-" + "f" * 12)
        )


class DecisionReviewLogicalClockTests(unittest.TestCase):
    def test_historical_over_10k_job_dirs_keep_causal_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                previous, previous_hash = build("ffffffffffff", 2_000_000_000_500_000_000)
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, exist_ok=True, mode=0o700)
                folder = jobs / "grabowski-job-ffffffffffff"
                folder.mkdir(mode=0o700)
                metadata = folder / "metadata.json"
                metadata.write_text(
                    json.dumps({"origin": previous, "origin_sha256": previous_hash}),
                    encoding="utf-8",
                )
                os.chmod(metadata, 0o600)
                next(job_origin.DECISION_REVIEW_ORDER_ROOT.glob("*.json")).unlink()
                for number in range(10_010):
                    (jobs / f"grabowski-job-{number:012x}").mkdir(mode=0o700)
                current, _ = build("eeeeeeeeeeee", 1_900_000_000_100_000_000)
        self.assertEqual(current["scope"]["started_at_unix_ns"],
                         previous["scope"]["started_at_unix_ns"] + 1)

    def test_hard_typed_scan_budget_stays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b, mock.patch.object(job_origin, "DECISION_REVIEW_ORDER_MAX_JOB_DIRECTORIES", 2):
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                for number in range(3):
                    (jobs / f"grabowski-job-{number:012x}").mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, "directory limit"):
                    build("ffffffffffff", 1_900_000_000_100_000_000)

    def test_noncanonical_metadata_never_disappears_from_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                other = jobs / "foreign-claimed-review"
                other.mkdir(mode=0o700)
                metadata = other / "metadata.json"
                metadata.write_text("{}", encoding="utf-8")
                metadata.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "noncanonical job metadata"):
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)

    def test_nonmatching_names_still_consume_global_scan_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b, mock.patch.object(
                job_origin, "DECISION_REVIEW_ORDER_MAX_JOB_DIRECTORIES", 2
            ):
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                for number in range(3):
                    (jobs / f"unrelated-{number}.json").write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "directory limit"):
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)

    def test_canonical_job_symlink_cannot_redirect_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                outside = Path(temp) / "outside"
                outside.mkdir(mode=0o700)
                (jobs / "grabowski-job-ffffffffffff").symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "directory changed or is unsafe"):
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)

    def test_metadata_symlink_not_followed_even_inside_owned_job(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                job = jobs / "grabowski-job-ffffffffffff"
                job.mkdir(mode=0o700)
                target = Path(temp) / "secret.txt"
                target.write_text("secret", encoding="utf-8")
                (job / "metadata.json").symlink_to(target)
                with self.assertRaises(OSError) as failure:
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)
                self.assertEqual(failure.exception.errno, errno.ELOOP)

    def test_aggregate_metadata_budget_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b, mock.patch.object(
                job_origin, "DECISION_REVIEW_ORDER_MAX_TOTAL_METADATA_BYTES", 3
            ):
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                job = jobs / "grabowski-job-ffffffffffff"
                job.mkdir(mode=0o700)
                metadata = job / "metadata.json"
                metadata.write_text("{}", encoding="utf-8")
                os.chmod(metadata, 0o600)
                (job / "metadata.json").write_text('{"scope":null}', encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "aggregate budget"):
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)

    def test_noncanonical_symlink_cannot_hide_review_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                other = Path(temp) / "other"
                other.mkdir(mode=0o700)
                (jobs / "foreign-claimed-review").symlink_to(other)
                with self.assertRaisesRegex(ValueError, "directory changed or is unsafe"):
                    build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)

    def test_noncanonical_unreadable_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            a, b = self.roots(temp)
            with a, b:
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                other = jobs / "foreign-unreadable"
                other.mkdir(mode=0o700)
                other.chmod(0)
                try:
                    with self.assertRaisesRegex(
                        ValueError, "directory changed or is unsafe"
                    ):
                        build("aaaaaaaaaaaa", 1_900_000_000_100_000_000)
                finally:
                    other.chmod(0o700)

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
                job_directory.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                job_directory.mkdir(mode=0o700)
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

    def test_child_metadata_published_after_visit_invalidates_bootstrap(self) -> None:
        # Updating an already visited child leaves the JOBS ROOT timestamp
        # unchanged. An order-state rebuild must not accept that stale scan.
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                initial, digest = build("000000000004", 2_000_000_000_500_000_000)
                jobs = job_origin.DECISION_REVIEW_JOBS_ROOT
                jobs.mkdir(parents=True, mode=0o700)
                first = jobs / "grabowski-job-000000000004"
                second = jobs / "grabowski-job-000000000005"
                first.mkdir(mode=0o700)
                second.mkdir(mode=0o700)
                metadata = first / "metadata.json"
                metadata.write_text(
                    json.dumps({"origin": initial, "origin_sha256": digest}),
                    encoding="utf-8",
                )
                metadata.chmod(0o600)
                ordinary = second / "metadata.json"
                ordinary.write_text("{}", encoding="utf-8")
                ordinary.chmod(0o600)
                key = job_origin._decision_review_order_key(initial["scope"])
                original_open = job_origin.os.open
                visited = []
                triggered = []

                def inject(path, flags, *args, **kwargs):
                    if (
                        path in (first.name, second.name)
                        and kwargs.get("dir_fd") is not None
                    ):
                        if not visited:
                            visited.append(path)
                        elif path != visited[0] and not triggered:
                            # Mutate the child already visited, regardless of
                            # filesystem-dependent scandir iteration order.
                            prior = jobs / visited[0]
                            changed = json.loads(json.dumps(initial))
                            changed["unit"] = prior.name
                            changed["scope"]["started_at_unix_ns"] += 1000
                            changed_digest = hashlib.sha256(
                                job_origin.canonical_json_bytes(changed)
                            ).hexdigest()
                            replacement = prior / "metadata.next"
                            replacement.write_text(
                                json.dumps({
                                    "origin": changed,
                                    "origin_sha256": changed_digest,
                                }), encoding="utf-8",
                            )
                            replacement.chmod(0o600)
                            os.replace(replacement, prior / "metadata.json")
                            triggered.append(True)
                    return original_open(path, flags, *args, **kwargs)

                with mock.patch.object(job_origin.os, "open", side_effect=inject):
                    with self.assertRaisesRegex(
                        ValueError, "changed during scan"
                    ):
                        job_origin._existing_decision_review_max_ns(
                            key, jobs_root=jobs,
                        )
                self.assertEqual(triggered, [True])

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