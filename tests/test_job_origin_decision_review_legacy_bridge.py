from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

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


def build(suffix: str, *, created: int, observed_ns: int | None) -> tuple[dict, str]:
    return job_origin.build_origin(
        unit=f"grabowski-job-{suffix}",
        owner=f"uid:{os.getuid()}",
        argv_sha256="e" * 64,
        scope=scope(observed_ns),
        notify_on_done={"requested": False, "channels": []},
        created_at_unix=created,
        started_at="2026-09-15T12:00:00Z",
        invoker_tool="grabowski_job_start",
    )


def persist(jobs_root: Path, suffix: str, origin: dict, digest: str) -> None:
    directory = jobs_root / f"grabowski-job-{suffix}"
    directory.mkdir(parents=True, mode=0o700)
    metadata_path = directory / "metadata.json"
    metadata_path.write_text(
        json.dumps({"origin": origin, "origin_sha256": digest}, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(metadata_path, 0o600)


class DecisionReviewLegacyBridgeTests(unittest.TestCase):
    def roots(self, temporary: str):
        root = Path(temporary)
        return (
            mock.patch.object(job_origin, "DECISION_REVIEW_ORDER_ROOT", root / "order"),
            mock.patch.object(job_origin, "DECISION_REVIEW_JOBS_ROOT", root / "jobs"),
        )

    def test_new_causal_attempt_is_ordered_after_existing_legacy_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                legacy, legacy_digest = build(
                    "000000000101", created=2_000_000_000, observed_ns=None
                )
                persist(
                    job_origin.DECISION_REVIEW_JOBS_ROOT,
                    "000000000101",
                    legacy,
                    legacy_digest,
                )
                new, _ = build(
                    "000000000102",
                    created=1_900_000_000,
                    observed_ns=1_900_000_000_100_000_000,
                )

        self.assertGreater(new["created_at_unix"], legacy["created_at_unix"])
        self.assertGreater(
            new["scope"]["started_at_unix_ns"],
            legacy["created_at_unix"] * 1_000_000_000 + 999_999_999,
        )

    def test_each_allocation_rechecks_legacy_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            order_patch, jobs_patch = self.roots(temporary)
            with order_patch, jobs_patch:
                first, first_digest = build(
                    "000000000103",
                    created=1_900_000_000,
                    observed_ns=1_900_000_000_100_000_000,
                )
                persist(
                    job_origin.DECISION_REVIEW_JOBS_ROOT,
                    "000000000103",
                    first,
                    first_digest,
                )
                legacy, legacy_digest = build(
                    "000000000104", created=2_100_000_000, observed_ns=None
                )
                persist(
                    job_origin.DECISION_REVIEW_JOBS_ROOT,
                    "000000000104",
                    legacy,
                    legacy_digest,
                )
                second, _ = build(
                    "000000000105",
                    created=1_800_000_000,
                    observed_ns=1_800_000_000_100_000_000,
                )

        self.assertGreater(second["created_at_unix"], legacy["created_at_unix"])
        self.assertGreater(
            second["scope"]["started_at_unix_ns"],
            legacy["created_at_unix"] * 1_000_000_000 + 999_999_999,
        )


if __name__ == "__main__":
    unittest.main()
