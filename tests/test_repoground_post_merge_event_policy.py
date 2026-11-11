"""Regression: post-merge publication obeys the installed Fleet event opt-out.

The RepoGround source-publishing obligation must not be held hostage by the
separately disabled authenticated Git/CI event handoff. Existing receipts are
not deleted or reclassified by this caller.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_repoground_post_merge as post_merge  # noqa: E402


class PostMergePublisherEventPolicyTests(unittest.TestCase):
    def test_publisher_command_uses_existing_fleet_event_opt_out(self) -> None:
        self.assertEqual(
            post_merge._publisher_command(
                Path("/publisher"), "heimgewebe/commonthing"
            ),
            [
                "/publisher",
                "--repo",
                "heimgewebe/commonthing",
                "--if-changed",
                "--no-authenticated-events",
                "--retention",
                "3",
            ],
        )

    def test_converge_passes_event_opt_out_without_weakening_freshness(self) -> None:
        merge_sha = "a" * 40
        head = "b" * 40
        calls: list[list[str]] = []

        def publish(argv: list[str], _timeout: int) -> dict[str, object]:
            calls.append(list(argv))
            return {"returncode": 0, "payload": {"status": "ok"}, "stderr": ""}

        result = post_merge.converge(
            repository="heimgewebe/commonthing",
            merge_sha=merge_sha,
            publisher=Path("/publisher"),
            publisher_runner=publish,
            freshness_reader=lambda _repo: {
                "freshness": "fresh_exact",
                "freshness_status": "fresh",
                "bundle": {"git_commit": head},
                "live_repo": {
                    "repo_path": "/tmp/repo",
                    "source_kind": "publication_source_checkout",
                    "head": head,
                    "branch_head_observation": {"status": "observed", "head": head},
                },
            },
            ancestry_checker=lambda _path, old, current: (
                old, current
            ) == (merge_sha, head),
            max_attempts=1,
        )
        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(len(calls), 1)
        self.assertIn("--no-authenticated-events", calls[0])


if __name__ == "__main__":
    unittest.main()