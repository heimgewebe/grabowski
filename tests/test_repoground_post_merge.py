from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_repoground_post_merge as post_merge  # noqa: E402


MERGE = "a" * 40
HEAD = "b" * 40
REPO = "heimgewebe/demo"


def publisher_result(status: str = "ok", returncode: int = 0) -> dict[str, object]:
    return {
        "returncode": returncode,
        "payload": {"status": status},
        "stderr": "",
    }


def freshness(
    *,
    state: str,
    bundle: str,
    live: str,
    remote: str | None = None,
) -> dict[str, object]:
    return {
        "freshness": state,
        "freshness_status": "fresh" if state == "fresh_exact" else "stale",
        "reason": "test",
        "bundle": {"git_commit": bundle},
        "live_repo": {
            "repo_path": "/tmp/repo",
            "head": live,
            "branch_head_observation": {
                "status": "observed",
                "head": remote if remote is not None else live,
            },
        },
    }


def captain_result(
    *,
    merge_sha: str | None = MERGE,
    completed: bool = True,
    verified: bool = True,
    queued: bool = False,
    reconciliation_merge_sha: str | None = None,
) -> dict[str, object]:
    execution: dict[str, object] = {
        "action": "pr-merge",
        "repo": REPO,
        "verification_passed": verified,
        "merge_completion_verified": completed,
        "merge_queued": queued,
        "verified_pr": {
            "mergeCommit": {"oid": merge_sha} if merge_sha is not None else None
        },
    }
    if reconciliation_merge_sha is not None:
        execution["post_merge_reconciliation"] = {
            "status": "verified_base_mutation_pr_metadata_unsettled",
            "errors": [],
            "merge_sha": reconciliation_merge_sha,
        }
    return {"output": {"executions": [execution]}}


class RepoGroundPostMergeConvergenceTests(unittest.TestCase):
    def test_busy_retries_then_fresh_exact(self) -> None:
        publishes = iter([publisher_result("busy"), publisher_result("ok")])
        sleeps: list[float] = []

        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher=Path("/publisher"),
            publisher_runner=lambda _argv, _timeout: next(publishes),
            freshness_reader=lambda _repo: freshness(
                state="fresh_exact", bundle=HEAD, live=HEAD
            ),
            ancestry_checker=lambda _path, merge, head: (merge, head) == (MERGE, HEAD),
            sleep_fn=sleeps.append,
            busy_sleep_seconds=2,
            max_attempts=3,
        )

        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(
            [item["publisher_status"] for item in result["attempts"]],
            ["busy", "ok"],
        )
        self.assertEqual(sleeps, [2])

    def test_stale_after_publish_republishes_until_exact(self) -> None:
        freshness_values = iter(
            [
                freshness(state="stale_head", bundle=MERGE, live=HEAD),
                freshness(state="fresh_exact", bundle=HEAD, live=HEAD),
            ]
        )
        publish_count = 0

        def run_publisher(_argv: list[str], _timeout: int) -> dict[str, object]:
            nonlocal publish_count
            publish_count += 1
            return publisher_result()

        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher_runner=run_publisher,
            freshness_reader=lambda _repo: next(freshness_values),
            ancestry_checker=lambda _path, _merge, _head: True,
            sleep_fn=lambda _seconds: None,
            max_attempts=3,
        )

        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(publish_count, 2)

    def test_persistent_busy_fails_bounded(self) -> None:
        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher_runner=lambda _argv, _timeout: publisher_result("busy"),
            freshness_reader=lambda _repo: (_ for _ in ()).throw(
                AssertionError("freshness must not be read while busy")
            ),
            ancestry_checker=lambda _path, _merge, _head: True,
            sleep_fn=lambda _seconds: None,
            max_attempts=2,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "publisher_busy_exhausted")
        self.assertEqual(len(result["attempts"]), 2)

    def test_publisher_failure_is_not_reported_fresh(self) -> None:
        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher_runner=lambda _argv, _timeout: publisher_result(
                "error", returncode=1
            ),
            freshness_reader=lambda _repo: (_ for _ in ()).throw(
                AssertionError("freshness must not be read after publisher failure")
            ),
            ancestry_checker=lambda _path, _merge, _head: True,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "publisher_failed")

    def test_merge_must_remain_ancestor_of_final_head(self) -> None:
        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher_runner=lambda _argv, _timeout: publisher_result(),
            freshness_reader=lambda _repo: freshness(
                state="fresh_exact", bundle=HEAD, live=HEAD
            ),
            ancestry_checker=lambda _path, _merge, _head: False,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "merge_not_ancestor_of_live_head")

    def test_remote_head_must_match_bundle_and_live_head(self) -> None:
        result = post_merge.converge(
            repository=REPO,
            merge_sha=MERGE,
            publisher_runner=lambda _argv, _timeout: publisher_result(),
            freshness_reader=lambda _repo: freshness(
                state="fresh_exact", bundle=HEAD, live=HEAD, remote="c" * 40
            ),
            ancestry_checker=lambda _path, _merge, _head: True,
            sleep_fn=lambda _seconds: None,
            max_attempts=1,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "freshness_not_converged")


class RepoGroundPostMergeJobStarterResolutionTests(unittest.TestCase):
    def test_resolves_normally_imported_operator_module(self) -> None:
        def starter(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"unit": "grabowski-job-normal"}

        modules = {
            "grabowski_operator": types.SimpleNamespace(grabowski_job_start=starter),
            "__main__": types.SimpleNamespace(
                __spec__=types.SimpleNamespace(name="unrelated_main"),
            ),
        }

        self.assertIs(post_merge.resolve_job_starter(modules), starter)

    def test_resolves_python_dash_m_operator_main_module(self) -> None:
        def starter(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"unit": "grabowski-job-main"}

        modules = {
            "__main__": types.SimpleNamespace(
                __spec__=types.SimpleNamespace(name="grabowski_operator"),
                grabowski_job_start=starter,
            ),
        }

        self.assertIs(post_merge.resolve_job_starter(modules), starter)

    def test_rejects_unrelated_main_module(self) -> None:
        modules = {
            "__main__": types.SimpleNamespace(
                __spec__=types.SimpleNamespace(name="some_other_module"),
                grabowski_job_start=lambda *_args, **_kwargs: {},
            ),
        }

        self.assertIsNone(post_merge.resolve_job_starter(modules))


class RepoGroundPostMergeSchedulingTests(unittest.TestCase):
    def test_verified_merge_schedules_durable_freshness_job(self) -> None:
        calls: list[dict[str, object]] = []

        def start_job(
            argv: list[str], *, cwd: str, runtime_seconds: int
        ) -> dict[str, object]:
            calls.append({"argv": argv, "cwd": cwd, "runtime_seconds": runtime_seconds})
            return {
                "unit": "grabowski-job-123456789abc",
                "job_id": "123456789abc",
                "argv_sha256": "c" * 64,
                "expected_receipt": {"status_tool": "grabowski_job_status"},
            }

        result = post_merge.schedule_from_captain_result(
            captain_result(),
            job_starter=start_job,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "scheduled")
        self.assertEqual(result["repository"], REPO)
        self.assertEqual(result["merge_sha"], MERGE)
        self.assertEqual(result["unit"], "grabowski-job-123456789abc")
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["runtime_seconds"], post_merge.DEFAULT_JOB_RUNTIME_SECONDS
        )
        self.assertEqual(calls[0]["argv"][-4:], ["--repo", REPO, "--merge-sha", MERGE])

    def test_exact_base_reconciliation_merge_sha_can_schedule(self) -> None:
        result = post_merge.schedule_from_captain_result(
            captain_result(
                merge_sha=None,
                reconciliation_merge_sha=MERGE,
            ),
            job_starter=lambda *_args, **_kwargs: {
                "unit": "grabowski-job-abcdef123456"
            },
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "scheduled")
        self.assertEqual(result["merge_sha"], MERGE)

    def test_queued_merge_does_not_schedule_before_completion(self) -> None:
        started = False

        def start_job(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal started
            started = True
            return {"unit": "grabowski-job-should-not-start"}

        result = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=start_job,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "pending_merge_queue")
        self.assertEqual(result["reason"], "merge_queued_not_completed")
        self.assertFalse(started)

    def test_unverified_merge_does_not_schedule(self) -> None:
        result = post_merge.schedule_from_captain_result(
            captain_result(verified=False),
            job_starter=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("job must not start")
            ),
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "not_scheduled")
        self.assertEqual(result["reason"], "merge_verification_not_passed")

    def test_unknown_job_dispatch_does_not_reclassify_merge_failure(self) -> None:
        class UnknownDispatch(RuntimeError):
            unit = "grabowski-job-unknown123456"

        def start_job(*_args: object, **_kwargs: object) -> dict[str, object]:
            raise UnknownDispatch("synthetic uncertain launch")

        result = post_merge.schedule_from_captain_result(
            captain_result(),
            job_starter=start_job,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "schedule_unknown")
        self.assertEqual(result["unit"], "grabowski-job-unknown123456")
        self.assertIn("job_not_started", result["does_not_establish"])
        self.assertIn("merge_failure", result["does_not_establish"])


if __name__ == "__main__":
    unittest.main()
