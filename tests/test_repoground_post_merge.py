from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_repoground_post_merge as post_merge  # noqa: E402


MERGE = "a" * 40
HEAD = "b" * 40
REPO = "heimgewebe/demo"
PR = 96
BASE = "main"


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
    source_kind: str = "publication_source_checkout",
) -> dict[str, object]:
    return {
        "freshness": state,
        "freshness_status": "fresh" if state == "fresh_exact" else "stale",
        "reason": "test",
        "bundle": {"git_commit": bundle},
        "live_repo": {
            "repo_path": "/tmp/repo",
            "source_kind": source_kind,
            "head": live,
            **(
                {
                    "branch_head_observation": {
                        "status": "observed",
                        "head": remote if remote is not None else live,
                    }
                }
                if source_kind == "publication_source_checkout"
                else {}
            ),
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
        "pr": PR,
        "expected_head": HEAD,
        "expected_base": BASE,
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


    def test_conventional_checkout_requires_remote_exactness_only_in_post_merge(self) -> None:
        with patch.object(post_merge, "_read_remote_main_head", return_value=HEAD):
            result = post_merge.converge(
                repository=REPO,
                merge_sha=MERGE,
                publisher_runner=lambda _argv, _timeout: publisher_result(),
                freshness_reader=lambda _repo: freshness(
                    state="fresh_exact",
                    bundle=HEAD,
                    live=HEAD,
                    source_kind="conventional_checkout",
                ),
                ancestry_checker=lambda _path, _merge, _head: True,
                sleep_fn=lambda _seconds: None,
                max_attempts=1,
            )
        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(result["final"]["remote_head"], HEAD)

    def test_conventional_checkout_remote_unavailable_is_explicit_failure(self) -> None:
        with patch.object(
            post_merge,
            "_read_remote_main_head",
            side_effect=post_merge.RepoGroundPostMergeError("synthetic unavailable"),
        ):
            result = post_merge.converge(
                repository=REPO,
                merge_sha=MERGE,
                publisher_runner=lambda _argv, _timeout: publisher_result(),
                freshness_reader=lambda _repo: freshness(
                    state="fresh_exact",
                    bundle=HEAD,
                    live=HEAD,
                    source_kind="conventional_checkout",
                ),
                ancestry_checker=lambda _path, _merge, _head: True,
                sleep_fn=lambda _seconds: None,
                max_attempts=3,
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "authoritative_remote_head_unavailable")
        self.assertEqual(len(result["attempts"]), 1)


class RepoGroundPublisherBoundTests(unittest.TestCase):
    def test_stdout_limit_is_enforced_while_publisher_runs(self) -> None:
        code = (
            "import sys,time;"
            "sys.stdout.write('x'*4096);"
            "sys.stdout.flush();"
            "time.sleep(5)"
        )
        with patch.object(post_merge, "MAX_PUBLISH_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError,
                "stdout exceeds bounded output",
            ):
                post_merge._run_publisher([sys.executable, "-c", code], 5)

    def test_stderr_limit_is_enforced_while_publisher_runs(self) -> None:
        code = (
            "import sys,time;"
            "sys.stderr.write('x'*4096);"
            "sys.stderr.flush();"
            "time.sleep(5)"
        )
        with patch.object(post_merge, "MAX_PUBLISH_OUTPUT_BYTES", 1024):
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError,
                "stderr exceeds bounded output",
            ):
                post_merge._run_publisher([sys.executable, "-c", code], 5)


    def test_timeout_still_applies_after_child_closes_output_pipes(self) -> None:
        code = (
            "import os,time;"
            "os.close(1);"
            "os.close(2);"
            "time.sleep(5)"
        )
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            post_merge._run_bounded_process(
                [sys.executable, "-c", code],
                1,
                max_output_bytes=1024,
            )
        self.assertLess(time.monotonic() - started, 3)


class RepoGroundMergeQueueWatchTests(unittest.TestCase):
    @staticmethod
    def _view(
        state: str,
        *,
        head: str = HEAD,
        base: str = BASE,
        merge_sha: str | None = None,
    ) -> dict[str, object]:
        return {
            "number": PR,
            "state": state,
            "headRefOid": head,
            "baseRefName": base,
            "mergeCommit": (
                {"oid": merge_sha}
                if merge_sha is not None
                else None
            ),
        }

    def test_waits_for_merge_then_runs_existing_convergence(self) -> None:
        views = iter(
            [
                self._view("OPEN"),
                self._view("MERGED", merge_sha=MERGE),
            ]
        )
        sleeps: list[float] = []
        converged: list[tuple[str, str]] = []

        def converge_queue(repository: str, merge_sha: str) -> dict[str, object]:
            converged.append((repository, merge_sha))
            return {"status": "fresh_exact"}

        result = post_merge.watch_merge_queue(
            repository=REPO,
            pull_request=PR,
            expected_head=HEAD,
            expected_base=BASE,
            max_attempts=3,
            poll_seconds=2,
            queue_reader=lambda _repo, _pr: next(views),
            queue_converger=converge_queue,
            sleep_fn=sleeps.append,
        )

        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(result["reason"], "merge_queue_completed_and_freshness_converged")
        self.assertEqual(result["merge_sha"], MERGE)
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(converged, [(REPO, MERGE)])
        self.assertEqual(sleeps, [2])

    def test_transient_queue_read_error_is_retried(self) -> None:
        calls = 0

        def read_queue(_repo: str, _pr: int) -> dict[str, object]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise post_merge.RepoGroundPostMergeError("temporary read failure")
            return self._view("MERGED", merge_sha=MERGE)

        result = post_merge.watch_merge_queue(
            repository=REPO,
            pull_request=PR,
            expected_head=HEAD,
            expected_base=BASE,
            max_attempts=2,
            poll_seconds=0,
            queue_reader=read_queue,
            queue_converger=lambda _repo, _sha: {"status": "fresh_exact"},
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(calls, 2)
        self.assertEqual(result["attempt_count"], 2)

    def test_identity_drift_fails_before_convergence(self) -> None:
        converged = False

        def converge_queue(_repository: str, _merge_sha: str) -> dict[str, object]:
            nonlocal converged
            converged = True
            return {"status": "fresh_exact"}

        result = post_merge.watch_merge_queue(
            repository=REPO,
            pull_request=PR,
            expected_head=HEAD,
            expected_base=BASE,
            max_attempts=1,
            poll_seconds=0,
            queue_reader=lambda _repo, _pr: self._view(
                "MERGED",
                head="c" * 40,
                merge_sha=MERGE,
            ),
            queue_converger=converge_queue,
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "merge_queue_identity_mismatch")
        self.assertFalse(converged)

    def test_watch_deadline_preserves_convergence_runtime_reserve(self) -> None:
        now = [0.0]
        reads = 0

        def read_queue(_repo: str, _pr: int) -> dict[str, object]:
            nonlocal reads
            reads += 1
            now[0] += 1
            return self._view("OPEN")

        def sleep(seconds: float) -> None:
            now[0] += seconds

        result = post_merge.watch_merge_queue(
            repository=REPO,
            pull_request=PR,
            expected_head=HEAD,
            expected_base=BASE,
            max_attempts=50,
            poll_seconds=5,
            watch_seconds=12,
            queue_reader=read_queue,
            queue_converger=lambda _repo, _sha: (_ for _ in ()).throw(
                AssertionError("deadline exhaustion must not start convergence")
            ),
            sleep_fn=sleep,
            monotonic_fn=lambda: now[0],
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "merge_queue_watch_deadline_exhausted")
        self.assertEqual(result["attempt_count"], 2)
        self.assertEqual(reads, 2)
        self.assertEqual(now[0], 12)

    def test_watch_rejects_budget_that_uses_convergence_reserve(self) -> None:
        with self.assertRaisesRegex(
            post_merge.RepoGroundPostMergeError,
            "queue watch_seconds is out of bounds",
        ):
            post_merge.watch_merge_queue(
                repository=REPO,
                pull_request=PR,
                expected_head=HEAD,
                expected_base=BASE,
                max_attempts=1,
                poll_seconds=0,
                watch_seconds=post_merge.DEFAULT_QUEUE_WATCH_SECONDS + 1,
                queue_reader=lambda _repo, _pr: (_ for _ in ()).throw(
                    AssertionError("invalid budget must fail before queue read")
                ),
                sleep_fn=lambda _seconds: None,
            )

    def test_closed_without_merge_is_terminal_and_does_not_converge(self) -> None:
        result = post_merge.watch_merge_queue(
            repository=REPO,
            pull_request=PR,
            expected_head=HEAD,
            expected_base=BASE,
            max_attempts=1,
            poll_seconds=0,
            queue_reader=lambda _repo, _pr: self._view("CLOSED"),
            queue_converger=lambda _repo, _sha: (_ for _ in ()).throw(
                AssertionError("closed PR must not converge")
            ),
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "merge_queue_closed_without_merge")


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


class RepoGroundCaptainAuditFollowupTests(unittest.TestCase):
    def test_audit_bound_direct_merge_reconstructs_trusted_command(self) -> None:
        record = {
            "operation": "captain-run-audit-completion",
            "kind": "grabowski_captain_run_audit",
            "schema_version": 1,
            "phase": "completion",
            "action": "pr-merge",
            "target_repo": REPO,
            "target_pr": PR,
            "expected_head": HEAD,
            "expected_base": BASE,
            "execution_result": {
                "verification_passed": True,
                "provenance_mode": "captain_dispatch_verified",
                "observed_merge_sha": MERGE,
            },
        }
        with patch.object(
            post_merge,
            "_verified_captain_completion_record",
            return_value=record,
        ):
            request = post_merge.captain_followup_request_from_audit(
                "1" * 64,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(request["status"], "ready")
        self.assertEqual(request["repository"], REPO)
        self.assertEqual(request["merge_sha"], MERGE)
        self.assertEqual(
            request["argv"][-4:],
            ["--repo", REPO, "--merge-sha", MERGE],
        )

    def test_audit_bound_queue_reconstructs_identity_without_caller_argv(self) -> None:
        record = {
            "operation": "captain-run-audit-completion",
            "kind": "grabowski_captain_run_audit",
            "schema_version": 1,
            "phase": "completion",
            "action": "pr-merge",
            "target_repo": REPO,
            "target_pr": PR,
            "expected_head": HEAD,
            "expected_base": BASE,
            "execution_result": {
                "verification_passed": True,
                "provenance_mode": "captain_queue_dispatch_pending",
                "observed_merge_sha": None,
            },
        }
        with patch.object(
            post_merge,
            "_verified_captain_completion_record",
            return_value=record,
        ):
            request = post_merge.captain_followup_request_from_audit(
                "2" * 64,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(request["status"], "ready_queue_watch")
        self.assertEqual(request["pull_request"], PR)
        self.assertIn("--expected-head", request["argv"])
        self.assertIn(HEAD, request["argv"])
        self.assertIn("--expected-base", request["argv"])
        self.assertIn(BASE, request["argv"])

    def test_external_merge_is_not_fast_path_eligible(self) -> None:
        record = {
            "operation": "captain-run-audit-completion",
            "kind": "grabowski_captain_run_audit",
            "schema_version": 1,
            "phase": "completion",
            "action": "pr-merge",
            "target_repo": REPO,
            "target_pr": PR,
            "expected_head": HEAD,
            "expected_base": BASE,
            "execution_result": {
                "verification_passed": True,
                "provenance_mode": "external_merge_reconciled",
                "observed_merge_sha": MERGE,
            },
        }
        with patch.object(
            post_merge,
            "_verified_captain_completion_record",
            return_value=record,
        ):
            request = post_merge.captain_followup_request_from_audit(
                "3" * 64,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(request["status"], "not_scheduled")
        self.assertEqual(request["reason"], "captain_merge_not_fast_path_eligible")


class RepoGroundPostMergeAuditBindingTests(unittest.TestCase):
    def test_reconcile_scans_newest_captain_audits_first(self) -> None:
        calls: list[dict[str, object]] = []

        def query_audit(filters, *, limit, order):
            calls.append({"filters": filters, "limit": limit, "order": order})
            return {
                "items": [],
                "matched": 0,
                "truncated": False,
            }

        audit_query = types.SimpleNamespace(query_audit=query_audit)
        operator = types.SimpleNamespace()
        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": operator,
                },
            ),
            patch.object(
                post_merge,
                "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=900,
                limit=64,
            )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["matched"], 0)
        self.assertEqual(result["processed"], 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["order"], "desc")

    def test_reconcile_stops_after_first_new_job_mutation(self) -> None:
        items = [
            {
                "record": {"action": "pr-merge"},
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {"action": "pr-merge"},
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            query_audit=lambda *_args, **_kwargs: {
                "items": items,
                "matched": 2,
                "truncated": False,
            }
        )
        scheduled: list[str] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-one",
                "reused": False,
            }

        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": types.SimpleNamespace(),
                },
            ),
            patch.object(
                post_merge,
                "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
            patch.object(
                post_merge,
                "schedule_from_captain_audit_completion",
                side_effect=schedule,
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups()

        self.assertEqual(scheduled, ["1" * 64])
        self.assertEqual(result["matched"], 2)
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["outcomes"][0]["status"], "scheduled")
        self.assertFalse(result["outcomes"][0]["reused"])

    def test_verified_completion_record_uses_verified_snapshot_contract(self) -> None:
        snapshot = object()
        completion_sha = "1" * 64
        record = {
            "operation": "captain-run-audit-completion",
            "kind": "grabowski_captain_run_audit",
            "schema_version": 1,
            "phase": "completion",
            "action": "pr-merge",
        }

        audit_query = types.SimpleNamespace(
            capture_verified_audit_snapshot=lambda: snapshot,
        )

        def verified(
            record_sha256: str,
            *,
            snapshot: object,
            audit_query_module: object,
        ) -> dict[str, object]:
            self.assertEqual(record_sha256, completion_sha)
            self.assertIs(snapshot, audit_query.capture_verified_audit_snapshot())
            self.assertIs(audit_query_module, audit_query)
            return record

        orchestration = types.SimpleNamespace(
            _verified_captain_audit_record=verified,
        )
        with patch.dict(
            sys.modules,
            {
                "grabowski_audit_query": audit_query,
                "grabowski_grip_orchestration": orchestration,
            },
        ):
            result = post_merge._verified_captain_completion_record(completion_sha)

        self.assertEqual(result, record)


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

    def test_queued_merge_schedules_bound_durable_watcher(self) -> None:
        calls: list[dict[str, object]] = []

        def start_job(
            argv: list[str], *, cwd: str, runtime_seconds: int
        ) -> dict[str, object]:
            calls.append(
                {
                    "argv": argv,
                    "cwd": cwd,
                    "runtime_seconds": runtime_seconds,
                }
            )
            return {
                "unit": "grabowski-job-queue123456",
                "job_id": "queue123456",
            }

        result = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=start_job,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(result["status"], "scheduled")
        self.assertEqual(result["reason"], "durable_merge_queue_watch_started")
        self.assertEqual(result["pull_request"], PR)
        self.assertEqual(len(calls), 1)
        argv = calls[0]["argv"]
        self.assertIn("--pr", argv)
        self.assertIn(str(PR), argv)
        self.assertIn("--expected-head", argv)
        self.assertIn(HEAD, argv)
        self.assertIn("--expected-base", argv)
        self.assertIn(BASE, argv)
        self.assertNotIn("--merge-sha", argv)
        self.assertIn("--queue-watch-seconds", argv)
        watch_index = argv.index("--queue-watch-seconds")
        self.assertEqual(
            float(argv[watch_index + 1]),
            post_merge.DEFAULT_QUEUE_WATCH_SECONDS,
        )
        self.assertEqual(
            calls[0]["runtime_seconds"],
            post_merge.DEFAULT_JOB_RUNTIME_SECONDS,
        )
        self.assertEqual(
            post_merge.DEFAULT_QUEUE_WATCH_SECONDS
            + post_merge.DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS,
            post_merge.DEFAULT_JOB_RUNTIME_SECONDS,
        )
        minimum_convergence_budget = (
            post_merge.DEFAULT_MAX_ATTEMPTS
            * post_merge.DEFAULT_PUBLISH_TIMEOUT_SECONDS
            + (post_merge.DEFAULT_MAX_ATTEMPTS - 1)
            * post_merge.DEFAULT_BUSY_SLEEP_SECONDS
            + post_merge.DEFAULT_MAX_ATTEMPTS
            * post_merge.DEFAULT_ANCESTRY_TIMEOUT_SECONDS
            + post_merge.DEFAULT_QUEUE_READ_TIMEOUT_SECONDS
        )
        self.assertGreater(
            post_merge.DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS,
            minimum_convergence_budget,
        )

    def test_repeated_queued_merge_reuses_same_live_running_job(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []

        def argv_hash(_argv: list[str]) -> str:
            return "d" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            return {
                "unit": unit,
                "metadata": metadata,
                "job_record": {**metadata, "final_status": live_status[unit]},
                "final_status": live_status[unit],
            }

        def require_mutation(*_args: object, **_kwargs: object) -> None:
            return None

        def private_start(
            argv: list[str],
            *,
            cwd: str,
            runtime_seconds: int,
            reserved_unit: str,
        ) -> dict[str, object]:
            starts.append(reserved_unit)
            job: dict[str, object] = {
                "unit": reserved_unit,
                "job_id": reserved_unit.removeprefix("grabowski-job-"),
                "argv_sha256": argv_hash(argv),
                "cwd": cwd,
                "runtime_seconds": runtime_seconds,
                "final_status": "launch_submitted",
                "expected_receipt": {"status_tool": "grabowski_job_status"},
            }
            jobs[reserved_unit] = job
            live_status[reserved_unit] = "running"
            return job

        operator = types.SimpleNamespace(
            grabowski_job_start=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("public starter should be wrapped")
            ),
            grabowski_job_status=read_status,
            _argv_hash=argv_hash,
            _read_job_metadata=read_metadata,
            _require_operator_mutation=require_mutation,
            _start_job=private_start,
        )
        starter = post_merge.resolve_job_starter({"grabowski_operator": operator})
        self.assertIsNotNone(starter)

        first = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )
        second = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(len(starts), 1)
        self.assertEqual(first["unit"], second["unit"])
        self.assertEqual(jobs[first["unit"]]["final_status"], "launch_submitted")
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(first["reason"], "durable_merge_queue_watch_started")
        self.assertEqual(second["reason"], "durable_merge_queue_watch_reused")

    def test_terminal_live_status_does_not_reuse_stale_launch_metadata(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []

        def argv_hash(_argv: list[str]) -> str:
            return "e" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            return {
                "unit": unit,
                "metadata": metadata,
                "job_record": {**metadata, "final_status": live_status[unit]},
                "final_status": live_status[unit],
            }

        def private_start(
            argv: list[str],
            *,
            cwd: str,
            runtime_seconds: int,
            reserved_unit: str,
        ) -> dict[str, object]:
            starts.append(reserved_unit)
            job: dict[str, object] = {
                "unit": reserved_unit,
                "job_id": reserved_unit.removeprefix("grabowski-job-"),
                "argv_sha256": argv_hash(argv),
                "cwd": cwd,
                "runtime_seconds": runtime_seconds,
                "final_status": "launch_submitted",
            }
            jobs[reserved_unit] = job
            live_status[reserved_unit] = "running"
            return job

        operator = types.SimpleNamespace(
            grabowski_job_start=lambda *_args, **_kwargs: {},
            grabowski_job_status=read_status,
            _argv_hash=argv_hash,
            _read_job_metadata=read_metadata,
            _require_operator_mutation=lambda *_args, **_kwargs: None,
            _start_job=private_start,
        )
        starter = post_merge.resolve_job_starter({"grabowski_operator": operator})
        self.assertIsNotNone(starter)

        first = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )
        live_status[first["unit"]] = "succeeded"
        second = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(jobs[first["unit"]]["final_status"], "launch_submitted")
        self.assertEqual(len(starts), 1)
        self.assertEqual(first["unit"], second["unit"])
        self.assertEqual(second["status"], "already_satisfied")
        self.assertTrue(second["reused"])

    def test_all_terminal_live_statuses_allow_replacement_job(self) -> None:
        for terminal_status in (
            "failed",
            "timed_out",
            "signalled",
            "terminated_unclear",
            "launch_failed",
        ):
            with self.subTest(terminal_status=terminal_status):
                jobs: dict[str, dict[str, object]] = {}
                live_status: dict[str, str] = {}
                starts: list[str] = []

                def argv_hash(_argv: list[str]) -> str:
                    return "e" * 64

                def read_metadata(unit: str) -> dict[str, object]:
                    if unit not in jobs:
                        raise ValueError("missing")
                    return jobs[unit]

                def read_status(unit: str) -> dict[str, object]:
                    metadata = read_metadata(unit)
                    return {
                        "unit": unit,
                        "metadata": metadata,
                        "final_status": live_status[unit],
                    }

                def private_start(
                    argv: list[str],
                    *,
                    cwd: str,
                    runtime_seconds: int,
                    reserved_unit: str,
                ) -> dict[str, object]:
                    starts.append(reserved_unit)
                    job: dict[str, object] = {
                        "unit": reserved_unit,
                        "job_id": reserved_unit.removeprefix("grabowski-job-"),
                        "argv_sha256": argv_hash(argv),
                        "cwd": cwd,
                        "runtime_seconds": runtime_seconds,
                        "final_status": "launch_submitted",
                    }
                    jobs[reserved_unit] = job
                    live_status[reserved_unit] = "running"
                    return job

                operator = types.SimpleNamespace(
                    grabowski_job_start=lambda *_args, **_kwargs: {},
                    grabowski_job_status=read_status,
                    _argv_hash=argv_hash,
                    _read_job_metadata=read_metadata,
                    _require_operator_mutation=lambda *_args, **_kwargs: None,
                    _start_job=private_start,
                )
                starter = post_merge.resolve_job_starter({"grabowski_operator": operator})
                self.assertIsNotNone(starter)
                first = post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )
                live_status[first["unit"]] = terminal_status
                second = post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )
                self.assertEqual(len(starts), 2)
                self.assertNotEqual(first["unit"], second["unit"])
                self.assertFalse(second["reused"])


    def test_uncertain_live_queue_job_fails_closed_without_duplicate(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []

        def argv_hash(_argv: list[str]) -> str:
            return "f" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            return {
                "unit": unit,
                "metadata": metadata,
                "job_record": {**metadata, "final_status": live_status[unit]},
                "final_status": live_status[unit],
            }

        def private_start(
            argv: list[str],
            *,
            cwd: str,
            runtime_seconds: int,
            reserved_unit: str,
        ) -> dict[str, object]:
            starts.append(reserved_unit)
            job: dict[str, object] = {
                "unit": reserved_unit,
                "job_id": reserved_unit.removeprefix("grabowski-job-"),
                "argv_sha256": argv_hash(argv),
                "cwd": cwd,
                "runtime_seconds": runtime_seconds,
                "final_status": "launch_submitted",
            }
            jobs[reserved_unit] = job
            live_status[reserved_unit] = "running"
            return job

        operator = types.SimpleNamespace(
            grabowski_job_start=lambda *_args, **_kwargs: {},
            grabowski_job_status=read_status,
            _argv_hash=argv_hash,
            _read_job_metadata=read_metadata,
            _require_operator_mutation=lambda *_args, **_kwargs: None,
            _start_job=private_start,
        )
        starter = post_merge.resolve_job_starter({"grabowski_operator": operator})
        self.assertIsNotNone(starter)

        first = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )
        live_status[first["unit"]] = "missing_finalization_evidence"
        second = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(jobs[first["unit"]]["final_status"], "launch_submitted")
        self.assertEqual(len(starts), 1)
        self.assertEqual(second["status"], "schedule_unknown")
        self.assertEqual(second["reason"], "durable_job_reuse_outcome_unknown")
        self.assertEqual(second["unit"], first["unit"])

    def test_queue_watch_rejects_runtime_without_convergence_reserve(self) -> None:
        with self.assertRaisesRegex(
            post_merge.RepoGroundPostMergeError,
            "leaves no convergence reserve",
        ):
            post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=lambda *_args, **_kwargs: {
                    "unit": "grabowski-job-must-not-start"
                },
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
                runtime_seconds=post_merge.DEFAULT_CONVERGENCE_RUNTIME_RESERVE_SECONDS,
            )

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