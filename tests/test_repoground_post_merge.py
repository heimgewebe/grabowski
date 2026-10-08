from __future__ import annotations

from pathlib import Path
import sqlite3
import subprocess
import tempfile
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
        with patch.object(
            post_merge, "_read_remote_branch_head", return_value=HEAD
        ) as remote_head:
            result = post_merge.converge(
                repository=REPO,
                merge_sha=MERGE,
                target_branch="release/v1",
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
        self.assertEqual(result["final"]["target_branch"], "release/v1")
        remote_head.assert_called_once_with("/tmp/repo", "release/v1")

    def test_conventional_checkout_remote_unavailable_is_explicit_failure(self) -> None:
        with patch.object(
            post_merge,
            "_read_remote_branch_head",
            side_effect=post_merge.RepoGroundPostMergeError("synthetic unavailable"),
        ):
            result = post_merge.converge(
                repository=REPO,
                merge_sha=MERGE,
                target_branch="develop",
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

        def converge_queue(repository: str, merge_sha: str, _target_branch: str) -> dict[str, object]:
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

    def test_queue_convergence_uses_verified_base_branch(self) -> None:
        with patch.object(
            post_merge,
            "converge",
            return_value={"status": "fresh_exact"},
        ) as converge_call:
            result = post_merge.watch_merge_queue(
                repository=REPO,
                pull_request=PR,
                expected_head=HEAD,
                expected_base="release/v2",
                max_attempts=1,
                poll_seconds=0,
                queue_reader=lambda _repo, _pr: self._view(
                    "MERGED",
                    base="release/v2",
                    merge_sha=MERGE,
                ),
                sleep_fn=lambda _seconds: None,
            )

        self.assertEqual(result["status"], "fresh_exact")
        converge_call.assert_called_once_with(
            repository=REPO,
            merge_sha=MERGE,
            target_branch="release/v2",
        )

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
            queue_converger=lambda _repo, _sha, _base: {"status": "fresh_exact"},
            sleep_fn=lambda _seconds: None,
        )

        self.assertEqual(result["status"], "fresh_exact")
        self.assertEqual(calls, 2)
        self.assertEqual(result["attempt_count"], 2)

    def test_identity_drift_fails_before_convergence(self) -> None:
        converged = False

        def converge_queue(_repository: str, _merge_sha: str, _target_branch: str) -> dict[str, object]:
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
            queue_converger=lambda _repo, _sha, _base: (_ for _ in ()).throw(
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
            queue_converger=lambda _repo, _sha, _base: (_ for _ in ()).throw(
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
        self.assertEqual(request["target_branch"], BASE)
        self.assertEqual(
            request["argv"][-6:],
            ["--repo", REPO, "--merge-sha", MERGE, "--target-branch", BASE],
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
    def test_default_reconcile_lookback_outlives_durable_job_runtime(self) -> None:
        self.assertGreater(
            post_merge.DEFAULT_RECONCILE_LOOKBACK_SECONDS,
            post_merge.DEFAULT_JOB_RUNTIME_SECONDS,
        )

    def test_reconcile_scans_full_lookback_before_scheduling(self) -> None:
        now = 10_000
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "runtime-deploy",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": f"{index:064x}"},
            }
            for index in range(1, 70)
        ]
        merge_sha256 = "f" * 64
        items.extend(
            [
                {
                    "record": {
                        "operation": "captain-run-audit-completion",
                        "action": "pr-merge",
                        "timestamp_unix": 9_940,
                    },
                    "evidence": {"record_sha256": merge_sha256},
                },
                {
                    "record": {
                        "operation": "captain-run-audit-completion",
                        "action": "runtime-deploy",
                        "timestamp_unix": 8_000,
                    },
                    "evidence": {"record_sha256": "e" * 64},
                },
            ]
        )
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=1_000,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
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
            patch.object(post_merge.time, "time", return_value=now),
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
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
                limit=64,
            )

        self.assertEqual(scheduled, [merge_sha256])
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["lookback_horizon_reached"])
        self.assertGreater(result["scanned_records"], 64)

    def test_predecessor_discovery_uses_canonical_release_inputs_path(self) -> None:
        self.assertEqual(
            post_merge.DEFAULT_PREDECESSOR_RECONCILER_SOURCE.relative_to(
                Path.home()
            ),
            Path(
                ".local/share/grabowski-mcp/inputs/src/"
                "grabowski_repoground_post_merge.py"
            ),
        )

    def test_discovery_initialization_seeds_verified_tip_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            db = directory / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            snapshot = types.SimpleNamespace(total_records=1_675_780)
            reads = []
            audit = types.SimpleNamespace(
                capture_verified_audit_snapshot=lambda: (
                    reads.append(True) or snapshot
                ),
            )
            modules = {
                "grabowski_audit_query": audit,
                "grabowski_operator": types.SimpleNamespace(STATE_DIR=directory),
                "grabowski_tasks": tasks,
            }
            predecessor = directory / "not-installed.py"
            with patch.dict(sys.modules, modules):
                first = post_merge.initialize_reconcile_discovery_watermark(
                    predecessor_module_path=predecessor
                )
                self.assertTrue(first["initialized"])
                self.assertEqual(first["global_ordinal"], 1_675_780)
                snapshot.total_records = 2_000_000
                second = post_merge.initialize_reconcile_discovery_watermark(
                    predecessor_module_path=predecessor
                )
                self.assertFalse(second["initialized"])
                self.assertEqual(second["global_ordinal"], 1_675_780)
                self.assertEqual(len(reads), 1)
                self.assertEqual(
                    post_merge._load_reconcile_discovery_ordinal(tasks),
                    1_675_780,
                )

    def test_discovery_initialization_fails_closed_for_predecessor_without_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            db = directory / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            predecessor = directory / "grabowski_repoground_post_merge.py"
            predecessor.write_text("existing release", encoding="utf-8")
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            modules = {
                "grabowski_audit_query": types.SimpleNamespace(
                    capture_verified_audit_snapshot=lambda: self.fail(
                        "audit scan must not occur after ambiguous prior activation"
                    ),
                ),
                "grabowski_operator": types.SimpleNamespace(STATE_DIR=directory),
                "grabowski_tasks": tasks,
            }
            with patch.dict(sys.modules, modules):
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError,
                    "discovery watermark is missing",
                ):
                    post_merge.initialize_reconcile_discovery_watermark(
                        predecessor_module_path=predecessor
                    )
                self.assertIsNone(
                    post_merge._load_reconcile_discovery_ordinal(tasks)
                )

    def test_discovery_initialization_handles_empty_verified_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            db = directory / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            modules = {
                "grabowski_audit_query": types.SimpleNamespace(
                    capture_verified_audit_snapshot=lambda: types.SimpleNamespace(
                        total_records=0
                    ),
                ),
                "grabowski_operator": types.SimpleNamespace(STATE_DIR=directory),
                "grabowski_tasks": tasks,
            }
            with patch.dict(sys.modules, modules):
                result = post_merge.initialize_reconcile_discovery_watermark(
                    predecessor_module_path=directory / "not-installed.py"
                )
                self.assertEqual(result["global_ordinal"], 0)
                self.assertEqual(
                    post_merge._load_reconcile_discovery_ordinal(tasks), 0
                )

    def test_reconcile_resumes_from_discovery_watermark_after_long_outage(self) -> None:
        old_merge_sha256 = "a" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "runtime-deploy",
                    "timestamp_unix": 10_100,
                },
                "evidence": {
                    "record_sha256": "b" * 64,
                    "global_ordinal": 15,
                },
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 10_000,
                },
                "evidence": {
                    "record_sha256": old_merge_sha256,
                    "global_ordinal": 14,
                },
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "runtime-deploy",
                    "timestamp_unix": 9_900,
                },
                "evidence": {
                    "record_sha256": "c" * 64,
                    "global_ordinal": 12,
                },
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        scheduled: list[str] = []
        saved: list[tuple[str | None, int | None]] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-old-outage",
                "reused": False,
            }

        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": operator,
            "grabowski_tasks": tasks_module,
        }
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=20_000),
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
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=12,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(scheduled, [old_merge_sha256])
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["scanned_records"], 3)
        self.assertTrue(result["lookback_horizon_reached"])
        self.assertEqual(result["discovery_ordinal_before"], 12)
        self.assertEqual(result["discovery_ordinal_after"], 12)
        self.assertTrue(result["discovery_watermark_reached"])
        self.assertFalse(result["progress_persisted"])
        self.assertEqual(saved, [])

    def test_reconcile_bootstrap_recovers_old_merge_after_first_outage(self) -> None:
        merge_sha256 = "d" * 64
        items = [
            {
                "record": {"operation": "runtime-observation", "timestamp_unix": 49_950},
                "evidence": {"record_sha256": "e" * 64, "global_ordinal": 15},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 10_010,
                },
                "evidence": {"record_sha256": merge_sha256, "global_ordinal": 14},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        scheduled = []
        saved = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-bootstrap-outage",
                "reused": False,
            }

        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": operator,
                    "grabowski_tasks": tasks_module,
                },
            ),
            patch.object(post_merge.time, "time", return_value=50_000),
            patch.object(
                post_merge, "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
            patch.object(
                post_merge, "schedule_from_captain_audit_completion",
                side_effect=schedule,
            ),
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge, "_load_reconcile_discovery_ordinal", return_value=None,
            ),
            patch.object(
                post_merge, "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(scheduled, [merge_sha256])
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["lookback_horizon_reached"])
        self.assertFalse(result["progress_persisted"])
        self.assertEqual(saved, [])

    def test_reconcile_deferral_does_not_advance_discovery_watermark(self) -> None:
        merge_sha256 = "a" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": merge_sha256, "global_ordinal": 13},
            },
            {
                "record": {"operation": "runtime-observation", "timestamp_unix": 9_940},
                "evidence": {"record_sha256": "b" * 64, "global_ordinal": 12},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        saved = []
        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": operator,
                    "grabowski_tasks": tasks_module,
                },
            ),
            patch.object(post_merge.time, "time", return_value=10_000),
            patch.object(
                post_merge, "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
            patch.object(
                post_merge, "schedule_from_captain_audit_completion",
                return_value={
                    "status": "retry_deferred",
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO,
                    "unit": "grabowski-job-deferred",
                    "reused": True,
                },
            ),
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge, "_load_reconcile_discovery_ordinal", return_value=12,
            ),
            patch.object(
                post_merge, "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["discovery_ordinal_after"], 12)
        self.assertFalse(result["discovery_watermark_persisted"])
        self.assertEqual(saved, [(merge_sha256, None)])

    def test_reconcile_exhaustion_records_debt_before_discovery_advances(self) -> None:
        sha = "a" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": sha, "global_ordinal": 13},
            },
            {
                "record": {"operation": "routine-event", "timestamp_unix": 9_940},
                "evidence": {"record_sha256": "b" * 64, "global_ordinal": 12},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": types.SimpleNamespace(STATE_DIR=Path("/state")),
            "grabowski_tasks": types.SimpleNamespace(),
        }
        cases = (
            ("merge_verification_not_passed", True),
            ("captain_merge_not_fast_path_eligible", True),
            ("durable_freshness_job_slots_exhausted", True),
            ("unrecognized_not_scheduled_reason", False),
        )
        for reason, terminal in cases:
            with self.subTest(reason=reason):
                progress = []
                with (
                    patch.dict(sys.modules, modules),
                    patch.object(post_merge.time, "time", return_value=10_000),
                    patch.object(
                        post_merge, "resolve_job_starter",
                        return_value=lambda *_args, **_kwargs: {},
                    ),
                    patch.object(
                        post_merge, "schedule_from_captain_audit_completion",
                        return_value={
                            "status": "not_scheduled",
                            "reason": reason,
                            "repository": REPO,
                            "reused": False,
                        },
                    ),
                    patch.object(
                        post_merge, "_load_reconcile_cursor", return_value=None,
                    ),
                    patch.object(
                        post_merge, "_load_reconcile_discovery_ordinal",
                        return_value=12,
                    ),
                    patch.object(
                        post_merge, "_save_reconcile_progress",
                        side_effect=lambda _tasks, *, cursor, discovery_ordinal,
                        exhausted_completion_record_sha256s=(): progress.append(
                            (cursor, discovery_ordinal, tuple(exhausted_completion_record_sha256s))
                        ),
                    ),
                ):
                    result = post_merge.reconcile_recent_captain_audit_followups(
                        lookback_seconds=100,
                    )

                self.assertEqual(result["processed"], 1)
                self.assertEqual(result["matched"], 1)
                self.assertEqual(result["discovery_ordinal_after"], 13 if terminal else 12)
                self.assertEqual(result["discovery_watermark_persisted"], terminal)
                self.assertEqual(
                    progress,
                    [(sha, 13 if terminal else None,
                      (sha,) if reason == "durable_freshness_job_slots_exhausted" else ())],
                )
                self.assertEqual(
                    result["exhausted_obligations_recorded"],
                    [sha] if reason == "durable_freshness_job_slots_exhausted" else [],
                )

    def test_reconcile_after_exhausted_checkpoint_discovers_new_merge(self) -> None:
        old_sha, new_sha = "a" * 64, "c" * 64
        entries = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": old_sha, "global_ordinal": 13},
            },
            {
                "record": {"operation": "routine-event", "timestamp_unix": 9_940},
                "evidence": {"record_sha256": "b" * 64, "global_ordinal": 12},
            },
        ]
        query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=3,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(entries),
        )
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(database)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12
            )
            outcomes = {
                old_sha: {
                    "status": "not_scheduled",
                    "reason": "durable_freshness_job_slots_exhausted",
                    "repository": REPO,
                },
                new_sha: {
                    "status": "scheduled",
                    "reason": "durable_freshness_job_started",
                    "repository": REPO,
                    "unit": "grabowski-job-new",
                    "reused": False,
                },
            }
            with (
                patch.dict(
                    sys.modules,
                    {
                        "grabowski_audit_query": query,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path("/state")
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge,
                    "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge,
                    "schedule_from_captain_audit_completion",
                    side_effect=lambda sha, **_kwargs: outcomes[sha],
                ),
            ):
                first = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100
                )
                self.assertTrue(first["discovery_watermark_persisted"])
                self.assertEqual(first["exhausted_obligations_recorded"], [old_sha])
                self.assertEqual(
                    post_merge._load_reconcile_discovery_ordinal(tasks), 13
                )
                entries.insert(
                    0,
                    {
                        "record": {
                            "operation": "captain-run-audit-completion",
                            "action": "pr-merge",
                            "timestamp_unix": 9_960,
                        },
                        "evidence": {
                            "record_sha256": new_sha,
                            "global_ordinal": 14,
                        },
                    },
                )
                second = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100
                )
                self.assertEqual(second["matched"], 1)
                self.assertEqual(second["processed"], 1)
                self.assertEqual(second["outcomes"][0]["captain_audit_completion_sha256"], new_sha)
                self.assertEqual(second["scanned_records"], 2)
                self.assertFalse(second["progress_persisted"])

    def test_exhausted_mixed_with_deferred_is_not_exposed_until_checkpoint(self) -> None:
        exhausted, deferred, newer = "a" * 64, "b" * 64, "c" * 64
        records = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_960,
                },
                "evidence": {"record_sha256": exhausted, "global_ordinal": 14},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": deferred, "global_ordinal": 13},
            },
            {
                "record": {"operation": "routine-event", "timestamp_unix": 9_940},
                "evidence": {"record_sha256": "d" * 64, "global_ordinal": 12},
            },
        ]
        query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=4,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(records),
        )
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(database)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12
            )
            outcomes = {
                exhausted: {
                    "status": "not_scheduled",
                    "reason": "durable_freshness_job_slots_exhausted",
                    "repository": REPO,
                },
                deferred: {
                    "status": "retry_deferred",
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO,
                    "reused": True,
                },
            }
            modules = {
                "grabowski_audit_query": query,
                "grabowski_operator": types.SimpleNamespace(STATE_DIR=Path("/state")),
                "grabowski_tasks": tasks,
            }
            with (
                patch.dict(sys.modules, modules),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge, "schedule_from_captain_audit_completion",
                    side_effect=lambda sha, **_kwargs: outcomes[sha],
                ),
            ):
                blocked = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100
                )
                self.assertEqual(blocked["processed"], 2)
                self.assertFalse(blocked["discovery_watermark_persisted"])
                self.assertEqual(blocked["discovery_ordinal_after"], 12)
                self.assertEqual(blocked["exhausted_obligations_recorded"], [])
                self.assertEqual(post_merge._load_reconcile_discovery_ordinal(tasks), 12)
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "not durably registered"
                ):
                    post_merge._require_exhausted_record(tasks, exhausted)

                # Only a later fully settled read-only pass may publish the
                # exhausted obligation together with the verified audit tip.
                outcomes[deferred] = {
                    "status": "already_satisfied",
                    "reason": "durable_freshness_already_converged",
                    "repository": REPO,
                    "reused": True,
                }
                settled = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100
                )
                self.assertTrue(settled["discovery_watermark_persisted"])
                self.assertEqual(settled["discovery_ordinal_after"], 14)
                self.assertEqual(settled["exhausted_obligations_recorded"], [exhausted])
                post_merge._require_exhausted_record(tasks, exhausted)

                # A newer merge is discovered without reopening the older one.
                records.insert(
                    0,
                    {
                        "record": {
                            "operation": "captain-run-audit-completion",
                            "action": "pr-merge",
                            "timestamp_unix": 9_970,
                        },
                        "evidence": {
                            "record_sha256": newer, "global_ordinal": 15
                        },
                    },
                )
                outcomes[newer] = {
                    "status": "scheduled",
                    "reason": "durable_freshness_job_started",
                    "repository": REPO,
                    "reused": False,
                }
                later = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100
                )
                self.assertEqual(later["matched"], 1)
                self.assertEqual(later["processed"], 1)
                self.assertEqual(
                    later["outcomes"][0]["captain_audit_completion_sha256"], newer
                )
                self.assertFalse(later["discovery_watermark_persisted"])

    def test_reconcile_partial_pass_does_not_skip_unprocessed_audits(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950 - i,
                },
                "evidence": {
                    "record_sha256": str(i + 1) * 64,
                    "global_ordinal": 14 - i,
                },
            }
            for i in range(2)
        ]
        items.append({
            "record": {"operation": "runtime-observation", "timestamp_unix": 9_940},
            "evidence": {"record_sha256": "3" * 64, "global_ordinal": 12},
        })
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        saved = []
        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": operator,
                    "grabowski_tasks": tasks_module,
                },
            ),
            patch.object(post_merge.time, "time", return_value=10_000),
            patch.object(post_merge.time, "monotonic", side_effect=[0.0, 0.0, 1000.0]),
            patch.object(
                post_merge, "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
            patch.object(
                post_merge, "schedule_from_captain_audit_completion",
                return_value={
                    "status": "already_satisfied",
                    "reason": "durable_freshness_already_converged",
                    "repository": REPO,
                    "unit": None,
                    "reused": True,
                },
            ),
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge, "_load_reconcile_discovery_ordinal", return_value=12,
            ),
            patch.object(
                post_merge, "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(result["matched"], 2)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(result["discovery_ordinal_after"], 12)
        self.assertFalse(result["discovery_watermark_persisted"])
        self.assertEqual(saved, [("1" * 64, None)])

    def test_reconcile_bootstrap_lookback_avoids_historical_replay(self) -> None:
        old_merge_sha256 = "d" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "runtime-deploy",
                    "timestamp_unix": 9_950,
                },
                "evidence": {
                    "record_sha256": "e" * 64,
                    "global_ordinal": 15,
                },
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 8_000,
                },
                "evidence": {
                    "record_sha256": old_merge_sha256,
                    "global_ordinal": 14,
                },
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        saved: list[tuple[str | None, int | None]] = []

        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": operator,
            "grabowski_tasks": tasks_module,
        }
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=10_000),
            patch.object(
                post_merge,
                "resolve_job_starter",
                return_value=lambda *_args, **_kwargs: {},
            ),
            patch.object(
                post_merge,
                "schedule_from_captain_audit_completion",
                return_value={
                    "status": "already_satisfied",
                    "reason": "durable_freshness_already_converged",
                    "repository": REPO,
                    "merge_sha": MERGE,
                    "unit": None,
                    "reused": True,
                },
            ),
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=None,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["lookback_horizon_reached"])
        self.assertEqual(result["discovery_ordinal_after"], 15)
        self.assertTrue(result["discovery_watermark_persisted"])
        self.assertTrue(result["progress_persisted"])
        self.assertEqual(saved, [(old_merge_sha256, 15)])

    def test_reconcile_skips_irrelevant_legacy_timestamp_before_parsing(self) -> None:
        merge_sha256 = "d" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": merge_sha256},
            },
            {
                "record": {
                    "operation": "legacy",
                    "timestamp": "before-v2",
                },
                "evidence": {"record_sha256": "c" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
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
            patch.object(post_merge.time, "time", return_value=10_000),
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
            result = post_merge.reconcile_recent_captain_audit_followups(
                lookback_seconds=100,
            )

        self.assertEqual(scheduled, [merge_sha256])
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["scanned_records"], 2)
        self.assertFalse(result["lookback_horizon_reached"])

    def test_reconcile_stops_after_first_new_job_mutation(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_940,
                },
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
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
            patch.object(post_merge.time, "time", return_value=10_000),
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
        self.assertEqual(result["processing_order"], "cursor_round_robin_newest_seed")

    def test_reconcile_accepts_projected_iso_timestamp_without_unix_field(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp": "1970-01-01T02:45:50+00:00",
                },
                "evidence": {"record_sha256": "1" * 64},
            }
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
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
            patch.object(post_merge.time, "time", return_value=10_000),
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
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["processed"], 1)

    def test_reconcile_retry_backoff_allows_older_pending_merge_to_progress(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_940,
                },
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        scheduled: list[str] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            if record_sha256 == "1" * 64:
                return {
                    "status": "retry_deferred",
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO,
                    "unit": "grabowski-job-newest",
                    "reused": True,
                }
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-older",
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
            patch.object(post_merge.time, "time", return_value=10_000),
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

        self.assertEqual(scheduled, ["1" * 64, "2" * 64])
        self.assertEqual(result["processed"], 2)
        self.assertEqual(
            [item["status"] for item in result["outcomes"]],
            ["retry_deferred", "scheduled"],
        )

    def test_reconcile_exhausted_newest_allows_older_pending_merge_to_progress(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_940,
                },
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        scheduled: list[str] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            if record_sha256 == "1" * 64:
                return {
                    "status": "not_scheduled",
                    "reason": "durable_freshness_job_slots_exhausted",
                    "repository": REPO,
                    "merge_sha": MERGE,
                    "reused": False,
                }
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-older",
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
            patch.object(post_merge.time, "time", return_value=10_000),
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

        self.assertEqual(scheduled, ["1" * 64, "2" * 64])
        self.assertEqual(result["processed"], 2)
        self.assertEqual(
            [item["status"] for item in result["outcomes"]],
            ["not_scheduled", "scheduled"],
        )
        self.assertEqual(
            result["outcomes"][0]["reason"],
            "durable_freshness_job_slots_exhausted",
        )

    def test_reconcile_pass_budget_stops_before_next_expensive_identity(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_940,
                },
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        scheduled: list[str] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            return {
                "status": "retry_deferred",
                "reason": "durable_freshness_job_retry_backoff",
                "repository": REPO,
                "unit": "grabowski-job-oldest",
                "reused": True,
            }

        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": types.SimpleNamespace(),
                },
            ),
            patch.object(post_merge.time, "time", return_value=10_000),
            patch.object(
                post_merge.time,
                "monotonic",
                side_effect=[0.0, 0.0, 181.0],
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
        self.assertEqual(result["processed"], 1)
        self.assertTrue(result["budget_exhausted"])
        self.assertEqual(result["remaining"], 1)
        self.assertEqual(
            result["pass_budget_seconds"],
            post_merge.DEFAULT_RECONCILE_PASS_BUDGET_SECONDS,
        )

    def test_reconcile_cursor_persists_in_existing_task_metadata_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )

            tasks_module = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(database)
            )
            cursor = "c" * 64
            post_merge._save_reconcile_cursor(tasks_module, cursor)
            self.assertEqual(post_merge._load_reconcile_cursor(tasks_module), cursor)
            post_merge._save_reconcile_progress(
                tasks_module,
                cursor=None,
                discovery_ordinal=17,
            )
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks_module),
                17,
            )

            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE metadata SET value=? WHERE key=?",
                    (
                        '{"schema_version":1,"cursor":"invalid"}',
                        post_merge.RECONCILE_CURSOR_METADATA_KEY,
                    ),
                )
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError,
                "cursor identity is invalid",
            ):
                post_merge._load_reconcile_cursor(tasks_module)

    def test_exhausted_recovery_inventory_is_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            first_sha, second_sha = "a" * 64, "b" * 64
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(first_sha, second_sha),
            )
            with patch.dict(sys.modules, {"grabowski_tasks": tasks}):
                first = post_merge.list_exhausted_audit_followups(limit=1)
                self.assertTrue(first["truncated"])
                self.assertEqual(first["returned"], 1)
                self.assertEqual(
                    first["items"],
                    [{"captain_audit_completion_sha256": first_sha}],
                )
                second = post_merge.list_exhausted_audit_followups(
                    limit=1, after_sha256=first["next_after_sha256"],
                )
                self.assertFalse(second["truncated"])
                self.assertEqual(
                    second["items"],
                    [{"captain_audit_completion_sha256": second_sha}],
                )
                with self.assertRaises(post_merge.RepoGroundPostMergeError):
                    post_merge.list_exhausted_audit_followups(after_sha256="invalid")
                with sqlite3.connect(db) as connection:
                    connection.execute(
                        "UPDATE metadata SET value=? WHERE key=?",
                        ('{"schema_version":999}',
                         post_merge._exhausted_record_key(second_sha)),
                    )
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "invalid"
                ):
                    post_merge.list_exhausted_audit_followups(
                        limit=1, after_sha256=first_sha
                    )

    def test_manual_exhausted_recovery_uses_only_existing_publisher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            sha = "a" * 64
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(sha,),
            )
            request = {
                "status": "ready", "repository": REPO,
                "merge_sha": MERGE, "target_branch": BASE,
            }
            with (
                patch.dict(sys.modules, {"grabowski_tasks": tasks}),
                patch.object(
                    post_merge, "captain_followup_request_from_audit",
                    return_value=request,
                ),
                patch.object(
                    post_merge, "converge",
                    return_value={"status": "fresh_exact"},
                ) as publisher,
                patch.object(
                    post_merge, "watch_merge_queue",
                    side_effect=AssertionError("queue watcher not requested"),
                ),
            ):
                result = post_merge.recover_exhausted_audit_followup(sha)
                self.assertEqual(result["status"], "fresh_exact")
                self.assertTrue(result["ledger_retained"])
                self.assertTrue(result["acknowledgement_required"])
                publisher.assert_called_once_with(
                    repository=REPO, merge_sha=MERGE, target_branch=BASE
                )
                post_merge._require_exhausted_record(tasks, sha)

    def test_exhausted_ack_requires_fresh_remote_and_is_a_separate_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            sha = "a" * 64
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(sha,),
            )
            request = {
                "status": "ready", "repository": REPO,
                "merge_sha": MERGE, "target_branch": BASE,
            }
            with (
                patch.dict(sys.modules, {"grabowski_tasks": tasks}),
                patch.object(
                    post_merge, "captain_followup_request_from_audit",
                    return_value=request,
                ),
                patch.object(
                    post_merge, "_read_freshness",
                    return_value=freshness(
                        state="fresh_exact", bundle=HEAD, live=HEAD, remote=HEAD
                    ),
                ),
                patch.object(post_merge, "_check_ancestry", return_value=True),
                patch.object(
                    post_merge, "_read_remote_branch_head",
                    side_effect=["c" * 40, HEAD],
                ),
                patch.object(
                    post_merge, "converge",
                    side_effect=AssertionError("ACK must not publish"),
                ),
            ):
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "newer origin branch"
                ):
                    post_merge.acknowledge_exhausted_audit_followup(sha)
                post_merge._require_exhausted_record(tasks, sha)
                ack = post_merge.acknowledge_exhausted_audit_followup(sha)
                self.assertEqual(ack["status"], "ok")
                self.assertEqual(ack["authoritative_head"], HEAD)
                self.assertTrue(ack["ledger_removed"])
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "not durably registered"
                ):
                    post_merge.acknowledge_exhausted_audit_followup(sha)

    def test_acknowledged_debt_is_not_resurrected_when_cursor_and_watermark_do_not_change(self) -> None:
        exhausted = "e" * 64
        cursor = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=cursor, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(exhausted,),
            )
            request = {
                "status": "ready", "repository": REPO,
                "merge_sha": MERGE, "target_branch": BASE,
            }
            with (
                patch.dict(sys.modules, {"grabowski_tasks": tasks}),
                patch.object(
                    post_merge, "captain_followup_request_from_audit",
                    return_value=request,
                ),
                patch.object(
                    post_merge, "_read_freshness",
                    return_value=freshness(
                        state="fresh_exact", bundle=HEAD, live=HEAD, remote=HEAD
                    ),
                ),
                patch.object(post_merge, "_check_ancestry", return_value=True),
                patch.object(
                    post_merge, "_read_remote_branch_head", return_value=HEAD,
                ),
            ):
                acknowledged = post_merge.acknowledge_exhausted_audit_followup(
                    exhausted
                )
            self.assertTrue(acknowledged["ledger_removed"])
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 12
            )
            self.assertEqual(post_merge._load_reconcile_cursor(tasks), cursor)
            # An old Reconcile attempt still sees exactly its expected CAS
            # progress after the ACK. The ACK must be monotone per audit ID.
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError, "already acknowledged"
            ):
                post_merge._save_reconcile_progress(
                    tasks,
                    cursor=None,
                    discovery_ordinal=None,
                    exhausted_completion_record_sha256s=(exhausted,),
                    expected_discovery_ordinal=12,
                    expected_cursor=cursor,
                )
            with sqlite3.connect(db) as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT value FROM metadata WHERE key=?",
                        (post_merge._exhausted_record_key(exhausted),),
                    ).fetchone()
                )
                tombstone = connection.execute(
                    "SELECT value FROM metadata WHERE key=?",
                    (post_merge._acknowledged_record_key(exhausted),),
                ).fetchone()
            self.assertIsNotNone(tombstone)
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 12
            )
            self.assertEqual(post_merge._load_reconcile_cursor(tasks), cursor)

            # Future passes must treat a verified immutable ACK as satisfied,
            # not touch exhausted systemd slots or try to recreate the debt.
            items = [
                {
                    "record": {
                        "operation": "captain-run-audit-completion",
                        "action": "pr-merge",
                        "timestamp_unix": 9_950,
                    },
                    "evidence": {
                        "record_sha256": exhausted, "global_ordinal": 13,
                    },
                },
                {
                    "record": {"operation": "routine-event", "timestamp_unix": 9_940},
                    "evidence": {
                        "record_sha256": "b" * 64, "global_ordinal": 12,
                    },
                },
            ]
            audit = types.SimpleNamespace(
                MAX_SCAN_RECORDS=100,
                capture_verified_audit_snapshot=lambda: object(),
                _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
            )
            with (
                patch.dict(
                    sys.modules, {
                        "grabowski_audit_query": audit,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path(temporary),
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge, "schedule_from_captain_audit_completion",
                    side_effect=AssertionError(
                        "an acknowledged audit must not be scheduled again"
                    ),
                ),
            ):
                observed = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100,
                )
            self.assertEqual(observed["matched"], 1)
            self.assertEqual(observed["processed"], 1)
            self.assertEqual(
                observed["outcomes"][0]["reason"],
                "durable_exhausted_audit_previously_acknowledged",
            )
            self.assertEqual(observed["discovery_ordinal_after"], 13)
            self.assertFalse(post_merge._read_exhausted_acknowledgement(tasks, "b" * 64))
            self.assertTrue(post_merge._read_exhausted_acknowledgement(tasks, exhausted))
            with sqlite3.connect(db) as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT value FROM metadata WHERE key=?",
                        (post_merge._exhausted_record_key(exhausted),),
                    ).fetchone()
                )

    def test_exhausted_ack_tombstone_failure_preserves_original_ledger(self) -> None:
        exhausted = "f" * 64
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TRIGGER deny_ack BEFORE INSERT ON metadata "
                    "WHEN NEW.key LIKE 'repoground_post_merge_ack_v1:%' "
                    "BEGIN SELECT RAISE(ABORT, 'ack marker denied'); END"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(exhausted,),
            )
            request = {
                "status": "ready", "repository": REPO,
                "merge_sha": MERGE, "target_branch": BASE,
            }
            with (
                patch.dict(sys.modules, {"grabowski_tasks": tasks}),
                patch.object(
                    post_merge, "captain_followup_request_from_audit",
                    return_value=request,
                ),
                patch.object(
                    post_merge, "_read_freshness",
                    return_value=freshness(
                        state="fresh_exact", bundle=HEAD, live=HEAD, remote=HEAD
                    ),
                ),
                patch.object(post_merge, "_check_ancestry", return_value=True),
                patch.object(
                    post_merge, "_read_remote_branch_head", return_value=HEAD,
                ),
            ):
                with self.assertRaises(sqlite3.IntegrityError):
                    post_merge.acknowledge_exhausted_audit_followup(exhausted)
            post_merge._require_exhausted_record(tasks, exhausted)
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 12
            )

    def test_corrupt_ack_tombstone_fails_closed_before_debt_insert(self) -> None:
        exhausted = "d" * 64
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES(?, ?)",
                    (
                        "repoground_post_merge_ack_v1:" + exhausted,
                        '{"schema_version":999}',
                    ),
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError,
                "acknowledgement record is invalid",
            ):
                post_merge._save_reconcile_progress(
                    tasks, cursor=None, discovery_ordinal=14,
                    exhausted_completion_record_sha256s=(exhausted,),
                )
            with sqlite3.connect(db) as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT value FROM metadata WHERE key=?",
                        (post_merge._exhausted_record_key(exhausted),),
                    ).fetchone()
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT value FROM metadata WHERE key=?",
                        (post_merge.RECONCILE_DISCOVERY_METADATA_KEY,),
                    ).fetchone()
                )

    def test_queue_exhausted_recovery_checks_verified_identity_before_ack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            sha = "a" * 64
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12,
                exhausted_completion_record_sha256s=(sha,),
            )
            request = {
                "status": "ready_queue_watch", "repository": REPO,
                "pull_request": PR, "expected_head": HEAD, "expected_base": BASE,
            }
            observed = {
                "number": PR, "state": "MERGED", "headRefOid": HEAD,
                "baseRefName": BASE, "mergeCommit": {"oid": MERGE},
            }
            with (
                patch.dict(sys.modules, {"grabowski_tasks": tasks}),
                patch.object(
                    post_merge, "captain_followup_request_from_audit",
                    return_value=request,
                ),
                patch.object(
                    post_merge, "watch_merge_queue",
                    return_value={"status": "fresh_exact"},
                ) as watch,
                patch.object(post_merge, "_read_queue_pr", return_value=observed) as read_pr,
                patch.object(
                    post_merge, "_read_freshness",
                    return_value=freshness(
                        state="fresh_exact", bundle=HEAD, live=HEAD, remote=HEAD
                    ),
                ),
                patch.object(post_merge, "_check_ancestry", return_value=True),
                patch.object(post_merge, "_read_remote_branch_head", return_value=HEAD),
            ):
                recovered = post_merge.recover_exhausted_audit_followup(sha)
                self.assertEqual(recovered["status"], "fresh_exact")
                watch.assert_called_once_with(
                    repository=REPO, pull_request=PR,
                    expected_head=HEAD, expected_base=BASE,
                )
                observed["headRefOid"] = "f" * 40
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "verified merged identity"
                ):
                    post_merge.acknowledge_exhausted_audit_followup(sha)
                post_merge._require_exhausted_record(tasks, sha)
                observed["headRefOid"] = HEAD
                result = post_merge.acknowledge_exhausted_audit_followup(sha)
                self.assertTrue(result["ledger_removed"])
                self.assertEqual(read_pr.call_count, 2)

    def test_more_than_one_hundred_exhausted_audits_are_checkpointed_in_pages(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {
                    "record_sha256": f"{ordinal:064x}",
                    "global_ordinal": ordinal,
                },
            }
            for ordinal in range(1, 121)
        ]
        segment = types.SimpleNamespace(
            global_start_ordinal=1,
            global_end_ordinal=120,
            records=120,
            items=items,
        )
        snapshot = types.SimpleNamespace(
            total_records=120, segments=(segment,)
        )
        def iterator(view: object, *, order: str):
            values = [
                item for part in view.segments for item in part.items
            ]
            return iter(values if order == "asc" else list(reversed(values)))
        query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=200,
            capture_verified_audit_snapshot=lambda: snapshot,
            _iter_snapshot_items=iterator,
        )
        handled: list[str] = []
        def classify(sha: str, **_kwargs: object) -> dict:
            handled.append(sha)
            return {
                "status": "not_scheduled",
                "reason": "durable_freshness_job_slots_exhausted",
                "repository": REPO,
            }
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=0
            )
            with (
                patch.dict(
                    sys.modules,
                    {
                        "grabowski_audit_query": query,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path(temporary)
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge,
                    "schedule_from_captain_audit_completion",
                    side_effect=classify,
                ),
            ):
                first = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100, limit=64
                )
                self.assertEqual(first["scan_mode"], "bounded_rotation")
                self.assertEqual(first["matched"], 64)
                self.assertEqual(first["processed"], 64)
                self.assertEqual(first["discovery_ordinal_after"], 64)
                self.assertEqual(len(first["exhausted_obligations_recorded"]), 64)
                second = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100, limit=64
                )
            self.assertEqual(second["matched"], 56)
            self.assertEqual(second["processed"], 56)
            self.assertEqual(second["discovery_ordinal_after"], 120)
            self.assertEqual(len(second["exhausted_obligations_recorded"]), 56)
            self.assertEqual(len(handled), 120)
            self.assertEqual(
                set(handled),
                {f"{ordinal:064x}" for ordinal in range(1, 121)},
            )
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 120
            )
            with sqlite3.connect(db) as connection:
                count = connection.execute(
                    "SELECT count(*) FROM metadata WHERE key LIKE ?",
                    (post_merge.RECONCILE_EXHAUSTED_METADATA_PREFIX + "%",),
                ).fetchone()[0]
            self.assertEqual(count, 120)

    def test_exact_scan_limit_uses_bounded_window_and_checks_boundary(self) -> None:
        merge_sha256 = "a" * 64
        items = [
            {
                "record": {
                    "operation": (
                        "captain-run-audit-completion"
                        if ordinal == 13 else "routine-observation"
                    ),
                    "action": "pr-merge" if ordinal == 13 else "other",
                    "timestamp_unix": 9_950,
                },
                "evidence": {
                    "record_sha256": (
                        merge_sha256 if ordinal == 13 else f"{ordinal:064x}"
                    ),
                    "global_ordinal": ordinal,
                },
            }
            for ordinal in range(10, 14)
        ]
        segment = types.SimpleNamespace(
            global_start_ordinal=10,
            global_end_ordinal=13,
            records=4,
            items=items,
        )
        snapshot = types.SimpleNamespace(
            total_records=13,
            segments=(segment,),
        )

        def verified_iterator(snapshot_view: object, *, order: str):
            values = [
                item for part in snapshot_view.segments for item in part.items
            ]
            return iter(values if order == "asc" else list(reversed(values)))

        audit = types.SimpleNamespace(
            MAX_SCAN_RECORDS=3,
            capture_verified_audit_snapshot=lambda: snapshot,
            _iter_snapshot_items=verified_iterator,
        )
        scheduled: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=10
            )

            def schedule(record_sha256: str, **_kwargs: object) -> dict:
                scheduled.append(record_sha256)
                return {
                    "status": "already_satisfied",
                    "reason": "durable_freshness_already_converged",
                    "repository": REPO,
                    "reused": True,
                }

            with (
                patch.dict(
                    sys.modules,
                    {
                        "grabowski_audit_query": audit,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path(temporary)
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge, "schedule_from_captain_audit_completion",
                    side_effect=schedule,
                ),
            ):
                result = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100,
                )
        self.assertEqual(result["scan_mode"], "bounded_rotation")
        self.assertEqual(result["scanned_records"], 3)
        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["discovery_ordinal_after"], 13)
        self.assertEqual(scheduled, [merge_sha256])

    def test_bounded_audit_rotation_recovers_merge_beyond_scan_cap(self) -> None:
        old_sha, new_sha = "a" * 64, "b" * 64
        def item(ordinal: int, *, sha: str | None = None) -> dict:
            completion = sha is not None
            return {
                "record": {
                    "operation": (
                        "captain-run-audit-completion" if completion else "routine-event"
                    ),
                    **({"action": "pr-merge"} if completion else {}),
                    "timestamp_unix": 9_950 + ordinal,
                },
                "evidence": {
                    "record_sha256": sha if completion else f"{ordinal:064x}",
                    "global_ordinal": ordinal,
                },
            }
        older = types.SimpleNamespace(
            global_start_ordinal=11, global_end_ordinal=14,
            records=4, items=[item(11, sha=old_sha), item(12),
                              item(13), item(14)],
        )
        newer = types.SimpleNamespace(
            global_start_ordinal=15, global_end_ordinal=18,
            records=4, items=[item(15, sha=new_sha), item(16),
                              item(17), item(18)],
        )
        snapshot = types.SimpleNamespace(
            total_records=18, segments=(older, newer),
        )
        def verified_iterator(snap: object, *, order: str):
            self.assertIn(order, {"asc", "desc"})
            values = [value for seg in snap.segments for value in seg.items]
            return iter(values if order == "asc" else list(reversed(values)))
        audit = types.SimpleNamespace(
            MAX_SCAN_RECORDS=3,
            capture_verified_audit_snapshot=lambda: snapshot,
            _iter_snapshot_items=verified_iterator,
        )
        states = {"old": "retry_deferred", "new": "scheduled"}
        newly_started: list[str] = []
        def schedule(record_sha256: str, **_kw: object) -> dict:
            if record_sha256 == old_sha:
                return {
                    "status": states["old"],
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO, "reused": True,
                }
            self.assertEqual(record_sha256, new_sha)
            current = states["new"]
            if current == "scheduled":
                newly_started.append(record_sha256)
                states["new"] = "already_satisfied"
            return {
                "status": current,
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "reused": current != "scheduled",
                "unit": "grabowski-job-new",
            }
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(database)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=10
            )
            modules = {
                "grabowski_audit_query": audit,
                "grabowski_operator": types.SimpleNamespace(STATE_DIR=Path("/state")),
                "grabowski_tasks": tasks,
            }
            with (
                patch.dict(sys.modules, modules),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge, "schedule_from_captain_audit_completion",
                    side_effect=schedule,
                ),
            ):
                def step() -> dict:
                    return post_merge.reconcile_recent_captain_audit_followups(
                        lookback_seconds=100
                    )
                first = step()
                self.assertEqual(first["scanned_records"], 3)
                self.assertEqual(first["scan_next_after"], 14)
                self.assertEqual(first["discovery_ordinal_after"], 10)
                second = step()
                self.assertEqual(second["scanned_records"], 3)
                self.assertEqual(second["matched"], 1)
                self.assertEqual(newly_started, [new_sha])
                self.assertFalse(second["progress_persisted"])
                third = step()
                self.assertEqual(third["scan_next_after"], 17)
                fourth = step()
                self.assertEqual(fourth["scan_next_after"], 11)
                self.assertEqual(newly_started, [new_sha])
                states["old"] = "already_satisfied"
                resumed = step()
                self.assertEqual(resumed["discovery_ordinal_after"], 13)
                self.assertEqual(step()["discovery_ordinal_after"], 16)
                self.assertEqual(step()["discovery_ordinal_after"], 18)
                self.assertEqual(
                    post_merge._load_reconcile_discovery_ordinal(tasks), 18
                )

    def test_slow_exhausted_window_checkpoints_terminal_prefix_before_budget(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {
                    "record_sha256": f"{ordinal:064x}",
                    "global_ordinal": ordinal,
                },
            }
            for ordinal in range(1, 5)
        ]
        segment = types.SimpleNamespace(
            global_start_ordinal=1,
            global_end_ordinal=4,
            records=4,
            items=items,
        )
        snapshot = types.SimpleNamespace(total_records=4, segments=(segment,))

        def iterator(view: object, *, order: str):
            values = [item for seg in view.segments for item in seg.items]
            return iter(values if order == "asc" else list(reversed(values)))

        audit = types.SimpleNamespace(
            MAX_SCAN_RECORDS=10,
            capture_verified_audit_snapshot=lambda: snapshot,
            _iter_snapshot_items=iterator,
        )
        calls: list[str] = []

        def schedule(sha: str, **_kwargs: object) -> dict:
            calls.append(sha)
            return {
                "status": "not_scheduled",
                "reason": "durable_freshness_job_slots_exhausted",
                "repository": REPO,
            }

        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=0
            )
            with (
                patch.dict(
                    sys.modules,
                    {
                        "grabowski_audit_query": audit,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path(temporary)
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
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
                with patch.object(
                    post_merge.time,
                    "monotonic",
                    side_effect=[0.0, 0.0, 3.0, 181.0],
                ):
                    first = post_merge.reconcile_recent_captain_audit_followups(
                        lookback_seconds=100, limit=4
                    )
                self.assertTrue(first["budget_exhausted"])
                self.assertEqual(first["processed"], 2)
                self.assertEqual(first["discovery_ordinal_after"], 2)
                self.assertTrue(first["discovery_watermark_persisted"])
                self.assertEqual(
                    first["exhausted_obligations_recorded"],
                    ["1".zfill(64), "2".zfill(64)],
                )
                self.assertEqual(first["scan_next_after"], 3)
                self.assertEqual(
                    post_merge._load_reconcile_discovery_ordinal(tasks), 2
                )
                second = post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100, limit=4
                )
            self.assertEqual(second["discovery_ordinal_after"], 4)
            self.assertTrue(second["discovery_watermark_persisted"])
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 4
            )
            self.assertEqual(
                set(calls), {f"{ordinal:064x}" for ordinal in range(1, 5)}
            )
            with sqlite3.connect(db) as connection:
                rows = connection.execute(
                    "SELECT key FROM metadata WHERE key LIKE ?",
                    (post_merge.RECONCILE_EXHAUSTED_METADATA_PREFIX + "%",),
                ).fetchall()
            self.assertEqual(len(rows), 4)

    def test_stale_reconciliation_cannot_resurrect_acknowledged_debt(self) -> None:
        exhausted = "e" * 64
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor="a" * 64, discovery_ordinal=12
            )
            post_merge._save_reconcile_progress(
                tasks, cursor="b" * 64, discovery_ordinal=14,
                exhausted_completion_record_sha256s=(exhausted,),
                expected_discovery_ordinal=12,
                expected_cursor="a" * 64,
            )
            # Manual recovery was independently verified and acknowledged.
            key = post_merge._exhausted_record_key(exhausted)
            with sqlite3.connect(db) as connection:
                connection.execute("DELETE FROM metadata WHERE key=?", (key,))
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError, "changed"
            ):
                post_merge._save_reconcile_progress(
                    tasks, cursor="c" * 64, discovery_ordinal=13,
                    exhausted_completion_record_sha256s=(exhausted,),
                    expected_discovery_ordinal=12,
                    expected_cursor="a" * 64,
                )
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 14
            )
            self.assertEqual(
                post_merge._load_reconcile_cursor(tasks), "b" * 64
            )
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError, "not durably registered"
            ):
                post_merge._require_exhausted_record(tasks, exhausted)

    def test_reconcile_rejects_peer_watermark_change_before_debt_insert(self) -> None:
        exhausted = "e" * 64
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {
                    "record_sha256": exhausted,
                    "global_ordinal": 13,
                },
            },
            {
                "record": {"operation": "routine-event", "timestamp_unix": 9_940},
                "evidence": {"record_sha256": "f" * 64, "global_ordinal": 12},
            },
        ]
        audit = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor=None, discovery_ordinal=12
            )

            def simulate_peer_before_persist(sha: str, **kwargs: object) -> dict:
                # Another pass checkpoints the same exhausted identity, then
                # an operator ACKs the now recovered obligation.
                self.assertEqual(sha, exhausted)
                post_merge._save_reconcile_progress(
                    tasks, cursor="a" * 64, discovery_ordinal=13,
                    exhausted_completion_record_sha256s=(exhausted,),
                )
                with sqlite3.connect(db) as connection:
                    connection.execute(
                        "DELETE FROM metadata WHERE key=?",
                        (post_merge._exhausted_record_key(exhausted),),
                    )
                return {
                    "status": "not_scheduled",
                    "reason": "durable_freshness_job_slots_exhausted",
                    "repository": REPO,
                }

            with (
                patch.dict(
                    sys.modules,
                    {
                        "grabowski_audit_query": audit,
                        "grabowski_operator": types.SimpleNamespace(
                            STATE_DIR=Path("/state")
                        ),
                        "grabowski_tasks": tasks,
                    },
                ),
                patch.object(post_merge.time, "time", return_value=10_000),
                patch.object(
                    post_merge, "resolve_job_starter",
                    return_value=lambda *_args, **_kwargs: {},
                ),
                patch.object(
                    post_merge, "schedule_from_captain_audit_completion",
                    side_effect=simulate_peer_before_persist,
                ),
            ):
                with self.assertRaisesRegex(
                    post_merge.RepoGroundPostMergeError, "changed"
                ):
                    post_merge.reconcile_recent_captain_audit_followups(
                        lookback_seconds=100
                    )
            self.assertEqual(
                post_merge._load_reconcile_discovery_ordinal(tasks), 13
            )
            self.assertEqual(
                post_merge._load_reconcile_cursor(tasks), "a" * 64
            )
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError, "not durably registered"
            ):
                post_merge._require_exhausted_record(tasks, exhausted)

    def test_reconcile_cursor_cas_rejects_parallel_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(db) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(db)
            )
            post_merge._save_reconcile_progress(
                tasks, cursor="a" * 64, discovery_ordinal=12
            )
            post_merge._save_reconcile_progress(
                tasks, cursor="b" * 64, discovery_ordinal=None,
                expected_discovery_ordinal=12, expected_cursor="a" * 64,
            )
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError, "changed"
            ):
                post_merge._save_reconcile_progress(
                    tasks, cursor="c" * 64, discovery_ordinal=None,
                    expected_discovery_ordinal=12, expected_cursor="a" * 64,
                )
            self.assertEqual(
                post_merge._load_reconcile_cursor(tasks), "b" * 64
            )

    def test_exhausted_debt_and_watermark_commit_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "tasks.sqlite3"
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
            tasks = types.SimpleNamespace(
                _database_connection=lambda: sqlite3.connect(database)
            )
            exhausted = "d" * 64
            post_merge._save_reconcile_progress(
                tasks,
                cursor="a" * 64,
                discovery_ordinal=13,
                exhausted_completion_record_sha256s=(exhausted,),
            )
            with sqlite3.connect(database) as connection:
                payload = connection.execute(
                    "SELECT value FROM metadata WHERE key=?",
                    (post_merge.RECONCILE_EXHAUSTED_METADATA_PREFIX + exhausted,),
                ).fetchone()
                self.assertIsNotNone(payload)
                self.assertEqual(
                    __import__("json").loads(payload[0])["status"],
                    "manual_recovery_required",
                )
                connection.execute(
                    "CREATE TRIGGER reject_debt BEFORE INSERT ON metadata "
                    "WHEN NEW.key LIKE 'repoground_post_merge_exhausted_v1:%' "
                    "BEGIN SELECT RAISE(ABORT, 'debt rejected'); END"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                post_merge._save_reconcile_progress(
                    tasks,
                    cursor="b" * 64,
                    discovery_ordinal=14,
                    exhausted_completion_record_sha256s=("e" * 64,),
                )
            self.assertEqual(post_merge._load_reconcile_cursor(tasks), "a" * 64)
            self.assertEqual(post_merge._load_reconcile_discovery_ordinal(tasks), 13)
            with sqlite3.connect(database) as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT value FROM metadata WHERE key=?",
                        (post_merge.RECONCILE_EXHAUSTED_METADATA_PREFIX + "e" * 64,),
                    ).fetchone()
                )

    def test_reconcile_skips_cursor_write_when_same_pass_starts_job(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950 - index,
                },
                "evidence": {"record_sha256": str(index + 1) * 64},
            }
            for index in range(3)
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        scheduled: list[str] = []
        saved: list[tuple[str | None, int | None]] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            if record_sha256 == "1" * 64:
                return {
                    "status": "retry_deferred",
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO,
                    "unit": "grabowski-job-one",
                    "reused": True,
                }
            if record_sha256 == "2" * 64:
                return {
                    "status": "already_satisfied",
                    "reason": "durable_freshness_already_converged",
                    "repository": REPO,
                    "unit": "grabowski-job-two",
                    "reused": True,
                }
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-three",
                "reused": False,
            }

        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": operator,
            "grabowski_tasks": tasks_module,
        }
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=10_000),
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
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=None,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups()

        self.assertEqual(scheduled, ["1" * 64, "2" * 64, "3" * 64])
        self.assertEqual(saved, [])
        self.assertIsNone(result["cursor_after"])
        self.assertFalse(result["cursor_persisted"])
        self.assertTrue(result["cursor_persistence_available"])

    def test_reconcile_persists_cursor_once_after_read_only_pass(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950 - index,
                },
                "evidence": {"record_sha256": str(index + 1) * 64},
            }
            for index in range(2)
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        saved: list[tuple[str | None, int | None]] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            return {
                "status": "retry_deferred",
                "reason": "durable_freshness_job_retry_backoff",
                "repository": REPO,
                "unit": f"grabowski-job-{record_sha256[0]}",
                "reused": True,
            }

        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": operator,
            "grabowski_tasks": tasks_module,
        }
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=10_000),
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
            patch.object(post_merge, "_load_reconcile_cursor", return_value=None),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=None,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=lambda _tasks, *, cursor, discovery_ordinal: saved.append(
                    (cursor, discovery_ordinal)
                ),
            ),
        ):
            result = post_merge.reconcile_recent_captain_audit_followups()

        self.assertEqual(saved, [("2" * 64, None)])
        self.assertEqual(result["cursor_after"], "2" * 64)
        self.assertTrue(result["cursor_persisted"])

    def test_reconcile_cursor_rotates_after_budget_limited_read_only_work(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_950,
                },
                "evidence": {"record_sha256": "1" * 64},
            },
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "pr-merge",
                    "timestamp_unix": 9_940,
                },
                "evidence": {"record_sha256": "2" * 64},
            },
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=100,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        operator = types.SimpleNamespace(STATE_DIR=Path("/state"))
        tasks_module = types.SimpleNamespace()
        cursor_state: dict[str, str | None] = {"value": None}
        scheduled: list[str] = []

        def schedule(record_sha256: str, **_kwargs: object) -> dict[str, object]:
            scheduled.append(record_sha256)
            if record_sha256 == "1" * 64:
                return {
                    "status": "retry_deferred",
                    "reason": "durable_freshness_job_retry_backoff",
                    "repository": REPO,
                    "unit": "grabowski-job-newer",
                    "reused": True,
                }
            return {
                "status": "scheduled",
                "reason": "durable_freshness_job_started",
                "repository": REPO,
                "merge_sha": MERGE,
                "unit": "grabowski-job-older",
                "reused": False,
            }

        def save_progress(
            _tasks: object,
            *,
            cursor: str | None,
            discovery_ordinal: int | None,
        ) -> None:
            self.assertIsNone(discovery_ordinal)
            if cursor is not None:
                cursor_state["value"] = cursor

        modules = {
            "grabowski_audit_query": audit_query,
            "grabowski_operator": operator,
            "grabowski_tasks": tasks_module,
        }
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=10_000),
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
            patch.object(
                post_merge,
                "_load_reconcile_cursor",
                side_effect=lambda _tasks: cursor_state["value"],
            ),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=None,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=save_progress,
            ),
            patch.object(post_merge.time, "monotonic", side_effect=[0.0, 0.0, 181.0]),
        ):
            first = post_merge.reconcile_recent_captain_audit_followups()

        self.assertEqual(scheduled, ["1" * 64])
        self.assertTrue(first["budget_exhausted"])
        self.assertEqual(first["cursor_before"], None)
        self.assertEqual(first["cursor_after"], "1" * 64)
        self.assertEqual(cursor_state["value"], "1" * 64)

        scheduled.clear()
        with (
            patch.dict(sys.modules, modules),
            patch.object(post_merge.time, "time", return_value=10_000),
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
            patch.object(
                post_merge,
                "_load_reconcile_cursor",
                side_effect=lambda _tasks: cursor_state["value"],
            ),
            patch.object(
                post_merge,
                "_load_reconcile_discovery_ordinal",
                return_value=None,
            ),
            patch.object(
                post_merge,
                "_save_reconcile_progress",
                side_effect=save_progress,
            ),
            patch.object(post_merge.time, "monotonic", side_effect=[1_000.0, 1_000.0]),
        ):
            second = post_merge.reconcile_recent_captain_audit_followups()

        self.assertEqual(scheduled, ["2" * 64])
        self.assertEqual(second["cursor_before"], "1" * 64)
        self.assertEqual(second["cursor_after"], "1" * 64)
        self.assertEqual(cursor_state["value"], "1" * 64)
        self.assertFalse(second["cursor_persisted"])
        self.assertFalse(second["budget_exhausted"])

    def test_reconcile_fails_before_mutation_when_scan_limit_hides_horizon(self) -> None:
        items = [
            {
                "record": {
                    "operation": "captain-run-audit-completion",
                    "action": "runtime-deploy",
                    "timestamp_unix": 9_950 - index,
                },
                "evidence": {"record_sha256": f"{index + 1:064x}"},
            }
            for index in range(4)
        ]
        audit_query = types.SimpleNamespace(
            MAX_SCAN_RECORDS=3,
            capture_verified_audit_snapshot=lambda: object(),
            _iter_snapshot_items=lambda _snapshot, *, order: iter(items),
        )
        with (
            patch.dict(
                sys.modules,
                {
                    "grabowski_audit_query": audit_query,
                    "grabowski_operator": types.SimpleNamespace(),
                },
            ),
            patch.object(post_merge.time, "time", return_value=10_000),
            patch.object(
                post_merge,
                "resolve_job_starter",
                side_effect=AssertionError("mutation path must not be reached"),
            ),
        ):
            with self.assertRaisesRegex(
                post_merge.RepoGroundPostMergeError,
                "scan truncated before discovery boundary",
            ):
                post_merge.reconcile_recent_captain_audit_followups(
                    lookback_seconds=100,
                )


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
        self.assertEqual(
            calls[0]["argv"][-6:],
            ["--repo", REPO, "--merge-sha", MERGE, "--target-branch", BASE],
        )

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

    def test_running_job_reuses_semantic_identity_across_release_paths(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        starts: list[str] = []

        def argv_hash(argv: list[str]) -> str:
            return ("a" if "/release-a/" in argv[2] else "b") * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            return {
                "unit": unit,
                "metadata": metadata,
                "final_status": "running",
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
                "argv": list(argv),
                "argv_sha256": argv_hash(argv),
                "cwd": cwd,
                "runtime_seconds": runtime_seconds,
                "created_at_unix": 10_000,
            }
            jobs[reserved_unit] = job
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

        suffix = [
            "--repo",
            REPO,
            "--pr",
            str(PR),
            "--expected-head",
            HEAD,
            "--expected-base",
            BASE,
        ]
        first = starter(
            ["/release-a/python", "-B", "/release-a/grabowski_repoground_post_merge.py", *suffix],
            cwd="/release-a",
            runtime_seconds=post_merge.DEFAULT_JOB_RUNTIME_SECONDS,
        )
        second = starter(
            ["/release-b/python", "-B", "/release-b/grabowski_repoground_post_merge.py", *suffix],
            cwd="/release-b",
            runtime_seconds=post_merge.DEFAULT_JOB_RUNTIME_SECONDS,
        )

        self.assertEqual(len(starts), 1)
        self.assertEqual(first["unit"], second["unit"])
        self.assertTrue(second["reused"])

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
                created_at = 10_000
                terminalized_at = created_at + 900

                def argv_hash(_argv: list[str]) -> str:
                    return "e" * 64

                def read_metadata(unit: str) -> dict[str, object]:
                    if unit not in jobs:
                        raise ValueError("missing")
                    return jobs[unit]

                def read_status(unit: str) -> dict[str, object]:
                    metadata = read_metadata(unit)
                    result: dict[str, object] = {
                        "unit": unit,
                        "metadata": metadata,
                        "final_status": live_status[unit],
                    }
                    if live_status[unit] in {
                        "failed",
                        "timed_out",
                        "signalled",
                        "terminated_unclear",
                    }:
                        result["finalization_receipt"] = {
                            "timestamp_unix": terminalized_at,
                        }
                    return result

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
                        "created_at_unix": created_at,
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
                with patch.object(
                    post_merge.time,
                    "time",
                    return_value=terminalized_at
                    + post_merge.POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS
                    + 1,
                ):
                    second = post_merge.schedule_from_captain_result(
                        captain_result(completed=False, queued=True),
                        job_starter=starter,
                        python_executable="/usr/bin/python3",
                        script_path=Path(post_merge.__file__),
                    )
                self.assertEqual(len(starts), 2)
                self.assertNotEqual(first["unit"], second["unit"])
                self.assertFalse(second["reused"])


    def test_multiple_slow_terminal_reads_still_reach_replacement_slot(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []
        elapsed_seconds = 0
        terminalized_at = 10_000
        retry_time = (
            terminalized_at
            + post_merge.POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS
            + 1
        )

        def argv_hash(_argv: list[str]) -> str:
            return "7" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            nonlocal elapsed_seconds
            elapsed_seconds += 25
            metadata = read_metadata(unit)
            result: dict[str, object] = {
                "unit": unit,
                "metadata": metadata,
                "final_status": live_status[unit],
            }
            if live_status[unit] == "failed":
                result["finalization_receipt"] = {
                    "timestamp_unix": terminalized_at,
                }
            return result

        def private_start(
            argv: list[str],
            *,
            cwd: str,
            runtime_seconds: int,
            reserved_unit: str,
        ) -> dict[str, object]:
            nonlocal elapsed_seconds
            elapsed_seconds += 60
            starts.append(reserved_unit)
            job: dict[str, object] = {
                "unit": reserved_unit,
                "job_id": reserved_unit.removeprefix("grabowski-job-"),
                "argv_sha256": argv_hash(argv),
                "cwd": cwd,
                "runtime_seconds": runtime_seconds,
                "created_at_unix": terminalized_at - 900,
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

        current = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )
        for _ in range(4):
            live_status[current["unit"]] = "failed"
            with patch.object(post_merge.time, "time", return_value=retry_time):
                current = post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )

        live_status[current["unit"]] = "failed"
        elapsed_seconds = 0
        with patch.object(post_merge.time, "time", return_value=retry_time):
            replacement = post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=starter,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(len(starts), 6)
        self.assertFalse(replacement["reused"])
        self.assertEqual(elapsed_seconds, (5 * 25) + 60)
        self.assertGreater(elapsed_seconds, 120)
        self.assertLess(elapsed_seconds, 900)

    def test_retry_backoff_starts_when_long_running_job_finishes(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []
        created_at = 10_000
        terminalized_at = created_at + 900

        def argv_hash(_argv: list[str]) -> str:
            return "9" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            result: dict[str, object] = {
                "unit": unit,
                "metadata": metadata,
                "final_status": live_status[unit],
            }
            if live_status[unit] == "failed":
                result["finalization_receipt"] = {
                    "timestamp_unix": terminalized_at,
                }
            return result

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
                "created_at_unix": created_at,
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
        live_status[first["unit"]] = "failed"
        with patch.object(post_merge.time, "time", return_value=terminalized_at + 60):
            second = post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=starter,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(len(starts), 1)
        self.assertEqual(second["status"], "retry_deferred")
        self.assertTrue(second["reused"])
        self.assertEqual(
            second["retry_after_unix"],
            terminalized_at + post_merge.POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS,
        )

    def test_terminal_job_without_finalization_evidence_defers_read_only(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []

        def argv_hash(_argv: list[str]) -> str:
            return "8" * 64

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
                "finalization_receipt": None,
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
                "created_at_unix": 10_000,
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
        live_status[first["unit"]] = "failed"
        second = post_merge.schedule_from_captain_result(
            captain_result(completed=False, queued=True),
            job_starter=starter,
            python_executable="/usr/bin/python3",
            script_path=Path(post_merge.__file__),
        )

        self.assertEqual(len(starts), 1)
        self.assertEqual(second["status"], "retry_deferred")
        self.assertTrue(second["terminal_evidence_pending"])
        self.assertIsNone(second["retry_after_unix"])

    def test_metadata_free_reserved_log_slot_is_durable_recovery_not_retry_loop(self) -> None:
        starts: list[str] = []
        mutation_checks: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            jobs_root = Path(temporary) / "jobs"
            jobs_root.mkdir(mode=0o700)

            def read_metadata(_unit: str) -> dict[str, object]:
                raise ValueError("metadata.json missing after log allocation")

            def private_start(
                _argv: list[str],
                *,
                cwd: str,
                runtime_seconds: int,
                reserved_unit: str,
            ) -> dict[str, object]:
                starts.append(reserved_unit)
                directory = jobs_root / reserved_unit
                directory.mkdir(mode=0o700, exist_ok=True)
                (directory / "stdout.log").touch(mode=0o600, exist_ok=True)
                # Effect may have happened in this attempt. Never launch a
                # second job or persist cursor/metadata in that same pass.
                raise FileExistsError(
                    "stdout.log created before metadata.json could be committed"
                )

            operator = types.SimpleNamespace(
                JOBS_DIR=jobs_root,
                grabowski_job_start=lambda *_args, **_kwargs: {},
                grabowski_job_status=lambda *_args, **_kwargs: self.fail(
                    "no metadata identity; must not claim a running unit"
                ),
                _argv_hash=lambda _argv: "f" * 64,
                _read_job_metadata=read_metadata,
                _require_operator_mutation=lambda *_args, **_kwargs: mutation_checks.append(
                    "durable_job"
                ),
                _start_job=private_start,
            )
            starter = post_merge.resolve_job_starter(
                {"grabowski_operator": operator}
            )
            self.assertIsNotNone(starter)

            def schedule() -> dict:
                return post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )

            first = schedule()
            self.assertEqual(first["status"], "schedule_unknown")
            self.assertEqual(len(starts), 1)
            self.assertEqual(mutation_checks, ["durable_job"])
            self.assertTrue(starts[0].startswith("grabowski-job-rgpm-"))

            # Newly created files might still be written by a concurrent
            # actor. Deferral is read-only; it must not launch another unit.
            recent = schedule()
            self.assertEqual(recent["status"], "schedule_unknown")
            self.assertEqual(len(starts), 1)
            self.assertEqual(mutation_checks, ["durable_job"])

            # After a sufficient unchanged grace interval, an unidentifiable
            # metadata-free slot becomes a durable manual-recovery obligation,
            # not a repeated O_EXCL mutation or another unit launch.
            future_ns = time.time_ns() + (
                post_merge.POST_MERGE_METADATA_FREE_SLOT_GRACE_SECONDS + 10
            ) * 1_000_000_000
            with patch.object(post_merge.time, "time_ns", return_value=future_ns):
                deferred = schedule()
            self.assertEqual(deferred["status"], "not_scheduled")
            self.assertEqual(
                deferred["reason"], "durable_freshness_job_slots_exhausted",
            )
            self.assertEqual(len(starts), 1)
            self.assertEqual(mutation_checks, ["durable_job"])

            # A corrupt *present* metadata file must never be mistaken for
            # an absent file, even long after the log files stopped changing.
            (jobs_root / starts[0] / "metadata.json").write_text(
                "{invalid-json", encoding="utf-8"
            )
            with patch.object(
                post_merge.time, "time_ns",
                return_value=future_ns + 10_000_000_000,
            ):
                malformed = schedule()
            # The old identity remains ambiguous, never a proven failed
            # launch. After the grace window, however, it must become
            # manually recoverable instead of starving all future merges.
            self.assertEqual(malformed["status"], "not_scheduled")
            self.assertEqual(
                malformed["reason"], "durable_freshness_job_slots_exhausted"
            )
            self.assertEqual(len(starts), 1)
            self.assertEqual(mutation_checks, ["durable_job"])

    def test_corrupt_metadata_slot_becomes_manual_attention_after_grace(self) -> None:
        # Invalid metadata may belong to an actually launched job. Neither
        # delete it nor retry it automatically; after grace, require manual
        # fresh_exact recovery rather than indefinite global starvation.
        starts: list[str] = []
        mutation_checks: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            jobs_root = Path(temporary) / "jobs"
            jobs_root.mkdir(mode=0o700)

            def read_metadata(_unit: str) -> dict[str, object]:
                raise ValueError("existing metadata.json is malformed")

            def private_start(
                _argv: list[str],
                *,
                cwd: str,
                runtime_seconds: int,
                reserved_unit: str,
            ) -> dict[str, object]:
                starts.append(reserved_unit)
                directory = jobs_root / reserved_unit
                directory.mkdir(mode=0o700, exist_ok=True)
                (directory / "stdout.log").touch(mode=0o600, exist_ok=True)
                (directory / "metadata.json").write_text("{corrupt", encoding="utf-8")
                raise FileExistsError("stdout.log exists")

            operator = types.SimpleNamespace(
                JOBS_DIR=jobs_root,
                grabowski_job_start=lambda *_args, **_kwargs: {},
                grabowski_job_status=lambda *_args, **_kwargs: self.fail(
                    "corrupt metadata does not prove unit identity"
                ),
                _argv_hash=lambda _argv: "f" * 64,
                _read_job_metadata=read_metadata,
                _require_operator_mutation=lambda *_args, **_kwargs: mutation_checks.append(
                    "durable_job"
                ),
                _start_job=private_start,
            )
            starter = post_merge.resolve_job_starter({"grabowski_operator": operator})
            self.assertIsNotNone(starter)

            def schedule() -> dict:
                return post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )

            first = schedule()
            self.assertEqual(first["status"], "schedule_unknown")
            advanced_ns = time.time_ns() + (
                post_merge.POST_MERGE_METADATA_FREE_SLOT_GRACE_SECONDS + 600
            ) * 1_000_000_000
            with patch.object(post_merge.time, "time_ns", return_value=advanced_ns):
                later = schedule()
            self.assertEqual(later["status"], "not_scheduled")
            self.assertEqual(
                later["reason"], "durable_freshness_job_slots_exhausted"
            )
            self.assertEqual(len(starts), 1)
            self.assertEqual(mutation_checks, ["durable_job"])

    def test_no_log_reserved_directory_ages_to_manual_recovery(self) -> None:
        starts: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            jobs_root = Path(temporary) / "jobs"
            jobs_root.mkdir(mode=0o700)

            def read_metadata(_unit: str) -> dict[str, object]:
                raise ValueError("metadata never created")

            def private_start(
                _argv: list[str],
                *,
                cwd: str,
                runtime_seconds: int,
                reserved_unit: str,
            ) -> dict[str, object]:
                starts.append(reserved_unit)
                (jobs_root / reserved_unit).mkdir(mode=0o700, exist_ok=True)
                raise FileExistsError("job directory allocated without logs")

            operator = types.SimpleNamespace(
                JOBS_DIR=jobs_root,
                grabowski_job_start=lambda *_args, **_kwargs: {},
                grabowski_job_status=lambda *_args, **_kwargs: self.fail(
                    "no metadata-based job identity available"
                ),
                _argv_hash=lambda _argv: "f" * 64,
                _read_job_metadata=read_metadata,
                _require_operator_mutation=lambda *_args, **_kwargs: None,
                _start_job=private_start,
            )
            starter = post_merge.resolve_job_starter(
                {"grabowski_operator": operator}
            )
            self.assertIsNotNone(starter)

            def schedule() -> dict:
                return post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )

            self.assertEqual(schedule()["status"], "schedule_unknown")
            self.assertEqual(schedule()["status"], "schedule_unknown")
            self.assertEqual(len(starts), 1)
            future_ns = time.time_ns() + (
                post_merge.POST_MERGE_METADATA_FREE_SLOT_GRACE_SECONDS + 10
            ) * 1_000_000_000
            with patch.object(
                post_merge.time, "time_ns", return_value=future_ns
            ):
                abandoned = schedule()
            self.assertEqual(abandoned["status"], "not_scheduled")
            self.assertEqual(
                abandoned["reason"], "durable_freshness_job_slots_exhausted"
            )
            self.assertEqual(len(starts), 1)

    def test_exhausted_retry_slots_are_read_only_not_scheduled(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []
        created_at = 10_000

        def argv_hash(_argv: list[str]) -> str:
            return "e" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            result: dict[str, object] = {
                "unit": unit,
                "metadata": metadata,
                "final_status": live_status[unit],
            }
            if live_status[unit] == "failed":
                result["finalization_receipt"] = {
                    "timestamp_unix": created_at,
                }
            return result

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
                "created_at_unix": created_at,
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

        with patch.object(
            post_merge.time,
            "time",
            return_value=created_at
            + post_merge.POST_MERGE_FAILURE_RETRY_BACKOFF_SECONDS
            + 1,
        ):
            for _index in range(post_merge.POST_MERGE_JOB_SLOT_LIMIT):
                result = post_merge.schedule_from_captain_result(
                    captain_result(completed=False, queued=True),
                    job_starter=starter,
                    python_executable="/usr/bin/python3",
                    script_path=Path(post_merge.__file__),
                )
                self.assertEqual(result["status"], "scheduled")
                live_status[result["unit"]] = "failed"

            exhausted = post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=starter,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(len(starts), post_merge.POST_MERGE_JOB_SLOT_LIMIT)
        self.assertEqual(exhausted["status"], "not_scheduled")
        self.assertEqual(
            exhausted["reason"],
            "durable_freshness_job_slots_exhausted",
        )

    def test_verified_missing_unit_recovers_after_grace_without_early_duplicate(self) -> None:
        jobs: dict[str, dict[str, object]] = {}
        live_status: dict[str, str] = {}
        starts: list[str] = []
        created_at = 10_000

        def argv_hash(_argv: list[str]) -> str:
            return "6" * 64

        def read_metadata(unit: str) -> dict[str, object]:
            if unit not in jobs:
                raise ValueError("missing")
            return jobs[unit]

        def read_status(unit: str) -> dict[str, object]:
            metadata = read_metadata(unit)
            final_status = live_status[unit]
            result: dict[str, object] = {
                "unit": unit,
                "metadata": metadata,
                "final_status": final_status,
            }
            if final_status == "missing_finalization_evidence":
                result["terminalization_evidence"] = {
                    "query_valid": True,
                    "systemd_visible": False,
                    "load_state": "not-found",
                }
            return result

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
                "created_at_unix": created_at,
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

        with patch.object(
            post_merge.time,
            "time",
            return_value=created_at
            + post_merge.POST_MERGE_MISSING_UNIT_RECOVERY_GRACE_SECONDS
            - 1,
        ):
            deferred = post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=starter,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )
        self.assertEqual(len(starts), 1)
        self.assertEqual(deferred["status"], "retry_deferred")

        with patch.object(
            post_merge.time,
            "time",
            return_value=created_at
            + post_merge.POST_MERGE_MISSING_UNIT_RECOVERY_GRACE_SECONDS,
        ):
            replacement = post_merge.schedule_from_captain_result(
                captain_result(completed=False, queued=True),
                job_starter=starter,
                python_executable="/usr/bin/python3",
                script_path=Path(post_merge.__file__),
            )

        self.assertEqual(len(starts), 2)
        self.assertNotEqual(first["unit"], replacement["unit"])
        self.assertFalse(replacement["reused"])

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