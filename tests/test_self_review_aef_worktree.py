"""Real AEF checkout identities and signed frozen-Candidate handoffs."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import test_agent_workspace as workspace_fixture
import test_self_review_first_party as semantic_fixture
import grabowski_grips as grips


shared_review = semantic_fixture.review
producer = semantic_fixture.producer
workspace = workspace_fixture.workspace


class SelfReviewAefWorktreeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Unrelated suite harnesses can leave shared verifier mocks behind.
        # All semantic evidence and negative signature checks use real source.
        spec = importlib.util.spec_from_file_location(
            "isolated_aef_first_party_verifier",
            Path(shared_review.__file__).resolve(strict=True),
        )
        if spec is None or spec.loader is None:
            raise AssertionError("real AEF source verifier could not be loaded")
        self.review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.review)
        self._patch(producer, "provenance", self.review)
        self._patch(semantic_fixture, "review", self.review)
        self.fixture = semantic_fixture.FirstPartySemanticReviewTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.root = self.fixture.root
        self.canonical = self.fixture.repo

    def _patch(self, target, name, *args, **kwargs):
        patcher = mock.patch.object(target, name, *args, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def _git_result(self, repository: Path, arguments: list[str]) -> dict:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True, text=True, check=False,
        )
        return {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    def _git(self, repository: Path, *arguments: str) -> str:
        result = self._git_result(repository, list(arguments))
        self.assertEqual(0, result["returncode"], result["stderr"])
        return result["stdout"].strip()

    def _frontdoor(self, repository: Path) -> dict:
        # The real read-only frontdoor branch computes the same source-bound
        # target as writer execution, before either branch acquires a lane.
        request = grips._agent_execution_source_request(
            {
                "source_kind": "thread_focus", "source_id": "thread-1",
                "repo": str(repository),
                "source_revision": self._git(repository, "rev-parse", "HEAD"),
                "write_paths": ["src"], "objective": "Review the fixture frozen source",
                "test_argv": ["python3", "-m", "unittest", "-q"],
                "task_class": "independent-review", "verification_policy": "independent_review",
                "runtime_seconds": 120, "retention_until_unix": int(time.time()) + 9000,
            },
            {"checks": []}, self._git_result,
        )
        self.assertEqual("controller_handback", request["state"])
        self.assertIsNone(request["lane_id"])
        return request

    def _linked(self, repository: Path, target: Path, revision: str | None = None) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        self._git(
            repository, "worktree", "add", "--detach", str(target),
            revision or self._git(repository, "rev-parse", "HEAD"),
        )
        return target

    def _clone(self, target: Path, repository_name: str) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        self._git(self.root, "clone", "--quiet", "--no-hardlinks", str(self.canonical), str(target))
        self._git(target, "remote", "set-url", "origin", f"git@github.com:heimgewebe/{repository_name}.git")
        return target

    def _candidate(self) -> dict:
        fixture = self.fixture
        written_source = (self.canonical / fixture.source_path).read_bytes()
        self._git(self.canonical, "reset", "--hard", fixture.base)
        self.frontdoor = self._frontdoor(self.canonical)
        candidate = self._linked(self.canonical, Path(self.frontdoor["target_path"]), fixture.base)
        fixture.repo = candidate
        fixture.head = fixture.base
        fixture._git("checkout", "-b", self.frontdoor["branch"])
        (candidate / fixture.source_path).write_bytes(written_source + b"DIRTY_CANDIDATE = 73\n")
        state = self.root / "workspaces"
        state.mkdir(mode=0o700)
        self._patch(workspace, "WORKSPACE_ROOT", state)
        manifest = workspace_fixture.AgentWorkspaceTests.manifest(SimpleNamespace(
            git=SimpleNamespace(repo=self.canonical, writer=candidate, base=fixture.base),
            state=state,
        ))
        manifest["writer_branch"] = self.frontdoor["branch"]
        manifest["commands"]["review"] = list(workspace.CONTROLLER_SELF_REVIEW_PENDING_ARGV)
        manifest["tasks"] = {"writer": "a" * 24, "tests": "b" * 24, "review": None}
        writer = workspace._role_receipt(manifest, "writer")
        writer.update({
            "expected_branch": manifest["writer_branch"],
            "branch_before": manifest["writer_branch"], "branch_after": manifest["writer_branch"],
        })
        writer["receipt_sha256"] = workspace._sha256_json({
            key: value for key, value in writer.items() if key != "receipt_sha256"
        })
        workspace._atomic_json(workspace._role_receipt_path(manifest, "writer"), writer)
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        patch = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"], "writer_result": patch,
        }
        workspace._persist_candidate_evidence(manifest, snapshot, patch, writer)
        tests_output = workspace._role_receipt_path(manifest, "tests")
        tests = workspace_fixture.signed_role_receipt("tests", manifest, snapshot)
        workspace._atomic_json(tests_output, tests)
        workspace._write_manifest(manifest)
        fixture.candidate_manifest = manifest
        fixture.workspace = workspace
        self.manifest = manifest

        # Actual private task/outcome records, as in the existing Candidate
        # fixture. Their wrappers, hashes, cwd and receipts are all verified.
        self.db = self.root / "candidate-tasks.sqlite3"
        outcomes = self.root / "candidate-outcomes"
        outcomes.mkdir(mode=0o700)
        columns = [
            "task_id", "host", "cwd", "argv_json", "argv_sha256", "unit", "state",
            "attempt", "lifecycle_receipt_sha256", "execution_backend", "systemd_scope",
        ]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("CREATE TABLE tasks (" + ",".join(
                name + (" INTEGER" if name == "attempt" else " TEXT") for name in columns
            ) + ")")
            for role_name in ("writer", "tests"):
                task_id = manifest["tasks"][role_name]
                argv = (
                    workspace._writer_task_argv(manifest) if role_name == "writer" else
                    workspace._role_task_argv(
                        manifest, "tests", snapshot["writer_head"], snapshot["diff_sha256"],
                        snapshot["dirty"], command=manifest["commands"]["tests"], output_path=tests_output,
                    )
                )
                row = dict(zip(columns, [
                    task_id, "heim-pc", str(candidate),
                    json.dumps(argv, ensure_ascii=False, separators=(",", ":")),
                    workspace._task_argv_sha256(argv), f"grabowski-task-{task_id}-a1.service",
                    "completed", 1, None, "systemd-user", "user",
                ]))
                outcome = {key: row[key] for key in (
                    "task_id", "unit", "state", "attempt", "argv_sha256", "execution_backend", "systemd_scope",
                )}
                outcome["observation"] = {
                    "state": "completed", "properties": {"Result": "success", "ExecMainStatus": "0"},
                }
                outcome["receipt_sha256"] = self.review._digest(outcome)
                row["lifecycle_receipt_sha256"] = outcome["receipt_sha256"]
                outcome_path = outcomes / (task_id + ".json")
                outcome_path.write_bytes(self.review._canonical(outcome))
                outcome_path.chmod(0o600)
                connection.execute(
                    "INSERT INTO tasks VALUES (" + ",".join("?" for _ in columns) + ")",
                    [row[key] for key in columns],
                )
            connection.commit()
        finally:
            connection.close()
        self.db.chmod(0o600)
        self._patch(producer, "TASK_DB", self.db)
        self._patch(producer, "OUTCOMES", outcomes)
        return producer.plan_frozen_candidate_review(manifest["workspace_id"])

    def test_actual_aef_target_supports_signed_five_axis_candidate_handoff(self) -> None:
        plan = self._candidate()
        self.assertEqual(self.frontdoor["target_path"], plan["worktree"])
        self.assertEqual(self.root, Path(plan["worktree"]).parent)
        self.assertEqual(list(workspace.CONTROLLER_SELF_REVIEW_PENDING_ARGV), self.manifest["commands"]["review"])
        self.assertNotIn("lane_binding", self.manifest["resources"])
        context, repository = producer._frozen_candidate_context(self.manifest["workspace_id"])
        self.assertEqual(Path(plan["worktree"]), repository)
        self.assertEqual(plan["binding"]["candidate_binding"], context)
        started = self.fixture._start_plan(plan)
        self.fixture._complete_candidate(plan, started)
        finalized = self.fixture._finalize_candidate(plan, started)
        self.assertEqual(5, len(finalized["axes"]))
        self.assertEqual({"verdict": "PASS", "findings": []}, self.fixture._verify_candidate(plan))

        wrong_workspace = copy.deepcopy(plan)
        wrong_workspace["binding"]["candidate_binding"]["workspace_id"] += "-other"
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "frozen Candidate binding invalid"):
            self.fixture._verify_candidate(wrong_workspace)

        # A shared PASS stub cannot satisfy this test: changing real signed
        # handoff bytes must fail before the restored record passes again.
        finalized_path = self.fixture.state / "sessions" / started["review_session_id"] / "finalized.json"
        original = finalized_path.read_bytes()
        envelope = json.loads(original)
        envelope["record"]["finalized_at_unix"] += 1
        try:
            finalized_path.write_bytes(self.review._canonical(envelope))
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "signature"):
                self.fixture._verify_candidate(plan)
        finally:
            finalized_path.write_bytes(original)
        self.assertEqual({"verdict": "PASS", "findings": []}, self.fixture._verify_candidate(plan))

    def test_candidate_tasks_cannot_cross_another_aef_worktree(self) -> None:
        self._candidate()
        other = self._linked(self.canonical, self.root / ".grabowski-aef-grabowski-ffffffffffff")
        self.assertEqual((other, "heimgewebe/grabowski"), producer._managed_repository_identity(other))
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "UPDATE tasks SET cwd=? WHERE task_id=?", (str(other), self.manifest["tasks"]["tests"]),
            )
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "Candidate task origin invalid"):
            producer._frozen_candidate_context(self.manifest["workspace_id"])

    def test_actual_frontdoor_repo_slug_normalization_and_truncation(self) -> None:
        name = "ABCDEFGHIJKLMNO__tail"
        canonical = self._clone(self.root / name, name)
        frontdoor = self._frontdoor(canonical)
        target = self._linked(canonical, Path(frontdoor["target_path"]))
        self.assertTrue(target.name.startswith(".grabowski-aef-abcdefghijklmno-"))
        self.assertEqual((target, "heimgewebe/" + name), producer._managed_repository_identity(target))

    def test_canonical_and_both_existing_worktree_pools_remain_accepted(self) -> None:
        canonical = self._clone(self.root / "vibe-lab", "vibe-lab")
        paths = [canonical]
        for pool in (".grabowski-worktrees", ".vibe-lab-worktrees"):
            paths.append(self._linked(canonical, self.root / pool / "candidate"))
        for path in paths:
            with self.subTest(layout=str(path)):
                self.assertEqual(
                    (path, "heimgewebe/vibe-lab"),
                    producer._managed_repository_identity(path, expected_repo="heimgewebe/vibe-lab"),
                )

    def test_registered_direct_work_lane_review_identity(self) -> None:
        import grabowski_checkouts as checkouts

        target = self._linked(self.canonical, self.root / "grabowski-operation-list-20261126")
        branch = "fix/operation-list"
        self._git(target, "switch", "-c", branch)
        common = (self.canonical / ".git").resolve()
        lane = "a" * 32
        key = checkouts._checkout_key(common, target)
        binding = {
            "checkout_key": key, "repo_common_dir": str(common),
            "repo_path": str(self.canonical), "checkout_path": str(target),
            "owner_id": "lane:" + lane, "source": {"kind": "work_lane", "id": lane},
            "expected_branch": branch, "phase": "active",
        }
        with mock.patch.object(checkouts, "_strict_lifecycle_binding", return_value=binding) as lookup:
            self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
            lookup.assert_called_once_with(key, write_free=True)
            # No live lease or fixed base HEAD is required for read-only review.
            for phase in ("completed_retained", "archived"):
                binding["phase"] = phase
                self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
            binding["phase"] = "active"
            for field, value in (
                ("checkout_key", "b" * 64), ("repo_common_dir", "/other/.git"),
                ("repo_path", "/other"), ("checkout_path", "/other/checkout"),
                ("owner_id", "unbound"), ("expected_branch", "wrong"),
                ("source", {"kind": "work_lane", "id": "b" * 32}),
                ("source", {"kind": "untrusted", "id": lane}),
                ("phase", "externally_terminal_missing"),
            ):
                old = binding[field]
                binding[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                    producer._managed_repository_identity(target)
                binding[field] = old
        with mock.patch.object(checkouts, "_strict_lifecycle_binding", return_value=None):
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                producer._managed_repository_identity(target)
        with mock.patch.object(checkouts, "_strict_lifecycle_binding", return_value=binding):
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "repository origin invalid"):
                producer._managed_repository_identity(target, expected_repo="heimgewebe/vibe-lab")

    def test_registered_lane_review_does_not_mutate_wal_sidecars(self) -> None:
        import grabowski_checkouts as checkouts

        target = self._linked(self.canonical, self.root / "registered-wal-lane")
        branch = "fix/registered-wal-lane"
        self._git(target, "switch", "-c", branch)
        common = (self.canonical / ".git").resolve()
        lane = "a" * 32
        key = checkouts._checkout_key(common, target)
        database = self.root / "fixture-checkouts.sqlite3"
        wal = Path(str(database) + "-wal")
        shm = Path(str(database) + "-shm")
        with mock.patch.object(checkouts, "CHECKOUT_DB", database):
            connection = checkouts._database()
            try:
                connection.execute(
                    "INSERT INTO lifecycle_bindings VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (key, str(common), str(self.canonical), str(target), "lane:" + lane,
                     "review fixture", "work_lane", lane, "implementation-worktree",
                     "active", int(time.time()) + 3600, self._git(target, "rev-parse", "HEAD"),
                     branch, 1, 1, None, None),
                )
                connection.commit()
                self.assertEqual(0, connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0])
                self.assertEqual(0, wal.stat().st_size)
                before = [p.read_bytes() for p in (database, wal, shm)]
                self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
                self.assertEqual(before, [p.read_bytes() for p in (database, wal, shm)])
                connection.execute("UPDATE lifecycle_bindings SET phase='completed_retained'")
                connection.commit()
                self.assertGreater(wal.stat().st_size, 0)
                before = [p.read_bytes() for p in (database, wal, shm)]
                self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
                self.assertEqual(before, [p.read_bytes() for p in (database, wal, shm)])
                connection.execute("UPDATE lifecycle_bindings SET phase='externally_terminal_missing'")
                connection.commit()
                before = [p.read_bytes() for p in (database, wal, shm)]
                with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                    producer._managed_repository_identity(target)
                self.assertEqual(before, [p.read_bytes() for p in (database, wal, shm)])
                connection.execute("UPDATE lifecycle_bindings SET phase='completed_retained'")
                connection.commit()
            finally:
                connection.close()
            self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
            self.assertFalse(wal.exists())
            self.assertFalse(shm.exists())

    def test_active_bureau_review_requires_exact_journal_workspace_and_live_owner(self) -> None:
        import grabowski_bureau_pickup as pickup

        run_id = "BUR-RUN-20261128T200220Z-c251c39643"
        owner = "bureau-run:" + run_id
        branch = "bureau/review-fixture/c251c39643"
        target = self._linked(self.canonical, self.root / ".bureau-worktrees" / run_id)
        self._git(target, "switch", "-c", branch)
        status = {
            "run_id": run_id, "root_binding_source": "journal-bound", "journal_available": True,
            "execution_binding": {"run_id": run_id, "actively_bound": True},
            "coordination": {
                "status": "coordinated", "blocking": False,
                "run": {
                    "run_id": run_id, "workspace_path": str(target), "workspace_branch": branch,
                    "task_id": "review-fixture",
                    "reservations": [{"resource_id": "repo.grabowski", "mode": "write"}],
                },
                "lease": {"status": "active-bound"},
                "stored_lease_binding": {"owner_id": owner, "task_id": "review-fixture"},
                "release": {"owner_id": owner, "required": True},
            },
        }
        with mock.patch.object(producer, "_registered_lane_checkout", return_value=False), \
             mock.patch.object(pickup, "grabowski_bureau_pickup_status", return_value=status) as observe:
            self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
            observe.assert_called_once_with(run_id)
            for path, value in (
                (("journal_available",), False),
                (("root_binding_source",), "current-canonical-with-legacy-fallback"),
                (("run_id",), "foreign"),
                (("execution_binding", "actively_bound"), False),
                (("execution_binding", "run_id"), "foreign"),
                (("coordination", "blocking"), True),
                (("coordination", "lease", "status"), "terminal-released-or-expired"),
                (("coordination", "stored_lease_binding", "owner_id"), "foreign"),
                (("coordination", "stored_lease_binding", "task_id"), "foreign"),
                (("coordination", "release", "owner_id"), "foreign"),
                (("coordination", "run", "workspace_path"), str(self.root / "other")),
                (("coordination", "run", "workspace_branch"), "foreign"),
                (("coordination", "run", "reservations"), [{"resource_id": "repo.foreign", "mode": "write"}]),
                (("coordination", "run", "reservations"), [{"resource_id": "repo.grabowski", "mode": "read"}]),
            ):
                with self.subTest(path=path, value=value):
                    changed = copy.deepcopy(status)
                    node = changed
                    for part in path[:-1]:
                        node = node[part]
                    node[path[-1]] = value
                    observe.return_value = changed
                    with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                        producer._managed_repository_identity(target)
            observe.return_value = status
            observe.side_effect = RuntimeError("unavailable")
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "coordination unavailable"):
                producer._managed_repository_identity(target)
            observe.side_effect = None
            self._git(target, "switch", "-c", "foreign-branch")
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                producer._managed_repository_identity(target)
            self._git(target, "switch", branch)
            (target / self.fixture.source_path).write_text("dirty review source\n")
            binding = {
                "repo": "heimgewebe/grabowski", "head_sha": self._git(target, "rev-parse", "HEAD"),
                "base_sha": self.fixture.base, "review_purpose": "pull_request",
            }
            with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not clean"):
                producer._current_source(target, binding)

    def test_exact_kleinanzeiger_repository_can_use_signed_first_party_review(self) -> None:
        canonical = self._clone(self.root / "kleinanzeiger", "kleinanzeiger")
        expected = "alexdermohr/kleinanzeiger"
        binding = {
            "repo": expected, "pr": 283, "base_sha": "a" * 40,
            "head_sha": "b" * 40, "diff_sha256": "c" * 64,
            "review_batch_id": "d" * 32, "review_purpose": "pull_request",
        }
        self.assertEqual(expected, self.review._first_party_binding(binding)["repo"])
        for remote in (
            "git@github.com:alexdermohr/kleinanzeiger.git",
            "https://github.com/alexdermohr/kleinanzeiger.git",
        ):
            with self.subTest(remote=remote):
                self._git(canonical, "remote", "set-url", "origin", remote)
                self.assertEqual(
                    (canonical, expected),
                    producer._managed_repository_identity(canonical, expected_repo=expected),
                )
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "origin invalid"):
            producer._managed_repository_identity(canonical, expected_repo="heimgewebe/kleinanzeiger")
        for wrong in (
            "git@github.com:alexdermohr/another.git",
            "git@github.com:foreign/kleinanzeiger.git",
        ):
            with self.subTest(wrong=wrong):
                self._git(canonical, "remote", "set-url", "origin", wrong)
                with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "origin invalid"):
                    producer._managed_repository_identity(canonical)
        invalid = dict(binding, repo="alexdermohr/another")
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "binding invalid"):
            self.review._first_party_binding(invalid)

    def test_exact_machtverflechtungen_repository_can_use_signed_review(self) -> None:
        canonical = self._clone(self.root / "machtverflechtungen", "machtverflechtungen")
        expected = "alexdermohr/machtverflechtungen"
        binding = {
            "repo": expected, "pr": 184, "base_sha": "a" * 40,
            "head_sha": "b" * 40, "diff_sha256": "c" * 64,
            "review_batch_id": "d" * 32, "review_purpose": "pull_request",
        }
        self.assertEqual(expected, self.review._first_party_binding(binding)["repo"])
        for remote in (
            "git@github.com:alexdermohr/machtverflechtungen.git",
            "https://github.com/alexdermohr/machtverflechtungen.git",
            "ssh://git@github.com/alexdermohr/machtverflechtungen.git",
        ):
            with self.subTest(remote=remote):
                self._git(canonical, "remote", "set-url", "origin", remote)
                self.assertEqual(
                    (canonical, expected),
                    producer._managed_repository_identity(canonical, expected_repo=expected),
                )
        for bad_remote in (
            "git@github.com:unrelated/machtverflechtungen.git",
            "git@github.com:alexdermohr/other.git",
            "git@github.com:alexdermohr/Machtverflechtungen.git",
        ):
            with self.subTest(remote=bad_remote):
                self._git(canonical, "remote", "set-url", "origin", bad_remote)
                with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "origin invalid"):
                    producer._managed_repository_identity(canonical)
        for bad_identity in (
            "alexdermohr/another",
            "wrongowner/machtverflechtungen",
            "alexdermohr/Machtverflechtungen",
            "alexdermohr/machtverflechtungen/extra",
        ):
            with self.subTest(repo=bad_identity):
                with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "binding invalid"):
                    self.review._first_party_binding(dict(binding, repo=bad_identity))

    def test_aef_path_does_not_override_origin_or_expected_repository(self) -> None:
        frontdoor = self._frontdoor(self.canonical)
        target = self._linked(self.canonical, Path(frontdoor["target_path"]))
        self.assertEqual((target, "heimgewebe/grabowski"), producer._managed_repository_identity(target))
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "repository origin invalid"):
            producer._managed_repository_identity(target, expected_repo="heimgewebe/vibe-lab")
        self._git(self.canonical, "remote", "set-url", "origin", "git@github.com:other/grabowski.git")
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "repository origin invalid"):
            producer._managed_repository_identity(target)

    def test_aef_name_does_not_authorize_a_foreign_git_common_directory(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        outside = self._clone(Path(temporary.name) / "grabowski", "grabowski")
        target = self._linked(outside, self.root / ".grabowski-aef-grabowski-012345abcdef")
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
            producer._managed_repository_identity(target)

    def test_malformed_or_misplaced_aef_names_stay_rejected(self) -> None:
        names = (
            ".grabowski-aef-vibe-lab-012345abcdef", ".grabowski-aef-grabowski-012345abcde",
            ".grabowski-aef-grabowski-012345abcdef0", ".grabowski-aef-grabowski-012345ABCDEF",
            ".grabowski-aef-grabowski-012345abcdeg", ".grabowski-aef-grabowski-012345abcdef-extra",
            ".grabowski-aef-grabowski", "grabowski-aef-grabowski-012345abcdef",
        )
        paths = [self.root / name for name in names]
        paths.append(self.root / "nested" / ".grabowski-aef-grabowski-012345abcdef")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        paths.append(Path(temporary.name) / ".grabowski-aef-grabowski-012345abcdef")
        for path in paths:
            with self.subTest(path=str(path)):
                self._linked(self.canonical, path)
                with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "not a managed checkout"):
                    producer._managed_repository_identity(path)


if __name__ == "__main__":
    unittest.main()
