"""Real signed-ingress and Git-read coverage for first-party semantic review."""
from __future__ import annotations

import hashlib
import importlib.util
import secrets
import json
import os
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as review  # noqa: E402
import grabowski_self_review_producer as producer  # noqa: E402
import grabowski_transport_assertion as assertion  # noqa: E402


SECRET = "first-party-test-connector-secret"
SCOPE_SHA256 = hashlib.sha256(b"first-party-test-scope").hexdigest()
RUNTIME_SHA256 = hashlib.sha256(b"first-party-test-runtime").hexdigest()


class FirstPartySemanticReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.skipTest("OpenSSH is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "grabowski"
        self.repo.mkdir(mode=0o700)
        self._git("init", "-q")
        self._git("config", "user.email", "review-test@example.invalid")
        self._git("config", "user.name", "Review Test")
        self._git("remote", "add", "origin", "git@github.com:heimgewebe/grabowski.git")
        source = self.repo / "src" / "reviewed.py"
        self.source_path = "src/reviewed.py"
        source.parent.mkdir()
        source.write_text(
            "\n".join(f"BASE_{number} = {number}" for number in range(1, 31)) + "\n",
            encoding="utf-8",
        )
        self._git("add", "src/reviewed.py")
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip()
        source.write_text(
            "\n".join(f"HEAD_{number} = {number * 2}" for number in range(1, 31)) + "\n",
            encoding="utf-8",
        )
        self._git("add", "src/reviewed.py")
        self._git("commit", "-qm", "head")
        self.head = self._git("rev-parse", "HEAD").strip()

        self.key = self.root / "issuer"
        generated = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            capture_output=True, check=False,
        )
        self.assertEqual(0, generated.returncode, generated.stderr.decode())
        self.signers = self.root / "allowed_signers"
        public = (self.root / "issuer.pub").read_text(encoding="utf-8").strip()
        self.signers.write_text(review.PRINCIPAL + " " + public + "\n", encoding="utf-8")
        self.signers.chmod(0o600)
        self.state = self.root / "first-party-state"
        self.transport_state = self.root / "transport-state"
        self.now = int(time.time())
        self._request_counter = 0
        self.canonical_patch = mock.patch.object(producer, "CANONICAL_REPO", self.repo)
        self.canonical_patch.start()
        self.addCleanup(self.canonical_patch.stop)
        self.managed_root_patch = mock.patch.object(
            producer, "MANAGED_REPOS_ROOT", self.root,
        )
        self.managed_root_patch.start()
        self.addCleanup(self.managed_root_patch.stop)

        self.transport_patches = [
            mock.patch.object(assertion, "STATE_ROOT", self.transport_state),
            mock.patch.object(assertion, "LOCK_PATH", self.transport_state / ".lock"),
        ]
        for patcher in self.transport_patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _git(self, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout

    def _plan(self) -> dict:
        return producer.plan_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256="c" * 64,
            bwrap="/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap",
            python="/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3",
        )

    def _first_party_plan(self) -> dict:
        diff_sha256 = hashlib.sha256(
            review._first_party_diff(
                self.repo, {"base_sha": self.base, "head_sha": self.head},
            )
        ).hexdigest()
        return producer.plan_first_party_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256=diff_sha256,
        )

    def _candidate_plan(self, *, dirty: bool = True, retried_tests: bool = False,
                        capture_tail_bytes: int = 0) -> dict:
        from test_agent_workspace import AgentWorkspaceTests, signed_role_receipt, workspace
        canonical = self.repo
        written_source = (canonical / self.source_path).read_bytes()
        pool = self.root / ".grabowski-worktrees"
        pool.mkdir()
        candidate = pool / "candidate"
        self._git("worktree", "add", "--detach", str(candidate), self.base if dirty else self.head)
        self._git("reset", "--hard", self.base)
        self.repo = candidate
        self._git("checkout", "-b", "candidate-review")
        if dirty:
            self.head = self.base
            (candidate / self.source_path).write_bytes(written_source + b"DIRTY_CANDIDATE = 73\n")
        state = self.root / "workspaces"
        state.mkdir(mode=0o700)
        patcher = mock.patch.object(workspace, "WORKSPACE_ROOT", state)
        patcher.start()
        self.addCleanup(patcher.stop)
        fixture = SimpleNamespace(
            git=SimpleNamespace(repo=canonical, writer=candidate, base=self.base), state=state,
        )
        manifest = AgentWorkspaceTests.manifest(fixture)
        manifest["writer_branch"] = "candidate-review"
        manifest["commands"]["review"] = list(workspace.CONTROLLER_SELF_REVIEW_PENDING_ARGV)
        manifest["tasks"] = {"writer": "a" * 24, "tests": "b" * 24, "review": None}
        writer = workspace._role_receipt(manifest, "writer")
        writer.update({"expected_branch": "candidate-review", "branch_before": "candidate-review", "branch_after": "candidate-review"})
        if capture_tail_bytes:
            writer_capture = b"W" * capture_tail_bytes
            writer.update({
                "stdout_tail": writer_capture.decode("ascii"),
                "stdout_bytes": len(writer_capture),
                "stdout_sha256": hashlib.sha256(writer_capture).hexdigest(),
            })
        writer["receipt_sha256"] = workspace._sha256_json({k: v for k, v in writer.items() if k != "receipt_sha256"})
        workspace._atomic_json(workspace._role_receipt_path(manifest, "writer"), writer)
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        if dirty:
            patch = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        else:
            # A clean frozen patch already has immutable committed source.
            # Keep the existing dirty-workspace freezer's contract unchanged.
            payload = producer.provenance._git_read(
                candidate,
                ["diff", "--binary", "--no-ext-diff", "--no-textconv", self.base, "--"],
                maximum=workspace.MAX_PATCH_BYTES,
            )
            path = workspace._writer_patch_path(manifest)
            size, sha = workspace._atomic_bounded_chunks(path, [payload], max_bytes=workspace.MAX_PATCH_BYTES)
            patch = {"type": "patch", "path": str(path), "sha256": sha, "bytes": size, "applies_to": self.base}
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"], "writer_result": patch,
        }
        workspace._persist_candidate_evidence(manifest, snapshot, patch, writer)
        selected_tests = manifest["commands"]["tests"]
        if retried_tests:
            selected_tests = ["python3", "-m", "unittest", "discover"]
            manifest["role_final_attempt"] = {"tests": 2}
            manifest["role_retries"] = {"tests": {"count": 1, "attempts": [
                {"attempt": 2, "new_command_sha256": workspace._sha256_json(selected_tests)},
            ]}}
        tests_output = workspace._role_receipt_path(manifest, "tests", attempt=2 if retried_tests else 1)
        tests_receipt = signed_role_receipt(
            "tests", manifest, snapshot, argv_sha256=workspace._sha256_json(selected_tests),
        )
        if capture_tail_bytes:
            tests_capture = b"T" * capture_tail_bytes
            tests_receipt.update({
                "stdout_tail": tests_capture.decode("ascii"),
                "stdout_bytes": len(tests_capture),
                "stdout_sha256": hashlib.sha256(tests_capture).hexdigest(),
            })
            tests_receipt["receipt_sha256"] = workspace._sha256_json({
                k: v for k, v in tests_receipt.items() if k != "receipt_sha256"
            })
        workspace._atomic_json(tests_output, tests_receipt)
        workspace._write_manifest(manifest)
        self.candidate_manifest = manifest
        self.workspace = workspace
        db = self.root / "tasks.sqlite3"
        outcomes = self.root / "outcomes"
        outcomes.mkdir(mode=0o700)
        columns = ["task_id", "host", "cwd", "argv_json", "argv_sha256", "unit", "state", "attempt",
                   "lifecycle_receipt_sha256", "execution_backend", "systemd_scope"]
        connection = sqlite3.connect(db)
        connection.execute("CREATE TABLE tasks (" + ",".join(
            name + (" INTEGER" if name == "attempt" else " TEXT") for name in columns
        ) + ")")
        for name in ("writer", "tests"):
            task = manifest["tasks"][name]
            argv = (workspace._writer_task_argv(manifest) if name == "writer" else
                    workspace._role_task_argv(manifest, "tests", snapshot["writer_head"], snapshot["diff_sha256"], dirty,
                                              command=selected_tests, output_path=tests_output))
            row = dict(zip(columns, [task, "heim-pc", str(candidate), json.dumps(argv, ensure_ascii=False, separators=(",", ":")),
                       workspace._task_argv_sha256(argv), f"grabowski-task-{task}-a1.service", "completed", 1,
                       None, "systemd-user", "user"]))
            outcome = {k: row[k] for k in ("task_id", "unit", "state", "attempt", "argv_sha256", "execution_backend", "systemd_scope")}
            outcome["observation"] = {"state": "completed", "properties": {"Result": "success", "ExecMainStatus": "0"}}
            outcome["receipt_sha256"] = review._digest(outcome)
            row["lifecycle_receipt_sha256"] = outcome["receipt_sha256"]
            (outcomes / (task + ".json")).write_bytes(review._canonical(outcome))
            (outcomes / (task + ".json")).chmod(0o600)
            connection.execute("INSERT INTO tasks VALUES (" + ",".join("?" for _ in columns) + ")", [row[k] for k in columns])
        connection.commit()
        connection.close()
        db.chmod(0o600)
        for patcher in (mock.patch.object(producer, "TASK_DB", db), mock.patch.object(producer, "OUTCOMES", outcomes)):
            patcher.start()
            self.addCleanup(patcher.stop)
        return producer.plan_frozen_candidate_review(manifest["workspace_id"])

    def _finalize_candidate(self, plan: dict, started: dict, *, reason: str | None = None) -> dict:
        return review.finalize_first_party_candidate(
            started["review_session_id"], started["session_nonce"],
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {
                "review_session_id": started["review_session_id"], "session_nonce": started["session_nonce"],
                "report": {"finalize": True},
                **({"reason": reason} if reason is not None else {}),
            }),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )

    def _verify_candidate(self, plan: dict) -> dict:
        return review.verified_first_party_candidate_handoff(
            plan, root=self.state, signers=self.signers, root_owned_signers=False, now_unix=self.now,
        )

    def _complete_candidate(self, plan: dict, started: dict, *, reject: bool = False) -> None:
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            count = len(review._first_party_diff(self.repo, plan["binding"]).decode().splitlines())
            self._read(started, axis, "diff", "", "head", 1, count)
            self._read(started, axis, "source", self.source_path, "head", 1, 4)
            self._read(started, axis, "source", self.source_path, "base", 1, 4)
            refs = [f"{self.source_path}:L1-L4", f"{self.source_path}:{self.base}:L1-L4"]
            self._submit(started, self._report(axis, number, refs, reject=reject and number == 1))

    def _submit(self, started: dict, report: dict, *, reason: str | None = None) -> dict:
        return review.submit_first_party_axis_review(
            started["review_session_id"], started["session_nonce"], report,
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {
                "review_session_id": started["review_session_id"], "session_nonce": started["session_nonce"],
                "report": report,
                **({"reason": reason} if reason is not None else {}),
            }),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )

    def test_dirty_frozen_candidate_signed_five_axis_handoff(self) -> None:
        plan = self._candidate_plan()
        self.assertTrue(plan["binding"]["candidate_binding"]["dirty"])
        started = self._start_plan(plan)
        dirty_read = self._read(started, review.REQUIRED_AXES[0], "source", self.source_path, "head", 31, 31)
        self.assertEqual("DIRTY_CANDIDATE = 73\n", dirty_read["content"])
        self._complete_candidate(plan, started)
        finalized = self._finalize_candidate(plan, started)
        self.assertEqual(5, len(finalized["axes"]))
        self.assertEqual({"verdict": "PASS", "findings": []}, self._verify_candidate(plan))
        with self.assertRaises((review.ReviewExecutionRejected, FileExistsError, assertion.TransportAssertionReplay)):
            self._finalize_candidate(plan, started)

    def test_review_producer_follows_configured_task_database(self) -> None:
        # The task writer and review producer are separate processes: reload
        # both in the same fresh runtime instead of patching a test constant.
        custom_db = self.root / "isolated-tasks.sqlite3"
        script = (
            "import json, pathlib, sys; "
            "sys.path.insert(0, " + repr(str(Path(__file__).resolve().parents[1] / "src")) + "); "
            "import grabowski_self_review_producer as producer; "
            "import grabowski_self_review_execution as execution; "
            "print(json.dumps({'task_db': str(producer.TASK_DB), "
            "'producer_outcomes': str(producer.OUTCOMES), "
            "'execution_outcomes': str(execution.OUTCOME_ROOT)}))"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script],
            cwd=self.repo,
            env={**os.environ, "GRABOWSKI_TASK_DB": str(custom_db)},
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(str(custom_db), observed["task_db"])
        self.assertEqual(str(custom_db.with_suffix(".outcomes")), observed["producer_outcomes"])
        self.assertEqual(observed["producer_outcomes"], observed["execution_outcomes"])

    def test_full_captured_writer_test_output_allows_signed_candidate_session(self) -> None:
        # Realistic max-size immutable role captures; hashes remain bound to
        # the original Writer/Test receipts, not arbitrary caller-supplied PASS.
        plan = self._candidate_plan(capture_tail_bytes=12_000)
        binding = plan["binding"]["candidate_binding"]
        writer = self.workspace._role_receipt(self.candidate_manifest, "writer")
        tests = self.workspace._role_receipt(self.candidate_manifest, "tests")
        self.assertEqual(12_000, len(writer["stdout_tail"]))
        self.assertEqual(12_000, len(tests["stdout_tail"]))
        self.assertEqual(writer["receipt_sha256"], binding["writer_receipt_sha256"])
        self.assertEqual(tests["receipt_sha256"], binding["test_receipt_sha256"])
        self.assertNotIn("writer_receipt", binding)
        self.assertNotIn("test_receipt", binding)
        self.assertLess(len(review._canonical(plan["binding"])), review.MAX_RECEIPT)
        started = self._start_plan(plan)
        session_file = self.state / "sessions" / started["review_session_id"] / "session.json"
        self.assertLessEqual(session_file.stat().st_size, review.MAX_RECEIPT)
        self.assertNotIn(b"W" * 100, session_file.read_bytes())
        self.assertNotIn(b"T" * 100, session_file.read_bytes())
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        self.assertEqual("PASS", self._verify_candidate(plan)["verdict"])

    def test_historical_full_candidate_binding_still_verifies(self) -> None:
        plan = self._candidate_plan()
        legacy, _worktree = producer._frozen_candidate_context(
            self.candidate_manifest["workspace_id"], legacy_extended=True,
        )
        self.assertIn("writer_receipt", legacy)
        self.assertIn("test_receipt", legacy)
        historical = {
            **plan,
            "binding": {**plan["binding"], "candidate_binding": legacy},
            "source_raw_diff_sha256": review._digest(legacy),
        }
        self.assertEqual(
            historical["source_raw_diff_sha256"],
            producer._current_source(self.repo, historical["binding"]),
        )
        started = self._start_plan(historical)
        self._complete_candidate(historical, started)
        self._finalize_candidate(historical, started)
        self.assertEqual("PASS", self._verify_candidate(historical)["verdict"])

    def test_signed_legacy_candidate_reject_blocks_compact_review_batch(self) -> None:
        # Rotating from the historical full receipt binding to the new
        # digest-only format must not erase an authenticated material finding.
        plan = self._candidate_plan()
        old_context, _ = producer._frozen_candidate_context(
            self.candidate_manifest["workspace_id"], legacy_extended=True,
        )
        legacy = {
            **plan,
            "binding": {**plan["binding"], "candidate_binding": old_context},
            "source_raw_diff_sha256": review._digest(old_context),
        }
        started = self._start_plan(legacy)
        self._complete_candidate(legacy, started, reject=True)
        compact = producer.plan_frozen_candidate_review(
            self.candidate_manifest["workspace_id"],
        )
        self.assertNotIn("writer_receipt", compact["binding"]["candidate_binding"])
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            review._assert_no_first_party_reject_for_legacy_review(
                compact["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False,
            )

    def test_dirty_candidate_finalization_accepts_substantive_signed_32k_receipt(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        source_path = self.source_path
        diff_line_count = len(
            review._first_party_diff(self.repo, plan["binding"]).splitlines()
        )
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._read(started, axis, "diff", "", "head", 1, diff_line_count)
            first = self._read(started, axis, "source", source_path, "head", 1, 4)
            second = self._read(started, axis, "source", source_path, "base", 1, 4)
            report = self._report(
                axis, number, [first["source_ref"], second["source_ref"]],
            )
            # A realistic, detailed high-critical review can carry substantial
            # source-based reasoning. Ordinary per-axis records stay <=16 KiB.
            report["summary"] += (
                " Extended source-based method assessment compares each changed "
                "line with its unchanged base, tests rejection paths and explains "
                "the concrete effect of the preserved authority boundary."
            ) * 18
            self._submit(started, report)
        finalized = self._finalize_candidate(plan, started)
        self.assertEqual(5, len(finalized["axes"]))
        signed_path = (
            self.state / "sessions" / started["review_session_id"] / "finalized.json"
        )
        self.assertGreater(signed_path.stat().st_size, review.MAX_RECEIPT)
        self.assertLessEqual(
            len(review._canonical(finalized)), review.MAX_CANDIDATE_FINALIZED_RECEIPT,
        )
        self.assertEqual({"verdict": "PASS", "findings": []}, self._verify_candidate(plan))
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "over budget"):
            review._write_signed_record(
                self.root / "oversized-finalized.json",
                {"oversized": "x" * review.MAX_CANDIDATE_FINALIZED_RECEIPT},
                key=self.key, signers=self.signers,
                max_bytes=review.MAX_CANDIDATE_FINALIZED_RECEIPT,
            )

    def test_clean_frozen_candidate_signed_five_axis_handoff(self) -> None:
        plan = self._candidate_plan(dirty=False)
        self.assertFalse(plan["binding"]["candidate_binding"]["dirty"])
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        self.assertEqual("PASS", self._verify_candidate(plan)["verdict"])

    def test_frozen_candidate_origin_survives_nix_python_runtime_switch(self) -> None:
        # The trusted Writer/Test tasks really used the original Python.
        # A later Nix reviewer must verify their recorded argv, not rebuild it
        # with its own new sys.executable.
        original = self._candidate_plan()
        next_python = "/nix/store/" + "f" * 32 + "-new-reviewer/bin/python3"
        self.assertNotEqual(sys.executable, next_python)
        with mock.patch.object(sys, "executable", next_python):
            replay = producer.plan_frozen_candidate_review(
                self.candidate_manifest["workspace_id"]
            )
            self.assertEqual(
                original["binding"]["candidate_binding"],
                replay["binding"]["candidate_binding"],
            )
            started = self._start_plan(replay)
            self._complete_candidate(replay, started)
            self._finalize_candidate(replay, started)
            self.assertEqual("PASS", self._verify_candidate(replay)["verdict"])

    def test_rewritten_server_task_argv_cannot_fake_cross_runtime_origin(self) -> None:
        self._candidate_plan()
        writer_id = self.candidate_manifest["tasks"]["writer"]
        db = sqlite3.connect(producer.TASK_DB)
        try:
            old = db.execute(
                "SELECT argv_json FROM tasks WHERE task_id=?", (writer_id,)
            ).fetchone()[0]
            argv = json.loads(old)
            argv[0] = "/nix/store/" + "0" * 32 + "-forged-runtime/bin/python3"
            rewritten = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
            db.execute(
                "UPDATE tasks SET argv_json=?, argv_sha256=? WHERE task_id=?",
                (rewritten, hashlib.sha256(rewritten.encode()).hexdigest(), writer_id),
            )
            db.commit()
        finally:
            db.close()
        with mock.patch.object(
            sys, "executable", "/nix/store/" + "f" * 32 + "-new-reviewer/bin/python3"
        ):
            with self.assertRaisesRegex(
                review.ReviewExecutionRejected, "Candidate task origin invalid"
            ):
                producer.plan_frozen_candidate_review(
                    self.candidate_manifest["workspace_id"]
                )

    def test_candidate_handoff_accepts_bound_completed_retried_tests(self) -> None:
        plan = self._candidate_plan(retried_tests=True)
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        self.assertEqual("PASS", self._verify_candidate(plan)["verdict"])

    def test_candidate_handoff_runs_role_capture_collect_and_close(self) -> None:
        self._candidate_role_capture_collect_and_close(runtime_switch=False)

    def test_completed_candidate_review_survives_runtime_switch_at_collect_and_close(self) -> None:
        self._candidate_role_capture_collect_and_close(runtime_switch=True)

    def _candidate_role_capture_collect_and_close(self, *, runtime_switch: bool) -> None:
        from test_agent_workspace import passing_toolchain_preflight, friction, role
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        workspace = self.workspace
        command = producer.candidate_review_command(plan["binding"]["review_batch_id"])
        real_verify = review.verified_first_party_candidate_handoff
        public_review = {}
        launched = []

        def start_task(**kwargs):
            launched.append(kwargs["argv"])
            public_review.update({"task_id": "c" * 24, "host": kwargs["host"], "attempt": 1,
                                  "resume_policy": "never", "cwd": kwargs["cwd"],
                                  "argv_sha256": workspace._task_argv_sha256(kwargs["argv"]),
                                  "state": "running", "terminal": False})
            return {"task": public_review}

        def complete_review_task():
            task_id = public_review["task_id"]
            argv = launched[0]
            argv_json = json.dumps(argv, ensure_ascii=False, separators=(",", ":"))
            argv_sha256 = workspace._task_argv_sha256(argv)
            self.assertEqual(public_review["argv_sha256"], argv_sha256)
            unit = f"grabowski-task-{task_id}-a1.service"
            outcome = {
                "task_id": task_id, "state": "completed", "unit": unit,
                "argv_sha256": argv_sha256, "attempt": 1,
                "execution_backend": "systemd-user", "systemd_scope": "user",
                "observation": {"state": "completed", "properties": {
                    "Result": "success", "ExecMainStatus": "0",
                }},
            }
            outcome["receipt_sha256"] = review._digest(outcome)
            path = producer.OUTCOMES / (task_id + ".json")
            self.assertFalse(path.exists())
            path.write_bytes(review._canonical(outcome))
            path.chmod(0o600)
            connection = sqlite3.connect(producer.TASK_DB)
            try:
                with connection:
                    connection.execute(
                        "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (task_id, public_review["host"], public_review["cwd"], argv_json,
                         argv_sha256, unit, "completed", 1, outcome["receipt_sha256"],
                         "systemd-user", "user"),
                    )
            finally:
                connection.close()
            public_review.update({"state": "completed", "terminal": True})

        def task_public(task_id, **kwargs):
            if task_id == "c" * 24:
                return public_review
            return {**producer._task_row(producer.TASK_DB, task_id), "terminal": True}

        with (
            mock.patch.object(producer, "RECEIPTS", self.root / "plans-state"),
            mock.patch.object(review, "verified_first_party_candidate_handoff", side_effect=lambda p: real_verify(
                p, root=self.state, signers=self.signers, root_owned_signers=False, now_unix=self.now,
            )),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_role_toolchain_preflight", side_effect=passing_toolchain_preflight),
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=start_task),
            mock.patch.object(workspace, "_task_public", side_effect=task_public),
            mock.patch.object(workspace.base, "_append_audit"),
            mock.patch.object(friction, "EXECUTION_OUTCOME_LOG", self.root / "execution-outcomes.jsonl"),
        ):
            producer._store_plan(plan)
            retried = workspace.grabowski_agent_workspace_role_retry(
                self.candidate_manifest["workspace_id"], "review", command,
            )
            self.assertEqual("retry_started", retried["state"])
            # Exercise the actual signed verifier, subprocess stdin/output,
            # parser and create-only role receipt. Only OS sandbox launching
            # is substituted here; this fixture is not isolation proof.
            with (
                mock.patch.object(role, "sandbox_argv", side_effect=lambda repo, argv, **kw: argv),
                mock.patch.object(role, "runtime_sandbox_argv", side_effect=lambda argv: argv),
            ):
                self.assertEqual(0, role.main(launched[0][3:]))
            complete_review_task()
            manifest = workspace._manifest(self.candidate_manifest["workspace_id"])
            producer.verify_workspace_candidate_review(manifest)
            if runtime_switch:
                next_python = "/nix/store/" + "f" * 32 + "-new-reviewer/bin/python3"
                runtime = mock.patch.object(sys, "executable", next_python)
                runtime.start()
                self.addCleanup(runtime.stop)
                self.assertIsNone(producer.candidate_review_batch(command),
                                  "new dispatch still requires the current runtime")
                producer.verify_workspace_candidate_review(manifest)
                for field in ("batch", "task", "attempt", "workspace", "repository", "command_hash"):
                    altered = copy.deepcopy(manifest)
                    if field == "batch":
                        altered["first_party_candidate_review_batch"] = "0" * 32
                    elif field == "task":
                        altered["tasks"]["review"] = altered["tasks"]["tests"]
                    elif field == "attempt":
                        altered["role_final_attempt"]["review"] += 1
                    elif field == "workspace":
                        altered["workspace_id"] = "0" * 32
                    elif field == "repository":
                        altered["writer_worktree"] = str(self.root)
                    else:
                        altered["role_retries"]["review"]["attempts"][-1]["new_command_sha256"] = "0" * 64
                    with self.subTest(binding=field):
                        with self.assertRaises((review.ReviewExecutionRejected, workspace.AgentWorkspaceError)):
                            producer.verify_workspace_candidate_review(altered)
                altered_argv = list(launched[0])
                altered_argv[altered_argv.index("--output") + 1] += ".foreign"
                connection = sqlite3.connect(producer.TASK_DB)
                try:
                    with connection:
                        connection.execute(
                            "UPDATE tasks SET argv_json=?, argv_sha256=? WHERE task_id=?",
                            (json.dumps(altered_argv, ensure_ascii=False, separators=(",", ":")),
                             workspace._task_argv_sha256(altered_argv), public_review["task_id"]),
                        )
                    with self.assertRaisesRegex(review.ReviewExecutionRejected, "wrapper/command drift"):
                        producer.verify_workspace_candidate_review(manifest)
                    with connection:
                        connection.execute(
                            "UPDATE tasks SET argv_json=?, argv_sha256=? WHERE task_id=?",
                            (json.dumps(launched[0], ensure_ascii=False, separators=(",", ":")),
                             workspace._task_argv_sha256(launched[0]), public_review["task_id"]),
                        )
                finally:
                    connection.close()
            collected = workspace.grabowski_agent_workspace_collect(self.candidate_manifest["workspace_id"])
            self.assertEqual("complete", collected["state"], collected)
            self.assertEqual("PASS", collected["result"]["verification_summary"]["outcome"])
            result = collected["result"]
            with (
                mock.patch.object(workspace, "_tmux_has_session", return_value=False),
                mock.patch.object(workspace.resources, "release_resources", return_value={
                    "released": [{"resource_key": k} for k in self.candidate_manifest["resources"]["lease_keys"]],
                }),
                mock.patch.object(workspace.resources, "list_resources", return_value=[]),
            ):
                closed = workspace.grabowski_agent_workspace_close(
                    self.candidate_manifest["workspace_id"], result["writer_head"],
                    result["diff_sha256"], result["result_sha256"],
                )
            self.assertEqual("complete", closed["close_receipt"]["state"])

    def test_candidate_missing_axis_and_fake_pass_cannot_finalize(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        with self.assertRaises(review.ReviewExecutionRejected):
            self._submit(started, {"axis": review.REQUIRED_AXES[0], "verdict": "PASS"})
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "coverage"):
            self._finalize_candidate(plan, started)

    def test_candidate_source_drift_and_patch_tamper_reject(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        source = self.repo / self.source_path
        original = source.read_bytes()
        source.write_bytes(original + b"DRIFT = True\n")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "drift"):
            self._verify_candidate(plan)
        source.write_bytes(original)
        patch = Path(plan["binding"]["candidate_binding"]["patch"]["path"])
        patch.write_bytes(patch.read_bytes() + b"edited patch\n")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "patch"):
            self._verify_candidate(plan)

    def test_candidate_historical_reject_survives_batch_rotation(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        self._complete_candidate(plan, started, reject=True)
        with self.assertRaises(review.ReviewExecutionRejected):
            self._finalize_candidate(plan, started)
        # A fresh test receipt cannot erase an earlier semantic REJECT for
        # this unchanged Candidate by changing the full session source hash.
        tests_path = self.workspace._role_receipt_path(self.candidate_manifest, "tests")
        tests = json.loads(tests_path.read_bytes())
        tests["fixture_execution_note"] = "fresh completed test readback"
        tests["receipt_sha256"] = self.workspace._sha256_json({k: v for k, v in tests.items() if k != "receipt_sha256"})
        self.workspace._atomic_json(tests_path, tests)
        later = producer.plan_frozen_candidate_review(self.candidate_manifest["workspace_id"])
        later_session = self._start_plan(later)
        self._complete_candidate(later, later_session)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material finding"):
            self._finalize_candidate(later, later_session)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material finding"):
            review._assert_no_first_party_reject_for_legacy_review(
                later["binding"], repository=self.repo, root=self.state, signers=self.signers, root_owned_signers=False,
            )

    def test_candidate_source_read_checks_drift_before_signing_readback(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        original_reader = review._first_party_source_blob

        def drifting_read(*args):
            data = original_reader(*args)
            source = self.repo / self.source_path
            source.write_bytes(source.read_bytes() + b"DRIFT_DURING_READ = True\n")
            return data

        with mock.patch.object(review, "_first_party_source_blob", side_effect=drifting_read):
            with self.assertRaisesRegex(review.ReviewExecutionRejected, "drift"):
                self._read(started, review.REQUIRED_AXES[0], "source", self.source_path, "head", 1, 4)
        reads = self.state / "sessions" / started["review_session_id"] / "reads"
        self.assertEqual([], list(reads.iterdir()))

    def test_candidate_writer_and_test_receipts_are_required(self) -> None:
        plan = self._candidate_plan()
        for role in ("writer", "tests"):
            path = self.workspace._role_receipt_path(self.candidate_manifest, role)
            original = path.read_bytes()
            path.unlink()
            with self.assertRaisesRegex(review.ReviewExecutionRejected, "receipt"):
                producer._current_source(self.repo, plan["binding"])
            path.write_bytes(original)
            path.chmod(0o600)
            changed = json.loads(original)
            changed["returncode"] = 37
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(review.ReviewExecutionRejected, "receipt"):
                producer._current_source(self.repo, plan["binding"])
            path.write_bytes(original)

    def test_candidate_signed_axis_cannot_replay_into_another_session(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        later = producer.plan_frozen_candidate_review(self.candidate_manifest["workspace_id"])
        new = self._start_plan(later)
        axis = review.REQUIRED_AXES[0]
        count = len(review._first_party_diff(self.repo, later["binding"]).decode().splitlines())
        self._read(new, axis, "diff", "", "head", 1, count)
        old_axes = self.state / "sessions" / started["review_session_id"] / "axes"
        new_axes = self.state / "sessions" / new["review_session_id"] / "axes"
        for path in old_axes.iterdir():
            shutil.copyfile(path, new_axes / path.name)
            (new_axes / path.name).chmod(0o600)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "axis.*binding|crossed|axis.*invalid"):
            self._finalize_candidate(later, new)

    def test_candidate_missing_signed_axis_receipt_blocks_handoff_readback(self) -> None:
        plan = self._candidate_plan()
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        axes = self.state / "sessions" / started["review_session_id"] / "axes"
        path = next(axes.glob("*.json"))
        envelope = json.loads(path.read_bytes())
        del envelope["signature"]
        path.write_bytes(review._canonical(envelope))
        with self.assertRaises((review.ReviewExecutionRejected, FileNotFoundError)):
            self._verify_candidate(plan)

    def _issuer(self, tool_name: str, arguments: dict) -> dict:
        """Consume a real HMAC assertion; this origin is intentionally not mocked."""
        self._request_counter += 1
        request_id = secrets.token_hex(16)  # A new real request identity per signed invocation.
        arguments_sha256 = assertion.canonical_arguments_sha256(arguments)
        body_sha256 = hashlib.sha256(
            json.dumps(
                {"name": tool_name, "arguments": arguments},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        mac = assertion.assertion_mac(
            secret=SECRET, request_id=request_id, issued_at_unix=self.now,
            audience=assertion.ASSERTION_AUDIENCE, tool_name=tool_name,
            arguments_sha256=arguments_sha256, body_sha256=body_sha256,
            runtime_binding_sha256=RUNTIME_SHA256,
        )
        evidence = assertion.consume_assertion(
            secret=SECRET, client_scope_sha256=SCOPE_SHA256,
            runtime_binding_sha256=RUNTIME_SHA256,
            asserted_runtime_binding_sha256=RUNTIME_SHA256,
            request_id=request_id, issued_at_unix=self.now,
            audience=assertion.ASSERTION_AUDIENCE, tool_name=tool_name,
            arguments_sha256=arguments_sha256, body_sha256=body_sha256,
            mac_sha256=mac, session_id="first-party-review-test",
            now_unix=self.now,
        )
        evidence["client_scope_kind"] = "connector_capability"
        return review.authenticated_first_party_issuer(
            "primary", evidence, expected_tool=tool_name,
        )

    def _start(self) -> tuple[dict, dict]:
        plan = self._plan()
        return plan, self._start_plan(plan)

    def _start_plan(self, plan: dict) -> dict:
        arguments = {
            "review_batch_id": plan["binding"]["review_batch_id"],
            "reason": "Start exact-revision semantic review.",
            "user_intent": "Verify the first-party review workflow.",
        }
        started = review.start_first_party_review_session(
            plan, self._issuer(review.FIRST_PARTY_TOOL_START, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )
        return started

    def _seal_direct(self, plan: dict) -> tuple[dict, Path]:
        receipts = self.root / ("audits-" + plan["binding"]["review_batch_id"])
        sealed = producer._seal_first_party_review(
            plan, signers=self.signers, receipts=receipts,
            first_party_root=self.state, repository=self.repo,
            root_owned_signers=False, now_unix=self.now,
        )
        audit = json.loads(
            Path(sealed["audit_path"]).read_text(encoding="utf-8")
        )
        return audit, receipts

    def _receipt_errors(self, audit: dict, receipts: Path) -> list[str]:
        # Other suites explicitly mock the module-level public verifier for
        # unrelated routing tests. A security-negative test must execute the
        # actual source verifier even after a leaked test mock.
        spec = importlib.util.spec_from_file_location(
            "isolated_first_party_signed_receipt_verifier",
            Path(review.__file__).resolve(strict=True),
        )
        if spec is None or spec.loader is None:
            raise AssertionError("real source verifier could not be loaded")
        actual = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(actual)
        return actual.review_receipt_errors(
            audit, _receipts=receipts, _signers=self.signers,
            _first_party_root=self.state, _repository=self.repo,
            _root_owned_signers=False, _now_unix=self.now,
        )

    def _read(self, started: dict, axis: str, read_kind: str, path: str,
              revision: str, first: int, last: int,
              *, now_unix: int | None = None) -> dict:
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "axis": axis,
            "read_kind": read_kind, "path": path, "revision": revision,
            "start_line": first, "end_line": last,
            "reason": "Read exact Git evidence for this semantic axis.",
            "user_intent": "Verify the first-party review workflow.",
        }
        return review.record_first_party_source_read(
            started["review_session_id"], started["session_nonce"], axis,
            read_kind, path, revision, first, last,
            self._issuer(review.FIRST_PARTY_TOOL_READ, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False,
            now_unix=self.now if now_unix is None else now_unix,
        )

    def _report(self, axis: str, number: int, refs: list[str], *, reject: bool = False) -> dict:
        prefix = f"Axis {number} {axis}"
        findings = []
        if reject:
            findings = [{
                "id": f"material-{number}", "severity": "high",
                "verdict": "UNRESOLVED",
                "summary": prefix + " identifies an unresolved authority failure whose exploit path remains reachable and therefore requires a source change before this exact revision can pass.",
                "evidence_refs": [refs[0]],
            }]
        return {
            "axis": axis, "verdict": "REJECT" if reject else "PASS",
            "summary": prefix + " performs a semantic review of the concrete control flow, data ownership, failure behavior, and exact-revision interactions. It compares the intended invariant with both changed source regions and explains why the observed implementation does or does not leave a material defect.",
            "axis_observations": [
                prefix + " observes that the first changed region establishes the controlling invariant and follows its values through the relevant failure boundary instead of treating test success as semantic evidence.",
                prefix + " observes that the second changed region has a distinct downstream consequence, including the rejection behavior and the authority boundary that must remain closed for this revision.",
            ],
            "evidence_refs": refs,
            "reviewed_risks": [
                {
                    "risk": prefix + " risk of accepting an unbound or replayed semantic decision",
                    "assessment": prefix + " traces the binding and replay checks across the first source range, evaluates the reachable failure path, and concludes whether a different session, head, or unsigned payload could satisfy the gate.",
                    "verdict": "MATERIAL" if reject else "NON_MATERIAL",
                    "evidence_refs": [refs[0]],
                },
                {
                    "risk": prefix + " risk of losing material findings during producer handoff",
                    "assessment": prefix + " traces the second source range into the immutable receipt handoff and checks that a negative verdict cannot be normalized, overwritten, or replaced by deterministic technical task output.",
                    "verdict": "NON_MATERIAL",
                    "evidence_refs": [refs[1]],
                },
            ],
            "findings": findings,
        }

    def _submit_axis(self, started: dict, axis: str, number: int,
                     *, reject: bool = False, full_diff: bool = True,
                     resolve_ids: tuple[str, ...] = ()) -> dict:
        lines = review._first_party_diff(
            self.repo, {"base_sha": self.base, "head_sha": self.head},
        ).decode("utf-8").splitlines(keepends=True)
        self._read(
            started, axis, "diff", "", "head", 1,
            len(lines) if full_diff else 1,
        )
        first = self._read(started, axis, "source", self.source_path, "head", 1, 8)
        second = self._read(started, axis, "source", self.source_path, "head", 9, 16)
        report = self._report(axis, number, [first["source_ref"], second["source_ref"]], reject=reject)
        for finding_id in resolve_ids:
            report["findings"].append({
                "id": finding_id, "severity": "high", "verdict": "RESOLVED",
                "summary": (
                    "This later authenticated revision-bound controller review "
                    "reexamines the original material claim against the exact "
                    "same frozen Git source. The earlier concern is explicitly "
                    "resolved as a mistaken reading of this source branch, "
                    "with the inspected source reference below, rather than "
                    "merely being ignored through a new review batch."
                ),
                "evidence_refs": [first["source_ref"]],
            })
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": report,
            "reason": "Submit substantive source-bound semantic analysis.",
            "user_intent": "Verify the first-party review workflow.",
        }
        return review.submit_first_party_axis_review(
            started["review_session_id"], started["session_nonce"], report,
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, arguments),
            root=self.state, key=self.key, signers=self.signers,
            root_owned_signers=False, now_unix=self.now,
        )

    def test_concurrent_axes_validate_before_signing(self) -> None:
        self._concurrent_axes(duplicate=True)

    def test_concurrent_distinct_axes_remain_verifiable(self) -> None:
        self._concurrent_axes(duplicate=False)

    def _concurrent_axes(self, *, duplicate: bool) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        reports = []
        issuers = []
        for number, axis in enumerate(review.REQUIRED_AXES[:2], 1):
            lines = review._first_party_diff(self.repo, plan["binding"]).splitlines()
            self._read(started, axis, "diff", "", "head", 1, len(lines))
            first = self._read(started, axis, "source", self.source_path, "head", 1, 8)
            second = self._read(started, axis, "source", self.source_path, "head", 9, 16)
            report = self._report(axis, number, [first["source_ref"], second["source_ref"]])
            if reports and duplicate:
                report["axis_observations"] = reports[0]["axis_observations"][:]
            reports.append(report)
            issuers.append(self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {"report": report}))

        # Both requests reach the exclusive-lock boundary before either enters.
        # Validation outside that boundary therefore deterministically sees stale axes.
        barrier = threading.Barrier(2)
        original_lock = review._first_party_lock

        def synchronized_lock(root, *, read_only=False):
            if not read_only:
                barrier.wait(timeout=20)
            return original_lock(root, read_only=read_only)

        def submit(number):
            try:
                return review.submit_first_party_axis_review(
                    started["review_session_id"], started["session_nonce"],
                    reports[number], issuers[number], root=self.state,
                    key=self.key, signers=self.signers, root_owned_signers=False,
                    now_unix=self.now,
                )
            except review.ReviewExecutionRejected as exc:
                return exc

        with mock.patch.object(review, "_first_party_lock", side_effect=synchronized_lock), \
                mock.patch.object(review, "_write_signed_record", wraps=review._write_signed_record) as signed:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(submit, range(2)))
            self.assertEqual(1 if duplicate else 2, signed.call_count, results)
        self.assertEqual(1 if duplicate else 2, sum(isinstance(item, dict) for item in results))
        if duplicate:
            loser = next(i for i, item in enumerate(results) if isinstance(item, Exception))
            self.assertIn("observation", str(results[loser]))
            # Reuse the already authenticated reads, with a fresh report and
            # invocation. Repeating identical read arguments would be a replay.
            reports[loser] = self._report(
                review.REQUIRED_AXES[loser], 11, reports[loser]["evidence_refs"],
            )
            issuers[loser] = self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {"report": reports[loser]})
            self.assertEqual("axis_accepted", submit(loser)["status"])
        else:
            self.assertEqual([1, 2], sorted(item["accepted_axis_count"] for item in results))
        # The surviving signed axis is verifiable; fresh, distinct observations
        # can complete every other axis in the same session.
        for number, axis in enumerate(review.REQUIRED_AXES[2:], 3):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_history_over_2048_authentic_unrelated_sessions(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        session_root = self.state / "sessions" / started["review_session_id"]
        original = review._read_signed_record(
            session_root / "session.json", signers=self.signers, root_owned_signers=False,
        )
        for number in range(2049):
            old = copy.deepcopy(original)
            old["session_id"] = f"{number:032x}"
            old["binding"]["pr"] += number + 1
            old["binding_sha256"] = review._digest(old["binding"])
            directory = self.state / "sessions" / old["session_id"]
            directory.mkdir(mode=0o700)
            review._write_signed_record(
                directory / "session.json", old, key=self.key, signers=self.signers,
            )
        # The actual Frozen-Candidate role retry must also survive 2049
        # unrelated *authentically signed* historical sessions. The fixture
        # signer is non-root but verification still checks real SSH signatures.
        real_read = review._read_signed_record

        def fixture_signed_read(path, *, signers, root_owned_signers):
            return real_read(path, signers=signers, root_owned_signers=False)

        with mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state), \
                mock.patch.object(review, "TRUSTED_SIGNERS", self.signers), \
                mock.patch.object(review, "_read_signed_record", side_effect=fixture_signed_read):
            producer.assert_candidate_review_history("unrelated-frozen-candidate")

        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

        # A partial historical same-revision session still blocks after that
        # unrelated history; there is no unsigned index or count-based bypass.
        rejected = self._start_plan(self._first_party_plan())
        self._submit_axis(rejected, review.REQUIRED_AXES[0], 1, reject=True)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._seal_direct(plan)

    def _legacy_abbreviated_diff(self, width: int) -> bytes:
        return review._git_read(
            self.repo,
            [
                "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                "--ignore-submodules=none", "--unified=3", f"--abbrev={width}",
                self.base, self.head, "--",
            ],
            maximum=review.FIRST_PARTY_MAX_DIFF_BYTES,
        )

    def test_legacy_abbrev_pass_remains_signed_and_verified_after_full_index(self) -> None:
        stable = review._first_party_diff(
            self.repo, {"base_sha": self.base, "head_sha": self.head},
        )
        abbreviated = self._legacy_abbreviated_diff(10)
        self.assertNotEqual(stable, abbreviated)
        self.assertEqual(
            abbreviated,
            review._first_party_signed_diff(
                self.repo, {
                    "binding": {"review_purpose": "pull_request", "base_sha": self.base,
                                "head_sha": self.head},
                    "canonical_diff_sha256": hashlib.sha256(abbreviated).hexdigest(),
                },
            ),
        )
        with mock.patch.object(review, "_first_party_diff", return_value=abbreviated):
            old_plan = self._first_party_plan()
            started = self._start_plan(old_plan)
            for number, axis in enumerate(review.REQUIRED_AXES, 1):
                self._submit_axis(started, axis, number)
            old_audit, old_receipts = self._seal_direct(old_plan)

        # The old exact signed source reads must remain valid on the new
        # pinned FULL-index renderer, without rewriting any old receipt.
        self.assertEqual([], self._receipt_errors(old_audit, old_receipts))
        new_plan = self._first_party_plan()
        new_start = self._start_plan(new_plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(new_start, axis, number)
        new_audit, new_receipts = self._seal_direct(new_plan)
        self.assertEqual([], self._receipt_errors(new_audit, new_receipts))

        # Unrelated object growth cannot change the new full-index source.
        other = self.repo / "unrelated-object"
        other.write_text("not part of either reviewed commit", encoding="utf-8")
        self._git("hash-object", "-w", "--", "unrelated-object")
        self.assertEqual(
            hashlib.sha256(stable).hexdigest(),
            hashlib.sha256(review._first_party_diff(
                self.repo, new_plan["binding"],
            )).hexdigest(),
        )

    def test_signed_legacy_mixed_index_widths_survive_full_index_and_reject_tampering(self) -> None:
        # Real SHA-1 collision in the first seven hex digits, not a mock PASS:
        # Git uses 8 characters for this file and 7 for the other file.
        collision = self.repo / "src" / "collision.py"
        collision.write_bytes(b"unique-blob-00000506\n")
        self._git("add", "src/collision.py")
        self._git("commit", "-qm", "collision base")
        self.base = self._git("rev-parse", "HEAD").strip()
        collision.write_bytes(b"unique-blob-00005938\n")
        ordinary = self.repo / self.source_path
        ordinary.write_bytes(
            ordinary.read_bytes() + "EXTRA_HEAD = 79\nNEL_BREAK\u0085SECOND = 80\n".encode("utf-8")
        )
        self._git("add", "src/collision.py", self.source_path)
        self._git("commit", "-qm", "collision head")
        self.head = self._git("rev-parse", "HEAD").strip()
        legacy = self._legacy_abbreviated_diff(7)
        rendered_indexes = [
            line for line in legacy.decode("utf-8").splitlines()
            if line.startswith("index ")
        ]
        self.assertEqual(2, len(rendered_indexes))
        self.assertIn("index 53bb2227..53bb2222 100644", rendered_indexes)
        self.assertTrue(any(
            len(line.split()[1].split("..")[0]) == 7
            and len(line.split()[1].split("..")[1]) == 7
            for line in rendered_indexes
        ))
        complete = review._first_party_diff(
            self.repo, {"base_sha": self.base, "head_sha": self.head},
        )
        self.assertNotEqual(legacy, complete)

        with mock.patch.object(review, "_first_party_diff", return_value=legacy):
            old_plan = self._first_party_plan()
            started = self._start_plan(old_plan)
            self._complete_candidate(old_plan, started)
            old_audit, old_receipts = self._seal_direct(old_plan)

        session_root = self.state / "sessions" / started["review_session_id"]
        session = review._read_signed_record(
            session_root / "session.json", signers=self.signers,
            root_owned_signers=False,
        )
        self.assertIn("\u0085".encode("utf-8"), legacy)
        original_git_read = review._git_read

        def forbid_untrusted_redisplay(repo, arguments, **kwargs):
            if any(item.startswith("--abbrev=") for item in arguments):
                raise AssertionError("signed chunks must not need mutable Git abbreviation width")
            return original_git_read(repo, arguments, **kwargs)

        with mock.patch.object(review, "_git_read", side_effect=forbid_untrusted_redisplay):
            recovered = review._first_party_signed_diff(
                self.repo, session, session_root=session_root,
                signers=self.signers, root_owned_signers=False,
            )
        self.assertEqual(legacy, recovered)
        # The registered five signed diff reads must be checked using one
        # historical diff reconstruction per verifier pass, not N times.
        with mock.patch.object(
            review, "_first_party_signed_diff", wraps=review._first_party_signed_diff,
        ) as recover_once:
            persisted = review._load_first_party_reads(
                session, session_root, signers=self.signers,
                root_owned_signers=False, repository=self.repo,
            )
        self.assertGreaterEqual(
            sum(item["read_kind"] == "diff" for item in persisted), 5,
        )
        self.assertEqual(1, recover_once.call_count)
        self.assertEqual([], self._receipt_errors(old_audit, old_receipts))

        # A fresh signed review must keep the prior genuine full-read receipt.
        current = self._first_party_plan()
        current_start = self._start_plan(current)
        self._complete_candidate(current, current_start)
        current_audit, current_receipts = self._seal_direct(current)
        self.assertEqual([], self._receipt_errors(current_audit, current_receipts))

        # Corrupt a signed data sidecar: recomputation must never hide the
        # mismatch behind a re-rendered Git diff or manufacture a PASS.
        signed_diff = next(
            item for item in sorted(session_root.joinpath("reads").glob("*.json"))
            if review._read_signed_record(
                item, signers=self.signers, root_owned_signers=False,
            )["read_kind"] == "diff"
        )
        first_data = signed_diff.with_suffix(".data")
        first_data.write_bytes(first_data.read_bytes() + b"tampering")
        with self.assertRaises(review.ReviewExecutionRejected):
            review._first_party_signed_diff(
                self.repo, session, session_root=session_root,
                signers=self.signers, root_owned_signers=False,
            )

    def test_legacy_abbrev_material_reject_still_blocks_full_index_review(self) -> None:
        abbreviated = self._legacy_abbreviated_diff(9)
        self.assertNotEqual(
            abbreviated, review._first_party_diff(
                self.repo, {"base_sha": self.base, "head_sha": self.head},
            ),
        )
        with mock.patch.object(review, "_first_party_diff", return_value=abbreviated):
            old_plan = self._first_party_plan()
            old_start = self._start_plan(old_plan)
            self._submit_axis(
                old_start, review.REQUIRED_AXES[0], 1, reject=True,
            )

        # Complete old signed data and material REJECT travel through exact
        # historical Git bytes, not through a synthetic empty-session skip.
        new_plan = self._first_party_plan()
        new_start = self._start_plan(new_plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(new_start, axis, number)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "previous signed material",
        ):
            self._seal_direct(new_plan)

    def test_empty_signed_wrong_canonical_diff_session_cannot_poison_new_review(self) -> None:
        # Real production regression: one valid issuer-signed START accidentally
        # used the GitHub-PR identity as local canonical diff identity. It has
        # zero review-axis receipts, hence no finding or REJECT to suppress.
        old_plan = self._first_party_plan()
        github_rendered_diff = b"GitHub PR rendered diff != local git raw diff"
        old_plan["binding"]["diff_sha256"] = hashlib.sha256(
            github_rendered_diff
        ).hexdigest()
        with mock.patch.object(
            review, "_first_party_diff", return_value=github_rendered_diff
        ):
            old_session = self._start_plan(old_plan)
        legacy_root = self.state / "sessions" / old_session["review_session_id"]
        self.assertEqual([], list((legacy_root / "axes").iterdir()))
        legacy = review._read_signed_record(
            legacy_root / "session.json", signers=self.signers,
            root_owned_signers=False,
        )
        self.assertNotEqual(
            hashlib.sha256(review._first_party_diff(
                self.repo, old_plan["binding"]
            )).hexdigest(),
            legacy["canonical_diff_sha256"],
        )
        self.assertEqual(
            legacy["binding"]["diff_sha256"], legacy["canonical_diff_sha256"],
            "historical defect confused GitHub patch identity with local raw diff",
        )
        self.assertEqual(
            producer._current_source(self.repo, old_plan["binding"]),
            legacy["source_raw_diff_sha256"],
        )

        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

        # If the supposedly empty historical registry later acquires any axis
        # entry, the exact same audit must fail closed, not silently skip it.
        invalid_axis = legacy_root / "axes" / "contracts_correctness.json"
        invalid_axis.write_text("{}", encoding="utf-8")
        invalid_axis.chmod(0o600)
        self.assertTrue(self._receipt_errors(audit, receipts))
        invalid_axis.unlink()

        # A malformed/unsigned READ sidecar is also not an empty inert session.
        # The old axis-only exception silently accepted this adversarial case.
        invalid_read = legacy_root / "reads" / ("a" * 32 + ".json")
        invalid_read.write_text("{}", encoding="utf-8")
        invalid_read.chmod(0o600)
        self.assertTrue(
            self._receipt_errors(audit, receipts),
            "malformed old read record must remain fail-closed",
        )

    def test_prior_signed_material_reject_remains_blocking_across_batches(self) -> None:
        # No change to Git source, PR or canonical diff between batches.
        plan_a = self._first_party_plan()
        session_a = self._start_plan(plan_a)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(session_a, axis, number, reject=number == 1)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "material finding"):
            self._seal_direct(plan_a)

        plan_b = self._first_party_plan()
        session_b = self._start_plan(plan_b)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(session_b, axis, number)
        self.assertNotEqual(plan_a["binding"]["review_batch_id"], plan_b["binding"]["review_batch_id"])
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous.*material"):
            self._seal_direct(plan_b)

    def test_later_explicit_signed_resolution_allows_same_revision(self) -> None:
        plan_a = self._first_party_plan()
        started_a = self._start_plan(plan_a)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started_a, axis, number, reject=number == 1)

        self.now += 1  # Signed second-resolution timestamps must prove later ordering.
        plan_b = self._first_party_plan()
        started_b = self._start_plan(plan_b)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                started_b, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        audit_b, receipts_b = self._seal_direct(plan_b)
        self.assertEqual([], self._receipt_errors(audit_b, receipts_b))

    def test_same_second_resolution_cannot_clear_prior_signed_reject(self) -> None:
        rejected = self._start_plan(self._first_party_plan())
        self._submit_axis(rejected, review.REQUIRED_AXES[0], 1, reject=True)
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                started, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._seal_direct(plan)

    def test_same_second_reject_invalidates_already_sealed_resolution(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                started, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

        rejected = self._start_plan(self._first_party_plan())
        self._submit_axis(rejected, review.REQUIRED_AXES[0], 1, reject=True)
        self.assertTrue(
            self._receipt_errors(audit, receipts),
            "a signed REJECT must dominate a resolution with the same timestamp",
        )

    def test_previous_signed_reject_is_scoped_to_original_revision(self) -> None:
        plan_a = self._first_party_plan()
        started_a = self._start_plan(plan_a)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started_a, axis, number, reject=number == 1)
        source = self.repo / self.source_path
        source.write_text(source.read_text(encoding="utf-8") + "REVISION = True\\n")
        self._git("add", self.source_path)
        self._git("commit", "-qm", "resolve material concern in a new revision")
        self.head = self._git("rev-parse", "HEAD").strip()
        plan_b = self._first_party_plan()
        started_b = self._start_plan(plan_b)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started_b, axis, number)
        audit_b, receipts_b = self._seal_direct(plan_b)
        self.assertEqual([], self._receipt_errors(audit_b, receipts_b))

    def _signed_release_plan(
        self, *, release_id: str = "test-release-r3",
    ) -> tuple[dict, dict, str]:
        release = {
            "serving_release_id": release_id,
            "serving_tree": self._git("rev-parse", self.base + "^{tree}").strip(),
            "target_tree": self._git("rev-parse", self.head + "^{tree}").strip(),
        }
        diff = producer._current_source(
            self.repo, {"repo": "heimgewebe/grabowski",
                        "base_sha": self.base, "head_sha": self.head},
        )
        plan = producer.plan_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256=diff, purpose="post_merge_release",
            release_binding=release,
            bwrap="/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap",
            python="/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3",
        )
        return plan, release, diff

    def _check_signed_release_fallback(self, release: dict, diff: str) -> dict:
        import grabowski_release_admission as admission

        genuine = review._assert_no_first_party_reject_for_legacy_review

        def signed_history(binding: dict, **_options: object) -> None:
            genuine(
                binding, repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False,
            )

        with (
            mock.patch.object(admission, "RELEASE_SELF_REVIEW_ROOT", self.root / "no-r3-audit"),
            mock.patch.object(admission, "validate_independent_release_review",
                              return_value={"review_pr": 1649, "independent_pass_count": 1,
                                            "admissible_slots": ["independent-claude"]}),
            mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state),
            mock.patch.object(review, "_assert_no_first_party_reject_for_legacy_review",
                              side_effect=signed_history),
        ):
            return admission.validate_release_review(
                serving_head=self.base, target_head=self.head, diff_sha256=diff, review_pr=1649,
                serving_release_id=release["serving_release_id"],
                serving_tree=release["serving_tree"], target_tree=release["target_tree"],
            )

    def test_release_without_historical_session_allows_independent_pass(self) -> None:
        _plan, release, diff = self._signed_release_plan()
        self.assertEqual(
            "independent", self._check_signed_release_fallback(release, diff)["review_mode"],
        )

    def test_release_partial_signed_reject_blocks_independent_pass(self) -> None:
        import grabowski_release_admission as admission

        plan, release, diff = self._signed_release_plan()
        started = self._start_plan(plan)
        self._submit_axis(started, review.REQUIRED_AXES[0], 1, reject=True)
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "material REJECT"):
            self._check_signed_release_fallback(release, diff)

    def test_release_later_signed_resolution_allows_independent_pass(self) -> None:
        plan, release, diff = self._signed_release_plan()
        first = self._start_plan(plan)
        self._submit_axis(first, review.REQUIRED_AXES[0], 1, reject=True)
        later, _, _ = self._signed_release_plan()
        self.now += 1  # A truly later signed submission, not an older same-second claim.
        second = self._start_plan(later)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                second, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        self.assertEqual(
            "independent", self._check_signed_release_fallback(release, diff)["review_mode"],
        )

    def test_release_other_release_identity_does_not_inherit_signed_reject(self) -> None:
        plan, _release, diff = self._signed_release_plan()
        session = self._start_plan(plan)
        self._submit_axis(session, review.REQUIRED_AXES[0], 1, reject=True)
        _, different_release, _ = self._signed_release_plan(release_id="different-release")
        self.assertEqual(
            "independent", self._check_signed_release_fallback(different_release, diff)["review_mode"],
        )

    def test_release_tampered_signed_axis_cannot_pass_independent(self) -> None:
        import grabowski_release_admission as admission

        plan, release, diff = self._signed_release_plan()
        session = self._start_plan(plan)
        self._submit_axis(session, review.REQUIRED_AXES[0], 1, reject=True)
        path = (
            self.state / "sessions" / session["review_session_id"] /
            "axes" / (review.REQUIRED_AXES[0] + ".json")
        )
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "authenticated"):
            self._check_signed_release_fallback(release, diff)

    def test_release_concurrent_signed_reject_rechecked_at_final_authorization(self) -> None:
        import grabowski_release_admission as admission

        plan, release, diff = self._signed_release_plan()
        original = review._assert_no_first_party_reject_for_legacy_review

        def signed_history(binding: dict, **_options: object) -> None:
            original(binding, repository=self.repo, root=self.state,
                     signers=self.signers, root_owned_signers=False)

        def ci_with_concurrent_reject(_target: str, **_kwargs: object) -> dict:
            session = self._start_plan(plan)
            self._submit_axis(session, review.REQUIRED_AXES[0], 1, reject=True)
            return {
                "checks": [], "checks_sha256": "a" * 64,
                "workflow": {
                    "ci_policy_transition_required": False,
                    "ci_policy_transition_review_binding_sha256": None,
                },
            }

        with (
            mock.patch.object(admission, "RELEASE_SELF_REVIEW_ROOT", self.root / "no-r3-audit"),
            mock.patch.object(admission, "validate_independent_release_review",
                              return_value={"review_pr": 1649, "independent_pass_count": 1,
                                            "admissible_slots": ["independent-claude"]}),
            mock.patch.object(admission, "_fresh_github_checks", side_effect=ci_with_concurrent_reject),
            mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state),
            mock.patch.object(review, "_assert_no_first_party_reject_for_legacy_review",
                              side_effect=signed_history) as verifier,
        ):
            with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "material REJECT"):
                admission.validate_release(
                    serving_head=self.base, target_head=self.head,
                    serving_release_id=release["serving_release_id"],
                    serving_tree=release["serving_tree"], target_tree=release["target_tree"],
                    diff_sha256=diff, review_pr=1649,
                )
        self.assertEqual(1, verifier.call_count, "new REJECT must be checked after CI")

    def test_release_independent_pass_cannot_hide_signed_first_party_reject(self) -> None:
        import grabowski_release_admission as admission

        release = {
            "serving_release_id": "test-release-r3",
            "serving_tree": self._git("rev-parse", self.base + "^{tree}").strip(),
            "target_tree": self._git("rev-parse", self.head + "^{tree}").strip(),
        }
        raw_diff = producer._current_source(
            self.repo, {"repo": "heimgewebe/grabowski",
                        "base_sha": self.base, "head_sha": self.head},
        )
        plan = producer.plan_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256=raw_diff, purpose="post_merge_release",
            release_binding=release,
            bwrap="/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap",
            python="/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3",
        )
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started, axis, number, reject=number == 1)
        signed_guard = review._assert_no_first_party_reject_for_legacy_review

        def read_actual_signed_history(binding: dict, **_options: object) -> None:
            signed_guard(
                binding, repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False,
            )

        with (
            mock.patch.object(admission, "RELEASE_SELF_REVIEW_ROOT", self.root / "no-sealed-r3"),
            mock.patch.object(admission, "validate_independent_release_review",
                              return_value={"review_pr": 1649, "independent_pass_count": 1,
                                            "admissible_slots": ["independent-claude"]}) as independent,
            mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state),
            mock.patch.object(review, "_assert_no_first_party_reject_for_legacy_review",
                              side_effect=read_actual_signed_history) as history,
        ):
            with self.assertRaisesRegex(admission.ReleaseAdmissionDenied, "first.party|material|REJECT"):
                admission.validate_release_review(
                    serving_head=self.base, target_head=self.head,
                    diff_sha256=raw_diff, review_pr=1649,
                    serving_release_id=release["serving_release_id"],
                    serving_tree=release["serving_tree"], target_tree=release["target_tree"],
                )
        self.assertTrue(history.called, "release fallback must inspect signed session receipts")
        self.assertTrue(independent.called, "the positive independent result must be reconciled")

    def test_standard_tier_gate_cannot_hide_signed_first_party_reject(self) -> None:
        from test_pr_review_gate_self_diff import _self_review, _state, gate

        plan = self._first_party_plan()
        binding = plan["binding"]
        state = _state(diff_sha=binding["diff_sha256"])
        state["pr"]["number"] = 1649
        state["pr"]["baseRefOid"] = self.base
        state["pr"]["headRefOid"] = self.head
        state["pr"]["files"] = [{"path": self.source_path}]
        state["pr"]["reviews"] = [{
            "author": {"login": "chatgpt-codex-connector"},
            "state": "APPROVED", "commit_id": self.head,
        }]
        packet = _self_review(diff_sha=binding["diff_sha256"])
        packet["pr"] = 1649
        packet["base_sha"] = self.base
        packet["head_sha"] = self.head
        packet["reviewed_files"] = [self.source_path]
        packet["review_iterations"] = [
            {"n": n, "summary": f"independent source review pass {n}",
             "material_findings": 0} for n in range(1, 4)
        ]
        self.assertNotEqual(
            "high_critical",
            gate.classify_complexity(state["pr"], packet,
                                     repo_name="heimgewebe/grabowski")["review_tier"],
        )
        with mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state):
            baseline = gate.evaluate_review_gate(state, self_review=packet)
        self.assertEqual("PASS", baseline["verdict"], baseline["failures"])

        signed = self._start_plan(plan)
        self._submit_axis(signed, review.REQUIRED_AXES[0], 1, reject=True)
        genuine = review._assert_no_first_party_reject_for_legacy_review

        def verify_signed_history(candidate: dict, **_kwargs: object) -> None:
            genuine(candidate, repository=self.repo, root=self.state,
                    signers=self.signers, root_owned_signers=False)

        with (
            mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state),
            mock.patch.object(review, "_assert_no_first_party_reject_for_legacy_review",
                              side_effect=verify_signed_history),
        ):
            rejected = gate.evaluate_review_gate(state, self_review=packet)
        self.assertEqual("BLOCK", rejected["verdict"], rejected["failures"])
        self.assertTrue(
            any("signed first-party" in item for item in rejected["failures"]),
            rejected["failures"],
        )

    def test_captain_standard_tier_checks_signed_history_and_later_resolution(self) -> None:
        import grabowski_merge_guard as captain

        plan = self._first_party_plan()
        started = self._start_plan(plan)
        self._submit_axis(started, review.REQUIRED_AXES[0], 1, reject=True)
        serving_checkout = self.root / "serving-only"
        self._git("worktree", "add", "--detach", str(serving_checkout), self.base)
        binding = {
            "repository": "heimgewebe/grabowski",
            "pull_request": 1649,
            "base_sha": self.base, "head_sha": self.head,
            "diff_sha256": plan["binding"]["diff_sha256"],
        }
        authentic = review._assert_no_first_party_reject_for_legacy_review

        def inspect_original_signed_review(candidate: dict, **_options: object) -> None:
            self.assertEqual(candidate["repo"].casefold(), "heimgewebe/grabowski")
            authentic(
                candidate, repository=serving_checkout, root=self.state,
                signers=self.signers, root_owned_signers=False,
            )

        with (
            mock.patch.object(review, "FIRST_PARTY_REVIEW_ROOT", self.state),
            mock.patch.object(review, "_assert_no_first_party_reject_for_legacy_review",
                              side_effect=inspect_original_signed_review),
        ):
            self.assertEqual(
                ["merge_guard_signed_first_party_material_reject_or_invalid_history"],
                captain._signed_first_party_material_history_errors(binding),
            )
            self.assertEqual(
                [], captain._signed_first_party_material_history_errors({
                    **binding, "pull_request": 1650,
                }),
                "a signed REJECT must not bleed into another PR identity",
            )
            self.assertEqual(
                [], captain._signed_first_party_material_history_errors({
                    **binding, "repository": "alexdermohr/machtverflechtungen",
                }),
                "a heimgewebe-only signed review cannot apply to another GitHub owner",
            )
            self.assertEqual(
                ["merge_guard_signed_first_party_history_binding_invalid"],
                captain._signed_first_party_material_history_errors({
                    **binding, "repository": "../invalid/name",
                }),
                "invalid repository identities must still be rejected",
            )
            self.assertEqual(
                ["merge_guard_signed_first_party_material_reject_or_invalid_history"],
                captain._signed_first_party_material_history_errors({
                    **binding, "repository": "Heimgewebe/grabowski",
                }),
                "case aliases of the signed owner must not bypass REJECT history",
            )
            self.assertEqual(
                ["merge_guard_signed_first_party_material_reject_or_invalid_history"],
                captain._signed_first_party_material_history_errors({
                    **binding, "repository": "heimgewebe/Grabowski",
                }),
                "case aliases of signed repository names must not bypass REJECT history",
            )

            for malformed in (
                "", "heimgewebe/", "heimgewebe//grabowski",
                "heimgewebe/grabowski/extra", "heimgewebe/grabowski ",
                None, 42, [], {},
            ):
                self.assertEqual(
                    ["merge_guard_signed_first_party_history_binding_invalid"],
                    captain._signed_first_party_material_history_errors({
                        **binding, "repository": malformed,
                    }),
                    "malformed or untyped repository identities must fail closed",
                )
            self.assertEqual(
                ["merge_guard_signed_first_party_material_reject_or_invalid_history"],
                captain._signed_first_party_material_history_errors({
                    **binding, "repository": "HEIMGEWEBE/Grabowski",
                }),
                "mixed-case owner and repository aliases retain the signed REJECT",
            )

            self.now += 1
            resolution = self._start_plan(self._first_party_plan())
            self._submit_axis(
                resolution, review.REQUIRED_AXES[0], 1, resolve_ids=("material-1",),
            )
            self.assertEqual(
                [], captain._signed_first_party_material_history_errors(binding),
                "a genuinely later signed resolution must clear the exact finding",
            )
            for alias in ("heimgewebe/Grabowski", "Heimgewebe/grabowski", "HEIMGEWEBE/Grabowski"):
                self.assertEqual(
                    [], captain._signed_first_party_material_history_errors({
                        **binding, "repository": alias,
                    }),
                    "a signed resolution must also clear the same GitHub repository under case aliases",
                )

    def test_signed_mixed_case_historical_repository_reject_and_resolution(self) -> None:
        # The original record is genuinely signed for a managed mixed-case
        # repository, not rewritten after signing to manufacture a match.
        lower = self.repo
        upper = self.root / "Grabowski"
        lower.rename(upper)
        self.repo = upper
        self._git("remote", "set-url", "origin", "git@github.com:heimgewebe/Grabowski.git")
        historical = self._first_party_plan()
        self.assertEqual("heimgewebe/Grabowski", historical["binding"]["repo"])
        started = self._start_plan(historical)
        self._submit_axis(started, review.REQUIRED_AXES[0], 1, reject=True)
        signed = review._read_signed_record(
            self.state / "sessions" / started["review_session_id"] / "session.json",
            signers=self.signers, root_owned_signers=False,
        )
        self.assertEqual("heimgewebe/Grabowski", signed["binding"]["repo"])

        self._git("remote", "set-url", "origin", "git@github.com:heimgewebe/grabowski.git")
        upper.rename(lower)
        self.repo = lower
        same_revision = self._first_party_plan()
        self.assertEqual("heimgewebe/grabowski", same_revision["binding"]["repo"])
        newer = self._start_plan(same_revision)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(newer, axis, number)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "previous signed material"):
            self._seal_direct(same_revision)

        # The same real historic REJECT cannot bleed across PR identity.
        separate_pr = producer.plan_first_party_review(
            repo=self.repo, pr=1650, base_sha=self.base, head_sha=self.head,
            diff_sha256=same_revision["binding"]["diff_sha256"],
        )
        other = self._start_plan(separate_pr)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(other, axis, number)
        other_audit, other_receipts = self._seal_direct(separate_pr)
        self.assertEqual([], self._receipt_errors(other_audit, other_receipts))

        # Only a later, actually signed resolution clears that exact PR.
        self.now += 1
        resolved_plan = self._first_party_plan()
        resolved = self._start_plan(resolved_plan)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                resolved, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        audit, receipts = self._seal_direct(resolved_plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_signed_unicode_historical_repository_is_invalid(self) -> None:
        # The old record is signed by the real fixture key, not injected via
        # an untrusted mock. Unicode long-s casefolds to ASCII "s" in Python,
        # but GitHub repo identity and the signed producer are ASCII-only.
        historical = self._first_party_plan()
        started = self._start_plan(historical)
        path = self.state / "sessions" / started["review_session_id"] / "session.json"
        old = review._read_signed_record(
            path, signers=self.signers, root_owned_signers=False,
        )
        old["binding"]["repo"] = "heimgewebe/grabow\u017fki"
        old["binding_sha256"] = review._digest(old["binding"])
        path.unlink()
        path.with_suffix(".sig").unlink()
        review._write_signed_record(
            path, old, key=self.key, signers=self.signers,
        )
        signed = review._read_signed_record(
            path, signers=self.signers, root_owned_signers=False,
        )
        self.assertEqual("heimgewebe/grabow\u017fki", signed["binding"]["repo"])
        self.assertEqual(
            "heimgewebe/grabowski", signed["binding"]["repo"].casefold(),
            "the crafted signed history must exercise an actual Unicode-fold collision",
        )

        current = self._first_party_plan()
        later = self._start_plan(current)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(later, axis, number)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected,
            "previous signed session repository identity invalid",
        ):
            self._seal_direct(current)

    def test_signed_reject_survives_equivalent_diff_identity(self) -> None:
        original = self._first_party_plan()
        first = self._start_plan(original)
        self._submit_axis(first, review.REQUIRED_AXES[0], 1, reject=True)
        # GitHub can represent identical immutable base/head source bytes
        # under canonical, canonical-v1, or current-provider raw SHA labels.
        alias = producer.plan_first_party_review(
            repo=self.repo, pr=1649, base_sha=self.base, head_sha=self.head,
            diff_sha256="d" * 64,
        )
        self.assertNotEqual(original["binding"]["diff_sha256"], alias["binding"]["diff_sha256"])
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "previous signed material",
        ):
            review._assert_no_first_party_reject_for_legacy_review(
                alias["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False,
            )
        second = self._start_plan(alias)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(second, axis, number)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "previous signed material",
        ):
            self._seal_direct(alias)

    def test_legacy_v2_review_cannot_hide_first_party_reject(self) -> None:
        plan_a = self._first_party_plan()
        started_a = self._start_plan(plan_a)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(started_a, axis, number, reject=number == 1)
        another_batch = self._first_party_plan()
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "previous signed material",
        ):
            review._assert_no_first_party_reject_for_legacy_review(
                another_batch["binding"], repository=self.repo,
                root=self.state, signers=self.signers,
                root_owned_signers=False,
            )

    def test_later_signed_reject_invalidates_previous_sealed_pass(self) -> None:
        plan_a = self._first_party_plan()
        session_a = self._start_plan(plan_a)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(session_a, axis, number)
        audit_a, receipts_a = self._seal_direct(plan_a)
        self.assertEqual([], self._receipt_errors(audit_a, receipts_a))

        plan_b = self._first_party_plan()
        session_b = self._start_plan(plan_b)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(session_b, axis, number, reject=number == 1)
        self.assertTrue(
            self._receipt_errors(audit_a, receipts_a),
            "later authentic material REJECT must invalidate an old PASS audit",
        )

    def test_five_real_authenticated_source_read_reports_are_accepted(self) -> None:
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            result = self._submit_axis(started, axis, number)
            self.assertEqual("axis_accepted", result["status"])
        accepted = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False, now_unix=self.now,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(accepted))
        self.assertTrue(all(
            item["provenance_kind"] == "first_party_authenticated_controller"
            for item in accepted.values()
        ))

    def test_first_party_direct_audit_passes_public_receipt_verifier(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

        for field, replacement in (
            ("repo", "heimgewebe/heim-pc"),
            ("base_sha", "1" * 40),
            ("head_sha", "2" * 40),
            ("diff_sha256", "3" * 64),
        ):
            replay = copy.deepcopy(audit)
            replay[field] = replacement
            self.assertTrue(self._receipt_errors(replay, receipts), field)
        altered_proof = copy.deepcopy(audit)
        altered_proof["review_pass_receipts"][0]["axis_report_sha256"] = "4" * 64
        self.assertTrue(self._receipt_errors(altered_proof, receipts))

        persisted_read = next((
            self.state / "sessions" / audit["review_pass_receipts"][0]["session_id"] / "reads"
        ).glob("*.data"))
        persisted_read.write_bytes(b"tampered source bytes")
        self.assertTrue(self._receipt_errors(audit, receipts))

    def test_forged_repo_is_rejected_even_when_another_test_mocks_public_verifier(self) -> None:
        """Exercise the real cryptographic verifier despite prior gate fixture mocks."""
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        forged = copy.deepcopy(audit)
        forged["repo"] = "heimgewebe/heim-pc"
        with mock.patch.object(review, "review_receipt_errors", return_value=[]):
            self.assertTrue(
                self._receipt_errors(forged, receipts),
                "a mock from an unrelated gate test must not falsify the signed verifier",
            )

    def test_heim_pc_nix_review_seals_without_grabowski_test_tasks(self) -> None:
        self.repo = self.root / "heim-pc"
        self.repo.mkdir(mode=0o700)
        self.source_path = "flake.nix"
        self._git("init", "-q")
        self._git("config", "user.email", "review-test@example.invalid")
        self._git("config", "user.name", "Review Test")
        self._git("remote", "add", "origin", "git@github.com:heimgewebe/heim-pc.git")
        source = self.repo / self.source_path
        source.write_text(
            "{\n" + "".join(f"  # base nix policy line {n}\n" for n in range(1, 25))
            + "  outputs = { self }: {};\n}\n",
            encoding="utf-8",
        )
        self._git("add", self.source_path)
        self._git("commit", "-qm", "base")
        self.base = self._git("rev-parse", "HEAD").strip()
        source.write_text(
            "{\n" + "".join(f"  # reviewed nix authority line {n}\n" for n in range(1, 25))
            + "  outputs = { self }: {};\n}\n",
            encoding="utf-8",
        )
        self._git("add", self.source_path)
        self._git("commit", "-qm", "head")
        self.head = self._git("rev-parse", "HEAD").strip()
        # Grabowski shares one managed worktree root across repositories.
        shared = self.root / ".grabowski-worktrees"
        shared.mkdir()
        candidate = shared / "heim-pc-high-critical"
        self._git("worktree", "add", "--detach", str(candidate), self.head)
        self.repo = candidate

        plan = self._first_party_plan()
        self.assertEqual("heimgewebe/heim-pc", plan["binding"]["repo"])
        self.assertNotIn("tasks", plan)
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_wrong_remote_and_missing_axis_block_direct_audit(self) -> None:
        self._git(
            "remote", "set-url", "origin", "git@github.com:heimgewebe/heim-pc.git",
        )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "origin"):
            self._first_party_plan()
        self._git(
            "remote", "set-url", "origin", "git@github.com:heimgewebe/grabowski.git",
        )
        unmanaged = self.root / "unmanaged" / "grabowski"
        unmanaged.mkdir(parents=True)
        subprocess.run(
            ["git", "-C", str(unmanaged), "init", "-q"], check=True,
        )
        subprocess.run(
            ["git", "-C", str(unmanaged), "remote", "add", "origin",
             "git@github.com:heimgewebe/grabowski.git"], check=True,
        )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "managed checkout"):
            producer._managed_repository_identity(unmanaged)
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES[:-1], start=1):
            self._submit_axis(started, axis, number)
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "axis coverage"):
            self._seal_direct(plan)

    def test_github_pr_diff_identity_is_distinct_from_local_source_diff(self) -> None:
        # GitHub's canonical PR patch is not byte-identical to git --no-renames
        # for real PRs. The Gate binds it independently from the local diff.
        plan = self._first_party_plan()
        local_sha = hashlib.sha256(
            review._first_party_diff(self.repo, plan["binding"]),
        ).hexdigest()
        self.assertNotEqual("e" * 64, local_sha)
        plan["binding"]["diff_sha256"] = "e" * 64
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        audit, receipts = self._seal_direct(plan)
        self.assertEqual("e" * 64, audit["diff_sha256"])
        self.assertEqual([], self._receipt_errors(audit, receipts))

    def test_https_origin_is_admitted_as_the_same_github_repository(self) -> None:
        self._git("remote", "set-url", "origin",
                  "https://github.com/heimgewebe/grabowski.git")
        _worktree, slug = producer._managed_repository_identity(
            self.repo, expected_repo="heimgewebe/grabowski",
        )
        self.assertEqual("heimgewebe/grabowski", slug)

    def test_completed_review_remains_valid_after_session_write_deadline(self) -> None:
        # The deadline limits NEW source reads and report submissions. A fully
        # signed, revision-bound completed review is durable Captain evidence.
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number)
        after_deadline = self.now + review.FIRST_PARTY_SESSION_TTL_SECONDS + 1
        accepted = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False,
            now_unix=after_deadline,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(accepted))
        axis = review.REQUIRED_AXES[0]
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "expired"):
            self._read(
                started, axis, "diff", "", "head", 2, 2,
                now_unix=after_deadline,
            )

    def test_partial_canonical_diff_must_not_authorize_five_passes(self) -> None:
        plan, started = self._start()
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number, full_diff=False)
        # Each axis saw only the first diff line. The current producer must
        # not infer review of all changed paths from that single observed line.
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "canonical diff coverage incomplete",
        ):
            review.verified_first_party_semantic_review_passes(
                plan["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False, now_unix=self.now,
            )

    def test_large_delta_is_verified_from_multiple_bounded_chunks(self) -> None:
        # A real large PR must not be returned as a single truncation-prone
        # MCP response. Verify all Git diff lines across separate read receipts.
        bulk = self.repo / "src" / "bulk.txt"
        bulk.write_text(
            "".join(f"large delta line {line}: sourced review data\n" for line in range(1400)),
            encoding="utf-8",
        )
        self._git("add", "src/bulk.txt")
        self._git("commit", "-qm", "large delta")
        self.head = self._git("rev-parse", "HEAD").strip()
        plan, started = self._start()
        lines = review._first_party_diff(
            self.repo, plan["binding"],
        ).decode("utf-8").splitlines(keepends=True)
        self.assertGreater(len(lines), review.FIRST_PARTY_MAX_READ_LINES)
        axis = review.REQUIRED_AXES[0]
        first = self._read(
            started, axis, "diff", "", "head", 1,
            review.FIRST_PARTY_MAX_READ_LINES,
        )
        self.assertEqual(len(lines), first["diff_total_lines"])
        self.assertLessEqual(
            len(first["content"].encode("utf-8")), review.FIRST_PARTY_MAX_READ_BYTES,
        )
        for start in range(review.FIRST_PARTY_MAX_READ_LINES + 1, len(lines) + 1,
                           review.FIRST_PARTY_MAX_READ_LINES):
            self._read(
                started, axis, "diff", "", "head", start,
                min(start + review.FIRST_PARTY_MAX_READ_LINES - 1, len(lines)),
            )
        for number, each_axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, each_axis, number, full_diff=False)
        verified = review.verified_first_party_semantic_review_passes(
            plan["binding"], repository=self.repo, root=self.state,
            signers=self.signers, root_owned_signers=False, now_unix=self.now,
        )
        self.assertEqual(set(review.REQUIRED_AXES), set(verified))

    def test_authenticated_self_review_mcp_mutations_require_operator_gate(self) -> None:
        # Even an enrolled connector cannot persist a signed review while
        # the operator mutation blockade or audit-integrity gate is denying.
        import grabowski_mcp as mcp

        requests = [
            ("session_start", mcp.grabowski_self_review_session_start,
             ("pending-batch", "source inspection", "real review")),
            ("source_read", mcp.grabowski_self_review_source_read,
             ("session-id", "nonce", review.REQUIRED_AXES[0],
              "diff", "", "head", 1, 2, "read source", "real review")),
            ("axis_submit", mcp.grabowski_self_review_axis_submit,
             ("session-id", "nonce", {"axis": review.REQUIRED_AXES[0]},
              "submit verdict", "real review")),
        ]
        for name, endpoint, arguments in requests:
            with self.subTest(endpoint=name):
                with (
                    mock.patch.object(mcp, "_require_capability"),
                    mock.patch.object(
                        mcp, "_require_mutations_enabled",
                        side_effect=PermissionError("operator blockade active"),
                    ) as gate,
                    mock.patch.object(
                        mcp, "_authenticated_self_review_issuer",
                        side_effect=RuntimeError("reached authentication before mutation gate"),
                    ) as issuer,
                ):
                    with self.assertRaisesRegex(PermissionError, "operator blockade active"):
                        endpoint(*arguments)
                    gate.assert_called_once_with(
                        "file_write", path=str(review.FIRST_PARTY_REVIEW_ROOT),
                    )
                    issuer.assert_not_called()

    def test_secondary_enrolled_connector_cannot_issue_controller_reviews(self) -> None:
        # A valid transport identity for a different enrolled connector is
        # not the primary Grabowski controller's semantic review authority.
        evidence = {
            "state": "consumed", "single_use": True,
            "transport_mode": "signed-one-call-v1",
            "client_scope_kind": "connector_capability",
            "tool_name": review.FIRST_PARTY_TOOL_START,
            "client_scope_sha256": SCOPE_SHA256,
            "runtime_binding_sha256": RUNTIME_SHA256,
            "arguments_sha256": "a" * 64,
            "consumption_receipt_sha256": "b" * 64,
            "request_id": "c" * 32,
        }
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "controller issuer",
        ):
            review.authenticated_first_party_issuer(
                "unrelated-connector", evidence,
                expected_tool=review.FIRST_PARTY_TOOL_START,
            )

    def test_unsourced_report_and_spoofed_issuer_are_rejected(self) -> None:
        plan = self._plan()
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "issuer"):
            review.start_first_party_review_session(
                plan, {"connector_id": "arbitrary-cli"},
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        report = self._report(
            axis, 1, ["src/reviewed.py:L1-L8", "src/reviewed.py:L9-L16"],
        )
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": report,
            "reason": "Attempt an unsourced semantic submission.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "observed source"):
            review.submit_first_party_axis_review(
                started["review_session_id"], started["session_nonce"], report,
                self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )

    def test_duplicate_cross_session_and_revision_drift_are_rejected(self) -> None:
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        self._submit_axis(started, axis, 1)
        duplicate = self._report(
            axis, 99, ["src/reviewed.py:L1-L8", "src/reviewed.py:L9-L16"],
        )
        duplicate_arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "report": duplicate,
            "reason": "Attempt a duplicate semantic submission.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "duplicated"):
            review.submit_first_party_axis_review(
                started["review_session_id"], started["session_nonce"], duplicate,
                self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, duplicate_arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False, now_unix=self.now,
            )
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "session"):
            self._read(
                {**started, "session_nonce": "f" * 32},
                review.REQUIRED_AXES[1], "diff", "", "head", 1, 1,
            )
        self._git("commit", "--allow-empty", "-qm", "drift")
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "drift|head changed"):
            self._read(
                started, review.REQUIRED_AXES[1], "diff", "", "head", 1, 1,
            )

    def test_material_finding_blocks_complete_session(self) -> None:
        plan = self._first_party_plan()
        started = self._start_plan(plan)
        for number, axis in enumerate(review.REQUIRED_AXES, start=1):
            self._submit_axis(started, axis, number, reject=number == 1)
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "material finding unresolved",
        ):
            review.verified_first_party_semantic_review_passes(
                plan["binding"], repository=self.repo, root=self.state,
                signers=self.signers, root_owned_signers=False, now_unix=self.now,
            )
        with self.assertRaisesRegex(
            review.ReviewExecutionRejected, "material finding unresolved",
        ):
            self._seal_direct(plan)

    def test_expired_session_rejects_fresh_authenticated_read(self) -> None:
        _plan, started = self._start()
        axis = review.REQUIRED_AXES[0]
        arguments = {
            "review_session_id": started["review_session_id"],
            "session_nonce": started["session_nonce"], "axis": axis,
            "read_kind": "diff", "path": "", "revision": "head",
            "start_line": 1, "end_line": 1,
            "reason": "Attempt a source read after expiry.",
            "user_intent": "Verify the first-party review workflow.",
        }
        with self.assertRaisesRegex(review.ReviewExecutionRejected, "expired"):
            review.record_first_party_source_read(
                started["review_session_id"], started["session_nonce"], axis,
                "diff", "", "head", 1, 1,
                self._issuer(review.FIRST_PARTY_TOOL_READ, arguments),
                root=self.state, key=self.key, signers=self.signers,
                root_owned_signers=False,
                now_unix=self.now + review.FIRST_PARTY_SESSION_TTL_SECONDS + 1,
            )


if __name__ == "__main__":
    unittest.main()
