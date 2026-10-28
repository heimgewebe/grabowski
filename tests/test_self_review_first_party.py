"""Real signed-ingress and Git-read coverage for first-party semantic review."""
from __future__ import annotations

import hashlib
import importlib.util
import secrets
import json
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

    def _candidate_plan(self, *, dirty: bool = True, retried_tests: bool = False) -> dict:
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
        writer["receipt_sha256"] = workspace._sha256_json({k: v for k, v in writer.items() if k != "receipt_sha256"})
        workspace._atomic_json(workspace._role_receipt_path(manifest, "writer"), writer)
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        if dirty:
            patch = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        else:
            # A clean frozen patch already has immutable committed source.
            # Keep the existing dirty-workspace freezer's contract unchanged.
            payload = review._first_party_diff(candidate, {"base_sha": self.base, "head_sha": self.head})
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
        workspace._atomic_json(tests_output, signed_role_receipt(
            "tests", manifest, snapshot, argv_sha256=workspace._sha256_json(selected_tests),
        ))
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

    def _finalize_candidate(self, plan: dict, started: dict) -> dict:
        return review.finalize_first_party_candidate(
            started["review_session_id"], started["session_nonce"],
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {
                "review_session_id": started["review_session_id"], "session_nonce": started["session_nonce"],
                "report": {"finalize": True},
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

    def _submit(self, started: dict, report: dict) -> dict:
        return review.submit_first_party_axis_review(
            started["review_session_id"], started["session_nonce"], report,
            self._issuer(review.FIRST_PARTY_TOOL_SUBMIT, {
                "review_session_id": started["review_session_id"], "session_nonce": started["session_nonce"],
                "report": report,
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

    def test_clean_frozen_candidate_signed_five_axis_handoff(self) -> None:
        plan = self._candidate_plan(dirty=False)
        self.assertFalse(plan["binding"]["candidate_binding"]["dirty"])
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        self.assertEqual("PASS", self._verify_candidate(plan)["verdict"])

    def test_candidate_handoff_accepts_bound_completed_retried_tests(self) -> None:
        plan = self._candidate_plan(retried_tests=True)
        started = self._start_plan(plan)
        self._complete_candidate(plan, started)
        self._finalize_candidate(plan, started)
        self.assertEqual("PASS", self._verify_candidate(plan)["verdict"])

    def test_candidate_handoff_runs_role_capture_collect_and_close(self) -> None:
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
                                  "state": "completed", "terminal": True})
            return {"task": public_review}

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
        next(axes.glob("*.sig")).unlink()
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

        plan_b = self._first_party_plan()
        started_b = self._start_plan(plan_b)
        for number, axis in enumerate(review.REQUIRED_AXES, 1):
            self._submit_axis(
                started_b, axis, number,
                resolve_ids=("material-1",) if number == 1 else (),
            )
        audit_b, receipts_b = self._seal_direct(plan_b)
        self.assertEqual([], self._receipt_errors(audit_b, receipts_b))

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
