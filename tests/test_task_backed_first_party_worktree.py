"""Public task-backed sealing with real signed first-party worktree evidence.

Only the private storage roots and signer ownership policy are test-specific.
The five semantic axes use the authenticated session/read/submit fixture and
the real signature verifier. TaskDB, lifecycle and capture records represent
completed technical tasks; this does not launch systemd or a Nix sandbox.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import unittest
from unittest import mock

import test_self_review_first_party as semantic_fixture


review = semantic_fixture.review
producer = semantic_fixture.producer


class TaskBackedFirstPartyWorktreeTests(unittest.TestCase):
    def setUp(self) -> None:
        # Some unrelated harnesses leave a module-level PASS mock behind.
        # Load the source, including its public verifier, into this fixture's
        # own module so every negative case still verifies real signatures.
        spec = importlib.util.spec_from_file_location(
            "isolated_task_backed_first_party_verifier",
            Path(review.__file__).resolve(strict=True),
        )
        if spec is None or spec.loader is None:
            raise AssertionError("real task-backed source verifier could not be loaded")
        self.review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.review)
        self._patch(producer, "provenance", self.review)
        self._patch(semantic_fixture, "review", self.review)
        self.fixture = semantic_fixture.FirstPartySemanticReviewTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        fixture = self.fixture
        self.repos = fixture.root / "repos"
        self.repos.mkdir(mode=0o700)
        self.canonical = self.repos / "grabowski"
        fixture.repo.rename(self.canonical)
        fixture.repo = self.canonical
        self._patch(producer, "CANONICAL_REPO", self.canonical)
        self._patch(producer, "MANAGED_REPOS_ROOT", self.repos)
        self._patch(Path, "home", return_value=fixture.root)
        self.pool = self.repos / ".grabowski-worktrees"
        self.pool.mkdir(mode=0o700)
        self.worktree = self.pool / "task-backed-review"
        fixture._git("worktree", "add", "--detach", str(self.worktree), fixture.head)
        fixture._git("reset", "--hard", fixture.base)
        fixture.repo = self.worktree
        self.plan = fixture._plan()
        started = fixture._start_plan(self.plan)
        for number, axis in enumerate(self.review.REQUIRED_AXES, start=1):
            fixture._submit_axis(started, axis, number)

        self.outcomes = fixture.root / "task-outcomes"
        self.captures = fixture.root / "task-captures"
        self.receipts = fixture.root / "task-receipts"
        for directory in (self.outcomes, self.captures, self.receipts):
            directory.mkdir(mode=0o700)
        self.db = fixture.root / "task-backed.sqlite3"
        self.tasks = {
            axis: f"{number:024x}"
            for number, axis in enumerate(producer.METHODS, start=1)
        }
        self._write_task_evidence()
        for name, value in (
            ("SIGNING_KEY", fixture.key), ("SIGNERS", fixture.signers),
            ("RECEIPTS", self.receipts), ("TASK_DB", self.db),
            ("OUTCOMES", self.outcomes), ("CAPTURE_ROOT", self.captures),
        ):
            self._patch(producer, name, value)
        self._patch(self.review, "OUTCOME_ROOT", self.outcomes)

        # Production public entrypoints do not accept caller-selected roots.
        # Route their real validators to this fixture without changing any
        # repository argument, semantic result, source probe or signature.
        real_semantic = self.review.verified_first_party_semantic_review_passes
        real_verify = self.review._verify
        real_seal = producer._seal_review

        def isolated_semantic(*args, **kwargs):
            kwargs.update(
                root=fixture.state, signers=fixture.signers,
                root_owned_signers=False, now_unix=fixture.now,
            )
            return real_semantic(*args, **kwargs)

        def isolated_verify(*args, **kwargs):
            kwargs.update(
                outcomes=self.outcomes, capture_root=self.captures,
                first_party_root=fixture.state, root_owned_signers=False,
            )
            return real_verify(*args, **kwargs)

        def isolated_seal(*args, **kwargs):
            kwargs["root_owned_signers"] = False
            return real_seal(*args, **kwargs)

        self._patch(
            self.review, "verified_first_party_semantic_review_passes",
            side_effect=isolated_semantic,
        )
        self._patch(self.review, "_verify", side_effect=isolated_verify)
        self._patch(producer, "_seal_review", side_effect=isolated_seal)
        self._patch(
            self.review, "_verified_v2_semantic_review_passes",
            side_effect=AssertionError("signed first-party review must not fall back to V2"),
        )

    def _patch(self, target, name, *args, **kwargs):
        patcher = mock.patch.object(target, name, *args, **kwargs)
        patched = patcher.start()
        self.addCleanup(patcher.stop)
        return patched

    def _git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def _write_task_evidence(self) -> None:
        fixture = self.fixture
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, host TEXT, cwd TEXT, "
                "argv_json TEXT, argv_sha256 TEXT, unit TEXT, state TEXT, attempt INTEGER, "
                "lifecycle_receipt_sha256 TEXT, execution_backend TEXT, systemd_scope TEXT)"
            )
            for number, (axis, task_id) in enumerate(self.tasks.items(), start=1):
                argv_json = json.dumps(
                    self.plan["tasks"][axis], ensure_ascii=False, separators=(",", ":"),
                )
                argv_sha256 = hashlib.sha256(argv_json.encode()).hexdigest()
                unit = f"grabowski-task-{task_id}-a1.service"
                raw = self.plan["source_raw_diff_sha256"]
                report = {
                    "schema_version": 1,
                    "kind": "grabowski_trusted_source_inspection_v1",
                    "axis": axis,
                    "binding_sha256": self.review._digest(self.plan["binding"]),
                    "source_raw_diff_sha256": raw,
                    "method_kind": "deterministic-source-inspection-and-isolated-tests",
                    "summary": (
                        f"Technical fixture for {axis} records the inspected source "
                        "and method execution against the frozen linked worktree. "
                        "Its successful tests do not supply the signed semantic review."
                    ),
                    "evidence_refs": ["src/reviewed.py:L1-L2"],
                    "material_findings": 0,
                    "measurements": {
                        "changed_paths": 1, "inspected_paths": 1,
                        "python_statements": 30, "defined_symbols": 0,
                        "json_contracts": 0,
                    },
                }
                output = (
                    f"source_raw_diff_sha256:{raw}\nRan {number + 12} tests in 0.05s\n\nOK\n".encode()
                    + b"\n" + self.review.PHASE_OBSERVATION_PREFIX
                    + self.review._canonical(report) + b"\n"
                )
                observation = {
                    "state": "completed",
                    "properties": {"Result": "success", "ExecMainStatus": "0"},
                }
                outcome = {
                    "schema_version": 2, "kind": "grabowski_task_lifecycle_receipt",
                    "task_id": task_id, "unit": unit, "authoritative_unit": unit,
                    "execution_backend": "systemd-user", "systemd_scope": "user",
                    "attempt": 1, "state": "completed",
                    "argv_sha256": argv_sha256, "execution_envelope_sha256": None,
                    "resource_keys": [], "observed_at_unix": fixture.now,
                    "observation": observation,
                    "observation_sha256": self.review._digest(observation),
                    "terminalization": {},
                }
                outcome["receipt_sha256"] = self.review._digest(outcome)
                outcome_path = self.outcomes / (task_id + ".json")
                outcome_path.write_bytes(self.review._canonical(outcome))
                outcome_path.chmod(0o600)
                folder = self.captures / f".grabowski-task-output-{task_id}-a1"
                folder.mkdir(mode=0o700)
                for name, body in (("stdout.log", output), ("stderr.log", b"")):
                    stream = folder / name
                    stream.write_bytes(body)
                    stream.chmod(0o600)
                connection.execute(
                    "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        task_id, "heim-pc", str(self.worktree), argv_json,
                        argv_sha256, unit, "completed", 1, outcome["receipt_sha256"],
                        "systemd-user", "user",
                    ),
                )
        self.db.chmod(0o600)

    def _seal(self) -> dict:
        result = producer.seal_review(self.plan, self.tasks)
        self.assertEqual("sealed_and_verified", result["status"])
        self.assertEqual(5, result["review_pass_count"])
        return json.loads(Path(result["audit_path"]).read_bytes())

    def _errors(self, audit: dict) -> list[str]:
        # Deliberately omit _repository: test the production default resolver.
        return self.review.review_receipt_errors(
            audit, _receipts=self.receipts, _signers=self.fixture.signers,
            _first_party_root=self.fixture.state, _root_owned_signers=False,
            _now_unix=self.fixture.now,
        )

    def _assert_rejected(self, audit: dict, message: str) -> None:
        self.assertEqual(
            ["high_critical_server_review_provenance_invalid:ReviewExecutionRejected"],
            self._errors(audit),
        )
        # The public error intentionally redacts details. Independently check
        # the underlying rejection so an unrelated fixture failure cannot pass.
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, message):
            self.review._verify(
                audit, receipts=self.receipts, outcomes=self.outcomes,
                signers=self.fixture.signers, repository=None,
                now_unix=self.fixture.now, root_owned_signers=False,
            )

    def _other_worktree(self) -> Path:
        other = self.pool / "other-review"
        self._git(self.canonical, "worktree", "add", "--detach", str(other), self.fixture.head)
        return other

    def _rewrite_receipt_worktree(
        self, audit: dict, number: int, worktree: Path, *, resign: bool,
    ) -> None:
        reference = audit["review_pass_receipts"][number]
        material_path = self.receipts / (reference["id"] + ".json")
        record = json.loads(material_path.read_bytes())
        record["worktree_path"] = str(worktree)
        material = self.review._canonical(record)
        material_path.write_bytes(material)
        reference["receipt_sha256"] = hashlib.sha256(material).hexdigest()
        if resign:
            signature = producer._sign(
                material, key=self.fixture.key, signers=self.fixture.signers,
            )
            (self.receipts / (reference["id"] + ".sig")).write_bytes(signature)
            reference["signature_sha256"] = hashlib.sha256(signature).hexdigest()

    def test_public_seal_and_default_verifier_use_signed_linked_worktree(self) -> None:
        self.assertEqual(self.fixture.base, self._git(self.canonical, "rev-parse", "HEAD"))
        self.assertEqual(self.fixture.head, self._git(self.worktree, "rev-parse", "HEAD"))
        self.assertNotEqual(self.fixture.base, self.fixture.head)
        audit = self._seal()
        self.assertNotIn("review_origin", audit)
        self.assertEqual(5, len(audit["review_pass_receipts"]))
        for axis, reference in zip(producer.METHODS, audit["review_pass_receipts"], strict=True):
            record = json.loads((self.receipts / (reference["id"] + ".json")).read_bytes())
            self.assertEqual(axis, record["axis"])
            self.assertEqual(str(self.worktree), record["worktree_path"])
            self.assertIn("semantic_first_party", record)
            self.assertNotIn("semantic_v2", record)
        self.assertEqual([], self._errors(audit))
        audit["worktree_path"] = str(self.canonical)
        self.assertEqual([], self._errors(audit), "unsigned audit paths must not select the checkout")

    def test_public_seal_and_default_verifier_reject_another_repository(self) -> None:
        other = self.repos / "heim-pc"
        other.mkdir(mode=0o700)
        self._git(other, "init", "-q")
        self._git(other, "remote", "add", "origin", "git@github.com:heimgewebe/heim-pc.git")
        plan = copy.deepcopy(self.plan)
        plan["worktree"] = str(other)
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "repository origin invalid"):
            producer.seal_review(plan, self.tasks)
        audit = self._seal()
        self._rewrite_receipt_worktree(audit, 0, other, resign=True)
        self._assert_rejected(audit, "repository origin invalid")

    def test_public_seal_rejects_another_worktree_of_the_same_revision(self) -> None:
        plan = copy.deepcopy(self.plan)
        plan["worktree"] = str(self._other_worktree())
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "repository crossed review session"):
            producer.seal_review(plan, self.tasks)

    def test_unsigned_receipt_path_edit_cannot_redirect_default_verifier(self) -> None:
        audit = self._seal()
        self._rewrite_receipt_worktree(audit, 0, self._other_worktree(), resign=False)
        self._assert_rejected(audit, "signature")

    def test_public_verifier_isolated_from_shared_module_pass_mock(self) -> None:
        with mock.patch.object(review, "review_receipt_errors", return_value=[]) as leaked:
            self.assertIsNot(review, self.review)
            audit = self._seal()
            self.assertEqual([], self._errors(audit))
            self._rewrite_receipt_worktree(audit, 0, self._other_worktree(), resign=False)
            self._assert_rejected(audit, "signature")
            leaked.assert_not_called()

    def test_signed_first_receipt_cannot_cross_the_authenticated_session_worktree(self) -> None:
        audit = self._seal()
        self._rewrite_receipt_worktree(audit, 0, self._other_worktree(), resign=True)
        self._assert_rejected(audit, "repository crossed review session")

    def test_signed_fifth_receipt_must_match_the_selected_semantic_worktree(self) -> None:
        audit = self._seal()
        self._rewrite_receipt_worktree(audit, 4, self._other_worktree(), resign=True)
        self._assert_rejected(audit, "task crossed semantic worktree")

    def test_all_five_technical_captures_and_outcomes_are_still_verified(self) -> None:
        audit = self._seal()
        self.assertEqual([], self._errors(audit))
        for axis, task_id in self.tasks.items():
            capture = self.captures / f".grabowski-task-output-{task_id}-a1" / "stdout.log"
            original_capture = capture.read_bytes()
            with self.subTest(axis=axis, evidence="capture"):
                try:
                    capture.write_bytes(original_capture + b"tampered\n")
                    self._assert_rejected(audit, "differs from server task capture")
                finally:
                    capture.write_bytes(original_capture)
            outcome_path = self.outcomes / (task_id + ".json")
            original_outcome = outcome_path.read_bytes()
            outcome = json.loads(original_outcome)
            outcome["state"] = "failed"
            outcome["receipt_sha256"] = self.review._digest({
                key: value for key, value in outcome.items() if key != "receipt_sha256"
            })
            with self.subTest(axis=axis, evidence="lifecycle"):
                try:
                    outcome_path.write_bytes(self.review._canonical(outcome))
                    self._assert_rejected(audit, "lifecycle receipt digest not authentic")
                finally:
                    outcome_path.write_bytes(original_outcome)
        self.assertEqual([], self._errors(audit))

    def test_five_signed_axes_do_not_replace_the_fifth_completed_task(self) -> None:
        final_task = self.tasks[list(producer.METHODS)[-1]]
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE tasks SET state='failed' WHERE task_id=?", (final_task,))
        with self.assertRaisesRegex(self.review.ReviewExecutionRejected, "server task origin"):
            producer.seal_review(self.plan, self.tasks)
        self.assertFalse((self.receipts / "batches").exists())


if __name__ == "__main__":
    unittest.main()
