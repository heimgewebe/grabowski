"""End-to-end contract for genuine server task-bound self-review signing."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as execute
import grabowski_self_review_producer as producer


class ServerReviewProducerTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("ssh-keygen") is None or shutil.which("git") is None:
            self.skipTest("OpenSSH and Git required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        def git(*args):
            p = subprocess.run(["git", "-C", str(self.repo), *args],
                               capture_output=True, text=True, check=True)
            return p.stdout.strip()
        git("init", "-q")
        p = self.repo / "src" / "example.py"
        p.parent.mkdir()
        p.write_text("alpha = 1\nbeta = 2\n", encoding="utf-8")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "base")
        self.base = git("rev-parse", "HEAD")
        p.write_text("alpha = 1\nbeta = 3\n", encoding="utf-8")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "head")
        self.head = git("rev-parse", "HEAD")
        self.raw = hashlib.sha256(b"raw-fixture").hexdigest()
        self.binding = {
            "repo": "heimgewebe/grabowski", "pr": 1649,
            "base_sha": self.base, "head_sha": self.head,
            "diff_sha256": "a" * 64,
            "review_batch_id": "b" * 32,
            "review_purpose": "pull_request",
        }
        self.bwrap = "/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap"
        self.python = "/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3"
        self.plan = {
            "schema_version": 1, "kind": "grabowski_self_review_execution_plan",
            "binding": self.binding, "worktree": str(self.repo),
            "source_raw_diff_sha256": self.raw,
            "tasks": {
                axis: producer._task_command(
                    self.binding, axis, self.repo, bwrap=self.bwrap, python=self.python
                )
                for axis in producer.METHODS
            },
        }
        self.reports = {
            axis: {
                "summary": (
                    f"Method {axis} included an actual distinct review of the "
                    "changed target revision and method-specific negative cases. "
                    "No material findings remain after direct source inspection."
                ),
                "evidence_refs": ["src/example.py:L1-L2"],
                "material_findings": 0,
            }
            for axis in producer.METHODS
        }
        self.tasks = {
            axis: f"{i:024x}" for i, axis in enumerate(producer.METHODS, start=1)
        }
        self.outcomes = self.root / "outcomes"
        self.captures = self.root / "task-output"
        self.receipts = self.root / "receipts"
        for directory in (self.outcomes, self.captures, self.receipts):
            directory.mkdir(mode=0o700)
        self.key = self.root / "key"
        command = ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)]
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode:
            self.skipTest("Cannot generate isolated test signing key")
        self.signers = self.root / "signers"
        key_data = (self.root / "key.pub").read_text().strip()
        self.signers.write_text(
            execute.PRINCIPAL + ' namespaces="' + execute.NAMESPACE + '" ' + key_data + "\n"
        )
        self.signers.chmod(0o600)
        self.db = self.root / "tasks.sqlite3"
        self.connection = sqlite3.connect(self.db)
        self.connection.execute(
            "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, host TEXT, cwd TEXT, "
            "argv_json TEXT, argv_sha256 TEXT, unit TEXT, state TEXT, attempt INTEGER, "
            "lifecycle_receipt_sha256 TEXT, execution_backend TEXT, systemd_scope TEXT)"
        )
        self.now = int(time.time())
        for i, axis in enumerate(producer.METHODS, start=1):
            task_id = self.tasks[axis]
            argv = self.plan["tasks"][axis]
            digest = hashlib.sha256(
                json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode()
            ).hexdigest()
            unit = f"grabowski-task-{task_id}-a1.service"
            observation_report = {
                "schema_version": 1,
                "kind": "grabowski_trusted_source_inspection_v1",
                "axis": axis,
                "binding_sha256": execute._digest(self.binding),
                "source_raw_diff_sha256": self.raw,
                "method_kind": "deterministic-source-inspection-and-isolated-tests",
                "summary": self.reports[axis]["summary"],
                "evidence_refs": self.reports[axis]["evidence_refs"],
                "material_findings": 0,
                "measurements": {
                    "changed_paths": 1, "inspected_paths": 1,
                    "python_statements": 2, "defined_symbols": 0,
                    "json_contracts": 0,
                },
            }
            output = (
                f"source_raw_diff_sha256:{self.raw}\nRan {i+12} tests in 0.05s\n\nOK\n".encode()
                + b"\n" + execute.PHASE_OBSERVATION_PREFIX
                + execute._canonical(observation_report) + b"\n"
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
                "argv_sha256": digest, "execution_envelope_sha256": None,
                "resource_keys": [], "observed_at_unix": self.now,
                "observation": observation,
                "observation_sha256": execute._digest(observation),
                "terminalization": {},
            }
            outcome["receipt_sha256"] = execute._digest(outcome)
            path = self.outcomes / (task_id + ".json")
            path.write_text(json.dumps(outcome, sort_keys=True, indent=2) + "\n")
            path.chmod(0o600)
            folder = self.captures / f".grabowski-task-output-{task_id}-a1"
            folder.mkdir(mode=0o700)
            for name, body in (("stdout.log", output), ("stderr.log", b"")):
                stream = folder / name
                stream.write_bytes(body)
                stream.chmod(0o600)
            self.connection.execute(
                "INSERT INTO tasks VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    task_id, "heim-pc", str(self.repo),
                    json.dumps(argv, ensure_ascii=False, separators=(",", ":")),
                    digest, unit, "completed", 1, outcome["receipt_sha256"],
                    "systemd-user", "user",
                ),
            )
        self.connection.commit()
        self.connection.close()
        self.db.chmod(0o600)

    def seal(self):
        return producer._seal_review(
            self.plan, self.tasks, self.reports,
            key=self.key, signers=self.signers, receipts=self.receipts,
            task_db=self.db, outcomes=self.outcomes,
            capture_root=self.captures, repository=self.repo,
            root_owned_signers=False,
            source_observer=lambda repo, binding: self.raw,
        )

    def test_plan_cli_does_not_log_private_task_arguments(self):
        marker = "SYNTHETIC_SECRET_CANARY_NEVER_LOG"
        self.plan["tasks"]["contracts_correctness"].append(marker)
        stdout = io.StringIO()
        arguments = [
            "plan", "--repo", str(self.repo), "--base", self.base,
            "--head", self.head, "--diff", "a" * 64,
            "--bwrap", self.bwrap, "--python", self.python, "--pr", "1649",
        ]
        with (
            mock.patch.object(producer, "_require_installed_runtime"),
            mock.patch.object(producer, "plan_review", return_value=self.plan),
            mock.patch.object(producer, "_require_live_pr"),
            mock.patch.object(producer, "_store_plan", return_value=self.root / "private-plan.json"),
            redirect_stdout(stdout),
        ):
            self.assertEqual(0, producer.main(arguments))
        output = json.loads(stdout.getvalue())
        self.assertEqual("planned_not_executed", output["status"])
        self.assertNotIn(marker, stdout.getvalue())
        self.assertNotIn("tasks", output)
        self.assertNotIn("plan_path", output)
        self.assertEqual(5, output["task_count"])

    def test_seal_cli_does_not_log_private_reports_or_receipt_paths(self):
        marker = "SYNTHETIC_SECRET_REPORT_CANARY_NEVER_LOG"
        stdout = io.StringIO()
        sealed = {
            "status": "sealed_and_verified",
            "review_batch_id": self.binding["review_batch_id"],
            "review_pass_count": 5, "review_audit_sha256": "f" * 64,
            "source_head": self.head, "audit_path": "/private/" + marker,
            "arbitrary_future_field": marker,
        }
        with (
            mock.patch.object(producer, "_load_plan", return_value=self.plan),
            mock.patch.object(producer, "_require_live_pr"),
            mock.patch.object(producer, "seal_review", return_value=sealed),
            redirect_stdout(stdout),
        ):
            self.assertEqual(
                0,
                producer.main([
                    "seal", "--batch-id", self.binding["review_batch_id"],
                    "--task-ids-json", json.dumps(self.tasks),
                    "--phase-reports-json", json.dumps(self.reports),
                ]),
            )
        output = json.loads(stdout.getvalue())
        self.assertEqual("sealed_and_verified", output["status"])
        self.assertEqual(self.head, output["source_head"])
        self.assertNotIn(marker, stdout.getvalue())
        self.assertNotIn("audit_path", output)
        self.assertNotIn("arbitrary_future_field", output)

    def test_every_trusted_outer_worker_uses_isolated_python_imports(self):
        for axis, argv in self.plan["tasks"].items():
            with self.subTest(axis=axis):
                self.assertEqual(
                    [self.python, "-I", "-B", "-c"], argv[-5:-1],
                )
                self.assertIn("grabowski-phase-source-inspection-v1", argv[-1])

    def test_review_suite_allowlist_is_readonly_compatible_and_distinct(self):
        self.assertEqual(
            [
                "test_review_evidence_schemas.py",
                "test_pr_review_gate_external.py",
                "test_self_review_execution.py",
                "test_self_review_producer.py",
                "test_pr_review_gate_recovery_risk_paths.py",
            ],
            [execute.METHOD_TEST_SUITE[axis] for axis in producer.METHODS],
        )

    def test_five_genuine_origin_bound_tasks_seal_and_verify(self):
        result = self.seal()
        self.assertEqual("sealed_and_verified", result["status"])
        self.assertEqual(5, result["review_pass_count"])
        audit = json.loads(Path(result["audit_path"]).read_text())
        self.assertEqual([x["axis"] for x in audit["review_iterations"]],
                         list(producer.METHODS))
        execute._verify(
            audit, receipts=self.receipts, outcomes=self.outcomes,
            signers=self.signers, repository=self.repo, now_unix=self.now,
            root_owned_signers=False, capture_root=self.captures,
        )

    def test_same_batch_cannot_be_sealed_twice(self):
        self.seal()
        with self.assertRaises(FileExistsError):
            self.seal()

    def test_wrong_method_argv_cannot_get_signed(self):
        self.plan["tasks"]["contracts_correctness"][-1] = "invented PASS"
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "plan task command altered"):
            self.seal()

    def test_changed_server_task_argv_fails(self):
        conn = sqlite3.connect(self.db)
        conn.execute(
            "UPDATE tasks SET argv_sha256=? WHERE task_id=?",
            ("0"*64, self.tasks["contracts_correctness"]),
        )
        conn.commit(); conn.close()
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "origin"):
            self.seal()

    def test_failed_registered_task_cannot_get_signed(self):
        conn = sqlite3.connect(self.db)
        conn.execute(
            "UPDATE tasks SET state=? WHERE task_id=?",
            ("failed", self.tasks["contracts_correctness"]),
        )
        conn.commit(); conn.close()
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "origin"):
            self.seal()

    def test_signed_marker_cannot_replace_real_output(self):
        path = self.captures / f".grabowski-task-output-{1:024x}-a1" / "stdout.log"
        path.write_bytes(b"PASS")
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "output did not pass"):
            self.seal()

    def test_wrong_source_head_changes_signed_plan(self):
        self.plan["binding"]["head_sha"] = "f" * 40
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "plan task command altered"):
            self.seal()

    def test_duplicate_task_id_cannot_reuse_execution(self):
        self.tasks["adversarial_countercheck"] = self.tasks["contracts_correctness"]
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "five tasks incomplete"):
            self.seal()

    def test_genuine_five_green_test_tasks_with_invented_reports_cannot_be_signed(self):
        # Real (fixture-verified) task identities, lifecycle receipts, captures
        # and test PASS must NOT turn caller-invented semantic prose into PASS.
        self.reports["security_authority_concurrency"]["summary"] = (
            "Invented green security review: all risks were inspected deeply "
            "and every concurrent authority race was ruled out by my personal "
            "assurance, despite there being no task-observed report of that work."
        )
        with self.assertRaisesRegex(
            execute.ReviewExecutionRejected, "differs from server task observation",
        ):
            self.seal()

    def test_untriaged_findings_block_producer(self):
        self.reports["security_authority_concurrency"]["material_findings"] = 1
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "not fully triaged"):
            self.seal()

    def test_fabricated_evidence_refs_block(self):
        self.reports["tests_negative_cases"]["evidence_refs"] = ["nonexistent"]
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "unresolvable"):
            self.seal()

    def test_invalid_signing_key_permissions_block(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "signing key unsafe"):
            self.seal()

    def test_wrong_signer_namespace_blocks(self):
        raw = self.signers.read_text()
        self.signers.write_text(raw.replace(execute.NAMESPACE, "different-namespace"))
        self.signers.chmod(0o600)
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "signature not authentic"):
            self.seal()

    def test_mutated_private_capture_fails_even_if_task_was_successful(self):
        path = self.captures / f".grabowski-task-output-{1:024x}-a1" / "stderr.log"
        path.write_bytes(b"unrecorded error")
        with self.assertRaisesRegex(execute.ReviewExecutionRejected, "output did not pass"):
            self.seal()


if __name__ == "__main__":
    unittest.main()