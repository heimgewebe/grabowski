"""Security regression tests for server-origin self-review phase receipts."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import grabowski_self_review_execution as execution  # noqa: E402
import grabowski_decision_reviews as decisions  # noqa: E402


class ReviewExecutionProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("ssh-keygen") is None:
            self.skipTest("OpenSSH is required for receipt-origin tests")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.receipts = root / "receipts"
        self.outcomes = root / "outcomes"
        self.capture_root = root / "task-output"
        self.receipts.mkdir(mode=0o700)
        self.outcomes.mkdir(mode=0o700)
        self.capture_root.mkdir(mode=0o700)
        self.key = root / "issuer"
        keygen = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            capture_output=True, check=False,
        )
        if keygen.returncode != 0:
            self.skipTest("OpenSSH Ed25519 keygen unavailable")
        self.signers = root / "allowed_signers"
        public = (root / "issuer.pub").read_text(encoding="utf-8").strip()
        self.signers.write_text(execution.PRINCIPAL + " " + public + "\n", encoding="utf-8")
        self.signers.chmod(0o600)
        self.now = int(time.time())
        self.head = "a" * 40
        self.audit = {
            "repo": "heimgewebe/grabowski",
            "pr": 1649,
            "base_sha": "b" * 40,
            "head_sha": self.head,
            "diff_sha256": "c" * 64,
            "review_batch_id": "d" * 32,
            "review_iterations": [],
            "review_pass_receipts": [],
        }
        self.semantic_patch = mock.patch.object(
            execution, "verified_semantic_review_passes",
            side_effect=self._fixture_roles,
        )
        self.semantic_patch.start()
        self.addCleanup(self.semantic_patch.stop)

    def _fixture_roles(self, binding, *, repository, axes_to_review=execution.REQUIRED_AXES):
        # Explicit unit-test fixture, never an authentic V2 role receipt.
        return {
            phase["axis"]: {
                "phase": phase,
                "provenance": {
                    "fixture_v2_role_unit": f"grabowski-job-{phase['n']:012x}",
                },
            }
            for phase in self.audit["review_iterations"]
        }

    def test_isolated_phase_mounts_exclude_host_root_home_and_runtime_secrets(self) -> None:
        worktree = "/home/alex/repos/.grabowski-worktrees/receipt-sandbox-test"
        args = execution._sandbox_bwrap_flags(worktree)
        sources = [args[i + 1] for i, item in enumerate(args[:-2]) if item == "--ro-bind"]
        self.assertNotIn("/", sources)
        self.assertNotIn("/home", sources)
        self.assertNotIn("/run", sources)
        self.assertNotIn("/home/alex", sources)
        self.assertIn("/nix/store", sources)
        self.assertIn(worktree, sources)
        self.assertEqual(args.count("--clearenv"), 1)
        self.assertIn(["--setenv", "HOME", "/tmp"], [args[i:i+3] for i in range(len(args)-2)])
        self.assertIn(
            ["--setenv", "PATH", "/run/current-system/sw/bin"],
            [args[i:i+3] for i in range(len(args)-2)],
        )
        self.assertNotIn(".config", " ".join(sources))
        self.assertNotIn(".local/state", " ".join(sources))

    def test_trusted_review_worker_ignores_pr_checkout_module_shadows(self) -> None:
        # A PR may add json.py/ast.py/subprocess.py at repository root.
        # Without Python -I the outer trusted review method could import it.
        candidate = Path(self.temp.name) / "malicious-checkout"
        candidate.mkdir(mode=0o700)
        for name in ("json.py", "ast.py", "subprocess.py", "hashlib.py"):
            (candidate / name).write_text(
                "raise RuntimeError('SYNTHETIC_IMPORT_HIJACK_CANARY')\n",
                encoding="utf-8",
            )
        protected = subprocess.run(
            [
                sys.executable, "-I", "-B", "-c",
                "import json,ast,subprocess,hashlib;print('stdlib-verified')",
            ],
            cwd=candidate, capture_output=True, text=True,
            check=False, timeout=10,
        )
        self.assertEqual(0, protected.returncode, protected.stderr)
        self.assertEqual("stdlib-verified", protected.stdout.strip())
        self.assertNotIn("SYNTHETIC_IMPORT_HIJACK_CANARY", protected.stderr)

    def _write(self, path: Path, data: bytes) -> None:
        path.write_bytes(data)
        path.chmod(0o600)

    def _sign(self, raw: bytes) -> bytes:
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", execution.NAMESPACE],
            input=raw, capture_output=True, check=False, timeout=10,
        )
        if proc.returncode != 0:
            raise AssertionError("Cannot sign test receipt: " + proc.stderr.decode()[:300])
        return proc.stdout

    def _phase(
        self,
        n: int,
        *,
        producer: str = execution.PRODUCER,
        evidence_ref: str = "src/example.py:L1-L2",
        axis: str | None = None,
        isolation: bool = True,
    ) -> None:
        axis = axis or (
            execution.REQUIRED_AXES[n - 1]
            if n <= len(execution.REQUIRED_AXES)
            else "additional_adversarial_probe"
        )
        phase = {
            "n": n, "axis": axis,
            "summary": (
                "Phase was actually executed against the frozen diff with a "
                "method-specific inspection and deterministic evidence readback "
                f"number {n}; any material findings were triaged explicitly."
            ),
            "evidence_refs": [evidence_ref], "material_findings": 0,
        }
        receipt_id = f"{n:032x}"
        task_id = f"{n:024x}"
        unit = f"grabowski-task-{task_id}-a1.service"
        bwrap = "/nix/store/" + "a" * 32 + "-bubblewrap-0.12.0/bin/bwrap"
        python = "/nix/store/" + "b" * 32 + "-grabowski-operator-test/bin/python3"
        worktree = str(Path(self.temp.name))
        binding = {
            "repo": self.audit["repo"], "pr": self.audit["pr"],
            "base_sha": self.audit["base_sha"], "head_sha": self.head,
            "diff_sha256": self.audit["diff_sha256"],
            "review_batch_id": self.audit["review_batch_id"],
            "review_purpose": self.audit.get("review_purpose", "pull_request"),
            **(
                {"release_binding": self.audit["release_binding"]}
                if self.audit.get("review_purpose") == "post_merge_release"
                else {}
            ),
        }
        sandbox_argv = [
            bwrap, *execution._sandbox_bwrap_flags(worktree), "--",
            python, "-I", "-B", "-c",
            execution.trusted_phase_source(binding, axis, worktree),
        ]
        argv = hashlib.sha256(json.dumps(
            sandbox_argv, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        report_observation = {
            "schema_version": 1,
            "kind": "grabowski_trusted_source_inspection_v1",
            "axis": axis,
            "binding_sha256": execution._digest(binding),
            "source_raw_diff_sha256": "f" * 64,
            "method_kind": "deterministic-source-inspection-and-isolated-tests",
            "summary": phase["summary"],
            "evidence_refs": phase["evidence_refs"],
            "material_findings": 0,
            "measurements": {
                "changed_paths": 1, "inspected_paths": 1,
                "python_statements": 1, "defined_symbols": 0,
                "json_contracts": 0,
            },
        }
        output = (
            ("source_raw_diff_sha256:" + "f" * 64 + f"\nRan {n+9} tests in 0.10s\n\nOK\n").encode()
            + b"\n" + execution.PHASE_OBSERVATION_PREFIX
            + execution._canonical(report_observation) + b"\n"
        )
        output_sha = hashlib.sha256(output).hexdigest()
        isolation_sha = execution._digest({
            "argv_sha256": argv,
            "isolation_policy": "bwrap-readonly-no-net-v1",
            "axis": axis,
        })
        observation = {
            "state": "completed",
            "properties": {"Result": "success", "ExecMainStatus": "0"},
        }
        task_material = {
            "schema_version": 2, "kind": "grabowski_task_lifecycle_receipt",
            "task_id": task_id, "unit": unit, "authoritative_unit": unit,
            "execution_backend": "systemd-user", "systemd_scope": "user",
            "attempt": 1, "state": "completed", "argv_sha256": argv,
            "execution_envelope_sha256": "e" * 64,
            "resource_keys": [], "observed_at_unix": self.now,
            "observation": observation,
            "observation_sha256": execution._digest(observation),
            "terminalization": {},
        }
        outcome = {
            **task_material,
            "receipt_sha256": execution._digest(task_material),
        }
        self._write(
            self.outcomes / f"{task_id}.json",
            (json.dumps(outcome, sort_keys=True, indent=2) + "\n").encode(),
        )
        record = {
            "schema_version": 1, "kind": execution.KIND,
            "producer": producer,
            "binding": binding,
            "n": n, "axis": axis,
            "review_pass_sha256": execution._digest(phase),
            "evidence_refs_sha256": execution._digest(phase["evidence_refs"]),
            "stdout_sha256": output_sha, "source_raw_diff_sha256": "f" * 64,
            "source_inspection_report_sha256": execution._digest({
                "summary": phase["summary"], "evidence_refs": phase["evidence_refs"],
                "material_findings": phase["material_findings"],
            }),
            "semantic_v2": {
                "fixture_v2_role_unit": f"grabowski-job-{n:012x}",
            },
            "sandbox": "isolated-read-only",
            "sandbox_argv": sandbox_argv, "worktree_path": worktree,
            "isolation_sha256": isolation_sha if isolation else "f" * 64,
            "exit_code": 0, "execution_nonce": f"{n+100:032x}",
            "observed_at_unix": self.now,
            "task": {
                "id": task_id, "unit": unit, "argv_sha256": argv,
                "lifecycle_receipt_sha256": outcome["receipt_sha256"],
            },
        }
        material = execution._canonical(record)
        signature = self._sign(material)
        self._write(self.receipts / (receipt_id + ".json"), material)
        self._write(self.receipts / (receipt_id + ".sig"), signature)
        self._write(self.receipts / (receipt_id + ".out"), output)
        output_dir = self.capture_root / f".grabowski-task-output-{task_id}-a1"
        output_dir.mkdir(mode=0o700)
        self._write(output_dir / "stdout.log", output)
        self._write(output_dir / "stderr.log", b"")
        self.audit["review_iterations"].append(phase)
        self.audit["review_pass_receipts"].append({
            "id": receipt_id,
            "receipt_sha256": hashlib.sha256(material).hexdigest(),
            "signature_sha256": hashlib.sha256(signature).hexdigest(),
            "output_sha256": output_sha,
        })

    def _five(self, **options) -> None:
        for n in range(1, 6):
            self._phase(n, **(options if n == 5 else {}))

    def _validate(self, audit: dict | None = None, **options) -> None:
        execution._verify(
            audit or self.audit, receipts=self.receipts, outcomes=self.outcomes,
            signers=self.signers, repository=Path(self.temp.name),
            now_unix=self.now, root_owned_signers=False,
            read_source=lambda _head, _path: b"alpha\nbeta\ngamma\n",
            capture_root=self.capture_root,
            **options,
        )

    def test_unit_fixture_five_source_tasks_and_v2_receipts_pass(self) -> None:
        self._five()
        self._validate()

    def test_five_green_tasks_without_genuine_v2_roles_block(self):
        self._five()
        with mock.patch.object(
            execution, "verified_semantic_review_passes",
            side_effect=execution.ReviewExecutionRejected("missing genuine V2 semantic roles"),
        ):
            with self.assertRaisesRegex(
                execution.ReviewExecutionRejected, "missing genuine V2 semantic roles",
            ):
                self._validate()

    def test_sixth_genuine_distinct_phase_allowed(self) -> None:
        self._five()
        self._phase(6)
        self._validate()

    def test_fabricated_five_phase_audit_without_server_receipts_blocks(self) -> None:
        self.audit["review_iterations"] = [
            {"n": i, "axis": axis, "summary": "x" * 50,
             "evidence_refs": ["nonexistent"], "material_findings": 0}
            for i, axis in enumerate(execution.REQUIRED_AXES, start=1)
        ]
        with self.assertRaises(execution.ReviewExecutionRejected):
            self._validate()

    def test_task_without_actual_source_inspection_marker_blocks_even_with_green_tests(self):
        binding = {
            "repo": self.audit["repo"], "pr": self.audit["pr"],
            "base_sha": self.audit["base_sha"],
            "head_sha": self.audit["head_sha"],
            "diff_sha256": self.audit["diff_sha256"],
            "review_batch_id": self.audit["review_batch_id"],
            "review_purpose": "pull_request",
        }
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "source review report absent",
        ):
            execution.observed_phase_report(
                b"source_raw_diff_sha256:" + b"f" * 64 + b"\nRan 11 tests in 0.1s\n\nOK\n",
                binding=binding, axis=execution.REQUIRED_AXES[0],
            )

    def test_partial_changed_file_inspection_cannot_count_as_review_pass(self):
        self._phase(1)
        identity = f"{1:032x}"
        receipt = json.loads((self.receipts / (identity + ".json")).read_text())
        original = (self.receipts / (identity + ".out")).read_bytes()
        marker = execution.PHASE_OBSERVATION_PREFIX
        at = original.rfind(marker)
        self.assertGreaterEqual(at, 0)
        observed = json.loads(original[at + len(marker):-1])
        observed["measurements"]["changed_paths"] = 2
        observed["measurements"]["inspected_paths"] = 1
        modified = original[:at] + marker + execution._canonical(observed) + b"\n"
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "not substantive",
        ):
            execution.observed_phase_report(
                modified, binding=receipt["binding"], axis=receipt["axis"],
            )

    def test_trusted_worker_fails_closed_on_uninspected_git_blob(self):
        self._phase(1)
        identity = f"{1:032x}"
        receipt = json.loads((self.receipts / (identity + ".json")).read_text())
        source = execution.trusted_phase_source(
            receipt["binding"], receipt["axis"], receipt["worktree_path"],
        )
        self.assertIn("def bounded(argv,limit,timeout):", source)
        self.assertIn("if size>limit:raise ValueError", source)
        self.assertIn("if blob.returncode or b\'\\x00\' in blob.stdout:sys.exit(92)", source)
        self.assertIn("except UnicodeError:sys.exit(93)", source)

    def test_wrong_producer_rejected_even_with_valid_signature(self) -> None:
        self._five(producer="caller")
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "origin mismatch"):
            self._validate()

    def test_nonexistent_evidence_rejected_even_with_valid_signature(self) -> None:
        self._five(evidence_ref="nonexistent")
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "unresolvable"):
            self._validate()

    def test_wrong_diff_cannot_replay_signed_receipts(self) -> None:
        self._five()
        self.audit["diff_sha256"] = "e" * 64
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "binding"):
            self._validate()

    def test_post_merge_release_exact_serving_and_target_pass(self) -> None:
        self.audit["review_purpose"] = "post_merge_release"
        self.audit["release_binding"] = {
            "serving_release_id": "verified-serving-release",
            "serving_tree": "1" * 40,
            "target_tree": "2" * 40,
        }
        self._five()
        self._validate()

    def test_pr_receipts_cannot_be_replayed_as_r3_release(self) -> None:
        self._five()
        self.audit["review_purpose"] = "post_merge_release"
        self.audit["release_binding"] = {
            "serving_release_id": "verified-serving-release",
            "serving_tree": "1" * 40,
            "target_tree": "2" * 40,
        }
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "binding"):
            self._validate()

    def test_r3_signed_receipts_cannot_be_replayed_for_another_serving_release(self) -> None:
        self.audit["review_purpose"] = "post_merge_release"
        self.audit["release_binding"] = {
            "serving_release_id": "verified-serving-release",
            "serving_tree": "1" * 40,
            "target_tree": "2" * 40,
        }
        self._five()
        self.audit["release_binding"]["serving_release_id"] = "different-serving-release"
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "binding"):
            self._validate()

    def test_duplicate_receipt_rejected(self) -> None:
        self._five()
        self.audit["review_pass_receipts"][4] = deepcopy(self.audit["review_pass_receipts"][3])
        with self.assertRaises(execution.ReviewExecutionRejected):
            self._validate()

    def test_four_passes_rejected(self) -> None:
        for i in range(1, 5):
            self._phase(i)
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "coverage"):
            self._validate()

    def test_poisoned_path_cannot_bypass_real_signature_verification(self) -> None:
        self._five()
        forged = self.receipts / ("1".zfill(32) + ".sig")
        fake_signature = (
            b"-----BEGIN SSH SIGNATURE-----\n"
            b"fake signature body with no trusted private key\n"
            b"-----END SSH SIGNATURE-----\n"
        )
        self._write(forged, fake_signature)
        self.audit["review_pass_receipts"][0]["signature_sha256"] = hashlib.sha256(
            fake_signature
        ).hexdigest()
        fake_bin = Path(self.temp.name) / "fake-bin"
        fake_bin.mkdir(mode=0o700)
        fake = fake_bin / "ssh-keygen"
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(fake_bin)}):
            with self.assertRaisesRegex(
                execution.ReviewExecutionRejected, "signature not authentic"
            ):
                self._validate()

    def test_tampered_private_receipt_rejected(self) -> None:
        self._five()
        path = self.receipts / ("1".zfill(32) + ".json")
        self._write(path, path.read_bytes().replace(b"execution_nonce", b"execution_noncf"))
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "bytes changed"):
            self._validate()

    def test_tampered_output_rejected(self) -> None:
        self._five()
        path = self.receipts / ("1".zfill(32) + ".out")
        self._write(path, b"FAKE stdout\n")
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "bytes changed"):
            self._validate()

    def test_signed_output_without_matching_server_capture_is_rejected(self) -> None:
        self._five()
        capture = self.capture_root / f".grabowski-task-output-{1:024x}-a1" / "stdout.log"
        self._write(capture, b"Ran 100 tests in 0.12s\\n\\nOK\\n")
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "server task capture"):
            self._validate()

    def test_missing_task_capture_is_rejected(self) -> None:
        self._five()
        capture = self.capture_root / f".grabowski-task-output-{1:024x}-a1" / "stdout.log"
        capture.unlink()
        with self.assertRaises((FileNotFoundError, execution.ReviewExecutionRejected)):
            self._validate()

    def test_no_isolation_attestation_rejected(self) -> None:
        self._five(isolation=False)
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "isolation"):
            self._validate()

    def test_duplicate_axes_rejected(self) -> None:
        self._five(axis=execution.REQUIRED_AXES[0])
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "axes"):
            self._validate()

    def test_task_receipt_drift_rejected(self) -> None:
        self._five()
        path = self.outcomes / (f"{1:024x}.json")
        data = json.loads(path.read_text())
        data["state"] = "failed"
        self._write(path, (json.dumps(data, sort_keys=True, indent=2)+"\n").encode())
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "lifecycle receipt digest"):
            self._validate()

    def test_stale_receipt_rejected(self) -> None:
        self._five()
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "stale"):
            execution._verify(
                self.audit, receipts=self.receipts, outcomes=self.outcomes,
                signers=self.signers, repository=Path(self.temp.name),
                now_unix=self.now+86401, root_owned_signers=False,
                read_source=lambda _head, _path: b"alpha\nbeta\n",
            )

    def test_untrusted_signer_allowlist_rejected(self) -> None:
        self._five()
        self.signers.chmod(0o666)
        with self.assertRaisesRegex(execution.ReviewExecutionRejected, "writable by others"):
            self._validate()




class SemanticV2RoleContractTests(unittest.TestCase):
    """Mock V2 job reads; verify semantic binding rules, not a live reviewer."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        def git(*args):
            process = subprocess.run(
                ["git", "-C", str(self.repo), *args],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            return process.stdout.strip()
        git("init", "-q")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "example.py").write_text(
            "def reviewed_contract():\n    return True\n", encoding="utf-8",
        )
        git("add", "-A")
        git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "--no-gpg-sign", "-qm", "fixture")
        head = git("rev-parse", "HEAD")
        self.binding = {
            "repo": "heimgewebe/grabowski", "pr": 1649,
            "base_sha": head, "head_sha": head,
            "diff_sha256": "a" * 64,
            "review_batch_id": "b" * 32, "review_purpose": "pull_request",
        }
        self.attempts = []
        self.receipts = {}
        for number, axis in enumerate(execution.REQUIRED_AXES, start=1):
            summary = (
                "Mock V2 semantic role output for the specific axis " + axis
                + ": analyze the actual changed interface and identify concrete "
                "preconditions, observable failure behavior, concurrency hazards, "
                "negative paths, and compatibility assumptions. Cite affected "
                "source rather than inferring success from five green test runs."
            )
            risks = [
                {
                    "risk": "Unauthorized admission under revision drift " + axis,
                    "assessment": (
                        "Mock role explicitly inspected the source-bound revision "
                        "identity comparison, and would reject a changed base/head "
                        "even when the technical smoke tests all report success."
                    ),
                    "evidence_refs": ["src/example.py:L1"],
                },
                {
                    "risk": "Untriaged semantic finding concealed by tests " + axis,
                    "assessment": (
                        "Mock role evaluated the actual decision boundary and "
                        "requires explicit rejection for outstanding security "
                        "findings instead of inferring material_findings zero."
                    ),
                    "evidence_refs": ["src/example.py:L1"],
                },
            ]
            document = {
                "schema_version": 1,
                "kind": "grabowski_semantic_self_review_v1",
                **self.binding,
                "axis": axis, "verdict": "PASS", "findings": [],
                "summary": summary,
                "evidence_refs": ["src/example.py:L1"],
                "reviewed_risks": risks,
            }
            stdout = json.dumps(
                document, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            )
            receipt = {
                "verdict": "PASS", "findings": [],
                "failure_classification": "passed", "returncode": 0,
                "stdout_tail": stdout, "stdout_bytes": len(stdout.encode()),
                "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                "review_document_object_sha256": decisions.sha256_json(document),
            }
            receipt["receipt_sha256"] = decisions._agent_role_receipt_sha256(receipt)
            unit = f"grabowski-job-{number:012x}"
            self.receipts[unit] = receipt
            self.attempts.append({
                "slot": f"selfrev.{self.binding['review_batch_id'][:16]}.{axis}",
                "unit": unit, "classification": "pass", "terminal": True,
                "terminal_status": "succeeded",
                "review_role_verified": True, "review_route_verified": True,
                "independence_verified": True, "verdict": "PASS_THIS_REVISION",
                "material_findings": 0,
                "origin_sha256": "c" * 64, "result_sha256": "d" * 64,
                "review_role_receipt_sha256": receipt["receipt_sha256"],
                "review_route_id": "codex-sol-review-high",
                "review_provider_family": "openai",
            })

    def verify_fixture(self):
        def role_read(path, *args, **kwargs):
            return self.receipts[Path(path).parent.name]
        with (
            mock.patch.object(
                decisions, "reconcile",
                return_value={"status": "settled", "errors": [], "attempts": self.attempts},
            ),
            mock.patch.object(
                decisions, "_read_private_json", side_effect=role_read,
            ),
        ):
            return execution.verified_semantic_review_passes(
                self.binding, repository=self.repo,
            )

    def test_five_mocked_v2_role_documents_satisfy_contract(self):
        result = self.verify_fixture()
        self.assertEqual(set(result), set(execution.REQUIRED_AXES))
        self.assertEqual(
            len({item["provenance"]["unit"] for item in result.values()}), 5,
        )

    def test_unicode_v2_document_preserves_exact_digest_and_bytes(self):
        unit = "grabowski-job-000000000001"
        receipt = self.receipts[unit]
        document = json.loads(receipt["stdout_tail"])
        document["summary"] += " – Prüfung mit Umlauten: Sicherheit und Integrität."
        wire = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
        receipt["stdout_tail"] = wire
        receipt["stdout_bytes"] = len(wire.encode("utf-8"))
        receipt["stdout_sha256"] = hashlib.sha256(wire.encode("utf-8")).hexdigest()
        receipt["review_document_object_sha256"] = (
            decisions._agent_role_command_sha256(document)
        )
        receipt["receipt_sha256"] = decisions._agent_role_receipt_sha256(receipt)
        self.attempts[0]["review_role_receipt_sha256"] = receipt["receipt_sha256"]
        result = self.verify_fixture()
        self.assertEqual(len(result), len(execution.REQUIRED_AXES))

    def test_missing_axis_role_blocks(self):
        self.attempts.pop()
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "axis absent or ambiguous",
        ):
            self.verify_fixture()

    def test_no_semantic_roles_cannot_be_replaced_by_green_tasks(self):
        with mock.patch.object(
            decisions, "reconcile",
            return_value={"status": "not_applicable", "errors": [], "attempts": []},
        ):
            with self.assertRaisesRegex(
                execution.ReviewExecutionRejected, "not settled",
            ):
                execution.verified_semantic_review_passes(
                    self.binding, repository=self.repo,
                )

    def test_role_receipt_sha256_tampering_blocks(self):
        self.receipts["grabowski-job-000000000001"]["stdout_tail"] += " "
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "role receipt drifted",
        ):
            self.verify_fixture()

    def test_untriaged_semantic_role_blocked(self):
        self.attempts[0]["material_findings"] = 1
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "result not authenticated",
        ):
            self.verify_fixture()

    def test_replayed_role_unit_across_axes_blocks(self):
        self.attempts[1]["unit"] = self.attempts[0]["unit"]
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "task replayed",
        ):
            self.verify_fixture()


class WorkerCoverageIntegrationTests(unittest.TestCase):
    """Execute the frozen source inspection worker against real local Git states."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "test_review_evidence_schemas.py").write_text(
            "import unittest\nclass Probe(unittest.TestCase):\n"
            "    def test_ok(self): self.assertTrue(True)\n", encoding="utf-8",
        )
        (self.repo / "obsolete.py").write_text("value = 1\n", encoding="utf-8")
        self.base = self.commit("base")

    def git(self, *args):
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True, text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def commit(self, label):
        self.git("add", "-A")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--no-gpg-sign", "-qm", label)
        return self.git("rev-parse", "HEAD")

    def worker(self):
        head = self.git("rev-parse", "HEAD")
        binding = {
            "repo": "heimgewebe/grabowski", "pr": 1649,
            "base_sha": self.base, "head_sha": head,
            "diff_sha256": "a" * 64, "review_batch_id": "b" * 32,
            "review_purpose": "pull_request",
        }
        script = execution.trusted_phase_source(
            binding, "contracts_correctness", str(self.repo),
        )
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script],
            cwd=self.repo, capture_output=True, timeout=35, check=False,
        )
        return binding, result

    def report(self, binding, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = execution.PHASE_OBSERVATION_PREFIX
        pos = result.stdout.rfind(prefix)
        self.assertGreaterEqual(pos, 0, result.stdout[-500:])
        decoded = json.loads(result.stdout[pos + len(prefix):-1])
        observed = execution.observed_phase_report(
            result.stdout, binding=binding, axis="contracts_correctness",
        )
        self.assertEqual(decoded["evidence_refs"], observed["evidence_refs"])
        return decoded

    def test_deleted_file_uses_verified_base_reference(self):
        (self.repo / "obsolete.py").unlink()
        self.commit("delete")
        binding, result = self.worker()
        report = self.report(binding, result)
        self.assertEqual(report["measurements"]["changed_paths"], 1)
        self.assertEqual(report["measurements"]["inspected_paths"], 1)
        ref = report["evidence_refs"][0]
        self.assertEqual(ref, f"obsolete.py:{self.base}:L1")
        execution._source_reference(
            ref, head=binding["head_sha"], base=self.base,
            repository=self.repo, read_source=None,
        )
        with self.assertRaisesRegex(
            execution.ReviewExecutionRejected, "revision not bound",
        ):
            execution._source_reference(
                ref, head=binding["head_sha"], base="f" * 40,
                repository=self.repo, read_source=None,
            )

    def test_rename_counts_deleted_and_added_paths(self):
        (self.repo / "obsolete.py").rename(self.repo / "renamed.py")
        self.commit("rename")
        binding, result = self.worker()
        report = self.report(binding, result)
        self.assertEqual(report["measurements"]["changed_paths"], 2)
        self.assertEqual(report["measurements"]["inspected_paths"], 2)
        source = execution.trusted_phase_source(
            binding, "contracts_correctness", str(self.repo),
        )
        self.assertIn("fields=delta.stdout.split(b'\\x00')", source)
        self.assertNotIn("inspection=run('diff'", source)

    def test_chmod_only_counts_full_path(self):
        (self.repo / "obsolete.py").chmod(0o755)
        self.commit("chmod")
        binding, result = self.worker()
        report = self.report(binding, result)
        self.assertEqual(report["measurements"]["changed_paths"], 1)
        self.assertEqual(report["measurements"]["inspected_paths"], 1)

    def test_nul_binary_blob_blocks(self):
        (self.repo / "obsolete.py").write_bytes(b"binary\x00payload\n")
        self.commit("binary")
        _, result = self.worker()
        self.assertEqual(result.returncode, 92)
        self.assertNotIn(execution.PHASE_OBSERVATION_PREFIX, result.stdout)

    def test_symlink_blocks(self):
        (self.repo / "new-link").symlink_to("obsolete.py")
        self.commit("symlink")
        _, result = self.worker()
        self.assertEqual(result.returncode, 95)
        self.assertNotIn(execution.PHASE_OBSERVATION_PREFIX, result.stdout)

    def test_gitlink_changed_path_cannot_be_silently_skipped(self):
        nested = self.repo / "nested"
        nested.mkdir()
        def subgit(*args):
            child = subprocess.run(
                ["git", "-C", str(nested), *args],
                capture_output=True, text=True, check=False, timeout=15,
            )
            self.assertEqual(0, child.returncode, child.stderr)
        subgit("init", "-q")
        (nested / "file.txt").write_text("nested\n", encoding="utf-8")
        subgit("add", "-A")
        subgit("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
               "commit", "--no-gpg-sign", "-qm", "nested")
        self.git("add", "nested")
        self.commit("gitlink")
        _, result = self.worker()
        self.assertEqual(95, result.returncode, result.stderr[:300])
        self.assertNotIn(execution.PHASE_OBSERVATION_PREFIX, result.stdout)

    def test_oversize_blob_stream_is_bounded(self):
        (self.repo / "huge.txt").write_bytes(b"x" * 2097153)
        self.commit("huge")
        _, result = self.worker()
        self.assertEqual(result.returncode, 98)
        self.assertNotIn(execution.PHASE_OBSERVATION_PREFIX, result.stdout)

    def test_oversize_test_stdout_stream_is_bounded(self):
        (self.repo / "tests" / "test_review_evidence_schemas.py").write_text(
            "import unittest\nclass Probe(unittest.TestCase):\n"
            "    def test_noisy(self): print('X' * 1048577)\n", encoding="utf-8",
        )
        self.commit("noisy")
        _, result = self.worker()
        self.assertEqual(result.returncode, 98)
        self.assertNotIn(execution.PHASE_OBSERVATION_PREFIX, result.stdout)

if __name__ == "__main__":
    unittest.main()