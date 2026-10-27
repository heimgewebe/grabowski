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
            python, "-B", "-c",
            execution.trusted_phase_source(binding, axis, worktree),
        ]
        argv = hashlib.sha256(json.dumps(
            sandbox_argv, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        output = ("source_raw_diff_sha256:" + "f" * 64 + f"\nRan {n+9} tests in 0.10s\n\nOK\n").encode()
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

    def test_five_authentic_distinct_server_phases_pass(self) -> None:
        self._five()
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


if __name__ == "__main__":
    unittest.main()