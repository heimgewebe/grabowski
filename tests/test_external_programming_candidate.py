from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location("external_programming_candidate_test", ROOT / "tools" / "external_programming_candidate.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


candidate_tool = _load_tool()


class ExternalProgrammingCandidateTests(unittest.TestCase):
    def _packet(self, directory: Path, repo: Path, *, provider: str = "agy") -> Path:
        source = "VALUE = 1\n"
        packet = {
            "schema_version": 1,
            "kind": "external_programming_candidate_packet",
            "competition_id": f"gac-{provider}-competitor-{'1' * 10}-{'2' * 10}",
            "request_id": f"runner-{provider}",
            "request_fingerprint": "7" * 64,
            "provider": provider,
            "mode": "competitor",
            "repository": str(repo),
            "expected_head": "a" * 40,
            "task": "Improve the sample",
            "task_sha256": hashlib.sha256(b"Improve the sample").hexdigest(),
            "allowed_paths": ["src", "tests"],
            "forbidden_paths": [],
            "context": [{"path": "src/sample.py", "sha256": hashlib.sha256(source.encode()).hexdigest(), "text": source}],
            "primary_summary": "",
            "packet_nonce": "3" * 32,
            "created_at": "2026-07-12T12:00:00Z",
        }
        packet["packet_sha256"] = candidate_tool.sha256_json(packet)
        path = directory / "packet.json"
        path.write_text(json.dumps(packet), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def _candidate(self) -> dict:
        return {
            "approach_id": "simple",
            "approach_summary": "Change the constant and test it.",
            "assumptions": ["source is authoritative"],
            "design_invariants": ["keep API stable"],
            "tradeoffs": ["small change"],
            "risks": ["stale test"],
            "proposed_tests": ["run unit test"],
            "changed_paths": ["src/sample.py"],
            "patch": "",
            "contrast_observations": ["avoid new abstraction"],
            "confidence": "medium",
        }

    def test_prompt_contains_schema_for_agy_and_nonce_fences(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            repo = root / "repo"
            repo.mkdir()
            repo.chmod(0o700)
            packet = candidate_tool.validate_packet(candidate_tool.load_private_json(self._packet(root, repo), label="packet"))
            prompt = candidate_tool.build_prompt(packet)
            self.assertIn("Required JSON Schema", prompt)
            self.assertIn('"approach_id"', prompt)
            self.assertIn("BEGIN UNTRUSTED SOURCE", prompt)
            self.assertIn(packet["packet_nonce"], prompt)

    def test_validate_candidate_rejects_scope_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            packet = {"allowed_paths": ["src"], "forbidden_paths": []}
            value = self._candidate()
            value["changed_paths"] = ["outside.py"]
            with self.assertRaisesRegex(candidate_tool.CandidateError, "outside scope"):
                candidate_tool.validate_candidate(value, packet, repo)

    def test_invalid_optional_patch_is_dropped_but_reasoning_survives(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            value = self._candidate()
            value["patch"] = "No patch proposed; reasoning only."
            packet = {"allowed_paths": ["src"], "forbidden_paths": []}
            result = candidate_tool.validate_candidate(value, packet, repo)
        self.assertEqual(result["patch"], "")
        self.assertEqual(result["patch_paths"], [])
        self.assertFalse(result["patch_check"]["syntax_accepted"])
        self.assertTrue(result["patch_rejection"]["rejected"])
        self.assertEqual(result["approach_summary"], value["approach_summary"])

    def test_environment_does_not_forward_secret_variables(self) -> None:
        with mock.patch.dict(os.environ, {"SECRET_TOKEN": "do-not-forward", "PATH": "/usr/bin", "HOME": "/tmp/home"}, clear=True):
            environment = candidate_tool.provider_environment()
        self.assertNotIn("SECRET_TOKEN", environment)
        self.assertEqual(environment["PATH"], "/usr/bin")

    def test_atomic_output_rejects_existing_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            target = root / "target"
            target.write_text("safe", encoding="utf-8")
            link = root / "receipt.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(candidate_tool.CandidateError, "already exists"):
                candidate_tool.atomic_bytes(link, b"unsafe", create_only=True)
            self.assertEqual(target.read_text(), "safe")

    def test_main_writes_bound_receipt_without_mutating_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            repo = root / "repo"
            repo.mkdir(mode=0o700)
            (repo / "src").mkdir()
            (repo / "src" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
            directory = root / "candidate"
            directory.mkdir(mode=0o700)
            packet_path = self._packet(directory, repo)
            output = directory / "receipt.json"
            raw = directory / "raw-output.json"
            stderr = directory / "stderr.txt"
            external = json.dumps(self._candidate()).encode()
            git_calls = []

            def fake_git(_repo, args, **kwargs):
                git_calls.append(args)
                if args[:2] == ["rev-parse", "HEAD^{commit}"]:
                    return subprocess.CompletedProcess(args, 0, b"a" * 40 + b"\n", b"")
                if args and args[0] == "status":
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                if args[:2] == ["apply", "--check"]:
                    return subprocess.CompletedProcess(args, 0, b"", b"")
                raise AssertionError(args)

            calls = []

            def fake_run(argv, **kwargs):
                calls.append((argv, kwargs))
                if argv[1:] == ["--version"]:
                    return subprocess.CompletedProcess(argv, 0, "agy 1.1.1\n", "")
                self.assertEqual(argv[0], "agy")
                self.assertEqual(kwargs["cwd"], directory)
                self.assertNotIn("SECRET_TOKEN", kwargs["env"])
                return subprocess.CompletedProcess(argv, 0, external, b"")

            with (
                mock.patch.object(candidate_tool, "run_git", side_effect=fake_git),
                mock.patch.object(candidate_tool.shutil, "which", return_value="/usr/bin/true"),
                mock.patch.object(candidate_tool.subprocess, "run", side_effect=fake_run),
                mock.patch.dict(os.environ, {"PATH": "/usr/bin", "HOME": str(root), "SECRET_TOKEN": "hidden"}, clear=True),
            ):
                result = candidate_tool.main([
                    "--packet", str(packet_path),
                    "--output", str(output),
                    "--raw-output", str(raw),
                    "--stderr-output", str(stderr),
                    "--timeout-seconds", "60",
                ])
            self.assertEqual(result, 0)
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["expected_head"], "a" * 40)
            self.assertEqual(receipt["authority"], "advisory_only")
            self.assertFalse(receipt["automatic_apply"])
            self.assertTrue((directory / "prompt.txt").is_file())
            self.assertIn("Required JSON Schema", (directory / "prompt.txt").read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertGreaterEqual(len(git_calls), 4)

    def test_main_rejects_output_escape_before_provider_call(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            repo = root / "repo"
            repo.mkdir(mode=0o700)
            directory = root / "candidate"
            directory.mkdir(mode=0o700)
            packet_path = self._packet(directory, repo)
            result = candidate_tool.main([
                "--packet", str(packet_path),
                "--output", str(root / "receipt.json"),
                "--raw-output", str(directory / "raw-output.json"),
                "--stderr-output", str(directory / "stderr.txt"),
                "--timeout-seconds", "60",
            ])
            self.assertEqual(result, 2)
            self.assertFalse((root / "receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
