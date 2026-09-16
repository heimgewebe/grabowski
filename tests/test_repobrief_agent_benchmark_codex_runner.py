from __future__ import annotations

from argparse import Namespace
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "repobrief_agent_benchmark_codex_runner.py"
SPEC = importlib.util.spec_from_file_location("repobrief_agent_benchmark_codex_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

TASKSET_SHA = "a" * 64
MANIFEST_SHA = "b" * 64
COMMIT = "c" * 40


def request(*, condition: str = "baseline", commit: str = COMMIT) -> dict:
    allowed = {"glob", "grep", "read_file", "search"}
    repobrief = None
    if condition == "treatment":
        allowed.update(runner.ALLOWED_MCP)
        repobrief = {
            "manifest": "/bundles/repo.bundle.manifest.json",
            "manifest_sha256": MANIFEST_SHA,
            "mcp_command": ["/usr/bin/python3", "repobrief-mcp-stdio.py", "--bundle-root", "/bundles"],
        }
    pair_id = "taskset:case:r1"
    request_id = f"{pair_id}:{condition}"
    return {
        "kind": runner.base.REQUEST_KIND,
        "version": runner.base.VERSION,
        "request_id": request_id,
        "pair_id": pair_id,
        "case_id": "case",
        "condition": condition,
        "order": 1 if condition == "baseline" else 2,
        "repetition": 1,
        "taskset_id": "taskset",
        "taskset_sha256": TASKSET_SHA,
        "repository": {
            "id": "repo",
            "repository": "heimgewebe/repo",
            "commit": commit,
        },
        "session_id": f"session:{request_id}",
        "workspace_id": f"workspace:{request_id}",
        "prompt": "Find the implementation and cite it.",
        "allowed_tools": sorted(allowed),
        "budgets": {
            "wall_seconds": 300,
            "input_tokens": 64000,
            "output_tokens": 6000,
            "max_tool_calls": 80,
            "max_tool_input_bytes": 1048576,
            "max_tool_output_bytes": 8388608,
        },
        "runner": {
            "execution_contract": runner.EXECUTION_CONTRACT,
            "provider": runner.PROVIDER,
            "model": runner.MODEL,
            "sampling": runner.SAMPLING,
        },
        "repobrief": repobrief,
        "isolation": {
            "fresh_session": True,
            "fresh_workspace": True,
            "cross_condition_reuse_allowed": False,
        },
        "does_not_establish": list(runner.base.DOES_NOT_ESTABLISH),
    }


def answer() -> dict:
    return {
        "text": "The implementation is in src/example.py.",
        "outcome": "answer",
        "reported_paths": ["src/example.py"],
        "reported_symbols": ["example"],
        "citations": [{"path": "src/example.py", "start_line": 1, "end_line": 2}],
        "claims": ["read_only_default"],
        "asserted_sufficient_evidence": True,
    }


def stream(value: dict, *, command: str = "cat src/example.py") -> bytes:
    events = [
        {"type": "thread.started", "thread_id": "fixture-thread"},
        {"type": "turn.started"},
        {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": command,
                "aggregated_output": "def example():\n    return True\n",
                "exit_code": 0,
                "status": "completed",
            },
        },
        {
            "type": "item.completed",
            "item": {"type": "agent_message", "text": json.dumps(answer(), sort_keys=True)},
        },
        {
            "type": "turn.completed",
            "usage": {"input_tokens": 120, "output_tokens": 30, "cached_input_tokens": 0},
        },
    ]
    return b"".join(json.dumps(event, sort_keys=True).encode("utf-8") + b"\n" for event in events)


def git(arguments: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=cwd, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def repository(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    git(["init"], source)
    git(["config", "user.email", "test@example.invalid"], source)
    git(["config", "user.name", "Test"], source)
    (source / "src").mkdir()
    (source / "src" / "example.py").write_text(
        "def example():\n    return True\n", encoding="utf-8"
    )
    git(["add", "."], source)
    git(["commit", "-m", "fixture"], source)
    return source, git(["rev-parse", "HEAD"], source)


def planned_request_root(root: Path, value: dict) -> Path:
    result = root / "requests"
    result.mkdir()
    (result / "request.json").write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return result


def repository_map(root: Path, source: Path) -> Path:
    path = root / "repositories.json"
    path.write_text(
        json.dumps({"repo": {"repository": "heimgewebe/repo", "root": str(source)}}),
        encoding="utf-8",
    )
    return path


def fixture_args(root: Path, fixture: Path, *, stderr: Path | None = None, returncode: int = 0) -> Namespace:
    return Namespace(
        request_root=root / "requests",
        repository_map=root / "repositories.json",
        state_root=root / "state",
        transcript_root=root / "transcripts",
        provider_evidence_root=root / "provider-evidence",
        codex_command="codex",
        codex_command_sha256=None,
        allow_live_provider=False,
        stream_fixture=fixture,
        stderr_fixture=stderr,
        fixture_returncode=returncode,
    )


def treatment_tools() -> list[dict]:
    metadata = {
        'ask_context': ('RepoGround context pack', 'Build a cited context pack from one existing RepoGround bundle.'),
        'grounding_verify': ('RepoGround grounding verifier', 'Verify declared citations and ranges against an existing RepoGround bundle.'),
        'live_freshness': ('RepoGround live freshness', 'Compare snapshot Git provenance with the configured local checkout without refreshing it.'),
    }
    annotations = {'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True}
    return [
        {
            'name': name,
            'title': metadata[name][0],
            'description': metadata[name][1],
            'inputSchema': json.loads(json.dumps(runner.EXPECTED_UPSTREAM_MCP_INPUT_SCHEMAS[name])),
            'annotations': dict(annotations),
        }
        for name in sorted(runner.UPSTREAM_MCP)
    ]


class RepoBriefCodexRunnerTests(unittest.TestCase):
    def test_request_contract_is_exact_and_provider_specific(self) -> None:
        runner.validate_request(request())
        runner.validate_request(request(condition="treatment"))

        value = request()
        value["runner"]["model"] = "gpt-other"
        with self.assertRaisesRegex(runner.RunnerError, "Codex runner contract mismatch"):
            runner.validate_request(value)

        value = request()
        value["runner"]["sampling"] = {"reasoning_effort": "high"}
        with self.assertRaisesRegex(runner.RunnerError, "Codex runner contract mismatch"):
            runner.validate_request(value)

    def test_provider_environment_removes_payg_keys(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "HOME": "/home/test",
                "OPENAI_API_KEY": "must-not-leak",
                "AZURE_OPENAI_API_KEY": "must-not-leak",
                "ANTHROPIC_API_KEY": "must-not-leak",
                "CODEX_ACCESS_TOKEN": "must-not-leak",
            },
            clear=True,
        ):
            environment = runner.provider_env()
        self.assertEqual(environment["HOME"], "/home/test")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("AZURE_OPENAI_API_KEY", environment)
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("CODEX_ACCESS_TOKEN", environment)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_chatgpt_subscription_gate_rejects_other_login_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            auth_dir = home / ".codex"
            auth_dir.mkdir(parents=True, mode=0o700)
            auth = auth_dir / "auth.json"
            auth.write_bytes(b"opaque-chatgpt-auth")
            auth.chmod(0o600)
            environment = {"HOME": str(home), "PATH": "/usr/bin:/bin"}
            ok = subprocess.CompletedProcess(
                ["codex", "login", "status"], 0,
                stdout=b"Logged in using ChatGPT\n", stderr=b"",
            )
            with patch.object(runner, "provider_env", return_value=environment), patch.object(
                runner.subprocess, "run", return_value=ok
            ):
                self.assertEqual(runner.validate_chatgpt_subscription("/opt/codex"), b"opaque-chatgpt-auth")
            bad = subprocess.CompletedProcess(
                ["codex", "login", "status"], 0,
                stdout=b"Logged in using API key\n", stderr=b"",
            )
            with patch.object(runner, "provider_env", return_value=environment), patch.object(
                runner.subprocess, "run", return_value=bad
            ):
                with self.assertRaisesRegex(runner.RunnerError, "ChatGPT subscription"):
                    runner.validate_chatgpt_subscription("/opt/codex")

    def test_staged_codex_home_is_private_and_cleanup_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir(mode=0o700)
            runtime_home = runner.stage_codex_home(state, b"opaque-auth")
            self.assertTrue(runtime_home.is_dir())
            self.assertEqual(stat.S_IMODE(runtime_home.stat().st_mode), 0o700)
            auth = runtime_home / "auth.json"
            self.assertEqual(auth.read_bytes(), b"opaque-auth")
            self.assertEqual(stat.S_IMODE(auth.stat().st_mode), 0o600)
            self.assertIsNone(runner.cleanup_codex_home(runtime_home))
            self.assertFalse(runtime_home.exists())
            with patch.object(runner.shutil, "rmtree", side_effect=OSError("cleanup failed")):
                self.assertEqual(runner.cleanup_codex_home(Path("/tmp/example")), "OSError")

    def test_stderr_policy_is_explicit_and_fail_closed(self) -> None:
        empty = runner.classify_stderr(b"")
        self.assertTrue(empty["allowed"])
        self.assertEqual(empty["classification"], "empty")

        whitespace = runner.classify_stderr(b" \n\t\r\n")
        self.assertTrue(whitespace["allowed"])
        self.assertEqual(whitespace["classification"], "whitespace_only")

        text = runner.classify_stderr(b"warning: something happened\n")
        self.assertFalse(text["allowed"])
        self.assertEqual(text["classification"], "text_unqualified")
        self.assertEqual(text["meaningful_line_count"], 1)
        self.assertEqual(len(text["line_sha256"]), 1)

        binary = runner.classify_stderr(b"\xff\xfe")
        self.assertFalse(binary["allowed"])
        self.assertEqual(binary["classification"], "non_utf8_unqualified")

        qualified_line = (
            b"WARNING: proceeding, even though we could not create PATH aliases: "
            b"Read-only file system (os error 30)\n"
        )
        qualified = runner.classify_stderr(qualified_line)
        self.assertTrue(qualified["allowed"])
        self.assertEqual(qualified["classification"], "qualified_benign_text")
        self.assertEqual(qualified["meaningful_line_count"], 1)
        self.assertEqual(len(runner.QUALIFIED_BENIGN_STDERR_PATTERNS), 1)

        near_match = runner.classify_stderr(
            b"WARNING: proceeding, even though we could not create PATH aliases: "
            b"Permission denied (os error 13)\n"
        )
        self.assertFalse(near_match["allowed"])
        self.assertEqual(near_match["classification"], "text_unqualified")

    def test_command_normalization_is_read_only_and_fail_closed(self) -> None:
        self.assertEqual(runner.command_kind("rg --files src"), "glob")
        self.assertEqual(runner.command_kind("rg -g '*.py' --files src"), "glob")
        self.assertEqual(runner.command_kind("rg example src"), "grep")
        self.assertEqual(runner.command_kind("rg -n 'foo|bar' src"), "grep")
        self.assertEqual(runner.command_kind("rg 'foo{1,3}' src"), "grep")
        self.assertEqual(runner.command_kind("rg foo#bar src"), "grep")
        self.assertEqual(runner.command_kind("rg --regexp=example src"), "grep")
        self.assertEqual(runner.command_kind("cat src/example.py"), "read_file")
        self.assertEqual(runner.command_kind("sed -n '1,2p' src/example.py"), "read_file")
        for command in (
            "ls",
            "git status",
            "python -c 'print(1)'",
            "cat a | head",
            "cat a && cat b",
            "cat a > /tmp/a",
            "cat a b",
            "sed -i 's/a/b/' src/example.py",
            "sed -n '1,$p' src/example.py",
            "rg --pre cat example src",
            "rg --hostname-bin sh example src",
            "rg --files -e example src",
            "cat /etc/hostname",
            "cat ../outside",
            "cat $HOME/file",
            "sed -n '1,2p' /etc/hostname",
            "rg example /etc",
            "rg --files ../other",
            "/usr/bin/cat src/example.py",
            "sh -lc 'cat src/example.py'",
            "bash -lc 'cat src/example.py'",
            "rg needle src\ncat secret",
            "cat src/example.py\r\nrg needle src",
            "rg needle src |& id",
            "cat src/example.py &> output",
            "cat src/example.py >& output",
            "cat src/example.py <<< data",
            "cat src/example.py >| output",
            "rg {needle,../sibling}",
            "rg needle --glob *.py",
            'rg "$HOME" src',
            "rg foo#bar | id",
            "rg foo#bar ../outside",
        ):
            with self.subTest(command=command):
                with self.assertRaises(runner.RunnerError):
                    runner.command_kind(command)

    def test_build_commands_isolates_baseline_and_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema = root / "schema.json"
            checkout = root / "repo"
            checkout.mkdir()
            codex_home = root / "codex-home"
            baseline = runner.build_command(
                request(), "/opt/codex", checkout, schema, codex_home
            )
            treatment = runner.build_command(
                request(condition="treatment"), "/opt/codex", checkout, schema, codex_home
            )
        baseline_joined = " ".join(baseline)
        treatment_joined = " ".join(treatment)
        for flag in (
            "--ephemeral", "--ignore-user-config", "--ignore-rules",
            "--strict-config", "--json",
        ):
            self.assertIn(flag, baseline)
        self.assertNotIn("--sandbox", baseline)
        self.assertIn(f'default_permissions="{runner.PERMISSION_PROFILE}"', baseline)
        self.assertIn("features.network_proxy=true", baseline)
        self.assertTrue(any("domains={}" in item for item in baseline))
        self.assertTrue(any(":workspace_roots" in item for item in baseline))
        self.assertIn('web_search="disabled"', baseline)
        self.assertNotIn("mcp_servers.repobrief", baseline_joined)
        self.assertIn("mcp_servers.repobrief", treatment_joined)
        self.assertIn("--codex-mcp-proxy", treatment_joined)

    def test_raw_provider_evidence_is_written_before_unqualified_stderr_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            fixture = root / "stdout.jsonl"
            fixture.write_bytes(stream(value))
            stderr = root / "stderr.txt"
            stderr.write_bytes(b"warning: not yet qualified\n")
            args = fixture_args(root, fixture, stderr=stderr)

            with self.assertRaisesRegex(runner.RunnerError, "after evidence persistence"):
                runner.execute(value, args)

            names = runner._provider_artifact_names(value)
            raw_stdout = root / "transcripts" / names["stdout"]
            raw_stderr = root / "provider-evidence" / names["stderr"]
            diagnostics_path = root / "provider-evidence" / names["diagnostics"]
            stderr_policy_path = root / "provider-evidence" / names["stderr_policy"]
            self.assertEqual(raw_stdout.read_bytes(), fixture.read_bytes())
            self.assertEqual(raw_stderr.read_bytes(), stderr.read_bytes())
            diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
            self.assertEqual(diagnostics["semantic_interpretation"], "not_performed")
            self.assertEqual(
                diagnostics["stderr"]["sha256"], hashlib.sha256(stderr.read_bytes()).hexdigest()
            )
            self.assertEqual(diagnostics["stdout"]["sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest())
            stderr_policy = json.loads(stderr_policy_path.read_text(encoding="utf-8"))
            self.assertEqual(stderr_policy["stderr"]["classification"], "text_unqualified")
            self.assertFalse(stderr_policy["stderr"]["allowed"])

    def test_capture_diagnostics_are_persisted_before_stderr_classifier_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = request()
            capture = {
                "stdout": b"captured\n",
                "stderr": b"diagnostic\n",
                "returncode": 0,
                "capture_error": None,
                "stdout_overflow": False,
                "stderr_overflow": False,
            }
            now = datetime.now(timezone.utc)
            with patch.object(runner, "classify_stderr", side_effect=runner.RunnerError("classifier boom")):
                with self.assertRaisesRegex(runner.RunnerError, "classifier boom"):
                    runner.persist_provider_capture(
                        value,
                        transcript_root=root / "transcripts",
                        evidence_root=root / "provider-evidence",
                        capture=capture,
                        started_at=now,
                        ended_at=now,
                        synthetic_fixture=True,
                    )
            names = runner._provider_artifact_names(value)
            self.assertEqual((root / "transcripts" / names["stdout"]).read_bytes(), b"captured\n")
            self.assertEqual((root / "provider-evidence" / names["stderr"]).read_bytes(), b"diagnostic\n")
            diagnostics = json.loads(
                (root / "provider-evidence" / names["diagnostics"]).read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostics["semantic_interpretation"], "not_performed")
            self.assertFalse((root / "provider-evidence" / names["stderr_policy"]).exists())

    def test_partial_private_write_is_preserved_for_forensics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            path, descriptor = runner._open_private_directory(root, create_final=False)
            real_write = os.write
            calls = 0
            def flaky_write(fd, data):
                nonlocal calls
                if calls == 0:
                    calls += 1
                    return real_write(fd, bytes(data[:3]))
                raise OSError("simulated disk failure")
            try:
                with patch.object(runner.os, "write", side_effect=flaky_write):
                    with self.assertRaisesRegex(OSError, "simulated disk failure"):
                        runner._write_private_dirfd(descriptor, "partial.bin", b"abcdef")
            finally:
                os.close(descriptor)
            self.assertEqual((path / "partial.bin").read_bytes(), b"abc")

    def test_directory_fsync_failure_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            root.mkdir(mode=0o700)
            path, descriptor = runner._open_private_directory(root, create_final=False)
            real_fsync = os.fsync
            calls = 0
            def flaky_fsync(fd):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated directory fsync failure")
                return real_fsync(fd)
            try:
                with patch.object(runner.os, "fsync", side_effect=flaky_fsync):
                    with self.assertRaisesRegex(OSError, "directory fsync failure"):
                        runner._write_private_dirfd(descriptor, "durable.bin", b"complete")
            finally:
                os.close(descriptor)
            self.assertEqual((path / "durable.bin").read_bytes(), b"complete")

    def test_malformed_stdout_is_still_persisted_before_parser_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            fixture = root / "stdout.jsonl"
            fixture.write_bytes(b"not-json\n")
            args = fixture_args(root, fixture)

            with self.assertRaisesRegex(runner.RunnerError, "invalid JSON"):
                runner.execute(value, args)

            names = runner._provider_artifact_names(value)
            self.assertEqual(
                (root / "transcripts" / names["stdout"]).read_bytes(), b"not-json\n"
            )
            stderr_policy = json.loads(
                (root / "provider-evidence" / names["stderr_policy"]).read_text(encoding="utf-8")
            )
            self.assertEqual(stderr_policy["stderr"]["classification"], "empty")

    def test_nonzero_provider_exit_is_evidenced_before_receipt_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            fixture = root / "stdout.jsonl"
            fixture.write_bytes(stream(value))
            args = fixture_args(root, fixture, returncode=7)

            with self.assertRaisesRegex(runner.RunnerError, "exited nonzero: 7"):
                runner.execute(value, args)

            names = runner._provider_artifact_names(value)
            diagnostics = json.loads(
                (root / "provider-evidence" / names["diagnostics"]).read_text(encoding="utf-8")
            )
            self.assertEqual(diagnostics["returncode"], 7)
            self.assertTrue((root / "transcripts" / names["stdout"]).is_file())
            self.assertTrue((root / "provider-evidence" / names["stderr"]).is_file())

    def test_synthetic_end_to_end_produces_compatible_normalized_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            fixture = root / "stdout.jsonl"
            fixture.write_bytes(stream(value))
            args = fixture_args(root, fixture)

            report = runner.execute(value, args)

            self.assertEqual(report["kind"], runner.base.FIXTURE_REPORT_KIND)
            self.assertTrue(report["synthetic_fixture"])
            receipt = report["normalized_candidate"]
            self.assertEqual(receipt["request_sha256"], runner.base._sha256_json(value))
            self.assertEqual(receipt["provider"]["name"], "synthetic-fixture")
            self.assertEqual(receipt["provider"]["token_source"], "synthetic")
            self.assertEqual(receipt["tool_calls"][0]["name"], "read_file")
            self.assertEqual(receipt["answer"], answer())
            names = runner._provider_artifact_names(value)
            self.assertEqual(receipt["transcript"]["artifact"], names["stdout"])
            self.assertEqual(
                (root / "transcripts" / names["stdout"]).read_bytes(), fixture.read_bytes()
            )
            diagnostics = json.loads(
                (root / "provider-evidence" / names["diagnostics"]).read_text(encoding="utf-8")
            )
            stderr_policy = json.loads(
                (root / "provider-evidence" / names["stderr_policy"]).read_text(encoding="utf-8")
            )
            self.assertEqual(stderr_policy["stderr"]["classification"], "empty")
            self.assertTrue(diagnostics["synthetic_fixture"])

    def test_live_execution_requires_explicit_authorization_before_workspace_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = Namespace(
                request_root=root / "missing-requests",
                repository_map=root / "missing-map.json",
                state_root=root / "state",
                transcript_root=root / "transcripts",
                provider_evidence_root=root / "provider-evidence",
                codex_command="/opt/codex",
                codex_command_sha256=None,
                allow_live_provider=False,
                stream_fixture=None,
                stderr_fixture=None,
                fixture_returncode=0,
            )
            with self.assertRaisesRegex(runner.RunnerError, "explicit allow_live_provider"):
                runner.execute(request(), args)
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "transcripts").exists())
            self.assertFalse((root / "provider-evidence").exists())

    def test_bad_live_executable_hash_fails_before_workspace_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            fake_codex = root / "codex"
            fake_codex.write_bytes(b"#!/bin/sh\nexit 0\n")
            fake_codex.chmod(0o700)
            args = Namespace(
                request_root=root / "requests",
                repository_map=root / "repositories.json",
                state_root=root / "state",
                transcript_root=root / "transcripts",
                provider_evidence_root=root / "provider-evidence",
                codex_command=str(fake_codex),
                codex_command_sha256="0" * 64,
                allow_live_provider=True,
                stream_fixture=None,
                stderr_fixture=None,
                fixture_returncode=0,
            )
            with self.assertRaisesRegex(runner.RunnerError, "mismatched"):
                runner.execute(value, args)
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "transcripts").exists())
            self.assertFalse((root / "provider-evidence").exists())

    def test_treatment_manifest_mismatch_fails_before_workspace_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(condition="treatment", commit=commit)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"frozen-manifest\n")
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = "0" * 64
            planned_request_root(root, value)
            repository_map(root, source)
            fixture = root / "stdout.jsonl"
            fixture.write_bytes(stream(value))
            args = fixture_args(root, fixture)

            with self.assertRaisesRegex(runner.RunnerError, "manifest SHA mismatch"):
                runner.execute(value, args)
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "transcripts").exists())
            self.assertFalse((root / "provider-evidence").exists())

    def test_treatment_manifest_symlink_fails_before_workspace_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(condition="treatment", commit=commit)
            real_manifest = root / "manifest-real.json"
            real_manifest.write_bytes(b"frozen-manifest\n")
            manifest = root / "manifest.json"
            manifest.symlink_to(real_manifest)
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = hashlib.sha256(real_manifest.read_bytes()).hexdigest()
            planned_request_root(root, value); repository_map(root, source)
            fixture = root / "stdout.jsonl"; fixture.write_bytes(stream(value))
            args = fixture_args(root, fixture)
            with self.assertRaisesRegex(runner.RunnerError, "regular non-symlink"):
                runner.execute(value, args)
            self.assertFalse((root / "state").exists())

    def test_existing_provider_artifact_fails_before_workspace_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value); repository_map(root, source)
            fixture = root / "stdout.jsonl"; fixture.write_bytes(stream(value))
            transcript_root = root / "transcripts"; transcript_root.mkdir(mode=0o700)
            names = runner._provider_artifact_names(value)
            (transcript_root / names["stdout"]).write_bytes(b"occupied")
            args = fixture_args(root, fixture)
            with self.assertRaisesRegex(runner.RunnerError, "already exists"):
                runner.execute(value, args)
            self.assertFalse((root / "state" / "codex-workspaces").exists())

    def test_symlink_provider_root_fails_before_workspace_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value); repository_map(root, source)
            fixture = root / "stdout.jsonl"; fixture.write_bytes(stream(value))
            real = root / "real-transcripts"; real.mkdir(mode=0o700)
            (root / "transcripts").symlink_to(real, target_is_directory=True)
            args = fixture_args(root, fixture)
            with self.assertRaisesRegex(runner.RunnerError, "unsafe component"):
                runner.execute(value, args)
            self.assertFalse((root / "state" / "codex-workspaces").exists())

    def test_live_execution_rejects_fixture_controls_before_workspace_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stderr = root / "stderr.txt"
            stderr.write_text("fixture-only", encoding="utf-8")
            args = Namespace(
                request_root=root / "missing-requests",
                repository_map=root / "missing-map.json",
                state_root=root / "state",
                transcript_root=root / "transcripts",
                provider_evidence_root=root / "provider-evidence",
                codex_command="/opt/codex",
                codex_command_sha256="0" * 64,
                allow_live_provider=True,
                stream_fixture=None,
                stderr_fixture=stderr,
                fixture_returncode=0,
            )
            with self.assertRaisesRegex(runner.RunnerError, "synthetic fixture controls"):
                runner.execute(request(), args)
            self.assertFalse((root / "state").exists())

    def test_fixture_rejects_live_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = root / "fixture.jsonl"
            fixture.write_bytes(b"{}\n")
            args = fixture_args(root, fixture)
            args.allow_live_provider = True
            with self.assertRaisesRegex(runner.RunnerError, "must not carry live-provider"):
                runner.execute(request(), args)
            self.assertFalse((root / "state").exists())

    def test_executable_is_absolute_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "codex"
            path.write_bytes(b"#!/bin/sh\nexit 0\n")
            path.chmod(0o700)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(runner.validate_executable(str(path), digest), str(path.resolve()))
            with self.assertRaisesRegex(runner.RunnerError, "mismatched"):
                runner.validate_executable(str(path), "0" * 64)
            with self.assertRaisesRegex(runner.RunnerError, "must be absolute"):
                runner.validate_executable("codex", digest)
            link = Path(temporary) / "codex-link"
            link.symlink_to(path)
            with self.assertRaisesRegex(runner.RunnerError, "must not be a symlink"):
                runner.validate_executable(str(link), digest)
            with self.assertRaisesRegex(runner.RunnerError, "read-only filesystem"):
                runner.validate_executable(
                    str(path), digest, require_read_only_mount=True
                )
            read_only = type(
                "ReadOnlyStatVfs",
                (),
                {"f_flag": getattr(os, "ST_RDONLY", 1)},
            )()
            with patch.object(runner.os, "statvfs", return_value=read_only):
                self.assertEqual(
                    runner.validate_executable(
                        str(path), digest, require_read_only_mount=True
                    ),
                    str(path.resolve()),
                )

    def test_run_bounded_preserves_streams_when_provider_rejects_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "reject_input.py"
            script.write_text(
                "import os, sys, time\n"
                "os.close(0)\n"
                "sys.stderr.write('input-closed\\n'); sys.stderr.flush()\n"
                "time.sleep(0.2)\n",
                encoding="utf-8",
            )
            capture = runner.run_bounded(
                [sys.executable, str(script)],
                cwd=root,
                timeout_seconds=2,
                stdin_data=b"x" * (2 * 1024 * 1024),
            )
            self.assertTrue(str(capture["capture_error"]).startswith("stdin_write_failed:"))
            self.assertIn(b"input-closed", capture["stderr"])

    def test_run_bounded_converts_post_start_stream_exception_to_capture_error(self) -> None:
        real_selector = runner.selectors.DefaultSelector

        class FlakySelector:
            def __init__(self) -> None:
                self.inner = real_selector()
                self.saw_event = False

            def register(self, *args, **kwargs):
                return self.inner.register(*args, **kwargs)

            def unregister(self, *args, **kwargs):
                return self.inner.unregister(*args, **kwargs)

            def get_map(self):
                return self.inner.get_map()

            def select(self, timeout=None):
                if self.saw_event:
                    raise OSError("simulated selector failure")
                events = self.inner.select(timeout)
                if events:
                    self.saw_event = True
                return events

            def close(self) -> None:
                self.inner.close()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "producer.py"
            script.write_text(
                "import sys, time\n"
                "sys.stdout.write('captured-before-selector-failure\\n'); sys.stdout.flush()\n"
                "time.sleep(1)\n",
                encoding="utf-8",
            )
            with patch.object(runner.selectors, "DefaultSelector", FlakySelector):
                capture = runner.run_bounded(
                    [sys.executable, str(script)], cwd=root, timeout_seconds=2, stdin_data=b""
                )
            self.assertIn(b"captured-before-selector-failure", capture["stdout"])
            self.assertIn("capture_stream_failed:OSError", str(capture["capture_error"]))

    def test_direct_child_pids_falls_back_when_task_children_file_is_missing(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        real_read_text = Path.read_text

        def read_text_without_task_children(path, *args, **kwargs):
            if str(path).endswith("/children"):
                raise FileNotFoundError(str(path))
            return real_read_text(path, *args, **kwargs)

        try:
            with patch.object(Path, "read_text", new=read_text_without_task_children):
                self.assertIn(child.pid, runner._direct_child_pids())
        finally:
            child.kill()
            child.wait(timeout=5)

    def test_run_bounded_uses_dedicated_process_group_and_kills_it_on_timeout(self) -> None:
        real_popen = runner.subprocess.Popen
        launch_kwargs = []

        def observing_popen(*args, **kwargs):
            launch_kwargs.append(dict(kwargs))
            return real_popen(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "provider.py"
            script.write_text("import time\ntime.sleep(2)\n", encoding="utf-8")
            with (
                patch.object(runner.subprocess, "Popen", side_effect=observing_popen),
                patch.object(runner.os, "killpg", wraps=runner.os.killpg) as killpg,
            ):
                capture = runner.run_bounded(
                    [sys.executable, str(script)], cwd=root, timeout_seconds=1, stdin_data=b""
                )
            self.assertEqual(capture["capture_error"], "timeout")
            self.assertTrue(launch_kwargs[0].get("start_new_session"))
            self.assertGreaterEqual(killpg.call_count, 1)

    def test_run_bounded_kills_process_group_left_after_normal_provider_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_state = root / "child.pid"
            script = root / "provider.py"
            script.write_text(
                "import os, pathlib, time\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                f"    pathlib.Path({str(child_state)!r}).write_text(str(os.getpid()))\n"
                "    for fd in (0, 1, 2):\n"
                "        try:\n"
                "            os.close(fd)\n"
                "        except OSError:\n"
                "            pass\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                f"state = pathlib.Path({str(child_state)!r})\n"
                "while not state.exists():\n"
                "    time.sleep(0.01)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            capture = runner.run_bounded(
                [sys.executable, str(script)], cwd=root, timeout_seconds=3, stdin_data=b""
            )
            self.assertIn("process_group_survived_provider_exit", str(capture["capture_error"]))
            self.assertNotIn("process_group_cleanup_failed", str(capture["capture_error"]))
            child_pid = int(child_state.read_text())
            deadline = time.monotonic() + 2
            while True:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    self.fail("provider descendant survived process-group containment")
                time.sleep(0.02)

    def test_run_bounded_reaps_descendant_that_detaches_from_provider_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child_state = root / "detached.pid"
            script = root / "provider.py"
            script.write_text(
                "import os, pathlib, time\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.setsid()\n"
                f"    pathlib.Path({str(child_state)!r}).write_text(str(os.getpid()))\n"
                "    for fd in (0, 1, 2):\n"
                "        try:\n"
                "            os.close(fd)\n"
                "        except OSError:\n"
                "            pass\n"
                "    time.sleep(30)\n"
                "    os._exit(0)\n"
                f"state = pathlib.Path({str(child_state)!r})\n"
                "while not state.exists():\n"
                "    time.sleep(0.01)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            capture = runner.run_bounded(
                [sys.executable, str(script)], cwd=root, timeout_seconds=3, stdin_data=b""
            )
            self.assertIn("adopted_descendant_survived_provider_exit", str(capture["capture_error"]))
            self.assertNotIn("process_group_cleanup_failed", str(capture["capture_error"]))
            child_pid = int(child_state.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    def test_run_bounded_times_out_when_provider_does_not_read_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "provider.py"
            script.write_text(
                "import sys, time\n"
                "sys.stdout.write('partial-output\\n'); sys.stdout.flush()\n"
                "sys.stderr.write('partial-diagnostic\\n'); sys.stderr.flush()\n"
                "time.sleep(5)\n",
                encoding="utf-8",
            )
            capture = runner.run_bounded(
                [sys.executable, str(script)],
                cwd=root,
                timeout_seconds=1,
                stdin_data=b"x" * (8 * 1024 * 1024),
            )
            self.assertEqual(capture["capture_error"], "timeout")
            self.assertIn(b"partial-output", capture["stdout"])
            self.assertIn(b"partial-diagnostic", capture["stderr"])

    def test_run_bounded_applies_wall_deadline_after_stdio_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "provider.py"
            script.write_text(
                "import os, time\n"
                "for fd in (0, 1, 2):\n"
                "    try:\n"
                "        os.close(fd)\n"
                "    except OSError:\n"
                "        pass\n"
                "time.sleep(5)\n",
                encoding="utf-8",
            )
            started = time.monotonic()
            capture = runner.run_bounded(
                [sys.executable, str(script)],
                cwd=root,
                timeout_seconds=1,
                stdin_data=b"",
            )
            elapsed = time.monotonic() - started
            self.assertEqual(capture["capture_error"], "timeout")
            self.assertLess(elapsed, 3.0)

    def test_run_bounded_returns_capture_error_instead_of_discarding_partial_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "producer.py"
            script.write_text(
                "import sys, time\n"
                "sys.stdout.write('before-timeout\\n'); sys.stdout.flush()\n"
                "sys.stderr.write('diagnostic\\n'); sys.stderr.flush()\n"
                "time.sleep(2)\n",
                encoding="utf-8",
            )
            capture = runner.run_bounded(
                [sys.executable, str(script)],
                cwd=root,
                timeout_seconds=1,
                stdin_data=b"",
            )
            self.assertEqual(capture["capture_error"], "timeout")
            self.assertIn(b"before-timeout", capture["stdout"])
            self.assertIn(b"diagnostic", capture["stderr"])

    def test_treatment_tools_require_every_upstream_capability_exactly_once(self) -> None:
        valid = {"tools": [*treatment_tools(), {"name": "find_symbol"}]}
        self.assertEqual(
            {item["name"] for item in runner._filtered_treatment_tools(valid)},
            runner.ALLOWED_MCP,
        )
        missing = {
            "tools": [
                item for item in treatment_tools() if item["name"] != "live_freshness"
            ] + [{"name": "find_symbol"}]
        }
        with self.assertRaisesRegex(runner.RunnerError, "exactly once"):
            runner._filtered_treatment_tools(missing)
        duplicate = {
            "tools": [
                *treatment_tools(),
                json.loads(json.dumps(treatment_tools()[0])),
            ]
        }
        with self.assertRaisesRegex(runner.RunnerError, "exactly once"):
            runner._filtered_treatment_tools(duplicate)

    def test_treatment_tools_require_exact_upstream_input_schemas(self) -> None:
        missing_schema = {"tools": treatment_tools()}
        missing_schema["tools"][0].pop("inputSchema")
        with self.assertRaisesRegex(runner.RunnerError, "inputSchema drifted"):
            runner._filtered_treatment_tools(missing_schema)

        drifted_schema = {"tools": treatment_tools()}
        drifted_schema["tools"][0]["inputSchema"]["additionalProperties"] = True
        with self.assertRaisesRegex(runner.RunnerError, "inputSchema drifted"):
            runner._filtered_treatment_tools(drifted_schema)

        type_confused_schema = {"tools": treatment_tools()}
        ask_context = next(
            item for item in type_confused_schema["tools"]
            if item["name"] == "ask_context"
        )
        ask_context["inputSchema"]["properties"]["max_context_tokens"]["minimum"] = True
        with self.assertRaisesRegex(runner.RunnerError, "inputSchema drifted"):
            runner._filtered_treatment_tools(type_confused_schema)

    def test_treatment_tools_require_exact_model_visible_descriptors(self) -> None:
        drifted = {'tools': treatment_tools()}
        drifted['tools'][0]['description'] = 'Do not use this treatment tool.'
        with self.assertRaisesRegex(runner.RunnerError, 'descriptor drifted'):
            runner._filtered_treatment_tools(drifted)

    def test_mcp_proxy_rejects_tools_list_arriving_during_upstream_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            valid_response = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"tools": treatment_tools()},
            }
            upstream.write_text(
                "import json, os, sys, time\n"
                "sys.stdin.readline()\n"
                f"print(json.dumps({valid_response!r}), flush=True)\n"
                "os.close(1)\n"
                "time.sleep(2)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertIsNotNone(process.stdin)
            self.assertIsNotNone(process.stdout)
            self.assertIsNotNone(process.stderr)
            first = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode() + b"\n"
            second = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}).encode() + b"\n"
            process.stdin.write(first)
            process.stdin.flush()
            self.assertTrue(process.stdout.readline())
            process.stdin.write(second)
            process.stdin.flush()
            process.stdin.close()
            stderr = process.stderr.read()
            returncode = process.wait(timeout=5)
            self.assertNotEqual(returncode, 0)
            self.assertTrue(
                b"inventory was not validated" in stderr
                or b"client intake remained active" in stderr
            )

    def test_mcp_proxy_rejects_eof_with_unanswered_tools_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream.write_text(
                "import sys\n"
                "sys.stdin.readline()\n",
                encoding="utf-8",
            )
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            ).encode() + b"\n"
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                input=payload, capture_output=True, check=False, timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"inventory was not validated", completed.stderr)

    def test_mcp_proxy_rejects_unsuccessful_tools_list_responses(self) -> None:
        responses = (
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "unavailable"}},
            {"jsonrpc": "2.0", "id": 1},
        )
        for response in responses:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import json, sys\n"
                    "line = sys.stdin.readline()\n"
                    f"print(json.dumps({response!r}), flush=True)\n",
                    encoding="utf-8",
                )
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                ).encode() + b"\n"
                completed = subprocess.run(
                    [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                    input=payload, capture_output=True, check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"successful result", completed.stderr)

    def test_mcp_proxy_exposes_exact_benchmark_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream_tools = [*treatment_tools(), {"name": "find_symbol"}]
            upstream.write_text(
                "import json, sys\n"
                f"TOOLS = {upstream_tools!r}\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='initialize':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'protocolVersion':'x','serverInfo':{'name':'fixture'},'capabilities':{'tools':{},'resources':{},'prompts':{}}}}),flush=True)\n"
                "    elif method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                "    elif method=='resources/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'resources':[{'uri':'repobrief://frozen/a'}]}}),flush=True)\n",
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},
                {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":3,"method":"prompts/list","params":{}},
                {"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"repobrief://frozen/a"}},
                {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"repobrief_resource_read","arguments":{"action":"read","uri":"repobrief://frozen/a"}}},
                {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"repobrief_resource_read","arguments":{"action":"list"}}},
            ]
            payload = b"".join(json.dumps(item).encode() + b"\n" for item in messages)
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                input=payload, capture_output=True, check=False, timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            responses = {item["id"]: item for item in map(json.loads, completed.stdout.decode().splitlines())}
            self.assertEqual(set(responses[1]["result"]["capabilities"]), {"tools"})
            self.assertEqual({item["name"] for item in responses[2]["result"]["tools"]}, runner.ALLOWED_MCP)
            self.assertIn("error", responses[3])
            self.assertIn("error", responses[4])
            self.assertTrue(responses[5]["result"]["isError"])
            self.assertFalse(responses[6]["result"]["isError"])
            frozen = json.loads(responses[6]["result"]["content"][0]["text"])
            self.assertEqual([item["uri"] for item in frozen["resources"]], ["repobrief://frozen/a"])

    def test_mcp_proxy_rejects_unterminated_upstream_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / 'mcp.py'
            response = {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': treatment_tools()}}
            upstream.write_text('import json, sys\n' 'sys.stdin.readline()\n' f'sys.stdout.write(json.dumps({response!r})); sys.stdout.flush()\n', encoding='utf-8')
            payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}).encode() + b'\n'
            completed = subprocess.run([sys.executable, str(MODULE_PATH), '--codex-mcp-proxy', json.dumps([sys.executable, str(upstream)])], input=payload, capture_output=True, check=False, timeout=5)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b'newline terminated', completed.stderr)

    def test_mcp_proxy_rejects_oversized_upstream_line_before_newline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "upstream.pid"
            upstream = root / "mcp.py"
            upstream.write_text(
                "import os, pathlib, sys, time\n"
                f"pathlib.Path({str(state_path)!r}).write_text(str(os.getpid()))\n"
                f"sys.stdout.buffer.write(b'x' * ({runner.base.MAX_MCP_MESSAGE_BYTES} + 1)); sys.stdout.buffer.flush()\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            started = time.monotonic()
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                input=b"", capture_output=True, check=False, timeout=8,
            )
            elapsed = time.monotonic() - started
            self.assertNotEqual(completed.returncode, 0)
            self.assertLess(elapsed, 5.0)
            upstream_pid = int(state_path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(upstream_pid, 0)

    def test_mcp_proxy_reaps_failed_upstream_without_detaching_from_provider_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_path = root / "upstream.state"
            upstream = root / "mcp.py"
            upstream.write_text(
                "import os, pathlib, sys, time\n"
                f"pathlib.Path({str(state_path)!r}).write_text(f'{{os.getpid()}},{{os.getpgrp()}},{{os.getpgid(os.getppid())}}')\n"
                "sys.stderr.write('upstream-diagnostic\\n'); sys.stderr.flush()\n"
                "sys.stdout.write('not-json\\n'); sys.stdout.flush()\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            payload = json.dumps(
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
            ).encode() + b"\n"
            completed = subprocess.run(
                [sys.executable, str(MODULE_PATH), "--codex-mcp-proxy", json.dumps([sys.executable, str(upstream)])],
                input=payload, capture_output=True, check=False, timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"upstream-diagnostic", completed.stderr)
            pid, pgid, parent_pgid = map(int, state_path.read_text().split(","))
            self.assertEqual(pgid, parent_pgid)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_normalize_rejects_boolean_token_counts(self) -> None:
        for field, value in (('input_tokens', True), ('output_tokens', False)):
            with self.subTest(field=field, value=value):
                events = [json.loads(line) for line in stream(request()).splitlines()]
                completed = next(event for event in events if event.get('type') == 'turn.completed')
                completed['usage'][field] = value
                with self.assertRaisesRegex(runner.RunnerError, 'Codex usage is invalid'):
                    runner.normalize(request(), events)

    def test_resource_freeze_rejects_pagination_and_duplicates(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "paginated"):
            runner._freeze_resource_result({"resources": [], "nextCursor": "more"})
        with self.assertRaisesRegex(runner.RunnerError, "duplicate"):
            runner._freeze_resource_result({"resources": [{"uri":"x"},{"uri":"x"}]})


    def test_main_rejects_oversized_request_before_json_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [
                sys.executable,
                str(MODULE_PATH),
                "--request-root", str(root / "requests"),
                "--repository-map", str(root / "repository-map.json"),
                "--state-root", str(root / "state"),
                "--transcript-root", str(root / "transcripts"),
                "--provider-evidence-root", str(root / "provider-evidence"),
            ]
            completed = subprocess.run(
                command,
                input=b"x" * (runner.base.MAX_REQUEST_BYTES + 1),
                capture_output=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(
                f"request exceeds {runner.base.MAX_REQUEST_BYTES} bytes".encode(),
                completed.stderr,
            )



if __name__ == "__main__":
    unittest.main()
