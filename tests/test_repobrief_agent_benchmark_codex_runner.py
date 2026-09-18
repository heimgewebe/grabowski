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
BOOTSTRAP_PATH = ROOT / "tools" / "repobrief_agent_benchmark_source_bootstrap.py"
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


def file_identity(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    metadata = resolved.lstat()
    return {
        "path": str(resolved),
        "bytes": metadata.st_size,
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
        "mode": oct(metadata.st_mode & 0o777),
    }


def runtime_code_identity(path: Path) -> dict:
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    return {
        "name": resolved.name,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def write_dispatch_authorization(
    root: Path, value: dict, mcp_files: list[dict]
) -> Path:
    state_root = root / "state"
    state_root.mkdir(mode=0o700)
    ledger_root = state_root / "preflight-dispatch-ledger"
    ledger_root.mkdir(mode=0o700)
    pair_digest = hashlib.sha256(value["pair_id"].encode("utf-8")).hexdigest()
    pair_root = ledger_root / pair_digest
    pair_root.mkdir(mode=0o700)
    manifest = Path(value["repobrief"]["manifest"])
    baseline = request(
        condition="baseline",
        commit=value["repository"]["commit"],
    )
    report_out = root / "preflight-report.json"
    digest_out = Path(str(report_out) + ".sha256")
    binding = {
        "pair_id": value["pair_id"],
        "requests": {
            "baseline": {
                "request_id": baseline["request_id"],
                "sha256": runner.base._sha256_json(baseline),
            },
            "treatment": {
                "request_id": value["request_id"],
                "sha256": runner.base._sha256_json(value),
            },
        },
        "state_root": str(state_root.resolve()),
        "report_out": str(report_out.resolve()),
        "report_digest_out": str(digest_out.resolve()),
        "manifest": file_identity(manifest),
        "mcp_command_sha256": runner.base._sha256_json(
            value["repobrief"]["mcp_command"]
        ),
        "mcp_command_files": mcp_files,
        "provider": {
            "codex": {
                "path": str(Path(sys.executable).resolve()),
                "bytes": Path(sys.executable).resolve().stat().st_size,
                "sha256": hashlib.sha256(
                    Path(sys.executable).resolve().read_bytes()
                ).hexdigest(),
            },
            "authentication": {
                "mode": "chatgpt_subscription",
                "credential_digest_public": False,
                "credential_bytes": len(b"opaque-chatgpt-auth"),
                "commitment": {
                    "schema_version": 1,
                    "kind": runner.CODEX_CREDENTIAL_COMMITMENT_KIND,
                    "nonce": "ab" * 16,
                    "commitment_sha256": runner._credential_commitment_sha256(
                        b"opaque-chatgpt-auth", "ab" * 16
                    ),
                },
            },
        },
    }
    code_files = []
    for name in runner._AUTHORIZED_RUNTIME_CODE_NAMES:
        code_path = runner._runtime_code_path(name)
        code_raw = code_path.read_bytes()
        code_files.append(
            {
                "name": name,
                "bytes": len(code_raw),
                "sha256": hashlib.sha256(code_raw).hexdigest(),
            }
        )
    binding["code"] = {
        "files": code_files,
        "bundle_sha256": runner.base._sha256_json(code_files),
    }

    authorization = {
        "kind": runner.PREFLIGHT_LEDGER_KIND,
        "version": runner.PREFLIGHT_LEDGER_VERSION,
        "created_at": "2026-09-17T00:00:00Z",
        "contract_sha256": runner.base._sha256_json(binding),
        "binding": binding,
        "retry_permitted": False,
    }
    path = pair_root / "authorization.json"
    report = {
        "kind": runner.PREFLIGHT_AUTHORIZATION_REPORT_KIND,
        "version": "1.0",
        "status": "authorized",
        "pair_id": value["pair_id"],
        "synthetic_fixture": False,
        "dispatch_ledger": {
            "root": str(pair_root),
            "authorization": str(path),
            "authorization_sha256": None,
            "contract_sha256": authorization["contract_sha256"],
            "event_count": 1,
            "final_event_sha256": "f" * 64,
            "condition_intents": [],
            "provider_process_intents": 0,
            "fixture_intents": 0,
            "observed_costs": {},
            "retry_permitted": False,
        },
        "request_sha256": {
            "baseline": runner.base._sha256_json(baseline),
            "treatment": runner.base._sha256_json(value),
        },
        "snapshot": {"status": "fresh"},
        "source_before": {"head": value["repository"]["commit"]},
        "source_after": {"head": value["repository"]["commit"]},
        "timings": {
            "snapshot_preparation_ms": 1,
            "freshness_check_ms": 1,
        },
        "provider": binding["provider"],
        "default_promoted": False,
        "does_not_establish": [],
    }
    authorization["report_evidence_sha256"] = runner.base._sha256_json(
        runner._preflight_report_evidence_projection(report)
    )
    report["dispatch_ledger"]["authorization_sha256"] = (
        runner.base._sha256_json(authorization)
    )

    report_bytes = (
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    report_out.write_bytes(report_bytes)
    report_out.chmod(0o600)
    digest_out.write_text(
        f"{hashlib.sha256(report_bytes).hexdigest()}  {report_out.name}\n",
        encoding="ascii",
    )
    digest_out.chmod(0o600)
    path.write_text(json.dumps(authorization, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return state_root


def bootstrap_program() -> str:
    return BOOTSTRAP_PATH.read_text(encoding="utf-8")


def proxy_command(upstream: Path, root: Path) -> list[str]:
    manifest = root / "bound.bundle.manifest.json"
    if not manifest.exists():
        manifest.write_text("{}\n", encoding="utf-8")
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    authorized = [file_identity(Path(sys.executable)), file_identity(upstream)]
    return [
        sys.executable,
        "-I",
        "-c",
        bootstrap_program(),
        str(MODULE_PATH),
        "--codex-mcp-proxy",
        json.dumps([str(Path(sys.executable).resolve()), str(upstream), "--bundle-root", str(root)]),
        str(manifest),
        digest,
        json.dumps(authorized, sort_keys=True),
    ]


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

    def test_direct_runner_rejects_unbootstrapped_start(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--help"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            b"must be started through the immutable source bootstrap",
            completed.stderr,
        )

    def test_immutable_bootstrap_captures_runner_before_execution(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                bootstrap_program(),
                str(MODULE_PATH),
                "--help",
            ],
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr.decode("utf-8", errors="replace"),
        )
        self.assertIn(b"Run one isolated read-only RepoBrief Codex benchmark request", completed.stdout)

    def test_authorized_runtime_code_must_match_executed_runner_bytes(self) -> None:
        files = []
        for name in runner._AUTHORIZED_RUNTIME_CODE_NAMES:
            path = runner._runtime_code_path(name)
            raw = path.read_bytes()
            files.append(
                {"name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            )
        code = {
            "files": files,
            "bundle_sha256": runner.base._sha256_json(files),
        }
        drifted = dict(runner._SELF_SOURCE_IDENTITY)
        drifted["sha256"] = "0" * 64
        with (
            patch.object(runner, "_SELF_SOURCE_IDENTITY", drifted),
            self.assertRaisesRegex(
                runner.RunnerError, "differs from executed bytes"
            ),
        ):
            runner._validated_authorized_runtime_code(code)

    def test_authorized_runtime_code_must_match_executed_bootstrap_bytes(self) -> None:
        files = []
        for name in runner._AUTHORIZED_RUNTIME_CODE_NAMES:
            path = runner._runtime_code_path(name)
            raw = path.read_bytes()
            files.append(
                {"name": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            )
        code = {
            "files": files,
            "bundle_sha256": runner.base._sha256_json(files),
        }
        raw = BOOTSTRAP_PATH.read_bytes()
        identity = {
            "schema_version": runner.ENTRYPOINT_BOOTSTRAP_SCHEMA_VERSION,
            "kind": runner.ENTRYPOINT_BOOTSTRAP_KIND,
            "name": runner.ENTRYPOINT_BOOTSTRAP_NAME,
            "bytes": len(raw),
            "sha256": "0" * 64,
        }
        with (
            patch.object(runner, "_ENTRYPOINT_BOOTSTRAP_IDENTITY", identity),
            self.assertRaisesRegex(
                runner.RunnerError, "differs from executed bytes"
            ),
        ):
            runner._validated_authorized_runtime_code(code)

    def test_chatgpt_credential_commitment_rejects_same_length_drift(self) -> None:
        nonce = "ab" * 16
        authorized = b"credential-A"
        expected = {
            "mode": "chatgpt_subscription",
            "credential_digest_public": False,
            "credential_bytes": len(authorized),
            "commitment": {
                "schema_version": 1,
                "kind": runner.CODEX_CREDENTIAL_COMMITMENT_KIND,
                "nonce": nonce,
                "commitment_sha256": runner._credential_commitment_sha256(
                    authorized, nonce
                ),
            },
        }
        runner._assert_authorized_chatgpt_auth(authorized, expected)
        with self.assertRaisesRegex(
            runner.RunnerError, "does not match preflight authorization"
        ):
            runner._assert_authorized_chatgpt_auth(b"credential-B", expected)

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

    def test_chatgpt_subscription_status_uses_exact_staged_auth_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "home"
            auth_dir = home / ".codex"
            auth_dir.mkdir(parents=True, mode=0o700)
            auth = auth_dir / "auth.json"
            auth.write_bytes(b"credential-A")
            auth.chmod(0o600)
            observed: dict[str, bytes | str] = {}

            def status(argv, **kwargs):
                environment = kwargs["env"]
                snapshot_home = Path(environment["CODEX_HOME"])
                observed["home"] = str(snapshot_home)
                observed["bytes"] = (snapshot_home / "auth.json").read_bytes()
                # Mutate the original only after the snapshot exists.  The status
                # probe and returned runtime bytes must remain credential-A.
                auth.write_bytes(b"credential-B")
                return subprocess.CompletedProcess(
                    argv, 0, stdout=b"Logged in using ChatGPT\n", stderr=b""
                )

            with (
                patch.dict(os.environ, {"HOME": str(home)}, clear=True),
                patch.object(runner, "validate_toolchain", return_value="/usr/bin:/bin"),
                patch.object(runner.subprocess, "run", side_effect=status),
            ):
                returned = runner.validate_chatgpt_subscription("/opt/codex")

            self.assertEqual(observed["bytes"], b"credential-A")
            self.assertEqual(returned, b"credential-A")
            self.assertEqual(auth.read_bytes(), b"credential-B")

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
                request(condition="treatment"), "/opt/codex", checkout, schema, codex_home,
                authorized_mcp_files=[
                    {"path": "/usr/bin/python3", "bytes": 1, "sha256": "0" * 64, "mode": "0o755"}
                ],
                proxy_path=(root / "bound-proxy.py").resolve(),
                manifest_path=(root / "bound.bundle.manifest.json").resolve(),
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

    def test_live_baseline_requires_dispatch_authorization_before_codex_status_or_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, commit = repository(root)
            value = request(commit=commit)
            planned_request_root(root, value)
            repository_map(root, source)
            args = Namespace(
                request_root=root / "requests",
                repository_map=root / "repositories.json",
                state_root=root / "state",
                transcript_root=root / "transcripts",
                provider_evidence_root=root / "provider-evidence",
                codex_command="/opt/codex",
                codex_command_sha256="1" * 64,
                allow_live_provider=True,
                stream_fixture=None,
                stderr_fixture=None,
                fixture_returncode=0,
            )
            with (
                patch.object(runner, "validate_executable", return_value="/opt/codex"),
                patch.object(runner, "validate_toolchain") as toolchain,
                patch.object(runner, "validate_chatgpt_subscription") as login_status,
                patch.object(runner, "run_bounded") as provider_launch,
                self.assertRaisesRegex(runner.RunnerError, "preflight dispatch ledger"),
            ):
                runner.execute(value, args)
            toolchain.assert_not_called()
            login_status.assert_not_called()
            provider_launch.assert_not_called()

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
                proxy_command(upstream, root),
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
                proxy_command(upstream, root),
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
                    proxy_command(upstream, root),
                    input=payload, capture_output=True, check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertTrue(
                    b"successful result" in completed.stderr
                    or b"response envelope is invalid" in completed.stderr
                )

    def test_mcp_proxy_coalesces_pipelined_resource_lists_to_first_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            count_path = root / "resource-list-count.txt"
            upstream = root / "mcp.py"
            upstream.write_text(
                "import json, pathlib, sys\n"
                f"COUNT = pathlib.Path({str(count_path)!r})\n"
                f"TOOLS = {treatment_tools()!r}\n"
                "resource_lists = 0\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                "    elif method=='resources/list':\n"
                "        resource_lists += 1\n"
                "        uri = 'repobrief://first' if resource_lists == 1 else 'repobrief://second'\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'resources':[{'uri':uri}]}}),flush=True)\n"
                "COUNT.write_text(str(resource_lists))\n",
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"repobrief_resource_read","arguments":{"action":"list"}}},
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"repobrief_resource_read","arguments":{"action":"list"}}},
            ]
            completed = subprocess.run(
                proxy_command(upstream, root),
                input=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
                capture_output=True, check=False, timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            responses = {item["id"]: item for item in map(json.loads, completed.stdout.decode().splitlines())}
            first = responses[2]["result"]["content"][0]["text"]
            second = responses[3]["result"]["content"][0]["text"]
            self.assertEqual(first, second)
            self.assertEqual(
                [item["uri"] for item in json.loads(first)["resources"]],
                ["repobrief://first"],
            )
            self.assertEqual(count_path.read_text(), "1")

    def test_mcp_proxy_rejects_malformed_resource_read_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream.write_text(
                "import json, sys\n"
                f"TOOLS = {treatment_tools()!r}\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                "    elif method=='resources/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'resources':[{'uri':'repobrief://frozen/a'}]}}),flush=True)\n"
                "    elif method=='resources/read':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':None}),flush=True)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                proxy_command(upstream, root),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertIsNotNone(process.stdin)
            self.assertIsNotNone(process.stdout)
            self.assertIsNotNone(process.stderr)

            def roundtrip(message: dict) -> dict:
                assert process.stdin is not None and process.stdout is not None
                process.stdin.write(json.dumps(message).encode() + b"\n")
                process.stdin.flush()
                return json.loads(process.stdout.readline())

            tools = roundtrip(
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
            )
            self.assertIn("result", tools)
            listed = roundtrip(
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                    "name":"repobrief_resource_read",
                    "arguments":{"action":"list"},
                }}
            )
            self.assertFalse(listed["result"]["isError"])
            process.stdin.write(json.dumps(
                {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                    "name":"repobrief_resource_read",
                    "arguments":{"action":"read","uri":"repobrief://frozen/a"},
                }}
            ).encode() + b"\n")
            process.stdin.flush()
            process.stdin.close()
            stderr = process.stderr.read()
            returncode = process.wait(timeout=5)
            self.assertNotEqual(returncode, 0)
            self.assertIn(b"resource read result is malformed", stderr)

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
                proxy_command(upstream, root),
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
            completed = subprocess.run(proxy_command(upstream, root), input=payload, capture_output=True, check=False, timeout=5)
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
                proxy_command(upstream, root),
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
                proxy_command(upstream, root),
                input=payload, capture_output=True, check=False, timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"upstream-diagnostic", completed.stderr)
            pid, pgid, parent_pgid = map(int, state_path.read_text().split(","))
            self.assertEqual(pgid, parent_pgid)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_mcp_upstream_is_bound_and_manifest_root_is_forced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "python3"
            executable.write_bytes(Path(sys.executable).read_bytes())
            executable.chmod(0o755)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            sibling = root / "sibling.bundle.manifest.json"
            sibling.write_text("{}\n", encoding="utf-8")
            authorized = [file_identity(executable), file_identity(script)]
            argv, bindings = runner._bind_mcp_upstream(
                [str(executable), str(script), "--bundle-root", str(root)],
                manifest,
                authorized,
            )
            self.assertEqual(argv[-1], str(manifest))
            self.assertEqual([item["path"] for item in bindings], [executable, script])

            message = {
                "params": {"arguments": {"query": "where", "bundle_manifest": None}}
            }
            runner._pin_treatment_arguments(message, manifest)
            arguments = message["params"]["arguments"]
            self.assertEqual(arguments["bundle_manifest"], str(manifest))
            self.assertIsNone(arguments["repo"])
            self.assertIsNone(arguments["stem"])
            for selector, value in (
                ("bundle_manifest", str(sibling)), ("repo", "other/repo"), ("stem", "other")
            ):
                conflicting = {"params": {"arguments": {selector: value}}}
                with self.subTest(selector=selector), self.assertRaises(runner.RunnerError):
                    runner._pin_treatment_arguments(conflicting, manifest)

    def test_mcp_absolute_interpreter_symlink_resolves_to_bound_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "python3.real"
            executable.write_bytes(Path(sys.executable).read_bytes())
            executable.chmod(0o755)
            alias = root / "python3"
            alias.symlink_to(executable)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")

            authorized = [file_identity(executable), file_identity(script)]
            argv, bindings = runner._bind_mcp_upstream(
                [str(alias), str(script), "--bundle-root", str(root)],
                manifest,
                authorized,
            )

            self.assertEqual(argv[0], str(executable.resolve()))
            self.assertEqual(bindings[0]["path"], executable.resolve())
            runner._revalidate_mcp_file(bindings[0], label="MCP executable")

    def test_preflight_mcp_authorization_binds_exact_program_files_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "python3"
            executable.write_bytes(Path(sys.executable).read_bytes())
            executable.chmod(0o755)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            value = request(condition="treatment")
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = hashlib.sha256(
                manifest.read_bytes()
            ).hexdigest()
            value["repobrief"]["mcp_command"] = [
                str(executable), str(script), "--bundle-root", str(root)
            ]
            authorized = [file_identity(executable), file_identity(script)]
            state_root = write_dispatch_authorization(root, value, authorized)
            loaded = runner._load_preflight_mcp_authorization(value, state_root)
            self.assertEqual(loaded, authorized)
            argv, _bindings = runner._bind_mcp_upstream(
                value["repobrief"]["mcp_command"], manifest, loaded
            )
            self.assertEqual(argv[0], str(executable.resolve()))
            script.write_text("# drift after authorization\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.RunnerError, "preflight-authorized"):
                runner._bind_mcp_upstream(
                    value["repobrief"]["mcp_command"], manifest, loaded
                )

    def test_preflight_mcp_authorization_rejects_request_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            value = request(condition="treatment")
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = hashlib.sha256(
                manifest.read_bytes()
            ).hexdigest()
            value["repobrief"]["mcp_command"] = [
                str(Path(sys.executable).resolve()), str(script), "--bundle-root", str(root)
            ]
            authorized = [file_identity(Path(sys.executable)), file_identity(script)]
            state_root = write_dispatch_authorization(root, value, authorized)
            value["prompt"] = "drifted after authorization"
            with self.assertRaisesRegex(runner.RunnerError, "treatment request"):
                runner._load_preflight_mcp_authorization(value, state_root)

    def test_mcp_proxy_rejects_invalid_client_jsonrpc_versions(self) -> None:
        cases = (
            {"id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "1.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": 2, "id": 1, "method": "tools/list", "params": {}},
        )
        for message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                upstream.write_text("import sys\nsys.stdin.read()\n", encoding="utf-8")
                completed = subprocess.run(
                    proxy_command(upstream, root),
                    input=json.dumps(message).encode() + b"\n",
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"proxy stream failed", completed.stderr)

    def test_mcp_proxy_rejects_missing_treatment_request_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream.write_text("import sys\nsys.stdin.read()\n", encoding="utf-8")
            payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "ask_context", "arguments": {"query": "where"}},
                }
            ).encode() + b"\n"
            completed = subprocess.run(
                proxy_command(upstream, root), input=payload,
                capture_output=True, check=False, timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"proxy stream failed", completed.stderr)

    def test_mcp_proxy_rejects_malformed_error_responses(self) -> None:
        errors = (
            None,
            {},
            {"code": True, "message": "failed"},
            {"code": -32000, "message": 1},
        )
        for error in errors:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import json, sys\n"
                    "sys.stdin.readline()\n"
                    f"print(json.dumps({{'jsonrpc':'2.0','id':2,'error':{error!r}}}), flush=True)\n",
                    encoding="utf-8",
                )
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}
                ).encode() + b"\n"
                completed = subprocess.run(
                    proxy_command(upstream, root), input=payload,
                    capture_output=True, check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"error response is invalid", completed.stderr)

    def test_mcp_proxy_rejects_type_alias_response_ids(self) -> None:
        for invalid_identifier in (True, 1.0, None, {"nested": "id"}):
            with self.subTest(identifier=invalid_identifier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                encoded = json.dumps(invalid_identifier)
                upstream.write_text(
                    "import json, sys\n"
                    f"INVALID = json.loads({encoded!r})\n"
                    "sys.stdin.readline()\n"
                    "print(json.dumps({'jsonrpc':'2.0','id':INVALID,'result':{}}), flush=True)\n",
                    encoding="utf-8",
                )
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
                ).encode() + b"\n"
                completed = subprocess.run(
                    proxy_command(upstream, root), input=payload,
                    capture_output=True, check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"response envelope is invalid", completed.stderr)

    def test_mcp_program_and_script_bindings_reject_symlinks_and_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "tool"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            for target, label, executable_flag in (
                (executable, "MCP executable", True), (script, "MCP script", False)
            ):
                link = root / (target.name + ".link")
                link.symlink_to(target)
                with self.subTest(label=label), self.assertRaises(runner.RunnerError):
                    runner._bind_mcp_file(link, label=label, executable=executable_flag)
                binding = runner._bind_mcp_file(
                    target, label=label, executable=executable_flag
                )
                target.write_bytes(target.read_bytes() + b"# drift\n")
                with self.assertRaisesRegex(runner.RunnerError, "changed during execution"):
                    runner._revalidate_mcp_file(binding, label=label)

    def test_mcp_proxy_rejects_malformed_or_unknown_response_envelopes(self) -> None:
        cases = (
            {"id": 1, "result": {"tools": treatment_tools()}},
            {"jsonrpc": "1.0", "id": 1, "result": {"tools": treatment_tools()}},
            {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
            {"jsonrpc": "2.0", "id": 1},
            {"jsonrpc": "2.0", "id": 999, "result": {"tools": treatment_tools()}},
        )
        for response in cases:
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import json, sys\n"
                    "sys.stdin.readline()\n"
                    f"print(json.dumps({response!r}), flush=True)\n",
                    encoding="utf-8",
                )
                payload = json.dumps(
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                ).encode() + b"\n"
                completed = subprocess.run(
                    proxy_command(upstream, root), input=payload, capture_output=True,
                    check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"response envelope is invalid", completed.stderr)

    def test_mcp_proxy_rejects_explicit_null_treatment_request_id(self) -> None:
        for invalid in (
            None, True, False, [], {}, 1.5,
            float("inf"), float("-inf"), float("nan"),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(runner._valid_jsonrpc_request_id(invalid))
        for valid in ("", "request-1", 0, -1):
            with self.subTest(valid=valid):
                self.assertTrue(runner._valid_jsonrpc_request_id(valid))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream.write_text(
                "import json, sys\n"
                f"TOOLS = {treatment_tools()!r}\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n",
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":None,"method":"tools/call","params":{"name":"ask_context","arguments":{"query":"where"}}},
            ]
            completed = subprocess.run(
                proxy_command(upstream, root),
                input=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
                capture_output=True,
                check=False,
                timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_mcp_proxy_rejects_malformed_treatment_tool_result_before_forwarding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "mcp.py"
            upstream.write_text(
                "import json, sys\n"
                f"TOOLS = {treatment_tools()!r}\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                "    elif method=='tools/call':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':None}),flush=True)\n",
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask_context","arguments":{"query":"where"}}},
            ]
            completed = subprocess.run(
                proxy_command(upstream, root),
                input=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
                capture_output=True, check=False, timeout=5,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"treatment tool result is malformed", completed.stderr)
            responses = [json.loads(line) for line in completed.stdout.decode().splitlines()]
            self.assertNotIn(2, {item.get("id") for item in responses})

    def test_mcp_proxy_rejects_tool_specific_treatment_payload_drift(self) -> None:
        cases = (
            ("ask_context", {"query": "where"}),
            ("grounding_verify", {"declaration": {}}),
            ("live_freshness", {}),
        )
        for tool_name, arguments in cases:
            with self.subTest(tool=tool_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import json, sys\n"
                    f"TOOLS = {treatment_tools()!r}\n"
                    "for line in sys.stdin:\n"
                    "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                    "    if method=='tools/list':\n"
                    "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                    "    elif method=='tools/call':\n"
                    "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'content':[{'type':'text','text':'ok'}],'structuredContent':{},'isError':False}}),flush=True)\n",
                    encoding="utf-8",
                )
                messages = [
                    {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                    {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool_name,"arguments":arguments}},
                ]
                completed = subprocess.run(
                    proxy_command(upstream, root),
                    input=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
                    capture_output=True, check=False, timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"is malformed", completed.stderr)
                responses = [json.loads(line) for line in completed.stdout.decode().splitlines()]
                self.assertNotIn(2, {item.get("id") for item in responses})

    def test_treatment_result_accepts_pinned_tool_specific_payloads(self) -> None:
        manifest = Path("/frozen/repo.bundle.manifest.json")
        freshness = {
            "kind": "repobrief.live_freshness",
            "version": "v1",
            "status": "not_comparable",
            "reason": "repo_root_not_configured",
            "bundle_manifest": str(manifest),
            "repo_root": None,
            "read_only_git_probe": False,
            "implicit_refresh": False,
            "does_not_establish": list(runner.EXPECTED_REPOGROUND_FRESHNESS_DOES_NOT_ESTABLISH),
        }
        context_pack = {
            "kind": runner.EXPECTED_ASK_CONTEXT_PACK_KIND,
            "version": runner.EXPECTED_ASK_CONTEXT_PACK_VERSION,
            "request_id": "0123456789abcdef",
            "snapshot_ref": {},
            "freshness": {"status": "fresh"},
            "availability": {"status": "available"},
            "required_reading": {"status": "available"},
            "retrieval": {},
            "retrieval_infrastructure": {"status": "available"},
            "retrieval_hits": [],
            "resolved_ranges": [],
            "answer_scaffold": {
                "citation_obligations": [],
                "caveats_to_surface": [],
                "non_claims_to_surface": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
            },
            "budget": {
                "max_context_tokens": 1,
                "token_derived_byte_ceiling": 4,
                "max_context_bytes": 4,
                "max_answer_tokens": 1,
                "context_bytes_used": 0,
                "context_unicode_characters_used": 0,
                "approx_context_chars_used": 0,
                "byte_budget_is_hard": True,
                "unit": "utf8_bytes",
                "accounting": "pinned test contract",
                "omissions": [],
                "truncated": False,
                "does_not_establish_quality": True,
            },
            "forbidden_operations": list(runner.EXPECTED_ASK_CONTEXT_FORBIDDEN_OPERATIONS),
            "does_not_establish": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
        }
        verdict = {
            "kind": runner.EXPECTED_GROUNDING_VERDICT_KIND,
            "version": runner.EXPECTED_GROUNDING_VERDICT_VERSION,
            "status": "degraded",
            "checked_declaration": {},
            "snapshot_ref": {},
            "citation_checks": [],
            "range_checks": [],
            "required_reading_checks": [],
            "diagnostics": [],
            "freshness_caveats": [],
            "availability_caveats": [],
            "does_not_establish": list(runner.EXPECTED_REPOGROUND_EVIDENCE_DOES_NOT_ESTABLISH),
        }
        projection = {
            "mutation_boundary": {
                "ref": "repobrief.mutation_boundary.read_only_frontdoor.v1",
                "writes": [],
                "read_only": True,
                "read_paths_do_not_refresh": True,
                "not_reachable_from_snapshot_create": True,
                "forbidden_operations": ["secret_read", "snapshot_create_side_effect"],
            },
            "does_not_establish": {
                "ref": "repobrief.does_not_establish.default.v1",
                "items": list(runner.EXPECTED_REPOGROUND_FRONTDOOR_DOES_NOT_ESTABLISH),
            },
        }
        cases = {
            "ask_context": {
                "kind": runner.EXPECTED_REPOGROUND_READ_ONLY_KIND,
                "version": runner.EXPECTED_REPOGROUND_READ_ONLY_VERSION,
                "tool": "ask_context",
                "status": "ok",
                "context_pack": context_pack,
                "request_semantics": "repobrief.ask_request.v1",
                "context_pack_semantics": "repobrief.ask_context_pack.v1",
                **projection,
                "live_freshness": freshness,
            },
            "grounding_verify": {
                "kind": runner.EXPECTED_REPOGROUND_READ_ONLY_KIND,
                "version": runner.EXPECTED_REPOGROUND_READ_ONLY_VERSION,
                "tool": "grounding_verify",
                "status": "degraded",
                "verdict": verdict,
                "declaration_semantics": "repobrief.answer_grounding_declaration.v1",
                "verdict_semantics": "repobrief.answer_grounding_verdict.v1",
                **projection,
                "live_freshness": freshness,
            },
            "live_freshness": freshness,
        }
        for tool_name, payload in cases.items():
            with self.subTest(tool=tool_name):
                result = {
                    "content": [{"type": "text", "text": "ok"}],
                    "structuredContent": payload,
                    "isError": False,
                }
                validated = runner._validated_treatment_tool_result(
                    result, tool_name=tool_name, expected_manifest=manifest
                )
                self.assertEqual(validated["structuredContent"], payload)
                self.assertEqual(
                    validated["content"],
                    [{"type": "text", "text": runner.canonical(payload)}],
                )

        nested_drifts = {
            "ask_context": "context_pack",
            "grounding_verify": "verdict",
        }
        for tool_name, field in nested_drifts.items():
            with self.subTest(tool=tool_name, drift=field):
                payload = json.loads(json.dumps(cases[tool_name]))
                payload[field] = {}
                with self.assertRaises(runner.RunnerError):
                    runner._validated_treatment_tool_result(
                        {
                            "content": [{"type": "text", "text": "ok"}],
                            "structuredContent": payload,
                            "isError": False,
                        },
                        tool_name=tool_name,
                        expected_manifest=manifest,
                    )

        error = {
            "content": [{"type": "text", "text": "error"}],
            "structuredContent": {
                "status": "error", "tool": "ask_context", "error": "boom"
            },
            "isError": True,
        }
        validated_error = runner._validated_treatment_tool_result(
            error, tool_name="ask_context", expected_manifest=manifest
        )
        self.assertEqual(
            validated_error["structuredContent"],
            error["structuredContent"],
        )
        self.assertEqual(
            validated_error["content"],
            [{"type": "text", "text": runner.canonical(error["structuredContent"])}],
        )

    def test_mcp_proxy_tracks_and_forwards_treatment_tool_responses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seen = root / "seen.json"
            upstream = root / "mcp.py"
            upstream.write_text(
                "import json, pathlib, sys\n"
                f"SEEN = pathlib.Path({str(seen)!r})\n"
                f"TOOLS = {treatment_tools()!r}\n"
                "for line in sys.stdin:\n"
                "    m=json.loads(line); method=m.get('method'); ident=m.get('id')\n"
                "    if method=='tools/list':\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'tools':TOOLS}}),flush=True)\n"
                "    elif method=='tools/call':\n"
                "        args=m.get('params',{}).get('arguments',{})\n"
                "        SEEN.write_text(json.dumps(args, sort_keys=True))\n"
                "        fresh={'kind':'repobrief.live_freshness','version':'v1','status':'not_comparable','reason':'repo_root_not_configured','bundle_manifest':args.get('bundle_manifest'),'repo_root':None,'read_only_git_probe':False,'implicit_refresh':False,'does_not_establish':['freshness_against_remote','remote_branch_state','pull_request_diff_current','runtime_correctness','repo_understood','merge_readiness']}\n"
                "        pack={'kind':'repobrief.ask_context_pack','version':'1.0','request_id':'0123456789abcdef','snapshot_ref':{},'freshness':{'status':'fresh'},'availability':{'status':'available'},'required_reading':{'status':'available'},'retrieval':{},'retrieval_infrastructure':{'status':'available'},'retrieval_hits':[],'resolved_ranges':[],'answer_scaffold':{'citation_obligations':[],'caveats_to_surface':[],'non_claims_to_surface':['actual_reading_proven','answer_correct','repo_understood','all_relevant_context_used','claims_true','test_sufficiency','regression_absence','runtime_behavior','forensic_ready','merge_readiness','security_correctness']},'budget':{'max_context_tokens':1,'token_derived_byte_ceiling':4,'max_context_bytes':4,'max_answer_tokens':1,'context_bytes_used':0,'context_unicode_characters_used':0,'approx_context_chars_used':0,'byte_budget_is_hard':True,'unit':'utf8_bytes','accounting':'pinned test contract','omissions':[],'truncated':False,'does_not_establish_quality':True},'forbidden_operations':['implicit_refresh','git_mutation','snapshot_creation_on_read','patch_application','pull_request_mutation','shell_execution','merge_authorization'],'does_not_establish':['actual_reading_proven','answer_correct','repo_understood','all_relevant_context_used','claims_true','test_sufficiency','regression_absence','runtime_behavior','forensic_ready','merge_readiness','security_correctness']}\n"
                "        boundary={'ref':'repobrief.mutation_boundary.read_only_frontdoor.v1','writes':[],'read_only':True,'read_paths_do_not_refresh':True,'not_reachable_from_snapshot_create':True,'forbidden_operations':['secret_read','snapshot_create_side_effect']}\n"
                "        nonclaims={'ref':'repobrief.does_not_establish.default.v1','items':['truth','correctness','completeness','runtime_behavior','test_sufficiency','regression_absence','repo_understood','claims_true','forensic_ready','review_complete','pr_mergeable','mcp_server_available']}\n"
                "        payload={'kind':'repobrief.mcp.read_only_frontdoor','version':'v1','tool':'ask_context','status':'ok','context_pack':pack,'request_semantics':'repobrief.ask_request.v1','context_pack_semantics':'repobrief.ask_context_pack.v1','mutation_boundary':boundary,'does_not_establish':nonclaims,'live_freshness':fresh}\n"
                "        print(json.dumps({'jsonrpc':'2.0','id':ident,'result':{'content':[{'type':'text','text':'ok'}],'structuredContent':payload,'isError':False}}),flush=True)\n",
                encoding="utf-8",
            )
            messages = [
                {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
                {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ask_context","arguments":{"query":"where"}}},
            ]
            completed = subprocess.run(
                proxy_command(upstream, root),
                input=b"".join(json.dumps(item).encode() + b"\n" for item in messages),
                capture_output=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            responses = {item["id"]: item for item in map(json.loads, completed.stdout.decode().splitlines())}
            self.assertEqual(
                responses[2]["result"]["content"][0]["text"],
                runner.canonical(responses[2]["result"]["structuredContent"]),
            )
            self.assertNotEqual(responses[2]["result"]["content"][0]["text"], "ok")
            arguments = json.loads(seen.read_text(encoding="utf-8"))
            self.assertEqual(arguments["bundle_manifest"], str(root / "bound.bundle.manifest.json"))
            self.assertIsNone(arguments["repo"])
            self.assertIsNone(arguments["stem"])

    def test_normalize_rejects_boolean_token_counts(self) -> None:
        for field, value in (('input_tokens', True), ('output_tokens', False)):
            with self.subTest(field=field, value=value):
                events = [json.loads(line) for line in stream(request()).splitlines()]
                completed = next(event for event in events if event.get('type') == 'turn.completed')
                completed['usage'][field] = value
                with self.assertRaisesRegex(runner.RunnerError, 'Codex usage is invalid'):
                    runner.normalize(request(), events)

    def test_normalize_requires_repobrief_call_for_treatment(self) -> None:
        value = request(condition="treatment")
        events = [json.loads(line) for line in stream(value).splitlines()]
        with self.assertRaisesRegex(
            runner.RunnerError, "treatment used no successful RepoBrief tool or resource"
        ):
            runner.normalize(value, events)

    def test_normalize_accepts_repobrief_call_for_treatment(self) -> None:
        value = request(condition="treatment")
        events = [json.loads(line) for line in stream(value).splitlines()]
        command_event = next(
            event
            for event in events
            if event.get("type") == "item.completed"
            and isinstance(event.get("item"), dict)
            and event["item"].get("type") == "command_execution"
        )
        command_event["item"] = {
            "type": "mcp_tool_call",
            "server": "repobrief",
            "tool": "live_freshness",
            "arguments": {"bundle_manifest": "/bundles/repo.bundle.manifest.json"},
            "result": {"isError": False, "status": "ok"},
            "status": "completed",
        }

        _input_tokens, _output_tokens, calls, normalized_answer = runner.normalize(
            value, events
        )

        self.assertEqual([call["name"] for call in calls], ["live_freshness"])
        self.assertEqual(calls[0]["status"], "success")
        self.assertEqual(normalized_answer, answer())

    def test_normalize_rejects_iserror_only_treatment_call(self) -> None:
        value = request(condition="treatment")
        events = [json.loads(line) for line in stream(value).splitlines()]
        command_event = next(
            event
            for event in events
            if event.get("type") == "item.completed"
            and isinstance(event.get("item"), dict)
            and event["item"].get("type") == "command_execution"
        )
        command_event["item"] = {
            "type": "mcp_tool_call",
            "server": "repobrief",
            "tool": "live_freshness",
            "arguments": {"bundle_manifest": "/bundles/repo.bundle.manifest.json"},
            "result": {
                "content": [{"type": "text", "text": "failed"}],
                "structuredContent": {"status": "error"},
                "isError": True,
            },
            "status": "completed",
        }

        with self.assertRaisesRegex(
            runner.RunnerError,
            "treatment used no successful RepoBrief tool or resource",
        ):
            runner.normalize(value, events)

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
                "-I",
                "-c",
                bootstrap_program(),
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


    def test_staged_proxy_survives_later_source_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"; state_root.mkdir(mode=0o700)
            source = root / MODULE_PATH.name; source.write_bytes(MODULE_PATH.read_bytes())
            expected = {"name": source.name, "bytes": source.stat().st_size, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            with patch.object(runner, "__file__", str(source)):
                binding = runner.stage_mcp_proxy(
                    state_root, expected, runtime_code_identity(runner.BASE_PATH)
                )
            staged = Path(binding["path"]); original = staged.read_bytes()
            source.write_text("# replaced source\n", encoding="utf-8")
            self.assertEqual(staged.read_bytes(), original)
            runner._revalidate_staged_mcp_proxy(binding)
            self.assertIsNone(runner.cleanup_staged_mcp_proxy(binding))
            self.assertFalse(staged.exists())

    def test_staged_proxy_contains_authorized_base_and_starts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"
            state_root.mkdir(mode=0o700)
            binding = runner.stage_mcp_proxy(
                state_root,
                runtime_code_identity(MODULE_PATH),
                runtime_code_identity(runner.BASE_PATH),
            )
            staged = Path(binding["path"])
            self.assertEqual(staged.name, MODULE_PATH.name)
            self.assertTrue(staged.with_name(runner.BASE_PATH.name).is_file())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    bootstrap_program(),
                    str(staged),
                    "--help",
                ],
                capture_output=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf-8", errors="replace"),
            )
            self.assertFalse((staged.parent / "__pycache__").exists())
            self.assertIsNone(runner.cleanup_staged_mcp_proxy(binding))
            self.assertFalse(staged.parent.exists())

    def test_staged_proxy_mutation_fails_closed_and_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"; state_root.mkdir(mode=0o700)
            source = root / MODULE_PATH.name; source.write_bytes(MODULE_PATH.read_bytes())
            expected = {"name": source.name, "bytes": source.stat().st_size, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            with patch.object(runner, "__file__", str(source)):
                binding = runner.stage_mcp_proxy(
                    state_root, expected, runtime_code_identity(runner.BASE_PATH)
                )
            staged = Path(binding["path"]); staged.write_text("# mutated stage\n", encoding="utf-8")
            with self.assertRaisesRegex(runner.RunnerError, "proxy stage changed during execution"):
                runner._revalidate_staged_mcp_proxy(binding)
            self.assertEqual(runner.cleanup_staged_mcp_proxy(binding), "RunnerError")
            self.assertTrue(staged.exists())

    def test_treatment_command_references_only_bound_proxy_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"; state_root.mkdir(mode=0o700)
            source = root / MODULE_PATH.name; source.write_bytes(MODULE_PATH.read_bytes())
            expected = {"name": source.name, "bytes": source.stat().st_size, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}
            with patch.object(runner, "__file__", str(source)):
                binding = runner.stage_mcp_proxy(
                    state_root, expected, runtime_code_identity(runner.BASE_PATH)
                )
            source.write_text("# replaced after staging\n", encoding="utf-8")
            checkout = root / "repo"; checkout.mkdir()
            schema = root / "schema.json"
            codex_home = root / "codex-home"; (codex_home / "tmp").mkdir(parents=True)
            staged_manifest = root / "staged.bundle.manifest.json"
            staged_manifest.write_text("{}\n", encoding="utf-8")
            command = runner.build_command(
                request(condition="treatment"), "/opt/codex", checkout, schema, codex_home,
                authorized_mcp_files=[], proxy_path=Path(binding["path"]),
                manifest_path=staged_manifest.resolve(),
            )
            encoded = next(item for item in command if item.startswith("mcp_servers.repobrief.args="))
            proxy_args = json.loads(encoded.split("=", 1)[1])
            self.assertEqual(proxy_args[:2], ["-I", "-c"])
            self.assertEqual(proxy_args[2], bootstrap_program())
            self.assertEqual(proxy_args[3], str(binding["path"]))
            self.assertNotIn(str(source), encoded)
            self.assertIsNone(runner.cleanup_staged_mcp_proxy(binding))

    def test_staged_proxy_cleanup_rejects_unexpected_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"
            state_root.mkdir(mode=0o700)
            binding = runner.stage_mcp_proxy(
                state_root,
                runtime_code_identity(MODULE_PATH),
                runtime_code_identity(runner.BASE_PATH),
            )
            unexpected = Path(binding["runtime_dir"]) / "unexpected.txt"
            unexpected.write_text("unexpected\n", encoding="utf-8")
            self.assertEqual(runner.cleanup_staged_mcp_proxy(binding), "RunnerError")
            self.assertTrue(unexpected.exists())


    def test_codex_executable_must_match_preflight_provider_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authorized = root / "codex-a"
            launched = root / "codex-b"
            authorized.write_bytes(b"authorized-codex")
            launched.write_bytes(b"different-codex!")
            authorized.chmod(0o755); launched.chmod(0o755)
            expected_identity = {
                "path": str(authorized.resolve()),
                "bytes": authorized.stat().st_size,
                "sha256": hashlib.sha256(authorized.read_bytes()).hexdigest(),
            }
            with self.assertRaisesRegex(
                runner.RunnerError, "does not match preflight authorization"
            ):
                runner._assert_authorized_codex_executable(
                    str(launched.resolve()),
                    hashlib.sha256(launched.read_bytes()).hexdigest(),
                    expected_identity,
                )

    def test_authorized_runtime_code_rejects_base_runner_drift(self) -> None:
        code_files = []
        original_paths = {}
        for name in runner._AUTHORIZED_RUNTIME_CODE_NAMES:
            path = runner._runtime_code_path(name)
            original_paths[name] = path
            data = path.read_bytes()
            code_files.append({
                "name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()
            })
        code = {"files": code_files, "bundle_sha256": runner.base._sha256_json(code_files)}
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "repobrief_agent_benchmark_runner.py"
            replacement.write_bytes(original_paths[replacement.name].read_bytes() + b"\n# drift\n")
            def runtime_path(name: str) -> Path:
                return replacement if name == replacement.name else original_paths[name]
            with patch.object(runner, "_runtime_code_path", side_effect=runtime_path):
                with self.assertRaisesRegex(runner.RunnerError, "runtime code changed after preflight"):
                    runner._validated_authorized_runtime_code(code)

    def test_staged_manifest_survives_original_replacement_and_binds_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"; state_root.mkdir(mode=0o700)
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text('{"version": 1}\n', encoding="utf-8")
            expected = file_identity(manifest)
            binding = runner.stage_repoground_manifest(state_root, expected)
            staged = Path(binding["path"]); staged_bytes = staged.read_bytes()
            manifest.write_text('{"version": 2}\n', encoding="utf-8")
            self.assertEqual(staged.read_bytes(), staged_bytes)
            checkout = root / "repo"; checkout.mkdir()
            schema = root / "schema.json"
            codex_home = root / "codex-home"; (codex_home / "tmp").mkdir(parents=True)
            command = runner.build_command(
                request(condition="treatment"), "/opt/codex", checkout, schema, codex_home,
                authorized_mcp_files=[], proxy_path=(root / "bound-proxy.py").resolve(),
                manifest_path=staged.resolve(),
            )
            encoded = next(item for item in command if item.startswith("mcp_servers.repobrief.args="))
            self.assertIn(str(staged), encoded)
            self.assertNotIn(str(manifest), encoded)
            runner._revalidate_staged_repoground_manifest(binding)
            self.assertIsNone(runner.cleanup_staged_repoground_manifest(binding))
            self.assertFalse(staged.exists())

    def test_staged_manifest_preserves_relative_artifact_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"
            state_root.mkdir(mode=0o700)
            bundle = root / "bundle"
            (bundle / "nested").mkdir(parents=True)
            artifact = bundle / "nested" / "brief.md"
            artifact.write_text("authorized artifact\n", encoding="utf-8")
            artifact_raw = artifact.read_bytes()
            manifest = bundle / "chosen.bundle.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "role": "canonical_md",
                                "path": "nested/brief.md",
                                "bytes": len(artifact_raw),
                                "sha256": hashlib.sha256(artifact_raw).hexdigest(),
                            }
                        ]
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            binding = runner.stage_repoground_manifest(
                state_root, file_identity(manifest)
            )
            staged = Path(binding["path"])
            staged_artifact = staged.parent / "nested" / "brief.md"
            self.assertEqual(staged.name, manifest.name)
            self.assertEqual(
                staged_artifact.read_text(encoding="utf-8"),
                "authorized artifact\n",
            )
            artifact.write_text("drifted original\n", encoding="utf-8")
            self.assertEqual(
                staged_artifact.read_text(encoding="utf-8"),
                "authorized artifact\n",
            )
            runner._revalidate_staged_repoground_manifest(binding)
            self.assertIsNone(runner.cleanup_staged_repoground_manifest(binding))
            self.assertFalse(staged.parent.exists())

    def test_staged_manifest_rejects_artifact_content_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_root = root / "state"
            state_root.mkdir(mode=0o700)
            bundle = root / "bundle"
            bundle.mkdir()
            artifact = bundle / "brief.md"
            authorized = b"authorized artifact\n"
            artifact.write_bytes(authorized)
            manifest = bundle / "chosen.bundle.manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "role": "canonical_md",
                                "path": "brief.md",
                                "bytes": len(authorized),
                                "sha256": hashlib.sha256(authorized).hexdigest(),
                            }
                        ]
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            expected = file_identity(manifest)
            artifact.write_bytes(b"replaced after preflight\n")

            with self.assertRaisesRegex(
                runner.RunnerError,
                "bundle artifact changed after preflight authorization",
            ):
                runner.stage_repoground_manifest(state_root, expected)

    def test_preflight_authorization_rejects_legacy_projected_request_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            value = request(condition="treatment")
            value["repobrief"]["manifest"] = str(manifest)
            value["repobrief"]["manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
            value["repobrief"]["mcp_command"] = [str(Path(sys.executable).resolve()), str(script), "--bundle-root", str(root)]
            authorized = [file_identity(Path(sys.executable)), file_identity(script)]
            state_root = write_dispatch_authorization(root, value, authorized)
            authorization_path = next((state_root / "preflight-dispatch-ledger").glob("*/authorization.json"))
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["binding"]["requests"]["treatment"]["sha256"] = runner.base._sha256_json(
                runner._preflight_request_projection(value)
            )
            authorization["contract_sha256"] = runner.base._sha256_json(authorization["binding"])
            authorization_path.write_text(json.dumps(authorization, sort_keys=True), encoding="utf-8")
            authorization_path.chmod(0o600)
            with self.assertRaisesRegex(runner.RunnerError, "treatment request"):
                runner._load_preflight_mcp_authorization(value, state_root)

    def test_relative_mcp_script_uses_preflight_authorized_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "python3"
            executable.write_bytes(Path(sys.executable).read_bytes())
            executable.chmod(0o755)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            manifest = root / "chosen.bundle.manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            authorized = [file_identity(executable), file_identity(script)]
            with patch.object(runner.Path, "cwd", side_effect=AssertionError("runtime cwd must not resolve an authorized relative script")):
                argv, bindings = runner._bind_mcp_upstream(
                    [str(executable), "server.py", "--bundle-root", str(root)],
                    manifest,
                    authorized,
                )
            self.assertEqual(argv[1], str(script.resolve()))
            self.assertEqual(bindings[1]["path"], script.resolve())

    def test_mcp_proxy_rejects_invalid_client_params_before_forwarding(self) -> None:
        for params in (None, 1, "invalid", True):
            with self.subTest(params=params), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                marker = root / "forwarded"
                upstream = root / "mcp.py"
                upstream.write_text(
                    "import pathlib, sys\n"
                    f"marker = pathlib.Path({str(marker)!r})\n"
                    "line = sys.stdin.readline()\n"
                    "if line:\n"
                    "    marker.write_text(line, encoding='utf-8')\n",
                    encoding="utf-8",
                )
                message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}
                completed = subprocess.run(
                    proxy_command(upstream, root),
                    input=json.dumps(message).encode() + b"\n",
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"benchmark MCP proxy stream failed", completed.stderr)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
