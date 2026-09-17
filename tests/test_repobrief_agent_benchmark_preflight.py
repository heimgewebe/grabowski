from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import importlib.util
import json
import os
import signal
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SUPPORT_PATH = Path(__file__).resolve().parent / "repobrief_agent_benchmark_preflight_cases.py"
SPEC = importlib.util.spec_from_file_location(
    "repobrief_agent_benchmark_preflight_cases", SUPPORT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RepoBrief preflight test cases")
support = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = support
SPEC.loader.exec_module(support)


def _load_tool_module(name: str, filename: str):
    path = ROOT / "tools" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


codex_runner = _load_tool_module(
    "repobrief_agent_benchmark_codex_runner_for_preflight_tests",
    "repobrief_agent_benchmark_codex_runner.py",
)
codex_preflight = _load_tool_module(
    "repobrief_agent_benchmark_codex_preflight_for_tests",
    "repobrief_agent_benchmark_codex_preflight.py",
)

_ORIGINAL_EXECUTE_PREFLIGHT = support.preflight.execute_preflight
_TEST_PROVIDER_BINDING_ISSUED_AT: dict[Path, str] = {}


def _test_provider_binding_issued_at(state_root: Path) -> str:
    key = state_root.expanduser().resolve()
    issued_at = _TEST_PROVIDER_BINDING_ISSUED_AT.get(key)
    if issued_at is None:
        issued_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        _TEST_PROVIDER_BINDING_ISSUED_AT[key] = issued_at
    return issued_at


def _fake_claude(
    root: Path,
    baseline: dict,
    treatment: dict,
    *,
    treatment_uses_mcp: bool = True,
    baseline_cost: str = "0.01",
    treatment_cost: str = "0.01",
) -> Path:
    script = root / "claude"
    baseline_stream = support.stream(baseline, cost=baseline_cost).decode("utf-8")
    treatment_stream = support.stream(
        treatment, cost=treatment_cost, use_repobrief=treatment_uses_mcp
    ).decode("utf-8")
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"log_path = {str(root / 'claude-invocations.jsonl')!r}\n"
        "with open(log_path, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if '--version' in sys.argv:\n"
        "    print('claude-code fixture 1.0')\n"
        "    raise SystemExit(0)\n"
        f"baseline = {baseline_stream!r}\n"
        f"treatment = {treatment_stream!r}\n"
        "index = sys.argv.index('--mcp-config') + 1\n"
        "config = json.load(open(sys.argv[index], encoding='utf-8'))\n"
        "is_treatment = bool(config.get('mcpServers'))\n"
        "sys.stdout.write(treatment if is_treatment else baseline)\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _execute_with_test_provider_binding(*args, **kwargs):
    synthetic = (
        kwargs.get("baseline_fixture") is not None
        or kwargs.get("treatment_fixture") is not None
    )
    if not synthetic:
        state_root = Path(kwargs["state_root"]).expanduser().resolve()
        credential = state_root.parent / ".credentials.json"
        credential.write_text("{}\n", encoding="utf-8")
        credential.chmod(0o600)
        executable = Path(kwargs["claude"]).expanduser().resolve()
        nonce = "ab" * 16
        issued_at = _test_provider_binding_issued_at(state_root)
        kwargs["claude_credential_file"] = credential
        kwargs["claude_command_sha256"] = hashlib.sha256(
            executable.read_bytes()
        ).hexdigest()
        kwargs["claude_credential_commitment_nonce"] = nonce
        kwargs["claude_credential_commitment_sha256"] = support.preflight._commitment_sha256(
            credential.read_bytes(), nonce
        )
        kwargs["claude_credential_commitment_issued_at"] = issued_at
        with mock.patch.dict(
            os.environ,
            {support.preflight.CLAUDE_AUTH_ROOT_ENV: str(credential.parent)},
            clear=False,
        ):
            return _ORIGINAL_EXECUTE_PREFLIGHT(*args, **kwargs)
    return _ORIGINAL_EXECUTE_PREFLIGHT(*args, **kwargs)


support.fake_claude = _fake_claude
support.preflight.execute_preflight = _execute_with_test_provider_binding
RepoBriefAgentBenchmarkPreflightTests = (
    support.RepoBriefAgentBenchmarkPreflightTests
)


def _preflight_kwargs(root: Path, environment: dict) -> dict:
    return {
        "pair_id": support.PAIR_ID,
        "request_root": environment["request_root"],
        "repository_map": environment["repository_map"],
        "state_root": root / "state",
        "transcript_root": root / "transcripts",
        "evidence_root": root / "evidence",
        "claude": str(environment["claude"]),
        "max_cost_usd": support.Decimal("1.00"),
        "validator_command": [sys.executable, str(root / "validator.py")],
    }


def _fixture_kwargs(root: Path, environment: dict) -> dict:
    baseline = root / "baseline.jsonl"
    treatment = root / "treatment.jsonl"
    baseline.write_bytes(support.stream(environment["baseline"]))
    treatment.write_bytes(support.stream(environment["treatment"]))
    return {
        **_preflight_kwargs(root, environment),
        "baseline_fixture": baseline,
        "treatment_fixture": treatment,
    }


def _rate_limit_refusal_stream(
    request: dict,
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cost: str = "0",
    api_error_status: int = 429,
    duration_api_ms: int | bool = 0,
    include_tool_use: bool = False,
    is_using_overage: bool = False,
    omit_session_id_for: str | None = None,
) -> bytes:
    session_id = f"provider-refusal-{request['condition']}"
    zero_server_tools = {"web_search_requests": 0, "web_fetch_requests": 0}
    assistant_content: list[dict] = [
        {"type": "text", "text": "session limit reached"}
    ]
    if include_tool_use:
        assistant_content.append(
            {
                "type": "tool_use",
                "id": "unexpected-tool",
                "name": "Read",
                "input": {"file_path": "src/example.py"},
            }
        )
    usage = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "server_tool_use": zero_server_tools,
    }
    messages = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": session_id,
            "model": support.MODEL,
            "tools": list(support.runner.READ_ONLY_BUILTINS),
        },
        {
            "type": "system",
            "subtype": "status",
            "status": "requesting",
            "session_id": session_id,
        },
        {
            "type": "rate_limit_event",
            "session_id": session_id,
            "rate_limit_info": {
                "status": "rejected",
                "rateLimitType": "five_hour",
                "isUsingOverage": is_using_overage,
            },
        },
        {
            "type": "assistant",
            "session_id": session_id,
            "error": "rate_limit",
            "is_api_error_message": True,
            "message": {
                "model": "<synthetic>",
                "role": "assistant",
                "usage": usage,
                "content": assistant_content,
            },
        },
        {
            "type": "result",
            "subtype": "success",
            "is_error": True,
            "session_id": session_id,
            "terminal_reason": "api_error",
            "api_error_status": api_error_status,
            "duration_api_ms": duration_api_ms,
            "usage": usage,
            "modelUsage": {},
            "subagent_stats": {
                "spawned": 0,
                "started_in_background": 0,
                "completed": 0,
                "failed": 0,
            },
            "total_cost_usd": cost,
        },
    ]
    if omit_session_id_for is not None:
        matching = [
            message for message in messages if message.get("type") == omit_session_id_for
        ]
        if not matching:
            raise AssertionError(f"unknown message type: {omit_session_id_for}")
        matching[0].pop("session_id", None)
    return b"".join(
        json.dumps(message, sort_keys=True).encode("utf-8") + b"\n"
        for message in messages
    )


def _write_failure_transcript(
    request: dict, transcript_root: Path, payload: bytes
) -> None:
    path, _artifact = support.runner._transcript_path(request, transcript_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


class ClaudeExecutableIdentityTests(unittest.TestCase):
    def _identity(self, executable: Path) -> dict:
        with mock.patch.object(
            support.preflight._core.shutil,
            "which",
            return_value=str(executable),
        ):
            return support.preflight._core._claude_identity("claude")

    def test_hashes_regular_executable_in_bounded_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            payload = b"provider-free fixture\n" * 100_000
            executable.write_bytes(payload)
            executable.chmod(0o755)
            real_read = os.read
            read_sizes: list[int] = []

            def recording_read(descriptor: int, size: int) -> bytes:
                read_sizes.append(size)
                return real_read(descriptor, size)

            with mock.patch.object(
                support.preflight._core.os,
                "read",
                side_effect=recording_read,
            ):
                identity = self._identity(executable)
            self.assertEqual(identity["resolved_path"], str(executable.resolve()))
            self.assertEqual(identity["bytes"], len(payload))
            self.assertEqual(identity["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertGreater(len(read_sizes), 1)
            self.assertTrue(
                all(
                    size == support.preflight._core.EXECUTABLE_HASH_CHUNK_BYTES
                    for size in read_sizes
                )
            )

    def test_resolves_symlink_to_exact_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "claude-version"
            link = root / "claude"
            payload = b"provider-free fixture"
            target.write_bytes(payload)
            target.chmod(0o755)
            link.symlink_to(target)
            identity = self._identity(link)
            self.assertEqual(identity["resolved_path"], str(target.resolve()))
            self.assertEqual(identity["bytes"], len(payload))

    def test_rejects_non_executable_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            executable.write_bytes(b"not executable")
            executable.chmod(0o644)
            with self.assertRaisesRegex(
                support.preflight._core.PreflightError,
                "is not executable",
            ):
                self._identity(executable)

    def test_rejects_empty_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            executable.touch()
            executable.chmod(0o755)
            with self.assertRaisesRegex(
                support.preflight._core.PreflightError,
                "executable is empty",
            ):
                self._identity(executable)

    def test_rejects_oversized_executable_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            with executable.open("wb") as handle:
                handle.truncate(
                    support.preflight._core.runner.MAX_PROVIDER_EXECUTABLE_BYTES + 1
                )
            executable.chmod(0o755)
            with mock.patch.object(
                support.preflight._core.os,
                "read",
                side_effect=AssertionError("oversized executable must not be read"),
            ):
                with self.assertRaisesRegex(
                    support.preflight._core.PreflightError,
                    "exceeds maximum size",
                ):
                    self._identity(executable)

    def test_rejects_non_regular_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            executable.mkdir()
            with self.assertRaisesRegex(
                support.preflight._core.PreflightError,
                "must be a regular file",
            ):
                self._identity(executable)

    def test_detects_same_path_mutation_during_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "claude"
            payload = b"a" * (
                support.preflight._core.EXECUTABLE_HASH_CHUNK_BYTES * 2
            )
            executable.write_bytes(payload)
            executable.chmod(0o755)
            real_read = os.read
            mutated = False

            def mutating_read(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                chunk = real_read(descriptor, size)
                if chunk and not mutated:
                    mutated = True
                    executable.write_bytes(b"b" * len(payload))
                    executable.chmod(0o755)
                return chunk

            with mock.patch.object(
                support.preflight._core.os,
                "read",
                side_effect=mutating_read,
            ):
                with self.assertRaisesRegex(
                    support.preflight._core.PreflightError,
                    "changed during hashing",
                ):
                    self._identity(executable)

    def test_detects_path_replacement_during_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "claude"
            replacement = root / "replacement"
            payload = b"a" * (
                support.preflight._core.EXECUTABLE_HASH_CHUNK_BYTES * 2
            )
            executable.write_bytes(payload)
            executable.chmod(0o755)
            replacement.write_bytes(b"b" * len(payload))
            replacement.chmod(0o755)
            real_read = os.read
            replaced = False

            def replacing_read(descriptor: int, size: int) -> bytes:
                nonlocal replaced
                chunk = real_read(descriptor, size)
                if chunk and not replaced:
                    replaced = True
                    replacement.replace(executable)
                return chunk

            with mock.patch.object(
                support.preflight._core.os,
                "read",
                side_effect=replacing_read,
            ):
                with self.assertRaisesRegex(
                    support.preflight._core.PreflightError,
                    "changed during hashing",
                ):
                    self._identity(executable)

    @unittest.skipUnless(
        os.environ.get("GRABOWSKI_TEST_INSTALLED_CLAUDE") == "1",
        "opt-in provider-free installed Claude identity check",
    )
    def test_installed_claude_matches_independent_streamed_sha256(self) -> None:
        executable = shutil.which("claude")
        if executable is None:
            self.skipTest("Claude executable is not installed")
        identity = support.preflight._core._claude_identity("claude")
        digest = hashlib.sha256()
        total = 0
        with Path(identity["resolved_path"]).open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
        self.assertEqual(identity["bytes"], total)
        self.assertEqual(identity["sha256"], digest.hexdigest())


class RepoBriefAgentBenchmarkPreflightAdapterTests(unittest.TestCase):
    def test_adapter_preserves_exact_core_claude_command(self) -> None:
        adapter, remaining = support.preflight._adapter_arguments(
            [
                "--claude-command",
                "/absolute/claude",
                "--claude-command-sha256",
                "a" * 64,
                "--claude-credential-file",
                "/private/credentials.json",
                "--claude-credential-commitment-nonce",
                "ab" * 16,
                "--claude-credential-commitment-sha256",
                "b" * 64,
                "--claude-credential-commitment-issued-at",
                "2026-09-06T04:00:00Z",
            ]
        )

        self.assertEqual(adapter.claude_command_sha256, "a" * 64)
        self.assertEqual(
            adapter.claude_credential_file,
            Path("/private/credentials.json"),
        )
        self.assertEqual(adapter.claude_credential_commitment_nonce, "ab" * 16)
        self.assertEqual(adapter.claude_credential_commitment_sha256, "b" * 64)
        self.assertEqual(
            adapter.claude_credential_commitment_issued_at,
            "2026-09-06T04:00:00Z",
        )
        self.assertEqual(remaining, ["--claude-command", "/absolute/claude"])

    def test_adapter_does_not_accept_prefix_abbreviations(self) -> None:
        adapter, remaining = support.preflight._adapter_arguments(
            [
                "--claude-command-sha",
                "a" * 64,
                "--claude-credential",
                "/private/credentials.json",
            ]
        )

        self.assertIsNone(adapter.claude_command_sha256)
        self.assertIsNone(adapter.claude_credential_file)
        self.assertEqual(
            remaining,
            [
                "--claude-command-sha",
                "a" * 64,
                "--claude-credential",
                "/private/credentials.json",
            ],
        )

    def test_core_parser_rejects_prefix_abbreviation(self) -> None:
        argv = [
            "--pair-id",
            support.PAIR_ID,
            "--request-root",
            "/tmp/requests",
            "--repository-map",
            "/tmp/repository-map.json",
            "--state-root",
            "/tmp/state",
            "--transcript-root",
            "/tmp/transcripts",
            "--evidence-root",
            "/tmp/evidence",
            "--report-out",
            "/tmp/report.json",
            "--validator-command",
            "/tmp/validator-command.json",
            "--claude-com",
            "/absolute/claude",
            "--max-cost-usd",
            "0.20",
        ]

        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                support.preflight._core.build_parser().parse_args(argv)

    def test_exact_live_argv_reaches_core_without_provider_start(self) -> None:
        captured: dict[str, object] = {}

        def fake_core_main(argv: list[str]) -> int:
            captured["argv"] = list(argv)
            captured["credential"] = support.preflight._credential_file.get()
            captured["command_sha256"] = support.preflight._command_sha256.get()
            captured["commitment_nonce"] = support.preflight._credential_commitment_nonce.get()
            captured["commitment_sha256"] = support.preflight._credential_commitment_sha256.get()
            captured["commitment_issued_at"] = support.preflight._credential_commitment_issued_at.get()
            return 0

        live_argv = [
            "--pair-id",
            support.PAIR_ID,
            "--request-root",
            "/tmp/requests",
            "--repository-map",
            "/tmp/repository-map.json",
            "--state-root",
            "/tmp/state",
            "--transcript-root",
            "/tmp/transcripts",
            "--evidence-root",
            "/tmp/evidence",
            "--report-out",
            "/tmp/report.json",
            "--validator-command",
            "/tmp/validator-command.json",
            "--claude-command",
            "/absolute/claude",
            "--claude-command-sha256",
            "a" * 64,
            "--claude-credential-file",
            "/private/credentials.json",
            "--claude-credential-commitment-nonce",
            "ab" * 16,
            "--claude-credential-commitment-sha256",
            "b" * 64,
            "--claude-credential-commitment-issued-at",
            "2026-09-06T04:00:00Z",
            "--max-cost-usd",
            "0.20",
        ]

        with mock.patch.object(support.preflight._core, "main", fake_core_main):
            self.assertEqual(support.preflight.main(live_argv), 0)

        forwarded = captured["argv"]
        self.assertIsInstance(forwarded, list)
        self.assertIn("--claude-command", forwarded)
        command_index = forwarded.index("--claude-command")
        self.assertEqual(forwarded[command_index + 1], "/absolute/claude")
        self.assertNotIn("--claude-command-sha256", forwarded)
        self.assertNotIn("--claude-credential-file", forwarded)
        self.assertNotIn("--claude-credential-commitment-nonce", forwarded)
        self.assertNotIn("--claude-credential-commitment-sha256", forwarded)
        self.assertNotIn("--claude-credential-commitment-issued-at", forwarded)
        self.assertEqual(captured["credential"], Path("/private/credentials.json"))
        self.assertEqual(captured["command_sha256"], "a" * 64)
        self.assertEqual(captured["commitment_nonce"], "ab" * 16)
        self.assertEqual(captured["commitment_sha256"], "b" * 64)
        self.assertEqual(captured["commitment_issued_at"], "2026-09-06T04:00:00Z")

    def test_live_provider_binding_resolves_symlinked_launcher_without_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "claude-2.1.259"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            launcher = root / "claude"
            launcher.symlink_to(executable)
            credential = root / ".credentials.json"
            credential.write_text("{}\n", encoding="utf-8")
            credential.chmod(0o600)
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            raw_credential_digest = hashlib.sha256(credential.read_bytes()).hexdigest()
            nonce = "ab" * 16
            issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
                "+00:00", "Z"
            )
            commitment_sha256 = support.preflight._commitment_sha256(
                credential.read_bytes(), nonce
            )
            credential_token = support.preflight._credential_file.set(credential)
            sha_token = support.preflight._command_sha256.set(digest)
            commitment_nonce_token = support.preflight._credential_commitment_nonce.set(nonce)
            commitment_sha_token = support.preflight._credential_commitment_sha256.set(
                commitment_sha256
            )
            commitment_time_token = support.preflight._credential_commitment_issued_at.set(
                issued_at
            )
            authorized_token = support.preflight._authorized_credential_sha256.set(None)
            try:
                with (
                    mock.patch.dict(
                        os.environ,
                        {support.preflight.CLAUDE_AUTH_ROOT_ENV: str(root)},
                        clear=False,
                    ),
                    mock.patch.object(
                        support.preflight, "_claude_quota_readiness"
                    ) as quota_readiness,
                ):
                    binding = support.preflight._dispatch_provider_binding_adapter(
                        str(launcher), False
                    )
                    quota_readiness.assert_not_called()
            finally:
                support.preflight._authorized_credential_sha256.reset(authorized_token)
                support.preflight._credential_commitment_issued_at.reset(commitment_time_token)
                support.preflight._credential_commitment_sha256.reset(commitment_sha_token)
                support.preflight._credential_commitment_nonce.reset(commitment_nonce_token)
                support.preflight._command_sha256.reset(sha_token)
                support.preflight._credential_file.reset(credential_token)
            self.assertEqual(binding["claude"]["path"], str(executable.resolve()))
            self.assertEqual(binding["claude"]["sha256"], digest)
            self.assertEqual(binding["credential"]["mode"], "0o600")
            self.assertFalse(binding["credential"]["credential_digest_public"])
            self.assertNotIn("path", binding["credential"])
            self.assertNotIn("sha256", binding["credential"])
            self.assertEqual(
                binding["credential"]["commitment"]["commitment_sha256"],
                commitment_sha256,
            )
            self.assertNotIn(
                raw_credential_digest, json.dumps(binding["credential"], sort_keys=True)
            )
            self.assertNotIn("quota_readiness", binding)


    def test_noncanonical_credential_path_blocks_before_secret_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical_root = root / "canonical"
            canonical_root.mkdir()
            canonical = canonical_root / ".credentials.json"
            canonical.write_text("{}\n", encoding="utf-8")
            canonical.chmod(0o600)
            other = root / "other.json"
            other.write_text("{}\n", encoding="utf-8")
            other.chmod(0o600)
            credential_token = support.preflight._credential_file.set(other)
            sha_token = support.preflight._command_sha256.set("0" * 64)
            nonce_token = support.preflight._credential_commitment_nonce.set("ab" * 16)
            commitment_token = support.preflight._credential_commitment_sha256.set("0" * 64)
            issued_token = support.preflight._credential_commitment_issued_at.set(
                datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
                    "+00:00", "Z"
                )
            )
            authorized_token = support.preflight._authorized_credential_sha256.set(None)
            try:
                with (
                    mock.patch.dict(
                        os.environ,
                        {support.preflight.CLAUDE_AUTH_ROOT_ENV: str(canonical_root)},
                        clear=False,
                    ),
                    mock.patch.object(
                        support.preflight,
                        "_original_validated_credential_data",
                    ) as secret_read,
                    self.assertRaisesRegex(
                        support.preflight.PreflightError,
                        "credential path is not canonical",
                    ),
                ):
                    support.preflight._dispatch_provider_binding_adapter(
                        "/does/not/matter", False
                    )
                secret_read.assert_not_called()
            finally:
                support.preflight._authorized_credential_sha256.reset(authorized_token)
                support.preflight._credential_commitment_issued_at.reset(issued_token)
                support.preflight._credential_commitment_sha256.reset(commitment_token)
                support.preflight._credential_commitment_nonce.reset(nonce_token)
                support.preflight._command_sha256.reset(sha_token)
                support.preflight._credential_file.reset(credential_token)

    def test_stale_credential_commitment_blocks(self) -> None:
        data = b"{}\n"
        nonce = "ab" * 16
        nonce_token = support.preflight._credential_commitment_nonce.set(nonce)
        commitment_token = support.preflight._credential_commitment_sha256.set(
            support.preflight._commitment_sha256(data, nonce)
        )
        issued_token = support.preflight._credential_commitment_issued_at.set(
            "2026-09-06T03:00:00Z"
        )
        try:
            with (
                mock.patch.object(
                    support.preflight,
                    "_utc_now",
                    return_value=datetime(2026, 9, 6, 3, 10, 1, tzinfo=timezone.utc),
                ),
                self.assertRaisesRegex(
                    support.preflight.PreflightError,
                    "credential commitment is stale",
                ),
            ):
                support.preflight._validated_credential_commitment(data)
        finally:
            support.preflight._credential_commitment_issued_at.reset(issued_token)
            support.preflight._credential_commitment_sha256.reset(commitment_token)
            support.preflight._credential_commitment_nonce.reset(nonce_token)

    def test_future_credential_commitment_blocks(self) -> None:
        data = b"{}\n"
        nonce = "ab" * 16
        nonce_token = support.preflight._credential_commitment_nonce.set(nonce)
        commitment_token = support.preflight._credential_commitment_sha256.set(
            support.preflight._commitment_sha256(data, nonce)
        )
        issued_token = support.preflight._credential_commitment_issued_at.set(
            "2026-09-06T03:03:00Z"
        )
        try:
            with (
                mock.patch.object(
                    support.preflight,
                    "_utc_now",
                    return_value=datetime(2026, 9, 6, 3, 0, 0, tzinfo=timezone.utc),
                ),
                self.assertRaisesRegex(
                    support.preflight.PreflightError,
                    "credential commitment timestamp is in the future",
                ),
            ):
                support.preflight._validated_credential_commitment(data)
        finally:
            support.preflight._credential_commitment_issued_at.reset(issued_token)
            support.preflight._credential_commitment_sha256.reset(commitment_token)
            support.preflight._credential_commitment_nonce.reset(nonce_token)

    def test_credential_commitment_mismatch_blocks_before_provider_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "claude"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            credential = root / ".credentials.json"
            credential.write_text("{}\n", encoding="utf-8")
            credential.chmod(0o600)
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
            credential_token = support.preflight._credential_file.set(credential)
            sha_token = support.preflight._command_sha256.set(digest)
            nonce_token = support.preflight._credential_commitment_nonce.set("ab" * 16)
            commitment_token = support.preflight._credential_commitment_sha256.set("0" * 64)
            issued_token = support.preflight._credential_commitment_issued_at.set(
                datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
                    "+00:00", "Z"
                )
            )
            authorized_token = support.preflight._authorized_credential_sha256.set(None)
            try:
                with (
                    mock.patch.dict(
                        os.environ,
                        {support.preflight.CLAUDE_AUTH_ROOT_ENV: str(root)},
                        clear=False,
                    ),
                    self.assertRaisesRegex(
                        support.preflight.PreflightError,
                        "credential commitment mismatch",
                    ),
                ):
                    support.preflight._dispatch_provider_binding_adapter(
                        str(executable), False
                    )
            finally:
                support.preflight._authorized_credential_sha256.reset(authorized_token)
                support.preflight._credential_commitment_issued_at.reset(issued_token)
                support.preflight._credential_commitment_sha256.reset(commitment_token)
                support.preflight._credential_commitment_nonce.reset(nonce_token)
                support.preflight._command_sha256.reset(sha_token)
                support.preflight._credential_file.reset(credential_token)

    @staticmethod
    def _quota_credential(token: str = "synthetic-token") -> bytes:
        return json.dumps({"claudeAiOauth": {"accessToken": token}}).encode()

    @staticmethod
    def _quota_http(body, status: int = 200):
        response = mock.Mock(status=status)
        response.read.return_value = body if isinstance(body, bytes) else json.dumps(body).encode()
        http = mock.Mock()
        http.getresponse.return_value = response
        return http

    def _quota_call(self, body, *, credential=None, status: int = 200, now=None):
        http = self._quota_http(body, status)
        connection = mock.patch.object(support.preflight.http.client, "HTTPSConnection", return_value=http)
        if now is None:
            with connection:
                return support.preflight._claude_quota_readiness(credential or self._quota_credential()), http
        with connection, mock.patch.object(support.preflight, "_utc_now", return_value=now):
            return support.preflight._claude_quota_readiness(credential or self._quota_credential()), http

    @staticmethod
    def _quota_argv(issued_at: str = "2026-09-15T03:00:00Z", *, nonce: str = "0" * 32, digest: str = "1" * 64) -> list[str]:
        return ["--claude-quota-readiness-only", "--quota-commitment-nonce", nonce,
                "--quota-commitment-sha256", digest, "--quota-commitment-issued-at", issued_at]

    def test_quota_readiness_is_explicitly_unknown_without_provider_probe(self) -> None:
        with mock.patch.object(support.preflight.http.client, "HTTPSConnection") as connection, mock.patch("subprocess.run") as provider_call:
            readiness = support.preflight._claude_quota_readiness()
        connection.assert_not_called(); provider_call.assert_not_called()
        self.assertEqual((readiness["status"], readiness["reason"]), ("unknown", "oauth_credential_unavailable"))
        self.assertIsNone(readiness["provider_available"])
        self.assertFalse(readiness["authentication_is_quota_evidence"])
        self.assertFalse(readiness["spend_and_credits_considered"])
        self.assertIn("retry_authority", readiness["does_not_establish"])

    def test_quota_readiness_observes_subscription_windows_without_spend(self) -> None:
        secret = "synthetic-oauth-access-token"
        now = datetime(2026, 9, 15, 5, 0, tzinfo=timezone.utc)
        readiness, http = self._quota_call({
            "five_hour": {"utilization": 25.0, "resets_at": "2026-09-15T06:00:00Z"},
            "seven_day": {"utilization": 40.0, "resets_at": "2026-09-20T06:00:00Z"},
            "extra_usage": {"is_enabled": True, "used_credits": 1},
        }, credential=self._quota_credential(secret), now=now)
        http.request.assert_called_once_with("GET", "/api/oauth/usage?at_wall=1&skip_spend=1", headers={
            "Authorization": f"Bearer {secret}", "Accept": "application/json", "Content-Type": "application/json"})
        http.close.assert_called_once_with()
        self.assertEqual((readiness["status"], readiness["remaining_five_hour_quota"], readiness["remaining_weekly_quota"]), ("observed", 75.0, 60.0))
        self.assertTrue(readiness["subscription_quota_not_exhausted"])
        self.assertNotIn(secret, json.dumps(readiness, sort_keys=True)); self.assertNotIn("extra_usage", json.dumps(readiness, sort_keys=True))
        exhausted, _ = self._quota_call({"five_hour": {"utilization": 100.0, "resets_at": None}, "seven_day": {"utilization": 50.0, "resets_at": None}})
        self.assertFalse(exhausted["subscription_quota_not_exhausted"])
        self.assertEqual((exhausted["remaining_five_hour_quota"], exhausted["remaining_weekly_quota"]), (0.0, 50.0))

    def test_quota_readiness_fails_closed_on_invalid_bounded_evidence(self) -> None:
        valid = self._quota_credential()
        cases = [
            (b"not-json", "credential_json_invalid", None),
            (b"{}", "oauth_access_token_unavailable", None),
            (valid, "required_usage_windows_unavailable", {"five_hour": {"utilization": 1.0, "resets_at": None}}),
            (valid, "required_usage_windows_unavailable", {"five_hour": {"utilization": True, "resets_at": None}, "seven_day": {"utilization": 1.0, "resets_at": None}}),
            (valid, "required_usage_windows_unavailable", {"five_hour": {"utilization": 101.0, "resets_at": None}, "seven_day": {"utilization": 1.0, "resets_at": None}}),
            (valid, "usage_response_invalid", b"not-json"),
        ]
        for credential, reason, body in cases:
            with self.subTest(reason=reason, body=body):
                if body is None:
                    with mock.patch.object(support.preflight.http.client, "HTTPSConnection") as connection:
                        result = support.preflight._claude_quota_readiness(credential)
                    connection.assert_not_called()
                else:
                    result, _ = self._quota_call(body, credential=credential)
                self.assertEqual((result["status"], result["reason"]), ("unknown", reason))
        now = datetime(2026, 9, 15, 5, 0, tzinfo=timezone.utc)
        for reset in ["not-a-timestamp", "2026-09-15T06:00:00", "2026-09-15T04:59:59Z", "2026-09-15T05:00:00Z", "0001-01-01T00:00:00+23:59"]:
            with self.subTest(reset=reset):
                result, _ = self._quota_call({"five_hour": {"utilization": 1.0, "resets_at": reset}, "seven_day": {"utilization": 1.0, "resets_at": "2026-09-20T06:00:00Z"}}, now=now)
                self.assertEqual(result["reason"], "required_usage_windows_unavailable")
        huge = b"9" * 5000
        with mock.patch.object(support.preflight.http.client, "HTTPSConnection") as connection:
            bad_credential = support.preflight._claude_quota_readiness(b'{"ignored":' + huge + b',"claudeAiOauth":{"accessToken":"synthetic-token"}}')
        connection.assert_not_called(); self.assertEqual(bad_credential["reason"], "credential_json_invalid")
        bad_response, _ = self._quota_call(b'{"ignored":' + huge + b',"five_hour":{"utilization":1,"resets_at":null},"seven_day":{"utilization":1,"resets_at":null}}')
        self.assertEqual(bad_response["reason"], "usage_response_invalid")

    def test_quota_readiness_deadline_and_failures_are_bounded_and_sanitized(self) -> None:
        body = {"five_hour": {"utilization": 1.0, "resets_at": None}, "seven_day": {"utilization": 1.0, "resets_at": None}}
        http = self._quota_http(body)
        with mock.patch.object(support.preflight.http.client, "HTTPSConnection", return_value=http), mock.patch.object(support.preflight.signal, "getsignal", return_value=signal.SIG_DFL), mock.patch.object(support.preflight.signal, "getitimer", return_value=(0.0, 0.0)), mock.patch.object(support.preflight.signal, "signal") as set_signal, mock.patch.object(support.preflight.signal, "setitimer") as set_timer:
            self.assertEqual(support.preflight._claude_quota_readiness(self._quota_credential())["status"], "observed")
        set_timer.assert_has_calls([mock.call(signal.ITIMER_REAL, 5.0), mock.call(signal.ITIMER_REAL, 0.0)]); self.assertGreaterEqual(set_signal.call_count, 2)
        with mock.patch.object(support.preflight.signal, "getitimer", return_value=(1.0, 0.0)), mock.patch.object(support.preflight.http.client, "HTTPSConnection") as connection:
            unavailable = support.preflight._claude_quota_readiness(self._quota_credential())
        connection.assert_not_called(); self.assertEqual(unavailable["reason"], "usage_request_failed")
        secret = "synthetic-token-never-return-this"; credential = self._quota_credential(secret)
        unauthorized, _ = self._quota_call(b"", credential=credential, status=401)
        broken = mock.Mock(); broken.request.side_effect = OSError(f"network failure {secret}")
        with mock.patch.object(support.preflight.http.client, "HTTPSConnection", return_value=broken): failed = support.preflight._claude_quota_readiness(credential)
        oversized, _ = self._quota_call(b"x" * (support.preflight.CLAUDE_USAGE_MAX_RESPONSE_BYTES + 1), credential=credential)
        self.assertEqual([unauthorized["reason"], failed["reason"], oversized["reason"]], ["usage_http_status_401", "usage_request_failed", "usage_response_too_large"])
        for result in (unauthorized, failed, oversized): self.assertNotIn(secret, json.dumps(result, sort_keys=True))

    def test_quota_readiness_only_mode_is_isolated_and_structured(self) -> None:
        readiness = {"status": "observed", "provider_available": None, "subscription_quota_not_exhausted": True}
        with mock.patch.object(support.preflight, "_validated_live_credential_binding", return_value=(b"synthetic-credential", mock.Mock(st_mode=0o100600), {"kind": "synthetic-commitment"})), mock.patch.object(support.preflight, "_claude_quota_readiness", return_value=readiness), mock.patch.object(support.preflight._core, "main") as core_main, mock.patch.object(support.preflight.sys, "stdout") as stdout:
            stdout.write.return_value = None; self.assertEqual(support.preflight.main(self._quota_argv()), 0)
        core_main.assert_not_called()
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {support.preflight.CLAUDE_AUTH_ROOT_ENV: "relative-auth-root"}, clear=False), redirect_stderr(stderr), mock.patch.object(support.preflight._core, "main") as core_main:
            self.assertEqual(support.preflight.main(self._quota_argv()), 2)
        core_main.assert_not_called(); self.assertEqual(json.loads(stderr.getvalue())["error"], "canonical Claude auth root is invalid")
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); credential=root/".credentials.json"; credential_data=b"{}\n"; credential.write_bytes(credential_data); credential.chmod(0o600); nonce="ab"*16
            stderr=io.StringIO()
            with mock.patch.dict(os.environ, {support.preflight.CLAUDE_AUTH_ROOT_ENV: str(root)}, clear=False), redirect_stderr(stderr), mock.patch.object(support.preflight._core, "main") as core_main, mock.patch.object(support.preflight, "_claude_quota_readiness") as quota_readiness:
                status=support.preflight.main(self._quota_argv("0001-01-01T00:00:00+23:59", nonce=nonce, digest=support.preflight._commitment_sha256(credential_data, nonce)))
        self.assertEqual(status, 2); core_main.assert_not_called(); quota_readiness.assert_not_called()
        self.assertEqual(json.loads(stderr.getvalue())["error"], "Claude credential commitment timestamp is invalid")

    def test_live_call_requires_explicit_provider_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "requires credential file and Claude executable SHA-256",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(
                    pair_id=support.PAIR_ID,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[
                        sys.executable,
                        str(root / "validator.py"),
                    ],
                )

    def test_fixture_rejects_live_provider_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            baseline_fixture = root / "baseline.jsonl"
            treatment_fixture = root / "treatment.jsonl"
            baseline_fixture.write_bytes(support.stream(environment["baseline"]))
            treatment_fixture.write_bytes(support.stream(environment["treatment"]))
            credential = root / "credentials.json"
            credential.write_text("{}\n", encoding="utf-8")
            credential.chmod(0o600)
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "synthetic fixtures must not carry live provider bindings",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(
                    pair_id=support.PAIR_ID,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[
                        sys.executable,
                        str(root / "validator.py"),
                    ],
                    baseline_fixture=baseline_fixture,
                    treatment_fixture=treatment_fixture,
                    claude_credential_file=credential,
                    claude_command_sha256="0" * 64,
                )

    def test_main_rejects_missing_live_bindings_before_core(self) -> None:
        self.assertEqual(support.preflight.main([]), 2)

    def test_live_preflight_starts_exactly_two_claude_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            report = _execute_with_test_provider_binding(
                **_preflight_kwargs(root, environment)
            )
            invocations = [
                json.loads(line)
                for line in (root / "claude-invocations.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(invocations), 2)
            self.assertTrue(all("--version" not in item for item in invocations))
            self.assertEqual(
                report["dispatch_ledger"]["provider_process_intents"], 2
            )
            self.assertIsNone(report["environment"]["claude"]["version"])
            self.assertFalse(
                report["environment"]["claude"]["version_probed"]
            )


class ProviderExecutionClassificationTests(unittest.TestCase):
    def test_exact_zero_work_rate_limit_refusal_is_classified_without_retry_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            request = environment["baseline"]
            transcript_root = root / "transcripts"
            _write_failure_transcript(
                request, transcript_root, _rate_limit_refusal_stream(request)
            )
            summary = support.preflight._core._failure_transcript_summary(
                request, transcript_root
            )
            self.assertFalse(summary["outcome_ambiguous"])
            self.assertEqual(summary["observed_cost_usd"], "0")
            self.assertEqual(
                summary["provider_execution"]["classification"],
                "provider_refusal_before_model_execution",
            )
            self.assertFalse(
                summary["provider_execution"]["classification_grants_retry"]
            )
            self.assertEqual(
                summary["provider_execution"]["api_error_status"], 429
            )
            self.assertEqual(
                summary["provider_execution"]["rate_limit_type"], "five_hour"
            )

    def test_any_work_or_nonzero_cost_fails_closed(self) -> None:
        cases = {
            "input-token": {"input_tokens": 1},
            "output-token": {"output_tokens": 1},
            "cost": {"cost": "0.01"},
            "api-duration": {"duration_api_ms": 1},
            "boolean-api-duration": {"duration_api_ms": False},
            "different-status": {"api_error_status": 503},
            "tool-use": {"include_tool_use": True},
            "overage-active": {"is_using_overage": True},
            "missing-rate-limit-session": {
                "omit_session_id_for": "rate_limit_event"
            },
            "missing-assistant-session": {"omit_session_id_for": "assistant"},
            "missing-result-session": {"omit_session_id_for": "result"},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                environment = support.fixture_environment(root)
                request = environment["baseline"]
                transcript_root = root / "transcripts"
                _write_failure_transcript(
                    request,
                    transcript_root,
                    _rate_limit_refusal_stream(request, **overrides),
                )
                summary = support.preflight._core._failure_transcript_summary(
                    request, transcript_root
                )
                self.assertEqual(
                    summary["provider_execution"]["classification"],
                    "unknown_or_model_work_possible",
                )
                self.assertFalse(
                    summary["provider_execution"]["classification_grants_retry"]
                )

    def test_ledger_records_classification_but_still_blocks_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)

            def reject_without_model_work(request, **runner_kwargs):
                _write_failure_transcript(
                    request,
                    Path(runner_kwargs["transcript_root"]),
                    _rate_limit_refusal_stream(request),
                )
                raise support.preflight.runner.RunnerError(
                    "provider did not produce a successful result"
                )

            with mock.patch.object(
                support.preflight._core.runner,
                "execute",
                side_effect=reject_without_model_work,
            ):
                with self.assertRaisesRegex(
                    support.preflight.runner.RunnerError,
                    "did not produce a successful result",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            failure = next(
                event for event in events if event["event"] == "condition-failed"
            )
            self.assertEqual(
                failure["payload"]["transcript"]["provider_execution"][
                    "classification"
                ],
                "provider_refusal_before_model_execution",
            )
            self.assertFalse(
                failure["payload"]["transcript"]["provider_execution"][
                    "classification_grants_retry"
                ]
            )
            self.assertFalse(events[-1]["payload"]["retry_permitted"])
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 1)


class RepoBriefAgentBenchmarkPreflightLedgerTests(unittest.TestCase):
    def test_fixture_success_is_one_shot_and_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            report = _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            ledger = report["dispatch_ledger"]
            self.assertEqual(ledger["condition_intents"], ["baseline", "treatment"])
            self.assertEqual(ledger["provider_process_intents"], 0)
            self.assertEqual(ledger["fixture_intents"], 2)
            self.assertEqual(ledger["event_count"], 6)
            self.assertFalse(ledger["retry_permitted"])
            events = support.ledger_events(root / "state")
            previous = events[0]["contract_sha256"]
            for event in events:
                self.assertEqual(event["previous_event_sha256"], previous)
                previous = support.preflight._sha256_json(event)
            self.assertEqual(previous, ledger["final_event_sha256"])
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "blocks retry"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)

    def test_changed_binding_cannot_reuse_existing_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            kwargs["max_cost_usd"] = support.Decimal("0.50")
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "different schema, code, plan, path, or budget"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)

    def test_ambiguous_launch_records_intent_and_blocks_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            error = support.preflight.runner.RunnerError(
                "provider process launch outcome is unknown"
            )
            with mock.patch.object(
                support.preflight._core.runner, "execute", side_effect=error
            ):
                with self.assertRaisesRegex(
                    support.preflight.runner.RunnerError, "outcome is unknown"
                ):
                    _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-failed",
                    "preflight-failed",
                ],
            )
            self.assertTrue(
                events[2]["payload"]["transcript"]["outcome_ambiguous"]
            )
            self.assertEqual(
                events[-1]["payload"]["provider_process_intents"], 1
            )
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "blocks retry"
            ):
                _execute_with_test_provider_binding(**kwargs)

    def test_ambiguous_launch_retry_keeps_test_authorization_across_clock_tick(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            error = support.preflight.runner.RunnerError(
                "provider process launch outcome is unknown"
            )
            real_datetime = datetime
            first_tick = real_datetime.now(timezone.utc).replace(microsecond=0)
            second_tick = first_tick + timedelta(seconds=1)
            with mock.patch(f"{__name__}.datetime") as clock:
                clock.now.side_effect = [first_tick, second_tick]
                with mock.patch.object(
                    support.preflight._core.runner, "execute", side_effect=error
                ):
                    with self.assertRaisesRegex(
                        support.preflight.runner.RunnerError, "outcome is unknown"
                    ):
                        _execute_with_test_provider_binding(**kwargs)
                with self.assertRaisesRegex(
                    support.preflight.PreflightError,
                    "prior or ambiguous attempt blocks retry",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            self.assertEqual(clock.now.call_count, 1)

    def test_budget_stop_preserves_observed_overshoot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            environment["claude"] = _fake_claude(
                root,
                environment["baseline"],
                environment["treatment"],
                treatment_cost="1.25",
            )
            kwargs = _preflight_kwargs(root, environment)
            with self.assertRaisesRegex(
                support.preflight.runner.RunnerError, "cost exceeds max_budget_usd"
            ):
                _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            failure = next(
                event
                for event in events
                if event["event"] == "condition-failed"
            )
            transcript = failure["payload"]["transcript"]
            self.assertEqual(transcript["observed_cost_usd"], "1.25")
            self.assertFalse(transcript["outcome_ambiguous"])
            terminal = events[-1]["payload"]
            self.assertEqual(terminal["observed_costs"]["baseline"], "0.01")
            self.assertEqual(terminal["observed_costs"]["treatment"], "1.25")
            self.assertEqual(terminal["provider_process_intents"], 2)
            self.assertFalse(terminal["retry_permitted"])

    def test_existing_receipt_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            receipt = support.preflight._receipt_path(
                root / "evidence", environment["baseline"]
            )
            receipt.parent.mkdir(parents=True)
            receipt.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "receipt path already exists"
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            self.assertEqual(receipt.read_text(encoding="utf-8"), "sentinel\n")
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                ["preflight-failed"],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 0)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])

    def test_duplicate_condition_and_third_intent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            with mock.patch.object(
                support.preflight._core,
                "_dispatch_provider_binding",
                return_value={"mode": "live_provider_fixture"},
            ):
                binding = support.preflight._dispatch_binding(
                    baseline=environment["baseline"],
                    treatment=environment["treatment"],
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=root / "state",
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=None,
                    claude=str(environment["claude"]),
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=[sys.executable, str(root / "validator.py")],
                    synthetic=False,
                )
            ledger = support.preflight._initialize_dispatch_ledger(
                binding=binding, state_root=root / "state"
            )
            support.preflight._record_dispatch_intent(
                ledger,
                environment["baseline"],
                synthetic=False,
                max_cost_usd=support.Decimal("1.00"),
            )
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "already exists for baseline"
            ):
                support.preflight._record_dispatch_intent(
                    ledger,
                    environment["baseline"],
                    synthetic=False,
                    max_cost_usd=support.Decimal("1.00"),
                )
            support.preflight._record_dispatch_intent(
                ledger,
                environment["treatment"],
                synthetic=False,
                max_cost_usd=support.Decimal("1.00"),
            )
            third = dict(environment["baseline"])
            third["condition"] = "baseline"
            ledger["condition_intents"] = ["treatment", "other"]
            with self.assertRaisesRegex(
                support.preflight.PreflightError, "third process intent"
            ):
                support.preflight._record_dispatch_intent(
                    ledger,
                    third,
                    synthetic=False,
                    max_cost_usd=support.Decimal("1.00"),
                )


    def test_request_mutation_after_baseline_blocks_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            original = support.preflight._core.runner.execute

            def mutate_plan_after_baseline(request: dict, **run_kwargs):
                output = original(request, **run_kwargs)
                if request["condition"] == "baseline":
                    path = support.preflight._request_path(
                        environment["request_root"], environment["treatment"]
                    )
                    changed = json.loads(path.read_text(encoding="utf-8"))
                    changed["prompt"] += " changed"
                    path.write_text(
                        json.dumps(changed, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                return output

            with mock.patch.object(
                support.preflight._core.runner,
                "execute",
                side_effect=mutate_plan_after_baseline,
            ):
                with self.assertRaises(support.preflight.PreflightError):
                    _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-completed",
                    "preflight-failed",
                ],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 1)

    def test_credential_mutation_after_intent_blocks_before_provider_spawn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            original = support.preflight._core._record_dispatch_intent
            credential = root / ".credentials.json"

            def mutate_after_intent(*args, **record_kwargs):
                result = original(*args, **record_kwargs)
                request = args[1]
                if request["condition"] == "baseline":
                    credential.write_text('{"changed":true}\n', encoding="utf-8")
                    credential.chmod(0o600)
                return result

            with mock.patch.object(
                support.preflight._core,
                "_record_dispatch_intent",
                side_effect=mutate_after_intent,
            ):
                with self.assertRaisesRegex(
                    support.preflight.runner.RunnerError,
                    "credential file changed after authorization",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            self.assertFalse((root / "claude-invocations.jsonl").exists())
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                [
                    "authorized",
                    "dispatch-intent",
                    "condition-failed",
                    "preflight-failed",
                ],
            )
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 1)

    def test_credential_mutation_after_baseline_blocks_treatment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _preflight_kwargs(root, environment)
            original = support.preflight._core.runner.execute
            credential = root / ".credentials.json"

            def mutate_credential_after_baseline(request: dict, **run_kwargs):
                output = original(request, **run_kwargs)
                if request["condition"] == "baseline":
                    credential.write_text('{"changed":true}\n', encoding="utf-8")
                    credential.chmod(0o600)
                return output

            with mock.patch.object(
                support.preflight._core.runner,
                "execute",
                side_effect=mutate_credential_after_baseline,
            ):
                with self.assertRaisesRegex(
                    support.preflight.PreflightError,
                    "credential commitment mismatch",
                ):
                    _execute_with_test_provider_binding(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(events[-1]["event"], "preflight-failed")
            self.assertEqual(events[-1]["payload"]["provider_process_intents"], 1)
            self.assertEqual(events[-1]["payload"]["observed_costs"]["baseline"], "0.01")


    def test_synthetic_cli_publishes_report_bound_in_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            fixtures = _fixture_kwargs(root, environment)
            report = root / "published-report.json"
            argv = [
                "--pair-id",
                support.PAIR_ID,
                "--request-root",
                str(environment["request_root"]),
                "--repository-map",
                str(environment["repository_map"]),
                "--state-root",
                str(root / "state"),
                "--transcript-root",
                str(root / "transcripts"),
                "--evidence-root",
                str(root / "evidence"),
                "--report-out",
                str(report),
                "--validator-command",
                str(environment["validator_command"]),
                "--max-cost-usd",
                "1.00",
                "--baseline-stream-fixture",
                str(fixtures["baseline_fixture"]),
                "--treatment-stream-fixture",
                str(fixtures["treatment_fixture"]),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = support.preflight.main(argv)
            self.assertEqual(result, 0, stderr.getvalue())
            self.assertTrue(report.is_file())
            self.assertTrue(Path(str(report) + ".sha256").is_file())
            parent = root / "state" / "preflight-dispatch-ledger"
            pair_root = next(parent.iterdir())
            authorization = json.loads(
                (pair_root / "authorization.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                authorization["binding"]["report_out"], str(report.resolve())
            )
            self.assertEqual(
                authorization["binding"]["report_digest_out"],
                str(Path(str(report.resolve()) + ".sha256")),
            )
            published = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(published["status"], "synthetic_only")
            self.assertFalse(published["dispatch_ledger"]["retry_permitted"])

    def test_preexisting_report_path_blocks_before_process_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            report = root / "report.json"
            report.write_text("sentinel\n", encoding="utf-8")
            kwargs["report_out"] = report
            with self.assertRaisesRegex(
                support.preflight.PreflightError,
                "preflight report path already exists",
            ):
                _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            self.assertEqual(report.read_text(encoding="utf-8"), "sentinel\n")
            events = support.ledger_events(root / "state")
            self.assertEqual(
                [event["event"] for event in events],
                ["preflight-failed"],
            )
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 0)

    def test_source_mutation_before_authorization_publishes_no_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            original = support.preflight._core.source_state
            calls = 0

            def mutating_source_state(source: Path) -> dict:
                nonlocal calls
                calls += 1
                if calls == 2:
                    (source / "mutation-before-authorization.txt").write_text(
                        "changed", encoding="utf-8"
                    )
                return original(source)

            with mock.patch.object(
                support.preflight._core,
                "source_state",
                side_effect=mutating_source_state,
            ):
                with self.assertRaisesRegex(
                    support.preflight.PreflightError, "source checkout changed"
                ):
                    _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            pair_root = next((root / "state" / "preflight-dispatch-ledger").iterdir())
            self.assertFalse((pair_root / "authorization.json").exists())
            events = support.ledger_events(root / "state")
            self.assertEqual([event["event"] for event in events], ["preflight-failed"])
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 0)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])

    def test_source_mutation_records_terminal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            kwargs = _fixture_kwargs(root, environment)
            original = support.preflight._core.source_state
            calls = 0

            def mutating_source_state(source: Path) -> dict:
                nonlocal calls
                calls += 1
                if calls == 3:
                    (source / "mutation.txt").write_text(
                        "changed", encoding="utf-8"
                    )
                return original(source)

            with mock.patch.object(
                support.preflight._core,
                "source_state",
                side_effect=mutating_source_state,
            ):
                with self.assertRaisesRegex(
                    support.preflight.PreflightError, "source checkout changed"
                ):
                    _ORIGINAL_EXECUTE_PREFLIGHT(**kwargs)
            events = support.ledger_events(root / "state")
            self.assertEqual(events[-1]["event"], "preflight-failed")
            self.assertEqual(events[-1]["payload"]["fixture_intents"], 2)
            self.assertFalse(events[-1]["payload"]["retry_permitted"])


class CodexProductionAuthorizationTests(unittest.TestCase):
    @staticmethod
    def _codex_pair(environment: dict) -> tuple[str, dict, dict]:
        pair_id = f"{support.TASKSET}:{support.CASE}:r2"
        requests = []
        for original in (environment["baseline"], environment["treatment"]):
            value = json.loads(json.dumps(original))
            condition = value["condition"]
            request_id = f"{pair_id}:{condition}"
            value["pair_id"] = pair_id
            value["repetition"] = 2
            value["request_id"] = request_id
            value["session_id"] = f"session:{request_id}"
            value["workspace_id"] = f"workspace:{request_id}"
            value["runner"] = {
                "execution_contract": codex_runner.EXECUTION_CONTRACT,
                "provider": codex_runner.PROVIDER,
                "model": codex_runner.MODEL,
                "sampling": codex_runner.SAMPLING,
            }
            requests.append(value)
        request_root = environment["request_root"]
        for path in request_root.glob("*.json"):
            path.unlink()
        for value in requests:
            filename = value["request_id"].replace(":", "__") + ".json"
            (request_root / filename).write_text(
                json.dumps(value, sort_keys=True), encoding="utf-8"
            )
        environment["baseline"], environment["treatment"] = requests
        return pair_id, requests[0], requests[1]

    def test_codex_producer_ledger_is_consumable_by_exact_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            pair_id, baseline, treatment = self._codex_pair(environment)
            state_root = root / "state"
            transcript_root = root / "transcripts"
            evidence_root = root / "evidence"
            report_out = root / "preflight-report.json"
            codex = root / "codex"
            codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            codex.chmod(0o755)
            codex_sha256 = hashlib.sha256(codex.read_bytes()).hexdigest()

            with (
                mock.patch.object(
                    codex_preflight.codex_runner,
                    "validate_executable",
                    return_value=str(codex.resolve()),
                ),
                mock.patch.object(codex_preflight.codex_runner, "validate_toolchain"),
                mock.patch.object(
                    codex_preflight.codex_runner,
                    "validate_chatgpt_subscription",
                    return_value=b'{"tokens":{}}',
                ),
            ):
                report = codex_preflight.authorize_pair(
                    pair_id=pair_id,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=state_root,
                    transcript_root=transcript_root,
                    evidence_root=evidence_root,
                    report_out=report_out,
                    codex_command=str(codex.resolve()),
                    codex_command_sha256=codex_sha256,
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=codex_preflight.core._command_array(
                        environment["validator_command"]
                    ),
                )

            self.assertEqual(report["status"], "authorized")
            authorization_path = Path(report["dispatch_ledger"]["authorization"])
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            binding = authorization["binding"]
            self.assertEqual(
                binding["requests"]["treatment"]["sha256"],
                codex_runner.base._sha256_json(treatment),
            )
            self.assertEqual(
                binding["requests"]["baseline"]["sha256"],
                codex_runner.base._sha256_json(baseline),
            )
            self.assertGreaterEqual(len(binding["mcp_command_files"]), 2)
            code_files = {item["name"]: item for item in binding["code"]["files"]}
            self.assertIn(Path(codex_runner.__file__).name, code_files)

            runtime_binding = {
                "request_root": environment["request_root"],
                "repository_map": environment["repository_map"],
                "transcript_root": transcript_root,
                "evidence_root": evidence_root,
            }
            consumed = codex_runner._load_preflight_dispatch_authorization(
                treatment, state_root, runtime_binding=runtime_binding
            )
            self.assertEqual(
                consumed["proxy_code"]["sha256"],
                code_files[Path(codex_runner.__file__).name]["sha256"],
            )
            self.assertEqual(
                [str(item["path"]) for item in consumed["mcp_files"]],
                [item["path"] for item in binding["mcp_command_files"]],
            )
            self.assertIsInstance(consumed["repository_map_bytes"], bytes)
            self.assertEqual(
                codex_runner._repository_root_from_authorized_map_bytes(
                    treatment, consumed["repository_map_bytes"]
                ),
                environment["source"].resolve(),
            )

            # Baseline consumes the same pair/provider/runtime authorization,
            # without inheriting treatment-only MCP/RepoGround requirements.
            baseline_consumed = codex_runner._load_preflight_dispatch_authorization(
                baseline, state_root, runtime_binding=runtime_binding
            )
            self.assertEqual(baseline_consumed["mcp_files"], [])
            self.assertIsNone(baseline_consumed["proxy_code"])
            self.assertIsNone(baseline_consumed["manifest"])

            wrong_runtime = dict(runtime_binding)
            wrong_runtime["transcript_root"] = root / "other-transcripts"
            with self.assertRaisesRegex(
                codex_runner.RunnerError, "runtime binding mismatch: transcript_root"
            ):
                codex_runner._load_preflight_dispatch_authorization(
                    baseline, state_root, runtime_binding=wrong_runtime
                )

            original_map = environment["repository_map"].read_bytes()
            environment["repository_map"].write_bytes(original_map + b"\n")
            try:
                with self.assertRaisesRegex(
                    codex_runner.RunnerError, "repository map identity mismatch"
                ):
                    codex_runner._load_preflight_dispatch_authorization(
                        baseline, state_root, runtime_binding=runtime_binding
                    )
            finally:
                environment["repository_map"].write_bytes(original_map)

            hidden = authorization_path.with_name("authorization.hidden")
            authorization_path.rename(hidden)
            try:
                with self.assertRaisesRegex(
                    codex_runner.RunnerError, "preflight dispatch authorization is unavailable"
                ):
                    codex_runner._load_preflight_dispatch_authorization(
                        baseline, state_root, runtime_binding=runtime_binding
                    )
            finally:
                hidden.rename(authorization_path)

    def test_authorize_dispatch_rejects_cross_provider_binding_before_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            claude_baseline, _ = support.preflight.load_pair(
                environment["request_root"], support.PAIR_ID
            )
            pair_id, _, _ = self._codex_pair(environment)
            bad_state = root / "bad-state"
            with self.assertRaisesRegex(
                codex_preflight.core.PreflightError,
                "provider binding does not match treatment runner contract",
            ):
                codex_preflight.core.authorize_dispatch(
                    pair_id=pair_id,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=bad_state,
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=root / "report.json",
                    provider_binding={
                        "mode": "live_provider",
                        "runner": dict(claude_baseline["runner"]),
                    },
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=codex_preflight.core._command_array(
                        environment["validator_command"]
                    ),
                )
            self.assertFalse(bad_state.exists())

    def test_authorize_dispatch_rejects_nonfinite_cost_before_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            pair_id, _, treatment = self._codex_pair(environment)
            bad_state = root / "nan-state"
            with self.assertRaisesRegex(
                codex_preflight.core.PreflightError, "max cost must be finite"
            ):
                codex_preflight.core.authorize_dispatch(
                    pair_id=pair_id,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=bad_state,
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=root / "report.json",
                    provider_binding={
                        "mode": "live_provider",
                        "runner": dict(treatment["runner"]),
                    },
                    max_cost_usd=support.Decimal("NaN"),
                    validator_command=codex_preflight.core._command_array(
                        environment["validator_command"]
                    ),
                )
            self.assertFalse(bad_state.exists())

    def test_failed_late_authorization_does_not_publish_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            pair_id, _, treatment = self._codex_pair(environment)
            state_root = root / "state"
            with (
                mock.patch.object(
                    codex_preflight.core,
                    "probe_freshness",
                    side_effect=codex_preflight.core.PreflightError("late preflight failure"),
                ),
                self.assertRaisesRegex(
                    codex_preflight.core.PreflightError, "late preflight failure"
                ),
            ):
                codex_preflight.core.authorize_dispatch(
                    pair_id=pair_id,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=state_root,
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=root / "report.json",
                    provider_binding={
                        "mode": "live_provider",
                        "runner": dict(treatment["runner"]),
                    },
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=codex_preflight.core._command_array(
                        environment["validator_command"]
                    ),
                )
            pair_digest = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()
            pair_root = state_root / "preflight-dispatch-ledger" / pair_digest
            self.assertTrue(pair_root.is_dir())
            self.assertFalse((pair_root / "authorization.json").exists())
            events = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((pair_root / "events").glob("*.json"))
            ]
            self.assertNotIn("authorized", [event["event"] for event in events])
            self.assertEqual(events[-1]["event"], "preflight-failed")
            self.assertFalse(events[-1]["payload"]["retry_permitted"])

    def test_report_persistence_failure_leaves_no_dispatch_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            pair_id, _, _ = self._codex_pair(environment)
            state_root = root / "state"
            report_out = root / "preflight-report.json"
            codex = root / "codex"
            codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            codex.chmod(0o755)
            codex_sha256 = hashlib.sha256(codex.read_bytes()).hexdigest()

            with (
                mock.patch.object(
                    codex_preflight.codex_runner,
                    "validate_executable",
                    return_value=str(codex.resolve()),
                ),
                mock.patch.object(codex_preflight.codex_runner, "validate_toolchain"),
                mock.patch.object(
                    codex_preflight.codex_runner,
                    "validate_chatgpt_subscription",
                    return_value=b'{"tokens":{}}',
                ),
                mock.patch.object(
                    codex_preflight.core,
                    "_write_report_artifacts",
                    side_effect=codex_preflight.core.PreflightError("report persistence failed"),
                ),
                self.assertRaisesRegex(
                    codex_preflight.core.PreflightError, "report persistence failed"
                ),
            ):
                codex_preflight.authorize_pair(
                    pair_id=pair_id,
                    request_root=environment["request_root"],
                    repository_map=environment["repository_map"],
                    state_root=state_root,
                    transcript_root=root / "transcripts",
                    evidence_root=root / "evidence",
                    report_out=report_out,
                    codex_command=str(codex.resolve()),
                    codex_command_sha256=codex_sha256,
                    max_cost_usd=support.Decimal("1.00"),
                    validator_command=codex_preflight.core._command_array(
                        environment["validator_command"]
                    ),
                )

            pair_digest = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()
            pair_root = state_root / "preflight-dispatch-ledger" / pair_digest
            self.assertFalse((pair_root / "authorization.json").exists())
            events = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in sorted((pair_root / "events").glob("*.json"))
            ]
            self.assertNotIn("authorized", [event["event"] for event in events])
            self.assertEqual(events[-1]["event"], "preflight-failed")

    def test_provider_specific_request_validation_has_no_cross_provider_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = support.fixture_environment(root)
            claude_baseline, claude_treatment = support.preflight.load_pair(
                environment["request_root"], support.PAIR_ID
            )
            self.assertIs(
                support.preflight._core._request_validation_runner(claude_treatment),
                support.preflight._core.runner,
            )

            pair_id, codex_baseline, codex_treatment = self._codex_pair(environment)
            loaded_baseline, loaded_treatment = codex_preflight.core.load_pair(
                environment["request_root"], pair_id
            )
            self.assertEqual(loaded_baseline["runner"], codex_baseline["runner"])
            self.assertEqual(loaded_treatment["runner"], codex_treatment["runner"])

            drift_cases = {
                "execution_contract": "wrong-contract",
                "provider": "anthropic-claude-code",
                "model": "wrong-model",
                "sampling": {"temperature": 0},
            }
            treatment_path = next(
                path for path in environment["request_root"].glob("*.json")
                if "treatment" in path.name
            )
            original_text = treatment_path.read_text(encoding="utf-8")
            for field, value in drift_cases.items():
                with self.subTest(field=field):
                    candidate = json.loads(original_text)
                    candidate["runner"][field] = value
                    treatment_path.write_text(
                        json.dumps(candidate, sort_keys=True), encoding="utf-8"
                    )
                    with self.assertRaises(codex_preflight.core.PreflightError):
                        codex_preflight.core.load_pair(environment["request_root"], pair_id)
                    treatment_path.write_text(original_text, encoding="utf-8")

            mixed = json.loads(json.dumps(codex_baseline))
            mixed["runner"] = dict(claude_baseline["runner"])
            baseline_path = next(
                path for path in environment["request_root"].glob("*.json")
                if "baseline" in path.name
            )
            baseline_path.write_text(json.dumps(mixed, sort_keys=True), encoding="utf-8")
            with self.assertRaisesRegex(
                codex_preflight.core.PreflightError,
                "paired requests use different provider contracts",
            ):
                codex_preflight.core.load_pair(environment["request_root"], pair_id)


class McpCommandFileIdentityTests(unittest.TestCase):
    def test_mcp_relative_script_is_authorized_against_explicit_preflight_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "server.py"
            script.write_text("pass\n", encoding="utf-8")
            executable = Path(sys.executable).resolve()
            identities = support.preflight._core._command_file_identities(
                [str(executable), "server.py"], relative_to=root
            )
            self.assertEqual(
                [item["path"] for item in identities],
                [str(executable), str(script.resolve())],
            )
            legacy = support.preflight._core._command_file_identities(
                [str(executable), "server.py"]
            )
            self.assertEqual([item["path"] for item in legacy], [str(executable)])


if __name__ == "__main__":
    unittest.main()
