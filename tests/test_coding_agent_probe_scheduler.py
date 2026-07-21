from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import signal
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "coding_agent_probe_scheduler.py"
SPEC = importlib.util.spec_from_file_location(
    "coding_agent_probe_scheduler", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
SCHEDULER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCHEDULER)


class CodingAgentProbeSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "state.json"
        self.lock = self.root / "probe.lock"
        self.receipt = self.root / "receipt.json"
        self.failure = self.root / "failure.json"
        self.router = self.root / "agent-route"
        self.router_digest = self.root / "router.sha256"
        self.initial = {
            "schema_version": 2,
            "updated_at": "2026-07-18T15:00:00Z",
            "catalog_sha256": "catalog",
            "catalog": {},
            "pools": {"pool": {"status": "available"}},
            "routes": {"route": {"runs": 7}},
            "history": {"marker": {"value": 1}},
        }
        self.state.write_text(json.dumps(self.initial), encoding="utf-8")
        os.chmod(self.state, 0o600)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _process_is_live(process_id: int) -> bool:
        try:
            stat_payload = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        except FileNotFoundError:
            return False
        except PermissionError:
            return True
        try:
            state = stat_payload.rsplit(")", 1)[1].strip().split(maxsplit=1)[0]
        except IndexError:
            return True
        return state not in {"X", "Z"}

    def _wait_for_positive_pid(
        self, path: Path, *, timeout_seconds: float
    ) -> int:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                process_id = int(path.read_text(encoding="ascii").strip())
            except (FileNotFoundError, ValueError):
                time.sleep(0.02)
                continue
            if process_id > 0:
                return process_id
            time.sleep(0.02)
        self.fail(
            f"PID file did not contain a positive integer before timeout: {path}"
        )

    def test_wait_for_positive_pid_tolerates_empty_existing_file(self) -> None:
        pid_path = self.root / "child.pid"
        pid_path.touch()
        with (
            mock.patch.object(Path, "read_text", side_effect=["", "321\n"]) as read_text,
            mock.patch.object(time, "sleep") as sleep,
        ):
            process_id = self._wait_for_positive_pid(pid_path, timeout_seconds=1)
        self.assertEqual(321, process_id)
        self.assertEqual(2, read_text.call_count)
        sleep.assert_called_once_with(0.02)

    def write_router(
        self, *, mutate_history: bool = False, tamper_digest: bool = False
    ) -> None:
        program = f"""\
#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import sys

state_path = Path({str(self.state)!r})
if sys.argv[1] == "probe":
    state = json.loads(state_path.read_text())
    body = {{
        "schema_version": 2,
        "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "harnesses": {{}},
        "providers": {{"codex": {{"available": True}}}},
        "verified_quota_pools": [],
        "api_key_environment_scrubbed": {list(SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV)!r},
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }}
    digest_fields = (
        "schema_version",
        "observed_at",
        "harnesses",
        "providers",
        "verified_quota_pools",
        "model_invocations",
        "paid_api_requests_authorized",
    )
    canonical = json.dumps(
        {{field: body[field] for field in digest_fields}},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    body["catalog_probe_sha256"] = hmac.new(
        b"grabowski-coding-agent-probe-v3", canonical, hashlib.sha256
    ).hexdigest()
    if {tamper_digest!r}:
        body["catalog_probe_sha256"] = "0" * 64
    state["catalog"] = body
    state["updated_at"] = body["observed_at"]
    if {mutate_history!r}:
        state["history"] = {{"changed": True}}
    temporary = state_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    os.replace(temporary, state_path)
    print(json.dumps(body))
elif sys.argv[1] == "status":
    print(json.dumps({{
        "schema_version": 2,
        "catalog_fresh": True,
        "automatic_execution_authorized": False,
    }}))
else:
    raise SystemExit(2)
"""
        self.router.write_text(textwrap.dedent(program), encoding="utf-8")
        os.chmod(self.router, 0o700)
        digest = hashlib.sha256(self.router.read_bytes()).hexdigest()
        self.router_digest.write_text(digest + "\n", encoding="ascii")
        os.chmod(self.router_digest, 0o600)

    def arguments(self) -> list[str]:
        return [
            "--router",
            str(self.router),
            "--router-sha256-file",
            str(self.router_digest),
            "--state",
            str(self.state),
            "--lock",
            str(self.lock),
            "--receipt",
            str(self.receipt),
            "--failure",
            str(self.failure),
            "--timeout-seconds",
            "10",
        ]

    def test_success_preserves_history_scrubs_keys_and_writes_readback_receipt(
        self,
    ) -> None:
        self.write_router()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(0, result)
        after = json.loads(self.state.read_text(encoding="utf-8"))
        receipt = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual(self.initial["history"], after["history"])
        self.assertEqual("ok", receipt["status"])
        self.assertTrue(receipt["status_readback"]["catalog_fresh"])
        self.assertFalse(receipt["status_readback"]["automatic_execution_authorized"])
        self.assertEqual(0, receipt["model_invocations"])
        self.assertEqual(0, receipt["paid_api_requests_authorized"])
        self.assertEqual(
            len(SCHEDULER.FORBIDDEN_API_KEY_ENV),
            receipt["api_key_environment_removed_count"],
        )
        self.assertFalse(self.failure.exists())

    def test_probe_validation_rejects_plain_sha256_without_domain_binding(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": list(
                SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV
            ),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        canonical = json.dumps(
            probe,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        probe["catalog_probe_sha256"] = hashlib.sha256(canonical).hexdigest()
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "digest does not match"
        ):
            SCHEDULER.validate_probe(probe)

    def test_probe_validation_rejects_tampered_scrub_claim_outside_digest(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": [],
            "api_key_environment_scrubbed": list(
                SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV
            ),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        digest = SCHEDULER.probe_digest(probe)
        probe["catalog_probe_sha256"] = digest
        probe["api_key_environment_scrubbed"] = ["OPENAI_API_KEY"]
        self.assertEqual(digest, SCHEDULER.probe_digest(probe))
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            "api_key_environment_scrubbed is invalid",
        ):
            SCHEDULER.validate_probe(probe)

    def test_probe_validation_rejects_invalid_verified_pool_claims(self) -> None:
        base = {
            "schema_version": 2,
            "observed_at": SCHEDULER.iso_now(),
            "harnesses": {},
            "providers": {},
            "api_key_environment_scrubbed": list(
                SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV
            ),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        for value in (
            ["grok-com", "grok-com"],
            ["unknown"],
            [{"pool": "grok-com"}],
        ):
            with self.subTest(value=value):
                probe = {**base, "verified_quota_pools": value}
                probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
                with self.assertRaisesRegex(
                    SCHEDULER.ProbeSchedulerError, "verified_quota_pools"
                ):
                    SCHEDULER.validate_probe(probe)

    def test_state_validation_preserves_same_catalog_and_adds_only_verified_time(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": "2026-07-20T11:00:00Z",
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["grok-com"],
            "api_key_environment_scrubbed": list(
                SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV
            ),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
        before = {
            **self.initial,
            "pools": {
                "pool": {"status": "available"},
                "grok-com": {"status": "unknown"},
                "jules-account": {
                    "status": "unknown",
                    "verified_at": "2026-07-19T00:00:00Z",
                },
            },
        }
        after = json.loads(json.dumps(before))
        after["catalog"] = probe
        after["pools"]["grok-com"]["verified_at"] = probe["observed_at"]
        after["pools"]["jules-account"].pop("verified_at")
        SCHEDULER.validate_state_after_probe(before, after, probe)

        tampered = json.loads(json.dumps(after))
        tampered["pools"]["pool"]["status"] = "blocked"
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "beyond verified timestamps"
        ):
            SCHEDULER.validate_state_after_probe(before, tampered, probe)

    def test_state_validation_requires_exact_reset_after_catalog_change(self) -> None:
        probe = {
            "schema_version": 2,
            "observed_at": "2026-07-20T11:00:00Z",
            "harnesses": {},
            "providers": {},
            "verified_quota_pools": ["jules-account"],
            "api_key_environment_scrubbed": list(
                SCHEDULER.EXPECTED_ROUTER_SCRUBBED_API_KEY_ENV
            ),
            "model_invocations": 0,
            "paid_api_requests_authorized": 0,
        }
        probe["catalog_probe_sha256"] = SCHEDULER.probe_digest(probe)
        after = {
            "schema_version": 2,
            "updated_at": probe["observed_at"],
            "catalog_sha256": "new-catalog",
            "catalog": probe,
            "pools": {
                "jules-account": {"verified_at": probe["observed_at"]}
            },
            "routes": {},
            "history": self.initial["history"],
        }
        SCHEDULER.validate_state_after_probe(self.initial, after, probe)

        stale_routes = json.loads(json.dumps(after))
        stale_routes["routes"] = self.initial["routes"]
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "reset route history"
        ):
            SCHEDULER.validate_state_after_probe(self.initial, stale_routes, probe)

        stale_pools = json.loads(json.dumps(after))
        stale_pools["pools"]["pool"] = self.initial["pools"]["pool"]
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError, "reset pool state"
        ):
            SCHEDULER.validate_state_after_probe(self.initial, stale_pools, probe)

    def test_history_mutation_fails_closed_and_records_bounded_failure(self) -> None:
        self.write_router(mutate_history=True)
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("failed", failure["status"])
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_router_digest_mismatch_fails_before_execution(self) -> None:
        self.write_router()
        before = self.state.read_bytes()
        self.router_digest.write_text("0" * 64 + "\n", encoding="ascii")
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_tampered_probe_digest_fails_closed(self) -> None:
        self.write_router(tamper_digest=True)
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        failure = json.loads(self.failure.read_text(encoding="utf-8"))
        self.assertEqual("ProbeSchedulerError", failure["error_type"])
        self.assertEqual("probe_scheduler_failed_closed", failure["error"])
        self.assertFalse(self.receipt.exists())

    def test_probe_digest_safety_guard_rejects_sensitive_fields(self) -> None:
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            r"sensitive field: providers\.claude\.auth\.password",
        ):
            SCHEDULER.assert_probe_digest_safe(
                {"providers": {"claude": {"auth": {"password": "redacted"}}}}
            )
        SCHEDULER.assert_probe_digest_safe(
            {
                "api_key_environment_scrubbed": ["OPENAI_API_KEY"],
                "context_token_count": 4096,
            }
        )

    def test_lock_contention_is_a_clean_noop(self) -> None:
        self.write_router()
        descriptor = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = SCHEDULER.main(self.arguments())
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(0, result)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.failure.exists())

    def test_router_special_mode_bits_fail_before_execution(self) -> None:
        for special_bit in (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX):
            with self.subTest(special_bit=oct(special_bit)):
                self.write_router()
                os.chmod(self.router, 0o700 | special_bit)
                before = self.state.read_bytes()
                result = SCHEDULER.main(self.arguments())
                self.assertEqual(1, result)
                self.assertEqual(before, self.state.read_bytes())
                self.assertFalse(self.receipt.exists())
                self.failure.unlink(missing_ok=True)

    def test_router_digest_pin_special_mode_bits_fail_closed(self) -> None:
        for special_bit in (stat.S_ISUID, stat.S_ISGID, stat.S_ISVTX):
            with self.subTest(special_bit=oct(special_bit)):
                self.write_router()
                os.chmod(self.router_digest, 0o600 | special_bit)
                before = self.state.read_bytes()
                result = SCHEDULER.main(self.arguments())
                self.assertEqual(1, result)
                self.assertEqual(before, self.state.read_bytes())
                self.assertFalse(self.receipt.exists())
                self.failure.unlink(missing_ok=True)

    def test_router_symlink_is_rejected_before_execution(self) -> None:
        self.write_router()
        real_router = self.root / "agent-route.real"
        self.router.replace(real_router)
        self.router.symlink_to(real_router)
        before = self.state.read_bytes()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(self.receipt.exists())

    def test_state_symlink_is_rejected_before_execution(self) -> None:
        self.write_router()
        real_state = self.root / "state.real.json"
        self.state.replace(real_state)
        self.state.symlink_to(real_state)
        before = real_state.read_bytes()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, real_state.read_bytes())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_router_digest_pin_directory_fails_before_execution(self) -> None:
        self.write_router()
        before = self.state.read_bytes()
        self.router_digest.unlink()
        self.router_digest.mkdir()
        result = SCHEDULER.main(self.arguments())
        self.assertEqual(1, result)
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_unreadable_state_fails_closed(self) -> None:
        self.write_router()
        os.chmod(self.state, 0o000)
        try:
            result = SCHEDULER.main(self.arguments())
        finally:
            os.chmod(self.state, 0o600)
        self.assertEqual(1, result)
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.failure.exists())

    def test_command_output_is_rejected_before_unbounded_buffering(self) -> None:
        environment = dict(os.environ)
        programs = {
            "stdout": "import sys; sys.stdout.write('x' * 4096)",
            "stderr": "import sys; sys.stderr.write('x' * 4096)",
        }
        for stream, program in programs.items():
            with (
                self.subTest(stream=stream),
                mock.patch.object(SCHEDULER, "MAX_COMMAND_OUTPUT_BYTES", 1024),
                self.assertRaisesRegex(
                    SCHEDULER.ProbeSchedulerError,
                    "command output exceeded the limit",
                ),
            ):
                SCHEDULER.run_json_command(
                    [sys.executable, "-c", program],
                    environment=environment,
                    timeout_seconds=5,
                )

    def test_command_timeout_terminates_the_child_process_group(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            "command failed to execute",
        ):
            SCHEDULER.run_json_command(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                environment=dict(os.environ),
                timeout_seconds=1,
            )
        self.assertLess(time.monotonic() - started, 5)

    def test_termination_does_not_reap_leader_before_final_group_kill(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        events: list[tuple[str, object]] = []
        process.wait.side_effect = lambda timeout: events.append(("wait", timeout))

        with (
            mock.patch.object(
                SCHEDULER.os,
                "killpg",
                side_effect=lambda process_group_id, sent_signal: events.append(
                    ("killpg", (process_group_id, sent_signal))
                ),
            ),
            mock.patch.object(
                SCHEDULER.time,
                "sleep",
                side_effect=lambda seconds: events.append(("sleep", seconds)),
            ),
        ):
            SCHEDULER.terminate_process_group(process)

        self.assertEqual(
            [
                ("killpg", (12345, signal.SIGTERM)),
                ("sleep", SCHEDULER.PROCESS_TERMINATION_GRACE_SECONDS),
                ("killpg", (12345, signal.SIGKILL)),
                ("wait", SCHEDULER.PROCESS_TERMINATION_GRACE_SECONDS),
            ],
            events,
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
    def test_termination_preserves_descendant_grace_after_leader_exit(self) -> None:
        child_pid_path = self.root / "graceful-child.pid"
        child_ready_path = self.root / "graceful-child.ready"
        cleanup_started_path = self.root / "cleanup.started"
        cleanup_completed_path = self.root / "cleanup.completed"
        child_program = "\n".join(
            (
                "from pathlib import Path",
                "import signal, sys, time",
                "ready, started, completed = map(Path, sys.argv[1:4])",
                "def handle(signum, frame):",
                "    started.write_text('1', encoding='ascii')",
                "    time.sleep(0.15)",
                "    completed.write_text('1', encoding='ascii')",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM, handle)",
                "ready.write_text('1', encoding='ascii')",
                "time.sleep(30)",
            )
        )
        parent_program = "\n".join(
            (
                "from pathlib import Path",
                "import subprocess, sys, time",
                "pid_path, ready, started, completed = map(Path, sys.argv[1:5])",
                "child = subprocess.Popen(",
                "    [sys.executable, '-c', sys.argv[5], str(ready), str(started), str(completed)],",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "deadline = time.monotonic() + 5",
                "while not ready.exists():",
                "    if time.monotonic() >= deadline: raise SystemExit(3)",
                "    time.sleep(0.01)",
                "pid_path.write_text(str(child.pid), encoding='ascii')",
                "time.sleep(30)",
            )
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                parent_program,
                str(child_pid_path),
                str(child_ready_path),
                str(cleanup_started_path),
                str(cleanup_completed_path),
                child_program,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        child_pid = None
        try:
            child_pid = self._wait_for_positive_pid(
                child_pid_path,
                timeout_seconds=5,
            )
            self.assertEqual(process.pid, os.getpgid(process.pid))
            with mock.patch.object(SCHEDULER, "PROCESS_TERMINATION_GRACE_SECONDS", 0.5):
                SCHEDULER.terminate_process_group(process)
            self.assertTrue(cleanup_started_path.exists())
            self.assertTrue(cleanup_completed_path.exists())
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            if child_pid is not None and self._process_is_live(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc")
    def test_timeout_kills_term_resistant_descendant_after_leader_exit(self) -> None:
        child_pid_path = self.root / "term-resistant-child.pid"
        program = "\n".join(
            (
                "from pathlib import Path",
                "import signal, subprocess, sys, time",
                "child = subprocess.Popen(",
                "    [sys.executable, '-c',",
                "     'import signal, time; '",
                "     'signal.signal(signal.SIGTERM, signal.SIG_IGN); '",
                "     'time.sleep(30)'],",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "Path(sys.argv[1]).write_text(str(child.pid), encoding='ascii')",
                "time.sleep(30)",
            )
        )
        child_pid = None
        try:
            with self.assertRaisesRegex(
                SCHEDULER.ProbeSchedulerError,
                "command failed to execute",
            ):
                SCHEDULER.run_json_command(
                    [sys.executable, "-c", program, str(child_pid_path)],
                    environment=dict(os.environ),
                    timeout_seconds=2,
                )
            child_pid = self._wait_for_positive_pid(
                child_pid_path,
                timeout_seconds=3,
            )
            deadline = time.monotonic() + 5
            while self._process_is_live(child_pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(self._process_is_live(child_pid))
        finally:
            if child_pid is not None and self._process_is_live(child_pid):
                os.kill(child_pid, signal.SIGKILL)

    def test_output_reads_never_exceed_remaining_budget_plus_one(self) -> None:
        with mock.patch.object(SCHEDULER, "MAX_COMMAND_OUTPUT_BYTES", 1024):
            self.assertEqual(1025, SCHEDULER.bounded_output_read_size(0))
            self.assertEqual(25, SCHEDULER.bounded_output_read_size(1000))
            self.assertEqual(1, SCHEDULER.bounded_output_read_size(1024))
            self.assertEqual(1, SCHEDULER.bounded_output_read_size(2048))

    def test_invalid_command_json_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            SCHEDULER.ProbeSchedulerError,
            "command did not return JSON",
        ):
            SCHEDULER.run_json_command(
                [sys.executable, "-c", "print('not-json')"],
                environment=dict(os.environ),
                timeout_seconds=5,
            )

    def test_atomic_write_uses_private_mode_without_path_chmod(self) -> None:
        target = self.root / "nested" / "private.json"
        with mock.patch.object(
            SCHEDULER.os,
            "chmod",
            side_effect=AssertionError("path chmod is unsafe"),
        ):
            SCHEDULER.atomic_write_private(target, {"ok": True})
        self.assertEqual(0o600, stat.S_IMODE(target.stat().st_mode))
        self.assertEqual({"ok": True}, json.loads(target.read_text(encoding="utf-8")))

    def test_safe_unlink_tolerates_disappearance_after_lstat(self) -> None:
        target = self.root / "vanishing.json"
        target.write_text("{}", encoding="utf-8")
        with mock.patch.object(Path, "unlink", side_effect=FileNotFoundError):
            SCHEDULER.safe_unlink(target)


if __name__ == "__main__":
    unittest.main()
