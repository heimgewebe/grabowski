from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
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

    def write_router(
        self, *, mutate_history: bool = False, tamper_digest: bool = False
    ) -> None:
        program = f"""\
#!/usr/bin/env python3
import hashlib
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
        "api_key_environment_scrubbed": [],
    }}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    body["catalog_probe_sha256"] = hashlib.sha256(canonical).hexdigest()
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
