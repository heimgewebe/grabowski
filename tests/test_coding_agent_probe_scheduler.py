from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest


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


if __name__ == "__main__":
    unittest.main()
