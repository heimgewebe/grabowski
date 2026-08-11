from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "grabowski_transport_assertion_filter_test_module",
    ROOT / "src/grabowski_transport_assertion.py",
)
assert SPEC is not None and SPEC.loader is not None
assertion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assertion)

SECRET = "A" * 43
SCOPE = "1" * 64
RUNTIME = "2" * 64
ARGS = assertion.canonical_arguments_sha256({"argv": ["true"]})


def _evidence(index: int, *, now: int = 100) -> dict[str, object]:
    request_id = f"{index + 1:032x}"
    body = hashlib.sha256(f"body-{index}".encode()).hexdigest()
    mac = assertion.assertion_mac(
        secret=SECRET,
        request_id=request_id,
        issued_at_unix=now,
        audience=assertion.ASSERTION_AUDIENCE,
        tool_name="grabowski_terminal_run",
        arguments_sha256=ARGS,
        body_sha256=body,
        runtime_binding_sha256=RUNTIME,
    )
    return {
        "secret": SECRET,
        "client_scope_sha256": SCOPE,
        "runtime_binding_sha256": RUNTIME,
        "asserted_runtime_binding_sha256": RUNTIME,
        "request_id": request_id,
        "issued_at_unix": now,
        "audience": assertion.ASSERTION_AUDIENCE,
        "tool_name": "grabowski_terminal_run",
        "arguments_sha256": ARGS,
        "body_sha256": body,
        "mac_sha256": mac,
    }


class ReplayFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        assertion.STATE_ROOT = root
        assertion.LOCK_PATH = root / ".lock"

    def test_fixed_size_single_file_and_replay(self) -> None:
        for index in range(256):
            assertion.consume_assertion(**_evidence(index), now_unix=101)
        path = assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME
        self.assertEqual(path.stat().st_size, assertion.REPLAY_FILTER_TOTAL_BYTES)
        self.assertEqual(
            sorted(item.name for item in assertion.STATE_ROOT.iterdir()),
            [".lock", assertion.REPLAY_FILTER_FILENAME],
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**_evidence(17, now=5000), now_unix=5001)

    def test_replay_filter_survives_client_scope_restart(self) -> None:
        first = _evidence(4)
        assertion.consume_assertion(**first, now_unix=101)
        restarted = dict(first)
        restarted["client_scope_sha256"] = "3" * 64
        restarted["issued_at_unix"] = 5000
        restarted["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(restarted["request_id"]),
            issued_at_unix=5000,
            audience=assertion.ASSERTION_AUDIENCE,
            tool_name="grabowski_terminal_run",
            arguments_sha256=ARGS,
            body_sha256=str(restarted["body_sha256"]),
            runtime_binding_sha256=RUNTIME,
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**restarted, now_unix=5001)

    def test_legacy_tombstone_remains_authoritative(self) -> None:
        item = _evidence(2)
        assertion.STATE_ROOT.mkdir(mode=0o700)
        scope_dir = assertion.STATE_ROOT / SCOPE
        scope_dir.mkdir(mode=0o700)
        receipt = {
            "request_id": item["request_id"],
            "client_scope_sha256": SCOPE,
            "tool_name": item["tool_name"],
            "arguments_sha256": item["arguments_sha256"],
            "body_sha256": item["body_sha256"],
            "runtime_binding_sha256": RUNTIME,
        }
        path = scope_dir / f"{item['request_id']}.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**item, now_unix=101)
        self.assertFalse((assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME).exists())

    def test_corrupt_existing_filter_fails_closed(self) -> None:
        assertion.STATE_ROOT.mkdir(mode=0o700)
        path = assertion.STATE_ROOT / assertion.REPLAY_FILTER_FILENAME
        with path.open("wb") as handle:
            handle.truncate(assertion.REPLAY_FILTER_TOTAL_BYTES)
        path.chmod(0o600)
        with self.assertRaisesRegex(assertion.TransportAssertionError, "header mismatch"):
            assertion.consume_assertion(**_evidence(9), now_unix=101)


if __name__ == "__main__":
    unittest.main()
