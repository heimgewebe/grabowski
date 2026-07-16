from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_client_snapshot as snapshot


TOOL_HASH = "a" * 64
INSTRUCTIONS_HASH = "b" * 64
RELEASE_ID = "release-test"
REPO_HEAD = "c" * 40


class ClientSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name) / "client-snapshot"
        self.patches = (
            mock.patch.object(snapshot, "STATE_ROOT", root),
            mock.patch.object(snapshot, "SNAPSHOT_PATH", root / "current.json"),
            mock.patch.object(snapshot, "LOCK_PATH", root / ".lock"),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def parameters(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "client_id": "chatgpt-api-tool",
            "session_id": "session-1",
            "observed_tool_count": 140,
            "observed_names_sha256": TOOL_HASH,
            "observed_release_id": RELEASE_ID,
            "observed_agent_instructions_sha256": INSTRUCTIONS_HASH,
            "_server_tool_contract": {
                "registered_tool_count": 140,
                "registered_names_sha256": TOOL_HASH,
                "runtime_matches_deployment_contract": True,
            },
            "_server_runtime": {
                "release_id": RELEASE_ID,
                "repo_head": REPO_HEAD,
            },
            "_server_agent_instructions_sha256": INSTRUCTIONS_HASH,
        }
        value.update(overrides)
        return value

    def status(self, *, now_unix: int = 1_100) -> dict[str, object]:
        return snapshot.snapshot_status(
            expected_tool_count=140,
            expected_names_sha256=TOOL_HASH,
            expected_release_id=RELEASE_ID,
            expected_repo_head=REPO_HEAD,
            expected_agent_instructions_sha256=INSTRUCTIONS_HASH,
            now_unix=now_unix,
        )

    def test_matching_snapshot_is_fresh_and_observable(self) -> None:
        result = snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

        self.assertTrue(result["verified"])
        self.assertEqual(result["state"], "matched")
        observed = self.status()
        self.assertEqual(observed["state"], "matched")
        self.assertTrue(observed["observable"])
        self.assertTrue(observed["fresh"])
        self.assertTrue(observed["matched"])
        self.assertEqual(snapshot.SNAPSHOT_PATH.stat().st_mode & 0o777, 0o600)

    def test_mismatch_is_persisted_but_never_observable(self) -> None:
        result = snapshot.bind_snapshot(
            self.parameters(observed_tool_count=139),
            now_unix=1_000,
        )

        self.assertFalse(result["verified"])
        self.assertEqual(result["mismatches"], ["tool_count"])
        observed = self.status()
        self.assertEqual(observed["state"], "mismatch")
        self.assertFalse(observed["observable"])

    def test_stale_snapshot_is_not_observable(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

        observed = self.status(
            now_unix=1_000 + snapshot.SNAPSHOT_TTL_SECONDS + 1
        )
        self.assertEqual(observed["state"], "stale")
        self.assertFalse(observed["observable"])
        self.assertFalse(observed["fresh"])

    def test_tampered_receipt_fails_closed(self) -> None:
        snapshot.bind_snapshot(self.parameters(), now_unix=1_000)
        document = json.loads(snapshot.SNAPSHOT_PATH.read_text(encoding="utf-8"))
        document["verified"] = False
        snapshot.SNAPSHOT_PATH.write_text(
            json.dumps(document),
            encoding="utf-8",
        )
        snapshot.SNAPSHOT_PATH.chmod(0o600)

        observed = self.status()
        self.assertEqual(observed["state"], "invalid")
        self.assertFalse(observed["observable"])

    def test_symlink_receipt_is_rejected(self) -> None:
        snapshot.STATE_ROOT.mkdir(mode=0o700, parents=True)
        target = snapshot.STATE_ROOT / "target.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o600)
        snapshot.SNAPSHOT_PATH.symlink_to(target.name)

        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(self.parameters(), now_unix=1_000)

    def test_server_context_cannot_be_omitted_or_spoofed_by_shape(self) -> None:
        parameters = self.parameters()
        parameters.pop("_server_tool_contract")
        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(parameters, now_unix=1_000)

        parameters = self.parameters(
            _server_tool_contract={
                "registered_tool_count": 140,
                "registered_names_sha256": TOOL_HASH,
                "runtime_matches_deployment_contract": False,
            }
        )
        with self.assertRaises(snapshot.ClientSnapshotError):
            snapshot.bind_snapshot(parameters, now_unix=1_000)


if __name__ == "__main__":
    unittest.main()
