from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_transport_roundtrip as roundtrip


BINDING = {
    "release_id": "release-1",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}
META_SCOPE = {"kind": "connector_session", "label": "mcp-client-1-session-1"}
FIRST_INTENT = {
    "tool_name": "first-write",
    "arguments_sha256": "d" * 64,
}
SECOND_INTENT = {
    "tool_name": "second-write",
    "arguments_sha256": "e" * 64,
}


class IntentReplacementRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        self.state_root_patch = mock.patch.object(roundtrip, "STATE_ROOT", root)
        self.lock_path_patch = mock.patch.object(
            roundtrip,
            "LOCK_PATH",
            root / ".lock",
        )
        self.state_root_patch.start()
        self.lock_path_patch.start()
        self.addCleanup(self.state_root_patch.stop)
        self.addCleanup(self.lock_path_patch.stop)

    def begin(
        self,
        intent: dict[str, str] | None,
        *,
        now: int,
    ) -> dict[str, object]:
        return roundtrip.begin(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=now,
        )

    def acknowledge(
        self,
        challenge_receipt_sha256: str,
        *,
        now: int,
    ) -> dict[str, object]:
        return roundtrip.acknowledge(
            client_scope=META_SCOPE,
            challenge_receipt_sha256=challenge_receipt_sha256,
            runtime_binding=BINDING,
            now_unix=now,
        )

    def consume(
        self,
        intent: dict[str, str],
        *,
        now: int,
    ) -> dict[str, object]:
        return roundtrip.consume_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name=intent["tool_name"],
            arguments_sha256=intent["arguments_sha256"],
            now_unix=now,
        )

    def test_pending_exact_intent_is_idempotent_and_consumable(self) -> None:
        pending = self.begin(FIRST_INTENT, now=100)
        replay = self.begin(FIRST_INTENT, now=101)

        self.assertFalse(pending["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            replay["challenge_receipt_sha256"],
            pending["challenge_receipt_sha256"],
        )
        self.assertEqual(pending["pending_challenge_count"], 1)
        self.assertEqual(pending["verified_receipt_count"], 0)

        verified = self.acknowledge(
            str(pending["challenge_receipt_sha256"]),
            now=102,
        )
        consumed = self.consume(FIRST_INTENT, now=103)

        self.assertEqual(consumed["state"], "consumed")
        self.assertTrue(consumed["verification_was_intent_bound"])
        self.assertEqual(
            consumed["verification_receipt_sha256"],
            verified["verification_receipt_sha256"],
        )

    def test_exact_verified_intent_is_replayed_and_consumable(self) -> None:
        pending = self.begin(FIRST_INTENT, now=100)
        verified = self.acknowledge(
            str(pending["challenge_receipt_sha256"]),
            now=101,
        )
        replay = self.begin(FIRST_INTENT, now=102)

        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["state"], "verified")
        self.assertEqual(replay["pending_challenge_count"], 0)
        self.assertEqual(replay["verified_receipt_count"], 1)
        self.assertEqual(
            replay["verification_receipt_sha256"],
            verified["verification_receipt_sha256"],
        )

        consumed = self.consume(FIRST_INTENT, now=103)
        self.assertEqual(
            consumed["verification_receipt_sha256"],
            verified["verification_receipt_sha256"],
        )

    def test_verified_second_intent_preserves_the_first_exact_intent(self) -> None:
        first = self.begin(FIRST_INTENT, now=100)
        first_verified = self.acknowledge(
            str(first["challenge_receipt_sha256"]),
            now=101,
        )
        second = self.begin(SECOND_INTENT, now=102)

        self.assertEqual(second["state"], "challenge_pending")
        self.assertEqual(second["verified_receipt_count"], 1)
        first_consumed = self.consume(FIRST_INTENT, now=103)
        self.assertEqual(
            first_consumed["verification_receipt_sha256"],
            first_verified["verification_receipt_sha256"],
        )

        second_verified = self.acknowledge(
            str(second["challenge_receipt_sha256"]),
            now=104,
        )
        consumed = self.consume(SECOND_INTENT, now=105)

        self.assertNotEqual(
            first_verified["verification_receipt_sha256"],
            second_verified["verification_receipt_sha256"],
        )
        self.assertEqual(
            consumed["verification_receipt_sha256"],
            second_verified["verification_receipt_sha256"],
        )
        self.assertEqual(consumed["tool_name"], SECOND_INTENT["tool_name"])
        self.assertEqual(
            consumed["arguments_sha256"],
            SECOND_INTENT["arguments_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
