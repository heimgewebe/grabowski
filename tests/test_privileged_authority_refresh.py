from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

priv = importlib.import_module("grabowski_privileged")


class FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = response

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def settimeout(self, value: float) -> None:
        pass

    def connect(self, value: object) -> None:
        pass

    def sendall(self, value: bytes) -> None:
        pass

    def shutdown(self, value: int) -> None:
        pass

    def recv(self, size: int) -> bytes:
        value, self.response = self.response, b""
        return value


class RootbrokerAuthorityRefreshTests(unittest.TestCase):
    def test_same_head_short_circuits_without_force(self) -> None:
        head = "a" * 40
        with patch.object(
            priv.operator, "_require_operator_capability"
        ), patch.object(
            priv, "_operator_authority_attestation_head", return_value=head
        ), patch.object(priv, "_privileged_broker_status") as broker:
            result = priv.ensure_rootbroker_authority(head)
        self.assertEqual(result["outcome"], "already_current")
        self.assertFalse(result["force_refresh"])
        broker.assert_not_called()

    def test_force_refresh_executes_even_when_attestation_head_matches(self) -> None:
        head = "a" * 40
        response = json.dumps({"returncode": 0, "stderr": ""}).encode() + b"\n"
        reference = {"request_id": "b" * 32, "reference_sha256": "c" * 64}
        with patch.object(
            priv.operator, "_require_operator_capability"
        ), patch.object(
            priv, "_operator_authority_attestation_head", side_effect=[head, head]
        ), patch.object(
            priv, "_privileged_broker_status", return_value={"ready": True}
        ), patch.object(
            priv, "_create_privileged_reference", return_value=reference
        ) as create, patch.object(
            priv.socket, "socket", return_value=FakeSocket(response)
        ), patch.object(priv, "_append_operator_audit"):
            result = priv.ensure_rootbroker_authority(head, force_refresh=True)
        self.assertTrue(result["success"])
        self.assertTrue(result["force_refresh"])
        self.assertEqual(create.call_args.kwargs["target"], head)


if __name__ == "__main__":
    unittest.main()
