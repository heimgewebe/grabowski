from __future__ import annotations

import ast
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import grabowski_n8n_runtime as runtime


PROFILE = runtime.FORREST_PROFILE
SECRET_PATH = runtime.FORREST_SECRET_PATH
SECRET_SHA = "a" * 64
RESPONSE_SHA = "b" * 64
SECRET_DATA = b"synthetic-api-key"


def secret_snapshot() -> dict:
    return {
        "source_path": SECRET_PATH,
        "data": SECRET_DATA,
        "sha256": SECRET_SHA,
        "size": len(SECRET_DATA),
    }


class N8nRuntimeTests(unittest.TestCase):
    def test_runtime_has_no_mcp_or_grips_import(self) -> None:
        tree = ast.parse(Path(runtime.__file__).read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertNotIn("grabowski_mcp", imported)
        self.assertNotIn("grabowski_grips", imported)

    def test_verify_is_locally_read_only(self) -> None:
        request = {
            "provider_profile": PROFILE,
            "secret_path": SECRET_PATH,
            "expected_secret_sha256": SECRET_SHA,
            "expected_state": "isolated",
        }
        provider_output = {
            "ok": True,
            "mode": "verify",
            "providerProfile": PROFILE,
            "providerMutationPerformed": False,
            "observed": {"state": "isolated", "responseSha256": RESPONSE_SHA},
        }
        loader = Mock(return_value=secret_snapshot())
        recorder = Mock(side_effect=AssertionError("verify must not record apply audit"))
        with patch.object(runtime.provider, "verify", return_value=provider_output):
            result = runtime.dispatch(
                "verify",
                request,
                secret_loader=loader,
                apply_recorder=recorder,
            )
        self.assertEqual(provider_output, result)
        loader.assert_called_once_with("verify", SECRET_PATH, SECRET_SHA)
        recorder.assert_not_called()
        self.assertNotIn("auditRecordSha256", result)

    def test_apply_keeps_local_audit_receipt_without_secret_bytes_in_recorder(self) -> None:
        request = {
            "provider_profile": PROFILE,
            "secret_path": SECRET_PATH,
            "expected_secret_sha256": SECRET_SHA,
            "expected_version_id": "version-1",
            "expected_response_sha256": RESPONSE_SHA,
        }
        provider_output = {
            "ok": True,
            "mode": "apply",
            "providerProfile": PROFILE,
            "providerMutationPerformed": True,
        }
        loader = Mock(return_value=secret_snapshot())
        recorder = Mock(return_value="c" * 64)
        with patch.object(runtime.provider, "apply", return_value=provider_output):
            result = runtime.dispatch(
                "apply",
                request,
                secret_loader=loader,
                apply_recorder=recorder,
            )
        loader.assert_called_once_with("apply", SECRET_PATH, SECRET_SHA)
        recorder.assert_called_once()
        action, metadata, output = recorder.call_args.args
        self.assertEqual("apply", action)
        self.assertNotIn("data", metadata)
        self.assertEqual(SECRET_PATH, metadata["source_path"])
        self.assertEqual(SECRET_SHA, metadata["sha256"])
        self.assertEqual(len(SECRET_DATA), metadata["size"])
        self.assertIs(provider_output, output)
        self.assertEqual("c" * 64, result["auditRecordSha256"])

    def test_apply_without_recorder_fails_before_provider_effect(self) -> None:
        request = {
            "provider_profile": PROFILE,
            "secret_path": SECRET_PATH,
            "expected_secret_sha256": SECRET_SHA,
            "expected_version_id": "version-1",
            "expected_response_sha256": RESPONSE_SHA,
        }
        loader = Mock(return_value=secret_snapshot())
        with patch.object(runtime.provider, "apply") as apply:
            with self.assertRaisesRegex(runtime.N8nRuntimeError, "apply recorder"):
                runtime.dispatch("apply", request, secret_loader=loader)
        apply.assert_not_called()
        loader.assert_not_called()

    def test_loader_identity_drift_fails_before_provider_effect(self) -> None:
        request = {
            "provider_profile": PROFILE,
            "secret_path": SECRET_PATH,
            "expected_secret_sha256": SECRET_SHA,
            "expected_state": "isolated",
        }
        snapshot = secret_snapshot()
        snapshot["source_path"] = "/tmp/wrong"
        with patch.object(runtime.provider, "verify") as verify:
            with self.assertRaisesRegex(runtime.N8nRuntimeError, "path changed"):
                runtime.dispatch(
                    "verify",
                    request,
                    secret_loader=Mock(return_value=snapshot),
                )
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
