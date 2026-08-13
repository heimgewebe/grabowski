from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

import grabowski_n8n_runtime as runtime


PROFILE = runtime.FORREST_PROFILE
SECRET_PATH = runtime.FORREST_SECRET_PATH
SECRET_SHA = "a" * 64
RESPONSE_SHA = "b" * 64


grabowski_mcp = types.ModuleType("grabowski_mcp")
grabowski_mcp._require_capability = lambda *_a, **_k: None
grabowski_mcp._require_valid_audit_chain = lambda *_a, **_k: None
grabowski_mcp._require_mutations_enabled = lambda *_a, **_k: None
grabowski_mcp._resolve_secret_use_source = lambda *_a, **_k: Path(SECRET_PATH)
grabowski_mcp._load_policy = lambda: {}
grabowski_mcp._policy_limit = lambda *_a, **_k: 1024
grabowski_mcp._read_bound_regular_bytes = lambda *_a, **_k: {"data": b"synthetic-api-key", "sha256": SECRET_SHA, "size": 17}
grabowski_mcp._new_transaction_dir = lambda *_a, **_k: ("transaction-1", Path("/tmp/transaction-1"))
grabowski_mcp._write_json_evidence = lambda *_a, **_k: None
grabowski_mcp._append_audit_with_digest = lambda *_a, **_k: "c" * 64
grabowski_mcp._utc_timestamp = lambda: "2026-08-13T17:00:00Z"
grabowski_mcp.grabowski_grips = types.SimpleNamespace(sha256_json=lambda _value: "d" * 64)


class N8nRuntimeTests(unittest.TestCase):
    def _enter_secret_patches(self, stack: ExitStack) -> None:
        stack.enter_context(
            patch.object(
                grabowski_mcp,
                "_resolve_secret_use_source",
                return_value=Path(SECRET_PATH),
            )
        )
        stack.enter_context(patch.object(grabowski_mcp, "_load_policy", return_value={}))
        stack.enter_context(patch.object(grabowski_mcp, "_policy_limit", return_value=1024))
        stack.enter_context(
            patch.object(
                grabowski_mcp,
                "_read_bound_regular_bytes",
                return_value={
                    "data": b"synthetic-api-key",
                    "sha256": SECRET_SHA,
                    "size": len(b"synthetic-api-key"),
                },
            )
        )

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
        with ExitStack() as stack:
            require_capability = stack.enter_context(
                patch.object(grabowski_mcp, "_require_capability")
            )
            require_audit = stack.enter_context(
                patch.object(grabowski_mcp, "_require_valid_audit_chain")
            )
            self._enter_secret_patches(stack)
            stack.enter_context(patch.dict(sys.modules, {"grabowski_mcp": grabowski_mcp}))
            stack.enter_context(
                patch.object(runtime.provider, "verify", return_value=provider_output)
            )
            stack.enter_context(
                patch.object(
                    grabowski_mcp,
                    "_new_transaction_dir",
                    side_effect=AssertionError(
                        "read-only verify must not create transaction state"
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    grabowski_mcp,
                    "_write_json_evidence",
                    side_effect=AssertionError(
                        "read-only verify must not write evidence state"
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    grabowski_mcp,
                    "_append_audit_with_digest",
                    side_effect=AssertionError(
                        "read-only verify must not append audit state"
                    ),
                )
            )
            result = runtime.dispatch("verify", request)

        self.assertEqual(provider_output, result)
        require_capability.assert_called_once_with("secret_use")
        require_audit.assert_called_once_with()
        self.assertNotIn("auditRecordSha256", result)

    def test_apply_keeps_local_audit_receipt(self) -> None:
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
        with ExitStack() as stack:
            require_mutations = stack.enter_context(
                patch.object(grabowski_mcp, "_require_mutations_enabled")
            )
            self._enter_secret_patches(stack)
            stack.enter_context(patch.dict(sys.modules, {"grabowski_mcp": grabowski_mcp}))
            stack.enter_context(
                patch.object(runtime.provider, "apply", return_value=provider_output)
            )
            stack.enter_context(
                patch.object(
                    grabowski_mcp,
                    "_new_transaction_dir",
                    return_value=("transaction-1", Path("/tmp/transaction-1")),
                )
            )
            write_evidence = stack.enter_context(
                patch.object(grabowski_mcp, "_write_json_evidence")
            )
            append_audit = stack.enter_context(
                patch.object(
                    grabowski_mcp,
                    "_append_audit_with_digest",
                    return_value="c" * 64,
                )
            )
            result = runtime.dispatch("apply", request)

        require_mutations.assert_called_once_with(
            "secret_use",
            path=SECRET_PATH,
            fresh_preflight=True,
        )
        write_evidence.assert_called_once()
        append_audit.assert_called_once()
        self.assertEqual("c" * 64, result["auditRecordSha256"])


if __name__ == "__main__":
    unittest.main()
