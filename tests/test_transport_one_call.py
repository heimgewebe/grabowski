from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import types
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# make validate intentionally runs without runtime dependencies installed.
# Bind the branch modules to the same minimal MCP double used by the operator
# contract suite so this test cannot accidentally exercise a deployed runtime.
from test_operator_contract import _FakeFastMCP, _FakeToolAnnotations

_mcp_names = ("mcp", "mcp.server", "mcp.server.fastmcp", "mcp.types")
_previous_mcp = {name: sys.modules.get(name) for name in _mcp_names}
_fake_mcp = types.ModuleType("mcp")
_fake_server = types.ModuleType("mcp.server")
_fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
_fake_types = types.ModuleType("mcp.types")
_fake_fastmcp.FastMCP = _FakeFastMCP
_fake_types.ToolAnnotations = _FakeToolAnnotations
sys.modules.update(
    {
        "mcp": _fake_mcp,
        "mcp.server": _fake_server,
        "mcp.server.fastmcp": _fake_fastmcp,
        "mcp.types": _fake_types,
    }
)
try:
    import grabowski_mcp as base
    import grabowski_operator as operator
    import grabowski_transport_assertion as assertion
    import grabowski_transport_roundtrip as roundtrip
finally:
    for _name, _previous in _previous_mcp.items():
        if _previous is None:
            sys.modules.pop(_name, None)
        else:
            sys.modules[_name] = _previous

SPEC = importlib.util.spec_from_file_location(
    "grabowski_transport_ingress_test_module",
    ROOT / "tools/grabowski_transport_ingress.py",
)
assert SPEC is not None and SPEC.loader is not None
ingress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingress)

SECRET = "A" * 43
SCOPE = {"kind": "connector_capability", "label": "connector-scope-test"}
BINDING = {
    "release_id": "release-test",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}


def _runtime_sha256() -> str:
    return assertion.runtime_binding_sha256(BINDING)


def _tool_body(arguments: dict[str, object] | None = None, request_id: int = 7) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "grabowski_terminal_run",
                "arguments": arguments or {"argv": ["true"]},
            },
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _ctx(headers: dict[str, str]) -> SimpleNamespace:
    return SimpleNamespace(
        request_context=SimpleNamespace(
            request=SimpleNamespace(headers=headers)
        )
    )


class TransportAssertionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        self.state_patch = mock.patch.object(assertion, "STATE_ROOT", root)
        self.lock_patch = mock.patch.object(assertion, "LOCK_PATH", root / ".lock")
        self.state_patch.start()
        self.lock_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.addCleanup(self.lock_patch.stop)

    def _evidence(self, *, now: int = 100) -> dict[str, object]:
        body = _tool_body()
        headers = ingress.signed_tool_headers(
            token=SECRET,
            body=body,
            session_id="session-1",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=now,
        )
        args_hash = assertion.canonical_arguments_sha256({"argv": ["true"]})
        return {
            "secret": SECRET,
            "client_scope_sha256": roundtrip.client_scope_sha256(SCOPE),
            "runtime_binding_sha256": _runtime_sha256(),
            "asserted_runtime_binding_sha256": headers[
                ingress.RUNTIME_BINDING_SHA256_HEADER
            ],
            "request_id": headers[ingress.REQUEST_ID_HEADER],
            "issued_at_unix": now,
            "audience": headers[ingress.REQUEST_AUDIENCE_HEADER],
            "tool_name": "grabowski_terminal_run",
            "arguments_sha256": args_hash,
            "body_sha256": headers[ingress.REQUEST_BODY_SHA256_HEADER],
            "mac_sha256": headers[ingress.REQUEST_MAC_HEADER],
        }

    def test_valid_assertion_is_consumed_once(self) -> None:
        evidence = assertion.consume_assertion(**self._evidence(), now_unix=101)
        self.assertEqual(evidence["state"], "consumed")
        self.assertEqual(evidence["transport_mode"], assertion.ASSERTION_VERSION)
        self.assertRegex(evidence["consumption_receipt_sha256"], r"^[0-9a-f]{64}$")
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**self._evidence(), now_unix=102)

    def test_mac_tampering_fails_before_replay_state(self) -> None:
        evidence = self._evidence()
        evidence["arguments_sha256"] = "d" * 64
        with self.assertRaisesRegex(assertion.TransportAssertionError, "MAC mismatch"):
            assertion.consume_assertion(**evidence, now_unix=101)

    def test_runtime_binding_tampering_fails_closed(self) -> None:
        evidence = self._evidence()
        evidence["asserted_runtime_binding_sha256"] = "e" * 64
        with self.assertRaisesRegex(assertion.TransportAssertionError, "MAC mismatch"):
            assertion.consume_assertion(**evidence, now_unix=101)

    def test_stale_assertion_fails(self) -> None:
        with self.assertRaisesRegex(assertion.TransportAssertionError, "stale"):
            assertion.consume_assertion(
                **self._evidence(now=100),
                now_unix=100 + assertion.ASSERTION_MAX_AGE_SECONDS + 1,
            )

    def test_replay_tombstone_survives_original_retention_window(self) -> None:
        first = self._evidence(now=100)
        assertion.consume_assertion(**first, now_unix=101)
        later = self._evidence(now=100 + assertion.REPLAY_RETENTION_SECONDS + 1000)
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(
                **later, now_unix=100 + assertion.REPLAY_RETENTION_SECONDS + 1001
            )

    def test_request_id_is_retry_stable_and_payload_bound(self) -> None:
        first = ingress.signed_tool_headers(
            token=SECRET,
            body=_tool_body({"argv": ["true"]}),
            session_id="session-1",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=100,
        )
        replay = ingress.signed_tool_headers(
            token=SECRET,
            body=_tool_body({"argv": ["true"]}),
            session_id="session-1",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=101,
        )
        changed = ingress.signed_tool_headers(
            token=SECRET,
            body=_tool_body({"argv": ["false"]}),
            session_id="session-1",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=101,
        )
        self.assertEqual(first[ingress.REQUEST_ID_HEADER], replay[ingress.REQUEST_ID_HEADER])
        self.assertNotEqual(first[ingress.REQUEST_ID_HEADER], changed[ingress.REQUEST_ID_HEADER])
        self.assertNotEqual(first[ingress.REQUEST_MAC_HEADER], replay[ingress.REQUEST_MAC_HEADER])


class TransportIngressTests(unittest.TestCase):
    def test_ingress_client_authentication_is_secret_bound(self) -> None:
        self.assertFalse(ingress._ingress_client_authenticated({}, SECRET))
        self.assertFalse(
            ingress._ingress_client_authenticated(
                {ingress.INGRESS_AUTH_HEADER: "not-the-owner-secret"}, SECRET
            )
        )
        self.assertTrue(
            ingress._ingress_client_authenticated(
                {ingress.INGRESS_AUTH_HEADER: SECRET}, SECRET
            )
        )

    def test_managed_headers_from_caller_are_stripped(self) -> None:
        request = SimpleNamespace(
            headers={
                "host": "127.0.0.1:18180",
                "content-type": "application/json",
                "x-grabowski-request-mac": "attacker",
                "x-grabowski-connector-capability": "attacker",
                "x-grabowski-ingress-auth": "attacker",
            }
        )
        headers = ingress._forward_headers(request, SECRET)
        self.assertEqual(headers[ingress.CAPABILITY_HEADER], SECRET)
        self.assertEqual(headers[ingress.INGRESS_VERSION_HEADER], assertion.ASSERTION_VERSION)
        self.assertNotEqual(headers.get(ingress.REQUEST_MAC_HEADER), "attacker")
        self.assertEqual(headers.get("content-type"), "application/json")

    def test_runtime_binding_is_derived_from_immutable_release_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            releases = home / "releases"
            release_id = "release-abc"
            release = releases / release_id
            release.mkdir(parents=True)
            manifest = release / "deployment-manifest.json"
            value = {
                "completion_status": "complete",
                "release_id": release_id,
                "repo_head": "a" * 40,
                "agent_instructions": {"sha256": "c" * 64},
                "entrypoint_contract": {
                    "expected_tools": ["tool_b", "tool_a"]
                },
            }
            manifest.write_text(json.dumps(value), encoding="utf-8")
            manifest.chmod(0o600)
            pointer = home / "deployment-manifest.json"
            pointer.symlink_to(manifest)
            with mock.patch.object(ingress, "DEPLOYMENT_RELEASE_ROOT", releases):
                binding, digest = ingress._read_runtime_binding(pointer)
            expected_names = hashlib.sha256(
                json.dumps(
                    ["tool_a", "tool_b"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(expected_names, binding["registered_names_sha256"] )
            self.assertEqual(assertion.runtime_binding_sha256(binding), digest)

    def test_tools_call_without_jsonrpc_id_is_rejected(self) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "grabowski_terminal_run", "arguments": {}},
            }
        ).encode()
        with self.assertRaisesRegex(ValueError, "request id"):
            ingress.signed_tool_headers(
                token=SECRET,
                body=body,
                session_id="session-1",
                runtime_binding_sha256=_runtime_sha256(),
                now_unix=100,
            )


class OperatorSignedTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        patches = [
            mock.patch.object(assertion, "STATE_ROOT", root),
            mock.patch.object(assertion, "LOCK_PATH", root / ".lock"),
            mock.patch.object(base, "_transport_connector_capability_scope", return_value=SCOPE),
            mock.patch.object(operator, "_require_current_serving_process", return_value=None),
            mock.patch.object(base, "_transport_roundtrip_runtime_binding", return_value=BINDING),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_operator_prefers_signed_one_call_without_roundtrip(self) -> None:
        arguments = {"argv": ["true"]}
        body = _tool_body(arguments)
        signed = ingress.signed_tool_headers(
            token=SECRET,
            body=body,
            session_id="session-1",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=int(__import__("time").time()),
        )
        headers = {
            base._TRANSPORT_CONNECTOR_CAPABILITY_HEADER: SECRET,
            base._TRANSPORT_INGRESS_VERSION_HEADER: assertion.ASSERTION_VERSION,
            base._TRANSPORT_REQUEST_ID_HEADER: signed[ingress.REQUEST_ID_HEADER],
            base._TRANSPORT_REQUEST_TIMESTAMP_HEADER: signed[ingress.REQUEST_TIMESTAMP_HEADER],
            base._TRANSPORT_REQUEST_AUDIENCE_HEADER: signed[ingress.REQUEST_AUDIENCE_HEADER],
            base._TRANSPORT_REQUEST_BODY_SHA256_HEADER: signed[ingress.REQUEST_BODY_SHA256_HEADER],
            base._TRANSPORT_RUNTIME_BINDING_SHA256_HEADER: signed[
                ingress.RUNTIME_BINDING_SHA256_HEADER
            ],
            base._TRANSPORT_REQUEST_MAC_HEADER: signed[ingress.REQUEST_MAC_HEADER],
        }
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        with mock.patch.object(
            roundtrip,
            "consume_verified",
            side_effect=AssertionError("legacy roundtrip must not run"),
        ):
            evidence = operator._require_transport_roundtrip_for_tool(
                tool_name="grabowski_terminal_run",
                arguments=arguments,
                context=_ctx(headers),
                tool=tool,
            )
        self.assertEqual(evidence["transport_mode"], assertion.ASSERTION_VERSION)
        self.assertEqual(evidence["client_scope_kind"], "connector_capability")


if __name__ == "__main__":
    unittest.main()
