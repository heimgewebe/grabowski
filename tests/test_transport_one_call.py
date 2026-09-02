from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import types
import tempfile
import threading
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
_previous_grabowski = {
    name: module
    for name, module in sys.modules.items()
    if name.startswith("grabowski_")
}
for _name in _previous_grabowski:
    sys.modules.pop(_name, None)
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

    SPEC = importlib.util.spec_from_file_location(
        "grabowski_transport_ingress_test_module",
        ROOT / "tools/grabowski_transport_ingress.py",
    )
    assert SPEC is not None and SPEC.loader is not None
    ingress = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(ingress)
finally:
    for _name, _previous in _previous_mcp.items():
        if _previous is None:
            sys.modules.pop(_name, None)
        else:
            sys.modules[_name] = _previous
    for _name in tuple(sys.modules):
        if _name.startswith("grabowski_") and _name not in _previous_grabowski:
            sys.modules.pop(_name, None)
    sys.modules.update(_previous_grabowski)

SECRET = "A" * 43
FOREIGN_SECRET = "B" * 43
SCOPE = {"kind": "connector_capability", "label": "connector-scope-test"}
BINDING = {
    "release_id": "release-test",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}


def _runtime_sha256() -> str:
    return assertion.runtime_binding_sha256(BINDING)


def _tool_body(
    arguments: dict[str, object] | None = None, request_id: int = 7
) -> bytes:
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
        request_context=SimpleNamespace(request=SimpleNamespace(headers=headers))
    )


class _FakeJSONResponse:
    def __init__(self, content: object, *, status_code: int = 200) -> None:
        self.status_code = status_code
        self.body = json.dumps(content, separators=(",", ":")).encode("utf-8")


def _run_locally_rejected_proxy(
    proxy: ingress.TransportIngress, request: object
) -> _FakeJSONResponse:
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.AsyncClient = mock.Mock(
        side_effect=AssertionError("local rejection constructed outbound client")
    )
    fake_starlette = types.ModuleType("starlette")
    fake_background = types.ModuleType("starlette.background")
    fake_background.BackgroundTask = object
    fake_responses = types.ModuleType("starlette.responses")
    fake_responses.JSONResponse = _FakeJSONResponse
    fake_responses.StreamingResponse = object
    fake_starlette.background = fake_background
    fake_starlette.responses = fake_responses
    with mock.patch.dict(
        sys.modules,
        {
            "httpx": fake_httpx,
            "starlette": fake_starlette,
            "starlette.background": fake_background,
            "starlette.responses": fake_responses,
        },
    ):
        return asyncio.run(proxy.proxy(request))


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

    def test_consumed_request_id_cannot_be_rebound_to_another_target(self) -> None:
        original = self._evidence()
        assertion.consume_assertion(**original, now_unix=101)
        rebound = dict(original)
        rebound["arguments_sha256"] = assertion.canonical_arguments_sha256(
            {"argv": ["false"]}
        )
        rebound["body_sha256"] = "f" * 64
        rebound["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(rebound["request_id"]),
            issued_at_unix=int(rebound["issued_at_unix"]),
            audience=str(rebound["audience"]),
            tool_name=str(rebound["tool_name"]),
            arguments_sha256=str(rebound["arguments_sha256"]),
            body_sha256=str(rebound["body_sha256"]),
            runtime_binding_sha256=str(rebound["asserted_runtime_binding_sha256"]),
        )
        with self.assertRaises(assertion.TransportAssertionReplay):
            assertion.consume_assertion(**rebound, now_unix=102)

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

    def test_valid_old_runtime_signature_fails_current_runtime_binding(self) -> None:
        evidence = self._evidence()
        old_runtime = "e" * 64
        evidence["asserted_runtime_binding_sha256"] = old_runtime
        evidence["mac_sha256"] = assertion.assertion_mac(
            secret=SECRET,
            request_id=str(evidence["request_id"]),
            issued_at_unix=int(evidence["issued_at_unix"]),
            audience=str(evidence["audience"]),
            tool_name=str(evidence["tool_name"]),
            arguments_sha256=str(evidence["arguments_sha256"]),
            body_sha256=str(evidence["body_sha256"]),
            runtime_binding_sha256=old_runtime,
        )
        with self.assertRaisesRegex(
            assertion.TransportAssertionError, "runtime binding mismatch"
        ):
            assertion.consume_assertion(**evidence, now_unix=101)

    def test_foreign_connector_secret_cannot_reuse_owner_assertion(self) -> None:
        evidence = self._evidence()
        evidence["secret"] = FOREIGN_SECRET
        with self.assertRaisesRegex(assertion.TransportAssertionError, "MAC mismatch"):
            assertion.consume_assertion(**evidence, now_unix=101)

    def test_concurrent_replay_admits_exactly_one_consumer(self) -> None:
        evidence = self._evidence()
        workers = 8
        barrier = threading.Barrier(workers)

        def consume() -> str:
            barrier.wait(timeout=5)
            try:
                assertion.consume_assertion(**evidence, now_unix=101)
            except assertion.TransportAssertionReplay:
                return "replay"
            return "consumed"

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda _index: consume(), range(workers)))
        self.assertEqual(results.count("consumed"), 1)
        self.assertEqual(results.count("replay"), workers - 1)

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
        self.assertEqual(
            first[ingress.REQUEST_ID_HEADER], replay[ingress.REQUEST_ID_HEADER]
        )
        self.assertNotEqual(
            first[ingress.REQUEST_ID_HEADER], changed[ingress.REQUEST_ID_HEADER]
        )
        self.assertNotEqual(
            first[ingress.REQUEST_MAC_HEADER], replay[ingress.REQUEST_MAC_HEADER]
        )

    def test_integer_arguments_are_exactly_bound_without_sensitive_output(self) -> None:
        arguments = {
            "attempt": 2**63 + 17,
            "enabled": True,
            "nested": {"delta": -7, "secret": "do-not-project"},
        }
        body = _tool_body(arguments)
        headers = ingress.signed_tool_headers(
            token=SECRET,
            body=body,
            session_id="session-integer",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=100,
        )
        consumed = assertion.consume_assertion(
            secret=SECRET,
            client_scope_sha256=roundtrip.client_scope_sha256(SCOPE),
            runtime_binding_sha256=_runtime_sha256(),
            asserted_runtime_binding_sha256=headers[
                ingress.RUNTIME_BINDING_SHA256_HEADER
            ],
            request_id=headers[ingress.REQUEST_ID_HEADER],
            issued_at_unix=100,
            audience=headers[ingress.REQUEST_AUDIENCE_HEADER],
            tool_name="grabowski_terminal_run",
            arguments_sha256=assertion.canonical_arguments_sha256(arguments),
            body_sha256=headers[ingress.REQUEST_BODY_SHA256_HEADER],
            mac_sha256=headers[ingress.REQUEST_MAC_HEADER],
            now_unix=101,
        )
        self.assertEqual(
            consumed["arguments_sha256"],
            assertion.canonical_arguments_sha256(arguments),
        )
        projected = json.dumps(consumed, sort_keys=True)
        self.assertNotIn("do-not-project", projected)
        self.assertNotIn("nested", projected)


class TransportIngressTests(unittest.TestCase):
    class FakeRequest:
        def __init__(
            self,
            chunks: list[bytes],
            *,
            content_length: int | None = None,
        ) -> None:
            self._chunks = chunks
            self.headers = {ingress.INGRESS_AUTH_HEADER: SECRET}
            if content_length is not None:
                self.headers["content-length"] = str(content_length)
            self.url = SimpleNamespace(query="")

        async def stream(self):
            for chunk in self._chunks:
                yield chunk

    def test_private_token_reader_matches_operator_capability_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "primary.token"
            valid_fixture = "test-fixture-" + "A" * 30
            path.write_text(valid_fixture + "\n", encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(ingress._read_private_token(path), valid_fixture)
            invalid = (
                valid_fixture + "\n\n",
                "short-token",
                "A" * 42,
                "A" * 129,
                "A" * 42 + "!",
            )
            for value in invalid:
                with self.subTest(value_length=len(value)):
                    path.write_text(value, encoding="ascii")
                    path.chmod(0o600)
                    with self.assertRaises(ingress.IngressConfigurationError):
                        ingress._read_private_token(path)

    def test_selector_route_avoids_full_reads_until_generation_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selector_path = Path(directory) / "routing.json"
            canonical = ingress.publish_routing_selector(
                path=selector_path,
                expected_selector_sha256=None,
                selected_slot="canonical",
                runtime_binding=BINDING,
                cutover_id="t167-bootstrap",
                now_unix=100,
            )
            original_reader = ingress._read_private_selector_bytes
            with mock.patch.object(
                ingress,
                "_read_private_selector_bytes",
                wraps=original_reader,
            ) as full_reader:
                proxy = ingress.TransportIngress(
                    token=SECRET, selector_file=selector_path
                )
                self.assertEqual(full_reader.call_count, 1)
                for _ in range(1000):
                    route = proxy._route()
                    self.assertEqual(route["selector_sha256"], canonical["selector_sha256"])
                self.assertEqual(full_reader.call_count, 1)

                green = ingress.publish_routing_selector(
                    path=selector_path,
                    expected_selector_sha256=canonical["selector_sha256"],
                    selected_slot="green",
                    runtime_binding={**BINDING, "release_id": "release-green"},
                    cutover_id="t167-cutover",
                    now_unix=101,
                )
                reads_after_publish = full_reader.call_count
                route = proxy._route()
                self.assertEqual(route["selector_sha256"], green["selector_sha256"])
                self.assertEqual(route["generation"], 2)
                self.assertEqual(route["selected_slot"], "green")
                self.assertEqual(full_reader.call_count, reads_after_publish + 1)
                for _ in range(25):
                    self.assertEqual(proxy._route()["generation"], 2)
                self.assertEqual(full_reader.call_count, reads_after_publish + 1)

    def test_changed_invalid_selector_never_falls_back_to_cached_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            selector_path = Path(directory) / "routing.json"
            canonical = ingress.publish_routing_selector(
                path=selector_path,
                expected_selector_sha256=None,
                selected_slot="canonical",
                runtime_binding=BINDING,
                cutover_id="t167-bootstrap-invalid",
                now_unix=100,
            )
            proxy = ingress.TransportIngress(token=SECRET, selector_file=selector_path)
            self.assertEqual(
                proxy._route()["selector_sha256"], canonical["selector_sha256"]
            )

            selector_path.write_text("{", encoding="utf-8")
            selector_path.chmod(0o600)
            with self.assertRaisesRegex(
                ingress.IngressConfigurationError, "invalid JSON"
            ):
                proxy._route()
            self.assertEqual(
                proxy._selector_route["selector_sha256"],
                canonical["selector_sha256"],
            )

            selector_path.unlink()
            with self.assertRaisesRegex(
                ingress.IngressConfigurationError, "unavailable"
            ):
                proxy._route()
            self.assertEqual(
                proxy._selector_route["selector_sha256"],
                canonical["selector_sha256"],
            )

    def test_chunked_request_body_is_bounded_while_streaming(self) -> None:
        proxy = ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=_runtime_sha256(),
        )
        request = self.FakeRequest([b"12345678", b"9"])
        with mock.patch.object(ingress, "MAX_REQUEST_BYTES", 8):
            response = _run_locally_rejected_proxy(proxy, request)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(json.loads(response.body), {"error": "request_too_large"})

    def test_declared_content_length_must_match_streamed_body(self) -> None:
        proxy = ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=_runtime_sha256(),
        )
        response = _run_locally_rejected_proxy(
            proxy, self.FakeRequest([b"x"], content_length=2)
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            json.loads(response.body), {"error": "content_length_mismatch"}
        )

    def test_noncanonical_tool_arguments_fail_as_bounded_client_error(self) -> None:
        proxy = ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=_runtime_sha256(),
        )
        body = (
            b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":'
            b'{"name":"grabowski_terminal_run","arguments":{"value":NaN}}}'
        )
        response = _run_locally_rejected_proxy(
            proxy, self.FakeRequest([body], content_length=len(body))
        )
        self.assertEqual(response.status_code, 400)
        projected = json.loads(response.body)
        self.assertEqual(projected["error"], "invalid_mcp_request")
        self.assertNotIn(SECRET, json.dumps(projected))

    def test_unauthorized_request_is_rejected_before_outbound_client(self) -> None:
        proxy = ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=_runtime_sha256(),
        )
        request = self.FakeRequest([b""])
        request.headers[ingress.INGRESS_AUTH_HEADER] = "not-the-owner-secret"
        response = _run_locally_rejected_proxy(proxy, request)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            json.loads(response.body), {"error": "unauthorized_ingress_client"}
        )

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
        self.assertEqual(
            headers[ingress.INGRESS_VERSION_HEADER], assertion.ASSERTION_VERSION
        )
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
                "entrypoint_contract": {"expected_tools": ["tool_b", "tool_a"]},
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
            self.assertEqual(expected_names, binding["registered_names_sha256"])
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
            mock.patch.object(
                base, "_transport_connector_capability_scope", return_value=SCOPE
            ),
            mock.patch.object(
                operator, "_require_current_serving_process", return_value=None
            ),
            mock.patch.object(
                base, "_transport_roundtrip_runtime_binding", return_value=BINDING
            ),
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
            base._TRANSPORT_REQUEST_TIMESTAMP_HEADER: signed[
                ingress.REQUEST_TIMESTAMP_HEADER
            ],
            base._TRANSPORT_REQUEST_AUDIENCE_HEADER: signed[
                ingress.REQUEST_AUDIENCE_HEADER
            ],
            base._TRANSPORT_REQUEST_BODY_SHA256_HEADER: signed[
                ingress.REQUEST_BODY_SHA256_HEADER
            ],
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

    def test_mcp_preserves_typed_signed_one_call_replay(self) -> None:
        arguments = {"argv": ["true"]}
        body = _tool_body(arguments)
        signed = ingress.signed_tool_headers(
            token=SECRET,
            body=body,
            session_id="session-typed-replay",
            runtime_binding_sha256=_runtime_sha256(),
            now_unix=int(__import__("time").time()),
        )
        headers = {
            base._TRANSPORT_CONNECTOR_CAPABILITY_HEADER: SECRET,
            base._TRANSPORT_INGRESS_VERSION_HEADER: assertion.ASSERTION_VERSION,
            base._TRANSPORT_REQUEST_ID_HEADER: signed[ingress.REQUEST_ID_HEADER],
            base._TRANSPORT_REQUEST_TIMESTAMP_HEADER: signed[
                ingress.REQUEST_TIMESTAMP_HEADER
            ],
            base._TRANSPORT_REQUEST_AUDIENCE_HEADER: signed[
                ingress.REQUEST_AUDIENCE_HEADER
            ],
            base._TRANSPORT_REQUEST_BODY_SHA256_HEADER: signed[
                ingress.REQUEST_BODY_SHA256_HEADER
            ],
            base._TRANSPORT_RUNTIME_BINDING_SHA256_HEADER: signed[
                ingress.RUNTIME_BINDING_SHA256_HEADER
            ],
            base._TRANSPORT_REQUEST_MAC_HEADER: signed[ingress.REQUEST_MAC_HEADER],
        }
        arguments_sha256 = roundtrip.canonical_arguments_sha256(arguments)
        first = base._transport_signed_one_call_evidence(
            _ctx(headers),
            tool_name="grabowski_terminal_run",
            arguments_sha256=arguments_sha256,
            runtime_binding=BINDING,
        )
        self.assertEqual(first["transport_mode"], assertion.ASSERTION_VERSION)
        with self.assertRaises(assertion.TransportAssertionReplay):
            base._transport_signed_one_call_evidence(
                _ctx(headers),
                tool_name="grabowski_terminal_run",
                arguments_sha256=arguments_sha256,
                runtime_binding=BINDING,
            )

    def test_publisher_replay_recovery_preflight_requires_safe_state_store_preview(
        self,
    ) -> None:
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "effect_started": False,
            "ambiguity": False,
            "retryable": False,
            "publication_mode": "state_store",
            "task_id": "RAB-V1-T002K",
            "proposal_sha256": "9" * 64,
            "approval": {"allowed": True},
        }
        fake_intake = SimpleNamespace(
            grabowski_bureau_task_publish_preview=mock.Mock(return_value=preview)
        )
        with mock.patch.dict(sys.modules, {"grabowski_bureau_intake": fake_intake}):
            evidence = operator._signed_replay_recovery_preflight(
                tool_name="grabowski_bureau_task_publish",
                arguments={"proposal_id": "proposal-1"},
            )
        self.assertEqual(evidence["task_id"], "RAB-V1-T002K")
        self.assertEqual(evidence["proposal_sha256"], "9" * 64)
        self.assertRegex(evidence["preview_sha256"], r"^[0-9a-f]{64}$")

        unsafe = dict(preview)
        unsafe["ambiguity"] = True
        fake_intake.grabowski_bureau_task_publish_preview.return_value = unsafe
        with mock.patch.dict(sys.modules, {"grabowski_bureau_intake": fake_intake}):
            self.assertIsNone(
                operator._signed_replay_recovery_preflight(
                    tool_name="grabowski_bureau_task_publish",
                    arguments={"proposal_id": "proposal-1"},
                )
            )

    def test_operator_recovers_publisher_replay_only_after_domain_preflight_and_exact_roundtrip(
        self,
    ) -> None:
        arguments = {"proposal_id": "proposal-1"}
        expected_arguments_sha256 = roundtrip.canonical_arguments_sha256(arguments)
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        recovery = {
            "transport_mode": "roundtrip-test",
            "consumption_receipt_sha256": "a" * 64,
        }
        preflight = {
            "kind": "grabowski_signed_replay_recovery_preflight",
            "schema_version": 1,
            "tool_name": "grabowski_bureau_task_publish",
            "task_id": "RAB-V1-T002K",
            "proposal_sha256": "9" * 64,
            "publication_mode": "state_store",
            "preview_sha256": "8" * 64,
        }
        with (
            mock.patch.object(
                base,
                "_transport_signed_one_call_evidence",
                side_effect=assertion.TransportAssertionReplay(
                    "signed one-call transport request was already consumed"
                ),
            ),
            mock.patch.object(
                operator, "_signed_replay_recovery_preflight", return_value=preflight
            ) as domain_preflight,
            mock.patch.object(
                base, "_transport_roundtrip_client_scope", return_value=SCOPE
            ),
            mock.patch.object(
                roundtrip, "consume_verified", return_value=recovery
            ) as consume_verified,
            mock.patch.object(roundtrip, "begin") as begin,
        ):
            evidence = operator._require_transport_roundtrip_for_tool(
                tool_name="grabowski_bureau_task_publish",
                arguments=arguments,
                context=_ctx({}),
                tool=tool,
            )
        domain_preflight.assert_called_once_with(
            tool_name="grabowski_bureau_task_publish", arguments=arguments
        )
        consume_verified.assert_called_once_with(
            client_scope=SCOPE,
            runtime_binding=BINDING,
            tool_name="grabowski_bureau_task_publish",
            arguments_sha256=expected_arguments_sha256,
        )
        begin.assert_not_called()
        self.assertTrue(evidence["signed_one_call_replay_recovery"])
        self.assertEqual(
            evidence["recovery_basis"],
            "domain_reconciled_preverified_exact_roundtrip",
        )
        self.assertEqual(evidence["recovery_preflight"], preflight)

    def test_operator_generic_signed_replay_cannot_use_roundtrip_recovery(self) -> None:
        arguments = {"argv": ["true"]}
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        replay_message = "signed one-call transport request was already consumed"
        with (
            mock.patch.object(
                base,
                "_transport_signed_one_call_evidence",
                side_effect=assertion.TransportAssertionReplay(replay_message),
            ),
            mock.patch.object(
                operator, "_signed_replay_recovery_preflight", return_value=None
            ) as domain_preflight,
            mock.patch.object(roundtrip, "consume_verified") as consume_verified,
            mock.patch.object(roundtrip, "begin") as begin,
        ):
            with self.assertRaisesRegex(RuntimeError, replay_message):
                operator._require_transport_roundtrip_for_tool(
                    tool_name="grabowski_terminal_run",
                    arguments=arguments,
                    context=_ctx({}),
                    tool=tool,
                )
        domain_preflight.assert_called_once_with(
            tool_name="grabowski_terminal_run", arguments=arguments
        )
        consume_verified.assert_not_called()
        begin.assert_not_called()

    def test_operator_publisher_replay_remains_blocked_without_preverified_roundtrip(
        self,
    ) -> None:
        arguments = {"proposal_id": "proposal-1"}
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        replay_message = "signed one-call transport request was already consumed"
        with (
            mock.patch.object(
                base,
                "_transport_signed_one_call_evidence",
                side_effect=assertion.TransportAssertionReplay(replay_message),
            ),
            mock.patch.object(
                operator,
                "_signed_replay_recovery_preflight",
                return_value={"kind": "safe-domain-preview"},
            ),
            mock.patch.object(
                base, "_transport_roundtrip_client_scope", return_value=SCOPE
            ),
            mock.patch.object(
                roundtrip,
                "consume_verified",
                side_effect=roundtrip.TransportRoundtripRequired(
                    "fresh verification required"
                ),
            ) as consume_verified,
            mock.patch.object(roundtrip, "begin") as begin,
        ):
            with self.assertRaisesRegex(RuntimeError, replay_message):
                operator._require_transport_roundtrip_for_tool(
                    tool_name="grabowski_bureau_task_publish",
                    arguments=arguments,
                    context=_ctx({}),
                    tool=tool,
                )
        consume_verified.assert_called_once()
        begin.assert_not_called()

    def test_github_pr_view_read_only_shape_is_transport_exempt(self) -> None:
        safe_calls = [
            {"arguments": ["pr", "view", "734", "--repo", "heimgewebe/metarepo"]},
            {"arguments": ["pr", "view", "734", "--json", "number,state,headRefOid"]},
            {"arguments": ["pr", "view", "--comments"]},
        ]
        for arguments in safe_calls:
            with self.subTest(arguments=arguments):
                self.assertTrue(
                    operator._transport_roundtrip_exempt_call(
                        "grabowski_github", arguments
                    )
                )

    def test_other_github_or_ambiguous_shapes_stay_transport_gated(self) -> None:
        unsafe_calls = [
            {"arguments": ["pr", "merge", "734"]},
            {"arguments": ["pr", "view", "734", "--web"]},
            {"arguments": ["pr", "view", "734", "-w"]},
            {"arguments": ["pr", "view", "734", "--web=true"]},
            {"arguments": ["pr", "view", "734", "--jq", ".number"]},
            {"arguments": ["pr", "view", "734", "--template", "{{.number}}"]},
            {"arguments": ["pr", "view", "734", "--future-mutate"]},
            {"arguments": ["pr", "view", "734", "extra-positional"]},
            {"arguments": ["issue", "view", "1"]},
            {"arguments": ["api", "repos/x/y"]},
            {"arguments": ["api", "graphql", "-f", "query=query { viewer { login } }"]},
        ]
        for arguments in unsafe_calls:
            with self.subTest(arguments=arguments):
                self.assertFalse(
                    operator._transport_roundtrip_exempt_call(
                        "grabowski_github", arguments
                    )
                )
        self.assertFalse(
            operator._transport_roundtrip_exempt_call(
                "grabowski_terminal_run", {"argv": ["true"]}
            )
        )

    def test_trusted_github_cli_pin_rejects_unsafe_metadata(self) -> None:
        trusted_file = SimpleNamespace(
            st_mode=operator.stat.S_IFREG | 0o755, st_uid=0
        )
        trusted_dir = SimpleNamespace(
            st_mode=operator.stat.S_IFDIR | 0o755, st_uid=0
        )

        def lstat_for(path: object) -> object:
            value = Path(path)
            if value == operator.TRUSTED_GITHUB_CLI_PATH:
                return trusted_file
            if value in {
                operator.TRUSTED_GITHUB_CLI_PATH.parent,
                operator.TRUSTED_GITHUB_CLI_PATH.parent.parent,
            }:
                return trusted_dir
            raise AssertionError(f"unexpected lstat path: {value}")

        with mock.patch.object(operator.os, "lstat", side_effect=lstat_for):
            self.assertEqual(operator._trusted_github_cli_path(), "/usr/bin/gh")

        unsafe_cases = [
            SimpleNamespace(st_mode=operator.stat.S_IFREG | 0o755, st_uid=1000),
            SimpleNamespace(st_mode=operator.stat.S_IFREG | 0o775, st_uid=0),
            SimpleNamespace(st_mode=operator.stat.S_IFLNK | 0o777, st_uid=0),
        ]
        for unsafe_file in unsafe_cases:
            with self.subTest(mode=unsafe_file.st_mode, uid=unsafe_file.st_uid):
                def unsafe_lstat(path: object) -> object:
                    value = Path(path)
                    if value == operator.TRUSTED_GITHUB_CLI_PATH:
                        return unsafe_file
                    return trusted_dir

                with mock.patch.object(operator.os, "lstat", side_effect=unsafe_lstat):
                    with self.assertRaises(RuntimeError):
                        operator._trusted_github_cli_path()

    def test_github_wrapper_ignores_path_shim_and_uses_trusted_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            shim = Path(directory) / "gh"
            shim.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            shim.chmod(0o755)
            hostile_environment = {
                "PATH": directory,
                "GH_FORCE_TTY": "1",
                "GH_PAGER": str(Path(directory) / "evil-gh-pager"),
                "PAGER": str(Path(directory) / "evil-pager"),
                "GIT_PAGER": str(Path(directory) / "evil-git-pager"),
                "LD_PRELOAD": str(Path(directory) / "evil.so"),
                "BROWSER": str(Path(directory) / "evil-browser"),
                "EDITOR": str(Path(directory) / "evil-editor"),
                "VISUAL": str(Path(directory) / "evil-visual"),
                "GH_TOKEN": "fixture-token",
            }
            with (
                mock.patch.dict(operator.os.environ, hostile_environment, clear=False),
                mock.patch.object(operator, "_trusted_owner_mode", return_value=True),
                mock.patch.object(operator, "_require_operator_mutation"),
                mock.patch.object(
                    operator, "_trusted_github_cli_path", return_value="/usr/bin/gh"
                ) as trusted,
                mock.patch.object(
                    operator, "_run", return_value={"returncode": 0}
                ) as run,
            ):
                operator.grabowski_github(
                    ["pr", "view", "1031", "--json", "number,state"],
                    cwd=str(ROOT),
                )
        trusted.assert_called_once_with()
        command = run.call_args.args[0]
        environment = run.call_args.kwargs["environment"]
        self.assertEqual(command[0], "/usr/bin/gh")
        self.assertNotEqual(command[0], str(shim))
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertNotIn(directory, environment["PATH"])
        self.assertEqual(environment["GH_PAGER"], "cat")
        self.assertEqual(environment["PAGER"], "cat")
        self.assertEqual(environment["GIT_PAGER"], "cat")
        self.assertEqual(environment["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GH_TOKEN"], "fixture-token")
        for unsafe_key in (
            "GH_FORCE_TTY",
            "LD_PRELOAD",
            "BROWSER",
            "EDITOR",
            "VISUAL",
        ):
            self.assertNotIn(unsafe_key, environment)

    def test_exempt_github_environment_keeps_untrusted_secret_scrubbing(self) -> None:
        with (
            mock.patch.dict(operator.os.environ, {"GH_TOKEN": "fixture-token"}, clear=False),
            mock.patch.object(operator, "_trusted_owner_mode", return_value=False),
        ):
            environment = operator._github_pr_view_environment()
        self.assertNotIn("GH_TOKEN", environment)
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["GH_PAGER"], "cat")

    def test_nonexempt_github_call_keeps_default_child_environment(self) -> None:
        with (
            mock.patch.object(operator, "_require_operator_mutation"),
            mock.patch.object(
                operator, "_trusted_github_cli_path", return_value="/usr/bin/gh"
            ),
            mock.patch.object(operator, "_run", return_value={"returncode": 0}) as run,
        ):
            operator.grabowski_github(
                ["issue", "view", "1", "--repo", "heimgewebe/grabowski"],
                cwd=str(ROOT),
            )
        self.assertIsNone(run.call_args.kwargs["environment"])

    def test_github_pr_view_does_not_consume_signed_assertion(self) -> None:
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        with (
            mock.patch.object(operator, "_require_current_serving_process") as serving,
            mock.patch.object(base, "_transport_signed_one_call_evidence") as signed,
            mock.patch.object(roundtrip, "consume_verified") as legacy,
        ):
            evidence = operator._require_transport_roundtrip_for_tool(
                tool_name="grabowski_github",
                arguments={
                    "arguments": [
                        "pr",
                        "view",
                        "734",
                        "--repo",
                        "heimgewebe/metarepo",
                    ]
                },
                context=_ctx({}),
                tool=tool,
            )
        self.assertIsNone(evidence)
        serving.assert_not_called()
        signed.assert_not_called()
        legacy.assert_not_called()

    def test_stale_serving_process_blocks_before_signed_assertion_consumption(
        self,
    ) -> None:
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        with (
            mock.patch.object(
                operator,
                "_require_current_serving_process",
                side_effect=RuntimeError("stale serving process"),
            ),
            mock.patch.object(base, "_transport_signed_one_call_evidence") as signed,
        ):
            with self.assertRaisesRegex(RuntimeError, "stale serving process"):
                operator._require_transport_roundtrip_for_tool(
                    tool_name="grabowski_terminal_run",
                    arguments={"argv": ["true"]},
                    context=_ctx({}),
                    tool=tool,
                )
        signed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
