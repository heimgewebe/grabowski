from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TOOLS = ROOT / "tools"
for path in (SRC, TOOLS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import grabowski_external_connector_gateway as gateway  # noqa: E402
import grabowski_transport_ingress as signed_ingress  # noqa: E402


class _Headers(dict[str, str]):
    pass


class _MultiHeaders(_Headers):
    def __init__(self, values: dict[str, list[str]]) -> None:
        super().__init__(
            {name: items[0] for name, items in values.items() if items}
        )
        self._values = values

    def getlist(self, name: str) -> list[str]:
        return list(self._values.get(name, []))


class _StreamingResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_raw(self):
        for chunk in self._chunks:
            yield chunk


class ExternalConnectorGatewayTests(unittest.TestCase):
    EXTERNAL = "E" * 43
    INTERNAL = "I" * 43

    def headers(self, **values: str) -> _Headers:
        return _Headers({key.replace("_", "-"): value for key, value in values.items()})

    def test_bearer_auth_is_accepted(self) -> None:
        for scheme in ("Bearer", "bearer", "BEARER"):
            with self.subTest(scheme=scheme):
                headers = _Headers({"authorization": f"{scheme} {self.EXTERNAL}"})
                self.assertTrue(
                    gateway._external_client_authenticated(headers, self.EXTERNAL)
                )

    def test_duplicate_auth_headers_are_rejected(self) -> None:
        self.assertFalse(
            gateway._external_client_authenticated(
                _MultiHeaders(
                    {
                        "authorization": [
                            f"Bearer {self.EXTERNAL}",
                            f"Bearer {'X' * 43}",
                        ]
                    }
                ),
                self.EXTERNAL,
            )
        )
        self.assertFalse(
            gateway._external_client_authenticated(
                _MultiHeaders(
                    {"x-api-key": [self.EXTERNAL, self.EXTERNAL]}
                ),
                self.EXTERNAL,
            )
        )

    def test_api_key_auth_is_accepted(self) -> None:
        headers = _Headers({"x-api-key": self.EXTERNAL})
        self.assertTrue(gateway._external_client_authenticated(headers, self.EXTERNAL))

    def test_missing_wrong_or_ambiguous_auth_is_rejected(self) -> None:
        self.assertFalse(gateway._external_client_authenticated(_Headers(), self.EXTERNAL))
        self.assertFalse(
            gateway._external_client_authenticated(
                _Headers({"authorization": f"Bearer {'X' * 43}"}),
                self.EXTERNAL,
            )
        )
        self.assertFalse(
            gateway._external_client_authenticated(
                _Headers(
                    {
                        "authorization": f"Bearer {self.EXTERNAL}",
                        "x-api-key": self.EXTERNAL,
                    }
                ),
                self.EXTERNAL,
            )
        )

    def test_forward_headers_strip_external_and_spoofed_grabowski_authority(self) -> None:
        request = types.SimpleNamespace(
            headers=_Headers(
                {
                    "authorization": f"Bearer {self.EXTERNAL}",
                    "x-api-key": self.EXTERNAL,
                    "X-Grabowski-Connector-Capability": "spoofed",
                    "X-Grabowski-Ingress-Auth": "spoofed",
                    "x-grabowski-request-id": "spoofed",
                    "mcp-session-id": "session-1",
                    "accept": "application/json, text/event-stream",
                    "host": "example.invalid",
                    "content-length": "10",
                }
            )
        )
        forwarded = gateway._forward_headers(request, self.INTERNAL)
        lowered = {name.lower(): value for name, value in forwarded.items()}
        self.assertNotIn("authorization", lowered)
        self.assertNotIn("x-api-key", lowered)
        self.assertNotIn("x-grabowski-connector-capability", lowered)
        self.assertNotIn("x-grabowski-request-id", lowered)
        self.assertEqual(
            lowered[signed_ingress.INGRESS_AUTH_HEADER.lower()], self.INTERNAL
        )
        self.assertEqual(lowered["mcp-session-id"], "session-1")
        self.assertIn("accept", lowered)

    def test_disallowed_tool_call_is_identified_before_proxy(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "grabowski_destroy_path", "arguments": {}},
        }
        body = json.dumps(payload).encode("utf-8")
        parsed = gateway._parse_json_rpc(body)
        self.assertEqual(gateway._tool_call_name(parsed), "grabowski_destroy_path")
        rejection = gateway._tool_not_available_response(parsed)
        self.assertEqual(rejection["id"], 7)
        self.assertEqual(rejection["error"]["code"], -32601)

    def test_tools_list_projection_is_exact_and_order_preserving(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "tools": [
                    {"name": "grabowski_status", "inputSchema": {}},
                    {"name": "grabowski_destroy_path", "inputSchema": {}},
                    {"name": "grabowski_git_status", "inputSchema": {}},
                ],
                "nextCursor": None,
            },
        }
        filtered = json.loads(
            gateway._filter_tools_list_payload(
                json.dumps(payload).encode("utf-8"),
                {"grabowski_status", "grabowski_git_status"},
            ).decode("utf-8")
        )
        self.assertEqual(
            [tool["name"] for tool in filtered["result"]["tools"]],
            ["grabowski_status", "grabowski_git_status"],
        )
        self.assertIsNone(filtered["result"]["nextCursor"])

    def test_tools_list_projection_preserves_pagination_without_requiring_full_allowlist(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "tools": [{"name": "grabowski_status", "inputSchema": {}}],
                "nextCursor": "page-2",
            },
        }
        filtered = json.loads(
            gateway._filter_tools_list_payload(
                json.dumps(payload).encode("utf-8"),
                {"grabowski_status", "grabowski_git_status"},
            ).decode("utf-8")
        )
        self.assertEqual(
            [tool["name"] for tool in filtered["result"]["tools"]],
            ["grabowski_status"],
        )
        self.assertEqual(filtered["result"]["nextCursor"], "page-2")

    def test_tools_list_projection_filters_streamable_http_sse(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {
                "tools": [
                    {"name": "grabowski_status", "inputSchema": {}},
                    {"name": "grabowski_destroy_path", "inputSchema": {}},
                ]
            },
        }
        raw = (
            "event: message\r\n"
            f"data: {json.dumps(payload, separators=(',', ':'))}\r\n\r\n"
        ).encode("utf-8")
        filtered = gateway._filter_tools_list_response(
            raw,
            "text/event-stream; charset=utf-8",
            {"grabowski_status"},
        ).decode("utf-8")
        data_line = next(
            line for line in filtered.splitlines() if line.startswith("data: ")
        )
        projected = json.loads(data_line.removeprefix("data: "))
        self.assertEqual(
            [tool["name"] for tool in projected["result"]["tools"]],
            ["grabowski_status"],
        )
        self.assertIn("event: message\r\n", filtered)
        self.assertTrue(filtered.endswith("\r\n\r\n"))

    def test_tools_list_projection_preserves_sse_priming_event(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"tools": [{"name": "grabowski_status", "inputSchema": {}}]},
        }
        priming = "id: priming-1\r\ndata: \r\n\r\n"
        message = (
            "event: message\r\n"
            f"data: {json.dumps(payload, separators=(',', ':'))}\r\n\r\n"
        )
        filtered = gateway._filter_tools_list_response(
            (priming + message).encode("utf-8"),
            "text/event-stream",
            {"grabowski_status"},
        ).decode("utf-8")
        self.assertTrue(filtered.startswith(priming))

    def test_tools_list_projection_rejects_unprojectable_sse_event(self) -> None:
        raw = (
            "event: message\n"
            'data: {"jsonrpc":"2.0","id":4,"result":{"prompts":[]}}\n\n'
        ).encode("utf-8")
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "unexpected result"
        ):
            gateway._filter_tools_list_response(
                raw,
                "text/event-stream",
                {"grabowski_status"},
            )

    def test_tools_list_projection_rejects_unknown_upstream_media_type(self) -> None:
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "unsupported content type"
        ):
            gateway._filter_tools_list_response(
                b"{}",
                "application/octet-stream",
                {"grabowski_status"},
            )

    def test_tools_list_upstream_read_is_bounded_while_streaming(self) -> None:
        response = _StreamingResponse([b"abcd", b"efgh"])
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "too large"
        ):
            asyncio.run(
                gateway._read_bounded_upstream_response(
                    response, maximum_bytes=7
                )
            )

    def test_tools_list_upstream_read_preserves_chunk_bytes(self) -> None:
        response = _StreamingResponse([b"abc", b"", b"def"])
        self.assertEqual(
            asyncio.run(
                gateway._read_bounded_upstream_response(
                    response, maximum_bytes=6
                )
            ),
            b"abcdef",
        )

    def test_gateway_rejects_shared_external_and_internal_secret(self) -> None:
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "must be distinct"
        ):
            gateway.ExternalConnectorGateway(
                connector_id="maulwurf-x",
                external_token=self.EXTERNAL,
                internal_token=self.EXTERNAL,
                allowed_tools=["grabowski_status"],
                upstream="http://127.0.0.1:18183/mcp",
            )

    def test_repository_maulwurf_x_policy_contains_only_published_read_only_tools(self) -> None:
        policy = json.loads((ROOT / "config" / "maulwurf-x-tools.json").read_text())
        entrypoint = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text())
        expected = set(entrypoint["expected_tools"])
        catalog = json.loads((ROOT / "contracts" / "capability-catalog.v1.json").read_text())
        records = catalog.get("capabilities", catalog.get("tools", []))
        if not isinstance(records, list):
            self.fail("capability catalog record list is unavailable")
        read_only = {
            record.get("tool")
            for record in records
            if isinstance(record, dict) and record.get("read_only") is True
        }
        allowed = set(policy["allowed_tools"])
        self.assertEqual(policy["connector_id"], "maulwurf-x")
        self.assertEqual(policy["mode"], "allowlist")
        self.assertTrue(policy["read_only_only"])
        self.assertTrue(allowed)
        self.assertTrue(allowed <= expected)
        self.assertTrue(allowed <= read_only)

    def test_gateway_token_parent_must_be_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "tokens"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            token = root / "maulwurf-x.token"
            token.write_text(self.EXTERNAL, encoding="ascii")
            os.chmod(token, 0o600)
            self.assertEqual(gateway._read_gateway_token(token), self.EXTERNAL)
            os.chmod(root, 0o755)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "private and owner-controlled"
            ):
                gateway._read_gateway_token(token)

    def test_gateway_policy_requires_global_marker_and_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "transport-connectors"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            policy = root / "maulwurf-x.tools.json"
            policy.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "connector_id": "maulwurf-x",
                        "mode": "allowlist",
                        "allowed_tools": ["grabowski_status"],
                        "read_only_only": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(policy, 0o600)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "enforced read-only allowlist"
            ):
                gateway._load_gateway_policy(policy, "maulwurf-x")
            marker = root / "require-tool-policy"
            marker.write_text("required-v1", encoding="ascii")
            os.chmod(marker, 0o600)
            loaded = gateway._load_gateway_policy(policy, "maulwurf-x")
            policy.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "connector_id": "maulwurf-x",
                        "mode": "allowlist",
                        "allowed_tools": ["grabowski_status"],
                        "read_only_only": False,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(policy, 0o600)
            with self.assertRaisesRegex(
                gateway.GatewayConfigurationError, "enforced read-only allowlist"
            ):
                gateway._load_gateway_policy(policy, "maulwurf-x")
        self.assertTrue(loaded["enforced"])
        self.assertEqual(loaded["allowed_tools"], ["grabowski_status"])

    def test_gateway_method_surface_excludes_future_unscoped_capabilities(self) -> None:
        self.assertEqual(
            gateway.ALLOWED_JSON_RPC_METHODS,
            {
                "initialize",
                "notifications/initialized",
                "notifications/cancelled",
                "ping",
                "tools/list",
                "tools/call",
            },
        )
        self.assertNotIn("resources/read", gateway.ALLOWED_JSON_RPC_METHODS)
        self.assertNotIn("prompts/get", gateway.ALLOWED_JSON_RPC_METHODS)

    def test_oauth_redirect_uri_is_limited_to_grok_and_xai_https(self) -> None:
        for value in (
            "https://grok.com/oauth/callback",
            "https://accounts.x.ai/connectors/oauth/callback",
        ):
            self.assertTrue(gateway._oauth_redirect_uri_allowed(value))
        for value in (
            "http://grok.com/oauth/callback",
            "https://evil.example/oauth/callback",
            "https://grok.com.evil.example/oauth/callback",
            "https://user@grok.com/oauth/callback",
            "https://grok.com/oauth/callback#fragment",
        ):
            self.assertFalse(gateway._oauth_redirect_uri_allowed(value))

    def test_oauth_code_is_pkce_bound_expiring_and_single_use(self) -> None:
        verifier = "A" * 43
        redirect = "https://grok.com/oauth/callback"
        client_id = gateway._oauth_client_id("maulwurf-x")
        code = gateway._oauth_issue_code(
            secret=self.EXTERNAL,
            connector_id="maulwurf-x",
            client_id=client_id,
            redirect_uri=redirect,
            code_challenge=gateway._oauth_pkce_s256(verifier),
            now=1000,
        )
        consumed: set[str] = set()
        self.assertTrue(
            gateway._oauth_consume_code(
                code,
                secret=self.EXTERNAL,
                connector_id="maulwurf-x",
                client_id=client_id,
                redirect_uri=redirect,
                code_verifier=verifier,
                consumed=consumed,
                now=1001,
            )
        )
        self.assertFalse(
            gateway._oauth_consume_code(
                code,
                secret=self.EXTERNAL,
                connector_id="maulwurf-x",
                client_id=client_id,
                redirect_uri=redirect,
                code_verifier=verifier,
                consumed=consumed,
                now=1001,
            )
        )
        self.assertFalse(
            gateway._oauth_consume_code(
                code,
                secret=self.EXTERNAL,
                connector_id="maulwurf-x",
                client_id=client_id,
                redirect_uri=redirect,
                code_verifier=verifier,
                consumed=set(),
                now=1120,
            )
        )

    def test_oauth_code_rejects_wrong_verifier_redirect_and_signature(self) -> None:
        verifier = "B" * 43
        redirect = "https://grok.com/oauth/callback"
        client_id = gateway._oauth_client_id("maulwurf-x")
        code = gateway._oauth_issue_code(
            secret=self.EXTERNAL,
            connector_id="maulwurf-x",
            client_id=client_id,
            redirect_uri=redirect,
            code_challenge=gateway._oauth_pkce_s256(verifier),
            now=2000,
        )
        common = {
            "secret": self.EXTERNAL,
            "connector_id": "maulwurf-x",
            "client_id": client_id,
            "consumed": set(),
            "now": 2001,
        }
        self.assertFalse(
            gateway._oauth_consume_code(
                code,
                redirect_uri=redirect,
                code_verifier="C" * 43,
                **common,
            )
        )
        self.assertFalse(
            gateway._oauth_consume_code(
                code,
                redirect_uri="https://grok.com/other",
                code_verifier=verifier,
                **common,
            )
        )
        self.assertFalse(
            gateway._oauth_consume_code(
                code[:-1] + ("A" if code[-1] != "A" else "B"),
                redirect_uri=redirect,
                code_verifier=verifier,
                **common,
            )
        )

    def test_oauth_basic_client_auth_is_unambiguous(self) -> None:
        client_id = gateway._oauth_client_id("maulwurf-x")
        encoded = gateway.base64.b64encode(
            f"{client_id}:{self.EXTERNAL}".encode("utf-8")
        ).decode("ascii")
        self.assertEqual(
            gateway._oauth_basic_client(
                _Headers({"authorization": f"Basic {encoded}"})
            ),
            (client_id, self.EXTERNAL),
        )
        self.assertIsNone(gateway._oauth_basic_client(_Headers()))
        self.assertIsNone(
            gateway._oauth_basic_client(
                _Headers({"authorization": f"Bearer {self.EXTERNAL}"})
            )
        )

    def test_proxy_preflight_rejects_bodies_on_get_and_delete(self) -> None:
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/read",
                "params": {},
            }
        ).encode("utf-8")
        for method in ("GET", "DELETE"):
            with self.subTest(method=method):
                self.assertEqual(
                    gateway._preflight_json_rpc_request(
                        method, body, {"grabowski_status"}
                    ),
                    (400, {"error": "request_body_not_allowed_for_http_method"}),
                )

    def test_proxy_preflight_rejects_json_rpc_batches_without_runtime_dependencies(self) -> None:
        body = json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "grabowski_destroy_path",
                        "arguments": {},
                    },
                }
            ]
        ).encode("utf-8")
        rejection = gateway._preflight_json_rpc_request(
            "POST", body, {"grabowski_status"}
        )
        self.assertEqual(
            rejection,
            (400, {"error": "invalid_json_rpc_object"}),
        )


if __name__ == "__main__":
    unittest.main()
