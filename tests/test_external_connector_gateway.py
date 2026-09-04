from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


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

    def test_tools_list_projection_fails_if_configured_tool_is_missing(self) -> None:
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"tools": [{"name": "grabowski_status", "inputSchema": {}}]},
        }
        with self.assertRaisesRegex(
            gateway.GatewayConfigurationError, "missing upstream"
        ):
            gateway._filter_tools_list_payload(
                json.dumps(payload).encode("utf-8"),
                {"grabowski_status", "grabowski_git_status"},
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

    def test_proxy_rejects_json_rpc_batches_before_upstream(self) -> None:
        proxy = gateway.ExternalConnectorGateway(
            connector_id="maulwurf-x",
            external_token=self.EXTERNAL,
            internal_token=self.INTERNAL,
            allowed_tools=["grabowski_status"],
            upstream="http://127.0.0.1:18183/mcp",
        )
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
        request = types.SimpleNamespace(
            method="POST",
            headers=_Headers(
                {
                    "authorization": f"Bearer {self.EXTERNAL}",
                    "content-length": str(len(body)),
                }
            ),
        )
        with mock.patch.object(
            signed_ingress,
            "_read_bounded_request_body",
            new=mock.AsyncMock(return_value=body),
        ):
            response = __import__("asyncio").run(proxy.proxy(request))
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"invalid_json_rpc_object", response.body)


if __name__ == "__main__":
    unittest.main()
