from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from starlette.requests import Request
from starlette.routing import Route


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SPEC = importlib.util.spec_from_file_location(
    "grabowski_transport_ingress_oauth_discovery_test_module",
    ROOT / "tools/grabowski_transport_ingress.py",
)
assert SPEC is not None and SPEC.loader is not None
ingress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingress)

SECRET = "A" * 43
RUNTIME_BINDING_SHA256 = "b" * 64


class TransportIngressOAuthDiscoveryTests(unittest.TestCase):
    def _transport(self) -> object:
        return ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=RUNTIME_BINDING_SHA256,
        )

    @staticmethod
    def _request(*, root_path: str = "") -> Request:
        return Request(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": f"{root_path}{ingress.OAUTH_PROTECTED_RESOURCE_PATH}",
                "raw_path": (
                    f"{root_path}{ingress.OAUTH_PROTECTED_RESOURCE_PATH}"
                ).encode("ascii"),
                "root_path": root_path,
                "query_string": b"",
                "headers": [],
                "server": ("127.0.0.1", 18180),
                "client": ("127.0.0.1", 40000),
            }
        )

    def test_build_app_exposes_both_oauth_discovery_paths_without_mcp_auth(self) -> None:
        app = ingress.build_app(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=RUNTIME_BINDING_SHA256,
        )
        routes = {
            route.path: route for route in app.routes if isinstance(route, Route)
        }
        for path in (
            ingress.OAUTH_PROTECTED_RESOURCE_PATH,
            ingress.OAUTH_PROTECTED_RESOURCE_MCP_PATH,
        ):
            with self.subTest(path=path):
                self.assertIn(path, routes)
                self.assertEqual(routes[path].methods, {"GET", "HEAD"})
                self.assertEqual(routes[path].endpoint.__name__, "oauth_resource")
        self.assertEqual(routes["/mcp"].endpoint.__name__, "proxy")
        self.assertEqual(routes["/mcp"].methods, {"DELETE", "GET", "HEAD", "POST"})

    def test_oauth_discovery_advertises_ingress_facing_mcp_resource(self) -> None:
        response = asyncio.run(self._transport().oauth_resource(self._request()))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.body),
            {
                "resource": "http://127.0.0.1:18180/mcp",
                "resource_name": "Grabowski MCP",
                "authorization_servers": [],
                "bearer_methods_supported": [],
            },
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["content-type"], "application/json")

    def test_oauth_discovery_resource_preserves_asgi_root_path(self) -> None:
        response = asyncio.run(
            self._transport().oauth_resource(self._request(root_path="/mounted"))
        )
        self.assertEqual(
            json.loads(response.body)["resource"],
            "http://127.0.0.1:18180/mounted/mcp",
        )


if __name__ == "__main__":
    unittest.main()
