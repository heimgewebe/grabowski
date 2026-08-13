from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
import unittest


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
try:
    STARLETTE_AVAILABLE = importlib.util.find_spec("starlette") is not None
except (ImportError, ValueError):
    STARLETTE_AVAILABLE = False


class TransportIngressOAuthDiscoveryTests(unittest.TestCase):
    def _transport(self) -> object:
        return ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=RUNTIME_BINDING_SHA256,
        )

    def test_oauth_metadata_contract_is_dependency_free_and_root_path_safe(self) -> None:
        self.assertEqual(
            ingress._oauth_protected_resource_metadata("http://127.0.0.1:18180/"),
            {
                "resource": "http://127.0.0.1:18180/mcp",
                "resource_name": "Grabowski MCP",
                "authorization_servers": [],
                "bearer_methods_supported": [],
            },
        )
        self.assertEqual(
            ingress._oauth_protected_resource_metadata(
                "http://127.0.0.1:18180/mounted/"
            )["resource"],
            "http://127.0.0.1:18180/mounted/mcp",
        )

    @unittest.skipUnless(
        STARLETTE_AVAILABLE,
        "Starlette is optional in dependency-free repository validation",
    )
    def test_build_app_uses_real_starlette_route_semantics(self) -> None:
        from starlette.routing import Route

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

    @unittest.skipUnless(
        STARLETTE_AVAILABLE,
        "Starlette is optional in dependency-free repository validation",
    )
    def test_oauth_response_uses_real_starlette_json_response(self) -> None:
        from starlette.requests import Request

        request = Request(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": ingress.OAUTH_PROTECTED_RESOURCE_PATH,
                "raw_path": ingress.OAUTH_PROTECTED_RESOURCE_PATH.encode("ascii"),
                "root_path": "",
                "query_string": b"",
                "headers": [],
                "server": ("127.0.0.1", 18180),
                "client": ("127.0.0.1", 40000),
            }
        )
        response = asyncio.run(self._transport().oauth_resource(request))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.body),
            ingress._oauth_protected_resource_metadata("http://127.0.0.1:18180/"),
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["content-type"], "application/json")


if __name__ == "__main__":
    unittest.main()
