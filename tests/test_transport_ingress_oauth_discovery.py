from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import types
import unittest
from unittest import mock


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


class _FakeJSONResponse:
    def __init__(
        self,
        content: object,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = json.dumps(content, separators=(",", ":")).encode("utf-8")
        self.headers = {} if headers is None else dict(headers)


class _FakeRoute:
    def __init__(self, path: str, endpoint: object, *, methods: list[str]) -> None:
        self.path = path
        self.endpoint = endpoint
        self.methods = methods


class _FakeStarletteApp:
    def __init__(self, *, routes: list[object]) -> None:
        self.routes = routes


class TransportIngressOAuthDiscoveryTests(unittest.TestCase):
    def _transport(self) -> object:
        return ingress.TransportIngress(
            token=SECRET,
            upstream=ingress.DEFAULT_UPSTREAM,
            runtime_binding_sha256=RUNTIME_BINDING_SHA256,
        )

    def test_build_app_exposes_both_oauth_discovery_paths_without_mcp_auth(self) -> None:
        fake_starlette = types.ModuleType("starlette")
        fake_applications = types.ModuleType("starlette.applications")
        fake_routing = types.ModuleType("starlette.routing")
        fake_applications.Starlette = _FakeStarletteApp
        fake_routing.Route = _FakeRoute
        fake_starlette.applications = fake_applications
        fake_starlette.routing = fake_routing
        with mock.patch.dict(
            sys.modules,
            {
                "starlette": fake_starlette,
                "starlette.applications": fake_applications,
                "starlette.routing": fake_routing,
            },
        ):
            app = ingress.build_app(
                token=SECRET,
                upstream=ingress.DEFAULT_UPSTREAM,
                runtime_binding_sha256=RUNTIME_BINDING_SHA256,
            )
        routes = {route.path: route for route in app.routes}
        for path in (
            ingress.OAUTH_PROTECTED_RESOURCE_PATH,
            ingress.OAUTH_PROTECTED_RESOURCE_MCP_PATH,
        ):
            with self.subTest(path=path):
                self.assertIn(path, routes)
                self.assertEqual(routes[path].methods, ["GET"])
                self.assertEqual(routes[path].endpoint.__name__, "oauth_resource")
        self.assertEqual(routes["/mcp"].endpoint.__name__, "proxy")

    def test_oauth_discovery_advertises_ingress_facing_mcp_resource(self) -> None:
        fake_starlette = types.ModuleType("starlette")
        fake_responses = types.ModuleType("starlette.responses")
        fake_responses.JSONResponse = _FakeJSONResponse
        fake_starlette.responses = fake_responses
        request = SimpleNamespace(base_url="http://127.0.0.1:18180/")
        with mock.patch.dict(
            sys.modules,
            {
                "starlette": fake_starlette,
                "starlette.responses": fake_responses,
            },
        ):
            response = asyncio.run(self._transport().oauth_resource(request))
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
        self.assertEqual(response.headers, {"Cache-Control": "no-store"})


if __name__ == "__main__":
    unittest.main()
