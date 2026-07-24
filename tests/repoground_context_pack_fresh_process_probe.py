"""Emit one repoground_context_pack payload from a genuinely fresh interpreter.

Started as a child process by tests/test_repoground_bundles.py so the
determinism contract can be observed across real process boundaries instead of
across repeated in-process calls. The single argument is a JSON object that
binds the child to an already-materialised bundle fixture. Query-lane tests may
also bind an immutable synthetic query result; the child performs no fixture
setup or result normalisation of its own.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import types


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorator(func):
            self.tools[kwargs.get("name", func.__name__)] = func
            return func

        return decorator

    def run(self, *args, **kwargs):
        return None


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _install_mcp_stubs() -> None:
    mcp_pkg = types.ModuleType("mcp")
    mcp_server_pkg = types.ModuleType("mcp.server")
    mcp_fastmcp_pkg = types.ModuleType("mcp.server.fastmcp")
    mcp_fastmcp_pkg.FastMCP = _FakeFastMCP
    mcp_types_pkg = types.ModuleType("mcp.types")
    mcp_types_pkg.ToolAnnotations = _FakeToolAnnotations
    sys.modules.setdefault("mcp", mcp_pkg)
    sys.modules.setdefault("mcp.server", mcp_server_pkg)
    sys.modules.setdefault("mcp.server.fastmcp", mcp_fastmcp_pkg)
    sys.modules.setdefault("mcp.types", mcp_types_pkg)


def main(argv: list[str]) -> int:
    config = json.loads(argv[1])
    sys.path.insert(0, str(Path(config["src_root"])))
    _install_mcp_stubs()

    import grabowski_mcp as mcp

    mcp.HOME = Path(config["home"])
    mcp.MERGES_ROOT = Path(config["merges"])
    mcp.REPOGROUND_PUBLICATION_ROOT = Path(config["publications"])
    mcp.BUNDLE_REGISTRY = Path(config["registry"])
    mcp._require_capability = lambda _capability: None
    preflight = config.get("preflight")
    if preflight is not None:

        def _fixed_preflight(*_args, **_kwargs):
            return json.loads(json.dumps(preflight))

        mcp._repoground_agent_preflight = _fixed_preflight

    query_payload = config.get("query_payload")
    if query_payload is not None:
        expected_query = config.get("query")
        expected_k = config.get("k", 5)

        def _fixed_query(
            _manifest,
            query,
            *,
            k,
            filters,
            resolve_evidence,
            project_sources,
        ):
            if query != expected_query or k != expected_k:
                raise RuntimeError("fresh-process query binding mismatch")
            if filters != {} or not resolve_evidence or not project_sources:
                raise RuntimeError("fresh-process query mode mismatch")
            return json.loads(json.dumps(query_payload))

        mcp._repoground_query_existing_index = _fixed_query

    payload = mcp.repoground_context_pack(
        config["repo"],
        config["task_profile"],
        stem=config.get("stem"),
        query=config.get("query"),
        k=config.get("k", 5),
        max_snippets=config.get("max_snippets", 5),
    )
    sys.stdout.write(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
