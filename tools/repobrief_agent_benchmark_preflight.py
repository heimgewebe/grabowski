#!/usr/bin/env python3
"""Canonical CLI adapter for the RepoBrief live-preflight core.

The core was built against the first runner contract. This small boundary maps
that internal cost argument onto the hardened runner contract merged in PR
#182. It is the only supported executable entry point for the preflight.
"""
from __future__ import annotations

from decimal import Decimal
import importlib.util
from pathlib import Path
import sys
from typing import Any

CORE_PATH = Path(__file__).with_name("repobrief_agent_benchmark_preflight_core.py")
SPEC = importlib.util.spec_from_file_location(
    "repobrief_agent_benchmark_preflight_core", CORE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load RepoBrief benchmark preflight core")
_core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = _core
SPEC.loader.exec_module(_core)

_original_execute = _core.runner.execute


def _require_cost(value: Any, label: str, *, maximum: Decimal) -> Decimal:
    """Parse the runner budget and apply the stricter preflight maximum."""

    normalized = _core.runner._parse_max_budget_usd(value)
    amount = Decimal(normalized)
    if amount > maximum:
        raise _core.runner.RunnerError(f"{label} must be > 0 and <= {maximum}")
    return amount


def _execute_adapter(
    request: dict[str, Any],
    *,
    request_root: Path,
    repository_map: Path,
    state_root: Path,
    transcript_root: Path,
    claude: str,
    max_cost_usd: Decimal,
    stream_fixture: Path | None = None,
) -> dict[str, Any]:
    """Translate the core call into the explicit live-authorization contract."""

    fixture = stream_fixture is not None
    budget = None if fixture else format(max_cost_usd, "f")
    return _original_execute(
        request,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        claude=claude,
        stream_fixture=stream_fixture,
        allow_live_provider=not fixture,
        max_budget_usd=budget,
    )


_core.runner._require_cost = _require_cost
_core.runner.execute = _execute_adapter
runner = _core.runner


def __getattr__(name: str) -> Any:
    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_core)))


def main(argv: list[str] | None = None) -> int:
    return int(_core.main(argv))


if __name__ == "__main__":
    raise SystemExit(main())
