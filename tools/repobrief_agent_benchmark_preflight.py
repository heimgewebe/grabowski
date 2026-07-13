#!/usr/bin/env python3
"""Canonical authorization adapter for the RepoBrief live-preflight core.

The extensive orchestrator core is kept independent from provider-specific
credential handling. This adapter binds it to the final hardened runner
contract: explicit live authorization, bounded provider spend, a private OAuth
credential file, and an absolute SHA-256-bound Claude executable.
"""
from __future__ import annotations

import argparse
import hashlib
from contextvars import ContextVar
from decimal import Decimal
import importlib.util
import json
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
_original_provider_environment = _core.runner._provider_environment
_credential_file: ContextVar[Path | None] = ContextVar(
    "repobrief_preflight_credential_file", default=None
)
_command_sha256: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_command_sha256", default=None
)


def _require_cost(value: Any, label: str, *, maximum: Decimal) -> Decimal:
    normalized = _core.runner._parse_max_budget_usd(value)
    amount = Decimal(normalized)
    if amount > maximum:
        raise _core.runner.RunnerError(f"{label} must be > 0 and <= {maximum}")
    return amount


def _provider_environment_adapter(auth_config: Path | None = None) -> dict[str, str]:
    """Preserve runner auth isolation and support the core's version probe."""

    if auth_config is None:
        return _core._unprivileged_environment()
    return _original_provider_environment(auth_config)


def _dispatch_provider_binding_adapter(
    claude: str, synthetic: bool
) -> dict[str, Any]:
    credential = _credential_file.get()
    command_sha = _command_sha256.get()
    if synthetic:
        if credential is not None or command_sha is not None:
            raise _core.PreflightError(
                "synthetic fixtures must not carry live provider bindings"
            )
        return {
            "mode": "synthetic_fixture",
            "claude_command": claude,
        }
    if credential is None or command_sha is None:
        raise _core.PreflightError(
            "live preflight requires credential file and Claude executable SHA-256"
        )
    try:
        executable = _core.runner._validate_provider_executable(
            stream_fixture=None,
            executable=claude,
            expected_sha256=command_sha,
        )
        credential_data = _core.runner._validated_credential_data(
            stream_fixture=None,
            credential_file=credential,
        )
    except _core.runner.RunnerError as exc:
        raise _core.PreflightError(str(exc)) from exc
    if credential_data is None:
        raise _core.PreflightError("live credential binding is unavailable")
    executable_path = Path(executable)
    credential_path = credential.expanduser()
    executable_metadata = executable_path.lstat()
    credential_metadata = credential_path.lstat()
    return {
        "mode": "live_provider",
        "claude": {
            "path": str(executable_path),
            "bytes": executable_metadata.st_size,
            "sha256": command_sha,
        },
        "credential": {
            "path": str(credential_path.resolve()),
            "bytes": len(credential_data),
            "sha256": hashlib.sha256(credential_data).hexdigest(),
            "mode": oct(credential_metadata.st_mode & 0o777),
        },
    }


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
    fixture = stream_fixture is not None
    credential = _credential_file.get()
    command_sha = _command_sha256.get()
    if fixture:
        if credential is not None or command_sha is not None:
            raise _core.PreflightError(
                "synthetic fixtures must not carry live provider bindings"
            )
    elif credential is None or command_sha is None:
        raise _core.PreflightError(
            "live preflight requires credential file and Claude executable SHA-256"
        )
    return _original_execute(
        request,
        request_root=request_root,
        repository_map=repository_map,
        state_root=state_root,
        transcript_root=transcript_root,
        claude=claude,
        stream_fixture=stream_fixture,
        allow_live_provider=not fixture,
        max_budget_usd=None if fixture else format(max_cost_usd, "f"),
        claude_credential_file=credential,
        claude_command_sha256=command_sha,
    )


_core.runner._require_cost = _require_cost
_core.runner._provider_environment = _provider_environment_adapter
_core.runner.execute = _execute_adapter
_core._dispatch_provider_binding = _dispatch_provider_binding_adapter
runner = _core.runner


def execute_preflight(
    *,
    claude_credential_file: Path | None = None,
    claude_command_sha256: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    baseline_fixture = kwargs.get("baseline_fixture")
    treatment_fixture = kwargs.get("treatment_fixture")
    synthetic = baseline_fixture is not None or treatment_fixture is not None
    if synthetic and (
        claude_credential_file is not None or claude_command_sha256 is not None
    ):
        raise _core.PreflightError(
            "synthetic fixtures must not carry live provider bindings"
        )
    if not synthetic and (
        claude_credential_file is None or claude_command_sha256 is None
    ):
        raise _core.PreflightError(
            "live preflight requires credential file and Claude executable SHA-256"
        )
    credential_token = _credential_file.set(claude_credential_file)
    sha_token = _command_sha256.set(claude_command_sha256)
    try:
        return _core.execute_preflight(**kwargs)
    finally:
        _command_sha256.reset(sha_token)
        _credential_file.reset(credential_token)


def __getattr__(name: str) -> Any:
    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_core)))


def _adapter_arguments(argv: list[str] | None) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--claude-credential-file", type=Path)
    parser.add_argument("--claude-command-sha256")
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    adapter, remaining = _adapter_arguments(argv)
    synthetic = (
        "--baseline-stream-fixture" in remaining
        or "--treatment-stream-fixture" in remaining
    )
    if synthetic and (
        adapter.claude_credential_file is not None
        or adapter.claude_command_sha256 is not None
    ):
        error = "synthetic fixtures must not carry live provider bindings"
        print(json.dumps({"status": "error", "error": error}), file=sys.stderr)
        return 2
    if not synthetic and (
        adapter.claude_credential_file is None
        or adapter.claude_command_sha256 is None
    ):
        error = "live preflight requires credential file and Claude executable SHA-256"
        print(json.dumps({"status": "error", "error": error}), file=sys.stderr)
        return 2
    credential_token = _credential_file.set(adapter.claude_credential_file)
    sha_token = _command_sha256.set(adapter.claude_command_sha256)
    try:
        return int(_core.main(remaining))
    finally:
        _command_sha256.reset(sha_token)
        _credential_file.reset(credential_token)


if __name__ == "__main__":
    raise SystemExit(main())
