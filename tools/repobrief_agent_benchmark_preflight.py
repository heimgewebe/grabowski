#!/usr/bin/env python3
"""Canonical authorization adapter for the RepoBrief live-preflight core.

The extensive orchestrator core is kept independent from provider-specific
credential handling. This adapter binds it to the final hardened runner
contract: explicit live authorization, bounded provider spend, a private OAuth
credential file, and an absolute SHA-256-bound Claude executable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import os
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
_original_validated_credential_data = _core.runner._validated_credential_data
_credential_file: ContextVar[Path | None] = ContextVar(
    "repobrief_preflight_credential_file", default=None
)
_command_sha256: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_command_sha256", default=None
)
_authorized_credential_sha256: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_authorized_credential_sha256", default=None
)
_credential_commitment_nonce: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_credential_commitment_nonce", default=None
)
_credential_commitment_sha256: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_credential_commitment_sha256", default=None
)
_credential_commitment_issued_at: ContextVar[str | None] = ContextVar(
    "repobrief_preflight_credential_commitment_issued_at", default=None
)
CLAUDE_AUTH_ROOT_ENV = "GRABOWSKI_CLAUDE_AUTH_ROOT"
CLAUDE_CREDENTIAL_COMMITMENT_KIND = "grabowski.claude_credential_commitment"
CLAUDE_CREDENTIAL_COMMITMENT_DOMAIN = "grabowski.claude-credential-commitment.v1"
CLAUDE_CREDENTIAL_COMMITMENT_MAX_AGE_SECONDS = 600
CLAUDE_CREDENTIAL_COMMITMENT_CLOCK_SKEW_SECONDS = 120


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _commitment_sha256(credential_data: bytes, nonce: str) -> str:
    credential_sha256 = hashlib.sha256(credential_data).hexdigest()
    payload = json.dumps(
        {
            "domain": CLAUDE_CREDENTIAL_COMMITMENT_DOMAIN,
            "nonce": nonce,
            "credential_sha256": credential_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_claude_credential_path() -> Path:
    auth_root = Path(
        os.environ.get(CLAUDE_AUTH_ROOT_ENV, str(Path.home() / ".claude"))
    ).expanduser()
    if not auth_root.is_absolute() or auth_root.is_symlink():
        raise _core.PreflightError("canonical Claude auth root is invalid")
    return auth_root / ".credentials.json"


def _validated_credential_commitment(credential_data: bytes) -> dict[str, Any]:
    nonce = _credential_commitment_nonce.get()
    expected = _credential_commitment_sha256.get()
    issued_at = _credential_commitment_issued_at.get()
    if not isinstance(nonce, str) or len(nonce) != 32 or any(
        char not in "0123456789abcdef" for char in nonce
    ):
        raise _core.PreflightError("Claude credential commitment nonce is invalid")
    if not isinstance(expected, str) or len(expected) != 64 or any(
        char not in "0123456789abcdef" for char in expected
    ):
        raise _core.PreflightError("Claude credential commitment SHA-256 is invalid")
    try:
        parsed = datetime.fromisoformat(str(issued_at).replace("Z", "+00:00"))
    except ValueError as exc:
        raise _core.PreflightError("Claude credential commitment timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise _core.PreflightError("Claude credential commitment timestamp is invalid")
    parsed = parsed.astimezone(timezone.utc)
    age_seconds = (_utc_now() - parsed).total_seconds()
    if age_seconds < -CLAUDE_CREDENTIAL_COMMITMENT_CLOCK_SKEW_SECONDS:
        raise _core.PreflightError("Claude credential commitment timestamp is in the future")
    if age_seconds > CLAUDE_CREDENTIAL_COMMITMENT_MAX_AGE_SECONDS:
        raise _core.PreflightError("Claude credential commitment is stale")
    actual = _commitment_sha256(credential_data, nonce)
    if not hmac.compare_digest(actual, expected):
        raise _core.PreflightError("Claude credential commitment mismatch")
    return {
        "schema_version": 1,
        "kind": CLAUDE_CREDENTIAL_COMMITMENT_KIND,
        "nonce": nonce,
        "commitment_sha256": expected,
        "generated_at": parsed.isoformat().replace("+00:00", "Z"),
        "max_age_seconds": CLAUDE_CREDENTIAL_COMMITMENT_MAX_AGE_SECONDS,
        "credential_digest_public": False,
    }


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


def _validated_credential_data_adapter(
    *,
    stream_fixture: Path | None,
    credential_file: Path | None,
) -> bytes | None:
    data = _original_validated_credential_data(
        stream_fixture=stream_fixture, credential_file=credential_file
    )
    expected = _authorized_credential_sha256.get()
    if stream_fixture is not None:
        if expected is not None:
            raise _core.runner.RunnerError(
                "synthetic fixture received a live credential authorization"
            )
        return data
    if data is None or expected is None:
        raise _core.runner.RunnerError(
            "live credential authorization is unavailable"
        )
    if hashlib.sha256(data).hexdigest() != expected:
        raise _core.runner.RunnerError(
            "Claude credential file changed after authorization"
        )
    return data


def _claude_quota_readiness() -> dict[str, Any]:
    """Bind the fact that remaining Claude subscription quota is not observable here.

    Authentication and an intact local credential prove only that Claude Code can
    attempt provider access. They do not prove remaining five-hour or weekly quota.
    The benchmark must never spend a model request merely to discover that state.
    """

    return {
        "status": "unknown",
        "source": "non_consuming_quota_surface_not_configured",
        "authentication_is_quota_evidence": False,
        "provider_available": None,
        "remaining_five_hour_quota": None,
        "remaining_weekly_quota": None,
        "does_not_establish": [
            "remaining_five_hour_quota",
            "remaining_weekly_quota",
            "provider_availability",
        ],
    }


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
    credential_path = credential.expanduser()
    canonical_credential = _canonical_claude_credential_path()
    if credential_path != canonical_credential:
        raise _core.PreflightError("live preflight credential path is not canonical")
    try:
        executable = _core.runner._validate_provider_executable(
            stream_fixture=None,
            executable=claude,
            expected_sha256=command_sha,
        )
        credential_data = _original_validated_credential_data(
            stream_fixture=None,
            credential_file=credential,
        )
    except _core.runner.RunnerError as exc:
        raise _core.PreflightError(str(exc)) from exc
    if credential_data is None:
        raise _core.PreflightError("live credential binding is unavailable")
    credential_metadata = credential_path.lstat()
    if credential_metadata.st_uid != os.getuid() or credential_metadata.st_nlink != 1:
        raise _core.PreflightError("Claude credential file is not owner-private")
    commitment = _validated_credential_commitment(credential_data)
    executable_path = Path(executable)
    executable_metadata = executable_path.lstat()
    credential_sha256 = hashlib.sha256(credential_data).hexdigest()
    authorized_sha256 = _authorized_credential_sha256.get()
    if authorized_sha256 is None:
        _authorized_credential_sha256.set(credential_sha256)
    elif authorized_sha256 != credential_sha256:
        raise _core.PreflightError(
            "Claude credential file changed after authorization"
        )
    return {
        "mode": "live_provider",
        "claude": {
            "path": str(executable_path),
            "bytes": executable_metadata.st_size,
            "sha256": command_sha,
        },
        "credential": {
            "bytes": len(credential_data),
            "mode": oct(credential_metadata.st_mode & 0o777),
            "credential_digest_public": False,
            "commitment": commitment,
        },
        "quota_readiness": _claude_quota_readiness(),
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
_core.runner._validated_credential_data = _validated_credential_data_adapter
_core.runner.execute = _execute_adapter
_core._dispatch_provider_binding = _dispatch_provider_binding_adapter
runner = _core.runner


def execute_preflight(
    *,
    claude_credential_file: Path | None = None,
    claude_command_sha256: str | None = None,
    claude_credential_commitment_nonce: str | None = None,
    claude_credential_commitment_sha256: str | None = None,
    claude_credential_commitment_issued_at: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    baseline_fixture = kwargs.get("baseline_fixture")
    treatment_fixture = kwargs.get("treatment_fixture")
    synthetic = baseline_fixture is not None or treatment_fixture is not None
    if synthetic and any(
        value is not None
        for value in (
            claude_credential_file,
            claude_command_sha256,
            claude_credential_commitment_nonce,
            claude_credential_commitment_sha256,
            claude_credential_commitment_issued_at,
        )
    ):
        raise _core.PreflightError(
            "synthetic fixtures must not carry live provider bindings"
        )
    if not synthetic and any(
        value is None
        for value in (
            claude_credential_file,
            claude_command_sha256,
            claude_credential_commitment_nonce,
            claude_credential_commitment_sha256,
            claude_credential_commitment_issued_at,
        )
    ):
        raise _core.PreflightError(
            "live preflight requires credential file and Claude executable SHA-256 plus opaque credential commitment"
        )
    credential_token = _credential_file.set(claude_credential_file)
    sha_token = _command_sha256.set(claude_command_sha256)
    commitment_nonce_token = _credential_commitment_nonce.set(
        claude_credential_commitment_nonce
    )
    commitment_sha_token = _credential_commitment_sha256.set(
        claude_credential_commitment_sha256
    )
    commitment_time_token = _credential_commitment_issued_at.set(
        claude_credential_commitment_issued_at
    )
    authorized_credential_token = _authorized_credential_sha256.set(None)
    try:
        return _core.execute_preflight(**kwargs)
    finally:
        _authorized_credential_sha256.reset(authorized_credential_token)
        _credential_commitment_issued_at.reset(commitment_time_token)
        _credential_commitment_sha256.reset(commitment_sha_token)
        _credential_commitment_nonce.reset(commitment_nonce_token)
        _command_sha256.reset(sha_token)
        _credential_file.reset(credential_token)


def __getattr__(name: str) -> Any:
    return getattr(_core, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_core)))


def _adapter_arguments(argv: list[str] | None) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--claude-credential-file", type=Path)
    parser.add_argument("--claude-command-sha256")
    parser.add_argument("--claude-credential-commitment-nonce")
    parser.add_argument("--claude-credential-commitment-sha256")
    parser.add_argument("--claude-credential-commitment-issued-at")
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    adapter, remaining = _adapter_arguments(argv)
    synthetic = (
        "--baseline-stream-fixture" in remaining
        or "--treatment-stream-fixture" in remaining
    )
    if synthetic and any(
        value is not None
        for value in (
            adapter.claude_credential_file,
            adapter.claude_command_sha256,
            adapter.claude_credential_commitment_nonce,
            adapter.claude_credential_commitment_sha256,
            adapter.claude_credential_commitment_issued_at,
        )
    ):
        error = "synthetic fixtures must not carry live provider bindings"
        print(json.dumps({"status": "error", "error": error}), file=sys.stderr)
        return 2
    if not synthetic and any(
        value is None
        for value in (
            adapter.claude_credential_file,
            adapter.claude_command_sha256,
            adapter.claude_credential_commitment_nonce,
            adapter.claude_credential_commitment_sha256,
            adapter.claude_credential_commitment_issued_at,
        )
    ):
        error = (
            "live preflight requires credential file and Claude executable SHA-256 "
            "plus opaque credential commitment"
        )
        print(json.dumps({"status": "error", "error": error}), file=sys.stderr)
        return 2
    credential_token = _credential_file.set(adapter.claude_credential_file)
    sha_token = _command_sha256.set(adapter.claude_command_sha256)
    commitment_nonce_token = _credential_commitment_nonce.set(
        adapter.claude_credential_commitment_nonce
    )
    commitment_sha_token = _credential_commitment_sha256.set(
        adapter.claude_credential_commitment_sha256
    )
    commitment_time_token = _credential_commitment_issued_at.set(
        adapter.claude_credential_commitment_issued_at
    )
    authorized_credential_token = _authorized_credential_sha256.set(None)
    try:
        return int(_core.main(remaining))
    finally:
        _authorized_credential_sha256.reset(authorized_credential_token)
        _credential_commitment_issued_at.reset(commitment_time_token)
        _credential_commitment_sha256.reset(commitment_sha_token)
        _credential_commitment_nonce.reset(commitment_nonce_token)
        _command_sha256.reset(sha_token)
        _credential_file.reset(credential_token)


if __name__ == "__main__":
    raise SystemExit(main())
