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
import http.client
import math
import os
import signal
from contextlib import contextmanager
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
CLAUDE_USAGE_API_HOST = "api.anthropic.com"
CLAUDE_USAGE_API_PATH = "/api/oauth/usage?at_wall=1&skip_spend=1"
CLAUDE_USAGE_TIMEOUT_SECONDS = 5
CLAUDE_USAGE_MAX_RESPONSE_BYTES = 64 * 1024
CLAUDE_USAGE_MAX_JSON_INTEGER_DIGITS = 128


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




def _bounded_json_int(value: str) -> int:
    digits = value.lstrip("-")
    if not digits or len(digits) > CLAUDE_USAGE_MAX_JSON_INTEGER_DIGITS:
        raise ValueError("JSON integer is outside the quota-evidence bound")
    return int(value)


@contextmanager
def _quota_request_deadline(seconds: float):
    """Bound the whole synchronous quota request, including DNS and body reads."""

    try:
        previous_handler = signal.getsignal(signal.SIGALRM)
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
    except (AttributeError, OSError, ValueError) as exc:
        raise TimeoutError("quota request deadline is unavailable") from exc
    if previous_timer != (0.0, 0.0):
        raise TimeoutError("quota request deadline is already in use")

    def _deadline_expired(_signum: int, _frame: Any) -> None:
        raise TimeoutError("quota request deadline exceeded")

    armed = False
    try:
        signal.signal(signal.SIGALRM, _deadline_expired)
        signal.setitimer(signal.ITIMER_REAL, float(seconds))
        armed = True
        yield
    except (AttributeError, OSError, ValueError) as exc:
        raise TimeoutError("quota request deadline is unavailable") from exc
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        try:
            signal.signal(signal.SIGALRM, previous_handler)
        except (AttributeError, OSError, ValueError):
            pass


def _unknown_claude_quota_readiness(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "source": "claude_oauth_usage_at_wall_skip_spend",
        "reason": reason,
        "authentication_is_quota_evidence": False,
        "provider_available": None,
        "subscription_quota_not_exhausted": None,
        "remaining_five_hour_quota": None,
        "remaining_weekly_quota": None,
        "five_hour": None,
        "seven_day": None,
        "spend_and_credits_considered": False,
        "does_not_establish": [
            "remaining_five_hour_quota",
            "remaining_weekly_quota",
            "provider_availability",
            "sufficient_quota_for_complete_benchmark_pair",
            "model_request_success",
            "retry_authority",
        ],
    }


def _validated_claude_usage_window(
    payload: dict[str, Any], key: str
) -> dict[str, Any] | None:
    window = payload.get(key)
    if not isinstance(window, dict):
        return None
    utilization = window.get("utilization")
    if isinstance(utilization, bool) or not isinstance(utilization, (int, float)):
        return None
    if isinstance(utilization, float) and not math.isfinite(utilization):
        return None
    if utilization < 0 or utilization > 100:
        return None
    utilization_percent = float(utilization)
    resets_at = window.get("resets_at")
    if resets_at is not None:
        if not isinstance(resets_at, str) or not resets_at.strip():
            return None
        try:
            parsed_reset = datetime.fromisoformat(resets_at.replace("Z", "+00:00"))
            if parsed_reset.tzinfo is None:
                return None
            normalized_reset = parsed_reset.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None
        if normalized_reset <= _utc_now():
            return None
    return {
        "utilization_percent": utilization_percent,
        "remaining_percent": round(100.0 - utilization_percent, 6),
        "resets_at": resets_at,
    }


def _claude_quota_readiness(
    credential_data: bytes | None = None,
) -> dict[str, Any]:
    """Read Claude subscription utilization without sending a model request.

    Claude Code itself uses this OAuth account-read endpoint for ``/usage``. The
    at-wall form is intentionally paired with ``skip_spend=1`` so benchmark
    admission never treats optional spend or usage credits as subscription quota.
    Authentication alone remains distinct from quota evidence, and any malformed
    credential, response, or network failure degrades to an explicit unknown state.
    """

    if credential_data is None:
        return _unknown_claude_quota_readiness("oauth_credential_unavailable")
    try:
        credential = json.loads(
            credential_data.decode("utf-8"), parse_int=_bounded_json_int
        )
    except (UnicodeDecodeError, ValueError):
        return _unknown_claude_quota_readiness("credential_json_invalid")
    if not isinstance(credential, dict):
        return _unknown_claude_quota_readiness("credential_json_invalid")
    oauth = credential.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        return _unknown_claude_quota_readiness("oauth_access_token_unavailable")
    access_token = oauth.get("accessToken")
    if (
        not isinstance(access_token, str)
        or not access_token
        or access_token != access_token.strip()
        or len(access_token) > 16384
    ):
        return _unknown_claude_quota_readiness("oauth_access_token_unavailable")

    connection: http.client.HTTPSConnection | None = None
    try:
        with _quota_request_deadline(CLAUDE_USAGE_TIMEOUT_SECONDS):
            connection = http.client.HTTPSConnection(
                CLAUDE_USAGE_API_HOST, timeout=CLAUDE_USAGE_TIMEOUT_SECONDS
            )
            connection.request(
                "GET",
                CLAUDE_USAGE_API_PATH,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                return _unknown_claude_quota_readiness(
                    f"usage_http_status_{response.status}"
                )
            raw_response = response.read(CLAUDE_USAGE_MAX_RESPONSE_BYTES + 1)
    except Exception:
        return _unknown_claude_quota_readiness("usage_request_failed")
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    if len(raw_response) > CLAUDE_USAGE_MAX_RESPONSE_BYTES:
        return _unknown_claude_quota_readiness("usage_response_too_large")
    try:
        payload = json.loads(
            raw_response.decode("utf-8"), parse_int=_bounded_json_int
        )
    except (UnicodeDecodeError, ValueError):
        return _unknown_claude_quota_readiness("usage_response_invalid")
    if not isinstance(payload, dict):
        return _unknown_claude_quota_readiness("usage_response_invalid")

    five_hour = _validated_claude_usage_window(payload, "five_hour")
    seven_day = _validated_claude_usage_window(payload, "seven_day")
    if five_hour is None or seven_day is None:
        return _unknown_claude_quota_readiness(
            "required_usage_windows_unavailable"
        )

    subscription_quota_not_exhausted = (
        five_hour["remaining_percent"] > 0
        and seven_day["remaining_percent"] > 0
    )
    return {
        "status": "observed",
        "source": "claude_oauth_usage_at_wall_skip_spend",
        "reason": None,
        "authentication_is_quota_evidence": False,
        "provider_available": None,
        "subscription_quota_not_exhausted": subscription_quota_not_exhausted,
        "remaining_five_hour_quota": five_hour["remaining_percent"],
        "remaining_weekly_quota": seven_day["remaining_percent"],
        "five_hour": five_hour,
        "seven_day": seven_day,
        "spend_and_credits_considered": False,
        "does_not_establish": [
            "provider_availability",
            "sufficient_quota_for_complete_benchmark_pair",
            "model_request_success",
            "retry_authority",
        ],
    }


def _validated_live_credential_binding(
    credential: Path | None,
) -> tuple[bytes, os.stat_result, dict[str, Any]]:
    if credential is None:
        raise _core.PreflightError("live preflight requires credential file")
    credential_path = credential.expanduser()
    canonical_credential = _canonical_claude_credential_path()
    if credential_path != canonical_credential:
        raise _core.PreflightError("live preflight credential path is not canonical")
    try:
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
    credential_sha256 = hashlib.sha256(credential_data).hexdigest()
    authorized_sha256 = _authorized_credential_sha256.get()
    if authorized_sha256 is None:
        _authorized_credential_sha256.set(credential_sha256)
    elif authorized_sha256 != credential_sha256:
        raise _core.PreflightError(
            "Claude credential file changed after authorization"
        )
    return credential_data, credential_metadata, commitment


def _quota_readiness_only_report(credential: Path) -> dict[str, Any]:
    credential_data, credential_metadata, commitment = (
        _validated_live_credential_binding(credential)
    )
    readiness = _claude_quota_readiness(credential_data)
    return {
        "kind": "grabowski.claude_quota_readiness",
        "version": "1.0",
        "status": readiness["status"],
        "quota_readiness": readiness,
        "credential": {
            "bytes": len(credential_data),
            "mode": oct(credential_metadata.st_mode & 0o777),
            "credential_digest_public": False,
            "commitment": commitment,
        },
        "provider_process_intents": 0,
        "model_request_intents": 0,
        "dispatch_ledger_created": False,
        "does_not_establish": [
            "benchmark_authorization",
            "benchmark_dispatch",
            "retry_authority",
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
    credential_data, credential_metadata, commitment = (
        _validated_live_credential_binding(credential)
    )
    try:
        executable = _core.runner._validate_provider_executable(
            stream_fixture=None,
            executable=claude,
            expected_sha256=command_sha,
        )
    except _core.runner.RunnerError as exc:
        raise _core.PreflightError(str(exc)) from exc
    executable_path = Path(executable)
    executable_metadata = executable_path.lstat()
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
    parser.add_argument("--claude-credential-commitment-nonce", "--quota-commitment-nonce", dest="claude_credential_commitment_nonce")
    parser.add_argument("--claude-credential-commitment-sha256", "--quota-commitment-sha256", dest="claude_credential_commitment_sha256")
    parser.add_argument("--claude-credential-commitment-issued-at", "--quota-commitment-issued-at", dest="claude_credential_commitment_issued_at")
    parser.add_argument("--claude-quota-readiness-only", action="store_true")
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    adapter, remaining = _adapter_arguments(argv)
    if adapter.claude_quota_readiness_only:
        if remaining:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": "quota-readiness-only accepts no benchmark arguments",
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        if adapter.claude_credential_file is not None:
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": (
                            "quota-readiness-only derives the canonical credential "
                            "path internally"
                        ),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        if any(
            value is None
            for value in (
                adapter.claude_credential_commitment_nonce,
                adapter.claude_credential_commitment_sha256,
                adapter.claude_credential_commitment_issued_at,
            )
        ):
            print(
                json.dumps(
                    {
                        "status": "error",
                        "error": (
                            "quota-readiness-only requires an opaque credential "
                            "commitment"
                        ),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        try:
            credential = _canonical_claude_credential_path()
        except _core.PreflightError as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
        credential_token = _credential_file.set(credential)
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
            report = _quota_readiness_only_report(credential)
        except (_core.PreflightError, _core.runner.RunnerError) as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, sort_keys=True),
                file=sys.stderr,
            )
            return 2
        finally:
            _authorized_credential_sha256.reset(authorized_credential_token)
            _credential_commitment_issued_at.reset(commitment_time_token)
            _credential_commitment_sha256.reset(commitment_sha_token)
            _credential_commitment_nonce.reset(commitment_nonce_token)
            _credential_file.reset(credential_token)
        json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True)
        sys.stdout.write("\n")
        return 0
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
