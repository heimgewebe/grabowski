from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import selectors
import signal
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.request

import grabowski_coding_agent_router as router

MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
MAX_GROK_AUTH_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 20
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"
OPENROUTER_OX_ALPHA_MODEL = "stealth/ox-alpha"
OPENROUTER_OX_ALPHA_OPENCODE_MODEL = "openrouter/stealth/ox-alpha"
MAX_OPENROUTER_MODELS_BYTES = 8 * 1024 * 1024
PROBE_DIGEST_DOMAIN = b"grabowski-coding-agent-probe-v3"
PROBE_DIGEST_FIELDS = (
    "schema_version",
    "observed_at",
    "harnesses",
    "providers",
    "verified_quota_pools",
    "api_key_environment_scrubbed",
    "model_invocations",
    "paid_api_requests_authorized",
)
PROBE_VERIFIABLE_QUOTA_POOLS = (
    "grok-com",
    "jules-account",
    "opencode-free",
    "openrouter-ox-alpha-preview",
    "openhands-account",
)
SENSITIVE_PROBE_FIELD_TOKENS = (
    "password",
    "passwd",
    "token",
    "secret",
    "credential",
    "api_key",
    "apikey",
)
ALLOWED_SENSITIVE_METADATA_FIELDS = frozenset({"api_key_environment_scrubbed"})
CLAUDE_AUTH_METHOD_BY_CODE = {1: "claude.ai"}
CLAUDE_SUBSCRIPTION_BY_CODE = {
    1: "pro",
    2: "max",
    3: "team",
    4: "enterprise",
}


class CodingAgentRouterCliError(RuntimeError):
    pass


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _assert_probe_digest_safe(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for raw_key, nested in value.items():
            key = str(raw_key)
            normalized = key.casefold().replace("-", "_")
            if (
                key not in ALLOWED_SENSITIVE_METADATA_FIELDS
                and any(
                    normalized == token
                    or normalized.startswith(f"{token}_")
                    or normalized.endswith(f"_{token}")
                    for token in SENSITIVE_PROBE_FIELD_TOKENS
                )
            ):
                location = ".".join((*path, key))
                raise CodingAgentRouterCliError(
                    f"probe digest payload contains sensitive field: {location}"
                )
            _assert_probe_digest_safe(nested, path=(*path, key))
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            _assert_probe_digest_safe(nested, path=(*path, str(index)))


def _probe_digest(value: dict[str, Any]) -> str:
    missing = [field for field in PROBE_DIGEST_FIELDS if field not in value]
    if missing:
        raise CodingAgentRouterCliError(
            f"probe digest payload is missing fields: {', '.join(missing)}"
        )
    projection = {field: value[field] for field in PROBE_DIGEST_FIELDS}
    _assert_probe_digest_safe(projection)
    payload = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(PROBE_DIGEST_DOMAIN, payload, hashlib.sha256).hexdigest()


def _clean_environment(catalog: dict[str, Any]) -> dict[str, str]:
    environment = dict(os.environ)
    for name in catalog["policy"].get("forbidden_api_key_env", []):
        environment.pop(name, None)
    environment["NO_COLOR"] = "1"
    return environment


def _terminate_metadata_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _run_metadata(
    argv: list[str], catalog: dict[str, Any], *, timeout: int = COMMAND_TIMEOUT_SECONDS
) -> dict[str, Any]:
    if not argv or not Path(argv[0]).is_absolute():
        return {"ok": False, "error_type": "non_absolute_executable"}
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_clean_environment(catalog),
            start_new_session=True,
        )
    except OSError as exc:
        return {"ok": False, "error_type": type(exc).__name__}
    assert process.stdout is not None and process.stderr is not None
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    error_type: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                error_type = "TimeoutExpired"
                break
            events = selector.select(min(remaining, 0.2))
            for key, _mask in events:
                stream = key.fileobj
                chunk = os.read(stream.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(stream)
                    continue
                buffer = streams[stream]
                buffer.extend(chunk)
                if len(buffer) > MAX_COMMAND_OUTPUT_BYTES:
                    error_type = "output_limit"
                    break
            if error_type is not None:
                break
        if error_type is not None:
            _terminate_metadata_process(process)
            return {"ok": False, "error_type": error_type}
        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _terminate_metadata_process(process)
            return {"ok": False, "error_type": "TimeoutExpired"}
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stdout = bytes(streams[process.stdout])
    stderr = bytes(streams[process.stderr])
    return {
        "ok": returncode == 0,
        "returncode": returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }


def _resolve_executable(binary: Any) -> str | None:
    if not isinstance(binary, str) or not binary:
        return None
    found = shutil.which(binary)
    if not found:
        return None
    try:
        resolved = Path(found).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None
    return str(resolved)


def _run_harness_metadata(
    harnesses: dict[str, Any],
    harness: str,
    arguments: list[str],
    catalog: dict[str, Any],
) -> dict[str, Any]:
    record = harnesses.get(harness, {})
    executable = record.get("binary") if isinstance(record, dict) else None
    if not isinstance(executable, str) or not Path(executable).is_absolute():
        return {"ok": False, "error_type": "binary_unavailable"}
    return _run_metadata([executable, *arguments], catalog)


def _binary_versions(catalog: dict[str, Any]) -> dict[str, Any]:
    commands = {
        "codex": ["--version"],
        "claude": ["--version"],
        "antigravity": ["--version"],
        "opencode": ["--version"],
        "openhands": ["--version"],
        "grok": ["--version"],
        "jules": ["version"],
        "cline": ["--version"],
        "qwen-code": ["--version"],
        "aider": ["--version"],
        "goose": ["--version"],
    }
    result: dict[str, Any] = {}
    for harness, specification in catalog["harnesses"].items():
        path = _resolve_executable(specification.get("binary"))
        record: dict[str, Any] = {
            "binary": path,
            "available": harness == "grabowski" or path is not None,
        }
        if path is not None and harness in commands:
            observed = _run_metadata([path, *commands[harness]], catalog)
            record["version_ok"] = observed.get("ok") is True
            version_text = str(
                observed.get("stdout") or observed.get("stderr") or ""
            )
            record["version"] = version_text.strip().splitlines()[:3]
        result[harness] = record
    return result


def _claude_auth_status_codes(value: Any) -> tuple[bool, int, int]:
    if not isinstance(value, dict):
        return False, 0, 0
    logged_in = value.get("loggedIn") is True
    auth_method_code = 1 if value.get("authMethod") == "claude.ai" else 0
    raw_subscription = value.get("subscriptionType")
    subscription_code = 0
    if raw_subscription == "pro":
        subscription_code = 1
    elif raw_subscription == "max":
        subscription_code = 2
    elif raw_subscription == "team":
        subscription_code = 3
    elif raw_subscription == "enterprise":
        subscription_code = 4
    return logged_in, auth_method_code, subscription_code


def _claude_auth_summary_from_codes(
    logged_in: bool, auth_method_code: int, subscription_code: int
) -> dict[str, Any]:
    return {
        "logged_in": logged_in is True,
        "auth_method": CLAUDE_AUTH_METHOD_BY_CODE.get(auth_method_code),
        "subscription_type": CLAUDE_SUBSCRIPTION_BY_CODE.get(subscription_code),
    }


def _claude_auth_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return _claude_auth_summary_from_codes(*_claude_auth_status_codes(value))


def _grok_subscription_auth_status(
    catalog: dict[str, Any],
    *,
    home: Path | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "authenticated": False,
        "entitlement_verified": False,
        "status": "missing",
        "subscription_tier": None,
        "account_binding_sha256": None,
    }
    contract = catalog.get("quota_pools", {}).get("grok-com", {}).get(
        "entitlement_contract"
    )
    if (
        not isinstance(contract, dict)
        or set(contract)
        != {"issuer", "kind", "plan", "principal_type", "tier_code"}
        or contract.get("kind") != "grok_oidc_tier_claim_v1"
        or not isinstance(contract.get("issuer"), str)
        or not contract.get("issuer")
        or not isinstance(contract.get("plan"), str)
        or not contract.get("plan")
        or not isinstance(contract.get("principal_type"), str)
        or not contract.get("principal_type")
        or isinstance(contract.get("tier_code"), bool)
        or not isinstance(contract.get("tier_code"), int)
    ):
        status["status"] = "invalid-contract"
        return status
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        status["status"] = "unsafe-storage"
        return status

    base = home or Path.home()
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []

    def identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    try:
        descriptors.append(os.open(str(base), directory_flags))
        home_metadata = os.fstat(descriptors[-1])
        if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_uid != os.getuid():
            status["status"] = "unsafe-home"
            return status
        descriptors.append(os.open(".grok", directory_flags, dir_fd=descriptors[-1]))
        grok_metadata = os.fstat(descriptors[-1])
        if (
            not stat.S_ISDIR(grok_metadata.st_mode)
            or grok_metadata.st_uid != os.getuid()
            or stat.S_IMODE(grok_metadata.st_mode) & 0o022
        ):
            status["status"] = "unsafe-directory"
            return status
        descriptors.append(os.open("auth.json", file_flags, dir_fd=descriptors[-1]))
        descriptor = descriptors[-1]
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 1 <= before.st_size <= MAX_GROK_AUTH_BYTES
        ):
            status["status"] = "unsafe-file"
            return status
        chunks: list[bytes] = []
        remaining = MAX_GROK_AUTH_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if identity(before) != identity(after) or len(raw) != before.st_size:
            status["status"] = "changed-during-read"
            return status
        if len(raw) > MAX_GROK_AUTH_BYTES:
            status["status"] = "oversized"
            return status
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            status["status"] = "invalid-json"
            return status
        if not isinstance(payload, dict) or len(payload) != 1:
            status["status"] = "ambiguous-account"
            return status
        account_key, record = next(iter(payload.items()))
        if not isinstance(account_key, str) or not isinstance(record, dict):
            status["status"] = "invalid-record"
            return status
        issuer = contract["issuer"]
        client_id = record.get("oidc_client_id")
        token = record.get("key")
        if (
            not isinstance(record.get("auth_mode"), str)
            or record["auth_mode"].casefold() != "oidc"
            or record.get("oidc_issuer") != issuer
            or not isinstance(client_id, str)
            or not client_id
            or account_key != f"{issuer}::{client_id}"
            or not isinstance(token, str)
            or not 64 <= len(token) <= 32768
            or token.count(".") != 2
            or any(character.isspace() for character in token)
        ):
            status["status"] = "invalid-record"
            return status
        encoded_claims = token.split(".", 2)[1]
        if not 1 <= len(encoded_claims) <= 16384:
            status["status"] = "invalid-claims"
            return status
        padded = encoded_claims + "=" * (-len(encoded_claims) % 4)
        try:
            claims_raw = base64.b64decode(
                padded.encode("ascii"), altchars=b"-_", validate=True
            )
            claims = json.loads(claims_raw.decode("utf-8"))
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
            status["status"] = "invalid-claims"
            return status
        if not isinstance(claims, dict):
            status["status"] = "invalid-claims"
            return status
        now = int(time.time()) if now_unix is None else now_unix
        expires_at = claims.get("exp")
        issued_at = claims.get("iat")
        stable_fields = ("principal_id", "principal_type", "team_id")
        if (
            isinstance(now, bool)
            or not isinstance(now, int)
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or expires_at <= now + 30
            or isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or issued_at > now + 300
            or claims.get("iss") != issuer
            or claims.get("principal_type") != contract["principal_type"]
            or claims.get("tier") != contract["tier_code"]
            or claims.get("sub") != record.get("user_id")
            or claims.get("sub") != record.get("principal_id")
            or any(
                not isinstance(record.get(field), str)
                or not record.get(field)
                or claims.get(field) != record.get(field)
                for field in stable_fields
            )
        ):
            status["status"] = "entitlement-mismatch"
            return status
        binding = {
            "issuer": issuer,
            "client_id": client_id,
            "principal_id": record["principal_id"],
            "team_id": record["team_id"],
        }
        status.update(
            {
                "authenticated": True,
                "entitlement_verified": True,
                "status": "valid",
                "subscription_tier": contract["plan"],
                "account_binding_sha256": hashlib.sha256(
                    json.dumps(
                        binding,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("utf-8")
                ).hexdigest(),
            }
        )
        return status
    except OSError:
        status["status"] = "missing"
        return status
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _configured_models(catalog: dict[str, Any], harness: str) -> list[str]:
    return sorted(
        {
            str(route["model"])
            for route in catalog["routes"]
            if route.get("harness") == harness
        }
    )


def _configured_model_aliases(
    catalog: dict[str, Any], harness: str
) -> dict[str, str]:
    configured = set(_configured_models(catalog, harness))
    candidates: dict[str, set[str]] = {
        model: {model} for model in configured
    }
    for route in catalog["routes"]:
        canonical = route.get("model")
        argv = route.get("argv_prefix")
        if (
            route.get("harness") != harness
            or canonical not in configured
            or not isinstance(argv, list)
        ):
            continue
        for index, value in enumerate(argv[:-1]):
            alias = argv[index + 1]
            if value == "--model" and isinstance(alias, str) and alias:
                candidates.setdefault(alias, set()).add(canonical)
    return {
        alias: next(iter(models))
        for alias, models in candidates.items()
        if len(models) == 1
    }


def _antigravity_models_from_output(
    catalog: dict[str, Any], stdout: str
) -> list[str]:
    aliases = _configured_model_aliases(catalog, "antigravity")
    discovered = {
        aliases[model_field]
        for line in stdout.splitlines()
        if (model_field := line.split("\t", 1)[0].strip()) in aliases
    }
    return sorted(discovered)


def _grok_models_from_output(
    catalog: dict[str, Any], stdout: str
) -> list[str]:
    marker = "Available models:"
    if marker not in stdout:
        return []
    available = stdout.split(marker, 1)[1]
    discovered = []
    for model in _configured_models(catalog, "grok"):
        pattern = rf"(?<![A-Za-z0-9._/-]){re.escape(model)}(?![A-Za-z0-9._/-])"
        if re.search(pattern, available):
            discovered.append(model)
    return discovered


def _openhands_subscription_auth_status(
    *, home: Path | None = None, now_ms: int | None = None
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "authenticated": False,
        "provider": "openai",
        "status": "missing",
        "storage_mode_ok": False,
    }
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        status["status"] = "unsafe-storage"
        return status

    base = home or Path.home()
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors: list[int] = []

    def directory_ok(metadata: os.stat_result, *, private: bool) -> bool:
        return (
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.getuid()
            and (not private or stat.S_IMODE(metadata.st_mode) & 0o077 == 0)
        )

    def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
        )

    try:
        home_fd = os.open(base, directory_flags)
        descriptors.append(home_fd)
        if not directory_ok(os.fstat(home_fd), private=False):
            status["status"] = "unsafe-storage"
            return status

        openhands_fd = os.open(".openhands", directory_flags, dir_fd=home_fd)
        descriptors.append(openhands_fd)
        if not directory_ok(os.fstat(openhands_fd), private=False):
            status["status"] = "unsafe-storage"
            return status

        auth_fd = os.open("auth", directory_flags, dir_fd=openhands_fd)
        descriptors.append(auth_fd)
        auth_before = os.fstat(auth_fd)
        if not directory_ok(auth_before, private=True):
            status["status"] = "unsafe-storage"
            return status

        credential_fd = os.open("openai_oauth.json", file_flags, dir_fd=auth_fd)
        descriptors.append(credential_fd)
        before = os.fstat(credential_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > 64 * 1024
        ):
            status["status"] = "unsafe-storage"
            return status

        payload = bytearray()
        while len(payload) <= 64 * 1024:
            chunk = os.read(credential_fd, min(16 * 1024, 64 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > 64 * 1024:
            status["status"] = "invalid"
            return status

        after = os.fstat(credential_fd)
        linked = os.stat("openai_oauth.json", dir_fd=auth_fd, follow_symlinks=False)
        auth_after = os.fstat(auth_fd)
        if (
            file_identity(before) != file_identity(after)
            or file_identity(after) != file_identity(linked)
            or file_identity(auth_before) != file_identity(auth_after)
        ):
            status["status"] = "unsafe-storage"
            return status
        status["storage_mode_ok"] = True
    except FileNotFoundError:
        return status
    except OSError:
        status["status"] = "unreadable"
        return status
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        status["status"] = "invalid"
        return status
    if not isinstance(value, dict):
        status["status"] = "invalid"
        return status
    expires_at = value.get("expires_at")
    token_shape_ok = (
        value.get("type") == "oauth"
        and value.get("vendor") == "openai"
        and isinstance(value.get("access_token"), str)
        and bool(value.get("access_token"))
        and isinstance(value.get("refresh_token"), str)
        and bool(value.get("refresh_token"))
        and isinstance(expires_at, int)
        and not isinstance(expires_at, bool)
    )
    if not token_shape_ok:
        status["status"] = "invalid"
        return status
    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if expires_at <= current_ms + 60_000:
        status["status"] = "expired"
        return status
    status["authenticated"] = True
    status["status"] = "valid"
    return status


def _opencode_free_model_verified(models: list[str]) -> bool:
    return any(
        model.startswith("opencode/")
        and (model.endswith("-free") or model.endswith(":free"))
        for model in models
    )


def _openrouter_ox_alpha_price_status() -> dict[str, Any]:
    base = {
        "available": False,
        "model_id": None,
        "price_source": "public-models-api",
        "zero_price_verified": False,
        "pricing_status": "unavailable",
    }
    request = urllib.request.Request(
        OPENROUTER_MODELS_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "grabowski-coding-agent-probe/1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=COMMAND_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_OPENROUTER_MODELS_BYTES + 1)
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        return base
    if len(payload) > MAX_OPENROUTER_MODELS_BYTES:
        return {**base, "pricing_status": "response-too-large"}
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {**base, "pricing_status": "invalid-response"}
    if not isinstance(decoded, dict) or not isinstance(decoded.get("data"), list):
        return {**base, "pricing_status": "invalid-response"}
    matches = [
        item
        for item in decoded["data"]
        if isinstance(item, dict) and item.get("id") == OPENROUTER_OX_ALPHA_MODEL
    ]
    if len(matches) != 1:
        return {**base, "available": True, "pricing_status": "model-not-unique"}
    pricing = matches[0].get("pricing")
    if not isinstance(pricing, dict) or not {"prompt", "completion"}.issubset(pricing):
        return {
            **base,
            "available": True,
            "model_id": OPENROUTER_OX_ALPHA_MODEL,
            "pricing_status": "pricing-incomplete",
        }

    def zero_price(value: Any) -> bool:
        if isinstance(value, bool) or value is None:
            return False
        try:
            return Decimal(str(value)) == Decimal("0")
        except (InvalidOperation, ValueError):
            return False

    verified = bool(pricing) and all(zero_price(value) for value in pricing.values())
    return {
        **base,
        "available": True,
        "model_id": OPENROUTER_OX_ALPHA_MODEL,
        "zero_price_verified": verified,
        "pricing_status": "zero" if verified else "nonzero-or-unknown",
    }


def _probe(catalog: dict[str, Any]) -> dict[str, Any]:
    harnesses = _binary_versions(catalog)
    providers: dict[str, Any] = {}

    providers["codex"] = {
        "available": harnesses.get("codex", {}).get("available") is True,
        "models": _configured_models(catalog, "codex"),
    }

    claude_status = _run_harness_metadata(
        harnesses, "claude", ["auth", "status"], catalog
    )
    claude_auth: dict[str, Any] = {}
    if claude_status.get("ok") is True:
        try:
            value = json.loads(str(claude_status.get("stdout", "")))
        except json.JSONDecodeError:
            value = None
        claude_auth = _claude_auth_summary_from_codes(
            *_claude_auth_status_codes(value)
        )
    providers["claude"] = {
        "available": harnesses.get("claude", {}).get("available") is True,
        "auth": claude_auth,
        "models": _configured_models(catalog, "claude"),
    }

    antigravity = _run_harness_metadata(
        harnesses, "antigravity", ["models"], catalog
    )
    providers["antigravity"] = {
        "available": harnesses.get("antigravity", {}).get("available") is True,
        "models": (
            _antigravity_models_from_output(
                catalog, str(antigravity.get("stdout", ""))
            )
            if antigravity.get("ok") is True
            else []
        ),
        "legacy_state_key": "agy",
    }
    opencode = _run_harness_metadata(harnesses, "opencode", ["models"], catalog)
    opencode_models = (
        [line.strip() for line in str(opencode.get("stdout", "")).splitlines() if line.strip()]
        if opencode.get("ok") is True
        else []
    )
    providers["opencode"] = {
        "available": harnesses.get("opencode", {}).get("available") is True,
        "models": opencode_models,
        "free_model_verified": _opencode_free_model_verified(opencode_models),
    }
    providers["openrouter"] = (
        _openrouter_ox_alpha_price_status()
        if OPENROUTER_OX_ALPHA_OPENCODE_MODEL in opencode_models
        else {
            "available": False,
            "model_id": None,
            "price_source": "public-models-api",
            "zero_price_verified": False,
            "pricing_status": "local-model-unavailable",
        }
    )
    openhands_auth = _openhands_subscription_auth_status()
    providers["openhands"] = {
        "available": harnesses.get("openhands", {}).get("available") is True,
        **openhands_auth,
        "approval_mode": "always-approve",
        "models": _configured_models(catalog, "openhands"),
    }

    grok_auth_before = _grok_subscription_auth_status(catalog)
    grok_status = _run_harness_metadata(
        harnesses, "grok", ["models"], catalog
    )
    grok_auth_after = _grok_subscription_auth_status(catalog)
    grok_models = (
        _grok_models_from_output(catalog, str(grok_status.get("stdout", "")))
        if grok_status.get("ok") is True
        else []
    )
    before_binding = grok_auth_before.get("account_binding_sha256")
    after_binding = grok_auth_after.get("account_binding_sha256")
    grok_logged_in = (
        grok_status.get("ok") is True
        and grok_auth_before.get("authenticated") is True
        and grok_auth_after.get("authenticated") is True
        and isinstance(before_binding, str)
        and before_binding == after_binding
    )
    grok_entitlement_verified = (
        grok_logged_in
        and grok_auth_before.get("entitlement_verified") is True
        and grok_auth_after.get("entitlement_verified") is True
        and "grok-4.6" in grok_models
    )
    providers["grok"] = {
        "available": harnesses.get("grok", {}).get("available") is True,
        "logged_in": grok_logged_in,
        "entitlement_verified": grok_entitlement_verified,
        "subscription_tier": (
            grok_auth_after.get("subscription_tier")
            if grok_entitlement_verified
            else None
        ),
        "account_binding_sha256": (
            after_binding if grok_entitlement_verified else None
        ),
        "auth_status": grok_auth_after.get("status"),
        "models": grok_models,
    }

    jules = _run_harness_metadata(
        harnesses, "jules", ["remote", "list", "--repo"], catalog
    )
    providers["jules"] = {
        "available": harnesses.get("jules", {}).get("available") is True,
        "authenticated": jules.get("ok") is True
        and bool(str(jules.get("stdout", "")).strip()),
        "repository_count": len(
            [line for line in str(jules.get("stdout", "")).splitlines() if line.strip()]
        ),
    }
    providers["cline"] = {
        "available": harnesses.get("cline", {}).get("available") is True,
        "config": {"free_entitlement_verified": False},
    }

    ollama_path = _resolve_executable("ollama")
    ollama = (
        _run_metadata([ollama_path, "list"], catalog)
        if ollama_path is not None
        else {"ok": False, "error_type": "binary_unavailable"}
    )
    local_models: list[str] = []
    if ollama.get("ok") is True:
        for line in str(ollama.get("stdout", "")).splitlines()[1:]:
            values = line.split()
            if values:
                local_models.append(values[0])
    providers["ollama"] = {
        "available": ollama_path is not None,
        "models": local_models,
        "loaded_models": [],
    }
    providers["local_harnesses"] = {
        key: harnesses.get(key, {}) for key in ("qwen-code", "aider", "goose")
    }

    verified_quota_pools: list[str] = []
    if providers["grok"].get("entitlement_verified") is True:
        verified_quota_pools.append("grok-com")
    if providers["jules"].get("authenticated") is True:
        verified_quota_pools.append("jules-account")
    if providers["opencode"].get("free_model_verified") is True:
        verified_quota_pools.append("opencode-free")
    if (
        OPENROUTER_OX_ALPHA_OPENCODE_MODEL in providers["opencode"].get("models", [])
        and providers["openrouter"].get("model_id") == OPENROUTER_OX_ALPHA_MODEL
        and providers["openrouter"].get("zero_price_verified") is True
    ):
        verified_quota_pools.append("openrouter-ox-alpha-preview")
    if providers["openhands"].get("authenticated") is True:
        verified_quota_pools.append("openhands-account")
    body = {
        "schema_version": 2,
        "observed_at": _iso_now(),
        "harnesses": harnesses,
        "providers": providers,
        "verified_quota_pools": verified_quota_pools,
        "api_key_environment_scrubbed": catalog["policy"].get(
            "forbidden_api_key_env", []
        ),
        "model_invocations": 0,
        "paid_api_requests_authorized": 0,
    }
    return {**body, "catalog_probe_sha256": _probe_digest(body)}


def _default_state(catalog_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "updated_at": _iso_now(),
        "catalog_sha256": catalog_sha256,
        "catalog": {},
        "pools": {},
        "routes": {},
        "history": {},
    }


def _load_mutable_state(catalog_sha256: str) -> dict[str, Any]:
    value = router._load_state()
    if not value:
        return _default_state(catalog_sha256)
    if value.get("schema_version") != 2:
        raise CodingAgentRouterCliError("router state schema_version must be 2")
    for key in ("catalog", "pools", "routes", "history"):
        if not isinstance(value.get(key, {}), dict):
            raise CodingAgentRouterCliError(f"router state {key} must be an object")
        value.setdefault(key, {})
    if value.get("catalog_sha256") != catalog_sha256:
        reset = _default_state(catalog_sha256)
        reset["history"] = value["history"]
        return reset
    return value


@contextmanager
def _exclusive_state_write_lock(path: Path):
    path = path.expanduser()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise CodingAgentRouterCliError(
            "router state parent is not a private user-owned directory"
        )
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = os.open(
        parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        descriptor = os.open(
            ".coding-agent-router-state.lock",
            flags,
            0o600,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise CodingAgentRouterCliError("router state lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _state_target_identity(path: Path) -> tuple[int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise CodingAgentRouterCliError(
            "router state target must be an owned single-link regular file"
        )
    return metadata.st_dev, metadata.st_ino


def _atomic_write_private_json(path: Path, value: dict[str, Any]) -> None:
    path = path.expanduser()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_metadata = parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise CodingAgentRouterCliError(
            "router state parent is not a private user-owned directory"
        )
    initial_target = _state_target_identity(path)
    payload = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    if len(payload) > router.MAX_STATE_BYTES:
        raise CodingAgentRouterCliError("router state exceeds the size limit")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise CodingAgentRouterCliError("temporary router state is not owned regular file")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if _state_target_identity(path) != initial_target:
            raise CodingAgentRouterCliError("router state target changed before replace")
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_probe_locked(probe: dict[str, Any], validation: dict[str, Any]) -> None:
    observed_at = probe.get("observed_at")
    if router._parse_time(observed_at) is None:
        raise CodingAgentRouterCliError("probe observed_at must be timezone-aware")
    verified_pools = probe.get("verified_quota_pools", [])
    if (
        not isinstance(verified_pools, list)
        or any(not isinstance(pool_id, str) for pool_id in verified_pools)
        or len(set(verified_pools)) != len(verified_pools)
        or any(
            pool_id not in PROBE_VERIFIABLE_QUOTA_POOLS
            for pool_id in verified_pools
        )
    ):
        raise CodingAgentRouterCliError("probe verified_quota_pools is invalid")
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    state["catalog"] = probe
    state["catalog_sha256"] = validation["catalog_sha256"]
    for pool_id in PROBE_VERIFIABLE_QUOTA_POOLS:
        pool = state["pools"].get(pool_id)
        if pool_id in verified_pools:
            state["pools"].setdefault(pool_id, {})["verified_at"] = observed_at
        elif isinstance(pool, dict):
            pool.pop("verified_at", None)
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)


def _write_probe(probe: dict[str, Any], validation: dict[str, Any]) -> None:
    state_path = router._state_path()
    with _exclusive_state_write_lock(state_path):
        _write_probe_locked(probe, validation)


def _status(catalog: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    state = router._load_state()
    bound = bool(state) and state.get("catalog_sha256") == validation["catalog_sha256"]
    fresh = bound and router._state_catalog_fresh(state)
    return {
        "schema_version": 2,
        "validation": validation,
        "catalog_source": validation.get("catalog_source"),
        "catalog_fresh": fresh,
        "live_catalog": state.get("catalog", {}) if isinstance(state, dict) else {},
        "pools": {
            key: router._effective_pool(key, catalog, state)
            for key in catalog["quota_pools"]
        }
        if isinstance(state, dict)
        else {},
        "route_stats": state.get("routes", {}) if isinstance(state, dict) else {},
        "automatic_execution_authorized": False,
        "authoritative_work": "direct_operator",
        "external_agent_authority": "advisory_review_or_explicit_contrast_only",
    }


def _bounded_nonnegative_number(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise CodingAgentRouterCliError(f"{label} must be a nonnegative finite number")
    return float(value)


def _observe_locked(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    route = router._route_map(catalog).get(arguments.route)
    if route is None or route.get("controller") is True:
        raise CodingAgentRouterCliError("observe requires a known external route")
    duration = _bounded_nonnegative_number(arguments.duration_seconds, "duration_seconds")
    rework = _bounded_nonnegative_number(arguments.rework_minutes, "rework_minutes")
    reported_cost = _bounded_nonnegative_number(
        arguments.reported_cost_usd, "reported_cost_usd"
    )
    remaining_ratio = _bounded_nonnegative_number(
        arguments.remaining_ratio, "remaining_ratio"
    )
    if remaining_ratio is not None and remaining_ratio > 1:
        raise CodingAgentRouterCliError(
            "remaining_ratio must be between zero and one"
        )
    if arguments.reset_at is not None and router._parse_time(arguments.reset_at) is None:
        raise CodingAgentRouterCliError(
            "reset_at must be a timezone-aware timestamp"
        )
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    record = state["routes"].setdefault(arguments.route, {})
    counters: dict[str, int] = {}
    for field in ("runs", "successes", "failures"):
        value = record.get(field, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CodingAgentRouterCliError(
                f"existing route counter {field} is invalid"
            )
        counters[field] = value
    record["runs"] = counters["runs"] + 1
    record["last_outcome"] = arguments.outcome
    record["last_observed_at"] = _iso_now()
    if arguments.outcome == "success":
        record["successes"] = counters["successes"] + 1
    else:
        record["failures"] = counters["failures"] + 1
    if duration is not None:
        record["last_duration_seconds"] = duration
    if rework is not None:
        observations = record.get("rework_observations", 0)
        previous_average = record.get("average_rework_minutes", 0.0)
        if (
            isinstance(observations, bool)
            or not isinstance(observations, int)
            or observations < 0
            or isinstance(previous_average, bool)
            or not isinstance(previous_average, (int, float))
            or not math.isfinite(float(previous_average))
            or float(previous_average) < 0
        ):
            raise CodingAgentRouterCliError("existing rework history is invalid")
        record["average_rework_minutes"] = (
            float(previous_average) * observations + rework
        ) / (observations + 1)
        record["rework_observations"] = observations + 1
    if reported_cost is not None:
        record["last_reported_cost_usd"] = reported_cost
    boundary = datetime.now(timezone.utc)
    for pool_id in route["quota_pools"]:
        pool = state["pools"].setdefault(pool_id, {})
        if arguments.outcome == "success":
            pool["status"] = "available"
            pool["last_success_at"] = _iso_now()
            for field in ("blocked_reason", "cooldown_until", "reset_at"):
                pool.pop(field, None)
        elif arguments.outcome == "rate_limit":
            pool["status"] = "cooldown"
            pool.pop("blocked_reason", None)
            pool.pop("reset_at", None)
            pool["cooldown_until"] = (boundary + timedelta(minutes=15)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
        elif arguments.outcome == "quota_exhausted":
            pool["status"] = "exhausted"
            pool.pop("blocked_reason", None)
            pool.pop("cooldown_until", None)
            pool["reset_at"] = arguments.reset_at or (
                boundary + timedelta(hours=5)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        elif arguments.outcome == "auth_error":
            pool["status"] = "blocked"
            pool.pop("cooldown_until", None)
            pool.pop("reset_at", None)
            pool["blocked_reason"] = "authentication error"
        elif arguments.outcome == "transient":
            pool["status"] = "cooldown"
            pool.pop("blocked_reason", None)
            pool.pop("reset_at", None)
            pool["cooldown_until"] = (boundary + timedelta(minutes=5)).replace(
                microsecond=0
            ).isoformat().replace("+00:00", "Z")
        if remaining_ratio is not None:
            pool["remaining_ratio"] = remaining_ratio
        pool["updated_at"] = _iso_now()
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)
    return {"recorded": True, "route": arguments.route, "route_state": record}


def _observe(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    with _exclusive_state_write_lock(router._state_path()):
        return _observe_locked(arguments, catalog, validation)


def _set_quota_locked(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    if arguments.pool not in catalog["quota_pools"]:
        raise CodingAgentRouterCliError("set-quota requires a known quota pool")
    if arguments.remaining_ratio is not None and not 0 <= arguments.remaining_ratio <= 1:
        raise CodingAgentRouterCliError("remaining_ratio must be between zero and one")
    for key in ("active_sessions", "used_tasks"):
        value = getattr(arguments, key)
        if value is not None and value < 0:
            raise CodingAgentRouterCliError(f"{key} must be nonnegative")
    for key in ("reset_at", "cooldown_until"):
        value = getattr(arguments, key)
        if value is not None and router._parse_time(value) is None:
            raise CodingAgentRouterCliError(f"{key} must be a timezone-aware timestamp")
    state = _load_mutable_state(str(validation["catalog_sha256"]))
    pool = state["pools"].setdefault(arguments.pool, {})
    if arguments.status in {"unknown", "available"}:
        for field in (
            "blocked_reason",
            "cooldown_until",
            "remaining_ratio",
            "reset_at",
        ):
            pool.pop(field, None)
    elif arguments.status == "constrained":
        for field in ("blocked_reason", "cooldown_until", "reset_at"):
            pool.pop(field, None)
    elif arguments.status == "cooldown":
        pool.pop("blocked_reason", None)
        pool.pop("reset_at", None)
    elif arguments.status == "exhausted":
        pool.pop("blocked_reason", None)
        pool.pop("cooldown_until", None)
    elif arguments.status == "blocked":
        pool.pop("cooldown_until", None)
        pool.pop("reset_at", None)
    pool["status"] = arguments.status
    for key in (
        "remaining_ratio",
        "reset_at",
        "cooldown_until",
        "active_sessions",
        "used_tasks",
    ):
        value = getattr(arguments, key)
        if value is not None:
            pool[key] = value
    if arguments.verified_now:
        pool["verified_at"] = _iso_now()
    pool["updated_at"] = _iso_now()
    state["updated_at"] = _iso_now()
    _atomic_write_private_json(router._state_path(), state)
    return {"updated": True, "pool": arguments.pool, "pool_state": pool}


def _set_quota(
    arguments: argparse.Namespace,
    catalog: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    with _exclusive_state_write_lock(router._state_path()):
        return _set_quota_locked(arguments, catalog, validation)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Direct-first coding-agent metadata and advisory router."
    )
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    probe = commands.add_parser("probe")
    probe.add_argument("--no-write", action="store_true")
    commands.add_parser("inventory")
    commands.add_parser("status")

    recommend = commands.add_parser("recommend")
    recommend.add_argument("--task-class", required=True)
    recommend.add_argument("--changed-files", type=int, default=1)
    recommend.add_argument("--duration-minutes", type=int, default=30)
    recommend.add_argument("--novelty", choices=["low", "medium", "high"], default="medium")
    recommend.add_argument("--risk-flag", action="append", default=[])
    recommend.add_argument("--latency-priority", action="store_true")
    recommend.add_argument("--need-review", action="store_true")

    observe = commands.add_parser("observe")
    observe.add_argument("--route", required=True)
    observe.add_argument(
        "--outcome",
        required=True,
        choices=[
            "success",
            "rate_limit",
            "quota_exhausted",
            "auth_error",
            "transient",
            "quality_failure",
        ],
    )
    observe.add_argument("--remaining-ratio", type=float)
    observe.add_argument("--reset-at")
    observe.add_argument("--duration-seconds", type=float)
    observe.add_argument("--rework-minutes", type=float)
    observe.add_argument("--reported-cost-usd", type=float)

    quota = commands.add_parser("set-quota")
    quota.add_argument("--pool", required=True)
    quota.add_argument(
        "--status",
        required=True,
        choices=["unknown", "available", "constrained", "cooldown", "exhausted", "blocked"],
    )
    quota.add_argument("--remaining-ratio", type=float)
    quota.add_argument("--reset-at")
    quota.add_argument("--cooldown-until")
    quota.add_argument("--active-sessions", type=int)
    quota.add_argument("--used-tasks", type=int)
    quota.add_argument("--verified-now", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        catalog, validation = router._load_catalog()
        if arguments.command == "validate":
            output: dict[str, Any] = validation
        elif arguments.command == "probe":
            output = _probe(catalog)
            if not arguments.no_write:
                _write_probe(output, validation)
        elif arguments.command == "inventory":
            output = router.grabowski_coding_agent_catalog(include_disabled=True)
        elif arguments.command == "status":
            output = _status(catalog, validation)
        elif arguments.command == "recommend":
            output = router.grabowski_coding_agent_route(
                task_class=arguments.task_class,
                changed_files=arguments.changed_files,
                duration_minutes=arguments.duration_minutes,
                novelty=arguments.novelty,
                risk_flags=arguments.risk_flag,
                latency_priority=arguments.latency_priority,
                need_review=arguments.need_review,
            )
        elif arguments.command == "observe":
            output = _observe(arguments, catalog, validation)
        elif arguments.command == "set-quota":
            output = _set_quota(arguments, catalog, validation)
        else:
            raise CodingAgentRouterCliError("unsupported command")
        print(json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "error": "coding_agent_router_cli_failed_closed",
                    "error_type": type(exc).__name__,
                    "automatic_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
