#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import errno
from datetime import datetime, timezone

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
from typing import Any
import uuid
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

import grabowski_mcp as base


HOME = Path.home().resolve()
EVIDENCE_ROOT = (HOME / "repos" / "merges").resolve()
STATE_DIR = (HOME / ".local" / "state" / "grabowski").resolve()
JOBS_DIR = STATE_DIR / "jobs"
JOB_PREFIX = "grabowski-job-"
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 120
TRUSTED_MAX_TIMEOUT = 86_400
DEFAULT_JOB_RUNTIME = 7_200
MAX_JOB_RUNTIME = 86_400
TRUSTED_MAX_JOB_RUNTIME = 2_592_000
DEFAULT_OUTPUT_BYTES = 250_000
MAX_OUTPUT_BYTES = 2_000_000
TRUSTED_MAX_OUTPUT_BYTES = 33_554_432
MAX_NOTIFY_ON_DONE_CHANNELS = 5
MAX_NOTIFY_ON_DONE_TEXT = 200
MAX_FINALIZATION_RECEIPT_BYTES = 64 * 1024
DYNAMIC_SECRET_GLOBAL_MIN_LENGTH = 8
COMMON_SHORT_SECRET_VALUES = frozenset(
    {"0", "1", "true", "false", "yes", "no", "on", "off", "null", "none"}
)
JOB_METADATA_TEMP_STALE_SECONDS = 3600
JOB_METADATA_DIRECTORY_SWEEP_LIMIT = 256
JOB_METADATA_ENTRY_SWEEP_LIMIT = 4096
JOB_METADATA_TEMP_SWEEP_LIMIT = 64
JOB_METADATA_TEMP_RE = re.compile(r"metadata\.json\.[0-9a-f]{32}\.tmp")
FINALIZATION_RECEIPT_NAME = "finalization.json"
RUNTIME_DEPLOY_FINALIZATION_KIND = "grabowski_runtime_deploy_finalization"
RESERVED_RUNTIME_DEPLOY_RUNNER = (HOME / "repos" / "grabowski" / "tools" / "run_scheduled_deploy.py").resolve()
JOB_EXPECTED_HEAD_RE = re.compile(r"[0-9a-f]{40,64}")
JOB_FINAL_STATUS_NON_CLAIMS = (
    "notification_delivery",
    "hidden_finalization_failure",
    "receipt_file_integrity",
)
NOTIFICATION_NON_CLAIMS = ("notification_sent", "notification_delivery", "job_success")
EXPECTED_RECEIPT_NON_CLAIMS = (
    "receipt_exists",
    "receipt_integrity",
    "job_success",
    "notification_delivery",
)
CONSUMER_VIEWS = frozenset({"minimal", "standard", "evidence"})
CONSUMER_VIEW_ALIASES = {"concise": "minimal", "full": "evidence"}
MAX_CONSUMER_FIELDS = 40
MAX_CONSUMER_CURSOR_BYTES = 2048
JOB_NOTIFICATION_RECEIPT_NAME = "notification.json"
JOB_NOTIFICATION_ACK_NAME = "notification-ack.json"
JOB_NOTIFICATION_NON_CLAIMS = (
    "external_push_delivery",
    "user_has_seen_notification",
    "job_success",
)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _normalize_consumer_view(value: str | None, *, default: str = "minimal") -> str:
    selected = default if value is None else value
    if not isinstance(selected, str):
        raise ValueError("view must be a string")
    selected = CONSUMER_VIEW_ALIASES.get(selected, selected)
    if selected not in CONSUMER_VIEWS:
        raise ValueError(f"view must be one of {sorted(CONSUMER_VIEWS)}")
    return selected


def _normalize_consumer_fields(fields: list[str] | None) -> list[str] | None:
    if fields is None:
        return None
    if not isinstance(fields, list) or len(fields) > MAX_CONSUMER_FIELDS:
        raise ValueError(f"fields must be a list with at most {MAX_CONSUMER_FIELDS} entries")
    normalized: list[str] = []
    for field in fields:
        if (
            not isinstance(field, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", field)
        ):
            raise ValueError("fields entries must be bounded lower-case identifiers")
        if field not in normalized:
            normalized.append(field)
    return normalized


def _project_consumer_fields(
    payload: dict[str, Any],
    *,
    fields: list[str] | None,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    selected = _normalize_consumer_fields(fields)
    if selected is None:
        return payload
    unknown = sorted(set(selected) - set(payload))
    if unknown:
        raise ValueError(f"Unknown response field(s): {', '.join(unknown)}")
    keep = set(selected) | {key for key in required if key in payload}
    projected = {key: value for key, value in payload.items() if key in keep}
    projected["projection"] = {
        "selected_fields": sorted(keep),
        "omitted_fields": sorted(set(payload) - keep),
        "required_fields_preserved": [key for key in required if key in payload],
    }
    return projected


def _encode_consumer_cursor(scope: str, position: dict[str, Any]) -> str:
    if not isinstance(scope, str) or not scope or len(scope) > 200:
        raise ValueError("cursor scope is invalid")
    body = {"schema_version": 1, "scope": scope, "position": position}
    body["checksum"] = hashlib.sha256(_canonical_json_bytes(body)).hexdigest()
    encoded = base64.urlsafe_b64encode(_canonical_json_bytes(body)).decode("ascii").rstrip("=")
    if len(encoded) > MAX_CONSUMER_CURSOR_BYTES:
        raise ValueError("cursor is too large")
    return encoded


def _decode_consumer_cursor(cursor: str | None, scope: str) -> dict[str, Any] | None:
    if cursor in (None, ""):
        return None
    if not isinstance(cursor, str) or len(cursor) > MAX_CONSUMER_CURSOR_BYTES:
        raise ValueError("cursor is invalid")
    try:
        padding = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + padding))
    except (ValueError, json.JSONDecodeError, binascii.Error) as exc:
        raise ValueError("cursor is invalid") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("cursor schema is invalid")
    checksum = value.pop("checksum", None)
    expected = hashlib.sha256(_canonical_json_bytes(value)).hexdigest()
    if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected):
        raise ValueError("cursor checksum is invalid")
    if value.get("scope") != scope or not isinstance(value.get("position"), dict):
        raise ValueError("cursor does not match this result set")
    return value["position"]

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
MUTATING = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

SENSITIVE_ENV_PARTS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "COOKIE",
    "CREDENTIAL",
    "AUTHORIZATION",
    "API_KEY",
    "APIKEY",
)
PRIVILEGE_ESCALATORS = {"sudo", "su", "pkexec", "doas"}
PROTECTED_BRANCHES = {"main", "master"}
PRIVILEGED_REFERENCE_TTL_SECONDS = 900
PRIVILEGED_REFERENCE_REPLAY_POLICY = "single-use-external-broker"
_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
OPERATOR_CAPABILITIES = (
    "terminal_execute",
    "durable_job",
    "git_cli",
    "github_cli",
    "user_service_control",
    "tmux_interaction",
    "process_inspect",
    "process_signal",
    "port_inspect",
    "privileged_reference",
    "power_execute",
    "resource_lease",
    "artifact_transfer",
    "browser_worker",
    "gui_worker",
)
PRIVILEGED_REFERENCE_ACTIONS = {
    "install_system_package",
    "edit_system_service",
    "bind_privileged_port",
    "change_file_owner",
    "mount_filesystem",
    "reset_failed_systemd_unit",
    "operator_power_argv",
}

REDACTIONS = (
    (_OPENAI_SECRET_PATTERN, "<REDACTED_OPENAI_KEY>"),
    (_ANTHROPIC_SECRET_PATTERN, "<REDACTED_ANTHROPIC_KEY>"),
    (
        re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{12,}=*", re.I),
        "Bearer <REDACTED>",
    ),
    (
        re.compile(
            r"-----BEGIN [^-]*PRIVATE KEY-----.*?"
            r"-----END [^-]*PRIVATE KEY-----",
            re.S,
        ),
        "<REDACTED_PRIVATE_KEY>",
    ),
    (
        re.compile(
            r"(?im)^([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY)"
            r"[A-Z0-9_]*\s*=\s*).+$"
        ),
        r"\1<REDACTED>",
    ),
)


def _find_server() -> FastMCP:
    servers = [
        value
        for value in vars(base).values()
        if isinstance(value, FastMCP)
    ]
    unique = []
    for server in servers:
        if all(server is not existing for existing in unique):
            unique.append(server)

    if len(unique) != 1:
        raise RuntimeError(
            f"Expected exactly one FastMCP instance, found {len(unique)}"
        )
    return unique[0]


mcp = _find_server()


def _redact_dynamic_secret(text: str, secret: str) -> str:
    if not secret:
        return text

    escaped = re.escape(secret)
    result = re.sub(rf"(?m)^{escaped}$", "<REDACTED>", text)
    result = re.sub(
        rf"(?i)(\b[A-Z0-9_-]*(?:TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|CREDENTIAL|AUTHORIZATION|API_KEY|APIKEY)[A-Z0-9_-]*\s*[:=]\s*){escaped}(?=$|[\s,;])",
        rf"\1<REDACTED>",
        result,
    )
    if (
        len(secret) >= DYNAMIC_SECRET_GLOBAL_MIN_LENGTH
        and secret.casefold() not in COMMON_SHORT_SECRET_VALUES
    ):
        result = result.replace(secret, "<REDACTED>")
    return result


def _redact(text: str, extra_secrets: list[str] | None = None) -> str:
    result = text
    for pattern, replacement in REDACTIONS:
        result = pattern.sub(replacement, result)
    for secret in sorted(set(extra_secrets or []), key=len, reverse=True):
        result = _redact_dynamic_secret(result, secret)
    return result


def _json_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _argv_hash(argv: list[str]) -> str:
    return _json_sha256(argv)


def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            redacted.append("<REDACTED>")
            hide_next = False
            continue

        key = item.split("=", 1)[0].lstrip("-").replace("-", "_").upper()
        if any(part in key for part in SENSITIVE_ENV_PARTS):
            if "=" in item:
                redacted.append(f"{item.split('=', 1)[0]}=<REDACTED>")
            else:
                redacted.append(item)
                hide_next = True
            continue
        redacted.append(_redact(item))
    return redacted


def _argv_secret_values(argv: list[str]) -> list[str]:
    values: list[str] = []
    hide_next = False
    for item in argv:
        if hide_next:
            values.append(item)
            hide_next = False
            continue

        key = item.split("=", 1)[0].lstrip("-").replace("-", "_").upper()
        if not any(part in key for part in SENSITIVE_ENV_PARTS):
            continue
        if "=" in item:
            values.append(item.split("=", 1)[1])
        else:
            hide_next = True
    return values


def _redacted_command(argv: list[str]) -> str:
    return shlex.join(_redact_argv(argv))


def _operator_capabilities() -> set[str]:
    policy = base._load_policy()
    forbidden = set(policy.get("forbidden_capabilities", []))
    profiles = policy.get("profiles")
    if isinstance(profiles, dict):
        profile = base._active_profile(policy)
        raw = profile.get("capabilities", [])
        capabilities = {item for item in raw if isinstance(item, str)}
    else:
        capabilities = set(OPERATOR_CAPABILITIES)
    return {
        capability
        for capability in capabilities
        if capability in OPERATOR_CAPABILITIES and capability not in forbidden
    }


def _trusted_owner_mode(policy: dict[str, Any] | None = None) -> bool:
    predicate = getattr(base, "_trusted_owner_enabled", None)
    if predicate is None:
        return False
    return bool(predicate(policy or base._load_policy()))


def _require_operator_capability(capability: str) -> None:
    if capability not in _operator_capabilities():
        raise PermissionError(f"Operator capability is not enabled: {capability}")


def _require_operator_mutation(capability: str) -> None:
    _require_operator_capability(capability)
    state = base._kill_switch_state()
    if state["engaged"]:
        raise PermissionError(
            "Grabowski operator kill switch is engaged; mutating tools are disabled."
        )
    base._require_valid_audit_chain()


def _limit(text: str, limit: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text, False
    clipped = encoded[:limit].decode("utf-8", errors="replace")
    return clipped + "\n<OUTPUT_TRUNCATED>", True


def _safe_environment() -> dict[str, str]:
    if _trusted_owner_mode():
        environment = dict(os.environ)
    else:
        environment = {}
        for key, value in os.environ.items():
            upper = key.upper()
            if any(part in upper for part in SENSITIVE_ENV_PARTS):
                continue
            environment[key] = value
    environment["GRABOWSKI_EVIDENCE_ROOT"] = str(EVIDENCE_ROOT)
    environment["GRABOWSKI_TRUSTED_OWNER"] = "1" if _trusted_owner_mode() else "0"
    return environment


def _resolve_cwd(cwd: str | None) -> Path:
    path = HOME if cwd is None else Path(cwd).expanduser()
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Working directory is not a directory: {resolved}")
    if (
        resolved == EVIDENCE_ROOT or EVIDENCE_ROOT in resolved.parents
    ) and not _trusted_owner_mode():
        raise PermissionError(
            f"Commands may not run inside immutable evidence: {resolved}"
        )
    return resolved


def _path_inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _path_like_argument(value: str) -> bool:
    if "://" in value:
        return False
    return value.startswith(("/", ".", "~")) or "/" in value


def _argument_path_candidates(value: str) -> list[str]:
    candidates = [value]
    if "=" in value:
        candidates.append(value.split("=", 1)[1])
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        tokens = []
    for token in tokens:
        candidates.append(token)
        if "=" in token:
            candidates.append(token.split("=", 1)[1])
    return candidates


def _expand_home_references(value: str) -> str:
    return re.sub(r"\$\{HOME\}|\$HOME\b", str(HOME), value)


def _argument_targets_evidence(value: str, cwd: Path) -> bool:
    if str(EVIDENCE_ROOT) in _expand_home_references(value):
        return True
    for candidate in _argument_path_candidates(value):
        candidate = _expand_home_references(candidate)
        if str(EVIDENCE_ROOT) in candidate:
            return True
        if not _path_like_argument(candidate):
            continue
        path = Path(candidate).expanduser()
        if not path.is_absolute():
            path = cwd / path
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            resolved = path.absolute()
        if _path_inside(resolved, EVIDENCE_ROOT):
            return True
    return False


def _validate_argv(argv: list[str], *, cwd: Path | None = None) -> list[str]:
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")

    policy = base._load_policy()
    trusted_owner = _trusted_owner_mode(policy)
    executable = Path(argv[0]).name
    if executable in PRIVILEGE_ESCALATORS and not trusted_owner:
        raise PermissionError(
            f"Privilege escalation is not available through Grabowski: "
            f"{executable}"
        )

    base._reject_forbidden_hosts_in_argv(argv, policy=policy)

    working_directory = HOME if cwd is None else cwd
    if not trusted_owner:
        for item in argv:
            if _argument_targets_evidence(item, working_directory):
                raise PermissionError(
                    "Direct command arguments may not target immutable evidence."
                )

    return argv


def _timeout(value: int) -> int:
    maximum = TRUSTED_MAX_TIMEOUT if _trusted_owner_mode() else MAX_TIMEOUT
    if value < 1 or value > maximum:
        raise ValueError(
            f"timeout_seconds must be between 1 and {maximum}"
        )
    return value


def _job_runtime(value: int) -> int:
    maximum = TRUSTED_MAX_JOB_RUNTIME if _trusted_owner_mode() else MAX_JOB_RUNTIME
    if value < 1 or value > maximum:
        raise ValueError(f"runtime_seconds must be between 1 and {maximum}")
    return value


def _output_limit(value: int) -> int:
    maximum = TRUSTED_MAX_OUTPUT_BYTES if _trusted_owner_mode() else MAX_OUTPUT_BYTES
    if value < 1 or value > maximum:
        raise ValueError(
            f"max_output_bytes must be between 1 and {maximum}"
        )
    return value


def _terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    grace_seconds: float = 3.0,
) -> tuple[bytes, bytes]:
    if process.poll() is not None:
        return process.communicate()
    os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.communicate()


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=_safe_environment() if environment is None else environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout_raw, stderr_raw = process.communicate(timeout=timeout_seconds)
        timed_out = False
        returncode: int | None = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        stdout_raw, stderr_raw = _terminate_process_group(process)
        returncode = process.returncode

    argv_secrets = _argv_secret_values(argv)
    stdout = _redact(
        stdout_raw.decode("utf-8", errors="replace"),
        argv_secrets,
    )
    stderr = _redact(
        stderr_raw.decode("utf-8", errors="replace"),
        argv_secrets,
    )
    stdout, stdout_truncated = _limit(stdout, max_output_bytes)
    stderr, stderr_truncated = _limit(stderr, max_output_bytes)

    return {
        "argv": _redact_argv(argv),
        "argv_sha256": _argv_hash(argv),
        "command": _redacted_command(argv),
        "cwd": str(cwd),
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _parse_show(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _validate_unit(unit: str, *, job_only: bool = False) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,200}", unit):
        raise ValueError("Invalid systemd unit name")
    if job_only and not unit.startswith(JOB_PREFIX):
        raise PermissionError(
            f"Only {JOB_PREFIX}* units are valid job targets."
        )
    return unit


def _systemd_safe_description(
    kind: str,
    unit: str,
    argv_sha256: str | None = None,
) -> str:
    """Return a bounded single-line Description= value for systemd-run."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,40}", kind):
        raise ValueError("Invalid systemd description kind")
    name = _validate_unit(unit)
    parts = ["Grabowski", kind, name]
    if argv_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", argv_sha256):
            raise ValueError("Invalid argv sha256")
        parts.append(f"argv={argv_sha256[:12]}")
    value = " ".join(parts)
    if any(item in value for item in ("\n", "\r", "\x00")):
        raise ValueError("Invalid systemd description")
    if len(value.encode("utf-8")) > 200:
        raise ValueError("Systemd description is too large")
    return value


def _job_timestamp() -> tuple[int, str]:
    now = datetime.now(timezone.utc)
    return (
        int(now.timestamp()),
        now.isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def _bounded_job_text(value: Any, *, label: str, max_chars: int = MAX_NOTIFY_ON_DONE_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = _redact(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{label} must not contain control characters")
    text = text.strip()
    if not text:
        raise ValueError(f"{label} must be non-empty")
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def _normalize_notify_on_done(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {
            "requested": False,
            "channels": [],
            "delivery_mode": "metadata_only",
            "delivery_enabled": False,
            "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
        }
    if not isinstance(value, dict):
        raise ValueError("notify_on_done must be an object when provided")
    allowed = {"requested", "channels", "note"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"Unknown notify_on_done field(s): {', '.join(unknown)}")
    requested = value.get("requested", False)
    if not isinstance(requested, bool):
        raise ValueError("notify_on_done.requested must be a boolean")
    raw_channels = value.get("channels", [])
    if raw_channels is None:
        raw_channels = []
    if not isinstance(raw_channels, list):
        raise ValueError("notify_on_done.channels must be a list")
    if len(raw_channels) > MAX_NOTIFY_ON_DONE_CHANNELS:
        raise ValueError("notify_on_done.channels has too many entries")
    channels = [
        _bounded_job_text(channel, label="notify_on_done channel", max_chars=40)
        for channel in raw_channels
    ]
    result: dict[str, Any] = {
        "requested": requested,
        "channels": channels,
        "delivery_mode": "metadata_only",
        "delivery_enabled": False,
        "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
    }
    if "note" in value:
        result["note"] = _bounded_job_text(value["note"], label="notify_on_done note")
    return result


def _job_identity(unit: str, *, owner: str | None = None) -> dict[str, Any]:
    return {
        "job_id": unit.removeprefix(JOB_PREFIX),
        "unit": unit,
        "owner": owner or f"uid:{os.getuid()}",
    }


def _job_receipt_paths(directory: Path) -> dict[str, str]:
    return {
        "metadata": str(directory / "metadata.json"),
        "stdout": str(directory / "stdout.log"),
        "stderr": str(directory / "stderr.log"),
        "finalization": str(directory / FINALIZATION_RECEIPT_NAME),
    }


def _job_expected_receipt(
    *,
    unit: str,
    metadata_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    finalization_path: Path | None = None,
) -> dict[str, Any]:
    receipt = {
        "kind": "grabowski_job_receipt",
        "unit": unit,
        "metadata_path": str(metadata_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "status_tool": "grabowski_job_status",
        "logs_tool": "grabowski_job_logs",
        "does_not_establish": list(EXPECTED_RECEIPT_NON_CLAIMS),
    }
    if finalization_path is not None:
        receipt["finalization_path"] = str(finalization_path)
    return receipt


def _runtime_deploy_expected_head(metadata: dict[str, Any]) -> str | None:
    argv = metadata.get("argv")
    argv_sha256 = metadata.get("argv_sha256")
    if (
        not isinstance(argv, list)
        or not all(isinstance(item, str) for item in argv)
        or not isinstance(argv_sha256, str)
        or _argv_hash(argv) != argv_sha256
    ):
        return None
    positions = [index for index, item in enumerate(argv) if item == "--expected-head"]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        return None
    expected_head = argv[positions[0] + 1]
    if not JOB_EXPECTED_HEAD_RE.fullmatch(expected_head):
        return None
    return expected_head


def _job_finalization_contract(
    *,
    unit: str,
    directory: Path,
    argv_sha256: str,
    expected_head: str,
) -> dict[str, Any]:
    if not JOB_EXPECTED_HEAD_RE.fullmatch(expected_head):
        raise ValueError("finalization expected_head must be a lowercase Git object ID")
    material = {
        "schema_version": 1,
        "kind": RUNTIME_DEPLOY_FINALIZATION_KIND,
        "unit": unit,
        "job_id": unit.removeprefix(JOB_PREFIX),
        "argv_sha256": argv_sha256,
        "expected_head": expected_head,
        "receipt_paths": _job_receipt_paths(directory),
    }
    return {**material, "contract_sha256": _json_sha256(material)}


def _read_finalization_receipt_file(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return {"ok": False, "state": "missing_receipt", "path": str(path)}
    except OSError as exc:
        reason = "receipt_symlink" if exc.errno == errno.ELOOP else "receipt_open_failed"
        return {
            "ok": False,
            "state": "invalid_receipt",
            "reason": reason,
            "path": str(path),
        }
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            return {
                "ok": False,
                "state": "invalid_receipt",
                "reason": "receipt_not_regular_file",
                "path": str(path),
            }
        size = status.st_size
        if size <= 0 or size > MAX_FINALIZATION_RECEIPT_BYTES:
            return {
                "ok": False,
                "state": "invalid_receipt",
                "reason": "receipt_size_invalid",
                "path": str(path),
                "bytes": size,
            }
        raw = bytearray()
        while len(raw) <= MAX_FINALIZATION_RECEIPT_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_FINALIZATION_RECEIPT_BYTES + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        final_status = os.fstat(descriptor)
        if (
            len(raw) != size
            or len(raw) > MAX_FINALIZATION_RECEIPT_BYTES
            or final_status.st_dev != status.st_dev
            or final_status.st_ino != status.st_ino
            or final_status.st_size != status.st_size
            or final_status.st_mtime_ns != status.st_mtime_ns
        ):
            return {
                "ok": False,
                "state": "invalid_receipt",
                "reason": "receipt_changed_while_reading",
                "path": str(path),
                "bytes": len(raw),
            }
        return {
            "ok": True,
            "path": str(path),
            "bytes": size,
            "raw": bytes(raw),
        }
    finally:
        os.close(descriptor)


def _finalization_receipt_result(
    unit: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    contract = metadata.get("finalization_contract")
    if contract is None:
        return {
            "configured": False,
            "valid": False,
            "state": "not_configured",
            "does_not_establish": ["job_success"],
        }
    if not isinstance(contract, dict):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "contract_not_object",
            "does_not_establish": ["job_success"],
        }

    directory = _job_directory(unit)
    expected_paths = _job_receipt_paths(directory)
    expected_material = {
        "schema_version": 1,
        "kind": RUNTIME_DEPLOY_FINALIZATION_KIND,
        "unit": unit,
        "job_id": unit.removeprefix(JOB_PREFIX),
        "argv_sha256": metadata.get("argv_sha256"),
        "expected_head": contract.get("expected_head"),
        "receipt_paths": expected_paths,
    }
    allowed_contract_keys = set(expected_material) | {"contract_sha256"}
    if set(contract) != allowed_contract_keys:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "contract_shape_mismatch",
            "does_not_establish": ["job_success"],
        }
    if not isinstance(expected_material["argv_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_material["argv_sha256"]
    ):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "metadata_argv_sha256_invalid",
            "does_not_establish": ["job_success"],
        }
    if not isinstance(expected_material["expected_head"], str) or not JOB_EXPECTED_HEAD_RE.fullmatch(
        expected_material["expected_head"]
    ):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "expected_head_invalid",
            "does_not_establish": ["job_success"],
        }
    argv_expected_head = _runtime_deploy_expected_head(metadata)
    if argv_expected_head is None:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "metadata_argv_binding_invalid",
            "does_not_establish": ["job_success"],
        }
    if expected_material["expected_head"] != argv_expected_head:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "contract_binding_mismatch:expected_head_argv",
            "does_not_establish": ["job_success"],
        }
    for key, expected in expected_material.items():
        if contract.get(key) != expected:
            return {
                "configured": True,
                "valid": False,
                "state": "invalid_contract",
                "reason": f"contract_binding_mismatch:{key}",
                "does_not_establish": ["job_success"],
            }
    if contract.get("contract_sha256") != _json_sha256(expected_material):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_contract",
            "reason": "contract_sha256_mismatch",
            "does_not_establish": ["job_success"],
        }

    path = directory / FINALIZATION_RECEIPT_NAME
    file_result = _read_finalization_receipt_file(path)
    if file_result.get("ok") is not True:
        return {
            "configured": True,
            "valid": False,
            **file_result,
            "does_not_establish": ["job_success"],
        }
    raw = file_result["raw"]
    size = file_result["bytes"]
    receipt_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "receipt_json_invalid",
            "path": str(path),
            "bytes": size,
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }
    if not isinstance(payload, dict):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "receipt_not_object",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }

    allowed_payload_keys = {
        "schema_version",
        "kind",
        "unit",
        "job_id",
        "argv_sha256",
        "expected_head",
        "receipt_paths",
        "final_status",
        "completion_status",
        "repo_head",
        "release_id",
        "failure_type",
        "timestamp_unix",
        "payload_sha256",
    }
    if set(payload) != allowed_payload_keys:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "receipt_shape_mismatch",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }
    payload_material = {key: value for key, value in payload.items() if key != "payload_sha256"}
    if payload.get("payload_sha256") != _json_sha256(payload_material):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "payload_sha256_mismatch",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }
    bindings = {
        "schema_version": 1,
        "kind": RUNTIME_DEPLOY_FINALIZATION_KIND,
        "unit": unit,
        "job_id": unit.removeprefix(JOB_PREFIX),
        "argv_sha256": metadata.get("argv_sha256"),
        "expected_head": contract["expected_head"],
        "receipt_paths": expected_paths,
    }
    for key, expected in bindings.items():
        if payload.get(key) != expected:
            return {
                "configured": True,
                "valid": False,
                "state": "invalid_receipt",
                "reason": f"receipt_binding_mismatch:{key}",
                "path": str(path),
                "receipt_sha256": receipt_sha256,
                "does_not_establish": ["job_success"],
            }
    timestamp = payload.get("timestamp_unix")
    created_at = metadata.get("created_at_unix")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "timestamp_invalid",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }
    if isinstance(created_at, int) and not isinstance(created_at, bool) and timestamp < created_at:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "timestamp_precedes_job",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }

    final_status = payload.get("final_status")
    if final_status == "completed":
        release_id = payload.get("release_id")
        if (
            payload.get("completion_status") != "complete"
            or payload.get("repo_head") != contract["expected_head"]
            or not isinstance(release_id, str)
            or not release_id
            or len(release_id.encode("utf-8")) > 512
            or payload.get("failure_type") is not None
        ):
            return {
                "configured": True,
                "valid": False,
                "state": "invalid_receipt",
                "reason": "completed_receipt_semantics_invalid",
                "path": str(path),
                "receipt_sha256": receipt_sha256,
                "does_not_establish": ["job_success"],
            }
    elif final_status == "failed":
        failure_type = payload.get("failure_type")
        if (
            payload.get("completion_status") != "failed"
            or payload.get("repo_head") is not None
            or payload.get("release_id") is not None
            or not isinstance(failure_type, str)
            or not failure_type
            or len(failure_type.encode("utf-8")) > 200
        ):
            return {
                "configured": True,
                "valid": False,
                "state": "invalid_receipt",
                "reason": "failed_receipt_semantics_invalid",
                "path": str(path),
                "receipt_sha256": receipt_sha256,
                "does_not_establish": ["job_success"],
            }
    else:
        return {
            "configured": True,
            "valid": False,
            "state": "invalid_receipt",
            "reason": "final_status_invalid",
            "path": str(path),
            "receipt_sha256": receipt_sha256,
            "does_not_establish": ["job_success"],
        }

    return {
        "configured": True,
        "valid": True,
        "state": "valid",
        "path": str(path),
        "bytes": size,
        "receipt_sha256": receipt_sha256,
        "payload_sha256": payload["payload_sha256"],
        "final_status": final_status,
        "expected_head": contract["expected_head"],
        "timestamp_unix": timestamp,
        "does_not_establish": ["notification_delivery", "root_cause"],
    }


def _systemd_job_query_valid(result: dict[str, Any], properties: dict[str, str]) -> bool:
    load_state = properties.get("LoadState")
    active_state = properties.get("ActiveState")
    return (
        result.get("returncode") == 0
        and load_state not in {None, ""}
        and active_state not in {None, ""}
    )


def _systemd_job_query_visible(result: dict[str, Any], properties: dict[str, str]) -> bool:
    return (
        _systemd_job_query_valid(result, properties)
        and properties.get("LoadState") != "not-found"
    )


def _job_final_status(systemd_visible: bool, properties: dict[str, str]) -> str:
    if not systemd_visible:
        return "missing_finalization_evidence"
    active_state = properties.get("ActiveState", "")
    result = properties.get("Result", "")
    exec_status = properties.get("ExecMainStatus", "")
    if active_state in {"active", "activating", "reloading", "deactivating"}:
        return "running"
    if active_state == "failed":
        return "failed"
    if active_state == "inactive":
        if result == "success" and exec_status in {"", "0"}:
            return "succeeded"
        if result and result != "success":
            return "failed"
        if exec_status not in {"", "0"}:
            return "failed"
        return "terminated_unclear"
    return "unknown"


def _job_terminalization_evidence(
    systemd_visible: bool,
    properties: dict[str, str],
    *,
    query_valid: bool | None = None,
) -> dict[str, Any]:
    if query_valid is None:
        query_valid = systemd_visible
    final_status = _job_final_status(systemd_visible, properties)
    return {
        "source": "systemd-show",
        "query_valid": query_valid,
        "systemd_visible": systemd_visible,
        "final_status": final_status,
        "load_state": properties.get("LoadState", ""),
        "active_state": properties.get("ActiveState", ""),
        "sub_state": properties.get("SubState", ""),
        "result": properties.get("Result", ""),
        "exec_main_code": properties.get("ExecMainCode", ""),
        "exec_main_status": properties.get("ExecMainStatus", ""),
        "does_not_establish": list(JOB_FINAL_STATUS_NON_CLAIMS),
    }


def _safe_notify_metadata_error(message: str) -> dict[str, Any]:
    fallback = _normalize_notify_on_done(None)
    text = _redact(message)
    text = "".join(
        char if ord(char) >= 32 and ord(char) != 127 else "�"
        for char in text
    ).strip()
    fallback["metadata_invalid"] = True
    fallback["metadata_error"] = text[:MAX_NOTIFY_ON_DONE_TEXT] or "invalid notify_on_done metadata"
    return fallback


def _safe_normalize_stored_notify_on_done(value: Any) -> dict[str, Any]:
    if value is None:
        return _normalize_notify_on_done(None)
    if not isinstance(value, dict):
        return _safe_notify_metadata_error("notify_on_done must be an object when provided")
    allowed_stored = {
        "requested",
        "channels",
        "note",
        "delivery_mode",
        "delivery_enabled",
        "does_not_establish",
    }
    unknown = sorted(set(value) - allowed_stored)
    if unknown:
        return _safe_notify_metadata_error(f"Unknown notify_on_done field(s): {', '.join(unknown)}")
    if value.get("delivery_enabled") is not None and value.get("delivery_enabled") is not False:
        return _safe_notify_metadata_error("notify_on_done.delivery_enabled must be false")
    if value.get("delivery_mode") is not None and value.get("delivery_mode") != "metadata_only":
        return _safe_notify_metadata_error("notify_on_done.delivery_mode must be metadata_only")
    if "does_not_establish" in value:
        raw_non_claims = value["does_not_establish"]
        if (
            not isinstance(raw_non_claims, list)
            or not all(isinstance(item, str) for item in raw_non_claims)
            or not set(NOTIFICATION_NON_CLAIMS).issubset(set(raw_non_claims))
        ):
            return _safe_notify_metadata_error("notify_on_done.does_not_establish is invalid")
    try:
        source = {key: value[key] for key in ("requested", "channels", "note") if key in value}
        return _normalize_notify_on_done(source)
    except ValueError as exc:
        return _safe_notify_metadata_error(str(exc))


def _job_notification_evidence(notify_on_done: dict[str, Any], terminalization: dict[str, Any]) -> dict[str, Any]:
    evidence = {
        "requested": bool(notify_on_done.get("requested")),
        "delivery_enabled": False,
        "delivery_state": "not_sent",
        "reason": "notify_on_done is metadata-only in this slice",
        "final_status_preserved": terminalization.get("final_status"),
        "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
    }
    if notify_on_done.get("metadata_invalid") is True:
        evidence["metadata_invalid"] = True
        evidence["metadata_error"] = notify_on_done.get("metadata_error", "invalid notify_on_done metadata")
    return evidence


def _read_job_notification_json(directory: Path, name: str) -> dict[str, Any] | None:
    if name not in {JOB_NOTIFICATION_RECEIPT_NAME, JOB_NOTIFICATION_ACK_NAME}:
        raise ValueError("invalid notification receipt name")
    path = directory / name
    try:
        snapshot = base._read_bound_regular_bytes(
            path,
            MAX_FINALIZATION_RECEIPT_BYTES,
        )
    except FileNotFoundError:
        return None
    if int(snapshot["mode"]) & 0o077:
        raise ValueError("job notification receipt must be private")
    try:
        value = json.loads(snapshot["data"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("job notification receipt is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("job notification receipt must be an object")
    return value


def _validated_job_notification(directory: Path, unit: str) -> dict[str, Any] | None:
    receipt = _read_job_notification_json(directory, JOB_NOTIFICATION_RECEIPT_NAME)
    if receipt is None:
        return None
    if receipt.get("kind") != "grabowski_job_notification" or receipt.get("unit") != unit:
        raise ValueError("job notification receipt identity mismatch")
    stored_hash = receipt.get("receipt_sha256")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    expected_hash = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, expected_hash):
        raise ValueError("job notification receipt hash mismatch")
    return receipt


def _validated_job_notification_ack(
    directory: Path,
    unit: str,
    receipt: dict[str, Any],
) -> dict[str, Any] | None:
    acknowledgement = _read_job_notification_json(directory, JOB_NOTIFICATION_ACK_NAME)
    if acknowledgement is None:
        return None
    if (
        acknowledgement.get("kind") != "grabowski_job_notification_ack"
        or acknowledgement.get("unit") != unit
        or acknowledgement.get("job_id") != receipt.get("job_id")
        or acknowledgement.get("notification_id") != receipt.get("notification_id")
        or acknowledgement.get("receipt_sha256") != receipt.get("receipt_sha256")
    ):
        raise ValueError("job notification acknowledgement binding mismatch")
    non_claims = acknowledgement.get("does_not_establish")
    if (
        not isinstance(non_claims, list)
        or not {"external_push_delivery", "job_success"}.issubset(set(non_claims))
    ):
        raise ValueError("job notification acknowledgement non-claims are invalid")
    stored_hash = acknowledgement.get("ack_sha256")
    unsigned = {
        key: value
        for key, value in acknowledgement.items()
        if key != "ack_sha256"
    }
    expected_hash = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    if not isinstance(stored_hash, str) or not hmac.compare_digest(stored_hash, expected_hash):
        raise ValueError("job notification acknowledgement hash mismatch")
    return acknowledgement


def _publish_private_create_only_json(
    directory: Path,
    target: Path,
    payload: dict[str, Any],
) -> bool:
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_FINALIZATION_RECEIPT_BYTES:
        raise ValueError("job notification acknowledgement is too large")
    temporary = directory / f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    published = False
    temporary_identity: tuple[int, int] | None = None
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_metadata = temporary.lstat()
        temporary_identity = (temporary_metadata.st_dev, temporary_metadata.st_ino)
        if (
            not stat.S_ISREG(temporary_metadata.st_mode)
            or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
            or temporary_metadata.st_nlink != 1
        ):
            raise RuntimeError("temporary notification acknowledgement is unsafe")
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            return False
        published = True
        try:
            temporary.unlink()
        except OSError:
            try:
                current = target.lstat()
                if (current.st_dev, current.st_ino) == temporary_identity:
                    target.unlink()
                    published = False
            finally:
                raise
        target_metadata = target.lstat()
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or stat.S_IMODE(target_metadata.st_mode) != 0o600
            or target_metadata.st_nlink != 1
            or (target_metadata.st_dev, target_metadata.st_ino) != temporary_identity
        ):
            try:
                current = target.lstat()
                if (current.st_dev, current.st_ino) == temporary_identity:
                    target.unlink()
                    published = False
            except FileNotFoundError:
                published = False
            raise RuntimeError("published notification acknowledgement failed integrity validation")
        _fsync_directory(directory)
        return True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if published and temporary_identity is not None:
            try:
                current = target.lstat()
            except FileNotFoundError as exc:
                raise RuntimeError("published notification acknowledgement disappeared") from exc
            if current.st_nlink != 1:
                if (current.st_dev, current.st_ino) == temporary_identity:
                    target.unlink()
                raise RuntimeError(
                    "published notification acknowledgement lost single-link integrity"
                )


def _job_notification_evidence_for_unit(
    unit: str,
    notify_on_done: dict[str, Any],
    terminalization: dict[str, Any],
) -> dict[str, Any]:
    base_evidence = _job_notification_evidence(notify_on_done, terminalization)
    if notify_on_done.get("requested") is not True:
        return base_evidence
    directory = _job_directory(unit)
    try:
        receipt = _validated_job_notification(directory, unit)
    except (OSError, ValueError) as exc:
        return {
            **base_evidence,
            "delivery_mode": "operator_outbox",
            "delivery_state": "invalid_receipt",
            "reason": _redact(str(exc))[:MAX_NOTIFY_ON_DONE_TEXT],
            "does_not_establish": list(JOB_NOTIFICATION_NON_CLAIMS),
        }
    if receipt is None:
        running = terminalization.get("final_status") == "running"
        return {
            **base_evidence,
            "delivery_mode": "operator_outbox",
            "delivery_state": "pending_finalization" if running else "missing_receipt",
            "reason": (
                "job is still running"
                if running
                else "terminal job has no notification receipt"
            ),
            "does_not_establish": list(JOB_NOTIFICATION_NON_CLAIMS),
        }
    try:
        acknowledgement = _validated_job_notification_ack(directory, unit, receipt)
    except (OSError, ValueError) as exc:
        return {
            **base_evidence,
            "delivery_mode": "operator_outbox",
            "delivery_state": "invalid_acknowledgement",
            "reason": _redact(str(exc))[:MAX_NOTIFY_ON_DONE_TEXT],
            "notification": receipt,
            "does_not_establish": list(JOB_NOTIFICATION_NON_CLAIMS),
        }
    state = "acknowledged" if acknowledgement is not None else "queued"
    return {
        "requested": True,
        "delivery_enabled": True,
        "delivery_mode": "operator_outbox",
        "delivery_state": state,
        "final_status_preserved": terminalization.get("final_status"),
        "notification": receipt,
        "ack_sha256": (
            acknowledgement.get("ack_sha256")
            if acknowledgement is not None
            else None
        ),
        "does_not_establish": list(JOB_NOTIFICATION_NON_CLAIMS),
    }

def _job_paths_for_unit(unit: str) -> dict[str, Path]:
    directory = _job_directory(unit)
    return {
        "directory": directory,
        "metadata_path": directory / "metadata.json",
        "stdout_path": directory / "stdout.log",
        "stderr_path": directory / "stderr.log",
    }


def _project_job_metadata(unit: str, metadata: dict[str, Any]) -> dict[str, Any]:
    paths = _job_paths_for_unit(unit)
    stored_job_id = metadata.get("job_id")
    job_id = unit.removeprefix(JOB_PREFIX)
    stored_job_id_mismatch = isinstance(stored_job_id, str) and stored_job_id != job_id
    job_id_projected = not isinstance(stored_job_id, str) or stored_job_id_mismatch
    stored_unit_mismatch = metadata.get("unit") != unit
    identity = _job_identity(
        unit,
        owner=metadata.get("owner") if isinstance(metadata.get("owner"), str) else None,
    )
    scope_projected = not isinstance(metadata.get("scope"), dict)
    scope = metadata.get("scope") if isinstance(metadata.get("scope"), dict) else {
        "cwd": metadata.get("cwd"),
        "argv_sha256": metadata.get("argv_sha256"),
        "runtime_seconds": metadata.get("runtime_seconds"),
    }
    expected_receipt_projected = not isinstance(metadata.get("expected_receipt"), dict)
    expected_receipt = metadata.get("expected_receipt")
    if expected_receipt_projected:
        finalization_path = None
        if isinstance(metadata.get("finalization_contract"), dict):
            finalization_path = paths["directory"] / FINALIZATION_RECEIPT_NAME
        expected_receipt = _job_expected_receipt(
            unit=unit,
            metadata_path=paths["metadata_path"],
            stdout_path=paths["stdout_path"],
            stderr_path=paths["stderr_path"],
            finalization_path=finalization_path,
        )
    notify_on_done = _safe_normalize_stored_notify_on_done(metadata.get("notify_on_done"))
    started_at_projected = "started_at" not in metadata
    projected = {
        **metadata,
        **identity,
        "scope": scope,
        "started_at": metadata.get("started_at"),
        "expected_receipt": expected_receipt,
        "notify_on_done": notify_on_done,
    }
    if (
        scope_projected
        or expected_receipt_projected
        or started_at_projected
        or job_id_projected
        or stored_unit_mismatch
    ):
        projected["metadata_projection"] = {
            "legacy_fields_projected": True,
            "scope_projected": scope_projected,
            "expected_receipt_projected": expected_receipt_projected,
            "started_at_projected": started_at_projected,
            "job_id_projected": job_id_projected,
            "stored_job_id_mismatch": stored_job_id_mismatch,
            "stored_unit_mismatch": stored_unit_mismatch,
            "does_not_establish": ["original_started_at", "receipt_integrity", "job_success"],
        }
    return projected


def _metadata_launch_failure_evidence(metadata: dict[str, Any]) -> dict[str, Any] | None:
    evidence = metadata.get("terminalization_evidence")
    if not isinstance(evidence, dict):
        return None
    if metadata.get("final_status") != "launch_failed":
        return None
    if evidence.get("final_status") != "launch_failed":
        return None
    return {
        **evidence,
        "query_valid": False,
        "systemd_visible": False,
        "final_status": "launch_failed",
    }


def _job_status_record(
    unit: str,
    metadata: dict[str, Any],
    *,
    systemd_visible: bool,
    query_valid: bool,
    properties: dict[str, str],
) -> dict[str, Any]:
    terminalization = _job_terminalization_evidence(
        systemd_visible,
        properties,
        query_valid=query_valid,
    )
    finalization_receipt = _finalization_receipt_result(unit, metadata)
    if not systemd_visible:
        metadata_terminalization = _metadata_launch_failure_evidence(metadata)
        if metadata_terminalization is not None:
            terminalization = metadata_terminalization
        elif finalization_receipt.get("valid") is True:
            terminalization = {
                "source": "persisted-runner-receipt",
                "query_valid": query_valid,
                "systemd_visible": False,
                "fallback_used": True,
                "final_status": finalization_receipt["final_status"],
                "receipt_valid": True,
                "receipt_sha256": finalization_receipt["receipt_sha256"],
                "payload_sha256": finalization_receipt["payload_sha256"],
                "expected_head": finalization_receipt["expected_head"],
                "timestamp_unix": finalization_receipt["timestamp_unix"],
                "does_not_establish": ["notification_delivery", "root_cause", "live_process_status"],
            }
        else:
            terminalization = {
                **terminalization,
                "fallback_used": False,
                "receipt_state": finalization_receipt.get("state"),
                "receipt_reason": finalization_receipt.get("reason"),
            }
    projected = _project_job_metadata(unit, metadata)
    notify_on_done = projected["notify_on_done"]
    return {
        **projected,
        "final_status": terminalization["final_status"],
        "terminalization_evidence": terminalization,
        "finalization_receipt": finalization_receipt,
        "notification_evidence": _job_notification_evidence_for_unit(
            unit, notify_on_done, terminalization
        ),
    }


def _jobs_root() -> Path:
    if JOBS_DIR.is_symlink():
        raise PermissionError(f"Jobs directory may not be a symlink: {JOBS_DIR}")
    JOBS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = JOBS_DIR.resolve(strict=True)
    if root.parent != STATE_DIR:
        raise PermissionError(f"Jobs directory escaped state root: {root}")
    return root


def _job_directory(unit: str, *, create: bool = False) -> Path:
    name = _validate_unit(unit, job_only=True)
    root = _jobs_root()
    path = root / name
    if path.is_symlink():
        raise PermissionError(f"Job directory may not be a symlink: {path}")
    if create:
        path.mkdir(mode=0o700)
    elif not path.is_dir():
        raise ValueError(f"Job metadata does not exist: {name}")
    resolved = path.resolve(strict=True)
    if resolved.parent != root:
        raise PermissionError(f"Job directory escaped jobs root: {resolved}")
    return resolved


def _write_job_metadata(directory: Path, payload: dict[str, Any]) -> Path:
    path = directory / "metadata.json"
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(directory)
    return path


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_stale_job_metadata_temps(
    root: Path,
    *,
    now_unix: int | None = None,
) -> dict[str, int]:
    current = int(time.time()) if now_unix is None else now_unix
    inspected = 0
    entries_scanned = 0
    removed = 0
    errors = 0
    if root.is_symlink() or not root.is_dir():
        return {"inspected": 0, "removed": 0, "errors": 1}

    try:
        job_entries = os.scandir(root)
    except OSError:
        return {"inspected": 0, "removed": 0, "errors": 1}

    with job_entries:
        for directory_index, job_entry in enumerate(job_entries):
            if (
                directory_index >= JOB_METADATA_DIRECTORY_SWEEP_LIMIT
                or entries_scanned >= JOB_METADATA_ENTRY_SWEEP_LIMIT
                or inspected >= JOB_METADATA_TEMP_SWEEP_LIMIT
            ):
                break
            try:
                if not job_entry.is_dir(follow_symlinks=False):
                    continue
                directory_status = job_entry.stat(follow_symlinks=False)
            except OSError:
                errors += 1
                continue
            if (
                directory_status.st_uid != os.getuid()
                or directory_status.st_mode & 0o022
            ):
                continue
            job_directory = Path(job_entry.path)
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                directory_flags |= os.O_NOFOLLOW
            try:
                directory_fd = os.open(job_directory, directory_flags)
            except OSError:
                errors += 1
                continue
            try:
                candidates = os.scandir(directory_fd)
            except OSError:
                os.close(directory_fd)
                errors += 1
                continue
            try:
                with candidates:
                    for candidate in candidates:
                        if (
                            inspected >= JOB_METADATA_TEMP_SWEEP_LIMIT
                            or entries_scanned >= JOB_METADATA_ENTRY_SWEEP_LIMIT
                        ):
                            break
                        entries_scanned += 1
                        if not JOB_METADATA_TEMP_RE.fullmatch(candidate.name):
                            continue
                        inspected += 1
                        try:
                            status = candidate.stat(follow_symlinks=False)
                            if (
                                not candidate.is_file(follow_symlinks=False)
                                or status.st_uid != os.getuid()
                                or status.st_mode & 0o022
                                or current - int(status.st_mtime)
                                < JOB_METADATA_TEMP_STALE_SECONDS
                            ):
                                continue
                            os.unlink(candidate.name, dir_fd=directory_fd)
                            removed += 1
                        except OSError:
                            errors += 1
            finally:
                os.close(directory_fd)
    return {"inspected": inspected, "removed": removed, "errors": errors}


def _replace_job_metadata(directory: Path, payload: dict[str, Any]) -> Path:
    path = directory / "metadata.json"
    temp_path = directory / f"metadata.json.{uuid.uuid4().hex}.tmp"
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        temp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temp_path, path)
        _fsync_directory(directory)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return path


def _job_launcher_evidence(result: dict[str, Any]) -> dict[str, Any]:
    stdout = result.get("stdout", "") if isinstance(result.get("stdout", ""), str) else ""
    stderr = result.get("stderr", "") if isinstance(result.get("stderr", ""), str) else ""
    return {
        "source": "systemd-run",
        "returncode": result.get("returncode"),
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
        "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
        "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
        "does_not_establish": ["job_success", "notification_delivery"],
    }


def _read_job_metadata(unit: str) -> dict[str, Any]:
    directory = _job_directory(unit)
    path = directory / "metadata.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Job metadata is missing: {unit}")
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"Job metadata is too large: {unit}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("unit") != unit:
        raise ValueError(f"Job metadata is invalid: {unit}")
    return payload


def _read_job_log(path: Path, max_lines: int) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        return {"text": "", "truncated": False, "bytes": 0}
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > MAX_OUTPUT_BYTES:
            handle.seek(-MAX_OUTPUT_BYTES, os.SEEK_END)
        data = handle.read(MAX_OUTPUT_BYTES)
    decoded = _redact(data.decode("utf-8", errors="replace"))
    lines = decoded.splitlines()
    line_truncated = len(lines) > max_lines
    text = "\n".join(lines[-max_lines:])
    return {
        "text": text,
        "truncated": size > MAX_OUTPUT_BYTES or line_truncated,
        "bytes": size,
    }


GIT_ENVIRONMENT_EXACT_DENY = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_EXEC_PATH",
        "GIT_CONFIG",
    }
)


def _git_environment() -> dict[str, str]:
    environment = _safe_environment()
    for key in tuple(environment):
        if key in GIT_ENVIRONMENT_EXACT_DENY or key.startswith("GIT_CONFIG_"):
            environment.pop(key, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GCM_INTERACTIVE"] = "never"
    environment["GIT_PAGER"] = "cat"
    environment["PAGER"] = "cat"
    return environment


def _git_push_environment() -> dict[str, str]:
    environment = _git_environment()
    for key in (
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_PROXY_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_ALLOW_PROTOCOL",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "ssh",
            "GIT_SSH_COMMAND": "/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no -oClearAllForwardings=yes",
            "GIT_SSH_VARIANT": "ssh",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
        }
    )
    return environment


GIT_SAFE_GLOBAL_FLAGS = frozenset(
    {
        "-p",
        "--paginate",
        "-P",
        "--no-pager",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--no-lazy-fetch",
    }
)
GIT_REPOSITORY_REBIND_OPTIONS = frozenset(
    {"-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--bare"}
)
GIT_CONFIG_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+")
GIT_REMOTE_WRITE_BYPASS_SUBCOMMANDS = frozenset({"send-pack", "http-push"})
GIT_SAFE_PUSH_LONG_OPTIONS = frozenset(
    {
        "--dry-run",
        "--porcelain",
        "--quiet",
        "--verbose",
        "--progress",
        "--atomic",
        "--thin",
        "--no-thin",
        "--ipv4",
        "--ipv6",
        "--set-upstream",
    }
)
GIT_SAFE_PUSH_SHORT_OPTIONS = frozenset({"n", "q", "u", "v", "4", "6"})
GIT_REMOTE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _git_config_assignment(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError("Git -c configuration must use name=value")
    key, configured = value.split("=", 1)
    if any(character in configured for character in ("\x00", "\n", "\r")):
        raise ValueError("Git -c configuration value contains control characters")
    if not GIT_CONFIG_KEY_RE.fullmatch(key):
        raise ValueError("Git -c configuration key is invalid")
    return key.casefold(), configured


def _split_git_invocation(arguments: list[str]) -> tuple[str, list[str], list[tuple[str, str]]]:
    configurations: list[tuple[str, str]] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item == "-c":
            if index + 1 >= len(arguments):
                raise ValueError("Git -c requires name=value")
            configurations.append(_git_config_assignment(arguments[index + 1]))
            index += 2
            continue
        if item == "--config-env" or item.startswith("--config-env="):
            raise PermissionError(
                "Git --config-env is blocked because indirect configuration cannot be audited."
            )
        if item in GIT_REPOSITORY_REBIND_OPTIONS:
            if item != "--bare" and index + 1 >= len(arguments):
                raise ValueError(f"Git {item} requires a value")
            raise PermissionError(
                f"Git repository rebinding option is blocked in grabowski_git: {item}"
            )
        if any(
            item.startswith(prefix)
            for prefix in (
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
            )
        ):
            raise PermissionError(
                "Git repository rebinding options are blocked in grabowski_git."
            )
        if item in GIT_SAFE_GLOBAL_FLAGS:
            index += 1
            continue
        if item.startswith("-"):
            raise ValueError(f"Unsupported Git global option before subcommand: {item}")
        return item, arguments[index + 1 :], configurations
    raise ValueError("Git subcommand is missing")


def _git_config_entries(repo: Path, pattern: str) -> list[tuple[str, str]]:
    completed = subprocess.run(
        ["git", "-C", str(repo), "config", "--get-regexp", pattern],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=_git_environment(),
    )
    if completed.returncode == 1 and not completed.stdout.strip():
        return []
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "Git configuration query failed")
    entries: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if not separator or not key:
            raise ValueError("Git configuration query returned malformed output")
        entries.append((key.casefold(), value))
    return entries


def _git_config_values(repo: Path, key: str) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(repo), "config", "--get-all", key],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=_git_environment(),
    )
    if completed.returncode == 1 and not completed.stdout.strip():
        return []
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "Git configuration query failed")
    return completed.stdout.splitlines()


def _remote_target_identity(url: str) -> tuple[str, str, str, bool] | None:
    if not url or any(character.isspace() or ord(character) < 32 for character in url):
        return None
    is_ssh = False
    ssh_user = ""
    if "://" in url:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            return None
        if not host or parsed.password is not None or parsed.query or parsed.fragment:
            return None
        scheme = parsed.scheme.casefold()
        is_ssh = scheme in {"ssh", "git+ssh", "ssh+git"}
        if is_ssh:
            ssh_user = parsed.username or ""
        default_port = {
            "http": 80,
            "https": 443,
            "ssh": 22,
            "git+ssh": 22,
            "ssh+git": 22,
        }.get(scheme)
        host_identity = host.casefold()
        if port is not None and port != default_port:
            host_identity = f"{host_identity}:{port}"
        path = parsed.path.lstrip("/")
    else:
        match = re.fullmatch(r"(?:([^/@:]+)@)?([^/:]+):(.+)", url)
        if match is None:
            return None
        ssh_user = match.group(1) or ""
        host_identity = match.group(2).casefold()
        path = match.group(3).lstrip("/")
        is_ssh = True
    if host_identity.startswith("-") or ssh_user.startswith("-"):
        return None
    path = path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or path in {".", ".."}:
        return None
    return host_identity, path, ssh_user, is_ssh


def _validate_push_remote_target(repo: Path, remote: str) -> None:
    configured_urls = _git_config_values(repo, f"remote.{remote}.url")
    if len(configured_urls) != 1:
        raise PermissionError(
            "Generic Git push requires exactly one configured URL for the selected remote."
        )
    completed = subprocess.run(
        ["git", "-C", str(repo), "remote", "get-url", "--push", "--all", remote],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=_git_environment(),
    )
    effective_urls = completed.stdout.splitlines() if completed.returncode == 0 else []
    if completed.returncode != 0 or len(effective_urls) != 1:
        raise PermissionError(
            "Generic Git push requires exactly one effective URL for the selected remote."
        )
    configured_identity = _remote_target_identity(configured_urls[0])
    effective_identity = _remote_target_identity(effective_urls[0])
    if configured_identity is None or effective_identity is None:
        raise PermissionError("Git push remote URL is not a supported network target.")
    if not effective_identity[3]:
        raise PermissionError("Git push requires one effective SSH remote target.")
    same_repository = effective_identity[:2] == configured_identity[:2]
    configured_ssh_user = configured_identity[2] if configured_identity[3] else ""
    effective_ssh_user = effective_identity[2]
    same_user_contract = (
        effective_ssh_user == configured_ssh_user
        if configured_identity[3]
        else effective_ssh_user in {"", "git"}
    )
    if not same_repository or not same_user_contract:
        raise PermissionError(
            "Git URL rewrite configuration is blocked because it changes the selected push target."
        )


def _reject_git_alias_configuration(configurations: list[tuple[str, str]]) -> None:
    if any(key.startswith("alias.") for key, _value in configurations):
        raise PermissionError(
            "Git alias injection is blocked because it can conceal a push operation."
        )


def _reject_configured_alias(repo: Path, subcommand: str) -> None:
    aliases = _git_config_entries(repo, rf"^alias\.{re.escape(subcommand)}$")
    if aliases:
        raise PermissionError(
            "Configured Git aliases are blocked in grabowski_git because they can conceal a push operation."
        )


def _parse_safe_push_arguments(push_arguments: list[str]) -> tuple[str, str, str]:
    positionals: list[str] = []
    positional_only = False
    for item in push_arguments:
        if item == "--" and not positional_only:
            positional_only = True
            continue
        if not positional_only and item.startswith("--"):
            if item in GIT_SAFE_PUSH_LONG_OPTIONS:
                continue
            raise PermissionError(
                f"Git push option is blocked in the generic terminal path: {item}"
            )
        if not positional_only and item.startswith("-"):
            if len(item) > 1 and all(
                character in GIT_SAFE_PUSH_SHORT_OPTIONS for character in item[1:]
            ):
                continue
            raise PermissionError(
                f"Git push option is blocked in the generic terminal path: {item}"
            )
        positionals.append(item)

    if len(positionals) != 2:
        raise PermissionError(
            "Generic Git push requires exactly one remote and one explicit branch refspec."
        )
    remote, refspec = positionals
    if remote in {".", ".."} or not GIT_REMOTE_NAME_RE.fullmatch(remote):
        raise PermissionError("Generic Git push requires a configured remote name.")
    if refspec.startswith("+"):
        raise PermissionError("Forced Git pushes are blocked in the generic terminal path.")
    if refspec.count(":") != 1:
        raise PermissionError("Generic Git push requires one explicit source:destination refspec.")
    source, destination = refspec.split(":", 1)
    if not source:
        raise PermissionError("Deleting remote refs is blocked in the generic terminal path.")
    if not destination:
        raise PermissionError("Generic Git push requires an explicit destination branch.")
    if any(character.isspace() or ord(character) < 32 for character in refspec):
        raise PermissionError("Git push refspec contains invalid control or whitespace characters.")
    if "*" in source or "*" in destination:
        raise PermissionError("Aggregate Git push refspecs are blocked in the generic terminal path.")
    prefix = "refs/heads/"
    if not destination.startswith(prefix):
        raise PermissionError("Generic Git push may target only one explicit branch ref.")
    branch = destination[len(prefix) :]
    if branch in PROTECTED_BRANCHES:
        raise PermissionError("Pushes to protected main branches are blocked in the generic terminal path.")
    completed = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=_git_environment(),
    )
    if completed.returncode != 0:
        raise PermissionError("Git push destination branch is invalid.")
    return remote, source, destination


def _reject_push_configuration(repo: Path, remote: str) -> None:
    escaped_remote = re.escape(remote)
    pattern = (
        rf"^(remote\.{escaped_remote}\.(push|pushurl|mirror|receivepack)"
        rf"|push\.(pushoption|followtags|gpgsign|recursesubmodules))$"
    )
    if _git_config_entries(repo, pattern):
        raise PermissionError(
            "Git push configuration that can alter ref or transport semantics is blocked."
        )


def _guard_git(arguments: list[str], repo: Path) -> None:
    if not arguments:
        raise ValueError("Git arguments must not be empty")

    subcommand, command_arguments, configurations = _split_git_invocation(arguments)
    _reject_git_alias_configuration(configurations)
    if subcommand in GIT_REMOTE_WRITE_BYPASS_SUBCOMMANDS:
        raise PermissionError(
            f"Direct Git remote-write subcommand is blocked; use push: {subcommand}"
        )
    if subcommand == "subtree" and command_arguments[:1] == ["push"]:
        raise PermissionError(
            "Git subtree push is blocked in grabowski_git; use the typed publication path."
        )
    if subcommand != "push":
        _reject_configured_alias(repo, subcommand)
        return

    if configurations:
        raise PermissionError(
            "Git command-line configuration is blocked for push in the generic terminal path."
        )
    remote, _source, _destination = _parse_safe_push_arguments(command_arguments)
    _reject_push_configuration(repo, remote)
    _validate_push_remote_target(repo, remote)


@mcp.tool(name="grabowski_terminal_run", annotations=MUTATING)
def grabowski_terminal_run(
    argv: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT,
    max_output_bytes: int = DEFAULT_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Run one non-interactive command and return redacted output."""
    _require_operator_mutation("terminal_execute")
    working_directory = _resolve_cwd(cwd)
    return _run(
        _validate_argv(argv, cwd=working_directory),
        cwd=working_directory,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=_output_limit(max_output_bytes),
    )


def _reserved_runtime_deploy_command(
    command: list[str],
    working_directory: Path,
) -> bool:
    for argument in command[1:]:
        for candidate in _argument_path_candidates(argument):
            if not _path_like_argument(candidate):
                continue
            path = Path(_expand_home_references(candidate)).expanduser()
            if not path.is_absolute():
                path = working_directory / path
            try:
                resolved = path.resolve(strict=False)
            except OSError:
                resolved = path.absolute()
            if resolved == RESERVED_RUNTIME_DEPLOY_RUNNER:
                return True
    return False


def _start_job(
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME,
    notify_on_done: dict[str, Any] | None = None,
    *,
    finalization_expected_head: str | None = None,
    reserved_unit: str | None = None,
    allow_reserved_runtime_deploy: bool = False,
) -> dict[str, Any]:
    """Start an already-authorized durable job."""
    working_directory = _resolve_cwd(cwd)
    command = _validate_argv(argv, cwd=working_directory)
    if (
        _reserved_runtime_deploy_command(command, working_directory)
        and not allow_reserved_runtime_deploy
    ):
        raise PermissionError(
            "runtime deploy runner is reserved for the typed self-deploy scheduler"
        )
    runtime = _job_runtime(runtime_seconds)
    notify_metadata = _normalize_notify_on_done(notify_on_done)
    unit = (
        _validate_unit(reserved_unit, job_only=True)
        if reserved_unit is not None
        else JOB_PREFIX + uuid.uuid4().hex[:12]
    )
    metadata_temp_cleanup = _cleanup_stale_job_metadata_temps(_jobs_root())
    directory = _job_directory(unit, create=True)
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    for path in (stdout_path, stderr_path):
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        os.close(descriptor)

    now_unix, now_iso = _job_timestamp()
    metadata_path = directory / "metadata.json"
    identity = _job_identity(unit)
    argv_sha256 = _argv_hash(command)
    finalization_contract = None
    if finalization_expected_head is not None:
        finalization_contract = _job_finalization_contract(
            unit=unit,
            directory=directory,
            argv_sha256=argv_sha256,
            expected_head=finalization_expected_head,
        )
    metadata = {
        "schema_version": 1,
        **identity,
        "scope": {
            "cwd": str(working_directory),
            "argv_sha256": argv_sha256,
            "runtime_seconds": runtime,
        },
        "argv": _redact_argv(command),
        "argv_sha256": argv_sha256,
        "command": _redacted_command(command),
        "cwd": str(working_directory),
        "runtime_seconds": runtime,
        "created_at_unix": now_unix,
        "started_at": now_iso,
        "started_at_unix": now_unix,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "expected_receipt": _job_expected_receipt(
            unit=unit,
            metadata_path=metadata_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            finalization_path=(directory / FINALIZATION_RECEIPT_NAME) if finalization_contract else None,
        ),
        **({"finalization_contract": finalization_contract} if finalization_contract else {}),
        "final_status": "launch_prepared",
        "terminalization_evidence": {
            "source": "prelaunch-metadata",
            "query_valid": False,
            "final_status": "launch_prepared",
            "systemd_visible": False,
            "does_not_establish": list(JOB_FINAL_STATUS_NON_CLAIMS),
        },
        "notify_on_done": notify_metadata,
        "notification_evidence": {
            "requested": bool(notify_metadata.get("requested")),
            "delivery_enabled": False,
            "delivery_state": "not_sent",
            "reason": "notify_on_done is metadata-only in this slice",
            "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
        },
    }
    metadata_path = _write_job_metadata(directory, metadata)

    systemd_argv = [
        "systemd-run",
        "--user",
        f"--description={_systemd_safe_description('job', unit, metadata['argv_sha256'])}",
        "--unit",
        unit,
        "--property=Type=exec",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=10s",
        "--property=LimitCORE=0",
        f"--property=RuntimeMaxSec={runtime}s",
        f"--property=WorkingDirectory={working_directory}",
        f"--setenv=GRABOWSKI_JOB_DIRECTORY={directory}",
        f"--property=ExecStopPost={sys.executable} -m grabowski_job_finalizer",
        f"--property=StandardOutput=append:{stdout_path}",
        f"--property=StandardError=append:{stderr_path}",
    ]
    if finalization_contract is not None:
        environment = {
            "GRABOWSKI_JOB_ID": finalization_contract["job_id"],
            "GRABOWSKI_JOB_UNIT": finalization_contract["unit"],
            "GRABOWSKI_JOB_ARGV_SHA256": finalization_contract["argv_sha256"],
            "GRABOWSKI_JOB_EXPECTED_HEAD": finalization_contract["expected_head"],
            "GRABOWSKI_JOB_METADATA_PATH": finalization_contract["receipt_paths"]["metadata"],
            "GRABOWSKI_JOB_STDOUT_PATH": finalization_contract["receipt_paths"]["stdout"],
            "GRABOWSKI_JOB_STDERR_PATH": finalization_contract["receipt_paths"]["stderr"],
            "GRABOWSKI_JOB_FINALIZATION_PATH": finalization_contract["receipt_paths"]["finalization"],
        }
        systemd_argv.extend(f"--setenv={key}={value}" for key, value in environment.items())
    systemd_argv.extend(["--", *command])
    result = _run(
        systemd_argv,
        cwd=HOME,
        timeout_seconds=60,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    launcher_evidence = _job_launcher_evidence(result)
    if result["returncode"] != 0:
        metadata = {
            **metadata,
            "final_status": "launch_failed",
            "terminalization_evidence": {
                "source": "systemd-run-launch",
                "query_valid": False,
                "final_status": "launch_failed",
                "systemd_visible": False,
                "does_not_establish": list(JOB_FINAL_STATUS_NON_CLAIMS),
            },
            "launcher_evidence": launcher_evidence,
            "notification_evidence": {
                "requested": bool(notify_metadata.get("requested")),
                "delivery_enabled": False,
                "delivery_state": "not_sent",
                "reason": "notify_on_done is metadata-only in this slice",
                "final_status_preserved": "launch_failed",
                "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
            },
        }
        _replace_job_metadata(directory, metadata)
        raise RuntimeError(result["stderr"] or result["stdout"])

    metadata = {
        **metadata,
        "final_status": "launch_submitted",
        "terminalization_evidence": {
            "source": "systemd-run-launch",
            "query_valid": False,
            "final_status": "launch_submitted",
            "systemd_visible": False,
            "does_not_establish": list(JOB_FINAL_STATUS_NON_CLAIMS),
        },
        "launcher_evidence": launcher_evidence,
        "notification_evidence": {
            "requested": bool(notify_metadata.get("requested")),
            "delivery_enabled": False,
            "delivery_state": "not_sent",
            "reason": "notify_on_done is metadata-only in this slice",
            "final_status_preserved": "launch_submitted",
            "does_not_establish": list(NOTIFICATION_NON_CLAIMS),
        },
    }
    metadata_path = _replace_job_metadata(directory, metadata)
    return {
        **metadata,
        "metadata_path": str(metadata_path),
        "launcher": result,
        "metadata_temp_cleanup": metadata_temp_cleanup,
    }


@mcp.tool(name="grabowski_job_start", annotations=MUTATING)
def grabowski_job_start(
    argv: list[str],
    cwd: str | None = None,
    runtime_seconds: int = DEFAULT_JOB_RUNTIME,
    notify_on_done: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start a durable background command as a transient user systemd unit."""
    _require_operator_mutation("durable_job")
    return _start_job(
        argv,
        cwd=cwd,
        runtime_seconds=runtime_seconds,
        notify_on_done=notify_on_done,
    )


@mcp.tool(name="grabowski_job_status", annotations=READ_ONLY)
def grabowski_job_status(unit: str) -> dict[str, Any]:
    """Return durable metadata and current systemd status for one job."""
    _require_operator_capability("durable_job")
    name = _validate_unit(unit, job_only=True)
    metadata = _read_job_metadata(name)
    result = _run(
        [
            "systemctl",
            "--user",
            "show",
            name,
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainCode",
            "--property=ExecMainStatus",
            "--property=RuntimeMaxUSec",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    properties = _parse_show(result["stdout"])
    query_valid = _systemd_job_query_valid(result, properties)
    systemd_visible = _systemd_job_query_visible(result, properties)
    job_record = _job_status_record(
        name,
        metadata,
        systemd_visible=systemd_visible,
        query_valid=query_valid,
        properties=properties,
    )
    return {
        "unit": name,
        "metadata": metadata,
        "job_record": job_record,
        "final_status": job_record["final_status"],
        "terminalization_evidence": job_record["terminalization_evidence"],
        "finalization_receipt": job_record["finalization_receipt"],
        "notification_evidence": job_record["notification_evidence"],
        "systemd_visible": systemd_visible,
        "returncode": result["returncode"],
        "properties": properties,
        "stderr": result["stderr"],
    }


@mcp.tool(name="grabowski_job_notification_list", annotations=READ_ONLY)
def grabowski_job_notification_list(
    limit: int = 50,
    state: str = "queued",
) -> dict[str, Any]:
    """List durable operator-outbox notifications without claiming external push."""
    _require_operator_capability("durable_job")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if state not in {"queued", "acknowledged", "all"}:
        raise ValueError("state must be queued, acknowledged or all")
    rows: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    for directory in sorted(_jobs_root().iterdir(), key=lambda item: item.name, reverse=True):
        if len(rows) >= limit:
            break
        if directory.is_symlink() or not directory.is_dir() or not directory.name.startswith(JOB_PREFIX):
            continue
        try:
            receipt = _validated_job_notification(directory, directory.name)
            if receipt is None:
                continue
            acknowledgement = _validated_job_notification_ack(
                directory,
                directory.name,
                receipt,
            )
            delivery_state = "acknowledged" if acknowledgement is not None else "queued"
            if state != "all" and delivery_state != state:
                continue
            rows.append({
                "unit": directory.name,
                "job_id": receipt.get("job_id"),
                "notification_id": receipt.get("notification_id"),
                "terminal_status": receipt.get("terminal_status"),
                "delivery_state": delivery_state,
                "requested_channels": receipt.get("requested_channels", []),
                "note": receipt.get("note"),
                "receipt_sha256": receipt.get("receipt_sha256"),
                "ack_sha256": (
                    acknowledgement.get("ack_sha256")
                    if acknowledgement is not None
                    else None
                ),
            })
        except (OSError, ValueError) as exc:
            invalid.append({
                "unit": directory.name,
                "error": _redact(str(exc))[:MAX_NOTIFY_ON_DONE_TEXT],
            })
    return {
        "schema_version": 1,
        "delivery_mode": "operator_outbox",
        "state_filter": state,
        "returned": len(rows),
        "notifications": rows,
        "invalid_receipts": invalid[:20],
        "does_not_establish": list(JOB_NOTIFICATION_NON_CLAIMS),
    }


@mcp.tool(name="grabowski_job_notification_ack", annotations=MUTATING)
def grabowski_job_notification_ack(
    unit: str,
    expected_receipt_sha256: str,
) -> dict[str, Any]:
    """Acknowledge one exact operator-outbox receipt idempotently."""
    _require_operator_mutation("durable_job")
    name = _validate_unit(unit, job_only=True)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_receipt_sha256):
        raise ValueError("expected_receipt_sha256 must be a SHA-256 digest")
    directory = _job_directory(name)
    receipt = _validated_job_notification(directory, name)
    if receipt is None:
        raise ValueError("job notification receipt does not exist")
    if not hmac.compare_digest(
        str(receipt.get("receipt_sha256", "")), expected_receipt_sha256
    ):
        raise ValueError("job notification receipt changed")

    existing = _validated_job_notification_ack(directory, name, receipt)
    if existing is not None:
        return {"created": False, "acknowledgement": existing}

    now_unix, now_iso = _job_timestamp()
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "grabowski_job_notification_ack",
        "unit": name,
        "job_id": receipt.get("job_id"),
        "notification_id": receipt.get("notification_id"),
        "receipt_sha256": expected_receipt_sha256,
        "acknowledged_at": now_iso,
        "acknowledged_at_unix": now_unix,
        "does_not_establish": ["external_push_delivery", "job_success"],
    }
    payload["ack_sha256"] = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    target = directory / JOB_NOTIFICATION_ACK_NAME
    created = _publish_private_create_only_json(directory, target, payload)
    if not created:
        winner = _validated_job_notification_ack(directory, name, receipt)
        if winner is None:
            raise RuntimeError("notification acknowledgement publish race has no winner")
        return {"created": False, "acknowledgement": winner}

    base._append_audit({
        "timestamp_unix": now_unix,
        "operation": "job-notification-ack",
        "unit": name,
        "receipt_sha256": expected_receipt_sha256,
        "ack_sha256": payload["ack_sha256"],
    })
    return {"created": True, "acknowledgement": payload}


@mcp.tool(name="grabowski_job_logs", annotations=READ_ONLY)
def grabowski_job_logs(
    unit: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Read persistent stdout and stderr for one Grabowski job."""
    _require_operator_capability("durable_job")
    name = _validate_unit(unit, job_only=True)
    if max_lines < 1 or max_lines > 2000:
        raise ValueError("max_lines must be between 1 and 2000")
    metadata = _read_job_metadata(name)
    directory = _job_directory(name)
    expected = {
        "stdout_path": directory / "stdout.log",
        "stderr_path": directory / "stderr.log",
    }
    for key, path in expected.items():
        if metadata.get(key) != str(path):
            raise ValueError(f"Job metadata path mismatch: {key}")
    projected = _project_job_metadata(name, metadata)
    return {
        "unit": name,
        "metadata": metadata,
        "job_identity": {
            "job_id": projected.get("job_id"),
            "unit": name,
            "owner": projected.get("owner"),
            "scope": projected.get("scope"),
        },
        "expected_receipt": projected.get("expected_receipt"),
        "finalization_receipt": _finalization_receipt_result(name, metadata),
        "notify_on_done": projected.get("notify_on_done"),
        "stdout": _read_job_log(expected["stdout_path"], max_lines),
        "stderr": _read_job_log(expected["stderr_path"], max_lines),
    }


@mcp.tool(name="grabowski_job_cancel", annotations=MUTATING)
def grabowski_job_cancel(unit: str) -> dict[str, Any]:
    """Stop one Grabowski background job."""
    _require_operator_mutation("durable_job")
    name = _validate_unit(unit, job_only=True)
    return _run(
        ["systemctl", "--user", "stop", name],
        cwd=HOME,
        timeout_seconds=60,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_git", annotations=MUTATING)
def grabowski_git(
    repo: str,
    arguments: list[str],
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run Git with a fail-closed single-branch push subset."""
    _require_operator_mutation("git_cli")
    path = Path(repo).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    if (path == EVIDENCE_ROOT or EVIDENCE_ROOT in path.parents) and not _trusted_owner_mode():
        raise PermissionError("Git mutation of immutable evidence is blocked.")
    _guard_git(arguments, path)
    subcommand, _command_arguments, _configurations = _split_git_invocation(arguments)
    if subcommand == "push":
        remote, _source, _destination = _parse_safe_push_arguments(_command_arguments)
        command_prefix = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            f"remote.{remote}.mirror=false",
            "-c",
            f"remote.{remote}.receivepack=git-receive-pack",
            "-c",
            "push.followTags=false",
            "-c",
            "push.pushOption=",
            "-c",
            "push.gpgSign=false",
            "-c",
            "push.recurseSubmodules=no",
            "-C",
            str(path),
        ]
        environment = _git_push_environment()
    else:
        command_prefix = ["git", "-C", str(path)]
        environment = _git_environment()
    command = _validate_argv([*command_prefix, *arguments], cwd=path)
    return _run(
        command,
        cwd=path,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=MAX_OUTPUT_BYTES,
        environment=environment,
    )


@mcp.tool(name="grabowski_github", annotations=MUTATING)
def grabowski_github(
    arguments: list[str],
    cwd: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run GitHub CLI with redacted output."""
    _require_operator_mutation("github_cli")
    if not arguments:
        raise ValueError("GitHub CLI arguments must not be empty")
    working_directory = _resolve_cwd(cwd)
    command = _validate_argv(["gh", *arguments], cwd=working_directory)
    return _run(
        command,
        cwd=working_directory,
        timeout_seconds=_timeout(timeout_seconds),
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_user_service", annotations=MUTATING)
def grabowski_user_service(
    unit: str,
    action: str,
    max_lines: int = 200,
) -> dict[str, Any]:
    """Inspect or control one user-level systemd service."""
    _require_operator_capability("user_service_control")
    name = _validate_unit(unit)
    allowed = {
        "status",
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
        "logs",
    }
    if action not in allowed:
        raise ValueError(f"action must be one of {sorted(allowed)}")
    if action not in {"status", "logs"}:
        _require_operator_mutation("user_service_control")

    if action == "logs":
        if max_lines < 1 or max_lines > 2000:
            raise ValueError("max_lines must be between 1 and 2000")
        argv = [
            "journalctl",
            "--user",
            "--unit",
            name,
            "--no-pager",
            "--lines",
            str(max_lines),
        ]
    elif action == "status":
        argv = [
            "systemctl",
            "--user",
            "status",
            name,
            "--no-pager",
            "--full",
        ]
    else:
        argv = ["systemctl", "--user", action, name]

    return _run(
        argv,
        cwd=HOME,
        timeout_seconds=120,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_list", annotations=READ_ONLY)
def grabowski_tmux_list() -> dict[str, Any]:
    """List tmux sessions visible to the current user."""
    _require_operator_capability("tmux_interaction")
    return _run(
        [
            "tmux",
            "list-sessions",
            "-F",
            "#{session_name}\t#{session_windows}\t"
            "#{session_attached}\t#{session_activity}",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_capture", annotations=READ_ONLY)
def grabowski_tmux_capture(
    target: str,
    start_line: int = -300,
) -> dict[str, Any]:
    """Capture text from one tmux pane."""
    _require_operator_capability("tmux_interaction")
    if not target or len(target) > 200:
        raise ValueError("Invalid tmux target")
    if start_line > 0 or start_line < -10000:
        raise ValueError("start_line must be between -10000 and 0")
    return _run(
        [
            "tmux",
            "capture-pane",
            "-p",
            "-t",
            target,
            "-S",
            str(start_line),
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_tmux_send", annotations=MUTATING)
def grabowski_tmux_send(
    target: str,
    text: str,
    press_enter: bool = True,
) -> dict[str, Any]:
    """Send literal text to one tmux pane, optionally followed by Enter."""
    _require_operator_mutation("tmux_interaction")
    if not target or len(target) > 200:
        raise ValueError("Invalid tmux target")
    if len(text.encode("utf-8")) > 100_000:
        raise ValueError("tmux text exceeds 100000 bytes")

    first = _run(
        ["tmux", "send-keys", "-t", target, "-l", "--", text],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    if first["returncode"] != 0 or not press_enter:
        return first

    second = _run(
        ["tmux", "send-keys", "-t", target, "Enter"],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=DEFAULT_OUTPUT_BYTES,
    )
    return {
        "target": target,
        "text_bytes": len(text.encode("utf-8")),
        "press_enter": press_enter,
        "send_text": first,
        "send_enter": second,
    }


@mcp.tool(name="grabowski_process_list", annotations=READ_ONLY)
def grabowski_process_list(pattern: str | None = None) -> dict[str, Any]:
    """List current-user processes, optionally filtered by a regex."""
    _require_operator_capability("process_inspect")
    result = _run(
        [
            "ps",
            "-u",
            str(os.getuid()),
            "-o",
            "pid=,ppid=,stat=,etimes=,comm=,args=",
        ],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    lines = result["stdout"].splitlines()
    if pattern:
        regex = re.compile(pattern)
        lines = [line for line in lines if regex.search(line)]
    return {"pattern": pattern, "lines": lines, "count": len(lines)}


@mcp.tool(name="grabowski_process_signal", annotations=MUTATING)
def grabowski_process_signal(
    pid: int,
    signal_name: str = "TERM",
) -> dict[str, Any]:
    """Send TERM, INT, HUP or KILL to one process owned by the current user."""
    _require_operator_mutation("process_signal")
    allowed = {
        "TERM": signal.SIGTERM,
        "INT": signal.SIGINT,
        "HUP": signal.SIGHUP,
        "KILL": signal.SIGKILL,
    }
    name = signal_name.upper()
    if name not in allowed:
        raise ValueError(f"signal_name must be one of {sorted(allowed)}")
    if pid in {0, 1, os.getpid(), os.getppid()}:
        raise PermissionError("Protected process identifier")

    stat = Path(f"/proc/{pid}/status")
    if not stat.is_file():
        raise ValueError(f"Process does not exist: {pid}")
    owner_line = next(
        (
            line
            for line in stat.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if line.startswith("Uid:")
        ),
        None,
    )
    if owner_line is None:
        raise RuntimeError("Could not determine process owner")
    real_uid = int(owner_line.split()[1])
    if real_uid != os.getuid():
        raise PermissionError("Process is not owned by the current user")

    os.kill(pid, allowed[name])
    return {"pid": pid, "signal": name, "sent": True}


@mcp.tool(name="grabowski_ports", annotations=READ_ONLY)
def grabowski_ports() -> dict[str, Any]:
    """List listening TCP and UDP sockets."""
    _require_operator_capability("port_inspect")
    return _run(
        ["ss", "-lntup"],
        cwd=HOME,
        timeout_seconds=30,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )


@mcp.tool(name="grabowski_privileged_action_reference", annotations=READ_ONLY)
def grabowski_privileged_action_reference(
    action: str,
    target: str,
    justification: str,
) -> dict[str, Any]:
    """Create a strict reference for a future privileged action without executing it."""
    _require_operator_capability("privileged_reference")
    if action not in PRIVILEGED_REFERENCE_ACTIONS:
        raise ValueError(
            f"action must be one of {sorted(PRIVILEGED_REFERENCE_ACTIONS)}"
        )
    for label, value in {
        "target": target,
        "justification": justification,
    }.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{label} must be a non-empty string")
        if len(value.encode("utf-8")) > 1000 or "\x00" in value:
            raise ValueError(f"{label} is too large or contains NUL")
        if _redact(value) != value:
            raise ValueError(f"{label} appears to contain secret material")

    created_at = int(time.time())
    payload = {
        "schema_version": 1,
        "execution": "unprivileged-reference-only",
        "may_execute": False,
        "requires_external_privileged_agent": True,
        "replay_policy": PRIVILEGED_REFERENCE_REPLAY_POLICY,
        "action": action,
        "target": target,
        "justification": justification,
        "request_id": uuid.uuid4().hex,
        "created_at_unix": created_at,
        "expires_at_unix": created_at + PRIVILEGED_REFERENCE_TTL_SECONDS,
    }
    payload["reference_sha256"] = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return payload


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Grabowski MCP operator."
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18181)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.transport == "streamable-http":
        if args.host != "127.0.0.1":
            raise SystemExit(
                "Grabowski HTTP transport must bind to 127.0.0.1"
            )
        if not 1024 <= args.port <= 65535:
            raise SystemExit("port must be between 1024 and 65535")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
