from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

import grabowski_mcp as base

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator


mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
HOME = operator.HOME

SCHEMA_VERSION = 1
AGENT_URL = os.environ.get(
    "GRABOWSKI_JUNO_URL",
    "http://100.111.206.65:8765",
).rstrip("/")
AGENT_ID = "ipad-10th-gen-wifi"
AGENT_TAILSCALE_IP = "100.111.206.65"
EXPECTED_AGENT_HOST = AGENT_TAILSCALE_IP
EXPECTED_AGENT_PORT = 8765
EXPECTED_PAIRING_PEER = "100.68.88.111"
SECRET_PATH = Path(
    os.environ.get(
        "GRABOWSKI_JUNO_SECRET_FILE",
        str(HOME / ".config" / "grabowski" / "secrets" / "juno-ipad-agent.key"),
    )
).expanduser()
RECEIPT_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_JUNO_RECEIPT_ROOT",
        str(HOME / ".local" / "state" / "grabowski" / "juno-ipad" / "receipts"),
    )
).expanduser()
MAX_RESPONSE_BYTES = 512 * 1024
MAX_CODE_BYTES = 384 * 1024
MAX_PURPOSE_BYTES = 1_000
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 20
NETWORK_TIMEOUT_SECONDS = 6.0
TERMINAL_STATES = {
    "succeeded",
    "failed",
    "timed_out",
    "abandoned_after_restart",
}
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
CONSENT_CODE_RE = re.compile(r"^[0-9]{6}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class _NoRedirectHandler(HTTPRedirectHandler):
    def _reject(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
    ) -> None:
        raise HTTPError(request.full_url, code, message, headers, file_pointer)

    http_error_301 = _reject
    http_error_302 = _reject
    http_error_303 = _reject
    http_error_307 = _reject
    http_error_308 = _reject


def _validated_agent_base_url() -> str:
    parsed = urlparse(AGENT_URL)
    if (
        parsed.scheme != "http"
        or parsed.hostname != EXPECTED_AGENT_HOST
        or parsed.port != EXPECTED_AGENT_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("Juno agent URL is outside the exact private endpoint")
    return f"http://{EXPECTED_AGENT_HOST}:{EXPECTED_AGENT_PORT}"


def _signed_headers(secret: bytes, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    body_sha256 = _sha256_bytes(body)
    message = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}".encode(
        "utf-8"
    )
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "X-Grabowski-Timestamp": timestamp,
        "X-Grabowski-Nonce": nonce,
        "X-Grabowski-Body-SHA256": body_sha256,
        "X-Grabowski-Signature": signature,
    }


def _request(
    method: str,
    path: str,
    document: Any | None = None,
    *,
    secret: bytes | None = None,
) -> Any:
    if not path.startswith("/") or "\x00" in path:
        raise ValueError("invalid Juno request path")
    body = b"" if document is None else _canonical_json_bytes(document)
    headers = {"Accept": "application/json"}
    if document is not None:
        headers["Content-Type"] = "application/json; charset=utf-8"
    if secret is not None:
        headers.update(_signed_headers(secret, method, path, body))
    base_url = _validated_agent_base_url()
    request = Request(
        f"{base_url}{path}",
        data=body if method.upper() in {"POST", "PUT", "PATCH"} else None,
        headers=headers,
        method=method.upper(),
    )
    opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
    try:
        with opener.open(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
    except HTTPError as exc:
        payload = exc.read(MAX_RESPONSE_BYTES + 1)
        status = exc.code
    except URLError as exc:
        raise RuntimeError(f"Juno agent unreachable: {exc.reason}") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Juno agent response exceeds bounded size")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        if not 200 <= status < 300:
            raise RuntimeError(f"Juno agent error HTTP {status}: invalid_json") from exc
        raise RuntimeError(f"invalid Juno agent response: HTTP {status}") from exc
    if not 200 <= status < 300:
        error = parsed.get("error") if isinstance(parsed, dict) else None
        raise RuntimeError(f"Juno agent error HTTP {status}: {error or 'unknown'}")
    return parsed


def _health() -> dict[str, Any]:
    value = _request("GET", "/health")
    if not isinstance(value, dict):
        raise RuntimeError("Juno health is not an object")
    if value.get("service") != "grabowski-juno-ipad-agent":
        raise RuntimeError("unexpected Juno agent identity")
    if value.get("arbitrary_python") is not True:
        raise RuntimeError("Juno agent does not declare arbitrary Python mode")
    return value


def _read_private_secret(path: Path | None = None) -> bytes:
    path = SECRET_PATH if path is None else path
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Juno secret is not a regular file")
        if metadata.st_nlink != 1:
            raise RuntimeError("Juno secret must have exactly one hardlink")
        if metadata.st_uid != os.getuid():
            raise RuntimeError("Juno secret is not owned by the current user")
        if metadata.st_mode & 0o077:
            raise RuntimeError("Juno secret is readable by group or others")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            secret = handle.read(33)
    finally:
        os.close(fd)
    if len(secret) != 32:
        raise RuntimeError("Juno secret must be exactly 32 bytes")
    return secret


def _atomic_create(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _provision_secret(consent_code: str, *, replace_secret: bool) -> tuple[bytes, Any]:
    target = SECRET_PATH
    pending = target.with_name(f".{target.name}.pairing-pending")
    target_exists = os.path.lexists(target)
    if target_exists and not replace_secret:
        secret = _read_private_secret(target)
        response = _request(
            "POST",
            "/v1/pair",
            {
                "schema_version": SCHEMA_VERSION,
                "secret_b64": base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
                "consent_code": consent_code,
            },
        )
        return secret, response
    if target_exists:
        _read_private_secret(target)
    if pending.exists():
        secret = _read_private_secret(pending)
    else:
        secret = secrets.token_bytes(32)
        _atomic_create(pending, secret)
        _fsync_directory(pending.parent)
    response = _request(
        "POST",
        "/v1/pair",
        {
            "schema_version": SCHEMA_VERSION,
            "secret_b64": base64.urlsafe_b64encode(secret).decode("ascii").rstrip("="),
            "consent_code": consent_code,
        },
    )
    os.replace(pending, target)
    os.chmod(target, 0o600)
    _fsync_directory(target.parent)
    return secret, response


def _validate_expected_agent(health: dict[str, Any], expected_started_at: str) -> None:
    if not isinstance(expected_started_at, str) or not expected_started_at.strip():
        raise ValueError("expected_started_at must be non-empty")
    if health.get("started_at") != expected_started_at:
        raise RuntimeError("Juno agent instance changed since authorization")
    if health.get("pairing_peer") != EXPECTED_PAIRING_PEER:
        raise RuntimeError("Juno agent is not bound to the heim-pc Tailscale peer")


def _target_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        result: set[str] = set()
        for item in value.values():
            result.update(_target_values(item))
        return result
    if isinstance(value, (list, tuple)):
        result = set()
        for item in value:
            result.update(_target_values(item))
        return result
    return set()


def _validate_escalation(session_escalation: dict[str, Any]) -> None:
    base._validate_session_escalation(session_escalation)
    target_values = _target_values(session_escalation.get("target"))
    if not target_values.intersection({AGENT_ID, AGENT_TAILSCALE_IP}):
        raise PermissionError("session escalation is not bound to the Juno iPad agent")


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return operator._redact(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    return value


def _write_receipt(kind: str, fields: dict[str, Any]) -> dict[str, Any]:
    RECEIPT_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "agent_id": AGENT_ID,
        "recorded_at_unix": int(time.time()),
        **fields,
    }
    receipt["receipt_sha256"] = _sha256_bytes(_canonical_json_bytes(receipt))
    path = RECEIPT_ROOT / f"{int(time.time())}-{uuid.uuid4().hex}.json"
    _atomic_create(path, _canonical_json_bytes(receipt) + b"\n")
    _fsync_directory(path.parent)
    return {
        "path": str(path),
        "sha256": receipt["receipt_sha256"],
    }


@mcp.tool(name="grabowski_juno_status", annotations=READ_ONLY)
def grabowski_juno_status(job_id: str = "") -> dict[str, Any]:
    """Read the Juno iPad agent health or one authenticated job receipt."""
    operator._require_operator_capability("terminal_execute")
    health = _health()
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "agent_id": AGENT_ID,
        "health": _redact_value(health),
    }
    if job_id:
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("invalid Juno job id")
        if health.get("paired") is not True:
            raise RuntimeError("Juno agent is not paired")
        secret = _read_private_secret()
        result["job"] = _redact_value(
            _request("GET", f"/v1/jobs/{quote(job_id, safe='')}", secret=secret)
        )
    return result


@mcp.tool(name="grabowski_juno_pair", annotations=MUTATING)
def grabowski_juno_pair(
    consent_code: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    replace_secret: bool = False,
) -> dict[str, Any]:
    """Pair the locally consented Juno iPad agent without exposing its secret."""
    _validate_escalation(session_escalation)
    operator._require_operator_mutation(
        "terminal_execute",
        host=AGENT_ID,
        fresh_preflight=True,
    )
    if not CONSENT_CODE_RE.fullmatch(consent_code):
        raise ValueError("consent_code must contain exactly six digits")
    health = _health()
    _validate_expected_agent(health, expected_started_at)
    if health.get("paired") is True:
        secret = _read_private_secret()
        authenticated = _request("GET", "/v1/jobs?limit=1", secret=secret)
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "already_paired_and_authenticated",
            "agent_id": AGENT_ID,
            "started_at": expected_started_at,
            "authentication_probe": _redact_value(authenticated),
        }
    if health.get("pairing_consent_required") is not True:
        raise RuntimeError("Juno agent does not report local pairing consent")
    expires = health.get("pairing_consent_expires_at_unix")
    if not isinstance(expires, int) or isinstance(expires, bool) or expires < int(time.time()):
        raise RuntimeError("Juno local pairing consent is expired")
    _secret, response = _provision_secret(
        consent_code,
        replace_secret=replace_secret,
    )
    post_health = _health()
    _validate_expected_agent(post_health, expected_started_at)
    if post_health.get("paired") is not True:
        raise RuntimeError("Juno pairing response returned without paired readback")
    receipt = _write_receipt(
        "grabowski_juno_pair_receipt",
        {
            "started_at": expected_started_at,
            "pairing_response": _redact_value(response),
            "paired_readback": True,
            "secret_path": str(SECRET_PATH),
            "does_not_establish": [
                "iPadOS root access",
                "background execution persistence",
                "job safety",
            ],
        },
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "paired",
        "agent_id": AGENT_ID,
        "started_at": expected_started_at,
        "receipt": receipt,
    }


@mcp.tool(name="grabowski_juno_run", annotations=MUTATING)
def grabowski_juno_run(
    code: str,
    code_sha256: str,
    purpose: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    timeout_seconds: int = 10,
) -> dict[str, Any]:
    """Run one locally consented, hash-bound Python job inside the Juno process."""
    _validate_escalation(session_escalation)
    operator._require_operator_mutation(
        "terminal_execute",
        host=AGENT_ID,
        fresh_preflight=True,
    )
    if not isinstance(code, str):
        raise ValueError("code must be a string")
    code_bytes = code.encode("utf-8")
    if not code_bytes or len(code_bytes) > MAX_CODE_BYTES:
        raise ValueError("code size is outside the Juno contract")
    actual_code_sha256 = _sha256_bytes(code_bytes)
    if not SHA256_RE.fullmatch(code_sha256) or code_sha256 != actual_code_sha256:
        raise ValueError("code_sha256 does not match the supplied code")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError("purpose must be non-empty")
    if len(purpose.encode("utf-8")) > MAX_PURPOSE_BYTES or operator._redact(purpose) != purpose:
        raise ValueError("purpose is too large or appears to contain secret material")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
        raise ValueError("timeout_seconds must be an integer")
    if not MIN_TIMEOUT_SECONDS <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}")
    health = _health()
    _validate_expected_agent(health, expected_started_at)
    if health.get("paired") is not True:
        raise RuntimeError("Juno agent is not paired")
    secret = _read_private_secret()
    job_id = f"job-mcp-{uuid.uuid4()}"
    submitted = _request(
        "POST",
        "/v1/jobs",
        {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_id,
            "code": code,
            "timeout_seconds": timeout_seconds,
            "metadata": {
                "purpose": purpose,
                "code_sha256": code_sha256,
                "submitted_by": "grabowski_juno_run",
            },
        },
        secret=secret,
    )
    deadline = time.monotonic() + timeout_seconds + 4
    status = submitted
    while isinstance(status, dict) and status.get("state") not in TERMINAL_STATES:
        if time.monotonic() >= deadline:
            break
        time.sleep(0.2)
        status = _request(
            "GET",
            f"/v1/jobs/{quote(job_id, safe='')}",
            secret=secret,
        )
    redacted_status = _redact_value(status)
    receipt = _write_receipt(
        "grabowski_juno_job_receipt",
        {
            "started_at": expected_started_at,
            "job_id": job_id,
            "code_sha256": code_sha256,
            "purpose_sha256": _sha256_bytes(purpose.encode("utf-8")),
            "terminal": (
                isinstance(status, dict) and status.get("state") in TERMINAL_STATES
            ),
            "result_sha256": _sha256_bytes(_canonical_json_bytes(redacted_status)),
            "does_not_establish": [
                "job isolation from the Juno process",
                "native-call timeout enforcement",
                "iPadOS background persistence",
            ],
        },
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": AGENT_ID,
        "started_at": expected_started_at,
        "job_id": job_id,
        "code_sha256": code_sha256,
        "status": redacted_status,
        "receipt": receipt,
    }
