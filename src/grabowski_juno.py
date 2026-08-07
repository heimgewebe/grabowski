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

NATIVE_PERMISSION_CAPABILITIES = frozenset(
    {
        "camera",
        "microphone",
        "photos_read_write",
        "notifications",
        "location_when_in_use",
    }
)
MAX_NATIVE_PERMISSION_RESULT_BYTES = 16 * 1024

_NATIVE_PERMISSION_JOB_SOURCE = r"""
from __future__ import annotations

import base64
import builtins
import ctypes
from datetime import datetime, timezone
import json
import threading
import time
from typing import Any

from juno.objc import Block, ObjCClass, ObjCInstance, on_main_thread

SCHEMA_VERSION = 1
REQUEST_TIMEOUT_SECONDS = 12.0
NOTIFICATION_STATUS_TIMEOUT_SECONDS = 3.0
ALLOWED_CAPABILITIES = {
    "camera",
    "microphone",
    "photos_read_write",
    "notifications",
    "location_when_in_use",
}
RETENTION_LIMIT = 64
_RUNTIME_KEY = "_grabowski_juno_native_permission_runtime_v1"
_runtime = getattr(builtins, _RUNTIME_KEY, None)
if not isinstance(_runtime, dict):
    _runtime = {"retained": []}
    setattr(builtins, _RUNTIME_KEY, _runtime)
_RETAINED = _runtime["retained"]


def _retain(value: Any) -> Any:
    if len(_RETAINED) >= RETENTION_LIMIT:
        raise RuntimeError("native permission retention bound exhausted")
    _RETAINED.append(value)
    return value


def _release(value: Any) -> None:
    for index, item in enumerate(_RETAINED):
        if item is value:
            del _RETAINED[index]
            return


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _zero(value: Any) -> Any:
    return value() if callable(value) else value


def _notification_status() -> dict[str, int]:
    center = _zero(ObjCClass("UNUserNotificationCenter").currentNotificationCenter)
    done = threading.Event()
    holder: dict[str, Any] = {}

    def completed(settings_pointer: int) -> None:
        try:
            settings = ObjCInstance(settings_pointer)
            holder.update(
                {
                    "authorization": int(_zero(settings.authorizationStatus)),
                    "alert": int(_zero(settings.alertSetting)),
                    "badge": int(_zero(settings.badgeSetting)),
                    "sound": int(_zero(settings.soundSetting)),
                }
            )
        except Exception as exc:
            holder["error_type"] = type(exc).__name__
        finally:
            done.set()
            _release(block)

    block = _retain(Block(completed, None, ctypes.c_void_p))
    try:
        center.getNotificationSettingsWithCompletionHandler_(block)
    except Exception:
        _release(block)
        raise
    if not done.wait(NOTIFICATION_STATUS_TIMEOUT_SECONDS):
        # Keep the block retained: iPadOS may still deliver the callback later.
        raise RuntimeError("notification settings callback timed out")
    if "error_type" in holder:
        raise RuntimeError(f"notification settings callback failed: {holder['error_type']}")
    return {
        "authorization": int(holder["authorization"]),
        "alert": int(holder["alert"]),
        "badge": int(holder["badge"]),
        "sound": int(holder["sound"]),
    }


def _permission_status(capability: str) -> dict[str, Any]:
    if capability == "camera":
        value = int(ObjCClass("AVCaptureDevice").authorizationStatusForMediaType_("vide"))
        return {"authorization": value}
    if capability == "microphone":
        value = int(ObjCClass("AVCaptureDevice").authorizationStatusForMediaType_("soun"))
        return {"authorization": value}
    if capability == "photos_read_write":
        value = int(ObjCClass("PHPhotoLibrary").authorizationStatusForAccessLevel_(2))
        return {"authorization": value}
    if capability == "notifications":
        return _notification_status()
    if capability == "location_when_in_use":
        manager = ObjCClass("CLLocationManager")
        return {
            "authorization": int(_zero(manager.authorizationStatus)),
            "services_enabled": bool(_zero(manager.locationServicesEnabled)),
        }
    raise ValueError("unsupported native permission capability")


def _all_status() -> dict[str, dict[str, Any]]:
    return {
        capability: _permission_status(capability)
        for capability in (
            "camera",
            "microphone",
            "photos_read_write",
            "notifications",
            "location_when_in_use",
        )
    }


def _foreground_state() -> int:
    app = _zero(ObjCClass("UIApplication").sharedApplication)
    return int(_zero(app.applicationState))


def _wait_for_determined(capability: str, done: threading.Event | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = _permission_status(capability)
        if int(status["authorization"]) != 0:
            return status
        if done is not None and done.is_set():
            status = _permission_status(capability)
            if int(status["authorization"]) != 0:
                return status
        time.sleep(0.2)
    status = _permission_status(capability)
    if int(status["authorization"]) != 0:
        return status
    raise RuntimeError("permission request timed out without a determined readback")


def _request_camera_or_microphone(capability: str) -> dict[str, Any]:
    media_type = "vide" if capability == "camera" else "soun"
    device = ObjCClass("AVCaptureDevice")
    done = threading.Event()

    def completed(_granted: bool) -> None:
        done.set()
        _release(block)

    block = _retain(Block(completed, None, ctypes.c_bool))

    @on_main_thread
    def invoke() -> None:
        device.requestAccessForMediaType_completionHandler_(media_type, block)

    try:
        invoke()
    except Exception:
        _release(block)
        raise
    # On timeout the block intentionally remains retained for a late iPadOS callback.
    return _wait_for_determined(capability, done)


def _request_photos() -> dict[str, Any]:
    library = ObjCClass("PHPhotoLibrary")
    done = threading.Event()

    def completed(_status: int) -> None:
        done.set()
        _release(block)

    block = _retain(Block(completed, None, ctypes.c_long))

    @on_main_thread
    def invoke() -> None:
        library.requestAuthorizationForAccessLevel_handler_(2, block)

    try:
        invoke()
    except Exception:
        _release(block)
        raise
    # On timeout the block intentionally remains retained for a late iPadOS callback.
    return _wait_for_determined("photos_read_write", done)


def _request_notifications() -> dict[str, Any]:
    center = _zero(ObjCClass("UNUserNotificationCenter").currentNotificationCenter)
    done = threading.Event()
    callback_error = {"present": False}

    def completed(_granted: bool, error_pointer: int) -> None:
        callback_error["present"] = bool(error_pointer)
        done.set()
        _release(block)

    block = _retain(Block(completed, None, ctypes.c_bool, ctypes.c_void_p))

    @on_main_thread
    def invoke() -> None:
        center.requestAuthorizationWithOptions_completionHandler_(1 | 2 | 4, block)

    try:
        invoke()
    except Exception:
        _release(block)
        raise
    # On timeout the block intentionally remains retained for a late iPadOS callback.
    post = _wait_for_determined("notifications", done)
    if callback_error["present"] and int(post["authorization"]) == 0:
        raise RuntimeError("notification permission callback returned an error")
    return post


def _request_location() -> dict[str, Any]:
    manager_class = ObjCClass("CLLocationManager")

    @on_main_thread
    def invoke() -> Any:
        manager = _retain(manager_class.alloc().init())
        try:
            manager.requestWhenInUseAuthorization()
        except Exception:
            _release(manager)
            raise
        return manager

    manager = invoke()
    try:
        post = _wait_for_determined("location_when_in_use")
    except Exception:
        # Keep the manager retained: iPadOS may still complete a visible prompt later.
        raise
    _release(manager)
    return post


def _run(request: dict[str, Any]) -> dict[str, Any]:
    operation = request.get("operation")
    if operation == "status":
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_native_permission_status",
            "verification_time": _utc_now(),
            "permissions": _all_status(),
            "does_not_establish": [
                "photo_or_media_contents",
                "audio_or_camera_contents",
                "location_coordinates",
                "clipboard_contents",
                "contact_message_or_safari_access",
            ],
        }

    if operation != "request":
        raise ValueError("unsupported native permission operation")
    capability = request.get("capability")
    if capability not in ALLOWED_CAPABILITIES:
        raise ValueError("unsupported native permission capability")
    pre = _permission_status(capability)
    if int(pre["authorization"]) != 0:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "ipad_native_permission_request",
            "verification_time": _utc_now(),
            "capability": capability,
            "state": "already_determined",
            "foreground_verified": False,
            "pre_status": pre,
            "post_status": pre,
        }

    app_state = _foreground_state()
    if app_state != 0:
        raise RuntimeError(f"Juno must be foreground for a permission request; applicationState={app_state}")

    if capability in {"camera", "microphone"}:
        post = _request_camera_or_microphone(capability)
    elif capability == "photos_read_write":
        post = _request_photos()
    elif capability == "notifications":
        post = _request_notifications()
    else:
        post = _request_location()

    if int(post["authorization"]) == 0:
        raise RuntimeError("permission remained undetermined after request")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "ipad_native_permission_request",
        "verification_time": _utc_now(),
        "capability": capability,
        "state": "determined_after_request",
        "foreground_verified": True,
        "pre_status": pre,
        "post_status": post,
    }


_REQUEST = json.loads(base64.b64decode("__REQUEST_B64__").decode("utf-8"))
GRABOWSKI_RESULT = _run(_REQUEST)
"""


def _validate_native_permission_capability(value: str) -> str:
    if not isinstance(value, str) or value not in NATIVE_PERMISSION_CAPABILITIES:
        raise ValueError(
            "capability must be one of: " + ", ".join(sorted(NATIVE_PERMISSION_CAPABILITIES))
        )
    return value


def _native_permission_code(request: dict[str, Any]) -> tuple[str, str]:
    request_b64 = base64.b64encode(_canonical_json_bytes(request)).decode("ascii")
    code = _NATIVE_PERMISSION_JOB_SOURCE.replace("__REQUEST_B64__", request_b64)
    code_bytes = code.encode("utf-8")
    if len(code_bytes) > MAX_CODE_BYTES:
        raise ValueError("typed native permission job exceeds the Juno code transport bound")
    return code, _sha256_bytes(code_bytes)


def _native_authorization_status(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} status is not an object")
    authorization = value.get("authorization")
    if isinstance(authorization, bool) or not isinstance(authorization, int) or not 0 <= authorization <= 16:
        raise RuntimeError(f"{label} authorization status is invalid")
    allowed = {"authorization"}
    if label == "notifications":
        allowed |= {"alert", "badge", "sound"}
        for field in ("alert", "badge", "sound"):
            field_value = value.get(field)
            if isinstance(field_value, bool) or not isinstance(field_value, int) or not 0 <= field_value <= 16:
                raise RuntimeError(f"notification {field} setting is invalid")
    if label == "location_when_in_use":
        allowed.add("services_enabled")
        if not isinstance(value.get("services_enabled"), bool):
            raise RuntimeError("location services_enabled is invalid")
    if set(value) != allowed:
        raise RuntimeError(f"{label} status contains unexpected fields")
    return value


def _validate_native_permission_result(request: dict[str, Any], result: Any) -> dict[str, Any]:
    if not isinstance(result, dict) or result.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("native permission result schema mismatch")
    if len(_canonical_json_bytes(result)) > MAX_NATIVE_PERMISSION_RESULT_BYTES:
        raise RuntimeError("native permission result exceeds bounded size")
    operation = request.get("operation")
    if operation == "status":
        expected_fields = {
            "schema_version",
            "kind",
            "verification_time",
            "permissions",
            "does_not_establish",
        }
        if set(result) != expected_fields:
            raise RuntimeError("native permission status contains unexpected top-level fields")
        if result.get("kind") != "ipad_native_permission_status":
            raise RuntimeError("native permission status result kind mismatch")
        permissions = result.get("permissions")
        if not isinstance(permissions, dict) or set(permissions) != NATIVE_PERMISSION_CAPABILITIES:
            raise RuntimeError("native permission status set mismatch")
        for capability in sorted(NATIVE_PERMISSION_CAPABILITIES):
            _native_authorization_status(permissions[capability], label=capability)
        limitations = result.get("does_not_establish")
        if not isinstance(limitations, list) or len(limitations) > 16:
            raise RuntimeError("native permission status limitations are invalid")
        if not isinstance(result.get("verification_time"), str) or not result["verification_time"]:
            raise RuntimeError("native permission status verification_time is invalid")
        return result

    if operation != "request" or result.get("kind") != "ipad_native_permission_request":
        raise RuntimeError("native permission request result kind mismatch")
    expected_fields = {
        "schema_version",
        "kind",
        "verification_time",
        "capability",
        "state",
        "foreground_verified",
        "pre_status",
        "post_status",
    }
    if set(result) != expected_fields:
        raise RuntimeError("native permission request contains unexpected top-level fields")
    capability = request.get("capability")
    if result.get("capability") != capability:
        raise RuntimeError("native permission request capability mismatch")
    if result.get("state") not in {"already_determined", "determined_after_request"}:
        raise RuntimeError("native permission request state is invalid")
    if not isinstance(result.get("foreground_verified"), bool):
        raise RuntimeError("native permission foreground evidence is invalid")
    pre = _native_authorization_status(result.get("pre_status"), label=str(capability))
    post = _native_authorization_status(result.get("post_status"), label=str(capability))
    if result["state"] == "already_determined":
        if int(pre["authorization"]) == 0 or pre != post or result["foreground_verified"]:
            raise RuntimeError("already-determined native permission result is inconsistent")
    else:
        if int(pre["authorization"]) != 0 or int(post["authorization"]) == 0 or not result["foreground_verified"]:
            raise RuntimeError("requested native permission result is inconsistent")
    if not isinstance(result.get("verification_time"), str) or not result["verification_time"]:
        raise RuntimeError("native permission request verification_time is invalid")
    return result


def _run_native_permission_job(
    *,
    operation: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
    capability: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "operation": operation}
    if capability is not None:
        request["capability"] = _validate_native_permission_capability(capability)
    code, code_sha256 = _native_permission_code(request)
    execution = grabowski_juno_run(
        code=code,
        code_sha256=code_sha256,
        purpose=f"Run typed Juno iPad native permission operation: {operation}",
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
        timeout_seconds=20,
    )
    status = execution.get("status")
    terminal_succeeded = isinstance(status, dict) and status.get("state") == "succeeded"
    result = status.get("result") if isinstance(status, dict) else None
    semantic_valid: bool | None = None
    semantic_error: str | None = None
    if terminal_succeeded:
        try:
            _validate_native_permission_result(request, result)
            semantic_valid = True
        except Exception as exc:
            semantic_valid = False
            semantic_error = operator._redact(f"{type(exc).__name__}: {str(exc)[:240]}")
    receipt = _write_receipt(
        "grabowski_juno_native_permission_receipt",
        {
            "started_at": expected_started_at,
            "operation": operation,
            "capability": capability,
            "job_id": execution.get("job_id"),
            "code_sha256": code_sha256,
            "terminal_succeeded": terminal_succeeded,
            "semantic_validation": {
                "valid": semantic_valid,
                "error": semantic_error,
            },
            "result_sha256": (
                _sha256_bytes(_canonical_json_bytes(result)) if result is not None else None
            ),
            "does_not_establish": [
                "iPadOS root access",
                "private content access",
                "location coordinates",
                "permission grant when post-readback remains undetermined",
            ],
        },
    )
    if terminal_succeeded and semantic_valid is not True:
        raise RuntimeError(
            "Juno native permission result failed host semantic validation; "
            f"receipt_sha256={receipt.get('sha256')}"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "agent_id": AGENT_ID,
        "started_at": expected_started_at,
        "operation": operation,
        "capability": capability,
        "job_id": execution.get("job_id"),
        "status": status,
        "receipt": receipt,
    }


@mcp.tool(name="ipad_native_permission_status", annotations=MUTATING)
def ipad_native_permission_status(
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Read bounded native iPad permission states without reading private content."""
    operator._require_operator_capability("terminal_execute")
    return _run_native_permission_job(
        operation="status",
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
    )


@mcp.tool(name="ipad_native_permission_request", annotations=MUTATING)
def ipad_native_permission_request(
    capability: str,
    expected_started_at: str,
    session_escalation: dict[str, Any],
) -> dict[str, Any]:
    """Request one allowlisted native iPad permission and return only status readback."""
    operator._require_operator_capability("terminal_execute")
    checked = _validate_native_permission_capability(capability)
    return _run_native_permission_job(
        operation="request",
        capability=checked,
        expected_started_at=expected_started_at,
        session_escalation=session_escalation,
    )
