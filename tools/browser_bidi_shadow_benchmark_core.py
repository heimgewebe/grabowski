"""Fail-closed WebDriver BiDi shadow benchmark support.

This module is deliberately not a production browser adapter.  It exists to
measure an isolated Firefox/WebDriver BiDi path against a caller-supplied
semantic reference without changing Grabowski's canonical Chrome/CDP browser
control plane.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import signal
import secrets
import socket
import struct
import subprocess
import tempfile
import time
from typing import Any
from urllib.parse import quote, urlsplit


SCHEMA_VERSION = 1
MAX_HTTP_BYTES = 1_048_576
MAX_WEBSOCKET_BYTES = 1_048_576
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFAULT_HTML = (
    "<main><button>Wave B semantic target</button>"
    "<p>BiDi shadow benchmark</p></main>"
)
DEFAULT_REFERENCE = {
    "ready_state": "complete",
    "elements": [{"role": "button", "name": "Wave B semantic target"}],
}


class BidiShadowError(RuntimeError):
    """Raised when shadow evidence cannot be established safely."""


def _sha256_json(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_loopback_ws_url(
    value: str, *, expected_session_id: str, expected_port: int
) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise BidiShadowError("BiDi WebSocket URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "ws"
        or not parsed.hostname
        or not _is_loopback_host(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise BidiShadowError("BiDi WebSocket URL is not a strict loopback URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BidiShadowError("BiDi WebSocket port is invalid") from exc
    if port != expected_port:
        raise BidiShadowError("BiDi WebSocket port does not match the bound port")
    expected_path = f"/session/{expected_session_id}"
    if parsed.path != expected_path:
        raise BidiShadowError("BiDi WebSocket session path does not match")
    return value


def build_geckodriver_argv(
    *,
    geckodriver: Path,
    firefox: Path,
    http_port: int,
    websocket_port: int,
    profile_root: Path,
) -> list[str]:
    if http_port == websocket_port:
        raise BidiShadowError("WebDriver HTTP and BiDi WebSocket ports must differ")
    for port in (http_port, websocket_port):
        if isinstance(port, bool) or not 1024 <= port <= 65535:
            raise BidiShadowError("benchmark port is outside the allowed range")
    return [
        str(geckodriver),
        "--host",
        "127.0.0.1",
        "--port",
        str(http_port),
        "--websocket-port",
        str(websocket_port),
        "--binary",
        str(firefox),
        "--profile-root",
        str(profile_root),
        "-vv",
    ]


def build_session_payload() -> dict[str, Any]:
    return {
        "capabilities": {
            "alwaysMatch": {
                "browserName": "firefox",
                "webSocketUrl": True,
                "moz:firefoxOptions": {"args": ["-headless"]},
            }
        }
    }


def parse_session_response(
    document: dict[str, Any], *, expected_websocket_port: int
) -> dict[str, str]:
    try:
        value = document["value"]
        session_id = value["sessionId"]
        capabilities = value["capabilities"]
        websocket_url = capabilities["webSocketUrl"]
        browser_version = capabilities["browserVersion"]
        geckodriver_version = capabilities["moz:geckodriverVersion"]
    except (KeyError, TypeError) as exc:
        raise BidiShadowError("WebDriver session response is incomplete") from exc
    for name, field in (
        ("session id", session_id),
        ("browser version", browser_version),
        ("geckodriver version", geckodriver_version),
    ):
        if not isinstance(field, str) or not field:
            raise BidiShadowError(f"WebDriver {name} is invalid")
    validate_loopback_ws_url(
        websocket_url,
        expected_session_id=session_id,
        expected_port=expected_websocket_port,
    )
    return {
        "session_id": session_id,
        "websocket_url": websocket_url,
        "browser_version": browser_version,
        "geckodriver_version": geckodriver_version,
    }


def normalize_semantic_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BidiShadowError("semantic observation is not an object")
    ready_state = value.get("readyState", value.get("ready_state"))
    elements = value.get("elements")
    if not isinstance(ready_state, str) or not isinstance(elements, list):
        raise BidiShadowError("semantic observation is incomplete")
    normalized_elements: list[dict[str, str]] = []
    for item in elements:
        if not isinstance(item, dict):
            raise BidiShadowError("semantic element is not an object")
        role = item.get("role")
        name = item.get("name")
        if not isinstance(role, str) or not isinstance(name, str):
            raise BidiShadowError("semantic element role/name is invalid")
        normalized_elements.append({"role": role, "name": name})
    return {"ready_state": ready_state, "elements": normalized_elements}


def compare_semantics(
    reference: dict[str, Any], observed: dict[str, Any]
) -> dict[str, Any]:
    left = normalize_semantic_observation(reference)
    right = normalize_semantic_observation(observed)
    mismatches: list[str] = []
    if left["ready_state"] != right["ready_state"]:
        mismatches.append("ready_state")
    if left["elements"] != right["elements"]:
        mismatches.append("elements")
    return {
        "matched": not mismatches,
        "mismatches": mismatches,
        "reference_sha256": _sha256_json(left),
        "observed_sha256": _sha256_json(right),
    }


def _http_json(
    method: str,
    port: int,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    body = None
    headers: dict[str, str] = {}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_seconds)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_HTTP_BYTES + 1)
    finally:
        connection.close()
    if len(raw) > MAX_HTTP_BYTES:
        raise BidiShadowError("WebDriver response exceeds bounded size")
    if not 200 <= response.status < 300:
        detail = ""
        try:
            error_document = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            error_document = {}
        if isinstance(error_document, dict):
            error_value = error_document.get("value")
            if isinstance(error_value, dict):
                error_name = error_value.get("error")
                error_message = error_value.get("message")
                parts = [
                    field[:300]
                    for field in (error_name, error_message)
                    if isinstance(field, str) and field
                ]
                if parts:
                    detail = ": " + " - ".join(parts)
        raise BidiShadowError(
            f"WebDriver HTTP returned status {response.status}{detail}"
        )
    if not raw:
        return {}
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BidiShadowError("WebDriver response is not JSON") from exc
    if not isinstance(document, dict):
        raise BidiShadowError("WebDriver response is not an object")
    return document


def _read_http_upgrade(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise BidiShadowError("BiDi WebSocket closed during handshake")
        data.extend(chunk)
        if len(data) > 65536:
            raise BidiShadowError("BiDi WebSocket handshake exceeds bounded size")
    header, remainder = bytes(data).split(b"\r\n\r\n", 1)
    if remainder:
        raise BidiShadowError("unexpected WebSocket payload during handshake")
    return header


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise BidiShadowError("BiDi WebSocket closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def _send_frame(sock: socket.socket, opcode: int, payload: bytes) -> None:
    if len(payload) > MAX_WEBSOCKET_BYTES:
        raise BidiShadowError("BiDi WebSocket payload exceeds bounded size")
    mask = secrets.token_bytes(4)
    length = len(payload)
    first = 0x80 | opcode
    if length < 126:
        header = bytes((first, 0x80 | length))
    elif length <= 0xFFFF:
        header = bytes((first, 0x80 | 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 0x80 | 127)) + struct.pack("!Q", length)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(header + mask + masked)


def _recv_frame(sock: socket.socket) -> tuple[bool, int, bytes]:
    first, second = _recv_exact(sock, 2)
    final = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if masked:
        raise BidiShadowError("server sent an invalid masked WebSocket frame")
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if length > MAX_WEBSOCKET_BYTES:
        raise BidiShadowError("BiDi WebSocket frame exceeds bounded size")
    return final, opcode, _recv_exact(sock, length)


class BidiJsonConnection:
    def __init__(self, websocket_url: str, *, timeout_seconds: float = 5.0):
        self.websocket_url = websocket_url
        self.timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None
        self._next_id = 1

    def __enter__(self) -> "BidiJsonConnection":
        parsed = urlsplit(self.websocket_url)
        if parsed.scheme != "ws" or not parsed.hostname or parsed.port is None:
            raise BidiShadowError("BiDi WebSocket URL is invalid")
        if not _is_loopback_host(parsed.hostname):
            raise BidiShadowError("BiDi WebSocket host is not loopback")
        sock = socket.create_connection(
            (parsed.hostname, parsed.port), timeout=self.timeout_seconds
        )
        sock.settimeout(self.timeout_seconds)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        host_header = f"{parsed.hostname}:{parsed.port}"
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(request)
        header = _read_http_upgrade(sock).decode("iso-8859-1")
        lines = header.split("\r\n")
        if not lines or " 101 " not in f" {lines[0]} ":
            sock.close()
            raise BidiShadowError("BiDi WebSocket upgrade was rejected")
        fields: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, field = line.split(":", 1)
            fields[name.strip().lower()] = field.strip()
        expected_accept = base64.b64encode(
            hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if fields.get("sec-websocket-accept") != expected_accept:
            sock.close()
            raise BidiShadowError("BiDi WebSocket accept hash does not match")
        self._socket = sock
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._socket is not None:
            try:
                _send_frame(self._socket, 0x8, b"")
            except OSError:
                pass
            self._socket.close()
            self._socket = None

    def _receive_text(self) -> str:
        if self._socket is None:
            raise BidiShadowError("BiDi WebSocket is not connected")
        fragments = bytearray()
        active = False
        while True:
            final, opcode, payload = _recv_frame(self._socket)
            if opcode == 0x8:
                raise BidiShadowError("BiDi WebSocket closed")
            if opcode == 0x9:
                _send_frame(self._socket, 0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x1:
                if active:
                    raise BidiShadowError("unexpected nested WebSocket text frame")
                active = True
                fragments.extend(payload)
            elif opcode == 0x0 and active:
                fragments.extend(payload)
            else:
                raise BidiShadowError("unexpected BiDi WebSocket opcode")
            if len(fragments) > MAX_WEBSOCKET_BYTES:
                raise BidiShadowError("BiDi WebSocket message exceeds bounded size")
            if final:
                try:
                    return fragments.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise BidiShadowError("BiDi WebSocket message is not UTF-8") from exc

    def call(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], float]:
        if self._socket is None:
            raise BidiShadowError("BiDi WebSocket is not connected")
        message_id = self._next_id
        self._next_id += 1
        payload = json.dumps(
            {"id": message_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        started = time.perf_counter_ns()
        _send_frame(self._socket, 0x1, payload)
        while True:
            try:
                response = json.loads(self._receive_text())
            except json.JSONDecodeError as exc:
                raise BidiShadowError("BiDi response is not JSON") from exc
            if not isinstance(response, dict):
                raise BidiShadowError("BiDi response is not an object")
            if response.get("id") != message_id:
                continue
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            if response.get("type") == "error" or "error" in response:
                raise BidiShadowError(
                    f"BiDi command {method} failed: {response.get('error', 'unknown')}"
                )
            if "result" not in response:
                raise BidiShadowError(f"BiDi command {method} has no result")
            return response, elapsed_ms


def _wait_for_driver(port: int, process: subprocess.Popen[Any], timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not ready"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise BidiShadowError(
                f"geckodriver exited before readiness with code {process.returncode}"
            )
        try:
            document = _http_json("GET", port, "/status", timeout_seconds=0.5)
            if isinstance(document.get("value"), dict):
                return
        except (BidiShadowError, OSError, http.client.HTTPException) as exc:
            last_error = str(exc)
        time.sleep(0.05)
    raise BidiShadowError(f"geckodriver readiness timed out: {last_error}")


def _semantic_expression() -> str:
    return (
        "JSON.stringify({readyState:document.readyState,elements:"
        "[...document.querySelectorAll('button')].map(el=>({"
        "role:el.getAttribute('role')||'button',"
        "name:(el.innerText||'').trim()}))})"
    )


def _parse_evaluate_response(response: dict[str, Any]) -> dict[str, Any]:
    try:
        remote_value = response["result"]["result"]
        if remote_value.get("type") != "string":
            raise BidiShadowError("BiDi semantic result is not a string")
        serialized = remote_value["value"]
        decoded = json.loads(serialized)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise BidiShadowError("BiDi semantic result is invalid") from exc
    return normalize_semantic_observation(decoded)


def run_shadow_benchmark(
    *,
    geckodriver: Path,
    firefox: Path,
    http_port: int,
    websocket_port: int,
    work_root: Path,
    reference: dict[str, Any] | None = None,
    html: str = DEFAULT_HTML,
    readiness_timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    reference = DEFAULT_REFERENCE if reference is None else reference
    for label, executable in (("geckodriver", geckodriver), ("firefox", firefox)):
        if not executable.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
            raise BidiShadowError(f"{label} executable is unavailable")
    if not work_root.is_absolute() or not work_root.is_dir():
        raise BidiShadowError("benchmark work root is unavailable")

    started = time.perf_counter_ns()
    session_id: str | None = None
    process: subprocess.Popen[Any] | None = None
    log_path: Path | None = None
    timings: dict[str, float] = {}
    session_identity: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="grabowski-bidi-shadow-", dir=work_root) as temporary:
        root = Path(temporary)
        profile_root = root / "profiles"
        profile_root.mkdir(mode=0o700)
        log_path = root / "geckodriver.log"
        argv = build_geckodriver_argv(
            geckodriver=geckodriver,
            firefox=firefox,
            http_port=http_port,
            websocket_port=websocket_port,
            profile_root=profile_root,
        )
        with log_path.open("wb") as log_file:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=True,
                start_new_session=True,
            )
            try:
                ready_started = time.perf_counter_ns()
                _wait_for_driver(http_port, process, readiness_timeout_seconds)
                timings["driver_ready_ms"] = (
                    time.perf_counter_ns() - ready_started
                ) / 1_000_000

                session_started = time.perf_counter_ns()
                session_document = _http_json(
                    "POST",
                    http_port,
                    "/session",
                    payload=build_session_payload(),
                    timeout_seconds=readiness_timeout_seconds,
                )
                timings["session_create_ms"] = (
                    time.perf_counter_ns() - session_started
                ) / 1_000_000
                session_identity = parse_session_response(
                    session_document, expected_websocket_port=websocket_port
                )
                session_id = session_identity["session_id"]

                target_url = "data:text/html," + quote(html, safe="")
                with BidiJsonConnection(session_identity["websocket_url"]) as bidi:
                    tree, tree_ms = bidi.call(
                        "browsingContext.getTree", {"maxDepth": 0}
                    )
                    contexts = tree["result"].get("contexts")
                    if not isinstance(contexts, list) or len(contexts) != 1:
                        raise BidiShadowError(
                            "BiDi benchmark requires exactly one top-level context"
                        )
                    context = contexts[0].get("context")
                    if not isinstance(context, str) or not context:
                        raise BidiShadowError("BiDi browsing context is invalid")
                    navigation, navigate_ms = bidi.call(
                        "browsingContext.navigate",
                        {"context": context, "url": target_url, "wait": "complete"},
                    )
                    navigation_url = navigation["result"].get("url")
                    if navigation_url != target_url:
                        raise BidiShadowError("BiDi navigation readback does not match")
                    evaluation, evaluate_ms = bidi.call(
                        "script.evaluate",
                        {
                            "expression": _semantic_expression(),
                            "target": {"context": context},
                            "awaitPromise": True,
                            "resultOwnership": "none",
                        },
                    )
                timings.update(
                    {
                        "get_tree_ms": tree_ms,
                        "navigate_ms": navigate_ms,
                        "evaluate_ms": evaluate_ms,
                    }
                )
                observation = _parse_evaluate_response(evaluation)
                parity = compare_semantics(reference, observation)
                return {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "grabowski_browser_bidi_shadow_benchmark",
                    "state": "passed" if parity["matched"] else "semantic_mismatch",
                    "transport": "webdriver-bidi",
                    "production_adapter_changed": False,
                    "browser": {
                        "name": "firefox",
                        "version": session_identity["browser_version"],
                    },
                    "driver": {
                        "name": "geckodriver",
                        "version": session_identity["geckodriver_version"],
                    },
                    "binding": {
                        "http_host": "127.0.0.1",
                        "http_port": http_port,
                        "websocket_host": "127.0.0.1",
                        "websocket_port": websocket_port,
                        "session_id_sha256": hashlib.sha256(
                            session_id.encode("utf-8")
                        ).hexdigest(),
                    },
                    "semantic_observation": observation,
                    "parity": parity,
                    "timings_ms": {key: round(value, 3) for key, value in timings.items()},
                    "total_ms": round(
                        (time.perf_counter_ns() - started) / 1_000_000, 3
                    ),
                    "retry_authorized": False,
                    "does_not_establish": [
                        "production_adapter_parity",
                        "production_default_suitability",
                        "general_accessibility_tree_parity",
                        "permission_to_replace_chrome_cdp",
                        "external_effect_correctness",
                        "resource_lease_ownership",
                    ],
                }
            finally:
                if session_id is not None:
                    try:
                        _http_json(
                            "DELETE",
                            http_port,
                            f"/session/{session_id}",
                            timeout_seconds=3.0,
                        )
                    except Exception:
                        pass
                _terminate_process_group(process)


def _terminate_process_group(
    process: subprocess.Popen[Any], *, grace_seconds: float = 3.0
) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=grace_seconds)


def failure_report(exc: BaseException) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_browser_bidi_shadow_benchmark",
        "state": "failed_closed",
        "error_class": exc.__class__.__name__,
        "reason": str(exc)[:500],
        "production_adapter_changed": False,
        "retry_authorized": False,
        "does_not_establish": [
            "transport_unavailability_is_permanent",
            "production_adapter_parity",
            "permission_to_replace_chrome_cdp",
            "resource_lease_ownership",
        ],
    }
