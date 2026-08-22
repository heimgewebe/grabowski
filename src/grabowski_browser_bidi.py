from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import socket
import struct
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MAX_HTTP_BYTES = 1_048_576
MAX_WEBSOCKET_BYTES = 1_048_576
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class BrowserBidiError(RuntimeError):
    pass


def _http_json(method: str, port: int, path: str, *, payload: dict[str, Any] | None = None, timeout_seconds: float = 5.0) -> dict[str, Any]:
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
        raise BrowserBidiError("WebDriver response exceeds bounded size")
    if not 200 <= response.status < 300:
        raise BrowserBidiError(f"WebDriver HTTP returned status {response.status}")
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserBidiError("WebDriver response is not JSON") from exc
    if not isinstance(value, dict):
        raise BrowserBidiError("WebDriver response is not an object")
    return value


def cdp_endpoint_ready(port: int, *, timeout_seconds: float = 3.0) -> bool:
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise BrowserBidiError("CDP readiness port is outside the allowed range")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/json/version")
            response = connection.getresponse()
            raw = response.read(65537)
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
            continue
        finally:
            connection.close()
        if response.status != 200 or len(raw) > 65536:
            time.sleep(0.05)
            continue
        try:
            document = json.loads(raw)
            websocket_url = document["webSocketDebuggerUrl"]
        except (json.JSONDecodeError, KeyError, TypeError):
            time.sleep(0.05)
            continue
        if not isinstance(websocket_url, str):
            time.sleep(0.05)
            continue
        parsed = urlsplit(websocket_url)
        try:
            websocket_port = parsed.port
        except ValueError:
            websocket_port = None
        if (
            parsed.scheme == "ws"
            and parsed.hostname == "127.0.0.1"
            and websocket_port == port
            and parsed.username is None
            and parsed.password is None
            and parsed.path.startswith("/devtools/browser/")
            and not parsed.query
            and not parsed.fragment
        ):
            return True
        time.sleep(0.05)
    return False


def driver_ready(port: int, *, timeout_seconds: float = 8.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "not ready"
    while time.monotonic() < deadline:
        try:
            document = _http_json("GET", port, "/status", timeout_seconds=0.5)
            if isinstance(document.get("value"), dict):
                return
        except (BrowserBidiError, OSError, http.client.HTTPException) as exc:
            last_error = str(exc)
        time.sleep(0.05)
    raise BrowserBidiError(f"ChromeDriver readiness timed out: {last_error}")


def chrome_session_payload(*, chrome: Path, profile: Path, args: list[str]) -> dict[str, Any]:
    return {
        "capabilities": {
            "alwaysMatch": {
                "browserName": "chrome",
                "webSocketUrl": True,
                "goog:chromeOptions": {
                    "binary": str(chrome),
                    "args": ["--no-first-run", "--no-default-browser-check", f"--user-data-dir={profile}", *args],
                },
            }
        }
    }


def _validate_chrome_ws(value: str, *, expected_session_id: str, expected_port: int) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BrowserBidiError("Chrome BiDi WebSocket URL is not loopback-only")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BrowserBidiError("Chrome BiDi WebSocket port is invalid") from exc
    if (
        port is None
        or port != expected_port
        or not 1024 <= port <= 65535
        or parsed.path != f"/session/{expected_session_id}"
    ):
        raise BrowserBidiError("Chrome BiDi WebSocket identity mismatch")
    resolved = socket.getaddrinfo(parsed.hostname, port, socket.AF_INET, socket.SOCK_STREAM)
    addresses = {item[4][0] for item in resolved if item[4]}
    if addresses != {"127.0.0.1"}:
        raise BrowserBidiError("Chrome BiDi WebSocket host is not strict IPv4 loopback")
    return urlunsplit(("ws", f"127.0.0.1:{port}", parsed.path, "", ""))


def create_chrome_session(*, port: int, chrome: Path, profile: Path, args: list[str], timeout_seconds: float = 8.0) -> dict[str, str]:
    document = _http_json("POST", port, "/session", payload=chrome_session_payload(chrome=chrome, profile=profile, args=args), timeout_seconds=timeout_seconds)
    try:
        value = document["value"]
        session_id = value["sessionId"]
        capabilities = value["capabilities"]
        websocket_url = capabilities["webSocketUrl"]
        browser_version = capabilities["browserVersion"]
        driver_version = capabilities["chrome"]["chromedriverVersion"].split()[0]
    except (KeyError, TypeError, AttributeError) as exc:
        raise BrowserBidiError("Chrome WebDriver session response is incomplete") from exc
    if not all(isinstance(item, str) and item for item in (session_id, websocket_url, browser_version, driver_version)):
        raise BrowserBidiError("Chrome WebDriver session identity is invalid")
    return {
        "session_id": session_id,
        "websocket_url": _validate_chrome_ws(websocket_url, expected_session_id=session_id, expected_port=port),
        "browser_version": browser_version,
        "driver_version": driver_version,
    }


def delete_session(port: int, session_id: str, *, timeout_seconds: float = 3.0) -> None:
    _http_json("DELETE", port, f"/session/{session_id}", timeout_seconds=timeout_seconds)


def _read_http_upgrade(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise BrowserBidiError("BiDi WebSocket closed during handshake")
        data.extend(chunk)
        if len(data) > 65536:
            raise BrowserBidiError("BiDi WebSocket handshake exceeds bounded size")
    header, remainder = bytes(data).split(b"\r\n\r\n", 1)
    if remainder:
        raise BrowserBidiError("unexpected WebSocket payload during handshake")
    return header


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise BrowserBidiError("BiDi WebSocket closed unexpectedly")
        data.extend(chunk)
    return bytes(data)


def _send_frame(sock: socket.socket, opcode: int, payload: bytes) -> None:
    if len(payload) > MAX_WEBSOCKET_BYTES:
        raise BrowserBidiError("BiDi WebSocket payload exceeds bounded size")
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
    if second & 0x80:
        raise BrowserBidiError("server sent an invalid masked WebSocket frame")
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if length > MAX_WEBSOCKET_BYTES:
        raise BrowserBidiError("BiDi WebSocket frame exceeds bounded size")
    return final, opcode, _recv_exact(sock, length)


class BidiJsonConnection:
    def __init__(self, websocket_url: str, *, timeout_seconds: float = 5.0):
        self.websocket_url = websocket_url
        self.timeout_seconds = timeout_seconds
        self._socket: socket.socket | None = None
        self._next_id = 1

    def __enter__(self) -> "BidiJsonConnection":
        parsed = urlsplit(self.websocket_url)
        if parsed.scheme != "ws" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise BrowserBidiError("BiDi WebSocket URL is invalid")
        sock = socket.create_connection((parsed.hostname, parsed.port), timeout=self.timeout_seconds)
        sock.settimeout(self.timeout_seconds)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode("ascii")
        sock.sendall(request)
        header = _read_http_upgrade(sock).decode("iso-8859-1")
        lines = header.split("\r\n")
        if not lines or " 101 " not in f" {lines[0]} ":
            sock.close(); raise BrowserBidiError("BiDi WebSocket upgrade was rejected")
        fields: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                name, field = line.split(":", 1); fields[name.strip().lower()] = field.strip()
        expected = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        if fields.get("sec-websocket-accept") != expected:
            sock.close(); raise BrowserBidiError("BiDi WebSocket accept hash does not match")
        self._socket = sock
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._socket is not None:
            try: _send_frame(self._socket, 0x8, b"")
            except OSError: pass
            self._socket.close(); self._socket = None

    def _receive_text(self) -> str:
        if self._socket is None:
            raise BrowserBidiError("BiDi WebSocket is not connected")
        fragments = bytearray(); active = False
        while True:
            final, opcode, payload = _recv_frame(self._socket)
            if opcode == 0x8: raise BrowserBidiError("BiDi WebSocket closed")
            if opcode == 0x9: _send_frame(self._socket, 0xA, payload); continue
            if opcode == 0xA: continue
            if opcode == 0x1:
                if active: raise BrowserBidiError("unexpected nested WebSocket text frame")
                active = True; fragments.extend(payload)
            elif opcode == 0x0 and active: fragments.extend(payload)
            else: raise BrowserBidiError("unexpected BiDi WebSocket opcode")
            if len(fragments) > MAX_WEBSOCKET_BYTES: raise BrowserBidiError("BiDi WebSocket message exceeds bounded size")
            if final:
                try: return fragments.decode("utf-8")
                except UnicodeDecodeError as exc: raise BrowserBidiError("BiDi WebSocket message is not UTF-8") from exc

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._socket is None: raise BrowserBidiError("BiDi WebSocket is not connected")
        message_id = self._next_id; self._next_id += 1
        _send_frame(self._socket, 0x1, json.dumps({"id": message_id, "method": method, "params": params}, separators=(",", ":")).encode("utf-8"))
        while True:
            try: response = json.loads(self._receive_text())
            except json.JSONDecodeError as exc: raise BrowserBidiError("BiDi response is not JSON") from exc
            if not isinstance(response, dict): raise BrowserBidiError("BiDi response is not an object")
            if response.get("id") != message_id: continue
            if response.get("type") == "error" or "error" in response:
                raise BrowserBidiError(f"BiDi command {method} failed")
            result = response.get("result")
            if not isinstance(result, dict): raise BrowserBidiError(f"BiDi command {method} has no result")
            return result
