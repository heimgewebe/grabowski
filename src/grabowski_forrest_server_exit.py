from __future__ import annotations

import hashlib
import json
import re
import subprocess
from typing import Any

SSH = "/usr/bin/ssh"
HOST = "wg-prod-1"
EXPECTED_443 = "http://127.0.0.1:18000"
PRESERVED_8443 = "http://127.0.0.1:18090"
SSH_PREFIX = [
    SSH,
    "-o",
    "BatchMode=yes",
    "-o",
    "ClearAllForwardings=yes",
    "-o",
    "ConnectTimeout=10",
    "--",
    HOST,
]
_HEADER = re.compile(r"^https://(?P<host>[^ ]+) \(Funnel on\)$")
_PROXY = re.compile(r"^\|-- / proxy (?P<target>http://127\.0\.0\.1:\d+)$")


def _run_remote(argv: list[str]) -> subprocess.CompletedProcess[str]:
    if not argv or any(not isinstance(part, str) or not part for part in argv):
        raise RuntimeError("invalid fixed remote argv")
    return subprocess.run(
        [*SSH_PREFIX, *argv],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> str:
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with returncode {result.returncode}")
    return result.stdout


def _route_port(host: str) -> int:
    authority = host.rsplit("@", 1)[-1]
    if ":" not in authority:
        return 443
    port_text = authority.rsplit(":", 1)[-1]
    try:
        return int(port_text)
    except ValueError as exc:
        raise RuntimeError("unexpected Tailscale serve authority") from exc


def _parse_serve_status(text: str) -> dict[int, str]:
    routes: dict[int, str] = {}
    lines = [line.strip() for line in text.splitlines()]
    for index, line in enumerate(lines):
        match = _HEADER.fullmatch(line)
        if match is None:
            continue
        target = None
        for child in lines[index + 1 : index + 4]:
            proxy = _PROXY.fullmatch(child)
            if proxy is not None:
                target = proxy.group("target")
                break
            if child.startswith("https://"):
                break
        if target is None:
            raise RuntimeError("Tailscale serve route lacks exact proxy target")
        port = _route_port(match.group("host"))
        if port in routes:
            raise RuntimeError(f"duplicate Tailscale serve port {port}")
        routes[port] = target
    if not routes:
        raise RuntimeError("no Tailscale serve routes parsed")
    return routes


def _listen_ports(text: str) -> set[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        local = fields[3] if len(fields) > 3 else fields[-1]
        match = re.search(r":(?P<port>\d+)$", local)
        if match:
            ports.add(int(match.group("port")))
    return ports


def _observe() -> dict[str, Any]:
    serve = _require_success(_run_remote(["tailscale", "serve", "status"]), "serve status")
    sockets = _require_success(_run_remote(["ss", "-ltnH"]), "socket status")
    routes = _parse_serve_status(serve)
    listening = _listen_ports(sockets)
    safe = {
        "routes": {str(port): target for port, target in sorted(routes.items())},
        "port18000Listening": 18000 in listening,
        "port18090Listening": 18090 in listening,
    }
    safe["stateSha256"] = hashlib.sha256(
        json.dumps(safe, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return safe


def _validate_pre(state: dict[str, Any]) -> None:
    routes = state["routes"]
    if routes.get("443") != EXPECTED_443:
        raise RuntimeError("Forrest 443 route precondition mismatch")
    if routes.get("8443") != PRESERVED_8443:
        raise RuntimeError("protected 8443 route precondition mismatch")
    if state["port18000Listening"] is not False:
        raise RuntimeError("Forrest backend port 18000 must already be closed")
    if state["port18090Listening"] is not True:
        raise RuntimeError("protected backend port 18090 is not listening")


def _validate_post(before: dict[str, Any], after: dict[str, Any]) -> None:
    before_routes = dict(before["routes"])
    after_routes = dict(after["routes"])
    if "443" in after_routes:
        raise RuntimeError("Forrest 443 route still present")
    expected_remaining = {key: value for key, value in before_routes.items() if key != "443"}
    if after_routes != expected_remaining:
        raise RuntimeError("non-Forrest Tailscale serve routes changed")
    if after_routes.get("8443") != PRESERVED_8443:
        raise RuntimeError("protected 8443 route changed")
    if after["port18000Listening"] is not False:
        raise RuntimeError("Forrest backend port 18000 reopened")
    if after["port18090Listening"] is not True:
        raise RuntimeError("protected backend port 18090 changed")


def apply() -> dict[str, Any]:
    before = _observe()
    _validate_pre(before)
    mutation = _run_remote(["tailscale", "serve", "--https=443", "off"])
    if mutation.returncode != 0:
        raise RuntimeError(f"fixed Tailscale 443 removal failed with returncode {mutation.returncode}")
    after = _observe()
    _validate_post(before, after)
    return {
        "ok": True,
        "fixedHost": HOST,
        "removedHttpsPort": 443,
        "removedProxyTarget": EXPECTED_443,
        "preservedHttpsPort": 8443,
        "preservedProxyTarget": PRESERVED_8443,
        "before": before,
        "after": after,
        "providerMutationPerformed": True,
    }
