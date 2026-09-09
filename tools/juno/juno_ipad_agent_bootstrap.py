#!/usr/bin/env python3
"""Duplicate-safe local bootstrap for the Grabowski Juno iPad Agent.

This file is intended as the target of a Juno/Shortcuts "Run Python File"
action. It starts the sibling agent only when the canonical local health
endpoint is definitely absent. Ambiguous health failures fail closed so a
second server is never started on top of a possibly wedged first instance.
"""

from __future__ import annotations

import errno
import http.client
import json
from pathlib import Path
import runpy
import socket
import sys
import time
from typing import Literal


HOST = "127.0.0.1"
PORT = 8765
HEALTH_PATH = "/health"
EXPECTED_SERVICE = "grabowski-juno-ipad-agent"
MAX_HEALTH_BYTES = 64 * 1024
PROBE_TIMEOUT_SECONDS = 0.75
PROBE_ATTEMPTS = 3
PROBE_DELAY_SECONDS = 0.25

ProbeState = Literal["healthy", "absent", "ambiguous"]


def _probe_once() -> tuple[ProbeState, str]:
    connection = http.client.HTTPConnection(HOST, PORT, timeout=PROBE_TIMEOUT_SECONDS)
    try:
        connection.request(
            "GET",
            HEALTH_PATH,
            headers={"Accept": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        payload = response.read(MAX_HEALTH_BYTES + 1)
    except ConnectionRefusedError:
        return "absent", "connection refused"
    except (TimeoutError, socket.timeout):
        return "ambiguous", "health request timed out"
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            return "absent", "connection refused"
        return "ambiguous", f"health request failed: {type(exc).__name__}"
    finally:
        connection.close()

    if response.status != 200:
        return "ambiguous", f"unexpected health HTTP status {response.status}"
    if len(payload) > MAX_HEALTH_BYTES:
        return "ambiguous", "health response exceeds bounded size"
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "ambiguous", "health response is not valid JSON"
    if not isinstance(document, dict):
        return "ambiguous", "health response is not an object"
    if document.get("service") != EXPECTED_SERVICE:
        return "ambiguous", "another service owns the canonical port"
    if document.get("status") != "ok":
        return "ambiguous", "Juno agent health is not ok"
    return "healthy", "Juno agent already healthy"


def _probe() -> tuple[ProbeState, str]:
    detail = "connection refused"
    for attempt in range(PROBE_ATTEMPTS):
        state, detail = _probe_once()
        if state != "absent":
            return state, detail
        if attempt + 1 < PROBE_ATTEMPTS:
            time.sleep(PROBE_DELAY_SECONDS)
    return "absent", detail


def _run_agent(agent_path: Path | None = None) -> None:
    path = agent_path or Path(__file__).with_name("juno_ipad_agent.py")
    if not path.is_file():
        raise RuntimeError(f"Juno agent sibling is missing: {path.name}")
    previous_argv = sys.argv[:]
    try:
        sys.argv = [str(path)]
        namespace = runpy.run_path(
            str(path),
            run_name="grabowski_juno_ipad_agent_recovery_target",
        )
        agent_main = namespace.get("main")
        if not callable(agent_main):
            raise RuntimeError("Juno agent sibling does not expose main()")
        result = agent_main()
        if result not in (None, 0):
            raise RuntimeError(f"Juno agent exited with status {result}")
    finally:
        sys.argv = previous_argv


def main() -> int:
    state, detail = _probe()
    if state == "healthy":
        print("Grabowski Juno iPad Agent läuft bereits; kein Neustart nötig.")
        return 0
    if state == "ambiguous":
        print(
            "Juno-Agent-Zustand ist mehrdeutig; keine zweite Instanz wird gestartet: "
            f"{detail}",
            file=sys.stderr,
        )
        return 2

    print("Kein Juno-Agent auf 127.0.0.1:8765; starte die kanonische Instanz …")
    _run_agent()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
