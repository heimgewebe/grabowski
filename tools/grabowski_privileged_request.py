#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys

DEFAULT_SOCKET = Path("/run/grabowski/privileged-broker.sock")
MAX_BYTES = 512 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description="Send one privileged reference to the root broker")
    parser.add_argument("reference_file")
    parser.add_argument("--socket", default=str(DEFAULT_SOCKET))
    args = parser.parse_args()
    supplied = Path(args.reference_file).expanduser()
    if supplied.is_symlink():
        raise ValueError("reference path must not be a symlink")
    source = supplied.resolve(strict=True)
    if not source.is_file():
        raise ValueError("reference path must be a regular non-symlink file")
    payload = source.read_bytes()
    if not payload or len(payload) > 64 * 1024:
        raise ValueError("reference file is empty or exceeds the input limit")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict) or "reference_sha256" not in value:
        raise ValueError("reference file does not contain a privileged reference")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3660)
        client.connect(args.socket)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        chunks = []
        size = 0
        while True:
            chunk = client.recv(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise RuntimeError("broker response exceeds output limit")
            chunks.append(chunk)
    response = b"".join(chunks).decode("utf-8", errors="replace")
    sys.stdout.write(response)
    if response and not response.endswith("\n"):
        sys.stdout.write("\n")
    try:
        parsed = json.loads(response)
    except json.JSONDecodeError:
        return 2
    return 0 if isinstance(parsed, dict) and parsed.get("returncode") == 0 else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)
