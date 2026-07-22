#!/usr/bin/env python3
"""Submit authenticated Python jobs to the Grabowski Juno iPad Agent."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener, urlopen

SCHEMA_VERSION = 1
DEFAULT_URL = "http://100.111.206.65:8765"
DEFAULT_SECRET_PATH = Path.home() / ".config/grabowski/secrets/juno-ipad-agent.key"
TERMINAL_STATES = {
    "succeeded",
    "failed",
    "timed_out",
    "abandoned_after_restart",
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")



def atomic_create_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_private_secret(path: Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{label} ist keine reguläre Datei")
        if metadata.st_nlink != 1:
            raise RuntimeError(f"{label} hat nicht genau einen Hardlink")
        if metadata.st_uid != os.getuid():
            raise RuntimeError(f"{label} gehört nicht dem aktuellen Benutzer")
        if metadata.st_mode & 0o077:
            raise RuntimeError(f"{label} ist für Gruppe oder andere lesbar")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


def provision_pairing_secret(
    client: "AgentClient",
    secret_path: Path,
    *,
    replace_secret: bool,
    consent_code: str,
) -> Any:
    target = secret_path.expanduser()
    pending = target.with_name(f".{target.name}.pairing-pending")
    target_exists = os.path.lexists(target)
    if target_exists and not replace_secret:
        secret = read_private_secret(target, label="bestehende Schlüsseldatei")
        if len(secret) != 32:
            raise RuntimeError("Bestehender Pairing-Schlüssel muss exakt 32 Byte lang sein")
        return client.pair(secret, consent_code)
    if target_exists:
        read_private_secret(target, label="bestehende Schlüsseldatei")
    if pending.exists():
        secret = read_private_secret(pending, label="Pairing-Pending-Datei")
    else:
        secret = secrets.token_bytes(32)
        atomic_create_bytes(pending, secret)
        fsync_directory(pending.parent)
    if len(secret) != 32:
        raise RuntimeError("Pairing-Pending-Schlüssel muss exakt 32 Byte lang sein")
    response = client.pair(secret, consent_code)
    os.replace(pending, target)
    os.chmod(target, 0o600)
    fsync_directory(target.parent)
    return response

def load_secret(path: Path) -> bytes:
    secret = read_private_secret(
        path.expanduser(),
        label="Agent-Schlüsseldatei",
    )
    if len(secret) < 32:
        raise ValueError("Agent-Schlüssel muss mindestens 32 Byte lang sein")
    return secret


def signed_headers(
    secret: bytes,
    method: str,
    path_with_query: str,
    body: bytes,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp_text = str(int(time.time()) if timestamp is None else int(timestamp))
    nonce_text = secrets.token_urlsafe(24) if nonce is None else nonce
    body_sha256 = hashlib.sha256(body).hexdigest()
    message = (
        f"{method.upper()}\n{path_with_query}\n{timestamp_text}\n"
        f"{nonce_text}\n{body_sha256}"
    ).encode("utf-8")
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "X-Grabowski-Timestamp": timestamp_text,
        "X-Grabowski-Nonce": nonce_text,
        "X-Grabowski-Body-SHA256": body_sha256,
        "X-Grabowski-Signature": signature,
    }


class AgentClient:
    def __init__(self, base_url: str, secret: bytes, network_timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.secret = secret
        self.network_timeout = network_timeout

    def request(
        self,
        method: str,
        path_with_query: str,
        document: Any | None = None,
        *,
        authenticated: bool = True,
    ) -> tuple[int, Any]:
        body = b"" if document is None else canonical_json_bytes(document)
        headers = {"Accept": "application/json"}
        if document is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        if authenticated:
            headers.update(
                signed_headers(
                    self.secret,
                    method,
                    path_with_query,
                    body,
                )
            )
        request = Request(
            f"{self.base_url}{path_with_query}",
            data=body if method.upper() in {"POST", "PUT", "PATCH"} else None,
            headers=headers,
            method=method.upper(),
        )
        opener = build_opener(ProxyHandler({}))
        try:
            with opener.open(request, timeout=self.network_timeout) as response:
                payload = response.read()
                status = response.status
        except HTTPError as exc:
            payload = exc.read()
            status = exc.code
        except URLError as exc:
            raise RuntimeError(f"Agent nicht erreichbar: {exc.reason}") from exc
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Ungültige Agent-Antwort: HTTP {status}, {payload[:200]!r}"
            ) from exc
        if status >= 400:
            raise RuntimeError(f"Agent-Fehler HTTP {status}: {parsed}")
        return status, parsed

    def health(self) -> Any:
        return self.request("GET", "/health", authenticated=False)[1]

    def pair(self, secret: bytes, consent_code: str) -> Any:
        if len(secret) != 32:
            raise ValueError("Pairing-Schlüssel muss exakt 32 Byte lang sein")
        if not (len(consent_code) == 6 and consent_code.isdigit()):
            raise ValueError("Kopplungscode muss aus sechs Ziffern bestehen")
        encoded = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
        return self.request(
            "POST",
            "/v1/pair",
            {
                "schema_version": SCHEMA_VERSION,
                "secret_b64": encoded,
                "consent_code": consent_code,
            },
            authenticated=False,
        )[1]

    def submit(
        self,
        code: str,
        *,
        timeout_seconds: int,
        metadata: dict[str, Any],
        job_id: str | None = None,
    ) -> Any:
        resolved_job_id = job_id or f"job-{uuid.uuid4()}"
        document = {
            "schema_version": SCHEMA_VERSION,
            "job_id": resolved_job_id,
            "code": code,
            "timeout_seconds": timeout_seconds,
            "metadata": metadata,
        }
        return self.request("POST", "/v1/jobs", document)[1]

    def status(self, job_id: str) -> Any:
        return self.request("GET", f"/v1/jobs/{quote(job_id, safe='')}")[1]

    def list_jobs(self, limit: int) -> Any:
        return self.request("GET", f"/v1/jobs?limit={limit}")[1]

    def shutdown(self) -> Any:
        return self.request("POST", "/v1/shutdown", {})[1]


def print_json(value: Any) -> None:
    json.dump(value, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def parse_metadata(value: str | None) -> dict[str, Any]:
    if value is None:
        return {}
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("--metadata muss ein JSON-Objekt sein")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("GRABOWSKI_JUNO_URL", DEFAULT_URL),
    )
    parser.add_argument(
        "--secret-file",
        type=Path,
        default=Path(
            os.environ.get("GRABOWSKI_JUNO_SECRET_FILE", str(DEFAULT_SECRET_PATH))
        ),
    )
    parser.add_argument("--network-timeout", type=float, default=10.0)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("health")

    pair_parser = subparsers.add_parser("pair")
    pair_parser.add_argument("--replace-secret", action="store_true")
    pair_parser.add_argument("--consent-code", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("code_file", type=Path)
    run_parser.add_argument("--job-id")
    run_parser.add_argument("--timeout", type=int, default=60)
    run_parser.add_argument("--metadata")
    run_parser.add_argument("--poll-interval", type=float, default=0.5)
    run_parser.add_argument("--no-wait", action="store_true")

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("job_id")

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--limit", type=int, default=50)

    subparsers.add_parser("shutdown")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "health":
            client = AgentClient(args.url, b"", args.network_timeout)
            print_json(client.health())
            return 0
        if args.command == "pair":
            client = AgentClient(args.url, b"", args.network_timeout)
            response = provision_pairing_secret(
                client,
                args.secret_file,
                replace_secret=args.replace_secret,
                consent_code=args.consent_code,
            )
            print_json(response)
            return 0
        secret = load_secret(args.secret_file)
        client = AgentClient(args.url, secret, args.network_timeout)
        if args.command == "status":
            print_json(client.status(args.job_id))
            return 0
        if args.command == "list":
            print_json(client.list_jobs(args.limit))
            return 0
        if args.command == "shutdown":
            print_json(client.shutdown())
            return 0
        if args.command == "run":
            code = args.code_file.read_text(encoding="utf-8")
            metadata = parse_metadata(args.metadata)
            submitted = client.submit(
                code,
                timeout_seconds=args.timeout,
                metadata=metadata,
                job_id=args.job_id,
            )
            if args.no_wait:
                print_json(submitted)
                return 0
            job_id = submitted["job_id"]
            while True:
                status = client.status(job_id)
                if status.get("state") in TERMINAL_STATES:
                    print_json(status)
                    return 0 if status.get("state") == "succeeded" else 1
                time.sleep(max(args.poll_interval, 0.05))
        raise AssertionError(f"unhandled command: {args.command}")
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
