#!/usr/bin/python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import sqlite3
import stat
import time
from pathlib import Path
import socket
import sys

DEFAULT_SOCKET = Path("/run/grabowski/privileged-broker.sock")
MAX_BYTES = 512 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\\Z")
SECRET_FD_PATH_RE = re.compile(r"/proc/self/fd/([0-9]+)\\Z")


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _session_authority(path: str) -> dict[str, object]:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError("session authority file path is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(candidate, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022
            or metadata.st_size <= 0
            or metadata.st_size > 128 * 1024
        ):
            raise PermissionError("session authority file is not private and owner-controlled")
        data = os.read(descriptor, metadata.st_size + 1)
        if len(data) != metadata.st_size:
            raise PermissionError("session authority file changed while being read")
    finally:
        os.close(descriptor)
    value = json.loads(data.decode("utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != "grabowski_secret_pty_session_authority"
    ):
        raise ValueError("session authority file is invalid")
    unsigned = dict(value)
    observed_sha256 = unsigned.pop("authority_sha256", None)
    if (
        not isinstance(observed_sha256, str)
        or SHA256_RE.fullmatch(observed_sha256) is None
        or _canonical_sha256(unsigned) != observed_sha256
    ):
        raise ValueError("session authority hash is invalid")
    return value


def _resource_db_path() -> Path:
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    return home / ".local" / "state" / "grabowski" / "resources.sqlite3"


def _validate_live_resource_leases(
    authority: dict[str, object],
    *,
    resource_db: Path | None = None,
    now: int | None = None,
) -> None:
    leases = authority.get("resource_leases")
    lease_owner = authority.get("lease_owner_id")
    authority_expiry = authority.get("expires_at_unix")
    if (
        not isinstance(leases, list)
        or not leases
        or len(leases) > 32
        or not isinstance(lease_owner, str)
        or not lease_owner
        or isinstance(authority_expiry, bool)
        or not isinstance(authority_expiry, int)
    ):
        raise PermissionError("session authority lease binding is invalid")
    keys = [item.get("resource_key") for item in leases if isinstance(item, dict)]
    if len(keys) != len(leases) or len(set(keys)) != len(keys):
        raise PermissionError("session authority lease keys are invalid")
    database = _resource_db_path() if resource_db is None else Path(resource_db)
    try:
        linked = database.lstat()
    except OSError as exc:
        raise PermissionError("resource lease database is unavailable") from exc
    if (
        database.is_symlink()
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or linked.st_mode & 0o022
    ):
        raise PermissionError("resource lease database is not owner-controlled")
    current = int(time.time()) if now is None else now
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    try:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(leases)")
        }
        required_columns = {
            "resource_key", "owner_id", "acquired_at_unix", "updated_at_unix",
            "expires_at_unix", "metadata_sha256",
        }
        if not required_columns <= columns:
            raise PermissionError("resource lease database schema is incompatible")
        for snapshot in leases:
            assert isinstance(snapshot, dict)
            resource_key = snapshot.get("resource_key")
            row = connection.execute(
                "SELECT resource_key, owner_id, acquired_at_unix, updated_at_unix, "
                "expires_at_unix, metadata_sha256 FROM leases WHERE resource_key=?",
                (resource_key,),
            ).fetchone()
            if row is None:
                raise PermissionError("required secret PTY resource lease is missing")
            observed = dict(row)
            expected = {
                key: snapshot.get(key)
                for key in required_columns
            }
            if observed != expected or observed["owner_id"] != lease_owner:
                raise PermissionError("secret PTY resource lease changed or is foreign")
            if (
                observed["expires_at_unix"] <= current
                or observed["expires_at_unix"] < authority_expiry
            ):
                raise PermissionError("secret PTY resource lease is stale")
    finally:
        connection.close()


def _secret_transport_envelope(reference: dict[str, object], fd_path: str, secret_sha256: str, session_authority: dict[str, object]) -> bytes:
    match = SECRET_FD_PATH_RE.fullmatch(fd_path)
    if match is None or int(match.group(1)) < 3:
        raise ValueError("secret fd path must name an inherited descriptor")
    if SHA256_RE.fullmatch(secret_sha256) is None:
        raise ValueError("secret SHA-256 is invalid")
    envelope: dict[str, object] = {
        "schema_version": 1,
        "kind": "grabowski_privileged_transport",
        "reference": reference,
        "secret_fd": int(match.group(1)),
        "secret_sha256": secret_sha256,
        "session_authority": session_authority,
    }
    envelope["transport_sha256"] = _canonical_sha256(envelope)
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _response_succeeded(parsed: object) -> bool:
    if not isinstance(parsed, dict):
        return False
    if parsed.get("mode") == "secret-pty":
        return (
            parsed.get("outcome") == "COMPLETED"
            and parsed.get("returncode") == 0
            and parsed.get("readback_required") is False
            and parsed.get("timed_out") is False
        )
    return parsed.get("returncode") == 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Send one privileged reference to the root broker")
    parser.add_argument("reference_file")
    parser.add_argument("--socket", default=str(DEFAULT_SOCKET))
    parser.add_argument("--secret-fd-path")
    parser.add_argument("--secret-sha256")
    parser.add_argument("--session-authority-file")
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
    supplied = (
        args.secret_fd_path is not None,
        args.secret_sha256 is not None,
        args.session_authority_file is not None,
    )
    if any(supplied) and not all(supplied):
        raise ValueError("secret fd path, SHA-256 and session authority must be supplied together")
    authority: dict[str, object] | None = None
    if args.secret_fd_path is not None:
        authority = _session_authority(args.session_authority_file)
        _validate_live_resource_leases(authority)
        if authority.get("action") != value.get("action"):
            raise PermissionError("session authority action does not match privileged reference")
        payload = _secret_transport_envelope(
            value, args.secret_fd_path, args.secret_sha256, authority
        )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3660)
        client.connect(args.socket)
        if authority is not None:
            _validate_live_resource_leases(authority)
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
    return 0 if _response_succeeded(parsed) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        raise SystemExit(2)