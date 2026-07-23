#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Sequence

DEFAULT_SOPS = Path.home() / ".local/bin/sops"
DEFAULT_AGE_KEY = Path.home() / ".config/sops/age/keys.txt"
DEFAULT_ENCRYPTED = Path.home() / ".config/grabowski/ntfy-topic.sops.json"
DEFAULT_RUNTIME = Path.home() / ".config/grabowski/ntfy-topic"


class TopicMaterializationError(RuntimeError):
    pass


def _private_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _require_private_regular_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TopicMaterializationError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TopicMaterializationError(f"{label} is not a regular file")
    if metadata.st_mode & 0o077:
        raise TopicMaterializationError(f"{label} must not be accessible by group or others")


def _read_private_text(path: Path, *, label: str) -> str:
    try:
        fd = os.open(path, _private_open_flags())
    except OSError as exc:
        raise TopicMaterializationError(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise TopicMaterializationError(f"{label} is not a regular file")
        if metadata.st_mode & 0o077:
            raise TopicMaterializationError(f"{label} must not be accessible by group or others")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _validate_topic(topic: str) -> str:
    value = topic.strip()
    if len(value) < 32 or not value.isalnum():
        raise TopicMaterializationError("ntfy topic is invalid")
    return value


def _require_sops(path: Path) -> None:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise TopicMaterializationError("sops executable is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise TopicMaterializationError("sops executable is unavailable")


def _run_sops(
    argv: Sequence[str],
    *,
    sops_path: Path,
    age_key_file: Path | None = None,
    input_bytes: bytes | None = None,
) -> bytes:
    _require_sops(sops_path)
    env = os.environ.copy()
    if age_key_file is not None:
        _require_private_regular_file(age_key_file, label="age key file")
        env["SOPS_AGE_KEY_FILE"] = str(age_key_file)
    try:
        completed = subprocess.run(
            [str(sops_path), *argv],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TopicMaterializationError("sops operation failed") from exc
    if completed.returncode != 0:
        raise TopicMaterializationError("sops operation failed")
    return completed.stdout


def _atomic_private_write(path: Path, payload: bytes, *, create_only: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if create_only and path.exists():
        raise TopicMaterializationError("destination already exists")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if create_only:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise TopicMaterializationError("destination already exists") from exc
            temporary.unlink()
        else:
            os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def encrypt_topic(
    *,
    source: Path,
    destination: Path,
    recipients: Sequence[str],
    sops_path: Path = DEFAULT_SOPS,
) -> dict[str, object]:
    topic = _validate_topic(_read_private_text(source, label="runtime topic file"))
    normalized = [item.strip() for item in recipients if item.strip()]
    if len(normalized) < 2 or len(set(normalized)) != len(normalized):
        raise TopicMaterializationError("at least two distinct age recipients are required")
    plaintext = json.dumps({"topic": topic}, separators=(",", ":")).encode("utf-8")
    ciphertext = _run_sops(
        [
            "--encrypt",
            "--age",
            ",".join(normalized),
            "--input-type",
            "json",
            "--output-type",
            "json",
            "/dev/stdin",
        ],
        sops_path=sops_path,
        input_bytes=plaintext,
    )
    if topic.encode("utf-8") in ciphertext:
        raise TopicMaterializationError("ciphertext unexpectedly contains plaintext topic")
    _atomic_private_write(destination, ciphertext, create_only=True)
    return {
        "status": "encrypted",
        "destination": str(destination),
        "recipient_count": len(normalized),
        "plaintext_absent": True,
    }


def _decrypt_topic(
    *,
    encrypted: Path,
    age_key_file: Path,
    sops_path: Path,
) -> str:
    _require_private_regular_file(encrypted, label="encrypted topic file")
    plaintext = _run_sops(
        [
            "--decrypt",
            "--input-type",
            "json",
            "--output-type",
            "json",
            str(encrypted),
        ],
        sops_path=sops_path,
        age_key_file=age_key_file,
    )
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TopicMaterializationError("decrypted topic payload is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"topic"} or not isinstance(payload["topic"], str):
        raise TopicMaterializationError("decrypted topic payload is invalid")
    return _validate_topic(payload["topic"])


def materialize_topic(
    *,
    encrypted: Path,
    destination: Path,
    age_key_file: Path = DEFAULT_AGE_KEY,
    sops_path: Path = DEFAULT_SOPS,
) -> dict[str, object]:
    topic = _decrypt_topic(encrypted=encrypted, age_key_file=age_key_file, sops_path=sops_path)
    _atomic_private_write(destination, f"{topic}\n".encode("utf-8"), create_only=False)
    _require_private_regular_file(destination, label="materialized runtime topic file")
    return {"status": "materialized", "destination": str(destination), "mode": "0600"}


def verify_topic(
    *,
    encrypted: Path,
    runtime: Path,
    age_key_file: Path = DEFAULT_AGE_KEY,
    sops_path: Path = DEFAULT_SOPS,
) -> dict[str, object]:
    topic = _decrypt_topic(encrypted=encrypted, age_key_file=age_key_file, sops_path=sops_path)
    runtime_topic = _validate_topic(_read_private_text(runtime, label="runtime topic file"))
    if topic != runtime_topic:
        raise TopicMaterializationError("runtime topic does not match encrypted canonical source")
    return {"status": "verified", "matches": True, "runtime_mode_private": True}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the SOPS-backed canonical ntfy topic source.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt")
    encrypt.add_argument("--source", type=Path, default=DEFAULT_RUNTIME)
    encrypt.add_argument("--destination", type=Path, default=DEFAULT_ENCRYPTED)
    encrypt.add_argument("--recipient", action="append", required=True)
    encrypt.add_argument("--sops", type=Path, default=DEFAULT_SOPS)

    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--encrypted", type=Path, default=DEFAULT_ENCRYPTED)
    materialize.add_argument("--destination", type=Path, default=DEFAULT_RUNTIME)
    materialize.add_argument("--age-key-file", type=Path, default=DEFAULT_AGE_KEY)
    materialize.add_argument("--sops", type=Path, default=DEFAULT_SOPS)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--encrypted", type=Path, default=DEFAULT_ENCRYPTED)
    verify.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    verify.add_argument("--age-key-file", type=Path, default=DEFAULT_AGE_KEY)
    verify.add_argument("--sops", type=Path, default=DEFAULT_SOPS)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "encrypt":
            result = encrypt_topic(
                source=args.source,
                destination=args.destination,
                recipients=args.recipient,
                sops_path=args.sops,
            )
        elif args.command == "materialize":
            result = materialize_topic(
                encrypted=args.encrypted,
                destination=args.destination,
                age_key_file=args.age_key_file,
                sops_path=args.sops,
            )
        else:
            result = verify_topic(
                encrypted=args.encrypted,
                runtime=args.runtime,
                age_key_file=args.age_key_file,
                sops_path=args.sops,
            )
    except TopicMaterializationError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
