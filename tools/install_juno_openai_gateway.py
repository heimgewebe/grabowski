#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request

SERVICE_NAME = "grabowski-juno-openai-gateway.service"
MODEL_ID = "grabowski-juno"
LOCAL_BASE_URL = "http://127.0.0.1:18195"
STATE_DIR = Path.home() / ".local" / "state" / "grabowski" / "juno-openai-gateway"
TOKEN_PATH = STATE_DIR / "token"
USER_UNIT_DIR = Path.home() / ".config" / "systemd" / "user"
UNIT_PATH = USER_UNIT_DIR / SERVICE_NAME
REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "systemd" / f"{SERVICE_NAME}.example"
GATEWAY_SOURCE_PATH = REPO_ROOT / "src" / "grabowski_juno_openai_gateway.py"
GATEWAY_EXEC_PATH = Path.home() / ".local" / "libexec" / "grabowski" / "grabowski_juno_openai_gateway.py"


def _secure_existing_token(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("gateway token must be a regular file")
        if metadata.st_uid != os.getuid():
            raise RuntimeError("gateway token owner is invalid")
        if metadata.st_nlink != 1:
            raise RuntimeError("gateway token must have exactly one hard link")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError("gateway token permissions are too broad")
        if not 32 <= metadata.st_size <= 4096:
            raise RuntimeError("gateway token size is invalid")
        data = os.read(descriptor, metadata.st_size + 1)
        if len(data) != metadata.st_size:
            raise RuntimeError("gateway token changed while being read")
    finally:
        os.close(descriptor)


def _ensure_token(path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        _secure_existing_token(path)
        return False
    try:
        token = secrets.token_urlsafe(48).encode("ascii") + b"\n"
        written = os.write(descriptor, token)
        if written != len(token):
            raise RuntimeError("short write while creating gateway token")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _secure_existing_token(path)
    return True


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _install_file(source: Path, destination: Path, *, mode: int) -> str:
    if not source.is_file():
        raise RuntimeError(f"install source is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        with source.open("rb") as source_handle, temporary.open("xb") as target_handle:
            shutil.copyfileobj(source_handle, target_handle)
            target_handle.flush()
            os.fsync(target_handle.fileno())
        temporary.chmod(mode)
        source_sha256 = _sha256_path(source)
        if _sha256_path(temporary) != source_sha256:
            raise RuntimeError(f"installed copy hash mismatch: {destination}")
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return source_sha256
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _install_unit(template: Path, destination: Path) -> str:
    return _install_file(template, destination, mode=0o644)


def _systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def _read_token_for_smoke(path: Path) -> str:
    _secure_existing_token(path)
    return path.read_text(encoding="ascii").strip()


def _wait_for_smoke(token_path: Path, timeout_seconds: int = 20) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "service did not become ready"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(LOCAL_BASE_URL + "/healthz", timeout=2) as response:
                if response.status != 200:
                    raise RuntimeError(f"health status {response.status}")
                json.loads(response.read())
            token = _read_token_for_smoke(token_path)
            request = urllib.request.Request(
                LOCAL_BASE_URL + "/v1/models",
                headers={"Authorization": "Bearer " + token},
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                payload = json.loads(response.read())
                model_ids = [entry.get("id") for entry in payload.get("data", [])]
                if response.status == 200 and MODEL_ID in model_ids:
                    return
                raise RuntimeError("model endpoint did not expose the expected model")
        except (OSError, ValueError, RuntimeError, urllib.error.URLError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.5)
    raise RuntimeError(f"gateway smoke failed: {last_error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install the controlled Juno OpenAI-compatible gateway")
    parser.add_argument("--no-start", action="store_true", help="install files but do not enable or start the service")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token_created = _ensure_token(TOKEN_PATH)
    gateway_sha256 = _install_file(GATEWAY_SOURCE_PATH, GATEWAY_EXEC_PATH, mode=0o700)
    unit_sha256 = _install_unit(TEMPLATE_PATH, UNIT_PATH)
    _systemctl("daemon-reload")
    state = "installed"
    if not args.no_start:
        _systemctl("enable", "--now", SERVICE_NAME)
        _wait_for_smoke(TOKEN_PATH)
        state = _systemctl("is-active", SERVICE_NAME).stdout.strip()
        if state != "active":
            raise RuntimeError(f"gateway service is not active: {state}")
    print(
        json.dumps(
            {
                "service": SERVICE_NAME,
                "state": state,
                "token_created": token_created,
                "gateway_path": str(GATEWAY_EXEC_PATH),
                "gateway_sha256": gateway_sha256,
                "unit_sha256": unit_sha256,
                "local_base_url": LOCAL_BASE_URL,
                "model": MODEL_ID,
                "tailscale_serve_changed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
