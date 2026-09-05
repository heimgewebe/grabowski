#!/usr/bin/env python3
"""Install the canonical Maulwurf X public bridge on its ingress host.

This installer is intentionally host-local and secret-free.  It copies only the
versioned bridge program and user-systemd unit, optionally reloads/starts that
unit, and never changes Tailscale Serve/Funnel state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any


BRIDGE_RELATIVE = Path("tools/grabowski_maulwurf_x_public_bridge.py")
UNIT_RELATIVE = Path("systemd/maulwurf-x-public-bridge.service.example")
BRIDGE_TARGET_RELATIVE = Path(
    ".local/libexec/grabowski/grabowski_maulwurf_x_public_bridge.py"
)
UNIT_TARGET_RELATIVE = Path(".config/systemd/user/maulwurf-x-public-bridge.service")
UNIT_NAME = "maulwurf-x-public-bridge.service"
EXPECTED_EXEC_START = (
    "ExecStart=/usr/bin/python3 "
    "%h/.local/libexec/grabowski/grabowski_maulwurf_x_public_bridge.py"
)


class ActivationError(RuntimeError):
    """Raised for a bounded, secret-free activation/readback failure."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_source(root: Path, relative: Path) -> tuple[Path, bytes]:
    root = root.expanduser().resolve(strict=True)
    candidate = root / relative
    linked = os.lstat(candidate)
    if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
        raise ValueError(f"source is not a regular non-symlink file: {relative}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"source escapes source root: {relative}") from exc
    return resolved, resolved.read_bytes()


def _validate_unit_payload(unit_bytes: bytes) -> None:
    try:
        unit_text = unit_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("systemd unit must be UTF-8") from exc
    exec_lines = [
        line.strip()
        for line in unit_text.splitlines()
        if line.strip().startswith("ExecStart=")
    ]
    if exec_lines != [EXPECTED_EXEC_START]:
        raise ValueError("systemd unit ExecStart does not target the installed bridge")


def _ensure_safe_parent(path: Path) -> None:
    parts = path.expanduser().absolute().parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        try:
            linked = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if stat.S_ISLNK(linked.st_mode):
            raise ValueError(f"target parent contains symlink: {current}")
        if not stat.S_ISDIR(linked.st_mode):
            raise ValueError(f"target parent is not a directory: {current}")


def _atomic_install(path: Path, data: bytes, mode: int) -> dict[str, Any]:
    path = path.expanduser().absolute()
    _ensure_safe_parent(path.parent)
    try:
        linked = os.lstat(path)
    except FileNotFoundError:
        previous = None
        current_mode = None
    else:
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise ValueError(f"target is not a regular non-symlink file: {path}")
        previous = path.read_bytes()
        current_mode = stat.S_IMODE(linked.st_mode)
    changed = previous != data or current_mode != mode
    if changed:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {
        "path": str(path),
        "sha256": _sha256(data),
        "mode": f"{mode:04o}",
        "changed": changed,
    }


def _run_checked(
    argv: list[str], *, operation: str
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ActivationError(
            f"{operation} failed with exit status {completed.returncode}"
        )
    return completed


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return _run_checked(
        ["systemctl", "--user", *args],
        operation=f"systemctl --user {args[0] if args else 'unknown'}",
    )


def _linger_active() -> bool:
    completed = _run_checked(
        [
            "loginctl",
            "show-user",
            str(os.getuid()),
            "--property=Linger",
            "--value",
        ],
        operation="systemd linger readback",
    )
    value = completed.stdout.strip().lower()
    if value not in {"yes", "no"}:
        raise ActivationError("systemd linger readback returned an invalid value")
    return value == "yes"


def _parse_systemd_readback(stdout: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in stdout.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key] = value
    return properties


def _verify_activation(readback: dict[str, str], expected_fragment: Path) -> None:
    expected = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "UnitFileState": "enabled",
        "Result": "success",
        "FragmentPath": str(expected_fragment),
    }
    for key, value in expected.items():
        if readback.get(key) != value:
            raise ActivationError(f"systemd readback mismatch for {key}")
    try:
        main_pid = int(readback.get("MainPID", "0"))
    except ValueError as exc:
        raise ActivationError("systemd readback MainPID is invalid") from exc
    if main_pid <= 0:
        raise ActivationError("systemd readback MainPID is not running")


def install(source_root: Path, target_home: Path, *, activate: bool) -> dict[str, Any]:
    bridge_source, bridge_bytes = _regular_source(source_root, BRIDGE_RELATIVE)
    unit_source, unit_bytes = _regular_source(source_root, UNIT_RELATIVE)
    _validate_unit_payload(unit_bytes)

    target_home_raw = target_home.expanduser().absolute()
    home_stat = os.lstat(target_home_raw)
    if stat.S_ISLNK(home_stat.st_mode) or not stat.S_ISDIR(home_stat.st_mode):
        raise ValueError("target home must be a real directory")
    target_home = target_home_raw.resolve(strict=True)

    linger_active: bool | None = None
    if activate:
        linger_active = _linger_active()
        if not linger_active:
            raise ActivationError("systemd linger must be active before activation")

    bridge_result = _atomic_install(
        target_home / BRIDGE_TARGET_RELATIVE, bridge_bytes, 0o755
    )
    unit_result = _atomic_install(target_home / UNIT_TARGET_RELATIVE, unit_bytes, 0o644)
    activation: dict[str, Any] = {
        "requested": activate,
        "linger_active": linger_active,
    }
    if activate:
        _systemctl("daemon-reload")
        _systemctl("enable", UNIT_NAME)
        _systemctl("restart", UNIT_NAME)
        readback_result = _systemctl(
            "show",
            UNIT_NAME,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--property=Result",
            "--property=NRestarts",
            "--property=MainPID",
            "--property=FragmentPath",
        )
        readback = _parse_systemd_readback(readback_result.stdout)
        expected_fragment = target_home / UNIT_TARGET_RELATIVE
        _verify_activation(readback, expected_fragment)
        activation["systemd_readback"] = readback
        activation["verified"] = True

    return {
        "schema_version": 1,
        "kind": "grabowski.maulwurf_x_public_bridge_install",
        "ok": True,
        "source_root": str(source_root.expanduser().resolve(strict=True)),
        "sources": {
            "bridge": {"path": str(bridge_source), "sha256": _sha256(bridge_bytes)},
            "unit": {"path": str(unit_source), "sha256": _sha256(unit_bytes)},
        },
        "installed": {"bridge": bridge_result, "unit": unit_result},
        "activation": activation,
        "tailscale_mutated": False,
        "secret_material_required": False,
    }


def _parser() -> argparse.ArgumentParser:
    default_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=default_root)
    parser.add_argument("--target-home", type=Path, default=Path.home())
    parser.add_argument(
        "--activate",
        action="store_true",
        help="daemon-reload, enable and restart the user service after installation",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = install(args.source_root, args.target_home, activate=args.activate)
    except (ActivationError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "grabowski.maulwurf_x_public_bridge_install",
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
