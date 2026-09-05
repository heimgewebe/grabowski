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


def _ensure_safe_parent(path: Path) -> None:
    parts = path.expanduser().absolute().parts
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if current.exists():
            linked = os.lstat(current)
            if stat.S_ISLNK(linked.st_mode):
                raise ValueError(f"target parent contains symlink: {current}")
            if not stat.S_ISDIR(linked.st_mode):
                raise ValueError(f"target parent is not a directory: {current}")
            continue
        current.mkdir(mode=0o700)


def _atomic_install(path: Path, data: bytes, mode: int) -> dict[str, Any]:
    path = path.expanduser().absolute()
    _ensure_safe_parent(path.parent)
    if path.exists():
        linked = os.lstat(path)
        if stat.S_ISLNK(linked.st_mode) or not stat.S_ISREG(linked.st_mode):
            raise ValueError(f"target is not a regular non-symlink file: {path}")
        previous = path.read_bytes()
    else:
        previous = None
    changed = previous != data or (
        path.exists() and stat.S_IMODE(path.stat().st_mode) != mode
    )
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


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def install(source_root: Path, target_home: Path, *, activate: bool) -> dict[str, Any]:
    bridge_source, bridge_bytes = _regular_source(source_root, BRIDGE_RELATIVE)
    unit_source, unit_bytes = _regular_source(source_root, UNIT_RELATIVE)
    target_home = target_home.expanduser().resolve(strict=True)
    home_stat = os.lstat(target_home)
    if stat.S_ISLNK(home_stat.st_mode) or not stat.S_ISDIR(home_stat.st_mode):
        raise ValueError("target home must be a real directory")

    bridge_result = _atomic_install(
        target_home / BRIDGE_TARGET_RELATIVE, bridge_bytes, 0o755
    )
    unit_result = _atomic_install(target_home / UNIT_TARGET_RELATIVE, unit_bytes, 0o644)
    activation: dict[str, Any] = {"requested": activate}
    if activate:
        _systemctl("daemon-reload")
        _systemctl("enable", UNIT_NAME)
        _systemctl("restart", UNIT_NAME)
        readback = _systemctl(
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
        activation["systemd_readback"] = [
            line for line in readback.stdout.splitlines() if line
        ]

    return {
        "schema_version": 1,
        "kind": "grabowski.maulwurf_x_public_bridge_install",
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
    result = install(args.source_root, args.target_home, activate=args.activate)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
