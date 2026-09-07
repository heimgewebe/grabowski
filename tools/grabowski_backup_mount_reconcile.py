#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any


MOUNT_PATH = Path("/mnt/backup")
UUID = "249180DA265E8DE0"
UUID_PATH = Path(f"/dev/disk/by-uuid/{UUID}")
LOCK_PATH = Path("/run/grabowski/backup-mount-reconcile.lock")


def _run(
    argv: list[str], *, ok: tuple[int, ...] = (0,)
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode not in ok:
        raise RuntimeError(
            f"command failed: {argv[0]} returncode={result.returncode}"
        )
    return result


def _configured_device() -> str:
    resolved = UUID_PATH.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISBLK(metadata.st_mode):
        raise RuntimeError("configured BACKUP UUID does not resolve to a block device")
    observed_uuid = _run(
        ["/usr/bin/lsblk", "-ndo", "UUID", str(resolved)]
    ).stdout.strip()
    if observed_uuid != UUID:
        raise RuntimeError("configured BACKUP device UUID mismatch")
    return str(resolved)


def _observe_mount() -> str | None:
    result = _run(
        [
            "/usr/bin/findmnt",
            "-rn",
            "-T",
            str(MOUNT_PATH),
            "-t",
            "ntfs3",
            "-o",
            "TARGET,SOURCE,FSTYPE",
        ],
        ok=(0, 1),
    )
    rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode == 1 and not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 3:
        raise RuntimeError("BACKUP mount identity is ambiguous")
    target, source, filesystem = rows[0]
    if (
        target != str(MOUNT_PATH)
        or filesystem != "ntfs3"
        or not source.startswith("/dev/")
    ):
        raise RuntimeError("BACKUP mount identity mismatch")
    return source


def _mount_busy() -> bool:
    result = _run(["/usr/bin/fuser", "-m", str(MOUNT_PATH)], ok=(0, 1))
    if result.returncode == 0:
        return True
    if result.stdout.strip() or result.stderr.strip():
        raise RuntimeError("BACKUP mount user probe returned unexpected output")
    return False


def _assert_stale_source_absent(source: str) -> None:
    if os.path.exists(source):
        raise RuntimeError(
            "BACKUP mount source still exists and differs from configured UUID device"
        )


def reconcile() -> dict[str, Any]:
    configured_source = _configured_device()
    mounted_source = _observe_mount()
    if mounted_source is None:
        return {
            "schema_version": 1,
            "kind": "grabowski_backup_mount_reconcile",
            "status": "already_unmounted",
            "effect_applied": False,
            "configured_source": configured_source,
        }
    if mounted_source == configured_source:
        return {
            "schema_version": 1,
            "kind": "grabowski_backup_mount_reconcile",
            "status": "already_current",
            "effect_applied": False,
            "configured_source": configured_source,
            "before_source": mounted_source,
        }

    _assert_stale_source_absent(mounted_source)
    if _observe_mount() != mounted_source:
        raise RuntimeError("BACKUP mount source changed during reconciliation preflight")
    if _mount_busy():
        raise RuntimeError("BACKUP mount is busy")
    if _observe_mount() != mounted_source:
        raise RuntimeError("BACKUP mount source changed before unmount")
    _assert_stale_source_absent(mounted_source)
    if _configured_device() != configured_source:
        raise RuntimeError("configured BACKUP device changed before unmount")

    _run(["/usr/bin/umount", str(MOUNT_PATH)])

    if _observe_mount() is not None:
        raise RuntimeError("stale BACKUP mount remains after unmount")
    if _configured_device() != configured_source:
        raise RuntimeError("configured BACKUP device changed during reconciliation")
    return {
        "schema_version": 1,
        "kind": "grabowski_backup_mount_reconcile",
        "status": "stale_mount_removed",
        "effect_applied": True,
        "configured_source": configured_source,
        "before_source": mounted_source,
    }


def main(argv: list[str]) -> int:
    if argv != ["reconcile"]:
        raise SystemExit(64)
    if os.geteuid() != 0:
        raise PermissionError("BACKUP mount reconciliation requires root")

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        LOCK_PATH,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        result = reconcile()
    finally:
        os.close(descriptor)

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
