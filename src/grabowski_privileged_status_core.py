from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
from typing import Any

BROKER = Path(
    os.environ.get(
        "GRABOWSKI_PRIVILEGED_BROKER",
        "/usr/local/libexec/grabowski-privileged-broker",
    )
)
BROKER_CONFIG = Path(
    os.environ.get(
        "GRABOWSKI_PRIVILEGED_BROKER_CONFIG",
        "/etc/grabowski/privileged-actions.json",
    )
)
BROKER_SOCKET = Path(
    os.environ.get(
        "GRABOWSKI_PRIVILEGED_BROKER_SOCKET",
        "/run/grabowski/privileged-broker.sock",
    )
)


def root_file_status(path: Path, executable: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": False,
        "regular": False,
        "root_owned": False,
        "not_group_or_world_writable": False,
        "mode": None,
        "executable": False,
        "valid": False,
    }
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return result
    result["exists"] = True
    result["regular"] = stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
    result["root_owned"] = metadata.st_uid == 0
    result["not_group_or_world_writable"] = not bool(metadata.st_mode & 0o022)
    result["mode"] = oct(stat.S_IMODE(metadata.st_mode))
    result["executable"] = bool(metadata.st_mode & 0o111)
    result["valid"] = bool(
        result["regular"]
        and result["root_owned"]
        and result["not_group_or_world_writable"]
        and (result["executable"] if executable else True)
    )
    return result


def socket_status(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": False,
        "socket": False,
        "owner_uid": None,
        "owner_gid": None,
        "mode": None,
        "valid": False,
    }
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return result
    result.update(
        {
            "exists": True,
            "socket": stat.S_ISSOCK(metadata.st_mode),
            "owner_uid": metadata.st_uid,
            "owner_gid": metadata.st_gid,
            "mode": oct(stat.S_IMODE(metadata.st_mode)),
        }
    )
    result["valid"] = bool(result["socket"] and not (metadata.st_mode & 0o007))
    return result


def privileged_broker_status(
    *,
    broker: Path = BROKER,
    config: Path = BROKER_CONFIG,
    socket_path: Path = BROKER_SOCKET,
) -> dict[str, Any]:
    broker_status = root_file_status(broker, True)
    config_status = root_file_status(config, False)
    live_socket = socket_status(socket_path)
    command = shutil.which("grabowski-privileged-request")
    return {
        "broker": broker_status,
        "config": config_status,
        "socket": live_socket,
        "request_client": command,
        "ready": bool(
            broker_status["valid"]
            and config_status["valid"]
            and live_socket["valid"]
            and command
        ),
        "execution_model": "root-owned-systemd-socket-template-broker",
        "reference_tool": "grabowski_privileged_action_reference",
        "fail_closed": True,
    }
