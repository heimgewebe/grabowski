from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
from typing import Any

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
BROKER = Path(os.environ.get(
    "GRABOWSKI_PRIVILEGED_BROKER",
    "/usr/local/libexec/grabowski-privileged-broker",
))
BROKER_CONFIG = Path(os.environ.get(
    "GRABOWSKI_PRIVILEGED_BROKER_CONFIG",
    "/etc/grabowski/privileged-actions.json",
))


def _root_file(path: Path, executable: bool) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path), "exists": False, "regular": False,
        "root_owned": False, "not_group_or_world_writable": False,
        "executable": False, "valid": False,
    }
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return result
    result["exists"] = True
    result["regular"] = stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
    result["root_owned"] = metadata.st_uid == 0
    result["not_group_or_world_writable"] = not bool(metadata.st_mode & 0o022)
    result["executable"] = bool(metadata.st_mode & 0o111)
    result["valid"] = bool(
        result["regular"] and result["root_owned"]
        and result["not_group_or_world_writable"]
        and (result["executable"] if executable else True)
    )
    return result


@mcp.tool(name="grabowski_privileged_broker_status", annotations=READ_ONLY)
def grabowski_privileged_broker_status() -> dict[str, Any]:
    """Inspect the fail-closed root-owned privileged broker installation."""
    operator._require_operator_capability("privileged_reference")
    broker = _root_file(BROKER, True)
    config = _root_file(BROKER_CONFIG, False)
    command = shutil.which("grabowski-privileged-request")
    return {
        "broker": broker,
        "config": config,
        "request_client": command,
        "ready": bool(broker["valid"] and config["valid"] and command),
        "execution_model": "root-owned-template-broker",
        "reference_tool": "grabowski_privileged_action_reference",
        "fail_closed": True,
    }
