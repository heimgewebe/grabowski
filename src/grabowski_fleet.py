from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
from typing import Any

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
HOME = operator.HOME
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
FLEET_CONFIG = Path(os.environ.get(
    "GRABOWSKI_FLEET_CONFIG",
    str(HOME / ".config" / "grabowski" / "fleet.json"),
)).expanduser()
HOST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
SSH_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}\Z")
PRODUCTION_ROLE = "production"


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise PermissionError(f"Fleet registry may not be a symlink: {path}")
    try:
        metadata = path.stat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Fleet registry missing: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 512 * 1024:
        raise ValueError(f"Fleet registry is not a bounded regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Fleet registry is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError("Fleet registry must contain one JSON object")
    return value


def _keys(value: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    unknown = sorted(set(value) - required - optional)
    if missing or unknown:
        raise ValueError(f"{label} key mismatch; missing={missing}, unknown={unknown}")


def load_fleet() -> dict[str, Any]:
    raw = _load_object(FLEET_CONFIG)
    _keys(raw, {"schema_version", "hosts"}, set(), "Fleet registry")
    if raw["schema_version"] != 1 or not isinstance(raw["hosts"], dict):
        raise ValueError("Fleet registry must use schema_version 1 and object hosts")
    hosts: dict[str, dict[str, Any]] = {}
    for name, candidate in raw["hosts"].items():
        if not isinstance(name, str) or not HOST_NAME.fullmatch(name):
            raise ValueError(f"Invalid fleet host name: {name!r}")
        if not isinstance(candidate, dict):
            raise ValueError(f"Fleet host {name} must be an object")
        _keys(candidate,
              {"transport", "target", "enabled", "roles", "command_allowlist"},
              {"connect_timeout_seconds"}, f"Fleet host {name}")
        transport = candidate["transport"]
        target = candidate["target"]
        roles = candidate["roles"]
        allowlist = candidate["command_allowlist"]
        timeout = candidate.get("connect_timeout_seconds", 10)
        if transport not in {"local", "ssh"}:
            raise ValueError(f"Fleet host {name} has invalid transport")
        if not isinstance(target, str) or not target:
            raise ValueError(f"Fleet host {name} has invalid target")
        if transport == "ssh" and not SSH_TARGET.fullmatch(target):
            raise ValueError(f"Fleet host {name} has unsafe SSH target")
        if not isinstance(candidate["enabled"], bool):
            raise ValueError(f"Fleet host {name} enabled must be boolean")
        if not (isinstance(roles, list) and len(roles) == len(set(roles))
                and all(isinstance(role, str) and HOST_NAME.fullmatch(role) for role in roles)):
            raise ValueError(f"Fleet host {name} has invalid roles")
        if not (isinstance(allowlist, list) and allowlist and len(allowlist) == len(set(allowlist))
                and all(isinstance(item, str) and (item == "*" or re.fullmatch(r"[A-Za-z0-9_.+/-]{1,200}", item)) for item in allowlist)):
            raise ValueError(f"Fleet host {name} has invalid command_allowlist")
        if not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError(f"Fleet host {name} has invalid connect timeout")
        hosts[name] = {**candidate, "connect_timeout_seconds": timeout}
    return {"schema_version": 1, "hosts": hosts}


def fleet_host(name: str) -> dict[str, Any]:
    if not isinstance(name, str) or not HOST_NAME.fullmatch(name):
        raise ValueError("Invalid fleet host name")
    fleet = load_fleet()
    if name not in fleet["hosts"]:
        raise ValueError(f"Unknown fleet host: {name}")
    host = fleet["hosts"][name]
    if not host["enabled"]:
        raise PermissionError(f"Fleet host is disabled: {name}")
    return host


def _safe_argv(argv: list[str]) -> list[str]:
    validated = operator._validate_argv(argv, cwd=HOME)
    if operator._redact_argv(validated) != validated:
        raise ValueError("argv appears to contain secret material")
    return validated


def _ensure_command_allowed(name: str, host: dict[str, Any], command: list[str]) -> None:
    allowlist = host["command_allowlist"]
    executable = Path(command[0]).name
    if "*" in allowlist:
        if PRODUCTION_ROLE in host["roles"]:
            raise PermissionError(
                f"Fleet host {name} has production role; wildcard command_allowlist is not allowed"
            )
        return
    if command[0] not in allowlist and executable not in allowlist:
        raise PermissionError(f"Executable is not allowed for fleet host {name}: {command[0]}")


def run_fleet_host(name: str, argv: list[str], *, timeout_seconds: int,
                   max_output_bytes: int) -> dict[str, Any]:
    host = fleet_host(name)
    command = _safe_argv(argv)
    timeout = operator._timeout(timeout_seconds)
    output_limit = operator._output_limit(max_output_bytes)
    _ensure_command_allowed(name, host, command)
    if host["transport"] == "local":
        result = operator._run(command, cwd=HOME, timeout_seconds=timeout,
                               max_output_bytes=output_limit)
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise RuntimeError("OpenSSH client is not installed")
        remote_command = "exec " + shlex.join(command)
        result = operator._run([
            ssh, "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
            "-o", f"ConnectTimeout={host['connect_timeout_seconds']}",
            "--", host["target"], remote_command,
        ], cwd=HOME, timeout_seconds=timeout, max_output_bytes=output_limit)
    return {"host": name, "transport": host["transport"], "roles": host["roles"],
            "remote_argv": command, "result": result}


@mcp.tool(name="grabowski_fleet_list", annotations=READ_ONLY)
def grabowski_fleet_list() -> dict[str, Any]:
    """Return the validated local and SSH host registry."""
    operator._require_operator_capability("terminal_execute")
    fleet = load_fleet()
    return {"path": str(FLEET_CONFIG), "schema_version": 1,
            "hosts": fleet["hosts"], "count": len(fleet["hosts"])}


@mcp.tool(name="grabowski_fleet_run", annotations=MUTATING)
def grabowski_fleet_run(host: str, argv: list[str],
                        timeout_seconds: int = operator.DEFAULT_TIMEOUT,
                        max_output_bytes: int = operator.DEFAULT_OUTPUT_BYTES) -> dict[str, Any]:
    """Run one argv command on one registered local or SSH host."""
    operator._require_operator_mutation("terminal_execute")
    return run_fleet_host(host, argv, timeout_seconds=timeout_seconds,
                          max_output_bytes=max_output_bytes)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run registered Grabowski fleet commands")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    run = sub.add_parser("run")
    run.add_argument("host")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    run.add_argument("--timeout", type=int, default=operator.DEFAULT_TIMEOUT)
    args = parser.parse_args()
    try:
        if args.command == "list":
            result = load_fleet()
        else:
            if not args.argv:
                raise ValueError("run requires an argv after the host")
            operator._require_operator_mutation("terminal_execute")
            result = run_fleet_host(args.host, args.argv,
                                    timeout_seconds=args.timeout,
                                    max_output_bytes=operator.DEFAULT_OUTPUT_BYTES)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
