from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
from typing import Any, Sequence

import grabowski_bureau_runtime_refresh_executor as bureau_runtime_refresh_executor

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
REMOTE_COMMAND_MODES = frozenset({"posix", "windows-powershell"})
TASK_UNIT_SHOW_OBSERVER = "task-systemd-user-show-v1"
TASK_UNIT_SHOW_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
)

TASK_OUTPUT_READ_OBSERVER = "task-output-read-v1"
TASK_OUTPUT_READ_CODE_SHA256 = (
    "1865172d0eaeca612e2047b3fa7c689458faba1aed130953324ff91bf47da31c"
)
TASK_OUTPUT_READ_PYTHON = "/usr/bin/python3"
TASK_OUTPUT_DIRECTORY = re.compile(
    re.escape(str(HOME))
    + r"/\.grabowski-task-output-([0-9a-f]{24})-a([1-9][0-9]*)\Z"
)
TASK_OUTPUT_STREAM = frozenset({"stdout.log", "stderr.log"})
TASK_OUTPUT_MAX_READ_LINES = 2000
TASK_OUTPUT_MAX_READ_BYTES = 60 * 1024
TASK_OUTPUT_CLEANUP_OBSERVER = "task-output-cleanup-v1"
TASK_OUTPUT_CLEANUP_CODE_SHA256 = (
    "6001b35604486ad1976ccb3b3efac6115ee02e5175c56138ef3cbbdaee2e294b"
)
TASK_OUTPUT_CLEANUP_MAX_STREAM_BYTES = 8 * 1024 * 1024


class FleetCommandDenied(PermissionError):
    """Raised when a fleet host rejects an otherwise valid command shape."""


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


def validate_fleet(raw: dict[str, Any]) -> dict[str, Any]:
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
              {"connect_timeout_seconds", "remote_command_mode"}, f"Fleet host {name}")
        transport = candidate["transport"]
        target = candidate["target"]
        roles = candidate["roles"]
        allowlist = candidate["command_allowlist"]
        timeout = candidate.get("connect_timeout_seconds", 10)
        remote_command_mode = candidate.get("remote_command_mode", "posix")
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
        if remote_command_mode not in REMOTE_COMMAND_MODES:
            raise ValueError(f"Fleet host {name} has invalid remote command mode")
        if transport != "ssh" and remote_command_mode != "posix":
            raise ValueError(f"Fleet host {name} remote command mode requires SSH transport")
        hosts[name] = {
            **candidate,
            "connect_timeout_seconds": timeout,
            "remote_command_mode": remote_command_mode,
        }
    return {"schema_version": 1, "hosts": hosts}


def load_fleet() -> dict[str, Any]:
    return validate_fleet(_load_object(FLEET_CONFIG))


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


def _windows_powershell_remote_command(command: list[str]) -> str:
    """Encode argv as inert JSON and reconstruct it inside Windows PowerShell."""
    payload = base64.b64encode(
        json.dumps(
            {"command": command[0], "args": command[1:]},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$j=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}'));"
        "$o=ConvertFrom-Json -InputObject $j;"
        "$c=[string]$o.command;"
        "$r=@($o.args);"
        "if([string]::IsNullOrEmpty($c)){exit 2};"
        "& $c @r;"
        "$ok=$?;"
        "$rc=$LASTEXITCODE;"
        "if($null -eq $rc){if($ok){exit 0}else{exit 1}};"
        "exit [int]$rc"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return (
        "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "
        + encoded
    )


def _ssh_remote_command(host: dict[str, Any], command: list[str]) -> str:
    if host["remote_command_mode"] == "windows-powershell":
        return _windows_powershell_remote_command(command)
    return "exec " + shlex.join(command)


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
        raise FleetCommandDenied(f"Executable is not allowed for fleet host {name}: {command[0]}")


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
        remote_command = _ssh_remote_command(host, command)
        result = operator._run([
            ssh, "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
            "-o", f"ConnectTimeout={host['connect_timeout_seconds']}",
            "--", host["target"], remote_command,
        ], cwd=HOME, timeout_seconds=timeout, max_output_bytes=output_limit)
    return {"host": name, "transport": host["transport"], "roles": host["roles"],
            "remote_argv": command, "result": result}


_TASK_UNIT = re.compile(r"grabowski-task-[0-9a-f]{24}-a[1-9][0-9]*\.service\Z")
_SYSTEMD_SHOW_PROPERTY = re.compile(r"[A-Za-z][A-Za-z0-9]*\Z")


def run_fleet_task_output_read(
    name: str,
    argv: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Run the narrow descriptor-bound task-output reader.

    This path deliberately bypasses the generic production executable allowlist
    only after binding the exact embedded Python program by SHA-256 and validating
    every remaining argument against the task-output path grammar. It therefore
    does not authorize arbitrary Python execution through ``grabowski_fleet_run``.
    """
    host = fleet_host(name)
    command = operator._validate_argv(argv, cwd=HOME)
    if len(command) < 3:
        raise ValueError("Invalid task-output reader argv length")
    redaction_probe = [
        command[0],
        command[1],
        "<hash-bound-task-output-read-code>",
        *command[3:],
    ]
    if operator._redact_argv(redaction_probe) != redaction_probe:
        raise ValueError("task-output reader argv appears to contain secret material")
    if len(command) != 7:
        raise ValueError("Invalid task-output reader argv length")
    if command[0] != TASK_OUTPUT_READ_PYTHON or command[1] != "-c":
        raise ValueError("Invalid task-output reader executable")
    code_sha256 = hashlib.sha256(command[2].encode("utf-8")).hexdigest()
    if code_sha256 != TASK_OUTPUT_READ_CODE_SHA256:
        raise PermissionError("Task-output reader code identity mismatch")
    directory_match = TASK_OUTPUT_DIRECTORY.fullmatch(command[3])
    if directory_match is None:
        raise ValueError("Invalid task-output directory")
    if command[4] not in TASK_OUTPUT_STREAM:
        raise ValueError("Invalid task-output stream")
    try:
        max_lines = int(command[5])
        byte_limit = int(command[6])
    except ValueError as exc:
        raise ValueError("Invalid task-output reader limits") from exc
    if str(max_lines) != command[5] or not 1 <= max_lines <= TASK_OUTPUT_MAX_READ_LINES:
        raise ValueError("Invalid task-output reader line limit")
    if str(byte_limit) != command[6] or not 1024 <= byte_limit <= TASK_OUTPUT_MAX_READ_BYTES:
        raise ValueError("Invalid task-output reader byte limit")
    timeout = operator._timeout(timeout_seconds)
    output_limit = operator._output_limit(max_output_bytes)
    if host["transport"] == "local":
        result = operator._run(
            command,
            cwd=HOME,
            timeout_seconds=timeout,
            max_output_bytes=output_limit,
        )
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise RuntimeError("OpenSSH client is not installed")
        remote_command = _ssh_remote_command(host, command)
        result = operator._run(
            [
                ssh,
                "-o",
                "BatchMode=yes",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                f"ConnectTimeout={host['connect_timeout_seconds']}",
                "--",
                host["target"],
                remote_command,
            ],
            cwd=HOME,
            timeout_seconds=timeout,
            max_output_bytes=output_limit,
        )
    return {
        "host": name,
        "transport": host["transport"],
        "roles": host["roles"],
        "remote_argv": command,
        "observer": TASK_OUTPUT_READ_OBSERVER,
        "reader_code_sha256": code_sha256,
        "task_id": directory_match.group(1),
        "attempt": int(directory_match.group(2)),
        "stream": command[4],
        "result": result,
    }


def run_fleet_task_output_cleanup(
    name: str,
    argv: list[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Run the fixed task-output inventory/delete contract on one fleet host.

    The generic fleet allowlist is not consulted because this path accepts only
    the hash-bound embedded program and exact task-output arguments. No caller-
    supplied Python program, executable, path family or deletion target is allowed.
    """
    host = fleet_host(name)
    command = operator._validate_argv(argv, cwd=HOME)
    if len(command) != 10:
        raise ValueError("Invalid task-output cleanup argv length")
    if command[0] != TASK_OUTPUT_READ_PYTHON or command[1] != "-c":
        raise ValueError("Invalid task-output cleanup executable")
    code_sha256 = hashlib.sha256(command[2].encode("utf-8")).hexdigest()
    if code_sha256 != TASK_OUTPUT_CLEANUP_CODE_SHA256:
        raise PermissionError("Task-output cleanup code identity mismatch")
    redaction_probe = [
        command[0],
        command[1],
        "<hash-bound-task-output-cleanup-code>",
        *command[3:],
    ]
    if operator._redact_argv(redaction_probe) != redaction_probe:
        raise ValueError("task-output cleanup argv appears to contain secret material")
    mode = command[3]
    if mode not in {"inspect", "delete"}:
        raise ValueError("Invalid task-output cleanup mode")
    directory_match = TASK_OUTPUT_DIRECTORY.fullmatch(command[4])
    if directory_match is None:
        raise ValueError("Invalid task-output cleanup directory")
    if re.fullmatch(r"[0-9a-f]{64}", command[5]) is None:
        raise ValueError("Invalid task-output cleanup token")
    if mode == "inspect":
        if command[6:10] != ["-", "-", "-1", "-1"]:
            raise ValueError("Invalid task-output cleanup inspect binding")
    else:
        if (
            re.fullmatch(r"[0-9a-f]{64}", command[6]) is None
            or re.fullmatch(r"[0-9a-f]{64}", command[7]) is None
        ):
            raise ValueError("Invalid task-output cleanup digest binding")
        try:
            stdout_bytes = int(command[8])
            stderr_bytes = int(command[9])
        except ValueError as exc:
            raise ValueError("Invalid task-output cleanup size binding") from exc
        if (
            str(stdout_bytes) != command[8]
            or str(stderr_bytes) != command[9]
            or not 0 <= stdout_bytes <= TASK_OUTPUT_CLEANUP_MAX_STREAM_BYTES
            or not 0 <= stderr_bytes <= TASK_OUTPUT_CLEANUP_MAX_STREAM_BYTES
        ):
            raise ValueError("Invalid task-output cleanup size binding")
    timeout = operator._timeout(timeout_seconds)
    output_limit = operator._output_limit(max_output_bytes)
    if host["transport"] == "local":
        result = operator._run(
            command, cwd=HOME, timeout_seconds=timeout, max_output_bytes=output_limit
        )
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise RuntimeError("OpenSSH client is not installed")
        remote_command = _ssh_remote_command(host, command)
        result = operator._run(
            [
                ssh,
                "-o",
                "BatchMode=yes",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                f"ConnectTimeout={host['connect_timeout_seconds']}",
                "--",
                host["target"],
                remote_command,
            ],
            cwd=HOME,
            timeout_seconds=timeout,
            max_output_bytes=output_limit,
        )
    return {
        "host": name,
        "transport": host["transport"],
        "roles": host["roles"],
        "remote_argv": command,
        "observer": TASK_OUTPUT_CLEANUP_OBSERVER,
        "cleanup_code_sha256": code_sha256,
        "task_id": directory_match.group(1),
        "attempt": int(directory_match.group(2)),
        "mode": mode,
        "result": result,
    }


def run_fleet_task_unit_show(
    name: str,
    unit: str,
    properties: Sequence[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, Any]:
    """Run the narrow read-only task-unit observer used by task reconcile.

    This deliberately does not add generic ``systemctl`` to a production host's
    command allowlist.  The only accepted command shape is
    ``systemctl --user show <grabowski-task-unit>`` with bounded property names.
    """
    host = fleet_host(name)
    if not isinstance(unit, str) or _TASK_UNIT.fullmatch(unit) is None:
        raise ValueError("Invalid Grabowski task unit")
    if not (
        isinstance(properties, (list, tuple))
        and 1 <= len(properties) <= 32
        and all(isinstance(item, str) and _SYSTEMD_SHOW_PROPERTY.fullmatch(item) for item in properties)
    ):
        raise ValueError("Invalid systemd property list")
    command = ["systemctl", "--user", "show", unit, "--no-pager"]
    command.extend(f"--property={item}" for item in properties)
    timeout = operator._timeout(timeout_seconds)
    output_limit = operator._output_limit(max_output_bytes)
    if host["transport"] == "local":
        result = operator._run(command, cwd=HOME, timeout_seconds=timeout,
                               max_output_bytes=output_limit)
    else:
        ssh = shutil.which("ssh")
        if not ssh:
            raise RuntimeError("OpenSSH client is not installed")
        remote_command = _ssh_remote_command(host, command)
        result = operator._run([
            ssh, "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes",
            "-o", f"ConnectTimeout={host['connect_timeout_seconds']}",
            "--", host["target"], remote_command,
        ], cwd=HOME, timeout_seconds=timeout, max_output_bytes=output_limit)
    return {"host": name, "transport": host["transport"], "roles": host["roles"],
            "remote_argv": command, "observer": TASK_UNIT_SHOW_OBSERVER,
            "result": result}


@mcp.tool(name="grabowski_fleet_list", annotations=READ_ONLY)
def grabowski_fleet_list() -> dict[str, Any]:
    """Return the validated local and SSH host registry."""
    fleet = load_fleet()
    return {"path": str(FLEET_CONFIG), "schema_version": 1,
            "hosts": fleet["hosts"], "count": len(fleet["hosts"])}


def run_public_fleet_host(
    host: str,
    argv: list[str],
    *,
    surface: str,
) -> dict[str, Any]:
    """Gate one generic fleet call with fixed server-owned sync limits."""
    command = _safe_argv(argv)
    bureau_runtime_refresh_executor.reject_generic_runtime_refresh_execution(
        command, surface=surface
    )
    timeout = operator.SYNCHRONOUS_TRANSPORT_TIMEOUT_SECONDS
    output_limit = operator.SYNCHRONOUS_TRANSPORT_OUTPUT_BYTES
    operator._enforce_synchronous_call_shape(
        command,
        timeout_seconds=timeout,
        max_output_bytes=output_limit,
        surface=surface,
    )
    result = run_fleet_host(
        host,
        command,
        timeout_seconds=timeout,
        max_output_bytes=output_limit,
    )
    result["synchronous_contract"] = operator._synchronous_public_contract(
        surface=surface
    )
    return result


@mcp.tool(name="grabowski_fleet_run", annotations=MUTATING)
def grabowski_fleet_run(
    host: str,
    argv: list[str],
) -> dict[str, Any]:
    """Run one fleet command with fixed server-owned synchronous limits."""
    fleet_host(host)
    operator._require_operator_mutation(
        "terminal_execute", host=host, opaque_command=True
    )
    return run_public_fleet_host(
        host,
        argv,
        surface="grabowski_fleet_run",
    )


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run registered Grabowski fleet commands")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    run = sub.add_parser("run")
    run.add_argument("host")
    run.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command == "list":
            result = load_fleet()
        else:
            if not args.argv:
                raise ValueError("run requires an argv after the host")
            fleet_host(args.host)
            operator._require_operator_mutation(
                "terminal_execute", host=args.host, opaque_command=True
            )
            result = run_public_fleet_host(
                args.host,
                args.argv,
                surface="grabowski_fleet_cli",
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
