#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "agent-route"
DEFAULT_TARGET = Path.home() / "bin" / "agent-route"
DEFAULT_PIN = (
    Path.home()
    / ".config"
    / "grabowski"
    / "coding-agent-probe-scheduler-router.sha256"
)
DEFAULT_RUNTIME_PYTHON = Path.home() / ".local/share/grabowski-mcp/.venv/bin/python"


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExistingFile:
    present: bool
    data: bytes = b""
    mode: int = 0


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_existing(path: Path) -> ExistingFile:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return ExistingFile(False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise InstallError(f"unsafe existing file: {path}")
    return ExistingFile(True, path.read_bytes(), stat.S_IMODE(metadata.st_mode))


def _safe_parent(path: Path, mode: int) -> Path:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=mode)
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise InstallError(f"unsafe parent directory: {parent}")
    return parent


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    parent = _safe_parent(path, 0o700)
    _safe_existing(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise InstallError("unsafe temporary install file")
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _restore(path: Path, previous: ExistingFile) -> None:
    if previous.present:
        _atomic_write(path, previous.data, previous.mode)
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _run_json(argv: list[str], *, timeout: int = 30) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            check=False,
            timeout=timeout,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("router verification command failed to execute") from exc
    if result.returncode != 0:
        raise InstallError("router verification command returned nonzero")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InstallError("router verification command returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise InstallError("router verification JSON root is not an object")
    return value


def _verify_runtime(runtime_python: Path) -> dict[str, Any]:
    if not runtime_python.is_absolute() or not os.access(runtime_python, os.X_OK):
        raise InstallError("runtime Python is not executable")
    validation = _run_json(
        [str(runtime_python), "-m", "grabowski_coding_agent_router_cli", "validate"]
    )
    if validation.get("valid") is not True:
        raise InstallError("runtime router catalog validation failed")
    if validation.get("catalog_source") != "embedded-runtime":
        raise InstallError("runtime router does not use the embedded catalog")
    return validation


def _verify_installed(target: Path) -> dict[str, Any]:
    recommendation = _run_json(
        [
            str(target),
            "recommend",
            "--task-class",
            "complex-patch",
            "--changed-files",
            "50",
            "--duration-minutes",
            "600",
            "--novelty",
            "high",
            "--need-review",
        ]
    )
    if (
        recommendation.get("decision") != "controller"
        or recommendation.get("controller") != "grabowski-primary"
        or recommendation.get("primary_role") != "direct-writer"
        or recommendation.get("external_primary_writer_forbidden") is not True
        or recommendation.get("automatic_execution_authorized") is not False
    ):
        raise InstallError("installed router does not satisfy direct-first readback")
    return recommendation


def _expected() -> tuple[bytes, bytes, str]:
    wrapper = SOURCE.read_bytes()
    digest = _sha256(wrapper)
    return wrapper, f"{digest}\n".encode("ascii"), digest


def check(target: Path, pin: Path, runtime_python: Path) -> dict[str, Any]:
    wrapper, pin_bytes, digest = _expected()
    target_state = _safe_existing(target)
    pin_state = _safe_existing(pin)
    runtime = _verify_runtime(runtime_python)
    installed = (
        target_state.present
        and target_state.data == wrapper
        and stat.S_IMODE(target_state.mode) == 0o755
        and pin_state.present
        and pin_state.data == pin_bytes
        and stat.S_IMODE(pin_state.mode) == 0o600
    )
    return {
        "schema_version": 1,
        "kind": "coding-agent-router-cli-install-check",
        "installed": installed,
        "wrapper_sha256": digest,
        "runtime_catalog_sha256": runtime.get("catalog_sha256"),
        "runtime_catalog_source": runtime.get("catalog_source"),
        "automatic_execution_authorized": False,
    }


def apply(target: Path, pin: Path, runtime_python: Path) -> dict[str, Any]:
    wrapper, pin_bytes, digest = _expected()
    runtime = _verify_runtime(runtime_python)
    previous_target = _safe_existing(target)
    previous_pin = _safe_existing(pin)
    try:
        _atomic_write(target, wrapper, 0o755)
        _atomic_write(pin, pin_bytes, 0o600)
        recommendation = _verify_installed(target)
    except BaseException:
        errors: list[str] = []
        for path, previous in ((target, previous_target), (pin, previous_pin)):
            try:
                _restore(path, previous)
            except BaseException as exc:
                errors.append(f"{path}:{type(exc).__name__}")
        if errors:
            raise InstallError("router install failed and rollback was incomplete")
        raise
    return {
        "schema_version": 1,
        "kind": "coding-agent-router-cli-install-receipt",
        "status": "installed",
        "wrapper_sha256": digest,
        "runtime_catalog_sha256": runtime.get("catalog_sha256"),
        "runtime_catalog_source": runtime.get("catalog_source"),
        "readback": {
            "decision": recommendation.get("decision"),
            "controller": recommendation.get("controller"),
            "primary_role": recommendation.get("primary_role"),
            "automatic_execution_authorized": recommendation.get(
                "automatic_execution_authorized"
            ),
        },
        "rollback_performed": False,
        "automatic_execution_authorized": False,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    action = result.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--apply", action="store_true")
    result.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    result.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    result.add_argument(
        "--runtime-python", type=Path, default=DEFAULT_RUNTIME_PYTHON
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        output = (
            check(arguments.target, arguments.pin, arguments.runtime_python)
            if arguments.check
            else apply(arguments.target, arguments.pin, arguments.runtime_python)
        )
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "status": "failed",
                    "error": "coding_agent_router_cli_install_failed_closed",
                    "error_type": type(exc).__name__,
                    "automatic_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
