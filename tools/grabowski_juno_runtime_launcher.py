#!/usr/bin/env python3
"""Launch Juno against the current canonical Grabowski runtime, not an old Pop!_OS venv."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

OPERATOR_UNIT = "grabowski-operator.service"
NIXOS_SYSTEMCTL = Path("/run/current-system/sw/bin/systemctl")
NIXOS_PYTHON = Path("/run/current-system/sw/bin/python3")
SERVICE_SCRIPT = "grabowski_juno_openai_gateway.py"


def _parse_operator_package(value: str, *, store_root: Path = Path("/nix/store")) -> Path:
    """Accept only the executable advertised by the active NixOS system service."""
    match = re.fullmatch(r"\{ path=([^\s;]+) ; argv\[\]=[^\n]+", value.strip())
    if match is None:
        raise RuntimeError("cannot resolve the canonical Grabowski systemd ExecStart")
    executable = Path(match.group(1))
    package = executable.parent.parent
    if (
        executable.parent.name != "bin"
        or executable.name != "grabowski-operator"
        or package.parent != store_root
        or re.fullmatch(r"[a-z0-9]{32}-grabowski-operator-[A-Za-z0-9._+-]+", package.name) is None
    ):
        raise RuntimeError("Grabowski systemd ExecStart is not a pinned Nix-store operator")
    return package


def _runtime_from_nixos() -> tuple[Path, Path]:
    result = subprocess.run(
        [str(NIXOS_SYSTEMCTL), "show", OPERATOR_UNIT,
         "--property=ExecStart", "--value", "--no-pager"],
        capture_output=True, text=True, timeout=8, check=True,
    )
    package = _parse_operator_package(result.stdout)
    python = package / "bin/python3"
    candidates = list((package / "lib").glob("python3.*/site-packages"))
    if len(candidates) != 1 or not python.is_file():
        raise RuntimeError("active Grabowski runtime has no unique Nix Python environment")
    site = candidates[0]
    if not (site / "grabowski_coding_agent_router.py").is_file():
        raise RuntimeError("active Grabowski runtime lacks its coding-agent router")
    if not (site / "grabowski_coding_agent_router_cli.py").is_file():
        raise RuntimeError("active Grabowski runtime lacks its probe CLI")
    return python, site


def _runtime_from_legacy() -> tuple[Path, Path]:
    root = Path.home() / ".local/share/grabowski-mcp"
    python = root / ".venv/bin/python"
    site = root / "inputs/src"
    if not python.is_file() or not (site / "grabowski_coding_agent_router.py").is_file():
        raise RuntimeError("legacy Grabowski runtime is unavailable")
    return python, site


def _command(mode: str, *, python: Path, site: Path) -> tuple[list[str], dict[str, str]]:
    if mode not in {"serve", "probe"}:
        raise ValueError("supported modes are serve and probe")
    home = Path.home()
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(site)
    environment["PATH"] = os.pathsep.join(
        [str(home / ".nix-profile/bin"), str(home / ".local/bin"),
         "/run/current-system/sw/bin", "/usr/local/bin", "/usr/bin", "/bin"]
    )
    if mode == "probe":
        argv = [str(python), "-m", "grabowski_coding_agent_router_cli", "probe"]
    else:
        gateway = home / ".local/libexec/grabowski" / SERVICE_SCRIPT
        argv = [str(python), str(gateway), "--host", "127.0.0.1",
                "--port", "18195", "--token-file",
                str(home / ".local/state/grabowski/juno-openai-gateway/token")]
    return argv, environment


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in {"serve", "probe"}:
        raise SystemExit("usage: grabowski_juno_runtime_launcher.py {serve|probe}")
    try:
        if NIXOS_PYTHON.is_file():
            python, site = _runtime_from_nixos()
        else:
            python, site = _runtime_from_legacy()
        command, environment = _command(args[0], python=python, site=site)
        os.execve(command[0], command, environment)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Juno runtime unavailable: {type(error).__name__}: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
