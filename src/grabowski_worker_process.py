from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise PermissionError("worker config may not be a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128 * 1024:
        raise ValueError("worker config must be a bounded regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema_version", "kind", "argv", "environment", "xvfb_argv"}:
        raise ValueError("worker config contract mismatch")
    if value["schema_version"] != 1 or value["kind"] not in {"browser", "gui"}:
        raise ValueError("unsupported worker config")
    if not isinstance(value["argv"], list) or not value["argv"] or not all(
        isinstance(item, str) and item and "\x00" not in item for item in value["argv"]
    ):
        raise ValueError("invalid worker argv")
    if not isinstance(value["environment"], dict) or not all(
        isinstance(key, str)
        and isinstance(item, str)
        and "\x00" not in key
        and "\x00" not in item
        for key, item in value["environment"].items()
    ):
        raise ValueError("invalid worker environment")
    if value["kind"] == "browser" and value["xvfb_argv"] is not None:
        raise ValueError("browser worker may not configure Xvfb")
    if value["kind"] == "gui" and not (
        isinstance(value["xvfb_argv"], list)
        and value["xvfb_argv"]
        and all(isinstance(item, str) and item and "\x00" not in item for item in value["xvfb_argv"])
    ):
        raise ValueError("GUI worker requires Xvfb argv")
    return value


def _environment(extra: dict[str, str]) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(extra)
    return environment


def _browser(config: dict[str, Any]) -> int:
    os.execvpe(config["argv"][0], config["argv"], _environment(config["environment"]))
    return 127


def _gui(config: dict[str, Any]) -> int:
    environment = _environment(config["environment"])
    xvfb = subprocess.Popen(
        config["xvfb_argv"],
        stdin=subprocess.DEVNULL,
        stdout=sys.stdout,
        stderr=sys.stderr,
        env=environment,
        start_new_session=False,
    )
    child: subprocess.Popen[bytes] | None = None

    def terminate(signum: int, _frame: object) -> None:
        if child is not None and child.poll() is None:
            child.send_signal(signum)
        if xvfb.poll() is None:
            xvfb.send_signal(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, terminate)
    try:
        deadline = time.monotonic() + 10
        socket_path = Path("/tmp/.X11-unix") / f"X{environment['DISPLAY'].lstrip(':')}"
        while time.monotonic() < deadline:
            if xvfb.poll() is not None:
                raise RuntimeError("Xvfb exited before display readiness")
            if socket_path.exists():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Xvfb display readiness timed out")
        child = subprocess.Popen(
            config["argv"],
            stdin=subprocess.DEVNULL,
            stdout=sys.stdout,
            stderr=sys.stderr,
            env=environment,
            start_new_session=False,
        )
        return child.wait()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if xvfb.poll() is None:
            xvfb.terminate()
            try:
                xvfb.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xvfb.kill()
                xvfb.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one isolated Grabowski worker process")
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    config = _load(Path(arguments.config).expanduser().resolve(strict=True))
    if config["kind"] == "browser":
        return _browser(config)
    return _gui(config)


if __name__ == "__main__":
    raise SystemExit(main())
