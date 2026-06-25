#!/usr/bin/env python3

from pathlib import Path

from deploy_runtime import (
    DeployError,
    parse_runtime_input,
    parse_runtime_lock,
)


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "requirements" / "runtime.in"
LOCK = ROOT / "requirements" / "runtime.lock.txt"


def main() -> int:
    try:
        direct = parse_runtime_input(INPUT)
        locked = parse_runtime_lock(LOCK)
    except DeployError as exc:
        raise SystemExit(str(exc)) from exc

    missing = sorted(set(direct) - set(locked))
    if missing:
        raise SystemExit(
            "Runtime lock is missing direct pins: " + ", ".join(missing)
        )

    print(f"PASS: runtime lock contains {len(locked)} pinned, hashed packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
