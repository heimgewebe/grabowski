#!/usr/bin/env python3

from pathlib import Path

from deploy_runtime import (
    DeployError,
    parse_pinned_input_file,
    parse_pinned_lock_file,
    parse_runtime_input,
    parse_runtime_lock,
)


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements"


def _validate_pair(
    name: str,
    input_path: Path,
    lock_path: Path,
    parse_input,
    parse_lock,
) -> int:
    direct = parse_input(input_path)
    locked = parse_lock(lock_path)

    missing = sorted(set(direct) - set(locked))
    if missing:
        raise SystemExit(
            f"{name} lock is missing direct pins: " + ", ".join(missing)
        )
    mismatched = sorted(
        f"{pkg}=={direct[pkg]} != {locked[pkg]}"
        for pkg in direct
        if direct[pkg] != locked[pkg]
    )
    if mismatched:
        raise SystemExit(
            f"{name} lock direct pins differ: " + ", ".join(mismatched)
        )

    print(
        f"PASS: {name} lock pins {len(direct)} direct / "
        f"{len(locked)} total hashed packages"
    )
    return len(locked)


def main() -> int:
    pairs = [
        (
            "runtime",
            REQUIREMENTS / "runtime.in",
            REQUIREMENTS / "runtime.lock.txt",
            parse_runtime_input,
            parse_runtime_lock,
        ),
        (
            "deploy-tooling",
            REQUIREMENTS / "deploy-tooling.in",
            REQUIREMENTS / "deploy-tooling.lock.txt",
            lambda path: parse_pinned_input_file(path, label="Deploy-Tooling-Input"),
            lambda path: parse_pinned_lock_file(path, label="Deploy-Tooling-Lockfile"),
        ),
    ]
    try:
        for name, input_path, lock_path, parse_input, parse_lock in pairs:
            _validate_pair(name, input_path, lock_path, parse_input, parse_lock)
    except DeployError as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
