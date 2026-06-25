#!/usr/bin/env python3
"""Prove the deploy-tooling venv holds only the locked + base distributions.

Run with the deploy-tooling venv interpreter so importlib.metadata reflects
exactly what is installed there. Any distribution beyond the lock pins and the
allowed venv base (pip/setuptools/wheel) is rejected.
"""

import importlib.metadata
from pathlib import Path

from deploy_runtime import (
    ALLOWED_VENV_BASE_DISTS,
    DeployError,
    normalize_package_name,
    parse_pinned_lock_file,
)


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements" / "deploy-tooling.lock.txt"


def main() -> int:
    try:
        locked = parse_pinned_lock_file(LOCK, label="Deploy-Tooling-Lockfile")
    except DeployError as exc:
        raise SystemExit(str(exc)) from exc

    installed: dict[str, str] = {}
    for dist in importlib.metadata.distributions():
        name = dist.metadata["Name"] if dist.metadata.get("Name") else None
        if name:
            installed[normalize_package_name(name)] = dist.version

    allowed = set(locked) | ALLOWED_VENV_BASE_DISTS
    unexpected = sorted(set(installed) - allowed)
    if unexpected:
        raise SystemExit(
            "Unerwartete Distributionen in Deploy-Tooling-Venv: "
            + ", ".join(unexpected)
        )
    missing = sorted(set(locked) - set(installed))
    if missing:
        raise SystemExit(
            "Deploy-Tooling-Lockpakete fehlen in der Venv: " + ", ".join(missing)
        )
    mismatched = sorted(
        f"{name}=={installed[name]} != {locked[name]}"
        for name in locked
        if installed.get(name) != locked[name]
    )
    if mismatched:
        raise SystemExit(
            "Deploy-Tooling-Versionen weichen vom Lock ab: " + ", ".join(mismatched)
        )

    print(
        f"PASS: deploy-tooling venv holds exactly {len(locked)} locked "
        "distributions plus the allowed base"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
