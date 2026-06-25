#!/usr/bin/env python3

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "requirements" / "runtime.in"
LOCK = ROOT / "requirements" / "runtime.lock.txt"
PIN = re.compile(r"^[A-Za-z0-9_.-]+==[^\s\\]+(?:\s*\\)?$")


def logical_blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    current: list[str] = []

    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw[:1].isspace():
            if not current:
                raise SystemExit(
                    f"Continuation without requirement in {LOCK}: {raw!r}"
                )
            current.append(stripped)
            continue
        if current:
            blocks.append(current)
        current = [stripped]

    if current:
        blocks.append(current)
    return blocks


def main() -> int:
    if not INPUT.is_file():
        raise SystemExit(f"Missing runtime input: {INPUT}")
    if not LOCK.is_file():
        raise SystemExit(f"Missing runtime lock: {LOCK}")

    input_lines = [
        line.strip()
        for line in INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if input_lines != ["mcp==1.27.2"]:
        raise SystemExit(
            "runtime.in must contain the single reviewed direct pin "
            "mcp==1.27.2"
        )

    blocks = logical_blocks(LOCK.read_text(encoding="utf-8"))
    if not blocks:
        raise SystemExit("Runtime lock contains no requirements")

    names: set[str] = set()
    for block in blocks:
        requirement = block[0]
        if requirement.startswith(("-e ", "git+", "http://", "https://")):
            raise SystemExit(f"Untrusted runtime requirement: {requirement}")
        if not PIN.match(requirement):
            raise SystemExit(f"Runtime requirement is not exactly pinned: {requirement}")
        if not any(line.startswith("--hash=sha256:") for line in block[1:]):
            raise SystemExit(f"Runtime requirement lacks SHA-256 hashes: {requirement}")
        names.add(requirement.split("==", 1)[0].lower().replace("_", "-"))

    if "mcp" not in names:
        raise SystemExit("Runtime lock does not contain mcp")

    print(f"PASS: runtime lock contains {len(blocks)} pinned, hashed packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
