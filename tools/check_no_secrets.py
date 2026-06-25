#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
patterns = [
    ("OpenAI-style API key", re.compile(r"s" + r"k-[A-Za-z0-9_-]{20,}")),
    ("Bearer token", re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}")),
    (
        "private key block",
        re.compile(r"BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY"),
    ),
    (
        "assigned control-plane key",
        re.compile(r"CONTROL_PLANE_API_KEY\s*=\s*[\"']?[A-Za-z0-9._-]{16,}"),
    ),
]
ignored_parts = {".git", "__pycache__", ".venv", ".pytest_cache", ".ruff_cache"}
violations = []
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    if any(part in ignored_parts for part in path.parts):
        continue
    if path == Path(__file__).resolve():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for label, pattern in patterns:
        if pattern.search(text):
            violations.append(f"{path.relative_to(ROOT)}: {label}")
if violations:
    print("Potential secrets detected:")
    for violation in violations:
        print(f"  - {violation}")
    raise SystemExit(1)
print("PASS: no obvious committed secrets detected")
