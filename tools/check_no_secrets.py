#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
_SECRET_KEY_PREFIX = "s" + "k-"
_OPENAI_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"(?:(?:proj|svcacct|admin)-[A-Za-z0-9._-]{20,}|[A-Za-z0-9]{24,})(?![A-Za-z0-9._-])"
)
_ANTHROPIC_SECRET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    + re.escape(_SECRET_KEY_PREFIX)
    + r"ant-[A-Za-z0-9._-]{20,}(?![A-Za-z0-9._-])"
)
patterns = [
    ("OpenAI-style API key", _OPENAI_SECRET_PATTERN),
    ("Anthropic-style API key", _ANTHROPIC_SECRET_PATTERN),
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
