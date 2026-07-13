from __future__ import annotations

import hashlib
import json
from typing import Any

ARGV_IDENTITY_SCHEMA_VERSION = 1


def canonical_argv_json(argv: Any) -> str:
    """Return the single canonical JSON representation used for task argv identity."""
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list")
    if any(not isinstance(item, str) or not item or "\x00" in item for item in argv):
        raise ValueError("argv entries must be non-empty strings without NUL")
    return json.dumps(argv, ensure_ascii=False, separators=(",", ":"))


def argv_sha256(argv: Any) -> str:
    return hashlib.sha256(canonical_argv_json(argv).encode("utf-8")).hexdigest()
