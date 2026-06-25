#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "access.example.json"
required = {
    "version": int,
    "mode": str,
    "read_roots": list,
    "write_roots": list,
    "write_excluded_roots": list,
    "max_read_bytes": int,
    "max_write_bytes": int,
    "max_list_entries": int,
    "forbid_symlinks": bool,
    "forbidden_components": list,
    "forbidden_file_patterns": list,
    "forbidden_capabilities": list,
}
data = json.loads(POLICY.read_text(encoding="utf-8"))
for key, expected_type in required.items():
    if key not in data:
        raise SystemExit(f"Missing policy field: {key}")
    if not isinstance(data[key], expected_type):
        raise SystemExit(
            f"Invalid type for {key}: {type(data[key]).__name__}, "
            f"expected {expected_type.__name__}"
        )
if data["version"] != 1:
    raise SystemExit("Policy version must be 1.")
if "${HOME}/repos/merges" not in data["write_excluded_roots"]:
    raise SystemExit("${HOME}/repos/merges must remain an explicit write exclusion.")
if "${HOME}/repos" not in data["read_roots"]:
    raise SystemExit("${HOME}/repos must remain readable.")
print("PASS: access.example.json satisfies the repository contract")
