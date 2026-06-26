#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fingerprint(names):
    raw = json.dumps(sorted(names), separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tools", nargs="*")
    parser.add_argument("--observed-file")
    args = parser.parse_args()
    if args.observed_file:
        observed = json.loads(Path(args.observed_file).read_text(encoding="utf-8"))
        if not isinstance(observed, list) or not all(isinstance(item, str) for item in observed):
            raise ValueError("observed file must contain a JSON string list")
    else:
        observed = args.tools
    if not observed:
        raise ValueError("at least one observed tool is required")
    expected = json.loads(
        (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
    )["expected_tools"]
    result = {
        "matches": set(expected) == set(observed),
        "expected_count": len(expected),
        "observed_count": len(observed),
        "expected_sha256": fingerprint(expected),
        "observed_sha256": fingerprint(observed),
        "missing_from_connector": sorted(set(expected) - set(observed)),
        "unexpected_in_connector": sorted(set(observed) - set(expected)),
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
