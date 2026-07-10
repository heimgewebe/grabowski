#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable

OBJECT_ID_RE = re.compile(r"[0-9a-f]{40,64}")
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


def _load_runtime_scheduler() -> Callable[[str, int], dict[str, Any]]:
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    from grabowski_self_deploy import grabowski_runtime_deploy_schedule

    return grabowski_runtime_deploy_schedule


def schedule(expected_head: str, delay_seconds: int) -> dict[str, Any]:
    if not isinstance(expected_head, str) or not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if not isinstance(delay_seconds, int) or isinstance(delay_seconds, bool) or not 5 <= delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 5 and 60")
    result = _load_runtime_scheduler()(expected_head, delay_seconds)
    if not isinstance(result, dict):
        raise RuntimeError("runtime deploy scheduler returned a non-object receipt")
    if result.get("scheduled") is not True or result.get("expected_head") != expected_head:
        raise RuntimeError("runtime deploy scheduler returned an unbound receipt")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--delay-seconds", type=int, default=8)
    args = parser.parse_args()
    try:
        emit(schedule(args.expected_head, args.delay_seconds))
        return 0
    except Exception as exc:
        emit({"scheduled": False, "error_type": type(exc).__name__, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
