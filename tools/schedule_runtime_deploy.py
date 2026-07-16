#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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


def _load_runtime_scheduler() -> Callable[[str, int, str | None, str | None], dict[str, Any]]:
    source = str(SRC)
    if source not in sys.path:
        sys.path.insert(0, source)
    from grabowski_self_deploy import grabowski_runtime_deploy_schedule

    return grabowski_runtime_deploy_schedule


def schedule(
    expected_head: str,
    delay_seconds: int,
    source_repository: str | None = None,
    source_lease_owner_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(expected_head, str) or not OBJECT_ID_RE.fullmatch(expected_head):
        raise ValueError("expected_head must be a lowercase Git object ID")
    if not isinstance(delay_seconds, int) or isinstance(delay_seconds, bool) or not 5 <= delay_seconds <= 60:
        raise ValueError("delay_seconds must be between 5 and 60")
    if source_repository is not None:
        if (
            not isinstance(source_repository, str)
            or not source_repository
            or len(source_repository.encode("utf-8")) > 4096
            or not Path(source_repository).is_absolute()
        ):
            raise ValueError("source_repository must be a bounded absolute path")
    if source_lease_owner_id is not None and re.fullmatch(
        r"[A-Za-z0-9._:@-]{1,128}", source_lease_owner_id
    ) is None:
        raise ValueError("source_lease_owner_id is invalid")
    result = _load_runtime_scheduler()(
        expected_head,
        delay_seconds,
        source_repository,
        source_lease_owner_id,
    )
    if not isinstance(result, dict):
        raise RuntimeError("runtime deploy scheduler returned a non-object receipt")
    identity = result.get("source_identity")
    identity_sha256 = result.get("source_identity_sha256")
    if not isinstance(identity, dict):
        raise RuntimeError("runtime deploy scheduler returned an unbound receipt")
    identity_material = {
        key: value for key, value in identity.items() if key != "identity_sha256"
    }
    computed_identity_sha256 = hashlib.sha256(
        json.dumps(
            identity_material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if (
        result.get("scheduled") is not True
        or result.get("expected_head") != expected_head
        or identity.get("head") != expected_head
        or identity.get("identity_sha256") != identity_sha256
        or computed_identity_sha256 != identity_sha256
    ):
        raise RuntimeError("runtime deploy scheduler returned an unbound receipt")
    if source_repository is not None and identity.get("repository") != source_repository:
        raise RuntimeError("runtime deploy scheduler returned a different source repository")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--delay-seconds", type=int, default=8)
    parser.add_argument("--source-repository")
    parser.add_argument("--source-lease-owner-id")
    args = parser.parse_args()
    try:
        emit(
            schedule(
                args.expected_head,
                args.delay_seconds,
                args.source_repository,
                args.source_lease_owner_id,
            )
        )
        return 0
    except Exception as exc:
        emit({"scheduled": False, "error_type": type(exc).__name__, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
