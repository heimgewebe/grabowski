from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

MAX_INPUT_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 512 * 1024
MAX_TTL_SECONDS = 900
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_root_config(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("broker config must be a regular non-symlink file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RuntimeError("broker config must be root-owned and not group/world writable")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise RuntimeError("broker config exceeds size limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema_version", "actions"}:
        raise RuntimeError("broker config has invalid top-level keys")
    if value["schema_version"] != 1 or not isinstance(value["actions"], dict):
        raise RuntimeError("broker config has unsupported schema")
    return value


def parse_reference(data: bytes, *, now: int | None = None) -> dict[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("privileged reference exceeds input limit")
    value = json.loads(data.decode("utf-8"))
    required = {
        "schema_version", "execution", "may_execute",
        "requires_external_privileged_agent", "replay_policy", "action",
        "target", "justification", "request_id", "created_at_unix",
        "expires_at_unix", "reference_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("privileged reference has invalid keys")
    reference_hash = value["reference_sha256"]
    unsigned = dict(value)
    unsigned.pop("reference_sha256")
    if not isinstance(reference_hash, str) or canonical_sha256(unsigned) != reference_hash:
        raise ValueError("privileged reference hash is invalid")
    if value["schema_version"] != 1:
        raise ValueError("privileged reference schema is unsupported")
    if value["execution"] != "unprivileged-reference-only" or value["may_execute"] is not False:
        raise ValueError("privileged reference execution contract is invalid")
    if value["requires_external_privileged_agent"] is not True:
        raise ValueError("privileged reference does not require a broker")
    if value["replay_policy"] != "single-use-external-broker":
        raise ValueError("privileged reference replay policy is invalid")
    if not isinstance(value["request_id"], str) or not REQUEST_ID.fullmatch(value["request_id"]):
        raise ValueError("privileged reference request_id is invalid")
    if not all(isinstance(value[key], str) and value[key].strip()
               for key in ("action", "target", "justification")):
        raise ValueError("privileged reference strings must be non-empty")
    current = int(time.time()) if now is None else now
    created = value["created_at_unix"]
    expires = value["expires_at_unix"]
    if not isinstance(created, int) or not isinstance(expires, int):
        raise ValueError("privileged reference timestamps are invalid")
    if created > current + 30 or expires < current:
        raise PermissionError("privileged reference is not currently valid")
    if expires <= created or expires - created > MAX_TTL_SECONDS:
        raise ValueError("privileged reference TTL is invalid")
    return value


def resolve_action(config: dict[str, Any], reference: dict[str, Any]) -> tuple[list[str], int]:
    candidate = config["actions"].get(reference["action"])
    if not isinstance(candidate, dict):
        raise PermissionError("privileged action is not configured")
    required = {"enabled", "target_pattern", "argv", "timeout_seconds"}
    if set(candidate) != required or candidate["enabled"] is not True:
        raise PermissionError("privileged action is disabled or malformed")
    pattern = candidate["target_pattern"]
    if not isinstance(pattern, str) or len(pattern) > 500:
        raise ValueError("privileged target pattern is invalid")
    if re.fullmatch(pattern, reference["target"]) is None:
        raise PermissionError("privileged target does not match its contract")
    template = candidate["argv"]
    timeout = candidate["timeout_seconds"]
    if not isinstance(template, list) or not template:
        raise ValueError("privileged argv template is invalid")
    if not all(isinstance(token, str) and token for token in template):
        raise ValueError("privileged argv template is invalid")
    if not isinstance(timeout, int) or not 1 <= timeout <= 3600:
        raise ValueError("privileged timeout is invalid")
    argv = [reference["target"] if token == "{target}" else token for token in template]
    if any("{" in token or "}" in token for token in argv):
        raise ValueError("privileged argv contains an unknown placeholder")
    if not Path(argv[0]).is_absolute():
        raise ValueError("privileged executable must be an absolute path")
    return argv, timeout


def claim_once(state_root: Path, request_id: str) -> Path:
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = state_root / request_id
    descriptor = os.open(
        marker,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    os.close(descriptor)
    return marker
