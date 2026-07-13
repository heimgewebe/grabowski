#!/usr/bin/env python3
"""Run one deterministic Systemkatalog query and emit a bounded Grabowski usage receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

RECEIPT_KIND = "grabowski.systemkatalog_usage_receipt"
RECEIPT_SCHEMA_VERSION = 1
QUERY_RESULT_KIND = "system_catalog_query_result"
QUERY_COMMANDS = {"system", "repository", "truth-owner", "relations", "entrypoints"}
REASONS = {
    "truth_owner",
    "repository_selection",
    "scope_boundary",
    "entrypoint_lookup",
    "relation_lookup",
    "system_overview",
}
RESULT_USES = {"used", "not_used", "unknown"}
DECISION_EFFECTS = {"changed", "confirmed", "none", "unknown"}
ARGUMENT_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
COMMAND_REASON = {
    "system": {"system_overview", "scope_boundary"},
    "repository": {"repository_selection", "scope_boundary"},
    "truth-owner": {"truth_owner"},
    "relations": {"relation_lookup"},
    "entrypoints": {"entrypoint_lookup"},
}


class UsageReceiptError(ValueError):
    pass


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_inputs(command: str, argument: str, reason: str, result_use: str, decision_effect: str) -> None:
    if command not in QUERY_COMMANDS:
        raise UsageReceiptError(f"unsupported query command: {command}")
    if ARGUMENT_RE.fullmatch(argument) is None:
        raise UsageReceiptError("argument must be a bounded Systemkatalog identifier")
    if reason not in REASONS:
        raise UsageReceiptError(f"unsupported consultation reason: {reason}")
    if reason not in COMMAND_REASON[command]:
        raise UsageReceiptError(f"reason {reason} is incompatible with query command {command}")
    if result_use not in RESULT_USES:
        raise UsageReceiptError(f"unsupported result use: {result_use}")
    if decision_effect not in DECISION_EFFECTS:
        raise UsageReceiptError(f"unsupported decision effect: {decision_effect}")
    if decision_effect in {"changed", "confirmed"} and result_use != "used":
        raise UsageReceiptError("changed or confirmed decisions require result_use=used")
    if result_use == "not_used" and decision_effect not in {"none", "unknown"}:
        raise UsageReceiptError("not_used results cannot change or confirm a decision")


def _query(root: Path, command: str, argument: str) -> dict[str, Any]:
    root = root.expanduser().resolve()
    script_candidate = root / "scripts/systemkatalog_query.py"
    if script_candidate.is_symlink():
        raise UsageReceiptError("Systemkatalog query script must not be a symlink")
    script = script_candidate.resolve()
    try:
        script.relative_to(root)
    except ValueError as exc:
        raise UsageReceiptError("Systemkatalog query script escapes the configured root") from exc
    if not script.is_file():
        raise UsageReceiptError(f"missing regular Systemkatalog query script: {script}")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        completed = subprocess.run(
            [sys.executable, str(script), command, argument],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise UsageReceiptError("Systemkatalog query timed out after 15 seconds") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "query failed").strip()
        raise UsageReceiptError(f"Systemkatalog query failed: {detail[:500]}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise UsageReceiptError("Systemkatalog query returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise UsageReceiptError("Systemkatalog query result must be an object")
    if value.get("schemaVersion") != 1 or value.get("kind") != QUERY_RESULT_KIND:
        raise UsageReceiptError("Systemkatalog query result identity mismatch")
    if value.get("command") != command:
        raise UsageReceiptError("Systemkatalog query result command mismatch")
    if value.get("catalogRepository") != "heimgewebe/systemkatalog":
        raise UsageReceiptError("Systemkatalog query result repository mismatch")
    commit = value.get("catalogCommit")
    if not isinstance(commit, str) or SHA40_RE.fullmatch(commit) is None:
        raise UsageReceiptError("Systemkatalog query result lacks a valid catalog commit")
    source_paths = value.get("sourcePaths")
    if not isinstance(source_paths, list) or not source_paths or not all(
        isinstance(item, str) and item and not item.startswith("/") and ".." not in Path(item).parts
        for item in source_paths
    ):
        raise UsageReceiptError("Systemkatalog query result source paths are invalid")
    return value


def build_receipt(
    *,
    systemkatalog_root: Path,
    command: str,
    argument: str,
    reason: str,
    result_use: str,
    decision_effect: str,
) -> dict[str, Any]:
    _validate_inputs(command, argument, reason, result_use, decision_effect)
    query_result = _query(systemkatalog_root, command, argument)
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "systemkatalog": {
            "repository": query_result["catalogRepository"],
            "commit": query_result["catalogCommit"],
            "query": {"command": command, "argument": argument},
            "query_result_sha256": _sha256_json(query_result),
            "source_paths": query_result["sourcePaths"],
        },
        "usage": {
            "consulted": True,
            "reason": reason,
            "result_use": result_use,
            "decision_effect": decision_effect,
            "usage_evidence": "operator_declared",
        },
        "query_result": query_result,
        "does_not_establish": [
            "decision_causality",
            "semantic_truth_beyond_the_bound_catalog_commit",
            "task_priority",
            "runtime_health",
            "merge_readiness",
        ],
    }
    receipt["receipt_sha256"] = _sha256_json(receipt)
    return receipt


def _write_atomic(path: Path, encoded: bytes) -> None:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise UsageReceiptError("output path must not be a symlink")
    parent = candidate.parent.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / candidate.name
    if target.exists() and not target.is_file():
        raise UsageReceiptError("output path must be a regular file")
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    tmp = Path(raw_tmp)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        os.chmod(target, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--systemkatalog-root",
        type=Path,
        default=Path(os.environ.get("SYSTEMKATALOG_ROOT", "/home/alex/repos/systemkatalog")),
    )
    parser.add_argument("--query", required=True, choices=sorted(QUERY_COMMANDS))
    parser.add_argument("--argument", required=True)
    parser.add_argument("--reason", required=True, choices=sorted(REASONS))
    parser.add_argument("--result-use", required=True, choices=sorted(RESULT_USES))
    parser.add_argument("--decision-effect", required=True, choices=sorted(DECISION_EFFECTS))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        receipt = build_receipt(
            systemkatalog_root=args.systemkatalog_root,
            command=args.query,
            argument=args.argument,
            reason=args.reason,
            result_use=args.result_use,
            decision_effect=args.decision_effect,
        )
    except UsageReceiptError as exc:
        parser.error(str(exc))
    encoded = (json.dumps(receipt, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if args.output is not None:
        _write_atomic(args.output, encoded)
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
