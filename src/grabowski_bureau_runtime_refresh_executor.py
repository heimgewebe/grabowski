from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
from typing import Any

SCHEMA_VERSION = 1
RESERVED_TASK_COMMAND = "grabowski-bureau-runtime-refresh-apply"
EXECUTOR_MODULE = "grabowski_bureau_runtime_refresh_executor"
CANONICAL_BUREAU_REFRESH = Path("/home/alex/.local/bin/bureau-runtime-refresh")
CANONICAL_FINDMNT = Path("/usr/bin/findmnt")
CANONICAL_STATE_ROOT = Path("/home/alex/.local/state/bureau/runtime-refresh")
CANONICAL_BUREAU_STATE_DB = Path("/home/alex/.local/state/bureau/bureau.sqlite3")
CANONICAL_INTENTS_ROOT = CANONICAL_STATE_ROOT / "intents"
MAX_INTENT_BYTES = 256 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
OWNER_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
INTENT_MUTATION_ROOT_FIELDS = (
    "prefix",
    "bin_dir",
    "libexec_dir",
    "user_unit_dir",
    "runtime_user_unit_dir",
    "state_root",
)
EXPECTED_RUNTIME_EXECUTION_CONTEXT = {
    "schema_version": 1,
    "kind": "grabowski_bureau_runtime_refresh_execution_context",
    "executor_tool": "grabowski_task_start",
    "reserved_command": RESERVED_TASK_COMMAND,
    "host": "heim-pc",
    "cwd": "/home/alex",
    "execution_backend": "systemd-user",
    "resume_policy": "never",
    "writability_evidence": ["findmnt", "statvfs", "os.access"],
    "required_writable_intent_roots": list(INTENT_MUTATION_ROOT_FIELDS),
    "directory_access": ["W_OK", "X_OK"],
    "forbid_generic_surfaces": [
        "grabowski_terminal_run",
        "grabowski_job_start",
        "grabowski_fleet_run",
        "grabowski_task_start:direct-apply",
    ],
}


class BureauRuntimeRefreshExecutorError(RuntimeError):
    pass


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _bureau_payload_digest(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return hashlib.sha256(_canonical_json_bytes(payload) + b"\n").hexdigest()


def is_reserved_task_request(argv: list[str]) -> bool:
    return bool(argv) and argv[0] == RESERVED_TASK_COMMAND


def _python_module_command(argv: list[str], module: str) -> bool:
    if len(argv) < 3 or Path(argv[0]).name not in {"python", "python3"}:
        return False
    return argv[1:3] == ["-m", module]


def is_executor_module_command(argv: list[str]) -> bool:
    return _python_module_command(argv, EXECUTOR_MODULE)


def is_direct_bureau_runtime_refresh_apply(argv: list[str]) -> bool:
    if not argv:
        return False
    if Path(argv[0]).name == "bureau-runtime-refresh":
        return "apply" in argv[1:]
    if _python_module_command(argv, "bureau.runtime_refresh"):
        return "apply" in argv[3:]
    return False


def _looks_like_wrapped_bureau_runtime_refresh_apply(argv: list[str]) -> bool:
    if not argv:
        return False
    material = "\n".join(argv)
    if not any(
        marker in material
        for marker in ("bureau-runtime-refresh", "bureau.runtime_refresh", "runtime_refresh")
    ):
        return False
    return (
        re.search(r"(?<![A-Za-z0-9_-])apply(?![A-Za-z0-9_-])", material) is not None
        or "apply_runtime_refresh" in material
    )


def reject_generic_runtime_refresh_execution(argv: list[str], *, surface: str) -> None:
    if is_reserved_task_request(argv):
        raise PermissionError(
            f"{RESERVED_TASK_COMMAND} is reserved for grabowski_task_start; "
            f"surface {surface} may not execute it directly"
        )
    if is_executor_module_command(argv):
        raise PermissionError(
            f"{EXECUTOR_MODULE} is reserved for grabowski_task_start durable execution; "
            f"surface {surface} may not execute it directly"
        )
    if is_direct_bureau_runtime_refresh_apply(argv) or _looks_like_wrapped_bureau_runtime_refresh_apply(argv):
        raise PermissionError(
            "direct bureau-runtime-refresh apply is blocked on generic Grabowski execution "
            f"surface {surface}; use grabowski_task_start with the reserved "
            f"{RESERVED_TASK_COMMAND} request"
        )


def _executor_parser(*, prog: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, add_help=False)
    parser.add_argument("--intent", required=True)
    parser.add_argument("--expected-intent-sha256", required=True)
    parser.add_argument("--lease-owner", required=True)
    parser.add_argument("--lease-task-id", required=True)
    return parser


def parse_reserved_task_request(argv: list[str]) -> dict[str, str]:
    if not is_reserved_task_request(argv):
        raise BureauRuntimeRefreshExecutorError("reserved executor command is required")
    try:
        parsed = _executor_parser(prog=RESERVED_TASK_COMMAND).parse_args(argv[1:])
    except SystemExit as exc:
        raise BureauRuntimeRefreshExecutorError("executor request arguments are invalid") from exc
    return _validate_request_values(
        intent=parsed.intent,
        expected_intent_sha256=parsed.expected_intent_sha256,
        lease_owner=parsed.lease_owner,
        lease_task_id=parsed.lease_task_id,
    )


def parse_executor_module_request(argv: list[str]) -> dict[str, str]:
    if not is_executor_module_command(argv):
        raise BureauRuntimeRefreshExecutorError("executor module command is required")
    try:
        parsed = _executor_parser(prog=EXECUTOR_MODULE).parse_args(argv[3:])
    except SystemExit as exc:
        raise BureauRuntimeRefreshExecutorError("executor module arguments are invalid") from exc
    return _validate_request_values(
        intent=parsed.intent,
        expected_intent_sha256=parsed.expected_intent_sha256,
        lease_owner=parsed.lease_owner,
        lease_task_id=parsed.lease_task_id,
    )


def _validate_request_values(
    *, intent: str, expected_intent_sha256: str, lease_owner: str, lease_task_id: str
) -> dict[str, str]:
    if SHA256_RE.fullmatch(expected_intent_sha256) is None:
        raise BureauRuntimeRefreshExecutorError("expected intent SHA-256 is invalid")
    if OWNER_RE.fullmatch(lease_owner) is None:
        raise BureauRuntimeRefreshExecutorError("lease owner is invalid")
    if not lease_task_id or len(lease_task_id.encode("utf-8")) > 256 or "\x00" in lease_task_id:
        raise BureauRuntimeRefreshExecutorError("lease task id is invalid")
    path = Path(intent).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise BureauRuntimeRefreshExecutorError("intent path must be absolute and normalized")
    resolved = path.resolve(strict=False)
    if resolved.parent != CANONICAL_INTENTS_ROOT or resolved.name != f"{expected_intent_sha256}.json":
        raise BureauRuntimeRefreshExecutorError("intent path is outside the canonical digest-bound root")
    return {
        "intent": str(resolved),
        "expected_intent_sha256": expected_intent_sha256,
        "lease_owner": lease_owner,
        "lease_task_id": lease_task_id,
    }


def load_bound_intent(request: dict[str, str]) -> dict[str, Any]:
    path = Path(request["intent"])
    try:
        linked = path.lstat()
    except OSError as exc:
        raise BureauRuntimeRefreshExecutorError("intent is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or linked.st_size > MAX_INTENT_BYTES
        or linked.st_mode & 0o022
    ):
        raise BureauRuntimeRefreshExecutorError("intent file identity is unsafe")
    try:
        raw = path.read_bytes()
        after = path.lstat()
        intent = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BureauRuntimeRefreshExecutorError("intent is unreadable or malformed") from exc
    if (
        after.st_dev != linked.st_dev
        or after.st_ino != linked.st_ino
        or after.st_size != linked.st_size
        or after.st_mtime_ns != linked.st_mtime_ns
        or after.st_ctime_ns != linked.st_ctime_ns
    ):
        raise BureauRuntimeRefreshExecutorError("intent changed during read")
    if not isinstance(intent, dict):
        raise BureauRuntimeRefreshExecutorError("intent payload is not an object")
    expected = request["expected_intent_sha256"]
    if intent.get("intent_sha256") != expected:
        raise BureauRuntimeRefreshExecutorError("intent self identity differs from requested digest")
    if _bureau_payload_digest(intent, "intent_sha256") != expected:
        raise BureauRuntimeRefreshExecutorError("intent SHA-256 does not match payload")
    if intent.get("kind") != "bureau_runtime_refresh_intent" or intent.get("schema_version") != 1:
        raise BureauRuntimeRefreshExecutorError("intent contract is unsupported")
    if intent.get("state_root") != str(CANONICAL_STATE_ROOT):
        raise BureauRuntimeRefreshExecutorError("intent state root is noncanonical")
    if intent.get("approval_task_id") != request["lease_task_id"]:
        raise BureauRuntimeRefreshExecutorError("lease task id differs from intent authority")
    prefix = intent.get("prefix")
    main_commit = intent.get("main_commit")
    target_sha256 = intent.get("target_sha256")
    if not isinstance(prefix, str) or not Path(prefix).is_absolute():
        raise BureauRuntimeRefreshExecutorError("intent runtime prefix is invalid")
    if not isinstance(main_commit, str) or SHA40_RE.fullmatch(main_commit) is None:
        raise BureauRuntimeRefreshExecutorError("intent main commit is invalid")
    if not isinstance(target_sha256, str) or SHA256_RE.fullmatch(target_sha256) is None:
        raise BureauRuntimeRefreshExecutorError("intent target digest is invalid")
    return intent


def validate_authority_execution_contract(intent: dict[str, Any]) -> dict[str, Any]:
    authority_state = intent.get("authority_state_store")
    authority_task = intent.get("authority_task_spec")
    if not isinstance(authority_state, dict) or not isinstance(authority_task, dict):
        raise BureauRuntimeRefreshExecutorError("intent authority binding is missing")
    if authority_state.get("state_db") != str(CANONICAL_BUREAU_STATE_DB):
        raise BureauRuntimeRefreshExecutorError("intent authority StateStore path is noncanonical")
    expected_revision = authority_task.get("revision")
    expected_sha = authority_task.get("spec_sha256")
    task_id = intent.get("approval_task_id")
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 1
        or not isinstance(expected_sha, str)
        or SHA256_RE.fullmatch(expected_sha) is None
        or not isinstance(task_id, str)
        or not task_id
    ):
        raise BureauRuntimeRefreshExecutorError("intent authority revision binding is invalid")
    try:
        linked = CANONICAL_BUREAU_STATE_DB.lstat()
    except OSError as exc:
        raise BureauRuntimeRefreshExecutorError("Bureau StateStore is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or linked.st_mode & 0o022
    ):
        raise BureauRuntimeRefreshExecutorError("Bureau StateStore identity is unsafe")
    try:
        connection = sqlite3.connect(
            f"file:{CANONICAL_BUREAU_STATE_DB}?mode=ro", uri=True, timeout=5
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute(
                "SELECT p.current_revision AS current_revision, p.spec_sha256 AS pointer_sha256, "
                "r.revision AS revision, r.spec_sha256 AS revision_sha256, r.spec_json AS spec_json "
                "FROM task_specs p JOIN task_spec_revisions r "
                "ON r.task_id=p.task_id AND r.revision=p.current_revision WHERE p.task_id=?",
                (task_id,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise BureauRuntimeRefreshExecutorError("Bureau StateStore task read failed") from exc
    if row is None:
        raise BureauRuntimeRefreshExecutorError("runtime-refresh authority is absent from StateStore")
    if (
        row["current_revision"] != expected_revision
        or row["revision"] != expected_revision
        or row["pointer_sha256"] != expected_sha
        or row["revision_sha256"] != expected_sha
    ):
        raise BureauRuntimeRefreshExecutorError("runtime-refresh authority revision drifted")
    try:
        spec = json.loads(str(row["spec_json"]))
    except (TypeError, json.JSONDecodeError) as exc:
        raise BureauRuntimeRefreshExecutorError("runtime-refresh authority TaskSpec is malformed") from exc
    if not isinstance(spec, dict) or spec.get("id") != task_id:
        raise BureauRuntimeRefreshExecutorError("runtime-refresh authority TaskSpec identity drifted")
    if _sha256_json(spec) != expected_sha:
        raise BureauRuntimeRefreshExecutorError("runtime-refresh authority TaskSpec digest drifted")
    metadata = spec.get("metadata")
    contract = metadata.get("runtime_execution_context") if isinstance(metadata, dict) else None
    if contract != EXPECTED_RUNTIME_EXECUTION_CONTEXT:
        raise BureauRuntimeRefreshExecutorError("runtime-refresh execution-context contract is missing or mismatched")
    return {
        "schema_version": SCHEMA_VERSION,
        "task_id": task_id,
        "revision": expected_revision,
        "spec_sha256": expected_sha,
        "contract": contract,
        "execution_contract_sha256": _sha256_json(contract),
    }


def build_executor_command(request: dict[str, str], *, runtime_python: Path) -> list[str]:
    if not runtime_python.is_file() or not os.access(runtime_python, os.X_OK):
        raise BureauRuntimeRefreshExecutorError("installed Grabowski runtime Python is unavailable")
    return [
        str(runtime_python),
        "-m",
        EXECUTOR_MODULE,
        "--intent",
        request["intent"],
        "--expected-intent-sha256",
        request["expected_intent_sha256"],
        "--lease-owner",
        request["lease_owner"],
        "--lease-task-id",
        request["lease_task_id"],
    ]


def operation_identity(
    request: dict[str, str], intent: dict[str, Any], authority_contract: dict[str, Any]
) -> dict[str, str]:
    scope = {
        "schema_version": SCHEMA_VERSION,
        "intent_sha256": request["expected_intent_sha256"],
        "target_sha256": intent["target_sha256"],
        "prefix": str(Path(intent["prefix"]).resolve(strict=False)),
        "state_root": intent["state_root"],
        "lease_owner": request["lease_owner"],
        "lease_task_id": request["lease_task_id"],
        "execution_contract_sha256": authority_contract["execution_contract_sha256"],
    }
    return {
        "repository_head": intent["main_commit"],
        "source_fingerprint_sha256": request["expected_intent_sha256"],
        "purpose": f"Bureau runtime refresh apply {request['expected_intent_sha256'][:16]}",
        "scope_sha256": _sha256_json(scope),
    }


def _intent_mutation_roots(intent: dict[str, Any]) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for field in INTENT_MUTATION_ROOT_FIELDS:
        value = intent.get(field)
        if not isinstance(value, str) or not value or "\x00" in value:
            raise BureauRuntimeRefreshExecutorError(
                f"intent mutation root {field} is missing or invalid"
            )
        path = Path(value).expanduser()
        if not path.is_absolute() or ".." in path.parts:
            raise BureauRuntimeRefreshExecutorError(
                f"intent mutation root {field} is not absolute and normalized"
            )
        roots[field] = path.resolve(strict=False)
    return roots


def _probe_writable_directory(field: str, path: Path) -> dict[str, Any]:
    try:
        linked = path.lstat()
        filesystem = os.statvfs(path)
        writable = os.access(path, os.W_OK)
        searchable = os.access(path, os.X_OK)
        probe = subprocess.run(
            [str(CANONICAL_FINDMNT), "--json", "-T", str(path), "-o", "TARGET,FSTYPE,OPTIONS"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BureauRuntimeRefreshExecutorError(
            f"runtime mutation root {field} writability is unobservable"
        ) from exc
    try:
        document = json.loads(probe.stdout) if probe.returncode == 0 else None
        filesystems = document.get("filesystems") if isinstance(document, dict) else None
        mount = filesystems[0] if isinstance(filesystems, list) and len(filesystems) == 1 else None
        options = mount.get("options") if isinstance(mount, dict) else None
        option_set = (
            {item.strip() for item in options.split(",")}
            if isinstance(options, str)
            else set()
        )
    except (json.JSONDecodeError, AttributeError) as exc:
        raise BureauRuntimeRefreshExecutorError(
            f"findmnt result for runtime mutation root {field} is malformed"
        ) from exc
    is_directory = stat.S_ISDIR(linked.st_mode) and not stat.S_ISLNK(linked.st_mode)
    filesystem_read_only = bool(filesystem.f_flag & os.ST_RDONLY)
    mount_rw = "rw" in option_set and "ro" not in option_set
    evidence = {
        "field": field,
        "path": str(path),
        "is_directory": is_directory,
        "filesystem_flags": int(filesystem.f_flag),
        "filesystem_read_only": filesystem_read_only,
        "path_writable": bool(writable),
        "path_searchable": bool(searchable),
        "mount_target": mount.get("target") if isinstance(mount, dict) else None,
        "mount_fstype": mount.get("fstype") if isinstance(mount, dict) else None,
        "mount_options": sorted(option_set),
        "mount_rw": mount_rw,
    }
    evidence["writable"] = bool(
        is_directory
        and not filesystem_read_only
        and writable
        and searchable
        and mount_rw
    )
    return evidence


def execution_context_preflight(
    request: dict[str, str], intent: dict[str, Any], authority_contract: dict[str, Any]
) -> dict[str, Any]:
    roots = _intent_mutation_roots(intent)
    root_evidence = {
        field: _probe_writable_directory(field, path)
        for field, path in roots.items()
    }
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_runtime_refresh_execution_context_preflight",
        "intent_sha256": request["expected_intent_sha256"],
        "approval_task_id": intent["approval_task_id"],
        "target_sha256": intent["target_sha256"],
        "authority_revision": authority_contract["revision"],
        "authority_spec_sha256": authority_contract["spec_sha256"],
        "execution_contract_sha256": authority_contract["execution_contract_sha256"],
        "mutation_roots": root_evidence,
        "writable": all(item["writable"] is True for item in root_evidence.values()),
    }
    evidence["execution_context_sha256"] = _sha256_json(evidence)
    if evidence["writable"] is not True:
        blocked = sorted(
            field for field, item in root_evidence.items() if item["writable"] is not True
        )
        raise BureauRuntimeRefreshExecutorError(
            "runtime mutation roots are not writable in the durable task execution context: "
            + ",".join(blocked)
            + ":"
            + evidence["execution_context_sha256"]
        )
    return evidence


def _validate_bureau_launcher() -> Path:
    path = CANONICAL_BUREAU_REFRESH
    try:
        linked = path.lstat()
    except OSError as exc:
        raise BureauRuntimeRefreshExecutorError("Bureau runtime-refresh launcher is unavailable") from exc
    if (
        stat.S_ISLNK(linked.st_mode)
        or not stat.S_ISREG(linked.st_mode)
        or linked.st_uid != os.getuid()
        or linked.st_mode & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise BureauRuntimeRefreshExecutorError("Bureau runtime-refresh launcher identity is unsafe")
    return path


def main(argv: list[str] | None = None) -> int:
    raw = [sys.executable, "-m", EXECUTOR_MODULE, *(sys.argv[1:] if argv is None else argv)]
    try:
        request = parse_executor_module_request(raw)
        intent = load_bound_intent(request)
        authority_contract = validate_authority_execution_contract(intent)
        evidence = execution_context_preflight(request, intent, authority_contract)
        launcher = _validate_bureau_launcher()
    except BureauRuntimeRefreshExecutorError as exc:
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "kind": "grabowski_bureau_runtime_refresh_executor_failure",
                    "status": "blocked_before_apply",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 2
    print(json.dumps(evidence, sort_keys=True), flush=True)
    os.execv(
        str(launcher),
        [
            str(launcher),
            "--state-root",
            intent["state_root"],
            "apply",
            "--intent",
            request["intent"],
            "--lease-owner",
            request["lease_owner"],
            "--lease-task-id",
            request["lease_task_id"],
        ],
    )
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
