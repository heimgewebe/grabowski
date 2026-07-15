from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
from typing import Any, Callable, Iterator

CommandRunner = Callable[[Path, list[str]], dict[str, Any]]
LeaseInspector = Callable[[str], dict[str, Any] | None]
FrictionRecorder = Callable[..., dict[str, Any]]
FrictionResolver = Callable[..., dict[str, Any]]

SCHEMA_VERSION = 1
RECEIPT_KIND = "grabowski.worktree_ensure_receipt"
IDEMPOTENCY_KEY_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.:-]{0,127}$")
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SUCCESS_STATES = frozenset({"CREATED", "ALREADY_CORRECT"})
TERMINAL_STATES = frozenset({"CREATED", "ALREADY_CORRECT", "CONFLICT", "REJECTED_BY_LEASE", "NOT_ACCEPTED"})
MAX_RECEIPT_BYTES = 1_048_576


class WorktreeEnsurePreflight(ValueError):
    pass


class WorktreeEnsureAction(RuntimeError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bounded_text(value: Any, limit: int = 2048) -> str:
    text = str(value or "")
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore") + "…"


def _receipt_root() -> Path:
    configured = os.environ.get("GRABOWSKI_WORKTREE_ENSURE_RECEIPT_ROOT")
    if configured:
        return Path(configured).expanduser()
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))).expanduser()
    return state_home / "grabowski" / "grip-receipts" / "worktree-ensure"


def _receipt_paths(idempotency_key: str) -> tuple[Path, Path]:
    digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    root = _receipt_root()
    return root / f"{digest}.json", root / f"{digest}.lock"


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except OSError as exc:
        raise WorktreeEnsureAction(f"receipt directory cannot be inspected: {path}") from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise WorktreeEnsureAction(f"receipt directory must be an owner-controlled directory: {path}")
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise WorktreeEnsureAction(f"receipt directory permissions cannot be secured: {path}") from exc


def _open_regular_nofollow(path: Path, flags: int, mode: int | None = None) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | os.O_CLOEXEC | nofollow, 0o600 if mode is None else mode)
    except OSError as exc:
        raise WorktreeEnsureAction(f"secure receipt file open failed: {path}: {_bounded_text(exc, 512)}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise WorktreeEnsureAction(f"receipt file must be an owner-controlled regular file: {path}")
        os.fchmod(descriptor, 0o600)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def _locked_receipt(idempotency_key: str) -> Iterator[tuple[Path, Any]]:
    receipt_path, lock_path = _receipt_paths(idempotency_key)
    _ensure_private_directory(receipt_path.parent)
    descriptor = _open_regular_nofollow(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        yield receipt_path, lock_handle


def _validate_receipt_shape(value: dict[str, Any], path: Path) -> None:
    if value.get("kind") != RECEIPT_KIND or value.get("schema_version") != SCHEMA_VERSION:
        raise WorktreeEnsureAction(f"durable receipt kind or schema mismatch: {path}")
    state = value.get("state")
    result_state = value.get("result_state")
    if state not in {"intent", "complete"}:
        raise WorktreeEnsureAction(f"durable receipt state is invalid: {path}")
    if state == "intent" and result_state is not None:
        raise WorktreeEnsureAction(f"intent receipt must not carry a terminal result: {path}")
    if state == "complete" and result_state not in TERMINAL_STATES:
        raise WorktreeEnsureAction(f"complete receipt has an invalid result state: {path}")
    for field in ("parameters_sha256", "idempotency_key_sha256"):
        if not isinstance(value.get(field), str) or SHA256_RE.fullmatch(value[field]) is None:
            raise WorktreeEnsureAction(f"durable receipt field {field} is invalid: {path}")
    if not isinstance(value.get("inputs"), dict):
        raise WorktreeEnsureAction(f"durable receipt inputs are invalid: {path}")
    if value.get("post_state") is not None and not isinstance(value.get("post_state"), dict):
        raise WorktreeEnsureAction(f"durable receipt post_state is invalid: {path}")
    if not isinstance(value.get("lease"), dict):
        raise WorktreeEnsureAction(f"durable receipt lease evidence is missing: {path}")
    lifecycle = value.get("lifecycle")
    if lifecycle is not None:
        if not isinstance(lifecycle, dict):
            raise WorktreeEnsureAction(f"durable receipt lifecycle evidence is invalid: {path}")
        if lifecycle.get("automatic_cleanup_authorized") is not False:
            raise WorktreeEnsureAction(f"durable receipt lifecycle cleanup authority is invalid: {path}")
        if lifecycle.get("terminal_decision") != "retain":
            raise WorktreeEnsureAction(f"durable receipt lifecycle decision is invalid: {path}")
    for field in ("created_at_unix", "updated_at_unix"):
        timestamp = value.get(field)
        if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp < 0:
            raise WorktreeEnsureAction(f"durable receipt field {field} is invalid: {path}")


def _read_receipt(path: Path) -> dict[str, Any] | None:
    try:
        descriptor = _open_regular_nofollow(path, os.O_RDONLY)
    except WorktreeEnsureAction as exc:
        if not os.path.lexists(path):
            return None
        raise exc
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if info.st_size > MAX_RECEIPT_BYTES:
            raise WorktreeEnsureAction(f"durable receipt exceeds size limit: {path}")
        raw_bytes = handle.read(MAX_RECEIPT_BYTES + 1)
    if len(raw_bytes) > MAX_RECEIPT_BYTES:
        raise WorktreeEnsureAction(f"durable receipt exceeds size limit: {path}")
    try:
        raw = raw_bytes.decode("utf-8")
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorktreeEnsureAction(f"durable receipt is invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise WorktreeEnsureAction(f"durable receipt must be a JSON object: {path}")
    supplied = value.get("receipt_sha256")
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if not isinstance(supplied, str) or supplied != _sha256_json(material):
        raise WorktreeEnsureAction(f"durable receipt integrity mismatch: {path}")
    _validate_receipt_shape(value, path)
    return value


def _write_receipt(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    material = {key: item for key, item in value.items() if key != "receipt_sha256"}
    material["receipt_sha256"] = _sha256_json(material)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    data = (json.dumps(material, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_RECEIPT_BYTES:
        raise WorktreeEnsureAction("durable receipt exceeds size limit before write")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = _open_regular_nofollow(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return material


def _required_string(parameters: dict[str, Any], name: str) -> str:
    value = parameters.get(name)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise WorktreeEnsurePreflight(f"{name} must be a non-empty trimmed string")
    return value


def _normalize_inputs(parameters: dict[str, Any]) -> dict[str, Any]:
    repo_raw = _required_string(parameters, "repo")
    target_raw = _required_string(parameters, "target_path")
    branch = _required_string(parameters, "branch")
    base_head = _required_string(parameters, "base_head").lower()
    owner = _required_string(parameters, "lease_owner_id")
    idempotency_key = _required_string(parameters, "idempotency_key")
    if IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key) is None:
        raise WorktreeEnsurePreflight("idempotency_key contains unsupported characters or is too long")
    if SHA40_RE.fullmatch(base_head) is None:
        raise WorktreeEnsurePreflight("base_head must be an exact 40-character lowercase commit SHA")

    repo = Path(repo_raw).expanduser().resolve(strict=True)
    if not repo.is_dir():
        raise WorktreeEnsurePreflight("repo must resolve to an existing directory")
    target = Path(target_raw).expanduser()
    if not target.is_absolute():
        raise WorktreeEnsurePreflight("target_path must be absolute")
    target = target.resolve(strict=False)
    repo_parent = repo.parent.resolve(strict=True)
    if target == repo or not target.is_relative_to(repo_parent):
        raise WorktreeEnsurePreflight("target_path must be below the repository parent and differ from repo")
    if not target.parent.exists() or not target.parent.is_dir():
        raise WorktreeEnsurePreflight("target_path parent must already exist")

    return {
        "repo": str(repo),
        "target_path": str(target),
        "branch": branch,
        "base_head": base_head,
        "lease_owner_id": owner,
        "idempotency_key": idempotency_key,
        "required_resource_keys": [f"path:{target}", f"repo:{repo}"],
    }


def _command(runner: CommandRunner, repo: Path, argv: list[str]) -> dict[str, Any]:
    result = runner(repo, argv)
    if not isinstance(result, dict):
        raise WorktreeEnsureAction("command runner returned a non-object result")
    return result


def _returncode(result: dict[str, Any]) -> int:
    try:
        return int(result.get("returncode", 1))
    except (TypeError, ValueError):
        return 1


def _stdout(result: dict[str, Any]) -> str:
    value = result.get("stdout", "")
    return value if isinstance(value, str) else ""


def _command_error(result: dict[str, Any]) -> str:
    return _bounded_text(result.get("stderr") or result.get("stdout") or "git command failed")


def _parse_worktrees(value: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in value.splitlines():
        if not line:
            continue
        if line.startswith("worktree "):
            if current is not None:
                entries.append(current)
            current = {"path": line.removeprefix("worktree ")}
        elif current is None:
            continue
        elif line.startswith("HEAD "):
            current["head"] = line.removeprefix("HEAD ")
        elif line.startswith("branch "):
            current["branch"] = line.removeprefix("branch refs/heads/")
        elif line == "detached":
            current["detached"] = True
        elif line == "bare":
            current["bare"] = True
        elif line == "locked" or line.startswith("locked "):
            current["locked"] = True
        elif line == "prunable" or line.startswith("prunable "):
            current["prunable"] = True
        else:
            current.setdefault("unknown_fields", []).append(line)
    if current is not None:
        entries.append(current)
    return entries


def _same_path(left: str, right: Path) -> bool:
    try:
        return Path(left).expanduser().resolve(strict=False) == right
    except OSError:
        return False


def _observe(inputs: dict[str, Any], runner: CommandRunner) -> dict[str, Any]:
    repo = Path(inputs["repo"])
    target = Path(inputs["target_path"])
    branch = inputs["branch"]
    base_head = inputs["base_head"]

    root_result = _command(runner, repo, ["rev-parse", "--show-toplevel"])
    if _returncode(root_result) != 0:
        raise WorktreeEnsurePreflight(f"repo is not a readable Git checkout: {_command_error(root_result)}")
    try:
        actual_root = Path(_stdout(root_result)).resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise WorktreeEnsurePreflight("Git root could not be resolved") from exc
    if actual_root != repo:
        raise WorktreeEnsurePreflight(f"repo must be the Git top-level checkout: actual={actual_root}")

    branch_valid = _command(runner, repo, ["check-ref-format", "--branch", branch])
    if _returncode(branch_valid) != 0:
        raise WorktreeEnsurePreflight(f"branch is invalid: {_command_error(branch_valid)}")

    commit_result = _command(runner, repo, ["rev-parse", "--verify", f"{base_head}^{{commit}}"])
    if _returncode(commit_result) != 0 or _stdout(commit_result).strip().lower() != base_head:
        raise WorktreeEnsurePreflight("base_head is not the exact readable commit requested")

    list_result = _command(runner, repo, ["worktree", "list", "--porcelain"])
    if _returncode(list_result) != 0:
        raise WorktreeEnsureAction(f"worktree inventory failed: {_command_error(list_result)}")
    entries = _parse_worktrees(_stdout(list_result))
    target_entry = next((entry for entry in entries if _same_path(str(entry.get("path", "")), target)), None)
    branch_entries = [entry for entry in entries if entry.get("branch") == branch]

    ref_result = _command(runner, repo, ["show-ref", "--verify", "--hash", f"refs/heads/{branch}"])
    branch_ref_head = _stdout(ref_result).strip() if _returncode(ref_result) == 0 else None
    target_lexists = os.path.lexists(target)

    post_state: dict[str, Any] = {
        "repo": str(repo),
        "target_path": str(target),
        "requested_branch": branch,
        "requested_head": base_head,
        "target_path_exists": target_lexists,
        "target_registered": target_entry is not None,
        "branch_ref_head": branch_ref_head,
        "branch_registered_paths": [str(entry.get("path", "")) for entry in branch_entries],
        "matches_requested_state": False,
        "dirty": None,
        "actual_branch": target_entry.get("branch") if target_entry else None,
        "actual_head": target_entry.get("head") if target_entry else None,
    }

    if target_entry is not None:
        status_result = _command(runner, target, ["status", "--short", "--branch", "--untracked-files=normal"])
        status_available = _returncode(status_result) == 0
        lines = [line for line in _stdout(status_result).splitlines() if line] if status_available else []
        entries_body = lines[1:] if lines else []
        post_state["status_available"] = status_available
        post_state["status_header"] = lines[0] if lines else ""
        post_state["status_entries"] = entries_body[:100]
        post_state["dirty"] = bool(entries_body) if status_available else None
        post_state["status_error"] = "" if status_available else _command_error(status_result)
        post_state["matches_requested_state"] = bool(
            status_available
            and not entries_body
            and target_entry.get("branch") == branch
            and target_entry.get("head") == base_head
            and branch_ref_head == base_head
            and not target_entry.get("detached")
            and not target_entry.get("bare")
            and not target_entry.get("prunable")
        )
    else:
        post_state["status_available"] = False
        post_state["status_header"] = ""
        post_state["status_entries"] = []
        post_state["status_error"] = "target is not a registered worktree"

    if post_state["matches_requested_state"]:
        post_state["classification"] = "ALREADY_CORRECT"
    elif target_entry is not None or target_lexists or branch_ref_head is not None or branch_entries:
        post_state["classification"] = "CONFLICT"
    else:
        post_state["classification"] = "ABSENT"
    return post_state


def _lease_state(inputs: dict[str, Any], inspect_lease: LeaseInspector) -> dict[str, Any]:
    now = int(time.time())
    owner = inputs["lease_owner_id"]
    checked: list[dict[str, Any]] = []
    reasons: list[str] = []
    for resource_key in inputs["required_resource_keys"]:
        try:
            lease = inspect_lease(resource_key)
        except Exception as exc:
            lease = None
            reasons.append(f"lease read failed for {resource_key}: {_bounded_text(exc, 512)}")
        if not isinstance(lease, dict):
            reasons.append(f"missing lease: {resource_key}")
            checked.append({"resource_key": resource_key, "owned": False, "live": False})
            continue
        actual_owner = lease.get("owner_id")
        expires = lease.get("expires_at_unix")
        live = isinstance(expires, int) and not isinstance(expires, bool) and expires > now
        owned = actual_owner == owner
        if not owned:
            reasons.append(f"lease owner mismatch: {resource_key}")
        if not live:
            reasons.append(f"lease expired or invalid: {resource_key}")
        checked.append(
            {
                "resource_key": resource_key,
                "owner_id": actual_owner if isinstance(actual_owner, str) else None,
                "expires_at_unix": expires if isinstance(expires, int) else None,
                "owned": owned,
                "live": live,
            }
        )
    return {"valid": not reasons, "owner_id": owner, "checked": checked, "reasons": reasons}


def _record_friction(
    recorder: FrictionRecorder | None,
    *,
    result_state: str,
    symptom: str,
    notes: list[str],
) -> dict[str, Any] | None:
    if recorder is None:
        return None
    kind = "fail_closed_gate" if result_state in {"CONFLICT", "REJECTED_BY_LEASE"} else "execution_context"
    try:
        return recorder(
            kind=kind,
            surface="runtime",
            operation="repo.worktree.ensure",
            symptom=_bounded_text(symptom),
            suspected_trigger="typed worktree ensure precondition or execution outcome",
            fallback="inspect the durable receipt and post-state before using a new idempotency key",
            resolved=False,
            notes=[_bounded_text(note, 1024) for note in notes[:8]],
        )
    except Exception as exc:
        return {"recorded": False, "error": _bounded_text(exc, 1024)}


def _resolve_friction(
    resolver: FrictionResolver | None,
    event_id: str,
    receipt_path: Path,
    parameters_sha256: str,
) -> dict[str, Any] | None:
    if resolver is None or not event_id:
        return None
    try:
        return resolver(
            status="resolved",
            decision="idempotent replay recovered the requested worktree state",
            evidence_ref=f"file:{receipt_path}#parameters_sha256={parameters_sha256}",
            resolved_by="worktree-ensure-grip",
            event_id=event_id,
            reason="",
            bureau_task_id="",
        )
    except Exception as exc:
        return {"resolved": False, "error": _bounded_text(exc, 1024)}


def _durable_record(
    *,
    inputs: dict[str, Any],
    parameters_sha256: str,
    state: str,
    result_state: str | None,
    post_state: dict[str, Any] | None,
    error_class: str | None,
    error: str,
    friction: dict[str, Any] | None = None,
    friction_closeout: dict[str, Any] | None = None,
    created_at_unix: int | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "kind": RECEIPT_KIND,
        "schema_version": SCHEMA_VERSION,
        "state": state,
        "result_state": result_state,
        "parameters_sha256": parameters_sha256,
        "idempotency_key_sha256": hashlib.sha256(inputs["idempotency_key"].encode("utf-8")).hexdigest(),
        "inputs": {key: value for key, value in inputs.items() if key != "idempotency_key"},
        "post_state": post_state,
        "error_class": error_class,
        "error": _bounded_text(error),
        "friction": friction,
        "friction_closeout": friction_closeout,
        "created_at_unix": created_at_unix or now,
        "updated_at_unix": now,
    }


def _public_output(
    record: dict[str, Any],
    receipt_path: Path,
    *,
    replayed: bool,
    recovered: bool,
    lifecycle_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result_state = record.get("result_state")
    receipt_status = "passed" if result_state in SUCCESS_STATES else ("blocked" if result_state in {"CONFLICT", "REJECTED_BY_LEASE"} else "failed")
    stored_lifecycle = record.get("lifecycle")
    lifecycle = lifecycle_override or stored_lifecycle
    lifecycle_bound = isinstance(stored_lifecycle, dict) and lifecycle_override is None
    return {
        "receipt_status": receipt_status,
        "result_state": result_state,
        "error_class": record.get("error_class"),
        "error": record.get("error", ""),
        "parameters_sha256": record.get("parameters_sha256"),
        "idempotency_key_sha256": record.get("idempotency_key_sha256"),
        "durable_receipt_path": str(receipt_path),
        "durable_receipt_sha256": record.get("receipt_sha256"),
        "replayed": replayed,
        "recovered_after_interruption": recovered,
        "post_state": record.get("post_state"),
        "lifecycle": lifecycle,
        "lifecycle_integrity": {
            "sha256": _sha256_json(lifecycle) if isinstance(lifecycle, dict) else None,
            "source": (
                "durable_receipt"
                if lifecycle_bound
                else "checkout_retention_db"
                if isinstance(lifecycle, dict)
                else None
            ),
            "bound_to_durable_receipt": lifecycle_bound,
        },
        "friction": record.get("friction"),
        "friction_closeout": record.get("friction_closeout"),
        "non_claims": [
            "does not provide exactly-once execution",
            "does not create or renew leases",
            "does not clean up conflicting worktrees or branches",
            "does not prove connector delivery of the response",
            "a legacy lifecycle projection is not bound by the original receipt hash",
        ],
    }


def _bind_checkout_lifecycle(
    inputs: dict[str, Any],
    post_state: dict[str, Any],
    lease: dict[str, Any],
) -> dict[str, Any]:
    import grabowski_checkouts as checkouts

    checked = lease.get("checked")
    expiries = [
        item.get("expires_at_unix")
        for item in checked
        if isinstance(item, dict)
        and isinstance(item.get("expires_at_unix"), int)
        and not isinstance(item.get("expires_at_unix"), bool)
    ] if isinstance(checked, list) else []
    if not expiries:
        raise WorktreeEnsureAction("worktree lifecycle requires live lease expiry evidence")
    retention_until_unix = max(min(expiries), int(time.time()) + 24 * 60 * 60)
    repo = Path(inputs["repo"])
    checkout = Path(inputs["target_path"])
    top_level, common_dir, record = checkouts._worktree_for_path(repo, checkout)
    checkouts._require_linked(record)
    checkouts._require_expected(
        record,
        str(post_state["actual_head"]),
        str(inputs["branch"]),
    )
    owner_id = checkouts._owner(str(inputs["lease_owner_id"]))
    task_id = f"worktree-ensure:{inputs['idempotency_key']}"
    purpose = f"ensure exact worktree for {task_id}"
    retention = checkouts._upsert_retention(
        checkout_key=str(record["checkout_key"]),
        repo_common_dir=common_dir,
        repo_path=top_level,
        checkout_path=checkout,
        owner_id=owner_id,
        purpose=purpose,
        retention_until_unix=retention_until_unix,
        expected_head=str(post_state["actual_head"]),
        expected_branch=str(inputs["branch"]),
    )
    return {
        "schema_version": 1,
        "state": "retained",
        "checkout_key": retention["checkout_key"],
        "checkout_path": retention["checkout_path"],
        "owner_id": retention["owner_id"],
        "task": {"kind": "worktree_ensure", "id": task_id},
        "purpose": retention["purpose"],
        "created_at_unix": retention["created_at_unix"],
        "updated_at_unix": retention["updated_at_unix"],
        "expires_at_unix": retention["retention_until_unix"],
        "expected_head": retention["expected_head"],
        "expected_branch": retention["expected_branch"],
        "terminal_decision": "retain",
        "terminal_reason": "external GitHub and Bureau truth require later reconciliation",
        "automatic_cleanup_authorized": False,
        "does_not_establish": [
            "permission_to_delete_checkout",
            "pull_request_integration_truth",
            "bureau_task_completion",
        ],
    }


def _after_worktree_mutation() -> None:
    """Fault-injection seam used by tests; production behavior is intentionally empty."""


def ensure_worktree(
    parameters: dict[str, Any],
    runner: CommandRunner,
    inspect_lease: LeaseInspector,
    *,
    record_friction: FrictionRecorder | None = None,
    resolve_friction: FrictionResolver | None = None,
) -> dict[str, Any]:
    inputs = _normalize_inputs(parameters)
    parameters_sha256 = _sha256_json(inputs)
    idempotency_key = inputs["idempotency_key"]

    with _locked_receipt(idempotency_key) as (receipt_path, _lock_handle):
        existing = _read_receipt(receipt_path)
        if existing is not None and existing.get("parameters_sha256") != parameters_sha256:
            return {
                "receipt_status": "blocked",
                "result_state": "CONFLICT",
                "error_class": "IDEMPOTENCY_KEY_REUSE",
                "error": "idempotency key is already bound to different normalized inputs",
                "parameters_sha256": parameters_sha256,
                "idempotency_key_sha256": hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest(),
                "durable_receipt_path": str(receipt_path),
                "durable_receipt_sha256": existing.get("receipt_sha256"),
                "replayed": True,
                "recovered_after_interruption": False,
                "post_state": existing.get("post_state"),
                "friction": None,
                "friction_closeout": None,
                "non_claims": ["the existing durable receipt was not overwritten"],
            }

        if existing is not None and existing.get("state") == "complete":
            result_state = existing.get("result_state")
            if result_state in SUCCESS_STATES:
                observation = _observe(inputs, runner)
                if not observation.get("matches_requested_state"):
                    return {
                        "receipt_status": "blocked",
                        "result_state": "CONFLICT",
                        "error_class": "POST_STATE_DRIFT",
                        "error": "durable success receipt exists but current post-state has drifted",
                        "parameters_sha256": parameters_sha256,
                        "idempotency_key_sha256": existing.get("idempotency_key_sha256"),
                        "durable_receipt_path": str(receipt_path),
                        "durable_receipt_sha256": existing.get("receipt_sha256"),
                        "replayed": True,
                        "recovered_after_interruption": False,
                        "post_state": observation,
                        "friction": existing.get("friction"),
                        "friction_closeout": existing.get("friction_closeout"),
                        "non_claims": ["the prior durable receipt remains immutable evidence of the earlier result"],
                    }
            lifecycle = existing.get("lifecycle")
            if result_state in SUCCESS_STATES and not isinstance(lifecycle, dict):
                assert observation is not None
                lifecycle = _bind_checkout_lifecycle(inputs, observation, existing["lease"])
            return _public_output(
                existing,
                receipt_path,
                replayed=True,
                recovered=False,
                lifecycle_override=lifecycle if isinstance(lifecycle, dict) else None,
            )

        recovering_intent = existing is not None and existing.get("state") == "intent"
        recovery_friction: dict[str, Any] | None = None
        observation: dict[str, Any] | None = None
        lease: dict[str, Any]

        if recovering_intent:
            recovery_friction = _record_friction(
                record_friction,
                result_state="NOT_ACCEPTED",
                symptom="incomplete worktree-ensure intent found during idempotent replay",
                notes=[f"receipt={receipt_path}", "post-state readback will determine recovery"],
            )
            observation = _observe(inputs, runner)
            lease = _lease_state(inputs, inspect_lease)

            if observation["classification"] == "ALREADY_CORRECT":
                event_id = str((recovery_friction or {}).get("event_id") or "")
                closeout = _resolve_friction(resolve_friction, event_id, receipt_path, parameters_sha256)
                record = _durable_record(
                    inputs=inputs,
                    parameters_sha256=parameters_sha256,
                    state="complete",
                    result_state="CREATED",
                    post_state=observation,
                    error_class=None,
                    error="",
                    friction=recovery_friction,
                    friction_closeout=closeout,
                    created_at_unix=existing.get("created_at_unix"),
                )
                record["lease"] = lease
                record["recovery_without_live_lease"] = not lease["valid"]
                record["lifecycle"] = _bind_checkout_lifecycle(inputs, observation, lease)
                written = _write_receipt(receipt_path, record)
                return _public_output(written, receipt_path, replayed=True, recovered=True)

            if observation["classification"] == "CONFLICT":
                friction = recovery_friction or _record_friction(
                    record_friction,
                    result_state="CONFLICT",
                    symptom="interrupted worktree ensure recovered into a conflicting state",
                    notes=[
                        f"target_registered={observation['target_registered']}",
                        f"target_path_exists={observation['target_path_exists']}",
                        f"branch_ref_head={observation['branch_ref_head']}",
                    ],
                )
                record = _durable_record(
                    inputs=inputs,
                    parameters_sha256=parameters_sha256,
                    state="complete",
                    result_state="CONFLICT",
                    post_state=observation,
                    error_class="WORKTREE_CONFLICT",
                    error="interrupted operation did not recover to the requested exact state",
                    friction=friction,
                    created_at_unix=existing.get("created_at_unix"),
                )
                record["lease"] = lease
                written = _write_receipt(receipt_path, record)
                return _public_output(written, receipt_path, replayed=True, recovered=False)
        else:
            lease = _lease_state(inputs, inspect_lease)

        if not lease["valid"]:
            if observation is None:
                observation = _observe(inputs, runner)
            friction = recovery_friction or _record_friction(
                record_friction,
                result_state="REJECTED_BY_LEASE",
                symptom="worktree ensure rejected because required leases are not live and owner-bound",
                notes=lease["reasons"],
            )
            record = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="complete",
                result_state="REJECTED_BY_LEASE",
                post_state=observation,
                error_class="LEASE_REJECTED",
                error="; ".join(lease["reasons"]),
                friction=friction,
                created_at_unix=existing.get("created_at_unix") if existing else None,
            )
            record["lease"] = lease
            written = _write_receipt(receipt_path, record)
            return _public_output(written, receipt_path, replayed=recovering_intent, recovered=False)

        if observation is None:
            observation = _observe(inputs, runner)
        if observation["classification"] == "ALREADY_CORRECT":
            record = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="complete",
                result_state="ALREADY_CORRECT",
                post_state=observation,
                error_class=None,
                error="",
            )
            record["lease"] = lease
            record["lifecycle"] = _bind_checkout_lifecycle(inputs, observation, lease)
            written = _write_receipt(receipt_path, record)
            return _public_output(written, receipt_path, replayed=False, recovered=False)

        if observation["classification"] == "CONFLICT":
            friction = _record_friction(
                record_friction,
                result_state="CONFLICT",
                symptom="worktree target, branch or registered state conflicts with requested state",
                notes=[
                    f"target_registered={observation['target_registered']}",
                    f"target_path_exists={observation['target_path_exists']}",
                    f"branch_ref_head={observation['branch_ref_head']}",
                ],
            )
            record = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="complete",
                result_state="CONFLICT",
                post_state=observation,
                error_class="WORKTREE_CONFLICT",
                error="target path or branch is already bound to a different state",
                friction=friction,
            )
            record["lease"] = lease
            written = _write_receipt(receipt_path, record)
            return _public_output(written, receipt_path, replayed=False, recovered=False)

        if not recovering_intent:
            intent = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="intent",
                result_state=None,
                post_state=observation,
                error_class=None,
                error="",
            )
            intent["lease"] = lease
            existing = _write_receipt(receipt_path, intent)

        pre_mutation_lease = _lease_state(inputs, inspect_lease)
        if not pre_mutation_lease["valid"]:
            friction = recovery_friction or _record_friction(
                record_friction,
                result_state="REJECTED_BY_LEASE",
                symptom="worktree ensure lease changed before mutation",
                notes=pre_mutation_lease["reasons"],
            )
            record = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="complete",
                result_state="REJECTED_BY_LEASE",
                post_state=observation,
                error_class="LEASE_REJECTED_BEFORE_MUTATION",
                error="; ".join(pre_mutation_lease["reasons"]),
                friction=friction,
                created_at_unix=existing.get("created_at_unix") if existing else None,
            )
            record["lease"] = lease
            record["pre_mutation_lease"] = pre_mutation_lease
            written = _write_receipt(receipt_path, record)
            return _public_output(written, receipt_path, replayed=recovering_intent, recovered=False)

        lease = pre_mutation_lease
        mutation = _command(
            runner,
            Path(inputs["repo"]),
            ["worktree", "add", "-b", inputs["branch"], inputs["target_path"], inputs["base_head"]],
        )
        _after_worktree_mutation()

        post_state = _observe(inputs, runner)
        if post_state.get("matches_requested_state"):
            event_id = str((recovery_friction or {}).get("event_id") or "")
            closeout = _resolve_friction(resolve_friction, event_id, receipt_path, parameters_sha256)
            record = _durable_record(
                inputs=inputs,
                parameters_sha256=parameters_sha256,
                state="complete",
                result_state="CREATED",
                post_state=post_state,
                error_class=None,
                error="",
                friction=recovery_friction,
                friction_closeout=closeout,
                created_at_unix=existing.get("created_at_unix") if existing else None,
            )
            record["lease"] = lease
            record["lifecycle"] = _bind_checkout_lifecycle(inputs, post_state, lease)
            record["mutation"] = {
                "returncode": _returncode(mutation),
                "stdout": _bounded_text(_stdout(mutation)),
                "stderr": _bounded_text(mutation.get("stderr", "")),
            }
            written = _write_receipt(receipt_path, record)
            return _public_output(written, receipt_path, replayed=recovering_intent, recovered=recovering_intent)

        error = _command_error(mutation)
        result_state = "CONFLICT" if post_state["classification"] == "CONFLICT" else "NOT_ACCEPTED"
        error_class = "POST_MUTATION_CONFLICT" if result_state == "CONFLICT" else "GIT_WORKTREE_ADD_REJECTED"
        friction = recovery_friction or _record_friction(
            record_friction,
            result_state=result_state,
            symptom="git worktree add did not produce the requested verified post-state",
            notes=[f"returncode={_returncode(mutation)}", error],
        )
        record = _durable_record(
            inputs=inputs,
            parameters_sha256=parameters_sha256,
            state="complete",
            result_state=result_state,
            post_state=post_state,
            error_class=error_class,
            error=error,
            friction=friction,
            created_at_unix=existing.get("created_at_unix") if existing else None,
        )
        record["lease"] = lease
        record["mutation"] = {
            "returncode": _returncode(mutation),
            "stdout": _bounded_text(_stdout(mutation)),
            "stderr": _bounded_text(mutation.get("stderr", "")),
        }
        written = _write_receipt(receipt_path, record)
        return _public_output(written, receipt_path, replayed=recovering_intent, recovered=False)
