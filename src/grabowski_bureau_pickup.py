from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

import grabowski_bureau_intake as bureau
import grabowski_bureau_leases as bureau_leases
import grabowski_resources as resources

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

SCHEMA_VERSION = 1
STATE_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_BUREAU_PICKUP_ROOT",
        str(operator.STATE_DIR / "bureau-pickup"),
    )
).expanduser()
RUN_ID_RE = re.compile(r"^BUR-RUN-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_REQUEST_BYTES = 1024 * 1024
MIN_LEASE_TTL_SECONDS = 120
MAX_LEASE_TTL_SECONDS = 3600


class BureauPickupError(RuntimeError):
    def __init__(self, code: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "details": self.details}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _private_root() -> Path:
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_ROOT, 0o700)
    return STATE_ROOT


def _run_directory(run_id: str) -> Path:
    if RUN_ID_RE.fullmatch(run_id) is None:
        raise ValueError("run_id is invalid")
    path = _private_root() / "runs" / run_id
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def _read_private_bytes(path: Path, *, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise BureauPickupError(f"{label}-missing") from None
    except OSError as exc:
        raise BureauPickupError(
            f"{label}-open-failed", details={"error_type": type(exc).__name__}
        ) from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BureauPickupError(f"{label}-not-regular")
        if before.st_uid != os.getuid():
            raise BureauPickupError(f"{label}-owner-invalid")
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise BureauPickupError(f"{label}-mode-invalid")
        if before.st_nlink != 1:
            raise BureauPickupError(f"{label}-hardlink-invalid")
        if before.st_size > MAX_REQUEST_BYTES:
            raise BureauPickupError(f"{label}-too-large")
        chunks: list[bytes] = []
        remaining = MAX_REQUEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after:
        raise BureauPickupError(f"{label}-changed-during-read")
    raw = b"".join(chunks)
    if len(raw) > MAX_REQUEST_BYTES or len(raw) != before.st_size:
        raise BureauPickupError(f"{label}-size-invalid")
    return raw


def _write_bound_json(path: Path, value: Any) -> str:
    raw = _canonical_json(value)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("pickup artifact exceeds the bounded limit")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if path.exists():
        existing = _read_private_bytes(path, label="pickup-artifact")
        if existing != raw:
            raise BureauPickupError(
                "pickup-artifact-conflict", details={"path": str(path)}
            )
        return hashlib.sha256(raw).hexdigest()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return hashlib.sha256(raw).hexdigest()


def _read_bound_json(path: Path, *, label: str) -> dict[str, Any]:
    raw = _read_private_bytes(path, label=label)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise BureauPickupError(f"{label}-invalid") from None
    if not isinstance(value, dict):
        raise BureauPickupError(f"{label}-invalid")
    return value


def _text(value: Any, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    normalized = value.strip()
    if not normalized or "\x00" in normalized or len(normalized.encode()) > maximum:
        raise ValueError(f"{label} is empty, too large or contains NUL")
    return normalized


def _capabilities(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("capabilities must be a non-empty list")
    result = sorted({_text(item, label="capability", maximum=128) for item in value})
    return result


def _ttl(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("lease_ttl_seconds must be an integer")
    if not MIN_LEASE_TTL_SECONDS <= value <= MAX_LEASE_TTL_SECONDS:
        raise ValueError(
            f"lease_ttl_seconds must be between {MIN_LEASE_TTL_SECONDS} and "
            f"{MAX_LEASE_TTL_SECONDS}"
        )
    return value


def _normalize_scope_manifests(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("repository_scope_manifests must be an object")
    result: dict[str, dict[str, Any]] = {}
    for key, scope in value.items():
        normalized_key = resources.normalize_resource_key(key)
        if not normalized_key.startswith("repo:"):
            raise ValueError("repository scope keys must be broad repo resources")
        if not isinstance(scope, dict):
            raise ValueError("repository scope manifest must be an object")
        result[normalized_key] = scope
    return result


def _normalize_nonconflict_proofs(value: Any) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("nonconflict_proofs must be an object")
    result: dict[str, dict[str, Any]] = {}
    for key, proof in value.items():
        normalized_key = (
            "other" if key == "other" else resources.normalize_resource_key(key)
        )
        if not isinstance(proof, dict):
            raise ValueError("nonconflict proof must be an object")
        result[normalized_key] = proof
    return result


def _normalize_request(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    allowed = {
        "worker_id",
        "capabilities",
        "task_id",
        "resource",
        "kind",
        "base_dir",
        "approval_source",
        "lease_ttl_seconds",
        "create_workspace",
        "repository_scope_manifests",
        "nonconflict_proofs",
    }
    extra = sorted(set(request) - allowed)
    if extra:
        raise ValueError(f"unsupported request fields: {extra}")
    worker_id = _text(request.get("worker_id"), label="worker_id", maximum=200)
    task_id = _text(request.get("task_id"), label="task_id", maximum=200)
    kind = _text(
        request.get("kind", "interactive-agent"), label="kind", maximum=128
    )
    approval_source = _text(
        request.get("approval_source", "grabowski_bureau_pickup_execute"),
        label="approval_source",
        maximum=512,
    )
    resource = request.get("resource")
    if resource is not None:
        resource = _text(resource, label="resource", maximum=512)
    base_dir = request.get("base_dir")
    if base_dir is not None:
        base_dir = str(Path(_text(base_dir, label="base_dir", maximum=4096)).expanduser())
        if not Path(base_dir).is_absolute():
            raise ValueError("base_dir must be absolute")
    create_workspace = request.get("create_workspace", True)
    if not isinstance(create_workspace, bool):
        raise ValueError("create_workspace must be boolean")
    return {
        "worker_id": worker_id,
        "capabilities": _capabilities(request.get("capabilities")),
        "task_id": task_id,
        "resource": resource,
        "kind": kind,
        "base_dir": base_dir,
        "approval_source": approval_source,
        "lease_ttl_seconds": _ttl(request.get("lease_ttl_seconds", 900)),
        "create_workspace": create_workspace,
        "repository_scope_manifests": _normalize_scope_manifests(
            request.get("repository_scope_manifests")
        ),
        "nonconflict_proofs": _normalize_nonconflict_proofs(
            request.get("nonconflict_proofs")
        ),
    }


def _bureau_arguments(command: str) -> list[str]:
    return ["--json", "--json-envelope", command]


def _claim_intent(request: dict[str, Any]) -> dict[str, Any]:
    arguments = _bureau_arguments("claim-intent")
    arguments.extend(["--worker", request["worker_id"]])
    arguments.extend(["--kind", request["kind"]])
    arguments.extend(["--task-id", request["task_id"]])
    for capability in request["capabilities"]:
        arguments.extend(["--capability", capability])
    if request["resource"]:
        arguments.extend(["--resource", request["resource"]])
    if request["base_dir"]:
        arguments.extend(["--base-dir", request["base_dir"]])
    arguments.extend(["--approve", "--approval-source", request["approval_source"]])
    return bureau._invoke_bureau(arguments)


def _validate_intent_result(
    payload: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    status = payload.get("status")
    existing = status in {"existing-assignment", "existing-terminal"}
    if status == "claim-intent":
        intent = payload.get("intent")
    elif existing:
        envelope = payload.get("envelope")
        intent = envelope.get("claim_intent") if isinstance(envelope, dict) else None
    else:
        raise BureauPickupError("claim-intent-not-ready", details={"payload": payload})
    if not isinstance(intent, dict):
        raise BureauPickupError("claim-intent-missing")
    if RUN_ID_RE.fullmatch(str(intent.get("run_id", ""))) is None:
        raise BureauPickupError("claim-intent-run-id-invalid")
    if intent.get("task_id") != request["task_id"]:
        raise BureauPickupError("claim-intent-task-mismatch")
    if intent.get("worker_id") != request["worker_id"]:
        raise BureauPickupError("claim-intent-worker-mismatch")
    digest = intent.get("intent_sha256")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise BureauPickupError("claim-intent-digest-invalid")
    keys = intent.get("required_resource_keys")
    if not isinstance(keys, list) or keys != sorted(set(keys)):
        raise BureauPickupError("claim-intent-resource-set-invalid")
    if intent.get("lease_owner_id") != f"bureau-run:{intent['run_id']}":
        raise BureauPickupError("claim-intent-owner-invalid")
    expires_at = intent.get("expires_at_unix")
    if not isinstance(expires_at, int):
        raise BureauPickupError("claim-intent-expiry-invalid")
    if not existing and expires_at <= int(time.time()):
        raise BureauPickupError("claim-intent-expired")
    return intent, existing


def _lease_metadata(intent: dict[str, Any], *, group: str) -> dict[str, Any]:
    return {
        "task_id": intent["task_id"],
        "run_id": intent["run_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "pickup_schema_version": SCHEMA_VERSION,
        "pickup_group": group,
    }


def _acquisition_groups(
    intent: dict[str, Any], request: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = list(intent["required_resource_keys"])
    bureau_keys = bureau_leases.bureau_resource_keys(keys)
    remaining = [key for key in keys if key not in bureau_keys]
    repo_keys = [key for key in remaining if key.startswith("repo:")]
    other_keys = [key for key in remaining if not key.startswith("repo:")]
    groups: list[dict[str, Any]] = []
    if bureau_keys:
        metadata = _lease_metadata(intent, group="bureau")
        metadata["bureau_expected_state"] = intent["intent_sha256"]
        groups.append(
            {
                "name": "bureau",
                "resource_keys": bureau_keys,
                "metadata": metadata,
                "nonconflict_proof": None,
                "ttl_seconds": (
                    min(request["lease_ttl_seconds"], 300)
                    if {
                        bureau_leases.BUREAU_WORKTREE_ADMIN_KEY,
                        bureau_leases.BUREAU_MERGE_GATE_KEY,
                    }.intersection(bureau_keys)
                    else request["lease_ttl_seconds"]
                ),
            }
        )
    for key in repo_keys:
        scope = request["repository_scope_manifests"].get(key)
        if scope is None:
            raise BureauPickupError(
                "repository-scope-required", details={"resource_key": key}
            )
        metadata = _lease_metadata(intent, group=key)
        metadata["scope_manifest"] = scope
        metadata["scope_manifest_complete"] = True
        groups.append(
            {
                "name": key,
                "resource_keys": [key],
                "metadata": metadata,
                "nonconflict_proof": request["nonconflict_proofs"].get(key),
                "ttl_seconds": request["lease_ttl_seconds"],
            }
        )
    if other_keys:
        groups.append(
            {
                "name": "other",
                "resource_keys": other_keys,
                "metadata": _lease_metadata(intent, group="other"),
                "nonconflict_proof": request["nonconflict_proofs"].get("other"),
                "ttl_seconds": request["lease_ttl_seconds"],
            }
        )
    return groups


def _validate_acquired_group(
    owner_id: str, group: dict[str, Any], result: dict[str, Any]
) -> None:
    if result.get("owner_id") != owner_id:
        raise BureauPickupError(
            "lease-acquisition-owner-mismatch",
            details={"group": group["name"]},
        )
    leases = result.get("leases")
    if not isinstance(leases, list):
        raise BureauPickupError(
            "lease-acquisition-snapshots-invalid",
            details={"group": group["name"]},
        )
    observed: dict[str, dict[str, Any]] = {}
    for lease in leases:
        if not isinstance(lease, dict) or not isinstance(lease.get("resource_key"), str):
            raise BureauPickupError(
                "lease-acquisition-snapshot-invalid",
                details={"group": group["name"]},
            )
        key = lease["resource_key"]
        if key in observed or lease.get("owner_id") != owner_id:
            raise BureauPickupError(
                "lease-acquisition-snapshot-binding-invalid",
                details={"group": group["name"], "resource_key": key},
            )
        observed[key] = lease
    expected = sorted(group["resource_keys"])
    if sorted(observed) != expected:
        raise BureauPickupError(
            "lease-acquisition-resource-set-mismatch",
            details={"group": group["name"], "expected": expected, "observed": sorted(observed)},
        )


def _acquire_groups(
    intent: dict[str, Any], request: dict[str, Any], run_dir: Path
) -> dict[str, Any]:
    acquired: list[dict[str, Any]] = []
    owner_id = intent["lease_owner_id"]
    groups = _acquisition_groups(intent, request)
    try:
        for index, group in enumerate(groups, start=1):
            result = resources.acquire_resources(
                owner_id,
                group["resource_keys"],
                purpose=f"Bureau coordinated pickup {intent['run_id']} group {group['name']}",
                ttl_seconds=group["ttl_seconds"],
                metadata=group["metadata"],
                nonconflict_proof=group["nonconflict_proof"],
            )
            entry = {
                "group": group["name"],
                "resource_keys": group["resource_keys"],
                "result": result,
            }
            acquired.append(entry)
            _validate_acquired_group(owner_id, group, result)
            _write_bound_json(run_dir / f"lease-acquired-{index:02d}.json", entry)
    except Exception as exc:
        released = _compensate_acquisitions(owner_id, acquired, run_dir)
        raise BureauPickupError(
            "lease-acquisition-failed",
            details={
                "error_type": type(exc).__name__,
                "acquired_group_count": len(acquired),
                "compensation": released,
            },
        ) from exc
    flattened = [
        lease
        for entry in acquired
        for lease in entry["result"].get("leases", [])
        if isinstance(lease, dict)
    ]
    result = {
        "schema_version": SCHEMA_VERSION,
        "owner_id": owner_id,
        "task_id": intent["task_id"],
        "run_id": intent["run_id"],
        "claim_intent_sha256": intent["intent_sha256"],
        "resource_keys": intent["required_resource_keys"],
        "leases": flattened,
        "groups": acquired,
    }
    result["acquisition_sha256"] = _sha256(result)
    _write_bound_json(run_dir / "acquisition.json", result)
    return result


def _compensate_acquisitions(
    owner_id: str, acquired: list[dict[str, Any]], run_dir: Path
) -> dict[str, Any]:
    keys = sorted(
        {
            key
            for entry in acquired
            for key in entry.get("resource_keys", [])
            if isinstance(key, str)
        }
    )
    if not keys:
        return {"required": False, "released": []}
    try:
        result = resources.release_resources(owner_id, keys)
        payload = {"required": True, "status": "released", "result": result}
    except Exception as exc:
        payload = {
            "required": True,
            "status": "release-failed",
            "error_type": type(exc).__name__,
            "resource_keys": keys,
        }
    _write_bound_json(run_dir / "compensation.json", payload)
    return payload


def _lease_binding(intent: dict[str, Any], run_dir: Path) -> Path:
    path = run_dir / "lease-binding.json"
    _write_bound_json(
        path,
        {"owner_id": intent["lease_owner_id"], "task_id": intent["task_id"]},
    )
    return path


def _commit_claim(
    intent: dict[str, Any], request: dict[str, Any], run_dir: Path
) -> dict[str, Any]:
    intent_path = run_dir / "intent.json"
    arguments = _bureau_arguments("claim-commit")
    arguments.extend(["--intent", str(intent_path)])
    if intent["required_resource_keys"]:
        lease_path = _lease_binding(intent, run_dir)
        arguments.extend(["--lease-binding", str(lease_path)])
    if request["create_workspace"]:
        arguments.append("--workspace")
    return bureau._invoke_bureau(
        arguments,
        mutation=True,
        required_readback=[
            f"bureau_run:{intent['run_id']}",
            f"grabowski_leases:{intent['lease_owner_id']}",
        ],
    )


def _coordination_status(run_id: str) -> dict[str, Any]:
    return bureau._invoke_bureau(
        [*_bureau_arguments("claim-coordination-status"), run_id]
    )


def _definitive_missing_run(payload: dict[str, Any]) -> bool:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()
    return "unknown run" in text or payload.get("code") in {
        "unknown-run",
        "state-error-unknown-run",
    }


def _recover_after_commit(
    intent: dict[str, Any], acquisition: dict[str, Any], run_dir: Path
) -> dict[str, Any]:
    try:
        status = _coordination_status(intent["run_id"])
        _write_bound_json(run_dir / "commit-readback.json", status)
    except Exception as exc:
        failure = {
            "status": "recovery-required",
            "readback_error_type": type(exc).__name__,
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "does_not_establish": [
                "absence of a Bureau run",
                "permission to release leases",
                "safe retry without another readback",
            ],
        }
        try:
            _write_bound_json(run_dir / "commit-readback-failure.json", failure)
        except Exception:
            pass
        return failure
    if status.get("status") == "coordinated":
        return {
            "status": "recovered",
            "run": status.get("run"),
            "coordination": status,
            "acquisition": acquisition,
        }
    if _definitive_missing_run(status):
        compensation = _compensate_acquisitions(
            intent["lease_owner_id"], acquisition["groups"], run_dir
        )
        return {
            "status": "commit-not-applied",
            "coordination": status,
            "compensation": compensation,
        }
    return {
        "status": "recovery-required",
        "coordination": status,
        "lease_owner_id": intent["lease_owner_id"],
        "resource_keys": intent["required_resource_keys"],
        "does_not_establish": [
            "absence of a Bureau run",
            "permission to release leases",
            "safe retry without another readback",
        ],
    }


def grabowski_bureau_pickup_execute(request: dict[str, Any]) -> dict[str, Any]:
    """Coordinate one Bureau claim with owner-bound Grabowski leases and recovery."""
    operator._require_operator_mutation("terminal_execute")
    normalized = _normalize_request(request)
    request_sha256 = _sha256(normalized)
    intent_payload = _claim_intent(normalized)
    intent, existing = _validate_intent_result(intent_payload, normalized)
    run_dir = _run_directory(intent["run_id"])
    if existing:
        stored_request = _read_bound_json(
            run_dir / "request.json", label="request"
        )
        if stored_request != normalized:
            raise BureauPickupError("existing-assignment-request-mismatch")
        stored_intent = _read_bound_json(run_dir / "intent.json", label="intent")
        if stored_intent.get("intent_sha256") != intent["intent_sha256"]:
            raise BureauPickupError("existing-assignment-intent-mismatch")
        acquisition = _read_bound_json(
            run_dir / "acquisition.json", label="acquisition"
        )
        _validate_acquisition(acquisition)
        if acquisition.get("claim_intent_sha256") != intent["intent_sha256"]:
            raise BureauPickupError("existing-assignment-acquisition-mismatch")
        coordination = _coordination_status(intent["run_id"])
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup",
            "status": intent_payload["status"],
            "request_sha256": request_sha256,
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "claim_intent_sha256": intent["intent_sha256"],
            "acquisition_sha256": acquisition["acquisition_sha256"],
            "commit": intent_payload,
            "recovery": coordination,
            "journal": str(run_dir),
            "does_not_establish": [
                "ownership of an unjournaled assignment",
                "task completion",
                "automatic lease release",
            ],
        }
        bureau._audit(
            "bureau-pickup-retry",
            result,
            run_id=intent["run_id"],
            task_id=intent["task_id"],
        )
        return result
    _write_bound_json(run_dir / "request.json", normalized)
    _write_bound_json(run_dir / "intent-result.json", intent_payload)
    _write_bound_json(run_dir / "intent.json", intent)
    acquisition = _acquire_groups(intent, normalized, run_dir)
    try:
        commit = _commit_claim(intent, normalized, run_dir)
    except Exception as exc:
        commit = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup_commit_exception",
            "status": "unknown",
            "effect_started": True,
            "ambiguity": True,
            "error_type": type(exc).__name__,
            "required_readback": [
                f"bureau_run:{intent['run_id']}",
                f"grabowski_leases:{intent['lease_owner_id']}",
            ],
        }
    _write_bound_json(run_dir / "commit-result.json", commit)
    if commit.get("status") in {"claimed", "existing-assignment", "existing-terminal"}:
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski_bureau_pickup",
            "status": commit["status"],
            "request_sha256": request_sha256,
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "lease_owner_id": intent["lease_owner_id"],
            "resource_keys": intent["required_resource_keys"],
            "claim_intent_sha256": intent["intent_sha256"],
            "acquisition_sha256": acquisition["acquisition_sha256"],
            "commit": commit,
            "journal": str(run_dir),
            "does_not_establish": [
                "task completion",
                "merge readiness",
                "deployment authority",
                "automatic lease release",
            ],
        }
        bureau._audit(
            "bureau-pickup-execute",
            result,
            run_id=intent["run_id"],
            task_id=intent["task_id"],
        )
        return result
    recovered = _recover_after_commit(intent, acquisition, run_dir)
    result = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup",
        "status": recovered["status"],
        "request_sha256": request_sha256,
        "run_id": intent["run_id"],
        "task_id": intent["task_id"],
        "commit": commit,
        "recovery": recovered,
        "journal": str(run_dir),
    }
    bureau._audit(
        "bureau-pickup-execute",
        result,
        run_id=intent["run_id"],
        task_id=intent["task_id"],
    )
    return result


def grabowski_bureau_pickup_status(run_id: str) -> dict[str, Any]:
    """Read one coordinated Bureau run and its owner-bound lease state."""
    normalized_run_id = _text(run_id, label="run_id", maximum=128)
    if RUN_ID_RE.fullmatch(normalized_run_id) is None:
        raise ValueError("run_id is invalid")
    payload = _coordination_status(normalized_run_id)
    journal = STATE_ROOT.expanduser() / "runs" / normalized_run_id
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_status",
        "run_id": normalized_run_id,
        "coordination": payload,
        "journal_available": journal.is_dir() and not journal.is_symlink(),
    }




def _validate_acquisition(acquisition: dict[str, Any]) -> None:
    claimed = acquisition.get("acquisition_sha256")
    if not isinstance(claimed, str) or SHA256_RE.fullmatch(claimed) is None:
        raise BureauPickupError("acquisition-digest-invalid")
    payload = dict(acquisition)
    payload.pop("acquisition_sha256", None)
    if _sha256(payload) != claimed:
        raise BureauPickupError("acquisition-digest-mismatch")
    keys = acquisition.get("resource_keys")
    if not isinstance(keys, list) or keys != sorted(set(keys)):
        raise BureauPickupError("acquisition-resource-set-invalid")
    if acquisition.get("owner_id") != f"bureau-run:{acquisition.get('run_id')}":
        raise BureauPickupError("acquisition-owner-invalid")

def _verify_release_binding(
    run_id: str, status: dict[str, Any], acquisition: dict[str, Any]
) -> tuple[str, list[str]]:
    if status.get("status") != "coordinated":
        raise BureauPickupError("terminal-readback-unavailable")
    run = status.get("run")
    if not isinstance(run, dict) or run.get("run_id") != run_id:
        raise BureauPickupError("terminal-run-binding-invalid")
    if run.get("state") in {"assigned", "running", "verifying"}:
        raise BureauPickupError(
            "run-still-active", details={"state": run.get("state")}
        )
    release = status.get("release")
    if not isinstance(release, dict) or release.get("required") is not True:
        raise BureauPickupError("lease-release-not-required")
    owner_id = release.get("owner_id")
    keys = release.get("resource_keys")
    if owner_id != acquisition.get("owner_id"):
        raise BureauPickupError("lease-release-owner-mismatch")
    if keys != acquisition.get("resource_keys"):
        raise BureauPickupError("lease-release-resource-mismatch")
    if release.get("claim_intent_sha256") != acquisition.get(
        "claim_intent_sha256"
    ):
        raise BureauPickupError("lease-release-intent-mismatch")
    if not isinstance(keys, list):
        raise BureauPickupError("lease-release-resource-set-invalid")
    expected_by_key = {
        lease["resource_key"]: lease
        for lease in acquisition.get("leases", [])
        if isinstance(lease, dict) and isinstance(lease.get("resource_key"), str)
    }
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is None:
            continue
        expected = expected_by_key.get(key)
        if expected is None:
            raise BureauPickupError("lease-release-snapshot-missing")
        if observed.get("owner_id") != owner_id:
            raise BureauPickupError(
                "lease-release-foreign-owner", details={"resource_key": key}
            )
        if observed.get("metadata_sha256") != expected.get("metadata_sha256"):
            raise BureauPickupError(
                "lease-release-metadata-drift", details={"resource_key": key}
            )
    return owner_id, keys


def grabowski_bureau_pickup_release(run_id: str) -> dict[str, Any]:
    """Release exactly one terminal coordinated run's unchanged Grabowski leases."""
    operator._require_operator_mutation("terminal_execute")
    normalized_run_id = _text(run_id, label="run_id", maximum=128)
    run_dir = _run_directory(normalized_run_id)
    acquisition = _read_bound_json(run_dir / "acquisition.json", label="acquisition")
    _validate_acquisition(acquisition)
    existing_release_path = run_dir / "release-result.json"
    if existing_release_path.is_file() and not existing_release_path.is_symlink():
        remaining_existing: dict[str, dict[str, Any]] = {}
        for key in acquisition["resource_keys"]:
            observed = resources.inspect_resource(key)
            if observed is not None:
                remaining_existing[key] = observed
        if not remaining_existing:
            return {
                "schema_version": SCHEMA_VERSION,
                "kind": "grabowski_bureau_pickup_release",
                "status": "already-released",
                "run_id": normalized_run_id,
                "owner_id": acquisition["owner_id"],
                "resource_keys": acquisition["resource_keys"],
                "release": _read_bound_json(
                    existing_release_path, label="release-result"
                ),
                "journal": str(run_dir),
            }
    status = _coordination_status(normalized_run_id)
    _write_bound_json(run_dir / "terminal-readback.json", status)
    owner_id, keys = _verify_release_binding(
        normalized_run_id, status, acquisition
    )
    result = resources.release_resources(owner_id, keys)
    _write_bound_json(run_dir / "release-result.json", result)
    remaining: dict[str, dict[str, Any]] = {}
    for key in keys:
        observed = resources.inspect_resource(key)
        if observed is not None:
            remaining[key] = observed
    if remaining:
        raise BureauPickupError(
            "lease-release-incomplete", details={"resource_keys": sorted(remaining)}
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_pickup_release",
        "status": "released",
        "run_id": normalized_run_id,
        "owner_id": owner_id,
        "resource_keys": keys,
        "release": result,
        "terminal_readback_sha256": _sha256(status),
        "journal": str(run_dir),
        "does_not_establish": [
            "workspace cleanup authority",
            "foreign lease release authority",
            "task verification",
        ],
    }
    bureau._audit(
        "bureau-pickup-release", payload, run_id=normalized_run_id
    )
    return payload
