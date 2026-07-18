from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

import grabowski_bureau_leases as bureau_runtime
import grabowski_mcp as base
import grabowski_resources as resources

try:
    import grabowski_operator_core as operator
except ModuleNotFoundError:
    import grabowski_operator as operator

mcp = operator.mcp
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING

SCHEMA_VERSION = 1
ARTIFACT_ROOT = Path(
    os.environ.get(
        "GRABOWSKI_BUREAU_INTAKE_ROOT",
        str(operator.STATE_DIR / "bureau-intake"),
    )
).expanduser()
BUREAU_ROOT = bureau_runtime.BUREAU_REPOSITORY_ROOT
MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30
PROPOSAL_ID_RE = re.compile(r"^[0-9a-f]{64}$")
BUREAU_MANAGED_LAUNCHER = Path("/home/alex/.local/bin/bureau")
BUREAU_DEPLOYMENT_MANIFEST = (
    bureau_runtime.BUREAU_RUNTIME_ROOT / "deployment-manifest.json"
)
_MANAGED_LAUNCHER_MANIFEST_PATH_RE = re.compile(
    r"^manifest_path = Path\([\'\"]([^\'\"]+)[\'\"]\)$", re.MULTILINE
)
_MANAGED_LAUNCHER_MANIFEST_SHA_RE = re.compile(
    r"^expected_manifest_sha256 = [\'\"]([0-9a-f]{64})[\'\"]$", re.MULTILINE
)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private_root() -> Path:
    ARTIFACT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ARTIFACT_ROOT, 0o700)
    return ARTIFACT_ROOT


def _write_bound_json(path: Path, value: Any) -> str:
    raw = _canonical_json(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("JSON input exceeds the bounded adapter limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != raw:
            raise RuntimeError(f"bound adapter artifact conflicts: {path}")
        return _sha256(raw)
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
    return _sha256(raw)


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is not a regular file")
    raw = path.read_bytes()
    if len(raw) > MAX_OUTPUT_BYTES:
        raise RuntimeError(f"{label} exceeds the bounded adapter limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _managed_runtime_binding() -> dict[str, Any]:
    launcher_identity = bureau_runtime._regular_file_identity(
        BUREAU_MANAGED_LAUNCHER, label="managed-launcher"
    )
    if not os.access(BUREAU_MANAGED_LAUNCHER, os.X_OK):
        raise bureau_runtime.BureauLeaseContractError("managed-launcher-not-executable")
    try:
        launcher_text = BUREAU_MANAGED_LAUNCHER.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-unreadable",
            details={"error_type": type(exc).__name__},
        ) from None
    path_match = _MANAGED_LAUNCHER_MANIFEST_PATH_RE.search(launcher_text)
    sha_match = _MANAGED_LAUNCHER_MANIFEST_SHA_RE.search(launcher_text)
    if path_match is None or sha_match is None:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-binding-missing"
        )
    configured_manifest = Path(path_match.group(1))
    if configured_manifest != BUREAU_DEPLOYMENT_MANIFEST:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-path-mismatch"
        )
    manifest_identity = bureau_runtime._regular_file_identity(
        BUREAU_DEPLOYMENT_MANIFEST, label="deployment-manifest"
    )
    if manifest_identity["sha256"] != sha_match.group(1):
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-manifest-digest-mismatch"
        )
    try:
        manifest = json.loads(BUREAU_DEPLOYMENT_MANIFEST.read_text(encoding="utf-8"))
        if (
            manifest["schema_version"] != 1
            or manifest["kind"] != "bureau_runtime_deployment"
        ):
            raise ValueError("unsupported deployment manifest")
        source_commit = manifest["source_commit"]
        configured_registry_root = Path(manifest["canonical_registry_root"])
        configured_inventory_path = Path(manifest["canonical_registry_inventory_path"])
        if (
            not configured_registry_root.is_absolute()
            or configured_registry_root.is_symlink()
            or not configured_inventory_path.is_absolute()
            or configured_inventory_path.is_symlink()
        ):
            raise ValueError("canonical Registry paths must be absolute non-symlinks")
        registry_root = configured_registry_root.resolve(strict=True)
        inventory_path = configured_inventory_path.resolve(strict=True)
        registry_tree_sha256 = manifest["canonical_registry_tree_sha256"]
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "deployment-manifest-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    snapshots_root = (
        bureau_runtime.BUREAU_RUNTIME_ROOT / "registry-snapshots"
    ).resolve(strict=True)
    if not registry_root.is_dir() or not registry_root.is_relative_to(snapshots_root):
        raise bureau_runtime.BureauLeaseContractError("canonical-registry-root-invalid")
    if inventory_path.parent != registry_root:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-path-invalid"
        )
    inventory_identity = bureau_runtime._regular_file_identity(
        inventory_path, label="canonical-registry-inventory"
    )
    try:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        if (
            inventory["schema_version"] != 1
            or inventory["kind"] != "bureau_registry_snapshot"
            or inventory["source_commit"] != source_commit
            or inventory["tree_sha256"] != registry_tree_sha256
            or not isinstance(inventory["paths"], list)
            or not inventory["paths"]
        ):
            raise ValueError("invalid canonical Registry inventory")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-invalid",
            details={"error_type": type(exc).__name__},
        ) from None
    return {
        "launcher_path": BUREAU_MANAGED_LAUNCHER,
        "launcher_identity": launcher_identity,
        "manifest_path": BUREAU_DEPLOYMENT_MANIFEST,
        "manifest_identity": manifest_identity,
        "registry_root": registry_root,
        "inventory_path": inventory_path,
        "inventory_identity": inventory_identity,
        "source_commit": source_commit,
        "registry_tree_sha256": registry_tree_sha256,
    }


def _assert_managed_runtime_unchanged(binding: dict[str, Any]) -> None:
    observed_launcher = bureau_runtime._regular_file_identity(
        binding["launcher_path"], label="managed-launcher-readback"
    )
    observed_manifest = bureau_runtime._regular_file_identity(
        binding["manifest_path"], label="deployment-manifest-readback"
    )
    observed_inventory = bureau_runtime._regular_file_identity(
        binding["inventory_path"], label="canonical-registry-inventory-readback"
    )
    if observed_launcher != binding["launcher_identity"]:
        raise bureau_runtime.BureauLeaseContractError(
            "managed-launcher-changed-during-call"
        )
    if observed_manifest != binding["manifest_identity"]:
        raise bureau_runtime.BureauLeaseContractError(
            "deployment-manifest-changed-during-call"
        )
    if observed_inventory != binding["inventory_identity"]:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-inventory-changed-during-call"
        )
    try:
        observed_root = binding["registry_root"].resolve(strict=True)
    except OSError as exc:
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-readback-failed",
            details={"error_type": type(exc).__name__},
        ) from None
    if (
        observed_root != binding["registry_root"]
        or observed_root.is_symlink()
        or not observed_root.is_dir()
    ):
        raise bureau_runtime.BureauLeaseContractError(
            "canonical-registry-root-changed-during-call"
        )


def _adapter_failure(
    code: str,
    *,
    details: dict[str, Any] | None = None,
    effect_started: bool = False,
    ambiguity: bool = False,
    required_readback: list[str] | None = None,
    retryable: bool | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "grabowski_bureau_intake_adapter_failure",
        "code": code,
        "effect_started": effect_started,
        "retryable": (
            code in {"bureau-runtime-timeout", "bureau-runtime-unavailable"}
            if retryable is None
            else retryable
        ),
        "ambiguity": ambiguity,
        "required_readback": sorted(set(required_readback or [])),
        "details": details or {},
    }


def _invoke_bureau(
    arguments: list[str],
    *,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    mutation: bool = False,
    required_readback: list[str] | None = None,
) -> dict[str, Any]:
    readback = sorted(set(required_readback or []))
    try:
        runtime = bureau_runtime._contract_runtime()
        managed_runtime = _managed_runtime_binding()
    except (OSError, RuntimeError, bureau_runtime.BureauLeaseContractError) as exc:
        return _adapter_failure(
            "bureau-runtime-unavailable",
            details={"error_type": type(exc).__name__},
        )
    try:
        completed = subprocess.run(
            [
                str(runtime["python_launcher"]),
                "-I",
                str(managed_runtime["launcher_path"]),
                *arguments,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=bureau_runtime.BUREAU_RUNTIME_ROOT,
            env=bureau_runtime._safe_environment(),
        )
    except subprocess.TimeoutExpired:
        return _adapter_failure(
            "bureau-runtime-timeout",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=not mutation,
        )
    except OSError as exc:
        return _adapter_failure(
            "bureau-runtime-unavailable",
            details={"error_type": type(exc).__name__},
        )
    try:
        bureau_runtime._assert_contract_runtime_unchanged(runtime)
        _assert_managed_runtime_unchanged(managed_runtime)
    except (OSError, RuntimeError, bureau_runtime.BureauLeaseContractError) as exc:
        return _adapter_failure(
            "bureau-runtime-drift",
            details={"error_type": type(exc).__name__},
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    stdout = completed.stdout.encode("utf-8")
    stderr = completed.stderr.encode("utf-8")
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        return _adapter_failure(
            "bureau-output-too-large",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _adapter_failure(
            "bureau-output-invalid",
            details={
                "returncode": completed.returncode,
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
            },
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    if not isinstance(value, dict):
        return _adapter_failure(
            "bureau-output-invalid",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    payload = value.get("result", value)
    if not isinstance(payload, dict):
        return _adapter_failure(
            "bureau-output-invalid",
            effect_started=mutation,
            ambiguity=mutation,
            required_readback=readback,
            retryable=False,
        )
    return payload


def _audit(operation: str, payload: dict[str, Any], **extra: Any) -> None:
    base._append_audit(
        {
            "operation": operation,
            "bureau_result_kind": payload.get("kind"),
            "bureau_status": payload.get("status"),
            "bureau_code": payload.get("code"),
            "effect_started": bool(payload.get("effect_started")),
            "ambiguity": bool(payload.get("ambiguity")),
            **extra,
        }
    )


def _proposal_directory(proposal_id: str) -> Path:
    if not PROPOSAL_ID_RE.fullmatch(proposal_id):
        raise ValueError("proposal_id must be a lowercase SHA-256 digest")
    return _private_root() / "proposals" / proposal_id


@mcp.tool(name="grabowski_bureau_candidate_record", annotations=MUTATING)
def grabowski_bureau_candidate_record(request: dict[str, Any]) -> dict[str, Any]:
    """Record one source-bound Bureau candidate through the canonical typed intake contract."""
    operator._require_operator_mutation("terminal_execute")
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    raw = _canonical_json(request)
    request_id = _sha256(raw)
    request_path = _private_root() / "requests" / f"{request_id}.json"
    _write_bound_json(request_path, request)
    payload = _invoke_bureau(
        [
            "--json",
            "--json-envelope",
            "operator-candidate-record",
            "--request",
            str(request_path),
        ],
        mutation=True,
        required_readback=["candidate_by_idempotency_key"],
    )
    _audit("bureau-candidate-record", payload, request_sha256=request_id)
    return {**payload, "adapter_request_sha256": request_id}


@mcp.tool(name="grabowski_bureau_candidate_assess", annotations=READ_ONLY)
def grabowski_bureau_candidate_assess(
    candidate_id: str = "",
    event_id: int = 0,
    initiative: str = "",
    task_id: str = "",
) -> dict[str, Any]:
    """Assess one Bureau candidate read-only against current canonical Registry truth."""
    if bool(candidate_id) == bool(event_id):
        raise ValueError("provide exactly one of candidate_id or event_id")
    arguments = ["--json", "--json-envelope", "operator-candidate-assess"]
    arguments.extend(
        ["--candidate-id", candidate_id]
        if candidate_id
        else ["--event-id", str(event_id)]
    )
    if initiative:
        arguments.extend(["--initiative", initiative])
    if task_id:
        arguments.extend(["--task-id", task_id])
    return _invoke_bureau(arguments)


@mcp.tool(name="grabowski_bureau_task_propose", annotations=MUTATING)
def grabowski_bureau_task_propose(
    task_json: dict[str, Any],
    publishing_task_id: str,
    candidate_id: str = "",
    event_id: int = 0,
    unresolved_fields: list[str] | None = None,
    placeholder_justification: str = "",
    registry_root: str = str(BUREAU_ROOT),
) -> dict[str, Any]:
    """Create an immutable Bureau task proposal artifact without changing Registry or Queue truth."""
    operator._require_operator_mutation("terminal_execute", path=registry_root)
    if bool(candidate_id) == bool(event_id):
        raise ValueError("provide exactly one of candidate_id or event_id")
    if not isinstance(task_json, dict):
        raise ValueError("task_json must be an object")
    request = {
        "task_json": task_json,
        "publishing_task_id": publishing_task_id,
        "candidate_id": candidate_id,
        "event_id": event_id,
        "unresolved_fields": sorted(set(unresolved_fields or [])),
        "placeholder_justification": placeholder_justification,
        "registry_root": str(Path(registry_root).expanduser().resolve()),
    }
    proposal_id = _sha256(_canonical_json(request))
    directory = _proposal_directory(proposal_id)
    task_path = directory / "task.json"
    plan_path = directory / "plan.json"
    result_path = directory / "proposal-result.json"
    _write_bound_json(task_path, task_json)
    if plan_path.exists():
        if plan_path.is_symlink() or not plan_path.is_file():
            raise RuntimeError("proposal plan is not a regular file")
        os.chmod(plan_path, 0o600)
        preview = _invoke_bureau(
            [
                "--root",
                request["registry_root"],
                "--json",
                "--json-envelope",
                "operator-task-publish",
                "--plan",
                str(plan_path),
                "--preview",
            ]
        )
        if preview.get("kind") != "bureau_task_publication_preview":
            return {
                **preview,
                "adapter_proposal_id": proposal_id,
                "idempotent_adapter_replay": True,
            }
        result = (
            _read_json_object(result_path, label="proposal result")
            if result_path.exists()
            else {
                "schema_version": SCHEMA_VERSION,
                "kind": "bureau_task_proposal_result",
                "status": "existing",
                "proposal_sha256": preview.get("proposal_sha256"),
                "effect_started": False,
            }
        )
        return {
            **result,
            "adapter_proposal_id": proposal_id,
            "idempotent_adapter_replay": True,
            "publication_preview": preview,
        }
    arguments = [
        "--root",
        request["registry_root"],
        "--json",
        "--json-envelope",
        "operator-task-propose",
        "--task-json",
        str(task_path),
        "--publishing-task-id",
        publishing_task_id,
        "--write-plan",
        str(plan_path),
    ]
    arguments.extend(
        ["--candidate-id", candidate_id]
        if candidate_id
        else ["--event-id", str(event_id)]
    )
    for field in request["unresolved_fields"]:
        arguments.extend(["--unresolved-field", field])
    if placeholder_justification:
        arguments.extend(["--placeholder-justification", placeholder_justification])
    payload = _invoke_bureau(
        arguments,
        mutation=True,
        required_readback=["proposal_artifact"],
    )
    if payload.get("kind") == "bureau_task_proposal_result" and plan_path.exists():
        os.chmod(plan_path, 0o600)
        _write_bound_json(result_path, payload)
    _audit("bureau-task-propose", payload, proposal_id=proposal_id)
    return {
        **payload,
        "adapter_proposal_id": proposal_id,
        "idempotent_adapter_replay": False,
    }


@mcp.tool(name="grabowski_bureau_task_publish_preview", annotations=READ_ONLY)
def grabowski_bureau_task_publish_preview(
    proposal_id: str,
    registry_root: str = str(BUREAU_ROOT),
) -> dict[str, Any]:
    """Validate one immutable Bureau proposal and report its exact publication resources without effects."""
    plan_path = _proposal_directory(proposal_id) / "plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise FileNotFoundError(f"unknown proposal: {proposal_id}")
    return _invoke_bureau(
        [
            "--root",
            str(Path(registry_root).expanduser().resolve()),
            "--json",
            "--json-envelope",
            "operator-task-publish",
            "--plan",
            str(plan_path),
            "--preview",
        ]
    )


@mcp.tool(name="grabowski_bureau_task_publish", annotations=MUTATING)
def grabowski_bureau_task_publish(
    proposal_id: str,
    registry_root: str = str(BUREAU_ROOT),
    lease_ttl_seconds: int = 240,
) -> dict[str, Any]:
    """Acquire exact short Bureau leases, publish one reviewed task branch and PR, then release on a clear outcome."""
    resolved_root = str(Path(registry_root).expanduser().resolve())
    operator._require_operator_mutation("terminal_execute", path=resolved_root)
    operator._require_operator_mutation("resource_lease")
    if lease_ttl_seconds < 90 or lease_ttl_seconds > 300:
        raise ValueError("lease_ttl_seconds must be between 90 and 300")
    directory = _proposal_directory(proposal_id)
    plan_path = directory / "plan.json"
    if not plan_path.is_file() or plan_path.is_symlink():
        raise FileNotFoundError(f"unknown proposal: {proposal_id}")
    plan = _read_json_object(plan_path, label="proposal plan")
    publishing_task_id = plan.get("publishing_task_id")
    proposal_sha256 = plan.get("proposal_sha256")
    if not isinstance(publishing_task_id, str) or not isinstance(proposal_sha256, str):
        return _adapter_failure("proposal-binding-invalid")
    owner_id = f"bureau-publication:{proposal_sha256[:24]}"
    binding_path = directory / "lease-binding.json"
    receipt_path = directory / "publication-receipt.json"
    workspace_root = directory / "workspaces"
    _write_bound_json(
        binding_path, {"owner_id": owner_id, "task_id": publishing_task_id}
    )
    apply_arguments = [
        "--root",
        resolved_root,
        "--json",
        "--json-envelope",
        "operator-task-publish",
        "--plan",
        str(plan_path),
        "--apply",
        "--lease-binding",
        str(binding_path),
        "--resource-db",
        str(resources.RESOURCE_DB),
        "--workspace-root",
        str(workspace_root),
        "--receipt",
        str(receipt_path),
    ]
    if receipt_path.is_file() and not receipt_path.is_symlink():
        payload = _invoke_bureau(apply_arguments, timeout_seconds=30)
        _audit(
            "bureau-task-publish-receipt-replay",
            payload,
            proposal_id=proposal_id,
            owner_id=owner_id,
        )
        return {
            **payload,
            "adapter_proposal_id": proposal_id,
            "lease_owner_id": owner_id,
            "leases_acquired": False,
            "leases_released": True,
            "idempotent_adapter_replay": True,
        }
    preview = grabowski_bureau_task_publish_preview(proposal_id, resolved_root)
    if (
        preview.get("kind") != "bureau_task_publication_preview"
        or preview.get("status") != "ready"
    ):
        return preview
    resource_keys = preview.get("required_resource_keys")
    if (
        not isinstance(resource_keys, list)
        or len(resource_keys) != 2
        or any(not isinstance(key, str) for key in resource_keys)
    ):
        return _adapter_failure("publication-resource-contract-invalid")
    metadata = {
        "task_id": publishing_task_id,
        "operation": "registry-publication",
        "proposal_sha256": proposal_sha256,
        "bureau_phase": "work",
    }
    try:
        acquired = resources.acquire_resources(
            owner_id,
            resource_keys,
            purpose=f"Publish reviewed Bureau proposal {proposal_sha256}",
            ttl_seconds=lease_ttl_seconds,
            metadata=metadata,
        )
    except Exception as exc:
        payload = _adapter_failure(
            "publication-lease-acquire-failed",
            details={"error_type": type(exc).__name__, "resource_keys": resource_keys},
        )
        _audit(
            "bureau-task-publish", payload, proposal_id=proposal_id, owner_id=owner_id
        )
        return {
            **payload,
            "adapter_proposal_id": proposal_id,
            "lease_owner_id": owner_id,
        }
    base._append_audit(
        {
            "operation": "bureau-publication-resource-acquire",
            "owner_id": owner_id,
            "resource_keys": resource_keys,
            "proposal_sha256": proposal_sha256,
            "expires_at_unix": acquired["expires_at_unix"],
            "bureau_contract": acquired.get("bureau_contract"),
        }
    )
    payload = _invoke_bureau(
        apply_arguments,
        timeout_seconds=120,
        mutation=True,
        required_readback=[
            "publication_receipt",
            "remote_branch",
            "pull_request",
            "resource_leases",
        ],
    )
    receipt_readback_attempted = False
    if bool(payload.get("ambiguity")) and receipt_path.is_file():
        os.chmod(receipt_path, 0o600)
        receipt_readback_attempted = True
        replay = _invoke_bureau(apply_arguments, timeout_seconds=30)
        if replay.get("status") == "published" and not bool(replay.get("ambiguity")):
            payload = {**replay, "ambiguity_reconciled": "receipt-replay"}
    release_requested = not bool(payload.get("ambiguity"))
    leases_released = False
    release_error: dict[str, Any] | None = None
    if release_requested:
        try:
            released = resources.release_resources(owner_id, resource_keys)
            leases_released = len(released["released"]) == len(resource_keys)
            base._append_audit(
                {
                    "operation": "bureau-publication-resource-release",
                    "owner_id": owner_id,
                    "resource_keys": [
                        item["resource_key"] for item in released["released"]
                    ],
                    "proposal_sha256": proposal_sha256,
                }
            )
        except Exception as exc:
            release_error = {"error_type": type(exc).__name__}
    payload = {
        **payload,
        "receipt_readback_attempted": receipt_readback_attempted,
    }
    if payload.get("status") == "published" and receipt_path.is_file():
        os.chmod(receipt_path, 0o600)
        receipt = _read_json_object(receipt_path, label="publication receipt")
        payload = {
            **payload,
            "adapter_receipt_sha256": _sha256(_canonical_json(receipt)),
        }
    if release_error is not None:
        payload = {
            **payload,
            "cleanup_incomplete": True,
            "lease_release_error": release_error,
            "required_readback": sorted(
                set(payload.get("required_readback", [])) | {"resource_leases"}
            ),
        }
    _audit("bureau-task-publish", payload, proposal_id=proposal_id, owner_id=owner_id)
    return {
        **payload,
        "adapter_proposal_id": proposal_id,
        "lease_owner_id": owner_id,
        "lease_expires_at_unix": acquired["expires_at_unix"],
        "leases_acquired": True,
        "leases_released": leases_released,
        "idempotent_adapter_replay": False,
        "required_resource_keys": resource_keys,
    }
