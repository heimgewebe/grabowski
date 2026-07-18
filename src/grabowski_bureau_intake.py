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
_RUNTIME_WRAPPER = r"""
import hashlib
import importlib
import json
from pathlib import Path
import sys

binding = json.loads(sys.argv[1])
argv = json.loads(sys.argv[2])

def digest(path_string):
    return hashlib.sha256(Path(path_string).read_bytes()).hexdigest()

def verify_files():
    for expected in binding["package_files"].values():
        if digest(expected["path"]) != expected["sha256"]:
            raise RuntimeError("bound Bureau package file changed")

verify_files()
cli = importlib.import_module("bureau.cli")
loaded = Path(cli.__file__).resolve()
expected = Path(binding["module_paths"]["bureau.cli"]).resolve()
if loaded != expected:
    raise RuntimeError("unexpected Bureau CLI module path")
verify_files()
returncode = cli.main(argv)
verify_files()
raise SystemExit(returncode)
"""


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


def _runtime_binding(runtime: dict[str, Any]) -> str:
    return json.dumps(
        {
            "module_paths": {
                name: str(path) for name, path in runtime["module_paths"].items()
            },
            "package_files": {
                relative: {
                    "path": str(runtime["package_paths"][relative]),
                    "sha256": identity["sha256"],
                }
                for relative, identity in runtime["package_identities"].items()
            },
        },
        sort_keys=True,
        separators=(",", ":"),
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
                "-c",
                _RUNTIME_WRAPPER,
                _runtime_binding(runtime),
                json.dumps(arguments, separators=(",", ":")),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
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
