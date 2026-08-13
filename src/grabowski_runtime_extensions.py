from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
from typing import Any

import grabowski_capabilities as capabilities
import grabowski_mcp as base
import grabowski_consumer_surface as consumer_surface
import grabowski_operator_core as operator

mcp = operator.mcp
HOME = operator.HOME
EVIDENCE_ROOT = operator.EVIDENCE_ROOT
PROTECTED_BRANCHES = operator.PROTECTED_BRANCHES
READ_ONLY = operator.READ_ONLY
MUTATING = operator.MUTATING
MAX_OUTPUT_BYTES = operator.MAX_OUTPUT_BYTES
LOGICAL_RUNTIME_SERVICE = "grabowski-mcp"
OPERATOR_UNIT = "grabowski-operator.service"
TUNNEL_UNIT = "tunnel-client-grabowski.service"
RUNTIME_TARGET = "heim-pc"

HOST_CAPABILITY_SCHEMA_VERSION = 1
HOST_CAPABILITY_RESULT_KIND = "grabowski.host_capability_resolution"
HOST_OPERATOR_ENTRY_ENV = "GRABOWSKI_HOST_OPERATOR_ENTRY"
HOST_OPERATOR_ENTRY_DEFAULT = HOME / ".config" / "heimgewebe" / "operator-entry.v1.json"
HOST_OPERATOR_ENTRY_MAX_BYTES = 512 * 1024
HOST_CAPABILITY_MAX_INTENT_CHARS = 160
HOST_CAPABILITY_AUTHORITY_KIND = "capability_locator_only"
HOST_CAPABILITY_DOES_NOT_ESTABLISH = (
    "execution_authority",
    "child_command_authority",
    "current_capability_readiness",
    "runtime_health",
    "audio_file_access",
    "cloud_or_metered_cost_authorization",
    "secret_access_authority",
    "capability_result_correctness",
    "future_contract_state",
)


class HostCapabilityResolutionError(RuntimeError):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _host_contract_path() -> Path:
    raw = os.environ.get(HOST_OPERATOR_ENTRY_ENV)
    path = Path(raw).expanduser() if raw is not None else HOST_OPERATOR_ENTRY_DEFAULT
    if not path.is_absolute():
        raise HostCapabilityResolutionError(
            "contract_path_invalid",
            f"{HOST_OPERATOR_ENTRY_ENV} must resolve to an absolute path",
        )
    return path


def _host_read_contract(
    path: Path,
    *,
    missing_code: str,
    invalid_code: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise HostCapabilityResolutionError(
            missing_code,
            "host operator-entry contract is unavailable",
            details={"path": str(path)},
        ) from exc
    except OSError as exc:
        raise HostCapabilityResolutionError(
            invalid_code,
            "host operator-entry contract cannot be opened safely",
            details={"path": str(path), "error_type": type(exc).__name__},
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HostCapabilityResolutionError(
                invalid_code,
                "host operator-entry contract is not a regular file",
                details={"path": str(path)},
            )
        if before.st_size < 2 or before.st_size > HOST_OPERATOR_ENTRY_MAX_BYTES:
            raise HostCapabilityResolutionError(
                invalid_code,
                "host operator-entry contract violates the size bound",
                details={"path": str(path), "bytes": before.st_size},
            )
        chunks: list[bytes] = []
        remaining = HOST_OPERATOR_ENTRY_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            raise HostCapabilityResolutionError(
                "contract_changed_during_read",
                "host operator-entry contract changed while it was read",
            )
        if len(payload) != before.st_size or len(payload) > HOST_OPERATOR_ENTRY_MAX_BYTES:
            raise HostCapabilityResolutionError(
                invalid_code,
                "host operator-entry contract read size changed",
            )
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HostCapabilityResolutionError(
                invalid_code,
                "host operator-entry contract is not valid UTF-8 JSON",
            ) from exc
        if not isinstance(decoded, dict):
            raise HostCapabilityResolutionError(
                invalid_code,
                "host operator-entry root must be an object",
            )
        return decoded, {
            "path": str(path),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "mtime_ns": before.st_mtime_ns,
        }
    finally:
        os.close(descriptor)


def _host_text(value: Any, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise HostCapabilityResolutionError("contract_invalid", f"{label} must be text")
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise HostCapabilityResolutionError("contract_invalid", f"{label} is invalid")
    return normalized


def _host_resolve_home(value: Any) -> Any:
    token = "${HOME}"
    if isinstance(value, str):
        if value == token:
            return str(HOME)
        prefix = token + "/"
        if value.startswith(prefix):
            relative = value[len(prefix):]
            if not relative or relative.startswith("/"):
                raise HostCapabilityResolutionError(
                    "contract_template_invalid",
                    "invalid HOME-relative locator path",
                )
            return str(HOME / relative)
        if token in value:
            raise HostCapabilityResolutionError(
                "contract_template_invalid",
                "unsupported HOME template placement",
            )
        return value
    if isinstance(value, list):
        return [_host_resolve_home(item) for item in value]
    if isinstance(value, dict):
        return {key: _host_resolve_home(item) for key, item in value.items()}
    return value


def _host_validate_locators(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if document.get("schemaVersion") != 1 or document.get("kind") != "heim_pc_operator_entry":
        raise HostCapabilityResolutionError("contract_invalid", "unsupported host operator-entry contract")
    if document.get("authority") != "static_local_entry_contract":
        raise HostCapabilityResolutionError("contract_invalid", "unsupported host operator-entry authority")
    model = document.get("operatorModel")
    if not isinstance(model, dict) or model.get("liveStateRequiresFreshRead") is not True:
        raise HostCapabilityResolutionError(
            "contract_invalid",
            "host operator-entry must require fresh live-state reads",
        )
    projection = document.get("projection")
    if not isinstance(projection, dict) or projection.get("byteIdenticalContractRequired") is not True:
        raise HostCapabilityResolutionError(
            "contract_invalid",
            "host operator-entry must require byte-identical projection",
        )
    path_resolution = document.get("pathResolution")
    variables = path_resolution.get("variables") if isinstance(path_resolution, dict) else None
    home = variables.get("HOME") if isinstance(variables, dict) else None
    if (
        not isinstance(home, dict)
        or home.get("source") != "operator_process_home"
        or home.get("required") is not True
        or home.get("mustResolveToAbsoluteDirectory") is not True
    ):
        raise HostCapabilityResolutionError(
            "contract_invalid",
            "host operator-entry HOME resolution contract is missing or invalid",
        )
    locators = document.get("capabilityLocators")
    if not isinstance(locators, dict) or not locators:
        raise HostCapabilityResolutionError(
            "capability_locators_missing",
            "host operator-entry publishes no capabilityLocators",
        )
    validated: dict[str, dict[str, Any]] = {}
    seen: dict[str, str] = {}
    for raw_id, raw_locator in locators.items():
        locator_id = _host_text(raw_id, label="locator id", maximum=160)
        if not isinstance(raw_locator, dict) or raw_locator.get("schemaVersion") != 1:
            raise HostCapabilityResolutionError("contract_invalid", f"locator {locator_id} is invalid")
        authority = _host_text(raw_locator.get("authority"), label=f"locator {locator_id} authority", maximum=240)
        authority_kind = _host_text(raw_locator.get("authorityKind"), label=f"locator {locator_id} authorityKind", maximum=120)
        if authority_kind != HOST_CAPABILITY_AUTHORITY_KIND:
            raise HostCapabilityResolutionError(
                "authority_kind_unsupported",
                f"locator {locator_id} is not locator-only",
            )
        intents = raw_locator.get("intents")
        if not isinstance(intents, list) or not intents:
            raise HostCapabilityResolutionError("contract_invalid", f"locator {locator_id} intents are invalid")
        normalized_intents: list[str] = []
        for raw_intent in intents:
            normalized = _host_text(
                raw_intent,
                label=f"locator {locator_id} intent",
                maximum=HOST_CAPABILITY_MAX_INTENT_CHARS,
            ).casefold()
            previous = seen.get(normalized)
            if previous is not None:
                raise HostCapabilityResolutionError(
                    "intent_ambiguous",
                    "host operator-entry publishes a duplicate capability intent",
                    details={
                        "intent": normalized,
                        "first_locator": previous,
                        "second_locator": locator_id,
                    },
                )
            seen[normalized] = locator_id
            normalized_intents.append(normalized)
        validated[locator_id] = {
            **raw_locator,
            "authority": authority,
            "authorityKind": authority_kind,
            "_normalized_intents": normalized_intents,
        }
    return validated


def _host_projection_identity(
    document: dict[str, Any],
    installed: dict[str, Any],
) -> dict[str, Any]:
    host = document.get("host")
    if not isinstance(host, dict):
        raise HostCapabilityResolutionError("contract_invalid", "host section is missing")
    canonical_raw = _host_text(
        host.get("canonicalEntryFile"),
        label="host.canonicalEntryFile",
        maximum=1024,
    )
    canonical_resolved = _host_resolve_home(canonical_raw)
    if not isinstance(canonical_resolved, str) or not Path(canonical_resolved).is_absolute():
        raise HostCapabilityResolutionError(
            "contract_invalid",
            "canonicalEntryFile did not resolve to an absolute path",
        )
    _canonical_document, canonical = _host_read_contract(
        Path(canonical_resolved),
        missing_code="canonical_contract_missing",
        invalid_code="canonical_contract_invalid",
    )
    if canonical["sha256"] != installed["sha256"]:
        raise HostCapabilityResolutionError(
            "installed_projection_drift",
            "installed host operator-entry differs from canonical source",
            details={
                "installed_sha256": installed["sha256"],
                "canonical_sha256": canonical["sha256"],
            },
        )
    return {
        "required": True,
        "matches": True,
        "installed": installed,
        "canonical": canonical,
    }


def resolve_host_capability(intent: str) -> dict[str, Any]:
    """Resolve one host-local capability intent from the installed static contract."""
    try:
        normalized_intent = _host_text(
            intent,
            label="intent",
            maximum=HOST_CAPABILITY_MAX_INTENT_CHARS,
        ).casefold()
        document, installed = _host_read_contract(
            _host_contract_path(),
            missing_code="installed_contract_missing",
            invalid_code="installed_contract_invalid",
        )
        locators = _host_validate_locators(document)
        projection = _host_projection_identity(document, installed)
        matches = [
            (locator_id, locator)
            for locator_id, locator in locators.items()
            if normalized_intent in locator["_normalized_intents"]
        ]
        if not matches:
            return {
                "schema_version": HOST_CAPABILITY_SCHEMA_VERSION,
                "kind": HOST_CAPABILITY_RESULT_KIND,
                "status": "not_found",
                "intent": intent.strip(),
                "matching": {
                    "strategy": "exact-casefold-declared-intent-v1",
                    "match_count": 0,
                    "available_intent_count": sum(
                        len(locator["_normalized_intents"])
                        for locator in locators.values()
                    ),
                },
                "contract_identity": projection,
                "does_not_establish": list(HOST_CAPABILITY_DOES_NOT_ESTABLISH),
            }
        locator_id, internal = matches[0]
        locator = {
            key: value
            for key, value in internal.items()
            if key != "_normalized_intents"
        }
        return {
            "schema_version": HOST_CAPABILITY_SCHEMA_VERSION,
            "kind": HOST_CAPABILITY_RESULT_KIND,
            "status": "resolved",
            "intent": intent.strip(),
            "matching": {
                "strategy": "exact-casefold-declared-intent-v1",
                "match_count": 1,
                "locator_id": locator_id,
            },
            "authority": locator["authority"],
            "authority_kind": locator["authorityKind"],
            "locator": locator,
            "resolved_locator": _host_resolve_home(locator),
            "contract_identity": projection,
            "policy_resolution": locator.get("policyResolution"),
            "does_not_establish": list(HOST_CAPABILITY_DOES_NOT_ESTABLISH),
        }
    except HostCapabilityResolutionError as exc:
        return {
            "schema_version": HOST_CAPABILITY_SCHEMA_VERSION,
            "kind": HOST_CAPABILITY_RESULT_KIND,
            "status": "blocked",
            "intent": intent.strip() if isinstance(intent, str) else None,
            "error": {
                "code": exc.code,
                "message": str(exc),
                "details": exc.details,
            },
            "does_not_establish": list(HOST_CAPABILITY_DOES_NOT_ESTABLISH),
        }


@mcp.tool(name="grabowski_host_capability_resolve", annotations=READ_ONLY)
def grabowski_host_capability_resolve(intent: str) -> dict[str, Any]:
    """Resolve one host capability from the installed contract without execution authority."""
    operator._require_operator_capability("file_read")
    return resolve_host_capability(intent)



def runtime_service_model(deployment: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = deployment if isinstance(deployment, dict) else {}
    return {
        "logical_runtime_service": LOGICAL_RUNTIME_SERVICE,
        "runtime_target": RUNTIME_TARGET,
        "operator_unit": OPERATOR_UNIT,
        "tunnel_unit": TUNNEL_UNIT,
        "deployment_release": metadata.get("release_id"),
        "repo_head": metadata.get("repo_head"),
    }


def _runtime_contract_snapshot() -> dict[str, Any]:
    manifest_path = base.DEPLOYMENT_MANIFEST
    try:
        if manifest_path.is_file() and manifest_path.stat().st_size <= base.MAX_MANIFEST_BYTES:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            contract = manifest.get("entrypoint_contract")
            if isinstance(contract, dict):
                return {"source": str(manifest_path), "contract": contract}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    repository_contract = Path(__file__).resolve().parents[1] / "config" / "runtime-entrypoint.json"
    try:
        contract = json.loads(repository_contract.read_text(encoding="utf-8"))
        if isinstance(contract, dict):
            return {"source": str(repository_contract), "contract": contract}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return {"source": None, "contract": {}}


def _git_state(repo: Path) -> dict[str, Any]:
    def run(*arguments: str) -> tuple[int, str]:
        completed = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=operator._safe_environment(),
        )
        return completed.returncode, completed.stdout.strip()
    head_code, head = run("rev-parse", "HEAD")
    branch_code, branch = run("branch", "--show-current")
    status_code, status = run("status", "--porcelain")
    return {
        "path": str(repo),
        "head": head if head_code == 0 else None,
        "branch": branch if branch_code == 0 else None,
        "dirty": bool(status) if status_code == 0 else None,
    }


def _worktree_context(runtime_head: str | None) -> dict[str, Any]:
    repository = HOME / "repos" / "grabowski"
    if not repository.is_dir():
        return {"repository": str(repository), "exists": False, "worktrees": []}
    completed = subprocess.run(
        ["git", "-C", str(repository), "worktree", "list", "--porcelain"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=operator._safe_environment(),
    )
    worktrees: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in completed.stdout.splitlines() + [""]:
        if not line:
            if current:
                current["matches_runtime"] = bool(runtime_head and current.get("head") == runtime_head)
                worktrees.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        if key == "worktree":
            current["path"] = value
        elif key == "HEAD":
            current["head"] = value
        elif key == "branch":
            current["branch"] = value.removeprefix("refs/heads/")
        elif key in {"detached", "bare", "prunable"}:
            current[key] = True
    canonical = next((item for item in worktrees if item.get("path") == str(repository)), None)
    return {
        "repository": str(repository),
        "exists": True,
        "command_returncode": completed.returncode,
        "canonical_checkout": canonical,
        "canonical_matches_runtime": bool(canonical and canonical.get("matches_runtime")),
        "runtime_matching_worktrees": [item for item in worktrees if item.get("matches_runtime")],
        "worktrees": worktrees,
    }


def _validate_branch_name(repo: Path, branch: str) -> str:
    if not branch or len(branch) > 200:
        raise ValueError("Invalid branch name")
    completed = subprocess.run(
        ["git", "-C", str(repo), "check-ref-format", "--branch", branch],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=operator._safe_environment(),
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or "Invalid branch name")
    return branch


@mcp.tool(name="grabowski_context", annotations=READ_ONLY)
def grabowski_context(
    profile: str = "concise",
    view: str | None = None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Return compact operator context; full evidence is explicitly opt-in."""
    default_view = "minimal" if profile == "concise" else "standard"
    selected_view = consumer_surface.normalize_view(view, default=default_view)
    if profile not in capabilities.PROFILE_CATEGORIES:
        raise ValueError(f"profile must be one of {sorted(capabilities.PROFILE_CATEGORIES)}")
    snapshot = _runtime_contract_snapshot()
    contract = snapshot["contract"]
    browser_operator_contract = contract.get("browser_operator_default")
    if not isinstance(browser_operator_contract, dict):
        browser_operator_contract = None
    expected_tools = contract.get("expected_tools", [])
    if not isinstance(expected_tools, list):
        expected_tools = []
    classification = capabilities.classify_contract(expected_tools)
    deployment = base._deployment_metadata()
    runtime_head = deployment.get("repo_head")
    repository = HOME / "repos" / "grabowski"
    canonical = _git_state(repository) if repository.is_dir() else {
        "path": str(repository),
        "head": None,
        "branch": None,
        "dirty": None,
    }
    canonical_matches_runtime = bool(
        isinstance(runtime_head, str) and canonical.get("head") == runtime_head
    )
    policy = base._load_policy()
    active_profile = base._active_profile(policy)
    known_gaps: list[str] = []
    for key, values in classification.items():
        if values:
            known_gaps.append(f"{key}: {', '.join(values[:20])}")
    if not expected_tools:
        known_gaps.append("runtime entrypoint contract is unavailable")
    if browser_operator_contract is None:
        known_gaps.append("browser operator default contract is unavailable")
    warnings: list[dict[str, Any]] = []
    if not canonical_matches_runtime:
        warnings.append({
            "code": "canonical_runtime_head_mismatch",
            "canonical_head": canonical.get("head"),
            "runtime_head": runtime_head,
        })
    if any(classification.values()):
        warnings.append({"code": "capability_catalog_drift", "classification": classification})
    warnings.append({"code": "client_snapshot_unobservable"})
    payload: dict[str, Any] = {
        "schema_version": 2,
        "profile": profile,
        "view": selected_view,
        "generated_at_unix": int(time.time()),
        "runtime": {
            "service": LOGICAL_RUNTIME_SERVICE,
            "service_model": runtime_service_model(deployment),
            "completion_status": deployment.get("completion_status"),
            "provenance_valid": bool(deployment.get("provenance_valid")),
            "runtime_binding_valid": bool(deployment.get("runtime_binding_valid")),
        },
        "browser_operator_contract": browser_operator_contract,
        "policy": {
            "mode": policy.get("mode"),
            "active_profile": active_profile["name"],
            "trusted_owner": base._trusted_owner_enabled(policy),
            "access_profiles": sorted(policy.get("profiles", {})),
            "max_risk_level": base._profile_values(policy, "max_risk_level") or "high",
        },
        "catalog": {
            "expected_tool_count": len(expected_tools),
            "catalog_matches_contract": not any(classification.values()),
            "classification": classification,
        },
        "checkout": {
            "repository": str(repository),
            "canonical_checkout": canonical,
            "canonical_matches_runtime": canonical_matches_runtime,
        },
        "warnings": warnings,
        "known_gaps": known_gaps,
        "recommended_next_action": (
            "inspect warnings before mutation" if warnings else "none"
        ),
        "evidence_refs": {
            "contract_source": snapshot["source"],
            "release_id": deployment.get("release_id"),
            "repo_head": runtime_head,
        },
        "does_not_establish": [
            "client_snapshot_freshness",
            "repository_correctness",
            "action_authority",
        ],
    }
    if selected_view in {"standard", "evidence"}:
        records = capabilities.capability_records(expected_tools)
        selected_records = capabilities.filter_capabilities(records, profile)
        category_counts: dict[str, int] = {}
        for record in selected_records:
            category = str(record.get("category", "unknown"))
            category_counts[category] = category_counts.get(category, 0) + 1
        worktrees = _worktree_context(runtime_head if isinstance(runtime_head, str) else None)
        payload["capability_summary"] = {
            "selected_count": len(selected_records),
            "by_category": dict(sorted(category_counts.items())),
        }
        if selected_view == "standard":
            payload["capability_summary"].update({
                "sample": selected_records[:20],
                "sample_truncated": len(selected_records) > 20,
            })
        else:
            payload["capability_summary"]["records_ref"] = "capabilities"
        payload["checkout"].update({
            "worktree_count": len(worktrees.get("worktrees", [])),
            "runtime_matching_worktree_count": len(
                worktrees.get("runtime_matching_worktrees", [])
            ),
        })
    if selected_view == "evidence":
        records = capabilities.capability_records(expected_tools)
        worktrees = _worktree_context(runtime_head if isinstance(runtime_head, str) else None)
        expected_tools_sha256 = hashlib.sha256(
            consumer_surface.canonical_json_bytes(expected_tools)
        ).hexdigest()
        compact_capabilities = [
            {
                key: record.get(key)
                for key in ("tool", "category", "risk_class")
                if key in record
            }
            for record in capabilities.filter_capabilities(records, profile)
        ]
        payload.update({
            "runtime_evidence": {
                "contract_source": snapshot["source"],
                "expected_tool_count": len(expected_tools),
                "expected_tools_sha256": expected_tools_sha256,
                "deployment": deployment,
            },
            "policy_evidence": {
                "capabilities": sorted(base._effective_capabilities(policy)),
                "read_roots": base._profile_values(policy, "read_roots"),
                "write_roots": base._profile_values(policy, "write_roots"),
                "write_excluded_roots": base._profile_values(
                    policy, "write_excluded_roots"
                ) or [],
                "secret_roots": base._secret_root_values(policy),
                "browser_profile_roots": base._browser_profile_root_values(policy),
                "secret_export_roots": base._secret_export_root_values(policy),
                "forbidden_capabilities": policy.get("forbidden_capabilities", []),
                "kill_switch": base._kill_switch_state(),
                "audit": base._verify_audit_log(base.AUDIT_LOG),
            },
            "capabilities": compact_capabilities,
            "checkout_evidence": {
                "command_returncode": worktrees.get("command_returncode"),
                "worktrees": worktrees.get("worktrees", []),
            },
            "drift": {
                "catalog_matches_contract": not any(classification.values()),
                "canonical_checkout_matches_runtime": worktrees.get(
                    "canonical_matches_runtime"
                ),
                "runtime_matching_worktree_count": len(
                    worktrees.get("runtime_matching_worktrees", [])
                ),
                "connector_snapshot_observable": False,
            },
        })
    return consumer_surface.project_fields(
        payload,
        fields=fields,
        required=consumer_surface.CONTEXT_REQUIRED_FIELDS,
    )


@mcp.tool(name="grabowski_git_branch", annotations=MUTATING)
def grabowski_git_branch(repo: str, action: str, branch: str, start_point: str = "HEAD") -> dict[str, Any]:
    """Create or switch one local Git branch through a typed operation."""
    operator._require_operator_mutation("git_cli")
    path = Path(repo).expanduser().resolve(strict=True)
    if not path.is_dir():
        raise ValueError(f"Repository path is not a directory: {path}")
    if (path == EVIDENCE_ROOT or EVIDENCE_ROOT in path.parents) and not operator._trusted_owner_mode():
        raise PermissionError("Git mutation of immutable evidence is blocked.")
    name = _validate_branch_name(path, branch)
    allowed = {"create", "switch", "create-and-switch"}
    if action not in allowed:
        raise ValueError(f"action must be one of {sorted(allowed)}")
    if action != "switch" and name in PROTECTED_BRANCHES and not operator._trusted_owner_mode():
        raise PermissionError("Creation of a protected main branch is blocked.")
    if not start_point or len(start_point) > 200 or start_point.startswith("-"):
        raise ValueError("Invalid start point")
    before = _git_state(path)
    if action == "create":
        arguments = ["branch", name, start_point]
    elif action == "switch":
        arguments = ["switch", name]
    else:
        arguments = ["switch", "-c", name, start_point]
    result = operator._run(
        ["git", "-C", str(path), *arguments],
        cwd=path,
        timeout_seconds=60,
        max_output_bytes=MAX_OUTPUT_BYTES,
    )
    after = _git_state(path)
    record = {
        "timestamp_unix": int(time.time()),
        "operation": "git-branch",
        "action": action,
        "repo": str(path),
        "branch": name,
        "start_point": start_point,
        "returncode": result["returncode"],
        "before": before,
        "after": after,
    }
    if result["returncode"] == 0:
        base._append_audit(record)
    return {"result": result, "audit": record}
