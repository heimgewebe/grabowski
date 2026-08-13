from __future__ import annotations

from typing import Any

import grabowski_n8n_provider as provider


FORREST_PROFILE = "forrest-transcription-post-done-v1"
FORREST_SECRET_PATH = "/home/alex/.local/state/forrest-closeout-private/n8n-transcription-cutover-20260812.key"


class N8nRuntimeError(RuntimeError):
    """Fail-closed runtime adapter error without secret material."""


def _request_fields(action: str, request: dict[str, Any]) -> dict[str, Any]:
    profile = request.get("provider_profile")
    secret_path = request.get("secret_path")
    expected_secret_sha256 = request.get("expected_secret_sha256")
    if profile != FORREST_PROFILE:
        raise N8nRuntimeError("provider profile is not runtime-allowlisted")
    if secret_path != FORREST_SECRET_PATH:
        raise N8nRuntimeError("provider secret path is not runtime-allowlisted")
    if not isinstance(expected_secret_sha256, str):
        raise N8nRuntimeError("provider secret digest is required")
    if action == "verify":
        return {
            "provider_profile": profile,
            "expected_state": request.get("expected_state"),
        }
    if action == "apply":
        return {
            "provider_profile": profile,
            "expected_version_id": request.get("expected_version_id"),
            "expected_response_sha256": request.get("expected_response_sha256"),
        }
    raise N8nRuntimeError("unsupported n8n runtime action")


def dispatch(action: str, request: dict[str, Any]) -> dict[str, Any]:
    """Consume one fixed n8n credential through Grabowski's bound secret primitives."""
    if not isinstance(request, dict):
        raise N8nRuntimeError("provider request must be an object")

    call = _request_fields(action, request)

    # Imported lazily to avoid an import cycle: grabowski_mcp imports grabowski_grips,
    # while this adapter is invoked only after the MCP runtime has finished loading.
    import grabowski_mcp as runtime

    secret_path = request["secret_path"]
    expected_secret_sha256 = request["expected_secret_sha256"]
    if action == "apply":
        runtime._require_mutations_enabled("secret_use", path=secret_path, fresh_preflight=True)
    else:
        runtime._require_capability("secret_use")
        runtime._require_valid_audit_chain()

    source = runtime._resolve_secret_use_source(secret_path)
    if str(source) != FORREST_SECRET_PATH:
        raise N8nRuntimeError("resolved provider secret path changed")
    policy = runtime._load_policy()
    snapshot = runtime._read_bound_regular_bytes(
        source,
        runtime._policy_limit(policy, "max_read_bytes"),
    )
    if snapshot["sha256"] != expected_secret_sha256:
        raise N8nRuntimeError("provider secret digest precondition failed")

    try:
        if action == "verify":
            output = provider.verify(secret_data=snapshot["data"], **call)
        else:
            output = provider.apply(secret_data=snapshot["data"], **call)
    except provider.N8nProviderError as exc:
        raise N8nRuntimeError(str(exc)) from exc

    # The verify grip is published as read-only. Its receipt already binds the
    # provider response, so it must not create local transaction or audit state.
    if action == "verify":
        return output

    transaction_id, transaction_dir = runtime._new_transaction_dir(
        "n8n-provider-apply", source
    )
    evidence = {
        "schema_version": 1,
        "transaction_id": transaction_id,
        "operation": f"n8n-provider-{action}",
        "provider_profile": FORREST_PROFILE,
        "source_path": str(source),
        "source_sha256": snapshot["sha256"],
        "source_size": snapshot["size"],
        "provider_mutation_performed": output.get("providerMutationPerformed") is True,
        "output_sha256": runtime.grabowski_grips.sha256_json(output),
    }
    runtime._write_json_evidence(transaction_dir / "provider.json", evidence)
    audit_record_sha256 = runtime._append_audit_with_digest(
        {
            "timestamp": runtime._utc_timestamp(),
            "operation": f"n8n-provider-{action}",
            "transaction_id": transaction_id,
            "path": str(source),
            "source_path": str(source),
            "after_sha256": snapshot["sha256"],
            "bytes": snapshot["size"],
            "provider_profile": FORREST_PROFILE,
            "provider_mutation_performed": output.get("providerMutationPerformed") is True,
            "output_sha256": evidence["output_sha256"],
        }
    )
    return {
        **output,
        "auditRecordSha256": audit_record_sha256,
    }
