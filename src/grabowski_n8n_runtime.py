from __future__ import annotations

from collections.abc import Callable
from typing import Any

import grabowski_n8n_provider as provider


FORREST_PROFILE = "forrest-transcription-post-done-v1"
FORREST_SECRET_PATH = "/home/alex/.local/state/forrest-closeout-private/n8n-transcription-cutover-20260812.key"

SecretLoader = Callable[[str, str, str], dict[str, Any]]
ApplyRecorder = Callable[[str, dict[str, Any], dict[str, Any]], str]


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


def _load_secret_snapshot(
    action: str,
    request: dict[str, Any],
    secret_loader: SecretLoader,
) -> dict[str, Any]:
    snapshot = secret_loader(
        action,
        request["secret_path"],
        request["expected_secret_sha256"],
    )
    if not isinstance(snapshot, dict):
        raise N8nRuntimeError("secret loader returned invalid snapshot")
    source_path = snapshot.get("source_path")
    data = snapshot.get("data")
    digest = snapshot.get("sha256")
    size = snapshot.get("size")
    if source_path != FORREST_SECRET_PATH:
        raise N8nRuntimeError("resolved provider secret path changed")
    if digest != request["expected_secret_sha256"]:
        raise N8nRuntimeError("provider secret digest precondition failed")
    if not isinstance(data, bytes):
        raise N8nRuntimeError("secret loader returned invalid bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size != len(data):
        raise N8nRuntimeError("secret loader returned invalid size")
    return {
        "source_path": source_path,
        "data": data,
        "sha256": digest,
        "size": size,
    }


def dispatch(
    action: str,
    request: dict[str, Any],
    *,
    secret_loader: SecretLoader,
    apply_recorder: ApplyRecorder | None = None,
) -> dict[str, Any]:
    """Run one fixed n8n edge operation through injected composition-root ports."""
    if not isinstance(request, dict):
        raise N8nRuntimeError("provider request must be an object")

    call = _request_fields(action, request)
    if not callable(secret_loader):
        raise N8nRuntimeError("secret loader is unavailable")
    if action == "apply" and not callable(apply_recorder):
        raise N8nRuntimeError("apply recorder is unavailable")

    snapshot = _load_secret_snapshot(action, request, secret_loader)

    try:
        if action == "verify":
            output = provider.verify(secret_data=snapshot["data"], **call)
        else:
            output = provider.apply(secret_data=snapshot["data"], **call)
    except provider.N8nProviderError as exc:
        raise N8nRuntimeError(str(exc)) from exc

    if action == "verify":
        return output

    audit_record_sha256 = apply_recorder(
        action,
        {
            "source_path": snapshot["source_path"],
            "sha256": snapshot["sha256"],
            "size": snapshot["size"],
        },
        output,
    )
    if not isinstance(audit_record_sha256, str) or not audit_record_sha256:
        raise N8nRuntimeError("apply recorder returned invalid audit receipt")
    return {
        **output,
        "auditRecordSha256": audit_record_sha256,
    }
