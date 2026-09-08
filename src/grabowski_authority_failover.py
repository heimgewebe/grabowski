"""Classified local-first authority relay for the secondary operator.

G6.6 keeps canonical lifecycle truth on heim-pc.  The secondary operator may
relay an existing typed authority operation only when the corresponding local
canonical authority is physically unavailable.  Domain, policy, safety,
review, CI and authority denials are never failover triggers.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


SCHEMA_VERSION = 1
REQUEST_KIND = "grabowski.authority_relay_request"
RESPONSE_KIND = "grabowski.authority_relay_response"
SECONDARY_BRANDING_VARIANTS = frozenset({"der-kleine-maulwurf", "kleiner-maulwurf"})
BRANDING_ENVIRONMENT = "GRABOWSKI_MCP_BRANDING_VARIANT"
CANONICAL_AUTHORITY_HOST = "heim-pc"
PRIMARY_HOME = Path("/home/alex")
PRIMARY_RUNTIME_ROOT = PRIMARY_HOME / ".local/share/grabowski-mcp"
PRIMARY_RUNTIME_PYTHON = PRIMARY_RUNTIME_ROOT / ".venv/bin/python"
PRIMARY_BUREAU_CONTROL_ROOT = Path("/home/alex/repos/.bureau-worktrees/control-main")
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2_000_000
MAX_RELAY_TIMEOUT_SECONDS = 120
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

# The command is server-owned.  The request is inert base64 JSON; no caller
# supplied Python, shell text, executable or remote path is accepted.
REMOTE_BOOTSTRAP_CODE = (
    "import sys;"
    "import grabowski_authority_failover as r;"
    "raise SystemExit(r.remote_main(sys.argv[1]))"
)
REMOTE_BOOTSTRAP_SHA256 = hashlib.sha256(REMOTE_BOOTSTRAP_CODE.encode("utf-8")).hexdigest()

BUREAU_OPERATIONS: dict[str, tuple[str, frozenset[str]]] = {
    "candidate_record": (
        "grabowski_bureau_candidate_record",
        frozenset({"request"}),
    ),
    "candidate_assess": (
        "grabowski_bureau_candidate_assess",
        frozenset(
            {
                "selector",
                "expected_initiative",
                "expected_task_id",
                "candidate_id",
                "event_id",
                "idempotency_key",
                "initiative",
                "task_id",
            }
        ),
    ),
    "task_propose": (
        "grabowski_bureau_task_propose",
        frozenset(
            {
                "task_json",
                "publishing_task_id",
                "candidate_id",
                "event_id",
                "unresolved_fields",
                "placeholder_justification",
                "registry_root",
            }
        ),
    ),
    "task_review": (
        "grabowski_bureau_task_review",
        frozenset({"proposal_id", "reviewer", "proposal_sha256", "registry_root"}),
    ),
    "task_publish_preview": (
        "grabowski_bureau_task_publish_preview",
        frozenset({"proposal_id", "registry_root"}),
    ),
    "task_publish": (
        "grabowski_bureau_task_publish",
        frozenset({"proposal_id", "registry_root", "lease_ttl_seconds"}),
    ),
}


class AuthorityRelayError(RuntimeError):
    """Fail-closed classified relay failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        dispatched: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.details = details or {}
        self.dispatched = bool(dispatched)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AuthorityRelayError(
            "request_not_json",
            "authority relay request is not canonical JSON",
        ) from exc


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def is_secondary_operator() -> bool:
    return os.environ.get(BRANDING_ENVIRONMENT, "").strip() in SECONDARY_BRANDING_VARIANTS


def systemkatalog_failure_is_failover_trigger(code: str) -> bool:
    """Only physical absence of the local canonical root can trigger relay."""
    return is_secondary_operator() and code == "root_unavailable"


def bureau_route(registry_root: str | None = None) -> dict[str, Any]:
    """Classify Bureau authority without converting denials into failover."""
    if not is_secondary_operator():
        return {"route": "local", "reason": "primary-or-nonsecondary-runtime"}
    if registry_root is not None:
        try:
            requested = Path(registry_root).expanduser()
        except (TypeError, ValueError):
            return {"route": "local", "reason": "registry-root-invalid"}
        if not requested.is_absolute() or requested != PRIMARY_BUREAU_CONTROL_ROOT:
            return {"route": "local", "reason": "caller-specific-registry-root"}

    # Lazy import avoids introducing a runtime cycle into the Bureau modules.
    import grabowski_bureau_leases as bureau_runtime

    try:
        bureau_runtime._validated_bureau_repository_root()
    except bureau_runtime.BureauLeaseContractError as exc:
        if exc.code == "bureau-repository-unavailable":
            return {
                "route": "remote-primary",
                "reason": "local-bureau-repository-unavailable",
                "local_code": exc.code,
            }
        return {
            "route": "local",
            "reason": "local-bureau-contract-denial",
            "local_code": exc.code,
        }
    try:
        bureau_runtime._contract_runtime()
    except bureau_runtime.BureauLeaseContractError as exc:
        if exc.code == "contract-executable-unavailable":
            return {
                "route": "remote-primary",
                "reason": "local-bureau-runtime-unavailable",
                "local_code": exc.code,
            }
        return {
            "route": "local",
            "reason": "local-bureau-runtime-denial",
            "local_code": exc.code,
        }
    except OSError as exc:
        # An OS-level disappearance after the repository preflight is still a
        # physical availability failure, not a domain decision.
        if isinstance(exc, FileNotFoundError):
            return {
                "route": "remote-primary",
                "reason": "local-bureau-runtime-unavailable",
                "local_error_type": type(exc).__name__,
            }
        return {
            "route": "local",
            "reason": "local-bureau-runtime-error",
            "local_error_type": type(exc).__name__,
        }
    return {"route": "local", "reason": "local-bureau-authority-ready"}


def _validate_bureau_request(operation: str, arguments: dict[str, Any]) -> None:
    contract = BUREAU_OPERATIONS.get(operation)
    if contract is None:
        raise AuthorityRelayError(
            "operation_not_allowed",
            "Bureau relay operation is not allowlisted",
        )
    if not isinstance(arguments, dict) or set(arguments) != set(contract[1]):
        raise AuthorityRelayError(
            "arguments_contract_mismatch",
            "Bureau relay arguments do not match the operation contract",
        )
    registry_root = arguments.get("registry_root")
    if registry_root is not None and registry_root != str(PRIMARY_BUREAU_CONTROL_ROOT):
        raise AuthorityRelayError(
            "registry_root_not_canonical",
            "remote Bureau relay only accepts the canonical control checkout",
        )


def _request(authority: str, operation: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
    if authority not in {"bureau", "systemkatalog"}:
        raise AuthorityRelayError("authority_not_allowed", "authority is not relayable")
    if authority == "bureau":
        _validate_bureau_request(operation, arguments)
    elif operation != "query" or set(arguments) != {"operation", "value"}:
        raise AuthorityRelayError(
            "arguments_contract_mismatch",
            "Systemkatalog relay arguments do not match the query contract",
        )
    request = {
        "schema_version": SCHEMA_VERSION,
        "kind": REQUEST_KIND,
        "authority": authority,
        "operation": operation,
        "arguments": arguments,
    }
    payload = _canonical_json(request)
    if len(payload) > MAX_REQUEST_BYTES:
        raise AuthorityRelayError(
            "request_too_large",
            "authority relay request exceeds the fixed transport bound",
            details={"bytes": len(payload), "maximum": MAX_REQUEST_BYTES},
        )
    return request, payload, _sha256(payload)


def _relay_failure_details(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "returncode": result.get("returncode"),
        "timed_out": bool(result.get("timed_out")),
        "stdout_truncated": bool(result.get("stdout_truncated")),
        "stderr_truncated": bool(result.get("stderr_truncated")),
        "stdout_sha256": _sha256(str(result.get("stdout", "")).encode("utf-8")),
        "stderr_sha256": _sha256(str(result.get("stderr", "")).encode("utf-8")),
    }


def relay_to_primary(
    authority: str,
    operation: str,
    arguments: dict[str, Any],
    *,
    mutation: bool,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Relay exactly one typed operation to the canonical primary runtime."""
    if not is_secondary_operator():
        raise AuthorityRelayError(
            "relay_not_secondary",
            "authority relay is available only to the secondary operator",
        )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or timeout_seconds < 1
        or timeout_seconds > MAX_RELAY_TIMEOUT_SECONDS
    ):
        raise AuthorityRelayError("timeout_invalid", "authority relay timeout is invalid")
    _normalized, payload, request_sha256 = _request(authority, operation, arguments)
    encoded = base64.b64encode(payload).decode("ascii")

    import grabowski_fleet as fleet

    dispatched = False
    try:
        dispatched = True
        observation = fleet.run_fleet_host(
            CANONICAL_AUTHORITY_HOST,
            [
                str(PRIMARY_RUNTIME_PYTHON),
                "-I",
                "-c",
                REMOTE_BOOTSTRAP_CODE,
                encoded,
            ],
            timeout_seconds=timeout_seconds,
            max_output_bytes=MAX_RESPONSE_BYTES,
        )
    except Exception as exc:
        raise AuthorityRelayError(
            "relay_transport_failed",
            "canonical authority relay transport failed",
            details={"error_type": type(exc).__name__},
            dispatched=dispatched and mutation,
        ) from exc
    result = observation.get("result")
    if not isinstance(result, dict):
        raise AuthorityRelayError(
            "relay_result_invalid",
            "canonical authority relay returned no bounded result",
            dispatched=mutation,
        )
    if (
        result.get("returncode") != 0
        or result.get("timed_out") is True
        or result.get("stdout_truncated") is True
        or result.get("stderr_truncated") is True
    ):
        raise AuthorityRelayError(
            "relay_remote_failed",
            "canonical authority relay did not return a complete success envelope",
            details=_relay_failure_details(result),
            dispatched=mutation,
        )
    stdout = result.get("stdout")
    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise AuthorityRelayError(
            "relay_response_invalid",
            "canonical authority relay response is missing or exceeds its bound",
            dispatched=mutation,
        )
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise AuthorityRelayError(
            "relay_response_invalid",
            "canonical authority relay response is not JSON",
            details={"stdout_sha256": _sha256(stdout.encode("utf-8"))},
            dispatched=mutation,
        ) from exc
    if (
        not isinstance(response, dict)
        or response.get("schema_version") != SCHEMA_VERSION
        or response.get("kind") != RESPONSE_KIND
        or response.get("authority") != authority
        or response.get("operation") != operation
        or response.get("request_sha256") != request_sha256
        or not isinstance(response.get("result"), dict)
    ):
        raise AuthorityRelayError(
            "relay_response_contract_mismatch",
            "canonical authority relay response is not bound to the request",
            dispatched=mutation,
        )
    runtime_binding = response.get("runtime_binding")
    if (
        not isinstance(runtime_binding, dict)
        or not isinstance(runtime_binding.get("release_id"), str)
        or not isinstance(runtime_binding.get("repo_head"), str)
        or not isinstance(runtime_binding.get("relay_source_sha256"), str)
        or SHA256_RE.fullmatch(runtime_binding["relay_source_sha256"]) is None
        or runtime_binding.get("provenance_valid") is not True
        or runtime_binding.get("runtime_binding_valid") is not True
        or runtime_binding.get("artifact_integrity_valid") is not True
    ):
        raise AuthorityRelayError(
            "relay_runtime_binding_invalid",
            "canonical authority relay response lacks a valid runtime binding",
            dispatched=mutation,
        )
    response_sha256 = _sha256(_canonical_json(response))
    return {
        **response["result"],
        "authority_failover": {
            "schema_version": SCHEMA_VERSION,
            "route": "remote-primary",
            "authority_host": CANONICAL_AUTHORITY_HOST,
            "reason": "local-authority-unavailable",
            "automatic_failback": "local-first-next-call",
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
            "remote_runtime": runtime_binding,
            "bootstrap_sha256": REMOTE_BOOTSTRAP_SHA256,
        },
    }


def relay_bureau(
    operation: str,
    arguments: dict[str, Any],
    *,
    mutation: bool,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    return relay_to_primary(
        "bureau",
        operation,
        arguments,
        mutation=mutation,
        timeout_seconds=timeout_seconds,
    )


def relay_systemkatalog(operation: str, value: str | None) -> dict[str, Any]:
    return relay_to_primary(
        "systemkatalog",
        "query",
        {"operation": operation, "value": value},
        mutation=False,
        timeout_seconds=30,
    )


def _runtime_binding() -> dict[str, Any]:
    try:
        import grabowski_mcp as runtime

        deployment = runtime._deployment_metadata()
    except Exception as exc:
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary runtime integrity cannot be established",
            details={"error_type": type(exc).__name__},
        ) from exc
    if (
        deployment.get("completion_status") != "complete"
        or deployment.get("provenance_valid") is not True
        or deployment.get("runtime_binding_valid") is not True
        or deployment.get("artifact_integrity_valid") is not True
    ):
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary runtime is not complete and integrity-valid",
            details={
                "completion_status": deployment.get("completion_status"),
                "provenance_valid": deployment.get("provenance_valid") is True,
                "runtime_binding_valid": deployment.get("runtime_binding_valid") is True,
                "artifact_integrity_valid": deployment.get("artifact_integrity_valid") is True,
            },
        )
    release_id = deployment.get("release_id")
    repo_head = deployment.get("repo_head")
    if not isinstance(release_id, str) or not release_id:
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary runtime lacks release identity",
        )
    if not isinstance(repo_head, str) or not re.fullmatch(r"[0-9a-f]{40}", repo_head):
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary runtime lacks repository identity",
        )
    source_identity = deployment.get("source_identity_by_module")
    source_hashes = deployment.get("source_sha256s")
    if (
        not isinstance(source_identity, dict)
        or source_identity.get("grabowski_authority_failover") is not True
        or not isinstance(source_hashes, dict)
        or not isinstance(source_hashes.get("grabowski_authority_failover"), str)
        or SHA256_RE.fullmatch(source_hashes["grabowski_authority_failover"]) is None
    ):
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary authority relay source is not deployment-bound",
        )
    try:
        relay_source_sha256 = _sha256(Path(__file__).read_bytes())
    except OSError as exc:
        raise AuthorityRelayError(
            "primary_relay_source_unreadable",
            "primary relay source cannot be bound",
        ) from exc
    if relay_source_sha256 != source_hashes["grabowski_authority_failover"]:
        raise AuthorityRelayError(
            "primary_runtime_integrity_invalid",
            "primary authority relay source does not match the deployed manifest",
        )
    return {
        "release_id": release_id,
        "repo_head": repo_head,
        "relay_source_sha256": relay_source_sha256,
        "provenance_valid": True,
        "runtime_binding_valid": True,
        "artifact_integrity_valid": True,
    }


def _decode_remote_request(encoded_request: str) -> tuple[dict[str, Any], bytes, str]:
    if not isinstance(encoded_request, str) or not encoded_request:
        raise AuthorityRelayError("request_invalid", "relay request is empty")
    try:
        payload = base64.b64decode(encoded_request, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AuthorityRelayError("request_invalid", "relay request is not valid base64") from exc
    if len(payload) > MAX_REQUEST_BYTES:
        raise AuthorityRelayError("request_too_large", "relay request exceeds its bound")
    try:
        request = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityRelayError("request_invalid", "relay request is not valid JSON") from exc
    if not isinstance(request, dict) or set(request) != {
        "schema_version",
        "kind",
        "authority",
        "operation",
        "arguments",
    }:
        raise AuthorityRelayError("request_contract_mismatch", "relay request shape is invalid")
    if request.get("schema_version") != SCHEMA_VERSION or request.get("kind") != REQUEST_KIND:
        raise AuthorityRelayError("request_contract_mismatch", "relay request contract is invalid")
    authority = request.get("authority")
    operation = request.get("operation")
    arguments = request.get("arguments")
    if not isinstance(authority, str) or not isinstance(operation, str) or not isinstance(arguments, dict):
        raise AuthorityRelayError("request_contract_mismatch", "relay request values are invalid")
    canonical = _canonical_json(request)
    if canonical != payload:
        raise AuthorityRelayError("request_not_canonical", "relay request is not canonical JSON")
    return request, payload, _sha256(payload)


def _dispatch_remote(request: dict[str, Any]) -> dict[str, Any]:
    authority = request["authority"]
    operation = request["operation"]
    arguments = request["arguments"]
    if authority == "systemkatalog":
        if operation != "query" or set(arguments) != {"operation", "value"}:
            raise AuthorityRelayError("request_contract_mismatch", "Systemkatalog relay request is invalid")
        import grabowski_systemkatalog

        return grabowski_systemkatalog.query_systemkatalog(
            arguments["operation"], arguments["value"]
        )
    if authority != "bureau":
        raise AuthorityRelayError("authority_not_allowed", "relay authority is not allowed")
    _validate_bureau_request(operation, arguments)
    function_name = BUREAU_OPERATIONS[operation][0]
    import grabowski_bureau_intake

    function = getattr(grabowski_bureau_intake, function_name, None)
    if not callable(function):
        raise AuthorityRelayError("remote_surface_missing", "primary Bureau surface is unavailable")
    return function(**arguments)


def remote_main(encoded_request: str) -> int:
    """Private SSH relay entrypoint executed only on the canonical primary host."""
    try:
        if is_secondary_operator() or Path.home() != PRIMARY_HOME:
            raise AuthorityRelayError(
                "remote_host_not_primary",
                "authority relay execution is not on the canonical primary account",
            )
        request, _payload, request_sha256 = _decode_remote_request(encoded_request)
        runtime_binding = _runtime_binding()
        result = _dispatch_remote(request)
        if not isinstance(result, dict):
            raise AuthorityRelayError("remote_result_invalid", "typed authority returned no object")
        response = {
            "schema_version": SCHEMA_VERSION,
            "kind": RESPONSE_KIND,
            "authority": request["authority"],
            "operation": request["operation"],
            "request_sha256": request_sha256,
            "runtime_binding": runtime_binding,
            "result": result,
        }
        encoded = _canonical_json(response)
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise AuthorityRelayError("response_too_large", "typed authority response exceeds its bound")
        print(encoded.decode("utf-8"))
        return 0
    except AuthorityRelayError as exc:
        error = {
            "schema_version": SCHEMA_VERSION,
            "kind": "grabowski.authority_relay_error",
            "code": exc.code,
            "message": str(exc),
            "details": exc.details,
        }
        print(_canonical_json(error).decode("utf-8"))
        return 2
