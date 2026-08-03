from __future__ import annotations

import asyncio
import secrets
import threading
from typing import Annotated, Any
import weakref

from pydantic import Field

import grabowski_operator_core
import grabowski_checkouts
import grabowski_checkout_binding_reconciler
import grabowski_current_work_surface
import grabowski_operator_optimization
import grabowski_runtime_extensions
import grabowski_audit_query
import grabowski_read_surface
import grabowski_self_deploy
import grabowski_fleet
import grabowski_juno
import grabowski_juno_storage
import grabowski_artifacts
import grabowski_merge_delivery_surface
import grabowski_agent_workspace
import grabowski_agent_workspace_observer
import grabowski_operations
import grabowski_privileged
import grabowski_recovery
import grabowski_blockade_runtime
import grabowski_friction
import grabowski_agent_bootstrap
import grabowski_recall
import grabowski_context_fabric
import grabowski_resources
import grabowski_bureau_intake
import grabowski_bureau_pickup
import grabowski_tasks
import grabowski_agent_competition
import grabowski_coding_agent_router
import grabowski_workers
import grabowski_reposkop_context  # noqa: F401


_TRANSPORT_ROUNDTRIP = grabowski_operator_core.base.grabowski_transport_roundtrip
_ORIGINAL_TRANSPORT_SCOPE_VALIDATOR = _TRANSPORT_ROUNDTRIP.validate_client_scope
_ORIGINAL_TRANSPORT_SCOPE_RESOLVER = (
    grabowski_operator_core.base._transport_roundtrip_client_scope
)
_TRANSPORT_SESSION_SCOPE_LOCK = threading.Lock()
_TRANSPORT_SESSION_SCOPES: weakref.WeakKeyDictionary[object, str] = (
    weakref.WeakKeyDictionary()
)


def _validate_runtime_transport_client_scope(value: Any) -> dict[str, str]:
    """Extend the transport contract with one non-authenticating server-session scope."""
    if (
        isinstance(value, dict)
        and set(value) == {"kind", "label"}
        and value.get("kind") == "server_session"
    ):
        label = value.get("label")
        if (
            not isinstance(label, str)
            or not label
            or label.strip() != label
            or "\x00" in label
            or len(label.encode("utf-8")) > 512
        ):
            raise _TRANSPORT_ROUNDTRIP.TransportRoundtripError(
                "transport client scope label is invalid"
            )
        return {"kind": "server_session", "label": label}
    return _ORIGINAL_TRANSPORT_SCOPE_VALIDATOR(value)


def _runtime_transport_client_scope(ctx: Any) -> dict[str, str]:
    """Prefer declared client metadata, then isolate unlabeled stateful sessions."""
    declared_scope = _ORIGINAL_TRANSPORT_SCOPE_RESOLVER(ctx)
    if declared_scope["kind"] != "shared_unlabeled" or ctx is None:
        return declared_scope
    try:
        if bool(ctx.fastmcp.settings.stateless_http):
            return declared_scope
    except (AttributeError, RuntimeError, TypeError, ValueError):
        # Older or synthetic contexts without transport settings are treated as
        # stateful only when they still expose a stable weak-referenceable session.
        pass
    try:
        session = ctx.session
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return declared_scope
    if session is None:
        return declared_scope
    try:
        with _TRANSPORT_SESSION_SCOPE_LOCK:
            label = _TRANSPORT_SESSION_SCOPES.get(session)
            if label is None:
                label = f"server-session-{secrets.token_hex(32)}"
                _TRANSPORT_SESSION_SCOPES[session] = label
    except TypeError:
        # Unknown or non-weak-referenceable SDK sessions remain fail-closed in
        # the explicit shared scope rather than gaining an unstable identity.
        return declared_scope
    return _validate_runtime_transport_client_scope(
        {"kind": "server_session", "label": label}
    )


# The central gate and the roundtrip grip both resolve through these module
# functions at request time. Install the extension before the HTTP runtime is
# configured so one stateful session owns its single-use challenge and receipt.
_TRANSPORT_ROUNDTRIP.validate_client_scope = _validate_runtime_transport_client_scope
grabowski_operator_core.base._transport_roundtrip_client_scope = (
    _runtime_transport_client_scope
)


mcp = grabowski_operator_core.mcp
READ_ONLY = grabowski_operator_core.READ_ONLY


@mcp.tool(name="grabowski_current_work", annotations=READ_ONLY)
async def grabowski_current_work(
    repositories: Annotated[
        list[str],
        Field(
            description=(
                "Absolute local repository paths; short aliases such as "
                "'grabowski' are rejected."
            )
        ),
    ],
    view: str = "current",
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, object]:
    """Project work for absolute local repository paths without blocking the MCP event loop."""
    return await asyncio.to_thread(
        grabowski_current_work_surface.grabowski_current_work,
        repositories,
        view=view,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool(name="grabowski_operator_optimization_report", annotations=READ_ONLY)
async def grabowski_operator_optimization_report(
    repositories: list[str],
    window: str = "7d",
    view: str = "minimal",
    top_limit: int = 10,
    friction_limit: int = 100,
    outcome_limit: int = 200,
    current_work_limit: int = 50,
) -> dict[str, object]:
    """Audit bounded operator friction without blocking the MCP event loop."""
    return await asyncio.to_thread(
        grabowski_operator_optimization.build_operator_optimization_report,
        repositories,
        window=window,
        view=view,
        top_limit=top_limit,
        friction_limit=friction_limit,
        outcome_limit=outcome_limit,
        current_work_limit=current_work_limit,
    )


@mcp.tool(name="grabowski_checkout_binding_reconciliation", annotations=READ_ONLY)
async def grabowski_checkout_binding_reconciliation(
    repository_filters: list[str] | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, object]:
    """Compare checkout bindings without blocking the MCP event loop."""
    return await asyncio.to_thread(
        grabowski_checkout_binding_reconciler.reconcile_checkout_bindings,
        repository_filters=repository_filters,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool(name="grabowski_merge_delivery_record", annotations=grabowski_operator_core.MUTATING)
def grabowski_merge_delivery_record(
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    diff_sha256: str,
    artifact_id: str,
    artifact_sha256: str,
    artifact_receipt_sha256: str,
    delivery_channel: str,
    delivery_reference: str,
) -> dict[str, object]:
    """Optionally record one durable, exact user-visible diff artifact handoff."""
    grabowski_operator_core._require_operator_mutation(
        "artifact_transfer",
        path=str(grabowski_merge_delivery_surface.delivery.MERGE_DELIVERY_ROOT),
        host="heim-pc",
    )
    return grabowski_merge_delivery_surface.grabowski_merge_delivery_record(
        repository,
        pull_request,
        base_sha,
        head_sha,
        diff_sha256,
        artifact_id,
        artifact_sha256,
        artifact_receipt_sha256,
        delivery_channel,
        delivery_reference,
    )


def main() -> None:
    grabowski_operator_core.main()


if __name__ == "__main__":
    main()
