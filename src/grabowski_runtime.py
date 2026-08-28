from __future__ import annotations

import asyncio
from typing import Annotated

from pydantic import Field

import grabowski_operator_core
import grabowski_mcp
import grabowski_checkouts
import grabowski_checkout_binding_reconciler
import grabowski_current_work as grabowski_current_work_model
import grabowski_current_work_surface
import grabowski_work_acquire  # noqa: F401
import grabowski_operator_optimization
import grabowski_runtime_extensions
import grabowski_audit_query
import grabowski_reposkop_effectiveness  # noqa: F401
import grabowski_read_surface
import grabowski_self_deploy
import grabowski_fleet
import grabowski_juno
import grabowski_juno_storage
import grabowski_juno_bluetooth
import grabowski_artifacts
import grabowski_merge_delivery_surface
import grabowski_agent_workspace
import grabowski_agent_workspace_observer
import grabowski_operations
import grabowski_privileged
import grabowski_recovery
import grabowski_provenance_recovery  # noqa: F401
import grabowski_blockade_runtime
import grabowski_friction
import grabowski_agent_bootstrap
import grabowski_recall
import grabowski_context_fabric
import grabowski_systemkatalog  # noqa: F401
import grabowski_resources
import grabowski_bureau_intake
import grabowski_bureau_pickup
import grabowski_tasks
import grabowski_agent_competition
import grabowski_coding_agent_router
import grabowski_workers
import grabowski_reposkop_context  # noqa: F401


mcp = grabowski_operator_core.mcp
READ_ONLY = grabowski_operator_core.READ_ONLY


def _stage_unpublished_tools() -> None:
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None:
        raise RuntimeError("FastMCP tool manager is unavailable for publication staging")
    for tool_name in sorted(grabowski_mcp.STAGED_UNPUBLISHED_TOOL_NAMES):
        if manager.get_tool(tool_name) is None:
            raise RuntimeError(
                f"staged unpublished tool was not registered before runtime assembly: {tool_name}"
            )
        manager.remove_tool(tool_name)


_stage_unpublished_tools()


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
    limit: Annotated[
        int,
        Field(
            ge=1,
            le=grabowski_current_work_model.PAGE_LIMIT_MAX,
            description="Server-side page size for the bounded current-work projection.",
        ),
    ] = 20,
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
    top_limit: Annotated[
        int,
        Field(
            ge=1,
            le=grabowski_operator_optimization.MAX_TOP_LIMIT,
            description="Maximum number of ranked findings returned by the bounded report.",
        ),
    ] = 10,
    friction_limit: Annotated[
        int,
        Field(
            ge=1,
            le=grabowski_operator_optimization.MAX_FRICTION_LIMIT,
            description="Maximum number of friction records inspected by the report.",
        ),
    ] = 100,
    outcome_limit: Annotated[
        int,
        Field(
            ge=1,
            le=grabowski_operator_optimization.MAX_OUTCOME_LIMIT,
            description="Maximum number of execution outcomes inspected by the report.",
        ),
    ] = 200,
    current_work_limit: Annotated[
        int,
        Field(
            ge=1,
            le=grabowski_operator_optimization.MAX_CURRENT_WORK_LIMIT,
            description="Server-side page size for current-work evidence used by the report.",
        ),
    ] = 50,
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
