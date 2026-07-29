from __future__ import annotations

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


@mcp.tool(name="grabowski_current_work", annotations=READ_ONLY)
def grabowski_current_work(
    repositories: list[str],
    view: str = "current",
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, object]:
    """Project bounded current operator work without creating a second lifecycle truth."""
    return grabowski_current_work_surface.grabowski_current_work(
        repositories,
        view=view,
        limit=limit,
        cursor=cursor,
    )


@mcp.tool(name="grabowski_operator_optimization_report", annotations=READ_ONLY)
def grabowski_operator_optimization_report(
    repositories: list[str],
    window: str = "7d",
    view: str = "minimal",
    top_limit: int = 10,
    friction_limit: int = 100,
    outcome_limit: int = 200,
    current_work_limit: int = 50,
) -> dict[str, object]:
    """Audit bounded operator friction and optimization potential on manual request."""
    return grabowski_operator_optimization.build_operator_optimization_report(
        repositories,
        window=window,
        view=view,
        top_limit=top_limit,
        friction_limit=friction_limit,
        outcome_limit=outcome_limit,
        current_work_limit=current_work_limit,
    )


@mcp.tool(name="grabowski_checkout_binding_reconciliation", annotations=READ_ONLY)
def grabowski_checkout_binding_reconciliation(
    repository_filters: list[str] | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, object]:
    """Compare durable checkout bindings with current Git state, strictly read-only."""
    return grabowski_checkout_binding_reconciler.reconcile_checkout_bindings(
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
    """Record one durable, exact user-visible diff delivery before merge."""
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
