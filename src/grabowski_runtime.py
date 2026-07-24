from __future__ import annotations

import grabowski_operator_core
import grabowski_checkouts
import grabowski_checkout_binding_reconciler
import grabowski_current_work_surface
import grabowski_runtime_extensions
import grabowski_audit_query
import grabowski_read_surface
import grabowski_self_deploy
import grabowski_fleet
import grabowski_juno
import grabowski_juno_storage
import grabowski_artifacts
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


def main() -> None:
    grabowski_operator_core.main()


if __name__ == "__main__":
    main()
