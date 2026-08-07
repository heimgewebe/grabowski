from __future__ import annotations

from typing import Any


SIGNAL_RANK = {
    "red": 4,
    "unknown": 3,
    "amber": 2,
    "target_required": 1,
    "green": 0,
}


def overview_signal(
    *,
    observable: bool,
    healthy: bool | None = None,
    attention: bool = False,
) -> str:
    if not observable:
        return "unknown"
    if healthy is False:
        return "red"
    if attention:
        return "amber"
    return "green"


def build_component_map(
    *,
    runtime_healthy: bool,
    client_snapshot: dict[str, Any],
    coding_agent_catalog: dict[str, Any],
    tasks: dict[str, Any],
    leases: dict[str, Any],
    obligations: dict[str, Any],
    source_registry: dict[str, Any],
) -> dict[str, Any]:
    task_attention = int(
        (tasks.get("projection_counts") or {}).get("attention", 0) or 0
    )
    obligation_attention = int(obligations.get("attention_count") or 0)
    active_leases = int(leases.get("active_count") or 0)
    connector_observable = bool(
        client_snapshot.get("platform_connector_snapshot_observable")
    )
    components = [
        {
            "id": "grabowski",
            "role": "authoritative local operator runtime",
            "authority": "deployment manifest and audit log",
            "signal": overview_signal(observable=True, healthy=runtime_healthy),
            "observed": True,
            "evidence": {"healthy": runtime_healthy},
        },
        {
            "id": "connector",
            "role": "ChatGPT-to-runtime transport binding",
            "authority": "client snapshot handshake",
            "signal": overview_signal(
                observable=connector_observable,
                healthy=(
                    bool(client_snapshot.get("matched"))
                    if connector_observable
                    else None
                ),
            ),
            "observed": connector_observable,
            "evidence": {
                "fresh": client_snapshot.get("fresh"),
                "matched": client_snapshot.get("matched"),
                "platform_connector_snapshot_observable": connector_observable,
                "server_loopback_observable": client_snapshot.get(
                    "server_loopback_observable"
                ),
            },
        },
        {
            "id": "task_store",
            "role": "durable execution ledger and projection",
            "authority": "Grabowski task database",
            "signal": overview_signal(
                observable=bool(tasks.get("available")),
                healthy=(
                    tasks.get("unknown_state_count") == 0
                    if tasks.get("available")
                    else None
                ),
                attention=task_attention > 0,
            ),
            "observed": bool(tasks.get("available")),
            "evidence": {
                "projection_counts": tasks.get("projection_counts", {}),
                "unknown_state_count": tasks.get("unknown_state_count"),
            },
        },
        {
            "id": "resource_leases",
            "role": "exclusive ownership and non-conflict guard",
            "authority": "Grabowski resource lease database",
            "signal": overview_signal(
                observable=bool(leases.get("available"))
                and not bool(leases.get("may_be_truncated")),
                healthy=True,
            ),
            "observed": bool(leases.get("available")),
            "evidence": {
                "active_count": active_leases,
                "count_complete": leases.get("count_complete"),
            },
        },
        {
            "id": "operator_obligations",
            "role": "operator follow-up and closure obligations",
            "authority": "operator obligation store",
            "signal": overview_signal(
                observable=bool(obligations.get("available"))
                and not bool(obligations.get("scan_truncated")),
                healthy=int(obligations.get("integrity_error_count") or 0) == 0,
                attention=obligation_attention > 0,
            ),
            "observed": bool(obligations.get("available")),
            "evidence": {
                "attention_count": obligation_attention,
                "integrity_error_count": obligations.get("integrity_error_count"),
            },
        },
        {
            "id": "coding_agent_router",
            "role": "advisory review and contrast routing",
            "authority": "deployment coding-agent catalog",
            "signal": overview_signal(
                observable=True,
                healthy=bool(coding_agent_catalog.get("ready")),
            ),
            "observed": True,
            "evidence": {
                "model_count": coding_agent_catalog.get("model_count"),
                "harness_count": coding_agent_catalog.get("harness_count"),
                "route_count": coding_agent_catalog.get("route_count"),
            },
        },
    ]
    for component_id, role in (
        ("bureau", "canonical initiative and task lifecycle"),
        ("repobrief", "commit-bound repository context"),
        ("chronik", "receipt-bound operation history"),
        ("systemkatalog", "stable ecosystem semantics"),
        ("github_ci", "target-bound pull request and CI truth"),
    ):
        source = source_registry[component_id]
        components.append(
            {
                "id": component_id,
                "name": source.get("display_name", component_id),
                "role": role,
                "authority": source["authority"],
                "signal": "target_required",
                "observed": False,
                "required_binding": source.get("required_binding", []),
                "evidence": {},
            }
        )

    overall = max(
        (item["signal"] for item in components),
        key=lambda signal: SIGNAL_RANK[signal],
    )
    return {
        "schema_version": 1,
        "projection_only": True,
        "overall_signal": overall,
        "signal_semantics": {
            "green": "observed and healthy",
            "amber": "observed and actionable attention exists",
            "red": "observed integrity or health failure",
            "unknown": "required source is unavailable or incomplete",
            "target_required": (
                "global status cannot establish this component without an exact "
                "target binding"
            ),
        },
        "components": components,
        "counts": {
            signal: sum(item["signal"] == signal for item in components)
            for signal in SIGNAL_RANK
        },
        "does_not_establish": [
            "a second lifecycle truth",
            (
                "target-specific Bureau, GitHub, RepoGround, Chronik or "
                "Systemkatalog health"
            ),
            "permission to mutate",
        ],
    }
