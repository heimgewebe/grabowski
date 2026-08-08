from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_system_map as system_map  # noqa: E402


SOURCE_REGISTRY = {
    "bureau": {"authority": "Bureau", "required_binding": ["task"]},
    "repobrief": {
        "display_name": "RepoGround",
        "authority": "RepoGround",
        "required_binding": ["repo", "stem"],
    },
    "chronik": {"authority": "Chronik", "required_binding": ["operation"]},
    "systemkatalog": {"authority": "Systemkatalog", "required_binding": ["system"]},
    "github_ci": {"authority": "GitHub", "required_binding": ["repo", "pr"]},
}


def _component_map(**overrides: object) -> dict[str, object]:
    arguments = {
        "runtime_healthy": True,
        "client_snapshot": {
            "observable": True,
            "matched": True,
            "fresh": True,
            "platform_connector_snapshot_observable": True,
        },
        "coding_agent_catalog": {
            "ready": True,
            "model_count": 23,
            "harness_count": 12,
            "route_count": 34,
        },
        "tasks": {
            "available": True,
            "projection_counts": {"attention": 0},
            "unknown_state_count": 0,
        },
        "leases": {
            "available": True,
            "active_count": 2,
            "count_complete": True,
            "may_be_truncated": False,
        },
        "obligations": {
            "available": True,
            "attention_count": 0,
            "integrity_error_count": 0,
            "scan_truncated": False,
        },
        "source_registry": SOURCE_REGISTRY,
    }
    arguments.update(overrides)
    return system_map.build_component_map(**arguments)


def test_component_map_is_projection_only_and_target_bound() -> None:
    result = _component_map()

    assert result["projection_only"] is True
    assert result["overall_signal"] == "target_required"
    components = {item["id"]: item for item in result["components"]}
    assert components["grabowski"]["signal"] == "green"
    assert components["bureau"]["signal"] == "target_required"
    assert components["bureau"]["observed"] is False
    assert components["repobrief"]["id"] == "repobrief"
    assert components["repobrief"]["name"] == "RepoGround"
    assert components["repobrief"]["authority"] == "RepoGround"
    assert result["counts"] == {
        "red": 0,
        "unknown": 0,
        "amber": 0,
        "target_required": 5,
        "green": 6,
    }


def test_server_loopback_snapshot_does_not_make_platform_connector_green() -> None:
    result = _component_map(
        client_snapshot={
            "observable": True,
            "matched": True,
            "fresh": True,
            "platform_connector_snapshot_observable": False,
            "server_loopback_observable": True,
        }
    )

    components = {item["id"]: item for item in result["components"]}
    connector = components["connector"]
    assert connector["signal"] == "unknown"
    assert connector["observed"] is False
    assert connector["evidence"]["platform_connector_snapshot_observable"] is False
    assert connector["evidence"]["server_loopback_observable"] is True
    assert result["overall_signal"] == "unknown"


def test_stale_platform_snapshot_stays_unknown() -> None:
    result = _component_map(
        client_snapshot={
            "observable": True,
            "matched": True,
            "fresh": False,
            "platform_connector_snapshot_observable": True,
            "server_loopback_observable": True,
        }
    )

    components = {item["id"]: item for item in result["components"]}
    connector = components["connector"]
    assert connector["signal"] == "unknown"
    assert connector["observed"] is False
    assert connector["evidence"]["fresh"] is False
    assert connector["evidence"]["platform_connector_snapshot_observable"] is True


def test_attention_is_amber_without_becoming_health_failure() -> None:
    result = _component_map(
        tasks={
            "available": True,
            "projection_counts": {"attention": 7},
            "unknown_state_count": 0,
        },
        obligations={
            "available": True,
            "attention_count": 3,
            "integrity_error_count": 0,
            "scan_truncated": False,
        },
    )

    components = {item["id"]: item for item in result["components"]}
    assert components["task_store"]["signal"] == "amber"
    assert components["operator_obligations"]["signal"] == "amber"
    assert result["overall_signal"] == "amber"


def test_unavailable_source_dominates_attention() -> None:
    result = _component_map(
        client_snapshot={"observable": False, "matched": None, "fresh": None},
        tasks={
            "available": True,
            "projection_counts": {"attention": 2},
            "unknown_state_count": 0,
        },
    )

    components = {item["id"]: item for item in result["components"]}
    assert components["connector"]["signal"] == "unknown"
    assert result["overall_signal"] == "unknown"


def test_integrity_failure_is_red() -> None:
    result = _component_map(
        obligations={
            "available": True,
            "attention_count": 4,
            "integrity_error_count": 1,
            "scan_truncated": False,
        },
    )

    components = {item["id"]: item for item in result["components"]}
    assert components["operator_obligations"]["signal"] == "red"
    assert result["overall_signal"] == "red"
