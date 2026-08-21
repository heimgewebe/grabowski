from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
EXECUTION_PLAN_KIND = "ExecutionPlan.v1"
REVISION_REQUEST_KIND = "RevisionRequest.v1"
ROUTING_CONTRACT_VERSION = "agent-execution-fabric-routing-v1"
TOPOLOGIES = frozenset({"direct", "writer_verify_reduce", "fork_compare"})
VERIFICATION_POLICIES = frozenset(
    {"deterministic", "independent_review", "competition"}
)
NODE_KINDS = frozenset(
    {
        "controller",
        "scoped_writer",
        "verifier",
        "reducer",
        "alternative",
        "compare",
        "integration",
        "observer",
    }
)
EXECUTORS = frozenset({"controller", "scoped_writer"})
EFFECT_PROFILES = frozenset({"candidate", "delivery"})
UNKNOWN_EFFECT_POLICIES = frozenset({"reconcile"})
INDETERMINATE_POLICIES = frozenset({"block", "revise"})
MUTATING_NODE_KINDS = frozenset({"controller", "scoped_writer"})
EDGE_ARTIFACT_CONTRACTS = frozenset(
    {
        "CandidateManifest.v1",
        "VerificationReceipt.v1",
        "VerificationSummary.v1",
        "RevisionRequest.v1",
        "CandidateAdoptionReceipt.v1",
    }
)
MAX_TEXT = 512
MAX_NODES = 32
MAX_EDGES = 96
MAX_WRITE_SCOPE = 128
MAX_REQUESTED_CHANGES = 64
MAX_ROUTE_DECISION_BYTES = 131072
MAX_EXECUTION_PLAN_BYTES = 262144
MAX_REVISION_REQUEST_BYTES = 262144
MAX_FINDING_BYTES = 16384
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")


class ExecutionPlanError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionPlanError("value is not canonical JSON") from exc


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _required_text(value: Any, field: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ExecutionPlanError(f"{field} must be text")
    normalized = value.strip()
    if not normalized or normalized != value or len(normalized) > maximum:
        raise ExecutionPlanError(f"{field} must be bounded trimmed text")
    if any(character in normalized for character in "\r\n\x00"):
        raise ExecutionPlanError(f"{field} contains an invalid control character")
    return normalized


def _identifier(value: Any, field: str) -> str:
    result = _required_text(value, field, maximum=128)
    if IDENTITY_RE.fullmatch(result) is None:
        raise ExecutionPlanError(f"{field} contains unsupported characters")
    return result


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ExecutionPlanError(f"{field} must be a lowercase SHA-256")
    return value


def _bounded_int(
    value: Any, field: str, *, minimum: int = 0, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionPlanError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ExecutionPlanError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _source_binding(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"kind", "id"}:
        raise ExecutionPlanError("source_binding shape is invalid")
    return {
        "kind": _identifier(value.get("kind"), "source_binding.kind"),
        "id": _required_text(value.get("id"), "source_binding.id"),
    }


def route_binding_from_decision(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionPlanError("route decision must be an object")
    route = dict(value)
    if len(canonical_json_bytes(route)) > MAX_ROUTE_DECISION_BYTES:
        raise ExecutionPlanError("route decision exceeds the bounded contract size")
    recommendation = _sha256(
        route.get("recommendation_sha256"), "route.recommendation_sha256"
    )
    material = {key: item for key, item in route.items() if key != "recommendation_sha256"}
    if sha256_json(material) != recommendation:
        raise ExecutionPlanError("route recommendation digest mismatch")
    if route.get("routing_contract_version") != ROUTING_CONTRACT_VERSION:
        raise ExecutionPlanError("route contract version is unsupported")
    executor = _required_text(route.get("executor"), "route.executor", maximum=32)
    if executor not in EXECUTORS:
        raise ExecutionPlanError("route executor is unsupported")
    effect_profile = _required_text(
        route.get("effect_profile"), "route.effect_profile", maximum=32
    )
    if effect_profile not in EFFECT_PROFILES:
        raise ExecutionPlanError("route effect profile is unsupported")
    if effect_profile == "delivery" and executor != "scoped_writer":
        raise ExecutionPlanError(
            "delivery effect profile requires a scoped_writer route"
        )
    verification_policy = _required_text(
        route.get("verification_policy"), "route.verification_policy", maximum=32
    )
    if verification_policy not in VERIFICATION_POLICIES:
        raise ExecutionPlanError("route verification policy is unsupported")
    if effect_profile == "delivery" and verification_policy != "independent_review":
        raise ExecutionPlanError(
            "delivery effect profile requires verification_policy=independent_review"
        )
    return {
        "routing_contract_version": ROUTING_CONTRACT_VERSION,
        "recommendation_sha256": recommendation,
        "executor": executor,
        "writer_route": _identifier(route.get("writer_route"), "route.writer_route"),
        "effect_profile": effect_profile,
        "verification_policy": verification_policy,
        "task_class": _identifier(route.get("task_class"), "route.task_class"),
        "decision": route,
    }


def _route_binding(value: Any) -> dict[str, Any]:
    expected = {
        "routing_contract_version",
        "recommendation_sha256",
        "executor",
        "writer_route",
        "effect_profile",
        "verification_policy",
        "task_class",
        "decision",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("route_binding shape is invalid")
    decision = value.get("decision")
    if not isinstance(decision, Mapping):
        raise ExecutionPlanError("route_binding decision is missing")
    rebuilt = route_binding_from_decision(decision)
    if dict(value) != rebuilt:
        raise ExecutionPlanError(
            "route_binding projection differs from the bound route decision"
        )
    return rebuilt


def _scope_path(value: Any, field: str) -> str:
    path = _required_text(value, field, maximum=1024)
    if path.startswith("/") or path.startswith("~"):
        raise ExecutionPlanError(f"{field} must be repository-relative")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or parts[0] == ".git":
        raise ExecutionPlanError(f"{field} is not a safe repository-relative path")
    return path


def _write_scope(value: Any, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_WRITE_SCOPE:
        raise ExecutionPlanError(f"{field} must be a bounded list")
    result = sorted({_scope_path(item, field) for item in value})
    if len(result) != len(value):
        raise ExecutionPlanError(f"{field} contains duplicate paths")
    return result


def _node(value: Any, *, plan_scope: set[str]) -> dict[str, Any]:
    expected = {"node_id", "kind", "critical", "mutates", "write_scope"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("execution node shape is invalid")
    node_id = _identifier(value.get("node_id"), "node.node_id")
    kind = _required_text(value.get("kind"), "node.kind", maximum=32)
    if kind not in NODE_KINDS:
        raise ExecutionPlanError(f"unsupported execution node kind: {kind}")
    if not isinstance(value.get("critical"), bool) or not isinstance(
        value.get("mutates"), bool
    ):
        raise ExecutionPlanError("node critical and mutates must be booleans")
    scope = _write_scope(value.get("write_scope"), f"node[{node_id}].write_scope")
    if not set(scope).issubset(plan_scope):
        raise ExecutionPlanError("node write scope exceeds plan write scope")
    if value.get("mutates") is True and kind not in MUTATING_NODE_KINDS:
        raise ExecutionPlanError(
            "only controller or scoped_writer execution nodes may mutate"
        )
    if value.get("mutates") is True and not scope:
        raise ExecutionPlanError("mutating execution node requires explicit write scope")
    if value.get("mutates") is False and scope:
        raise ExecutionPlanError("read-only execution node may not claim write scope")
    return {
        "node_id": node_id,
        "kind": kind,
        "critical": bool(value["critical"]),
        "mutates": bool(value["mutates"]),
        "write_scope": scope,
    }


def _edge(value: Any, *, node_ids: set[str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"from", "to", "artifact"}:
        raise ExecutionPlanError("typed edge shape is invalid")
    source = _identifier(value.get("from"), "edge.from")
    target = _identifier(value.get("to"), "edge.to")
    artifact = _identifier(value.get("artifact"), "edge.artifact")
    if artifact not in EDGE_ARTIFACT_CONTRACTS:
        raise ExecutionPlanError(
            f"unsupported typed edge artifact contract: {artifact}"
        )
    if source == target:
        raise ExecutionPlanError("typed edge may not target its source node")
    if source not in node_ids or target not in node_ids:
        raise ExecutionPlanError("typed edge references an unknown node")
    return {"from": source, "to": target, "artifact": artifact}


def _reject_cycles(nodes: Sequence[dict[str, Any]], edges: Sequence[dict[str, str]]) -> None:
    incoming = {node["node_id"]: 0 for node in nodes}
    outgoing: dict[str, list[str]] = {node_id: [] for node_id in incoming}
    for edge in edges:
        outgoing[edge["from"]].append(edge["to"])
        incoming[edge["to"]] += 1
    ready = sorted(node_id for node_id, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        node_id = ready.pop(0)
        visited += 1
        for target in sorted(outgoing[node_id]):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
                ready.sort()
    if visited != len(nodes):
        raise ExecutionPlanError("execution plan graph contains a cycle")


def _validate_topology(
    topology: str,
    nodes: Sequence[dict[str, Any]],
    verification_policy: str,
) -> None:
    kinds = [node["kind"] for node in nodes]
    mutating = [node for node in nodes if node["mutates"]]
    if topology == "direct":
        if any(kind in {"alternative", "compare"} for kind in kinds):
            raise ExecutionPlanError("direct topology may not contain fork/compare nodes")
        if len(mutating) > 1:
            raise ExecutionPlanError("direct topology allows at most one mutating node")
    elif topology == "writer_verify_reduce":
        if not any(kind in {"controller", "scoped_writer"} for kind in kinds):
            raise ExecutionPlanError("writer_verify_reduce requires a writer node")
        if "verifier" not in kinds or "reducer" not in kinds:
            raise ExecutionPlanError(
                "writer_verify_reduce requires verifier and reducer nodes"
            )
        if len(mutating) != 1:
            raise ExecutionPlanError(
                "writer_verify_reduce requires exactly one mutating writer"
            )
        if any(kind in {"alternative", "compare"} for kind in kinds):
            raise ExecutionPlanError(
                "writer_verify_reduce may not contain fork/compare nodes"
            )
    elif topology == "fork_compare":
        if verification_policy != "competition":
            raise ExecutionPlanError(
                "fork_compare requires verification_policy=competition"
            )
        if kinds.count("alternative") < 2 or "compare" not in kinds:
            raise ExecutionPlanError(
                "fork_compare requires at least two alternatives and one compare node"
            )
        if any(node["mutates"] for node in nodes):
            raise ExecutionPlanError(
                "P4 fork_compare is read-only; competing writers require separate lanes"
            )
    else:
        raise ExecutionPlanError("execution plan topology is unsupported")
    if verification_policy == "competition" and topology != "fork_compare":
        raise ExecutionPlanError(
            "verification_policy=competition requires an explicit fork_compare topology"
        )


def _failure_policy(value: Any) -> dict[str, str]:
    expected = {"on_indeterminate", "on_unknown_effect", "revision"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("failure_policy shape is invalid")
    indeterminate = _required_text(
        value.get("on_indeterminate"), "failure_policy.on_indeterminate", maximum=16
    )
    unknown = _required_text(
        value.get("on_unknown_effect"), "failure_policy.on_unknown_effect", maximum=16
    )
    revision = _required_text(value.get("revision"), "failure_policy.revision", maximum=16)
    if indeterminate not in INDETERMINATE_POLICIES:
        raise ExecutionPlanError("unsupported indeterminate failure policy")
    if unknown not in UNKNOWN_EFFECT_POLICIES:
        raise ExecutionPlanError("unknown effects must reconcile")
    if revision != "bounded":
        raise ExecutionPlanError("P4 revision policy must be bounded")
    return {
        "on_indeterminate": indeterminate,
        "on_unknown_effect": unknown,
        "revision": revision,
    }


def _budgets(value: Any) -> dict[str, int]:
    expected = {"max_revisions", "max_duration_seconds", "max_tool_calls"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("budgets shape is invalid")
    return {
        "max_revisions": _bounded_int(
            value.get("max_revisions"), "budgets.max_revisions", maximum=1
        ),
        "max_duration_seconds": _bounded_int(
            value.get("max_duration_seconds"),
            "budgets.max_duration_seconds",
            minimum=1,
            maximum=86400,
        ),
        "max_tool_calls": _bounded_int(
            value.get("max_tool_calls"),
            "budgets.max_tool_calls",
            minimum=1,
            maximum=1000,
        ),
    }


def _completion_policy(
    value: Any,
    *,
    nodes: Sequence[dict[str, Any]],
    verification_policy: str,
) -> dict[str, Any]:
    expected = {"required_nodes", "require_all_critical", "verifier_quorum"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("completion_policy shape is invalid")
    required_raw = value.get("required_nodes")
    if not isinstance(required_raw, (list, tuple)):
        raise ExecutionPlanError("completion_policy.required_nodes must be a list")
    required = sorted(
        {_identifier(item, "completion_policy.required_nodes") for item in required_raw}
    )
    if len(required) != len(required_raw):
        raise ExecutionPlanError("completion policy contains duplicate required nodes")
    node_ids = {node["node_id"] for node in nodes}
    if not set(required).issubset(node_ids):
        raise ExecutionPlanError("completion policy references an unknown node")
    require_all_critical = value.get("require_all_critical")
    if require_all_critical is not True:
        raise ExecutionPlanError(
            "P4 completion policy must require every critical node"
        )
    critical = {node["node_id"] for node in nodes if node["critical"]}
    if not critical.issubset(set(required)):
        raise ExecutionPlanError("completion policy skips a critical node")
    verifier_count = sum(1 for node in nodes if node["kind"] == "verifier")
    quorum = _bounded_int(
        value.get("verifier_quorum"),
        "completion_policy.verifier_quorum",
        maximum=verifier_count,
    )
    if verification_policy == "independent_review" and quorum < 1:
        raise ExecutionPlanError("independent review requires verifier quorum")
    return {
        "required_nodes": required,
        "require_all_critical": require_all_critical,
        "verifier_quorum": quorum,
    }


def build_execution_plan(
    *,
    source_binding: Mapping[str, Any],
    route_decision: Mapping[str, Any],
    topology: str,
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    write_scope: Sequence[str],
    verification_policy: str,
    failure_policy: Mapping[str, Any],
    budgets: Mapping[str, Any],
    completion_policy: Mapping[str, Any],
) -> dict[str, Any]:
    source = _source_binding(source_binding)
    route = route_binding_from_decision(route_decision)
    return _build_execution_plan_from_binding(
        source_binding=source,
        route_binding=route,
        topology=topology,
        nodes=nodes,
        edges=edges,
        write_scope=write_scope,
        verification_policy=verification_policy,
        failure_policy=failure_policy,
        budgets=budgets,
        completion_policy=completion_policy,
    )


def _build_execution_plan_from_binding(
    *,
    source_binding: Mapping[str, Any],
    route_binding: Mapping[str, Any],
    topology: Any,
    nodes: Any,
    edges: Any,
    write_scope: Any,
    verification_policy: Any,
    failure_policy: Any,
    budgets: Any,
    completion_policy: Any,
) -> dict[str, Any]:
    source = _source_binding(source_binding)
    route = _route_binding(route_binding)
    topology_value = _required_text(topology, "topology", maximum=32)
    if topology_value not in TOPOLOGIES:
        raise ExecutionPlanError("execution plan topology is unsupported")
    policy = _required_text(
        verification_policy, "verification_policy", maximum=32
    )
    if policy not in VERIFICATION_POLICIES:
        raise ExecutionPlanError("execution plan verification policy is unsupported")
    if route["verification_policy"] != policy:
        raise ExecutionPlanError("execution plan verification policy drifted from route")
    scope = _write_scope(write_scope, "write_scope")
    if not isinstance(nodes, (list, tuple)) or not 1 <= len(nodes) <= MAX_NODES:
        raise ExecutionPlanError("nodes must be a bounded non-empty list")
    normalized_nodes = [_node(item, plan_scope=set(scope)) for item in nodes]
    normalized_nodes.sort(key=lambda item: item["node_id"])
    node_ids = [item["node_id"] for item in normalized_nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ExecutionPlanError("execution plan node ids must be unique")
    if not isinstance(edges, (list, tuple)) or len(edges) > MAX_EDGES:
        raise ExecutionPlanError("edges must be a bounded list")
    normalized_edges = [_edge(item, node_ids=set(node_ids)) for item in edges]
    normalized_edges.sort(key=lambda item: (item["from"], item["to"], item["artifact"]))
    edge_ids = [tuple(item.values()) for item in normalized_edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ExecutionPlanError("execution plan contains duplicate typed edges")
    if len(normalized_nodes) > 1:
        referenced = {
            endpoint
            for edge in normalized_edges
            for endpoint in (edge["from"], edge["to"])
        }
        if referenced != set(node_ids):
            raise ExecutionPlanError("execution plan contains a disconnected node")
    _reject_cycles(normalized_nodes, normalized_edges)
    _validate_topology(topology_value, normalized_nodes, policy)
    failure = _failure_policy(failure_policy)
    budget = _budgets(budgets)
    completion = _completion_policy(
        completion_policy, nodes=normalized_nodes, verification_policy=policy
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": EXECUTION_PLAN_KIND,
        "source_binding": source,
        "route_binding": route,
        "topology": topology_value,
        "nodes": normalized_nodes,
        "edges": normalized_edges,
        "write_scope": scope,
        "verification_policy": policy,
        "failure_policy": failure,
        "budgets": budget,
        "completion_policy": completion,
    }
    if len(canonical_json_bytes(body)) > MAX_EXECUTION_PLAN_BYTES:
        raise ExecutionPlanError("ExecutionPlan.v1 exceeds the bounded contract size")
    return {**body, "plan_id": sha256_json(body)}


def validate_execution_plan(value: Any) -> dict[str, Any]:
    expected = {
        "schema_version",
        "kind",
        "plan_id",
        "source_binding",
        "route_binding",
        "topology",
        "nodes",
        "edges",
        "write_scope",
        "verification_policy",
        "failure_policy",
        "budgets",
        "completion_policy",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("ExecutionPlan.v1 shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != EXECUTION_PLAN_KIND:
        raise ExecutionPlanError("ExecutionPlan.v1 contract is unsupported")
    rebuilt = _build_execution_plan_from_binding(
        source_binding=value.get("source_binding"),
        route_binding=value.get("route_binding"),
        topology=value.get("topology"),
        nodes=value.get("nodes"),
        edges=value.get("edges"),
        write_scope=value.get("write_scope"),
        verification_policy=value.get("verification_policy"),
        failure_policy=value.get("failure_policy"),
        budgets=value.get("budgets"),
        completion_policy=value.get("completion_policy"),
    )
    if dict(value) != rebuilt:
        raise ExecutionPlanError("ExecutionPlan.v1 plan_id or canonical material drifted")
    return rebuilt


def _finding(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionPlanError("revision finding must be an object")
    finding = dict(value)
    code = _identifier(finding.get("code"), "revision finding code")
    if len(canonical_json_bytes(finding)) > MAX_FINDING_BYTES:
        raise ExecutionPlanError("revision finding exceeds the bounded contract size")
    finding["code"] = code
    return finding


def build_revision_request(
    *,
    candidate_id: str,
    verification_summary_sha256: str,
    collection_result_sha256: str,
    findings_sha256: str,
    findings: Sequence[Mapping[str, Any]],
    round_number: int,
    next_round: int,
    write_scope: Sequence[str],
    revision_index: int = 1,
    max_revisions: int = 1,
) -> dict[str, Any]:
    candidate = _sha256(candidate_id, "candidate_id")
    summary = _sha256(
        verification_summary_sha256, "verification_summary_sha256"
    )
    collection = _sha256(collection_result_sha256, "collection_result_sha256")
    supplied_findings_sha = _sha256(findings_sha256, "findings_sha256")
    if not isinstance(findings, (list, tuple)) or not 1 <= len(findings) <= MAX_REQUESTED_CHANGES:
        raise ExecutionPlanError("RevisionRequest.v1 requires bounded findings")
    normalized_findings = [_finding(item) for item in findings]
    normalized_findings.sort(key=lambda item: canonical_json_bytes(item))
    if sha256_json(normalized_findings) != supplied_findings_sha:
        raise ExecutionPlanError("RevisionRequest.v1 findings digest mismatch")
    round_value = _bounded_int(round_number, "round", minimum=1, maximum=2)
    next_value = _bounded_int(next_round, "next_round", minimum=1, maximum=2)
    if round_value != 1 or next_value != 2:
        raise ExecutionPlanError("P4 RevisionRequest.v1 is limited to round one -> two")
    index = _bounded_int(revision_index, "revision_index", minimum=1, maximum=1)
    maximum = _bounded_int(max_revisions, "max_revisions", minimum=1, maximum=1)
    if index > maximum:
        raise ExecutionPlanError("revision index exceeds the bounded revision budget")
    scope = _write_scope(write_scope, "revision write_scope")
    if not scope:
        raise ExecutionPlanError("RevisionRequest.v1 requires explicit write scope")
    changes = [
        {
            "code": finding["code"],
            "finding_sha256": sha256_json(finding),
            "finding": finding,
        }
        for finding in normalized_findings
    ]
    body = {
        "schema_version": SCHEMA_VERSION,
        "kind": REVISION_REQUEST_KIND,
        "candidate_id": candidate,
        "verification_summary_sha256": summary,
        "collection_result_sha256": collection,
        "findings_sha256": supplied_findings_sha,
        "verification_outcome": "NEEDS_CHANGE",
        "round": round_value,
        "next_round": next_value,
        "write_scope": scope,
        "requested_changes": changes,
        "budget": {
            "revision_index": index,
            "max_revisions": maximum,
        },
    }
    if len(canonical_json_bytes(body)) > MAX_REVISION_REQUEST_BYTES:
        raise ExecutionPlanError("RevisionRequest.v1 exceeds the bounded contract size")
    return {**body, "revision_request_id": sha256_json(body)}


def validate_revision_request(value: Any) -> dict[str, Any]:
    expected = {
        "schema_version",
        "kind",
        "revision_request_id",
        "candidate_id",
        "verification_summary_sha256",
        "collection_result_sha256",
        "findings_sha256",
        "verification_outcome",
        "round",
        "next_round",
        "write_scope",
        "requested_changes",
        "budget",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ExecutionPlanError("RevisionRequest.v1 shape is not canonical")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("kind") != REVISION_REQUEST_KIND:
        raise ExecutionPlanError("RevisionRequest.v1 contract is unsupported")
    if value.get("verification_outcome") != "NEEDS_CHANGE":
        raise ExecutionPlanError("RevisionRequest.v1 requires NEEDS_CHANGE")
    changes = value.get("requested_changes")
    if not isinstance(changes, list) or not changes:
        raise ExecutionPlanError("RevisionRequest.v1 requested_changes are missing")
    findings: list[dict[str, Any]] = []
    for change in changes:
        if not isinstance(change, Mapping) or set(change) != {
            "code",
            "finding_sha256",
            "finding",
        }:
            raise ExecutionPlanError("RevisionRequest.v1 change shape is invalid")
        finding = _finding(change.get("finding"))
        code = _identifier(change.get("code"), "requested_change.code")
        if code != finding["code"]:
            raise ExecutionPlanError("RevisionRequest.v1 change code drifted")
        if _sha256(
            change.get("finding_sha256"), "requested_change.finding_sha256"
        ) != sha256_json(finding):
            raise ExecutionPlanError("RevisionRequest.v1 finding digest drifted")
        findings.append(finding)
    budget = value.get("budget")
    if not isinstance(budget, Mapping) or set(budget) != {
        "revision_index",
        "max_revisions",
    }:
        raise ExecutionPlanError("RevisionRequest.v1 budget shape is invalid")
    rebuilt = build_revision_request(
        candidate_id=value.get("candidate_id"),
        verification_summary_sha256=value.get("verification_summary_sha256"),
        collection_result_sha256=value.get("collection_result_sha256"),
        findings_sha256=value.get("findings_sha256"),
        findings=findings,
        round_number=value.get("round"),
        next_round=value.get("next_round"),
        write_scope=value.get("write_scope"),
        revision_index=budget.get("revision_index"),
        max_revisions=budget.get("max_revisions"),
    )
    if dict(value) != rebuilt:
        raise ExecutionPlanError(
            "RevisionRequest.v1 identity or canonical material drifted"
        )
    return rebuilt
