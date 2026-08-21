from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_execution_plan as execution_plan


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def route_decision(
    *,
    verification_policy: str = "independent_review",
    effect_profile: str = "candidate",
    executor: str = "scoped_writer",
) -> dict:
    body = {
        "schema_version": 2,
        "routing_contract_version": execution_plan.ROUTING_CONTRACT_VERSION,
        "executor": executor,
        "writer_route": "codex-sol-high",
        "effect_profile": effect_profile,
        "verification_policy": verification_policy,
        "task_class": "complex-patch",
        "risk": {"flags": [], "novelty": "medium", "critical_task_class": False},
        "ignored_for_plan_binding": {"controller": "grabowski-primary"},
    }
    return {**body, "recommendation_sha256": execution_plan.sha256_json(body)}


def writer_verify_plan(**overrides: object) -> dict:
    values: dict[str, object] = {
        "source_binding": {"kind": "direct-user", "id": "p4-test"},
        "route_decision": route_decision(),
        "topology": "writer_verify_reduce",
        "nodes": [
            {
                "node_id": "writer",
                "kind": "scoped_writer",
                "critical": True,
                "mutates": True,
                "write_scope": ["src/app.py"],
            },
            {
                "node_id": "tests",
                "kind": "verifier",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
            {
                "node_id": "reduce",
                "kind": "reducer",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
        ],
        "edges": [
            {"from": "writer", "to": "tests", "artifact": "CandidateManifest.v1"},
            {"from": "tests", "to": "reduce", "artifact": "VerificationReceipt.v1"},
        ],
        "write_scope": ["src/app.py"],
        "verification_policy": "independent_review",
        "failure_policy": {
            "on_indeterminate": "block",
            "on_unknown_effect": "reconcile",
            "revision": "bounded",
        },
        "budgets": {
            "max_revisions": 1,
            "max_duration_seconds": 3600,
            "max_tool_calls": 100,
        },
        "completion_policy": {
            "required_nodes": ["writer", "tests", "reduce"],
            "require_all_critical": True,
            "verifier_quorum": 1,
        },
    }
    values.update(overrides)
    return execution_plan.build_execution_plan(**values)  # type: ignore[arg-type]


class ExecutionPlanTests(unittest.TestCase):
    def test_execution_plan_module_is_packaged_and_runtime_declared(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"grabowski_execution_plan"', pyproject)
        runtime = json.loads((ROOT / "config/runtime-entrypoint.json").read_text())
        sources = {
            item.get("module"): item.get("source")
            for item in runtime.get("supporting_sources", [])
            if isinstance(item, dict)
        }
        self.assertEqual(
            sources.get("grabowski_execution_plan"),
            "src/grabowski_execution_plan.py",
        )

    def test_execution_plan_is_canonical_immutable_and_route_bound(self) -> None:
        first = writer_verify_plan()
        second = writer_verify_plan(
            nodes=list(reversed(first["nodes"])),
            edges=list(reversed(first["edges"])),
            route_decision=route_decision(),
        )
        self.assertEqual(first, second)
        self.assertEqual(first["kind"], "ExecutionPlan.v1")
        self.assertEqual(first["plan_id"], execution_plan.sha256_json(
            {key: value for key, value in first.items() if key != "plan_id"}
        ))
        self.assertEqual(
            first["route_binding"]["recommendation_sha256"],
            route_decision()["recommendation_sha256"],
        )
        self.assertEqual(execution_plan.validate_execution_plan(first), first)

    def test_route_digest_drift_is_rejected(self) -> None:
        route = route_decision()
        route["writer_route"] = "different-route"
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "digest mismatch"):
            writer_verify_plan(route_decision=route)

    def test_delivery_profile_is_immutably_bound_through_execution_plan(self) -> None:
        plan = writer_verify_plan(
            route_decision=route_decision(
                effect_profile="delivery", verification_policy="independent_review"
            )
        )
        self.assertEqual("delivery", plan["route_binding"]["effect_profile"])
        self.assertEqual(plan, execution_plan.validate_execution_plan(plan))

    def test_delivery_profile_rejects_deterministic_verification(self) -> None:
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError,
            "requires verification_policy=independent_review",
        ):
            execution_plan.route_binding_from_decision(
                route_decision(
                    effect_profile="delivery", verification_policy="deterministic"
                )
            )

    def test_delivery_profile_rejects_controller_route(self) -> None:
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError, "requires a scoped_writer"
        ):
            execution_plan.route_binding_from_decision(
                route_decision(effect_profile="delivery", executor="controller")
            )

    def test_route_and_revision_payloads_are_bounded(self) -> None:
        route = route_decision()
        route["oversized"] = "x" * execution_plan.MAX_ROUTE_DECISION_BYTES
        material = {key: value for key, value in route.items() if key != "recommendation_sha256"}
        route["recommendation_sha256"] = execution_plan.sha256_json(material)
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "bounded contract size"):
            writer_verify_plan(route_decision=route)

        finding = {
            "code": "oversized",
            "message": "x" * execution_plan.MAX_FINDING_BYTES,
        }
        findings_sha = execution_plan.sha256_json([finding])
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "finding exceeds"):
            execution_plan.build_revision_request(
                candidate_id=SHA_A,
                verification_summary_sha256=SHA_B,
                collection_result_sha256=SHA_C,
                findings_sha256=findings_sha,
                findings=[finding],
                round_number=1,
                next_round=2,
                write_scope=["src/app.py"],
            )

    def test_plan_verification_policy_must_match_route_without_selecting_topology(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "drifted from route"):
            writer_verify_plan(
                route_decision=route_decision(verification_policy="deterministic"),
                verification_policy="independent_review",
            )

    def test_typed_edge_requires_named_artifact(self) -> None:
        edges = [
            {"from": "writer", "to": "tests"},
            {"from": "tests", "to": "reduce", "artifact": "VerificationReceipt.v1"},
        ]
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "edge shape"):
            writer_verify_plan(edges=edges)

    def test_typed_edge_rejects_unknown_artifact_contract(self) -> None:
        edges = [
            {"from": "writer", "to": "tests", "artifact": "UntypedBlob.v1"},
            {"from": "tests", "to": "reduce", "artifact": "VerificationReceipt.v1"},
        ]
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError, "unsupported typed edge artifact"
        ):
            writer_verify_plan(edges=edges)

    def test_only_controller_or_scoped_writer_nodes_may_mutate(self) -> None:
        nodes = copy.deepcopy(writer_verify_plan()["nodes"])
        writer = next(node for node in nodes if node["node_id"] == "writer")
        verifier = next(node for node in nodes if node["node_id"] == "tests")
        writer["mutates"] = False
        writer["write_scope"] = []
        verifier["mutates"] = True
        verifier["write_scope"] = ["src/app.py"]
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError,
            "only controller or scoped_writer execution nodes may mutate",
        ):
            writer_verify_plan(nodes=nodes)

    def test_completion_policy_cannot_disable_critical_requirement(self) -> None:
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError, "must require every critical node"
        ):
            writer_verify_plan(
                completion_policy={
                    "required_nodes": ["writer"],
                    "require_all_critical": False,
                    "verifier_quorum": 0,
                }
            )

    def test_graph_cycle_is_rejected(self) -> None:
        edges = [
            {"from": "writer", "to": "tests", "artifact": "CandidateManifest.v1"},
            {"from": "tests", "to": "reduce", "artifact": "VerificationReceipt.v1"},
            {"from": "reduce", "to": "writer", "artifact": "VerificationSummary.v1"},
        ]
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "cycle"):
            writer_verify_plan(edges=edges)

    def test_disconnected_node_is_rejected_as_fake_dependency(self) -> None:
        nodes = writer_verify_plan()["nodes"] + [
            {
                "node_id": "observer",
                "kind": "observer",
                "critical": False,
                "mutates": False,
                "write_scope": [],
            }
        ]
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "disconnected"):
            writer_verify_plan(nodes=nodes)

    def test_node_write_scope_cannot_escape_plan_scope(self) -> None:
        nodes = copy.deepcopy(writer_verify_plan()["nodes"])
        next(node for node in nodes if node["node_id"] == "writer")["write_scope"] = [
            "src/other.py"
        ]
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "exceeds plan"):
            writer_verify_plan(nodes=nodes)

    def test_critical_node_cannot_be_skipped_by_completion_policy(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "critical node"):
            writer_verify_plan(
                completion_policy={
                    "required_nodes": ["writer", "reduce"],
                    "require_all_critical": True,
                    "verifier_quorum": 1,
                }
            )

    def test_independent_review_requires_quorum(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "requires verifier quorum"):
            writer_verify_plan(
                completion_policy={
                    "required_nodes": ["writer", "tests", "reduce"],
                    "require_all_critical": True,
                    "verifier_quorum": 0,
                }
            )

    def test_unknown_effect_policy_cannot_authorize_retry(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "must reconcile"):
            writer_verify_plan(
                failure_policy={
                    "on_indeterminate": "block",
                    "on_unknown_effect": "retry",
                    "revision": "bounded",
                }
            )

    def test_p4_revision_budget_is_bounded_to_one(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "max_revisions"):
            writer_verify_plan(
                budgets={
                    "max_revisions": 2,
                    "max_duration_seconds": 3600,
                    "max_tool_calls": 100,
                }
            )

    def test_fork_compare_requires_competition_and_read_only_alternatives(self) -> None:
        nodes = [
            {
                "node_id": "a",
                "kind": "alternative",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
            {
                "node_id": "b",
                "kind": "alternative",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
            {
                "node_id": "compare",
                "kind": "compare",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
        ]
        edges = [
            {"from": "a", "to": "compare", "artifact": "CandidateManifest.v1"},
            {"from": "b", "to": "compare", "artifact": "CandidateManifest.v1"},
        ]
        plan = execution_plan.build_execution_plan(
            source_binding={"kind": "direct-user", "id": "fork-test"},
            route_decision=route_decision(verification_policy="competition"),
            topology="fork_compare",
            nodes=nodes,
            edges=edges,
            write_scope=[],
            verification_policy="competition",
            failure_policy={
                "on_indeterminate": "block",
                "on_unknown_effect": "reconcile",
                "revision": "bounded",
            },
            budgets={
                "max_revisions": 0,
                "max_duration_seconds": 3600,
                "max_tool_calls": 100,
            },
            completion_policy={
                "required_nodes": ["a", "b", "compare"],
                "require_all_critical": True,
                "verifier_quorum": 0,
            },
        )
        self.assertEqual(plan["topology"], "fork_compare")
        mutated = copy.deepcopy(nodes)
        mutated[0]["mutates"] = True
        mutated[0]["write_scope"] = ["src/app.py"]
        with self.assertRaisesRegex(
            execution_plan.ExecutionPlanError,
            "only controller or scoped_writer execution nodes may mutate",
        ):
            execution_plan.build_execution_plan(
                source_binding={"kind": "direct-user", "id": "fork-test"},
                route_decision=route_decision(verification_policy="competition"),
                topology="fork_compare",
                nodes=mutated,
                edges=edges,
                write_scope=["src/app.py"],
                verification_policy="competition",
                failure_policy={
                    "on_indeterminate": "block",
                    "on_unknown_effect": "reconcile",
                    "revision": "bounded",
                },
                budgets={
                    "max_revisions": 0,
                    "max_duration_seconds": 3600,
                    "max_tool_calls": 100,
                },
                completion_policy={
                    "required_nodes": ["a", "b", "compare"],
                    "require_all_critical": True,
                    "verifier_quorum": 0,
                },
            )

    def test_fork_compare_cannot_embed_a_mutating_controller(self) -> None:
        nodes = [
            {
                "node_id": "a",
                "kind": "alternative",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
            {
                "node_id": "b",
                "kind": "alternative",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
            {
                "node_id": "controller",
                "kind": "controller",
                "critical": True,
                "mutates": True,
                "write_scope": ["src/app.py"],
            },
            {
                "node_id": "compare",
                "kind": "compare",
                "critical": True,
                "mutates": False,
                "write_scope": [],
            },
        ]
        edges = [
            {"from": "a", "to": "controller", "artifact": "CandidateManifest.v1"},
            {"from": "b", "to": "controller", "artifact": "CandidateManifest.v1"},
            {"from": "controller", "to": "compare", "artifact": "VerificationSummary.v1"},
        ]
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "fork_compare is read-only"):
            execution_plan.build_execution_plan(
                source_binding={"kind": "direct-user", "id": "fork-test"},
                route_decision=route_decision(verification_policy="competition"),
                topology="fork_compare",
                nodes=nodes,
                edges=edges,
                write_scope=["src/app.py"],
                verification_policy="competition",
                failure_policy={
                    "on_indeterminate": "block",
                    "on_unknown_effect": "reconcile",
                    "revision": "bounded",
                },
                budgets={
                    "max_revisions": 0,
                    "max_duration_seconds": 3600,
                    "max_tool_calls": 100,
                },
                completion_policy={
                    "required_nodes": ["a", "b", "controller", "compare"],
                    "require_all_critical": True,
                    "verifier_quorum": 0,
                },
            )

    def test_revision_request_binds_candidate_summary_findings_scope_and_budget(self) -> None:
        findings = [
            {"code": "scope", "message": "stay in scope"},
            {"code": "regression", "message": "fix failing case"},
        ]
        normalized = sorted(findings, key=execution_plan.canonical_json_bytes)
        request = execution_plan.build_revision_request(
            candidate_id=SHA_A,
            verification_summary_sha256=SHA_B,
            collection_result_sha256=SHA_C,
            findings_sha256=execution_plan.sha256_json(normalized),
            findings=findings,
            round_number=1,
            next_round=2,
            write_scope=["src/app.py"],
        )
        self.assertEqual(request["kind"], "RevisionRequest.v1")
        self.assertEqual(request["candidate_id"], SHA_A)
        self.assertEqual(request["budget"], {"revision_index": 1, "max_revisions": 1})
        self.assertEqual(execution_plan.validate_revision_request(request), request)
        tampered = copy.deepcopy(request)
        tampered["requested_changes"][0]["finding"]["message"] = "changed"
        with self.assertRaises(execution_plan.ExecutionPlanError):
            execution_plan.validate_revision_request(tampered)

    def test_revision_request_rejects_findings_digest_drift(self) -> None:
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "findings digest"):
            execution_plan.build_revision_request(
                candidate_id=SHA_A,
                verification_summary_sha256=SHA_B,
                collection_result_sha256=SHA_C,
                findings_sha256="d" * 64,
                findings=[{"code": "scope"}],
                round_number=1,
                next_round=2,
                write_scope=["src/app.py"],
            )

    def test_revision_request_rejects_unbounded_round_or_scope(self) -> None:
        findings = [{"code": "scope"}]
        findings_sha = execution_plan.sha256_json(findings)
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "round one"):
            execution_plan.build_revision_request(
                candidate_id=SHA_A,
                verification_summary_sha256=SHA_B,
                collection_result_sha256=SHA_C,
                findings_sha256=findings_sha,
                findings=findings,
                round_number=2,
                next_round=2,
                write_scope=["src/app.py"],
            )
        with self.assertRaisesRegex(execution_plan.ExecutionPlanError, "repository-relative"):
            execution_plan.build_revision_request(
                candidate_id=SHA_A,
                verification_summary_sha256=SHA_B,
                collection_result_sha256=SHA_C,
                findings_sha256=findings_sha,
                findings=findings,
                round_number=1,
                next_round=2,
                write_scope=["/etc/passwd"],
            )


if __name__ == "__main__":
    unittest.main()
