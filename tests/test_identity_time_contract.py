from __future__ import annotations

import ast
import importlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

effect_receipt = importlib.import_module("grabowski_effect_receipt")
transport_assertion = importlib.import_module("grabowski_transport_assertion")


CONTRACT_PATH = ROOT / "contracts" / "identity-time-contract.v1.json"
TASKS_PATH = SRC / "grabowski_tasks.py"
OPERATIONAL_TRUTH_PATH = SRC / "grabowski_operational_truth.py"
WORKERS_PATH = SRC / "grabowski_workers.py"


def _function(path: Path, name: str) -> ast.FunctionDef:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"missing function {name} in {path}")


def _strings(node: ast.AST) -> set[str]:
    return {
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }


class IdentityTimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

    def test_contract_is_descriptive_and_non_authoritative(self) -> None:
        self.assertEqual(self.contract["schema_version"], 1)
        self.assertEqual(self.contract["kind"], "grabowski_identity_time_contract")
        authority = self.contract["authority"]
        self.assertEqual(authority["mode"], "descriptive-and-testable")
        self.assertFalse(authority["adds_mutable_truth"])
        self.assertFalse(authority["adds_execution_authority"])
        self.assertFalse(authority["adds_retry_authority"])
        self.assertFalse(authority["adds_identity_namespace"])

    def test_contract_names_all_current_identity_roles(self) -> None:
        roles = set(self.contract["identity_roles"])
        self.assertEqual(
            roles,
            {
                "semantic_operation",
                "operational_projection_identity",
                "task",
                "execution_attempt",
                "legacy_task_request_reference",
                "worker",
                "transport_request",
                "effect_admission_request",
                "effect_admission",
                "effect_completion",
                "task_lifecycle_receipt",
            },
        )

    def test_request_id_namespaces_are_explicitly_distinct(self) -> None:
        aliases = self.contract["ambiguous_names"]["request_id"]
        by_namespace = {item["namespace"]: item for item in aliases}
        self.assertEqual(set(by_namespace), {"transport", "effect-receipt", "task"})
        self.assertEqual(
            by_namespace["transport"]["canonical_role"],
            "transport_request",
        )
        self.assertEqual(
            by_namespace["effect-receipt"]["canonical_role"],
            "effect_admission_request",
        )
        self.assertEqual(
            by_namespace["task"]["canonical_role"],
            "legacy_task_request_reference",
        )
        legacy = self.contract["identity_roles"]["legacy_task_request_reference"]
        self.assertEqual(legacy["identity_status"], "legacy-non-authoritative-reference")
        tasks_text = TASKS_PATH.read_text(encoding="utf-8")
        self.assertIn('"request_id": ("TEXT", 0, 0)', tasks_text)
        self.assertIn('"request_id": record.get("request_id")', tasks_text)
        tree = ast.parse(tasks_text, filename=str(TASKS_PATH))
        self.assertFalse(
            any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(argument.arg == "request_id" for argument in node.args.args + node.args.kwonlyargs)
                for node in ast.walk(tree)
            )
        )

    def test_operation_identity_namespaces_keep_projection_non_authoritative(self) -> None:
        aliases = self.contract["ambiguous_names"]["operation_identity"]
        by_namespace = {item["namespace"]: item for item in aliases}
        self.assertEqual(set(by_namespace), {"task", "operational-truth"})
        self.assertEqual(
            by_namespace["task"]["canonical_role"],
            "semantic_operation",
        )
        self.assertEqual(
            by_namespace["operational-truth"]["canonical_role"],
            "operational_projection_identity",
        )
        projection = self.contract["identity_roles"]["operational_projection_identity"]
        self.assertIn("task start deduplication", projection["not_authority_for"])
        self.assertIn("retry admission", projection["not_authority_for"])

        function = _function(OPERATIONAL_TRUTH_PATH, "compute_operation_identity")
        strings = _strings(function)
        self.assertTrue(
            {
                "operation_identity",
                "operation_id",
                "unit",
                "authoritative_unit",
                "argv_sha256",
                "execution_envelope_sha256",
                "task_id",
                "work_id",
            }.issubset(strings)
        )

    def test_transport_request_identity_is_retry_stable_and_payload_bound(self) -> None:
        common = {
            "secret": "A" * 43,
            "session_id": "session-1",
            "rpc_request_id": '"rpc-1"',
        }
        first = transport_assertion.derive_request_id(
            **common,
            body_sha256="1" * 64,
        )
        replay = transport_assertion.derive_request_id(
            **common,
            body_sha256="1" * 64,
        )
        changed_payload = transport_assertion.derive_request_id(
            **common,
            body_sha256="2" * 64,
        )
        changed_session = transport_assertion.derive_request_id(
            **{**common, "session_id": "session-2"},
            body_sha256="1" * 64,
        )
        self.assertEqual(first, replay)
        self.assertNotEqual(first, changed_payload)
        self.assertNotEqual(first, changed_session)

    def test_effect_request_identity_is_admission_scoped(self) -> None:
        first = effect_receipt.admit(
            tool="write",
            arguments={"value": 1},
            runtime_sha256="a" * 64,
            effect_class="mutating",
            admitted_at_unix=10,
        )
        second = effect_receipt.admit(
            tool="write",
            arguments={"value": 1},
            runtime_sha256="a" * 64,
            effect_class="mutating",
            admitted_at_unix=10,
        )
        completion = effect_receipt.complete(
            first,
            completion_class="succeeded",
            completed_at_unix=11,
        )

        self.assertNotEqual(first["request_id"], second["request_id"])
        self.assertEqual(completion["request_id"], first["request_id"])
        self.assertEqual(completion["admission_sha256"], first["admission_sha256"])
        self.assertIn("safe_retry_after_response_loss", first["does_not_establish"])

    def test_operation_identity_material_and_retry_binding_remain_separate(self) -> None:
        operation = _function(TASKS_PATH, "_normalize_task_operation_identity")
        operation_strings = _strings(operation)
        self.assertTrue(
            {
                "repository_head",
                "source_fingerprint_sha256",
                "purpose",
                "scope_sha256",
                "canonical_cwd",
                "operation_identity_sha256",
            }.issubset(operation_strings)
        )

        retry = _function(TASKS_PATH, "_operation_retry_binding")
        retry_strings = _strings(retry)
        self.assertTrue(
            {
                "source_task_id",
                "source_lifecycle_receipt_sha256",
                "source_operation_identity_sha256",
                "force_new_reason",
            }.issubset(retry_strings)
        )

    def test_task_attempt_is_a_generation_within_task_identity(self) -> None:
        unit = _function(TASKS_PATH, "_task_unit")
        names = {node.id for node in ast.walk(unit) if isinstance(node, ast.Name)}
        self.assertTrue({"task_id", "attempt"}.issubset(names))
        self.assertIn("Task attempt must be positive", _strings(unit))

    def test_worker_identity_is_registry_and_resource_owner_identity(self) -> None:
        worker = self.contract["identity_roles"]["worker"]
        self.assertEqual(worker["canonical_name"], "worker_id")
        self.assertEqual(worker["owner"], "grabowski_workers")
        browser = _function(WORKERS_PATH, "browser_start")
        gui = _function(WORKERS_PATH, "gui_start")
        public = _function(WORKERS_PATH, "_public")
        release = _function(WORKERS_PATH, "_release")
        self.assertIn("worker_id", _strings(browser))
        self.assertIn("worker_id", _strings(gui))
        self.assertIn("worker_id", _strings(public))
        self.assertIn("worker_id", _strings(release))
        self.assertIn("worker:", WORKERS_PATH.read_text(encoding="utf-8"))

    def test_worker_runtime_limit_uses_source_monotonic_clock(self) -> None:
        function = _function(WORKERS_PATH, "_planned_runtime_limit_reached")
        strings = _strings(function)
        self.assertTrue(
            {
                "runtime_seconds",
                "ActiveEnterTimestampMonotonic",
                "ActiveExitTimestampMonotonic",
            }.issubset(strings)
        )
        self.assertNotIn("observed_at_unix", strings)
        operators = {type(node) for node in ast.walk(function)}
        self.assertIn(ast.Sub, operators)
        self.assertIn(ast.Mult, operators)

    def test_clock_domains_forbid_cross_domain_substitution(self) -> None:
        clocks = self.contract["clock_domains"]
        self.assertEqual(
            clocks["observation_wall_clock"]["semantics"],
            "time at which Grabowski observed or sampled state",
        )
        monotonic_forbidden = clocks["source_monotonic"]["forbidden"]
        self.assertIn(
            "direct comparison with Unix wall-clock values",
            monotonic_forbidden,
        )
        logical = clocks["logical_generation"]
        self.assertEqual(logical["clock"], "logical generation, not a timestamp")

    def test_declared_implementation_evidence_resolves(self) -> None:
        for reference in self.contract["implementation_evidence"].values():
            path_text, function_text = reference.split(":", 1)
            path = ROOT / path_text
            self.assertTrue(path.is_file(), reference)
            for function_name in function_text.split(","):
                _function(path, function_name)


if __name__ == "__main__":
    unittest.main()
