from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import grabowski_operations as operations
import grabowski_tool_surface_budget as budget


class ToolSurfaceBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(budget.CONTRACT_PATH.read_text(encoding="utf-8"))
        cls.schema = json.loads(budget.SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.runtime = json.loads(
            budget.RUNTIME_ENTRYPOINT_PATH.read_text(encoding="utf-8")
        )
        cls.capabilities = json.loads(
            budget.CAPABILITY_CATALOG_PATH.read_text(encoding="utf-8")
        )
        cls.operations = json.loads(
            budget.OPERATIONS_CATALOG_PATH.read_text(encoding="utf-8")
        )
        cls.operation_metadata = json.loads(
            budget.OPERATION_METADATA_PATH.read_text(encoding="utf-8")
        )

    def _validate(
        self,
        contract: dict[str, object],
        runtime: dict[str, object] | None = None,
        capabilities: dict[str, object] | None = None,
        operations_payload: dict[str, object] | None = None,
        operation_metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return budget.validate_contract(
            contract,
            runtime or self.runtime,
            capabilities or self.capabilities,
            operations_payload or self.operations,
            operation_metadata or self.operation_metadata,
        )

    def test_repository_contract_is_current_and_schema_valid(self) -> None:
        report = budget.validate_repository()
        self.assertTrue(report["valid"], report)
        self.assertTrue(report["schema_valid"])
        self.assertEqual(report["baseline_tool_count"], 125)
        self.assertEqual(report["current_tool_count"], 158)
        self.assertEqual(report["growth"], 41)
        self.assertEqual(report["accepted_addition_count"], 41)
        self.assertEqual(report["operation_count"], 3)
        self.assertEqual(report["retired_tool_count"], 8)

    def test_runtime_tool_projection_accepts_schema_two_without_assets(self) -> None:
        self.assertEqual(
            budget._runtime_tools(
                {"schema_version": 2, "expected_tools": ["grabowski_status"]}
            ),
            ["grabowski_status"],
        )

    def test_runtime_tool_projection_rejects_malformed_schema_three_assets(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["runtime_assets"] = {"source": "catalog.json"}
        report = self._validate(copy.deepcopy(self.contract), runtime=runtime)
        self.assertFalse(report["valid"])
        self.assertIn("runtime_assets must be a list", report["errors"][0])

    def test_unbudgeted_public_tool_is_rejected(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["expected_tools"].append("grabowski_new_probe")
        capabilities = copy.deepcopy(self.capabilities)
        capabilities["tools"].append(
            {
                "tool": "grabowski_new_probe",
                "category": "diagnostics",
                "description": "Read one new diagnostic value.",
                "purpose": "Test an unjustified public tool addition.",
                "effects": [],
                "read_only": True,
                "reversibility": "not-applicable",
                "risk_class": "low",
            }
        )
        report = self._validate(
            copy.deepcopy(self.contract), runtime=runtime, capabilities=capabilities
        )
        self.assertFalse(report["valid"])
        self.assertIn("unbudgeted-public-tools", report["errors"][0])
        self.assertIn("grabowski_new_probe", report["errors"][0])

    def test_distinct_security_boundary_tool_can_be_accepted(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["expected_tools"].append("grabowski_secret_rotate")
        capabilities = copy.deepcopy(self.capabilities)
        new_capability = {
            "tool": "grabowski_secret_rotate",
            "category": "secret",
            "description": "Rotate one configured secret through a separate authority boundary.",
            "purpose": "Test a justified distinct secret authority surface.",
            "effects": ["secret-rotate"],
            "read_only": False,
            "reversibility": "manual",
            "risk_class": "high",
        }
        capabilities["tools"].append(new_capability)
        contract = copy.deepcopy(self.contract)
        contract["accepted_additions"]["grabowski_secret_rotate"] = {
            "tool_contract": budget.capability_projection(new_capability),
            "justification_kind": "distinct_authority_boundary",
            "rationale": (
                "Secret rotation requires a separately reviewable authority boundary "
                "that cannot be represented as an ordinary command operation."
            ),
            "evidence_refs": ["test:separate-secret-authority"],
            "operation_alternative_considered": (
                "A typed operation was rejected because it would inherit the broader "
                "generic terminal execution authority."
            ),
            "exception_detail": {
                "claim": "The tool owns a distinct secret mutation authority.",
                "evidence": "Dedicated capability and effect contract.",
            },
        }
        report = self._validate(contract, runtime=runtime, capabilities=capabilities)
        self.assertTrue(report["valid"], report)
        self.assertEqual(
            report["accepted_addition_count"],
            len(self.contract["accepted_additions"]) + 1,
        )
        self.assertEqual(report["growth"], 42)

    def test_semantic_drift_of_existing_tool_is_rejected(self) -> None:
        capabilities = copy.deepcopy(self.capabilities)
        status = next(
            item for item in capabilities["tools"] if item["tool"] == "grabowski_status"
        )
        status["risk_class"] = "high"
        report = self._validate(copy.deepcopy(self.contract), capabilities=capabilities)
        self.assertFalse(report["valid"])
        self.assertIn("tool capability semantics drift", report["errors"][0])

    def test_arbitrary_fixed_cap_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["policy"]["fixed_tool_cap"] = 125
        report = self._validate(contract)
        self.assertFalse(report["valid"])
        self.assertIn("fixed_tool_cap", report["errors"][0])

    def test_baseline_anchor_blocks_grandfathering(self) -> None:
        runtime = copy.deepcopy(self.runtime)
        runtime["expected_tools"].append("grabowski_grandfathered_probe")
        capabilities = copy.deepcopy(self.capabilities)
        new_capability = {
            "tool": "grabowski_grandfathered_probe",
            "category": "diagnostics",
            "description": "Read one value through an unjustified grandfathered surface.",
            "purpose": "Prove that rewriting baseline hashes cannot bypass review.",
            "effects": [],
            "read_only": True,
            "reversibility": "not-applicable",
            "risk_class": "low",
        }
        capabilities["tools"].append(new_capability)
        contract = copy.deepcopy(self.contract)
        projected = budget.capability_projection(new_capability)
        contract["baseline"]["tools"].append(projected)
        contract["baseline"]["tools"].sort(key=lambda item: item["tool"])
        names = [item["tool"] for item in contract["baseline"]["tools"]]
        contract["baseline"]["tool_count"] = len(names)
        contract["baseline"]["tool_names_sha256"] = budget._sha256(names)
        contract["baseline"]["tool_semantics_sha256"] = budget._sha256(
            contract["baseline"]["tools"]
        )
        report = self._validate(contract, runtime=runtime, capabilities=capabilities)
        self.assertFalse(report["valid"])
        self.assertIn("baseline anchor drift", report["errors"][0])

    def test_schema_rejects_incomplete_addition(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["accepted_additions"]["grabowski_missing_evidence"] = {
            "justification_kind": "distinct_authority_boundary"
        }
        errors = budget.validate_schema(contract, self.schema)
        self.assertTrue(errors)
        self.assertTrue(any("tool_contract" in error for error in errors), errors)

    def test_schema_hash_drift_is_rejected_before_validation(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["title"] = "Unreviewed replacement schema"
        errors = budget.validate_schema(self.contract, schema)
        self.assertEqual(
            errors,
            ["invalid tool-surface JSON schema: code-bound schema hash drift"],
        )

    def test_validator_has_no_third_party_runtime_dependency(self) -> None:
        source = Path(budget.__file__).read_text(encoding="utf-8")
        self.assertNotIn("from jsonschema", source)
        self.assertNotIn("import jsonschema", source)

    def test_typed_operation_adds_intent_without_public_tool_growth(self) -> None:
        operations_by_name = {
            item["operation"]: item
            for item in self.contract["operation_catalog"]["operations"]
        }
        self.assertIn("inspect-user-service", operations_by_name)
        self.assertEqual(
            operations_by_name["inspect-user-service"]["execution_authorities"],
            ["operator-mutation"],
        )
        self.assertEqual(
            operations_by_name["inspect-user-service"]["effects"], ["service-read"]
        )
        self.assertNotIn(
            "grabowski_inspect_user_service", self.runtime["expected_tools"]
        )

    def test_baseline_cannot_be_reinitialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "contracts" / "tool-surface-budget.v1.json"
            path.parent.mkdir(parents=True)
            path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(
                budget.ToolSurfaceBudgetError, "already initialized"
            ):
                budget.initialize_contract(root)


class OperationCatalogBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.operations = json.loads(
            budget.OPERATIONS_CATALOG_PATH.read_text(encoding="utf-8")
        )
        cls.operation_metadata = json.loads(
            budget.OPERATION_METADATA_PATH.read_text(encoding="utf-8")
        )

    def test_current_engine_renders_new_catalog_operation(self) -> None:
        with patch.object(
            operations, "OPERATIONS_CONFIG", budget.OPERATIONS_CATALOG_PATH
        ):
            plan = operations._render("inspect-user-service", {"unit": "demo.service"})
        self.assertEqual(
            plan["steps"][0]["argv"],
            [
                "systemctl",
                "--user",
                "show",
                "demo.service",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
            ],
        )

    def test_operation_without_metadata_is_rejected(self) -> None:
        metadata = copy.deepcopy(self.operation_metadata)
        metadata["operations"].pop("inspect-user-service")
        with self.assertRaisesRegex(
            budget.ToolSurfaceBudgetError, "metadata names differ"
        ):
            budget._operations(self.operations, metadata)

    def test_operation_metadata_requires_explicit_effects(self) -> None:
        metadata = copy.deepcopy(self.operation_metadata)
        metadata["operations"]["inspect-user-service"].pop("effects")
        with self.assertRaisesRegex(
            budget.ToolSurfaceBudgetError, "invalid metadata keys"
        ):
            budget._operations(self.operations, metadata)


if __name__ == "__main__":
    unittest.main()
