from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_browser_structured_tools as structured


EFFECTS = {
    "read": {
        "admission": "implemented",
        "requires_operator_mutation": False,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "local_ui": {
        "admission": "implemented",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
    "external_mutation": {
        "admission": "fail_closed",
        "requires_operator_mutation": True,
        "ambiguous_outcome": {
            "retry_authorized": False,
            "authoritative_readback_required": True,
            "readback_grants_retry_authority": False,
        },
    },
}


def effect_resolver(name: str):
    return EFFECTS.get(name)


def provider_spec(provider_id: str = "example.api", origin: str = "https://example.com") -> dict:
    return {
        "schema_version": 1,
        "provider_id": provider_id,
        "origins": [origin],
        "operations": [
            {"operation": "read.item", "effect_class": "read"},
            {"operation": "focus.item", "effect_class": "local_ui"},
            {"operation": "submit.item", "effect_class": "external_mutation"},
        ],
    }


def eligible_registry() -> structured.StructuredToolProviderRegistry:
    registry = structured.StructuredToolProviderRegistry(effect_resolver=effect_resolver)
    registry.register(provider_spec())
    return registry


def valid_receipt(assessment: dict, *, ok: bool = True) -> dict:
    return {
        "schema_version": 1,
        "kind": "structured_tool_provider_receipt",
        "provider_id": assessment["provider_id"],
        "operation": assessment["operation"],
        "effect_class": assessment["effect_class"],
        "effect_contract_sha256": assessment["effect_contract_sha256"],
        "target_sha256": assessment["target"]["target_sha256"],
        "ok": ok,
        "result_code": "ok" if ok else "provider_error",
        "effect_state": "observed" if ok else "unknown",
        "authoritative_readback": ok,
        "provider_receipt_sha256": hashlib.sha256(b"provider-receipt").hexdigest(),
    }


class ProviderContractTests(unittest.TestCase):
    def test_valid_contract_is_deterministic_and_execution_free(self) -> None:
        spec = provider_spec()
        spec["operations"] = list(reversed(spec["operations"]))
        contract = structured.normalize_provider_spec(spec, effect_resolver=effect_resolver)
        self.assertEqual(contract["provider_id"], "example.api")
        self.assertEqual(
            [item["operation"] for item in contract["operations"]],
            ["focus.item", "read.item", "submit.item"],
        )
        self.assertFalse(contract["provider_execution_available"])
        self.assertFalse(contract["automatic_routing_available"])
        self.assertRegex(contract["contract_sha256"], r"^[0-9a-f]{64}$")

    def test_unknown_provider_fields_are_rejected(self) -> None:
        spec = provider_spec()
        spec["invoke"] = "do-not-run"
        with self.assertRaisesRegex(structured.StructuredToolContractError, "provider-fields-unknown"):
            structured.normalize_provider_spec(spec, effect_resolver=effect_resolver)

    def test_provider_identifier_is_canonical(self) -> None:
        for provider_id in ("Example.api", "example/api", "1example", "x" * 65):
            with self.subTest(provider_id=provider_id):
                with self.assertRaises(structured.StructuredToolContractError):
                    structured.normalize_provider_spec(
                        provider_spec(provider_id=provider_id), effect_resolver=effect_resolver
                    )

    def test_origins_must_be_exact_canonical_origins(self) -> None:
        invalid = [
            "https://Example.com",
            "https://example.com/",
            "https://example.com:443",
            "https://user@example.com",
            "https://example.com?secret=1",
            "ftp://example.com",
        ]
        for origin in invalid:
            with self.subTest(origin=origin):
                with self.assertRaises(structured.StructuredToolContractError):
                    structured.normalize_provider_spec(
                        provider_spec(origin=origin), effect_resolver=effect_resolver
                    )

    def test_dns_origin_labels_fail_closed(self) -> None:
        for origin in (
            "https://bad_host.example",
            "https://-bad.example",
            "https://bad-.example",
        ):
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(
                    structured.StructuredToolContractError, "url-invalid"
                ):
                    structured.normalize_provider_spec(
                        provider_spec(origin=origin), effect_resolver=effect_resolver
                    )

    def test_duplicate_origins_are_rejected(self) -> None:
        spec = provider_spec()
        spec["origins"] = ["https://example.com", "https://example.com"]
        with self.assertRaisesRegex(structured.StructuredToolContractError, "provider-origins"):
            structured.normalize_provider_spec(spec, effect_resolver=effect_resolver)

    def test_duplicate_operations_are_rejected(self) -> None:
        spec = provider_spec()
        spec["operations"].append({"operation": "read.item", "effect_class": "read"})
        with self.assertRaisesRegex(structured.StructuredToolContractError, "provider-operation-duplicate"):
            structured.normalize_provider_spec(spec, effect_resolver=effect_resolver)

    def test_unknown_effect_is_rejected(self) -> None:
        spec = provider_spec()
        spec["operations"][0]["effect_class"] = "invented"
        with self.assertRaisesRegex(structured.StructuredToolContractError, "effect-unknown"):
            structured.normalize_provider_spec(spec, effect_resolver=effect_resolver)

    def test_nonconservative_effect_contract_is_rejected(self) -> None:
        bad = json.loads(json.dumps(EFFECTS))
        bad["read"]["ambiguous_outcome"]["retry_authorized"] = True
        with self.assertRaisesRegex(structured.StructuredToolContractError, "effect-contract-invalid"):
            structured.normalize_provider_spec(
                provider_spec(), effect_resolver=lambda name: bad.get(name)
            )

    def test_missing_default_effect_catalog_fails_closed(self) -> None:
        with mock.patch.object(
            structured.importlib, "import_module", side_effect=ModuleNotFoundError("mcp")
        ):
            with self.assertRaisesRegex(structured.StructuredToolContractError, "effect-catalog-unavailable"):
                structured.normalize_provider_spec(provider_spec())


class ExplicitRegistryTests(unittest.TestCase):
    def test_duplicate_provider_registration_is_rejected(self) -> None:
        registry = eligible_registry()
        with self.assertRaisesRegex(structured.StructuredToolContractError, "provider-duplicate"):
            registry.register(provider_spec())

    def test_two_registered_providers_create_no_route(self) -> None:
        registry = structured.StructuredToolProviderRegistry(effect_resolver=effect_resolver)
        registry.register(provider_spec("alpha.api", "https://alpha.example"))
        registry.register(provider_spec("beta.api", "https://beta.example"))
        self.assertEqual(registry.provider_ids(), ("alpha.api", "beta.api"))
        for forbidden in ("select", "route", "invoke", "execute", "fallback"):
            self.assertFalse(hasattr(registry, forbidden), forbidden)
        alpha = registry.assess("alpha.api", "read.item", "https://alpha.example/item/1")
        beta = registry.assess("beta.api", "read.item", "https://beta.example/item/1")
        self.assertTrue(alpha["eligible"])
        self.assertTrue(beta["eligible"])
        self.assertFalse(alpha["automatic_route_selected"])
        self.assertFalse(beta["automatic_route_selected"])

    def test_unknown_provider_requires_explicit_identity(self) -> None:
        registry = eligible_registry()
        with self.assertRaisesRegex(structured.StructuredToolContractError, "provider-unknown"):
            registry.assess("other.api", "read.item", "https://example.com/item")

    def test_unsupported_operation_is_ineligible_not_routed(self) -> None:
        result = eligible_registry().assess(
            "example.api", "delete.item", "https://example.com/item"
        )
        self.assertFalse(result["eligible"])
        self.assertEqual(result["result_code"], "operation_unsupported")
        self.assertIsNone(result["effect_class"])
        self.assertFalse(result["provider_execution_performed"])

    def test_out_of_scope_target_is_ineligible(self) -> None:
        result = eligible_registry().assess(
            "example.api", "read.item", "https://elsewhere.example/item"
        )
        self.assertFalse(result["eligible"])
        self.assertEqual(result["result_code"], "target_out_of_scope")

    def test_fail_closed_effect_is_not_eligible(self) -> None:
        result = eligible_registry().assess(
            "example.api", "submit.item", "https://example.com/item"
        )
        self.assertFalse(result["eligible"])
        self.assertEqual(result["result_code"], "effect_fail_closed")
        self.assertEqual(result["effect_class"], "external_mutation")

    def test_target_rejects_query_fragment_userinfo_and_non_http(self) -> None:
        invalid = [
            "https://example.com/item?secret=1",
            "https://example.com/item#secret",
            "https://user@example.com/item",
            "file:///tmp/item",
            "https://example.com/it em",
        ]
        registry = eligible_registry()
        for target in invalid:
            with self.subTest(target=target):
                with self.assertRaises(structured.StructuredToolContractError):
                    registry.assess("example.api", "read.item", target)

    def test_eligibility_projects_only_target_digests(self) -> None:
        result = eligible_registry().assess(
            "example.api", "read.item", "https://example.com/private/path"
        )
        self.assertTrue(result["eligible"])
        self.assertEqual(
            set(result["target"]), {"target_sha256", "origin_sha256", "path_sha256"}
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("private/path", serialized)
        self.assertNotIn("https://example.com", serialized)
        self.assertFalse(result["retry_authorized"])
        self.assertTrue(result["authoritative_readback_required"])


class ReceiptNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = eligible_registry()
        self.target = "https://example.com/item/42"
        self.assessment = self.registry.assess("example.api", "read.item", self.target)

    def test_valid_receipt_normalizes_without_execution_or_retry(self) -> None:
        outcome = self.registry.normalize_receipt(
            "example.api", "read.item", self.target, valid_receipt(self.assessment)
        )
        self.assertEqual(outcome["kind"], "structured_tool_outcome")
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertFalse(outcome["normalizer_execution_performed"])
        self.assertFalse(outcome["automatic_route_selected"])
        self.assertFalse(outcome["retry_authorized"])
        self.assertTrue(outcome["authoritative_readback_required"])
        self.assertFalse(outcome["readback_grants_retry_authority"])

    def test_receipt_extra_sensitive_fields_are_not_projected(self) -> None:
        receipt = valid_receipt(self.assessment)
        receipt.update(
            {
                "headers": {"Authorization": "Bearer secret"},
                "body": "secret-body",
                "credentials": "secret-credential",
            }
        )
        outcome = self.registry.normalize_receipt(
            "example.api", "read.item", self.target, receipt
        )
        serialized = json.dumps(outcome, sort_keys=True)
        for secret in ("Authorization", "Bearer secret", "secret-body", "secret-credential"):
            self.assertNotIn(secret, serialized)

    def test_receipt_bindings_are_all_mandatory(self) -> None:
        mutations = {
            "provider_id": "other.api",
            "operation": "focus.item",
            "effect_class": "local_ui",
            "effect_contract_sha256": "0" * 64,
            "target_sha256": "1" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                receipt = valid_receipt(self.assessment)
                receipt[field] = value
                with self.assertRaisesRegex(structured.StructuredToolReceiptError, "receipt-binding"):
                    self.registry.normalize_receipt(
                        "example.api", "read.item", self.target, receipt
                    )

    def test_success_requires_ok_code_observed_state_and_readback(self) -> None:
        cases = [
            ("result_code", "provider_error"),
            ("effect_state", "unknown"),
            ("authoritative_readback", False),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                receipt = valid_receipt(self.assessment)
                receipt[field] = value
                with self.assertRaisesRegex(structured.StructuredToolReceiptError, "receipt-invalid"):
                    self.registry.normalize_receipt(
                        "example.api", "read.item", self.target, receipt
                    )

    def test_failure_unknown_state_remains_non_retryable(self) -> None:
        outcome = self.registry.normalize_receipt(
            "example.api", "read.item", self.target, valid_receipt(self.assessment, ok=False)
        )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertFalse(outcome["retry_authorized"])
        self.assertTrue(outcome["authoritative_readback_required"])

    def test_receipt_cannot_be_normalized_for_ineligible_effect(self) -> None:
        assessment = self.registry.assess(
            "example.api", "submit.item", "https://example.com/item"
        )
        with self.assertRaisesRegex(structured.StructuredToolReceiptError, "provider-not-eligible"):
            self.registry.normalize_receipt(
                "example.api",
                "submit.item",
                "https://example.com/item",
                valid_receipt(assessment),
            )


class ToolBootstrapTests(unittest.TestCase):
    def test_cli_help_works_without_runtime_provider_execution(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/browser_structured_tools.py"), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("StructuredToolProvider", result.stdout)


if __name__ == "__main__":
    unittest.main()
