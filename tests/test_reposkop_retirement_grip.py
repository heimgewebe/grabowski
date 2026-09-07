from __future__ import annotations

import unittest
from unittest.mock import patch

import grabowski_grips as grips
import grabowski_mcp


PUBLIC_PARAMETERS = {
    "request_id": "gpp-" + "a" * 32,
    "observation_id": "chatgpt-thread-primary-1",
    "query": "reposkop",
    "matched_tool_names": [],
    "source_reference": "chatgpt-tool-discovery:thread:primary:reposkop",
}


def server_binding(
    *,
    connector_id: str = "primary",
    surface_id: str = "grabowski",
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "connector_id": connector_id,
        "surface_id": surface_id,
        "client_scope_kind": "connector_capability",
        "client_scope_sha256": "1" * 64,
        "state_scope_sha256": "2" * 64,
        "runtime_binding_sha256": "3" * 64,
        "release_id": "release-test",
        "repo_head": "4" * 40,
        "registered_names_sha256": "5" * 64,
        "agent_instructions_sha256": "6" * 64,
    }


class ReposkopRetirementGripTests(unittest.TestCase):
    def test_surface_is_mutating_and_not_observer_available(self) -> None:
        observer = {item["name"]: item for item in grips.list_grips("observer")}
        operator = {item["name"]: item for item in grips.list_grips("operator")}
        name = "reposkop-retirement-surface-observe"

        self.assertEqual(grips.MUTATING, operator[name]["effect"])
        self.assertFalse(observer[name]["availability"]["available"])
        self.assertTrue(operator[name]["availability"]["available"])

    def test_server_binding_is_required(self) -> None:
        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
        ) as record:
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                PUBLIC_PARAMETERS,
                allow_mutation=True,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("server retirement binding", result["output"]["error"])
        record.assert_not_called()

    def test_primary_binding_is_forwarded_and_converges(self) -> None:
        binding = server_binding()
        low_level = {
            "state": "retirement_surface_converged",
            "request_id": PUBLIC_PARAMETERS["request_id"],
            "surface_id": "grabowski",
            "observation_sha256": "7" * 64,
            "resolution_sha256": "8" * 64,
            "generic_platform_publication_state": "awaiting_platform_observation",
            "generic_platform_publication_unchanged": True,
            "does_not_establish": [
                "complete_platform_tool_schema_publication",
                "platform_origin_cryptographic_attestation",
                "platform_converged",
                "consumer_zero_outside_the_observed_chatgpt_surface",
            ],
        }
        parameters = {**PUBLIC_PARAMETERS, "_server_retirement_binding": binding}

        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
            return_value=low_level,
        ) as record:
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                parameters,
                allow_mutation=True,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        record.assert_called_once_with(
            request_id=PUBLIC_PARAMETERS["request_id"],
            surface_id="grabowski",
            observation_id=PUBLIC_PARAMETERS["observation_id"],
            query="reposkop",
            matched_tool_names=[],
            source_reference=PUBLIC_PARAMETERS["source_reference"],
            server_binding=binding,
        )
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["server-principal-bound"])
        self.assertEqual("pass", checks["state-store-bound"])
        self.assertEqual("pass", checks["runtime-bound"])
        self.assertEqual("pass", checks["generic-publication-not-promoted"])
        self.assertEqual("pass", checks["private-retirement-evidence-persisted"])

    def test_independently_generic_converged_state_is_not_treated_as_promotion(self) -> None:
        binding = server_binding()
        low_level = {
            "state": "retirement_surface_converged",
            "request_id": PUBLIC_PARAMETERS["request_id"],
            "surface_id": "grabowski",
            "observation_sha256": "7" * 64,
            "resolution_sha256": "8" * 64,
            "generic_platform_publication_state": "platform_converged",
            "generic_platform_publication_unchanged": True,
            "does_not_establish": ["platform_converged"],
        }
        parameters = {**PUBLIC_PARAMETERS, "_server_retirement_binding": binding}
        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
            return_value=low_level,
        ):
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                parameters,
                allow_mutation=True,
            )

        self.assertEqual("passed", result["receipt"]["status"])
        checks = {item["id"]: item["status"] for item in result["receipt"]["checks"]}
        self.assertEqual("pass", checks["generic-publication-not-promoted"])

    def test_blocked_surface_propagates_blocked_receipt(self) -> None:
        binding = server_binding()
        low_level = {
            "state": "retirement_surface_blocked",
            "request_id": PUBLIC_PARAMETERS["request_id"],
            "surface_id": "grabowski",
            "observation_sha256": "7" * 64,
            "forbidden_tool_names_present": ["future_reposkop_diagnostic"],
            "generic_platform_publication_state": "awaiting_platform_observation",
            "generic_platform_publication_unchanged": True,
            "does_not_establish": ["platform_converged"],
        }
        parameters = {
            **PUBLIC_PARAMETERS,
            "matched_tool_names": ["future_reposkop_diagnostic"],
            "_server_retirement_binding": binding,
        }
        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
            return_value=low_level,
        ):
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                parameters,
                allow_mutation=True,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual(
            ["reposkop_tool_discovery_match_present"],
            result["output"]["blocked_reasons"],
        )

    def test_caller_surface_id_is_rejected(self) -> None:
        parameters = {
            **PUBLIC_PARAMETERS,
            "surface_id": "der_kleine_maulwurf",
            "_server_retirement_binding": server_binding(),
        }
        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
        ) as record:
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                parameters,
                allow_mutation=True,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("unknown retirement surface grip field", result["output"]["error"])
        record.assert_not_called()

    def test_binding_rejects_surface_principal_swap(self) -> None:
        parameters = {
            **PUBLIC_PARAMETERS,
            "_server_retirement_binding": server_binding(
                connector_id="primary",
                surface_id="der_kleine_maulwurf",
            ),
        }
        with patch.object(
            grips.grabowski_client_snapshot,
            "record_platform_retirement_surface_observation",
        ) as record:
            result = grips.run_grip(
                "reposkop-retirement-surface-observe",
                parameters,
                allow_mutation=True,
            )

        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertIn("surface/principal binding mismatch", result["output"]["error"])
        record.assert_not_called()


class ReposkopRetirementMcpBindingTests(unittest.TestCase):
    def _run_mcp(
        self,
        connector_id: str,
        *,
        supplied_parameters: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], object]:
        scope = {"kind": "connector_capability", "label": "7" * 64}
        runtime = {
            "release_id": "runtime-release",
            "repo_head": "8" * 40,
            "registered_names_sha256": "9" * 64,
            "agent_instructions_sha256": "a" * 64,
        }
        parameters = dict(PUBLIC_PARAMETERS if supplied_parameters is None else supplied_parameters)
        with (
            patch.object(grabowski_mcp, "_require_capability"),
            patch.object(grabowski_mcp, "_require_mutations_enabled"),
            patch.object(
                grabowski_mcp,
                "_session_grip_policy_decision",
                return_value={"allowed": True},
            ),
            patch.object(
                grabowski_mcp,
                "_transport_connector_identity",
                return_value=connector_id,
            ),
            patch.object(
                grabowski_mcp,
                "_transport_connector_capability_scope",
                return_value=scope,
            ),
            patch.object(
                grabowski_mcp,
                "_transport_roundtrip_runtime_binding",
                return_value=runtime,
            ),
            patch.object(
                grabowski_mcp.grabowski_transport_roundtrip,
                "client_scope_sha256",
                return_value="b" * 64,
            ),
            patch.object(
                grabowski_mcp.grabowski_transport_assertion,
                "runtime_binding_sha256",
                return_value="c" * 64,
            ),
            patch.object(
                grabowski_mcp,
                "_retirement_state_scope_sha256",
                return_value="d" * 64,
            ),
            patch.object(
                grabowski_mcp.grabowski_grips,
                "grip_run",
                return_value={"ok": True},
            ) as run,
        ):
            result = grabowski_mcp.grip_run(
                "reposkop-retirement-surface-observe",
                parameters,
                profile="operator",
                allow_mutation=True,
                ctx=object(),
            )
        return result, run

    def test_primary_surface_is_server_derived(self) -> None:
        result, run = self._run_mcp("primary")
        self.assertEqual({"ok": True}, result)
        dispatched = run.call_args.args[1]
        self.assertEqual("grabowski", dispatched["_server_retirement_binding"]["surface_id"])
        self.assertEqual("primary", dispatched["_server_retirement_binding"]["connector_id"])
        self.assertEqual("b" * 64, dispatched["_server_retirement_binding"]["client_scope_sha256"])
        self.assertEqual("d" * 64, dispatched["_server_retirement_binding"]["state_scope_sha256"])
        self.assertEqual("c" * 64, dispatched["_server_retirement_binding"]["runtime_binding_sha256"])

    def test_maulwurf_surface_is_server_derived(self) -> None:
        result, run = self._run_mcp("kleiner-maulwurf")
        self.assertEqual({"ok": True}, result)
        dispatched = run.call_args.args[1]
        self.assertEqual(
            "der_kleine_maulwurf",
            dispatched["_server_retirement_binding"]["surface_id"],
        )
        self.assertEqual(
            "kleiner-maulwurf",
            dispatched["_server_retirement_binding"]["connector_id"],
        )

    def test_unknown_connector_cannot_create_retirement_binding(self) -> None:
        result, run = self._run_mcp("unknown-connector")
        self.assertEqual("blocked", result["status"])
        self.assertIn("retirement binding unavailable", result["output"]["error"])
        run.assert_not_called()

    def test_caller_cannot_supply_server_binding(self) -> None:
        parameters = {
            **PUBLIC_PARAMETERS,
            "_server_retirement_binding": server_binding(),
        }
        result, run = self._run_mcp("primary", supplied_parameters=parameters)
        self.assertEqual("blocked", result["status"])
        self.assertIn(
            "caller supplied reserved server parameter: _server_retirement_binding",
            result["output"]["error"],
        )
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
