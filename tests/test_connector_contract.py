from __future__ import annotations

import copy
import unittest

import grabowski_connector_contract as contract


NAMES = [
    "alpha",
    "grabowski_bureau_candidate_assess",
    "grabowski_secret_reveal",
    "grabowski_task_start",
]


def _object_schema(properties: set[str]) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            name: {"type": "string", "default": ""}
            for name in sorted(properties)
        },
    }


def _sentinel_schemas() -> dict[str, dict[str, object]]:
    return {
        "grabowski_bureau_candidate_assess": _object_schema(
            contract.REQUIRED_SCHEMA_PROPERTIES[
                "grabowski_bureau_candidate_assess"
            ]
        ),
        "grabowski_secret_reveal": _object_schema({"path"}),
        "grabowski_task_start": _object_schema(
            contract.REQUIRED_SCHEMA_PROPERTIES["grabowski_task_start"]
        ),
    }


def _artifact(
    schemas: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    schemas = _sentinel_schemas() if schemas is None else schemas
    return {
        "schema_version": 1,
        "tools": [
            {"name": name, "inputSchema": schemas[name]}
            if name in schemas
            else name
            for name in NAMES
        ],
    }


class ConnectorContractTests(unittest.TestCase):
    def test_mixed_artifact_has_complete_names_and_exact_sentinel_coverage(self) -> None:
        names, schemas, metadata = contract.parse_observed_artifact(_artifact())

        self.assertEqual(names, NAMES)
        self.assertEqual(set(schemas), contract.REQUIRED_SCHEMA_SENTINELS)
        self.assertEqual(metadata["name_count"], len(NAMES))
        self.assertEqual(metadata["names_sha256"], contract.fingerprint(NAMES))
        self.assertEqual(metadata["schema_coverage_count"], 3)
        self.assertLessEqual(
            metadata["artifact_bytes"], contract.MAX_OBSERVED_ARTIFACT_BYTES
        )

    def test_positive_probe_matches_all_contract_axes(self) -> None:
        names, schemas, _ = contract.parse_observed_artifact(_artifact())
        result = contract.probe_contract(
            names,
            schemas,
            NAMES,
            _sentinel_schemas(),
            NAMES,
        )

        self.assertTrue(result["matches"])
        self.assertTrue(result["name_contract_matches"])
        self.assertTrue(result["runtime_contract_matches"])
        self.assertTrue(result["schema_contract_matches"])
        self.assertEqual(result["missing_schema_sentinels"], [])
        self.assertEqual(result["required_schema_property_mismatches"], [])
        self.assertEqual(result["schema_mismatches"], [])

    def test_candidate_assess_idempotency_key_is_a_concrete_negative_probe(self) -> None:
        runtime_schemas = _sentinel_schemas()
        observed_schemas = copy.deepcopy(runtime_schemas)
        del observed_schemas["grabowski_bureau_candidate_assess"]["properties"][
            "idempotency_key"
        ]

        result = contract.probe_contract(
            NAMES,
            observed_schemas,
            NAMES,
            runtime_schemas,
            NAMES,
        )

        self.assertFalse(result["matches"])
        self.assertFalse(result["schema_contract_matches"])
        self.assertEqual(
            [
                item
                for item in result["required_schema_property_mismatches"]
                if item["tool"] == "grabowski_bureau_candidate_assess"
                and item["source"] == "connector"
            ],
            [
                {
                    "tool": "grabowski_bureau_candidate_assess",
                    "source": "connector",
                    "missing_properties": ["idempotency_key"],
                }
            ],
        )

    def test_each_task_start_identity_field_is_a_concrete_negative_probe(self) -> None:
        runtime_schemas = _sentinel_schemas()
        for field in sorted(
            contract.REQUIRED_SCHEMA_PROPERTIES["grabowski_task_start"]
        ):
            with self.subTest(field=field):
                observed_schemas = copy.deepcopy(runtime_schemas)
                del observed_schemas["grabowski_task_start"]["properties"][field]
                result = contract.probe_contract(
                    NAMES,
                    observed_schemas,
                    NAMES,
                    runtime_schemas,
                    NAMES,
                )
                self.assertFalse(result["matches"])
                self.assertFalse(result["schema_contract_matches"])
                self.assertEqual(
                    [
                        item
                        for item in result["required_schema_property_mismatches"]
                        if item["tool"] == "grabowski_task_start"
                        and item["source"] == "connector"
                    ],
                    [
                        {
                            "tool": "grabowski_task_start",
                            "source": "connector",
                            "missing_properties": [field],
                        }
                    ],
                )

    def test_missing_duplicate_and_extra_schema_entries_fail_closed(self) -> None:
        schemas = _sentinel_schemas()
        missing = contract.probe_contract(
            NAMES[:-1],
            schemas,
            NAMES,
            schemas,
            NAMES,
        )
        self.assertFalse(missing["matches"])
        self.assertEqual(missing["missing_from_connector"], ["grabowski_task_start"])

        duplicate = _artifact()
        duplicate["tools"].append("alpha")
        with self.assertRaisesRegex(
            contract.ConnectorContractError, "duplicate observed artifact tool"
        ):
            contract.parse_observed_artifact(duplicate)

        extra_schema = _artifact()
        extra_schema["tools"][0] = {
            "name": "alpha",
            "inputSchema": {"type": "object"},
        }
        names, observed_schemas, _ = contract.parse_observed_artifact(extra_schema)
        result = contract.probe_contract(
            names,
            observed_schemas,
            NAMES,
            schemas,
            NAMES,
        )
        self.assertFalse(result["schema_contract_matches"])
        self.assertEqual(result["unexpected_schema_tools"], ["alpha"])

    def test_oversized_artifact_fails_before_acceptance(self) -> None:
        oversized = {
            "schema_version": 1,
            "tools": [f"tool-{index:04d}-" + ("x" * 40) for index in range(900)],
        }
        with self.assertRaisesRegex(
            contract.ConnectorContractError, "32-KiB size limit"
        ):
            contract.parse_observed_artifact(oversized)

    def test_schema_metadata_does_not_create_false_drift(self) -> None:
        runtime = _sentinel_schemas()
        observed = copy.deepcopy(runtime)
        observed["grabowski_task_start"]["title"] = "Connected title"
        observed["grabowski_task_start"]["properties"][
            "operation_identity"
        ]["description"] = "Connected description"

        result = contract.probe_contract(
            NAMES,
            observed,
            NAMES,
            runtime,
            NAMES,
        )
        self.assertTrue(result["matches"])

    def test_runtime_export_keeps_only_three_schema_objects(self) -> None:
        schemas = _sentinel_schemas()
        runtime_tools = [
            {
                "name": name,
                "inputSchema": schemas.get(name, {"type": "object"}),
            }
            for name in NAMES
        ]
        artifact = contract.mixed_artifact_from_runtime_tools(runtime_tools)
        names, observed_schemas, _ = contract.parse_observed_artifact(artifact)

        self.assertEqual(names, NAMES)
        self.assertEqual(set(observed_schemas), contract.REQUIRED_SCHEMA_SENTINELS)


if __name__ == "__main__":
    unittest.main()
