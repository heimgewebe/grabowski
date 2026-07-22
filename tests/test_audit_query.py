from __future__ import annotations

from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _line(record: dict[str, object]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _component(path: str, records: list[dict[str, object]]):
    data = b"\n".join(_line(record) for record in records) + (b"\n" if records else b"")
    return (
        Path(path),
        data,
        {
            "valid": True,
            "exists": True,
            "records": len(records),
            "legacy_records": sum(record.get("record_sha256") is None for record in records),
            "v2_records": sum(record.get("record_sha256") is not None for record in records),
            "last_record_sha256": records[-1].get("record_sha256") if records else None,
            "active_bytes": len(data),
            "segment_sha256": hashlib.sha256(data).hexdigest(),
            "error": None,
        },
    )


class AuditQueryTests(unittest.TestCase):
    def _load_module(
        self,
        components=None,
        *,
        read_error: Exception | None = None,
        lazy_overrides: dict[Path, tuple[bytes, dict[str, object]]] | None = None,
    ):
        fake_base = types.ModuleType("grabowski_mcp")
        fake_base.AUDIT_LOG = Path("/tmp/grabowski-audit-test/write-audit.jsonl")
        fake_base.required_capabilities = []
        fake_base._require_capability = fake_base.required_capabilities.append

        class FakeMCP:
            def __init__(self):
                self.tools: dict[str, object] = {}

            def tool(self, *, name, annotations):
                def decorate(function):
                    self.tools[name] = function
                    return function
                return decorate

        fake_operator = types.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_base._audit_coordination_lock = lambda path, exclusive=False: nullcontext()
        fake_base.read_chain_calls = []

        original_components = list(components or [])
        lazy_files = {
            Path(path): (data, dict(status))
            for path, data, status in original_components
        }
        if lazy_overrides:
            lazy_files.update(lazy_overrides)

        if read_error is not None:
            def fail_read(
                path,
                use_segment_cache=False,
                retain_verified_segment_data=True,
            ):
                raise read_error
            fake_base._read_audit_chain_unlocked = fail_read
        else:
            def read_chain(
                path,
                use_segment_cache=False,
                retain_verified_segment_data=True,
            ):
                fake_base.read_chain_calls.append(
                    {
                        "use_segment_cache": use_segment_cache,
                        "retain_verified_segment_data": retain_verified_segment_data,
                    }
                )
                returned = []
                for index, (segment_path, data, status) in enumerate(original_components):
                    returned_data = data
                    if index > 0 and not retain_verified_segment_data:
                        returned_data = b""
                    returned.append((segment_path, returned_data, dict(status)))
                return returned, False
            fake_base._read_audit_chain_unlocked = read_chain

        def read_audit_file_bytes(path):
            try:
                data, _status = lazy_files[Path(path)]
            except KeyError as exc:
                raise AssertionError(f"unexpected lazy audit read: {path}") from exc
            return data, True

        fake_base._read_audit_file_bytes = read_audit_file_bytes

        previous = sys.modules.get("grabowski_mcp")
        previous_operator = sys.modules.get("grabowski_operator_core")
        sys.modules["grabowski_mcp"] = fake_base
        sys.modules["grabowski_operator_core"] = fake_operator
        name = f"grabowski_audit_query_under_test_{id(self)}_{id(fake_base)}"
        spec = importlib.util.spec_from_file_location(
            name,
            ROOT / "src/grabowski_audit_query.py",
        )
        self.assertIsNotNone(spec)
        module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        assert spec and spec.loader
        sys.modules[name] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        def restore() -> None:
            if previous is None:
                sys.modules.pop("grabowski_mcp", None)
            else:
                sys.modules["grabowski_mcp"] = previous
            if previous_operator is None:
                sys.modules.pop("grabowski_operator_core", None)
            else:
                sys.modules["grabowski_operator_core"] = previous_operator
            sys.modules.pop(name, None)

        self.addCleanup(restore)
        return module

    def _components(self):
        old_records = [
            {
                "audit_schema_version": 2,
                "operation": "resource-acquire",
                "owner_id": "operator:alpha",
                "resource_keys": ["repo:/srv/example"],
                "timestamp_unix": 10,
                "record_sha256": "1" * 64,
                "secret_token": "must-not-project",
            },
            {
                "audit_schema_version": 2,
                "operation": "task-start",
                "task_id": "task-1",
                "unit": "grabowski-task-task-1.service",
                "resource_keys": ["repo:/srv/example"],
                "timestamp_unix": 20,
                "record_sha256": "2" * 64,
            },
        ]
        active_records = [
            {
                "audit_schema_version": 2,
                "operation": "task-complete",
                "task_id": "task-1",
                "unit": "grabowski-task-task-1.service",
                "returncode": 0,
                "timestamp_unix": 30,
                "record_sha256": "3" * 64,
            },
            {
                "audit_schema_version": 2,
                "operation": "task-start",
                "task_id": "task-2",
                "resource_keys": ["repo:/srv/other"],
                "requested_resource_keys": ["repo:/srv/example"],
                "launcher_outcome_unknown": True,
                "timestamp_unix": 40,
                "record_sha256": "4" * 64,
            },
        ]
        # Runtime chain reader returns active -> predecessor; snapshot normalizes oldest first.
        return [
            _component("/tmp/grabowski-audit-test/write-audit.jsonl", active_records),
            _component("/tmp/grabowski-audit-test/audit-segments/old.jsonl", old_records),
        ]

    def test_module_registers_three_read_only_audit_tools(self) -> None:
        module = self._load_module(self._components())
        self.assertEqual(
            set(module.mcp.tools),
            {"grabowski_audit_query", "grabowski_audit_trace", "grabowski_audit_analyze"},
        )

    def test_public_tools_require_audit_read_capability(self) -> None:
        module = self._load_module(self._components())
        module.grabowski_audit_query({}, limit=1)
        module.grabowski_audit_trace("task_id", "task-1", limit=1)
        module.grabowski_audit_analyze({}, top=1)
        self.assertEqual(
            module.base.required_capabilities,
            ["audit_read", "audit_read", "audit_read"],
        )

    def test_snapshot_uses_verification_cache_without_dropping_archived_records(self) -> None:
        module = self._load_module(self._components())
        projection = module.build_audit_projection()

        self.assertEqual(module.base.read_chain_calls, [
            {"use_segment_cache": True, "retain_verified_segment_data": False}
        ])
        self.assertEqual(projection["source"]["total_records"], 4)
        self.assertEqual(projection["items"][0]["record"]["operation"], "resource-acquire")
        self.assertEqual(projection["items"][-1]["record"]["task_id"], "task-2")

    def test_projection_is_oldest_first_hash_bound_and_safe_field_only(self) -> None:
        module = self._load_module(self._components())
        projection = module.build_audit_projection()

        self.assertEqual(projection["authority"], "derived_from_verified_audit_chain")
        self.assertEqual(projection["source"]["archived_segment_count"], 1)
        self.assertEqual(projection["items"][0]["evidence"]["global_ordinal"], 1)
        self.assertEqual(projection["items"][-1]["evidence"]["global_ordinal"], 4)
        self.assertEqual(projection["items"][0]["audit_ref"], f"audit-record-sha256:{'1' * 64}")
        self.assertNotIn("secret_token", projection["items"][0]["record"])
        self.assertEqual(len(projection["source"]["chain_content_sha256"]), 64)
        self.assertEqual(len(projection["source"]["chain_materialization_sha256"]), 64)
        self.assertIn("causality", projection["does_not_establish"])

    def test_query_filters_across_segments_and_orders_descending(self) -> None:
        module = self._load_module(self._components())
        result = module.query_audit({"operation": "task-start"}, order="desc")

        self.assertEqual(result["matched"], 2)
        self.assertTrue(result["matched_total_known"])
        self.assertEqual(result["items"][0]["record"]["task_id"], "task-2")
        self.assertEqual(result["items"][1]["record"]["task_id"], "task-1")

    def test_query_separates_held_and_requested_resource_semantics(self) -> None:
        module = self._load_module(self._components())
        compatibility = module.query_audit({"resource_key": "repo:/srv/example"})
        held = module.query_audit({"held_resource_key": "repo:/srv/example"})
        requested = module.query_audit({"requested_resource_key": "repo:/srv/example"})

        self.assertEqual(compatibility["matched"], 3)
        self.assertEqual(held["matched"], 2)
        self.assertEqual(requested["matched"], 1)
        self.assertEqual(requested["items"][0]["record"]["task_id"], "task-2")

    def test_query_supports_failure_signal_filter(self) -> None:
        module = self._load_module(self._components())
        result = module.query_audit({"has_failure_signal": True})

        self.assertEqual(result["matched"], 1)
        self.assertEqual(result["items"][0]["record"]["task_id"], "task-2")

    def test_query_result_and_scan_limits_are_independent_and_explicit(self) -> None:
        module = self._load_module(self._components())
        result = module.query_audit({}, limit=1)
        self.assertEqual(result["matched"], 4)
        self.assertEqual(result["returned"], 1)
        self.assertTrue(result["result_truncated"])
        self.assertFalse(result["scan"]["scan_truncated"])

        module.MAX_SCAN_RECORDS = 2
        bounded = module.query_audit({}, limit=10, order="asc")
        self.assertEqual(bounded["scan"]["scanned_records"], 2)
        self.assertTrue(bounded["scan"]["scan_truncated"])
        self.assertFalse(bounded["matched_total_known"])
        self.assertTrue(bounded["truncated"])

    def test_query_limit_is_bounded(self) -> None:
        module = self._load_module(self._components())
        with self.assertRaisesRegex(ValueError, "limit must be between"):
            module.query_audit({}, limit=201)

    def test_trace_is_one_hop_and_labels_typed_shared_correlations(self) -> None:
        module = self._load_module(self._components())
        result = module.trace_audit("task_id", "task-1")

        self.assertEqual(result["seed_count"], 2)
        self.assertEqual(result["seed_count_used"], 2)
        self.assertEqual(result["matched"], 3)
        first = result["items"][0]
        self.assertFalse(first["trace"]["direct_anchor_match"])
        self.assertIn("held_resource_key:repo:/srv/example", first["trace"]["shared_correlations"])
        self.assertTrue(result["items"][1]["trace"]["direct_anchor_match"])
        self.assertIn("causality_between_correlated_records", result["does_not_establish"])

    def test_trace_requested_resource_anchor_does_not_promote_to_held_relation(self) -> None:
        module = self._load_module(self._components())
        result = module.trace_audit("requested_resource_key", "repo:/srv/example")

        self.assertEqual(result["seed_count"], 1)
        self.assertEqual(result["matched"], 1)
        self.assertIn(
            "requested_resource_key:repo:/srv/example",
            result["items"][0]["trace"]["shared_correlations"],
        )
        self.assertNotIn(
            "held_resource_key:repo:/srv/example",
            result["items"][0]["trace"]["shared_correlations"],
        )

    def test_trace_missing_anchor_returns_empty_without_inventing_links(self) -> None:
        module = self._load_module(self._components())
        result = module.trace_audit("task_id", "missing-task")

        self.assertEqual(result["seed_count"], 0)
        self.assertEqual(result["matched"], 0)
        self.assertEqual(result["correlation_tokens"], {})
        self.assertFalse(result["correlation_tokens_truncated"])
        self.assertEqual(result["correlation_token_omissions"], {})

    def test_trace_reports_correlation_token_truncation(self) -> None:
        records = []
        for index in range(70):
            records.append(
                {
                    "audit_schema_version": 2,
                    "operation": "task-start",
                    "task_id": "wide-task",
                    "resource_keys": [f"repo:/srv/{index:02d}"],
                    "record_sha256": f"{index + 1:064x}",
                }
            )
        module = self._load_module(
            [_component("/tmp/grabowski-audit-test/write-audit.jsonl", records)]
        )
        result = module.trace_audit("task_id", "wide-task", limit=10)

        self.assertTrue(result["correlation_tokens_truncated"])
        self.assertEqual(result["correlation_token_omissions"], {"held_resource_key": 6})
        self.assertEqual(len(result["correlation_tokens"]["held_resource_key"]), 64)
        self.assertTrue(result["correlation_incomplete"])

    def test_trace_bounds_broad_seed_expansion(self) -> None:
        records = [
            {
                "operation": "task-start",
                "owner_id": "operator:wide",
                "task_id": f"task-{index}",
                "resource_keys": [f"repo:/srv/{index}"],
                "record_sha256": f"{index + 1:064x}",
            }
            for index in range(5)
        ]
        module = self._load_module(
            [_component("/tmp/grabowski-audit-test/write-audit.jsonl", records)]
        )
        module.MAX_TRACE_SEEDS = 2
        result = module.trace_audit("owner_id", "operator:wide")

        self.assertEqual(result["seed_count"], 5)
        self.assertEqual(result["seed_count_used"], 2)
        self.assertTrue(result["seed_truncated"])
        self.assertTrue(result["correlation_incomplete"])
        self.assertEqual(result["matched"], 5)

    def test_bounded_top_counter_compacts_lazy_heap(self) -> None:
        module = self._load_module([])
        counter = module._BoundedTopCounter(8)
        for index in range(1000):
            counter.add(f"value-{index}")

        self.assertEqual(len(counter._entries), 8)
        self.assertLessEqual(len(counter._minimum_heap), counter.capacity * 4)
        self.assertEqual(counter.evictions, 992)

    def test_analysis_counts_typed_resources_and_failure_signals(self) -> None:
        module = self._load_module(self._components())
        result = module.analyze_audit()

        self.assertEqual(result["record_count"], 4)
        self.assertEqual(result["time_range_unix"], {"minimum": 10, "maximum": 40})
        self.assertEqual(result["signals"]["failure_signal_count"], 1)
        self.assertEqual(result["signals"]["launcher_outcome_unknown_count"], 1)
        operation_counts = {entry["value"]: entry["count"] for entry in result["top_operations"]}
        self.assertEqual(operation_counts["task-start"], 2)
        held_counts = {entry["value"]: entry["count"] for entry in result["top_resource_keys"]}
        requested_counts = {
            entry["value"]: entry["count"]
            for entry in result["top_requested_resource_keys"]
        }
        self.assertEqual(held_counts["repo:/srv/example"], 2)
        self.assertEqual(requested_counts["repo:/srv/example"], 1)
        self.assertIn("root_cause", result["does_not_establish"])

    def test_analysis_counter_is_bounded_and_discloses_approximation(self) -> None:
        records = [
            {
                "operation": f"operation-{index}",
                "record_sha256": f"{index + 1:064x}",
            }
            for index in range(80)
        ]
        module = self._load_module(
            [_component("/tmp/grabowski-audit-test/write-audit.jsonl", records)]
        )
        result = module.analyze_audit(top=1)

        self.assertTrue(result["top_values_approximate"])
        self.assertFalse(result["top_value_quality"]["operations"]["exact"])
        self.assertLessEqual(
            result["top_value_quality"]["operations"]["tracked_values"],
            64,
        )

    def test_source_segment_metadata_is_bounded(self) -> None:
        components = []
        for index in range(10):
            components.append(
                _component(
                    f"/tmp/grabowski-audit-test/segment-{9-index}.jsonl",
                    [{"operation": "x", "record_sha256": f"{index + 1:064x}"}],
                )
            )
        module = self._load_module(components)
        source = module.query_audit({}, limit=1)["source"]

        self.assertEqual(source["segment_count"], 10)
        self.assertEqual(len(source["segments"]), module.MAX_SEGMENT_SAMPLE)
        self.assertTrue(source["segments_truncated"])
        self.assertEqual(source["segment_omissions"], 2)

    def test_projection_reports_allowlisted_schema_mismatch_without_exposing_value(self) -> None:
        records = [
            {
                "operation": "resource-acquire",
                "resource_keys": [{"secret": "must-not-project"}],
                "record_sha256": "a" * 64,
            }
        ]
        module = self._load_module(
            [_component("/tmp/grabowski-audit-test/write-audit.jsonl", records)]
        )
        item = module.query_audit({}, limit=1)["items"][0]

        self.assertNotIn("resource_keys", item["record"])
        self.assertTrue(item["evidence"]["projection_schema_mismatch"])
        self.assertEqual(item["evidence"]["projection_omitted_fields"], ["resource_keys"])

    def test_lazy_archived_hash_drift_fails_closed(self) -> None:
        components = self._components()
        archived_path, archived_data, archived_status = components[1]
        changed = archived_data + b"{}\n"
        override_status = dict(archived_status)
        override_status["records"] = archived_status["records"] + 1
        module = self._load_module(
            components,
            lazy_overrides={archived_path: (changed, override_status)},
        )

        with self.assertRaisesRegex(ValueError, "sha256-mismatch-after-snapshot"):
            module.query_audit({}, order="asc")

    def test_equal_time_window_and_unicode_operation_prefix_are_supported(self) -> None:
        records = [
            {
                "operation": "überblick-start",
                "timestamp_unix": 50,
                "record_sha256": "b" * 64,
            }
        ]
        module = self._load_module(
            [_component("/tmp/grabowski-audit-test/write-audit.jsonl", records)]
        )
        result = module.query_audit(
            {"operation_prefix": "über", "since_unix": 50, "until_unix": 50}
        )
        self.assertEqual(result["matched"], 1)

    def test_unsupported_filter_and_anchor_fail_closed(self) -> None:
        module = self._load_module(self._components())
        with self.assertRaisesRegex(ValueError, "Unsupported audit query filter"):
            module.query_audit({"secret_token": "x"})
        with self.assertRaisesRegex(ValueError, "filters must be an object"):
            module.query_audit([])
        with self.assertRaisesRegex(ValueError, "filters must be an object"):
            module.analyze_audit([])
        with self.assertRaisesRegex(ValueError, "anchor_kind"):
            module.trace_audit("host", "heim-pc")

    def test_filter_validation_is_strict_even_for_empty_chain(self) -> None:
        module = self._load_module([])
        with self.assertRaisesRegex(ValueError, "Unsupported audit query filter"):
            module.query_audit({"unknown": "value"})
        with self.assertRaisesRegex(ValueError, "exactly 64 lowercase hexadecimal"):
            module.query_audit({"record_sha256": "abc"})
        with self.assertRaisesRegex(ValueError, "less than or equal"):
            module.query_audit({"since_unix": 20, "until_unix": 10})
        with self.assertRaisesRegex(ValueError, "exactly 64 lowercase hexadecimal"):
            module.trace_audit("record_sha256", "ABC")

    def test_verified_chain_read_failure_propagates(self) -> None:
        module = self._load_module(read_error=ValueError("audit-segment-sha256-mismatch"))
        with self.assertRaisesRegex(ValueError, "audit-segment-sha256-mismatch"):
            module.query_audit({})


    def test_trace_external_evidence_is_opt_in_and_preserves_non_causality(self) -> None:
        module = self._load_module(self._components())
        plain = module.trace_audit("task_id", "task-1")
        self.assertNotIn("external_evidence", plain)

        module._cross_store_evidence = lambda items, limit: {
            "schema_version": 1,
            "kind": "grabowski_cross_store_evidence_projection",
            "authority": "derived_correlation_only",
            "evidence": [],
            "gaps": [],
            "truncated": False,
            "does_not_establish": ["causality", "root_cause"],
        }
        enriched = module.trace_audit(
            "task_id",
            "task-1",
            include_external_evidence=True,
            external_limit=3,
        )
        self.assertEqual(
            enriched["external_evidence"]["authority"],
            "derived_correlation_only",
        )
        self.assertIn("causality", enriched["external_evidence"]["does_not_establish"])
        self.assertIn(
            "causality_between_correlated_records",
            enriched["does_not_establish"],
        )

    def test_cross_store_projection_keeps_source_authorities_and_structured_gaps(self) -> None:
        module = self._load_module(self._components())
        module._task_external_evidence = lambda task_id: ([{
            "source": "task",
            "status": "verified",
            "authority": "authoritative_task_store",
            "relation": "direct_identity",
            "identity": {"task_id": task_id},
            "evidence_sha256": "a" * 64,
            "record": {"task_id": task_id},
        }], [{"source": "receipt", "status": "gap", "reason": "receipt_not_bound", "context": {"task_id": task_id}}])
        module._lease_external_evidence = lambda resource_key: ([{
            "source": "lease",
            "status": "verified",
            "authority": "authoritative_resource_lease_store",
            "relation": "direct_resource_identity",
            "identity": {"resource_key": resource_key},
            "evidence_sha256": "b" * 64,
            "record": {"resource_key": resource_key},
        }], [])
        module._deployment_external_evidence = lambda items: ([], [{
            "source": "deployment",
            "status": "gap",
            "reason": "no_deployment_identity_in_audit_seed",
            "context": {},
        }])

        result = module._cross_store_evidence(
            [
                {
                    "record": {
                        "task_id": "task-1",
                        "resource_keys": ["repo:/srv/example"],
                    }
                }
            ],
            limit=10,
        )
        self.assertEqual(result["authority"], "derived_correlation_only")
        self.assertEqual(
            {item["authority"] for item in result["evidence"]},
            {"authoritative_task_store", "authoritative_resource_lease_store"},
        )
        self.assertEqual(
            {gap["reason"] for gap in result["gaps"]},
            {"receipt_not_bound", "no_deployment_identity_in_audit_seed"},
        )
        self.assertIn("single_cross_store_truth", result["does_not_establish"])
        self.assertEqual(
            result["relation_semantics"]["temporal_proximity"],
            "not promoted to external evidence",
        )

    def test_deployment_evidence_requires_valid_complete_provenance(self) -> None:
        module = self._load_module([])
        items = [{"record": {"release_id": "release-1"}}]
        module.base._deployment_metadata = lambda: {
            "release_id": "release-1",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "provenance_valid": False,
        }

        evidence, gaps = module._deployment_external_evidence(items)

        self.assertEqual(evidence, [])
        self.assertEqual(gaps[0]["reason"], "deployment_metadata_unverifiable")
        self.assertFalse(gaps[0]["context"]["provenance_valid"])

    def test_deployment_evidence_binds_exact_identity_and_provenance(self) -> None:
        module = self._load_module([])
        items = [{"record": {"head": "b" * 40}}]
        module.base._deployment_metadata = lambda: {
            "release_id": "release-1",
            "repo_head": "b" * 40,
            "entrypoint_contract_sha256": "c" * 64,
            "source_sha256": "d" * 64,
            "runtime_input_sha256": "e" * 64,
            "runtime_lock_sha256": "f" * 64,
            "completion_status": "complete",
            "provenance_valid": True,
        }

        evidence, gaps = module._deployment_external_evidence(items)

        self.assertEqual(gaps, [])
        self.assertEqual(evidence[0]["status"], "verified")
        self.assertEqual(evidence[0]["relation"], "direct_identity")
        self.assertEqual(evidence[0]["identity"]["matched_values"], ["b" * 40])
        self.assertTrue(evidence[0]["record"]["provenance_valid"])

    def test_cross_store_external_limit_is_bounded(self) -> None:
        module = self._load_module(self._components())
        with self.assertRaisesRegex(ValueError, "external_limit must be between"):
            module._cross_store_evidence([], limit=0)
        with self.assertRaisesRegex(ValueError, "external_limit must be between"):
            module._cross_store_evidence([], limit=51)

    def test_external_trace_inputs_fail_before_audit_read(self) -> None:
        module = self._load_module(self._components())
        module.capture_verified_audit_snapshot = lambda _path=None: (_ for _ in ()).throw(
            AssertionError("audit read must not happen")
        )
        with self.assertRaisesRegex(ValueError, "include_external_evidence must be a boolean"):
            module.trace_audit("task_id", "task-1", include_external_evidence=1)
        with self.assertRaisesRegex(ValueError, "external_limit must be between"):
            module.trace_audit(
                "task_id",
                "task-1",
                include_external_evidence=True,
                external_limit=0,
            )

    def test_receipt_digest_drift_is_reported_as_gap(self) -> None:
        module = self._load_module([])
        import tempfile
        from contextlib import contextmanager

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outcomes = root / "outcomes"
            outcomes.mkdir()
            task_id = "task-drift"
            claimed = "a" * 64
            (outcomes / f"{task_id}.json").write_text(
                json.dumps(
                    {
                        "task_id": task_id,
                        "state": "completed",
                        "attempt": 1,
                        "receipt_sha256": claimed,
                    }
                ),
                encoding="utf-8",
            )
            row = {
                "task_id": task_id,
                "attempt": 1,
                "state": "completed",
                "unit": "unit",
                "updated_at_unix": 1,
                "lifecycle_receipt_sha256": claimed,
                "terminalization_sha256": "b" * 64,
                "chronik_outbox_enabled": 0,
            }

            class Connection:
                def execute(self, _query, _parameters):
                    return self

                def fetchone(self):
                    return row

            fake_tasks = types.ModuleType("grabowski_tasks")
            fake_tasks.TASK_DB = root / "tasks.sqlite3"
            fake_tasks.TASK_OUTCOMES_DIR = outcomes
            fake_tasks._preflight_task_store = lambda: "5"
            fake_tasks._task_archive_record = lambda value: {
                "task_id": value["task_id"],
                "attempt": value["attempt"],
                "state": value["state"],
            }
            fake_tasks._read_existing_outcome_receipt = (
                lambda _path, transition_sha256, allow_legacy: (_ for _ in ()).throw(
                    RuntimeError("receipt digest mismatch")
                )
            )
            fake_sqlite = types.ModuleType("grabowski_sqlite_store")

            @contextmanager
            def readonly_sqlite(_path):
                yield Connection()

            fake_sqlite.readonly_sqlite = readonly_sqlite
            previous_tasks = sys.modules.get("grabowski_tasks")
            previous_sqlite = sys.modules.get("grabowski_sqlite_store")
            sys.modules["grabowski_tasks"] = fake_tasks
            sys.modules["grabowski_sqlite_store"] = fake_sqlite
            try:
                evidence, gaps = module._task_external_evidence(task_id)
            finally:
                if previous_tasks is None:
                    sys.modules.pop("grabowski_tasks", None)
                else:
                    sys.modules["grabowski_tasks"] = previous_tasks
                if previous_sqlite is None:
                    sys.modules.pop("grabowski_sqlite_store", None)
                else:
                    sys.modules["grabowski_sqlite_store"] = previous_sqlite

        self.assertEqual(evidence[0]["source"], "task")
        self.assertNotIn("receipt", {item["source"] for item in evidence})
        self.assertEqual(
            [gap["reason"] for gap in gaps if gap["source"] == "receipt"],
            ["receipt_unverifiable"],
        )


    def test_receipt_reread_payload_must_recompute_to_bound_digest(self) -> None:
        module = self._load_module([])
        import tempfile
        from contextlib import contextmanager

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outcomes = root / "outcomes"
            outcomes.mkdir()
            task_id = "task-reread-drift"
            claimed = "a" * 64
            (outcomes / f"{task_id}.json").write_text(
                json.dumps(
                    {
                        "task_id": task_id,
                        "state": "forged-after-verifier",
                        "attempt": 99,
                        "receipt_sha256": claimed,
                    }
                ),
                encoding="utf-8",
            )
            row = {
                "task_id": task_id,
                "attempt": 1,
                "state": "completed",
                "unit": "unit",
                "updated_at_unix": 1,
                "lifecycle_receipt_sha256": claimed,
                "terminalization_sha256": "b" * 64,
                "chronik_outbox_enabled": 0,
            }

            class Connection:
                def execute(self, _query, _parameters):
                    return self

                def fetchone(self):
                    return row

            fake_tasks = types.ModuleType("grabowski_tasks")
            fake_tasks.TASK_DB = root / "tasks.sqlite3"
            fake_tasks.TASK_OUTCOMES_DIR = outcomes
            fake_tasks._preflight_task_store = lambda: "5"
            fake_tasks._task_archive_record = lambda value: {
                "task_id": value["task_id"],
                "attempt": value["attempt"],
                "state": value["state"],
            }
            fake_tasks._read_existing_outcome_receipt = (
                lambda _path, transition_sha256, allow_legacy: claimed
            )
            fake_sqlite = types.ModuleType("grabowski_sqlite_store")

            @contextmanager
            def readonly_sqlite(_path):
                yield Connection()

            fake_sqlite.readonly_sqlite = readonly_sqlite
            previous_tasks = sys.modules.get("grabowski_tasks")
            previous_sqlite = sys.modules.get("grabowski_sqlite_store")
            sys.modules["grabowski_tasks"] = fake_tasks
            sys.modules["grabowski_sqlite_store"] = fake_sqlite
            try:
                evidence, gaps = module._task_external_evidence(task_id)
            finally:
                if previous_tasks is None:
                    sys.modules.pop("grabowski_tasks", None)
                else:
                    sys.modules["grabowski_tasks"] = previous_tasks
                if previous_sqlite is None:
                    sys.modules.pop("grabowski_sqlite_store", None)
                else:
                    sys.modules["grabowski_sqlite_store"] = previous_sqlite

        self.assertNotIn("receipt", {item["source"] for item in evidence})
        self.assertEqual(
            [gap["reason"] for gap in gaps if gap["source"] == "receipt"],
            ["receipt_unverifiable"],
        )

    def test_chronik_evidence_uses_task_bound_state_root(self) -> None:
        module = self._load_module([])
        from contextlib import contextmanager

        task_id = "task-custom-root"
        expected_run_id = f"task-{task_id}-a2"
        custom_root = Path("/srv/custom-chronik-state")
        expected_path = custom_root / "grabowski" / "chronik-outbox" / f"grabowski_{expected_run_id}.jsonl"
        event_id = "sha256:" + "c" * 64
        event = {"source": {"run_id": expected_run_id}, "event_id": event_id, "kind": "agent.run.completed"}
        data = json.dumps(event).encode("utf-8") + b"\n"
        seen: dict[str, object] = {}
        row = {
            "task_id": task_id,
            "attempt": 2,
            "state": "completed",
            "unit": "unit",
            "updated_at_unix": 1,
            "lifecycle_receipt_sha256": None,
            "terminalization_sha256": None,
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": str(custom_root),
        }

        class Connection:
            def execute(self, _query, _parameters):
                return self

            def fetchone(self):
                return row

        fake_tasks = types.ModuleType("grabowski_tasks")
        fake_tasks.TASK_DB = Path("/tmp/tasks.sqlite3")
        fake_tasks.TASK_OUTCOMES_DIR = Path("/tmp/outcomes")
        fake_tasks._preflight_task_store = lambda: "5"
        fake_tasks._task_archive_record = lambda value: {
            "task_id": value["task_id"],
            "attempt": value["attempt"],
            "state": value["state"],
        }
        fake_sqlite = types.ModuleType("grabowski_sqlite_store")

        @contextmanager
        def readonly_sqlite(_path):
            yield Connection()

        fake_sqlite.readonly_sqlite = readonly_sqlite
        fake_chronik = types.ModuleType("grabowski_chronik")
        fake_chronik.MAX_BUNDLE_BYTES = 1024
        fake_chronik.run_id = lambda record: f"task-{record['task_id']}-a{record['attempt']}"
        fake_chronik.state_root = lambda record: Path(record["chronik_outbox_state_root"])

        def outbox_path(value, root=None):
            seen["root"] = root
            return root / "grabowski" / "chronik-outbox" / f"grabowski_{value['source']['run_id']}.jsonl"

        def read_regular_file(path, **_kwargs):
            seen["path"] = path
            return data, (1, 2, len(data), 3, 4)

        fake_chronik.outbox_path = outbox_path
        fake_chronik._read_regular_file = read_regular_file
        fake_chronik.event_id = lambda _event: event_id
        previous = {name: sys.modules.get(name) for name in ("grabowski_tasks", "grabowski_sqlite_store", "grabowski_chronik")}
        sys.modules["grabowski_tasks"] = fake_tasks
        sys.modules["grabowski_sqlite_store"] = fake_sqlite
        sys.modules["grabowski_chronik"] = fake_chronik
        try:
            evidence, gaps = module._task_external_evidence(task_id)
        finally:
            for name, value in previous.items():
                if value is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = value

        self.assertEqual(seen["root"], custom_root)
        self.assertEqual(seen["path"], expected_path)
        self.assertIn("chronik", {item["source"] for item in evidence})
        self.assertNotIn("chronik_source_unverifiable", {gap["reason"] for gap in gaps})

    def test_chronik_event_source_identity_drift_is_a_gap(self) -> None:
        module = self._load_module([])
        from contextlib import contextmanager

        task_id = "task-chronik-drift"
        row = {
            "task_id": task_id,
            "attempt": 1,
            "state": "completed",
            "unit": "unit",
            "updated_at_unix": 1,
            "lifecycle_receipt_sha256": None,
            "terminalization_sha256": None,
            "chronik_outbox_enabled": 1,
            "chronik_outbox_state_root": "/tmp/state",
        }

        class Connection:
            def execute(self, _query, _parameters):
                return self

            def fetchone(self):
                return row

        fake_tasks = types.ModuleType("grabowski_tasks")
        fake_tasks.TASK_DB = Path("/tmp/tasks.sqlite3")
        fake_tasks.TASK_OUTCOMES_DIR = Path("/tmp/outcomes")
        fake_tasks._preflight_task_store = lambda: "5"
        fake_tasks._task_archive_record = lambda value: {"task_id": value["task_id"], "attempt": value["attempt"]}
        fake_sqlite = types.ModuleType("grabowski_sqlite_store")

        @contextmanager
        def readonly_sqlite(_path):
            yield Connection()

        fake_sqlite.readonly_sqlite = readonly_sqlite
        fake_chronik = types.ModuleType("grabowski_chronik")
        fake_chronik.MAX_BUNDLE_BYTES = 1024
        fake_chronik.run_id = lambda record: f"task-{record['task_id']}-a{record['attempt']}"
        fake_chronik.state_root = lambda record: Path(record["chronik_outbox_state_root"])
        fake_chronik.outbox_path = lambda value, root=None: root / "grabowski" / "chronik-outbox" / f"grabowski_{value['source']['run_id']}.jsonl"
        stored_event_id = "sha256:" + "d" * 64
        drifted = {"source": {"run_id": "task-other-a1"}, "event_id": stored_event_id}
        raw_data = json.dumps(drifted).encode("utf-8") + b"\n"
        fake_chronik._read_regular_file = lambda *_args, **_kwargs: (raw_data, (1, 2, len(raw_data), 3, 4))
        fake_chronik.event_id = lambda _event: stored_event_id
        previous = {name: sys.modules.get(name) for name in ("grabowski_tasks", "grabowski_sqlite_store", "grabowski_chronik")}
        sys.modules["grabowski_tasks"] = fake_tasks
        sys.modules["grabowski_sqlite_store"] = fake_sqlite
        sys.modules["grabowski_chronik"] = fake_chronik
        try:
            evidence, gaps = module._task_external_evidence(task_id)
        finally:
            for name, value in previous.items():
                if value is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = value

        self.assertNotIn("chronik", {item["source"] for item in evidence})
        self.assertEqual(
            [gap["reason"] for gap in gaps if gap["source"] == "chronik"],
            ["chronik_source_unverifiable"],
        )

    def test_expired_lease_is_reported_as_inactive_gap(self) -> None:
        module = self._load_module([])
        from contextlib import contextmanager

        metadata_sha256 = hashlib.sha256(b"{}").hexdigest()
        row = {
            "resource_key": "repo:/srv/example",
            "owner_id": "owner",
            "purpose": "test",
            "acquired_at_unix": 1,
            "updated_at_unix": 2,
            "expires_at_unix": 10,
            "metadata_sha256": metadata_sha256,
            "metadata_json": "{}",
            "reclaimed_from_owner": None,
        }

        class Connection:
            def execute(self, _query, _parameters):
                return self

            def fetchone(self):
                return row

        fake_resources = types.ModuleType("grabowski_resources")
        fake_resources.RESOURCE_DB = Path("/tmp/resources.sqlite3")
        fake_resources._preflight_resource_store = lambda: "2"
        fake_resources.normalize_resource_key = lambda value: value
        fake_resources._public = lambda value: {key: item for key, item in dict(value).items() if key != "metadata_json"}
        fake_resources._row_metadata = lambda _value: {}
        fake_resources._metadata = lambda _value: ("{}", metadata_sha256)
        fake_resources._now = lambda: 20
        fake_sqlite = types.ModuleType("grabowski_sqlite_store")

        @contextmanager
        def readonly_sqlite(_path):
            yield Connection()

        fake_sqlite.readonly_sqlite = readonly_sqlite
        previous_resources = sys.modules.get("grabowski_resources")
        previous_sqlite = sys.modules.get("grabowski_sqlite_store")
        sys.modules["grabowski_resources"] = fake_resources
        sys.modules["grabowski_sqlite_store"] = fake_sqlite
        try:
            evidence, gaps = module._lease_external_evidence("repo:/srv/example")
        finally:
            if previous_resources is None:
                sys.modules.pop("grabowski_resources", None)
            else:
                sys.modules["grabowski_resources"] = previous_resources
            if previous_sqlite is None:
                sys.modules.pop("grabowski_sqlite_store", None)
            else:
                sys.modules["grabowski_sqlite_store"] = previous_sqlite

        self.assertEqual(evidence, [])
        self.assertEqual(gaps[0]["reason"], "lease_not_active")
        self.assertEqual(gaps[0]["context"]["expires_at_unix"], 10)


if __name__ == "__main__":
    unittest.main()
