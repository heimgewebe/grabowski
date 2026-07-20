from __future__ import annotations

import base64
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests.test_friction import FrictionFailureRuntimeTests
from tests.test_operator_contract import _load_operator_module
from tests.test_operator_v2_runtime import grabowski_mcp
from tests.test_read_surface import read_surface
from tests.test_tasks import LOCAL_HOST, _launcher, tasks


class ConsumerSurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.operator = _load_operator_module()

    def test_common_views_aliases_projection_and_cursor_integrity(self) -> None:
        self.assertEqual(self.operator._normalize_consumer_view("minimal"), "minimal")
        self.assertEqual(self.operator._normalize_consumer_view("standard"), "standard")
        self.assertEqual(self.operator._normalize_consumer_view("evidence"), "evidence")
        self.assertEqual(self.operator._normalize_consumer_view("concise"), "minimal")
        self.assertEqual(self.operator._normalize_consumer_view("full"), "evidence")
        with self.assertRaises(ValueError):
            self.operator._normalize_consumer_view("everything")

        payload = {
            "schema_version": 2,
            "view": "minimal",
            "data": [1, 2],
            "warnings": [{"code": "important"}],
            "recommended_next_action": "inspect",
            "does_not_establish": ["correctness"],
        }
        projected = self.operator._project_consumer_fields(
            payload,
            fields=["data"],
            required=(
                "schema_version",
                "view",
                "warnings",
                "recommended_next_action",
                "does_not_establish",
            ),
        )
        self.assertEqual(projected["data"], [1, 2])
        self.assertEqual(projected["warnings"], [{"code": "important"}])
        self.assertEqual(projected["recommended_next_action"], "inspect")
        self.assertIn("does_not_establish", projected)
        self.assertEqual(
            projected["projection"]["required_fields_preserved"],
            [
                "schema_version",
                "view",
                "warnings",
                "recommended_next_action",
                "does_not_establish",
            ],
        )
        with self.assertRaisesRegex(ValueError, "Unknown response field"):
            self.operator._project_consumer_fields(payload, fields=["missing"])

        cursor = self.operator._encode_consumer_cursor(
            "surface:minimal:filter-a",
            {"offset": 2},
        )
        self.assertEqual(
            self.operator._decode_consumer_cursor(cursor, "surface:minimal:filter-a"),
            {"offset": 2},
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.operator._decode_consumer_cursor(cursor, "surface:evidence:filter-a")
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.operator._decode_consumer_cursor(cursor, "surface:minimal:filter-b")
        tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        with self.assertRaises(ValueError):
            self.operator._decode_consumer_cursor(tampered, "surface:minimal:filter-a")
        with self.assertRaises(ValueError):
            self.operator._decode_consumer_cursor("not-base64!", "surface:minimal:filter-a")

        malformed = {"schema_version": 1, "scope": "surface:minimal:filter-a"}
        malformed["checksum"] = hashlib.sha256(
            self.operator._canonical_json_bytes(malformed)
        ).hexdigest()
        encoded = base64.urlsafe_b64encode(
            self.operator._canonical_json_bytes(malformed)
        ).decode("ascii").rstrip("=")
        with self.assertRaisesRegex(ValueError, "position is invalid"):
            self.operator._decode_consumer_cursor(encoded, "surface:minimal:filter-a")

        snapshot_cursor = self.operator._encode_consumer_cursor(
            "checkout-summary:minimal:old-snapshot",
            {"offset": 2},
        )
        with self.assertRaisesRegex(
            ValueError,
            self.operator.consumer_surface.CURSOR_SNAPSHOT_CHANGED_ERROR,
        ):
            self.operator.consumer_surface.decode_cursor(
                snapshot_cursor,
                "checkout-summary:minimal:new-snapshot",
                snapshot_scope="checkout-summary:minimal",
            )

    def test_status_views_and_required_warnings_survive_projection(self) -> None:
        policy = {
            "mode": "bounded-read-write",
            "active_profile": "trusted-owner",
            "profiles": {
                "observe": {},
                "maintain": {},
                "trusted-owner": {},
            },
            "forbidden_capabilities": [],
        }
        deployment = {
            "release_id": "release-1",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "manifest_parse_valid": True,
            "manifest_schema_valid": True,
            "repo_head_valid": True,
            "agent_instructions_identity_valid": True,
            "runtime_binding_valid": True,
            "environment_compatibility_valid": True,
            "provenance_valid": True,
            "artifact_integrity_valid": True,
        }
        contract = {
            "expected_tool_count": 120,
            "registered_tool_count": 120,
            "name_hash_contract": "sha256-json-sorted-utf8-v1",
            "expected_names_sha256": "c" * 64,
            "registered_names_sha256": "c" * 64,
            "runtime_matches_deployment_contract": True,
            "client_snapshot_observable": False,
            "client_snapshot": {
                "state": "missing",
                "observable": False,
                "fresh": False,
                "matched": False,
                "verification_model": "client-declared-server-compared-v1",
                "recommended_next_action": "bind the current connector snapshot",
            },
            "refresh_required_when_client_count_or_hash_differs": True,
        }
        values = {
            "read_roots": ["/tmp"],
            "write_roots": ["/tmp"],
            "write_excluded_roots": [],
            "max_risk_level": "high",
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(grabowski_mcp, "_load_policy", return_value=policy))
            stack.enter_context(
                mock.patch.object(
                    grabowski_mcp,
                    "_active_profile",
                    return_value={"name": "trusted-owner"},
                )
            )
            stack.enter_context(mock.patch.object(grabowski_mcp, "_deployment_metadata", return_value=deployment))
            stack.enter_context(
                mock.patch.object(
                    grabowski_mcp,
                    "_runtime_tool_contract_summary",
                    return_value=contract,
                )
            )
            stack.enter_context(
                mock.patch.object(
                    grabowski_mcp,
                    "_operator_system_overview",
                    return_value={
                        "schema_version": 1,
                        "operator_ready": False,
                        "readiness": {
                            "runtime_ready": True,
                            "connector_snapshot_ready": False,
                            "truth_model_ready": True,
                        },
                        "runtime": {"healthy": True},
                        "connector": {
                            "state": "missing",
                            "observable": False,
                            "fresh": False,
                            "matched": False,
                            "verification_model": "client-declared-server-compared-v1",
                        },
                        "tasks": {"available": True, "unknown_state_count": 0},
                        "leases": {"available": True, "active_count": 2},
                        "operator_obligations": {
                            "available": True,
                            "attention_count": 1,
                            "integrity_error_count": 0,
                        },
                        "component_errors": [],
                        "recommended_next_action": "bind the current connector snapshot",
                        "does_not_establish": [
                            "platform-enforced client snapshot identity"
                        ],
                    },
                )
            )
            stack.enter_context(
                mock.patch.object(
                    grabowski_mcp,
                    "_verify_audit_log",
                    return_value={
                        "valid": True,
                        "records": 5,
                        "last_record_sha256": "b" * 64,
                        "error": None,
                    },
                )
            )
            stack.enter_context(mock.patch.object(grabowski_mcp, "_kill_switch_state", return_value={"engaged": False}))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_effective_capabilities", return_value={"file_read"}))
            stack.enter_context(
                mock.patch.object(
                    grabowski_mcp,
                    "_profile_values",
                    side_effect=lambda _policy, key: values.get(key),
                )
            )
            stack.enter_context(mock.patch.object(
                grabowski_mcp,
                "_operator_relay_protocol",
                return_value={
                    "name": "Operator Relay v0",
                    "control_loop": ["typed_grabowski_tool"],
                    "routing_roles": {"shell_or_git_grip": "grabowski_task"},
                    "does_not_establish": ["automatic_merge"],
                    "workspace_execution_model": {
                        "external_agent_delegation": "adaptive_opt_in",
                        "automatic_patch_apply": False,
                        "automatic_winner_selection": False,
                    },
                },
            ))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_trusted_owner_enabled", return_value=True))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_capability_requirement_summary", return_value={"ok": True}))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_secret_root_values", return_value=[]))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_browser_profile_root_values", return_value=[]))
            stack.enter_context(mock.patch.object(grabowski_mcp, "_secret_export_root_values", return_value=[]))

            minimal = grabowski_mcp.grabowski_status(view="minimal")
            standard = grabowski_mcp.grabowski_status(view="standard")
            evidence = grabowski_mcp.grabowski_status(view="evidence")
            concise = grabowski_mcp.grabowski_status(view="concise")
            full = grabowski_mcp.grabowski_status(view="full")
            projected = grabowski_mcp.grabowski_status(
                view="minimal",
                fields=["service"],
            )

        self.assertEqual(minimal["view"], "minimal")
        self.assertNotIn("capabilities", minimal)
        self.assertEqual(
            minimal["agent_instructions"]["version"],
            "grabowski-agent-facing-contract-v1",
        )
        self.assertTrue(
            minimal["agent_instructions"]["runtime_matches_deployment_manifest"]
        )
        self.assertFalse(minimal["agent_instructions"]["client_compliance_observable"])
        self.assertEqual(standard["view"], "standard")
        self.assertIn("capabilities", standard)
        self.assertNotIn("deployment", standard)
        self.assertNotIn("routing_roles", standard["operating_protocol"])
        self.assertFalse(standard["operating_protocol"]["automatic_patch_apply"])
        self.assertFalse(standard["operating_protocol"]["automatic_winner_selection"])
        self.assertEqual(evidence["view"], "evidence")
        self.assertIn("deployment", evidence)
        self.assertIn("routing_roles", evidence["operating_protocol"])
        self.assertEqual(concise["view"], "minimal")
        self.assertEqual(full["view"], "evidence")
        warning_codes = {item["code"] for item in minimal["warnings"]}
        self.assertIn("client_snapshot_missing", warning_codes)
        self.assertIn("system_overview", standard)
        self.assertFalse(standard["system_overview"]["operator_ready"])
        self.assertEqual(
            "client-declared-server-compared-v1",
            minimal["tool_contract"]["client_snapshot"]["verification_model"],
        )
        self.assertTrue(minimal["healthy"])
        self.assertEqual(projected["service"], "grabowski-mcp")
        self.assertIn("warnings", projected)
        self.assertIn("recommended_next_action", projected)
        self.assertIn("does_not_establish", projected)
        with self.assertRaisesRegex(ValueError, "Unknown response field"):
            with mock.patch.object(grabowski_mcp, "_load_policy", return_value=policy):
                grabowski_mcp._project_status_fields(minimal, ["missing"])

    def test_status_refuses_valid_but_nonwritable_audit(self) -> None:
        policy = {
            "mode": "bounded-read-write",
            "active_profile": "trusted-owner",
            "profiles": {"trusted-owner": {}},
            "forbidden_capabilities": [],
        }
        deployment = {
            "release_id": "release-1",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "manifest_parse_valid": True,
            "manifest_schema_valid": True,
            "repo_head_valid": True,
            "agent_instructions_identity_valid": True,
            "runtime_binding_valid": True,
            "environment_compatibility_valid": True,
            "provenance_valid": True,
            "artifact_integrity_valid": True,
        }
        contract = {
            "expected_tool_count": 152,
            "registered_tool_count": 152,
            "runtime_matches_deployment_contract": True,
            "client_snapshot_observable": True,
            "client_snapshot": {
                "state": "matched",
                "observable": True,
                "fresh": True,
                "matched": True,
            },
        }
        audit = {
            "valid": True,
            "audit_writable": False,
            "audit_state": "storage_exhausted",
            "remaining_bytes": 0,
            "rotation_required": True,
            "active_bytes": 100,
            "rotation_threshold_bytes": 90,
            "last_record_sha256": "b" * 64,
        }
        with mock.patch.object(
            grabowski_mcp, "_load_policy", return_value=policy
        ), mock.patch.object(
            grabowski_mcp,
            "_active_profile",
            return_value={"name": "trusted-owner"},
        ), mock.patch.object(
            grabowski_mcp, "_deployment_metadata", return_value=deployment
        ), mock.patch.object(
            grabowski_mcp,
            "_runtime_tool_contract_summary",
            return_value=contract,
        ), mock.patch.object(
            grabowski_mcp, "_verify_audit_log", return_value=audit
        ), mock.patch.object(
            grabowski_mcp, "_kill_switch_state", return_value={"engaged": False}
        ):
            result = grabowski_mcp.grabowski_status(view="minimal")

        self.assertFalse(result["healthy"])
        warning_codes = {item["code"] for item in result["warnings"]}
        self.assertIn("audit_not_writable", warning_codes)
        self.assertIn("audit_rotation_required", warning_codes)
        self.assertEqual(
            result["recommended_next_action"],
            "restore audit writability before operator mutation",
        )

    def test_minimal_status_does_not_query_consolidated_overview(self) -> None:
        policy = {
            "mode": "bounded-read-write",
            "active_profile": "trusted-owner",
            "profiles": {"trusted-owner": {}},
            "forbidden_capabilities": [],
        }
        deployment = {
            "release_id": "release-1",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "manifest_parse_valid": True,
            "manifest_schema_valid": True,
            "repo_head_valid": True,
            "agent_instructions_identity_valid": True,
            "runtime_binding_valid": True,
            "environment_compatibility_valid": True,
            "provenance_valid": True,
            "artifact_integrity_valid": True,
        }
        contract = {
            "expected_tool_count": 140,
            "registered_tool_count": 140,
            "runtime_matches_deployment_contract": True,
            "client_snapshot_observable": False,
            "client_snapshot": {
                "state": "missing",
                "observable": False,
                "recommended_next_action": "bind snapshot",
            },
        }
        with mock.patch.object(
            grabowski_mcp, "_load_policy", return_value=policy
        ), mock.patch.object(
            grabowski_mcp,
            "_active_profile",
            return_value={"name": "trusted-owner"},
        ), mock.patch.object(
            grabowski_mcp, "_deployment_metadata", return_value=deployment
        ), mock.patch.object(
            grabowski_mcp,
            "_runtime_tool_contract_summary",
            return_value=contract,
        ), mock.patch.object(
            grabowski_mcp,
            "_verify_audit_log",
            return_value={
                "valid": True,
                "records": 1,
                "last_record_sha256": "b" * 64,
                "error": None,
            },
        ), mock.patch.object(
            grabowski_mcp, "_kill_switch_state", return_value={"engaged": False}
        ), mock.patch.object(
            grabowski_mcp, "_operator_system_overview"
        ) as overview:
            result = grabowski_mcp.grabowski_status(view="minimal")

        overview.assert_not_called()
        self.assertEqual("bind snapshot", result["recommended_next_action"])
        self.assertNotIn("system_overview", result)

    def test_operator_system_overview_prioritizes_connector_and_compacts_components(self) -> None:
        fake_tasks = SimpleNamespace(
            grabowski_task_list=lambda **_kwargs: {
                "state_counts": {"running": 1, "failed": 2},
                "projection_counts": {
                    "active": 1,
                    "attention": 2,
                    "terminal": 2,
                },
                "projection_counts_overlap": True,
                "unknown_state_count": 0,
                "state_counts_complete": True,
            }
        )
        fake_resources = SimpleNamespace(
            count_resources=lambda **_kwargs: 3
        )
        fake_obligations = SimpleNamespace(
            list_obligations=lambda parameters: {
                "record_count": 1,
                "integrity_errors": [],
                "scan_truncated": False,
                "summary_only": parameters.get("summary_only"),
            }
        )
        with mock.patch.dict(
            "sys.modules",
            {
                "grabowski_tasks": fake_tasks,
                "grabowski_resources": fake_resources,
                "grabowski_operator_obligation": fake_obligations,
            },
        ):
            overview = grabowski_mcp._operator_system_overview(
                runtime_healthy=True,
                coding_agent_catalog={
                    "ready": True,
                    "source": "embedded-runtime",
                },
                client_snapshot={
                    "state": "missing",
                    "observable": False,
                    "fresh": False,
                    "matched": False,
                    "verification_model": "client-declared-server-compared-v1",
                    "recommended_next_action": "bind snapshot",
                },
            )

        self.assertFalse(overview["operator_ready"])
        self.assertEqual("bind snapshot", overview["recommended_next_action"])
        self.assertEqual(2, overview["tasks"]["projection_counts"]["attention"])
        self.assertEqual(3, overview["leases"]["active_count"])
        self.assertEqual(1, overview["operator_obligations"]["attention_count"])
        self.assertEqual([], overview["component_errors"])
        self.assertEqual(
            "target_required",
            overview["source_registry"]["github_ci"]["observation_state"],
        )
        self.assertEqual(
            "target_required",
            overview["source_registry"]["systemkatalog"]["observation_state"],
        )

    def test_operator_system_overview_prioritizes_invalid_coding_catalog(self) -> None:
        fake_tasks = SimpleNamespace(
            grabowski_task_list=lambda **_kwargs: {
                "state_counts": {},
                "projection_counts": {},
                "projection_counts_overlap": False,
                "unknown_state_count": 0,
                "state_counts_complete": True,
            }
        )
        fake_resources = SimpleNamespace(count_resources=lambda **_kwargs: 0)
        fake_obligations = SimpleNamespace(
            list_obligations=lambda _parameters: {
                "record_count": 0,
                "integrity_errors": [],
                "scan_truncated": False,
            }
        )
        with mock.patch.dict(
            "sys.modules",
            {
                "grabowski_tasks": fake_tasks,
                "grabowski_resources": fake_resources,
                "grabowski_operator_obligation": fake_obligations,
            },
        ):
            overview = grabowski_mcp._operator_system_overview(
                runtime_healthy=True,
                coding_agent_catalog={
                    "ready": False,
                    "error": "invalid catalog",
                },
                client_snapshot={
                    "state": "current",
                    "observable": True,
                    "fresh": True,
                    "matched": True,
                    "verification_model": "test",
                },
            )
        self.assertFalse(overview["operator_ready"])
        self.assertFalse(overview["readiness"]["coding_agent_catalog_ready"])
        self.assertEqual(
            "repair coding-agent catalog semantics before routed execution",
            overview["recommended_next_action"],
        )

    def test_task_pagination_has_no_duplicates_and_cursor_is_view_filter_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "state" / "tasks.sqlite3"
            resource_database = root / "state" / "resources.sqlite3"
            with mock.patch.object(tasks, "TASK_DB", database), mock.patch.object(
                tasks.resources,
                "RESOURCE_DB",
                resource_database,
            ), mock.patch.object(
                tasks.fleet,
                "fleet_host",
                return_value=LOCAL_HOST,
            ), mock.patch.object(
                tasks,
                "_dispatch",
                return_value=_launcher(),
            ), mock.patch.object(tasks.base, "_append_audit"), mock.patch.object(
                tasks,
                "_require_recovery_gate",
                return_value={"checked_at_unix": 1},
            ):
                created = [
                    tasks.grabowski_task_start(
                        "local",
                        ["/bin/echo", str(index)],
                        cwd=str(root),
                        runtime_seconds=60,
                    )["task"]
                    for index in range(3)
                ]
                tasks._set_state(created[0]["task_id"], "failed")

                ids: list[str] = []
                cursor = None
                first_cursor = None
                while True:
                    page = tasks.grabowski_task_list(
                        limit=1,
                        view="minimal",
                        cursor=cursor,
                    )
                    ids.extend(item["task_id"] for item in page["tasks"])
                    cursor = page["pagination"]["next_cursor"]
                    if first_cursor is None:
                        first_cursor = cursor
                    if cursor is None:
                        break
                self.assertEqual(len(ids), 3)
                self.assertEqual(len(set(ids)), 3)
                self.assertEqual(set(ids), {item["task_id"] for item in created})

                self.assertIsNotNone(first_cursor)
                with self.assertRaisesRegex(ValueError, "does not match"):
                    tasks.grabowski_task_list(
                        limit=1,
                        view="evidence",
                        cursor=first_cursor,
                    )
                with self.assertRaisesRegex(ValueError, "does not match"):
                    tasks.grabowski_task_list(
                        limit=1,
                        view="minimal",
                        state="running",
                        cursor=first_cursor,
                    )
                projected = tasks.grabowski_task_list(
                    limit=100,
                    view="minimal",
                    fields=["tasks"],
                )
                self.assertIn("warnings", projected)
                self.assertIn("recommended_next_action", projected)
                self.assertIn("does_not_establish", projected)
                self.assertTrue(projected["warnings"])
                with self.assertRaisesRegex(ValueError, "Unknown response field"):
                    tasks.grabowski_task_list(fields=["missing"])
                self.assertEqual(tasks.grabowski_task_list(view="concise")["view"], "minimal")
                self.assertEqual(tasks.grabowski_task_list(view="full")["view"], "evidence")

    def test_checkout_pagination_has_no_duplicates_and_cursor_is_view_bound(self) -> None:
        worktrees = [
            {
                "path": f"/repo/worktree-{index}",
                "head": str(index) * 40,
                "branch": f"branch-{index}",
                "detached": False,
                "bare": False,
                "prunable": index == 2,
                "matches_runtime": index == 0,
            }
            for index in range(3)
        ]
        context = {
            "repository": "/repo",
            "exists": True,
            "canonical_checkout": worktrees[0],
            "canonical_matches_runtime": False,
            "runtime_matching_worktrees": [worktrees[0]],
            "worktrees": worktrees,
            "command_returncode": 0,
        }
        with mock.patch.object(read_surface, "operator", self.operator), mock.patch.object(
            read_surface.base,
            "_deployment_metadata",
            return_value={"repo_head": "0" * 40},
        ), mock.patch.object(
            read_surface.runtime_extensions,
            "_worktree_context",
            return_value=context,
        ):
            paths: list[str] = []
            cursor = None
            first_cursor = None
            while True:
                page = read_surface.grabowski_checkout_summary(
                    view="minimal",
                    limit=1,
                    cursor=cursor,
                )
                paths.extend(item["path"] for item in page["worktrees"])
                cursor = page["pagination"]["next_cursor"]
                if first_cursor is None:
                    first_cursor = cursor
                if cursor is None:
                    break
            self.assertEqual(paths, sorted(item["path"] for item in worktrees))
            self.assertEqual(len(paths), len(set(paths)))
            self.assertIsNotNone(first_cursor)
            with self.assertRaisesRegex(ValueError, "does not match"):
                read_surface.grabowski_checkout_summary(
                    view="evidence",
                    limit=1,
                    cursor=first_cursor,
                )
            projected = read_surface.grabowski_checkout_summary(
                view="minimal",
                fields=["worktrees"],
            )
            self.assertIn("warnings", projected)
            self.assertIn("recommended_next_action", projected)
            self.assertIn("does_not_establish", projected)
            with self.assertRaisesRegex(ValueError, "Unknown response field"):
                read_surface.grabowski_checkout_summary(fields=["missing"])

    def test_friction_pagination_has_no_duplicates_and_cursor_is_view_bound(self) -> None:
        case = FrictionFailureRuntimeTests(methodName="runTest")
        module = case._load_module()
        module.operator = self.operator
        try:
            for index in range(3):
                module.record_friction_event(
                    kind="operator_bug",
                    surface="runtime",
                    operation=f"operation-{index}",
                    symptom=f"symptom-{index}",
                )
            ids: list[str] = []
            cursor = None
            first_cursor = None
            while True:
                page = module.friction_summary(
                    view="minimal",
                    limit=1,
                    cursor=cursor,
                )
                ids.extend(item["event_id"] for item in page["events"])
                cursor = page["pagination"]["next_cursor"]
                if first_cursor is None:
                    first_cursor = cursor
                if cursor is None:
                    break
            self.assertEqual(len(ids), 3)
            self.assertEqual(len(set(ids)), 3)
            self.assertIsNotNone(first_cursor)
            with self.assertRaisesRegex(ValueError, "does not match"):
                module.friction_summary(
                    view="evidence",
                    limit=1,
                    cursor=first_cursor,
                )
            standard = module.friction_summary(view="standard", limit=20)
            evidence = module.friction_summary(view="evidence", limit=20)
            self.assertIn("connector_transport_diagnostics", standard)
            self.assertNotIn(
                "decision_required_events",
                standard["failure_classification"],
            )
            self.assertNotIn("groups", standard["next_grip_proposals"])
            self.assertIn(
                "decision_required_events",
                evidence["failure_classification"],
            )
            self.assertIn("groups", evidence["next_grip_proposals"])
            projected = module.friction_summary(
                view="minimal",
                fields=["events"],
            )
            self.assertIn("warnings", projected)
            self.assertIn("recommended_next_action", projected)
            self.assertIn("does_not_establish", projected)
            with self.assertRaisesRegex(ValueError, "Unknown response field"):
                module.friction_summary(fields=["missing"])
        finally:
            case.doCleanups()

    def test_context_contract_uses_common_views_and_preserves_safety_fields(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "grabowski_runtime_extensions.py"
        ).read_text(encoding="utf-8")
        self.assertIn("selected_view = consumer_surface.normalize_view", source)
        self.assertIn('if selected_view in {"standard", "evidence"}:', source)
        self.assertIn('if selected_view == "evidence":', source)
        for field in (
            '"warnings"',
            '"known_gaps"',
            '"recommended_next_action"',
            '"does_not_establish"',
        ):
            self.assertIn(field, source)
        self.assertIn('"expected_tools_sha256"', source)
        self.assertIn('"expected_tool_count"', source)
        self.assertNotIn('"expected_tools": expected_tools', source)
        self.assertIn('["records_ref"] = "capabilities"', source)
        self.assertIn('for key in ("tool", "category", "risk_class")', source)


if __name__ == "__main__":
    unittest.main()
