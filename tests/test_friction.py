from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class FrictionLedgerContractTests(unittest.TestCase):
    def test_event_schema_is_strict_and_bounded(self) -> None:
        schema = json.loads((ROOT / "contracts/operator-friction-event.v1.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertLessEqual(schema["properties"]["operation"]["maxLength"], 2000)
        self.assertLessEqual(schema["properties"]["notes"]["maxItems"], 20)
        self.assertIn("platform_filter", schema["properties"]["kind"]["enum"])
        self.assertIn("connector_snapshot", schema["properties"]["kind"]["enum"])
        self.assertIn("connector_transport", schema["properties"]["kind"]["enum"])
        self.assertIn("chat_tool", schema["properties"]["surface"]["enum"])

    def test_source_registers_record_and_summary_tools(self) -> None:
        source = (ROOT / "src/grabowski_friction.py").read_text(encoding="utf-8")
        self.assertIn('name="grabowski_friction_record"', source)
        self.assertIn('name="grabowski_friction_summary"', source)
        self.assertIn('name="grabowski_friction_resolve"', source)
        self.assertIn('name="grabowski_connector_transport_diagnostics"', source)
        self.assertIn('MAX_TEXT_BYTES = 2000', source)
        self.assertIn('MAX_NOTE_COUNT = 20', source)
        self.assertIn('FAILURE_CLASSES = frozenset({', source)
        self.assertIn('def classify_friction_event', source)
        self.assertIn('def connector_transport_diagnostics', source)
        self.assertIn('def connector_transport_live_diagnostics', source)
        self.assertIn('connector_transport_diagnostics', source)
        self.assertIn('journal_transport_probes', source)
        self.assertIn('invalid_lines', source)
        self.assertIn('def _bounded_event', source)
        self.assertIn('operator._redact(text)', source)
        self.assertIn('base._require_mutations_enabled("friction_record")', source)
        self.assertNotIn('operator._require_operator_mutation("friction_record")', source)

    def test_decision_schema_is_strict_and_evidence_bound(self) -> None:
        schema = json.loads((ROOT / "contracts/operator-friction-decision.v1.schema.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertIn("deferred", schema["properties"]["status"]["enum"])
        self.assertIn("linked_to_task", schema["properties"]["status"]["enum"])
        self.assertIn("evidence_ref", schema["required"])
        self.assertIn("non_claims", schema["required"])

        self.assertEqual(
            set(schema["properties"]["status"]["enum"]),
            {"resolved", "superseded", "deferred", "accepted_risk", "wont_fix", "linked_to_task"},
        )
        self.assertEqual(
            schema["properties"]["non_claims"]["const"],
            [
                "does_not_prove_root_cause",
                "does_not_authorize_task_resume",
                "does_not_establish_merge_readiness",
                "does_not_rewrite_raw_friction_history",
                "does_not_make_a_linked_bureau_task_ready",
            ],
        )
        condition_statuses = {
            rule["if"]["properties"]["status"]["const"] for rule in schema["allOf"]
        }
        self.assertEqual(condition_statuses, {"deferred", "linked_to_task"})




class FrictionFailureRuntimeTests(unittest.TestCase):
    def _load_module(self):
        sys_mod = __import__("sys")
        types_mod = __import__("types")
        tempfile_mod = __import__("tempfile")
        util = __import__("importlib.util", fromlist=["spec_from_file_location", "module_from_spec"])
        temporary = tempfile_mod.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        fake_base = types_mod.ModuleType("grabowski_mcp")
        fake_base._append_audit = lambda payload: None
        fake_base._require_mutations_enabled = lambda capability: None
        fake_base.grabowski_status = lambda: {
            "deployment": {
                "completion_status": "complete",
                "repo_head": "abc",
                "source_identity_valid": True,
                "runtime_binding_valid": True,
                "environment_compatibility_valid": True,
                "provenance_valid": True,
            },
            "tool_contract": {
                "registered_tool_count": 99,
                "expected_tool_count": 99,
                "runtime_matches_deployment_contract": True,
                "client_snapshot_observable": False,
            },
            "kill_switch": {"engaged": False},
        }

        class FakeMCP:
            def tool(self, *args, **kwargs):
                return lambda function: function

        fake_operator = types_mod.ModuleType("grabowski_operator_core")
        fake_operator.mcp = FakeMCP()
        fake_operator.READ_ONLY = {}
        fake_operator.MUTATING = {}
        fake_operator.STATE_DIR = root / "state"
        fake_operator.HOME = root
        fake_operator._redact = lambda value: value
        fake_operator._require_operator_capability = lambda capability: None
        fake_operator._validate_unit = lambda unit: unit
        fake_operator._safe_environment = lambda: {}
        fake_operator._redact_argv = lambda argv: argv
        fake_operator._argv_hash = lambda argv: "argv-hash"
        fake_operator._redacted_command = lambda argv: " ".join(argv)
        fake_operator._limit = lambda text, max_bytes: (text, False)
        fake_operator._parse_show = lambda text: dict(
            line.split("=", 1) for line in text.splitlines() if "=" in line
        )
        fake_operator._normalize_consumer_view = lambda view, default="minimal": {
            "concise": "minimal", "full": "evidence"
        }.get(view or default, view or default)
        fake_operator._decode_consumer_cursor = lambda cursor, scope: None
        fake_operator._encode_consumer_cursor = lambda scope, position: "test-cursor"
        fake_operator._project_consumer_fields = lambda payload, **kwargs: payload

        old_base = sys_mod.modules.get("grabowski_mcp")
        old_core = sys_mod.modules.get("grabowski_operator_core")
        sys_mod.modules["grabowski_mcp"] = fake_base
        sys_mod.modules["grabowski_operator_core"] = fake_operator

        name = f"_gopt001_friction_{id(self)}"
        spec = util.spec_from_file_location(name, ROOT / "src/grabowski_friction.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = util.module_from_spec(spec)
        sys_mod.modules[name] = module
        spec.loader.exec_module(module)

        def restore_modules() -> None:
            if old_base is None:
                sys_mod.modules.pop("grabowski_mcp", None)
            else:
                sys_mod.modules["grabowski_mcp"] = old_base
            if old_core is None:
                sys_mod.modules.pop("grabowski_operator_core", None)
            else:
                sys_mod.modules["grabowski_operator_core"] = old_core
            sys_mod.modules.pop(name, None)

        self.addCleanup(restore_modules)
        module.FRICTION_LOG = root / "state" / "friction" / "events.jsonl"
        module.FRICTION_DECISION_LOG = root / "state" / "friction" / "decisions.jsonl"
        return module

    def test_classifies_and_keeps_corrupt_lines_bounded(self) -> None:
        module = self._load_module()
        self.assertEqual(
            module.classify_friction_event({"kind": "ci_contract", "symptom": "contract drift"}),
            "contract_error",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "ci_contract", "symptom": "expected red-phase"}),
            "expected_red_phase",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "fail_closed_gate", "symptom": "gate closed"}),
            "policy_gate",
        )
        self.assertEqual(
            module.classify_friction_event({"kind": "platform_filter", "symptom": "rejected"}),
            "platform_filter",
        )
        self.assertEqual(
            module.classify_friction_event(
                {
                    "kind": "execution_context",
                    "surface": "connector",
                    "symptom": "Server returned 502: upstream or external service error",
                }
            ),
            "connector_transport",
        )
        self.assertEqual(
            module.classify_friction_event(
                {
                    "kind": "operator_bug",
                    "surface": "recovery",
                    "symptom": "grabowski_recovery_status timed out",
                }
            ),
            "actionable_failure",
        )

        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "bug-1",
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "bounded operation",
                "symptom": "unexpected exception",
                "resolved": False,
            },
            {
                "event_id": "filter-1",
                "kind": "platform_filter",
                "surface": "chat_tool",
                "operation": "narrow operation",
                "symptom": "rejected",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "not json\n"
            + json.dumps(events[0], sort_keys=True)
            + "\n"
            + json.dumps(["not", "event"])
            + "\n"
            + json.dumps(events[1], sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["non_event_lines"], 1)
        self.assertEqual(summary["returned"], 2)
        classification = summary["failure_classification"]
        self.assertEqual(classification["authority"], "read_only_evidence")
        self.assertEqual(classification["by_failure_class"]["actionable_failure"], 1)
        self.assertEqual(classification["by_failure_class"]["platform_filter"], 1)
        self.assertEqual(classification["decision_required_count"], 2)
        self.assertIn("task_resume_permission", classification["does_not_establish"])
        self.assertNotIn("raw_lines", summary)
        self.assertNotIn("raw_lines", classification)

    def test_failure_class_config_is_consistent(self) -> None:
        module = self._load_module()
        self.assertEqual(set(module.FAILURE_CLASS_DECISIONS), module.FAILURE_CLASSES)
        self.assertLessEqual(module.ACTION_REQUIRED_FAILURE_CLASSES, module.FAILURE_CLASSES)
        self.assertEqual(
            module.classify_friction_event(
                {
                    "kind": "ci_contract",
                    "symptom": "expected red-phase superseded by PR 83",
                }
            ),
            "superseded",
        )

    def test_summary_limit_counts_recent_valid_events(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        old = {"event_id": "old", "kind": "operator_bug", "surface": "runtime"}
        first = {"event_id": "first", "kind": "platform_filter", "surface": "chat_tool"}
        second = {"event_id": "second", "kind": "ci_contract", "surface": "ci"}
        module.FRICTION_LOG.write_text(
            json.dumps(old, sort_keys=True)
            + "\n"
            + json.dumps(first, sort_keys=True)
            + "\n"
            + "not json\n"
            + json.dumps(["not", "event"])
            + "\n"
            + json.dumps(second, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        summary = module.friction_summary(view="evidence", limit=2)
        self.assertEqual(summary["limit_scope"], "recent_valid_events")
        self.assertEqual(summary["returned"], 2)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["non_event_lines"], 1)
        self.assertEqual(
            [event["event_id"] for event in summary["events"]],
            ["first", "second"],
        )

    def test_summary_events_are_bounded(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "event_id": "legacy",
            "kind": "foreign-kind",
            "surface": "foreign-surface",
            "operation": "legacy operation",
            "symptom": "x" * 400,
            "notes": ["private note body"],
            "resolved": False,
        }
        module.FRICTION_LOG.write_text(
            json.dumps(event, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary = module.friction_summary(view="evidence", limit=1)
        rendered = json.dumps(summary["events"], sort_keys=True)
        self.assertNotIn("private note body", rendered)
        self.assertEqual(summary["by_kind"]["unknown"], 1)
        self.assertEqual(summary["by_surface"]["unknown"], 1)
        self.assertLessEqual(len(summary["events"][0]["symptom"]), 240)
        self.assertEqual(summary["events"][0]["notes_count"], 1)


    def test_connector_transport_diagnostics_and_retry_policy_are_explicit(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "transport-1",
                "kind": "execution_context",
                "surface": "connector",
                "operation": "broad terminal run",
                "symptom": "ChatGPT connector returned 502 upstream/external service error",
                "resolved": False,
            },
            {
                "event_id": "transport-2",
                "kind": "connector_transport",
                "surface": "connector",
                "operation": "recovery status",
                "symptom": "streamable_http Received exception from stream after POST /mcp",
                "resolved": False,
            },
            {
                "event_id": "recovery-timeout",
                "kind": "operator_bug",
                "surface": "recovery",
                "operation": "recovery status",
                "symptom": "grabowski_recovery_status timed out once",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        summary = module.friction_summary(view="evidence", limit=10)
        classification = summary["failure_classification"]
        diagnostics = summary["connector_transport_diagnostics"]
        proposals = summary["next_grip_proposals"]

        self.assertEqual(classification["by_failure_class"]["connector_transport"], 2)
        self.assertEqual(classification["by_failure_class"]["actionable_failure"], 1)
        self.assertEqual(diagnostics["authority"], "read_only_diagnostic_guidance")
        self.assertEqual(diagnostics["event_count"], 2)
        self.assertEqual(diagnostics["unresolved_event_count"], 2)
        self.assertEqual(diagnostics["recent_event_ids"], ["transport-1", "transport-2"])
        self.assertEqual(diagnostics["split_retry_policy"]["read_only_retry_limit"], 1)
        self.assertIn("safe_mutation_retry", diagnostics["does_not_establish"])
        self.assertIn("bounded recent journal search", " ".join(diagnostics["recommended_bounded_probe"]))
        groups = {group["pattern"]: group for group in proposals["groups"]}
        self.assertTrue(groups["connector_transport"]["actionable_repeated"])
        recommendation = {item["pattern"]: item for item in proposals["recommendations"]}["connector_transport"]
        self.assertEqual(recommendation["title"], "Add connector transport diagnostics")
        self.assertEqual(recommendation["evidence_event_ids"], ["transport-1", "transport-2"])

    def test_connector_transport_history_bounds_pre_runtime_http_404_recovery(self) -> None:
        module = self._load_module()
        events = [
            {
                "event_id": "pre-runtime-404",
                "kind": "connector_transport",
                "surface": "connector",
                "operation": "runtime health",
                "symptom": "MCP tunnel returned HTTP 404; response_status=404 before any Grabowski receipt",
                "resolved": False,
            },
            {
                "event_id": "latency-only",
                "kind": "connector_transport",
                "surface": "connector",
                "operation": "runtime health",
                "symptom": "request completed after 404 ms",
                "resolved": False,
            },
        ]

        diagnostics = module.connector_transport_diagnostics(events)

        self.assertEqual(diagnostics["schema_version"], 2)
        self.assertEqual(diagnostics["historical_http_status_counts"], {"404": 1})
        self.assertIn(
            "not a time series or lifetime aggregate",
            diagnostics["historical_http_status_counts_semantics"],
        )
        recovery = diagnostics["pre_runtime_http_404_recovery"]
        self.assertEqual(recovery["authority"], "guidance_only")
        self.assertFalse(recovery["machine_enforced"])
        self.assertEqual(recovery["applicability"], "caller_must_establish")
        self.assertEqual(
            recovery["recommended_action"],
            "refresh_catalog_then_one_read_only_retry",
        )
        self.assertEqual(len(recovery["caller_must_establish"]), 2)
        self.assertEqual(recovery["catalog_refresh_limit"], 1)
        self.assertEqual(recovery["read_only_retry_limit"], 1)
        self.assertIn("stop before mutation", recovery["sequence"][-1])
        self.assertIn("not root-cause proof", recovery["success_semantics"])
        self.assertIn(
            "retry exactly one small typed read-only call",
            diagnostics["split_retry_policy"]["pre_runtime_http_404_rule"],
        )

    def test_explicit_http_status_parser_is_symmetric_deduplicated_and_bounded(self) -> None:
        module = self._load_module()
        cases = {
            "HTTP 302": [302],
            "http 404": [404],
            "Http status: 502": [502],
            "HTTP404": [404],
            "HTTP/1.1 502": [502],
            "HTTP/2 404": [404],
            "status=503": [503],
            "status: 404, status_code=200": [200, 404],
            "httpStatus: 404": [404],
            "statusCode=503": [503],
            "HTTP 404; response_status=404": [404],
            "request completed after 404 ms": [],
            "error 404 in comment": [],
            "version 4040": [],
            "SOMEHTTP 404": [],
            "MYHTTPSTATUS: 502": [],
            "HTTP404Handler": [],
            "status=404ms": [],
            "HTTP 999": [],
        }

        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(module._explicit_http_statuses({"msg": message}), expected)

    def test_explicit_http_status_parser_accepts_common_structured_key_styles(self) -> None:
        module = self._load_module()
        payload = {
            "statusCode": 200,
            "response": {"httpStatus": "404"},
            "http": {"responseCode": 503},
        }

        self.assertEqual(module._explicit_http_statuses(payload), [200, 404, 503])

    def test_connector_transport_live_diagnostics_captures_bounded_runtime_receipt(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "transport-1",
                "kind": "connector_transport",
                "surface": "connector",
                "operation": "broad terminal run",
                "symptom": "502 upstream/external service error after POST /mcp",
                "resolved": False,
            },
            {
                "event_id": "transport-2",
                "kind": "connector_transport",
                "surface": "connector",
                "operation": "status poll",
                "symptom": "streamable_http Received exception from stream",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        def fake_run(argv, *, timeout_seconds=30, max_output_bytes=131_072):
            if argv[0] == "systemctl":
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nNRestarts=0\n",
                    "stderr": "",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
            if argv[0] == "journalctl":
                records = [
                    {
                        "__REALTIME_TIMESTAMP": "1783717201502676",
                        "MESSAGE": json.dumps({
                            "time": "2026-07-10T00:00:01.502676+02:00",
                            "level": "INFO",
                            "component": "dispatcher",
                            "msg": "dispatcher forwarded command to MCP server",
                        }),
                    },
                    {
                        "__REALTIME_TIMESTAMP": "1783717202000000",
                        "MESSAGE": json.dumps({
                            "time": "2026-07-10T00:00:02+02:00",
                            "level": "ERROR",
                            "component": "dispatcher",
                            "msg": "Received exception from stream: 502 upstream/external service error",
                        }),
                    },
                ]
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "".join(json.dumps(record) + "\n" for record in records),
                    "stderr": "",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
            raise AssertionError(argv)

        module._run_diagnostic_command = fake_run

        diagnostics = module.connector_transport_live_diagnostics(limit=10, max_log_lines=25)

        self.assertEqual(diagnostics["authority"], "read_only_transport_diagnostic_receipt")
        self.assertEqual(diagnostics["friction_log"]["connector_transport_diagnostics"]["event_count"], 2)
        self.assertTrue(diagnostics["runtime_status"]["available"])
        self.assertEqual(
            diagnostics["service_statuses"]["grabowski-operator.service"]["properties"]["ActiveState"],
            "active",
        )
        self.assertEqual(diagnostics["schema_version"], 3)
        self.assertEqual(
            diagnostics["friction_log"]["connector_transport_diagnostics"]["schema_version"],
            2,
        )
        self.assertTrue(diagnostics["live_transport_errors_observed"])
        probe = diagnostics["journal_transport_probes"]["grabowski-operator.service"]
        self.assertEqual(probe["max_lines"], 25)
        self.assertEqual(probe["transport_error_count"], 1)
        self.assertEqual(probe["http_status_counts"], {"502": 1})
        self.assertEqual(probe["activity_counts"], {"forwarded_to_mcp": 1})
        self.assertEqual(probe["window_state"], "errors_without_later_activity")
        self.assertEqual(probe["post_error_activity_counts"], {})
        self.assertEqual(diagnostics["transport_window_state"], "errors_without_later_activity")
        self.assertEqual(diagnostics["planned_lifecycle_issue_count"], 0)
        self.assertIn("command_success_or_failure", diagnostics["does_not_establish"])
        self.assertIn("target state is re-read", diagnostics["recommended_next_policy"]["mutation_rule"])
        rendered = json.dumps(diagnostics, sort_keys=True)
        self.assertNotIn("host python[1]", rendered)

    def test_connector_transport_live_diagnostics_preserves_known_error_over_incomplete_peer(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.FRICTION_LOG.write_text("", encoding="utf-8")

        def fake_run(argv, *, timeout_seconds=30, max_output_bytes=131_072):
            if argv[0] == "systemctl":
                return {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nNRestarts=0\n",
                    "stderr": "",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
            if argv[0] == "journalctl":
                unit = argv[argv.index("--unit") + 1]
                if unit == "grabowski-operator.service":
                    record = {
                        "__REALTIME_TIMESTAMP": "100",
                        "MESSAGE": json.dumps({
                            "level": "ERROR",
                            "msg": "Received exception from stream: 502 upstream/external service error",
                        }),
                    }
                    return {
                        "returncode": 0,
                        "timed_out": False,
                        "stdout": json.dumps(record) + "\n",
                        "stderr": "",
                        "stdout_truncated": False,
                        "stderr_truncated": False,
                    }
                return {
                    "returncode": 1,
                    "timed_out": False,
                    "stdout": "",
                    "stderr": "journal unavailable",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
            raise AssertionError(argv)

        module._run_diagnostic_command = fake_run
        diagnostics = module.connector_transport_live_diagnostics(limit=1, max_log_lines=25)

        self.assertEqual(diagnostics["transport_error_count"], 1)
        self.assertEqual(diagnostics["transport_window_state"], "errors_without_later_activity")
        self.assertEqual(
            diagnostics["transport_window_state_by_unit"]["tunnel-client-grabowski.service"],
            "indeterminate_incomplete",
        )

    def test_connector_transport_probe_uses_journal_priority_for_plain_errors(self) -> None:
        module = self._load_module()
        record = {
            "__REALTIME_TIMESTAMP": "1783718211000000",
            "PRIORITY": "3",
            "MESSAGE": "Received exception from stream: 503 upstream/external service error",
        }
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": json.dumps(record) + "\n",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 1)
        self.assertEqual(probe["http_status_counts"], {"503": 1})
        self.assertIn("stream_exception", probe["error_domain_counts"])

    def test_connector_transport_probe_does_not_treat_latency_as_http_status(self) -> None:
        module = self._load_module()
        records = [
            {
                "PRIORITY": "6",
                "MESSAGE": json.dumps({
                    "time": "2026-07-10T23:16:50+02:00",
                    "level": "INFO",
                    "component": "dispatcher",
                    "msg": "Received exception from stream after 502 ms during recovered probe",
                }),
            },
            {
                "PRIORITY": "6",
                "MESSAGE": json.dumps({
                    "time": "2026-07-10T23:16:51+02:00",
                    "level": "INFO",
                    "component": "dispatcher",
                    "msg": "configured timeout=30 for connector diagnostics",
                }),
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe(
            "tunnel-client-grabowski.service",
            25,
        )

        self.assertEqual(probe["transport_error_count"], 0)
        self.assertEqual(probe["http_status_counts"], {})

    def test_connector_transport_probe_does_not_treat_fractional_timestamp_as_502(self) -> None:
        module = self._load_module()
        record = {
            "__REALTIME_TIMESTAMP": "1783718210502676",
            "MESSAGE": json.dumps({
                "time": "2026-07-10T23:16:50.50267652+02:00",
                "level": "INFO",
                "component": "dispatcher",
                "msg": "dispatcher forwarded command to MCP server",
            }),
        }
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": json.dumps(record) + "\n",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 0)
        self.assertEqual(probe["http_status_counts"], {})
        self.assertEqual(probe["activity_counts"], {"forwarded_to_mcp": 1})

    def test_connector_transport_probe_separates_completed_stop_lifecycle_issues(self) -> None:
        module = self._load_module()
        invocation = "a" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "msg": "harpoon server stopped",
                    "error": {"kind": "shutdown"},
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "105",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "INFO",
                    "msg": "OnStop hook executing",
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "106",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "INFO",
                    "msg": "OnStop hook executed",
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 0)
        self.assertEqual(probe["window_state"], "no_errors")
        self.assertEqual(probe["completed_stop_invocation_count"], 1)
        self.assertEqual(probe["qualified_planned_stop_invocation_count"], 1)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 1)
        self.assertEqual(
            probe["planned_lifecycle_error_domain_counts"],
            {"reported_error": 1},
        )
        self.assertEqual(probe["planned_lifecycle_samples"][0]["invocation_id"], invocation)

    def test_connector_transport_probe_requires_visible_onstop_sequence(self) -> None:
        module = self._load_module()
        invocation = "9" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "msg": "harpoon server stopped",
                    "error": {"kind": "shutdown"},
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["completed_stop_invocation_count"], 1)
        self.assertEqual(probe["qualified_planned_stop_invocation_count"], 0)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 0)
        self.assertEqual(probe["transport_error_count"], 1)

    def test_connector_transport_probe_fails_closed_without_exact_completed_stop(self) -> None:
        module = self._load_module()
        invocation = "b" * 32
        error_record = {
            "__REALTIME_TIMESTAMP": "100",
            "_SYSTEMD_INVOCATION_ID": invocation,
            "MESSAGE": json.dumps({
                "level": "ERROR",
                "component": "dispatcher",
                "msg": "harpoon server stopped",
                "error": {"kind": "shutdown"},
            }),
        }
        markers = [
            None,
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "failed",
                "MESSAGE": "Stop failed.",
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": "c" * 32,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
        ]
        for marker_record in markers:
            with self.subTest(marker=marker_record):
                records = [error_record] + ([marker_record] if marker_record else [])
                module._run_diagnostic_command = lambda *args, **kwargs: {
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "".join(json.dumps(record) + "\n" for record in records),
                    "stderr": "",
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                }
                probe = module._journal_transport_probe(
                    "tunnel-client-grabowski.service",
                    25,
                )
                self.assertEqual(probe["transport_error_count"], 1)
                self.assertEqual(probe["planned_lifecycle_issue_count"], 0)
                self.assertEqual(probe["window_state"], "errors_without_later_activity")

    def test_connector_transport_probe_requires_shutdown_component_binding(self) -> None:
        module = self._load_module()
        invocation = "f" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "component": "controlplane",
                    "msg": "failed to release dispatcher worker pool",
                    "error": {"kind": "shutdown"},
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 1)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 0)

    def test_connector_transport_probe_keeps_unknown_error_in_completed_stop_invocation(self) -> None:
        module = self._load_module()
        invocation = "e" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "component": "dispatcher",
                    "msg": "failed to post response to control plane",
                    "error": {"kind": "temporary"},
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 1)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 0)
        self.assertEqual(probe["completed_stop_invocation_count"], 1)
        self.assertEqual(probe["qualified_planned_stop_invocation_count"], 0)

    def test_connector_transport_probe_reports_activity_after_real_error(self) -> None:
        module = self._load_module()
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": "d" * 32,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "component": "dispatcher",
                    "msg": "failed to post response to control plane",
                    "error": {"kind": "temporary"},
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "200",
                "MESSAGE": json.dumps({
                    "level": "INFO",
                    "component": "dispatcher",
                    "msg": "dispatcher forwarded command to MCP server",
                }),
            },
            {
                "__REALTIME_TIMESTAMP": "300",
                "MESSAGE": json.dumps({
                    "level": "INFO",
                    "component": "dispatcher",
                    "msg": "dispatcher acknowledged notification with control plane",
                }),
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["transport_error_count"], 1)
        self.assertEqual(probe["window_state"], "errors_followed_by_activity")
        self.assertEqual(
            probe["post_error_activity_counts"],
            {"control_plane_ack": 1, "forwarded_to_mcp": 1},
        )

    def test_connector_transport_probe_requires_complete_ordered_onstop_sequence(self) -> None:
        module = self._load_module()
        invocation = "8" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({"level": "INFO", "msg": "OnStop hook executing"}),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
            {
                "__REALTIME_TIMESTAMP": "120",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({"level": "INFO", "msg": "OnStop hook executed"}),
            },
            {
                "__REALTIME_TIMESTAMP": "105",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "msg": "harpoon server stopped",
                    "error": {"kind": "shutdown"},
                }),
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["completed_stop_invocation_count"], 1)
        self.assertEqual(probe["qualified_planned_stop_invocation_count"], 0)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 0)
        self.assertEqual(probe["transport_error_count"], 1)

    def test_connector_transport_probe_keeps_error_after_completed_stop(self) -> None:
        module = self._load_module()
        invocation = "7" * 32
        records = [
            {
                "__REALTIME_TIMESTAMP": "100",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({"level": "INFO", "msg": "OnStop hook executing"}),
            },
            {
                "__REALTIME_TIMESTAMP": "101",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({"level": "INFO", "msg": "OnStop hook executed"}),
            },
            {
                "__REALTIME_TIMESTAMP": "110",
                "MESSAGE_ID": module.SYSTEMD_STOP_COMPLETED_MESSAGE_ID,
                "USER_UNIT": "tunnel-client-grabowski.service",
                "USER_INVOCATION_ID": invocation,
                "JOB_TYPE": "stop",
                "JOB_RESULT": "done",
                "MESSAGE": "Stopped Grabowski MCP Tunnel.",
            },
            {
                "__REALTIME_TIMESTAMP": "120",
                "_SYSTEMD_INVOCATION_ID": invocation,
                "MESSAGE": json.dumps({
                    "level": "ERROR",
                    "msg": "harpoon server stopped",
                    "error": {"kind": "shutdown"},
                }),
            },
        ]
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": "".join(json.dumps(record) + "\n" for record in records),
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertEqual(probe["qualified_planned_stop_invocation_count"], 1)
        self.assertEqual(probe["planned_lifecycle_issue_count"], 0)
        self.assertEqual(probe["transport_error_count"], 1)

    def test_connector_transport_probe_marks_failed_or_invalid_window_incomplete(self) -> None:
        module = self._load_module()
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 1,
            "timed_out": False,
            "stdout": "not-json\n",
            "stderr": "journal unavailable",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertFalse(probe["journal_window_complete"])
        self.assertEqual(probe["window_state"], "indeterminate_incomplete")
        self.assertEqual(probe["invalid_json_records"], 1)

    def test_connector_transport_probe_marks_truncated_window_indeterminate(self) -> None:
        module = self._load_module()
        record = {
            "__REALTIME_TIMESTAMP": "100",
            "MESSAGE": json.dumps({
                "level": "INFO",
                "component": "dispatcher",
                "msg": "dispatcher forwarded command to MCP server",
            }),
        }
        module._run_diagnostic_command = lambda *args, **kwargs: {
            "returncode": 0,
            "timed_out": False,
            "stdout": json.dumps(record) + "\n",
            "stderr": "",
            "stdout_truncated": True,
            "stderr_truncated": False,
        }

        probe = module._journal_transport_probe("tunnel-client-grabowski.service", 25)

        self.assertFalse(probe["journal_window_complete"])
        self.assertEqual(probe["window_state"], "indeterminate_truncated")

    def test_connector_transport_live_diagnostics_bounds_log_lines(self) -> None:
        module = self._load_module()
        with self.assertRaises(ValueError):
            module.connector_transport_live_diagnostics(max_log_lines=0)
        with self.assertRaises(ValueError):
            module.connector_transport_live_diagnostics(max_log_lines=501)

    def test_next_grip_proposals_group_repeated_friction_patterns(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "gate-1",
                "kind": "fail_closed_gate",
                "surface": "github",
                "operation": "review gate",
                "symptom": "blocked gate missing external review evidence",
                "resolved": False,
            },
            {
                "event_id": "gate-2",
                "kind": "fail_closed_gate",
                "surface": "ci",
                "operation": "review gate",
                "symptom": "gate blocked waiting for self-review diff hash",
                "resolved": False,
            },
            {
                "event_id": "receipt-1",
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "captain receipt",
                "symptom": "missing receipt field for postflight",
                "resolved": False,
            },
            {
                "event_id": "receipt-2",
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "captain receipt",
                "symptom": "receipt missing field for rollback",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]

        self.assertEqual(proposals["authority"], "proposal_only")
        self.assertIn("bureau_queue_mutation", proposals["does_not_establish"])
        self.assertEqual(proposals["matched_event_count"], 4)
        self.assertEqual(proposals["unmatched_event_count"], 0)
        groups = {group["pattern"]: group for group in proposals["groups"]}
        self.assertEqual(groups["blocked_gates"]["unresolved"], 2)
        self.assertEqual(groups["missing_receipt_fields"]["unresolved"], 2)
        recommendations = {item["pattern"]: item for item in proposals["recommendations"]}
        self.assertEqual(recommendations["blocked_gates"]["recommendation_type"], "next_grip")
        self.assertEqual(recommendations["blocked_gates"]["unresolved"], 2)
        self.assertEqual(recommendations["blocked_gates"]["evidence_threshold"], 2)
        self.assertTrue(recommendations["blocked_gates"]["inherits_does_not_establish"])
        repair = recommendations["blocked_gates"]["repair_contract"]
        self.assertEqual(repair["schema_version"], 1)
        self.assertEqual(repair["authority"], "evidence_preparation_only")
        self.assertEqual(repair["preferred_route"], "explicit_preflight")
        self.assertIn("live leases, dirty state and running work", repair["required_evidence"])
        self.assertIn("no unchanged retry", repair["retry_policy"])
        self.assertEqual(
            repair["post_state_readback"],
            "mandatory and bound to the same target identity",
        )
        self.assertIn("policy_bypass", repair["does_not_establish"])
        self.assertEqual(
            recommendations["blocked_gates"]["evidence_event_ids"],
            ["gate-1", "gate-2"],
        )
        minimal = module.friction_summary(view="minimal", limit=10)
        compact = {
            item["pattern"]: item
            for item in minimal["next_grip_proposals"]["recommendations"]
        }
        self.assertEqual(
            compact["blocked_gates"]["repair_contract"]["preferred_route"],
            "explicit_preflight",
        )
        repair["required_evidence"].append("caller mutation")
        repair["preparation_steps"].clear()
        repeated = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]
        repeated_repair = {
            item["pattern"]: item
            for item in repeated["recommendations"]
        }["blocked_gates"]["repair_contract"]
        self.assertNotIn("caller mutation", repeated_repair["required_evidence"])
        self.assertTrue(repeated_repair["preparation_steps"])
        self.assertEqual(
            recommendations["missing_receipt_fields"]["recommendation_type"],
            "small_bureau_task",
        )
        self.assertFalse(proposals["no_action"]["recommended"])

    def test_next_grip_proposals_require_repeated_unresolved_evidence(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "event_id": "snapshot-1",
            "kind": "connector_snapshot",
            "surface": "connector",
            "operation": "tool snapshot",
            "symptom": "stale snapshot after runtime refresh",
            "resolved": False,
        }
        module.FRICTION_LOG.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]

        self.assertEqual(proposals["recommendations"], [])
        self.assertFalse(proposals["has_recommendations"])
        self.assertTrue(proposals["no_action"]["recommended"])
        groups = {group["pattern"]: group for group in proposals["groups"]}
        self.assertFalse(groups["stale_snapshots"]["actionable_repeated"])
        self.assertEqual(groups["stale_snapshots"]["evidence_event_ids"], ["snapshot-1"])

    def test_next_grip_recommendations_use_unresolved_evidence_ids(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "gate-1",
                "kind": "fail_closed_gate",
                "surface": "github",
                "operation": "review gate",
                "symptom": "gate blocked but already resolved",
                "resolved": True,
            },
            {
                "event_id": "gate-2",
                "kind": "fail_closed_gate",
                "surface": "ci",
                "operation": "review gate",
                "symptom": "blocked gate already triaged",
                "resolved": True,
            },
            {
                "event_id": "gate-3",
                "kind": "fail_closed_gate",
                "surface": "github",
                "operation": "review gate",
                "symptom": "blocked gate missing external review",
                "resolved": False,
            },
            {
                "event_id": "gate-4",
                "kind": "fail_closed_gate",
                "surface": "ci",
                "operation": "review gate",
                "symptom": "gate blocked missing current review",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]
        groups = {group["pattern"]: group for group in proposals["groups"]}
        recommendation = {item["pattern"]: item for item in proposals["recommendations"]}["blocked_gates"]

        self.assertEqual(groups["blocked_gates"]["evidence_event_ids"], ["gate-1", "gate-2", "gate-3", "gate-4"])
        self.assertEqual(groups["blocked_gates"]["unresolved_evidence_event_ids"], ["gate-3", "gate-4"])
        self.assertEqual(recommendation["evidence_event_ids"], ["gate-3", "gate-4"])

    def test_next_grip_proposals_do_not_trigger_on_broad_tool_words_alone(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "argv-1",
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "debug output",
                "symptom": "printed argv for diagnostics",
                "resolved": False,
            },
            {
                "event_id": "codex-1",
                "kind": "operator_bug",
                "surface": "github",
                "operation": "comment scan",
                "symptom": "codex mentioned a neutral note",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]

        self.assertEqual(proposals["recommendations"], [])
        self.assertEqual(proposals["matched_event_count"], 0)
        self.assertEqual(proposals["unmatched_event_count"], 2)
        self.assertTrue(proposals["no_action"]["recommended"])

    def test_next_grip_proposals_allow_multi_pattern_event_without_double_matching_event_count(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "multi-1",
                "kind": "fail_closed_gate",
                "surface": "github",
                "operation": "review gate",
                "symptom": "review loop blocked by gate evidence",
                "resolved": False,
            }
        ]
        module.FRICTION_LOG.write_text(json.dumps(events[0], sort_keys=True) + "\n", encoding="utf-8")

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]
        groups = {group["pattern"]: group for group in proposals["groups"]}

        self.assertIn("blocked_gates", groups)
        self.assertIn("review_loops", groups)
        self.assertEqual(proposals["matched_event_count"], 1)
        self.assertEqual(proposals["unmatched_event_count"], 0)
        self.assertEqual(groups["blocked_gates"]["evidence_event_ids"], ["multi-1"])
        self.assertEqual(groups["review_loops"]["evidence_event_ids"], ["multi-1"])

    def test_next_grip_proposals_surface_missing_event_ids(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "captain receipt",
                "symptom": "missing receipt field for rollback",
                "resolved": False,
            },
            {
                "kind": "operator_bug",
                "surface": "runtime",
                "operation": "captain receipt",
                "symptom": "receipt missing field for postflight",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]
        group = {group["pattern"]: group for group in proposals["groups"]}["missing_receipt_fields"]
        recommendation = {item["pattern"]: item for item in proposals["recommendations"]}["missing_receipt_fields"]

        self.assertEqual(group["missing_event_id_count"], 2)
        self.assertEqual(group["unresolved_missing_event_id_count"], 2)
        self.assertEqual(group["unresolved_evidence_event_ids"], ["unknown", "unknown"])
        self.assertEqual(recommendation["missing_event_id_count"], 2)
        self.assertEqual(recommendation["evidence_event_ids"], ["unknown", "unknown"])

    def test_next_grip_proposals_emit_no_action_for_empty_events(self) -> None:
        module = self._load_module()

        proposals = module.propose_next_grip_from_friction([])

        self.assertEqual(proposals["groups"], [])
        self.assertEqual(proposals["recommendations"], [])
        self.assertEqual(proposals["matched_event_count"], 0)
        self.assertEqual(proposals["unmatched_event_count"], 0)
        self.assertFalse(proposals["has_recommendations"])
        self.assertTrue(proposals["no_action"]["recommended"])


    def test_next_grip_proposals_emit_no_action_for_resolved_repeated_noise(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "review-1",
                "kind": "ci_contract",
                "surface": "github",
                "operation": "external review loop",
                "symptom": "external review stale diff hash",
                "resolved": True,
            },
            {
                "event_id": "review-2",
                "kind": "ci_contract",
                "surface": "github",
                "operation": "self-review",
                "symptom": "review loop resolved by new evidence",
                "resolved": True,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        proposals = module.friction_summary(view="evidence", limit=10)["next_grip_proposals"]

        self.assertEqual(proposals["recommendation_count"], 0)
        self.assertTrue(proposals["no_action"]["recommended"])
        groups = {group["pattern"]: group for group in proposals["groups"]}
        self.assertTrue(groups["review_loops"]["repeated"])
        self.assertFalse(groups["review_loops"]["actionable_repeated"])


    def _write_closeout_events(self, module) -> None:
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": "filter-1",
                "recorded_at_unix": 1,
                "kind": "platform_filter",
                "surface": "github",
                "operation": "merge",
                "symptom": "blocked",
                "resolved": False,
            },
            {
                "event_id": "filter-2",
                "recorded_at_unix": 2,
                "kind": "platform_filter",
                "surface": "terminal",
                "operation": "push",
                "symptom": "blocked",
                "resolved": False,
            },
            {
                "event_id": "gate-1",
                "recorded_at_unix": 3,
                "kind": "fail_closed_gate",
                "surface": "runtime",
                "operation": "gate",
                "symptom": "fail closed",
                "resolved": False,
            },
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

    def test_private_reader_rechecks_actual_bytes_after_metadata_bound(self) -> None:
        module = self._load_module()
        path = module.FRICTION_LOG
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"abcd")
        real_fstat = module.os.fstat

        def understated_fstat(fd: int):
            metadata = real_fstat(fd)
            return type("Metadata", (), {"st_mode": metadata.st_mode, "st_size": 1})()

        with patch.object(module.os, "fstat", side_effect=understated_fstat):
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                module._read_private_text(path, max_bytes=2)

    def test_closeout_loader_bounds_bytes_and_all_nonempty_lines(self) -> None:
        module = self._load_module()
        path = module.FRICTION_DECISION_LOG
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * 33, encoding="utf-8")
        module.MAX_FRICTION_LEDGER_BYTES = 32
        with self.assertRaisesRegex(RuntimeError, "byte limit"):
            module._load_jsonl_records(path)

        module.MAX_FRICTION_LEDGER_BYTES = 1024
        path.write_text("not-json\nnot-json\nnot-json\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "line limit"):
            module._load_jsonl_records(path, maximum=2)

    def test_resolve_one_event_is_append_only_and_reduces_summary_noise(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        before = module.FRICTION_LOG.read_bytes()

        result = module.resolve_friction(
            event_id="filter-1",
            status="resolved",
            decision="Typed lifecycle grip now handles this operation.",
            evidence_ref="pr:heimgewebe/grabowski#152",
            resolved_by="chatgpt-grabowski",
        )

        self.assertEqual(result["appended_count"], 1)
        self.assertEqual(module.FRICTION_LOG.read_bytes(), before)
        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["schema_version"], 2)
        self.assertEqual(summary["unresolved"], 2)
        self.assertEqual(summary["resolution_counts"]["resolved"], 1)
        event = next(item for item in summary["events"] if item["event_id"] == "filter-1")
        self.assertEqual(event["resolution_status"], "resolved")
        self.assertEqual(event["closeout"]["evidence_ref"], "pr:heimgewebe/grabowski#152")
        self.assertEqual(summary["failure_classification"]["decision_required_count"], 2)

    def test_resolve_class_can_defer_recurring_failure_class(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)

        result = module.resolve_friction(
            failure_class="platform_filter",
            status="deferred",
            decision="Defer old platform-filter incidents after provider-neutral replacement.",
            evidence_ref="bureau:GRABOWSKI-OPERATOR-SURFACE-V1-T019",
            resolved_by="chatgpt-grabowski",
            reason="Historical incidents are retained but no longer require individual action.",
        )

        self.assertEqual(result["target_count"], 2)
        self.assertEqual(result["appended_count"], 2)
        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["resolution_counts"]["deferred"], 2)
        self.assertEqual(summary["unresolved"], 1)
        self.assertEqual(summary["failure_classification"]["decision_required_count"], 1)

    def test_class_closeout_is_bounded_and_reports_remaining_targets(self) -> None:
        module = self._load_module()
        module.FRICTION_LOG.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {
                "event_id": f"filter-{index:03d}",
                "recorded_at_unix": index,
                "kind": "platform_filter",
                "surface": "github",
                "operation": "merge",
                "symptom": "blocked",
                "resolved": False,
            }
            for index in range(module.MAX_FRICTION_CLOSEOUT_BATCH + 2)
        ]
        module.FRICTION_LOG.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )

        first = module.resolve_friction(
            failure_class="platform_filter",
            status="deferred",
            decision="Close one bounded batch.",
            evidence_ref="receipt:bulk-1",
            resolved_by="operator",
            reason="Bounded triage batch.",
        )
        self.assertEqual(first["target_count"], module.MAX_FRICTION_CLOSEOUT_BATCH)
        self.assertEqual(first["matched_target_count"], module.MAX_FRICTION_CLOSEOUT_BATCH + 2)
        self.assertTrue(first["targets_truncated"])
        self.assertEqual(first["remaining_target_count"], 2)
        self.assertEqual(module.friction_summary(view="evidence", limit=500)["unresolved"], 2)

        second = module.resolve_friction(
            failure_class="platform_filter",
            status="deferred",
            decision="Close the remaining bounded batch.",
            evidence_ref="receipt:bulk-2",
            resolved_by="operator",
            reason="Bounded triage batch.",
        )
        self.assertEqual(second["target_count"], 2)
        self.assertFalse(second["targets_truncated"])
        self.assertEqual(second["remaining_target_count"], 0)

    def test_summary_ignores_closeout_for_duplicate_raw_event_id(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        module.resolve_friction(
            event_id="filter-1",
            status="resolved",
            decision="Resolved before ledger duplication.",
            evidence_ref="receipt:before-duplicate",
            resolved_by="operator",
        )
        duplicate = {
            "event_id": "filter-1",
            "recorded_at_unix": 4,
            "kind": "platform_filter",
            "surface": "chat_tool",
            "operation": "merge",
            "symptom": "duplicate id",
            "resolved": False,
        }
        with module.FRICTION_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(duplicate, sort_keys=True) + "\n")

        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["unresolved"], 4)
        self.assertFalse(summary["event_log_integrity"]["integrity_valid"])
        self.assertEqual(summary["event_log_integrity"]["duplicate_event_ids"], ["filter-1"])
        duplicate_events = [event for event in summary["events"] if event["event_id"] == "filter-1"]
        self.assertEqual([event["resolution_status"] for event in duplicate_events], ["unresolved", "unresolved"])
        with self.assertRaisesRegex(RuntimeError, "duplicate event_id"):
            module.resolve_friction(
                event_id="filter-1",
                status="resolved",
                decision="Must remain blocked.",
                evidence_ref="receipt:duplicate",
                resolved_by="operator",
            )

    def test_duplicate_closeout_is_idempotent_but_conflict_is_rejected(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        kwargs = {
            "event_id": "filter-1",
            "status": "resolved",
            "decision": "Resolved by typed lifecycle.",
            "evidence_ref": "receipt:abc",
            "resolved_by": "operator",
        }
        first = module.resolve_friction(**kwargs)
        second = module.resolve_friction(**kwargs)
        self.assertEqual(first["appended_count"], 1)
        self.assertEqual(second["appended_count"], 0)
        self.assertEqual(second["already_recorded_count"], 1)
        with self.assertRaisesRegex(ValueError, "different closeout"):
            module.resolve_friction(**{**kwargs, "decision": "Conflicting decision."})

    def test_invalid_event_and_deferred_without_reason_are_rejected(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        with self.assertRaisesRegex(ValueError, "event_id not found"):
            module.resolve_friction(
                event_id="missing",
                status="resolved",
                decision="No such event.",
                evidence_ref="receipt:none",
                resolved_by="operator",
            )
        with self.assertRaisesRegex(ValueError, "requires reason"):
            module.resolve_friction(
                event_id="filter-1",
                status="deferred",
                decision="Later.",
                evidence_ref="bureau:TASK",
                resolved_by="operator",
            )

    def test_malformed_closeout_fails_closed_for_summary_and_mutation(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        module.FRICTION_DECISION_LOG.parent.mkdir(parents=True, exist_ok=True)
        module.FRICTION_DECISION_LOG.write_text(
            json.dumps({"event_id": "filter-1"}) + "\n",
            encoding="utf-8",
        )
        module.FRICTION_DECISION_LOG.chmod(0o600)

        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["unresolved"], 3)
        self.assertFalse(summary["decision_log"]["integrity_valid"])
        self.assertEqual(summary["decision_log"]["invalid_record_count"], 1)
        with self.assertRaisesRegex(RuntimeError, "decision log integrity"):
            module.resolve_friction(
                event_id="filter-2",
                status="resolved",
                decision="Would otherwise close the event.",
                evidence_ref="receipt:blocked",
                resolved_by="operator",
            )

    def test_conflicting_duplicate_closeouts_do_not_suppress_event(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        module.resolve_friction(
            event_id="filter-1",
            status="resolved",
            decision="Resolved by typed lifecycle.",
            evidence_ref="receipt:first",
            resolved_by="operator",
        )
        first = json.loads(module.FRICTION_DECISION_LOG.read_text(encoding="utf-8").splitlines()[0])
        conflict = {
            **first,
            "closeout_id": "b" * 32,
            "status": "deferred",
            "decision": "Conflicting decision.",
            "reason": "Later.",
        }
        with module.FRICTION_DECISION_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(conflict, sort_keys=True) + "\n")

        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["unresolved"], 3)
        self.assertFalse(summary["decision_log"]["integrity_valid"])
        self.assertEqual(summary["decision_log"]["conflicting_event_ids"], ["filter-1"])

    def test_linked_bureau_task_is_recorded_without_readiness_claim(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        result = module.resolve_friction(
            event_id="gate-1",
            status="linked_to_task",
            decision="Track the gate remediation in Bureau.",
            evidence_ref="bureau:GRABOWSKI-OPERATOR-SURFACE-V1-T020",
            resolved_by="operator",
            bureau_task_id="GRABOWSKI-OPERATOR-SURFACE-V1-T020",
        )
        self.assertEqual(result["appended_count"], 1)
        record = json.loads(module.FRICTION_DECISION_LOG.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(record["bureau_task_id"], "GRABOWSKI-OPERATOR-SURFACE-V1-T020")
        self.assertIn("does_not_make_a_linked_bureau_task_ready", record["non_claims"])

    def test_summary_ignores_closeout_with_failure_class_binding_mismatch(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        module.resolve_friction(
            event_id="filter-1",
            status="resolved",
            decision="valid before tamper",
            evidence_ref="receipt:binding",
            resolved_by="operator",
        )
        record = json.loads(module.FRICTION_DECISION_LOG.read_text(encoding="utf-8"))
        record["failure_class"] = "policy_gate"
        module.FRICTION_DECISION_LOG.write_text(json.dumps(record) + "\n", encoding="utf-8")
        module.FRICTION_DECISION_LOG.chmod(0o600)

        summary = module.friction_summary(view="evidence", limit=10)
        self.assertEqual(summary["unresolved"], 3)
        self.assertFalse(summary["event_log_integrity"]["integrity_valid"])
        self.assertEqual(
            summary["event_log_integrity"]["closeout_binding_mismatch_event_ids"],
            ["filter-1"],
        )
        with self.assertRaisesRegex(RuntimeError, "closeout binding mismatch"):
            module.resolve_friction(
                event_id="filter-2",
                status="resolved",
                decision="must remain blocked",
                evidence_ref="receipt:binding-block",
                resolved_by="operator",
            )

    def test_summary_read_rejects_event_log_symlink(self) -> None:
        module = self._load_module()
        target = module.FRICTION_LOG.parent / "summary-target.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{}\n", encoding="utf-8")
        module.FRICTION_LOG.symlink_to(target)
        with self.assertRaises(OSError):
            module.friction_summary(view="evidence", limit=10)

    def test_append_rejects_symlink_and_nonprivate_ledgers(self) -> None:
        module = self._load_module()
        target = module.FRICTION_LOG.parent / "target.jsonl"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")
        module.FRICTION_LOG.symlink_to(target)
        with self.assertRaises(OSError):
            module.record_friction_event(
                kind="operator_bug",
                surface="runtime",
                operation="symlink smoke",
                symptom="must fail closed",
            )

        module.FRICTION_LOG.unlink()
        module.FRICTION_LOG.write_text("", encoding="utf-8")
        module.FRICTION_LOG.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError, "private owner-controlled"):
            module.record_friction_event(
                kind="operator_bug",
                surface="runtime",
                operation="mode smoke",
                symptom="must fail closed",
            )

    def test_decision_lock_rejects_symlink(self) -> None:
        module = self._load_module()
        self._write_closeout_events(module)
        lock_path = Path(f"{module.FRICTION_DECISION_LOG}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        target = lock_path.parent / "lock-target"
        target.write_text("", encoding="utf-8")
        lock_path.symlink_to(target)
        with self.assertRaises(OSError):
            module.resolve_friction(
                event_id="filter-1",
                status="resolved",
                decision="must not follow lock symlink",
                evidence_ref="receipt:lock-smoke",
                resolved_by="operator",
            )


class FrictionRepairContractTests(unittest.TestCase):
    def setUp(self) -> None:
        loader = FrictionFailureRuntimeTests()
        self.module = loader._load_module()
        self.addCleanup(loader.doCleanups)

    def test_all_proposal_patterns_have_exact_repair_contracts(self) -> None:
        self.assertEqual(
            set(self.module.FRICTION_PROPOSAL_PATTERNS),
            set(self.module.FRICTION_REPAIR_CONTRACTS),
        )

    def test_missing_repair_contract_fails_loudly(self) -> None:
        group = {
            "pattern": "future_pattern",
            "actionable_repeated": True,
            "count": 2,
            "unresolved": 2,
            "by_failure_class": {},
            "by_kind": {},
            "by_surface": {},
            "unresolved_evidence_event_ids": [],
            "unresolved_evidence_event_ids_truncated": False,
            "unresolved_missing_event_id_count": 0,
        }
        rule = {
            "terms": ("future",),
            "recommendation_type": "next_grip",
            "title": "Future",
            "rationale": "Future contract",
        }
        with patch.dict(self.module.FRICTION_PROPOSAL_PATTERNS, {"future_pattern": rule}):
            with self.assertRaisesRegex(RuntimeError, "lacks repair contract"):
                self.module._recommendation_for_group(group)

    def test_repair_contract_rejects_invalid_shapes(self) -> None:
        with patch.dict(
            self.module.FRICTION_REPAIR_CONTRACTS,
            {"blocked_gates": {"preferred_route": "explicit_preflight"}},
        ):
            with self.assertRaisesRegex(RuntimeError, "invalid fields"):
                self.module._repair_contract_for_pattern("blocked_gates")


if __name__ == "__main__":
    unittest.main()
