from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import types
from typing import get_args
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class _FakeFastMCP:
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

def _load_read_surface():
    fake_mcp = types.ModuleType("mcp")
    fake_types = types.ModuleType("mcp.types")
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_pydantic = types.ModuleType("pydantic")
    fake_pydantic.Field = lambda **kwargs: kwargs
    operator = types.ModuleType("grabowski_operator_core")
    operator.mcp = _FakeFastMCP()
    operator.HOME = Path.home()
    operator._safe_environment = lambda: dict(os.environ)
    operator._terminate_process_group = lambda process: (b"", b"")
    operator._redact = lambda text: text
    operator._limit = lambda text, limit: (text, False)
    operator._redact_argv = lambda argv: list(argv)
    operator._argv_hash = lambda argv: hashlib.sha256(json.dumps(argv).encode()).hexdigest()
    operator._redacted_command = lambda argv: shlex.join(argv)
    operator._require_operator_capability = lambda capability: None
    operator._validate_unit = lambda unit: unit
    operator._parse_show = lambda output: dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    base = types.ModuleType("grabowski_mcp")
    base.AUDIT_LOG = Path("/tmp/audit")
    base._resolve_existing = lambda raw, kind: Path(raw)
    base._deployment_metadata = lambda: {}
    base._verify_audit_log = lambda path: {"valid": True, "total_records": 0, "last_record_sha256": None}
    base._audit_records_snapshot = lambda: (
        [],
        {"valid": True, "total_records": 0, "last_record_sha256": None},
    )
    base._audit_records = lambda: []
    base._kill_switch_state = lambda: {"engaged": False}
    base._read_limited_process_pipes = lambda *args, **kwargs: (b"", b"", False, False, False)
    capabilities = types.ModuleType("grabowski_capabilities")
    capabilities.classify_contract = lambda expected: {}
    runtime_extensions = types.ModuleType("grabowski_runtime_extensions")
    runtime_extensions.LOGICAL_RUNTIME_SERVICE = "grabowski-mcp"
    runtime_extensions.runtime_service_model = lambda deployment: {
        "logical_runtime_service": "grabowski-mcp",
        "runtime_target": "heim-pc",
        "operator_unit": "grabowski-operator.service",
        "tunnel_unit": "tunnel-client-grabowski.service",
        "deployment_release": deployment.get("release_id"),
        "repo_head": deployment.get("repo_head"),
    }
    runtime_extensions._runtime_contract_snapshot = lambda: {"source": "test", "contract": {"expected_tools": []}}
    runtime_extensions._worktree_context = lambda head: {"worktrees": []}
    module_name = "grabowski_read_surface_test"
    spec = importlib.util.spec_from_file_location(module_name, ROOT / "src" / "grabowski_read_surface.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_read_surface")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"mcp": fake_mcp, "mcp.types": fake_types, "pydantic": fake_pydantic, "grabowski_operator_core": operator, "grabowski_mcp": base, "grabowski_capabilities": capabilities, "grabowski_runtime_extensions": runtime_extensions, module_name: module}, clear=False):
        spec.loader.exec_module(module)
    return module

read_surface = _load_read_surface()

class ReadSurfaceTests(unittest.TestCase):
    def test_annotations_are_truthful(self) -> None:
        self.assertTrue(read_surface.LOCAL_READ.readOnlyHint)
        self.assertFalse(read_surface.LOCAL_READ.destructiveHint)
        self.assertTrue(read_surface.LOCAL_READ.idempotentHint)
        self.assertFalse(read_surface.LOCAL_READ.openWorldHint)
        self.assertTrue(read_surface.REMOTE_READ.readOnlyHint)
        self.assertFalse(read_surface.REMOTE_READ.destructiveHint)
        self.assertTrue(read_surface.REMOTE_READ.idempotentHint)
        self.assertTrue(read_surface.REMOTE_READ.openWorldHint)

    def test_git_command_disables_external_helpers(self) -> None:
        repo = Path("/tmp/repository")
        argv = read_surface._git_command(repo, "status", "--short")
        self.assertEqual(argv[0], "git")
        self.assertIn("diff.external=", argv)
        self.assertIn("core.hooksPath=/dev/null", argv)
        self.assertIn("core.fsmonitor=false", argv)
        self.assertIn("protocol.file.allow=never", argv)
        self.assertEqual(argv[-2:], ["status", "--short"])

    def test_read_environment_disables_prompts_and_pagers(self) -> None:
        with patch.object(read_surface.operator, "_safe_environment", return_value={"GIT_EXTERNAL_DIFF": "evil", "GIT_ASKPASS": "evil", "PAGER": "evil", "PATH": os.environ.get("PATH", "")}):
            environment = read_surface._read_environment()
        self.assertNotIn("GIT_EXTERNAL_DIFF", environment)
        self.assertNotIn("GIT_ASKPASS", environment)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_PAGER"], "cat")
        self.assertEqual(environment["GH_PROMPT_DISABLED"], "1")

    def test_schema_aliases_publish_bounds(self) -> None:
        self.assertEqual(get_args(read_surface.OutputBytes)[1]["ge"], 1024)
        self.assertEqual(get_args(read_surface.OutputBytes)[1]["le"], read_surface.MAX_OUTPUT_BYTES)
        self.assertEqual(get_args(read_surface.GitCommitCount)[1]["ge"], 1)
        self.assertEqual(get_args(read_surface.LogLineCount)[1]["le"], read_surface.MAX_LOG_LINES)

    def test_run_read_uses_streaming_bound(self) -> None:
        process = types.SimpleNamespace(returncode=0)
        with patch.object(read_surface.subprocess, "Popen", return_value=process), patch.object(read_surface.base, "_read_limited_process_pipes", return_value=(b"bounded", b"", False, True, False)) as reader:
            result = read_surface._run_read(["command"], cwd=Path("/tmp"), max_output_bytes=4096)
        reader.assert_called_once_with(process, timeout_seconds=60, max_output_bytes=4096)
        self.assertEqual(result["stdout"], "bounded")
        self.assertTrue(result["stdout_truncated"])

    def test_revision_rejects_option_injection(self) -> None:
        for revision in ("--help", "-p", "HEAD\n--exec=evil", "", "HEAD value"):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    read_surface._validate_revision(revision)
        self.assertEqual(read_surface._validate_revision("HEAD~2"), "HEAD~2")
        self.assertEqual(read_surface._validate_revision("refs/heads/main"), "refs/heads/main")

    def test_resolve_revision_requires_exactly_one_object(self) -> None:
        repository = Path("/tmp/repository")
        object_id = "a" * 40
        result = {"returncode": 0, "timed_out": False, "stdout_truncated": False, "stdout": object_id + "\n", "stderr": ""}
        with patch.object(read_surface, "_run_read", return_value=result) as runner:
            resolved = read_surface._resolve_revision(repository, "HEAD~1")
        self.assertEqual(resolved, object_id)
        self.assertEqual(runner.call_args.args[0][-4:], ["rev-parse", "--verify", "--end-of-options", "HEAD~1^{object}"])

    def test_resolve_revision_rejects_revision_sets(self) -> None:
        result = {"returncode": 0, "timed_out": False, "stdout_truncated": False, "stdout": ("a" * 40) + "\n" + ("b" * 40) + "\n", "stderr": ""}
        with patch.object(read_surface, "_run_read", return_value=result):
            with self.assertRaises(ValueError):
                read_surface._resolve_revision(Path("/tmp/repository"), "main..topic")

    def test_pr_validation_rejects_bool_and_nonpositive(self) -> None:
        for value in (True, False, 0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    read_surface._validate_pr(value)
        self.assertEqual(read_surface._validate_pr(12), 12)

    def test_git_status_uses_fixed_arguments(self) -> None:
        repo = Path("/tmp/repository")
        sentinel = {"returncode": 0}
        with patch.object(read_surface, "_resolve_repository", return_value=repo), patch.object(read_surface, "_run_read", return_value=sentinel) as runner:
            result = read_surface.grabowski_git_status(str(repo))
        self.assertIs(result, sentinel)
        self.assertEqual(runner.call_args.args[0][-4:], ["status", "--short", "--branch", "--untracked-files=normal"])

    def test_git_diff_has_no_arbitrary_arguments(self) -> None:
        repo = Path("/tmp/repository")
        with patch.object(read_surface, "_resolve_repository", return_value=repo), patch.object(read_surface, "_run_read", return_value={"returncode": 0}) as runner:
            read_surface.grabowski_git_diff(str(repo), staged=True, max_output_bytes=4096)
        argv = runner.call_args.args[0]
        self.assertIn("--no-ext-diff", argv)
        self.assertIn("--no-textconv", argv)
        self.assertIn("--cached", argv)
        self.assertEqual(argv[-1], "--")
        self.assertEqual(runner.call_args.kwargs["max_output_bytes"], 4096)

    def test_git_show_uses_resolved_object_before_path_separator(self) -> None:
        repo = Path("/tmp/repository")
        object_id = "c" * 40
        with patch.object(read_surface, "_resolve_repository", return_value=repo), patch.object(read_surface, "_resolve_revision", return_value=object_id) as resolver, patch.object(read_surface, "_run_read", return_value={"returncode": 0}) as runner:
            read_surface.grabowski_git_show(str(repo), revision="HEAD~1")
        resolver.assert_called_once_with(repo, "HEAD~1")
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-2:], [object_id, "--"])
        self.assertIn("--no-ext-diff", argv)
        self.assertIn("--no-textconv", argv)

    def test_service_status_uses_property_allowlist(self) -> None:
        result = {"returncode": 0, "stdout": "LoadState=loaded\nActiveState=active\n", "stderr": ""}
        with patch.object(read_surface.operator, "_require_operator_capability"), patch.object(read_surface.operator, "_validate_unit", return_value="demo.service"), patch.object(read_surface, "_run_read", return_value=result) as runner:
            response = read_surface.grabowski_service_status("demo.service")
        argv = runner.call_args.args[0]
        self.assertEqual(argv[:4], ["systemctl", "--user", "show", "demo.service"])
        self.assertNotIn("status", argv)
        self.assertEqual(response["properties"]["ActiveState"], "active")
        self.assertEqual(response["stdout"], "")

    def test_service_logs_bounds_lines(self) -> None:
        with patch.object(read_surface.operator, "_require_operator_capability"), patch.object(read_surface.operator, "_validate_unit", return_value="demo.service"):
            with self.assertRaises(ValueError):
                read_surface.grabowski_service_logs("demo.service", 0)
            with self.assertRaises(ValueError):
                read_surface.grabowski_service_logs("demo.service", 2001)

    def test_runtime_health_distinguishes_logical_service_and_units(self) -> None:
        deployment = {
            "completion_status": "complete",
            "release_id": "release-1",
            "repo_head": "a" * 40,
        }
        deployment.update({key: True for key in read_surface.DEPLOYMENT_INTEGRITY_FIELDS})
        audit = {
            "valid": True,
            "audit_writable": True,
            "audit_state": "ready",
            "active_bytes": 123,
            "max_bytes": 456,
            "remaining_bytes": 333,
            "reserve_bytes": 64,
            "rotation_required": False,
            "archived_segment_count": 2,
            "total_records": 99,
        }
        with (
            patch.object(read_surface.base, "_deployment_metadata", return_value=deployment),
            patch.object(read_surface.base, "_verify_audit_log", return_value=audit),
        ):
            health = read_surface.grabowski_runtime_health()
        self.assertEqual(health["service"], "grabowski-mcp")
        self.assertEqual(health["service_model"]["operator_unit"], "grabowski-operator.service")
        self.assertEqual(health["service_model"]["tunnel_unit"], "tunnel-client-grabowski.service")
        self.assertEqual(health["service_model"]["deployment_release"], "release-1")
        self.assertTrue(health["healthy"])
        self.assertTrue(health["audit_writable"])
        self.assertEqual(health["audit_active_bytes"], 123)
        self.assertEqual(health["audit_archived_segment_count"], 2)

    def test_runtime_health_is_not_healthy_when_audit_is_valid_but_not_writable(self) -> None:
        deployment = {"completion_status": "complete"}
        deployment.update({key: True for key in read_surface.DEPLOYMENT_INTEGRITY_FIELDS})
        audit = {
            "valid": True,
            "audit_writable": False,
            "audit_state": "storage_exhausted",
        }
        with (
            patch.object(read_surface.base, "_deployment_metadata", return_value=deployment),
            patch.object(read_surface.base, "_verify_audit_log", return_value=audit),
        ):
            health = read_surface.grabowski_runtime_health()
        self.assertFalse(health["healthy"])
        self.assertTrue(health["audit_valid"])
        self.assertFalse(health["audit_writable"])
        self.assertEqual(health["audit_state"], "storage_exhausted")

    def test_github_fields_exclude_body_and_comments(self) -> None:
        fields = set(read_surface.GITHUB_PR_FIELDS)
        self.assertNotIn("body", fields)
        self.assertNotIn("comments", fields)
        self.assertNotIn("reviews", fields)
        self.assertIn("number", fields)
        self.assertIn("state", fields)

    def test_json_result_parses_and_removes_raw_stdout(self) -> None:
        result = {"returncode": 0, "stdout": json.dumps({"number": 7}), "stderr": ""}
        parsed = read_surface._parse_json_result(result)
        self.assertTrue(parsed["json_valid"])
        self.assertEqual(parsed["data"], {"number": 7})
        self.assertEqual(parsed["stdout"], "")

    def test_json_result_parses_valid_output_with_nonzero_status(self) -> None:
        result = {"returncode": 8, "stdout": json.dumps([{"name": "pending", "state": "PENDING"}]), "stderr": ""}
        parsed = read_surface._parse_json_result(result)
        self.assertEqual(parsed["returncode"], 8)
        self.assertTrue(parsed["json_valid"])
        self.assertEqual(parsed["data"][0]["state"], "PENDING")
        self.assertEqual(parsed["stdout"], "")

    def test_audit_projection_binds_verified_snapshot_and_fixed_windows(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "resource-acquire",
                "timestamp": datetime.fromtimestamp(
                    now - 60, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "a" * 64,
                "resource_keys": ["repo:/work/demo", "path:/work/demo/file"],
                "reclaimed_count": 2,
            },
            {
                "operation": "bureau-candidate-record",
                "timestamp": datetime.fromtimestamp(
                    now - 120, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "b" * 64,
                "bureau_status": "failed",
                "bureau_code": "request-schema-unsupported",
                "effect_started": False,
            },
            {
                "operation": "bureau-candidate-record",
                "timestamp": datetime.fromtimestamp(
                    now - 180, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "c" * 64,
                "bureau_status": "failed",
                "bureau_code": "request-schema-unsupported",
                "effect_started": False,
            },
            {
                "operation": "bureau-candidate-record",
                "timestamp": datetime.fromtimestamp(
                    now - 240, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "d" * 64,
                "bureau_status": "failed",
                "bureau_code": "request-schema-unsupported",
                "effect_started": False,
            },
            {
                "operation": "bureau-task-publish",
                "timestamp": datetime.fromtimestamp(
                    now - 270, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "e" * 64,
                "bureau_status": "published",
                "bureau_code": "publication-complete",
                "effect_started": True,
            },
            {
                "operation": "remove",
                "timestamp": datetime.fromtimestamp(
                    now - 300, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "f" * 64,
                "before_sha256": "0" * 64,
                "after_sha256": None,
                "rollback": {"available": True},
            },
        ]
        status = {
            "valid": True,
            "total_records": len(records),
            "total_legacy_records": 0,
            "last_record_sha256": "f" * 64,
            "archived_segment_count": 2,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=(records, status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", return_value=now),
        ):
            result = read_surface.grabowski_audit_projection(
                view="standard", top_limit=5
            )
        self.assertEqual(result["projection_kind"], "audit_projection.v1")
        self.assertEqual(result["source_binding"]["record_count"], len(records))
        self.assertEqual(result["source_binding"]["last_record_sha256"], "f" * 64)
        self.assertEqual(
            [item["label"] for item in result["windows"]], ["24h", "7d", "30d"]
        )
        self.assertEqual(result["windows"][0]["record_count"], len(records))
        self.assertEqual(
            result["windows"][0]["resource_activity"][
                "resource_reclamation_event_count"
            ],
            1,
        )
        self.assertEqual(
            result["windows"][0]["resource_activity"]["reclaimed_resource_count"], 2
        )
        self.assertNotIn(
            "repeated_resource_reclamation",
            [item["pattern"] for item in result["candidate_patterns"]],
        )
        self.assertEqual(
            result["windows"][0]["mutation_evidence"]["rollback_available"], 1
        )
        self.assertEqual(
            result["candidate_patterns"][0]["pattern"],
            "repeated_bureau_contract_failures",
        )
        self.assertEqual(
            result["candidate_patterns"][0]["top_codes"][0],
            {"code": "request-schema-unsupported", "count": 3},
        )
        self.assertNotIn(
            "publication-complete",
            json.dumps(result["windows"][0]["top_bureau_failure_codes"]),
        )
        self.assertEqual(result["candidate_patterns"][0]["authority"], "proposal_only")
        self.assertNotIn("owner_id", json.dumps(result))
        self.assertNotIn("/work/demo", json.dumps(result))


    def test_audit_projection_redacts_untrusted_dimension_labels(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "/home/alex/private-operation",
                "timestamp": datetime.fromtimestamp(
                    now - 60, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "a" * 64,
                "bureau_code": "secret /home/alex/private-code",
                "resource_keys": ["secret /home/alex:private-resource"],
            },
            {
                "operation": "friction-record",
                "timestamp": datetime.fromtimestamp(
                    now - 30, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "b" * 64,
                "kind": "secret /home/alex/private-kind",
                "surface": "secret /home/alex/private-surface",
            },
        ]
        status = {
            "valid": True,
            "total_records": 2,
            "total_legacy_records": 0,
            "last_record_sha256": "b" * 64,
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=(records, status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", return_value=now),
        ):
            result = read_surface.grabowski_audit_projection(
                view="evidence", top_limit=10
            )
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("/home/alex", encoded)
        self.assertNotIn("private-operation", encoded)
        self.assertNotIn("private-code", encoded)
        self.assertNotIn("private-resource", encoded)
        self.assertNotIn("private-kind", encoded)
        self.assertNotIn("private-surface", encoded)
        self.assertIn("<redacted>", encoded)

    def test_audit_projection_counts_reclamation_events_separately(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "resource-acquire",
                "timestamp": datetime.fromtimestamp(
                    now - offset, tz=timezone.utc
                ).isoformat(),
                "record_sha256": f"{index:x}" * 64,
                "reclaimed_count": count,
            }
            for index, (offset, count) in enumerate(
                ((60, 1), (120, 2), (180, 3)), start=1
            )
        ]
        status = {
            "valid": True,
            "total_records": 3,
            "total_legacy_records": 0,
            "last_record_sha256": "3" * 64,
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=(records, status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", return_value=now),
        ):
            result = read_surface.grabowski_audit_projection()
        activity = result["windows"][0]["resource_activity"]
        self.assertEqual(activity["resource_reclamation_event_count"], 3)
        self.assertEqual(activity["reclaimed_resource_count"], 6)
        candidate = next(
            item
            for item in result["candidate_patterns"]
            if item["pattern"] == "repeated_resource_reclamation"
        )
        self.assertEqual(candidate["event_count_7d"], 3)
        self.assertEqual(candidate["reclaimed_resource_count_7d"], 6)

    def test_audit_projection_findings_hash_ignores_window_clock_edges(self) -> None:
        record = {
            "operation": "task-start",
            "timestamp": datetime.fromtimestamp(1_800_000_000 - 60, tz=timezone.utc).isoformat(),
            "record_sha256": "a" * 64,
        }
        status = {
            "valid": True,
            "total_records": 1,
            "total_legacy_records": 0,
            "last_record_sha256": "a" * 64,
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=([record], status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", side_effect=[1_800_000_000, 1_800_000_030]),
        ):
            first = read_surface.grabowski_audit_projection()
            second = read_surface.grabowski_audit_projection()
        self.assertEqual(first["findings_sha256"], second["findings_sha256"])
        self.assertNotEqual(first["projection_sha256"], second["projection_sha256"])

    def test_audit_projection_fails_closed_for_invalid_chain(self) -> None:
        with patch.object(
            read_surface.base,
            "_audit_records_snapshot",
            side_effect=ValueError("previous-hash-mismatch"),
        ):
            with self.assertRaisesRegex(RuntimeError, "previous-hash-mismatch"):
                read_surface.grabowski_audit_projection()

    def test_audit_projection_reports_concurrent_advance_without_rebinding_snapshot(
        self,
    ) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "task-start",
                "timestamp": datetime.fromtimestamp(
                    now - 1, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "a" * 64,
            }
        ]
        before = {
            "valid": True,
            "total_records": 1,
            "total_legacy_records": 7,
            "last_record_sha256": "a" * 64,
            "archived_segment_count": 2,
            "audit_writable": True,
        }
        after = {
            "valid": True,
            "total_records": 2,
            "total_legacy_records": 8,
            "last_record_sha256": "b" * 64,
            "archived_segment_count": 3,
            "audit_writable": False,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=(records, before),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=after),
            patch.object(read_surface.time, "time", return_value=now),
        ):
            result = read_surface.grabowski_audit_projection()
        self.assertTrue(result["source_binding"]["advanced_during_projection"])
        self.assertEqual(result["source_binding"]["last_record_sha256"], "a" * 64)
        self.assertEqual(
            result["warnings"][0]["code"], "audit_advanced_during_projection"
        )
        self.assertEqual(result["warnings"][1]["count"], 7)
        self.assertEqual(result["source_binding"]["archived_segment_count"], 2)
        self.assertTrue(result["source_binding"]["audit_writable"])
        self.assertEqual(result["source_binding"]["post_read_total_records"], 2)

    def test_audit_projection_rejects_non_integer_top_limit(self) -> None:
        for value in (True, False, 1.5, "2", None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "top_limit"):
                    read_surface.grabowski_audit_projection(top_limit=value)

    def test_audit_projection_views_and_field_projection(self) -> None:
        now = 1_800_000_000
        record = {
            "operation": "task-start",
            "timestamp": datetime.fromtimestamp(
                now - 60, tz=timezone.utc
            ).isoformat(),
            "record_sha256": "a" * 64,
        }
        status = {
            "valid": True,
            "total_records": 1,
            "total_legacy_records": 0,
            "last_record_sha256": "a" * 64,
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=([record], status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", return_value=now),
        ):
            minimal = read_surface.grabowski_audit_projection(view="minimal")
            evidence = read_surface.grabowski_audit_projection(view="evidence")
            projected = read_surface.grabowski_audit_projection(
                fields=["findings_sha256"]
            )
        self.assertNotIn("top_failure_reasons", minimal["windows"][0])
        self.assertNotIn("operation_counts", minimal["windows"][0])
        self.assertIn("top_failure_reasons", evidence["windows"][0])
        self.assertIn("operation_counts", evidence["windows"][0])
        self.assertIn("timestamp_quality", evidence["all_time"])
        self.assertIn("findings_sha256", projected)
        self.assertNotIn("windows", projected)
        self.assertIn("source_binding", projected)
        self.assertIn("windows", projected["projection"]["omitted_fields"])

    def test_audit_projection_parses_each_timestamp_once(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "task-start",
                "timestamp": datetime.fromtimestamp(
                    now - index, tz=timezone.utc
                ).isoformat(),
                "record_sha256": f"{index:064x}",
            }
            for index in range(1, 101)
        ]
        status = {
            "valid": True,
            "total_records": len(records),
            "total_legacy_records": 0,
            "last_record_sha256": records[-1]["record_sha256"],
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        original = read_surface._audit_timestamp_unix
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=(records, status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", return_value=now),
            patch.object(
                read_surface, "_audit_timestamp_unix", wraps=original
            ) as parser,
        ):
            read_surface.grabowski_audit_projection()
        self.assertEqual(parser.call_count, len(records))

    def test_audit_projection_rejects_snapshot_binding_mismatch(self) -> None:
        record = {
            "operation": "task-start",
            "timestamp": "2027-01-15T08:00:00+00:00",
            "record_sha256": "a" * 64,
        }
        status = {
            "valid": True,
            "total_records": 2,
            "last_record_sha256": "a" * 64,
        }
        with patch.object(
            read_surface.base,
            "_audit_records_snapshot",
            return_value=([record], status),
        ):
            with self.assertRaisesRegex(RuntimeError, "snapshot binding mismatch"):
                read_surface.grabowski_audit_projection()

    def test_audit_projection_findings_hash_changes_when_window_membership_changes(
        self,
    ) -> None:
        now = 1_800_000_000
        record = {
            "operation": "task-start",
            "timestamp": datetime.fromtimestamp(
                now - 86_400 + 10, tz=timezone.utc
            ).isoformat(),
            "record_sha256": "a" * 64,
        }
        status = {
            "valid": True,
            "total_records": 1,
            "total_legacy_records": 0,
            "last_record_sha256": "a" * 64,
            "archived_segment_count": 0,
            "audit_writable": True,
        }
        with (
            patch.object(
                read_surface.base,
                "_audit_records_snapshot",
                return_value=([record], status),
            ),
            patch.object(read_surface.base, "_verify_audit_log", return_value=status),
            patch.object(read_surface.time, "time", side_effect=[now, now + 30]),
        ):
            first = read_surface.grabowski_audit_projection()
            second = read_surface.grabowski_audit_projection()
        self.assertEqual(first["windows"][0]["record_count"], 1)
        self.assertEqual(second["windows"][0]["record_count"], 0)
        self.assertNotEqual(first["findings_sha256"], second["findings_sha256"])
    def test_contract_drift_combines_structural_and_semantic_health(self) -> None:
        healthy_router = types.ModuleType("grabowski_coding_agent_router")
        healthy_router.coding_agent_catalog_health = lambda: {
            "ready": True,
            "source": "deployment_catalog",
            "catalog_sha256": "a" * 64,
        }
        with patch.dict(
            sys.modules, {"grabowski_coding_agent_router": healthy_router}, clear=False
        ):
            result = read_surface.grabowski_contract_drift()
        self.assertTrue(result["capability_catalog_matches_contract"])
        self.assertTrue(result["semantic_catalog_ready"])
        self.assertTrue(result["catalog_matches_contract"])
        self.assertEqual(
            result["coding_agent_catalog"]["source"], "deployment_catalog"
        )

        invalid_router = types.ModuleType("grabowski_coding_agent_router")
        invalid_router.coding_agent_catalog_health = lambda: {
            "ready": False,
            "error_type": "CodingAgentRouterError",
            "error": "invalid catalog",
        }
        with patch.dict(
            sys.modules, {"grabowski_coding_agent_router": invalid_router}, clear=False
        ):
            invalid = read_surface.grabowski_contract_drift()
        self.assertTrue(invalid["capability_catalog_matches_contract"])
        self.assertFalse(invalid["semantic_catalog_ready"])
        self.assertFalse(invalid["catalog_matches_contract"])

    def test_contract_contains_all_read_tools(self) -> None:
        contract = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8"))
        expected = set(contract["expected_tools"])
        required = {"grabowski_runtime_health", "grabowski_audit_projection", "grabowski_deployment_identity", "grabowski_contract_drift", "grabowski_checkout_summary", "grabowski_git_status", "grabowski_git_diff", "grabowski_git_log", "grabowski_git_show", "grabowski_github_pr_view", "grabowski_github_checks", "grabowski_service_status", "grabowski_service_logs"}
        self.assertTrue(required.issubset(expected))
        supporting = {item["module"]: item["source"] for item in contract["supporting_sources"]}
        self.assertEqual(supporting["grabowski_read_surface"], "src/grabowski_read_surface.py")


if __name__ == "__main__":
    unittest.main()
