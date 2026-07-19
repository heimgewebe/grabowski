from __future__ import annotations

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
    base._verify_audit_log = lambda path: {"valid": True}
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

    def test_contract_contains_all_read_tools(self) -> None:
        contract = json.loads((ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8"))
        expected = set(contract["expected_tools"])
        required = {"grabowski_runtime_health", "grabowski_deployment_identity", "grabowski_contract_drift", "grabowski_checkout_summary", "grabowski_git_status", "grabowski_git_diff", "grabowski_git_log", "grabowski_git_show", "grabowski_github_pr_view", "grabowski_github_checks", "grabowski_service_status", "grabowski_service_logs"}
        self.assertTrue(required.issubset(expected))
        supporting = {item["module"]: item["source"] for item in contract["supporting_sources"]}
        self.assertEqual(supporting["grabowski_read_surface"], "src/grabowski_read_surface.py")


if __name__ == "__main__":
    unittest.main()
