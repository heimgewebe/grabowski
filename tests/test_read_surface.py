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
from unittest.mock import Mock, patch

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
    base._runtime_tool_contract_summary = lambda: {
        "client_snapshot_observable": False,
        "client_schema_snapshot_observable": False,
    }
    base._read_limited_process_pipes = lambda *args, **kwargs: (b"", b"", False, False, False)
    capabilities = types.ModuleType("grabowski_capabilities")
    capabilities.classify_contract = lambda expected: {}
    checkouts = types.ModuleType("grabowski_checkouts")
    checkouts.active_capacity_projection = lambda repository: {
        "repository": str(repository),
        "available": True,
    }
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
    src_path = str(ROOT / "src")
    added_src_path = src_path not in sys.path
    if added_src_path:
        sys.path.insert(0, src_path)
    try:
        with patch.dict(
            sys.modules,
            {
                "mcp": fake_mcp,
                "mcp.types": fake_types,
                "pydantic": fake_pydantic,
                "grabowski_operator_core": operator,
                "grabowski_mcp": base,
                "grabowski_capabilities": capabilities,
                "grabowski_checkouts": checkouts,
                "grabowski_runtime_extensions": runtime_extensions,
                module_name: module,
            },
            clear=False,
        ):
            spec.loader.exec_module(module)
    finally:
        if added_src_path:
            sys.path.remove(src_path)
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
        self.assertIn(
            "canonical GitHub", get_args(read_surface.GitHubRepository)[1]["description"]
        )
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

    def test_github_repository_accepts_canonical_identifier(self) -> None:
        with patch.object(read_surface, "_resolve_repository") as resolver:
            cwd, argv = read_surface._resolve_github_repository(
                "heimgewebe/grabowski"
            )
        resolver.assert_not_called()
        self.assertEqual(cwd, read_surface.operator.HOME)
        self.assertEqual(argv, ["--repo", "heimgewebe/grabowski"])
        _, dot_repository_argv = read_surface._resolve_github_repository(
            "heimgewebe/.github"
        )
        self.assertEqual(dot_repository_argv, ["--repo", "heimgewebe/.github"])

    def test_github_repository_rejects_relative_paths_and_option_like_names(
        self,
    ) -> None:
        for repo in (
            "../grabowski",
            "heimgewebe/grabowski/extra",
            "heimgewebe/..",
            "heimgewebe-/grabowski",
            "--repo/heimgewebe",
            "heimgewebe/grabowski?x=1",
            "heimgewebe/grabowski#frag",
            "heimgewebe/grab%0aowski",
            "heimgewebe//grabowski",
        ):
            with self.subTest(repo=repo):
                with self.assertRaisesRegex(ValueError, "canonical GitHub"):
                    read_surface._resolve_github_repository(repo)

    def test_github_rest_rejects_paths_outside_fixed_allowlist_before_network(self) -> None:
        invalid_paths = (
            "/repos/heimgewebe/grabowski/../../users",
            "/repos/heimgewebe/../pulls/1",
            "/repos/heimgewebe/grabowski/pulls/1?extra=1",
            "/repos/heimgewebe/grabowski/issues/1",
            "/repos/heimgewebe/grab%0aowski/pulls/1",
            "/repos/heimgewebe//grabowski/pulls/1",
        )
        with patch.object(read_surface.http.client, "HTTPSConnection") as connection:
            for path in invalid_paths:
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "allowlist"):
                    read_surface._github_rest_json(path)
        connection.assert_not_called()

    def test_github_rest_path_uses_canonical_encoded_segments(self) -> None:
        self.assertEqual(
            read_surface._github_rest_path("heimgewebe/.github", "pulls", "12"),
            "/repos/heimgewebe/.github/pulls/12",
        )
        with self.assertRaisesRegex(ValueError, "query"):
            read_surface._github_rest_path(
                "heimgewebe/grabowski", "pulls", "12", query="page=2"
            )

    def test_github_checks_uses_repo_flag_for_canonical_identifier(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": "[]",
            "stderr": "",
        }
        with patch.object(read_surface, "_run_read", return_value=result) as runner:
            response = read_surface.grabowski_github_checks(
                "heimgewebe/grabowski", 546
            )
        self.assertEqual(response["data"], [])
        argv = runner.call_args.args[0]
        self.assertEqual(
            argv[:7],
            [
                "gh",
                "pr",
                "checks",
                "546",
                "--repo",
                "heimgewebe/grabowski",
                "--json",
            ],
        )
        self.assertEqual(runner.call_args.kwargs["cwd"], read_surface.operator.HOME)

    def test_github_pr_view_uses_repo_flag_for_canonical_identifier(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": "{}",
            "stderr": "",
        }
        with patch.object(read_surface, "_run_read", return_value=result) as runner:
            response = read_surface.grabowski_github_pr_view(
                "heimgewebe/grabowski", 546
            )
        self.assertEqual(response["data"], {})
        self.assertEqual(
            runner.call_args.args[0][:7],
            [
                "gh",
                "pr",
                "view",
                "546",
                "--repo",
                "heimgewebe/grabowski",
                "--json",
            ],
        )
        self.assertEqual(runner.call_args.kwargs["cwd"], read_surface.operator.HOME)

    def test_github_pr_view_keeps_absolute_worktree_behavior(self) -> None:
        repository = Path("/tmp/repository")
        result = {
            "returncode": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": "{}",
            "stderr": "",
        }
        with (
            patch.object(
                read_surface, "_resolve_repository", return_value=repository
            ) as resolver,
            patch.object(read_surface, "_run_read", return_value=result) as runner,
        ):
            read_surface.grabowski_github_pr_view(str(repository), 12)
        resolver.assert_called_once_with(str(repository))
        self.assertNotIn("--repo", runner.call_args.args[0])
        self.assertEqual(runner.call_args.kwargs["cwd"], repository)

    def test_github_pr_view_falls_back_to_bounded_anonymous_rest_without_cli(self) -> None:
        rest = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "number": 546,
                "title": "read only",
                "state": "open",
                "draft": False,
                "mergeable": True,
                "head": {"ref": "topic", "sha": "a" * 40},
                "base": {"ref": "main"},
                "html_url": "https://github.com/heimgewebe/grabowski/pull/546",
                "updated_at": "2026-09-03T06:00:00Z",
            },
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", return_value=rest) as request,
            patch.object(read_surface, "_run_read") as runner,
        ):
            response = read_surface.grabowski_github_pr_view("heimgewebe/grabowski", 546)
        runner.assert_not_called()
        request.assert_called_once_with("/repos/heimgewebe/grabowski/pulls/546")
        self.assertEqual(response["data"]["headRefName"], "topic")
        self.assertEqual(response["data"]["state"], "OPEN")
        self.assertEqual(response["data"]["mergeable"], "MERGEABLE")
        self.assertIsNone(response["data"]["reviewDecision"])
        self.assertEqual(response["field_availability"]["reviewDecision"], "unavailable_anonymous_rest")

    def test_github_checks_falls_back_to_bounded_anonymous_rest_without_cli(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "a" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "validate",
                        "status": "completed",
                        "conclusion": "success",
                        "details_url": "https://github.com/example/check/1",
                        "started_at": "2026-09-03T06:00:00Z",
                        "completed_at": "2026-09-03T06:01:00Z",
                        "output": {"title": "validation"},
                    }
                ],
            },
        }
        statuses = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"state": "success", "total_count": 0, "statuses": []},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]) as request,
            patch.object(read_surface, "_run_read") as runner,
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        runner.assert_not_called()
        self.assertEqual(request.call_count, 3)
        self.assertEqual(response["head_sha"], "a" * 40)
        self.assertEqual(response["data"][0]["bucket"], "pass")
        self.assertEqual(response["data"][0]["state"], "SUCCESS")
        self.assertIsNone(response["data"][0]["workflow"])
        self.assertEqual(response["check_run_count"], 1)
        self.assertEqual(response["status_context_count"], 0)
        self.assertEqual(response["transport_returncode"], 0)
        self.assertEqual(response["returncode"], 0)

    def test_github_checks_anonymous_fallback_includes_legacy_status_contexts(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "b" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"total_count": 0, "check_runs": []},
        }
        statuses = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "state": "failure",
                "total_count": 2,
                "statuses": [
                    {
                        "state": "failure",
                        "context": "legacy/required",
                        "description": "required legacy status failed",
                        "target_url": "https://ci.example/failure",
                        "created_at": "2026-09-03T06:00:00Z",
                        "updated_at": "2026-09-03T06:01:00Z",
                    },
                    {
                        "state": "pending",
                        "context": "legacy/pending",
                        "description": "still running",
                        "target_url": "https://ci.example/pending",
                        "created_at": "2026-09-03T06:02:00Z",
                        "updated_at": "2026-09-03T06:02:00Z",
                    },
                ],
            },
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]) as request,
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertEqual(request.call_count, 3)
        by_name = {item["name"]: item for item in response["data"]}
        self.assertEqual(by_name["legacy/required"]["bucket"], "fail")
        self.assertEqual(by_name["legacy/required"]["state"], "FAILURE")
        self.assertEqual(by_name["legacy/pending"]["bucket"], "pending")
        self.assertEqual(by_name["legacy/pending"]["state"], "PENDING")
        self.assertEqual(response["check_run_count"], 0)
        self.assertEqual(response["status_context_count"], 2)
        self.assertEqual(response["total_count"], 2)
        self.assertEqual(response["transport_returncode"], 0)
        self.assertEqual(response["returncode"], 1)

    def test_github_checks_preserves_check_rows_when_status_transport_is_unavailable(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "e" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "validate",
                        "status": "completed",
                        "conclusion": "success",
                        "output": {},
                    }
                ],
            },
        }
        status_error = {
            "transport": "github-rest-anonymous",
            "origin": "https://api.github.com",
            "returncode": 1,
            "http_status": 403,
            "json_valid": True,
            "data": {"message": "API rate limit exceeded"},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, status_error]),
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertEqual(response["http_status"], 403)
        self.assertFalse(response["complete"])
        self.assertEqual(response["returncode"], 1)
        self.assertEqual(response["check_run_count"], 1)
        self.assertEqual(response["data"][0]["name"], "validate")
        self.assertFalse(response["checks_truncated"])
        self.assertEqual(response["reported_check_run_count"], 1)
        self.assertNotIn("API rate limit exceeded", json.dumps(response, sort_keys=True))

    def test_github_checks_preserves_check_rows_when_status_shape_is_invalid(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "a" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "validate",
                        "status": "completed",
                        "conclusion": "success",
                        "output": {},
                    }
                ],
            },
        }
        statuses = {
            "transport": "github-rest-anonymous",
            "origin": "https://api.github.com",
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"state": "success"},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]),
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertFalse(response["complete"])
        self.assertFalse(response["json_valid"])
        self.assertEqual(response["returncode"], 1)
        self.assertEqual(response["field_availability"]["commit_status"], "invalid_shape")
        self.assertEqual(response["data"][0]["name"], "validate")

    def test_github_checks_anonymous_fallback_uses_pending_exit_code(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "d" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "total_count": 1,
                "check_runs": [
                    {
                        "name": "validate",
                        "status": "in_progress",
                        "conclusion": None,
                        "details_url": "https://github.com/example/check/pending",
                        "started_at": "2026-09-03T06:00:00Z",
                        "completed_at": None,
                        "output": {},
                    }
                ],
            },
        }
        statuses = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"state": "pending", "total_count": 0, "statuses": []},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]),
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertEqual(response["transport_returncode"], 0)
        self.assertEqual(response["returncode"], 8)
        self.assertEqual(response["data"][0]["bucket"], "pending")

    def test_github_checks_anonymous_fallback_fails_closed_on_truncated_status_contexts(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "c" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"total_count": 0, "check_runs": []},
        }
        statuses = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"state": "pending", "total_count": 101, "statuses": [{}] * 100},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]),
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertTrue(response["json_valid"])
        self.assertFalse(response["complete"])
        self.assertFalse(response["checks_truncated"])
        self.assertTrue(response["status_contexts_truncated"])
        self.assertEqual(response["status_context_count"], 100)
        self.assertEqual(response["reported_status_context_count"], 101)
        self.assertEqual(len(response["data"]), 100)
        self.assertEqual(response["returncode"], 1)

    def test_github_checks_anonymous_fallback_preserves_bounded_check_page_when_truncated(self) -> None:
        pull = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"head": {"sha": "b" * 40}},
        }
        checks = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {
                "total_count": 101,
                "check_runs": [
                    {
                        "name": f"check-{index}",
                        "status": "completed",
                        "conclusion": "success",
                        "output": {},
                    }
                    for index in range(100)
                ],
            },
        }
        statuses = {
            "returncode": 0,
            "http_status": 200,
            "json_valid": True,
            "data": {"state": "success", "total_count": 0, "statuses": []},
        }
        with (
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json", side_effect=[pull, checks, statuses]),
        ):
            response = read_surface.grabowski_github_checks("heimgewebe/grabowski", 546)
        self.assertFalse(response["complete"])
        self.assertTrue(response["checks_truncated"])
        self.assertFalse(response["status_contexts_truncated"])
        self.assertEqual(response["check_run_count"], 100)
        self.assertEqual(response["reported_check_run_count"], 101)
        self.assertEqual(len(response["data"]), 100)
        self.assertEqual(response["returncode"], 1)

    def test_github_rest_projection_preserves_gh_state_enums(self) -> None:
        merged = read_surface._github_pr_projection(
            {
                "state": "closed",
                "merged_at": "2026-09-03T06:00:00Z",
                "mergeable": None,
            }
        )
        conflicting = read_surface._github_pr_projection(
            {"state": "open", "merged_at": None, "mergeable": False}
        )
        self.assertEqual(merged["state"], "MERGED")
        self.assertEqual(merged["mergeable"], "UNKNOWN")
        self.assertEqual(conflicting["state"], "OPEN")
        self.assertEqual(conflicting["mergeable"], "CONFLICTING")

    def test_github_rest_pending_check_normalizes_to_gh_pending_state(self) -> None:
        projected = read_surface._github_check_projection(
            {
                "status": "in_progress",
                "conclusion": None,
                "name": "validate",
                "output": {},
            }
        )
        self.assertEqual(projected["bucket"], "pending")
        self.assertEqual(projected["state"], "PENDING")

    def test_github_rest_redirect_is_fail_closed(self) -> None:
        response = Mock()
        response.status = 301
        response.read.return_value = b'{"message":"moved somewhere private"}'
        response.getheader.side_effect = {
            "X-RateLimit-Limit": "60",
            "X-RateLimit-Remaining": "17",
            "X-RateLimit-Reset": "1788449999",
            "X-RateLimit-Resource": "core",
        }.get
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(
            read_surface.http.client, "HTTPSConnection", return_value=connection
        ):
            result = read_surface._github_rest_json(
                "/repos/heimgewebe/grabowski/pulls/1"
            )
        self.assertEqual(result["http_status"], 301)
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["error_kind"], "github_rest_http_error")
        self.assertIsNone(result["data"])
        self.assertEqual(result["rate_limit"]["limit"], 60)
        self.assertEqual(result["rate_limit"]["remaining"], 17)
        self.assertEqual(result["rate_limit"]["reset_unix"], 1788449999)
        self.assertNotIn("moved somewhere private", json.dumps(result, sort_keys=True))
        connection.request.assert_called_once()

    def test_github_projection_bounds_untrusted_strings(self) -> None:
        projected = read_surface._github_check_projection(
            {
                "name": "n" * 1000,
                "details_url": "u" * 2000,
                "status": "completed",
                "conclusion": "success",
                "output": {"title": "d" * 1000},
            }
        )
        self.assertEqual(len(projected["name"]), 255)
        self.assertEqual(len(projected["description"]), read_surface.MAX_PROJECTED_TEXT)
        self.assertEqual(len(projected["link"]), read_surface.MAX_PROJECTED_URL)

    def test_github_anonymous_fallback_rejects_absolute_worktree(self) -> None:
        repository = Path("/tmp/repository")
        with (
            patch.object(read_surface, "_resolve_repository", return_value=repository),
            patch.object(read_surface.operator, "_require_operator_capability", side_effect=PermissionError("disabled")),
            patch.object(read_surface, "_github_rest_json") as request,
        ):
            with self.assertRaisesRegex(PermissionError, "absolute-worktree"):
                read_surface.grabowski_github_pr_view(str(repository), 12)
        request.assert_not_called()

    def test_tailscale_status_uses_fixed_argv_and_redacts_account_fields(self) -> None:
        payload = {
            "Version": "1.2.3",
            "TUN": True,
            "BackendState": "Running",
            "HaveNodeKey": True,
            "TailscaleIPs": ["100.64.0.1"],
            "Self": {"HostName": "node", "DNSName": "node.private.ts.net.", "Online": True, "PublicKey": "secret-key", "UserID": 1},
            "Peer": {"nodekey:secret": {"HostName": "peer", "DNSName": "peer.private.ts.net.", "Online": True, "PublicKey": "peer-key", "UserID": 2, "Addrs": ["1.2.3.4:123"], "PeerAPIURL": ["http://100.64.0.2:1"], "LastHandshake": "private-handshake", "KeyExpiry": "private-expiry", "Relay": "private-relay"}},
            "User": {"1": {"LoginName": "private@example.test"}},
            "CurrentTailnet": {"Name": "private@example.test"},
            "Health": ["login private@example.test via node.private.ts.net"],
        }
        result = {
            "returncode": 0,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": json.dumps(payload),
            "stderr": "warning private@example.test nodekey:secret",
        }
        with patch.object(read_surface.shutil, "which", return_value="/usr/bin/tailscale"), patch.object(read_surface, "_run_read", return_value=result) as runner:
            response = read_surface.grabowski_tailscale_status()
        self.assertEqual(runner.call_args.args[0], ["/usr/bin/tailscale", "status", "--json"])
        encoded = json.dumps(response, sort_keys=True)
        for forbidden_value in (
            "private@example.test",
            "nodekey:secret",
            "secret-key",
            "peer-key",
            "1.2.3.4:123",
            "node.private.ts.net",
            "peer.private.ts.net",
            "private-handshake",
            "private-expiry",
            "private-relay",
            "100.64.0.1",
        ):
            self.assertNotIn(forbidden_value, encoded)
        projected = json.dumps(response["data"], sort_keys=True)
        for forbidden_field in ("PeerAPIURL", "PublicKey", "UserID", "Addrs"):
            self.assertNotIn(forbidden_field, projected)
        self.assertNotIn("stdout", response)
        self.assertNotIn("stderr", response)
        self.assertEqual(response["data"]["peer_count"], 1)
        self.assertEqual(response["data"]["health_issue_count"], 1)
        self.assertTrue(response["status_readable"])

    def test_tailscale_status_missing_binary_is_not_available(self) -> None:
        with patch.object(read_surface.shutil, "which", return_value=None):
            response = read_surface.grabowski_tailscale_status()
        self.assertFalse(response["available"])
        self.assertFalse(response["executable_present"])
        self.assertFalse(response["status_readable"])

    def test_tailscale_projection_bounds_peer_materialization_before_projection(self) -> None:
        payload = {
            "Peer": {
                f"nodekey:{index}": {
                    "HostName": "x" * 1000,
                    "DNSName": "secret.ts.net",
                    "Online": True,
                }
                for index in range(read_surface.MAX_TAILSCALE_PEERS + 10)
            },
            "Health": [],
        }
        projected = read_surface._tailscale_status_projection(payload)
        self.assertEqual(
            projected["peer_count"], read_surface.MAX_TAILSCALE_PEERS + 10
        )
        self.assertEqual(len(projected["Peers"]), read_surface.MAX_TAILSCALE_PEERS)
        self.assertTrue(projected["peers_truncated"])
        self.assertNotIn("secret.ts.net", json.dumps(projected, sort_keys=True))

    def test_tailscale_status_failure_distinguishes_executable_from_readability(self) -> None:
        result = {
            "returncode": 1,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": "",
            "stderr": "failed",
        }
        with (
            patch.object(read_surface.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(read_surface, "_run_read", return_value=result),
        ):
            response = read_surface.grabowski_tailscale_status()
        self.assertFalse(response["available"])
        self.assertTrue(response["executable_present"])
        self.assertFalse(response["status_readable"])
        self.assertEqual(response["reason"], "tailscale_status_command_failed")

    def test_tailscale_status_unexpected_shape_is_fail_closed_without_raw_payload(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": json.dumps(["private@example.test", "nodekey:secret"]),
            "stderr": "",
        }
        with (
            patch.object(read_surface.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(read_surface, "_run_read", return_value=result),
        ):
            response = read_surface.grabowski_tailscale_status()
        encoded = json.dumps(response, sort_keys=True)
        self.assertFalse(response["available"])
        self.assertTrue(response["executable_present"])
        self.assertFalse(response["status_readable"])
        self.assertFalse(response["json_valid"])
        self.assertEqual(response["reason"], "tailscale_status_unexpected_shape")
        self.assertNotIn("private@example.test", encoded)
        self.assertNotIn("nodekey:secret", encoded)
        self.assertNotIn("stdout", response)
        self.assertNotIn("stderr", response)

    def test_tailscale_status_failure_never_returns_valid_json_payload(self) -> None:
        secret_payload = {
            "CurrentTailnet": {"Name": "private@example.test"},
            "Self": {"PublicKey": "nodekey:secret", "UserID": 42},
        }
        result = {
            "returncode": 1,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": json.dumps(secret_payload),
            "stderr": "private@example.test",
        }
        with (
            patch.object(read_surface.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(read_surface, "_run_read", return_value=result),
        ):
            response = read_surface.grabowski_tailscale_status()
        encoded = json.dumps(response, sort_keys=True)
        self.assertNotIn("private@example.test", encoded)
        self.assertNotIn("nodekey:secret", encoded)
        self.assertNotIn("stdout", response)
        self.assertNotIn("stderr", response)
        self.assertIsNone(response["data"])
        self.assertEqual(response["reason"], "tailscale_status_command_failed")

    def test_tailscale_status_invalid_json_never_returns_raw_stdout(self) -> None:
        result = {
            "returncode": 0,
            "timed_out": False,
            "duration_seconds": 0.1,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout": "private@example.test nodekey:secret not-json",
            "stderr": "",
        }
        with (
            patch.object(read_surface.shutil, "which", return_value="/usr/bin/tailscale"),
            patch.object(read_surface, "_run_read", return_value=result),
        ):
            response = read_surface.grabowski_tailscale_status()
        encoded = json.dumps(response, sort_keys=True)
        self.assertNotIn("private@example.test", encoded)
        self.assertNotIn("nodekey:secret", encoded)
        self.assertNotIn("stdout", response)
        self.assertNotIn("stderr", response)
        self.assertFalse(response["json_valid"])
        self.assertEqual(response["reason"], "tailscale_status_invalid_json")
        self.assertIsNone(response["data"])

    def test_git_status_uses_fixed_arguments(self) -> None:
        repo = Path("/tmp/repository")
        sentinel = {"returncode": 0}
        with patch.object(read_surface, "_resolve_repository", return_value=repo), patch.object(read_surface, "_run_read", return_value=sentinel) as runner:
            result = read_surface.grabowski_git_status(str(repo))
        self.assertIs(result, sentinel)
        self.assertEqual(runner.call_args.args[0][-4:], ["status", "--short", "--branch", "--untracked-files=normal"])

    def test_git_status_optionally_returns_shared_branch_preimage(self) -> None:
        repo = Path("/tmp/repository")
        status = {"returncode": 0}
        preimage = {
            "schema_version": 1,
            "repository": str(repo),
            "branch": "feature",
            "head": "a" * 40,
            "head_state": "present",
            "index_sha256": "b" * 64,
            "operation_refs": {},
            "preimage_sha256": "c" * 64,
        }
        with (
            patch.object(read_surface, "_resolve_repository", return_value=repo),
            patch.object(read_surface, "_run_read", return_value=status),
            patch.object(
                read_surface.grabowski_git_preimage,
                "capture_branch_preimage",
                return_value=preimage,
                create=True,
            ) as builder,
        ):
            result = read_surface.grabowski_git_status(
                str(repo), include_branch_preimage=True
            )
        self.assertEqual(
            result["branch_preimage"]["kind"], "grabowski_git_branch_preimage"
        )
        self.assertEqual(result["branch_preimage"]["preimage_sha256"], "c" * 64)
        self.assertEqual(builder.call_args.args[0], repo)

    def test_git_status_preimage_still_enforces_read_policy(self) -> None:
        with patch.object(
            read_surface.base,
            "_resolve_existing",
            side_effect=PermissionError("Path is outside allowed roots"),
        ):
            with self.assertRaisesRegex(PermissionError, "outside allowed roots"):
                read_surface.grabowski_git_status(
                    "/tmp/private-repo", include_branch_preimage=True
                )

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
        with patch.object(
            read_surface, "_resolve_repository", return_value=repo
        ), patch.object(
            read_surface, "_resolve_revision", return_value=object_id
        ) as resolver, patch.object(
            read_surface, "_run_read", return_value={"returncode": 0}
        ) as runner:
            result = read_surface.grabowski_git_show(
                str(repo), revision="HEAD~1"
            )
        self.assertEqual(resolver.call_count, 2)
        resolver.assert_any_call(repo, "HEAD~1")
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-2:], [object_id, "--"])
        self.assertIn("--no-ext-diff", argv)
        self.assertIn("--no-textconv", argv)
        self.assertEqual(
            result["revision_binding"],
            {
                "requested_revision": "HEAD~1",
                "output_object_id": object_id,
                "readback_object_id": object_id,
                "readback_status": "stable",
                "stable": True,
            },
        )

    def test_git_show_reports_ref_movement_after_immutable_read(self) -> None:
        repo = Path("/tmp/repository")
        output_object = "c" * 40
        moved_object = "d" * 40
        with patch.object(
            read_surface, "_resolve_repository", return_value=repo
        ), patch.object(
            read_surface,
            "_resolve_revision",
            side_effect=[output_object, moved_object],
        ), patch.object(
            read_surface,
            "_run_read",
            return_value={"returncode": 0},
        ):
            result = read_surface.grabowski_git_show(
                str(repo), revision="refs/heads/main"
            )
        self.assertEqual(
            result["revision_binding"],
            {
                "requested_revision": "refs/heads/main",
                "output_object_id": output_object,
                "readback_object_id": moved_object,
                "readback_status": "moved",
                "stable": False,
            },
        )

    def test_git_show_reports_unresolvable_post_read_ref(self) -> None:
        repo = Path("/tmp/repository")
        output_object = "e" * 40
        with patch.object(
            read_surface, "_resolve_repository", return_value=repo
        ), patch.object(
            read_surface,
            "_resolve_revision",
            side_effect=[output_object, ValueError("gone")],
        ), patch.object(
            read_surface,
            "_run_read",
            return_value={"returncode": 0},
        ):
            result = read_surface.grabowski_git_show(
                str(repo), revision="refs/heads/topic"
            )
        binding = result["revision_binding"]
        self.assertEqual(binding["output_object_id"], output_object)
        self.assertIsNone(binding["readback_object_id"])
        self.assertEqual(binding["readback_status"], "unresolvable")
        self.assertFalse(binding["stable"])

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
                "bureau_retryable": True,
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
                "bureau_retryable": False,
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
        self.assertEqual(result["signal_projection"]["projection_kind"], "audit-signal.v1")
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
        self.assertEqual(
            result["windows"][0]["resource_activity"][
                "reclamation_unattributed_resource_count"
            ],
            2,
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
        self.assertEqual(
            result["candidate_patterns"][0]["failure_retryable_count_7d"], 1
        )
        self.assertEqual(
            result["candidate_patterns"][0]["failure_nonretryable_count_7d"], 1
        )
        self.assertEqual(
            result["candidate_patterns"][0][
                "failure_retryability_unknown_count_7d"
            ],
            1,
        )
        self.assertAlmostEqual(
            result["candidate_patterns"][0]["failure_retryability_coverage"],
            2 / 3,
            places=6,
        )
        self.assertNotIn(
            "publication-complete",
            json.dumps(result["windows"][0]["top_bureau_failure_codes"]),
        )
        self.assertEqual(result["candidate_patterns"][0]["authority"], "proposal_only")
        identity = result["windows"][0]["bureau_failure_identity"]
        self.assertEqual(identity["failure_record_count"], 3)
        self.assertEqual(identity["complete_identity_count"], 0)
        self.assertEqual(identity["partial_identity_count"], 0)
        self.assertEqual(identity["unknown_identity_count"], 3)
        self.assertEqual(identity["exact_identity_coverage"], 0.0)
        self.assertEqual(
            result["candidate_patterns"][0]["failure_identity_unknown_count_7d"],
            3,
        )
        self.assertEqual(result["candidate_patterns"][0]["failure_identity_coverage"], 0.0)
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
        self.assertEqual(activity["reclamation_self_resource_count"], 0)
        self.assertEqual(activity["reclamation_foreign_resource_count"], 0)
        self.assertEqual(activity["reclamation_unattributed_resource_count"], 6)
        candidate = next(
            item
            for item in result["candidate_patterns"]
            if item["pattern"] == "repeated_resource_reclamation"
        )
        self.assertEqual(candidate["event_count_7d"], 3)
        self.assertEqual(candidate["reclaimed_resource_count_7d"], 6)
        self.assertEqual(candidate["same_owner_reclaimed_resource_count_7d"], 0)
        self.assertEqual(candidate["foreign_owner_reclaimed_resource_count_7d"], 0)
        self.assertEqual(candidate["unattributed_reclaimed_resource_count_7d"], 6)
        self.assertEqual(candidate["reclamation_attribution_coverage"], 0.0)

    def test_audit_projection_attributes_reclamation_without_exposing_owners(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": "resource-acquire",
                "timestamp": datetime.fromtimestamp(
                    now - 60, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "1" * 64,
                "owner_id": "lane:self-a",
                "resource_keys": ["path:/safe/a", "path:/safe/b"],
                "reclaimed_count": 2,
                "reclamation_evidence": [
                    {"resource_index": 0, "previous_owner_id": "lane:self-a"},
                    {"resource_index": 1, "previous_owner_id": "lane:foreign-a"},
                ],
            },
            {
                "operation": "resource-acquire",
                "timestamp": datetime.fromtimestamp(
                    now - 120, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "2" * 64,
                "owner_id": "lane:new-b",
                "resource_keys": ["path:/safe/c", "path:/safe/d"],
                "reclaimed_count": 2,
                "reclamation_evidence": [
                    {"resource_index": 0, "previous_owner_id": "lane:foreign-b"},
                    {"resource_index": 0, "previous_owner_id": "lane:duplicate"},
                    {"resource_index": True, "previous_owner_id": "lane:invalid"},
                    {"resource_index": 4, "previous_owner_id": "lane:out-of-range"},
                ],
            },
            {
                "operation": "resource-acquire",
                "timestamp": datetime.fromtimestamp(
                    now - 180, tz=timezone.utc
                ).isoformat(),
                "record_sha256": "3" * 64,
                "owner_id": "lane:self-c",
                "resource_keys": ["path:/safe/e"],
                "reclaimed_count": 1,
                "reclamation_evidence": [
                    {"resource_index": 0, "previous_owner_id": "lane:self-c"},
                ],
            },
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
            result = read_surface.grabowski_audit_projection(view="evidence")
        activity = result["windows"][0]["resource_activity"]
        self.assertEqual(activity["reclaimed_resource_count"], 5)
        self.assertEqual(activity["reclamation_self_resource_count"], 2)
        self.assertEqual(activity["reclamation_foreign_resource_count"], 2)
        self.assertEqual(activity["reclamation_unattributed_resource_count"], 1)
        candidate = next(
            item
            for item in result["candidate_patterns"]
            if item["pattern"] == "repeated_resource_reclamation"
        )
        self.assertEqual(candidate["same_owner_reclaimed_resource_count_7d"], 2)
        self.assertEqual(candidate["foreign_owner_reclaimed_resource_count_7d"], 2)
        self.assertEqual(candidate["unattributed_reclaimed_resource_count_7d"], 1)
        self.assertEqual(candidate["reclamation_attribution_coverage"], 0.8)
        self.assertIn("unattributed", candidate["recommendation"])
        encoded = json.dumps(result)
        self.assertNotIn("lane:self-a", encoded)
        self.assertNotIn("lane:foreign-a", encoded)

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

    def test_audit_projection_findings_hash_is_presentation_independent(self) -> None:
        now = 1_800_000_000
        records = [
            {
                "operation": operation,
                "timestamp": datetime.fromtimestamp(
                    now - offset, tz=timezone.utc
                ).isoformat(),
                "record_sha256": f"{index:064x}",
            }
            for index, (operation, offset) in enumerate(
                (("task-start", 60), ("resource-acquire", 120), ("friction-record", 180)),
                start=1,
            )
        ]
        status = {
            "valid": True,
            "total_records": len(records),
            "total_legacy_records": 0,
            "last_record_sha256": records[-1]["record_sha256"],
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
            minimal = read_surface.grabowski_audit_projection(
                view="minimal", top_limit=1
            )
            evidence = read_surface.grabowski_audit_projection(
                view="evidence", top_limit=25
            )
        self.assertEqual(minimal["findings_sha256"], evidence["findings_sha256"])
        self.assertNotEqual(minimal["projection_sha256"], evidence["projection_sha256"])

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
        self.assertIn("projection_sha256", projected)
        self.assertEqual(projected["findings_sha256"], minimal["findings_sha256"])
        self.assertEqual(projected["projection_sha256"], minimal["projection_sha256"])
        self.assertNotIn("windows", projected)
        self.assertIn("source_binding", projected)
        self.assertIn("windows", projected["projection"]["omitted_fields"])
        self.assertIn(
            "projection_sha256", projected["projection"]["required_fields_preserved"]
        )

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


class BureauFailureIdentityProjectionTests(unittest.TestCase):
    @staticmethod
    def _schema(command: str, direction: str) -> dict[str, str]:
        material = {
            "schema_version": 1,
            "surface": "grabowski_bureau_intake",
            "command": command,
            "mode": "call",
            "direction": direction,
        }
        return {
            "id": f"grabowski_bureau_intake.{command}.call.{direction}.v1",
            "sha256": read_surface._audit_identity_sha256(material),
        }

    @classmethod
    def _contract_identity(
        cls,
        *,
        source_commit: str | None,
        command: str = "operator-candidate-record",
    ) -> dict:
        if source_commit is None:
            runtime = {"status": "unknown"}
            completeness = "partial"
        else:
            runtime_material = {
                "status": "observed",
                "source_commit": source_commit,
                "registry_tree_sha256": "b" * 64,
                "launcher_sha256": "c" * 64,
                "manifest_sha256": "d" * 64,
                "inventory_sha256": "e" * 64,
            }
            runtime = {
                **runtime_material,
                "identity_sha256": read_surface._audit_identity_sha256(runtime_material),
            }
            completeness = "complete"
        material = {
            "schema_version": 1,
            "kind": "grabowski_bureau_contract_identity",
            "completeness": completeness,
            "adapter": {
                "surface": "grabowski_bureau_intake",
                "schema_version": 1,
                "command": command,
                "mode": "call",
            },
            "runtime": runtime,
            "request_schema": cls._schema(command, "request"),
            "result_schema": cls._schema(command, "result"),
        }
        return {
            **material,
            "identity_sha256": read_surface._audit_identity_sha256(material),
        }

    @classmethod
    def _record(
        cls,
        *,
        now: int,
        seconds_ago: int,
        source_commit: str | None,
        code: str = "request-schema-unsupported",
        result_kind: str = "bureau_operator_intake_failure",
    ) -> dict:
        operation = "bureau-candidate-record"
        identity = cls._contract_identity(source_commit=source_commit)
        result_schema_material = {"kind": result_kind, "schema_version": 1}
        result_schema_identity = {
            **result_schema_material,
            "sha256": read_surface._audit_identity_sha256(result_schema_material),
        }
        failure_material = {
            "schema_version": 1,
            "caller_surface": operation,
            "contract_identity_sha256": identity["identity_sha256"],
            "result_schema_identity_sha256": result_schema_identity["sha256"],
        }
        return {
            "operation": operation,
            "timestamp": datetime.fromtimestamp(
                now - seconds_ago, tz=timezone.utc
            ).isoformat(),
            "record_sha256": hashlib.sha256(
                f"{seconds_ago}:{source_commit}".encode()
            ).hexdigest(),
            "bureau_status": "failed",
            "bureau_code": code,
            "bureau_retryable": False,
            "effect_started": False,
            "bureau_failure_identity_schema_version": 1,
            "bureau_caller_surface": operation,
            "bureau_contract_identity": identity,
            "bureau_result_schema_identity": result_schema_identity,
            "bureau_failure_identity_sha256": read_surface._audit_identity_sha256(
                failure_material
            ),
        }

    @staticmethod
    def _project(records: list[dict], now: int) -> dict:
        status = {
            "valid": True,
            "total_records": len(records),
            "total_legacy_records": 0,
            "last_record_sha256": records[-1]["record_sha256"],
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
            return read_surface.grabowski_audit_projection(
                view="standard", top_limit=10
            )

    def test_same_code_with_distinct_runtime_identities_stays_two_groups(self) -> None:
        now = 1_800_000_000
        records = [
            self._record(now=now, seconds_ago=60, source_commit="a" * 40),
            self._record(now=now, seconds_ago=120, source_commit="a" * 40),
            self._record(now=now, seconds_ago=180, source_commit="f" * 40),
            self._record(now=now, seconds_ago=240, source_commit="f" * 40),
        ]
        result = self._project(records, now)
        summary = result["windows"][0]["bureau_failure_identity"]
        pattern = result["candidate_patterns"][0]

        self.assertEqual(summary["complete_identity_count"], 4)
        self.assertEqual(summary["unknown_identity_count"], 0)
        self.assertEqual(summary["exact_identity_coverage"], 1.0)
        self.assertEqual(summary["exact_identity_group_count"], 2)
        self.assertEqual(len(summary["top_exact_identity_groups"]), 2)
        self.assertEqual(pattern["failure_identity_group_count_7d"], 2)
        self.assertEqual(len(pattern["top_identity_groups"]), 2)
        self.assertEqual(
            {group["runtime"]["source_commit"] for group in pattern["top_identity_groups"]},
            {"a" * 40, "f" * 40},
        )
        self.assertNotIn("/", json.dumps(pattern["top_identity_groups"], sort_keys=True))

    def test_exact_identity_projects_bounded_failure_reason_classes(self) -> None:
        now = 1_800_000_000
        reasons = [
            "candidate request contains unknown fields",
            "candidate request contains unknown fields",
            "live register repo must be a repo.* resource",
            "unknown live register task SECRET-TASK-ID",
            "task JSON does not have an executable typed acceptance contract: task SECRET-TASK-ID criterion SECRET-CRITERION",
            "publishing task SECRET-TASK-ID is not in the authoritative StateStore",
            "unknown initiative SECRET-INITIATIVE",
            None,
        ]
        records = [
            self._record(
                now=now,
                seconds_ago=(index + 1) * 60,
                source_commit="a" * 40,
                code="candidate-record-invalid",
            )
            for index in range(len(reasons))
        ]
        for record, reason in zip(records, reasons, strict=True):
            if reason is not None:
                record["bureau_failure_reason"] = reason

        result = self._project(records, now)
        summary_group = result["windows"][0]["bureau_failure_identity"][
            "top_exact_identity_groups"
        ][0]
        pattern_group = result["candidate_patterns"][0]["top_identity_groups"][0]

        for group in (summary_group, pattern_group):
            self.assertEqual(group["failure_reason_class_count"], 6)
            self.assertEqual(group["failure_reason_attributed_count"], 7)
            self.assertEqual(group["failure_reason_unknown_count"], 1)
            self.assertEqual(group["failure_reason_coverage"], 0.875)
            self.assertEqual(len(group["top_failure_reason_classes"]), 5)
            self.assertEqual(
                group["top_failure_reason_classes"][0],
                {"reason": "candidate request contains unknown fields", "count": 2},
            )
            public_json = json.dumps(group, sort_keys=True)
            self.assertNotIn("SECRET-TASK-ID", public_json)
            self.assertNotIn("SECRET-CRITERION", public_json)
            self.assertNotIn("SECRET-INITIATIVE", public_json)
            self.assertNotIn("failure_reason_counts", group)

    def test_unclassified_failure_reason_falls_back_without_raw_identity_leak(self) -> None:
        now = 1_800_000_000
        raw_reason = "unexpected /home/alex/repos/SECRET-REPO task SECRET-TASK-ID"
        records = [
            self._record(
                now=now,
                seconds_ago=(index + 1) * 60,
                source_commit="a" * 40,
                code="candidate-record-invalid",
            )
            for index in range(4)
        ]
        for record in records[:3]:
            record["bureau_failure_reason"] = raw_reason

        result = self._project(records, now)
        summary_group = result["windows"][0]["bureau_failure_identity"][
            "top_exact_identity_groups"
        ][0]
        pattern_group = result["candidate_patterns"][0]["top_identity_groups"][0]

        for group in (summary_group, pattern_group):
            self.assertEqual(group["failure_reason_class_count"], 1)
            self.assertEqual(group["failure_reason_attributed_count"], 3)
            self.assertEqual(group["failure_reason_unknown_count"], 1)
            self.assertEqual(group["failure_reason_coverage"], 0.75)
            self.assertEqual(
                group["top_failure_reason_classes"],
                [{"reason": "bureau code: candidate-record-invalid", "count": 3}],
            )
            public_json = json.dumps(group, sort_keys=True)
            self.assertNotIn("SECRET-REPO", public_json)
            self.assertNotIn("SECRET-TASK-ID", public_json)
            self.assertNotIn("/home/alex/repos", public_json)

    def test_same_runtime_with_distinct_result_schema_families_stays_two_groups(self) -> None:
        now = 1_800_000_000
        records = [
            self._record(
                now=now,
                seconds_ago=60,
                source_commit="a" * 40,
                result_kind="bureau_operator_intake_failure",
            ),
            self._record(
                now=now,
                seconds_ago=120,
                source_commit="a" * 40,
                result_kind="grabowski_bureau_intake_adapter_failure",
            ),
            self._record(
                now=now,
                seconds_ago=180,
                source_commit="a" * 40,
                result_kind="bureau_operator_intake_failure",
            ),
        ]
        result = self._project(records, now)
        summary = result["windows"][0]["bureau_failure_identity"]

        self.assertEqual(summary["complete_identity_count"], 3)
        self.assertEqual(summary["exact_identity_group_count"], 2)
        self.assertEqual(
            {
                group["result_payload_schema"]["kind"]
                for group in summary["top_exact_identity_groups"]
            },
            {
                "bureau_operator_intake_failure",
                "grabowski_bureau_intake_adapter_failure",
            },
        )

    def test_partial_identity_is_not_counted_as_exact(self) -> None:
        now = 1_800_000_000
        result = self._project(
            [self._record(now=now, seconds_ago=60, source_commit=None)],
            now,
        )
        summary = result["windows"][0]["bureau_failure_identity"]

        self.assertEqual(summary["failure_record_count"], 1)
        self.assertEqual(summary["complete_identity_count"], 0)
        self.assertEqual(summary["partial_identity_count"], 1)
        self.assertEqual(summary["unknown_identity_count"], 0)
        self.assertEqual(summary["exact_identity_coverage"], 0.0)
        self.assertEqual(summary["exact_identity_group_count"], 0)

    def test_malformed_identity_is_conservatively_unknown(self) -> None:
        now = 1_800_000_000
        record = self._record(now=now, seconds_ago=60, source_commit="a" * 40)
        record["bureau_contract_identity"]["runtime"]["manifest_sha256"] = "0" * 64
        result = self._project([record], now)
        summary = result["windows"][0]["bureau_failure_identity"]

        self.assertEqual(summary["complete_identity_count"], 0)
        self.assertEqual(summary["partial_identity_count"], 0)
        self.assertEqual(summary["unknown_identity_count"], 1)
        self.assertEqual(summary["identity_group_count"], 0)



if __name__ == "__main__":
    unittest.main()
