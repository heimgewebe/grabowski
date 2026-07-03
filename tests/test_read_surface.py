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



# PR review gate tests live here to avoid relying on tool-file discovery in older runtimes.
def _load_pr_review_gate():
    spec = importlib.util.spec_from_file_location("pr_review_gate_test", ROOT / "tools" / "pr_review_gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load pr_review_gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

pr_review_gate = _load_pr_review_gate()
REVIEW_GATE_HEAD = "a" * 40
REVIEW_GATE_BASE = "b" * 40


def _review_gate_checks(*, py310="pass", py312="pass"):
    return [
        {"bucket": py310, "name": "validate (3.10)"},
        {"bucket": py312, "name": "validate (3.12)"},
    ]


def _review_gate_state(*, files=None, additions=10, deletions=2, reviews=None, checks=None, mergeable="MERGEABLE", merge_state="CLEAN"):
    default_files = files if files is not None else ["src/example.py"]
    default_reviews = [{"author": {"login": "chatgpt-codex-connector"}, "body": "reviewed", "commit_id": REVIEW_GATE_HEAD}]
    return {
        "pr": {
            "number": 12,
            "title": "review gate",
            "state": "OPEN",
            "isDraft": False,
            "mergeStateStatus": merge_state,
            "headRefOid": REVIEW_GATE_HEAD,
            "baseRefOid": REVIEW_GATE_BASE,
            "mergeable": mergeable,
            "changedFiles": len(default_files),
            "additions": additions,
            "deletions": deletions,
            "files": [{"path": path} for path in default_files],
            "reviews": reviews if reviews is not None else default_reviews,
            "latestReviews": [],
            "comments": [],
        },
        "checks": checks if checks is not None else _review_gate_checks(),
    }


def _review_gate_self_review(**overrides):
    payload = {
        "head_sha": REVIEW_GATE_HEAD,
        "diff_reviewed": True,
        "all_findings_triaged": True,
        "review_iterations": [{"n": 1, "summary": "reviewed", "material_findings": 0}],
        "stop_reason": "clean_pass",
        "findings": [],
        "material_findings_remaining": 0,
        "claude_review": {"required": False, "reason": "small low-risk diff"},
    }
    payload.update(overrides)
    return payload


class PrReviewGateTests(unittest.TestCase):
    def test_blocks_low_severity_findings_without_terminal_state(self) -> None:
        review = _review_gate_self_review(findings=[{"id": "p3", "severity": "p3", "status": "fixed"}, {"id": "info", "severity": "info", "status": "untriaged"}])
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("finding 1 is not terminally triaged", result["failures"])

    def test_passes_when_all_findings_are_terminally_triaged(self) -> None:
        review = _review_gate_self_review(findings=[{"id": "p2", "severity": "p2", "status": "fixed"}, {"id": "docs", "severity": "info", "status": "deferred_with_reason", "reason": "follow-up docs slice"}])
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=review)
        self.assertEqual(result["verdict"], "PASS")

    def test_blocks_without_iterative_self_review(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=_review_gate_self_review(review_iterations=[]))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review has no review_iterations", result["failures"])

    def test_blocks_complex_pr_without_claude_review(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(files=["src/grabowski_runtime.py"], additions=700, deletions=1), self_review=_review_gate_self_review(claude_review={"required": False, "reason": "claimed small"}))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("Claude review is required but not observed on current head", result["failures"])

    def test_head_sha_must_match(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=_review_gate_self_review(head_sha="c" * 40))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("self-review head_sha mismatch", result["failures"])

    def test_failing_checks_block(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=_review_gate_checks(py312="fail")), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])


class PrReviewGateCommentSourceTests(unittest.TestCase):
    def test_comment_sources_count_for_codex(self) -> None:
        current = _review_gate_state(reviews=[])
        current["reviewComments"] = [{"user": {"login": "chatgpt-codex-connector"}, "body": "reviewed", "commit_id": REVIEW_GATE_HEAD}]
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["codex_seen"])

    def test_rest_pr_review_commit_id_counts_for_codex(self) -> None:
        current = _review_gate_state(reviews=[])
        current["prReviews"] = [{"user": {"login": "chatgpt-codex-connector"}, "body": "reviewed", "commit_id": REVIEW_GATE_HEAD}]
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["codex_seen"])


class PrReviewGateClaudeFindingTests(unittest.TestCase):
    def test_p1_accepted_without_fix_still_blocks(self) -> None:
        review = _review_gate_self_review(findings=[{"id": "sev", "severity": "p1", "status": "accepted", "reason": "known risk"}])
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("finding 0 is not terminally triaged", result["failures"])

    def test_missing_head_sha_blocks(self) -> None:
        current = _review_gate_state()
        current["pr"].pop("headRefOid")
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("PR headRefOid is missing", result["failures"])

    def test_zero_checks_block(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=[]), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("no status checks observed", result["failures"])


class PrReviewGateCancelTests(unittest.TestCase):
    def test_cancelled_checks_block(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=_review_gate_checks(py312="cancel")), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])


class PrReviewGatePaginationTests(unittest.TestCase):
    def test_load_state_flattens_comment_and_review_pages(self) -> None:
        calls = [
            {"number": 58, "reviews": [], "latestReviews": [], "comments": []},
            _review_gate_checks(),
            {"nameWithOwner": "heimgewebe/grabowski"},
            [[{"id": 1}], [{"id": 2}]],
            [[{"id": 3, "commit_id": REVIEW_GATE_HEAD}]],
        ]
        with patch.object(pr_review_gate, "_run_json", side_effect=calls) as mocked:
            result = pr_review_gate.load_pr_state(Path("/tmp"), 58)
        self.assertEqual(result["reviewComments"], [{"id": 1}, {"id": 2}])
        self.assertEqual(result["prReviews"], [{"id": 3, "commit_id": REVIEW_GATE_HEAD}])
        self.assertIn('--slurp', mocked.call_args_list[-2].args[1])
        self.assertIn('--slurp', mocked.call_args_list[-1].args[1])

class PrReviewGateTrustedSourceTests(unittest.TestCase):
    def test_comment_text_is_not_codex_source(self) -> None:
        current = _review_gate_state()
        current["pr"]["rev"+"iews"] = []
        current["pr"]["comments"] = [{"author": {"login": "alexdermohr"}, "body": "chatgpt-" + "codex"}]
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["codex_seen"])

    def test_comment_text_is_not_claude_source(self) -> None:
        current = _review_gate_state(files=["src/grabowski_runtime.py"], additions=700, deletions=1)
        current["pr"]["comments"] = [{"author": {"login": "alexdermohr"}, "body": "cla" + "ude"}]
        review = _review_gate_self_review(claude_review={"required": False, "reason": "claimed small"})
        result = pr_review_gate.evaluate_review_gate(current, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["claude_seen"])

    def test_skipping_checks_block(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=_review_gate_checks(py312="skipping")), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("1 non-green check(s)", result["failures"])


class PrReviewGateCurrentHeadEvidenceTests(unittest.TestCase):
    def test_old_codex_review_does_not_satisfy_current_head(self) -> None:
        current = _review_gate_state()
        current["pr"]["reviews"] = [{"author": {"login": "chatgpt-codex-connector"}, "commit": {"oid": "d" * 40}}]
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["codex_seen"])
        self.assertIn("Codex review was not observed", result["failures"])

    def test_self_reported_claude_collection_does_not_satisfy_complex_pr(self) -> None:
        current = _review_gate_state(files=["src/grabowski_runtime.py"], additions=700, deletions=1)
        current["pr"]["reviews"] = [{"author": {"login": "chatgpt-codex-connector"}, "commit": {"oid": REVIEW_GATE_HEAD}}]
        review = _review_gate_self_review(claude_review={"required": True, "collected": True, "reason": "self reported"})
        result = pr_review_gate.evaluate_review_gate(current, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["claude_seen"])
        self.assertIn("Claude review is required but not observed on current head", result["failures"])

    def test_current_head_claude_actor_satisfies_complex_pr(self) -> None:
        current = _review_gate_state(files=["src/grabowski_runtime.py"], additions=700, deletions=1)
        current["pr"]["reviews"] = [
            {"author": {"login": "chatgpt-codex-connector"}, "commit": {"oid": REVIEW_GATE_HEAD}},
            {"author": {"login": "claude-code[bot]"}, "commit": {"oid": REVIEW_GATE_HEAD}},
        ]
        review = _review_gate_self_review(claude_review={"required": True, "reason": "complex"})
        result = pr_review_gate.evaluate_review_gate(current, self_review=review)
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["review_sources"]["claude_seen"])

class PrReviewGateRiskPathTests(unittest.TestCase):
    def test_core_grabowski_paths_require_independent_review(self) -> None:
        for path in (
            "src/grabowski_mcp.py",
            "src/grabowski_operator.py",
            "src/grabowski_privileged.py",
            "tools/pr_review_gate.py",
        ):
            with self.subTest(path=path):
                current = _review_gate_state(files=[path], additions=3, deletions=1)
                review = _review_gate_self_review(claude_review={"required": False, "reason": "small diff"})
                result = pr_review_gate.evaluate_review_gate(current, self_review=review)
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn("risk path touched", result["complexity"]["reasons"])
                self.assertIn("Claude review is required but not observed on current head", result["failures"])

class PrReviewGateStateAndCheckTests(unittest.TestCase):
    def test_trusted_codex_changes_requested_blocks(self) -> None:
        current = _review_gate_state(reviews=[{"author": {"login": "chatgpt-codex-connector"}, "commit_id": REVIEW_GATE_HEAD, "state": "CHANGES_REQUESTED"}])
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["codex_seen"])
        self.assertIn("Codex review has blocking state(s): CHANGES_REQUESTED", result["failures"])

    def test_required_claude_pending_blocks(self) -> None:
        current = _review_gate_state(reviews=[
            {"author": {"login": "chatgpt-codex-connector"}, "commit_id": REVIEW_GATE_HEAD},
            {"author": {"login": "claude-code[bot]"}, "commit_id": REVIEW_GATE_HEAD, "state": "PENDING"},
        ])
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review(claude_review={"required": True, "reason": "risk"}))
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["claude_seen"])
        self.assertIn("Claude review has blocking state(s): PENDING", result["failures"])

    def test_untrusted_actor_with_codex_name_does_not_count(self) -> None:
        current = _review_gate_state(reviews=[{"author": {"login": "not-chatgpt-codex-connector"}, "commit_id": REVIEW_GATE_HEAD}])
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["codex_seen"])
        self.assertIn("Codex review was not observed", result["failures"])

    def test_missing_expected_matrix_check_blocks(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=[{"bucket": "pass", "name": "validate (3.10)"}]), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("expected check(s) missing: validate (3.12)", result["failures"])

    def test_expected_matrix_checks_pass_without_missing_check_block(self) -> None:
        result = pr_review_gate.evaluate_review_gate(_review_gate_state(), self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "PASS")
        self.assertFalse(any("expected check(s) missing" in failure for failure in result["failures"]))

    def test_expected_py312_non_pass_states_block(self) -> None:
        for bucket in ("fail", "pending", "cancel", "skipping"):
            with self.subTest(bucket=bucket):
                result = pr_review_gate.evaluate_review_gate(_review_gate_state(checks=_review_gate_checks(py312=bucket)), self_review=_review_gate_self_review())
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn("1 non-green check(s)", result["failures"])


    def test_missing_merge_metadata_blocks(self) -> None:
        current = _review_gate_state()
        current["pr"].pop("mergeStateStatus")
        current["pr"].pop("mergeable")
        result = pr_review_gate.evaluate_review_gate(current, self_review=_review_gate_self_review())
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertIn("GitHub mergeStateStatus is None, not CLEAN", result["failures"])
        self.assertIn("GitHub mergeable is None, not MERGEABLE", result["failures"])

    def test_bare_claude_login_does_not_satisfy_complex_pr(self) -> None:
        current = _review_gate_state(files=["src/grabowski_runtime.py"], additions=700, deletions=1)
        current["pr"]["reviews"] = [
            {"author": {"login": "chatgpt-codex-connector"}, "commit": {"oid": REVIEW_GATE_HEAD}},
            {"author": {"login": "claude-code"}, "commit": {"oid": REVIEW_GATE_HEAD}},
        ]
        review = _review_gate_self_review(claude_review={"required": True, "reason": "complex"})
        result = pr_review_gate.evaluate_review_gate(current, self_review=review)
        self.assertEqual(result["verdict"], "BLOCK")
        self.assertFalse(result["review_sources"]["claude_seen"])
        self.assertIn("Claude review is required but not observed on current head", result["failures"])

    def test_mergeable_conflicting_or_unknown_blocks(self) -> None:
        for mergeable in ("CONFLICTING", "UNKNOWN"):
            with self.subTest(mergeable=mergeable):
                result = pr_review_gate.evaluate_review_gate(_review_gate_state(mergeable=mergeable), self_review=_review_gate_self_review())
                self.assertEqual(result["verdict"], "BLOCK")
                self.assertIn(f"GitHub mergeable is {mergeable}, not MERGEABLE", result["failures"])


if __name__ == "__main__":
    unittest.main()
