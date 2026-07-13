from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_agent_role as role
import grabowski_agent_sandbox as sandbox
import grabowski_agent_workspace as workspace
import grabowski_agent_writer as writer


def run(cwd: Path, *argv: str) -> str:
    return subprocess.check_output(list(argv), cwd=cwd, text=True).strip()


def binding_evidence(kind: str, identifier: str) -> dict:
    return {
        "source": "test",
        "kind": kind,
        "id": identifier,
        "evidence_sha256": "e" * 64,
    }


def complete_route_evidence() -> dict:
    facts = {
        "task_kind": "code",
        "changed_file_estimate": 7,
        "expected_duration_minutes": 120,
        "novelty": "high",
        "risk_flags": ["concurrency", "schema"],
        "connector_instability": True,
        "parallel_work": True,
        "user_requested_external": False,
        "available_external_agents": [],
    }
    recommendation = {
        "schema_version": 1,
        "score": 14,
        "execution_mode": "full_workspace",
        "input_facts": facts,
        "external_candidates": [],
    }
    return {
        "schema_version": 1,
        "recommendation_id": workspace._sha256_json(recommendation),
        "score": recommendation["score"],
        "recommended_route": recommendation["execution_mode"],
        "actual_route": "full_workspace",
        "input_facts": facts,
        "external_candidates": [],
        "deviation_reason": None,
    }


def signed_receipt(payload: dict) -> dict:
    result = dict(payload)
    result["receipt_sha256"] = workspace._sha256_json(result)
    return result


def persist_collection(manifest: dict, payload: dict) -> dict:
    result = dict(payload)
    result["tests"] = {
        "status": "passed",
        "receipt_sha256": "a" * 64,
        "returncode": 0,
        **(result.get("tests") if isinstance(result.get("tests"), dict) else {}),
    }
    result["review"] = {
        "status": "passed",
        "returncode": 0,
        "verdict": "PASS",
        "findings": [],
        "receipt_sha256": "b" * 64,
        **(result.get("review") if isinstance(result.get("review"), dict) else {}),
    }
    result["state"] = "complete"
    result["result_sha256"] = workspace._collection_result_sha256(result)
    manifest["collection"] = result
    workspace._write_manifest(manifest)
    workspace._atomic_json(
        workspace._workspace_dir(manifest["workspace_id"]) / "collection-receipt.json",
        result,
    )
    return result


def signed_role_receipt(
    role_name: str,
    manifest: dict,
    snapshot: dict,
    **overrides,
) -> dict:
    payload = {
        "role": role_name,
        "expected_head": snapshot["writer_head"],
        "expected_base_head": manifest["expected_base_head"],
        "expected_diff_sha256": snapshot["diff_sha256"],
        "expected_dirty": snapshot["dirty"],
        "head_before": snapshot["writer_head"],
        "head_after": snapshot["writer_head"],
        "diff_after": snapshot["diff_sha256"],
        "worktree_dirty_after": snapshot["dirty"],
        "argv_sha256": workspace._sha256_json(manifest["commands"][role_name]),
        "sandbox": "bubblewrap-minimal-root-read-only-worktree-v1",
        "returncode": 0,
    }
    if role_name == "review":
        payload.update({"verdict": "PASS", "findings": []})
    payload.update(overrides)
    return signed_receipt(payload)


def passing_toolchain_preflight(manifest: dict, role_name: str, command: list[str]) -> dict:
    del manifest
    return {
        "role": role_name,
        "command_sha256": workspace._sha256_json(command),
        "checked_at": "test",
        "sandbox": role.SANDBOX_LABEL,
        "executable": command[0],
        "declared_python_module": role.declared_python_module(command),
        "passed": True,
        "missing_executable": False,
        "missing_python_module": False,
        "probe_error": None,
        "probe_returncode": 0,
        "failure_classification": "passed",
    }


def missing_module_preflight(manifest: dict, role_name: str, command: list[str]) -> dict:
    result = passing_toolchain_preflight(manifest, role_name, command)
    result.update(
        {
            "passed": False,
            "missing_python_module": True,
            "failure_classification": "environment_toolchain_failure",
        }
    )
    return result


class GitFixture:
    def __init__(self, root: Path) -> None:
        self.repo = root / "repo"
        self.writer = root / "writer"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
        (self.repo / "tests" / "test_app.py").write_text("def test_ok(): assert True\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "base"], cwd=self.repo, check=True, stdout=subprocess.PIPE)
        self.base = run(self.repo, "git", "rev-parse", "HEAD")

    def add_writer(self, branch: str = "feat/writer") -> None:
        subprocess.run(
            ["git", "worktree", "add", "-b", branch, str(self.writer), self.base],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
        )

    def commit_writer(self, path: str = "src/app.py", content: str = "value = 2\n") -> str:
        target = self.writer / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", path], cwd=self.writer, check=True)
        subprocess.run(["git", "commit", "-m", "writer"], cwd=self.writer, check=True, stdout=subprocess.PIPE)
        return run(self.writer, "git", "rev-parse", "HEAD")


class AgentWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git = GitFixture(self.root)
        self.state = self.root / "state"
        self.state.mkdir()
        self.root_patch = mock.patch.object(workspace, "WORKSPACE_ROOT", self.state)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.real_role_toolchain_preflight = workspace._role_toolchain_preflight
        self.preflight_patch = mock.patch.object(
            workspace,
            "_role_toolchain_preflight",
            side_effect=passing_toolchain_preflight,
        )
        self.preflight_patch.start()
        self.addCleanup(self.preflight_patch.stop)
        self.addCleanup(self.temp.cleanup)

    def manifest(self, *, with_writer: bool = True) -> dict:
        if with_writer and not self.git.writer.exists():
            self.git.add_writer()
        identifier, session = workspace._workspace_identity(
            "thread_focus", "thread-1", self.git.repo, self.git.base
        )
        directory = self.state / identifier
        directory.mkdir(parents=True, exist_ok=True)
        value = {
            "schema_version": 1,
            "creation_state": "ready",
            "workspace_id": identifier,
            "session_name": session,
            "binding": {"kind": "thread_focus", "id": "thread-1"},
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/writer",
            "writer_worktree": str(self.git.writer),
            "scope": {"allowed_paths": ["src"], "forbidden_paths": ["secrets"]},
            "commands": {
                "writer": ["python3", "writer.py"],
                "tests": ["python3", "-c", "print('ok')"],
                "review": ["python3", "-c", "print('{\"verdict\":\"PASS\",\"findings\":[]}')"],
            },
            "roles": {
                "captain": {"access": "integrator_control", "merge_authority": False},
                "writer": {"access": "write_worktree", "merge_authority": False},
                "tests": {"access": "read_only", "merge_authority": False},
                "review": {"access": "read_only", "merge_authority": False},
            },
            "resources": {
                "owner_id": f"agent-workspace:{identifier}",
                "lease_keys": [f"service:agent-workspace-{identifier}"],
                "runtime_seconds": 600,
                "memory_max_bytes": None,
                "task_host": workspace.AGENT_WORKSPACE_TASK_HOST,
            },
            "tasks": {"writer": "writer-task", "tests": None, "review": None},
            "task_start_intents": {},
            "pane_ids": {"captain": "%1", "writer": "%2", "tests": "%3", "review": "%4"},
            "collection": None,
            "close_receipt": None,
        }
        workspace._atomic_json(directory / "manifest.json", value)
        workspace._atomic_json(
            directory / "writer-receipt.json",
            signed_receipt(
                {
                    "role": "writer",
                    "expected_base_head": self.git.base,
                    "expected_branch": "feat/writer",
                    "allowed_paths": ["src"],
                    "allowed_paths_sha256": workspace._sha256_json(["src"]),
                    "command_sha256": workspace._sha256_json(value["commands"]["writer"]),
                    "head_before": self.git.base,
                    "branch_before": "feat/writer",
                    "head_after": self.git.base,
                    "branch_after": "feat/writer",
                    "sandbox": "bubblewrap-minimal-root-bounded-writable-paths-v1",
                    "git_common_dir_mode": "read_only",
                    "returncode": 0,
                }
            ),
        )
        return value

    def test_deterministic_session_name_changes_with_binding(self) -> None:
        first = workspace._workspace_identity("thread_focus", "thread-1", self.git.repo, self.git.base)
        second = workspace._workspace_identity("thread_focus", "thread-1", self.git.repo, self.git.base)
        other = workspace._workspace_identity("thread_focus", "thread-2", self.git.repo, self.git.base)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertRegex(first[0], workspace.WORKSPACE_ID_RE)

    def test_normalize_create_enforces_isolation_roles_and_scope(self) -> None:
        plan = workspace._normalize_create(
            binding_kind="thread_focus",
            binding_id="thread-1",
            repository=str(self.git.repo),
            expected_base_head=self.git.base,
            writer_branch="feat/new-writer",
            writer_worktree=str(self.root / "new-writer"),
            allowed_paths=["src"],
            forbidden_paths=["secrets"],
            writer_argv=["python3", "writer.py"],
            test_argv=["python3", "-m", "pytest"],
            review_argv=["reviewer", "--json"],
            runtime_seconds=600,
            memory_max_bytes=None,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        self.assertEqual(plan["roles"]["writer"]["access"], "write_worktree")
        self.assertEqual(plan["roles"]["tests"]["access"], "read_only")
        self.assertFalse(any(role["merge_authority"] for role in plan["roles"].values()))
        self.assertNotEqual(plan["writer_worktree"], plan["repository"])
        self.assertTrue(any(key.startswith("service:repo-writer-") for key in plan["resources"]["lease_keys"]))
        self.assertEqual(plan["resources"]["task_host"], workspace.AGENT_WORKSPACE_TASK_HOST)
        self.assertEqual(set(plan), set(workspace.PLAN_FIELDS))

    def test_route_evidence_is_hash_bound_and_missing_evidence_fails_closed(self) -> None:
        normalized = workspace._normalize_route_evidence(complete_route_evidence())
        self.assertTrue(normalized["evidence_complete"])
        self.assertEqual(normalized["status"], "verified")
        missing = workspace._normalize_route_evidence(None)
        self.assertFalse(missing["evidence_complete"])
        tampered = complete_route_evidence()
        tampered["score"] += 1
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "recommendation_id"):
            workspace._normalize_route_evidence(tampered)
        deviated = complete_route_evidence()
        deviated["recommended_route"] = "workspace_with_contrast"
        recommendation = {
            "schema_version": 1,
            "score": deviated["score"],
            "execution_mode": deviated["recommended_route"],
            "input_facts": deviated["input_facts"],
            "external_candidates": deviated["external_candidates"],
        }
        deviated["recommendation_id"] = workspace._sha256_json(recommendation)
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "deviation_reason"):
            workspace._normalize_route_evidence(deviated)

    def test_close_blocks_new_workspace_without_route_evidence(self) -> None:
        manifest = self.manifest()
        manifest["route_evidence"] = workspace._normalize_route_evidence(None)
        collection = persist_collection(
            manifest,
            {
                "workspace_id": manifest["workspace_id"],
                "writer_head": manifest["expected_base_head"],
                "diff_sha256": "d" * 64,
                "expected_base_head": manifest["expected_base_head"],
                "writer_result": {"type": "patch", "sha256": "e" * 64},
            },
        )
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_collection_integrity_status", return_value={"valid": True}),
            mock.patch.object(workspace, "_append_workspace_event"),
            mock.patch.object(workspace, "_write_manifest"),
            mock.patch.object(workspace, "_git_snapshot") as snapshot,
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"],
                manifest["expected_base_head"],
                "d" * 64,
                collection["result_sha256"],
            )
        self.assertEqual(result["state"], "route_evidence_incomplete")
        self.assertEqual(result["recommended_next_action"], "recreate_with_route_evidence")
        snapshot.assert_not_called()

    def test_scope_overlap_is_rejected(self) -> None:
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "overlap"):
            workspace._normalize_create(
                binding_kind="thread_focus",
                binding_id="thread-1",
                repository=str(self.git.repo),
                expected_base_head=self.git.base,
                writer_branch="feat/new-writer",
                writer_worktree=str(self.root / "new-writer"),
                allowed_paths=["src"],
                forbidden_paths=["src/private"],
                writer_argv=["true"],
                test_argv=["true"],
                review_argv=["true"],
                runtime_seconds=600,
                memory_max_bytes=None,
                runner=workspace._run,
                binding_verifier=binding_evidence,
            )

    def test_existing_worktree_or_branch_collision_is_rejected_after_plan_normalization(self) -> None:
        self.git.add_writer()
        plan = workspace._normalize_create(
            binding_kind="thread_focus",
            binding_id="thread-1",
            repository=str(self.git.repo),
            expected_base_head=self.git.base,
            writer_branch="feat/writer",
            writer_worktree=str(self.git.writer),
            allowed_paths=["src"],
            forbidden_paths=[],
            writer_argv=["true"],
            test_argv=["true"],
            review_argv=["true"],
            runtime_seconds=600,
            memory_max_bytes=None,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "already exists"):
            workspace._validate_new_workspace_collisions(plan, workspace._run)

    def test_nested_role_commands_follow_operator_policy_and_reject_privilege_escalators(self) -> None:
        base = {
            "binding_kind": "thread_focus",
            "binding_id": "thread-command-policy",
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/command-policy",
            "writer_worktree": str(self.root / "command-policy-writer"),
            "allowed_paths": ["src"],
            "forbidden_paths": [],
            "runtime_seconds": 600,
            "memory_max_bytes": None,
            "runner": workspace._run,
            "binding_verifier": binding_evidence,
        }
        for field in ("writer_argv", "test_argv", "review_argv"):
            for escalator in ("sudo", "su", "pkexec", "doas"):
                commands = {
                    "writer_argv": ["true"],
                    "test_argv": ["true"],
                    "review_argv": ["true"],
                }
                commands[field] = [f"/usr/bin/{escalator}", "true"]
                with self.subTest(field=field, escalator=escalator):
                    with self.assertRaises(workspace.AgentWorkspaceError) as raised:
                        workspace._normalize_create(**base, **commands)
                    message = str(raised.exception)
                    self.assertIn(field, message)
                    self.assertIn(escalator, message)

        trusted_owner_commands = {
            "writer_argv": ["/usr/bin/sudo", "true"],
            "test_argv": ["true"],
            "review_argv": ["true"],
        }
        with mock.patch.object(
            workspace.operator,
            "_validate_argv",
            side_effect=lambda argv, cwd=None: list(argv),
        ):
            with self.assertRaisesRegex(
                workspace.AgentWorkspaceError,
                "writer_argv may not invoke privilege escalator sudo",
            ):
                workspace._normalize_create(**base, **trusted_owner_commands)

        for command in (
            ["/usr/bin/env", "-i", "/usr/bin/sudo", "true"],
            ["/usr/bin/bash", "-lc", "sudo true"],
            ["/usr/bin/timeout", "30", "/usr/bin/pkexec", "true"],
        ):
            with self.subTest(command=command):
                with mock.patch.object(
                    workspace.operator,
                    "_validate_argv",
                    side_effect=lambda argv, cwd=None: list(argv),
                ):
                    with self.assertRaisesRegex(
                        workspace.AgentWorkspaceError,
                        "may not invoke privilege escalator",
                    ):
                        workspace._role_argv(command, "writer_argv", cwd=self.git.repo)

        with mock.patch.object(
            workspace.operator,
            "_validate_argv",
            side_effect=PermissionError("policy denied nested command"),
        ):
            with self.assertRaisesRegex(
                workspace.AgentWorkspaceError,
                "writer_argv violates the operator command policy",
            ):
                workspace._normalize_create(
                    **base,
                    writer_argv=["true"],
                    test_argv=["true"],
                    review_argv=["true"],
                )

    def test_snapshot_reports_scope_violation_and_dirty_state(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "tests" / "test_app.py").write_text("def test_bad(): assert False\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        self.assertTrue(snapshot["dirty"])
        self.assertFalse(snapshot["scope_passed"])
        self.assertEqual(snapshot["scope_violations"][0]["reason"], "outside_allowed_paths")

    def test_snapshot_hash_is_stable_and_changes_with_content(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        first = workspace._git_snapshot(manifest, workspace._run)
        second = workspace._git_snapshot(manifest, workspace._run)
        self.assertEqual(first["diff_sha256"], second["diff_sha256"])
        (self.git.writer / "src" / "app.py").write_text("value = 3\n", encoding="utf-8")
        third = workspace._git_snapshot(manifest, workspace._run)
        self.assertNotEqual(first["diff_sha256"], third["diff_sha256"])

    def test_base_drift_is_visible_and_blocks_collect(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 2\n", encoding="utf-8")
        (self.git.repo / "src" / "main.py").write_text("main = True\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.git.repo, check=True)
        subprocess.run(["git", "commit", "-m", "main drift"], cwd=self.git.repo, check=True, stdout=subprocess.PIPE)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "base_drift")
        self.assertTrue(result["snapshot"]["base_drift"])

    def test_pane_end_does_not_establish_success(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=False),
        ):
            status = workspace._status_data(manifest)
        self.assertFalse(status["tmux"]["live"])
        self.assertFalse(status["tmux"]["establishes_success"])
        self.assertFalse(status["success_ready"])

    def test_collect_running_writer_is_blocked_without_starting_checks(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "running", "terminal": False}),
            mock.patch.object(workspace, "_start_role_task") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_running")
        start.assert_not_called()

    def test_unknown_writer_runs_reconcile_check(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "outcome_unknown", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_reconcile_check", return_value={"decision": "inspect"}) as reconcile,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        reconcile.assert_called_once_with("writer-task")
        self.assertEqual(result["state"], "writer_outcome_unknown")
        self.assertEqual(result["reconcile"]["decision"], "inspect")

    def test_dirty_collect_materializes_patch_and_starts_read_only_checks(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        task_values = iter([{"task_id": "tests-task"}, {"task_id": "review-task"}])
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_start_role_task", side_effect=lambda *_: next(task_values)) as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "collecting")
        self.assertEqual(start.call_count, 2)
        frozen = workspace._manifest(manifest["workspace_id"])["frozen_writer"]
        self.assertTrue(frozen["dirty"])
        self.assertEqual(frozen["writer_result"]["type"], "patch")
        self.assertTrue(workspace._verify_patch_artifact(frozen["writer_result"]))
        self.assertTrue(self.git.writer.exists())

    def test_writer_commit_is_rejected_as_unbound_result(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_start_role_task") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_head_changed")
        start.assert_not_called()


    def test_collect_rejects_writer_change_after_freeze(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 3\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        writer_result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": True,
            "writer_result": writer_result,
        }
        workspace._write_manifest(manifest)
        (self.git.writer / "src" / "app.py").write_text("value = 4\n", encoding="utf-8")
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_changed_after_freeze")


    def test_complete_collection_is_head_and_diff_bound(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 5\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": workspace._materialize_writer_patch(manifest, snapshot, workspace._run),
        }
        workspace._write_manifest(manifest)
        tests_receipt = signed_role_receipt("tests", manifest, snapshot)
        review_receipt = signed_role_receipt("review", manifest, snapshot)
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), tests_receipt)
        workspace._atomic_json(workspace._role_receipt_path(manifest, "review"), review_receipt)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["result"]["writer_head"], snapshot["writer_head"])
        self.assertEqual(result["result"]["diff_sha256"], snapshot["diff_sha256"])
        self.assertRegex(result["result"]["result_sha256"], workspace.SHA256_RE)
        self.assertFalse(result["result"]["tmux_establishes_success"])

    def test_status_success_requires_completed_writer_task(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        persist_collection(manifest, {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
            "tests": {"status": "passed"},
            "review": {"status": "passed", "verdict": "PASS", "findings": []},
        })

        def task_state(task_id):
            state = "failed" if task_id == "writer-task" else "completed"
            return {"task_id": task_id, "state": state, "terminal": True}

        with (
            mock.patch.object(workspace, "_task_public", side_effect=task_state),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertTrue(status["closeable"])
        self.assertFalse(status["success_ready"])

    def test_status_and_closeability_block_open_or_invalid_role_start_intents(self) -> None:
        manifest = self.manifest()
        manifest["task_start_intents"] = {
            "review": {
                "role": "review",
                "task_argv_sha256": "a" * 64,
            }
        }
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertFalse(status["closeable"])
        self.assertFalse(status["success_ready"])
        self.assertTrue(status["role_start_reconcile_required"])

        manifest["task_start_intents"] = []
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            invalid = workspace._status_data(manifest)
        self.assertFalse(invalid["closeable"])
        self.assertTrue(invalid["role_start_reconcile_required"])

    def test_status_success_requires_passing_review_process(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        persist_collection(manifest, {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
            "tests": {"status": "passed"},
            "review": {"status": "failed", "verdict": "PASS", "findings": []},
        })
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertTrue(status["closeable"])
        self.assertFalse(status["success_ready"])

    def test_attach_only_returns_existing_session_command(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(workspace.operator, "_require_operator_capability"),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            result = workspace.grabowski_agent_workspace_attach(manifest["workspace_id"])
        self.assertEqual(result["attach_argv"][-2:], ["-t", manifest["session_name"]])
        self.assertFalse(result["creates_state"])

    def test_close_blocks_active_tasks(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(manifest, {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
        })
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "running", "terminal": False}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"], snapshot["writer_head"], snapshot["diff_sha256"], collection["result_sha256"]
            )
        self.assertEqual(result["state"], "active_tasks")
        self.assertTrue(self.git.writer.exists())

    def test_close_preserves_branch_and_worktree_and_writes_receipt(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(manifest, {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
        })
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
            mock.patch.object(workspace, "_tmux_result", return_value={"returncode": 0, "stdout": "", "stderr": ""}) as tmux,
            mock.patch.object(
                workspace.resources,
                "release_resources",
                return_value={
                    "released": [
                        {"resource_key": key}
                        for key in manifest["resources"]["lease_keys"]
                    ]
                },
            ),
            mock.patch.object(workspace.resources, "list_resources", return_value=[]),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"], snapshot["writer_head"], snapshot["diff_sha256"], collection["result_sha256"]
            )
        receipt = result["close_receipt"]
        self.assertTrue(receipt["worktree_preserved"])
        self.assertTrue(receipt["branch_preserved"])
        self.assertTrue(receipt["no_unsecured_changes_discarded"])
        self.assertEqual(receipt["state"], "complete")
        self.assertTrue(self.git.writer.exists())
        self.assertEqual(run(self.git.writer, "git", "branch", "--show-current"), "feat/writer")
        tmux.assert_called_with(["kill-session", "-t", manifest["session_name"]])
        self.assertTrue((self.state / manifest["workspace_id"] / "close-receipt.json").is_file())

    def test_close_persists_and_blocks_unverified_remaining_resource_leases(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(
            manifest,
            {
                "writer_head": snapshot["writer_head"],
                "diff_sha256": snapshot["diff_sha256"],
            },
        )
        expected_keys = list(manifest["resources"]["lease_keys"])
        remaining_key = expected_keys[-1]
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=False),
            mock.patch.object(
                workspace.resources,
                "release_resources",
                return_value={"released": [{"resource_key": expected_keys[0]}]},
            ),
            mock.patch.object(
                workspace.resources,
                "list_resources",
                return_value=[{"resource_key": remaining_key}],
            ),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            with self.assertRaisesRegex(
                workspace.AgentWorkspaceActionError,
                "resource release incomplete",
            ):
                workspace.grabowski_agent_workspace_close(
                    manifest["workspace_id"],
                    snapshot["writer_head"],
                    snapshot["diff_sha256"],
                    collection["result_sha256"],
                )
        persisted = workspace._load_json(
            self.state / manifest["workspace_id"] / "close-receipt.json"
        )
        self.assertEqual(persisted["state"], "resource_release_incomplete")
        self.assertFalse(persisted["resources_released"])
        self.assertEqual(persisted["remaining_resource_keys"], [remaining_key])
        self.assertIsNone(workspace._manifest(manifest["workspace_id"])["close_receipt"])

    def test_close_accepts_verified_absence_after_release_receipt_error(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(
            manifest,
            {
                "writer_head": snapshot["writer_head"],
                "diff_sha256": snapshot["diff_sha256"],
            },
        )
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=False),
            mock.patch.object(
                workspace.resources,
                "release_resources",
                side_effect=RuntimeError("release response lost"),
            ),
            mock.patch.object(workspace.resources, "list_resources", return_value=[]),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"],
                snapshot["writer_head"],
                snapshot["diff_sha256"],
                collection["result_sha256"],
            )
        receipt = result["close_receipt"]
        self.assertTrue(receipt["resources_released"])
        self.assertEqual(receipt["remaining_resource_keys"], [])
        self.assertIn("release response lost", receipt["resource_release_error"])

    def test_read_only_role_sandbox_has_no_writable_repo_bind(self) -> None:
        argv = role.sandbox_argv(self.git.repo, ["python3", "-c", "print('ok')"])
        self.assertIn("--ro-bind", argv)
        self.assertNotIn("--bind", argv)
        self.assertEqual(argv[argv.index("--chdir") + 1], str(self.git.repo))
        workspace_bind = [
            index for index, item in enumerate(argv)
            if item == "--ro-bind" and index + 2 < len(argv) and argv[index + 2] == str(self.git.repo)
        ]
        self.assertEqual(len(workspace_bind), 1)
        self.assertNotIn(str(Path.home()), argv)
        self.assertIn("--cap-drop", argv)
        self.assertNotIn("--unshare-net", argv)

    def test_partial_creation_blocks_status_success_collect_and_close(self) -> None:
        manifest = self.manifest()
        manifest["creation_state"] = "creating"
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace, "_git_snapshot", return_value={"dirty": False}),
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
            mock.patch.object(workspace.operator, "_require_operator_capability"),
        ):
            status = workspace.grabowski_agent_workspace_status(manifest["workspace_id"])
        self.assertFalse(status["creation_ready"])
        self.assertFalse(status["closeable"])
        self.assertFalse(status["success_ready"])

        with mock.patch.object(workspace.operator, "_require_operator_mutation"):
            collected = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(collected["state"], "creation_incomplete")
        self.assertIn("creation_state_not_ready", collected["completion_errors"])

        with mock.patch.object(workspace.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(workspace.AgentWorkspaceError, "creation is incomplete"):
                workspace.grabowski_agent_workspace_close(
                    manifest["workspace_id"],
                    self.git.base,
                    "0" * 64,
                    "1" * 64,
                )

    def test_create_rollback_preserves_dirty_writer_worktree(self) -> None:
        plan_id, _ = workspace._workspace_identity("thread_focus", "thread-rollback", self.git.repo, self.git.base)
        def fake_task_start(**kwargs):
            worktree = Path(kwargs["cwd"])
            (worktree / "src" / "unsaved.py").write_text("unsaved = True\n", encoding="utf-8")
            return {
                "task": {
                    "task_id": "writer-task",
                    "host": kwargs["host"],
                    "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                    "cwd": kwargs["cwd"],
                }
            }

        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
            mock.patch.object(workspace.resources, "acquire_resources", return_value={"leases": []}),
            mock.patch.object(workspace.resources, "release_resources", return_value={"released": []}),
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=fake_task_start),
            mock.patch.object(workspace.tasks, "grabowski_task_cancel"),
            mock.patch.object(workspace, "_create_tmux", side_effect=RuntimeError("tmux failed")),
        ):
            with self.assertRaisesRegex(RuntimeError, "tmux failed"):
                workspace.grabowski_agent_workspace_create(
                    binding_kind="thread_focus", binding_id="thread-rollback", repository=str(self.git.repo),
                    expected_base_head=self.git.base, writer_branch="feat/rollback",
                    writer_worktree=str(self.root / "rollback-writer"), allowed_paths=["src"],
                    writer_argv=["true"], test_argv=["true"], review_argv=["true"], runtime_seconds=600,
                )
        self.assertTrue((self.root / "rollback-writer" / "src" / "unsaved.py").is_file())
        failure = json.loads((self.state / plan_id / "create-failure.json").read_text())
        self.assertTrue(failure["worktree_preserved"])


    def test_create_audit_failure_never_publishes_ready_workspace(self) -> None:
        binding_id = "thread-audit-failure"
        plan_id, _ = workspace._workspace_identity(
            "thread_focus", binding_id, self.git.repo, self.git.base
        )
        cancel = mock.Mock(
            return_value={"task": {"state": "cancelled"}, "result": {"returncode": 0}}
        )
        release = mock.Mock(return_value={"released": []})

        def fake_task_start(**kwargs):
            return {
                "task": {
                    "task_id": "writer-task",
                    "host": kwargs["host"],
                    "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                    "cwd": kwargs["cwd"],
                }
            }

        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
            mock.patch.object(workspace.resources, "acquire_resources", return_value={"leases": [{}]}),
            mock.patch.object(workspace.resources, "release_resources", release),
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=fake_task_start),
            mock.patch.object(workspace.tasks, "grabowski_task_cancel", cancel),
            mock.patch.object(
                workspace,
                "_create_tmux",
                return_value={"captain": "%1", "writer": "%2", "tests": "%3", "review": "%4"},
            ),
            mock.patch.object(
                workspace,
                "_tmux_result",
                return_value={"returncode": 0, "stdout": "", "stderr": ""},
            ),
            mock.patch.object(workspace.base, "_append_audit", side_effect=RuntimeError("audit unavailable")),
        ):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                workspace.grabowski_agent_workspace_create(
                    binding_kind="thread_focus",
                    binding_id=binding_id,
                    repository=str(self.git.repo),
                    expected_base_head=self.git.base,
                    writer_branch="feat/audit-failure",
                    writer_worktree=str(self.root / "audit-failure-writer"),
                    allowed_paths=["src"],
                    writer_argv=["true"],
                    test_argv=["true"],
                    review_argv=["true"],
                    runtime_seconds=600,
                )
        manifest = workspace._manifest(plan_id)
        self.assertEqual(manifest["creation_state"], "creating")
        failure = json.loads(
            (self.state / plan_id / "create-failure.json").read_text(encoding="utf-8")
        )
        self.assertIn("audit unavailable", failure["error"])
        self.assertTrue(failure["writer_cancel_confirmed"])
        self.assertTrue(failure["lease_released"])
        cancel.assert_called_once_with("writer-task")
        release.assert_called_once()

    def test_create_retry_returns_only_complete_live_workspace_as_idempotent(self) -> None:
        binding_id = "thread-idempotent"
        worktree = self.root / "idempotent-writer"
        create_kwargs = {
            "binding_kind": "thread_focus",
            "binding_id": binding_id,
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/idempotent",
            "writer_worktree": str(worktree),
            "allowed_paths": ["src"],
            "writer_argv": ["true"],
            "test_argv": ["true"],
            "review_argv": ["true"],
            "forbidden_paths": [],
            "runtime_seconds": 600,
            "memory_max_bytes": None,
        }
        plan = workspace._normalize_create(
            **create_kwargs,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        directory = self.state / plan["workspace_id"]
        directory.mkdir(parents=True, mode=0o700)
        manifest = {
            **plan,
            "plan_sha256": workspace._sha256_json(plan),
            "creation_state": "ready",
            "created_at": workspace._utc(),
            "updated_at": workspace._utc(),
            "tasks": {"writer": "writer-task", "tests": None, "review": None},
            "task_start_intents": {},
            "pane_ids": {"captain": "%1", "writer": "%2", "tests": "%3", "review": "%4"},
            "collection": None,
            "close_receipt": None,
        }
        workspace._atomic_json(directory / "manifest.json", manifest)
        leases = [{"resource_key": key} for key in plan["resources"]["lease_keys"]]
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
            mock.patch.object(workspace.resources, "list_resources", return_value=leases),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
            mock.patch.object(workspace, "_tmux_pane_ids", return_value={"%1", "%2", "%3", "%4"}),
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={
                    "task_id": "writer-task",
                    "state": "running",
                    "terminal": False,
                    "host": workspace.AGENT_WORKSPACE_TASK_HOST,
                    "argv_sha256": workspace._sha256_json(workspace._writer_task_argv(manifest)),
                    "cwd": str(worktree),
                },
            ),
            mock.patch.object(
                workspace,
                "_writer_create_identity",
                return_value={
                    "writer_branch_matches": True,
                    "writer_head": self.git.base,
                    "writer_branch": "feat/idempotent",
                    "writer_worktree": str(worktree),
                },
            ),
            mock.patch.object(workspace, "_validate_new_workspace_collisions") as collision_check,
        ):
            result = workspace.grabowski_agent_workspace_create(**create_kwargs)
        self.assertTrue(result["idempotent"])
        self.assertTrue(result["tmux_live"])
        collision_check.assert_not_called()

    def test_create_retry_blocks_live_pane_task_and_git_drift(self) -> None:
        plan = workspace._normalize_create(
            binding_kind="thread_focus",
            binding_id="thread-live-drift",
            repository=str(self.git.repo),
            expected_base_head=self.git.base,
            writer_branch="feat/live-drift",
            writer_worktree=str(self.root / "live-drift-writer"),
            allowed_paths=["src"],
            forbidden_paths=[],
            writer_argv=["true"],
            test_argv=["true"],
            review_argv=["true"],
            runtime_seconds=600,
            memory_max_bytes=None,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        directory = self.state / plan["workspace_id"]
        directory.mkdir(parents=True, mode=0o700)
        manifest = {
            **plan,
            "plan_sha256": workspace._sha256_json(plan),
            "creation_state": "ready",
            "created_at": workspace._utc(),
            "updated_at": workspace._utc(),
            "tasks": {"writer": "writer-task", "tests": None, "review": None},
            "task_start_intents": {},
            "pane_ids": {"captain": "%1", "writer": "%2", "tests": "%3", "review": "%4"},
            "collection": None,
            "close_receipt": None,
        }
        workspace._atomic_json(directory / "manifest.json", manifest)
        leases = [{"resource_key": key} for key in plan["resources"]["lease_keys"]]
        valid_task = {
            "task_id": "writer-task",
            "host": workspace.AGENT_WORKSPACE_TASK_HOST,
            "state": "running",
            "terminal": False,
            "argv_sha256": workspace._sha256_json(workspace._writer_task_argv(manifest)),
            "cwd": plan["writer_worktree"],
        }
        valid_identity = {
            "writer_branch_matches": True,
            "writer_head": self.git.base,
            "writer_branch": plan["writer_branch"],
            "writer_worktree": plan["writer_worktree"],
        }
        cases = (
            (
                "tmux_pane_inventory_mismatch",
                {"%1", "%2", "%3", "%99"},
                valid_task,
                valid_identity,
            ),
            (
                "writer_task_argv_mismatch",
                {"%1", "%2", "%3", "%4"},
                {**valid_task, "argv_sha256": "0" * 64},
                valid_identity,
            ),
            (
                "writer_task_cwd_mismatch",
                {"%1", "%2", "%3", "%4"},
                {**valid_task, "cwd": str(self.root / "other")},
                valid_identity,
            ),
            (
                "writer_branch_mismatch",
                {"%1", "%2", "%3", "%4"},
                valid_task,
                {**valid_identity, "writer_branch_matches": False},
            ),
            (
                "writer_head_mismatch",
                {"%1", "%2", "%3", "%4"},
                valid_task,
                {**valid_identity, "writer_head": "f" * 40},
            ),
        )
        for expected_error, pane_ids, task_state, identity in cases:
            with self.subTest(expected_error=expected_error):
                with (
                    mock.patch.object(workspace.resources, "list_resources", return_value=leases),
                    mock.patch.object(workspace, "_tmux_has_session", return_value=True),
                    mock.patch.object(workspace, "_tmux_pane_ids", return_value=pane_ids),
                    mock.patch.object(workspace, "_task_public", return_value=task_state),
                    mock.patch.object(workspace, "_writer_create_identity", return_value=identity),
                ):
                    result = workspace._existing_workspace_response(
                        directory=directory,
                        plan=plan,
                        plan_sha256=workspace._sha256_json(plan),
                    )
                self.assertFalse(result["idempotent"])
                self.assertEqual(result["state"], "creation_runtime_incomplete")
                self.assertIn(expected_error, result["runtime_errors"])

    def test_create_retry_blocks_failed_or_incomplete_manifest(self) -> None:
        for state_kind in ("failed", "incomplete"):
            with self.subTest(state_kind=state_kind):
                binding_id = f"thread-{state_kind}"
                create_kwargs = {
                    "binding_kind": "thread_focus",
                    "binding_id": binding_id,
                    "repository": str(self.git.repo),
                    "expected_base_head": self.git.base,
                    "writer_branch": f"feat/{state_kind}",
                    "writer_worktree": str(self.root / f"{state_kind}-writer"),
                    "allowed_paths": ["src"],
                    "writer_argv": ["true"],
                    "test_argv": ["true"],
                    "review_argv": ["true"],
                    "forbidden_paths": [],
                    "runtime_seconds": 600,
                    "memory_max_bytes": None,
                }
                plan = workspace._normalize_create(
                    **create_kwargs,
                    runner=workspace._run,
                    binding_verifier=binding_evidence,
                )
                directory = self.state / plan["workspace_id"]
                directory.mkdir(parents=True, mode=0o700)
                manifest = {
                    **plan,
                    "plan_sha256": workspace._sha256_json(plan),
                    "created_at": workspace._utc(),
                    "updated_at": workspace._utc(),
                    "tasks": {"writer": "writer-task", "tests": None, "review": None},
                    "pane_ids": {},
                    "collection": None,
                    "close_receipt": None,
                }
                workspace._atomic_json(directory / "manifest.json", manifest)
                if state_kind == "failed":
                    workspace._atomic_json(
                        directory / "create-failure.json",
                        {
                            "schema_version": 1,
                            "workspace_id": plan["workspace_id"],
                            "plan_sha256": workspace._sha256_json(plan),
                            "failed_at": workspace._utc(),
                            "writer_task_id": "writer-task",
                            "writer_cancel_confirmed": True,
                            "lease_retained": False,
                            "worktree_preserved": True,
                        },
                    )
                with (
                    mock.patch.object(workspace.operator, "_require_operator_mutation"),
                    mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
                    mock.patch.object(workspace.resources, "list_resources") as leases,
                    mock.patch.object(workspace, "_tmux_has_session") as tmux,
                ):
                    result = workspace.grabowski_agent_workspace_create(**create_kwargs)
                self.assertFalse(result["idempotent"])
                self.assertTrue(result["retry_requires_recovery"])
                self.assertEqual(
                    result["state"],
                    "creation_failed" if state_kind == "failed" else "creation_incomplete",
                )
                leases.assert_not_called()
                tmux.assert_not_called()

    def test_create_retry_rejects_manifest_with_forged_plan_digest(self) -> None:
        create_kwargs = {
            "binding_kind": "thread_focus",
            "binding_id": "thread-forged-plan",
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/forged-plan",
            "writer_worktree": str(self.root / "forged-plan-writer"),
            "allowed_paths": ["src"],
            "writer_argv": ["true"],
            "test_argv": ["true"],
            "review_argv": ["true"],
            "forbidden_paths": [],
            "runtime_seconds": 600,
            "memory_max_bytes": None,
        }
        plan = workspace._normalize_create(
            **create_kwargs,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        directory = self.state / plan["workspace_id"]
        directory.mkdir(parents=True, mode=0o700)
        manifest = {
            **plan,
            "plan_sha256": workspace._sha256_json(plan),
            "commands": {**plan["commands"], "writer": ["false"]},
            "tasks": {"writer": "writer-task", "tests": None, "review": None},
            "pane_ids": {"captain": "%1", "writer": "%2", "tests": "%3", "review": "%4"},
            "collection": None,
            "close_receipt": None,
        }
        workspace._atomic_json(directory / "manifest.json", manifest)
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
        ):
            with self.assertRaisesRegex(workspace.AgentWorkspaceError, "plan digest mismatch"):
                workspace.grabowski_agent_workspace_create(**create_kwargs)

    def test_create_retry_uses_failure_receipt_without_manifest_and_checks_plan_binding(self) -> None:
        create_kwargs = {
            "binding_kind": "thread_focus",
            "binding_id": "thread-failure-only",
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/failure-only",
            "writer_worktree": str(self.root / "failure-only-writer"),
            "allowed_paths": ["src"],
            "writer_argv": ["true"],
            "test_argv": ["true"],
            "review_argv": ["true"],
            "forbidden_paths": [],
            "runtime_seconds": 600,
            "memory_max_bytes": None,
        }
        plan = workspace._normalize_create(
            **create_kwargs,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        directory = self.state / plan["workspace_id"]
        directory.mkdir(parents=True, mode=0o700)
        failure_path = directory / "create-failure.json"
        workspace._atomic_json(
            failure_path,
            {
                "schema_version": 1,
                "workspace_id": plan["workspace_id"],
                "plan_sha256": workspace._sha256_json(plan),
                "failed_at": workspace._utc(),
                "writer_task_id": None,
                "writer_start_attempted": True,
                "writer_task_argv_sha256": "a" * 64,
                "writer_cancel_confirmed": False,
                "lease_retained": True,
                "worktree_preserved": True,
            },
        )
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
        ):
            result = workspace.grabowski_agent_workspace_create(**create_kwargs)
        self.assertEqual(result["state"], "creation_failed")
        self.assertTrue(result["retry_requires_recovery"])
        self.assertEqual(result["failure"]["writer_task_argv_sha256"], "a" * 64)

        payload = json.loads(failure_path.read_text(encoding="utf-8"))
        payload["plan_sha256"] = "b" * 64
        workspace._atomic_json(failure_path, payload)
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
        ):
            with self.assertRaisesRegex(workspace.AgentWorkspaceError, "different plan"):
                workspace.grabowski_agent_workspace_create(**create_kwargs)

    def test_create_retry_rejects_non_private_workspace_directory(self) -> None:
        create_kwargs = {
            "binding_kind": "thread_focus",
            "binding_id": "thread-open-directory",
            "repository": str(self.git.repo),
            "expected_base_head": self.git.base,
            "writer_branch": "feat/open-directory",
            "writer_worktree": str(self.root / "open-directory-writer"),
            "allowed_paths": ["src"],
            "writer_argv": ["true"],
            "test_argv": ["true"],
            "review_argv": ["true"],
            "forbidden_paths": [],
            "runtime_seconds": 600,
            "memory_max_bytes": None,
        }
        plan = workspace._normalize_create(
            **create_kwargs,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        directory = self.state / plan["workspace_id"]
        directory.mkdir(parents=True, mode=0o700)
        directory.chmod(0o750)
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
        ):
            with self.assertRaisesRegex(PermissionError, "private owner-controlled"):
                workspace.grabowski_agent_workspace_create(**create_kwargs)

    def test_create_failure_retains_lease_when_writer_cancel_is_unconfirmed(self) -> None:
        plan_id, _ = workspace._workspace_identity(
            "thread_focus", "thread-cancel-unknown", self.git.repo, self.git.base
        )
        release = mock.Mock(return_value={"released": []})
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
            mock.patch.object(workspace.resources, "acquire_resources", return_value={"leases": [{}]}),
            mock.patch.object(workspace.resources, "release_resources", release),
            mock.patch.object(
                workspace.tasks,
                "grabowski_task_start",
                side_effect=lambda **kwargs: {
                    "task": {
                        "task_id": "writer-task",
                        "host": kwargs["host"],
                        "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                        "cwd": kwargs["cwd"],
                    }
                },
            ),
            mock.patch.object(
                workspace.tasks,
                "grabowski_task_cancel",
                side_effect=RuntimeError("cancel outcome unknown"),
            ),
            mock.patch.object(workspace, "_create_tmux", side_effect=RuntimeError("tmux failed")),
        ):
            with self.assertRaisesRegex(RuntimeError, "tmux failed"):
                workspace.grabowski_agent_workspace_create(
                    binding_kind="thread_focus",
                    binding_id="thread-cancel-unknown",
                    repository=str(self.git.repo),
                    expected_base_head=self.git.base,
                    writer_branch="feat/cancel-unknown",
                    writer_worktree=str(self.root / "cancel-unknown-writer"),
                    allowed_paths=["src"],
                    writer_argv=["true"],
                    test_argv=["true"],
                    review_argv=["true"],
                    runtime_seconds=600,
                )
        release.assert_not_called()
        failure = json.loads((self.state / plan_id / "create-failure.json").read_text())
        self.assertFalse(failure["writer_cancel_confirmed"])
        self.assertTrue(failure["lease_retained"])
        self.assertIn("cancel outcome unknown", failure["writer_cancel_error"])

    def test_create_failure_retains_worktree_and_lease_when_task_start_outcome_is_unknown(self) -> None:
        plan_id, _ = workspace._workspace_identity(
            "thread_focus", "thread-start-unknown", self.git.repo, self.git.base
        )
        release = mock.Mock(return_value={"released": []})
        worktree = self.root / "start-unknown-writer"
        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_verify_bureau_binding", side_effect=binding_evidence),
            mock.patch.object(workspace.resources, "acquire_resources", return_value={"leases": [{}]}),
            mock.patch.object(workspace.resources, "release_resources", release),
            mock.patch.object(
                workspace.tasks,
                "grabowski_task_start",
                side_effect=RuntimeError("task start result lost"),
            ),
            mock.patch.object(workspace.tasks, "grabowski_task_cancel") as cancel,
        ):
            with self.assertRaisesRegex(RuntimeError, "task start result lost"):
                workspace.grabowski_agent_workspace_create(
                    binding_kind="thread_focus",
                    binding_id="thread-start-unknown",
                    repository=str(self.git.repo),
                    expected_base_head=self.git.base,
                    writer_branch="feat/start-unknown",
                    writer_worktree=str(worktree),
                    allowed_paths=["src"],
                    writer_argv=["true"],
                    test_argv=["true"],
                    review_argv=["true"],
                    runtime_seconds=600,
                )
        cancel.assert_not_called()
        release.assert_not_called()
        self.assertTrue(worktree.is_dir())
        manifest = workspace._manifest(plan_id)
        writer_intent = manifest["task_start_intents"]["writer"]
        self.assertEqual(writer_intent["role"], "writer")
        self.assertRegex(writer_intent["task_argv_sha256"], workspace.SHA256_RE)
        self.assertEqual(writer_intent["task_host"], workspace.AGENT_WORKSPACE_TASK_HOST)
        self.assertEqual(writer_intent["task_cwd"], str(worktree))
        failure = json.loads((self.state / plan_id / "create-failure.json").read_text())
        self.assertTrue(failure["writer_start_attempted"])
        self.assertRegex(failure["writer_task_argv_sha256"], workspace.SHA256_RE)
        self.assertEqual(failure["writer_task_host"], workspace.AGENT_WORKSPACE_TASK_HOST)
        self.assertEqual(failure["writer_task_cwd"], str(worktree))
        self.assertFalse(failure["writer_cancel_confirmed"])
        self.assertTrue(failure["lease_retained"])
        self.assertIn("start outcome is unknown", failure["writer_cancel_error"])

    def test_writer_worktree_inside_canonical_checkout_is_rejected(self) -> None:
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "outside the canonical checkout"):
            workspace._normalize_create(
                binding_kind="thread_focus",
                binding_id="thread-1",
                repository=str(self.git.repo),
                expected_base_head=self.git.base,
                writer_branch="feat/nested",
                writer_worktree=str(self.git.repo / "nested-worktree"),
                allowed_paths=["src"],
                forbidden_paths=[],
                writer_argv=["true"],
                test_argv=["true"],
                review_argv=["true"],
                runtime_seconds=600,
                memory_max_bytes=None,
                runner=workspace._run,
                binding_verifier=binding_evidence,
            )

    def test_live_thread_focus_binding_requires_one_active_record(self) -> None:
        bureau_root = self.root / "bureau"
        bureau_root.mkdir()
        bureau_bin = self.root / "bureau-bin"
        bureau_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        bureau_bin.chmod(0o755)
        payload = {
            "records": [
                {
                    "event_id": 42,
                    "record": {
                        "kind": "thread_focus",
                        "thread_id": "thread-1",
                        "status": "active",
                        "repo": "repo.grabowski",
                        "worker_id": "worker-1",
                        "does_not_establish": ["merge_readiness"],
                    },
                }
            ]
        }
        runner = mock.Mock(return_value={"returncode": 0, "stdout": json.dumps(payload), "stderr": ""})
        with (
            mock.patch.object(workspace, "BUREAU", bureau_bin),
            mock.patch.object(workspace, "BUREAU_ROOT", bureau_root),
        ):
            evidence = workspace._verify_bureau_binding("thread_focus", "thread-1", runner=runner)
        self.assertEqual(evidence["event_id"], 42)
        self.assertEqual(evidence["status"], "active")
        self.assertEqual(evidence["id"], "thread-1")
        self.assertRegex(evidence["evidence_sha256"], workspace.SHA256_RE)

    def test_bureau_task_binding_requires_healthy_actionable_registry_task(self) -> None:
        bureau_root = self.root / "bureau"
        task_dir = bureau_root / "registry" / "tasks"
        task_dir.mkdir(parents=True)
        bureau_bin = self.root / "bureau-bin"
        bureau_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        bureau_bin.chmod(0o755)
        task_id = "TEST-V1-T001"
        task_path = task_dir / f"{task_id}.json"
        task_path.write_text(
            json.dumps({"schema_version": 1, "id": task_id, "title": "Test", "state": "ready"}),
            encoding="utf-8",
        )
        runner = mock.Mock(return_value={"returncode": 0, "stdout": json.dumps({"healthy": True}), "stderr": ""})
        with (
            mock.patch.object(workspace, "BUREAU", bureau_bin),
            mock.patch.object(workspace, "BUREAU_ROOT", bureau_root),
        ):
            evidence = workspace._verify_bureau_binding("bureau_task", task_id, runner=runner)
            task_path.write_text(
                json.dumps({"schema_version": 1, "id": task_id, "title": "Test", "state": "verified"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(workspace.AgentWorkspaceError, "not actionable"):
                workspace._verify_bureau_binding("bureau_task", task_id, runner=runner)
        self.assertEqual(evidence["state"], "ready")
        self.assertRegex(evidence["task_sha256"], workspace.SHA256_RE)

    def test_clean_writer_without_commit_is_not_a_result(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_result_missing")
        self.assertTrue(result["worktree_preserved"])

    def test_writer_branch_mismatch_blocks_collection(self) -> None:
        manifest = self.manifest()
        subprocess.run(["git", "checkout", "-b", "feat/other"], cwd=self.git.writer, check=True, stdout=subprocess.PIPE)
        self.git.commit_writer()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_branch_mismatch")
        self.assertFalse(result["snapshot"]["writer_branch_matches"])

    def test_untracked_symlink_is_rejected_by_workspace_and_role(self) -> None:
        manifest = self.manifest()
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "data.txt").write_text("outside\n", encoding="utf-8")
        (self.git.writer / "src" / "escape").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "symlink"):
            workspace._git_snapshot(manifest, workspace._run)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            role.current_binding(self.git.writer, self.git.base)

    def test_collect_persists_first_read_only_task_before_second_start_fails(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 6\n", encoding="utf-8")
        calls = 0

        def start(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                return {"task_id": "tests-task"}
            raise RuntimeError("review launch failed")

        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_start_role_task", side_effect=start),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            with self.assertRaisesRegex(RuntimeError, "review launch failed"):
                workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        updated = workspace._manifest(manifest["workspace_id"])
        self.assertEqual(updated["tasks"]["tests"], "tests-task")
        self.assertIsNone(updated["tasks"]["review"])
        self.assertIn("frozen_writer", updated)
        review_intent = updated["task_start_intents"]["review"]
        self.assertEqual(review_intent["role"], "review")
        self.assertRegex(review_intent["task_argv_sha256"], workspace.SHA256_RE)
        self.assertEqual(review_intent["task_host"], workspace.AGENT_WORKSPACE_TASK_HOST)
        self.assertEqual(review_intent["task_cwd"], str(self.git.writer))
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"task_id": "writer-task", "state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_start_role_task") as retry_start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            retry = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(retry["state"], "role_start_outcome_unknown")
        self.assertTrue(retry["reconcile_required"])
        retry_start.assert_not_called()

    def test_started_task_must_echo_host_argv_and_cwd_binding(self) -> None:
        argv = ["/usr/bin/true"]
        valid = {
            "task_id": "task-1",
            "host": workspace.AGENT_WORKSPACE_TASK_HOST,
            "argv_sha256": workspace._sha256_json(argv),
            "cwd": str(self.git.repo),
        }
        self.assertEqual(
            workspace._validate_started_task(
                valid,
                role="writer",
                expected_host=workspace.AGENT_WORKSPACE_TASK_HOST,
                expected_argv=argv,
                expected_cwd=str(self.git.repo),
            ),
            valid,
        )
        for field, value in (
            ("host", "other-host"),
            ("argv_sha256", "0" * 64),
            ("cwd", str(self.root / "other")),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "task binding mismatch"):
                    workspace._validate_started_task(
                        {**valid, field: value},
                        role="writer",
                        expected_host=workspace.AGENT_WORKSPACE_TASK_HOST,
                        expected_argv=argv,
                        expected_cwd=str(self.git.repo),
                    )

    def test_worktree_cleanup_only_deletes_exact_clean_base_identity(self) -> None:
        exact = self.root / "cleanup-exact"
        subprocess.run(
            ["git", "worktree", "add", "-b", "feat/cleanup-exact", str(exact), self.git.base],
            cwd=self.git.repo,
            check=True,
            stdout=subprocess.PIPE,
        )
        self.assertTrue(
            workspace._remove_created_worktree(
                self.git.repo,
                exact,
                "feat/cleanup-exact",
                self.git.base,
                workspace._run,
            )
        )
        self.assertFalse(exact.exists())

        tree = run(self.git.repo, "git", "rev-parse", f"{self.git.base}^{{tree}}")
        foreign = subprocess.run(
            ["git", "commit-tree", tree, "-p", self.git.base],
            cwd=self.git.repo,
            input="foreign cleanup identity\n",
            text=True,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
        subprocess.run(
            ["git", "branch", "feat/cleanup-foreign", foreign],
            cwd=self.git.repo,
            check=True,
        )
        self.assertFalse(
            workspace._remove_created_worktree(
                self.git.repo,
                self.root / "missing-cleanup-foreign",
                "feat/cleanup-foreign",
                self.git.base,
                workspace._run,
            )
        )
        self.assertEqual(
            run(self.git.repo, "git", "rev-parse", "feat/cleanup-foreign"),
            foreign,
        )

    def test_unknown_worktree_mutation_retains_lease_when_identity_drifted(self) -> None:
        plan = workspace._normalize_create(
            binding_kind="thread_focus",
            binding_id="thread-worktree-unknown",
            repository=str(self.git.repo),
            expected_base_head=self.git.base,
            writer_branch="feat/worktree-unknown",
            writer_worktree=str(self.root / "worktree-unknown"),
            allowed_paths=["src"],
            forbidden_paths=[],
            writer_argv=["true"],
            test_argv=["true"],
            review_argv=["true"],
            runtime_seconds=600,
            memory_max_bytes=None,
            runner=workspace._run,
            binding_verifier=binding_evidence,
        )
        release = mock.Mock(return_value={"released": []})

        def uncertain_worktree(*args, **kwargs):
            del args, kwargs
            worktree = Path(plan["writer_worktree"])
            subprocess.run(
                ["git", "worktree", "add", "-b", plan["writer_branch"], str(worktree), self.git.base],
                cwd=self.git.repo,
                check=True,
                stdout=subprocess.PIPE,
            )
            (worktree / "src" / "foreign.py").write_text("foreign = True\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=worktree, check=True)
            subprocess.run(
                ["git", "commit", "-m", "foreign mutation"],
                cwd=worktree,
                check=True,
                stdout=subprocess.PIPE,
            )
            raise RuntimeError("worktree add result lost")

        with (
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace, "_normalize_create", return_value=plan),
            mock.patch.object(workspace, "_validate_new_workspace_collisions"),
            mock.patch.object(workspace.resources, "acquire_resources", return_value={"leases": [{}]}),
            mock.patch.object(workspace.resources, "release_resources", release),
            mock.patch.object(workspace, "_checked", side_effect=uncertain_worktree),
        ):
            with self.assertRaisesRegex(RuntimeError, "worktree add result lost"):
                workspace.grabowski_agent_workspace_create(
                    binding_kind="thread_focus",
                    binding_id="thread-worktree-unknown",
                    repository=str(self.git.repo),
                    expected_base_head=self.git.base,
                    writer_branch=plan["writer_branch"],
                    writer_worktree=plan["writer_worktree"],
                    allowed_paths=["src"],
                    writer_argv=["true"],
                    test_argv=["true"],
                    review_argv=["true"],
                    runtime_seconds=600,
                )
        release.assert_not_called()
        self.assertTrue(Path(plan["writer_worktree"]).is_dir())
        failure = json.loads(
            (self.state / plan["workspace_id"] / "create-failure.json").read_text(encoding="utf-8")
        )
        self.assertTrue(failure["worktree_create_attempted"])
        self.assertFalse(failure["worktree_cleanup_confirmed"])
        self.assertTrue(failure["lease_retained"])

    def test_writer_sandbox_rejects_preexisting_hardlink_inside_writable_scope(self) -> None:
        self.git.add_writer()
        outside = self.root / "outside-hardlink.txt"
        outside.write_text("sensitive\n", encoding="utf-8")
        linked = self.git.writer / "src" / "linked.txt"
        os.link(outside, linked)
        common = Path(run(self.git.writer, "git", "rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = (self.git.writer / common).resolve()
        with self.assertRaisesRegex(sandbox.AgentSandboxError, "hardlinked file"):
            sandbox.minimal_sandbox_argv(
                workspace=self.git.writer,
                command=["/usr/bin/python3", "-c", "print('ok')"],
                workspace_writable=True,
                writable_paths=[self.git.writer / "src"],
                git_common_dir=common,
            )

    def test_writer_sandbox_writable_tree_scan_is_bounded(self) -> None:
        self.git.add_writer()
        first = self.git.writer / "src" / "first.txt"
        second = self.git.writer / "src" / "second.txt"
        first.write_text("one\n", encoding="utf-8")
        second.write_text("two\n", encoding="utf-8")
        common = Path(run(self.git.writer, "git", "rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = (self.git.writer / common).resolve()
        with mock.patch.object(sandbox, "MAX_WRITABLE_SCOPE_ENTRIES", 1):
            with self.assertRaisesRegex(sandbox.AgentSandboxError, "exceeds 1 entries"):
                sandbox.minimal_sandbox_argv(
                    workspace=self.git.writer,
                    command=["/usr/bin/python3", "-c", "print('ok')"],
                    workspace_writable=True,
                    writable_paths=[self.git.writer / "src"],
                    git_common_dir=common,
                )

    def test_writer_sandbox_exposes_only_worktree_as_writable_host_path(self) -> None:
        self.git.add_writer()
        common = Path(run(self.git.writer, "git", "rev-parse", "--git-common-dir"))
        if not common.is_absolute():
            common = (self.git.writer / common).resolve()
        argv = sandbox.minimal_sandbox_argv(
            workspace=self.git.writer,
            command=["/usr/bin/python3", "-c", "print('ok')"],
            workspace_writable=True,
            writable_paths=[self.git.writer / "src"],
            git_common_dir=common,
        )
        writable = [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv)
            if item == "--bind"
        ]
        self.assertEqual(writable, [(str(self.git.writer / "src"), str(self.git.writer / "src"))])
        self.assertIn((str(self.git.writer), str(self.git.writer)), [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv)
            if item == "--ro-bind"
        ])
        self.assertIn((str(common), str(common)), [
            (argv[index + 1], argv[index + 2])
            for index, item in enumerate(argv)
            if item == "--ro-bind"
        ])
        self.assertNotIn(str(Path.home()), argv)

    def test_lock_rejects_fifo_hardlink_and_non_private_mode(self) -> None:
        for unsafe_kind in ("fifo", "hardlink", "mode"):
            with self.subTest(unsafe_kind=unsafe_kind):
                manifest = self.manifest()
                lock_path = workspace._workspace_dir(manifest["workspace_id"]) / ".lock"
                if lock_path.exists():
                    lock_path.unlink()
                if unsafe_kind == "fifo":
                    os.mkfifo(lock_path, 0o600)
                elif unsafe_kind == "hardlink":
                    target = self.root / "outside-lock"
                    target.write_text("", encoding="utf-8")
                    target.chmod(0o600)
                    os.link(target, lock_path)
                else:
                    lock_path.write_text("", encoding="utf-8")
                    lock_path.chmod(0o640)
                with self.assertRaisesRegex(PermissionError, "owner-controlled private regular file"):
                    workspace._lock(manifest["workspace_id"])
                if unsafe_kind == "hardlink":
                    target.unlink()
                lock_path.unlink()

    def test_lock_times_out_instead_of_waiting_forever(self) -> None:
        workspace_id = self.manifest()["workspace_id"]
        with (
            mock.patch.object(workspace.fcntl, "flock", side_effect=BlockingIOError),
            mock.patch.object(workspace.time, "monotonic", side_effect=[0.0, 11.0]),
            mock.patch.object(workspace.time, "sleep") as sleep_mock,
            mock.patch.object(workspace, "WORKSPACE_LOCK_TIMEOUT_SECONDS", 10.0),
        ):
            with self.assertRaisesRegex(TimeoutError, "lock acquisition timed out"):
                workspace._lock(workspace_id)
        sleep_mock.assert_not_called()

    def test_lock_closes_handle_when_flock_fails(self) -> None:
        workspace_id = self.manifest()["workspace_id"]
        handle = mock.Mock()
        handle.fileno.return_value = 123
        with (
            mock.patch.object(workspace.os, "open", return_value=123),
            mock.patch.object(
                workspace.os,
                "fstat",
                return_value=types.SimpleNamespace(
                    st_mode=workspace.stat.S_IFREG | 0o600,
                    st_nlink=1,
                    st_uid=os.getuid(),
                ),
            ),
            mock.patch.object(workspace, "_fdopen_owned", return_value=handle),
            mock.patch.object(workspace.fcntl, "flock", side_effect=OSError("flock failed")),
        ):
            with self.assertRaisesRegex(OSError, "flock failed"):
                workspace._lock(workspace_id)
        handle.close.assert_called_once_with()

    def test_task_host_binding_rejects_manifest_override(self) -> None:
        manifest = self.manifest()
        manifest["resources"]["task_host"] = "other-host"
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "task host binding"):
            workspace._bound_task_host(manifest)

    def test_fdopen_owned_closes_descriptor_when_wrapper_creation_fails(self) -> None:
        target = self.root / "fdopen-failure.tmp"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        original_close = os.close
        with (
            mock.patch.object(workspace.os, "fdopen", side_effect=OSError("fdopen failed")),
            mock.patch.object(workspace.os, "close", wraps=original_close) as close_mock,
        ):
            with self.assertRaisesRegex(OSError, "fdopen failed"):
                workspace._fdopen_owned(descriptor, "wb")
        close_mock.assert_called_once_with(descriptor)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_role_receipt_writers_cleanup_descriptor_and_temporary_on_fdopen_failure(self) -> None:
        cases = (
            (role, role.write_receipt, "role"),
            (writer, writer._write_receipt, "writer"),
        )
        for module, receipt_writer, name in cases:
            with self.subTest(name=name):
                target = self.root / f"{name}-receipt.json"
                original_close = os.close
                with (
                    mock.patch.object(module.os, "fdopen", side_effect=OSError("fdopen failed")),
                    mock.patch.object(module.os, "close", wraps=original_close) as close_mock,
                ):
                    with self.assertRaisesRegex(OSError, "fdopen failed"):
                        receipt_writer(target, {"schema_version": 1})
                self.assertTrue(close_mock.called)
                self.assertFalse(target.exists())
                self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_role_receipt_writers_replace_owned_regular_target_and_reject_hardlink(self) -> None:
        cases = (
            (role.write_receipt, "role"),
            (writer._write_receipt, "writer"),
        )
        for receipt_writer, name in cases:
            with self.subTest(name=name):
                target = self.root / f"{name}-existing-receipt.json"
                target.write_text("old\n", encoding="utf-8")
                target.chmod(0o600)
                receipt_writer(target, {"schema_version": 1, "kind": name})
                self.assertEqual(
                    json.loads(target.read_text(encoding="utf-8")),
                    {"schema_version": 1, "kind": name},
                )
                outside = self.root / f"{name}-outside-receipt.json"
                outside.write_text("outside\n", encoding="utf-8")
                outside.chmod(0o600)
                target.unlink()
                os.link(outside, target)
                with self.assertRaisesRegex(PermissionError, "owner-controlled regular file"):
                    receipt_writer(target, {"schema_version": 1})
                target.unlink()
                outside.unlink()

    def test_atomic_bounded_chunks_removes_partial_file_when_limit_is_exceeded(self) -> None:
        target = self.root / "bounded-patch.bin"
        with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "exceeds the safety boundary"):
            workspace._atomic_bounded_chunks(target, iter((b"abc", b"def")), max_bytes=5)
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_materialized_patch_applies_to_base_and_includes_untracked(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 9\n", encoding="utf-8")
        (self.git.writer / "src" / "new.py").write_text("new = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        self.assertTrue(workspace._verify_patch_artifact(result))
        apply_repo = self.root / "apply"
        subprocess.run(["git", "clone", "--no-hardlinks", str(self.git.repo), str(apply_repo)], check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "checkout", self.git.base], cwd=apply_repo, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "apply", result["path"]], cwd=apply_repo, check=True)
        self.assertEqual((apply_repo / "src" / "app.py").read_text(), "value = 9\n")
        self.assertEqual((apply_repo / "src" / "new.py").read_text(), "new = True\n")

    def test_patch_artifact_is_bound_to_workspace_path_and_bounded_metadata(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 10\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        expected_path = workspace._writer_patch_path(manifest)
        self.assertTrue(workspace._verify_patch_artifact(result, expected_path=expected_path))
        outside = self.root / "outside.patch"
        outside.write_bytes(expected_path.read_bytes())
        outside.chmod(0o600)
        redirected = dict(result, path=str(outside))
        self.assertFalse(workspace._verify_patch_artifact(redirected, expected_path=expected_path))
        oversized = dict(result, bytes=workspace.MAX_PATCH_BYTES + 1)
        self.assertFalse(workspace._verify_patch_artifact(oversized, expected_path=expected_path))
        preserved = self.root / "preserved-writer.patch"
        expected_path.replace(preserved)
        expected_path.symlink_to(preserved)
        self.assertFalse(workspace._verify_patch_artifact(result, expected_path=expected_path))
        expected_path.unlink()
        os.link(preserved, expected_path)
        self.assertFalse(workspace._verify_patch_artifact(result, expected_path=expected_path))
        expected_path.unlink()
        os.mkfifo(expected_path, 0o600)
        self.assertFalse(workspace._verify_patch_artifact(result, expected_path=expected_path))
        expected_path.unlink()
        preserved.replace(expected_path)
        expected_path.chmod(0o640)
        self.assertFalse(workspace._verify_patch_artifact(result, expected_path=expected_path))

    def test_pass_receipt_requires_current_bound_task_to_be_completed(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 12\n", encoding="utf-8")
        task_values = iter([{"task_id": "tests-task"}, {"task_id": "review-task"}])
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_start_role_task", side_effect=lambda *_: next(task_values)),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            first = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        snapshot = first["snapshot"]
        for role_name in ("tests", "review"):
            workspace._atomic_json(
                workspace._role_receipt_path(manifest, role_name),
                signed_role_receipt(role_name, manifest, snapshot),
            )

        def task_state(task_id):
            state = "failed" if task_id == "tests-task" else "completed"
            return {"task_id": task_id, "state": state, "terminal": True}

        with (
            mock.patch.object(workspace, "_task_public", side_effect=task_state),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "role_task_receipt_state_mismatch")
        self.assertEqual(result["role"], "tests")
        self.assertEqual(result["receipt_returncode"], 0)

    def test_patch_collection_can_be_success_ready(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 11\n", encoding="utf-8")
        task_values = iter([{"task_id": "tests-task"}, {"task_id": "review-task"}])
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_start_role_task", side_effect=lambda *_: next(task_values)),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            first = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        snapshot = first["snapshot"]
        for role_name in ("tests", "review"):
            workspace._atomic_json(
                workspace._role_receipt_path(manifest, role_name),
                signed_role_receipt(role_name, manifest, snapshot),
            )
        def completed(task_id):
            return {"task_id": task_id, "state": "completed", "terminal": True}
        with (
            mock.patch.object(workspace, "_task_public", side_effect=completed),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            second = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(second["state"], "complete")
        updated = workspace._manifest(manifest["workspace_id"])
        with (
            mock.patch.object(workspace, "_task_public", side_effect=completed),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(updated)
        self.assertTrue(status["success_ready"])
        self.assertEqual(status["collection"]["writer_result"]["type"], "patch")

    def test_binary_untracked_patch_is_byte_exact_and_applies(self) -> None:
        manifest = self.manifest()
        payload = bytes(range(256)) + b"\x00\xff\xfe" * 1024
        target = self.git.writer / "src" / "asset.bin"
        target.write_bytes(payload)
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        apply_repo = self.root / "binary-apply"
        subprocess.run(["git", "clone", "--no-hardlinks", str(self.git.repo), str(apply_repo)], check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "checkout", self.git.base], cwd=apply_repo, check=True, stdout=subprocess.PIPE)
        subprocess.run(["git", "apply", result["path"]], cwd=apply_repo, check=True)
        self.assertEqual((apply_repo / "src" / "asset.bin").read_bytes(), payload)

    def test_nul_delimited_changed_paths_preserve_spaces_tabs_and_newlines(self) -> None:
        manifest = self.manifest()
        relative = "src/name with space\tand-newline\n.py"
        (self.git.writer / relative).write_text("value = 1\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        self.assertIn(relative, snapshot["changed_paths"])
        self.assertTrue(snapshot["scope_passed"])

    def test_bounded_capture_does_not_limit_child_file_size(self) -> None:
        target = self.root / "large-output-artifact.bin"
        command = [
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(target)!r}).write_bytes(b'x' * (20 * 1024 * 1024)); print('ok')",
        ]
        captured = sandbox.run_bounded_capture(command, stdout_limit=1024, stderr_limit=1024)
        self.assertEqual(captured.returncode, 0)
        self.assertFalse(captured.output_limit_exceeded)
        self.assertEqual(target.stat().st_size, 20 * 1024 * 1024)

    def test_bounded_capture_kills_descendants_after_group_leader_exits(self) -> None:
        marker_path = self.root / "escaped-child.marker"
        child_code = (
            "import time; from pathlib import Path; "
            f"time.sleep(0.4); Path({str(marker_path)!r}).write_text('escaped')"
        )
        parent_code = (
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', " + repr(child_code) + "], "
            "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
            "print('leader-exited')"
        )
        captured = sandbox.run_bounded_capture(
            [sys.executable, "-c", parent_code],
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertEqual(captured.returncode, 0)
        time.sleep(0.7)
        self.assertFalse(marker_path.exists())

    def test_bounded_capture_kills_output_overflow(self) -> None:
        captured = sandbox.run_bounded_capture(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertTrue(captured.stdout_limit_exceeded)
        self.assertNotEqual(captured.returncode, 0)

    def test_missing_bwrap_blocks_execution_but_not_argv_construction(self) -> None:
        argv = role.sandbox_argv(self.git.repo, ["python3", "-c", "print('ok')"])
        self.assertTrue(argv)
        with mock.patch.object(sandbox, "BWRAP", self.root / "missing-bwrap"):
            with self.assertRaisesRegex(sandbox.AgentSandboxError, "bubblewrap unavailable"):
                sandbox.require_bwrap()

    def test_collect_detects_writer_change_during_patch_freeze(self) -> None:
        manifest = self.manifest()
        target = self.git.writer / "src" / "app.py"
        target.write_text("value = 12\n", encoding="utf-8")
        original = workspace._materialize_writer_patch

        def racing_materialize(*args, **kwargs):
            result = original(*args, **kwargs)
            target.write_text("value = 13\n", encoding="utf-8")
            return result

        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_materialize_writer_patch", side_effect=racing_materialize),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_changed_during_freeze")
        self.assertNotEqual(result["snapshot_before"]["diff_sha256"], result["snapshot_after"]["diff_sha256"])

    def test_collect_detects_writer_change_after_immediate_freeze_check(self) -> None:
        manifest = self.manifest()
        target = self.git.writer / "src" / "app.py"
        target.write_text("value = 120\n", encoding="utf-8")
        original_snapshot = workspace._git_snapshot
        calls = 0

        def delayed_change(*args, **kwargs):
            nonlocal calls
            calls += 1
            result = original_snapshot(*args, **kwargs)
            if calls == 2:
                target.write_text("value = 121\n", encoding="utf-8")
            return result

        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_git_snapshot", side_effect=delayed_change),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_changed_during_freeze")
        self.assertNotEqual(result["snapshot_before"]["diff_sha256"], result["snapshot_after"]["diff_sha256"])
        self.assertGreaterEqual(calls, 3)

    def test_collect_returns_structured_role_receipt_binding_mismatch(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 14\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": workspace._materialize_writer_patch(manifest, snapshot, workspace._run),
        }
        workspace._write_manifest(manifest)
        workspace._atomic_json(
            workspace._role_receipt_path(manifest, "tests"),
            signed_role_receipt("tests", manifest, snapshot, expected_diff_sha256="0" * 64),
        )
        workspace._atomic_json(
            workspace._role_receipt_path(manifest, "review"),
            signed_role_receipt("review", manifest, snapshot),
        )
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "role_receipt_binding_mismatch")
        self.assertEqual(result["role"], "tests")

    def test_root_git_metadata_cannot_be_writer_scope(self) -> None:
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "Git metadata"):
            workspace._normalize_create(
                binding_kind="thread_focus",
                binding_id="thread-1",
                repository=str(self.git.repo),
                expected_base_head=self.git.base,
                writer_branch="feat/git-scope",
                writer_worktree=str(self.root / "git-scope-writer"),
                allowed_paths=[".git"],
                forbidden_paths=[],
                writer_argv=["true"],
                test_argv=["true"],
                review_argv=["true"],
                runtime_seconds=600,
                memory_max_bytes=None,
                runner=workspace._run,
                binding_verifier=binding_evidence,
            )

    def test_untracked_hardlink_is_rejected_by_workspace_and_role(self) -> None:
        manifest = self.manifest()
        outside = self.root / "outside-hardlink.bin"
        outside.write_bytes(b"outside")
        os.link(outside, self.git.writer / "src" / "hardlink.bin")
        with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "hardlinked"):
            workspace._git_snapshot(manifest, workspace._run)
        with self.assertRaisesRegex(RuntimeError, "hardlinked"):
            role.current_binding(self.git.writer, self.git.base)

    def test_tampered_writer_receipt_blocks_collection(self) -> None:
        manifest = self.manifest()
        path = workspace._role_receipt_path(manifest, "writer")
        receipt = workspace._load_json(path)
        receipt["returncode"] = 7
        workspace._atomic_json(path, receipt)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "writer_receipt_invalid")

    def test_tampered_role_receipt_blocks_collection(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("value = 15\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": workspace._materialize_writer_patch(manifest, snapshot, workspace._run),
        }
        workspace._write_manifest(manifest)
        tests_receipt = signed_role_receipt("tests", manifest, snapshot)
        tests_receipt["returncode"] = 9
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), tests_receipt)
        workspace._atomic_json(
            workspace._role_receipt_path(manifest, "review"),
            signed_role_receipt("review", manifest, snapshot),
        )
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "role_receipt_integrity_mismatch")
        self.assertEqual(result["role"], "tests")

    def test_tampered_collection_blocks_status_and_close(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(manifest, {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "tests": {"status": "passed"},
            "review": {"status": "passed", "verdict": "PASS", "findings": []},
        })
        manifest["collection"] = dict(collection)
        manifest["collection"]["tests"] = {"status": "failed"}
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertFalse(status["collection_integrity"]["valid"])
        self.assertFalse(status["closeable"])
        with mock.patch.object(workspace.operator, "_require_operator_mutation"):
            with self.assertRaisesRegex(workspace.AgentWorkspaceError, "integrity"):
                workspace.grabowski_agent_workspace_close(
                    manifest["workspace_id"],
                    snapshot["writer_head"],
                    snapshot["diff_sha256"],
                    collection["result_sha256"],
                )

    def test_safe_git_environment_disables_executable_helpers(self) -> None:
        environment = sandbox.safe_git_environment({"HOME": str(self.root)})
        pairs = {
            environment[f"GIT_CONFIG_KEY_{index}"]: environment[f"GIT_CONFIG_VALUE_{index}"]
            for index in range(int(environment["GIT_CONFIG_COUNT"]))
        }
        self.assertEqual(pairs["core.hooksPath"], "/dev/null")
        self.assertEqual(pairs["core.fsmonitor"], "false")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_ALLOW_PROTOCOL"], "ssh:https:file")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")

    def test_workspace_git_runner_does_not_execute_post_checkout_hook(self) -> None:
        hook = self.git.repo / ".git" / "hooks" / "post-checkout"
        marker_path = self.root / "hook-executed"
        hook.write_text(f"#!/bin/sh\necho executed > {marker_path}\n", encoding="utf-8")
        hook.chmod(0o755)
        target = self.root / "safe-hook-worktree"
        result = workspace._run(
            self.git.repo,
            ["git", "worktree", "add", "-b", "feat/no-hook", str(target), self.git.base],
        )
        self.assertEqual(result["returncode"], 0, result["stderr"])
        self.assertTrue(target.is_dir())
        self.assertFalse(marker_path.exists())

    def test_workspace_git_runner_disables_fsmonitor_command(self) -> None:
        marker_path = self.root / "fsmonitor-executed"
        monitor = self.root / "fsmonitor.sh"
        monitor.write_text(
            f"#!/bin/sh\necho executed > {marker_path}\nprintf '\n'\n",
            encoding="utf-8",
        )
        monitor.chmod(0o755)
        subprocess.run(
            ["git", "config", "core.fsmonitor", str(monitor)],
            cwd=self.git.repo,
            check=True,
        )
        result = workspace._run(
            self.git.repo,
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        )
        self.assertEqual(result["returncode"], 0, result["stderr"])
        self.assertFalse(marker_path.exists())

    def test_runtime_sandbox_argv_uses_validated_resolved_binary(self) -> None:
        binary = self.root / "bwrap-real"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        with mock.patch.object(sandbox, "BWRAP", binary):
            argv = sandbox.runtime_sandbox_argv(["/untrusted/bwrap", "--version"])
        self.assertEqual(argv[0], str(binary.resolve()))
        self.assertEqual(argv[1:], ["--version"])

    def test_bounded_capture_does_not_wait_for_detached_pipe_holder(self) -> None:
        started = time.monotonic()
        captured = sandbox.run_bounded_capture(
            [
                sys.executable,
                "-c",
                "import os,time; pid=os.fork(); os._exit(0) if pid else (time.sleep(30), os._exit(0))",
            ],
            stdout_limit=1024,
            stderr_limit=1024,
        )
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(captured.returncode, 0)

    def test_load_json_rejects_oversized_state_file(self) -> None:
        path = self.state / "oversized.json"
        path.write_bytes(b"{" + b" " * workspace.MAX_STATE_JSON_BYTES + b"}")
        path.chmod(0o600)
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "exceeds"):
            workspace._load_json(path)

    def test_load_json_binds_metadata_and_payload_to_one_private_regular_inode(self) -> None:
        target = self.state / "state.json"
        workspace._atomic_json(target, {"schema_version": 1})
        self.assertEqual(workspace._load_json(target), {"schema_version": 1})

        target.chmod(0o640)
        with self.assertRaisesRegex(PermissionError, "unsafe workspace state path"):
            workspace._load_json(target)
        target.chmod(0o600)

        outside = self.state / "outside-state.json"
        outside.write_text('{"schema_version": 1}\n', encoding="utf-8")
        outside.chmod(0o600)
        target.unlink()
        os.link(outside, target)
        with self.assertRaisesRegex(PermissionError, "unsafe workspace state path"):
            workspace._load_json(target)
        target.unlink()
        outside.unlink()

        os.mkfifo(target, 0o600)
        with self.assertRaisesRegex(PermissionError, "unsafe workspace state path"):
            workspace._load_json(target)
        target.unlink()

        target.symlink_to(self.state / "missing-state.json")
        with self.assertRaisesRegex(PermissionError, "unsafe workspace state path"):
            workspace._load_json(target)

    def test_pane_command_binds_workspace_environment_explicitly(self) -> None:
        with mock.patch.dict("os.environ", {"PYTHONPATH": "/tmp/source"}, clear=False):
            command = workspace._pane_command("gaw-test-pane-12345678", "captain")
        self.assertIn("GRABOWSKI_AGENT_WORKSPACE_ROOT=", command)
        self.assertIn("GRABOWSKI_TMUX_BIN=", command)
        self.assertIn("PYTHONPATH=/tmp/source", command)
        self.assertIn("gaw-test-pane-12345678", command)
        self.assertTrue(command.endswith("captain"))

    def test_created_pane_id_requires_exact_tmux_identifier(self) -> None:
        self.assertEqual(
            workspace._created_pane_id(
                {"returncode": 0, "stdout": "%42\n", "stderr": ""},
                "tmux",
            ),
            "%42",
        )
        for value in ("%abc", "%1 extra", "pane-1", "%"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "valid pane id"):
                    workspace._created_pane_id(
                        {"returncode": 0, "stdout": value + "\n", "stderr": ""},
                        "tmux",
                    )

    def test_tmux_creation_cleans_owned_session_when_first_pane_receipt_is_invalid(self) -> None:
        manifest = self.manifest()
        commands: list[list[str]] = []

        def tmux(argv: list[str], *, timeout: int = 30):
            del timeout
            commands.append(argv)
            if argv[0] == "new-session":
                return {"returncode": 0, "stdout": "not-a-pane-id\n", "stderr": ""}
            if argv[0] == "kill-session":
                return {"returncode": 0, "stdout": "", "stderr": ""}
            raise AssertionError(argv)

        with (
            mock.patch.object(workspace, "_tmux_has_session", return_value=False),
            mock.patch.object(workspace, "_tmux_result", side_effect=tmux),
        ):
            with self.assertRaisesRegex(workspace.AgentWorkspaceActionError, "valid pane id"):
                workspace._create_tmux(manifest)
        self.assertEqual(commands[-1], ["kill-session", "-t", manifest["session_name"]])

    def test_tmux_creation_records_role_specific_pane_ids(self) -> None:
        manifest = self.manifest()
        created = iter(["%11", "%12", "%13", "%14"])
        commands: list[list[str]] = []

        def tmux(argv: list[str], *, timeout: int = 30):
            del timeout
            commands.append(argv)
            if argv[0] in {"new-session", "split-window"}:
                return {"returncode": 0, "stdout": next(created) + "\n", "stderr": ""}
            if argv[0] == "list-panes":
                return {"returncode": 0, "stdout": "%11\n%12\n%13\n%14\n", "stderr": ""}
            return {"returncode": 0, "stdout": "", "stderr": ""}

        with (
            mock.patch.object(workspace, "_tmux_has_session", return_value=False),
            mock.patch.object(workspace, "_tmux_result", side_effect=tmux),
        ):
            panes = workspace._create_tmux(manifest)
        self.assertEqual(
            panes,
            {"captain": "%11", "writer": "%12", "tests": "%13", "review": "%14"},
        )
        starts = [argv for argv in commands if argv[0] in {"new-session", "split-window"}]
        self.assertIn("captain", starts[0][-1])
        self.assertIn("writer", starts[1][-1])
        self.assertIn("tests", starts[2][-1])
        self.assertIn("review", starts[3][-1])

    def test_collect_blocks_missing_toolchain_preflight_without_consuming_attempt(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        manifest["commands"]["tests"] = ["python3", "-m", "pytest"]
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(
                workspace,
                "_role_toolchain_preflight",
                side_effect=missing_module_preflight,
            ),
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "role_toolchain_preflight_failed")
        self.assertEqual(result["role"], "tests")
        self.assertTrue(result["preflight"]["missing_python_module"])
        self.assertEqual(result["preflight"]["declared_python_module"], "pytest")
        self.assertFalse(result["preflight"]["missing_executable"])
        start.assert_not_called()
        persisted = workspace._manifest(manifest["workspace_id"])
        self.assertIsNone(persisted["tasks"]["tests"])
        self.assertEqual(persisted.get("task_start_intents", {}), {})
        self.assertEqual(len(persisted["role_preflight_blocks"]["tests"]), 1)
        self.assertFalse((self.state / manifest["workspace_id"] / "tests-receipt.json").exists())

    def test_role_retry_starts_with_replacement_command_after_preflight_block_and_preserves_attempt_one(
        self,
    ) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        manifest["commands"]["tests"] = ["python3", "-m", "pytest"]
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(
                workspace,
                "_role_toolchain_preflight",
                side_effect=missing_module_preflight,
            ),
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            blocked = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(blocked["state"], "role_toolchain_preflight_failed")
        start.assert_not_called()

        def fake_task_start(**kwargs):
            return {
                "task": {
                    "task_id": "tests-retry-task",
                    "host": kwargs["host"],
                    "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                    "cwd": kwargs["cwd"],
                }
            }

        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=fake_task_start),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            retried = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(retried["state"], "retry_started")
        self.assertEqual(retried["attempt"], 1)
        self.assertEqual(retried["task"]["task_id"], "tests-retry-task")
        self.assertEqual(retried["attempt_record"]["retry_reason"], "toolchain_preflight_blocked")
        self.assertEqual(
            retried["attempt_record"]["previous_failure_classification"],
            "toolchain_preflight_blocked",
        )
        self.assertEqual(retried["attempt_record"]["selected_final_attempt"], 1)
        self.assertEqual(retried["attempt_record"]["new_task_id"], "tests-retry-task")
        self.assertIsNone(retried["attempt_record"]["previous_task_id"])
        self.assertIsNone(retried["attempt_record"]["previous_receipt_sha256"])

        persisted = workspace._manifest(manifest["workspace_id"])
        self.assertEqual(persisted["tasks"]["tests"], "tests-retry-task")
        self.assertEqual(persisted["role_final_attempt"]["tests"], 1)
        self.assertEqual(persisted["role_retries"]["tests"]["count"], 1)
        self.assertEqual(len(persisted["role_preflight_blocks"]["tests"]), 1)
        self.assertEqual(persisted.get("task_start_intents", {}), {})
        self.assertFalse((self.state / manifest["workspace_id"] / "tests-receipt.json").exists())
        self.assertFalse(
            workspace._role_receipt_path(manifest, "tests", attempt=1).exists()
        )

        # A second retry attempt for the same role must be refused once the budget is spent.
        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "tests-retry-task", "state": "running", "terminal": False}),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as second_start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            second = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(second["state"], "role_running")
        second_start.assert_not_called()

    def test_collect_completes_using_retried_command_receipt(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        manifest["commands"]["tests"] = ["python3", "-m", "pytest"]
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(
                workspace,
                "_role_toolchain_preflight",
                side_effect=missing_module_preflight,
            ),
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "writer-task", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_start"),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])

        replacement = ["python3", "-m", "unittest"]

        def fake_task_start(**kwargs):
            return {
                "task": {
                    "task_id": "tests-retry-task",
                    "host": kwargs["host"],
                    "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                    "cwd": kwargs["cwd"],
                }
            }

        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=fake_task_start),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            workspace.grabowski_agent_workspace_role_retry(manifest["workspace_id"], "tests", replacement)

        manifest = workspace._manifest(manifest["workspace_id"])
        manifest["tasks"]["review"] = "review-task"
        workspace._write_manifest(manifest)
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        tests_receipt = signed_role_receipt(
            "tests", manifest, snapshot, argv_sha256=workspace._sha256_json(replacement)
        )
        review_receipt = signed_role_receipt("review", manifest, snapshot)
        workspace._atomic_json(
            workspace._role_receipt_path(manifest, "tests", attempt=1), tests_receipt
        )
        workspace._atomic_json(workspace._role_receipt_path(manifest, "review"), review_receipt)

        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_collect(manifest["workspace_id"])
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["result"]["tests"]["status"], "passed")
        checklist_items = {item["item"] for item in result["external_closeout_checklist"]}
        self.assertEqual(
            checklist_items,
            {
                "pr_integration_truth",
                "bureau_task_reconciliation",
                "workspace_lease_release",
                "writer_worktree_archive_or_cleanup",
                "operator_final_summary",
            },
        )
        self.assertTrue(all(item["status"] == "unknown" for item in result["external_closeout_checklist"]))

    def test_role_retry_blocks_unresolved_retry_start_intent_before_second_start(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": workspace._materialize_writer_patch(
                manifest, snapshot, workspace._run
            ),
        }
        manifest["tasks"]["tests"] = "tests-task-1"
        manifest["role_preflight_blocks"] = {
            "tests": [
                {
                    "failure_classification": "environment_toolchain_failure",
                    "attempt": None,
                    "attempt_consumed": False,
                }
            ]
        }
        intent = {
            "role": "tests",
            "kind": "retry",
            "attempt": 1,
            "task_argv_sha256": "a" * 64,
        }
        manifest["task_start_intents"] = {"tests": intent}
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "role_start_outcome_unknown")
        self.assertTrue(result["reconcile_required"])
        self.assertEqual(result["task_start_intent"], intent)
        start.assert_not_called()
        persisted = workspace._manifest(manifest["workspace_id"])
        self.assertEqual(persisted["task_start_intents"]["tests"], intent)

        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(persisted)
        self.assertEqual(
            status["role_retry"]["tests"]["classification"],
            "role_start_outcome_unknown",
        )
        self.assertFalse(status["role_retry"]["tests"]["eligible"])
        self.assertEqual(status["recommended_next_action"], "reconcile_role_start_outcome")

        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            collection = workspace.grabowski_agent_workspace_collect(
                manifest["workspace_id"]
            )
        self.assertEqual(collection["state"], "role_start_outcome_unknown")
        self.assertEqual(collection["task_start_intents"], {"tests": intent})
        self.assertTrue(collection["reconcile_required"])

    def test_role_retry_blocks_existing_attempt_receipt_before_task_start(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["role_preflight_blocks"] = {
            "tests": [
                {
                    "failure_classification": "environment_toolchain_failure",
                    "attempt": None,
                    "attempt_consumed": False,
                }
            ]
        }
        workspace._write_manifest(manifest)
        receipt_path = workspace._role_receipt_path(manifest, "tests", attempt=1)
        receipt_path.write_text("orphan receipt\n", encoding="utf-8")
        receipt_path.chmod(0o600)
        before = receipt_path.read_bytes()
        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "attempt_receipt_already_exists")
        self.assertEqual(result["attempt"], 1)
        self.assertEqual(receipt_path.read_bytes(), before)
        start.assert_not_called()

    def test_role_retry_blocks_on_semantic_test_failure(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        writer_result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": writer_result,
        }
        manifest["tasks"]["tests"] = "tests-task-1"
        workspace._write_manifest(manifest)
        receipt = signed_role_receipt("tests", manifest, snapshot, returncode=1)
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), receipt)

        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "tests-task-1", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "semantic_test_failure")
        self.assertEqual(result["returncode"], 1)
        start.assert_not_called()

    def test_role_retry_blocks_on_review_needs_change(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        writer_result = workspace._materialize_writer_patch(manifest, snapshot, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": writer_result,
        }
        manifest["tasks"]["review"] = "review-task-1"
        workspace._write_manifest(manifest)
        receipt = signed_role_receipt(
            "review",
            manifest,
            snapshot,
            verdict="NEEDS_CHANGE",
            findings=[{"summary": "needs a fix"}],
            returncode=1,
        )
        workspace._atomic_json(workspace._role_receipt_path(manifest, "review"), receipt)

        with (
            mock.patch.object(workspace, "_task_public", return_value={"task_id": "review-task-1", "state": "completed", "terminal": True}),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "review", ["python3", "-c", "print('{\"verdict\":\"PASS\",\"findings\":[]}')"]
            )
        self.assertEqual(result["state"], "review_verdict_blocks_retry")
        self.assertEqual(result["verdict"], "NEEDS_CHANGE")
        start.assert_not_called()

    def test_role_retry_blocks_after_close(self) -> None:
        manifest = self.manifest()
        manifest["close_receipt"] = {"state": "complete"}
        workspace._write_manifest(manifest)
        with mock.patch.object(workspace.operator, "_require_operator_mutation"):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "workspace_closed")

    def test_role_retry_blocks_on_binding_drift(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        workspace._write_manifest(manifest)
        (self.git.writer / "src" / "app.py").write_text("dirty = True\nextra = 1\n", encoding="utf-8")

        with mock.patch.object(workspace.operator, "_require_operator_mutation"):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "binding_drift")

    def test_role_retry_rejects_writer_role(self) -> None:
        manifest = self.manifest()
        with self.assertRaisesRegex(workspace.AgentWorkspaceError, "writer may never be retried"):
            workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "writer", ["true"]
            )

    def test_malformed_retry_state_blocks_status_and_retry_fail_closed(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["tasks"]["tests"] = None
        manifest["role_preflight_blocks"] = {
            "tests": [
                {
                    "failure_classification": "environment_toolchain_failure",
                    "attempt": None,
                    "attempt_consumed": False,
                }
            ]
        }
        manifest["role_retries"] = {
            "tests": {"count": "one", "attempts": []}
        }
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "retry_state_invalid")
        start.assert_not_called()

        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"state": "completed", "terminal": True},
            ),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(workspace._manifest(manifest["workspace_id"]))
        self.assertEqual(
            status["role_retry"]["tests"]["classification"],
            "retry_state_invalid",
        )
        self.assertFalse(status["role_retry"]["tests"]["eligible"])
        self.assertIsNone(status["role_retry"]["tests"]["retries_used"])

    def test_role_retry_enforces_max_one_retry_budget(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["tasks"]["tests"] = None
        manifest["role_preflight_blocks"] = {"tests": [{"passed": False, "attempt": None, "attempt_consumed": False, "proposed_attempt": 1, "failure_classification": "environment_toolchain_failure"}]}
        manifest["role_retries"] = {"tests": {"count": 1, "attempts": [{"attempt": 2}]}}
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "retry_limit_reached")
        start.assert_not_called()

    def test_close_requires_explicit_abandon_for_failed_roles(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(
            manifest,
            {
                "writer_head": snapshot["writer_head"],
                "diff_sha256": snapshot["diff_sha256"],
                "tests": {"status": "failed"},
                "review": {"status": "passed", "verdict": "PASS", "findings": []},
            },
        )
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            blocked = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"], snapshot["writer_head"], snapshot["diff_sha256"], collection["result_sha256"]
            )
        self.assertEqual(blocked["state"], "failed_roles_require_explicit_abandonment")
        self.assertEqual(blocked["failed_roles"], ["tests"])
        self.assertTrue(self.git.writer.exists())
        self.assertIsNone(workspace._manifest(manifest["workspace_id"])["close_receipt"])

        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
            mock.patch.object(workspace, "_tmux_result", return_value={"returncode": 0, "stdout": "", "stderr": ""}),
            mock.patch.object(
                workspace.resources,
                "release_resources",
                return_value={"released": [{"resource_key": key} for key in manifest["resources"]["lease_keys"]]},
            ),
            mock.patch.object(workspace.resources, "list_resources", return_value=[]),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"],
                snapshot["writer_head"],
                snapshot["diff_sha256"],
                collection["result_sha256"],
                abandon_failed_roles=True,
            )
        receipt = result["close_receipt"]
        self.assertEqual(receipt["closure_outcome"], "abandoned_failed_roles")
        self.assertEqual(receipt["failed_roles"], ["tests"])
        self.assertEqual(receipt["state"], "complete")

    def test_status_reports_role_retry_eligibility_and_recommended_action(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["role_preflight_blocks"] = {"tests": [{"passed": False, "attempt": None, "attempt_consumed": False, "proposed_attempt": 1, "failure_classification": "environment_toolchain_failure"}]}
        manifest["tasks"]["tests"] = None
        manifest["tasks"]["review"] = None
        workspace._write_manifest(manifest)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertTrue(status["role_retry"]["tests"]["eligible"])
        self.assertEqual(status["role_retry"]["tests"]["classification"], "eligible")
        self.assertFalse(status["role_retry"]["review"]["eligible"])
        self.assertEqual(status["role_retry"]["review"]["classification"], "not_attempted")
        self.assertEqual(status["recommended_next_action"], "retry_role:tests")

    def test_status_recommends_abandon_for_unretryable_failed_roles(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        persist_collection(
            manifest,
            {
                "writer_head": snapshot["writer_head"],
                "diff_sha256": snapshot["diff_sha256"],
                "tests": {"status": "failed"},
                "review": {"status": "passed", "verdict": "PASS", "findings": []},
            },
        )
        manifest = workspace._manifest(manifest["workspace_id"])
        receipt = signed_role_receipt("tests", manifest, snapshot, returncode=1)
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), receipt)
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        self.assertEqual(status["failed_roles"], ["tests"])
        self.assertFalse(status["role_retry"]["tests"]["eligible"])
        self.assertEqual(status["role_retry"]["tests"]["classification"], "semantic_test_failure")
        self.assertEqual(status["closure_outcome"], "would_abandon_failed_roles")
        self.assertEqual(status["recommended_next_action"], "close_with_abandon_failed_roles")

    def test_expected_role_command_hash_is_bound_to_selected_attempt(self) -> None:
        manifest = self.manifest()
        original = workspace._sha256_json(manifest["commands"]["tests"])
        second = "2" * 64
        third = "3" * 64
        manifest["role_retries"] = {
            "tests": {
                "count": 2,
                "attempts": [
                    {"attempt": 2, "new_command_sha256": second},
                    {"attempt": 3, "new_command_sha256": third},
                ],
            }
        }
        manifest["role_final_attempt"] = {"tests": 2}
        self.assertEqual(workspace._expected_role_argv_sha256(manifest, "tests"), second)
        self.assertEqual(
            workspace._expected_role_argv_sha256(manifest, "tests", attempt=3), third
        )
        self.assertEqual(
            workspace._expected_role_argv_sha256(manifest, "tests", attempt=1), original
        )
        manifest["role_retries"]["tests"]["attempts"].append(
            {"attempt": 2, "new_command_sha256": "4" * 64}
        )
        self.assertIsNone(workspace._expected_role_argv_sha256(manifest, "tests"))

    def test_role_receipt_paths_are_attempt_specific_and_never_collide(self) -> None:
        manifest = self.manifest()
        first = workspace._role_receipt_path(manifest, "tests", attempt=1)
        second = workspace._role_receipt_path(manifest, "tests", attempt=2)
        self.assertNotEqual(first, second)
        self.assertEqual(first.name, "tests-receipt.json")
        self.assertEqual(second.name, "tests-receipt.attempt-2.json")
        self.assertEqual(workspace._role_final_attempt(manifest, "tests"), 1)
        manifest["role_final_attempt"] = {"tests": 2}
        self.assertEqual(workspace._role_final_attempt(manifest, "tests"), 2)
        with self.assertRaises(workspace.AgentWorkspaceError):
            workspace._role_receipt_path(manifest, "tests", attempt=0)

    def test_status_always_exposes_external_closeout_checklist(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "running", "terminal": False}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
        ):
            status = workspace._status_data(manifest)
        items = {item["item"] for item in status["external_closeout_checklist"]}
        self.assertEqual(
            items,
            {
                "pr_integration_truth",
                "bureau_task_reconciliation",
                "workspace_lease_release",
                "writer_worktree_archive_or_cleanup",
                "operator_final_summary",
            },
        )

    def test_close_expose_unresolved_external_closeout_checklist(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(manifest, {
            "writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"],
        })
        with (
            mock.patch.object(workspace, "_task_public", return_value={"state": "completed", "terminal": True}),
            mock.patch.object(workspace, "_tmux_has_session", return_value=True),
            mock.patch.object(workspace, "_tmux_result", return_value={"returncode": 0, "stdout": "", "stderr": ""}),
            mock.patch.object(
                workspace.resources,
                "release_resources",
                return_value={"released": [{"resource_key": key} for key in manifest["resources"]["lease_keys"]]},
            ),
            mock.patch.object(workspace.resources, "list_resources", return_value=[]),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
            mock.patch.object(workspace.base, "_append_audit"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"], snapshot["writer_head"], snapshot["diff_sha256"], collection["result_sha256"]
            )
        checklist = result["external_closeout_checklist"]
        self.assertTrue(checklist)
        lease_item = next(item for item in checklist if item["item"] == "workspace_lease_release")
        self.assertEqual(lease_item["status"], "verified")
        self.assertTrue(lease_item["evidence"]["resources_released"])
        self.assertTrue(
            all(
                item["status"] == "unknown"
                for item in checklist
                if item["item"] != "workspace_lease_release"
            )
        )
        bureau_item = next(item for item in checklist if item["item"] == "bureau_task_reconciliation")
        self.assertEqual(bureau_item["binding"], manifest["binding"])


    def test_terminal_typed_environment_failure_retries_as_attempt_two(self) -> None:
        manifest = self.manifest()
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
            "writer_result": workspace._materialize_writer_patch(manifest, snapshot, workspace._run),
        }
        manifest["tasks"]["tests"] = "tests-task-1"
        workspace._write_manifest(manifest)
        first_receipt = signed_role_receipt(
            "tests",
            manifest,
            snapshot,
            returncode=1,
            failure_classification="environment_toolchain_failure",
        )
        first_path = workspace._role_receipt_path(manifest, "tests", attempt=1)
        workspace._atomic_json(first_path, first_receipt)
        first_bytes = first_path.read_bytes()

        def fake_task_start(**kwargs):
            return {
                "task": {
                    "task_id": "tests-task-2",
                    "host": kwargs["host"],
                    "argv_sha256": workspace._sha256_json(kwargs["argv"]),
                    "cwd": kwargs["cwd"],
                }
            }

        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"task_id": "tests-task-1", "state": "failed", "terminal": True},
            ),
            mock.patch.object(workspace.tasks, "grabowski_task_start", side_effect=fake_task_start),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "retry_started")
        self.assertEqual(result["attempt"], 2)
        self.assertEqual(result["attempt_record"]["previous_task_id"], "tests-task-1")
        self.assertEqual(
            result["attempt_record"]["retry_reason"],
            "terminal_environment_toolchain_failure",
        )
        self.assertEqual(
            result["attempt_record"]["previous_failure_classification"],
            "environment_toolchain_failure",
        )
        self.assertEqual(result["attempt_record"]["selected_final_attempt"], 2)
        self.assertEqual(
            result["attempt_record"]["previous_receipt_sha256"],
            first_receipt["receipt_sha256"],
        )
        self.assertEqual(first_path.read_bytes(), first_bytes)
        persisted = workspace._manifest(manifest["workspace_id"])
        self.assertEqual(persisted["role_final_attempt"]["tests"], 2)
        self.assertEqual(persisted["tasks"]["tests"], "tests-task-2")
        self.assertFalse(workspace._role_receipt_path(manifest, "tests", attempt=2).exists())

    def test_explicit_semantic_rc127_does_not_become_environment_retry(self) -> None:
        manifest = self.manifest()
        manifest["commands"]["tests"] = ["missing-tool"]
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["tasks"]["tests"] = "tests-task-1"
        workspace._write_manifest(manifest)
        receipt = signed_role_receipt(
            "tests",
            manifest,
            snapshot,
            returncode=127,
            failure_classification="semantic_test_failure",
            stderr_tail="bwrap: execvp missing-tool: No such file or directory",
        )
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), receipt)
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"task_id": "tests-task-1", "state": "failed", "terminal": True},
            ),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "semantic_test_failure")
        start.assert_not_called()

    def test_toolchain_probe_source_does_not_execute_sitecustomize_or_target_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            site_marker = root / "sitecustomize-ran"
            module_marker = root / "module-ran"
            (root / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(site_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            (root / "probe_target.py").write_text(
                f"from pathlib import Path\nPath({str(module_marker)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    role._MODULE_PROBE_SOURCE,
                    "probe_target",
                    sys.executable,
                ],
                cwd=root,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["module_found"])
        self.assertFalse(site_marker.exists())
        self.assertFalse(module_marker.exists())

    def test_toolchain_probe_uses_exact_resolved_interpreter_without_site_initialization(self) -> None:
        manifest = self.manifest()
        resolved = "/custom/venv/bin/python3"

        def capture(payload: bytes) -> sandbox.BoundedCapture:
            return sandbox.BoundedCapture(
                returncode=0,
                stdout_bytes=len(payload),
                stderr_bytes=0,
                stdout_sha256="a" * 64,
                stderr_sha256="b" * 64,
                stdout_tail=payload.decode("utf-8"),
                stderr_tail="",
                stdout_content=payload,
                stdout_content_exceeded=False,
                stdout_limit_exceeded=False,
                stderr_limit_exceeded=False,
            )

        captures = [
            capture(
                json.dumps(
                    {
                        "executable_found": True,
                        "resolved_executable": resolved,
                    }
                ).encode("utf-8")
            ),
            capture(b'{"module_found": true}'),
        ]
        with (
            mock.patch.object(role, "runtime_sandbox_argv", side_effect=lambda argv: argv),
            mock.patch.object(
                role,
                "run_bounded_capture",
                side_effect=captures,
            ) as run_capture,
        ):
            result = self.real_role_toolchain_preflight(
                manifest, "tests", ["python3", "-m", "unittest"]
            )
        self.assertTrue(result["passed"])
        self.assertEqual(result["resolved_executable"], resolved)
        self.assertEqual(run_capture.call_count, 2)
        executable_probe = run_capture.call_args_list[0].args[0]
        module_probe = run_capture.call_args_list[1].args[0]
        executable_index = executable_probe.index(role._sandbox_probe_python())
        self.assertEqual(
            executable_probe[executable_index + 1 : executable_index + 4],
            ["-I", "-S", "-c"],
        )
        module_index = module_probe.index(resolved)
        self.assertEqual(
            module_probe[module_index + 1 : module_index + 4],
            ["-I", "-S", "-c"],
        )
        self.assertEqual(module_probe[-2:], ["unittest", resolved])


    def test_preflight_probe_error_is_not_reported_as_missing_prerequisites(self) -> None:
        manifest = self.manifest()
        with (
            mock.patch.object(role, "runtime_sandbox_argv", side_effect=lambda argv: argv),
            mock.patch.object(role, "run_bounded_capture", side_effect=OSError("probe unavailable")),
        ):
            result = self.real_role_toolchain_preflight(
                manifest, "tests", ["python3", "-m", "unittest"]
            )
        self.assertFalse(result["passed"])
        self.assertEqual(result["failure_classification"], "toolchain_probe_error")
        self.assertFalse(result["missing_executable"])
        self.assertFalse(result["missing_python_module"])
        self.assertIn("probe unavailable", result["probe_error"])

    def test_preflight_checks_exact_executable_path(self) -> None:
        manifest = self.manifest()
        capture = sandbox.BoundedCapture(
            returncode=0,
            stdout_bytes=52,
            stderr_bytes=0,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            stdout_tail='{"executable_found": false, "resolved_executable": null}',
            stderr_tail="",
            stdout_content=b'{"executable_found": false, "resolved_executable": null}',
            stdout_content_exceeded=False,
            stdout_limit_exceeded=False,
            stderr_limit_exceeded=False,
        )
        with (
            mock.patch.object(role, "runtime_sandbox_argv", side_effect=lambda argv: argv),
            mock.patch.object(role, "run_bounded_capture", return_value=capture),
        ):
            result = self.real_role_toolchain_preflight(
                manifest, "tests", ["/definitely/missing/python3", "-m", "unittest"]
            )
        self.assertEqual(result["executable"], "/definitely/missing/python3")
        self.assertTrue(result["missing_executable"])
        self.assertFalse(result["missing_python_module"])
        self.assertEqual(result["failure_classification"], "environment_toolchain_failure")

    def test_close_blocks_complete_collection_with_incomplete_role_evidence(self) -> None:
        manifest = self.manifest()
        self.git.commit_writer()
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["tasks"].update({"tests": "tests-task", "review": "review-task"})
        collection = persist_collection(
            manifest,
            {"writer_head": snapshot["writer_head"], "diff_sha256": snapshot["diff_sha256"]},
        )
        collection.pop("review")
        collection["result_sha256"] = workspace._collection_result_sha256(collection)
        manifest["collection"] = collection
        workspace._write_manifest(manifest)
        workspace._atomic_json(
            self.state / manifest["workspace_id"] / "collection-receipt.json", collection
        )
        with (
            mock.patch.object(
                workspace, "_task_public", return_value={"state": "completed", "terminal": True}
            ),
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_close(
                manifest["workspace_id"],
                snapshot["writer_head"],
                snapshot["diff_sha256"],
                collection["result_sha256"],
            )
        self.assertEqual(result["state"], "incomplete_role_evidence")
        self.assertEqual(result["incomplete_roles"], ["review"])
        self.assertIsNone(workspace._manifest(manifest["workspace_id"])["close_receipt"])



    def test_review_environment_failure_precedes_invalid_output_classification(self) -> None:
        payload = {"returncode": 126, "verdict": "INVALID", "error": "invalid review"}
        with mock.patch.object(
            role,
            "toolchain_probe",
            return_value={"failure_classification": "environment_toolchain_failure"},
        ):
            classification = role.classify_result(
                "review", ["python3", "-m", "missing_reviewer"], self.git.writer, payload
            )
        self.assertEqual(classification, "environment_toolchain_failure")
        self.assertEqual(
            payload["post_failure_toolchain_probe"]["failure_classification"],
            "environment_toolchain_failure",
        )

    def test_role_attempt_receipt_create_only_preserves_existing_bytes(self) -> None:
        target = self.root / "immutable-attempt.json"
        target.write_text("original\n", encoding="utf-8")
        target.chmod(0o600)
        before = target.read_bytes()
        with self.assertRaisesRegex(FileExistsError, "already exists"):
            role.write_receipt(target, {"schema_version": 1}, create_only=True)
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_role_attempt_receipt_create_only_publish_race_preserves_winner(self) -> None:
        target = self.root / "raced-attempt.json"
        winner = b'{"winner": true}\n'

        def competing_publish(*args: object, **kwargs: object) -> None:
            del args, kwargs
            target.write_bytes(winner)
            target.chmod(0o600)
            raise FileExistsError("competing publisher won")

        with mock.patch.object(role.os, "link", side_effect=competing_publish):
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                role.write_receipt(
                    target,
                    {"schema_version": 1, "winner": False},
                    create_only=True,
                )
        self.assertEqual(target.read_bytes(), winner)
        self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])

    def test_role_attempt_receipt_rejects_broken_symlink_target(self) -> None:
        target = self.root / "broken-attempt.json"
        target.symlink_to(self.root / "missing-receipt.json")
        with self.assertRaisesRegex(PermissionError, "owner-controlled regular file"):
            role.write_receipt(target, {"schema_version": 1}, create_only=True)
        self.assertTrue(target.is_symlink())
        self.assertEqual(list(target.parent.glob(f".{target.name}.*.tmp")), [])



    def test_untyped_legacy_missing_executable_text_does_not_authorize_retry(self) -> None:
        manifest = self.manifest()
        manifest["commands"]["tests"] = ["missing-tool"]
        (self.git.writer / "src" / "app.py").write_text("dirty = True\n", encoding="utf-8")
        snapshot = workspace._git_snapshot(manifest, workspace._run)
        manifest["frozen_writer"] = {
            "writer_head": snapshot["writer_head"],
            "diff_sha256": snapshot["diff_sha256"],
            "dirty": snapshot["dirty"],
        }
        manifest["tasks"]["tests"] = "legacy-tests-task"
        workspace._write_manifest(manifest)
        receipt = signed_role_receipt(
            "tests",
            manifest,
            snapshot,
            returncode=127,
            stderr_tail="bwrap: execvp missing-tool: No such file or directory",
        )
        workspace._atomic_json(workspace._role_receipt_path(manifest, "tests"), receipt)
        with (
            mock.patch.object(
                workspace,
                "_task_public",
                return_value={"task_id": "legacy-tests-task", "state": "failed", "terminal": True},
            ),
            mock.patch.object(workspace.tasks, "grabowski_task_start") as start,
            mock.patch.object(workspace.operator, "_require_operator_mutation"),
        ):
            result = workspace.grabowski_agent_workspace_role_retry(
                manifest["workspace_id"], "tests", ["python3", "-m", "unittest"]
            )
        self.assertEqual(result["state"], "semantic_test_failure")
        start.assert_not_called()

    def test_private_runtime_venv_falls_back_to_usr_interpreter(self) -> None:
        calls: list[list[str]] = []

        def probe(repo: Path, command: list[str]):
            del repo
            calls.append(command)
            if len(calls) == 1:
                return ({"executable_found": True, "resolved_executable": "/usr/bin/python3"}, None, 0)
            return ({"module_found": True}, None, 0)

        with (
            mock.patch.object(role.sys, "executable", "/home/alex/private-venv/bin/python"),
            mock.patch.object(role, "_probe_json", side_effect=probe),
        ):
            result = role.toolchain_probe(
                Path("/tmp/repository"),
                ["/usr/bin/python3", "-m", "unittest"],
            )

        self.assertTrue(result["passed"])
        self.assertEqual(calls[0][0], "/usr/bin/python3")
        self.assertEqual(calls[1][0], "/usr/bin/python3")

    def test_probe_runner_fails_closed_without_usr_python(self) -> None:
        with (
            mock.patch.object(role.sys, "executable", "/home/alex/private-venv/bin/python"),
            mock.patch.object(Path, "resolve", side_effect=FileNotFoundError("missing")),
        ):
            with self.assertRaisesRegex(RuntimeError, "no Python interpreter"):
                role._sandbox_probe_python()

    def test_forged_close_outcome_is_not_projected_without_valid_receipt(self) -> None:
        manifest = self.manifest()
        manifest["close_receipt"] = {"closure_outcome": "successful"}
        workspace._write_manifest(manifest)
        self.assertEqual(workspace._prospective_closure_outcome(manifest, None), "unknown")




    def test_workspace_outcome_receipt_is_phase_bound_and_idempotent(self) -> None:
        manifest = self.manifest()
        collection = persist_collection(
            manifest,
            {
                "workspace_id": manifest["workspace_id"],
                "binding": manifest["binding"],
                "expected_base_head": manifest["expected_base_head"],
                "writer_head": manifest["expected_base_head"],
                "diff_sha256": "d" * 64,
                "writer_result": {
                    "type": "patch",
                    "path": str(self.state / manifest["workspace_id"] / "writer.patch"),
                    "sha256": "e" * 64,
                    "bytes": 10,
                    "applies_to": manifest["expected_base_head"],
                },
                "changed_paths": ["src/app.py"],
                "scope_passed": True,
                "scope_violations": [],
                "dirty": True,
                "base_drift": False,
                "integration_probe": None,
                "task_ids": {"writer": "writer-task", "tests": "tests-task", "review": "review-task"},
                "writer_task": {"state": "completed"},
                "writer_receipt_sha256": "f" * 64,
                "collected_at": "2026-07-13T05:30:00+00:00",
            },
        )
        manifest["collection"] = collection
        manifest["created_at"] = "2026-07-13T05:20:00+00:00"
        first = workspace._publish_workspace_outcome(manifest, "collection")
        second = workspace._publish_workspace_outcome(manifest, "collection")
        self.assertEqual(first, second)
        self.assertEqual(first["phase"], "collection")
        self.assertEqual(first["elapsed_seconds"], 600)
        self.assertEqual(first["route_evidence"]["actual_route"], "full_workspace")
        self.assertFalse(first["route_evidence"]["evidence_complete"])
        self.assertEqual(
            first["frozen_result_identity"]["result_sha256"],
            collection["result_sha256"],
        )
        self.assertTrue(workspace._outcome_receipt_path(manifest, "collection").is_file())
        self.assertEqual(
            manifest["outcome_receipts"]["collection"]["outcome_sha256"],
            first["outcome_sha256"],
        )
        self.assertFalse(first["evidence_complete"])
        self.assertTrue(first["route_legacy_compatibility"])
        self.assertNotIn("route_evidence", first["missing_fields"])
        self.assertIn(
            "first_pass_role_results.tests.receipt_sha256",
            first["missing_fields"],
        )

    def test_workspace_outcome_with_route_and_role_receipts_is_complete_and_versioned(self) -> None:
        manifest = self.manifest()
        manifest["route_evidence"] = workspace._normalize_route_evidence(complete_route_evidence())
        manifest["created_at"] = "2026-07-13T05:20:00+00:00"
        for role_name in ("tests", "review"):
            payload = {"role": role_name, "returncode": 0}
            if role_name == "review":
                payload.update({"verdict": "PASS", "findings": []})
            workspace._atomic_json(
                workspace._role_receipt_path(manifest, role_name, attempt=1),
                signed_receipt(payload),
            )
        base = {
            "workspace_id": manifest["workspace_id"],
            "binding": manifest["binding"],
            "expected_base_head": manifest["expected_base_head"],
            "writer_head": manifest["expected_base_head"],
            "diff_sha256": "d" * 64,
            "writer_result": {
                "type": "patch",
                "path": str(self.state / manifest["workspace_id"] / "writer.patch"),
                "sha256": "e" * 64,
                "bytes": 10,
                "applies_to": manifest["expected_base_head"],
            },
            "writer_task": {"state": "completed"},
            "writer_receipt_sha256": "f" * 64,
            "collected_at": "2026-07-13T05:30:00+00:00",
        }
        first_collection = persist_collection(manifest, base)
        manifest["collection"] = first_collection
        first = workspace._publish_workspace_outcome(manifest, "collection")
        self.assertTrue(first["evidence_complete"])
        self.assertEqual(first["missing_fields"], [])
        self.assertEqual(first["route_evidence"]["status"], "verified")
        first_path = workspace._outcome_receipt_path(manifest, "collection")
        updated = dict(base)
        updated["collected_at"] = "2026-07-13T05:31:00+00:00"
        updated["tests"] = {"status": "passed", "returncode": 0, "receipt_sha256": "1" * 64}
        second_collection = persist_collection(manifest, updated)
        manifest["collection"] = second_collection
        second = workspace._publish_workspace_outcome(manifest, "collection")
        second_path = workspace._outcome_receipt_path(manifest, "collection")
        self.assertNotEqual(first["outcome_identity"], second["outcome_identity"])
        self.assertNotEqual(first_path, second_path)
        self.assertTrue(first_path.is_file())
        self.assertTrue(second_path.is_file())
        self.assertEqual(len(manifest["outcome_receipts"]["collection"]["history"]), 2)


if __name__ == "__main__":
    unittest.main()
