from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import sys
import types

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

import grabowski_agent_competition as competition  # noqa: E402


class AgentCompetitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        (self.repo / "src").mkdir()
        (self.repo / "tests").mkdir()
        (self.repo / "src" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.repo / "tests" / "test_sample.py").write_text("def test_value():\n    assert True\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=self.repo, check=True)
        self.head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.patchers = [
            mock.patch.object(competition, "COMPETITION_ROOT", self.state),
            mock.patch.object(competition.operator, "_require_operator_mutation"),
            mock.patch.object(competition.operator, "_require_operator_capability"),
            mock.patch.object(competition.shutil, "which", side_effect=lambda provider: f"/usr/bin/{provider}"),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.temporary.cleanup()

    def _task_start(self, task_id: str):
        return {
            "task": {
                "task_id": task_id,
                "unit": f"grabowski-task-{task_id}.service",
                "attempt": 1,
                "state": "running",
                "resume_policy": "never",
            },
            "audit": {},
        }

    def _start(self, *, provider: str = "claude", mode: str = "competitor", task: str = "Improve sample") -> dict:
        task_id = f"task-{provider}-{mode}"
        with mock.patch.object(competition.tasks, "grabowski_task_start", return_value=self._task_start(task_id)) as start:
            result = competition.grabowski_agent_competition_start(
                request_id=f"test-{provider}-{mode}",
                provider=provider,
                mode=mode,
                repository=str(self.repo),
                expected_head=self.head,
                task=task,
                allowed_paths=["src", "tests"],
                context_paths=["src/sample.py", "tests/test_sample.py"],
                forbidden_paths=[],
                timeout_seconds=120,
            )
        call = start.call_args.kwargs
        self.assertEqual(call["resume_policy"], "never")
        self.assertEqual(call["resource_keys"], [f"path:{self.state / result['competition_id']}"])
        return result

    def _write_receipt(
        self,
        identifier: str,
        *,
        changed_paths: list[str],
        risks: list[str],
        tests: list[str],
        patch: str = "",
    ) -> dict:
        manifest = competition._validated_manifest(identifier)
        candidate = {
            "approach_id": identifier,
            "approach_summary": f"Approach for {identifier}",
            "assumptions": ["base is clean"],
            "design_invariants": ["no automatic merge"],
            "tradeoffs": ["more evidence"],
            "risks": risks,
            "proposed_tests": tests,
            "changed_paths": changed_paths,
            "patch": patch,
            "contrast_observations": ["compare boundaries"],
            "confidence": "medium",
            "patch_paths": competition._receipt_patch_paths(patch),
            "patch_sha256": hashlib.sha256(patch.encode()).hexdigest(),
            "patch_check": {
                "attempted": bool(patch),
                "applies": False,
                "returncode": None,
                "stderr_sha256": None,
                "syntax_accepted": True,
            },
            "patch_rejection": None,
        }
        receipt = {
            "schema_version": 1,
            "kind": "external_programming_candidate_receipt",
            "competition_id": identifier,
            "request_id": manifest["request_id"],
            "request_fingerprint": manifest["request_fingerprint"],
            "provider": manifest["provider"],
            "mode": manifest["mode"],
            "repository": manifest["repository"],
            "expected_head": manifest["expected_head"],
            "task_sha256": manifest["task_sha256"],
            "packet_sha256": manifest["packet_sha256"],
            "prompt_sha256": "1" * 64,
            "provider_version": "test",
            "command_shape": [manifest["provider"]],
            "provider_cwd_kind": "isolated_candidate_directory",
            "command_sha256": "2" * 64,
            "prompt_in_argv": False,
            "returncode": 0,
            "runtime_seconds": 1.0,
            "stdout_sha256": "3" * 64,
            "stderr_sha256": "4" * 64,
            "before": {"head": self.head, "clean": True, "context_count": 2},
            "after": {"head": self.head, "clean": True, "context_count": 2},
            "candidate": candidate,
            "authority": "advisory_only",
            "automatic_apply": False,
            "automatic_commit": False,
            "automatic_merge": False,
            "automatic_deploy": False,
            "does_not_establish": ["correctness"],
        }
        receipt["receipt_sha256"] = competition._sha256_json(receipt)
        competition._atomic_json(self.state / identifier / "receipt.json", receipt)
        return receipt

    def test_atomic_publish_cleanup_failure_rolls_back_visible_target(self) -> None:
        directory = self.state / "atomic-test"
        directory.mkdir(mode=0o700)
        target = directory / "state.json"
        original_unlink = competition.os.unlink
        failed_once = False

        def fail_first_temporary_unlink(path):
            nonlocal failed_once
            candidate = Path(path)
            if candidate.name.startswith(".state.json.") and not failed_once:
                failed_once = True
                raise PermissionError("temporary cleanup denied")
            return original_unlink(path)

        with mock.patch.object(competition.os, "unlink", side_effect=fail_first_temporary_unlink):
            with self.assertRaisesRegex(PermissionError, "temporary cleanup denied"):
                competition._atomic_json(target, {"value": 1})
        self.assertFalse(target.exists())
        self.assertEqual(list(directory.iterdir()), [])

    def test_git_environment_discards_rebinding_and_replace_objects(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"PATH": "/usr/bin", "HOME": "/tmp/home", "GIT_DIR": "/tmp/evil", "GIT_CONFIG_COUNT": "1"},
            clear=True,
        ):
            environment = competition._git_environment()
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_context_reads_bound_commit_not_later_worktree_bytes(self) -> None:
        original = (self.repo / "src/sample.py").read_bytes()
        (self.repo / "src/sample.py").write_text("DIRTY = True\n", encoding="utf-8")
        context = competition._context(
            self.repo,
            self.head,
            ["src/sample.py"],
            ["src"],
            [],
        )
        self.assertEqual(context[0]["text"].encode("utf-8"), original)
        self.assertEqual(context[0]["sha256"], competition._sha256_bytes(original))

    def test_route_is_adaptive_and_external_is_not_default_for_small_work(self) -> None:
        direct = competition.grabowski_agent_execution_route(
            task_kind="docs",
            changed_file_estimate=1,
            expected_duration_minutes=5,
            novelty="low",
            available_external_agents=["claude", "agy"],
        )
        self.assertEqual(direct["execution_mode"], "direct_operator")
        competitive = competition.grabowski_agent_execution_route(
            task_kind="code",
            changed_file_estimate=12,
            expected_duration_minutes=180,
            novelty="high",
            risk_flags=["security", "concurrency"],
            user_requested_external=True,
            available_external_agents=["claude", "agy"],
        )
        self.assertEqual(competitive["execution_mode"], "workspace_with_competition")
        self.assertFalse(competitive["automatic_winner_selection"])
        self.assertEqual(len(competitive["external_candidates"]), 2)

    def test_route_rejects_coercive_bools_and_unknown_agents(self) -> None:
        with self.assertRaisesRegex(competition.AgentCompetitionError, "must be boolean"):
            competition.grabowski_agent_execution_route("code", 1, 1, "low", connector_instability="false")  # type: ignore[arg-type]
        with self.assertRaisesRegex(competition.AgentCompetitionError, "unsupported external agents"):
            competition.grabowski_agent_execution_route("code", 1, 1, "low", available_external_agents=["unknown"])

    def test_start_uses_nested_durable_task_contract_and_writes_private_bound_state(self) -> None:
        result = self._start()
        directory = self.state / result["competition_id"]
        packet = json.loads((directory / "packet.json").read_text())
        manifest = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(manifest["task_id"], "task-claude-competitor")
        self.assertEqual(packet["expected_head"], self.head)
        self.assertEqual(packet["packet_sha256"], manifest["packet_sha256"])
        self.assertEqual(packet["request_id"], "test-claude-competitor")
        self.assertEqual(packet["request_fingerprint"], manifest["request_fingerprint"])
        self.assertEqual((directory / "packet.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / "start-intent.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((directory / "manifest.json").stat().st_mode & 0o777, 0o600)

    def test_start_is_idempotent_and_contract_bound(self) -> None:
        task_id = "task-stable"
        kwargs = {
            "request_id": "stable-request",
            "provider": "claude",
            "mode": "competitor",
            "repository": str(self.repo),
            "expected_head": self.head,
            "task": "Improve sample",
            "allowed_paths": ["src", "tests"],
            "context_paths": ["src/sample.py", "tests/test_sample.py"],
            "forbidden_paths": [],
            "timeout_seconds": 120,
        }
        with mock.patch.object(competition.tasks, "grabowski_task_start", return_value=self._task_start(task_id)) as start:
            first = competition.grabowski_agent_competition_start(**kwargs)
            second = competition.grabowski_agent_competition_start(**kwargs)
        self.assertFalse(first["already_started"])
        self.assertTrue(second["already_started"])
        self.assertEqual(first["competition_id"], second["competition_id"])
        self.assertEqual(start.call_count, 1)
        changed = dict(kwargs)
        changed["primary_summary"] = "different"
        with self.assertRaisesRegex(competition.AgentCompetitionError, "different competition contract"):
            competition.grabowski_agent_competition_start(**changed)

    def test_request_lock_blocks_overlapping_identical_start_window(self) -> None:
        identifier = "gac-claude-competitor-1111111111-2222222222"
        with competition._competition_request_lock(identifier):
            with mock.patch.object(competition, "REQUEST_LOCK_TIMEOUT_SECONDS", 0.0):
                with self.assertRaisesRegex(competition.AgentCompetitionError, "lock timed out"):
                    with competition._competition_request_lock(identifier):
                        self.fail("overlapping request lock must not be acquired")
        lock_path = self.state / f".{identifier}.lock"
        self.assertTrue(lock_path.is_file())
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)


    def test_unresolved_start_intent_blocks_duplicate_start(self) -> None:
        request_id = "unresolved-request"
        task = "Improve sample"
        task_sha256 = competition._sha256_bytes(task.encode("utf-8"))
        identifier = competition._competition_id("claude", "competitor", task_sha256, request_id)
        directory = self.state / identifier
        directory.mkdir(mode=0o700)
        context = [
            {"path": "src/sample.py", "sha256": competition._sha256_bytes((self.repo / "src/sample.py").read_bytes())},
            {"path": "tests/test_sample.py", "sha256": competition._sha256_bytes((self.repo / "tests/test_sample.py").read_bytes())},
        ]
        contract = {
            "request_id": request_id,
            "provider": "claude",
            "mode": "competitor",
            "repository": str(self.repo),
            "expected_head": self.head,
            "task_sha256": task_sha256,
            "task": task,
            "allowed_paths": ["src", "tests"],
            "forbidden_paths": [],
            "context": context,
            "primary_summary": "",
            "timeout_seconds": 120,
            "max_budget_usd": 2.0,
        }
        intent = {
            "schema_version": 1,
            "kind": "external_programming_competition_start_intent",
            "competition_id": identifier,
            "request_id": request_id,
            "request_fingerprint": competition._sha256_json(contract),
            "packet_sha256": "a" * 64,
            "command_sha256": "b" * 64,
            "created_at": "2026-07-12T00:00:00Z",
            "state": "prepared",
        }
        intent["start_intent_sha256"] = competition._sha256_json(intent)
        competition._atomic_json(directory / "start-intent.json", intent)
        status = competition.grabowski_agent_competition_status(identifier)
        self.assertEqual(status["lifecycle_state"], "start_prepared_outcome_unresolved")
        self.assertFalse(status["manifest_present"])
        self.assertTrue(status["retry_blocked"])
        self.assertIsNone(status["task"])
        with mock.patch.object(competition.tasks, "grabowski_task_start") as start:
            with self.assertRaisesRegex(competition.AgentCompetitionError, "outcome is unresolved"):
                competition.grabowski_agent_competition_start(
                    request_id=request_id,
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task=task,
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py", "tests/test_sample.py"],
                    timeout_seconds=120,
                )
        start.assert_not_called()

    def test_task_start_exception_is_projected_as_unknown_not_failed(self) -> None:
        request_id = "unknown-start-request"
        task = "Improve sample"
        task_sha256 = competition._sha256_bytes(task.encode("utf-8"))
        identifier = competition._competition_id("claude", "competitor", task_sha256, request_id)
        with mock.patch.object(competition.tasks, "grabowski_task_start", side_effect=RuntimeError("transport lost")):
            with self.assertRaisesRegex(RuntimeError, "transport lost"):
                competition.grabowski_agent_competition_start(
                    request_id=request_id,
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task=task,
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py", "tests/test_sample.py"],
                    timeout_seconds=120,
                )
        status = competition.grabowski_agent_competition_status(identifier)
        self.assertEqual(status["lifecycle_state"], "task_start_outcome_unknown")
        self.assertEqual(status["cancel_state"], "not_attempted")
        self.assertIsNone(status["task"])
        self.assertTrue(status["retry_blocked"])

    def test_manifest_publish_failure_always_records_cancel_projection(self) -> None:
        request_id = "manifest-failure-request"
        task = "Improve sample"
        task_sha256 = competition._sha256_bytes(task.encode("utf-8"))
        identifier = competition._competition_id("claude", "competitor", task_sha256, request_id)
        original_atomic = competition._atomic_json

        def fail_manifest(path, value):
            if path.name == "manifest.json":
                raise competition.AgentCompetitionError("manifest publish failed")
            return original_atomic(path, value)

        cancel_result = {
            "task": {"task_id": "task-manifest", "unit": "u", "state": "cancelled"},
            "result": {"returncode": 0},
        }
        with (
            mock.patch.object(competition, "_atomic_json", side_effect=fail_manifest),
            mock.patch.object(
                competition.tasks,
                "grabowski_task_start",
                return_value=self._task_start("task-manifest"),
            ),
            mock.patch.object(competition.tasks, "grabowski_task_cancel", return_value=cancel_result) as cancel,
        ):
            with self.assertRaisesRegex(competition.AgentCompetitionError, "manifest publish failed"):
                competition.grabowski_agent_competition_start(
                    request_id=request_id,
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task=task,
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py", "tests/test_sample.py"],
                    timeout_seconds=120,
                )
        cancel.assert_called_once_with("task-manifest")
        with mock.patch.object(
            competition.tasks,
            "grabowski_task_status",
            return_value={"task_id": "task-manifest", "unit": "u", "state": "cancelled"},
        ):
            status = competition.grabowski_agent_competition_status(identifier)
        self.assertEqual(status["lifecycle_state"], "manifest_publish_failed")
        self.assertEqual(status["cancel_state"], "confirmed")
        self.assertEqual(status["task"]["state"], "cancelled")
        self.assertFalse(status["manifest_present"])

    def test_tampered_start_intent_is_not_accepted_as_idempotent_state(self) -> None:
        started = self._start()
        directory = self.state / started["competition_id"]
        (directory / "manifest.json").unlink()
        intent_path = directory / "start-intent.json"
        intent = json.loads(intent_path.read_text())
        intent_path.unlink()
        intent["packet_sha256"] = "f" * 64
        competition._atomic_json(intent_path, intent)
        with mock.patch.object(competition.tasks, "grabowski_task_start") as start:
            with self.assertRaisesRegex(competition.AgentCompetitionError, "start intent contract is invalid"):
                competition.grabowski_agent_competition_start(
                    request_id="test-claude-competitor",
                    provider="claude",
                    mode="competitor",
                    repository=str(self.repo),
                    expected_head=self.head,
                    task="Improve sample",
                    allowed_paths=["src", "tests"],
                    context_paths=["src/sample.py", "tests/test_sample.py"],
                    timeout_seconds=120,
                )
        start.assert_not_called()

    def test_start_rejects_sensitive_allowed_scope(self) -> None:
        (self.repo / "secrets").mkdir()
        (self.repo / "secrets" / "note.txt").write_text("x", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "add secret-looking path"], cwd=self.repo, check=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        with self.assertRaisesRegex(competition.AgentCompetitionError, "sensitive-looking allowed"):
            competition.grabowski_agent_competition_start(
                request_id="test-sensitive-scope",
                provider="claude",
                mode="competitor",
                repository=str(self.repo),
                expected_head=head,
                task="task",
                allowed_paths=["secrets"],
                context_paths=["secrets/note.txt"],
            )

    def test_status_is_bounded_and_does_not_return_patch_body(self) -> None:
        started = self._start()
        self._write_receipt(started["competition_id"], changed_paths=["src/sample.py"], risks=["race"], tests=["unit test"])
        with mock.patch.object(
            competition.tasks,
            "grabowski_task_status",
            return_value={"task_id": started["task_id"], "unit": "u", "attempt": 1, "state": "completed", "updated_at_unix": 1},
        ):
            status = competition.grabowski_agent_competition_status(started["competition_id"])
        self.assertTrue(status["candidate_ready"])
        self.assertNotIn("receipt", status)
        self.assertNotIn("patch", status["candidate"])
        self.assertEqual(status["candidate"]["patch_size_bytes"], 0)

    def test_receipt_absence_remains_optional(self) -> None:
        started = self._start()
        self.assertIsNone(competition._receipt(started["competition_id"]))

    def test_dangling_receipt_symlink_fails_closed(self) -> None:
        started = self._start()
        path = self.state / started["competition_id"] / "receipt.json"
        path.symlink_to(path.with_name("missing-receipt.json"))
        with self.assertRaisesRegex(competition.AgentCompetitionError, "regular private file"):
            competition._receipt(started["competition_id"])

    def test_receipt_symlink_to_regular_file_fails_closed(self) -> None:
        started = self._start()
        directory = self.state / started["competition_id"]
        target = directory / "other-receipt.json"
        target.write_text("{}\n", encoding="utf-8")
        target.chmod(0o600)
        (directory / "receipt.json").symlink_to(target)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "regular private file"):
            competition._receipt(started["competition_id"])

    def test_self_hashed_receipt_cannot_change_manifest_binding(self) -> None:
        started = self._start()
        receipt = self._write_receipt(started["competition_id"], changed_paths=["src/sample.py"], risks=[], tests=[])
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        receipt["expected_head"] = "f" * 40
        receipt["receipt_sha256"] = competition._sha256_json({key: value for key, value in receipt.items() if key != "receipt_sha256"})
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "binding mismatch"):
            competition._receipt(started["competition_id"])

    def test_self_hashed_receipt_with_invalid_candidate_shape_fails_closed(self) -> None:
        started = self._start()
        receipt = self._write_receipt(
            started["competition_id"],
            changed_paths=["src/sample.py"],
            risks=[],
            tests=[],
        )
        path = self.state / started["competition_id"] / "receipt.json"
        path.unlink()
        del receipt["candidate"]["patch_check"]
        receipt["receipt_sha256"] = competition._sha256_json(
            {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        )
        competition._atomic_json(path, receipt)
        with self.assertRaisesRegex(competition.AgentCompetitionError, "candidate shape"):
            competition._receipt(started["competition_id"])

    def test_one_candidate_cannot_create_validation_consensus_by_repeating_a_test(self) -> None:
        first = self._start(provider="claude", mode="competitor", task="duplicate test")
        second = self._start(provider="agy", mode="contrast", task="duplicate test")
        self._write_receipt(
            first["competition_id"],
            changed_paths=[],
            risks=[],
            tests=["same test", "same test"],
        )
        self._write_receipt(
            second["competition_id"],
            changed_paths=[],
            risks=[],
            tests=["other test"],
        )
        result = competition.grabowski_agent_competition_compare(
            [first["competition_id"], second["competition_id"]]
        )
        self.assertEqual(result["consensus"]["proposed_tests"], [])
        self.assertFalse(
            any(item["kind"] == "validation_consensus" for item in result["insights"])
        )

    def test_compare_does_not_claim_identical_empty_patches_or_perfect_empty_paths(self) -> None:
        first = self._start(provider="claude", mode="competitor", task="empty comparison")
        second = self._start(provider="agy", mode="contrast", task="empty comparison")
        self._write_receipt(first["competition_id"], changed_paths=[], risks=[], tests=[])
        self._write_receipt(second["competition_id"], changed_paths=[], risks=[], tests=[])
        result = competition.grabowski_agent_competition_compare(
            [first["competition_id"], second["competition_id"]]
        )
        pair = result["pairwise_contrasts"][0]
        self.assertFalse(pair["both_patches_available"])
        self.assertFalse(pair["same_patch"])
        self.assertIsNone(pair["path_jaccard"])

    def test_compare_emits_consensus_and_divergence_without_winner(self) -> None:
        first = self._start(provider="claude", mode="competitor", task="same task")
        second = self._start(provider="agy", mode="contrast", task="same task")
        self._write_receipt(first["competition_id"], changed_paths=["src/sample.py", "tests/test_sample.py"], risks=["race"], tests=["unit test"])
        self._write_receipt(second["competition_id"], changed_paths=["src/sample.py"], risks=["race"], tests=["unit test"])
        result = competition.grabowski_agent_competition_compare([first["competition_id"], second["competition_id"]])
        self.assertEqual(result["consensus"]["changed_paths"], ["src/sample.py"])
        self.assertEqual(result["divergence"]["changed_paths"], ["tests/test_sample.py"])
        self.assertFalse(result["winner_selected"])
        self.assertFalse(result["automatic_apply"])
        self.assertIn("unit test", result["consensus"]["proposed_tests"])


if __name__ == "__main__":
    unittest.main()
